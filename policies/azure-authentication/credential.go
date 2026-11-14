/*
 *  Copyright (c) 2026, WSO2 LLC. (http://www.wso2.org) All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

package azureauthentication

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand/v2"
	"net/http"
	"os"
	"regexp"
	"sync"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	azpolicy "github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
)

// rejectionCacheFor is how long a refused token request is answered again without a new one, give
// or take a quarter for jitter. It keeps a misconfigured identity from sending Entra ID or the
// managed identity endpoint a token request for every API request.
const rejectionCacheFor = 2 * time.Second

var (
	// Retries that fit the default 10 s tokenRequestTimeout. Managed identity retries the codes the
	// SDK lists for IMDS (404, 410, 429 and 5xx); Entra ID retries azcore's defaults.
	entraRetry   = azpolicy.RetryOptions{MaxRetries: 2, RetryDelay: 200 * time.Millisecond, MaxRetryDelay: 2 * time.Second}
	managedRetry = azpolicy.RetryOptions{MaxRetries: 4, RetryDelay: time.Second, MaxRetryDelay: 4 * time.Second}

	// containerAppsRetry is Entra ID's: the Container Apps identity endpoint runs beside the app
	// and gets its tokens from Entra ID, so it fails the way Entra ID does, not the way IMDS does
	// while it starts.
	containerAppsRetry = azpolicy.RetryOptions{MaxRetries: 2, RetryDelay: 200 * time.Millisecond, MaxRetryDelay: 2 * time.Second}

	// transport is the credentials' HTTP transport. nil means the SDK's default client; tests
	// replace it.
	transport azpolicy.Transporter

	// oauthErrorCodePattern matches an OAuth error code such as invalid_client.
	oauthErrorCodePattern = regexp.MustCompile(`^[a-z_]{1,64}$`)

	// tokenFieldPattern and jwtPattern find tokens in the SDK's error text: MSAL quotes a response
	// body it couldn't decode, and that body may carry the token it was meant to deliver.
	tokenFieldPattern = regexp.MustCompile(`("(?:access_token|refresh_token|id_token)"\s*:\s*)"[^"]*"`)
	jwtPattern        = regexp.MustCompile(`eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*`)

	// errNoToken is a token response that succeeded without a token, which MSAL's managed identity
	// client passes on as a success.
	errNoToken = errors.New("the token response has no access token")

	// credentials holds the credentials shared by every policy instance in the process.
	credentials = newCredentialRegistry()
)

// identity selects a credential. An empty clientID means AZURE_CLIENT_ID for workload-identity and
// the host's default identity for managed-identity; an empty tenantID means AZURE_TENANT_ID.
type identity struct {
	authenticationType string
	clientID           string
	tenantID           string
}

// newManagedIdentityCredential builds the SDK credential for the host's managed identity, from
// whichever endpoint the host's environment points the SDK at.
func newManagedIdentityCredential(id identity) (azcore.TokenCredential, error) {
	return managedIdentityCredential(id.clientID, managedRetry)
}

// newContainerAppsCredential builds the SDK credential for a managed identity of the container app
// the gateway runs in. The SDK uses the Container Apps identity endpoint only while
// IDENTITY_ENDPOINT and IDENTITY_HEADER are set; otherwise it falls back to IMDS, which Container
// Apps doesn't have, and every request would wait out its timeout.
func newContainerAppsCredential(id identity) (azcore.TokenCredential, error) {
	var missing []string
	for _, name := range []string{"IDENTITY_ENDPOINT", "IDENTITY_HEADER"} {
		if os.Getenv(name) == "" {
			missing = append(missing, name)
		}
	}
	switch {
	case len(missing) == 1:
		return nil, fmt.Errorf("%s is not set", missing[0])
	case len(missing) > 1:
		return nil, fmt.Errorf("%s are not set", listing(missing, "and"))
	case os.Getenv("IDENTITY_SERVER_THUMBPRINT") != "":
		return nil, errors.New("IDENTITY_SERVER_THUMBPRINT is set, which points the SDK at Service Fabric's endpoint instead")
	}
	return managedIdentityCredential(id.clientID, containerAppsRetry)
}

// managedIdentityCredential builds the SDK credential for the host's managed identity clientID, or
// its default identity when clientID is "". It never reads AZURE_CLIENT_ID: the Workload Identity
// webhook sets it for the federated identity, which need not be assigned to the host.
func managedIdentityCredential(clientID string, retry azpolicy.RetryOptions) (azcore.TokenCredential, error) {
	opts := &azidentity.ManagedIdentityCredentialOptions{
		ClientOptions: azcore.ClientOptions{Retry: retry, Transport: transport},
	}
	if clientID != "" {
		opts.ID = azidentity.ClientID(clientID)
	}
	return azidentity.NewManagedIdentityCredential(opts)
}

// newWorkloadIdentityCredential builds the SDK credential for AKS Workload Identity. It reads
// AZURE_CLIENT_ID, AZURE_TENANT_ID, AZURE_FEDERATED_TOKEN_FILE and AZURE_AUTHORITY_HOST, and the
// clientId and tenantId params take precedence over the first two.
func newWorkloadIdentityCredential(id identity) (azcore.TokenCredential, error) {
	return azidentity.NewWorkloadIdentityCredential(&azidentity.WorkloadIdentityCredentialOptions{
		ClientOptions: azcore.ClientOptions{Retry: entraRetry, Transport: transport},
		ClientID:      id.clientID,
		TenantID:      id.tenantID,
		// The authority host only ever comes from the gateway's environment, so it needs no
		// validation by the public cloud, which an air-gapped or sovereign gateway can't reach.
		DisableInstanceDiscovery: true,
	})
}

// credentialRegistry holds one credential per identity, so every route and API that uses an
// identity shares its token cache, across config pushes too.
type credentialRegistry struct {
	mu         sync.Mutex
	byIdentity map[identity]*credential
}

func newCredentialRegistry() *credentialRegistry {
	return &credentialRegistry{byIdentity: make(map[identity]*credential)}
}

// get returns the credential for id, building it the first time.
func (r *credentialRegistry) get(id identity) (*credential, error) {
	kind := kindOf(id.authenticationType)
	if kind == nil {
		return nil, fmt.Errorf("unknown authentication type %q", id.authenticationType)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if c, ok := r.byIdentity[id]; ok {
		return c, nil
	}
	sdkCredential, err := kind.newCredential(id)
	if err != nil {
		return nil, err
	}
	c := &credential{
		sdk:        sdkCredential,
		kind:       kind,
		slots:      make(map[string]chan struct{}),
		rejections: make(map[string]rejection),
	}
	r.byIdentity[id] = c
	return c, nil
}

// credential is an identity's SDK credential, which caches and refreshes its tokens, and the token
// requests it was refused recently, by scope.
type credential struct {
	sdk  azcore.TokenCredential
	kind *authenticationKind

	mu         sync.Mutex
	slots      map[string]chan struct{} // see slot
	rejections map[string]rejection
}

// slot returns the admission slot a GetToken for scope waits for, one caller at a time. An SDK
// that fetches one token at a time per credential (oneFetchAtATime) does so behind a lock that
// doesn't watch the caller's context, so all its scopes share one slot and the wait honours the
// caller's timeout. Otherwise each scope has its own slot, and a cached token never waits for
// another scope's fetch.
func (c *credential) slot(scope string) chan struct{} {
	key := scope
	if c.kind.oneFetchAtATime {
		key = ""
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	s, ok := c.slots[key]
	if !ok {
		s = make(chan struct{}, 1)
		c.slots[key] = s
	}
	return s
}

type rejection struct {
	err   *tokenError
	until time.Time
}

// tokenError is a failed token request: a short reason for the fault and the log, free of the
// service's error text, and the SDK's error, which only the log gets.
type tokenError struct {
	reason   string
	cause    error
	rejected bool // the service refused the request itself: a 4xx other than 429
	cached   bool // answered from the rejection cache, without a new request
}

func (e *tokenError) Error() string { return e.reason + ": " + e.loggable() }
func (e *tokenError) Unwrap() error { return e.cause }

// loggable is the SDK's error text with any token in it replaced by [REDACTED].
func (e *tokenError) loggable() string {
	text := tokenFieldPattern.ReplaceAllString(e.cause.Error(), `$1"[REDACTED]"`)
	return jwtPattern.ReplaceAllString(text, "[REDACTED]")
}

// token returns an access token for scope, obtained within timeout. A request the service refused
// is answered from the rejection cache for about rejectionCacheFor.
func (c *credential) token(ctx context.Context, scope string, timeout time.Duration) (string, *tokenError) {
	if err := c.recentRejection(scope); err != nil {
		return "", err
	}

	fetchCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	slot := c.slot(scope)
	select {
	case slot <- struct{}{}:
		defer func() { <-slot }()
	case <-fetchCtx.Done():
		return "", c.describe(fetchCtx, fetchCtx.Err())
	}
	// A caller that waited behind a refused request takes its answer instead of asking again.
	if err := c.recentRejection(scope); err != nil {
		return "", err
	}

	tok, err := c.sdk.GetToken(fetchCtx, azpolicy.TokenRequestOptions{Scopes: []string{scope}})
	if err == nil && tok.Token == "" {
		err = errNoToken
	}
	if err == nil {
		return tok.Token, nil
	}

	terr := c.describe(fetchCtx, err)
	if terr.rejected {
		c.remember(scope, terr)
	}
	return "", terr
}

// describe gives a failed GetToken its reason. The SDK reports most failures as one error type
// with the response attached, so the reason comes from the status and the OAuth error code.
func (c *credential) describe(fetchCtx context.Context, err error) *tokenError {
	var failed *azidentity.AuthenticationFailedError
	isAuthFailure := errors.As(err, &failed)
	service := c.kind.service
	switch {
	case errors.Is(err, errNoToken):
		return &tokenError{reason: service + " returned an unusable response", cause: err}
	case fetchCtx.Err() != nil:
		return &tokenError{reason: "timed out obtaining an access token from " + service, cause: err}
	case !isAuthFailure && c.kind.imds:
		// The managed identity credential reports every failure as an AuthenticationFailedError,
		// except IMDS refusing the request without a usable response: its 400 for the host's
		// default identity when the host has several, or a local proxy's 403.
		return &tokenError{reason: service + " rejected the token request", cause: err, rejected: true}
	case isAuthFailure && failed.RawResponse != nil:
		status, code := failed.RawResponse.StatusCode, oauthErrorCode(failed.RawResponse)
		if c.refuses(status) {
			detail := fmt.Sprintf("HTTP %d", status)
			if code != "" {
				detail += ", " + code
			}
			return &tokenError{reason: fmt.Sprintf("%s rejected the token request (%s)", service, detail), cause: err, rejected: true}
		}
		reason := fmt.Sprintf("%s returned HTTP %d", service, status)
		if code != "" {
			reason += " (" + code + ")"
		}
		return &tokenError{reason: reason, cause: err}
	default:
		return &tokenError{reason: "could not obtain an access token from " + service, cause: err}
	}
}

// refuses reports whether status means the service refused the request itself, rather than a
// failure that can clear on its own: throttling, or IMDS starting up or updating (404 and 410).
func (c *credential) refuses(status int) bool {
	switch {
	case status < 400 || status >= 500 || status == http.StatusTooManyRequests:
		return false
	case c.kind.imds && (status == http.StatusNotFound || status == http.StatusGone):
		return false
	default:
		return true
	}
}

// oauthErrorCode returns the OAuth error code in resp's body, such as invalid_client, or "" if the
// body has none. The Container Apps identity endpoint passes Entra ID's code on as errorCode. The
// description and message are left out: they can name the tenant, the application and the resource.
func oauthErrorCode(resp *http.Response) string {
	body, err := runtime.Payload(resp)
	if err != nil {
		return ""
	}
	var parsed struct {
		Error     string `json:"error"`
		ErrorCode string `json:"errorCode"`
	}
	if json.Unmarshal(body, &parsed) != nil {
		return ""
	}
	code := cmp.Or(parsed.Error, parsed.ErrorCode)
	if !oauthErrorCodePattern.MatchString(code) {
		return ""
	}
	return code
}

// recentRejection returns the cached rejection of scope, or nil if there is none or it expired.
func (c *credential) recentRejection(scope string) *tokenError {
	c.mu.Lock()
	defer c.mu.Unlock()
	r, ok := c.rejections[scope]
	if !ok {
		return nil
	}
	if !time.Now().Before(r.until) {
		delete(c.rejections, scope)
		return nil
	}
	cached := *r.err
	cached.cached = true
	return &cached
}

func (c *credential) remember(scope string, err *tokenError) {
	jitter := rand.N(rejectionCacheFor/2 + 1)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.rejections[scope] = rejection{err: err, until: time.Now().Add(rejectionCacheFor*3/4 + jitter)}
}
