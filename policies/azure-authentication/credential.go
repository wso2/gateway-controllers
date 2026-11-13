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
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand/v2"
	"net/http"
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

// Where tokens come from, as fault reasons and the failure log name it. A managed identity token
// comes from IMDS on a VM or AKS node, or from the host's own endpoint on App Service, Container
// Apps or Arc.
const (
	entraService           = "Microsoft Entra ID"
	managedIdentityService = "the managed identity endpoint"
)

var (
	// Retries that fit the default 10 s tokenRequestTimeout. Managed identity retries the codes the
	// SDK lists for IMDS (404, 410, 429 and 5xx); Entra ID retries azcore's defaults.
	entraRetry   = azpolicy.RetryOptions{MaxRetries: 2, RetryDelay: 200 * time.Millisecond, MaxRetryDelay: 2 * time.Second}
	managedRetry = azpolicy.RetryOptions{MaxRetries: 4, RetryDelay: time.Second, MaxRetryDelay: 4 * time.Second}

	// transport is the credentials' HTTP transport. nil means the SDK's default client; tests
	// replace it.
	transport azpolicy.Transporter

	// oauthErrorCodePattern matches an OAuth error code such as invalid_client.
	oauthErrorCodePattern = regexp.MustCompile(`^[a-z_]{1,64}$`)

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

// newCredential builds the SDK credential for id. The workload identity credential reads
// AZURE_CLIENT_ID, AZURE_TENANT_ID, AZURE_FEDERATED_TOKEN_FILE and AZURE_AUTHORITY_HOST, and the
// clientId and tenantId params take precedence over the first two. The managed identity credential
// never reads AZURE_CLIENT_ID: the Workload Identity webhook sets it for the federated identity,
// which need not be assigned to the host.
func newCredential(id identity) (azcore.TokenCredential, error) {
	if id.authenticationType == AuthenticationTypeManagedIdentity {
		opts := &azidentity.ManagedIdentityCredentialOptions{
			ClientOptions: azcore.ClientOptions{Retry: managedRetry, Transport: transport},
		}
		if id.clientID != "" {
			opts.ID = azidentity.ClientID(id.clientID)
		}
		return azidentity.NewManagedIdentityCredential(opts)
	}
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
	r.mu.Lock()
	defer r.mu.Unlock()
	if c, ok := r.byIdentity[id]; ok {
		return c, nil
	}
	sdkCredential, err := newCredential(id)
	if err != nil {
		return nil, err
	}
	c := &credential{sdk: sdkCredential, service: entraService, rejections: make(map[string]rejection)}
	if id.authenticationType == AuthenticationTypeManagedIdentity {
		c.service = managedIdentityService
	}
	r.byIdentity[id] = c
	return c, nil
}

// credential is an identity's SDK credential, which caches and refreshes its tokens, and the token
// requests it was refused recently, by scope.
type credential struct {
	sdk     azcore.TokenCredential
	service string // entraService or managedIdentityService

	mu         sync.Mutex
	rejections map[string]rejection
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

func (e *tokenError) Error() string { return e.reason + ": " + e.cause.Error() }
func (e *tokenError) Unwrap() error { return e.cause }

// token returns an access token for scope, asking the SDK for at most timeout. A request the
// service refused is answered from the rejection cache for about rejectionCacheFor.
func (c *credential) token(ctx context.Context, scope string, timeout time.Duration) (string, *tokenError) {
	if err := c.recentRejection(scope); err != nil {
		return "", err
	}

	fetchCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	tok, err := c.sdk.GetToken(fetchCtx, azpolicy.TokenRequestOptions{Scopes: []string{scope}})
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
	switch {
	case fetchCtx.Err() != nil:
		return &tokenError{reason: "timed out obtaining an access token from " + c.service, cause: err}
	case errors.As(err, &failed) && failed.RawResponse != nil:
		status, code := failed.RawResponse.StatusCode, oauthErrorCode(failed.RawResponse)
		if c.refuses(status) {
			detail := fmt.Sprintf("HTTP %d", status)
			if code != "" {
				detail += ", " + code
			}
			return &tokenError{reason: fmt.Sprintf("%s rejected the token request (%s)", c.service, detail), cause: err, rejected: true}
		}
		reason := fmt.Sprintf("%s returned HTTP %d", c.service, status)
		if code != "" {
			reason += " (" + code + ")"
		}
		return &tokenError{reason: reason, cause: err}
	default:
		return &tokenError{reason: "could not obtain an access token from " + c.service, cause: err}
	}
}

// refuses reports whether status means the service refused the request itself, rather than a
// failure that can clear on its own: throttling, or IMDS starting up or updating (404 and 410).
func (c *credential) refuses(status int) bool {
	switch {
	case status < 400 || status >= 500 || status == http.StatusTooManyRequests:
		return false
	case c.service == managedIdentityService && (status == http.StatusNotFound || status == http.StatusGone):
		return false
	default:
		return true
	}
}

// oauthErrorCode returns the OAuth error code in resp's body, such as invalid_client, or "" if the
// body has none. The description is left out: it can name the tenant and the application.
func oauthErrorCode(resp *http.Response) string {
	body, err := runtime.Payload(resp)
	if err != nil {
		return ""
	}
	var parsed struct {
		Error string `json:"error"`
	}
	if json.Unmarshal(body, &parsed) != nil || !oauthErrorCodePattern.MatchString(parsed.Error) {
		return ""
	}
	return parsed.Error
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
