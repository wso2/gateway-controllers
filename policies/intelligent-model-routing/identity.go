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
 */

package intelligentmodelrouting

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/wso2/api-platform/sdk/ai/azureauthentication"
)

const (
	// authenticationTypeAPIKey sends the API key; it is the default authentication type.
	authenticationTypeAPIKey = "api-key"

	// defaultTokenScope is the scope requested for Azure OpenAI access tokens.
	defaultTokenScope = "https://cognitiveservices.azure.com/.default"

	// hostDefaultClientID names the host's default identity in logs, for a managed identity
	// without a client ID.
	hostDefaultClientID = "host-default"

	// azureAuthParam is the API's choice of how the policy authenticates.
	azureAuthParam = "azureAuth"

	// allowedAuthTypesParam is the gateway's list of the authentication types its APIs may use.
	allowedAuthTypesParam = "llmAllowedAuthTypes"

	// allowedEndpointsParam is the gateway's list of the endpoints its APIs may call.
	allowedEndpointsParam = "llmAllowedEndpoints"
)

// authentication is how the policy authenticates to the LLM provider.
type authentication struct {
	typ        string // authenticationTypeAPIKey or one of azureauthentication.Types()
	clientID   string // identity modes only; "" for the default identity
	tokenScope string // identity modes only
}

// usesIdentity reports whether the policy authenticates with the gateway's Azure identity.
func (a authentication) usesIdentity() bool {
	return a.typ != authenticationTypeAPIKey
}

// logClientID names the identity in logs: its client ID, AZURE_CLIENT_ID for workload identity
// without one, or host-default for a host's identity without one.
func (a authentication) logClientID() string {
	switch {
	case a.clientID != "":
		return a.clientID
	case a.typ == azureauthentication.WorkloadIdentity:
		return os.Getenv("AZURE_CLIENT_ID")
	default:
		return hostDefaultClientID
	}
}

// parseAuthentication reads how the API authenticates, from its azureAuth, and checks that the
// gateway allows it.
func parseAuthentication(params map[string]interface{}) (authentication, error) {
	auth, err := readAzureAuth(params)
	if err != nil {
		return authentication{}, err
	}
	if err := checkAllowedType(params, auth.typ); err != nil {
		return authentication{}, err
	}
	return auth, nil
}

// readAzureAuth reads the API's azureAuth; without a type it means api-key. In api-key mode the
// identity fields are ignored, since a console form can leave them behind when the type changes.
func readAzureAuth(params map[string]interface{}) (authentication, error) {
	raw, ok := params[azureAuthParam]
	if !ok || raw == nil {
		return authentication{typ: authenticationTypeAPIKey}, nil
	}
	settings, ok := raw.(map[string]interface{})
	if !ok {
		return authentication{}, fmt.Errorf("'%s' must be an object", azureAuthParam)
	}

	typ, err := optionalString(settings, "authenticationType")
	if err != nil {
		return authentication{}, err
	}
	switch {
	case typ == "" || typ == authenticationTypeAPIKey:
		return authentication{typ: authenticationTypeAPIKey}, nil
	case !slices.Contains(azureauthentication.Types(), typ):
		return authentication{}, fmt.Errorf("'%s.authenticationType' must be %s", azureAuthParam, quotedList(authenticationTypes()))
	}

	clientID, err := optionalString(settings, "clientId")
	if err != nil {
		return authentication{}, err
	}
	scope, err := optionalString(settings, "scope")
	if err != nil {
		return authentication{}, err
	}
	if err := (azureauthentication.Identity{Type: typ, ClientID: clientID}).Validate(); err != nil {
		return authentication{}, fmt.Errorf("'%s.clientId' is invalid: %w", azureAuthParam, err)
	}
	scope = cmp.Or(scope, defaultTokenScope)
	if err := azureauthentication.ValidateScope(scope); err != nil {
		return authentication{}, fmt.Errorf("'%s.scope' is invalid: %w", azureAuthParam, err)
	}
	return authentication{typ: typ, clientID: clientID, tokenScope: scope}, nil
}

// checkAllowedType checks typ against the gateway's allowed types; an empty list allows all. An
// entry that isn't a type fails every API, so a typo shows at the first deployment.
func checkAllowedType(params map[string]interface{}, typ string) error {
	allowed, err := stringList(params, allowedAuthTypesParam)
	if err != nil {
		return err
	}
	for _, entry := range allowed {
		if !slices.Contains(authenticationTypes(), entry) {
			return fmt.Errorf("'%s' entry %q is not an authentication type: use %s", allowedAuthTypesParam, entry, quotedList(authenticationTypes()))
		}
	}
	if len(allowed) == 0 || slices.Contains(allowed, typ) {
		return nil
	}
	return fmt.Errorf("authentication type %q is not allowed on this gateway: '%s' allows %s; choose one with %s.authenticationType",
		typ, allowedAuthTypesParam, quotedList(allowed), azureAuthParam)
}

// checkAllowedEndpoint checks the endpoint in effect, the API's or the gateway's, against the
// gateway's resource URLs (scheme, host and port); an empty list allows all, a bad entry none.
func checkAllowedEndpoint(params map[string]interface{}, endpoint string) error {
	allowed, err := stringList(params, allowedEndpointsParam)
	if err != nil {
		return err
	}
	resources := make([]string, 0, len(allowed))
	for _, entry := range allowed {
		resource, ok := resourceOf(entry, true)
		if !ok {
			return fmt.Errorf("'%s' entry %q is not a resource URL, such as https://<resource>.openai.azure.com", allowedEndpointsParam, entry)
		}
		resources = append(resources, resource)
	}
	if len(allowed) == 0 {
		return nil
	}
	if resource, ok := resourceOf(strings.TrimSpace(endpoint), false); ok && slices.Contains(resources, resource) {
		return nil
	}
	return fmt.Errorf("endpoint %q is not allowed on this gateway: '%s' allows %s", endpoint, allowedEndpointsParam, quotedList(allowed))
}

// resourceOf returns the lower-cased scheme, host and port of an http(s) URL, default port filled
// in. With bare, the URL must have no path (other than "/"), query or fragment.
func resourceOf(raw string, bare bool) (string, bool) {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
		return "", false
	}
	if bare && ((u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" || u.ForceQuery) {
		return "", false
	}
	// Fail closed on a non-ASCII host: lower-casing can fold a look-alike to ASCII while the HTTP
	// client dials its IDNA form, so it would pass the check yet reach a different host.
	for i := 0; i < len(u.Hostname()); i++ {
		if u.Hostname()[i] >= 0x80 {
			return "", false
		}
	}
	scheme := strings.ToLower(u.Scheme)
	port := u.Port()
	if port == "" {
		port = "80"
		if scheme == "https" {
			port = "443"
		}
	}
	return scheme + "://" + strings.ToLower(u.Hostname()) + ":" + port, true
}

// optionalString returns a trimmed string field of azureAuth, or "" when it is absent or null.
func optionalString(settings map[string]interface{}, key string) (string, error) {
	v, ok := settings[key]
	if !ok || v == nil {
		return "", nil
	}
	s, ok := v.(string)
	if !ok {
		return "", fmt.Errorf("'%s.%s' must be a string", azureAuthParam, key)
	}
	return strings.TrimSpace(s), nil
}

// stringList reads an optional array of strings, which arrives as []interface{} from config or
// JSON and as []string when built in code.
func stringList(params map[string]interface{}, key string) ([]string, error) {
	v, ok := params[key]
	if !ok || v == nil {
		return nil, nil
	}
	var items []interface{}
	switch typed := v.(type) {
	case []string:
		for _, s := range typed {
			items = append(items, s)
		}
	case []interface{}:
		items = typed
	default:
		return nil, fmt.Errorf("'%s' must be an array of strings", key)
	}
	list := make([]string, 0, len(items))
	for _, item := range items {
		s, ok := item.(string)
		if !ok {
			return nil, fmt.Errorf("'%s' must be an array of strings", key)
		}
		list = append(list, strings.TrimSpace(s))
	}
	return list, nil
}

// authenticationTypes lists every authentication type: api-key, then the Azure identities.
func authenticationTypes() []string {
	return append([]string{authenticationTypeAPIKey}, azureauthentication.Types()...)
}

// quotedList quotes names for a message: "a", "b" or "c".
func quotedList(names []string) string {
	quoted := make([]string, len(names))
	for i, n := range names {
		quoted[i] = strconv.Quote(n)
	}
	if len(quoted) == 1 {
		return quoted[0]
	}
	return strings.Join(quoted[:len(quoted)-1], ", ") + " or " + quoted[len(quoted)-1]
}

// tokenSource gets Entra ID access tokens for the gateway's identity. *azureauthentication.Credential is
// one; unit tests fake it.
type tokenSource interface {
	Token(ctx context.Context, scope string, timeout time.Duration) (string, error)
}

// getTokenSource returns the gateway-wide credential for id, which every policy with the same
// identity shares. Tests replace it.
var getTokenSource = func(id azureauthentication.Identity) (tokenSource, error) {
	cred, err := azureauthentication.Get(id)
	if err != nil {
		return nil, err
	}
	return cred, nil
}

// useIdentity returns the gateway's credential for auth, which fails when the host can't provide
// the identity, such as Container Apps without IDENTITY_ENDPOINT.
func useIdentity(auth authentication) (tokenSource, error) {
	tokens, err := getTokenSource(azureauthentication.Identity{Type: auth.typ, ClientID: auth.clientID})
	if err != nil {
		return nil, fmt.Errorf("authentication type %q can't be used: %w", auth.typ, err)
	}
	return tokens, nil
}

// accessToken returns a token for the gateway's identity, fetched with the request's context. Its
// error wraps the *azureauthentication.TokenError and never contains a token.
func (p *IntelligentModelRoutingPolicy) accessToken(ctx context.Context) (string, error) {
	token, err := p.tokens.Token(ctx, p.auth.tokenScope, azureauthentication.DefaultTokenTimeout)
	if err != nil {
		return "", fmt.Errorf("could not obtain an access token for the LLM provider: %w", err)
	}
	return token, nil
}

// logTokenFailure logs a failure to get a token for the gateway's identity and reports whether err
// was one. A cached failure, already logged, or a request that ended while waiting logs at DEBUG.
func logTokenFailure(ctx context.Context, err error, auth authentication) bool {
	var tokenErr *azureauthentication.TokenError
	if !errors.As(err, &tokenErr) {
		return false
	}
	attrs := []any{"authenticationType", auth.typ, "clientId", auth.logClientID(), "scope", auth.tokenScope}
	if ctx.Err() != nil {
		slog.Debug("IntelligentModelRouting: the request ended before an access token was available", attrs...)
		return true
	}
	level := slog.LevelError
	if tokenErr.Cached {
		level = slog.LevelDebug
	}
	slog.Log(ctx, level, "IntelligentModelRouting: could not obtain an access token for the LLM provider",
		append([]any{"reason", tokenErr.Reason, "error", err.Error()}, attrs...)...)
	return true
}

// logRefusedToken logs an identity's token the LLM refused with 401 or 403, without the LLM's
// answer, which can name the identity, and reports whether err was one.
func logRefusedToken(ctx context.Context, err error, auth authentication) bool {
	if !auth.usesIdentity() {
		return false
	}
	var statusErr *llmStatusError
	if !errors.As(err, &statusErr) ||
		(statusErr.StatusCode != http.StatusUnauthorized && statusErr.StatusCode != http.StatusForbidden) {
		return false
	}
	slog.Log(ctx, slog.LevelError, "IntelligentModelRouting: the LLM provider refused the access token",
		"status", statusErr.StatusCode,
		"authenticationType", auth.typ,
		"clientId", auth.logClientID(),
		"scope", auth.tokenScope)
	return true
}

// logIdentityFailure logs a classifier error caused by the gateway's identity and reports whether it
// did, so the caller skips its own line, which would carry the LLM's answer above DEBUG.
func logIdentityFailure(ctx context.Context, err error, auth authentication, message string) bool {
	if logTokenFailure(ctx, err, auth) {
		return true
	}
	if !logRefusedToken(ctx, err, auth) {
		return false
	}
	// Only this DEBUG line keeps the LLM's answer, which tells the causes apart.
	slog.Debug("IntelligentModelRouting: "+message, "error", err)
	return true
}
