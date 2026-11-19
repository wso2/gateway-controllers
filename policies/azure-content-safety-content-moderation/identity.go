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

package azurecontentsafetycontentmoderation

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/wso2/api-platform/sdk/ai/azureauthentication"
)

const (
	// authenticationTypeAPIKey sends the gateway's subscription key, as every version before
	// v1.2.0 does. It is the default. The other authentication types are azureauthentication's.
	authenticationTypeAPIKey = "api-key"

	// defaultTokenScope is Azure AI services' scope, which Content Safety accepts.
	defaultTokenScope = "https://cognitiveservices.azure.com/.default"

	// hostDefaultClientID names the host's default identity in logs, for a managed identity
	// without a client ID.
	hostDefaultClientID = "host-default"

	// azureAuthParam is the API's choice of how the policy authenticates.
	azureAuthParam = "azureAuth"

	// allowedAuthTypesParam is the gateway's list of the authentication types its APIs may use.
	allowedAuthTypesParam = "azureContentSafetyAllowedAuthTypes"

	// allowedEndpointsParam is the gateway's list of the endpoints its APIs may call.
	allowedEndpointsParam = "azureContentSafetyAllowedEndpoints"
)

// errNoAccessToken is what a client sees, with showAssessment, when the check failed for want of a
// token: never the reason, which can describe the gateway's identity.
var errNoAccessToken = errors.New("Could not obtain an access token for Azure Content Safety")

// authentication is how the policy authenticates to Azure Content Safety.
type authentication struct {
	typ        string // authenticationTypeAPIKey or one of azureauthentication.Types()
	clientID   string // identity modes only; "" for the default identity
	tokenScope string // identity modes only
}

// usesIdentity reports whether the policy authenticates with the gateway's Azure identity.
func (a authentication) usesIdentity() bool { return a.typ != authenticationTypeAPIKey }

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

// readAzureAuth reads the API's azureAuth. Without it, or without a type, the policy sends the
// gateway's key. In api-key mode the identity fields are ignored, since a console form can leave
// them behind when the type changes. In an identity mode the client ID, when set, must be a GUID
// and the scope one resource's /.default scope; nothing comes from the gateway's settings.
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

// checkAllowedType checks typ against the gateway's list of allowed authentication types. An
// empty or absent list allows every type. An entry that isn't a type fails every API, so a typo
// in the gateway's config is found at the first deployment instead of locking types out unseen.
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

// checkAllowedEndpoint checks the endpoint in effect against the gateway's list of allowed
// endpoints. An API can override the endpoint, and the policy engine merges the API's params over
// the gateway's, so the policy can't tell whose endpoint it has: the list is what keeps the
// gateway's key, and tokens for its identity, from going to an endpoint the gateway hasn't listed.
// An empty or absent list allows every endpoint. Entries match regardless of case and of a
// trailing slash. An entry that isn't an http or https URL fails every API, so a typo is found at
// the first deployment.
func checkAllowedEndpoint(params map[string]interface{}, endpoint string) error {
	allowed, err := stringList(params, allowedEndpointsParam)
	if err != nil {
		return err
	}
	for _, entry := range allowed {
		u, err := url.Parse(entry)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return fmt.Errorf("'%s' entry %q is not an endpoint URL, such as https://<resource>.cognitiveservices.azure.com", allowedEndpointsParam, entry)
		}
	}
	if len(allowed) == 0 {
		return nil
	}
	for _, entry := range allowed {
		if strings.EqualFold(strings.TrimRight(entry, "/"), strings.TrimRight(strings.TrimSpace(endpoint), "/")) {
			return nil
		}
	}
	return fmt.Errorf("endpoint %q is not allowed on this gateway: '%s' allows %s", endpoint, allowedEndpointsParam, quotedList(allowed))
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

// accessToken returns a token for the Content Safety call, or the reason there is none, for the
// fault's description. A failure is logged at ERROR even when passthroughOnError hides it from the
// client, so a broken identity can't quietly turn moderation off. A rejection answered from the
// cache was logged when it happened, so it is logged at DEBUG, and so is a request that ended
// before the token arrived, which is not an identity failure.
func (p *AzureContentSafetyContentModerationPolicy) accessToken(ctx context.Context, isResponse bool) (string, error) {
	token, err := p.tokens.Token(ctx, p.auth.tokenScope, azureauthentication.DefaultTokenTimeout)
	if err == nil {
		return token, nil
	}

	attrs := []any{"authenticationType", p.auth.typ, "clientId", p.auth.logClientID(), "scope", p.auth.tokenScope, "isResponse", isResponse}
	if ctx.Err() != nil {
		const reason = "the request ended before an access token was available"
		slog.Debug("AzureContentSafety: "+reason, attrs...)
		return "", errors.New(reason)
	}

	reason, level := "could not obtain an access token", slog.LevelError
	var terr *azureauthentication.TokenError
	if errors.As(err, &terr) {
		reason = terr.Reason
		if terr.Cached {
			level = slog.LevelDebug
		}
	}
	// err.Error() is the TokenError's text: the SDK's error with any token withheld.
	slog.Log(ctx, level, "AzureContentSafety: could not obtain an access token for Azure Content Safety",
		append([]any{"reason", reason, "error", err.Error()}, attrs...)...)
	return "", errors.New(reason)
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
