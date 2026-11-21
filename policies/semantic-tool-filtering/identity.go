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

package semantictoolfiltering

import (
	"cmp"
	"fmt"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"

	"github.com/wso2/api-platform/sdk/ai/azureauthentication"
	embeddingproviders "github.com/wso2/api-platform/sdk/ai/embeddings"
)

const (
	// hostDefaultClientID names the host's default identity in logs, for a managed identity
	// without a client ID.
	hostDefaultClientID = "host-default"

	// azureAuthParam is the API's choice of how the policy authenticates.
	azureAuthParam = "azureAuth"

	// allowedAuthTypesParam is the gateway's list of the authentication types its APIs may use.
	allowedAuthTypesParam = "embeddingAllowedAuthTypes"

	// allowedEndpointsParam is the gateway's list of the endpoints its APIs may call.
	allowedEndpointsParam = "embeddingAllowedEndpoints"
)

// authentication is how the policy authenticates to the embedding provider.
type authentication struct {
	typ        string // embeddingproviders.AuthenticationTypeAPIKey or one of azureauthentication.Types()
	clientID   string // identity modes only; "" for the default identity
	tokenScope string // identity modes only
}

// usesIdentity reports whether the policy authenticates with the gateway's Azure identity.
func (a authentication) usesIdentity() bool {
	return a.typ != embeddingproviders.AuthenticationTypeAPIKey
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

// readAzureAuth reads the API's azureAuth. Without it, or without a type, the policy sends the
// gateway's key. In api-key mode the identity fields are ignored, since a console form can leave
// them behind when the type changes. In an identity mode the client ID, when set, must be a GUID
// and the scope one resource's /.default scope; nothing comes from the gateway's settings.
func readAzureAuth(params map[string]interface{}) (authentication, error) {
	raw, ok := params[azureAuthParam]
	if !ok || raw == nil {
		return authentication{typ: embeddingproviders.AuthenticationTypeAPIKey}, nil
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
	case typ == "" || typ == embeddingproviders.AuthenticationTypeAPIKey:
		return authentication{typ: embeddingproviders.AuthenticationTypeAPIKey}, nil
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
	scope = cmp.Or(scope, embeddingproviders.DefaultTokenScope)
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
// resources. An API can override the endpoint, and the policy engine merges the API's params over
// the gateway's, so the policy can't tell whose endpoint it has: the list is what keeps the
// gateway's key, and tokens for its identity, from going to a resource the gateway hasn't listed.
// An empty or absent list allows every endpoint. Entries are resource URLs, such as
// https://<resource>.openai.azure.com, and match on scheme, host and port, ignoring case, so any
// deployment and API version on a listed resource is allowed. An entry that isn't an http or
// https URL with no path, query or fragment fails every API, so a typo is found at the first
// deployment.
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

// resourceOf returns the lower-cased scheme, host and port of an absolute http or https URL, with
// the scheme's default port filled in. With bare, the URL must have no path (other than "/"),
// query or fragment, as a resource URL has none.
func resourceOf(raw string, bare bool) (string, bool) {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
		return "", false
	}
	if bare && ((u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" || u.ForceQuery) {
		return "", false
	}
	// Fail closed on a non-ASCII host: Go's lower-casing folds some characters to ASCII, while the
	// HTTP client dials the IDNA form of the host, so a look-alike would pass the check and be
	// dialed as a different host.
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
	return append([]string{embeddingproviders.AuthenticationTypeAPIKey}, azureauthentication.Types()...)
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
