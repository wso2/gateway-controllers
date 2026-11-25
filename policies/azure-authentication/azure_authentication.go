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

// Package azureauthentication implements the azure-authentication policy: it obtains a
// Microsoft Entra ID access token for the gateway's own Azure identity and injects it into the
// request before it is forwarded to an Azure-hosted backend such as Azure AI Foundry.
package azureauthentication

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"regexp"
	"slices"
	"strings"
	"time"

	sdkauth "github.com/wso2/api-platform/sdk/ai/azureauthentication"
	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

const (
	// hostDefaultCredentialID is the AuthContext.CredentialID of a managed identity without a
	// clientId. The host then uses its system-assigned identity or, if it has none, its only
	// user-assigned identity, so the policy does not know which one it is.
	hostDefaultCredentialID = "host-default"

	defaultScope               = "https://ai.azure.com/.default"
	defaultTokenRequestTimeout = 10 * time.Second

	// maxTokenRequestTimeout keeps a token fetch well inside the ext_proc message timeout.
	maxTokenRequestTimeout = 30 * time.Second

	failureMessage = "failed to authenticate request to upstream Azure service"
)

var (
	// guidPattern matches an Entra application (client) ID.
	guidPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

	// tenantPattern matches a tenant GUID or a domain name. The tenant is placed in the token URL
	// path, so anything that could change the path ("/", "?", "%", "..") is rejected.
	tenantPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]*(\.[A-Za-z0-9-]+)*$`)

	// tokenRequestTimeoutPattern is the definition's pattern for tokenRequestTimeout: whole seconds
	// from 1s to 30s or milliseconds from 1ms to 30000ms. It is checked here too because a value
	// given through an LLM provider's upstream.auth reaches the policy unvalidated.
	tokenRequestTimeoutPattern = regexp.MustCompile(`^(([1-9]|[12][0-9]|30)s|([1-9][0-9]{0,3}|[12][0-9]{4}|30000)ms)$`)
)

// Policy injects an Entra ID access token for the gateway's workload identity or managed identity
// into the Authorization header before the request is forwarded upstream.
type Policy struct {
	kind     *authenticationKind
	scope    string
	tenantID string // only for a kind that usesTenant
	clientID string // "" for a host's identity without clientId: the host's default
	timeout  time.Duration
	tokens   tokenSource
}

type params struct {
	kind                *authenticationKind
	scope               string
	clientID            string
	tenantID            string
	tokenRequestTimeout time.Duration
}

// GetPolicy is the v1alpha2 factory entry point. The policy engine calls it once per route the
// policy is attached to; instances with the same identity share one credential and its tokens.
func GetPolicy(metadata policy.PolicyMetadata, rawParams map[string]interface{}) (policy.Policy, error) {
	p, err := extractParams(rawParams)
	if err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}

	if p.kind.usesTenant {
		// The credential would fall back to the AZURE_* variables itself. Resolving them first
		// gives a route that leaves them out and a route that names the same identity one
		// credential, and gives the AuthContext and the log the identity in use.
		if p.clientID, err = fromEnvironment(p.clientID, "AZURE_CLIENT_ID", "clientId", guidPattern,
			"an application (client) ID in GUID form"); err != nil {
			return nil, err
		}
		if p.tenantID, err = fromEnvironment(p.tenantID, "AZURE_TENANT_ID", "tenantId", tenantPattern,
			"a tenant ID (GUID) or a domain name"); err != nil {
			return nil, err
		}
	}
	tokens, err := getTokenSource(sdkauth.Identity{Type: p.kind.name, ClientID: p.clientID, TenantID: p.tenantID})
	if err != nil {
		return nil, err
	}

	pol := &Policy{
		kind:     p.kind,
		scope:    p.scope,
		tenantID: p.tenantID,
		clientID: p.clientID,
		timeout:  p.tokenRequestTimeout,
		tokens:   tokens,
	}

	slog.Debug("AzureAuthentication: policy initialized", append([]any{
		"route", metadata.RouteName, "apiName", metadata.APIName, "authenticationType", p.kind.name},
		pol.identityAttrs()...)...)

	return pol, nil
}

// identityAttrs are the log attributes naming the policy's identity and scope: the tenant only
// for a kind that usesTenant, and host-default for a host's identity without a client ID.
func (p *Policy) identityAttrs() []any {
	if !p.kind.usesTenant {
		return []any{"clientId", p.credentialID(), "scope", p.scope}
	}
	return []any{"tenantId", p.tenantID, "clientId", p.clientID, "scope", p.scope}
}

// fromEnvironment returns value, or else the variable name's value, which must have the form the
// param would. An unset variable is left for the SDK to report.
func fromEnvironment(value, name, param string, pattern *regexp.Regexp, form string) (string, error) {
	if value != "" {
		return value, nil
	}
	value = os.Getenv(name)
	if value != "" && !pattern.MatchString(value) {
		return "", fmt.Errorf("%s must be %s; workload identity uses it when '%s' is not set", name, form, param)
	}
	return value, nil
}

// credentialID is the identity's client ID, or host-default for a host's identity without one.
func (p *Policy) credentialID() string {
	if p.clientID == "" {
		return hostDefaultCredentialID
	}
	return p.clientID
}

// paramNames are the policy's parameters, in the order policy-definition.yaml defines them.
var paramNames = []string{
	"authenticationType", "scope", "clientId", "tenantId", "tokenRequestTimeout",
}

// attachedToParam is the key the gateway controller adds to the params of every policy it attaches:
// whether the policy is on the API or a route. The policy engine also passes it as
// PolicyMetadata.AttachedTo; the policy doesn't use it.
const attachedToParam = "attachedTo"

// extractParams reads and checks the policy params. It is the only check for params given in an
// LLM provider's upstream.auth, which the controller does not validate, so it rejects a key that
// is not a parameter: a misspelled clientId, tenantId or scope would otherwise silently give a
// token for another identity or resource. It is slightly more lenient than the policy
// definition, which the controller applies to APIs: string values are trimmed, and an empty or
// null optional value means its default.
func extractParams(raw map[string]interface{}) (params, error) {
	var p params
	var err error

	if err = rejectUnknownParams(raw); err != nil {
		return p, err
	}
	authenticationType, err := requiredString(raw, "authenticationType")
	if err != nil {
		return p, err
	}
	if p.kind = kindOf(authenticationType); p.kind == nil {
		return p, fmt.Errorf("'authenticationType' must be %s", listing(authenticationTypeNames(), "or"))
	}

	if p.scope, err = optionalString(raw, "scope", defaultScope); err != nil {
		return p, err
	}
	if sdkauth.ValidateScope(p.scope) != nil {
		return p, fmt.Errorf("'scope' must be a single scope ending in /.default, e.g. %s", defaultScope)
	}

	// For a kind that usesTenant both fall back to the environment; a host's identity takes its
	// tenant from the identity itself.
	if p.clientID, err = optionalString(raw, "clientId", ""); err != nil {
		return p, err
	}
	if p.clientID != "" && !guidPattern.MatchString(p.clientID) {
		return p, errors.New("'clientId' must be an application (client) ID in GUID form")
	}
	if p.tenantID, err = optionalString(raw, "tenantId", ""); err != nil {
		return p, err
	}
	if !p.kind.usesTenant && p.tenantID != "" {
		return p, fmt.Errorf("'tenantId' is not used with authenticationType %q", p.kind.name)
	}
	if p.tenantID != "" && !tenantPattern.MatchString(p.tenantID) {
		return p, errors.New("'tenantId' must be a tenant ID (GUID) or a domain name")
	}

	timeout, err := optionalString(raw, "tokenRequestTimeout", "")
	if err != nil {
		return p, err
	}
	p.tokenRequestTimeout = defaultTokenRequestTimeout
	if timeout != "" {
		d, err := time.ParseDuration(timeout)
		if !tokenRequestTimeoutPattern.MatchString(timeout) || err != nil || d > maxTokenRequestTimeout {
			return p, errors.New("'tokenRequestTimeout' must be whole seconds from 1s to 30s or milliseconds from 1ms to 30000ms, e.g. \"10s\"")
		}
		p.tokenRequestTimeout = d
	}
	return p, nil
}

// rejectUnknownParams fails when raw has a key that is neither one of paramNames nor the gateway's
// attachedTo, naming every such key and the parameters the policy has.
func rejectUnknownParams(raw map[string]interface{}) error {
	var unknown []string
	for key := range raw {
		if key != attachedToParam && !slices.Contains(paramNames, key) {
			unknown = append(unknown, "'"+key+"'")
		}
	}
	if len(unknown) == 0 {
		return nil
	}
	slices.Sort(unknown)
	known := listing(paramNames, "and")
	if len(unknown) == 1 {
		return fmt.Errorf("%s is not a parameter of the azure-authentication policy; its parameters are %s", unknown[0], known)
	}
	return fmt.Errorf("%s are not parameters of the azure-authentication policy; its parameters are %s",
		strings.Join(unknown, ", "), known)
}

// listing joins items for a message: "a", "a or b", "a, b or c".
func listing(items []string, conjunction string) string {
	if len(items) == 1 {
		return items[0]
	}
	return strings.Join(items[:len(items)-1], ", ") + " " + conjunction + " " + items[len(items)-1]
}

// requiredString returns a trimmed, non-empty string param.
func requiredString(raw map[string]interface{}, key string) (string, error) {
	v, ok := raw[key]
	if !ok {
		return "", fmt.Errorf("'%s' is required", key)
	}
	s, ok := v.(string)
	if !ok {
		return "", fmt.Errorf("'%s' must be a string", key)
	}
	s = strings.TrimSpace(s)
	if s == "" {
		return "", fmt.Errorf("'%s' cannot be empty", key)
	}
	return s, nil
}

// optionalString returns a trimmed string param, or def when the key is absent, null or blank.
func optionalString(raw map[string]interface{}, key, def string) (string, error) {
	v, ok := raw[key]
	if !ok || v == nil {
		return def, nil
	}
	s, ok := v.(string)
	if !ok {
		return "", fmt.Errorf("'%s' must be a string", key)
	}
	if s = strings.TrimSpace(s); s == "" {
		return def, nil
	}
	return s, nil
}

// Mode reports that only request headers are processed: the policy sets one header and never
// needs the body or the response.
func (p *Policy) Mode() policy.ProcessingMode {
	return policy.ProcessingMode{
		RequestHeaderMode:  policy.HeaderModeProcess,
		RequestBodyMode:    policy.BodyModeSkip,
		ResponseHeaderMode: policy.HeaderModeSkip,
		ResponseBodyMode:   policy.BodyModeSkip,
	}
}

// OnRequestHeaders sets the access token as "Authorization: Bearer <token>", the only form in
// which Azure AI Foundry and Azure OpenAI accept an Entra ID token.
func (p *Policy) OnRequestHeaders(ctx context.Context, reqCtx *policy.RequestHeaderContext, _ map[string]interface{}) policy.RequestHeaderAction {
	token, err := p.tokens.Token(ctx, p.scope, p.timeout)
	switch {
	case err == nil:
		p.recordAuth(reqCtx, true)
		return policy.UpstreamRequestHeaderModifications{
			HeadersToSet: map[string]string{"Authorization": "Bearer " + token},
		}
	case ctx.Err() != nil:
		return p.requestEnded(reqCtx)
	default:
		return p.authFailure(reqCtx, err)
	}
}

// authFailure returns 502: the caller's request was fine, it is the gateway's own upstream
// credential that could not be obtained. The client sees a generic message; the reason goes to
// fault policies (Description), and the reason and the SDK's error go to the log.
func (p *Policy) authFailure(reqCtx *policy.RequestHeaderContext, err error) policy.RequestHeaderAction {
	failure := "could not obtain an access token from " + p.tokens.Service()
	reason, level := failure, slog.LevelError
	var terr *sdkauth.TokenError
	if errors.As(err, &terr) {
		reason = terr.Reason
		// A rejection served from the cache was logged at ERROR when its token request failed.
		if terr.Cached {
			level = slog.LevelDebug
		}
	}
	// A TokenError's text is the SDK's error with any token withheld.
	attrs := append([]any{"reason", reason, "error", err.Error()}, p.identityAttrs()...)
	if reqCtx != nil && reqCtx.SharedContext != nil {
		attrs = append(attrs, "requestId", reqCtx.RequestID, "apiName", reqCtx.APIName)
	}
	slog.Log(context.Background(), level, "AzureAuthentication: "+failure, attrs...)

	p.recordAuth(reqCtx, false)
	return failureResponse(reason)
}

// requestEnded answers a request whose own context ended while it waited for a token, such as a
// client that disconnected. It is not an Entra ID or IMDS failure, so it is logged at Debug and
// leaves the AuthContext as it was.
func (p *Policy) requestEnded(reqCtx *policy.RequestHeaderContext) policy.RequestHeaderAction {
	const reason = "the request ended before an access token was available"
	attrs := append([]any{"reason", reason}, p.identityAttrs()...)
	if reqCtx != nil && reqCtx.SharedContext != nil {
		attrs = append(attrs, "requestId", reqCtx.RequestID, "apiName", reqCtx.APIName)
	}
	slog.Debug("AzureAuthentication: "+reason, attrs...)
	return failureResponse(reason)
}

// failureResponse is the 502 the policy answers when it has no token for the upstream request,
// with reason as the fault's internal description.
func failureResponse(reason string) policy.ImmediateResponse {
	body, _ := json.Marshal(map[string]string{"error": "Bad Gateway", "message": failureMessage})
	return policy.ImmediateResponse{
		StatusCode: http.StatusBadGateway,
		Headers:    map[string]string{"Content-Type": "application/json"},
		Body:       body,
		IsFault:    true,
		Fault: &policy.FaultDetails{
			Code:        policy.FaultCodeMediationFailed,
			Type:        policy.FaultTypeMediation,
			Direction:   policy.DirectionRequest,
			Message:     failureMessage,
			Description: reason,
		},
	}
}

// recordAuth records the outcome in the shared AuthContext, keeping any earlier context (such
// as the inbound api-key-auth result) as Previous.
func (p *Policy) recordAuth(reqCtx *policy.RequestHeaderContext, ok bool) {
	if reqCtx == nil || reqCtx.SharedContext == nil {
		return
	}
	props := map[string]string{
		"authenticationType": p.kind.name,
		"scope":              p.scope,
	}
	if p.kind.usesTenant {
		props["tenantId"] = p.tenantID
	}
	reqCtx.AuthContext = &policy.AuthContext{
		Authenticated: ok,
		AuthType:      p.kind.authType,
		CredentialID:  p.credentialID(),
		Properties:    props,
		Previous:      reqCtx.AuthContext,
	}
}
