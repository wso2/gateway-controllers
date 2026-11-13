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
	"cmp"
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

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

const (
	// hostDefaultCredentialID is the AuthContext.CredentialID of a managed identity without a
	// clientId. The host then uses its system-assigned identity or, if it has none, its only
	// user-assigned identity, so the policy does not know which one it is.
	hostDefaultCredentialID = "host-default"

	defaultScope               = "https://ai.azure.com/.default"
	defaultHeaderName          = "Authorization"
	defaultValuePrefix         = "Bearer"
	defaultTokenRequestTimeout = 10 * time.Second

	// maxTokenRequestTimeout keeps a token fetch well inside the ext_proc message timeout.
	maxTokenRequestTimeout = 30 * time.Second

	failureMessage = "failed to authenticate request to upstream Azure service"
)

var (
	// scopePattern accepts a single client-credentials scope: a resource followed by /.default.
	scopePattern = regexp.MustCompile(`^\S+/\.default$`)

	// headerNamePattern is an RFC 9110 token, which also rules out pseudo-headers.
	headerNamePattern = regexp.MustCompile("^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")

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
// into a request header before the request is forwarded upstream.
type Policy struct {
	kind        *authenticationKind
	scope       string
	tenantID    string // only for a kind that usesTenant
	clientID    string // "" for a host's identity without clientId: the host's default
	headerName  string
	valuePrefix string
	timeout     time.Duration
	credential  *credential
}

type params struct {
	kind                *authenticationKind
	scope               string
	clientID            string
	tenantID            string
	headerName          string
	valuePrefix         string
	tokenRequestTimeout time.Duration
}

// GetPolicy is the v1alpha2 factory entry point. The policy engine calls it once per route the
// policy is attached to; instances with the same identity share one credential and its tokens.
func GetPolicy(metadata policy.PolicyMetadata, rawParams map[string]interface{}) (policy.Policy, error) {
	p, err := extractParams(rawParams)
	if err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}

	cred, err := credentials.get(identity{authenticationType: p.kind.name, clientID: p.clientID, tenantID: p.tenantID})
	if err != nil {
		return nil, fmt.Errorf("%s: %w", p.kind.unavailable, err)
	}

	pol := &Policy{
		kind:        p.kind,
		scope:       p.scope,
		clientID:    p.clientID,
		headerName:  p.headerName,
		valuePrefix: p.valuePrefix,
		timeout:     p.tokenRequestTimeout,
		credential:  cred,
	}
	if p.kind.usesTenant {
		// The credential falls back to the AZURE_* variables; resolve them the same way for the
		// AuthContext and the log.
		pol.clientID = cmp.Or(p.clientID, os.Getenv("AZURE_CLIENT_ID"))
		pol.tenantID = cmp.Or(p.tenantID, os.Getenv("AZURE_TENANT_ID"))
	}

	slog.Debug("AzureAuthentication: policy initialized", append(append([]any{
		"route", metadata.RouteName, "apiName", metadata.APIName, "authenticationType", p.kind.name},
		pol.identityAttrs()...), "headerName", p.headerName)...)

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

// credentialID is the identity's client ID, or host-default for a host's identity without one.
func (p *Policy) credentialID() string {
	if p.clientID == "" {
		return hostDefaultCredentialID
	}
	return p.clientID
}

// paramNames are the policy's parameters, in the order policy-definition.yaml defines them.
var paramNames = []string{
	"authenticationType", "scope", "clientId", "tenantId", "headerName", "valuePrefix", "tokenRequestTimeout",
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
	if !scopePattern.MatchString(p.scope) {
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

	if p.headerName, err = optionalString(raw, "headerName", defaultHeaderName); err != nil {
		return p, err
	}
	if !headerNamePattern.MatchString(p.headerName) {
		return p, errors.New("'headerName' must be a valid HTTP header name")
	}

	if p.valuePrefix, err = optionalString(raw, "valuePrefix", defaultValuePrefix); err != nil {
		return p, err
	}
	if strings.ContainsFunc(p.valuePrefix, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
		return p, errors.New("'valuePrefix' must not contain control characters")
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

// optionalString returns a trimmed string param, or def when the key is absent. An explicitly
// empty string is returned as "" (so valuePrefix: "" means no prefix).
func optionalString(raw map[string]interface{}, key, def string) (string, error) {
	v, ok := raw[key]
	if !ok || v == nil {
		return def, nil
	}
	s, ok := v.(string)
	if !ok {
		return "", fmt.Errorf("'%s' must be a string", key)
	}
	return strings.TrimSpace(s), nil
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

// OnRequestHeaders injects the access token into headerName.
func (p *Policy) OnRequestHeaders(ctx context.Context, reqCtx *policy.RequestHeaderContext, _ map[string]interface{}) policy.RequestHeaderAction {
	token, err := p.credential.token(ctx, p.scope, p.timeout)
	switch {
	case err == nil:
		p.recordAuth(reqCtx, true)
		return policy.UpstreamRequestHeaderModifications{
			HeadersToSet: map[string]string{p.headerName: headerValue(p.valuePrefix, token)},
		}
	case ctx.Err() != nil:
		return p.requestEnded(reqCtx)
	default:
		return p.authFailure(reqCtx, err)
	}
}

func headerValue(prefix, token string) string {
	if prefix == "" {
		return token
	}
	return prefix + " " + token
}

// authFailure returns 502: the caller's request was fine, it is the gateway's own upstream
// credential that could not be obtained. The client sees a generic message; the reason goes to
// fault policies (Description), and the reason and the SDK's error go to the log.
func (p *Policy) authFailure(reqCtx *policy.RequestHeaderContext, err *tokenError) policy.RequestHeaderAction {
	attrs := append([]any{"reason", err.reason, "error", err.loggable()}, p.identityAttrs()...)
	if reqCtx != nil && reqCtx.SharedContext != nil {
		attrs = append(attrs, "requestId", reqCtx.RequestID, "apiName", reqCtx.APIName)
	}
	// A rejection served from the cache was logged at ERROR when its token request failed.
	level := slog.LevelError
	if err.cached {
		level = slog.LevelDebug
	}
	slog.Log(context.Background(), level, "AzureAuthentication: could not obtain an access token from "+p.kind.service, attrs...)

	p.recordAuth(reqCtx, false)
	return failureResponse(err.reason)
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
