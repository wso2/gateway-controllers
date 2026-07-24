/*
 * Copyright (c) 2026, WSO2 LLC. (https://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package mcpauthz

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

const (
	WWWAuthenticateHeader     = "WWW-Authenticate"
	AuthMethodBearer          = "Bearer resource_metadata="
	WellKnownPath             = ".well-known/oauth-protected-resource"
	MetadataMcpMethod         = "mcp.method"
	MetadataMcpCapabilityType = "mcp.type"
	MetadataMcpCapabilityName = "mcp.name"
	McpOAuthAuthType          = "mcp/oauth"
	McpOAuthzAuthType         = "mcp/oauth+authz"

	// Bearer error codes per RFC 6750 §3.1: invalid_token pairs with 401,
	// insufficient_scope with 403, invalid_request with 400.
	ErrorInvalidRequest    = "invalid_request"
	ErrorInvalidToken      = "invalid_token"
	ErrorInsufficientScope = "insufficient_scope"
)

// MCPRequest represents the JSON-RPC MCP request structure
type MCPRequest struct {
	Method string           `json:"method"`
	Params MCPRequestParams `json:"params"`
}

// MCPRequestParams represents the params section of an MCP request
// Different MCP methods use different param structures:
// - tools/call: uses "name" (tool name) and "arguments"
// - resources/read: uses "uri" (resource URI)
// - prompts/get: uses "name" (prompt name)
type MCPRequestParams struct {
	Name      string         `json:"name"` // For tools/call, prompts/get
	Arguments map[string]any `json:"arguments"`
	URI       string         `json:"uri"` // For resources/read
}

// Rule represents a single authorization rule
type Rule struct {
	Attribute Attribute
	// RequiredClaims and RequiredScopes are the deprecated flat conditions. They remain supported
	// for backward compatibility but are superseded by Claims / Scopes (which take precedence when
	// non-empty). RequiredScopes is any-match (OR); RequiredClaims is exact-match on every entry (AND).
	RequiredClaims map[string]string
	RequiredScopes []string
	// Scopes and Claims are the new allOf/anyOf conditions. When non-empty they take precedence over
	// the deprecated fields for the same dimension.
	Scopes ScopeConstraints
	Claims ClaimConstraints
}

// ScopeConstraints defines required scopes: allOf (all), anyOf (any), or both. 
// Empty means no requirement. Replaces deprecated requiredScopes (anyOf).
type ScopeConstraints struct {
	AllOf []string
	AnyOf []string
}

func (s ScopeConstraints) isEmpty() bool { return len(s.AllOf) == 0 && len(s.AnyOf) == 0 }

// ClaimMatcher matches a single claim against the AuthContext: satisfied when the context value for
// Claim is one of Values.
type ClaimMatcher struct {
	Claim  string
	Values []string
}

// ClaimConstraints defines required claims: allOf (all match), anyOf (any match), or both. 
// Empty means no requirement. Replaces deprecated requiredClaims (allOf).
type ClaimConstraints struct {
	AllOf []ClaimMatcher
	AnyOf []ClaimMatcher
}

func (c ClaimConstraints) isEmpty() bool { return len(c.AllOf) == 0 && len(c.AnyOf) == 0 }

// Attribute represents the MCP resource attribute being authorized
type Attribute struct {
	Type string
	Name string
}

type McpAuthzPolicy struct {
	Rules []Rule
}

// deprecationUsage tracks whether the deprecated per-rule fields were used (and whether a new
// counterpart overrode them), for one-time warnings at policy load.
type deprecationUsage struct {
	scopesUsed, scopesIgnored bool
	claimsUsed, claimsIgnored bool
}

func (d deprecationUsage) or(o deprecationUsage) deprecationUsage {
	return deprecationUsage{
		scopesUsed:    d.scopesUsed || o.scopesUsed,
		scopesIgnored: d.scopesIgnored || o.scopesIgnored,
		claimsUsed:    d.claimsUsed || o.claimsUsed,
		claimsIgnored: d.claimsIgnored || o.claimsIgnored,
	}
}

// GetPolicy is the v1alpha2 factory entry point (loaded by v1alpha2 kernels).
func GetPolicy(
	metadata policy.PolicyMetadata,
	params map[string]interface{},
) (policy.Policy, error) {
	slog.Debug("MCP Authorization Policy: GetPolicy called")

	p := &McpAuthzPolicy{}

	// Parse rules from params
	rules, dep, err := parseRules(params)
	if err != nil {
		return nil, fmt.Errorf("failed to parse rules: %w", err)
	}
	p.Rules = rules

	// Deprecation notices (only when a deprecated field is actually in use).
	if dep.scopesUsed {
		if dep.scopesIgnored {
			slog.Warn("MCP Authorization Policy: rule 'requiredScopes' is deprecated and ignored where 'scopes' is configured; migrate to 'scopes' (allOf/anyOf).")
		} else {
			slog.Warn("MCP Authorization Policy: rule 'requiredScopes' is deprecated; migrate to 'scopes' (allOf/anyOf).")
		}
	}
	if dep.claimsUsed {
		if dep.claimsIgnored {
			slog.Warn("MCP Authorization Policy: rule 'requiredClaims' is deprecated and ignored where 'claims' is configured; migrate to 'claims' (allOf/anyOf).")
		} else {
			slog.Warn("MCP Authorization Policy: rule 'requiredClaims' is deprecated; migrate to 'claims' (allOf/anyOf).")
		}
	}

	slog.Debug("MCP Authorization Policy: Parsed policy configuration",
		"rulesCount", len(p.Rules))

	return p, nil
}

// parseRules extracts and validates rules from the 4 top-level arrays: tools, resources, prompts, methods
func parseRules(params map[string]any) ([]Rule, deprecationUsage, error) {
	var allRules []Rule
	var dep deprecationUsage

	// Parse each array type
	arrayTypes := []struct {
		key   string
		type_ string
	}{
		{"tools", "tool"},
		{"resources", "resource"},
		{"prompts", "prompt"},
		{"methods", "method"},
	}

	for _, at := range arrayTypes {
		rules, d, err := parseArrayRules(params, at.key, at.type_)
		if err != nil {
			return nil, dep, fmt.Errorf("failed to parse %s: %w", at.key, err)
		}
		allRules = append(allRules, rules...)
		dep = dep.or(d)
	}

	return allRules, dep, nil
}

// parseArrayRules parses rules from a specific array (tools, resources, prompts, or methods)
func parseArrayRules(params map[string]any, arrayKey, attributeType string) ([]Rule, deprecationUsage, error) {
	var dep deprecationUsage
	rulesRaw, ok := params[arrayKey]
	if !ok {
		// Array is optional
		return nil, dep, nil
	}

	rulesArray, ok := rulesRaw.([]any)
	if !ok {
		return nil, dep, fmt.Errorf("%s must be an array", arrayKey)
	}

	var rules []Rule
	for i, ruleRaw := range rulesArray {
		ruleMap, ok := ruleRaw.(map[string]any)
		if !ok {
			return nil, dep, fmt.Errorf("%s[%d] must be an object", arrayKey, i)
		}

		rule, d, err := parseRuleItem(ruleMap, arrayKey, i, attributeType)
		if err != nil {
			return nil, dep, err
		}
		rules = append(rules, rule)
		dep = dep.or(d)
	}

	return rules, dep, nil
}

// parseRuleItem parses a single rule item from a map. It reads both the new scopes/claims and the
// deprecated requiredScopes/requiredClaims; the new fields take precedence per dimension at
// evaluation time. Returns which deprecated fields were used (for one-time warnings).
func parseRuleItem(ruleMap map[string]any, arrayKey string, index int, attributeType string) (Rule, deprecationUsage, error) {
	var dep deprecationUsage
	rule := Rule{Attribute: Attribute{Type: attributeType}}
	ctx := fmt.Sprintf("%s[%d]", arrayKey, index)

	// Parse name (required)
	nameRaw, ok := ruleMap["name"]
	if !ok {
		return rule, dep, fmt.Errorf("%s.name is required", ctx)
	}
	nameStr, ok := nameRaw.(string)
	if !ok {
		return rule, dep, fmt.Errorf("%s.name must be a string", ctx)
	}
	rule.Attribute.Name = nameStr

	// Parse the new scopes / claims (optional). Malformed → error (fail closed at load).
	scopes, err := parseScopeConstraints(ruleMap, ctx)
	if err != nil {
		return rule, dep, err
	}
	claims, err := parseClaimConstraints(ruleMap, ctx)
	if err != nil {
		return rule, dep, err
	}
	rule.Scopes = scopes
	rule.Claims = claims

	// Parse the deprecated requiredScopes (any-match) / requiredClaims (exact-match, AND).
	if scopesRaw, ok := ruleMap["requiredScopes"]; ok {
		scopesArray, ok := scopesRaw.([]any)
		if !ok {
			return rule, dep, fmt.Errorf("%s.requiredScopes must be an array", ctx)
		}
		for j, scopeRaw := range scopesArray {
			scopeStr, ok := scopeRaw.(string)
			if !ok {
				return rule, dep, fmt.Errorf("%s.requiredScopes[%d] must be a string", ctx, j)
			}
			rule.RequiredScopes = append(rule.RequiredScopes, scopeStr)
		}
	}
	if claimsRaw, ok := ruleMap["requiredClaims"]; ok {
		claimsMap, ok := claimsRaw.(map[string]any)
		if !ok {
			return rule, dep, fmt.Errorf("%s.requiredClaims must be an object", ctx)
		}
		rule.RequiredClaims = make(map[string]string)
		for k, v := range claimsMap {
			vStr, ok := v.(string)
			if !ok {
				return rule, dep, fmt.Errorf("%s.requiredClaims[%s] must be a string", ctx, k)
			}
			rule.RequiredClaims[k] = vStr
		}
	}

	// Record deprecation usage (only when actually provided with values — decision D3).
	if len(rule.RequiredScopes) > 0 {
		dep.scopesUsed = true
		dep.scopesIgnored = !rule.Scopes.isEmpty()
	}
	if len(rule.RequiredClaims) > 0 {
		dep.claimsUsed = true
		dep.claimsIgnored = !rule.Claims.isEmpty()
	}

	// A rule must define at least one authorization condition (new or deprecated).
	if rule.Scopes.isEmpty() && rule.Claims.isEmpty() && len(rule.RequiredScopes) == 0 && len(rule.RequiredClaims) == 0 {
		return rule, dep, fmt.Errorf("%s must define at least one of scopes, claims, requiredScopes, or requiredClaims", ctx)
	}

	return rule, dep, nil
}

// getString returns v as a string, or "" if it is not a string.
func getString(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

// parseStringArray extracts a []string from m[key]; absent/nil → nil; malformed → error. Blank entries dropped.
func parseStringArray(m map[string]any, key, ctx string) ([]string, error) {
	raw, ok := m[key]
	if !ok || raw == nil {
		return nil, nil
	}
	arr, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("%s.%s must be an array", ctx, key)
	}
	var out []string
	for i, item := range arr {
		s, ok := item.(string)
		if !ok {
			return nil, fmt.Errorf("%s.%s[%d] must be a string", ctx, key, i)
		}
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out, nil
}

// parseScopeConstraints reads the new per-rule `scopes` object. Absent/empty → empty; malformed → error.
func parseScopeConstraints(ruleMap map[string]any, ctx string) (ScopeConstraints, error) {
	raw, ok := ruleMap["scopes"]
	if !ok || raw == nil {
		return ScopeConstraints{}, nil
	}
	m, ok := raw.(map[string]any)
	if !ok {
		return ScopeConstraints{}, fmt.Errorf("%s.scopes must be an object", ctx)
	}
	allOf, err := parseStringArray(m, "allOf", ctx+".scopes")
	if err != nil {
		return ScopeConstraints{}, err
	}
	anyOf, err := parseStringArray(m, "anyOf", ctx+".scopes")
	if err != nil {
		return ScopeConstraints{}, err
	}
	return ScopeConstraints{AllOf: allOf, AnyOf: anyOf}, nil
}

// parseClaimMatchers parses an array of { claim, values:[…] } matchers. Malformed → error.
func parseClaimMatchers(raw any, ctx string) ([]ClaimMatcher, error) {
	if raw == nil {
		return nil, nil
	}
	arr, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("%s must be an array", ctx)
	}
	var out []ClaimMatcher
	for i, item := range arr {
		mm, ok := item.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("%s[%d] must be an object", ctx, i)
		}
		claim := strings.TrimSpace(getString(mm["claim"]))
		if claim == "" {
			return nil, fmt.Errorf("%s[%d].claim is required", ctx, i)
		}
		values, err := parseStringArray(mm, "values", fmt.Sprintf("%s[%d]", ctx, i))
		if err != nil {
			return nil, err
		}
		if len(values) == 0 {
			return nil, fmt.Errorf("%s[%d].values must have at least one value", ctx, i)
		}
		out = append(out, ClaimMatcher{Claim: claim, Values: values})
	}
	return out, nil
}

// parseClaimConstraints reads the new per-rule `claims` object. Absent/empty → empty; malformed → error.
func parseClaimConstraints(ruleMap map[string]any, ctx string) (ClaimConstraints, error) {
	raw, ok := ruleMap["claims"]
	if !ok || raw == nil {
		return ClaimConstraints{}, nil
	}
	m, ok := raw.(map[string]any)
	if !ok {
		return ClaimConstraints{}, fmt.Errorf("%s.claims must be an object", ctx)
	}
	allOf, err := parseClaimMatchers(m["allOf"], ctx+".claims.allOf")
	if err != nil {
		return ClaimConstraints{}, err
	}
	anyOf, err := parseClaimMatchers(m["anyOf"], ctx+".claims.anyOf")
	if err != nil {
		return ClaimConstraints{}, err
	}
	return ClaimConstraints{AllOf: allOf, AnyOf: anyOf}, nil
}

// claimConstraintsFromRequired maps the deprecated requiredClaims (all exact-match, AND) onto the new structure.
func claimConstraintsFromRequired(rc map[string]string) ClaimConstraints {
	matchers := make([]ClaimMatcher, 0, len(rc))
	for k, v := range rc {
		matchers = append(matchers, ClaimMatcher{Claim: k, Values: []string{v}})
	}
	return ClaimConstraints{AllOf: matchers}
}

func (p *McpAuthzPolicy) Mode() policy.ProcessingMode {
	return policy.ProcessingMode{
		RequestHeaderMode:  policy.HeaderModeSkip,
		RequestBodyMode:    policy.BodyModeBuffer,
		ResponseHeaderMode: policy.HeaderModeSkip,
		ResponseBodyMode:   policy.BodyModeSkip,
	}
}

func (p *McpAuthzPolicy) OnRequestBody(ctx context.Context, reqCtx *policy.RequestContext, _ map[string]any) policy.RequestAction {
	if strings.EqualFold(reqCtx.Method, "POST") && strings.Contains(reqCtx.Path, "/mcp") {
		slog.Debug("MCP Authorization Policy: Processing MCP request for authorization")
	} else {
		slog.Debug("MCP Authorization Policy: Skipping authz...")
		return nil
	}

	// Check AuthContext populated by an upstream auth policy
	authCtx := reqCtx.SharedContext.AuthContext
	if authCtx == nil || !authCtx.Authenticated {
		slog.Debug("MCP Authorization Policy: No authenticated context found")
		return p.handleAuthFailure(reqCtx, http.StatusUnauthorized, ErrorInvalidToken, "Unauthorized: scope/claim validation failed", nil)
	}

	// Parse MCP request to extract method and name
	var mcpReq MCPRequest
	if err := json.Unmarshal(reqCtx.Body.Content, &mcpReq); err != nil {
		slog.Debug("MCP Authorization Policy: Failed to parse MCP request", "error", err)
		return p.handleAuthFailure(reqCtx, http.StatusBadRequest, ErrorInvalidRequest, "Invalid MCP request format", nil)
	}

	slog.Debug("MCP Authorization Policy: Extracted MCP attributes",
		"method", mcpReq.Method,
		"name", mcpReq.Params.Name,
		"uri", mcpReq.Params.URI)

	// Determine attribute type from method
	attributeType, ok := p.getAttributeTypeFromMethod(mcpReq.Method)
	if !ok {
		slog.Debug("MCP Authorization Policy: Skipping since the method is not one of tools, resources, or prompts", "method", mcpReq.Method)
		return nil
	}

	// Extract attribute name/identifier based on method type
	attributeName := p.getAttributeNameFromParams(mcpReq.Method, mcpReq.Params)

	// Set MCP metadata in context for other policies
	if reqCtx.Metadata == nil {
		reqCtx.Metadata = make(map[string]any)
	}
	reqCtx.Metadata[MetadataMcpMethod] = mcpReq.Method
	reqCtx.Metadata[MetadataMcpCapabilityType] = attributeType
	reqCtx.Metadata[MetadataMcpCapabilityName] = attributeName

	// Check authorization rules
	authorized, missingScopes := p.checkAuthorization(attributeType, attributeName, mcpReq.Method, authCtx)
	if !authorized {
		slog.Debug("MCP Authorization Policy: Authorization check failed",
			"attributeName", mcpReq.Params.Name,
			"method", mcpReq.Method)
		return p.handleAuthFailure(reqCtx, http.StatusForbidden, ErrorInsufficientScope, "Forbidden: insufficient permissions to access this MCP resource", missingScopes)
	}

	slog.Debug("MCP Authorization Policy: Authorization check passed")
	authCtx.Authorized = true
	if authCtx.AuthType == McpOAuthAuthType {
		authCtx.AuthType = McpOAuthzAuthType
	}
	return nil
}

func (p *McpAuthzPolicy) handleAuthFailure(reqCtx *policy.RequestContext, statusCode int, errorCode, errorMessage string, scopeMap map[string]struct{}) policy.RequestAction {
	slog.Debug("MCP Authorization Policy: handleAuthFailure called",
		"errorMessage", errorMessage,
	)

	var missingScopes []string
	for s := range scopeMap {
		missingScopes = append(missingScopes, s)
	}

	wwwAuthHeader := generateWwwAuthenticateHeader(reqCtx.Scheme, reqCtx.Authority, reqCtx.Vhost, reqCtx.APIContext, reqCtx.Metadata, missingScopes, errorCode, errorMessage)

	headers := map[string]string{
		"content-type":        "application/json",
		WWWAuthenticateHeader: wwwAuthHeader,
	}

	errResponse := map[string]interface{}{
		"error":   http.StatusText(statusCode),
		"message": errorMessage,
	}
	bodyBytes, _ := json.Marshal(errResponse)

	return policy.ImmediateResponse{
		StatusCode: statusCode,
		Headers:    headers,
		Body:       bodyBytes,
	}
}

// getAttributeTypeFromMethod extracts the attribute type from the MCP method
func (p *McpAuthzPolicy) getAttributeTypeFromMethod(method string) (string, bool) {
	parts := strings.Split(method, "/")
	if len(parts) != 2 {
		return "", false
	}

	resourceType := parts[0]
	switch resourceType {
	case "tools":
		return "tool", true
	case "resources":
		return "resource", true
	case "prompts":
		return "prompt", true
	default:
		return "", false
	}
}

// getAttributeNameFromParams extracts the attribute name/identifier from params based on method type
func (p *McpAuthzPolicy) getAttributeNameFromParams(method string, params MCPRequestParams) string {
	parts := strings.Split(method, "/")
	if len(parts) != 2 {
		return ""
	}

	resourceType := parts[0]
	switch resourceType {
	case "tools", "prompts":
		// For tools/call and prompts/get, use the "name" field
		return params.Name
	case "resources":
		// For resources/read (and other resource methods), use the "uri" field
		return params.URI
	default:
		return ""
	}
}

// checkAuthorization validates whether the request should be authorized
func (p *McpAuthzPolicy) checkAuthorization(attributeType, attributeName, method string, authCtx *policy.AuthContext) (bool, map[string]struct{}) {
	if len(p.Rules) == 0 {
		slog.Debug("MCP Authorization Policy: No rules configured")
		return true, nil
	}

	// Find matching rules (most specific first)
	matchingRules := p.findMatchingRules(attributeType, attributeName, method)
	if len(matchingRules) == 0 {
		slog.Debug("MCP Authorization Policy: No matching rules found")
		return true, nil
	}

	var missingScopes = make(map[string]struct{})
	// Check if any matching rule grants access
	isAuthorized := true
	for _, rule := range matchingRules {
		if ok, scopes := p.ruleGrantsAccess(rule, authCtx); !ok {
			slog.Debug("MCP Authorization Policy: Rule did not grant access",
				"attributeType", attributeType,
				"attributeName", attributeName,
				"missingScopes", scopes)
			isAuthorized = false
			for _, s := range scopes {
				if _, exists := missingScopes[s]; !exists {
					missingScopes[s] = struct{}{}
				}
			}
			continue
		}
	}

	return isAuthorized, missingScopes
}

// findMatchingRules returns rules that match the attribute, sorted by specificity
func (p *McpAuthzPolicy) findMatchingRules(attributeType, attributeName, method string) []Rule {
	var matching []Rule

	for _, rule := range p.Rules {
		// Special handling for method-based rules since attribute type is derived from the method prefix
		if rule.Attribute.Type == "method" && (rule.Attribute.Name == "*" || rule.Attribute.Name == method) {
			slog.Debug("MCP Authorization Policy: Found matching method-based rule", "method", method)
			matching = append(matching, rule)
			continue
		}

		if rule.Attribute.Type != attributeType {
			slog.Debug("MCP Authorization Policy: Skipping rule due to attribute type mismatch",
				"ruleAttributeType", rule.Attribute.Type,
				"requestAttributeType", attributeType)
			continue
		}

		// Match exact name or wildcard
		// Ignore the attribute name if it's empty. This handles cases where the callable capabilities
		// are not present (eg: tools/list).
		if attributeName != "" && (rule.Attribute.Name == "*" || rule.Attribute.Name == attributeName) {
			slog.Debug("MCP Authorization Policy: Found matching rule",
				"attributeType", attributeType,
				"attributeName", attributeName)
			matching = append(matching, rule)
		}
	}

	// Sort by specificity: exact names before wildcards
	specificRules := []Rule{}
	wildcardRules := []Rule{}
	for _, rule := range matching {
		if rule.Attribute.Name == "*" {
			wildcardRules = append(wildcardRules, rule)
		} else {
			specificRules = append(specificRules, rule)
		}
	}

	return append(specificRules, wildcardRules...)
}

// ruleGrantsAccess checks if a rule's claims and scopes are satisfied. The new Scopes/Claims take
// precedence per dimension; each falls back to the deprecated field when its new counterpart is empty.
func (p *McpAuthzPolicy) ruleGrantsAccess(rule Rule, authCtx *policy.AuthContext) (bool, []string) {
	scopes := rule.Scopes
	if scopes.isEmpty() && len(rule.RequiredScopes) > 0 {
		scopes = ScopeConstraints{AnyOf: rule.RequiredScopes}
	}
	claims := rule.Claims
	if claims.isEmpty() && len(rule.RequiredClaims) > 0 {
		claims = claimConstraintsFromRequired(rule.RequiredClaims)
	}

	// Check claims
	if !claims.isEmpty() {
		if !p.checkClaims(claims, authCtx) {
			return false, nil
		}
	}

	// Check scopes
	if !scopes.isEmpty() {
		if ok, missing := p.checkScopes(scopes, authCtx); !ok {
			return false, missing
		}
	}

	return true, nil
}

// checkClaims verifies a ClaimConstraints set against the AuthContext: every allOf matcher must
// match, and (when present) at least one anyOf matcher must match.
func (p *McpAuthzPolicy) checkClaims(cc ClaimConstraints, authCtx *policy.AuthContext) bool {
	for _, m := range cc.AllOf {
		if !claimMatcherMatches(m, authCtx) {
			slog.Debug("MCP Authorization Policy: allOf claim matcher not satisfied", "claim", m.Claim)
			return false
		}
	}
	if len(cc.AnyOf) > 0 {
		found := false
		for _, m := range cc.AnyOf {
			if claimMatcherMatches(m, authCtx) {
				found = true
				break
			}
		}
		if !found {
			slog.Debug("MCP Authorization Policy: no anyOf claim matcher satisfied")
			return false
		}
	}
	return true
}

// claimMatcherMatches reports whether the AuthContext value for the matcher's claim is one of its
// values. sub/iss/aud are read from the typed fields; any other claim prefers the structured
// TypedProperties (so array-valued claims match as sets) and falls back to the flattened Properties.
func claimMatcherMatches(m ClaimMatcher, authCtx *policy.AuthContext) bool {
	if len(m.Values) == 0 {
		return false
	}
	want := make(map[string]bool, len(m.Values))
	for _, v := range m.Values {
		want[v] = true
	}
	switch m.Claim {
	case "sub":
		return want[authCtx.Subject]
	case "iss":
		return want[authCtx.Issuer]
	case "aud":
		for _, a := range authCtx.Audience {
			if want[a] {
				return true
			}
		}
		return false
	default:
		// Prefer the typed claim value (set intersection); this correctly handles array-valued
		// custom claims. Fall back to the flattened Properties string for auth policies that do
		// not populate TypedProperties.
		if raw, ok := authCtx.TypedProperties[m.Claim]; ok {
			for _, tv := range typedValueStrings(raw) {
				if want[tv] {
					return true
				}
			}
			return false
		}
		if authCtx.Properties == nil {
			return false
		}
		return want[authCtx.Properties[m.Claim]]
	}
}

// typedValueToString renders a scalar typed claim value as a string, matching how jwt-auth flattens
// values into Properties (numbers as integers, bools as true/false, anything else as JSON).
func typedValueToString(v interface{}) string {
	switch val := v.(type) {
	case string:
		return val
	case float64:
		return strconv.FormatInt(int64(val), 10)
	case bool:
		return strconv.FormatBool(val)
	default:
		b, _ := json.Marshal(val)
		return string(b)
	}
}

// typedValueStrings renders a typed claim value (as stored in AuthContext.TypedProperties) as a slice
// of strings: a scalar becomes one element, an array becomes many. Blank results are dropped so an
// empty or nil value never matches (fail-closed).
func typedValueStrings(v interface{}) []string {
	switch val := v.(type) {
	case nil:
		return nil
	case []interface{}:
		var out []string
		for _, item := range val {
			if s := typedValueToString(item); s != "" {
				out = append(out, s)
			}
		}
		return out
	default:
		if s := typedValueToString(v); s != "" {
			return []string{s}
		}
		return nil
	}
}

// checkScopes verifies a ScopeConstraints set against the AuthContext scopes: every allOf scope must
// be present, and (when present) at least one anyOf scope must be present. On failure it returns the
// scopes that would satisfy the unmet condition (for the WWW-Authenticate challenge).
func (p *McpAuthzPolicy) checkScopes(sc ScopeConstraints, authCtx *policy.AuthContext) (bool, []string) {
	var missing []string
	for _, s := range sc.AllOf {
		if !authCtx.Scopes[s] {
			missing = append(missing, s)
		}
	}
	if len(missing) > 0 {
		slog.Debug("MCP Authorization Policy: Missing required (allOf) scopes", "missing", missing)
		return false, missing
	}
	if len(sc.AnyOf) > 0 {
		for _, s := range sc.AnyOf {
			if authCtx.Scopes[s] {
				slog.Debug("MCP Authorization Policy: Found matching (anyOf) scope", "scope", s)
				return true, nil
			}
		}
		slog.Debug("MCP Authorization Policy: No anyOf scope present", "anyOf", sc.AnyOf)
		return false, sc.AnyOf
	}
	return true, nil
}

// generateResourcePath generates the full resource URL for the given resource path
func generateResourcePath(scheme, authority, vhost, apiContext, gatewayHost, resource string) string {
	slog.Debug("MCP Authorization Policy: Generating resource path for", "resource", resource)

	_, port := parseAuthority(authority)

	// Determine the host - prefer vhost, fallback to gatewayHost param
	var host string
	if vhost != "" && !strings.Contains(vhost, "*") {
		host = vhost
		slog.Debug("MCP Authorization Policy: Using VHost with port from context", "vhost", host)
	} else {
		if gatewayHost == "" {
			gatewayHost = "localhost"
		}
		host = gatewayHost
		slog.Debug("MCP Authorization Policy: VHost not found, using gateway host from params", "host", host)
	}

	// Determine port if not present in authority
	if port == -1 {
		slog.Debug("MCP Authorization Policy: No port specified, using default port based on scheme")
		if scheme == "https" {
			port = 8443
		} else {
			port = 8080
		}
	}

	// Build host:port, omitting standard ports
	hostWithPort := host
	if !isStandardPort(scheme, port) {
		slog.Debug("MCP Auth Policy: Adding non-standard port to host", "port", port)
		hostWithPort = fmt.Sprintf("%s:%d", host, port)
	}

	// Build the full URL path
	if apiContext != "" {
		return fmt.Sprintf("%s://%s%s/%s", scheme, hostWithPort, apiContext, resource)
	}
	return fmt.Sprintf("%s://%s/%s", scheme, hostWithPort, resource)
}

// generateWwwAuthenticateHeader generates the WWW-Authenticate header value
func generateWwwAuthenticateHeader(scheme, authority, vhost, apiContext string, metadata map[string]any, scopes []string, errorCode, errorDesc string) string {
	slog.Debug("MCP Authorization Policy: Generating WWW-Authenticate header")
	gatewayHostString, _ := metadata["gatewayHost"].(string)
	headerValue := AuthMethodBearer + "\"" + generateResourcePath(scheme, authority, vhost, apiContext, gatewayHostString, WellKnownPath) + "\""
	if len(scopes) > 0 {
		slog.Debug("MCP Authorization Policy: Adding scopes to WWW-Authenticate header")
		headerValue += ", scope=\"" + strings.Join(scopes, " ") + "\""
	}
	if errorCode != "" {
		slog.Debug("MCP Authorization Policy: Adding error code to WWW-Authenticate header", "error", errorCode)
		headerValue += ", error=\"" + errorCode + "\""
		if errorDesc != "" {
			headerValue += ", error_description=\"" + errorDesc + "\""
		}
	}
	return headerValue
}

// parseAuthority extracts host and port from an authority string (e.g., "example.com:8080")
func parseAuthority(authority string) (host string, port int) {
	if authority == "" {
		return "", -1
	}
	hostPort := strings.SplitN(authority, ":", 2)
	host = hostPort[0]
	if len(hostPort) > 1 {
		port, _ = strconv.Atoi(hostPort[1])
	} else {
		port = -1
	}
	return host, port
}

// isStandardPort returns true if the port is the standard port for the given scheme
func isStandardPort(scheme string, port int) bool {
	return (scheme == "http" && port == 80) || (scheme == "https" && port == 443)
}
