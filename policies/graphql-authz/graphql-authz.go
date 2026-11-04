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

// Package graphqlauthz implements the GraphQL Authorization policy.
//
// The policy authorizes a GraphQL request's root Query/Mutation fields using
// JWT claims and/or OAuth scopes carried on the request's AuthContext (populated
// by an upstream authentication policy such as jwt-auth). Rules are configured
// per field name under "queries" / "mutations" ("op-level" rules), a type-wide
// "*" wildcard, and a cross-type "global" fallback. All rules that apply to a
// field apply together — mirroring mcp-authz, a "*" or "global" rule is not
// skipped just because a more specific rule also matched; every rule that
// matches must grant access. A field matched by no rule at all (no exact, no
// "*", no "global") is not this policy's concern: it passes through untouched,
// leaving that field to whatever else is attached to the API (another policy,
// or nothing).
package graphqlauthz

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"github.com/vektah/gqlparser/v2/ast"
	"github.com/vektah/gqlparser/v2/parser"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

const (
	wildcardName = "*"

	// typeNameField is the meta-field every GraphQL type carries (including the
	// root Query/Mutation types). It resolves to the type's name and carries no
	// data, so it is excluded from authorization entirely rather than requiring
	// every rule set to explicitly allow it.
	typeNameField = "__typename"

	// Metadata keys published for downstream policies/analytics, mirroring the
	// mcp-authz convention of publishing the parsed request shape regardless of
	// whether this policy ends up governing it.
	MetadataGraphQLOperationType = "graphql.operationType"
	MetadataGraphQLFields        = "graphql.fields"
)

// ScopeConstraints defines a required set of OAuth scopes: allOf (all must be
// present) and/or anyOf (at least one must be present). Empty means no requirement.
type ScopeConstraints struct {
	AllOf []string
	AnyOf []string
}

func (s ScopeConstraints) isEmpty() bool { return len(s.AllOf) == 0 && len(s.AnyOf) == 0 }

// ClaimMatcher matches a single claim against the AuthContext: satisfied when the
// context value for Claim is one of Values.
type ClaimMatcher struct {
	Claim  string
	Values []string
}

// ClaimConstraints defines a required set of claims: allOf (all matchers must
// match) and/or anyOf (at least one must match). Empty means no requirement.
type ClaimConstraints struct {
	AllOf []ClaimMatcher
	AnyOf []ClaimMatcher
}

func (c ClaimConstraints) isEmpty() bool { return len(c.AllOf) == 0 && len(c.AnyOf) == 0 }

// Rule is a single authorization rule for a GraphQL root field.
type Rule struct {
	Name   string // exact field name, or "*" to match every field of its type
	Scopes ScopeConstraints
	Claims ClaimConstraints
}

func (r Rule) isEmpty() bool { return r.Scopes.isEmpty() && r.Claims.isEmpty() }

// GraphQLAuthzPolicy authorizes GraphQL query/mutation root fields.
type GraphQLAuthzPolicy struct {
	Queries   []Rule
	Mutations []Rule
	Global    *Rule
}

// graphQLRequest is the standard GraphQL-over-HTTP request body.
// See https://graphql.github.io/graphql-over-http/draft/#sec-Request.
type graphQLRequest struct {
	Query         string          `json:"query"`
	OperationName string          `json:"operationName"`
	Variables     json.RawMessage `json:"variables"`
}

// GetPolicy is the v1alpha2 factory entry point (loaded by v1alpha2 kernels).
func GetPolicy(metadata policy.PolicyMetadata, params map[string]interface{}) (policy.Policy, error) {
	p := &GraphQLAuthzPolicy{}

	queries, err := parseRuleArray(params, "queries")
	if err != nil {
		return nil, err
	}
	mutations, err := parseRuleArray(params, "mutations")
	if err != nil {
		return nil, err
	}
	global, err := parseGlobalRule(params)
	if err != nil {
		return nil, err
	}

	if len(queries) == 0 && len(mutations) == 0 && global == nil {
		return nil, fmt.Errorf("at least one of 'queries', 'mutations', or 'global' must be provided")
	}

	p.Queries, p.Mutations, p.Global = queries, mutations, global

	slog.Debug("GraphQL Authorization: policy initialized",
		"queriesCount", len(p.Queries), "mutationsCount", len(p.Mutations), "hasGlobal", p.Global != nil)

	return p, nil
}

// parseRuleArray parses params[key] (queries or mutations) into a []Rule.
func parseRuleArray(params map[string]interface{}, key string) ([]Rule, error) {
	raw, ok := params[key]
	if !ok || raw == nil {
		return nil, nil
	}
	arr, ok := raw.([]interface{})
	if !ok {
		return nil, fmt.Errorf("'%s' must be an array", key)
	}
	rules := make([]Rule, 0, len(arr))
	for i, itemRaw := range arr {
		ctx := fmt.Sprintf("%s[%d]", key, i)
		itemMap, ok := itemRaw.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("%s must be an object", ctx)
		}

		nameRaw, ok := itemMap["name"]
		if !ok {
			return nil, fmt.Errorf("%s.name is required", ctx)
		}
		name, ok := nameRaw.(string)
		if !ok || strings.TrimSpace(name) == "" {
			return nil, fmt.Errorf("%s.name must be a non-empty string", ctx)
		}

		scopes, err := parseScopeConstraints(itemMap, ctx)
		if err != nil {
			return nil, err
		}
		claims, err := parseClaimConstraints(itemMap, ctx)
		if err != nil {
			return nil, err
		}

		rule := Rule{Name: name, Scopes: scopes, Claims: claims}
		if rule.isEmpty() {
			return nil, fmt.Errorf("%s must define at least one of 'scopes' or 'claims'", ctx)
		}
		rules = append(rules, rule)
	}
	return rules, nil
}

// parseGlobalRule parses the optional top-level "global" fallback rule.
func parseGlobalRule(params map[string]interface{}) (*Rule, error) {
	raw, ok := params["global"]
	if !ok || raw == nil {
		return nil, nil
	}
	m, ok := raw.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("'global' must be an object")
	}

	scopes, err := parseScopeConstraints(m, "global")
	if err != nil {
		return nil, err
	}
	claims, err := parseClaimConstraints(m, "global")
	if err != nil {
		return nil, err
	}

	rule := Rule{Name: wildcardName, Scopes: scopes, Claims: claims}
	if rule.isEmpty() {
		return nil, fmt.Errorf("'global' must define at least one of 'scopes' or 'claims'")
	}
	return &rule, nil
}

// getString returns v as a string, or "" if it is not a string.
func getString(v interface{}) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

// parseStringArray extracts a []string from m[key]; absent/nil -> nil; malformed -> error.
// Blank entries are dropped.
func parseStringArray(m map[string]interface{}, key, ctx string) ([]string, error) {
	raw, ok := m[key]
	if !ok || raw == nil {
		return nil, nil
	}
	arr, ok := raw.([]interface{})
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

// parseScopeConstraints reads the `scopes` object. Absent/empty -> empty; malformed -> error.
// An explicitly-configured allOf/anyOf that normalizes to an empty slice (an empty array, or
// one containing only blank strings) is rejected rather than silently treated as absent: it
// almost always signals a config mistake (e.g. a templated list that rendered empty), and
// silently ignoring it would leave the rule quietly weaker than intended.
func parseScopeConstraints(m map[string]interface{}, ctx string) (ScopeConstraints, error) {
	raw, ok := m["scopes"]
	if !ok || raw == nil {
		return ScopeConstraints{}, nil
	}
	sm, ok := raw.(map[string]interface{})
	if !ok {
		return ScopeConstraints{}, fmt.Errorf("%s.scopes must be an object", ctx)
	}
	allOf, err := parseStringArray(sm, "allOf", ctx+".scopes")
	if err != nil {
		return ScopeConstraints{}, err
	}
	if v, present := sm["allOf"]; present && v != nil && len(allOf) == 0 {
		return ScopeConstraints{}, fmt.Errorf("%s.scopes.allOf must not be empty", ctx)
	}
	anyOf, err := parseStringArray(sm, "anyOf", ctx+".scopes")
	if err != nil {
		return ScopeConstraints{}, err
	}
	if v, present := sm["anyOf"]; present && v != nil && len(anyOf) == 0 {
		return ScopeConstraints{}, fmt.Errorf("%s.scopes.anyOf must not be empty", ctx)
	}
	return ScopeConstraints{AllOf: allOf, AnyOf: anyOf}, nil
}

// parseClaimMatchers parses an array of { claim, values:[...] } matchers. Malformed -> error.
func parseClaimMatchers(raw interface{}, ctx string) ([]ClaimMatcher, error) {
	if raw == nil {
		return nil, nil
	}
	arr, ok := raw.([]interface{})
	if !ok {
		return nil, fmt.Errorf("%s must be an array", ctx)
	}
	var out []ClaimMatcher
	for i, item := range arr {
		mm, ok := item.(map[string]interface{})
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

// parseClaimConstraints reads the `claims` object. Absent/empty -> empty; malformed -> error.
func parseClaimConstraints(m map[string]interface{}, ctx string) (ClaimConstraints, error) {
	raw, ok := m["claims"]
	if !ok || raw == nil {
		return ClaimConstraints{}, nil
	}
	cm, ok := raw.(map[string]interface{})
	if !ok {
		return ClaimConstraints{}, fmt.Errorf("%s.claims must be an object", ctx)
	}
	allOf, err := parseClaimMatchers(cm["allOf"], ctx+".claims.allOf")
	if err != nil {
		return ClaimConstraints{}, err
	}
	anyOf, err := parseClaimMatchers(cm["anyOf"], ctx+".claims.anyOf")
	if err != nil {
		return ClaimConstraints{}, err
	}
	return ClaimConstraints{AllOf: allOf, AnyOf: anyOf}, nil
}

func (p *GraphQLAuthzPolicy) Mode() policy.ProcessingMode {
	return policy.ProcessingMode{
		RequestHeaderMode:  policy.HeaderModeSkip,
		RequestBodyMode:    policy.BodyModeBuffer,
		ResponseHeaderMode: policy.HeaderModeSkip,
		ResponseBodyMode:   policy.BodyModeSkip,
	}
}

// fieldRuleMatch pairs a governed root field with every rule that governs it
// (an exact-name rule, a type-wide "*" rule, and/or "global" can all apply to
// the same field at once). Every rule in Rules must grant access.
type fieldRuleMatch struct {
	FieldName string
	Rules     []Rule
}

// OnRequestBody authorizes the GraphQL request's root query/mutation fields.
func (p *GraphQLAuthzPolicy) OnRequestBody(ctx context.Context, reqCtx *policy.RequestContext, _ map[string]interface{}) policy.RequestAction {
	ds := reqCtx.DownstreamRequest()
	if !strings.EqualFold(ds.Method, "POST") {
		slog.Debug("GraphQL Authorization: skipping non-POST request", "method", ds.Method)
		return nil
	}

	// SharedContext is embedded in RequestContext, so a nil one makes every
	// reqCtx.Metadata and reqCtx.AuthContext access panic.
	if reqCtx.SharedContext == nil {
		reqCtx.SharedContext = &policy.SharedContext{}
	}

	if reqCtx.Body == nil || !reqCtx.Body.Present || len(reqCtx.Body.Content) == 0 {
		return p.errorResponse(http.StatusBadRequest, "A GraphQL request body is required")
	}

	var req graphQLRequest
	if err := json.Unmarshal(reqCtx.Body.Content, &req); err != nil || strings.TrimSpace(req.Query) == "" {
		slog.Debug("GraphQL Authorization: failed to parse request body")
		return p.errorResponse(http.StatusBadRequest, `Invalid GraphQL request: a non-empty "query" field is required`)
	}

	doc, parseErr := parser.ParseQuery(&ast.Source{Input: req.Query})
	if parseErr != nil {
		slog.Debug("GraphQL Authorization: failed to parse GraphQL query", "error", parseErr)
		return p.errorResponse(http.StatusBadRequest, "Invalid GraphQL query: "+parseErr.Error())
	}

	op := doc.Operations.ForName(req.OperationName)
	if op == nil {
		msg := "Unable to determine which operation to execute; specify \"operationName\" when the document defines more than one operation"
		if req.OperationName != "" {
			msg = fmt.Sprintf("Unknown operation named %q", req.OperationName)
		}
		return p.errorResponse(http.StatusBadRequest, msg)
	}

	if op.Operation != ast.Query && op.Operation != ast.Mutation {
		// Subscriptions are not governed by this policy.
		slog.Debug("GraphQL Authorization: skipping ungoverned operation type", "operation", op.Operation)
		return nil
	}

	fieldNames := rootFieldNames(op.SelectionSet, doc.Fragments)

	// Publish parsed request metadata for other policies, whether or not this
	// policy ends up governing the request (mirrors the mcp-authz convention).
	if reqCtx.Metadata == nil {
		reqCtx.Metadata = make(map[string]interface{})
	}
	reqCtx.Metadata[MetadataGraphQLOperationType] = string(op.Operation)
	reqCtx.Metadata[MetadataGraphQLFields] = fieldNames

	// Rule matching decides governance before any identity is consulted. A field
	// no rule targets — no op-level rule, no "*" wildcard, no "global" — is not
	// governed by this policy and passes through: authorization for it is left
	// to whatever else is attached to the API (another policy, or nothing). A
	// field matched by more than one rule (e.g. its own exact rule plus "*" or
	// "global") must satisfy all of them.
	matches := p.matchFields(string(op.Operation), fieldNames)
	if len(matches) == 0 {
		slog.Debug("GraphQL Authorization: no matching rule for any requested field; request is not governed",
			"operation", op.Operation, "fields", fieldNames)
		return nil
	}

	// At least one field is governed, so an authenticated identity is required.
	authCtx := reqCtx.SharedContext.AuthContext
	if authCtx == nil || !authCtx.Authenticated {
		slog.Debug("GraphQL Authorization: no authenticated context found for a governed field")
		return p.errorResponse(http.StatusUnauthorized, "Unauthorized: authentication required for this GraphQL operation")
	}

	authorized, missingScopes := evaluateMatches(matches, authCtx)
	if !authorized {
		slog.Debug("GraphQL Authorization: authorization check failed", "missingScopes", missingScopes)
		msg := "Forbidden: insufficient permissions to execute this GraphQL operation"
		if len(missingScopes) > 0 {
			msg = fmt.Sprintf("%s (missing scope(s): %s)", msg, strings.Join(missingScopes, ", "))
		}
		return p.errorResponse(http.StatusForbidden, msg)
	}

	slog.Debug("GraphQL Authorization: authorization check passed")
	authCtx.Authorized = true
	return nil
}

// errorResponse builds a standard GraphQL error response: {"errors":[{"message": "..."}]}.
func (p *GraphQLAuthzPolicy) errorResponse(statusCode int, message string) policy.RequestAction {
	body, err := json.Marshal(map[string]interface{}{
		"errors": []map[string]string{{"message": message}},
	})
	if err != nil {
		body = []byte(`{"errors":[{"message":"GraphQL authorization failed"}]}`)
	}
	return policy.ImmediateResponse{
		StatusCode: statusCode,
		Headers:    map[string]string{"content-type": "application/json"},
		Body:       body,
	}
}

// rootFieldNames collects the deduplicated set of root field names selected by set,
// expanding inline fragments and fragment spreads. Fragment names already on the
// current expansion path are skipped, guarding against cycles. The "__typename"
// meta-field is never included: it carries no data and is not subject to
// authorization.
func rootFieldNames(set ast.SelectionSet, fragments ast.FragmentDefinitionList) []string {
	var names []string
	seenNames := map[string]bool{}
	var walk func(ast.SelectionSet, map[string]bool)
	walk = func(ss ast.SelectionSet, activeFragments map[string]bool) {
		for _, sel := range ss {
			switch s := sel.(type) {
			case *ast.Field:
				if s.Name == typeNameField {
					continue
				}
				if !seenNames[s.Name] {
					seenNames[s.Name] = true
					names = append(names, s.Name)
				}
			case *ast.InlineFragment:
				walk(s.SelectionSet, activeFragments)
			case *ast.FragmentSpread:
				if activeFragments[s.Name] {
					continue
				}
				frag := fragments.ForName(s.Name)
				if frag == nil {
					continue
				}
				activeFragments[s.Name] = true
				walk(frag.SelectionSet, activeFragments)
				delete(activeFragments, s.Name)
			}
		}
	}
	walk(set, map[string]bool{})
	return names
}

// matchFields collects every rule that governs each field in fieldNames, using
// op-level rules (queries or mutations, matching opType), the type-wide "*"
// wildcard, and "global". A field matched by no rule at all is omitted from the
// result (not governed by this policy).
func (p *GraphQLAuthzPolicy) matchFields(opType string, fieldNames []string) []fieldRuleMatch {
	var typeRules []Rule
	if opType == string(ast.Mutation) {
		typeRules = p.Mutations
	} else {
		typeRules = p.Queries
	}

	var matches []fieldRuleMatch
	for _, name := range fieldNames {
		rules := matchingRulesForField(typeRules, p.Global, name)
		if len(rules) == 0 {
			continue
		}
		matches = append(matches, fieldRuleMatch{FieldName: name, Rules: rules})
	}
	return matches
}

// matchingRulesForField returns every rule that governs fieldName: its own
// exact-name rule in typeRules (if any), the type-wide "*" rule in typeRules (if
// any), and "global" (if configured) — in that order. Mirroring mcp-authz's
// rule-matching semantics, these stack rather than override one another: a "*"
// or "global" rule applies to a field *in addition to* a more specific rule that
// also matches it, not instead of it. An empty result means the field is not
// governed by this policy at all.
func matchingRulesForField(typeRules []Rule, global *Rule, fieldName string) []Rule {
	var matches []Rule
	var wildcard *Rule
	for i := range typeRules {
		if typeRules[i].Name == fieldName {
			matches = append(matches, typeRules[i])
		} else if typeRules[i].Name == wildcardName {
			wildcard = &typeRules[i]
		}
	}
	if wildcard != nil {
		matches = append(matches, *wildcard)
	}
	if global != nil {
		matches = append(matches, *global)
	}
	return matches
}

// evaluateMatches checks every field match against the AuthContext. Every rule
// governing every matched field must grant access; the union of unmet scopes
// across all of them is returned for the caller's error message.
func evaluateMatches(matches []fieldRuleMatch, authCtx *policy.AuthContext) (bool, []string) {
	authorized := true
	missing := map[string]struct{}{}
	for _, m := range matches {
		for _, rule := range m.Rules {
			if ok, scopes := ruleGrantsAccess(rule, authCtx); !ok {
				authorized = false
				for _, s := range scopes {
					missing[s] = struct{}{}
				}
			}
		}
	}
	var missingList []string
	for s := range missing {
		missingList = append(missingList, s)
	}
	sort.Strings(missingList)
	return authorized, missingList
}

// ruleGrantsAccess checks whether a single rule's claims and scopes are satisfied.
func ruleGrantsAccess(rule Rule, authCtx *policy.AuthContext) (bool, []string) {
	if !rule.Claims.isEmpty() && !checkClaims(rule.Claims, authCtx) {
		return false, nil
	}
	if !rule.Scopes.isEmpty() {
		if ok, missing := checkScopes(rule.Scopes, authCtx); !ok {
			return false, missing
		}
	}
	return true, nil
}

// checkClaims verifies a ClaimConstraints set: every allOf matcher must match, and
// (when present) at least one anyOf matcher must match.
func checkClaims(cc ClaimConstraints, authCtx *policy.AuthContext) bool {
	for _, m := range cc.AllOf {
		if !claimMatcherMatches(m, authCtx) {
			return false
		}
	}
	if len(cc.AnyOf) > 0 {
		for _, m := range cc.AnyOf {
			if claimMatcherMatches(m, authCtx) {
				return true
			}
		}
		return false
	}
	return true
}

// claimMatcherMatches reports whether the AuthContext value for the matcher's claim
// is one of its values. sub/iss/aud are read from the typed fields; any other claim
// prefers TypedProperties (so array-valued claims match as sets) and falls back to
// the flattened Properties.
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

// typedValueToString renders a scalar typed claim value as a string, matching how
// jwt-auth flattens values into Properties (numbers as integers, bools as
// true/false, anything else as JSON).
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

// typedValueStrings renders a typed claim value as a slice of strings: a scalar
// becomes one element, an array becomes many. Blank results are dropped so an
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

// checkScopes verifies a ScopeConstraints set: every allOf scope must be present,
// and (when present) at least one anyOf scope must be present. On failure it
// returns the scopes that would satisfy the unmet condition.
func checkScopes(sc ScopeConstraints, authCtx *policy.AuthContext) (bool, []string) {
	var missing []string
	for _, s := range sc.AllOf {
		if !authCtx.Scopes[s] {
			missing = append(missing, s)
		}
	}
	if len(missing) > 0 {
		return false, missing
	}
	if len(sc.AnyOf) > 0 {
		for _, s := range sc.AnyOf {
			if authCtx.Scopes[s] {
				return true, nil
			}
		}
		return false, sc.AnyOf
	}
	return true, nil
}
