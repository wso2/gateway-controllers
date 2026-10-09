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

package graphqlauthz

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

func mockRequestContext(body []byte, authCtx *policy.AuthContext) *policy.RequestContext {
	return &policy.RequestContext{
		SharedContext: &policy.SharedContext{
			Metadata:    make(map[string]interface{}),
			AuthContext: authCtx,
		},
		Headers: policy.NewHeaders(nil),
		Body:    &policy.Body{Content: body, Present: true},
		Method:  "POST",
		Path:    "/graphql",
	}
}

func authenticatedAuthCtx(scopes []string, claims map[string]string) *policy.AuthContext {
	scopeMap := make(map[string]bool, len(scopes))
	for _, s := range scopes {
		scopeMap[s] = true
	}
	return &policy.AuthContext{
		Authenticated: true,
		AuthType:      "jwt",
		Scopes:        scopeMap,
		Properties:    claims,
	}
}

func graphQLBody(t *testing.T, query, operationName string) []byte {
	t.Helper()
	b, err := json.Marshal(map[string]interface{}{"query": query, "operationName": operationName})
	if err != nil {
		t.Fatalf("failed to marshal request body: %v", err)
	}
	return b
}

func rule(name string, scopesAnyOf []string) map[string]interface{} {
	return map[string]interface{}{
		"name": name,
		"scopes": map[string]interface{}{
			"anyOf": toAnySlice(scopesAnyOf),
		},
	}
}

func toAnySlice(ss []string) []interface{} {
	out := make([]interface{}, len(ss))
	for i, s := range ss {
		out[i] = s
	}
	return out
}

// ---- GetPolicy ----

func TestGetPolicy_RequiresAtLeastOneSection(t *testing.T) {
	if _, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{}); err == nil {
		t.Fatal("expected error when none of queries/mutations/global are provided")
	}
}

func TestGetPolicy_ValidQueries(t *testing.T) {
	params := map[string]interface{}{
		"queries": []interface{}{rule("books", []string{"read:books"})},
	}
	p, err := GetPolicy(policy.PolicyMetadata{}, params)
	if err != nil {
		t.Fatalf("GetPolicy returned error: %v", err)
	}
	gp := p.(*GraphQLAuthzPolicy)
	if len(gp.Queries) != 1 || gp.Queries[0].Name != "books" {
		t.Fatalf("unexpected parsed queries: %+v", gp.Queries)
	}
}

func TestGetPolicy_RuleMustHaveScopesOrClaims(t *testing.T) {
	params := map[string]interface{}{
		"queries": []interface{}{map[string]interface{}{"name": "books"}},
	}
	if _, err := GetPolicy(policy.PolicyMetadata{}, params); err == nil {
		t.Fatal("expected error when a rule defines neither scopes nor claims")
	}
}

func TestGetPolicy_RuleRequiresName(t *testing.T) {
	params := map[string]interface{}{
		"queries": []interface{}{map[string]interface{}{"scopes": map[string]interface{}{"anyOf": []interface{}{"x"}}}},
	}
	if _, err := GetPolicy(policy.PolicyMetadata{}, params); err == nil {
		t.Fatal("expected error when a rule is missing 'name'")
	}
}

func TestGetPolicy_GlobalOnly(t *testing.T) {
	params := map[string]interface{}{
		"global": map[string]interface{}{"scopes": map[string]interface{}{"anyOf": []interface{}{"api:access"}}},
	}
	p, err := GetPolicy(policy.PolicyMetadata{}, params)
	if err != nil {
		t.Fatalf("GetPolicy returned error: %v", err)
	}
	gp := p.(*GraphQLAuthzPolicy)
	if gp.Global == nil {
		t.Fatal("expected Global rule to be set")
	}
}

func TestGetPolicy_GlobalMustHaveScopesOrClaims(t *testing.T) {
	params := map[string]interface{}{"global": map[string]interface{}{}}
	if _, err := GetPolicy(policy.PolicyMetadata{}, params); err == nil {
		t.Fatal("expected error when 'global' defines neither scopes nor claims")
	}
}

func TestGetPolicy_RejectsExplicitlyEmptyScopeArray(t *testing.T) {
	cases := []struct {
		name string
		key  string
		val  []interface{}
	}{
		{"allOf empty array", "allOf", toAnySlice(nil)},
		{"anyOf empty array", "anyOf", toAnySlice(nil)},
		{"allOf blank strings only", "allOf", toAnySlice([]string{"  ", ""})},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			params := map[string]interface{}{
				"queries": []interface{}{
					map[string]interface{}{
						"name": "books",
						"scopes": map[string]interface{}{
							c.key: c.val,
						},
					},
				},
			}
			if _, err := GetPolicy(policy.PolicyMetadata{}, params); err == nil {
				t.Fatalf("expected error for explicitly empty scopes.%s, got none", c.key)
			}
		})
	}
}

func TestGetPolicy_AbsentScopeArrayStillAllowed(t *testing.T) {
	// A rule relying on claims alone, with scopes omitted entirely, must still work —
	// only an explicitly-provided-but-empty array is rejected, not an absent one.
	params := map[string]interface{}{
		"queries": []interface{}{
			map[string]interface{}{
				"name": "books",
				"claims": map[string]interface{}{
					"allOf": []interface{}{
						map[string]interface{}{"claim": "role", "values": toAnySlice([]string{"admin"})},
					},
				},
			},
		},
	}
	if _, err := GetPolicy(policy.PolicyMetadata{}, params); err != nil {
		t.Fatalf("expected no error when scopes is omitted entirely, got: %v", err)
	}
}

// ---- OnRequestBody: parsing / structural errors ----

func TestOnRequestBody_EmptyBody(t *testing.T) {
	p := mustPolicy(t, map[string]interface{}{"global": simpleGlobal("x")})
	reqCtx := &policy.RequestContext{
		SharedContext: &policy.SharedContext{},
		Body:          &policy.Body{Present: false},
		Method:        "POST",
	}
	assertImmediateStatus(t, p.OnRequestBody(context.Background(), reqCtx, nil), 400)
}

func TestOnRequestBody_MalformedQuery(t *testing.T) {
	p := mustPolicy(t, map[string]interface{}{"global": simpleGlobal("x")})
	reqCtx := mockRequestContext(graphQLBody(t, "query { books {", ""), nil)
	assertImmediateStatus(t, p.OnRequestBody(context.Background(), reqCtx, nil), 400)
}

func TestOnRequestBody_NonPOSTPassesThrough(t *testing.T) {
	p := mustPolicy(t, map[string]interface{}{"global": simpleGlobal("x")})
	reqCtx := mockRequestContext(graphQLBody(t, "query { books }", ""), nil)
	reqCtx.Method = "GET"
	if action := p.OnRequestBody(context.Background(), reqCtx, nil); action != nil {
		t.Fatalf("expected nil (pass-through) for non-POST request, got %#v", action)
	}
}

func TestOnRequestBody_SubscriptionUngoverned(t *testing.T) {
	p := mustPolicy(t, map[string]interface{}{"global": simpleGlobal("x")})
	reqCtx := mockRequestContext(graphQLBody(t, "subscription { bookAdded { id } }", ""), nil)
	if action := p.OnRequestBody(context.Background(), reqCtx, nil); action != nil {
		t.Fatalf("expected nil (pass-through) for subscriptions, got %#v", action)
	}
}

func TestOnRequestBody_AmbiguousOperationName(t *testing.T) {
	p := mustPolicy(t, map[string]interface{}{"global": simpleGlobal("x")})
	query := `query A { books } query B { authors }`
	reqCtx := mockRequestContext(graphQLBody(t, query, ""), nil)
	assertImmediateStatus(t, p.OnRequestBody(context.Background(), reqCtx, nil), 400)
}

// ---- OnRequestBody: authorization decisions ----

// A field with no op-level rule and no global fallback is not governed by
// this policy instance at all: it passes through, leaving that field to
// whatever else is attached at the API level (another policy, or nothing).
func TestOnRequestBody_UngovernedFieldPassesThrough(t *testing.T) {
	params := map[string]interface{}{
		"queries": []interface{}{rule("books", []string{"read:books"})},
	}
	p := mustPolicy(t, params)
	// "authors" has no rule anywhere (no exact rule, no "*" rule, no global),
	// so it is not this policy's concern — no AuthContext required either.
	reqCtx := mockRequestContext(graphQLBody(t, "query { authors }", ""), nil)
	if action := p.OnRequestBody(context.Background(), reqCtx, nil); action != nil {
		t.Fatalf("expected nil (pass-through) for an ungoverned field, got %#v", action)
	}
}

func TestOnRequestBody_TypenameIsNeverGoverned(t *testing.T) {
	params := map[string]interface{}{
		"queries": []interface{}{rule("books", []string{"read:books"})},
	}
	p := mustPolicy(t, params)
	// A query selecting only the "__typename" meta-field has no real root
	// field to authorize, so it passes through even without authentication.
	reqCtx := mockRequestContext(graphQLBody(t, "query { __typename }", ""), nil)
	if action := p.OnRequestBody(context.Background(), reqCtx, nil); action != nil {
		t.Fatalf("expected nil (pass-through) for a __typename-only query, got %#v", action)
	}
}

func TestOnRequestBody_GovernedFieldNoAuthContext(t *testing.T) {
	params := map[string]interface{}{
		"queries": []interface{}{rule("books", []string{"read:books"})},
	}
	p := mustPolicy(t, params)
	reqCtx := mockRequestContext(graphQLBody(t, "query { books }", ""), nil)
	assertImmediateStatus(t, p.OnRequestBody(context.Background(), reqCtx, nil), 401)
}

func TestOnRequestBody_GovernedFieldUnauthenticated(t *testing.T) {
	params := map[string]interface{}{
		"queries": []interface{}{rule("books", []string{"read:books"})},
	}
	p := mustPolicy(t, params)
	authCtx := &policy.AuthContext{Authenticated: false}
	reqCtx := mockRequestContext(graphQLBody(t, "query { books }", ""), authCtx)
	assertImmediateStatus(t, p.OnRequestBody(context.Background(), reqCtx, nil), 401)
}

func TestOnRequestBody_ExactRuleGrantsAccess(t *testing.T) {
	params := map[string]interface{}{
		"queries": []interface{}{rule("books", []string{"read:books"})},
	}
	p := mustPolicy(t, params)
	authCtx := authenticatedAuthCtx([]string{"read:books"}, nil)
	reqCtx := mockRequestContext(graphQLBody(t, "query { books }", ""), authCtx)
	if action := p.OnRequestBody(context.Background(), reqCtx, nil); action != nil {
		t.Fatalf("expected nil (pass-through) when scopes are satisfied, got %#v", action)
	}
	if !authCtx.Authorized {
		t.Error("expected AuthContext.Authorized to be set to true")
	}
}

func TestOnRequestBody_ExactRuleDeniesInsufficientScope(t *testing.T) {
	params := map[string]interface{}{
		"queries": []interface{}{rule("books", []string{"read:books"})},
	}
	p := mustPolicy(t, params)
	authCtx := authenticatedAuthCtx([]string{"read:other"}, nil)
	reqCtx := mockRequestContext(graphQLBody(t, "query { books }", ""), authCtx)
	assertImmediateStatus(t, p.OnRequestBody(context.Background(), reqCtx, nil), 403)
}

func TestOnRequestBody_MutationRulesAreSeparateFromQueries(t *testing.T) {
	params := map[string]interface{}{
		"queries":   []interface{}{rule("books", []string{"read:books"})},
		"mutations": []interface{}{rule("addBook", []string{"write:books"})},
	}
	p := mustPolicy(t, params)

	// A caller with only the query scope must not be able to run the mutation.
	authCtx := authenticatedAuthCtx([]string{"read:books"}, nil)
	reqCtx := mockRequestContext(graphQLBody(t, `mutation { addBook }`, ""), authCtx)
	assertImmediateStatus(t, p.OnRequestBody(context.Background(), reqCtx, nil), 403)
}

func TestOnRequestBody_TypeWildcardFallback(t *testing.T) {
	params := map[string]interface{}{
		"queries": []interface{}{
			rule("books", []string{"read:books"}),
			rule("*", []string{"read:any"}),
		},
	}
	p := mustPolicy(t, params)

	// "authors" has no exact rule, falls back to the "*" query rule.
	authCtx := authenticatedAuthCtx([]string{"read:any"}, nil)
	reqCtx := mockRequestContext(graphQLBody(t, "query { authors }", ""), authCtx)
	if action := p.OnRequestBody(context.Background(), reqCtx, nil); action != nil {
		t.Fatalf("expected pass-through via wildcard rule, got %#v", action)
	}
}

// Mirrors mcp-authz: a "*" rule applies to a field *in addition to* a more
// specific rule that also matches it, not instead of it — both must pass.
func TestOnRequestBody_ExactRuleAndWildcardBothMustPass(t *testing.T) {
	params := map[string]interface{}{
		"queries": []interface{}{
			rule("books", []string{"read:books"}),
			rule("*", []string{"read:any"}),
		},
	}
	p := mustPolicy(t, params)

	// "books" matches both its own exact rule and the "*" rule. Satisfying only
	// the exact rule's scope is not enough.
	authCtxOnlyExact := authenticatedAuthCtx([]string{"read:books"}, nil)
	reqCtx := mockRequestContext(graphQLBody(t, "query { books }", ""), authCtxOnlyExact)
	assertImmediateStatus(t, p.OnRequestBody(context.Background(), reqCtx, nil), 403)

	authCtxBoth := authenticatedAuthCtx([]string{"read:books", "read:any"}, nil)
	reqCtx2 := mockRequestContext(graphQLBody(t, "query { books }", ""), authCtxBoth)
	if action := p.OnRequestBody(context.Background(), reqCtx2, nil); action != nil {
		t.Fatalf("expected pass-through once both the exact and wildcard scopes are satisfied, got %#v", action)
	}
}

func TestOnRequestBody_GlobalFallbackWhenNoOpLevelRuleMatches(t *testing.T) {
	params := map[string]interface{}{
		"queries": []interface{}{rule("books", []string{"read:books"})},
		"global":  simpleGlobal("api:access"),
	}
	p := mustPolicy(t, params)

	// "authors" has no queries[] rule (exact or "*"), so the global rule governs it.
	authCtxDenied := authenticatedAuthCtx([]string{"read:books"}, nil)
	reqCtx := mockRequestContext(graphQLBody(t, "query { authors }", ""), authCtxDenied)
	assertImmediateStatus(t, p.OnRequestBody(context.Background(), reqCtx, nil), 403)

	authCtxAllowed := authenticatedAuthCtx([]string{"api:access"}, nil)
	reqCtx2 := mockRequestContext(graphQLBody(t, "query { authors }", ""), authCtxAllowed)
	if action := p.OnRequestBody(context.Background(), reqCtx2, nil); action != nil {
		t.Fatalf("expected pass-through via global fallback, got %#v", action)
	}
}

// Mirrors mcp-authz: "global" applies to a field *in addition to* its own
// op-level rule, not instead of it — both must pass.
func TestOnRequestBody_OpLevelRuleAndGlobalBothMustPass(t *testing.T) {
	params := map[string]interface{}{
		"queries": []interface{}{rule("books", []string{"read:books"})},
		"global":  simpleGlobal("api:access"),
	}
	p := mustPolicy(t, params)

	// "books" has its own op-level rule; having only the global scope is not enough...
	authCtxOnlyGlobal := authenticatedAuthCtx([]string{"api:access"}, nil)
	reqCtx := mockRequestContext(graphQLBody(t, "query { books }", ""), authCtxOnlyGlobal)
	assertImmediateStatus(t, p.OnRequestBody(context.Background(), reqCtx, nil), 403)

	// ...and neither is having only the op-level scope, without the global one.
	authCtxOnlyOpLevel := authenticatedAuthCtx([]string{"read:books"}, nil)
	reqCtx2 := mockRequestContext(graphQLBody(t, "query { books }", ""), authCtxOnlyOpLevel)
	assertImmediateStatus(t, p.OnRequestBody(context.Background(), reqCtx2, nil), 403)

	// Both together satisfy both rules.
	authCtxBoth := authenticatedAuthCtx([]string{"read:books", "api:access"}, nil)
	reqCtx3 := mockRequestContext(graphQLBody(t, "query { books }", ""), authCtxBoth)
	if action := p.OnRequestBody(context.Background(), reqCtx3, nil); action != nil {
		t.Fatalf("expected pass-through once both the op-level and global scopes are satisfied, got %#v", action)
	}
}

func TestOnRequestBody_ClaimBasedRule(t *testing.T) {
	params := map[string]interface{}{
		"mutations": []interface{}{
			map[string]interface{}{
				"name": "deleteBook",
				"claims": map[string]interface{}{
					"allOf": []interface{}{
						map[string]interface{}{"claim": "role", "values": toAnySlice([]string{"admin"})},
					},
				},
			},
		},
	}
	p := mustPolicy(t, params)

	authCtxUser := authenticatedAuthCtx(nil, map[string]string{"role": "user"})
	reqCtx := mockRequestContext(graphQLBody(t, "mutation { deleteBook }", ""), authCtxUser)
	assertImmediateStatus(t, p.OnRequestBody(context.Background(), reqCtx, nil), 403)

	authCtxAdmin := authenticatedAuthCtx(nil, map[string]string{"role": "admin"})
	reqCtx2 := mockRequestContext(graphQLBody(t, "mutation { deleteBook }", ""), authCtxAdmin)
	if action := p.OnRequestBody(context.Background(), reqCtx2, nil); action != nil {
		t.Fatalf("expected pass-through when claim matches, got %#v", action)
	}
}

func TestOnRequestBody_MultipleRootFieldsAllMustPass(t *testing.T) {
	params := map[string]interface{}{
		"queries": []interface{}{
			rule("books", []string{"read:books"}),
			rule("authors", []string{"read:authors"}),
		},
	}
	p := mustPolicy(t, params)

	// Only has read:books, but the request also selects "authors".
	authCtx := authenticatedAuthCtx([]string{"read:books"}, nil)
	reqCtx := mockRequestContext(graphQLBody(t, "query { books authors }", ""), authCtx)
	assertImmediateStatus(t, p.OnRequestBody(context.Background(), reqCtx, nil), 403)
}

func TestOnRequestBody_FragmentSpreadFieldsAreGoverned(t *testing.T) {
	params := map[string]interface{}{
		"queries": []interface{}{rule("books", []string{"read:books"})},
	}
	p := mustPolicy(t, params)
	query := `query { ...F } fragment F on Query { books }`

	authCtx := authenticatedAuthCtx(nil, nil)
	reqCtx := mockRequestContext(graphQLBody(t, query, ""), authCtx)
	assertImmediateStatus(t, p.OnRequestBody(context.Background(), reqCtx, nil), 403)
}

func TestMode(t *testing.T) {
	p := mustPolicy(t, map[string]interface{}{"global": simpleGlobal("x")})
	mode := p.Mode()
	if mode.RequestBodyMode != policy.BodyModeBuffer {
		t.Errorf("expected RequestBodyMode to be BodyModeBuffer, got %v", mode.RequestBodyMode)
	}
}

// evaluateMatches collects missing scopes into a map before returning them as a slice,
// so the order is otherwise unspecified; this asserts the result is always sorted,
// regardless of the map's internal (randomized) iteration order.
func TestEvaluateMatches_MissingScopesAreSorted(t *testing.T) {
	matches := []fieldRuleMatch{
		{
			FieldName: "books",
			Rules: []Rule{
				{Name: "books", Scopes: ScopeConstraints{AllOf: []string{"zeta:scope", "delta:scope"}}},
			},
		},
		{
			FieldName: "authors",
			Rules: []Rule{
				{Name: "authors", Scopes: ScopeConstraints{AllOf: []string{"mike:scope", "alpha:scope"}}},
			},
		},
	}
	authCtx := authenticatedAuthCtx(nil, nil) // no scopes at all: every listed scope is missing
	authorized, missing := evaluateMatches(matches, authCtx)
	if authorized {
		t.Fatal("expected authorized to be false")
	}
	want := []string{"alpha:scope", "delta:scope", "mike:scope", "zeta:scope"}
	if !reflect.DeepEqual(missing, want) {
		t.Fatalf("expected sorted missing scopes %v, got %v", want, missing)
	}
}

// ---- helpers ----

func simpleGlobal(scope string) map[string]interface{} {
	return map[string]interface{}{"scopes": map[string]interface{}{"anyOf": []interface{}{scope}}}
}

func mustPolicy(t *testing.T, params map[string]interface{}) *GraphQLAuthzPolicy {
	t.Helper()
	p, err := GetPolicy(policy.PolicyMetadata{}, params)
	if err != nil {
		t.Fatalf("GetPolicy returned error: %v", err)
	}
	return p.(*GraphQLAuthzPolicy)
}

func assertImmediateStatus(t *testing.T, action policy.RequestAction, wantStatus int) {
	t.Helper()
	resp, ok := action.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("expected ImmediateResponse, got %#v", action)
	}
	if resp.StatusCode != wantStatus {
		t.Fatalf("expected status %d, got %d (body: %s)", wantStatus, resp.StatusCode, resp.Body)
	}
}
