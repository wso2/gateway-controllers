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
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

// createMockContext builds a RequestContext with a body and optional AuthContext,
// simulating that an upstream auth policy (mcp-auth/jwt-auth) already ran.
func createMockContext(method, path string, body []byte, authCtx *policy.AuthContext) *policy.RequestContext {
	return &policy.RequestContext{
		SharedContext: &policy.SharedContext{
			RequestID:     "test-request-id",
			Metadata:      make(map[string]any),
			AuthContext:   authCtx,
			OperationPath: path,
		},
		Headers: policy.NewHeaders(nil),
		Body: &policy.Body{
			Content: body,
			Present: true,
		},
		Path:   path,
		Method: method,
		Scheme: "http",
	}
}

func authenticatedAuthCtx(scopes map[string]bool, subject, issuer string, audiences []string, props map[string]string) *policy.AuthContext {
	return &policy.AuthContext{
		Authenticated: true,
		AuthType:      "jwt",
		Subject:       subject,
		Issuer:        issuer,
		Audience:      audiences,
		Scopes:        scopes,
		Properties:    props,
	}
}

func toolsParam(tools []any) map[string]any {
	return map[string]any{"tools": tools}
}

func toolCallBody(toolName string) []byte {
	b, _ := json.Marshal(map[string]any{
		"method": "tools/call",
		"params": map[string]any{"name": toolName},
	})
	return b
}

// ---- GetPolicy ----

func TestGetPolicy(t *testing.T) {
	params := toolsParam([]any{
		map[string]any{
			"name":           "my-tool",
			"requiredScopes": []any{"mcp:tools:read"},
		},
	})
	p, err := GetPolicy(policy.PolicyMetadata{}, params)
	if err != nil {
		t.Fatalf("GetPolicy returned error: %v", err)
	}
	if p == nil {
		t.Error("GetPolicy returned nil policy")
	}
}

func TestGetPolicy_EmptyParams(t *testing.T) {
	// Empty params should be valid (no rules configured means allow all)
	p, err := GetPolicy(policy.PolicyMetadata{}, map[string]any{})
	if err != nil {
		t.Errorf("Expected no error for empty params, got: %v", err)
	}
	if p == nil {
		t.Error("Expected non-nil policy for empty params")
	}
}

// ---- OnRequest: path/method guard ----

func TestOnRequest_SkipsNonMCP_GET(t *testing.T) {
	p := &McpAuthzPolicy{}
	ctx := createMockContext("GET", "/mcp", toolCallBody("tool1"), authenticatedAuthCtx(nil, "alice", "", nil, nil))
	action := p.OnRequestBody(context.Background(), ctx, map[string]any{})
	if action != nil {
		t.Errorf("Expected nil for non-POST, got %T", action)
	}
}

func TestOnRequest_SkipsNonMCP_Path(t *testing.T) {
	p := &McpAuthzPolicy{}
	ctx := createMockContext("POST", "/api/resource", toolCallBody("tool1"), authenticatedAuthCtx(nil, "alice", "", nil, nil))
	action := p.OnRequestBody(context.Background(), ctx, map[string]any{})
	if action != nil {
		t.Errorf("Expected nil for non-/mcp path, got %T", action)
	}
}

// ---- OnRequest: AuthContext checks ----

// A capability that IS targeted by a rule must fail closed when no AuthContext was populated.
// The policy must be given a rule for "tool1": a rule set that does not target the invocation means
// the invocation is not governed at all, which is asserted separately by the passthrough tests.
func TestOnRequest_NoAuthContext(t *testing.T) {
	p := &McpAuthzPolicy{Rules: []Rule{
		{
			Attribute:      Attribute{Type: "tool", Name: "tool1"},
			RequiredScopes: []string{"api:read"},
		},
	}}
	ctx := createMockContext("POST", "/mcp", toolCallBody("tool1"), nil)
	action := p.OnRequestBody(context.Background(), ctx, map[string]any{})
	resp, ok := action.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("Expected ImmediateResponse, got %T", action)
	}
	if resp.StatusCode != 401 {
		t.Errorf("Expected 401, got %d", resp.StatusCode)
	}
	if wwwAuth := resp.Headers[WWWAuthenticateHeader]; !strings.Contains(wwwAuth, `error="invalid_token"`) {
		t.Errorf("Expected error=\"invalid_token\" in WWW-Authenticate header, got: %s", wwwAuth)
	}
}

// As above, for an AuthContext left behind by an auth policy that ran but did not authenticate.
func TestOnRequest_NotAuthenticated(t *testing.T) {
	p := &McpAuthzPolicy{Rules: []Rule{
		{
			Attribute:      Attribute{Type: "tool", Name: "tool1"},
			RequiredScopes: []string{"api:read"},
		},
	}}
	authCtx := &policy.AuthContext{Authenticated: false, AuthType: "jwt"}
	ctx := createMockContext("POST", "/mcp", toolCallBody("tool1"), authCtx)
	action := p.OnRequestBody(context.Background(), ctx, map[string]any{})
	resp, ok := action.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("Expected ImmediateResponse, got %T", action)
	}
	if resp.StatusCode != 401 {
		t.Errorf("Expected 401, got %d", resp.StatusCode)
	}
	if wwwAuth := resp.Headers[WWWAuthenticateHeader]; !strings.Contains(wwwAuth, `error="invalid_token"`) {
		t.Errorf("Expected error=\"invalid_token\" in WWW-Authenticate header, got: %s", wwwAuth)
	}
}

// ---- OnRequest: body parsing ----

func TestOnRequest_InvalidMCPBody(t *testing.T) {
	p := &McpAuthzPolicy{}
	authCtx := authenticatedAuthCtx(nil, "alice", "", nil, nil)
	ctx := createMockContext("POST", "/mcp", []byte("not-json"), authCtx)
	action := p.OnRequestBody(context.Background(), ctx, map[string]any{})
	resp, ok := action.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("Expected ImmediateResponse, got %T", action)
	}
	if resp.StatusCode != 400 {
		t.Errorf("Expected 400, got %d", resp.StatusCode)
	}
	if wwwAuth := resp.Headers[WWWAuthenticateHeader]; !strings.Contains(wwwAuth, `error="invalid_request"`) {
		t.Errorf("Expected error=\"invalid_request\" in WWW-Authenticate header, got: %s", wwwAuth)
	}
}

// ---- OnRequest: rule matching ----

func TestOnRequest_NoMatchingRules(t *testing.T) {
	p := &McpAuthzPolicy{Rules: []Rule{
		{
			Attribute:      Attribute{Type: "tool", Name: "other-tool"},
			RequiredScopes: []string{"read"},
		},
	}}
	authCtx := authenticatedAuthCtx(map[string]bool{"read": true}, "alice", "", nil, nil)
	ctx := createMockContext("POST", "/mcp", toolCallBody("my-tool"), authCtx)
	action := p.OnRequestBody(context.Background(), ctx, map[string]any{})
	if action != nil {
		t.Errorf("Expected nil (allow) when no rules match, got %T", action)
	}
}

func TestOnRequest_ScopeCheckPasses(t *testing.T) {
	p := &McpAuthzPolicy{Rules: []Rule{
		{
			Attribute:      Attribute{Type: "tool", Name: "my-tool"},
			RequiredScopes: []string{"mcp:tools:read"},
		},
	}}
	authCtx := authenticatedAuthCtx(map[string]bool{"mcp:tools:read": true}, "alice", "", nil, nil)
	ctx := createMockContext("POST", "/mcp", toolCallBody("my-tool"), authCtx)
	action := p.OnRequestBody(context.Background(), ctx, map[string]any{})
	if action != nil {
		t.Errorf("Expected nil (authorized), got %T", action)
	}
}

func TestOnRequest_ScopeCheckFails(t *testing.T) {
	p := &McpAuthzPolicy{Rules: []Rule{
		{
			Attribute:      Attribute{Type: "tool", Name: "my-tool"},
			RequiredScopes: []string{"mcp:tools:write"},
		},
	}}
	authCtx := authenticatedAuthCtx(map[string]bool{"mcp:tools:read": true}, "alice", "", nil, nil)
	ctx := createMockContext("POST", "/mcp", toolCallBody("my-tool"), authCtx)
	action := p.OnRequestBody(context.Background(), ctx, map[string]any{})
	resp, ok := action.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("Expected ImmediateResponse (forbidden), got %T", action)
	}
	if resp.StatusCode != 403 {
		t.Errorf("Expected 403, got %d", resp.StatusCode)
	}
	// WWW-Authenticate header should mention the missing scope
	wwwAuth := resp.Headers[WWWAuthenticateHeader]
	if !strings.Contains(wwwAuth, "mcp:tools:write") {
		t.Errorf("Expected missing scope in WWW-Authenticate header, got: %s", wwwAuth)
	}
	if !strings.Contains(wwwAuth, "error=\"insufficient_scope\"") {
		t.Errorf("Expected error=\"insufficient_scope\" in WWW-Authenticate header, got: %s", wwwAuth)
	}
}

func TestOnRequest_ClaimCheckPasses_Sub(t *testing.T) {
	p := &McpAuthzPolicy{Rules: []Rule{
		{
			Attribute:      Attribute{Type: "tool", Name: "my-tool"},
			RequiredClaims: map[string]string{"sub": "alice"},
		},
	}}
	authCtx := authenticatedAuthCtx(nil, "alice", "", nil, nil)
	ctx := createMockContext("POST", "/mcp", toolCallBody("my-tool"), authCtx)
	action := p.OnRequestBody(context.Background(), ctx, map[string]any{})
	if action != nil {
		t.Errorf("Expected nil (authorized), got %T", action)
	}
}

func TestOnRequest_ClaimCheckFails(t *testing.T) {
	p := &McpAuthzPolicy{Rules: []Rule{
		{
			Attribute:      Attribute{Type: "tool", Name: "my-tool"},
			RequiredClaims: map[string]string{"sub": "bob"},
		},
	}}
	authCtx := authenticatedAuthCtx(nil, "alice", "", nil, nil)
	ctx := createMockContext("POST", "/mcp", toolCallBody("my-tool"), authCtx)
	action := p.OnRequestBody(context.Background(), ctx, map[string]any{})
	resp, ok := action.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("Expected ImmediateResponse (forbidden), got %T", action)
	}
	if resp.StatusCode != 403 {
		t.Errorf("Expected 403, got %d", resp.StatusCode)
	}
}

func TestOnRequest_WildcardRule(t *testing.T) {
	p := &McpAuthzPolicy{Rules: []Rule{
		{
			Attribute:      Attribute{Type: "tool", Name: "*"},
			RequiredScopes: []string{"mcp:tools:call"},
		},
	}}
	authCtx := authenticatedAuthCtx(map[string]bool{"mcp:tools:call": true}, "alice", "", nil, nil)
	ctx := createMockContext("POST", "/mcp", toolCallBody("any-tool"), authCtx)
	action := p.OnRequestBody(context.Background(), ctx, map[string]any{})
	if action != nil {
		t.Errorf("Expected nil (authorized by wildcard rule), got %T", action)
	}
}

// ---- AuthContext mutation on success ----

func TestOnRequest_Success_SetsAuthorizedAndAuthType(t *testing.T) {
	params := toolsParam([]any{
		map[string]any{
			"name":           "my-tool",
			"requiredScopes": []any{"mcp:tools:read"},
		},
	})
	p, _ := GetPolicy(policy.PolicyMetadata{}, params)
	rp := p.(policy.RequestPolicy)

	authCtx := &policy.AuthContext{
		Authenticated: true,
		AuthType:      McpOAuthAuthType,
		Scopes:        map[string]bool{"mcp:tools:read": true},
	}
	body := toolCallBody("my-tool")
	ctx := createMockContext("POST", "/mcp", body, authCtx)

	action := rp.OnRequestBody(context.Background(), ctx, params)

	if action != nil {
		t.Fatalf("Expected nil (pass-through), got %T", action)
	}
	if !ctx.SharedContext.AuthContext.Authorized {
		t.Error("Expected AuthContext.Authorized=true after successful authz")
	}
	if ctx.SharedContext.AuthContext.AuthType != McpOAuthzAuthType {
		t.Errorf("Expected AuthType=%q, got %q", McpOAuthzAuthType, ctx.SharedContext.AuthContext.AuthType)
	}
}

func TestOnRequest_Success_NonMcpOAuthAuthType_Unchanged(t *testing.T) {
	params := toolsParam([]any{
		map[string]any{
			"name":           "my-tool",
			"requiredScopes": []any{"mcp:tools:read"},
		},
	})
	p, _ := GetPolicy(policy.PolicyMetadata{}, params)
	rp := p.(policy.RequestPolicy)

	authCtx := &policy.AuthContext{
		Authenticated: true,
		AuthType:      "jwt",
		Scopes:        map[string]bool{"mcp:tools:read": true},
	}
	body := toolCallBody("my-tool")
	ctx := createMockContext("POST", "/mcp", body, authCtx)

	action := rp.OnRequestBody(context.Background(), ctx, params)

	if action != nil {
		t.Fatalf("Expected nil (pass-through), got %T", action)
	}
	if !ctx.SharedContext.AuthContext.Authorized {
		t.Error("Expected AuthContext.Authorized=true after successful authz")
	}
	// AuthType should be unchanged when it was not "mcp/oauth"
	if ctx.SharedContext.AuthContext.AuthType != "jwt" {
		t.Errorf("Expected AuthType='jwt' (unchanged), got %q", ctx.SharedContext.AuthContext.AuthType)
	}
}

// ============================================================================
// New scopes/claims (allOf + anyOf), precedence over deprecated fields, and
// deprecation logging — mirroring the jwt-auth change.
// ============================================================================

func assertAllowed(t *testing.T, action policy.RequestAction) {
	t.Helper()
	if action != nil {
		t.Fatalf("expected allow (nil), got %T", action)
	}
}

func assertForbidden(t *testing.T, action policy.RequestAction) {
	t.Helper()
	resp, ok := action.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("expected ImmediateResponse (forbidden), got %T", action)
	}
	if resp.StatusCode != 403 {
		t.Fatalf("expected 403, got %d", resp.StatusCode)
	}
}

func run(p *McpAuthzPolicy, authCtx *policy.AuthContext) policy.RequestAction {
	ctx := createMockContext("POST", "/mcp", toolCallBody("my-tool"), authCtx)
	return p.OnRequestBody(context.Background(), ctx, map[string]any{})
}

func TestOnRequest_Scopes_AllOf(t *testing.T) {
	p := &McpAuthzPolicy{Rules: []Rule{{
		Attribute: Attribute{Type: "tool", Name: "my-tool"},
		Scopes:    ScopeConstraints{AllOf: []string{"api:read", "api:deploy"}},
	}}}
	assertAllowed(t, run(p, authenticatedAuthCtx(map[string]bool{"api:read": true, "api:deploy": true}, "alice", "", nil, nil)))
	assertForbidden(t, run(p, authenticatedAuthCtx(map[string]bool{"api:read": true}, "alice", "", nil, nil)))
}

func TestOnRequest_Scopes_AnyOf(t *testing.T) {
	p := &McpAuthzPolicy{Rules: []Rule{{
		Attribute: Attribute{Type: "tool", Name: "my-tool"},
		Scopes:    ScopeConstraints{AnyOf: []string{"api:write", "api:update"}},
	}}}
	assertAllowed(t, run(p, authenticatedAuthCtx(map[string]bool{"api:update": true}, "alice", "", nil, nil)))
	assertForbidden(t, run(p, authenticatedAuthCtx(map[string]bool{"api:read": true}, "alice", "", nil, nil)))
}

func TestOnRequest_Scopes_AllOfAndAnyOf(t *testing.T) {
	p := &McpAuthzPolicy{Rules: []Rule{{
		Attribute: Attribute{Type: "tool", Name: "my-tool"},
		Scopes: ScopeConstraints{
			AllOf: []string{"api:read", "api:deploy"},
			AnyOf: []string{"api:write", "api:update"},
		},
	}}}
	// all allOf + one anyOf → allow
	assertAllowed(t, run(p, authenticatedAuthCtx(map[string]bool{"api:read": true, "api:deploy": true, "api:update": true}, "a", "", nil, nil)))
	// allOf satisfied but no anyOf → deny
	assertForbidden(t, run(p, authenticatedAuthCtx(map[string]bool{"api:read": true, "api:deploy": true}, "a", "", nil, nil)))
	// anyOf satisfied but allOf incomplete → deny
	assertForbidden(t, run(p, authenticatedAuthCtx(map[string]bool{"api:read": true, "api:write": true}, "a", "", nil, nil)))
}

func TestOnRequest_Claims_AllOf_AnyOf(t *testing.T) {
	// (sub = alice) AND (department in {platform, engineering})
	p := &McpAuthzPolicy{Rules: []Rule{{
		Attribute: Attribute{Type: "tool", Name: "my-tool"},
		Claims: ClaimConstraints{
			AllOf: []ClaimMatcher{{Claim: "sub", Values: []string{"alice"}}},
			AnyOf: []ClaimMatcher{{Claim: "department", Values: []string{"platform", "engineering"}}},
		},
	}}}
	assertAllowed(t, run(p, authenticatedAuthCtx(nil, "alice", "", nil, map[string]string{"department": "engineering"})))
	// allOf fails (sub != alice)
	assertForbidden(t, run(p, authenticatedAuthCtx(nil, "bob", "", nil, map[string]string{"department": "platform"})))
	// anyOf fails (department not in set)
	assertForbidden(t, run(p, authenticatedAuthCtx(nil, "alice", "", nil, map[string]string{"department": "sales"})))
}

func TestOnRequest_Claims_MultiValueMatcher(t *testing.T) {
	// A single matcher with multiple values is OR within the values.
	p := &McpAuthzPolicy{Rules: []Rule{{
		Attribute: Attribute{Type: "tool", Name: "my-tool"},
		Claims:    ClaimConstraints{AllOf: []ClaimMatcher{{Claim: "role", Values: []string{"admin", "superadmin"}}}},
	}}}
	assertAllowed(t, run(p, authenticatedAuthCtx(nil, "a", "", nil, map[string]string{"role": "superadmin"})))
	assertForbidden(t, run(p, authenticatedAuthCtx(nil, "a", "", nil, map[string]string{"role": "viewer"})))
}

func TestGetPolicy_NewFormat_ParsesAndEnforces(t *testing.T) {
	params := toolsParam([]any{map[string]any{
		"name":   "my-tool",
		"scopes": map[string]any{"allOf": []any{"api:read"}, "anyOf": []any{"api:write", "api:update"}},
		"claims": map[string]any{"allOf": []any{map[string]any{"claim": "sub", "values": []any{"alice"}}}},
	}})
	p, err := GetPolicy(policy.PolicyMetadata{}, params)
	if err != nil {
		t.Fatalf("GetPolicy: %v", err)
	}
	authz := p.(*McpAuthzPolicy)
	assertAllowed(t, run(authz, authenticatedAuthCtx(map[string]bool{"api:read": true, "api:write": true}, "alice", "", nil, nil)))
	// missing the anyOf scope → deny
	assertForbidden(t, run(authz, authenticatedAuthCtx(map[string]bool{"api:read": true}, "alice", "", nil, nil)))
}

func TestGetPolicy_Precedence_ScopesOverRequiredScopes(t *testing.T) {
	params := toolsParam([]any{map[string]any{
		"name":           "my-tool",
		"requiredScopes": []any{"old-scope"},
		"scopes":         map[string]any{"allOf": []any{"new-scope"}},
	}})
	p, err := GetPolicy(policy.PolicyMetadata{}, params)
	if err != nil {
		t.Fatalf("GetPolicy: %v", err)
	}
	// Token satisfies the deprecated requiredScopes but not the new scopes → new wins → deny.
	assertForbidden(t, run(p.(*McpAuthzPolicy), authenticatedAuthCtx(map[string]bool{"old-scope": true}, "a", "", nil, nil)))
}

func TestGetPolicy_Precedence_ClaimsOverRequiredClaims(t *testing.T) {
	params := toolsParam([]any{map[string]any{
		"name":           "my-tool",
		"requiredClaims": map[string]any{"sub": "alice"},
		"claims":         map[string]any{"allOf": []any{map[string]any{"claim": "sub", "values": []any{"bob"}}}},
	}})
	p, err := GetPolicy(policy.PolicyMetadata{}, params)
	if err != nil {
		t.Fatalf("GetPolicy: %v", err)
	}
	// subject alice passes deprecated requiredClaims but new claims needs bob → new wins → deny.
	assertForbidden(t, run(p.(*McpAuthzPolicy), authenticatedAuthCtx(nil, "alice", "", nil, nil)))
}

func TestGetPolicy_EmptyNewScopes_FallsBackToOld(t *testing.T) {
	// scopes present but empty → treated as unset (D1); deprecated requiredScopes applies.
	params := toolsParam([]any{map[string]any{
		"name":           "my-tool",
		"scopes":         map[string]any{},
		"requiredScopes": []any{"read"},
	}})
	p, err := GetPolicy(policy.PolicyMetadata{}, params)
	if err != nil {
		t.Fatalf("GetPolicy: %v", err)
	}
	assertAllowed(t, run(p.(*McpAuthzPolicy), authenticatedAuthCtx(map[string]bool{"read": true}, "a", "", nil, nil)))
}

func TestGetPolicy_MalformedScopes_Error(t *testing.T) {
	// Malformed new scopes → fail closed at load (D2).
	params := toolsParam([]any{map[string]any{"name": "t", "scopes": "not-an-object"}})
	if _, err := GetPolicy(policy.PolicyMetadata{}, params); err == nil {
		t.Fatal("expected error for malformed scopes")
	}
}

func TestLogDeprecation(t *testing.T) {
	capture := func(params map[string]any) string {
		var buf bytes.Buffer
		prev := slog.Default()
		slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
		defer slog.SetDefault(prev)
		if _, err := GetPolicy(policy.PolicyMetadata{}, params); err != nil {
			t.Fatalf("GetPolicy: %v", err)
		}
		return buf.String()
	}

	// New only → no warning.
	if out := capture(toolsParam([]any{map[string]any{
		"name": "t", "scopes": map[string]any{"allOf": []any{"api:read"}},
	}})); strings.Contains(out, "deprecated") {
		t.Errorf("expected no deprecation warning, got: %s", out)
	}

	// Deprecated requiredScopes only → migrate warning.
	if out := capture(toolsParam([]any{map[string]any{
		"name": "t", "requiredScopes": []any{"api:read"},
	}})); !strings.Contains(out, "'requiredScopes' is deprecated; migrate") {
		t.Errorf("expected migrate warning, got: %s", out)
	}

	// Both new and deprecated on the same rule → "ignored" variant.
	if out := capture(toolsParam([]any{map[string]any{
		"name": "t", "requiredScopes": []any{"api:read"},
		"scopes": map[string]any{"allOf": []any{"api:read"}},
	}})); !strings.Contains(out, "ignored where 'scopes' is configured") {
		t.Errorf("expected 'ignored' warning, got: %s", out)
	}

	// Deprecated requiredClaims → warning.
	if out := capture(toolsParam([]any{map[string]any{
		"name": "t", "requiredClaims": map[string]any{"sub": "alice"},
	}})); !strings.Contains(out, "'requiredClaims' is deprecated") {
		t.Errorf("expected requiredClaims warning, got: %s", out)
	}
}

// Claim matchers over the iss and aud (slice) branches of claimMatcherMatches.
func TestOnRequest_Claims_AudAndIss(t *testing.T) {
	p := &McpAuthzPolicy{Rules: []Rule{{
		Attribute: Attribute{Type: "tool", Name: "my-tool"},
		Claims: ClaimConstraints{AllOf: []ClaimMatcher{
			{Claim: "iss", Values: []string{"https://idp.example.com"}},
			{Claim: "aud", Values: []string{"api://target"}},
		}},
	}}}
	// iss matches and aud slice contains the value → allow
	assertAllowed(t, run(p, authenticatedAuthCtx(nil, "a", "https://idp.example.com", []string{"other", "api://target"}, nil)))
	// aud slice lacks the value → deny
	assertForbidden(t, run(p, authenticatedAuthCtx(nil, "a", "https://idp.example.com", []string{"other"}, nil)))
	// iss mismatch → deny
	assertForbidden(t, run(p, authenticatedAuthCtx(nil, "a", "https://evil.example.com", []string{"api://target"}, nil)))
}

// A configured claim that is entirely absent from the AuthContext must deny (fail-closed).
func TestOnRequest_Claims_MissingClaimDenies(t *testing.T) {
	p := &McpAuthzPolicy{Rules: []Rule{{
		Attribute: Attribute{Type: "tool", Name: "my-tool"},
		Claims:    ClaimConstraints{AllOf: []ClaimMatcher{{Claim: "department", Values: []string{"platform"}}}},
	}}}
	// No Properties at all → deny
	assertForbidden(t, run(p, authenticatedAuthCtx(nil, "a", "", nil, nil)))
	// Present but different value → deny
	assertForbidden(t, run(p, authenticatedAuthCtx(nil, "a", "", nil, map[string]string{"department": "sales"})))
}

// New scopes on one dimension + deprecated requiredClaims on the other; both enforced independently.
func TestGetPolicy_Mixed_NewScopes_OldClaims(t *testing.T) {
	params := toolsParam([]any{map[string]any{
		"name":           "my-tool",
		"scopes":         map[string]any{"allOf": []any{"api:read"}},
		"requiredClaims": map[string]any{"sub": "alice"},
	}})
	p, err := GetPolicy(policy.PolicyMetadata{}, params)
	if err != nil {
		t.Fatalf("GetPolicy: %v", err)
	}
	authz := p.(*McpAuthzPolicy)
	// both satisfied → allow
	assertAllowed(t, run(authz, authenticatedAuthCtx(map[string]bool{"api:read": true}, "alice", "", nil, nil)))
	// scope ok but deprecated claim fails → deny
	assertForbidden(t, run(authz, authenticatedAuthCtx(map[string]bool{"api:read": true}, "bob", "", nil, nil)))
	// deprecated claim ok but scope fails → deny
	assertForbidden(t, run(authz, authenticatedAuthCtx(map[string]bool{"other": true}, "alice", "", nil, nil)))
}

// Reverse mix: deprecated requiredScopes (OR) + new claims (allOf). Both dimensions are resolved
// independently, so this direction must work the same as Mixed_NewScopes_OldClaims.
func TestGetPolicy_Mixed_OldScopes_NewClaims(t *testing.T) {
	params := toolsParam([]any{map[string]any{
		"name":           "my-tool",
		"requiredScopes": []any{"api:read"},
		"claims":         map[string]any{"allOf": []any{map[string]any{"claim": "sub", "values": []any{"alice"}}}},
	}})
	p, err := GetPolicy(policy.PolicyMetadata{}, params)
	if err != nil {
		t.Fatalf("GetPolicy: %v", err)
	}
	authz := p.(*McpAuthzPolicy)
	// both satisfied → allow
	assertAllowed(t, run(authz, authenticatedAuthCtx(map[string]bool{"api:read": true}, "alice", "", nil, nil)))
	// deprecated scope ok but new claim fails → deny
	assertForbidden(t, run(authz, authenticatedAuthCtx(map[string]bool{"api:read": true}, "bob", "", nil, nil)))
	// new claim ok but deprecated scope fails → deny
	assertForbidden(t, run(authz, authenticatedAuthCtx(map[string]bool{"other": true}, "alice", "", nil, nil)))
}

// mcp-authz evaluates ALL matching rules (specific + wildcard) with AND semantics.
func TestOnRequest_MultipleMatchingRules_AllMustPass(t *testing.T) {
	p := &McpAuthzPolicy{Rules: []Rule{
		{Attribute: Attribute{Type: "tool", Name: "*"}, Scopes: ScopeConstraints{AllOf: []string{"base"}}},
		{Attribute: Attribute{Type: "tool", Name: "my-tool"}, Scopes: ScopeConstraints{AllOf: []string{"api:deploy"}}},
	}}
	// both rules satisfied → allow
	assertAllowed(t, run(p, authenticatedAuthCtx(map[string]bool{"base": true, "api:deploy": true}, "a", "", nil, nil)))
	// wildcard rule fails (no "base") → deny even though the specific rule passes
	assertForbidden(t, run(p, authenticatedAuthCtx(map[string]bool{"api:deploy": true}, "a", "", nil, nil)))
	// specific rule fails (no "api:deploy") → deny even though the wildcard rule passes
	assertForbidden(t, run(p, authenticatedAuthCtx(map[string]bool{"base": true}, "a", "", nil, nil)))
}

// New format works on a non-tool rule array (resources, keyed by uri).
func TestGetPolicy_NewFormat_ResourceRule(t *testing.T) {
	params := map[string]any{"resources": []any{map[string]any{
		"name":   "file://data",
		"scopes": map[string]any{"anyOf": []any{"res:read", "res:admin"}},
	}}}
	p, err := GetPolicy(policy.PolicyMetadata{}, params)
	if err != nil {
		t.Fatalf("GetPolicy: %v", err)
	}
	authz := p.(*McpAuthzPolicy)
	body, _ := json.Marshal(map[string]any{"method": "resources/read", "params": map[string]any{"uri": "file://data"}})

	ctx := createMockContext("POST", "/mcp", body, authenticatedAuthCtx(map[string]bool{"res:admin": true}, "a", "", nil, nil))
	assertAllowed(t, authz.OnRequestBody(context.Background(), ctx, map[string]any{}))

	ctx = createMockContext("POST", "/mcp", body, authenticatedAuthCtx(map[string]bool{"other": true}, "a", "", nil, nil))
	assertForbidden(t, authz.OnRequestBody(context.Background(), ctx, map[string]any{}))
}

// ---- TypedProperties (structured claim) matching ----

// A multi-valued (array) custom claim carried in AuthContext.TypedProperties is matched as a set —
// the fix for the flattened-Properties limitation. The value keeps its native []interface{} type,
// exactly as jwt-auth stores it from the parsed token.
func TestOnRequest_Claims_MultiValuedClaimViaTypedProperties(t *testing.T) {
	p := &McpAuthzPolicy{Rules: []Rule{{
		Attribute: Attribute{Type: "tool", Name: "my-tool"},
		Claims:    ClaimConstraints{AllOf: []ClaimMatcher{{Claim: "roles", Values: []string{"admin"}}}},
	}}}

	// "admin" is one element of the token's roles array → authorized.
	allowed := &policy.AuthContext{
		Authenticated:   true,
		AuthType:        "jwt",
		TypedProperties: map[string]interface{}{"roles": []interface{}{"developer", "admin"}},
	}
	assertAllowed(t, run(p, allowed))

	// roles present but "admin" not among them → denied.
	denied := &policy.AuthContext{
		Authenticated:   true,
		AuthType:        "jwt",
		TypedProperties: map[string]interface{}{"roles": []interface{}{"developer", "viewer"}},
	}
	assertForbidden(t, run(p, denied))
}

// A scalar custom claim carried in TypedProperties (native string) is matched directly.
func TestOnRequest_Claims_ScalarClaimViaTypedProperties(t *testing.T) {
	p := &McpAuthzPolicy{Rules: []Rule{{
		Attribute: Attribute{Type: "tool", Name: "my-tool"},
		Claims:    ClaimConstraints{AllOf: []ClaimMatcher{{Claim: "department", Values: []string{"platform"}}}},
	}}}
	authCtx := &policy.AuthContext{
		Authenticated:   true,
		AuthType:        "jwt",
		TypedProperties: map[string]interface{}{"department": "platform"},
	}
	assertAllowed(t, run(p, authCtx))
}

// When TypedProperties is absent (e.g., an auth policy that doesn't populate it), matching falls
// back to the flattened Properties string — preserving the previous behavior.
func TestOnRequest_Claims_FallsBackToProperties(t *testing.T) {
	p := &McpAuthzPolicy{Rules: []Rule{{
		Attribute: Attribute{Type: "tool", Name: "my-tool"},
		Claims:    ClaimConstraints{AllOf: []ClaimMatcher{{Claim: "department", Values: []string{"platform"}}}},
	}}}
	// No TypedProperties; scalar claim in Properties → matches via fallback.
	authCtx := &policy.AuthContext{
		Authenticated: true,
		AuthType:      "jwt",
		Properties:    map[string]string{"department": "platform"},
	}
	assertAllowed(t, run(p, authCtx))
}

// ---- Rule must define at least one authorization condition ----

// A rule with only a name (no claims/scopes/requiredClaims/requiredScopes) is rejected: an
// unconditional rule would grant access to anyone and defeat the policy's purpose.
func TestGetPolicy_RuleWithoutAnyCondition_IsRejected(t *testing.T) {
	_, err := GetPolicy(policy.PolicyMetadata{}, toolsParam([]any{
		map[string]any{"name": "my-tool"},
	}))
	if err == nil {
		t.Fatal("expected GetPolicy to reject a rule with no scopes/claims condition, got nil error")
	}
}

// ---- Deprecated requiredClaims preserves exact-scalar semantics (no array/set matching) ----

// authCtxWithArrayRole mimics how an auth policy (jwt-auth) populates a multi-valued claim: the
// flattened string form in Properties and the native array in TypedProperties.
func authCtxWithArrayRole() *policy.AuthContext {
	return &policy.AuthContext{
		Authenticated:   true,
		AuthType:        "jwt",
		Properties:      map[string]string{"role": `["admin","editor"]`},
		TypedProperties: map[string]interface{}{"role": []interface{}{"admin", "editor"}},
	}
}

// Regression guard: a scalar requiredClaims entry must NOT match an array-valued claim. This is the
// behavior mcp-authz had before TypedProperties — the deprecated field keeps exact-scalar matching
// so upgrading the policy version cannot silently change an authorization decision.
func TestRequiredClaims_Deprecated_DoesNotMatchArrayClaim(t *testing.T) {
	p, err := GetPolicy(policy.PolicyMetadata{}, toolsParam([]any{map[string]any{
		"name":           "my-tool",
		"requiredClaims": map[string]any{"role": "admin"},
	}}))
	if err != nil {
		t.Fatalf("GetPolicy: %v", err)
	}
	assertForbidden(t, run(p.(*McpAuthzPolicy), authCtxWithArrayRole()))
}

// A scalar requiredClaims entry still matches a scalar claim (old positive behavior preserved).
func TestRequiredClaims_Deprecated_MatchesScalarClaim(t *testing.T) {
	p, err := GetPolicy(policy.PolicyMetadata{}, toolsParam([]any{map[string]any{
		"name":           "my-tool",
		"requiredClaims": map[string]any{"role": "admin"},
	}}))
	if err != nil {
		t.Fatalf("GetPolicy: %v", err)
	}
	authCtx := &policy.AuthContext{
		Authenticated:   true,
		AuthType:        "jwt",
		Properties:      map[string]string{"role": "admin"},
		TypedProperties: map[string]interface{}{"role": "admin"},
	}
	assertAllowed(t, run(p.(*McpAuthzPolicy), authCtx))
}

// Contrast: the NEW `claims` field DOES match the same array-valued claim, confirming the split —
// only the deprecated field keeps exact-scalar semantics; the new field gets array-aware matching.
func TestClaims_NewField_MatchesArrayClaim_WhereRequiredClaimsDoesNot(t *testing.T) {
	p, err := GetPolicy(policy.PolicyMetadata{}, toolsParam([]any{map[string]any{
		"name":   "my-tool",
		"claims": map[string]any{"allOf": []any{map[string]any{"claim": "role", "values": []any{"admin"}}}},
	}}))
	if err != nil {
		t.Fatalf("GetPolicy: %v", err)
	}
	assertAllowed(t, run(p.(*McpAuthzPolicy), authCtxWithArrayRole()))
}

// These tests cover the interaction between the MCP authentication policy's exception lists and
// this policy's rule set. When mcp-auth excludes a capability from authentication it returns early
// without populating SharedContext.AuthContext, so the invocation reaches this policy with no
// identity at all. Rule matching, not the presence of an AuthContext, decides whether this policy
// governs the invocation.
//
// The passthrough assertions below are paired deliberately with fail-closed assertions for a
// governed capability: the failure mode of a careless fix here is silently dropping enforcement.

// ---- helpers ----

// mcpBody builds a JSON-RPC MCP request body for an arbitrary method and params.
func mcpBody(method string, params map[string]any) []byte {
	req := map[string]any{"jsonrpc": "2.0", "id": 1, "method": method}
	if params != nil {
		req["params"] = params
	}
	b, _ := json.Marshal(req)
	return b
}

// runBody evaluates the policy against a POST /mcp request carrying the given body and AuthContext.
func runBody(p *McpAuthzPolicy, body []byte, authCtx *policy.AuthContext) policy.RequestAction {
	ctx := createMockContext("POST", "/mcp", body, authCtx)
	return p.OnRequestBody(context.Background(), ctx, map[string]any{})
}

// toolAOnlyPolicy governs tool "toolA" and nothing else. "toolB" stands for a capability listed in
// the mcp-auth exceptions and given no authorization rule.
func toolAOnlyPolicy() *McpAuthzPolicy {
	return &McpAuthzPolicy{Rules: []Rule{
		{
			Attribute:      Attribute{Type: "tool", Name: "toolA"},
			RequiredScopes: []string{"scope:a"},
		},
	}}
}

func assertPassthrough(t *testing.T, action policy.RequestAction, whatFor string) {
	t.Helper()
	if action != nil {
		if resp, ok := action.(policy.ImmediateResponse); ok {
			t.Fatalf("%s: expected passthrough (nil), got %d: %s", whatFor, resp.StatusCode, string(resp.Body))
		}
		t.Fatalf("%s: expected passthrough (nil), got %T", whatFor, action)
	}
}

func assertStatus(t *testing.T, action policy.RequestAction, want int, whatFor string) policy.ImmediateResponse {
	t.Helper()
	resp, ok := action.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("%s: expected ImmediateResponse with status %d, got %T (passthrough)", whatFor, want, action)
	}
	if resp.StatusCode != want {
		t.Fatalf("%s: expected %d, got %d: %s", whatFor, want, resp.StatusCode, string(resp.Body))
	}
	return resp
}

func assertWwwAuthContains(t *testing.T, resp policy.ImmediateResponse, want string) {
	t.Helper()
	if got := resp.Headers[WWWAuthenticateHeader]; !strings.Contains(got, want) {
		t.Errorf("expected %q in WWW-Authenticate header, got: %s", want, got)
	}
}

// ---- the reported bug: an mcp-auth-excluded capability must pass through ----

// Tool B is excluded from authentication by mcp-auth and targeted by no authorization rule, so it
// arrives with a nil AuthContext. It must not be rejected.
func TestAuthExcludedTool_NoBearerToken_PassesThrough(t *testing.T) {
	action := runBody(toolAOnlyPolicy(), mcpBody("tools/call", map[string]any{"name": "toolB"}), nil)
	assertPassthrough(t, action, "auth-excluded toolB with no bearer token")
}

// An unrelated token does not drag an ungoverned capability into the decision path. mcp-auth never
// validates a token for an excluded capability, so the AuthContext stays nil either way; this pins
// that the excluded capability does not start caring about token validity.
func TestAuthExcludedTool_UnrelatedBearerToken_PassesThrough(t *testing.T) {
	unrelated := authenticatedAuthCtx(map[string]bool{"scope:unrelated": true}, "bob", "https://other.idp", nil, nil)
	action := runBody(toolAOnlyPolicy(), mcpBody("tools/call", map[string]any{"name": "toolB"}), unrelated)
	assertPassthrough(t, action, "auth-excluded toolB with an unrelated bearer token")
}

// An AuthContext left behind by an auth policy that ran and failed must not change the outcome for a
// capability this policy does not govern.
func TestAuthExcludedTool_FailedAuthContext_PassesThrough(t *testing.T) {
	failed := &policy.AuthContext{Authenticated: false, AuthType: "mcp/oauth"}
	action := runBody(toolAOnlyPolicy(), mcpBody("tools/call", map[string]any{"name": "toolB"}), failed)
	assertPassthrough(t, action, "auth-excluded toolB with a failed AuthContext")
}

// The same exclusion scenario expressed with the scopes/claims allOf-anyOf rule shapes rather than
// the deprecated requiredScopes. Rule matching keys off the attribute type and name alone, so the
// condition shape must not affect whether an invocation is governed.
func TestAuthExcludedTool_NewStyleRuleShapes_PassThrough(t *testing.T) {
	cases := []struct {
		name string
		rule Rule
	}{
		{"scopes.allOf", Rule{
			Attribute: Attribute{Type: "tool", Name: "toolA"},
			Scopes:    ScopeConstraints{AllOf: []string{"scope:a", "scope:b"}},
		}},
		{"scopes.anyOf", Rule{
			Attribute: Attribute{Type: "tool", Name: "toolA"},
			Scopes:    ScopeConstraints{AnyOf: []string{"scope:a", "scope:b"}},
		}},
		{"claims.allOf", Rule{
			Attribute: Attribute{Type: "tool", Name: "toolA"},
			Claims:    ClaimConstraints{AllOf: []ClaimMatcher{{Claim: "role", Values: []string{"admin"}}}},
		}},
		{"claims.anyOf", Rule{
			Attribute: Attribute{Type: "tool", Name: "toolA"},
			Claims:    ClaimConstraints{AnyOf: []ClaimMatcher{{Claim: "role", Values: []string{"admin", "ops"}}}},
		}},
		{"scopes and claims combined", Rule{
			Attribute: Attribute{Type: "tool", Name: "toolA"},
			Scopes:    ScopeConstraints{AllOf: []string{"scope:a"}},
			Claims:    ClaimConstraints{AllOf: []ClaimMatcher{{Claim: "role", Values: []string{"admin"}}}},
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := &McpAuthzPolicy{Rules: []Rule{tc.rule}}

			// The excluded, ungoverned capability passes through with no identity at all.
			assertPassthrough(t, runBody(p, mcpBody("tools/call", map[string]any{"name": "toolB"}), nil),
				"auth-excluded toolB against a "+tc.name+" rule for toolA")

			// The governed capability still fails closed with no identity.
			assertStatus(t, runBody(p, mcpBody("tools/call", map[string]any{"name": "toolA"}), nil), 401,
				"governed toolA against a "+tc.name+" rule")
		})
	}
}

// ---- the other half: a governed capability still fails closed ----

func TestGovernedTool_NoAuthContext_FailsClosed(t *testing.T) {
	action := runBody(toolAOnlyPolicy(), mcpBody("tools/call", map[string]any{"name": "toolA"}), nil)
	resp := assertStatus(t, action, 401, "governed toolA with no AuthContext")
	assertWwwAuthContains(t, resp, `error="invalid_token"`)
}

func TestGovernedTool_NotAuthenticated_FailsClosed(t *testing.T) {
	failed := &policy.AuthContext{Authenticated: false, AuthType: "mcp/oauth"}
	action := runBody(toolAOnlyPolicy(), mcpBody("tools/call", map[string]any{"name": "toolA"}), failed)
	assertStatus(t, action, 401, "governed toolA with an unauthenticated AuthContext")
}

func TestGovernedTool_AuthenticatedMissingScope_Forbidden(t *testing.T) {
	authCtx := authenticatedAuthCtx(map[string]bool{"scope:other": true}, "alice", "", nil, nil)
	action := runBody(toolAOnlyPolicy(), mcpBody("tools/call", map[string]any{"name": "toolA"}), authCtx)
	resp := assertStatus(t, action, 403, "governed toolA missing the required scope")
	assertWwwAuthContains(t, resp, `error="insufficient_scope"`)
	assertWwwAuthContains(t, resp, `scope="scope:a"`)
}

func TestGovernedTool_AuthenticatedWithScope_Allowed(t *testing.T) {
	authCtx := authenticatedAuthCtx(map[string]bool{"scope:a": true}, "alice", "", nil, nil)
	action := runBody(toolAOnlyPolicy(), mcpBody("tools/call", map[string]any{"name": "toolA"}), authCtx)
	assertPassthrough(t, action, "governed toolA with the required scope")
	if !authCtx.Authorized {
		t.Error("expected Authorized=true after a successful authorization decision")
	}
}

// ---- non-capability methods: the MCP handshake must survive ----

// With methods.enabled=false in mcp-auth, initialize/ping are auth-exempt and arrive with no
// AuthContext. Rejecting them breaks the handshake before any tool is ever invoked.
func TestNonCapabilityMethods_NoAuthContext_PassThrough(t *testing.T) {
	cases := []struct {
		name   string
		method string
		params map[string]any
	}{
		{"initialize", "initialize", map[string]any{"protocolVersion": "2025-06-18"}},
		{"ping", "ping", nil},
		{"notifications/initialized", "notifications/initialized", nil},
		{"tools/list", "tools/list", nil},
		{"resources/list", "resources/list", nil},
		{"prompts/list", "prompts/list", nil},
		{"completion/complete", "completion/complete", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			action := runBody(toolAOnlyPolicy(), mcpBody(tc.method, tc.params), nil)
			assertPassthrough(t, action, tc.method+" with no AuthContext")
		})
	}
}

// tools/list maps to attribute type "tool" with an empty name; the empty name must stop it from
// matching the toolA rule rather than the rule set happening not to contain it.
func TestToolsList_WithGoverningToolRule_PassesThrough(t *testing.T) {
	action := runBody(toolAOnlyPolicy(), mcpBody("tools/list", nil), nil)
	assertPassthrough(t, action, "tools/list against a tool rule set")
}

// ---- resources and prompts ----

func TestResourceRead_GovernedAndUngoverned(t *testing.T) {
	p := &McpAuthzPolicy{Rules: []Rule{{
		Attribute:      Attribute{Type: "resource", Name: "file://finance/reports"},
		RequiredScopes: []string{"finance:read"},
	}}}

	governed := runBody(p, mcpBody("resources/read", map[string]any{"uri": "file://finance/reports"}), nil)
	assertStatus(t, governed, 401, "governed resource with no AuthContext")

	ungoverned := runBody(p, mcpBody("resources/read", map[string]any{"uri": "file://public/readme"}), nil)
	assertPassthrough(t, ungoverned, "ungoverned resource with no AuthContext")
}

func TestPromptGet_GovernedAndUngoverned(t *testing.T) {
	p := &McpAuthzPolicy{Rules: []Rule{{
		Attribute:      Attribute{Type: "prompt", Name: "summarize"},
		RequiredScopes: []string{"prompt:use"},
	}}}

	governed := runBody(p, mcpBody("prompts/get", map[string]any{"name": "summarize"}), nil)
	assertStatus(t, governed, 401, "governed prompt with no AuthContext")

	ungoverned := runBody(p, mcpBody("prompts/get", map[string]any{"name": "greet"}), nil)
	assertPassthrough(t, ungoverned, "ungoverned prompt with no AuthContext")
}

// A rule of one attribute type must not govern a same-named capability of another type. Before the
// reordering this mismatch was masked by the unconditional 401.
func TestCrossTypeRule_DoesNotGovern(t *testing.T) {
	p := &McpAuthzPolicy{Rules: []Rule{{
		Attribute:      Attribute{Type: "resource", Name: "toolA"},
		RequiredScopes: []string{"scope:a"},
	}}}
	action := runBody(p, mcpBody("tools/call", map[string]any{"name": "toolA"}), nil)
	assertPassthrough(t, action, "tools/call toolA against a resource rule named toolA")
}

// ---- wildcard rules: a recorded decision, not an accident ----

// KNOWN LIMITATION. A wildcard rule governs every capability of its type, including one that
// mcp-auth excluded from authentication, so such an invocation is rejected for want of an identity.
// Deciding that an explicit auth exclusion should beat a wildcard rule requires mcp-auth to publish
// its skip decision into shared context, since a nil AuthContext cannot distinguish "auth was
// deliberately skipped" from "auth is absent". Tracked separately; do not flip this assertion
// without making that change.
func TestWildcardRule_GovernsAuthExcludedTool_KnownLimitation(t *testing.T) {
	p := &McpAuthzPolicy{Rules: []Rule{{
		Attribute:      Attribute{Type: "tool", Name: "*"},
		RequiredScopes: []string{"scope:any"},
	}}}
	action := runBody(p, mcpBody("tools/call", map[string]any{"name": "toolB"}), nil)
	assertStatus(t, action, 401, "auth-excluded toolB against a wildcard tool rule")
}

func TestWildcardRule_AuthenticatedWithScope_Allowed(t *testing.T) {
	p := &McpAuthzPolicy{Rules: []Rule{{
		Attribute:      Attribute{Type: "tool", Name: "*"},
		RequiredScopes: []string{"scope:any"},
	}}}
	authCtx := authenticatedAuthCtx(map[string]bool{"scope:any": true}, "alice", "", nil, nil)
	action := runBody(p, mcpBody("tools/call", map[string]any{"name": "toolB"}), authCtx)
	assertPassthrough(t, action, "toolB against a satisfied wildcard tool rule")
}

// An empty attribute name must not match a wildcard rule either.
func TestWildcardRule_ToolsList_PassesThrough(t *testing.T) {
	p := &McpAuthzPolicy{Rules: []Rule{{
		Attribute:      Attribute{Type: "tool", Name: "*"},
		RequiredScopes: []string{"scope:any"},
	}}}
	action := runBody(p, mcpBody("tools/list", nil), nil)
	assertPassthrough(t, action, "tools/list against a wildcard tool rule")
}

// ---- rule matching edge cases ----

// A policy with no rules governs nothing, regardless of authentication state.
func TestZeroRules_PassThrough(t *testing.T) {
	assertPassthrough(t, runBody(&McpAuthzPolicy{}, mcpBody("tools/call", map[string]any{"name": "toolA"}), nil),
		"zero-rule policy with no AuthContext")

	authCtx := authenticatedAuthCtx(map[string]bool{"scope:a": true}, "alice", "", nil, nil)
	assertPassthrough(t, runBody(&McpAuthzPolicy{}, mcpBody("tools/call", map[string]any{"name": "toolA"}), authCtx),
		"zero-rule policy with an authenticated AuthContext")
}

// When an exact rule and a wildcard rule both match, every matching rule must pass and the unmet
// scopes of all of them are reported.
func TestExactAndWildcardBothMatch(t *testing.T) {
	p := &McpAuthzPolicy{Rules: []Rule{
		{Attribute: Attribute{Type: "tool", Name: "toolA"}, RequiredScopes: []string{"scope:a"}},
		{Attribute: Attribute{Type: "tool", Name: "*"}, RequiredScopes: []string{"scope:x"}},
	}}

	partial := authenticatedAuthCtx(map[string]bool{"scope:a": true}, "alice", "", nil, nil)
	resp := assertStatus(t, runBody(p, mcpBody("tools/call", map[string]any{"name": "toolA"}), partial), 403,
		"toolA satisfying only the exact rule")
	assertWwwAuthContains(t, resp, `scope="scope:x"`)

	full := authenticatedAuthCtx(map[string]bool{"scope:a": true, "scope:x": true}, "alice", "", nil, nil)
	assertPassthrough(t, runBody(p, mcpBody("tools/call", map[string]any{"name": "toolA"}), full),
		"toolA satisfying both the exact and wildcard rules")
}

// Rule names are matched exactly or as a standalone "*"; they are not prefixes or patterns.
func TestRuleNameMatchIsExact_NotPrefix(t *testing.T) {
	p := &McpAuthzPolicy{Rules: []Rule{{
		Attribute:      Attribute{Type: "resource", Name: "file://finance/reports"},
		RequiredScopes: []string{"finance:read"},
	}}}
	action := runBody(p, mcpBody("resources/read", map[string]any{"uri": "file://finance/reports/q1"}), nil)
	assertPassthrough(t, action, "a URI under a governed prefix is not itself governed")
}

func TestRuleNameMatchIsCaseSensitive(t *testing.T) {
	action := runBody(toolAOnlyPolicy(), mcpBody("tools/call", map[string]any{"name": "toola"}), nil)
	assertPassthrough(t, action, "differently-cased tool name")
}

// A method rule fires for methods of the form <type>/<verb>...
func TestMethodRule_MatchesSlashMethod(t *testing.T) {
	p := &McpAuthzPolicy{Rules: []Rule{{
		Attribute:      Attribute{Type: "method", Name: "tools/list"},
		RequiredScopes: []string{"scope:list"},
	}}}
	assertStatus(t, runBody(p, mcpBody("tools/list", nil), nil), 401, "governed tools/list with no AuthContext")
}

// ...but not for a bare method like initialize, because the attribute type is derived from the
// method prefix and a method with no "/" is skipped before rule matching runs. A methods rule naming
// a bare method is therefore dead config today. Pinned as existing behaviour, tracked separately;
// this fix deliberately does not change it.
func TestMethodRule_BareMethodIsDeadConfig(t *testing.T) {
	p := &McpAuthzPolicy{Rules: []Rule{{
		Attribute:      Attribute{Type: "method", Name: "initialize"},
		RequiredScopes: []string{"scope:init"},
	}}}
	assertPassthrough(t, runBody(p, mcpBody("initialize", nil), nil), "initialize against a method rule naming it")
}

func TestMethodWildcardRule_GovernsSlashMethods(t *testing.T) {
	p := &McpAuthzPolicy{Rules: []Rule{{
		Attribute:      Attribute{Type: "method", Name: "*"},
		RequiredScopes: []string{"scope:any"},
	}}}
	assertStatus(t, runBody(p, mcpBody("tools/call", map[string]any{"name": "toolB"}), nil), 401,
		"toolB against a method wildcard rule")
}

// ---- malformed and hostile input ----

// The policy previously dereferenced reqCtx.Body without a nil check.
func TestNilBody_NoPanic(t *testing.T) {
	authCtx := authenticatedAuthCtx(map[string]bool{"scope:a": true}, "alice", "", nil, nil)
	ctx := createMockContext("POST", "/mcp", nil, authCtx)
	ctx.Body = nil
	assertPassthrough(t, toolAOnlyPolicy().OnRequestBody(context.Background(), ctx, map[string]any{}), "nil Body")
}

func TestBodyNotPresent_NoPanic(t *testing.T) {
	ctx := createMockContext("POST", "/mcp", nil, nil)
	ctx.Body.Present = false
	assertPassthrough(t, toolAOnlyPolicy().OnRequestBody(context.Background(), ctx, map[string]any{}), "absent Body")
}

// A nil SharedContext must not panic on the fail-closed path.
func TestNilSharedContext_GovernedTool_FailsClosed(t *testing.T) {
	ctx := createMockContext("POST", "/mcp", mcpBody("tools/call", map[string]any{"name": "toolA"}), nil)
	ctx.SharedContext = nil
	action := toolAOnlyPolicy().OnRequestBody(context.Background(), ctx, map[string]any{})
	assertStatus(t, action, 401, "governed toolA with a nil SharedContext")
}

// Parsing now precedes the identity check, so a malformed body is reported as 400 rather than 401.
// This matches mcp-auth, which rejects an unparseable body before authenticating.
func TestMalformedBody_NoAuthContext_IsBadRequest(t *testing.T) {
	resp := assertStatus(t, runBody(toolAOnlyPolicy(), []byte(`{"method":`), nil), 400, "malformed body with no AuthContext")
	assertWwwAuthContains(t, resp, `error="invalid_request"`)
}

func TestMalformedInput_Variants(t *testing.T) {
	cases := []struct {
		name string
		body []byte
		want int // 0 means passthrough
	}{
		{"empty body content", []byte(``), 400},
		{"json null", []byte(`null`), 400},
		{"empty method", []byte(`{"method":""}`), 0},
		{"method without slash", []byte(`{"method":"tools"}`), 0},
		{"method with two slashes", []byte(`{"method":"a/b/c"}`), 0},
		{"non-string params.name", []byte(`{"method":"tools/call","params":{"name":123}}`), 400},
		{"tools/call with no params", []byte(`{"method":"tools/call"}`), 0},
		{"tools/call with empty name", []byte(`{"method":"tools/call","params":{"name":""}}`), 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			action := runBody(toolAOnlyPolicy(), tc.body, nil)
			if tc.want == 0 {
				assertPassthrough(t, action, tc.name)
				return
			}
			assertStatus(t, action, tc.want, tc.name)
		})
	}
}

func TestVeryLongToolName_NoMatch(t *testing.T) {
	action := runBody(toolAOnlyPolicy(), mcpBody("tools/call", map[string]any{"name": strings.Repeat("x", 4096)}), nil)
	assertPassthrough(t, action, "a 4096-character tool name")
}

func TestUnicodeToolName_MatchesByteExactly(t *testing.T) {
	p := &McpAuthzPolicy{Rules: []Rule{{
		Attribute:      Attribute{Type: "tool", Name: "outil-café-🔧"},
		RequiredScopes: []string{"scope:a"},
	}}}
	assertStatus(t, runBody(p, mcpBody("tools/call", map[string]any{"name": "outil-café-🔧"}), nil), 401,
		"a governed unicode tool name")
	assertPassthrough(t, runBody(p, mcpBody("tools/call", map[string]any{"name": "outil-cafe-🔧"}), nil),
		"a near-miss unicode tool name")
}

// Authentication- and authorization-driving members must be unambiguous across
// this policy's case-insensitive decoder and a case-sensitive MCP backend.
func TestAmbiguousAuthorizationMembers_AreBadRequest(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{
			name: "case variant method shadows governed call",
			body: `{"method":"tools/call","Method":"ping","params":{"name":"toolA"}}`,
		},
		{
			name: "case variant params shadows governed params",
			body: `{"method":"tools/call","params":{"name":"toolA"},"Params":{"name":"toolB"}}`,
		},
		{
			name: "Unicode case-folded params shadows governed params",
			body: `{"method":"tools/call","params":{"name":"toolA"},"param\u017f":{"name":"toolB"}}`,
		},
		{
			name: "case variant name shadows governed tool",
			body: `{"method":"tools/call","params":{"name":"toolA","Name":"toolB"}}`,
		},
		{
			name: "case variant uri shadows resource",
			body: `{"method":"resources/read","params":{"uri":"file:///protected","URI":"file:///public"}}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := assertStatus(t, runBody(toolAOnlyPolicy(), []byte(tt.body), nil), 400, tt.name)
			assertWwwAuthContains(t, resp, `error="invalid_request"`)
		})
	}
}

func TestDuplicateAuthorizationMember_IsBadRequest(t *testing.T) {
	body := []byte(`{"method":"tools/call","params":{"name":"toolB","name":"toolA"}}`)
	resp := assertStatus(t, runBody(toolAOnlyPolicy(), body, nil), 400, "duplicate params.name")
	assertWwwAuthContains(t, resp, `error="invalid_request"`)
}

func TestExtensionMethodParameters_AreUntouched(t *testing.T) {
	body := []byte(`{"method":"vendor/run","params":{"Name":"case-sensitive","URI":"custom"}}`)
	assertPassthrough(t, runBody(toolAOnlyPolicy(), body, nil), "extension-method parameters")
}

// ---- request gating ----

func TestGetOnMcpPath_PassesThrough(t *testing.T) {
	ctx := createMockContext("GET", "/mcp", mcpBody("tools/call", map[string]any{"name": "toolA"}), nil)
	assertPassthrough(t, toolAOnlyPolicy().OnRequestBody(context.Background(), ctx, map[string]any{}), "GET /mcp")
}

// ---- context and metadata side effects ----

// MCP metadata is published for every parsed capability request, including ones this policy does not
// govern, so peer policies reading it are unaffected by the early return.
func TestUngovernedInvocation_StillPublishesMetadata(t *testing.T) {
	ctx := createMockContext("POST", "/mcp", mcpBody("tools/call", map[string]any{"name": "toolB"}), nil)
	assertPassthrough(t, toolAOnlyPolicy().OnRequestBody(context.Background(), ctx, map[string]any{}), "ungoverned toolB")

	if got := ctx.Metadata[MetadataMcpMethod]; got != "tools/call" {
		t.Errorf("expected %s=tools/call, got %v", MetadataMcpMethod, got)
	}
	if got := ctx.Metadata[MetadataMcpCapabilityType]; got != "tool" {
		t.Errorf("expected %s=tool, got %v", MetadataMcpCapabilityType, got)
	}
	if got := ctx.Metadata[MetadataMcpCapabilityName]; got != "toolB" {
		t.Errorf("expected %s=toolB, got %v", MetadataMcpCapabilityName, got)
	}
}

// An ungoverned invocation reaches no authorization decision, so it must not be marked authorized
// and its AuthType must not be promoted to mcp/oauth+authz.
func TestUngovernedInvocation_DoesNotMutateAuthContext(t *testing.T) {
	authCtx := &policy.AuthContext{Authenticated: true, AuthType: McpOAuthAuthType}
	assertPassthrough(t, runBody(toolAOnlyPolicy(), mcpBody("tools/call", map[string]any{"name": "toolB"}), authCtx),
		"ungoverned toolB with an authenticated AuthContext")

	if authCtx.Authorized {
		t.Error("expected Authorized to stay false: no authorization decision was made")
	}
	if authCtx.AuthType != McpOAuthAuthType {
		t.Errorf("expected AuthType to stay %q, got %q", McpOAuthAuthType, authCtx.AuthType)
	}
}

// A governed and satisfied invocation still promotes mcp/oauth to mcp/oauth+authz.
func TestGovernedInvocation_PromotesMcpOAuthAuthType(t *testing.T) {
	authCtx := &policy.AuthContext{
		Authenticated: true,
		AuthType:      McpOAuthAuthType,
		Scopes:        map[string]bool{"scope:a": true},
	}
	assertPassthrough(t, runBody(toolAOnlyPolicy(), mcpBody("tools/call", map[string]any{"name": "toolA"}), authCtx),
		"governed toolA with the required scope")

	if !authCtx.Authorized {
		t.Error("expected Authorized=true")
	}
	if authCtx.AuthType != McpOAuthzAuthType {
		t.Errorf("expected AuthType=%q, got %q", McpOAuthzAuthType, authCtx.AuthType)
	}
}

// TestGenerateResourcePath_GatewayUrlHandling covers gatewayUrl, the recommended
// replacement for gatewayHost: when set, it is used verbatim as the full base URL
// — no scheme/port inference from the request, and it takes priority over both
// vhost and gatewayHost.
func TestGenerateResourcePath_GatewayUrlHandling(t *testing.T) {
	tests := []struct {
		name        string
		gatewayURL  string
		gatewayHost string
		vhost       string
		scheme      string
		authority   string
		want        string
	}{
		{
			name:       "gatewayUrl used verbatim, no port inference at all",
			gatewayURL: "https://shriek-prescribe-pleading.ngrok-free.dev",
			scheme:     "https",
			authority:  "localhost:8443",
			want:       "https://shriek-prescribe-pleading.ngrok-free.dev/.well-known/oauth-protected-resource",
		},
		{
			name:       "gatewayUrl with its own port used verbatim",
			gatewayURL: "https://gateway.com:9443",
			scheme:     "https",
			authority:  "localhost:8443",
			want:       "https://gateway.com:9443/.well-known/oauth-protected-resource",
		},
		{
			name:       "trailing slash on gatewayUrl is trimmed, not doubled",
			gatewayURL: "https://gateway.com/",
			scheme:     "https",
			authority:  "localhost:8443",
			want:       "https://gateway.com/.well-known/oauth-protected-resource",
		},
		{
			name:        "gatewayUrl overrides gatewayHost when both are set",
			gatewayURL:  "https://gateway.com",
			gatewayHost: "should-be-ignored.example.com",
			scheme:      "https",
			authority:   "localhost:8443",
			want:        "https://gateway.com/.well-known/oauth-protected-resource",
		},
		{
			name:       "gatewayUrl overrides vhost when both are set",
			gatewayURL: "https://gateway.com",
			vhost:      "should-be-ignored.example.com",
			scheme:     "https",
			authority:  "localhost:8443",
			want:       "https://gateway.com/.well-known/oauth-protected-resource",
		},
		{
			// The design question this locks in: adding a non-empty schema
			// default for gatewayUrl would make it win here too, permanently
			// hiding gatewayHost — so it must stay empty/absent by default.
			name:        "gatewayUrl overrides both gatewayHost AND vhost when all three are set simultaneously",
			gatewayURL:  "https://gateway.com",
			gatewayHost: "should-be-ignored-1.example.com",
			vhost:       "should-be-ignored-2.example.com",
			scheme:      "https",
			authority:   "localhost:8443",
			want:        "https://gateway.com/.well-known/oauth-protected-resource",
		},
		{
			// gatewayUrl absent (the "not migrated yet" case, and what every
			// deployment looks like today since there is no schema default) —
			// must fall through to gatewayHost exactly as it did before
			// gatewayUrl existed. The regression this whole table exists to
			// guard: adding gatewayUrl must not change any existing
			// gatewayHost-only deployment's behavior.
			name:        "gatewayUrl absent falls through to gatewayHost",
			gatewayHost: "legacy.example.com",
			scheme:      "https",
			authority:   "localhost:8443",
			want:        "https://legacy.example.com:8443/.well-known/oauth-protected-resource",
		},
		{
			// gatewayUrl absent AND gatewayHost absent: falls all the way
			// through to the original "localhost" default — the
			// pre-gatewayUrl baseline, unaffected.
			name:      "gatewayUrl and gatewayHost both absent falls through to localhost default",
			scheme:    "https",
			authority: "localhost:8443",
			want:      "https://localhost:8443/.well-known/oauth-protected-resource",
		},
		{
			// gatewayUrl absent, vhost set, gatewayHost absent: vhost's
			// existing priority over gatewayHost is unaffected by gatewayUrl's
			// mere existence.
			name:      "gatewayUrl absent, vhost still takes its existing priority over gatewayHost",
			vhost:     "api.example.com",
			scheme:    "https",
			authority: "localhost:8443",
			want:      "https://api.example.com:8443/.well-known/oauth-protected-resource",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := generateResourcePath(tt.scheme, tt.authority, tt.vhost, "", tt.gatewayHost, tt.gatewayURL, WellKnownPath)
			if got != tt.want {
				t.Errorf("generateResourcePath() = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestGenerateWwwAuthenticateHeader_MetadataExtraction covers the mcp-authz-
// specific layer mcp-auth doesn't have: gatewayHost/gatewayUrl arrive here via
// shared reqCtx.Metadata (populated by mcp-auth running earlier in the chain),
// extracted via a type assertion (`metadata["gatewayUrl"].(string)`) rather than
// read directly from this policy's own params. That extraction must stay safe —
// no panic — when the key is missing, the map itself is nil, or the stored value
// isn't a string, and it must still respect gatewayUrl's priority over
// gatewayHost once both are present.
func TestGenerateWwwAuthenticateHeader_MetadataExtraction(t *testing.T) {
	tests := []struct {
		name       string
		metadata   map[string]any
		scheme     string
		authority  string
		wantPrefix string
	}{
		{
			name:       "nil metadata map does not panic, falls through to localhost default",
			metadata:   nil,
			scheme:     "https",
			authority:  "localhost:8443",
			wantPrefix: `Bearer resource_metadata="https://localhost:8443/.well-known/oauth-protected-resource"`,
		},
		{
			name:       "metadata present but missing both keys falls through to localhost default",
			metadata:   map[string]any{"unrelated": "value"},
			scheme:     "https",
			authority:  "localhost:8443",
			wantPrefix: `Bearer resource_metadata="https://localhost:8443/.well-known/oauth-protected-resource"`,
		},
		{
			name:       "gatewayUrl present with the wrong type does not panic, falls through to gatewayHost",
			metadata:   map[string]any{"gatewayHost": "legacy.example.com", "gatewayUrl": 12345},
			scheme:     "https",
			authority:  "localhost:8443",
			wantPrefix: `Bearer resource_metadata="https://legacy.example.com:8443/.well-known/oauth-protected-resource"`,
		},
		{
			name:       "gatewayHost present with the wrong type does not panic, falls through to localhost default",
			metadata:   map[string]any{"gatewayHost": true},
			scheme:     "https",
			authority:  "localhost:8443",
			wantPrefix: `Bearer resource_metadata="https://localhost:8443/.well-known/oauth-protected-resource"`,
		},
		{
			name:       "both present and correctly typed: gatewayUrl still wins via the metadata extraction path",
			metadata:   map[string]any{"gatewayHost": "should-be-ignored.example.com", "gatewayUrl": "https://gateway.com"},
			scheme:     "https",
			authority:  "localhost:8443",
			wantPrefix: `Bearer resource_metadata="https://gateway.com/.well-known/oauth-protected-resource"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := generateWwwAuthenticateHeader(tt.scheme, tt.authority, "", "", tt.metadata, nil, "", "")
			if !strings.HasPrefix(got, tt.wantPrefix) {
				t.Errorf("generateWwwAuthenticateHeader() = %q, want prefix %q", got, tt.wantPrefix)
			}
		})
	}
}

func TestRejectionsDeclareFault(t *testing.T) {
	assertFault := func(t *testing.T, action policy.RequestAction, wantCode, wantType string) {
		t.Helper()
		resp, ok := action.(policy.ImmediateResponse)
		if !ok {
			t.Fatalf("expected ImmediateResponse, got %T", action)
		}
		if !resp.IsFault {
			t.Fatalf("expected IsFault=true on a rejection")
		}
		if resp.Fault == nil {
			t.Fatalf("expected Error to be populated on a rejection")
		}
		if resp.Fault.Code != wantCode {
			t.Fatalf("expected Error.Code=%q, got %q", wantCode, resp.Fault.Code)
		}
		if resp.Fault.Type != wantType {
			t.Fatalf("expected Error.Type=%q, got %q", wantType, resp.Fault.Type)
		}
		if resp.Fault.Direction != policy.DirectionRequest {
			t.Fatalf("expected Error.Direction=%q, got %q", policy.DirectionRequest, resp.Fault.Direction)
		}
	}

	t.Run("insufficient scope", func(t *testing.T) {
		authCtx := authenticatedAuthCtx(map[string]bool{"scope:other": true}, "alice", "", nil, nil)
		action := runBody(toolAOnlyPolicy(), mcpBody("tools/call", map[string]any{"name": "toolA"}), authCtx)
		assertFault(t, action, policy.FaultCodeInvalidScope, policy.FaultTypeAuthorization)
	})

	t.Run("authentication required", func(t *testing.T) {
		action := runBody(toolAOnlyPolicy(), mcpBody("tools/call", map[string]any{"name": "toolA"}), nil)
		assertFault(t, action, policy.FaultCodeAuthMissingCredentials, policy.FaultTypeAuthentication)
	})

	t.Run("malformed MCP request", func(t *testing.T) {
		action := runBody(toolAOnlyPolicy(), []byte("{not json"), nil)
		assertFault(t, action, policy.FaultCodeInvalidRequestBody, policy.FaultTypeValidation)
	})
}
