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
			RequestID:   "test-request-id",
			Metadata:    make(map[string]any),
			AuthContext: authCtx,
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

func TestOnRequest_NoAuthContext(t *testing.T) {
	p := &McpAuthzPolicy{}
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

func TestOnRequest_NotAuthenticated(t *testing.T) {
	p := &McpAuthzPolicy{}
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
