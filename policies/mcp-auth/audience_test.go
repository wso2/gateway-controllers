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

package mcpauthn

import (
	"context"
	"maps"
	"reflect"
	"strings"
	"testing"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

// audiences is forwarded to jwt-auth verbatim, like every other parameter jwt-auth understands, so
// these tests pin the behaviour end to end through the delegation: on each path that authenticates,
// a configured audience list admits only tokens whose aud names one of its entries, and leaving
// the list out (or empty) admits any audience, as before the parameter was declared.

const testResource = "https://gw.example.com/weather/mcp"

// audienceAuthPath authenticates one request carrying authz, on one of the policy's paths.
type audienceAuthPath struct {
	name string
	run  func(authz string, params map[string]any) (any, *policy.SharedContext)
}

// audienceAuthPaths returns every path on which the policy delegates to jwt-auth: the body phase
// of a route without a resolver, the header phase of a resolver route in each MCP era, and the
// transport endpoints, which carry no JSON-RPC body.
func audienceAuthPaths() []audienceAuthPath {
	return []audienceAuthPath{
		{"body phase without a resolver", func(authz string, params map[string]any) (any, *policy.SharedContext) {
			ctx := unresolvedBodyPost(map[string][]string{"authorization": {authz}},
				`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"x"}}`)
			ctx.Scheme, ctx.Authority = "http", "localhost:8080"
			return createTestPolicy().OnRequestBody(context.Background(), ctx, params), ctx.SharedContext
		}},
		{"resolver route, legacy request", func(authz string, params map[string]any) (any, *policy.SharedContext) {
			ctx := resolvedHeaderPost(map[string][]string{"authorization": {authz}},
				map[string]string{attrBodyMethod: "tools/call", attrBodyCapabilityName: "x"})
			ctx.Scheme, ctx.Authority = "http", "localhost:8080"
			return createTestPolicy().OnRequestHeaders(context.Background(), ctx, params), ctx.SharedContext
		}},
		{"resolver route, 2026-07-28 request", func(authz string, params map[string]any) (any, *policy.SharedContext) {
			ctx := resolvedHeaderPost(map[string][]string{
				"authorization":       {authz},
				headerProtocolVersion: {"2026-07-28"},
				headerMcpMethod:       {"tools/call"},
				headerMcpName:         {"x"},
			}, map[string]string{attrBodyMethod: "tools/call", attrBodyCapabilityName: "x"})
			ctx.Scheme, ctx.Authority = "http", "localhost:8080"
			return createTestPolicy().OnRequestHeaders(context.Background(), ctx, params), ctx.SharedContext
		}},
		{"transport GET /mcp", func(authz string, params map[string]any) (any, *policy.SharedContext) {
			ctx := createMockRequestHeaderContext(map[string][]string{"authorization": {authz}})
			ctx.Method, ctx.Path, ctx.OperationPath = "GET", "/mcp", "/mcp"
			return createTestPolicy().OnRequestHeaders(context.Background(), ctx, params), ctx.SharedContext
		}},
	}
}

func TestAudiences_EnforcedOnEveryAuthenticationPath(t *testing.T) {
	privateKey, publicKey := generateRSATestKeys(t)
	jwksServer := createMcpTestJWKSServer(t, publicKey, "test-kid")
	defer jwksServer.Close()

	// token returns an Authorization value for a valid token, with aud only when aud is non-nil.
	token := func(aud any) string {
		claims := map[string]interface{}{"sub": "user123", "iss": "https://issuer.example.com"}
		if aud != nil {
			claims["aud"] = aud
		}
		return "Bearer " + createMcpTestToken(t, privateKey, claims)
	}
	// withAudiences returns the delegation params, with audiences only when audiences is non-nil.
	withAudiences := func(audiences []any) map[string]any {
		params := mcpTransportKeyManagerParams(jwksServer.URL)
		if audiences != nil {
			params["audiences"] = audiences
		}
		return params
	}

	cases := []struct {
		name      string
		audiences []any
		authz     string
		accepted  bool
	}{
		// Unchanged behaviour: without a list, the audience is not checked.
		{"not configured, token without aud", nil, token(nil), true},
		{"not configured, token for another server", nil, token("https://other.example.com/mcp"), true},
		{"empty list, token for another server", []any{}, token("https://other.example.com/mcp"), true},

		{"aud names the configured audience", []any{testResource}, token(testResource), true},
		{"aud array includes the configured audience", []any{testResource}, token([]any{"https://other.example.com/mcp", testResource}), true},
		{"aud names the second configured audience", []any{"api://weather", testResource}, token(testResource), true},
		{"token for another server", []any{testResource}, token("https://other.example.com/mcp"), false},
		{"token without aud", []any{testResource}, token(nil), false},
		// The comparison is exact: no URL normalisation.
		{"aud differs by a trailing slash", []any{testResource}, token(testResource + "/"), false},
		{"aud differs in case", []any{testResource}, token(strings.ToUpper(testResource)), false},
	}

	for _, path := range audienceAuthPaths() {
		for _, c := range cases {
			t.Run(path.name+"/"+c.name, func(t *testing.T) {
				params := withAudiences(c.audiences)
				before := maps.Clone(params)

				action, shared := path.run(c.authz, params)

				if !reflect.DeepEqual(before, params) {
					t.Fatalf("params were mutated: before %v, after %v", before, params)
				}
				resp, rejected := action.(policy.ImmediateResponse)
				if c.accepted {
					if rejected {
						t.Fatalf("expected the token to be accepted, got %d %s (%+v)", resp.StatusCode, resp.Body, resp.Fault)
					}
					if shared.AuthContext == nil || !shared.AuthContext.Authenticated || shared.AuthContext.AuthType != AuthType {
						t.Fatalf("expected an authenticated %s AuthContext, got %+v", AuthType, shared.AuthContext)
					}
					return
				}
				if !rejected {
					t.Fatalf("expected the token to be rejected, got %T", action)
				}
				assertAudienceRejection(t, resp)
				if shared.AuthContext == nil || shared.AuthContext.Authenticated || shared.AuthContext.AuthType != AuthType {
					t.Fatalf("expected an unauthenticated %s AuthContext, got %+v", AuthType, shared.AuthContext)
				}
			})
		}
	}
}

// assertAudienceRejection checks the fault jwt-auth declares for an audience mismatch is passed
// through, and that the client sees the same response as for any other invalid token.
func assertAudienceRejection(t *testing.T, resp policy.ImmediateResponse) {
	t.Helper()
	if resp.StatusCode != 401 || !resp.IsFault || resp.Fault == nil {
		t.Fatalf("status %d, IsFault %v, Fault %+v", resp.StatusCode, resp.IsFault, resp.Fault)
	}
	f := resp.Fault
	if f.Code != policy.FaultCodeAuthInvalidCredentials || f.Type != policy.FaultTypeAuthentication ||
		f.Direction != policy.DirectionRequest {
		t.Fatalf("fault = %s/%s/%s", f.Code, f.Type, f.Direction)
	}
	if f.Description != "no valid audience found in token" || f.Message != "Authentication failed" {
		t.Fatalf("fault description %q, message %q", f.Description, f.Message)
	}
	if want := `{"error":"Unauthorized","message":"Authentication failed"}`; string(resp.Body) != want {
		t.Fatalf("body %s, want %s", resp.Body, want)
	}
	want := `Bearer resource_metadata="http://gateway.com:8080/.well-known/oauth-protected-resource", ` +
		`error="invalid_token", error_description="Authentication failed"`
	if got := resp.Headers[WWWAuthenticateHeader]; got != want {
		t.Fatalf("WWW-Authenticate %q, want %q", got, want)
	}
}

// The jwt-auth verdict cache is shared by every API and keeps the audience out of its key. The
// same token must stay accepted where no audience is configured and refused where one is, in
// either order: the refusal is not cached, and the accepted verdict does not skip the check.
func TestAudiences_SharedVerdictCache(t *testing.T) {
	privateKey, publicKey := generateRSATestKeys(t)
	jwksServer := createMcpTestJWKSServer(t, publicKey, "test-kid")
	defer jwksServer.Close()
	authz := "Bearer " + createMcpTestToken(t, privateKey, map[string]interface{}{
		"sub": "user123", "iss": "https://issuer.example.com", "aud": "https://other.example.com/mcp",
	})

	open := mcpTransportKeyManagerParams(jwksServer.URL)
	strict := mcpTransportKeyManagerParams(jwksServer.URL)
	strict["audiences"] = []any{testResource}

	run := audienceAuthPaths()[0].run
	for i, step := range []struct {
		params   map[string]any
		accepted bool
	}{{open, true}, {strict, false}, {open, true}, {strict, false}} {
		action, _ := run(authz, step.params)
		if _, rejected := action.(policy.ImmediateResponse); rejected == step.accepted {
			t.Fatalf("request %d: accepted %v, want %v", i+1, !rejected, step.accepted)
		}
	}
}

// A client cannot tell an audience mismatch from any other invalid token: status, headers and
// body are the same, and so is the fault code. Only the fault's Description tells them apart.
func TestAudiences_RejectionMatchesOtherInvalidToken(t *testing.T) {
	privateKey, publicKey := generateRSATestKeys(t)
	jwksServer := createMcpTestJWKSServer(t, publicKey, "test-kid")
	defer jwksServer.Close()
	otherKey, _ := generateRSATestKeys(t)

	params := mcpTransportKeyManagerParams(jwksServer.URL)
	params["audiences"] = []any{testResource}
	run := audienceAuthPaths()[0].run

	wrongAudience, _ := run("Bearer "+createMcpTestToken(t, privateKey, map[string]interface{}{
		"iss": "https://issuer.example.com", "aud": "https://other.example.com/mcp",
	}), params)
	badSignature, _ := run("Bearer "+createMcpTestToken(t, otherKey, map[string]interface{}{
		"iss": "https://issuer.example.com", "aud": testResource,
	}), params)

	a, okA := wrongAudience.(policy.ImmediateResponse)
	b, okB := badSignature.(policy.ImmediateResponse)
	if !okA || !okB {
		t.Fatalf("expected both tokens to be rejected, got %T and %T", wrongAudience, badSignature)
	}
	if a.StatusCode != b.StatusCode || string(a.Body) != string(b.Body) || !reflect.DeepEqual(a.Headers, b.Headers) {
		t.Fatalf("client responses differ:\n%d %v %s\n%d %v %s", a.StatusCode, a.Headers, a.Body, b.StatusCode, b.Headers, b.Body)
	}
	if a.Fault.Code != b.Fault.Code || a.Fault.Type != b.Fault.Type {
		t.Fatalf("faults differ: %s/%s and %s/%s", a.Fault.Code, a.Fault.Type, b.Fault.Code, b.Fault.Type)
	}
	if a.Fault.Description == b.Fault.Description {
		t.Fatalf("expected the descriptions to name the different reasons, both %q", a.Fault.Description)
	}
}
