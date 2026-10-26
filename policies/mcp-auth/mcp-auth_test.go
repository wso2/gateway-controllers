/*
 * Copyright (c) 2025, WSO2 LLC. (https://www.wso2.com).
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
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

func TestMcpAuthPolicy_Mode(t *testing.T) {
	p := &McpAuthPolicy{}
	got := p.Mode()
	want := policy.ProcessingMode{
		RequestHeaderMode:  policy.HeaderModeProcess,
		RequestBodyMode:    policy.BodyModeBuffer,
		ResponseHeaderMode: policy.HeaderModeSkip,
		ResponseBodyMode:   policy.BodyModeSkip,
	}
	if got != want {
		t.Fatalf("unexpected mode: got %+v, want %+v", got, want)
	}
}

func TestGetPolicy(t *testing.T) {
	p, err := GetPolicy(policy.PolicyMetadata{}, nil)
	if err != nil {
		t.Errorf("GetPolicy returned error: %v", err)
	}
	if p == nil {
		t.Error("GetPolicy returned nil policy")
	}
}

func TestGetPolicy_GatewayUrlValidation(t *testing.T) {
	tests := []struct {
		name       string
		gatewayURL string
		wantErr    bool
	}{
		{name: "absent", gatewayURL: "", wantErr: false},
		{name: "valid https", gatewayURL: "https://mcp1.example.com", wantErr: false},
		{name: "valid http", gatewayURL: "http://mcp1.example.com:8080", wantErr: false},
		{name: "unsupported scheme", gatewayURL: "ftp://mcp1.example.com", wantErr: true},
		{name: "no scheme", gatewayURL: "mcp1.example.com", wantErr: true},
		{name: "no host", gatewayURL: "https://", wantErr: true},
		{name: "no host with port only", gatewayURL: "https://:8443", wantErr: true},
		{name: "has query string", gatewayURL: "https://mcp1.example.com?foo=bar", wantErr: true},
		{name: "has fragment", gatewayURL: "https://mcp1.example.com#section", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			params := map[string]any{}
			if tt.gatewayURL != "" {
				params["gatewayUrl"] = tt.gatewayURL
			}
			_, err := GetPolicy(policy.PolicyMetadata{}, params)
			if tt.wantErr && err == nil {
				t.Errorf("GetPolicy(gatewayUrl=%q): expected error, got nil", tt.gatewayURL)
			}
			if !tt.wantErr && err != nil {
				t.Errorf("GetPolicy(gatewayUrl=%q): unexpected error: %v", tt.gatewayURL, err)
			}
		})
	}
}

func TestOnRequestHeaders_WellKnown_Success(t *testing.T) {
	p, _ := GetPolicy(policy.PolicyMetadata{}, map[string]any{
		"requiredScopes": []any{"scope1", "scope2"},
	})
	ctx := createMockRequestHeaderContext(map[string][]string{
		McpSessionHeader: {"session-123"},
	})
	ctx.Method = "GET"
	ctx.OperationPath = "/.well-known/oauth-protected-resource"

	params := map[string]any{
		"keyManagers": []any{
			map[string]any{
				"name":   "km1",
				"issuer": "https://issuer1.com",
			},
		},
	}

	action := p.(*McpAuthPolicy).OnRequestHeaders(context.Background(), ctx, params)

	resp, ok := action.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("Expected ImmediateResponse, got %T", action)
	}

	if resp.StatusCode != 200 {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	if resp.Headers[McpSessionHeader] != "session-123" {
		t.Errorf("Expected session header 'session-123', got %s", resp.Headers[McpSessionHeader])
	}

	var metadata ProtectedResourceMetadata
	if err := json.Unmarshal(resp.Body, &metadata); err != nil {
		t.Fatalf("Failed to unmarshal body: %v", err)
	}

	expectedResource := "http://localhost:8080/mcp"
	if metadata.Resource != expectedResource {
		t.Errorf("Expected resource '%s', got '%s'", expectedResource, metadata.Resource)
	}

	if len(metadata.AuthorizationServers) != 1 || metadata.AuthorizationServers[0] != "https://issuer1.com" {
		t.Errorf("Unexpected authorization servers: %v", metadata.AuthorizationServers)
	}

	if len(metadata.ScopesSupported) != 2 {
		t.Errorf("Unexpected scopes supported: %v", metadata.ScopesSupported)
	}
}

func TestOnRequestHeaders_WellKnown_NoRequiredScopesOmitsScopesSupported(t *testing.T) {
	p, _ := GetPolicy(policy.PolicyMetadata{}, map[string]any{})
	ctx := createMockRequestHeaderContext(nil)
	ctx.Method = "GET"
	ctx.OperationPath = "/.well-known/oauth-protected-resource"

	params := map[string]any{
		"keyManagers": []any{
			map[string]any{
				"name":   "km1",
				"issuer": "https://issuer1.com",
			},
		},
	}

	action := p.(*McpAuthPolicy).OnRequestHeaders(context.Background(), ctx, params)

	resp, ok := action.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("Expected ImmediateResponse, got %T", action)
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(resp.Body, &raw); err != nil {
		t.Fatalf("Failed to unmarshal body: %v", err)
	}

	if _, present := raw["scopes_supported"]; present {
		t.Errorf("Expected scopes_supported to be omitted, got body: %s", resp.Body)
	}
}

func TestOnRequestHeaders_WellKnown_NoKeyManagers(t *testing.T) {
	p := createTestPolicy()
	ctx := createMockRequestHeaderContext(nil)
	ctx.Method = "GET"
	ctx.OperationPath = "/.well-known/oauth-protected-resource"

	action := p.OnRequestHeaders(context.Background(), ctx, map[string]any{})
	resp, ok := action.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("Expected ImmediateResponse, got %T", action)
	}
	if resp.StatusCode != 401 {
		t.Errorf("Expected status 401, got %d", resp.StatusCode)
	}
}

func TestOnRequestHeaders_WellKnown_NoKeyManagers_WithForbiddenStatus(t *testing.T) {
	p := &McpAuthPolicy{
		OnFailureStatusCode: 403,
		ErrorMessageFormat:  "json",
	}
	ctx := createMockRequestHeaderContext(nil)
	ctx.Method = "GET"
	ctx.OperationPath = "/.well-known/oauth-protected-resource"

	action := p.OnRequestHeaders(context.Background(), ctx, map[string]any{})
	resp, ok := action.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("Expected ImmediateResponse, got %T", action)
	}
	if resp.StatusCode != 403 {
		t.Errorf("Expected status 403, got %d", resp.StatusCode)
	}
}

func TestOnRequestHeaders_WellKnown_FilteredIssuers(t *testing.T) {
	p, _ := GetPolicy(policy.PolicyMetadata{}, map[string]any{
		"issuers": []any{"km2"}, // Only allow km2
	})
	ctx := createMockRequestHeaderContext(nil)
	ctx.Method = "GET"
	ctx.OperationPath = "/.well-known/oauth-protected-resource"

	params := map[string]any{
		"keyManagers": []any{
			map[string]any{
				"name":   "km1",
				"issuer": "https://issuer1.com",
			},
			map[string]any{
				"name":   "km2",
				"issuer": "https://issuer2.com",
			},
		},
	}

	action := p.(*McpAuthPolicy).OnRequestHeaders(context.Background(), ctx, params)

	resp, ok := action.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("Expected ImmediateResponse, got %T", action)
	}

	var metadata ProtectedResourceMetadata
	if err := json.Unmarshal(resp.Body, &metadata); err != nil {
		t.Fatalf("Failed to unmarshal body: %v", err)
	}

	if len(metadata.AuthorizationServers) != 1 || metadata.AuthorizationServers[0] != "https://issuer2.com" {
		t.Errorf("Expected only issuer2, got %v", metadata.AuthorizationServers)
	}
}

func TestOnRequestHeaders_WellKnown_WithVhost(t *testing.T) {
	p := createTestPolicy()
	ctx := createMockRequestHeaderContext(map[string][]string{
		McpSessionHeader: {"session-456"},
	})
	ctx.Method = "GET"
	ctx.OperationPath = "/.well-known/oauth-protected-resource"
	ctx.Scheme = "https"
	ctx.Authority = "localhost:8443"
	ctx.Vhost = "api.example.com"

	params := map[string]any{
		"keyManagers": []any{
			map[string]any{
				"name":   "km1",
				"issuer": "https://issuer1.com",
			},
		},
	}

	action := p.OnRequestHeaders(context.Background(), ctx, params)

	resp, ok := action.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("Expected ImmediateResponse, got %T", action)
	}

	if resp.StatusCode != 200 {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	var metadata ProtectedResourceMetadata
	if err := json.Unmarshal(resp.Body, &metadata); err != nil {
		t.Fatalf("Failed to unmarshal body: %v", err)
	}

	// Should use vhost (api.example.com) with port from authority (8443)
	expectedResource := "https://api.example.com:8443/mcp"
	if metadata.Resource != expectedResource {
		t.Errorf("Expected resource '%s', got '%s'", expectedResource, metadata.Resource)
	}
}

func TestOnRequestHeaders_WellKnown_WithVhost_StandardPort(t *testing.T) {
	p := createTestPolicy()
	ctx := createMockRequestHeaderContext(nil)
	ctx.Method = "GET"
	ctx.OperationPath = "/.well-known/oauth-protected-resource"
	ctx.Scheme = "https"
	ctx.Authority = "api.example.com:443"
	ctx.Vhost = "api.example.com"

	params := map[string]any{
		"keyManagers": []any{
			map[string]any{
				"name":   "km1",
				"issuer": "https://issuer1.com",
			},
		},
	}

	action := p.OnRequestHeaders(context.Background(), ctx, params)

	resp, ok := action.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("Expected ImmediateResponse, got %T", action)
	}

	var metadata ProtectedResourceMetadata
	if err := json.Unmarshal(resp.Body, &metadata); err != nil {
		t.Fatalf("Failed to unmarshal body: %v", err)
	}

	// Should use vhost without port since 443 is standard for https
	expectedResource := "https://api.example.com/mcp"
	if metadata.Resource != expectedResource {
		t.Errorf("Expected resource '%s', got '%s'", expectedResource, metadata.Resource)
	}
}

// TestOnRequestHeaders_WellKnown_GatewayUrl covers gatewayUrl on the OTHER call
// site of generateResourcePathFromFields — the well-known metadata document
// response built directly in OnRequestHeaders, as opposed to the
// WWW-Authenticate header built via OnRequestBody's delegated-auth-failure path
// tested in TestOnRequestBody_Delegation_Failure_GatewayUrlHandling. Both call
// sites share the same underlying function, but a regression could still land in
// only one of the two call sites, so both need direct coverage.
func TestOnRequestHeaders_WellKnown_GatewayUrl(t *testing.T) {
	p := createTestPolicy()
	ctx := createMockRequestHeaderContext(nil)
	ctx.Method = "GET"
	ctx.OperationPath = "/.well-known/oauth-protected-resource"
	ctx.Scheme = "https"
	ctx.Authority = "localhost:8443"
	ctx.Vhost = "should-be-ignored.example.com" // gatewayUrl must win over this too

	params := map[string]any{
		"gatewayUrl":  "https://shriek-prescribe-pleading.ngrok-free.dev",
		"gatewayHost": "should-also-be-ignored.example.com",
		"keyManagers": []any{
			map[string]any{
				"name":   "km1",
				"issuer": "https://issuer1.com",
			},
		},
	}

	action := p.OnRequestHeaders(context.Background(), ctx, params)

	resp, ok := action.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("Expected ImmediateResponse, got %T", action)
	}

	var metadata ProtectedResourceMetadata
	if err := json.Unmarshal(resp.Body, &metadata); err != nil {
		t.Fatalf("Failed to unmarshal body: %v", err)
	}

	expectedResource := "https://shriek-prescribe-pleading.ngrok-free.dev/mcp"
	if metadata.Resource != expectedResource {
		t.Errorf("Expected resource '%s', got '%s'", expectedResource, metadata.Resource)
	}
}

func TestOnRequestHeaders_WellKnown_WithVhost_AndAPIContext(t *testing.T) {
	p := createTestPolicy()
	ctx := createMockRequestHeaderContext(nil)
	ctx.Method = "GET"
	ctx.OperationPath = "/.well-known/oauth-protected-resource"
	ctx.Scheme = "https"
	ctx.Authority = "localhost:8443"
	ctx.Vhost = "api.example.com"
	ctx.APIContext = "/v1/myapi"

	params := map[string]any{
		"keyManagers": []any{
			map[string]any{
				"name":   "km1",
				"issuer": "https://issuer1.com",
			},
		},
	}

	action := p.OnRequestHeaders(context.Background(), ctx, params)

	resp, ok := action.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("Expected ImmediateResponse, got %T", action)
	}

	var metadata ProtectedResourceMetadata
	if err := json.Unmarshal(resp.Body, &metadata); err != nil {
		t.Fatalf("Failed to unmarshal body: %v", err)
	}

	// Should include API context in the resource path
	expectedResource := "https://api.example.com:8443/v1/myapi/mcp"
	if metadata.Resource != expectedResource {
		t.Errorf("Expected resource '%s', got '%s'", expectedResource, metadata.Resource)
	}
}

func TestOnRequestBody_Delegation_Failure(t *testing.T) {
	_, publicKey := generateRSATestKeys(t)
	jwksServer := createMcpTestJWKSServer(t, publicKey, "test-kid")
	defer jwksServer.Close()

	p := createTestPolicy()
	ctx := createMockRequestBodyContext(map[string][]string{
		McpSessionHeader: {"session-123"},
	})
	ctx.Method = "POST"
	ctx.Path = "/mcp"
	ctx.OperationPath = "/mcp"

	// Pass keyManagers but no valid JWT token - JWT Auth should fail with 401
	params := map[string]any{
		"gatewayHost": "gateway.com",
		"keyManagers": []any{
			map[string]any{
				"name":   "test-km",
				"issuer": "https://issuer.example.com",
				"jwks": map[string]any{
					"remote": map[string]any{
						"uri": jwksServer.URL + "/jwks.json",
					},
				},
			},
		},
	}

	action := p.OnRequestBody(context.Background(), ctx, params)

	// We expect ImmediateResponse (failure from JWT Auth wrapped)
	resp, ok := action.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("Expected ImmediateResponse (auth failure), got %T", action)
	}

	if resp.StatusCode != 401 {
		t.Errorf("Expected status 401, got %d", resp.StatusCode)
	}

	authHeader := resp.Headers[WWWAuthenticateHeader]
	if authHeader == "" {
		t.Error("Expected WWW-Authenticate header")
	}

	expectedPrefix := `Bearer resource_metadata="http://gateway.com:8080/.well-known/oauth-protected-resource"`
	if !strings.HasPrefix(authHeader, expectedPrefix) {
		t.Errorf("Unexpected WWW-Authenticate header: %s", authHeader)
	}

	if resp.Headers[McpSessionHeader] != "session-123" {
		t.Errorf("Expected session header 'session-123', got %s", resp.Headers[McpSessionHeader])
	}
}

// TestOnRequestBody_Delegation_Failure_GatewayUrlHandling covers gatewayUrl, the
// recommended replacement for gatewayHost: when set, it is used verbatim as the
// full base URL — no scheme/port inference from the request, and it takes
// priority over both vhost and gatewayHost.
func TestOnRequestBody_Delegation_Failure_GatewayUrlHandling(t *testing.T) {
	tests := []struct {
		name        string
		gatewayURL  string
		omitURLKey  bool // if true, "gatewayUrl" is left out of params entirely instead of set to gatewayURL
		gatewayHost string // set alongside gatewayURL to prove gatewayURL wins
		vhost       string // set alongside gatewayURL to prove gatewayURL wins
		scheme      string
		authority   string
		wantPrefix  string
	}{
		{
			name:       "gatewayUrl used verbatim, no port inference at all",
			gatewayURL: "https://shriek-prescribe-pleading.ngrok-free.dev",
			scheme:     "https",
			authority:  "localhost:8443",
			wantPrefix: `Bearer resource_metadata="https://shriek-prescribe-pleading.ngrok-free.dev/.well-known/oauth-protected-resource"`,
		},
		{
			name:       "gatewayUrl with its own port used verbatim",
			gatewayURL: "https://gateway.com:9443",
			scheme:     "https",
			authority:  "localhost:8443",
			wantPrefix: `Bearer resource_metadata="https://gateway.com:9443/.well-known/oauth-protected-resource"`,
		},
		{
			name:       "trailing slash on gatewayUrl is trimmed, not doubled",
			gatewayURL: "https://gateway.com/",
			scheme:     "https",
			authority:  "localhost:8443",
			wantPrefix: `Bearer resource_metadata="https://gateway.com/.well-known/oauth-protected-resource"`,
		},
		{
			name:        "gatewayUrl overrides gatewayHost when both are set",
			gatewayURL:  "https://gateway.com",
			gatewayHost: "should-be-ignored.example.com",
			scheme:      "https",
			authority:   "localhost:8443",
			wantPrefix:  `Bearer resource_metadata="https://gateway.com/.well-known/oauth-protected-resource"`,
		},
		{
			name:       "gatewayUrl overrides vhost when both are set",
			gatewayURL: "https://gateway.com",
			vhost:      "should-be-ignored.example.com",
			scheme:     "https",
			authority:  "localhost:8443",
			wantPrefix: `Bearer resource_metadata="https://gateway.com/.well-known/oauth-protected-resource"`,
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
			wantPrefix:  `Bearer resource_metadata="https://gateway.com/.well-known/oauth-protected-resource"`,
		},
		{
			// gatewayUrl entirely absent from params (the "not migrated yet"
			// case, and what every deployment looks like today since there is
			// no schema default) — must fall through to gatewayHost exactly as
			// it did before gatewayUrl existed. This is the regression this
			// whole table exists to guard: adding gatewayUrl must not change
			// any existing gatewayHost-only deployment's behavior.
			name:        "gatewayUrl key entirely absent falls through to gatewayHost",
			omitURLKey:  true,
			gatewayHost: "legacy.example.com",
			scheme:      "https",
			authority:   "localhost:8443",
			wantPrefix:  `Bearer resource_metadata="https://legacy.example.com:8443/.well-known/oauth-protected-resource"`,
		},
		{
			// gatewayUrl present but explicitly "" behaves identically to it
			// being absent entirely — getStringParam treats both the same way,
			// and this locks that equivalence in explicitly.
			name:        "gatewayUrl explicitly empty string behaves identically to absent",
			gatewayURL:  "",
			omitURLKey:  false,
			gatewayHost: "legacy.example.com",
			scheme:      "https",
			authority:   "localhost:8443",
			wantPrefix:  `Bearer resource_metadata="https://legacy.example.com:8443/.well-known/oauth-protected-resource"`,
		},
		{
			// gatewayUrl absent AND gatewayHost absent: falls all the way
			// through to the original "localhost" default — the pre-gatewayUrl
			// baseline, unaffected.
			name:       "gatewayUrl and gatewayHost both absent falls through to localhost default",
			omitURLKey: true,
			scheme:     "https",
			authority:  "localhost:8443",
			wantPrefix: `Bearer resource_metadata="https://localhost:8443/.well-known/oauth-protected-resource"`,
		},
		{
			// gatewayUrl absent, vhost set, gatewayHost absent: vhost's
			// existing priority over gatewayHost is unaffected by gatewayUrl's
			// mere existence in the schema.
			name:       "gatewayUrl absent, vhost still takes its existing priority over gatewayHost",
			omitURLKey: true,
			vhost:      "api.example.com",
			scheme:     "https",
			authority:  "localhost:8443",
			wantPrefix: `Bearer resource_metadata="https://api.example.com:8443/.well-known/oauth-protected-resource"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, publicKey := generateRSATestKeys(t)
			jwksServer := createMcpTestJWKSServer(t, publicKey, "test-kid")
			defer jwksServer.Close()

			p := createTestPolicy()
			ctx := createMockRequestBodyContext(map[string][]string{
				McpSessionHeader: {"session-123"},
			})
			ctx.Method = "POST"
			ctx.Path = "/mcp"
			ctx.OperationPath = "/mcp"
			ctx.Scheme = tt.scheme
			ctx.Authority = tt.authority
			ctx.Vhost = tt.vhost

			params := map[string]any{
				"keyManagers": []any{
					map[string]any{
						"name":   "test-km",
						"issuer": "https://issuer.example.com",
						"jwks": map[string]any{
							"remote": map[string]any{
								"uri": jwksServer.URL + "/jwks.json",
							},
						},
					},
				},
			}
			if !tt.omitURLKey {
				params["gatewayUrl"] = tt.gatewayURL
			}
			// Mirror the real resolution pipeline: an absent config.toml key with
			// a schema default gets that default materialized into the params
			// map (see ConfigResolver.resolveSystemParamMarker), so "gatewayHost
			// unset" in these tests means "key absent", not "key present as
			// empty string" — getStringParam's own fallback only fires for the
			// former.
			if tt.gatewayHost != "" {
				params["gatewayHost"] = tt.gatewayHost
			}

			action := p.OnRequestBody(context.Background(), ctx, params)

			resp, ok := action.(policy.ImmediateResponse)
			if !ok {
				t.Fatalf("Expected ImmediateResponse (auth failure), got %T", action)
			}

			authHeader := resp.Headers[WWWAuthenticateHeader]
			if !strings.HasPrefix(authHeader, tt.wantPrefix) {
				t.Errorf("expected prefix %q, got: %s", tt.wantPrefix, authHeader)
			}
		})
	}
}

// jsonRPCErrorResponse mirrors the JSON-RPC 2.0 error envelope for assertions.
// ID is captured as RawMessage so a missing "id" field (nil) can be distinguished
// from an explicit "id": null (the literal bytes "null").
type jsonRPCErrorResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Error   struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
		Data    string `json:"data"`
	} `json:"error"`
}

// mcpBadRequest issues an OnRequestBody call for a POST /mcp with the given body
// and returns the resulting ImmediateResponse.
func mcpBadRequest(t *testing.T, body []byte) policy.ImmediateResponse {
	t.Helper()
	p := createTestPolicy()
	ctx := createMockRequestBodyContext(nil)
	ctx.Method = "POST"
	ctx.Path = "/mcp"
	ctx.OperationPath = "/mcp"
	ctx.Body = &policy.Body{Content: body, Present: true}

	action := p.OnRequestBody(context.Background(), ctx, map[string]any{})
	resp, ok := action.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("Expected ImmediateResponse, got %T", action)
	}
	return resp
}

// assertJSONRPCError decodes the response body and validates the JSON-RPC error envelope.
func assertJSONRPCError(t *testing.T, resp policy.ImmediateResponse, wantCode int, wantMessage string) {
	t.Helper()
	if resp.StatusCode != 400 {
		t.Errorf("Expected status 400, got %d", resp.StatusCode)
	}
	if ct := resp.Headers["content-type"]; ct != "application/json" {
		t.Errorf("Expected content-type application/json, got %q", ct)
	}
	var parsed jsonRPCErrorResponse
	if err := json.Unmarshal(resp.Body, &parsed); err != nil {
		t.Fatalf("Response body is not valid JSON: %v (body: %s)", err, resp.Body)
	}
	if parsed.JSONRPC != "2.0" {
		t.Errorf("Expected jsonrpc \"2.0\", got %q", parsed.JSONRPC)
	}
	if parsed.ID == nil {
		t.Errorf("Expected id field to be present")
	} else if string(parsed.ID) != "null" {
		t.Errorf("Expected id to be null, got %s", parsed.ID)
	}
	if parsed.Error.Code != wantCode {
		t.Errorf("Expected error code %d, got %d", wantCode, parsed.Error.Code)
	}
	if parsed.Error.Message != wantMessage {
		t.Errorf("Expected error message %q, got %q", wantMessage, parsed.Error.Message)
	}
}

// TestOnRequestBody_InvalidJSON_ReturnsParseError verifies that a body with invalid
// JSON syntax is reported as HTTP 400 with a JSON-RPC -32700 (Parse error) object,
// rather than an authentication failure. Regression test for wso2/api-platform#2751.
func TestOnRequestBody_InvalidJSON_ReturnsParseError(t *testing.T) {
	resp := mcpBadRequest(t, []byte("not-json"))
	assertJSONRPCError(t, resp, JSONRPCParseError, "Parse error")
}

// TestOnRequestBody_InvalidStructure_ReturnsInvalidRequest verifies that a body that
// is valid JSON but not a valid MCP request object is reported as HTTP 400 with a
// JSON-RPC -32600 (Invalid Request) object.
func TestOnRequestBody_InvalidStructure_ReturnsInvalidRequest(t *testing.T) {
	resp := mcpBadRequest(t, []byte("[]"))
	assertJSONRPCError(t, resp, JSONRPCInvalidRequest, "Invalid Request")
}

// TestOnRequestBody_ShadowedMember_DoesNotBypassAuth checks that with "ping" exempt,
// an unauthenticated POST carrying both "method":"tools/call" and "Method":"ping"
// does not reach the backend.
func TestOnRequestBody_ShadowedMember_DoesNotBypassAuth(t *testing.T) {
	p := &McpAuthPolicy{
		OnFailureStatusCode: 401,
		ErrorMessageFormat:  "json",
		AuthConfig: GetMcpAuthConfig(map[string]any{
			"tools":   map[string]any{"enabled": true},
			"methods": map[string]any{"enabled": true, "exceptions": []any{"ping"}},
		}),
	}
	ctx := createMockRequestBodyContext(nil)
	ctx.Method = "POST"
	ctx.Path = "/mcp"
	ctx.OperationPath = "/mcp"
	ctx.Body = &policy.Body{
		Content: []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","Method":"ping","params":{"name":"delete_everything"}}`),
		Present: true,
	}

	action := p.OnRequestBody(context.Background(), ctx, map[string]any{})

	// A nil action forwards the request upstream, which is exactly the bypass.
	if action == nil {
		t.Fatal("Request with a shadowed \"method\" member was forwarded upstream without authentication")
	}
	resp, ok := action.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("Expected ImmediateResponse, got %T", action)
	}
	assertJSONRPCError(t, resp, JSONRPCInvalidRequest, "Invalid Request")
}

// TestOnRequestBody_AmbiguousMembers covers member-name spellings this policy and a
// case-sensitive MCP backend would resolve differently, plus legitimate bodies that
// must keep flowing. Bodies are exempt, so acceptance shows up as a nil action.
func TestOnRequestBody_AmbiguousMembers(t *testing.T) {
	tests := []struct {
		name       string
		body       string
		wantReject bool
	}{
		{
			name:       "case variant method shadows exempt method",
			body:       `{"method":"tools/call","Method":"ping"}`,
			wantReject: true,
		},
		{
			name:       "shadow member declared before the canonical one",
			body:       `{"Method":"ping","method":"tools/call"}`,
			wantReject: true,
		},
		{
			name:       "upper case shadow member",
			body:       `{"method":"tools/call","METHOD":"ping"}`,
			wantReject: true,
		},
		{
			name:       "method present only under a non-canonical spelling",
			body:       `{"Method":"ping"}`,
			wantReject: true,
		},
		{
			name:       "exact duplicate method members",
			body:       `{"method":"ping","method":"tools/call"}`,
			wantReject: true,
		},
		{
			name:       "case variant params shadows the canonical params",
			body:       `{"method":"tools/call","params":{"name":"protected"},"Params":{"name":"safe_tool"}}`,
			wantReject: true,
		},
		{
			name:       "Unicode case-folded params shadows the canonical params",
			body:       `{"method":"tools/call","params":{"name":"protected"},"param\u017f":{"name":"safe_tool"}}`,
			wantReject: true,
		},
		{
			name:       "case variant name inside params",
			body:       `{"method":"tools/call","params":{"name":"protected","Name":"safe_tool"}}`,
			wantReject: true,
		},
		{
			name:       "case variant uri inside params",
			body:       `{"method":"resources/read","params":{"uri":"file:///protected","URI":"file:///safe"}}`,
			wantReject: true,
		},
		{
			name:       "canonical exempt method",
			body:       `{"jsonrpc":"2.0","id":1,"method":"ping"}`,
			wantReject: false,
		},
		{
			name:       "unrelated extra member is tolerated",
			body:       `{"jsonrpc":"2.0","id":1,"method":"ping","_meta":{"Trace":"abc"}}`,
			wantReject: false,
		},
		{
			name: "mixed case tool arguments are untouched",
			body: `{"jsonrpc":"2.0","id":1,"method":"tools/call",` +
				`"params":{"name":"safe_tool","arguments":{"UserID":1,"Nested":{"Key":"v"}}}}`,
			wantReject: false,
		},
		{
			name:       "extension method parameters are untouched",
			body:       `{"jsonrpc":"2.0","id":1,"method":"vendor/run","params":{"Name":"case-sensitive","URI":"custom"}}`,
			wantReject: false,
		},
		{
			name:       "non-object params is not inspected",
			body:       `{"jsonrpc":"2.0","id":1,"method":"ping","params":null}`,
			wantReject: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &McpAuthPolicy{
				OnFailureStatusCode: 401,
				ErrorMessageFormat:  "json",
				AuthConfig: GetMcpAuthConfig(map[string]any{
					"tools":     map[string]any{"enabled": true, "exceptions": []any{"safe_tool"}},
					"resources": map[string]any{"enabled": true, "exceptions": []any{"file:///safe"}},
					"methods":   map[string]any{"enabled": true, "exceptions": []any{"ping", "vendor/run"}},
				}),
			}
			ctx := createMockRequestBodyContext(nil)
			ctx.Method = "POST"
			ctx.Path = "/mcp"
			ctx.OperationPath = "/mcp"
			ctx.Body = &policy.Body{Content: []byte(tt.body), Present: true}

			action := p.OnRequestBody(context.Background(), ctx, map[string]any{})

			if !tt.wantReject {
				if action != nil {
					t.Fatalf("Expected the request to be accepted as exempt, got %T: %+v", action, action)
				}
				return
			}
			resp, ok := action.(policy.ImmediateResponse)
			if !ok {
				t.Fatalf("Expected ImmediateResponse rejecting the request, got %T", action)
			}
			assertJSONRPCError(t, resp, JSONRPCInvalidRequest, "Invalid Request")

			var parsed jsonRPCErrorResponse
			if err := json.Unmarshal(resp.Body, &parsed); err != nil {
				t.Fatalf("Failed to decode error body: %v", err)
			}
			if !strings.HasPrefix(parsed.Error.Data, "Ambiguous MCP request:") {
				t.Errorf("Expected the error data to explain the ambiguity, got %q", parsed.Error.Data)
			}
		})
	}
}

func TestOnRequestBody_InvalidOnFailureStatusCode(t *testing.T) {
	p := &McpAuthPolicy{}
	ctx := createMockRequestBodyContext(nil)
	ctx.Path = "/api/resource"

	action := p.OnRequestBody(context.Background(), ctx, map[string]any{
		"onFailureStatusCode": 200,
	})

	resp, ok := action.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("Expected ImmediateResponse, got %T", action)
	}
	if resp.StatusCode != 500 {
		t.Fatalf("Expected status 500, got %d", resp.StatusCode)
	}
}

func TestOnRequestBody_InvalidErrorMessageFormat(t *testing.T) {
	p := &McpAuthPolicy{}
	ctx := createMockRequestBodyContext(nil)
	ctx.Path = "/api/resource"

	action := p.OnRequestBody(context.Background(), ctx, map[string]any{
		"errorMessageFormat": "xml",
	})

	resp, ok := action.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("Expected ImmediateResponse, got %T", action)
	}
	if resp.StatusCode != 500 {
		t.Fatalf("Expected status 500, got %d", resp.StatusCode)
	}
}

func TestOnRequestHeaders_WellKnown_PathWithPrefix_Success(t *testing.T) {
	p := createTestPolicy()
	ctx := createMockRequestHeaderContext(nil)
	ctx.Method = "GET"
	ctx.OperationPath = "/mcp/v1/.well-known/oauth-protected-resource"

	action := p.OnRequestHeaders(context.Background(), ctx, map[string]any{
		"keyManagers": []any{
			map[string]any{
				"name":   "km1",
				"issuer": "https://issuer1.com",
			},
		},
	})

	resp, ok := action.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("Expected ImmediateResponse, got %T", action)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("Expected status 200, got %d", resp.StatusCode)
	}
}

func TestOnRequestHeaders_WellKnown_FalsePositivePathDoesNotMatch(t *testing.T) {
	p := createTestPolicy()
	ctx := createMockRequestHeaderContext(nil)
	ctx.Method = "GET"
	ctx.OperationPath = "/api/.well-known/oauth-protected-resource-extra"

	action := p.OnRequestHeaders(context.Background(), ctx, map[string]any{})

	// The path doesn't match well-known endpoint pattern
	// so the policy returns UpstreamRequestHeaderModifications (no action taken)
	_, ok := action.(policy.UpstreamRequestHeaderModifications)
	if !ok {
		t.Fatalf("Expected UpstreamRequestHeaderModifications (no match), got %T", action)
	}
}

// ─── Transport endpoint authentication (GET /mcp, DELETE /mcp) ───────────────
//
// Only POST /mcp carries a JSON-RPC body, so the POST-only body-phase check used to
// let GET (SSE stream) and DELETE (session termination) through unauthenticated.

// mcpTransportKeyManagerParams returns delegation params pointing at a JWKS test server.
func mcpTransportKeyManagerParams(jwksURL string) map[string]any {
	return map[string]any{
		"gatewayHost":         "gateway.com",
		"headerName":          "Authorization",
		"authHeaderScheme":    "Bearer",
		"onFailureStatusCode": 401,
		"errorMessageFormat":  "json",
		"keyManagers": []any{
			map[string]any{
				"name":   "test-issuer",
				"issuer": "https://issuer.example.com",
				"jwks": map[string]any{
					"remote": map[string]any{
						"uri": jwksURL + "/jwks.json",
					},
				},
			},
		},
	}
}

// mcpTransportRequest issues an OnRequestHeaders call for the given method on /mcp.
func mcpTransportRequest(t *testing.T, p *McpAuthPolicy, method string, headers map[string][]string, params map[string]any) policy.RequestHeaderAction {
	t.Helper()
	ctx := createMockRequestHeaderContext(headers)
	ctx.Method = method
	ctx.Path = "/mcp"
	ctx.OperationPath = "/mcp"
	return p.OnRequestHeaders(context.Background(), ctx, params)
}

// TestOnRequestHeaders_TransportEndpoints_RequireAuthentication verifies GET/DELETE
// /mcp are rejected with a 401 challenge when no token is presented.
func TestOnRequestHeaders_TransportEndpoints_RequireAuthentication(t *testing.T) {
	_, publicKey := generateRSATestKeys(t)
	jwksServer := createMcpTestJWKSServer(t, publicKey, "test-kid")
	defer jwksServer.Close()

	for _, method := range []string{"GET", "DELETE"} {
		t.Run(method, func(t *testing.T) {
			action := mcpTransportRequest(t, createTestPolicy(), method, map[string][]string{
				McpSessionHeader: {"session-123"},
			}, mcpTransportKeyManagerParams(jwksServer.URL))

			resp, ok := action.(policy.ImmediateResponse)
			if !ok {
				t.Fatalf("%s /mcp was forwarded upstream without authentication: got %T, want ImmediateResponse", method, action)
			}
			if resp.StatusCode != 401 {
				t.Errorf("Expected status 401, got %d", resp.StatusCode)
			}
			expectedPrefix := `Bearer resource_metadata="http://gateway.com:8080/.well-known/oauth-protected-resource"`
			if authHeader := resp.Headers[WWWAuthenticateHeader]; !strings.HasPrefix(authHeader, expectedPrefix) {
				t.Errorf("Unexpected WWW-Authenticate header: %q", authHeader)
			}
			if resp.Headers[McpSessionHeader] != "session-123" {
				t.Errorf("Expected session header 'session-123', got %q", resp.Headers[McpSessionHeader])
			}
		})
	}
}

// TestOnRequestHeaders_TransportEndpoints_ValidTokenAccepted verifies a valid token
// lets GET/DELETE /mcp through and is recorded as an mcp/oauth authentication.
func TestOnRequestHeaders_TransportEndpoints_ValidTokenAccepted(t *testing.T) {
	privateKey, publicKey := generateRSATestKeys(t)
	jwksServer := createMcpTestJWKSServer(t, publicKey, "test-kid")
	defer jwksServer.Close()

	token := createMcpTestToken(t, privateKey, map[string]interface{}{
		"sub": "user123",
		"iss": "https://issuer.example.com",
	})

	for _, method := range []string{"GET", "DELETE"} {
		t.Run(method, func(t *testing.T) {
			ctx := createMockRequestHeaderContext(map[string][]string{
				"authorization": {fmt.Sprintf("Bearer %s", token)},
			})
			ctx.Method = method
			ctx.Path = "/mcp"
			ctx.OperationPath = "/mcp"

			action := createTestPolicy().OnRequestHeaders(context.Background(), ctx, mcpTransportKeyManagerParams(jwksServer.URL))

			if _, ok := action.(policy.ImmediateResponse); ok {
				t.Fatalf("Expected %s /mcp with a valid token to be forwarded, got an auth failure", method)
			}
			if ctx.SharedContext.AuthContext == nil || !ctx.SharedContext.AuthContext.Authenticated {
				t.Fatal("Expected AuthContext to be set and authenticated")
			}
			if ctx.SharedContext.AuthContext.AuthType != AuthType {
				t.Errorf("Expected AuthType %q, got %q", AuthType, ctx.SharedContext.AuthContext.AuthType)
			}
		})
	}
}

// TestOnRequestHeaders_OptionsMcp_SkipsAuthentication verifies CORS preflights stay
// unauthenticated, since browsers send them without credentials.
func TestOnRequestHeaders_OptionsMcp_SkipsAuthentication(t *testing.T) {
	action := mcpTransportRequest(t, createTestPolicy(), "OPTIONS", nil, map[string]any{})

	if _, ok := action.(policy.UpstreamRequestHeaderModifications); !ok {
		t.Fatalf("Expected OPTIONS /mcp to pass through, got %T", action)
	}
}

// TestOnRequestHeaders_PostMcp_DefersToBodyPhase verifies POST /mcp is still gated in
// the body phase, where the JSON-RPC method is known.
func TestOnRequestHeaders_PostMcp_DefersToBodyPhase(t *testing.T) {
	action := mcpTransportRequest(t, createTestPolicy(), "POST", nil, map[string]any{})

	if _, ok := action.(policy.UpstreamRequestHeaderModifications); !ok {
		t.Fatalf("Expected POST /mcp to defer to the body phase, got %T", action)
	}
}

// TestOnRequestHeaders_TransportEndpoints_FullyUnprotectedServer verifies an MCP
// server with every capability group disabled keeps its transport endpoints open.
func TestOnRequestHeaders_TransportEndpoints_FullyUnprotectedServer(t *testing.T) {
	p := createTestPolicy()
	p.AuthConfig = GetMcpAuthConfig(map[string]any{
		"tools":     map[string]any{"enabled": false},
		"resources": map[string]any{"enabled": false},
		"prompts":   map[string]any{"enabled": false},
		"methods":   map[string]any{"enabled": false},
	})

	action := mcpTransportRequest(t, p, "GET", nil, map[string]any{})

	if _, ok := action.(policy.UpstreamRequestHeaderModifications); !ok {
		t.Fatalf("Expected GET /mcp on a fully public MCP server to pass through, got %T", action)
	}
}

// TestOnRequestHeaders_TransportEndpoints_PartiallyProtectedServer verifies the
// transport endpoints stay gated while any part of the MCP server is still protected.
func TestOnRequestHeaders_TransportEndpoints_PartiallyProtectedServer(t *testing.T) {
	cases := map[string]map[string]any{
		"methods disabled, tools enabled": {
			"tools":     map[string]any{"enabled": true},
			"resources": map[string]any{"enabled": false},
			"prompts":   map[string]any{"enabled": false},
			"methods":   map[string]any{"enabled": false},
		},
		// An exception under a disabled group inverts to "requires auth".
		"all disabled, one exception": {
			"tools":     map[string]any{"enabled": false},
			"resources": map[string]any{"enabled": false},
			"prompts":   map[string]any{"enabled": false},
			"methods":   map[string]any{"enabled": false, "exceptions": []any{"tools/call"}},
		},
	}

	_, publicKey := generateRSATestKeys(t)
	jwksServer := createMcpTestJWKSServer(t, publicKey, "test-kid")
	defer jwksServer.Close()

	for name, authConfig := range cases {
		t.Run(name, func(t *testing.T) {
			p := createTestPolicy()
			p.AuthConfig = GetMcpAuthConfig(authConfig)

			action := mcpTransportRequest(t, p, "GET", nil, mcpTransportKeyManagerParams(jwksServer.URL))

			resp, ok := action.(policy.ImmediateResponse)
			if !ok {
				t.Fatalf("Expected GET /mcp to be challenged, got %T", action)
			}
			if resp.StatusCode != 401 {
				t.Errorf("Expected status 401, got %d", resp.StatusCode)
			}
		})
	}
}

// TestRequiresTransportAuth covers the request classification directly.
func TestRequiresTransportAuth(t *testing.T) {
	p := createTestPolicy()
	cases := []struct {
		name          string
		method        string
		operationPath string
		want          bool
	}{
		{"GET on mcp endpoint", "GET", "/mcp", true},
		{"DELETE on mcp endpoint", "DELETE", "/mcp", true},
		{"HEAD on mcp endpoint", "HEAD", "/mcp", true},
		{"lower-cased delete", "delete", "/mcp", true},
		{"POST is gated in the body phase", "POST", "/mcp", false},
		{"lower-cased post is gated in the body phase", "post", "/mcp", false},
		{"OPTIONS preflight", "OPTIONS", "/mcp", false},
		{"protected resource metadata stays public", "GET", "/.well-known/oauth-protected-resource", false},
		{"context-prefixed metadata stays public", "GET", "/mcp/v1/.well-known/oauth-protected-resource", false},
		{"non-mcp operation", "GET", "/api/resource", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := p.requiresTransportAuth(tc.method, tc.operationPath); got != tc.want {
				t.Errorf("requiresTransportAuth(%q, %q) = %v, want %v", tc.method, tc.operationPath, got, tc.want)
			}
		})
	}
}

// TestOnRequestBody_TransportEndpoints_NoSecondDelegation verifies the body phase
// leaves GET/DELETE /mcp alone, as the header phase has already authenticated them.
func TestOnRequestBody_TransportEndpoints_NoSecondDelegation(t *testing.T) {
	for _, method := range []string{"GET", "DELETE"} {
		t.Run(method, func(t *testing.T) {
			ctx := createMockRequestBodyContext(nil)
			ctx.Method = method
			ctx.Path = "/mcp"
			ctx.OperationPath = "/mcp"

			action := createTestPolicy().OnRequestBody(context.Background(), ctx, map[string]any{})

			if _, ok := action.(policy.UpstreamRequestModifications); !ok {
				t.Fatalf("Expected %s /mcp body phase to pass through, got %T", method, action)
			}
		})
	}
}

func TestOnRequestBody_WellKnown_MissingIssuerInKeyManagerConfig(t *testing.T) {
	p := &McpAuthPolicy{}
	ctx := createMockRequestBodyContext(nil)
	ctx.Method = "GET"
	ctx.Path = "/.well-known/oauth-protected-resource"

	action := p.OnRequestBody(context.Background(), ctx, map[string]any{
		"keyManagers": []any{
			map[string]any{
				"name": "km1",
			},
		},
	})

	resp, ok := action.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("Expected ImmediateResponse, got %T", action)
	}
	if resp.StatusCode != 500 {
		t.Fatalf("Expected status 500, got %d", resp.StatusCode)
	}
}

func TestOnRequestHeaders_HandleAuthFailureWithNilMetadata(t *testing.T) {
	p, _ := GetPolicy(policy.PolicyMetadata{}, map[string]any{
		"issuers": []any{"unknown-km"},
	})
	ctx := createMockRequestHeaderContext(nil)
	ctx.SharedContext.Metadata = nil
	ctx.Method = "GET"
	ctx.OperationPath = "/.well-known/oauth-protected-resource"

	action := p.(*McpAuthPolicy).OnRequestHeaders(context.Background(), ctx, map[string]any{
		"keyManagers": []any{
			map[string]any{
				"name":   "km1",
				"issuer": "https://issuer1.com",
			},
		},
	})

	resp, ok := action.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("Expected ImmediateResponse, got %T", action)
	}
	if resp.StatusCode != 401 {
		t.Fatalf("Expected status 401, got %d", resp.StatusCode)
	}
	if ctx.SharedContext.Metadata == nil {
		t.Fatal("Expected metadata map to be initialized")
	}
	if got := ctx.SharedContext.Metadata[MetadataKeyAuthSuccess]; got != false {
		t.Fatalf("Expected auth.success=false, got %v", got)
	}
	if got := ctx.SharedContext.Metadata[MetadataKeyAuthMethod]; got != "mcpAuth" {
		t.Fatalf("Expected auth.method=mcpAuth, got %v", got)
	}
}

// createTestPolicy creates an McpAuthPolicy with valid default configuration for testing
func createTestPolicy() *McpAuthPolicy {
	return &McpAuthPolicy{
		OnFailureStatusCode: 401,
		ErrorMessageFormat:  "json",
		AuthConfig:          GetMcpAuthConfig(map[string]any{}),
	}
}

func TestOnRequestBody_Delegation_Success_SetsAuthContextAuthType(t *testing.T) {
	privateKey, publicKey := generateRSATestKeys(t)
	jwksServer := createMcpTestJWKSServer(t, publicKey, "test-kid")
	defer jwksServer.Close()

	token := createMcpTestToken(t, privateKey, map[string]interface{}{
		"sub":   "user123",
		"iss":   "https://issuer.example.com",
		"scope": "read write",
	})

	p := createTestPolicy()
	ctx := createMockRequestBodyContext(map[string][]string{
		"authorization": {fmt.Sprintf("Bearer %s", token)},
	})
	ctx.Method = "POST"
	ctx.Path = "/mcp"
	ctx.OperationPath = "/mcp"

	params := map[string]any{
		"headerName":          "Authorization",
		"authHeaderScheme":    "Bearer",
		"onFailureStatusCode": 401,
		"errorMessageFormat":  "json",
		"allowedAlgorithms":   []any{"RS256"},
		"keyManagers": []any{
			map[string]any{
				"name":   "test-issuer",
				"issuer": "https://issuer.example.com",
				"jwks": map[string]any{
					"remote": map[string]any{
						"uri": jwksServer.URL + "/jwks.json",
					},
				},
			},
		},
	}

	action := p.OnRequestBody(context.Background(), ctx, params)

	// Should NOT be an ImmediateResponse — jwt-auth succeeded
	if _, ok := action.(policy.ImmediateResponse); ok {
		t.Fatalf("Expected successful action (not ImmediateResponse), but got auth failure")
	}

	// AuthContext must be set and authenticated
	if ctx.SharedContext.AuthContext == nil {
		t.Fatal("Expected AuthContext to be set on success")
	}
	if !ctx.SharedContext.AuthContext.Authenticated {
		t.Error("Expected AuthContext.Authenticated=true on success")
	}
	// AuthType must be overridden to mcp/oauth by mcp-auth
	if ctx.SharedContext.AuthContext.AuthType != "mcp/oauth" {
		t.Errorf("Expected AuthType='mcp/oauth', got %q", ctx.SharedContext.AuthContext.AuthType)
	}
}

// TestOnRequestBody_RequiredScopes_NotEnforced: requiredScopes are advertise-only, so a token missing them still authenticates. Regression test for wso2/api-platform#2589.
func TestOnRequestBody_RequiredScopes_NotEnforced(t *testing.T) {
	privateKey, publicKey := generateRSATestKeys(t)
	jwksServer := createMcpTestJWKSServer(t, publicKey, "test-kid")
	defer jwksServer.Close()

	// Token carries only "read" — missing "write" and "admin".
	token := createMcpTestToken(t, privateKey, map[string]interface{}{
		"sub":   "user123",
		"iss":   "https://issuer.example.com",
		"scope": "read",
	})

	p := createTestPolicy()
	p.RequiredScopes = []string{"read", "write", "admin"}

	ctx := createMockRequestBodyContext(map[string][]string{
		"authorization": {fmt.Sprintf("Bearer %s", token)},
	})
	ctx.Method = "POST"
	ctx.Path = "/mcp"
	ctx.OperationPath = "/mcp"

	params := map[string]any{
		"headerName":          "Authorization",
		"authHeaderScheme":    "Bearer",
		"onFailureStatusCode": 401,
		"errorMessageFormat":  "json",
		"allowedAlgorithms":   []any{"RS256"},
		// Present in params as at runtime; the policy must strip it before delegating.
		"requiredScopes": []any{"read", "write", "admin"},
		"keyManagers": []any{
			map[string]any{
				"name":   "test-issuer",
				"issuer": "https://issuer.example.com",
				"jwks": map[string]any{
					"remote": map[string]any{
						"uri": jwksServer.URL + "/jwks.json",
					},
				},
			},
		},
	}

	action := p.OnRequestBody(context.Background(), ctx, params)

	// Must NOT be rejected: requiredScopes are advertised, not enforced, by mcp-auth.
	if _, ok := action.(policy.ImmediateResponse); ok {
		t.Fatalf("Expected success despite missing scopes (advertise-only), but got auth failure")
	}
	if ctx.SharedContext.AuthContext == nil || !ctx.SharedContext.AuthContext.Authenticated {
		t.Fatal("Expected token to authenticate successfully even though it lacks configured requiredScopes")
	}

	// The original params map must be left untouched (no in-place deletion).
	if _, ok := params["requiredScopes"]; !ok {
		t.Error("Expected params[\"requiredScopes\"] to be preserved; policy must copy, not mutate")
	}
}

func createMockRequestBodyContext(headers map[string][]string) *policy.RequestContext {
	if headers == nil {
		headers = map[string][]string{}
	}
	return &policy.RequestContext{
		SharedContext: &policy.SharedContext{
			RequestID: "test-request-id",
			Metadata:  make(map[string]any),
		},
		Headers:   policy.NewHeaders(headers),
		Path:      "/api/test",
		Method:    "GET",
		Scheme:    "http",
		Authority: "localhost:8080",
	}
}

// createMockRequestHeaderContext creates a RequestHeaderContext for testing OnRequestHeaders
func createMockRequestHeaderContext(headers map[string][]string) *policy.RequestHeaderContext {
	if headers == nil {
		headers = map[string][]string{}
	}
	return &policy.RequestHeaderContext{
		SharedContext: &policy.SharedContext{
			RequestID: "test-request-id",
			Metadata:  make(map[string]any),
		},
		Headers:   policy.NewHeaders(headers),
		Path:      "/api/test",
		Method:    "GET",
		Scheme:    "http",
		Authority: "localhost:8080",
	}
}

// generateRSATestKeys creates a fresh RSA key pair for use in tests.
func generateRSATestKeys(t *testing.T) (*rsa.PrivateKey, *rsa.PublicKey) {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}
	return privateKey, &privateKey.PublicKey
}

// createMcpTestToken creates a signed JWT with the given claims, valid for 1 hour.
func createMcpTestToken(t *testing.T, privateKey *rsa.PrivateKey, claims map[string]interface{}) string {
	t.Helper()
	mapClaims := jwt.MapClaims{}
	for k, v := range claims {
		mapClaims[k] = v
	}
	mapClaims["exp"] = time.Now().Add(time.Hour).Unix()
	mapClaims["iat"] = time.Now().Unix()

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, mapClaims)
	token.Header["kid"] = "test-kid"
	signed, err := token.SignedString(privateKey)
	if err != nil {
		t.Fatalf("Failed to sign token: %v", err)
	}
	return signed
}

// createMcpTestJWKSServer starts an httptest server that serves a JWKS for the given public key.
func createMcpTestJWKSServer(t *testing.T, publicKey *rsa.PublicKey, kid string) *httptest.Server {
	t.Helper()
	nBytes := publicKey.N.Bytes()
	eBytes := big.NewInt(int64(publicKey.E)).Bytes()
	jwks := map[string]interface{}{
		"keys": []interface{}{
			map[string]interface{}{
				"kty": "RSA",
				"use": "sig",
				"kid": kid,
				"alg": "RS256",
				"n":   base64.RawURLEncoding.EncodeToString(nBytes),
				"e":   base64.RawURLEncoding.EncodeToString(eBytes),
			},
		},
	}
	jwksJSON, err := json.Marshal(jwks)
	if err != nil {
		t.Fatalf("Failed to marshal JWKS: %v", err)
	}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(jwksJSON)
	}))
}

func TestGetSecurityConfigParam_Defaults(t *testing.T) {
	params := map[string]interface{}{}

	config := getSecurityConfigParam(params, "tools")

	if !config.Enabled {
		t.Error("Expected Enabled to default to true")
	}
	if len(config.Exceptions) != 0 {
		t.Errorf("Expected empty exceptions, got %v", config.Exceptions)
	}
}

func TestGetSecurityConfigParam_WithValues(t *testing.T) {
	params := map[string]interface{}{
		"tools": map[string]interface{}{
			"enabled":    false,
			"exceptions": []interface{}{"tool1", "tool2"},
		},
	}

	config := getSecurityConfigParam(params, "tools")

	if config.Enabled {
		t.Error("Expected Enabled to be false")
	}
	if len(config.Exceptions) != 2 {
		t.Errorf("Expected 2 exceptions, got %d", len(config.Exceptions))
	}
	if config.Exceptions[0] != "tool1" || config.Exceptions[1] != "tool2" {
		t.Errorf("Unexpected exceptions: %v", config.Exceptions)
	}
}

func TestGetMcpAuthConfig_AllFields(t *testing.T) {
	params := map[string]interface{}{
		"tools": map[string]interface{}{
			"enabled":    true,
			"exceptions": []interface{}{"public-tool"},
		},
		"resources": map[string]interface{}{
			"enabled":    false,
			"exceptions": []interface{}{"public-resource"},
		},
		"prompts": map[string]interface{}{
			"enabled":    true,
			"exceptions": []interface{}{},
		},
		"methods": map[string]interface{}{
			"enabled":    false,
			"exceptions": []interface{}{"initialize", "ping"},
		},
	}

	config := GetMcpAuthConfig(params)

	// Check tools
	if !config.Tools.Enabled {
		t.Error("Expected Tools.Enabled to be true")
	}
	if len(config.Tools.Exceptions) != 1 || config.Tools.Exceptions[0] != "public-tool" {
		t.Errorf("Unexpected Tools.Exceptions: %v", config.Tools.Exceptions)
	}

	// Check resources
	if config.Resources.Enabled {
		t.Error("Expected Resources.Enabled to be false")
	}
	if len(config.Resources.Exceptions) != 1 || config.Resources.Exceptions[0] != "public-resource" {
		t.Errorf("Unexpected Resources.Exceptions: %v", config.Resources.Exceptions)
	}

	// Check prompts
	if !config.Prompts.Enabled {
		t.Error("Expected Prompts.Enabled to be true")
	}
	if len(config.Prompts.Exceptions) != 0 {
		t.Errorf("Expected empty Prompts.Exceptions, got %v", config.Prompts.Exceptions)
	}

	// Check methods
	if config.Methods.Enabled {
		t.Error("Expected Methods.Enabled to be false")
	}
	if len(config.Methods.Exceptions) != 2 {
		t.Errorf("Expected 2 Methods.Exceptions, got %d", len(config.Methods.Exceptions))
	}
}

func TestGetMcpAuthConfig_EmptyParams(t *testing.T) {
	params := map[string]interface{}{}

	config := GetMcpAuthConfig(params)

	// All should have defaults
	if !config.Tools.Enabled || !config.Resources.Enabled || !config.Prompts.Enabled || !config.Methods.Enabled {
		t.Error("Expected all security configs to default to enabled=true")
	}
}

func TestGetMcpAuthPolicy_WithIssuersAndScopes(t *testing.T) {
	params := map[string]interface{}{
		"tools": map[string]interface{}{
			"enabled":    true,
			"exceptions": []interface{}{"public-tool"},
		},
		"issuers":        []interface{}{"issuer1", "issuer2"},
		"requiredScopes": []interface{}{"read", "write"},
	}

	p, err := GetPolicy(policy.PolicyMetadata{}, params)
	if err != nil {
		t.Fatalf("GetPolicy returned error: %v", err)
	}

	mcpPolicy := p.(*McpAuthPolicy)

	// Check issuers
	if len(mcpPolicy.Issuers) != 2 {
		t.Errorf("Expected 2 issuers, got %d", len(mcpPolicy.Issuers))
	}

	// Check scopes
	if len(mcpPolicy.RequiredScopes) != 2 {
		t.Errorf("Expected 2 scopes, got %d", len(mcpPolicy.RequiredScopes))
	}

	// Check that AuthConfig was also set
	if !mcpPolicy.AuthConfig.Tools.Enabled {
		t.Error("Expected AuthConfig.Tools.Enabled to be true")
	}
}

// assertFallbackBodyAgrees checks the legacy JSON-RPC body that travels with the description.
//
// Both are always sent: the description is what a gateway with an error renderer uses, and
// the body is what a gateway without one sends, so a policy upgraded on its own still answers
// an unparseable request the way it always has. Asserting they AGREE — rather than restating
// the literals — is what catches one of the two drifting.
//
// The `data` member is the one field that deliberately differs in reach, not in content: the
// body carries it, and the description carries the same string as Description, which a
// renderer withholds from the client. So this asserts they hold the same value, and that
// enabling the renderer only ever narrows what a malformed request reveals.
func assertFallbackBodyAgrees(t *testing.T, resp policy.ImmediateResponse) {
	t.Helper()
	if len(resp.Body) == 0 {
		t.Fatal("Expected a fallback body alongside the description, got none")
	}
	if got := resp.Headers["content-type"]; got != "application/json" {
		t.Errorf("Expected content-type application/json for the fallback body, got %q", got)
	}

	var envelope struct {
		JSONRPC string `json:"jsonrpc"`
		ID      any    `json:"id"`
		Error   struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
			Data    string `json:"data"`
		} `json:"error"`
	}
	if err := json.Unmarshal(resp.Body, &envelope); err != nil {
		t.Fatalf("Fallback body is not a JSON-RPC envelope: %v (%q)", err, resp.Body)
	}
	if envelope.JSONRPC != JSONRPCVersion {
		t.Errorf("Expected jsonrpc %q in the fallback body, got %q", JSONRPCVersion, envelope.JSONRPC)
	}
	if envelope.ID != nil {
		t.Errorf("Expected a null id for an unparseable request, got %v", envelope.ID)
	}
	if resp.Fault.JSONRPC == nil || resp.Fault.JSONRPC.Code == nil {
		t.Fatalf("Expected a described JSON-RPC code to compare against, got %+v", resp.Fault)
	}
	if envelope.Error.Code != *resp.Fault.JSONRPC.Code {
		t.Errorf("Fallback body code %d disagrees with the described code %d",
			envelope.Error.Code, *resp.Fault.JSONRPC.Code)
	}
	if envelope.Error.Message != resp.Fault.Message {
		t.Errorf("Fallback body message %q disagrees with the described message %q",
			envelope.Error.Message, resp.Fault.Message)
	}
	if envelope.Error.Data != resp.Fault.Description {
		t.Errorf("Fallback body data %q disagrees with the described Description %q",
			envelope.Error.Data, resp.Fault.Description)
	}
}

// TestMcpAuth_RejectionsDeclareFault covers the three shapes of rejection this policy
// makes, and the one short-circuit that is deliberately NOT a fault. The code, not the
// status, is what tells one rejection from another.
func TestMcpAuth_RejectionsDeclareFault(t *testing.T) {
	t.Run("auth failure", func(t *testing.T) {
		p := &McpAuthPolicy{}
		shared := &policy.SharedContext{Metadata: map[string]any{}}
		resp := p.handleAuthFailure(shared, 401, "json", "key managers not configured", policy.FaultCodeAuthGeneral)

		if !resp.IsFault {
			t.Fatalf("expected IsFault=true on an auth rejection")
		}
		if resp.Fault == nil {
			t.Fatalf("expected Error to be populated")
		}
		if resp.Fault.Code != policy.FaultCodeAuthGeneral {
			t.Fatalf("expected Error.Code=%q, got %q", policy.FaultCodeAuthGeneral, resp.Fault.Code)
		}
		if resp.Fault.Type != policy.FaultTypeAuthentication {
			t.Fatalf("expected Error.Type=%q, got %q", policy.FaultTypeAuthentication, resp.Fault.Type)
		}
		if resp.Fault.Direction != policy.DirectionRequest {
			t.Fatalf("expected Error.Direction=%q, got %q", policy.DirectionRequest, resp.Fault.Direction)
		}
	})

	t.Run("malformed MCP request", func(t *testing.T) {
		p := &McpAuthPolicy{}
		resp := p.handleBadRequest(&json.SyntaxError{})

		if !resp.IsFault {
			t.Fatalf("expected IsFault=true on a malformed request")
		}
		if resp.Fault == nil {
			t.Fatalf("expected Error to be populated")
		}
		if resp.Fault.Code != policy.FaultCodeInvalidRequestBody {
			t.Fatalf("expected Error.Code=%q, got %q", policy.FaultCodeInvalidRequestBody, resp.Fault.Code)
		}
		if resp.Fault.Type != policy.FaultTypeValidation {
			t.Fatalf("expected Error.Type=%q, got %q", policy.FaultTypeValidation, resp.Fault.Type)
		}
	})

	t.Run("invalid configuration", func(t *testing.T) {
		resp := buildInvalidConfigResponse("bad config").(policy.ImmediateResponse)
		if !resp.IsFault {
			t.Fatalf("expected IsFault=true on a misconfigured auth policy")
		}
		if resp.Fault == nil || resp.Fault.Code != policy.FaultCodeAuthGeneral {
			t.Fatalf("expected Error.Code=%q, got %+v", policy.FaultCodeAuthGeneral, resp.Fault)
		}
	})

	t.Run("well-known metadata response is not a fault", func(t *testing.T) {
		// A protected-resource-metadata discovery response is a successful 200. Marking
		// it a fault would notify on every MCP client that reads the metadata.
		privateKey, _ := generateRSATestKeys(t)
		_ = privateKey
		p := &McpAuthPolicy{
			OnFailureStatusCode: 401,
			ErrorMessageFormat:  "json",
		}
		ctx := createMockRequestHeaderContext(map[string][]string{})
		ctx.Path = WellKnownEndpointPath
		ctx.OperationPath = WellKnownEndpointPath
		ctx.Method = "GET"
		params := map[string]interface{}{
			"keyManagers": []interface{}{
				map[string]interface{}{
					"name":   "km",
					"issuer": "https://issuer.example.com",
					"jwks": map[string]interface{}{
						"remote": map[string]interface{}{"uri": "http://127.0.0.1:1/jwks.json"},
					},
				},
			},
		}
		action := p.OnRequestHeaders(context.Background(), ctx, params)
		resp, ok := action.(policy.ImmediateResponse)
		if !ok {
			t.Fatalf("expected ImmediateResponse, got %T", action)
		}
		if resp.StatusCode != 200 {
			t.Fatalf("expected the metadata response, got status %d", resp.StatusCode)
		}
		if resp.IsFault {
			t.Fatalf("the metadata discovery response must not be a fault")
		}
	})
}
