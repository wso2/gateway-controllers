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

package mcpacllist

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

func TestParseAclConfig_ValidationCases(t *testing.T) {
	tests := []struct {
		name              string
		params            map[string]any
		capabilityType    string
		wantErr           string
		wantEnabled       bool
		wantMode          string
		wantExceptionKeys []string
	}{
		{
			name:           "missing capability config returns disabled",
			params:         map[string]any{},
			capabilityType: "tools",
			wantEnabled:    false,
		},
		{
			name: "valid config trims exception values",
			params: map[string]any{
				"tools": map[string]any{
					"mode":       "allow",
					"exceptions": []any{" toolA ", "toolB"},
				},
			},
			capabilityType:    "tools",
			wantEnabled:       true,
			wantMode:          "allow",
			wantExceptionKeys: []string{"toolA", "toolB"},
		},
		{
			name: "missing mode defaults to deny",
			params: map[string]any{
				"tools": map[string]any{},
			},
			capabilityType: "tools",
			wantEnabled:    true,
			wantMode:       "deny",
		},
		{
			name: "invalid mode",
			params: map[string]any{
				"tools": map[string]any{
					"mode": "read-only",
				},
			},
			capabilityType: "tools",
			wantErr:        "tools.mode must be 'allow' or 'deny'",
		},
		{
			name: "capability block must be object",
			params: map[string]any{
				"tools": "not-an-object",
			},
			capabilityType: "tools",
			wantErr:        "tools must be an object",
		},
		{
			name: "exceptions must be array",
			params: map[string]any{
				"tools": map[string]any{
					"mode":       "allow",
					"exceptions": "toolA",
				},
			},
			capabilityType: "tools",
			wantErr:        "tools.exceptions must be an array",
		},
		{
			name: "exceptions values must be non-empty strings",
			params: map[string]any{
				"tools": map[string]any{
					"mode":       "allow",
					"exceptions": []any{"toolA", 123},
				},
			},
			capabilityType: "tools",
			wantErr:        "tools.exceptions[1] must be a non-empty string",
		},
		{
			name: "exceptions reject padded empty string",
			params: map[string]any{
				"tools": map[string]any{
					"mode":       "allow",
					"exceptions": []any{"   "},
				},
			},
			capabilityType: "tools",
			wantErr:        "tools.exceptions[0] must be a non-empty string",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config, err := parseAclConfig(tt.params, tt.capabilityType)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("Expected error containing %q, got nil", tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("Expected error containing %q, got %q", tt.wantErr, err.Error())
				}
				return
			}

			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}
			if config.Enabled != tt.wantEnabled {
				t.Fatalf("Expected enabled %v, got %v", tt.wantEnabled, config.Enabled)
			}
			if config.Mode != tt.wantMode {
				t.Fatalf("Expected mode %q, got %q", tt.wantMode, config.Mode)
			}
			if len(tt.wantExceptionKeys) != len(config.Exceptions) {
				t.Fatalf("Expected %d exceptions, got %d", len(tt.wantExceptionKeys), len(config.Exceptions))
			}
			for _, key := range tt.wantExceptionKeys {
				if _, ok := config.Exceptions[key]; !ok {
					t.Fatalf("Expected exception %q to exist", key)
				}
			}
		})
	}
}

func TestGetPolicy_ValidationCases(t *testing.T) {
	tests := []struct {
		name    string
		params  map[string]any
		wantErr string
	}{
		{
			name:   "empty config keeps all capability configs disabled",
			params: map[string]any{},
		},
		{
			name: "single branch config is accepted",
			params: map[string]any{
				"tools": map[string]any{
					"mode": "deny",
				},
			},
		},
		{
			name: "invalid tools mode",
			params: map[string]any{
				"tools": map[string]any{
					"mode": "invalid",
				},
			},
			wantErr: "invalid tools configuration: tools.mode must be 'allow' or 'deny'",
		},
		{
			name: "resources block must be object",
			params: map[string]any{
				"resources": "invalid",
			},
			wantErr: "invalid resources configuration: resources must be an object",
		},
		{
			name: "prompts exceptions must be array",
			params: map[string]any{
				"prompts": map[string]any{
					"mode":       "allow",
					"exceptions": "prompt-a",
				},
			},
			wantErr: "invalid prompts configuration: prompts.exceptions must be an array",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := GetPolicy(policy.PolicyMetadata{}, tt.params)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("Expected error containing %q, got nil", tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("Expected error containing %q, got %q", tt.wantErr, err.Error())
				}
				return
			}

			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}
			if p == nil {
				t.Fatalf("Expected policy instance, got nil")
			}
		})
	}
}

func TestIsMcpPostRequest_PathMatching(t *testing.T) {
	tests := []struct {
		name     string
		method   string
		path     string
		wantPass bool
	}{
		{name: "exact mcp path", method: "POST", path: "/mcp", wantPass: true},
		{name: "nested mcp path", method: "POST", path: "/mcp/v1", wantPass: true},
		{name: "mcp path with query", method: "POST", path: "/mcp?tenant=a", wantPass: true},
		{name: "non-mcp substring path", method: "POST", path: "/foo-mcp-tools", wantPass: false},
		{name: "non-root mcp segment", method: "POST", path: "/api/mcp", wantPass: false},
		{name: "wrong method", method: "GET", path: "/mcp", wantPass: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := isMcpPostRequest(tt.method, tt.path)
			if actual != tt.wantPass {
				t.Fatalf("Expected %v, got %v", tt.wantPass, actual)
			}
		})
	}
}

func TestOnRequest_DenyWhenException(t *testing.T) {
	params := map[string]any{
		"tools": map[string]any{
			"mode":       "allow",
			"exceptions": []any{"toolA"},
		},
	}

	p, err := GetPolicy(policy.PolicyMetadata{}, params)
	if err != nil {
		t.Fatalf("Failed to create policy: %v", err)
	}

	payload := map[string]any{
		"jsonrpc": "2.0",
		"id":      "1",
		"method":  "tools/call",
		"params": map[string]any{
			"name": "toolA",
		},
	}
	body, _ := json.Marshal(payload)

	ctx := createMockRequestContext(map[string][]string{})
	ctx.Method = "POST"
	ctx.OperationPath = "/mcp"
	ctx.Body = &policy.Body{Content: body, Present: true}

	action := p.(*McpAclListPolicy).OnRequestBody(context.Background(), ctx, params)
	if _, ok := action.(policy.ImmediateResponse); !ok {
		t.Fatalf("Expected ImmediateResponse, got %T", action)
	}
}

func TestOnRequest_AllowWhenNotException(t *testing.T) {
	params := map[string]any{
		"tools": map[string]any{
			"mode":       "allow",
			"exceptions": []any{"toolA"},
		},
	}

	p, err := GetPolicy(policy.PolicyMetadata{}, params)
	if err != nil {
		t.Fatalf("Failed to create policy: %v", err)
	}

	payload := map[string]any{
		"jsonrpc": "2.0",
		"id":      "1",
		"method":  "tools/call",
		"params": map[string]any{
			"name": "toolB",
		},
	}
	body, _ := json.Marshal(payload)

	ctx := createMockRequestContext(map[string][]string{})
	ctx.Method = "POST"
	ctx.OperationPath = "/mcp"
	ctx.Body = &policy.Body{Content: body, Present: true}

	action := p.(*McpAclListPolicy).OnRequestBody(context.Background(), ctx, params)
	if _, ok := action.(policy.UpstreamRequestModifications); !ok {
		t.Fatalf("Expected UpstreamRequestModifications (continue), got %T", action)
	}
}

func TestOnRequest_DenySSERequestWithSessionHeader(t *testing.T) {
	params := map[string]any{
		"tools": map[string]any{
			"mode":       "allow",
			"exceptions": []any{"toolA"},
		},
	}

	p, err := GetPolicy(policy.PolicyMetadata{}, params)
	if err != nil {
		t.Fatalf("Failed to create policy: %v", err)
	}

	payload := map[string]any{
		"jsonrpc": "2.0",
		"id":      "sse-1",
		"method":  "tools/call",
		"params": map[string]any{
			"name": "toolA",
		},
	}
	payloadBytes, _ := json.Marshal(payload)
	streamBody := buildEventStream([]sseEvent{{fields: []string{"event: message"}, data: string(payloadBytes)}})

	ctx := createMockRequestContext(map[string][]string{
		"content-type":   {"text/event-stream"},
		"mcp-session-id": {"session-123"},
	})
	ctx.Method = "POST"
	ctx.OperationPath = "/mcp"
	ctx.Body = &policy.Body{Content: streamBody, Present: true}

	action := p.(*McpAclListPolicy).OnRequestBody(context.Background(), ctx, params)
	resp, ok := action.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("Expected ImmediateResponse, got %T", action)
	}
	if resp.StatusCode != 400 {
		t.Fatalf("Expected status 400, got %d", resp.StatusCode)
	}
	if resp.Headers["Content-Type"] != "text/event-stream" {
		t.Fatalf("Expected event stream response, got %q", resp.Headers["Content-Type"])
	}
	if resp.Headers[mcpSessionHeader] != "session-123" {
		t.Fatalf("Expected session header to be propagated")
	}

	events := parseEventStream(resp.Body)
	if len(events) != 1 {
		t.Fatalf("Expected 1 SSE event in response, got %d", len(events))
	}

	var responsePayload map[string]any
	if err := json.Unmarshal([]byte(events[0].data), &responsePayload); err != nil {
		t.Fatalf("Failed to parse SSE response payload: %v", err)
	}
	if responsePayload["id"] != "sse-1" {
		t.Fatalf("Expected JSON-RPC id sse-1, got %v", responsePayload["id"])
	}

	errObj, ok := responsePayload["error"].(map[string]any)
	if !ok {
		t.Fatalf("Expected error object in SSE response")
	}
	if errObj["code"] != float64(-32000) {
		t.Fatalf("Expected error code -32000, got %v", errObj["code"])
	}
}

func TestOnResponse_FilterList_DenyMode(t *testing.T) {
	params := map[string]any{
		"tools": map[string]any{
			"mode":       "deny",
			"exceptions": []any{"toolB"},
		},
	}

	p, err := GetPolicy(policy.PolicyMetadata{}, params)
	if err != nil {
		t.Fatalf("Failed to create policy: %v", err)
	}

	responsePayload := map[string]any{
		"jsonrpc": "2.0",
		"id":      "1",
		"result": map[string]any{
			"tools": []any{
				map[string]any{"name": "toolA"},
				map[string]any{"name": "toolB"},
			},
		},
	}
	body, _ := json.Marshal(responsePayload)

	ctx := createMockResponseContext(nil, nil)
	ctx.RequestMethod = "POST"
	ctx.OperationPath = "/mcp"
	ctx.ResponseBody = &policy.Body{Content: body, Present: true}
	ctx.Metadata[metadataMcpCapabilityType] = "tools"
	ctx.Metadata[metadataMcpAction] = "list"

	action := p.(*McpAclListPolicy).OnResponseBody(context.Background(), ctx, params)
	mods, ok := action.(policy.DownstreamResponseModifications)
	if !ok {
		t.Fatalf("Expected UpstreamResponseModifications, got %T", action)
	}

	var updated map[string]any
	if err := json.Unmarshal(mods.Body, &updated); err != nil {
		t.Fatalf("Failed to unmarshal response: %v", err)
	}
	result := updated["result"].(map[string]any)
	tools := result["tools"].([]any)
	if len(tools) != 1 {
		t.Fatalf("Expected 1 tool, got %d", len(tools))
	}
	tool := tools[0].(map[string]any)
	if tool["name"] != "toolB" {
		t.Fatalf("Expected toolB, got %v", tool["name"])
	}
}

func TestOnResponse_FilterList_ResourcesUri(t *testing.T) {
	params := map[string]any{
		"resources": map[string]any{
			"mode":       "deny",
			"exceptions": []any{"https://example.com/allowed"},
		},
	}

	p, err := GetPolicy(policy.PolicyMetadata{}, params)
	if err != nil {
		t.Fatalf("Failed to create policy: %v", err)
	}

	responsePayload := map[string]any{
		"jsonrpc": "2.0",
		"id":      "1",
		"result": map[string]any{
			"resources": []any{
				map[string]any{"uri": "https://example.com/blocked"},
				map[string]any{"uri": "https://example.com/allowed"},
			},
		},
	}
	body, _ := json.Marshal(responsePayload)

	ctx := createMockResponseContext(nil, nil)
	ctx.RequestMethod = "POST"
	ctx.OperationPath = "/mcp"
	ctx.ResponseBody = &policy.Body{Content: body, Present: true}
	ctx.Metadata[metadataMcpCapabilityType] = "resources"
	ctx.Metadata[metadataMcpAction] = "list"

	action := p.(*McpAclListPolicy).OnResponseBody(context.Background(), ctx, params)
	mods, ok := action.(policy.DownstreamResponseModifications)
	if !ok {
		t.Fatalf("Expected UpstreamResponseModifications, got %T", action)
	}

	var updated map[string]any
	if err := json.Unmarshal(mods.Body, &updated); err != nil {
		t.Fatalf("Failed to unmarshal response: %v", err)
	}
	result := updated["result"].(map[string]any)
	resources := result["resources"].([]any)
	if len(resources) != 1 {
		t.Fatalf("Expected 1 resource, got %d", len(resources))
	}
	resource := resources[0].(map[string]any)
	if resource["uri"] != "https://example.com/allowed" {
		t.Fatalf("Expected allowed resource, got %v", resource["uri"])
	}
}

func TestOnResponse_SSEFilterOnlyListEvents(t *testing.T) {
	params := map[string]any{
		"tools": map[string]any{
			"mode":       "deny",
			"exceptions": []any{"toolB"},
		},
	}

	p, err := GetPolicy(policy.PolicyMetadata{}, params)
	if err != nil {
		t.Fatalf("Failed to create policy: %v", err)
	}

	listPayload := map[string]any{
		"jsonrpc": "2.0",
		"id":      "1",
		"result": map[string]any{
			"tools": []any{
				map[string]any{"name": "toolA"},
				map[string]any{"name": "toolB"},
			},
		},
	}
	listPayloadBytes, _ := json.Marshal(listPayload)

	nonListPayload := map[string]any{
		"jsonrpc": "2.0",
		"id":      "2",
		"result": map[string]any{
			"message": "keep-me",
		},
	}
	nonListPayloadBytes, _ := json.Marshal(nonListPayload)

	streamBody := buildEventStream([]sseEvent{
		{fields: []string{"event: list"}, data: string(listPayloadBytes)},
		{fields: []string{"event: heartbeat"}},
		{fields: []string{"event: passthrough"}, data: string(nonListPayloadBytes)},
	})

	ctx := createMockResponseContext(nil, map[string][]string{
		"content-type": {"text/event-stream"},
	})
	ctx.RequestMethod = "POST"
	ctx.OperationPath = "/mcp"
	ctx.ResponseBody = &policy.Body{Content: streamBody, Present: true}
	ctx.Metadata[metadataMcpCapabilityType] = "tools"
	ctx.Metadata[metadataMcpAction] = "list"

	action := p.(*McpAclListPolicy).OnResponseBody(context.Background(), ctx, params)
	mods, ok := action.(policy.DownstreamResponseModifications)
	if !ok {
		t.Fatalf("Expected UpstreamResponseModifications, got %T", action)
	}

	events := parseEventStream(mods.Body)
	if len(events) != 3 {
		t.Fatalf("Expected 3 SSE events, got %d", len(events))
	}

	var updatedListPayload map[string]any
	if err := json.Unmarshal([]byte(events[0].data), &updatedListPayload); err != nil {
		t.Fatalf("Failed to parse updated list event: %v", err)
	}
	updatedResult := updatedListPayload["result"].(map[string]any)
	updatedTools := updatedResult["tools"].([]any)
	if len(updatedTools) != 1 {
		t.Fatalf("Expected filtered list event to contain 1 tool, got %d", len(updatedTools))
	}
	if updatedTools[0].(map[string]any)["name"] != "toolB" {
		t.Fatalf("Expected filtered tool to be toolB, got %v", updatedTools[0].(map[string]any)["name"])
	}

	if events[1].data != "" {
		t.Fatalf("Expected heartbeat event data to stay empty")
	}
	if events[2].data != string(nonListPayloadBytes) {
		t.Fatalf("Expected non-list event payload to remain unchanged")
	}
}

func createMockRequestContext(headers map[string][]string) *policy.RequestContext {
	return &policy.RequestContext{
		SharedContext: &policy.SharedContext{
			RequestID: "test-request-id",
			Metadata:  make(map[string]any),
		},
		Headers: policy.NewHeaders(headers),
		Body:    nil,
		Path:    "/mcp",
		Method:  "POST",
		Scheme:  "http",
	}
}

func createMockResponseContext(requestHeaders, responseHeaders map[string][]string) *policy.ResponseContext {
	return &policy.ResponseContext{
		SharedContext: &policy.SharedContext{
			RequestID: "test-request-id",
			Metadata:  make(map[string]any),
		},
		RequestHeaders:  policy.NewHeaders(requestHeaders),
		ResponseHeaders: policy.NewHeaders(responseHeaders),
		RequestBody:     nil,
		ResponseBody:    nil,
	}
}

// ─── resolver-bearing routes ─────────────────────────────────────────────────
//
// Everything above builds contexts with no resolver, so those tests are the
// gateway-without-a-resolver path and must keep passing untouched. What follows covers the route
// that carries one, where the capability arrives in the mirrored headers or the resolver's
// attributes instead of a body.

const (
	attrPresent  = "mcp.body.present"
	attrMethod   = "mcp.body.method"
	attrCapName  = "mcp.body.capability.name"
	attrUnusable = "mcp.body.unusable"
	attrJSONRPC  = "mcp.body.jsonrpc.id"
)

// toolsDenyAllExcept builds a policy that denies every tool but the ones listed.
// unresolvedHeaderCtx strips the resolver marks, modelling a route that carries no resolver.
func unresolvedHeaderCtx(c *policy.RequestHeaderContext) *policy.RequestHeaderContext {
	c.APIKind, c.ResolvedOperation = "", ""
	delete(c.Metadata, metadataBodyResolved)
	return c
}

// resolvedRequestCtx marks a body-phase context as belonging to a route whose resolver already
// ran, which is what makes the body phase stand aside.
func resolvedRequestCtx(c *policy.RequestContext) *policy.RequestContext {
	c.APIKind, c.ResolvedOperation = policy.APIKindMCP, "mcp"
	c.Metadata = map[string]any{metadataBodyResolved: true}
	return c
}

func toolsDenyAllExcept(t *testing.T, allowed ...string) *McpAclListPolicy {
	t.Helper()
	exceptions := make([]any, 0, len(allowed))
	for _, a := range allowed {
		exceptions = append(exceptions, a)
	}
	params := map[string]any{
		"tools": map[string]any{"mode": "deny", "exceptions": exceptions},
	}
	p, err := GetPolicy(policy.PolicyMetadata{}, params)
	if err != nil {
		t.Fatalf("GetPolicy: %v", err)
	}
	return p.(*McpAclListPolicy)
}

// resolvedHeaderPost builds a header-phase POST /mcp on a route whose resolver ran. The resolver
// publishes mcp.body.present for any body it received, so a fixture that omits it models a state
// the engine cannot produce.
func resolvedHeaderPost(headers map[string][]string, attrs map[string]string) *policy.RequestHeaderContext {
	withBody := map[string]string{attrPresent: "true"}
	for k, v := range attrs {
		withBody[k] = v
	}
	ctx := &policy.RequestHeaderContext{
		SharedContext: &policy.SharedContext{
			RequestID:            "test-request-id",
			Metadata:             map[string]any{metadataBodyResolved: true},
			APIKind:              policy.APIKindMCP,
			ResolvedOperation:    "mcp",
			ResolutionAttributes: policy.NewResolutionAttributes(withBody),
		},
		Headers: policy.NewHeaders(headers),
		Path:    "/mcp",
		Method:  "POST",
	}
	ctx.OperationPath = "/mcp"
	return ctx
}

func TestMode_AsksForBothRequestPhases(t *testing.T) {
	m := toolsDenyAllExcept(t, "toolB").Mode()
	if m.RequestHeaderMode != policy.HeaderModeProcess || m.RequestBodyMode != policy.BodyModeBuffer {
		t.Fatalf("request modes = %v/%v, want Process/Buffer: which phase decides is settled per request", m.RequestHeaderMode, m.RequestBodyMode)
	}
	// Filtering a */list result is body work no header carries, so this never varies.
	if m.ResponseBodyMode != policy.BodyModeBuffer {
		t.Fatalf("ResponseBodyMode = %v, want Buffer", m.ResponseBodyMode)
	}
}

func TestOnRequestHeaders_EnforcesTheAcl(t *testing.T) {
	tests := []struct {
		name    string
		attrs   map[string]string
		blocked bool
	}{
		{"a denied tool is blocked", map[string]string{attrMethod: "tools/call", attrCapName: "toolA"}, true},
		{"an allowed tool passes", map[string]string{attrMethod: "tools/call", attrCapName: "toolB"}, false},
		{"a listing is not an invocation", map[string]string{attrMethod: "tools/list"}, false},
		{"a family with no ACL configured passes", map[string]string{attrMethod: "prompts/get", attrCapName: "p"}, false},
		{"a method outside the three families passes", map[string]string{attrMethod: "ping"}, false},
		{"a body that named no operation passes", nil, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := toolsDenyAllExcept(t, "toolB")
			action := p.OnRequestHeaders(context.Background(), resolvedHeaderPost(nil, tc.attrs), nil)
			if tc.blocked && action == nil {
				t.Fatal("expected the request to be blocked")
			}
			if !tc.blocked && action != nil {
				t.Fatalf("expected the request to pass, got %#v", action)
			}
		})
	}
}

// The live ACL bypass this migration closes, on a resolver route.
//
// The gateway parses into map[string]any, which is case-SENSITIVE; the backend's struct tags are
// not, and take the last match. So a body naming both "method" and "Method" reads as tools/list
// here — not an invocation, no ACL check — and as tools/call there, executing the denied tool.
// The resolver refuses to read such a body at all, and this rejection is what acts on that.
func TestOnRequestHeaders_RejectsAnUnreadableBody(t *testing.T) {
	tests := []struct {
		reason      string
		wantCode    float64
		wantMessage string
	}{
		// the bypass: "method" and "Method" in one body
		{reasonAmbiguous, -32600, "Ambiguous MCP request: body names a member more than once"},
		{reasonSyntaxError, -32700, "Invalid JSON"},
		{reasonNotAnObject, -32600, "Request body is not a single JSON-RPC request object"},
		{reasonInvalidMemberType, -32600, "Request body has a member of the wrong type"},
		{"a reason this build does not know", -32600, "Invalid MCP request"},
	}
	for _, tc := range tests {
		t.Run(tc.reason, func(t *testing.T) {
			p := toolsDenyAllExcept(t, "toolB")
			ctx := resolvedHeaderPost(nil, map[string]string{attrUnusable: tc.reason})
			action := p.OnRequestHeaders(context.Background(), ctx, nil)
			resp, ok := action.(policy.ImmediateResponse)
			if !ok {
				t.Fatalf("expected a rejection, got %#v", action)
			}
			if resp.StatusCode != 400 {
				t.Fatalf("expected 400, got %d", resp.StatusCode)
			}
			var parsed map[string]any
			if err := json.Unmarshal(resp.Body, &parsed); err != nil {
				t.Fatalf("expected a JSON-RPC error body: %v", err)
			}
			errObj := parsed["error"].(map[string]any)
			if errObj["code"] != tc.wantCode {
				t.Fatalf("expected code %v, got %v", tc.wantCode, errObj["code"])
			}
			if errObj["message"] != tc.wantMessage {
				t.Fatalf("expected message %q, got %v", tc.wantMessage, errObj["message"])
			}
		})
	}
}

// The highest-value test in this migration. The response filter is gated entirely on a note the
// request phase leaves in SharedContext.Metadata — a response body does not say what was asked for
// — so if the write does not survive the hook move, */list results silently stop being filtered
// and denied tools leak to the client. Nothing else fails if it is dropped.
func TestOnRequestHeaders_LeavesTheNoteTheResponsePhaseNeeds(t *testing.T) {
	p := toolsDenyAllExcept(t, "toolB")
	ctx := resolvedHeaderPost(nil, map[string]string{attrMethod: "tools/list"})

	if action := p.OnRequestHeaders(context.Background(), ctx, nil); action != nil {
		t.Fatalf("a listing is not an invocation and must pass, got %#v", action)
	}

	// Plural, not the resolver's singular "tool": this value is used to pick the ACL group
	// AND to index the response JSON at {"result":{"tools":[…]}}. A singular value silently
	// disables both, and no request-blocking test would catch it.
	if got := ctx.Metadata[metadataMcpCapabilityType]; got != "tools" {
		t.Fatalf("capability type = %#v, want the plural %q", got, "tools")
	}
	if got := ctx.Metadata[metadataMcpAction]; got != "list" {
		t.Fatalf("action = %#v, want %q", got, "list")
	}
}

// And the note actually drives the filter: the same SharedContext carried into the response phase
// must still strip the denied tool out of the list.
func TestResponseFilteringSurvivesTheHookMove(t *testing.T) {
	p := toolsDenyAllExcept(t, "toolB")
	reqCtx := resolvedHeaderPost(nil, map[string]string{attrMethod: "tools/list"})
	p.OnRequestHeaders(context.Background(), reqCtx, nil)

	body, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": 1,
		"result": map[string]any{"tools": []any{
			map[string]any{"name": "toolA"},
			map[string]any{"name": "toolB"},
		}},
	})
	respCtx := &policy.ResponseContext{
		SharedContext:   reqCtx.SharedContext, // the same map the request phase wrote into
		RequestHeaders:  policy.NewHeaders(nil),
		ResponseHeaders: policy.NewHeaders(nil),
		ResponseBody:    &policy.Body{Content: body, Present: true},
		RequestMethod:   "POST",
	}
	respCtx.OperationPath = "/mcp"

	action := p.OnResponseBody(context.Background(), respCtx, nil)
	mods, ok := action.(policy.DownstreamResponseModifications)
	if !ok {
		t.Fatalf("expected the list to be filtered, got %#v", action)
	}
	var parsed map[string]any
	if err := json.Unmarshal(mods.Body, &parsed); err != nil {
		t.Fatalf("filtered body is not JSON: %v", err)
	}
	tools := parsed["result"].(map[string]any)["tools"].([]any)
	if len(tools) != 1 || tools[0].(map[string]any)["name"] != "toolB" {
		t.Fatalf("expected only toolB to survive, got %v", tools)
	}
}

// Each hook belongs to exactly one kind of route. The executor already gates on Mode(), so these
// guards are unreachable in production — they stop a direct call in a test deciding twice.
func TestHooksDeferToTheOtherPhase(t *testing.T) {
	denied, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "tools/call",
		"params": map[string]any{"name": "toolA"},
	})
	bodyCtx := func() *policy.RequestContext {
		c := createMockRequestContext(nil)
		c.OperationPath = "/mcp"
		c.Body = &policy.Body{Content: denied, Present: true}
		return c
	}

	t.Run("body phase defers on a resolver route", func(t *testing.T) {
		action := toolsDenyAllExcept(t, "toolB").OnRequestBody(context.Background(), resolvedRequestCtx(bodyCtx()), nil)
		if _, blocked := action.(policy.ImmediateResponse); blocked {
			t.Fatal("expected the body phase to defer")
		}
		// Control: the same body on a resolver-less route IS blocked.
		control := toolsDenyAllExcept(t, "toolB").OnRequestBody(context.Background(), bodyCtx(), nil)
		if _, blocked := control.(policy.ImmediateResponse); !blocked {
			t.Fatal("control: a resolver-less route must block the denied tool")
		}
	})

	t.Run("header phase defers without a resolver", func(t *testing.T) {
		p := toolsDenyAllExcept(t, "toolB")
		attrs := map[string]string{attrMethod: "tools/call", attrCapName: "toolA"}
		if action := p.OnRequestHeaders(context.Background(), unresolvedHeaderCtx(resolvedHeaderPost(nil, attrs)), nil); action != nil {
			t.Fatalf("expected the header phase to defer, got %#v", action)
		}
		// Control: the same input on a resolver route IS blocked.
		if action := toolsDenyAllExcept(t, "toolB").OnRequestHeaders(context.Background(), resolvedHeaderPost(nil, attrs), nil); action == nil {
			t.Fatal("control: a resolver route must block the denied tool")
		}
	})
}

// A resource is identified by its uri, a tool and a prompt by name — the same family-keyed choice
// the resolver makes when it publishes capability.name, so both paths agree.
func TestOnRequestHeaders_ResourcesAreKeyedOnTheUri(t *testing.T) {
	p, err := GetPolicy(policy.PolicyMetadata{}, map[string]any{
		"resources": map[string]any{"mode": "deny", "exceptions": []any{"file:///public"}},
	})
	if err != nil {
		t.Fatalf("GetPolicy: %v", err)
	}
	acl := p.(*McpAclListPolicy)

	allowed := resolvedHeaderPost(nil, map[string]string{attrMethod: "resources/read", attrCapName: "file:///public"})
	if action := acl.OnRequestHeaders(context.Background(), allowed, nil); action != nil {
		t.Fatalf("expected the listed uri to pass, got %#v", action)
	}
	denied := resolvedHeaderPost(nil, map[string]string{attrMethod: "resources/read", attrCapName: "file:///secret"})
	if action := acl.OnRequestHeaders(context.Background(), denied, nil); action == nil {
		t.Fatal("expected an unlisted uri to be blocked")
	}
}

// Every context embeds *SharedContext, so a nil one panics on any Metadata access.
func TestNilSharedContextDoesNotPanic(t *testing.T) {
	p := toolsDenyAllExcept(t, "toolB")

	headerCtx := resolvedHeaderPost(nil, map[string]string{attrMethod: "tools/call", attrCapName: "toolA"})
	headerCtx.SharedContext = nil
	if action := p.OnRequestHeaders(context.Background(), headerCtx, nil); action != nil {
		t.Fatalf("expected a request with no shared context to pass, got %#v", action)
	}

	respCtx := createMockResponseContext(nil, nil)
	respCtx.SharedContext = nil
	if action := p.OnResponseBody(context.Background(), respCtx, nil); action != nil {
		t.Fatalf("expected no response modifications, got %#v", action)
	}
}

// Both request paths render an unreadable body through handleUnusableBody, so the same bytes get
// the same error whether the resolver read them or this policy parsed them itself. The
// resolver-less path can only ever reach reasonSyntaxError — it has no ambiguity check — which is
// the gap recorded in the docs.
func TestUnreadableBodyRendersIdenticallyOnBothPaths(t *testing.T) {
	bodyCtx := createMockRequestContext(nil)
	bodyCtx.OperationPath = "/mcp"
	bodyCtx.Body = &policy.Body{Content: []byte(`{"method":`), Present: true}

	viaBody := toolsDenyAllExcept(t, "toolB").OnRequestBody(context.Background(), bodyCtx, nil)
	bodyResp, ok := viaBody.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("expected the body parse to reject, got %#v", viaBody)
	}

	hdrCtx := resolvedHeaderPost(nil, map[string]string{attrUnusable: reasonSyntaxError})
	viaResolver := toolsDenyAllExcept(t, "toolB").OnRequestHeaders(context.Background(), hdrCtx, nil)
	resolverResp, ok := viaResolver.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("expected the resolver path to reject, got %#v", viaResolver)
	}

	if bodyResp.StatusCode != resolverResp.StatusCode || string(bodyResp.Body) != string(resolverResp.Body) {
		t.Fatalf("the two paths disagree:\n  body     %d %s\n  resolver %d %s",
			bodyResp.StatusCode, bodyResp.Body, resolverResp.StatusCode, resolverResp.Body)
	}
}

// Released ordering: a params that is not an object at all is reported only when this policy
// would actually govern the operation. Checking it any earlier would surface -32602 for a
// capability family the operator configured no ACL for, or for a listing this policy only acts on
// in the response phase — turning requests that flow today into 400s.
//
// Only the body path can reach this; the header path is handed a plain string by the resolver.
func TestMalformedParamsReportedOnlyWhenTheOperationIsGoverned(t *testing.T) {
	tests := []struct {
		name     string
		method   string
		rejected bool
	}{
		{"an invocation of a configured family is reported", "tools/call", true},
		{"a family with no ACL configured passes", "prompts/get", false},
		{"a family with no ACL configured passes (resources)", "resources/read", false},
		{"a listing is not an invocation, so it passes", "tools/list", false},
		{"a method outside the three families passes", "ping", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// params is a string, not an object — malformed for every case here.
			body, _ := json.Marshal(map[string]any{
				"jsonrpc": "2.0", "id": 1, "method": tc.method, "params": "not-an-object",
			})
			ctx := createMockRequestContext(nil)
			ctx.OperationPath = "/mcp"
			ctx.Body = &policy.Body{Content: body, Present: true}

			action := toolsDenyAllExcept(t, "toolB").OnRequestBody(context.Background(), ctx, nil)
			resp, rejected := action.(policy.ImmediateResponse)
			if rejected != tc.rejected {
				t.Fatalf("rejected = %v, want %v (got %#v)", rejected, tc.rejected, action)
			}
			if !tc.rejected {
				return
			}
			var parsed map[string]any
			if err := json.Unmarshal(resp.Body, &parsed); err != nil {
				t.Fatalf("expected a JSON-RPC error body: %v", err)
			}
			errObj := parsed["error"].(map[string]any)
			if errObj["code"] != float64(-32602) || errObj["message"] != "Invalid MCP request params" {
				t.Fatalf("expected the released -32602 params error, got %v", errObj)
			}
		})
	}
}

// A modern request is governed on Mcp-Method and Mcp-Name, so the body verdict says nothing about
// it and the ACL applies as usual. Rejecting that body is mcp-spec-validation's job.
func TestOnRequestHeaders_ModernUnusableBodyStillGovernsOnTheHeaders(t *testing.T) {
	modern := func(name string) map[string][]string {
		return map[string][]string{
			headerProtocolVersion: {"2026-07-28"},
			headerMcpMethod:       {"tools/call"},
			headerMcpName:         {name},
		}
	}
	for _, reason := range []string{reasonSyntaxError, reasonInvalidMemberType, reasonNotAnObject, reasonAmbiguous} {
		t.Run(reason+", denied tool", func(t *testing.T) {
			p := toolsDenyAllExcept(t, "toolB")
			ctx := resolvedHeaderPost(modern("toolA"), map[string]string{attrUnusable: reason})
			resp, ok := p.OnRequestHeaders(context.Background(), ctx, nil).(policy.ImmediateResponse)
			if !ok || resp.StatusCode != 400 {
				t.Fatalf("expected the ACL to block the tool named in the headers, got %#v", resp)
			}
		})

		t.Run(reason+", allowed tool", func(t *testing.T) {
			p := toolsDenyAllExcept(t, "toolB")
			ctx := resolvedHeaderPost(modern("toolB"), map[string]string{attrUnusable: reason})
			if action := p.OnRequestHeaders(context.Background(), ctx, nil); action != nil {
				t.Fatalf("expected the allowed tool to pass, got %#v", action)
			}
		})
	}
}

// 2026-07-28 requires Mcp-Method, so the legacy pass-through does not apply: a modern request
// without it is refused, even when the body names a tool the ACL would deny.
func TestOnRequestHeaders_ModernWithoutMcpMethodIsRejected(t *testing.T) {
	p := toolsDenyAllExcept(t, "toolB")
	ctx := resolvedHeaderPost(map[string][]string{headerProtocolVersion: {"2026-07-28"}},
		map[string]string{attrBodyMethod: "tools/call", attrBodyCapabilityName: "toolA"})
	resp, ok := p.OnRequestHeaders(context.Background(), ctx, nil).(policy.ImmediateResponse)
	if !ok || resp.StatusCode != 400 {
		t.Fatalf("expected a 400 rejection, got %#v", resp)
	}
	var parsed map[string]any
	if err := json.Unmarshal(resp.Body, &parsed); err != nil {
		t.Fatalf("expected a JSON-RPC error body: %v", err)
	}
	if code := parsed["error"].(map[string]any)["code"]; code != float64(jsonRpcErrCodeHeaderMismatch) {
		t.Fatalf("error code = %v, want %d", code, jsonRpcErrCodeHeaderMismatch)
	}
}

// Likewise a missing or undecodable Mcp-Name; a legacy body naming no tool is left to the server.
func TestOnRequestHeaders_ModernWithoutRequiredMcpNameIsRejected(t *testing.T) {
	for name, headerName := range map[string][]string{
		"withheld":        nil,
		"does not decode": {"=?base64?!!!not-base64!!!?="},
	} {
		t.Run(name, func(t *testing.T) {
			headers := map[string][]string{headerProtocolVersion: {"2026-07-28"}, headerMcpMethod: {"tools/call"}}
			if headerName != nil {
				headers[headerMcpName] = headerName
			}
			p := toolsDenyAllExcept(t, "toolB")
			ctx := resolvedHeaderPost(headers, map[string]string{attrBodyMethod: "tools/call", attrBodyCapabilityName: "toolB"})
			resp, ok := p.OnRequestHeaders(context.Background(), ctx, nil).(policy.ImmediateResponse)
			if !ok || resp.StatusCode != 400 {
				t.Fatalf("expected a 400 rejection, got %#v", resp)
			}
			var parsed map[string]any
			if err := json.Unmarshal(resp.Body, &parsed); err != nil {
				t.Fatalf("expected a JSON-RPC error body: %v", err)
			}
			if code := parsed["error"].(map[string]any)["code"]; code != float64(jsonRpcErrCodeHeaderMismatch) {
				t.Fatalf("error code = %v, want %d", code, jsonRpcErrCodeHeaderMismatch)
			}
		})
	}

	t.Run("legacy body naming no tool is unchanged", func(t *testing.T) {
		p := toolsDenyAllExcept(t, "toolB")
		ctx := resolvedHeaderPost(nil, map[string]string{attrBodyMethod: "tools/call"})
		if resp, ok := p.OnRequestHeaders(context.Background(), ctx, nil).(policy.ImmediateResponse); ok && resp.Body != nil &&
			strings.Contains(string(resp.Body), "Mcp-Name") {
			t.Fatalf("a legacy request must not be judged on Mcp-Name, got %s", resp.Body)
		}
	})
}

// TestRejectionsDeclareFault pins the fault declaration and the code chosen per rejection.
func TestRejectionsDeclareFault(t *testing.T) {
	params := map[string]any{
		"tools": map[string]any{
			"mode":       "allow",
			"exceptions": []any{"toolA"},
		},
	}
	p, err := GetPolicy(policy.PolicyMetadata{}, params)
	if err != nil {
		t.Fatalf("Failed to create policy: %v", err)
	}

	run := func(t *testing.T, body []byte) policy.ImmediateResponse {
		t.Helper()
		ctx := createMockRequestContext(map[string][]string{})
		ctx.Method = "POST"
		ctx.OperationPath = "/mcp"
		ctx.Body = &policy.Body{Content: body, Present: true}

		action := p.(*McpAclListPolicy).OnRequestBody(context.Background(), ctx, params)
		resp, ok := action.(policy.ImmediateResponse)
		if !ok {
			t.Fatalf("Expected ImmediateResponse, got %T", action)
		}
		if !resp.IsFault {
			t.Fatalf("expected IsFault=true on a rejection")
		}
		if resp.Fault == nil {
			t.Fatalf("expected Error to be populated on a rejection")
		}
		if resp.Fault.Direction != policy.DirectionRequest {
			t.Fatalf("expected Error.Direction=%q, got %q", policy.DirectionRequest, resp.Fault.Direction)
		}
		assertFallbackBodyAgrees(t, resp)
		return resp
	}

	t.Run("capability denied by the ACL", func(t *testing.T) {
		body, _ := json.Marshal(map[string]any{
			"jsonrpc": "2.0",
			"id":      "1",
			"method":  "tools/call",
			"params":  map[string]any{"name": "toolA"},
		})
		resp := run(t, body)
		if resp.Fault.Code != policy.FaultCodeAuthForbidden {
			t.Fatalf("expected Error.Code=%q, got %q", policy.FaultCodeAuthForbidden, resp.Fault.Code)
		}
		if resp.Fault.Type != policy.FaultTypeAuthorization {
			t.Fatalf("expected Error.Type=%q, got %q", policy.FaultTypeAuthorization, resp.Fault.Type)
		}
	})

	t.Run("body is not JSON", func(t *testing.T) {
		resp := run(t, []byte("{not json"))
		if resp.Fault.Code != policy.FaultCodeInvalidRequestBody {
			t.Fatalf("expected Error.Code=%q, got %q", policy.FaultCodeInvalidRequestBody, resp.Fault.Code)
		}
		if resp.Fault.Type != policy.FaultTypeValidation {
			t.Fatalf("expected Error.Type=%q, got %q", policy.FaultTypeValidation, resp.Fault.Type)
		}
	})
}

// TestListFilteringIsNotAFault covers the response path: this policy rewrites a successful
// tools/list response to remove disallowed entries. That is a transformation of a healthy
// response, not a failure — marking it a fault would notify on every successful listing.
func TestListFilteringIsNotAFault(t *testing.T) {
	params := map[string]any{
		"tools": map[string]any{
			"mode":       "allow",
			"exceptions": []any{"toolA"},
		},
	}
	p, err := GetPolicy(policy.PolicyMetadata{}, params)
	if err != nil {
		t.Fatalf("Failed to create policy: %v", err)
	}

	body, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      "1",
		"result": map[string]any{
			"tools": []any{
				map[string]any{"name": "toolA"},
				map[string]any{"name": "toolB"},
			},
		},
	})

	ctx := createMockResponseContext(nil, nil)
	ctx.RequestMethod = "POST"
	ctx.OperationPath = "/mcp"
	ctx.ResponseBody = &policy.Body{Content: body, Present: true}
	ctx.Metadata[metadataMcpCapabilityType] = "tools"
	ctx.Metadata[metadataMcpAction] = "list"

	action := p.(*McpAclListPolicy).OnResponseBody(context.Background(), ctx, params)
	mods, ok := action.(policy.DownstreamResponseModifications)
	if !ok {
		t.Fatalf("expected DownstreamResponseModifications, got %T", action)
	}
	if mods.IsFault {
		t.Fatalf("filtering a successful list response must not be a fault")
	}
	if mods.Fault != nil {
		t.Fatalf("filtering a successful list response must not describe an error")
	}
}

// assertFallbackBodyAgrees checks the legacy JSON-RPC body that travels alongside the
// description.
//
// Both are always sent. The description is what a gateway with an error renderer uses; the
// body is what a gateway without one sends, so a policy upgraded on its own still answers a
// rejection the way it always has. Asserting they AGREE — rather than restating the literals
// a second time — is what catches the failure that matters: one of the two drifting, so the
// answer a caller gets depends on which gateway happens to be running.
func assertFallbackBodyAgrees(t *testing.T, resp policy.ImmediateResponse) {
	t.Helper()
	if len(resp.Body) == 0 {
		t.Fatal("Expected a fallback body alongside the description, got none")
	}

	raw := resp.Body
	wantType := "application/json"
	if after, found := strings.CutPrefix(string(raw), "data: "); found {
		// SSE framing: the envelope is the event's data member.
		raw = []byte(strings.TrimSuffix(after, "\n\n"))
		wantType = "text/event-stream"
	}
	if got := resp.Headers["Content-Type"] + resp.Headers["content-type"]; got != wantType {
		t.Fatalf("Expected Content-Type %q for the fallback body, got %q", wantType, got)
	}

	var envelope struct {
		JSONRPC string `json:"jsonrpc"`
		ID      any    `json:"id"`
		Error   struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		t.Fatalf("Fallback body is not a JSON-RPC envelope: %v (%q)", err, raw)
	}
	if envelope.JSONRPC != "2.0" {
		t.Fatalf("Expected jsonrpc 2.0 in the fallback body, got %q", envelope.JSONRPC)
	}
	if resp.Fault == nil || resp.Fault.JSONRPC == nil || resp.Fault.JSONRPC.Code == nil {
		t.Fatalf("Expected a described JSON-RPC error to compare against, got %+v", resp.Fault)
	}
	if envelope.Error.Code != *resp.Fault.JSONRPC.Code {
		t.Fatalf("Fallback body code %d disagrees with the described code %d",
			envelope.Error.Code, *resp.Fault.JSONRPC.Code)
	}
	if envelope.Error.Message != resp.Fault.Message {
		t.Fatalf("Fallback body message %q disagrees with the described message %q",
			envelope.Error.Message, resp.Fault.Message)
	}
	if !sameJSONRPCID(envelope.ID, resp.Fault.JSONRPC.ID) {
		t.Fatalf("Fallback body id %v disagrees with the described id %v",
			envelope.ID, resp.Fault.JSONRPC.ID)
	}
}

// sameJSONRPCID compares two decoded JSON-RPC ids. A number survives json.Unmarshal as
// float64 but reaches the description as whatever the policy parsed, so compare through the
// JSON encoding rather than with ==.
func sameJSONRPCID(fromBody, described any) bool {
	a, errA := json.Marshal(fromBody)
	b, errB := json.Marshal(described)
	return errA == nil && errB == nil && string(a) == string(b)
}
