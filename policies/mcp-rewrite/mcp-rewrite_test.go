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

package mcprewrite

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

func TestGetPolicy_RejectsEmptyOrWhitespaceTarget(t *testing.T) {
	tests := []struct {
		name     string
		params   map[string]any
		errorStr string
	}{
		{
			name: "tools target empty",
			params: map[string]any{
				"tools": []any{
					map[string]any{
						"name":        "toolA",
						"description": "desc",
						"inputSchema": `{"type":"object"}`,
						"target":      "",
					},
				},
			},
			errorStr: "invalid tools configuration: tools[0].target must be a non-empty string",
		},
		{
			name: "resources target whitespace",
			params: map[string]any{
				"resources": []any{
					map[string]any{
						"name":   "Resource A",
						"uri":    "resource://a",
						"target": "   ",
					},
				},
			},
			errorStr: "invalid resources configuration: resources[0].target must be a non-empty string",
		},
		{
			name: "prompts target whitespace",
			params: map[string]any{
				"prompts": []any{
					map[string]any{
						"name":   "promptA",
						"target": "\t",
					},
				},
			},
			errorStr: "invalid prompts configuration: prompts[0].target must be a non-empty string",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := GetPolicy(policy.PolicyMetadata{}, tt.params)
			if err == nil {
				t.Fatalf("Expected error containing %q, got nil", tt.errorStr)
			}
			if !strings.Contains(err.Error(), tt.errorStr) {
				t.Fatalf("Expected error containing %q, got %q", tt.errorStr, err.Error())
			}
		})
	}
}

func TestOnRequest_RewritesToolCallTarget(t *testing.T) {
	params := map[string]any{
		"tools": []any{
			map[string]any{
				"name":        "toolA",
				"description": "desc",
				"inputSchema": `{"type":"object"}`,
				"target":      "backendTool",
			},
		},
	}

	p := mustPolicy(t, params)
	body := mustJSON(t, map[string]any{
		"jsonrpc": "2.0",
		"id":      "1",
		"method":  "tools/call",
		"params": map[string]any{
			"name": "toolA",
		},
	})

	ctx := createMockRequestContext(nil)
	ctx.Method = "POST"
	ctx.Path = "/mcp"
	ctx.Body = &policy.Body{Content: body, Present: true}

	action := p.(*McpRewritePolicy).OnRequestBody(context.Background(), ctx, params)
	mods, ok := action.(policy.UpstreamRequestModifications)
	if !ok {
		t.Fatalf("Expected UpstreamRequestModifications, got %T", action)
	}

	updated := mustJSONMap(t, mods.Body)
	updatedParams := updated["params"].(map[string]any)
	if updatedParams["name"] != "backendTool" {
		t.Fatalf("Expected rewritten name 'backendTool', got %v", updatedParams["name"])
	}
}

func TestOnRequest_UnlistedCapabilityRejected(t *testing.T) {
	tests := []struct {
		name          string
		params        map[string]any
		method        string
		requestParams map[string]any
		expectedError string
	}{
		{
			name: "tools",
			params: map[string]any{
				"tools": []any{
					map[string]any{
						"name":        "toolA",
						"description": "desc",
						"inputSchema": `{"type":"object"}`,
					},
				},
			},
			method:        "tools/call",
			requestParams: map[string]any{"name": "toolB"},
			expectedError: "MCP tools 'toolB' is not allowed",
		},
		{
			name: "resources",
			params: map[string]any{
				"resources": []any{
					map[string]any{
						"name": "Resource A",
						"uri":  "resource://a",
					},
				},
			},
			method:        "resources/read",
			requestParams: map[string]any{"uri": "resource://b"},
			expectedError: "MCP resources 'resource://b' is not allowed",
		},
		{
			name: "prompts",
			params: map[string]any{
				"prompts": []any{
					map[string]any{
						"name": "promptA",
					},
				},
			},
			method:        "prompts/get",
			requestParams: map[string]any{"name": "promptB"},
			expectedError: "MCP prompts 'promptB' is not allowed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := mustPolicy(t, tt.params)
			body := mustJSON(t, map[string]any{
				"jsonrpc": "2.0",
				"id":      "req-1",
				"method":  tt.method,
				"params":  tt.requestParams,
			})

			ctx := createMockRequestContext(nil)
			ctx.Method = "POST"
			ctx.Path = "/mcp"
			ctx.Body = &policy.Body{Content: body, Present: true}

			action := p.(*McpRewritePolicy).OnRequestBody(context.Background(), ctx, tt.params)
			resp := mustImmediateResponse(t, action)
			if resp.StatusCode != 403 {
				t.Fatalf("Expected status code 403, got %d", resp.StatusCode)
			}
			assertJSONRPCError(t, resp.Body, -32602, tt.expectedError)
		})
	}
}

func TestOnRequest_EmptyListDenyAll_ByCapability(t *testing.T) {
	tests := []struct {
		name          string
		method        string
		paramKey      string
		paramValue    string
		params        map[string]any
		expectedError string
	}{
		{
			name:          "tools",
			method:        "tools/call",
			paramKey:      "name",
			paramValue:    "toolA",
			params:        map[string]any{"tools": []any{}},
			expectedError: "MCP tools 'toolA' is not allowed",
		},
		{
			name:          "resources",
			method:        "resources/read",
			paramKey:      "uri",
			paramValue:    "resource://a",
			params:        map[string]any{"resources": []any{}},
			expectedError: "MCP resources 'resource://a' is not allowed",
		},
		{
			name:          "prompts",
			method:        "prompts/get",
			paramKey:      "name",
			paramValue:    "promptA",
			params:        map[string]any{"prompts": []any{}},
			expectedError: "MCP prompts 'promptA' is not allowed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := mustPolicy(t, tt.params)
			body := mustJSON(t, map[string]any{
				"jsonrpc": "2.0",
				"id":      "deny-all",
				"method":  tt.method,
				"params": map[string]any{
					tt.paramKey: tt.paramValue,
				},
			})

			ctx := createMockRequestContext(nil)
			ctx.Method = "POST"
			ctx.Path = "/mcp"
			ctx.Body = &policy.Body{Content: body, Present: true}

			action := p.(*McpRewritePolicy).OnRequestBody(context.Background(), ctx, tt.params)
			resp := mustImmediateResponse(t, action)
			if resp.StatusCode != 403 {
				t.Fatalf("Expected status code 403, got %d", resp.StatusCode)
			}
			assertJSONRPCError(t, resp.Body, -32602, tt.expectedError)
		})
	}
}

func TestOnRequest_UnlistedSSERejected_WithSessionHeader(t *testing.T) {
	params := map[string]any{
		"tools": []any{
			map[string]any{
				"name":        "toolA",
				"description": "desc",
				"inputSchema": `{"type":"object"}`,
			},
		},
	}

	p := mustPolicy(t, params)
	payload := mustJSON(t, map[string]any{
		"jsonrpc": "2.0",
		"id":      "sse-1",
		"method":  "tools/call",
		"params": map[string]any{
			"name": "toolB",
		},
	})
	streamBody := buildEventStream([]sseEvent{
		{
			fields: []string{"event: message"},
			data:   string(payload),
		},
	})

	ctx := createMockRequestContext(map[string][]string{
		"content-type":   {"text/event-stream"},
		"mcp-session-id": {"session-123"},
	})
	ctx.Method = "POST"
	ctx.Path = "/mcp"
	ctx.Body = &policy.Body{Content: streamBody, Present: true}

	action := p.(*McpRewritePolicy).OnRequestBody(context.Background(), ctx, params)
	resp := mustImmediateResponse(t, action)
	if resp.StatusCode != 403 {
		t.Fatalf("Expected status code 403, got %d", resp.StatusCode)
	}
	if resp.Headers["Content-Type"] != "text/event-stream" {
		t.Fatalf("Expected Content-Type text/event-stream, got %q", resp.Headers["Content-Type"])
	}
	if resp.Headers[mcpSessionHeader] != "session-123" {
		t.Fatalf("Expected mcp-session-id to be propagated")
	}

	events := parseEventStream(resp.Body)
	if len(events) != 1 {
		t.Fatalf("Expected 1 SSE event, got %d", len(events))
	}
	assertJSONRPCError(t, []byte(events[0].data), -32602, "MCP tools 'toolB' is not allowed")
}

func TestOnRequest_InvalidParamsRejected(t *testing.T) {
	params := map[string]any{
		"tools": []any{
			map[string]any{
				"name":        "toolA",
				"description": "desc",
				"inputSchema": `{"type":"object"}`,
			},
		},
	}

	p := mustPolicy(t, params)
	body := mustJSON(t, map[string]any{
		"jsonrpc": "2.0",
		"id":      "bad-params",
		"method":  "tools/call",
		"params":  []any{"toolA"},
	})

	ctx := createMockRequestContext(nil)
	ctx.Method = "POST"
	ctx.Path = "/mcp"
	ctx.Body = &policy.Body{Content: body, Present: true}

	action := p.(*McpRewritePolicy).OnRequestBody(context.Background(), ctx, params)
	resp := mustImmediateResponse(t, action)
	if resp.StatusCode != 400 {
		t.Fatalf("Expected status code 400, got %d", resp.StatusCode)
	}
	assertJSONRPCError(t, resp.Body, -32602, "Invalid MCP request params")
}

func TestOnRequest_MissingCapabilityNameRejected(t *testing.T) {
	params := map[string]any{
		"tools": []any{
			map[string]any{
				"name":        "toolA",
				"description": "desc",
				"inputSchema": `{"type":"object"}`,
			},
		},
	}

	p := mustPolicy(t, params)
	body := mustJSON(t, map[string]any{
		"jsonrpc": "2.0",
		"id":      "missing-name",
		"method":  "tools/call",
		"params": map[string]any{
			"foo": "bar",
		},
	})

	ctx := createMockRequestContext(nil)
	ctx.Method = "POST"
	ctx.Path = "/mcp"
	ctx.Body = &policy.Body{Content: body, Present: true}

	action := p.(*McpRewritePolicy).OnRequestBody(context.Background(), ctx, params)
	resp := mustImmediateResponse(t, action)
	if resp.StatusCode != 400 {
		t.Fatalf("Expected status code 400, got %d", resp.StatusCode)
	}
	assertJSONRPCError(t, resp.Body, -32602, "Missing MCP tools name")
}

func TestOnRequest_ToolCallWithoutTarget_NoRewrite(t *testing.T) {
	params := map[string]any{
		"tools": []any{
			map[string]any{
				"name":        "toolA",
				"description": "desc",
				"inputSchema": `{"type":"object"}`,
			},
		},
	}

	p := mustPolicy(t, params)
	body := mustJSON(t, map[string]any{
		"jsonrpc": "2.0",
		"id":      "1",
		"method":  "tools/call",
		"params": map[string]any{
			"name": "toolA",
		},
	})

	ctx := createMockRequestContext(nil)
	ctx.Method = "POST"
	ctx.Path = "/mcp"
	ctx.Body = &policy.Body{Content: body, Present: true}

	action := p.(*McpRewritePolicy).OnRequestBody(context.Background(), ctx, params)
	if _, ok := action.(policy.UpstreamRequestModifications); !ok {
		t.Fatalf("Expected UpstreamRequestModifications, got %T", action)
	}
	if mod := action.(policy.UpstreamRequestModifications); mod.Body != nil {
		t.Fatalf("Expected no body rewrite, got body modification")
	}
}

func TestOnResponse_RewritesAndFiltersConfiguredListItems(t *testing.T) {
	params := map[string]any{
		"tools": []any{
			map[string]any{
				"name":        "toolA",
				"description": "desc",
				"inputSchema": `{"type":"object"}`,
				"target":      "backendTool",
			},
		},
	}

	p := mustPolicy(t, params)
	body := mustJSON(t, map[string]any{
		"jsonrpc": "2.0",
		"id":      "resp-1",
		"result": map[string]any{
			"tools": []any{
				map[string]any{"name": "backendTool", "description": "old"},
				map[string]any{"name": "other"},
				"invalid",
			},
		},
	})

	ctx := createMockResponseContext(nil, nil)
	ctx.RequestMethod = "POST"
	ctx.RequestPath = "/mcp"
	ctx.ResponseBody = &policy.Body{Content: body, Present: true}
	ctx.Metadata[metadataMcpCapabilityType] = "tools"
	ctx.Metadata[metadataMcpAction] = "list"

	action := p.(*McpRewritePolicy).OnResponseBody(context.Background(), ctx, params)
	mods, ok := action.(policy.DownstreamResponseModifications)
	if !ok {
		t.Fatalf("Expected UpstreamResponseModifications, got %T", action)
	}

	updated := mustJSONMap(t, mods.Body)
	result := updated["result"].(map[string]any)
	tools := result["tools"].([]any)
	if len(tools) != 1 {
		t.Fatalf("Expected 1 tool after filtering, got %d", len(tools))
	}
	first := tools[0].(map[string]any)
	if first["name"] != "toolA" {
		t.Fatalf("Expected rewritten name 'toolA', got %v", first["name"])
	}
	inputSchema, ok := first["inputSchema"].(map[string]any)
	if !ok {
		t.Fatalf("Expected inputSchema object, got %T", first["inputSchema"])
	}
	if inputSchema["type"] != "object" {
		t.Fatalf("Expected inputSchema.type 'object', got %v", inputSchema["type"])
	}
}

func TestOnResponse_EmptyListDenyAll_ByCapability(t *testing.T) {
	tests := []struct {
		name           string
		capabilityType string
		listKey        string
		itemKey        string
		itemValue      string
		params         map[string]any
	}{
		{
			name:           "tools",
			capabilityType: "tools",
			listKey:        "tools",
			itemKey:        "name",
			itemValue:      "backendTool",
			params:         map[string]any{"tools": []any{}},
		},
		{
			name:           "resources",
			capabilityType: "resources",
			listKey:        "resources",
			itemKey:        "uri",
			itemValue:      "resource://backend",
			params:         map[string]any{"resources": []any{}},
		},
		{
			name:           "prompts",
			capabilityType: "prompts",
			listKey:        "prompts",
			itemKey:        "name",
			itemValue:      "promptBackend",
			params:         map[string]any{"prompts": []any{}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := mustPolicy(t, tt.params)
			body := mustJSON(t, map[string]any{
				"jsonrpc": "2.0",
				"id":      "deny-all-list",
				"result": map[string]any{
					tt.listKey: []any{
						map[string]any{tt.itemKey: tt.itemValue},
					},
				},
			})

			ctx := createMockResponseContext(nil, nil)
			ctx.RequestMethod = "POST"
			ctx.RequestPath = "/mcp"
			ctx.ResponseBody = &policy.Body{Content: body, Present: true}
			ctx.Metadata[metadataMcpCapabilityType] = tt.capabilityType
			ctx.Metadata[metadataMcpAction] = "list"

			action := p.(*McpRewritePolicy).OnResponseBody(context.Background(), ctx, tt.params)
			mods, ok := action.(policy.DownstreamResponseModifications)
			if !ok {
				t.Fatalf("Expected UpstreamResponseModifications, got %T", action)
			}

			updated := mustJSONMap(t, mods.Body)
			result := updated["result"].(map[string]any)
			items := result[tt.listKey].([]any)
			if len(items) != 0 {
				t.Fatalf("Expected empty list after deny-all filtering, got %d", len(items))
			}
		})
	}
}

func TestOnResponse_SSEListFiltering(t *testing.T) {
	params := map[string]any{
		"prompts": []any{
			map[string]any{
				"name":   "promptA",
				"target": "backendPrompt",
			},
		},
	}

	p := mustPolicy(t, params)
	eventPayload := mustJSON(t, map[string]any{
		"jsonrpc": "2.0",
		"id":      "sse-list-1",
		"result": map[string]any{
			"prompts": []any{
				map[string]any{"name": "backendPrompt"},
				map[string]any{"name": "other"},
			},
		},
	})
	body := buildEventStream([]sseEvent{
		{
			fields: []string{"event: message"},
			data:   string(eventPayload),
		},
	})

	ctx := createMockResponseContext(nil, map[string][]string{
		"content-type": {"text/event-stream"},
	})
	ctx.RequestMethod = "POST"
	ctx.RequestPath = "/mcp"
	ctx.ResponseBody = &policy.Body{Content: body, Present: true}
	ctx.Metadata[metadataMcpCapabilityType] = "prompts"
	ctx.Metadata[metadataMcpAction] = "list"

	action := p.(*McpRewritePolicy).OnResponseBody(context.Background(), ctx, params)
	mods, ok := action.(policy.DownstreamResponseModifications)
	if !ok {
		t.Fatalf("Expected UpstreamResponseModifications, got %T", action)
	}

	events := parseEventStream(mods.Body)
	if len(events) != 1 {
		t.Fatalf("Expected 1 event, got %d", len(events))
	}
	updated := mustJSONMap(t, []byte(events[0].data))
	result := updated["result"].(map[string]any)
	prompts := result["prompts"].([]any)
	if len(prompts) != 1 {
		t.Fatalf("Expected 1 prompt after filtering, got %d", len(prompts))
	}
	first := prompts[0].(map[string]any)
	if first["name"] != "promptA" {
		t.Fatalf("Expected rewritten prompt name 'promptA', got %v", first["name"])
	}
}

func mustPolicy(t *testing.T, params map[string]any) policy.Policy {
	t.Helper()
	p, err := GetPolicy(policy.PolicyMetadata{}, params)
	if err != nil {
		t.Fatalf("Failed to create policy: %v", err)
	}
	return p
}

func mustJSON(t *testing.T, payload map[string]any) []byte {
	t.Helper()
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("Failed to marshal JSON payload: %v", err)
	}
	return body
}

func mustJSONMap(t *testing.T, body []byte) map[string]any {
	t.Helper()
	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatalf("Failed to unmarshal JSON payload: %v", err)
	}
	return payload
}

func mustImmediateResponse(t *testing.T, action policy.RequestAction) policy.ImmediateResponse {
	t.Helper()
	resp, ok := action.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("Expected ImmediateResponse, got %T", action)
	}
	return resp
}

func assertJSONRPCError(t *testing.T, body []byte, code float64, message string) {
	t.Helper()
	payload := mustJSONMap(t, body)
	errorObj, ok := payload["error"].(map[string]any)
	if !ok {
		t.Fatalf("Expected JSON-RPC error object, got %T", payload["error"])
	}
	if errorObj["code"] != code {
		t.Fatalf("Expected error code %v, got %v", code, errorObj["code"])
	}
	if errorObj["message"] != message {
		t.Fatalf("Expected error message %q, got %v", message, errorObj["message"])
	}
}

func createMockRequestContext(headers map[string][]string) *policy.RequestContext {
	return &policy.RequestContext{
		SharedContext: &policy.SharedContext{
			RequestID:     "test-request-id",
			Metadata:      make(map[string]any),
			OperationPath: "/mcp",
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
			RequestID:     "test-request-id",
			Metadata:      make(map[string]any),
			OperationPath: "/mcp",
		},
		RequestHeaders:  policy.NewHeaders(requestHeaders),
		ResponseHeaders: policy.NewHeaders(responseHeaders),
		RequestBody:     nil,
		ResponseBody:    nil,
	}
}

// rewriteToolA is the one config every mirrored-header test below uses: toolA rewrites to
// backendTool, so a rewrite always changes the name and always makes the mirror stale.
func rewriteToolA(t *testing.T) (policy.Policy, map[string]any) {
	t.Helper()
	params := map[string]any{
		"tools": []any{
			map[string]any{
				"name":        "toolA",
				"description": "desc",
				"inputSchema": `{"type":"object"}`,
				"target":      "backendTool",
			},
		},
	}
	return mustPolicy(t, params), params
}

// toolCallContext builds a tools/call on toolA carrying the given headers.
func toolCallContext(t *testing.T, headers map[string][]string) *policy.RequestContext {
	t.Helper()
	ctx := createMockRequestContext(headers)
	ctx.Method = "POST"
	ctx.Path = "/mcp"
	ctx.Body = &policy.Body{Content: mustJSON(t, map[string]any{
		"jsonrpc": "2.0",
		"id":      "1",
		"method":  "tools/call",
		"params":  map[string]any{"name": "toolA"},
	}), Present: true}
	return ctx
}

func mustModifications(t *testing.T, action policy.RequestAction) policy.UpstreamRequestModifications {
	t.Helper()
	mods, ok := action.(policy.UpstreamRequestModifications)
	if !ok {
		t.Fatalf("Expected UpstreamRequestModifications, got %T", action)
	}
	return mods
}

// TestOnRequest_RefusesToLaunderAMirrorMismatch is the most important assertion in this file.
//
// The header names a capability the caller is allowed and peer policies governed on; the body
// names a different one. Rewriting the header to match the body would hand the backend a
// self-consistent request invoking a capability authorization never saw, and the backend's
// mandatory -32020 check would have nothing left to catch.
func TestOnRequest_RefusesToLaunderAMirrorMismatch(t *testing.T) {
	p, params := rewriteToolA(t)
	ctx := toolCallContext(t, map[string][]string{
		"mcp-protocol-version": {"2026-07-28"},
		"mcp-method":           {"tools/call"},
		"mcp-name":             {"query_database"},
	})

	action := p.(*McpRewritePolicy).OnRequestBody(context.Background(), ctx, params)

	if mods, ok := action.(policy.UpstreamRequestModifications); ok {
		t.Fatalf("Expected the request to be rejected, but it was forwarded with headers %v and body %s",
			mods.HeadersToSet, string(mods.Body))
	}
	resp := mustImmediateResponse(t, action)
	if resp.StatusCode != 400 {
		t.Fatalf("Expected status 400, got %d", resp.StatusCode)
	}
	assertJSONRPCError(t, resp.Body, -32020, "Mcp-Name does not match the capability in the request body")
}

func TestOnRequest_RefusesAMethodMirrorMismatch(t *testing.T) {
	p, params := rewriteToolA(t)
	ctx := toolCallContext(t, map[string][]string{
		"mcp-protocol-version": {"2026-07-28"},
		"mcp-method":           {"tools/list"},
		"mcp-name":             {"toolA"},
	})

	action := p.(*McpRewritePolicy).OnRequestBody(context.Background(), ctx, params)
	if mods, ok := action.(policy.UpstreamRequestModifications); ok {
		t.Fatalf("Expected the request to be rejected, but it was forwarded with headers %v and body %s",
			mods.HeadersToSet, string(mods.Body))
	}
	resp := mustImmediateResponse(t, action)
	if resp.StatusCode != 400 {
		t.Fatalf("Expected status 400, got %d", resp.StatusCode)
	}
	assertJSONRPCError(t, resp.Body, -32020, "Mcp-Method does not match the method in the request body")
}

// A body that names a method whose mirror is absent cannot be repaired here, because a rewrite
// never changes the method. It is refused rather than forwarded half-mirrored.
func TestOnRequest_RefusesAModernBodyMethodWithNoMirroredMethod(t *testing.T) {
	p, params := rewriteToolA(t)
	ctx := toolCallContext(t, map[string][]string{
		"mcp-protocol-version": {"2026-07-28"},
		"mcp-name":             {"toolA"},
	})

	resp := mustImmediateResponse(t, p.(*McpRewritePolicy).OnRequestBody(context.Background(), ctx, params))
	if resp.StatusCode != 400 {
		t.Fatalf("Expected status 400, got %d", resp.StatusCode)
	}
	assertJSONRPCError(t, resp.Body, -32020, "Mcp-Method header is missing, but a method is present in the request body")
}

// The method check runs before the capability is resolved, so a contradictory request is refused
// whatever it names. It is rejected rather than forwarded, so it cannot reach the backend by
// skipping the unlisted-capability block below it.
func TestOnRequest_MethodMismatchRefusedBeforeCapabilityLookup(t *testing.T) {
	p, params := rewriteToolA(t)
	ctx := createMockRequestContext(map[string][]string{
		"mcp-protocol-version": {"2026-07-28"},
		"mcp-method":           {"tools/list"},
	})
	ctx.Method = "POST"
	ctx.Path = "/mcp"
	ctx.Body = &policy.Body{Content: mustJSON(t, map[string]any{
		"jsonrpc": "2.0",
		"id":      "1",
		"method":  "tools/call",
		"params":  map[string]any{"name": "unlistedTool"},
	}), Present: true}

	resp := mustImmediateResponse(t, p.(*McpRewritePolicy).OnRequestBody(context.Background(), ctx, params))
	assertJSONRPCError(t, resp.Body, -32020, "Mcp-Method does not match the method in the request body")
}

// A conformant modern listing must still publish the request-phase note the response phase gates
// on, or */list results would stop being rewritten and leak backend capability names.
func TestOnRequest_ModernListStillPublishesListMetadata(t *testing.T) {
	p, params := rewriteToolA(t)
	ctx := createMockRequestContext(map[string][]string{
		"mcp-protocol-version": {"2026-07-28"},
		"mcp-method":           {"tools/list"},
	})
	ctx.Method = "POST"
	ctx.Path = "/mcp"
	ctx.Body = &policy.Body{Content: mustJSON(t, map[string]any{
		"jsonrpc": "2.0",
		"id":      "1",
		"method":  "tools/list",
	}), Present: true}

	p.(*McpRewritePolicy).OnRequestBody(context.Background(), ctx, params)

	if got := ctx.Metadata[metadataMcpAction]; got != "list" {
		t.Fatalf("Expected the list note to be published, got %v", got)
	}
	if got := ctx.Metadata[metadataMcpCapabilityType]; got != "tools" {
		t.Fatalf("Expected capability type 'tools', got %v", got)
	}
}

// An undecodable sentinel is not the same as an absent header: the client mirrored something,
// and what a peer policy made of it cannot be established, so it is refused rather than
// silently overwritten.
func TestOnRequest_RefusesAnUndecodableMirroredName(t *testing.T) {
	p, params := rewriteToolA(t)
	ctx := toolCallContext(t, map[string][]string{
		"mcp-protocol-version": {"2026-07-28"},
		"mcp-method":           {"tools/call"},
		"mcp-name":             {"=?base64?not valid base64!?="},
	})

	resp := mustImmediateResponse(t, p.(*McpRewritePolicy).OnRequestBody(context.Background(), ctx, params))
	assertJSONRPCError(t, resp.Body, -32020, "Mcp-Name is not a decodable sentinel value")
}

func TestOnRequest_ModernRewriteRestatesTheMirroredName(t *testing.T) {
	p, params := rewriteToolA(t)
	ctx := toolCallContext(t, map[string][]string{
		"mcp-protocol-version": {"2026-07-28"},
		"mcp-method":           {"tools/call"},
		"mcp-name":             {"toolA"},
	})

	mods := mustModifications(t, p.(*McpRewritePolicy).OnRequestBody(context.Background(), ctx, params))

	updated := mustJSONMap(t, mods.Body)
	if got := updated["params"].(map[string]any)["name"]; got != "backendTool" {
		t.Fatalf("Expected rewritten body name 'backendTool', got %v", got)
	}
	if got := mods.HeadersToSet["Mcp-Name"]; got != "backendTool" {
		t.Fatalf("Expected Mcp-Name rewritten to 'backendTool', got %q", got)
	}
}

// A body naming a capability whose mirror is absent is refused, on the same terms as the method:
// the mirror is incomplete, so the request is not one to rewrite.
func TestOnRequest_RefusesAModernBodyNameWithNoMirroredName(t *testing.T) {
	p, params := rewriteToolA(t)
	ctx := toolCallContext(t, map[string][]string{
		"mcp-protocol-version": {"2026-07-28"},
		"mcp-method":           {"tools/call"},
	})

	resp := mustImmediateResponse(t, p.(*McpRewritePolicy).OnRequestBody(context.Background(), ctx, params))
	assertJSONRPCError(t, resp.Body, -32020, "Mcp-Name header is missing, but a capability name is present in the request body")
}

// The message names the method that required it, so a resources/read reads correctly too.
func TestMirroredNameMismatch(t *testing.T) {
	tests := []struct {
		name    string
		headers map[string][]string
		capName string
		want    string
	}{
		{"legacy ignores the header entirely", map[string][]string{"mcp-name": {"other"}}, "toolA", ""},
		{"modern agreeing", map[string][]string{"mcp-protocol-version": {"2026-07-28"}, "mcp-name": {"toolA"}}, "toolA", ""},
		{"modern absent against a body name", map[string][]string{"mcp-protocol-version": {"2026-07-28"}}, "file://a", "Mcp-Name header is missing, but a capability name is present in the request body"},
		{"both absent is not a failure", map[string][]string{"mcp-protocol-version": {"2026-07-28"}}, "", ""},
		{"modern undecodable", map[string][]string{"mcp-protocol-version": {"2026-07-28"}, "mcp-name": {"=?base64?zz!?="}}, "toolA", "Mcp-Name is not a decodable sentinel value"},
		{"modern disagreeing", map[string][]string{"mcp-protocol-version": {"2026-07-28"}, "mcp-name": {"other"}}, "toolA", "Mcp-Name does not match the capability in the request body"},
		{"sentinel decodes before comparing", map[string][]string{"mcp-protocol-version": {"2026-07-28"}, "mcp-name": {"=?base64?dG9vbF/DvG1sYXV0?="}}, "tool_ümlaut", ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := mirroredNameMismatch(policy.NewHeaders(tc.headers), tc.capName); got != tc.want {
				t.Fatalf("mirroredNameMismatch = %q, want %q", got, tc.want)
			}
		})
	}
}

// A legacy revision mirrors nothing, so there is no header to verify and none to write back.
func TestOnRequest_LegacyRewriteSetsNoHeader(t *testing.T) {
	p, params := rewriteToolA(t)

	for _, version := range []string{"", "2025-06-18", "2025-11-25"} {
		headers := map[string][]string{}
		if version != "" {
			headers["mcp-protocol-version"] = []string{version}
		}
		ctx := toolCallContext(t, headers)

		mods := mustModifications(t, p.(*McpRewritePolicy).OnRequestBody(context.Background(), ctx, params))
		updated := mustJSONMap(t, mods.Body)
		if got := updated["params"].(map[string]any)["name"]; got != "backendTool" {
			t.Fatalf("version %q: expected rewritten body name 'backendTool', got %v", version, got)
		}
		if len(mods.HeadersToSet) != 0 {
			t.Fatalf("version %q: expected no header rewrite, got %v", version, mods.HeadersToSet)
		}
	}
}

// No rewrite means no stale mirror, so neither half is touched even on a modern request whose
// header disagrees — the backend's own -32020 check still sees the disagreement it should.
func TestOnRequest_NoOpRewriteLeavesBothHalvesAlone(t *testing.T) {
	params := map[string]any{
		"tools": []any{
			map[string]any{
				"name":        "toolA",
				"description": "desc",
				"inputSchema": `{"type":"object"}`,
				"target":      "toolA",
			},
		},
	}
	p := mustPolicy(t, params)
	ctx := toolCallContext(t, map[string][]string{
		"mcp-protocol-version": {"2026-07-28"},
		"mcp-method":           {"tools/call"},
		"mcp-name":             {"toolA"},
	})

	mods := mustModifications(t, p.(*McpRewritePolicy).OnRequestBody(context.Background(), ctx, params))
	if mods.Body != nil {
		t.Fatalf("Expected no body rewrite, got %s", string(mods.Body))
	}
	if len(mods.HeadersToSet) != 0 {
		t.Fatalf("Expected no header rewrite, got %v", mods.HeadersToSet)
	}
}

// The mirror is checked as soon as the body names a capability, not only when a rewrite would
// follow, so a self-contradicting request is refused on the same terms as a mismatched method.
func TestOnRequest_RefusesAMismatchedNameEvenWithNothingToRewrite(t *testing.T) {
	params := map[string]any{
		"tools": []any{
			map[string]any{
				"name":        "toolA",
				"description": "desc",
				"inputSchema": `{"type":"object"}`,
				"target":      "toolA",
			},
		},
	}
	p := mustPolicy(t, params)
	ctx := toolCallContext(t, map[string][]string{
		"mcp-protocol-version": {"2026-07-28"},
		"mcp-method":           {"tools/call"},
		"mcp-name":             {"something_else"},
	})

	resp := mustImmediateResponse(t, p.(*McpRewritePolicy).OnRequestBody(context.Background(), ctx, params))
	assertJSONRPCError(t, resp.Body, -32020, "Mcp-Name does not match the capability in the request body")
}

// A target that is not safely representable as visible ASCII is wrapped before it travels.
func TestOnRequest_ModernRewriteEncodesANonASCIITarget(t *testing.T) {
	params := map[string]any{
		"tools": []any{
			map[string]any{
				"name":        "toolA",
				"description": "desc",
				"inputSchema": `{"type":"object"}`,
				"target":      "tool_ümlaut",
			},
		},
	}
	p := mustPolicy(t, params)
	ctx := toolCallContext(t, map[string][]string{
		"mcp-protocol-version": {"2026-07-28"},
		"mcp-method":           {"tools/call"},
		"mcp-name":             {"toolA"},
	})

	mods := mustModifications(t, p.(*McpRewritePolicy).OnRequestBody(context.Background(), ctx, params))

	const wantHeader = "=?base64?dG9vbF/DvG1sYXV0?="
	if got := mods.HeadersToSet["Mcp-Name"]; got != wantHeader {
		t.Fatalf("Expected Mcp-Name %q, got %q", wantHeader, got)
	}
	// The body carries the real value; only the header is wrapped.
	updated := mustJSONMap(t, mods.Body)
	if got := updated["params"].(map[string]any)["name"]; got != "tool_ümlaut" {
		t.Fatalf("Expected body name 'tool_ümlaut', got %v", got)
	}
}

func TestEncodeSentinel_RoundTripsThroughDecode(t *testing.T) {
	tests := []struct {
		name       string
		value      string
		wantHeader string
	}{
		{"plain ascii is left alone", "backendTool", "backendTool"},
		{"non-ascii is wrapped", "tool_ümlaut", "=?base64?dG9vbF/DvG1sYXV0?="},
		{"a space is not visible ascii", "two words", "=?base64?dHdvIHdvcmRz?="},
		{"a newline cannot travel in a header", "a\r\nInjected: yes", "=?base64?YQ0KSW5qZWN0ZWQ6IHllcw==?="},
		// A literal that would be mistaken for sentinel form must be wrapped, or a reader
		// would decode it into something the operator never wrote.
		{"a sentinel-shaped literal is wrapped", "=?base64?dG9vbA==?=", "=?base64?PT9iYXNlNjQ/ZEc5dmJBPT0/PQ==?="},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			encoded := encodeSentinel(tc.value)
			if encoded != tc.wantHeader {
				t.Fatalf("encodeSentinel(%q) = %q, want %q", tc.value, encoded, tc.wantHeader)
			}
			decoded, err := decodeSentinel(encoded)
			if err != nil {
				t.Fatalf("decodeSentinel(%q) returned an error: %v", encoded, err)
			}
			if decoded != tc.value {
				t.Fatalf("round trip of %q produced %q", tc.value, decoded)
			}
		})
	}
}

// A body the resolver could not read is rejected before any rewrite: the gateway and the server
// may read those bytes differently, and this policy is about to change them.
func TestOnRequest_RejectsAnUnusableBody(t *testing.T) {
	tests := []struct {
		reason  string
		code    float64
		message string
	}{
		{"syntax-error", -32700, "Invalid JSON"},
		{"invalid-member-type", -32600, "Request body has a member of the wrong type"},
		{"not-an-object", -32600, "Request body is not a single JSON-RPC request object"},
		{"ambiguous", -32600, "Ambiguous MCP request: body names a member more than once"},
	}

	for _, tc := range tests {
		t.Run(tc.reason, func(t *testing.T) {
			p, params := rewriteToolA(t)
			ctx := toolCallContext(t, nil)
			ctx.SharedContext.ResolutionAttributes = policy.NewResolutionAttributes(map[string]string{
				"mcp.body.present":  "true",
				"mcp.body.unusable": tc.reason,
			})

			resp := mustImmediateResponse(t, p.(*McpRewritePolicy).OnRequestBody(context.Background(), ctx, params))
			if resp.StatusCode != 400 {
				t.Fatalf("Expected status 400, got %d", resp.StatusCode)
			}
			assertJSONRPCError(t, resp.Body, tc.code, tc.message)
		})
	}
}

// The unusable-body check reads resolver attributes, so it is a no-op on a gateway without a
// resolver: broken JSON is still rejected by the local parse, exactly as in v1.0.3.
func TestOnRequest_NoResolverStillRejectsBrokenJSONLocally(t *testing.T) {
	p, params := rewriteToolA(t)
	ctx := toolCallContext(t, nil)
	ctx.Body = &policy.Body{Content: []byte(`{"jsonrpc":"2.0","method":`), Present: true}

	resp := mustImmediateResponse(t, p.(*McpRewritePolicy).OnRequestBody(context.Background(), ctx, params))
	assertJSONRPCError(t, resp.Body, -32700, "Invalid JSON")
}

// A resolver-less gateway publishes no attributes, so a well-formed request rewrites normally
// and the new check changes nothing about the path v1.0.3 took.
func TestOnRequest_NoResolverRewritesUnchanged(t *testing.T) {
	p, params := rewriteToolA(t)
	ctx := toolCallContext(t, nil)
	if ctx.SharedContext.ResolutionAttributes.Len() != 0 {
		t.Fatalf("Expected no resolution attributes on a resolver-less route")
	}

	mods := mustModifications(t, p.(*McpRewritePolicy).OnRequestBody(context.Background(), ctx, params))
	updated := mustJSONMap(t, mods.Body)
	if got := updated["params"].(map[string]any)["name"]; got != "backendTool" {
		t.Fatalf("Expected rewritten name 'backendTool', got %v", got)
	}
	if len(mods.HeadersToSet) != 0 {
		t.Fatalf("Expected no header rewrite without a modern version header, got %v", mods.HeadersToSet)
	}
}

// A legacy revision mirrors nothing, so an Mcp-Method header on one of those describes nothing
// and must not be checked against the body. Pins the era guard on the method check.
func TestOnRequest_LegacyIgnoresAContradictoryMirroredMethod(t *testing.T) {
	p, params := rewriteToolA(t)

	for _, version := range []string{"", "2025-06-18", "2025-11-25"} {
		headers := map[string][]string{"mcp-method": {"tools/list"}}
		if version != "" {
			headers["mcp-protocol-version"] = []string{version}
		}
		ctx := toolCallContext(t, headers)

		mods := mustModifications(t, p.(*McpRewritePolicy).OnRequestBody(context.Background(), ctx, params))
		updated := mustJSONMap(t, mods.Body)
		if got := updated["params"].(map[string]any)["name"]; got != "backendTool" {
			t.Fatalf("version %q: expected the rewrite to proceed, got %v", version, got)
		}
	}
}

func TestMirroredMethodMismatch(t *testing.T) {
	tests := []struct {
		name    string
		headers map[string][]string
		method  string
		want    string
	}{
		{"legacy ignores the header entirely", map[string][]string{"mcp-method": {"tools/list"}}, "tools/call", ""},
		{"modern agreeing", map[string][]string{"mcp-protocol-version": {"2026-07-28"}, "mcp-method": {"tools/call"}}, "tools/call", ""},
		{"modern absent against a body method", map[string][]string{"mcp-protocol-version": {"2026-07-28"}}, "tools/call", "Mcp-Method header is missing, but a method is present in the request body"},
		{"both absent is not a failure", map[string][]string{"mcp-protocol-version": {"2026-07-28"}}, "", ""},
		{"modern disagreeing", map[string][]string{"mcp-protocol-version": {"2026-07-28"}, "mcp-method": {"tools/list"}}, "tools/call", "Mcp-Method does not match the method in the request body"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := mirroredMethodMismatch(policy.NewHeaders(tc.headers), tc.method); got != tc.want {
				t.Fatalf("mirroredMethodMismatch = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestRejectionsDeclareFault pins the code chosen per rejection condition.
//
// The split is the point: blocking a capability by policy is an authorization decision and
// a malformed request is a validation failure, so the two carry different codes.
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

	p := &McpRewritePolicy{}
	headers := policy.NewHeaders(map[string][]string{})

	t.Run("malformed request", func(t *testing.T) {
		assertFault(t, p.buildRequestErrorResponse(headers, 400, -32700, "Invalid JSON", nil,
			policy.FaultCodeInvalidRequestBody, policy.FaultTypeValidation),
			policy.FaultCodeInvalidRequestBody, policy.FaultTypeValidation)
	})

	t.Run("capability blocked by policy", func(t *testing.T) {
		assertFault(t, p.buildRequestErrorResponse(headers, 403, -32602, "not allowed", "1",
			policy.FaultCodeAuthForbidden, policy.FaultTypeAuthorization),
			policy.FaultCodeAuthForbidden, policy.FaultTypeAuthorization)
	})

	t.Run("rewrite failed", func(t *testing.T) {
		assertFault(t, p.buildRequestErrorResponse(headers, 500, -32603, "Failed to update MCP request", "1",
			policy.FaultCodeMediationFailed, policy.FaultTypeMediation),
			policy.FaultCodeMediationFailed, policy.FaultTypeMediation)
	})
}

// TestResponseRewriteIsNotAFault covers this policy's category-C path: it rewrites
// capability names in a successful MCP response. That is a transformation of a healthy
// response, so neither field is set — a fault there would notify on every successful call.
func TestResponseRewriteIsNotAFault(t *testing.T) {
	mods := policy.DownstreamResponseModifications{Body: []byte(`{"jsonrpc":"2.0"}`)}
	if mods.IsFault {
		t.Fatalf("a response rewrite must not be a fault")
	}
	if mods.Fault != nil {
		t.Fatalf("a response rewrite must not describe an error")
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
