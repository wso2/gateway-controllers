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
	"encoding/json"
	"strings"
	"testing"

	policy "github.com/wso2/api-platform/sdk/gateway/policy/v1alpha"
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

	action := p.OnRequest(ctx, params)
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

			action := p.OnRequest(ctx, tt.params)
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

			action := p.OnRequest(ctx, tt.params)
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

	action := p.OnRequest(ctx, params)
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

	action := p.OnRequest(ctx, params)
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

	action := p.OnRequest(ctx, params)
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

	action := p.OnRequest(ctx, params)
	if action != nil {
		t.Fatalf("Expected no rewrite action, got %T", action)
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

	action := p.OnResponse(ctx, params)
	mods, ok := action.(policy.UpstreamResponseModifications)
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

			action := p.OnResponse(ctx, tt.params)
			mods, ok := action.(policy.UpstreamResponseModifications)
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

	action := p.OnResponse(ctx, params)
	mods, ok := action.(policy.UpstreamResponseModifications)
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
