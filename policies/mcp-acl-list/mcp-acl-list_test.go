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
	"encoding/json"
	"strings"
	"testing"

	policy "github.com/wso2/api-platform/sdk/gateway/policy/v1alpha"
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

	action := p.OnRequest(ctx, params)
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

	action := p.OnRequest(ctx, params)
	if action != nil {
		t.Fatalf("Expected no action, got %T", action)
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

	action := p.OnRequest(ctx, params)
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

	action := p.OnResponse(ctx, params)
	mods, ok := action.(policy.UpstreamResponseModifications)
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

	action := p.OnResponse(ctx, params)
	mods, ok := action.(policy.UpstreamResponseModifications)
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

	action := p.OnResponse(ctx, params)
	mods, ok := action.(policy.UpstreamResponseModifications)
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
