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
	"testing"

	policy "github.com/wso2/api-platform/sdk/gateway/policy/v1alpha"
)

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

	ctx := createMockRequestContext(nil)
	ctx.Method = "POST"
	ctx.Path = "/mcp"
	ctx.Body = &policy.Body{Content: body, Present: true}

	action := p.OnRequest(ctx, params)
	mods, ok := action.(policy.UpstreamRequestModifications)
	if !ok {
		t.Fatalf("Expected UpstreamRequestModifications, got %T", action)
	}

	var updated map[string]any
	if err := json.Unmarshal(mods.Body, &updated); err != nil {
		t.Fatalf("Failed to unmarshal updated payload: %v", err)
	}
	updatedParams := updated["params"].(map[string]any)
	if updatedParams["name"] != "backendTool" {
		t.Fatalf("Expected rewritten name 'backendTool', got %v", updatedParams["name"])
	}
}

func TestOnResponse_RewritesListItemsByTarget(t *testing.T) {
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

	p, err := GetPolicy(policy.PolicyMetadata{}, params)
	if err != nil {
		t.Fatalf("Failed to create policy: %v", err)
	}

	responsePayload := map[string]any{
		"jsonrpc": "2.0",
		"id":      "1",
		"result": map[string]any{
			"tools": []any{
				map[string]any{"name": "backendTool", "description": "old"},
				map[string]any{"name": "other"},
			},
		},
	}
	body, _ := json.Marshal(responsePayload)

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

	var updated map[string]any
	if err := json.Unmarshal(mods.Body, &updated); err != nil {
		t.Fatalf("Failed to unmarshal response: %v", err)
	}
	result := updated["result"].(map[string]any)
	tools := result["tools"].([]any)
	if len(tools) != 2 {
		t.Fatalf("Expected 2 tools, got %d", len(tools))
	}
	first := tools[0].(map[string]any)
	if first["name"] != "toolA" {
		t.Fatalf("Expected rewritten name 'toolA', got %v", first["name"])
	}
	inputSchema, ok := first["inputSchema"].(map[string]any)
	if !ok {
		t.Fatalf("Expected inputSchema to be parsed as object, got %T", first["inputSchema"])
	}
	if inputSchema["type"] != "object" {
		t.Fatalf("Expected inputSchema.type 'object', got %v", inputSchema["type"])
	}
}

func TestOnRequest_ToolCallWithoutTarget_NoRewrite(t *testing.T) {
	params := map[string]any{
		"tools": []any{
			map[string]any{
				"name":        "toolA",
				"description": "desc",
				"inputSchema": `{"type":"object"}`,
				// no target
			},
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

	ctx := createMockRequestContext(nil)
	ctx.Method = "POST"
	ctx.Path = "/mcp"
	ctx.Body = &policy.Body{Content: body, Present: true}

	action := p.OnRequest(ctx, params)
	if action != nil {
		t.Fatalf("Expected no rewrite action, got %T", action)
	}
}

func TestOnResponse_RewritesListItems_WithAllCapabilities(t *testing.T) {
	params := map[string]any{
		"tools": []any{
			map[string]any{
				"name":        "toolA",
				"description": "desc",
				"inputSchema": `{"type":"object"}`,
				"target":      "backendTool",
			},
		},
		"resources": []any{
			map[string]any{
				"name":   "Resource A",
				"uri":    "https://example.com/resource-a",
				"target": "backend://resource-a",
			},
		},
		"prompts": []any{
			map[string]any{
				"name":   "promptA",
				"target": "backendPrompt",
			},
		},
	}

	p, err := GetPolicy(policy.PolicyMetadata{}, params)
	if err != nil {
		t.Fatalf("Failed to create policy: %v", err)
	}

	tests := []struct {
		name           string
		capabilityType string
		listKey        string
		entryKey       string
		entryValue     string
		configuredName string
		responseItem   map[string]any
	}{
		{
			name:           "tools list",
			capabilityType: "tools",
			listKey:        "tools",
			entryKey:       "name",
			entryValue:     "backendTool",
			configuredName: "toolA",
			responseItem:   map[string]any{"name": "backendTool"},
		},
		{
			name:           "resources list",
			capabilityType: "resources",
			listKey:        "resources",
			entryKey:       "uri",
			entryValue:     "backend://resource-a",
			configuredName: "https://example.com/resource-a",
			responseItem:   map[string]any{"uri": "backend://resource-a"},
		},
		{
			name:           "prompts list",
			capabilityType: "prompts",
			listKey:        "prompts",
			entryKey:       "name",
			entryValue:     "backendPrompt",
			configuredName: "promptA",
			responseItem:   map[string]any{"name": "backendPrompt"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			responsePayload := map[string]any{
				"jsonrpc": "2.0",
				"id":      "1",
				"result": map[string]any{
					tt.listKey: []any{
						tt.responseItem,
					},
				},
			}
			body, _ := json.Marshal(responsePayload)

			ctx := createMockResponseContext(nil, nil)
			ctx.RequestMethod = "POST"
			ctx.RequestPath = "/mcp"
			ctx.ResponseBody = &policy.Body{Content: body, Present: true}
			ctx.Metadata[metadataMcpCapabilityType] = tt.capabilityType
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
			items := result[tt.listKey].([]any)
			if len(items) != 1 {
				t.Fatalf("Expected 1 item, got %d", len(items))
			}
			item := items[0].(map[string]any)
			if item[tt.entryKey] != tt.configuredName {
				t.Fatalf("Expected %s '%s', got %v", tt.entryKey, tt.configuredName, item[tt.entryKey])
			}
		})
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
