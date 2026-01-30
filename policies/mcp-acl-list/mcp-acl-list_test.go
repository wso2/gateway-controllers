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
	"testing"

	policy "github.com/wso2/api-platform/sdk/gateway/policy/v1alpha"
)

func TestParseAclConfig_ExceptionsStringList(t *testing.T) {
	params := map[string]any{
		"tools": map[string]any{
			"mode":       "allow",
			"exceptions": []any{"toolA", "toolB"},
		},
	}

	config, err := parseAclConfig(params, "tools")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if !config.Enabled {
		t.Fatalf("Expected config to be enabled")
	}
	if config.Mode != "allow" {
		t.Fatalf("Expected mode 'allow', got %s", config.Mode)
	}
	if len(config.Exceptions) != 2 {
		t.Fatalf("Expected 2 exceptions, got %d", len(config.Exceptions))
	}
	if _, ok := config.Exceptions["toolA"]; !ok {
		t.Fatalf("Expected exception 'toolA' to be present")
	}
}

func TestParseAclConfig_InvalidExceptionsType(t *testing.T) {
	params := map[string]any{
		"tools": map[string]any{
			"mode":       "allow",
			"exceptions": []any{"toolA", 123},
		},
	}

	_, err := parseAclConfig(params, "tools")
	if err == nil {
		t.Fatalf("Expected error for invalid exception type")
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
	ctx.Path = "/mcp"
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
	ctx.Path = "/mcp"
	ctx.Body = &policy.Body{Content: body, Present: true}

	action := p.OnRequest(ctx, params)
	if action != nil {
		t.Fatalf("Expected no action, got %T", action)
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
	ctx.RequestPath = "/mcp"
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
