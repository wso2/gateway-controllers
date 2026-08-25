/*
 *  Copyright (c) 2026, WSO2 LLC. (http://www.wso2.org) All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

package setheaders

import (
	"context"
	"strings"
	"testing"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

// Helper function to create test headers
func createTestHeaders(headers map[string]string) *policy.Headers {
	headerMap := make(map[string][]string)
	for k, v := range headers {
		headerMap[k] = []string{v}
	}
	return policy.NewHeaders(headerMap)
}

func TestGetPolicy(t *testing.T) {
	metadata := policy.PolicyMetadata{}
	params := map[string]interface{}{}

	p, err := GetPolicy(metadata, params)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if p == nil {
		t.Fatal("Expected policy instance, got nil")
	}

	if _, ok := p.(*SetHeadersPolicy); !ok {
		t.Errorf("Expected SetHeadersPolicy, got %T", p)
	}
}

func TestSetHeadersPolicy_OnRequestHeaders_NoHeaders(t *testing.T) {
	p := &SetHeadersPolicy{}
	ctx := &policy.RequestHeaderContext{
		SharedContext: &policy.SharedContext{
			RequestID: "req-1",
			Metadata:  map[string]interface{}{},
		},
		Headers: createTestHeaders(map[string]string{
			"content-type": "application/json",
		}),
	}

	// No requestHeaders parameter
	params := map[string]interface{}{}
	result := p.OnRequestHeaders(context.Background(), ctx, params)

	// Should return empty modifications
	mods, ok := result.(policy.UpstreamRequestHeaderModifications)
	if !ok {
		t.Errorf("Expected UpstreamRequestHeaderModifications, got %T", result)
	}

	if len(mods.HeadersToSet) != 0 {
		t.Errorf("Expected no headers to be set, got %d headers", len(mods.HeadersToSet))
	}
}

func TestSetHeadersPolicy_OnRequestHeaders_SingleHeader(t *testing.T) {
	p := &SetHeadersPolicy{}
	ctx := &policy.RequestHeaderContext{
		SharedContext: &policy.SharedContext{
			RequestID: "req-1",
			Metadata:  map[string]interface{}{},
		},
		Headers: createTestHeaders(map[string]string{
			"content-type": "application/json",
		}),
	}

	params := map[string]interface{}{
		"requestHeaders": []interface{}{
			map[string]interface{}{
				"name":  "X-Custom-Header",
				"value": "custom-value",
			},
		},
	}

	result := p.OnRequestHeaders(context.Background(), ctx, params)

	mods, ok := result.(policy.UpstreamRequestHeaderModifications)
	if !ok {
		t.Errorf("Expected UpstreamRequestHeaderModifications, got %T", result)
	}

	if len(mods.HeadersToSet) != 1 {
		t.Errorf("Expected 1 header to be set, got %d headers", len(mods.HeadersToSet))
	}

	expectedHeaderName := "x-custom-header" // Should be normalized to lowercase
	if mods.HeadersToSet[expectedHeaderName] != "custom-value" {
		t.Errorf("Expected header '%s' to have value 'custom-value', got '%s'",
			expectedHeaderName, mods.HeadersToSet[expectedHeaderName])
	}
}

func TestSetHeadersPolicy_OnRequestHeaders_MultipleHeaders(t *testing.T) {
	p := &SetHeadersPolicy{}
	ctx := &policy.RequestHeaderContext{
		SharedContext: &policy.SharedContext{
			RequestID: "req-1",
			Metadata:  map[string]interface{}{},
		},
		Headers: createTestHeaders(map[string]string{
			"content-type": "application/json",
		}),
	}

	params := map[string]interface{}{
		"requestHeaders": []interface{}{
			map[string]interface{}{
				"name":  "X-API-Key",
				"value": "secret-key-123",
			},
			map[string]interface{}{
				"name":  "X-Client-Version",
				"value": "1.2.3",
			},
			map[string]interface{}{
				"name":  "X-Request-ID",
				"value": "req-456",
			},
		},
	}

	result := p.OnRequestHeaders(context.Background(), ctx, params)

	mods, ok := result.(policy.UpstreamRequestHeaderModifications)
	if !ok {
		t.Errorf("Expected UpstreamRequestHeaderModifications, got %T", result)
	}

	if len(mods.HeadersToSet) != 3 {
		t.Errorf("Expected 3 headers to be set, got %d headers", len(mods.HeadersToSet))
	}

	expectedHeaders := map[string]string{
		"x-api-key":        "secret-key-123",
		"x-client-version": "1.2.3",
		"x-request-id":     "req-456",
	}

	for name, expectedValue := range expectedHeaders {
		if actualValue := mods.HeadersToSet[name]; actualValue != expectedValue {
			t.Errorf("Expected header '%s' to have value '%s', got '%s'",
				name, expectedValue, actualValue)
		}
	}
}

func TestSetHeadersPolicy_OnRequestHeaders_HeaderNameNormalization(t *testing.T) {
	p := &SetHeadersPolicy{}
	ctx := &policy.RequestHeaderContext{
		SharedContext: &policy.SharedContext{
			RequestID: "req-1",
			Metadata:  map[string]interface{}{},
		},
		Headers: createTestHeaders(map[string]string{}),
	}

	params := map[string]interface{}{
		"requestHeaders": []interface{}{
			map[string]interface{}{
				"name":  "  X-UPPER-CASE  ", // With spaces and uppercase
				"value": "test-value",
			},
		},
	}

	result := p.OnRequestHeaders(context.Background(), ctx, params)

	mods, ok := result.(policy.UpstreamRequestHeaderModifications)
	if !ok {
		t.Errorf("Expected UpstreamRequestHeaderModifications, got %T", result)
	}

	expectedHeaderName := "x-upper-case" // Should be trimmed and lowercase
	if mods.HeadersToSet[expectedHeaderName] != "test-value" {
		t.Errorf("Expected header '%s' to be normalized and set, got headers: %v",
			expectedHeaderName, mods.HeadersToSet)
	}
}

func TestSetHeadersPolicy_OnResponseHeaders_NoHeaders(t *testing.T) {
	p := &SetHeadersPolicy{}
	ctx := &policy.ResponseHeaderContext{
		SharedContext: &policy.SharedContext{
			RequestID: "req-1",
			Metadata:  map[string]interface{}{},
		},
		ResponseHeaders: createTestHeaders(map[string]string{
			"content-type": "application/json",
		}),
	}

	// No responseHeaders parameter
	params := map[string]interface{}{}
	result := p.OnResponseHeaders(context.Background(), ctx, params)

	// Should return empty modifications
	mods, ok := result.(policy.DownstreamResponseHeaderModifications)
	if !ok {
		t.Errorf("Expected DownstreamResponseHeaderModifications, got %T", result)
	}

	if len(mods.HeadersToSet) != 0 {
		t.Errorf("Expected no headers to be set, got %d headers", len(mods.HeadersToSet))
	}
}

func TestSetHeadersPolicy_OnResponseHeaders_SingleHeader(t *testing.T) {
	p := &SetHeadersPolicy{}
	ctx := &policy.ResponseHeaderContext{
		SharedContext: &policy.SharedContext{
			RequestID: "req-1",
			Metadata:  map[string]interface{}{},
		},
		ResponseHeaders: createTestHeaders(map[string]string{
			"content-type": "application/json",
		}),
	}

	params := map[string]interface{}{
		"responseHeaders": []interface{}{
			map[string]interface{}{
				"name":  "X-Response-Time",
				"value": "123ms",
			},
		},
	}

	result := p.OnResponseHeaders(context.Background(), ctx, params)

	mods, ok := result.(policy.DownstreamResponseHeaderModifications)
	if !ok {
		t.Errorf("Expected DownstreamResponseHeaderModifications, got %T", result)
	}

	if len(mods.HeadersToSet) != 1 {
		t.Errorf("Expected 1 header to be set, got %d headers", len(mods.HeadersToSet))
	}

	expectedHeaderName := "x-response-time" // Should be normalized to lowercase
	if mods.HeadersToSet[expectedHeaderName] != "123ms" {
		t.Errorf("Expected header '%s' to have value '123ms', got '%s'",
			expectedHeaderName, mods.HeadersToSet[expectedHeaderName])
	}
}

func TestSetHeadersPolicy_OnResponseHeaders_MultipleHeaders(t *testing.T) {
	p := &SetHeadersPolicy{}
	ctx := &policy.ResponseHeaderContext{
		SharedContext: &policy.SharedContext{
			RequestID: "req-1",
			Metadata:  map[string]interface{}{},
		},
		ResponseHeaders: createTestHeaders(map[string]string{
			"content-type": "application/json",
		}),
	}

	params := map[string]interface{}{
		"responseHeaders": []interface{}{
			map[string]interface{}{
				"name":  "X-Cache-Status",
				"value": "HIT",
			},
			map[string]interface{}{
				"name":  "X-Server-Version",
				"value": "2.1.0",
			},
			map[string]interface{}{
				"name":  "X-Content-Hash",
				"value": "abc123def456",
			},
		},
	}

	result := p.OnResponseHeaders(context.Background(), ctx, params)

	mods, ok := result.(policy.DownstreamResponseHeaderModifications)
	if !ok {
		t.Errorf("Expected DownstreamResponseHeaderModifications, got %T", result)
	}

	if len(mods.HeadersToSet) != 3 {
		t.Errorf("Expected 3 headers to be set, got %d headers", len(mods.HeadersToSet))
	}

	expectedHeaders := map[string]string{
		"x-cache-status":   "HIT",
		"x-server-version": "2.1.0",
		"x-content-hash":   "abc123def456",
	}

	for name, expectedValue := range expectedHeaders {
		if actualValue := mods.HeadersToSet[name]; actualValue != expectedValue {
			t.Errorf("Expected header '%s' to have value '%s', got '%s'",
				name, expectedValue, actualValue)
		}
	}
}

func TestSetHeadersPolicy_BothRequestAndResponse(t *testing.T) {
	p := &SetHeadersPolicy{}

	// Test request phase
	reqCtx := &policy.RequestHeaderContext{
		SharedContext: &policy.SharedContext{
			RequestID: "req-1",
			Metadata:  map[string]interface{}{},
		},
		Headers: createTestHeaders(map[string]string{}),
	}

	params := map[string]interface{}{
		"requestHeaders": []interface{}{
			map[string]interface{}{
				"name":  "X-Request-Header",
				"value": "request-value",
			},
		},
		"responseHeaders": []interface{}{
			map[string]interface{}{
				"name":  "X-Response-Header",
				"value": "response-value",
			},
		},
	}

	reqResult := p.OnRequestHeaders(context.Background(), reqCtx, params)
	reqMods, ok := reqResult.(policy.UpstreamRequestHeaderModifications)
	if !ok {
		t.Errorf("Expected UpstreamRequestHeaderModifications, got %T", reqResult)
	}

	if reqMods.HeadersToSet["x-request-header"] != "request-value" {
		t.Errorf("Expected request header to be set")
	}

	// Test response phase
	respCtx := &policy.ResponseHeaderContext{
		SharedContext: &policy.SharedContext{
			RequestID: "req-1",
			Metadata:  map[string]interface{}{},
		},
		ResponseHeaders: createTestHeaders(map[string]string{}),
	}

	respResult := p.OnResponseHeaders(context.Background(), respCtx, params)
	respMods, ok := respResult.(policy.DownstreamResponseHeaderModifications)
	if !ok {
		t.Errorf("Expected DownstreamResponseHeaderModifications, got %T", respResult)
	}

	if respMods.HeadersToSet["x-response-header"] != "response-value" {
		t.Errorf("Expected response header to be set")
	}
}

func TestSetHeadersPolicy_BodyPhase(t *testing.T) {
	params := map[string]interface{}{
		"request": map[string]interface{}{
			"phase": "body",
			"headers": []interface{}{
				map[string]interface{}{"name": "Authorization", "value": "Bearer provider-secret"},
			},
		},
	}
	raw, err := GetPolicy(policy.PolicyMetadata{}, params)
	if err != nil {
		t.Fatal(err)
	}
	p := raw.(*SetHeadersPolicy)
	if p.Mode().RequestBodyMode != policy.BodyModeBuffer {
		t.Fatalf("body mode = %v, want buffer", p.Mode().RequestBodyMode)
	}
	if err := p.Validate(params); err != nil {
		t.Fatal(err)
	}
	headerMods := p.OnRequestHeaders(context.Background(), &policy.RequestHeaderContext{}, params).(policy.UpstreamRequestHeaderModifications)
	if len(headerMods.HeadersToSet) != 0 {
		t.Fatalf("body-phase headers were applied during header phase: %v", headerMods.HeadersToSet)
	}
	bodyMods := p.OnRequestBody(context.Background(), &policy.RequestContext{}, params).(policy.UpstreamRequestModifications)
	if bodyMods.HeadersToSet["authorization"] != "Bearer provider-secret" {
		t.Fatalf("body-phase header missing: %v", bodyMods.HeadersToSet)
	}
}

func TestSetHeadersPolicy_DefaultRemainsHeaderPhase(t *testing.T) {
	raw, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{})
	if err != nil {
		t.Fatal(err)
	}
	if raw.Mode().RequestBodyMode != policy.BodyModeSkip {
		t.Fatalf("default request body mode = %v, want skip", raw.Mode().RequestBodyMode)
	}
}

func TestSetHeadersPolicy_RejectsInvalidRequestPhase(t *testing.T) {
	p := &SetHeadersPolicy{}
	err := p.Validate(map[string]interface{}{
		"request": map[string]interface{}{
			"phase": "request_body",
			"headers": []interface{}{
				map[string]interface{}{"name": "Authorization", "value": "secret"},
			},
		},
	})
	if err == nil || !strings.Contains(err.Error(), "request.phase must be either 'header' or 'body'") {
		t.Fatalf("expected invalid request phase error, got %v", err)
	}
}

func TestSetHeadersPolicy_EmptyHeadersList(t *testing.T) {
	p := &SetHeadersPolicy{}
	ctx := &policy.RequestHeaderContext{
		SharedContext: &policy.SharedContext{
			RequestID: "req-1",
			Metadata:  map[string]interface{}{},
		},
		Headers: createTestHeaders(map[string]string{}),
	}

	params := map[string]interface{}{
		"requestHeaders": []interface{}{}, // Empty array
	}

	result := p.OnRequestHeaders(context.Background(), ctx, params)

	mods, ok := result.(policy.UpstreamRequestHeaderModifications)
	if !ok {
		t.Errorf("Expected UpstreamRequestHeaderModifications, got %T", result)
	}

	if len(mods.HeadersToSet) != 0 {
		t.Errorf("Expected no headers to be set for empty array, got %d headers", len(mods.HeadersToSet))
	}
}

func TestSetHeadersPolicy_InvalidHeadersType(t *testing.T) {
	p := &SetHeadersPolicy{}
	ctx := &policy.RequestHeaderContext{
		SharedContext: &policy.SharedContext{
			RequestID: "req-1",
			Metadata:  map[string]interface{}{},
		},
		Headers: createTestHeaders(map[string]string{}),
	}

	params := map[string]interface{}{
		"requestHeaders": "not-an-array", // Invalid type
	}

	result := p.OnRequestHeaders(context.Background(), ctx, params)

	mods, ok := result.(policy.UpstreamRequestHeaderModifications)
	if !ok {
		t.Errorf("Expected UpstreamRequestHeaderModifications, got %T", result)
	}

	if len(mods.HeadersToSet) != 0 {
		t.Errorf("Expected no headers to be set for invalid type, got %d headers", len(mods.HeadersToSet))
	}
}

func TestSetHeadersPolicy_InvalidHeaderEntry(t *testing.T) {
	p := &SetHeadersPolicy{}
	ctx := &policy.RequestHeaderContext{
		SharedContext: &policy.SharedContext{
			RequestID: "req-1",
			Metadata:  map[string]interface{}{},
		},
		Headers: createTestHeaders(map[string]string{}),
	}

	params := map[string]interface{}{
		"requestHeaders": []interface{}{
			"not-an-object", // Invalid entry type
			map[string]interface{}{
				"name":  "Valid-Header",
				"value": "valid-value",
			},
		},
	}

	result := p.OnRequestHeaders(context.Background(), ctx, params)

	mods, ok := result.(policy.UpstreamRequestHeaderModifications)
	if !ok {
		t.Errorf("Expected UpstreamRequestHeaderModifications, got %T", result)
	}

	// Should only process valid entries
	if len(mods.HeadersToSet) != 1 {
		t.Errorf("Expected 1 valid header to be set, got %d headers", len(mods.HeadersToSet))
	}

	if mods.HeadersToSet["valid-header"] != "valid-value" {
		t.Errorf("Expected valid header to be processed correctly")
	}
}

func TestSetHeadersPolicy_SpecialCharactersInValues(t *testing.T) {
	p := &SetHeadersPolicy{}
	ctx := &policy.RequestHeaderContext{
		SharedContext: &policy.SharedContext{
			RequestID: "req-1",
			Metadata:  map[string]interface{}{},
		},
		Headers: createTestHeaders(map[string]string{}),
	}

	params := map[string]interface{}{
		"requestHeaders": []interface{}{
			map[string]interface{}{
				"name":  "X-Special-Chars",
				"value": "value with spaces, symbols: !@#$%^&*()_+{}|:<>?[]\\;'\"",
			},
		},
	}

	result := p.OnRequestHeaders(context.Background(), ctx, params)

	mods, ok := result.(policy.UpstreamRequestHeaderModifications)
	if !ok {
		t.Errorf("Expected UpstreamRequestHeaderModifications, got %T", result)
	}

	expectedValue := "value with spaces, symbols: !@#$%^&*()_+{}|:<>?[]\\;'\""
	if mods.HeadersToSet["x-special-chars"] != expectedValue {
		t.Errorf("Expected special characters to be preserved in header value, got '%s'",
			mods.HeadersToSet["x-special-chars"])
	}
}

// Test the key difference: overwrite behavior when same header name appears multiple times
func TestSetHeadersPolicy_MultipleHeadersSameName_OverwriteBehavior(t *testing.T) {
	p := &SetHeadersPolicy{}
	ctx := &policy.RequestHeaderContext{
		SharedContext: &policy.SharedContext{
			RequestID: "req-1",
			Metadata:  map[string]interface{}{},
		},
		Headers: createTestHeaders(map[string]string{}),
	}

	// Configuration with multiple headers having the same name
	// This tests that the policy overwrites (last value wins) instead of appending
	params := map[string]interface{}{
		"requestHeaders": []interface{}{
			map[string]interface{}{
				"name":  "X-Custom-Header",
				"value": "first-value",
			},
			map[string]interface{}{
				"name":  "X-Custom-Header", // Same header name - should overwrite
				"value": "second-value",
			},
			map[string]interface{}{
				"name":  "X-Another-Header",
				"value": "another-value",
			},
		},
	}

	result := p.OnRequestHeaders(context.Background(), ctx, params)

	mods, ok := result.(policy.UpstreamRequestHeaderModifications)
	if !ok {
		t.Errorf("Expected UpstreamRequestHeaderModifications, got %T", result)
	}

	// Should have 2 unique header names (last value wins for duplicates)
	if len(mods.HeadersToSet) != 2 {
		t.Errorf("Expected 2 unique headers in HeadersToSet, got %d headers", len(mods.HeadersToSet))
	}

	// Check that the last value for X-Custom-Header is used (overwrite behavior)
	if mods.HeadersToSet["x-custom-header"] != "second-value" {
		t.Errorf("Expected 'x-custom-header' to have last value 'second-value' (overwrite), got '%s'",
			mods.HeadersToSet["x-custom-header"])
	}

	// Check that the other header is present with single value
	if mods.HeadersToSet["x-another-header"] != "another-value" {
		t.Errorf("Expected 'x-another-header' to have value 'another-value', got '%s'",
			mods.HeadersToSet["x-another-header"])
	}
}

// Test validation methods
func TestSetHeadersPolicy_Validate_ValidConfiguration(t *testing.T) {
	p := &SetHeadersPolicy{}

	params := map[string]interface{}{
		"requestHeaders": []interface{}{
			map[string]interface{}{
				"name":  "X-Request-Header",
				"value": "request-value",
			},
		},
		"responseHeaders": []interface{}{
			map[string]interface{}{
				"name":  "X-Response-Header",
				"value": "response-value",
			},
		},
	}

	err := p.Validate(params)
	if err != nil {
		t.Errorf("Expected no error for valid configuration, got: %v", err)
	}
}

func TestSetHeadersPolicy_Validate_OnlyRequestHeaders(t *testing.T) {
	p := &SetHeadersPolicy{}

	params := map[string]interface{}{
		"requestHeaders": []interface{}{
			map[string]interface{}{
				"name":  "X-Request-Header",
				"value": "request-value",
			},
		},
	}

	err := p.Validate(params)
	if err != nil {
		t.Errorf("Expected no error for valid requestHeaders only, got: %v", err)
	}
}

func TestSetHeadersPolicy_Validate_OnlyResponseHeaders(t *testing.T) {
	p := &SetHeadersPolicy{}

	params := map[string]interface{}{
		"responseHeaders": []interface{}{
			map[string]interface{}{
				"name":  "X-Response-Header",
				"value": "response-value",
			},
		},
	}

	err := p.Validate(params)
	if err != nil {
		t.Errorf("Expected no error for valid responseHeaders only, got: %v", err)
	}
}

func TestSetHeadersPolicy_Validate_NoHeadersSpecified(t *testing.T) {
	p := &SetHeadersPolicy{}

	params := map[string]interface{}{}

	err := p.Validate(params)
	if err == nil || !strings.Contains(err.Error(), "at least one of 'request.headers' or 'response.headers' must be specified") {
		t.Errorf("Expected 'at least one must be specified' error, got: %v", err)
	}
}

func TestSetHeadersPolicy_Validate_InvalidRequestHeaders(t *testing.T) {
	p := &SetHeadersPolicy{}

	params := map[string]interface{}{
		"requestHeaders": []interface{}{
			map[string]interface{}{
				"name": "X-Test-Header",
				// Missing value field
			},
		},
	}

	err := p.Validate(params)
	if err == nil || !strings.Contains(err.Error(), "missing required 'value' field") {
		t.Errorf("Expected 'missing required value field' error, got: %v", err)
	}
}

func TestSetHeadersPolicy_Validate_InvalidResponseHeaders(t *testing.T) {
	p := &SetHeadersPolicy{}

	params := map[string]interface{}{
		"responseHeaders": "not-an-array", // Invalid type
	}

	err := p.Validate(params)
	if err == nil || !strings.Contains(err.Error(), "must be an array") {
		t.Errorf("Expected 'must be an array' error, got: %v", err)
	}
}

func TestSetHeadersPolicy_Validate_EmptyRequestHeaders(t *testing.T) {
	p := &SetHeadersPolicy{}

	params := map[string]interface{}{
		"requestHeaders": []interface{}{}, // Empty array
	}

	err := p.Validate(params)
	if err == nil || !strings.Contains(err.Error(), "request.headers cannot be empty") {
		t.Errorf("Expected 'request.headers cannot be empty' error, got: %v", err)
	}
}

func TestSetHeadersPolicy_Validate_BothInvalid(t *testing.T) {
	p := &SetHeadersPolicy{}

	params := map[string]interface{}{
		"requestHeaders": []interface{}{
			map[string]interface{}{
				// Missing both name and value
			},
		},
		"responseHeaders": []interface{}{
			map[string]interface{}{
				"name":  "X-Response-Header",
				"value": "response-value",
			},
		},
	}

	err := p.Validate(params)
	// Should fail on requestHeaders validation first
	if err == nil || !strings.Contains(err.Error(), "missing required 'name' field") {
		t.Errorf("Expected 'missing required name field' error, got: %v", err)
	}
}

func TestSetHeadersPolicy_OnRequestHeaders_NestedHeaders(t *testing.T) {
	p := &SetHeadersPolicy{}
	ctx := &policy.RequestHeaderContext{
		SharedContext: &policy.SharedContext{
			RequestID: "req-1",
			Metadata:  map[string]interface{}{},
		},
		Headers: createTestHeaders(map[string]string{}),
	}

	params := map[string]interface{}{
		"request": map[string]interface{}{
			"headers": []interface{}{
				map[string]interface{}{
					"name":  "X-Nested-Request",
					"value": "nested-request-value",
				},
			},
		},
	}

	result := p.OnRequestHeaders(context.Background(), ctx, params)
	mods, ok := result.(policy.UpstreamRequestHeaderModifications)
	if !ok {
		t.Errorf("Expected UpstreamRequestHeaderModifications, got %T", result)
	}

	if mods.HeadersToSet["x-nested-request"] != "nested-request-value" {
		t.Errorf("Expected nested request header to be set, got %v", mods.HeadersToSet)
	}
}

func TestSetHeadersPolicy_OnResponseHeaders_NestedHeaders(t *testing.T) {
	p := &SetHeadersPolicy{}
	ctx := &policy.ResponseHeaderContext{
		SharedContext: &policy.SharedContext{
			RequestID: "req-1",
			Metadata:  map[string]interface{}{},
		},
		ResponseHeaders: createTestHeaders(map[string]string{}),
	}

	params := map[string]interface{}{
		"response": map[string]interface{}{
			"headers": []interface{}{
				map[string]interface{}{
					"name":  "X-Nested-Response",
					"value": "nested-response-value",
				},
			},
		},
	}

	result := p.OnResponseHeaders(context.Background(), ctx, params)
	mods, ok := result.(policy.DownstreamResponseHeaderModifications)
	if !ok {
		t.Errorf("Expected DownstreamResponseHeaderModifications, got %T", result)
	}

	if mods.HeadersToSet["x-nested-response"] != "nested-response-value" {
		t.Errorf("Expected nested response header to be set, got %v", mods.HeadersToSet)
	}
}

// ─── Mode parameter tests ────────────────────────────────────────────────────

func TestSetHeadersPolicy_Validate_ModeSet(t *testing.T) {
	p := &SetHeadersPolicy{}

	params := map[string]interface{}{
		"mode": "set",
		"requestHeaders": []interface{}{
			map[string]interface{}{
				"name":  "X-Request-Header",
				"value": "request-value",
			},
		},
	}

	err := p.Validate(params)
	if err != nil {
		t.Errorf("Expected no error for mode 'set', got: %v", err)
	}
}

func TestSetHeadersPolicy_Validate_ModeAppend(t *testing.T) {
	p := &SetHeadersPolicy{}

	params := map[string]interface{}{
		"mode": "append",
		"requestHeaders": []interface{}{
			map[string]interface{}{
				"name":  "X-Request-Header",
				"value": "request-value",
			},
		},
	}

	err := p.Validate(params)
	if err != nil {
		t.Errorf("Expected no error for mode 'append', got: %v", err)
	}
}

func TestSetHeadersPolicy_Validate_InvalidModeValue(t *testing.T) {
	p := &SetHeadersPolicy{}

	params := map[string]interface{}{
		"mode": "merge", // Not a supported mode
		"requestHeaders": []interface{}{
			map[string]interface{}{
				"name":  "X-Request-Header",
				"value": "request-value",
			},
		},
	}

	err := p.Validate(params)
	if err == nil || !strings.Contains(err.Error(), "mode must be either 'set' or 'append'") {
		t.Errorf("Expected 'mode must be either' error, got: %v", err)
	}
}

func TestSetHeadersPolicy_Validate_InvalidModeType(t *testing.T) {
	p := &SetHeadersPolicy{}

	params := map[string]interface{}{
		"mode": 123, // Not a string
		"requestHeaders": []interface{}{
			map[string]interface{}{
				"name":  "X-Request-Header",
				"value": "request-value",
			},
		},
	}

	err := p.Validate(params)
	if err == nil || !strings.Contains(err.Error(), "mode must be a string") {
		t.Errorf("Expected 'mode must be a string' error, got: %v", err)
	}
}

func TestSetHeadersPolicy_OnRequestHeaders_AppendMode(t *testing.T) {
	p := &SetHeadersPolicy{}
	ctx := &policy.RequestHeaderContext{
		SharedContext: &policy.SharedContext{
			RequestID: "req-1",
			Metadata:  map[string]interface{}{},
		},
		Headers: createTestHeaders(map[string]string{
			"x-roles": "admin",
		}),
	}

	params := map[string]interface{}{
		"mode": "append",
		"requestHeaders": []interface{}{
			map[string]interface{}{
				"name":  "X-Roles",
				"value": "editor",
			},
		},
	}

	result := p.OnRequestHeaders(context.Background(), ctx, params)

	mods, ok := result.(policy.UpstreamRequestHeaderModifications)
	if !ok {
		t.Errorf("Expected UpstreamRequestHeaderModifications, got %T", result)
	}

	if len(mods.HeadersToSet) != 0 {
		t.Errorf("Expected no headers in HeadersToSet for append mode, got %d", len(mods.HeadersToSet))
	}

	if len(mods.HeadersToAppend) != 1 {
		t.Errorf("Expected 1 header in HeadersToAppend, got %d", len(mods.HeadersToAppend))
	}

	values := mods.HeadersToAppend["x-roles"]
	if len(values) != 1 || values[0] != "editor" {
		t.Errorf("Expected 'x-roles' to append ['editor'], got %v", values)
	}
}

func TestSetHeadersPolicy_OnRequestHeaders_AppendMode_DuplicateNames(t *testing.T) {
	p := &SetHeadersPolicy{}
	ctx := &policy.RequestHeaderContext{
		SharedContext: &policy.SharedContext{
			RequestID: "req-1",
			Metadata:  map[string]interface{}{},
		},
		Headers: createTestHeaders(map[string]string{}),
	}

	// In append mode duplicate names must all be preserved, in configured order,
	// instead of last-value-wins.
	params := map[string]interface{}{
		"mode": "append",
		"requestHeaders": []interface{}{
			map[string]interface{}{
				"name":  "X-Roles",
				"value": "editor",
			},
			map[string]interface{}{
				"name":  "X-Roles",
				"value": "viewer",
			},
			map[string]interface{}{
				"name":  "X-Other",
				"value": "other-value",
			},
		},
	}

	result := p.OnRequestHeaders(context.Background(), ctx, params)

	mods, ok := result.(policy.UpstreamRequestHeaderModifications)
	if !ok {
		t.Errorf("Expected UpstreamRequestHeaderModifications, got %T", result)
	}

	if len(mods.HeadersToAppend) != 2 {
		t.Errorf("Expected 2 unique header names in HeadersToAppend, got %d", len(mods.HeadersToAppend))
	}

	roles := mods.HeadersToAppend["x-roles"]
	if len(roles) != 2 || roles[0] != "editor" || roles[1] != "viewer" {
		t.Errorf("Expected 'x-roles' to append ['editor', 'viewer'] in order, got %v", roles)
	}

	other := mods.HeadersToAppend["x-other"]
	if len(other) != 1 || other[0] != "other-value" {
		t.Errorf("Expected 'x-other' to append ['other-value'], got %v", other)
	}
}

func TestSetHeadersPolicy_OnRequestHeaders_AppendMode_HeaderNameNormalization(t *testing.T) {
	p := &SetHeadersPolicy{}
	ctx := &policy.RequestHeaderContext{
		SharedContext: &policy.SharedContext{
			RequestID: "req-1",
			Metadata:  map[string]interface{}{},
		},
		Headers: createTestHeaders(map[string]string{}),
	}

	params := map[string]interface{}{
		"mode": "append",
		"requestHeaders": []interface{}{
			map[string]interface{}{
				"name":  "  X-UPPER-CASE  ", // With spaces and uppercase
				"value": "test-value",
			},
		},
	}

	result := p.OnRequestHeaders(context.Background(), ctx, params)

	mods, ok := result.(policy.UpstreamRequestHeaderModifications)
	if !ok {
		t.Errorf("Expected UpstreamRequestHeaderModifications, got %T", result)
	}

	values := mods.HeadersToAppend["x-upper-case"] // Should be trimmed and lowercase
	if len(values) != 1 || values[0] != "test-value" {
		t.Errorf("Expected header 'x-upper-case' to be normalized and appended, got headers: %v",
			mods.HeadersToAppend)
	}
}

func TestSetHeadersPolicy_OnResponseHeaders_AppendMode(t *testing.T) {
	p := &SetHeadersPolicy{}
	ctx := &policy.ResponseHeaderContext{
		SharedContext: &policy.SharedContext{
			RequestID: "req-1",
			Metadata:  map[string]interface{}{},
		},
		ResponseHeaders: createTestHeaders(map[string]string{
			"vary": "Accept",
		}),
	}

	params := map[string]interface{}{
		"mode": "append",
		"responseHeaders": []interface{}{
			map[string]interface{}{
				"name":  "Vary",
				"value": "Accept-Encoding",
			},
		},
	}

	result := p.OnResponseHeaders(context.Background(), ctx, params)

	mods, ok := result.(policy.DownstreamResponseHeaderModifications)
	if !ok {
		t.Errorf("Expected DownstreamResponseHeaderModifications, got %T", result)
	}

	if len(mods.HeadersToSet) != 0 {
		t.Errorf("Expected no headers in HeadersToSet for append mode, got %d", len(mods.HeadersToSet))
	}

	values := mods.HeadersToAppend["vary"]
	if len(values) != 1 || values[0] != "Accept-Encoding" {
		t.Errorf("Expected 'vary' to append ['Accept-Encoding'], got %v", values)
	}
}

func TestSetHeadersPolicy_OnRequestHeaders_ExplicitSetMode(t *testing.T) {
	p := &SetHeadersPolicy{}
	ctx := &policy.RequestHeaderContext{
		SharedContext: &policy.SharedContext{
			RequestID: "req-1",
			Metadata:  map[string]interface{}{},
		},
		Headers: createTestHeaders(map[string]string{}),
	}

	params := map[string]interface{}{
		"mode": "set",
		"requestHeaders": []interface{}{
			map[string]interface{}{
				"name":  "X-Custom-Header",
				"value": "custom-value",
			},
		},
	}

	result := p.OnRequestHeaders(context.Background(), ctx, params)

	mods, ok := result.(policy.UpstreamRequestHeaderModifications)
	if !ok {
		t.Errorf("Expected UpstreamRequestHeaderModifications, got %T", result)
	}

	if len(mods.HeadersToAppend) != 0 {
		t.Errorf("Expected no headers in HeadersToAppend for set mode, got %d", len(mods.HeadersToAppend))
	}

	if mods.HeadersToSet["x-custom-header"] != "custom-value" {
		t.Errorf("Expected 'x-custom-header' to be set to 'custom-value', got '%s'",
			mods.HeadersToSet["x-custom-header"])
	}
}

func TestSetHeadersPolicy_OnRequestHeaders_DefaultModeIsSet(t *testing.T) {
	p := &SetHeadersPolicy{}
	ctx := &policy.RequestHeaderContext{
		SharedContext: &policy.SharedContext{
			RequestID: "req-1",
			Metadata:  map[string]interface{}{},
		},
		Headers: createTestHeaders(map[string]string{}),
	}

	// No mode key — must behave exactly like mode "set"
	params := map[string]interface{}{
		"requestHeaders": []interface{}{
			map[string]interface{}{
				"name":  "X-Custom-Header",
				"value": "custom-value",
			},
		},
	}

	result := p.OnRequestHeaders(context.Background(), ctx, params)

	mods, ok := result.(policy.UpstreamRequestHeaderModifications)
	if !ok {
		t.Errorf("Expected UpstreamRequestHeaderModifications, got %T", result)
	}

	if len(mods.HeadersToAppend) != 0 {
		t.Errorf("Expected no headers in HeadersToAppend when mode is absent, got %d", len(mods.HeadersToAppend))
	}

	if mods.HeadersToSet["x-custom-header"] != "custom-value" {
		t.Errorf("Expected default mode to set 'x-custom-header' to 'custom-value', got '%s'",
			mods.HeadersToSet["x-custom-header"])
	}
}

func TestSetHeadersPolicy_AppendMode_NestedConfiguration(t *testing.T) {
	p := &SetHeadersPolicy{}

	params := map[string]interface{}{
		"mode": "append",
		"request": map[string]interface{}{
			"headers": []interface{}{
				map[string]interface{}{
					"name":  "X-Nested-Request",
					"value": "nested-request-value",
				},
			},
		},
		"response": map[string]interface{}{
			"headers": []interface{}{
				map[string]interface{}{
					"name":  "X-Nested-Response",
					"value": "nested-response-value",
				},
			},
		},
	}

	if err := p.Validate(params); err != nil {
		t.Errorf("Expected no error for nested append configuration, got: %v", err)
	}

	reqCtx := &policy.RequestHeaderContext{
		SharedContext: &policy.SharedContext{
			RequestID: "req-1",
			Metadata:  map[string]interface{}{},
		},
		Headers: createTestHeaders(map[string]string{}),
	}

	reqResult := p.OnRequestHeaders(context.Background(), reqCtx, params)
	reqMods, ok := reqResult.(policy.UpstreamRequestHeaderModifications)
	if !ok {
		t.Errorf("Expected UpstreamRequestHeaderModifications, got %T", reqResult)
	}

	reqValues := reqMods.HeadersToAppend["x-nested-request"]
	if len(reqValues) != 1 || reqValues[0] != "nested-request-value" {
		t.Errorf("Expected nested request header to be appended, got %v", reqMods.HeadersToAppend)
	}

	respCtx := &policy.ResponseHeaderContext{
		SharedContext: &policy.SharedContext{
			RequestID: "req-1",
			Metadata:  map[string]interface{}{},
		},
		ResponseHeaders: createTestHeaders(map[string]string{}),
	}

	respResult := p.OnResponseHeaders(context.Background(), respCtx, params)
	respMods, ok := respResult.(policy.DownstreamResponseHeaderModifications)
	if !ok {
		t.Errorf("Expected DownstreamResponseHeaderModifications, got %T", respResult)
	}

	respValues := respMods.HeadersToAppend["x-nested-response"]
	if len(respValues) != 1 || respValues[0] != "nested-response-value" {
		t.Errorf("Expected nested response header to be appended, got %v", respMods.HeadersToAppend)
	}
}

func TestSetHeadersPolicy_Validate_NestedConfiguration(t *testing.T) {
	p := &SetHeadersPolicy{}

	params := map[string]interface{}{
		"request": map[string]interface{}{
			"headers": []interface{}{
				map[string]interface{}{
					"name":  "X-Nested-Request",
					"value": "nested-request-value",
				},
			},
		},
		"response": map[string]interface{}{
			"headers": []interface{}{
				map[string]interface{}{
					"name":  "X-Nested-Response",
					"value": "nested-response-value",
				},
			},
		},
	}

	err := p.Validate(params)
	if err != nil {
		t.Errorf("Expected no error for nested configuration, got: %v", err)
	}
}
