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

package analyticsheaderfilter

import (
	"testing"

	policy "github.com/wso2/api-platform/sdk/gateway/policy/v1alpha"
)

func TestGetPolicy(t *testing.T) {
	p, err := GetPolicy(policy.PolicyMetadata{}, nil)
	if err != nil {
		t.Errorf("GetPolicy returned error: %v", err)
	}
	if p == nil {
		t.Error("GetPolicy returned nil policy")
	}
	if _, ok := p.(*AnalyticsHeaderFilterPolicy); !ok {
		t.Error("GetPolicy returned wrong policy type")
	}
}

func TestMode(t *testing.T) {
	p := &AnalyticsHeaderFilterPolicy{}
	mode := p.Mode()

	if mode.RequestHeaderMode != policy.HeaderModeProcess {
		t.Errorf("Expected RequestHeaderMode to be HeaderModeProcess, got %v", mode.RequestHeaderMode)
	}
	if mode.RequestBodyMode != policy.BodyModeSkip {
		t.Errorf("Expected RequestBodyMode to be BodyModeSkip, got %v", mode.RequestBodyMode)
	}
	if mode.ResponseHeaderMode != policy.HeaderModeProcess {
		t.Errorf("Expected ResponseHeaderMode to be HeaderModeProcess, got %v", mode.ResponseHeaderMode)
	}
	if mode.ResponseBodyMode != policy.BodyModeSkip {
		t.Errorf("Expected ResponseBodyMode to be BodyModeSkip, got %v", mode.ResponseBodyMode)
	}
}

func TestParseHeaderList(t *testing.T) {
	p := &AnalyticsHeaderFilterPolicy{}

	tests := []struct {
		name     string
		input    interface{}
		expected []string
	}{
		{
			name:     "nil input",
			input:    nil,
			expected: nil,
		},
		{
			name:     "empty array",
			input:    []interface{}{},
			expected: []string{},
		},
		{
			name:     "valid headers",
			input:    []interface{}{"Authorization", "Content-Type", "X-Custom-Header"},
			expected: []string{"authorization", "content-type", "x-custom-header"},
		},
		{
			name:     "headers with whitespace",
			input:    []interface{}{" Authorization ", "\tContent-Type\t", "\nX-Custom\n"},
			expected: []string{"authorization", "content-type", "x-custom"},
		},
		{
			name:     "mixed valid and invalid headers",
			input:    []interface{}{"Authorization", 123, "", "  ", "Content-Type"},
			expected: []string{"authorization", "content-type"},
		},
		{
			name:     "non-array input",
			input:    "not-an-array",
			expected: nil,
		},
		{
			name:     "array with non-string elements",
			input:    []interface{}{123, true, nil},
			expected: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := p.parseHeaderList(tt.input)
			if len(result) != len(tt.expected) {
				t.Errorf("Expected %d headers, got %d", len(tt.expected), len(result))
				return
			}
			for i, expected := range tt.expected {
				if result[i] != expected {
					t.Errorf("Expected header[%d] to be %s, got %s", i, expected, result[i])
				}
			}
		})
	}
}

func TestParseMode(t *testing.T) {
	p := &AnalyticsHeaderFilterPolicy{}

	tests := []struct {
		name        string
		input       interface{}
		expected    string
		expectError bool
	}{
		{
			name:        "nil input",
			input:       nil,
			expected:    "",
			expectError: true,
		},
		{
			name:        "valid allow mode",
			input:       "allow",
			expected:    "allow",
			expectError: false,
		},
		{
			name:        "valid deny mode",
			input:       "deny",
			expected:    "deny",
			expectError: false,
		},
		{
			name:        "valid allow mode with case",
			input:       "ALLOW",
			expected:    "allow",
			expectError: false,
		},
		{
			name:        "valid deny mode with whitespace",
			input:       " deny ",
			expected:    "deny",
			expectError: false,
		},
		{
			name:        "invalid mode",
			input:       "invalid",
			expected:    "",
			expectError: true,
		},
		{
			name:        "non-string input",
			input:       123,
			expected:    "",
			expectError: true,
		},
		{
			name:        "empty string",
			input:       "",
			expected:    "",
			expectError: true,
		},
		{
			name:        "whitespace only",
			input:       "  ",
			expected:    "",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := p.parseMode(tt.input)
			if tt.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no error but got: %v", err)
			}
			if result != tt.expected {
				t.Errorf("Expected %s, got %s", tt.expected, result)
			}
		})
	}
}

func TestParseHeaderFilterConfig(t *testing.T) {
	p := &AnalyticsHeaderFilterPolicy{}

	tests := []struct {
		name            string
		input           interface{}
		expectedMode    string
		expectedHeaders []string
		expectError     bool
	}{
		{
			name:            "nil input",
			input:           nil,
			expectedMode:    "",
			expectedHeaders: nil,
			expectError:     false,
		},
		{
			name: "valid config with allow mode",
			input: map[string]interface{}{
				"mode":    "allow",
				"headers": []interface{}{"Authorization", "Content-Type"},
			},
			expectedMode:    "allow",
			expectedHeaders: []string{"authorization", "content-type"},
			expectError:     false,
		},
		{
			name: "valid config with deny mode",
			input: map[string]interface{}{
				"mode":    "deny",
				"headers": []interface{}{"X-Debug", "X-Internal"},
			},
			expectedMode:    "deny",
			expectedHeaders: []string{"x-debug", "x-internal"},
			expectError:     false,
		},
		{
			name: "config with empty headers array",
			input: map[string]interface{}{
				"mode":    "allow",
				"headers": []interface{}{},
			},
			expectedMode:    "allow",
			expectedHeaders: []string{},
			expectError:     false,
		},
		{
			name: "config without headers field",
			input: map[string]interface{}{
				"mode": "deny",
			},
			expectedMode:    "deny",
			expectedHeaders: nil,
			expectError:     false,
		},
		{
			name: "config without mode field",
			input: map[string]interface{}{
				"headers": []interface{}{"Authorization"},
			},
			expectedMode:    "",
			expectedHeaders: nil,
			expectError:     true,
		},
		{
			name: "config with null mode",
			input: map[string]interface{}{
				"mode":    nil,
				"headers": []interface{}{"Authorization"},
			},
			expectedMode:    "",
			expectedHeaders: nil,
			expectError:     true,
		},
		{
			name: "config with invalid mode",
			input: map[string]interface{}{
				"mode":    "invalid",
				"headers": []interface{}{"Authorization"},
			},
			expectedMode:    "",
			expectedHeaders: nil,
			expectError:     true,
		},
		{
			name:            "non-object input",
			input:           "not-an-object",
			expectedMode:    "",
			expectedHeaders: nil,
			expectError:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mode, headers, err := p.parseHeaderFilterConfig(tt.input)
			if tt.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no error but got: %v", err)
			}
			if mode != tt.expectedMode {
				t.Errorf("Expected mode %s, got %s", tt.expectedMode, mode)
			}
			if len(headers) != len(tt.expectedHeaders) {
				t.Errorf("Expected %d headers, got %d", len(tt.expectedHeaders), len(headers))
				return
			}
			for i, expected := range tt.expectedHeaders {
				if headers[i] != expected {
					t.Errorf("Expected header[%d] to be %s, got %s", i, expected, headers[i])
				}
			}
		})
	}
}

func TestOnRequest(t *testing.T) {
	p := &AnalyticsHeaderFilterPolicy{}

	tests := []struct {
		name                    string
		params                  map[string]interface{}
		expectedDropAction      *policy.DropHeaderAction
		expectDropActionPresent bool
	}{
		{
			name:                    "no request param",
			params:                  map[string]interface{}{},
			expectedDropAction:      nil,
			expectDropActionPresent: false,
		},
		{
			name: "nil request param",
			params: map[string]interface{}{
				"request": nil,
			},
			expectedDropAction:      nil,
			expectDropActionPresent: false,
		},
		{
			name: "valid request with allow mode",
			params: map[string]interface{}{
				"request": map[string]interface{}{
					"mode":    "allow",
					"headers": []interface{}{"Authorization", "Content-Type"},
				},
			},
			expectedDropAction: &policy.DropHeaderAction{
				Action:  "allow",
				Headers: []string{"authorization", "content-type"},
			},
			expectDropActionPresent: true,
		},
		{
			name: "valid request with deny mode",
			params: map[string]interface{}{
				"request": map[string]interface{}{
					"mode":    "deny",
					"headers": []interface{}{"X-Debug", "X-Internal"},
				},
			},
			expectedDropAction: &policy.DropHeaderAction{
				Action:  "deny",
				Headers: []string{"x-debug", "x-internal"},
			},
			expectDropActionPresent: true,
		},
		{
			name: "invalid request config",
			params: map[string]interface{}{
				"request": map[string]interface{}{
					"headers": []interface{}{"Authorization"},
					// missing mode
				},
			},
			expectedDropAction:      nil,
			expectDropActionPresent: false,
		},
		{
			name: "both request and response present",
			params: map[string]interface{}{
				"request": map[string]interface{}{
					"mode":    "allow",
					"headers": []interface{}{"Authorization"},
				},
				"response": map[string]interface{}{
					"mode":    "deny",
					"headers": []interface{}{"X-Debug"},
				},
			},
			expectedDropAction: &policy.DropHeaderAction{
				Action:  "allow",
				Headers: []string{"authorization"},
			},
			expectDropActionPresent: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := createMockRequestContext(nil)
			result := p.OnRequest(ctx, tt.params)

			if modifications, ok := result.(policy.UpstreamRequestModifications); ok {
				if tt.expectDropActionPresent {
					if modifications.DropHeadersFromAnalytics.Action != tt.expectedDropAction.Action {
						t.Errorf("Expected action %s, got %s", tt.expectedDropAction.Action, modifications.DropHeadersFromAnalytics.Action)
					}
					if len(modifications.DropHeadersFromAnalytics.Headers) != len(tt.expectedDropAction.Headers) {
						t.Errorf("Expected %d headers, got %d", len(tt.expectedDropAction.Headers), len(modifications.DropHeadersFromAnalytics.Headers))
						return
					}
					for i, expected := range tt.expectedDropAction.Headers {
						if modifications.DropHeadersFromAnalytics.Headers[i] != expected {
							t.Errorf("Expected header[%d] to be %s, got %s", i, expected, modifications.DropHeadersFromAnalytics.Headers[i])
						}
					}
				} else {
					if modifications.DropHeadersFromAnalytics.Action != "" || len(modifications.DropHeadersFromAnalytics.Headers) > 0 {
						t.Error("Expected no drop action but got one")
					}
				}
			} else {
				t.Errorf("Expected UpstreamRequestModifications, got %T", result)
			}
		})
	}
}

func TestOnResponse(t *testing.T) {
	p := &AnalyticsHeaderFilterPolicy{}

	tests := []struct {
		name                    string
		params                  map[string]interface{}
		expectedDropAction      *policy.DropHeaderAction
		expectDropActionPresent bool
	}{
		{
			name:                    "no response param",
			params:                  map[string]interface{}{},
			expectedDropAction:      nil,
			expectDropActionPresent: false,
		},
		{
			name: "nil response param",
			params: map[string]interface{}{
				"response": nil,
			},
			expectedDropAction:      nil,
			expectDropActionPresent: false,
		},
		{
			name: "valid response with allow mode",
			params: map[string]interface{}{
				"response": map[string]interface{}{
					"mode":    "allow",
					"headers": []interface{}{"Content-Type", "X-Custom"},
				},
			},
			expectedDropAction: &policy.DropHeaderAction{
				Action:  "allow",
				Headers: []string{"content-type", "x-custom"},
			},
			expectDropActionPresent: true,
		},
		{
			name: "valid response with deny mode",
			params: map[string]interface{}{
				"response": map[string]interface{}{
					"mode":    "deny",
					"headers": []interface{}{"X-Debug", "X-Internal"},
				},
			},
			expectedDropAction: &policy.DropHeaderAction{
				Action:  "deny",
				Headers: []string{"x-debug", "x-internal"},
			},
			expectDropActionPresent: true,
		},
		{
			name: "invalid response config",
			params: map[string]interface{}{
				"response": map[string]interface{}{
					"headers": []interface{}{"Content-Type"},
					// missing mode
				},
			},
			expectedDropAction:      nil,
			expectDropActionPresent: false,
		},
		{
			name: "both request and response present",
			params: map[string]interface{}{
				"request": map[string]interface{}{
					"mode":    "allow",
					"headers": []interface{}{"Authorization"},
				},
				"response": map[string]interface{}{
					"mode":    "deny",
					"headers": []interface{}{"X-Debug"},
				},
			},
			expectedDropAction: &policy.DropHeaderAction{
				Action:  "deny",
				Headers: []string{"x-debug"},
			},
			expectDropActionPresent: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := createMockResponseContext(nil, nil)
			result := p.OnResponse(ctx, tt.params)

			if modifications, ok := result.(policy.UpstreamResponseModifications); ok {
				if tt.expectDropActionPresent {
					if modifications.DropHeadersFromAnalytics.Action != tt.expectedDropAction.Action {
						t.Errorf("Expected action %s, got %s", tt.expectedDropAction.Action, modifications.DropHeadersFromAnalytics.Action)
					}
					if len(modifications.DropHeadersFromAnalytics.Headers) != len(tt.expectedDropAction.Headers) {
						t.Errorf("Expected %d headers, got %d", len(tt.expectedDropAction.Headers), len(modifications.DropHeadersFromAnalytics.Headers))
						return
					}
					for i, expected := range tt.expectedDropAction.Headers {
						if modifications.DropHeadersFromAnalytics.Headers[i] != expected {
							t.Errorf("Expected header[%d] to be %s, got %s", i, expected, modifications.DropHeadersFromAnalytics.Headers[i])
						}
					}
				} else {
					if modifications.DropHeadersFromAnalytics.Action != "" || len(modifications.DropHeadersFromAnalytics.Headers) > 0 {
						t.Error("Expected no drop action but got one")
					}
				}
			} else {
				t.Errorf("Expected UpstreamResponseModifications, got %T", result)
			}
		})
	}
}

// Helper functions for creating mock contexts
func createMockRequestContext(headers map[string][]string) *policy.RequestContext {
	return &policy.RequestContext{
		SharedContext: &policy.SharedContext{
			RequestID: "test-request-id",
			Metadata:  make(map[string]any),
		},
		Headers: policy.NewHeaders(headers),
		Body:    nil,
		Path:    "/api/test",
		Method:  "GET",
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
