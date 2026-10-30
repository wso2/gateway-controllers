package contentlengthguardrail

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

func mustMessageMap(t *testing.T, body []byte) map[string]interface{} {
	t.Helper()

	var payload map[string]interface{}
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatalf("failed to unmarshal response body: %v", err)
	}

	msg, ok := payload["message"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected message object, got %#v", payload["message"])
	}

	return msg
}

func TestExtractInt(t *testing.T) {
	tests := []struct {
		name      string
		input     interface{}
		expected  int
		expectErr bool
	}{
		{"int", 10, 10, false},
		{"int64", int64(11), 11, false},
		{"float64 integer", float64(12), 12, false},
		{"string integer", "13", 13, false},
		{"string float integer", "14.0", 14, false},
		{"float64 non-integer", float64(10.5), 0, true},
		{"string non-integer", "10.5", 0, true},
		{"invalid string", "abc", 0, true},
		{"bool", true, 0, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := extractInt(tc.input)
			if tc.expectErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.expected {
				t.Fatalf("expected %d, got %d", tc.expected, got)
			}
		})
	}
}

func TestParseParams(t *testing.T) {
	tests := []struct {
		name        string
		input       map[string]interface{}
		expectErr   bool
		errContains string
		expected    ContentLengthGuardrailPolicyParams
	}{
		{
			name:        "missing min",
			input:       map[string]interface{}{"max": 10},
			expectErr:   true,
			errContains: "'min' parameter is required",
		},
		{
			name:        "missing max",
			input:       map[string]interface{}{"min": 1},
			expectErr:   true,
			errContains: "'max' parameter is required",
		},
		{
			name:        "negative min",
			input:       map[string]interface{}{"min": -1, "max": 10},
			expectErr:   true,
			errContains: "'min' cannot be negative",
		},
		{
			name:        "max not greater than zero",
			input:       map[string]interface{}{"min": 0, "max": 0},
			expectErr:   true,
			errContains: "'max' must be greater than 0",
		},
		{
			name:        "min greater than max",
			input:       map[string]interface{}{"min": 11, "max": 10},
			expectErr:   true,
			errContains: "'min' cannot be greater than 'max'",
		},
		{
			name:        "invalid jsonPath type",
			input:       map[string]interface{}{"min": 1, "max": 10, "jsonPath": 12},
			expectErr:   true,
			errContains: "'jsonPath' must be a string",
		},
		{
			name:        "invalid enabled type",
			input:       map[string]interface{}{"min": 1, "max": 10, "enabled": "true"},
			expectErr:   true,
			errContains: "'enabled' must be a boolean",
		},
		{
			name:        "invalid invert type",
			input:       map[string]interface{}{"min": 1, "max": 10, "invert": "true"},
			expectErr:   true,
			errContains: "'invert' must be a boolean",
		},
		{
			name:        "invalid showAssessment type",
			input:       map[string]interface{}{"min": 1, "max": 10, "showAssessment": "true"},
			expectErr:   true,
			errContains: "'showAssessment' must be a boolean",
		},
		{
			name: "valid with defaults",
			input: map[string]interface{}{
				"min": 1,
				"max": 10,
			},
			expected: ContentLengthGuardrailPolicyParams{
				Enabled:           RequestFlowEnabledByDefault,
				Min:               1,
				Max:               10,
				JsonPath:          DefaultJSONPath,
				StreamingJsonPath: DefaultStreamingJsonPath,
			},
		},
		{
			name: "valid with all optional fields",
			input: map[string]interface{}{
				"min":            "2",
				"max":            float64(20),
				"jsonPath":       "$.text",
				"invert":         true,
				"showAssessment": true,
			},
			expected: ContentLengthGuardrailPolicyParams{
				Enabled:           RequestFlowEnabledByDefault,
				Min:               2,
				Max:               20,
				JsonPath:          "$.text",
				StreamingJsonPath: DefaultStreamingJsonPath,
				Invert:            true,
				ShowAssessment:    true,
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseParams(tc.input, false)
			if tc.expectErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				if tc.errContains != "" && !strings.Contains(err.Error(), tc.errContains) {
					t.Fatalf("expected error containing %q, got %q", tc.errContains, err.Error())
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.expected {
				t.Fatalf("expected %+v, got %+v", tc.expected, got)
			}
		})
	}

	responseDefaults, err := parseParams(map[string]interface{}{"min": 1, "max": 10}, true)
	if err != nil {
		t.Fatalf("unexpected response defaults parse error: %v", err)
	}
	if responseDefaults.JsonPath != DefaultResponseJSONPath {
		t.Fatalf("expected response default jsonPath %q, got %q", DefaultResponseJSONPath, responseDefaults.JsonPath)
	}
	if responseDefaults.Enabled != ResponseFlowEnabledByDefault {
		t.Fatalf("expected response default enabled %v, got %v", ResponseFlowEnabledByDefault, responseDefaults.Enabled)
	}
}

func TestParseParams_DisabledFlow_DoesNotRequireMinMax(t *testing.T) {
	tests := []struct {
		name       string
		input      map[string]interface{}
		isResponse bool
	}{
		{
			name:       "request flow disabled",
			input:      map[string]interface{}{"enabled": false},
			isResponse: false,
		},
		{
			name:       "response flow disabled",
			input:      map[string]interface{}{"enabled": false},
			isResponse: true,
		},
		{
			name:       "response flow disabled with invalid min max",
			input:      map[string]interface{}{"enabled": false, "min": 0, "max": 0},
			isResponse: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseParams(tc.input, tc.isResponse)
			if err != nil {
				t.Fatalf("expected disabled flow params to parse without min/max, got error: %v", err)
			}
			if got.Enabled {
				t.Fatalf("expected enabled=false, got true")
			}
		})
	}
}

func TestDisabledFlow_GetPolicyAndHandlers_NoRequiredParams(t *testing.T) {
	t.Run("request flow disabled", func(t *testing.T) {
		pRaw, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{
			"request": map[string]interface{}{"enabled": false},
		})
		if err != nil {
			t.Fatalf("expected disabled request flow without min/max to be accepted, got %v", err)
		}
		p, ok := pRaw.(*ContentLengthGuardrailPolicy)
		if !ok {
			t.Fatalf("expected *ContentLengthGuardrailPolicy, got %T", pRaw)
		}
		if !p.hasRequestParams || p.requestParams.Enabled {
			t.Fatalf("expected request params present and disabled, got hasRequest=%v enabled=%v", p.hasRequestParams, p.requestParams.Enabled)
		}

		action := p.OnRequestBody(context.Background(), &policy.RequestContext{
			Body: &policy.Body{Content: []byte(`{"messages":[{"content":"hello"}]}`)},
		}, nil)
		if _, ok := action.(policy.UpstreamRequestModifications); !ok {
			t.Fatalf("expected request no-op when request.enabled=false, got %T", action)
		}
	})

	t.Run("response flow disabled", func(t *testing.T) {
		pRaw, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{
			"response": map[string]interface{}{"enabled": false},
		})
		if err != nil {
			t.Fatalf("expected disabled response flow without min/max to be accepted, got %v", err)
		}
		p, ok := pRaw.(*ContentLengthGuardrailPolicy)
		if !ok {
			t.Fatalf("expected *ContentLengthGuardrailPolicy, got %T", pRaw)
		}
		if !p.hasResponseParams || p.responseParams.Enabled {
			t.Fatalf("expected response params present and disabled, got hasResponse=%v enabled=%v", p.hasResponseParams, p.responseParams.Enabled)
		}

		action := p.OnResponseBody(context.Background(), &policy.ResponseContext{
			ResponseBody: &policy.Body{Content: []byte(`{"choices":[{"message":{"content":"hello"}}]}`)},
		}, nil)
		if _, ok := action.(policy.DownstreamResponseModifications); !ok {
			t.Fatalf("expected response no-op when response.enabled=false, got %T", action)
		}
	})

	t.Run("response flow disabled with invalid min max", func(t *testing.T) {
		pRaw, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{
			"response": map[string]interface{}{
				"enabled": false,
				"min":     0,
				"max":     0,
			},
		})
		if err != nil {
			t.Fatalf("expected disabled response flow with invalid min/max to be accepted, got %v", err)
		}
		p, ok := pRaw.(*ContentLengthGuardrailPolicy)
		if !ok {
			t.Fatalf("expected *ContentLengthGuardrailPolicy, got %T", pRaw)
		}
		if p.responseParams.Min != 0 || p.responseParams.Max != 0 {
			t.Fatalf("expected disabled flow to ignore provided min/max, got min=%d max=%d", p.responseParams.Min, p.responseParams.Max)
		}
	})
}

func TestGetPolicy(t *testing.T) {
	tests := []struct {
		name        string
		params      map[string]interface{}
		expectErr   bool
		errContains string
		check       func(t *testing.T, p *ContentLengthGuardrailPolicy)
	}{
		{
			name:        "missing request and response",
			params:      map[string]interface{}{},
			expectErr:   true,
			errContains: "at least one of 'request' or 'response' parameters must be provided",
		},
		{
			name: "invalid request params",
			params: map[string]interface{}{
				"request": map[string]interface{}{"min": -1, "max": 10},
			},
			expectErr:   true,
			errContains: "invalid request parameters",
		},
		{
			name: "invalid response params",
			params: map[string]interface{}{
				"response": map[string]interface{}{"min": -1, "max": 10},
			},
			expectErr:   true,
			errContains: "invalid response parameters",
		},
		{
			name: "request only",
			params: map[string]interface{}{
				"request": map[string]interface{}{"min": 1, "max": 10},
			},
			check: func(t *testing.T, p *ContentLengthGuardrailPolicy) {
				if !p.hasRequestParams || p.hasResponseParams {
					t.Fatalf("expected request=true response=false, got request=%v response=%v", p.hasRequestParams, p.hasResponseParams)
				}
				if p.requestParams.Min != 1 || p.requestParams.Max != 10 {
					t.Fatalf("unexpected request params: %+v", p.requestParams)
				}
				if p.requestParams.JsonPath != DefaultJSONPath {
					t.Fatalf("expected default request jsonPath %q, got %q", DefaultJSONPath, p.requestParams.JsonPath)
				}
				if !p.requestParams.Enabled {
					t.Fatalf("expected request enabled by default")
				}
			},
		},
		{
			name: "response only",
			params: map[string]interface{}{
				"response": map[string]interface{}{"min": 2, "max": 20},
			},
			check: func(t *testing.T, p *ContentLengthGuardrailPolicy) {
				if p.hasRequestParams || !p.hasResponseParams {
					t.Fatalf("expected request=false response=true, got request=%v response=%v", p.hasRequestParams, p.hasResponseParams)
				}
				if p.responseParams.Min != 2 || p.responseParams.Max != 20 {
					t.Fatalf("unexpected response params: %+v", p.responseParams)
				}
				if p.responseParams.JsonPath != DefaultResponseJSONPath {
					t.Fatalf("expected default response jsonPath %q, got %q", DefaultResponseJSONPath, p.responseParams.JsonPath)
				}
				if p.responseParams.Enabled {
					t.Fatalf("expected response disabled by default")
				}
			},
		},
		{
			name: "both request and response",
			params: map[string]interface{}{
				"request":  map[string]interface{}{"min": 1, "max": 10},
				"response": map[string]interface{}{"min": 2, "max": 20},
			},
			check: func(t *testing.T, p *ContentLengthGuardrailPolicy) {
				if !p.hasRequestParams || !p.hasResponseParams {
					t.Fatalf("expected both request and response params to be present")
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			pRaw, err := GetPolicy(policy.PolicyMetadata{}, tc.params)
			if tc.expectErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				if tc.errContains != "" && !strings.Contains(err.Error(), tc.errContains) {
					t.Fatalf("expected error containing %q, got %q", tc.errContains, err.Error())
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			p, ok := pRaw.(*ContentLengthGuardrailPolicy)
			if !ok {
				t.Fatalf("expected *ContentLengthGuardrailPolicy, got %T", pRaw)
			}

			if tc.check != nil {
				tc.check(t, p)
			}
		})
	}
}

func TestValidatePayload_RequestPaths(t *testing.T) {
	p := &ContentLengthGuardrailPolicy{}

	pass := p.validatePayload([]byte("hello"), ContentLengthGuardrailPolicyParams{Min: 1, Max: 10}, false)
	if _, ok := pass.(policy.UpstreamRequestModifications); !ok {
		t.Fatalf("expected UpstreamRequestModifications on valid payload, got %T", pass)
	}

	fail := p.validatePayload([]byte(""), ContentLengthGuardrailPolicyParams{Min: 1, Max: 10, ShowAssessment: true}, false)
	imm, ok := fail.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("expected ImmediateResponse on invalid payload, got %T", fail)
	}
	if imm.StatusCode != GuardrailErrorCode {
		t.Fatalf("expected status %d, got %d", GuardrailErrorCode, imm.StatusCode)
	}
	msg := mustMessageMap(t, imm.Body)
	if msg["direction"] != "REQUEST" {
		t.Fatalf("expected REQUEST direction, got %#v", msg["direction"])
	}
	if msg["interveningGuardrail"] != "content-length-guardrail" {
		t.Fatalf("unexpected interveningGuardrail: %#v", msg["interveningGuardrail"])
	}
	if msg["assessments"] == nil {
		t.Fatalf("expected assessments when showAssessment is true")
	}
}

func TestValidatePayload_ResponsePaths(t *testing.T) {
	p := &ContentLengthGuardrailPolicy{}

	pass := p.validatePayload([]byte("hello"), ContentLengthGuardrailPolicyParams{Min: 1, Max: 10}, true)
	if _, ok := pass.(policy.DownstreamResponseModifications); !ok {
		t.Fatalf("expected DownstreamResponseModifications on valid response payload, got %T", pass)
	}

	fail := p.validatePayload([]byte(""), ContentLengthGuardrailPolicyParams{Min: 1, Max: 10, ShowAssessment: false}, true)
	resp, ok := fail.(policy.DownstreamResponseModifications)
	if !ok {
		t.Fatalf("expected DownstreamResponseModifications on invalid response payload, got %T", fail)
	}
	if resp.StatusCode == nil || *resp.StatusCode != GuardrailErrorCode {
		t.Fatalf("expected response status %d, got %#v", GuardrailErrorCode, resp.StatusCode)
	}
	if resp.HeadersToSet["Content-Type"] != "application/json" {
		t.Fatalf("expected response content-type header, got %#v", resp.HeadersToSet)
	}
	msg := mustMessageMap(t, resp.Body)
	if msg["direction"] != "RESPONSE" {
		t.Fatalf("expected RESPONSE direction, got %#v", msg["direction"])
	}
	if _, ok := msg["assessments"]; ok {
		t.Fatalf("did not expect assessments when showAssessment is false")
	}
}

func TestValidatePayload_InvertMode(t *testing.T) {
	p := &ContentLengthGuardrailPolicy{}
	params := ContentLengthGuardrailPolicyParams{
		Min:    1,
		Max:    3,
		Invert: true,
	}

	// In invert mode, content within range should fail.
	within := p.validatePayload([]byte("ab"), params, false)
	if _, ok := within.(policy.ImmediateResponse); !ok {
		t.Fatalf("expected ImmediateResponse when in-range payload is rejected in invert mode, got %T", within)
	}

	// In invert mode, content outside range should pass.
	outside := p.validatePayload([]byte("abcd"), params, false)
	if _, ok := outside.(policy.UpstreamRequestModifications); !ok {
		t.Fatalf("expected UpstreamRequestModifications when out-of-range payload passes in invert mode, got %T", outside)
	}
}

func TestValidatePayload_JSONPathExtraction(t *testing.T) {
	p := &ContentLengthGuardrailPolicy{}
	payload := []byte(`{"data":{"text":"abc"}}`)

	pass := p.validatePayload(payload, ContentLengthGuardrailPolicyParams{
		Min:      3,
		Max:      3,
		JsonPath: "$.data.text",
	}, false)
	if _, ok := pass.(policy.UpstreamRequestModifications); !ok {
		t.Fatalf("expected pass using jsonPath extraction, got %T", pass)
	}

	fail := p.validatePayload(payload, ContentLengthGuardrailPolicyParams{
		Min:            1,
		Max:            10,
		JsonPath:       "$.missing",
		ShowAssessment: true,
	}, false)
	imm, ok := fail.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("expected ImmediateResponse on jsonPath extraction failure, got %T", fail)
	}
	msg := mustMessageMap(t, imm.Body)
	if msg["actionReason"] != "Error extracting value from JSONPath" {
		t.Fatalf("unexpected actionReason: %#v", msg["actionReason"])
	}
	assessmentStr, ok := msg["assessments"].(string)
	if !ok || assessmentStr == "" {
		t.Fatalf("expected string assessments from extraction error, got %#v", msg["assessments"])
	}
}

// Quotes in the extracted message are content and must be counted
func TestValidatePayload_CountsQuotes(t *testing.T) {
	p := &ContentLengthGuardrailPolicy{}

	tests := []struct {
		name     string
		content  string
		byteLen  int
		wantPass bool
	}{
		{name: "wrapping quotes counted", content: `"Hello"`, byteLen: 7, wantPass: true},
		{name: "wrapping quotes not stripped", content: `"Hello"`, byteLen: 5, wantPass: false},
		{name: "trailing quote counted", content: `He said "hi"`, byteLen: 12, wantPass: true},
		{name: "lone quote counted", content: `"`, byteLen: 1, wantPass: true},
		{name: "multiline wrapping quotes counted", content: "\"line1\nline2\"", byteLen: 13, wantPass: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			payload, err := json.Marshal(map[string]interface{}{
				"messages": []map[string]string{{"content": tc.content}},
			})
			if err != nil {
				t.Fatalf("failed to marshal payload: %v", err)
			}

			result := p.validatePayload(payload, ContentLengthGuardrailPolicyParams{
				Min:      tc.byteLen,
				Max:      tc.byteLen,
				JsonPath: DefaultJSONPath,
			}, false)

			if tc.wantPass {
				if _, ok := result.(policy.UpstreamRequestModifications); !ok {
					t.Fatalf("expected pass for %q at %d bytes, got %T", tc.content, tc.byteLen, result)
				}
				return
			}
			imm, ok := result.(policy.ImmediateResponse)
			if !ok {
				t.Fatalf("expected ImmediateResponse for %q at %d bytes, got %T", tc.content, tc.byteLen, result)
			}
			if imm.StatusCode != GuardrailErrorCode {
				t.Fatalf("expected status %d, got %d", GuardrailErrorCode, imm.StatusCode)
			}
		})
	}
}

// Quotes count toward both limits, and the limits are still enforced around them
func TestValidatePayload_QuoteBoundaries(t *testing.T) {
	p := &ContentLengthGuardrailPolicy{}

	tests := []struct {
		name       string
		content    string
		min        int
		max        int
		rawBody    bool
		isResponse bool
		invert     bool
		wantPass   bool
	}{
		{name: "quotes push content over max", content: `"Hello"`, min: 1, max: 6},
		{name: "quotes push single char over max", content: `"a"`, min: 1, max: 2},
		{name: "max enforced without quotes", content: "Hello world", min: 1, max: 5},
		{name: "min enforced without quotes", content: "ab", min: 4, max: 10},
		{name: "quotes satisfy min", content: `"ab"`, min: 4, max: 10, wantPass: true},
		{name: "inner quotes counted", content: `say "hi" now`, min: 1, max: 11},
		{name: "whitespace around quotes trimmed over max", content: `   "Hi"   `, min: 1, max: 3},
		{name: "whitespace around quotes trimmed exact", content: `   "Hi"   `, min: 4, max: 4, wantPass: true},
		{name: "raw body quotes counted", content: `"hello"`, min: 1, max: 5, rawBody: true},
		{name: "invert quotes move content out of range", content: `"ab"`, min: 1, max: 3, invert: true, wantPass: true},
		{name: "invert quotes keep content in range", content: `"a"`, min: 1, max: 3, invert: true},
		{name: "response quotes push content over max", content: `"Hello"`, min: 1, max: 6, isResponse: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			params := ContentLengthGuardrailPolicyParams{
				Min:    tc.min,
				Max:    tc.max,
				Invert: tc.invert,
			}
			payload := []byte(tc.content)
			if !tc.rawBody {
				var err error
				payload, err = json.Marshal(map[string]interface{}{
					"messages": []map[string]string{{"content": tc.content}},
				})
				if err != nil {
					t.Fatalf("failed to marshal payload: %v", err)
				}
				params.JsonPath = DefaultJSONPath
			}

			result := p.validatePayload(payload, params, tc.isResponse)

			if tc.isResponse {
				resp, ok := result.(policy.DownstreamResponseModifications)
				if !ok {
					t.Fatalf("expected DownstreamResponseModifications for %q, got %T", tc.content, result)
				}
				if tc.wantPass && resp.StatusCode != nil {
					t.Fatalf("expected pass for %q, got status %d", tc.content, *resp.StatusCode)
				}
				if !tc.wantPass && (resp.StatusCode == nil || *resp.StatusCode != GuardrailErrorCode) {
					t.Fatalf("expected status %d for %q, got %#v", GuardrailErrorCode, tc.content, resp.StatusCode)
				}
				return
			}

			if tc.wantPass {
				if _, ok := result.(policy.UpstreamRequestModifications); !ok {
					t.Fatalf("expected pass for %q in range %d-%d, got %T", tc.content, tc.min, tc.max, result)
				}
				return
			}
			imm, ok := result.(policy.ImmediateResponse)
			if !ok {
				t.Fatalf("expected ImmediateResponse for %q in range %d-%d, got %T", tc.content, tc.min, tc.max, result)
			}
			if imm.StatusCode != GuardrailErrorCode {
				t.Fatalf("expected status %d, got %d", GuardrailErrorCode, imm.StatusCode)
			}
		})
	}
}

func TestBuildAssessmentObject(t *testing.T) {
	p := &ContentLengthGuardrailPolicy{}

	normal := p.buildAssessmentObject("content length 20 bytes is outside the allowed range 1-10 bytes", nil, false, true, 1, 10)
	if normal["actionReason"] != "Violation of applied content length constraints detected." {
		t.Fatalf("unexpected actionReason: %#v", normal["actionReason"])
	}
	if normal["assessments"] != "Violation of content length detected. Expected content length to be between 1 and 10 bytes." {
		t.Fatalf("unexpected assessments: %#v", normal["assessments"])
	}

	inverted := p.buildAssessmentObject("content length 2 bytes is within the excluded range 1-10 bytes", nil, false, true, 1, 10)
	if inverted["assessments"] != "Violation of content length detected. Expected content length to be outside the range of 1 to 10 bytes." {
		t.Fatalf("unexpected inverted assessments: %#v", inverted["assessments"])
	}

	withErr := p.buildAssessmentObject("Error extracting value from JSONPath", json.Unmarshal([]byte("{"), &map[string]interface{}{}), false, true, 1, 10)
	if withErr["actionReason"] != "Error extracting value from JSONPath" {
		t.Fatalf("unexpected actionReason with error: %#v", withErr["actionReason"])
	}
	if _, ok := withErr["assessments"].(string); !ok {
		t.Fatalf("expected error assessments string, got %#v", withErr["assessments"])
	}
}

func TestOnRequestBodyAndOnResponseBody(t *testing.T) {
	// No request params configured -> no-op.
	p := &ContentLengthGuardrailPolicy{hasRequestParams: false, hasResponseParams: false}
	reqNoOp := p.OnRequestBody(context.Background(), &policy.RequestContext{}, nil)
	if _, ok := reqNoOp.(policy.UpstreamRequestModifications); !ok {
		t.Fatalf("expected request no-op modifications, got %T", reqNoOp)
	}
	respNoOp := p.OnResponseBody(context.Background(), &policy.ResponseContext{}, nil)
	if _, ok := respNoOp.(policy.DownstreamResponseModifications); !ok {
		t.Fatalf("expected response no-op modifications, got %T", respNoOp)
	}

	// Request validation with nil body should fail when min > 0.
	p.hasRequestParams = true
	p.requestParams = ContentLengthGuardrailPolicyParams{Enabled: true, Min: 1, Max: 10}
	reqFail := p.OnRequestBody(context.Background(), &policy.RequestContext{Body: nil}, nil)
	if _, ok := reqFail.(policy.ImmediateResponse); !ok {
		t.Fatalf("expected ImmediateResponse for request nil-body validation failure, got %T", reqFail)
	}

	// Response validation with nil body should fail when min > 0.
	p.hasResponseParams = true
	p.responseParams = ContentLengthGuardrailPolicyParams{Enabled: true, Min: 1, Max: 10}
	respFail := p.OnResponseBody(context.Background(), &policy.ResponseContext{ResponseBody: nil}, nil)
	respMod, ok := respFail.(policy.DownstreamResponseModifications)
	if !ok {
		t.Fatalf("expected DownstreamResponseModifications for response nil-body validation failure, got %T", respFail)
	}
	if respMod.StatusCode == nil || *respMod.StatusCode != GuardrailErrorCode {
		t.Fatalf("expected status code %d, got %#v", GuardrailErrorCode, respMod.StatusCode)
	}

	// Explicitly disabled request flow should no-op.
	p.requestParams.Enabled = false
	reqDisabled := p.OnRequestBody(context.Background(), &policy.RequestContext{Body: &policy.Body{Content: []byte(`{"messages":[{"content":"hi"}]}`)}}, nil)
	if _, ok := reqDisabled.(policy.UpstreamRequestModifications); !ok {
		t.Fatalf("expected request no-op when request.enabled=false, got %T", reqDisabled)
	}

	// Explicitly disabled response flow should no-op.
	p.responseParams.Enabled = false
	respDisabled := p.OnResponseBody(context.Background(), &policy.ResponseContext{ResponseBody: &policy.Body{Content: []byte(`{"choices":[{"message":{"content":"hi"}}]}`)}}, nil)
	if _, ok := respDisabled.(policy.DownstreamResponseModifications); !ok {
		t.Fatalf("expected response no-op when response.enabled=false, got %T", respDisabled)
	}
}
