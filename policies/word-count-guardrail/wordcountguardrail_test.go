package wordcountguardrail

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

func TestWordCountGuardrailPolicy_Mode(t *testing.T) {
	p := &WordCountGuardrailPolicy{}
	got := p.Mode()
	want := policy.ProcessingMode{
		RequestHeaderMode:  policy.HeaderModeSkip,
		RequestBodyMode:    policy.BodyModeBuffer,
		ResponseHeaderMode: policy.HeaderModeSkip,
		ResponseBodyMode:   policy.BodyModeStream,
	}
	if got != want {
		t.Fatalf("unexpected mode: got %+v, want %+v", got, want)
	}
}

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
		expected    WordCountGuardrailPolicyParams
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
			expected: WordCountGuardrailPolicyParams{
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
				"jsonPath":       "",
				"invert":         true,
				"showAssessment": true,
			},
			expected: WordCountGuardrailPolicyParams{
				Enabled:           RequestFlowEnabledByDefault,
				Min:               2,
				Max:               20,
				JsonPath:          "",
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
		isResponse bool
	}{
		{
			name:       "request flow disabled",
			isResponse: false,
		},
		{
			name:       "response flow disabled",
			isResponse: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseParams(map[string]interface{}{"enabled": false}, tc.isResponse)
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
		p, ok := pRaw.(*WordCountGuardrailPolicy)
		if !ok {
			t.Fatalf("expected *WordCountGuardrailPolicy, got %T", pRaw)
		}
		if !p.hasRequestParams || p.requestParams.Enabled {
			t.Fatalf("expected request params present and disabled, got hasRequest=%v enabled=%v", p.hasRequestParams, p.requestParams.Enabled)
		}

		action := p.OnRequestBody(context.Background(), &policy.RequestContext{
			Body: &policy.Body{Content: []byte(`{"messages":[{"content":"hello world"}]}`)},
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
		p, ok := pRaw.(*WordCountGuardrailPolicy)
		if !ok {
			t.Fatalf("expected *WordCountGuardrailPolicy, got %T", pRaw)
		}
		if !p.hasResponseParams || p.responseParams.Enabled {
			t.Fatalf("expected response params present and disabled, got hasResponse=%v enabled=%v", p.hasResponseParams, p.responseParams.Enabled)
		}

		action := p.OnResponseBody(context.Background(), &policy.ResponseContext{
			ResponseBody: &policy.Body{Content: []byte(`{"choices":[{"message":{"content":"hello world"}}]}`)},
		}, nil)
		if _, ok := action.(policy.DownstreamResponseModifications); !ok {
			t.Fatalf("expected response no-op when response.enabled=false, got %T", action)
		}
	})
}

func TestParseParams_DisabledFlow_IgnoresProvidedMinMax(t *testing.T) {
	for _, isResponse := range []bool{false, true} {
		got, err := parseParams(map[string]interface{}{
			"enabled":        false,
			"min":            0,
			"max":            0,
			"invert":         false,
			"showAssessment": false,
		}, isResponse)
		if err != nil {
			t.Fatalf("expected disabled flow with zero min/max to parse for isResponse=%v, got error: %v", isResponse, err)
		}
		if got.Enabled {
			t.Fatalf("expected enabled=false for isResponse=%v, got true", isResponse)
		}
	}
}

func TestGetPolicy_DisabledResponseWithZeroMinMax_IsAccepted(t *testing.T) {
	pRaw, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{
		"request": map[string]interface{}{
			"enabled":        true,
			"min":            2,
			"max":            3,
			"jsonPath":       "$.messages[-1].content",
			"invert":         false,
			"showAssessment": true,
		},
		"response": map[string]interface{}{
			"enabled":        false,
			"min":            0,
			"max":            0,
			"jsonPath":       "$.choices[0].message.content",
			"invert":         false,
			"showAssessment": false,
		},
	})
	if err != nil {
		t.Fatalf("expected disabled response with zero min/max to be accepted, got %v", err)
	}

	p, ok := pRaw.(*WordCountGuardrailPolicy)
	if !ok {
		t.Fatalf("expected *WordCountGuardrailPolicy, got %T", pRaw)
	}
	if !p.hasRequestParams {
		t.Fatalf("expected request params to be present")
	}
	if !p.hasResponseParams || p.responseParams.Enabled {
		t.Fatalf("expected response params present and disabled, got hasResponse=%v enabled=%v", p.hasResponseParams, p.responseParams.Enabled)
	}
}

func TestGetPolicy_DisabledRequestWithZeroMinMax_IsAccepted(t *testing.T) {
	pRaw, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{
		"request": map[string]interface{}{
			"enabled":        false,
			"min":            0,
			"max":            0,
			"jsonPath":       "$.messages[-1].content",
			"invert":         false,
			"showAssessment": false,
		},
		"response": map[string]interface{}{
			"enabled":        true,
			"min":            2,
			"max":            3,
			"jsonPath":       "$.choices[0].message.content",
			"invert":         false,
			"showAssessment": true,
		},
	})
	if err != nil {
		t.Fatalf("expected disabled request with zero min/max to be accepted, got %v", err)
	}

	p, ok := pRaw.(*WordCountGuardrailPolicy)
	if !ok {
		t.Fatalf("expected *WordCountGuardrailPolicy, got %T", pRaw)
	}
	if !p.hasRequestParams || p.requestParams.Enabled {
		t.Fatalf("expected request params present and disabled, got hasRequest=%v enabled=%v", p.hasRequestParams, p.requestParams.Enabled)
	}
	if !p.hasResponseParams {
		t.Fatalf("expected response params to be present")
	}
}

func TestGetPolicy_EmptyFlowObject_IsIgnored(t *testing.T) {
	t.Run("request configured with empty response object", func(t *testing.T) {
		pRaw, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{
			"request":  map[string]interface{}{"min": 1, "max": 10},
			"response": map[string]interface{}{},
		})
		if err != nil {
			t.Fatalf("expected empty response object to be ignored, got %v", err)
		}

		p, ok := pRaw.(*WordCountGuardrailPolicy)
		if !ok {
			t.Fatalf("expected *WordCountGuardrailPolicy, got %T", pRaw)
		}
		if !p.hasRequestParams {
			t.Fatalf("expected request params to be present")
		}
		if p.hasResponseParams {
			t.Fatalf("expected empty response object to be ignored")
		}
	})

	t.Run("response configured with empty request object", func(t *testing.T) {
		pRaw, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{
			"request":  map[string]interface{}{},
			"response": map[string]interface{}{"enabled": true, "min": 1, "max": 10},
		})
		if err != nil {
			t.Fatalf("expected empty request object to be ignored, got %v", err)
		}

		p, ok := pRaw.(*WordCountGuardrailPolicy)
		if !ok {
			t.Fatalf("expected *WordCountGuardrailPolicy, got %T", pRaw)
		}
		if p.hasRequestParams {
			t.Fatalf("expected empty request object to be ignored")
		}
		if !p.hasResponseParams {
			t.Fatalf("expected response params to be present")
		}
	})

	t.Run("both empty objects still fail", func(t *testing.T) {
		_, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{
			"request":  map[string]interface{}{},
			"response": map[string]interface{}{},
		})
		if err == nil {
			t.Fatalf("expected error when both flow objects are empty")
		}
		if !strings.Contains(err.Error(), "at least one of 'request' or 'response' parameters must be provided") {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}

func TestGetPolicy(t *testing.T) {
	tests := []struct {
		name        string
		params      map[string]interface{}
		expectErr   bool
		errContains string
		check       func(t *testing.T, p *WordCountGuardrailPolicy)
	}{
		{
			name:        "missing request and response",
			params:      map[string]interface{}{},
			expectErr:   true,
			errContains: "at least one of 'request' or 'response' parameters must be provided",
		},
		{
			name: "invalid request flow type",
			params: map[string]interface{}{
				"request": "invalid",
			},
			expectErr:   true,
			errContains: "'request' must be an object",
		},
		{
			name: "invalid response flow type",
			params: map[string]interface{}{
				"response": true,
			},
			expectErr:   true,
			errContains: "'response' must be an object",
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
			check: func(t *testing.T, p *WordCountGuardrailPolicy) {
				if !p.hasRequestParams || p.hasResponseParams {
					t.Fatalf("expected request=true response=false, got request=%v response=%v", p.hasRequestParams, p.hasResponseParams)
				}
				if p.requestParams.Min != 1 || p.requestParams.Max != 10 {
					t.Fatalf("unexpected request params: %+v", p.requestParams)
				}
				if p.requestParams.JsonPath != DefaultJSONPath {
					t.Fatalf("expected default jsonPath %q, got %q", DefaultJSONPath, p.requestParams.JsonPath)
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
			check: func(t *testing.T, p *WordCountGuardrailPolicy) {
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
			check: func(t *testing.T, p *WordCountGuardrailPolicy) {
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

			p, ok := pRaw.(*WordCountGuardrailPolicy)
			if !ok {
				t.Fatalf("expected *WordCountGuardrailPolicy, got %T", pRaw)
			}

			if tc.check != nil {
				tc.check(t, p)
			}
		})
	}
}

func TestValidatePayload_RequestPaths(t *testing.T) {
	p := &WordCountGuardrailPolicy{}

	pass := p.validatePayload([]byte(`{"messages":"hello world"}`), WordCountGuardrailPolicyParams{Min: 1, Max: 10, JsonPath: "$.messages"}, false)
	if _, ok := pass.(policy.UpstreamRequestModifications); !ok {
		t.Fatalf("expected UpstreamRequestModifications on valid payload, got %T", pass)
	}

	fail := p.validatePayload([]byte(`{"messages":""}`), WordCountGuardrailPolicyParams{Min: 1, Max: 10, JsonPath: "$.messages", ShowAssessment: true}, false)
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
	if msg["interveningGuardrail"] != "word-count-guardrail" {
		t.Fatalf("unexpected interveningGuardrail: %#v", msg["interveningGuardrail"])
	}
	if msg["assessments"] == nil {
		t.Fatalf("expected assessments when showAssessment is true")
	}
}

func TestValidatePayload_ResponsePaths(t *testing.T) {
	p := &WordCountGuardrailPolicy{}

	pass := p.validatePayload([]byte(`{"messages":"hello world"}`), WordCountGuardrailPolicyParams{Min: 1, Max: 10, JsonPath: "$.messages"}, true)
	if _, ok := pass.(policy.DownstreamResponseModifications); !ok {
		t.Fatalf("expected DownstreamResponseModifications on valid response payload, got %T", pass)
	}

	fail := p.validatePayload([]byte(`{"messages":""}`), WordCountGuardrailPolicyParams{Min: 1, Max: 10, JsonPath: "$.messages", ShowAssessment: false}, true)
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
	p := &WordCountGuardrailPolicy{}
	params := WordCountGuardrailPolicyParams{
		Min:      1,
		Max:      3,
		JsonPath: "$.messages",
		Invert:   true,
	}

	// In invert mode, content within range should fail.
	within := p.validatePayload([]byte(`{"messages":"one two"}`), params, false)
	if _, ok := within.(policy.ImmediateResponse); !ok {
		t.Fatalf("expected ImmediateResponse when in-range payload is rejected in invert mode, got %T", within)
	}

	// In invert mode, content outside range should pass.
	outside := p.validatePayload([]byte(`{"messages":"one two three four"}`), params, false)
	if _, ok := outside.(policy.UpstreamRequestModifications); !ok {
		t.Fatalf("expected UpstreamRequestModifications when out-of-range payload passes in invert mode, got %T", outside)
	}
}

func TestValidatePayload_JSONPathExtraction(t *testing.T) {
	p := &WordCountGuardrailPolicy{}
	payload := []byte(`{"data":{"text":"one two"}}`)

	pass := p.validatePayload(payload, WordCountGuardrailPolicyParams{
		Min:      2,
		Max:      2,
		JsonPath: "$.data.text",
	}, false)
	if _, ok := pass.(policy.UpstreamRequestModifications); !ok {
		t.Fatalf("expected pass using jsonPath extraction, got %T", pass)
	}

	fail := p.validatePayload(payload, WordCountGuardrailPolicyParams{
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

func TestBuildAssessmentObject(t *testing.T) {
	p := &WordCountGuardrailPolicy{}

	normal := p.buildAssessmentObject("word count 20 is outside the allowed range 1-10 words", nil, false, true, 1, 10)
	if normal["actionReason"] != "Violation of applied word count constraints detected" {
		t.Fatalf("unexpected actionReason: %#v", normal["actionReason"])
	}
	if normal["assessments"] != "Violation of word count detected. Expected word count to be between 1 and 10 words." {
		t.Fatalf("unexpected assessments: %#v", normal["assessments"])
	}

	inverted := p.buildAssessmentObject("word count 2 is within the excluded range 1-10 words", nil, false, true, 1, 10)
	if inverted["assessments"] != "Violation of word count detected. Expected word count to be outside the range of 1 to 10 words." {
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

// ─── SSE / streaming helpers ──────────────────────────────────────────────────

// sseEvent returns a full SSE data line (with trailing \n\n) for the given
// delta content fragment, using the same JSON shape as the user-provided events.
func sseEvent(content string) string {
	quoted, _ := json.Marshal(content)
	return `data: {"id":"chatcmpl-test","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"content":` + string(quoted) + `},"logprobs":null,"finish_reason":null}],"obfuscation":"test"}` + "\n\n"
}

// sseInitEvent returns the very first SSE chunk that carries role=assistant
// and empty content — exactly the pattern in the user-provided stream.
func sseInitEvent() string {
	return `data: {"id":"chatcmpl-test","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"role":"assistant","content":"","refusal":null},"logprobs":null,"finish_reason":null}],"obfuscation":"test"}` + "\n\n"
}

// sseFinishEvent returns the chunk that signals finish_reason=stop with an
// empty delta — also present in the user-provided stream.
func sseFinishEvent() string {
	return `data: {"id":"chatcmpl-test","object":"chat.completion.chunk","choices":[{"index":0,"delta":{},"logprobs":null,"finish_reason":"stop"}],"obfuscation":"test"}` + "\n\n"
}

// sseDoneEvent returns the SSE terminal marker.
func sseDoneEvent() string {
	return "data: [DONE]\n\n"
}

// accumulateEvents joins SSE event strings into a single accumulated buffer,
// simulating what the kernel passes to NeedsMoreResponseData.
func accumulateEvents(events ...string) []byte {
	return []byte(strings.Join(events, ""))
}

// newStreamingPolicy constructs a policy with only response-flow params enabled
// and streaming configured, matching a typical streaming guardrail setup.
func newStreamingPolicy(min, max int) *WordCountGuardrailPolicy {
	return &WordCountGuardrailPolicy{
		hasResponseParams: true,
		responseParams: WordCountGuardrailPolicyParams{
			Enabled:           true,
			Min:               min,
			Max:               max,
			StreamingJsonPath: DefaultStreamingJsonPath,
		},
	}
}

// ─── NeedsMoreResponseData tests ─────────────────────────────────────────────

func TestNeedsMoreResponseData_DisabledOrNoParams(t *testing.T) {
	acc := accumulateEvents(sseInitEvent(), sseEvent("hello world"))

	t.Run("no response params", func(t *testing.T) {
		p := &WordCountGuardrailPolicy{hasResponseParams: false}
		if p.NeedsMoreResponseData(acc) {
			t.Fatal("expected false when hasResponseParams=false")
		}
	})

	t.Run("response params disabled", func(t *testing.T) {
		p := &WordCountGuardrailPolicy{
			hasResponseParams: true,
			responseParams:    WordCountGuardrailPolicyParams{Enabled: false, Min: 10, Max: 100},
		}
		if p.NeedsMoreResponseData(acc) {
			t.Fatal("expected false when response params disabled")
		}
	})
}

func TestNeedsMoreResponseData_NonSSEContent(t *testing.T) {
	p := newStreamingPolicy(10, 100)
	plainJSON := []byte(`{"choices":[{"message":{"content":"hello world"}}]}`)
	if p.NeedsMoreResponseData(plainJSON) {
		t.Fatal("expected false for non-SSE content")
	}
}

func TestNeedsMoreResponseData_MinZero_NoGating(t *testing.T) {
	p := newStreamingPolicy(0, 10)
	// Even with partial SSE content, min=0 means no buffering gate.
	acc := accumulateEvents(sseInitEvent(), sseEvent("hello"))
	if p.NeedsMoreResponseData(acc) {
		t.Fatal("expected false for min=0 (no gating needed)")
	}
}

// TestNeedsMoreResponseData_NormalMode_GatesUntilMin verifies the gate-then-stream
// behaviour using the same SSE event shape as the user-provided stream.
// Words arrive one or more per event, mirroring the real stream:
//
//	init (empty) → "You" → " provided" → … → " and" → " a"  (10 words total)
//
// The gate must stay open (return true) until the 10th word arrives, then close.
func TestNeedsMoreResponseData_NormalMode_GatesUntilMin(t *testing.T) {
	const min = 10
	p := newStreamingPolicy(min, 100)

	// These fragments, when concatenated, produce exactly the first 10 words
	// of the user-provided stream:
	//   "You provided a dummy email address as [EMAIL_0001] and a"
	// Note: "[EMAIL_0001]" arrives as 6 separate fragments in the real stream;
	// we consolidate them here to keep the test readable.
	fragments := []string{
		"You",       // 1
		" provided", // 2
		" a",        // 3
		" dummy",    // 4
		" email",    // 5
		" address",  // 6
		" as",       // 7
		" [EMAIL",   // 8  ← "[EMAIL" is one whitespace-delimited token
		"_0001]",    // 8  (still 8; no space, extends "[EMAIL_0001]")
		" and",      // 9
		" a",        // 10
	}

	var events []string
	events = append(events, sseInitEvent()) // empty-content init, contributes 0 words

	var acc strings.Builder
	acc.WriteString(sseInitEvent())

	wordCount := 0
	for i, frag := range fragments {
		events = append(events, sseEvent(frag))
		acc.WriteString(sseEvent(frag))

		// Count words in the full concatenated text so far (mirrors countWords logic).
		fullText := strings.TrimSpace(strings.Join(func() []string {
			var parts []string
			for _, f := range fragments[:i+1] {
				parts = append(parts, f)
			}
			return parts
		}(), ""))
		ws := strings.Fields(fullText)
		wordCount = len(ws)

		got := p.NeedsMoreResponseData([]byte(acc.String()))
		if wordCount < min {
			if !got {
				t.Errorf("fragment %d (%q): word count=%d < min=%d, expected NeedsMoreResponseData=true, got false",
					i, frag, wordCount, min)
			}
		} else {
			if got {
				t.Errorf("fragment %d (%q): word count=%d >= min=%d, expected NeedsMoreResponseData=false, got true",
					i, frag, wordCount, min)
			}
		}
	}
}

func TestNeedsMoreResponseData_FlushesOnDONE(t *testing.T) {
	// Even if min is not reached, [DONE] must always cause a flush (return false).
	p := newStreamingPolicy(100, 1000) // min=100 words, far more than stream has

	// Partial content + [DONE]
	acc := accumulateEvents(sseInitEvent(), sseEvent("hello"), sseDoneEvent())
	if p.NeedsMoreResponseData(acc) {
		t.Fatal("expected false when [DONE] is present, regardless of word count vs min")
	}
}

func TestNeedsMoreResponseData_FlushesOnFinishReasonStop(t *testing.T) {
	// The finish_reason=stop chunk has delta:{} (no content field).
	// It should not cause an early flush on its own; only [DONE] does.
	p := newStreamingPolicy(10, 100)
	acc := accumulateEvents(sseInitEvent(), sseEvent("hello"), sseFinishEvent())
	// Word count = 1, still below min=10, and no [DONE] yet → should still gate.
	if !p.NeedsMoreResponseData(acc) {
		t.Fatal("expected true (still gating) after finish_reason=stop chunk without [DONE]")
	}
}

func TestNeedsMoreResponseData_InvertMode(t *testing.T) {
	// Invert: block if word count falls within [min, max].
	// NeedsMoreResponseData must buffer until count > max (so we can be sure it
	// will be OUTSIDE the excluded range), or until [DONE] arrives.
	const minW, maxW = 5, 15
	p := &WordCountGuardrailPolicy{
		hasResponseParams: true,
		responseParams: WordCountGuardrailPolicyParams{
			Enabled:           true,
			Min:               minW,
			Max:               maxW,
			Invert:            true,
			StreamingJsonPath: DefaultStreamingJsonPath,
		},
	}

	// Build 10 words (within [5,15]) — should still be gating.
	acc := accumulateEvents(sseInitEvent())
	words10 := []string{"one", " two", " three", " four", " five",
		" six", " seven", " eight", " nine", " ten"}
	for _, w := range words10 {
		acc = append(acc, []byte(sseEvent(w))...)
	}
	if !p.NeedsMoreResponseData(acc) {
		t.Fatal("invert: 10 words in [5,15], expected NeedsMoreResponseData=true (still gating)")
	}

	// Add 6 more words to push count > max=15 → gate should open.
	extra := []string{" eleven", " twelve", " thirteen", " fourteen", " fifteen", " sixteen"}
	for _, w := range extra {
		acc = append(acc, []byte(sseEvent(w))...)
	}
	if p.NeedsMoreResponseData(acc) {
		t.Fatal("invert: 16 words > max=15, expected NeedsMoreResponseData=false (gate open)")
	}
}

func TestNeedsMoreResponseData_InvertMode_FlushesOnDONE(t *testing.T) {
	p := &WordCountGuardrailPolicy{
		hasResponseParams: true,
		responseParams: WordCountGuardrailPolicyParams{
			Enabled: true, Min: 5, Max: 100, Invert: true,
			StreamingJsonPath: DefaultStreamingJsonPath,
		},
	}
	// count=3 < max, but [DONE] forces flush.
	acc := accumulateEvents(sseInitEvent(), sseEvent("one"), sseEvent(" two"), sseEvent(" three"), sseDoneEvent())
	if p.NeedsMoreResponseData(acc) {
		t.Fatal("invert: expected false when [DONE] present, regardless of count vs max")
	}
}

// TestNeedsMoreResponseData_InitEventEmptyContent specifically tests that the
// first SSE event — which carries role=assistant and content="" — does NOT
// prematurely open the gate (i.e., it contributes 0 words, so NeedsMoreResponseData
// must return true when min > 0).
func TestNeedsMoreResponseData_InitEventEmptyContent(t *testing.T) {
	p := newStreamingPolicy(5, 100)
	// Only the init event (empty content) — must remain gating.
	acc := accumulateEvents(sseInitEvent())
	if !p.NeedsMoreResponseData(acc) {
		t.Fatal("init event (content=\"\") contributes 0 words; expected NeedsMoreResponseData=true when min=5")
	}
}

// TestNeedsMoreResponseData_UserSSEStream exercises NeedsMoreResponseData with
// the exact SSE event shape from the user-provided stream. It verifies:
//  1. Init chunk (empty content) keeps the gate closed.
//  2. Word-by-word deltas accumulate correctly.
//  3. The gate opens exactly when word count reaches min.
//  4. finish_reason=stop chunk does not prematurely open the gate.
//  5. [DONE] always opens the gate.
func TestNeedsMoreResponseData_UserSSEStream(t *testing.T) {
	const min = 10
	p := newStreamingPolicy(min, 100)

	// Simulate the exact fragment sequence from the user-provided stream.
	// Each entry is (fragment, expectedWordCount) after accumulating up to that point.
	type step struct {
		event         string
		expectedWords int
	}
	steps := []step{
		{sseInitEvent(), 0},        // role:assistant, content:"" → 0 words
		{sseEvent("You"), 1},       // 1
		{sseEvent(" provided"), 2}, // 2
		{sseEvent(" a"), 3},        // 3
		{sseEvent(" dummy"), 4},    // 4
		{sseEvent(" email"), 5},    // 5
		{sseEvent(" address"), 6},  // 6
		{sseEvent(" as"), 7},       // 7
		{sseEvent(" ["), 8},        // 8  ("[" is a whitespace-separated token)
		{sseEvent("EMAIL"), 8},     // still 8 (no space, extends "[EMAIL")
		{sseEvent("_"), 8},         // still 8
		{sseEvent("000"), 8},       // still 8
		{sseEvent("1"), 8},         // still 8
		{sseEvent("]"), 8},         // still 8 ("[EMAIL_0001]" = one token)
		{sseEvent(" and"), 9},      // 9
		{sseEvent(" a"), 10},       // 10 ← gate must open here
		{sseFinishEvent(), 10},     // finish_reason:stop, delta:{} → no new words
	}

	var acc strings.Builder
	for i, s := range steps {
		acc.WriteString(s.event)
		got := p.NeedsMoreResponseData([]byte(acc.String()))
		wantGating := s.expectedWords < min
		if got != wantGating {
			t.Errorf("step %d: word count=%d, expected NeedsMoreResponseData=%v, got %v",
				i, s.expectedWords, wantGating, got)
		}
	}

	// [DONE] must always cause a flush, even if we're below min.
	acc.WriteString(sseDoneEvent())
	if p.NeedsMoreResponseData([]byte(acc.String())) {
		t.Error("[DONE] present: expected NeedsMoreResponseData=false regardless of accumulated count")
	}
}

func TestExtractSSEDeltaContent_Diagnostic(t *testing.T) {
	events := accumulateEvents(
		sseInitEvent(),
		sseEvent("You"),
		sseEvent(" provided"),
		sseEvent(" a"),
	)
	got := extractSSEDeltaContent(string(events), DefaultStreamingJsonPath)
	t.Logf("extractSSEDeltaContent result: %q", got)
	want := "You provided a"
	if got != want {
		t.Errorf("expected %q, got %q", want, got)
	}
}

func TestOnRequestBodyAndOnResponseBody(t *testing.T) {
	// No request params configured -> no-op.
	p := &WordCountGuardrailPolicy{hasRequestParams: false, hasResponseParams: false}
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
	p.requestParams = WordCountGuardrailPolicyParams{Enabled: true, Min: 1, Max: 10, JsonPath: ""}
	reqFail := p.OnRequestBody(context.Background(), &policy.RequestContext{Body: nil}, nil)
	if _, ok := reqFail.(policy.ImmediateResponse); !ok {
		t.Fatalf("expected ImmediateResponse for request nil-body validation failure, got %T", reqFail)
	}

	// Response validation with nil body should fail when min > 0.
	p.hasResponseParams = true
	p.responseParams = WordCountGuardrailPolicyParams{Enabled: true, Min: 1, Max: 10, JsonPath: ""}
	respFail := p.OnResponseBody(context.Background(), &policy.ResponseContext{ResponseBody: nil}, nil)
	respMod, ok := respFail.(policy.DownstreamResponseModifications)
	if !ok {
		t.Fatalf("expected DownstreamResponseModifications for response nil-body validation failure, got %T", respFail)
	}
	if respMod.StatusCode == nil || *respMod.StatusCode != GuardrailErrorCode {
		t.Fatalf("expected status code %d, got %#v", GuardrailErrorCode, respMod.StatusCode)
	}

	p.requestParams.Enabled = false
	reqDisabled := p.OnRequestBody(context.Background(), &policy.RequestContext{Body: &policy.Body{Content: []byte(`{"messages":[{"content":"hello world"}]}`)}}, nil)
	if _, ok := reqDisabled.(policy.UpstreamRequestModifications); !ok {
		t.Fatalf("expected request no-op when request.enabled=false, got %T", reqDisabled)
	}

	p.responseParams.Enabled = false
	respDisabled := p.OnResponseBody(context.Background(), &policy.ResponseContext{ResponseBody: &policy.Body{Content: []byte(`{"choices":[{"message":{"content":"hello world"}}]}`)}}, nil)
	if _, ok := respDisabled.(policy.DownstreamResponseModifications); !ok {
		t.Fatalf("expected response no-op when response.enabled=false, got %T", respDisabled)
	}
}

// ─── OnResponseBodyChunk stream-stop tests ───────────────────────────────────

func newStreamingRespCtx() *policy.ResponseStreamContext {
	return &policy.ResponseStreamContext{SharedContext: &policy.SharedContext{}}
}

// TestOnResponseBodyChunk_MaxViolation_EmitsErrorAndTerminates verifies that
// when the accumulated word count exceeds max mid-stream, OnResponseBodyChunk
// returns an SSE error event with TerminateStream set so the engine closes the
// stream cleanly.
func TestOnResponseBodyChunk_MaxViolation_EmitsErrorAndTerminates(t *testing.T) {
	p := newStreamingPolicy(1, 3)
	ctx := context.Background()
	respCtx := newStreamingRespCtx()

	// First three words (count == max) pass through unmodified.
	for _, word := range []string{"one", " two", " three"} {
		chunk := &policy.StreamBody{Chunk: []byte(sseEvent(word))}
		got := p.OnResponseBodyChunk(ctx, respCtx, chunk, nil)
		if fwd, ok := got.(policy.ForwardResponseChunk); ok && fwd.Body != nil {
			t.Fatalf("word %q: expected passthrough (Body=nil), got %q", word, fwd.Body)
		}
	}

	// Fourth word pushes count to 4, exceeding max=3 — must emit error with TerminateStream.
	chunk := &policy.StreamBody{Chunk: []byte(sseEvent(" four"))}
	got := p.OnResponseBodyChunk(ctx, respCtx, chunk, nil)

	term, ok := got.(policy.TerminateResponseChunk)
	if !ok {
		t.Fatalf("expected TerminateResponseChunk on max violation, got %T", got)
	}
	if term.Body == nil {
		t.Fatal("expected error body on max violation, got nil")
	}
	if !got.TerminateStream() {
		t.Fatal("expected TerminateStream=true on max violation")
	}
	if !strings.Contains(string(term.Body), "WORD_COUNT_GUARDRAIL") {
		t.Fatalf("expected WORD_COUNT_GUARDRAIL in error body, got: %s", term.Body)
	}
	// Parse the SSE event and verify guardrail action fields.
	msg := mustMessageMap(t, []byte(strings.TrimPrefix(strings.TrimSuffix(string(term.Body), "\n\n"), "data: ")))
	if msg["action"] != "GUARDRAIL_INTERVENED" {
		t.Fatalf("expected action=GUARDRAIL_INTERVENED, got %#v", msg["action"])
	}
	if msg["interveningGuardrail"] != "word-count-guardrail" {
		t.Fatalf("expected interveningGuardrail=word-count-guardrail, got %#v", msg["interveningGuardrail"])
	}
}

// TestWordCountGuardrail_InterventionDeclaresFault covers the one funnel every rejection this policy
// makes passes through, in both phases.
func TestWordCountGuardrail_InterventionDeclaresFault(t *testing.T) {
	p := &WordCountGuardrailPolicy{}

	t.Run("request phase", func(t *testing.T) {
		action := p.buildErrorResponse("blocked detail", nil, false, false, 1, 10)
		resp, ok := action.(policy.ImmediateResponse)
		if !ok {
			t.Fatalf("expected ImmediateResponse, got %T", action)
		}
		if !resp.IsFault {
			t.Fatalf("expected IsFault=true on a guardrail intervention")
		}
		assertGuardrailError(t, resp.Fault, policy.DirectionRequest)
	})

	t.Run("response phase", func(t *testing.T) {
		action := p.buildErrorResponse("blocked detail", nil, true, false, 1, 10)
		mods, ok := action.(policy.DownstreamResponseModifications)
		if !ok {
			t.Fatalf("expected DownstreamResponseModifications, got %T", action)
		}
		if !mods.IsFault {
			t.Fatalf("expected IsFault=true on a response-side guardrail intervention")
		}
		// Direction is what separates a request-side hit from a response-side one; they
		// share a status code and only the policy knows which it made.
		assertGuardrailError(t, mods.Fault, policy.DirectionResponse)
	})
}

// TestWordCountGuardrail_AssessmentsGatedByShowAssessment covers the one field that must not leak:
// Assessments frequently holds the very content the guardrail existed to stop, so it is
// populated only where the operator opted in through showAssessment.
func TestWordCountGuardrail_AssessmentsGatedByShowAssessment(t *testing.T) {
	p := &WordCountGuardrailPolicy{}

	for _, show := range []bool{false, true} {
		name := "showAssessment=false"
		if show {
			name = "showAssessment=true"
		}
		t.Run(name, func(t *testing.T) {
			action := p.buildErrorResponse("blocked detail", nil, false, show, 1, 10)
			resp := action.(policy.ImmediateResponse)
			if resp.Fault == nil || resp.Fault.Guardrail == nil {
				t.Fatalf("expected the guardrail error to be populated")
			}
			got := resp.Fault.Guardrail.Assessments
			if show && got == nil {
				t.Fatalf("expected Assessments when showAssessment=true")
			}
			if !show && got != nil {
				t.Fatalf("Assessments must stay empty when showAssessment=false, got %v", got)
			}
		})
	}
}

// assertGuardrailError checks the parts of the description that are the same for every
// intervention this policy makes.
func assertGuardrailError(t *testing.T, err *policy.FaultDetails, wantDirection string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected Error to be populated")
	}
	if err.Code != codeGuardrailIntervened {
		t.Fatalf("expected Error.Code=%q, got %q", codeGuardrailIntervened, err.Code)
	}
	if err.Type != policy.FaultTypeGuardrail {
		t.Fatalf("expected Error.Type=%q, got %q", policy.FaultTypeGuardrail, err.Type)
	}
	if err.Direction != wantDirection {
		t.Fatalf("expected Error.Direction=%q, got %q", wantDirection, err.Direction)
	}
	if err.Description == "" {
		t.Fatalf("expected Error.Description to carry the blocked detail")
	}
	if err.Guardrail == nil {
		t.Fatalf("expected Guardrail detail to be populated")
	}
	if err.Guardrail.InterveningGuardrail != guardrailName {
		t.Fatalf("expected InterveningGuardrail=%q, got %q", guardrailName, err.Guardrail.InterveningGuardrail)
	}
	if err.Guardrail.Action != policy.GuardrailActionIntervened {
		t.Fatalf("expected Action=%q, got %q", policy.GuardrailActionIntervened, err.Guardrail.Action)
	}
	if err.Guardrail.ActionReason == "" {
		t.Fatalf("expected ActionReason to be set")
	}
}

// TestWordCountGuardrail_ExtractionFailureDeclaresFault pins the JSONPath extraction failure: no check
// ran, so it is not a guardrail verdict. An unreadable request body is the caller's; an
// unreadable response body leaves the policy unable to do its job. The client response is
// the one the policy returned before the fault was declared.
func TestWordCountGuardrail_ExtractionFailureDeclaresFault(t *testing.T) {
	p := &WordCountGuardrailPolicy{}
	params := WordCountGuardrailPolicyParams{JsonPath: "$.text", Min: 1, Max: 10}
	for _, isResponse := range []bool{false, true} {
		got := p.validatePayload([]byte(`not-json`), params, isResponse)
		if isResponse {
			assertNoVerdictFault(t, got, `{"message":{"action":"GUARDRAIL_INTERVENED","actionReason":"Error extracting value from JSONPath","direction":"RESPONSE","interveningGuardrail":"word-count-guardrail"},"type":"WORD_COUNT_GUARDRAIL"}`, policy.FaultCodeMediationFailed, policy.FaultTypeMediation, policy.DirectionResponse)
		} else {
			assertNoVerdictFault(t, got, `{"message":{"action":"GUARDRAIL_INTERVENED","actionReason":"Error extracting value from JSONPath","direction":"REQUEST","interveningGuardrail":"word-count-guardrail"},"type":"WORD_COUNT_GUARDRAIL"}`, policy.FaultCodeInvalidRequestBody, policy.FaultTypeValidation, policy.DirectionRequest)
		}
	}
}

// assertNoVerdictFault checks that a rejection made without a guardrail verdict declares
// the given fault, carries no guardrail details, and leaves the client response unchanged:
// status 422, a JSON Content-Type, and wantBody.
func assertNoVerdictFault(t *testing.T, got interface{}, wantBody, wantCode, wantType, wantDirection string) {
	t.Helper()
	var fault *policy.FaultDetails
	var isFault bool
	var status int
	var headers map[string]string
	var body []byte
	switch g := got.(type) {
	case policy.ImmediateResponse:
		status, headers, body = g.StatusCode, g.Headers, g.Body
		fault, isFault = g.Fault, g.IsFault
	case policy.DownstreamResponseModifications:
		if g.StatusCode == nil {
			t.Fatalf("expected a status code on the error response")
		}
		status, headers, body = *g.StatusCode, g.HeadersToSet, g.Body
		fault, isFault = g.Fault, g.IsFault
	default:
		t.Fatalf("expected an error response, got %T", got)
	}
	if status != 422 || len(headers) != 1 || headers["Content-Type"] != "application/json" || string(body) != wantBody {
		t.Fatalf("client response changed: got %d %v %s, want 422 map[Content-Type:application/json] %s", status, headers, body, wantBody)
	}
	if !isFault || fault == nil {
		t.Fatalf("expected the rejection to declare a fault")
	}
	if fault.Code != wantCode || fault.Type != wantType || fault.Direction != wantDirection {
		t.Fatalf("expected fault %s/%s/%s, got %s/%s/%s", wantCode, wantType, wantDirection, fault.Code, fault.Type, fault.Direction)
	}
	if fault.Guardrail != nil {
		t.Fatalf("a rejection without a verdict must not carry guardrail details, got %+v", fault.Guardrail)
	}
	if fault.Message == "" || fault.Description == "" {
		t.Fatalf("expected Message and Description to be set, got %+v", fault)
	}
}
