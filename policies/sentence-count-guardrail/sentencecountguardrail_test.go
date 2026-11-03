package sentencecountguardrail

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

func TestSentenceCountGuardrailPolicy_Mode(t *testing.T) {
	p := &SentenceCountGuardrailPolicy{}
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
		expected    SentenceCountGuardrailPolicyParams
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
			expected: SentenceCountGuardrailPolicyParams{
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
			expected: SentenceCountGuardrailPolicyParams{
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
		p, ok := pRaw.(*SentenceCountGuardrailPolicy)
		if !ok {
			t.Fatalf("expected *SentenceCountGuardrailPolicy, got %T", pRaw)
		}
		if !p.hasRequestParams || p.requestParams.Enabled {
			t.Fatalf("expected request params present and disabled, got hasRequest=%v enabled=%v", p.hasRequestParams, p.requestParams.Enabled)
		}

		action := p.OnRequestBody(context.Background(), &policy.RequestContext{
			Body: &policy.Body{Content: []byte(`{"messages":[{"content":"Hi."}]}`)},
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
		p, ok := pRaw.(*SentenceCountGuardrailPolicy)
		if !ok {
			t.Fatalf("expected *SentenceCountGuardrailPolicy, got %T", pRaw)
		}
		if !p.hasResponseParams || p.responseParams.Enabled {
			t.Fatalf("expected response params present and disabled, got hasResponse=%v enabled=%v", p.hasResponseParams, p.responseParams.Enabled)
		}

		action := p.OnResponseBody(context.Background(), &policy.ResponseContext{
			ResponseBody: &policy.Body{Content: []byte(`{"choices":[{"message":{"content":"Hi."}}]}`)},
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

func TestGetPolicy_EmptyFlowObject_IsIgnored(t *testing.T) {
	t.Run("request configured with empty response object", func(t *testing.T) {
		pRaw, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{
			"request":  map[string]interface{}{"min": 1, "max": 10},
			"response": map[string]interface{}{},
		})
		if err != nil {
			t.Fatalf("expected empty response object to be ignored, got %v", err)
		}

		p, ok := pRaw.(*SentenceCountGuardrailPolicy)
		if !ok {
			t.Fatalf("expected *SentenceCountGuardrailPolicy, got %T", pRaw)
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

		p, ok := pRaw.(*SentenceCountGuardrailPolicy)
		if !ok {
			t.Fatalf("expected *SentenceCountGuardrailPolicy, got %T", pRaw)
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
		check       func(t *testing.T, p *SentenceCountGuardrailPolicy)
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
			check: func(t *testing.T, p *SentenceCountGuardrailPolicy) {
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
			check: func(t *testing.T, p *SentenceCountGuardrailPolicy) {
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
			check: func(t *testing.T, p *SentenceCountGuardrailPolicy) {
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

			p, ok := pRaw.(*SentenceCountGuardrailPolicy)
			if !ok {
				t.Fatalf("expected *SentenceCountGuardrailPolicy, got %T", pRaw)
			}

			if tc.check != nil {
				tc.check(t, p)
			}
		})
	}
}

func TestValidatePayload_RequestPaths(t *testing.T) {
	p := &SentenceCountGuardrailPolicy{}

	pass := p.validatePayload([]byte(`{"messages":"Hello."}`), SentenceCountGuardrailPolicyParams{Min: 1, Max: 10, JsonPath: "$.messages"}, false)
	if _, ok := pass.(policy.UpstreamRequestModifications); !ok {
		t.Fatalf("expected UpstreamRequestModifications on valid payload, got %T", pass)
	}

	fail := p.validatePayload([]byte(`{"messages":""}`), SentenceCountGuardrailPolicyParams{Min: 1, Max: 10, JsonPath: "$.messages", ShowAssessment: true}, false)
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
	if msg["interveningGuardrail"] != "sentence-count-guardrail" {
		t.Fatalf("unexpected interveningGuardrail: %#v", msg["interveningGuardrail"])
	}
	if msg["assessments"] == nil {
		t.Fatalf("expected assessments when showAssessment is true")
	}
}

func TestValidatePayload_ResponsePaths(t *testing.T) {
	p := &SentenceCountGuardrailPolicy{}

	pass := p.validatePayload([]byte(`{"messages":"Hello."}`), SentenceCountGuardrailPolicyParams{Min: 1, Max: 10, JsonPath: "$.messages"}, true)
	if _, ok := pass.(policy.DownstreamResponseModifications); !ok {
		t.Fatalf("expected UpstreamResponseModifications on valid response payload, got %T", pass)
	}

	fail := p.validatePayload([]byte(`{"messages":""}`), SentenceCountGuardrailPolicyParams{Min: 1, Max: 10, JsonPath: "$.messages", ShowAssessment: false}, true)
	resp, ok := fail.(policy.DownstreamResponseModifications)
	if !ok {
		t.Fatalf("expected UpstreamResponseModifications on invalid response payload, got %T", fail)
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
	p := &SentenceCountGuardrailPolicy{}
	params := SentenceCountGuardrailPolicyParams{
		Min:      1,
		Max:      3,
		JsonPath: "$.messages",
		Invert:   true,
	}

	// In invert mode, content within range should fail.
	within := p.validatePayload([]byte(`{"messages":"One."}`), params, false)
	if _, ok := within.(policy.ImmediateResponse); !ok {
		t.Fatalf("expected ImmediateResponse when in-range payload is rejected in invert mode, got %T", within)
	}

	// In invert mode, content outside range should pass.
	outside := p.validatePayload([]byte(`{"messages":"One. Two. Three. Four."}`), params, false)
	if _, ok := outside.(policy.UpstreamRequestModifications); !ok {
		t.Fatalf("expected UpstreamRequestModifications when out-of-range payload passes in invert mode, got %T", outside)
	}
}

func TestValidatePayload_JSONPathExtraction(t *testing.T) {
	p := &SentenceCountGuardrailPolicy{}
	payload := []byte(`{"data":{"text":"First. Second."}}`)

	pass := p.validatePayload(payload, SentenceCountGuardrailPolicyParams{
		Min:      2,
		Max:      2,
		JsonPath: "$.data.text",
	}, false)
	if _, ok := pass.(policy.UpstreamRequestModifications); !ok {
		t.Fatalf("expected pass using jsonPath extraction, got %T", pass)
	}

	fail := p.validatePayload(payload, SentenceCountGuardrailPolicyParams{
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
	p := &SentenceCountGuardrailPolicy{}

	normal := p.buildAssessmentObject("sentence count 20 is outside the allowed range 1-10 sentences", nil, false, true, 1, 10)
	if normal["actionReason"] != "Violation of applied sentence count constraints detected" {
		t.Fatalf("unexpected actionReason: %#v", normal["actionReason"])
	}
	if normal["assessments"] != "Violation of sentence count detected. Expected sentence count to be between 1 and 10 sentences." {
		t.Fatalf("unexpected assessments: %#v", normal["assessments"])
	}

	inverted := p.buildAssessmentObject("sentence count 2 is within the excluded range 1-10 sentences", nil, false, true, 1, 10)
	if inverted["assessments"] != "Violation of sentence count detected. Expected sentence count to be outside the range of 1 to 10 sentences." {
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
	p := &SentenceCountGuardrailPolicy{hasRequestParams: false, hasResponseParams: false}
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
	p.requestParams = SentenceCountGuardrailPolicyParams{Enabled: true, Min: 1, Max: 10, JsonPath: ""}
	reqFail := p.OnRequestBody(context.Background(), &policy.RequestContext{Body: nil}, nil)
	if _, ok := reqFail.(policy.ImmediateResponse); !ok {
		t.Fatalf("expected ImmediateResponse for request nil-body validation failure, got %T", reqFail)
	}

	// Response validation with nil body should fail when min > 0.
	p.hasResponseParams = true
	p.responseParams = SentenceCountGuardrailPolicyParams{Enabled: true, Min: 1, Max: 10, JsonPath: ""}
	respFail := p.OnResponseBody(context.Background(), &policy.ResponseContext{ResponseBody: nil}, nil)
	respMod, ok := respFail.(policy.DownstreamResponseModifications)
	if !ok {
		t.Fatalf("expected UpstreamResponseModifications for response nil-body validation failure, got %T", respFail)
	}
	if respMod.StatusCode == nil || *respMod.StatusCode != GuardrailErrorCode {
		t.Fatalf("expected status code %d, got %#v", GuardrailErrorCode, respMod.StatusCode)
	}

	p.requestParams.Enabled = false
	reqDisabled := p.OnRequestBody(context.Background(), &policy.RequestContext{Body: &policy.Body{Content: []byte(`{"messages":[{"content":"Hi."}]}`)}}, nil)
	if _, ok := reqDisabled.(policy.UpstreamRequestModifications); !ok {
		t.Fatalf("expected request no-op when request.enabled=false, got %T", reqDisabled)
	}

	p.responseParams.Enabled = false
	respDisabled := p.OnResponseBody(context.Background(), &policy.ResponseContext{ResponseBody: &policy.Body{Content: []byte(`{"choices":[{"message":{"content":"Hi."}}]}`)}}, nil)
	if _, ok := respDisabled.(policy.DownstreamResponseModifications); !ok {
		t.Fatalf("expected response no-op when response.enabled=false, got %T", respDisabled)
	}
}

// ─── OnResponseBodyChunk stream-stop tests ───────────────────────────────────

func sseEvent(content string) string {
	quoted, _ := json.Marshal(content)
	return `data: {"id":"chatcmpl-test","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"content":` + string(quoted) + `},"logprobs":null,"finish_reason":null}],"obfuscation":"test"}` + "\n\n"
}

func newStreamingPolicy(min, max int) *SentenceCountGuardrailPolicy {
	return &SentenceCountGuardrailPolicy{
		hasResponseParams: true,
		responseParams: SentenceCountGuardrailPolicyParams{
			Enabled:           true,
			Min:               min,
			Max:               max,
			StreamingJsonPath: DefaultStreamingJsonPath,
		},
	}
}

func newStreamingRespCtx() *policy.ResponseStreamContext {
	return &policy.ResponseStreamContext{SharedContext: &policy.SharedContext{}}
}

// TestOnResponseBodyChunk_MaxViolation_EmitsErrorAndTerminates verifies that
// when the accumulated sentence count exceeds max mid-stream, OnResponseBodyChunk
// returns an SSE error event with TerminateStream set so the engine closes the
// stream cleanly.
func TestOnResponseBodyChunk_MaxViolation_EmitsErrorAndTerminates(t *testing.T) {
	p := newStreamingPolicy(1, 2)
	ctx := context.Background()
	respCtx := newStreamingRespCtx()

	// First two sentences (count == max) pass through unmodified.
	for _, sentence := range []string{"Hello.", " World."} {
		chunk := &policy.StreamBody{Chunk: []byte(sseEvent(sentence))}
		got := p.OnResponseBodyChunk(ctx, respCtx, chunk, nil)
		if fwd, ok := got.(policy.ForwardResponseChunk); ok && fwd.Body != nil {
			t.Fatalf("sentence %q: expected passthrough (Body=nil), got %q", sentence, fwd.Body)
		}
	}

	// Third sentence pushes count to 3, exceeding max=2 — must emit error with TerminateStream.
	chunk := &policy.StreamBody{Chunk: []byte(sseEvent(" Bye."))}
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
	if !strings.Contains(string(term.Body), "SENTENCE_COUNT_GUARDRAIL") {
		t.Fatalf("expected SENTENCE_COUNT_GUARDRAIL in error body, got: %s", term.Body)
	}
	// Parse the SSE event and verify guardrail action fields.
	msg := mustMessageMap(t, []byte(strings.TrimPrefix(strings.TrimSuffix(string(term.Body), "\n\n"), "data: ")))
	if msg["action"] != "GUARDRAIL_INTERVENED" {
		t.Fatalf("expected action=GUARDRAIL_INTERVENED, got %#v", msg["action"])
	}
	if msg["interveningGuardrail"] != "sentence-count-guardrail" {
		t.Fatalf("expected interveningGuardrail=sentence-count-guardrail, got %#v", msg["interveningGuardrail"])
	}
}

// TestSentenceCountGuardrail_InterventionDeclaresFault covers the one funnel every rejection this policy
// makes passes through, in both phases.
func TestSentenceCountGuardrail_InterventionDeclaresFault(t *testing.T) {
	p := &SentenceCountGuardrailPolicy{}

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

// TestSentenceCountGuardrail_AssessmentsGatedByShowAssessment covers the one field that must not leak:
// Assessments frequently holds the very content the guardrail existed to stop, so it is
// populated only where the operator opted in through showAssessment.
func TestSentenceCountGuardrail_AssessmentsGatedByShowAssessment(t *testing.T) {
	p := &SentenceCountGuardrailPolicy{}

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

// TestSentenceCountGuardrail_ExtractionFailureDeclaresFault pins the JSONPath extraction failure: no check
// ran, so it is not a guardrail verdict. An unreadable request body is the caller's; an
// unreadable response body leaves the policy unable to do its job. The client response is
// the one the policy returned before the fault was declared.
func TestSentenceCountGuardrail_ExtractionFailureDeclaresFault(t *testing.T) {
	p := &SentenceCountGuardrailPolicy{}
	params := SentenceCountGuardrailPolicyParams{JsonPath: "$.text", Min: 1, Max: 10}
	for _, isResponse := range []bool{false, true} {
		got := p.validatePayload([]byte(`not-json`), params, isResponse)
		if isResponse {
			assertNoVerdictFault(t, got, `{"message":{"action":"GUARDRAIL_INTERVENED","actionReason":"Error extracting value from JSONPath","direction":"RESPONSE","interveningGuardrail":"sentence-count-guardrail"},"type":"SENTENCE_COUNT_GUARDRAIL"}`, policy.FaultCodeMediationFailed, policy.FaultTypeMediation, policy.DirectionResponse)
		} else {
			assertNoVerdictFault(t, got, `{"message":{"action":"GUARDRAIL_INTERVENED","actionReason":"Error extracting value from JSONPath","direction":"REQUEST","interveningGuardrail":"sentence-count-guardrail"},"type":"SENTENCE_COUNT_GUARDRAIL"}`, policy.FaultCodeInvalidRequestBody, policy.FaultTypeValidation, policy.DirectionRequest)
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
