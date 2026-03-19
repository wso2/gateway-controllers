package urlguardrail

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	policy "github.com/wso2/api-platform/sdk/gateway/policy/v1alpha"
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
		{"string integer", "13", 0, true},
		{"string float integer", "14.0", 0, true},
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
		expected    URLGuardrailPolicyParams
	}{
		{
			name:  "valid defaults",
			input: map[string]interface{}{},
			expected: URLGuardrailPolicyParams{
				Enabled:  RequestFlowEnabledByDefault,
				JsonPath: DefaultRequestJSONPath,
				Timeout:  DefaultTimeout,
			},
		},
		{
			name: "valid with all fields",
			input: map[string]interface{}{
				"jsonPath":       "$.data.text",
				"onlyDNS":        true,
				"timeout":        float64(2500),
				"showAssessment": true,
			},
			expected: URLGuardrailPolicyParams{
				Enabled:        RequestFlowEnabledByDefault,
				JsonPath:       "$.data.text",
				OnlyDNS:        true,
				Timeout:        2500,
				ShowAssessment: true,
			},
		},
		{
			name:        "invalid enabled type",
			input:       map[string]interface{}{"enabled": "true"},
			expectErr:   true,
			errContains: "'enabled' must be a boolean",
		},
		{
			name:        "invalid jsonPath type",
			input:       map[string]interface{}{"jsonPath": 123},
			expectErr:   true,
			errContains: "'jsonPath' must be a string",
		},
		{
			name:        "invalid onlyDNS type",
			input:       map[string]interface{}{"onlyDNS": "true"},
			expectErr:   true,
			errContains: "'onlyDNS' must be a boolean",
		},
		{
			name:        "invalid timeout type",
			input:       map[string]interface{}{"timeout": "3000"},
			expectErr:   true,
			errContains: "'timeout' must be a number",
		},
		{
			name:        "negative timeout",
			input:       map[string]interface{}{"timeout": -1},
			expectErr:   true,
			errContains: "'timeout' cannot be negative",
		},
		{
			name:        "invalid showAssessment type",
			input:       map[string]interface{}{"showAssessment": "false"},
			expectErr:   true,
			errContains: "'showAssessment' must be a boolean",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseParams(tc.input, DefaultRequestJSONPath, RequestFlowEnabledByDefault)
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
}

func TestGetPolicy(t *testing.T) {
	tests := []struct {
		name        string
		params      map[string]interface{}
		expectErr   bool
		errContains string
		check       func(t *testing.T, p *URLGuardrailPolicy)
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
				"request": map[string]interface{}{"timeout": -1},
			},
			expectErr:   true,
			errContains: "invalid request parameters",
		},
		{
			name: "invalid response params",
			params: map[string]interface{}{
				"response": map[string]interface{}{"timeout": -1},
			},
			expectErr:   true,
			errContains: "invalid response parameters",
		},
		{
			name: "request only",
			params: map[string]interface{}{
				"request": map[string]interface{}{"timeout": 1000},
			},
			check: func(t *testing.T, p *URLGuardrailPolicy) {
				if !p.hasRequestParams || p.hasResponseParams {
					t.Fatalf("expected request=true response=false, got request=%v response=%v", p.hasRequestParams, p.hasResponseParams)
				}
				if p.requestParams.Timeout != 1000 {
					t.Fatalf("unexpected request timeout: %d", p.requestParams.Timeout)
				}
				if p.requestParams.JsonPath != DefaultRequestJSONPath {
					t.Fatalf("unexpected request jsonPath: %s", p.requestParams.JsonPath)
				}
				if p.requestParams.Enabled {
					t.Fatalf("expected request disabled by default")
				}
			},
		},
		{
			name: "response only",
			params: map[string]interface{}{
				"response": map[string]interface{}{"timeout": 1200},
			},
			check: func(t *testing.T, p *URLGuardrailPolicy) {
				if p.hasRequestParams || !p.hasResponseParams {
					t.Fatalf("expected request=false response=true, got request=%v response=%v", p.hasRequestParams, p.hasResponseParams)
				}
				if p.responseParams.Timeout != 1200 {
					t.Fatalf("unexpected response timeout: %d", p.responseParams.Timeout)
				}
				if p.responseParams.JsonPath != DefaultResponseJSONPath {
					t.Fatalf("unexpected response jsonPath: %s", p.responseParams.JsonPath)
				}
				if !p.responseParams.Enabled {
					t.Fatalf("expected response enabled by default")
				}
			},
		},
		{
			name: "both request and response",
			params: map[string]interface{}{
				"request":  map[string]interface{}{"timeout": 1000},
				"response": map[string]interface{}{"timeout": 2000},
			},
			check: func(t *testing.T, p *URLGuardrailPolicy) {
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

			p, ok := pRaw.(*URLGuardrailPolicy)
			if !ok {
				t.Fatalf("expected *URLGuardrailPolicy, got %T", pRaw)
			}

			if tc.check != nil {
				tc.check(t, p)
			}
		})
	}
}

func TestMode(t *testing.T) {
	p := &URLGuardrailPolicy{}
	mode := p.Mode()

	if mode.RequestHeaderMode != policy.HeaderModeSkip {
		t.Fatalf("expected RequestHeaderMode=Skip, got %v", mode.RequestHeaderMode)
	}
	if mode.RequestBodyMode != policy.BodyModeBuffer {
		t.Fatalf("expected RequestBodyMode=Buffer, got %v", mode.RequestBodyMode)
	}
	if mode.ResponseHeaderMode != policy.HeaderModeSkip {
		t.Fatalf("expected ResponseHeaderMode=Skip, got %v", mode.ResponseHeaderMode)
	}
	if mode.ResponseBodyMode != policy.BodyModeBuffer {
		t.Fatalf("expected ResponseBodyMode=Buffer, got %v", mode.ResponseBodyMode)
	}
}

func TestCheckDNS(t *testing.T) {
	p := &URLGuardrailPolicy{}
	if !p.checkDNS("http://127.0.0.1", 100) {
		t.Fatalf("expected DNS validation to pass for 127.0.0.1")
	}
	if p.checkDNS("not-a-url", 100) {
		t.Fatalf("expected DNS validation to fail for malformed URL")
	}
}

func TestCheckURL(t *testing.T) {
	okServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer okServer.Close()

	badServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer badServer.Close()

	p := &URLGuardrailPolicy{}
	if !p.checkURL(okServer.URL, 1000) {
		t.Fatalf("expected checkURL to pass for healthy server")
	}
	if p.checkURL(badServer.URL, 1000) {
		t.Fatalf("expected checkURL to fail for 500 response")
	}
	if p.checkURL("http://127.0.0.1:1", 200) {
		t.Fatalf("expected checkURL to fail for unreachable endpoint")
	}
}

func TestValidatePayload_RequestPaths(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	p := &URLGuardrailPolicy{}

	pass := p.validatePayload([]byte(`{"text":"`+server.URL+`"}`), URLGuardrailPolicyParams{JsonPath: "$.text", Timeout: 1000}, false)
	if _, ok := pass.(policy.UpstreamRequestModifications); !ok {
		t.Fatalf("expected UpstreamRequestModifications on valid URL payload, got %T", pass)
	}

	fail := p.validatePayload([]byte(`{"text":"http://127.0.0.1:1"}`), URLGuardrailPolicyParams{JsonPath: "$.text", Timeout: 200, ShowAssessment: true}, false)
	imm, ok := fail.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("expected ImmediateResponse on invalid URL payload, got %T", fail)
	}
	if imm.StatusCode != GuardrailErrorCode {
		t.Fatalf("expected status %d, got %d", GuardrailErrorCode, imm.StatusCode)
	}
	msg := mustMessageMap(t, imm.Body)
	if msg["direction"] != "REQUEST" {
		t.Fatalf("expected REQUEST direction, got %#v", msg["direction"])
	}
	if msg["interveningGuardrail"] != "url-guardrail" {
		t.Fatalf("unexpected interveningGuardrail: %#v", msg["interveningGuardrail"])
	}
	assessments, ok := msg["assessments"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected detailed assessments object, got %#v", msg["assessments"])
	}
	invalidList, ok := assessments["invalidUrls"].([]interface{})
	if !ok || len(invalidList) != 1 {
		t.Fatalf("expected one invalid URL in assessments, got %#v", assessments["invalidUrls"])
	}
}

func TestValidatePayload_ResponsePaths(t *testing.T) {
	p := &URLGuardrailPolicy{}

	pass := p.validatePayload([]byte(`{"text":"no urls here"}`), URLGuardrailPolicyParams{JsonPath: "$.text", Timeout: 100}, true)
	if _, ok := pass.(policy.UpstreamResponseModifications); !ok {
		t.Fatalf("expected UpstreamResponseModifications on no-url payload, got %T", pass)
	}

	fail := p.validatePayload([]byte(`{"text":"http://127.0.0.1:1"}`), URLGuardrailPolicyParams{JsonPath: "$.text", Timeout: 200, ShowAssessment: false}, true)
	resp, ok := fail.(policy.UpstreamResponseModifications)
	if !ok {
		t.Fatalf("expected UpstreamResponseModifications on invalid response URL payload, got %T", fail)
	}
	if resp.StatusCode == nil || *resp.StatusCode != GuardrailErrorCode {
		t.Fatalf("expected response status %d, got %#v", GuardrailErrorCode, resp.StatusCode)
	}
	if resp.SetHeaders["Content-Type"] != "application/json" {
		t.Fatalf("expected response content-type header, got %#v", resp.SetHeaders)
	}
	msg := mustMessageMap(t, resp.Body)
	if msg["direction"] != "RESPONSE" {
		t.Fatalf("expected RESPONSE direction, got %#v", msg["direction"])
	}
	if _, ok := msg["assessments"]; ok {
		t.Fatalf("did not expect assessments when showAssessment is false")
	}
}

func TestValidatePayload_OnlyDNSMode(t *testing.T) {
	p := &URLGuardrailPolicy{}

	pass := p.validatePayload([]byte(`{"text":"http://127.0.0.1"}`), URLGuardrailPolicyParams{JsonPath: "$.text", OnlyDNS: true, Timeout: 200}, false)
	if _, ok := pass.(policy.UpstreamRequestModifications); !ok {
		t.Fatalf("expected UpstreamRequestModifications for valid DNS-only check, got %T", pass)
	}
}

func TestValidatePayload_JSONPathExtractionFailure(t *testing.T) {
	p := &URLGuardrailPolicy{}
	fail := p.validatePayload([]byte(`{"text":"hello"}`), URLGuardrailPolicyParams{JsonPath: "$.missing", Timeout: 100, ShowAssessment: true}, false)
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
	p := &URLGuardrailPolicy{}

	normal := p.buildAssessmentObject("Violation of url validity detected", nil, false, true, []string{"http://bad.local"})
	if normal["actionReason"] != "Violation of url validity detected." {
		t.Fatalf("unexpected actionReason: %#v", normal["actionReason"])
	}
	assessments, ok := normal["assessments"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected assessments object, got %#v", normal["assessments"])
	}
	invalid, ok := assessments["invalidUrls"].([]string)
	if !ok || len(invalid) != 1 || invalid[0] != "http://bad.local" {
		t.Fatalf("unexpected invalidUrls content: %#v", assessments["invalidUrls"])
	}

	withErr := p.buildAssessmentObject("Error extracting value from JSONPath", json.Unmarshal([]byte("{"), &map[string]interface{}{}), false, true, nil)
	if withErr["actionReason"] != "Error extracting value from JSONPath" {
		t.Fatalf("unexpected actionReason with error: %#v", withErr["actionReason"])
	}
	if _, ok := withErr["assessments"].(string); !ok {
		t.Fatalf("expected error assessments string, got %#v", withErr["assessments"])
	}
}

func TestOnRequestAndOnResponse(t *testing.T) {
	// No params configured -> no-op.
	p := &URLGuardrailPolicy{hasRequestParams: false, hasResponseParams: false}
	reqNoOp := p.OnRequest(&policy.RequestContext{}, nil)
	if _, ok := reqNoOp.(policy.UpstreamRequestModifications); !ok {
		t.Fatalf("expected request no-op modifications, got %T", reqNoOp)
	}
	respNoOp := p.OnResponse(&policy.ResponseContext{}, nil)
	if _, ok := respNoOp.(policy.UpstreamResponseModifications); !ok {
		t.Fatalf("expected response no-op modifications, got %T", respNoOp)
	}

	// Request validation with nil body and explicit jsonPath should fail extraction.
	p.hasRequestParams = true
	p.requestParams = URLGuardrailPolicyParams{Enabled: true, JsonPath: "$.text", Timeout: 100}
	reqFail := p.OnRequest(&policy.RequestContext{Body: nil}, nil)
	if _, ok := reqFail.(policy.ImmediateResponse); !ok {
		t.Fatalf("expected ImmediateResponse for request nil-body extraction failure, got %T", reqFail)
	}

	// Response validation with nil body and explicit jsonPath should fail extraction.
	p.hasResponseParams = true
	p.responseParams = URLGuardrailPolicyParams{Enabled: true, JsonPath: "$.text", Timeout: 100}
	respFail := p.OnResponse(&policy.ResponseContext{ResponseBody: nil}, nil)
	respMod, ok := respFail.(policy.UpstreamResponseModifications)
	if !ok {
		t.Fatalf("expected UpstreamResponseModifications for response nil-body extraction failure, got %T", respFail)
	}
	if respMod.StatusCode == nil || *respMod.StatusCode != GuardrailErrorCode {
		t.Fatalf("expected status code %d, got %#v", GuardrailErrorCode, respMod.StatusCode)
	}

	p.requestParams.Enabled = false
	reqDisabled := p.OnRequest(&policy.RequestContext{Body: &policy.Body{Content: []byte(`{"text":"https://example.com"}`)}}, nil)
	if _, ok := reqDisabled.(policy.UpstreamRequestModifications); !ok {
		t.Fatalf("expected request no-op when request.enabled=false, got %T", reqDisabled)
	}

	p.responseParams.Enabled = false
	respDisabled := p.OnResponse(&policy.ResponseContext{ResponseBody: &policy.Body{Content: []byte(`{"text":"https://example.com"}`)}}, nil)
	if _, ok := respDisabled.(policy.UpstreamResponseModifications); !ok {
		t.Fatalf("expected response no-op when response.enabled=false, got %T", respDisabled)
	}
}
