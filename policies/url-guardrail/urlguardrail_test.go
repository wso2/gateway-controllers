package urlguardrail

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
				Enabled:           RequestFlowEnabledByDefault,
				JsonPath:          DefaultRequestJSONPath,
				StreamingJsonPath: DefaultStreamingJsonPath,
				Timeout:           DefaultTimeout,
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
				Enabled:           RequestFlowEnabledByDefault,
				JsonPath:          "$.data.text",
				StreamingJsonPath: DefaultStreamingJsonPath,
				OnlyDNS:           true,
				Timeout:           2500,
				ShowAssessment:    true,
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
	if _, ok := pass.(policy.DownstreamResponseModifications); !ok {
		t.Fatalf("expected UpstreamResponseModifications on no-url payload, got %T", pass)
	}

	fail := p.validatePayload([]byte(`{"text":"http://127.0.0.1:1"}`), URLGuardrailPolicyParams{JsonPath: "$.text", Timeout: 200, ShowAssessment: false}, true)
	resp, ok := fail.(policy.DownstreamResponseModifications)
	if !ok {
		t.Fatalf("expected UpstreamResponseModifications on invalid response URL payload, got %T", fail)
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

func TestOnRequestBodyAndOnResponseBody(t *testing.T) {
	// No params configured -> no-op.
	p := &URLGuardrailPolicy{hasRequestParams: false, hasResponseParams: false}
	reqNoOp := p.OnRequestBody(context.Background(), &policy.RequestContext{}, nil)
	if _, ok := reqNoOp.(policy.UpstreamRequestModifications); !ok {
		t.Fatalf("expected request no-op modifications, got %T", reqNoOp)
	}
	respNoOp := p.OnResponseBody(context.Background(), &policy.ResponseContext{}, nil)
	if _, ok := respNoOp.(policy.DownstreamResponseModifications); !ok {
		t.Fatalf("expected response no-op modifications, got %T", respNoOp)
	}

	// Request validation with nil body and explicit jsonPath should fail extraction.
	p.hasRequestParams = true
	p.requestParams = URLGuardrailPolicyParams{Enabled: true, JsonPath: "$.text", Timeout: 100}
	reqFail := p.OnRequestBody(context.Background(), &policy.RequestContext{Body: nil}, nil)
	if _, ok := reqFail.(policy.ImmediateResponse); !ok {
		t.Fatalf("expected ImmediateResponse for request nil-body extraction failure, got %T", reqFail)
	}

	// Response validation with nil body and explicit jsonPath should fail extraction.
	p.hasResponseParams = true
	p.responseParams = URLGuardrailPolicyParams{Enabled: true, JsonPath: "$.text", Timeout: 100}
	respFail := p.OnResponseBody(context.Background(), &policy.ResponseContext{ResponseBody: nil}, nil)
	respMod, ok := respFail.(policy.DownstreamResponseModifications)
	if !ok {
		t.Fatalf("expected UpstreamResponseModifications for response nil-body extraction failure, got %T", respFail)
	}
	if respMod.StatusCode == nil || *respMod.StatusCode != GuardrailErrorCode {
		t.Fatalf("expected status code %d, got %#v", GuardrailErrorCode, respMod.StatusCode)
	}

	p.requestParams.Enabled = false
	reqDisabled := p.OnRequestBody(context.Background(), &policy.RequestContext{Body: &policy.Body{Content: []byte(`{"text":"https://example.com"}`)}}, nil)
	if _, ok := reqDisabled.(policy.UpstreamRequestModifications); !ok {
		t.Fatalf("expected request no-op when request.enabled=false, got %T", reqDisabled)
	}

	p.responseParams.Enabled = false
	respDisabled := p.OnResponseBody(context.Background(), &policy.ResponseContext{ResponseBody: &policy.Body{Content: []byte(`{"text":"https://example.com"}`)}}, nil)
	if _, ok := respDisabled.(policy.DownstreamResponseModifications); !ok {
		t.Fatalf("expected response no-op when response.enabled=false, got %T", respDisabled)
	}
}

// ─── OnResponseBodyChunk non-SSE (plain JSON chunked transfer) tests ─────────

// TestOnResponseBodyChunk_NonSSE_InvalidURL_ReturnsError verifies that the
// non-SSE path correctly detects and blocks invalid URLs when JSONPath extraction
// succeeds and the extracted text contains an unreachable URL.
func TestOnResponseBodyChunk_NonSSE_InvalidURL_ReturnsError(t *testing.T) {
	p := newStreamingURLPolicy(200)
	ctx := context.Background()
	respCtx := newStreamingRespCtx()

	body := []byte(`{"choices":[{"message":{"content":"visit http://127.0.0.1:1 for info"}}]}`)
	chunk := &policy.StreamBody{Chunk: body, EndOfStream: true}
	got := p.OnResponseBodyChunk(ctx, respCtx, chunk, nil)

	term, ok := got.(policy.TerminateResponseChunk)
	if !ok {
		t.Fatalf("expected TerminateResponseChunk for invalid URL in non-SSE chunk, got %T", got)
	}
	if term.Body == nil {
		t.Fatal("expected error body for invalid URL in non-SSE chunk, got nil")
	}
	if !strings.Contains(string(term.Body), "URL_GUARDRAIL") {
		t.Fatalf("expected URL_GUARDRAIL in error body, got: %s", term.Body)
	}
}

// ─── OnResponseBodyChunk stream-stop tests ───────────────────────────────────

func sseContentChunk(content string) []byte {
	quoted, _ := json.Marshal(content)
	return []byte(`data: {"id":"chatcmpl-test","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"content":` + string(quoted) + `},"finish_reason":null}]}` + "\n\n")
}

func newStreamingRespCtx() *policy.ResponseStreamContext {
	return &policy.ResponseStreamContext{SharedContext: &policy.SharedContext{}}
}

func newStreamingURLPolicy(timeout int) *URLGuardrailPolicy {
	return &URLGuardrailPolicy{
		hasResponseParams: true,
		responseParams: URLGuardrailPolicyParams{
			Enabled:           true,
			StreamingJsonPath: DefaultStreamingJsonPath,
			Timeout:           timeout,
		},
	}
}

// TestOnResponseBodyChunk_InvalidURL_EmitsErrorAndTerminates verifies that when
// a chunk contains an invalid URL, OnResponseBodyChunk returns an SSE error
// event with TerminateStream set so the engine closes the stream cleanly.
func TestOnResponseBodyChunk_InvalidURL_EmitsErrorAndTerminates(t *testing.T) {
	p := newStreamingURLPolicy(200)
	ctx := context.Background()
	respCtx := newStreamingRespCtx()

	// Chunk with no URL passes through unmodified.
	plain := &policy.StreamBody{Chunk: sseContentChunk("no urls here")}
	got := p.OnResponseBodyChunk(ctx, respCtx, plain, nil)
	if fwd, ok := got.(policy.ForwardResponseChunk); ok && fwd.Body != nil {
		t.Fatalf("expected passthrough for chunk with no URL, got %q", fwd.Body)
	}

	// Chunk containing an unreachable URL triggers the guardrail.
	invalid := &policy.StreamBody{Chunk: sseContentChunk("visit http://127.0.0.1:1 for info")}
	got = p.OnResponseBodyChunk(ctx, respCtx, invalid, nil)

	term, ok := got.(policy.TerminateResponseChunk)
	if !ok {
		t.Fatalf("expected TerminateResponseChunk on invalid URL violation, got %T", got)
	}
	if term.Body == nil {
		t.Fatal("expected error body on invalid URL, got nil")
	}
	if !got.TerminateStream() {
		t.Fatal("expected TerminateStream=true on invalid URL violation")
	}
	if !strings.Contains(string(term.Body), "URL_GUARDRAIL") {
		t.Fatalf("expected URL_GUARDRAIL in error body, got: %s", term.Body)
	}
	// Parse the SSE event and verify guardrail action fields.
	msg := mustMessageMap(t, []byte(strings.TrimPrefix(strings.TrimSuffix(string(term.Body), "\n\n"), "data: ")))
	if msg["action"] != "GUARDRAIL_INTERVENED" {
		t.Fatalf("expected action=GUARDRAIL_INTERVENED, got %#v", msg["action"])
	}
	if msg["interveningGuardrail"] != "url-guardrail" {
		t.Fatalf("expected interveningGuardrail=url-guardrail, got %#v", msg["interveningGuardrail"])
	}
}

// TestURLGuardrail_InterventionDeclaresFault covers the one funnel every rejection this policy
// makes passes through, in both phases.
func TestURLGuardrail_InterventionDeclaresFault(t *testing.T) {
	p := &URLGuardrailPolicy{}

	t.Run("request phase", func(t *testing.T) {
		action := p.buildErrorResponse("blocked detail", nil, false, false, []string{"http://invalid.example"})
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
		action := p.buildErrorResponse("blocked detail", nil, true, false, []string{"http://invalid.example"})
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

// TestURLGuardrail_AssessmentsGatedByShowAssessment covers the one field that must not leak:
// Assessments frequently holds the very content the guardrail existed to stop, so it is
// populated only where the operator opted in through showAssessment.
func TestURLGuardrail_AssessmentsGatedByShowAssessment(t *testing.T) {
	p := &URLGuardrailPolicy{}

	for _, show := range []bool{false, true} {
		name := "showAssessment=false"
		if show {
			name = "showAssessment=true"
		}
		t.Run(name, func(t *testing.T) {
			action := p.buildErrorResponse("blocked detail", nil, false, show, []string{"http://invalid.example"})
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

// TestURLGuardrail_ExtractionFailureDeclaresFault pins the JSONPath extraction failure: no check
// ran, so it is not a guardrail verdict. An unreadable request body is the caller's; an
// unreadable response body leaves the policy unable to do its job. The client response is
// the one the policy returned before the fault was declared.
func TestURLGuardrail_ExtractionFailureDeclaresFault(t *testing.T) {
	p := &URLGuardrailPolicy{}
	params := URLGuardrailPolicyParams{JsonPath: "$.text"}
	for _, isResponse := range []bool{false, true} {
		got := p.validatePayload([]byte(`not-json`), params, isResponse)
		if isResponse {
			assertNoVerdictFault(t, got, `{"message":{"action":"GUARDRAIL_INTERVENED","actionReason":"Error extracting value from JSONPath","direction":"RESPONSE","interveningGuardrail":"url-guardrail"},"type":"URL_GUARDRAIL"}`, policy.FaultCodeMediationFailed, policy.FaultTypeMediation, policy.DirectionResponse)
		} else {
			assertNoVerdictFault(t, got, `{"message":{"action":"GUARDRAIL_INTERVENED","actionReason":"Error extracting value from JSONPath","direction":"REQUEST","interveningGuardrail":"url-guardrail"},"type":"URL_GUARDRAIL"}`, policy.FaultCodeInvalidRequestBody, policy.FaultTypeValidation, policy.DirectionRequest)
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
