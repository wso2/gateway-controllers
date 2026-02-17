package regexguardrail

import (
	"encoding/json"
	"strings"
	"testing"

	policy "github.com/wso2/api-platform/sdk/gateway/policy/v1alpha"
)

func TestRegexGuardrailPolicy_Mode(t *testing.T) {
	p := &RegexGuardrailPolicy{}

	got := p.Mode()
	want := policy.ProcessingMode{
		RequestHeaderMode:  policy.HeaderModeSkip,
		RequestBodyMode:    policy.BodyModeBuffer,
		ResponseHeaderMode: policy.HeaderModeSkip,
		ResponseBodyMode:   policy.BodyModeBuffer,
	}
	if got != want {
		t.Fatalf("unexpected mode: got %+v, want %+v", got, want)
	}
}

func TestRegexGuardrailPolicy_GetPolicy_Defaults_RequestOnly(t *testing.T) {
	p := mustGetRegexPolicy(t, map[string]interface{}{
		"request": map[string]interface{}{
			"regex": "hello",
		},
	})

	if !p.hasRequestParams {
		t.Fatalf("expected request params to be enabled")
	}
	if p.hasResponseParams {
		t.Fatalf("expected response params to be disabled")
	}
	if got := p.requestParams.JsonPath; got != DefaultJSONPath {
		t.Fatalf("unexpected default jsonPath: got %q, want %q", got, DefaultJSONPath)
	}
	if p.requestParams.Invert {
		t.Fatalf("expected default invert=false")
	}
	if p.requestParams.ShowAssessment {
		t.Fatalf("expected default showAssessment=false")
	}
}

func TestRegexGuardrailPolicy_GetPolicy_Defaults_ResponseOnly(t *testing.T) {
	p := mustGetRegexPolicy(t, map[string]interface{}{
		"response": map[string]interface{}{
			"regex": "hello",
		},
	})

	if p.hasRequestParams {
		t.Fatalf("expected request params to be disabled")
	}
	if !p.hasResponseParams {
		t.Fatalf("expected response params to be enabled")
	}
	if got := p.responseParams.JsonPath; got != DefaultJSONPath {
		t.Fatalf("unexpected default jsonPath: got %q, want %q", got, DefaultJSONPath)
	}
	if p.responseParams.Invert {
		t.Fatalf("expected default invert=false")
	}
	if p.responseParams.ShowAssessment {
		t.Fatalf("expected default showAssessment=false")
	}
}

func TestRegexGuardrailPolicy_GetPolicy_RequestAndResponse(t *testing.T) {
	p := mustGetRegexPolicy(t, map[string]interface{}{
		"request": map[string]interface{}{
			"regex":          "hello",
			"jsonPath":       "$.messages",
			"invert":         true,
			"showAssessment": true,
		},
		"response": map[string]interface{}{
			"regex":          "world",
			"jsonPath":       "$.output",
			"invert":         false,
			"showAssessment": true,
		},
	})

	if !p.hasRequestParams || !p.hasResponseParams {
		t.Fatalf("expected both request and response params enabled")
	}
	if p.requestParams.Regex != "hello" || p.responseParams.Regex != "world" {
		t.Fatalf("unexpected regex values: req=%q resp=%q", p.requestParams.Regex, p.responseParams.Regex)
	}
	if p.requestParams.JsonPath != "$.messages" || p.responseParams.JsonPath != "$.output" {
		t.Fatalf("unexpected jsonPath values: req=%q resp=%q", p.requestParams.JsonPath, p.responseParams.JsonPath)
	}
	if !p.requestParams.Invert || p.responseParams.Invert {
		t.Fatalf("unexpected invert values: req=%v resp=%v", p.requestParams.Invert, p.responseParams.Invert)
	}
	if !p.requestParams.ShowAssessment || !p.responseParams.ShowAssessment {
		t.Fatalf("expected showAssessment=true for both")
	}
}

func TestRegexGuardrailPolicy_GetPolicy_Errors(t *testing.T) {
	tests := []struct {
		name           string
		params         map[string]interface{}
		wantErrContain string
	}{
		{
			name: "neither request nor response",
			params: map[string]interface{}{
				"foo": "bar",
			},
			wantErrContain: "at least one of 'request' or 'response' parameters must be provided",
		},
		{
			name: "request regex missing",
			params: map[string]interface{}{
				"request": map[string]interface{}{},
			},
			wantErrContain: "invalid request parameters: 'regex' parameter is required",
		},
		{
			name: "response regex wrong type",
			params: map[string]interface{}{
				"response": map[string]interface{}{
					"regex": 123,
				},
			},
			wantErrContain: "invalid response parameters: 'regex' must be a string",
		},
		{
			name: "regex empty",
			params: map[string]interface{}{
				"request": map[string]interface{}{
					"regex": "",
				},
			},
			wantErrContain: "invalid request parameters: 'regex' cannot be empty",
		},
		{
			name: "regex invalid pattern",
			params: map[string]interface{}{
				"request": map[string]interface{}{
					"regex": "[abc",
				},
			},
			wantErrContain: "invalid request parameters: invalid regex pattern",
		},
		{
			name: "jsonPath wrong type",
			params: map[string]interface{}{
				"request": map[string]interface{}{
					"regex":    "hello",
					"jsonPath": true,
				},
			},
			wantErrContain: "invalid request parameters: 'jsonPath' must be a string",
		},
		{
			name: "invert wrong type",
			params: map[string]interface{}{
				"request": map[string]interface{}{
					"regex":  "hello",
					"invert": "true",
				},
			},
			wantErrContain: "invalid request parameters: 'invert' must be a boolean",
		},
		{
			name: "showAssessment wrong type",
			params: map[string]interface{}{
				"request": map[string]interface{}{
					"regex":          "hello",
					"showAssessment": "true",
				},
			},
			wantErrContain: "invalid request parameters: 'showAssessment' must be a boolean",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := GetPolicy(policy.PolicyMetadata{}, tt.params)
			if err == nil {
				t.Fatalf("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tt.wantErrContain) {
				t.Fatalf("error mismatch: got %q, want contain %q", err.Error(), tt.wantErrContain)
			}
		})
	}
}

func TestRegexGuardrailPolicy_OnRequest_NoRequestConfig_NoOp(t *testing.T) {
	p := mustGetRegexPolicy(t, map[string]interface{}{
		"response": map[string]interface{}{
			"regex": "hello",
		},
	})

	action := p.OnRequest(newRequestContextWithBody(`{"message":"hello"}`), nil)
	if _, ok := action.(policy.UpstreamRequestModifications); !ok {
		t.Fatalf("expected UpstreamRequestModifications, got %T", action)
	}
}

func TestRegexGuardrailPolicy_OnResponse_NoResponseConfig_NoOp(t *testing.T) {
	p := mustGetRegexPolicy(t, map[string]interface{}{
		"request": map[string]interface{}{
			"regex": "hello",
		},
	})

	action := p.OnResponse(newResponseContextWithBody(`{"message":"hello"}`), nil)
	if _, ok := action.(policy.UpstreamResponseModifications); !ok {
		t.Fatalf("expected UpstreamResponseModifications, got %T", action)
	}
}

func TestRegexGuardrailPolicy_OnRequest_EmptyBody_NoOp(t *testing.T) {
	p := mustGetRegexPolicy(t, map[string]interface{}{
		"request": map[string]interface{}{
			"regex": "hello",
		},
	})

	ctx := &policy.RequestContext{
		SharedContext: &policy.SharedContext{
			RequestID: "test-id",
			Metadata:  map[string]interface{}{},
		},
		Body: &policy.Body{
			Content: []byte{},
			Present: false,
		},
	}
	action := p.OnRequest(ctx, nil)
	if _, ok := action.(policy.UpstreamRequestModifications); !ok {
		t.Fatalf("expected UpstreamRequestModifications, got %T", action)
	}
}

func TestRegexGuardrailPolicy_OnResponse_EmptyBody_NoOp(t *testing.T) {
	p := mustGetRegexPolicy(t, map[string]interface{}{
		"response": map[string]interface{}{
			"regex": "hello",
		},
	})

	ctx := &policy.ResponseContext{
		SharedContext: &policy.SharedContext{
			RequestID: "test-id",
			Metadata:  map[string]interface{}{},
		},
		ResponseBody: &policy.Body{
			Content: []byte{},
			Present: false,
		},
	}
	action := p.OnResponse(ctx, nil)
	if _, ok := action.(policy.UpstreamResponseModifications); !ok {
		t.Fatalf("expected UpstreamResponseModifications, got %T", action)
	}
}

func TestRegexGuardrailPolicy_OnRequest_DefaultJSONPath_Success(t *testing.T) {
	p := mustGetRegexPolicy(t, map[string]interface{}{
		"request": map[string]interface{}{
			"regex": "hello",
		},
	})

	action := p.OnRequest(newRequestContextWithBody(`{"messages":"hello world"}`), nil)
	if _, ok := action.(policy.UpstreamRequestModifications); !ok {
		t.Fatalf("expected UpstreamRequestModifications, got %T", action)
	}
}

func TestRegexGuardrailPolicy_OnRequest_CustomJSONPath_Success(t *testing.T) {
	p := mustGetRegexPolicy(t, map[string]interface{}{
		"request": map[string]interface{}{
			"regex":    "secret",
			"jsonPath": "$.messages[0].content",
		},
	})

	action := p.OnRequest(newRequestContextWithBody(`{"messages":[{"content":"my secret token"}]}`), nil)
	if _, ok := action.(policy.UpstreamRequestModifications); !ok {
		t.Fatalf("expected UpstreamRequestModifications, got %T", action)
	}
}

func TestRegexGuardrailPolicy_OnRequest_EmptyJSONPath_UsesWholePayload(t *testing.T) {
	p := mustGetRegexPolicy(t, map[string]interface{}{
		"request": map[string]interface{}{
			"regex":    "sam",
			"jsonPath": "",
		},
	})

	action := p.OnRequest(newRequestContextWithBody(`{"name":"sam"}`), nil)
	if _, ok := action.(policy.UpstreamRequestModifications); !ok {
		t.Fatalf("expected UpstreamRequestModifications, got %T", action)
	}
}

func TestRegexGuardrailPolicy_OnRequest_InvertBehavior(t *testing.T) {
	passPolicy := mustGetRegexPolicy(t, map[string]interface{}{
		"request": map[string]interface{}{
			"regex":    "forbidden",
			"jsonPath": "$.messages",
			"invert":   true,
		},
	})
	passAction := passPolicy.OnRequest(newRequestContextWithBody(`{"messages":"allowed content"}`), nil)
	if _, ok := passAction.(policy.UpstreamRequestModifications); !ok {
		t.Fatalf("expected pass with invert=true on non-match, got %T", passAction)
	}

	failPolicy := mustGetRegexPolicy(t, map[string]interface{}{
		"request": map[string]interface{}{
			"regex":    "forbidden",
			"jsonPath": "$.messages",
			"invert":   true,
		},
	})
	failAction := failPolicy.OnRequest(newRequestContextWithBody(`{"messages":"contains forbidden term"}`), nil)
	assertRequestErrorResponse(t, failAction, false, "REQUEST")
}

func TestRegexGuardrailPolicy_OnRequest_RegexViolation_ShowAssessmentFalse(t *testing.T) {
	p := mustGetRegexPolicy(t, map[string]interface{}{
		"request": map[string]interface{}{
			"regex":          "abc",
			"jsonPath":       "$.messages",
			"showAssessment": false,
		},
	})

	action := p.OnRequest(newRequestContextWithBody(`{"messages":"does not match"}`), nil)
	body := assertRequestErrorResponse(t, action, false, "REQUEST")

	message := extractMessageAssessment(t, body)
	if _, exists := message["assessments"]; exists {
		t.Fatalf("did not expect assessments when showAssessment=false")
	}
}

func TestRegexGuardrailPolicy_OnRequest_RegexViolation_ShowAssessmentTrue(t *testing.T) {
	p := mustGetRegexPolicy(t, map[string]interface{}{
		"request": map[string]interface{}{
			"regex":          "abc",
			"jsonPath":       "$.messages",
			"showAssessment": true,
		},
	})

	action := p.OnRequest(newRequestContextWithBody(`{"messages":"does not match"}`), nil)
	body := assertRequestErrorResponse(t, action, true, "REQUEST")

	message := extractMessageAssessment(t, body)
	assessments, ok := message["assessments"].(string)
	if !ok || !strings.Contains(assessments, "Violation of regular expression detected") {
		t.Fatalf("expected detailed assessments for violation, got %v", message["assessments"])
	}
}

func TestRegexGuardrailPolicy_OnRequest_ExtractionError_ShowAssessmentTrue(t *testing.T) {
	p := mustGetRegexPolicy(t, map[string]interface{}{
		"request": map[string]interface{}{
			"regex":          "abc",
			"jsonPath":       "$.missing.path",
			"showAssessment": true,
		},
	})

	action := p.OnRequest(newRequestContextWithBody(`{"message":"abc"}`), nil)
	body := assertRequestErrorResponse(t, action, true, "REQUEST")
	message := extractMessageAssessment(t, body)

	assessments, ok := message["assessments"].(string)
	if !ok || !strings.Contains(assessments, "key not found") {
		t.Fatalf("expected extraction error details in assessments, got %v", message["assessments"])
	}
}

func TestRegexGuardrailPolicy_OnRequest_DefaultJSONPath_ArrayPayload_ExtractionError(t *testing.T) {
	p := mustGetRegexPolicy(t, map[string]interface{}{
		"request": map[string]interface{}{
			"regex": "hello",
		},
	})

	// Default jsonPath is $.messages; this payload has messages as an array, which
	// is not extractable as string/number by ExtractStringValueFromJsonpath.
	action := p.OnRequest(newRequestContextWithBody(`{"messages":[{"content":"hello"}]}`), nil)
	assertRequestErrorResponse(t, action, false, "REQUEST")
}

func TestRegexGuardrailPolicy_OnResponse_Success(t *testing.T) {
	p := mustGetRegexPolicy(t, map[string]interface{}{
		"response": map[string]interface{}{
			"regex":    "ok",
			"jsonPath": "$.status",
		},
	})

	action := p.OnResponse(newResponseContextWithBody(`{"status":"ok"}`), nil)
	if _, ok := action.(policy.UpstreamResponseModifications); !ok {
		t.Fatalf("expected UpstreamResponseModifications, got %T", action)
	}
}

func TestRegexGuardrailPolicy_OnResponse_RegexViolation_ShowAssessmentFalse(t *testing.T) {
	p := mustGetRegexPolicy(t, map[string]interface{}{
		"response": map[string]interface{}{
			"regex":          "ok",
			"jsonPath":       "$.status",
			"showAssessment": false,
		},
	})

	action := p.OnResponse(newResponseContextWithBody(`{"status":"failed"}`), nil)
	body := assertResponseErrorResponse(t, action, false, "RESPONSE")
	message := extractMessageAssessment(t, body)
	if _, exists := message["assessments"]; exists {
		t.Fatalf("did not expect assessments when showAssessment=false")
	}
}

func TestRegexGuardrailPolicy_OnResponse_RegexViolation_ShowAssessmentTrue(t *testing.T) {
	p := mustGetRegexPolicy(t, map[string]interface{}{
		"response": map[string]interface{}{
			"regex":          "ok",
			"jsonPath":       "$.status",
			"showAssessment": true,
		},
	})

	action := p.OnResponse(newResponseContextWithBody(`{"status":"failed"}`), nil)
	body := assertResponseErrorResponse(t, action, true, "RESPONSE")
	message := extractMessageAssessment(t, body)
	if _, exists := message["assessments"]; !exists {
		t.Fatalf("expected assessments when showAssessment=true")
	}
}

func TestRegexGuardrailPolicy_BuildAssessmentObject(t *testing.T) {
	p := &RegexGuardrailPolicy{}

	req := p.buildAssessmentObject("reason", nil, false, false)
	if got := req["direction"]; got != "REQUEST" {
		t.Fatalf("unexpected request direction: %v", got)
	}
	if got := req["actionReason"]; got != "Violation of regular expression detected." {
		t.Fatalf("unexpected request actionReason: %v", got)
	}

	respWithErr := p.buildAssessmentObject("Error extracting value from JSONPath", errSentinel("boom"), true, true)
	if got := respWithErr["direction"]; got != "RESPONSE" {
		t.Fatalf("unexpected response direction: %v", got)
	}
	if got := respWithErr["actionReason"]; got != "Error extracting value from JSONPath" {
		t.Fatalf("unexpected response actionReason: %v", got)
	}
	if got := respWithErr["assessments"]; got != "boom" {
		t.Fatalf("unexpected response assessments: %v", got)
	}
}

func mustGetRegexPolicy(t *testing.T, params map[string]interface{}) *RegexGuardrailPolicy {
	t.Helper()

	p, err := GetPolicy(policy.PolicyMetadata{}, params)
	if err != nil {
		t.Fatalf("failed to create policy: %v", err)
	}
	rp, ok := p.(*RegexGuardrailPolicy)
	if !ok {
		t.Fatalf("expected *RegexGuardrailPolicy, got %T", p)
	}
	return rp
}

func assertRequestErrorResponse(t *testing.T, action policy.RequestAction, expectAssessments bool, wantDirection string) map[string]interface{} {
	t.Helper()

	resp, ok := action.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("expected ImmediateResponse, got %T", action)
	}
	if resp.StatusCode != GuardrailErrorCode {
		t.Fatalf("unexpected status code: got %d, want %d", resp.StatusCode, GuardrailErrorCode)
	}
	if resp.Headers["Content-Type"] != "application/json" {
		t.Fatalf("unexpected content type header: %v", resp.Headers["Content-Type"])
	}

	body := decodeJSONMap(t, resp.Body)
	if got := body["type"]; got != "REGEX_GUARDRAIL" {
		t.Fatalf("unexpected type: %v", got)
	}
	assessment := extractMessageAssessment(t, body)
	validateAssessmentCore(t, assessment, expectAssessments, wantDirection)
	return body
}

func assertResponseErrorResponse(t *testing.T, action policy.ResponseAction, expectAssessments bool, wantDirection string) map[string]interface{} {
	t.Helper()

	resp, ok := action.(policy.UpstreamResponseModifications)
	if !ok {
		t.Fatalf("expected UpstreamResponseModifications, got %T", action)
	}
	if resp.StatusCode == nil || *resp.StatusCode != GuardrailErrorCode {
		t.Fatalf("unexpected status code: got %v, want %d", resp.StatusCode, GuardrailErrorCode)
	}
	if resp.SetHeaders["Content-Type"] != "application/json" {
		t.Fatalf("unexpected content type header: %v", resp.SetHeaders["Content-Type"])
	}

	body := decodeJSONMap(t, resp.Body)
	if got := body["type"]; got != "REGEX_GUARDRAIL" {
		t.Fatalf("unexpected type: %v", got)
	}
	assessment := extractMessageAssessment(t, body)
	validateAssessmentCore(t, assessment, expectAssessments, wantDirection)
	return body
}

func validateAssessmentCore(t *testing.T, assessment map[string]interface{}, expectAssessments bool, wantDirection string) {
	t.Helper()

	if got := assessment["action"]; got != "GUARDRAIL_INTERVENED" {
		t.Fatalf("unexpected action: %v", got)
	}
	if got := assessment["interveningGuardrail"]; got != "regex-guardrail" {
		t.Fatalf("unexpected interveningGuardrail: %v", got)
	}
	if got := assessment["direction"]; got != wantDirection {
		t.Fatalf("unexpected direction: got %v, want %q", got, wantDirection)
	}
	if expectAssessments {
		if _, exists := assessment["assessments"]; !exists {
			t.Fatalf("expected assessments to be present")
		}
	}
}

func extractMessageAssessment(t *testing.T, body map[string]interface{}) map[string]interface{} {
	t.Helper()

	msg, ok := body["message"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected body.message as object, got %T", body["message"])
	}
	return msg
}

func decodeJSONMap(t *testing.T, payload []byte) map[string]interface{} {
	t.Helper()

	var result map[string]interface{}
	if err := json.Unmarshal(payload, &result); err != nil {
		t.Fatalf("failed to unmarshal JSON body: %v; body=%s", err, string(payload))
	}
	return result
}

func newRequestContextWithBody(body string) *policy.RequestContext {
	return &policy.RequestContext{
		SharedContext: &policy.SharedContext{
			RequestID: "test-request-id",
			Metadata:  map[string]interface{}{},
		},
		Body: &policy.Body{
			Content: []byte(body),
			Present: body != "",
		},
	}
}

func newResponseContextWithBody(body string) *policy.ResponseContext {
	return &policy.ResponseContext{
		SharedContext: &policy.SharedContext{
			RequestID: "test-request-id",
			Metadata:  map[string]interface{}{},
		},
		ResponseBody: &policy.Body{
			Content: []byte(body),
			Present: body != "",
		},
	}
}

type errSentinel string

func (e errSentinel) Error() string {
	return string(e)
}
