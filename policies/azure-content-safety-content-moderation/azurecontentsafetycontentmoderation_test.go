package azurecontentsafetycontentmoderation

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

func TestAzureContentSafetyContentModerationPolicy_Mode(t *testing.T) {
	p := &AzureContentSafetyContentModerationPolicy{}
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

func TestValidateAzureConfigParams(t *testing.T) {
	tests := []struct {
		name           string
		params         map[string]interface{}
		wantErrContain string
	}{
		{
			name:           "missing endpoint",
			params:         map[string]interface{}{"azureContentSafetyKey": "k"},
			wantErrContain: "'azureContentSafetyEndpoint' parameter is required",
		},
		{
			name:           "endpoint wrong type",
			params:         map[string]interface{}{"azureContentSafetyEndpoint": 1, "azureContentSafetyKey": "k"},
			wantErrContain: "'azureContentSafetyEndpoint' must be a string",
		},
		{
			name:           "missing key",
			params:         map[string]interface{}{"azureContentSafetyEndpoint": "https://example.com"},
			wantErrContain: "'azureContentSafetyKey' parameter is required",
		},
		{
			name:           "key empty",
			params:         map[string]interface{}{"azureContentSafetyEndpoint": "https://example.com", "azureContentSafetyKey": ""},
			wantErrContain: "'azureContentSafetyKey' cannot be empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateAzureConfigParams(tt.params)
			if err == nil {
				t.Fatalf("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tt.wantErrContain) {
				t.Fatalf("error mismatch: got %q, want contain %q", err.Error(), tt.wantErrContain)
			}
		})
	}
}

func TestParseRequestResponseParams_DefaultsAndErrors(t *testing.T) {
	got, err := parseRequestResponseParams(map[string]interface{}{}, false)
	if err != nil {
		t.Fatalf("expected defaults parse success, got error: %v", err)
	}
	if got.JsonPath != requestDefaultJSONPath {
		t.Fatalf("unexpected default request jsonPath: got %q, want %q", got.JsonPath, requestDefaultJSONPath)
	}
	if got.HateSeverityThreshold != 4 || got.SexualSeverityThreshold != 5 || got.SelfHarmSeverityThreshold != 3 || got.ViolenceSeverityThreshold != 4 {
		t.Fatalf("unexpected default thresholds: %+v", got)
	}
	gotResponse, err := parseRequestResponseParams(map[string]interface{}{}, true)
	if err != nil {
		t.Fatalf("expected response defaults parse success, got error: %v", err)
	}
	if gotResponse.JsonPath != responseDefaultJSONPath {
		t.Fatalf("unexpected default response jsonPath: got %q, want %q", gotResponse.JsonPath, responseDefaultJSONPath)
	}

	tests := []struct {
		name           string
		params         map[string]interface{}
		wantErrContain string
	}{
		{
			name:           "jsonPath wrong type",
			params:         map[string]interface{}{"jsonPath": true},
			wantErrContain: "'jsonPath' must be a string",
		},
		{
			name:           "passthroughOnError wrong type",
			params:         map[string]interface{}{"passthroughOnError": "true"},
			wantErrContain: "'passthroughOnError' must be a boolean",
		},
		{
			name:           "showAssessment wrong type",
			params:         map[string]interface{}{"showAssessment": "true"},
			wantErrContain: "'showAssessment' must be a boolean",
		},
		{
			name:           "threshold out of range",
			params:         map[string]interface{}{"hateSeverityThreshold": 8},
			wantErrContain: "'hateSeverityThreshold' must be between -1 and 7",
		},
		{
			name:           "threshold not integer",
			params:         map[string]interface{}{"hateSeverityThreshold": 1.5},
			wantErrContain: "'hateSeverityThreshold' must be a number",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseRequestResponseParams(tt.params, false)
			if err == nil {
				t.Fatalf("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tt.wantErrContain) {
				t.Fatalf("error mismatch: got %q, want contain %q", err.Error(), tt.wantErrContain)
			}
		})
	}
}

func TestAzureContentSafetyPolicy_GetPolicy_Errors(t *testing.T) {
	base := map[string]interface{}{
		"azureContentSafetyEndpoint": "https://example.com",
		"azureContentSafetyKey":      "k",
	}

	_, err := GetPolicy(policy.PolicyMetadata{}, base)
	if err == nil || !strings.Contains(err.Error(), "at least one of 'request' or 'response' parameters must be provided") {
		t.Fatalf("expected request/response presence error, got %v", err)
	}

	badReq := map[string]interface{}{
		"azureContentSafetyEndpoint": "https://example.com",
		"azureContentSafetyKey":      "k",
		"request": map[string]interface{}{
			"showAssessment": "true",
		},
	}
	_, err = GetPolicy(policy.PolicyMetadata{}, badReq)
	if err == nil || !strings.Contains(err.Error(), "invalid request parameters") {
		t.Fatalf("expected invalid request parameters error, got %v", err)
	}
}

func TestAzureContentSafetyPolicy_OnRequest_NoRequestConfig_NoOp(t *testing.T) {
	p := mustGetAzurePolicy(t, map[string]interface{}{
		"azureContentSafetyEndpoint": "https://example.com",
		"azureContentSafetyKey":      "k",
		"response": map[string]interface{}{
			"jsonPath": "$.messages",
		},
	})

	action := p.OnRequestBody(context.Background(), azureRequestContext(`{"message":"hello"}`), nil)
	if _, ok := action.(policy.UpstreamRequestModifications); !ok {
		t.Fatalf("expected UpstreamRequestModifications, got %T", action)
	}
}

func TestAzureContentSafetyPolicy_OnResponse_NoResponseConfig_NoOp(t *testing.T) {
	p := mustGetAzurePolicy(t, map[string]interface{}{
		"azureContentSafetyEndpoint": "https://example.com",
		"azureContentSafetyKey":      "k",
		"request": map[string]interface{}{
			"jsonPath": "$.messages",
		},
	})

	action := p.OnResponseBody(context.Background(), azureResponseContext(`{"message":"hello"}`), nil)
	if _, ok := action.(policy.DownstreamResponseModifications); !ok {
		t.Fatalf("expected UpstreamResponseModifications, got %T", action)
	}
}

func TestAzureContentSafetyPolicy_NoValidCategories_PassThrough(t *testing.T) {
	p := mustGetAzurePolicy(t, map[string]interface{}{
		"azureContentSafetyEndpoint": "https://example.com",
		"azureContentSafetyKey":      "k",
		"request": map[string]interface{}{
			"hateSeverityThreshold":     -1,
			"sexualSeverityThreshold":   -1,
			"selfHarmSeverityThreshold": -1,
			"violenceSeverityThreshold": -1,
		},
	})

	action := p.OnRequestBody(context.Background(), azureRequestContext(`{"message":"hello"}`), nil)
	if _, ok := action.(policy.UpstreamRequestModifications); !ok {
		t.Fatalf("expected pass-through when no valid categories, got %T", action)
	}
}

func TestAzureContentSafetyPolicy_JSONPathError_PassthroughBehavior(t *testing.T) {
	pPass := mustGetAzurePolicy(t, map[string]interface{}{
		"azureContentSafetyEndpoint": "https://example.com",
		"azureContentSafetyKey":      "k",
		"request": map[string]interface{}{
			"jsonPath":           "$.missing.path",
			"passthroughOnError": true,
		},
	})
	a1 := pPass.OnRequestBody(context.Background(), azureRequestContext(`{"message":"hello"}`), nil)
	if _, ok := a1.(policy.UpstreamRequestModifications); !ok {
		t.Fatalf("expected pass-through for jsonPath error when passthrough enabled, got %T", a1)
	}

	pFail := mustGetAzurePolicy(t, map[string]interface{}{
		"azureContentSafetyEndpoint": "https://example.com",
		"azureContentSafetyKey":      "k",
		"request": map[string]interface{}{
			"jsonPath":           "$.missing.path",
			"passthroughOnError": false,
			"showAssessment":     true,
		},
	})
	a2 := pFail.OnRequestBody(context.Background(), azureRequestContext(`{"message":"hello"}`), nil)
	body := assertAzureRequestError(t, a2, true, "REQUEST")
	msg := extractAzureMessage(t, body)
	if _, ok := msg["assessments"]; !ok {
		t.Fatalf("expected assessments for extraction error with showAssessment=true")
	}
}

func TestAzureContentSafetyPolicy_APICallError_PassthroughBehavior(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"bad request"}`))
	}))
	defer srv.Close()

	pPass := mustGetAzurePolicy(t, map[string]interface{}{
		"azureContentSafetyEndpoint": srv.URL,
		"azureContentSafetyKey":      "k",
		"request": map[string]interface{}{
			"jsonPath":           "$.messages",
			"passthroughOnError": true,
		},
	})
	a1 := pPass.OnRequestBody(context.Background(), azureRequestContext(`{"message":"hello"}`), nil)
	if _, ok := a1.(policy.UpstreamRequestModifications); !ok {
		t.Fatalf("expected pass-through on API error when passthrough enabled, got %T", a1)
	}

	pFail := mustGetAzurePolicy(t, map[string]interface{}{
		"azureContentSafetyEndpoint": srv.URL,
		"azureContentSafetyKey":      "k",
		"request": map[string]interface{}{
			"jsonPath":           "$.messages",
			"passthroughOnError": false,
		},
	})
	a2 := pFail.OnRequestBody(context.Background(), azureRequestContext(`{"message":"hello"}`), nil)
	assertAzureRequestError(t, a2, false, "REQUEST")
}

func TestAzureContentSafetyPolicy_APISuccess_NoViolation(t *testing.T) {
	srv := azureMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/contentsafety/text:analyze" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"categoriesAnalysis":[{"category":"Hate","severity":1}]}`))
	})
	defer srv.Close()

	p := mustGetAzurePolicy(t, map[string]interface{}{
		"azureContentSafetyEndpoint": srv.URL,
		"azureContentSafetyKey":      "k",
		"request": map[string]interface{}{
			"jsonPath":              "$.messages",
			"hateSeverityThreshold": 4,
		},
	})
	action := p.OnRequestBody(context.Background(), azureRequestContext(`{"messages":"hello"}`), nil)
	if _, ok := action.(policy.UpstreamRequestModifications); !ok {
		t.Fatalf("expected UpstreamRequestModifications on non-violation, got %T", action)
	}
}

func TestAzureContentSafetyPolicy_APIViolation_RequestAndResponse(t *testing.T) {
	srv := azureMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"categoriesAnalysis":[{"category":"Hate","severity":5}]}`))
	})
	defer srv.Close()

	p := mustGetAzurePolicy(t, map[string]interface{}{
		"azureContentSafetyEndpoint": srv.URL,
		"azureContentSafetyKey":      "k",
		"request": map[string]interface{}{
			"jsonPath":              "$.messages",
			"hateSeverityThreshold": 3,
			"showAssessment":        true,
		},
		"response": map[string]interface{}{
			"jsonPath":              "$.messages",
			"hateSeverityThreshold": 3,
			"showAssessment":        true,
		},
	})

	reqAction := p.OnRequestBody(context.Background(), azureRequestContext(`{"messages":"blocked text"}`), nil)
	reqBody := assertAzureRequestError(t, reqAction, true, "REQUEST")
	reqMsg := extractAzureMessage(t, reqBody)
	assessment, ok := reqMsg["assessments"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected assessments object on violation, got %T", reqMsg["assessments"])
	}
	if _, ok := assessment["categories"]; !ok {
		t.Fatalf("expected assessments.categories on violation")
	}

	respAction := p.OnResponseBody(context.Background(), azureResponseContext(`{"messages":"blocked response"}`), nil)
	respBody := assertAzureResponseError(t, respAction, true, "RESPONSE")
	respMsg := extractAzureMessage(t, respBody)
	if _, ok := respMsg["assessments"]; !ok {
		t.Fatalf("expected response assessments on violation")
	}
}

func mustGetAzurePolicy(t *testing.T, params map[string]interface{}) *AzureContentSafetyContentModerationPolicy {
	t.Helper()
	p, err := GetPolicy(policy.PolicyMetadata{}, params)
	if err != nil {
		t.Fatalf("failed to create policy: %v", err)
	}
	ap, ok := p.(*AzureContentSafetyContentModerationPolicy)
	if !ok {
		t.Fatalf("expected *AzureContentSafetyContentModerationPolicy, got %T", p)
	}
	return ap
}

func azureMockServer(t *testing.T, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("expected POST, got %s", r.Method)
		}
		if got := r.URL.Query().Get("api-version"); got != "2024-09-01" {
			t.Fatalf("expected api-version=2024-09-01, got %q", got)
		}
		if r.Header.Get("Ocp-Apim-Subscription-Key") == "" {
			t.Fatalf("expected subscription key header")
		}
		handler(w, r)
	}))
}

func azureRequestContext(body string) *policy.RequestContext {
	return &policy.RequestContext{
		SharedContext: &policy.SharedContext{
			RequestID: "req-id",
			Metadata:  map[string]interface{}{},
		},
		Body: &policy.Body{
			Content: []byte(body),
			Present: body != "",
		},
	}
}

func azureResponseContext(body string) *policy.ResponseContext {
	return &policy.ResponseContext{
		SharedContext: &policy.SharedContext{
			RequestID: "req-id",
			Metadata:  map[string]interface{}{},
		},
		ResponseBody: &policy.Body{
			Content: []byte(body),
			Present: body != "",
		},
	}
}

func assertAzureRequestError(t *testing.T, action policy.RequestAction, expectAssessments bool, wantDirection string) map[string]interface{} {
	t.Helper()
	resp, ok := action.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("expected ImmediateResponse, got %T", action)
	}
	if resp.StatusCode != GuardrailErrorCode {
		t.Fatalf("unexpected status code: got %d, want %d", resp.StatusCode, GuardrailErrorCode)
	}
	body := decodeAzureJSON(t, resp.Body)
	validateAzureErrorBody(t, body, expectAssessments, wantDirection)
	return body
}

func assertAzureResponseError(t *testing.T, action policy.ResponseAction, expectAssessments bool, wantDirection string) map[string]interface{} {
	t.Helper()
	resp, ok := action.(policy.DownstreamResponseModifications)
	if !ok {
		t.Fatalf("expected UpstreamResponseModifications, got %T", action)
	}
	if resp.StatusCode == nil || *resp.StatusCode != GuardrailErrorCode {
		t.Fatalf("unexpected status code: got %v", resp.StatusCode)
	}
	body := decodeAzureJSON(t, resp.Body)
	validateAzureErrorBody(t, body, expectAssessments, wantDirection)
	return body
}

func validateAzureErrorBody(t *testing.T, body map[string]interface{}, expectAssessments bool, wantDirection string) {
	t.Helper()
	if got := body["type"]; got != "AZURE_CONTENT_SAFETY_CONTENT_MODERATION" {
		t.Fatalf("unexpected type: %v", got)
	}
	msg := extractAzureMessage(t, body)
	if got := msg["action"]; got != "GUARDRAIL_INTERVENED" {
		t.Fatalf("unexpected action: %v", got)
	}
	if got := msg["direction"]; got != wantDirection {
		t.Fatalf("unexpected direction: got %v, want %q", got, wantDirection)
	}
	if expectAssessments {
		if _, ok := msg["assessments"]; !ok {
			t.Fatalf("expected assessments to be present")
		}
	}
}

func extractAzureMessage(t *testing.T, body map[string]interface{}) map[string]interface{} {
	t.Helper()
	msg, ok := body["message"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected body.message object, got %T", body["message"])
	}
	return msg
}

func decodeAzureJSON(t *testing.T, raw []byte) map[string]interface{} {
	t.Helper()
	var m map[string]interface{}
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("failed to decode json: %v", err)
	}
	return m
}

// TestAzureContentSafety_InterventionDeclaresFault covers the funnel every intervention
func TestAzureContentSafety_InterventionDeclaresFault(t *testing.T) {
	p := &AzureContentSafetyContentModerationPolicy{}
	analysis := []map[string]interface{}{{"category": "Hate", "severity": 6}}

	t.Run("request phase", func(t *testing.T) {
		action := p.buildErrorResponse("blocked detail", nil, false, false, analysis, "inspected", "Hate")
		resp, ok := action.(policy.ImmediateResponse)
		if !ok {
			t.Fatalf("expected ImmediateResponse, got %T", action)
		}
		if !resp.IsFault {
			t.Fatalf("expected IsFault=true on a guardrail intervention")
		}
		if resp.Fault == nil || resp.Fault.Code != policy.GuardrailCodeHate {
			t.Fatalf("expected Error.Code=%q, got %+v", policy.GuardrailCodeHate, resp.Fault)
		}
		if resp.Fault.Direction != policy.DirectionRequest {
			t.Fatalf("expected Error.Direction=%q, got %q", policy.DirectionRequest, resp.Fault.Direction)
		}
		if resp.Fault.Guardrail == nil || resp.Fault.Guardrail.InterveningGuardrail != guardrailName {
			t.Fatalf("expected the guardrail envelope to name %q, got %+v", guardrailName, resp.Fault.Guardrail)
		}
	})

	t.Run("response phase", func(t *testing.T) {
		action := p.buildErrorResponse("blocked detail", nil, true, false, analysis, "inspected", "Hate")
		mods, ok := action.(policy.DownstreamResponseModifications)
		if !ok {
			t.Fatalf("expected DownstreamResponseModifications, got %T", action)
		}
		if !mods.IsFault {
			t.Fatalf("expected IsFault=true on a response-side intervention")
		}
		if mods.Fault == nil || mods.Fault.Direction != policy.DirectionResponse {
			t.Fatalf("expected Error.Direction=%q, got %+v", policy.DirectionResponse, mods.Fault)
		}
	})
}

// TestAzureContentSafety_AssessmentsGatedByShowAssessment covers the field that must not
// leak: for a response-side hit the assessment holds the content the guardrail existed to
// stop from leaving, so it is populated only where the operator opted in.
func TestAzureContentSafety_AssessmentsGatedByShowAssessment(t *testing.T) {
	p := &AzureContentSafetyContentModerationPolicy{}
	analysis := []map[string]interface{}{{"category": "Hate", "severity": 6}}

	for _, show := range []bool{false, true} {
		name := "showAssessment=false"
		if show {
			name = "showAssessment=true"
		}
		t.Run(name, func(t *testing.T) {
			action := p.buildErrorResponse("blocked detail", nil, true, show, analysis, "inspected", "Hate")
			mods := action.(policy.DownstreamResponseModifications)
			if mods.Fault == nil || mods.Fault.Guardrail == nil {
				t.Fatalf("expected the guardrail error to be populated")
			}
			got := mods.Fault.Guardrail.Assessments
			if show && got == nil {
				t.Fatalf("expected Assessments when showAssessment=true")
			}
			if !show && got != nil {
				t.Fatalf("Assessments must stay empty when showAssessment=false, got %v", got)
			}
		})
	}
}

// TestAzureContentSafety_ExtractionFailureDeclaresFault pins the JSONPath extraction failure: no check
// ran, so it is not a guardrail verdict. An unreadable request body is the caller's; an
// unreadable response body leaves the policy unable to do its job. The client response is
// the one the policy returned before the fault was declared.
func TestAzureContentSafety_ExtractionFailureDeclaresFault(t *testing.T) {
	p := &AzureContentSafetyContentModerationPolicy{}
	params := AzureContentSafetyPolicyParams{JsonPath: "$.text", HateSeverityThreshold: 2}
	for _, isResponse := range []bool{false, true} {
		got := p.validatePayload([]byte(`not-json`), params, isResponse)
		want := p.buildErrorResponse("Error extracting value from JSONPath", errors.New("unused without showAssessment"), isResponse, false, nil, "", "")
		if isResponse {
			assertNoVerdictFault(t, got, want, policy.FaultCodeMediationFailed, policy.FaultTypeMediation, policy.DirectionResponse)
		} else {
			assertNoVerdictFault(t, got, want, policy.FaultCodeInvalidRequestBody, policy.FaultTypeValidation, policy.DirectionRequest)
		}
	}
}

// assertNoVerdictFault checks that a rejection made without a guardrail verdict declares
// the given fault, carries no guardrail details, and leaves the client response unchanged.
func assertNoVerdictFault(t *testing.T, got, want interface{}, wantCode, wantType, wantDirection string) {
	t.Helper()
	var fault *policy.FaultDetails
	var isFault bool
	switch g := got.(type) {
	case policy.ImmediateResponse:
		w := want.(policy.ImmediateResponse)
		if g.StatusCode != w.StatusCode || string(g.Body) != string(w.Body) || !reflect.DeepEqual(g.Headers, w.Headers) {
			t.Fatalf("client response changed: got %d %s, want %d %s", g.StatusCode, g.Body, w.StatusCode, w.Body)
		}
		fault, isFault = g.Fault, g.IsFault
	case policy.DownstreamResponseModifications:
		w := want.(policy.DownstreamResponseModifications)
		if g.StatusCode == nil || *g.StatusCode != *w.StatusCode || string(g.Body) != string(w.Body) || !reflect.DeepEqual(g.HeadersToSet, w.HeadersToSet) {
			t.Fatalf("client response changed: got %v %s, want %d %s", g.StatusCode, g.Body, *w.StatusCode, w.Body)
		}
		fault, isFault = g.Fault, g.IsFault
	default:
		t.Fatalf("expected an error response, got %T", got)
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

// TestAzureContentSafety_APIFailureDeclaresFault pins the Azure call that fails: the
// policy could not do its job, which is not a moderation verdict.
func TestAzureContentSafety_APIFailureDeclaresFault(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	p := &AzureContentSafetyContentModerationPolicy{endpoint: server.URL, apiKey: "key", client: server.Client()}
	params := AzureContentSafetyPolicyParams{JsonPath: "$.text", HateSeverityThreshold: 2}
	for _, isResponse := range []bool{false, true} {
		got := p.validatePayload([]byte(`{"text":"hello"}`), params, isResponse)
		want := p.buildErrorResponse("Error calling Azure Content Safety API", errors.New("unused without showAssessment"), isResponse, false, nil, "", "")
		wantDirection := policy.DirectionRequest
		if isResponse {
			wantDirection = policy.DirectionResponse
		}
		assertNoVerdictFault(t, got, want, policy.FaultCodeMediationFailed, policy.FaultTypeMediation, wantDirection)
	}
}
