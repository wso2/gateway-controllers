package azurecontentsafetycontentmoderation

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	policy "github.com/wso2/api-platform/sdk/gateway/policy/v1alpha"
)

func TestAzureContentSafetyPolicy_Mode(t *testing.T) {
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
	got, err := parseRequestResponseParams(map[string]interface{}{})
	if err != nil {
		t.Fatalf("expected defaults parse success, got error: %v", err)
	}
	if got.HateSeverityThreshold != 4 || got.SexualSeverityThreshold != 5 || got.SelfHarmSeverityThreshold != 3 || got.ViolenceSeverityThreshold != 4 {
		t.Fatalf("unexpected default thresholds: %+v", got)
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
			_, err := parseRequestResponseParams(tt.params)
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

	action := p.OnRequest(azureRequestContext(`{"message":"hello"}`), nil)
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

	action := p.OnResponse(azureResponseContext(`{"message":"hello"}`), nil)
	if _, ok := action.(policy.UpstreamResponseModifications); !ok {
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

	action := p.OnRequest(azureRequestContext(`{"message":"hello"}`), nil)
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
	a1 := pPass.OnRequest(azureRequestContext(`{"message":"hello"}`), nil)
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
	a2 := pFail.OnRequest(azureRequestContext(`{"message":"hello"}`), nil)
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
	a1 := pPass.OnRequest(azureRequestContext(`{"message":"hello"}`), nil)
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
	a2 := pFail.OnRequest(azureRequestContext(`{"message":"hello"}`), nil)
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
	action := p.OnRequest(azureRequestContext(`{"messages":"hello"}`), nil)
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

	reqAction := p.OnRequest(azureRequestContext(`{"messages":"blocked text"}`), nil)
	reqBody := assertAzureRequestError(t, reqAction, true, "REQUEST")
	reqMsg := extractAzureMessage(t, reqBody)
	assessment, ok := reqMsg["assessments"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected assessments object on violation, got %T", reqMsg["assessments"])
	}
	if _, ok := assessment["categories"]; !ok {
		t.Fatalf("expected assessments.categories on violation")
	}

	respAction := p.OnResponse(azureResponseContext(`{"messages":"blocked response"}`), nil)
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
	resp, ok := action.(policy.UpstreamResponseModifications)
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
