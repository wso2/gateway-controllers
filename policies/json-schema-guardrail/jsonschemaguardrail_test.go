package jsonschemaguardrail

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/xeipuuv/gojsonschema"

	policy "github.com/wso2/api-platform/sdk/gateway/policy/v1alpha"
)

func decodeMessage(t *testing.T, body []byte) map[string]interface{} {
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

func schemaValidationErrors(t *testing.T, schema, document string) []gojsonschema.ResultError {
	t.Helper()
	res, err := gojsonschema.Validate(gojsonschema.NewStringLoader(schema), gojsonschema.NewStringLoader(document))
	if err != nil {
		t.Fatalf("unexpected schema validation setup error: %v", err)
	}
	return res.Errors()
}

func TestParseParams(t *testing.T) {
	tests := []struct {
		name        string
		input       map[string]interface{}
		expectErr   bool
		errContains string
		expected    JSONSchemaGuardrailPolicyParams
	}{
		{
			name:        "missing schema",
			input:       map[string]interface{}{},
			expectErr:   true,
			errContains: "'schema' parameter is required",
		},
		{
			name:        "schema not string",
			input:       map[string]interface{}{"schema": 10},
			expectErr:   true,
			errContains: "'schema' must be a string",
		},
		{
			name:        "schema empty",
			input:       map[string]interface{}{"schema": ""},
			expectErr:   true,
			errContains: "'schema' cannot be empty",
		},
		{
			name:        "schema invalid json",
			input:       map[string]interface{}{"schema": "{"},
			expectErr:   true,
			errContains: "'schema' must be valid JSON",
		},
		{
			name:        "jsonPath invalid type",
			input:       map[string]interface{}{"schema": `{"type":"object"}`, "jsonPath": 1},
			expectErr:   true,
			errContains: "'jsonPath' must be a string",
		},
		{
			name:        "enabled invalid type",
			input:       map[string]interface{}{"schema": `{"type":"object"}`, "enabled": "true"},
			expectErr:   true,
			errContains: "'enabled' must be a boolean",
		},
		{
			name:        "invert invalid type",
			input:       map[string]interface{}{"schema": `{"type":"object"}`, "invert": "true"},
			expectErr:   true,
			errContains: "'invert' must be a boolean",
		},
		{
			name:        "showAssessment invalid type",
			input:       map[string]interface{}{"schema": `{"type":"object"}`, "showAssessment": "true"},
			expectErr:   true,
			errContains: "'showAssessment' must be a boolean",
		},
		{
			name: "valid params",
			input: map[string]interface{}{
				"schema":         `{"type":"object","required":["name"]}`,
				"jsonPath":       "$.data",
				"invert":         true,
				"showAssessment": true,
			},
			expected: JSONSchemaGuardrailPolicyParams{
				Enabled:        RequestFlowEnabledByDefault,
				Schema:         `{"type":"object","required":["name"]}`,
				JsonPath:       "$.data",
				Invert:         true,
				ShowAssessment: true,
			},
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
			if !reflect.DeepEqual(got, tc.expected) {
				t.Fatalf("expected %+v, got %+v", tc.expected, got)
			}
		})
	}
}

func TestGetPolicy(t *testing.T) {
	_, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{})
	if err == nil || !strings.Contains(err.Error(), "at least one of 'request' or 'response' parameters must be provided") {
		t.Fatalf("expected missing phase params error, got %v", err)
	}

	_, err = GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{
		"request": map[string]interface{}{"schema": "{"},
	})
	if err == nil || !strings.Contains(err.Error(), "invalid request parameters") {
		t.Fatalf("expected invalid request params error, got %v", err)
	}

	_, err = GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{
		"response": map[string]interface{}{"schema": "{"},
	})
	if err == nil || !strings.Contains(err.Error(), "invalid response parameters") {
		t.Fatalf("expected invalid response params error, got %v", err)
	}

	pRaw, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{
		"request": map[string]interface{}{"schema": `{"type":"object"}`},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	p, ok := pRaw.(*JSONSchemaGuardrailPolicy)
	if !ok {
		t.Fatalf("expected *JSONSchemaGuardrailPolicy, got %T", pRaw)
	}
	if !p.hasRequestParams || p.hasResponseParams {
		t.Fatalf("expected request=true response=false, got request=%v response=%v", p.hasRequestParams, p.hasResponseParams)
	}
	if p.requestParams.JsonPath != DefaultRequestJSONPath {
		t.Fatalf("unexpected request jsonPath default: got %q, want %q", p.requestParams.JsonPath, DefaultRequestJSONPath)
	}
	if p.requestParams.Enabled {
		t.Fatalf("expected request disabled by default")
	}

	pRaw, err = GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{
		"request":  map[string]interface{}{"schema": `{"type":"object"}`},
		"response": map[string]interface{}{"schema": `{"type":"object"}`},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	p, ok = pRaw.(*JSONSchemaGuardrailPolicy)
	if !ok {
		t.Fatalf("expected *JSONSchemaGuardrailPolicy, got %T", pRaw)
	}
	if !p.hasRequestParams || !p.hasResponseParams {
		t.Fatalf("expected request=true response=true, got request=%v response=%v", p.hasRequestParams, p.hasResponseParams)
	}
	if p.requestParams.JsonPath != DefaultRequestJSONPath {
		t.Fatalf("unexpected request jsonPath default: got %q, want %q", p.requestParams.JsonPath, DefaultRequestJSONPath)
	}
	if p.requestParams.Enabled {
		t.Fatalf("expected request disabled by default")
	}
	if p.responseParams.JsonPath != DefaultResponseJSONPath {
		t.Fatalf("unexpected response jsonPath default: got %q, want %q", p.responseParams.JsonPath, DefaultResponseJSONPath)
	}
	if !p.responseParams.Enabled {
		t.Fatalf("expected response enabled by default")
	}
}

func TestExtractValueFromJSONPathForSchema(t *testing.T) {
	got, err := extractValueFromJSONPathForSchema([]byte(`{"data":{"name":"alice"}}`), "$.data")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(got) != `{"name":"alice"}` {
		t.Fatalf("unexpected extracted JSON bytes: %s", string(got))
	}

	_, err = extractValueFromJSONPathForSchema([]byte(`{`), "$.data")
	if err == nil || !strings.Contains(err.Error(), "error unmarshaling JSON") {
		t.Fatalf("expected JSON unmarshal error, got %v", err)
	}

	_, err = extractValueFromJSONPathForSchema([]byte(`[]`), "$.data")
	if err == nil || !strings.Contains(err.Error(), "jsonPath extraction requires a JSON object payload") {
		t.Fatalf("expected non-object payload error, got %v", err)
	}

	_, err = extractValueFromJSONPathForSchema([]byte(`{"data":{"name":"alice"}}`), "$.missing")
	if err == nil || !strings.Contains(err.Error(), "key not found") {
		t.Fatalf("expected missing path error, got %v", err)
	}
}

func TestMode(t *testing.T) {
	p := &JSONSchemaGuardrailPolicy{}
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

func TestValidatePayload_NormalAndInvert(t *testing.T) {
	p := &JSONSchemaGuardrailPolicy{}
	schema := `{"type":"object","properties":{"name":{"type":"string"}},"required":["name"]}`
	validPayload := []byte(`{"name":"alice"}`)
	invalidPayload := []byte(`{"name":10}`)

	// Normal mode valid -> pass
	result := p.validatePayload(validPayload, JSONSchemaGuardrailPolicyParams{
		Schema: schema,
	}, false)
	if _, ok := result.(policy.UpstreamRequestModifications); !ok {
		t.Fatalf("expected UpstreamRequestModifications, got %T", result)
	}

	// Normal mode invalid -> fail
	result = p.validatePayload(invalidPayload, JSONSchemaGuardrailPolicyParams{
		Schema:         schema,
		ShowAssessment: true,
	}, false)
	imm, ok := result.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("expected ImmediateResponse, got %T", result)
	}
	if imm.StatusCode != GuardrailErrorCode {
		t.Fatalf("expected status %d, got %d", GuardrailErrorCode, imm.StatusCode)
	}
	msg := decodeMessage(t, imm.Body)
	if msg["direction"] != "REQUEST" {
		t.Fatalf("expected REQUEST direction, got %#v", msg["direction"])
	}
	if msg["actionReason"] != "Violation of JSON schema detected." {
		t.Fatalf("unexpected actionReason: %#v", msg["actionReason"])
	}
	if assessments, ok := msg["assessments"].([]interface{}); !ok || len(assessments) == 0 {
		t.Fatalf("expected non-empty assessment details, got %#v", msg["assessments"])
	}

	// Invert mode valid -> fail
	result = p.validatePayload(validPayload, JSONSchemaGuardrailPolicyParams{
		Schema: schema,
		Invert: true,
	}, false)
	if _, ok := result.(policy.ImmediateResponse); !ok {
		t.Fatalf("expected ImmediateResponse for inverted-valid case, got %T", result)
	}

	// Invert mode invalid -> pass
	result = p.validatePayload(invalidPayload, JSONSchemaGuardrailPolicyParams{
		Schema: schema,
		Invert: true,
	}, false)
	if _, ok := result.(policy.UpstreamRequestModifications); !ok {
		t.Fatalf("expected UpstreamRequestModifications for inverted-invalid case, got %T", result)
	}
}

func TestValidatePayload_JSONPathAndSchemaErrors(t *testing.T) {
	p := &JSONSchemaGuardrailPolicy{}

	// JSONPath extraction error
	result := p.validatePayload([]byte(`{"name":"alice"}`), JSONSchemaGuardrailPolicyParams{
		Schema:         `{"type":"string"}`,
		JsonPath:       "$.missing",
		ShowAssessment: true,
	}, false)
	imm, ok := result.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("expected ImmediateResponse on JSONPath error, got %T", result)
	}
	msg := decodeMessage(t, imm.Body)
	if msg["actionReason"] != "Error extracting value from JSONPath" {
		t.Fatalf("expected jsonPath action reason, got %#v", msg["actionReason"])
	}
	if _, ok := msg["assessments"].(string); !ok {
		t.Fatalf("expected string assessments on extraction error, got %#v", msg["assessments"])
	}

	// Schema validation engine error (invalid schema keywords/types)
	result = p.validatePayload([]byte(`{"name":"alice"}`), JSONSchemaGuardrailPolicyParams{
		Schema:         `{"type":"not-a-valid-jsonschema-type"}`,
		ShowAssessment: true,
	}, false)
	imm, ok = result.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("expected ImmediateResponse on schema validation engine error, got %T", result)
	}
	msg = decodeMessage(t, imm.Body)
	if msg["actionReason"] != "Error validating schema" {
		t.Fatalf("expected schema error action reason, got %#v", msg["actionReason"])
	}
	if _, ok := msg["assessments"].(string); !ok {
		t.Fatalf("expected string assessments on schema error, got %#v", msg["assessments"])
	}
}

func TestBuildErrorResponseResponsePhase(t *testing.T) {
	p := &JSONSchemaGuardrailPolicy{}
	res := p.buildErrorResponse("test reason", nil, true, false, nil)
	mod, ok := res.(policy.UpstreamResponseModifications)
	if !ok {
		t.Fatalf("expected UpstreamResponseModifications, got %T", res)
	}
	if mod.StatusCode == nil || *mod.StatusCode != GuardrailErrorCode {
		t.Fatalf("expected status %d, got %#v", GuardrailErrorCode, mod.StatusCode)
	}
	if mod.SetHeaders["Content-Type"] != "application/json" {
		t.Fatalf("expected Content-Type header, got %#v", mod.SetHeaders)
	}
	msg := decodeMessage(t, mod.Body)
	if msg["direction"] != "RESPONSE" {
		t.Fatalf("expected RESPONSE direction, got %#v", msg["direction"])
	}
}

func TestBuildAssessmentObject(t *testing.T) {
	p := &JSONSchemaGuardrailPolicy{}
	errors := schemaValidationErrors(t,
		`{"type":"object","properties":{"name":{"type":"string"}},"required":["name"]}`,
		`{"name":10}`,
	)

	assessment := p.buildAssessmentObject("ignored", nil, false, true, errors)
	if assessment["actionReason"] != "Violation of JSON schema detected." {
		t.Fatalf("unexpected actionReason for validation failure: %#v", assessment["actionReason"])
	}
	details, ok := assessment["assessments"].([]map[string]interface{})
	if ok {
		if len(details) == 0 {
			t.Fatalf("expected non-empty error details")
		}
	} else {
		// JSON marshalling/unmarshalling is not involved here; the function sets []map directly.
		// Keep this branch strict for type regressions.
		t.Fatalf("expected []map[string]interface{} details, got %#v", assessment["assessments"])
	}

	withErr := p.buildAssessmentObject("Error extracting value from JSONPath", json.Unmarshal([]byte("{"), &map[string]interface{}{}), false, true, nil)
	if withErr["actionReason"] != "Error extracting value from JSONPath" {
		t.Fatalf("unexpected actionReason for runtime error: %#v", withErr["actionReason"])
	}
	if _, ok := withErr["assessments"].(string); !ok {
		t.Fatalf("expected string assessments for runtime error, got %#v", withErr["assessments"])
	}
}

func TestOnRequestAndOnResponse(t *testing.T) {
	// No configured phase params -> no-op
	p := &JSONSchemaGuardrailPolicy{}
	reqResult := p.OnRequest(&policy.RequestContext{}, nil)
	if _, ok := reqResult.(policy.UpstreamRequestModifications); !ok {
		t.Fatalf("expected UpstreamRequestModifications no-op, got %T", reqResult)
	}
	respResult := p.OnResponse(&policy.ResponseContext{}, nil)
	if _, ok := respResult.(policy.UpstreamResponseModifications); !ok {
		t.Fatalf("expected UpstreamResponseModifications no-op, got %T", respResult)
	}

	// Request phase configured, nil body -> validation failure
	p.hasRequestParams = true
	p.requestParams = JSONSchemaGuardrailPolicyParams{
		Enabled: true,
		Schema:  `{"type":"object","required":["name"]}`,
	}
	reqResult = p.OnRequest(&policy.RequestContext{Body: nil}, nil)
	if _, ok := reqResult.(policy.ImmediateResponse); !ok {
		t.Fatalf("expected ImmediateResponse on invalid request payload, got %T", reqResult)
	}

	// Response phase configured, nil body -> validation failure
	p.hasResponseParams = true
	p.responseParams = JSONSchemaGuardrailPolicyParams{
		Enabled: true,
		Schema:  `{"type":"object","required":["name"]}`,
	}
	respResult = p.OnResponse(&policy.ResponseContext{ResponseBody: nil}, nil)
	respMod, ok := respResult.(policy.UpstreamResponseModifications)
	if !ok {
		t.Fatalf("expected UpstreamResponseModifications on invalid response payload, got %T", respResult)
	}
	if respMod.StatusCode == nil || *respMod.StatusCode != GuardrailErrorCode {
		t.Fatalf("expected status %d, got %#v", GuardrailErrorCode, respMod.StatusCode)
	}

	p.requestParams.Enabled = false
	reqDisabled := p.OnRequest(&policy.RequestContext{Body: &policy.Body{Content: []byte(`{"name":"alice"}`)}}, nil)
	if _, ok := reqDisabled.(policy.UpstreamRequestModifications); !ok {
		t.Fatalf("expected request no-op when request.enabled=false, got %T", reqDisabled)
	}

	p.responseParams.Enabled = false
	respDisabled := p.OnResponse(&policy.ResponseContext{ResponseBody: &policy.Body{Content: []byte(`{"name":"alice"}`)}}, nil)
	if _, ok := respDisabled.(policy.UpstreamResponseModifications); !ok {
		t.Fatalf("expected response no-op when response.enabled=false, got %T", respDisabled)
	}
}
