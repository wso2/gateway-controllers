package jsonschemaguardrail

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/xeipuuv/gojsonschema"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
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

func TestParseParams_DisabledFlow_DoesNotRequireSchema(t *testing.T) {
	tests := []struct {
		name            string
		input           map[string]interface{}
		defaultJSONPath string
		defaultEnabled  bool
	}{
		{
			name:            "request flow disabled",
			input:           map[string]interface{}{"enabled": false},
			defaultJSONPath: DefaultRequestJSONPath,
			defaultEnabled:  RequestFlowEnabledByDefault,
		},
		{
			name:            "response flow disabled",
			input:           map[string]interface{}{"enabled": false},
			defaultJSONPath: DefaultResponseJSONPath,
			defaultEnabled:  ResponseFlowEnabledByDefault,
		},
		{
			name:            "disabled flow ignores empty schema",
			input:           map[string]interface{}{"enabled": false, "schema": ""},
			defaultJSONPath: DefaultResponseJSONPath,
			defaultEnabled:  ResponseFlowEnabledByDefault,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseParams(tc.input, tc.defaultJSONPath, tc.defaultEnabled)
			if err != nil {
				t.Fatalf("expected disabled flow params to parse without schema, got error: %v", err)
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
			t.Fatalf("expected disabled request flow without schema to be accepted, got %v", err)
		}
		p, ok := pRaw.(*JSONSchemaGuardrailPolicy)
		if !ok {
			t.Fatalf("expected *JSONSchemaGuardrailPolicy, got %T", pRaw)
		}
		if !p.hasRequestParams || p.requestParams.Enabled {
			t.Fatalf("expected request params present and disabled, got hasRequest=%v enabled=%v", p.hasRequestParams, p.requestParams.Enabled)
		}

		action := p.OnRequestBody(context.Background(), &policy.RequestContext{
			Body: &policy.Body{Content: []byte(`{"name":"alice"}`)},
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
			t.Fatalf("expected disabled response flow without schema to be accepted, got %v", err)
		}
		p, ok := pRaw.(*JSONSchemaGuardrailPolicy)
		if !ok {
			t.Fatalf("expected *JSONSchemaGuardrailPolicy, got %T", pRaw)
		}
		if !p.hasResponseParams || p.responseParams.Enabled {
			t.Fatalf("expected response params present and disabled, got hasResponse=%v enabled=%v", p.hasResponseParams, p.responseParams.Enabled)
		}

		action := p.OnResponseBody(context.Background(), &policy.ResponseContext{
			ResponseBody: &policy.Body{Content: []byte(`{"name":"alice"}`)},
		}, nil)
		if _, ok := action.(policy.DownstreamResponseModifications); !ok {
			t.Fatalf("expected response no-op when response.enabled=false, got %T", action)
		}
	})

	t.Run("disabled flow accepts empty schema", func(t *testing.T) {
		pRaw, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{
			"request": map[string]interface{}{
				"enabled": false,
				"schema":  "",
			},
		})
		if err != nil {
			t.Fatalf("expected disabled request flow with empty schema to be accepted, got %v", err)
		}
		p, ok := pRaw.(*JSONSchemaGuardrailPolicy)
		if !ok {
			t.Fatalf("expected *JSONSchemaGuardrailPolicy, got %T", pRaw)
		}
		if p.requestParams.Schema != "" {
			t.Fatalf("expected empty schema to be ignored for disabled flow, got %q", p.requestParams.Schema)
		}
	})
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

func TestValidatePayloadV2_NormalAndInvert(t *testing.T) {
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

func TestValidatePayloadV2_JSONPathAndSchemaErrors(t *testing.T) {
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

func TestBuildErrorResponseV2_ResponsePhase(t *testing.T) {
	p := &JSONSchemaGuardrailPolicy{}
	res := p.buildErrorResponse("test reason", nil, true, false, nil)
	mod, ok := res.(policy.DownstreamResponseModifications)
	if !ok {
		t.Fatalf("expected DownstreamResponseModifications, got %T", res)
	}
	if mod.StatusCode == nil || *mod.StatusCode != GuardrailErrorCode {
		t.Fatalf("expected status %d, got %#v", GuardrailErrorCode, mod.StatusCode)
	}
	if mod.HeadersToSet["Content-Type"] != "application/json" {
		t.Fatalf("expected Content-Type header, got %#v", mod.HeadersToSet)
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

func TestOnRequestBodyAndOnResponseBody(t *testing.T) {
	// No configured phase params -> no-op
	p := &JSONSchemaGuardrailPolicy{}
	reqResult := p.OnRequestBody(context.Background(), &policy.RequestContext{}, nil)
	if _, ok := reqResult.(policy.UpstreamRequestModifications); !ok {
		t.Fatalf("expected UpstreamRequestModifications no-op, got %T", reqResult)
	}
	respResult := p.OnResponseBody(context.Background(), &policy.ResponseContext{}, nil)
	if _, ok := respResult.(policy.DownstreamResponseModifications); !ok {
		t.Fatalf("expected DownstreamResponseModifications no-op, got %T", respResult)
	}

	// Request phase configured, nil body -> validation failure
	p.hasRequestParams = true
	p.requestParams = JSONSchemaGuardrailPolicyParams{
		Enabled: true,
		Schema:  `{"type":"object","required":["name"]}`,
	}
	reqResult = p.OnRequestBody(context.Background(), &policy.RequestContext{Body: nil}, nil)
	if _, ok := reqResult.(policy.ImmediateResponse); !ok {
		t.Fatalf("expected ImmediateResponse on invalid request payload, got %T", reqResult)
	}

	// Response phase configured, nil body -> validation failure
	p.hasResponseParams = true
	p.responseParams = JSONSchemaGuardrailPolicyParams{
		Enabled: true,
		Schema:  `{"type":"object","required":["name"]}`,
	}
	respResult = p.OnResponseBody(context.Background(), &policy.ResponseContext{ResponseBody: nil}, nil)
	respMod, ok := respResult.(policy.DownstreamResponseModifications)
	if !ok {
		t.Fatalf("expected DownstreamResponseModifications on invalid response payload, got %T", respResult)
	}
	if respMod.StatusCode == nil || *respMod.StatusCode != GuardrailErrorCode {
		t.Fatalf("expected status %d, got %#v", GuardrailErrorCode, respMod.StatusCode)
	}

	p.requestParams.Enabled = false
	reqDisabled := p.OnRequestBody(context.Background(), &policy.RequestContext{Body: &policy.Body{Content: []byte(`{"name":"alice"}`)}}, nil)
	if _, ok := reqDisabled.(policy.UpstreamRequestModifications); !ok {
		t.Fatalf("expected request no-op when request.enabled=false, got %T", reqDisabled)
	}

	p.responseParams.Enabled = false
	respDisabled := p.OnResponseBody(context.Background(), &policy.ResponseContext{ResponseBody: &policy.Body{Content: []byte(`{"name":"alice"}`)}}, nil)
	if _, ok := respDisabled.(policy.DownstreamResponseModifications); !ok {
		t.Fatalf("expected response no-op when response.enabled=false, got %T", respDisabled)
	}
}

// TestJSONSchemaGuardrail_InterventionDeclaresFault covers the one funnel every rejection this policy
// makes passes through, in both phases.
func TestJSONSchemaGuardrail_InterventionDeclaresFault(t *testing.T) {
	p := &JSONSchemaGuardrailPolicy{}
	errs := schemaValidationErrors(t,
		`{"type":"object","properties":{"n":{"type":"number"}},"required":["n"]}`,
		`{"n":"not a number"}`)

	t.Run("request phase", func(t *testing.T) {
		action := p.buildErrorResponse("blocked detail", nil, false, false, errs)
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
		action := p.buildErrorResponse("blocked detail", nil, true, false, errs)
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

// TestJSONSchemaGuardrail_AssessmentsGatedByShowAssessment covers the one field that must not leak:
// Assessments frequently holds the very content the guardrail existed to stop, so it is
// populated only where the operator opted in through showAssessment.
func TestJSONSchemaGuardrail_AssessmentsGatedByShowAssessment(t *testing.T) {
	p := &JSONSchemaGuardrailPolicy{}
	errs := schemaValidationErrors(t,
		`{"type":"object","properties":{"n":{"type":"number"}},"required":["n"]}`,
		`{"n":"not a number"}`)

	for _, show := range []bool{false, true} {
		name := "showAssessment=false"
		if show {
			name = "showAssessment=true"
		}
		t.Run(name, func(t *testing.T) {
			action := p.buildErrorResponse("blocked detail", nil, false, show, errs)
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

// TestJSONSchemaGuardrail_ExtractionFailureDeclaresFault pins the JSONPath extraction failure: no check
// ran, so it is not a guardrail verdict. An unreadable request body is the caller's; an
// unreadable response body leaves the policy unable to do its job. The client response is
// the one the policy returned before the fault was declared.
func TestJSONSchemaGuardrail_ExtractionFailureDeclaresFault(t *testing.T) {
	p := &JSONSchemaGuardrailPolicy{}
	params := JSONSchemaGuardrailPolicyParams{JsonPath: "$.text", Schema: `{"type":"string"}`}
	for _, isResponse := range []bool{false, true} {
		got := p.validatePayload([]byte(`not-json`), params, isResponse)
		want := p.buildErrorResponse("Error extracting value from JSONPath", errors.New("unused without showAssessment"), isResponse, false, nil)
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

// TestJSONSchemaGuardrail_ValidateErrorDeclaresFault pins the two ways gojsonschema.Validate
// can fail before reaching a verdict: a configured schema that cannot be loaded is the
// operator's, and content that is not JSON is read like a failed extraction.
func TestJSONSchemaGuardrail_ValidateErrorDeclaresFault(t *testing.T) {
	p := &JSONSchemaGuardrailPolicy{}

	t.Run("unusable schema", func(t *testing.T) {
		params := JSONSchemaGuardrailPolicyParams{Schema: `{"type":"not-a-type"}`}
		for _, isResponse := range []bool{false, true} {
			got := p.validatePayload([]byte(`{"a":1}`), params, isResponse)
			want := p.buildErrorResponse("Error validating schema", errors.New("unused without showAssessment"), isResponse, false, nil)
			wantDirection := policy.DirectionRequest
			if isResponse {
				wantDirection = policy.DirectionResponse
			}
			assertNoVerdictFault(t, got, want, policy.FaultCodeMediationFailed, policy.FaultTypeConfiguration, wantDirection)
		}
	})

	t.Run("content is not JSON", func(t *testing.T) {
		params := JSONSchemaGuardrailPolicyParams{Schema: `{"type":"object"}`}
		got := p.validatePayload([]byte(`not-json`), params, false)
		want := p.buildErrorResponse("Error validating schema", errors.New("unused without showAssessment"), false, false, nil)
		assertNoVerdictFault(t, got, want, policy.FaultCodeInvalidRequestBody, policy.FaultTypeValidation, policy.DirectionRequest)

		got = p.validatePayload([]byte(`not-json`), params, true)
		want = p.buildErrorResponse("Error validating schema", errors.New("unused without showAssessment"), true, false, nil)
		assertNoVerdictFault(t, got, want, policy.FaultCodeMediationFailed, policy.FaultTypeMediation, policy.DirectionResponse)
	})
}
