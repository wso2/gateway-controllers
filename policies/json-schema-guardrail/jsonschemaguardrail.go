/*
 *  Copyright (c) 2026, WSO2 LLC. (http://www.wso2.org) All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

package jsonschemaguardrail

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
	utils "github.com/wso2/api-platform/sdk/core/utils"
	"github.com/xeipuuv/gojsonschema"
)

// codeGuardrailIntervened is the specific code for what this guardrail checks —
// whether the content matched a SCHEMA — so a caller can tell this rejection from another
// guardrail's without parsing a message. The name is unchanged so every call site reads the
// same; only the value moved.
//
// The tradeoff, stated because it is real: 906xxx sits OUTSIDE carbon's guardrail range
// [900514, 900515), which is exactly one code wide. Carbon-compatible analytics assigns a
// fault category by range membership, so this classifies as "other" rather than
// "guardrail" there. Accepted deliberately: the code identifies the rejection, and the
// class is already carried by FaultDetails.Type ("guardrail") and by
// GuardrailDetails.InterveningGuardrail. See policy.GuardrailCodeIntervened for the full
// reasoning, and use that generic code for a guardrail with nothing specific to say.
const codeGuardrailIntervened = policy.GuardrailCodeSchema

// guardrailName identifies this guardrail in GuardrailDetails.InterveningGuardrail.
const guardrailName = "json-schema-guardrail"

const (
	GuardrailErrorCode           = 422
	DefaultRequestJSONPath       = "$.messages[-1].content"
	DefaultResponseJSONPath      = "$.choices[0].message.content"
	RequestFlowEnabledByDefault  = false
	ResponseFlowEnabledByDefault = true
)

// JSONSchemaGuardrailPolicy implements JSON schema validation
type JSONSchemaGuardrailPolicy struct {
	hasRequestParams  bool
	hasResponseParams bool
	requestParams     JSONSchemaGuardrailPolicyParams
	responseParams    JSONSchemaGuardrailPolicyParams
}

type JSONSchemaGuardrailPolicyParams struct {
	Enabled        bool
	Schema         string
	JsonPath       string
	Invert         bool
	ShowAssessment bool
}

// GetPolicy is the v1alpha2 factory entry point (loaded by v1alpha2 kernels).
func GetPolicy(
	metadata policy.PolicyMetadata,
	params map[string]interface{},
) (policy.Policy, error) {
	p := &JSONSchemaGuardrailPolicy{}

	// Extract and parse request parameters if present
	if requestParamsRaw, ok := params["request"].(map[string]interface{}); ok {
		requestParams, err := parseParams(requestParamsRaw, DefaultRequestJSONPath, RequestFlowEnabledByDefault)
		if err != nil {
			return nil, fmt.Errorf("invalid request parameters: %w", err)
		}
		p.hasRequestParams = true
		p.requestParams = requestParams
	}

	// Extract and parse response parameters if present
	if responseParamsRaw, ok := params["response"].(map[string]interface{}); ok {
		responseParams, err := parseParams(responseParamsRaw, DefaultResponseJSONPath, ResponseFlowEnabledByDefault)
		if err != nil {
			return nil, fmt.Errorf("invalid response parameters: %w", err)
		}
		p.hasResponseParams = true
		p.responseParams = responseParams
	}

	// At least one of request or response must be present
	if !p.hasRequestParams && !p.hasResponseParams {
		return nil, fmt.Errorf("at least one of 'request' or 'response' parameters must be provided")
	}

	slog.Debug("JSONSchemaGuardrail: Policy initialized", "hasRequestParams", p.hasRequestParams, "hasResponseParams", p.hasResponseParams)

	return p, nil
}


func (p *JSONSchemaGuardrailPolicy) Mode() policy.ProcessingMode {
	return policy.ProcessingMode{
		RequestHeaderMode:  policy.HeaderModeSkip,
		RequestBodyMode:    policy.BodyModeBuffer,
		ResponseHeaderMode: policy.HeaderModeSkip,
		ResponseBodyMode:   policy.BodyModeBuffer,
	}
}

// parseParams parses and validates parameters from map to struct
func parseParams(params map[string]interface{}, defaultJSONPath string, defaultEnabled bool) (JSONSchemaGuardrailPolicyParams, error) {
	result := JSONSchemaGuardrailPolicyParams{
		Enabled:  defaultEnabled,
		JsonPath: defaultJSONPath,
	}
	enabledExplicitlyFalse := false

	// Extract optional enabled parameter
	if enabledRaw, ok := params["enabled"]; ok {
		enabled, ok := enabledRaw.(bool)
		if !ok {
			return result, fmt.Errorf("'enabled' must be a boolean")
		}
		result.Enabled = enabled
		enabledExplicitlyFalse = !enabled
	}

	schemaRaw, hasSchema := params["schema"]
	if !enabledExplicitlyFalse && !hasSchema {
		return result, fmt.Errorf("'schema' parameter is required")
	}

	if enabledExplicitlyFalse {
		hasSchema = false
	}

	if hasSchema {
		schema, ok := schemaRaw.(string)
		if !ok {
			return result, fmt.Errorf("'schema' must be a string")
		}
		if schema == "" {
			return result, fmt.Errorf("'schema' cannot be empty")
		}

		// Validate schema is valid JSON
		var schemaJSON interface{}
		if err := json.Unmarshal([]byte(schema), &schemaJSON); err != nil {
			return result, fmt.Errorf("'schema' must be valid JSON: %v", err)
		}
		result.Schema = schema
	}

	// Extract optional jsonPath parameter
	if jsonPathRaw, ok := params["jsonPath"]; ok {
		if jsonPath, ok := jsonPathRaw.(string); ok {
			result.JsonPath = jsonPath
		} else {
			return result, fmt.Errorf("'jsonPath' must be a string")
		}
	}

	// Extract optional invert parameter
	if invertRaw, ok := params["invert"]; ok {
		if invert, ok := invertRaw.(bool); ok {
			result.Invert = invert
		} else {
			return result, fmt.Errorf("'invert' must be a boolean")
		}
	}

	// Extract optional showAssessment parameter
	if showAssessmentRaw, ok := params["showAssessment"]; ok {
		if showAssessment, ok := showAssessmentRaw.(bool); ok {
			result.ShowAssessment = showAssessment
		} else {
			return result, fmt.Errorf("'showAssessment' must be a boolean")
		}
	}

	return result, nil
}

// extractValueFromJSONPathForSchema extracts a value from JSON using JSONPath and returns as JSON bytes
func extractValueFromJSONPathForSchema(payload []byte, jsonPath string) ([]byte, error) {
	var any interface{}
	if err := json.Unmarshal(payload, &any); err != nil {
		return nil, fmt.Errorf("error unmarshaling JSON: %w", err)
	}
	jsonData, ok := any.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("jsonPath extraction requires a JSON object payload (got %T)", any)
	}

	value, err := utils.ExtractValueFromJsonpath(jsonData, jsonPath)
	if err != nil {
		return nil, err
	}

	// Marshal back to JSON
	valueBytes, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("error marshaling extracted value: %w", err)
	}

	return valueBytes, nil
}

// buildGuardrailErrorResponse describes the intervention for the gateway: the code and
// class that decide its analytics category, which side was refused, and the guardrail
// envelope this policy already publishes in its response body.
//
// Direction is per phase, not per policy: a request-side hit and a response-side hit are
// operationally different events that share a status code, and only this policy knows
// which it made.
func (p *JSONSchemaGuardrailPolicy) buildGuardrailErrorResponse(reason string, validationError error, isResponse, showAssessment bool, errors []gojsonschema.ResultError) *policy.FaultDetails {
	assessment := p.buildAssessmentObject(reason, validationError, isResponse, showAssessment, errors)

	direction := policy.DirectionRequest
	if isResponse {
		direction = policy.DirectionResponse
	}

	actionReason, _ := assessment["actionReason"].(string)

	guardrail := &policy.GuardrailDetails{
		InterveningGuardrail: guardrailName,
		Action:               policy.GuardrailActionIntervened,
		ActionReason:         actionReason,
	}
	// Assessments carries the content the guardrail existed to stop, so it is populated
	// only where the operator already opted in through showAssessment — the same gate the
	// published response envelope uses.
	if raw, ok := assessment["assessments"]; ok {
		guardrail.Assessments = map[string]any{"assessments": raw}
	}

	return &policy.FaultDetails{
		Code:      codeGuardrailIntervened,
		Type:      policy.FaultTypeGuardrail,
		Direction: direction,
		Message:   "Violation of the configured JSON schema detected",
		// reason is the detail of what was blocked. Description is withheld from the
		// response body by every renderer and reaches fault policies only, which is why
		// the detail belongs here rather than in Message.
		Description: reason,
		Guardrail:   guardrail,
	}
}

// extractionFault describes a rejection made because the value at jsonPath could not be
// read, so no check ran and there is no guardrail verdict to report. On a request the
// payload is the caller's, so it is an invalid request body; on a response it is the
// upstream's, and the policy could not do its job.
func extractionFault(reason string, err error, isResponse bool) *policy.FaultDetails {
	if isResponse {
		return &policy.FaultDetails{
			Code:        policy.FaultCodeMediationFailed,
			Type:        policy.FaultTypeMediation,
			Direction:   policy.DirectionResponse,
			Message:     "The response body could not be read for the guardrail check",
			Description: reason + ": " + err.Error(),
		}
	}
	return &policy.FaultDetails{
		Code:        policy.FaultCodeInvalidRequestBody,
		Type:        policy.FaultTypeValidation,
		Direction:   policy.DirectionRequest,
		Message:     "The request body could not be read for the guardrail check",
		Description: reason + ": " + err.Error(),
	}
}

// checkFailureFault describes a rejection made because the policy could not run its check
// at all, so there is no guardrail verdict to report: the policy failed its own job.
// faultType is policy.FaultTypeConfiguration when the policy's own parameters are what
// cannot be used, otherwise policy.FaultTypeMediation.
func checkFailureFault(faultType, reason string, err error, isResponse bool) *policy.FaultDetails {
	direction := policy.DirectionRequest
	if isResponse {
		direction = policy.DirectionResponse
	}
	return &policy.FaultDetails{
		Code:        policy.FaultCodeMediationFailed,
		Type:        faultType,
		Direction:   direction,
		Message:     "The guardrail check could not be completed",
		Description: reason + ": " + err.Error(),
	}
}

// withFault replaces the fault an error response declares, leaving its status, headers
// and body exactly as they are.
func withFault(action interface{}, fault *policy.FaultDetails) interface{} {
	switch a := action.(type) {
	case policy.ImmediateResponse:
		a.Fault = fault
		return a
	case policy.DownstreamResponseModifications:
		a.Fault = fault
		return a
	}
	return action
}

// buildAssessmentObject builds the assessment object
func (p *JSONSchemaGuardrailPolicy) buildAssessmentObject(reason string, validationError error, isResponse bool, showAssessment bool, errors []gojsonschema.ResultError) map[string]interface{} {
	assessment := map[string]interface{}{
		"action":               "GUARDRAIL_INTERVENED",
		"interveningGuardrail": "json-schema-guardrail",
	}

	if isResponse {
		assessment["direction"] = "RESPONSE"
	} else {
		assessment["direction"] = "REQUEST"
	}

	if validationError != nil {
		assessment["actionReason"] = reason
	} else {
		assessment["actionReason"] = "Violation of JSON schema detected."
	}

	if showAssessment {
		if validationError != nil {
			assessment["assessments"] = validationError.Error()
		} else if len(errors) > 0 {
			errorDetails := make([]map[string]interface{}, 0, len(errors))
			for _, err := range errors {
				errorDetails = append(errorDetails, map[string]interface{}{
					"field":       err.Field(),
					"description": err.Description(),
					"value":       err.Value(),
				})
			}
			assessment["assessments"] = errorDetails
		}
	}

	return assessment
}

// OnRequestBody validates request body against JSON schema.
func (p *JSONSchemaGuardrailPolicy) OnRequestBody(ctx context.Context, reqCtx *policy.RequestContext, _ map[string]interface{}) policy.RequestAction {
	if !p.hasRequestParams || !p.requestParams.Enabled {
		return policy.UpstreamRequestModifications{}
	}

	content := []byte{}
	if reqCtx.Body != nil {
		content = reqCtx.Body.Content
	}
	return p.validatePayload(content, p.requestParams, false).(policy.RequestAction)
}

// OnResponseBody validates response body against JSON schema.
func (p *JSONSchemaGuardrailPolicy) OnResponseBody(ctx context.Context, respCtx *policy.ResponseContext, _ map[string]interface{}) policy.ResponseAction {
	if !p.hasResponseParams || !p.responseParams.Enabled {
		return policy.DownstreamResponseModifications{}
	}

	content := []byte{}
	if respCtx.ResponseBody != nil {
		content = respCtx.ResponseBody.Content
	}
	return p.validatePayload(content, p.responseParams, true).(policy.ResponseAction)
}

// validatePayload validates payload against JSON schema, returning policy actions.
func (p *JSONSchemaGuardrailPolicy) validatePayload(payload []byte, params JSONSchemaGuardrailPolicyParams, isResponse bool) interface{} {
	schemaLoader := gojsonschema.NewStringLoader(params.Schema)

	var documentLoader gojsonschema.JSONLoader
	if params.JsonPath != "" {
		extractedValue, err := extractValueFromJSONPathForSchema(payload, params.JsonPath)
		if err != nil {
			slog.Debug("JSONSchemaGuardrail: Error extracting value from JSONPath", "jsonPath", params.JsonPath, "error", err, "isResponse", isResponse)
			return withFault(p.buildErrorResponse("Error extracting value from JSONPath", err, isResponse, params.ShowAssessment, nil), extractionFault("Error extracting value from JSONPath", err, isResponse))
		}
		documentLoader = gojsonschema.NewBytesLoader(extractedValue)
	} else {
		documentLoader = gojsonschema.NewBytesLoader(payload)
	}

	result, err := gojsonschema.Validate(schemaLoader, documentLoader)
	if err != nil {
		slog.Debug("JSONSchemaGuardrail: Error validating schema", "error", err, "isResponse", isResponse)
		// Validate fails either because the configured schema cannot be loaded, or because
		// the content is not JSON. Only the first is the policy's own failure.
		fault := extractionFault("Error validating schema", err, isResponse)
		if _, schemaErr := gojsonschema.NewSchema(schemaLoader); schemaErr != nil {
			fault = checkFailureFault(policy.FaultTypeConfiguration, "Error validating schema", err, isResponse)
		}
		return withFault(p.buildErrorResponse("Error validating schema", err, isResponse, params.ShowAssessment, nil), fault)
	}

	var validationPassed bool
	if params.Invert {
		validationPassed = !result.Valid()
	} else {
		validationPassed = result.Valid()
	}

	if !validationPassed {
		slog.Debug("JSONSchemaGuardrail: Validation failed", "valid", result.Valid(), "invert", params.Invert, "errorCount", len(result.Errors()), "isResponse", isResponse)
		var reason string
		if params.Invert {
			reason = "JSON schema validation passed but invert is enabled"
		} else {
			reason = "JSON schema validation failed"
		}
		return p.buildErrorResponse(reason, nil, isResponse, params.ShowAssessment, result.Errors())
	}

	slog.Debug("JSONSchemaGuardrail: Validation passed", "invert", params.Invert, "isResponse", isResponse)
	if isResponse {
		return policy.DownstreamResponseModifications{}
	}
	return policy.UpstreamRequestModifications{}
}

// buildErrorResponse builds a policy error response for both request and response phases.
func (p *JSONSchemaGuardrailPolicy) buildErrorResponse(reason string, validationError error, isResponse bool, showAssessment bool, errors []gojsonschema.ResultError) interface{} {
	assessment := p.buildAssessmentObject(reason, validationError, isResponse, showAssessment, errors)
	analyticsMetadata := map[string]interface{}{
		"isGuardrailHit": true,
		"guardrailName":  "json-schema-guardrail",
	}

	responseBody := map[string]interface{}{
		"type":    "JSON_SCHEMA_GUARDRAIL",
		"message": assessment,
	}

	bodyBytes, err := json.Marshal(responseBody)
	if err != nil {
		bodyBytes = []byte(`{"type":"JSON_SCHEMA_GUARDRAIL","message":"Internal error"}`)
	}

	errorResponse := p.buildGuardrailErrorResponse(reason, validationError, isResponse, showAssessment, errors)

	if isResponse {
		statusCode := GuardrailErrorCode
		return policy.DownstreamResponseModifications{
			StatusCode:        &statusCode,
			Body:              bodyBytes,
			AnalyticsMetadata: analyticsMetadata,
			HeadersToSet:      map[string]string{"Content-Type": "application/json"},
			IsFault:           true,
			Fault:             errorResponse,
		}
	}

	return policy.ImmediateResponse{
		StatusCode:        GuardrailErrorCode,
		AnalyticsMetadata: analyticsMetadata,
		Headers:           map[string]string{"Content-Type": "application/json"},
		Body:              bodyBytes,
		IsFault:           true,
		Fault:             errorResponse,
	}
}
