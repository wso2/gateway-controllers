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

package sentencecountguardrail

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"regexp"
	"strconv"
	"strings"

	policy "github.com/wso2/api-platform/sdk/gateway/policy/v1alpha"
	utils "github.com/wso2/api-platform/sdk/utils"
)

const (
	GuardrailErrorCode           = 422
	TextCleanRegex               = "^\"|\"$"
	SentenceSplitRegex           = "[.!?]"
	DefaultJSONPath              = "$.messages[-1].content"
	DefaultResponseJSONPath      = "$.choices[0].message.content"
	RequestFlowEnabledByDefault  = true
	ResponseFlowEnabledByDefault = false
)

var (
	textCleanRegexCompiled     = regexp.MustCompile(TextCleanRegex)
	sentenceSplitRegexCompiled = regexp.MustCompile(SentenceSplitRegex)
)

// SentenceCountGuardrailPolicy implements sentence count validation
type SentenceCountGuardrailPolicy struct {
	hasRequestParams  bool
	hasResponseParams bool
	requestParams     SentenceCountGuardrailPolicyParams
	responseParams    SentenceCountGuardrailPolicyParams
}

type SentenceCountGuardrailPolicyParams struct {
	Enabled        bool
	Min            int
	Max            int
	JsonPath       string
	Invert         bool
	ShowAssessment bool
}

func GetPolicy(
	metadata policy.PolicyMetadata,
	params map[string]interface{},
) (policy.Policy, error) {
	p := &SentenceCountGuardrailPolicy{}

	requestParamsRaw, hasRequest, err := getFlowParams(params, "request")
	if err != nil {
		return nil, err
	}
	if hasRequest {
		requestParams, err := parseParams(requestParamsRaw, false)
		if err != nil {
			return nil, fmt.Errorf("invalid request parameters: %w", err)
		}
		p.hasRequestParams = true
		p.requestParams = requestParams
	}

	responseParamsRaw, hasResponse, err := getFlowParams(params, "response")
	if err != nil {
		return nil, err
	}
	if hasResponse {
		responseParams, err := parseParams(responseParamsRaw, true)
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

	slog.Debug("SentenceCountGuardrail: Policy initialized", "hasRequestParams", p.hasRequestParams, "hasResponseParams", p.hasResponseParams)

	return p, nil
}

func getFlowParams(params map[string]interface{}, flow string) (map[string]interface{}, bool, error) {
	raw, exists := params[flow]
	if !exists {
		return nil, false, nil
	}
	flowParams, ok := raw.(map[string]interface{})
	if !ok {
		return nil, false, fmt.Errorf("'%s' must be an object", flow)
	}
	return flowParams, true, nil
}

// parseParams parses and validates parameters from map to struct
func parseParams(params map[string]interface{}, isResponse bool) (SentenceCountGuardrailPolicyParams, error) {
	result := SentenceCountGuardrailPolicyParams{
		JsonPath: DefaultJSONPath,
		Enabled:  RequestFlowEnabledByDefault,
	}
	if isResponse {
		result.JsonPath = DefaultResponseJSONPath
		result.Enabled = ResponseFlowEnabledByDefault
	}

	// Extract optional enabled parameter
	if enabledRaw, ok := params["enabled"]; ok {
		enabled, ok := enabledRaw.(bool)
		if !ok {
			return result, fmt.Errorf("'enabled' must be a boolean")
		}
		result.Enabled = enabled
	}

	// Validate and extract min parameter (required)
	minRaw, ok := params["min"]
	if !ok {
		return result, fmt.Errorf("'min' parameter is required")
	}
	min, err := extractInt(minRaw)
	if err != nil {
		return result, fmt.Errorf("'min' must be a number: %w", err)
	}
	if min < 0 {
		return result, fmt.Errorf("'min' cannot be negative")
	}
	result.Min = min

	// Validate and extract max parameter (required)
	maxRaw, ok := params["max"]
	if !ok {
		return result, fmt.Errorf("'max' parameter is required")
	}
	max, err := extractInt(maxRaw)
	if err != nil {
		return result, fmt.Errorf("'max' must be a number: %w", err)
	}
	if max <= 0 {
		return result, fmt.Errorf("'max' must be greater than 0")
	}
	if min > max {
		return result, fmt.Errorf("'min' cannot be greater than 'max'")
	}
	result.Max = max

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

// extractInt safely extracts an integer from various types
func extractInt(value interface{}) (int, error) {
	switch v := value.(type) {
	case int:
		return v, nil
	case int64:
		return int(v), nil
	case float64:
		if v != float64(int(v)) {
			return 0, fmt.Errorf("expected an integer but got %v", v)
		}
		return int(v), nil
	case string:
		parsed, err := strconv.ParseFloat(v, 64)
		if err != nil {
			return 0, err
		}
		if parsed != float64(int(parsed)) {
			return 0, fmt.Errorf("expected an integer but got %v", v)
		}
		return int(parsed), nil
	default:
		return 0, fmt.Errorf("cannot convert %T to int", value)
	}
}

// Mode returns the processing mode for this policy
func (p *SentenceCountGuardrailPolicy) Mode() policy.ProcessingMode {
	return policy.ProcessingMode{
		RequestHeaderMode:  policy.HeaderModeSkip,
		RequestBodyMode:    policy.BodyModeBuffer,
		ResponseHeaderMode: policy.HeaderModeSkip,
		ResponseBodyMode:   policy.BodyModeBuffer,
	}
}

// OnRequest validates request body sentence count
func (p *SentenceCountGuardrailPolicy) OnRequest(ctx *policy.RequestContext, params map[string]interface{}) policy.RequestAction {
	if !p.hasRequestParams || !p.requestParams.Enabled {
		return policy.UpstreamRequestModifications{}
	}

	var content []byte
	if ctx.Body != nil {
		content = ctx.Body.Content
	}
	return p.validatePayload(content, p.requestParams, false).(policy.RequestAction)
}

// OnResponse validates response body sentence count
func (p *SentenceCountGuardrailPolicy) OnResponse(ctx *policy.ResponseContext, params map[string]interface{}) policy.ResponseAction {
	if !p.hasResponseParams || !p.responseParams.Enabled {
		return policy.UpstreamResponseModifications{}
	}

	var content []byte
	if ctx.ResponseBody != nil {
		content = ctx.ResponseBody.Content
	}
	return p.validatePayload(content, p.responseParams, true).(policy.ResponseAction)
}

// validatePayload validates payload sentence count
func (p *SentenceCountGuardrailPolicy) validatePayload(payload []byte, params SentenceCountGuardrailPolicyParams, isResponse bool) interface{} {
	// Extract value using JSONPath
	extractedValue, err := extractStringFromJSONPath(payload, params.JsonPath)
	if err != nil {
		slog.Debug("SentenceCountGuardrail: Error extracting value from JSONPath", "jsonPath", params.JsonPath, "error", err, "isResponse", isResponse)
		return p.buildErrorResponse("Error extracting value from JSONPath", err, isResponse, params.ShowAssessment, params.Min, params.Max)
	}

	// Clean and trim
	extractedValue = textCleanRegexCompiled.ReplaceAllString(extractedValue, "")
	extractedValue = strings.TrimSpace(extractedValue)

	// Split into sentences and count non-empty
	sentences := sentenceSplitRegexCompiled.Split(extractedValue, -1)
	sentenceCount := 0
	for _, s := range sentences {
		if s != "" {
			sentenceCount++
		}
	}

	// Check if within range
	isWithinRange := sentenceCount >= params.Min && sentenceCount <= params.Max

	var validationPassed bool
	if params.Invert {
		validationPassed = !isWithinRange // Inverted: pass if NOT in range
	} else {
		validationPassed = isWithinRange // Normal: pass if in range
	}

	if !validationPassed {
		slog.Debug("SentenceCountGuardrail: Validation failed", "sentenceCount", sentenceCount, "min", params.Min, "max", params.Max, "invert", params.Invert, "isResponse", isResponse)
		var reason string
		if params.Invert {
			reason = fmt.Sprintf("sentence count %d is within the excluded range %d-%d sentences", sentenceCount, params.Min, params.Max)
		} else {
			reason = fmt.Sprintf("sentence count %d is outside the allowed range %d-%d sentences", sentenceCount, params.Min, params.Max)
		}
		return p.buildErrorResponse(reason, nil, isResponse, params.ShowAssessment, params.Min, params.Max)
	}

	slog.Debug("SentenceCountGuardrail: Validation passed", "sentenceCount", sentenceCount, "min", params.Min, "max", params.Max, "isResponse", isResponse)
	if isResponse {
		return policy.UpstreamResponseModifications{}
	}
	return policy.UpstreamRequestModifications{}
}

func extractStringFromJSONPath(payload []byte, jsonPath string) (string, error) {
	value, err := utils.ExtractStringValueFromJsonpath(payload, jsonPath)
	if err == nil {
		return value, nil
	}

	var jsonData map[string]interface{}
	if unmarshalErr := json.Unmarshal(payload, &jsonData); unmarshalErr != nil {
		return "", unmarshalErr
	}

	extracted, extractErr := utils.ExtractValueFromJsonpath(jsonData, jsonPath)
	if extractErr != nil {
		return "", extractErr
	}

	normalized, normalizeErr := normalizeExtractedValue(extracted)
	if normalizeErr != nil {
		return "", normalizeErr
	}

	return normalized, nil
}

func normalizeExtractedValue(value interface{}) (string, error) {
	switch v := value.(type) {
	case string:
		return v, nil
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64), nil
	case int:
		return strconv.Itoa(v), nil
	case bool:
		return strconv.FormatBool(v), nil
	case map[string]interface{}:
		if content, ok := v["content"]; ok {
			return normalizeExtractedValue(content)
		}
		if text, ok := v["text"]; ok {
			return normalizeExtractedValue(text)
		}
		encoded, err := json.Marshal(v)
		if err != nil {
			return "", err
		}
		return string(encoded), nil
	case []interface{}:
		parts := make([]string, 0, len(v))
		for _, item := range v {
			part, itemErr := normalizeExtractedValue(item)
			if itemErr != nil {
				continue
			}
			part = strings.TrimSpace(part)
			if part != "" {
				parts = append(parts, part)
			}
		}
		if len(parts) == 0 {
			return "", fmt.Errorf("value at JSONPath is an empty array")
		}
		return strings.Join(parts, " "), nil
	default:
		return "", fmt.Errorf("value at JSONPath is not a supported type")
	}
}

// buildErrorResponse builds an error response for both request and response phases
func (p *SentenceCountGuardrailPolicy) buildErrorResponse(reason string, validationError error, isResponse bool, showAssessment bool, min, max int) interface{} {
	assessment := p.buildAssessmentObject(reason, validationError, isResponse, showAssessment, min, max)

	responseBody := map[string]interface{}{
		"type":    "SENTENCE_COUNT_GUARDRAIL",
		"message": assessment,
	}

	bodyBytes, err := json.Marshal(responseBody)
	if err != nil {
		bodyBytes = []byte(`{"type":"SENTENCE_COUNT_GUARDRAIL","message":"Internal error"}`)
	}

	if isResponse {
		statusCode := GuardrailErrorCode
		return policy.UpstreamResponseModifications{
			StatusCode: &statusCode,
			Body:       bodyBytes,
			SetHeaders: map[string]string{
				"Content-Type": "application/json",
			},
		}
	}

	return policy.ImmediateResponse{
		StatusCode: GuardrailErrorCode,
		Headers: map[string]string{
			"Content-Type": "application/json",
		},
		Body: bodyBytes,
	}
}

// buildAssessmentObject builds the assessment object
func (p *SentenceCountGuardrailPolicy) buildAssessmentObject(reason string, validationError error, isResponse bool, showAssessment bool, min, max int) map[string]interface{} {
	assessment := map[string]interface{}{
		"action":               "GUARDRAIL_INTERVENED",
		"interveningGuardrail": "sentence-count-guardrail",
	}

	if isResponse {
		assessment["direction"] = "RESPONSE"
	} else {
		assessment["direction"] = "REQUEST"
	}

	if validationError != nil {
		assessment["actionReason"] = reason
	} else {
		assessment["actionReason"] = "Violation of applied sentence count constraints detected"
	}

	if showAssessment {
		if validationError != nil {
			assessment["assessments"] = validationError.Error()
		} else {
			var assessmentMessage string
			if strings.Contains(reason, "excluded range") {
				assessmentMessage = fmt.Sprintf("Violation of sentence count detected. Expected sentence count to be outside the range of %d to %d sentences.", min, max)
			} else {
				assessmentMessage = fmt.Sprintf("Violation of sentence count detected. Expected sentence count to be between %d and %d sentences.", min, max)
			}
			assessment["assessments"] = assessmentMessage
		}
	}

	return assessment
}
