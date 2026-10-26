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
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"regexp"
	"strconv"
	"strings"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
	utils "github.com/wso2/api-platform/sdk/core/utils"
)

// codeGuardrailIntervened is the specific code for what this guardrail checks —
// how many SENTENCES the content had — so a caller can tell this rejection from another
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
const codeGuardrailIntervened = policy.GuardrailCodeSentenceCount

// guardrailName identifies this guardrail in GuardrailDetails.InterveningGuardrail.
const guardrailName = "sentence-count-guardrail"

const (
	GuardrailErrorCode           = 422
	TextCleanRegex               = "^\"|\"$"
	SentenceSplitRegex           = "[.!?]"
	DefaultJSONPath              = "$.messages[-1].content"
	DefaultResponseJSONPath      = "$.choices[0].message.content"
	RequestFlowEnabledByDefault  = true
	ResponseFlowEnabledByDefault = false

	sseDataPrefix            = "data: "
	sseDone                  = "[DONE]"
	sseEventPrefix           = "event:"
	metaKeyAccContent        = "sentencecountguardrail:accumulated_content"
	metaKeyAccJsonBody       = "sentencecountguardrail:json_body"
	DefaultStreamingJsonPath = "$.choices[0].delta.content"
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
	Enabled           bool
	Min               int
	Max               int
	JsonPath          string
	StreamingJsonPath string
	Invert            bool
	ShowAssessment    bool
}

// GetPolicy is the v1alpha2 factory entry point (loaded by v1alpha2 kernels).
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

func (p *SentenceCountGuardrailPolicy) Mode() policy.ProcessingMode {
	return policy.ProcessingMode{
		RequestHeaderMode:  policy.HeaderModeSkip,
		RequestBodyMode:    policy.BodyModeBuffer,
		ResponseHeaderMode: policy.HeaderModeSkip,
		ResponseBodyMode:   policy.BodyModeStream,
	}
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
	if len(flowParams) == 0 {
		return nil, false, nil
	}
	return flowParams, true, nil
}

// parseParams parses and validates parameters from map to struct
func parseParams(params map[string]interface{}, isResponse bool) (SentenceCountGuardrailPolicyParams, error) {
	result := SentenceCountGuardrailPolicyParams{
		JsonPath:          DefaultJSONPath,
		StreamingJsonPath: DefaultStreamingJsonPath,
		Enabled:           RequestFlowEnabledByDefault,
	}
	enabledExplicitlyFalse := false
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
		enabledExplicitlyFalse = !enabled
	}

	minRaw, hasMin := params["min"]
	maxRaw, hasMax := params["max"]

	if !enabledExplicitlyFalse {
		if !hasMin {
			return result, fmt.Errorf("'min' parameter is required")
		}
		if !hasMax {
			return result, fmt.Errorf("'max' parameter is required")
		}

		if hasMin {
			min, err := extractInt(minRaw)
			if err != nil {
				return result, fmt.Errorf("'min' must be a number: %w", err)
			}
			if min < 0 {
				return result, fmt.Errorf("'min' cannot be negative")
			}
			result.Min = min
		}

		if hasMax {
			max, err := extractInt(maxRaw)
			if err != nil {
				return result, fmt.Errorf("'max' must be a number: %w", err)
			}
			if max <= 0 {
				return result, fmt.Errorf("'max' must be greater than 0")
			}
			result.Max = max
		}

		if hasMin && hasMax && result.Min > result.Max {
			return result, fmt.Errorf("'min' cannot be greater than 'max'")
		}
	}

	// Extract optional jsonPath parameter
	if jsonPathRaw, ok := params["jsonPath"]; ok {
		if jsonPath, ok := jsonPathRaw.(string); ok {
			result.JsonPath = jsonPath
		} else {
			return result, fmt.Errorf("'jsonPath' must be a string")
		}
	}

	// Extract optional streamingJsonPath parameter
	if streamingJsonPathRaw, ok := params["streamingJsonPath"]; ok {
		if streamingJsonPath, ok := streamingJsonPathRaw.(string); ok {
			result.StreamingJsonPath = streamingJsonPath
		} else {
			return result, fmt.Errorf("'streamingJsonPath' must be a string")
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

// buildGuardrailErrorResponse describes the intervention for the gateway: the code and
// class that decide its analytics category, which side was refused, and the guardrail
// envelope this policy already publishes in its response body.
//
// Direction is per phase, not per policy: a request-side hit and a response-side hit are
// operationally different events that share a status code, and only this policy knows
// which it made.
func (p *SentenceCountGuardrailPolicy) buildGuardrailErrorResponse(reason string, validationError error, isResponse, showAssessment bool, min, max int) *policy.FaultDetails {
	assessment := p.buildAssessmentObject(reason, validationError, isResponse, showAssessment, min, max)

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
		Message:   "Violation of applied sentence count constraints detected",
		// reason is the detail of what was blocked. Description is withheld from the
		// response body by every renderer and reaches fault policies only, which is why
		// the detail belongs here rather than in Message.
		Description: reason,
		Guardrail:   guardrail,
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

// OnRequestBody validates request body sentence count.
func (p *SentenceCountGuardrailPolicy) OnRequestBody(ctx context.Context, reqCtx *policy.RequestContext, _ map[string]interface{}) policy.RequestAction {
	if !p.hasRequestParams || !p.requestParams.Enabled {
		return policy.UpstreamRequestModifications{}
	}

	var content []byte
	if reqCtx.Body != nil {
		content = reqCtx.Body.Content
	}
	return p.validatePayload(content, p.requestParams, false).(policy.RequestAction)
}

// OnResponseBody validates response body sentence count.
//
// SSE (stream: true) responses that were buffered as a whole body are handled
// by extracting the full assistant text from delta events and validating that
// directly, bypassing the JSONPath extraction (which targets the non-streaming
// response structure).
func (p *SentenceCountGuardrailPolicy) OnResponseBody(ctx context.Context, respCtx *policy.ResponseContext, _ map[string]interface{}) policy.ResponseAction {
	if !p.hasResponseParams || !p.responseParams.Enabled {
		return policy.DownstreamResponseModifications{}
	}

	var content []byte
	if respCtx.ResponseBody != nil {
		content = respCtx.ResponseBody.Content
	}

	contentStr := string(content)
	if isSSEChunk(contentStr) {
		// SSE body: always use the SSE extraction path, even when all delta content fields are
		// null (e.g. tool-call responses), so we never fall through to JSONPath extraction on
		// SSE-formatted data.
		text := extractSSEDeltaContent(contentStr, p.responseParams.StreamingJsonPath)
		return p.validateSentenceCountInText(text, p.responseParams, true)
	}

	return p.validatePayload(content, p.responseParams, true).(policy.ResponseAction)
}

// validateSentenceCountInText validates sentence count on pre-extracted text,
// bypassing JSONPath extraction. Used for SSE-buffered responses.
func (p *SentenceCountGuardrailPolicy) validateSentenceCountInText(text string, params SentenceCountGuardrailPolicyParams, isResponse bool) policy.ResponseAction {
	text = textCleanRegexCompiled.ReplaceAllString(text, "")
	text = strings.TrimSpace(text)
	count := countSentences(text)

	isWithinRange := count >= params.Min && count <= params.Max
	validationPassed := isWithinRange
	if params.Invert {
		validationPassed = !isWithinRange
	}

	if !validationPassed {
		var reason string
		if params.Invert {
			reason = fmt.Sprintf("sentence count %d is within the excluded range %d-%d sentences", count, params.Min, params.Max)
		} else {
			reason = fmt.Sprintf("sentence count %d is outside the allowed range %d-%d sentences", count, params.Min, params.Max)
		}
		slog.Debug("SentenceCountGuardrail: buffered SSE validation failed",
			"count", count, "min", params.Min, "max", params.Max, "invert", params.Invert)
		return p.buildErrorResponse(reason, nil, isResponse, params.ShowAssessment, params.Min, params.Max).(policy.ResponseAction)
	}

	return policy.DownstreamResponseModifications{}
}

// validatePayload validates payload sentence count, returning policy actions.
func (p *SentenceCountGuardrailPolicy) validatePayload(payload []byte, params SentenceCountGuardrailPolicyParams, isResponse bool) interface{} {
	extractedValue, err := extractStringFromJSONPath(payload, params.JsonPath)
	if err != nil {
		slog.Debug("SentenceCountGuardrail: Error extracting value from JSONPath", "jsonPath", params.JsonPath, "error", err, "isResponse", isResponse)
		return p.buildErrorResponse("Error extracting value from JSONPath", err, isResponse, params.ShowAssessment, params.Min, params.Max)
	}

	extractedValue = textCleanRegexCompiled.ReplaceAllString(extractedValue, "")
	extractedValue = strings.TrimSpace(extractedValue)

	sentences := sentenceSplitRegexCompiled.Split(extractedValue, -1)
	sentenceCount := 0
	for _, s := range sentences {
		if s != "" {
			sentenceCount++
		}
	}

	isWithinRange := sentenceCount >= params.Min && sentenceCount <= params.Max

	var validationPassed bool
	if params.Invert {
		validationPassed = !isWithinRange
	} else {
		validationPassed = isWithinRange
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
		return policy.DownstreamResponseModifications{}
	}
	return policy.UpstreamRequestModifications{}
}

// buildErrorResponse builds a policy error response for both request and response phases.
func (p *SentenceCountGuardrailPolicy) buildErrorResponse(reason string, validationError error, isResponse bool, showAssessment bool, min, max int) interface{} {
	assessment := p.buildAssessmentObject(reason, validationError, isResponse, showAssessment, min, max)
	analyticsMetadata := map[string]interface{}{
		"isGuardrailHit": true,
		"guardrailName":  "sentence-count-guardrail",
	}

	responseBody := map[string]interface{}{
		"type":    "SENTENCE_COUNT_GUARDRAIL",
		"message": assessment,
	}

	bodyBytes, err := json.Marshal(responseBody)
	if err != nil {
		bodyBytes = []byte(`{"type":"SENTENCE_COUNT_GUARDRAIL","message":"Internal error"}`)
	}

	errorResponse := p.buildGuardrailErrorResponse(reason, validationError, isResponse, showAssessment, min, max)

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
		Headers: map[string]string{
			"Content-Type": "application/json",
		},
		Body:    bodyBytes,
		IsFault: true,
		Fault:   errorResponse,
	}
}

// ─── Streaming (SSE) support ──────────────────────────────────────────────────
//
// NeedsMoreResponseData and OnResponseBodyChunk together implement
// StreamingResponsePolicy using a gate-then-stream approach (modelled on the
// pii-masking reference implementation).
//
// min enforcement (gate-then-stream):
//   NeedsMoreResponseData buffers silently until the accumulated sentence count
//   reaches min, then flushes. From that point OnResponseBodyChunk processes
//   each subsequent chunk individually, using ctx.Metadata to track the
//   cumulative sentence count for max enforcement.
//
// invert enforcement:
//   NeedsMoreResponseData buffers until the sentence count exceeds max
//   (guaranteed outside the excluded range). If [DONE] arrives while still
//   gated, the full accumulated content is validated in OnResponseBodyChunk.

// NeedsMoreResponseData implements StreamingResponsePolicy.
// Buffers until the gate condition is satisfied — no bytes sent to the client
// during accumulation. Always flushes when [DONE] arrives.
func (p *SentenceCountGuardrailPolicy) NeedsMoreResponseData(accumulated []byte) bool {
	if !p.hasResponseParams || !p.responseParams.Enabled {
		return false
	}
	s := string(accumulated)
	if !isSSEChunk(s) {
		return false
	}
	// Stream is complete — flush for final validation.
	if strings.Contains(s, sseDataPrefix+sseDone) {
		return false
	}
	count := countSentences(extractSSEDeltaContent(s, p.responseParams.StreamingJsonPath))
	rp := p.responseParams
	if rp.Invert {
		// Invert mode: buffer while still within or below the excluded range.
		return count <= rp.Max
	}
	// Normal mode: buffer while below the required minimum.
	return rp.Min > 0 && count < rp.Min
}

// OnResponseBodyChunk implements StreamingResponsePolicy.
// Receives flushed batches from the kernel accumulator and validates them.
// ctx.Metadata tracks the full accumulated text across windows for accuracy.
func (p *SentenceCountGuardrailPolicy) OnResponseBodyChunk(ctx context.Context, respCtx *policy.ResponseStreamContext, chunk *policy.StreamBody, params map[string]interface{}) policy.StreamingResponseAction {
	if !p.hasResponseParams || !p.responseParams.Enabled {
		return policy.ForwardResponseChunk{}
	}
	if chunk == nil || len(chunk.Chunk) == 0 {
		return policy.ForwardResponseChunk{}
	}
	chunkStr := string(chunk.Chunk)
	if respCtx.Metadata == nil {
		respCtx.Metadata = make(map[string]interface{})
	}
	if !isSSEChunk(chunkStr) {
		// Plain JSON via chunked transfer (e.g. OpenAI stream:false with Transfer-Encoding: chunked).
		// Accumulate all chunks and validate the complete body at end of stream.
		prev, _ := respCtx.Metadata[metaKeyAccJsonBody].(string)
		full := prev + chunkStr
		respCtx.Metadata[metaKeyAccJsonBody] = full
		if !chunk.EndOfStream {
			return policy.ForwardResponseChunk{}
		}
		// An empty or whitespace-only EndOfStream chunk is a bare sentinel that arrives after
		// the SSE [DONE] event (common in many streaming frameworks). In this case all content
		// was already processed by the SSE path, so we must not attempt JSONPath extraction on
		// an empty body. Instead, run the final SSE min/invert check on accumulated SSE content.
		if strings.TrimSpace(full) == "" {
			rp := p.responseParams
			accContent, _ := respCtx.Metadata[metaKeyAccContent].(string)
			count := countSentences(accContent)
			if !rp.Invert {
				if count < rp.Min {
					reason := fmt.Sprintf("sentence count %d is below minimum of %d sentences", count, rp.Min)
					return policy.TerminateResponseChunk{
						Body: p.buildSSEErrorEvent(reason, rp),
						// Ending the stream here is a failure, not a clean close. Nothing else can
						// tell the two apart: the status was committed with the headers long before
						// this chunk arrived.
						IsFault: true,
						Fault:   p.buildGuardrailErrorResponse(reason, nil, true, rp.ShowAssessment, rp.Min, rp.Max),
					}
				}
			} else if count >= rp.Min && count <= rp.Max {
				reason := fmt.Sprintf("sentence count %d is within the excluded range %d-%d sentences", count, rp.Min, rp.Max)
				return policy.TerminateResponseChunk{
					Body: p.buildSSEErrorEvent(reason, rp),
					// Ending the stream here is a failure, not a clean close. Nothing else can
					// tell the two apart: the status was committed with the headers long before
					// this chunk arrived.
					IsFault: true,
					Fault:   p.buildGuardrailErrorResponse(reason, nil, true, rp.ShowAssessment, rp.Min, rp.Max),
				}
			}
			return policy.ForwardResponseChunk{}
		}
		result := p.validatePayload([]byte(full), p.responseParams, true)
		if mod, ok := result.(policy.DownstreamResponseModifications); ok && mod.StatusCode != nil {
			return policy.ForwardResponseChunk{Body: mod.Body}
		}
		return policy.ForwardResponseChunk{}
	}

	rp := p.responseParams

	// Append this batch's delta content to the running total stored in metadata
	// so that countSentences always operates on the full text seen so far,
	// avoiding off-by-one errors at flush-window boundaries.
	prev := ""
	if v, ok := respCtx.Metadata[metaKeyAccContent]; ok {
		if s, ok := v.(string); ok {
			prev = s
		}
	}
	fullContent := prev + extractSSEDeltaContent(chunkStr, rp.StreamingJsonPath)
	respCtx.Metadata[metaKeyAccContent] = fullContent
	count := countSentences(fullContent)
	isDone := chunk.EndOfStream

	if !rp.Invert {
		// Normal mode: max violation at any point, or below min at [DONE].
		if rp.Max > 0 && count > rp.Max {
			slog.Debug("SentenceCountGuardrail: max exceeded",
				"count", count, "max", rp.Max, "chunkIndex", chunk.Index)
			reason := fmt.Sprintf("sentence count %d exceeded maximum of %d sentences", count, rp.Max)
			return policy.TerminateResponseChunk{
				Body: p.buildSSEErrorEvent(reason, rp),
				// Ending the stream here is a failure, not a clean close. Nothing else can
				// tell the two apart: the status was committed with the headers long before
				// this chunk arrived.
				IsFault: true,
				Fault:   p.buildGuardrailErrorResponse(reason, nil, true, rp.ShowAssessment, rp.Min, rp.Max),
			}
		}
		if isDone && count < rp.Min {
			slog.Debug("SentenceCountGuardrail: below min at stream end",
				"count", count, "min", rp.Min, "chunkIndex", chunk.Index)
			reason := fmt.Sprintf("sentence count %d is below minimum of %d sentences", count, rp.Min)
			return policy.TerminateResponseChunk{
				Body: p.buildSSEErrorEvent(reason, rp),
				// Ending the stream here is a failure, not a clean close. Nothing else can
				// tell the two apart: the status was committed with the headers long before
				// this chunk arrived.
				IsFault: true,
				Fault:   p.buildGuardrailErrorResponse(reason, nil, true, rp.ShowAssessment, rp.Min, rp.Max),
			}
		}
		return policy.ForwardResponseChunk{}
	}

	// Invert mode: at [DONE], check if count falls within the excluded range.
	if isDone {
		if count >= rp.Min && count <= rp.Max {
			slog.Debug("SentenceCountGuardrail: invert violation at stream end",
				"count", count, "min", rp.Min, "max", rp.Max, "chunkIndex", chunk.Index)
			reason := fmt.Sprintf("sentence count %d is within the excluded range %d-%d sentences", count, rp.Min, rp.Max)
			return policy.TerminateResponseChunk{
				Body: p.buildSSEErrorEvent(reason, rp),
				// Ending the stream here is a failure, not a clean close. Nothing else can
				// tell the two apart: the status was committed with the headers long before
				// this chunk arrived.
				IsFault: true,
				Fault:   p.buildGuardrailErrorResponse(reason, nil, true, rp.ShowAssessment, rp.Min, rp.Max),
			}
		}
	}
	return policy.ForwardResponseChunk{}
}

// isSSEChunk reports whether s looks like SSE data (has at least one "data: " or "event:" line).
func isSSEChunk(s string) bool {
	for _, line := range strings.SplitN(s, "\n", 5) {
		if strings.HasPrefix(line, sseDataPrefix) || strings.HasPrefix(line, sseEventPrefix) {
			return true
		}
	}
	return false
}

// extractSSEDeltaContent extracts and concatenates content values from every
// complete SSE data line in s using the provided streamingJsonPath.
// Returns "" for non-SSE or empty content.
func extractSSEDeltaContent(s string, streamingJsonPath string) string {
	var sb strings.Builder
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimRight(line, "\r")
		var value string
		if strings.HasPrefix(line, sseDataPrefix) {
			value = strings.TrimPrefix(line, sseDataPrefix)
		} else if strings.HasPrefix(line, sseEventPrefix) {
			value = strings.TrimSpace(strings.TrimPrefix(line, sseEventPrefix))
		} else {
			continue
		}
		if value == sseDone || value == "" {
			continue
		}
		// Try extracting from streamingJsonPath
		if text, err := utils.ExtractStringValueFromJsonpath([]byte(value), streamingJsonPath); err == nil {
			sb.WriteString(text)
			continue
		}
		var jsonData map[string]interface{}
		if err := json.Unmarshal([]byte(value), &jsonData); err != nil {
			// Not JSON — use the entire value as content
			sb.WriteString(value)
			continue
		}
		val, err := utils.ExtractValueFromJsonpath(jsonData, streamingJsonPath)
		if err != nil {
			sb.WriteString(value)
			continue
		}
		sb.WriteString(joinSSEFragments(val))
	}
	return sb.String()
}

// joinSSEFragments converts an extracted JSONPath value to a string.
// Array elements are concatenated without a separator because SSE delta
// fragments must be joined as-is without artificial whitespace.
func joinSSEFragments(value interface{}) string {
	switch v := value.(type) {
	case string:
		return v
	case []interface{}:
		var sb strings.Builder
		for _, item := range v {
			if s, ok := item.(string); ok {
				sb.WriteString(s)
			}
		}
		return sb.String()
	default:
		return ""
	}
}

// countSentences counts non-empty sentence segments in accumulated text.
func countSentences(text string) int {
	text = textCleanRegexCompiled.ReplaceAllString(text, "")
	text = strings.TrimSpace(text)
	sentences := sentenceSplitRegexCompiled.Split(text, -1)
	count := 0
	for _, s := range sentences {
		if strings.TrimSpace(s) != "" {
			count++
		}
	}
	return count
}

// buildSSEErrorEvent formats a guardrail intervention as a single SSE data event.
func (p *SentenceCountGuardrailPolicy) buildSSEErrorEvent(reason string, rp SentenceCountGuardrailPolicyParams) []byte {
	assessment := p.buildAssessmentObject(reason, nil, true, rp.ShowAssessment, rp.Min, rp.Max)
	responseBody := map[string]interface{}{
		"type":    "SENTENCE_COUNT_GUARDRAIL",
		"message": assessment,
	}
	bodyBytes, err := json.Marshal(responseBody)
	if err != nil {
		bodyBytes = []byte(`{"type":"SENTENCE_COUNT_GUARDRAIL","message":"Internal error"}`)
	}
	return []byte(sseDataPrefix + string(bodyBytes) + "\n\n")
}
