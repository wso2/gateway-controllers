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

package regexguardrail

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"regexp"
	"strings"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
	utils "github.com/wso2/api-platform/sdk/core/utils"
)

const (
	GuardrailErrorCode           = 422
	DefaultRequestJSONPath       = "$.messages[-1].content"
	DefaultResponseJSONPath      = "$.choices[0].message.content"
	RequestFlowEnabledByDefault  = true
	ResponseFlowEnabledByDefault = false

	sseDataPrefix                     = "data: "
	sseDone                           = "[DONE]"
	sseEventPrefix                    = "event:"
	metaKeyAccumulatedResponseContent = "regexguardrail:accumulated_response_content"
	metaKeyAccJsonBody                = "regexguardrail:json_body"
	DefaultStreamingJsonPath          = "$.choices[0].delta.content"
)

// RegexGuardrailPolicy implements regex-based content validation
type RegexGuardrailPolicy struct {
	hasRequestParams  bool
	hasResponseParams bool
	requestParams     RegexGuardrailPolicyParams
	responseParams    RegexGuardrailPolicyParams
}

type RegexGuardrailPolicyParams struct {
	Enabled           bool
	Regex             string
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
	p := &RegexGuardrailPolicy{}

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

	slog.Debug("RegexGuardrail: Policy initialized", "hasRequestParams", p.hasRequestParams, "hasResponseParams", p.hasResponseParams)

	return p, nil
}


func (p *RegexGuardrailPolicy) Mode() policy.ProcessingMode {
	return policy.ProcessingMode{
		RequestHeaderMode:  policy.HeaderModeSkip,
		RequestBodyMode:    policy.BodyModeBuffer,
		ResponseHeaderMode: policy.HeaderModeSkip,
		ResponseBodyMode:   policy.BodyModeStream,
	}
}

// parseParams parses and validates parameters from map to struct
func parseParams(params map[string]interface{}, defaultJSONPath string, defaultEnabled bool) (RegexGuardrailPolicyParams, error) {
	result := RegexGuardrailPolicyParams{
		Enabled:        defaultEnabled,
		JsonPath:       defaultJSONPath,
		Invert:         false,
		ShowAssessment: false,
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

	regexRaw, hasRegex := params["regex"]
	if !enabledExplicitlyFalse && !hasRegex {
		return result, fmt.Errorf("'regex' parameter is required")
	}

	if enabledExplicitlyFalse {
		hasRegex = false
	}

	if hasRegex {
		regexPattern, ok := regexRaw.(string)
		if !ok {
			return result, fmt.Errorf("'regex' must be a string")
		}
		if regexPattern == "" {
			return result, fmt.Errorf("'regex' cannot be empty")
		}

		// Validate regex is compilable
		_, err := regexp.Compile(regexPattern)
		if err != nil {
			return result, fmt.Errorf("invalid regex pattern: %w", err)
		}
		result.Regex = regexPattern
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

// buildAssessmentObject builds the assessment object
func (p *RegexGuardrailPolicy) buildAssessmentObject(reason string, validationError error, isResponse bool, showAssessment bool) map[string]interface{} {
	assessment := map[string]interface{}{
		"action":               "GUARDRAIL_INTERVENED",
		"interveningGuardrail": "regex-guardrail",
	}

	if isResponse {
		assessment["direction"] = "RESPONSE"
	} else {
		assessment["direction"] = "REQUEST"
	}

	if validationError != nil {
		assessment["actionReason"] = reason
	} else {
		assessment["actionReason"] = "Violation of regular expression detected."
	}

	if showAssessment {
		if validationError != nil {
			assessment["assessments"] = validationError.Error()
		} else {
			var assessmentMessage string
			assessmentMessage = fmt.Sprintf("Violation of regular expression detected. %s", reason)
			assessment["assessments"] = assessmentMessage
		}
	}

	return assessment
}

// OnRequestBody validates request body against regex pattern.
func (p *RegexGuardrailPolicy) OnRequestBody(ctx context.Context, reqCtx *policy.RequestContext, _ map[string]interface{}) policy.RequestAction {
	if !p.hasRequestParams || !p.requestParams.Enabled {
		return policy.UpstreamRequestModifications{}
	}

	var content []byte
	if reqCtx.Body != nil {
		content = reqCtx.Body.Content
	}
	return p.validatePayload(content, p.requestParams, false).(policy.RequestAction)
}

// OnResponseBody validates response body against regex pattern.
func (p *RegexGuardrailPolicy) OnResponseBody(ctx context.Context, respCtx *policy.ResponseContext, _ map[string]interface{}) policy.ResponseAction {
	if !p.hasResponseParams || !p.responseParams.Enabled {
		return policy.DownstreamResponseModifications{}
	}

	var content []byte
	if respCtx.ResponseBody != nil {
		content = respCtx.ResponseBody.Content
	}
	return p.validatePayload(content, p.responseParams, true).(policy.ResponseAction)
}

// validatePayload validates payload against regex pattern, returning policy actions.
func (p *RegexGuardrailPolicy) validatePayload(payload []byte, params RegexGuardrailPolicyParams, isResponse bool) interface{} {
	if len(payload) == 0 {
		if isResponse {
			return policy.DownstreamResponseModifications{}
		}
		return policy.UpstreamRequestModifications{}
	}
	extractedValue, err := extractInspectableText(payload, params.JsonPath)
	if err != nil {
		slog.Debug("RegexGuardrail: Error extracting value from JSONPath", "jsonPath", params.JsonPath, "error", err, "isResponse", isResponse)
		return p.buildErrorResponse("Error extracting value from JSONPath", err, isResponse, params.ShowAssessment)
	}

	compiledRegex, err := regexp.Compile(params.Regex)
	if err != nil {
		slog.Debug("RegexGuardrail: Invalid regex pattern", "regex", params.Regex, "error", err, "isResponse", isResponse)
		return p.buildErrorResponse("Invalid regex pattern", err, isResponse, params.ShowAssessment)
	}
	matched := compiledRegex.MatchString(extractedValue)

	var validationPassed bool
	if params.Invert {
		validationPassed = !matched
	} else {
		validationPassed = matched
	}

	if !validationPassed {
		slog.Debug("RegexGuardrail: Validation failed", "regex", params.Regex, "matched", matched, "invert", params.Invert, "isResponse", isResponse)
		return p.buildErrorResponse("Violated regular expression: "+params.Regex, nil, isResponse, params.ShowAssessment)
	}

	slog.Debug("RegexGuardrail: Validation passed", "regex", params.Regex, "matched", matched, "invert", params.Invert, "isResponse", isResponse)
	if isResponse {
		return policy.DownstreamResponseModifications{}
	}
	return policy.UpstreamRequestModifications{}
}

// ─── Streaming (SSE) support ──────────────────────────────────────────────────
//
// NeedsMoreResponseData and OnResponseBodyChunk together implement
// StreamingResponsePolicy for SSE (stream: true) responses.
//
// Cross-chunk matching: regex patterns can span token boundaries
// (e.g. "forbidden phrase" split across two SSE events). The accumulated
// delta.content is stored in ctx.Metadata so every chunk sees the full text
// seen so far, making cross-boundary matches detectable without inter-chunk
// buffering in NeedsMoreResponseData.
//
// Invert semantics in streaming:
//   - invert=true  (blocklist): violation detected as soon as the pattern
//     appears anywhere in the accumulated content; the offending chunk is
//     replaced with an SSE error event.
//   - invert=false (allowlist): the full response must match the pattern.
//     We can only confirm this at stream end ([DONE]), so an SSE error event
//     is injected at the terminal chunk if no match was found. Content
//     already forwarded to the client cannot be retracted — this is an
//     inherent limitation of response streaming.

// NeedsMoreResponseData implements StreamingResponsePolicy.
// Returns false for every chunk: cross-chunk accumulation is handled via
// ctx.Metadata rather than kernel-level buffering, keeping each SSE event
// flowing to the client without delay.
func (p *RegexGuardrailPolicy) NeedsMoreResponseData(accumulated []byte) bool {
	return false
}

// OnResponseBodyChunk implements StreamingResponsePolicy.
// Validates SSE delta.content against the configured regex pattern,
// accumulating content across chunks so patterns split across token
// boundaries are still caught.
func (p *RegexGuardrailPolicy) OnResponseBodyChunk(ctx context.Context, respCtx *policy.ResponseStreamContext, chunk *policy.StreamBody, params map[string]interface{}) policy.StreamingResponseAction {
	if !p.hasResponseParams || !p.responseParams.Enabled {
		return policy.ForwardResponseChunk{}
	}
	if chunk == nil || len(chunk.Chunk) == 0 {
		return policy.ForwardResponseChunk{}
	}

	if respCtx.Metadata == nil {
		respCtx.Metadata = make(map[string]interface{})
	}

	chunkStr := string(chunk.Chunk)

	if !isSSEChunk(chunkStr) {
		// Plain JSON via chunked transfer (e.g. OpenAI stream:false with Transfer-Encoding: chunked).
		// Accumulate all chunks and validate the complete body at end of stream.
		prev, _ := respCtx.Metadata[metaKeyAccJsonBody].(string)
		full := prev + chunkStr
		respCtx.Metadata[metaKeyAccJsonBody] = full
		if !chunk.EndOfStream {
			return policy.ForwardResponseChunk{}
		}
		result := p.validatePayload([]byte(full), p.responseParams, true)
		if mod, ok := result.(policy.DownstreamResponseModifications); ok && mod.StatusCode != nil {
			return policy.TerminateResponseChunk{Body: mod.Body}
		}
		return policy.ForwardResponseChunk{}
	}

	rp := p.responseParams

	// Accumulate delta.content from this chunk into the running total.
	prev := ""
	if v, ok := respCtx.Metadata[metaKeyAccumulatedResponseContent]; ok {
		if s, ok := v.(string); ok {
			prev = s
		}
	}
	chunkContent := extractSSEDeltaContent(chunkStr, rp.StreamingJsonPath)
	accumulated := prev + chunkContent
	respCtx.Metadata[metaKeyAccumulatedResponseContent] = accumulated

	compiledRegex, err := regexp.Compile(rp.Regex)
	if err != nil {
		// Invalid regex — pass through; the buffered path already caught this.
		return policy.ForwardResponseChunk{}
	}

	matched := compiledRegex.MatchString(accumulated)
	isDone := chunk.EndOfStream

	var violated bool
	if rp.Invert {
		// Blocklist: fail as soon as the prohibited pattern appears.
		violated = matched
	} else {
		// Allowlist: the content must match by the time the stream ends.
		// Intermediate chunks cannot be validated (match may come later).
		if isDone && accumulated != "" {
			violated = !matched
		}
	}

	if violated {
		slog.Debug("RegexGuardrail: streaming validation failed",
			"regex", rp.Regex, "invert", rp.Invert, "chunkIndex", chunk.Index)
		return policy.TerminateResponseChunk{Body: p.buildSSEErrorEvent(rp)}
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

// buildSSEErrorEvent formats a guardrail intervention as a single SSE data
// event, replacing the offending chunk in the stream. ImmediateResponse is
// not available once response headers are committed.
func (p *RegexGuardrailPolicy) buildSSEErrorEvent(rp RegexGuardrailPolicyParams) []byte {
	assessment := p.buildAssessmentObject("Violated regular expression: "+rp.Regex, nil, true, rp.ShowAssessment)
	responseBody := map[string]interface{}{
		"type":    "REGEX_GUARDRAIL",
		"message": assessment,
	}
	bodyBytes, err := json.Marshal(responseBody)
	if err != nil {
		bodyBytes = []byte(`{"type":"REGEX_GUARDRAIL","message":"Internal error"}`)
	}
	return []byte(sseDataPrefix + string(bodyBytes) + "\n\n")
}

// buildErrorResponse builds a policy error response for both request and response phases.
func (p *RegexGuardrailPolicy) buildErrorResponse(reason string, validationError error, isResponse bool, showAssessment bool) interface{} {
	assessment := p.buildAssessmentObject(reason, validationError, isResponse, showAssessment)
	analyticsMetadata := map[string]interface{}{
		"isGuardrailHit": true,
		"guardrailName":  "regex-guardrail",
	}

	responseBody := map[string]interface{}{
		"type":    "REGEX_GUARDRAIL",
		"message": assessment,
	}

	bodyBytes, err := json.Marshal(responseBody)
	if err != nil {
		bodyBytes = []byte(`{"type":"REGEX_GUARDRAIL","message":"Internal error"}`)
	}

	if isResponse {
		statusCode := GuardrailErrorCode
		return policy.DownstreamResponseModifications{
			StatusCode:        &statusCode,
			Body:              bodyBytes,
			AnalyticsMetadata: analyticsMetadata,
			HeadersToSet:      map[string]string{"Content-Type": "application/json"},
		}
	}

	return policy.ImmediateResponse{
		StatusCode:        GuardrailErrorCode,
		AnalyticsMetadata: analyticsMetadata,
		Headers:           map[string]string{"Content-Type": "application/json"},
		Body:              bodyBytes,
	}
}
