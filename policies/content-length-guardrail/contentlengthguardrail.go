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

package contentlengthguardrail

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

const (
	GuardrailErrorCode           = 422
	TextCleanRegex               = "^\"|\"$"
	DefaultJSONPath              = "$.messages[-1].content"
	DefaultResponseJSONPath      = "$.choices[0].message.content"
	RequestFlowEnabledByDefault  = true
	ResponseFlowEnabledByDefault = false

	sseDataPrefix               = "data: "
	sseDone                     = "[DONE]"
	sseEventPrefix              = "event:"
	metaKeyResponseRunningBytes = "contentlengthguardrail:response_bytes"
	metaKeyAccJsonBody          = "contentlengthguardrail:json_body"
	DefaultStreamingJsonPath    = "$.choices[0].delta.content"
)

var textCleanRegexCompiled = regexp.MustCompile(TextCleanRegex)

// ContentLengthGuardrailPolicy implements content length validation
type ContentLengthGuardrailPolicy struct {
	hasRequestParams  bool
	hasResponseParams bool
	requestParams     ContentLengthGuardrailPolicyParams
	responseParams    ContentLengthGuardrailPolicyParams
}

type ContentLengthGuardrailPolicyParams struct {
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
	p := &ContentLengthGuardrailPolicy{}

	// Extract and parse request parameters if present
	if requestParamsRaw, ok := params["request"].(map[string]interface{}); ok {
		requestParams, err := parseParams(requestParamsRaw, false)
		if err != nil {
			return nil, fmt.Errorf("invalid request parameters: %w", err)
		}
		p.hasRequestParams = true
		p.requestParams = requestParams
	}

	// Extract and parse response parameters if present
	if responseParamsRaw, ok := params["response"].(map[string]interface{}); ok {
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

	slog.Debug("ContentLengthGuardrail: Policy initialized", "hasRequestParams", p.hasRequestParams, "hasResponseParams", p.hasResponseParams)

	return p, nil
}


func (p *ContentLengthGuardrailPolicy) Mode() policy.ProcessingMode {
	return policy.ProcessingMode{
		RequestHeaderMode:  policy.HeaderModeSkip,
		RequestBodyMode:    policy.BodyModeBuffer,
		ResponseHeaderMode: policy.HeaderModeSkip,
		ResponseBodyMode:   policy.BodyModeStream,
	}
}

// parseParams parses and validates parameters from map to struct
func parseParams(params map[string]interface{}, isResponse bool) (ContentLengthGuardrailPolicyParams, error) {
	result := ContentLengthGuardrailPolicyParams{
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
	}

	if enabledExplicitlyFalse {
		hasMin = false
		hasMax = false
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

// buildAssessmentObject builds the assessment object
func (p *ContentLengthGuardrailPolicy) buildAssessmentObject(reason string, validationError error, isResponse bool, showAssessment bool, min, max int) map[string]interface{} {
	assessment := map[string]interface{}{
		"action":               "GUARDRAIL_INTERVENED",
		"interveningGuardrail": "content-length-guardrail",
	}

	if isResponse {
		assessment["direction"] = "RESPONSE"
	} else {
		assessment["direction"] = "REQUEST"
	}

	if validationError != nil {
		assessment["actionReason"] = reason
	} else {
		assessment["actionReason"] = "Violation of applied content length constraints detected."
	}

	if showAssessment {
		if validationError != nil {
			assessment["assessments"] = validationError.Error()
		} else {
			var assessmentMessage string
			if strings.Contains(reason, "excluded range") {
				assessmentMessage = fmt.Sprintf("Violation of content length detected. Expected content length to be outside the range of %d to %d bytes.", min, max)
			} else {
				assessmentMessage = fmt.Sprintf("Violation of content length detected. Expected content length to be between %d and %d bytes.", min, max)
			}
			assessment["assessments"] = assessmentMessage
		}
	}

	return assessment
}

// OnRequestBody validates request body content length.
func (p *ContentLengthGuardrailPolicy) OnRequestBody(ctx context.Context, reqCtx *policy.RequestContext, _ map[string]interface{}) policy.RequestAction {
	if !p.hasRequestParams || !p.requestParams.Enabled {
		return policy.UpstreamRequestModifications{}
	}

	if reqCtx.Body == nil || reqCtx.Body.Content == nil {
		return policy.ImmediateResponse{
			StatusCode: GuardrailErrorCode,
			Headers:    map[string]string{"Content-Type": "application/json"},
			Body:       []byte(`{"type":"CONTENT_LENGTH_GUARDRAIL","message":"Request body is absent or could not be buffered"}`),
		}
	}

	return p.validatePayload(reqCtx.Body.Content, p.requestParams, false).(policy.RequestAction)
}

// OnResponseBody validates response body content length.
func (p *ContentLengthGuardrailPolicy) OnResponseBody(ctx context.Context, respCtx *policy.ResponseContext, _ map[string]interface{}) policy.ResponseAction {
	if !p.hasResponseParams || !p.responseParams.Enabled {
		return policy.DownstreamResponseModifications{}
	}

	content := []byte{}
	if respCtx.ResponseBody != nil {
		content = respCtx.ResponseBody.Content
	}
	return p.validatePayload(content, p.responseParams, true).(policy.ResponseAction)
}

// validatePayload validates payload content length, returning policy actions.
func (p *ContentLengthGuardrailPolicy) validatePayload(payload []byte, params ContentLengthGuardrailPolicyParams, isResponse bool) interface{} {
	extractedValue, err := extractInspectableText(payload, params.JsonPath)
	if err != nil {
		slog.Debug("ContentLengthGuardrail: Error extracting value from JSONPath", "jsonPath", params.JsonPath, "error", err, "isResponse", isResponse)
		return p.buildErrorResponse("Error extracting value from JSONPath", err, isResponse, params.ShowAssessment, params.Min, params.Max)
	}

	extractedValue = textCleanRegexCompiled.ReplaceAllString(extractedValue, "")
	extractedValue = strings.TrimSpace(extractedValue)

	byteCount := len([]byte(extractedValue))

	isWithinRange := byteCount >= params.Min && byteCount <= params.Max

	var validationPassed bool
	if params.Invert {
		validationPassed = !isWithinRange
	} else {
		validationPassed = isWithinRange
	}

	if !validationPassed {
		slog.Debug("ContentLengthGuardrail: Validation failed", "byteCount", byteCount, "min", params.Min, "max", params.Max, "invert", params.Invert, "isResponse", isResponse)
		var reason string
		if params.Invert {
			reason = fmt.Sprintf("content length %d bytes is within the excluded range %d-%d bytes", byteCount, params.Min, params.Max)
		} else {
			reason = fmt.Sprintf("content length %d bytes is outside the allowed range %d-%d bytes", byteCount, params.Min, params.Max)
		}
		return p.buildErrorResponse(reason, nil, isResponse, params.ShowAssessment, params.Min, params.Max)
	}

	slog.Debug("ContentLengthGuardrail: Validation passed", "byteCount", byteCount, "min", params.Min, "max", params.Max, "isResponse", isResponse)
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
// max enforcement (early termination):
//   NeedsMoreResponseData returns false immediately (no min gate), so each SSE
//   chunk is forwarded to OnResponseBodyChunk straight away. OnResponseBodyChunk
//   maintains a running byte count in ctx.Metadata and injects an SSE error
//   event as soon as the cumulative delta.content byte count exceeds max.
//
// min enforcement (gate-then-stream):
//   When min is configured, NeedsMoreResponseData buffers silently until the
//   accumulated delta.content byte count reaches min, then flushes. From that
//   point OnResponseBodyChunk processes each subsequent chunk individually,
//   using ctx.Metadata to track the cumulative byte count for max enforcement.
//
// invert enforcement:
//   NeedsMoreResponseData buffers until the byte count exceeds max (guaranteed
//   outside the excluded range). If [DONE] arrives while still gated, the full
//   accumulated content is validated in OnResponseBodyChunk.

// NeedsMoreResponseData implements StreamingResponsePolicy.
// Buffers until the gate condition is satisfied — no bytes sent to the client
// during accumulation. Always flushes when [DONE] arrives.
func (p *ContentLengthGuardrailPolicy) NeedsMoreResponseData(accumulated []byte) bool {
	if !p.hasResponseParams || !p.responseParams.Enabled {
		return false
	}
	s := string(accumulated)
	// Non-SSE: don't buffer — the buffered OnResponseBody handles it.
	if !isSSEChunk(s) {
		return false
	}
	// Stream is complete — flush for final validation.
	if strings.Contains(s, sseDataPrefix+sseDone) {
		return false
	}
	byteCount := len([]byte(extractSSEDeltaContent(s, p.responseParams.StreamingJsonPath)))
	rp := p.responseParams
	if rp.Invert {
		// Invert mode: buffer while still within or below the excluded range.
		return byteCount <= rp.Max
	}
	// Normal mode: buffer while below the required minimum.
	return rp.Min > 0 && byteCount < rp.Min
}

// OnResponseBodyChunk implements StreamingResponsePolicy.
// Maintains a running delta.content byte count across chunks and validates
// the content length against the configured min/max thresholds.
func (p *ContentLengthGuardrailPolicy) OnResponseBodyChunk(ctx context.Context, respCtx *policy.ResponseStreamContext, chunk *policy.StreamBody, params map[string]interface{}) policy.StreamingResponseAction {
	if !p.hasResponseParams || !p.responseParams.Enabled {
		return policy.ForwardResponseChunk{}
	}
	if chunk == nil || len(chunk.Chunk) == 0 {
		return policy.ForwardResponseChunk{}
	}

	if respCtx.Metadata == nil {
		respCtx.Metadata = map[string]any{}
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

	// Add this chunk's delta.content bytes to the running total stored in metadata.
	// Metadata persists across OnResponseBodyChunk invocations for the same request.
	prev := 0
	if v, ok := respCtx.Metadata[metaKeyResponseRunningBytes]; ok {
		if n, ok := v.(int); ok {
			prev = n
		}
	}
	chunkContent := extractSSEDeltaContent(chunkStr, rp.StreamingJsonPath)
	running := prev + len([]byte(chunkContent))
	respCtx.Metadata[metaKeyResponseRunningBytes] = running

	isDone := chunk.EndOfStream

	// Max violation: terminate early in normal mode at any point.
	// Invert mode is excluded — it requires the full length at [DONE] to decide.
	if rp.Max > 0 && !rp.Invert && running > rp.Max {
		reason := fmt.Sprintf("content length %d bytes is outside the allowed range %d-%d bytes", running, rp.Min, rp.Max)
		slog.Debug("ContentLengthGuardrail: streaming max violation",
			"runningBytes", running, "max", rp.Max)
		return policy.TerminateResponseChunk{Body: p.buildSSEErrorEvent(reason, rp.ShowAssessment, rp.Min, rp.Max)}
	}

	// At end of stream: perform the complete min/max/invert validation.
	if isDone {
		inRange := running >= rp.Min && (rp.Max == 0 || running <= rp.Max)
		passed := inRange
		if rp.Invert {
			passed = !inRange
		}
		if !passed {
			var reason string
			if rp.Invert {
				reason = fmt.Sprintf("content length %d bytes is within the excluded range %d-%d bytes", running, rp.Min, rp.Max)
			} else {
				reason = fmt.Sprintf("content length %d bytes is outside the allowed range %d-%d bytes", running, rp.Min, rp.Max)
			}
			slog.Debug("ContentLengthGuardrail: streaming validation failed",
				"runningBytes", running, "min", rp.Min, "max", rp.Max, "invert", rp.Invert)
			return policy.TerminateResponseChunk{Body: p.buildSSEErrorEvent(reason, rp.ShowAssessment, rp.Min, rp.Max)}
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

// buildSSEErrorEvent formats a guardrail violation as a single SSE data event
// that replaces the offending chunk. ImmediateResponse is unavailable once
// response headers are committed to the downstream client.
func (p *ContentLengthGuardrailPolicy) buildSSEErrorEvent(reason string, showAssessment bool, min, max int) []byte {
	assessment := p.buildAssessmentObject(reason, nil, true, showAssessment, min, max)
	responseBody := map[string]interface{}{
		"type":    "CONTENT_LENGTH_GUARDRAIL",
		"message": assessment,
	}
	bodyBytes, err := json.Marshal(responseBody)
	if err != nil {
		bodyBytes = []byte(`{"type":"CONTENT_LENGTH_GUARDRAIL","message":"Internal error"}`)
	}
	return []byte(sseDataPrefix + string(bodyBytes) + "\n\n")
}

// buildErrorResponse builds a policy error response for both request and response phases.
func (p *ContentLengthGuardrailPolicy) buildErrorResponse(reason string, validationError error, isResponse bool, showAssessment bool, min, max int) interface{} {
	assessment := p.buildAssessmentObject(reason, validationError, isResponse, showAssessment, min, max)
	analyticsMetadata := map[string]interface{}{
		"isGuardrailHit": true,
		"guardrailName":  "content-length-guardrail",
	}

	responseBody := map[string]interface{}{
		"type":    "CONTENT_LENGTH_GUARDRAIL",
		"message": assessment,
	}

	bodyBytes, err := json.Marshal(responseBody)
	if err != nil {
		bodyBytes = []byte(`{"type":"CONTENT_LENGTH_GUARDRAIL","message":"Internal error"}`)
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
