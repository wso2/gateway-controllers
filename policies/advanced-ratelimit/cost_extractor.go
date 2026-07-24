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

package ratelimit

import (
	"fmt"
	"log/slog"
	"strconv"
	"strings"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
	utils "github.com/wso2/api-platform/sdk/core/utils"
)

// CostSourceType defines the type of source for cost extraction
type CostSourceType string

const (
	// Request phase sources
	CostSourceRequestHeader   CostSourceType = "request_header"
	CostSourceRequestMetadata CostSourceType = "request_metadata"
	CostSourceRequestBody     CostSourceType = "request_body"
	CostSourceRequestCEL      CostSourceType = "request_cel"

	// Response phase sources
	CostSourceResponseHeader   CostSourceType = "response_header"
	CostSourceResponseMetadata CostSourceType = "response_metadata"
	CostSourceResponseBody     CostSourceType = "response_body"
	CostSourceResponseCEL      CostSourceType = "response_cel"
)

// CostSource represents a single source for extracting cost
type CostSource struct {
	Type       CostSourceType // source type
	Key        string         // Header name or metadata key
	JSONPath   string         // For body types: JSONPath expression
	Expression string         // For CEL types: CEL expression
	Multiplier float64        // Multiplier for extracted value (default: 1.0)
}

// CostExtractionConfig holds the configuration for cost extraction
type CostExtractionConfig struct {
	Enabled bool
	Sources []CostSource
	Default float64 // Default cost if all sources fail
}

// CostExtractor handles extracting cost from request/response data
type CostExtractor struct {
	config CostExtractionConfig
}

// NewCostExtractor creates a new CostExtractor with the given configuration
func NewCostExtractor(config CostExtractionConfig) *CostExtractor {
	return &CostExtractor{config: config}
}

// GetConfig returns the cost extraction configuration
func (e *CostExtractor) GetConfig() CostExtractionConfig {
	return e.config
}

func (e *CostExtractor) ExtractRequestCost(reqCtx *policy.RequestContext) (float64, bool) {
	if !e.config.Enabled {
		slog.Debug("Cost extraction disabled, returning default", "default", e.config.Default)
		return e.config.Default, false
	}

	slog.Debug("Extracting request cost",
		"sourceCount", len(e.config.Sources),
		"default", e.config.Default)

	var total float64
	var found bool

	for _, source := range e.config.Sources {
		if !isRequestPhaseSource(source.Type) {
			slog.Debug("Skipping non-request phase source",
				"type", source.Type)
			continue
		}

		slog.Debug("Attempting request cost extraction",
			"type", source.Type,
			"key", source.Key,
			"jsonPath", source.JSONPath)

		val, ok := e.extractFromRequestSource(reqCtx, source)
		if ok {
			found = true
			total += val * source.Multiplier
			slog.Debug("Request cost extracted from source",
				"type", source.Type,
				"key", source.Key,
				"jsonPath", source.JSONPath,
				"rawValue", val,
				"multiplier", source.Multiplier,
				"contribution", val*source.Multiplier)
		} else {
			slog.Debug("Failed to extract cost from source",
				"type", source.Type,
				"key", source.Key)
		}
	}

	if !found {
		slog.Debug("All request cost extraction sources failed, using default",
			"default", e.config.Default)
		return e.config.Default, false
	}

	if total < 0 {
		slog.Warn("Total cost from request sources is negative; clamping to zero", "cost", total)
		total = 0
	}

	slog.Debug("Request cost extracted successfully", "totalCost", total)
	return total, true
}

// ExtractResponseCost extracts cost from response-phase sources for v1alpha2 contexts.
// This mirrors ExtractResponseCost but accepts *policy.ResponseContext.
func (e *CostExtractor) ExtractResponseCost(respCtx *policy.ResponseContext) (float64, bool) {
	if !e.config.Enabled {
		slog.Debug("Cost extraction disabled, returning default", "default", e.config.Default)
		return e.config.Default, false
	}

	slog.Debug("Extracting response cost (v2)",
		"sourceCount", len(e.config.Sources),
		"default", e.config.Default)

	var total float64
	var found bool

	for _, source := range e.config.Sources {
		if !isResponsePhaseSource(source.Type) {
			slog.Debug("Skipping non-response phase source", "type", source.Type)
			continue
		}

		val, ok := e.extractFromResponseSource(respCtx, source)
		if ok {
			found = true
			total += val * source.Multiplier
			slog.Debug("Response cost extracted from source (v2)",
				"type", source.Type,
				"key", source.Key,
				"rawValue", val,
				"multiplier", source.Multiplier,
				"contribution", val*source.Multiplier)
		} else {
			slog.Debug("Failed to extract cost from source (v2)",
				"type", source.Type,
				"key", source.Key)
		}
	}

	if !found {
		slog.Debug("All response cost extraction sources failed (v2), using default",
			"default", e.config.Default)
		return e.config.Default, false
	}

	if total < 0 {
		slog.Warn("Total cost from response sources is negative; clamping to zero", "cost", total)
		total = 0
	}

	slog.Debug("Response cost extracted successfully (v2)", "totalCost", total)
	return total, true
}

func (e *CostExtractor) extractFromResponseSource(respCtx *policy.ResponseContext, source CostSource) (float64, bool) {
	switch source.Type {
	case CostSourceResponseHeader:
		return e.extractFromResponseHeader(respCtx, source.Key)
	case CostSourceResponseMetadata:
		return e.extractFromResponseMetadata(respCtx, source.Key)
	case CostSourceResponseBody:
		return e.extractFromResponseBody(respCtx, source.JSONPath)
	case CostSourceResponseCEL:
		return e.extractFromResponseCEL(respCtx, source.Expression)
	default:
		slog.Debug("Unsupported response cost source type for v1alpha2", "type", source.Type)
		return 0, false
	}
}

func (e *CostExtractor) extractFromResponseCEL(respCtx *policy.ResponseContext, expression string) (float64, bool) {
	evaluator, err := GetCELEvaluator()
	if err != nil {
		slog.Error("Failed to get CEL evaluator for response cost extraction (v2)", "error", err)
		return 0, false
	}

	cost, err := evaluator.EvaluateResponseCostExpression(expression, respCtx)
	if err != nil {
		slog.Debug("CEL response cost extraction failed (v2)",
			"expression", expression,
			"error", err)
		return 0, false
	}

	return cost, true
}

func (e *CostExtractor) extractFromResponseHeader(respCtx *policy.ResponseContext, headerName string) (float64, bool) {
	headers := getUpstreamHeaders(respCtx.Upstream, respCtx.ResponseHeaders)
	if headers == nil {
		return 0, false
	}
	values := headers.Get(strings.ToLower(headerName))
	if len(values) == 0 || values[0] == "" {
		return 0, false
	}
	cost, err := strconv.ParseFloat(values[0], 64)
	if err != nil {
		slog.Warn("Failed to parse cost from response header (v2)",
			"header", headerName, "value", values[0], "error", err)
		return 0, false
	}
	return cost, true
}

func (e *CostExtractor) extractFromResponseMetadata(respCtx *policy.ResponseContext, key string) (float64, bool) {
	return extractFromMetadataMap(respCtx.Metadata, key)
}

func (e *CostExtractor) extractFromResponseBody(respCtx *policy.ResponseContext, jsonPath string) (float64, bool) {
	if respCtx.ResponseBody == nil || !respCtx.ResponseBody.Present {
		return 0, false
	}
	return extractFromBodyBytes(respCtx.ResponseBody.Content, jsonPath)
}

// isRequestPhaseSource returns true if the source type is available during request phase
func isRequestPhaseSource(t CostSourceType) bool {
	switch t {
	case CostSourceRequestHeader, CostSourceRequestMetadata, CostSourceRequestBody, CostSourceRequestCEL:
		return true
	default:
		return false
	}
}

// isResponsePhaseSource returns true if the source type is available during response phase
func isResponsePhaseSource(t CostSourceType) bool {
	switch t {
	case CostSourceResponseHeader, CostSourceResponseMetadata, CostSourceResponseBody, CostSourceResponseCEL:
		return true
	default:
		return false
	}
}

func (e *CostExtractor) extractFromRequestSource(reqCtx *policy.RequestContext, source CostSource) (float64, bool) {
	switch source.Type {
	case CostSourceRequestHeader:
		return e.extractFromRequestHeader(reqCtx, source.Key)
	case CostSourceRequestMetadata:
		return e.extractFromRequestMetadata(reqCtx, source.Key)
	case CostSourceRequestBody:
		return e.extractFromRequestBody(reqCtx, source.JSONPath)
	case CostSourceRequestCEL:
		return e.extractFromRequestCEL(reqCtx, source.Expression)
	default:
		return 0, false
	}
}

func (e *CostExtractor) extractFromRequestHeader(reqCtx *policy.RequestContext, headerName string) (float64, bool) {
	return extractCostFromHeaders(getDownstreamHeaders(reqCtx.Downstream, reqCtx.Headers), headerName)
}

// extractCostFromHeaders parses a numeric cost value from the named header.
// Shared by both request-body-phase and request-header-phase extraction paths.
func extractCostFromHeaders(headers *policy.Headers, headerName string) (float64, bool) {
	if headers == nil {
		return 0, false
	}

	values := headers.Get(strings.ToLower(headerName))
	if len(values) == 0 || values[0] == "" {
		return 0, false
	}

	cost, err := strconv.ParseFloat(values[0], 64)
	if err != nil {
		slog.Warn("Failed to parse cost from request header",
			"header", headerName,
			"value", values[0],
			"error", err)
		return 0, false
	}

	return cost, true
}

// ExtractRequestHeaderOnlyCost extracts cost from request_header sources using the
// header-phase context. Only called when HasHeaderOnlyCostSources() is true,
// meaning all request-phase sources are request_header.
func (e *CostExtractor) ExtractRequestHeaderOnlyCost(reqCtx *policy.RequestHeaderContext) (float64, bool) {
	if !e.config.Enabled {
		return e.config.Default, false
	}

	var total float64
	var found bool

	for _, source := range e.config.Sources {
		if source.Type != CostSourceRequestHeader {
			continue
		}
		val, ok := extractCostFromHeaders(getDownstreamHeaders(reqCtx.Downstream, reqCtx.Headers), source.Key)
		if ok {
			found = true
			total += val * source.Multiplier
		}
	}

	if !found {
		return e.config.Default, false
	}
	return total, true
}

func (e *CostExtractor) extractFromRequestMetadata(reqCtx *policy.RequestContext, key string) (float64, bool) {
	return extractFromMetadataMap(reqCtx.Metadata, key)
}

func (e *CostExtractor) extractFromRequestBody(reqCtx *policy.RequestContext, jsonPath string) (float64, bool) {
	if reqCtx.Body == nil || !reqCtx.Body.Present {
		return 0, false
	}

	return extractFromBodyBytes(reqCtx.Body.Content, jsonPath)
}

func (e *CostExtractor) extractFromRequestCEL(reqCtx *policy.RequestContext, expression string) (float64, bool) {
	evaluator, err := GetCELEvaluator()
	if err != nil {
		slog.Error("Failed to get CEL evaluator for request cost extraction", "error", err)
		return 0, false
	}

	cost, err := evaluator.EvaluateRequestCostExpression(expression, reqCtx)
	if err != nil {
		slog.Debug("CEL request cost extraction failed",
			"expression", expression,
			"error", err)
		return 0, false
	}

	return cost, true
}

// extractFromMetadataMap is a helper to extract cost from a metadata map
func extractFromMetadataMap(metadata map[string]interface{}, key string) (float64, bool) {
	val, ok := metadata[key]
	if !ok {
		return 0, false
	}

	switch v := val.(type) {
	case int64:
		return float64(v), true
	case int:
		return float64(v), true
	case float64:
		return v, true
	case float32:
		return float64(v), true
	case string:
		cost, err := strconv.ParseFloat(v, 64)
		if err == nil {
			return cost, true
		}
		slog.Warn("Failed to parse cost from metadata string",
			"key", key,
			"value", v,
			"error", err)
	default:
		slog.Warn("Unsupported type for cost in metadata",
			"key", key,
			"type", fmt.Sprintf("%T", val))
	}

	return 0, false
}

const (
	sseDataPrefix  = "data: "
	sseDone        = "[DONE]"
	sseEventPrefix = "event:"
)

// extractFromBodyBytes is a helper to extract cost from body bytes using JSONPath.
// When the body is not valid JSON (e.g. buffered SSE events), it falls back to
// parsing each SSE "data:" line individually and returns the last successful match.
func extractFromBodyBytes(bodyBytes []byte, jsonPath string) (float64, bool) {
	if len(bodyBytes) == 0 {
		return 0, false
	}

	valueStr, err := utils.ExtractStringValueFromJsonpath(bodyBytes, jsonPath)
	if err != nil {
		// Fall back to SSE parsing: try JSONPath on each event, last match wins.
		if cost, ok := extractFromSSEBodyBytes(bodyBytes, jsonPath); ok {
			return cost, true
		}
		slog.Debug("Failed to extract cost from body",
			"jsonPath", jsonPath,
			"error", err)
		return 0, false
	}

	cost, err := strconv.ParseFloat(valueStr, 64)
	if err != nil {
		slog.Warn("Failed to parse cost from body",
			"jsonPath", jsonPath,
			"value", valueStr,
			"error", err)
		return 0, false
	}

	return cost, true
}

// extractFromSSEBodyBytes parses buffered SSE events and applies the JSONPath
// to each event individually. Returns the value from the last event that matches,
// since usage data typically appears in the final event of the stream.
func extractFromSSEBodyBytes(bodyBytes []byte, jsonPath string) (float64, bool) {
	var lastVal float64
	var found bool

	for _, line := range strings.Split(string(bodyBytes), "\n") {
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

		valueStr, err := utils.ExtractStringValueFromJsonpath([]byte(value), jsonPath)
		if err != nil {
			continue
		}
		cost, err := strconv.ParseFloat(valueStr, 64)
		if err != nil {
			continue
		}
		lastVal = cost
		found = true
	}

	if found {
		slog.Debug("Extracted cost from SSE event",
			"jsonPath", jsonPath,
			"value", lastVal)
	}
	return lastVal, found
}

// parseSSEChunk scans buf for complete SSE lines (newline-delimited) and applies
// jsonPath to the JSON payload of each data: or event: line.
//
// It returns:
//   - lastCost:  the numeric value from the last line that matched jsonPath
//   - found:     true if at least one line yielded a value
//   - remaining: any bytes after the last newline (an incomplete line); the caller
//                must prepend these to the next chunk before calling parseSSEChunk
//                again to guard against JSON payloads split across chunk boundaries
//
// last-match-wins is intentional: LLM providers send the authoritative token count
// in the final usage event, so overwriting on each match naturally yields the right
// value without needing to know which event is "last" in advance.
func parseSSEChunk(buf []byte, jsonPath string) (lastCost float64, found bool, remaining []byte) {
	s := string(buf)
	for {
		idx := strings.IndexByte(s, '\n')
		if idx < 0 {
			// No complete line remaining — return the fragment so the caller
			// can prepend it to the next chunk.
			return lastCost, found, []byte(s)
		}
		line := strings.TrimRight(s[:idx], "\r") // strip optional \r from CRLF line endings
		s = s[idx+1:]

		var value string
		switch {
		case strings.HasPrefix(line, sseDataPrefix):
			value = strings.TrimPrefix(line, sseDataPrefix)
		case strings.HasPrefix(line, sseEventPrefix):
			// event: lines carry the event type name, not a JSON payload —
			// included here for completeness but rarely contain the usage field.
			value = strings.TrimSpace(strings.TrimPrefix(line, sseEventPrefix))
		default:
			// comment (: ...), id:, retry:, or blank separator line — ignore
			continue
		}

		if value == sseDone || value == "" {
			// Stream terminator or empty data field — nothing to extract.
			continue
		}

		valueStr, err := utils.ExtractStringValueFromJsonpath([]byte(value), jsonPath)
		if err != nil {
			// jsonPath not present in this event. Expected for content chunks
			// (e.g. delta text events) — only trailing usage events carry the field.
			continue
		}
		cost, err := strconv.ParseFloat(valueStr, 64)
		if err != nil {
			continue
		}
		lastCost = cost
		found = true // will be overwritten if a later line also matches (last-match-wins)
	}
}

// RequiresResponseBody returns true if any source requires response body access
func (e *CostExtractor) RequiresResponseBody() bool {
	if !e.config.Enabled {
		return false
	}
	for _, source := range e.config.Sources {
		// response_body always needs body, response_cel may need it for body-related expressions
		if source.Type == CostSourceResponseBody || source.Type == CostSourceResponseCEL {
			return true
		}
	}
	return false
}

// HasRequestBodyPhase returns true if any source requires the OnRequestBody phase.
// request_body and request_cel need body content. request_metadata is also deferred
// to the body phase because metadata may be mutated by earlier policies before that phase.
// request_header is consumed directly in OnRequestHeaders and does not require buffering.
func (e *CostExtractor) HasRequestBodyPhase() bool {
	if !e.config.Enabled {
		return false
	}
	for _, source := range e.config.Sources {
		if source.Type == CostSourceRequestBody || source.Type == CostSourceRequestCEL ||
			source.Type == CostSourceRequestMetadata {
			return true
		}
	}
	return false
}

// HasResponseHeaderOnlyCostSources returns true if cost extraction is enabled,
// no source requires the response body phase (no response_body or response_cel),
// and all response-phase sources are response_header.
// response_metadata is excluded — it may be populated by upstream response-phase
// policies that haven't run yet in OnResponseHeaders.
// Request-phase sources are irrelevant and are ignored.
// When true, cost can be fully consumed in OnResponseHeaders with no body buffering.
func (e *CostExtractor) HasResponseHeaderOnlyCostSources() bool {
	if !e.config.Enabled || e.RequiresResponseBody() {
		return false
	}
	hasHeader := false
	for _, source := range e.config.Sources {
		if source.Type == CostSourceResponseHeader {
			hasHeader = true
			continue
		}
		// Any other response-phase source disqualifies response-header-only consumption.
		// Request-phase sources are irrelevant — skip them.
		if isResponsePhaseSource(source.Type) {
			return false
		}
	}
	return hasHeader
}

// HasRequestHeaderOnlyCostSources returns true if cost extraction is enabled,
// no source requires the request body phase (no request_body, request_cel, or
// request_metadata), and at least one request_header source exists.
// Response-phase sources (response_header, response_body, etc.) are ignored —
// only request-phase sources are evaluated to determine header-only eligibility.
// When true, cost can be fully consumed in OnRequestHeaders with no body buffering.
func (e *CostExtractor) HasRequestHeaderOnlyCostSources() bool {
	if !e.config.Enabled || e.HasRequestBodyPhase() {
		return false
	}
	hasHeader := false
	for _, source := range e.config.Sources {
		if source.Type == CostSourceRequestHeader {
			hasHeader = true
			continue
		}
		// Any other request-phase source disqualifies header-only consumption.
		// Response-phase sources are irrelevant — skip them.
		if isRequestPhaseSource(source.Type) {
			return false
		}
	}
	return hasHeader
}

// HasRequestPhaseSources returns true if any source is available during request phase
func (e *CostExtractor) HasRequestPhaseSources() bool {
	if !e.config.Enabled {
		return false
	}
	for _, source := range e.config.Sources {
		if isRequestPhaseSource(source.Type) {
			return true
		}
	}
	return false
}

// HasResponsePhaseSources returns true if any source is available during response phase
func (e *CostExtractor) HasResponsePhaseSources() bool {
	if !e.config.Enabled {
		return false
	}
	for _, source := range e.config.Sources {
		if isResponsePhaseSource(source.Type) {
			return true
		}
	}
	return false
}

// parseCostExtractionConfig parses the costExtraction configuration from a raw value
// which should be a map[string]interface{} from either quota["costExtraction"] or legacy params["costExtraction"].
func parseCostExtractionConfig(raw interface{}) (*CostExtractionConfig, error) {
	if raw == nil {
		return nil, nil
	}

	costExtractionMap, ok := raw.(map[string]interface{})
	if !ok {
		return nil, nil // invalid format, treat as not configured
	}

	config := &CostExtractionConfig{
		Enabled: false,
		Default: 1,
	}

	// Parse enabled
	if enabled, ok := costExtractionMap["enabled"].(bool); ok {
		config.Enabled = enabled
	}

	if !config.Enabled {
		return config, nil // Not enabled, no need to parse further
	}

	// Parse default
	if defaultVal, ok := costExtractionMap["default"].(float64); ok {
		config.Default = defaultVal
		if config.Default < 0 {
			config.Default = 0
		}
	} else if defaultVal, ok := costExtractionMap["default"].(int); ok {
		config.Default = float64(defaultVal)
		if config.Default < 0 {
			config.Default = 0
		}
	}

	// Parse sources
	sourcesRaw, ok := costExtractionMap["sources"].([]interface{})
	if !ok || len(sourcesRaw) == 0 {
		// No sources configured but enabled - disable it
		config.Enabled = false
		return config, nil
	}

	config.Sources = make([]CostSource, 0, len(sourcesRaw))
	for i, sourceRaw := range sourcesRaw {
		sourceMap, ok := sourceRaw.(map[string]interface{})
		if !ok {
			continue
		}

		sourceType, ok := sourceMap["type"].(string)
		if !ok {
			continue
		}

		source := CostSource{
			Type:       CostSourceType(sourceType),
			Multiplier: 1.0, // default multiplier
		}

		if key, ok := sourceMap["key"].(string); ok {
			source.Key = key
		}

		if jsonPath, ok := sourceMap["jsonPath"].(string); ok {
			source.JSONPath = jsonPath
		}

		// Parse expression for CEL types
		if expression, ok := sourceMap["expression"].(string); ok {
			source.Expression = expression
		}

		// Validate: CEL types require expression
		if (sourceType == "request_cel" || sourceType == "response_cel") && source.Expression == "" {
			return nil, fmt.Errorf("sources[%d]: type '%s' requires 'expression' field", i, sourceType)
		}

		// Parse multiplier
		if mult, ok := sourceMap["multiplier"].(float64); ok {
			if mult < 0 {
				return nil, fmt.Errorf("sources[%d].multiplier must be non-negative, got %v", i, mult)
			}
			source.Multiplier = mult
		} else if mult, ok := sourceMap["multiplier"].(int); ok {
			if mult < 0 {
				return nil, fmt.Errorf("sources[%d].multiplier must be non-negative, got %v", i, mult)
			}
			source.Multiplier = float64(mult)
		}

		config.Sources = append(config.Sources, source)
	}

	if len(config.Sources) == 0 {
		config.Enabled = false
	}

	return config, nil
}
