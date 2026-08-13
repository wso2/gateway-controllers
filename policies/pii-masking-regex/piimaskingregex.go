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

package piimaskingregex

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
	utils "github.com/wso2/api-platform/sdk/core/utils"
)

const (
	APIMInternalErrorCode     = 500
	APIMInternalExceptionCode = 900967
	TextCleanRegex            = "^\"|\"$"
	MetadataKeyPIIEntities    = "piimaskingregex:pii_entities"
	DefaultEmailEntityName    = "EMAIL"
	DefaultPhoneEntityName    = "PHONE"
	DefaultSSNEntityName      = "SSN"
	DefaultJSONPath           = "$.messages[-1].content"
	DefaultEmailRegex         = `(?i)\b[a-z0-9.!#$%&'*+/=?^_{|}~-]+@(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])\b`
	DefaultPhoneRegex         = `(?:\+?1[-.\s]?)?(?:\([2-9][0-9]{2}\)|[2-9][0-9]{2})[-.\s]?[2-9][0-9]{2}[-.\s]?[0-9]{4}\b`
	DefaultSSNRegex           = `(?:00[1-9]|0[1-9][0-9]|[1-5][0-9]{2}|6(?:[0-57-9][0-9]|6[0-57-9])|[7-8][0-9]{2})[- ]?(?:0[1-9]|[1-9][0-9])[- ]?(?:000[1-9]|00[1-9][0-9]|0[1-9][0-9]{2}|[1-9][0-9]{3})\b`

	// metadataKeyAccJSONBody accumulates a non-SSE (plain JSON) response body
	// across streaming chunks so the full body can be restored and emitted once
	// at end of stream. See OnResponseBodyChunk.
	metadataKeyAccJSONBody = "piimaskingregex:acc_json_body"

	// SSE constants for streaming responses
	sseDataPrefix  = "data: "
	sseDone        = "[DONE]"
	sseEventPrefix = "event:"
)

var textCleanRegexCompiled = regexp.MustCompile(TextCleanRegex)

// PIIMaskingRegexPolicy implements regex-based PII masking
type PIIMaskingRegexPolicy struct {
	params PIIMaskingRegexPolicyParams
}

type PIIMaskingRegexPolicyParams struct {
	PIIEntities map[string]*regexp.Regexp
	JsonPath    string
	RedactPII   bool
}

// GetPolicy is the v1alpha2 factory entry point (loaded by v1alpha2 kernels).
func GetPolicy(
	metadata policy.PolicyMetadata,
	params map[string]interface{},
) (policy.Policy, error) {
	p := &PIIMaskingRegexPolicy{}

	// Parse parameters.
	policyParams, err := parseParams(params)
	if err != nil {
		return nil, fmt.Errorf("invalid parameters: %w", err)
	}
	p.params = policyParams

	return p, nil
}

// Mode returns the processing mode for the PII masking regex policy.
func (p *PIIMaskingRegexPolicy) Mode() policy.ProcessingMode {
	return policy.ProcessingMode{
		RequestHeaderMode:  policy.HeaderModeSkip,
		RequestBodyMode:    policy.BodyModeBuffer,
		ResponseHeaderMode: policy.HeaderModeSkip,
		ResponseBodyMode:   policy.BodyModeStream,
	}
}

// parseParams parses and validates parameters from map to struct.
func parseParams(params map[string]interface{}) (PIIMaskingRegexPolicyParams, error) {
	var result PIIMaskingRegexPolicyParams
	result.JsonPath = DefaultJSONPath
	piiEntities := make(map[string]*regexp.Regexp)

	// Extract customPIIEntities parameter if provided.
	piiEntitiesRaw, ok := params["customPIIEntities"]
	if ok {
		// Parse custom PII entities.
		var piiEntitiesArray []map[string]interface{}
		switch v := piiEntitiesRaw.(type) {
		case string:
			if err := json.Unmarshal([]byte(v), &piiEntitiesArray); err != nil {
				return result, fmt.Errorf("error unmarshaling PII entities: %w", err)
			}
		case []interface{}:
			piiEntitiesArray = make([]map[string]interface{}, 0, len(v))
			for idx, item := range v {
				if itemMap, ok := item.(map[string]interface{}); ok {
					piiEntitiesArray = append(piiEntitiesArray, itemMap)
				} else {
					return result, fmt.Errorf("'customPIIEntities[%d]' must be an object", idx)
				}
			}
		default:
			return result, fmt.Errorf("'customPIIEntities' must be an array or JSON string")
		}

		// Validate each custom PII entity.
		for i, entityConfig := range piiEntitiesArray {
			piiEntity, ok := entityConfig["piiEntity"].(string)
			if !ok || strings.TrimSpace(piiEntity) == "" {
				return result, fmt.Errorf("'customPIIEntities[%d].piiEntity' is required and must be a non-empty string", i)
			}

			normalizedPIIEntity := strings.ToUpper(strings.TrimSpace(piiEntity))
			if !regexp.MustCompile(`^[A-Z_]+$`).MatchString(normalizedPIIEntity) {
				return result, fmt.Errorf("'customPIIEntities[%d].piiEntity' must contain only letters and underscores", i)
			}

			piiRegex, ok := entityConfig["piiRegex"].(string)
			if !ok || piiRegex == "" {
				return result, fmt.Errorf("'customPIIEntities[%d].piiRegex' is required and must be a non-empty string", i)
			}

			compiledPattern, err := regexp.Compile(piiRegex)
			if err != nil {
				return result, fmt.Errorf("'customPIIEntities[%d].piiRegex' is invalid: %w", i, err)
			}

			if _, exists := piiEntities[normalizedPIIEntity]; exists {
				return result, fmt.Errorf("duplicate piiEntity: %q", normalizedPIIEntity)
			}
			piiEntities[normalizedPIIEntity] = compiledPattern
		}
	}

	// Extract built-in entity toggles.
	enableEmail, err := parseBoolParam(params, "email")
	if err != nil {
		return result, err
	}
	enablePhone, err := parseBoolParam(params, "phone")
	if err != nil {
		return result, err
	}
	enableSSN, err := parseBoolParam(params, "ssn")
	if err != nil {
		return result, err
	}

	if enableEmail {
		if _, exists := piiEntities[DefaultEmailEntityName]; exists {
			return result, fmt.Errorf("duplicate piiEntity: %q", DefaultEmailEntityName)
		}
		piiEntities[DefaultEmailEntityName] = regexp.MustCompile(DefaultEmailRegex)
	}
	if enablePhone {
		if _, exists := piiEntities[DefaultPhoneEntityName]; exists {
			return result, fmt.Errorf("duplicate piiEntity: %q", DefaultPhoneEntityName)
		}
		piiEntities[DefaultPhoneEntityName] = regexp.MustCompile(DefaultPhoneRegex)
	}
	if enableSSN {
		if _, exists := piiEntities[DefaultSSNEntityName]; exists {
			return result, fmt.Errorf("duplicate piiEntity: %q", DefaultSSNEntityName)
		}
		piiEntities[DefaultSSNEntityName] = regexp.MustCompile(DefaultSSNRegex)
	}

	if len(piiEntities) == 0 {
		return result, fmt.Errorf("at least one PII detector must be configured using 'customPIIEntities' or one of 'email', 'phone', 'ssn'")
	}
	result.PIIEntities = piiEntities

	// Extract optional jsonPath parameter
	if jsonPathRaw, ok := params["jsonPath"]; ok {
		if jsonPath, ok := jsonPathRaw.(string); ok {
			result.JsonPath = jsonPath
		} else {
			return result, fmt.Errorf("'jsonPath' must be a string")
		}
	}

	// Extract optional redactPII parameter
	if redactPIIRaw, ok := params["redactPII"]; ok {
		if redactPII, ok := redactPIIRaw.(bool); ok {
			result.RedactPII = redactPII
		} else {
			return result, fmt.Errorf("'redactPII' must be a boolean")
		}
	}

	return result, nil
}

func parseBoolParam(params map[string]interface{}, key string) (bool, error) {
	valRaw, ok := params[key]
	if !ok {
		return false, nil
	}
	val, ok := valRaw.(bool)
	if !ok {
		return false, fmt.Errorf("'%s' must be a boolean", key)
	}
	return val, nil
}

// maskPIIFromContent masks PII from content using regex patterns
func (p *PIIMaskingRegexPolicy) maskPIIFromContent(content string, piiEntities map[string]*regexp.Regexp, metadata map[string]interface{}) (string, error) {
	if content == "" {
		return "", nil
	}

	maskedContent := content
	maskedPIIEntities := make(map[string]string)
	counter := 0
	// Pre-compile placeholder pattern for efficiency
	placeholderPattern := regexp.MustCompile(`^\[[A-Z_]+_[0-9a-f]{4}\]$`)

	// First pass: find all matches without replacing to avoid nested replacements
	allMatches := make(map[string]string) // original -> placeholder
	for key, pattern := range piiEntities {
		matches := pattern.FindAllString(maskedContent, -1)
		for _, match := range matches {
			if _, exists := allMatches[match]; !exists && !placeholderPattern.MatchString(match) {
				// Generate unique placeholder like [EMAIL_0000]
				placeholder := fmt.Sprintf("[%s_%04x]", key, counter)
				allMatches[match] = placeholder
				maskedPIIEntities[match] = placeholder
				counter++
			}
		}
	}

	// Second pass: replace all matches
	originals := make([]string, 0, len(allMatches))
	for original := range allMatches {
		originals = append(originals, original)
	}
	sort.Slice(originals, func(i, j int) bool { return len(originals[i]) > len(originals[j]) })
	for _, original := range originals {
		maskedContent = strings.ReplaceAll(maskedContent, original, allMatches[original])
	}

	// Store PII mappings in metadata for response restoration
	if len(maskedPIIEntities) > 0 {
		metadata[MetadataKeyPIIEntities] = maskedPIIEntities
	}

	if len(allMatches) > 0 {
		return maskedContent, nil
	}

	return "", nil
}

// redactPIIFromContent redacts PII from content using regex patterns
func (p *PIIMaskingRegexPolicy) redactPIIFromContent(content string, piiEntities map[string]*regexp.Regexp) string {
	if content == "" {
		return ""
	}

	maskedContent := content
	foundAndMasked := false

	for _, pattern := range piiEntities {
		if pattern.MatchString(maskedContent) {
			foundAndMasked = true
			maskedContent = pattern.ReplaceAllString(maskedContent, "*****")
		}
	}

	if foundAndMasked {
		return maskedContent
	}

	return ""
}

// restorePIIInResponse handles PII restoration in responses when redactPII is disabled
func (p *PIIMaskingRegexPolicy) restorePIIInResponse(originalContent string, maskedPIIEntities map[string]string) string {
	if len(maskedPIIEntities) == 0 {
		return originalContent
	}

	transformedContent := originalContent

	for original, placeholder := range maskedPIIEntities {
		if strings.Contains(transformedContent, placeholder) {
			transformedContent = strings.ReplaceAll(transformedContent, placeholder, original)
		}
	}

	return transformedContent
}

// updatePayloadWithMaskedContent updates the original payload by replacing the extracted content
func (p *PIIMaskingRegexPolicy) updatePayloadWithMaskedContent(originalPayload []byte, extractedValue, modifiedContent string, jsonPath string) []byte {
	if jsonPath == "" {
		// If no JSONPath, the entire payload was processed, return the modified content
		return []byte(modifiedContent)
	}

	// If JSONPath is specified, update only the specific field in the JSON structure
	var jsonData map[string]interface{}
	if err := json.Unmarshal(originalPayload, &jsonData); err != nil {
		// Fallback to returning the modified content as-is
		return []byte(modifiedContent)
	}

	// Set the new value at the JSONPath location
	err := utils.SetValueAtJSONPath(jsonData, jsonPath, modifiedContent)
	if err != nil {
		// Fallback to returning the original payload
		return originalPayload
	}

	// Marshal back to JSON to get the full modified payload
	updatedPayload, err := json.Marshal(jsonData)
	if err != nil {
		// Fallback to returning the original payload
		return originalPayload
	}

	return updatedPayload
}

// OnRequestHeaders implements v2alpha.RequestHeaderPolicy.
// PII masking operates on the body, so headers are passed through unchanged.
func (p *PIIMaskingRegexPolicy) OnRequestHeaders(ctx context.Context, reqCtx *policy.RequestHeaderContext, params map[string]interface{}) policy.RequestHeaderAction {
	return policy.UpstreamRequestHeaderModifications{}
}

// OnResponseHeaders implements v2alpha.ResponseHeaderPolicy.
// PII masking operates on the body, so headers are passed through unchanged.
func (p *PIIMaskingRegexPolicy) OnResponseHeaders(ctx context.Context, respCtx *policy.ResponseHeaderContext, params map[string]interface{}) policy.ResponseHeaderAction {
	return policy.DownstreamResponseHeaderModifications{}
}

// OnRequestBody masks PII in the request body before forwarding to upstream.
func (p *PIIMaskingRegexPolicy) OnRequestBody(ctx context.Context, reqCtx *policy.RequestContext, _ map[string]interface{}) policy.RequestAction {
	return p.processRequestBody(reqCtx, nil)
}

// processRequestBody masks PII in the request body before forwarding to upstream.
// Placeholders (e.g. [EMAIL_0000]) or redaction markers (*****) replace
// detected PII. Placeholder→original mappings are stored in shared metadata
// so processResponseBody can restore them.
func (p *PIIMaskingRegexPolicy) processRequestBody(reqCtx *policy.RequestContext, params map[string]interface{}) policy.RequestAction {
	if len(p.params.PIIEntities) == 0 {
		return policy.UpstreamRequestModifications{}
	}

	if reqCtx.Body == nil || reqCtx.Body.Content == nil {
		return policy.UpstreamRequestModifications{}
	}
	payload := reqCtx.Body.Content

	extractedValue, ok, err := extractStringFromPath(payload, p.params.JsonPath)
	if err != nil {
		return p.buildErrorResponse(fmt.Sprintf("error extracting value from JSONPath: %v", err)).(policy.RequestAction)
	}
	if !ok {
		// Value at path is not a scalar (e.g. multimodal content array); skip masking.
		return policy.UpstreamRequestModifications{}
	}

	extractedValue = textCleanRegexCompiled.ReplaceAllString(extractedValue, "")
	extractedValue = strings.TrimSpace(extractedValue)

	var modifiedContent string
	if p.params.RedactPII {
		modifiedContent = p.redactPIIFromContent(extractedValue, p.params.PIIEntities)
	} else {
		if reqCtx.Metadata == nil {
			reqCtx.Metadata = make(map[string]interface{})
		}
		modifiedContent, err = p.maskPIIFromContent(extractedValue, p.params.PIIEntities, reqCtx.Metadata)
		if err != nil {
			return p.buildErrorResponse(fmt.Sprintf("error masking PII: %v", err)).(policy.RequestAction)
		}
	}

	if modifiedContent != "" && modifiedContent != extractedValue {
		modifiedPayload := p.updatePayloadWithMaskedContent(payload, extractedValue, modifiedContent, p.params.JsonPath)
		return policy.UpstreamRequestModifications{
			Body: modifiedPayload,
		}
	}

	return policy.UpstreamRequestModifications{}
}

// OnResponseBody restores PII placeholders in a buffered response body.
func (p *PIIMaskingRegexPolicy) OnResponseBody(ctx context.Context, respCtx *policy.ResponseContext, _ map[string]interface{}) policy.ResponseAction {
	return p.processResponseBody(respCtx, nil)
}

// processResponseBody restores PII placeholders in a buffered response body.
//
// Two body formats are handled:
//   - Plain JSON (non-streaming): choices[*].message.content
//   - SSE-buffered (chunked transfer of streaming response that this chain could not
//     process in streaming mode): multiple "data: {...}" lines, choices[*].delta.content.
//     The same restoreSSEChunk logic used by OnResponseBodyChunk is reused here.
func (p *PIIMaskingRegexPolicy) processResponseBody(respCtx *policy.ResponseContext, params map[string]interface{}) policy.ResponseAction {
	if p.params.RedactPII {
		return policy.DownstreamResponseModifications{}
	}

	maskedPII, exists := respCtx.Metadata[MetadataKeyPIIEntities]
	if !exists {
		return policy.DownstreamResponseModifications{}
	}

	maskedPIIMap, ok := maskedPII.(map[string]string)
	if !ok || len(maskedPIIMap) == 0 {
		return policy.DownstreamResponseModifications{}
	}

	if respCtx.ResponseBody == nil || respCtx.ResponseBody.Content == nil {
		return policy.DownstreamResponseModifications{}
	}

	bodyStr := string(respCtx.ResponseBody.Content)

	// maskedPIIMap is keyed original→placeholder (set by maskPIIFromContent).
	// The restore helpers expect placeholder→original, so invert before use.
	restoreMap := invertStringMap(maskedPIIMap)

	if isSSEChunk(bodyStr) {
		// SSE-buffered: reuse the streaming restoration logic.
		action := p.restoreSSEChunk(bodyStr, restoreMap)
		if action.Body == nil {
			return policy.DownstreamResponseModifications{}
		}
		return policy.DownstreamResponseModifications{Body: action.Body}
	}

	// Plain JSON buffered response: try OpenAI choices[*].message.content first,
	// then fall back to raw placeholder replacement for generic JSON structures.
	updatedJSON, changed := restoreInChoices(bodyStr, restoreMap, "message")
	if changed {
		return policy.DownstreamResponseModifications{Body: []byte(updatedJSON)}
	}

	// Fallback: restore placeholders directly in the raw JSON bytes.
	action := p.restoreJSONChunk(bodyStr, restoreMap)
	if action.Body != nil {
		return policy.DownstreamResponseModifications{Body: action.Body}
	}
	return policy.DownstreamResponseModifications{}
}

// NeedsMoreResponseData implements v2alpha.StreamingResponsePolicy.
// Returns true when the accumulated SSE delta.content contains an unclosed '['
// that may be a PII placeholder, so the kernel keeps buffering until ']' arrives
// or 5 more SSE data lines have passed (whichever comes first).
//
// For non-SSE (plain JSON) responses delivered via chunked transfer encoding,
// accumulates until the full JSON body is complete and parseable.
func (p *PIIMaskingRegexPolicy) NeedsMoreResponseData(accumulated []byte) bool {
	if p.params.RedactPII {
		return false
	}

	s := string(accumulated)

	if !isSSEChunk(s) {
		// Non-SSE (plain JSON) body delivered over chunked transfer. Restoration
		// must rewrite placeholders anywhere in the body, so we buffer the whole
		// body ourselves in OnResponseBodyChunk (via respCtx.Metadata) and emit
		// the restored body at EndOfStream. Returning false hands us every chunk
		// directly, matching the streaming contract the other response policies
		// use (see regex-guardrail / word-count-guardrail). The previous
		// json.Valid gate here relied on kernel-level accumulation that did not
		// deliver the complete body as a single chunk, truncating the response to
		// an early fragment.
		return false
	}

	content, openBracketDataLineIdx, totalDataLines := extractSSEDeltaContentTracked(s)

	lastOpen := strings.LastIndex(content, "[")
	if lastOpen == -1 {
		return false
	}

	afterBracket := content[lastOpen+1:]
	if strings.Contains(afterBracket, "]") {
		return false
	}

	// Unclosed '[' found — wait, but no more than 5 data lines after it.
	dataLinesAfterOpen := totalDataLines - openBracketDataLineIdx - 1
	return dataLinesAfterOpen <= 5
}

// OnResponseBodyChunk implements v2alpha.StreamingResponsePolicy.
// Restores masked PII in response chunks.
//
// LLMs always use Transfer-Encoding: chunked, so this method handles two formats:
//   - SSE streaming: lines prefixed with "data: ", restores in choices[*].delta.content
//   - Full JSON (non-streaming, chunked transfer): restores in raw JSON bytes
func (p *PIIMaskingRegexPolicy) OnResponseBodyChunk(ctx context.Context, respCtx *policy.ResponseStreamContext, chunk *policy.StreamBody, params map[string]interface{}) policy.StreamingResponseAction {
	if p.params.RedactPII {
		return policy.ForwardResponseChunk{}
	}
	if chunk == nil {
		return policy.ForwardResponseChunk{}
	}
	// Note: unlike validate-only policies we do NOT early-return on an empty
	// chunk, because an empty EndOfStream sentinel is the signal to flush a body
	// we have been accumulating below.

	maskedPII, exists := respCtx.Metadata[MetadataKeyPIIEntities]
	if !exists {
		return policy.ForwardResponseChunk{}
	}
	maskedPIIMap, ok := maskedPII.(map[string]string)
	if !ok || len(maskedPIIMap) == 0 {
		return policy.ForwardResponseChunk{}
	}

	chunkStr := string(chunk.Chunk)

	// maskedPIIMap is keyed original→placeholder (set by maskPIIFromContent).
	// The restore helpers expect placeholder→original, so invert before use.
	restoreMap := invertStringMap(maskedPIIMap)

	// Detect format: SSE responses have lines starting with "data: "
	if isSSEChunk(chunkStr) {
		return p.restoreSSEChunk(chunkStr, restoreMap)
	}

	// Non-SSE (plain JSON) body over chunked transfer. A placeholder can span a
	// chunk boundary and restoration rewrites the whole body, so we cannot
	// forward chunks as they arrive. Accumulate across chunks and emit the
	// restored body exactly once, at EndOfStream. Intermediate chunks emit
	// nothing ([]byte{} = suppress this flush; nil would pass the raw,
	// still-masked bytes through).
	if respCtx.Metadata == nil {
		respCtx.Metadata = make(map[string]interface{})
	}
	prev, _ := respCtx.Metadata[metadataKeyAccJSONBody].(string)
	full := prev + chunkStr
	if !chunk.EndOfStream {
		respCtx.Metadata[metadataKeyAccJSONBody] = full
		return policy.ForwardResponseChunk{Body: []byte{}}
	}
	delete(respCtx.Metadata, metadataKeyAccJSONBody)
	return policy.ForwardResponseChunk{Body: []byte(p.restoreJSONBytes(full, restoreMap))}
}

// ─── SSE / Streaming helpers ─────────────────────────────────────────────────

// isSSEChunk reports whether the chunk looks like SSE data (has at least one "data: " or "event:" line).
func isSSEChunk(s string) bool {
	for _, line := range strings.SplitN(s, "\n", 5) {
		if strings.HasPrefix(line, sseDataPrefix) || strings.HasPrefix(line, sseEventPrefix) {
			return true
		}
	}
	return false
}

// restoreSSEChunk handles SSE streaming format: "data: {...}\n\n" lines.
//
// When the accumulator flushes a batch of SSE events (e.g. the placeholder
// [EMAIL_0000] split across " [", "EMAIL", "_", "0000", "]" in separate events),
// no single event contains the full placeholder. We therefore concatenate all
// delta.content values, restore on the full string, then redistribute: the
// first content-bearing event gets the complete restored text, and all subsequent
// events whose content has been merged into the first are dropped entirely.
func (p *PIIMaskingRegexPolicy) restoreSSEChunk(chunkStr string, maskedMap map[string]string) policy.ForwardResponseChunk {
	lines := strings.Split(chunkStr, "\n")

	// Collect every SSE data line that carries a non-empty delta.content.
	type contentLine struct {
		lineIdx int
		content string
	}
	var contentLines []contentLine
	for i, line := range lines {
		if !strings.HasPrefix(line, sseDataPrefix) {
			continue
		}
		jsonStr := strings.TrimPrefix(line, sseDataPrefix)
		if jsonStr == sseDone {
			continue
		}
		if c := extractFirstDeltaContent(jsonStr); c != "" {
			contentLines = append(contentLines, contentLine{lineIdx: i, content: c})
		}
	}

	if len(contentLines) == 0 {
		return policy.ForwardResponseChunk{}
	}

	// Concatenate fragments and restore in one pass.
	var sb strings.Builder
	for _, cl := range contentLines {
		sb.WriteString(cl.content)
	}
	fullContent := sb.String()
	restoredContent := restore(fullContent, maskedMap)

	if restoredContent == fullContent {
		return policy.ForwardResponseChunk{}
	}

	// Redistribute: first content-bearing event gets the full restored text;
	// subsequent events are dropped entirely.
	lines[contentLines[0].lineIdx] = replaceContentInSSELine(
		lines[contentLines[0].lineIdx], contentLines[0].content, restoredContent,
	)
	removeLines := make(map[int]bool, len(contentLines)-1)
	for _, cl := range contentLines[1:] {
		removeLines[cl.lineIdx] = true
	}

	filtered := lines[:0:0]
	for i, line := range lines {
		if removeLines[i] {
			// Also drop the blank separator line immediately after, if present.
			if i+1 < len(lines) && lines[i+1] == "" {
				removeLines[i+1] = true
			}
			continue
		}
		filtered = append(filtered, line)
	}

	return policy.ForwardResponseChunk{Body: []byte(strings.Join(filtered, "\n"))}
}

// extractFirstDeltaContent parses a single SSE JSON line and returns the
// delta.content value from the first choice, or empty string if absent/empty.
func extractFirstDeltaContent(jsonStr string) string {
	var data map[string]interface{}
	if err := json.Unmarshal([]byte(jsonStr), &data); err != nil {
		return ""
	}
	choices, _ := data["choices"].([]interface{})
	for _, cr := range choices {
		choice, _ := cr.(map[string]interface{})
		delta, _ := choice["delta"].(map[string]interface{})
		if content, _ := delta["content"].(string); content != "" {
			return content
		}
	}
	return ""
}

// replaceContentInSSELine replaces the delta.content value in a "data: {...}" SSE
// line in-place, touching only the JSON-encoded content value and leaving all
// other fields intact. Falls back to a full re-marshal if the in-place
// replacement cannot locate the expected token.
func replaceContentInSSELine(line, oldContent, newContent string) string {
	jsonStr := strings.TrimPrefix(line, sseDataPrefix)
	oldJSON, err1 := json.Marshal(oldContent)
	newJSON, err2 := json.Marshal(newContent)
	if err1 != nil || err2 != nil {
		return updateDeltaContentInLine(line, newContent)
	}
	updated := strings.Replace(jsonStr, `"content":`+string(oldJSON), `"content":`+string(newJSON), 1)
	if updated == jsonStr {
		// Token not found (e.g. whitespace around colon) — fall back.
		return updateDeltaContentInLine(line, newContent)
	}
	return sseDataPrefix + updated
}

// updateDeltaContentInLine is the fallback full-remarshal path used when
// replaceContentInSSELine cannot locate the content token in the raw JSON.
func updateDeltaContentInLine(line, newContent string) string {
	jsonStr := strings.TrimPrefix(line, sseDataPrefix)
	var data map[string]interface{}
	if err := json.Unmarshal([]byte(jsonStr), &data); err != nil {
		return line
	}
	choices, _ := data["choices"].([]interface{})
	updated := false
	for _, cr := range choices {
		choice, _ := cr.(map[string]interface{})
		delta, ok := choice["delta"].(map[string]interface{})
		if !ok {
			continue
		}
		if _, hasContent := delta["content"]; hasContent {
			delta["content"] = newContent
			updated = true
		}
	}
	if !updated {
		return line
	}
	b, err := json.Marshal(data)
	if err != nil {
		return line
	}
	return sseDataPrefix + string(b)
}

// restoreJSONChunk handles full JSON responses delivered via chunked transfer encoding.
// Placeholders are replaced directly in the raw JSON bytes so that key order,
// whitespace, and any trailing newline from the LLM are preserved exactly.
func (p *PIIMaskingRegexPolicy) restoreJSONChunk(chunkStr string, maskedMap map[string]string) policy.ForwardResponseChunk {
	result := p.restoreJSONBytes(chunkStr, maskedMap)
	if result == chunkStr {
		return policy.ForwardResponseChunk{}
	}
	return policy.ForwardResponseChunk{Body: []byte(result)}
}

// restoreJSONBytes replaces every placeholder with its original value directly in
// the raw JSON string, preserving key order, whitespace, and any trailing
// newline. Replacements are JSON-encoded so special characters (", \, etc.) stay
// correctly escaped. Returns the input unchanged when no placeholder is present.
func (p *PIIMaskingRegexPolicy) restoreJSONBytes(s string, maskedMap map[string]string) string {
	result := s
	for placeholder, original := range maskedMap {
		if !strings.Contains(result, placeholder) {
			continue
		}
		encodedBytes, err := json.Marshal(original)
		if err != nil {
			continue
		}
		escapedOriginal := string(encodedBytes[1 : len(encodedBytes)-1])
		result = strings.ReplaceAll(result, placeholder, escapedOriginal)
	}
	return result
}

// restoreInChoices parses a JSON string, restores PII placeholders in
// choices[*].<choiceKey>.content, and returns the updated JSON.
// choiceKey is "message" for non-streaming or "delta" for streaming.
func restoreInChoices(jsonStr string, maskedMap map[string]string, choiceKey string) (string, bool) {
	var data map[string]interface{}
	if err := json.Unmarshal([]byte(jsonStr), &data); err != nil {
		return jsonStr, false
	}

	choicesRaw, ok := data["choices"]
	if !ok {
		return jsonStr, false
	}
	choices, ok := choicesRaw.([]interface{})
	if !ok || len(choices) == 0 {
		return jsonStr, false
	}

	modified := false
	for _, choiceRaw := range choices {
		choice, ok := choiceRaw.(map[string]interface{})
		if !ok {
			continue
		}
		subRaw, ok := choice[choiceKey]
		if !ok {
			continue
		}
		sub, ok := subRaw.(map[string]interface{})
		if !ok {
			continue
		}
		content, ok := sub["content"].(string)
		if !ok || content == "" {
			continue
		}
		restored := restore(content, maskedMap)
		if restored != content {
			sub["content"] = restored
			modified = true
		}
	}

	if !modified {
		return jsonStr, false
	}

	updatedBytes, err := json.Marshal(data)
	if err != nil {
		return jsonStr, false
	}
	return string(updatedBytes), true
}

// extractSSEDeltaContentTracked concatenates choices[*].delta.content from all
// complete SSE data lines in the accumulated buffer. It returns:
//   - the concatenated content string
//   - the 0-based data-line index of the last line that contributed a '[' character
//   - the total number of complete SSE data lines processed
//
// TODO (Set Jsonstreaming path)
func extractSSEDeltaContentTracked(s string) (string, int, int) {
	var sb strings.Builder
	totalDataLines := 0
	lastOpenBracketDataLine := 0
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
		if value == sseDone {
			totalDataLines++
			continue
		}
		if value == "" {
			continue
		}
		var data map[string]interface{}
		lineContent := ""
		if err := json.Unmarshal([]byte(value), &data); err != nil {
			// Not JSON — use the entire value as content
			lineContent = value
		} else {
			choices, _ := data["choices"].([]interface{})
			for _, cr := range choices {
				choice, _ := cr.(map[string]interface{})
				delta, _ := choice["delta"].(map[string]interface{})
				content, _ := delta["content"].(string)
				lineContent += content
			}
		}
		if strings.Contains(lineContent, "[") {
			lastOpenBracketDataLine = totalDataLines
		}
		sb.WriteString(lineContent)
		totalDataLines++
	}
	return sb.String(), lastOpenBracketDataLine, totalDataLines
}

// invertStringMap returns a new map with keys and values swapped.
func invertStringMap(m map[string]string) map[string]string {
	inv := make(map[string]string, len(m))
	for k, v := range m {
		inv[v] = k
	}
	return inv
}

// restore replaces placeholders with their original values.
// maskedMap is placeholder → original.
func restore(content string, maskedMap map[string]string) string {
	result := content
	for placeholder, original := range maskedMap {
		result = strings.ReplaceAll(result, placeholder, original)
	}
	return result
}

// extractStringFromPath extracts the value at jsonPath from payload as a string.
// Returns (value, true, nil) when the value is a scalar string or number.
// Returns ("", false, nil) when the value exists but is not a scalar (e.g. array/object).
// Returns ("", false, err) on path or parse errors.
func extractStringFromPath(payload []byte, jsonPath string) (string, bool, error) {
	if jsonPath == "" {
		return string(payload), true, nil
	}
	var jsonData map[string]interface{}
	if err := json.Unmarshal(payload, &jsonData); err != nil {
		return "", false, err
	}
	raw, err := utils.ExtractValueFromJsonpath(jsonData, jsonPath)
	if err != nil {
		return "", false, err
	}
	switch v := raw.(type) {
	case string:
		return v, true, nil
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64), true, nil
	case int:
		return strconv.Itoa(v), true, nil
	default:
		return "", false, nil
	}
}

func (p *PIIMaskingRegexPolicy) buildErrorResponse(reason string) interface{} {
	responseBody := map[string]interface{}{
		"code":    APIMInternalExceptionCode,
		"message": "Error occurred during pii-masking-regex mediation: " + reason,
	}

	bodyBytes, err := json.Marshal(responseBody)
	if err != nil {
		bodyBytes = []byte(fmt.Sprintf(`{"code":%d,"type":"PII_MASKING_REGEX","message":"Internal error"}`, APIMInternalExceptionCode))
	}

	// For PII masking, errors typically occur in request phase, but return as ImmediateResponse
	return policy.ImmediateResponse{
		StatusCode: APIMInternalErrorCode,
		Headers: map[string]string{
			"Content-Type": "application/json",
		},
		Body: bodyBytes,
	}
}
