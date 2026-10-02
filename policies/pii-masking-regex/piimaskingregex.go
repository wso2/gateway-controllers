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

	// SSE constants for streaming responses
	sseDataPrefix  = "data: "
	sseDone        = "[DONE]"
	sseEventPrefix = "event:"
)

// DefaultStreamingJSONPaths locate the assistant text inside one SSE data frame.
// They are tried in order and the first match wins, so this policy is not bound
// to any single vendor's wire format. A shape that is not listed here is not
// restored: the frame passes through untouched and the client sees the masked
// placeholder, so a new provider format is added by extending this list.
var DefaultStreamingJSONPaths = []string{
	// OpenAI chat completions — also Azure OpenAI, Mistral, Groq, DeepSeek,
	// Together, Fireworks and everything else speaking the OpenAI wire format.
	"$.choices[0].delta.content",
	// Anthropic Messages — content_block_delta carries delta.text.
	"$.delta.text",
	// Google Gemini streamGenerateContent.
	"$.candidates[0].content.parts[0].text",
	// Amazon Bedrock Converse — contentBlockDelta wraps the same delta.text.
	"$.contentBlockDelta.delta.text",
	// Amazon Bedrock (Titan) and Anthropic legacy text completions.
	"$.outputText",
	"$.completion",
	// OpenAI legacy completions.
	"$.choices[0].text",
	// OpenAI Responses API (also Azure OpenAI and Azure AI Foundry /responses)
	// — response.output_text.delta carries the text as a plain string, not an
	// object. Last on purpose: it is the most generic shape here, so every
	// specific path above gets first refusal. Anthropic's delta is an object,
	// and ExtractStringValueFromJsonpath errors on non-scalars, so this cannot
	// steal a match from "$.delta.text".
	"$.delta",
}

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

	allMatches := findPIIMatches([]string{content}, piiEntities)
	if len(allMatches) == 0 {
		return "", nil
	}

	// Store PII mappings in metadata for response restoration
	metadata[MetadataKeyPIIEntities] = allMatches
	return applyPIIPlaceholders(content, allMatches), nil
}

// placeholderPattern matches a placeholder this policy generated, so an
// already-masked value is never masked a second time.
var placeholderPattern = regexp.MustCompile(`^\[[A-Z_]+_[0-9a-f]{4}\]$`)

// findPIIMatches finds every PII match across contents and assigns each distinct
// match one placeholder like [EMAIL_0000]. Sharing one counter across all
// contents keeps placeholders unique when several JSON values are masked in the
// same request, so response restoration stays unambiguous. It returns a map of
// original value to placeholder.
func findPIIMatches(contents []string, piiEntities map[string]*regexp.Regexp) map[string]string {
	allMatches := make(map[string]string)
	counter := 0

	// Visit entities in a stable order so placeholder numbering is deterministic.
	keys := make([]string, 0, len(piiEntities))
	for key := range piiEntities {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	for _, content := range contents {
		for _, key := range keys {
			for _, match := range piiEntities[key].FindAllString(content, -1) {
				if _, exists := allMatches[match]; exists || placeholderPattern.MatchString(match) {
					continue
				}
				allMatches[match] = fmt.Sprintf("[%s_%04x]", key, counter)
				counter++
			}
		}
	}
	return allMatches
}

// applyPIIPlaceholders replaces every original value in content with its
// placeholder, longest first so a match contained in a longer one is not
// replaced partially.
func applyPIIPlaceholders(content string, allMatches map[string]string) string {
	originals := make([]string, 0, len(allMatches))
	for original := range allMatches {
		originals = append(originals, original)
	}
	sort.Slice(originals, func(i, j int) bool { return len(originals[i]) > len(originals[j]) })

	masked := content
	for _, original := range originals {
		masked = strings.ReplaceAll(masked, original, allMatches[original])
	}
	return masked
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

// updatePayloadWithMaskedContent updates the original payload by replacing the extracted content.
// It returns an error rather than the original payload when the masked value cannot be written
// back, because the original payload still carries the PII this policy is meant to remove.
func (p *PIIMaskingRegexPolicy) updatePayloadWithMaskedContent(originalPayload []byte, extractedValue, modifiedContent string, jsonPath string) ([]byte, error) {
	if jsonPath == "" {
		// If no JSONPath, the entire payload was processed, return the modified content
		return []byte(modifiedContent), nil
	}

	// If JSONPath is specified, update only the specific field in the JSON structure
	var jsonData map[string]interface{}
	if err := json.Unmarshal(originalPayload, &jsonData); err != nil {
		return nil, fmt.Errorf("parsing payload for masked write-back: %w", err)
	}

	// Set the new value at the JSONPath location
	if err := utils.SetValueAtJSONPath(jsonData, jsonPath, modifiedContent); err != nil {
		return nil, fmt.Errorf("writing masked value to JSONPath: %w", err)
	}

	// Marshal back to JSON to get the full modified payload
	updatedPayload, err := json.Marshal(jsonData)
	if err != nil {
		return nil, fmt.Errorf("encoding masked payload: %w", err)
	}

	return updatedPayload, nil
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
		// The path selects an object, an array or a wildcard match (a multimodal
		// content array, a structured state). Mask every string inside it rather
		// than skipping it, which would forward the PII upstream unmasked.
		return p.maskStructuredValue(reqCtx, payload)
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
		modifiedPayload, err := p.updatePayloadWithMaskedContent(payload, extractedValue, modifiedContent, p.params.JsonPath)
		if err != nil {
			return p.buildErrorResponse(fmt.Sprintf("error applying masked content: %v", err)).(policy.RequestAction)
		}
		return policy.UpstreamRequestModifications{
			Body: modifiedPayload,
		}
	}

	return policy.UpstreamRequestModifications{}
}

// maskStructuredValue masks PII in every string (and number) under the configured JSONPath
// when it selects an object, an array or a wildcard match. Values are rewritten in place, so
// the rest of the payload is untouched, and all of them share one placeholder mapping.
func (p *PIIMaskingRegexPolicy) maskStructuredValue(reqCtx *policy.RequestContext, payload []byte) policy.RequestAction {
	var jsonData map[string]interface{}
	if err := json.Unmarshal(payload, &jsonData); err != nil {
		return p.buildErrorResponse(fmt.Sprintf("error extracting value from JSONPath: %v", err)).(policy.RequestAction)
	}
	keys := jsonPathKeys(p.params.JsonPath)

	var transform func(string) string
	if p.params.RedactPII {
		transform = func(value string) string {
			if redacted := p.redactPIIFromContent(value, p.params.PIIEntities); redacted != "" {
				return redacted
			}
			return value
		}
	} else {
		// First pass: collect every value so matches get placeholders from one shared map.
		var values []string
		if _, _, err := rewriteValuesAtPath(jsonData, keys, func(value string) string {
			values = append(values, value)
			return value
		}); err != nil {
			return p.buildErrorResponse(fmt.Sprintf("error extracting value from JSONPath: %v", err)).(policy.RequestAction)
		}
		allMatches := findPIIMatches(values, p.params.PIIEntities)
		if len(allMatches) == 0 {
			return policy.UpstreamRequestModifications{}
		}
		if reqCtx.Metadata == nil {
			reqCtx.Metadata = make(map[string]interface{})
		}
		reqCtx.Metadata[MetadataKeyPIIEntities] = allMatches
		transform = func(value string) string {
			return applyPIIPlaceholders(value, allMatches)
		}
	}

	_, changed, err := rewriteValuesAtPath(jsonData, keys, transform)
	if err != nil {
		return p.buildErrorResponse(fmt.Sprintf("error extracting value from JSONPath: %v", err)).(policy.RequestAction)
	}
	if !changed {
		return policy.UpstreamRequestModifications{}
	}

	modifiedPayload, err := json.Marshal(jsonData)
	if err != nil {
		return p.buildErrorResponse(fmt.Sprintf("error applying masked content: %v", err)).(policy.RequestAction)
	}
	return policy.UpstreamRequestModifications{Body: modifiedPayload}
}

var jsonPathIndexPattern = regexp.MustCompile(`^([a-zA-Z0-9_]+)\[(-?\d+)\]$`)

// jsonPathKeys splits a JSONPath into the segments rewriteValuesAtPath walks, using the same
// grammar as the SDK's ExtractValueFromJsonpath: dotted keys, key[N] (negative N counts from
// the end) and "*" over an object or array.
func jsonPathKeys(jsonPath string) []string {
	keys := strings.Split(jsonPath, ".")
	if len(keys) > 0 && keys[0] == "$" {
		keys = keys[1:]
	}
	return keys
}

// rewriteValuesAtPath applies transform to every string and number under the node that keys
// select, writing results back in place. It returns the (possibly replaced) node and whether
// anything changed. A "*" segment skips children the rest of the path does not match, as the
// SDK's extractor does.
func rewriteValuesAtPath(node interface{}, keys []string, transform func(string) string) (interface{}, bool, error) {
	if len(keys) == 0 {
		out, changed := rewriteAllValues(node, transform)
		return out, changed, nil
	}
	key, rest := keys[0], keys[1:]

	if key == "*" {
		changed := false
		switch v := node.(type) {
		case map[string]interface{}:
			for _, k := range sortedKeys(v) {
				if out, c, err := rewriteValuesAtPath(v[k], rest, transform); err == nil {
					v[k] = out
					changed = changed || c
				}
			}
		case []interface{}:
			for i := range v {
				if out, c, err := rewriteValuesAtPath(v[i], rest, transform); err == nil {
					v[i] = out
					changed = changed || c
				}
			}
		default:
			return nil, false, fmt.Errorf("wildcard used on non-iterable node")
		}
		return node, changed, nil
	}

	obj, ok := node.(map[string]interface{})
	if !ok {
		return nil, false, fmt.Errorf("invalid structure for key: %s", key)
	}

	if m := jsonPathIndexPattern.FindStringSubmatch(key); len(m) == 3 {
		arr, ok := obj[m[1]].([]interface{})
		if !ok {
			return nil, false, fmt.Errorf("not an array: %s", m[1])
		}
		idx, err := strconv.Atoi(m[2])
		if err != nil {
			return nil, false, fmt.Errorf("invalid array index: %s", m[2])
		}
		if idx < 0 {
			idx = len(arr) + idx
		}
		if idx < 0 || idx >= len(arr) {
			return nil, false, fmt.Errorf("array index out of range: %s", m[2])
		}
		out, changed, err := rewriteValuesAtPath(arr[idx], rest, transform)
		if err != nil {
			return nil, false, err
		}
		arr[idx] = out
		return node, changed, nil
	}

	child, exists := obj[key]
	if !exists {
		return nil, false, fmt.Errorf("key not found: %s", key)
	}
	out, changed, err := rewriteValuesAtPath(child, rest, transform)
	if err != nil {
		return nil, false, err
	}
	obj[key] = out
	return node, changed, nil
}

// rewriteAllValues applies transform to every string and number within node. A number is only
// replaced (by a string) when transform changes it, e.g. an SSN sent as a JSON number.
func rewriteAllValues(node interface{}, transform func(string) string) (interface{}, bool) {
	switch v := node.(type) {
	case string:
		out := transform(v)
		return out, out != v
	case float64:
		s := strconv.FormatFloat(v, 'f', -1, 64)
		if out := transform(s); out != s {
			return out, true
		}
		return v, false
	case map[string]interface{}:
		changed := false
		for _, k := range sortedKeys(v) {
			out, c := rewriteAllValues(v[k], transform)
			v[k] = out
			changed = changed || c
		}
		return v, changed
	case []interface{}:
		changed := false
		for i := range v {
			out, c := rewriteAllValues(v[i], transform)
			v[i] = out
			changed = changed || c
		}
		return v, changed
	}
	return node, false
}

func sortedKeys(m map[string]interface{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
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

// ─── Streaming restore ───────────────────────────────────────────
//
// Accumulation is the kernel's job, not the policy's. The policy engine buffers
// response chunks and only hands them to policies once no policy asks for more
// (anyPolicyNeedsMoreResponseData in the policy-engine kernel), and it now does
// that identically on the plain and compressed paths. NeedsMoreResponseData is
// how this policy makes that request, so no cross-chunk state is kept here:
// every flush is restored on its own, statelessly.
//
// What restoration needs is a *complete* placeholder. An LLM emits "[EMAIL_0000]"
// as several tokens ("[", "EMAIL", "_0000", "]"), each in its own SSE event, so a
// flush cut in the middle would match nothing and leak the masked text to the
// client. Waiting until a trailing unclosed "[" is closed is the entire rule.

// maxPlaceholderTailBytes bounds how much assistant text may accumulate after an
// unclosed "[" before it is released regardless of shape. Entity names are
// operator-configurable and so unbounded in principle; without a ceiling, prose
// opening a bracket onto a long uppercase run would buffer to the kernel's
// accumulator limit before anything reached the client. 64 bytes is far past any
// real placeholder — "[CREDIT_CARD_NUMBER_0000]" is 25.
const maxPlaceholderTailBytes = 64

// placeholderTailPattern matches the text after an unclosed "[" when that text
// could still become a placeholder.
//
// Placeholders are built as "[%s_%04x]" with the entity name uppercased, and the
// request side validates them with ^\[[A-Z_]+_[0-9a-f]{4}\]$. The two halves draw
// on disjoint character sets — the name is [A-Z_], the counter is [0-9a-f] — so a
// half-emitted placeholder is exactly a run of the first followed by up to four
// of the second. Anything else after the bracket (a space, lowercase prose,
// punctuation) proves no placeholder can complete, so the stream is released now.
var placeholderTailPattern = regexp.MustCompile(`^[A-Z_]*[0-9a-f]{0,4}$`)

// couldCompletePlaceholder reports whether content ends in an unclosed "[" whose
// trailing text is still a viable placeholder prefix — that is, whether waiting
// for more data could turn it into something restorable.
//
// This is what replaced counting SSE data events. Whether a placeholder is still
// arriving is a property of the *text*, not of how many frames the upstream split
// it across, so a placeholder emitted one character per event is held exactly as
// long as one emitted whole. An event-count bound could not express that: any
// fixed number is both too small for a finely-tokenised placeholder (it leaks)
// and too large for prose (it stalls).
func couldCompletePlaceholder(content string) bool {
	lastOpen := strings.LastIndex(content, "[")
	if lastOpen == -1 {
		return false
	}
	tail := content[lastOpen+1:]
	if strings.Contains(tail, "]") {
		return false // already closed — a whole placeholder is present
	}
	if len(tail) > maxPlaceholderTailBytes {
		return false
	}
	return placeholderTailPattern.MatchString(tail)
}

// NeedsMoreResponseData implements v2alpha.StreamingResponsePolicy.
//
// For non-SSE (plain JSON) responses delivered via chunked transfer encoding,
// accumulates until the full JSON body is complete and parseable. For SSE,
// accumulates while the assembled assistant text ends in a bracket that could
// still be completing a placeholder.
func (p *PIIMaskingRegexPolicy) NeedsMoreResponseData(accumulated []byte) bool {
	// Redaction is one-way: nothing is restored on the response path, so there is
	// never a reason to hold a chunk back.
	if p.params.RedactPII {
		return false
	}

	s := string(accumulated)

	if !isSSEChunk(s) {
		return !json.Valid([]byte(strings.TrimSpace(s)))
	}

	// A partially-received event carries a partially-received JSON payload, which
	// no JSONPath can be read from. Flushing it would hand the client the first
	// half of a placeholder and restore nothing, so wait for the event terminator.
	if !endsAtSSEEventBoundary(s) {
		return true
	}

	return couldCompletePlaceholder(extractSSEDeltaContent(s))
}

// endsAtSSEEventBoundary reports whether s ends on a complete SSE event. Both
// terminators are legal and a CRLF stream contains no "\n\n" at all, so matching
// LF alone would treat every CRLF event as incomplete and buffer the whole
// response to the kernel's accumulator ceiling.
func endsAtSSEEventBoundary(s string) bool {
	return strings.HasSuffix(s, "\n\n") || strings.HasSuffix(s, "\r\n\r\n")
}

// extractSSEDeltaContent concatenates the assistant text carried by every data
// event in an SSE buffer, which is the text a client ultimately assembles and so
// the only thing placeholder detection should look at. Frame boundaries are
// deliberately not preserved: a placeholder split across events is contiguous
// here, which is what lets the shape test in couldCompletePlaceholder work
// regardless of how finely the upstream tokenised it.
func extractSSEDeltaContent(s string) string {
	var sb strings.Builder
	for _, line := range strings.Split(s, "\n") {
		jsonStr, ok := sseDataPayload(line)
		if !ok || jsonStr == sseDone {
			continue
		}
		sb.WriteString(extractFirstDeltaContent(jsonStr, DefaultStreamingJSONPaths))
	}
	return sb.String()
}

// OnResponseBodyChunk implements v2alpha.StreamingResponsePolicy.
// Restores masked PII in a flushed response chunk.
//
// LLMs always use Transfer-Encoding: chunked, so this method handles two formats:
//   - SSE streaming: lines prefixed with "data: ", restores in choices[*].delta.content
//   - Full JSON (non-streaming, chunked transfer): restores in raw JSON bytes
//
// NeedsMoreResponseData guarantees the chunk seen here holds whole placeholders,
// so no state is carried between calls.
func (p *PIIMaskingRegexPolicy) OnResponseBodyChunk(ctx context.Context, respCtx *policy.ResponseStreamContext, chunk *policy.StreamBody, params map[string]interface{}) policy.StreamingResponseAction {
	if p.params.RedactPII {
		return policy.ForwardResponseChunk{}
	}
	if chunk == nil || len(chunk.Chunk) == 0 {
		return policy.ForwardResponseChunk{}
	}

	maskedPII, exists := respCtx.Metadata[MetadataKeyPIIEntities]
	if !exists {
		return policy.ForwardResponseChunk{}
	}
	maskedPIIMap, ok := maskedPII.(map[string]string)
	if !ok || len(maskedPIIMap) == 0 {
		return policy.ForwardResponseChunk{}
	}

	// maskedPIIMap is keyed original→placeholder (set by maskPIIFromContent).
	// The restore helpers expect placeholder→original, so invert before use.
	restoreMap := invertStringMap(maskedPIIMap)

	chunkStr := string(chunk.Chunk)
	if isSSEChunk(chunkStr) {
		return p.restoreSSEChunk(chunkStr, restoreMap)
	}
	return p.restoreJSONChunk(chunkStr, restoreMap)
}

// sseLineBody drops the trailing CR left on every line when a CRLF-delimited
// frame is split on "\n", so field parsing is terminator-agnostic.
func sseLineBody(line string) string {
	return strings.TrimSuffix(line, "\r")
}

// sseDataPayload returns the payload of an SSE "data: " field line and whether
// line is one at all. CR-tolerant, so "data: [DONE]\r" yields "[DONE]".
func sseDataPayload(line string) (string, bool) {
	body := sseLineBody(line)
	if !strings.HasPrefix(body, sseDataPrefix) {
		return "", false
	}
	return strings.TrimPrefix(body, sseDataPrefix), true
}

// rebuildSSEDataLine reassembles a data line around a rewritten payload,
// preserving the line's original CR terminator.
func rebuildSSEDataLine(line, payload string) string {
	if strings.HasSuffix(line, "\r") {
		return sseDataPrefix + payload + "\r"
	}
	return sseDataPrefix + payload
}

// isSSEFieldLine reports whether line is an SSE field that belongs to the event
// block it precedes. Comments (": keep-alive") are deliberately excluded: they
// are valid standalone and are preserved wherever they appear.
func isSSEFieldLine(line string) bool {
	body := sseLineBody(line)
	return strings.HasPrefix(body, sseEventPrefix) ||
		strings.HasPrefix(body, "id:") ||
		strings.HasPrefix(body, "retry:")
}

// markEventBlockForRemoval marks the whole SSE block owning the data line at
// dataIdx: the field lines immediately preceding it and the blank separator
// terminating it. Dropping only the data line would leave its "event:" line
// orphaned — a block with no data — which is malformed for providers that emit
// a field line per event, Anthropic being the one that does.
func markEventBlockForRemoval(lines []string, dataIdx int, removeLines map[int]bool) {
	removeLines[dataIdx] = true
	// Walk back over this block's field lines. A blank line, a comment, or the
	// preceding event's data line all stop the walk, so no other block is touched.
	for j := dataIdx - 1; j >= 0 && isSSEFieldLine(lines[j]); j-- {
		removeLines[j] = true
	}
	if dataIdx+1 < len(lines) && sseLineBody(lines[dataIdx+1]) == "" {
		removeLines[dataIdx+1] = true
	}
}

// restoreJSONBytes replaces every complete placeholder in s with its
// JSON-escaped original, preserving all other bytes exactly.
func restoreJSONBytes(s string, restoreMap map[string]string) string {
	result := s
	for placeholder, original := range restoreMap {
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
		jsonStr, ok := sseDataPayload(line)
		if !ok || jsonStr == sseDone {
			continue
		}
		if c := extractFirstDeltaContent(jsonStr, DefaultStreamingJSONPaths); c != "" {
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
		DefaultStreamingJSONPaths,
	)
	removeLines := make(map[int]bool, len(contentLines)-1)
	for _, cl := range contentLines[1:] {
		markEventBlockForRemoval(lines, cl.lineIdx, removeLines)
	}

	filtered := lines[:0:0]
	for i, line := range lines {
		if removeLines[i] {
			continue
		}
		filtered = append(filtered, line)
	}

	return policy.ForwardResponseChunk{Body: []byte(strings.Join(filtered, "\n"))}
}

// extractFirstDeltaContent parses a single SSE JSON line and returns the
// delta.content value from the first choice, or empty string if absent/empty.
func extractFirstDeltaContent(jsonStr string, paths []string) string {
	content, _ := extractFirstDeltaContentKeyed(jsonStr, paths)
	return content
}

// extractFirstDeltaContentKeyed returns the assistant text carried by one SSE
// data payload along with the JSONPath it was found at, so an in-place rewrite
// can target that same field. Paths are tried in order; the first that yields a
// non-empty string wins.
func extractFirstDeltaContentKeyed(jsonStr string, paths []string) (string, string) {
	for _, path := range paths {
		text, err := utils.ExtractStringValueFromJsonpath([]byte(jsonStr), path)
		if err == nil && text != "" {
			return text, path
		}
	}
	return "", ""
}

// jsonPathLeafKey returns the final field name of a JSONPath, e.g. "content"
// for "$.choices[0].delta.content". Used to locate the value in the raw JSON so
// a rewrite can preserve the frame's original key order and spacing instead of
// re-marshaling it.
func jsonPathLeafKey(path string) string {
	if i := strings.LastIndex(path, "."); i >= 0 {
		return path[i+1:]
	}
	return ""
}

// replaceContentInSSELine replaces the delta.content value in a "data: {...}" SSE
// line in-place, touching only the JSON-encoded content value and leaving all
// other fields intact. Falls back to a full re-marshal if the in-place
// replacement cannot locate the expected token.
func replaceContentInSSELine(line, oldContent, newContent string, paths []string) string {
	jsonStr, ok := sseDataPayload(line)
	if !ok {
		return line
	}
	_, matchedPath := extractFirstDeltaContentKeyed(jsonStr, paths)
	if matchedPath == "" {
		return line
	}
	key := jsonPathLeafKey(matchedPath)
	oldJSON, err1 := json.Marshal(oldContent)
	newJSON, err2 := json.Marshal(newContent)
	if err1 != nil || err2 != nil {
		return updateDeltaContentInLine(line, newContent, matchedPath)
	}
	updated := strings.Replace(jsonStr, `"`+key+`":`+string(oldJSON), `"`+key+`":`+string(newJSON), 1)
	if updated == jsonStr {
		// Token not found (e.g. whitespace around colon) — fall back.
		return updateDeltaContentInLine(line, newContent, matchedPath)
	}
	return rebuildSSEDataLine(line, updated)
}

// updateDeltaContentInLine is the fallback full-remarshal path used when
// replaceContentInSSELine cannot locate the content token in the raw JSON.
// It writes through the same JSONPath the text was extracted from, so it stays
// correct for any provider shape without knowing which one this is.
func updateDeltaContentInLine(line, newContent, matchedPath string) string {
	jsonStr, ok := sseDataPayload(line)
	if !ok {
		return line
	}
	var data map[string]interface{}
	if err := json.Unmarshal([]byte(jsonStr), &data); err != nil {
		return line
	}
	if err := utils.SetValueAtJSONPath(data, matchedPath, newContent); err != nil {
		return line
	}
	b, err := json.Marshal(data)
	if err != nil {
		return line
	}
	return rebuildSSEDataLine(line, string(b))
}

// restoreJSONChunk handles full JSON responses delivered via chunked transfer encoding.
// Placeholders are replaced directly in the raw JSON bytes so that key order,
// whitespace, and any trailing newline from the LLM are preserved exactly.
func (p *PIIMaskingRegexPolicy) restoreJSONChunk(chunkStr string, maskedMap map[string]string) policy.ForwardResponseChunk {
	result := restoreJSONBytes(chunkStr, maskedMap)
	if result == chunkStr {
		return policy.ForwardResponseChunk{}
	}
	return policy.ForwardResponseChunk{Body: []byte(result)}
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
