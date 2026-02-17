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
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"

	policy "github.com/wso2/api-platform/sdk/gateway/policy/v1alpha"
	utils "github.com/wso2/api-platform/sdk/utils"
)

const (
	APIMInternalErrorCode     = 500
	APIMInternalExceptionCode = 900967
	TextCleanRegex            = "^\"|\"$"
	MetadataKeyPIIEntities    = "piimaskingregex:pii_entities"
	DefaultEmailEntityName    = "EMAIL"
	DefaultPhoneEntityName    = "PHONE"
	DefaultSSNEntityName      = "SSN"
	DefaultEmailRegex         = `(?i)\b[a-z0-9.!#$%&'*+/=?^_{|}~-]+@(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])\b`
	DefaultPhoneRegex         = `(?:\+?1[-.\s]?)?(?:\([2-9][0-9]{2}\)|[2-9][0-9]{2})[-.\s]?[2-9][0-9]{2}[-.\s]?[0-9]{4}\b`
	DefaultSSNRegex           = `(?:00[1-9]|0[1-9][0-9]|[1-5][0-9]{2}|6(?:[0-57-9][0-9]|6[0-57-9])|[7-8][0-9]{2})[- ]?(?:0[1-9]|[1-9][0-9])[- ]?(?:000[1-9]|00[1-9][0-9]|0[1-9][0-9]{2}|[1-9][0-9]{3})\b`
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

// parseParams parses and validates parameters from map to struct.
func parseParams(params map[string]interface{}) (PIIMaskingRegexPolicyParams, error) {
	var result PIIMaskingRegexPolicyParams
	result.JsonPath = "$.messages"
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
			if !ok || piiEntity == "" {
				return result, fmt.Errorf("'customPIIEntities[%d].piiEntity' is required and must be a non-empty string", i)
			}

			if !regexp.MustCompile(`^[A-Z_]+$`).MatchString(piiEntity) {
				return result, fmt.Errorf("'customPIIEntities[%d].piiEntity' must match ^[A-Z_]+$", i)
			}

			piiRegex, ok := entityConfig["piiRegex"].(string)
			if !ok || piiRegex == "" {
				return result, fmt.Errorf("'customPIIEntities[%d].piiRegex' is required and must be a non-empty string", i)
			}

			compiledPattern, err := regexp.Compile(piiRegex)
			if err != nil {
				return result, fmt.Errorf("'customPIIEntities[%d].piiRegex' is invalid: %w", i, err)
			}

			if _, exists := piiEntities[piiEntity]; exists {
				return result, fmt.Errorf("duplicate piiEntity: %q", piiEntity)
			}
			piiEntities[piiEntity] = compiledPattern
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

// Mode returns the processing mode for this policy
func (p *PIIMaskingRegexPolicy) Mode() policy.ProcessingMode {
	return policy.ProcessingMode{
		RequestHeaderMode:  policy.HeaderModeSkip,
		RequestBodyMode:    policy.BodyModeBuffer,
		ResponseHeaderMode: policy.HeaderModeSkip,
		ResponseBodyMode:   policy.BodyModeBuffer,
	}
}

// OnRequest masks PII in request body
func (p *PIIMaskingRegexPolicy) OnRequest(ctx *policy.RequestContext, params map[string]interface{}) policy.RequestAction {
	if len(p.params.PIIEntities) == 0 {
		// No PII entities configured, pass through
		return policy.UpstreamRequestModifications{}
	}

	if ctx.Body == nil || ctx.Body.Content == nil {
		return policy.UpstreamRequestModifications{}
	}
	payload := ctx.Body.Content

	// Extract value using JSONPath
	extractedValue, err := utils.ExtractStringValueFromJsonpath(payload, p.params.JsonPath)
	if err != nil {
		return p.buildErrorResponse(fmt.Sprintf("error extracting value from JSONPath: %v", err)).(policy.RequestAction)
	}

	// Clean and trim
	extractedValue = textCleanRegexCompiled.ReplaceAllString(extractedValue, "")
	extractedValue = strings.TrimSpace(extractedValue)

	var modifiedContent string
	if p.params.RedactPII {
		// Redaction mode: replace with *****
		modifiedContent = p.redactPIIFromContent(extractedValue, p.params.PIIEntities)
	} else {
		// Masking mode: replace with placeholders and store mappings
		modifiedContent, err = p.maskPIIFromContent(extractedValue, p.params.PIIEntities, ctx.Metadata)
		if err != nil {
			return p.buildErrorResponse(fmt.Sprintf("error masking PII: %v", err)).(policy.RequestAction)
		}
	}

	// If content was modified, update the payload
	if modifiedContent != "" && modifiedContent != extractedValue {
		modifiedPayload := p.updatePayloadWithMaskedContent(payload, extractedValue, modifiedContent, p.params.JsonPath)
		return policy.UpstreamRequestModifications{
			Body: modifiedPayload,
		}
	}

	return policy.UpstreamRequestModifications{}
}

// OnResponse restores PII in response body (if redactPII is false)
func (p *PIIMaskingRegexPolicy) OnResponse(ctx *policy.ResponseContext, params map[string]interface{}) policy.ResponseAction {
	// If redactPII is true, no restoration needed
	if p.params.RedactPII {
		return policy.UpstreamResponseModifications{}
	}

	// Check if PII entities were masked in request
	maskedPII, exists := ctx.Metadata[MetadataKeyPIIEntities]
	if !exists {
		return policy.UpstreamResponseModifications{}
	}

	maskedPIIMap, ok := maskedPII.(map[string]string)
	if !ok {
		return policy.UpstreamResponseModifications{}
	}

	if ctx.ResponseBody == nil || ctx.ResponseBody.Content == nil {
		return policy.UpstreamResponseModifications{}
	}
	payload := ctx.ResponseBody.Content

	// Restore PII in response
	restoredContent := p.restorePIIInResponse(string(payload), maskedPIIMap)
	if restoredContent != string(payload) {
		return policy.UpstreamResponseModifications{
			Body: []byte(restoredContent),
		}
	}

	return policy.UpstreamResponseModifications{}
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

// buildErrorResponse builds an error response for both request and response phases
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
