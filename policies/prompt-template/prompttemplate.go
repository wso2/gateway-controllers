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

package prompttemplate

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/url"
	"regexp"
	"slices"
	"strings"

	policy "github.com/wso2/api-platform/sdk/gateway/policy/v1alpha"
	utils "github.com/wso2/api-platform/sdk/utils"
)

var (
	// promptTemplateRegex matches template://<template-name>?<params> patterns
	// Example: template://translate?from=english&to=spanish or template://translate
	promptTemplateRegex = regexp.MustCompile(`template://[a-zA-Z0-9_-]+(?:\?[^\s"']*)?`)
	// unresolvedPlaceholderRegex matches [[parameter]] placeholders.
	unresolvedPlaceholderRegex = regexp.MustCompile(`\[\[([a-zA-Z0-9_-]+)\]\]`)
	// textCleanRegex removes leading and trailing quotes from JSON-escaped strings
	textCleanRegex = regexp.MustCompile(`^"|"$`)
	// templateNameRegex validates template names.
	templateNameRegex = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)
)

const (
	OnMissingTemplateError       = "error"
	OnMissingTemplatePassthrough = "passthrough"
	OnUnresolvedPlaceholderKeep  = "keep"
	OnUnresolvedPlaceholderEmpty = "empty"
	OnUnresolvedPlaceholderError = "error"
)

// PromptTemplatePolicy implements prompt templating by applying custom templates
type PromptTemplatePolicy struct {
	params PromptTemplatePolicyParams
}

type TemplateConfig struct {
	Name     string `json:"name"`
	Template string `json:"template"`
}

type PromptTemplatePolicyParams struct {
	Templates []TemplateConfig
	JsonPath  string
	// error or passthrough
	OnMissingTemplate string
	// keep, empty, or error
	OnUnresolvedPlaceholder string
	// Templates map for quick lookup by name
	templates map[string]string
}

func GetPolicy(
	metadata policy.PolicyMetadata,
	params map[string]interface{},
) (policy.Policy, error) {
	p := &PromptTemplatePolicy{}

	// Parse parameters
	policyParams, err := parseParams(params)
	if err != nil {
		return nil, fmt.Errorf("invalid parameters: %w", err)
	}
	p.params = policyParams

	return p, nil
}

// parseParams parses and validates parameters from map to struct
func parseParams(params map[string]interface{}) (PromptTemplatePolicyParams, error) {
	var result PromptTemplatePolicyParams

	// Extract required templates parameter.
	templatesRaw, ok := params["templates"]
	if !ok {
		return result, fmt.Errorf("'templates' parameter is required")
	}

	var templateConfigs []TemplateConfig
	switch v := templatesRaw.(type) {
	case string:
		if err := json.Unmarshal([]byte(v), &templateConfigs); err != nil {
			return result, fmt.Errorf("error unmarshaling templates: %w", err)
		}
	case []interface{}:
		// Convert array of interfaces to TemplateConfig array.
		templateConfigs = make([]TemplateConfig, 0, len(v))
		for idx, item := range v {
			if itemMap, ok := item.(map[string]interface{}); ok {
				var templateConfig TemplateConfig
				jsonBytes, err := json.Marshal(itemMap)
				if err != nil {
					return result, fmt.Errorf("error marshaling templates[%d]: %w", idx, err)
				}
				if err := json.Unmarshal(jsonBytes, &templateConfig); err != nil {
					return result, fmt.Errorf("error unmarshaling templates[%d]: %w", idx, err)
				}
				templateConfigs = append(templateConfigs, templateConfig)
			} else {
				return result, fmt.Errorf("'templates[%d]' must be an object", idx)
			}
		}
	default:
		return result, fmt.Errorf("'templates' must be an array or JSON string")
	}

	if len(templateConfigs) == 0 {
		return result, fmt.Errorf("'templates' cannot be empty")
	}
	result.Templates = templateConfigs

	// Build templates map for quick lookup by name.
	result.templates = make(map[string]string)
	for i, templateConfig := range templateConfigs {
		name := strings.TrimSpace(templateConfig.Name)
		if name == "" {
			return result, fmt.Errorf("'templates[%d].name' cannot be empty", i)
		}
		if !templateNameRegex.MatchString(name) {
			return result, fmt.Errorf("'templates[%d].name' must match ^[a-zA-Z0-9_-]+$", i)
		}
		templateText := strings.TrimSpace(templateConfig.Template)
		if templateText == "" {
			return result, fmt.Errorf("'templates[%d].template' cannot be empty", i)
		}
		if _, exists := result.templates[name]; exists {
			return result, fmt.Errorf("duplicate template name: %q", name)
		}
		result.templates[name] = templateText
		result.Templates[i].Name = name
		result.Templates[i].Template = templateText
	}

	// Extract optional jsonPath parameter.
	if jsonPathRaw, ok := params["jsonPath"]; ok {
		jsonPath, ok := jsonPathRaw.(string)
		if !ok {
			return result, fmt.Errorf("'jsonPath' must be a string")
		}
		result.JsonPath = strings.TrimSpace(jsonPath)
	}

	// Extract optional onMissingTemplate parameter.
	result.OnMissingTemplate = OnMissingTemplateError
	if valRaw, ok := params["onMissingTemplate"]; ok {
		val, ok := valRaw.(string)
		if !ok {
			return result, fmt.Errorf("'onMissingTemplate' must be a string")
		}
		val = strings.ToLower(strings.TrimSpace(val))
		switch val {
		case OnMissingTemplateError, OnMissingTemplatePassthrough:
			result.OnMissingTemplate = val
		default:
			return result, fmt.Errorf("'onMissingTemplate' must be one of [error,passthrough]")
		}
	}

	// Extract optional onUnresolvedPlaceholder parameter.
	result.OnUnresolvedPlaceholder = OnUnresolvedPlaceholderKeep
	if valRaw, ok := params["onUnresolvedPlaceholder"]; ok {
		val, ok := valRaw.(string)
		if !ok {
			return result, fmt.Errorf("'onUnresolvedPlaceholder' must be a string")
		}
		val = strings.ToLower(strings.TrimSpace(val))
		switch val {
		case OnUnresolvedPlaceholderKeep, OnUnresolvedPlaceholderEmpty, OnUnresolvedPlaceholderError:
			result.OnUnresolvedPlaceholder = val
		default:
			return result, fmt.Errorf("'onUnresolvedPlaceholder' must be one of [keep,empty,error]")
		}
	}

	// Collect template names for logging
	templateNames := make([]string, 0, len(result.templates))
	for name := range result.templates {
		templateNames = append(templateNames, name)
	}
	slog.Debug("PromptTemplate: Policy initialized",
		"templateCount", len(result.templates),
		"templateNames", templateNames,
		"jsonPath", result.JsonPath,
		"onMissingTemplate", result.OnMissingTemplate,
		"onUnresolvedPlaceholder", result.OnUnresolvedPlaceholder,
	)

	return result, nil
}

// Mode returns the processing mode for this policy
func (p *PromptTemplatePolicy) Mode() policy.ProcessingMode {
	return policy.ProcessingMode{
		RequestHeaderMode:  policy.HeaderModeSkip,
		RequestBodyMode:    policy.BodyModeBuffer,
		ResponseHeaderMode: policy.HeaderModeSkip,
		ResponseBodyMode:   policy.BodyModeSkip,
	}
}

// OnRequest applies template to request body
func (p *PromptTemplatePolicy) OnRequest(ctx *policy.RequestContext, params map[string]interface{}) policy.RequestAction {
	var content []byte
	if ctx.Body != nil {
		content = ctx.Body.Content
	}

	if len(content) == 0 {
		return policy.UpstreamRequestModifications{}
	}

	// If jsonPath is empty, resolve template references across the whole payload
	// string (legacy behavior).
	if p.params.JsonPath == "" {
		updatedContent, err := p.resolveTemplatesInText(string(content), true)
		if err != nil {
			return p.buildErrorResponse("Error resolving templates", err)
		}
		if updatedContent == string(content) {
			return policy.UpstreamRequestModifications{}
		}
		return policy.UpstreamRequestModifications{
			Body: []byte(updatedContent),
		}
	}

	// jsonPath configured: resolve template references in the extracted string only.
	var payloadData map[string]interface{}
	if err := json.Unmarshal(content, &payloadData); err != nil {
		return p.buildErrorResponse("Error parsing JSON payload", err)
	}

	extractedValue, err := p.extractStringAtPath(content, p.params.JsonPath)
	if err != nil {
		return p.buildErrorResponse("Error extracting value from JSONPath", err)
	}

	updatedValue, err := p.resolveTemplatesInText(extractedValue, false)
	if err != nil {
		return p.buildErrorResponse("Error resolving templates", err)
	}
	if updatedValue == extractedValue {
		return policy.UpstreamRequestModifications{}
	}

	if err := utils.SetValueAtJSONPath(payloadData, p.params.JsonPath, updatedValue); err != nil {
		return p.buildErrorResponse("Error updating JSONPath", err)
	}

	updatedPayload, err := json.Marshal(payloadData)
	if err != nil {
		return p.buildErrorResponse("Error marshaling updated JSON payload", err)
	}

	return policy.UpstreamRequestModifications{
		Body: updatedPayload,
	}
}

func (p *PromptTemplatePolicy) resolveTemplatesInText(content string, escapeForJSON bool) (string, error) {
	matches := promptTemplateRegex.FindAllString(content, -1)
	if len(matches) == 0 {
		return content, nil
	}

	updatedContent := content
	for _, matched := range matches {
		resolvedPrompt, shouldReplace, err := p.resolveTemplateReference(matched)
		if err != nil {
			return "", err
		}
		if !shouldReplace {
			continue
		}

		replacement := resolvedPrompt
		if escapeForJSON {
			escaped, err := p.escapeForJSONString(replacement)
			if err != nil {
				return "", err
			}
			replacement = escaped
		}
		updatedContent = strings.ReplaceAll(updatedContent, matched, replacement)
	}

	return updatedContent, nil
}

func (p *PromptTemplatePolicy) resolveTemplateReference(reference string) (string, bool, error) {
	parsedURL, err := url.Parse(reference)
	if err != nil {
		return "", false, fmt.Errorf("invalid template reference %q: %w", reference, err)
	}

	templateName := parsedURL.Host
	templateText, exists := p.params.templates[templateName]
	if !exists {
		if p.params.OnMissingTemplate == OnMissingTemplatePassthrough {
			return "", false, nil
		}
		return "", false, fmt.Errorf("template %q not found", templateName)
	}

	// Parse query parameters for placeholder replacement.
	paramsMap := make(map[string]string)
	if parsedURL.RawQuery != "" {
		queryParams, err := url.ParseQuery(parsedURL.RawQuery)
		if err == nil {
			for key, values := range queryParams {
				if len(values) > 0 {
					paramsMap[key] = values[0]
				}
			}
		}
	}

	resolvedPrompt := templateText
	for key, value := range paramsMap {
		placeholder := "[[" + key + "]]"
		resolvedPrompt = strings.ReplaceAll(resolvedPrompt, placeholder, value)
	}

	unresolvedMatches := unresolvedPlaceholderRegex.FindAllStringSubmatch(resolvedPrompt, -1)
	if len(unresolvedMatches) > 0 {
		switch p.params.OnUnresolvedPlaceholder {
		case OnUnresolvedPlaceholderKeep:
			// Keep unresolved placeholders as-is.
		case OnUnresolvedPlaceholderEmpty:
			resolvedPrompt = unresolvedPlaceholderRegex.ReplaceAllString(resolvedPrompt, "")
		case OnUnresolvedPlaceholderError:
			names := make([]string, 0, len(unresolvedMatches))
			for _, match := range unresolvedMatches {
				if len(match) > 1 {
					names = append(names, match[1])
				}
			}
			slices.Sort(names)
			names = slices.Compact(names)
			return "", false, fmt.Errorf("unresolved placeholders in template %q: %s", templateName, strings.Join(names, ","))
		}
	}

	return resolvedPrompt, true, nil
}

func (p *PromptTemplatePolicy) escapeForJSONString(value string) (string, error) {
	escapedPromptBytes, err := json.Marshal(value)
	if err != nil {
		return "", fmt.Errorf("error marshaling resolved prompt to JSON: %w", err)
	}
	escapedPrompt := string(escapedPromptBytes)
	escapedPrompt = textCleanRegex.ReplaceAllString(escapedPrompt, "")
	return escapedPrompt, nil
}

func (p *PromptTemplatePolicy) extractStringAtPath(payload []byte, jsonPath string) (string, error) {
	extractedValue, err := utils.ExtractStringValueFromJsonpath(payload, jsonPath)
	if err != nil {
		return "", err
	}
	// Normalize quoted JSON strings.
	extractedValue = textCleanRegex.ReplaceAllString(extractedValue, "")
	return extractedValue, nil
}

// OnResponse is not used for this policy
func (p *PromptTemplatePolicy) OnResponse(ctx *policy.ResponseContext, params map[string]interface{}) policy.ResponseAction {
	return policy.UpstreamResponseModifications{}
}

// buildErrorResponse builds an error response
func (p *PromptTemplatePolicy) buildErrorResponse(reason string, validationError error) policy.RequestAction {
	errorMessage := reason
	if validationError != nil {
		errorMessage = fmt.Sprintf("%s: %v", reason, validationError)
	}

	responseBody := map[string]interface{}{
		"type":    "PROMPT_TEMPLATE_ERROR",
		"message": errorMessage,
	}

	bodyBytes, err := json.Marshal(responseBody)
	if err != nil {
		bodyBytes = []byte(`{"type":"PROMPT_TEMPLATE_ERROR","message":"Internal error"}`)
	}

	return policy.ImmediateResponse{
		StatusCode: 500,
		Headers: map[string]string{
			"Content-Type": "application/json",
		},
		Body: bodyBytes,
	}
}
