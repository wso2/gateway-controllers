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

package promptdecorator

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

var arrayIndexRegex = regexp.MustCompile(`^([a-zA-Z0-9_]+)\[(-?\d+)\]$`)

const (
	defaultTextDecorationJSONPath     = "$.messages[-1].content"
	defaultMessagesDecorationJSONPath = "$.messages"
)

var validDecoratorRoles = map[string]struct{}{
	"system":    {},
	"user":      {},
	"assistant": {},
	"tool":      {},
}

// PromptDecoratorPolicy implements prompt decoration by applying custom decorations
type PromptDecoratorPolicy struct {
	params PromptDecoratorPolicyParams
}

type Decoration struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type PromptDecoratorConfig struct {
	Text     *string      `json:"text,omitempty"`
	Messages []Decoration `json:"messages,omitempty"`
}

type PromptDecoratorPolicyParams struct {
	PromptDecoratorConfig PromptDecoratorConfig
	JsonPath              string
	Append                bool
}

func GetPolicy(
	metadata policy.PolicyMetadata,
	params map[string]interface{},
) (policy.Policy, error) {
	p := &PromptDecoratorPolicy{}

	// Parse parameters
	policyParams, err := parseParams(params)
	if err != nil {
		return nil, fmt.Errorf("invalid parameters: %w", err)
	}
	p.params = policyParams

	slog.Debug("PromptDecorator: Policy initialized", "jsonPath", p.params.JsonPath, "append", p.params.Append)

	return p, nil
}

// parseParams parses and validates parameters from map to struct
func parseParams(params map[string]interface{}) (PromptDecoratorPolicyParams, error) {
	var result PromptDecoratorPolicyParams

	// Extract required promptDecoratorConfig parameter
	promptDecoratorConfigRaw, ok := params["promptDecoratorConfig"]
	if !ok {
		return result, fmt.Errorf("'promptDecoratorConfig' parameter is required")
	}

	var promptDecoratorConfig PromptDecoratorConfig
	switch v := promptDecoratorConfigRaw.(type) {
	case string:
		if err := json.Unmarshal([]byte(v), &promptDecoratorConfig); err != nil {
			return result, fmt.Errorf("error unmarshaling promptDecoratorConfig: %w", err)
		}
	case map[string]interface{}:
		// Convert map to JSON and back to struct
		jsonBytes, err := json.Marshal(v)
		if err != nil {
			return result, fmt.Errorf("error marshaling promptDecoratorConfig: %w", err)
		}
		if err := json.Unmarshal(jsonBytes, &promptDecoratorConfig); err != nil {
			return result, fmt.Errorf("error unmarshaling promptDecoratorConfig: %w", err)
		}
	default:
		return result, fmt.Errorf("'promptDecoratorConfig' must be a JSON string or object")
	}

	textConfigured := promptDecoratorConfig.Text != nil
	messagesConfigured := len(promptDecoratorConfig.Messages) > 0

	if textConfigured && messagesConfigured {
		return result, fmt.Errorf("'promptDecoratorConfig' must define exactly one of 'text' or 'messages'")
	}

	if !textConfigured && !messagesConfigured {
		return result, fmt.Errorf("'promptDecoratorConfig' must define one of 'text' or 'messages'")
	}

	if textConfigured {
		if strings.TrimSpace(*promptDecoratorConfig.Text) == "" {
			return result, fmt.Errorf("'promptDecoratorConfig.text' must be a non-empty string")
		}
	}

	if messagesConfigured {
		for i, msg := range promptDecoratorConfig.Messages {
			role := strings.ToLower(strings.TrimSpace(msg.Role))
			if role == "" {
				return result, fmt.Errorf("'promptDecoratorConfig.messages[%d].role' must be a non-empty string", i)
			}
			if _, ok := validDecoratorRoles[role]; !ok {
				return result, fmt.Errorf("'promptDecoratorConfig.messages[%d].role' must be one of [system,user,assistant,tool]", i)
			}
			if strings.TrimSpace(msg.Content) == "" {
				return result, fmt.Errorf("'promptDecoratorConfig.messages[%d].content' must be a non-empty string", i)
			}
			// Normalize role to keep output consistent.
			promptDecoratorConfig.Messages[i].Role = role
		}
	}

	result.PromptDecoratorConfig = promptDecoratorConfig

	// Extract optional jsonPath parameter. If omitted (or empty), select default
	// based on promptDecoratorConfig type.
	if jsonPathRaw, ok := params["jsonPath"]; ok {
		jsonPath, ok := jsonPathRaw.(string)
		if !ok {
			return result, fmt.Errorf("'jsonPath' must be a string")
		}
		if strings.TrimSpace(jsonPath) != "" {
			result.JsonPath = jsonPath
		}
	} else {
		// jsonPath not provided
	}

	if result.JsonPath == "" {
		if textConfigured {
			result.JsonPath = defaultTextDecorationJSONPath
		} else {
			result.JsonPath = defaultMessagesDecorationJSONPath
		}
	}

	// Extract optional append parameter
	if appendRaw, ok := params["append"]; ok {
		if appendVal, ok := appendRaw.(bool); ok {
			result.Append = appendVal
		} else {
			return result, fmt.Errorf("'append' must be a boolean")
		}
	}

	return result, nil
}

// Mode returns the processing mode for this policy
func (p *PromptDecoratorPolicy) Mode() policy.ProcessingMode {
	return policy.ProcessingMode{
		RequestHeaderMode:  policy.HeaderModeSkip,
		RequestBodyMode:    policy.BodyModeBuffer,
		ResponseHeaderMode: policy.HeaderModeSkip,
		ResponseBodyMode:   policy.BodyModeSkip,
	}
}

// OnRequest decorates request body
func (p *PromptDecoratorPolicy) OnRequest(ctx *policy.RequestContext, params map[string]interface{}) policy.RequestAction {
	var content []byte
	if ctx.Body != nil {
		content = ctx.Body.Content
	}

	// Check for empty or nil content before unmarshaling
	if ctx.Body == nil || len(content) == 0 {
		return p.buildErrorResponse("Empty request body", nil)
	}

	// Parse JSON payload
	var payloadData map[string]interface{}
	if err := json.Unmarshal(content, &payloadData); err != nil {
		slog.Debug("PromptDecorator: Error parsing JSON payload", "error", err)
		return p.buildErrorResponse("Error parsing JSON payload", err)
	}

	// Extract value using JSONPath
	extractedValue, err := utils.ExtractValueFromJsonpath(payloadData, p.params.JsonPath)
	if err != nil {
		slog.Debug("PromptDecorator: Error extracting value from JSONPath", "jsonPath", p.params.JsonPath, "error", err)
		return p.buildErrorResponse("Error extracting value from JSONPath", err)
	}

	// Check if we're decorating a string content field or an array of messages
	switch v := extractedValue.(type) {
	case string:
		// Decorating a content string (for example, $.messages[-1].content)
		if p.params.PromptDecoratorConfig.Text == nil {
			return p.buildErrorResponse(
				"Invalid configuration for string target",
				fmt.Errorf("use promptDecoratorConfig.text when jsonPath resolves to a string"),
			)
		}
		decorationStr := *p.params.PromptDecoratorConfig.Text

		// Apply decoration (prepend or append)
		var updatedContent string
		if p.params.Append {
			updatedContent = v + " " + decorationStr
		} else {
			updatedContent = decorationStr + " " + v
		}

		slog.Debug("PromptDecorator: Applied string decoration", "jsonPath", p.params.JsonPath, "append", p.params.Append, "originalLength", len(v), "updatedLength", len(updatedContent))
		// Update the content field
		return p.updateStringAtPath(payloadData, p.params.JsonPath, updatedContent)

	case []interface{}:
		// Decorating an array of messages (for example, $.messages)
		if len(p.params.PromptDecoratorConfig.Messages) == 0 {
			return p.buildErrorResponse(
				"Invalid configuration for messages target",
				fmt.Errorf("use promptDecoratorConfig.messages when jsonPath resolves to an array"),
			)
		}

		messages := make([]map[string]interface{}, 0, len(v))
		var malformedEntries []string

		for i, item := range v {
			if msg, ok := item.(map[string]interface{}); ok {
				messages = append(messages, msg)
			} else {
				// Detect non-map entries and collect details for error reporting
				elementType := fmt.Sprintf("%T", item)
				elementValue := fmt.Sprintf("%v", item)
				malformedEntries = append(malformedEntries, fmt.Sprintf("index %d: type=%s, value=%s", i, elementType, elementValue))
				slog.Debug("PromptDecorator: Non-map element detected in messages array", "jsonPath", p.params.JsonPath, "index", i, "type", elementType, "value", elementValue)
			}
		}

		// If malformed entries found, return error without modifying the slice
		if len(malformedEntries) > 0 {
			errorDetails := fmt.Sprintf("malformed entries at %s", strings.Join(malformedEntries, "; "))
			return p.buildErrorResponse("Array contains non-map elements", fmt.Errorf(errorDetails))
		}

		// Create decoration messages from decoration config
		decorationMessages, err := p.createDecorationMessages()
		if err != nil {
			slog.Debug("PromptDecorator: Error creating decoration messages", "error", err)
			return p.buildErrorResponse("Error creating decoration messages", err)
		}

		// Apply decoration (prepend or append)
		var updatedMessages []map[string]interface{}
		if p.params.Append {
			updatedMessages = append(messages, decorationMessages...)
		} else {
			updatedMessages = append(decorationMessages, messages...)
		}

		slog.Debug("PromptDecorator: Applied array decoration", "jsonPath", p.params.JsonPath, "append", p.params.Append, "originalCount", len(messages), "decorationCount", len(decorationMessages), "updatedCount", len(updatedMessages))
		// Update the messages array
		return p.updateArrayAtPath(payloadData, p.params.JsonPath, updatedMessages)

	case []map[string]interface{}:
		// Already in the right format
		if len(p.params.PromptDecoratorConfig.Messages) == 0 {
			return p.buildErrorResponse(
				"Invalid configuration for messages target",
				fmt.Errorf("use promptDecoratorConfig.messages when jsonPath resolves to an array"),
			)
		}
		messages := v

		// Create decoration messages from decoration config
		decorationMessages, err := p.createDecorationMessages()
		if err != nil {
			slog.Debug("PromptDecorator: Error creating decoration messages", "error", err)
			return p.buildErrorResponse("Error creating decoration messages", err)
		}

		// Apply decoration (prepend or append)
		var updatedMessages []map[string]interface{}
		if p.params.Append {
			updatedMessages = append(messages, decorationMessages...)
		} else {
			updatedMessages = append(decorationMessages, messages...)
		}

		slog.Debug("PromptDecorator: Applied array decoration", "jsonPath", p.params.JsonPath, "append", p.params.Append, "originalCount", len(messages), "decorationCount", len(decorationMessages), "updatedCount", len(updatedMessages))
		// Update the messages array
		return p.updateArrayAtPath(payloadData, p.params.JsonPath, updatedMessages)

	default:
		slog.Debug("PromptDecorator: Invalid extracted value type", "type", fmt.Sprintf("%T", extractedValue))
		return p.buildErrorResponse("Extracted value must be a string or an array of message objects", fmt.Errorf("unexpected type: %T", extractedValue))
	}
}

// createDecorationMessages creates decoration messages from promptDecoratorConfig.messages.
func (p *PromptDecoratorPolicy) createDecorationMessages() ([]map[string]interface{}, error) {
	if len(p.params.PromptDecoratorConfig.Messages) == 0 {
		return nil, fmt.Errorf("promptDecoratorConfig.messages must be provided for chat prompt decoration")
	}

	decorationMessages := make([]map[string]interface{}, 0, len(p.params.PromptDecoratorConfig.Messages))
	for _, item := range p.params.PromptDecoratorConfig.Messages {
		decorationMessages = append(decorationMessages, map[string]interface{}{
			"role":    item.Role,
			"content": item.Content,
		})
	}
	return decorationMessages, nil
}

// updateStringAtPath updates a string value at the given JSONPath
func (p *PromptDecoratorPolicy) updateStringAtPath(payloadData map[string]interface{}, jsonPath string, value string) policy.RequestAction {
	path := jsonPath
	if strings.HasPrefix(path, "$.") {
		path = strings.TrimPrefix(path, "$.")
	}
	if path == "" {
		return p.buildErrorResponse("Invalid JSONPath", fmt.Errorf("empty path"))
	}

	pathComponents := strings.Split(path, ".")
	current := interface{}(payloadData)

	// Navigate to parent
	for i := 0; i < len(pathComponents)-1; i++ {
		key := pathComponents[i]
		current = p.navigatePath(current, key)
		if current == nil {
			slog.Debug("PromptDecorator: Error navigating JSONPath", "jsonPath", jsonPath, "key", key)
			return p.buildErrorResponse("Error navigating JSONPath", fmt.Errorf("key not found: %s", key))
		}
	}

	// Update final key
	finalKey := pathComponents[len(pathComponents)-1]
	if err := p.setValueAtPath(current, finalKey, value); err != nil {
		slog.Debug("PromptDecorator: Error updating JSONPath", "jsonPath", jsonPath, "error", err)
		return p.buildErrorResponse("Error updating JSONPath", err)
	}

	updatedPayload, err := json.Marshal(payloadData)
	if err != nil {
		slog.Debug("PromptDecorator: Error marshaling updated JSON payload", "error", err)
		return p.buildErrorResponse("Error marshaling updated JSON payload", err)
	}

	return policy.UpstreamRequestModifications{
		Body: updatedPayload,
	}
}

// updateArrayAtPath updates an array value at the given JSONPath
func (p *PromptDecoratorPolicy) updateArrayAtPath(payloadData map[string]interface{}, jsonPath string, value []map[string]interface{}) policy.RequestAction {
	path := jsonPath
	if strings.HasPrefix(path, "$.") {
		path = strings.TrimPrefix(path, "$.")
	}
	if path == "" {
		return p.buildErrorResponse("Invalid JSONPath", fmt.Errorf("empty path"))
	}

	pathComponents := strings.Split(path, ".")
	current := interface{}(payloadData)

	// Navigate to parent
	for i := 0; i < len(pathComponents)-1; i++ {
		key := pathComponents[i]
		current = p.navigatePath(current, key)
		if current == nil {
			slog.Debug("PromptDecorator: Error navigating JSONPath", "jsonPath", jsonPath, "key", key)
			return p.buildErrorResponse("Error navigating JSONPath", fmt.Errorf("key not found: %s", key))
		}
	}

	// Convert []map[string]interface{} to []interface{}
	valueInterface := make([]interface{}, len(value))
	for i, v := range value {
		valueInterface[i] = v
	}

	// Update final key
	finalKey := pathComponents[len(pathComponents)-1]
	if err := p.setValueAtPath(current, finalKey, valueInterface); err != nil {
		slog.Debug("PromptDecorator: Error updating JSONPath", "jsonPath", jsonPath, "error", err)
		return p.buildErrorResponse("Error updating JSONPath", err)
	}

	updatedPayload, err := json.Marshal(payloadData)
	if err != nil {
		slog.Debug("PromptDecorator: Error marshaling updated JSON payload", "error", err)
		return p.buildErrorResponse("Error marshaling updated JSON payload", err)
	}

	return policy.UpstreamRequestModifications{
		Body: updatedPayload,
	}
}

// navigatePath navigates through a JSON structure using a key (which may contain array indices)
func (p *PromptDecoratorPolicy) navigatePath(current interface{}, key string) interface{} {
	if matches := arrayIndexRegex.FindStringSubmatch(key); len(matches) == 3 {
		arrayName := matches[1]
		idxStr := matches[2]
		idx, err := strconv.Atoi(idxStr)
		if err != nil {
			return nil
		}

		if node, ok := current.(map[string]interface{}); ok {
			if arrVal, exists := node[arrayName]; exists {
				if arr, ok := arrVal.([]interface{}); ok {
					if idx < 0 {
						idx = len(arr) + idx
					}
					if idx < 0 || idx >= len(arr) {
						return nil
					}
					return arr[idx]
				}
			}
		}
		return nil
	}

	if node, ok := current.(map[string]interface{}); ok {
		if val, exists := node[key]; exists {
			return val
		}
	}
	return nil
}

// setValueAtPath sets a value at a path (key may contain array indices)
func (p *PromptDecoratorPolicy) setValueAtPath(current interface{}, key string, value interface{}) error {
	if matches := arrayIndexRegex.FindStringSubmatch(key); len(matches) == 3 {
		arrayName := matches[1]
		idxStr := matches[2]
		idx, err := strconv.Atoi(idxStr)
		if err != nil {
			return fmt.Errorf("invalid array index: %s", idxStr)
		}

		if node, ok := current.(map[string]interface{}); ok {
			if arrVal, exists := node[arrayName]; exists {
				if arr, ok := arrVal.([]interface{}); ok {
					if idx < 0 {
						idx = len(arr) + idx
					}
					if idx < 0 || idx >= len(arr) {
						return fmt.Errorf("array index out of range: %s", idxStr)
					}
					arr[idx] = value
					return nil
				}
				return fmt.Errorf("not an array: %s", arrayName)
			}
			return fmt.Errorf("key not found: %s", arrayName)
		}
		return fmt.Errorf("invalid structure for key: %s", arrayName)
	}

	if node, ok := current.(map[string]interface{}); ok {
		node[key] = value
		return nil
	}
	return fmt.Errorf("invalid structure for key: %s", key)
}

// OnResponse is not used for this policy
func (p *PromptDecoratorPolicy) OnResponse(ctx *policy.ResponseContext, params map[string]interface{}) policy.ResponseAction {
	return policy.UpstreamResponseModifications{}
}

// buildErrorResponse builds an error response
func (p *PromptDecoratorPolicy) buildErrorResponse(reason string, validationError error) policy.RequestAction {
	errorMessage := reason
	if validationError != nil {
		errorMessage = fmt.Sprintf("%s: %v", reason, validationError)
	}

	responseBody := map[string]interface{}{
		"type":    "PROMPT_DECORATOR_ERROR",
		"message": errorMessage,
	}

	bodyBytes, err := json.Marshal(responseBody)
	if err != nil {
		bodyBytes = []byte(`{"type":"PROMPT_DECORATOR_ERROR","message":"Internal error"}`)
	}

	return policy.ImmediateResponse{
		StatusCode: 500,
		Headers: map[string]string{
			"Content-Type": "application/json",
		},
		Body: bodyBytes,
	}
}
