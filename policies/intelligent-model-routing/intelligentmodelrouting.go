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

// Package intelligentmodelrouting implements an LLM-powered model routing policy
// for the WSO2 API Platform Gateway. It classifies incoming user requests using
// a configured LLM provider and routes them to the appropriate AI model based on
// predefined routing rules with context descriptions.
//
// Ported from the Java Universal Gateway implementation:
// org.wso2.apim.policies.mediation.ai.intelligent.model.routing.IntelligentModelRouting
package intelligentmodelrouting

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
	utils "github.com/wso2/api-platform/sdk/core/utils"
)

// Constants matching IntelligentModelRoutingConstants.java
const (
	// ClassificationSystemPrompt is the system prompt sent to the LLM for request classification.
	// Exact replica of IntelligentModelRoutingConstants.CLASSIFICATION_SYSTEM_PROMPT.
	ClassificationSystemPrompt = "You are an API routing assistant. Analyze the user request and determine the best category. " +
		"Respond with ONLY the category name, nothing else."

	// NoneResponse is the LLM response indicating no rule matched.
	NoneResponse = "NONE"

	// llmHTTPTimeout is the timeout for LLM API calls.
	llmHTTPTimeout = 30 * time.Second
)

// RoutingRule represents a single routing rule configuration.
// Maps to IntelligentModelRoutingConfigDTO.RoutingRuleDTO in Java.
type RoutingRule struct {
	Name    string // Rule name (label for classification, e.g. "Weather Information")
	Context string // Plain-language description of what requests this rule handles
	Model   string // Target AI model name to route to
}

// RequestModelConfig holds the configuration for where the model name lives in the request.
// Follows the same pattern as model-round-robin and model-weighted-round-robin policies.
type RequestModelConfig struct {
	Location   string // "payload", "header", "queryParam", "pathParam"
	Identifier string // JSONPath (for payload) or header/param name
}

// LLMClientConfig holds the configuration for the LLM provider used for classification.
type LLMClientConfig struct {
	Provider string // "OPENAI" or "AZURE_OPENAI"
	Endpoint string // Chat completions API endpoint URL
	Model    string // LLM model name (e.g. "gpt-4o-mini"); optional for Azure
	APIKey   string // API key for authentication
}

// IntelligentModelRoutingPolicy implements LLM-based request classification and model routing.
type IntelligentModelRoutingPolicy struct {
	routingRules []RoutingRule
	defaultModel string
	contentPath  string
	requestModel RequestModelConfig
	llmConfig    LLMClientConfig
	httpClient   *http.Client
}

// GetPolicy is the v1alpha2 factory entry point. It parses configuration,
// validates parameters, and returns an initialized policy instance.
// This replaces the Java init(SynapseEnvironment) + setIntelligentModelRoutingConfigs() pattern.
func GetPolicy(
	metadata policy.PolicyMetadata,
	params map[string]interface{},
) (policy.Policy, error) {
	p := &IntelligentModelRoutingPolicy{
		httpClient: &http.Client{Timeout: llmHTTPTimeout},
	}

	if err := parseParams(params, p); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}

	slog.Debug("IntelligentModelRouting: Policy initialized",
		"rules", len(p.routingRules),
		"defaultModel", p.defaultModel,
		"llmProvider", p.llmConfig.Provider,
	)

	return p, nil
}

// Mode returns the processing mode for this policy.
// We need to buffer the request body to:
// 1. Extract user text via JSONPath for LLM classification
// 2. Modify the body to set the selected model name
func (p *IntelligentModelRoutingPolicy) Mode() policy.ProcessingMode {
	return policy.ProcessingMode{
		RequestHeaderMode:  policy.HeaderModeSkip,
		RequestBodyMode:    policy.BodyModeBuffer,
		ResponseHeaderMode: policy.HeaderModeSkip,
		ResponseBodyMode:   policy.BodyModeSkip,
	}
}

// OnRequestBody processes the incoming request body, classifies it using the LLM,
// and modifies the body to route to the appropriate model.
//
// This is the Go equivalent of IntelligentModelRouting.mediate(MessageContext) in Java.
// The flow is:
// 1. Extract user text from body using contentPath JSONPath
// 2. Build classification prompt with routing rules
// 3. Call LLM for classification
// 4. Validate response against known rules
// 5. Modify request body to set the selected model
func (p *IntelligentModelRoutingPolicy) OnRequestBody(
	ctx context.Context,
	reqCtx *policy.RequestContext,
	params map[string]interface{},
) policy.RequestAction {
	// Extract request body content
	var content []byte
	if reqCtx.Body != nil {
		content = reqCtx.Body.Content
	}

	if len(content) == 0 {
		slog.Debug("IntelligentModelRouting: Request body is empty, using default model")
		return p.modifyRequestModel(content, p.defaultModel)
	}

	// Extract user text from body using JSONPath
	userText := ""
	if p.contentPath != "" {
		extracted, err := utils.ExtractStringValueFromJsonpath(content, p.contentPath)
		if err != nil {
			slog.Debug("IntelligentModelRouting: JSONPath extraction failed, using default model",
				"contentPath", p.contentPath, "error", err)
			return p.modifyRequestModel(content, p.defaultModel)
		}
		userText = extracted
	} else {
		userText = string(content)
	}

	if strings.TrimSpace(userText) == "" {
		slog.Debug("IntelligentModelRouting: Extracted text is empty, using default model")
		return p.modifyRequestModel(content, p.defaultModel)
	}

	// Build classification prompt and call LLM
	userPrompt := buildClassificationPrompt(p.routingRules, userText)
	llmResponse, err := p.callLLM(ctx, ClassificationSystemPrompt, userPrompt)
	if err != nil {
		slog.Debug("IntelligentModelRouting: LLM call failed, using default model", "error", err)
		return p.modifyRequestModel(content, p.defaultModel)
	}

	// Validate and match LLM response against routing rules
	selectedModel := p.validateAndSelectModel(llmResponse)
	return p.modifyRequestModel(content, selectedModel)
}

// validateAndSelectModel validates the LLM response and returns the model to route to.
// Replicates the exact logic from Java's validateResponse() + selectEndpointForRouteRule().
func (p *IntelligentModelRoutingPolicy) validateAndSelectModel(response string) string {
	cleanResponse := strings.TrimSpace(response)

	if cleanResponse == "" || strings.EqualFold(cleanResponse, NoneResponse) {
		slog.Debug("IntelligentModelRouting: LLM returned empty or NONE, using default model")
		return p.defaultModel
	}

	// Case-insensitive match against routing rule names
	// Matches Java's findMatchingRouteRule()
	for _, rule := range p.routingRules {
		if strings.EqualFold(rule.Name, cleanResponse) {
			slog.Debug("IntelligentModelRouting: Route rule matched",
				"rule", rule.Name, "model", rule.Model)
			return rule.Model
		}
	}

	slog.Debug("IntelligentModelRouting: No route rule matched LLM response, using default model",
		"llmResponse", cleanResponse)
	return p.defaultModel
}

// modifyRequestModel modifies the request body to set the selected model name.
// For payload location, it uses JSONPath to set the model in the body.
// This follows the same pattern as model-round-robin and model-weighted-round-robin.
func (p *IntelligentModelRoutingPolicy) modifyRequestModel(content []byte, selectedModel string) policy.RequestAction {
	if p.requestModel.Location != "payload" || len(content) == 0 {
		// For non-payload locations (header, queryParam, pathParam), we would need
		// OnRequestHeaders which is not used in this policy. For now, we only
		// support payload-based model routing which is the most common for AI APIs.
		slog.Debug("IntelligentModelRouting: Selected model", "model", selectedModel)
		return policy.UpstreamRequestModifications{}
	}

	var payloadData map[string]interface{}
	if err := json.Unmarshal(content, &payloadData); err != nil {
		slog.Debug("IntelligentModelRouting: Failed to parse request body JSON", "error", err)
		return policy.UpstreamRequestModifications{}
	}

	if err := utils.SetValueAtJSONPath(payloadData, p.requestModel.Identifier, selectedModel); err != nil {
		slog.Debug("IntelligentModelRouting: Failed to set model in request body",
			"identifier", p.requestModel.Identifier, "error", err)
		return policy.UpstreamRequestModifications{}
	}

	updatedPayload, err := json.Marshal(payloadData)
	if err != nil {
		slog.Debug("IntelligentModelRouting: Failed to serialize updated body", "error", err)
		return policy.UpstreamRequestModifications{}
	}

	slog.Debug("IntelligentModelRouting: Modified request body model",
		"model", selectedModel, "identifier", p.requestModel.Identifier)
	return policy.UpstreamRequestModifications{Body: updatedPayload}
}

// buildClassificationPrompt constructs the LLM classification prompt from routing rules
// and user content. This is an exact replica of the Java buildClassificationPrompt() method.
//
// The prompt format matches IntelligentModelRouting.buildClassificationPrompt():
//
//	## TASK
//	Classify the user request into exactly ONE route rule from the list below.
//
//	## ROUTE RULES
//	- RuleName: Context description
//	...
//
//	## ALLOWED RESPONSES
//	You MUST respond with ONLY one of: RuleName1, RuleName2, NONE
//
//	## STRICT OUTPUT RULES
//	...
//
//	## USER REQUEST
//	<content>
//
//	## YOUR RESPONSE (single word only):
func buildClassificationPrompt(rules []RoutingRule, content string) string {
	ruleOptions, ruleNames := buildPromptComponents(rules)

	return "## TASK\n" +
		"Classify the user request into exactly ONE route rule from the list below.\n\n" +
		"## ROUTE RULES\n" + ruleOptions + "\n\n" +
		"## ALLOWED RESPONSES\n" +
		"You MUST respond with ONLY one of: " + ruleNames + ", NONE\n\n" +
		"## STRICT OUTPUT RULES\n" +
		"1. Output ONLY the route rule name - no explanations, no punctuation, no quotes\n" +
		"2. Match based on the context description of each rule\n" +
		"3. If the request clearly matches a rule's context, output that rule name\n" +
		"4. If no rule matches or unclear, output: NONE\n\n" +
		"## USER REQUEST\n" + content + "\n\n" +
		"## YOUR RESPONSE (single word only):"
}

// buildPromptComponents builds the rule options list and comma-separated rule names
// from routing rules. Exact port of Java's buildPromptComponents().
func buildPromptComponents(rules []RoutingRule) (string, string) {
	var options strings.Builder
	var names strings.Builder

	for _, rule := range rules {
		options.WriteString("- ")
		options.WriteString(rule.Name)
		if rule.Context != "" {
			options.WriteString(": ")
			options.WriteString(rule.Context)
		}
		options.WriteString("\n")

		if names.Len() > 0 {
			names.WriteString(", ")
		}
		names.WriteString(rule.Name)
	}

	return strings.TrimRight(options.String(), "\n"), names.String()
}

// --- LLM HTTP Client ---

// chatCompletionRequest is the request body for the LLM chat completions API.
type chatCompletionRequest struct {
	Model    string              `json:"model,omitempty"`
	Messages []chatMessage       `json:"messages"`
}

type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// chatCompletionResponse is the response body from the LLM chat completions API.
type chatCompletionResponse struct {
	Choices []struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
	} `json:"choices"`
}

// callLLM sends a chat completion request to the configured LLM provider and returns
// the text response. This replaces the Java llmProvider.getChatCompletion() call.
func (p *IntelligentModelRoutingPolicy) callLLM(ctx context.Context, systemPrompt, userPrompt string) (string, error) {
	reqBody := chatCompletionRequest{
		Messages: []chatMessage{
			{Role: "system", Content: systemPrompt},
			{Role: "user", Content: userPrompt},
		},
	}

	// Set model for OpenAI (Azure uses deployment name in URL)
	if p.llmConfig.Model != "" {
		reqBody.Model = p.llmConfig.Model
	}

	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("failed to marshal LLM request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, p.llmConfig.Endpoint, bytes.NewReader(bodyBytes))
	if err != nil {
		return "", fmt.Errorf("failed to create LLM HTTP request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")

	// Set auth header based on provider type
	switch p.llmConfig.Provider {
	case "AZURE_OPENAI":
		httpReq.Header.Set("api-key", p.llmConfig.APIKey)
	default: // OPENAI and others use Bearer token
		httpReq.Header.Set("Authorization", "Bearer "+p.llmConfig.APIKey)
	}

	resp, err := p.httpClient.Do(httpReq)
	if err != nil {
		return "", fmt.Errorf("LLM HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("LLM returned status %d: %s", resp.StatusCode, string(respBody))
	}

	var llmResp chatCompletionResponse
	if err := json.NewDecoder(resp.Body).Decode(&llmResp); err != nil {
		return "", fmt.Errorf("failed to decode LLM response: %w", err)
	}

	if len(llmResp.Choices) == 0 {
		return "", fmt.Errorf("LLM returned no choices")
	}

	return llmResp.Choices[0].Message.Content, nil
}

// --- Parameter Parsing ---

// parseParams parses and validates all policy parameters from the params map.
// This replaces the Java parseConfiguration() + init() flow.
func parseParams(params map[string]interface{}, p *IntelligentModelRoutingPolicy) error {
	// Parse contentPath (optional, defaults to "")
	if contentPath, ok := params["contentPath"].(string); ok && contentPath != "" {
		p.contentPath = contentPath
	}

	// Parse routingRules (required)
	rulesRaw, ok := params["routingRules"]
	if !ok {
		return fmt.Errorf("'routingRules' parameter is required")
	}

	rulesList, ok := rulesRaw.([]interface{})
	if !ok {
		return fmt.Errorf("'routingRules' must be an array")
	}

	if len(rulesList) == 0 {
		return fmt.Errorf("'routingRules' must contain at least one rule")
	}

	p.routingRules = make([]RoutingRule, 0, len(rulesList))
	for i, item := range rulesList {
		ruleMap, ok := item.(map[string]interface{})
		if !ok {
			return fmt.Errorf("'routingRules[%d]' must be an object", i)
		}

		rule, err := parseRoutingRule(ruleMap, i)
		if err != nil {
			return err
		}
		p.routingRules = append(p.routingRules, rule)
	}

	// Parse defaultModel (required)
	defaultModel, ok := params["defaultModel"].(string)
	if !ok || defaultModel == "" {
		return fmt.Errorf("'defaultModel' parameter is required")
	}
	p.defaultModel = defaultModel

	// Parse LLM provider config (system parameters)
	if err := parseLLMConfig(params, p); err != nil {
		return err
	}

	// Parse requestModel config (system parameter)
	if err := parseRequestModelConfig(params, p); err != nil {
		return err
	}

	return nil
}

// parseRoutingRule parses a single routing rule from the params map.
func parseRoutingRule(ruleMap map[string]interface{}, index int) (RoutingRule, error) {
	var rule RoutingRule

	name, ok := ruleMap["name"].(string)
	if !ok || name == "" {
		return rule, fmt.Errorf("'routingRules[%d].name' is required and must be a non-empty string", index)
	}
	rule.Name = name

	context, ok := ruleMap["context"].(string)
	if !ok || context == "" {
		return rule, fmt.Errorf("'routingRules[%d].context' is required and must be a non-empty string", index)
	}
	rule.Context = context

	model, ok := ruleMap["model"].(string)
	if !ok || model == "" {
		return rule, fmt.Errorf("'routingRules[%d].model' is required and must be a non-empty string", index)
	}
	rule.Model = model

	return rule, nil
}

// parseLLMConfig parses the LLM provider configuration from params.
func parseLLMConfig(params map[string]interface{}, p *IntelligentModelRoutingPolicy) error {
	provider, ok := params["llmProvider"].(string)
	if !ok || provider == "" {
		return fmt.Errorf("'llmProvider' parameter is required")
	}

	validProviders := map[string]bool{"OPENAI": true, "AZURE_OPENAI": true}
	if !validProviders[provider] {
		return fmt.Errorf("'llmProvider' must be one of: OPENAI, AZURE_OPENAI")
	}
	p.llmConfig.Provider = provider

	endpoint, ok := params["llmEndpoint"].(string)
	if !ok || endpoint == "" {
		return fmt.Errorf("'llmEndpoint' parameter is required")
	}
	p.llmConfig.Endpoint = endpoint

	// Model is required for OPENAI, optional for AZURE_OPENAI
	if model, ok := params["llmModel"].(string); ok && model != "" {
		p.llmConfig.Model = model
	} else if provider == "OPENAI" {
		return fmt.Errorf("'llmModel' is required for OPENAI provider")
	}

	apiKey, ok := params["llmApiKey"].(string)
	if !ok || apiKey == "" {
		return fmt.Errorf("'llmApiKey' parameter is required")
	}
	p.llmConfig.APIKey = apiKey

	return nil
}

// parseRequestModelConfig parses the requestModel configuration from params.
// This follows the exact same pattern as model-round-robin and model-weighted-round-robin.
func parseRequestModelConfig(params map[string]interface{}, p *IntelligentModelRoutingPolicy) error {
	requestModel, ok := params["requestModel"]
	if !ok {
		return fmt.Errorf("'requestModel' configuration is required")
	}

	requestModelMap, ok := requestModel.(map[string]interface{})
	if !ok {
		return fmt.Errorf("'requestModel' must be an object")
	}

	location, ok := requestModelMap["location"].(string)
	if !ok || location == "" {
		return fmt.Errorf("'requestModel.location' is required")
	}

	validLocations := map[string]bool{
		"payload": true, "header": true, "queryParam": true, "pathParam": true,
	}
	if !validLocations[location] {
		return fmt.Errorf("'requestModel.location' must be one of: payload, header, queryParam, pathParam")
	}
	p.requestModel.Location = location

	identifier, ok := requestModelMap["identifier"].(string)
	if !ok || identifier == "" {
		return fmt.Errorf("'requestModel.identifier' is required")
	}
	p.requestModel.Identifier = identifier

	return nil
}
