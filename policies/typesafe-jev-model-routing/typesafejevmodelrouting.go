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

// Package typesafejevmodelrouting implements a model routing policy backed by
// TypeSafe AI's Jev "System One" model. Jev chooses the user-defined routing
// rule that best fits each request (a calibrated Choice over the rule names,
// each described by its context), and the request is routed to that rule's
// model and optional additional provider.
package typesafejevmodelrouting

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
	utils "github.com/wso2/api-platform/sdk/core/utils"
)

const (
	defaultBaseURL             = "https://api.typesafe.ai"
	defaultJevModel            = "jev-latest"
	defaultContentPath         = "$.messages[-1].content"
	defaultConfidenceThreshold = 0.5
	defaultTimeout             = 5 * time.Second
	maxTimeout                 = 30 * time.Second

	// Jev's documented limit on the number of options in a Choice question.
	maxRoutingRules = 255

	// routeQuestionKey identifies the single Choice question in each Jev call.
	routeQuestionKey          = "route"
	routeQuestionInstructions = "Which routing rule best fits the user's request?"

	// Jev returns 429 when rate limited and 529 when overloaded; both are
	// documented as retryable. One retry with a short backoff, bounded by the
	// same per-call timeout as the first attempt.
	statusJevOverloaded = 529
	retryBackoff        = 250 * time.Millisecond

	// A Jev answer is a few kilobytes, so a larger body is not a valid answer.
	maxJevResponseBytes = 1 << 20
	// Only the start of an error body goes into error messages, which are logged.
	maxJevErrorBodyBytes = 512

	// metadataKeyUsage records Jev token usage in SharedContext.Metadata.
	metadataKeyUsage = "typesafe-jev-model-routing:usage"
)

// RoutingRule is one user-defined routing rule. Name is the option Jev
// chooses between; Context describes it to Jev.
type RoutingRule struct {
	Name     string
	Context  string
	Model    string
	Provider string // Optional additional-provider alias; empty preserves the current upstream.
}

// RequestModelConfig holds where the model name lives in the request.
type RequestModelConfig struct {
	Location   string
	Identifier string
}

// TypesafeJevModelRoutingPolicy routes each request to the model and provider
// of the routing rule Jev chooses.
type TypesafeJevModelRoutingPolicy struct {
	routingRules        []RoutingRule
	defaultModel        string
	defaultProvider     string
	contentPath         string
	confidenceThreshold float64
	timeout             time.Duration
	requestModel        RequestModelConfig

	apiKey   string
	baseURL  string
	jevModel string
	client   *http.Client
}

// GetPolicy is the v1alpha2 factory entry point.
func GetPolicy(
	metadata policy.PolicyMetadata,
	params map[string]interface{},
) (policy.Policy, error) {
	// No client-level timeout: each Jev call is bounded by the configured
	// timeout via context instead.
	p := &TypesafeJevModelRoutingPolicy{client: newPolicyHTTPClient(0, false)}
	if err := parseParams(params, p); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}

	slog.Debug("TypesafeJevModelRouting: Policy initialized",
		"rules", len(p.routingRules),
		"defaultModel", p.defaultModel,
		"confidenceThreshold", p.confidenceThreshold,
	)
	return p, nil
}

// Mode buffers the request body: it is needed to extract the text Jev
// classifies and to rewrite the model.
func (p *TypesafeJevModelRoutingPolicy) Mode() policy.ProcessingMode {
	return policy.ProcessingMode{
		RequestHeaderMode:  policy.HeaderModeSkip,
		RequestBodyMode:    policy.BodyModeBuffer,
		ResponseHeaderMode: policy.HeaderModeSkip,
		ResponseBodyMode:   policy.BodyModeSkip,
	}
}

// OnRequestBody asks Jev which routing rule fits the request and routes to
// that rule's model and provider, falling back to the default target when the
// text can't be extracted, Jev fails, or Jev isn't confident enough.
func (p *TypesafeJevModelRoutingPolicy) OnRequestBody(
	ctx context.Context,
	reqCtx *policy.RequestContext,
	params map[string]interface{},
) policy.RequestAction {
	var content []byte
	if reqCtx.Body != nil {
		content = reqCtx.Body.Content
	}
	if len(content) == 0 {
		slog.Debug("TypesafeJevModelRouting: Request body is empty, preserving current upstream")
		return policy.UpstreamRequestModifications{}
	}

	userText, err := extractRequestText(content, p.contentPath)
	if err != nil {
		slog.Debug("TypesafeJevModelRouting: JSONPath extraction failed, using default model",
			"contentPath", p.contentPath, "error", err)
		return p.modifyRequestModel(reqCtx, content, p.defaultTarget())
	}
	if strings.TrimSpace(userText) == "" {
		slog.Debug("TypesafeJevModelRouting: Extracted text is empty, using default model")
		return p.modifyRequestModel(reqCtx, content, p.defaultTarget())
	}

	answer, usage, err := p.callJev(ctx, userText)
	if usage != nil {
		if reqCtx.Metadata == nil {
			reqCtx.Metadata = make(map[string]interface{})
		}
		reqCtx.Metadata[metadataKeyUsage] = map[string]interface{}{
			"input_tokens": usage.InputTokens, "output_tokens": usage.OutputTokens,
		}
	}
	if err != nil {
		slog.Debug("TypesafeJevModelRouting: Jev call failed, using default model", "error", err)
		return p.modifyRequestModel(reqCtx, content, p.defaultTarget())
	}

	return p.modifyRequestModel(reqCtx, content, p.selectTarget(answer))
}

// selectTarget returns the chosen rule's target when Jev chose a configured
// rule with at least confidenceThreshold probability, else the default target.
func (p *TypesafeJevModelRoutingPolicy) selectTarget(answer choiceAnswer) modelTarget {
	for _, rule := range p.routingRules {
		if rule.Name != answer.Choice {
			continue
		}
		probability := answer.Probabilities[rule.Name]
		if probability < p.confidenceThreshold {
			slog.Debug("TypesafeJevModelRouting: Jev confidence below threshold, using default model",
				"rule", rule.Name, "probability", probability, "threshold", p.confidenceThreshold)
			return p.defaultTarget()
		}
		slog.Debug("TypesafeJevModelRouting: Routing rule selected",
			"rule", rule.Name, "probability", probability, "model", rule.Model, "provider", rule.Provider)
		return modelTarget{Model: rule.Model, Provider: rule.Provider}
	}

	slog.Debug("TypesafeJevModelRouting: Jev chose an unknown rule, using default model", "choice", answer.Choice)
	return p.defaultTarget()
}

// extractRequestText returns the text at contentPath. Like
// utils.ExtractStringValueFromJsonpath it accepts a string or a number, and it
// also reads an OpenAI-style content-part array, joining its text parts and
// skipping non-text parts (images, audio), so a message sent as parts is routed
// on its text instead of falling back to the default target.
func extractRequestText(content []byte, contentPath string) (string, error) {
	if contentPath == "" {
		return string(content), nil
	}
	var payload map[string]interface{}
	if err := json.Unmarshal(content, &payload); err != nil {
		return "", err
	}
	value, err := utils.ExtractValueFromJsonpath(payload, contentPath)
	if err != nil {
		return "", err
	}
	switch v := value.(type) {
	case string:
		return v, nil
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64), nil
	case []interface{}:
		var texts []string
		for i, item := range v {
			switch part := item.(type) {
			case string:
				texts = append(texts, part)
			case map[string]interface{}:
				if text, ok := part["text"].(string); ok {
					texts = append(texts, text)
					continue
				}
				// A typed non-text part is skipped; an untyped object means the
				// path points at something other than content parts.
				if _, typed := part["type"].(string); !typed {
					return "", fmt.Errorf("array element %d at contentPath is not a content part", i)
				}
			default:
				return "", fmt.Errorf("array element %d at contentPath is not a content part", i)
			}
		}
		return strings.Join(texts, "\n"), nil
	default:
		return "", fmt.Errorf("value at contentPath is not a string, number, or content-part array")
	}
}

// modelTarget keeps destination selection atomic, including fallback routing.
type modelTarget struct {
	Model    string
	Provider string
}

func (p *TypesafeJevModelRoutingPolicy) defaultTarget() modelTarget {
	return modelTarget{Model: p.defaultModel, Provider: p.defaultProvider}
}

// modifyRequestModel rewrites the model and selects the named upstream in the
// same action. Empty or invalid payloads keep the no-op behavior so a provider
// never receives a model that failed to be rewritten.
func (p *TypesafeJevModelRoutingPolicy) modifyRequestModel(reqCtx *policy.RequestContext, content []byte, selected modelTarget) policy.RequestAction {
	mods := policy.UpstreamRequestModifications{}
	if p.requestModel.Location != "payload" || len(content) == 0 {
		return mods
	}
	var payloadData map[string]interface{}
	if err := json.Unmarshal(content, &payloadData); err != nil || payloadData == nil {
		slog.Debug("TypesafeJevModelRouting: Failed to parse request body JSON", "error", err)
		return mods
	}
	if err := utils.SetValueAtJSONPath(payloadData, p.requestModel.Identifier, selected.Model); err != nil {
		slog.Debug("TypesafeJevModelRouting: Failed to set model in request body", "error", err)
		return mods
	}
	updatedPayload, err := json.Marshal(payloadData)
	if err != nil {
		slog.Debug("TypesafeJevModelRouting: Failed to serialize updated body", "error", err)
		return mods
	}
	mods.Body = updatedPayload

	// This engine-level key lets subsequent conditional auth and protocol
	// transformers identify the same provider as the named upstream override.
	// An omitted provider leaves prior routing metadata and the upstream intact.
	if selected.Provider != "" {
		providerName := selected.Provider
		mods.UpstreamName = &providerName
		if reqCtx.Metadata == nil {
			reqCtx.Metadata = make(map[string]interface{})
		}
		reqCtx.Metadata["selected_provider"] = providerName
	}
	return mods
}

// --- Jev API client ---

type jevQuestionPayload struct {
	Type         string      `json:"type"`
	Instructions string      `json:"instructions"`
	Criteria     interface{} `json:"criteria,omitempty"`
}

type jevSystemOneRequest struct {
	State     string                        `json:"state"`
	Model     string                        `json:"model"`
	Questions map[string]jevQuestionPayload `json:"questions"`
}

type jevUsage struct {
	InputTokens  int `json:"input_tokens"`
	OutputTokens int `json:"output_tokens"`
}

type jevSystemOneResponse struct {
	Answers map[string]json.RawMessage `json:"answers"`
	Usage   *jevUsage                  `json:"usage"`
}

// callJev asks Jev a single Choice question over the routing rule names, each
// described by its context, and returns the decoded answer.
func (p *TypesafeJevModelRoutingPolicy) callJev(ctx context.Context, state string) (choiceAnswer, *jevUsage, error) {
	options := make(map[string]string, len(p.routingRules))
	for _, rule := range p.routingRules {
		options[rule.Name] = rule.Context
	}
	reqBody := jevSystemOneRequest{
		State: state,
		Model: p.jevModel,
		Questions: map[string]jevQuestionPayload{
			routeQuestionKey: {Type: "choice", Instructions: routeQuestionInstructions, Criteria: options},
		},
	}
	payload, err := json.Marshal(reqBody)
	if err != nil {
		return choiceAnswer{}, nil, fmt.Errorf("failed to marshal Jev request: %w", err)
	}

	ctx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()

	status, body, err := p.postSystemOne(ctx, payload)
	if err == nil && (status == http.StatusTooManyRequests || status == statusJevOverloaded) {
		slog.Debug("TypesafeJevModelRouting: Jev rate limited or overloaded, retrying once", "status", status)
		select {
		case <-ctx.Done():
			return choiceAnswer{}, nil, fmt.Errorf("Jev API returned status %d and timed out before retry: %w", status, ctx.Err())
		case <-time.After(retryBackoff):
		}
		status, body, err = p.postSystemOne(ctx, payload)
	}
	if err != nil {
		return choiceAnswer{}, nil, err
	}
	if status != http.StatusOK {
		return choiceAnswer{}, nil, fmt.Errorf("Jev API returned status %d: %s", status, errorSnippet(body))
	}

	var parsed jevSystemOneResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return choiceAnswer{}, nil, fmt.Errorf("failed to decode Jev response: %w", err)
	}
	raw, ok := parsed.Answers[routeQuestionKey]
	if !ok {
		return choiceAnswer{}, parsed.Usage, fmt.Errorf("Jev response has no answer for %q", routeQuestionKey)
	}
	answer, err := decodeChoiceAnswer(raw)
	if err != nil {
		return choiceAnswer{}, parsed.Usage, fmt.Errorf("invalid Jev answer: %w", err)
	}
	return answer, parsed.Usage, nil
}

func (p *TypesafeJevModelRoutingPolicy) postSystemOne(ctx context.Context, payload []byte) (int, []byte, error) {
	url := strings.TrimSuffix(p.baseURL, "/") + "/v1/systemone"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return 0, nil, fmt.Errorf("failed to create Jev HTTP request: %w", err)
	}
	httpReq.Header.Set("Authorization", "Bearer "+p.apiKey)
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := p.client.Do(httpReq)
	if err != nil {
		return 0, nil, fmt.Errorf("Jev HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxJevResponseBytes+1))
	if err != nil {
		return 0, nil, fmt.Errorf("failed to read Jev response: %w", err)
	}
	if len(body) > maxJevResponseBytes {
		// A successful answer that doesn't fit is rejected rather than decoded
		// from a truncated body. An error body only feeds a diagnostic, so it is
		// cut instead, keeping the status for the retry decision.
		if resp.StatusCode == http.StatusOK {
			return 0, nil, fmt.Errorf("Jev response exceeds %d bytes", maxJevResponseBytes)
		}
		body = body[:maxJevResponseBytes]
	}
	return resp.StatusCode, body, nil
}

// errorSnippet returns the start of a Jev error body for an error message.
func errorSnippet(body []byte) string {
	if len(body) <= maxJevErrorBodyBytes {
		return string(body)
	}
	return string(body[:maxJevErrorBodyBytes]) + "... (truncated)"
}

type choiceAnswer struct {
	Choice        string
	Probabilities map[string]float64
	Confidence    *float64
}

// decodeChoiceAnswer requires "probabilities" to be present, since the chosen
// rule's probability is compared against confidenceThreshold; a missing
// distribution must not decode as zero confidence in every rule.
func decodeChoiceAnswer(raw json.RawMessage) (choiceAnswer, error) {
	var a struct {
		Choice        string             `json:"choice"`
		Probabilities map[string]float64 `json:"probabilities"`
		Confidence    *float64           `json:"confidence"`
	}
	if err := json.Unmarshal(raw, &a); err != nil {
		return choiceAnswer{}, err
	}
	if a.Probabilities == nil {
		return choiceAnswer{}, fmt.Errorf("answer missing 'probabilities' field")
	}
	return choiceAnswer{Choice: a.Choice, Probabilities: a.Probabilities, Confidence: a.Confidence}, nil
}

// --- Parameter parsing ---

func parseParams(params map[string]interface{}, p *TypesafeJevModelRoutingPolicy) error {
	apiKey, err := requiredStringParam(params, "apiKey")
	if err != nil {
		return err
	}
	p.apiKey = apiKey
	p.baseURL = stringParamOrDefault(params, "baseURL", defaultBaseURL)
	p.jevModel = stringParamOrDefault(params, "model", defaultJevModel)

	// Default to the final message content unless a non-empty path is configured.
	p.contentPath = defaultContentPath
	if contentPath, ok := params["contentPath"].(string); ok && contentPath != "" {
		p.contentPath = contentPath
	}

	rules, err := parseRoutingRules(params)
	if err != nil {
		return err
	}
	p.routingRules = rules

	defaultModel, ok := params["defaultModel"].(string)
	if !ok || defaultModel == "" {
		return fmt.Errorf("'defaultModel' parameter is required")
	}
	p.defaultModel = defaultModel

	defaultProvider, err := parseOptionalProvider(params, "defaultProvider", "defaultProvider")
	if err != nil {
		return err
	}
	p.defaultProvider = defaultProvider

	p.confidenceThreshold = defaultConfidenceThreshold
	if raw, ok := params["confidenceThreshold"]; ok {
		threshold, ok := numberParam(raw)
		if !ok {
			return fmt.Errorf("'confidenceThreshold' must be a number")
		}
		if threshold < 0 || threshold > 1 {
			return fmt.Errorf("'confidenceThreshold' must be between 0 and 1")
		}
		p.confidenceThreshold = threshold
	}

	p.timeout = defaultTimeout
	if raw, ok := params["timeout"]; ok {
		timeoutStr, ok := raw.(string)
		if !ok {
			return fmt.Errorf("'timeout' must be a duration string (e.g. \"5s\")")
		}
		timeout, err := time.ParseDuration(timeoutStr)
		if err != nil {
			return fmt.Errorf("'timeout' is not a valid duration: %w", err)
		}
		if timeout <= 0 || timeout > maxTimeout {
			return fmt.Errorf("'timeout' must be greater than 0 and at most %s", maxTimeout)
		}
		p.timeout = timeout
	}

	return parseRequestModelConfig(params, p)
}

func parseRoutingRules(params map[string]interface{}) ([]RoutingRule, error) {
	raw, ok := params["routingRules"]
	if !ok {
		return nil, fmt.Errorf("'routingRules' parameter is required")
	}
	list, ok := raw.([]interface{})
	if !ok {
		return nil, fmt.Errorf("'routingRules' must be an array")
	}
	if len(list) == 0 {
		return nil, fmt.Errorf("'routingRules' must contain at least one rule")
	}
	if len(list) > maxRoutingRules {
		return nil, fmt.Errorf("'routingRules' must contain at most %d rules", maxRoutingRules)
	}

	rules := make([]RoutingRule, 0, len(list))
	seen := make(map[string]bool, len(list))
	for i, item := range list {
		ruleMap, ok := item.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("'routingRules[%d]' must be an object", i)
		}
		rule, err := parseRoutingRule(ruleMap, i)
		if err != nil {
			return nil, err
		}
		// Rule names are the options Jev chooses between, so they must be unique.
		if seen[rule.Name] {
			return nil, fmt.Errorf("'routingRules[%d].name' %q is a duplicate; rule names must be unique", i, rule.Name)
		}
		seen[rule.Name] = true
		rules = append(rules, rule)
	}
	return rules, nil
}

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

	provider, err := parseOptionalProvider(ruleMap, "provider", fmt.Sprintf("routingRules[%d].provider", index))
	if err != nil {
		return rule, err
	}
	rule.Provider = provider

	return rule, nil
}

// parseOptionalProvider accepts an additional-provider alias, not a provider
// type enum. Empty or omitted values preserve existing upstream selection.
func parseOptionalProvider(params map[string]interface{}, key, field string) (string, error) {
	raw, exists := params[key]
	if !exists {
		return "", nil
	}
	provider, ok := raw.(string)
	if !ok {
		return "", fmt.Errorf("'%s' must be a string", field)
	}
	return strings.TrimSpace(provider), nil
}

// parseRequestModelConfig parses where the model name lives in the request.
// The gateway supplies it from the LLM provider template.
func parseRequestModelConfig(params map[string]interface{}, p *TypesafeJevModelRoutingPolicy) error {
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
	// Only the payload location is implemented: the model is rewritten inside
	// the JSON body during the request body phase.
	if location != "payload" {
		return fmt.Errorf("'requestModel.location' must be 'payload'")
	}
	p.requestModel.Location = location

	identifier, ok := requestModelMap["identifier"].(string)
	if !ok || identifier == "" {
		return fmt.Errorf("'requestModel.identifier' is required")
	}
	p.requestModel.Identifier = identifier
	return nil
}

func requiredStringParam(params map[string]interface{}, key string) (string, error) {
	raw, ok := params[key]
	if !ok {
		return "", fmt.Errorf("'%s' parameter is required", key)
	}
	value, ok := raw.(string)
	if !ok || value == "" {
		return "", fmt.Errorf("'%s' must be a non-empty string", key)
	}
	return value, nil
}

func stringParamOrDefault(params map[string]interface{}, key, def string) string {
	if raw, ok := params[key]; ok {
		if value, ok := raw.(string); ok && value != "" {
			return value
		}
	}
	return def
}

// numberParam accepts the numeric types params can decode to.
func numberParam(raw interface{}) (float64, bool) {
	switch v := raw.(type) {
	case float64:
		return v, true
	case float32:
		return float64(v), true
	case int:
		return float64(v), true
	case int64:
		return float64(v), true
	default:
		return 0, false
	}
}
