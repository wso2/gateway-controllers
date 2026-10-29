/*
 * Copyright (c) 2025, WSO2 LLC. (https://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package modelroundrobin

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
	utils "github.com/wso2/api-platform/sdk/core/utils"
)

const (
	// Metadata keys for context storage
	MetadataKeySelectedModel    = "model_roundrobin.selected_model"
	MetadataKeySelectedProvider = "model_roundrobin.selected_provider"
	MetadataKeyOriginalModel    = "model_roundrobin.original_model"
	MetadataKeyHeadersProcessed = "model_roundrobin.headers_processed"
	DefaultSuspendDuration      = 30

	// MetadataKeyProviderRouting is the engine-level contract key consumed by
	// conditional provider auth and protocol transformers to identify the
	// additional provider a request was routed to. It is only set when the
	// selected target specifies a provider.
	MetadataKeyProviderRouting = "selected_provider"

	// MetadataKeyPublishedRanking carries this policy's full rotation order for the request,
	// per specs/001-model-failover-policy/contracts/target-preference-list.md. A failover
	// policy traverses it after the leading target fails, so retries follow round-robin's own
	// order instead of a separately configured list.
	//
	// The value is []map[string]string with keys "model" and optional "provider" — BUILT-IN
	// TYPES ONLY. The consumer lives in a different Go module, and a Go type assertion matches
	// identical named types rather than structurally compatible ones, so publishing a struct
	// here would be silently unreadable. The single-selection keys above are plain strings for
	// the same reason.
	MetadataKeyPublishedRanking = "model_routing.published_ranking"

	// suspensionKeySeparator separates provider and model in the composite
	// suspension key so the same model name on different providers is tracked
	// independently. A NUL byte can never appear in a provider or model name.
	suspensionKeySeparator = "\x00"
)

// ModelRoundRobinPolicyParams holds the parsed policy parameters
type ModelRoundRobinPolicyParams struct {
	Models          []ModelConfig
	SuspendDuration int
	RequestModel    RequestModelConfig
}

// ModelConfig represents a single model configuration
type ModelConfig struct {
	Model string
	// Provider optionally names an additional LLM provider to route this target to.
	// It must match an LlmProxy additionalProviders[].as value (or the provider id
	// when `as` is absent). Empty means the LlmProxy primary/default provider.
	Provider string
}

// suspensionKey builds the composite key used to track failed targets. Keying on
// provider + model (rather than model alone) keeps the same model name on
// different providers independently suspendable.
func suspensionKey(provider, model string) string {
	return provider + suspensionKeySeparator + model
}

// RequestModelConfig holds the requestModel configuration
type RequestModelConfig struct {
	Location   string
	Identifier string
}

// ModelRoundRobinPolicy implements round-robin load balancing for AI models
type ModelRoundRobinPolicy struct {
	currentIndex    int
	mu              sync.Mutex
	suspendedModels map[string]time.Time // Track suspended models
	params          ModelRoundRobinPolicyParams
}

// GetPolicy is the v1alpha2 factory entry point (loaded by v1alpha2 kernels).
func GetPolicy(
	metadata policy.PolicyMetadata,
	params map[string]interface{},
) (policy.Policy, error) {
	// Parse and validate parameters
	policyParams, err := parseParams(params)
	if err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}

	p := &ModelRoundRobinPolicy{
		currentIndex:    0,
		suspendedModels: make(map[string]time.Time),
		params:          policyParams,
	}

	return p, nil
}

func (p *ModelRoundRobinPolicy) Mode() policy.ProcessingMode {
	return policy.ProcessingMode{
		RequestHeaderMode:  policy.HeaderModeProcess,
		RequestBodyMode:    policy.BodyModeBuffer,
		ResponseHeaderMode: policy.HeaderModeProcess,
		ResponseBodyMode:   policy.BodyModeSkip,
	}
}

// parseParams parses and validates parameters from map to struct
func parseParams(params map[string]interface{}) (ModelRoundRobinPolicyParams, error) {
	result := ModelRoundRobinPolicyParams{
		SuspendDuration: DefaultSuspendDuration,
	}

	// Parse models parameter (required)
	modelsRaw, ok := params["models"]
	if !ok {
		return result, fmt.Errorf("'models' parameter is required")
	}

	modelList, ok := modelsRaw.([]interface{})
	if !ok {
		return result, fmt.Errorf("'models' must be an array")
	}

	if len(modelList) == 0 {
		return result, fmt.Errorf("'models' array must contain at least one model")
	}

	// Parse each model in the array
	result.Models = make([]ModelConfig, 0, len(modelList))
	for i, item := range modelList {
		modelMap, ok := item.(map[string]interface{})
		if !ok {
			return result, fmt.Errorf("'models[%d]' must be an object", i)
		}

		var modelConfig ModelConfig

		// Parse model name (required)
		modelName, ok := modelMap["model"]
		if !ok {
			return result, fmt.Errorf("'models[%d].model' is required", i)
		}

		modelNameStr, ok := modelName.(string)
		if !ok {
			return result, fmt.Errorf("'models[%d].model' must be a string", i)
		}

		if len(modelNameStr) == 0 {
			return result, fmt.Errorf("'models[%d].model' must have a minimum length of 1", i)
		}
		modelConfig.Model = modelNameStr

		// Parse provider (optional). Omitted or empty means the LlmProxy
		// primary/default provider is used and no upstream override is applied.
		if providerRaw, ok := modelMap["provider"]; ok {
			providerStr, ok := providerRaw.(string)
			if !ok {
				return result, fmt.Errorf("'models[%d].provider' must be a string", i)
			}
			modelConfig.Provider = providerStr
		}

		result.Models = append(result.Models, modelConfig)
	}

	// Parse suspendDuration if provided (optional)
	if suspendDuration, ok := params["suspendDuration"]; ok {
		suspendDurationInt, err := extractInt(suspendDuration)
		if err != nil {
			return result, fmt.Errorf("'suspendDuration' must be an integer: %w", err)
		}

		if suspendDurationInt < 0 {
			return result, fmt.Errorf("'suspendDuration' must be >= 0")
		}
		result.SuspendDuration = suspendDurationInt
	}

	// Parse requestModel configuration (required, comes from systemParameters)
	requestModel, ok := params["requestModel"]
	if !ok {
		return result, fmt.Errorf("'requestModel' configuration is required")
	}

	requestModelMap, ok := requestModel.(map[string]interface{})
	if !ok {
		return result, fmt.Errorf("'requestModel' must be an object")
	}

	// Parse location (required)
	location, ok := requestModelMap["location"]
	if !ok {
		return result, fmt.Errorf("'requestModel.location' is required")
	}

	locationStr, ok := location.(string)
	if !ok {
		return result, fmt.Errorf("'requestModel.location' must be a string")
	}

	// Validate location value
	validLocations := map[string]bool{
		"payload":    true,
		"header":     true,
		"queryParam": true,
		"pathParam":  true,
	}
	if !validLocations[locationStr] {
		return result, fmt.Errorf("'requestModel.location' must be one of: payload, header, queryParam, pathParam")
	}
	result.RequestModel.Location = locationStr

	// Parse identifier (required)
	identifier, ok := requestModelMap["identifier"]
	if !ok {
		return result, fmt.Errorf("'requestModel.identifier' is required")
	}

	identifierStr, ok := identifier.(string)
	if !ok {
		return result, fmt.Errorf("'requestModel.identifier' must be a string")
	}

	if len(identifierStr) == 0 {
		return result, fmt.Errorf("'requestModel.identifier' must have a minimum length of 1")
	}
	result.RequestModel.Identifier = identifierStr

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
	default:
		return 0, fmt.Errorf("cannot convert %T to int", value)
	}
}

// selectNextAvailableModel selects the next available model in round-robin fashion
func (p *ModelRoundRobinPolicy) selectNextAvailableModel(models []ModelConfig) *ModelConfig {
	selected, _ := p.selectNextAvailableModelAt(models)
	return selected
}

// selectNextAvailableModelAt is selectNextAvailableModel plus the index it landed on, which is
// what the published rotation has to start from. Returning the model alone would force a
// search by value, and a configuration may legitimately list the same model twice under
// different providers.
func (p *ModelRoundRobinPolicy) selectNextAvailableModelAt(models []ModelConfig) (*ModelConfig, int) {
	p.mu.Lock()
	defer p.mu.Unlock()

	now := time.Now()
	attemptCount := 0
	totalModels := len(models)

	for attemptCount < totalModels {
		// Get current model (copy to avoid returning pointer to slice element)
		selectedIndex := p.currentIndex
		selectedModel := models[selectedIndex]
		key := suspensionKey(selectedModel.Provider, selectedModel.Model)

		// Move to next index for next call
		p.currentIndex = (p.currentIndex + 1) % totalModels

		// Check if this provider/model pair is suspended
		if suspendedUntil, ok := p.suspendedModels[key]; ok {
			if now.Before(suspendedUntil) {
				// This target is still suspended, try next
				attemptCount++
				continue
			}
			// Suspension period has expired, remove from suspended list
			delete(p.suspendedModels, key)
		}

		return &selectedModel, selectedIndex
	}

	return nil, -1
}

// publishRotation renders the full rotation starting at the selected position into the
// preference-list contract's wire representation.
//
// The whole rotation, not just the winner: a failover policy that only learned the winner would
// have to invent what comes after it, and the point of the contract is that retries follow this
// policy's own order. Starting at the selected position is what makes the order meaningful —
// the leading entry is the target this request actually goes to.
//
// Published unconditionally, even for a single-model configuration, so a consumer never has to
// distinguish "one model" from "this policy did not publish".
func publishRotation(models []ModelConfig, selectedIndex int) []map[string]string {
	if selectedIndex < 0 || len(models) == 0 {
		return nil
	}
	rotation := make([]map[string]string, 0, len(models))
	for offset := 0; offset < len(models); offset++ {
		m := models[(selectedIndex+offset)%len(models)]
		if m.Model == "" {
			continue
		}
		entry := map[string]string{"model": m.Model}
		if m.Provider != "" {
			entry["provider"] = m.Provider
		}
		rotation = append(rotation, entry)
	}
	return rotation
}

// OnRequestHeaders selects the next model and applies the modification for header/queryParam/pathParam
// locations in the request header phase. For payload location, the model is pre-selected and
// stored in metadata for OnRequest to apply to the body.
func (p *ModelRoundRobinPolicy) OnRequestHeaders(ctx context.Context, reqCtx *policy.RequestHeaderContext, params map[string]interface{}) policy.RequestHeaderAction {
	location := p.params.RequestModel.Location
	identifier := p.params.RequestModel.Identifier

	// Select next available model in round-robin fashion
	selectedModel, selectedIndex := p.selectNextAvailableModelAt(p.params.Models)
	if selectedModel == nil {
		return policy.ImmediateResponse{
			StatusCode: 503,
			Headers:    map[string]string{"Content-Type": "application/json"},
			Body:       []byte(`{"error": "All models are currently unavailable"}`),
		}
	}

	// Always record the selected model and its provider. The provider is stored
	// under a policy-internal key so OnResponseHeaders can rebuild the composite
	// suspension key even for the default (empty) provider.
	reqCtx.Metadata[MetadataKeySelectedModel] = selectedModel.Model
	reqCtx.Metadata[MetadataKeySelectedProvider] = selectedModel.Provider
	reqCtx.Metadata[MetadataKeyHeadersProcessed] = true

	// Publish the whole rotation for a failover policy to traverse. Set alongside the
	// single-selection keys, never instead of them: every other consumer reads those, and a
	// policy that has not adopted the contract must keep working unchanged.
	if rotation := publishRotation(p.params.Models, selectedIndex); len(rotation) > 0 {
		reqCtx.Metadata[MetadataKeyPublishedRanking] = rotation
	}
	slog.Debug("ModelRoundRobin: OnRequestHeaders selected model", "model", selectedModel.Model, "provider", selectedModel.Provider)

	mods := policy.UpstreamRequestHeaderModifications{}

	// When the target names an additional provider, route to its named upstream in
	// the header phase (so Envoy sees the selected cluster before forwarding) and
	// expose it to conditional provider auth / protocol transformers via the
	// engine's selected_provider metadata key. When the provider is empty we leave
	// UpstreamName unset and do not set selected_provider, so the LlmProxy primary
	// provider fallback, authentication, and default cluster logic keep working.
	if selectedModel.Provider != "" {
		providerName := selectedModel.Provider
		mods.UpstreamName = &providerName
		reqCtx.Metadata[MetadataKeyProviderRouting] = selectedModel.Provider
	}

	switch location {
	case "header":
		// Capture the ORIGINAL client model from the downstream snapshot
		// so metadata records what the client actually sent.
		if h := reqCtx.DownstreamHeaders(); h != nil {
			values := h.Get(identifier)
			if len(values) > 0 && values[0] != "" {
				reqCtx.Metadata[MetadataKeyOriginalModel] = values[0]
			}
		}
		mods.HeadersToSet = map[string]string{identifier: selectedModel.Model}
	case "queryParam":
		newPath := p.modifyQueryParamInPath(reqCtx.Path, identifier, selectedModel.Model)
		if newPath != reqCtx.Path {
			mods.Path = &newPath
		}
	case "pathParam":
		newPath := p.modifyPathParamInPath(reqCtx.Path, identifier, selectedModel.Model)
		if newPath != reqCtx.Path {
			mods.Path = &newPath
		}
	}
	return mods
}

// OnResponseHeaders suspends a model in the response header phase when an error is detected.
//
// Runs unchanged when a failover policy also governs the operation. The downstream chain is
// entered once per client request, so the status seen here is the FINAL one: a request failover
// rescued reports success and suspends nothing, and a 5xx only arrives once the whole chain is
// exhausted — which means the target selected here failed too. The two health views are
// independent and both correct, so neither needs to defer to the other.
func (p *ModelRoundRobinPolicy) OnResponseHeaders(ctx context.Context, respCtx *policy.ResponseHeaderContext, params map[string]interface{}) policy.ResponseHeaderAction {
	if respCtx.ResponseStatus >= 500 || respCtx.ResponseStatus == 429 {
		selectedModel := ""
		if model, ok := respCtx.Metadata[MetadataKeySelectedModel]; ok {
			if modelStr, ok := model.(string); ok {
				selectedModel = modelStr
			}
		}
		selectedProvider := ""
		if provider, ok := respCtx.Metadata[MetadataKeySelectedProvider]; ok {
			if providerStr, ok := provider.(string); ok {
				selectedProvider = providerStr
			}
		}
		if p.params.SuspendDuration > 0 && selectedModel != "" {
			// Suspend only the selected provider/model pair, not the model name on
			// every provider.
			key := suspensionKey(selectedProvider, selectedModel)
			p.mu.Lock()
			p.suspendedModels[key] = time.Now().Add(time.Duration(p.params.SuspendDuration) * time.Second)
			p.mu.Unlock()
			slog.Debug("ModelRoundRobin: OnResponseHeaders suspended model", "model", selectedModel, "provider", selectedProvider, "duration", p.params.SuspendDuration)
		}
	}
	return policy.DownstreamResponseHeaderModifications{}
}

// OnRequestBody processes the request body in the v1alpha2 engine.
// Since OnRequestHeaders always runs first in the v1alpha2 engine, only the payload
// location case requires body-phase processing.
func (p *ModelRoundRobinPolicy) OnRequestBody(ctx context.Context, reqCtx *policy.RequestContext, _ map[string]interface{}) policy.RequestAction {
	if p.params.RequestModel.Location != "payload" {
		// Non-payload locations were handled in OnRequestHeaders
		return policy.UpstreamRequestModifications{}
	}

	selectedModel, _ := reqCtx.Metadata[MetadataKeySelectedModel].(string)
	if selectedModel == "" {
		return policy.UpstreamRequestModifications{}
	}

	if reqCtx.Body == nil || reqCtx.Body.Content == nil {
		return policy.ImmediateResponse{
			StatusCode: 400,
			Headers:    map[string]string{"Content-Type": "application/json"},
			Body:       []byte(`{"error":"Request body is empty."}`),
		}
	}

	var payloadData map[string]interface{}
	if err := json.Unmarshal(reqCtx.Body.Content, &payloadData); err != nil {
		return policy.ImmediateResponse{
			StatusCode: 400,
			Headers:    map[string]string{"Content-Type": "application/json"},
			Body:       []byte(fmt.Sprintf(`{"error":"Invalid JSON in request body: %s"}`, err.Error())),
		}
	}

	identifier := p.params.RequestModel.Identifier
	if err := utils.SetValueAtJSONPath(payloadData, identifier, selectedModel); err != nil {
		return policy.ImmediateResponse{
			StatusCode: 400,
			Headers:    map[string]string{"Content-Type": "application/json"},
			Body:       []byte(fmt.Sprintf(`{"error":"Invalid or missing model at '%s': %s"}`, identifier, err.Error())),
		}
	}

	updatedPayload, err := json.Marshal(payloadData)
	if err != nil {
		return policy.ImmediateResponse{
			StatusCode: 500,
			Headers:    map[string]string{"Content-Type": "application/json"},
			Body:       []byte(fmt.Sprintf(`{"error":"Failed to serialize updated request body: %s"}`, err.Error())),
		}
	}

	slog.Debug("ModelRoundRobin: OnRequestBody modified payload model", "newModel", selectedModel)
	return policy.UpstreamRequestModifications{Body: updatedPayload}
}

// modifyQueryParamInPath updates a query parameter value in a raw path string.
func (p *ModelRoundRobinPolicy) modifyQueryParamInPath(rawPath, paramName, newModel string) string {
	if rawPath == "" {
		return rawPath
	}
	decodedPath, err := url.PathUnescape(rawPath)
	if err != nil {
		return rawPath
	}
	parts := strings.Split(decodedPath, "?")
	pathBase := parts[0]
	var queryValues url.Values
	if len(parts) == 2 {
		queryValues, err = url.ParseQuery(parts[1])
		if err != nil {
			return rawPath
		}
	} else {
		queryValues = make(url.Values)
	}
	queryValues.Set(paramName, newModel)
	return pathBase + "?" + queryValues.Encode()
}

// modifyPathParamInPath replaces a regex capture group in a raw path string.
func (p *ModelRoundRobinPolicy) modifyPathParamInPath(rawPath, regexPattern, newModel string) string {
	if rawPath == "" {
		return rawPath
	}
	decodedPath, err := url.PathUnescape(rawPath)
	if err != nil {
		return rawPath
	}
	parts := strings.Split(decodedPath, "?")
	pathWithoutQuery := parts[0]
	queryString := ""
	if len(parts) == 2 {
		queryString = parts[1]
	}
	re, err := regexp.Compile(regexPattern)
	if err != nil {
		return rawPath
	}
	matchIndices := re.FindStringSubmatchIndex(pathWithoutQuery)
	if len(matchIndices) < 4 || matchIndices[2] == -1 || matchIndices[3] == -1 {
		return rawPath
	}
	updatedPath := pathWithoutQuery[:matchIndices[2]] + newModel + pathWithoutQuery[matchIndices[3]:]
	if queryString != "" {
		return updatedPath + "?" + queryString
	}
	return updatedPath
}
