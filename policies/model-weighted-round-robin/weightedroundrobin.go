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

package modelweightedroundrobin

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
	MetadataKeySelectedModel    = "model_weighted_roundrobin.selected_model"
	MetadataKeyOriginalModel    = "model_weighted_roundrobin.original_model"
	MetadataKeyHeadersProcessed = "model_weighted_roundrobin.headers_processed"
	DefaultSuspendDuration      = 30
)

// ModelWeightedRoundRobinPolicyParams holds the parsed policy parameters
type ModelWeightedRoundRobinPolicyParams struct {
	Models          []WeightedModel
	SuspendDuration int
	RequestModel    RequestModelConfig
}

// WeightedModel represents a single weighted model configuration
type WeightedModel struct {
	Model  string
	Weight int
}

// RequestModelConfig holds the requestModel configuration
type RequestModelConfig struct {
	Location   string
	Identifier string
}

// ModelWeightedRoundRobinPolicy implements weighted round-robin load balancing for AI models
type ModelWeightedRoundRobinPolicy struct {
	currentIndex     int
	mu               sync.Mutex
	suspendedModels  map[string]time.Time // Track suspended models
	weightedSequence []*WeightedModel     // Pre-computed weighted sequence
	sequenceMu       sync.RWMutex         // Mutex for weighted sequence
	params           ModelWeightedRoundRobinPolicyParams
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

	// Convert WeightedModel slice to WeightedModel slice and build weighted sequence
	weightedModels := make([]*WeightedModel, len(policyParams.Models))
	for i, modelConfig := range policyParams.Models {
		weightedModels[i] = &WeightedModel{
			Model:  modelConfig.Model,
			Weight: modelConfig.Weight,
		}
	}

	p := &ModelWeightedRoundRobinPolicy{
		currentIndex:     0,
		suspendedModels:  make(map[string]time.Time),
		weightedSequence: buildWeightedSequence(weightedModels),
		params:           policyParams,
	}

	return p, nil
}

func (p *ModelWeightedRoundRobinPolicy) Mode() policy.ProcessingMode {
	return policy.ProcessingMode{
		RequestHeaderMode:  policy.HeaderModeProcess,
		RequestBodyMode:    policy.BodyModeBuffer,
		ResponseHeaderMode: policy.HeaderModeProcess,
		ResponseBodyMode:   policy.BodyModeSkip,
	}
}

// parseParams parses and validates parameters from map to struct
func parseParams(params map[string]interface{}) (ModelWeightedRoundRobinPolicyParams, error) {
	result := ModelWeightedRoundRobinPolicyParams{
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
	result.Models = make([]WeightedModel, 0, len(modelList))
	for i, item := range modelList {
		modelMap, ok := item.(map[string]interface{})
		if !ok {
			return result, fmt.Errorf("'models[%d]' must be an object", i)
		}

		var modelConfig WeightedModel

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

		// Parse weight (required)
		weight, ok := modelMap["weight"]
		if !ok {
			return result, fmt.Errorf("'models[%d].weight' is required", i)
		}

		weightInt, err := extractInt(weight)
		if err != nil {
			return result, fmt.Errorf("'models[%d].weight' must be an integer: %w", i, err)
		}

		if weightInt < 1 {
			return result, fmt.Errorf("'models[%d].weight' must be >= 1", i)
		}

		modelConfig.Weight = weightInt

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

// selectNextAvailableWeightedModel selects the next available model based on weight distribution
func (p *ModelWeightedRoundRobinPolicy) selectNextAvailableWeightedModel() *WeightedModel {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.sequenceMu.RLock()
	sequence := p.weightedSequence
	p.sequenceMu.RUnlock()

	if len(sequence) == 0 {
		return nil
	}

	now := time.Now()
	attemptCount := 0

	// Try to find an available model starting from current index
	for attemptCount < len(sequence) {
		selectedModel := sequence[p.currentIndex%len(sequence)]
		p.currentIndex++

		// Check if model is suspended
		if suspendedUntil, ok := p.suspendedModels[selectedModel.Model]; ok {
			if now.Before(suspendedUntil) {
				// This model is still suspended, try next
				attemptCount++
				continue
			}
			// Suspension period has expired, remove from suspended list
			delete(p.suspendedModels, selectedModel.Model)
		}

		return selectedModel
	}

	return nil
}

// buildWeightedSequence creates a sequence of models distributed according to their weights
func buildWeightedSequence(weightedModels []*WeightedModel) []*WeightedModel {
	var sequence []*WeightedModel

	// Calculate total weight
	totalWeight := 0
	for _, m := range weightedModels {
		if m.Weight > 0 {
			totalWeight += m.Weight
		}
	}

	if totalWeight == 0 {
		return sequence
	}

	// Build sequence by repeating models based on their weight
	// This ensures proportional distribution
	for _, model := range weightedModels {
		if model.Weight > 0 {
			// Each model is repeated based on its weight
			for i := 0; i < model.Weight; i++ {
				sequence = append(sequence, model)
			}
		}
	}

	return sequence
}

// OnRequestHeaders selects the next weighted model and applies the modification for
// header/queryParam/pathParam locations in the request header phase.
// For payload location, the model is pre-selected and stored in metadata for OnRequest.
func (p *ModelWeightedRoundRobinPolicy) OnRequestHeaders(ctx context.Context, reqCtx *policy.RequestHeaderContext, params map[string]interface{}) policy.RequestHeaderAction {
	location := p.params.RequestModel.Location
	identifier := p.params.RequestModel.Identifier

	selectedModel := p.selectNextAvailableWeightedModel()
	if selectedModel == nil {
		return policy.ImmediateResponse{
			StatusCode: 503,
			Headers:    map[string]string{"Content-Type": "application/json"},
			Body:       []byte(`{"error": "All models are currently unavailable"}`),
		}
	}

	reqCtx.Metadata[MetadataKeySelectedModel] = selectedModel.Model
	reqCtx.Metadata[MetadataKeyHeadersProcessed] = true
	slog.Debug("ModelWeightedRoundRobin: OnRequestHeaders selected model", "model", selectedModel.Model, "weight", selectedModel.Weight)

	switch location {
	case "header":
		// Capture the ORIGINAL client model from the downstream snapshot
		// so metadata records what the client actually sent, not a value a peer
		// policy rewrote during the header phase (the rewrite itself is emitted
		// separately via HeadersToSet).
		if h := getDownstreamHeaders(reqCtx.Downstream, reqCtx.Headers); h != nil {
			values := h.Get(identifier)
			if len(values) > 0 && values[0] != "" {
				reqCtx.Metadata[MetadataKeyOriginalModel] = values[0]
			}
		}
		return policy.UpstreamRequestHeaderModifications{
			HeadersToSet: map[string]string{identifier: selectedModel.Model},
		}
	case "queryParam":
		newPath := p.modifyQueryParamInPath(reqCtx.Path, identifier, selectedModel.Model)
		if newPath != reqCtx.Path {
			return policy.UpstreamRequestHeaderModifications{
				Path: &newPath,
			}
		}
		return policy.UpstreamRequestHeaderModifications{}
	case "pathParam":
		newPath := p.modifyPathParamInPath(reqCtx.Path, identifier, selectedModel.Model)
		if newPath != reqCtx.Path {
			return policy.UpstreamRequestHeaderModifications{
				Path: &newPath,
			}
		}
	}
	return policy.UpstreamRequestHeaderModifications{}
}

// OnResponseHeaders suspends a model in the response header phase when an error is detected.
func (p *ModelWeightedRoundRobinPolicy) OnResponseHeaders(ctx context.Context, respCtx *policy.ResponseHeaderContext, params map[string]interface{}) policy.ResponseHeaderAction {
	if respCtx.ResponseStatus >= 500 || respCtx.ResponseStatus == 429 {
		selectedModel := ""
		if model, ok := respCtx.Metadata[MetadataKeySelectedModel]; ok {
			if modelStr, ok := model.(string); ok {
				selectedModel = modelStr
			}
		}
		if p.params.SuspendDuration > 0 && selectedModel != "" {
			p.mu.Lock()
			p.suspendedModels[selectedModel] = time.Now().Add(time.Duration(p.params.SuspendDuration) * time.Second)
			p.mu.Unlock()
			slog.Debug("ModelWeightedRoundRobin: OnResponseHeaders suspended model", "model", selectedModel, "duration", p.params.SuspendDuration)
		}
	}
	return policy.DownstreamResponseHeaderModifications{}
}

// OnRequestBody processes the request body in the v1alpha2 engine.
// Since OnRequestHeaders always runs first in the v1alpha2 engine, only the payload
// location case requires body-phase processing.
func (p *ModelWeightedRoundRobinPolicy) OnRequestBody(ctx context.Context, reqCtx *policy.RequestContext, _ map[string]interface{}) policy.RequestAction {
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

	slog.Debug("ModelWeightedRoundRobin: OnRequestBody modified payload model", "newModel", selectedModel)
	return policy.UpstreamRequestModifications{Body: updatedPayload}
}

// modifyQueryParamInPath updates a query parameter value in a raw path string.
func (p *ModelWeightedRoundRobinPolicy) modifyQueryParamInPath(rawPath, paramName, newModel string) string {
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
func (p *ModelWeightedRoundRobinPolicy) modifyPathParamInPath(rawPath, regexPattern, newModel string) string {
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
