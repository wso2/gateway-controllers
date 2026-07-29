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
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"log/slog"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
	utils "github.com/wso2/api-platform/sdk/core/utils"
)

const (
	// Metadata keys for context storage
	MetadataKeySelectedModel      = "model_roundrobin.selected_model"
	MetadataKeyOriginalModel      = "model_roundrobin.original_model"
	MetadataKeyHeadersProcessed   = "model_roundrobin.headers_processed"
	MetadataKeyGeneratedSessionID = "model_roundrobin.generated_session_id"
	DefaultSuspendDuration        = 30
	GatewayStickyPrefix           = "_M"

	// GatewayIDRandomHexLen is the number of hex characters in the random portion of a
	// gateway-generated session ID. Kept in sync with generateGatewaySessionID.
	GatewayIDRandomHexLen = 16
)

// ModelRoundRobinPolicyParams holds the parsed policy parameters
type ModelRoundRobinPolicyParams struct {
	Models          []ModelConfig
	SuspendDuration int
	RequestModel    RequestModelConfig
	StickyKey       *StickyKeyConfig
}

// ModelConfig represents a single model configuration
type ModelConfig struct {
	Model string
}

// RequestModelConfig holds the requestModel configuration
type RequestModelConfig struct {
	Location   string
	Identifier string
}

// StickyKeyConfig holds the session stickiness configuration
type StickyKeyConfig struct {
	Location       string
	Identifier     string
	FallbackToAuth bool
	FallbackToIP   bool
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

	// Parse stickyKey if provided (optional)
	if stickyKeyRaw, ok := params["stickyKey"]; ok {
		stickyKeyMap, ok := stickyKeyRaw.(map[string]interface{})
		if !ok {
			return result, fmt.Errorf("'stickyKey' must be an object")
		}

		var stickyKeyConfig StickyKeyConfig

		// Parse location (required)
		location, ok := stickyKeyMap["location"]
		if !ok {
			return result, fmt.Errorf("'stickyKey.location' is required")
		}

		locationStr, ok := location.(string)
		if !ok {
			return result, fmt.Errorf("'stickyKey.location' must be a string")
		}

		validStickyLocations := map[string]bool{
			"header":     true,
			"queryParam": true,
			"payload":    true,
			"ip":         true,
		}
		if !validStickyLocations[locationStr] {
			return result, fmt.Errorf("'stickyKey.location' must be one of: header, queryParam, payload, ip")
		}
		stickyKeyConfig.Location = locationStr

		// Parse identifier (required if location is not ip)
		if locationStr != "ip" {
			identifier, ok := stickyKeyMap["identifier"]
			if !ok {
				return result, fmt.Errorf("'stickyKey.identifier' is required when location is '%s'", locationStr)
			}

			identifierStr, ok := identifier.(string)
			if !ok {
				return result, fmt.Errorf("'stickyKey.identifier' must be a string")
			}

			if len(identifierStr) == 0 {
				return result, fmt.Errorf("'stickyKey.identifier' must have a minimum length of 1")
			}
			stickyKeyConfig.Identifier = identifierStr
		}

		// Parse fallbackToAuth (optional, defaults to false)
		if fallbackToAuth, ok := stickyKeyMap["fallbackToAuth"]; ok {
			if val, ok := fallbackToAuth.(bool); ok {
				stickyKeyConfig.FallbackToAuth = val
			}
		}

		// Parse fallbackToIP (optional, defaults to false)
		if fallbackToIP, ok := stickyKeyMap["fallbackToIP"]; ok {
			if val, ok := fallbackToIP.(bool); ok {
				stickyKeyConfig.FallbackToIP = val
			}
		}

		result.StickyKey = &stickyKeyConfig
	}

	// A payload sticky key defers model selection to the request body phase, but that
	// phase only runs when the model itself is written into the payload. Combining a
	// payload sticky key with any other requestModel location would leave the request
	// completely unrouted, so reject it at configuration time rather than failing
	// silently at runtime.
	if result.StickyKey != nil && result.StickyKey.Location == "payload" &&
		result.RequestModel.Location != "payload" {
		return result, fmt.Errorf(
			"'stickyKey.location' of 'payload' requires 'requestModel.location' to be 'payload', got '%s'",
			result.RequestModel.Location)
	}

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
	p.mu.Lock()
	defer p.mu.Unlock()

	now := time.Now()
	attemptCount := 0
	totalModels := len(models)

	for attemptCount < totalModels {
		// Get current model (copy to avoid returning pointer to slice element)
		selectedModel := models[p.currentIndex]
		modelName := selectedModel.Model

		// Move to next index for next call
		p.currentIndex = (p.currentIndex + 1) % totalModels

		// Check if model is suspended
		if suspendedUntil, ok := p.suspendedModels[modelName]; ok {
			if now.Before(suspendedUntil) {
				// This model is still suspended, try next
				attemptCount++
				continue
			}
			// Suspension period has expired, remove from suspended list
			delete(p.suspendedModels, modelName)
		}

		return &selectedModel
	}

	return nil
}

// getSessionKey extracts the sticky key from header, query param, payload, or client IP.
// Fallbacks to Authorization header and client IP are only applied if explicitly enabled.
func (p *ModelRoundRobinPolicy) getSessionKey(headers *policy.Headers, path string, body []byte) string {
	if p.params.StickyKey == nil {
		return ""
	}

	loc := p.params.StickyKey.Location
	ident := p.params.StickyKey.Identifier

	var val string
	switch loc {
	case "header":
		if headers != nil {
			vals := headers.Get(ident)
			if len(vals) > 0 {
				val = vals[0]
			}
		}
	case "queryParam":
		decodedPath, err := url.PathUnescape(path)
		if err == nil {
			parts := strings.Split(decodedPath, "?")
			if len(parts) == 2 {
				values, err := url.ParseQuery(parts[1])
				if err == nil && len(values[ident]) > 0 {
					val = values[ident][0]
				}
			}
		}
	case "payload":
		if len(body) > 0 {
			if strVal, err := utils.ExtractStringValueFromJsonpath(body, ident); err == nil {
				val = strVal
			}
		}
	case "ip":
		if headers != nil {
			if xff := headers.Get("x-forwarded-for"); len(xff) > 0 && xff[0] != "" {
				ips := strings.Split(xff[0], ",")
				if len(ips) > 0 {
					val = strings.TrimSpace(ips[0])
				}
			}
			if val == "" {
				if xri := headers.Get("x-real-ip"); len(xri) > 0 && xri[0] != "" {
					val = xri[0]
				}
			}
		}
	}

	// Fallback Tier 1: Authorization header (only if enabled)
	if val == "" && p.params.StickyKey.FallbackToAuth && headers != nil {
		if auth := headers.Get("authorization"); len(auth) > 0 && auth[0] != "" {
			val = auth[0]
		}
	}

	// Fallback Tier 2: Client IP (only if enabled)
	if val == "" && p.params.StickyKey.FallbackToIP && headers != nil {
		if xff := headers.Get("x-forwarded-for"); len(xff) > 0 && xff[0] != "" {
			ips := strings.Split(xff[0], ",")
			if len(ips) > 0 {
				val = strings.TrimSpace(ips[0])
			}
		}
		if val == "" {
			if xri := headers.Get("x-real-ip"); len(xri) > 0 && xri[0] != "" {
				val = xri[0]
			}
		}
	}

	return val
}

// selectStickyModel selects a model stickily using stateless consistent hashing.
// If the selected model is suspended, it performs re-hashing with incremented attempts.
func (p *ModelRoundRobinPolicy) selectStickyModel(sessionKey string, models []ModelConfig) *ModelConfig {
	p.mu.Lock()
	defer p.mu.Unlock()

	now := time.Now()
	totalModels := len(models)

	attempt := 0
	for attempt < totalModels {
		hasher := fnv.New32a()
		hasher.Write([]byte(fmt.Sprintf("%s_%d", sessionKey, attempt)))
		hashVal := hasher.Sum32()

		index := int(hashVal % uint32(totalModels))
		selectedModel := models[index]
		modelName := selectedModel.Model

		// Check if model is suspended
		if suspendedUntil, ok := p.suspendedModels[modelName]; ok {
			if now.Before(suspendedUntil) {
				attempt++
				continue
			}
			delete(p.suspendedModels, modelName)
		}

		return &selectedModel
	}

	return nil
}

// isGatewayGeneratedID checks if a session ID was generated by the gateway
// and extracts the model index. Returns (index, true) if gateway-generated.
//
// The full generated format is enforced: exactly GatewayIDRandomHexLen hex characters,
// followed by GatewayStickyPrefix, followed by a non-negative integer. Matching loosely
// would let an ordinary user-supplied session key such as "alice_M1" be mistaken for a
// gateway ID and routed by index instead of by consistent hashing.
func isGatewayGeneratedID(sessionID string) (int, bool) {
	idx := strings.LastIndex(sessionID, GatewayStickyPrefix)
	if idx != GatewayIDRandomHexLen {
		return 0, false
	}
	if _, err := hex.DecodeString(sessionID[:idx]); err != nil {
		return 0, false
	}
	suffix := sessionID[idx+len(GatewayStickyPrefix):]
	modelIndex, err := strconv.Atoi(suffix)
	if err != nil || modelIndex < 0 {
		return 0, false
	}
	return modelIndex, true
}

// generateGatewaySessionID creates a new session ID with the model index encoded.
// Format: <random-hex>_M<index> (e.g., "a1b2c3d4e5f67890_M1")
func generateGatewaySessionID(modelIndex int) string {
	b := make([]byte, GatewayIDRandomHexLen/2)
	rand.Read(b)
	return hex.EncodeToString(b) + GatewayStickyPrefix + strconv.Itoa(modelIndex)
}

// selectModelByIndex selects a model by its index, skipping suspended models.
// If the model at the given index is suspended, it tries the next model in order.
func (p *ModelRoundRobinPolicy) selectModelByIndex(modelIndex int, models []ModelConfig) *ModelConfig {
	p.mu.Lock()
	defer p.mu.Unlock()

	now := time.Now()
	totalModels := len(models)

	if modelIndex < 0 || modelIndex >= totalModels {
		return nil
	}

	for attempt := 0; attempt < totalModels; attempt++ {
		idx := (modelIndex + attempt) % totalModels
		selectedModel := models[idx]
		modelName := selectedModel.Model

		if suspendedUntil, ok := p.suspendedModels[modelName]; ok {
			if now.Before(suspendedUntil) {
				continue
			}
			delete(p.suspendedModels, modelName)
		}

		return &selectedModel
	}

	return nil
}

// getModelIndex returns the index of a model in the models list.
func (p *ModelRoundRobinPolicy) getModelIndex(modelName string) int {
	for i, m := range p.params.Models {
		if m.Model == modelName {
			return i
		}
	}
	return 0
}

// OnRequestHeaders selects the next model and applies the modification for header/queryParam/pathParam
// locations in the request header phase. For payload location, the model is pre-selected and
// stored in metadata for OnRequest to apply to the body.
func (p *ModelRoundRobinPolicy) OnRequestHeaders(ctx context.Context, reqCtx *policy.RequestHeaderContext, params map[string]interface{}) policy.RequestHeaderAction {
	location := p.params.RequestModel.Location
	identifier := p.params.RequestModel.Identifier

	// Defer selection to body phase if session stickiness key is located in the payload
	if p.params.StickyKey != nil && p.params.StickyKey.Location == "payload" {
		reqCtx.Metadata[MetadataKeyHeadersProcessed] = true
		return policy.UpstreamRequestHeaderModifications{}
	}

	var selectedModel *ModelConfig
	if p.params.StickyKey != nil {
		sessionKey := p.getSessionKey(reqCtx.Headers, reqCtx.Path, nil)
		if sessionKey != "" {
			// Check if this is a gateway-generated session ID
			if modelIndex, ok := isGatewayGeneratedID(sessionKey); ok {
				selectedModel = p.selectModelByIndex(modelIndex, p.params.Models)
			} else {
				// User-provided session ID: use consistent hashing
				selectedModel = p.selectStickyModel(sessionKey, p.params.Models)
			}
		}
	}

	// Fallback to standard round-robin and generate a gateway session ID
	if selectedModel == nil {
		selectedModel = p.selectNextAvailableModel(p.params.Models)
		// If stickyKey is configured and we fell back to round-robin,
		// generate a gateway session ID for the client
		if selectedModel != nil && p.params.StickyKey != nil {
			modelIndex := p.getModelIndex(selectedModel.Model)
			generatedID := generateGatewaySessionID(modelIndex)
			reqCtx.Metadata[MetadataKeyGeneratedSessionID] = generatedID
			slog.Debug("ModelRoundRobin: generated gateway session ID", "sessionID", generatedID, "model", selectedModel.Model)
		}
	}

	if selectedModel == nil {
		return policy.ImmediateResponse{
			StatusCode: 503,
			Headers:    map[string]string{"Content-Type": "application/json"},
			Body:       []byte(`{"error": "All models are currently unavailable"}`),
		}
	}

	reqCtx.Metadata[MetadataKeySelectedModel] = selectedModel.Model
	reqCtx.Metadata[MetadataKeyHeadersProcessed] = true
	slog.Debug("ModelRoundRobin: OnRequestHeaders selected model", "model", selectedModel.Model)

	switch location {
	case "header":
		if reqCtx.Headers != nil {
			values := reqCtx.Headers.Get(identifier)
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
		return policy.UpstreamRequestHeaderModifications{}
	}
	return policy.UpstreamRequestHeaderModifications{}
}

// OnResponseHeaders suspends a model in the response header phase when an error is detected.
// It also returns the gateway-generated session ID to the client in a response header.
func (p *ModelRoundRobinPolicy) OnResponseHeaders(ctx context.Context, respCtx *policy.ResponseHeaderContext, params map[string]interface{}) policy.ResponseHeaderAction {
	responseHeaders := map[string]string{}

	// Return generated session ID to client
	if generatedID, ok := respCtx.Metadata[MetadataKeyGeneratedSessionID]; ok {
		if idStr, ok := generatedID.(string); ok && idStr != "" {
			headerName := "X-Gateway-Session-ID"
			if p.params.StickyKey != nil && p.params.StickyKey.Location == "header" {
				headerName = p.params.StickyKey.Identifier
			}
			responseHeaders[headerName] = idStr
			slog.Debug("ModelRoundRobin: returning generated session ID", "header", headerName, "sessionID", idStr)
		}
	}

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
			slog.Debug("ModelRoundRobin: OnResponseHeaders suspended model", "model", selectedModel, "duration", p.params.SuspendDuration)
		}
	}

	if len(responseHeaders) > 0 {
		return policy.DownstreamResponseHeaderModifications{
			HeadersToSet: responseHeaders,
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

	if reqCtx.Body == nil || reqCtx.Body.Content == nil {
		return policy.ImmediateResponse{
			StatusCode: 400,
			Headers:    map[string]string{"Content-Type": "application/json"},
			Body:       []byte(`{"error":"Request body is empty."}`),
		}
	}

	selectedModel, _ := reqCtx.Metadata[MetadataKeySelectedModel].(string)
	if selectedModel == "" {
		var selectedModelConfig *ModelConfig
		if p.params.StickyKey != nil {
			sessionKey := p.getSessionKey(reqCtx.Headers, reqCtx.Path, reqCtx.Body.Content)
			if sessionKey != "" {
				// Check if this is a gateway-generated session ID
				if modelIndex, ok := isGatewayGeneratedID(sessionKey); ok {
					selectedModelConfig = p.selectModelByIndex(modelIndex, p.params.Models)
				} else {
					// User-provided session ID: use consistent hashing
					selectedModelConfig = p.selectStickyModel(sessionKey, p.params.Models)
				}
			}
		}
		if selectedModelConfig == nil {
			selectedModelConfig = p.selectNextAvailableModel(p.params.Models)
			// If stickyKey is configured and we fell back to round-robin,
			// generate a gateway session ID for the client
			if selectedModelConfig != nil && p.params.StickyKey != nil {
				modelIndex := p.getModelIndex(selectedModelConfig.Model)
				generatedID := generateGatewaySessionID(modelIndex)
				reqCtx.Metadata[MetadataKeyGeneratedSessionID] = generatedID
			}
		}
		if selectedModelConfig == nil {
			return policy.ImmediateResponse{
				StatusCode: 503,
				Headers:    map[string]string{"Content-Type": "application/json"},
				Body:       []byte(`{"error": "All models are currently unavailable"}`),
			}
		}
		selectedModel = selectedModelConfig.Model
		reqCtx.Metadata[MetadataKeySelectedModel] = selectedModel
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
