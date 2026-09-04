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

// Package semanticmodelrouting implements a semantic similarity-based model routing
// policy for the WSO2 API Platform Gateway. It precomputes vector embeddings for
// sample utterances at initialization and routes incoming requests to the model
// whose utterances are most semantically similar (using cosine similarity).
//
// Ported from the Java Universal Gateway implementation:
// org.wso2.apim.policies.mediation.ai.semantic.model.routing.SemanticRouting
package semanticmodelrouting

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"math"
	"strconv"
	"strings"

	embeddingproviders "github.com/wso2/api-platform/sdk/ai/embeddings"
	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
	utils "github.com/wso2/api-platform/sdk/core/utils"
)

// DefaultSimilarityThreshold is the default cosine similarity threshold for routing.
// Matches SemanticRoutingConstants.DEFAULT_SIMILARITY_THRESHOLD in Java.
const DefaultSimilarityThreshold = 0.90

// SemanticRoute represents a single route configuration with its precomputed embeddings.
// Maps to SemanticRoutingConfigDTO.RouteConfig in Java.
type SemanticRoute struct {
	Model               string      // Target AI model name
	Utterances          []string    // Sample phrases for this route
	ScoreThreshold      float64     // Minimum cosine similarity to match (0.0 - 1.0)
	UtteranceEmbeddings [][]float32 // Precomputed embeddings (populated at init)
}

// RequestModelConfig holds the configuration for where the model name lives in the request.
type RequestModelConfig struct {
	Location   string // "payload", "header", "queryParam", "pathParam"
	Identifier string // JSONPath (for payload) or header/param name
}

// SemanticModelRoutingPolicy implements semantic similarity-based model routing.
type SemanticModelRoutingPolicy struct {
	routes            []SemanticRoute
	defaultModel      string
	contentPath       string
	requestModel      RequestModelConfig
	embeddingProvider embeddingproviders.EmbeddingProvider
}

// GetPolicy is the v1alpha2 factory entry point. It parses configuration,
// initializes the embedding provider, precomputes utterance embeddings, and
// returns an initialized policy instance.
//
// This replaces the Java init(SynapseEnvironment) + loadRoutingConfiguration() flow.
// The key design: embeddings are precomputed HERE at init, NOT at request time.
func GetPolicy(
	metadata policy.PolicyMetadata,
	params map[string]interface{},
) (policy.Policy, error) {
	p := &SemanticModelRoutingPolicy{}

	// Parse and validate parameters
	if err := parseParams(params, p); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}

	// Initialize embedding provider (reuse SDK, same as semantic-cache)
	embeddingConfig, err := parseEmbeddingConfig(params)
	if err != nil {
		return nil, fmt.Errorf("invalid embedding config: %w", err)
	}

	embeddingProvider, err := createEmbeddingProvider(embeddingConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create embedding provider: %w", err)
	}
	p.embeddingProvider = embeddingProvider

	// Precompute embeddings for all routes' utterances
	// This matches the Java precomputeEmbeddings() behavior in init()
	if err := p.precomputeAllEmbeddings(); err != nil {
		return nil, fmt.Errorf("failed to precompute embeddings: %w", err)
	}

	slog.Debug("SemanticModelRouting: Policy initialized",
		"routes", len(p.routes),
		"defaultModel", p.defaultModel,
	)

	return p, nil
}

// Mode returns the processing mode for this policy.
// We need to buffer the request body to:
// 1. Extract user text via JSONPath for embedding
// 2. Modify the body to set the selected model name
func (p *SemanticModelRoutingPolicy) Mode() policy.ProcessingMode {
	return policy.ProcessingMode{
		RequestHeaderMode:  policy.HeaderModeSkip,
		RequestBodyMode:    policy.BodyModeBuffer,
		ResponseHeaderMode: policy.HeaderModeSkip,
		ResponseBodyMode:   policy.BodyModeSkip,
	}
}

// OnRequestBody processes the incoming request body, computes its embedding,
// finds the best semantic match among routes, and modifies the body to route
// to the appropriate model.
//
// This is the Go equivalent of SemanticRouting.mediate(MessageContext) in Java.
// Flow:
// 1. Extract user text from body using contentPath JSONPath
// 2. Generate embedding for the user text
// 3. Compare against all routes' precomputed utterance embeddings
// 4. Select best match if score >= threshold, else use default
// 5. Modify request body to set the selected model
func (p *SemanticModelRoutingPolicy) OnRequestBody(
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
		slog.Debug("SemanticModelRouting: Request body is empty, using default model")
		return p.modifyRequestModel(content, p.defaultModel)
	}

	// Extract user text from body using JSONPath
	userText := ""
	if p.contentPath != "" {
		extracted, err := utils.ExtractStringValueFromJsonpath(content, p.contentPath)
		if err != nil {
			slog.Debug("SemanticModelRouting: JSONPath extraction failed, using default model",
				"contentPath", p.contentPath, "error", err)
			return p.modifyRequestModel(content, p.defaultModel)
		}
		userText = extracted
	} else {
		userText = string(content)
	}

	if strings.TrimSpace(userText) == "" {
		slog.Debug("SemanticModelRouting: Extracted text is empty, using default model")
		return p.modifyRequestModel(content, p.defaultModel)
	}

	// Generate embedding for the user request
	requestEmbedding, err := p.embeddingProvider.GetEmbedding(userText)
	if err != nil {
		slog.Debug("SemanticModelRouting: Failed to compute request embedding, using default model",
			"error", err)
		return p.modifyRequestModel(content, p.defaultModel)
	}

	if requestEmbedding == nil {
		slog.Debug("SemanticModelRouting: Request embedding is nil, using default model")
		return p.modifyRequestModel(content, p.defaultModel)
	}

	// Find best matching route
	bestRoute, bestScore := p.findBestRoute(requestEmbedding)

	if bestRoute != nil && bestScore >= bestRoute.ScoreThreshold {
		slog.Debug("SemanticModelRouting: Route matched",
			"model", bestRoute.Model,
			"score", fmt.Sprintf("%.4f", bestScore),
			"threshold", bestRoute.ScoreThreshold,
		)
		return p.modifyRequestModel(content, bestRoute.Model)
	}

	slog.Debug("SemanticModelRouting: No route matched threshold, using default model",
		"bestScore", fmt.Sprintf("%.4f", bestScore))
	return p.modifyRequestModel(content, p.defaultModel)
}

// findBestRoute iterates all routes and finds the one with the highest cosine
// similarity score. Exact port of Java's findBestRoute().
func (p *SemanticModelRoutingPolicy) findBestRoute(requestEmbedding []float32) (*SemanticRoute, float64) {
	var bestRoute *SemanticRoute
	bestScore := 0.0

	for i := range p.routes {
		route := &p.routes[i]

		if len(route.UtteranceEmbeddings) == 0 {
			slog.Debug("SemanticModelRouting: No precomputed embeddings for route, skipping",
				"model", route.Model)
			continue
		}

		// Compute max cosine similarity against all utterance embeddings
		maxSimilarity := computeMaxCosineSimilarity(requestEmbedding, route.UtteranceEmbeddings)

		slog.Debug("SemanticModelRouting: Route similarity",
			"model", route.Model,
			"score", fmt.Sprintf("%.4f", maxSimilarity),
			"threshold", route.ScoreThreshold,
		)

		if maxSimilarity > bestScore {
			bestScore = maxSimilarity
			bestRoute = route
		}
	}

	return bestRoute, bestScore
}

// computeMaxCosineSimilarity computes the maximum cosine similarity between a
// request embedding and a set of utterance embeddings.
// Exact port of Java's computeMaxCosineSimilarity().
func computeMaxCosineSimilarity(requestEmbedding []float32, utteranceEmbeddings [][]float32) float64 {
	maxSimilarity := 0.0
	for _, utteranceEmbedding := range utteranceEmbeddings {
		similarity := CalculateCosineSimilarity(requestEmbedding, utteranceEmbedding)
		if similarity > maxSimilarity {
			maxSimilarity = similarity
		}
	}
	return maxSimilarity
}

// CalculateCosineSimilarity computes the cosine similarity between two embedding
// vectors. Returns a value between -1.0 and 1.0, where 1.0 means identical.
//
// This is an exact port of Java's calculateCosineSimilarity(double[], double[]).
// The Go version uses float32 inputs (matching the SDK's embedding format) but
// performs all arithmetic in float64 for precision.
func CalculateCosineSimilarity(vectorA, vectorB []float32) float64 {
	if vectorA == nil || vectorB == nil || len(vectorA) != len(vectorB) {
		return 0.0
	}

	var dotProduct, normA, normB float64

	for i := range vectorA {
		a := float64(vectorA[i])
		b := float64(vectorB[i])
		dotProduct += a * b
		normA += a * a
		normB += b * b
	}

	denominator := math.Sqrt(normA) * math.Sqrt(normB)
	if denominator == 0.0 {
		return 0.0
	}
	return dotProduct / denominator
}

// modifyRequestModel modifies the request body to set the selected model name.
// Follows the same pattern as model-round-robin and model-weighted-round-robin.
func (p *SemanticModelRoutingPolicy) modifyRequestModel(content []byte, selectedModel string) policy.RequestAction {
	if p.requestModel.Location != "payload" || len(content) == 0 {
		slog.Debug("SemanticModelRouting: Selected model", "model", selectedModel)
		return policy.UpstreamRequestModifications{}
	}

	var payloadData map[string]interface{}
	if err := json.Unmarshal(content, &payloadData); err != nil {
		slog.Debug("SemanticModelRouting: Failed to parse request body JSON", "error", err)
		return policy.UpstreamRequestModifications{}
	}

	if err := utils.SetValueAtJSONPath(payloadData, p.requestModel.Identifier, selectedModel); err != nil {
		slog.Debug("SemanticModelRouting: Failed to set model in request body",
			"identifier", p.requestModel.Identifier, "error", err)
		return policy.UpstreamRequestModifications{}
	}

	updatedPayload, err := json.Marshal(payloadData)
	if err != nil {
		slog.Debug("SemanticModelRouting: Failed to serialize updated body", "error", err)
		return policy.UpstreamRequestModifications{}
	}

	slog.Debug("SemanticModelRouting: Modified request body model",
		"model", selectedModel, "identifier", p.requestModel.Identifier)
	return policy.UpstreamRequestModifications{Body: updatedPayload}
}

// precomputeAllEmbeddings precomputes embeddings for all routes' utterances.
// This matches the Java precomputeEmbeddings() behavior called during init().
func (p *SemanticModelRoutingPolicy) precomputeAllEmbeddings() error {
	for i := range p.routes {
		route := &p.routes[i]
		if len(route.Utterances) == 0 {
			continue
		}

		embeddings := make([][]float32, 0, len(route.Utterances))
		for _, utterance := range route.Utterances {
			embedding, err := p.embeddingProvider.GetEmbedding(utterance)
			if err != nil {
				return fmt.Errorf("failed to compute embedding for utterance %q in route %q: %w",
					utterance, route.Model, err)
			}
			embeddings = append(embeddings, embedding)
		}
		route.UtteranceEmbeddings = embeddings

		slog.Debug("SemanticModelRouting: Precomputed embeddings for route",
			"model", route.Model, "count", len(embeddings))
	}

	return nil
}

// --- Embedding Provider ---

// createEmbeddingProvider creates and initializes an embedding provider based on
// the config. This reuses the same SDK code as the semantic-cache policy.
func createEmbeddingProvider(config embeddingproviders.EmbeddingProviderConfig) (embeddingproviders.EmbeddingProvider, error) {
	var provider embeddingproviders.EmbeddingProvider

	switch config.EmbeddingProvider {
	case "OPENAI":
		provider = &embeddingproviders.OpenAIEmbeddingProvider{}
	case "MISTRAL":
		provider = &embeddingproviders.MistralEmbeddingProvider{}
	case "AZURE_OPENAI":
		provider = &embeddingproviders.AzureOpenAIEmbeddingProvider{}
	default:
		return nil, fmt.Errorf("unsupported embedding provider: %s", config.EmbeddingProvider)
	}

	if err := provider.Init(config); err != nil {
		return nil, fmt.Errorf("failed to initialize embedding provider: %w", err)
	}

	return provider, nil
}

// --- Parameter Parsing ---

// parseParams parses and validates all policy parameters from the params map.
func parseParams(params map[string]interface{}, p *SemanticModelRoutingPolicy) error {
	// Parse contentPath (optional)
	if contentPath, ok := params["contentPath"].(string); ok && contentPath != "" {
		p.contentPath = contentPath
	}

	// Parse routes (required)
	routesRaw, ok := params["routes"]
	if !ok {
		return fmt.Errorf("'routes' parameter is required")
	}

	routesList, ok := routesRaw.([]interface{})
	if !ok {
		return fmt.Errorf("'routes' must be an array")
	}

	if len(routesList) == 0 {
		return fmt.Errorf("'routes' must contain at least one route")
	}

	p.routes = make([]SemanticRoute, 0, len(routesList))
	for i, item := range routesList {
		routeMap, ok := item.(map[string]interface{})
		if !ok {
			return fmt.Errorf("'routes[%d]' must be an object", i)
		}

		route, err := parseRouteConfig(routeMap, i)
		if err != nil {
			return err
		}
		p.routes = append(p.routes, route)
	}

	// Parse defaultModel (required)
	defaultModel, ok := params["defaultModel"].(string)
	if !ok || defaultModel == "" {
		return fmt.Errorf("'defaultModel' parameter is required")
	}
	p.defaultModel = defaultModel

	// Parse requestModel config (system parameter)
	if err := parseRequestModelConfig(params, p); err != nil {
		return err
	}

	return nil
}

// parseRouteConfig parses a single route configuration from the params map.
func parseRouteConfig(routeMap map[string]interface{}, index int) (SemanticRoute, error) {
	var route SemanticRoute

	// Parse model (required)
	model, ok := routeMap["model"].(string)
	if !ok || model == "" {
		return route, fmt.Errorf("'routes[%d].model' is required and must be a non-empty string", index)
	}
	route.Model = model

	// Parse utterances (required)
	utterancesRaw, ok := routeMap["utterances"]
	if !ok {
		return route, fmt.Errorf("'routes[%d].utterances' is required", index)
	}

	utterancesList, ok := utterancesRaw.([]interface{})
	if !ok {
		return route, fmt.Errorf("'routes[%d].utterances' must be an array", index)
	}

	if len(utterancesList) == 0 {
		return route, fmt.Errorf("'routes[%d].utterances' must contain at least one utterance", index)
	}

	route.Utterances = make([]string, 0, len(utterancesList))
	for j, u := range utterancesList {
		utterance, ok := u.(string)
		if !ok || utterance == "" {
			return route, fmt.Errorf("'routes[%d].utterances[%d]' must be a non-empty string", index, j)
		}
		route.Utterances = append(route.Utterances, utterance)
	}

	// Parse scorethreshold (optional, defaults to DefaultSimilarityThreshold)
	// Matches Java's initializeRouteConfig() threshold parsing
	route.ScoreThreshold = DefaultSimilarityThreshold
	if thresholdRaw, ok := routeMap["scorethreshold"]; ok {
		threshold, err := extractFloat64(thresholdRaw)
		if err != nil {
			slog.Debug("SemanticModelRouting: Invalid score threshold, using default",
				"value", thresholdRaw, "default", DefaultSimilarityThreshold)
		} else if threshold >= 0.0 && threshold <= 1.0 {
			route.ScoreThreshold = threshold
		} else {
			slog.Debug("SemanticModelRouting: Score threshold out of range, using default",
				"value", threshold, "default", DefaultSimilarityThreshold)
		}
	}

	return route, nil
}

// parseEmbeddingConfig parses embedding provider configuration from params.
// Follows the same pattern as the semantic-cache policy.
func parseEmbeddingConfig(params map[string]interface{}) (embeddingproviders.EmbeddingProviderConfig, error) {
	config := embeddingproviders.EmbeddingProviderConfig{}

	provider, ok := params["embeddingProvider"].(string)
	if !ok || provider == "" {
		return config, fmt.Errorf("'embeddingProvider' parameter is required")
	}

	validProviders := map[string]bool{"OPENAI": true, "MISTRAL": true, "AZURE_OPENAI": true}
	if !validProviders[provider] {
		return config, fmt.Errorf("'embeddingProvider' must be one of: OPENAI, MISTRAL, AZURE_OPENAI")
	}
	config.EmbeddingProvider = provider

	endpoint, ok := params["embeddingEndpoint"].(string)
	if !ok || endpoint == "" {
		return config, fmt.Errorf("'embeddingEndpoint' is required for %s provider", provider)
	}
	config.EmbeddingEndpoint = endpoint

	// Model is required for OPENAI and MISTRAL, optional for AZURE_OPENAI
	if model, ok := params["embeddingModel"].(string); ok && model != "" {
		config.EmbeddingModel = model
	} else if provider == "OPENAI" || provider == "MISTRAL" {
		return config, fmt.Errorf("'embeddingModel' is required for %s provider", provider)
	}

	apiKey, ok := params["apiKey"].(string)
	if !ok || apiKey == "" {
		return config, fmt.Errorf("'apiKey' is required for %s provider", provider)
	}
	config.APIKey = apiKey

	// Set auth header name based on provider type
	if provider == "AZURE_OPENAI" {
		config.AuthHeaderName = "api-key"
	} else {
		config.AuthHeaderName = "Authorization"
	}

	return config, nil
}

// parseRequestModelConfig parses the requestModel configuration from params.
func parseRequestModelConfig(params map[string]interface{}, p *SemanticModelRoutingPolicy) error {
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

	// Only the payload location is implemented; see modifyRequestModel.
	validLocations := map[string]bool{
		"payload": true,
	}
	if !validLocations[location] {
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

// --- Utility Functions ---

// extractFloat64 safely extracts a float64 from various types.
// Matches the pattern from the semantic-cache policy.
func extractFloat64(value interface{}) (float64, error) {
	switch v := value.(type) {
	case float64:
		return v, nil
	case float32:
		return float64(v), nil
	case int:
		return float64(v), nil
	case int64:
		return float64(v), nil
	case string:
		parsed, err := strconv.ParseFloat(v, 64)
		if err != nil {
			return 0, fmt.Errorf("cannot convert %q to float64: %w", v, err)
		}
		return parsed, nil
	default:
		return 0, fmt.Errorf("cannot convert %T to float64", value)
	}
}
