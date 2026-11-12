/*
 *  Copyright (c) 2025, WSO2 LLC. (http://www.wso2.org) All Rights Reserved.
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

package semanticcache

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	embeddingproviders "github.com/wso2/api-platform/sdk/ai/embeddings"
	vectordbproviders "github.com/wso2/api-platform/sdk/ai/vectordb"
	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
	utils "github.com/wso2/api-platform/sdk/core/utils"
)

const (
	sseDataPrefix            = "data: "
	sseDone                  = "[DONE]"
	sseEventPrefix           = "event:"
	DefaultStreamingJsonPath = "$.choices[0].delta.content"
)

const (
	// MetadataKeyEmbedding is the key used to store embedding in metadata between request and response phases
	MetadataKeyEmbedding = "semantic_cache_embedding"
	// MetadataKeyAPIID is the key used to store API ID in metadata
	MetadataKeyAPIID = "semantic_cache_api_id"
	// applicationIDMetadataKey is the shared inter-policy metadata key that carries the caller's application identity.
	applicationIDMetadataKey = "x-wso2-application-id"
	// cacheScopeSeparator joins apiID and the encoded caller identity into the cache partition key.
	cacheScopeSeparator = "|"
	// identitySourceSeparator joins an identity source tag and its base64-encoded
	// value. Safe unconditionally: the tag is always one of the constants below
	// (never user input) and base64.RawURLEncoding never emits ':'.
	identitySourceSeparator = ":"

	identitySourceApplicationID = "appid"
	identitySourceSubject       = "subject"
	identitySourceCredentialID  = "credential"
	identitySourceTokenID       = "token"
)

// SemanticCachePolicy implements semantic caching for LLM responses
type SemanticCachePolicy struct {
	embeddingConfig     embeddingproviders.EmbeddingProviderConfig
	vectorStoreConfig   vectordbproviders.VectorDBProviderConfig
	embeddingProvider   embeddingproviders.EmbeddingProvider
	vectorStoreProvider vectordbproviders.VectorDBProvider
	jsonPath            string
	streamingJsonPath   string
	threshold           float64
	// cacheUnauthenticated allows caching for callers with no resolvable identity
	cacheUnauthenticated bool
	jevCacheCheck        jevCacheCheckConfig
	jevClient            *jevClient
}

// callerIdentity resolves the caller principal from metadata, falling back to
// auth context. The returned source tags which field the value came from, so
// equal values from different sources (e.g. an application ID that happens to
// match another caller's JWT subject) can be told apart by cacheScopeID.
func callerIdentity(sc *policy.SharedContext) (source string, value string, ok bool) {
	if sc == nil {
		return "", "", false
	}
	if sc.Metadata != nil {
		if v, ok := sc.Metadata[applicationIDMetadataKey]; ok {
			if s, ok := v.(string); ok && s != "" {
				return identitySourceApplicationID, s, true
			}
		}
	}
	if sc.AuthContext != nil {
		if sc.AuthContext.Subject != "" {
			return identitySourceSubject, sc.AuthContext.Subject, true
		}
		if sc.AuthContext.CredentialID != "" {
			return identitySourceCredentialID, sc.AuthContext.CredentialID, true
		}
		// api-key-auth sets neither Subject nor CredentialID for a key with no
		// linked application (e.g. an LLM provider API key) - TokenId (a hash of
		// the raw credential) is the last remaining per-caller signal in that case.
		if sc.AuthContext.TokenId != "" {
			return identitySourceTokenID, sc.AuthContext.TokenId, true
		}
	}
	return "", "", false
}

// cacheScopeID folds the caller identity into the api_id partition key used by
// Retrieve/Store. The identity value is base64-encoded and tagged with its
// source so two different sources can never collide on an equal raw value
// (e.g. an application ID "victim" vs. a JWT subject "victim" get distinct
// partitions, and a value crafted to contain a separator/tag can't be
// mistaken for a different source).
func (p *SemanticCachePolicy) cacheScopeID(sc *policy.SharedContext, apiID string) (string, bool) {
	if source, value, ok := callerIdentity(sc); ok {
		encoded := source + identitySourceSeparator + base64.RawURLEncoding.EncodeToString([]byte(value))
		return apiID + cacheScopeSeparator + encoded, true
	}
	if p.cacheUnauthenticated {
		return apiID, true
	}
	return "", false
}

// isNoStoreResponse reports whether Cache-Control marks the response as non-shareable.
func isNoStoreResponse(headers *policy.Headers) bool {
	if headers == nil {
		return false
	}
	for _, v := range headers.Get("cache-control") {
		lower := strings.ToLower(v)
		if strings.Contains(lower, "no-store") || strings.Contains(lower, "private") || strings.Contains(lower, "no-cache") {
			return true
		}
	}
	return false
}

// GetPolicy is the v1alpha2 factory entry point (loaded by v1alpha2 kernels).
func GetPolicy(
	metadata policy.PolicyMetadata,
	params map[string]interface{},
) (policy.Policy, error) {
	p := &SemanticCachePolicy{}

	// Parse and validate parameters
	if err := parseParams(params, p); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}
	if p.jevCacheCheck.Enabled {
		p.jevClient = newJevClient(p.jevCacheCheck)
	}

	// Initialize embedding provider
	embeddingProvider, err := createEmbeddingProvider(p.embeddingConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create embedding provider: %w", err)
	}
	p.embeddingProvider = embeddingProvider

	// Initialize vector store provider
	vectorStoreProvider, err := createVectorDBProvider(p.vectorStoreConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create vector store provider: %w", err)
	}
	p.vectorStoreProvider = vectorStoreProvider

	// Create index during initialization
	if err := p.vectorStoreProvider.CreateIndex(); err != nil {
		return nil, fmt.Errorf("failed to create vector store index: %w", err)
	}

	slog.Debug("SemanticCache: Policy initialized", "embeddingProvider", embeddingProvider, "vectorStoreProvider", vectorStoreProvider, "similarityThreshold", p.threshold)

	return p, nil
}

// Mode returns the processing mode for the semantic cache policy.
func (p *SemanticCachePolicy) Mode() policy.ProcessingMode {
	return policy.ProcessingMode{
		RequestHeaderMode:  policy.HeaderModeSkip,
		RequestBodyMode:    policy.BodyModeBuffer,
		ResponseHeaderMode: policy.HeaderModeSkip,
		ResponseBodyMode:   policy.BodyModeBuffer,
	}
}

// parseParams parses and validates parameters from the params map
func parseParams(params map[string]interface{}, p *SemanticCachePolicy) error {
	// Required parameters
	embeddingProvider, ok := params["embeddingProvider"].(string)
	if !ok || embeddingProvider == "" {
		return fmt.Errorf("'embeddingProvider' parameter is required")
	}

	vectorStoreProvider, ok := params["vectorStoreProvider"].(string)
	if !ok || vectorStoreProvider == "" {
		return fmt.Errorf("'vectorStoreProvider' parameter is required")
	}

	thresholdRaw, ok := params["similarityThreshold"]
	if !ok {
		return fmt.Errorf("'similarityThreshold' parameter is required")
	}
	threshold, err := extractFloat64(thresholdRaw)
	if err != nil {
		return fmt.Errorf("'similarityThreshold' must be a number: %w", err)
	}
	if threshold < 0.0 || threshold > 1.0 {
		return fmt.Errorf("'similarityThreshold' must be between 0.0 and 1.0 (similarity range)")
	}

	p.threshold = threshold

	// Parse embedding provider config
	p.embeddingConfig = embeddingproviders.EmbeddingProviderConfig{
		EmbeddingProvider: embeddingProvider,
	}

	// Required for OPENAI, MISTRAL, AZURE_OPENAI
	if endpoint, ok := params["embeddingEndpoint"].(string); ok && endpoint != "" {
		p.embeddingConfig.EmbeddingEndpoint = endpoint
	} else {
		return fmt.Errorf("'embeddingEndpoint' is required for %s provider", embeddingProvider)
	}

	// embeddingModel is required for OPENAI and MISTRAL, but not for AZURE_OPENAI
	// For AZURE_OPENAI, deployment name is in the endpoint URL, so model can be empty
	var embeddingModel string
	if model, ok := params["embeddingModel"].(string); ok && model != "" {
		embeddingModel = model
	} else if embeddingProvider == "OPENAI" || embeddingProvider == "MISTRAL" {
		return fmt.Errorf("'embeddingModel' is required for %s provider", embeddingProvider)
	}
	// Always set EmbeddingModel explicitly (empty string is allowed for AZURE_OPENAI)
	p.embeddingConfig.EmbeddingModel = embeddingModel

	if apiKey, ok := params["apiKey"].(string); ok && apiKey != "" {
		p.embeddingConfig.APIKey = apiKey
	} else {
		return fmt.Errorf("'apiKey' is required for %s provider", embeddingProvider)
	}

	// Set header name based on provider type
	// Azure OpenAI uses "api-key", others use "Authorization"
	if embeddingProvider == "AZURE_OPENAI" {
		p.embeddingConfig.AuthHeaderName = "api-key"
	} else {
		p.embeddingConfig.AuthHeaderName = "Authorization"
	}

	// Parse vector store provider config
	// Threshold is stored as similarity threshold (0-1, higher is better)
	p.vectorStoreConfig = vectordbproviders.VectorDBProviderConfig{
		VectorStoreProvider: vectorStoreProvider,
		Threshold:           fmt.Sprintf("%.2f", p.threshold),
	}

	if dbHost, ok := params["dbHost"].(string); ok && dbHost != "" {
		p.vectorStoreConfig.DBHost = dbHost
	} else {
		return fmt.Errorf("'dbHost' is required")
	}

	if dbPortRaw, ok := params["dbPort"]; ok {
		dbPort, err := extractInt(dbPortRaw)
		if err != nil {
			return fmt.Errorf("'dbPort' must be a number: %w", err)
		}
		p.vectorStoreConfig.DBPort = dbPort
	} else {
		return fmt.Errorf("'dbPort' is required")
	}

	if embeddingDim, ok := params["embeddingDimension"]; ok {
		dim, err := extractInt(embeddingDim)
		if err != nil {
			return fmt.Errorf("'embeddingDimension' must be a number: %w", err)
		}
		p.vectorStoreConfig.EmbeddingDimension = strconv.Itoa(dim)
	} else {
		return fmt.Errorf("'embeddingDimension' is required")
	}

	if username, ok := params["username"].(string); ok {
		p.vectorStoreConfig.Username = username
	}

	if password, ok := params["password"].(string); ok {
		p.vectorStoreConfig.Password = password
	}

	if database, ok := params["database"].(string); ok {
		p.vectorStoreConfig.DatabaseName = database
	}

	if ttlRaw, ok := params["ttl"]; ok {
		ttl, err := extractInt(ttlRaw)
		if err != nil {
			return fmt.Errorf("'ttl' must be a number: %w", err)
		}
		p.vectorStoreConfig.TTL = strconv.Itoa(ttl)
	}

	// Optional JSONPath for extracting text from request body
	if jsonPath, ok := params["jsonPath"].(string); ok {
		p.jsonPath = jsonPath
	}

	// Optional JSONPath for extracting content from SSE streaming delta events.
	// Defaults to $.choices[0].delta.content (OpenAI-compatible format).
	p.streamingJsonPath = DefaultStreamingJsonPath
	if streamingJsonPathRaw, ok := params["streamingJsonPath"]; ok {
		if streamingJsonPath, ok := streamingJsonPathRaw.(string); ok {
			p.streamingJsonPath = streamingJsonPath
		} else {
			return fmt.Errorf("'streamingJsonPath' must be a string")
		}
	}

	// Optional: opt in to caching for callers with no resolvable identity
	if cacheUnauthenticatedRaw, ok := params["cacheUnauthenticated"]; ok {
		cacheUnauthenticated, ok := cacheUnauthenticatedRaw.(bool)
		if !ok {
			return fmt.Errorf("'cacheUnauthenticated' must be a boolean")
		}
		p.cacheUnauthenticated = cacheUnauthenticated
	}

	jevConfig, err := parseJevCacheCheck(params)
	if err != nil {
		return err
	}
	p.jevCacheCheck = jevConfig

	return nil
}

// extractFloat64 safely extracts a float64 from various types
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
	case string:
		parsed, err := strconv.Atoi(v)
		if err != nil {
			return 0, fmt.Errorf("cannot convert %q to int: %w", v, err)
		}
		return parsed, nil
	default:
		return 0, fmt.Errorf("cannot convert %T to int", value)
	}
}

// createEmbeddingProvider creates a new embedding provider based on the config
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

// createVectorDBProvider creates a new vector DB provider based on the config
func createVectorDBProvider(config vectordbproviders.VectorDBProviderConfig) (vectordbproviders.VectorDBProvider, error) {
	var provider vectordbproviders.VectorDBProvider

	switch config.VectorStoreProvider {
	case "REDIS":
		provider = &vectordbproviders.RedisVectorDBProvider{}
	case "MILVUS":
		provider = &vectordbproviders.MilvusVectorDBProvider{}
	default:
		return nil, fmt.Errorf("unsupported vector store provider: %s", config.VectorStoreProvider)
	}

	if err := provider.Init(config); err != nil {
		return nil, fmt.Errorf("failed to initialize vector store provider: %w", err)
	}

	return provider, nil
}

// extractRequestText returns the text at jsonPath, or the whole body when no
// jsonPath is configured.
func (p *SemanticCachePolicy) extractRequestText(content []byte) (string, error) {
	if p.jsonPath == "" || len(content) == 0 {
		return string(content), nil
	}
	return utils.ExtractStringValueFromJsonpath(content, p.jsonPath)
}

// OnRequestBody implements the v1alpha2 body-phase request handler.
func (p *SemanticCachePolicy) OnRequestBody(ctx context.Context, reqCtx *policy.RequestContext, params map[string]interface{}) policy.RequestAction {
	var content []byte
	if reqCtx.Body != nil {
		content = reqCtx.Body.Content
	}

	// Extract text from request body using JSONPath if specified
	textToEmbed, err := p.extractRequestText(content)
	if err != nil {
		// JSONPath extraction failed - return error response
		return p.buildErrorResponse("Error extracting value from JSONPath", err)
	}

	// If no content to embed, continue to upstream
	if len(textToEmbed) == 0 {
		return policy.UpstreamRequestModifications{}
	}

	// Generate embedding
	embedding, err := p.embeddingProvider.GetEmbedding(textToEmbed)
	if err != nil {
		slog.Debug("SemanticCache: Error generating embedding", "error", err)
		// Log error but don't block request
		return policy.UpstreamRequestModifications{}
	}

	// Store embedding in metadata for response phase
	if reqCtx.Metadata == nil {
		reqCtx.Metadata = make(map[string]interface{})
	}
	embeddingBytes, err := json.Marshal(embedding)
	if err == nil {
		reqCtx.Metadata[MetadataKeyEmbedding] = string(embeddingBytes)
	}

	// Get API ID from context (use APIName and APIVersion to create unique ID)
	apiID := fmt.Sprintf("%s:%s", reqCtx.APIName, reqCtx.APIVersion)

	// Scope the lookup to the caller so responses are never cross-served
	scopeID, cacheable := p.cacheScopeID(reqCtx.SharedContext, apiID)
	if !cacheable {
		slog.Debug("SemanticCache: No caller identity resolved and cacheUnauthenticated is disabled, skipping cache lookup", "apiID", apiID)
		return policy.UpstreamRequestModifications{}
	}

	// Cosine similarity embedders (e.g. Mistral) have a floor of ~0.6 — even completely
	// unrelated texts score that high. Map [0.6, 1.0] → [0, 1] so the user-supplied
	// threshold works across the full semantic range.
	// effectiveThreshold = 0.6 + userThreshold * 0.4
	const minSimilarityBaseline = 0.6
	effectiveThreshold := minSimilarityBaseline + p.threshold*(1.0-minSimilarityBaseline)

	// Check cache for similar response
	// Threshold needs to be a string for the vector DB provider
	cacheFilter := map[string]interface{}{
		"threshold": fmt.Sprintf("%.4f", effectiveThreshold),
		"api_id":    scopeID,
		"ctx":       context.Background(), // Vector DB providers need context
	}

	cacheResponse, err := p.vectorStoreProvider.Retrieve(embedding, cacheFilter)
	if err != nil {
		slog.Debug("SemanticCache: Cache retrieval error", "error", err, "apiID", apiID)
		// Cache miss or error - continue to upstream
		return policy.UpstreamRequestModifications{}
	}

	// Check if we got a valid cache response
	// Retrieve returns empty CacheResponse on no match or threshold not met
	if cacheResponse.ResponsePayload == nil || len(cacheResponse.ResponsePayload) == 0 {
		slog.Debug("SemanticCache: Cache miss", "apiID", apiID, "threshold", effectiveThreshold)
		// Cache miss - continue to upstream
		return policy.UpstreamRequestModifications{}
	}

	// Cache hit - return cached response immediately
	slog.Debug("SemanticCache: Cache hit", "apiID", apiID)
	responseBytes, err := json.Marshal(cacheResponse.ResponsePayload)
	if err != nil {
		return policy.UpstreamRequestModifications{}
	}

	return policy.ImmediateResponse{
		StatusCode: 200,
		Headers: map[string]string{
			"Content-Type":   "application/json",
			"X-Cache-Status": "HIT",
		},
		Body: responseBytes,
	}
}

// OnResponseBody handles response body processing for semantic caching.
func (p *SemanticCachePolicy) OnResponseBody(ctx context.Context, respCtx *policy.ResponseContext, _ map[string]interface{}) policy.ResponseAction {
	return p.processResponseBody(ctx, respCtx)
}

// processResponseBody handles response body processing for semantic caching.
func (p *SemanticCachePolicy) processResponseBody(ctx context.Context, respCtx *policy.ResponseContext) policy.ResponseAction {
	// Only cache successful responses (200 status code)
	if respCtx.ResponseStatus != 200 {
		slog.Debug("SemanticCache: Skipping cache for non-200 response", "statusCode", respCtx.ResponseStatus)
		return policy.DownstreamResponseModifications{}
	}

	var content []byte
	if respCtx.ResponseBody != nil {
		content = respCtx.ResponseBody.Content
	}

	if len(content) == 0 {
		return policy.DownstreamResponseModifications{}
	}

	// Retrieve embedding from metadata (stored in request phase)
	embeddingStr, ok := respCtx.Metadata[MetadataKeyEmbedding].(string)
	if !ok || embeddingStr == "" {
		slog.Debug("SemanticCache: No embedding found in metadata, skipping cache storage")
		return policy.DownstreamResponseModifications{}
	}

	// Deserialize embedding
	var embedding []float32
	if err := json.Unmarshal([]byte(embeddingStr), &embedding); err != nil {
		return policy.DownstreamResponseModifications{}
	}

	// Parse response body
	var responseData map[string]interface{}
	if err := json.Unmarshal(content, &responseData); err != nil {
		// If the body is not valid JSON, check if it is a buffered SSE stream
		// Detect SSE from the upstream snapshot so response assembly reflects the
		// Content-Type the upstream actually returned, not a value a peer policy
		// rewrote during the response header phase.
		if isSSEResponse(respCtx.UpstreamHeaders()) || isSSEContent(string(content)) {
			assembled, sseErr := assembleSSEResponse(string(content), p.streamingJsonPath)
			if sseErr != nil {
				slog.Info("SemanticCache: Failed to reassemble SSE response for caching", "error", sseErr)
				return policy.DownstreamResponseModifications{}
			}
			responseData = assembled
		} else {
			slog.Info("SemanticCache: Failed to parse response body, skipping cache storage", "error", err)
			return policy.DownstreamResponseModifications{}
		}
	}

	// Get API ID from context (use APIName and APIVersion to create unique ID)
	apiID := fmt.Sprintf("%s:%s", respCtx.APIName, respCtx.APIVersion)
	if apiID == ":" {
		// Fallback to route name if API info not available
		apiID = respCtx.RequestID
	}

	// Never persist a response the upstream marked non-shareable (defense in
	// depth alongside per-caller scoping below). Best-effort: if headers are
	// unavailable, the response is treated as cacheable.
	if isNoStoreResponse(respCtx.ResponseHeaders) {
		slog.Debug("SemanticCache: Response marked no-store/private/no-cache, skipping cache storage", "apiID", apiID)
		return policy.DownstreamResponseModifications{}
	}

	// Bind the stored entry to the caller so it can only ever be served back to
	// that same caller (F-181: cache poisoning / missing provenance).
	// Identity-less responses are not stored unless the operator has explicitly
	// opted in via cacheUnauthenticated.
	scopeID, cacheable := p.cacheScopeID(respCtx.SharedContext, apiID)
	if !cacheable {
		slog.Debug("SemanticCache: No caller identity resolved and cacheUnauthenticated is disabled, skipping cache storage", "apiID", apiID)
		return policy.DownstreamResponseModifications{}
	}

	if p.jevCacheCheck.Enabled {
		// Re-extract the request text from the request body the kernel carries into the
		// response phase rather than passing it through SharedContext.Metadata, which is
		// exported unmasked to analytics and would leak the prompt.
		var requestContent []byte
		if respCtx.RequestBody != nil {
			requestContent = respCtx.RequestBody.Content
		}
		requestText, err := p.extractRequestText(requestContent)
		if err != nil || strings.TrimSpace(requestText) == "" {
			p.recordJevDecision(respCtx.SharedContext, jevDecision{Decision: jevDecisionSkip, Error: "request text is unavailable"}, nil)
			return policy.DownstreamResponseModifications{}
		}
		respText, err := responseText(responseData)
		if err != nil || strings.TrimSpace(respText) == "" {
			p.recordJevDecision(respCtx.SharedContext, jevDecision{Decision: jevDecisionSkip, Error: "response text is unavailable"}, nil)
			return policy.DownstreamResponseModifications{}
		}

		decision, usage, err := p.jevClient.shouldStore(ctx, requestText, respText, p.jevCacheCheck.Questions)
		if err != nil {
			slog.Debug("SemanticCache: Jev cache check failed, skipping cache storage", "error", err, "apiID", apiID)
			p.recordJevDecision(respCtx.SharedContext, jevDecision{Decision: jevDecisionSkip, Error: err.Error()}, usage)
			return policy.DownstreamResponseModifications{}
		}
		p.recordJevDecision(respCtx.SharedContext, decision, usage)
		if decision.Decision == jevDecisionSkip {
			slog.Debug("SemanticCache: Jev cache check rejected response", "questions", decision.Fired, "apiID", apiID)
			return policy.DownstreamResponseModifications{}
		}
	}

	// RequestHash records the resolved caller identity as meaningful provenance
	// instead of a throwaway random value; falls back to a UUID only in the
	// identity-less shared-bucket case (cacheUnauthenticated=true).
	requestHash := uuid.New().String()
	if _, identity, ok := callerIdentity(respCtx.SharedContext); ok {
		requestHash = identity
	}

	// Store in cache
	cacheResponse := vectordbproviders.CacheResponse{
		ResponsePayload:     responseData,
		RequestHash:         requestHash,
		ResponseFetchedTime: time.Now(),
	}

	cacheFilter := map[string]interface{}{
		"api_id": scopeID,
		"ctx":    context.Background(), // Vector DB providers need context
	}

	if err := p.vectorStoreProvider.Store(embedding, cacheResponse, cacheFilter); err != nil {
		slog.Debug("SemanticCache: Error storing in cache", "error", err, "apiID", scopeID)
		// Log error but don't modify response
		return policy.DownstreamResponseModifications{}
	}

	slog.Debug("SemanticCache: Response cached successfully", "apiID", scopeID)
	return policy.DownstreamResponseModifications{}
}

// isSSEResponse reports whether the response Content-Type indicates an SSE stream.
func isSSEResponse(headers *policy.Headers) bool {
	if headers == nil {
		return false
	}
	for _, v := range headers.Get("content-type") {
		if v == "text/event-stream" {
			return true
		}
	}
	return false
}

// isSSEContent reports whether the body content looks like buffered SSE data.
func isSSEContent(s string) bool {
	for _, line := range strings.Split(s, "\n") {
		if strings.HasPrefix(line, sseDataPrefix) || strings.HasPrefix(line, sseEventPrefix) {
			return true
		}
	}
	return false
}

// assembleSSEResponse parses buffered SSE events and reconstructs a single
// non-streaming JSON response suitable for caching. It uses streamingJsonPath
// to extract content from each SSE event (e.g. "$.choices[0].delta.content"),
// concatenates all extracted values, and rebuilds the last event with a
// choices[*].message object containing the full content.
func assembleSSEResponse(sseBody string, streamingJsonPath string) (map[string]interface{}, error) {
	var contentParts []string
	var lastEvent map[string]interface{}

	for _, line := range strings.Split(sseBody, "\n") {
		line = strings.TrimRight(line, "\r")
		var value string
		if strings.HasPrefix(line, sseDataPrefix) {
			value = strings.TrimPrefix(line, sseDataPrefix)
		} else if strings.HasPrefix(line, sseEventPrefix) {
			value = strings.TrimSpace(strings.TrimPrefix(line, sseEventPrefix))
		} else {
			continue
		}
		value = strings.TrimSpace(value)
		if value == sseDone || value == "" {
			continue
		}

		var event map[string]interface{}
		if err := json.Unmarshal([]byte(value), &event); err != nil {
			continue // skip non-JSON lines
		}
		lastEvent = event

		// Extract content using the configurable streaming JSONPath
		if text, err := utils.ExtractStringValueFromJsonpath([]byte(value), streamingJsonPath); err == nil && text != "" {
			contentParts = append(contentParts, text)
		}
	}

	if lastEvent == nil {
		return nil, fmt.Errorf("no valid SSE events found")
	}

	// Build a non-streaming response using the last event as a template
	assembled := make(map[string]interface{})
	for k, v := range lastEvent {
		assembled[k] = v
	}
	// Replace "chat.completion.chunk" with "chat.completion" if present
	if obj, ok := assembled["object"].(string); ok && obj == "chat.completion.chunk" {
		assembled["object"] = "chat.completion"
	}

	fullContent := strings.Join(contentParts, "")

	// Rebuild choices with message instead of delta
	if choices, ok := lastEvent["choices"].([]interface{}); ok && len(choices) > 0 {
		newChoices := make([]interface{}, len(choices))
		for i, c := range choices {
			choice, ok := c.(map[string]interface{})
			if !ok {
				newChoices[i] = c
				continue
			}
			newChoice := make(map[string]interface{})
			for k, v := range choice {
				if k == "delta" {
					continue
				}
				newChoice[k] = v
			}
			newChoice["message"] = map[string]interface{}{
				"role":    "assistant",
				"content": fullContent,
			}
			newChoices[i] = newChoice
		}
		assembled["choices"] = newChoices
	}

	return assembled, nil
}

// buildErrorResponse builds a v1alpha2 error response for JSONPath extraction failures.
func (p *SemanticCachePolicy) buildErrorResponse(message string, err error) policy.RequestAction {
	errorMsg := message
	if err != nil {
		errorMsg = fmt.Sprintf("%s: %v", message, err)
	}

	responseBody := map[string]interface{}{
		"type":    "SEMANTIC_CACHE",
		"message": errorMsg,
	}

	bodyBytes, marshalErr := json.Marshal(responseBody)
	if marshalErr != nil {
		bodyBytes = []byte(`{"type":"SEMANTIC_CACHE","message":"Internal error"}`)
	}

	return policy.ImmediateResponse{
		StatusCode: 400,
		Headers: map[string]string{
			"Content-Type": "application/json",
		},
		Body: bodyBytes,
		// The body is unchanged — clients have parsed this shape since before the fault
		// contract existed. Only the description is new, so a gateway that reads it can
		// classify the rejection and run the fault policies over it.
		IsFault: true,
		Fault: &policy.FaultDetails{
			Code:      policy.FaultCodeInvalidRequestBody,
			Type:      policy.FaultTypeValidation,
			Direction: policy.DirectionRequest,
			Message:   message,
		},
	}
}
