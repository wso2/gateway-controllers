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

package semantictoolfiltering

import (
	"fmt"
	"log/slog"
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"

	embeddingproviders "github.com/wso2/api-platform/sdk/ai/embeddings"
	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

const (
	// Selection modes
	SelectionModeTopK      = "By Rank"
	SelectionModeThreshold = "By Threshold"

	// Internal timeout for embedding provider (not exposed in policy definition)
	DefaultTimeoutMs = 5000
)

// ToolWithScore represents a tool with its similarity score
type ToolWithScore struct {
	Tool  map[string]interface{}
	Score float64
}

// TextTool represents a tool parsed from text format
type TextTool struct {
	Name        string
	Description string
	StartPos    int // Start position in original text
	EndPos      int // End position in original text (after </tooldescription>)
}

// SemanticToolFilteringPolicy implements semantic filtering for tool selection
type SemanticToolFilteringPolicy struct {
	embeddingConfig   embeddingproviders.EmbeddingProviderConfig
	embeddingProvider embeddingproviders.EmbeddingProvider
	selectionMode     string
	topK              int
	threshold         float64
	queryJSONPath     string
	toolsJSONPath     string
	userQueryIsJson   bool
	toolsIsJson       bool
	// auth is how the policy authenticates to the embedding provider.
	auth authentication
}

// getCacheKey generates a cache key that includes the embedding provider and model
// to avoid returning stale/incompatible embeddings if the provider or model changes.
// The key format is: hash(provider:model:description)
func (p *SemanticToolFilteringPolicy) getCacheKey(description string) string {
	// Combine provider, model, and description to create a unique cache key
	providerModel := fmt.Sprintf("%s:%s", p.embeddingConfig.EmbeddingProvider, p.embeddingConfig.EmbeddingModel)
	combinedKey := fmt.Sprintf("%s:%s", providerModel, description)
	return HashDescription(combinedKey)
}

// toolEmbeddingRequest represents a tool that needs embedding processing
type toolEmbeddingRequest struct {
	Name        string
	Description string // The text to generate embedding for
	HashKey     string // Pre-computed cache key
}

// toolEmbeddingResult represents a tool with its embedding
type toolEmbeddingResult struct {
	Name      string
	HashKey   string
	Embedding []float32
	FromCache bool
}

// processToolEmbeddingsWithCache processes tool embeddings with proper cache management.
// It first checks which tools are already cached, then generates embeddings for ALL
// uncached tools (so they can be used in similarity calculations), but only CACHES
// the ones that fit within the cache limit, avoiding wasteful evictions.
//
// Returns a map of hashKey -> embedding for all successfully processed tools
func (p *SemanticToolFilteringPolicy) processToolEmbeddingsWithCache(
	embeddingCache *EmbeddingCacheStore,
	apiId string,
	requests []toolEmbeddingRequest,
) map[string]toolEmbeddingResult {
	results := make(map[string]toolEmbeddingResult)

	if len(requests) == 0 {
		return results
	}

	// Get cache limits
	_, maxToolsPerAPI := embeddingCache.GetCacheLimits()

	// First pass: Check which tools are already cached
	var uncachedRequests []toolEmbeddingRequest

	for _, req := range requests {
		cachedEntry := embeddingCache.GetEntry(apiId, req.HashKey)
		if cachedEntry != nil {
			// Cache hit
			results[req.HashKey] = toolEmbeddingResult{
				Name:      req.Name,
				HashKey:   req.HashKey,
				Embedding: cachedEntry.Embedding,
				FromCache: true,
			}
			slog.Debug("SemanticToolFiltering: Cache hit for tool embedding", "toolName", req.Name)
		} else {
			uncachedRequests = append(uncachedRequests, req)
		}
	}

	slog.Debug("SemanticToolFiltering: Cache check complete",
		"totalTools", len(requests),
		"cachedTools", len(results),
		"uncachedTools", len(uncachedRequests))

	// Calculate available slots for caching new tools
	apiCache := embeddingCache.GetAPICache(apiId)
	currentCachedCount := 0
	if apiCache != nil {
		currentCachedCount = len(apiCache)
	}
	availableSlots := maxToolsPerAPI - currentCachedCount
	if availableSlots < 0 {
		availableSlots = 0
	}

	slog.Debug("SemanticToolFiltering: Available cache slots",
		"currentCached", currentCachedCount,
		"maxToolsPerAPI", maxToolsPerAPI,
		"availableSlots", availableSlots)

	// Generate embeddings for ALL uncached tools (for similarity calculation)
	// but only cache the ones that fit
	var toolEntriesToCache []ToolEntry
	toolsCached := 0

	for _, req := range uncachedRequests {
		embedding, err := p.embeddingProvider.GetEmbedding(req.Description)
		if err != nil {
			slog.Warn("SemanticToolFiltering: Error generating tool embedding, skipping",
				"error", err, "toolName", req.Name)
			continue
		}

		// Add to results so this tool can be used in similarity calculations
		results[req.HashKey] = toolEmbeddingResult{
			Name:      req.Name,
			HashKey:   req.HashKey,
			Embedding: embedding,
			FromCache: false,
		}

		// Only cache if we have available slots
		if toolsCached < availableSlots {
			toolEntriesToCache = append(toolEntriesToCache, ToolEntry{
				HashKey:   req.HashKey,
				Name:      req.Name,
				Embedding: embedding,
			})
			toolsCached++
		} else {
			slog.Debug("SemanticToolFiltering: Tool processed but not cached (limit reached)",
				"toolName", req.Name)
		}
	}

	slog.Debug("SemanticToolFiltering: Embedding generation complete",
		"totalProcessed", len(results),
		"newlyGenerated", len(uncachedRequests),
		"willCache", toolsCached,
		"notCached", len(uncachedRequests)-toolsCached)

	// Bulk add embeddings that fit in cache
	if len(toolEntriesToCache) > 0 {
		bulkResult := embeddingCache.BulkAddTools(apiId, toolEntriesToCache)
		slog.Debug("SemanticToolFiltering: Bulk added tool embeddings to cache",
			"added", len(bulkResult.Added),
			"skipped", len(bulkResult.Skipped),
			"alreadyCached", len(bulkResult.Cached))
	}

	return results
}

// GetPolicy is the v1alpha2 factory entry point (loaded by v1alpha2 kernels).
func GetPolicy(
	metadata policy.PolicyMetadata,
	params map[string]interface{},
) (policy.Policy, error) {
	p := &SemanticToolFilteringPolicy{}

	// Parse and validate embedding provider configuration (from systemParameters)
	if err := parseEmbeddingConfig(params, p); err != nil {
		return nil, fmt.Errorf("invalid embedding config: %w", err)
	}

	// Initialize embedding provider
	embeddingProvider, err := createEmbeddingProvider(p.embeddingConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create embedding provider: %w", err)
	}
	p.embeddingProvider = embeddingProvider

	// Parse policy parameters (runtime parameters)
	if err := parseParams(params, p); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}

	slog.Debug("SemanticToolFiltering: Policy initialized",
		"embeddingProvider", p.embeddingConfig.EmbeddingProvider,
		"selectionMode", p.selectionMode,
		"topK", p.topK,
		"threshold", p.threshold)

	return p, nil
}

// Mode returns the processing mode for the semantic tool filtering policy.
func (p *SemanticToolFilteringPolicy) Mode() policy.ProcessingMode {
	return policy.ProcessingMode{
		RequestHeaderMode:  policy.HeaderModeSkip,
		RequestBodyMode:    policy.BodyModeBuffer,
		ResponseHeaderMode: policy.HeaderModeSkip,
		ResponseBodyMode:   policy.BodyModeSkip,
	}
}

// parseEmbeddingConfig parses and validates embedding provider configuration
func parseEmbeddingConfig(params map[string]interface{}, p *SemanticToolFilteringPolicy) error {
	provider, ok := params["embeddingProvider"].(string)
	if !ok || provider == "" {
		return fmt.Errorf("'embeddingProvider' is required")
	}

	embeddingEndpoint, ok := params["embeddingEndpoint"].(string)
	if !ok || embeddingEndpoint == "" {
		return fmt.Errorf("'embeddingEndpoint' is required")
	}

	auth, err := parseAuthentication(params)
	if err != nil {
		return err
	}
	if err := checkAllowedEndpoint(params, embeddingEndpoint); err != nil {
		return err
	}

	// embeddingModel is required for OPENAI and MISTRAL, but not for AZURE_OPENAI
	embeddingModel, ok := params["embeddingModel"].(string)
	if !ok || embeddingModel == "" {
		providerUpper := strings.ToUpper(provider)
		if providerUpper == "OPENAI" || providerUpper == "MISTRAL" {
			return fmt.Errorf("'embeddingModel' is required for %s provider", provider)
		}
		// For AZURE_OPENAI, embeddingModel is optional (deployment name is in endpoint)
		embeddingModel = ""
	}

	// In an identity mode the SDK gets tokens for the gateway's identity and the key is never
	// passed on.
	var apiKey, authHeaderName string
	if !auth.usesIdentity() {
		apiKey, ok = params["apiKey"].(string)
		if !ok || apiKey == "" {
			return fmt.Errorf("'apiKey' is required")
		}

		// Set header name based on provider type
		// Azure OpenAI uses "api-key", others use "Authorization"
		authHeaderName = "Authorization"
		if strings.ToUpper(provider) == "AZURE_OPENAI" {
			authHeaderName = "api-key"
		}
	}

	p.embeddingConfig = embeddingproviders.EmbeddingProviderConfig{
		EmbeddingProvider:  strings.ToUpper(provider),
		EmbeddingEndpoint:  embeddingEndpoint,
		APIKey:             apiKey,
		AuthHeaderName:     authHeaderName,
		EmbeddingModel:     embeddingModel,
		TimeOut:            strconv.Itoa(DefaultTimeoutMs),
		AuthenticationType: auth.typ,
		ClientID:           auth.clientID,
		TokenScope:         auth.tokenScope,
	}
	p.auth = auth

	return nil
}

// parseParams parses and validates runtime parameters from the params map
func parseParams(params map[string]interface{}, p *SemanticToolFilteringPolicy) error {
	// Optional: selectionMode (default TOP_K)
	selectionMode, ok := params["selectionMode"].(string)
	if !ok || selectionMode == "" {
		selectionMode = SelectionModeTopK
	}
	if selectionMode != SelectionModeTopK && selectionMode != SelectionModeThreshold {
		return fmt.Errorf("'selectionMode' must be By Rank or By Threshold")
	}
	p.selectionMode = selectionMode

	// Optional: Limit (default 5 as per policy-definition.yaml)
	if limitRaw, ok := params["limit"]; ok {
		limit, err := extractInt(limitRaw)
		if err != nil {
			return fmt.Errorf("'limit' must be a number: %w", err)
		}
		if limit < 0 || limit > 20 {
			return fmt.Errorf("'limit' must be between 0 and 20")
		}
		p.topK = limit
	} else {
		p.topK = 5 // default from policy-definition.yaml
	}

	// Optional: similarityThreshold (default 0.7 as per policy-definition.yaml)
	if thresholdRaw, ok := params["threshold"]; ok {
		threshold, err := extractFloat64(thresholdRaw)
		if err != nil {
			return fmt.Errorf("'threshold' must be a number: %w", err)
		}
		if threshold < 0.0 || threshold > 1.0 {
			return fmt.Errorf("'threshold' must be between 0.0 and 1.0")
		}
		p.threshold = threshold
	} else {
		p.threshold = 0.7 // default from policy-definition.yaml
	}

	// Optional: jsonPath (default "$.messages[-1].content" as per policy-definition.yaml)
	if jsonPathRaw, ok := params["queryJSONPath"]; ok {
		if jsonPath, ok := jsonPathRaw.(string); ok {
			if jsonPath != "" {
				p.queryJSONPath = jsonPath
			} else {
				p.queryJSONPath = "$.messages[-1].content" // default from policy-definition.yaml
			}
		} else {
			return fmt.Errorf("'queryJSONPath' must be a string")
		}
	} else {
		p.queryJSONPath = "$.messages[-1].content" // default from policy-definition.yaml
	}

	// Optional: toolsPath (default "$.tools" as per policy-definition.yaml)
	if toolsPathRaw, ok := params["toolsJSONPath"]; ok {
		if toolsPath, ok := toolsPathRaw.(string); ok {
			if toolsPath != "" {
				p.toolsJSONPath = toolsPath
			} else {
				p.toolsJSONPath = "$.tools" // default from policy-definition.yaml
			}
		} else {
			return fmt.Errorf("'toolsJSONPath' must be a string")
		}
	} else {
		p.toolsJSONPath = "$.tools" // default from policy-definition.yaml
	}

	// Validate toolsJSONPath pattern - must be a simple dotted path with optional array indices
	// Pattern: $.field1.field2[0].field3 or $.tools
	// This restriction ensures compatibility with updateToolsInRequestBody which only supports
	// simple dotted paths with optional single-level array indices
	if err := validateSimpleJSONPath(p.toolsJSONPath); err != nil {
		return fmt.Errorf("'toolsJSONPath' validation failed: %w", err)
	}

	// Optional: userQueryIsJson (default true - JSON format)
	if userQueryIsJsonRaw, ok := params["userQueryIsJson"]; ok {
		userQueryIsJson, err := extractBool(userQueryIsJsonRaw)
		if err != nil {
			return fmt.Errorf("'userQueryIsJson' must be a boolean: %w", err)
		}
		p.userQueryIsJson = userQueryIsJson
	} else {
		p.userQueryIsJson = true // default to JSON format
	}

	// Optional: toolsIsJson (default true - JSON format)
	if toolsIsJsonRaw, ok := params["toolsIsJson"]; ok {
		toolsIsJson, err := extractBool(toolsIsJsonRaw)
		if err != nil {
			return fmt.Errorf("'toolsIsJson' must be a boolean: %w", err)
		}
		p.toolsIsJson = toolsIsJson
	} else {
		p.toolsIsJson = true // default to JSON format
	}

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

// extractBool safely extracts a boolean from various types
func extractBool(value interface{}) (bool, error) {
	switch v := value.(type) {
	case bool:
		return v, nil
	case string:
		lower := strings.ToLower(v)
		if lower == "true" || lower == "1" || lower == "yes" {
			return true, nil
		}
		if lower == "false" || lower == "0" || lower == "no" {
			return false, nil
		}
		return false, fmt.Errorf("cannot convert %q to bool", v)
	case int:
		return v != 0, nil
	case float64:
		return v != 0, nil
	default:
		return false, fmt.Errorf("cannot convert %T to bool", value)
	}
}

// jsonPathSegmentPattern validates a single JSONPath segment with an optional
// numeric array index or a single wildcard iterator marker.
var jsonPathSegmentPattern = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*(\[(\d+|\*)\])?$`)

type toolsPathSpec struct {
	arrayPath             string
	iteratedObjectSubpath string
}

// validateSimpleJSONPath validates that the given JSONPath is a simple dotted path
// that can be handled by updateToolsInRequestBody
func validateSimpleJSONPath(path string) error {
	if path == "" {
		return fmt.Errorf("path cannot be empty")
	}

	// Must start with "$."
	if !strings.HasPrefix(path, "$.") {
		return fmt.Errorf("path must start with '$.' prefix, got: %s", path)
	}

	segments := strings.Split(strings.TrimPrefix(path, "$."), ".")
	wildcardCount := 0

	for _, segment := range segments {
		if segment == "" {
			return fmt.Errorf("path contains an empty segment: %s", path)
		}
		if !jsonPathSegmentPattern.MatchString(segment) {
			return fmt.Errorf("path contains unsupported JSONPath syntax; only simple dotted paths with optional array indices or a single iterator wildcard are supported (e.g., '$.tools', '$.results[0].tools', '$.tools[*].function'); got: %s", path)
		}
		if strings.Contains(segment, "[*]") {
			wildcardCount++
		}
	}

	if wildcardCount > 1 {
		return fmt.Errorf("path can contain at most one iterator wildcard [*]: %s", path)
	}

	return nil
}

func parseToolsJSONPath(path string) (toolsPathSpec, error) {
	if err := validateSimpleJSONPath(path); err != nil {
		return toolsPathSpec{}, err
	}

	spec := toolsPathSpec{arrayPath: path}
	wildcardIdx := strings.Index(path, "[*]")
	if wildcardIdx == -1 {
		return spec, nil
	}

	spec.arrayPath = path[:wildcardIdx]
	suffix := path[wildcardIdx+3:]
	if suffix == "" {
		return spec, nil
	}
	if !strings.HasPrefix(suffix, ".") {
		return toolsPathSpec{}, fmt.Errorf("invalid tools path after iterator wildcard: %s", path)
	}

	spec.iteratedObjectSubpath = strings.TrimPrefix(suffix, ".")
	return spec, nil
}

func extractValueFromRelativePath(root interface{}, relativePath string) (interface{}, error) {
	if relativePath == "" {
		return root, nil
	}

	segments := strings.Split(relativePath, ".")
	current := root

	for _, segment := range segments {
		if segment == "" {
			return nil, fmt.Errorf("relative path contains an empty segment: %s", relativePath)
		}
		if strings.Contains(segment, "[*]") {
			return nil, fmt.Errorf("relative path cannot contain iterator wildcard [*]: %s", relativePath)
		}
		if !jsonPathSegmentPattern.MatchString(segment) {
			return nil, fmt.Errorf("relative path contains unsupported syntax: %s", relativePath)
		}

		field := segment
		index := -1
		if openIdx := strings.Index(segment, "["); openIdx != -1 && strings.HasSuffix(segment, "]") {
			field = segment[:openIdx]
			indexValue, err := strconv.Atoi(segment[openIdx+1 : len(segment)-1])
			if err != nil {
				return nil, fmt.Errorf("invalid array index in relative path: %s", segment)
			}
			index = indexValue
		}

		currentMap, ok := current.(map[string]interface{})
		if !ok {
			return nil, nil
		}

		next, ok := currentMap[field]
		if !ok {
			return nil, nil
		}

		if index == -1 {
			current = next
			continue
		}

		array, ok := next.([]interface{})
		if !ok || index < 0 || index >= len(array) {
			return nil, nil
		}
		current = array[index]
	}

	return current, nil
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

// extractUserQueryFromText extracts user query from text content using <userq> tags
func extractUserQueryFromText(content string) (string, error) {
	startTag := "<userq>"
	endTag := "</userq>"

	startIdx := strings.Index(content, startTag)
	if startIdx == -1 {
		return "", fmt.Errorf("user query start tag <userq> not found")
	}

	// Search for end tag only after the start tag to avoid matching stray earlier </userq>
	endIdx := strings.Index(content[startIdx+len(startTag):], endTag)
	if endIdx == -1 {
		return "", fmt.Errorf("user query end tag </userq> not found")
	}
	endIdx += startIdx + len(startTag)

	query := content[startIdx+len(startTag) : endIdx]
	return strings.TrimSpace(query), nil
}

// extractToolsFromText extracts tools from text content using <toolname> and <tooldescription> tags
func extractToolsFromText(content string) ([]TextTool, error) {
	var tools []TextTool

	toolNameStartTag := "<toolname>"
	toolNameEndTag := "</toolname>"
	toolDescStartTag := "<tooldescription>"
	toolDescEndTag := "</tooldescription>"

	// Find all tool definitions in the content
	searchStart := 0
	for {
		// Find tool name
		nameStartIdx := strings.Index(content[searchStart:], toolNameStartTag)
		if nameStartIdx == -1 {
			break
		}
		nameStartIdx += searchStart

		nameEndIdx := strings.Index(content[nameStartIdx:], toolNameEndTag)
		if nameEndIdx == -1 {
			return nil, fmt.Errorf("tool name end tag </toolname> not found for tool starting at position %d", nameStartIdx)
		}
		nameEndIdx += nameStartIdx

		toolName := strings.TrimSpace(content[nameStartIdx+len(toolNameStartTag) : nameEndIdx])

		// Find tool description after the name
		descSearchStart := nameEndIdx + len(toolNameEndTag)
		descStartIdx := strings.Index(content[descSearchStart:], toolDescStartTag)
		if descStartIdx == -1 {
			return nil, fmt.Errorf("tool description start tag <tooldescription> not found for tool '%s'", toolName)
		}
		descStartIdx += descSearchStart

		descEndIdx := strings.Index(content[descStartIdx:], toolDescEndTag)
		if descEndIdx == -1 {
			return nil, fmt.Errorf("tool description end tag </tooldescription> not found for tool '%s'", toolName)
		}
		descEndIdx += descStartIdx

		toolDesc := strings.TrimSpace(content[descStartIdx+len(toolDescStartTag) : descEndIdx])

		tools = append(tools, TextTool{
			Name:        toolName,
			Description: toolDesc,
			StartPos:    nameStartIdx,
			EndPos:      descEndIdx + len(toolDescEndTag),
		})

		// Move search start past this tool
		searchStart = descEndIdx + len(toolDescEndTag)
	}

	return tools, nil
}

// rebuildTextWithFilteredTools rebuilds the text content keeping only filtered tools
func rebuildTextWithFilteredTools(originalContent string, allTools []TextTool, filteredToolNames map[string]bool) string {
	if len(allTools) == 0 {
		return originalContent
	}

	// Sort tools by start position in reverse order to process from end to start
	// This ensures position calculations remain valid as we remove content
	sortedTools := make([]TextTool, len(allTools))
	copy(sortedTools, allTools)
	sort.Slice(sortedTools, func(i, j int) bool {
		return sortedTools[i].StartPos > sortedTools[j].StartPos
	})

	result := originalContent

	// Remove tools that are not in the filtered list
	for _, tool := range sortedTools {
		if !filteredToolNames[tool.Name] {
			// Remove this tool from the content
			result = result[:tool.StartPos] + result[tool.EndPos:]
		}
	}

	// Clean up any extra blank lines left after removal
	result = cleanupWhitespace(result)

	return result
}

// stripAllTags removes all text-format tags (userq, toolname, tooldescription) from the content.
// Called after filtering so the downstream payload is clean plain text.
func stripAllTags(content string) string {
	content = strings.ReplaceAll(content, "<userq>", "")
	content = strings.ReplaceAll(content, "</userq>", "")
	content = strings.ReplaceAll(content, "<toolname>", "")
	content = strings.ReplaceAll(content, "</toolname>", "")
	content = strings.ReplaceAll(content, "<tooldescription>", "")
	content = strings.ReplaceAll(content, "</tooldescription>", "")
	return cleanupWhitespace(content)
}

// cleanupWhitespace removes excessive blank lines while preserving original spacing and indentation.
// Only collapses multiple consecutive blank lines (3+ newlines) to a double newline.
// Does NOT modify spaces or trim content to preserve user prompts exactly.
func cleanupWhitespace(content string) string {
	// Replace multiple consecutive newlines (3+) with double newline only
	for strings.Contains(content, "\n\n\n") {
		content = strings.ReplaceAll(content, "\n\n\n", "\n\n")
	}
	return content
}

func extractToolNameAndDescription(tool map[string]interface{}) (string, string) {
	name, _ := tool["name"].(string)

	fields := []string{"description", "desc", "summary", "info"}
	description := ""
	for _, field := range fields {
		if desc, ok := tool[field].(string); ok && desc != "" {
			description = desc
			break
		}
	}

	// Support OpenAI-style wrappers such as {"type":"function","function":{...}}
	if function, ok := tool["function"].(map[string]interface{}); ok {
		if name == "" {
			if nestedName, ok := function["name"].(string); ok && nestedName != "" {
				name = nestedName
			}
		}
		if description == "" {
			for _, field := range fields {
				if desc, ok := function[field].(string); ok && desc != "" {
					description = desc
					break
				}
			}
		}
	}

	return name, description
}

func buildToolEmbeddingText(name, description string) string {
	if name != "" && description != "" {
		return fmt.Sprintf("%s: %s", name, description)
	}
	if description != "" {
		return description
	}
	return name
}

// extractToolDescription extracts the text used to represent a tool for embedding generation.
func extractToolDescription(tool map[string]interface{}) string {
	return buildToolEmbeddingText(extractToolNameAndDescription(tool))
}

// cosineSimilarity calculates cosine similarity between two embeddings
func cosineSimilarity(a, b []float32) (float64, error) {
	if len(a) == 0 || len(b) == 0 {
		return 0, fmt.Errorf("embedding vectors cannot be empty")
	}

	if len(a) != len(b) {
		return 0, fmt.Errorf("embedding dimensions do not match: %d vs %d", len(a), len(b))
	}

	var dot, normA, normB float64
	for i := range a {
		dot += float64(a[i] * b[i])
		normA += float64(a[i] * a[i])
		normB += float64(b[i] * b[i])
	}

	if normA == 0 || normB == 0 {
		return 0, fmt.Errorf("embedding vector norm is zero")
	}

	return dot / (math.Sqrt(normA) * math.Sqrt(normB)), nil
}

// filterTools filters tools based on selection mode and criteria
func (p *SemanticToolFilteringPolicy) filterTools(toolsWithScores []ToolWithScore) []map[string]interface{} {
	// Sort by score in descending order
	sort.Slice(toolsWithScores, func(i, j int) bool {
		return toolsWithScores[i].Score > toolsWithScores[j].Score
	})

	var filtered []map[string]interface{}

	switch p.selectionMode {
	case SelectionModeTopK:
		// Select top K tools
		limit := p.topK
		if limit > len(toolsWithScores) {
			limit = len(toolsWithScores)
		}
		for i := 0; i < limit; i++ {
			filtered = append(filtered, toolsWithScores[i].Tool)
		}

	case SelectionModeThreshold:
		// Select all tools above threshold
		for _, item := range toolsWithScores {
			if item.Score >= p.threshold {
				filtered = append(filtered, item.Tool)
			}
		}
	}

	return filtered
}

// updateToolsInRequestBody updates the tools array in the request body
func updateToolsInRequestBody(requestBody *map[string]interface{}, toolsPath string, tools []map[string]interface{}) error {
	spec, err := parseToolsJSONPath(toolsPath)
	if err != nil {
		return err
	}

	// Remove leading "$." if present
	path := strings.TrimPrefix(spec.arrayPath, "$.")
	parts := strings.Split(path, ".")

	if len(parts) == 0 {
		return fmt.Errorf("invalid toolsPath: %s", toolsPath)
	}

	// Handle array index in path, e.g., "tools[0]"
	curr := *requestBody
	for idx, part := range parts {
		// Check if part contains array index, e.g., "tools[0]"
		if openIdx := strings.Index(part, "["); openIdx != -1 && strings.HasSuffix(part, "]") {
			field := part[:openIdx]
			indexStr := part[openIdx+1 : len(part)-1]
			index, err := strconv.Atoi(indexStr)
			if err != nil {
				return fmt.Errorf("invalid array index in path: %s", part)
			}
			if index < 0 {
				return fmt.Errorf("negative array index in path: %s", part)
			}

			// If this is the last part, set the value at the array index
			if idx == len(parts)-1 {
				// Ensure the array exists
				arr, ok := curr[field].([]interface{})
				if !ok {
					// Create array if not present
					arr = make([]interface{}, index+1)
				} else if len(arr) <= index {
					// Extend array if needed
					newArr := make([]interface{}, index+1)
					copy(newArr, arr)
					arr = newArr
				}
				arr[index] = tools
				curr[field] = arr
				return nil
			}

			// Not last part, descend into the array element
			arr, ok := curr[field].([]interface{})
			if !ok {
				// Create array if not present
				arr = make([]interface{}, index+1)
				curr[field] = arr
			} else if len(arr) <= index {
				// Extend array if needed
				newArr := make([]interface{}, index+1)
				copy(newArr, arr)
				arr = newArr
				curr[field] = arr
			}
			// If element is nil, create map
			if arr[index] == nil {
				arr[index] = make(map[string]interface{})
			}
			nextMap, ok := arr[index].(map[string]interface{})
			if !ok {
				return fmt.Errorf("expected map at array index %d in field %s", index, field)
			}
			curr = nextMap
			continue
		}

		// If this is the last part, set the value
		if idx == len(parts)-1 {
			curr[part] = tools
			return nil
		}

		// If the next level doesn't exist, create it as a map
		next, ok := curr[part]
		if !ok {
			newMap := make(map[string]interface{})
			curr[part] = newMap
			curr = newMap
			continue
		}

		// If the next level is a map, descend into it
		nextMap, ok := next.(map[string]interface{})
		if !ok {
			return fmt.Errorf("expected map at path %s but found %T", part, next)
		}
		curr = nextMap
	}

	return nil
}
