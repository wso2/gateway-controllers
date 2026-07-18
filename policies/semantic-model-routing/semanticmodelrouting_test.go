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

package semanticmodelrouting

import (
	"math"
	"strings"
	"testing"
)

// --- Cosine Similarity Tests ---

func TestCalculateCosineSimilarity_IdenticalVectors(t *testing.T) {
	vectorA := []float32{1.0, 2.0, 3.0}
	vectorB := []float32{1.0, 2.0, 3.0}

	result := CalculateCosineSimilarity(vectorA, vectorB)

	// Identical vectors should have similarity of 1.0
	if math.Abs(result-1.0) > 1e-6 {
		t.Errorf("Expected similarity ~1.0 for identical vectors, got %.6f", result)
	}
}

func TestCalculateCosineSimilarity_OrthogonalVectors(t *testing.T) {
	vectorA := []float32{1.0, 0.0, 0.0}
	vectorB := []float32{0.0, 1.0, 0.0}

	result := CalculateCosineSimilarity(vectorA, vectorB)

	// Orthogonal vectors should have similarity of 0.0
	if math.Abs(result) > 1e-6 {
		t.Errorf("Expected similarity ~0.0 for orthogonal vectors, got %.6f", result)
	}
}

func TestCalculateCosineSimilarity_OppositeVectors(t *testing.T) {
	vectorA := []float32{1.0, 2.0, 3.0}
	vectorB := []float32{-1.0, -2.0, -3.0}

	result := CalculateCosineSimilarity(vectorA, vectorB)

	// Opposite vectors should have similarity of -1.0
	if math.Abs(result-(-1.0)) > 1e-6 {
		t.Errorf("Expected similarity ~-1.0 for opposite vectors, got %.6f", result)
	}
}

func TestCalculateCosineSimilarity_KnownVectors(t *testing.T) {
	// Known computation: [1,2,3] dot [4,5,6] = 4+10+18 = 32
	// |[1,2,3]| = sqrt(14), |[4,5,6]| = sqrt(77)
	// cos = 32 / (sqrt(14) * sqrt(77)) = 32 / sqrt(1078) ≈ 0.9746
	vectorA := []float32{1.0, 2.0, 3.0}
	vectorB := []float32{4.0, 5.0, 6.0}

	result := CalculateCosineSimilarity(vectorA, vectorB)
	expected := 32.0 / math.Sqrt(14.0*77.0)

	if math.Abs(result-expected) > 1e-6 {
		t.Errorf("Expected similarity ~%.6f, got %.6f", expected, result)
	}
}

func TestCalculateCosineSimilarity_ZeroVector(t *testing.T) {
	vectorA := []float32{0.0, 0.0, 0.0}
	vectorB := []float32{1.0, 2.0, 3.0}

	result := CalculateCosineSimilarity(vectorA, vectorB)

	// Zero vector should return 0.0 (avoid division by zero)
	if result != 0.0 {
		t.Errorf("Expected 0.0 for zero vector, got %.6f", result)
	}
}

func TestCalculateCosineSimilarity_NilVectors(t *testing.T) {
	result := CalculateCosineSimilarity(nil, []float32{1.0, 2.0})
	if result != 0.0 {
		t.Errorf("Expected 0.0 for nil vectorA, got %.6f", result)
	}

	result = CalculateCosineSimilarity([]float32{1.0, 2.0}, nil)
	if result != 0.0 {
		t.Errorf("Expected 0.0 for nil vectorB, got %.6f", result)
	}
}

func TestCalculateCosineSimilarity_DifferentLengths(t *testing.T) {
	vectorA := []float32{1.0, 2.0}
	vectorB := []float32{1.0, 2.0, 3.0}

	result := CalculateCosineSimilarity(vectorA, vectorB)

	// Different length vectors should return 0.0
	if result != 0.0 {
		t.Errorf("Expected 0.0 for different length vectors, got %.6f", result)
	}
}

// --- Max Cosine Similarity Tests ---

func TestComputeMaxCosineSimilarity(t *testing.T) {
	requestEmbedding := []float32{1.0, 0.0, 0.0}
	utteranceEmbeddings := [][]float32{
		{0.0, 1.0, 0.0},  // orthogonal = 0.0
		{1.0, 0.0, 0.0},  // identical = 1.0
		{0.5, 0.5, 0.0},  // partial match
	}

	result := computeMaxCosineSimilarity(requestEmbedding, utteranceEmbeddings)

	// Should return max similarity (1.0 from the identical vector)
	if math.Abs(result-1.0) > 1e-6 {
		t.Errorf("Expected max similarity ~1.0, got %.6f", result)
	}
}

func TestComputeMaxCosineSimilarity_EmptyUtterances(t *testing.T) {
	requestEmbedding := []float32{1.0, 0.0, 0.0}
	utteranceEmbeddings := [][]float32{}

	result := computeMaxCosineSimilarity(requestEmbedding, utteranceEmbeddings)

	if result != 0.0 {
		t.Errorf("Expected 0.0 for empty utterances, got %.6f", result)
	}
}

// --- Find Best Route Tests ---

func TestFindBestRoute_MatchesHighestScore(t *testing.T) {
	p := &SemanticModelRoutingPolicy{
		routes: []SemanticRoute{
			{
				Model:          "model-a",
				ScoreThreshold: 0.8,
				UtteranceEmbeddings: [][]float32{
					{0.0, 1.0, 0.0}, // low similarity with request
				},
			},
			{
				Model:          "model-b",
				ScoreThreshold: 0.8,
				UtteranceEmbeddings: [][]float32{
					{1.0, 0.0, 0.0}, // high similarity with request
				},
			},
		},
	}

	requestEmbedding := []float32{1.0, 0.0, 0.0}
	bestRoute, bestScore := p.findBestRoute(requestEmbedding)

	if bestRoute == nil {
		t.Fatal("Expected a best route, got nil")
	}

	if bestRoute.Model != "model-b" {
		t.Errorf("Expected best route 'model-b', got %q", bestRoute.Model)
	}

	if math.Abs(bestScore-1.0) > 1e-6 {
		t.Errorf("Expected best score ~1.0, got %.6f", bestScore)
	}
}

func TestFindBestRoute_SkipsRoutesWithNoEmbeddings(t *testing.T) {
	p := &SemanticModelRoutingPolicy{
		routes: []SemanticRoute{
			{
				Model:               "model-no-embeddings",
				ScoreThreshold:      0.8,
				UtteranceEmbeddings: nil,
			},
			{
				Model:          "model-with-embeddings",
				ScoreThreshold: 0.8,
				UtteranceEmbeddings: [][]float32{
					{1.0, 0.0, 0.0},
				},
			},
		},
	}

	requestEmbedding := []float32{1.0, 0.0, 0.0}
	bestRoute, _ := p.findBestRoute(requestEmbedding)

	if bestRoute == nil {
		t.Fatal("Expected a best route, got nil")
	}

	if bestRoute.Model != "model-with-embeddings" {
		t.Errorf("Expected 'model-with-embeddings', got %q", bestRoute.Model)
	}
}

// --- Parameter Parsing Tests ---

func TestParseParams_ValidConfig(t *testing.T) {
	params := map[string]interface{}{
		"contentPath": "$.messages[-1].content",
		"routes": []interface{}{
			map[string]interface{}{
				"model": "gpt-4o-mini",
				"utterances": []interface{}{
					"write code",
					"generate a function",
				},
				"scorethreshold": 0.85,
			},
			map[string]interface{}{
				"model": "gpt-4o",
				"utterances": []interface{}{
					"what is the weather",
				},
				"scorethreshold": 0.90,
			},
		},
		"defaultModel": "gpt-4o",
		"requestModel": map[string]interface{}{
			"location":   "payload",
			"identifier": "$.model",
		},
	}

	p := &SemanticModelRoutingPolicy{}
	err := parseParams(params, p)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if len(p.routes) != 2 {
		t.Errorf("Expected 2 routes, got %d", len(p.routes))
	}

	if p.routes[0].Model != "gpt-4o-mini" {
		t.Errorf("Expected first route model 'gpt-4o-mini', got %q", p.routes[0].Model)
	}

	if len(p.routes[0].Utterances) != 2 {
		t.Errorf("Expected 2 utterances for first route, got %d", len(p.routes[0].Utterances))
	}

	if p.routes[0].ScoreThreshold != 0.85 {
		t.Errorf("Expected threshold 0.85, got %.2f", p.routes[0].ScoreThreshold)
	}

	if p.defaultModel != "gpt-4o" {
		t.Errorf("Expected default model 'gpt-4o', got %q", p.defaultModel)
	}
}

func TestParseParams_DefaultThreshold(t *testing.T) {
	params := map[string]interface{}{
		"routes": []interface{}{
			map[string]interface{}{
				"model":      "gpt-4o-mini",
				"utterances": []interface{}{"test"},
				// No scorethreshold provided
			},
		},
		"defaultModel": "gpt-4o",
		"requestModel": map[string]interface{}{
			"location":   "payload",
			"identifier": "$.model",
		},
	}

	p := &SemanticModelRoutingPolicy{}
	err := parseParams(params, p)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if p.routes[0].ScoreThreshold != DefaultSimilarityThreshold {
		t.Errorf("Expected default threshold %.2f, got %.2f",
			DefaultSimilarityThreshold, p.routes[0].ScoreThreshold)
	}
}

func TestParseParams_ThresholdOutOfRange(t *testing.T) {
	params := map[string]interface{}{
		"routes": []interface{}{
			map[string]interface{}{
				"model":          "gpt-4o-mini",
				"utterances":     []interface{}{"test"},
				"scorethreshold": 1.5, // Out of range
			},
		},
		"defaultModel": "gpt-4o",
		"requestModel": map[string]interface{}{
			"location":   "payload",
			"identifier": "$.model",
		},
	}

	p := &SemanticModelRoutingPolicy{}
	err := parseParams(params, p)
	if err != nil {
		t.Fatalf("Expected no error (should use default), got: %v", err)
	}

	// Should fall back to default threshold
	if p.routes[0].ScoreThreshold != DefaultSimilarityThreshold {
		t.Errorf("Expected default threshold for out-of-range value, got %.2f",
			p.routes[0].ScoreThreshold)
	}
}

func TestParseParams_MissingRoutes(t *testing.T) {
	params := map[string]interface{}{
		"defaultModel": "gpt-4o",
		"requestModel": map[string]interface{}{
			"location":   "payload",
			"identifier": "$.model",
		},
	}

	p := &SemanticModelRoutingPolicy{}
	err := parseParams(params, p)
	if err == nil {
		t.Fatal("Expected error for missing routes, got nil")
	}
	if !strings.Contains(err.Error(), "routes") {
		t.Errorf("Expected error about routes, got: %v", err)
	}
}

func TestParseParams_EmptyRoutesArray(t *testing.T) {
	params := map[string]interface{}{
		"routes":       []interface{}{},
		"defaultModel": "gpt-4o",
		"requestModel": map[string]interface{}{
			"location":   "payload",
			"identifier": "$.model",
		},
	}

	p := &SemanticModelRoutingPolicy{}
	err := parseParams(params, p)
	if err == nil {
		t.Fatal("Expected error for empty routes, got nil")
	}
}

func TestParseParams_MissingDefaultModel(t *testing.T) {
	params := map[string]interface{}{
		"routes": []interface{}{
			map[string]interface{}{
				"model":      "gpt-4o-mini",
				"utterances": []interface{}{"test"},
			},
		},
		"requestModel": map[string]interface{}{
			"location":   "payload",
			"identifier": "$.model",
		},
	}

	p := &SemanticModelRoutingPolicy{}
	err := parseParams(params, p)
	if err == nil {
		t.Fatal("Expected error for missing defaultModel, got nil")
	}
	if !strings.Contains(err.Error(), "defaultModel") {
		t.Errorf("Expected error about defaultModel, got: %v", err)
	}
}

func TestParseParams_MissingRouteModel(t *testing.T) {
	params := map[string]interface{}{
		"routes": []interface{}{
			map[string]interface{}{
				"utterances": []interface{}{"test"},
			},
		},
		"defaultModel": "gpt-4o",
		"requestModel": map[string]interface{}{
			"location":   "payload",
			"identifier": "$.model",
		},
	}

	p := &SemanticModelRoutingPolicy{}
	err := parseParams(params, p)
	if err == nil {
		t.Fatal("Expected error for missing route model, got nil")
	}
	if !strings.Contains(err.Error(), "model") {
		t.Errorf("Expected error about model, got: %v", err)
	}
}

func TestParseParams_MissingUtterances(t *testing.T) {
	params := map[string]interface{}{
		"routes": []interface{}{
			map[string]interface{}{
				"model": "gpt-4o-mini",
			},
		},
		"defaultModel": "gpt-4o",
		"requestModel": map[string]interface{}{
			"location":   "payload",
			"identifier": "$.model",
		},
	}

	p := &SemanticModelRoutingPolicy{}
	err := parseParams(params, p)
	if err == nil {
		t.Fatal("Expected error for missing utterances, got nil")
	}
	if !strings.Contains(err.Error(), "utterances") {
		t.Errorf("Expected error about utterances, got: %v", err)
	}
}

func TestParseParams_EmptyUtterancesArray(t *testing.T) {
	params := map[string]interface{}{
		"routes": []interface{}{
			map[string]interface{}{
				"model":      "gpt-4o-mini",
				"utterances": []interface{}{},
			},
		},
		"defaultModel": "gpt-4o",
		"requestModel": map[string]interface{}{
			"location":   "payload",
			"identifier": "$.model",
		},
	}

	p := &SemanticModelRoutingPolicy{}
	err := parseParams(params, p)
	if err == nil {
		t.Fatal("Expected error for empty utterances, got nil")
	}
}

func TestParseParams_MissingRequestModel(t *testing.T) {
	params := map[string]interface{}{
		"routes": []interface{}{
			map[string]interface{}{
				"model":      "gpt-4o-mini",
				"utterances": []interface{}{"test"},
			},
		},
		"defaultModel": "gpt-4o",
	}

	p := &SemanticModelRoutingPolicy{}
	err := parseParams(params, p)
	if err == nil {
		t.Fatal("Expected error for missing requestModel, got nil")
	}
	if !strings.Contains(err.Error(), "requestModel") {
		t.Errorf("Expected error about requestModel, got: %v", err)
	}
}

func TestParseParams_InvalidRequestModelLocation(t *testing.T) {
	params := map[string]interface{}{
		"routes": []interface{}{
			map[string]interface{}{
				"model":      "gpt-4o-mini",
				"utterances": []interface{}{"test"},
			},
		},
		"defaultModel": "gpt-4o",
		"requestModel": map[string]interface{}{
			"location":   "invalid",
			"identifier": "$.model",
		},
	}

	p := &SemanticModelRoutingPolicy{}
	err := parseParams(params, p)
	if err == nil {
		t.Fatal("Expected error for invalid location, got nil")
	}
}

// --- Embedding Config Parsing Tests ---

func TestParseEmbeddingConfig_Valid(t *testing.T) {
	params := map[string]interface{}{
		"embeddingProvider": "OPENAI",
		"embeddingEndpoint": "https://api.openai.com/v1/embeddings",
		"embeddingModel":    "text-embedding-ada-002",
		"apiKey":            "sk-test-key",
	}

	config, err := parseEmbeddingConfig(params)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if config.EmbeddingProvider != "OPENAI" {
		t.Errorf("Expected provider 'OPENAI', got %q", config.EmbeddingProvider)
	}
	if config.EmbeddingModel != "text-embedding-ada-002" {
		t.Errorf("Expected model 'text-embedding-ada-002', got %q", config.EmbeddingModel)
	}
	if config.AuthHeaderName != "Authorization" {
		t.Errorf("Expected auth header 'Authorization', got %q", config.AuthHeaderName)
	}
}

func TestParseEmbeddingConfig_AzureOpenAI(t *testing.T) {
	params := map[string]interface{}{
		"embeddingProvider": "AZURE_OPENAI",
		"embeddingEndpoint": "https://myresource.openai.azure.com/openai/deployments/ada-002/embeddings",
		"apiKey":            "azure-key",
		// Note: embeddingModel is optional for AZURE_OPENAI
	}

	config, err := parseEmbeddingConfig(params)
	if err != nil {
		t.Fatalf("Azure OpenAI should not require embeddingModel, got: %v", err)
	}
	if config.AuthHeaderName != "api-key" {
		t.Errorf("Expected auth header 'api-key' for Azure, got %q", config.AuthHeaderName)
	}
}

func TestParseEmbeddingConfig_MissingProvider(t *testing.T) {
	params := map[string]interface{}{
		"embeddingEndpoint": "https://api.openai.com/v1/embeddings",
		"apiKey":            "sk-test-key",
	}

	_, err := parseEmbeddingConfig(params)
	if err == nil {
		t.Fatal("Expected error for missing provider, got nil")
	}
}

func TestParseEmbeddingConfig_InvalidProvider(t *testing.T) {
	params := map[string]interface{}{
		"embeddingProvider": "INVALID",
		"embeddingEndpoint": "https://example.com",
		"apiKey":            "key",
	}

	_, err := parseEmbeddingConfig(params)
	if err == nil {
		t.Fatal("Expected error for invalid provider, got nil")
	}
}

func TestParseEmbeddingConfig_OpenAI_MissingModel(t *testing.T) {
	params := map[string]interface{}{
		"embeddingProvider": "OPENAI",
		"embeddingEndpoint": "https://api.openai.com/v1/embeddings",
		"apiKey":            "sk-test-key",
		// Missing embeddingModel
	}

	_, err := parseEmbeddingConfig(params)
	if err == nil {
		t.Fatal("Expected error for missing embeddingModel with OPENAI, got nil")
	}
}

// --- Extract Float64 Tests ---

func TestExtractFloat64_Float64(t *testing.T) {
	result, err := extractFloat64(0.85)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if result != 0.85 {
		t.Errorf("Expected 0.85, got %f", result)
	}
}

func TestExtractFloat64_Int(t *testing.T) {
	result, err := extractFloat64(1)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if result != 1.0 {
		t.Errorf("Expected 1.0, got %f", result)
	}
}

func TestExtractFloat64_String(t *testing.T) {
	result, err := extractFloat64("0.85")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if result != 0.85 {
		t.Errorf("Expected 0.85, got %f", result)
	}
}

func TestExtractFloat64_InvalidString(t *testing.T) {
	_, err := extractFloat64("not-a-number")
	if err == nil {
		t.Fatal("Expected error for invalid string, got nil")
	}
}

func TestExtractFloat64_UnsupportedType(t *testing.T) {
	_, err := extractFloat64([]int{1, 2, 3})
	if err == nil {
		t.Fatal("Expected error for unsupported type, got nil")
	}
}

// --- Threshold Parsing Edge Cases ---

func TestParseRouteConfig_StringThreshold(t *testing.T) {
	routeMap := map[string]interface{}{
		"model":          "gpt-4o-mini",
		"utterances":     []interface{}{"test"},
		"scorethreshold": "0.85", // String instead of number
	}

	route, err := parseRouteConfig(routeMap, 0)
	if err != nil {
		t.Fatalf("Expected no error for string threshold, got: %v", err)
	}

	if route.ScoreThreshold != 0.85 {
		t.Errorf("Expected threshold 0.85 from string, got %.2f", route.ScoreThreshold)
	}
}

func TestParseRouteConfig_NegativeThreshold(t *testing.T) {
	routeMap := map[string]interface{}{
		"model":          "gpt-4o-mini",
		"utterances":     []interface{}{"test"},
		"scorethreshold": -0.5,
	}

	route, err := parseRouteConfig(routeMap, 0)
	if err != nil {
		t.Fatalf("Expected no error (should use default), got: %v", err)
	}

	// Negative threshold should fall back to default
	if route.ScoreThreshold != DefaultSimilarityThreshold {
		t.Errorf("Expected default threshold for negative value, got %.2f", route.ScoreThreshold)
	}
}
