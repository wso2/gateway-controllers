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

package intelligentmodelrouting

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// --- Parameter Parsing Tests ---

func TestParseParams_ValidConfig(t *testing.T) {
	params := map[string]interface{}{
		"contentPath": "$.messages[-1].content",
		"routingRules": []interface{}{
			map[string]interface{}{
				"name":    "Coding",
				"context": "Code related questions",
				"model":   "gpt-4o-mini",
			},
			map[string]interface{}{
				"name":    "Weather",
				"context": "Weather related queries",
				"model":   "gpt-4o",
			},
		},
		"defaultModel": "gpt-4o",
		"llmProvider":  "OPENAI",
		"llmEndpoint":  "https://api.openai.com/v1/chat/completions",
		"llmModel":     "gpt-4o-mini",
		"llmApiKey":    "sk-test-key",
		"requestModel": map[string]interface{}{
			"location":   "payload",
			"identifier": "$.model",
		},
	}

	p := &IntelligentModelRoutingPolicy{
		httpClient: &http.Client{},
	}

	err := parseParams(params, p)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if len(p.routingRules) != 2 {
		t.Errorf("Expected 2 routing rules, got %d", len(p.routingRules))
	}

	if p.routingRules[0].Name != "Coding" {
		t.Errorf("Expected first rule name 'Coding', got %q", p.routingRules[0].Name)
	}

	if p.routingRules[0].Context != "Code related questions" {
		t.Errorf("Expected first rule context 'Code related questions', got %q", p.routingRules[0].Context)
	}

	if p.routingRules[0].Model != "gpt-4o-mini" {
		t.Errorf("Expected first rule model 'gpt-4o-mini', got %q", p.routingRules[0].Model)
	}

	if p.defaultModel != "gpt-4o" {
		t.Errorf("Expected default model 'gpt-4o', got %q", p.defaultModel)
	}

	if p.contentPath != "$.messages[-1].content" {
		t.Errorf("Expected contentPath '$.messages[-1].content', got %q", p.contentPath)
	}

	if p.llmConfig.Provider != "OPENAI" {
		t.Errorf("Expected LLM provider 'OPENAI', got %q", p.llmConfig.Provider)
	}

	if p.requestModel.Location != "payload" {
		t.Errorf("Expected requestModel location 'payload', got %q", p.requestModel.Location)
	}

	if p.requestModel.Identifier != "$.model" {
		t.Errorf("Expected requestModel identifier '$.model', got %q", p.requestModel.Identifier)
	}
}

func TestParseParams_MissingRoutingRules(t *testing.T) {
	params := map[string]interface{}{
		"defaultModel": "gpt-4o",
		"llmProvider":  "OPENAI",
		"llmEndpoint":  "https://api.openai.com/v1/chat/completions",
		"llmModel":     "gpt-4o-mini",
		"llmApiKey":    "sk-test-key",
		"requestModel": map[string]interface{}{
			"location":   "payload",
			"identifier": "$.model",
		},
	}

	p := &IntelligentModelRoutingPolicy{httpClient: &http.Client{}}
	err := parseParams(params, p)
	if err == nil {
		t.Fatal("Expected error for missing routingRules, got nil")
	}
	if !strings.Contains(err.Error(), "routingRules") {
		t.Errorf("Expected error about routingRules, got: %v", err)
	}
}

func TestParseParams_MissingDefaultModel(t *testing.T) {
	params := map[string]interface{}{
		"routingRules": []interface{}{
			map[string]interface{}{
				"name":    "Coding",
				"context": "Code related",
				"model":   "gpt-4o-mini",
			},
		},
		"llmProvider": "OPENAI",
		"llmEndpoint": "https://api.openai.com/v1/chat/completions",
		"llmModel":    "gpt-4o-mini",
		"llmApiKey":   "sk-test-key",
		"requestModel": map[string]interface{}{
			"location":   "payload",
			"identifier": "$.model",
		},
	}

	p := &IntelligentModelRoutingPolicy{httpClient: &http.Client{}}
	err := parseParams(params, p)
	if err == nil {
		t.Fatal("Expected error for missing defaultModel, got nil")
	}
	if !strings.Contains(err.Error(), "defaultModel") {
		t.Errorf("Expected error about defaultModel, got: %v", err)
	}
}

func TestParseParams_EmptyRoutingRulesArray(t *testing.T) {
	params := map[string]interface{}{
		"routingRules": []interface{}{},
		"defaultModel": "gpt-4o",
		"llmProvider":  "OPENAI",
		"llmEndpoint":  "https://api.openai.com/v1/chat/completions",
		"llmModel":     "gpt-4o-mini",
		"llmApiKey":    "sk-test-key",
		"requestModel": map[string]interface{}{
			"location":   "payload",
			"identifier": "$.model",
		},
	}

	p := &IntelligentModelRoutingPolicy{httpClient: &http.Client{}}
	err := parseParams(params, p)
	if err == nil {
		t.Fatal("Expected error for empty routingRules, got nil")
	}
}

func TestParseParams_MissingRuleName(t *testing.T) {
	params := map[string]interface{}{
		"routingRules": []interface{}{
			map[string]interface{}{
				"context": "Code related",
				"model":   "gpt-4o-mini",
			},
		},
		"defaultModel": "gpt-4o",
		"llmProvider":  "OPENAI",
		"llmEndpoint":  "https://api.openai.com/v1/chat/completions",
		"llmModel":     "gpt-4o-mini",
		"llmApiKey":    "sk-test-key",
		"requestModel": map[string]interface{}{
			"location":   "payload",
			"identifier": "$.model",
		},
	}

	p := &IntelligentModelRoutingPolicy{httpClient: &http.Client{}}
	err := parseParams(params, p)
	if err == nil {
		t.Fatal("Expected error for missing rule name, got nil")
	}
	if !strings.Contains(err.Error(), "name") {
		t.Errorf("Expected error about name, got: %v", err)
	}
}

func TestParseParams_InvalidLLMProvider(t *testing.T) {
	params := map[string]interface{}{
		"routingRules": []interface{}{
			map[string]interface{}{
				"name":    "Coding",
				"context": "Code related",
				"model":   "gpt-4o-mini",
			},
		},
		"defaultModel": "gpt-4o",
		"llmProvider":  "INVALID_PROVIDER",
		"llmEndpoint":  "https://api.openai.com/v1/chat/completions",
		"llmModel":     "gpt-4o-mini",
		"llmApiKey":    "sk-test-key",
		"requestModel": map[string]interface{}{
			"location":   "payload",
			"identifier": "$.model",
		},
	}

	p := &IntelligentModelRoutingPolicy{httpClient: &http.Client{}}
	err := parseParams(params, p)
	if err == nil {
		t.Fatal("Expected error for invalid LLM provider, got nil")
	}
	if !strings.Contains(err.Error(), "llmProvider") {
		t.Errorf("Expected error about llmProvider, got: %v", err)
	}
}

func TestParseParams_AzureOpenAI_NoModelRequired(t *testing.T) {
	params := map[string]interface{}{
		"routingRules": []interface{}{
			map[string]interface{}{
				"name":    "Coding",
				"context": "Code related",
				"model":   "gpt-4o-mini",
			},
		},
		"defaultModel": "gpt-4o",
		"llmProvider":  "AZURE_OPENAI",
		"llmEndpoint":  "https://myresource.openai.azure.com/openai/deployments/gpt-4o/chat/completions",
		"llmApiKey":    "azure-api-key",
		"requestModel": map[string]interface{}{
			"location":   "payload",
			"identifier": "$.model",
		},
	}

	p := &IntelligentModelRoutingPolicy{httpClient: &http.Client{}}
	err := parseParams(params, p)
	if err != nil {
		t.Fatalf("Azure OpenAI should not require llmModel, got: %v", err)
	}
	if p.llmConfig.Provider != "AZURE_OPENAI" {
		t.Errorf("Expected AZURE_OPENAI provider, got %q", p.llmConfig.Provider)
	}
}

func TestParseParams_InvalidRequestModelLocation(t *testing.T) {
	params := map[string]interface{}{
		"routingRules": []interface{}{
			map[string]interface{}{
				"name":    "Coding",
				"context": "Code related",
				"model":   "gpt-4o-mini",
			},
		},
		"defaultModel": "gpt-4o",
		"llmProvider":  "OPENAI",
		"llmEndpoint":  "https://api.openai.com/v1/chat/completions",
		"llmModel":     "gpt-4o-mini",
		"llmApiKey":    "sk-test-key",
		"requestModel": map[string]interface{}{
			"location":   "invalid_location",
			"identifier": "$.model",
		},
	}

	p := &IntelligentModelRoutingPolicy{httpClient: &http.Client{}}
	err := parseParams(params, p)
	if err == nil {
		t.Fatal("Expected error for invalid location, got nil")
	}
}

// Only the payload location is implemented. header, queryParam and pathParam previously
// passed validation and then silently never routed, so they must now be rejected.
func TestParseParams_UnimplementedRequestModelLocationsRejected(t *testing.T) {
	for _, location := range []string{"header", "queryParam", "pathParam"} {
		t.Run(location, func(t *testing.T) {
			params := map[string]interface{}{
				"routingRules": []interface{}{
					map[string]interface{}{
						"name":    "Coding",
						"context": "Code related",
						"model":   "gpt-4o-mini",
					},
				},
				"defaultModel": "gpt-4o",
				"llmProvider":  "OPENAI",
				"llmEndpoint":  "https://api.openai.com/v1/chat/completions",
				"llmModel":     "gpt-4o-mini",
				"llmApiKey":    "sk-test-key",
				"requestModel": map[string]interface{}{
					"location":   location,
					"identifier": "x-model",
				},
			}

			p := &IntelligentModelRoutingPolicy{httpClient: &http.Client{}}
			err := parseParams(params, p)
			if err == nil {
				t.Fatalf("expected %q to be rejected, but parsing succeeded", location)
			}
			if !strings.Contains(err.Error(), "must be 'payload'") {
				t.Fatalf("unexpected error message for %q: %v", location, err)
			}
		})
	}
}

// --- Prompt Construction Tests ---

func TestBuildClassificationPrompt_SingleRule(t *testing.T) {
	rules := []RoutingRule{
		{Name: "Coding", Context: "Code related questions", Model: "gpt-4o-mini"},
	}

	prompt := buildClassificationPrompt(rules, "write a hello world program")

	// Verify the prompt contains all expected sections
	expectedSections := []string{
		"## TASK",
		"Classify the user request into exactly ONE route rule",
		"## ROUTE RULES",
		"- Coding: Code related questions",
		"## ALLOWED RESPONSES",
		"You MUST respond with ONLY one of: Coding, NONE",
		"## STRICT OUTPUT RULES",
		"Output ONLY the route rule name",
		"## USER REQUEST",
		"write a hello world program",
		"## YOUR RESPONSE (single word only):",
	}

	for _, expected := range expectedSections {
		if !strings.Contains(prompt, expected) {
			t.Errorf("Prompt missing expected section: %q\nGot:\n%s", expected, prompt)
		}
	}
}

func TestBuildClassificationPrompt_MultipleRules(t *testing.T) {
	rules := []RoutingRule{
		{Name: "Coding", Context: "Code related questions", Model: "gpt-4o-mini"},
		{Name: "Weather", Context: "Weather forecasts and conditions", Model: "gpt-4o"},
		{Name: "Travel", Context: "Flight booking and travel plans", Model: "claude-3"},
	}

	prompt := buildClassificationPrompt(rules, "what's the weather in Paris")

	// Check all rules appear
	if !strings.Contains(prompt, "- Coding: Code related questions") {
		t.Error("Prompt missing Coding rule")
	}
	if !strings.Contains(prompt, "- Weather: Weather forecasts and conditions") {
		t.Error("Prompt missing Weather rule")
	}
	if !strings.Contains(prompt, "- Travel: Flight booking and travel plans") {
		t.Error("Prompt missing Travel rule")
	}

	// Check allowed responses
	if !strings.Contains(prompt, "Coding, Weather, Travel, NONE") {
		t.Error("Prompt missing proper allowed responses list")
	}
}

func TestBuildPromptComponents(t *testing.T) {
	rules := []RoutingRule{
		{Name: "A", Context: "Context A", Model: "model-a"},
		{Name: "B", Context: "Context B", Model: "model-b"},
	}

	options, names := buildPromptComponents(rules)

	if !strings.Contains(options, "- A: Context A") {
		t.Errorf("Options missing 'A: Context A', got: %q", options)
	}
	if !strings.Contains(options, "- B: Context B") {
		t.Errorf("Options missing 'B: Context B', got: %q", options)
	}

	if names != "A, B" {
		t.Errorf("Expected names 'A, B', got %q", names)
	}
}

func TestBuildPromptComponents_EmptyContext(t *testing.T) {
	rules := []RoutingRule{
		{Name: "TestRule", Context: "", Model: "model-a"},
	}

	options, names := buildPromptComponents(rules)

	// Should not include ": " when context is empty
	if strings.Contains(options, ": ") {
		t.Errorf("Options should not contain ': ' for empty context, got: %q", options)
	}
	if !strings.Contains(options, "- TestRule") {
		t.Errorf("Options missing rule name, got: %q", options)
	}

	if names != "TestRule" {
		t.Errorf("Expected names 'TestRule', got %q", names)
	}
}

// --- Response Validation Tests ---

func TestValidateAndSelectModel_ExactMatch(t *testing.T) {
	p := &IntelligentModelRoutingPolicy{
		routingRules: []RoutingRule{
			{Name: "Coding", Context: "Code related", Model: "gpt-4o-mini"},
			{Name: "Weather", Context: "Weather info", Model: "gpt-4o"},
		},
		defaultModel: "default-model",
	}

	result := p.validateAndSelectTarget("Coding").Model
	if result != "gpt-4o-mini" {
		t.Errorf("Expected 'gpt-4o-mini', got %q", result)
	}
}

func TestValidateAndSelectModel_CaseInsensitive(t *testing.T) {
	p := &IntelligentModelRoutingPolicy{
		routingRules: []RoutingRule{
			{Name: "Coding", Context: "Code related", Model: "gpt-4o-mini"},
		},
		defaultModel: "default-model",
	}

	testCases := []string{"coding", "CODING", "CoDiNg"}
	for _, tc := range testCases {
		result := p.validateAndSelectTarget(tc).Model
		if result != "gpt-4o-mini" {
			t.Errorf("Case-insensitive match failed for %q: expected 'gpt-4o-mini', got %q", tc, result)
		}
	}
}

func TestValidateAndSelectModel_NONE(t *testing.T) {
	p := &IntelligentModelRoutingPolicy{
		routingRules: []RoutingRule{
			{Name: "Coding", Context: "Code related", Model: "gpt-4o-mini"},
		},
		defaultModel: "default-model",
	}

	result := p.validateAndSelectTarget("NONE").Model
	if result != "default-model" {
		t.Errorf("Expected 'default-model' for NONE response, got %q", result)
	}

	// Case-insensitive NONE
	result = p.validateAndSelectTarget("none").Model
	if result != "default-model" {
		t.Errorf("Expected 'default-model' for 'none' response, got %q", result)
	}
}

func TestValidateAndSelectModel_EmptyResponse(t *testing.T) {
	p := &IntelligentModelRoutingPolicy{
		routingRules: []RoutingRule{
			{Name: "Coding", Context: "Code related", Model: "gpt-4o-mini"},
		},
		defaultModel: "default-model",
	}

	result := p.validateAndSelectTarget("").Model
	if result != "default-model" {
		t.Errorf("Expected 'default-model' for empty response, got %q", result)
	}
}

func TestValidateAndSelectModel_WhitespaceResponse(t *testing.T) {
	p := &IntelligentModelRoutingPolicy{
		routingRules: []RoutingRule{
			{Name: "Coding", Context: "Code related", Model: "gpt-4o-mini"},
		},
		defaultModel: "default-model",
	}

	// Response with whitespace around the rule name should still match
	result := p.validateAndSelectTarget("  Coding  ").Model
	if result != "gpt-4o-mini" {
		t.Errorf("Expected 'gpt-4o-mini' for whitespace-padded response, got %q", result)
	}
}

func TestValidateAndSelectModel_NoMatch(t *testing.T) {
	p := &IntelligentModelRoutingPolicy{
		routingRules: []RoutingRule{
			{Name: "Coding", Context: "Code related", Model: "gpt-4o-mini"},
		},
		defaultModel: "default-model",
	}

	result := p.validateAndSelectTarget("UnknownRule").Model
	if result != "default-model" {
		t.Errorf("Expected 'default-model' for unknown rule, got %q", result)
	}
}

// --- LLM Client Integration Test (with mock server) ---

func TestCallLLM_SuccessfulClassification(t *testing.T) {
	// Create a mock LLM server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify request structure
		if r.Header.Get("Content-Type") != "application/json" {
			t.Error("Expected Content-Type: application/json")
		}
		if r.Header.Get("Authorization") != "Bearer test-key" {
			t.Error("Expected Bearer token auth")
		}

		var reqBody chatCompletionRequest
		if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
			t.Fatalf("Failed to decode request body: %v", err)
		}

		if reqBody.Model != "gpt-4o-mini" {
			t.Errorf("Expected model 'gpt-4o-mini', got %q", reqBody.Model)
		}

		if len(reqBody.Messages) != 2 {
			t.Errorf("Expected 2 messages, got %d", len(reqBody.Messages))
		}

		// Return mock response
		resp := chatCompletionResponse{
			Choices: []struct {
				Message struct {
					Content string `json:"content"`
				} `json:"message"`
			}{
				{Message: struct {
					Content string `json:"content"`
				}{Content: "Coding"}},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	p := &IntelligentModelRoutingPolicy{
		httpClient: server.Client(),
		llmConfig: LLMClientConfig{
			Provider: "OPENAI",
			Endpoint: server.URL,
			Model:    "gpt-4o-mini",
			APIKey:   "test-key",
		},
	}

	result, err := p.callLLM(t.Context(), "system prompt", "user prompt")
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if result != "Coding" {
		t.Errorf("Expected 'Coding', got %q", result)
	}
}

func TestCallLLM_AzureAuth(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Azure uses api-key header instead of Bearer
		if r.Header.Get("api-key") != "azure-key" {
			t.Error("Expected api-key header for Azure")
		}
		if r.Header.Get("Authorization") != "" {
			t.Error("Should not have Authorization header for Azure")
		}

		resp := chatCompletionResponse{
			Choices: []struct {
				Message struct {
					Content string `json:"content"`
				} `json:"message"`
			}{
				{Message: struct {
					Content string `json:"content"`
				}{Content: "Weather"}},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	p := &IntelligentModelRoutingPolicy{
		httpClient: server.Client(),
		llmConfig: LLMClientConfig{
			Provider: "AZURE_OPENAI",
			Endpoint: server.URL,
			APIKey:   "azure-key",
		},
	}

	result, err := p.callLLM(t.Context(), "system prompt", "user prompt")
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if result != "Weather" {
		t.Errorf("Expected 'Weather', got %q", result)
	}
}

func TestCallLLM_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error": "internal server error"}`))
	}))
	defer server.Close()

	p := &IntelligentModelRoutingPolicy{
		httpClient: server.Client(),
		llmConfig: LLMClientConfig{
			Provider: "OPENAI",
			Endpoint: server.URL,
			Model:    "gpt-4o-mini",
			APIKey:   "test-key",
		},
	}

	_, err := p.callLLM(t.Context(), "system prompt", "user prompt")
	if err == nil {
		t.Fatal("Expected error for server error, got nil")
	}
	if !strings.Contains(err.Error(), "500") {
		t.Errorf("Expected error to mention 500 status, got: %v", err)
	}
}

func TestCallLLM_EmptyChoices(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := chatCompletionResponse{Choices: nil}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	p := &IntelligentModelRoutingPolicy{
		httpClient: server.Client(),
		llmConfig: LLMClientConfig{
			Provider: "OPENAI",
			Endpoint: server.URL,
			Model:    "gpt-4o-mini",
			APIKey:   "test-key",
		},
	}

	_, err := p.callLLM(t.Context(), "system prompt", "user prompt")
	if err == nil {
		t.Fatal("Expected error for empty choices, got nil")
	}
}
