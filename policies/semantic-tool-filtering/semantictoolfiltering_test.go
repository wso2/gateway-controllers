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
 */

package semantictoolfiltering

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	embeddingproviders "github.com/wso2/api-platform/sdk/ai/embeddings"
	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

const (
	testAzureEndpoint = "https://res.openai.azure.com/openai/deployments/emb/embeddings?api-version=2024-10-21"
	testIdentityID    = "00000000-0000-0000-0000-000000000001"
)

// azureParams is a gateway with an Azure OpenAI embedding deployment and a key, plus extra.
func azureParams(extra map[string]interface{}) map[string]interface{} {
	params := map[string]interface{}{
		"embeddingProvider": "AZURE_OPENAI",
		"embeddingEndpoint": testAzureEndpoint,
		"apiKey":            "gateway-key",
		"selectionMode":     SelectionModeTopK,
	}
	for k, v := range extra {
		params[k] = v
	}
	return params
}

func TestGetPolicyErrorCarriesTheReason(t *testing.T) {
	params := azureParams(nil)
	delete(params, "embeddingEndpoint")
	if _, err := GetPolicy(policy.PolicyMetadata{}, params); err == nil ||
		!strings.Contains(err.Error(), "invalid embedding config: 'embeddingEndpoint' is required") {
		t.Fatalf("expected the missing endpoint to be named, got %v", err)
	}

	if _, err := GetPolicy(policy.PolicyMetadata{}, azureParams(map[string]interface{}{"limit": 30})); err == nil ||
		!strings.Contains(err.Error(), "invalid params: 'limit' must be between 0 and 20") {
		t.Fatalf("expected the bad limit to be named, got %v", err)
	}
}

func TestParseEmbeddingConfigIdentityModeNeedsNoKey(t *testing.T) {
	params := azureParams(map[string]interface{}{
		"azureAuth": map[string]interface{}{"authenticationType": "workload-identity"},
	})
	delete(params, "apiKey")
	p := &SemanticToolFilteringPolicy{}
	if err := parseEmbeddingConfig(params, p); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	c := p.embeddingConfig
	if c.AuthenticationType != "workload-identity" || c.TokenScope != embeddingproviders.DefaultTokenScope {
		t.Fatalf("identity not passed on: %+v", c)
	}
	if c.APIKey != "" || c.AuthHeaderName != "" {
		t.Fatalf("an identity mode must not carry a key: %+v", c)
	}
	if p.auth.typ != "workload-identity" {
		t.Fatalf("expected p.auth.typ workload-identity, got %q", p.auth.typ)
	}
}

func TestParseEmbeddingConfigIdentityModeDropsTheKey(t *testing.T) {
	p := &SemanticToolFilteringPolicy{}
	err := parseEmbeddingConfig(azureParams(map[string]interface{}{
		"azureAuth": map[string]interface{}{"authenticationType": "managed-identity", "clientId": testIdentityID},
	}), p)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	c := p.embeddingConfig
	if c.APIKey != "" || c.AuthHeaderName != "" {
		t.Fatalf("the gateway's key must not be passed on in an identity mode: %+v", c)
	}
	if c.AuthenticationType != "managed-identity" || c.ClientID != testIdentityID {
		t.Fatalf("identity not passed on: %+v", c)
	}
}

func TestParseEmbeddingConfigAPIKeyModeStillNeedsAKey(t *testing.T) {
	params := azureParams(nil)
	delete(params, "apiKey")
	if err := parseEmbeddingConfig(params, &SemanticToolFilteringPolicy{}); err == nil ||
		!strings.Contains(err.Error(), "'apiKey' is required") {
		t.Fatalf("expected the key to be required, got %v", err)
	}
}

func TestParseEmbeddingConfigAPIKeyModeIgnoresLeftoverIdentityFields(t *testing.T) {
	p := &SemanticToolFilteringPolicy{}
	err := parseEmbeddingConfig(azureParams(map[string]interface{}{
		"azureAuth": map[string]interface{}{"authenticationType": "api-key", "clientId": testIdentityID, "scope": "x"},
	}), p)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	c := p.embeddingConfig
	if c.AuthenticationType != "api-key" || c.ClientID != "" || c.TokenScope != "" ||
		c.APIKey != "gateway-key" || c.AuthHeaderName != "api-key" {
		t.Fatalf("unexpected config: %+v", c)
	}
}

func TestParseEmbeddingConfigRefusesAnUnlistedType(t *testing.T) {
	err := parseEmbeddingConfig(azureParams(map[string]interface{}{
		"embeddingAllowedAuthTypes": []interface{}{"api-key"},
		"azureAuth":                 map[string]interface{}{"authenticationType": "container-apps"},
	}), &SemanticToolFilteringPolicy{})
	if err == nil || !strings.Contains(err.Error(), `authentication type "container-apps" is not allowed on this gateway`) {
		t.Fatalf("expected container-apps to be refused, got %v", err)
	}
}

func TestGetPolicyErrorNamesTheEndpointNotTheKey(t *testing.T) {
	_, err := GetPolicy(policy.PolicyMetadata{}, azureParams(map[string]interface{}{
		"apiKey":                    "secret-key-value-123",
		"embeddingAllowedEndpoints": []interface{}{"https://other.openai.azure.com"},
	}))
	if err == nil || !strings.Contains(err.Error(), "invalid embedding config:") ||
		!strings.Contains(err.Error(), "is not allowed on this gateway") || !strings.Contains(err.Error(), testAzureEndpoint) {
		t.Fatalf("expected the endpoint to be refused by name, got %v", err)
	}
	if strings.Contains(err.Error(), "secret-key-value-123") {
		t.Fatalf("the error must never carry the key: %v", err)
	}
}

func TestGetPolicyRejectsAnIdentityWithANonAzureProvider(t *testing.T) {
	_, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{
		"embeddingProvider": "OPENAI",
		"embeddingModel":    "m",
		"embeddingEndpoint": "https://api.openai.com/v1/embeddings",
		"azureAuth":         map[string]interface{}{"authenticationType": "workload-identity"},
		"selectionMode":     SelectionModeTopK,
	})
	if err == nil || !strings.Contains(err.Error(), "only supported for the AZURE_OPENAI embedding provider") {
		t.Fatalf("expected the identity to be refused for OPENAI, got %v", err)
	}
}

func TestGetPolicyFailsWhenTheContainerAppIdentityIsUnavailable(t *testing.T) {
	t.Setenv("IDENTITY_ENDPOINT", "")
	t.Setenv("IDENTITY_HEADER", "")
	_, err := GetPolicy(policy.PolicyMetadata{}, azureParams(map[string]interface{}{
		"azureAuth": map[string]interface{}{"authenticationType": "container-apps"},
	}))
	if err == nil || !strings.Contains(err.Error(), `authentication type "container-apps" can't be used`) ||
		!strings.Contains(err.Error(), "IDENTITY_ENDPOINT") {
		t.Fatalf("expected the missing identity to fail the build, got %v", err)
	}
}

// A slow embedding request must stop at the policy's 5 s timeout, so the policy can fall back
// before the gateway gives up on the whole request.
func TestEmbeddingRequestStopsAtTheTimeout(t *testing.T) {
	const timeout = 5 * time.Second
	done := make(chan struct{})
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-time.After(timeout + 2*time.Second):
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"data":[{"embedding":[0.1,0.2,0.3]}]}`))
		case <-done:
		}
	}))
	defer slow.Close()
	defer close(done)

	got, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{
		"embeddingProvider": "OPENAI",
		"embeddingModel":    "text-embedding-3-small",
		"embeddingEndpoint": slow.URL,
		"apiKey":            "k",
		"selectionMode":     SelectionModeTopK,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	start := time.Now()
	_, err = got.(*SemanticToolFilteringPolicy).embeddingProvider.GetEmbedding("weather in London")
	elapsed := time.Since(start)
	if err == nil {
		t.Fatalf("expected the request to stop at %s, but it waited %s for the answer", timeout, elapsed.Round(100*time.Millisecond))
	}
	if elapsed > timeout+time.Second {
		t.Fatalf("expected the request to stop at about %s, it stopped after %s", timeout, elapsed.Round(100*time.Millisecond))
	}
}

func TestGetPolicyAPIKeyModeIsUnchanged(t *testing.T) {
	got, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{
		"embeddingProvider": "OPENAI",
		"embeddingModel":    "text-embedding-3-small",
		"embeddingEndpoint": "https://api.openai.com/v1/embeddings",
		"apiKey":            "k",
		"selectionMode":     SelectionModeTopK,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	c := got.(*SemanticToolFilteringPolicy).embeddingConfig
	if c.AuthHeaderName != "Authorization" || c.APIKey != "k" {
		t.Fatalf("api-key mode changed: %+v", c)
	}
}
