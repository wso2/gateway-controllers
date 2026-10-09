/*
 * Copyright (c) 2026, WSO2 LLC. (http://www.wso2.org) All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package azurellmcost

import (
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/wso2/api-platform/sdk/ai/llmusage"
	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
	"gopkg.in/yaml.v3"
)

var testPricingMap map[string]ModelPricing

func init() {
	_, filename, _, _ := runtime.Caller(0)
	pm, err := loadPricingFromFile(filepath.Join(filepath.Dir(filename), "testdata", "model_prices.json"))
	if err != nil {
		panic("failed to load pricing fixture: " + err.Error())
	}
	testPricingMap = pm
}

func almostEqual(a, b float64) bool { return math.Abs(a-b) < 1e-12 }

// ctxFor stores the shipped template and returns a context naming it. The
// handle is the template's own metadata.name, which is what the kernel records.
// apiContext is what the policy trims off the request path.
func ctxFor(t *testing.T, file, apiContext string) *policy.SharedContext {
	t.Helper()
	_, filename, _, _ := runtime.Caller(0)
	raw, err := os.ReadFile(filepath.Join(filepath.Dir(filename),
		"testdata", "templates", file))
	if err != nil {
		t.Fatalf("read template %s: %v", file, err)
	}
	var doc struct {
		Metadata struct {
			Name string `yaml:"name"`
		} `yaml:"metadata"`
		Spec map[string]interface{} `yaml:"spec"`
	}
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse template %s: %v", file, err)
	}
	handle := doc.Metadata.Name
	b, _ := json.Marshal(doc.Spec)
	var spec map[string]interface{}
	_ = json.Unmarshal(b, &spec)

	store := policy.GetLazyResourceStoreInstance()
	if err := store.StoreResource(&policy.LazyResource{
		ID: handle, ResourceType: llmusage.ResourceTypeLLMProviderTemplate, Resource: spec,
	}); err != nil {
		t.Fatalf("store template: %v", err)
	}
	t.Cleanup(func() { _ = store.RemoveResourceByIDAndType(handle, llmusage.ResourceTypeLLMProviderTemplate) })

	return &policy.SharedContext{
		APIContext: apiContext,
		Metadata:   map[string]interface{}{llmusage.MetadataTemplateHandle: handle},
	}
}

func newPolicy(region azureRegion, mappings map[string]string) *AzureLLMCostPolicy {
	m := make(map[string]deploymentMapping, len(mappings))
	for k, v := range mappings {
		m[k] = deploymentMapping{model: v, region: region}
	}
	return &AzureLLMCostPolicy{pricingMap: testPricingMap, modelMappings: m}
}

// Real captured payloads from the two Azure OpenAI API surfaces. Deployment
// "apim-gpt-4.1" resolves to gpt-4.1-2025-04-14 (input 2e-06, output 8e-06).
const (
	chatCompletionsResponse = `{
	  "object": "chat.completion",
	  "model": "gpt-4.1-2025-04-14",
	  "service_tier": "default",
	  "usage": {
	    "completion_tokens": 11,
	    "completion_tokens_details": {"audio_tokens":0,"reasoning_tokens":0},
	    "prompt_tokens": 10,
	    "prompt_tokens_details": {"audio_tokens":0,"cached_tokens":0},
	    "total_tokens": 21
	  }
	}`

	responsesAPIResponse = `{
	  "object": "response",
	  "status": "completed",
	  "model": "apim-gpt-4.1",
	  "service_tier": "default",
	  "usage": {
	    "input_tokens": 10,
	    "input_tokens_details": {"cached_tokens": 0},
	    "output_tokens": 12,
	    "output_tokens_details": {"reasoning_tokens": 0},
	    "total_tokens": 22
	  }
	}`
)

// Legacy surface: deployment lives in the URL and the body carries no "model".
// The response reports the resolved model, so this prices with no config.
func TestCompliance_Legacy_ChatCompletions_NoConfig(t *testing.T) {
	p := newPolicy(regionGlobalStandard, nil)
	sc := ctxFor(t, "azureopenai-template.yaml", "/az-01")
	request := `{"messages":[{"role":"user","content":"Say hello!"}]}`
	path := "/az-01/openai/deployments/apim-gpt-4.1/chat/completions?api-version=2024-02-01"

	result := p.computeCost(sc, []byte(chatCompletionsResponse), []byte(request), path)
	if !result.calculated {
		t.Fatal("legacy chat completions must price with no configuration")
	}
	if result.modelKey != "azure/gpt-4.1-2025-04-14" {
		t.Errorf("expected the resolved model, got %q", result.modelKey)
	}
	if want := 10*2e-6 + 11*8e-6; !almostEqual(result.cost, want) {
		t.Errorf("got %v, want %v", result.cost, want)
	}
	if result.usage.TotalInputTokens != 10 || result.usage.OutputTokens != 11 {
		t.Errorf("unexpected usage: %+v", result.usage)
	}
}

// v1 surface: deployment lives in the request body's "model".
func TestCompliance_V1_ChatCompletions_NoConfig(t *testing.T) {
	p := newPolicy(regionGlobalStandard, nil)
	sc := ctxFor(t, "azureopenai-template.yaml", "/az-01")
	request := `{"messages":[],"model":"apim-gpt-4.1"}`

	result := p.computeCost(sc, []byte(chatCompletionsResponse), []byte(request), "/az-01/chat/completions")
	if !result.calculated || result.modelKey != "azure/gpt-4.1-2025-04-14" {
		t.Fatalf("expected the resolved model, got %q calculated=%v", result.modelKey, result.calculated)
	}
	if want := 10*2e-6 + 11*8e-6; !almostEqual(result.cost, want) {
		t.Errorf("got %v, want %v", result.cost, want)
	}
}

func TestCompliance_V1_Responses_UnpricedWithoutMapping(t *testing.T) {
	p := newPolicy(regionGlobalStandard, nil)
	sc := ctxFor(t, "azureopenai-template.yaml", "/az-01")
	request := `{"input":[],"model":"apim-gpt-4.1"}`

	if result := p.computeCost(sc, []byte(responsesAPIResponse), []byte(request), "/az-01/responses"); result.calculated {
		t.Error("expected unpriced: /responses reports only the deployment name")
	}
}

// With a mapping, /responses prices off input_tokens/output_tokens.
func TestCompliance_V1_Responses_PricedWithMapping(t *testing.T) {
	p := newPolicy(regionGlobalStandard, map[string]string{"apim-gpt-4.1": "gpt-4.1-2025-04-14"})
	sc := ctxFor(t, "azureopenai-template.yaml", "/az-01")
	request := `{"input":[],"model":"apim-gpt-4.1"}`

	result := p.computeCost(sc, []byte(responsesAPIResponse), []byte(request), "/az-01/responses")
	if !result.calculated {
		t.Fatal("expected /responses to price via the model mapping")
	}
	if result.modelKey != "azure/gpt-4.1-2025-04-14" {
		t.Errorf("unexpected model key %q", result.modelKey)
	}
	if want := 10*2e-6 + 12*8e-6; !almostEqual(result.cost, want) {
		t.Errorf("got %v, want %v", result.cost, want)
	}
	if result.usage.TotalInputTokens != 10 || result.usage.OutputTokens != 12 {
		t.Errorf("input_tokens/output_tokens not read: %+v", result.usage)
	}
}

// The mapping must not displace the more precise model a chat-completions
// response reports.
func TestCompliance_V1_MappingMustNotDisplaceResolvedModel(t *testing.T) {
	p := newPolicy(regionGlobalStandard, map[string]string{"apim-gpt-4o": "gpt-4o"})
	sc := ctxFor(t, "azureopenai-template.yaml", "/az-01")
	response := `{"model":"gpt-4o-2024-05-13","service_tier":"default",
		"usage":{"prompt_tokens":1000,"completion_tokens":100,"prompt_tokens_details":{"cached_tokens":0}}}`
	request := `{"messages":[],"model":"apim-gpt-4o"}`

	result := p.computeCost(sc, []byte(response), []byte(request), "/az-01/chat/completions")
	if result.modelKey != "azure/gpt-4o-2024-05-13" {
		t.Fatalf("mapping displaced the reported model: got %q", result.modelKey)
	}
	if want := 1000*5e-6 + 100*1.5e-5; !almostEqual(result.cost, want) {
		t.Errorf("got %v, want %v", result.cost, want)
	}
}

// The mapping still wins when the reported name IS the deployment.
func TestCompliance_MappingStillCorrectsCollidingDeploymentName(t *testing.T) {
	p := newPolicy(regionGlobalStandard, map[string]string{"gpt-4o": "gpt-4.1-2025-04-14"})
	sc := ctxFor(t, "azureopenai-template.yaml", "/az-01")
	response := `{"model":"gpt-4o","usage":{"input_tokens":100,"output_tokens":50}}`

	result := p.computeCost(sc, []byte(response), nil, "/az-01/responses")
	if result.modelKey != "azure/gpt-4.1-2025-04-14" {
		t.Errorf("expected the mapping to correct the colliding name, got %q", result.modelKey)
	}
}

func TestCompliance_Legacy_Responses_404Body(t *testing.T) {
	p := newPolicy(regionGlobalStandard, map[string]string{"apim-gpt-4.1": "gpt-4.1-2025-04-14"})
	sc := ctxFor(t, "azureopenai-template.yaml", "/az-01")
	body := `{"error":{"code":"404","message":"Resource not found"}}`

	result := p.computeCost(sc, []byte(body), nil, "/az-01/openai/deployments/apim-gpt-4.1/responses")
	if result.calculated || result.cost != 0 {
		t.Errorf("a 404 error body must not be priced, got %+v", result)
	}
}

// A route naming neither Azure template is left unpriced.
func TestNonAzureTemplateIsUnpriced(t *testing.T) {
	p := newPolicy(regionGlobalStandard, nil)
	sc := ctxFor(t, "azureopenai-template.yaml", "/az-01")
	sc.Metadata[llmusage.MetadataTemplateHandle] = "not-an-azure-template"

	if result := p.computeCost(sc, []byte(chatCompletionsResponse), nil, "/chat/completions"); result.calculated {
		t.Error("expected a non-Azure template to be left unpriced")
	}
}

// Streamed chat completions: Azure closes with a content-filter chunk carrying
// a null usage, which must not erase the counts.
func TestStreamed_ChatCompletions(t *testing.T) {
	p := newPolicy(regionGlobalStandard, nil)
	sc := ctxFor(t, "azureopenai-template.yaml", "/az-01")
	body := []byte(`data: {"model":"gpt-4.1-2025-04-14","usage":null}` + "\n\n" +
		`data: {"model":"gpt-4.1-2025-04-14","usage":{"prompt_tokens":10,"completion_tokens":11,"total_tokens":21}}` + "\n\n" +
		`data: {"model":"","usage":null}` + "\n\ndata: [DONE]\n")

	result := p.computeCost(sc, body, nil, "/az-01/chat/completions")
	if !result.calculated {
		t.Fatal("a streamed chat completion must price")
	}
	if want := 10*2e-6 + 11*8e-6; !almostEqual(result.cost, want) {
		t.Errorf("got %v, want %v", result.cost, want)
	}
}

// The Responses API nests the completed response one level down when streamed.
func TestStreamed_Responses(t *testing.T) {
	p := newPolicy(regionGlobalStandard, map[string]string{"apim-gpt-4.1": "gpt-4.1-2025-04-14"})
	sc := ctxFor(t, "azureopenai-template.yaml", "/az-01")
	body := []byte("event: response.completed\ndata: " +
		`{"type":"response.completed","response":{"model":"apim-gpt-4.1","usage":{"input_tokens":10,"output_tokens":12,"total_tokens":22}}}` + "\n\n")

	result := p.computeCost(sc, body, nil, "/az-01/responses")
	if !result.calculated {
		t.Fatal("a streamed /responses must price")
	}
	if want := 10*2e-6 + 12*8e-6; !almostEqual(result.cost, want) {
		t.Errorf("got %v, want %v", result.cost, want)
	}
}

// Foundry serves the OpenAI models, catalogued only under azure/.
func TestFoundry_FallsBackToAzureNamespace(t *testing.T) {
	p := newPolicy(regionGlobalStandard, nil)
	sc := ctxFor(t, "azureaifoundry-template.yaml", "/az-01")

	result := p.computeCost(sc, []byte(chatCompletionsResponse), nil, "/az-01/chat/completions")
	if !result.calculated || result.modelKey != "azure/gpt-4.1-2025-04-14" {
		t.Fatalf("expected the azure/ fallback, got %q calculated=%v", result.modelKey, result.calculated)
	}
}

// The deployment's tier selects the pricing key prefix.
func TestTierFromDeploymentRegion(t *testing.T) {
	p := newPolicy(regionEU, map[string]string{"dep-eu": "gpt-4o-2024-08-06"})
	sc := ctxFor(t, "azureopenai-template.yaml", "/az-01")
	body := `{"model":"dep-eu","usage":{"prompt_tokens":100,"completion_tokens":50}}`

	result := p.computeCost(sc, []byte(body), nil, "/az-01/openai/deployments/dep-eu/chat/completions")
	if result.modelKey != "azure/eu/gpt-4o-2024-08-06" {
		t.Errorf("expected the eu tier key, got %q", result.modelKey)
	}
}

// Priority is read from the template's serviceTier valueMap.
func TestPriorityTierRates(t *testing.T) {
	p := newPolicy(regionGlobalStandard, nil)
	standard := `{"model":"gpt-4.1-2025-04-14","usage":{"prompt_tokens":1000,"completion_tokens":100}}`
	priority := `{"model":"gpt-4.1-2025-04-14","service_tier":"priority","usage":{"prompt_tokens":1000,"completion_tokens":100}}`

	a := p.computeCost(ctxFor(t, "azureopenai-template.yaml", "/az-01"), []byte(standard), nil, "/az-01/chat/completions")
	b := p.computeCost(ctxFor(t, "azureopenai-template.yaml", "/az-01"), []byte(priority), nil, "/az-01/chat/completions")
	if !a.calculated || !b.calculated {
		t.Fatal("both must price")
	}
	if !b.usage.IsPriority {
		t.Error("the priority tier did not reach the policy")
	}
}

// A provider that allows everything declares no resources, so the route's own
// path is "/*". The resource is taken from the URL instead.
func TestResponsesOnCatchAllRoute(t *testing.T) {
	p := newPolicy(regionGlobalStandard, map[string]string{"apim-gpt-4.1": "gpt-4.1-2025-04-14"})
	sc := ctxFor(t, "azureopenai-template.yaml", "/az-openai-01")
	sc.OperationPath = "/*"

	result := p.computeCost(sc, []byte(responsesAPIResponse), nil, "/az-openai-01/responses")
	if !result.calculated {
		t.Fatal("a catch-all route must still price /responses")
	}
	if want := 10*2e-6 + 12*8e-6; !almostEqual(result.cost, want) {
		t.Errorf("got %v, want %v", result.cost, want)
	}
}

func TestResourcePathFrom(t *testing.T) {
	tests := []struct{ requestPath, apiContext, apiVersion, want string }{
		{"/az-01/responses", "/az-01", "v1.0", "/responses"},
		{"/az-01/responses?api-version=2024-02-01", "/az-01", "v1.0", "/responses"},
		{"/responses", "/", "v1.0", "/responses"},
		{"/az/v1.0/responses", "/az/$version", "v1.0", "/responses"},
		{"/az-01/openai/deployments/d/chat/completions", "/az-01", "v1.0", "/openai/deployments/d/chat/completions"},
	}
	for _, tt := range tests {
		sc := &policy.SharedContext{APIContext: tt.apiContext, APIVersion: tt.apiVersion}
		if got := resourcePathFrom(sc, tt.requestPath); got != tt.want {
			t.Errorf("resourcePathFrom(%q, ctx=%q) = %q, want %q",
				tt.requestPath, tt.apiContext, got, tt.want)
		}
	}
}
