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
	"fmt"
	"testing"
)

// The gpt-5.6-sol and Llama-3.3 fixture entries carry Azure Retail Prices API
// meter values, so each expected cost below is Azure's own arithmetic.

func TestParseServiceTier(t *testing.T) {
	for in, want := range map[string]serviceTier{
		"priority": serviceTierPriority,
		"flex":     serviceTierFlex,
		"default":  serviceTierStandard,
		"standard": serviceTierStandard,
		"auto":     serviceTierStandard,
		"":         serviceTierStandard,
	} {
		if got := parseServiceTier(in); got != want {
			t.Errorf("parseServiceTier(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNormalizeUsage_FlexAndCacheWrites(t *testing.T) {
	tests := []struct {
		name string
		body string
		want Usage
	}{
		{
			name: "flex service tier",
			body: `{"model":"gpt-5.6-sol","service_tier":"flex","usage":{
				"prompt_tokens":100,"completion_tokens":50}}`,
			want: Usage{TotalInputTokens: 100, OutputTokens: 50, Tier: serviceTierFlex},
		},
		{
			name: "chat completions reports cache writes inside prompt_tokens",
			body: `{"model":"gpt-5.6-sol","usage":{
				"prompt_tokens":10000,"completion_tokens":500,
				"prompt_tokens_details":{"cached_tokens":4000,"cache_write_tokens":2000}}}`,
			want: Usage{TotalInputTokens: 10000, OutputTokens: 500, CachedReadTokens: 4000, CacheWriteTokens: 2000},
		},
		{
			name: "responses API reports cache writes inside input_tokens",
			body: `{"model":"sol-prod","usage":{
				"input_tokens":10000,"output_tokens":500,
				"input_tokens_details":{"cached_tokens":4000,"cache_write_tokens":2000}}}`,
			want: Usage{TotalInputTokens: 10000, OutputTokens: 500, CachedReadTokens: 4000, CacheWriteTokens: 2000},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := normalizeUsage([]byte(tc.body))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Errorf("got  %+v\nwant %+v", got, tc.want)
			}
		})
	}
}

// Every billed category of a GPT-5.6 request moves with the tier: input, cached
// input, cache writes and output each have their own meter per tier.
func TestComputeCost_GPT56TiersAndCacheWrites(t *testing.T) {
	p := newPolicy(regionGlobalStandard, nil)
	const M = 1e-6
	usage := `"usage":{"prompt_tokens":%d,"completion_tokens":500,
		"prompt_tokens_details":{"cached_tokens":4000,"cache_write_tokens":2000}}`
	tests := []struct {
		name   string
		tier   string
		prompt int
		want   float64
	}{
		{"standard", "default", 10_000, 4000*4*M + 4000*0.4*M + 2000*5*M + 500*20*M},
		{"priority", "priority", 10_000, 4000*8*M + 4000*0.8*M + 2000*10*M + 500*40*M},
		{"flex", "flex", 10_000, 4000*2*M + 4000*0.2*M + 2000*2.5*M + 500*10*M},
		{"long context", "default", 300_000, 294_000*8*M + 4000*0.8*M + 2000*10*M + 500*30*M},
		{"long context priority", "priority", 300_000, 294_000*16*M + 4000*1.6*M + 2000*20*M + 500*60*M},
		{"long context flex", "flex", 300_000, 294_000*4*M + 4000*0.4*M + 2000*5*M + 500*15*M},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			body := `{"model":"gpt-5.6-sol","service_tier":"` + tc.tier + `",` +
				fmt.Sprintf(usage, tc.prompt) + `}`
			result := p.computeCost([]byte(body), nil, openAIPath, templateAzureOpenAI)
			if !result.calculated || !almostEqual(result.cost, tc.want) {
				t.Errorf("got %v (calculated=%v), want %v", result.cost, result.calculated, tc.want)
			}
		})
	}
}

// A flex request on a model without flex rates keeps the standard rates rather
// than going unpriced, and a long-context flex request without the combined
// rates falls back to the long-context rates.
func TestResolveRates_FlexFallbacks(t *testing.T) {
	p, _, _ := lookupPricingWithKey(testPricingMap, "gpt-5.4", namespacesFor(templateAzureOpenAI, regionGlobalStandard))
	if r := resolveRates(1000, serviceTierFlex, p); !almostEqual(r.input, 2.5e-6) || !almostEqual(r.output, 1.5e-5) {
		t.Errorf("expected base rates, got input=%v output=%v", r.input, r.output)
	}
	if r := resolveRates(300_000, serviceTierFlex, p); !almostEqual(r.input, 5e-6) || !almostEqual(r.output, 2.25e-5) {
		t.Errorf("expected above-272k rates, got input=%v output=%v", r.input, r.output)
	}
}

// Azure bills cached and written tokens of a model with no cache meter as
// ordinary input. They must never come out free.
func TestComputeCost_MissingCacheRatesBillAsInput(t *testing.T) {
	p := newPolicy(regionGlobalStandard, nil)
	body := []byte(`{"model":"Llama-3.3-70B-Instruct","usage":{"prompt_tokens":1000,"completion_tokens":200,
		"prompt_tokens_details":{"cached_tokens":400,"cache_write_tokens":100}}}`)
	result := p.computeCost(body, nil, foundryPath, templateAzureAI)
	want := 1000*7.1e-7 + 200*7.1e-7
	if !result.calculated || !almostEqual(result.cost, want) {
		t.Errorf("got %v (calculated=%v), want %v", result.cost, result.calculated, want)
	}
}

// A Foundry-native model on a Data Zone deployment bills at its Data Zone rate.
func TestComputeCost_FoundryDataZoneDeploymentTier(t *testing.T) {
	body := []byte(`{"model":"Llama-3.3-70B-Instruct","usage":{"prompt_tokens":1000,"completion_tokens":200}}`)

	us := newPolicy(regionUS, map[string]string{"llama-us": "Llama-3.3-70B-Instruct"})
	usRes := us.computeCost(body, []byte(`{"model":"llama-us"}`), foundryPath, templateAzureAI)
	global := newPolicy(regionGlobalStandard, map[string]string{"llama-gl": "Llama-3.3-70B-Instruct"})
	glRes := global.computeCost(body, []byte(`{"model":"llama-gl"}`), foundryPath, templateAzureAI)

	if usRes.modelKey != "azure_ai/us/llama-3.3-70b-instruct" {
		t.Errorf("Data Zone deployment resolved to %q", usRes.modelKey)
	}
	if glRes.modelKey != "azure_ai/llama-3.3-70b-instruct" {
		t.Errorf("Global deployment resolved to %q", glRes.modelKey)
	}
	if want := 1200 * 7.81e-7; !almostEqual(usRes.cost, want) {
		t.Errorf("Data Zone cost %v, want %v", usRes.cost, want)
	}
	if want := 1200 * 7.1e-7; !almostEqual(glRes.cost, want) {
		t.Errorf("Global cost %v, want %v", glRes.cost, want)
	}
}

// Provisioned deployments bill reserved capacity by the hour, so no per-token
// cost is reported, whichever way the deployment is named.
func TestComputeCost_ProvisionedDeploymentNotPriced(t *testing.T) {
	p := &AzureLLMCostPolicy{pricingMap: testPricingMap, modelMappings: map[string]deploymentMapping{
		"ptu-4o": {model: "gpt-4o-2024-08-06", region: regionProvisioned},
	}}
	body := []byte(`{"model":"gpt-4o-2024-08-06","usage":{"prompt_tokens":1000,"completion_tokens":200}}`)

	if res := p.computeCost(body, []byte(`{"model":"ptu-4o"}`), openAIPath, templateAzureOpenAI); res.calculated || res.cost != 0 {
		t.Errorf("request-body deployment: got %v (calculated=%v), want unpriced", res.cost, res.calculated)
	}
	if res := p.computeCost(body, nil, "/openai/deployments/ptu-4o/chat/completions", templateAzureOpenAI); res.calculated || res.cost != 0 {
		t.Errorf("path deployment: got %v (calculated=%v), want unpriced", res.cost, res.calculated)
	}
	// The same model on an unlisted deployment is still priced.
	if res := p.computeCost(body, []byte(`{"model":"other"}`), openAIPath, templateAzureOpenAI); !res.calculated {
		t.Error("an unlisted deployment must still be priced")
	}
}

func TestParseRegion_Provisioned(t *testing.T) {
	for _, in := range []string{"provisioned", "Provisioned", " provisioned "} {
		if got := parseRegion(in); got != regionProvisioned {
			t.Errorf("parseRegion(%q) = %q, want %q", in, got, regionProvisioned)
		}
	}
}
