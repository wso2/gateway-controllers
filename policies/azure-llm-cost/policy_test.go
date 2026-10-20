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
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"math"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

// ==========================================================================
// Fixtures, helpers, and pricing-table resolution
// ==========================================================================

const floatTolerance = 1e-12

func almostEqual(a, b float64) bool {
	return math.Abs(a-b) <= floatTolerance
}

// testPricingMap is loaded once from the pinned testdata/model_prices.json fixture.
var testPricingMap map[string]ModelPricing

func init() {
	_, filename, _, _ := runtime.Caller(0)
	dir := filepath.Dir(filename)
	pricingFile := filepath.Join(dir, "testdata", "model_prices.json")
	pm, err := loadPricingFromFile(pricingFile)
	if err != nil {
		panic("pricing_test: failed to load pricing file: " + err.Error())
	}
	testPricingMap = pm
}

func TestLookupPricing_AzureOpenAI_DefaultTier(t *testing.T) {
	p, key, ok := lookupPricingWithKey(testPricingMap, "gpt-4o-2024-08-06", namespacesFor(templateAzureOpenAI, regionGlobalStandard))
	if !ok {
		t.Fatal("expected match for gpt-4o-2024-08-06")
	}
	if key != "azure/global-standard/gpt-4o-2024-08-06" {
		t.Errorf("expected key azure/global-standard/gpt-4o-2024-08-06, got %q", key)
	}
	if !almostEqual(p.InputCostPerToken, 2.5e-6) {
		t.Errorf("unexpected input rate: %v", p.InputCostPerToken)
	}
}

func TestLookupPricing_AzureOpenAI_RegionEU(t *testing.T) {
	p, key, ok := lookupPricingWithKey(testPricingMap, "gpt-4o-2024-08-06", namespacesFor(templateAzureOpenAI, regionEU))
	if !ok {
		t.Fatal("expected match for gpt-4o-2024-08-06 with region=eu")
	}
	if key != "azure/eu/gpt-4o-2024-08-06" {
		t.Errorf("expected key azure/eu/gpt-4o-2024-08-06, got %q", key)
	}
	if !almostEqual(p.InputCostPerToken, 2.75e-6) {
		t.Errorf("unexpected EU input rate: %v", p.InputCostPerToken)
	}
}

func TestLookupPricing_AzureOpenAI_RegionUS(t *testing.T) {
	_, key, ok := lookupPricingWithKey(testPricingMap, "gpt-4o-2024-08-06", namespacesFor(templateAzureOpenAI, regionUS))
	if !ok {
		t.Fatal("expected match for gpt-4o-2024-08-06 with region=us")
	}
	if key != "azure/us/gpt-4o-2024-08-06" {
		t.Errorf("expected key azure/us/gpt-4o-2024-08-06, got %q", key)
	}
}

// Global Standard is the default tier, but most entries in the file are
// unprefixed. gpt-5.4 has no azure/global-standard/ entry, so it must fall back
// to the unprefixed base key, which holds Global Standard rates.
func TestLookupPricing_GlobalStandardFallsBackToBase(t *testing.T) {
	_, key, ok := lookupPricingWithKey(testPricingMap, "gpt-5.4", namespacesFor(templateAzureOpenAI, regionGlobalStandard))
	if !ok {
		t.Fatal("expected global-standard to fall back to the base key")
	}
	if key != "azure/gpt-5.4" {
		t.Errorf("expected base key azure/gpt-5.4, got %q", key)
	}
}

// An explicit azure/global-standard/ entry must win over the base key when the
// file carries one — this is how an operator corrects the base entries that
// hold Data Zone rather than Global Standard rates.
func TestLookupPricing_GlobalStandardPrefixPreferredWhenPresent(t *testing.T) {
	_, key, ok := lookupPricingWithKey(testPricingMap, "gpt-4o-mini", namespacesFor(templateAzureOpenAI, regionGlobalStandard))
	if !ok {
		t.Fatal("expected a match for gpt-4o-mini")
	}
	if key != "azure/global-standard/gpt-4o-mini" {
		t.Errorf("expected the explicit global-standard entry, got %q", key)
	}
}

// Every tier falls back to the base key when the file has no entry for it.
// apac and regional carry no entries in the shipped file at all.
func TestLookupPricing_AllTiersFallBackToBase(t *testing.T) {
	for _, region := range []azureRegion{regionAPAC, regionRegional} {
		_, key, ok := lookupPricingWithKey(testPricingMap, "gpt-4o-2024-08-06", namespacesFor(templateAzureOpenAI, region))
		if !ok {
			t.Fatalf("region=%q: expected fallback to the base key", region)
		}
		if key != "azure/gpt-4o-2024-08-06" {
			t.Errorf("region=%q: expected base key, got %q", region, key)
		}
	}
}

// An unset region behaves as global-standard.
func TestLookupPricing_EmptyRegionDefaultsToGlobalStandard(t *testing.T) {
	_, withEmpty, ok1 := lookupPricingWithKey(testPricingMap, "gpt-4o-mini", namespacesFor(templateAzureOpenAI, ""))
	_, withGS, ok2 := lookupPricingWithKey(testPricingMap, "gpt-4o-mini", namespacesFor(templateAzureOpenAI, regionGlobalStandard))
	if !ok1 || !ok2 || withEmpty != withGS {
		t.Errorf("empty region should behave as global-standard: %q vs %q", withEmpty, withGS)
	}
}

func TestLookupPricing_FoundryTierFallsBackToBase(t *testing.T) {
	// claude-opus-4-5 has no azure_ai/eu/ entry, so an eu deployment must still
	// resolve to its base azure_ai/ entry rather than go unpriced.
	p, key, ok := lookupPricingWithKey(testPricingMap, "claude-opus-4-5", namespacesFor(templateAzureAI, regionEU))
	if !ok {
		t.Fatal("expected match for claude-opus-4-5 even with region=eu set")
	}
	if key != "azure_ai/claude-opus-4-5" {
		t.Errorf("expected key azure_ai/claude-opus-4-5, got %q", key)
	}
	if !almostEqual(p.CacheCreationInputTokenCost, 6.25e-6) {
		t.Errorf("unexpected cache creation rate: %v", p.CacheCreationInputTokenCost)
	}
}

// A tier fallback must be reported once per (region, model), so a misconfigured
// tier is visible without logging on every request. global-standard and
// azure_ai/ matches stay silent — see logTierFallback.
func TestLogTierFallback_WarnsOncePerRegionModel(t *testing.T) {
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
	defer slog.SetDefault(prev)
	tierFallbackSeen = sync.Map{}

	count := func() int { return strings.Count(buf.String(), "no pricing entry for the configured tier") }

	// gpt-5.4-nano has no eu entry, so eu falls back to the base key.
	lookupPricingWithKey(testPricingMap, "gpt-5.4", namespacesFor(templateAzureOpenAI, regionEU))
	if got := count(); got != 1 {
		t.Fatalf("expected 1 warning on first fallback, got %d", got)
	}
	// Repeat lookups for the same pair must not warn again.
	for i := 0; i < 5; i++ {
		lookupPricingWithKey(testPricingMap, "gpt-5.4", namespacesFor(templateAzureOpenAI, regionEU))
	}
	if got := count(); got != 1 {
		t.Errorf("expected the warning to be deduped, got %d", got)
	}
	// A different region for the same model is a separate pair.
	lookupPricingWithKey(testPricingMap, "gpt-5.4", namespacesFor(templateAzureOpenAI, regionAPAC))
	if got := count(); got != 2 {
		t.Errorf("expected a separate warning per region, got %d", got)
	}
	if !strings.Contains(buf.String(), "missing_key=azure/eu/gpt-5.4") {
		t.Errorf("warning should name the key to add; got:\n%s", buf.String())
	}
	// A Foundry-native model falling back from its tier warns the same way.
	lookupPricingWithKey(testPricingMap, "claude-opus-4-5", namespacesFor(templateAzureAI, regionEU))
	if got := count(); got != 3 {
		t.Errorf("expected a warning for the azure_ai/ tier fallback, got %d", got)
	}
	if !strings.Contains(buf.String(), "missing_key=azure_ai/eu/claude-opus-4-5 used_key=azure_ai/claude-opus-4-5") {
		t.Errorf("warning should name the azure_ai/ keys; got:\n%s", buf.String())
	}
}

func TestLogTierFallback_SilentCases(t *testing.T) {
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
	defer slog.SetDefault(prev)
	tierFallbackSeen = sync.Map{}

	// global-standard falling back to base is the normal, correct path.
	lookupPricingWithKey(testPricingMap, "gpt-5.4", namespacesFor(templateAzureOpenAI, regionGlobalStandard))
	// A tier entry that exists is not a fallback at all, in either catalog.
	lookupPricingWithKey(testPricingMap, "gpt-4o-2024-08-06", namespacesFor(templateAzureOpenAI, regionEU))
	lookupPricingWithKey(testPricingMap, "Llama-3.3-70B-Instruct", namespacesFor(templateAzureAI, regionUS))
	// A Foundry global-standard deployment falling back to its base key.
	lookupPricingWithKey(testPricingMap, "claude-opus-4-5", namespacesFor(templateAzureAI, regionGlobalStandard))

	if n := strings.Count(buf.String(), "no pricing entry for the configured tier"); n != 0 {
		t.Errorf("expected no warnings, got %d:\n%s", n, buf.String())
	}
}

// A model name must match a key exactly. Near neighbours — an unlisted dated
// snapshot, or a variant whose parent is listed — resolve to nothing.
func TestLookupPricing_ExactMatchOnly(t *testing.T) {
	for _, name := range []string{
		"gpt-4o-2024-08-06-custom", // trailing token, parent gpt-4o-2024-08-06 is listed
		"gpt-5.4-2099-01-01",       // unlisted snapshot, parent gpt-5.4 is listed
		"gpt-5-2025-06-04",         // unlisted snapshot of a listed family
		"gpt-4o-mini-unknownvar",   // variant of a listed model
	} {
		if _, key, ok := lookupPricingWithKey(testPricingMap, name, namespacesFor(templateAzureOpenAI, regionGlobalStandard)); ok {
			t.Errorf("%q resolved to %q; only exact matches should resolve", name, key)
		}
	}
}

// For a name held by both catalogs at different rates, the request path decides.
func TestLookupPricing_PathBreaksNamespaceTies(t *testing.T) {
	_, viaOpenAI, _ := lookupPricingWithKey(testPricingMap, "mistral-large-latest", namespacesFor(templateAzureOpenAI, regionGlobalStandard))
	_, viaFoundry, _ := lookupPricingWithKey(testPricingMap, "mistral-large-latest", namespacesFor(templateAzureAI, regionGlobalStandard))
	if viaOpenAI != "azure/mistral-large-latest" {
		t.Errorf("an /openai/ path should pick the Azure OpenAI entry, got %q", viaOpenAI)
	}
	if viaFoundry != "azure_ai/mistral-large-latest" {
		t.Errorf("a Foundry path should pick the Foundry entry, got %q", viaFoundry)
	}
}

// One policy instance serves both surfaces of a single Foundry resource: the
// OpenAI models it hosts price from azure/, its native models from azure_ai/.
func TestFoundryServesBothCatalogs(t *testing.T) {
	p := &AzureLLMCostPolicy{pricingMap: testPricingMap, modelMappings: map[string]deploymentMapping{
		"apim-gpt-5.6-terra": {model: "gpt-5.6-terra"},
		"my-claude":          {model: "claude-opus-4-5"},
	}}
	// An OpenAI model on Foundry, over the OpenAI-compatible path. The response
	// reports a dated snapshot the file does not carry, so the mapping resolves it.
	gpt := p.computeCost([]byte(`{"model":"gpt-5.6-terra-2026-07-09","service_tier":"default","usage":{"prompt_tokens":203,"completion_tokens":282,"prompt_tokens_details":{"cached_tokens":0}}}`), []byte(`{"model":"apim-gpt-5.6-terra"}`), "/openai/v1/chat/completions", templateAzureOpenAI)
	if !gpt.calculated || gpt.modelKey != "azure/gpt-5.6-terra" {
		t.Errorf("expected azure/gpt-5.6-terra, got %q (calculated=%v)", gpt.modelKey, gpt.calculated)
	}
	// A Foundry-native model over its own path.
	claude := p.computeCost([]byte(`{"model":"claude-opus-4-5","usage":{"input_tokens":32,"output_tokens":282}}`), []byte(`{"model":"my-claude"}`), "/models/chat/completions", templateAzureAI)
	if !claude.calculated || claude.modelKey != "azure_ai/claude-opus-4-5" {
		t.Errorf("expected azure_ai/claude-opus-4-5, got %q (calculated=%v)", claude.modelKey, claude.calculated)
	}
}

// The responses API echoes the deployment name on Azure AI Foundry exactly as it
// does on Azure OpenAI, so a mapping is needed there too.
func TestFoundryResponsesNeedsMapping(t *testing.T) {
	body := []byte(`{"object":"response","model":"apim-gpt-5.6-terra","service_tier":"default",
		"usage":{"input_tokens":203,"input_tokens_details":{"cached_tokens":0},
		         "output_tokens":300,"output_tokens_details":{"reasoning_tokens":28},"total_tokens":503}}`)
	req := []byte(`{"model":"apim-gpt-5.6-terra"}`)
	const path = "/az-01/openai/v1/responses"

	unmapped := &AzureLLMCostPolicy{pricingMap: testPricingMap, modelMappings: map[string]deploymentMapping{}}
	if res := unmapped.computeCost(body, req, path, templateAzureOpenAI); res.calculated {
		t.Errorf("expected unpriced without a mapping, got %q", res.modelKey)
	}

	mapped := &AzureLLMCostPolicy{pricingMap: testPricingMap, modelMappings: map[string]deploymentMapping{
		"apim-gpt-5.6-terra": {model: "gpt-5.6-terra"},
	}}
	res := mapped.computeCost(body, req, path, templateAzureOpenAI)
	if !res.calculated || res.modelKey != "azure/gpt-5.6-terra" {
		t.Fatalf("expected azure/gpt-5.6-terra, got %q (calculated=%v)", res.modelKey, res.calculated)
	}
	e, _, _ := lookupPricingWithKey(testPricingMap, "gpt-5.6-terra", namespacesFor(templateAzureOpenAI, regionGlobalStandard))
	want := 203*e.InputCostPerToken + 300*e.OutputCostPerToken
	if !almostEqual(res.cost, want) {
		t.Errorf("got %v, want %v", res.cost, want)
	}
}

func TestLookupPricing_UnknownModel(t *testing.T) {
	_, _, ok := lookupPricingWithKey(testPricingMap, "totally-unknown-model-xyz", namespacesFor(templateAzureOpenAI, regionGlobalStandard))
	if ok {
		t.Error("expected lookup to fail for a totally unknown model")
	}
}

func TestLookupPricing_CaseInsensitiveAndTrimmed(t *testing.T) {
	_, key, ok := lookupPricingWithKey(testPricingMap, "  GPT-4o-2024-08-06  ", namespacesFor(templateAzureOpenAI, regionGlobalStandard))
	if !ok {
		t.Fatal("expected case-insensitive, trimmed match to succeed")
	}
	if key != "azure/global-standard/gpt-4o-2024-08-06" {
		t.Errorf("expected key azure/global-standard/gpt-4o-2024-08-06, got %q", key)
	}
}

// TestNamespacesFor_HandleSelectsCatalog pins the catalog to the route's
// template. Azure OpenAI cannot serve a Foundry-native model, so it never
// reads azure_ai/; Foundry serves the OpenAI models too, so it falls back.
func TestNamespacesFor_HandleSelectsCatalog(t *testing.T) {
	openAI := namespacesFor(templateAzureOpenAI, regionGlobalStandard)
	if got := strings.Join(openAI, ","); got != "azure/global-standard/,azure/" {
		t.Errorf("azure-openai must search only the azure/ catalog, got %q", got)
	}

	foundry := namespacesFor(templateAzureAI, regionGlobalStandard)
	if got := strings.Join(foundry, ","); got != "azure_ai/global-standard/,azure_ai/,azure/global-standard/,azure/" {
		t.Errorf("azureai-foundry must search azure_ai/ first then fall back, got %q", got)
	}

	// The tier prefix scopes both catalogs, each ahead of its base key.
	if got := strings.Join(namespacesFor(templateAzureAI, regionEU), ","); got != "azure_ai/eu/,azure_ai/,azure/eu/,azure/" {
		t.Errorf("region must apply to both catalogs, got %q", got)
	}
}

// TestNamespacesFor_NonAzureTemplateYieldsNothing covers a route that names no
// Azure template. Returning nil is what stops the policy pricing traffic it has
// no catalog for.
func TestNamespacesFor_NonAzureTemplateYieldsNothing(t *testing.T) {
	for _, handle := range []string{"", "openai", "anthropic", "azure-openai-prod", "  "} {
		if got := namespacesFor(handle, regionGlobalStandard); got != nil {
			t.Errorf("handle %q must yield no catalog, got %v", handle, got)
		}
		if isAzureTemplate(handle) {
			t.Errorf("handle %q must not be treated as an Azure template", handle)
		}
	}
	// Case and surrounding space are not the operator's problem.
	for _, handle := range []string{"Azure-OpenAI", " azureai-foundry "} {
		if !isAzureTemplate(handle) {
			t.Errorf("handle %q should be recognised", handle)
		}
	}
}

// TestResolvePricing_NonAzureTemplateNotPriced is the case this policy must not
// get wrong: attached to a route that is not Azure, it leaves the request
// unpriced rather than billing it from the Azure catalog.
func TestResolvePricing_NonAzureTemplateNotPriced(t *testing.T) {
	p := newPolicy(regionGlobalStandard, map[string]string{})
	body := []byte(`{"model":"gpt-4o-2024-08-06","usage":{"prompt_tokens":100,"completion_tokens":50,"total_tokens":150}}`)

	if _, key, _, ok := p.resolvePricing(body, nil, openAIPath, ""); ok {
		t.Errorf("absent handle must not price, got %q", key)
	}
	if _, key, _, ok := p.resolvePricing(body, nil, openAIPath, "openai"); ok {
		t.Errorf("non-Azure handle must not price, got %q", key)
	}
	// Same model, correct handle, prices normally.
	if _, key, _, ok := p.resolvePricing(body, nil, openAIPath, templateAzureOpenAI); !ok || key != "azure/global-standard/gpt-4o-2024-08-06" {
		t.Errorf("azure-openai handle should price, got %q (ok=%v)", key, ok)
	}
}

// TestResolvePricing_CatalogsAreNotCrossRead asserts the mutual exclusion the
// handle buys: a Foundry-native model is unreachable from an Azure OpenAI
// route, so a misattached policy fails loudly instead of inventing a rate.
func TestResolvePricing_CatalogsAreNotCrossRead(t *testing.T) {
	p := newPolicy(regionGlobalStandard, map[string]string{})
	claude := []byte(`{"model":"claude-opus-4-5","usage":{"prompt_tokens":100,"completion_tokens":50,"total_tokens":150}}`)

	if _, key, _, ok := p.resolvePricing(claude, nil, openAIPath, templateAzureOpenAI); ok {
		t.Errorf("a Foundry-native model must not resolve on an azure-openai route, got %q", key)
	}
	if _, key, _, ok := p.resolvePricing(claude, nil, foundryPath, templateAzureAI); !ok || key != "azure_ai/claude-opus-4-5" {
		t.Errorf("expected azure_ai/claude-opus-4-5, got %q (ok=%v)", key, ok)
	}

	// An OpenAI model on Foundry still prices, via the azure/ fallback, which
	// is what keeps the 109 OpenAI models absent from azure_ai/ chargeable.
	openAIModel := []byte(`{"model":"gpt-4o-2024-08-06","usage":{"prompt_tokens":100,"completion_tokens":50,"total_tokens":150}}`)
	if _, key, _, ok := p.resolvePricing(openAIModel, nil, foundryPath, templateAzureAI); !ok || key != "azure/global-standard/gpt-4o-2024-08-06" {
		t.Errorf("expected the azure/ fallback to price it, got %q (ok=%v)", key, ok)
	}
}

func TestModelPricing_Unpriced(t *testing.T) {
	p, _, ok := lookupPricingWithKey(testPricingMap, "cohere-rerank-v4.0-pro", namespacesFor(templateAzureAI, regionGlobalStandard))
	if !ok {
		t.Fatal("expected match for cohere-rerank-v4.0-pro")
	}
	if !p.Unpriced() {
		t.Error("expected cohere-rerank-v4.0-pro to be treated as unpriced (no per-token rate)")
	}

	priced, _, ok := lookupPricingWithKey(testPricingMap, "gpt-4o-2024-08-06", namespacesFor(templateAzureOpenAI, regionGlobalStandard))
	if !ok {
		t.Fatal("expected match for gpt-4o-2024-08-06")
	}
	if priced.Unpriced() {
		t.Error("expected gpt-4o-2024-08-06 to be priced")
	}
}

func TestResolveRates_BaseRate(t *testing.T) {
	p, _, _ := lookupPricingWithKey(testPricingMap, "gpt-5.4", namespacesFor(templateAzureOpenAI, regionGlobalStandard))
	r := resolveRates(1000, serviceTierStandard, p)
	if !almostEqual(r.input, 2.5e-6) || !almostEqual(r.output, 1.5e-5) {
		t.Errorf("expected base rates, got input=%v output=%v", r.input, r.output)
	}
}

func TestResolveRates_Above272kOnly(t *testing.T) {
	p, _, _ := lookupPricingWithKey(testPricingMap, "gpt-5.4", namespacesFor(templateAzureOpenAI, regionGlobalStandard))
	r := resolveRates(300_000, serviceTierStandard, p)
	if !almostEqual(r.input, 5e-6) || !almostEqual(r.output, 2.25e-5) {
		t.Errorf("expected above-272k rates, got input=%v output=%v", r.input, r.output)
	}
}

func TestResolveRates_PriorityOnly(t *testing.T) {
	p, _, _ := lookupPricingWithKey(testPricingMap, "gpt-5.4", namespacesFor(templateAzureOpenAI, regionGlobalStandard))
	r := resolveRates(1000, serviceTierPriority, p)
	if !almostEqual(r.input, 5e-6) || !almostEqual(r.output, 3e-5) {
		t.Errorf("expected priority rates, got input=%v output=%v", r.input, r.output)
	}
}

func TestResolveRates_Above272kAndPriorityCombined(t *testing.T) {
	p, _, _ := lookupPricingWithKey(testPricingMap, "gpt-5.4", namespacesFor(templateAzureOpenAI, regionGlobalStandard))
	r := resolveRates(300_000, serviceTierPriority, p)
	if !almostEqual(r.input, 1e-5) || !almostEqual(r.output, 4.5e-5) {
		t.Errorf("expected combined above-272k+priority rates, got input=%v output=%v", r.input, r.output)
	}
}

// ==========================================================================
// Usage parsing and cost math
// ==========================================================================

// The response bodies below are the real usage-object shapes captured from live
// Azure OpenAI calls, one per endpoint family.
func TestNormalizeUsage_AllShapes(t *testing.T) {
	tests := []struct {
		name string
		body string
		want Usage
	}{
		{
			name: "chat completions (prompt_tokens_details, plural)",
			body: `{"model":"gpt-4o-mini-2024-07-18","usage":{
				"prompt_tokens":1000,"completion_tokens":200,"total_tokens":1200,
				"prompt_tokens_details":{"cached_tokens":300,"audio_tokens":0}}}`,
			want: Usage{TotalInputTokens: 1000, OutputTokens: 200, CachedReadTokens: 300},
		},
		{
			name: "assistants thread run (prompt_token_details, singular)",
			body: `{"model":"apim-4o-mini","usage":{
				"prompt_tokens":56,"completion_tokens":11,"total_tokens":67,
				"prompt_token_details":{"cached_tokens":16}}}`,
			want: Usage{TotalInputTokens: 56, OutputTokens: 11, CachedReadTokens: 16},
		},
		{
			name: "responses API (input_tokens / output_tokens)",
			body: `{"model":"apim-4o-mini","usage":{
				"input_tokens":10,"input_tokens_details":{"cached_tokens":4},
				"output_tokens":10,"output_tokens_details":{"reasoning_tokens":0},
				"total_tokens":20}}`,
			want: Usage{TotalInputTokens: 10, OutputTokens: 10, CachedReadTokens: 4},
		},
		{
			name: "anthropic style, cache tokens additive",
			body: `{"model":"claude-opus-4-5","usage":{
				"input_tokens":500,"output_tokens":150,
				"cache_creation_input_tokens":400,"cache_read_input_tokens":100,
				"cache_creation":{"ephemeral_5m_input_tokens":250,"ephemeral_1h_input_tokens":150}}}`,
			want: Usage{TotalInputTokens: 1000, OutputTokens: 150, CachedReadTokens: 100,
				CacheWriteTokens: 250, CacheWrite1hrTokens: 150},
		},
		{
			name: "anthropic style, no TTL breakdown",
			body: `{"model":"claude-opus-4-5","usage":{
				"input_tokens":500,"output_tokens":150,
				"cache_creation_input_tokens":400,"cache_read_input_tokens":100}}`,
			want: Usage{TotalInputTokens: 1000, OutputTokens: 150, CachedReadTokens: 100,
				CacheWriteTokens: 400},
		},
		{
			name: "priority service tier",
			body: `{"model":"gpt-5.4","service_tier":"priority","usage":{
				"prompt_tokens":100,"completion_tokens":50}}`,
			want: Usage{TotalInputTokens: 100, OutputTokens: 50, Tier: serviceTierPriority},
		},
		{
			name: "default service tier is not priority",
			body: `{"model":"gpt-4o","service_tier":"default","usage":{
				"prompt_tokens":100,"completion_tokens":50}}`,
			want: Usage{TotalInputTokens: 100, OutputTokens: 50},
		},
		{
			// Azure AI Foundry, Anthropic-style: cache fields present and zero,
			// service_tier nested and reported as "standard".
			name: "foundry claude, nested service_tier",
			body: `{"model":"claude-opus-4-8","usage":{
				"input_tokens":32,"cache_creation_input_tokens":0,"cache_read_input_tokens":0,
				"cache_creation":{"ephemeral_5m_input_tokens":0,"ephemeral_1h_input_tokens":0},
				"output_tokens":282,"output_tokens_details":{"thinking_tokens":0},
				"service_tier":"standard","inference_geo":"global"}}`,
			want: Usage{TotalInputTokens: 32, OutputTokens: 282},
		},
		{
			name: "nested service_tier of priority is honoured",
			body: `{"model":"claude-opus-4-8","usage":{
				"input_tokens":32,"output_tokens":282,"service_tier":"priority"}}`,
			want: Usage{TotalInputTokens: 32, OutputTokens: 282, Tier: serviceTierPriority},
		},
		{
			// Azure AI Foundry, OpenAI-style: a flat audio counter alongside the
			// standard token fields.
			name: "foundry openai-style with audio_prompt_tokens",
			body: `{"model":"deepseek-v3.2-speciale","usage":{
				"prompt_tokens":18,"completion_tokens":784,"total_tokens":802,
				"audio_prompt_tokens":0}}`,
			want: Usage{TotalInputTokens: 18, OutputTokens: 784},
		},
		{
			name: "no usage object at all",
			body: `{"model":"gpt-4o","choices":[{"message":{"content":"hi"}}]}`,
			want: Usage{},
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

func TestNormalizeUsage_InvalidJSON(t *testing.T) {
	if _, err := normalizeUsage([]byte(`{not json`)); err == nil {
		t.Error("expected an error for malformed JSON")
	}
}

func TestCalculateCost_ReadOnlyCaching(t *testing.T) {
	p, _, ok := lookupPricingWithKey(testPricingMap, "gpt-4o-2024-08-06", namespacesFor(templateAzureOpenAI, regionGlobalStandard))
	if !ok {
		t.Fatal("expected pricing lookup to succeed")
	}
	u := Usage{TotalInputTokens: 1000, OutputTokens: 200, CachedReadTokens: 300}
	want := 700*2.5e-6 + 300*1.25e-6 + 200*1e-5
	if got := calculateCost(u, p); !almostEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestCalculateCost_AnthropicCaching(t *testing.T) {
	p, _, ok := lookupPricingWithKey(testPricingMap, "claude-opus-4-5", namespacesFor(templateAzureAI, regionGlobalStandard))
	if !ok {
		t.Fatal("expected pricing lookup to succeed")
	}
	u := Usage{TotalInputTokens: 1000, OutputTokens: 150, CachedReadTokens: 100,
		CacheWriteTokens: 250, CacheWrite1hrTokens: 150}
	want := 500*5e-6 + 100*5e-7 + 250*6.25e-6 + 150*1e-5 + 150*2.5e-5
	if got := calculateCost(u, p); !almostEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

// Cached tokens must be billed at the cache-read rate, not the full input rate.
// This guards the prompt_token_details / prompt_tokens_details spelling trap,
// where a missed cached count is silently billed as uncached input.
func TestCalculateCost_CachedTokensAreDiscounted(t *testing.T) {
	p, _, _ := lookupPricingWithKey(testPricingMap, "gpt-4o-2024-08-06", namespacesFor(templateAzureOpenAI, regionGlobalStandard))
	withCache := calculateCost(Usage{TotalInputTokens: 1000, OutputTokens: 0, CachedReadTokens: 500}, p)
	noCache := calculateCost(Usage{TotalInputTokens: 1000, OutputTokens: 0}, p)
	if !(withCache < noCache) {
		t.Errorf("expected cached request to cost less: cached=%v uncached=%v", withCache, noCache)
	}
}

// ==========================================================================
// Policy behaviour
// ==========================================================================

// newPolicy builds a policy whose mappings all share one region, which is the
// shape most tests need.
func newPolicy(region azureRegion, mappings map[string]string) *AzureLLMCostPolicy {
	m := make(map[string]deploymentMapping, len(mappings))
	for k, v := range mappings {
		m[k] = deploymentMapping{model: v, region: region}
	}
	return &AzureLLMCostPolicy{pricingMap: testPricingMap, modelMappings: m}
}

// sharedContextWithTemplate mimics what the kernel records for an Azure route.
func sharedContextWithTemplate(handle string) *policy.SharedContext {
	return &policy.SharedContext{
		Metadata: map[string]interface{}{metadataTemplateHandle: handle},
	}
}

// azureOpenAIUpstream is the upstream endpoint of an Azure OpenAI resource;
// tests pass it wherever the provider should resolve to Azure OpenAI.
// Request paths that select each namespace order.
const openAIPath = "/az-01/openai/v1/chat/completions"

const foundryPath = "/az-01/models/chat/completions"

func TestAzureLLMCostPolicy_Mode(t *testing.T) {
	want := policy.ProcessingMode{
		RequestHeaderMode:  policy.HeaderModeSkip,
		RequestBodyMode:    policy.BodyModeBuffer,
		ResponseHeaderMode: policy.HeaderModeSkip,
		ResponseBodyMode:   policy.BodyModeStream,
	}
	if got := (&AzureLLMCostPolicy{}).Mode(); got != want {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

// ---------------------------------------------------------------------------
// Chat completions — the one endpoint that reports the real model name, so it
// must price with no configuration at all.
// ---------------------------------------------------------------------------

// Both response phases must publish the same analytics fields. Only streamed
// responses used to carry the token counts, so a non-streaming request lost its
// model id and every count, which the pipeline needs before it emits AI data.
func TestAnalyticsMetadata_SameOnBothResponsePhases(t *testing.T) {
	body := []byte(`{"model":"gpt-4o-2024-08-06","usage":{"prompt_tokens":100,"completion_tokens":50,"total_tokens":150}}`)
	req := []byte(`{"model":"apim-4o"}`)
	const path = "/openai/v1/chat/completions"

	p := &AzureLLMCostPolicy{pricingMap: testPricingMap, modelMappings: map[string]deploymentMapping{
		"apim-4o": {model: "gpt-4o-2024-08-06"},
	}}

	buffered := p.OnResponseBody(context.Background(), &policy.ResponseContext{
		SharedContext: sharedContextWithTemplate(templateAzureOpenAI),
		RequestPath:   path,
		RequestBody:   &policy.Body{Content: req, Present: true},
		ResponseBody:  &policy.Body{Content: body, Present: true},
	}, nil)

	streamed := p.OnResponseBodyChunk(context.Background(), &policy.ResponseStreamContext{
		SharedContext: sharedContextWithTemplate(templateAzureOpenAI),
		RequestPath:   path,
		RequestBody:   &policy.Body{Content: req, Present: true},
	}, &policy.StreamBody{Chunk: body, EndOfStream: true}, nil)

	bufferedMeta := buffered.(policy.DownstreamResponseModifications).AnalyticsMetadata
	streamedMeta := streamed.(policy.ForwardResponseChunk).AnalyticsMetadata

	for _, key := range []string{
		MetadataLLMCost, metadataModelID, metadataPromptTokenCount,
		metadataCompletionTokenCount, metadataTotalTokenCount,
	} {
		bv, bok := bufferedMeta[key]
		sv, sok := streamedMeta[key]
		if !bok {
			t.Errorf("buffered phase is missing %q", key)
			continue
		}
		if !sok {
			t.Errorf("streamed phase is missing %q", key)
			continue
		}
		if bv != sv {
			t.Errorf("%q differs: buffered=%v streamed=%v", key, bv, sv)
		}
	}
	if len(bufferedMeta) != len(streamedMeta) {
		t.Errorf("field count differs: buffered=%d streamed=%d", len(bufferedMeta), len(streamedMeta))
	}
}

// An unpriced request reports the cost alone from both phases, so a consumer
// cannot tell them apart there either.
func TestAnalyticsMetadata_UnpricedReportsCostOnlyFromBothPhases(t *testing.T) {
	p := &AzureLLMCostPolicy{pricingMap: testPricingMap, modelMappings: map[string]deploymentMapping{}}
	unpriced := costResult{}
	got := analyticsFor(unpriced)
	if len(got) != 1 {
		t.Errorf("expected only the cost, got %v", got)
	}
	if _, ok := got[MetadataLLMCost]; !ok {
		t.Errorf("cost must always be reported, got %v", got)
	}
	_ = p
}

func TestComputeCost_ChatCompletions_NoConfigNeeded(t *testing.T) {
	p := newPolicy(regionGlobalStandard, nil)
	body := []byte(`{"model":"gpt-4o-2024-08-06","usage":{
		"prompt_tokens":1000,"completion_tokens":200,
		"prompt_tokens_details":{"cached_tokens":300}}}`)
	result := p.computeCost(body, nil, "/openai/deployments/apim-4o-mini/chat/completions", templateAzureOpenAI)
	if !result.calculated {
		t.Fatal("expected cost to be calculated")
	}
	want := 700*2.5e-6 + 300*1.25e-6 + 200*1e-5
	if !almostEqual(result.cost, want) {
		t.Errorf("got %v, want %v", result.cost, want)
	}
	if result.modelKey != "azure/global-standard/gpt-4o-2024-08-06" {
		t.Errorf("unexpected model key %q", result.modelKey)
	}
}

// A Data Zone deployment is billed at its own tier, taken from its mapping
// entry, while the model name still comes from the response.
func TestComputeCost_DataZoneDeploymentTier(t *testing.T) {
	p := newPolicy(regionEU, map[string]string{"dep-eu": "gpt-4o-2024-08-06"})
	body := []byte(`{"model":"gpt-4o-2024-08-06","usage":{"prompt_tokens":1000,"completion_tokens":200,
		"prompt_tokens_details":{"cached_tokens":300}}}`)
	result := p.computeCost(body, []byte(`{"model":"dep-eu"}`), "", templateAzureOpenAI)
	want := 700*2.75e-6 + 300*1.375e-6 + 200*1.1e-5
	if !result.calculated || !almostEqual(result.cost, want) {
		t.Errorf("got %v (calculated=%v), want %v", result.cost, result.calculated, want)
	}
	if result.modelKey != "azure/eu/gpt-4o-2024-08-06" {
		t.Errorf("unexpected model key %q", result.modelKey)
	}
}

// ---------------------------------------------------------------------------
// Deployment-name endpoints — need a mapping, since the response reports the
// deployment rather than the model.
// ---------------------------------------------------------------------------

func TestComputeCost_ResponsesAPI_UnpricedWithoutMapping(t *testing.T) {
	p := newPolicy(regionGlobalStandard, nil)
	body := []byte(`{"model":"apim-4o-mini","usage":{
		"input_tokens":1000,"input_tokens_details":{"cached_tokens":0},"output_tokens":200}}`)
	if result := p.computeCost(body, nil, "/openai/responses", templateAzureOpenAI); result.calculated {
		t.Error("expected unpriced: a bare deployment name has no pricing entry")
	}
}

func TestComputeCost_ResponsesAPI_PricedWithMapping(t *testing.T) {
	p := newPolicy(regionGlobalStandard, map[string]string{"apim-4o-mini": "gpt-4o-mini-2024-07-18"})
	body := []byte(`{"model":"apim-4o-mini","usage":{
		"input_tokens":1000,"input_tokens_details":{"cached_tokens":200},"output_tokens":200}}`)
	result := p.computeCost(body, nil, "/openai/responses", templateAzureOpenAI)
	if !result.calculated {
		t.Fatal("expected cost to be calculated via the model mapping")
	}
	want := 800*1.65e-7 + 200*7.5e-8 + 200*6.6e-7
	if !almostEqual(result.cost, want) {
		t.Errorf("got %v, want %v", result.cost, want)
	}
	if result.modelKey != "azure/gpt-4o-mini-2024-07-18" {
		t.Errorf("unexpected model key %q", result.modelKey)
	}
}

func TestComputeCost_ThreadRun_SingularDetailsSpelling(t *testing.T) {
	p := newPolicy(regionGlobalStandard, map[string]string{"apim-4o-mini": "gpt-4o-mini-2024-07-18"})
	// Thread runs use "prompt_token_details" (singular), unlike chat completions.
	body := []byte(`{"model":"apim-4o-mini","usage":{
		"prompt_tokens":1000,"completion_tokens":200,"prompt_token_details":{"cached_tokens":400}}}`)
	result := p.computeCost(body, nil, "/openai/threads/t1/runs/r1", templateAzureOpenAI)
	if !result.calculated {
		t.Fatal("expected cost to be calculated")
	}
	if result.usage.CachedReadTokens != 400 {
		t.Errorf("cached tokens not read from the singular spelling: got %d", result.usage.CachedReadTokens)
	}
	want := 600*1.65e-7 + 400*7.5e-8 + 200*6.6e-7
	if !almostEqual(result.cost, want) {
		t.Errorf("got %v, want %v", result.cost, want)
	}
}

// The deployment name is recoverable from the path even when the body omits it.
func TestComputeCost_MappingViaPathDeployment(t *testing.T) {
	p := newPolicy(regionGlobalStandard, map[string]string{"apim-4o-mini": "gpt-4o-mini-2024-07-18"})
	body := []byte(`{"usage":{"prompt_tokens":100,"completion_tokens":50}}`)
	result := p.computeCost(body, nil, "/openai/deployments/apim-4o-mini/chat/completions?api-version=2024-02-01", templateAzureOpenAI)
	if !result.calculated {
		t.Fatal("expected the deployment from the path to resolve via mapping")
	}
	if result.modelKey != "azure/gpt-4o-mini-2024-07-18" {
		t.Errorf("unexpected model key %q", result.modelKey)
	}
}

// An explicit mapping must beat a coincidental pricing-table hit, so an operator
// can correct a deployment named after a different model than it actually runs.
func TestComputeCost_MappingWinsOverDirectLookup(t *testing.T) {
	p := newPolicy(regionGlobalStandard, map[string]string{"gpt-4o-2024-08-06": "gpt-4o-mini-2024-07-18"})
	body := []byte(`{"model":"gpt-4o-2024-08-06","usage":{"prompt_tokens":1000,"completion_tokens":0}}`)
	result := p.computeCost(body, nil, "", templateAzureOpenAI)
	if result.modelKey != "azure/gpt-4o-mini-2024-07-18" {
		t.Errorf("expected the mapping to win, got model key %q", result.modelKey)
	}
}

func TestComputeCost_FallsBackToRequestBodyModel(t *testing.T) {
	p := newPolicy(regionGlobalStandard, nil)
	response := []byte(`{"usage":{"prompt_tokens":1000,"completion_tokens":200,
		"prompt_tokens_details":{"cached_tokens":300}}}`)
	request := []byte(`{"model":"gpt-4o-2024-08-06","messages":[]}`)
	result := p.computeCost(response, request, "", templateAzureOpenAI)
	want := 700*2.5e-6 + 300*1.25e-6 + 200*1e-5
	if !result.calculated || !almostEqual(result.cost, want) {
		t.Errorf("got %v (calculated=%v), want %v", result.cost, result.calculated, want)
	}
}

// ---------------------------------------------------------------------------
// Tier modifiers
// ---------------------------------------------------------------------------

func TestComputeCost_TierModifiers(t *testing.T) {
	p := newPolicy(regionGlobalStandard, nil)
	tests := []struct {
		name string
		body string
		want float64
	}{
		{
			name: "below both thresholds uses base rates",
			body: `{"model":"gpt-5.4","usage":{"prompt_tokens":1000,"completion_tokens":200}}`,
			want: 1000*2.5e-6 + 200*1.5e-5,
		},
		{
			name: "above 272k only",
			body: `{"model":"gpt-5.4","usage":{"prompt_tokens":300000,"completion_tokens":200}}`,
			want: 300000*5e-6 + 200*2.25e-5,
		},
		{
			name: "priority only",
			body: `{"model":"gpt-5.4","service_tier":"priority","usage":{"prompt_tokens":1000,"completion_tokens":200}}`,
			want: 1000*5e-6 + 200*3e-5,
		},
		{
			name: "above 272k and priority combined",
			body: `{"model":"gpt-5.4","service_tier":"priority","usage":{"prompt_tokens":300000,"completion_tokens":200}}`,
			want: 300000*1e-5 + 200*4.5e-5,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := p.computeCost([]byte(tc.body), nil, "", templateAzureOpenAI)
			if !result.calculated || !almostEqual(result.cost, tc.want) {
				t.Errorf("got %v (calculated=%v), want %v", result.cost, result.calculated, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Graceful degradation — none of these may error or block the request.
// ---------------------------------------------------------------------------

func TestComputeCost_GracefulDegradation(t *testing.T) {
	p := newPolicy(regionGlobalStandard, nil)
	tests := []struct {
		name     string
		response string
		path     string
	}{
		{"unknown model", `{"model":"totally-unknown-xyz","usage":{"prompt_tokens":10,"completion_tokens":5}}`, ""},
		{"model with no per-token pricing", `{"model":"cohere-rerank-v4.0-pro","usage":{"prompt_tokens":10,"completion_tokens":5}}`, ""},
		{"missing usage object", `{"model":"gpt-4o-2024-08-06","choices":[{"message":{"content":"hi"}}]}`, ""},
		{"no model anywhere", `{"usage":{"prompt_tokens":10,"completion_tokens":5}}`, "/openai/responses"},
		{"malformed JSON", `{not json`, ""},
		{"empty body", ``, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := p.computeCost([]byte(tc.response), nil, tc.path, templateAzureOpenAI)
			if result.calculated {
				t.Error("expected calculated=false")
			}
			if result.cost != 0 {
				t.Errorf("expected cost 0, got %v", result.cost)
			}
		})
	}
}

// A mapping pointing at a model that isn't in the pricing table must degrade,
// not resolve to something arbitrary.
func TestComputeCost_MappingToUnknownModel(t *testing.T) {
	p := newPolicy(regionGlobalStandard, map[string]string{"apim-4o-mini": "no-such-model-xyz"})
	body := []byte(`{"model":"apim-4o-mini","usage":{"input_tokens":10,"output_tokens":5}}`)
	if result := p.computeCost(body, nil, "", templateAzureOpenAI); result.calculated {
		t.Error("expected unpriced when the mapped model has no pricing entry")
	}
}

// ---------------------------------------------------------------------------
// Streaming

// The Responses API stream nests the completed response one level down, so
// usage and model sit under "response" rather than at the top level. Captured
// from a live Azure OpenAI /openai/v1/responses stream.
func TestComputeCost_ResponsesAPI_StreamingNestsUsage(t *testing.T) {
	body := `event: response.created
data: {"type":"response.created","response":{"id":"resp_1","object":"response","status":"in_progress","model":"apim-gpt-5.6-terra","usage":null},"sequence_number":0}

event: response.output_text.delta
data: {"type":"response.output_text.delta","content_index":0,"delta":"Could","item_id":"msg_1","output_index":0,"sequence_number":4}

event: response.output_text.delta
data: {"type":"response.output_text.delta","content_index":0,"delta":" you","item_id":"msg_1","output_index":0,"sequence_number":5}

event: response.completed
data: {"type":"response.completed","response":{"id":"resp_1","object":"response","status":"completed","model":"apim-gpt-5.6-terra","service_tier":"default","usage":{"input_tokens":15,"input_tokens_details":{"cached_tokens":0},"output_tokens":119,"output_tokens_details":{"reasoning_tokens":0},"total_tokens":134}},"sequence_number":125}

`
	p := newPolicy(regionGlobalStandard, map[string]string{"apim-gpt-5.6-terra": "gpt-5.6-terra"})
	res := p.computeCost([]byte(body), []byte(`{"model":"apim-gpt-5.6-terra"}`),
		"/openai/v1/responses", templateAzureOpenAI)

	if !res.calculated {
		t.Fatal("streamed /responses must be priced; usage is nested under \"response\"")
	}
	if res.usage.TotalInputTokens != 15 || res.usage.OutputTokens != 119 {
		t.Errorf("tokens = in %d out %d, want in 15 out 119",
			res.usage.TotalInputTokens, res.usage.OutputTokens)
	}
	if res.modelKey != "azure/gpt-5.6-terra" {
		t.Errorf("modelKey = %q, want azure/gpt-5.6-terra", res.modelKey)
	}
}

// The nested response also carries the model and the service tier, so both are
// readable without a mapping.
func TestNormalizeUsage_NestedResponseEnvelope(t *testing.T) {
	body := []byte(`{"type":"response.completed","response":{"model":"gpt-5.6-terra","service_tier":"priority","usage":{"input_tokens":15,"output_tokens":119,"total_tokens":134}}}`)

	if got := extractModelName(body); got != "gpt-5.6-terra" {
		t.Errorf("extractModelName = %q, want gpt-5.6-terra", got)
	}
	u, err := normalizeUsage(body)
	if err != nil {
		t.Fatalf("normalizeUsage: %v", err)
	}
	if u.TotalInputTokens != 15 || u.OutputTokens != 119 {
		t.Errorf("tokens = in %d out %d, want in 15 out 119", u.TotalInputTokens, u.OutputTokens)
	}
	if u.Tier != serviceTierPriority {
		t.Error("service_tier inside the envelope must still select the priority tier")
	}
}

// A top-level usage object must keep winning over a nested one, so the
// non-streaming shapes are unaffected.
func TestNormalizeUsage_TopLevelUsageWinsOverNested(t *testing.T) {
	body := []byte(`{"model":"top","usage":{"prompt_tokens":7,"completion_tokens":3},
		"response":{"model":"nested","usage":{"input_tokens":999,"output_tokens":999}}}`)
	u, err := normalizeUsage(body)
	if err != nil {
		t.Fatalf("normalizeUsage: %v", err)
	}
	if u.TotalInputTokens != 7 || u.OutputTokens != 3 {
		t.Errorf("tokens = in %d out %d, want in 7 out 3", u.TotalInputTokens, u.OutputTokens)
	}
	if got := extractModelName(body); got != "top" {
		t.Errorf("extractModelName = %q, want top", got)
	}
}

// ---------------------------------------------------------------------------

// Azure's first chat-completions SSE chunk carries an empty "model"; later
// chunks carry the real one. The merge must not end up with the empty value.
func TestComputeCost_StreamingSSE(t *testing.T) {
	p := newPolicy(regionGlobalStandard, nil)
	sse := "data: {\"model\":\"\",\"choices\":[],\"prompt_filter_results\":[]}\n" +
		"data: {\"model\":\"gpt-4o-2024-08-06\",\"service_tier\":\"default\",\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\n" +
		"data: {\"model\":\"gpt-4o-2024-08-06\",\"usage\":{\"prompt_tokens\":1000,\"completion_tokens\":200,\"prompt_tokens_details\":{\"cached_tokens\":300}}}\n" +
		"data: [DONE]\n"
	result := p.computeCost([]byte(sse), nil, "", templateAzureOpenAI)
	if !result.calculated {
		t.Fatal("expected cost to be calculated from the merged SSE stream")
	}
	if result.modelKey != "azure/global-standard/gpt-4o-2024-08-06" {
		t.Errorf("empty model in the first chunk leaked through: got %q", result.modelKey)
	}
	want := 700*2.5e-6 + 300*1.25e-6 + 200*1e-5
	if !almostEqual(result.cost, want) {
		t.Errorf("got %v, want %v", result.cost, want)
	}
}

// ---------------------------------------------------------------------------
// Parameter parsing
// ---------------------------------------------------------------------------

// A trailing chunk that repeats "usage": null or "model": null must not erase
// what an earlier event supplied. Azure sends content-filter chunks after the
// usage-bearing one, and a plain overwrite reported a priced call as unpriced.
func TestMergeSSE_TrailingNullDoesNotEraseEarlierValue(t *testing.T) {
	const usageEvent = `data: {"model":"gpt-4o-2024-08-06","usage":{"prompt_tokens":21,"completion_tokens":1337,"total_tokens":1358}}` + "\n\n"

	cases := []struct {
		name string
		body string
	}{
		{
			"nulls before usage, the ordinary stream",
			`data: {"model":"gpt-4o-2024-08-06","usage":null}` + "\n\n" + usageEvent + "data: [DONE]\n\n",
		},
		{
			"usage:null in a trailing filter chunk",
			usageEvent + `data: {"model":"gpt-4o-2024-08-06","usage":null,"content_filter_results":{}}` + "\n\n" + "data: [DONE]\n\n",
		},
		{
			"model:null in a trailing chunk",
			usageEvent + `data: {"model":null}` + "\n\n" + "data: [DONE]\n\n",
		},
		{
			"model blank in a trailing chunk",
			usageEvent + `data: {"model":"","choices":[]}` + "\n\n" + "data: [DONE]\n\n",
		},
	}

	p := &AzureLLMCostPolicy{pricingMap: testPricingMap, modelMappings: map[string]deploymentMapping{}}
	for _, c := range cases {
		res := p.computeCost([]byte(c.body), nil, "/openai/v1/chat/completions", templateAzureOpenAI)
		if !res.calculated {
			t.Errorf("%s: expected a priced result, got calculated=false", c.name)
			continue
		}
		if res.modelKey != "azure/global-standard/gpt-4o-2024-08-06" {
			t.Errorf("%s: model resolved to %q", c.name, res.modelKey)
		}
		if res.usage.TotalInputTokens != 21 || res.usage.OutputTokens != 1337 {
			t.Errorf("%s: tokens lost, in=%d out=%d", c.name, res.usage.TotalInputTokens, res.usage.OutputTokens)
		}
	}
}

// A null for a key no earlier event supplied is still recorded, so the merged
// body keeps the shape the provider sent.
func TestMergeSSE_LeadingNullIsPreserved(t *testing.T) {
	merged, err := normalizeStreamBody([]byte(`data: {"model":"gpt-4o","usage":null}` + "\n\n" + "data: [DONE]\n\n"))
	if err != nil {
		t.Fatalf("merge failed: %v", err)
	}
	if !strings.Contains(string(merged), `"usage":null`) {
		t.Errorf("expected usage:null to survive when nothing else supplied it, got %s", merged)
	}
}

func TestParseRegion(t *testing.T) {
	for in, want := range map[string]azureRegion{
		"eu": regionEU, "EU": regionEU, " us ": regionUS,
		"apac": regionAPAC, "regional": regionRegional,
		"global-standard": regionGlobalStandard,
		// Unset, retired ("global"), and unrecognized values all default to
		// Global Standard — Azure's own default deployment type.
		"": regionGlobalStandard, "global": regionGlobalStandard, "bogus": regionGlobalStandard,
	} {
		if got := parseRegion(in); got != want {
			t.Errorf("parseRegion(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseModelMappings(t *testing.T) {
	raw := []interface{}{
		map[string]interface{}{"deployment": "My-4o-Mini", "model": "gpt-4o-mini", "region": "eu"},
		map[string]interface{}{"deployment": " prod-gpt5 ", "model": " gpt-5.1 "},
	}
	got, err := parseModelMappings(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Deployment keys are lowercased for case-insensitive matching.
	if m := got["my-4o-mini"]; m.model != "gpt-4o-mini" || m.region != regionEU {
		t.Errorf("unexpected mapping for my-4o-mini: %+v", m)
	}
	// An omitted region defaults to Global Standard.
	if m := got["prod-gpt5"]; m.model != "gpt-5.1" || m.region != regionGlobalStandard {
		t.Errorf("unexpected mapping for prod-gpt5: %+v", m)
	}
}

// The tier is a property of the deployment, so two deployments behind one route
// can be priced at different tiers.
func TestRegionIsPerDeployment(t *testing.T) {
	p := &AzureLLMCostPolicy{pricingMap: testPricingMap, modelMappings: map[string]deploymentMapping{
		"dep-eu":     {model: "gpt-4o-2024-08-06", region: regionEU},
		"dep-global": {model: "gpt-4o-2024-08-06", region: regionGlobalStandard},
	}}
	// The response reports the real model; the tier comes from the deployment.
	body := []byte(`{"model":"gpt-4o-2024-08-06","usage":{"prompt_tokens":1000,"completion_tokens":0}}`)

	euRes := p.computeCost(body, []byte(`{"model":"dep-eu"}`), "", templateAzureOpenAI)
	glRes := p.computeCost(body, []byte(`{"model":"dep-global"}`), "", templateAzureOpenAI)

	if euRes.modelKey != "azure/eu/gpt-4o-2024-08-06" {
		t.Errorf("eu deployment resolved to %q", euRes.modelKey)
	}
	if glRes.modelKey != "azure/global-standard/gpt-4o-2024-08-06" {
		t.Errorf("global deployment resolved to %q", glRes.modelKey)
	}
	if !(euRes.cost > glRes.cost) {
		t.Errorf("expected the Data Zone deployment to price higher: eu=%v global=%v", euRes.cost, glRes.cost)
	}
}

// The deployment is named in the path on the legacy surface.
func TestRegionFromPathDeployment(t *testing.T) {
	p := &AzureLLMCostPolicy{pricingMap: testPricingMap, modelMappings: map[string]deploymentMapping{
		"dep-eu": {model: "gpt-4o-2024-08-06", region: regionEU},
	}}
	body := []byte(`{"model":"gpt-4o-2024-08-06","usage":{"prompt_tokens":1000,"completion_tokens":0}}`)
	res := p.computeCost(body, nil, "/openai/deployments/dep-eu/chat/completions", templateAzureOpenAI)
	if res.modelKey != "azure/eu/gpt-4o-2024-08-06" {
		t.Errorf("expected the path deployment's tier, got %q", res.modelKey)
	}
}

// An unlisted deployment has no declared tier and falls back to Global Standard.
func TestRegionDefaultsWhenDeploymentUnlisted(t *testing.T) {
	p := &AzureLLMCostPolicy{pricingMap: testPricingMap, modelMappings: map[string]deploymentMapping{}}
	body := []byte(`{"model":"gpt-4o-2024-08-06","usage":{"prompt_tokens":1000,"completion_tokens":0}}`)
	res := p.computeCost(body, []byte(`{"model":"unlisted"}`), "", templateAzureOpenAI)
	if res.modelKey != "azure/global-standard/gpt-4o-2024-08-06" {
		t.Errorf("expected the default tier, got %q", res.modelKey)
	}
}

func TestParseModelMappings_Invalid(t *testing.T) {
	tests := []struct {
		name string
		raw  interface{}
	}{
		{"not an array", map[string]interface{}{"deployment": "a", "model": "b"}},
		{"entry not an object", []interface{}{"nope"}},
		{"missing model", []interface{}{map[string]interface{}{"deployment": "a"}}},
		{"missing deployment", []interface{}{map[string]interface{}{"model": "b"}}},
		{"blank values", []interface{}{map[string]interface{}{"deployment": "  ", "model": "b"}}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := parseModelMappings(tc.raw); err == nil {
				t.Error("expected an error")
			}
		})
	}
}

func TestParseModelMappings_Nil(t *testing.T) {
	got, err := parseModelMappings(nil)
	if err != nil || got != nil {
		t.Errorf("expected (nil, nil), got (%v, %v)", got, err)
	}
}

func TestDeploymentFromPath(t *testing.T) {
	for in, want := range map[string]string{
		"/openai/deployments/apim-4o-mini/chat/completions":                        "apim-4o-mini",
		"/openai/deployments/apim-4o-mini/chat/completions?api-version=2024-02-01": "apim-4o-mini",
		"/openai/deployments/my-gpt5":                                              "my-gpt5",
		"/openai/responses":                                                        "",
		"":                                                                         "",
	} {
		if got := deploymentFromPath(in); got != want {
			t.Errorf("deploymentFromPath(%q) = %q, want %q", in, got, want)
		}
	}
}

// ==========================================================================
// API-surface compliance (real captured payloads)
// ==========================================================================

// These tests pin the policy against the two Azure OpenAI API surfaces using
// real captured request/response pairs. Deployment name is "apim-gpt-4.1",
// which resolves to gpt-4.1-2025-04-14 (input 2e-06, output 8e-06).
//
//	Legacy  /openai/deployments/{deployment}/{op}?api-version=...
//	        - deployment in the URL, no "model" in the request body
//	        - /chat/completions supported, /responses returns 404
//	v1      /openai/v1/{op}   (no api-version)
//	        - deployment in the request body's "model" field
//	        - /chat/completions and /responses both supported
//
// The response's "model" is the resolved underlying model on chat completions
// (both surfaces) but the deployment name on /responses, which is why
// /responses needs a modelMappings entry and chat completions does not.

const (
	// Real legacy + v1 chat completions response (identical shape on both
	// surfaces). Trimmed to the fields the policy reads.
	chatCompletionsResponse = `{
	  "id": "chatcmpl-EA5eYiE59NTxMWPl4rSwkgcM3cK7n",
	  "object": "chat.completion",
	  "model": "gpt-4.1-2025-04-14",
	  "service_tier": "default",
	  "choices": [{"finish_reason":"stop","index":0,
	    "message":{"role":"assistant","content":"Hello! How can I help you today?"}}],
	  "usage": {
	    "completion_tokens": 11,
	    "completion_tokens_details": {"accepted_prediction_tokens":0,"audio_tokens":0,
	      "reasoning_tokens":0,"rejected_prediction_tokens":0},
	    "prompt_tokens": 10,
	    "prompt_tokens_details": {"audio_tokens":0,"cached_tokens":0},
	    "total_tokens": 21
	  }
	}`

	// Real v1 /responses response. Note "model" echoes the DEPLOYMENT name and
	// usage uses input_tokens/output_tokens.
	responsesAPIResponse = `{
	  "id": "resp_002ffbecc53ef324006a755360fd6c8193a2aa0564d74396a7",
	  "object": "response",
	  "status": "completed",
	  "model": "apim-gpt-4.1",
	  "service_tier": "default",
	  "output": [{"id":"msg_002","type":"message","status":"completed","role":"assistant",
	    "content":[{"type":"output_text","text":"Hello! How can I help you today?"}]}],
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
	request := `{"messages":[{"role":"user","content":"Say hello!"}]}`
	path := "/az-01/openai/deployments/apim-gpt-4.1/chat/completions?api-version=2024-02-01"

	result := p.computeCost([]byte(chatCompletionsResponse), []byte(request), path, templateAzureOpenAI)
	if !result.calculated {
		t.Fatal("legacy chat completions must price with no configuration")
	}
	if result.modelKey != "azure/gpt-4.1-2025-04-14" {
		t.Errorf("expected the resolved model, got %q", result.modelKey)
	}
	want := 10*2e-6 + 11*8e-6
	if !almostEqual(result.cost, want) {
		t.Errorf("got %v, want %v", result.cost, want)
	}
	if result.usage.TotalInputTokens != 10 || result.usage.OutputTokens != 11 {
		t.Errorf("unexpected usage: %+v", result.usage)
	}
}

// v1 surface: deployment lives in the request body's "model", path has no
// /deployments/ segment. The response still reports the resolved model.
func TestCompliance_V1_ChatCompletions_NoConfig(t *testing.T) {
	p := newPolicy(regionGlobalStandard, nil)
	request := `{"messages":[{"role":"user","content":"Say hello!"}],"model":"apim-gpt-4.1"}`
	path := "/az-01/openai/v1/chat/completions"

	result := p.computeCost([]byte(chatCompletionsResponse), []byte(request), path, templateAzureOpenAI)
	if !result.calculated {
		t.Fatal("v1 chat completions must price with no configuration")
	}
	if result.modelKey != "azure/gpt-4.1-2025-04-14" {
		t.Errorf("expected the resolved model, got %q", result.modelKey)
	}
	want := 10*2e-6 + 11*8e-6
	if !almostEqual(result.cost, want) {
		t.Errorf("got %v, want %v", result.cost, want)
	}
}

// v1 /responses echoes the deployment name, so it cannot resolve unaided.
func TestCompliance_V1_Responses_UnpricedWithoutMapping(t *testing.T) {
	p := newPolicy(regionGlobalStandard, nil)
	request := `{"input":[{"role":"user","content":"Say hello!"}],"model":"apim-gpt-4.1"}`
	path := "/az-01/openai/v1/responses"

	if result := p.computeCost([]byte(responsesAPIResponse), []byte(request), path, templateAzureOpenAI); result.calculated {
		t.Error("expected unpriced: /responses reports only the deployment name")
	}
}

// With a mapping, /responses prices correctly off input_tokens/output_tokens.
func TestCompliance_V1_Responses_PricedWithMapping(t *testing.T) {
	p := newPolicy(regionGlobalStandard, map[string]string{"apim-gpt-4.1": "gpt-4.1-2025-04-14"})
	request := `{"input":[{"role":"user","content":"Say hello!"}],"model":"apim-gpt-4.1"}`
	path := "/az-01/openai/v1/responses"

	result := p.computeCost([]byte(responsesAPIResponse), []byte(request), path, templateAzureOpenAI)
	if !result.calculated {
		t.Fatal("expected /responses to price via the model mapping")
	}
	if result.modelKey != "azure/gpt-4.1-2025-04-14" {
		t.Errorf("unexpected model key %q", result.modelKey)
	}
	want := 10*2e-6 + 12*8e-6
	if !almostEqual(result.cost, want) {
		t.Errorf("got %v, want %v", result.cost, want)
	}
	if result.usage.TotalInputTokens != 10 || result.usage.OutputTokens != 12 {
		t.Errorf("input_tokens/output_tokens not read: %+v", result.usage)
	}
}

// A mapping is required for /responses, so it will normally be configured — and
// on the v1 surface the deployment name is ALSO in every chat-completions
// request body. The mapping must not then displace the resolved model that the
// chat-completions response reports, which is the more precise name.
func TestCompliance_V1_MappingMustNotDisplaceResolvedModel(t *testing.T) {
	// Operator maps the deployment to the coarse, undated key.
	p := newPolicy(regionGlobalStandard, map[string]string{"apim-gpt-4o": "gpt-4o"})
	response := `{"model":"gpt-4o-2024-05-13","service_tier":"default",
		"usage":{"prompt_tokens":1000,"completion_tokens":100,
		"prompt_tokens_details":{"cached_tokens":0}}}`
	request := `{"messages":[],"model":"apim-gpt-4o"}`

	result := p.computeCost([]byte(response), []byte(request), "/az-01/openai/v1/chat/completions", templateAzureOpenAI)
	if !result.calculated {
		t.Fatal("expected a calculated cost")
	}
	if result.modelKey != "azure/gpt-4o-2024-05-13" {
		t.Fatalf("mapping displaced the model the response actually reported: got %q, want azure/gpt-4o-2024-05-13", result.modelKey)
	}
	want := 1000*5e-6 + 100*1.5e-5 // rates of the dated entry the response named
	if !almostEqual(result.cost, want) {
		t.Errorf("got %v, want %v (the undated entry would give %v)",
			result.cost, want, 1000*2.5e-6+100*1e-5)
	}
}

// The mapping must still win when the reported name IS the deployment, so an
// operator can correct a deployment whose name collides with a real model.
func TestCompliance_MappingStillCorrectsCollidingDeploymentName(t *testing.T) {
	// A deployment literally named "gpt-4o" that actually serves gpt-4.1.
	p := newPolicy(regionGlobalStandard, map[string]string{"gpt-4o": "gpt-4.1-2025-04-14"})
	response := `{"model":"gpt-4o","usage":{"input_tokens":100,"output_tokens":50}}`

	result := p.computeCost([]byte(response), nil, "/az-01/openai/v1/responses", templateAzureOpenAI)
	if result.modelKey != "azure/gpt-4.1-2025-04-14" {
		t.Errorf("expected the mapping to correct the colliding name, got %q", result.modelKey)
	}
}

// Legacy /responses 404s upstream, so the policy only ever sees an error body.
func TestCompliance_Legacy_Responses_404Body(t *testing.T) {
	p := newPolicy(regionGlobalStandard, map[string]string{"apim-gpt-4.1": "gpt-4.1-2025-04-14"})
	body := `{"error":{"code":"404","message":"Resource not found"}}`
	path := "/az-01/openai/deployments/apim-gpt-4.1/responses?api-version=2024-02-01"

	result := p.computeCost([]byte(body), nil, path, templateAzureOpenAI)
	if result.calculated {
		t.Error("a 404 error body has no usage and must not be priced")
	}
	if result.cost != 0 {
		t.Errorf("expected cost 0, got %v", result.cost)
	}
}

// ==========================================================================
// Benchmarks
// ==========================================================================

// --- lookup only ------------------------------------------------------------

// Exact hit on the first prefix tried: 1 map lookup.
func BenchmarkLookup_ExactHitFirstPrefix(b *testing.B) {
	for i := 0; i < b.N; i++ {
		lookupPricingWithKey(testPricingMap, "gpt-4o-mini", namespacesFor(templateAzureOpenAI, regionGlobalStandard))
	}
}

// Exact hit on the base key: 2 map lookups (tier prefix misses first).
func BenchmarkLookup_ExactHitBaseKey(b *testing.B) {
	for i := 0; i < b.N; i++ {
		lookupPricingWithKey(testPricingMap, "gpt-5.4", namespacesFor(templateAzureOpenAI, regionGlobalStandard))
	}
}

// A name with no matching key: both prefixes are probed, then it gives up.
func BenchmarkLookup_Unresolved(b *testing.B) {
	for i := 0; i < b.N; i++ {
		lookupPricingWithKey(testPricingMap, "gpt-4o-2024-08-06-custom", namespacesFor(templateAzureOpenAI, regionGlobalStandard))
	}
}

// Worst case: nothing matches, so every prefix at every strip depth is probed.
func BenchmarkLookup_FullMiss(b *testing.B) {
	for i := 0; i < b.N; i++ {
		lookupPricingWithKey(testPricingMap, "totally-unknown-model-with-many-segments-xyz", namespacesFor(templateAzureOpenAI, regionGlobalStandard))
	}
}

// --- end to end -------------------------------------------------------------

// The whole response-phase path for a buffered chat completion: JSON parse,
// model resolution, usage parse, cost math.
func BenchmarkComputeCost_BufferedChatCompletion(b *testing.B) {
	p := newPolicy(regionGlobalStandard, map[string]string{"apim-gpt-4.1": "gpt-4.1-2025-04-14"})
	body := []byte(chatCompletionsResponse)
	req := []byte(`{"messages":[{"role":"user","content":"Say hello!"}],"model":"apim-gpt-4.1"}`)
	path := "/az-01/openai/v1/chat/completions"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		p.computeCost(body, req, path, templateAzureOpenAI)
	}
}

// Same, but resolved via the mapping (the /responses path).
func BenchmarkComputeCost_ResponsesViaMapping(b *testing.B) {
	p := newPolicy(regionGlobalStandard, map[string]string{"apim-gpt-4.1": "gpt-4.1-2025-04-14"})
	body := []byte(responsesAPIResponse)
	req := []byte(`{"input":[{"role":"user","content":"Say hello!"}],"model":"apim-gpt-4.1"}`)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		p.computeCost(body, req, "/az-01/openai/v1/responses", templateAzureOpenAI)
	}
}

// Streaming: SSE accumulation is merged then priced once at end of stream.
// A realistic short completion is ~10 events; long ones are hundreds.
func benchStream(b *testing.B, events int) {
	p := newPolicy(regionGlobalStandard, nil)
	var sb strings.Builder
	sb.WriteString(`data: {"model":"","choices":[],"prompt_filter_results":[]}` + "\n")
	for i := 0; i < events; i++ {
		fmt.Fprintf(&sb, `data: {"model":"gpt-4o-2024-08-06","service_tier":"default","choices":[{"delta":{"content":"tok%d"}}]}`+"\n", i)
	}
	sb.WriteString(`data: {"model":"gpt-4o-2024-08-06","usage":{"prompt_tokens":1000,"completion_tokens":200,"prompt_tokens_details":{"cached_tokens":300}}}` + "\n")
	sb.WriteString("data: [DONE]\n")
	body := []byte(sb.String())
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		p.computeCost(body, nil, "", templateAzureOpenAI)
	}
}

func BenchmarkComputeCost_Streaming_10Events(b *testing.B) { benchStream(b, 10) }

func BenchmarkComputeCost_Streaming_200Events(b *testing.B) { benchStream(b, 200) }
