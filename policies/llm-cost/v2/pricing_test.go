package llmcost_test

import (
	"testing"

	"github.com/wso2/api-platform/sdk/ai/llmusage"
	llmcost "github.com/wso2/gateway-controllers/policies/llm-cost/v2"
)

// Tests for the pieces that need no provider template and no policy instance:
// model-key lookup, the cost arithmetic, and the bridge from extracted usage
// into the pricing struct. Every rate here is an inline literal, so nothing in
// this file depends on the pricing catalogue.

// An unrecognised model must be reported as unpriced rather than truncated onto
// a shorter key: billing "gpt-4o-acme-ft" at the gpt-4o rate is a silent error,
// and a fine-tune is not the base model's price.
func TestLookupPricing_DoesNotTruncateUnknownModels(t *testing.T) {
	pm := map[string]llmcost.ModelPricing{
		"gpt-4o":                       {InputCostPerToken: 1e-06},
		"claude-sonnet-4-20250514":     {InputCostPerToken: 2e-06},
		"mistral/mistral-large-2411":   {InputCostPerToken: 3e-06},
		"us.anthropic.claude-sonnet-4": {InputCostPerToken: 4e-06},
		"anthropic.claude-sonnet-4":    {InputCostPerToken: 5e-06},
	}

	unknown := []string{
		"gpt-4o-acme-ft-2024",                   // fine-tune of a known base
		"claude-sonnet-4-20250514-experimental", // suffixed variant of a known key
		"gpt-4o-mini",                           // a real, differently-priced model absent here
		"gpt-5.6-luna",
		"totally-made-up-model",
	}
	for _, model := range unknown {
		if _, key, found := llmcost.LookupPricingWithKey(pm, model); found {
			t.Errorf("%q must be unpriced, but matched %q", model, key)
		}
	}
}

// The remaining match paths carry real traffic and must keep working.
func TestLookupPricing_WholeKeyPaths(t *testing.T) {
	pm := map[string]llmcost.ModelPricing{
		"gpt-4o":                       {InputCostPerToken: 1e-06},
		"mistral/mistral-large-2411":   {InputCostPerToken: 3e-06},
		"us.anthropic.claude-sonnet-4": {InputCostPerToken: 4e-06},
		"anthropic.claude-sonnet-4":    {InputCostPerToken: 5e-06},
	}

	cases := []struct {
		name, model, wantKey string
	}{
		{"exact", "gpt-4o", "gpt-4o"},
		{"case-insensitive", "GPT-4o", "gpt-4o"},
		{"strips the echoed provider prefix", "openai/gpt-4o", "gpt-4o"},
		{"prepends a known provider prefix", "mistral-large-2411", "mistral/mistral-large-2411"},
		{"region-prefixed profile wins on its own key", "us.anthropic.claude-sonnet-4", "us.anthropic.claude-sonnet-4"},
		{"ARN resolves to the foundation model",
			"arn:aws:bedrock:us-east-1::foundation-model/anthropic.claude-sonnet-4", "anthropic.claude-sonnet-4"},
	}
	for _, c := range cases {
		_, key, found := llmcost.LookupPricingWithKey(pm, c.model)
		if !found || key != c.wantKey {
			t.Errorf("%s: %q -> key=%q found=%v, want key=%q", c.name, c.model, key, found, c.wantKey)
		}
	}
}

// A region-prefixed profile with no entry of its own falls back to the
// foundation model, which is the same model at the same price.
func TestLookupPricing_RegionProfileFallsBackToFoundationModel(t *testing.T) {
	pm := map[string]llmcost.ModelPricing{"anthropic.claude-sonnet-4": {InputCostPerToken: 5e-06}}

	_, key, found := llmcost.LookupPricingWithKey(pm, "eu.anthropic.claude-sonnet-4")
	if !found || key != "anthropic.claude-sonnet-4" {
		t.Errorf("got key=%q found=%v, want %q", key, found, "anthropic.claude-sonnet-4")
	}
}

// The breakdown and the billed total must come from the same arithmetic, or the
// two drift apart silently.
func TestCalculateCostComponents_TotalMatchesGenericCalculateCost(t *testing.T) {
	usage := llmcost.Usage{
		PromptTokens:        10000,
		CompletionTokens:    2000,
		CachedReadTokens:    3000,
		CacheWriteTokens:    500,
		CacheWrite1hrTokens: 250,
		ReasoningTokens:     400,
		AudioInputTokens:    100,
		AudioOutputTokens:   50,
		ImageOutputTokens:   20,
	}
	pricing := llmcost.ModelPricing{
		InputCostPerToken:                   1e-06,
		OutputCostPerToken:                  2e-06,
		CacheReadInputTokenCost:             5e-07,
		CacheCreationInputTokenCost:         1.2e-06,
		CacheCreationInputTokenCostAbove1hr: 2e-06,
		OutputCostPerReasoningToken:         3e-06,
		InputCostPerAudioToken:              4e-06,
		OutputCostPerAudioToken:             5e-06,
		OutputCostPerImageToken:             6e-06,
	}

	components := llmcost.CalculateCostComponents(usage, pricing)
	total := llmcost.GenericCalculateCost(usage, pricing)

	if diff := components.Total() - total; diff > 1e-12 || diff < -1e-12 {
		t.Errorf("components.Total() = %.12f, GenericCalculateCost = %.12f",
			components.Total(), total)
	}
}

// Anthropic declares its two cache TTLs as separate template fields, so the
// components must keep them apart rather than reporting one combined figure.
func TestCalculateCostComponents_SplitsCacheWriteByTTL(t *testing.T) {
	usage := llmcost.Usage{CacheWriteTokens: 1000, CacheWrite1hrTokens: 2000}
	pricing := llmcost.ModelPricing{
		InputCostPerToken:                   1e-06,
		CacheCreationInputTokenCost:         1e-06,
		CacheCreationInputTokenCostAbove1hr: 3e-06,
	}

	c := llmcost.CalculateCostComponents(usage, pricing)

	if c.CacheWrite5m <= 0 || c.CacheWrite1h <= 0 {
		t.Fatalf("both TTL components must be populated, got 5m=%v 1h=%v",
			c.CacheWrite5m, c.CacheWrite1h)
	}
	if c.CacheWrite1h <= c.CacheWrite5m {
		t.Errorf("1h component %v should exceed 5m component %v at these rates",
			c.CacheWrite1h, c.CacheWrite5m)
	}
	if want := float64(1000) * 1e-06; c.CacheWrite5m != want {
		t.Errorf("CacheWrite5m = %v, want %v", c.CacheWrite5m, want)
	}
	if want := float64(2000) * 3e-06; c.CacheWrite1h != want {
		t.Errorf("CacheWrite1h = %v, want %v", c.CacheWrite1h, want)
	}
}

// A tiered map that lacks the requested size must not swallow the charge; the
// single-rate field is the fallback.
func TestWebSearchCost_FallsBackToFlatRate(t *testing.T) {
	usage := llmcost.Usage{PromptTokens: 0, WebSearchRequests: 2, SearchContextSize: "high"}

	cases := []struct {
		name    string
		pricing llmcost.ModelPricing
		want    float64
	}{
		{"map has the size", llmcost.ModelPricing{
			SearchContextCostPerQuery: map[string]float64{"search_context_size_high": 0.03},
			WebSearchCostPerRequest:   0.01,
		}, 0.06},
		{"map lacks the size, flat rate present", llmcost.ModelPricing{
			SearchContextCostPerQuery: map[string]float64{"search_context_size_low": 0.025},
			WebSearchCostPerRequest:   0.01,
		}, 0.02},
		{"no map, flat rate only", llmcost.ModelPricing{
			WebSearchCostPerRequest: 0.01,
		}, 0.02},
		{"neither", llmcost.ModelPricing{}, 0},
	}

	for _, c := range cases {
		got := llmcost.CalculateCostComponents(usage, c.pricing).WebSearch
		if d := got - c.want; d > 1e-12 || d < -1e-12 {
			t.Errorf("%s: WebSearch = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestToPricingUsage_MapsEveryExtractedField(t *testing.T) {
	extracted := llmusage.Usage{
		TotalInputTokens:    1000,
		UncachedInputTokens: 200,
		CachedReadTokens:    800,
		CacheWriteTokens:    50,
		CacheWrite1hTokens:  25,
		OutputTokens:        300,
		ReasoningTokens:     40,
		AudioInputTokens:    10,
		AudioOutputTokens:   5,
		TotalTokens:         1300,
		IsPriority:          true,
		ServiceTier:         "priority",
		Model:               "gpt-4o",
	}

	got := llmcost.ToPricingUsage(extracted)

	// PromptTokens must be the FULL input total: GenericCalculateCost subtracts
	// the cached, cache-write and audio categories itself.
	if got.PromptTokens != 1000 {
		t.Errorf("PromptTokens = %d, want 1000", got.PromptTokens)
	}
	if got.CompletionTokens != 300 {
		t.Errorf("CompletionTokens = %d, want 300", got.CompletionTokens)
	}
	if got.TotalTokens != 1300 {
		t.Errorf("TotalTokens = %d, want 1300", got.TotalTokens)
	}
	if got.CachedReadTokens != 800 {
		t.Errorf("CachedReadTokens = %d, want 800", got.CachedReadTokens)
	}
	if got.CacheWriteTokens != 50 {
		t.Errorf("CacheWriteTokens = %d, want 50", got.CacheWriteTokens)
	}
	if got.CacheWrite1hrTokens != 25 {
		t.Errorf("CacheWrite1hrTokens = %d, want 25", got.CacheWrite1hrTokens)
	}
	if got.ReasoningTokens != 40 {
		t.Errorf("ReasoningTokens = %d, want 40", got.ReasoningTokens)
	}
	if got.AudioInputTokens != 10 {
		t.Errorf("AudioInputTokens = %d, want 10", got.AudioInputTokens)
	}
	if got.AudioOutputTokens != 5 {
		t.Errorf("AudioOutputTokens = %d, want 5", got.AudioOutputTokens)
	}
	if got.ServiceTier != "priority" {
		t.Errorf("ServiceTier = %q, want priority", got.ServiceTier)
	}
	if got.InputTokensForTiering != 1000 {
		t.Errorf("InputTokensForTiering = %d, want 1000", got.InputTokensForTiering)
	}
}

func TestToPricingUsage_NonPriorityTierIsEmpty(t *testing.T) {
	got := llmcost.ToPricingUsage(llmusage.Usage{TotalInputTokens: 10})

	if got.ServiceTier != "" {
		t.Errorf("ServiceTier = %q, want empty for a non-priority tier", got.ServiceTier)
	}
}

func TestToPricingUsage_CarriesEveryRateBearingTier(t *testing.T) {
	// pricing.go's resolveRates branches on priority, flex and batch, so all
	// three must survive the bridge or those rates are never applied.
	for _, tier := range []string{"priority", "flex", "batch"} {
		got := llmcost.ToPricingUsage(llmusage.Usage{TotalInputTokens: 10, ServiceTier: tier})
		if got.ServiceTier != tier {
			t.Errorf("ServiceTier = %q, want %q", got.ServiceTier, tier)
		}
	}
}

// The grounding rate lives in the pricing entry and differs by model
// generation, so the same query count costs different amounts per model.
func TestGeminiAdjust_RateComesFromPricingEntry(t *testing.T) {
	calc := &llmcost.GeminiCalculator{}
	usage := llmcost.Usage{GeminiWebSearchRequests: 3}
	tiered := func(rate float64) map[string]float64 {
		return map[string]float64{"search_context_size_low": rate,
			"search_context_size_medium": rate, "search_context_size_high": rate}
	}

	gen2 := calc.Adjust(1.0, usage, llmcost.ModelPricing{Provider: "gemini", SearchContextCostPerQuery: tiered(0.035)})
	gen3 := calc.Adjust(1.0, usage, llmcost.ModelPricing{Provider: "gemini", SearchContextCostPerQuery: tiered(0.014)})

	if !near(gen2, 1.105) {
		t.Errorf("at 0.035/query = %v, want 1.105", gen2)
	}
	if !near(gen3, 1.042) {
		t.Errorf("at 0.014/query = %v, want 1.042", gen3)
	}
}

// Vertex bills per grounded request; the Developer API bills each query.
func TestGeminiAdjust_VertexBillsOnceDeveloperBillsPerQuery(t *testing.T) {
	calc := &llmcost.GeminiCalculator{}
	usage := llmcost.Usage{GeminiWebSearchRequests: 4}
	rate := map[string]float64{"search_context_size_low": 0.035,
		"search_context_size_medium": 0.035, "search_context_size_high": 0.035}

	vertex := calc.Adjust(1.0, usage, llmcost.ModelPricing{Provider: "vertex_ai-language-models", SearchContextCostPerQuery: rate})
	dev := calc.Adjust(1.0, usage, llmcost.ModelPricing{Provider: "gemini", SearchContextCostPerQuery: rate})

	if !near(vertex, 1.035) {
		t.Errorf("vertex = %v, want 1.035 — one charge however many queries", vertex)
	}
	if !near(dev, 1.14) {
		t.Errorf("developer = %v, want 1.14 — four queries charged", dev)
	}
}

func TestGeminiAdjust_NoRateChargesNothing(t *testing.T) {
	calc := &llmcost.GeminiCalculator{}
	if got := calc.Adjust(1.0, llmcost.Usage{GeminiWebSearchRequests: 3}, llmcost.ModelPricing{}); got != 1.0 {
		t.Errorf("with no rate = %v, want the base cost 1.0", got)
	}
}

// near compares costs without tripping over binary floating point.
func near(got, want float64) bool {
	d := got - want
	return d < 1e-9 && d > -1e-9
}
