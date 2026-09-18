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

package llmcost

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"
)

var (
	pricingCache   = map[string]map[string]ModelPricing{}
	pricingCacheMu sync.RWMutex
)

// loadPricingFromFile reads a pricing file into a model key → ModelPricing map.
// Cached per path, so a restart is needed to pick up edits.
func loadPricingFromFile(path string) (map[string]ModelPricing, error) {
	pricingCacheMu.RLock()
	if pm, ok := pricingCache[path]; ok {
		pricingCacheMu.RUnlock()
		return pm, nil
	}
	pricingCacheMu.RUnlock()

	pm, err := loadPricingFromDisk(path)
	if err != nil {
		return nil, err
	}

	pricingCacheMu.Lock()
	pricingCache[path] = pm
	pricingCacheMu.Unlock()
	return pm, nil
}

func loadPricingFromDisk(path string) (map[string]ModelPricing, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	raw := map[string]json.RawMessage{}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("failed to parse pricing file: %w", err)
	}
	if len(raw) == 0 {
		return nil, fmt.Errorf("pricing file is empty or has no entries: %s", path)
	}
	pm := make(map[string]ModelPricing, len(raw))
	for key, msg := range raw {
		var p ModelPricing
		if err := json.Unmarshal(msg, &p); err != nil {
			slog.Warn("llm-cost: skipping invalid pricing entry", "key", key, "error", err)
			continue
		}
		pm[key] = p
	}
	return pm, nil
}

// ModelPricing holds one model's rates; fields map to model_prices.json keys.
type ModelPricing struct {
	Provider string `json:"provider"`

	// Standard token rates (per token, not per 1k)
	InputCostPerToken  float64 `json:"input_cost_per_token"`
	OutputCostPerToken float64 `json:"output_cost_per_token"`

	// Tiered rates — above a 128k context window
	InputCostPerTokenAbove128k  float64 `json:"input_cost_per_token_above_128k_tokens"`
	OutputCostPerTokenAbove128k float64 `json:"output_cost_per_token_above_128k_tokens"`

	// Tiered rates — above a 200k context window
	InputCostPerTokenAbove200k  float64 `json:"input_cost_per_token_above_200k_tokens"`
	OutputCostPerTokenAbove200k float64 `json:"output_cost_per_token_above_200k_tokens"`

	// Tiered rates — above a 272k context window
	InputCostPerTokenAbove272k  float64 `json:"input_cost_per_token_above_272k_tokens"`
	OutputCostPerTokenAbove272k float64 `json:"output_cost_per_token_above_272k_tokens"`

	// Billed instead of the standard rates when Usage.ServiceTier is "priority".
	// Providers name the tier differently; the template maps it.
	InputCostPerTokenPriority                float64 `json:"input_cost_per_token_priority"`
	OutputCostPerTokenPriority               float64 `json:"output_cost_per_token_priority"`
	CacheReadInputTokenCostPriority          float64 `json:"cache_read_input_token_cost_priority"`
	InputCostPerTokenAbove200kPriority       float64 `json:"input_cost_per_token_above_200k_tokens_priority"`
	OutputCostPerTokenAbove200kPriority      float64 `json:"output_cost_per_token_above_200k_tokens_priority"`
	CacheReadInputTokenCostAbove200kPriority float64 `json:"cache_read_input_token_cost_above_200k_tokens_priority"`
	InputCostPerAudioTokenPriority           float64 `json:"input_cost_per_audio_token_priority"`
	InputCostPerTokenAbove272kPriority       float64 `json:"input_cost_per_token_above_272k_tokens_priority"`
	OutputCostPerTokenAbove272kPriority      float64 `json:"output_cost_per_token_above_272k_tokens_priority"`
	CacheReadInputTokenCostAbove272kPriority float64 `json:"cache_read_input_token_cost_above_272k_tokens_priority"`

	// Flex tier rates — lower price, higher latency.
	InputCostPerTokenFlex       float64 `json:"input_cost_per_token_flex"`
	OutputCostPerTokenFlex      float64 `json:"output_cost_per_token_flex"`
	CacheReadInputTokenCostFlex float64 `json:"cache_read_input_token_cost_flex"`

	// Prompt caching
	CacheReadInputTokenCost                      float64 `json:"cache_read_input_token_cost"`
	CacheCreationInputTokenCost                  float64 `json:"cache_creation_input_token_cost"`
	CacheCreationInputTokenCostAbove1hr          float64 `json:"cache_creation_input_token_cost_above_1hr"`
	CacheReadInputTokenCostAbove200k             float64 `json:"cache_read_input_token_cost_above_200k_tokens"`
	CacheCreationInputTokenCostAbove200k         float64 `json:"cache_creation_input_token_cost_above_200k_tokens"`
	CacheCreationInputTokenCostAbove1hrAbove200k float64 `json:"cache_creation_input_token_cost_above_1hr_above_200k_tokens"`
	CacheReadInputTokenCostAbove272k             float64 `json:"cache_read_input_token_cost_above_272k_tokens"`

	// When set, cached audio input tokens are billed at this rate instead of
	// CacheReadInputTokenCost.
	CacheReadInputTokenCostPerAudioToken float64 `json:"cache_read_input_token_cost_per_audio_token"`

	// Reasoning / thinking tokens, where a provider rates them apart from output.
	OutputCostPerReasoningToken float64 `json:"output_cost_per_reasoning_token"`

	// Batch API discounted rates.
	InputCostPerTokenBatches  float64 `json:"input_cost_per_token_batches"`
	OutputCostPerTokenBatches float64 `json:"output_cost_per_token_batches"`

	// Per-modality rates. These tokens are also counted in the prompt/completion
	// totals, so the generic path subtracts them before billing.
	InputCostPerAudioToken  float64 `json:"input_cost_per_audio_token"`
	OutputCostPerAudioToken float64 `json:"output_cost_per_audio_token"`
	OutputCostPerImageToken float64 `json:"output_cost_per_image_token"`

	// For providers billing audio input by duration rather than tokens:
	// cost = seconds × this rate. Only the Mistral calculator reads it, though
	// Gemini entries carry it too.
	InputCostPerAudioPerSecond float64 `json:"input_cost_per_audio_per_second"`

	// Carried for reference; no calculator reads these yet.
	InputCostPerCharacter         float64 `json:"input_cost_per_character"`          // TTS models ($/character)
	InputCostPerSecond            float64 `json:"input_cost_per_second"`             // Whisper transcription ($/second)
	OutputCostPerSecond           float64 `json:"output_cost_per_second"`            // Whisper output ($/second)
	InputCostPerImage             float64 `json:"input_cost_per_image"`              // Image generation ($/image)
	InputCostPerPixel             float64 `json:"input_cost_per_pixel"`              // DALL-E pixel-based pricing
	OutputCostPerPixel            float64 `json:"output_cost_per_pixel"`             // DALL-E pixel-based output pricing
	OutputCostPerVideoPerSecond   float64 `json:"output_cost_per_video_per_second"`  // Video generation ($/second)
	CodeInterpreterCostPerSession float64 `json:"code_interpreter_cost_per_session"` // Container/code interpreter ($/session)

	// Built-in web search tool cost, keyed by search_context_size: low / medium / high.
	// Falls back to WebSearchCostPerRequest when the requested size is absent.
	SearchContextCostPerQuery map[string]float64 `json:"search_context_cost_per_query"`

	// Flat per-call web search rate, charged by every provider that has no tiered
	// entry above.
	WebSearchCostPerRequest float64 `json:"web_search_cost_per_request"`

	// Anthropic geo/speed multipliers, from the provider_specific_entry sub-object.
	ProviderSpecificEntry map[string]float64 `json:"provider_specific_entry"`

	// Carried for reference; tiering compares the token count to the thresholds,
	// not these.
	MaxInputTokens int64 `json:"max_input_tokens"`
	MaxTokens      int64 `json:"max_tokens"`
}

// Usage holds the normalised counts every provider calculator maps its response into.
type Usage struct {
	PromptTokens     int64
	CompletionTokens int64
	TotalTokens      int64

	// Decides the pricing tier. Anthropic counts all input categories; others use
	// PromptTokens, as does the zero fallback.
	InputTokensForTiering int64

	// Cached / reasoning tokens.
	// CacheWrite1hrTokens holds 1-hour TTL writes billed at the higher
	// cache_creation_input_token_cost_above_1hr rate; 0 means all writes are 5-min.
	CachedReadTokens    int64
	CacheWriteTokens    int64 // 5-min TTL cache write tokens
	CacheWrite1hrTokens int64 // 1-hr TTL cache write tokens
	ReasoningTokens     int64

	// Included in PromptTokens/CompletionTokens, then re-billed at modality rates.
	AudioInputTokens  int64
	AudioOutputTokens int64
	ImageOutputTokens int64

	// The audio subset of CachedReadTokens, billed at the per-audio cache rate
	// when one is defined.
	CachedAudioInputTokens int64

	// Audio duration for providers billing by time (e.g. Mistral Voxtral).
	AudioInputSeconds float64

	// Gemini Live search tool tokens, separate from PromptTokens.
	ToolUsePromptTokens int64

	// ServiceTier selects rate variants:
	//   "priority" → _priority fields, "flex" → _flex fields, "" → standard.
	ServiceTier string

	// GeminiWebSearchRequests is the grounding query count. The Developer API bills
	// each query; Vertex bills once per grounded request.
	GeminiWebSearchRequests int64

	// InferenceGeo and Speed are Anthropic-specific routing fields.
	InferenceGeo string // echoed in response usage.inference_geo
	Speed        string // NOT echoed — read from ctx.RequestBody ($.speed)

	// Built-in web search tool calls. SearchContextSize ("low"/"medium"/"high")
	// comes from the request body.
	WebSearchRequests int64
	SearchContextSize string
}

var knownProviderPrefixes = []string{
	"bedrock/",
	"mistral/",
	"vertex_ai/",
}

var bedrockInferenceProfilePrefixes = []string{
	"us-gov.", "us.", "eu.", "apac.", "global.", "au.", "jp.",
}

// LookupPricingWithKey finds a model's entry, trying: exact match → Bedrock
// aliases → strip provider prefix → prepend known prefixes. All matches are
// whole-key. It also returns the key that matched, so analytics does not split
// one pricing entry across ARN and bare-ID dimensions.
func LookupPricingWithKey(pricingMap map[string]ModelPricing, modelName string) (ModelPricing, string, bool) {
	// Canonicalize to lowercase once upfront so all comparisons are case-insensitive.
	modelName = strings.ToLower(strings.TrimSpace(modelName))

	// Every path below matches a whole key. Truncating an unmatched name to a
	// shorter prefix would price an unknown model at some other model's rate, so
	// a name we do not recognise is reported as unpriced instead.
	tryMatch := func(candidate string) (ModelPricing, string, bool) {
		if p, ok := pricingMap[candidate]; ok {
			return p, candidate, true
		}
		return ModelPricing{}, "", false
	}

	// 1. Exact match.
	if p, key, ok := tryMatch(modelName); ok {
		return p, key, true
	}

	// Bedrock may name a model via an inference profile or ARN. Profile-specific
	// pricing wins above; these aliases cover files with only the foundation ID.
	for _, alias := range bedrockModelAliases(modelName) {
		if p, key, ok := tryMatch(alias); ok {
			return p, key, true
		}
		if !strings.Contains(alias, "/") {
			if p, key, ok := tryMatch("bedrock/" + alias); ok {
				return p, key, true
			}
		}
	}

	// 2. Responses may echo "openai/gpt-4o" where the key is "gpt-4o".
	if idx := strings.Index(modelName, "/"); idx != -1 {
		bare := modelName[idx+1:]
		if p, key, ok := tryMatch(bare); ok {
			return p, key, true
		}
	}

	// 3. The reverse: Mistral returns "mistral-large-latest" where the key is
	//    "mistral/mistral-large-latest".
	if !strings.Contains(modelName, "/") {
		for _, prefix := range knownProviderPrefixes {
			if p, key, ok := tryMatch(prefix + modelName); ok {
				return p, key, true
			}
		}
	}

	return ModelPricing{}, "", false
}

// bedrockModelAliases canonicalises foundation-model and system-defined profile IDs.
// Application/provisioned profile IDs do not encode a model ID, so they cannot resolve.
func bedrockModelAliases(modelName string) []string {
	candidate := strings.TrimPrefix(modelName, "bedrock/")
	for _, marker := range []string{"foundation-model/", "inference-profile/"} {
		if i := strings.Index(candidate, marker); i >= 0 {
			candidate = candidate[i+len(marker):]
			break
		}
	}

	aliases := make([]string, 0, 2)
	if candidate != modelName {
		aliases = append(aliases, candidate)
	}
	for _, prefix := range bedrockInferenceProfilePrefixes {
		if strings.HasPrefix(candidate, prefix) {
			aliases = append(aliases, strings.TrimPrefix(candidate, prefix))
			break
		}
	}
	return aliases
}

// effectiveRates holds the rates left after tiering and service-tier overrides.
type effectiveRates struct {
	input        float64
	output       float64
	cacheRead    float64
	cacheWrite5m float64
	cacheWrite1h float64
}

// resolveRates applies context-window tiering, then service-tier overrides on top.
func resolveRates(usage Usage, pricing ModelPricing) effectiveRates {
	r := effectiveRates{
		input:        pricing.InputCostPerToken,
		output:       pricing.OutputCostPerToken,
		cacheRead:    pricing.CacheReadInputTokenCost,
		cacheWrite5m: pricing.CacheCreationInputTokenCost,
		cacheWrite1h: pricing.CacheCreationInputTokenCostAbove1hr,
	}
	if r.cacheWrite1h == 0 {
		// No distinct 1hr rate: fall back to the standard write rate.
		r.cacheWrite1h = r.cacheWrite5m
	}

	// Anthropic's 200k threshold counts input + cache tokens; everyone else tiers
	// on prompt tokens alone.
	tierTokens := usage.InputTokensForTiering
	if tierTokens == 0 {
		tierTokens = usage.PromptTokens
	}

	// Context-window tier selection.
	switch {
	case tierTokens > 272_000 && pricing.InputCostPerTokenAbove272k > 0:
		r.input = pricing.InputCostPerTokenAbove272k
		if pricing.OutputCostPerTokenAbove272k > 0 {
			r.output = pricing.OutputCostPerTokenAbove272k
		}
		if pricing.CacheReadInputTokenCostAbove272k > 0 {
			r.cacheRead = pricing.CacheReadInputTokenCostAbove272k
		}
	case tierTokens > 200_000 && pricing.InputCostPerTokenAbove200k > 0:
		r.input = pricing.InputCostPerTokenAbove200k
		if pricing.OutputCostPerTokenAbove200k > 0 {
			r.output = pricing.OutputCostPerTokenAbove200k
		}
		if pricing.CacheReadInputTokenCostAbove200k > 0 {
			r.cacheRead = pricing.CacheReadInputTokenCostAbove200k
		}
		if pricing.CacheCreationInputTokenCostAbove200k > 0 {
			r.cacheWrite5m = pricing.CacheCreationInputTokenCostAbove200k
			// For entries defining only a general >200k cache-write rate.
			r.cacheWrite1h = pricing.CacheCreationInputTokenCostAbove200k
		}
		if pricing.CacheCreationInputTokenCostAbove1hrAbove200k > 0 {
			r.cacheWrite1h = pricing.CacheCreationInputTokenCostAbove1hrAbove200k
		}
	case tierTokens > 128_000 && pricing.InputCostPerTokenAbove128k > 0:
		r.input = pricing.InputCostPerTokenAbove128k
		if pricing.OutputCostPerTokenAbove128k > 0 {
			r.output = pricing.OutputCostPerTokenAbove128k
		}
	}

	// Priority thresholds are checked narrowest first, so a >272k priority prompt
	// gets the compounded rate.
	switch usage.ServiceTier {
	case "priority":
		switch {
		case tierTokens > 272_000 && pricing.InputCostPerTokenAbove272kPriority > 0:
			r.input = pricing.InputCostPerTokenAbove272kPriority
			if pricing.OutputCostPerTokenAbove272kPriority > 0 {
				r.output = pricing.OutputCostPerTokenAbove272kPriority
			}
			if pricing.CacheReadInputTokenCostAbove272kPriority > 0 {
				r.cacheRead = pricing.CacheReadInputTokenCostAbove272kPriority
			}
		case tierTokens > 200_000 && pricing.InputCostPerTokenAbove200kPriority > 0:
			r.input = pricing.InputCostPerTokenAbove200kPriority
			if pricing.OutputCostPerTokenAbove200kPriority > 0 {
				r.output = pricing.OutputCostPerTokenAbove200kPriority
			}
			if pricing.CacheReadInputTokenCostAbove200kPriority > 0 {
				r.cacheRead = pricing.CacheReadInputTokenCostAbove200kPriority
			}
		case pricing.InputCostPerTokenPriority > 0:
			r.input = pricing.InputCostPerTokenPriority
			if pricing.OutputCostPerTokenPriority > 0 {
				r.output = pricing.OutputCostPerTokenPriority
			}
			if pricing.CacheReadInputTokenCostPriority > 0 {
				r.cacheRead = pricing.CacheReadInputTokenCostPriority
			}
		}
	case "flex":
		if pricing.InputCostPerTokenFlex > 0 {
			r.input = pricing.InputCostPerTokenFlex
			if pricing.OutputCostPerTokenFlex > 0 {
				r.output = pricing.OutputCostPerTokenFlex
			}
			if pricing.CacheReadInputTokenCostFlex > 0 {
				r.cacheRead = pricing.CacheReadInputTokenCostFlex
			}
		}
	case "batch":
		if pricing.InputCostPerTokenBatches > 0 {
			r.input = pricing.InputCostPerTokenBatches
			if pricing.OutputCostPerTokenBatches > 0 {
				r.output = pricing.OutputCostPerTokenBatches
			}
		}
	}

	return r
}

// CostComponents holds each separately-rated part of one request's cost. The
// parts are reported individually for analytics and summed for billing, so both
// come from the same arithmetic.
type CostComponents struct {
	Prompt       float64
	Completion   float64
	CacheRead    float64
	CacheWrite5m float64
	CacheWrite1h float64
	Reasoning    float64
	AudioInput   float64
	AudioOutput  float64
	ImageOutput  float64
	AudioSeconds float64
	WebSearch    float64
	ToolUse      float64
}

// total is the amount billed for the request before any provider-specific
// adjustment.
func (c CostComponents) Total() float64 {
	return c.Prompt + c.Completion + c.CacheRead + c.CacheWrite5m + c.CacheWrite1h +
		c.Reasoning + c.WebSearch + c.ToolUse + c.AudioInput + c.AudioOutput +
		c.ImageOutput + c.AudioSeconds
}

// GenericCalculateCost prices one request using the provider-agnostic rules.
func GenericCalculateCost(usage Usage, pricing ModelPricing) float64 {
	return CalculateCostComponents(usage, pricing).Total()
}

// CalculateCostComponents rates each category separately, for breakdown and sum.
func CalculateCostComponents(usage Usage, pricing ModelPricing) CostComponents {
	r := resolveRates(usage, pricing)

	// --- Token costs ---------------------------------------------------------

	// Cached, cache-write and audio tokens are billed separately below.
	regularPromptTokens := usage.PromptTokens - usage.CachedReadTokens - usage.CacheWriteTokens - usage.CacheWrite1hrTokens - usage.AudioInputTokens
	if regularPromptTokens < 0 {
		regularPromptTokens = 0
	}
	// Exclude reasoning, audio, and image tokens from the regular completion count.
	regularCompletionTokens := usage.CompletionTokens - usage.ReasoningTokens - usage.AudioOutputTokens - usage.ImageOutputTokens
	if regularCompletionTokens < 0 {
		regularCompletionTokens = 0
	}

	promptCost := float64(regularPromptTokens) * r.input
	completionCost := float64(regularCompletionTokens) * r.output

	// Split cached tokens by modality only when a per-audio cache rate exists.
	var cacheReadCost float64
	if pricing.CacheReadInputTokenCostPerAudioToken > 0 {
		textCachedTokens := usage.CachedReadTokens - usage.CachedAudioInputTokens
		if textCachedTokens < 0 {
			textCachedTokens = 0
		}
		cacheReadCost = float64(textCachedTokens)*r.cacheRead +
			float64(usage.CachedAudioInputTokens)*pricing.CacheReadInputTokenCostPerAudioToken
	} else {
		cacheReadCost = float64(usage.CachedReadTokens) * r.cacheRead
	}
	// Per TTL: providers offering both rate them differently and report them
	// as separate fields.
	cacheWrite5mCost := float64(usage.CacheWriteTokens) * r.cacheWrite5m
	cacheWrite1hCost := float64(usage.CacheWrite1hrTokens) * r.cacheWrite1h

	// Reasoning tokens billed at their own rate if defined, otherwise at output rate.
	reasoningRate := pricing.OutputCostPerReasoningToken
	if reasoningRate == 0 {
		reasoningRate = r.output
	}
	reasoningCost := float64(usage.ReasoningTokens) * reasoningRate

	// --- Modality costs ------------------------------------------------------

	// Note: service-tier (_priority) suffix does not apply to audio token rates.
	audioInputRate := pricing.InputCostPerAudioToken
	if audioInputRate == 0 {
		audioInputRate = r.input
	}
	audioInputCost := float64(usage.AudioInputTokens) * audioInputRate

	audioOutputRate := pricing.OutputCostPerAudioToken
	if audioOutputRate == 0 {
		audioOutputRate = r.output
	}
	audioOutputCost := float64(usage.AudioOutputTokens) * audioOutputRate

	imageOutputRate := pricing.OutputCostPerImageToken
	if imageOutputRate == 0 {
		imageOutputRate = r.output
	}
	imageOutputCost := float64(usage.ImageOutputTokens) * imageOutputRate

	// Audio billed by duration rather than token count (e.g. Mistral Voxtral).
	audioSecondsCost := usage.AudioInputSeconds * pricing.InputCostPerAudioPerSecond

	// --- Tool / search costs -------------------------------------------------

	// Rate by context size, falling back to the single per-call rate.
	var webSearchCost float64
	if usage.WebSearchRequests > 0 {
		webSearchCost = float64(usage.WebSearchRequests) * webSearchRate(usage.SearchContextSize, pricing)
	}

	// Gemini Live tool-use tokens: flat fee when defined, otherwise standard input rate.
	var toolUseCost float64
	if usage.ToolUsePromptTokens > 0 {
		if pricing.WebSearchCostPerRequest > 0 {
			toolUseCost = pricing.WebSearchCostPerRequest
		} else {
			toolUseCost = float64(usage.ToolUsePromptTokens) * r.input
		}
	}

	return CostComponents{
		Prompt:       promptCost,
		Completion:   completionCost,
		CacheRead:    cacheReadCost,
		CacheWrite5m: cacheWrite5mCost,
		CacheWrite1h: cacheWrite1hCost,
		Reasoning:    reasoningCost,
		AudioInput:   audioInputCost,
		AudioOutput:  audioOutputCost,
		ImageOutput:  imageOutputCost,
		AudioSeconds: audioSecondsCost,
		WebSearch:    webSearchCost,
		ToolUse:      toolUseCost,
	}
}

// webSearchRate resolves the rate for a context size. The single per-call rate is
// the fallback whenever the map does not answer — including when it lacks the size.
func webSearchRate(size string, pricing ModelPricing) float64 {
	if size == "" {
		size = "medium"
	}
	if rate, ok := pricing.SearchContextCostPerQuery["search_context_size_"+size]; ok && rate > 0 {
		return rate
	}
	return pricing.WebSearchCostPerRequest
}
