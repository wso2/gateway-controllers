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

// loadPricingFromFile returns the "azure/" and "azure_ai/" entries, cached by
// path, so a restart is needed to pick up edits.
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

	pm := make(map[string]ModelPricing)
	for key, msg := range raw {
		if !strings.HasPrefix(key, "azure/") && !strings.HasPrefix(key, "azure_ai/") {
			continue
		}
		var p ModelPricing
		if err := json.Unmarshal(msg, &p); err != nil {
			slog.Warn("azure-llm-cost: skipping invalid pricing entry", "key", key, "error", err)
			continue
		}
		// Source keys are inconsistently cased and every lookup candidate is
		// lowercased, so normalize here.
		pm[strings.ToLower(key)] = p
	}
	if len(pm) == 0 {
		return nil, fmt.Errorf("pricing file has no azure/ or azure_ai/ entries: %s", path)
	}
	return pm, nil
}

// ModelPricing carries the rate fields this policy uses. Names follow the
// schema of the pricing file shared with llm-cost; other fields are ignored.
type ModelPricing struct {
	// Informational only. The parsing path is decided by which key namespace
	// matched, so the legacy "azure_text" behaves exactly like "azure".
	Provider string `json:"provider"`

	InputCostPerToken  float64 `json:"input_cost_per_token"`
	OutputCostPerToken float64 `json:"output_cost_per_token"`

	// Audio, reasoning and server-tool rates. Absent for most entries, in which
	// case the corresponding tokens fall back to the text rate.
	InputCostPerAudioToken      float64 `json:"input_cost_per_audio_token"`
	OutputCostPerAudioToken     float64 `json:"output_cost_per_audio_token"`
	OutputCostPerReasoningToken float64 `json:"output_cost_per_reasoning_token"`

	// The search context cost is a single number for all sizes, or a JSON object with
	// multiple sizes of context.
	SearchContextCostPerQuery json.RawMessage `json:"search_context_cost_per_query"`

	// Cache reads and writes. An entry without one of these bills those tokens
	// at the input rate, which is what Azure charges a model with no cache meter.
	CacheReadInputTokenCost             float64 `json:"cache_read_input_token_cost"`
	CacheCreationInputTokenCost         float64 `json:"cache_creation_input_token_cost"`
	CacheCreationInputTokenCostAbove1hr float64 `json:"cache_creation_input_token_cost_above_1hr"`

	// Long-context tier (>272k input tokens), applied only when present.
	InputCostPerTokenAbove272k           float64 `json:"input_cost_per_token_above_272k_tokens"`
	OutputCostPerTokenAbove272k          float64 `json:"output_cost_per_token_above_272k_tokens"`
	CacheReadInputTokenCostAbove272k     float64 `json:"cache_read_input_token_cost_above_272k_tokens"`
	CacheCreationInputTokenCostAbove272k float64 `json:"cache_creation_input_token_cost_above_272k_tokens"`

	// Priority tier, applied only when present and the response reports it.
	InputCostPerTokenPriority           float64 `json:"input_cost_per_token_priority"`
	OutputCostPerTokenPriority          float64 `json:"output_cost_per_token_priority"`
	CacheReadInputTokenCostPriority     float64 `json:"cache_read_input_token_cost_priority"`
	CacheCreationInputTokenCostPriority float64 `json:"cache_creation_input_token_cost_priority"`

	// Flex tier, applied only when present and the response reports it.
	InputCostPerTokenFlex           float64 `json:"input_cost_per_token_flex"`
	OutputCostPerTokenFlex          float64 `json:"output_cost_per_token_flex"`
	CacheReadInputTokenCostFlex     float64 `json:"cache_read_input_token_cost_flex"`
	CacheCreationInputTokenCostFlex float64 `json:"cache_creation_input_token_cost_flex"`

	// Combined tiers, preferred over the plain above-272k rate when present.
	InputCostPerTokenAbove272kPriority           float64 `json:"input_cost_per_token_above_272k_tokens_priority"`
	OutputCostPerTokenAbove272kPriority          float64 `json:"output_cost_per_token_above_272k_tokens_priority"`
	CacheReadInputTokenCostAbove272kPriority     float64 `json:"cache_read_input_token_cost_above_272k_tokens_priority"`
	CacheCreationInputTokenCostAbove272kPriority float64 `json:"cache_creation_input_token_cost_above_272k_tokens_priority"`
	InputCostPerTokenAbove272kFlex               float64 `json:"input_cost_per_token_above_272k_tokens_flex"`
	OutputCostPerTokenAbove272kFlex              float64 `json:"output_cost_per_token_above_272k_tokens_flex"`
	CacheReadInputTokenCostAbove272kFlex         float64 `json:"cache_read_input_token_cost_above_272k_tokens_flex"`
	CacheCreationInputTokenCostAbove272kFlex     float64 `json:"cache_creation_input_token_cost_above_272k_tokens_flex"`
}

// searchQueryRate returns the per-query web search rate. The context size is a
// request-side tool option the response never reports, so the medium rate is
// charged; a single number applies to every size.
func (p ModelPricing) searchQueryRate() float64 {
	var flat float64
	if json.Unmarshal(p.SearchContextCostPerQuery, &flat) == nil {
		return flat
	}
	var sizes struct {
		Medium float64 `json:"search_context_size_medium"`
	}
	_ = json.Unmarshal(p.SearchContextCostPerQuery, &sizes)
	return sizes.Medium
}

// Unpriced reports an entry billed by some unit other than tokens.
func (p ModelPricing) Unpriced() bool {
	return p.InputCostPerToken == 0 && p.OutputCostPerToken == 0
}

// longContextThresholdTokens is the input size above which Azure bills the whole
// request, output included, at its long-context rates.
const longContextThresholdTokens = 272_000

// serviceTier is the processing tier the response reports. Azure bills priority
// and flex on their own meters; anything else is the standard tier.
type serviceTier string

const (
	serviceTierStandard serviceTier = ""
	serviceTierPriority serviceTier = "priority"
	serviceTierFlex     serviceTier = "flex"
)

// parseServiceTier maps a reported tier onto the ones billed differently. The
// standard tier reports "default" or "standard"; both are simply not these.
func parseServiceTier(reported string) serviceTier {
	switch serviceTier(reported) {
	case serviceTierPriority, serviceTierFlex:
		return serviceTier(reported)
	}
	return serviceTierStandard
}

// effectiveRates holds the rates after long-context and service-tier overrides.
type effectiveRates struct {
	input       float64
	output      float64
	cacheRead   float64
	cacheCreate float64
}

// tierCandidates lists the rate sets that may override the base rates, most
// specific first. A request above the long-context threshold on a priority or
// flex tier prefers the combined set, then the plain long-context set.
func (p ModelPricing) tierCandidates(longContext bool, tier serviceTier) []effectiveRates {
	var candidates []effectiveRates
	if longContext {
		switch tier {
		case serviceTierPriority:
			candidates = append(candidates, effectiveRates{p.InputCostPerTokenAbove272kPriority,
				p.OutputCostPerTokenAbove272kPriority, p.CacheReadInputTokenCostAbove272kPriority,
				p.CacheCreationInputTokenCostAbove272kPriority})
		case serviceTierFlex:
			candidates = append(candidates, effectiveRates{p.InputCostPerTokenAbove272kFlex,
				p.OutputCostPerTokenAbove272kFlex, p.CacheReadInputTokenCostAbove272kFlex,
				p.CacheCreationInputTokenCostAbove272kFlex})
		}
		candidates = append(candidates, effectiveRates{p.InputCostPerTokenAbove272k,
			p.OutputCostPerTokenAbove272k, p.CacheReadInputTokenCostAbove272k,
			p.CacheCreationInputTokenCostAbove272k})
	}
	switch tier {
	case serviceTierPriority:
		candidates = append(candidates, effectiveRates{p.InputCostPerTokenPriority,
			p.OutputCostPerTokenPriority, p.CacheReadInputTokenCostPriority,
			p.CacheCreationInputTokenCostPriority})
	case serviceTierFlex:
		candidates = append(candidates, effectiveRates{p.InputCostPerTokenFlex,
			p.OutputCostPerTokenFlex, p.CacheReadInputTokenCostFlex,
			p.CacheCreationInputTokenCostFlex})
	}
	return candidates
}

// resolveRates applies the first override set the entry defines, judged by its
// input rate; within it, each missing rate keeps the base rate. Cache reads and
// writes without any rate are billed as ordinary input rather than for free.
func resolveRates(inputTokensForTiering int64, tier serviceTier, pricing ModelPricing) effectiveRates {
	r := effectiveRates{
		input:       pricing.InputCostPerToken,
		output:      pricing.OutputCostPerToken,
		cacheRead:   pricing.CacheReadInputTokenCost,
		cacheCreate: pricing.CacheCreationInputTokenCost,
	}

	for _, override := range pricing.tierCandidates(inputTokensForTiering > longContextThresholdTokens, tier) {
		if override.input <= 0 {
			continue
		}
		r.input = override.input
		if override.output > 0 {
			r.output = override.output
		}
		if override.cacheRead > 0 {
			r.cacheRead = override.cacheRead
		}
		if override.cacheCreate > 0 {
			r.cacheCreate = override.cacheCreate
		}
		break
	}

	if r.cacheRead == 0 {
		r.cacheRead = r.input
	}
	if r.cacheCreate == 0 {
		r.cacheCreate = r.input
	}
	return r
}

// Handles of the templates shipped for each product. The kernel records the
// route's template under template_handle.
const (
	templateAzureOpenAI = "azure-openai"
	templateAzureAI     = "azureai-foundry"
)

// isAzureTemplate reports whether the handle names one of the Azure templates.
func isAzureTemplate(templateHandle string) bool {
	switch strings.ToLower(strings.TrimSpace(templateHandle)) {
	case templateAzureOpenAI, templateAzureAI:
		return true
	}
	return false
}

const (
	catalogAzureOpenAI = "azure/"
	catalogAzureAI     = "azure_ai/"
)

// Each catalog is searched tier-first, then at its base (Global Standard) key.
// Foundry also serves the OpenAI models, which are catalogued only under
// azure/, so it falls back there. Azure OpenAI cannot serve a Foundry-native
// model and so never reads azure_ai/.
func namespacesFor(templateHandle string, region azureRegion) []string {
	if region == "" {
		region = regionGlobalStandard
	}
	tiered := func(catalog string) []string {
		return []string{catalog + string(region) + "/", catalog}
	}

	switch strings.ToLower(strings.TrimSpace(templateHandle)) {
	case templateAzureOpenAI:
		return tiered(catalogAzureOpenAI)
	case templateAzureAI:
		return append(tiered(catalogAzureAI), tiered(catalogAzureOpenAI)...)
	}
	return nil
}

// azureRegion is the deployment type, which sets the price tier:
//
//	global-standard  Global Standard      any region; Azure's default
//	us / eu / apac   Data Zone Standard   pinned to that data zone
//	regional         Standard             pinned to a single region
//	provisioned      Provisioned (PTU)    reserved capacity billed by the hour
//
// The token-priced types prefix both catalogs. Provisioned deployments are not
// priced at all, since Azure does not bill them per token.
type azureRegion string

const (
	regionGlobalStandard azureRegion = "global-standard"
	regionUS             azureRegion = "us"
	regionEU             azureRegion = "eu"
	regionAPAC           azureRegion = "apac"
	regionRegional       azureRegion = "regional"
	regionProvisioned    azureRegion = "provisioned"
)

// lookupPricingWithKey requires an exact key match, so an unknown model is
// reported unresolved rather than billed at a near neighbour's rate. Adding an
// "azure/<region>/<model>" or "azure_ai/<region>/<model>" key is how an
// operator sets a tier-specific rate.
func lookupPricingWithKey(pricingMap map[string]ModelPricing, modelName string, prefixes []string) (ModelPricing, string, bool) {
	modelName = strings.ToLower(strings.TrimSpace(modelName))
	if modelName == "" {
		return ModelPricing{}, "", false
	}
	for _, prefix := range prefixes {
		if p, ok := pricingMap[prefix+modelName]; ok {
			logTierFallback(prefixes, modelName, prefix)
			return p, prefix + modelName, true
		}
	}
	return ModelPricing{}, "", false
}

// tierFallbackSeen keeps logTierFallback to once per (region, model).
var tierFallbackSeen sync.Map

// logTierFallback warns that a tier-specific entry was missing and the base
// entry of the same catalog was billed. Silent for global-standard, whose
// rates are the base.
func logTierFallback(prefixes []string, modelName, matchedPrefix string) {
	if matchedPrefix != catalogAzureOpenAI && matchedPrefix != catalogAzureAI {
		return
	}
	var tierPrefix string
	for _, p := range prefixes {
		if strings.HasPrefix(p, matchedPrefix) && p != matchedPrefix {
			tierPrefix = p
			break
		}
	}
	if tierPrefix == "" || tierPrefix == matchedPrefix+string(regionGlobalStandard)+"/" {
		return
	}
	if _, seen := tierFallbackSeen.LoadOrStore(tierPrefix+"|"+modelName, struct{}{}); seen {
		return
	}
	slog.Warn("azure-llm-cost: no pricing entry for the configured tier, billing at the base rate",
		"model", modelName,
		"missing_key", tierPrefix+modelName,
		"used_key", matchedPrefix+modelName)
}
