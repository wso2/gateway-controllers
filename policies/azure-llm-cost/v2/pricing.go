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

	// Read cost alone means read-only caching, where writes are free. A
	// creation cost too means Anthropic-style, where writes are billed.
	CacheReadInputTokenCost             float64 `json:"cache_read_input_token_cost"`
	CacheCreationInputTokenCost         float64 `json:"cache_creation_input_token_cost"`
	CacheCreationInputTokenCostAbove1hr float64 `json:"cache_creation_input_token_cost_above_1hr"`

	// Long-context tier (>272k input tokens), applied only when present.
	InputCostPerTokenAbove272k       float64 `json:"input_cost_per_token_above_272k_tokens"`
	OutputCostPerTokenAbove272k      float64 `json:"output_cost_per_token_above_272k_tokens"`
	CacheReadInputTokenCostAbove272k float64 `json:"cache_read_input_token_cost_above_272k_tokens"`

	// Priority tier, applied only when present and the response reports it.
	InputCostPerTokenPriority       float64 `json:"input_cost_per_token_priority"`
	OutputCostPerTokenPriority      float64 `json:"output_cost_per_token_priority"`
	CacheReadInputTokenCostPriority float64 `json:"cache_read_input_token_cost_priority"`

	// Combined tier, preferred over the plain above-272k rate when present.
	InputCostPerTokenAbove272kPriority       float64 `json:"input_cost_per_token_above_272k_tokens_priority"`
	OutputCostPerTokenAbove272kPriority      float64 `json:"output_cost_per_token_above_272k_tokens_priority"`
	CacheReadInputTokenCostAbove272kPriority float64 `json:"cache_read_input_token_cost_above_272k_tokens_priority"`
}

// Unpriced reports an entry billed by some unit other than tokens.
func (p ModelPricing) Unpriced() bool {
	return p.InputCostPerToken == 0 && p.OutputCostPerToken == 0
}

// effectiveRates holds the rates after long-context and priority overrides.
type effectiveRates struct {
	input       float64
	output      float64
	cacheRead   float64
	cacheCreate float64
}

// resolveRates applies each override only where the entry carries the field. A
// request qualifying for both prefers the combined fields.
func resolveRates(inputTokensForTiering int64, isPriority bool, pricing ModelPricing) effectiveRates {
	r := effectiveRates{
		input:       pricing.InputCostPerToken,
		output:      pricing.OutputCostPerToken,
		cacheRead:   pricing.CacheReadInputTokenCost,
		cacheCreate: pricing.CacheCreationInputTokenCost,
	}

	aboveTier := inputTokensForTiering > 272_000

	switch {
	case aboveTier && isPriority && pricing.InputCostPerTokenAbove272kPriority > 0:
		r.input = pricing.InputCostPerTokenAbove272kPriority
		if pricing.OutputCostPerTokenAbove272kPriority > 0 {
			r.output = pricing.OutputCostPerTokenAbove272kPriority
		}
		if pricing.CacheReadInputTokenCostAbove272kPriority > 0 {
			r.cacheRead = pricing.CacheReadInputTokenCostAbove272kPriority
		}
	case aboveTier && pricing.InputCostPerTokenAbove272k > 0:
		r.input = pricing.InputCostPerTokenAbove272k
		if pricing.OutputCostPerTokenAbove272k > 0 {
			r.output = pricing.OutputCostPerTokenAbove272k
		}
		if pricing.CacheReadInputTokenCostAbove272k > 0 {
			r.cacheRead = pricing.CacheReadInputTokenCostAbove272k
		}
	case isPriority && pricing.InputCostPerTokenPriority > 0:
		r.input = pricing.InputCostPerTokenPriority
		if pricing.OutputCostPerTokenPriority > 0 {
			r.output = pricing.OutputCostPerTokenPriority
		}
		if pricing.CacheReadInputTokenCostPriority > 0 {
			r.cacheRead = pricing.CacheReadInputTokenCostPriority
		}
	}

	return r
}

// azureRegion is the deployment type whose prefix is tried first. Provisioned
// (PTU) types bill reserved capacity, not tokens, so are absent:
//
//	global-standard  Global Standard      any region; Azure's default
//	us / eu / apac   Data Zone Standard   pinned to that data zone
//	regional         Standard             pinned to a single region
//
// Applied to the azure/ catalog only; azure_ai/ keys are not tier-scoped.
type azureRegion string

const (
	regionGlobalStandard azureRegion = "global-standard"
	regionUS             azureRegion = "us"
	regionEU             azureRegion = "eu"
	regionAPAC           azureRegion = "apac"
	regionRegional       azureRegion = "regional"
)

// lookupPricingWithKey requires an exact key match, so an unknown model is
// reported unresolved rather than billed at a near neighbour's rate. Adding an
// "azure/<region>/<model>" key is how an operator sets a tier-specific rate.
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
// entry was billed. Silent for global-standard, whose rates are the base.
func logTierFallback(prefixes []string, modelName, matchedPrefix string) {
	if matchedPrefix != "azure/" {
		return
	}
	var tierPrefix string
	for _, p := range prefixes {
		if strings.HasPrefix(p, "azure/") && p != "azure/" {
			tierPrefix = p
			break
		}
	}
	if tierPrefix == "" || tierPrefix == "azure/"+string(regionGlobalStandard)+"/" {
		return
	}
	if _, seen := tierFallbackSeen.LoadOrStore(tierPrefix+"|"+modelName, struct{}{}); seen {
		return
	}
	slog.Warn("azure-llm-cost: no pricing entry for the configured tier, billing at the base rate",
		"model", modelName,
		"missing_key", tierPrefix+modelName,
		"used_key", "azure/"+modelName)
}
