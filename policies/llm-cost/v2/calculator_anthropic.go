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
	"strings"
)

// AnthropicCalculator handles models with provider "anthropic".
// Uses input_tokens/output_tokens field names and adds cache token fields.
// The speed flag is not echoed in the response — it is read from the request body.
type AnthropicCalculator struct{}

// Adjust applies Anthropic geo-routing and speed-mode multipliers.
// Cache costs are excluded from the multiplier — they are charged at fixed rates.
func (c *AnthropicCalculator) Adjust(baseCost float64, usage Usage, pricing ModelPricing) float64 {
	geoNormalized := strings.ToLower(usage.InferenceGeo)
	isGeoRouted := geoNormalized != "" &&
		geoNormalized != "global" &&
		geoNormalized != "not_available"
	isFastMode := strings.ToLower(usage.Speed) == "fast"

	if !isGeoRouted && !isFastMode {
		return baseCost
	}

	pse := pricing.ProviderSpecificEntry
	if len(pse) == 0 {
		return baseCost
	}

	multiplier := 1.0
	if isGeoRouted {
		if m, ok := pse[geoNormalized]; ok {
			multiplier *= m
		}
	}
	if isFastMode {
		if m, ok := pse["fast"]; ok {
			multiplier *= m
		}
	}
	if multiplier == 1.0 {
		return baseCost
	}

	// Resolve the cache rates that GenericCalculateCost used (tier-aware).
	rates := resolveRates(usage, pricing)

	// Carve out cache costs before applying multiplier.
	cacheCost := float64(usage.CachedReadTokens)*rates.cacheRead +
		float64(usage.CacheWriteTokens)*rates.cacheWrite5m +
		float64(usage.CacheWrite1hrTokens)*rates.cacheWrite1h

	// Carve out web search cost — flat fee, not subject to geo/speed multiplier.
	var webSearchCost float64
	if usage.WebSearchRequests > 0 {
		if len(pricing.SearchContextCostPerQuery) > 0 {
			size := usage.SearchContextSize
			if size == "" {
				size = "medium"
			}
			if rate, ok := pricing.SearchContextCostPerQuery["search_context_size_"+size]; ok {
				webSearchCost = float64(usage.WebSearchRequests) * rate
			}
		} else if pricing.WebSearchCostPerRequest > 0 {
			webSearchCost = float64(usage.WebSearchRequests) * pricing.WebSearchCostPerRequest
		}
	}

	nonCacheCost := baseCost - cacheCost - webSearchCost
	if nonCacheCost < 0 {
		nonCacheCost = 0
	}

	return nonCacheCost*multiplier + cacheCost + webSearchCost
}

// fees reads the geo and speed flags that drive Adjust's multiplier, plus the
// web search call and its billed context size.
func (c *AnthropicCalculator) fees(fields fieldLookups, current Usage) Usage {
	// The streaming envelope nests usage under "message"; the template declares
	// both locations, so that difference does not reach this code.
	if raw, ok := fields.Response("inferenceGeo"); ok {
		current.InferenceGeo, _ = raw.(string)
	}
	if raw, ok := fields.Response("webSearchRequests"); ok {
		if requests, ok := toFloat(raw); ok {
			current.WebSearchRequests = int64(requests)
		}
	}

	// speed and search depth are request-side parameters Anthropic does not echo.
	if raw, ok := fields.Request("speed"); ok {
		current.Speed, _ = raw.(string)
	}
	if raw, ok := fields.Request("searchContextSize"); ok {
		current.SearchContextSize, _ = raw.(string)
	}
	return current
}
