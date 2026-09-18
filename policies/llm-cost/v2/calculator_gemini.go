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

import "strings"

// GeminiCalculator handles the "gemini" and "vertex_ai" provider families,
// which share the usageMetadata response namespace.
type GeminiCalculator struct{}

// Adjust adds the grounding fee on top of the token cost. The rate comes from
// the pricing entry and differs by model generation, so a model without one is
// charged nothing.
//
// The two families bill differently: Vertex charges per request that comes back
// with a grounding result, the Developer API charges each search query a prompt
// triggers. The free allowance spans requests and is not modelled here.
func (c *GeminiCalculator) Adjust(baseCost float64, usage Usage, pricing ModelPricing) float64 {
	if usage.GeminiWebSearchRequests == 0 {
		return baseCost
	}
	rate := groundingRate(pricing)
	if rate == 0 {
		return baseCost
	}
	if strings.HasPrefix(pricing.Provider, "vertex_ai") {
		return baseCost + rate
	}
	return baseCost + float64(usage.GeminiWebSearchRequests)*rate
}

// groundingRate reads the search rate the way the token paths do: the tiered
// map first, then the flat field. Gemini quotes one rate across the tiers.
func groundingRate(pricing ModelPricing) float64 {
	if len(pricing.SearchContextCostPerQuery) > 0 {
		for _, size := range []string{"medium", "low", "high"} {
			if rate, ok := pricing.SearchContextCostPerQuery["search_context_size_"+size]; ok {
				return rate
			}
		}
	}
	return pricing.WebSearchCostPerRequest
}

// fees reads the per-modality and grounding charges a field path cannot express.
func (c *GeminiCalculator) fees(fields fieldLookups, current Usage) Usage {
	cachedAudioIn := modalityTokens(fields, "cacheTokensDetails", "AUDIO")

	// promptTokensDetails totals include cached tokens, so the portion billed at
	// the audio input rate is the remainder after subtracting the cached audio.
	audioIn := modalityTokens(fields, "promptTokensDetails", "AUDIO") - cachedAudioIn
	if audioIn < 0 {
		audioIn = 0
	}

	audioOut := modalityTokens(fields, "candidatesTokensDetails", "AUDIO")
	// Gemini Live reports audio output here in place of candidatesTokensDetails.
	if live := modalityTokens(fields, "responseTokensDetails", "AUDIO"); live > 0 {
		audioOut = live
	}

	current.AudioInputTokens = audioIn
	current.AudioOutputTokens = audioOut
	current.CachedAudioInputTokens = cachedAudioIn
	current.ImageOutputTokens = modalityTokens(fields, "candidatesTokensDetails", "IMAGE")

	if raw, ok := fields.Response("toolUsePromptTokenCount"); ok {
		if tokens, ok := toFloat(raw); ok {
			current.ToolUsePromptTokens = int64(tokens)
		}
	}
	current.GeminiWebSearchRequests = groundingQueryCount(fields)
	return current
}

// modalityTokens picks one modality out of a list the template located. Entry
// field names are part of reading a list, not of finding it.
func modalityTokens(fields fieldLookups, name, modality string) int64 {
	raw, ok := fields.Response(name)
	if !ok {
		return 0
	}
	entries, ok := raw.([]interface{})
	if !ok {
		return 0
	}
	for _, entry := range entries {
		detail, ok := entry.(map[string]interface{})
		if !ok || detail["modality"] != modality {
			continue
		}
		if tokens, ok := toFloat(detail["tokenCount"]); ok {
			return int64(tokens)
		}
	}
	return 0
}

// groundingQueryCount counts searches; the fee is per query and no field
// reports the number.
func groundingQueryCount(fields fieldLookups) int64 {
	raw, ok := fields.Response("candidates")
	if !ok {
		return 0
	}
	candidates, ok := raw.([]interface{})
	if !ok {
		return 0
	}
	var queries int64
	for _, candidate := range candidates {
		entry, ok := candidate.(map[string]interface{})
		if !ok {
			continue
		}
		grounding, ok := entry["groundingMetadata"].(map[string]interface{})
		if !ok {
			continue
		}
		if list, ok := grounding["webSearchQueries"].([]interface{}); ok {
			queries += int64(len(list))
		}
	}
	return queries
}
