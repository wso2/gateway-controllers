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

import "encoding/json"

// Usage holds normalized token counts. TotalInputTokens includes cached and
// cache-write tokens, and is what the 272k tier is measured against.
type Usage struct {
	TotalInputTokens int64
	OutputTokens     int64

	// Subsets of TotalInputTokens. A 1-hour cache write is Anthropic-style only.
	CachedReadTokens    int64
	CacheWriteTokens    int64
	CacheWrite1hrTokens int64
	AudioInputTokens    int64

	// Subsets of OutputTokens.
	AudioOutputTokens int64
	ReasoningTokens   int64

	// Billed per query rather than per token.
	WebSearchRequests int64

	Tier serviceTier
}

// GPT-5.6 and later report cache_write_tokens, billed above the input rate.
type inputTokenDetails struct {
	CachedTokens     int64 `json:"cached_tokens"`
	CacheWriteTokens int64 `json:"cache_write_tokens"`
	AudioTokens      int64 `json:"audio_tokens"`
}

// Reasoning is spelled reasoning_tokens by OpenAI and thinking_tokens by
// Anthropic.
type outputTokenDetails struct {
	AudioTokens     int64 `json:"audio_tokens"`
	ReasoningTokens int64 `json:"reasoning_tokens"`
	ThinkingTokens  int64 `json:"thinking_tokens"`
}

// rawUsage covers every usage-object variant seen across the Azure endpoints:
//
//	prompt_tokens / completion_tokens + prompt_tokens_details   chat completions
//	prompt_tokens / completion_tokens + prompt_token_details    assistants thread runs
//	input_tokens  / output_tokens     + input_tokens_details    responses API
//	input_tokens  / output_tokens     + cache_read_input_tokens Anthropic-style
//
// The first three include cached tokens in the input total; the Anthropic
// variant reports them separately, so they must be added.
type rawUsage struct {
	PromptTokens     int64 `json:"prompt_tokens"`
	CompletionTokens int64 `json:"completion_tokens"`
	InputTokens      int64 `json:"input_tokens"`
	OutputTokens     int64 `json:"output_tokens"`

	PromptTokensDetails *inputTokenDetails `json:"prompt_tokens_details"`
	PromptTokenDetails  *inputTokenDetails `json:"prompt_token_details"`
	InputTokensDetails  *inputTokenDetails `json:"input_tokens_details"`

	CompletionTokensDetails *outputTokenDetails `json:"completion_tokens_details"`
	OutputTokensDetails     *outputTokenDetails `json:"output_tokens_details"`

	// Anthropic server tools, billed per request.
	ServerToolUse *struct {
		WebSearchRequests int64 `json:"web_search_requests"`
	} `json:"server_tool_use"`

	// Anthropic-style caching: these are additive to input_tokens.
	CacheCreationInputTokens int64 `json:"cache_creation_input_tokens"`
	CacheReadInputTokens     int64 `json:"cache_read_input_tokens"`
	CacheCreation            *struct {
		Ephemeral5mInputTokens int64 `json:"ephemeral_5m_input_tokens"`
		Ephemeral1hInputTokens int64 `json:"ephemeral_1h_input_tokens"`
	} `json:"cache_creation"`

	// Anthropic-style puts the tier inside usage; either position is accepted.
	ServiceTier string `json:"service_tier"`
}

// normalizeUsage accepts any rawUsage variant. No usage object yields a zero
// Usage and no error, which callers treat as unpriceable.
func normalizeUsage(responseBody []byte) (Usage, error) {
	var resp struct {
		ServiceTier string    `json:"service_tier"`
		Usage       *rawUsage `json:"usage"`

		// The Responses API stream wraps the completed response one level down,
		// so its usage and tier are only reachable through here.
		Response *struct {
			ServiceTier string    `json:"service_tier"`
			Usage       *rawUsage `json:"usage"`
		} `json:"response"`
	}
	if err := json.Unmarshal(responseBody, &resp); err != nil {
		return Usage{}, err
	}
	serviceTier := resp.ServiceTier
	if resp.Usage == nil && resp.Response != nil {
		resp.Usage = resp.Response.Usage
		if serviceTier == "" {
			serviceTier = resp.Response.ServiceTier
		}
	}
	if resp.Usage == nil {
		return Usage{}, nil
	}
	u := resp.Usage

	inputTokens := u.PromptTokens
	if inputTokens == 0 {
		inputTokens = u.InputTokens
	}
	outputTokens := u.CompletionTokens
	if outputTokens == 0 {
		outputTokens = u.OutputTokens
	}

	var cacheWrite5m, cacheWrite1hr int64
	if u.CacheCreation != nil {
		cacheWrite5m = u.CacheCreation.Ephemeral5mInputTokens
		cacheWrite1hr = u.CacheCreation.Ephemeral1hInputTokens
	}
	// An unrecognized bucket name leaves it empty, so fall back to the flat total rather than dropping
	if cacheWrite5m == 0 && cacheWrite1hr == 0 {
		cacheWrite5m = u.CacheCreationInputTokens
	}

	tier := parseServiceTier(serviceTier)
	if tier == serviceTierStandard {
		tier = parseServiceTier(u.ServiceTier)
	}
	usage := Usage{
		OutputTokens: outputTokens,
		Tier:         tier,
	}

	// Output-side details and server tools are reported the same way under both
	// caching conventions.
	for _, d := range []*outputTokenDetails{u.CompletionTokensDetails, u.OutputTokensDetails} {
		if d == nil {
			continue
		}
		if usage.AudioOutputTokens == 0 {
			usage.AudioOutputTokens = d.AudioTokens
		}
		if usage.ReasoningTokens == 0 {
			usage.ReasoningTokens = d.ReasoningTokens
			if usage.ReasoningTokens == 0 {
				usage.ReasoningTokens = d.ThinkingTokens
			}
		}
	}
	if u.ServerToolUse != nil {
		usage.WebSearchRequests = u.ServerToolUse.WebSearchRequests
	}

	if u.CacheReadInputTokens > 0 || cacheWrite5m > 0 || cacheWrite1hr > 0 {
		// input_tokens counts only uncached input, so add the cache categories.
		usage.TotalInputTokens = inputTokens + u.CacheReadInputTokens + cacheWrite5m + cacheWrite1hr
		usage.CachedReadTokens = u.CacheReadInputTokens
		usage.CacheWriteTokens = cacheWrite5m
		usage.CacheWrite1hrTokens = cacheWrite1hr
		return usage, nil
	}

	// Cached reads and writes are already in the input total. Either spelling.
	usage.TotalInputTokens = inputTokens
	for _, d := range []*inputTokenDetails{u.PromptTokensDetails, u.PromptTokenDetails, u.InputTokensDetails} {
		if d == nil {
			continue
		}
		if usage.CachedReadTokens == 0 {
			usage.CachedReadTokens = d.CachedTokens
		}
		if usage.CacheWriteTokens == 0 {
			usage.CacheWriteTokens = d.CacheWriteTokens
		}
		if usage.AudioInputTokens == 0 {
			usage.AudioInputTokens = d.AudioTokens
		}
	}
	return usage, nil
}

// calculateCost covers both caching styles; cache writes are billed at the
// write rate the tier resolves to, or as input where the entry has none.
func calculateCost(u Usage, p ModelPricing) float64 {
	rates := resolveRates(u.TotalInputTokens, u.Tier, p)

	cacheCreate1hr := p.CacheCreationInputTokenCostAbove1hr
	if cacheCreate1hr == 0 {
		cacheCreate1hr = rates.cacheCreate
	}
	audioIn := p.InputCostPerAudioToken
	if audioIn == 0 {
		audioIn = rates.input
	}
	audioOut := p.OutputCostPerAudioToken
	if audioOut == 0 {
		audioOut = rates.output
	}
	reasoning := p.OutputCostPerReasoningToken
	if reasoning == 0 {
		reasoning = rates.output
	}

	// The categories below are subsets of the two totals, so each is removed
	// from its total before being charged at its own rate.
	textInput := u.TotalInputTokens - u.CachedReadTokens - u.CacheWriteTokens - u.CacheWrite1hrTokens - u.AudioInputTokens
	if textInput < 0 {
		textInput = 0
	}
	textOutput := u.OutputTokens - u.AudioOutputTokens - u.ReasoningTokens
	if textOutput < 0 {
		textOutput = 0
	}

	return float64(textInput)*rates.input +
		float64(u.CachedReadTokens)*rates.cacheRead +
		float64(u.CacheWriteTokens)*rates.cacheCreate +
		float64(u.CacheWrite1hrTokens)*cacheCreate1hr +
		float64(u.AudioInputTokens)*audioIn +
		float64(textOutput)*rates.output +
		float64(u.AudioOutputTokens)*audioOut +
		float64(u.ReasoningTokens)*reasoning +
		float64(u.WebSearchRequests)*p.searchQueryRate()
}
