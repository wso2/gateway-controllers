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

import "github.com/wso2/api-platform/sdk/ai/llmusage"

// calculateCost covers both caching styles, since Azure OpenAI writes are 0.
// The categories below are subsets of the two totals, so each is removed from
// its total before being charged at its own rate.
func calculateCost(u llmusage.Usage, p ModelPricing) float64 {
	rates := resolveRates(u.TotalInputTokens, u.IsPriority, p)

	cacheCreate1hr := p.CacheCreationInputTokenCostAbove1hr
	if cacheCreate1hr == 0 {
		cacheCreate1hr = p.CacheCreationInputTokenCost
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

	textInput := u.TotalInputTokens - u.CachedReadTokens - u.CacheWriteTokens - u.CacheWrite1hTokens - u.AudioInputTokens
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
		float64(u.CacheWrite1hTokens)*cacheCreate1hr +
		float64(u.AudioInputTokens)*audioIn +
		float64(textOutput)*rates.output +
		float64(u.AudioOutputTokens)*audioOut +
		float64(u.ReasoningTokens)*reasoning
}
