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

// MistralCalculator handles models with provider "mistral". Kept separate from
// OpenAI, despite the compatible API, so Mistral-only charges have a home.
type MistralCalculator struct{}

// Adjust applies no post-calculation correction; Mistral prices purely per token.
func (c *MistralCalculator) Adjust(baseCost float64, _ Usage, _ ModelPricing) float64 {
	return baseCost
}

// fees reads the Voxtral audio-duration charge.
func (c *MistralCalculator) fees(fields fieldLookups, current Usage) Usage {
	// Voxtral bills audio by duration, so prompt_tokens covers only the text.
	if raw, ok := fields.Response("promptAudioSeconds"); ok {
		if seconds, ok := toFloat(raw); ok {
			current.AudioInputSeconds = seconds
		}
	}
	return current
}
