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

// feeCalculator supplies the per-provider charges that cannot be expressed as a
// template field path, plus any post-calculation correction.
// fieldLookup resolves a location declared under providerFields, returning
// whatever is there — value, list or object — without the caller knowing where.
type fieldLookup func(name string) (interface{}, bool)

// fieldLookups is all a calculator gets: it can only reach data the template
// located, so a new provider field is a template edit, not a struct tag here.
type fieldLookups struct {
	Response fieldLookup
	Request  fieldLookup
}

type feeCalculator interface {
	// fees applies the provider-specific charges. Fields it does not own pass
	// through unchanged.
	fees(fields fieldLookups, current Usage) Usage

	// Adjust applies any provider-specific post-calculation correction
	// (e.g. geo/speed multipliers for Anthropic) and returns the final cost in USD.
	Adjust(baseCost float64, usage Usage, pricing ModelPricing) float64
}

// SelectCalculator returns nil when a provider has no specific charges.
func SelectCalculator(provider string) feeCalculator {
	switch provider {
	case "openai":
		return &OpenAICalculator{}
	case "anthropic":
		return &AnthropicCalculator{}
	case "gemini",
		"vertex_ai",
		"vertex_ai-language-models",
		"vertex_ai-chat-models",
		"vertex_ai-code-chat-models",
		"vertex_ai-vision-models",
		"vertex_ai-embedding-models":
		return &GeminiCalculator{}
	case "mistral":
		return &MistralCalculator{}
	case "bedrock":
		return &BedrockCalculator{}
	default:
		return nil
	}
}
