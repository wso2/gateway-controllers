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

// BedrockCalculator handles native AWS Bedrock Converse and InvokeModel usage,
// as well as Converse responses converted to the OpenAI Chat Completions shape
// by openai-to-bedrock-transformer.
type BedrockCalculator struct{}

type bedrockCacheDetail struct {
	TTL         string
	InputTokens int64
}

func bedrockCacheWritesByTTL(details []bedrockCacheDetail, aggregate int64) (int64, int64) {
	if len(details) == 0 {
		return aggregate, 0
	}

	var cacheWrite5m, cacheWrite1h int64
	for _, detail := range details {
		switch detail.TTL {
		case "5m":
			cacheWrite5m += detail.InputTokens
		case "1h":
			cacheWrite1h += detail.InputTokens
		}
	}

	// Preserve any aggregate tokens not represented by a recognized TTL as
	// default (5-minute) writes. This also keeps older Bedrock responses, which
	// expose only cacheWriteInputTokens, backward compatible.
	if classified := cacheWrite5m + cacheWrite1h; aggregate > classified {
		cacheWrite5m += aggregate - classified
	}
	return cacheWrite5m, cacheWrite1h
}

// Adjust applies no post-calculation correction; Bedrock prices purely per token.
func (c *BedrockCalculator) Adjust(baseCost float64, _ Usage, _ ModelPricing) float64 {
	return baseCost
}

// fees splits the cache-write aggregate into its 5-minute and 1-hour buckets.
func (c *BedrockCalculator) fees(fields fieldLookups, current Usage) Usage {
	raw, ok := fields.Response("cacheDetails")
	if !ok {
		return current
	}

	cacheWrite5m, cacheWrite1h := bedrockCacheWritesByTTL(bedrockCacheDetailsFrom(raw), current.CacheWriteTokens)

	current.CacheWriteTokens = cacheWrite5m
	current.CacheWrite1hrTokens = cacheWrite1h
	return current
}

// bedrockCacheDetailsFrom walks the entries the template located.
func bedrockCacheDetailsFrom(raw interface{}) []bedrockCacheDetail {
	entries, ok := raw.([]interface{})
	if !ok {
		return nil
	}
	details := make([]bedrockCacheDetail, 0, len(entries))
	for _, entry := range entries {
		fields, ok := entry.(map[string]interface{})
		if !ok {
			continue
		}
		ttl, _ := fields["ttl"].(string)
		tokens, _ := fields["inputTokens"].(float64)
		details = append(details, bedrockCacheDetail{TTL: ttl, InputTokens: int64(tokens)})
	}
	return details
}
