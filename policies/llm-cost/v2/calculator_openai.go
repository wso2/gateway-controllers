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

// OpenAICalculator handles models with provider "openai".
type OpenAICalculator struct{}

// Adjust applies no post-calculation correction; OpenAI prices purely per token.
func (c *OpenAICalculator) Adjust(baseCost float64, _ Usage, _ ModelPricing) float64 {
	return baseCost
}

// fees detects the web search call and its billed context size.
func (c *OpenAICalculator) fees(fields fieldLookups, current Usage) Usage {
	// One call is billed per completion however many citations come back.
	var webSearchRequests int64
	if raw, ok := fields.Response("choices"); ok && hasURLCitation(raw) {
		webSearchRequests = 1
	}

	// The search depth is only in the request; the response never echoes it.
	var searchContextSize string
	if webSearchRequests > 0 {
		if raw, ok := fields.Request("searchContextSize"); ok {
			searchContextSize, _ = raw.(string)
		}
	}

	current.WebSearchRequests = webSearchRequests
	current.SearchContextSize = searchContextSize
	return current
}

// hasURLCitation looks for the annotation type that marks a web search.
func hasURLCitation(raw interface{}) bool {
	choices, ok := raw.([]interface{})
	if !ok {
		return false
	}
	for _, choice := range choices {
		fields, ok := choice.(map[string]interface{})
		if !ok {
			continue
		}
		message, ok := fields["message"].(map[string]interface{})
		if !ok {
			continue
		}
		annotations, ok := message["annotations"].([]interface{})
		if !ok {
			continue
		}
		for _, annotation := range annotations {
			entry, ok := annotation.(map[string]interface{})
			if ok && entry["type"] == "url_citation" {
				return true
			}
		}
	}
	return false
}
