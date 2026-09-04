/*
 * Copyright (c) 2026, WSO2 LLC. (https://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
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

package costbasedrouting

import (
	"context"
	"testing"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

func TestPatternBudgetSelection(t *testing.T) {
	params := wildcardParams("other")
	entries := params["modelBudgets"].([]interface{})
	for _, pattern := range []string{"gpt-*", "gpt-5*", "*-5.5"} {
		entries = append(entries, map[string]interface{}{
			"name": pattern, "model": map[string]interface{}{"modelName": pattern},
			"budgetLimits": []interface{}{map[string]interface{}{"amount": 1.0, "duration": "24h"}},
		})
	}
	params["modelBudgets"] = entries
	p := newPolicy(t, params)
	for _, tc := range []struct{ requested, route string }{
		{"gpt-4o", "premium"}, {"gpt-5.5", "gpt-5*"}, {"gpt-new", "gpt-*"}, {"claude-new", "unlisted-budget"},
	} {
		selection, failure := p.selectTarget(context.Background(), tc.requested)
		if failure != nil || selection.routeName != tc.route || selection.target.Model != tc.requested {
			t.Fatalf("%s: selection=%+v failure=%+v", tc.requested, selection, failure)
		}
	}
}

func TestPatternSharedBudgetDoesNotEscapeToCatchAll(t *testing.T) {
	params := wildcardParams("gpt-*")
	params["onExhausted"] = "reject"
	params["modelBudgets"] = append(params["modelBudgets"].([]interface{}), map[string]interface{}{
		"name": "catch-all", "model": map[string]interface{}{"modelName": "*"},
		"budgetLimits": []interface{}{map[string]interface{}{"amount": 100.0, "duration": "24h"}},
	})
	p := newPolicy(t, params)
	for _, name := range []string{"gpt-new", "gpt-another"} {
		_, metadata := requestHeaders(p, "/chat/completions", nil)
		mods := bodyMods(t, requestBody(p, metadata, []byte(`{"model":"`+name+`"}`)))
		if payloadModel(t, mods.Body) != name {
			t.Fatal("pattern rewrote requested model")
		}
		completeResponse(p, metadata, "1", llmCostStatusCalculated)
	}
	if _, failure := p.selectTarget(context.Background(), "gpt-third"); failure == nil {
		t.Fatal("exhausted pattern escaped to catch-all")
	}
}

func TestPatternFallbackAndValidation(t *testing.T) {
	params := wildcardParams("gpt-*")
	params["fallback"] = map[string]interface{}{"modelName": "gpt-4o-mini"}
	p := newPolicy(t, params)
	_, metadata := requestHeaders(p, "/chat/completions", nil)
	bodyMods(t, requestBody(p, metadata, []byte(`{"model":"gpt-new"}`)))
	completeResponse(p, metadata, "2", llmCostStatusCalculated)
	_, metadata = requestHeaders(p, "/chat/completions", nil)
	mods := bodyMods(t, requestBody(p, metadata, []byte(`{"model":"gpt-next"}`)))
	if payloadModel(t, mods.Body) != "gpt-4o-mini" {
		t.Fatal("did not use exact fallback budget")
	}
	completeResponse(p, metadata, "5", llmCostStatusCalculated)
	if _, failure := p.selectTarget(context.Background(), "gpt-next"); failure == nil {
		t.Fatal("exhausted fallback was reused")
	}
	params["fallback"] = map[string]interface{}{"modelName": "gpt-*"}
	if _, err := GetPolicy(policy.PolicyMetadata{}, params); err == nil {
		t.Fatal("accepted pattern fallback")
	}
}
