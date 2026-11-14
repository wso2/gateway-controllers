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
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package subscriptiontokenratelimit

import (
	"reflect"
	"testing"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

func tokenAnalytics(t *testing.T, action policy.RequestHeaderAction) map[string]any {
	t.Helper()
	switch a := action.(type) {
	case policy.UpstreamRequestHeaderModifications:
		return a.AnalyticsMetadata
	case policy.ImmediateResponse:
		return a.AnalyticsMetadata
	case nil:
		return nil
	default:
		t.Fatalf("unexpected action %#v", action)
		return nil
	}
}

// The token quota is checked when a request comes in, before its response's tokens are counted:
// a request is "within" while the quota isn't used up yet, and "over" once it is.
func TestTokenQuotaStatus(t *testing.T) {
	for _, tc := range []struct {
		onExceed, action string
		blocks           bool
	}{
		{"reject", "rejected", true},
		{"allow", "allowed", false},
	} {
		t.Run(tc.onExceed, func(t *testing.T) {
			storeTemplate(t, "openai", openAISpec())
			p := newPolicy(t)
			conds := tokenConditions(80, "total", tc.onExceed)
			first := call(t, p, "sub-1", "openai", conds, usageBody) // uses all 80 tokens
			if got := tokenAnalytics(t, first); !reflect.DeepEqual(got, map[string]any{"x-wso2-subscription-quota-status-tokens": "within"}) {
				t.Fatalf("first call analytics = %#v", got)
			}
			second := call(t, p, "sub-1", "openai", conds, usageBody)
			if isBlocked(second) != tc.blocks {
				t.Fatalf("blocked = %v, want %v", isBlocked(second), tc.blocks)
			}
			got := tokenAnalytics(t, second)
			if got["x-wso2-subscription-quota-status-tokens"] != "over" || got["x-wso2-subscription-quota-action-tokens"] != tc.action {
				t.Fatalf("second call analytics = %#v", got)
			}
		})
	}
}

func TestTokenQuotaStatusNotSetWithoutSubscription(t *testing.T) {
	storeTemplate(t, "openai", openAISpec())
	p := newPolicy(t)
	if got := tokenAnalytics(t, call(t, p, "", "openai", "", usageBody)); got != nil {
		t.Fatalf("analytics = %#v, want none", got)
	}
}
