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
	"context"
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

// erroringLimiter fails closed the way the rate-limit engine does when its store is unreachable.
type erroringLimiter struct{}

func (erroringLimiter) OnRequestHeaders(context.Context, *policy.RequestHeaderContext, map[string]interface{}) policy.RequestHeaderAction {
	return policy.ImmediateResponse{StatusCode: 500, Body: []byte(`{"error":"rate limit store unavailable"}`)}
}

func (erroringLimiter) Mode() policy.ProcessingMode { return policy.ProcessingMode{} }

func TestLimiterErrorIsNotOverage(t *testing.T) {
	reqCtx := &policy.RequestHeaderContext{SharedContext: &policy.SharedContext{APIId: "api-1"}}
	// Reject: the limiter's own error response is kept, with no quota status.
	resp, metadata := checkLimit(context.Background(), reqCtx, erroringLimiter{}, enforcedCondition{ID: "c1", Reject: true}, "sub-1", "requests", "")
	if resp == nil || resp.StatusCode != 500 || len(resp.AnalyticsMetadata) != 0 || metadata != nil {
		t.Fatalf("reject: got %#v, %#v; want the limiter's 500 without quota metadata", resp, metadata)
	}
	// Allow: the request passes, with no quota status.
	resp, metadata = checkLimit(context.Background(), reqCtx, erroringLimiter{}, enforcedCondition{ID: "c1"}, "sub-1", "requests", "")
	if resp != nil || metadata != nil {
		t.Fatalf("allow: got %#v, %#v; want nil, nil", resp, metadata)
	}
}
