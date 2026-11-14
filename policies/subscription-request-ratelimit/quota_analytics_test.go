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

package subscriptionrequestratelimit

import (
	"reflect"
	"testing"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

// analyticsOf returns the analytics metadata an action carries, whether it lets the request through
// or rejects it.
func analyticsOf(t *testing.T, action policy.RequestHeaderAction) map[string]any {
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

func assertAnalytics(t *testing.T, action policy.RequestHeaderAction, want map[string]any) {
	t.Helper()
	if got := analyticsOf(t, action); !reflect.DeepEqual(got, want) {
		t.Fatalf("analytics metadata = %#v, want %#v", got, want)
	}
}

func TestQuotaStatusWithinThenOverRejected(t *testing.T) {
	p := newPolicy(t, "r1", nil)
	conds := cond(2, "reject")
	for i := 1; i <= 2; i++ {
		action := send(p, reqCtx(t, "sub-1", "plan-1", conds))
		assertAllowed(t, action, i)
		assertAnalytics(t, action, map[string]any{"x-wso2-subscription-quota-status-requests": "within"})
	}
	action := send(p, reqCtx(t, "sub-1", "plan-1", conds))
	assertThrottled(t, action)
	assertAnalytics(t, action, map[string]any{
		"x-wso2-subscription-quota-status-requests": "over",
		"x-wso2-subscription-quota-action-requests": "rejected",
		"x-wso2-subscription-quota-limit-requests":  "2 requests per 1 minute",
	})
}

func TestQuotaStatusOverAllowedIsMarkedForOverage(t *testing.T) {
	p := newPolicy(t, "r1", nil)
	conds := cond(1, "allow")
	first := send(p, reqCtx(t, "sub-1", "plan-1", conds))
	assertAllowed(t, first, 1)
	assertAnalytics(t, first, map[string]any{"x-wso2-subscription-quota-status-requests": "within"})
	for i := 2; i <= 3; i++ {
		action := send(p, reqCtx(t, "sub-1", "plan-1", conds))
		assertAllowed(t, action, i)
		assertAnalytics(t, action, map[string]any{
			"x-wso2-subscription-quota-status-requests": "over",
			"x-wso2-subscription-quota-action-requests": "allowed",
			"x-wso2-subscription-quota-limit-requests":  "1 requests per 1 minute",
		})
	}
}

func TestQuotaStatusNamesTheStrictestWindow(t *testing.T) {
	p := newPolicy(t, "r1", nil)
	conds := `[{"id":"requests","type":"request-count","params":{"limits":[{"count":10,"timeAmount":1,"timeUnit":"MINUTE"},{"count":2,"timeAmount":5,"timeUnit":"HOUR"}]}}]`
	for i := 1; i <= 2; i++ {
		send(p, reqCtx(t, "sub-1", "plan-1", conds))
	}
	action := send(p, reqCtx(t, "sub-1", "plan-1", conds))
	if got := analyticsOf(t, action)["x-wso2-subscription-quota-limit-requests"]; got != "2 requests per 5 hours" {
		t.Fatalf("limit = %v, want the 5 hour window", got)
	}
}

func TestNoQuotaStatusWhenNothingIsCounted(t *testing.T) {
	p := newPolicy(t, "r1", nil)
	// No subscription: subscription-validation v2 didn't run.
	assertAnalytics(t, send(p, reqCtx(t, "", "", "")), nil)
	// A plan without a request-count condition.
	tools := `[{"id":"tool-calls","type":"tool-call-count","params":{"limits":[{"count":1,"timeUnit":"MINUTE"}]}}]`
	assertAnalytics(t, send(p, reqCtx(t, "sub-1", "plan-1", tools)), nil)
}
