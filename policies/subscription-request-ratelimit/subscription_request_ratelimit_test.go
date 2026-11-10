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
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

const (
	requestsOneMinute = `{"id":"requests","type":"request-count","params":{"limits":[{"count":%d,"timeAmount":1,"timeUnit":"MINUTE"}],"onExceed":"%s"}}`
)

func newPolicy(t *testing.T, route string, params map[string]interface{}) *SubscriptionRequestRateLimitPolicy {
	t.Helper()
	p, err := GetPolicy(policy.PolicyMetadata{RouteName: route, APIName: t.Name(), AttachedTo: policy.LevelAPI}, params)
	if err != nil {
		t.Fatalf("GetPolicy: %v", err)
	}
	return p.(*SubscriptionRequestRateLimitPolicy)
}

// reqCtx builds a request that subscription-validation v2 has validated.
func reqCtx(t *testing.T, subID, planID, conditions string) *policy.RequestHeaderContext {
	md := map[string]interface{}{}
	if subID != "" {
		md[metadataKeySubscriptionID] = subID
		md[metadataKeyPlanID] = planID
		md[metadataKeyPlanConditions] = conditions
	}
	return &policy.RequestHeaderContext{
		SharedContext: &policy.SharedContext{
			APIId:    "api-1",
			APIName:  t.Name(),
			APIKind:  policy.APIKindRestApi,
			Metadata: md,
		},
		Headers: policy.NewHeaders(nil),
		Scheme:  "https",
		Method:  "GET",
	}
}

func cond(count int, onExceed string) string {
	return "[" + fmt.Sprintf(requestsOneMinute, count, onExceed) + "]"
}

func send(p *SubscriptionRequestRateLimitPolicy, ctx *policy.RequestHeaderContext) policy.RequestHeaderAction {
	return p.OnRequestHeaders(context.Background(), ctx, nil)
}

func assertAllowed(t *testing.T, action policy.RequestHeaderAction, i int) {
	t.Helper()
	if resp, blocked := action.(policy.ImmediateResponse); blocked {
		t.Fatalf("request %d: expected pass-through, got %d %s", i, resp.StatusCode, resp.Body)
	}
}

func assertThrottled(t *testing.T, action policy.RequestHeaderAction) policy.ImmediateResponse {
	t.Helper()
	resp, ok := action.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("expected a 429, got %#v", action)
	}
	if resp.StatusCode != 429 {
		t.Fatalf("status = %d, want 429", resp.StatusCode)
	}
	if !resp.IsFault || resp.Fault == nil || resp.Fault.Code != policy.FaultCodeThrottledSubscription ||
		resp.Fault.Type != policy.FaultTypeThrottling {
		t.Fatalf("unexpected fault %#v", resp.Fault)
	}
	return resp
}

func TestEnforcesRequestCountWindow(t *testing.T) {
	p := newPolicy(t, "r1", nil)
	conds := cond(3, "reject")
	for i := 1; i <= 3; i++ {
		assertAllowed(t, send(p, reqCtx(t, "sub-1", "plan-1", conds)), i)
	}
	resp := assertThrottled(t, send(p, reqCtx(t, "sub-1", "plan-1", conds)))

	if got, want := string(resp.Body), `{"error":"rate_limit_exceeded","message":"Subscription quota exceeded: 3 requests per 1 minute"}`; got != want {
		t.Fatalf("body = %s, want %s", got, want)
	}
	if resp.Fault.Message != "Subscription plan request limit exceeded" {
		t.Fatalf("fault message = %q", resp.Fault.Message)
	}
	for k, want := range map[string]string{
		"X-RateLimit-Limit":     "3",
		"X-RateLimit-Remaining": "0",
		"RateLimit-Limit":       "3",
		"RateLimit-Remaining":   "0",
		"RateLimit-Policy":      "3;w=60",
		"Content-Type":          "application/json",
	} {
		if resp.Headers[k] != want {
			t.Fatalf("header %s = %q, want %q", k, resp.Headers[k], want)
		}
	}
	for _, k := range []string{"X-RateLimit-Reset", "X-RateLimit-Full-Quota-Reset", "RateLimit-Reset", "RateLimit-Full-Quota-Reset", "Retry-After"} {
		if _, err := strconv.ParseInt(resp.Headers[k], 10, 64); err != nil {
			t.Fatalf("header %s = %q is not a number", k, resp.Headers[k])
		}
	}
	if ra, _ := strconv.Atoi(resp.Headers["Retry-After"]); ra < 1 {
		t.Fatalf("Retry-After = %d, want >= 1", ra)
	}
}

func TestStrictestWindowWins(t *testing.T) {
	p := newPolicy(t, "r1", nil)
	conds := `[{"id":"requests","type":"request-count","params":{"limits":[{"count":10,"timeAmount":1,"timeUnit":"MINUTE"},{"count":2,"timeAmount":5,"timeUnit":"HOUR"}]}}]`
	for i := 1; i <= 2; i++ {
		assertAllowed(t, send(p, reqCtx(t, "sub-1", "plan-1", conds)), i)
	}
	resp := assertThrottled(t, send(p, reqCtx(t, "sub-1", "plan-1", conds)))
	if resp.Headers["RateLimit-Policy"] != "2;w=18000" {
		t.Fatalf("RateLimit-Policy = %q, want the 5 hour window", resp.Headers["RateLimit-Policy"])
	}
	if want := `{"error":"rate_limit_exceeded","message":"Subscription quota exceeded: 2 requests per 5 hours"}`; string(resp.Body) != want {
		t.Fatalf("body = %s", resp.Body)
	}
}

func TestOnExceedAllowLetsRequestsThrough(t *testing.T) {
	p := newPolicy(t, "r1", nil)
	conds := cond(1, "allow")
	for i := 1; i <= 5; i++ {
		assertAllowed(t, send(p, reqCtx(t, "sub-1", "plan-1", conds)), i)
	}
}

func TestMissingMetadataPassesThrough(t *testing.T) {
	p := newPolicy(t, "r1", nil)
	for i := 1; i <= 5; i++ {
		assertAllowed(t, send(p, reqCtx(t, "", "", "")), i)
	}
	if action := p.OnRequestHeaders(context.Background(), &policy.RequestHeaderContext{}, nil); action != nil {
		t.Fatalf("expected pass-through without a shared context, got %#v", action)
	}
}

func TestNoMatchingConditionPassesThrough(t *testing.T) {
	p := newPolicy(t, "r1", nil)
	for _, conds := range []string{
		`[]`,
		`[{"id":"tokens","type":"token-count","params":{"limits":[{"count":1,"timeUnit":"MINUTE"}]}}]`,
		`[{"id":"custom-1","type":"custom","params":{"anything":true}}]`,
	} {
		for i := 1; i <= 3; i++ {
			assertAllowed(t, send(p, reqCtx(t, "sub-1", "plan-1", conds)), i)
		}
	}
}

func TestInvalidConditionPassesThrough(t *testing.T) {
	p := newPolicy(t, "r1", nil)
	for _, conds := range []string{
		`not json`,
		`[{"id":"requests","type":"request-count","params":{"limits":[{"count":0,"timeUnit":"MINUTE"}]}}]`,
		`[{"id":"requests","type":"request-count","params":{"limits":[{"count":1,"timeUnit":"WEEK"}]}}]`,
	} {
		for i := 1; i <= 3; i++ {
			assertAllowed(t, send(p, reqCtx(t, "sub-1", "plan-1", conds)), i)
		}
	}
}

// A legacy throttle limit reaches this policy as the condition subscription-validation v2
// converts it to; timeAmount may be absent.
func TestLegacyConvertedCondition(t *testing.T) {
	p := newPolicy(t, "r1", nil)
	conds := `[{"id":"requests","type":"request-count","params":{"limits":[{"count":2,"timeUnit":"MINUTE"}],"onExceed":"reject"}}]`
	assertAllowed(t, send(p, reqCtx(t, "sub-1", "", conds)), 1)
	assertAllowed(t, send(p, reqCtx(t, "sub-1", "", conds)), 2)
	assertThrottled(t, send(p, reqCtx(t, "sub-1", "", conds)))
}

func TestCountersArePerSubscription(t *testing.T) {
	p := newPolicy(t, "r1", nil)
	conds := cond(1, "reject")
	assertAllowed(t, send(p, reqCtx(t, "sub-1", "plan-1", conds)), 1)
	assertThrottled(t, send(p, reqCtx(t, "sub-1", "plan-1", conds)))
	assertAllowed(t, send(p, reqCtx(t, "sub-2", "plan-1", conds)), 1)
	assertThrottled(t, send(p, reqCtx(t, "sub-2", "plan-1", conds)))
}

// The plan's limit applies to the whole API, so routes share the counter.
func TestCounterSharedAcrossRoutes(t *testing.T) {
	p1 := newPolicy(t, "route-a", nil)
	p2 := newPolicy(t, "route-b", nil)
	conds := cond(2, "reject")
	assertAllowed(t, send(p1, reqCtx(t, "sub-1", "plan-1", conds)), 1)
	assertAllowed(t, send(p2, reqCtx(t, "sub-1", "plan-1", conds)), 2)
	assertThrottled(t, send(p1, reqCtx(t, "sub-1", "plan-1", conds)))
	assertThrottled(t, send(p2, reqCtx(t, "sub-1", "plan-1", conds)))
}

func TestPlanChangeAppliesNewLimits(t *testing.T) {
	p := newPolicy(t, "r1", nil)
	assertAllowed(t, send(p, reqCtx(t, "sub-1", "plan-1", cond(1, "reject"))), 1)
	assertThrottled(t, send(p, reqCtx(t, "sub-1", "plan-1", cond(1, "reject"))))

	// The plan now allows 3 a minute.
	for i := 1; i <= 3; i++ {
		assertAllowed(t, send(p, reqCtx(t, "sub-1", "plan-1", cond(3, "reject"))), i)
	}
	assertThrottled(t, send(p, reqCtx(t, "sub-1", "plan-1", cond(3, "reject"))))

	// onExceed changed to allow: same limits, no longer blocking.
	assertAllowed(t, send(p, reqCtx(t, "sub-1", "plan-1", cond(3, "allow"))), 1)

	// Only the limiter of the newest limits is kept.
	if n := cachedDelegates(p); n != 1 {
		t.Fatalf("cached delegates after the plan change = %d, want 1", n)
	}
}

func cachedDelegates(p *SubscriptionRequestRateLimitPolicy) int {
	n := 0
	p.cache.delegates.Range(func(_, _ any) bool { n++; return true })
	return n
}

// Two plans on one route must not evict each other's limiter.
func TestTwoPlansOnOneRoute(t *testing.T) {
	p := newPolicy(t, "r1", nil)
	assertAllowed(t, send(p, reqCtx(t, "sub-1", "plan-1", cond(1, "reject"))), 1)
	assertAllowed(t, send(p, reqCtx(t, "sub-2", "plan-2", cond(5, "reject"))), 1)
	assertThrottled(t, send(p, reqCtx(t, "sub-1", "plan-1", cond(1, "reject"))))
	if n := cachedDelegates(p); n != 2 {
		t.Fatalf("cached delegates for two plans = %d, want 2", n)
	}
}

const eventAndRequestConditions = `[
	{"id":"requests","type":"request-count","params":{"limits":[{"count":100,"timeUnit":"MINUTE"}]}},
	{"id":"events","type":"event-count","params":{"limits":[{"count":1,"timeUnit":"MINUTE"}]}}
]`

func TestEventGatewayCountsEvents(t *testing.T) {
	p := newPolicy(t, "r1", nil)
	event := func() *policy.RequestHeaderContext {
		c := reqCtx(t, "sub-1", "plan-1", eventAndRequestConditions)
		c.Scheme = "event"
		c.APIKind = policy.APIKindWebSubApi
		return c
	}
	assertAllowed(t, send(p, event()), 1)
	resp := assertThrottled(t, send(p, event()))
	if resp.Fault.Message != "Subscription plan event limit exceeded" {
		t.Fatalf("fault message = %q", resp.Fault.Message)
	}
	if want := `{"error":"rate_limit_exceeded","message":"Subscription quota exceeded: 1 events per 1 minute"}`; string(resp.Body) != want {
		t.Fatalf("body = %s", resp.Body)
	}
	// A plain HTTP request is counted against request-count.
	assertAllowed(t, send(p, reqCtx(t, "sub-1", "plan-1", eventAndRequestConditions)), 1)
}

func TestWebSubApiKindCountsEvents(t *testing.T) {
	p := newPolicy(t, "r1", nil)
	c := func() *policy.RequestHeaderContext {
		c := reqCtx(t, "sub-1", "plan-1", eventAndRequestConditions)
		c.APIKind = policy.APIKindWebSubApi
		return c
	}
	assertAllowed(t, send(p, c()), 1)
	assertThrottled(t, send(p, c()))
}

func TestEventApiWithoutEventConditionPassesThrough(t *testing.T) {
	p := newPolicy(t, "r1", nil)
	for i := 1; i <= 3; i++ {
		c := reqCtx(t, "sub-1", "plan-1", cond(1, "reject"))
		c.Scheme = "event"
		assertAllowed(t, send(p, c), i)
	}
}

func TestCountAsOverride(t *testing.T) {
	asRequest := newPolicy(t, "r1", map[string]interface{}{"countAs": "request"})
	for i := 1; i <= 3; i++ {
		c := reqCtx(t, "sub-1", "plan-1", eventAndRequestConditions)
		c.Scheme = "event"
		assertAllowed(t, send(asRequest, c), i)
	}

	asEvent := newPolicy(t, "r2", map[string]interface{}{"countAs": "event"})
	assertAllowed(t, send(asEvent, reqCtx(t, "sub-9", "plan-1", eventAndRequestConditions)), 1)
	assertThrottled(t, send(asEvent, reqCtx(t, "sub-9", "plan-1", eventAndRequestConditions)))

	if _, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{"countAs": "message"}); err == nil {
		t.Fatalf("expected an invalid countAs to be rejected")
	}
}

func TestWindowDuration(t *testing.T) {
	for _, tc := range []struct {
		amount int
		unit   string
		want   time.Duration
	}{
		{0, "MINUTE", time.Minute},
		{1, "minute", time.Minute},
		{15, "MINUTE", 15 * time.Minute},
		{2, "HOUR", 2 * time.Hour},
		{1, "DAY", 24 * time.Hour},
		{1, "MONTH", 30 * 24 * time.Hour},
		{3, "MONTH", 90 * 24 * time.Hour},
		{1, "WEEK", 0},
	} {
		if got := windowDuration(tc.amount, tc.unit); got != tc.want {
			t.Errorf("windowDuration(%d, %q) = %s, want %s", tc.amount, tc.unit, got, tc.want)
		}
	}
}

func TestResolveConditionDefaults(t *testing.T) {
	ec, err := resolveCondition(planCondition{ID: "tokens", Type: conditionTypeTokenCount,
		Params: json.RawMessage(`{"limits":[{"count":5,"timeUnit":"DAY"}]}`)})
	if err != nil {
		t.Fatal(err)
	}
	if !ec.Reject || ec.TokenType != "total" || len(ec.Windows) != 1 || ec.Windows[0].Duration != 24*time.Hour {
		t.Fatalf("unexpected %+v", ec)
	}
	other, _ := resolveCondition(planCondition{ID: "tokens", Type: conditionTypeTokenCount,
		Params: json.RawMessage(`{"limits":[{"count":6,"timeUnit":"DAY"}],"onExceed":"allow"}`)})
	if other.Signature == ec.Signature || other.Reject {
		t.Fatalf("expected a new signature for new limits and allow, got %+v", other)
	}
}

// With a shared Redis, two gateway replicas (two policy instances) count together.
func TestRedisBackendSharesCounter(t *testing.T) {
	mr := miniredis.RunT(t)
	port, _ := strconv.Atoi(mr.Port())
	params := map[string]interface{}{
		"backend": "redis",
		"redis":   map[string]interface{}{"host": mr.Host(), "port": float64(port), "failureMode": "closed"},
	}
	replicaA := newPolicy(t, "r1", params)
	replicaB := newPolicy(t, "r1", params)
	conds := cond(2, "reject")
	assertAllowed(t, send(replicaA, reqCtx(t, "sub-1", "plan-1", conds)), 1)
	assertAllowed(t, send(replicaB, reqCtx(t, "sub-1", "plan-1", conds)), 2)
	assertThrottled(t, send(replicaA, reqCtx(t, "sub-1", "plan-1", conds)))
	if len(mr.Keys()) == 0 {
		t.Fatalf("expected counters in Redis")
	}
}
