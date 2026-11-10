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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

// This file is copied into each subscription limit policy (subscription-request-ratelimit,
// subscription-tool-ratelimit, subscription-token-ratelimit); every copy is identical apart from
// the package clause. Fix a bug in all of them.

// Metadata subscription-validation v2 writes on a validated request.
const (
	metadataKeySubscriptionID = "x-wso2-subscription-id"
	metadataKeyPlanID         = "x-wso2-subscription-plan-id"
	metadataKeyPlanConditions = "x-wso2-subscription-plan-conditions"
)

// Plan condition types.
const (
	conditionTypeRequestCount  = "request-count"
	conditionTypeEventCount    = "event-count"
	conditionTypeToolCallCount = "tool-call-count"
	conditionTypeTokenCount    = "token-count"
)

const (
	onExceedReject = "reject"
	onExceedAllow  = "allow"

	// A month window is 30 days, as subscription-validation v1 counted it.
	monthDuration = 30 * 24 * time.Hour
)

// systemParamKeys are the advanced-ratelimit system parameters passed to every delegate.
var systemParamKeys = []string{"algorithm", "backend", "redis", "memory", "local"}

// planCondition is one condition of the subscription's plan, as recorded in the metadata.
type planCondition struct {
	ID     string          `json:"id"`
	Type   string          `json:"type"`
	Params json.RawMessage `json:"params,omitempty"`
}

// subscriptionPlan is the subscription and plan subscription-validation v2 recorded.
type subscriptionPlan struct {
	SubscriptionID string
	PlanID         string
	Conditions     []planCondition
}

// readSubscriptionPlan reads the subscription recorded by subscription-validation v2. False when
// no subscription was recorded, meaning v2 did not run before this policy.
func readSubscriptionPlan(shared *policy.SharedContext) (subscriptionPlan, bool) {
	if shared == nil || shared.Metadata == nil {
		return subscriptionPlan{}, false
	}
	subID, _ := shared.Metadata[metadataKeySubscriptionID].(string)
	if subID == "" {
		return subscriptionPlan{}, false
	}
	plan := subscriptionPlan{SubscriptionID: subID}
	plan.PlanID, _ = shared.Metadata[metadataKeyPlanID].(string)
	if raw, _ := shared.Metadata[metadataKeyPlanConditions].(string); raw != "" {
		if err := json.Unmarshal([]byte(raw), &plan.Conditions); err != nil {
			slog.Warn("subscription limit: plan conditions in metadata are not valid JSON; not limiting",
				"error", err)
			plan.Conditions = nil
		}
	}
	return plan, true
}

// condition returns the plan's first condition of the given type.
func (s subscriptionPlan) condition(conditionType string) (planCondition, bool) {
	for _, c := range s.Conditions {
		if c.Type == conditionType {
			return c, true
		}
	}
	return planCondition{}, false
}

// limitWindow is one window of a limit condition as the plan states it.
type limitWindow struct {
	Count      int64  `json:"count"`
	TimeAmount int    `json:"timeAmount"`
	TimeUnit   string `json:"timeUnit"`
}

// conditionParams are the params of a limit condition.
type conditionParams struct {
	Limits    []limitWindow `json:"limits"`
	OnExceed  string        `json:"onExceed"`
	TokenType string        `json:"tokenType"`
}

// window is a limit with its resolved duration.
type window struct {
	Count    int64
	Duration time.Duration
}

// enforcedCondition is a limit condition ready to enforce.
type enforcedCondition struct {
	ID        string
	Type      string
	Windows   []window
	Reject    bool
	TokenType string
	// Signature identifies the limits (and token type); it changes when the plan's limits do.
	Signature string
}

// resolveCondition parses a limit condition. Invalid windows are skipped; an error means
// nothing is left to enforce.
func resolveCondition(c planCondition) (enforcedCondition, error) {
	var params conditionParams
	if len(c.Params) > 0 {
		if err := json.Unmarshal(c.Params, &params); err != nil {
			return enforcedCondition{}, fmt.Errorf("invalid params of condition %q: %w", c.ID, err)
		}
	}

	ec := enforcedCondition{ID: c.ID, Type: c.Type, Reject: true}
	if ec.ID == "" {
		ec.ID = c.Type
	}
	switch strings.ToLower(strings.TrimSpace(params.OnExceed)) {
	case "", onExceedReject:
	case onExceedAllow:
		ec.Reject = false
	default:
		slog.Warn("subscription limit: unknown onExceed; rejecting", "condition", ec.ID, "onExceed", params.OnExceed)
	}
	if c.Type == conditionTypeTokenCount {
		ec.TokenType = strings.ToLower(strings.TrimSpace(params.TokenType))
		if ec.TokenType == "" {
			ec.TokenType = "total"
		}
	}

	var sig strings.Builder
	sig.WriteString(ec.Type + "|" + ec.TokenType)
	for _, l := range params.Limits {
		d := windowDuration(l.TimeAmount, l.TimeUnit)
		if l.Count <= 0 || d <= 0 {
			slog.Warn("subscription limit: skipping invalid window",
				"condition", ec.ID, "count", l.Count, "timeAmount", l.TimeAmount, "timeUnit", l.TimeUnit)
			continue
		}
		ec.Windows = append(ec.Windows, window{Count: l.Count, Duration: d})
		fmt.Fprintf(&sig, "|%d/%s", l.Count, d)
	}
	if len(ec.Windows) == 0 {
		return enforcedCondition{}, fmt.Errorf("condition %q has no valid limit", ec.ID)
	}
	sum := sha256.Sum256([]byte(sig.String()))
	ec.Signature = hex.EncodeToString(sum[:])[:16]
	return ec, nil
}

// windowDuration converts a plan window to a duration. A missing or zero amount is 1.
func windowDuration(amount int, unit string) time.Duration {
	if amount <= 0 {
		amount = 1
	}
	var base time.Duration
	switch strings.ToUpper(strings.TrimSpace(unit)) {
	case "MINUTE":
		base = time.Minute
	case "HOUR":
		base = time.Hour
	case "DAY":
		base = 24 * time.Hour
	case "MONTH":
		base = monthDuration
	default:
		return 0
	}
	return time.Duration(amount) * base
}

// pickSystemParams keeps the advanced-ratelimit system parameters from the policy params.
func pickSystemParams(params map[string]interface{}) map[string]interface{} {
	out := make(map[string]interface{})
	for _, k := range systemParamKeys {
		if v, ok := params[k]; ok {
			out[k] = v
		}
	}
	return out
}

// delegateParams builds the advanced-ratelimit params for a condition: one quota whose windows are
// the condition's, counted per subscription. costExtraction is optional.
func delegateParams(ec enforcedCondition, costExtraction map[string]interface{}, systemParams map[string]interface{}) map[string]interface{} {
	limits := make([]interface{}, 0, len(ec.Windows))
	for _, w := range ec.Windows {
		limits = append(limits, map[string]interface{}{
			"limit":    float64(w.Count),
			"duration": w.Duration.String(),
		})
	}
	quota := map[string]interface{}{
		"name":   ec.ID,
		"limits": limits,
		// apiname shares the in-memory counter across the API's routes; the constant keeps the
		// condition's keys apart from other limits in a shared Redis.
		"keyExtraction": []interface{}{
			map[string]interface{}{"type": "apiname"},
			map[string]interface{}{"type": "constant", "key": "subscription:" + ec.ID + ":" + ec.Signature},
			map[string]interface{}{"type": "metadata", "key": metadataKeySubscriptionID},
		},
	}
	if costExtraction != nil {
		quota["costExtraction"] = costExtraction
	}
	out := map[string]interface{}{"quotas": []interface{}{quota}}
	for k, v := range systemParams {
		out[k] = v
	}
	return out
}

// delegateCacheKey identifies a delegate: a plan's condition with given limits.
func delegateCacheKey(planID string, ec enforcedCondition, extra string) string {
	key := ec.Type + "|" + planID + "|" + ec.Signature
	if extra != "" {
		key += "|" + extra
	}
	return key
}

// delegateSlot names a plan's condition without its limits. All delegates of a slot share one
// route name, so when the plan's limits change advanced-ratelimit closes the old limiters.
func delegateSlot(planID string, ec enforcedCondition, extra string) string {
	slot := ec.Type + "|" + planID + "|" + ec.ID
	if extra != "" {
		slot += "|" + extra
	}
	return slot
}

// delegateMetadata gives each slot its own route name, so advanced-ratelimit does not treat
// another plan's limiter on the same route as stale and close it.
func delegateMetadata(m policy.PolicyMetadata, slot string) policy.PolicyMetadata {
	m.RouteName = m.RouteName + "#subscription:" + slot
	return m
}

// delegateCache holds one advanced-ratelimit delegate per cache key, and only the newest one of
// each slot: a plan whose limits changed drops the delegate of its old limits.
type delegateCache struct {
	delegates sync.Map          // cache key -> policy.Policy
	mu        sync.Mutex        // serializes building, so each key is built once
	current   map[string]string // slot -> cache key of its newest delegate; guarded by mu
}

// get returns the cached delegate for key, building it once. Building one for a slot that had
// another key drops that key's delegate; requests already holding it still finish with it.
func (c *delegateCache) get(slot, key string, build func() (policy.Policy, error)) (policy.Policy, error) {
	if d, ok := c.delegates.Load(key); ok {
		return d.(policy.Policy), nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if d, ok := c.delegates.Load(key); ok {
		return d.(policy.Policy), nil
	}
	d, err := build()
	if err != nil {
		return nil, err
	}
	if d == nil {
		return nil, errors.New("delegate is nil")
	}
	c.delegates.Store(key, d)
	if c.current == nil {
		c.current = map[string]string{}
	}
	if prev, ok := c.current[slot]; ok && prev != key {
		c.delegates.Delete(prev)
	}
	c.current[slot] = key
	return d, nil
}

// load returns a delegate built earlier.
func (c *delegateCache) load(key string) (policy.Policy, bool) {
	d, ok := c.delegates.Load(key)
	if !ok {
		return nil, false
	}
	return d.(policy.Policy), true
}

type requestHeaderPolicer interface {
	OnRequestHeaders(context.Context, *policy.RequestHeaderContext, map[string]interface{}) policy.RequestHeaderAction
}

// checkLimit runs the delegate's header-phase check. It returns the 429 to send, or nil to let
// the request through; with onExceed allow an exceeded limit is logged and let through.
func checkLimit(ctx context.Context, reqCtx *policy.RequestHeaderContext, delegate policy.Policy,
	ec enforcedCondition, subscriptionID, unit, faultMessage string) *policy.ImmediateResponse {
	rl, ok := delegate.(requestHeaderPolicer)
	if !ok {
		return nil
	}
	immediate, blocked := rl.OnRequestHeaders(ctx, reqCtx, nil).(policy.ImmediateResponse)
	if !blocked {
		return nil
	}
	if !ec.Reject {
		slog.Warn("subscription limit exceeded; onExceed is allow, letting it through",
			"condition", ec.ID, "subscriptionId", subscriptionID, "apiId", reqCtx.APIId)
		return nil
	}
	slog.Debug("subscription limit exceeded", "condition", ec.ID, "subscriptionId", subscriptionID)
	resp := throttledResponse(immediate, unit, faultMessage)
	return &resp
}

var windowParamPattern = regexp.MustCompile(`;w=(\d+)`)

// throttledResponse renders the delegate's rejection the way subscription-validation v1 did:
// the same body, RateLimit/X-RateLimit/Retry-After headers and fault code.
func throttledResponse(delegated policy.ImmediateResponse, unit, faultMessage string) policy.ImmediateResponse {
	h := delegated.Headers
	limit, hasLimit := headerInt(h, "x-ratelimit-limit")
	remaining, _ := headerInt(h, "x-ratelimit-remaining")
	resetUnix, hasReset := headerInt(h, "x-ratelimit-reset")
	var windowSeconds int64
	if m := windowParamPattern.FindStringSubmatch(h["ratelimit-policy"]); m != nil {
		windowSeconds, _ = strconv.ParseInt(m[1], 10, 64)
	}

	message := "Subscription quota exceeded"
	if hasLimit && windowSeconds > 0 {
		message = fmt.Sprintf("Subscription quota exceeded: %d %s per %s", limit, unit,
			describeWindow(time.Duration(windowSeconds)*time.Second))
	}
	body, err := json.Marshal(map[string]string{
		"error":   "rate_limit_exceeded",
		"message": message,
	})
	if err != nil {
		body = []byte(`{"error":"rate_limit_exceeded","message":"subscription quota exceeded"}`)
	}

	headers := map[string]string{"Content-Type": "application/json"}
	if hasLimit {
		if remaining < 0 {
			remaining = 0
		}
		headers["X-RateLimit-Limit"] = strconv.FormatInt(limit, 10)
		headers["X-RateLimit-Remaining"] = strconv.FormatInt(remaining, 10)
		headers["RateLimit-Limit"] = strconv.FormatInt(limit, 10)
		headers["RateLimit-Remaining"] = strconv.FormatInt(remaining, 10)
		if windowSeconds > 0 {
			headers["RateLimit-Policy"] = fmt.Sprintf("%d;w=%d", limit, windowSeconds)
		}
	}
	var resetSeconds int64
	if hasReset {
		resetSeconds = resetUnix - time.Now().Unix()
		if resetSeconds < 0 {
			resetSeconds = 0
		}
		headers["X-RateLimit-Reset"] = strconv.FormatInt(resetUnix, 10)
		headers["X-RateLimit-Full-Quota-Reset"] = strconv.FormatInt(resetUnix, 10)
		headers["RateLimit-Reset"] = strconv.FormatInt(resetSeconds, 10)
		headers["RateLimit-Full-Quota-Reset"] = strconv.FormatInt(resetSeconds, 10)
	}
	retryAfter, hasRetry := headerInt(h, "retry-after")
	if !hasRetry {
		retryAfter = resetSeconds
	}
	if retryAfter < 1 {
		retryAfter = 1
	}
	headers["Retry-After"] = strconv.FormatInt(retryAfter, 10)

	return policy.ImmediateResponse{
		StatusCode: 429,
		Headers:    headers,
		Body:       body,
		IsFault:    true,
		Fault: &policy.FaultDetails{
			Code:      policy.FaultCodeThrottledSubscription,
			Type:      policy.FaultTypeThrottling,
			Direction: policy.DirectionRequest,
			Message:   faultMessage,
		},
	}
}

// headerInt reads an integer header the delegate set; its keys are lower case.
func headerInt(h map[string]string, key string) (int64, bool) {
	v, ok := h[key]
	if !ok {
		return 0, false
	}
	n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
	if err != nil {
		return 0, false
	}
	return n, true
}

// describeWindow renders a window as "1 minute", "6 hours", "1 month" and so on.
func describeWindow(d time.Duration) string {
	plural := func(n int64, unit string) string {
		if n == 1 {
			return "1 " + unit
		}
		return fmt.Sprintf("%d %ss", n, unit)
	}
	switch {
	case d >= monthDuration && d%monthDuration == 0:
		return plural(int64(d/monthDuration), "month")
	case d >= 24*time.Hour && d%(24*time.Hour) == 0:
		return plural(int64(d/(24*time.Hour)), "day")
	case d >= time.Hour && d%time.Hour == 0:
		return plural(int64(d/time.Hour), "hour")
	case d >= time.Minute && d%time.Minute == 0:
		return plural(int64(d/time.Minute), "minute")
	default:
		return d.String()
	}
}
