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

// Package subscriptionrequestratelimit enforces a subscription plan's request-count condition, or
// its event-count condition on an event API, per subscription.
package subscriptionrequestratelimit

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
	ratelimit "github.com/wso2/gateway-controllers/policies/advanced-ratelimit"
)

const (
	countAsAuto    = "auto"
	countAsRequest = "request"
	countAsEvent   = "event"

	// The event gateway runs the chain once per message with this scheme.
	eventScheme = "event"
)

// SubscriptionRequestRateLimitPolicy counts each request (or event) against the plan's limits.
type SubscriptionRequestRateLimitPolicy struct {
	metadata     policy.PolicyMetadata
	countAs      string
	systemParams map[string]interface{}
	cache        delegateCache
}

// GetPolicy is the v1alpha2 factory entry point.
func GetPolicy(metadata policy.PolicyMetadata, params map[string]interface{}) (policy.Policy, error) {
	countAs := countAsAuto
	if raw, ok := params["countAs"]; ok && raw != nil {
		s, _ := raw.(string)
		switch s = strings.ToLower(strings.TrimSpace(s)); s {
		case countAsAuto, countAsRequest, countAsEvent:
			countAs = s
		default:
			return nil, fmt.Errorf("subscription-request-ratelimit: countAs must be auto, request or event, got %v", raw)
		}
	}
	return &SubscriptionRequestRateLimitPolicy{
		metadata:     metadata,
		countAs:      countAs,
		systemParams: pickSystemParams(params),
	}, nil
}

// Mode returns the processing mode for this policy.
func (p *SubscriptionRequestRateLimitPolicy) Mode() policy.ProcessingMode {
	return policy.ProcessingMode{
		RequestHeaderMode:  policy.HeaderModeProcess,
		RequestBodyMode:    policy.BodyModeSkip,
		ResponseHeaderMode: policy.HeaderModeSkip,
		ResponseBodyMode:   policy.BodyModeSkip,
	}
}

// OnRequestHeaders counts the request, or the event, against the plan's condition.
func (p *SubscriptionRequestRateLimitPolicy) OnRequestHeaders(ctx context.Context, reqCtx *policy.RequestHeaderContext,
	_ map[string]interface{}) policy.RequestHeaderAction {
	if reqCtx == nil {
		return nil
	}
	plan, ok := readSubscriptionPlan(reqCtx.SharedContext)
	if !ok {
		slog.Debug("subscription-request-ratelimit: no subscription in metadata (subscription-validation v2 must run first); not limiting",
			"route", p.metadata.RouteName)
		return nil
	}

	conditionType, unit, faultMessage := conditionTypeRequestCount, "requests", "Subscription plan request limit exceeded"
	if p.countsEvents(reqCtx) {
		conditionType, unit, faultMessage = conditionTypeEventCount, "events", "Subscription plan event limit exceeded"
	}
	cond, ok := plan.condition(conditionType)
	if !ok {
		return nil
	}
	ec, err := resolveCondition(cond)
	if err != nil {
		slog.Warn("subscription-request-ratelimit: not limiting", "error", err, "planId", plan.PlanID)
		return nil
	}

	key := delegateCacheKey(plan.PlanID, ec, "")
	slot := delegateSlot(plan.PlanID, ec, "")
	delegate, err := p.cache.get(slot, key, func() (policy.Policy, error) {
		return ratelimit.GetPolicy(delegateMetadata(p.metadata, slot), delegateParams(ec, nil, p.systemParams))
	})
	if err != nil {
		slog.Warn("subscription-request-ratelimit: failed to build limiter; not limiting", "error", err, "planId", plan.PlanID)
		return nil
	}

	if resp := checkLimit(ctx, reqCtx, delegate, ec, plan.SubscriptionID, unit, faultMessage); resp != nil {
		return *resp
	}
	return nil
}

// countsEvents reports whether this execution is one event rather than one request.
func (p *SubscriptionRequestRateLimitPolicy) countsEvents(reqCtx *policy.RequestHeaderContext) bool {
	switch p.countAs {
	case countAsEvent:
		return true
	case countAsRequest:
		return false
	}
	if strings.EqualFold(reqCtx.Scheme, eventScheme) {
		return true
	}
	return reqCtx.SharedContext != nil && reqCtx.APIKind == policy.APIKindWebSubApi
}
