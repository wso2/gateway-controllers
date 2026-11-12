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

// Package subscriptionrequestratelimit enforces a subscription plan's request-count condition, per
// subscription.
package subscriptionrequestratelimit

import (
	"context"
	"log/slog"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
	ratelimit "github.com/wso2/gateway-controllers/policies/advanced-ratelimit"
)

// SubscriptionRequestRateLimitPolicy counts each request against the plan's limits.
type SubscriptionRequestRateLimitPolicy struct {
	metadata     policy.PolicyMetadata
	systemParams map[string]interface{}
	cache        delegateCache
}

// GetPolicy is the v1alpha2 factory entry point.
func GetPolicy(metadata policy.PolicyMetadata, params map[string]interface{}) (policy.Policy, error) {
	return &SubscriptionRequestRateLimitPolicy{
		metadata:     metadata,
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

// OnRequestHeaders counts the request against the plan's request-count condition.
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

	cond, ok := plan.condition(conditionTypeRequestCount)
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

	if resp := checkLimit(ctx, reqCtx, delegate, ec, plan.SubscriptionID, "requests", "Subscription plan request limit exceeded"); resp != nil {
		return *resp
	}
	return nil
}
