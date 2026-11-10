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

// Package subscriptionvalidation validates that a request has an active subscription to the API.
// v2 only validates: plan limits are enforced by the subscription-*-ratelimit policies, which read
// the subscription and plan this policy records in the request metadata.
package subscriptionvalidation

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
	policyenginev1 "github.com/wso2/api-platform/sdk/core/policyengine"
)

const (
	defaultSubscriptionKeyHeader = "Subscription-Key"
	defaultSubscriptionKeyCookie = ""
	applicationIDMetadataKey     = "x-wso2-application-id"
	forbiddenStatusCode          = 403
	forbiddenMessage             = "Subscription required for this API"

	// Metadata written by v1 as well.
	billingCustomerIDMetadataKey     = "x-wso2-billing-customer-id"
	billingSubscriptionIDMetadataKey = "x-wso2-billing-subscription-id"
	subscriptionStatusMetadataKey    = "x-wso2-subscription-status"
	subscriptionPlanNameMetadataKey  = "x-wso2-subscription-plan-name"

	// Metadata new in v2, read by the subscription-*-ratelimit policies.
	subscriptionIDMetadataKey         = "x-wso2-subscription-id"
	subscriptionPlanIDMetadataKey     = "x-wso2-subscription-plan-id"
	subscriptionConditionsMetadataKey = "x-wso2-subscription-plan-conditions"

	// Condition a legacy throttle limit becomes.
	requestCountConditionID   = "requests"
	requestCountConditionType = "request-count"
)

// PolicyConfig holds the resolved configuration for the subscriptionValidation policy.
type PolicyConfig struct {
	SubscriptionKeyHeader string
	SubscriptionKeyCookie string
}

// SubscriptionValidationPolicy validates that the caller has an active
// subscription for the requested API.
type SubscriptionValidationPolicy struct {
	cfg   PolicyConfig
	store *policyenginev1.SubscriptionStore
}

var ins = &SubscriptionValidationPolicy{
	cfg: PolicyConfig{
		SubscriptionKeyHeader: defaultSubscriptionKeyHeader,
		SubscriptionKeyCookie: defaultSubscriptionKeyCookie,
	},
	store: policyenginev1.GetSubscriptionStoreInstance(),
}

// GetPolicy is the v1alpha2 factory entry point (loaded by v1alpha2 kernels).
func GetPolicy(
	metadata policy.PolicyMetadata,
	params map[string]interface{},
) (policy.Policy, error) {
	return &SubscriptionValidationPolicy{
		cfg:   mergeConfig(ins.cfg, params),
		store: ins.store,
	}, nil
}

// mergeConfig merges raw parameters from the policy configuration into a base config.
func mergeConfig(base PolicyConfig, params map[string]interface{}) PolicyConfig {
	cfg := base
	if params == nil {
		return cfg
	}

	if raw, ok := params["subscriptionKeyHeader"]; ok {
		if s, ok := raw.(string); ok && strings.TrimSpace(s) != "" {
			cfg.SubscriptionKeyHeader = strings.TrimSpace(s)
		}
	}

	if raw, ok := params["subscriptionKeyCookie"]; ok {
		if s, ok := raw.(string); ok {
			cfg.SubscriptionKeyCookie = strings.TrimSpace(s)
		}
	}

	return cfg
}

func normalizeHeaderName(name string) string {
	return strings.ToLower(strings.TrimSpace(name))
}

// stripCookie removes the cookie with the given name from Cookie header values.
// It returns the updated Cookie header (single header value) and whether a removal occurred.
func stripCookie(cookieHeaderValues []string, cookieName string) (string, bool) {
	if cookieName == "" || len(cookieHeaderValues) == 0 {
		return "", false
	}

	parts := make([]string, 0, 8)
	removed := false

	for _, raw := range cookieHeaderValues {
		for _, part := range strings.Split(raw, ";") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			idx := strings.Index(part, "=")
			if idx < 0 {
				parts = append(parts, part)
				continue
			}
			name := strings.TrimSpace(part[:idx])
			if strings.EqualFold(name, cookieName) {
				removed = true
				continue
			}
			parts = append(parts, part)
		}
	}

	if !removed {
		return "", false
	}
	return strings.Join(parts, "; "), true
}

// Mode returns the processing mode for this policy.
func (p *SubscriptionValidationPolicy) Mode() policy.ProcessingMode {
	return policy.ProcessingMode{
		RequestHeaderMode:  policy.HeaderModeProcess,
		RequestBodyMode:    policy.BodyModeSkip,
		ResponseHeaderMode: policy.HeaderModeSkip,
		ResponseBodyMode:   policy.BodyModeSkip,
	}
}

// OnRequestHeaders validates the subscription in the request header phase.
func (p *SubscriptionValidationPolicy) OnRequestHeaders(ctx context.Context, reqCtx *policy.RequestHeaderContext, params map[string]interface{}) policy.RequestHeaderAction {
	if ctx == nil || reqCtx == nil || reqCtx.SharedContext == nil {
		return p.forbiddenResponse("request context is missing", policy.FaultCodeMediationFailed, policy.FaultTypeMediation)
	}

	apiID := reqCtx.APIId
	if strings.TrimSpace(apiID) == "" {
		slog.Error("subscriptionValidation: APIId is empty in SharedContext; failing validation")
		return p.forbiddenResponse("API id is missing", policy.FaultCodeMediationFailed, policy.FaultTypeMediation)
	}

	if p.store == nil {
		slog.Error("subscriptionValidation: subscription store is not initialized")
		return p.forbiddenResponse("subscription store is not available", policy.FaultCodeMediationFailed, policy.FaultTypeMediation)
	}

	// Decide on what the client sent, not on a header a peer policy rewrote.
	if ds := reqCtx.DownstreamHeaders(); ds != nil {
		headerValues := ds.Get(p.cfg.SubscriptionKeyHeader)
		if len(headerValues) > 0 {
			token := strings.TrimSpace(headerValues[0])
			if token != "" {
				hashed := policyenginev1.HashSubscriptionToken(token)
				entry, ok := p.lookupByToken(apiID, hashed)
				if !ok {
					return p.forbiddenResponse("", policy.FaultCodeSubscriptionInactive, policy.FaultTypeAuthentication)
				}
				writeSubscriptionMetadata(reqCtx.SharedContext, entry, "token:"+hashed)
				return policy.UpstreamRequestHeaderModifications{
					HeadersToRemove: []string{normalizeHeaderName(p.cfg.SubscriptionKeyHeader)},
				}
			}
		}
		if p.cfg.SubscriptionKeyCookie != "" {
			if token := getCookieValue(ds, p.cfg.SubscriptionKeyCookie); token != "" {
				hashed := policyenginev1.HashSubscriptionToken(token)
				entry, ok := p.lookupByToken(apiID, hashed)
				if !ok {
					return p.forbiddenResponse("", policy.FaultCodeSubscriptionInactive, policy.FaultTypeAuthentication)
				}
				writeSubscriptionMetadata(reqCtx.SharedContext, entry, "token:"+hashed)
				// Rewrite the live Cookie header, which is what goes upstream.
				cookieValues := reqCtx.Headers.Get("Cookie")
				updated, removed := stripCookie(cookieValues, p.cfg.SubscriptionKeyCookie)
				if removed {
					if updated == "" {
						return policy.UpstreamRequestHeaderModifications{
							HeadersToRemove: []string{"cookie"},
						}
					}
					return policy.UpstreamRequestHeaderModifications{
						HeadersToSet: map[string]string{"cookie": updated},
					}
				}
				return policy.UpstreamRequestHeaderModifications{}
			}
		}
	}

	metadata := reqCtx.Metadata
	if metadata != nil {
		if rawAppID, ok := metadata[applicationIDMetadataKey]; ok {
			appID := strings.TrimSpace(fmt.Sprint(rawAppID))
			if appID != "" {
				active, entry := p.store.IsActiveByApplication(apiID, appID)
				if !active {
					slog.Info("subscriptionValidation: no active subscription found (appId fallback)",
						"apiId", apiID,
						"applicationId", appID)
					return p.forbiddenResponse("", policy.FaultCodeSubscriptionInactive, policy.FaultTypeAuthentication)
				}
				writeSubscriptionMetadata(reqCtx.SharedContext, entry, "app:"+appID)
				return policy.UpstreamRequestHeaderModifications{}
			}
		}
	}

	return p.forbiddenResponse("no subscription token or application identity provided", policy.FaultCodeAuthMissingCredentials, policy.FaultTypeAuthentication)
}

// lookupByToken returns the active subscription for a hashed token.
func (p *SubscriptionValidationPolicy) lookupByToken(apiID, hashedToken string) (*policyenginev1.SubscriptionEntry, bool) {
	active, entry := p.store.IsActiveByToken(apiID, hashedToken)
	if !active {
		slog.Info("subscriptionValidation: no active subscription found (token)",
			"apiId", apiID)
		return nil, false
	}
	return entry, true
}

// forbiddenResponse constructs an ImmediateResponse with status 403.
func (p *SubscriptionValidationPolicy) forbiddenResponse(detail, code, faultType string) policy.ImmediateResponse {
	message := forbiddenMessage
	if detail != "" {
		message = fmt.Sprintf("%s: %s", message, detail)
	}

	payload := map[string]string{
		"error":   "forbidden",
		"message": message,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		body = []byte(`{"error":"forbidden","message":"subscription validation failed"}`)
	}

	return policy.ImmediateResponse{
		StatusCode: forbiddenStatusCode,
		Headers: map[string]string{
			"Content-Type": "application/json",
		},
		Body:    body,
		IsFault: true,
		Fault: &policy.FaultDetails{
			Code:      code,
			Type:      faultType,
			Direction: policy.DirectionRequest,
			// message already goes to the client as the body message.
			Message: message,
		},
	}
}

// writeSubscriptionMetadata records the subscription and its plan in sc.Metadata for later
// policies. fallbackID identifies the subscription when the gateway synced none.
func writeSubscriptionMetadata(sc *policy.SharedContext, entry *policyenginev1.SubscriptionEntry, fallbackID string) {
	if sc == nil || entry == nil {
		return
	}
	if sc.Metadata == nil {
		sc.Metadata = make(map[string]interface{})
	}
	if entry.BillingCustomerID != nil {
		sc.Metadata[billingCustomerIDMetadataKey] = *entry.BillingCustomerID
	}
	if entry.BillingSubscriptionID != nil {
		sc.Metadata[billingSubscriptionIDMetadataKey] = *entry.BillingSubscriptionID
	}
	if entry.Status != "" {
		sc.Metadata[subscriptionStatusMetadataKey] = entry.Status
	}
	if entry.PlanName != "" {
		sc.Metadata[subscriptionPlanNameMetadataKey] = entry.PlanName
	}

	subscriptionID := entry.SubscriptionID
	if subscriptionID == "" {
		subscriptionID = fallbackID
	}
	sc.Metadata[subscriptionIDMetadataKey] = subscriptionID
	if entry.PlanID != "" {
		sc.Metadata[subscriptionPlanIDMetadataKey] = entry.PlanID
	}
	sc.Metadata[subscriptionConditionsMetadataKey] = conditionsJSON(effectiveConditions(entry))
}

// effectiveConditions returns the plan's conditions. A plan synced before conditions has only a
// legacy throttle limit, which becomes a single request-count condition.
func effectiveConditions(entry *policyenginev1.SubscriptionEntry) []policyenginev1.SubscriptionCondition {
	if len(entry.Conditions) > 0 {
		return entry.Conditions
	}
	if entry.ThrottleLimitCount <= 0 || entry.ThrottleLimitUnit == "" {
		return nil
	}
	unit := legacyTimeUnit(entry.ThrottleLimitUnit)
	if unit == "" {
		slog.Warn("subscriptionValidation: unknown throttle limit unit; plan treated as unlimited",
			"unit", entry.ThrottleLimitUnit)
		return nil
	}
	onExceed := "allow"
	if entry.StopOnQuotaReach {
		onExceed = "reject"
	}
	params, err := json.Marshal(map[string]interface{}{
		"limits": []map[string]interface{}{
			{"count": entry.ThrottleLimitCount, "timeAmount": 1, "timeUnit": unit},
		},
		"onExceed": onExceed,
	})
	if err != nil {
		return nil
	}
	return []policyenginev1.SubscriptionCondition{
		{ID: requestCountConditionID, Type: requestCountConditionType, Params: params},
	}
}

// legacyTimeUnit maps a legacy throttle unit (Min, Hour, Day, Month) to a condition time unit.
func legacyTimeUnit(unit string) string {
	switch strings.ToLower(strings.TrimSpace(unit)) {
	case "min", "minute":
		return "MINUTE"
	case "hour":
		return "HOUR"
	case "day":
		return "DAY"
	case "month":
		return "MONTH"
	default:
		return ""
	}
}

// conditionsJSON renders conditions as a JSON array; no conditions is "[]".
func conditionsJSON(conditions []policyenginev1.SubscriptionCondition) string {
	if len(conditions) == 0 {
		return "[]"
	}
	b, err := json.Marshal(conditions)
	if err != nil {
		slog.Warn("subscriptionValidation: failed to encode plan conditions", "error", err)
		return "[]"
	}
	return string(b)
}

// getCookieValue parses the Cookie header and returns the value for the given cookie name.
// Returns empty string if the cookie is not found or Cookie header is missing.
func getCookieValue(headers *policy.Headers, name string) string {
	if headers == nil || name == "" {
		return ""
	}
	vals := headers.Get("Cookie")
	if len(vals) == 0 {
		return ""
	}
	// Cookie header format: "name1=value1; name2=value2"
	for _, raw := range vals {
		for _, part := range strings.Split(raw, ";") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			idx := strings.Index(part, "=")
			if idx < 0 {
				continue
			}
			cookieName := strings.TrimSpace(part[:idx])
			if strings.EqualFold(cookieName, name) {
				return strings.TrimSpace(part[idx+1:])
			}
		}
	}
	return ""
}
