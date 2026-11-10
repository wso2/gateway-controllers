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

// Package subscriptiontokenratelimit enforces a subscription plan's token-count condition,
// counting the LLM tokens of each response per subscription.
package subscriptiontokenratelimit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"strings"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
	ratelimit "github.com/wso2/gateway-controllers/policies/advanced-ratelimit"
)

const (
	// The LLM provider template lookup token-based-ratelimit uses.
	resourceTypeLlmProviderTemplate     = "LlmProviderTemplate"
	resourceTypeProviderTemplateMapping = "ProviderTemplateMapping"
	metadataKeyProviderName             = "provider_name"

	// Carries the delegate used on the request to its response phases.
	metadataKeyDelegate = "subscription-token-ratelimit:delegate"

	faultMessage = "Subscription plan token limit exceeded"
)

// SubscriptionTokenRateLimitPolicy counts LLM tokens against the plan's token-count condition.
type SubscriptionTokenRateLimitPolicy struct {
	metadata     policy.PolicyMetadata
	systemParams map[string]interface{}
	cache        delegateCache
}

// GetPolicy is the v1alpha2 factory entry point.
func GetPolicy(metadata policy.PolicyMetadata, params map[string]interface{}) (policy.Policy, error) {
	return &SubscriptionTokenRateLimitPolicy{
		metadata:     metadata,
		systemParams: pickSystemParams(params),
	}, nil
}

// Mode returns the processing mode for this policy. Tokens are read from the response.
func (p *SubscriptionTokenRateLimitPolicy) Mode() policy.ProcessingMode {
	return policy.ProcessingMode{
		RequestHeaderMode:  policy.HeaderModeProcess,
		RequestBodyMode:    policy.BodyModeSkip,
		ResponseHeaderMode: policy.HeaderModeProcess,
		ResponseBodyMode:   policy.BodyModeStream,
	}
}

// OnRequestHeaders rejects a request whose token quota is already used up, and selects the
// delegate that counts the response's tokens.
func (p *SubscriptionTokenRateLimitPolicy) OnRequestHeaders(ctx context.Context, reqCtx *policy.RequestHeaderContext,
	_ map[string]interface{}) policy.RequestHeaderAction {
	if reqCtx == nil {
		return nil
	}
	plan, ok := readSubscriptionPlan(reqCtx.SharedContext)
	if !ok {
		slog.Debug("subscription-token-ratelimit: no subscription in metadata (subscription-validation v2 must run first); not limiting",
			"route", p.metadata.RouteName)
		return nil
	}
	cond, ok := plan.condition(conditionTypeTokenCount)
	if !ok {
		return nil
	}
	ec, err := resolveCondition(cond)
	if err != nil {
		slog.Warn("subscription-token-ratelimit: not limiting", "error", err, "planId", plan.PlanID)
		return nil
	}

	providerName, _ := reqCtx.Metadata[metadataKeyProviderName].(string)
	if providerName == "" {
		slog.Debug("subscription-token-ratelimit: provider name not in metadata; not limiting",
			"route", p.metadata.RouteName)
		return nil
	}
	template := providerTemplate(providerName)
	if template == nil {
		return nil
	}
	sources := tokenCostSources(template, ec.TokenType)
	if len(sources) == 0 {
		slog.Warn("subscription-token-ratelimit: provider template defines no token usage for the token type; not limiting",
			"provider", providerName, "tokenType", ec.TokenType)
		return nil
	}

	key := delegateCacheKey(plan.PlanID, ec, providerName+":"+resourceHash(template))
	slot := delegateSlot(plan.PlanID, ec, providerName)
	delegate, err := p.cache.get(slot, key, func() (policy.Policy, error) {
		costExtraction := map[string]interface{}{"enabled": true, "sources": sources}
		return ratelimit.GetPolicy(delegateMetadata(p.metadata, slot), delegateParams(ec, costExtraction, p.systemParams))
	})
	if err != nil {
		slog.Warn("subscription-token-ratelimit: failed to build limiter; not limiting", "error", err, "planId", plan.PlanID)
		return nil
	}
	reqCtx.Metadata[metadataKeyDelegate] = key

	if resp := checkLimit(ctx, reqCtx, delegate, ec, plan.SubscriptionID, "tokens", faultMessage); resp != nil {
		return *resp
	}
	return nil
}

// requestDelegate returns the delegate chosen for this request, if any.
func (p *SubscriptionTokenRateLimitPolicy) requestDelegate(shared *policy.SharedContext) (policy.Policy, bool) {
	if shared == nil {
		return nil, false
	}
	key, _ := shared.Metadata[metadataKeyDelegate].(string)
	if key == "" {
		return nil, false
	}
	return p.cache.load(key)
}

// OnResponseHeaders lets the delegate prepare token counting and add its rate-limit headers.
func (p *SubscriptionTokenRateLimitPolicy) OnResponseHeaders(ctx context.Context, respCtx *policy.ResponseHeaderContext,
	params map[string]interface{}) policy.ResponseHeaderAction {
	type responseHeaderPolicer interface {
		OnResponseHeaders(context.Context, *policy.ResponseHeaderContext, map[string]interface{}) policy.ResponseHeaderAction
	}
	if respCtx == nil {
		return nil
	}
	if d, ok := p.requestDelegate(respCtx.SharedContext); ok {
		if rl, ok := d.(responseHeaderPolicer); ok {
			return rl.OnResponseHeaders(ctx, respCtx, params)
		}
	}
	return nil
}

// OnResponseBodyChunk lets the delegate count tokens of a streamed response.
func (p *SubscriptionTokenRateLimitPolicy) OnResponseBodyChunk(ctx context.Context, respCtx *policy.ResponseStreamContext,
	chunk *policy.StreamBody, params map[string]interface{}) policy.StreamingResponseAction {
	type responseChunkPolicer interface {
		OnResponseBodyChunk(context.Context, *policy.ResponseStreamContext, *policy.StreamBody, map[string]interface{}) policy.StreamingResponseAction
	}
	if respCtx != nil {
		if d, ok := p.requestDelegate(respCtx.SharedContext); ok {
			if rl, ok := d.(responseChunkPolicer); ok {
				return rl.OnResponseBodyChunk(ctx, respCtx, chunk, params)
			}
		}
	}
	return policy.ForwardResponseChunk{}
}

// NeedsMoreResponseData is false: the delegate buffers what it needs.
func (p *SubscriptionTokenRateLimitPolicy) NeedsMoreResponseData(_ []byte) bool {
	return false
}

// OnResponseBody lets the delegate count tokens of a buffered response.
func (p *SubscriptionTokenRateLimitPolicy) OnResponseBody(ctx context.Context, respCtx *policy.ResponseContext,
	params map[string]interface{}) policy.ResponseAction {
	type responseBodyPolicer interface {
		OnResponseBody(context.Context, *policy.ResponseContext, map[string]interface{}) policy.ResponseAction
	}
	if respCtx == nil {
		return nil
	}
	if d, ok := p.requestDelegate(respCtx.SharedContext); ok {
		if rl, ok := d.(responseBodyPolicer); ok {
			return rl.OnResponseBody(ctx, respCtx, params)
		}
	}
	return nil
}

// providerTemplate returns the LLM provider template mapped to the provider, or nil.
func providerTemplate(providerName string) map[string]interface{} {
	store := policy.GetLazyResourceStoreInstance()
	mapping, err := store.GetResourceByIDAndType(providerName, resourceTypeProviderTemplateMapping)
	if err != nil || mapping == nil {
		slog.Warn("subscription-token-ratelimit: provider template mapping not found; not limiting",
			"provider", providerName, "error", err)
		return nil
	}
	handle, _ := mapping.Resource["template_handle"].(string)
	if handle == "" {
		slog.Warn("subscription-token-ratelimit: template_handle missing in mapping; not limiting", "provider", providerName)
		return nil
	}
	template, err := store.GetResourceByIDAndType(handle, resourceTypeLlmProviderTemplate)
	if err != nil || template == nil {
		slog.Warn("subscription-token-ratelimit: LLM provider template not found; not limiting",
			"provider", providerName, "templateHandle", handle, "error", err)
		return nil
	}
	return template.Resource
}

// tokenCostSources maps the token type to cost sources from the template, as
// token-based-ratelimit does. total falls back to prompt + completion when the template has no
// total.
func tokenCostSources(template map[string]interface{}, tokenType string) []interface{} {
	spec, _ := template["spec"].(map[string]interface{})
	if spec == nil {
		return nil
	}
	var groups [][]string
	switch tokenType {
	case "prompt":
		groups = [][]string{{"promptTokens"}}
	case "completion":
		groups = [][]string{{"completionTokens"}}
	default:
		if tokenType != "total" {
			slog.Warn("subscription-token-ratelimit: unknown tokenType; counting total tokens", "tokenType", tokenType)
		}
		groups = [][]string{{"totalTokens"}, {"promptTokens", "completionTokens"}}
	}
	for _, group := range groups {
		var sources []interface{}
		for _, field := range group {
			if s := costSource(spec, field); s != nil {
				sources = append(sources, s)
			}
		}
		if len(sources) > 0 {
			if len(sources) < len(group) {
				slog.Warn("subscription-token-ratelimit: template defines only part of prompt+completion; total will undercount",
					"expectedFields", group)
			}
			return sources
		}
	}
	return nil
}

// costSource maps one template usage field to an advanced-ratelimit cost source.
func costSource(spec map[string]interface{}, field string) map[string]interface{} {
	usage, ok := spec[field].(map[string]interface{})
	if !ok {
		return nil
	}
	path, _ := usage["identifier"].(string)
	if path == "" {
		return nil
	}
	location, _ := usage["location"].(string)
	switch strings.ToLower(location) {
	case "header":
		return map[string]interface{}{"type": "request_header", "key": path}
	case "metadata":
		return map[string]interface{}{"type": "metadata", "key": path}
	default:
		return map[string]interface{}{"type": "response_body", "jsonPath": path}
	}
}

// resourceHash identifies a template version, so a changed template gets a new delegate.
func resourceHash(resource map[string]interface{}) string {
	b, err := json.Marshal(resource)
	if err != nil {
		return "unhashable"
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])[:16]
}
