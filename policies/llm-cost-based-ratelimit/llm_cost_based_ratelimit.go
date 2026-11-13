/*
 * Copyright (c) 2025, WSO2 LLC. (https://www.wso2.com).
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

package llmcostratelimit

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"strconv"
	"sync"
	"time"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
	ratelimit "github.com/wso2/gateway-controllers/policies/advanced-ratelimit"
)

const (
	MetadataKeyProviderName            = "provider_name"
	MetadataKeyDelegate                = "llm_cost_delegate"
	metadataKeyDelegateConsumer        = "llm_cost_delegate_consumer"
	MetadataKeyCostScaleFactor         = "llm_cost_scale_factor"
	metadataKeyCostScaleFactorConsumer = "llm_cost_scale_factor_consumer"

	// DefaultCostScaleFactor is the default scaling factor for dollar amounts.
	// Converts dollars to nano-dollars to preserve precision in int64 counters.
	// $1.00 = 1,000,000,000 nano-dollars
	// Can be overridden via systemParameters.costScaleFactor
	DefaultCostScaleFactor = 1_000_000_000
)

// delegateMetadataKey returns the metadata key for the delegate reference.
// Backend and consumer instances use separate keys to prevent one overwriting the other
// when both are in the same request chain.
func delegateMetadataKey(params map[string]interface{}) string {
	if consumerBased, _ := params["consumerBased"].(bool); consumerBased {
		return metadataKeyDelegateConsumer
	}
	return MetadataKeyDelegate
}

// costScaleFactorMetadataKey returns the metadata key for the cost scale factor.
// Backend and consumer instances use separate keys for the same reason as delegateMetadataKey.
func costScaleFactorMetadataKey(params map[string]interface{}) string {
	if consumerBased, _ := params["consumerBased"].(bool); consumerBased {
		return metadataKeyCostScaleFactorConsumer
	}
	return MetadataKeyCostScaleFactor
}

// delegateEntry holds a delegate and its cache key for atomic storage
type delegateEntry struct {
	cacheKey string
	delegate policy.Policy
}

// LLMCostRateLimitPolicy delegates LLM cost-based rate limiting to advanced-ratelimit
// by reading the pre-calculated cost from SharedContext.Metadata (set by the llm-cost system policy)
// and applying user-defined monetary budgets.
type LLMCostRateLimitPolicy struct {
	metadata  policy.PolicyMetadata
	delegates sync.Map // map[string]*delegateEntry (providerName -> delegate entry)
}

// GetPolicy is the v1alpha2 factory entry point (loaded by v1alpha2 kernels).
func GetPolicy(
	metadata policy.PolicyMetadata,
	params map[string]interface{},
) (policy.Policy, error) {
	if err := validateRedisTLS(params); err != nil {
		return nil, err
	}
	return &LLMCostRateLimitPolicy{
		metadata: metadata,
	}, nil
}

// Mode returns the processing mode for this policy.
// ResponseBodyMode is Stream so that OnResponseBodyChunk is called for each chunk,
// delegating to the advanced-ratelimit instance which reads x-llm-cost from
// SharedContext.Metadata at end-of-stream (set by the llm-cost system policy).
func (p *LLMCostRateLimitPolicy) Mode() policy.ProcessingMode {
	return policy.ProcessingMode{
		RequestHeaderMode:  policy.HeaderModeProcess,
		RequestBodyMode:    policy.BodyModeSkip,
		ResponseHeaderMode: policy.HeaderModeProcess,
		ResponseBodyMode:   policy.BodyModeStream,
	}
}

// OnRequestHeaders processes the request header phase by resolving and delegating to a
// provider-specific ratelimit instance. The delegate and cost scale factor are pinned
// to SharedContext.Metadata for use in OnResponseHeaders.
func (p *LLMCostRateLimitPolicy) OnRequestHeaders(ctx context.Context, reqCtx *policy.RequestHeaderContext,
	params map[string]interface{},
) policy.RequestHeaderAction {
	slog.Debug("OnRequestHeaders: processing LLM cost-based rate limit",
		"route", p.metadata.RouteName,
		"params", params)

	providerName, ok := reqCtx.SharedContext.Metadata[MetadataKeyProviderName].(string)
	if !ok || providerName == "" {
		slog.Debug("OnRequestHeaders: provider name not found in metadata; skipping LLM cost rate limit",
			"route", p.metadata.RouteName)
		return policy.UpstreamRequestHeaderModifications{}
	}

	slog.Debug("OnRequestHeaders: resolved provider",
		"route", p.metadata.RouteName,
		"provider", providerName)

	delegate, err := p.resolveDelegate(providerName, params)
	if err != nil {
		slog.Warn("OnRequestHeaders: failed to resolve rate limit delegate for provider",
			"route", p.metadata.RouteName,
			"provider", providerName,
			"error", err)
		return policy.UpstreamRequestHeaderModifications{}
	}

	if delegate == nil {
		slog.Debug("OnRequestHeaders: no delegate available for provider; skipping",
			"route", p.metadata.RouteName,
			"provider", providerName)
		return policy.UpstreamRequestHeaderModifications{}
	}

	// Pin the delegate to the request context for use in OnResponseHeaders
	if reqCtx.SharedContext.Metadata == nil {
		reqCtx.SharedContext.Metadata = make(map[string]interface{})
	}
	reqCtx.SharedContext.Metadata[delegateMetadataKey(params)] = delegate

	// Store the cost scale factor for use in OnResponseHeaders
	costScaleFactor := extractCostScaleFactor(params)
	reqCtx.SharedContext.Metadata[costScaleFactorMetadataKey(params)] = costScaleFactor

	slog.Debug("OnRequestHeaders: delegating to advanced-ratelimit",
		"route", p.metadata.RouteName,
		"provider", providerName,
		"costScaleFactor", costScaleFactor)

	type requestHeaderPolicer interface {
		OnRequestHeaders(context.Context, *policy.RequestHeaderContext, map[string]interface{}) policy.RequestHeaderAction
	}
	if rl, ok := delegate.(requestHeaderPolicer); ok {
		return rl.OnRequestHeaders(ctx, reqCtx, params)
	}

	return policy.UpstreamRequestHeaderModifications{}
}

// OnResponseHeaders processes the response header phase by delegating to the same
// provider-specific instance pinned during OnRequestHeaders.
// After delegation, it adds custom headers that show cost values in dollars.
func (p *LLMCostRateLimitPolicy) OnResponseHeaders(ctx context.Context, respCtx *policy.ResponseHeaderContext,
	params map[string]interface{},
) policy.ResponseHeaderAction {
	slog.Debug("OnResponseHeaders: processing LLM cost-based rate limit",
		"route", p.metadata.RouteName)

	type responseHeaderPolicer interface {
		OnResponseHeaders(context.Context, *policy.ResponseHeaderContext, map[string]interface{}) policy.ResponseHeaderAction
	}

	// Retrieve the cost scale factor: prefer the value pinned during OnRequestHeaders,
	// fall back to extracting it from params.
	costScaleFactor := extractCostScaleFactor(params)
	if scaleFactor, ok := respCtx.Metadata[costScaleFactorMetadataKey(params)].(int); ok && scaleFactor > 0 {
		costScaleFactor = scaleFactor
	}

	// First, try to use the delegate pinned during OnRequestHeaders (ensures consistency)
	if delegate, ok := respCtx.Metadata[delegateMetadataKey(params)].(policy.Policy); ok {
		slog.Debug("OnResponseHeaders: using pinned delegate from request phase",
			"route", p.metadata.RouteName)
		if rl, ok := delegate.(responseHeaderPolicer); ok {
			return p.addDollarHeaders(rl.OnResponseHeaders(ctx, respCtx, params), costScaleFactor)
		}
		return policy.DownstreamResponseHeaderModifications{}
	}

	// Fallback: look up by provider name (for cases where OnRequestHeaders didn't run)
	providerName, ok := respCtx.Metadata[MetadataKeyProviderName].(string)
	if !ok || providerName == "" {
		slog.Debug("OnResponseHeaders: provider name not found in metadata; skipping",
			"route", p.metadata.RouteName)
		return policy.DownstreamResponseHeaderModifications{}
	}

	slog.Debug("OnResponseHeaders: looking up delegate by provider (fallback)",
		"route", p.metadata.RouteName,
		"provider", providerName)

	if entry, ok := p.delegates.Load(providerName); ok {
		if de, ok := entry.(*delegateEntry); ok && de.delegate != nil {
			if rl, ok := de.delegate.(responseHeaderPolicer); ok {
				slog.Debug("OnResponseHeaders: delegating to advanced-ratelimit",
					"route", p.metadata.RouteName,
					"provider", providerName)
				return p.addDollarHeaders(rl.OnResponseHeaders(ctx, respCtx, params), costScaleFactor)
			}
		}
	}

	slog.Debug("OnResponseHeaders: no delegate found for provider",
		"route", p.metadata.RouteName,
		"provider", providerName)
	return policy.DownstreamResponseHeaderModifications{}
}

// OnResponseBodyChunk processes each streaming response chunk by delegating to the
// provider-specific advanced-ratelimit instance. The delegate reads x-llm-cost from
// SharedContext.Metadata at end-of-stream (set by the llm-cost system policy) and
// consumes the cost quota. Dollar-denominated headers are set during OnResponseHeaders.
func (p *LLMCostRateLimitPolicy) OnResponseBodyChunk(
	ctx context.Context,
	respCtx *policy.ResponseStreamContext,
	chunk *policy.StreamBody,
	params map[string]interface{},
) policy.StreamingResponseAction {
	type responseChunkPolicer interface {
		OnResponseBodyChunk(context.Context, *policy.ResponseStreamContext, *policy.StreamBody, map[string]interface{}) policy.StreamingResponseAction
	}

	// First, try the delegate pinned during OnRequestHeaders.
	if delegate, ok := respCtx.Metadata[delegateMetadataKey(params)].(policy.Policy); ok {
		if rl, ok := delegate.(responseChunkPolicer); ok {
			return rl.OnResponseBodyChunk(ctx, respCtx, chunk, params)
		}
		return policy.ForwardResponseChunk{}
	}

	// Fallback: look up by provider name (for cases where OnRequestHeaders didn't run).
	providerName, ok := respCtx.Metadata[MetadataKeyProviderName].(string)
	if !ok || providerName == "" {
		slog.Debug("OnResponseBodyChunk: provider name not found in metadata; skipping",
			"route", p.metadata.RouteName)
		return policy.ForwardResponseChunk{}
	}

	if entry, ok := p.delegates.Load(providerName); ok {
		if de, ok := entry.(*delegateEntry); ok && de.delegate != nil {
			if rl, ok := de.delegate.(responseChunkPolicer); ok {
				return rl.OnResponseBodyChunk(ctx, respCtx, chunk, params)
			}
		}
	}

	return policy.ForwardResponseChunk{}
}

// NeedsMoreResponseData returns false because the delegate (advanced-ratelimit) manages
// all state internally — x-llm-cost metadata is read at end-of-stream from SharedContext.
func (p *LLMCostRateLimitPolicy) NeedsMoreResponseData(_ []byte) bool {
	return false
}

// OnResponseBody processes the response body phase by delegating to the same
// provider-specific advanced-ratelimit instance pinned during OnRequestHeaders.
//
// The executor runs response policies in reverse chain order, so llm-cost (which
// follows this policy in the chain) runs its OnResponseBody first, setting
// x-llm-cost in SharedContext.Metadata before this method is called. The delegate
// (advanced-ratelimit) then reads that value to deduct the actual cost from the
// rate limit counter.
func (p *LLMCostRateLimitPolicy) OnResponseBody(ctx context.Context, respCtx *policy.ResponseContext,
	params map[string]interface{},
) policy.ResponseAction {
	slog.Debug("OnResponseBody: processing LLM cost-based rate limit",
		"route", p.metadata.RouteName)

	type responseBodyPolicer interface {
		OnResponseBody(context.Context, *policy.ResponseContext, map[string]interface{}) policy.ResponseAction
	}

	costScaleFactor := extractCostScaleFactor(params)
	if scaleFactor, ok := respCtx.SharedContext.Metadata[costScaleFactorMetadataKey(params)].(int); ok && scaleFactor > 0 {
		costScaleFactor = scaleFactor
	}

	// First, try to use the delegate pinned during OnRequestHeaders
	if delegate, ok := respCtx.SharedContext.Metadata[delegateMetadataKey(params)].(policy.Policy); ok {
		slog.Debug("OnResponseBody: using pinned delegate from request phase",
			"route", p.metadata.RouteName)
		if rl, ok := delegate.(responseBodyPolicer); ok {
			return p.addDollarHeadersResponseBody(rl.OnResponseBody(ctx, respCtx, params), costScaleFactor)
		}
		return policy.DownstreamResponseModifications{}
	}

	// Fallback: look up by provider name (for cases where OnRequestHeaders didn't run)
	providerName, ok := respCtx.SharedContext.Metadata[MetadataKeyProviderName].(string)
	if !ok || providerName == "" {
		slog.Debug("OnResponseBody: provider name not found in metadata; skipping",
			"route", p.metadata.RouteName)
		return policy.DownstreamResponseModifications{}
	}

	if entry, ok := p.delegates.Load(providerName); ok {
		if de, ok := entry.(*delegateEntry); ok && de.delegate != nil {
			if rl, ok := de.delegate.(responseBodyPolicer); ok {
				slog.Debug("OnResponseBody: delegating to advanced-ratelimit",
					"route", p.metadata.RouteName,
					"provider", providerName)
				return p.addDollarHeadersResponseBody(rl.OnResponseBody(ctx, respCtx, params), costScaleFactor)
			}
		}
	}

	slog.Debug("OnResponseBody: no delegate found for provider",
		"route", p.metadata.RouteName,
		"provider", providerName)
	return policy.DownstreamResponseModifications{}
}

// addDollarHeadersResponseBody transforms the delegate's ResponseAction to include
// human-readable dollar-denominated headers alongside the scaled values.
func (p *LLMCostRateLimitPolicy) addDollarHeadersResponseBody(action policy.ResponseAction, costScaleFactor int) policy.ResponseAction {
	if action == nil {
		return policy.DownstreamResponseModifications{}
	}

	modifications, ok := action.(policy.DownstreamResponseModifications)
	if !ok {
		return action
	}

	if modifications.HeadersToSet == nil {
		return action
	}

	newHeaders := make(map[string]string, len(modifications.HeadersToSet)+4)
	for k, v := range modifications.HeadersToSet {
		newHeaders[k] = v
	}

	addScaledHeader(newHeaders, "ratelimit-limit", "x-ratelimit-cost-limit-dollars", costScaleFactor)
	addScaledHeader(newHeaders, "ratelimit-remaining", "x-ratelimit-cost-remaining-dollars", costScaleFactor)
	addScaledHeader(newHeaders, "x-ratelimit-limit", "x-ratelimit-cost-limit-dollars", costScaleFactor)
	addScaledHeader(newHeaders, "x-ratelimit-remaining", "x-ratelimit-cost-remaining-dollars", costScaleFactor)

	modifications.HeadersToSet = newHeaders
	return modifications
}

// addDollarHeaders transforms the delegate's v1alpha2 response header action to include
// human-readable dollar-denominated headers alongside the scaled values.
func (p *LLMCostRateLimitPolicy) addDollarHeaders(action policy.ResponseHeaderAction, costScaleFactor int) policy.ResponseHeaderAction {
	if action == nil {
		return policy.DownstreamResponseHeaderModifications{}
	}

	modifications, ok := action.(policy.DownstreamResponseHeaderModifications)
	if !ok {
		return action
	}

	if modifications.HeadersToSet == nil {
		return action
	}

	// Create a copy of headers to avoid modifying the original
	newHeaders := make(map[string]string, len(modifications.HeadersToSet)+4)
	for k, v := range modifications.HeadersToSet {
		newHeaders[k] = v
	}

	// Convert scaled headers to dollar headers
	// Look for both IETF (ratelimit-*) and legacy (x-ratelimit-*) headers
	addScaledHeader(newHeaders, "ratelimit-limit", "x-ratelimit-cost-limit-dollars", costScaleFactor)
	addScaledHeader(newHeaders, "ratelimit-remaining", "x-ratelimit-cost-remaining-dollars", costScaleFactor)
	addScaledHeader(newHeaders, "x-ratelimit-limit", "x-ratelimit-cost-limit-dollars", costScaleFactor)
	addScaledHeader(newHeaders, "x-ratelimit-remaining", "x-ratelimit-cost-remaining-dollars", costScaleFactor)

	modifications.HeadersToSet = newHeaders
	return modifications
}

// addScaledHeader reads a scaled value from sourceKey and adds a dollar-formatted
// header at targetKey. If targetKey already exists, it won't be overwritten.
func addScaledHeader(headers map[string]string, sourceKey, targetKey string, costScaleFactor int) {
	// Skip if target already exists
	if _, exists := headers[targetKey]; exists {
		return
	}

	sourceValue, ok := headers[sourceKey]
	if !ok || sourceValue == "" {
		return
	}

	// Parse the scaled value
	scaledValue, err := strconv.ParseInt(sourceValue, 10, 64)
	if err != nil {
		slog.Debug("addScaledHeader: failed to parse source value",
			"sourceKey", sourceKey,
			"sourceValue", sourceValue,
			"error", err)
		return
	}

	// Convert to dollars using the configured scale factor
	dollars := float64(scaledValue) / float64(costScaleFactor)
	headers[targetKey] = fmt.Sprintf("%.6f", dollars)

	slog.Debug("addScaledHeader: added dollar header",
		"sourceKey", sourceKey,
		"scaledValue", scaledValue,
		"costScaleFactor", costScaleFactor,
		"targetKey", targetKey,
		"dollars", dollars)
}

// resolveDelegate ensures an advanced-ratelimit instance exists for the given provider.
// The delegate is cached per provider and invalidated when the effective params change.
// This method is thread-safe using sync.Map with atomic delegateEntry storage.
func (p *LLMCostRateLimitPolicy) resolveDelegate(providerName string, params map[string]interface{}) (policy.Policy, error) {
	slog.Debug("resolveDelegate: checking for existing delegate",
		"route", p.metadata.RouteName,
		"provider", providerName)

	// Cache key captures all fields that determine the delegate's config.
	cacheKey := providerName + ":" + computeResourceHash(map[string]interface{}{
		"budgetLimits":    params["budgetLimits"],
		"costScaleFactor": extractCostScaleFactor(params),
		"algorithm":       params["algorithm"],
		"backend":         params["backend"],
		"redis":           params["redis"],
		"memory":          params["memory"],
		"local":           params["local"],
	})

	// Fast path: reuse existing delegate if config hasn't changed.
	if existing, ok := p.delegates.Load(providerName); ok {
		if entry, ok := existing.(*delegateEntry); ok && entry.cacheKey == cacheKey {
			slog.Debug("resolveDelegate: reusing existing delegate (fast path)",
				"route", p.metadata.RouteName,
				"provider", providerName)
			return entry.delegate, nil
		}
		slog.Debug("resolveDelegate: params changed, recreating delegate",
			"route", p.metadata.RouteName,
			"provider", providerName)
	}

	// Slow path: build the delegate from params.
	rlParams := transformToRatelimitParams(params)
	if len(rlParams["quotas"].([]interface{})) == 0 {
		slog.Debug("resolveDelegate: no budget limits configured, skipping delegate creation",
			"route", p.metadata.RouteName,
			"provider", providerName)
		return nil, nil
	}

	slog.Debug("resolveDelegate: creating new delegate",
		"route", p.metadata.RouteName,
		"provider", providerName)

	delegate, err := ratelimit.GetPolicy(p.metadata, rlParams)
	if err != nil {
		slog.Error("resolveDelegate: failed to create delegate",
			"route", p.metadata.RouteName,
			"provider", providerName,
			"error", err)
		return nil, err
	}

	p.delegates.Store(providerName, &delegateEntry{cacheKey: cacheKey, delegate: delegate})

	slog.Debug("resolveDelegate: successfully created and stored new delegate",
		"route", p.metadata.RouteName,
		"provider", providerName)

	return delegate, nil
}

// computeResourceHash computes a SHA256 hash of the resource map for cache key generation.
func computeResourceHash(resource map[string]interface{}) string {
	// Serialize the resource to JSON
	data, err := json.Marshal(resource)
	if err != nil {
		// If marshaling fails, return a random string to force a cache miss
		return "error-" + randomString(8)
	}

	// Compute SHA256 hash
	hash := sha256.Sum256(data)
	// Return first 16 characters of hex encoding (sufficient for collision resistance)
	return hex.EncodeToString(hash[:])[:16]
}

// randomString generates a random string of the given length using crypto/rand.
func randomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		// Fallback: use timestamp-seeded values if crypto/rand fails
		ns := time.Now().UnixNano()
		for i := range b {
			b[i] = charset[ns%int64(len(charset))]
			ns >>= 1
		}
		return string(b)
	}
	for i, v := range b {
		b[i] = charset[int(v)%len(charset)]
	}
	return string(b)
}

// transformToRatelimitParams converts LLM cost-specific parameters to the advanced-ratelimit structure.
// Costs are configured as "cost per N tokens" (default N=1,000,000) and converted to per-token costs
// for the advanced-ratelimit engine by dividing by N.
//
// Budget limits (in dollars) are scaled by costScaleFactor (configurable via systemParameters.costScaleFactor)
// to preserve precision when the underlying rate limiter uses int64 counters.
// The cost multipliers are also scaled so that the final deduction is in the scaled unit.
func transformToRatelimitParams(params map[string]interface{}) map[string]interface{} {
	slog.Debug("transformToRatelimitParams: starting parameter transformation",
		"params", params)

	// Get the budget limits from user parameters
	budgetLimits := params["budgetLimits"]
	if budgetLimits == nil {
		slog.Debug("transformToRatelimitParams: no budgetLimits found")
		return map[string]interface{}{"quotas": []interface{}{}}
	}

	// Get the cost scale factor from system parameters
	costScaleFactor := extractCostScaleFactor(params)

	slog.Debug("transformToRatelimitParams: using x-llm-cost from SharedContext.Metadata for cost extraction",
		"costScaleFactor", costScaleFactor)

	// Build a single quota with multiple limits for different time windows
	// Scale the dollar amounts using the configured scale factor for precision
	var limits []interface{}
	budgetItems, ok := budgetLimits.([]interface{})
	if !ok {
		slog.Debug("transformToRatelimitParams: budgetLimits is not an array")
		return map[string]interface{}{"quotas": []interface{}{}}
	}

	for _, item := range budgetItems {
		if m, ok := item.(map[string]interface{}); ok {
			// Scale the amount from dollars to scaled units (e.g., micro-dollars)
			// Use float64 since the advanced-ratelimit policy expects float64 (from JSON parsing)
			var scaledAmount float64
			switch v := m["amount"].(type) {
			case float64:
				scaledAmount = v * float64(costScaleFactor)
			case int:
				scaledAmount = float64(v) * float64(costScaleFactor)
			case int64:
				scaledAmount = float64(v) * float64(costScaleFactor)
			default:
				slog.Warn("transformToRatelimitParams: unsupported amount type",
					"type", fmt.Sprintf("%T", m["amount"]))
				continue
			}

			limit := map[string]interface{}{
				"limit":    scaledAmount,
				"duration": m["duration"],
			}
			limits = append(limits, limit)

			slog.Debug("transformToRatelimitParams: scaled limit",
				"originalAmount", m["amount"],
				"scaledAmount", scaledAmount,
				"costScaleFactor", costScaleFactor,
				"duration", m["duration"])
		}
	}

	if len(limits) == 0 {
		slog.Debug("transformToRatelimitParams: no valid limits found")
		return map[string]interface{}{"quotas": []interface{}{}}
	}

	// Read the pre-calculated dollar cost from SharedContext.Metadata,
	// set by the LLM cost system policy. Scale to int64-compatible units.
	sources := []interface{}{
		map[string]interface{}{
			"type":       "response_metadata",
			"key":        "x-llm-cost",
			"multiplier": float64(costScaleFactor),
		},
	}

	consumerBased, _ := params["consumerBased"].(bool)
	var keyExtraction []interface{}
	if consumerBased {
		keyExtraction = []interface{}{
			map[string]interface{}{"type": "routename"},
			map[string]interface{}{"type": "metadata", "key": "x-wso2-application-id", "fallback": "default"},
		}
	} else {
		keyExtraction = []interface{}{
			map[string]interface{}{"type": "routename"},
		}
	}

	// Build the quota
	quota := map[string]interface{}{
		"name":          "llm_cost_quota",
		"limits":        limits,
		"keyExtraction": keyExtraction,
	}

	quota["costExtraction"] = map[string]interface{}{
		"enabled": true,
		"sources": sources,
		"default": 0, // Default to 0 cost if x-llm-cost metadata is absent
	}

	quotas := []interface{}{quota}

	rlParams := map[string]interface{}{
		"quotas": quotas,
	}

	// Copy through system parameters
	for _, key := range []string{"algorithm", "backend", "redis", "memory", "local"} {
		if val, ok := params[key]; ok {
			rlParams[key] = val
		}
	}

	slog.Debug("transformToRatelimitParams: completed transformation",
		"quotasCount", len(quotas),
		"hasAlgorithm", rlParams["algorithm"] != nil,
		"hasBackend", rlParams["backend"] != nil,
		"quotas", quotas)

	return rlParams
}

// extractCostScaleFactor extracts the cost scale factor from system parameters.
// The scale factor determines how dollar amounts are scaled for precision in int64 counters.
// Default: 1,000,000,000 (nano-dollars)
func extractCostScaleFactor(params map[string]interface{}) int {
	// Check for system parameters at root level (injected by gateway)
	if systemParams, ok := params["systemParameters"].(map[string]interface{}); ok {
		if scaleFactor := extractIntValue(systemParams["costScaleFactor"], 0); scaleFactor > 0 {
			return scaleFactor
		}
	}

	// Also check at root level for directly embedded system parameters
	if scaleFactor := extractIntValue(params["costScaleFactor"], 0); scaleFactor > 0 {
		return scaleFactor
	}

	return DefaultCostScaleFactor
}

// extractIntValue extracts an int from various numeric types with a default value
func extractIntValue(v interface{}, defaultValue int) int {
	if v == nil {
		return defaultValue
	}
	switch val := v.(type) {
	case int:
		return val
	case int64:
		return int(val)
	case int32:
		return int(val)
	case float64:
		return int(val)
	case float32:
		return int(val)
	}
	return defaultValue
}

// getFloatValue extracts a float64 from various numeric types
func getFloatValue(v interface{}) (float64, bool) {
	if v == nil {
		return 0, false
	}
	switch val := v.(type) {
	case float64:
		return val, true
	case float32:
		return float64(val), true
	case int:
		return float64(val), true
	case int64:
		return float64(val), true
	case int32:
		return float64(val), true
	}
	return 0, false
}
