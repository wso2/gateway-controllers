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

package tokenbasedratelimit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
	ratelimit "github.com/wso2/gateway-controllers/policies/advanced-ratelimit"
)

const (
	ResourceTypeLlmProviderTemplate     = "LlmProviderTemplate"
	ResourceTypeProviderTemplateMapping = "ProviderTemplateMapping"
	MetadataKeyProviderName             = "provider_name"
)

// TokenBasedRateLimitPolicy delegates LLM token-based rate limiting to advanced-ratelimit
// by dynamically resolving cost extraction paths from provider templates.
type TokenBasedRateLimitPolicy struct {
	metadata          policy.PolicyMetadata
	delegates         sync.Map           // map[string]policy.Policy (providerName -> advanced-ratelimit instance)
	delegateCacheKeys sync.Map           // map[string]string (providerName -> cacheKey for template change detection)
	sf                singleflight.Group // prevents duplicate delegate creation
}

// GetPolicy is the v1alpha2 factory entry point (loaded by v1alpha2 kernels).
func GetPolicy(
	metadata policy.PolicyMetadata,
	params map[string]interface{},
) (policy.Policy, error) {
	if err := validateRedisTLS(params); err != nil {
		return nil, err
	}
	return &TokenBasedRateLimitPolicy{
		metadata: metadata,
	}, nil
}

func (p *TokenBasedRateLimitPolicy) Mode() policy.ProcessingMode {
	return policy.ProcessingMode{
		RequestHeaderMode:  policy.HeaderModeProcess,
		RequestBodyMode:    policy.BodyModeSkip,
		ResponseHeaderMode: policy.HeaderModeProcess,
		ResponseBodyMode:   policy.BodyModeStream,
	}
}

// resolveDelegate ensures an advanced-ratelimit instance exists for the given provider.
// This method is thread-safe and uses singleflight to prevent duplicate delegate creation
// when multiple goroutines attempt to create a delegate for the same provider/template
// simultaneously. Only one goroutine performs the expensive creation, and others wait
// for the result. The delegate is cached with a key that includes a hash of the template,
// so when the template changes, a new delegate is created automatically.
func (p *TokenBasedRateLimitPolicy) resolveDelegate(providerName string, params map[string]interface{}) (policy.Policy, error) {
	slog.Debug("resolveDelegate: checking for existing delegate",
		"route", p.metadata.RouteName,
		"provider", providerName)

	// Get the template to compute the cache key
	store := policy.GetLazyResourceStoreInstance()

	// 1. Get Provider-to-Template Mapping
	mappingResource, err := store.GetResourceByIDAndType(providerName, ResourceTypeProviderTemplateMapping)
	if err != nil {
		slog.Error("resolveDelegate: failed to get provider template mapping",
			"route", p.metadata.RouteName,
			"provider", providerName,
			"error", err)
		return nil, err
	}

	if mappingResource == nil {
		slog.Error("resolveDelegate: provider template mapping not found",
			"route", p.metadata.RouteName,
			"provider", providerName)
		return nil, nil
	}

	templateHandle, ok := mappingResource.Resource["template_handle"].(string)
	if !ok || templateHandle == "" {
		slog.Error("resolveDelegate: template_handle not found or empty in mapping",
			"route", p.metadata.RouteName,
			"provider", providerName)
		return nil, nil
	}

	// 2. Get the Actual Template
	templateResource, err := store.GetResourceByIDAndType(templateHandle, ResourceTypeLlmProviderTemplate)
	if err != nil {
		slog.Error("resolveDelegate: failed to get LLM provider template",
			"route", p.metadata.RouteName,
			"provider", providerName,
			"templateHandle", templateHandle,
			"error", err)
		return nil, err
	}

	if templateResource == nil {
		slog.Error("resolveDelegate: LLM provider template not found",
			"route", p.metadata.RouteName,
			"provider", providerName,
			"templateHandle", templateHandle)
		return nil, nil
	}

	// 3. Compute a hash of the template to use in the cache key
	templateHash := computeResourceHash(templateResource.Resource)
	cacheKey := providerName + ":" + templateHash

	slog.Debug("resolveDelegate: computed cache key",
		"route", p.metadata.RouteName,
		"provider", providerName,
		"templateHandle", templateHandle,
		"templateHash", templateHash[:8],
		"cacheKey", cacheKey)

	// Fast path: check if delegate already exists for this provider
	// We check using providerName as the key since that's what OnResponseBody uses
	if existingDelegate, ok := p.delegates.Load(providerName); ok {
		// Check if the existing delegate is for the current template version
		// by comparing the stored cacheKey
		if storedCacheKey, hasKey := p.delegateCacheKeys.Load(providerName); hasKey {
			if storedCacheKey.(string) == cacheKey {
				slog.Debug("resolveDelegate: found existing delegate for current template (fast path)",
					"route", p.metadata.RouteName,
					"provider", providerName,
					"templateHash", templateHash[:8])
				return existingDelegate.(policy.Policy), nil
			}
			// Template changed - continue to create new delegate
			slog.Debug("resolveDelegate: template changed, creating new delegate",
				"route", p.metadata.RouteName,
				"provider", providerName,
				"oldTemplateHash", storedCacheKey.(string)[:8],
				"newTemplateHash", templateHash[:8])
		}
	}

	// Slow path: use singleflight to prevent duplicate delegate creation
	// Only one goroutine will execute the creation for a given cacheKey
	result, err, _ := p.sf.Do(cacheKey, func() (interface{}, error) {
		// Double-check: another goroutine may have created it while we were waiting
		if existingDelegate, ok := p.delegates.Load(providerName); ok {
			if storedCacheKey, hasKey := p.delegateCacheKeys.Load(providerName); hasKey {
				if storedCacheKey.(string) == cacheKey {
					slog.Debug("resolveDelegate: delegate created by another goroutine",
						"route", p.metadata.RouteName,
						"provider", providerName,
						"templateHash", templateHash[:8])
					return existingDelegate.(policy.Policy), nil
				}
			}
		}

		slog.Debug("resolveDelegate: creating new delegate (singleflight)",
			"route", p.metadata.RouteName,
			"provider", providerName,
			"templateHash", templateHash[:8])

		// Create the delegate (expensive operation)
		delegate, err := p.createDelegateWithTemplate(providerName, params, templateResource.Resource)
		if err != nil {
			slog.Error("resolveDelegate: failed to create delegate",
				"route", p.metadata.RouteName,
				"provider", providerName,
				"error", err)
			return nil, err
		}

		// Store the delegate with providerName as key (for OnResponseBody lookup)
		// and store the cacheKey separately for template change detection
		p.delegates.Store(providerName, delegate)
		p.delegateCacheKeys.Store(providerName, cacheKey)

		slog.Debug("resolveDelegate: successfully created and stored new delegate",
			"route", p.metadata.RouteName,
			"provider", providerName,
			"templateHash", templateHash[:8])

		return delegate, nil
	})

	if err != nil {
		return nil, err
	}
	return result.(policy.Policy), nil
}

// createDelegateWithTemplate creates a delegate using the provided template (already fetched).
// This avoids double-fetching the template when called from resolveDelegate.
func (p *TokenBasedRateLimitPolicy) createDelegateWithTemplate(providerName string, params map[string]interface{}, template map[string]interface{}) (policy.Policy, error) {
	// Transform LLM limits into advanced-ratelimit parameters
	rlParams := transformToRatelimitParams(params, template, p.metadata.AttachedTo)

	slog.Debug("createDelegateWithTemplate: parameters transformed",
		"route", p.metadata.RouteName,
		"provider", providerName,
		"quotasCount", len(rlParams["quotas"].([]interface{})))

	// Create the delegate instance
	delegate, err := ratelimit.GetPolicy(p.metadata, rlParams)
	if err != nil {
		slog.Error("createDelegateWithTemplate: failed to create advanced-ratelimit policy",
			"route", p.metadata.RouteName,
			"provider", providerName,
			"error", err)
		return nil, err
	}

	slog.Debug("createDelegateWithTemplate: successfully created delegate",
		"route", p.metadata.RouteName,
		"provider", providerName)

	return delegate, nil
}

// computeResourceHash computes a SHA256 hash of the resource map for cache key generation.
// This allows detecting when the template has changed.
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

// randomString generates a random string of the given length
func randomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[time.Now().UnixNano()%int64(len(charset))]
	}
	return string(b)
}

// transformToRatelimitParams converts LLM-specific parameters to the advanced-ratelimit structure.
func transformToRatelimitParams(params map[string]interface{}, template map[string]interface{}, attachedTo policy.Level) map[string]interface{} {
	slog.Debug("transformToRatelimitParams: starting parameter transformation",
		"params", params,
		"template", template,
		"attachedTo", attachedTo)

	var quotas []interface{}

	// Provider-wide (API-level) quotas must share one bucket across every resource of the
	// provider, mirroring basic-ratelimit's apiname switch for the same attachment level.
	keyType := "routename"
	if attachedTo == policy.LevelAPI {
		keyType = "apiname"
	}

	consumerBased, _ := params["consumerBased"].(bool)
	var keyExtraction []interface{}
	if consumerBased {
		keyExtraction = []interface{}{
			map[string]interface{}{"type": keyType},
			map[string]interface{}{"type": "metadata", "key": "x-wso2-application-id", "fallback": "default"},
		}
	} else {
		keyExtraction = []interface{}{
			map[string]interface{}{"type": keyType},
		}
	}

	// resolveCostSource maps a single template field to an advanced-ratelimit cost source,
	// or returns nil if the field isn't defined on the template.
	resolveCostSource := func(spec map[string]interface{}, templateKey string) map[string]interface{} {
		usage, ok := spec[templateKey].(map[string]interface{})
		if !ok {
			return nil
		}
		path, ok := usage["identifier"].(string)
		if !ok || path == "" {
			return nil
		}

		location, _ := usage["location"].(string)
		sourceConfig := map[string]interface{}{}
		switch location {
		case "header":
			sourceConfig["type"] = "request_header"
			sourceConfig["key"] = path
		case "metadata":
			sourceConfig["type"] = "metadata"
			sourceConfig["key"] = path
		default:
			// "payload" or any other/unspecified location: response_body + jsonPath.
			sourceConfig["type"] = "response_body"
			sourceConfig["jsonPath"] = path
		}
		return sourceConfig
	}

	// addQuota builds a quota whose cost is extracted from the first templateKeyGroup that
	// resolves at least one source. Groups are tried in order and are mutually exclusive —
	// this lets total_tokens fall back to summing promptTokens+completionTokens when the
	// template has no totalTokens field (e.g. Anthropic), without ever combining a resolved
	// totalTokens source with prompt/completion sources and double-counting.
	addQuota := func(name string, limitsKey string, templateKeyGroups ...[]string) {
		limits := params[limitsKey]
		if limits == nil {
			slog.Debug("addQuota: no limits found, skipping",
				"name", name,
				"limitsKey", limitsKey)
			return
		}

		convertedLimits := convertLimits(limits)
		if len(convertedLimits) == 0 {
			slog.Debug("addQuota: empty limits, skipping",
				"name", name,
				"limitsKey", limitsKey)
			return
		}

		quota := map[string]interface{}{
			"name":          name,
			"limits":        convertedLimits,
			"keyExtraction": keyExtraction,
		}

		var sources []interface{}
		if template != nil {
			// The template structure has spec directly: template["spec"]
			if spec, ok := template["spec"].(map[string]interface{}); ok {
				for _, group := range templateKeyGroups {
					var groupSources []interface{}
					for _, templateKey := range group {
						if source := resolveCostSource(spec, templateKey); source != nil {
							groupSources = append(groupSources, source)
						}
					}
					if len(groupSources) > 0 {
						if len(group) > 1 && len(groupSources) < len(group) {
							// A multi-field fallback group (e.g. promptTokens+completionTokens)
							// resolved only some of its fields — the quota will still use what
							// resolved, but the "total" it charges is incomplete and will
							// undercount actual usage.
							slog.Warn("addQuota: template defines only part of a multi-field cost fallback group; total will undercount actual usage",
								"name", name,
								"expectedFields", group,
								"resolvedCount", len(groupSources))
						}
						sources = groupSources
						break
					}
				}
			}
		}

		if len(sources) > 0 {
			slog.Debug("addQuota: configured cost extraction",
				"name", name,
				"sourceCount", len(sources))
			quota["costExtraction"] = map[string]interface{}{
				"enabled": true,
				"sources": sources,
			}
		} else {
			// Without costExtraction, advanced-ratelimit charges its flat default cost of 1
			// per request instead of the actual token count — surface this loudly so a
			// template gap doesn't silently degrade a token quota into a request quota.
			slog.Warn("addQuota: no cost extraction source resolved from template; quota will charge 1 per request instead of actual token usage",
				"name", name,
				"limitsKey", limitsKey)
		}

		quotas = append(quotas, quota)
	}

	addQuota("prompt_tokens", "promptTokenLimits", []string{"promptTokens"})
	addQuota("completion_tokens", "completionTokenLimits", []string{"completionTokens"})
	addQuota("total_tokens", "totalTokenLimits", []string{"totalTokens"}, []string{"promptTokens", "completionTokens"})

	rlParams := map[string]interface{}{
		"quotas": quotas,
	}

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

func convertLimits(rawLimits interface{}) []interface{} {
	items, ok := rawLimits.([]interface{})
	if !ok {
		return nil
	}
	var converted []interface{}
	for _, item := range items {
		if m, ok := item.(map[string]interface{}); ok {
			converted = append(converted, map[string]interface{}{
				"limit":    m["count"],
				"duration": m["duration"],
			})
		}
	}
	return converted
}

// OnRequestHeaders runs the full request-phase rate limit check in the header phase,
// eliminating the need to buffer the request body. It calls the delegate's OnRequestHeaders
// (pre-check / standard quota consumption) and then its OnRequestBody with a synthetic
// RequestContext built from the available header-phase data. This means request-header cost
// sources (e.g. X-Token-Cost) are extracted and consumed immediately, before the upstream
// is called, without requiring body buffering.
func (p *TokenBasedRateLimitPolicy) OnRequestHeaders(ctx context.Context, reqCtx *policy.RequestHeaderContext,
	params map[string]interface{},
) policy.RequestHeaderAction {
	type requestHeaderPolicer interface {
		OnRequestHeaders(context.Context, *policy.RequestHeaderContext, map[string]interface{}) policy.RequestHeaderAction
	}

	slog.Debug("OnRequestHeaders: processing token-based rate limit",
		"route", p.metadata.RouteName)

	providerName, ok := reqCtx.SharedContext.Metadata[MetadataKeyProviderName].(string)
	if !ok || providerName == "" {
		slog.Debug("OnRequestHeaders: provider name not found in metadata; skipping token-based rate limit",
			"route", p.metadata.RouteName)
		return nil
	}

	delegate, err := p.resolveDelegate(providerName, params)
	if err != nil {
		slog.Warn("OnRequestHeaders: failed to resolve rate limit delegate for provider",
			"route", p.metadata.RouteName,
			"provider", providerName,
			"error", err)
		return nil
	}

	if delegate == nil {
		slog.Warn("OnRequestHeaders: delegate is nil for provider",
			"route", p.metadata.RouteName,
			"provider", providerName)
		return nil
	}

	// Phase 1: header pre-check — blocks if quota is already at zero.
	if rl, ok := delegate.(requestHeaderPolicer); ok {
		if action := rl.OnRequestHeaders(ctx, reqCtx, params); isBlockingHeaderAction(action) {
			return action
		}
	}

	return policy.UpstreamRequestHeaderModifications{}
}

// isBlockingHeaderAction returns true when the action signals an immediate response
// (e.g. 429 rate-limit exceeded) that should stop request processing.
func isBlockingHeaderAction(action policy.RequestHeaderAction) bool {
	if action == nil {
		return false
	}
	_, ok := action.(policy.ImmediateResponse)
	return ok
}

// OnResponseHeaders delegates to the provider-specific ratelimit instance's OnResponseHeaders
// if a delegate is already cached for the provider.
func (p *TokenBasedRateLimitPolicy) OnResponseHeaders(ctx context.Context, respCtx *policy.ResponseHeaderContext,
	params map[string]interface{},
) policy.ResponseHeaderAction {
	type responseHeaderPolicer interface {
		OnResponseHeaders(context.Context, *policy.ResponseHeaderContext, map[string]interface{}) policy.ResponseHeaderAction
	}

	providerName, ok := respCtx.Metadata[MetadataKeyProviderName].(string)
	if !ok || providerName == "" {
		slog.Debug("OnResponseHeaders: provider name not found in metadata; skipping token-based rate limit",
			"route", p.metadata.RouteName)
		return policy.DownstreamResponseHeaderModifications{}
	}

	if delegate, ok := p.delegates.Load(providerName); ok {
		if rl, ok := delegate.(responseHeaderPolicer); ok {
			return rl.OnResponseHeaders(ctx, respCtx, params)
		}
	}

	return policy.DownstreamResponseHeaderModifications{}
}

// OnResponseBodyChunk processes each streaming response chunk by delegating to the
// provider-specific advanced-ratelimit instance. The delegate accumulates SSE or JSON
// chunks and consumes the token quota at end-of-stream.
func (p *TokenBasedRateLimitPolicy) OnResponseBodyChunk(
	ctx context.Context,
	respCtx *policy.ResponseStreamContext,
	chunk *policy.StreamBody,
	params map[string]interface{},
) policy.StreamingResponseAction {
	type responseChunkPolicer interface {
		OnResponseBodyChunk(context.Context, *policy.ResponseStreamContext, *policy.StreamBody, map[string]interface{}) policy.StreamingResponseAction
	}

	providerName, ok := respCtx.Metadata[MetadataKeyProviderName].(string)
	if !ok || providerName == "" {
		slog.Debug("OnResponseBodyChunk: provider name not found in metadata; skipping",
			"route", p.metadata.RouteName)
		return policy.ForwardResponseChunk{}
	}

	if delegate, ok := p.delegates.Load(providerName); ok {
		if rl, ok := delegate.(responseChunkPolicer); ok {
			return rl.OnResponseBodyChunk(ctx, respCtx, chunk, params)
		}
		return policy.ForwardResponseChunk{}
	}

	slog.Debug("OnResponseBody: no delegate found for provider",
		"route", p.metadata.RouteName,
		"provider", providerName)

	return policy.ForwardResponseChunk{}
}

// NeedsMoreResponseData returns false because the delegate (advanced-ratelimit) manages
// all buffering internally — SSE costs are extracted per-chunk and JSON bytes are
// accumulated in the delegate's per-request stream state.
func (p *TokenBasedRateLimitPolicy) NeedsMoreResponseData(_ []byte) bool {
	return false
}

// OnResponseBody processes the response body phase by delegating to the provider-specific instance.
func (p *TokenBasedRateLimitPolicy) OnResponseBody(ctx context.Context, respCtx *policy.ResponseContext,
	_ map[string]interface{},
) policy.ResponseAction {
	slog.Debug("OnResponseBody: processing token-based rate limit",
		"route", p.metadata.RouteName)

	providerName, ok := respCtx.SharedContext.Metadata[MetadataKeyProviderName].(string)
	if !ok || providerName == "" {
		slog.Debug("OnResponseBody: provider name not found in metadata; skipping",
			"route", p.metadata.RouteName)
		return nil
	}

	slog.Debug("OnResponseBody: looking up delegate",
		"route", p.metadata.RouteName,
		"provider", providerName)

	if delegate, ok := p.delegates.Load(providerName); ok {
		slog.Debug("OnResponseBody: delegating to advanced-ratelimit",
			"route", p.metadata.RouteName,
			"provider", providerName)
		type responseBodyPolicer interface {
			OnResponseBody(context.Context, *policy.ResponseContext, map[string]interface{}) policy.ResponseAction
		}
		if rl, ok := delegate.(responseBodyPolicer); ok {
			return rl.OnResponseBody(ctx, respCtx, nil)
		}
		return nil
	}

	slog.Debug("OnResponseBody: no delegate found for provider",
		"route", p.metadata.RouteName,
		"provider", providerName)

	return nil
}
