/*
 * Copyright (c) 2026, WSO2 LLC. (http://www.wso2.org) All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package ratelimit

import (
	"context"
	"errors"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
	"github.com/wso2/gateway-controllers/policies/advanced-ratelimit/limiter"
)

type fakeLimiter struct {
	allowFn        func(ctx context.Context, key string) (*limiter.Result, error)
	allowNFn       func(ctx context.Context, key string, n int64) (*limiter.Result, error)
	consumeNFn     func(ctx context.Context, key string, n int64) (*limiter.Result, error)
	getAvailableFn func(ctx context.Context, key string) (int64, error)
	closeFn        func() error

	allowCalls        int
	allowNCalls       int
	consumeNCalls     int
	getAvailableCalls int
	closeCalls        int

	lastKey   string
	lastCost  int64
	closeErr  error
	allowErr  error
	allowNErr error
}

func (f *fakeLimiter) Allow(ctx context.Context, key string) (*limiter.Result, error) {
	f.allowCalls++
	f.lastKey = key
	if f.allowFn != nil {
		return f.allowFn(ctx, key)
	}
	if f.allowErr != nil {
		return nil, f.allowErr
	}
	return newResult(true, 100, 99, 0, time.Minute), nil
}

func (f *fakeLimiter) AllowN(ctx context.Context, key string, n int64) (*limiter.Result, error) {
	f.allowNCalls++
	f.lastKey = key
	f.lastCost = n
	if f.allowNFn != nil {
		return f.allowNFn(ctx, key, n)
	}
	if f.allowNErr != nil {
		return nil, f.allowNErr
	}
	remaining := int64(100 - n)
	if remaining < 0 {
		remaining = 0
	}
	return newResult(true, 100, remaining, 0, time.Minute), nil
}

func (f *fakeLimiter) ConsumeOrClampN(ctx context.Context, key string, n int64) (*limiter.Result, error) {
	return newResult(true, 100, 50, 0, time.Minute), nil
}

func (f *fakeLimiter) ConsumeN(ctx context.Context, key string, n int64) (*limiter.Result, error) {
	f.consumeNCalls++
	f.lastKey = key
	f.lastCost = n
	if f.consumeNFn != nil {
		return f.consumeNFn(ctx, key, n)
	}
	return newResult(true, 100, 50, 0, time.Minute), nil
}

func (f *fakeLimiter) GetAvailable(ctx context.Context, key string) (int64, error) {
	f.getAvailableCalls++
	f.lastKey = key
	if f.getAvailableFn != nil {
		return f.getAvailableFn(ctx, key)
	}
	return 100, nil
}

func (f *fakeLimiter) Close() error {
	f.closeCalls++
	if f.closeFn != nil {
		return f.closeFn()
	}
	return f.closeErr
}

func newResult(allowed bool, limit, remaining int64, retryAfter, duration time.Duration) *limiter.Result {
	return &limiter.Result{
		Allowed:    allowed,
		Limit:      limit,
		Remaining:  remaining,
		Duration:   duration,
		RetryAfter: retryAfter,
		Reset:      time.Now().Add(duration),
		Policy:     struct{}{},
	}
}

func newRequestCtx(headers map[string][]string, metadata map[string]interface{}) *policy.RequestContext {
	if metadata == nil {
		metadata = map[string]interface{}{}
	}
	if headers == nil {
		headers = map[string][]string{}
	}
	return &policy.RequestContext{
		Headers: policy.NewHeaders(headers),
		Path:    "/pets/123",
		Method:  "GET",
		SharedContext: &policy.SharedContext{
			Metadata:   metadata,
			APIName:    "petstore",
			APIVersion: "v1",
			APIId:      "api-id",
			APIContext: "/petstore",
		},
	}
}

func newResponseCtx(reqHeaders, respHeaders map[string][]string, metadata map[string]interface{}, status int) *policy.ResponseContext {
	if metadata == nil {
		metadata = map[string]interface{}{}
	}
	if reqHeaders == nil {
		reqHeaders = map[string][]string{}
	}
	if respHeaders == nil {
		respHeaders = map[string][]string{}
	}
	return &policy.ResponseContext{
		RequestHeaders:  policy.NewHeaders(reqHeaders),
		ResponseHeaders: policy.NewHeaders(respHeaders),
		ResponseStatus:  status,
		SharedContext: &policy.SharedContext{
			Metadata:   metadata,
			APIName:    "petstore",
			APIVersion: "v1",
			APIId:      "api-id",
			APIContext: "/petstore",
		},
	}
}

func assertImmediateResponse(t *testing.T, action interface{}, expectedStatus int) policy.ImmediateResponse {
	t.Helper()
	resp, ok := action.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("expected policy.ImmediateResponse, got %T", action)
	}
	if resp.StatusCode != expectedStatus {
		t.Fatalf("expected status %d, got %d", expectedStatus, resp.StatusCode)
	}
	// A throttle rejection must reach the gateway's fault flow, and its code must land in
	if !resp.IsFault {
		t.Fatalf("expected IsFault=true on a throttle rejection")
	}
	if resp.Fault == nil {
		t.Fatalf("expected Error to be populated on a throttle rejection")
	}
	if resp.Fault.Type != policy.FaultTypeThrottling {
		t.Fatalf("expected Error.Type=%q, got %q", policy.FaultTypeThrottling, resp.Fault.Type)
	}
	switch resp.Fault.Code {
	case policy.FaultCodeThrottledAPI, policy.FaultCodeThrottledResource:
	default:
		t.Fatalf("unexpected Error.Code %q; must be a throttling code", resp.Fault.Code)
	}
	return resp
}

func newRequestHeaderCtx(headers map[string][]string, metadata map[string]interface{}) *policy.RequestHeaderContext {
	if metadata == nil {
		metadata = map[string]interface{}{}
	}
	if headers == nil {
		headers = map[string][]string{}
	}
	return &policy.RequestHeaderContext{
		SharedContext: &policy.SharedContext{
			Metadata:   metadata,
			APIName:    "petstore",
			APIVersion: "v1",
			APIId:      "api-id",
			APIContext: "/petstore",
		},
		Headers: policy.NewHeaders(headers),
		Path:    "/pets/123",
		Method:  "GET",
	}
}

func newResponseHeaderCtx(reqHeaders, respHeaders map[string][]string, metadata map[string]interface{}, status int) *policy.ResponseHeaderContext {
	if metadata == nil {
		metadata = map[string]interface{}{}
	}
	if reqHeaders == nil {
		reqHeaders = map[string][]string{}
	}
	if respHeaders == nil {
		respHeaders = map[string][]string{}
	}
	return &policy.ResponseHeaderContext{
		SharedContext: &policy.SharedContext{
			Metadata:   metadata,
			APIName:    "petstore",
			APIVersion: "v1",
			APIId:      "api-id",
			APIContext: "/petstore",
		},
		RequestHeaders:  policy.NewHeaders(reqHeaders),
		ResponseHeaders: policy.NewHeaders(respHeaders),
		ResponseStatus:  status,
	}
}

func assertResponseHeaderMods(t *testing.T, action interface{}, required map[string]string) policy.DownstreamResponseHeaderModifications {
	t.Helper()
	mods, ok := action.(policy.DownstreamResponseHeaderModifications)
	if !ok {
		t.Fatalf("expected policy.DownstreamResponseHeaderModifications, got %T", action)
	}
	for k, v := range required {
		if mods.HeadersToSet[k] != v {
			t.Fatalf("expected header %s=%q, got %q", k, v, mods.HeadersToSet[k])
		}
	}
	return mods
}

func assertUpstreamResponseHeaders(t *testing.T, action interface{}, required map[string]string) policy.DownstreamResponseModifications {
	t.Helper()
	mods, ok := action.(policy.DownstreamResponseModifications)
	if !ok {
		t.Fatalf("expected policy.DownstreamResponseModifications, got %T", action)
	}
	for k, v := range required {
		if mods.HeadersToSet[k] != v {
			t.Fatalf("expected header %s=%q, got %q", k, v, mods.HeadersToSet[k])
		}
	}
	return mods
}

func basicQuotaParams() map[string]interface{} {
	return map[string]interface{}{
		"backend":   "memory",
		"algorithm": "fixed-window",
		"quotas": []interface{}{
			map[string]interface{}{
				"name": "default",
				"limits": []interface{}{
					map[string]interface{}{
						"limit":    float64(10),
						"duration": "1m",
					},
				},
			},
		},
	}
}

func TestGetPolicy_ConfigAndDefaults(t *testing.T) {
	clearCaches()
	defer clearCaches()

	t.Run("uses unknown-route when metadata route empty", func(t *testing.T) {
		p, err := GetPolicy(policy.PolicyMetadata{APIName: "api-a", APIVersion: "v1"}, basicQuotaParams())
		if err != nil {
			t.Fatalf("GetPolicy returned error: %v", err)
		}
		rl := p.(*RateLimitPolicy)
		if rl.routeName != "unknown-route" {
			t.Fatalf("expected routeName unknown-route, got %q", rl.routeName)
		}
	})

	t.Run("returns error when quotas missing", func(t *testing.T) {
		_, err := GetPolicy(policy.PolicyMetadata{RouteName: "r1"}, map[string]interface{}{"backend": "memory"})
		if err == nil || !strings.Contains(err.Error(), "quotas configuration is required") {
			t.Fatalf("expected quotas required error, got %v", err)
		}
	})

	t.Run("returns error for invalid global keyExtraction shape", func(t *testing.T) {
		params := basicQuotaParams()
		params["keyExtraction"] = "invalid"
		_, err := GetPolicy(policy.PolicyMetadata{RouteName: "r1"}, params)
		if err == nil || !strings.Contains(err.Error(), "invalid keyExtraction") {
			t.Fatalf("expected invalid keyExtraction error, got %v", err)
		}
	})

	t.Run("uses per-quota keyExtraction when present", func(t *testing.T) {
		params := basicQuotaParams()
		params["keyExtraction"] = []interface{}{map[string]interface{}{"type": "constant", "key": "global"}}
		quotas := params["quotas"].([]interface{})
		quotas[0].(map[string]interface{})["keyExtraction"] = []interface{}{map[string]interface{}{"type": "constant", "key": "quota"}}

		p, err := GetPolicy(policy.PolicyMetadata{RouteName: "r1"}, params)
		if err != nil {
			t.Fatalf("GetPolicy returned error: %v", err)
		}
		rl := p.(*RateLimitPolicy)
		if len(rl.quotas[0].KeyExtraction) != 1 || rl.quotas[0].KeyExtraction[0].Key != "quota" {
			t.Fatalf("expected per-quota key extraction to be used, got %+v", rl.quotas[0].KeyExtraction)
		}
	})

	t.Run("falls back to global keyExtraction", func(t *testing.T) {
		params := basicQuotaParams()
		params["keyExtraction"] = []interface{}{map[string]interface{}{"type": "constant", "key": "global"}}

		p, err := GetPolicy(policy.PolicyMetadata{RouteName: "r1"}, params)
		if err != nil {
			t.Fatalf("GetPolicy returned error: %v", err)
		}
		rl := p.(*RateLimitPolicy)
		if len(rl.quotas[0].KeyExtraction) != 1 || rl.quotas[0].KeyExtraction[0].Key != "global" {
			t.Fatalf("expected global key extraction fallback, got %+v", rl.quotas[0].KeyExtraction)
		}
	})

	t.Run("falls back to default routename keyExtraction", func(t *testing.T) {
		p, err := GetPolicy(policy.PolicyMetadata{RouteName: "route-a"}, basicQuotaParams())
		if err != nil {
			t.Fatalf("GetPolicy returned error: %v", err)
		}
		rl := p.(*RateLimitPolicy)
		if len(rl.quotas[0].KeyExtraction) != 1 || rl.quotas[0].KeyExtraction[0].Type != "routename" {
			t.Fatalf("expected default routename key extraction, got %+v", rl.quotas[0].KeyExtraction)
		}
	})

	t.Run("uses default exceeded response configuration", func(t *testing.T) {
		p, err := GetPolicy(policy.PolicyMetadata{RouteName: "r1"}, basicQuotaParams())
		if err != nil {
			t.Fatalf("GetPolicy returned error: %v", err)
		}
		rl := p.(*RateLimitPolicy)
		if rl.statusCode != 429 {
			t.Fatalf("expected default statusCode 429, got %d", rl.statusCode)
		}
		if rl.responseFormat != "json" {
			t.Fatalf("expected default format json, got %q", rl.responseFormat)
		}
		if !strings.Contains(rl.responseBody, "Too Many Requests") {
			t.Fatalf("expected default body, got %q", rl.responseBody)
		}
	})

	t.Run("uses custom exceeded response and header toggles", func(t *testing.T) {
		params := basicQuotaParams()
		params["onRateLimitExceeded"] = map[string]interface{}{
			"statusCode": float64(503),
			"body":       "overloaded",
			"bodyFormat": "plain",
		}
		params["headers"] = map[string]interface{}{
			"includeXRateLimit": false,
			"includeIETF":       false,
			"includeRetryAfter": false,
		}
		p, err := GetPolicy(policy.PolicyMetadata{RouteName: "r1"}, params)
		if err != nil {
			t.Fatalf("GetPolicy returned error: %v", err)
		}
		rl := p.(*RateLimitPolicy)
		if rl.statusCode != 503 || rl.responseBody != "overloaded" || rl.responseFormat != "plain" {
			t.Fatalf("unexpected custom exceeded response: status=%d body=%q format=%q", rl.statusCode, rl.responseBody, rl.responseFormat)
		}
		if rl.includeXRL || rl.includeIETF || rl.includeRetry {
			t.Fatalf("expected header toggles disabled, got xrl=%t ietf=%t retry=%t", rl.includeXRL, rl.includeIETF, rl.includeRetry)
		}
	})

	t.Run("fails on unknown algorithm", func(t *testing.T) {
		params := basicQuotaParams()
		params["algorithm"] = "unknown"
		_, err := GetPolicy(policy.PolicyMetadata{RouteName: "r1"}, params)
		if err == nil || !strings.Contains(err.Error(), "unknown algorithm") {
			t.Fatalf("expected unknown algorithm error, got %v", err)
		}
	})

	t.Run("redis closed mode errors on unreachable redis", func(t *testing.T) {
		params := basicQuotaParams()
		params["backend"] = "redis"
		params["redis"] = map[string]interface{}{
			"host":              "192.0.2.1",
			"port":              float64(6399),
			"failureMode":       "closed",
			"connectionTimeout": "1ms",
			"readTimeout":       "1ms",
			"writeTimeout":      "1ms",
		}
		_, err := GetPolicy(policy.PolicyMetadata{RouteName: "r1"}, params)
		if err == nil || !strings.Contains(err.Error(), "failureMode=closed") {
			t.Fatalf("expected redis closed-mode error, got %v", err)
		}
	})

	t.Run("redis open mode allows policy creation on unreachable redis", func(t *testing.T) {
		params := basicQuotaParams()
		params["backend"] = "redis"
		params["redis"] = map[string]interface{}{
			"host":              "192.0.2.1",
			"port":              float64(6399),
			"failureMode":       "open",
			"connectionTimeout": "1ms",
			"readTimeout":       "1ms",
			"writeTimeout":      "1ms",
		}
		p, err := GetPolicy(policy.PolicyMetadata{RouteName: "r1"}, params)
		if err != nil {
			t.Fatalf("expected open-mode policy creation to succeed, got %v", err)
		}
		if p == nil {
			t.Fatal("expected non-nil policy")
		}
	})

	t.Run("multi-quota policy creation preserves quota names", func(t *testing.T) {
		params := map[string]interface{}{
			"backend":   "memory",
			"algorithm": "fixed-window",
			"quotas": []interface{}{
				map[string]interface{}{
					"name":   "burst",
					"limits": []interface{}{map[string]interface{}{"limit": float64(100), "duration": "1m"}},
				},
				map[string]interface{}{
					"name":   "daily",
					"limits": []interface{}{map[string]interface{}{"limit": float64(1000), "duration": "24h"}},
				},
			},
		}
		p, err := GetPolicy(policy.PolicyMetadata{RouteName: "r1"}, params)
		if err != nil {
			t.Fatalf("GetPolicy returned error: %v", err)
		}
		rl := p.(*RateLimitPolicy)
		if len(rl.quotas) != 2 {
			t.Fatalf("expected 2 quotas, got %d", len(rl.quotas))
		}
		if rl.quotas[0].Name != "burst" || rl.quotas[1].Name != "daily" {
			t.Fatalf("unexpected quota names: %+v", rl.quotas)
		}
		if rl.quotas[0].Limiter == nil || rl.quotas[1].Limiter == nil {
			t.Fatal("expected both quota limiters to be initialized")
		}
	})
}

func TestMemoryCacheReuseAndRefCounts(t *testing.T) {
	clearCaches()
	defer clearCaches()

	metadata := policy.PolicyMetadata{RouteName: "route-a", APIName: "api-a", APIVersion: "v1"}
	params := map[string]interface{}{
		"backend":   "memory",
		"algorithm": "fixed-window",
		"quotas": []interface{}{
			map[string]interface{}{
				"name":          "api-quota",
				"limits":        []interface{}{map[string]interface{}{"limit": float64(10), "duration": "1m"}},
				"keyExtraction": []interface{}{map[string]interface{}{"type": "apiname"}},
			},
		},
	}

	p1, err := GetPolicy(metadata, params)
	if err != nil {
		t.Fatalf("GetPolicy route-a first config failed: %v", err)
	}
	lim1 := p1.(*RateLimitPolicy).quotas[0].Limiter
	if got := getLimiterRefCountByInstance(lim1); got != 1 {
		t.Fatalf("expected refcount 1 after first policy, got %d", got)
	}
	if len(globalLimiterCache.byQuotaKey) != 1 {
		t.Fatalf("expected 1 cached limiter, got %d", len(globalLimiterCache.byQuotaKey))
	}

	p2, err := GetPolicy(metadata, params)
	if err != nil {
		t.Fatalf("GetPolicy route-a second config failed: %v", err)
	}
	lim2 := p2.(*RateLimitPolicy).quotas[0].Limiter
	if lim2 != lim1 {
		t.Fatal("expected same limiter pointer to be reused")
	}
	if got := getLimiterRefCountByInstance(lim1); got != 1 {
		t.Fatalf("expected refcount to remain 1 for same baseKey reconfigure, got %d", got)
	}
}

func TestSharedQuotaLimiterCleanup(t *testing.T) {
	clearCaches()
	defer clearCaches()

	apiName := "test-api"
	metadata1 := policy.PolicyMetadata{RouteName: "route-1", APIName: apiName, APIVersion: "v1"}
	metadata2 := policy.PolicyMetadata{RouteName: "route-2", APIName: apiName, APIVersion: "v1"}
	metadata3 := policy.PolicyMetadata{RouteName: "route-3", APIName: apiName, APIVersion: "v1"}

	sharedParams := func() map[string]interface{} {
		return map[string]interface{}{
			"backend":   "memory",
			"algorithm": "fixed-window",
			"quotas": []interface{}{
				map[string]interface{}{
					"name":          "api-quota",
					"limits":        []interface{}{map[string]interface{}{"limit": float64(10), "duration": "1m"}},
					"keyExtraction": []interface{}{map[string]interface{}{"type": "apiname"}},
				},
			},
		}
	}
	routeSpecificParams := func(name string) map[string]interface{} {
		return map[string]interface{}{
			"backend":   "memory",
			"algorithm": "fixed-window",
			"quotas": []interface{}{
				map[string]interface{}{
					"name":          name,
					"limits":        []interface{}{map[string]interface{}{"limit": float64(5), "duration": "1m"}},
					"keyExtraction": []interface{}{map[string]interface{}{"type": "routename"}},
				},
			},
		}
	}

	p1, err := GetPolicy(metadata1, sharedParams())
	if err != nil {
		t.Fatalf("Failed to create policy for route-1: %v", err)
	}
	lim1 := p1.(*RateLimitPolicy).quotas[0].Limiter
	if len(globalLimiterCache.byQuotaKey) != 1 {
		t.Fatalf("expected 1 cached limiter after route-1, got %d", len(globalLimiterCache.byQuotaKey))
	}
	if got := getLimiterRefCountByInstance(lim1); got != 1 {
		t.Fatalf("expected refcount 1 after route-1, got %d", got)
	}

	p2, err := GetPolicy(metadata2, sharedParams())
	if err != nil {
		t.Fatalf("Failed to create policy for route-2: %v", err)
	}
	lim2 := p2.(*RateLimitPolicy).quotas[0].Limiter
	if lim2 != lim1 {
		t.Fatal("expected route-1 and route-2 to share same limiter")
	}
	if len(globalLimiterCache.byQuotaKey) != 1 {
		t.Fatalf("expected still 1 cached limiter after route-2, got %d", len(globalLimiterCache.byQuotaKey))
	}
	if got := getLimiterRefCountByInstance(lim1); got != 2 {
		t.Fatalf("expected refcount 2 after route-2, got %d", got)
	}

	if _, err = GetPolicy(metadata1, routeSpecificParams("route-1-specific")); err != nil {
		t.Fatalf("Failed to update route-1: %v", err)
	}
	if got := getLimiterRefCountByInstance(lim1); got != 1 {
		t.Fatalf("expected shared refcount 1 after route-1 reconfigure, got %d", got)
	}

	p3, err := GetPolicy(metadata3, sharedParams())
	if err != nil {
		t.Fatalf("Failed to create route-3: %v", err)
	}
	lim3 := p3.(*RateLimitPolicy).quotas[0].Limiter
	if lim3 != lim1 {
		t.Fatal("expected route-3 to reuse existing shared limiter")
	}
	if got := getLimiterRefCountByInstance(lim1); got != 2 {
		t.Fatalf("expected shared refcount 2 after route-3, got %d", got)
	}

	if _, err = GetPolicy(metadata2, routeSpecificParams("route-2-specific")); err != nil {
		t.Fatalf("Failed to update route-2: %v", err)
	}
	if got := getLimiterRefCountByInstance(lim1); got != 1 {
		t.Fatalf("expected shared refcount 1 after route-2 reconfigure, got %d", got)
	}

	if _, err = GetPolicy(metadata3, routeSpecificParams("route-3-specific")); err != nil {
		t.Fatalf("Failed to update route-3: %v", err)
	}
	if got := getLimiterRefCountByInstance(lim1); got != 0 {
		t.Fatalf("expected shared limiter refcount 0 after all reconfigured, got %d", got)
	}
}

func TestRouteScopedQuotaCleanup(t *testing.T) {
	clearCaches()
	defer clearCaches()

	apiName := "test-api"
	metadata1 := policy.PolicyMetadata{RouteName: "route-1", APIName: apiName, APIVersion: "v1"}
	metadata2 := policy.PolicyMetadata{RouteName: "route-2", APIName: apiName, APIVersion: "v1"}

	params := func(name string) map[string]interface{} {
		return map[string]interface{}{
			"backend":   "memory",
			"algorithm": "fixed-window",
			"quotas": []interface{}{
				map[string]interface{}{
					"name":          name,
					"limits":        []interface{}{map[string]interface{}{"limit": float64(10), "duration": "1m"}},
					"keyExtraction": []interface{}{map[string]interface{}{"type": "routename"}},
				},
			},
		}
	}

	p1, err := GetPolicy(metadata1, params("route-quota"))
	if err != nil {
		t.Fatalf("Failed to create route-1 policy: %v", err)
	}
	p2, err := GetPolicy(metadata2, params("route-quota"))
	if err != nil {
		t.Fatalf("Failed to create route-2 policy: %v", err)
	}

	lim1 := p1.(*RateLimitPolicy).quotas[0].Limiter
	lim2 := p2.(*RateLimitPolicy).quotas[0].Limiter
	if lim1 == lim2 {
		t.Fatal("route-scoped limiters should not be shared across routes")
	}
	if len(globalLimiterCache.byQuotaKey) != 2 {
		t.Fatalf("expected 2 cached limiters, got %d", len(globalLimiterCache.byQuotaKey))
	}

	if _, err := GetPolicy(metadata1, params("route-1-updated")); err != nil {
		t.Fatalf("Failed to update route-1 policy: %v", err)
	}
	if getLimiterRefCountByInstance(lim1) != 0 {
		t.Fatal("expected old route-1 limiter to be cleaned up")
	}
	if getLimiterRefCountByInstance(lim2) != 1 {
		t.Fatal("expected route-2 limiter to remain referenced")
	}
}

func TestModeBehavior(t *testing.T) {
	mkQuota := func(enabled bool, sources []CostSource) QuotaRuntime {
		var ce *CostExtractor
		if enabled {
			ce = NewCostExtractor(CostExtractionConfig{Enabled: true, Default: 1, Sources: sources})
		}
		return QuotaRuntime{CostExtractionEnabled: enabled, CostExtractor: ce}
	}

	tests := []struct {
		name        string
		quotas      []QuotaRuntime
		wantReqBody policy.BodyProcessingMode
		wantResBody policy.BodyProcessingMode
	}{
		{
			name:        "no cost extraction",
			quotas:      []QuotaRuntime{{}},
			wantReqBody: policy.BodyModeSkip,
			wantResBody: policy.BodyModeSkip,
		},
		{
			name:        "request body source",
			quotas:      []QuotaRuntime{mkQuota(true, []CostSource{{Type: CostSourceRequestBody, JSONPath: "$.tokens"}})},
			wantReqBody: policy.BodyModeBuffer,
			wantResBody: policy.BodyModeSkip,
		},
		{
			// response_body uses BodyModeStream so the policy can process SSE events
			// per-chunk and avoid buffering the entire LLM response in memory.
			// OnResponseBody remains as the buffered fallback when another policy in
			// the chain forces BodyModeBuffer.
			name:        "response body source",
			quotas:      []QuotaRuntime{mkQuota(true, []CostSource{{Type: CostSourceResponseBody, JSONPath: "$.usage.total"}})},
			wantReqBody: policy.BodyModeSkip,
			wantResBody: policy.BodyModeStream,
		},
		{
			// request_body buffers the request; response_body streams the response.
			name:        "mixed body sources",
			quotas:      []QuotaRuntime{mkQuota(true, []CostSource{{Type: CostSourceRequestBody, JSONPath: "$.in"}, {Type: CostSourceResponseBody, JSONPath: "$.out"}})},
			wantReqBody: policy.BodyModeBuffer,
			wantResBody: policy.BodyModeStream,
		},
		{
			name:        "configured but effectively disabled",
			quotas:      []QuotaRuntime{mkQuota(false, []CostSource{{Type: CostSourceResponseBody, JSONPath: "$.x"}})},
			wantReqBody: policy.BodyModeSkip,
			wantResBody: policy.BodyModeSkip,
		},
		{
			name:        "request header only source skips body buffering",
			quotas:      []QuotaRuntime{mkQuota(true, []CostSource{{Type: CostSourceRequestHeader, Key: "x-cost"}})},
			wantReqBody: policy.BodyModeSkip,
			wantResBody: policy.BodyModeSkip,
		},
		{
			name:        "response header only source skips body buffering",
			quotas:      []QuotaRuntime{mkQuota(true, []CostSource{{Type: CostSourceResponseHeader, Key: "x-cost"}})},
			wantReqBody: policy.BodyModeSkip,
			wantResBody: policy.BodyModeSkip,
		},
		{
			name:        "request metadata source requires request body phase",
			quotas:      []QuotaRuntime{mkQuota(true, []CostSource{{Type: CostSourceRequestMetadata, Key: "tokens"}})},
			wantReqBody: policy.BodyModeBuffer,
			wantResBody: policy.BodyModeSkip,
		},
		{
			// response_metadata uses BodyModeStream: metadata written by upstream policies
			// is available in SharedContext at EOS, read via the synthetic ResponseContext
			// built in finalizeAndConsumeStreamingCosts.
			name:        "response metadata source requires response body phase",
			quotas:      []QuotaRuntime{mkQuota(true, []CostSource{{Type: CostSourceResponseMetadata, Key: "x-llm-cost"}})},
			wantReqBody: policy.BodyModeSkip,
			wantResBody: policy.BodyModeStream,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &RateLimitPolicy{quotas: tt.quotas}
			mode := p.Mode()
			if mode.RequestBodyMode != tt.wantReqBody || mode.ResponseBodyMode != tt.wantResBody {
				t.Fatalf("unexpected mode: req=%v resp=%v", mode.RequestBodyMode, mode.ResponseBodyMode)
			}
			if mode.RequestHeaderMode != policy.HeaderModeProcess || mode.ResponseHeaderMode != policy.HeaderModeProcess {
				t.Fatalf("expected header mode process for both phases, got req=%v resp=%v", mode.RequestHeaderMode, mode.ResponseHeaderMode)
			}
		})
	}
}

func TestCostExtractorMethods(t *testing.T) {
	enabled := func(sources []CostSource) *CostExtractor {
		return NewCostExtractor(CostExtractionConfig{Enabled: true, Default: 1, Sources: sources})
	}

	tests := []struct {
		name                 string
		sources              []CostSource
		wantReqHeaderOnly    bool
		wantRespHeaderOnly   bool
		wantReqBodyPhase     bool
		wantRequiresRespBody bool
	}{
		{
			name:                 "request_header only",
			sources:              []CostSource{{Type: CostSourceRequestHeader, Key: "x"}},
			wantReqHeaderOnly:    true,
			wantRespHeaderOnly:   false,
			wantReqBodyPhase:     false,
			wantRequiresRespBody: false,
		},
		{
			name:                 "response_header only",
			sources:              []CostSource{{Type: CostSourceResponseHeader, Key: "x"}},
			wantReqHeaderOnly:    false,
			wantRespHeaderOnly:   true,
			wantReqBodyPhase:     false,
			wantRequiresRespBody: false,
		},
		{
			name:                 "request_metadata only",
			sources:              []CostSource{{Type: CostSourceRequestMetadata, Key: "x"}},
			wantReqHeaderOnly:    false,
			wantRespHeaderOnly:   false,
			wantReqBodyPhase:     true,
			wantRequiresRespBody: false,
		},
		{
			name:                 "response_metadata only",
			sources:              []CostSource{{Type: CostSourceResponseMetadata, Key: "x"}},
			wantReqHeaderOnly:    false,
			wantRespHeaderOnly:   false,
			wantReqBodyPhase:     false,
			wantRequiresRespBody: false,
		},
		{
			name:                 "request_body only",
			sources:              []CostSource{{Type: CostSourceRequestBody, JSONPath: "$.x"}},
			wantReqHeaderOnly:    false,
			wantRespHeaderOnly:   false,
			wantReqBodyPhase:     true,
			wantRequiresRespBody: false,
		},
		{
			name:                 "response_body only",
			sources:              []CostSource{{Type: CostSourceResponseBody, JSONPath: "$.x"}},
			wantReqHeaderOnly:    false,
			wantRespHeaderOnly:   false,
			wantReqBodyPhase:     false,
			wantRequiresRespBody: true,
		},
		{
			name:                 "request_header + request_metadata disqualifies request header only",
			sources:              []CostSource{{Type: CostSourceRequestHeader, Key: "x"}, {Type: CostSourceRequestMetadata, Key: "y"}},
			wantReqHeaderOnly:    false,
			wantRespHeaderOnly:   false,
			wantReqBodyPhase:     true,
			wantRequiresRespBody: false,
		},
		{
			name:                 "response_header + response_body disqualifies response header only",
			sources:              []CostSource{{Type: CostSourceResponseHeader, Key: "x"}, {Type: CostSourceResponseBody, JSONPath: "$.y"}},
			wantReqHeaderOnly:    false,
			wantRespHeaderOnly:   false,
			wantReqBodyPhase:     false,
			wantRequiresRespBody: true,
		},
		{
			name:                 "response_header + response_metadata disqualifies response header only",
			sources:              []CostSource{{Type: CostSourceResponseHeader, Key: "x"}, {Type: CostSourceResponseMetadata, Key: "y"}},
			wantReqHeaderOnly:    false,
			wantRespHeaderOnly:   false,
			wantReqBodyPhase:     false,
			wantRequiresRespBody: false,
		},
		{
			// Response-phase sources are ignored when evaluating request-header-only,
			// and request-phase sources are ignored when evaluating response-header-only.
			name:                 "request_header + response_header both qualify for their respective header-only paths",
			sources:              []CostSource{{Type: CostSourceRequestHeader, Key: "x"}, {Type: CostSourceResponseHeader, Key: "y"}},
			wantReqHeaderOnly:    true,
			wantRespHeaderOnly:   true,
			wantReqBodyPhase:     false,
			wantRequiresRespBody: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ce := enabled(tt.sources)
			if got := ce.HasRequestHeaderOnlyCostSources(); got != tt.wantReqHeaderOnly {
				t.Errorf("HasRequestHeaderOnlyCostSources() = %v, want %v", got, tt.wantReqHeaderOnly)
			}
			if got := ce.HasResponseHeaderOnlyCostSources(); got != tt.wantRespHeaderOnly {
				t.Errorf("HasResponseHeaderOnlyCostSources() = %v, want %v", got, tt.wantRespHeaderOnly)
			}
			if got := ce.HasRequestBodyPhase(); got != tt.wantReqBodyPhase {
				t.Errorf("HasRequestBodyPhase() = %v, want %v", got, tt.wantReqBodyPhase)
			}
			if got := ce.RequiresResponseBody(); got != tt.wantRequiresRespBody {
				t.Errorf("RequiresResponseBody() = %v, want %v", got, tt.wantRequiresRespBody)
			}
		})
	}

	t.Run("disabled extractor always returns false for all predicates", func(t *testing.T) {
		ce := NewCostExtractor(CostExtractionConfig{Enabled: false, Sources: []CostSource{{Type: CostSourceRequestHeader, Key: "x"}}})
		if ce.HasRequestHeaderOnlyCostSources() {
			t.Error("HasRequestHeaderOnlyCostSources() should be false when disabled")
		}
		if ce.HasResponseHeaderOnlyCostSources() {
			t.Error("HasResponseHeaderOnlyCostSources() should be false when disabled")
		}
		if ce.HasRequestBodyPhase() {
			t.Error("HasRequestBodyPhase() should be false when disabled")
		}
		if ce.RequiresResponseBody() {
			t.Error("RequiresResponseBody() should be false when disabled")
		}
	})
}

func TestKeyExtractionBehavior(t *testing.T) {
	p := &RateLimitPolicy{routeName: "route-main"}
	ctx := newRequestCtx(map[string][]string{
		"x-tenant":        {"tenant-a", "tenant-b"},
		"x-forwarded-for": {"10.1.1.1, 10.1.1.2"},
		"x-real-ip":       {"10.9.9.9"},
	}, map[string]interface{}{"plan": "gold", "intPlan": 42})

	t.Run("empty key extraction returns route", func(t *testing.T) {
		q := &QuotaRuntime{}
		if got := p.extractQuotaKey(ctx, q); got != "route-main" {
			t.Fatalf("expected route-main, got %q", got)
		}
	})

	t.Run("header component", func(t *testing.T) {
		q := &QuotaRuntime{KeyExtraction: []KeyComponent{{Type: "header", Key: "x-tenant"}}}
		if got := p.extractQuotaKey(ctx, q); got != "tenant-a" {
			t.Fatalf("expected tenant-a, got %q", got)
		}
	})

	t.Run("missing header placeholder", func(t *testing.T) {
		q := &QuotaRuntime{KeyExtraction: []KeyComponent{{Type: "header", Key: "x-missing"}}}
		if got := p.extractQuotaKey(ctx, q); got != "_missing_header_x-missing_" {
			t.Fatalf("unexpected placeholder: %q", got)
		}
	})

	t.Run("metadata string value", func(t *testing.T) {
		q := &QuotaRuntime{KeyExtraction: []KeyComponent{{Type: "metadata", Key: "plan"}}}
		if got := p.extractQuotaKey(ctx, q); got != "gold" {
			t.Fatalf("expected gold, got %q", got)
		}
	})

	t.Run("missing or non-string metadata placeholder", func(t *testing.T) {
		q1 := &QuotaRuntime{KeyExtraction: []KeyComponent{{Type: "metadata", Key: "missing"}}}
		if got := p.extractQuotaKey(ctx, q1); got != "_missing_metadata_missing_" {
			t.Fatalf("unexpected placeholder: %q", got)
		}
		q2 := &QuotaRuntime{KeyExtraction: []KeyComponent{{Type: "metadata", Key: "intPlan"}}}
		if got := p.extractQuotaKey(ctx, q2); got != "_missing_metadata_intPlan_" {
			t.Fatalf("unexpected placeholder: %q", got)
		}
	})

	t.Run("missing metadata uses Fallback when set", func(t *testing.T) {
		q := &QuotaRuntime{KeyExtraction: []KeyComponent{{Type: "metadata", Key: "x-wso2-application-id", Fallback: "default"}}}
		if got := p.extractQuotaKey(ctx, q); got != "default" {
			t.Fatalf("expected fallback %q, got %q", "default", got)
		}
	})

	t.Run("empty string metadata uses Fallback when set", func(t *testing.T) {
		ctxEmptyApp := newRequestCtx(nil, map[string]interface{}{"x-wso2-application-id": ""})
		q := &QuotaRuntime{KeyExtraction: []KeyComponent{{Type: "metadata", Key: "x-wso2-application-id", Fallback: "default"}}}
		if got := p.extractQuotaKey(ctxEmptyApp, q); got != "default" {
			t.Fatalf("expected fallback %q for empty string value, got %q", "default", got)
		}
	})

	t.Run("present metadata value ignores Fallback", func(t *testing.T) {
		ctxWithApp := newRequestCtx(nil, map[string]interface{}{"x-wso2-application-id": "app-123"})
		q := &QuotaRuntime{KeyExtraction: []KeyComponent{{Type: "metadata", Key: "x-wso2-application-id", Fallback: "default"}}}
		if got := p.extractQuotaKey(ctxWithApp, q); got != "app-123" {
			t.Fatalf("expected actual value %q, got %q", "app-123", got)
		}
	})

	t.Run("multi-component consumer key with fallback", func(t *testing.T) {
		ctxNoApp := newRequestCtx(nil, nil)
		q := &QuotaRuntime{KeyExtraction: []KeyComponent{
			{Type: "routename"},
			{Type: "metadata", Key: "x-wso2-application-id", Fallback: "default"},
		}}
		p2 := &RateLimitPolicy{routeName: "my-route"}
		if got := p2.extractQuotaKey(ctxNoApp, q); got != "my-route:default" {
			t.Fatalf("expected %q, got %q", "my-route:default", got)
		}
	})

	t.Run("constant component", func(t *testing.T) {
		q := &QuotaRuntime{KeyExtraction: []KeyComponent{{Type: "constant", Key: "fixed"}}}
		if got := p.extractQuotaKey(ctx, q); got != "fixed" {
			t.Fatalf("expected fixed, got %q", got)
		}
	})

	t.Run("apiname/apiversion and missing values", func(t *testing.T) {
		q := &QuotaRuntime{KeyExtraction: []KeyComponent{{Type: "apiname"}, {Type: "apiversion"}}}
		if got := p.extractQuotaKey(ctx, q); got != "petstore:v1" {
			t.Fatalf("expected petstore:v1, got %q", got)
		}

		ctx2 := newRequestCtx(nil, nil)
		ctx2.APIName = ""
		ctx2.APIVersion = ""
		if got := p.extractKeyComponent(ctx2, KeyComponent{Type: "apiname"}); got != "" {
			t.Fatalf("expected empty apiname, got %q", got)
		}
		if got := p.extractKeyComponent(ctx2, KeyComponent{Type: "apiversion"}); got != "" {
			t.Fatalf("expected empty apiversion, got %q", got)
		}
	})

	t.Run("routename component", func(t *testing.T) {
		if got := p.extractKeyComponent(ctx, KeyComponent{Type: "routename"}); got != "route-main" {
			t.Fatalf("expected route-main, got %q", got)
		}
	})

	t.Run("ip precedence", func(t *testing.T) {
		if got := p.extractIPAddress(ctx.Headers); got != "10.1.1.1" {
			t.Fatalf("expected first x-forwarded-for IP, got %q", got)
		}

		onlyXReal := newRequestCtx(map[string][]string{"x-real-ip": {"10.8.8.8"}}, nil)
		if got := p.extractIPAddress(onlyXReal.Headers); got != "10.8.8.8" {
			t.Fatalf("expected x-real-ip fallback, got %q", got)
		}

		none := newRequestCtx(nil, nil)
		if got := p.extractIPAddress(none.Headers); got != "unknown" {
			t.Fatalf("expected unknown fallback, got %q", got)
		}
	})

	t.Run("unknown component type returns empty", func(t *testing.T) {
		if got := p.extractKeyComponent(ctx, KeyComponent{Type: "unknown"}); got != "" {
			t.Fatalf("expected empty string for unknown type, got %q", got)
		}
	})

	t.Run("multi-component order is preserved", func(t *testing.T) {
		q := &QuotaRuntime{KeyExtraction: []KeyComponent{{Type: "constant", Key: "a"}, {Type: "constant", Key: "b"}, {Type: "constant", Key: "c"}}}
		if got := p.extractQuotaKey(ctx, q); got != "a:b:c" {
			t.Fatalf("expected a:b:c, got %q", got)
		}
	})

	t.Run("cel happy path and failure path", func(t *testing.T) {
		happy := &QuotaRuntime{KeyExtraction: []KeyComponent{{Type: "cel", Expression: "'tenant-cel'"}}}
		if got := p.extractQuotaKey(ctx, happy); got != "tenant-cel" {
			t.Fatalf("expected cel evaluated string, got %q", got)
		}

		failed := &QuotaRuntime{KeyExtraction: []KeyComponent{{Type: "cel", Expression: "1"}}}
		if got := p.extractQuotaKey(ctx, failed); got != "_cel_eval_error_" {
			t.Fatalf("expected cel eval placeholder, got %q", got)
		}
	})
}

func TestKeyExtractionHeaderPhase(t *testing.T) {
	p := &RateLimitPolicy{routeName: "route-main"}
	hctx := &policy.RequestHeaderContext{
		SharedContext: &policy.SharedContext{
			APIName:    "petstore",
			APIVersion: "v1",
			Metadata:   map[string]interface{}{},
		},
		Headers: policy.NewHeaders(map[string][]string{
			"x-tenant": {"tenant-a"},
		}),
	}

	t.Run("apiname returns API name not route name", func(t *testing.T) {
		got := p.extractKeyComponentFromHeaderCtx(hctx, KeyComponent{Type: "apiname"})
		if got != "petstore" {
			t.Fatalf("expected petstore, got %q (regression: should not return route name)", got)
		}
	})

	t.Run("apiversion returns API version not route name", func(t *testing.T) {
		got := p.extractKeyComponentFromHeaderCtx(hctx, KeyComponent{Type: "apiversion"})
		if got != "v1" {
			t.Fatalf("expected v1, got %q (regression: should not return route name)", got)
		}
	})

	t.Run("apiname empty falls back to empty string", func(t *testing.T) {
		emptyCtx := &policy.RequestHeaderContext{
			SharedContext: &policy.SharedContext{Metadata: map[string]interface{}{}},
			Headers:       policy.NewHeaders(nil),
		}
		got := p.extractKeyComponentFromHeaderCtx(emptyCtx, KeyComponent{Type: "apiname"})
		if got != "" {
			t.Fatalf("expected empty string, got %q", got)
		}
	})

	t.Run("missing metadata uses Fallback in header phase", func(t *testing.T) {
		noAppCtx := newRequestHeaderCtx(nil, nil) // no x-wso2-application-id in metadata
		got := p.extractKeyComponentFromHeaderCtx(noAppCtx, KeyComponent{Type: "metadata", Key: "x-wso2-application-id", Fallback: "default"})
		if got != "default" {
			t.Fatalf("expected fallback %q, got %q", "default", got)
		}
	})

	t.Run("empty string metadata uses Fallback in header phase", func(t *testing.T) {
		emptyAppCtx := newRequestHeaderCtx(nil, map[string]interface{}{"x-wso2-application-id": ""})
		got := p.extractKeyComponentFromHeaderCtx(emptyAppCtx, KeyComponent{Type: "metadata", Key: "x-wso2-application-id", Fallback: "default"})
		if got != "default" {
			t.Fatalf("expected fallback %q for empty string, got %q", "default", got)
		}
	})

	t.Run("present metadata uses actual value over Fallback in header phase", func(t *testing.T) {
		withAppCtx := newRequestHeaderCtx(nil, map[string]interface{}{"x-wso2-application-id": "app-456"})
		got := p.extractKeyComponentFromHeaderCtx(withAppCtx, KeyComponent{Type: "metadata", Key: "x-wso2-application-id", Fallback: "default"})
		if got != "app-456" {
			t.Fatalf("expected actual value %q, got %q", "app-456", got)
		}
	})
}

// TestAuthPropertyKeyExtraction covers the "authproperty" keyExtraction type — reads a
// value from SharedContext.AuthContext.Properties, populated by auth policies like jwt-auth
// from non-standard JWT claims (e.g. a custom "app_id" claim), which is NOT reachable via
// "header" or "metadata".
func TestAuthPropertyKeyExtraction(t *testing.T) {
	p := &RateLimitPolicy{routeName: "route-main"}

	t.Run("present auth property is returned", func(t *testing.T) {
		hctx := &policy.RequestHeaderContext{
			SharedContext: &policy.SharedContext{
				Metadata: map[string]interface{}{},
				AuthContext: &policy.AuthContext{
					Authenticated: true,
					Properties:    map[string]string{"app_id": "guest-42"},
				},
			},
			Headers: policy.NewHeaders(nil),
		}
		got := p.extractKeyComponentFromHeaderCtx(hctx, KeyComponent{Type: "authproperty", Key: "app_id"})
		if got != "guest-42" {
			t.Fatalf("expected guest-42, got %q", got)
		}
	})

	t.Run("missing AuthContext falls back to placeholder when no Fallback set", func(t *testing.T) {
		hctx := &policy.RequestHeaderContext{
			SharedContext: &policy.SharedContext{Metadata: map[string]interface{}{}},
			Headers:       policy.NewHeaders(nil),
		}
		got := p.extractKeyComponentFromHeaderCtx(hctx, KeyComponent{Type: "authproperty", Key: "app_id"})
		if got != "_missing_authproperty_app_id_" {
			t.Fatalf("expected placeholder, got %q", got)
		}
	})

	t.Run("missing claim uses Fallback when set", func(t *testing.T) {
		hctx := &policy.RequestHeaderContext{
			SharedContext: &policy.SharedContext{
				Metadata:    map[string]interface{}{},
				AuthContext: &policy.AuthContext{Authenticated: true, Properties: map[string]string{}},
			},
			Headers: policy.NewHeaders(nil),
		}
		got := p.extractKeyComponentFromHeaderCtx(hctx, KeyComponent{Type: "authproperty", Key: "app_id", Fallback: "unknown-app"})
		if got != "unknown-app" {
			t.Fatalf("expected fallback unknown-app, got %q", got)
		}
	})

	t.Run("does not read from Metadata even if same key exists there", func(t *testing.T) {
		// Guards against accidentally aliasing authproperty to the metadata map.
		hctx := &policy.RequestHeaderContext{
			SharedContext: &policy.SharedContext{
				Metadata:    map[string]interface{}{"app_id": "from-metadata-not-auth"},
				AuthContext: &policy.AuthContext{Authenticated: true, Properties: map[string]string{"app_id": "from-auth-context"}},
			},
			Headers: policy.NewHeaders(nil),
		}
		got := p.extractKeyComponentFromHeaderCtx(hctx, KeyComponent{Type: "authproperty", Key: "app_id"})
		if got != "from-auth-context" {
			t.Fatalf("expected value from AuthContext.Properties, got %q", got)
		}
	})

	t.Run("full-context extraction (extractKeyComponent) behaves the same as header-phase", func(t *testing.T) {
		reqCtx := &policy.RequestContext{
			SharedContext: &policy.SharedContext{
				Metadata: map[string]interface{}{},
				AuthContext: &policy.AuthContext{
					Authenticated: true,
					Properties:    map[string]string{"app_id": "channel-partner"},
				},
			},
			Headers: policy.NewHeaders(nil),
		}
		got := p.extractKeyComponent(reqCtx, KeyComponent{Type: "authproperty", Key: "app_id"})
		if got != "channel-partner" {
			t.Fatalf("expected channel-partner, got %q", got)
		}
	})
}

// TestAuthPropertyKeyExtraction_EndToEnd proves authproperty works through the actual
// policy entrypoint (OnRequestHeaders), not just the extraction helper — mirrors a JWT
// carrying a custom "app_id" claim, which jwt-auth would already have written into
// AuthContext.Properties before advanced-ratelimit runs.
func TestAuthPropertyKeyExtraction_EndToEnd(t *testing.T) {
	lim := &fakeLimiter{allowNFn: func(ctx context.Context, key string, n int64) (*limiter.Result, error) {
		if key != "guest-42" {
			t.Fatalf("expected limiter key %q derived from AuthContext.Properties, got %q", "guest-42", key)
		}
		return newResult(true, 10, 9, 0, time.Minute), nil
	}}
	p := &RateLimitPolicy{
		quotas: []QuotaRuntime{{
			Name:          "per-app",
			KeyExtraction: []KeyComponent{{Type: "authproperty", Key: "app_id"}},
			Limiter:       lim,
			Limits:        []LimitConfig{{Limit: 10, Duration: time.Minute}},
		}},
		routeName:      "route-main",
		statusCode:     429,
		responseBody:   `{"error":"limited"}`,
		responseFormat: "json",
		backend:        "memory",
	}
	hctx := &policy.RequestHeaderContext{
		SharedContext: &policy.SharedContext{
			Metadata: map[string]interface{}{},
			AuthContext: &policy.AuthContext{
				Authenticated: true,
				AuthType:      "jwt",
				Properties:    map[string]string{"app_id": "guest-42"},
			},
		},
		Headers: policy.NewHeaders(nil),
	}

	action := p.OnRequestHeaders(context.Background(), hctx, nil)
	if _, ok := action.(policy.UpstreamRequestHeaderModifications); !ok {
		t.Fatalf("expected UpstreamRequestHeaderModifications, got %T", action)
	}
	if lim.allowNCalls != 1 {
		t.Fatalf("expected AllowN called once, got %d calls", lim.allowNCalls)
	}
}

// TestAuthPropertyAndMatch_Combined proves authproperty and match compose cleanly — this
// is the combined shape needed when a customer wants to bucket AND filter by a JWT claim
// that is only reachable via AuthContext, not a header.
func TestAuthPropertyAndMatch_Combined(t *testing.T) {
	basePolicy := func(lim *fakeLimiter) *RateLimitPolicy {
		return &RateLimitPolicy{
			quotas: []QuotaRuntime{{
				Name: "guest-and-partner-checkout",
				KeyExtraction: []KeyComponent{
					{Type: "authproperty", Key: "app_id", Match: regexp.MustCompile("^(guest-.*|channel-partner)$")},
				},
				Limiter: lim,
				Limits:  []LimitConfig{{Limit: 10, Duration: time.Minute}},
			}},
			routeName:      "route-main",
			statusCode:     429,
			responseBody:   `{"error":"limited"}`,
			responseFormat: "json",
			backend:        "memory",
		}
	}
	authCtx := func(appID string) *policy.RequestHeaderContext {
		return &policy.RequestHeaderContext{
			SharedContext: &policy.SharedContext{
				Metadata:    map[string]interface{}{},
				AuthContext: &policy.AuthContext{Authenticated: true, AuthType: "jwt", Properties: map[string]string{"app_id": appID}},
			},
			Headers: policy.NewHeaders(nil),
		}
	}

	t.Run("matching JWT claim is counted and enforced", func(t *testing.T) {
		lim := &fakeLimiter{allowNFn: func(ctx context.Context, key string, n int64) (*limiter.Result, error) {
			return newResult(true, 10, 9, 0, time.Minute), nil
		}}
		p := basePolicy(lim)
		action := p.OnRequestHeaders(context.Background(), authCtx("guest-42"), nil)
		if _, ok := action.(policy.UpstreamRequestHeaderModifications); !ok {
			t.Fatalf("expected UpstreamRequestHeaderModifications, got %T", action)
		}
		if lim.allowNCalls != 1 {
			t.Fatalf("expected AllowN called once, got %d calls", lim.allowNCalls)
		}
	})

	t.Run("non-matching JWT claim bypasses the quota entirely", func(t *testing.T) {
		lim := &fakeLimiter{allowNFn: func(ctx context.Context, key string, n int64) (*limiter.Result, error) {
			return newResult(false, 10, 0, 5*time.Second, time.Minute), nil
		}}
		p := basePolicy(lim)
		action := p.OnRequestHeaders(context.Background(), authCtx("internal-app-1"), nil)
		if _, ok := action.(policy.UpstreamRequestHeaderModifications); !ok {
			t.Fatalf("expected non-matching request to be allowed through, got %T", action)
		}
		if lim.allowNCalls != 0 {
			t.Fatalf("expected AllowN to never be called for a non-matching request, got %d calls", lim.allowNCalls)
		}
	})
}

func TestParseKeyExtraction_FallbackField(t *testing.T) {
	t.Run("fallback string is parsed", func(t *testing.T) {
		raw := []interface{}{
			map[string]interface{}{"type": "metadata", "key": "x-wso2-application-id", "fallback": "default"},
		}
		comps, err := parseKeyExtraction(raw)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(comps) != 1 {
			t.Fatalf("expected 1 component, got %d", len(comps))
		}
		if comps[0].Fallback != "default" {
			t.Fatalf("expected Fallback %q, got %q", "default", comps[0].Fallback)
		}
	})

	t.Run("no fallback field leaves Fallback empty", func(t *testing.T) {
		raw := []interface{}{
			map[string]interface{}{"type": "metadata", "key": "x-wso2-application-id"},
		}
		comps, err := parseKeyExtraction(raw)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if comps[0].Fallback != "" {
			t.Fatalf("expected empty Fallback, got %q", comps[0].Fallback)
		}
	})

	t.Run("non-string fallback returns error", func(t *testing.T) {
		raw := []interface{}{
			map[string]interface{}{"type": "metadata", "key": "x-wso2-application-id", "fallback": 42},
		}
		_, err := parseKeyExtraction(raw)
		if err == nil || !strings.Contains(err.Error(), "fallback must be a string") {
			t.Fatalf("expected fallback type error, got %v", err)
		}
	})
}

// TestConsumerFallbackKey_UsesDefaultWhenAppIDMissing verifies that when a consumer-based
// rate limit is configured with fallback "default" and a request arrives without an application
// ID in metadata, the key used is "routename:default" — not the backend key "routename".
// This means:
//  1. Unauthenticated requests share a single "default" counter (not the backend counter).
//  2. Once the "default" counter is exhausted, authenticated requests with a real app ID
//     are still allowed (their counter is independent).
func TestConsumerFallbackKey_UsesDefaultWhenAppIDMissing(t *testing.T) {
	clearCaches()
	defer clearCaches()

	consumerParams := map[string]interface{}{
		"backend":   "memory",
		"algorithm": "fixed-window",
		"quotas": []interface{}{
			map[string]interface{}{
				"name": "consumer-request-limit",
				"limits": []interface{}{
					map[string]interface{}{"limit": float64(2), "duration": "1h"},
				},
				"keyExtraction": []interface{}{
					map[string]interface{}{"type": "routename"},
					map[string]interface{}{"type": "metadata", "key": "x-wso2-application-id", "fallback": "default"},
				},
			},
		},
	}

	pol, err := GetPolicy(policy.PolicyMetadata{RouteName: "route-main"}, consumerParams)
	if err != nil {
		t.Fatalf("GetPolicy failed: %v", err)
	}
	p := pol.(*RateLimitPolicy)

	// Request 1 — no app ID — key: "route-main:default" — should be allowed (1/2)
	req1 := newRequestHeaderCtx(nil, nil)
	action1 := p.OnRequestHeaders(context.Background(), req1, consumerParams)
	if _, ok := action1.(policy.UpstreamRequestHeaderModifications); !ok {
		t.Fatalf("request 1 (no app ID): expected allowed, got %T", action1)
	}

	// Request 2 — no app ID — key: "route-main:default" — should be allowed (2/2)
	req2 := newRequestHeaderCtx(nil, nil)
	action2 := p.OnRequestHeaders(context.Background(), req2, consumerParams)
	if _, ok := action2.(policy.UpstreamRequestHeaderModifications); !ok {
		t.Fatalf("request 2 (no app ID): expected allowed, got %T", action2)
	}

	// Request 3 — no app ID — key: "route-main:default" — counter exhausted, should be blocked
	req3 := newRequestHeaderCtx(nil, nil)
	action3 := p.OnRequestHeaders(context.Background(), req3, consumerParams)
	assertImmediateResponse(t, action3, 429)

	// Request with a real app ID — key: "route-main:app-123" — separate counter, should be allowed
	reqWithApp := newRequestHeaderCtx(nil, map[string]interface{}{"x-wso2-application-id": "app-123"})
	actionWithApp := p.OnRequestHeaders(context.Background(), reqWithApp, consumerParams)
	if _, ok := actionWithApp.(policy.UpstreamRequestHeaderModifications); !ok {
		t.Fatalf("request with app ID: expected allowed (separate counter), got %T", actionWithApp)
	}
}

func TestOnRequestBehavior(t *testing.T) {
	basePolicy := func(quotas []QuotaRuntime) *RateLimitPolicy {
		return &RateLimitPolicy{
			quotas:         quotas,
			routeName:      "route-main",
			statusCode:     429,
			responseBody:   `{"error":"limited"}`,
			responseFormat: "json",
			backend:        "memory",
			includeXRL:     true,
			includeIETF:    true,
			includeRetry:   true,
		}
	}

	t.Run("standard allowed stores metadata", func(t *testing.T) {
		lim := &fakeLimiter{allowNFn: func(ctx context.Context, key string, n int64) (*limiter.Result, error) {
			return newResult(true, 10, 9, 0, time.Minute), nil
		}}
		p := basePolicy([]QuotaRuntime{{Name: "q1", KeyExtraction: []KeyComponent{{Type: "constant", Key: "k1"}}, Limiter: lim, Limits: []LimitConfig{{Limit: 10, Duration: time.Minute}}}})
		hctx := newRequestHeaderCtx(nil, nil)

		action := p.OnRequestHeaders(context.Background(), hctx, nil)
		if _, ok := action.(policy.UpstreamRequestHeaderModifications); !ok {
			t.Fatalf("expected UpstreamRequestHeaderModifications, got %T", action)
		}
		if _, ok := hctx.Metadata[rateLimitResultKey]; !ok {
			t.Fatalf("expected %s metadata to be present", rateLimitResultKey)
		}
		if _, ok := hctx.Metadata[rateLimitKeysKey]; !ok {
			t.Fatalf("expected %s metadata to be present", rateLimitKeysKey)
		}
		if lim.allowNCalls != 1 || lim.lastCost != 1 {
			t.Fatalf("expected AllowN called once with cost 1, calls=%d cost=%d", lim.allowNCalls, lim.lastCost)
		}
	})

	t.Run("standard denied returns immediate response", func(t *testing.T) {
		lim := &fakeLimiter{allowNFn: func(ctx context.Context, key string, n int64) (*limiter.Result, error) {
			return newResult(false, 10, 0, 5*time.Second, time.Minute), nil
		}}
		p := basePolicy([]QuotaRuntime{{Name: "q1", KeyExtraction: []KeyComponent{{Type: "constant", Key: "k1"}}, Limiter: lim, Limits: []LimitConfig{{Limit: 10, Duration: time.Minute}}}})
		action := p.OnRequestHeaders(context.Background(), newRequestHeaderCtx(nil, nil), nil)
		resp := assertImmediateResponse(t, action, 429)
		if resp.Headers["x-ratelimit-quota"] != "q1" {
			t.Fatalf("expected x-ratelimit-quota=q1, got %q", resp.Headers["x-ratelimit-quota"])
		}
		if resp.Headers["content-type"] != "application/json" {
			t.Fatalf("expected application/json, got %q", resp.Headers["content-type"])
		}
	})

	t.Run("standard limiter error fail-closed for memory", func(t *testing.T) {
		lim := &fakeLimiter{allowNErr: errors.New("boom")}
		p := basePolicy([]QuotaRuntime{{Name: "q1", KeyExtraction: []KeyComponent{{Type: "constant", Key: "k1"}}, Limiter: lim, Limits: []LimitConfig{{Limit: 10, Duration: time.Minute}}}})
		action := p.OnRequestHeaders(context.Background(), newRequestHeaderCtx(nil, nil), nil)
		_ = assertImmediateResponse(t, action, 429)
	})

	t.Run("standard limiter error fail-open for redis", func(t *testing.T) {
		lim := &fakeLimiter{allowNErr: errors.New("redis down")}
		p := basePolicy([]QuotaRuntime{{Name: "q1", KeyExtraction: []KeyComponent{{Type: "constant", Key: "k1"}}, Limiter: lim, Limits: []LimitConfig{{Limit: 10, Duration: time.Minute}}}})
		p.backend = "redis"
		p.redisFailOpen = true
		hctx := newRequestHeaderCtx(nil, nil)

		action := p.OnRequestHeaders(context.Background(), hctx, nil)
		if _, ok := action.(policy.UpstreamRequestHeaderModifications); !ok {
			t.Fatalf("expected UpstreamRequestHeaderModifications, got %T", action)
		}
	})

	t.Run("multi-quota short-circuits at first denied", func(t *testing.T) {
		lim1 := &fakeLimiter{allowNFn: func(ctx context.Context, key string, n int64) (*limiter.Result, error) {
			return newResult(true, 10, 5, 0, time.Minute), nil
		}}
		lim2 := &fakeLimiter{allowNFn: func(ctx context.Context, key string, n int64) (*limiter.Result, error) {
			return newResult(false, 10, 0, 10*time.Second, time.Minute), nil
		}}
		lim3 := &fakeLimiter{}
		p := basePolicy([]QuotaRuntime{
			{Name: "q1", KeyExtraction: []KeyComponent{{Type: "constant", Key: "k1"}}, Limiter: lim1, Limits: []LimitConfig{{Limit: 10, Duration: time.Minute}}},
			{Name: "q2", KeyExtraction: []KeyComponent{{Type: "constant", Key: "k2"}}, Limiter: lim2, Limits: []LimitConfig{{Limit: 10, Duration: time.Minute}}},
			{Name: "q3", KeyExtraction: []KeyComponent{{Type: "constant", Key: "k3"}}, Limiter: lim3, Limits: []LimitConfig{{Limit: 10, Duration: time.Minute}}},
		})
		action := p.OnRequestHeaders(context.Background(), newRequestHeaderCtx(nil, nil), nil)
		resp := assertImmediateResponse(t, action, 429)
		if resp.Headers["x-ratelimit-quota"] != "q2" {
			t.Fatalf("expected q2 violation, got %q", resp.Headers["x-ratelimit-quota"])
		}
		if lim3.allowNCalls != 0 {
			t.Fatalf("expected q3 not to be evaluated after q2 denial, got calls=%d", lim3.allowNCalls)
		}
	})

	t.Run("request phase cost extraction uses extracted cost", func(t *testing.T) {
		lim := &fakeLimiter{allowNFn: func(ctx context.Context, key string, n int64) (*limiter.Result, error) {
			return newResult(true, 100, 90, 0, time.Minute), nil
		}}
		ce := NewCostExtractor(CostExtractionConfig{
			Enabled: true,
			Default: 2,
			Sources: []CostSource{{Type: CostSourceRequestHeader, Key: "x-cost", Multiplier: 1}},
		})
		p := basePolicy([]QuotaRuntime{{
			Name:                  "q1",
			KeyExtraction:         []KeyComponent{{Type: "constant", Key: "k1"}},
			Limiter:               lim,
			Limits:                []LimitConfig{{Limit: 100, Duration: time.Minute}},
			CostExtractor:         ce,
			CostExtractionEnabled: true,
		}})
		// request_header sources are consumed in OnRequestHeaders — no body buffering needed
		hctx := newRequestHeaderCtx(map[string][]string{"x-cost": {"7"}}, nil)
		_ = p.OnRequestHeaders(context.Background(), hctx, nil)
		if lim.lastCost != 7 {
			t.Fatalf("expected extracted request cost 7, got %d", lim.lastCost)
		}
	})

	t.Run("negative request extraction clamps to zero", func(t *testing.T) {
		lim := &fakeLimiter{}
		ce := NewCostExtractor(CostExtractionConfig{
			Enabled: true,
			Default: 1,
			Sources: []CostSource{{Type: CostSourceRequestHeader, Key: "x-cost", Multiplier: 1}},
		})
		p := basePolicy([]QuotaRuntime{{
			Name:                  "q1",
			KeyExtraction:         []KeyComponent{{Type: "constant", Key: "k1"}},
			Limiter:               lim,
			Limits:                []LimitConfig{{Limit: 100, Duration: time.Minute}},
			CostExtractor:         ce,
			CostExtractionEnabled: true,
		}})
		// request_header sources are consumed in OnRequestHeaders — no body buffering needed
		hctx := newRequestHeaderCtx(map[string][]string{"x-cost": {"-5"}}, nil)
		_ = p.OnRequestHeaders(context.Background(), hctx, nil)
		if lim.lastCost != 0 {
			t.Fatalf("expected clamped request cost 0, got %d", lim.lastCost)
		}
	})

	t.Run("request extraction fallback uses default", func(t *testing.T) {
		lim := &fakeLimiter{}
		ce := NewCostExtractor(CostExtractionConfig{
			Enabled: true,
			Default: 5,
			Sources: []CostSource{{Type: CostSourceRequestHeader, Key: "x-cost", Multiplier: 1}},
		})
		p := basePolicy([]QuotaRuntime{{
			Name:                  "q1",
			KeyExtraction:         []KeyComponent{{Type: "constant", Key: "k1"}},
			Limiter:               lim,
			Limits:                []LimitConfig{{Limit: 100, Duration: time.Minute}},
			CostExtractor:         ce,
			CostExtractionEnabled: true,
		}})
		// request_header sources are consumed in OnRequestHeaders — no body buffering needed
		_ = p.OnRequestHeaders(context.Background(), newRequestHeaderCtx(nil, nil), nil)
		if lim.lastCost != 5 {
			t.Fatalf("expected default request cost 5, got %d", lim.lastCost)
		}
	})

	t.Run("response phase pre-check available allows request", func(t *testing.T) {
		lim := &fakeLimiter{getAvailableFn: func(ctx context.Context, key string) (int64, error) { return 3, nil }}
		ce := NewCostExtractor(CostExtractionConfig{
			Enabled: true,
			Default: 1,
			Sources: []CostSource{{Type: CostSourceResponseHeader, Key: "x-usage", Multiplier: 1}},
		})
		p := basePolicy([]QuotaRuntime{{
			Name:                  "rq",
			KeyExtraction:         []KeyComponent{{Type: "constant", Key: "resp-key"}},
			Limiter:               lim,
			Limits:                []LimitConfig{{Limit: 5, Duration: time.Minute}},
			CostExtractor:         ce,
			CostExtractionEnabled: true,
		}})
		hctx := newRequestHeaderCtx(nil, nil)

		action := p.OnRequestHeaders(context.Background(), hctx, nil)
		if _, ok := action.(policy.UpstreamRequestHeaderModifications); !ok {
			t.Fatalf("expected upstream action, got %T", action)
		}
		if lim.getAvailableCalls != 1 {
			t.Fatalf("expected GetAvailable called once, got %d", lim.getAvailableCalls)
		}
		if keys, ok := hctx.Metadata[rateLimitKeysKey].(map[string]string); !ok || keys["rq"] == "" {
			t.Fatalf("expected quota key stored in metadata, got %#v", hctx.Metadata[rateLimitKeysKey])
		}
	})

	t.Run("response phase pre-check exhausted blocks request", func(t *testing.T) {
		lim := &fakeLimiter{getAvailableFn: func(ctx context.Context, key string) (int64, error) { return 0, nil }}
		ce := NewCostExtractor(CostExtractionConfig{Enabled: true, Default: 1, Sources: []CostSource{{Type: CostSourceResponseHeader, Key: "x-usage", Multiplier: 1}}})
		p := basePolicy([]QuotaRuntime{{
			Name:                  "rq",
			KeyExtraction:         []KeyComponent{{Type: "constant", Key: "resp-key"}},
			Limiter:               lim,
			Limits:                []LimitConfig{{Limit: 5, Duration: time.Minute}},
			CostExtractor:         ce,
			CostExtractionEnabled: true,
		}})
		resp := assertImmediateResponse(t, p.OnRequestHeaders(context.Background(), newRequestHeaderCtx(nil, nil), nil), 429)
		if resp.Headers["x-ratelimit-remaining"] != "0" {
			t.Fatalf("expected x-ratelimit-remaining=0, got %q", resp.Headers["x-ratelimit-remaining"])
		}
	})

	t.Run("response pre-check error fail-open for redis", func(t *testing.T) {
		lim := &fakeLimiter{getAvailableFn: func(ctx context.Context, key string) (int64, error) { return 0, errors.New("redis down") }}
		ce := NewCostExtractor(CostExtractionConfig{Enabled: true, Default: 1, Sources: []CostSource{{Type: CostSourceResponseHeader, Key: "x-usage", Multiplier: 1}}})
		p := basePolicy([]QuotaRuntime{{
			Name:                  "rq",
			KeyExtraction:         []KeyComponent{{Type: "constant", Key: "resp-key"}},
			Limiter:               lim,
			Limits:                []LimitConfig{{Limit: 5, Duration: time.Minute}},
			CostExtractor:         ce,
			CostExtractionEnabled: true,
		}})
		p.backend = "redis"
		p.redisFailOpen = true
		if _, ok := p.OnRequestHeaders(context.Background(), newRequestHeaderCtx(nil, nil), nil).(policy.UpstreamRequestHeaderModifications); !ok {
			t.Fatalf("expected fail-open upstream action")
		}
	})

	t.Run("response pre-check error fail-closed", func(t *testing.T) {
		lim := &fakeLimiter{getAvailableFn: func(ctx context.Context, key string) (int64, error) { return 0, errors.New("redis down") }}
		ce := NewCostExtractor(CostExtractionConfig{Enabled: true, Default: 1, Sources: []CostSource{{Type: CostSourceResponseHeader, Key: "x-usage", Multiplier: 1}}})
		p := basePolicy([]QuotaRuntime{{
			Name:                  "rq",
			KeyExtraction:         []KeyComponent{{Type: "constant", Key: "resp-key"}},
			Limiter:               lim,
			Limits:                []LimitConfig{{Limit: 5, Duration: time.Minute}},
			CostExtractor:         ce,
			CostExtractionEnabled: true,
		}})
		_ = assertImmediateResponse(t, p.OnRequestHeaders(context.Background(), newRequestHeaderCtx(nil, nil), nil), 429)
	})

	t.Run("request body carries forward request header quota result without re-consuming", func(t *testing.T) {
		limHdr := &fakeLimiter{allowNFn: func(ctx context.Context, key string, n int64) (*limiter.Result, error) {
			return newResult(true, 100, 93, 0, time.Minute), nil
		}}
		limBody := &fakeLimiter{allowNFn: func(ctx context.Context, key string, n int64) (*limiter.Result, error) {
			return newResult(true, 50, 47, 0, time.Minute), nil
		}}
		ceHdr := NewCostExtractor(CostExtractionConfig{
			Enabled: true, Default: 1,
			Sources: []CostSource{{Type: CostSourceRequestHeader, Key: "x-cost", Multiplier: 1}},
		})
		ceBody := NewCostExtractor(CostExtractionConfig{
			Enabled: true, Default: 1,
			Sources: []CostSource{{Type: CostSourceRequestMetadata, Key: "tokens", Multiplier: 1}},
		})
		p := basePolicy([]QuotaRuntime{
			{Name: "hdr", KeyExtraction: []KeyComponent{{Type: "constant", Key: "k1"}}, Limiter: limHdr, Limits: []LimitConfig{{Limit: 100, Duration: time.Minute}}, CostExtractor: ceHdr, CostExtractionEnabled: true},
			{Name: "body", KeyExtraction: []KeyComponent{{Type: "constant", Key: "k2"}}, Limiter: limBody, Limits: []LimitConfig{{Limit: 50, Duration: time.Minute}}, CostExtractor: ceBody, CostExtractionEnabled: true},
		})

		// OnRequestHeaders: consumes hdr quota (request_header only), stores placeholder for body quota
		sharedMeta := map[string]interface{}{"tokens": float64(3)}
		hctx := newRequestHeaderCtx(map[string][]string{"x-cost": {"7"}}, sharedMeta)
		_ = p.OnRequestHeaders(context.Background(), hctx, nil)
		if limHdr.allowNCalls != 1 || limHdr.lastCost != 7 {
			t.Fatalf("expected header quota consumed once with cost 7, calls=%d cost=%d", limHdr.allowNCalls, limHdr.lastCost)
		}

		// Copy stored metadata into a RequestContext for OnRequestBody
		sharedMeta[rateLimitResultKey] = hctx.Metadata[rateLimitResultKey]
		sharedMeta[rateLimitKeysKey] = hctx.Metadata[rateLimitKeysKey]
		sharedMeta[rateLimitHeaderHandledKey] = hctx.Metadata[rateLimitHeaderHandledKey]
		reqCtx := newRequestCtx(map[string][]string{"x-cost": {"7"}}, sharedMeta)
		_ = p.OnRequestBody(context.Background(), reqCtx, nil)

		// hdr quota must NOT be re-consumed in body phase
		if limHdr.allowNCalls != 1 {
			t.Fatalf("expected header quota consumed only once, got %d calls", limHdr.allowNCalls)
		}
		// body quota must be consumed in body phase with cost from metadata
		if limBody.allowNCalls != 1 || limBody.lastCost != 3 {
			t.Fatalf("expected body quota consumed once with cost 3, calls=%d cost=%d", limBody.allowNCalls, limBody.lastCost)
		}
		// Both quota results must be present in final output
		results, ok := reqCtx.Metadata[rateLimitResultKey].([]quotaResult)
		if !ok || len(results) != 2 {
			t.Fatalf("expected 2 quota results after body phase, got %#v", reqCtx.Metadata[rateLimitResultKey])
		}
	})

	t.Run("mixed quotas standard consumed response key stored", func(t *testing.T) {
		limStandard := &fakeLimiter{allowNFn: func(ctx context.Context, key string, n int64) (*limiter.Result, error) {
			return newResult(true, 10, 9, 0, time.Minute), nil
		}}
		limResponse := &fakeLimiter{getAvailableFn: func(ctx context.Context, key string) (int64, error) { return 3, nil }}
		ce := NewCostExtractor(CostExtractionConfig{Enabled: true, Default: 1, Sources: []CostSource{{Type: CostSourceResponseHeader, Key: "x-usage", Multiplier: 1}}})

		p := basePolicy([]QuotaRuntime{
			{Name: "standard", KeyExtraction: []KeyComponent{{Type: "constant", Key: "k1"}}, Limiter: limStandard, Limits: []LimitConfig{{Limit: 10, Duration: time.Minute}}},
			{Name: "post", KeyExtraction: []KeyComponent{{Type: "constant", Key: "k2"}}, Limiter: limResponse, Limits: []LimitConfig{{Limit: 10, Duration: time.Minute}}, CostExtractor: ce, CostExtractionEnabled: true},
		})
		hctx := newRequestHeaderCtx(nil, nil)
		_ = p.OnRequestHeaders(context.Background(), hctx, nil)
		results, ok := hctx.Metadata[rateLimitResultKey].([]quotaResult)
		if !ok || len(results) != 2 {
			t.Fatalf("expected 2 stored quota results (standard + post placeholder), got %#v", hctx.Metadata[rateLimitResultKey])
		}
		if results[0].QuotaName != "standard" || results[0].Result == nil {
			t.Fatalf("expected standard quota result with non-nil Result, got %+v", results[0])
		}
		if results[1].QuotaName != "post" || results[1].Result != nil {
			t.Fatalf("expected post quota placeholder with nil Result, got %+v", results[1])
		}
		keys, ok := hctx.Metadata[rateLimitKeysKey].(map[string]string)
		if !ok || keys["post"] == "" {
			t.Fatalf("expected post quota key stored in metadata, got %#v", hctx.Metadata[rateLimitKeysKey])
		}
	})
}

func TestOnResponseBehavior(t *testing.T) {
	mkPolicy := func(quotas []QuotaRuntime) *RateLimitPolicy {
		return &RateLimitPolicy{
			quotas:       quotas,
			routeName:    "route-main",
			backend:      "memory",
			includeXRL:   true,
			includeIETF:  true,
			includeRetry: true,
		}
	}

	t.Run("no stored metadata returns nil", func(t *testing.T) {
		p := mkPolicy(nil)
		if action := p.OnResponseHeaders(context.Background(), newResponseHeaderCtx(nil, nil, nil, 200), nil); action != nil {
			t.Fatalf("expected nil action, got %T", action)
		}
	})

	t.Run("type-mismatched metadata safely ignored", func(t *testing.T) {
		p := mkPolicy(nil)
		hctx := newResponseHeaderCtx(nil, nil, map[string]interface{}{
			rateLimitResultKey: "bad",
			rateLimitKeysKey:   123,
		}, 200)
		if action := p.OnResponseHeaders(context.Background(), hctx, nil); action != nil {
			t.Fatalf("expected nil action, got %T", action)
		}
	})

	t.Run("standard quota uses stored request result", func(t *testing.T) {
		lim := &fakeLimiter{}
		p := mkPolicy([]QuotaRuntime{{Name: "q1", Limiter: lim, Limits: []LimitConfig{{Limit: 10, Duration: time.Minute}}}})
		hctx := newResponseHeaderCtx(nil, nil, map[string]interface{}{
			rateLimitResultKey: []quotaResult{{QuotaName: "q1", Key: "k1", Duration: time.Minute, Result: newResult(true, 10, 7, 0, time.Minute)}},
			rateLimitKeysKey:   map[string]string{"q1": "k1"},
		}, 200)

		action := p.OnResponseHeaders(context.Background(), hctx, nil)
		mods := assertResponseHeaderMods(t, action, map[string]string{"x-ratelimit-limit": "10", "x-ratelimit-remaining": "7"})
		if mods.HeadersToSet["ratelimit-policy"] == "" || mods.HeadersToSet["ratelimit"] == "" {
			t.Fatalf("expected IETF headers to be present, got %+v", mods.HeadersToSet)
		}
	})

	t.Run("response phase missing key skips quota without panic", func(t *testing.T) {
		lim := &fakeLimiter{}
		ce := NewCostExtractor(CostExtractionConfig{Enabled: true, Default: 1, Sources: []CostSource{{Type: CostSourceResponseHeader, Key: "x-cost", Multiplier: 1}}})
		p := mkPolicy([]QuotaRuntime{{Name: "post", Limiter: lim, Limits: []LimitConfig{{Limit: 10, Duration: time.Minute}}, CostExtractor: ce, CostExtractionEnabled: true}})
		hctx := newResponseHeaderCtx(nil, map[string][]string{"x-cost": {"2"}}, map[string]interface{}{
			rateLimitResultKey: []quotaResult{},
			rateLimitKeysKey:   map[string]string{},
		}, 200)
		if action := p.OnResponseHeaders(context.Background(), hctx, nil); action != nil {
			t.Fatalf("expected nil action when key missing, got %T", action)
		}
	})

	t.Run("negative response cost clamps to zero and uses stored result", func(t *testing.T) {
		lim := &fakeLimiter{}
		ce := NewCostExtractor(CostExtractionConfig{Enabled: true, Default: 1, Sources: []CostSource{{Type: CostSourceResponseHeader, Key: "x-cost", Multiplier: 1}}})
		p := mkPolicy([]QuotaRuntime{{Name: "post", Limiter: lim, Limits: []LimitConfig{{Limit: 10, Duration: time.Minute}}, CostExtractor: ce, CostExtractionEnabled: true}})
		hctx := newResponseHeaderCtx(nil, map[string][]string{"x-cost": {"-9"}}, map[string]interface{}{
			rateLimitResultKey: []quotaResult{{QuotaName: "post", Key: "k1", Duration: time.Minute, Result: newResult(true, 10, 8, 0, time.Minute)}},
			rateLimitKeysKey:   map[string]string{"post": "k1"},
		}, 200)

		action := p.OnResponseHeaders(context.Background(), hctx, nil)
		mods := assertResponseHeaderMods(t, action, map[string]string{"x-ratelimit-remaining": "8"})
		if lim.consumeNCalls != 0 {
			t.Fatalf("expected no ConsumeN call for clamped zero cost")
		}
		if mods.HeadersToSet["ratelimit"] == "" {
			t.Fatalf("expected ratelimit header, got %+v", mods.HeadersToSet)
		}
	})

	t.Run("zero response cost without stored result uses GetAvailable", func(t *testing.T) {
		lim := &fakeLimiter{getAvailableFn: func(ctx context.Context, key string) (int64, error) { return 3, nil }}
		ce := NewCostExtractor(CostExtractionConfig{Enabled: true, Default: 0, Sources: []CostSource{{Type: CostSourceResponseHeader, Key: "x-cost", Multiplier: 1}}})
		p := mkPolicy([]QuotaRuntime{{Name: "post", Limiter: lim, Limits: []LimitConfig{{Limit: 10, Duration: time.Minute}}, CostExtractor: ce, CostExtractionEnabled: true}})
		hctx := newResponseHeaderCtx(nil, map[string][]string{"x-cost": {"0"}}, map[string]interface{}{
			rateLimitResultKey: []quotaResult{},
			rateLimitKeysKey:   map[string]string{"post": "k1"},
		}, 200)

		action := p.OnResponseHeaders(context.Background(), hctx, nil)
		mods := assertResponseHeaderMods(t, action, map[string]string{"x-ratelimit-limit": "10", "x-ratelimit-remaining": "3"})
		if mods.HeadersToSet["ratelimit-policy"] == "" {
			t.Fatalf("expected ratelimit-policy header")
		}
	})

	t.Run("zero response cost synthetic path with GetAvailable error skips quota", func(t *testing.T) {
		lim := &fakeLimiter{getAvailableFn: func(ctx context.Context, key string) (int64, error) { return 0, errors.New("boom") }}
		ce := NewCostExtractor(CostExtractionConfig{Enabled: true, Default: 0, Sources: []CostSource{{Type: CostSourceResponseHeader, Key: "x-cost", Multiplier: 1}}})
		p := mkPolicy([]QuotaRuntime{{Name: "post", Limiter: lim, Limits: []LimitConfig{{Limit: 10, Duration: time.Minute}}, CostExtractor: ce, CostExtractionEnabled: true}})
		hctx := newResponseHeaderCtx(nil, map[string][]string{"x-cost": {"0"}}, map[string]interface{}{
			rateLimitResultKey: []quotaResult{},
			rateLimitKeysKey:   map[string]string{"post": "k1"},
		}, 200)
		if action := p.OnResponseHeaders(context.Background(), hctx, nil); action != nil {
			t.Fatalf("expected nil action, got %T", action)
		}
	})

	t.Run("positive response cost consumes via ConsumeN", func(t *testing.T) {
		lim := &fakeLimiter{consumeNFn: func(ctx context.Context, key string, n int64) (*limiter.Result, error) {
			return newResult(true, 10, 6, 0, time.Minute), nil
		}}
		ce := NewCostExtractor(CostExtractionConfig{Enabled: true, Default: 1, Sources: []CostSource{{Type: CostSourceResponseHeader, Key: "x-cost", Multiplier: 1}}})
		p := mkPolicy([]QuotaRuntime{{Name: "post", Limiter: lim, Limits: []LimitConfig{{Limit: 10, Duration: time.Minute}}, CostExtractor: ce, CostExtractionEnabled: true}})
		hctx := newResponseHeaderCtx(nil, map[string][]string{"x-cost": {"4"}}, map[string]interface{}{
			rateLimitResultKey: []quotaResult{},
			rateLimitKeysKey:   map[string]string{"post": "k1"},
		}, 200)

		action := p.OnResponseHeaders(context.Background(), hctx, nil)
		_ = assertResponseHeaderMods(t, action, map[string]string{"x-ratelimit-remaining": "6"})
		if lim.consumeNCalls != 1 || lim.lastCost != 4 {
			t.Fatalf("expected ConsumeN once with cost 4, calls=%d cost=%d", lim.consumeNCalls, lim.lastCost)
		}
	})

	t.Run("consume error fail-open on redis skips quota but still returns other headers", func(t *testing.T) {
		limResponse := &fakeLimiter{consumeNFn: func(ctx context.Context, key string, n int64) (*limiter.Result, error) {
			return nil, errors.New("redis error")
		}}
		limStandard := &fakeLimiter{}
		ce := NewCostExtractor(CostExtractionConfig{Enabled: true, Default: 1, Sources: []CostSource{{Type: CostSourceResponseHeader, Key: "x-cost", Multiplier: 1}}})

		p := mkPolicy([]QuotaRuntime{
			{Name: "standard", Limiter: limStandard, Limits: []LimitConfig{{Limit: 10, Duration: time.Minute}}},
			{Name: "post", Limiter: limResponse, Limits: []LimitConfig{{Limit: 20, Duration: time.Minute}}, CostExtractor: ce, CostExtractionEnabled: true},
		})
		p.backend = "redis"
		p.redisFailOpen = true
		hctx := newResponseHeaderCtx(nil, map[string][]string{"x-cost": {"7"}}, map[string]interface{}{
			rateLimitResultKey: []quotaResult{{QuotaName: "standard", Key: "s1", Duration: time.Minute, Result: newResult(true, 10, 9, 0, time.Minute)}},
			rateLimitKeysKey:   map[string]string{"post": "p1", "standard": "s1"},
		}, 200)
		action := p.OnResponseHeaders(context.Background(), hctx, nil)
		_ = assertResponseHeaderMods(t, action, map[string]string{"x-ratelimit-limit": "10", "x-ratelimit-remaining": "9"})
	})

	t.Run("consume error fail-closed currently skipped and returns nil when only quota", func(t *testing.T) {
		lim := &fakeLimiter{consumeNFn: func(ctx context.Context, key string, n int64) (*limiter.Result, error) {
			return nil, errors.New("hard error")
		}}
		ce := NewCostExtractor(CostExtractionConfig{Enabled: true, Default: 1, Sources: []CostSource{{Type: CostSourceResponseHeader, Key: "x-cost", Multiplier: 1}}})
		p := mkPolicy([]QuotaRuntime{{Name: "post", Limiter: lim, Limits: []LimitConfig{{Limit: 10, Duration: time.Minute}}, CostExtractor: ce, CostExtractionEnabled: true}})
		hctx := newResponseHeaderCtx(nil, map[string][]string{"x-cost": {"3"}}, map[string]interface{}{
			rateLimitResultKey: []quotaResult{},
			rateLimitKeysKey:   map[string]string{"post": "p1"},
		}, 200)
		if action := p.OnResponseHeaders(context.Background(), hctx, nil); action != nil {
			t.Fatalf("expected nil action, got %T", action)
		}
	})

	t.Run("mixed standard and response quotas produce consolidated headers", func(t *testing.T) {
		limResponse := &fakeLimiter{consumeNFn: func(ctx context.Context, key string, n int64) (*limiter.Result, error) {
			return newResult(true, 20, 11, 0, 2*time.Minute), nil
		}}
		ce := NewCostExtractor(CostExtractionConfig{Enabled: true, Default: 1, Sources: []CostSource{{Type: CostSourceResponseHeader, Key: "x-cost", Multiplier: 1}}})
		p := mkPolicy([]QuotaRuntime{
			{Name: "q1", Limits: []LimitConfig{{Limit: 10, Duration: time.Minute}}},
			{Name: "q2", Limiter: limResponse, Limits: []LimitConfig{{Limit: 20, Duration: 2 * time.Minute}}, CostExtractor: ce, CostExtractionEnabled: true},
		})
		hctx := newResponseHeaderCtx(nil, map[string][]string{"x-cost": {"4"}}, map[string]interface{}{
			rateLimitResultKey: []quotaResult{{QuotaName: "q1", Key: "k1", Duration: time.Minute, Result: newResult(true, 10, 8, 0, time.Minute)}},
			rateLimitKeysKey:   map[string]string{"q1": "k1", "q2": "k2"},
		}, 200)

		action := p.OnResponseHeaders(context.Background(), hctx, nil)
		mods := assertResponseHeaderMods(t, action, map[string]string{})
		if !strings.Contains(mods.HeadersToSet["ratelimit-policy"], `"q1"`) || !strings.Contains(mods.HeadersToSet["ratelimit-policy"], `"q2"`) {
			t.Fatalf("expected consolidated ratelimit-policy, got %q", mods.HeadersToSet["ratelimit-policy"])
		}
		if !strings.Contains(mods.HeadersToSet["ratelimit"], `"q1"`) || !strings.Contains(mods.HeadersToSet["ratelimit"], `"q2"`) {
			t.Fatalf("expected consolidated ratelimit, got %q", mods.HeadersToSet["ratelimit"])
		}
	})

	t.Run("OnResponseHeaders returns nil when response metadata source present", func(t *testing.T) {
		lim := &fakeLimiter{}
		ce := NewCostExtractor(CostExtractionConfig{Enabled: true, Default: 1, Sources: []CostSource{{Type: CostSourceResponseMetadata, Key: "x-llm-cost", Multiplier: 1}}})
		p := mkPolicy([]QuotaRuntime{{Name: "meta", Limiter: lim, Limits: []LimitConfig{{Limit: 10, Duration: time.Minute}}, CostExtractor: ce, CostExtractionEnabled: true}})
		hctx := newResponseHeaderCtx(nil, nil, map[string]interface{}{
			rateLimitResultKey: []quotaResult{{QuotaName: "meta", Key: "k1", Duration: time.Minute, Result: nil}},
			rateLimitKeysKey:   map[string]string{"meta": "k1"},
		}, 200)
		// response_metadata is populated by upstream policies in the body phase — must defer
		if action := p.OnResponseHeaders(context.Background(), hctx, nil); action != nil {
			t.Fatalf("expected nil action when response metadata source present, got %T", action)
		}
		// Results must still be written back so OnResponseBody can use them
		if _, ok := hctx.Metadata[rateLimitResultKey]; !ok {
			t.Fatalf("expected %s to remain in metadata after OnResponseHeaders returned nil", rateLimitResultKey)
		}
	})

	t.Run("response metadata source consumed in OnResponseBody", func(t *testing.T) {
		lim := &fakeLimiter{consumeNFn: func(ctx context.Context, key string, n int64) (*limiter.Result, error) {
			return newResult(true, 100, 88, 0, time.Minute), nil
		}}
		ce := NewCostExtractor(CostExtractionConfig{Enabled: true, Default: 1, Sources: []CostSource{{Type: CostSourceResponseMetadata, Key: "x-llm-cost", Multiplier: 1}}})
		p := mkPolicy([]QuotaRuntime{{Name: "meta", Limiter: lim, Limits: []LimitConfig{{Limit: 100, Duration: time.Minute}}, CostExtractor: ce, CostExtractionEnabled: true}})

		respCtx := newResponseCtx(nil, nil, map[string]interface{}{
			rateLimitResultKey: []quotaResult{{QuotaName: "meta", Key: "k1", Duration: time.Minute, Result: nil}},
			rateLimitKeysKey:   map[string]string{"meta": "k1"},
			"x-llm-cost":       float64(12),
		}, 200)

		action := p.OnResponseBody(context.Background(), respCtx, nil)
		mods, ok := action.(policy.DownstreamResponseModifications)
		if !ok {
			t.Fatalf("expected DownstreamResponseModifications, got %T", action)
		}
		if mods.HeadersToSet["x-ratelimit-remaining"] != "88" {
			t.Fatalf("expected remaining=88, got %q", mods.HeadersToSet["x-ratelimit-remaining"])
		}
		if lim.consumeNCalls != 1 || lim.lastCost != 12 {
			t.Fatalf("expected ConsumeN once with cost 12, calls=%d cost=%d", lim.consumeNCalls, lim.lastCost)
		}
	})

	t.Run("response header quota result carried forward in OnResponseBody without re-consumption", func(t *testing.T) {
		limHdr := &fakeLimiter{consumeNFn: func(ctx context.Context, key string, n int64) (*limiter.Result, error) {
			return newResult(true, 20, 15, 0, time.Minute), nil
		}}
		limBody := &fakeLimiter{consumeNFn: func(ctx context.Context, key string, n int64) (*limiter.Result, error) {
			return newResult(true, 10, 7, 0, time.Minute), nil
		}}
		ceHdr := NewCostExtractor(CostExtractionConfig{Enabled: true, Default: 1, Sources: []CostSource{{Type: CostSourceResponseHeader, Key: "x-hdr-cost", Multiplier: 1}}})
		ceBody := NewCostExtractor(CostExtractionConfig{Enabled: true, Default: 1, Sources: []CostSource{{Type: CostSourceResponseBody, JSONPath: "$.tokens", Multiplier: 1}}})
		p := mkPolicy([]QuotaRuntime{
			{Name: "hdr", Limiter: limHdr, Limits: []LimitConfig{{Limit: 20, Duration: time.Minute}}, CostExtractor: ceHdr, CostExtractionEnabled: true},
			{Name: "body", Limiter: limBody, Limits: []LimitConfig{{Limit: 10, Duration: time.Minute}}, CostExtractor: ceBody, CostExtractionEnabled: true},
		})

		// OnResponseHeaders: consumes hdr quota, defers body quota, returns nil (because body phase will run)
		sharedMeta := map[string]interface{}{
			rateLimitResultKey: []quotaResult{
				{QuotaName: "hdr", Key: "k1", Duration: time.Minute, Result: nil},
				{QuotaName: "body", Key: "k2", Duration: time.Minute, Result: nil},
			},
			rateLimitKeysKey: map[string]string{"hdr": "k1", "body": "k2"},
		}
		hctx := newResponseHeaderCtx(nil, map[string][]string{"x-hdr-cost": {"5"}}, sharedMeta, 200)
		if action := p.OnResponseHeaders(context.Background(), hctx, nil); action != nil {
			t.Fatalf("expected nil from OnResponseHeaders (body phase will run), got %T", action)
		}
		if limHdr.consumeNCalls != 1 || limHdr.lastCost != 5 {
			t.Fatalf("expected hdr quota consumed once with cost 5, calls=%d cost=%d", limHdr.consumeNCalls, limHdr.lastCost)
		}

		// OnResponseBody: must carry forward hdr result, consume body quota only
		respCtx := newResponseCtx(nil, map[string][]string{"x-hdr-cost": {"5"}}, sharedMeta, 200)
		respCtx.ResponseBody = &policy.Body{Present: true, Content: []byte(`{"tokens": 3}`)}
		action := p.OnResponseBody(context.Background(), respCtx, nil)
		mods, ok := action.(policy.DownstreamResponseModifications)
		if !ok {
			t.Fatalf("expected DownstreamResponseModifications from OnResponseBody, got %T", action)
		}

		// hdr quota must NOT be re-consumed
		if limHdr.consumeNCalls != 1 {
			t.Fatalf("expected hdr quota consumed only once (not re-consumed in body phase), got %d calls", limHdr.consumeNCalls)
		}
		// body quota must be consumed with correct cost
		if limBody.consumeNCalls != 1 || limBody.lastCost != 3 {
			t.Fatalf("expected body quota consumed once with cost 3, calls=%d cost=%d", limBody.consumeNCalls, limBody.lastCost)
		}
		// Headers must reflect both quotas
		if !strings.Contains(mods.HeadersToSet["ratelimit-policy"], `"hdr"`) || !strings.Contains(mods.HeadersToSet["ratelimit-policy"], `"body"`) {
			t.Fatalf("expected consolidated ratelimit-policy with both quotas, got %q", mods.HeadersToSet["ratelimit-policy"])
		}
	})

	t.Run("all results nil returns nil", func(t *testing.T) {
		p := mkPolicy([]QuotaRuntime{{Name: "q1"}})
		hctx := newResponseHeaderCtx(nil, nil, map[string]interface{}{
			rateLimitResultKey: []quotaResult{{QuotaName: "q1", Result: nil}},
		}, 200)
		if action := p.OnResponseHeaders(context.Background(), hctx, nil); action != nil {
			t.Fatalf("expected nil action, got %T", action)
		}
	})
}

func TestHeaderBuildersAndResponseConstruction(t *testing.T) {
	p := &RateLimitPolicy{includeXRL: true, includeIETF: true, includeRetry: true, responseFormat: "json", statusCode: 429, responseBody: "{}"}

	t.Run("buildMultiQuotaHeaders nil result", func(t *testing.T) {
		headers := p.buildMultiQuotaHeaders(nil, true, "")
		if len(headers) != 0 {
			t.Fatalf("expected empty headers for nil result, got %+v", headers)
		}
	})

	t.Run("buildMultiQuotaHeaders includes toggles", func(t *testing.T) {
		res := &limiter.Result{Limit: 10, Remaining: 5, Reset: time.Now().Add(30 * time.Second), Duration: time.Minute, RetryAfter: 250 * time.Millisecond, Policy: struct{}{}}
		headers := p.buildMultiQuotaHeaders([]quotaResult{{QuotaName: "q1", Result: res, Duration: time.Minute}}, true, "q1")
		if headers["x-ratelimit-limit"] != "10" || headers["x-ratelimit-remaining"] != "5" {
			t.Fatalf("expected X-RateLimit headers, got %+v", headers)
		}
		if !strings.Contains(headers["ratelimit-policy"], "q=10") || !strings.Contains(headers["ratelimit"], "r=5") {
			t.Fatalf("expected IETF rate limit headers, got %+v", headers)
		}
		if headers["retry-after"] != "1" {
			t.Fatalf("expected retry-after min clamp to 1, got %q", headers["retry-after"])
		}
	})

	t.Run("buildMultiQuotaHeaders with disabled toggles", func(t *testing.T) {
		p2 := &RateLimitPolicy{includeXRL: false, includeIETF: false, includeRetry: false}
		headers := p2.buildMultiQuotaHeaders([]quotaResult{{QuotaName: "q1", Result: newResult(true, 10, 5, 10*time.Second, time.Minute), Duration: time.Minute}}, true, "q1")
		if len(headers) != 0 {
			t.Fatalf("expected no headers with toggles disabled, got %+v", headers)
		}
	})

	t.Run("buildMultiQuotaHeaders most restrictive and structured fields", func(t *testing.T) {
		q1 := quotaResult{QuotaName: "q1", Result: &limiter.Result{Limit: 100, Remaining: 50, Reset: time.Now().Add(10 * time.Second), Duration: time.Minute}, Duration: time.Minute}
		q2 := quotaResult{QuotaName: "q2", Result: &limiter.Result{Limit: 10, Remaining: 1, Reset: time.Now().Add(20 * time.Second), Duration: 2 * time.Minute, RetryAfter: 2 * time.Second}, Duration: 0}
		headers := p.buildMultiQuotaHeaders([]quotaResult{q1, q2}, true, "q2")

		if headers["x-ratelimit-limit"] != "10" || headers["x-ratelimit-remaining"] != "1" {
			t.Fatalf("expected most restrictive XRL from q2, got %+v", headers)
		}
		if !strings.Contains(headers["ratelimit-policy"], `"q1";q=100;w=60`) {
			t.Fatalf("expected q1 structured policy part, got %q", headers["ratelimit-policy"])
		}
		if !strings.Contains(headers["ratelimit-policy"], `"q2";q=10;w=120`) {
			t.Fatalf("expected q2 window fallback from result duration, got %q", headers["ratelimit-policy"])
		}
		if headers["retry-after"] != "2" {
			t.Fatalf("expected retry-after from violated quota, got %q", headers["retry-after"])
		}
	})

	t.Run("buildMultiQuotaHeaders retry falls back to most restrictive", func(t *testing.T) {
		q1 := quotaResult{QuotaName: "q1", Result: &limiter.Result{Limit: 100, Remaining: 2, Reset: time.Now().Add(10 * time.Second), Duration: time.Minute, RetryAfter: 4 * time.Second}, Duration: time.Minute}
		headers := p.buildMultiQuotaHeaders([]quotaResult{q1}, true, "missing")
		if headers["retry-after"] != "4" {
			t.Fatalf("expected retry-after fallback from most restrictive, got %q", headers["retry-after"])
		}
	})

	t.Run("buildRateLimitResponse appends violated quota and sets content type", func(t *testing.T) {
		violated := &limiter.Result{Allowed: false, Limit: 10, Remaining: 0, RetryAfter: 3 * time.Second, Reset: time.Now().Add(time.Minute), Duration: time.Minute}
		resp := p.buildRateLimitResponse(violated, "blocked", []quotaResult{{QuotaName: "other", Result: newResult(true, 100, 90, 0, time.Minute)}})
		if resp.Headers["x-ratelimit-quota"] != "blocked" {
			t.Fatalf("expected violated quota header, got %q", resp.Headers["x-ratelimit-quota"])
		}
		if resp.Headers["content-type"] != "application/json" {
			t.Fatalf("expected application/json content-type, got %q", resp.Headers["content-type"])
		}

		pPlain := &RateLimitPolicy{includeXRL: true, includeIETF: true, includeRetry: true, responseFormat: "plain", statusCode: 429, responseBody: "limited"}
		respPlain := pPlain.buildRateLimitResponse(violated, "blocked", nil)
		if respPlain.Headers["content-type"] != "text/plain" {
			t.Fatalf("expected text/plain content-type, got %q", respPlain.Headers["content-type"])
		}
	})

	t.Run("buildMultiQuotaHeaders clamps negative ietf reset to zero", func(t *testing.T) {
		res := &limiter.Result{Limit: 10, Remaining: 5, Reset: time.Now().Add(-2 * time.Second), Duration: time.Minute, Policy: struct{}{}}
		headers := p.buildMultiQuotaHeaders([]quotaResult{{QuotaName: "q1", Result: res, Duration: time.Minute}}, false, "")
		if !strings.Contains(headers["ratelimit"], "t=0") {
			t.Fatalf("expected ratelimit to contain t=0, got %q", headers["ratelimit"])
		}
	})
}

func TestParseQuotasAndHelpers(t *testing.T) {
	t.Run("parseQuotas", func(t *testing.T) {
		tests := []struct {
			name    string
			params  map[string]interface{}
			wantErr string
			wantLen int
		}{
			{name: "nil quotas", params: map[string]interface{}{}, wantLen: 0},
			{name: "non array", params: map[string]interface{}{"quotas": "x"}, wantErr: "quotas must be an array"},
			{name: "non object quota", params: map[string]interface{}{"quotas": []interface{}{"x"}}, wantErr: "quotas[0] must be an object"},
			{name: "missing limits", params: map[string]interface{}{"quotas": []interface{}{map[string]interface{}{"name": "q1"}}}, wantErr: "quotas[0].limits is required"},
			{name: "empty limits", params: map[string]interface{}{"quotas": []interface{}{map[string]interface{}{"limits": []interface{}{}}}}, wantErr: "must not be empty"},
			{name: "invalid key extraction", params: map[string]interface{}{"quotas": []interface{}{map[string]interface{}{"limits": []interface{}{map[string]interface{}{"limit": float64(1), "duration": "1s"}}, "keyExtraction": "bad"}}}, wantErr: "invalid quotas[0].keyExtraction"},
			{name: "invalid cost extraction", params: map[string]interface{}{"quotas": []interface{}{map[string]interface{}{"limits": []interface{}{map[string]interface{}{"limit": float64(1), "duration": "1s"}}, "costExtraction": map[string]interface{}{"enabled": true, "sources": []interface{}{map[string]interface{}{"type": "request_cel"}}}}}}, wantErr: "invalid quotas[0].costExtraction"},
			{name: "valid quota", params: map[string]interface{}{"quotas": []interface{}{map[string]interface{}{"name": "q1", "limits": []interface{}{map[string]interface{}{"limit": float64(1), "duration": "1s"}}}}}, wantLen: 1},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				q, err := parseQuotas(tt.params)
				if tt.wantErr != "" {
					if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
						t.Fatalf("expected error containing %q, got %v", tt.wantErr, err)
					}
					return
				}
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if len(q) != tt.wantLen {
					t.Fatalf("expected len=%d, got %d", tt.wantLen, len(q))
				}
			})
		}
	})

	t.Run("parseSingleLimit", func(t *testing.T) {
		if _, err := parseSingleLimit("bad", "1s", nil); err == nil || !strings.Contains(err.Error(), "limit must be a number") {
			t.Fatalf("expected limit type error, got %v", err)
		}
		if _, err := parseSingleLimit(float64(1), 123, nil); err == nil || !strings.Contains(err.Error(), "duration must be a string") {
			t.Fatalf("expected duration type error, got %v", err)
		}
		if _, err := parseSingleLimit(float64(1), "bad", nil); err == nil || !strings.Contains(err.Error(), "invalid duration") {
			t.Fatalf("expected invalid duration error, got %v", err)
		}
		l, err := parseSingleLimit(float64(3), "1s", nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if l.Burst != 3 {
			t.Fatalf("expected burst default to limit=3, got %d", l.Burst)
		}
		if _, err := parseSingleLimit(float64(1), "1s", "bad"); err == nil || !strings.Contains(err.Error(), "burst must be a number") {
			t.Fatalf("expected burst type error, got %v", err)
		}
	})

	t.Run("parseLimits", func(t *testing.T) {
		limits, err := parseLimits(nil)
		if err != nil || len(limits) != 0 {
			t.Fatalf("expected nil input => empty nil error, got limits=%+v err=%v", limits, err)
		}
		if _, err := parseLimits("bad"); err == nil || !strings.Contains(err.Error(), "limits must be an array") {
			t.Fatalf("expected array error, got %v", err)
		}
		limits, err = parseLimits([]interface{}{})
		if err != nil || len(limits) != 0 {
			t.Fatalf("expected empty limits array => empty output, got %+v err=%v", limits, err)
		}
		if _, err := parseLimits([]interface{}{"bad"}); err == nil || !strings.Contains(err.Error(), "limits[0] must be an object") {
			t.Fatalf("expected limits[0] object error, got %v", err)
		}
		if _, err := parseLimits([]interface{}{map[string]interface{}{"duration": "1s"}}); err == nil || !strings.Contains(err.Error(), "limits[0].limit is required") {
			t.Fatalf("expected required limit error, got %v", err)
		}
	})

	t.Run("parseKeyExtraction", func(t *testing.T) {
		components, err := parseKeyExtraction(nil)
		if err != nil || len(components) != 0 {
			t.Fatalf("expected nil input => empty no error, got %+v err=%v", components, err)
		}
		if _, err := parseKeyExtraction("bad"); err == nil || !strings.Contains(err.Error(), "keyExtraction must be an array") {
			t.Fatalf("expected array error, got %v", err)
		}
		if _, err := parseKeyExtraction([]interface{}{"bad"}); err == nil || !strings.Contains(err.Error(), "keyExtraction[0] must be an object") {
			t.Fatalf("expected object error, got %v", err)
		}
		if _, err := parseKeyExtraction([]interface{}{map[string]interface{}{}}); err == nil || !strings.Contains(err.Error(), "keyExtraction[0].type is required") {
			t.Fatalf("expected type required error, got %v", err)
		}
		if _, err := parseKeyExtraction([]interface{}{map[string]interface{}{"type": "header", "key": 123}}); err == nil || !strings.Contains(err.Error(), "keyExtraction[0].key must be a string") {
			t.Fatalf("expected key type error, got %v", err)
		}
		if _, err := parseKeyExtraction([]interface{}{map[string]interface{}{"type": "cel", "expression": 123}}); err == nil || !strings.Contains(err.Error(), "keyExtraction[0].expression must be a string") {
			t.Fatalf("expected expression type error, got %v", err)
		}
		if _, err := parseKeyExtraction([]interface{}{map[string]interface{}{"type": "cel"}}); err == nil || !strings.Contains(err.Error(), "requires 'expression' field") {
			t.Fatalf("expected cel expression required error, got %v", err)
		}
	})

	t.Run("nested param getters", func(t *testing.T) {
		params := map[string]interface{}{
			"a": map[string]interface{}{
				"s": "str",
				"i": float64(3),
				"b": true,
				"d": "2s",
			},
		}
		if got := getStringParam(params, "a.s", "def"); got != "str" {
			t.Fatalf("expected str, got %q", got)
		}
		if got := getStringParam(params, "a.i", "def"); got != "def" {
			t.Fatalf("expected fallback def, got %q", got)
		}
		if got := getIntParam(params, "a.i", 9); got != 3 {
			t.Fatalf("expected 3, got %d", got)
		}
		if got := getIntParam(params, "a.s", 9); got != 9 {
			t.Fatalf("expected fallback 9, got %d", got)
		}
		if got := getBoolParam(params, "a.b", false); !got {
			t.Fatalf("expected true")
		}
		if got := getBoolParam(params, "a.s", false); got {
			t.Fatalf("expected fallback false")
		}
		if got := getDurationParam(params, "a.d", time.Second); got != 2*time.Second {
			t.Fatalf("expected 2s, got %v", got)
		}
		if got := getDurationParam(params, "a.s", time.Second); got != time.Second {
			t.Fatalf("expected fallback 1s, got %v", got)
		}
		if got := getStringParam(params, "missing.key", "def"); got != "def" {
			t.Fatalf("expected missing path fallback, got %q", got)
		}
	})

	t.Run("quota limit and duration helpers", func(t *testing.T) {
		q := &QuotaRuntime{}
		if getLimitFromQuota(q) != 0 || getDurationFromQuota(q) != 0 {
			t.Fatalf("expected zero values for empty limits")
		}
		q.Limits = []LimitConfig{{Limit: 8, Duration: 2 * time.Minute}}
		if getLimitFromQuota(q) != 8 || getDurationFromQuota(q) != 2*time.Minute {
			t.Fatalf("unexpected helper extraction: limit=%d duration=%v", getLimitFromQuota(q), getDurationFromQuota(q))
		}
	})

	t.Run("base cache key deterministic and sensitive to changes", func(t *testing.T) {
		params1 := map[string]interface{}{
			"memory": map[string]interface{}{"cleanupInterval": "1m"},
			"headers": map[string]interface{}{
				"includeXRateLimit": true,
				"includeIETF":       true,
				"includeRetryAfter": true,
			},
			"onRateLimitExceeded": map[string]interface{}{"body": "a", "statusCode": float64(429)},
		}
		params2 := map[string]interface{}{
			"headers": map[string]interface{}{
				"includeRetryAfter": true,
				"includeIETF":       true,
				"includeXRateLimit": true,
			},
			"onRateLimitExceeded": map[string]interface{}{"statusCode": float64(429), "body": "a"},
			"memory":              map[string]interface{}{"cleanupInterval": "1m"},
		}
		k1 := getBaseCacheKey("route1", "api1", "fixed-window", "memory", params1, "")
		k2 := getBaseCacheKey("route1", "api1", "fixed-window", "memory", params2, "")
		if k1 != k2 {
			t.Fatalf("expected deterministic key regardless of map order, got %q vs %q", k1, k2)
		}
		params2["headers"].(map[string]interface{})["includeIETF"] = false
		k3 := getBaseCacheKey("route1", "api1", "fixed-window", "memory", params2, "")
		if k3 == k1 {
			t.Fatalf("expected cache key change when significant params change")
		}
		// Backend is part of the key: same route/algo/params under a different backend
		// must not collide (memory vs redis-local-async share the cache path).
		if getBaseCacheKey("route1", "api1", "fixed-window", "memory", params1, "") ==
			getBaseCacheKey("route1", "api1", "fixed-window", "redis-local-async", params1, "") {
			t.Fatalf("expected distinct cache keys for different backends")
		}
	})

	t.Run("quota cache key api scoped sharing and route scoped isolation", func(t *testing.T) {
		baseRoute1 := "base-route-1"
		baseRoute2 := "base-route-2"

		apiScoped := &QuotaRuntime{
			Name:          "shared",
			Limits:        []LimitConfig{{Limit: 10, Duration: time.Minute}},
			KeyExtraction: []KeyComponent{{Type: "apiname"}},
		}
		k1 := getQuotaCacheKey(baseRoute1, "apiA", apiScoped, 0)
		k2 := getQuotaCacheKey(baseRoute2, "apiA", apiScoped, 0)
		if k1 != k2 {
			t.Fatalf("expected api-scoped quota keys to match across routes, got %q vs %q", k1, k2)
		}

		routeScoped := &QuotaRuntime{Name: "route", Limits: []LimitConfig{{Limit: 10, Duration: time.Minute}}, KeyExtraction: []KeyComponent{{Type: "routename"}}}
		rk1 := getQuotaCacheKey(baseRoute1, "apiA", routeScoped, 0)
		rk2 := getQuotaCacheKey(baseRoute2, "apiA", routeScoped, 0)
		if rk1 == rk2 {
			t.Fatalf("expected route-scoped quota keys to differ across routes")
		}

		changed := &QuotaRuntime{Name: "route", Limits: []LimitConfig{{Limit: 11, Duration: time.Minute}}, KeyExtraction: []KeyComponent{{Type: "routename"}}}
		rk3 := getQuotaCacheKey(baseRoute1, "apiA", changed, 0)
		if rk3 == rk1 {
			t.Fatalf("expected quota key change when quota config changes")
		}
	})

	/* TODO: fix bug — quota cache key must include CEL expression
	t.Run("BUGHUNT: quota cache key must include CEL expression", func(t *testing.T) {
		// Different CEL expressions represent different key extraction behavior.
		// Cache key collisions here will incorrectly reuse stale limiter state across config changes.
		q1 := &QuotaRuntime{
			Name:          "cel-quota",
			Limits:        []LimitConfig{{Limit: 10, Duration: time.Minute}},
			KeyExtraction: []KeyComponent{{Type: "cel", Expression: "request.Path"}},
		}
		q2 := &QuotaRuntime{
			Name:          "cel-quota",
			Limits:        []LimitConfig{{Limit: 10, Duration: time.Minute}},
			KeyExtraction: []KeyComponent{{Type: "cel", Expression: "request.Method"}},
		}

		k1 := getQuotaCacheKey("base-route", "api-a", q1, 0)
		k2 := getQuotaCacheKey("base-route", "api-a", q2, 0)
		if k1 == k2 {
			t.Fatalf("BUG: cache key collision for different CEL expressions: %q", k1)
		}
	})
	*/
}

func TestBuildMultiQuotaHeadersRetryAfterConditions(t *testing.T) {
	p := &RateLimitPolicy{includeXRL: true, includeIETF: true, includeRetry: true}
	res := newResult(false, 10, 0, 2*time.Second, time.Minute)

	headers := p.buildMultiQuotaHeaders([]quotaResult{{QuotaName: "q1", Result: res, Duration: time.Minute}}, false, "")
	if _, ok := headers["retry-after"]; ok {
		t.Fatal("retry-after should not be set when rateLimited=false")
	}

	p.includeRetry = false
	headers = p.buildMultiQuotaHeaders([]quotaResult{{QuotaName: "q1", Result: res, Duration: time.Minute}}, true, "q1")
	if _, ok := headers["retry-after"]; ok {
		t.Fatal("retry-after should not be set when includeRetry=false")
	}

	p.includeRetry = true
	res.RetryAfter = 0
	headers = p.buildMultiQuotaHeaders([]quotaResult{{QuotaName: "q1", Result: res, Duration: time.Minute}}, true, "q1")
	if _, ok := headers["retry-after"]; ok {
		t.Fatal("retry-after should not be set when RetryAfter<=0")
	}
}

func TestMostRestrictiveResultViaBuildMultiQuotaHeaders(t *testing.T) {
	p := &RateLimitPolicy{includeXRL: true}

	// Empty input returns empty headers
	headers := p.buildMultiQuotaHeaders(nil, false, "")
	if len(headers) != 0 {
		t.Fatalf("expected empty headers for nil input, got %+v", headers)
	}

	// Nil-only results return empty headers
	headers = p.buildMultiQuotaHeaders([]quotaResult{{QuotaName: "q1", Result: nil}, {QuotaName: "q2", Result: nil}}, false, "")
	if len(headers) != 0 {
		t.Fatalf("expected empty headers for nil-only results, got %+v", headers)
	}

	// Most restrictive (lowest remaining) is used for x-ratelimit-remaining
	r1 := newResult(true, 10, 5, 0, time.Minute)
	r2 := newResult(true, 10, 1, 0, time.Minute)
	r3 := newResult(true, 10, 4, 0, time.Minute)
	headers = p.buildMultiQuotaHeaders([]quotaResult{
		{QuotaName: "q1", Result: r1, Duration: time.Minute},
		{QuotaName: "q2", Result: r2, Duration: time.Minute},
		{QuotaName: "q3", Result: r3, Duration: time.Minute},
	}, false, "")
	if headers["x-ratelimit-remaining"] != "1" {
		t.Fatalf("expected most restrictive remaining=1, got %q", headers["x-ratelimit-remaining"])
	}
}

func TestParseCostExtractionConfigEdgeCases(t *testing.T) {
	cfg, err := parseCostExtractionConfig(nil)
	if err != nil || cfg != nil {
		t.Fatalf("expected nil,nil for nil input, got cfg=%+v err=%v", cfg, err)
	}

	cfg, err = parseCostExtractionConfig("bad")
	if err != nil || cfg != nil {
		t.Fatalf("expected invalid raw format to be ignored, got cfg=%+v err=%v", cfg, err)
	}

	cfg, err = parseCostExtractionConfig(map[string]interface{}{"enabled": true, "default": -4, "sources": []interface{}{map[string]interface{}{"type": "request_header", "key": "x"}}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Default != 0 {
		t.Fatalf("expected negative default clamped to 0, got %v", cfg.Default)
	}

	cfg, err = parseCostExtractionConfig(map[string]interface{}{"enabled": true, "sources": []interface{}{map[string]interface{}{"type": "request_header", "key": "x", "multiplier": -1}}})
	if err == nil || !strings.Contains(err.Error(), "multiplier must be non-negative") {
		t.Fatalf("expected negative multiplier error, got %v", err)
	}

	cfg, err = parseCostExtractionConfig(map[string]interface{}{"enabled": true, "sources": []interface{}{map[string]interface{}{"type": "request_header", "key": "x", "multiplier": 2}}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.Sources) != 1 || cfg.Sources[0].Multiplier != 2 {
		t.Fatalf("expected int multiplier conversion to float, got %+v", cfg.Sources)
	}

	cfg, err = parseCostExtractionConfig(map[string]interface{}{"enabled": true, "sources": []interface{}{map[string]interface{}{}}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Enabled {
		t.Fatalf("expected config disabled when all sources invalid, got %+v", cfg)
	}
}

func TestBuildMultiQuotaHeadersOnlyNilResults(t *testing.T) {
	p := &RateLimitPolicy{includeXRL: true, includeIETF: true, includeRetry: true}
	headers := p.buildMultiQuotaHeaders([]quotaResult{{QuotaName: "q1", Result: nil}}, true, "q1")
	if len(headers) != 0 {
		t.Fatalf("expected empty headers for nil-only results, got %+v", headers)
	}
}

func TestBuildRateLimitResponseWithoutViolatedResult(t *testing.T) {
	p := &RateLimitPolicy{includeXRL: true, includeIETF: true, includeRetry: true, statusCode: 429, responseBody: "{}", responseFormat: "json"}
	resp := p.buildRateLimitResponse(nil, "q1", nil)
	if resp.Headers["x-ratelimit-quota"] != "q1" {
		t.Fatalf("expected x-ratelimit-quota=q1, got %q", resp.Headers["x-ratelimit-quota"])
	}
	if resp.Headers["content-type"] != "application/json" {
		t.Fatalf("expected content-type application/json, got %q", resp.Headers["content-type"])
	}
}

func TestOnResponseRetryAfterFromViolatedQuotaPreference(t *testing.T) {
	p := &RateLimitPolicy{includeXRL: true, includeIETF: true, includeRetry: true}
	headers := p.buildMultiQuotaHeaders([]quotaResult{
		{QuotaName: "q1", Result: newResult(false, 100, 0, 7*time.Second, time.Minute), Duration: time.Minute},
		{QuotaName: "q2", Result: newResult(false, 100, 0, 2*time.Second, time.Minute), Duration: time.Minute},
	}, true, "q2")
	if headers["retry-after"] != "2" {
		t.Fatalf("expected retry-after=2 from violated quota q2, got %q", headers["retry-after"])
	}
}

func TestIETFResetIsNonNegativeInMultiQuotaHeaders(t *testing.T) {
	p := &RateLimitPolicy{includeXRL: true, includeIETF: true, includeRetry: true}
	headers := p.buildMultiQuotaHeaders([]quotaResult{{
		QuotaName: "q1",
		Duration:  time.Minute,
		Result: &limiter.Result{
			Limit:     10,
			Remaining: 2,
			Reset:     time.Now().Add(-time.Second),
			Duration:  time.Minute,
		},
	}}, false, "")

	parts := strings.Split(headers["ratelimit"], ";t=")
	if len(parts) < 2 {
		t.Fatalf("unexpected ratelimit header format: %q", headers["ratelimit"])
	}
	resetPart := strings.Trim(parts[1], " \"")
	resetPart = strings.TrimSuffix(resetPart, ",")
	reset, err := strconv.Atoi(resetPart)
	if err != nil {
		t.Fatalf("failed to parse reset from %q: %v", headers["ratelimit"], err)
	}
	if reset < 0 {
		t.Fatalf("expected non-negative reset, got %d", reset)
	}
}

/* TODO: fix bug — API-scoped cache key should include base configuration
func TestBugHunt_APIScopedCacheKeyShouldIncludeBaseConfiguration(t *testing.T) {
	// API-scoped keys should still include algorithm/config dimensions encoded in base.
	// Otherwise, incompatible limiter configurations can collide.
	q := &QuotaRuntime{
		Name:          "api-shared",
		Limits:        []LimitConfig{{Limit: 10, Duration: time.Minute}},
		KeyExtraction: []KeyComponent{{Type: "apiname"}},
	}

	kFixed := getQuotaCacheKey("base-fixed-window", "api-a", q, 0)
	kGCRA := getQuotaCacheKey("base-gcra", "api-a", q, 0)
	if kFixed == kGCRA {
		t.Fatalf("BUG: API-scoped cache key ignores base configuration; got same key %q", kFixed)
	}
}
*/

/* TODO: fix bug — API-scoped limiter cache collision across algorithms
func TestBugHunt_APIScopedLimiterCacheCollisionAcrossAlgorithms(t *testing.T) {
	clearCaches()
	defer clearCaches()

	metadataFixed := policy.PolicyMetadata{
		RouteName:  "route-fixed",
		APIName:    "api-a",
		APIVersion: "v1",
	}
	metadataGCRA := policy.PolicyMetadata{
		RouteName:  "route-gcra",
		APIName:    "api-a",
		APIVersion: "v1",
	}

	paramsFixed := map[string]interface{}{
		"backend":   "memory",
		"algorithm": "fixed-window",
		"quotas": []interface{}{
			map[string]interface{}{
				"name": "api-shared",
				"limits": []interface{}{
					map[string]interface{}{"limit": float64(10), "duration": "1m"},
				},
				"keyExtraction": []interface{}{
					map[string]interface{}{"type": "apiname"},
				},
			},
		},
	}
	paramsGCRA := map[string]interface{}{
		"backend":   "memory",
		"algorithm": "gcra",
		"quotas": []interface{}{
			map[string]interface{}{
				"name": "api-shared",
				"limits": []interface{}{
					map[string]interface{}{"limit": float64(10), "duration": "1m"},
				},
				"keyExtraction": []interface{}{
					map[string]interface{}{"type": "apiname"},
				},
			},
		},
	}

	pFixed, err := GetPolicy(metadataFixed, paramsFixed)
	if err != nil {
		t.Fatalf("fixed-window policy creation failed: %v", err)
	}
	pGCRA, err := GetPolicy(metadataGCRA, paramsGCRA)
	if err != nil {
		t.Fatalf("gcra policy creation failed: %v", err)
	}

	limFixed := pFixed.(*RateLimitPolicy).quotas[0].Limiter
	limGCRA := pGCRA.(*RateLimitPolicy).quotas[0].Limiter
	if limFixed == limGCRA {
		t.Fatal("BUG: API-scoped limiter cache collision across algorithms (fixed-window vs gcra)")
	}
}
*/

/* TODO: fix bug — zero limit should be rejected during parsing
func TestBugHunt_ZeroLimitShouldBeRejected(t *testing.T) {
	if _, err := parseSingleLimit(float64(0), "1s", nil); err == nil {
		t.Fatal("BUG: zero limit is accepted; should be rejected during parsing")
	}
}
*/

/* TODO: fix bug — limit/burst/duration must be positive
func TestBugHunt_LimitBurstAndDurationShouldBePositive(t *testing.T) {
	tests := []struct {
		name     string
		limit    interface{}
		duration interface{}
		burst    interface{}
	}{
		{
			name:     "negative limit",
			limit:    float64(-1),
			duration: "1s",
			burst:    nil,
		},
		{
			name:     "zero duration",
			limit:    float64(1),
			duration: "0s",
			burst:    nil,
		},
		{
			name:     "negative duration",
			limit:    float64(1),
			duration: "-1s",
			burst:    nil,
		},
		{
			name:     "negative burst",
			limit:    float64(10),
			duration: "1s",
			burst:    float64(-3),
		},
		{
			name:     "zero burst",
			limit:    float64(10),
			duration: "1s",
			burst:    float64(0),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := parseSingleLimit(tc.limit, tc.duration, tc.burst); err == nil {
				t.Fatalf("BUG: parseSingleLimit accepted invalid values limit=%v duration=%v burst=%v", tc.limit, tc.duration, tc.burst)
			}
		})
	}

	t.Run("fractional limit should be rejected", func(t *testing.T) {
		if _, err := parseSingleLimit(float64(1.7), "1s", nil); err == nil {
			t.Fatal("BUG: fractional limit accepted and truncated instead of being rejected")
		}
	})
}
*/

/* TODO: fix bug — unknown backend should fail validation
func TestBugHunt_UnknownBackendShouldFailValidation(t *testing.T) {
	params := map[string]interface{}{
		"backend":   "memroy-typo",
		"algorithm": "fixed-window",
		"quotas": []interface{}{
			map[string]interface{}{
				"name": "q1",
				"limits": []interface{}{
					map[string]interface{}{"limit": float64(10), "duration": "1m"},
				},
			},
		},
	}

	if _, err := GetPolicy(policy.PolicyMetadata{RouteName: "route-backend"}, params); err == nil {
		t.Fatal("BUG: unknown backend accepted and silently treated as memory")
	}
}
*/

/* TODO: fix bug — unknown keyExtraction type should fail validation
func TestBugHunt_UnknownKeyExtractionTypeShouldFailValidation(t *testing.T) {
	if _, err := parseKeyExtraction([]interface{}{map[string]interface{}{"type": "route_name_typo"}}); err == nil {
		t.Fatal("BUG: unknown keyExtraction type accepted without validation")
	}
}
*/

/* TODO: fix bug — keyExtraction types header/metadata/constant should require a key field
func TestBugHunt_KeyExtractionShouldRequireKeyForHeaderMetadataAndConstant(t *testing.T) {
	for _, tc := range []struct {
		name string
		typ  string
	}{
		{name: "header requires key", typ: "header"},
		{name: "metadata requires key", typ: "metadata"},
		{name: "constant requires key", typ: "constant"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := parseKeyExtraction([]interface{}{map[string]interface{}{"type": tc.typ}}); err == nil {
				t.Fatalf("BUG: keyExtraction type %q accepted without required key", tc.typ)
			}
		})
	}
}
*/

/* TODO: fix bug — unknown cost source type should fail validation
func TestBugHunt_UnknownCostSourceTypeShouldFailValidation(t *testing.T) {
	_, err := parseCostExtractionConfig(map[string]interface{}{
		"enabled": true,
		"sources": []interface{}{
			map[string]interface{}{"type": "response_hader_typo", "key": "x-cost"},
		},
	})
	if err == nil {
		t.Fatal("BUG: unknown costExtraction source type accepted without validation")
	}
}
*/

/* TODO: fix bug — invalid costExtraction shape should fail fast
func TestBugHunt_InvalidCostExtractionShapeShouldFailFast(t *testing.T) {
	// Passing non-object costExtraction should raise validation error rather than silently disabling.
	params := map[string]interface{}{
		"quotas": []interface{}{
			map[string]interface{}{
				"name": "q1",
				"limits": []interface{}{
					map[string]interface{}{"limit": float64(10), "duration": "1m"},
				},
				"costExtraction": "invalid-shape",
			},
		},
	}

	if _, err := parseQuotas(params); err == nil {
		t.Fatal("BUG: invalid costExtraction shape accepted silently")
	}
}
*/

/* TODO: fix bug — cost source required fields should be validated
func TestBugHunt_CostSourceRequiredFieldsShouldBeValidated(t *testing.T) {
	tests := []struct {
		name   string
		source map[string]interface{}
	}{
		{
			name:   "request_header missing key",
			source: map[string]interface{}{"type": "request_header"},
		},
		{
			name:   "response_header missing key",
			source: map[string]interface{}{"type": "response_header"},
		},
		{
			name:   "request_body missing jsonPath",
			source: map[string]interface{}{"type": "request_body"},
		},
		{
			name:   "response_body missing jsonPath",
			source: map[string]interface{}{"type": "response_body"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseCostExtractionConfig(map[string]interface{}{
				"enabled": true,
				"sources": []interface{}{tc.source},
			})
			if err == nil {
				t.Fatalf("BUG: cost source accepted without required fields: %+v", tc.source)
			}
		})
	}
}
*/

/* TODO: fix bug — GCRA zero-limit should not panic on request
func TestBugHunt_GCRAZeroLimitShouldNotPanicOnRequest(t *testing.T) {
	clearCaches()
	defer clearCaches()

	params := map[string]interface{}{
		"backend":   "memory",
		"algorithm": "gcra",
		"quotas": []interface{}{
			map[string]interface{}{
				"name": "zero-limit",
				"limits": []interface{}{
					map[string]interface{}{"limit": float64(0), "duration": "1m"},
				},
			},
		},
	}

	p, err := GetPolicy(policy.PolicyMetadata{RouteName: "route-zero", APIName: "api-zero", APIVersion: "v1"}, params)
	if err != nil {
		// Ideal behavior: reject invalid config at creation time.
		return
	}

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("BUG: zero-limit gcra policy panicked during request processing: %v", r)
		}
	}()

	ctx := newRequestCtx(nil, nil)
	_ = p.OnRequestBody(context.Background(), ctx, nil)
}
*/

/* TODO: fix bug — multi-quota header should sanitize quota names
func TestBugHunt_MultiQuotaHeaderShouldSanitizeQuotaNames(t *testing.T) {
	p := &RateLimitPolicy{includeXRL: true, includeIETF: true, includeRetry: true}
	headers := p.buildMultiQuotaHeaders([]quotaResult{
		{
			QuotaName: "bad\"name",
			Duration:  time.Minute,
			Result:    newResult(true, 10, 5, 0, time.Minute),
		},
	}, false, "")

	// Unescaped embedded quotes create invalid structured field syntax.
	if strings.Contains(headers["ratelimit-policy"], `bad"name`) {
		t.Fatalf("BUG: quota name not sanitized for structured header: %q", headers["ratelimit-policy"])
	}
}
*/

/* TODO: fix bug — invalid onRateLimitExceeded values should fail validation
func TestBugHunt_InvalidExceededResponseValuesShouldFailValidation(t *testing.T) {
	params := map[string]interface{}{
		"backend":   "memory",
		"algorithm": "fixed-window",
		"quotas": []interface{}{
			map[string]interface{}{
				"name": "q1",
				"limits": []interface{}{
					map[string]interface{}{"limit": float64(10), "duration": "1m"},
				},
			},
		},
		"onRateLimitExceeded": map[string]interface{}{
			"statusCode": float64(200),      // outside documented 400-599
			"bodyFormat": "xml-not-allowed", // outside documented enum
		},
	}

	if _, err := GetPolicy(policy.PolicyMetadata{RouteName: "route-invalid-exceeded"}, params); err == nil {
		t.Fatal("BUG: invalid onRateLimitExceeded.statusCode/bodyFormat accepted without validation")
	}
}
*/

/* TODO: fix bug — invalid redis.failureMode should fail validation
func TestBugHunt_InvalidRedisFailureModeShouldFailValidation(t *testing.T) {
	params := map[string]interface{}{
		"backend":   "redis",
		"algorithm": "fixed-window",
		"quotas": []interface{}{
			map[string]interface{}{
				"name": "q1",
				"limits": []interface{}{
					map[string]interface{}{"limit": float64(10), "duration": "1m"},
				},
			},
		},
		"redis": map[string]interface{}{
			"host":              "192.0.2.1",
			"port":              float64(6399),
			"failureMode":       "half-open-typo",
			"connectionTimeout": "1ms",
			"readTimeout":       "1ms",
			"writeTimeout":      "1ms",
		},
	}

	_, err := GetPolicy(policy.PolicyMetadata{RouteName: "route-invalid-failure-mode"}, params)
	if err == nil {
		t.Fatal("BUG: invalid redis.failureMode accepted without validation")
	}
	if strings.Contains(err.Error(), "failureMode=closed") {
		t.Fatalf("BUG: invalid redis.failureMode coerced to closed instead of validation error: %v", err)
	}
}
*/

/* TODO: fix bug — string multiplier type should be rejected with validation error
func TestBugHunt_MultiplierTypeShouldBeValidated(t *testing.T) {
	_, err := parseCostExtractionConfig(map[string]interface{}{
		"enabled": true,
		"sources": []interface{}{
			map[string]interface{}{
				"type":       "request_header",
				"key":        "x-cost",
				"multiplier": "2x",
			},
		},
	})
	if err == nil {
		t.Fatal("BUG: string multiplier accepted silently instead of validation error")
	}
}
*/

// newResponseStreamCtx builds a ResponseStreamContext for use in OnResponseBodyChunk tests.
// metadata should contain at least rateLimitKeysKey so EOS cost consumption can resolve quota keys.
func newResponseStreamCtx(reqHeaders, respHeaders map[string][]string, metadata map[string]interface{}, status int) *policy.ResponseStreamContext {
	if metadata == nil {
		metadata = map[string]interface{}{}
	}
	if reqHeaders == nil {
		reqHeaders = map[string][]string{}
	}
	if respHeaders == nil {
		respHeaders = map[string][]string{}
	}
	return &policy.ResponseStreamContext{
		SharedContext: &policy.SharedContext{
			Metadata:   metadata,
			APIName:    "petstore",
			APIVersion: "v1",
			APIId:      "api-id",
			APIContext: "/petstore",
		},
		RequestHeaders:  policy.NewHeaders(reqHeaders),
		ResponseHeaders: policy.NewHeaders(respHeaders),
		ResponseStatus:  status,
	}
}

// sendChunks is a test helper that calls OnResponseBodyChunk for each provided byte slice.
// The last slice is delivered with EndOfStream=true. It uses the same respCtx for all calls
// so that the per-request streaming state in Metadata accumulates correctly.
func sendChunks(t *testing.T, p *RateLimitPolicy, respCtx *policy.ResponseStreamContext, chunks [][]byte) {
	t.Helper()
	for i, c := range chunks {
		eos := i == len(chunks)-1
		chunk := &policy.StreamBody{Chunk: c, EndOfStream: eos, Index: uint64(i)}
		p.OnResponseBodyChunk(context.Background(), respCtx, chunk, nil)
	}
}

// ─── OnResponseBodyChunk integration tests ───────────────────────────────────

func TestOnResponseBodyChunk_OpenAISSE_MultiChunk(t *testing.T) {
	// Simulate an OpenAI SSE stream split across three chunks.
	// The final data: line before [DONE] carries usage — last-match-wins gives total_tokens=75.
	lim := &fakeLimiter{}
	ce := NewCostExtractor(CostExtractionConfig{
		Enabled: true,
		Default: 1,
		Sources: []CostSource{{Type: CostSourceResponseBody, JSONPath: "$.usage.total_tokens", Multiplier: 1}},
	})
	p := &RateLimitPolicy{
		quotas: []QuotaRuntime{{
			Name: "tokens", Limiter: lim,
			Limits:                []LimitConfig{{Limit: 10000, Duration: time.Minute}},
			CostExtractor:         ce,
			CostExtractionEnabled: true,
		}},
		routeName: "route-openai",
	}

	meta := map[string]interface{}{
		rateLimitKeysKey: map[string]string{"tokens": "openai-key"},
	}
	respCtx := newResponseStreamCtx(nil, nil, meta, 200)

	chunks := [][]byte{
		// Chunk 0: first content delta — no usage field
		[]byte("data: {\"id\":\"chatcmpl-1\",\"object\":\"chat.completion.chunk\",\"choices\":[{\"delta\":{\"content\":\"Hello\"}}]}\n"),
		// Chunk 1: final delta with usage (stream_options: {include_usage: true})
		[]byte("data: {\"id\":\"chatcmpl-1\",\"usage\":{\"prompt_tokens\":25,\"completion_tokens\":50,\"total_tokens\":75}}\n"),
		// Chunk 2: [DONE] terminator with EOS
		[]byte("data: [DONE]\n"),
	}
	sendChunks(t, p, respCtx, chunks)

	if lim.consumeNCalls != 1 {
		t.Fatalf("expected ConsumeN called once, got %d", lim.consumeNCalls)
	}
	if lim.lastCost != 75 {
		t.Fatalf("expected cost=75 from usage.total_tokens, got %d", lim.lastCost)
	}
}

func TestOnResponseBodyChunk_AnthropicSSE_OutputTokens(t *testing.T) {
	// Anthropic streams usage in the message_delta event. The message_stop event that
	// follows has no usage field, so last-match-wins returns output_tokens=20.
	lim := &fakeLimiter{}
	ce := NewCostExtractor(CostExtractionConfig{
		Enabled: true,
		Default: 1,
		Sources: []CostSource{{Type: CostSourceResponseBody, JSONPath: "$.usage.output_tokens", Multiplier: 1}},
	})
	p := &RateLimitPolicy{
		quotas: []QuotaRuntime{{
			Name: "tokens", Limiter: lim,
			Limits:                []LimitConfig{{Limit: 10000, Duration: time.Minute}},
			CostExtractor:         ce,
			CostExtractionEnabled: true,
		}},
		routeName: "route-anthropic",
	}

	meta := map[string]interface{}{
		rateLimitKeysKey: map[string]string{"tokens": "anthropic-key"},
	}
	respCtx := newResponseStreamCtx(nil, nil, meta, 200)

	// Deliver the full Anthropic SSE body as a single chunk with EOS.
	// anthropicSSEBody has message_delta with usage.output_tokens=20.
	chunk := &policy.StreamBody{
		Chunk:       []byte(anthropicSSEBody),
		EndOfStream: true,
		Index:       0,
	}
	p.OnResponseBodyChunk(context.Background(), respCtx, chunk, nil)

	if lim.consumeNCalls != 1 {
		t.Fatalf("expected ConsumeN called once, got %d", lim.consumeNCalls)
	}
	if lim.lastCost != 20 {
		t.Fatalf("expected cost=20 from usage.output_tokens, got %d", lim.lastCost)
	}
}

func TestOnResponseBodyChunk_PlainJSONChunked_AccumulateAndExtractAtEOS(t *testing.T) {
	// Plain JSON response delivered as two chunks (chunked transfer encoding).
	// The policy must accumulate both chunks and extract the jsonPath only at EOS.
	lim := &fakeLimiter{}
	ce := NewCostExtractor(CostExtractionConfig{
		Enabled: true,
		Default: 1,
		Sources: []CostSource{{Type: CostSourceResponseBody, JSONPath: "$.tokens", Multiplier: 1}},
	})
	p := &RateLimitPolicy{
		quotas: []QuotaRuntime{{
			Name: "tokens", Limiter: lim,
			Limits:                []LimitConfig{{Limit: 10000, Duration: time.Minute}},
			CostExtractor:         ce,
			CostExtractionEnabled: true,
		}},
		routeName: "route-json",
	}

	meta := map[string]interface{}{
		rateLimitKeysKey: map[string]string{"tokens": "json-key"},
	}
	respCtx := newResponseStreamCtx(nil, nil, meta, 200)

	// Split the JSON body across two chunks so the parser cannot extract mid-stream.
	sendChunks(t, p, respCtx, [][]byte{
		[]byte(`{"result":"ok","tok`),
		[]byte(`ens":42}`),
	})

	if lim.consumeNCalls != 1 {
		t.Fatalf("expected ConsumeN called once at EOS, got %d", lim.consumeNCalls)
	}
	if lim.lastCost != 42 {
		t.Fatalf("expected cost=42 from $.tokens, got %d", lim.lastCost)
	}
}

func TestOnResponseBodyChunk_NoUsageField_FallsBackToDefault(t *testing.T) {
	// When the jsonPath is absent from all SSE events, the configured default cost is used.
	lim := &fakeLimiter{}
	ce := NewCostExtractor(CostExtractionConfig{
		Enabled: true,
		Default: 5, // fallback
		Sources: []CostSource{{Type: CostSourceResponseBody, JSONPath: "$.usage.total_tokens", Multiplier: 1}},
	})
	p := &RateLimitPolicy{
		quotas: []QuotaRuntime{{
			Name: "tokens", Limiter: lim,
			Limits:                []LimitConfig{{Limit: 1000, Duration: time.Minute}},
			CostExtractor:         ce,
			CostExtractionEnabled: true,
		}},
		routeName: "route-nofield",
	}

	meta := map[string]interface{}{
		rateLimitKeysKey: map[string]string{"tokens": "nf-key"},
	}
	respCtx := newResponseStreamCtx(nil, nil, meta, 200)

	// SSE body where no data: line carries $.usage.total_tokens.
	sendChunks(t, p, respCtx, [][]byte{
		[]byte("data: {\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\n"),
		[]byte("data: [DONE]\n"),
	})

	if lim.consumeNCalls != 1 {
		t.Fatalf("expected ConsumeN called once (with default), got %d", lim.consumeNCalls)
	}
	if lim.lastCost != 5 {
		t.Fatalf("expected cost=5 (default), got %d", lim.lastCost)
	}
}

func TestOnResponseBodyChunk_MultiplierApplied(t *testing.T) {
	// Extracted value is multiplied before consumption.
	lim := &fakeLimiter{}
	ce := NewCostExtractor(CostExtractionConfig{
		Enabled: true,
		Default: 1,
		Sources: []CostSource{{Type: CostSourceResponseBody, JSONPath: "$.usage.total_tokens", Multiplier: 0.5}},
	})
	p := &RateLimitPolicy{
		quotas: []QuotaRuntime{{
			Name: "tokens", Limiter: lim,
			Limits:                []LimitConfig{{Limit: 10000, Duration: time.Minute}},
			CostExtractor:         ce,
			CostExtractionEnabled: true,
		}},
		routeName: "route-multiplier",
	}

	meta := map[string]interface{}{
		rateLimitKeysKey: map[string]string{"tokens": "mul-key"},
	}
	respCtx := newResponseStreamCtx(nil, nil, meta, 200)

	// total_tokens=100, multiplier=0.5 → expected cost=50
	chunk := &policy.StreamBody{
		Chunk:       []byte("data: {\"usage\":{\"total_tokens\":100}}\n"),
		EndOfStream: true,
		Index:       0,
	}
	p.OnResponseBodyChunk(context.Background(), respCtx, chunk, nil)

	if lim.consumeNCalls != 1 {
		t.Fatalf("expected ConsumeN called once, got %d", lim.consumeNCalls)
	}
	if lim.lastCost != 50 {
		t.Fatalf("expected cost=50 (100 × 0.5), got %d", lim.lastCost)
	}
}

func TestOnResponseBodyChunk_EmptyFirstChunkDeferrsSSEDetection(t *testing.T) {
	// The first chunk may be a keep-alive (empty bytes). SSE detection must be deferred
	// until the first non-empty chunk to avoid misidentifying the stream as JSON.
	lim := &fakeLimiter{}
	ce := NewCostExtractor(CostExtractionConfig{
		Enabled: true,
		Default: 1,
		Sources: []CostSource{{Type: CostSourceResponseBody, JSONPath: "$.usage.total_tokens", Multiplier: 1}},
	})
	p := &RateLimitPolicy{
		quotas: []QuotaRuntime{{
			Name: "tokens", Limiter: lim,
			Limits:                []LimitConfig{{Limit: 10000, Duration: time.Minute}},
			CostExtractor:         ce,
			CostExtractionEnabled: true,
		}},
		routeName: "route-keepalive",
	}

	meta := map[string]interface{}{
		rateLimitKeysKey: map[string]string{"tokens": "ka-key"},
	}
	respCtx := newResponseStreamCtx(nil, nil, meta, 200)

	sendChunks(t, p, respCtx, [][]byte{
		{}, // empty keep-alive — must not trigger JSON mode
		[]byte("data: {\"usage\":{\"total_tokens\":33}}\n"),
		[]byte("data: [DONE]\n"),
	})

	if lim.consumeNCalls != 1 {
		t.Fatalf("expected ConsumeN called once, got %d", lim.consumeNCalls)
	}
	if lim.lastCost != 33 {
		t.Fatalf("expected cost=33 after deferred SSE detection, got %d", lim.lastCost)
	}
}

func TestOnResponseBodyChunk_MultipleResponseBodySources_Summed(t *testing.T) {
	// Regression test for the multi-source bug: when a quota has two response_body
	// sources (e.g. prompt_tokens + completion_tokens), both values must be extracted
	// and summed. The old per-chunk per-source path overwrote qs.lastCost on each
	// source, so only the last source's value was charged.
	lim := &fakeLimiter{}
	ce := NewCostExtractor(CostExtractionConfig{
		Enabled: true,
		Default: 1,
		Sources: []CostSource{
			{Type: CostSourceResponseBody, JSONPath: "$.usage.prompt_tokens", Multiplier: 1},
			{Type: CostSourceResponseBody, JSONPath: "$.usage.completion_tokens", Multiplier: 1},
		},
	})
	p := &RateLimitPolicy{
		quotas: []QuotaRuntime{{
			Name:                  "tokens",
			Limiter:               lim,
			Limits:                []LimitConfig{{Limit: 10000, Duration: time.Minute}},
			CostExtractor:         ce,
			CostExtractionEnabled: true,
		}},
		routeName: "route-multisource",
	}

	meta := map[string]interface{}{
		rateLimitKeysKey: map[string]string{"tokens": "ms-key"},
	}
	respCtx := newResponseStreamCtx(nil, nil, meta, 200)

	// OpenAI-style stream: content deltas carry no usage; only the final event does.
	sendChunks(t, p, respCtx, [][]byte{
		[]byte("data: {\"choices\":[{\"delta\":{\"content\":\"Hello\"}}]}\n"),
		[]byte("data: {\"choices\":[{\"delta\":{\"content\":\" world\"}}]}\n"),
		// Final event: prompt_tokens=25, completion_tokens=50 → expected total=75
		[]byte("data: {\"usage\":{\"prompt_tokens\":25,\"completion_tokens\":50,\"total_tokens\":75}}\n"),
		[]byte("data: [DONE]\n"),
	})

	if lim.consumeNCalls != 1 {
		t.Fatalf("expected ConsumeN called once, got %d", lim.consumeNCalls)
	}
	// Both sources must be summed: 25 + 50 = 75
	if lim.lastCost != 75 {
		t.Fatalf("expected cost=75 (prompt_tokens+completion_tokens), got %d — multi-source accumulation broken", lim.lastCost)
	}
}

func TestOnResponseBodyChunk_MultipleResponseBodySources_WithMultipliers(t *testing.T) {
	// Two sources with different multipliers: prompt_tokens * 1.0, completion_tokens * 2.0
	// prompt=25, completion=50 → 25*1 + 50*2 = 125
	lim := &fakeLimiter{}
	ce := NewCostExtractor(CostExtractionConfig{
		Enabled: true,
		Default: 1,
		Sources: []CostSource{
			{Type: CostSourceResponseBody, JSONPath: "$.usage.prompt_tokens", Multiplier: 1.0},
			{Type: CostSourceResponseBody, JSONPath: "$.usage.completion_tokens", Multiplier: 2.0},
		},
	})
	p := &RateLimitPolicy{
		quotas: []QuotaRuntime{{
			Name:                  "tokens",
			Limiter:               lim,
			Limits:                []LimitConfig{{Limit: 10000, Duration: time.Minute}},
			CostExtractor:         ce,
			CostExtractionEnabled: true,
		}},
		routeName: "route-multimul",
	}

	meta := map[string]interface{}{
		rateLimitKeysKey: map[string]string{"tokens": "mm-key"},
	}
	respCtx := newResponseStreamCtx(nil, nil, meta, 200)

	sendChunks(t, p, respCtx, [][]byte{
		[]byte("data: {\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\n"),
		[]byte("data: {\"usage\":{\"prompt_tokens\":25,\"completion_tokens\":50,\"total_tokens\":75}}\n"),
		[]byte("data: [DONE]\n"),
	})

	if lim.consumeNCalls != 1 {
		t.Fatalf("expected ConsumeN called once, got %d", lim.consumeNCalls)
	}
	// 25*1 + 50*2 = 125
	if lim.lastCost != 125 {
		t.Fatalf("expected cost=125 (25×1 + 50×2), got %d", lim.lastCost)
	}
}

func TestOnResponseBodyChunk_OpenAISSE_ManyChunks(t *testing.T) {
	// Realistic OpenAI stream: 10 content delta events followed by a usage event
	// and [DONE]. Verifies that last-match-wins correctly picks the final usage value
	// even when many intermediate chunks contain no usage field.
	lim := &fakeLimiter{}
	ce := NewCostExtractor(CostExtractionConfig{
		Enabled: true,
		Default: 1,
		Sources: []CostSource{
			{Type: CostSourceResponseBody, JSONPath: "$.usage.total_tokens", Multiplier: 1},
		},
	})
	p := &RateLimitPolicy{
		quotas: []QuotaRuntime{{
			Name:                  "tokens",
			Limiter:               lim,
			Limits:                []LimitConfig{{Limit: 10000, Duration: time.Minute}},
			CostExtractor:         ce,
			CostExtractionEnabled: true,
		}},
		routeName: "route-many",
	}

	meta := map[string]interface{}{
		rateLimitKeysKey: map[string]string{"tokens": "many-key"},
	}
	respCtx := newResponseStreamCtx(nil, nil, meta, 200)

	// 10 content-only delta chunks (no usage field), then a usage-only chunk, then [DONE].
	words := []string{"The", " quick", " brown", " fox", " jumps", " over", " the", " lazy", " dog", "."}
	chunks := make([][]byte, 0, len(words)+2)
	for _, w := range words {
		chunks = append(chunks, []byte(`data: {"id":"chatcmpl-x","choices":[{"delta":{"content":"`+w+`"}}]}`+"\n"))
	}
	// Final usage event — prompt_tokens=12, completion_tokens=10, total_tokens=22
	chunks = append(chunks, []byte("data: {\"id\":\"chatcmpl-x\",\"choices\":[],\"usage\":{\"prompt_tokens\":12,\"completion_tokens\":10,\"total_tokens\":22}}\n"))
	chunks = append(chunks, []byte("data: [DONE]\n"))

	sendChunks(t, p, respCtx, chunks)

	if lim.consumeNCalls != 1 {
		t.Fatalf("expected ConsumeN called once, got %d", lim.consumeNCalls)
	}
	if lim.lastCost != 22 {
		t.Fatalf("expected cost=22 from final usage event, got %d", lim.lastCost)
	}
}

func TestOnResponseBodyChunk_AnthropicSSE_MultiChunk_SplitAcrossBoundary(t *testing.T) {
	// Anthropic SSE stream delivered as many small chunks — including a split mid-line —
	// to verify that byte accumulation correctly reconstructs the body at EOS.
	// The authoritative usage is in the message_delta event: input_tokens=10, output_tokens=20.
	lim := &fakeLimiter{}
	ce := NewCostExtractor(CostExtractionConfig{
		Enabled: true,
		Default: 1,
		Sources: []CostSource{
			{Type: CostSourceResponseBody, JSONPath: "$.usage.output_tokens", Multiplier: 1},
		},
	})
	p := &RateLimitPolicy{
		quotas: []QuotaRuntime{{
			Name:                  "tokens",
			Limiter:               lim,
			Limits:                []LimitConfig{{Limit: 10000, Duration: time.Minute}},
			CostExtractor:         ce,
			CostExtractionEnabled: true,
		}},
		routeName: "route-anthropic-split",
	}

	meta := map[string]interface{}{
		rateLimitKeysKey: map[string]string{"tokens": "as-key"},
	}
	respCtx := newResponseStreamCtx(nil, nil, meta, 200)

	// Split the anthropicSSEBody into individual lines (one chunk per line).
	// This simulates each SSE event arriving as a separate chunk and exercises
	// the accumulation path across many boundary crossings.
	lines := strings.Split(anthropicSSEBody, "\n")
	chunks := make([][]byte, 0, len(lines))
	for _, line := range lines {
		if line == "" {
			chunks = append(chunks, []byte("\n"))
		} else {
			chunks = append(chunks, []byte(line+"\n"))
		}
	}
	// Remove trailing empty chunk if present
	for len(chunks) > 0 && len(chunks[len(chunks)-1]) == 0 {
		chunks = chunks[:len(chunks)-1]
	}

	sendChunks(t, p, respCtx, chunks)

	if lim.consumeNCalls != 1 {
		t.Fatalf("expected ConsumeN called once, got %d", lim.consumeNCalls)
	}
	if lim.lastCost != 20 {
		t.Fatalf("expected cost=20 from message_delta usage.output_tokens, got %d", lim.lastCost)
	}
}

func TestOnResponseBodyChunk_AnthropicSSE_TwoSources_InputPlusOutput(t *testing.T) {
	// Two response_body sources extracting input and output tokens separately from
	// the Anthropic message_delta event. Both must be summed: 10 + 20 = 30.
	lim := &fakeLimiter{}
	ce := NewCostExtractor(CostExtractionConfig{
		Enabled: true,
		Default: 1,
		Sources: []CostSource{
			{Type: CostSourceResponseBody, JSONPath: "$.usage.input_tokens", Multiplier: 1},
			{Type: CostSourceResponseBody, JSONPath: "$.usage.output_tokens", Multiplier: 1},
		},
	})
	p := &RateLimitPolicy{
		quotas: []QuotaRuntime{{
			Name:                  "tokens",
			Limiter:               lim,
			Limits:                []LimitConfig{{Limit: 10000, Duration: time.Minute}},
			CostExtractor:         ce,
			CostExtractionEnabled: true,
		}},
		routeName: "route-anthropic-both",
	}

	meta := map[string]interface{}{
		rateLimitKeysKey: map[string]string{"tokens": "ab-key"},
	}
	respCtx := newResponseStreamCtx(nil, nil, meta, 200)

	// Deliver the Anthropic SSE body line-by-line to exercise multi-chunk accumulation.
	lines := strings.Split(anthropicSSEBody, "\n")
	chunks := make([][]byte, 0, len(lines))
	for _, line := range lines {
		if line == "" {
			chunks = append(chunks, []byte("\n"))
		} else {
			chunks = append(chunks, []byte(line+"\n"))
		}
	}
	for len(chunks) > 0 && len(chunks[len(chunks)-1]) == 0 {
		chunks = chunks[:len(chunks)-1]
	}

	sendChunks(t, p, respCtx, chunks)

	if lim.consumeNCalls != 1 {
		t.Fatalf("expected ConsumeN called once, got %d", lim.consumeNCalls)
	}
	// input_tokens=10 + output_tokens=20 = 30
	if lim.lastCost != 30 {
		t.Fatalf("expected cost=30 (input_tokens+output_tokens), got %d — multi-source accumulation broken", lim.lastCost)
	}
}

func TestOnResponseBodyChunk_OpenAISSE_BufferedAndIndividualChunks(t *testing.T) {
	// Simulates what happens when another policy in the chain returns NeedsMoreData=true:
	// the kernel buffers several SSE events and delivers them together as one large chunk,
	// while the remaining events arrive individually. The rate-limit policy must still
	// extract the correct final usage value from the complete accumulated body.
	//
	// Stream layout:
	//   chunk 0 (buffered — 4 events merged): 4 content delta events
	//   chunk 1 (individual):                 1 more content delta
	//   chunk 2 (individual):                 final usage event
	//   chunk 3 (individual + EOS):           [DONE]
	lim := &fakeLimiter{}
	ce := NewCostExtractor(CostExtractionConfig{
		Enabled: true,
		Default: 1,
		Sources: []CostSource{
			{Type: CostSourceResponseBody, JSONPath: "$.usage.total_tokens", Multiplier: 1},
		},
	})
	p := &RateLimitPolicy{
		quotas: []QuotaRuntime{{
			Name:                  "tokens",
			Limiter:               lim,
			Limits:                []LimitConfig{{Limit: 10000, Duration: time.Minute}},
			CostExtractor:         ce,
			CostExtractionEnabled: true,
		}},
		routeName: "route-buffered",
	}

	meta := map[string]interface{}{
		rateLimitKeysKey: map[string]string{"tokens": "buf-key"},
	}
	respCtx := newResponseStreamCtx(nil, nil, meta, 200)

	// Four events merged into one chunk by the kernel (simulating upstream buffering).
	buffered := strings.Join([]string{
		`data: {"choices":[{"delta":{"content":"The"}}]}`,
		`data: {"choices":[{"delta":{"content":" quick"}}]}`,
		`data: {"choices":[{"delta":{"content":" brown"}}]}`,
		`data: {"choices":[{"delta":{"content":" fox"}}]}`,
		"",
	}, "\n")

	sendChunks(t, p, respCtx, [][]byte{
		[]byte(buffered), // chunk 0: 4 events buffered together
		[]byte("data: {\"choices\":[{\"delta\":{\"content\":\" jumps\"}}]}\n"),                          // chunk 1: individual
		[]byte("data: {\"usage\":{\"prompt_tokens\":8,\"completion_tokens\":5,\"total_tokens\":13}}\n"), // chunk 2: usage
		[]byte("data: [DONE]\n"), // chunk 3: EOS
	})

	if lim.consumeNCalls != 1 {
		t.Fatalf("expected ConsumeN called once, got %d", lim.consumeNCalls)
	}
	if lim.lastCost != 13 {
		t.Fatalf("expected cost=13 from final usage event, got %d", lim.lastCost)
	}
}

func TestOnResponseBodyChunk_OpenAISSE_BufferedAndIndividual_MultiSource(t *testing.T) {
	// Same mixed-buffering scenario but with two response_body sources
	// (prompt_tokens + completion_tokens). Verifies that multi-source summing
	// is not affected by whether events arrive individually or batched.
	lim := &fakeLimiter{}
	ce := NewCostExtractor(CostExtractionConfig{
		Enabled: true,
		Default: 1,
		Sources: []CostSource{
			{Type: CostSourceResponseBody, JSONPath: "$.usage.prompt_tokens", Multiplier: 1},
			{Type: CostSourceResponseBody, JSONPath: "$.usage.completion_tokens", Multiplier: 1},
		},
	})
	p := &RateLimitPolicy{
		quotas: []QuotaRuntime{{
			Name:                  "tokens",
			Limiter:               lim,
			Limits:                []LimitConfig{{Limit: 10000, Duration: time.Minute}},
			CostExtractor:         ce,
			CostExtractionEnabled: true,
		}},
		routeName: "route-buffered-multi",
	}

	meta := map[string]interface{}{
		rateLimitKeysKey: map[string]string{"tokens": "bm-key"},
	}
	respCtx := newResponseStreamCtx(nil, nil, meta, 200)

	// First two events arrive buffered together; the usage event arrives alone.
	buffered := "data: {\"choices\":[{\"delta\":{\"content\":\"Hello\"}}]}\n" +
		"data: {\"choices\":[{\"delta\":{\"content\":\" world\"}}]}\n"

	sendChunks(t, p, respCtx, [][]byte{
		[]byte(buffered),
		// prompt_tokens=30, completion_tokens=45 → expected 30+45=75
		[]byte("data: {\"usage\":{\"prompt_tokens\":30,\"completion_tokens\":45,\"total_tokens\":75}}\n"),
		[]byte("data: [DONE]\n"),
	})

	if lim.consumeNCalls != 1 {
		t.Fatalf("expected ConsumeN called once, got %d", lim.consumeNCalls)
	}
	if lim.lastCost != 75 {
		t.Fatalf("expected cost=75 (30+45), got %d", lim.lastCost)
	}
}

func TestOnResponseBodyChunk_AnthropicSSE_BufferedEventsWithIndividualUsage(t *testing.T) {
	// Anthropic stream where the bulk of content events are buffered into one chunk
	// by an upstream policy, but the authoritative message_delta (with usage) and
	// message_stop arrive as individual chunks.
	//
	// input_tokens=10, output_tokens=20 in the message_delta event.
	lim := &fakeLimiter{}
	ce := NewCostExtractor(CostExtractionConfig{
		Enabled: true,
		Default: 1,
		Sources: []CostSource{
			{Type: CostSourceResponseBody, JSONPath: "$.usage.input_tokens", Multiplier: 1},
			{Type: CostSourceResponseBody, JSONPath: "$.usage.output_tokens", Multiplier: 1},
		},
	})
	p := &RateLimitPolicy{
		quotas: []QuotaRuntime{{
			Name:                  "tokens",
			Limiter:               lim,
			Limits:                []LimitConfig{{Limit: 10000, Duration: time.Minute}},
			CostExtractor:         ce,
			CostExtractionEnabled: true,
		}},
		routeName: "route-anthropic-buffered",
	}

	meta := map[string]interface{}{
		rateLimitKeysKey: map[string]string{"tokens": "ab2-key"},
	}
	respCtx := newResponseStreamCtx(nil, nil, meta, 200)

	// Chunk 0 (buffered): message_start + content_block_start + two content_block_delta events
	bufferedStart := "event: message_start\n" +
		"data: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":0,\"output_tokens\":0}}}\n" +
		"\n" +
		"event: content_block_start\n" +
		"data: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n" +
		"\n" +
		"event: content_block_delta\n" +
		"data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"Hello\"}}\n" +
		"\n" +
		"event: content_block_delta\n" +
		"data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\" world\"}}\n" +
		"\n"

	// Chunk 1 (individual): the authoritative message_delta with usage
	messageDelta := "event: message_delta\n" +
		"data: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"input_tokens\":10,\"output_tokens\":20}}\n" +
		"\n"

	// Chunk 2 (individual + EOS): message_stop
	messageStop := "event: message_stop\n" +
		"data: {\"type\":\"message_stop\"}\n"

	sendChunks(t, p, respCtx, [][]byte{
		[]byte(bufferedStart),
		[]byte(messageDelta),
		[]byte(messageStop),
	})

	if lim.consumeNCalls != 1 {
		t.Fatalf("expected ConsumeN called once, got %d", lim.consumeNCalls)
	}
	// input_tokens=10 + output_tokens=20 = 30
	if lim.lastCost != 30 {
		t.Fatalf("expected cost=30 (input_tokens+output_tokens from message_delta), got %d", lim.lastCost)
	}
}

func TestOnResponseBodyChunk_NoCostExtractionEnabled_NoConsume(t *testing.T) {
	// Quotas without cost extraction enabled must not call ConsumeN.
	lim := &fakeLimiter{}
	p := &RateLimitPolicy{
		quotas: []QuotaRuntime{{
			Name: "basic", Limiter: lim,
			Limits:                []LimitConfig{{Limit: 10, Duration: time.Minute}},
			CostExtractionEnabled: false,
		}},
		routeName: "route-nocost",
	}

	meta := map[string]interface{}{
		rateLimitKeysKey: map[string]string{"basic": "basic-key"},
	}
	respCtx := newResponseStreamCtx(nil, nil, meta, 200)

	sendChunks(t, p, respCtx, [][]byte{
		[]byte("data: {\"usage\":{\"total_tokens\":99}}\n"),
	})

	if lim.consumeNCalls != 0 {
		t.Fatalf("expected ConsumeN not called, got %d calls", lim.consumeNCalls)
	}
}

// TestOnResponseBodyChunk_MatchSkippedQuota_NoPhantomConsumption is a regression test for a
// bug where a quota skipped by a "match" condition (so it never gets an entry in the
// rateLimitKeysKey map) still had its streaming cost charged at end-of-stream — against an
// empty-string key, since the map lookup for a missing quota name silently returns "". That
// empty key is not private: apiname/apiversion/cel components can legitimately produce ""
// for an unrelated quota, so the phantom charge could land on a real, unrelated bucket.
// finalizeAndConsumeStreamingCosts must treat an empty looked-up key the same as "this quota
// was never assigned a key" and skip consumption entirely, matching the guard already used
// by the other three quotaKeys consumers (OnResponseHeaders cost extraction, the streaming
// availability snapshot, and OnResponseBody cost extraction).
func TestOnResponseBodyChunk_MatchSkippedQuota_NoPhantomConsumption(t *testing.T) {
	lim := &fakeLimiter{}
	ce := NewCostExtractor(CostExtractionConfig{
		Enabled: true,
		Default: 1,
		Sources: []CostSource{{Type: CostSourceResponseBody, JSONPath: "$.usage.total_tokens", Multiplier: 1}},
	})
	p := &RateLimitPolicy{
		quotas: []QuotaRuntime{{
			Name: "guest-tokens", Limiter: lim,
			Limits: []LimitConfig{{Limit: 10000, Duration: time.Minute}},
			KeyExtraction: []KeyComponent{
				{Type: "header", Key: "X-App-ID", Match: regexp.MustCompile("^guest-.*$")},
			},
			CostExtractor:         ce,
			CostExtractionEnabled: true,
		}},
		routeName: "route-chatbot",
	}

	// Simulates a match-skipped quota: the request phase never reached
	// quotaKeys[quotaName] = key for "guest-tokens" (its match didn't apply), so no entry
	// exists here — exactly what a real skip produces, not something contrived for the test.
	meta := map[string]interface{}{
		rateLimitKeysKey: map[string]string{},
	}
	respCtx := newResponseStreamCtx(nil, nil, meta, 200)

	sendChunks(t, p, respCtx, [][]byte{
		[]byte("data: {\"usage\":{\"total_tokens\":800}}\n"),
	})

	if lim.consumeNCalls != 0 {
		t.Fatalf("expected ConsumeN not called for a match-skipped quota, got %d calls (lastKey=%q, lastCost=%d)",
			lim.consumeNCalls, lim.lastKey, lim.lastCost)
	}
}

// TestOnResponseBodyChunk_PresentEmptyKey_StillConsumes guards against a stricter-but-wrong
// fix for the phantom-consumption bug above: a quota that was NOT skipped, and whose
// keyExtraction (e.g. "apiname" on an API with no name) legitimately produced an empty
// string, has a real entry in quotaKeys ("guest-tokens": "") — present, just empty. Unlike
// the absent-key case, this quota's streaming cost must still be consumed; the guard must
// distinguish "never recorded" from "recorded as empty" using the map's ok flag, not a
// key == "" check, which would incorrectly treat both the same way.
func TestOnResponseBodyChunk_PresentEmptyKey_StillConsumes(t *testing.T) {
	lim := &fakeLimiter{}
	ce := NewCostExtractor(CostExtractionConfig{
		Enabled: true,
		Default: 1,
		Sources: []CostSource{{Type: CostSourceResponseBody, JSONPath: "$.usage.total_tokens", Multiplier: 1}},
	})
	p := &RateLimitPolicy{
		quotas: []QuotaRuntime{{
			Name: "guest-tokens", Limiter: lim,
			Limits:                []LimitConfig{{Limit: 10000, Duration: time.Minute}},
			KeyExtraction:         []KeyComponent{{Type: "apiname"}},
			CostExtractor:         ce,
			CostExtractionEnabled: true,
		}},
		routeName: "route-chatbot",
	}

	// Present entry with an empty value — the quota WAS processed (e.g. apiname was unset),
	// not skipped by match. This must not be confused with an absent entry.
	meta := map[string]interface{}{
		rateLimitKeysKey: map[string]string{"guest-tokens": ""},
	}
	respCtx := newResponseStreamCtx(nil, nil, meta, 200)

	sendChunks(t, p, respCtx, [][]byte{
		[]byte("data: {\"usage\":{\"total_tokens\":800}}\n"),
	})

	if lim.consumeNCalls != 1 {
		t.Fatalf("expected ConsumeN called once for a present-but-empty key, got %d calls", lim.consumeNCalls)
	}
	if lim.lastCost != 800 {
		t.Fatalf("expected cost=800, got %d", lim.lastCost)
	}
}

// clearCaches resets all global caches for test isolation.
func clearCaches() {
	globalLimiterCache.mu.Lock()
	defer globalLimiterCache.mu.Unlock()
	globalLimiterCache.byQuotaKey = make(map[string]*limiterEntry)
	globalLimiterCache.quotaKeysByBaseKey = make(map[string]map[string]struct{})
}

// getSharedQuotaRefCount retrieves the total reference count across all cached limiters.
func getSharedQuotaRefCount(apiName, quotaName string, limit int64, duration string) int {
	globalLimiterCache.mu.Lock()
	defer globalLimiterCache.mu.Unlock()

	var totalRefCount int
	for _, entry := range globalLimiterCache.byQuotaKey {
		if entry.refCount > 0 {
			totalRefCount += entry.refCount
		}
	}
	return totalRefCount
}

// getLimiterRefCountByInstance checks how many routes are referencing a specific limiter instance.
func getLimiterRefCountByInstance(targetLimiter interface{}) int {
	globalLimiterCache.mu.Lock()
	defer globalLimiterCache.mu.Unlock()

	count := 0
	for _, entry := range globalLimiterCache.byQuotaKey {
		if entry.lim == targetLimiter {
			count += entry.refCount
		}
	}
	return count
}

func TestParseKeyExtraction_MatchField(t *testing.T) {
	t.Run("valid regex match is parsed and compiled", func(t *testing.T) {
		raw := []interface{}{
			map[string]interface{}{
				"type": "header",
				"key":  "X-App-ID",
				"match": map[string]interface{}{
					"type":  "regex",
					"value": "^(guest-.*|channel-partner)$",
				},
			},
		}
		comps, err := parseKeyExtraction(raw)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if comps[0].Match == nil {
			t.Fatalf("expected compiled Match regexp, got nil")
		}
		if comps[0].MatchType != "regex" || comps[0].MatchValue != "^(guest-.*|channel-partner)$" {
			t.Fatalf("expected MatchType/MatchValue to be recorded, got %q/%q", comps[0].MatchType, comps[0].MatchValue)
		}
		if !comps[0].Match.MatchString("guest-42") || !comps[0].Match.MatchString("channel-partner") {
			t.Fatalf("expected compiled regex to match guest-42 and channel-partner")
		}
		if comps[0].Match.MatchString("internal-app-1") {
			t.Fatalf("expected compiled regex to not match internal-app-1")
		}
	})

	t.Run("no match field leaves Match nil", func(t *testing.T) {
		raw := []interface{}{
			map[string]interface{}{"type": "header", "key": "X-App-ID"},
		}
		comps, err := parseKeyExtraction(raw)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if comps[0].Match != nil {
			t.Fatalf("expected nil Match when not configured")
		}
	})

	t.Run("invalid regex is rejected at config load", func(t *testing.T) {
		raw := []interface{}{
			map[string]interface{}{
				"type": "header",
				"key":  "X-App-ID",
				"match": map[string]interface{}{
					"type":  "regex",
					"value": "(unclosed",
				},
			},
		}
		_, err := parseKeyExtraction(raw)
		if err == nil || !strings.Contains(err.Error(), "not a valid regex") {
			t.Fatalf("expected invalid regex error, got %v", err)
		}
	})

	t.Run("missing match.type is rejected", func(t *testing.T) {
		raw := []interface{}{
			map[string]interface{}{
				"type":  "header",
				"key":   "X-App-ID",
				"match": map[string]interface{}{"value": "guest-.*"},
			},
		}
		_, err := parseKeyExtraction(raw)
		if err == nil || !strings.Contains(err.Error(), "match.type is required") {
			t.Fatalf("expected match.type required error, got %v", err)
		}
	})

	t.Run("missing match.value is rejected", func(t *testing.T) {
		raw := []interface{}{
			map[string]interface{}{
				"type":  "header",
				"key":   "X-App-ID",
				"match": map[string]interface{}{"type": "regex"},
			},
		}
		_, err := parseKeyExtraction(raw)
		if err == nil || !strings.Contains(err.Error(), "match.value is required") {
			t.Fatalf("expected match.value required error, got %v", err)
		}
	})

	t.Run("unsupported match.type is rejected", func(t *testing.T) {
		raw := []interface{}{
			map[string]interface{}{
				"type": "header",
				"key":  "X-App-ID",
				"match": map[string]interface{}{
					"type":  "glob",
					"value": "guest-*",
				},
			},
		}
		_, err := parseKeyExtraction(raw)
		if err == nil || !strings.Contains(err.Error(), "not supported") {
			t.Fatalf("expected unsupported match type error, got %v", err)
		}
	})

	t.Run("match is not an object is rejected", func(t *testing.T) {
		raw := []interface{}{
			map[string]interface{}{"type": "header", "key": "X-App-ID", "match": "regex"},
		}
		_, err := parseKeyExtraction(raw)
		if err == nil || !strings.Contains(err.Error(), "match must be an object") {
			t.Fatalf("expected match object type error, got %v", err)
		}
	})
}

func TestQuotaAppliesFromHeaderCtx(t *testing.T) {
	p := &RateLimitPolicy{routeName: "route-main"}

	t.Run("matching header value applies the quota", func(t *testing.T) {
		q := &QuotaRuntime{KeyExtraction: []KeyComponent{{Type: "header", Key: "X-App-ID", Match: regexp.MustCompile("^(guest-.*|channel-partner)$")}}}
		hctx := newRequestHeaderCtx(map[string][]string{"x-app-id": {"guest-42"}}, nil)
		if !p.quotaAppliesFromHeaderCtx(hctx, q) {
			t.Fatalf("expected quota to apply for matching value guest-42")
		}
	})

	t.Run("non-matching header value skips the quota", func(t *testing.T) {
		q := &QuotaRuntime{KeyExtraction: []KeyComponent{{Type: "header", Key: "X-App-ID", Match: regexp.MustCompile("^(guest-.*|channel-partner)$")}}}
		hctx := newRequestHeaderCtx(map[string][]string{"x-app-id": {"internal-app-1"}}, nil)
		if p.quotaAppliesFromHeaderCtx(hctx, q) {
			t.Fatalf("expected quota to be skipped for non-matching value internal-app-1")
		}
	})

	t.Run("component without match always applies", func(t *testing.T) {
		q := &QuotaRuntime{KeyExtraction: []KeyComponent{{Type: "header", Key: "X-App-ID"}}}
		hctx := newRequestHeaderCtx(map[string][]string{"x-app-id": {"anything"}}, nil)
		if !p.quotaAppliesFromHeaderCtx(hctx, q) {
			t.Fatalf("expected quota with no match condition to always apply")
		}
	})

	t.Run("multiple matched components require all to match (AND)", func(t *testing.T) {
		q := &QuotaRuntime{KeyExtraction: []KeyComponent{
			{Type: "header", Key: "X-App-ID", Match: regexp.MustCompile("^guest-.*$")},
			{Type: "apiname", Match: regexp.MustCompile("^petstore$")},
		}}
		matching := newRequestHeaderCtx(map[string][]string{"x-app-id": {"guest-1"}}, nil)
		matching.APIName = "petstore"
		if !p.quotaAppliesFromHeaderCtx(matching, q) {
			t.Fatalf("expected quota to apply when both components match")
		}

		partial := newRequestHeaderCtx(map[string][]string{"x-app-id": {"guest-1"}}, nil)
		partial.APIName = "other-api"
		if p.quotaAppliesFromHeaderCtx(partial, q) {
			t.Fatalf("expected quota to be skipped when only one of two matched components matches")
		}
	})
}

func TestQuotaAppliesFromHeaderCtx_MetadataType(t *testing.T) {
	// match is applied identically regardless of keyExtraction type — this locks in that
	// contract for "metadata" specifically, since that's how a value set by an earlier
	// policy in the chain (e.g. subscription-validation's x-wso2-application-id) reaches
	// this policy, not necessarily a raw request header.
	p := &RateLimitPolicy{routeName: "route-main"}
	q := &QuotaRuntime{KeyExtraction: []KeyComponent{
		{Type: "metadata", Key: "x-wso2-application-id", Match: regexp.MustCompile("^(guest-.*|channel-partner)$")},
	}}

	t.Run("matching metadata value applies the quota", func(t *testing.T) {
		hctx := newRequestHeaderCtx(nil, map[string]interface{}{"x-wso2-application-id": "guest-42"})
		if !p.quotaAppliesFromHeaderCtx(hctx, q) {
			t.Fatalf("expected quota to apply for matching metadata value guest-42")
		}
	})

	t.Run("non-matching metadata value skips the quota", func(t *testing.T) {
		hctx := newRequestHeaderCtx(nil, map[string]interface{}{"x-wso2-application-id": "internal-app-1"})
		if p.quotaAppliesFromHeaderCtx(hctx, q) {
			t.Fatalf("expected quota to be skipped for non-matching metadata value internal-app-1")
		}
	})
}

func TestMatchCondition_SkipsQuotaWhenNotMatching_MetadataType(t *testing.T) {
	basePolicy := func(comp KeyComponent, lim *fakeLimiter) *RateLimitPolicy {
		return &RateLimitPolicy{
			quotas: []QuotaRuntime{{
				Name:          "throttled-apps",
				KeyExtraction: []KeyComponent{comp},
				Limiter:       lim,
				Limits:        []LimitConfig{{Limit: 10, Duration: time.Minute}},
			}},
			routeName:      "route-main",
			statusCode:     429,
			responseBody:   `{"error":"limited"}`,
			responseFormat: "json",
			backend:        "memory",
		}
	}
	comp := KeyComponent{Type: "metadata", Key: "x-wso2-application-id", Match: regexp.MustCompile("^(guest-.*|channel-partner)$")}

	t.Run("matching metadata request is counted and enforced", func(t *testing.T) {
		lim := &fakeLimiter{allowNFn: func(ctx context.Context, key string, n int64) (*limiter.Result, error) {
			return newResult(true, 10, 9, 0, time.Minute), nil
		}}
		p := basePolicy(comp, lim)
		hctx := newRequestHeaderCtx(nil, map[string]interface{}{"x-wso2-application-id": "guest-42"})

		action := p.OnRequestHeaders(context.Background(), hctx, nil)
		if _, ok := action.(policy.UpstreamRequestHeaderModifications); !ok {
			t.Fatalf("expected UpstreamRequestHeaderModifications, got %T", action)
		}
		if lim.allowNCalls != 1 {
			t.Fatalf("expected AllowN called once for matching request, got %d calls", lim.allowNCalls)
		}
	})

	t.Run("non-matching metadata request bypasses the quota entirely", func(t *testing.T) {
		lim := &fakeLimiter{allowNFn: func(ctx context.Context, key string, n int64) (*limiter.Result, error) {
			return newResult(false, 10, 0, 5*time.Second, time.Minute), nil
		}}
		p := basePolicy(comp, lim)
		hctx := newRequestHeaderCtx(nil, map[string]interface{}{"x-wso2-application-id": "internal-app-1"})

		action := p.OnRequestHeaders(context.Background(), hctx, nil)
		if _, ok := action.(policy.UpstreamRequestHeaderModifications); !ok {
			t.Fatalf("expected non-matching request to be allowed through, got %T", action)
		}
		if lim.allowNCalls != 0 {
			t.Fatalf("expected AllowN to never be called for a non-matching request, got %d calls", lim.allowNCalls)
		}
	})
}

func TestMatchCondition_SkipsQuotaWhenNotMatching(t *testing.T) {
	basePolicy := func(comp KeyComponent, lim *fakeLimiter) *RateLimitPolicy {
		return &RateLimitPolicy{
			quotas: []QuotaRuntime{{
				Name:          "throttled-apps",
				KeyExtraction: []KeyComponent{comp},
				Limiter:       lim,
				Limits:        []LimitConfig{{Limit: 10, Duration: time.Minute}},
			}},
			routeName:      "route-main",
			statusCode:     429,
			responseBody:   `{"error":"limited"}`,
			responseFormat: "json",
			backend:        "memory",
		}
	}
	comp := KeyComponent{Type: "header", Key: "X-App-ID", Match: regexp.MustCompile("^(guest-.*|channel-partner)$")}

	t.Run("matching request is counted and enforced", func(t *testing.T) {
		lim := &fakeLimiter{allowNFn: func(ctx context.Context, key string, n int64) (*limiter.Result, error) {
			return newResult(true, 10, 9, 0, time.Minute), nil
		}}
		p := basePolicy(comp, lim)
		hctx := newRequestHeaderCtx(map[string][]string{"x-app-id": {"guest-42"}}, nil)

		action := p.OnRequestHeaders(context.Background(), hctx, nil)
		if _, ok := action.(policy.UpstreamRequestHeaderModifications); !ok {
			t.Fatalf("expected UpstreamRequestHeaderModifications, got %T", action)
		}
		if lim.allowNCalls != 1 {
			t.Fatalf("expected AllowN called once for matching request, got %d calls", lim.allowNCalls)
		}
	})

	t.Run("non-matching request bypasses the quota entirely", func(t *testing.T) {
		lim := &fakeLimiter{allowNFn: func(ctx context.Context, key string, n int64) (*limiter.Result, error) {
			return newResult(false, 10, 0, 5*time.Second, time.Minute), nil
		}}
		p := basePolicy(comp, lim)
		hctx := newRequestHeaderCtx(map[string][]string{"x-app-id": {"internal-app-1"}}, nil)

		action := p.OnRequestHeaders(context.Background(), hctx, nil)
		if _, ok := action.(policy.UpstreamRequestHeaderModifications); !ok {
			t.Fatalf("expected non-matching request to be allowed through, got %T", action)
		}
		if lim.allowNCalls != 0 {
			t.Fatalf("expected AllowN to never be called for a non-matching request, got %d calls", lim.allowNCalls)
		}
	})

	t.Run("non-matching request never blocked even when quota is already exhausted", func(t *testing.T) {
		// The limiter would deny if called at all; the point of this test is that it must
		// never be called for a non-matching request, no matter how exhausted the quota is.
		lim := &fakeLimiter{allowNFn: func(ctx context.Context, key string, n int64) (*limiter.Result, error) {
			return newResult(false, 10, 0, 5*time.Second, time.Minute), nil
		}}
		p := basePolicy(comp, lim)
		for i := 0; i < 5; i++ {
			hctx := newRequestHeaderCtx(map[string][]string{"x-app-id": {"internal-app-1"}}, nil)
			action := p.OnRequestHeaders(context.Background(), hctx, nil)
			if _, ok := action.(policy.UpstreamRequestHeaderModifications); !ok {
				t.Fatalf("expected non-matching request %d to be allowed through, got %T", i, action)
			}
		}
		if lim.allowNCalls != 0 {
			t.Fatalf("expected AllowN never called across repeated non-matching requests, got %d calls", lim.allowNCalls)
		}
	})
}

func TestGetQuotaCacheKey_ChangesWithMatchValue(t *testing.T) {
	base := "base-cache-key"
	qNoMatch := &QuotaRuntime{
		Name:          "q1",
		Limits:        []LimitConfig{{Limit: 10, Duration: time.Minute}},
		KeyExtraction: []KeyComponent{{Type: "header", Key: "X-App-ID"}},
	}
	qWithMatch := &QuotaRuntime{
		Name:          "q1",
		Limits:        []LimitConfig{{Limit: 10, Duration: time.Minute}},
		KeyExtraction: []KeyComponent{{Type: "header", Key: "X-App-ID", MatchType: "regex", MatchValue: "^guest-.*$"}},
	}
	qWithDifferentMatch := &QuotaRuntime{
		Name:          "q1",
		Limits:        []LimitConfig{{Limit: 10, Duration: time.Minute}},
		KeyExtraction: []KeyComponent{{Type: "header", Key: "X-App-ID", MatchType: "regex", MatchValue: "^channel-partner$"}},
	}

	keyNoMatch := getQuotaCacheKey(base, "petstore", qNoMatch, 0)
	keyWithMatch := getQuotaCacheKey(base, "petstore", qWithMatch, 0)
	keyWithDifferentMatch := getQuotaCacheKey(base, "petstore", qWithDifferentMatch, 0)

	if keyNoMatch == keyWithMatch {
		t.Fatalf("expected cache key to change when a match condition is added")
	}
	if keyWithMatch == keyWithDifferentMatch {
		t.Fatalf("expected cache key to change when the match value changes, so a config edit doesn't reuse a stale limiter")
	}
}

// TestThrottleErrorCodeFollowsAttachmentLevel pins the code chosen per attachment level. A
func TestThrottleErrorCodeFollowsAttachmentLevel(t *testing.T) {
	tests := []struct {
		name     string
		level    policy.Level
		wantCode string
	}{
		{name: "route level is a resource throttle", level: policy.LevelRoute, wantCode: policy.FaultCodeThrottledResource},
		{name: "api level is an api throttle", level: policy.LevelAPI, wantCode: policy.FaultCodeThrottledAPI},
		{name: "unset level defaults to api", level: "", wantCode: policy.FaultCodeThrottledAPI},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &RateLimitPolicy{attachedTo: tt.level}
			if got := p.throttleErrorCode(); got != tt.wantCode {
				t.Fatalf("expected %q, got %q", tt.wantCode, got)
			}
		})
	}
}

// TestThrottleRejectionDeclaresFault exercises the real rejection path end to end: exhaust
// a one-request quota and check the second request declares the fault.
func TestThrottleRejectionDeclaresFault(t *testing.T) {
	params := map[string]interface{}{
		"backend":   "memory",
		"algorithm": "fixed-window",
		"quotas": []interface{}{
			map[string]interface{}{
				"name": "tight",
				"limits": []interface{}{
					map[string]interface{}{"limit": float64(1), "duration": "1m"},
				},
			},
		},
	}
	p, err := GetPolicy(policy.PolicyMetadata{
		RouteName:  "r1",
		APIName:    "petstore",
		APIVersion: "v1",
		AttachedTo: policy.LevelRoute,
	}, params)
	if err != nil {
		t.Fatalf("GetPolicy failed: %v", err)
	}
	rl := p.(*RateLimitPolicy)

	first := rl.OnRequestHeaders(context.Background(), newRequestHeaderCtx(nil, nil), params)
	if resp, ok := first.(policy.ImmediateResponse); ok {
		t.Fatalf("expected the first request to pass, got status %d", resp.StatusCode)
	}

	second := rl.OnRequestHeaders(context.Background(), newRequestHeaderCtx(nil, nil), params)
	resp := assertImmediateResponse(t, second, rl.statusCode)
	if resp.Fault.Code != policy.FaultCodeThrottledResource {
		t.Fatalf("expected Error.Code=%q for a route-attached policy, got %q",
			policy.FaultCodeThrottledResource, resp.Fault.Code)
	}
	if resp.Fault.Direction != policy.DirectionRequest {
		t.Fatalf("expected Error.Direction=%q, got %q", policy.DirectionRequest, resp.Fault.Direction)
	}
	if resp.Fault.Description == "" {
		t.Fatalf("expected Error.Description to name the quota that tripped")
	}
}

// TestResponseHeaderDecorationIsNotAFault covers the response path: this policy publishes
// rate-limit headers on every response, including successful ones. Marking that a fault
// would notify on every request that was NOT throttled, which is the mistake the zero value
// of IsFault exists to prevent.
func TestResponseHeaderDecorationIsNotAFault(t *testing.T) {
	params := basicQuotaParams()
	p, err := GetPolicy(policy.PolicyMetadata{RouteName: "r1", APIName: "petstore", APIVersion: "v1"}, params)
	if err != nil {
		t.Fatalf("GetPolicy failed: %v", err)
	}
	rl := p.(*RateLimitPolicy)

	reqCtx := newRequestHeaderCtx(nil, nil)
	if action := rl.OnRequestHeaders(context.Background(), reqCtx, params); action == nil {
		t.Fatalf("expected the request to pass under a limit of 10")
	}

	respCtx := newResponseCtx(nil, nil, reqCtx.SharedContext.Metadata, 200)
	action := rl.OnResponseBody(context.Background(), respCtx, params)
	if action == nil {
		return
	}
	mods, ok := action.(policy.DownstreamResponseModifications)
	if !ok {
		t.Fatalf("expected DownstreamResponseModifications, got %T", action)
	}
	if mods.IsFault {
		t.Fatalf("publishing rate-limit headers on a healthy response must not be a fault")
	}
	if mods.Fault != nil {
		t.Fatalf("publishing rate-limit headers must not describe an error")
	}
}
