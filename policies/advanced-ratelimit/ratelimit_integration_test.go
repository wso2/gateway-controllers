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
	"strconv"
	"strings"
	"testing"
	"time"

	policy "github.com/wso2/api-platform/sdk/gateway/policy/v1alpha"
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
	return resp
}

func assertUpstreamResponseHeaders(t *testing.T, action interface{}, required map[string]string) policy.UpstreamResponseModifications {
	t.Helper()
	mods, ok := action.(policy.UpstreamResponseModifications)
	if !ok {
		t.Fatalf("expected policy.UpstreamResponseModifications, got %T", action)
	}
	for k, v := range required {
		if mods.SetHeaders[k] != v {
			t.Fatalf("expected header %s=%q, got %q", k, v, mods.SetHeaders[k])
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
			name:        "response body source",
			quotas:      []QuotaRuntime{mkQuota(true, []CostSource{{Type: CostSourceResponseBody, JSONPath: "$.usage.total"}})},
			wantReqBody: policy.BodyModeSkip,
			wantResBody: policy.BodyModeBuffer,
		},
		{
			name:        "mixed body sources",
			quotas:      []QuotaRuntime{mkQuota(true, []CostSource{{Type: CostSourceRequestBody, JSONPath: "$.in"}, {Type: CostSourceResponseBody, JSONPath: "$.out"}})},
			wantReqBody: policy.BodyModeBuffer,
			wantResBody: policy.BodyModeBuffer,
		},
		{
			name:        "configured but effectively disabled",
			quotas:      []QuotaRuntime{mkQuota(false, []CostSource{{Type: CostSourceResponseBody, JSONPath: "$.x"}})},
			wantReqBody: policy.BodyModeSkip,
			wantResBody: policy.BodyModeSkip,
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
		if got := p.extractIPAddress(ctx); got != "10.1.1.1" {
			t.Fatalf("expected first x-forwarded-for IP, got %q", got)
		}

		onlyXReal := newRequestCtx(map[string][]string{"x-real-ip": {"10.8.8.8"}}, nil)
		if got := p.extractIPAddress(onlyXReal); got != "10.8.8.8" {
			t.Fatalf("expected x-real-ip fallback, got %q", got)
		}

		none := newRequestCtx(nil, nil)
		if got := p.extractIPAddress(none); got != "unknown" {
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
		ctx := newRequestCtx(nil, nil)

		action := p.OnRequest(ctx, nil)
		if _, ok := action.(policy.UpstreamRequestModifications); !ok {
			t.Fatalf("expected UpstreamRequestModifications, got %T", action)
		}
		if _, ok := ctx.Metadata[rateLimitResultKey]; !ok {
			t.Fatalf("expected %s metadata to be present", rateLimitResultKey)
		}
		if _, ok := ctx.Metadata[rateLimitKeysKey]; !ok {
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
		action := p.OnRequest(newRequestCtx(nil, nil), nil)
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
		action := p.OnRequest(newRequestCtx(nil, nil), nil)
		_ = assertImmediateResponse(t, action, 429)
	})

	t.Run("standard limiter error fail-open for redis", func(t *testing.T) {
		lim := &fakeLimiter{allowNErr: errors.New("redis down")}
		p := basePolicy([]QuotaRuntime{{Name: "q1", KeyExtraction: []KeyComponent{{Type: "constant", Key: "k1"}}, Limiter: lim, Limits: []LimitConfig{{Limit: 10, Duration: time.Minute}}}})
		p.backend = "redis"
		p.redisFailOpen = true
		ctx := newRequestCtx(nil, nil)

		action := p.OnRequest(ctx, nil)
		if _, ok := action.(policy.UpstreamRequestModifications); !ok {
			t.Fatalf("expected UpstreamRequestModifications, got %T", action)
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
		action := p.OnRequest(newRequestCtx(nil, nil), nil)
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
		ctx := newRequestCtx(map[string][]string{"x-cost": {"7"}}, nil)

		_ = p.OnRequest(ctx, nil)
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
		ctx := newRequestCtx(map[string][]string{"x-cost": {"-5"}}, nil)

		_ = p.OnRequest(ctx, nil)
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
		_ = p.OnRequest(newRequestCtx(nil, nil), nil)
		if lim.lastCost != 5 {
			t.Fatalf("expected default request cost 5, got %d", lim.lastCost)
		}
	})

	t.Run("response phase pre-check available stores placeholder", func(t *testing.T) {
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
		ctx := newRequestCtx(nil, nil)

		action := p.OnRequest(ctx, nil)
		if _, ok := action.(policy.UpstreamRequestModifications); !ok {
			t.Fatalf("expected upstream action, got %T", action)
		}
		results, ok := ctx.Metadata[rateLimitResultKey].([]quotaResult)
		if !ok || len(results) != 1 {
			t.Fatalf("expected one stored quota result, got %#v", ctx.Metadata[rateLimitResultKey])
		}
		if results[0].Result != nil {
			t.Fatal("expected placeholder nil result for response-phase extraction")
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
		resp := assertImmediateResponse(t, p.OnRequest(newRequestCtx(nil, nil), nil), 429)
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
		if _, ok := p.OnRequest(newRequestCtx(nil, nil), nil).(policy.UpstreamRequestModifications); !ok {
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
		_ = assertImmediateResponse(t, p.OnRequest(newRequestCtx(nil, nil), nil), 429)
	})

	t.Run("mixed quotas store both result and placeholder", func(t *testing.T) {
		limStandard := &fakeLimiter{allowNFn: func(ctx context.Context, key string, n int64) (*limiter.Result, error) {
			return newResult(true, 10, 9, 0, time.Minute), nil
		}}
		limResponse := &fakeLimiter{getAvailableFn: func(ctx context.Context, key string) (int64, error) { return 3, nil }}
		ce := NewCostExtractor(CostExtractionConfig{Enabled: true, Default: 1, Sources: []CostSource{{Type: CostSourceResponseHeader, Key: "x-usage", Multiplier: 1}}})

		p := basePolicy([]QuotaRuntime{
			{Name: "standard", KeyExtraction: []KeyComponent{{Type: "constant", Key: "k1"}}, Limiter: limStandard, Limits: []LimitConfig{{Limit: 10, Duration: time.Minute}}},
			{Name: "post", KeyExtraction: []KeyComponent{{Type: "constant", Key: "k2"}}, Limiter: limResponse, Limits: []LimitConfig{{Limit: 10, Duration: time.Minute}}, CostExtractor: ce, CostExtractionEnabled: true},
		})
		ctx := newRequestCtx(nil, nil)
		_ = p.OnRequest(ctx, nil)
		results, ok := ctx.Metadata[rateLimitResultKey].([]quotaResult)
		if !ok || len(results) != 2 {
			t.Fatalf("expected 2 stored quota results, got %#v", ctx.Metadata[rateLimitResultKey])
		}
		if results[0].Result == nil || results[1].Result != nil {
			t.Fatalf("expected first result non-nil and second nil placeholder, got %+v", results)
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
		if action := p.OnResponse(newResponseCtx(nil, nil, nil, 200), nil); action != nil {
			t.Fatalf("expected nil action, got %T", action)
		}
	})

	t.Run("type-mismatched metadata safely ignored", func(t *testing.T) {
		p := mkPolicy(nil)
		ctx := newResponseCtx(nil, nil, map[string]interface{}{
			rateLimitResultKey: "bad",
			rateLimitKeysKey:   123,
		}, 200)
		if action := p.OnResponse(ctx, nil); action != nil {
			t.Fatalf("expected nil action, got %T", action)
		}
	})

	t.Run("standard quota uses stored request result", func(t *testing.T) {
		lim := &fakeLimiter{}
		p := mkPolicy([]QuotaRuntime{{Name: "q1", Limiter: lim, Limits: []LimitConfig{{Limit: 10, Duration: time.Minute}}}})
		ctx := newResponseCtx(nil, nil, map[string]interface{}{
			rateLimitResultKey: []quotaResult{{QuotaName: "q1", Key: "k1", Duration: time.Minute, Result: newResult(true, 10, 7, 0, time.Minute)}},
			rateLimitKeysKey:   map[string]string{"q1": "k1"},
		}, 200)

		action := p.OnResponse(ctx, nil)
		mods := assertUpstreamResponseHeaders(t, action, map[string]string{"x-ratelimit-limit": "10", "x-ratelimit-remaining": "7"})
		if mods.SetHeaders["ratelimit-policy"] == "" || mods.SetHeaders["ratelimit"] == "" {
			t.Fatalf("expected IETF headers to be present, got %+v", mods.SetHeaders)
		}
	})

	t.Run("response phase missing key skips quota without panic", func(t *testing.T) {
		lim := &fakeLimiter{}
		ce := NewCostExtractor(CostExtractionConfig{Enabled: true, Default: 1, Sources: []CostSource{{Type: CostSourceResponseHeader, Key: "x-cost", Multiplier: 1}}})
		p := mkPolicy([]QuotaRuntime{{Name: "post", Limiter: lim, Limits: []LimitConfig{{Limit: 10, Duration: time.Minute}}, CostExtractor: ce, CostExtractionEnabled: true}})
		ctx := newResponseCtx(nil, map[string][]string{"x-cost": {"2"}}, map[string]interface{}{
			rateLimitResultKey: []quotaResult{},
			rateLimitKeysKey:   map[string]string{},
		}, 200)
		if action := p.OnResponse(ctx, nil); action != nil {
			t.Fatalf("expected nil action when key missing, got %T", action)
		}
	})

	t.Run("negative response cost clamps to zero and uses stored result", func(t *testing.T) {
		lim := &fakeLimiter{}
		ce := NewCostExtractor(CostExtractionConfig{Enabled: true, Default: 1, Sources: []CostSource{{Type: CostSourceResponseHeader, Key: "x-cost", Multiplier: 1}}})
		p := mkPolicy([]QuotaRuntime{{Name: "post", Limiter: lim, Limits: []LimitConfig{{Limit: 10, Duration: time.Minute}}, CostExtractor: ce, CostExtractionEnabled: true}})
		ctx := newResponseCtx(nil, map[string][]string{"x-cost": {"-9"}}, map[string]interface{}{
			rateLimitResultKey: []quotaResult{{QuotaName: "post", Key: "k1", Duration: time.Minute, Result: newResult(true, 10, 8, 0, time.Minute)}},
			rateLimitKeysKey:   map[string]string{"post": "k1"},
		}, 200)

		action := p.OnResponse(ctx, nil)
		mods := assertUpstreamResponseHeaders(t, action, map[string]string{"x-ratelimit-remaining": "8"})
		if lim.consumeNCalls != 0 {
			t.Fatalf("expected no ConsumeN call for clamped zero cost")
		}
		if mods.SetHeaders["ratelimit"] == "" {
			t.Fatalf("expected ratelimit header, got %+v", mods.SetHeaders)
		}
	})

	t.Run("zero response cost without stored result uses GetAvailable", func(t *testing.T) {
		lim := &fakeLimiter{getAvailableFn: func(ctx context.Context, key string) (int64, error) { return 3, nil }}
		ce := NewCostExtractor(CostExtractionConfig{Enabled: true, Default: 0, Sources: []CostSource{{Type: CostSourceResponseHeader, Key: "x-cost", Multiplier: 1}}})
		p := mkPolicy([]QuotaRuntime{{Name: "post", Limiter: lim, Limits: []LimitConfig{{Limit: 10, Duration: time.Minute}}, CostExtractor: ce, CostExtractionEnabled: true}})
		ctx := newResponseCtx(nil, map[string][]string{"x-cost": {"0"}}, map[string]interface{}{
			rateLimitResultKey: []quotaResult{},
			rateLimitKeysKey:   map[string]string{"post": "k1"},
		}, 200)

		action := p.OnResponse(ctx, nil)
		mods := assertUpstreamResponseHeaders(t, action, map[string]string{"x-ratelimit-limit": "10", "x-ratelimit-remaining": "3"})
		if mods.SetHeaders["ratelimit-policy"] == "" {
			t.Fatalf("expected ratelimit-policy header")
		}
	})

	t.Run("zero response cost synthetic path with GetAvailable error skips quota", func(t *testing.T) {
		lim := &fakeLimiter{getAvailableFn: func(ctx context.Context, key string) (int64, error) { return 0, errors.New("boom") }}
		ce := NewCostExtractor(CostExtractionConfig{Enabled: true, Default: 0, Sources: []CostSource{{Type: CostSourceResponseHeader, Key: "x-cost", Multiplier: 1}}})
		p := mkPolicy([]QuotaRuntime{{Name: "post", Limiter: lim, Limits: []LimitConfig{{Limit: 10, Duration: time.Minute}}, CostExtractor: ce, CostExtractionEnabled: true}})
		ctx := newResponseCtx(nil, map[string][]string{"x-cost": {"0"}}, map[string]interface{}{
			rateLimitResultKey: []quotaResult{},
			rateLimitKeysKey:   map[string]string{"post": "k1"},
		}, 200)
		if action := p.OnResponse(ctx, nil); action != nil {
			t.Fatalf("expected nil action, got %T", action)
		}
	})

	t.Run("positive response cost consumes via ConsumeN", func(t *testing.T) {
		lim := &fakeLimiter{consumeNFn: func(ctx context.Context, key string, n int64) (*limiter.Result, error) {
			return newResult(true, 10, 6, 0, time.Minute), nil
		}}
		ce := NewCostExtractor(CostExtractionConfig{Enabled: true, Default: 1, Sources: []CostSource{{Type: CostSourceResponseHeader, Key: "x-cost", Multiplier: 1}}})
		p := mkPolicy([]QuotaRuntime{{Name: "post", Limiter: lim, Limits: []LimitConfig{{Limit: 10, Duration: time.Minute}}, CostExtractor: ce, CostExtractionEnabled: true}})
		ctx := newResponseCtx(nil, map[string][]string{"x-cost": {"4"}}, map[string]interface{}{
			rateLimitResultKey: []quotaResult{},
			rateLimitKeysKey:   map[string]string{"post": "k1"},
		}, 200)

		action := p.OnResponse(ctx, nil)
		_ = assertUpstreamResponseHeaders(t, action, map[string]string{"x-ratelimit-remaining": "6"})
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
		ctx := newResponseCtx(nil, map[string][]string{"x-cost": {"7"}}, map[string]interface{}{
			rateLimitResultKey: []quotaResult{{QuotaName: "standard", Key: "s1", Duration: time.Minute, Result: newResult(true, 10, 9, 0, time.Minute)}},
			rateLimitKeysKey:   map[string]string{"post": "p1", "standard": "s1"},
		}, 200)
		action := p.OnResponse(ctx, nil)
		_ = assertUpstreamResponseHeaders(t, action, map[string]string{"x-ratelimit-limit": "10", "x-ratelimit-remaining": "9"})
	})

	t.Run("consume error fail-closed currently skipped and returns nil when only quota", func(t *testing.T) {
		lim := &fakeLimiter{consumeNFn: func(ctx context.Context, key string, n int64) (*limiter.Result, error) {
			return nil, errors.New("hard error")
		}}
		ce := NewCostExtractor(CostExtractionConfig{Enabled: true, Default: 1, Sources: []CostSource{{Type: CostSourceResponseHeader, Key: "x-cost", Multiplier: 1}}})
		p := mkPolicy([]QuotaRuntime{{Name: "post", Limiter: lim, Limits: []LimitConfig{{Limit: 10, Duration: time.Minute}}, CostExtractor: ce, CostExtractionEnabled: true}})
		ctx := newResponseCtx(nil, map[string][]string{"x-cost": {"3"}}, map[string]interface{}{
			rateLimitResultKey: []quotaResult{},
			rateLimitKeysKey:   map[string]string{"post": "p1"},
		}, 200)
		if action := p.OnResponse(ctx, nil); action != nil {
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
		ctx := newResponseCtx(nil, map[string][]string{"x-cost": {"4"}}, map[string]interface{}{
			rateLimitResultKey: []quotaResult{{QuotaName: "q1", Key: "k1", Duration: time.Minute, Result: newResult(true, 10, 8, 0, time.Minute)}},
			rateLimitKeysKey:   map[string]string{"q1": "k1", "q2": "k2"},
		}, 200)

		action := p.OnResponse(ctx, nil)
		mods := assertUpstreamResponseHeaders(t, action, map[string]string{})
		if !strings.Contains(mods.SetHeaders["ratelimit-policy"], `"q1"`) || !strings.Contains(mods.SetHeaders["ratelimit-policy"], `"q2"`) {
			t.Fatalf("expected consolidated ratelimit-policy, got %q", mods.SetHeaders["ratelimit-policy"])
		}
		if !strings.Contains(mods.SetHeaders["ratelimit"], `"q1"`) || !strings.Contains(mods.SetHeaders["ratelimit"], `"q2"`) {
			t.Fatalf("expected consolidated ratelimit, got %q", mods.SetHeaders["ratelimit"])
		}
	})

	t.Run("all results nil returns nil", func(t *testing.T) {
		p := mkPolicy([]QuotaRuntime{{Name: "q1"}})
		ctx := newResponseCtx(nil, nil, map[string]interface{}{
			rateLimitResultKey: []quotaResult{{QuotaName: "q1", Result: nil}},
		}, 200)
		if action := p.OnResponse(ctx, nil); action != nil {
			t.Fatalf("expected nil action, got %T", action)
		}
	})
}

func TestHeaderBuildersAndResponseConstruction(t *testing.T) {
	p := &RateLimitPolicy{includeXRL: true, includeIETF: true, includeRetry: true, responseFormat: "json", statusCode: 429, responseBody: "{}"}

	t.Run("buildRateLimitHeaders nil result", func(t *testing.T) {
		headers := p.buildRateLimitHeaders(nil, true)
		if len(headers) != 0 {
			t.Fatalf("expected empty headers for nil result, got %+v", headers)
		}
	})

	t.Run("buildRateLimitHeaders includes toggles", func(t *testing.T) {
		res := &limiter.Result{Limit: 10, Remaining: 5, Reset: time.Now().Add(30 * time.Second), Duration: time.Minute, RetryAfter: 250 * time.Millisecond, Policy: struct{}{}}
		headers := p.buildRateLimitHeaders(res, true)
		if headers["x-ratelimit-limit"] != "10" || headers["x-ratelimit-remaining"] != "5" {
			t.Fatalf("expected X-RateLimit headers, got %+v", headers)
		}
		if headers["ratelimit-limit"] != "10" || headers["ratelimit-remaining"] != "5" {
			t.Fatalf("expected IETF rate limit headers, got %+v", headers)
		}
		if headers["retry-after"] != "1" {
			t.Fatalf("expected retry-after min clamp to 1, got %q", headers["retry-after"])
		}
	})

	t.Run("buildRateLimitHeaders with disabled toggles", func(t *testing.T) {
		p2 := &RateLimitPolicy{includeXRL: false, includeIETF: false, includeRetry: false}
		headers := p2.buildRateLimitHeaders(newResult(true, 10, 5, 10*time.Second, time.Minute), true)
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

	t.Run("buildRateLimitHeaders clamps negative ietf reset to zero", func(t *testing.T) {
		res := &limiter.Result{Limit: 10, Remaining: 5, Reset: time.Now().Add(-2 * time.Second), Duration: time.Minute, Policy: struct{}{}}
		headers := p.buildRateLimitHeaders(res, false)
		if headers["ratelimit-reset"] != "0" {
			t.Fatalf("expected ratelimit-reset=0, got %q", headers["ratelimit-reset"])
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
		k1 := getBaseCacheKey("route1", "api1", "fixed-window", params1)
		k2 := getBaseCacheKey("route1", "api1", "fixed-window", params2)
		if k1 != k2 {
			t.Fatalf("expected deterministic key regardless of map order, got %q vs %q", k1, k2)
		}
		params2["headers"].(map[string]interface{})["includeIETF"] = false
		k3 := getBaseCacheKey("route1", "api1", "fixed-window", params2)
		if k3 == k1 {
			t.Fatalf("expected cache key change when significant params change")
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

func TestBuildRateLimitHeadersRetryAfterConditions(t *testing.T) {
	p := &RateLimitPolicy{includeXRL: true, includeIETF: true, includeRetry: true}
	res := newResult(false, 10, 0, 2*time.Second, time.Minute)

	headers := p.buildRateLimitHeaders(res, false)
	if _, ok := headers["retry-after"]; ok {
		t.Fatal("retry-after should not be set when rateLimited=false")
	}

	p.includeRetry = false
	headers = p.buildRateLimitHeaders(res, true)
	if _, ok := headers["retry-after"]; ok {
		t.Fatal("retry-after should not be set when includeRetry=false")
	}

	p.includeRetry = true
	res.RetryAfter = 0
	headers = p.buildRateLimitHeaders(res, true)
	if _, ok := headers["retry-after"]; ok {
		t.Fatal("retry-after should not be set when RetryAfter<=0")
	}
}

func TestGetMostRestrictiveResult(t *testing.T) {
	p := &RateLimitPolicy{}
	if got := p.getMostRestrictiveResult(nil); got != nil {
		t.Fatalf("expected nil for empty input, got %+v", got)
	}
	if got := p.getMostRestrictiveResult([]*limiter.Result{nil, nil}); got != nil {
		t.Fatalf("expected nil for nil-only input, got %+v", got)
	}

	r1 := newResult(true, 10, 5, 0, time.Minute)
	r2 := newResult(true, 10, 1, 0, time.Minute)
	r3 := newResult(true, 10, 4, 0, time.Minute)
	got := p.getMostRestrictiveResult([]*limiter.Result{r1, r2, r3})
	if got != r2 {
		t.Fatalf("expected result with remaining=1, got remaining=%d", got.Remaining)
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
	_ = p.OnRequest(ctx, nil)
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
