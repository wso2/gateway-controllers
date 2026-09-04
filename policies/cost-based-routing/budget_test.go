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
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package costbasedrouting

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net"
	"os"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
	"github.com/wso2/gateway-controllers/policies/advanced-ratelimit/limiter"
)

// ─── Storage failure handling ────────────────────────────────────────────────

// failingLimiter reports a storage error from every operation. It stands in for
// an unreachable Redis so the fail-open and fail-closed paths can be exercised
// without a flaky network dependency.
type failingLimiter struct {
	queries atomic.Int64
	charges atomic.Int64
}

var errStorageDown = errors.New("storage unavailable")

func (f *failingLimiter) Allow(context.Context, string) (*limiter.Result, error) {
	return nil, errStorageDown
}

func (f *failingLimiter) AllowN(context.Context, string, int64) (*limiter.Result, error) {
	return nil, errStorageDown
}

func (f *failingLimiter) ConsumeOrClampN(context.Context, string, int64) (*limiter.Result, error) {
	return nil, errStorageDown
}

func (f *failingLimiter) ConsumeN(context.Context, string, int64) (*limiter.Result, error) {
	f.charges.Add(1)
	return nil, errStorageDown
}

func (f *failingLimiter) GetAvailable(context.Context, string) (int64, error) {
	f.queries.Add(1)
	return 0, errStorageDown
}

func (f *failingLimiter) Close() error { return nil }

func TestStorageFailureFailsOpenOnThePrimaryTarget(t *testing.T) {
	p := newPolicy(t, validParams())
	stub := &failingLimiter{}
	p.budget = &budgetStore{lim: stub, tracker: stub, backend: "redis", failOpen: true}

	action, metadata := requestHeaders(p, "/chat/completions", nil)

	if _, short := action.(policy.ImmediateResponse); short {
		t.Fatal("fail-open must not short-circuit the request")
	}
	if got := metadata[metadataSelectedTier]; got != tierPrimary {
		t.Errorf("tier = %v, want primary; a storage failure is not budget exhaustion", got)
	}
	if stub.queries.Load() != 1 {
		t.Errorf("budget queries = %d, want 1", stub.queries.Load())
	}
}

func TestStorageFailureFailsClosedWithoutGuessing(t *testing.T) {
	p := newPolicy(t, validParams())
	stub := &failingLimiter{}
	p.budget = &budgetStore{lim: stub, tracker: stub, backend: "redis", failOpen: false}

	action, metadata := requestHeaders(p, "/chat/completions", nil)

	response := immediate(t, action)
	if response.StatusCode != 503 {
		t.Errorf("status = %d, want 503", response.StatusCode)
	}
	if response.StatusCode == 429 {
		t.Error("a storage failure must never be reported as rate limiting")
	}
	if _, selected := metadata[metadataSelectedTier]; selected {
		t.Error("no target may be recorded when the budget state is unknown")
	}
}

func TestStorageFailureIsNotMistakenForExhaustion(t *testing.T) {
	p := newPolicy(t, validParams())
	stub := &failingLimiter{}
	p.budget = &budgetStore{lim: stub, tracker: stub, backend: "redis", failOpen: true}

	state, _, err := p.budget.Query(context.Background(), "any-key")
	if err == nil {
		t.Fatal("expected the storage error to be surfaced")
	}
	if state != budgetUnknown {
		t.Errorf("state = %v, want budgetUnknown", state)
	}
	if state == budgetExhausted {
		t.Error("a storage failure must not be reported as exhaustion")
	}
}

func TestChargeFailureIsLoggedAndDoesNotPanic(t *testing.T) {
	p := newPolicy(t, validParams())
	stub := &failingLimiter{}
	p.budget = &budgetStore{lim: stub, tracker: stub, backend: "redis", failOpen: true}

	_, metadata := requestHeaders(p, "/chat/completions", nil)
	completeResponse(p, metadata, "1.0", llmCostStatusCalculated)

	if stub.charges.Load() != 1 {
		t.Errorf("charge attempts = %d, want exactly 1", stub.charges.Load())
	}
	if charged, _ := metadata[metadataCostCharged].(bool); !charged {
		t.Error("the charge must be claimed once so a retry cannot double-deduct")
	}
}

// ─── Memory backend ──────────────────────────────────────────────────────────

func TestMemoryBackendTracksSpendingAcrossRequests(t *testing.T) {
	params := validParams()
	params["backend"] = "memory"
	p := newPolicy(t, params)
	key := p.budgetNamespace

	requestCycle(p, "2.5", nil)
	requestCycle(p, "2.5", nil)

	remaining := availableDollars(t, p, key)
	if remaining < 4.99 || remaining > 5.01 {
		t.Errorf("remaining budget = %.4f, want ~5.00", remaining)
	}
}

func TestMemoryBudgetSurvivesAPolicyReload(t *testing.T) {
	route := uniqueRoute(t)
	params := validParams()

	first := newPolicyOnRoute(t, params, route)
	requestCycle(first, "6.0", nil)

	// Re-attaching the same policy configuration must reuse the cached limiter
	// rather than silently resetting the budget.
	second := newPolicyOnRoute(t, validParams(), route)
	remaining := availableDollars(t, second, second.budgetNamespace)
	if remaining < 3.99 || remaining > 4.01 {
		t.Errorf("remaining budget after reload = %.4f, want ~4.00", remaining)
	}
}

func TestChangingBudgetConfigurationStartsAFreshWindow(t *testing.T) {
	route := uniqueRoute(t)

	first := newPolicyOnRoute(t, validParams(), route)
	requestCycle(first, "6.0", nil)

	changed := validParams()
	changed["budgetLimits"] = []interface{}{map[string]interface{}{"amount": 25.0, "duration": "24h"}}
	second := newPolicyOnRoute(t, changed, route)

	remaining := availableDollars(t, second, second.budgetNamespace)
	if remaining < 24.99 || remaining > 25.01 {
		t.Errorf("remaining budget = %.4f, want the new $25 limit", remaining)
	}
}

// ─── GCRA algorithm ──────────────────────────────────────────────────────────

func TestGCRAAlgorithmRoutesToFallbackWhenSpent(t *testing.T) {
	params := validParams()
	params["algorithm"] = "gcra"
	p := newPolicyWithFallbackBudget(t, params)

	if tier := requestCycle(p, "11.0", nil); tier != tierPrimary {
		t.Fatalf("first request tier = %q, want primary", tier)
	}

	_, metadata := requestHeaders(p, "/chat/completions", nil)
	if got := metadata[metadataSelectedTier]; got != tierFallback {
		t.Errorf("tier = %v, want fallback once the GCRA capacity is spent", got)
	}
}

// ─── Redis backends ──────────────────────────────────────────────────────────

func redisParams(t *testing.T, backend string) map[string]interface{} {
	t.Helper()

	addr := os.Getenv("REDIS_TEST_ADDR")
	if addr == "" {
		addr = "localhost:6379"
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("invalid REDIS_TEST_ADDR %q: %v", addr, err)
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil {
		t.Fatalf("invalid Redis port %q: %v", port, err)
	}

	client := redis.NewClient(&redis.Options{
		Addr:        addr,
		DialTimeout: 300 * time.Millisecond,
		MaxRetries:  -1,
	})
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	if err := client.Ping(ctx).Err(); err != nil {
		_ = client.Close()
		t.Skipf("no Redis reachable at %s (set REDIS_TEST_ADDR or start the repository Redis service): %v", addr, err)
	}

	prefix := fmt.Sprintf("cbr-test:%s:%d:", t.Name(), time.Now().UnixNano())
	t.Cleanup(func() {
		cleanupCtx := context.Background()
		iter := client.Scan(cleanupCtx, 0, prefix+"*", 0).Iterator()
		for iter.Next(cleanupCtx) {
			_ = client.Del(cleanupCtx, iter.Val()).Err()
		}
		_ = client.Close()
	})

	params := validParams()
	params["backend"] = backend
	params["redis"] = map[string]interface{}{
		"host":      host,
		"port":      portNumber,
		"keyPrefix": prefix,
	}
	return params
}

func TestRedisBackendRoutesAndCharges(t *testing.T) {
	p := newPolicyWithFallbackBudget(t, redisParams(t, "redis"))
	key := p.budgetNamespace

	if tier := requestCycle(p, "4.0", nil); tier != tierPrimary {
		t.Fatalf("first request tier = %q, want primary", tier)
	}
	remaining := availableDollars(t, p, key)
	if remaining < 5.99 || remaining > 6.01 {
		t.Errorf("remaining budget = %.4f, want ~6.00", remaining)
	}

	requestCycle(p, "7.0", nil)

	_, metadata := requestHeaders(p, "/chat/completions", nil)
	if got := metadata[metadataSelectedTier]; got != tierFallback {
		t.Errorf("tier = %v, want fallback once Redis reports the budget spent", got)
	}
}

func TestRedisBackendSharesStateAcrossGatewayInstances(t *testing.T) {
	params := withFallbackBudget(redisParams(t, "redis"))
	route := uniqueRoute(t)

	// Two policy instances stand in for two gateway replicas pointed at one Redis.
	replicaA := newPolicyOnRoute(t, params, route)
	replicaB := newPolicyOnRoute(t, params, route)

	if tier := requestCycle(replicaA, "11.0", nil); tier != tierPrimary {
		t.Fatalf("replica A tier = %q, want primary", tier)
	}

	_, metadata := requestHeaders(replicaB, "/chat/completions", nil)
	if got := metadata[metadataSelectedTier]; got != tierFallback {
		t.Errorf("replica B tier = %v, want fallback; Redis state must be shared", got)
	}
}

func TestRedisBudgetsAreIsolatedAcrossAPIsAndAttachmentLevels(t *testing.T) {
	params := redisParams(t, "redis")
	route := "POST|/chat/completions|*"

	newWithMetadata := func(metadata policy.PolicyMetadata) *CostBasedRoutingPolicy {
		t.Helper()
		instance, err := GetPolicy(metadata, params)
		if err != nil {
			t.Fatalf("GetPolicy failed: %v", err)
		}
		return instance.(*CostBasedRoutingPolicy)
	}

	apiRoute := newWithMetadata(policy.PolicyMetadata{
		APIId: "api-a", APIName: "chat", APIVersion: "v1", RouteName: route, AttachedTo: policy.LevelRoute,
	})
	otherAPI := newWithMetadata(policy.PolicyMetadata{
		APIId: "api-b", APIName: "chat", APIVersion: "v1", RouteName: route, AttachedTo: policy.LevelRoute,
	})
	apiLevel := newWithMetadata(policy.PolicyMetadata{
		APIId: "api-a", APIName: "chat", APIVersion: "v1", RouteName: route, AttachedTo: policy.LevelAPI,
	})

	requestCycle(apiRoute, "11.0", nil)
	for name, candidate := range map[string]*CostBasedRoutingPolicy{
		"different API":              otherAPI,
		"different attachment level": apiLevel,
	} {
		_, metadata := requestHeaders(candidate, "/chat/completions", nil)
		if got := metadata[metadataSelectedTier]; got != tierPrimary {
			t.Errorf("%s tier = %v, want primary; Redis budgets must be isolated", name, got)
		}
	}
}

func TestRedisLocalAsyncBackendRoutesAndCharges(t *testing.T) {
	p := newPolicyWithFallbackBudget(t, redisParams(t, "redis-local-async"))
	key := p.budgetNamespace

	if tier := requestCycle(p, "4.0", nil); tier != tierPrimary {
		t.Fatalf("first request tier = %q, want primary", tier)
	}
	remaining := availableDollars(t, p, key)
	if remaining < 5.99 || remaining > 6.01 {
		t.Errorf("remaining budget = %.4f, want ~6.00", remaining)
	}

	requestCycle(p, "7.0", nil)
	_, metadata := requestHeaders(p, "/chat/completions", nil)
	if got := metadata[metadataSelectedTier]; got != tierFallback {
		t.Errorf("tier = %v, want fallback", got)
	}
}

func TestGCRARedisLocalAsyncUsesRedisStorage(t *testing.T) {
	params := redisParams(t, "redis-local-async")
	params["algorithm"] = "gcra"
	p := newPolicy(t, params)

	if got := fmt.Sprintf("%T", p.budget.lim); got != "*gcra.RedisLimiter" {
		t.Fatalf("limiter type = %s, want *gcra.RedisLimiter; GCRA must not fall through to memory", got)
	}
}

func TestRedisLocalAsyncCacheKeyIncludesConnectionAndTuning(t *testing.T) {
	base, err := parseConfig(validParams())
	if err != nil {
		t.Fatal(err)
	}
	base.Backend = "redis-local-async"
	metadata := policy.PolicyMetadata{APIId: "api-a", RouteName: "route-a", AttachedTo: policy.LevelRoute}
	baseKey := cacheKeyFor(base, metadata)

	tests := map[string]func(*config){
		"host":          func(cfg *config) { cfg.Redis.Host = "redis-b" },
		"port":          func(cfg *config) { cfg.Redis.Port++ },
		"database":      func(cfg *config) { cfg.Redis.DB++ },
		"credentials":   func(cfg *config) { cfg.Redis.Password = "rotated" },
		"sync interval": func(cfg *config) { cfg.Local.SyncInterval += time.Millisecond },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			changed := base
			mutate(&changed)
			if got := cacheKeyFor(changed, metadata); got == baseKey {
				t.Fatal("cache key did not change")
			}
		})
	}
}

func TestRedisFailureModeClosedRejectsAnUnreachableServer(t *testing.T) {
	params := validParams()
	params["backend"] = "redis"
	params["redis"] = map[string]interface{}{
		"host":              "127.0.0.1",
		"port":              1, // nothing listens here
		"failureMode":       "closed",
		"connectionTimeout": "200ms",
		"keyPrefix":         "cbr-closed:" + t.Name() + ":",
	}

	_, err := GetPolicy(policy.PolicyMetadata{RouteName: uniqueRoute(t)}, params)
	if err == nil {
		t.Fatal("expected policy creation to fail when Redis is unreachable and failureMode is closed")
	}
}

// ─── Cost parsing and scaling ────────────────────────────────────────────────

func TestParseReportedCost(t *testing.T) {
	tests := []struct {
		name     string
		metadata map[string]interface{}
		wantCost float64
		wantOK   bool
	}{
		{
			name: "calculated string cost",
			metadata: map[string]interface{}{
				metadataLLMCost:       "0.0000421000",
				metadataLLMCostStatus: llmCostStatusCalculated,
			},
			wantCost: 0.0000421,
			wantOK:   true,
		},
		{
			name:     "cost without a status",
			metadata: map[string]interface{}{metadataLLMCost: 1.25},
			wantOK:   false,
		},
		{
			name: "not calculated",
			metadata: map[string]interface{}{
				metadataLLMCost:       "0.0000000000",
				metadataLLMCostStatus: "not_calculated",
			},
			wantOK: false,
		},
		{name: "absent", metadata: map[string]interface{}{}, wantOK: false},
		{name: "unparseable", metadata: map[string]interface{}{metadataLLMCost: "free"}, wantOK: false},
		{name: "negative", metadata: map[string]interface{}{metadataLLMCost: -0.5}, wantOK: false},
		{name: "NaN", metadata: map[string]interface{}{metadataLLMCost: math.NaN()}, wantOK: false},
		{name: "infinite", metadata: map[string]interface{}{metadataLLMCost: math.Inf(1)}, wantOK: false},
		{name: "wrong type", metadata: map[string]interface{}{metadataLLMCost: []string{"1"}}, wantOK: false},
		{
			name: "calculated zero",
			metadata: map[string]interface{}{
				metadataLLMCost:       "0",
				metadataLLMCostStatus: llmCostStatusCalculated,
			},
			wantCost: 0,
			wantOK:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cost, _, ok := parseReportedCost(tt.metadata)
			if ok != tt.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tt.wantOK)
			}
			if ok && math.Abs(cost-tt.wantCost) > 1e-12 {
				t.Errorf("cost = %v, want %v", cost, tt.wantCost)
			}
		})
	}
}

func TestScaleCost(t *testing.T) {
	scaled, ok := scaleCost(0.000042, DefaultCostScaleFactor)
	if !ok || scaled != 42000 {
		t.Errorf("scaleCost(0.000042) = %d, %v; want 42000, true", scaled, ok)
	}

	if _, ok := scaleCost(-1, DefaultCostScaleFactor); ok {
		t.Error("a negative cost must be rejected")
	}
	if _, ok := scaleCost(math.NaN(), DefaultCostScaleFactor); ok {
		t.Error("NaN must be rejected")
	}
	if _, ok := scaleCost(math.Inf(1), DefaultCostScaleFactor); ok {
		t.Error("+Inf must be rejected")
	}

	// An absurd cost clamps instead of wrapping around to a negative charge.
	clamped, ok := scaleCost(1e30, DefaultCostScaleFactor)
	if !ok || clamped != math.MaxInt64 {
		t.Errorf("scaleCost(1e30) = %d, %v; want MaxInt64, true", clamped, ok)
	}
}

func TestSmallCostsSurviveScaling(t *testing.T) {
	p := newPolicy(t, validParams())
	key := p.budgetNamespace

	// A sub-cent cost must not truncate to zero in the integer counter.
	for i := 0; i < 1000; i++ {
		requestCycle(p, "0.000001", nil)
	}

	remaining := availableDollars(t, p, key)
	if remaining > 9.9991 || remaining < 9.9989 {
		t.Errorf("remaining budget = %.6f, want ~9.999 after 1000 × $0.000001", remaining)
	}
}
