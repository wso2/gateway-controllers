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
	"math"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

// createTestRequestHeaderContext creates a request header context with provider metadata
func createTestRequestHeaderContext(providerName string) *policy.RequestHeaderContext {
	return &policy.RequestHeaderContext{
		Headers: policy.NewHeaders(map[string][]string{
			"content-type": {"application/json"},
		}),
		SharedContext: &policy.SharedContext{
			Metadata: map[string]interface{}{
				MetadataKeyProviderName: providerName,
			},
		},
	}
}

// TestLLMCostRateLimitPolicy_GetPolicy tests policy creation
func TestLLMCostRateLimitPolicy_GetPolicy(t *testing.T) {
	metadata := policy.PolicyMetadata{
		RouteName: "test-route",
	}

	params := map[string]interface{}{
		"budgetLimits": []interface{}{
			map[string]interface{}{
				"amount":   float64(10),
				"duration": "1h",
			},
		},
		"promptTokenCost":     float64(0.000002),
		"completionTokenCost": float64(0.000006),
		"algorithm":           "fixed-window",
		"backend":             "memory",
	}

	p, err := GetPolicy(metadata, params)
	if err != nil {
		t.Fatalf("Failed to create policy: %v", err)
	}

	if p == nil {
		t.Fatal("Expected policy instance, got nil")
	}

	costPolicy, ok := p.(*LLMCostRateLimitPolicy)
	if !ok {
		t.Fatalf("Expected LLMCostRateLimitPolicy, got %T", p)
	}

	if costPolicy.metadata.RouteName != "test-route" {
		t.Errorf("Expected route name 'test-route', got '%s'", costPolicy.metadata.RouteName)
	}
}

// TestLLMCostRateLimitPolicy_OnRequestHeaders_NoProvider tests behavior when provider is missing
func TestLLMCostRateLimitPolicy_OnRequestHeaders_NoProvider(t *testing.T) {
	metadata := policy.PolicyMetadata{
		RouteName: "test-route",
	}

	params := map[string]interface{}{
		"budgetLimits": []interface{}{
			map[string]interface{}{
				"amount":   float64(10),
				"duration": "1h",
			},
		},
	}

	p, err := GetPolicy(metadata, params)
	if err != nil {
		t.Fatalf("Failed to create policy: %v", err)
	}

	// Create context without provider metadata
	ctx := &policy.RequestHeaderContext{
		Headers: policy.NewHeaders(map[string][]string{}),
		SharedContext: &policy.SharedContext{
			Metadata: map[string]interface{}{}, // No provider_name
		},
	}

	action := p.(*LLMCostRateLimitPolicy).OnRequestHeaders(context.Background(), ctx, params)

	// Should return UpstreamRequestHeaderModifications (skip) when no provider is found
	if _, ok := action.(policy.UpstreamRequestHeaderModifications); !ok {
		t.Errorf("Expected UpstreamRequestHeaderModifications when provider is missing, got %T", action)
	}
}

// TestLLMCostRateLimitPolicy_OnRequestHeaders_EmptyProvider tests behavior with empty provider name
func TestLLMCostRateLimitPolicy_OnRequestHeaders_EmptyProvider(t *testing.T) {
	metadata := policy.PolicyMetadata{
		RouteName: "test-route",
	}

	params := map[string]interface{}{
		"budgetLimits": []interface{}{
			map[string]interface{}{
				"amount":   float64(10),
				"duration": "1h",
			},
		},
	}

	p, err := GetPolicy(metadata, params)
	if err != nil {
		t.Fatalf("Failed to create policy: %v", err)
	}

	// Create context with empty provider name
	ctx := &policy.RequestHeaderContext{
		Headers: policy.NewHeaders(map[string][]string{}),
		SharedContext: &policy.SharedContext{
			Metadata: map[string]interface{}{
				MetadataKeyProviderName: "",
			},
		},
	}

	action := p.(*LLMCostRateLimitPolicy).OnRequestHeaders(context.Background(), ctx, params)

	// Should return UpstreamRequestHeaderModifications (skip) when provider name is empty
	if _, ok := action.(policy.UpstreamRequestHeaderModifications); !ok {
		t.Errorf("Expected UpstreamRequestHeaderModifications when provider is empty, got %T", action)
	}
}

// TestTransformToRatelimitParams tests the parameter transformation
func TestTransformToRatelimitParams(t *testing.T) {
	params := map[string]interface{}{
		"budgetLimits": []interface{}{
			map[string]interface{}{
				"amount":   float64(10),
				"duration": "1h",
			},
			map[string]interface{}{
				"amount":   float64(100),
				"duration": "24h",
			},
		},
		"algorithm": "fixed-window",
		"backend":   "memory",
	}

	result := transformToRatelimitParams(params)

	// Check quotas were created
	quotas, ok := result["quotas"].([]interface{})
	if !ok {
		t.Fatal("Expected quotas to be []interface{}")
	}

	if len(quotas) != 1 {
		t.Fatalf("Expected 1 quota, got %d", len(quotas))
	}

	quota := quotas[0].(map[string]interface{})

	// Check limits were converted
	limits, ok := quota["limits"].([]interface{})
	if !ok {
		t.Fatal("Expected limits to be []interface{}")
	}

	if len(limits) != 2 {
		t.Errorf("Expected 2 limits, got %d", len(limits))
	}

	// Check cost extraction reads from x-llm-cost in SharedContext.Metadata
	costExtraction, ok := quota["costExtraction"].(map[string]interface{})
	if !ok {
		t.Fatal("Expected costExtraction to be present")
	}

	sources, ok := costExtraction["sources"].([]interface{})
	if !ok || len(sources) != 1 {
		t.Fatalf("Expected 1 cost source (x-llm-cost metadata), got %d", len(sources))
	}

	source := sources[0].(map[string]interface{})
	if source["type"] != "response_metadata" {
		t.Errorf("Expected source type 'response_metadata', got %v", source["type"])
	}
	if source["key"] != "x-llm-cost" {
		t.Errorf("Expected source key 'x-llm-cost', got %v", source["key"])
	}

	// Check passthrough parameters
	if result["algorithm"] != "fixed-window" {
		t.Errorf("Expected algorithm 'fixed-window', got %v", result["algorithm"])
	}

	if result["backend"] != "memory" {
		t.Errorf("Expected backend 'memory', got %v", result["backend"])
	}
}

// TestTransformToRatelimitParams_CustomScaleFactor tests that a custom costScaleFactor is applied to the multiplier
func TestTransformToRatelimitParams_CustomScaleFactor(t *testing.T) {
	params := map[string]interface{}{
		"budgetLimits": []interface{}{
			map[string]interface{}{
				"amount":   float64(10),
				"duration": "1h",
			},
		},
		"costScaleFactor": 1000000, // 1M micro-dollars
		"algorithm":       "fixed-window",
		"backend":         "memory",
	}

	result := transformToRatelimitParams(params)

	quotas, ok := result["quotas"].([]interface{})
	if !ok || len(quotas) != 1 {
		t.Fatal("Expected 1 quota")
	}

	quota := quotas[0].(map[string]interface{})
	costExtraction := quota["costExtraction"].(map[string]interface{})
	sources := costExtraction["sources"].([]interface{})
	source := sources[0].(map[string]interface{})

	if source["multiplier"] != float64(1000000) {
		t.Errorf("Expected multiplier 1000000, got %v", source["multiplier"])
	}
}

// TestTransformToRatelimitParams_NoBudgetLimits tests transformation with missing budgets
func TestTransformToRatelimitParams_NoBudgetLimits(t *testing.T) {
	params := map[string]interface{}{
		"promptTokenCost": float64(0.000002),
		"algorithm":       "fixed-window",
		"backend":         "memory",
	}

	result := transformToRatelimitParams(params)

	quotas, ok := result["quotas"].([]interface{})
	if !ok {
		t.Fatal("Expected quotas to be []interface{}")
	}

	// Should have 0 quotas since no budget limits are configured
	if len(quotas) != 0 {
		t.Errorf("Expected 0 quotas when no budgets configured, got %d", len(quotas))
	}
}

// TestTransformToRatelimitParams_AlwaysHasCostExtraction tests that cost extraction
// is always configured regardless of other parameters, since it reads from SharedContext.Metadata.
func TestTransformToRatelimitParams_AlwaysHasCostExtraction(t *testing.T) {
	params := map[string]interface{}{
		"budgetLimits": []interface{}{
			map[string]interface{}{
				"amount":   float64(10),
				"duration": "1h",
			},
		},
		"algorithm": "fixed-window",
		"backend":   "memory",
	}

	result := transformToRatelimitParams(params)

	quotas, ok := result["quotas"].([]interface{})
	if !ok || len(quotas) != 1 {
		t.Fatal("Expected 1 quota")
	}

	quota := quotas[0].(map[string]interface{})

	// x-llm-cost metadata source should always be present
	costExtraction, ok := quota["costExtraction"].(map[string]interface{})
	if !ok {
		t.Fatal("Expected costExtraction to always be present")
	}

	sources, ok := costExtraction["sources"].([]interface{})
	if !ok || len(sources) != 1 {
		t.Fatalf("Expected 1 cost source, got %d", len(sources))
	}
}

// TestLLMCostRateLimitPolicy_ConcurrentAccess tests thread-safe delegate creation
func TestLLMCostRateLimitPolicy_ConcurrentAccess(t *testing.T) {
	metadata := policy.PolicyMetadata{
		RouteName: "test-route",
	}

	params := map[string]interface{}{
		"budgetLimits": []interface{}{
			map[string]interface{}{
				"amount":   float64(10),
				"duration": "1h",
			},
		},
		"algorithm": "fixed-window",
		"backend":   "memory",
	}

	p, err := GetPolicy(metadata, params)
	if err != nil {
		t.Fatalf("Failed to create policy: %v", err)
	}

	costPolicy := p.(*LLMCostRateLimitPolicy)

	var wg sync.WaitGroup
	numGoroutines := 100
	var successCount atomic.Int32

	// Concurrent access without proper mock store - this will test the race condition handling
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx := createTestRequestHeaderContext("test-provider")
			action := costPolicy.OnRequestHeaders(context.Background(), ctx, params)
			// action should be UpstreamRequestHeaderModifications, shouldn't panic
			if _, ok := action.(policy.UpstreamRequestHeaderModifications); ok {
				successCount.Add(1)
			}
		}()
	}

	wg.Wait()

	// All goroutines should complete without panic
	t.Logf("Completed %d concurrent requests, %d returned UpstreamRequestHeaderModifications", numGoroutines, successCount.Load())
}

// TestLLMCostRateLimitPolicy_MultipleProviders tests handling multiple providers
func TestLLMCostRateLimitPolicy_MultipleProviders(t *testing.T) {
	metadata := policy.PolicyMetadata{
		RouteName: "multi-provider-route",
	}

	params := map[string]interface{}{
		"budgetLimits": []interface{}{
			map[string]interface{}{
				"amount":   float64(10),
				"duration": "1h",
			},
		},
		"algorithm": "fixed-window",
		"backend":   "memory",
	}

	p, err := GetPolicy(metadata, params)
	if err != nil {
		t.Fatalf("Failed to create policy: %v", err)
	}

	costPolicy := p.(*LLMCostRateLimitPolicy)

	providers := []string{"provider-1", "provider-2", "provider-3"}

	for _, provider := range providers {
		ctx := createTestRequestHeaderContext(provider)
		action := costPolicy.OnRequestHeaders(context.Background(), ctx, params)
		// May return default modifications, but shouldn't panic
		_ = action
	}

	// Verify delegates map has entries for each provider
	delegateCount := 0
	costPolicy.delegates.Range(func(key, value interface{}) bool {
		delegateCount++
		return true
	})

	t.Logf("Created delegates for %d providers", delegateCount)
}

// TestLLMCostRateLimitPolicy_Integration_NoBudgetLimits tests that no rate limiting
// is applied when budgetLimits are not configured.
func TestLLMCostRateLimitPolicy_Integration_NoBudgetLimits(t *testing.T) {
	metadata := policy.PolicyMetadata{
		RouteName: "test-route",
	}

	// No budgetLimits -- delegate should not be created and request should pass through.
	params := map[string]interface{}{
		"algorithm": "fixed-window",
		"backend":   "memory",
	}

	p, err := GetPolicy(metadata, params)
	if err != nil {
		t.Fatalf("Failed to create policy: %v", err)
	}

	ctx := createTestRequestHeaderContext("any-provider")
	action := p.(*LLMCostRateLimitPolicy).OnRequestHeaders(context.Background(), ctx, params)

	if _, ok := action.(policy.UpstreamRequestHeaderModifications); !ok {
		t.Errorf("Expected UpstreamRequestHeaderModifications when no budget limits configured, got %T", action)
	}
}

// stubCostChunkPolicer is a minimal delegate stub that records OnResponseBodyChunk calls.
type stubCostChunkPolicer struct {
	chunkCalls int
}

func (s *stubCostChunkPolicer) Mode() policy.ProcessingMode { return policy.ProcessingMode{} }
func (s *stubCostChunkPolicer) OnRequestHeaders(context.Context, *policy.RequestHeaderContext, map[string]interface{}) policy.RequestHeaderAction {
	return nil
}
func (s *stubCostChunkPolicer) OnResponseHeaders(context.Context, *policy.ResponseHeaderContext, map[string]interface{}) policy.ResponseHeaderAction {
	return nil
}
func (s *stubCostChunkPolicer) OnResponseBody(context.Context, *policy.ResponseContext, map[string]interface{}) policy.ResponseAction {
	return nil
}
func (s *stubCostChunkPolicer) OnResponseBodyChunk(_ context.Context, _ *policy.ResponseStreamContext, _ *policy.StreamBody, _ map[string]interface{}) policy.StreamingResponseAction {
	s.chunkCalls++
	return policy.ForwardResponseChunk{}
}
func (s *stubCostChunkPolicer) NeedsMoreResponseData(_ []byte) bool { return false }

func newCostStreamCtx(providerName string, pinnedDelegate policy.Policy) *policy.ResponseStreamContext {
	metadata := map[string]interface{}{}
	if providerName != "" {
		metadata[MetadataKeyProviderName] = providerName
	}
	if pinnedDelegate != nil {
		metadata[MetadataKeyDelegate] = pinnedDelegate
	}
	return &policy.ResponseStreamContext{
		SharedContext: &policy.SharedContext{
			Metadata: metadata,
		},
		ResponseHeaders: policy.NewHeaders(map[string][]string{}),
	}
}

// TestLLMCostRateLimitPolicy_Mode_ReturnsStream verifies that Mode reports BodyModeStream.
func TestLLMCostRateLimitPolicy_Mode_ReturnsStream(t *testing.T) {
	p := &LLMCostRateLimitPolicy{}
	mode := p.Mode()
	if mode.ResponseBodyMode != policy.BodyModeStream {
		t.Errorf("expected ResponseBodyMode=BodyModeStream, got %v", mode.ResponseBodyMode)
	}
}

// TestLLMCostRateLimitPolicy_NeedsMoreResponseData_ReturnsFalse verifies the streaming
// buffer hint is always false (metadata is read at EOS, no buffering needed).
func TestLLMCostRateLimitPolicy_NeedsMoreResponseData_ReturnsFalse(t *testing.T) {
	p := &LLMCostRateLimitPolicy{}
	if p.NeedsMoreResponseData([]byte("anything")) {
		t.Error("expected NeedsMoreResponseData to return false")
	}
}

// TestLLMCostRateLimitPolicy_OnResponseBodyChunk_NoProvider verifies that a missing
// provider name and no pinned delegate is handled gracefully.
func TestLLMCostRateLimitPolicy_OnResponseBodyChunk_NoProvider(t *testing.T) {
	p := &LLMCostRateLimitPolicy{metadata: policy.PolicyMetadata{RouteName: "r"}}
	respCtx := newCostStreamCtx("", nil)
	chunk := &policy.StreamBody{Chunk: []byte("data: {}"), EndOfStream: true}

	action := p.OnResponseBodyChunk(context.Background(), respCtx, chunk, nil)
	if !reflect.DeepEqual(action, policy.ForwardResponseChunk{}) {
		t.Errorf("expected empty ForwardResponseChunk, got %v", action)
	}
}

// TestLLMCostRateLimitPolicy_OnResponseBodyChunk_UsesPinnedDelegate verifies that the
// delegate pinned in metadata during OnRequestHeaders takes precedence.
func TestLLMCostRateLimitPolicy_OnResponseBodyChunk_UsesPinnedDelegate(t *testing.T) {
	stub := &stubCostChunkPolicer{}
	p := &LLMCostRateLimitPolicy{metadata: policy.PolicyMetadata{RouteName: "r"}}
	respCtx := newCostStreamCtx("", stub)

	chunks := [][]byte{
		[]byte("data: {\"usage\":{}}\n"),
		[]byte("data: [DONE]\n"),
	}
	for i, c := range chunks {
		eos := i == len(chunks)-1
		p.OnResponseBodyChunk(context.Background(), respCtx, &policy.StreamBody{Chunk: c, EndOfStream: eos, Index: uint64(i)}, nil)
	}

	if stub.chunkCalls != 2 {
		t.Errorf("expected pinned delegate OnResponseBodyChunk called 2 times, got %d", stub.chunkCalls)
	}
}

// TestLLMCostRateLimitPolicy_OnResponseBodyChunk_FallsBackToDelegatesMap verifies the
// fallback lookup by provider name when no delegate is pinned in metadata.
func TestLLMCostRateLimitPolicy_OnResponseBodyChunk_FallsBackToDelegatesMap(t *testing.T) {
	stub := &stubCostChunkPolicer{}
	p := &LLMCostRateLimitPolicy{metadata: policy.PolicyMetadata{RouteName: "r"}}
	p.delegates.Store("anthropic", &delegateEntry{cacheKey: "k", delegate: stub})

	respCtx := newCostStreamCtx("anthropic", nil)
	chunk := &policy.StreamBody{Chunk: []byte("data: [DONE]\n"), EndOfStream: true}

	p.OnResponseBodyChunk(context.Background(), respCtx, chunk, nil)

	if stub.chunkCalls != 1 {
		t.Errorf("expected delegate OnResponseBodyChunk called 1 time via fallback, got %d", stub.chunkCalls)
	}
}

// TestTransformToRatelimitParams_ConsumerBased_False verifies that when consumerBased is
// false (or absent), keyExtraction only contains the routename key.
func TestTransformToRatelimitParams_ConsumerBased_False(t *testing.T) {
	params := map[string]interface{}{
		"budgetLimits": []interface{}{
			map[string]interface{}{
				"amount":   float64(10),
				"duration": "1h",
			},
		},
		"consumerBased": false,
	}

	result := transformToRatelimitParams(params)

	quotas, ok := result["quotas"].([]interface{})
	if !ok || len(quotas) != 1 {
		t.Fatal("Expected 1 quota")
	}

	quota := quotas[0].(map[string]interface{})
	keyExtraction, ok := quota["keyExtraction"].([]interface{})
	if !ok {
		t.Fatal("Expected keyExtraction to be []interface{}")
	}

	if len(keyExtraction) != 1 {
		t.Fatalf("Expected 1 key extraction entry for backend limit, got %d", len(keyExtraction))
	}

	entry := keyExtraction[0].(map[string]interface{})
	if entry["type"] != "routename" {
		t.Errorf("Expected type 'routename', got %v", entry["type"])
	}
}

// TestTransformToRatelimitParams_ConsumerBased_True verifies that when consumerBased is
// true, keyExtraction contains both routename and the application ID metadata key.
func TestTransformToRatelimitParams_ConsumerBased_True(t *testing.T) {
	params := map[string]interface{}{
		"budgetLimits": []interface{}{
			map[string]interface{}{
				"amount":   float64(10),
				"duration": "1h",
			},
		},
		"consumerBased": true,
	}

	result := transformToRatelimitParams(params)

	quotas, ok := result["quotas"].([]interface{})
	if !ok || len(quotas) != 1 {
		t.Fatal("Expected 1 quota")
	}

	quota := quotas[0].(map[string]interface{})
	keyExtraction, ok := quota["keyExtraction"].([]interface{})
	if !ok {
		t.Fatal("Expected keyExtraction to be []interface{}")
	}

	if len(keyExtraction) != 2 {
		t.Fatalf("Expected 2 key extraction entries for consumer limit, got %d", len(keyExtraction))
	}

	first := keyExtraction[0].(map[string]interface{})
	if first["type"] != "routename" {
		t.Errorf("Expected first entry type 'routename', got %v", first["type"])
	}

	second := keyExtraction[1].(map[string]interface{})
	if second["type"] != "metadata" {
		t.Errorf("Expected second entry type 'metadata', got %v", second["type"])
	}
	if second["key"] != "x-wso2-application-id" {
		t.Errorf("Expected second entry key 'x-wso2-application-id', got %v", second["key"])
	}
	if second["fallback"] != "default" {
		t.Errorf("Expected second entry fallback 'default', got %v", second["fallback"])
	}
}

// stubThrottlingCostDelegate is a delegate stub whose request-header phase rejects with a
// fixed action, standing in for an advanced-ratelimit delegate whose budget is exhausted.
type stubThrottlingCostDelegate struct {
	stubCostChunkPolicer
	onRequestHeadersAction policy.RequestHeaderAction
}

func (s *stubThrottlingCostDelegate) OnRequestHeaders(context.Context, *policy.RequestHeaderContext, map[string]interface{}) policy.RequestHeaderAction {
	return s.onRequestHeadersAction
}

// TestDelegateFaultDeclarationIsPassedThrough covers what this policy contributes to the
// fault contract: nothing, deliberately. It returns the advanced-ratelimit delegate's
// action unchanged, so the delegate's IsFault and Fault reach the gateway untouched.
//
// The test exists because the alternative — rebuilding the response field-by-field to add
// or reshape something — is the mistake that silently drops both fields, and it is not
// visible from reading this policy alone.
func TestDelegateFaultDeclarationIsPassedThrough(t *testing.T) {
	params := map[string]interface{}{
		"budgetLimits": []interface{}{
			map[string]interface{}{"amount": float64(10), "duration": "1h"},
		},
		"algorithm": "fixed-window",
		"backend":   "memory",
	}
	p := &LLMCostRateLimitPolicy{metadata: policy.PolicyMetadata{RouteName: "fault-route"}}

	// Build the real delegate once so the cached entry carries the cache key the request
	// path computes, then swap in a stub that rejects.
	if _, err := p.resolveDelegate("openai", params); err != nil {
		t.Fatalf("resolveDelegate: %v", err)
	}
	entry, ok := p.delegates.Load("openai")
	if !ok {
		t.Fatalf("expected a cached delegate for the provider")
	}
	throttled := policy.ImmediateResponse{
		StatusCode: 429,
		Body:       []byte("Message throttled out"),
		IsFault:    true,
		Fault: &policy.FaultDetails{
			Code:      "900802", // RESOURCE_THROTTLE_OUT_ERROR_CODE
			Type:      "throttling",
			Direction: policy.DirectionRequest,
			Message:   "Message throttled out",
		},
	}
	p.delegates.Store("openai", &delegateEntry{
		cacheKey: entry.(*delegateEntry).cacheKey,
		delegate: &stubThrottlingCostDelegate{onRequestHeadersAction: throttled},
	})

	action := p.OnRequestHeaders(context.Background(), createTestRequestHeaderContext("openai"), params)

	resp, ok := action.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("expected ImmediateResponse, got %T", action)
	}
	if !resp.IsFault {
		t.Fatalf("the delegate's IsFault must reach the gateway unchanged")
	}
	if resp.Fault == nil || resp.Fault.Code != "900802" {
		t.Fatalf("the delegate's Fault must reach the gateway unchanged, got %+v", resp.Fault)
	}
}

// budgetParams returns params with a single budget limit.
func budgetParams(amount interface{}, duration string) map[string]interface{} {
	return map[string]interface{}{
		"budgetLimits": []interface{}{
			map[string]interface{}{"amount": amount, "duration": duration},
		},
		"algorithm": "fixed-window",
		"backend":   "memory",
	}
}

// firstQuotaLimits returns the limits of the single quota transformToRatelimitParams builds.
func firstQuotaLimits(t *testing.T, rlParams map[string]interface{}) []interface{} {
	t.Helper()
	quotas, ok := rlParams["quotas"].([]interface{})
	if !ok || len(quotas) != 1 {
		t.Fatalf("expected exactly one quota, got %v", rlParams["quotas"])
	}
	limits, ok := quotas[0].(map[string]interface{})["limits"].([]interface{})
	if !ok {
		t.Fatalf("expected limits on the quota, got %v", quotas[0])
	}
	return limits
}

// TestGetPolicy_PerformsNoConfigurationValidation: GetPolicy returns an instance for valid,
// empty and structurally invalid params alike; configuration errors surface at request time.
func TestGetPolicy_PerformsNoConfigurationValidation(t *testing.T) {
	cases := map[string]map[string]interface{}{
		"valid":                  budgetParams(float64(1), "1h"),
		"nil":                    nil,
		"empty":                  {},
		"budgetLimits a string":  {"budgetLimits": "ten dollars"},
		"budgetLimits a number":  {"budgetLimits": float64(10)},
		"budgetLimits non-array": {"budgetLimits": map[string]interface{}{"amount": float64(1), "duration": "1h"}},
	}
	for name, params := range cases {
		t.Run(name, func(t *testing.T) {
			p, err := GetPolicy(policy.PolicyMetadata{RouteName: "r"}, params)
			if err != nil {
				t.Fatalf("GetPolicy returned an error: %v", err)
			}
			if _, ok := p.(*LLMCostRateLimitPolicy); !ok {
				t.Fatalf("expected *LLMCostRateLimitPolicy, got %T", p)
			}
		})
	}
}

// TestTransformToRatelimitParams_NoUsableBudgetLimits: a budgetLimits value the transform cannot
// use yields no quota, so resolveDelegate creates no delegate and the route runs unlimited.
func TestTransformToRatelimitParams_NoUsableBudgetLimits(t *testing.T) {
	cases := map[string]map[string]interface{}{
		"absent":                {},
		"nil":                   {"budgetLimits": nil},
		"a string":              {"budgetLimits": "ten dollars"},
		"an object":             {"budgetLimits": map[string]interface{}{"amount": float64(1), "duration": "1h"}},
		"entries not objects":   {"budgetLimits": []interface{}{"one", float64(2), nil}},
		"amount a string":       budgetParams("1", "1h"),
		"amount nil":            budgetParams(nil, "1h"),
		"an empty array":        {"budgetLimits": []interface{}{}},
		"only unusable entries": {"budgetLimits": []interface{}{map[string]interface{}{"duration": "1h"}}},
	}
	for name, params := range cases {
		t.Run(name, func(t *testing.T) {
			quotas, ok := transformToRatelimitParams(params)["quotas"].([]interface{})
			if !ok || len(quotas) != 0 {
				t.Fatalf("expected no quotas, got %v", quotas)
			}
			p := &LLMCostRateLimitPolicy{}
			delegate, err := p.resolveDelegate("openai", params)
			if err != nil || delegate != nil {
				t.Fatalf("expected no delegate and no error, got %v, %v", delegate, err)
			}
			if _, cached := p.delegates.Load("openai"); cached {
				t.Fatal("no delegate must be cached when there is no budget")
			}
		})
	}
}

// TestTransformToRatelimitParams_AmountNumericTypes: float64, int and int64 amounts, as different
// config decoders produce them, scale to the same limit.
func TestTransformToRatelimitParams_AmountNumericTypes(t *testing.T) {
	for name, amount := range map[string]interface{}{
		"float64": float64(2),
		"int":     int(2),
		"int64":   int64(2),
	} {
		t.Run(name, func(t *testing.T) {
			limits := firstQuotaLimits(t, transformToRatelimitParams(budgetParams(amount, "1h")))
			got := limits[0].(map[string]interface{})["limit"].(float64)
			if got != 2*float64(DefaultCostScaleFactor) {
				t.Fatalf("expected %v, got %v", 2*float64(DefaultCostScaleFactor), got)
			}
		})
	}
}

// TestTransformToRatelimitParams_MultipleWindows: every window becomes its own limit, in order,
// at the same scale.
func TestTransformToRatelimitParams_MultipleWindows(t *testing.T) {
	params := map[string]interface{}{
		"budgetLimits": []interface{}{
			map[string]interface{}{"amount": float64(1), "duration": "1h"},
			map[string]interface{}{"amount": float64(5), "duration": "24h"},
			map[string]interface{}{"amount": float64(20), "duration": "720h"},
		},
	}
	limits := firstQuotaLimits(t, transformToRatelimitParams(params))
	want := []struct {
		limit    float64
		duration string
	}{{1e9, "1h"}, {5e9, "24h"}, {2e10, "720h"}}
	if len(limits) != len(want) {
		t.Fatalf("expected %d limits, got %d", len(want), len(limits))
	}
	for i, w := range want {
		l := limits[i].(map[string]interface{})
		if l["limit"] != w.limit || l["duration"] != w.duration {
			t.Errorf("limit %d: expected %v/%s, got %v/%v", i, w.limit, w.duration, l["limit"], l["duration"])
		}
	}
}

// TestTransformToRatelimitParams_DurationForwardedUnchanged: the policy does no duration
// validation of its own.
func TestTransformToRatelimitParams_DurationForwardedUnchanged(t *testing.T) {
	for _, duration := range []string{"1h30m", "not-a-duration", ""} {
		limits := firstQuotaLimits(t, transformToRatelimitParams(budgetParams(float64(1), duration)))
		if got := limits[0].(map[string]interface{})["duration"]; got != duration {
			t.Errorf("duration %q was changed to %v", duration, got)
		}
	}
	absent := map[string]interface{}{
		"budgetLimits": []interface{}{map[string]interface{}{"amount": float64(1)}},
	}
	limits := firstQuotaLimits(t, transformToRatelimitParams(absent))
	if got := limits[0].(map[string]interface{})["duration"]; got != nil {
		t.Errorf("an absent duration must be forwarded as nil, got %v", got)
	}
}

// TestExtractCostScaleFactor covers the default, both positions the factor can be injected at,
// their precedence, and the values that fall back to the default.
func TestExtractCostScaleFactor(t *testing.T) {
	nested := func(v interface{}) map[string]interface{} {
		return map[string]interface{}{"systemParameters": map[string]interface{}{"costScaleFactor": v}}
	}
	cases := []struct {
		name   string
		params map[string]interface{}
		want   int
	}{
		{"nil params", nil, DefaultCostScaleFactor},
		{"absent", map[string]interface{}{}, DefaultCostScaleFactor},
		{"root", map[string]interface{}{"costScaleFactor": float64(1000000)}, 1000000},
		{"nested", nested(float64(1000)), 1000},
		{"nested wins over root", map[string]interface{}{
			"costScaleFactor":  float64(1000000),
			"systemParameters": map[string]interface{}{"costScaleFactor": float64(1000)},
		}, 1000},
		{"nested zero falls to root", map[string]interface{}{
			"costScaleFactor":  float64(500),
			"systemParameters": map[string]interface{}{"costScaleFactor": float64(0)},
		}, 500},
		{"zero", nested(float64(0)), DefaultCostScaleFactor},
		{"negative", nested(float64(-5)), DefaultCostScaleFactor},
		{"root negative", map[string]interface{}{"costScaleFactor": -1}, DefaultCostScaleFactor},
		{"string", nested("1000"), DefaultCostScaleFactor},
		{"bool", nested(true), DefaultCostScaleFactor},
		{"nested not a map", map[string]interface{}{"systemParameters": "x"}, DefaultCostScaleFactor},
		{"int", nested(int(100)), 100},
		{"int64", nested(int64(100)), 100},
		{"int32", nested(int32(100)), 100},
		{"float32", nested(float32(100)), 100},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := extractCostScaleFactor(tc.params); got != tc.want {
				t.Fatalf("expected %d, got %d", tc.want, got)
			}
		})
	}
}

// TestTransformToRatelimitParams_ScaleFactorAppliesToLimitAndMultiplier: the limit and the cost
// multiplier use the same factor, so the budget enforced is the budget configured.
func TestTransformToRatelimitParams_ScaleFactorAppliesToLimitAndMultiplier(t *testing.T) {
	for _, factor := range []int{DefaultCostScaleFactor, 1000000, 100} {
		params := budgetParams(float64(2), "1h")
		params["costScaleFactor"] = float64(factor)
		rl := transformToRatelimitParams(params)

		limit := firstQuotaLimits(t, rl)[0].(map[string]interface{})["limit"].(float64)
		if limit != 2*float64(factor) {
			t.Errorf("factor %d: limit %v", factor, limit)
		}
		quota := rl["quotas"].([]interface{})[0].(map[string]interface{})
		sources := quota["costExtraction"].(map[string]interface{})["sources"].([]interface{})
		if m := sources[0].(map[string]interface{})["multiplier"]; m != float64(factor) {
			t.Errorf("factor %d: multiplier %v", factor, m)
		}
	}
}

// TestTransformToRatelimitParams_LargeScaleFactorStaysInInt64: the schema bounds the amount at
// 1,000,000 and the factor only below, so the largest budget at a large factor must still fit the
// int64 counters of the limiter.
func TestTransformToRatelimitParams_LargeScaleFactorStaysInInt64(t *testing.T) {
	params := budgetParams(float64(1000000), "1h")
	params["costScaleFactor"] = float64(9000000000000)
	limit := firstQuotaLimits(t, transformToRatelimitParams(params))[0].(map[string]interface{})["limit"].(float64)
	if limit != 9e18 {
		t.Fatalf("expected 9e18, got %v", limit)
	}
	if limit > float64(math.MaxInt64) || int64(limit) != 9000000000000000000 {
		t.Fatalf("the scaled limit %v does not survive conversion to int64", limit)
	}
}

// TestResolveDelegate_ReuseReplaceAndIsolation: identical params reuse the instance (spend
// survives), changed params replace it (spend is discarded), and each provider has its own,
// keyed by the provider name alone.
func TestResolveDelegate_ReuseReplaceAndIsolation(t *testing.T) {
	p := &LLMCostRateLimitPolicy{metadata: policy.PolicyMetadata{RouteName: "r"}}
	params := budgetParams(float64(1), "1h")

	first, err := p.resolveDelegate("openai", params)
	if err != nil || first == nil {
		t.Fatalf("resolveDelegate: %v, %v", first, err)
	}
	again, _ := p.resolveDelegate("openai", params)
	if again != first {
		t.Error("identical params must reuse the same delegate instance")
	}

	changed, _ := p.resolveDelegate("openai", budgetParams(float64(2), "1h"))
	if changed == first {
		t.Error("changed budget must replace the delegate")
	}
	if entry, _ := p.delegates.Load("openai"); entry.(*delegateEntry).delegate != changed {
		t.Error("the cache must hold the replacement")
	}

	other, _ := p.resolveDelegate("anthropic", params)
	if other == changed || other == nil {
		t.Error("each provider must get its own delegate")
	}

	keys := map[string]bool{}
	p.delegates.Range(func(k, _ interface{}) bool { keys[k.(string)] = true; return true })
	if len(keys) != 2 || !keys["openai"] || !keys["anthropic"] {
		t.Errorf("the cache must hold exactly one entry per provider name, got %v", keys)
	}
}

// stubHeaderBodyDelegate records which response phases ran and returns canned actions.
type stubHeaderBodyDelegate struct {
	stubCostChunkPolicer
	headerCalls, bodyCalls int
	headerAction           policy.ResponseHeaderAction
	bodyAction             policy.ResponseAction
}

func (s *stubHeaderBodyDelegate) OnResponseHeaders(context.Context, *policy.ResponseHeaderContext, map[string]interface{}) policy.ResponseHeaderAction {
	s.headerCalls++
	return s.headerAction
}

func (s *stubHeaderBodyDelegate) OnResponseBody(context.Context, *policy.ResponseContext, map[string]interface{}) policy.ResponseAction {
	s.bodyCalls++
	return s.bodyAction
}

func scaledHeaders() map[string]string {
	return map[string]string{"x-ratelimit-limit": "1000000000", "x-ratelimit-remaining": "250000000"}
}

func newStubHeaderBodyDelegate() *stubHeaderBodyDelegate {
	return &stubHeaderBodyDelegate{
		headerAction: policy.DownstreamResponseHeaderModifications{HeadersToSet: scaledHeaders()},
		bodyAction:   policy.DownstreamResponseModifications{HeadersToSet: scaledHeaders()},
	}
}

func headerCtx(metadata map[string]interface{}) *policy.ResponseHeaderContext {
	return &policy.ResponseHeaderContext{SharedContext: &policy.SharedContext{Metadata: metadata}}
}

func bodyCtx(metadata map[string]interface{}) *policy.ResponseContext {
	return &policy.ResponseContext{SharedContext: &policy.SharedContext{Metadata: metadata}}
}

// TestResponsePhases_PinnedDelegateWinsOverCache: both response phases act on the delegate the
// request phase pinned, never on a replacement found in the cache.
func TestResponsePhases_PinnedDelegateWinsOverCache(t *testing.T) {
	pinned, cached := newStubHeaderBodyDelegate(), newStubHeaderBodyDelegate()
	p := &LLMCostRateLimitPolicy{}
	p.delegates.Store("openai", &delegateEntry{cacheKey: "k", delegate: cached})
	metadata := map[string]interface{}{MetadataKeyProviderName: "openai", MetadataKeyDelegate: pinned}

	p.OnResponseHeaders(context.Background(), headerCtx(metadata), nil)
	p.OnResponseBody(context.Background(), bodyCtx(metadata), nil)

	if pinned.headerCalls != 1 || pinned.bodyCalls != 1 {
		t.Errorf("pinned delegate: headers %d, body %d", pinned.headerCalls, pinned.bodyCalls)
	}
	if cached.headerCalls != 0 || cached.bodyCalls != 0 {
		t.Errorf("cached delegate must not run, got headers %d, body %d", cached.headerCalls, cached.bodyCalls)
	}
}

// TestResponsePhases_FallBackToCacheByProviderName: with no pinned delegate the cached one for the
// provider counts the cost, and the dollar headers are added.
func TestResponsePhases_FallBackToCacheByProviderName(t *testing.T) {
	d := newStubHeaderBodyDelegate()
	p := &LLMCostRateLimitPolicy{}
	p.delegates.Store("openai", &delegateEntry{cacheKey: "k", delegate: d})
	metadata := map[string]interface{}{MetadataKeyProviderName: "openai"}

	h := p.OnResponseHeaders(context.Background(), headerCtx(metadata), nil)
	b := p.OnResponseBody(context.Background(), bodyCtx(metadata), nil)

	if d.headerCalls != 1 || d.bodyCalls != 1 {
		t.Fatalf("cached delegate: headers %d, body %d", d.headerCalls, d.bodyCalls)
	}
	hm := h.(policy.DownstreamResponseHeaderModifications).HeadersToSet
	bm := b.(policy.DownstreamResponseModifications).HeadersToSet
	for _, got := range []map[string]string{hm, bm} {
		if got["x-ratelimit-cost-limit-dollars"] != "1.000000" || got["x-ratelimit-cost-remaining-dollars"] != "0.250000" {
			t.Errorf("dollar headers missing or wrong: %v", got)
		}
	}
}

// TestResponsePhases_NoDelegateLeavesResponseUntouched: with neither a pinned nor a cached
// delegate the policy returns an empty modification set and counts nothing.
func TestResponsePhases_NoDelegateLeavesResponseUntouched(t *testing.T) {
	p := &LLMCostRateLimitPolicy{}
	p.delegates.Store("nil-delegate", &delegateEntry{cacheKey: "k"})
	for name, metadata := range map[string]map[string]interface{}{
		"no provider":          {},
		"empty provider":       {MetadataKeyProviderName: ""},
		"unknown provider":     {MetadataKeyProviderName: "unknown"},
		"cache entry is nil":   {MetadataKeyProviderName: "nil-delegate"},
		"pinned of wrong type": {MetadataKeyProviderName: "unknown", MetadataKeyDelegate: "not a policy"},
	} {
		t.Run(name, func(t *testing.T) {
			if got := p.OnResponseHeaders(context.Background(), headerCtx(metadata), nil); !reflect.DeepEqual(got, policy.DownstreamResponseHeaderModifications{}) {
				t.Errorf("headers: expected empty modifications, got %#v", got)
			}
			if got := p.OnResponseBody(context.Background(), bodyCtx(metadata), nil); !reflect.DeepEqual(got, policy.DownstreamResponseModifications{}) {
				t.Errorf("body: expected empty modifications, got %#v", got)
			}
		})
	}
}

// TestAddDollarHeaders covers both spellings of the scaled headers, a dollar header that is already
// set, and delegate responses that must pass through untouched.
func TestAddDollarHeaders(t *testing.T) {
	p := &LLMCostRateLimitPolicy{}
	const none = "<absent>"
	cases := []struct {
		name         string
		in           map[string]string
		factor       int
		wantLimit    string
		wantRemained string
	}{
		{"legacy spelling", map[string]string{"x-ratelimit-limit": "1000000000", "x-ratelimit-remaining": "250000000"}, DefaultCostScaleFactor, "1.000000", "0.250000"},
		{"IETF spelling", map[string]string{"ratelimit-limit": "2500000", "ratelimit-remaining": "500000"}, 1000000, "2.500000", "0.500000"},
		{"existing dollar header kept", map[string]string{
			"x-ratelimit-limit": "1000000000", "x-ratelimit-cost-limit-dollars": "preset",
		}, DefaultCostScaleFactor, "preset", none},
		{"unparseable", map[string]string{"x-ratelimit-limit": "lots", "x-ratelimit-remaining": "1.5"}, DefaultCostScaleFactor, none, none},
		{"empty", map[string]string{"x-ratelimit-limit": "", "x-ratelimit-remaining": ""}, DefaultCostScaleFactor, none, none},
		{"no rate limit headers", map[string]string{"x-other": "1"}, DefaultCostScaleFactor, none, none},
	}
	check := func(t *testing.T, got map[string]string, wantLimit, wantRemained string) {
		t.Helper()
		for header, want := range map[string]string{
			"x-ratelimit-cost-limit-dollars":     wantLimit,
			"x-ratelimit-cost-remaining-dollars": wantRemained,
		} {
			value, present := got[header]
			if want == none && present {
				t.Errorf("%s must not be invented, got %q", header, value)
			}
			if want != none && value != want {
				t.Errorf("%s: expected %q, got %q", header, want, value)
			}
		}
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			hs := p.addDollarHeaders(policy.DownstreamResponseHeaderModifications{HeadersToSet: tc.in}, tc.factor)
			check(t, hs.(policy.DownstreamResponseHeaderModifications).HeadersToSet, tc.wantLimit, tc.wantRemained)
			bs := p.addDollarHeadersResponseBody(policy.DownstreamResponseModifications{HeadersToSet: tc.in}, tc.factor)
			check(t, bs.(policy.DownstreamResponseModifications).HeadersToSet, tc.wantLimit, tc.wantRemained)
		})
	}

	t.Run("the delegate's own headers are not modified", func(t *testing.T) {
		in := map[string]string{"x-ratelimit-limit": "1000000000"}
		p.addDollarHeaders(policy.DownstreamResponseHeaderModifications{HeadersToSet: in}, DefaultCostScaleFactor)
		if len(in) != 1 {
			t.Errorf("the delegate's map was modified: %v", in)
		}
	})
	t.Run("nil action", func(t *testing.T) {
		if got := p.addDollarHeaders(nil, DefaultCostScaleFactor); !reflect.DeepEqual(got, policy.DownstreamResponseHeaderModifications{}) {
			t.Errorf("header phase: %#v", got)
		}
		if got := p.addDollarHeadersResponseBody(nil, DefaultCostScaleFactor); !reflect.DeepEqual(got, policy.DownstreamResponseModifications{}) {
			t.Errorf("body phase: %#v", got)
		}
	})
	t.Run("no headers", func(t *testing.T) {
		hs := policy.DownstreamResponseHeaderModifications{}
		if got := p.addDollarHeaders(hs, DefaultCostScaleFactor); !reflect.DeepEqual(got, hs) {
			t.Errorf("header phase: %#v", got)
		}
		bs := policy.DownstreamResponseModifications{}
		if got := p.addDollarHeadersResponseBody(bs, DefaultCostScaleFactor); !reflect.DeepEqual(got, bs) {
			t.Errorf("body phase: %#v", got)
		}
	})
	t.Run("another action type passes through", func(t *testing.T) {
		rejection := policy.ImmediateResponse{StatusCode: 429}
		if got := p.addDollarHeadersResponseBody(rejection, DefaultCostScaleFactor); !reflect.DeepEqual(got, rejection) {
			t.Errorf("expected the action unchanged, got %#v", got)
		}
	})
}

// TestPhases_DegradeToNoRateLimitingOnMalformedInput: malformed params, absent metadata maps and
// nil delegates never panic, and each phase returns a well-formed allow action.
func TestPhases_DegradeToNoRateLimitingOnMalformedInput(t *testing.T) {
	malformed := map[string]map[string]interface{}{
		"nil params":            nil,
		"empty params":          {},
		"budgetLimits a string": {"budgetLimits": "x"},
		"scale factor garbage":  {"budgetLimits": "x", "costScaleFactor": "y", "systemParameters": "z"},
	}
	for name, params := range malformed {
		t.Run(name, func(t *testing.T) {
			p, err := GetPolicy(policy.PolicyMetadata{RouteName: "r"}, params)
			if err != nil {
				t.Fatal(err)
			}
			policyUnderTest := p.(*LLMCostRateLimitPolicy)

			reqCtx := createTestRequestHeaderContext("openai")
			if got := policyUnderTest.OnRequestHeaders(context.Background(), reqCtx, params); !reflect.DeepEqual(got, policy.UpstreamRequestHeaderModifications{}) {
				t.Errorf("request headers: %#v", got)
			}
			if got := policyUnderTest.OnResponseHeaders(context.Background(), headerCtx(nil), params); !reflect.DeepEqual(got, policy.DownstreamResponseHeaderModifications{}) {
				t.Errorf("response headers: %#v", got)
			}
			if got := policyUnderTest.OnResponseBody(context.Background(), bodyCtx(nil), params); !reflect.DeepEqual(got, policy.DownstreamResponseModifications{}) {
				t.Errorf("response body: %#v", got)
			}
			chunkCtx := &policy.ResponseStreamContext{SharedContext: &policy.SharedContext{}}
			if got := policyUnderTest.OnResponseBodyChunk(context.Background(), chunkCtx, &policy.StreamBody{EndOfStream: true}, params); !reflect.DeepEqual(got, policy.ForwardResponseChunk{}) {
				t.Errorf("response chunk: %#v", got)
			}
		})
	}

	t.Run("request phase with a nil metadata map", func(t *testing.T) {
		p := &LLMCostRateLimitPolicy{}
		reqCtx := &policy.RequestHeaderContext{
			Headers:       policy.NewHeaders(map[string][]string{}),
			SharedContext: &policy.SharedContext{},
		}
		if got := p.OnRequestHeaders(context.Background(), reqCtx, budgetParams(float64(1), "1h")); !reflect.DeepEqual(got, policy.UpstreamRequestHeaderModifications{}) {
			t.Errorf("expected no modifications, got %#v", got)
		}
	})
}

// TestSharedAndConsumerInstancesKeepSeparateState: a shared-budget instance and a consumer-based
// instance on the same route pin their delegate and scale factor under different metadata keys, so
// neither overwrites the other within one request.
func TestSharedAndConsumerInstancesKeepSeparateState(t *testing.T) {
	if delegateMetadataKey(map[string]interface{}{}) == delegateMetadataKey(map[string]interface{}{"consumerBased": true}) {
		t.Fatal("the delegate metadata keys must differ")
	}
	if costScaleFactorMetadataKey(nil) == costScaleFactorMetadataKey(map[string]interface{}{"consumerBased": true}) {
		t.Fatal("the scale factor metadata keys must differ")
	}

	shared := budgetParams(float64(1), "1h")
	shared["costScaleFactor"] = float64(1000)
	consumer := budgetParams(float64(1), "1h")
	consumer["consumerBased"] = true
	consumer["costScaleFactor"] = float64(1000000)

	sharedPolicy := &LLMCostRateLimitPolicy{metadata: policy.PolicyMetadata{RouteName: "r"}}
	consumerPolicy := &LLMCostRateLimitPolicy{metadata: policy.PolicyMetadata{RouteName: "r"}}
	reqCtx := createTestRequestHeaderContext("openai")

	sharedPolicy.OnRequestHeaders(context.Background(), reqCtx, shared)
	consumerPolicy.OnRequestHeaders(context.Background(), reqCtx, consumer)

	md := reqCtx.SharedContext.Metadata
	sharedDelegate, consumerDelegate := md[MetadataKeyDelegate], md[metadataKeyDelegateConsumer]
	if sharedDelegate == nil || consumerDelegate == nil || sharedDelegate == consumerDelegate {
		t.Fatalf("expected two distinct pinned delegates, got %v and %v", sharedDelegate, consumerDelegate)
	}
	if md[MetadataKeyCostScaleFactor] != 1000 || md[metadataKeyCostScaleFactorConsumer] != 1000000 {
		t.Errorf("scale factors were overwritten: %v, %v", md[MetadataKeyCostScaleFactor], md[metadataKeyCostScaleFactorConsumer])
	}
}
