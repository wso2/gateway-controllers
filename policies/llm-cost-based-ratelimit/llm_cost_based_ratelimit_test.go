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
