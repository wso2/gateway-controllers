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
	"bytes"
	"context"
	"log/slog"
	"reflect"
	"strings"
	"testing"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

// captureSlog temporarily redirects the default slog logger to a buffer for the
// duration of the calling test, restoring the previous logger on cleanup.
func captureSlog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return &buf
}

// stubChunkPolicer is a minimal delegate stub that records chunk calls.
type stubChunkPolicer struct {
	chunkCalls int
}

func (s *stubChunkPolicer) Mode() policy.ProcessingMode { return policy.ProcessingMode{} }
func (s *stubChunkPolicer) OnRequestHeaders(context.Context, *policy.RequestHeaderContext, map[string]interface{}) policy.RequestHeaderAction {
	return nil
}
func (s *stubChunkPolicer) OnResponseHeaders(context.Context, *policy.ResponseHeaderContext, map[string]interface{}) policy.ResponseHeaderAction {
	return nil
}
func (s *stubChunkPolicer) OnResponseBody(context.Context, *policy.ResponseContext, map[string]interface{}) policy.ResponseAction {
	return nil
}
func (s *stubChunkPolicer) OnResponseBodyChunk(_ context.Context, _ *policy.ResponseStreamContext, _ *policy.StreamBody, _ map[string]interface{}) policy.StreamingResponseAction {
	s.chunkCalls++
	return policy.ForwardResponseChunk{}
}
func (s *stubChunkPolicer) NeedsMoreResponseData(_ []byte) bool { return false }

func newTokenStreamCtx(providerName string) *policy.ResponseStreamContext {
	metadata := map[string]interface{}{}
	if providerName != "" {
		metadata[MetadataKeyProviderName] = providerName
	}
	return &policy.ResponseStreamContext{
		SharedContext: &policy.SharedContext{
			Metadata: metadata,
		},
		ResponseHeaders: policy.NewHeaders(map[string][]string{}),
	}
}

// TestTokenBasedRateLimitPolicy_GetPolicy tests policy creation
func TestTokenBasedRateLimitPolicy_GetPolicy(t *testing.T) {
	metadata := policy.PolicyMetadata{
		RouteName: "test-route",
	}

	params := map[string]interface{}{
		"promptTokenLimits": []interface{}{
			map[string]interface{}{
				"count":    float64(100),
				"duration": "1m",
			},
		},
		"algorithm": "fixed-window",
		"backend":   "memory",
	}

	p, err := GetPolicy(metadata, params)
	if err != nil {
		t.Fatalf("Failed to create policy: %v", err)
	}

	if p == nil {
		t.Fatal("Expected policy instance, got nil")
	}

	tbPolicy, ok := p.(*TokenBasedRateLimitPolicy)
	if !ok {
		t.Fatalf("Expected TokenBasedRateLimitPolicy, got %T", p)
	}

	if tbPolicy.metadata.RouteName != "test-route" {
		t.Errorf("Expected route name 'test-route', got '%s'", tbPolicy.metadata.RouteName)
	}
}

// TestTransformToRatelimitParams tests the parameter transformation
func TestTransformToRatelimitParams(t *testing.T) {
	params := map[string]interface{}{
		"promptTokenLimits": []interface{}{
			map[string]interface{}{
				"count":    float64(100),
				"duration": "1m",
			},
		},
		"completionTokenLimits": []interface{}{
			map[string]interface{}{
				"count":    float64(200),
				"duration": "1m",
			},
		},
		"totalTokenLimits": []interface{}{
			map[string]interface{}{
				"count":    float64(300),
				"duration": "1m",
			},
		},
		"algorithm": "fixed-window",
		"backend":   "memory",
	}

	template := map[string]interface{}{
		"spec": map[string]interface{}{
			"promptTokens": map[string]interface{}{
				"identifier": "$.usage.prompt_tokens",
			},
			"completionTokens": map[string]interface{}{
				"identifier": "$.usage.completion_tokens",
			},
			"totalTokens": map[string]interface{}{
				"identifier": "$.usage.total_tokens",
			},
		},
	}

	result := transformToRatelimitParams(params, template, policy.LevelRoute)

	// Check quotas were created
	quotas, ok := result["quotas"].([]interface{})
	if !ok {
		t.Fatal("Expected quotas to be []interface{}")
	}

	if len(quotas) != 3 {
		t.Errorf("Expected 3 quotas, got %d", len(quotas))
	}

	// Check passthrough parameters
	if result["algorithm"] != "fixed-window" {
		t.Errorf("Expected algorithm 'fixed-window', got %v", result["algorithm"])
	}

	if result["backend"] != "memory" {
		t.Errorf("Expected backend 'memory', got %v", result["backend"])
	}
}

// TestConvertLimits tests the limit conversion function
func TestConvertLimits(t *testing.T) {
	rawLimits := []interface{}{
		map[string]interface{}{
			"count":    float64(100),
			"duration": "1m",
		},
		map[string]interface{}{
			"count":    float64(1000),
			"duration": "1h",
		},
	}

	converted := convertLimits(rawLimits)

	if len(converted) != 2 {
		t.Fatalf("Expected 2 converted limits, got %d", len(converted))
	}

	first := converted[0].(map[string]interface{})
	if first["limit"] != float64(100) {
		t.Errorf("Expected limit 100, got %v", first["limit"])
	}
	if first["duration"] != "1m" {
		t.Errorf("Expected duration '1m', got %v", first["duration"])
	}
}

// TestConvertLimits_InvalidInput tests handling of invalid input
func TestConvertLimits_InvalidInput(t *testing.T) {
	// Test with nil
	result := convertLimits(nil)
	if result != nil {
		t.Errorf("Expected nil for nil input, got %v", result)
	}

	// Test with non-array
	result = convertLimits("not-an-array")
	if result != nil {
		t.Errorf("Expected nil for non-array input, got %v", result)
	}

	// Test with invalid items
	rawLimits := []interface{}{
		"not-a-map",
		map[string]interface{}{
			"count":    float64(100),
			"duration": "1m",
		},
	}

	converted := convertLimits(rawLimits)
	// Should skip invalid items
	if len(converted) != 1 {
		t.Errorf("Expected 1 valid converted limit, got %d", len(converted))
	}
}

// TestTransformToRatelimitParams_NoLimits tests transformation with missing limits
func TestTransformToRatelimitParams_NoLimits(t *testing.T) {
	params := map[string]interface{}{
		"algorithm": "fixed-window",
		"backend":   "memory",
	}

	template := map[string]interface{}{}

	result := transformToRatelimitParams(params, template, policy.LevelRoute)

	quotas, ok := result["quotas"].([]interface{})
	if !ok {
		t.Fatal("Expected quotas to be []interface{}")
	}

	// Should have 0 quotas since no limits are configured
	if len(quotas) != 0 {
		t.Errorf("Expected 0 quotas when no limits configured, got %d", len(quotas))
	}
}

// TestTransformToRatelimitParams_EmptyPromptAndCompletionLimits ensures empty arrays are ignored.
func TestTransformToRatelimitParams_EmptyPromptAndCompletionLimits(t *testing.T) {
	params := map[string]interface{}{
		"promptTokenLimits":     []interface{}{},
		"completionTokenLimits": []interface{}{},
		"totalTokenLimits": []interface{}{
			map[string]interface{}{
				"count":    float64(10),
				"duration": "1m",
			},
		},
	}

	template := map[string]interface{}{
		"spec": map[string]interface{}{
			"promptTokens": map[string]interface{}{
				"identifier": "$.usage.prompt_tokens",
				"location":   "payload",
			},
			"completionTokens": map[string]interface{}{
				"identifier": "$.usage.completion_tokens",
				"location":   "payload",
			},
			"totalTokens": map[string]interface{}{
				"identifier": "$.usage.total_tokens",
				"location":   "payload",
			},
		},
	}

	result := transformToRatelimitParams(params, template, policy.LevelRoute)

	quotas, ok := result["quotas"].([]interface{})
	if !ok {
		t.Fatal("Expected quotas to be []interface{}")
	}

	if len(quotas) != 1 {
		t.Fatalf("Expected only 1 quota (total_tokens), got %d", len(quotas))
	}

	quota, ok := quotas[0].(map[string]interface{})
	if !ok {
		t.Fatalf("Expected quota to be map[string]interface{}, got %T", quotas[0])
	}

	if quota["name"] != "total_tokens" {
		t.Fatalf("Expected quota name total_tokens, got %v", quota["name"])
	}
}

// TestTransformToRatelimitParams_NoTemplatePaths tests transformation without template paths
func TestTransformToRatelimitParams_NoTemplatePaths(t *testing.T) {
	params := map[string]interface{}{
		"promptTokenLimits": []interface{}{
			map[string]interface{}{
				"count":    float64(100),
				"duration": "1m",
			},
		},
	}

	// Template without proper spec paths
	template := map[string]interface{}{}

	result := transformToRatelimitParams(params, template, policy.LevelRoute)

	quotas, ok := result["quotas"].([]interface{})
	if !ok {
		t.Fatal("Expected quotas to be []interface{}")
	}

	if len(quotas) != 1 {
		t.Fatalf("Expected 1 quota, got %d", len(quotas))
	}

	quota := quotas[0].(map[string]interface{})

	// Should have key extraction but no cost extraction
	if _, hasCostExtraction := quota["costExtraction"]; hasCostExtraction {
		t.Error("Expected no costExtraction when template paths are missing")
	}

	if _, hasKeyExtraction := quota["keyExtraction"]; !hasKeyExtraction {
		t.Error("Expected keyExtraction to be present")
	}
}

// TestTokenBasedRateLimitPolicy_TransformToRatelimitParams_TemplateLocationMapping tests
// that different template locations (payload, header, metadata) are correctly mapped to
// their corresponding cost extraction source types.
func TestTokenBasedRateLimitPolicy_TransformToRatelimitParams_TemplateLocationMapping(t *testing.T) {
	params := map[string]interface{}{
		"promptTokenLimits": []interface{}{
			map[string]interface{}{"count": float64(10), "duration": "1m"},
		},
		"completionTokenLimits": []interface{}{
			map[string]interface{}{"count": float64(10), "duration": "1m"},
		},
		"totalTokenLimits": []interface{}{
			map[string]interface{}{"count": float64(10), "duration": "1m"},
		},
	}
	template := map[string]interface{}{
		"spec": map[string]interface{}{
			"promptTokens": map[string]interface{}{
				"location":   "payload",
				"identifier": "$.usage.prompt_tokens",
			},
			"completionTokens": map[string]interface{}{
				"location":   "header",
				"identifier": "x-completion-cost",
			},
			"totalTokens": map[string]interface{}{
				"location":   "metadata",
				"identifier": "usage.total_tokens",
			},
		},
	}

	result := transformToRatelimitParams(params, template, policy.LevelRoute)
	quotas, ok := result["quotas"].([]interface{})
	if !ok {
		t.Fatalf("Expected quotas to be []interface{}, got %T", result["quotas"])
	}

	quotaByName := make(map[string]map[string]interface{})
	for _, q := range quotas {
		qm, ok := q.(map[string]interface{})
		if !ok {
			t.Fatalf("Expected quota map, got %T", q)
		}
		name, _ := qm["name"].(string)
		quotaByName[name] = qm
	}

	getSource := func(quotaName string) map[string]interface{} {
		t.Helper()
		quota := quotaByName[quotaName]
		if quota == nil {
			t.Fatalf("Missing quota %q", quotaName)
		}
		ce, ok := quota["costExtraction"].(map[string]interface{})
		if !ok {
			t.Fatalf("Missing costExtraction for quota %q", quotaName)
		}
		sources, ok := ce["sources"].([]interface{})
		if !ok || len(sources) != 1 {
			t.Fatalf("Expected one source for quota %q, got %v", quotaName, ce["sources"])
		}
		source, ok := sources[0].(map[string]interface{})
		if !ok {
			t.Fatalf("Expected source map for quota %q, got %T", quotaName, sources[0])
		}
		return source
	}

	promptSource := getSource("prompt_tokens")
	if promptSource["type"] != "response_body" || promptSource["jsonPath"] != "$.usage.prompt_tokens" {
		t.Fatalf("Unexpected prompt source mapping: %v", promptSource)
	}

	completionSource := getSource("completion_tokens")
	if completionSource["type"] != "request_header" || completionSource["key"] != "x-completion-cost" {
		t.Fatalf("Unexpected completion source mapping: %v", completionSource)
	}

	totalSource := getSource("total_tokens")
	if totalSource["type"] != "metadata" || totalSource["key"] != "usage.total_tokens" {
		t.Fatalf("Unexpected total source mapping: %v", totalSource)
	}
}

// getQuotaSources is a shared test helper that extracts the costExtraction sources
// for a named quota, or nil if the quota has no costExtraction configured.
func getQuotaSources(t *testing.T, quotas []interface{}, quotaName string) []interface{} {
	t.Helper()
	for _, q := range quotas {
		qm, ok := q.(map[string]interface{})
		if !ok || qm["name"] != quotaName {
			continue
		}
		ce, ok := qm["costExtraction"].(map[string]interface{})
		if !ok {
			return nil
		}
		sources, _ := ce["sources"].([]interface{})
		return sources
	}
	t.Fatalf("quota %q not found", quotaName)
	return nil
}

// TestTransformToRatelimitParams_TotalTokensFallsBackToPromptPlusCompletion covers the
// Anthropic-shaped template (no totalTokens field): the total_tokens quota must sum
// promptTokens + completionTokens instead of falling back to a flat cost of 1.
func TestTransformToRatelimitParams_TotalTokensFallsBackToPromptPlusCompletion(t *testing.T) {
	params := map[string]interface{}{
		"totalTokenLimits": []interface{}{
			map[string]interface{}{"count": float64(30), "duration": "1h"},
		},
	}
	template := map[string]interface{}{
		"spec": map[string]interface{}{
			"promptTokens": map[string]interface{}{
				"location":   "payload",
				"identifier": "$.usage.input_tokens",
			},
			"completionTokens": map[string]interface{}{
				"location":   "payload",
				"identifier": "$.usage.output_tokens",
			},
			// No totalTokens field — matches the built-in anthropic template.
		},
	}

	result := transformToRatelimitParams(params, template, policy.LevelRoute)
	quotas, ok := result["quotas"].([]interface{})
	if !ok {
		t.Fatalf("Expected quotas to be []interface{}, got %T", result["quotas"])
	}

	sources := getQuotaSources(t, quotas, "total_tokens")
	if len(sources) != 2 {
		t.Fatalf("Expected 2 fallback sources (prompt+completion) for total_tokens, got %d: %v", len(sources), sources)
	}

	first := sources[0].(map[string]interface{})
	if first["type"] != "response_body" || first["jsonPath"] != "$.usage.input_tokens" {
		t.Fatalf("Unexpected first fallback source: %v", first)
	}
	second := sources[1].(map[string]interface{})
	if second["type"] != "response_body" || second["jsonPath"] != "$.usage.output_tokens" {
		t.Fatalf("Unexpected second fallback source: %v", second)
	}
}

// TestTransformToRatelimitParams_TotalTokensPreferredOverPromptPlusCompletion guards
// against double-counting: when a template defines totalTokens AND promptTokens/
// completionTokens (the common case — openai, mistral, gemini, etc.), the total_tokens
// quota must use only the totalTokens source, never sum all three.
func TestTransformToRatelimitParams_TotalTokensPreferredOverPromptPlusCompletion(t *testing.T) {
	params := map[string]interface{}{
		"totalTokenLimits": []interface{}{
			map[string]interface{}{"count": float64(1000), "duration": "1h"},
		},
	}
	template := map[string]interface{}{
		"spec": map[string]interface{}{
			"promptTokens": map[string]interface{}{
				"location":   "payload",
				"identifier": "$.usage.prompt_tokens",
			},
			"completionTokens": map[string]interface{}{
				"location":   "payload",
				"identifier": "$.usage.completion_tokens",
			},
			"totalTokens": map[string]interface{}{
				"location":   "payload",
				"identifier": "$.usage.total_tokens",
			},
		},
	}

	result := transformToRatelimitParams(params, template, policy.LevelRoute)
	quotas, ok := result["quotas"].([]interface{})
	if !ok {
		t.Fatalf("Expected quotas to be []interface{}, got %T", result["quotas"])
	}

	sources := getQuotaSources(t, quotas, "total_tokens")
	if len(sources) != 1 {
		t.Fatalf("Expected exactly 1 source for total_tokens when totalTokens is defined, got %d: %v", len(sources), sources)
	}
	source := sources[0].(map[string]interface{})
	if source["type"] != "response_body" || source["jsonPath"] != "$.usage.total_tokens" {
		t.Fatalf("Unexpected total_tokens source: %v", source)
	}
}

// TestTransformToRatelimitParams_TotalTokensNoFieldsAtAll verifies that a template with
// none of totalTokens/promptTokens/completionTokens still produces a quota with no
// costExtraction (existing "no template paths" behavior is preserved for total_tokens).
func TestTransformToRatelimitParams_TotalTokensNoFieldsAtAll(t *testing.T) {
	params := map[string]interface{}{
		"totalTokenLimits": []interface{}{
			map[string]interface{}{"count": float64(30), "duration": "1h"},
		},
	}
	template := map[string]interface{}{"spec": map[string]interface{}{}}

	result := transformToRatelimitParams(params, template, policy.LevelRoute)
	quotas, ok := result["quotas"].([]interface{})
	if !ok {
		t.Fatalf("Expected quotas to be []interface{}, got %T", result["quotas"])
	}

	if sources := getQuotaSources(t, quotas, "total_tokens"); sources != nil {
		t.Fatalf("Expected no costExtraction sources when template defines no token fields, got %v", sources)
	}
}

// TestTransformToRatelimitParams_TotalTokensPartialFallbackWarns verifies that when the
// promptTokens+completionTokens fallback group resolves only one of its two fields, the
// quota still uses the single resolved source (existing behavior is preserved) but a
// warning is logged identifying the incomplete configuration, since the resulting
// total_tokens charge will silently undercount actual usage.
func TestTransformToRatelimitParams_TotalTokensPartialFallbackWarns(t *testing.T) {
	buf := captureSlog(t)

	params := map[string]interface{}{
		"totalTokenLimits": []interface{}{
			map[string]interface{}{"count": float64(30), "duration": "1h"},
		},
	}
	template := map[string]interface{}{
		"spec": map[string]interface{}{
			"promptTokens": map[string]interface{}{
				"location":   "payload",
				"identifier": "$.usage.input_tokens",
			},
			// completionTokens intentionally omitted — partial fallback group.
		},
	}

	result := transformToRatelimitParams(params, template, policy.LevelRoute)
	quotas, ok := result["quotas"].([]interface{})
	if !ok {
		t.Fatalf("Expected quotas to be []interface{}, got %T", result["quotas"])
	}

	sources := getQuotaSources(t, quotas, "total_tokens")
	if len(sources) != 1 {
		t.Fatalf("Expected the single resolved source to still be used, got %d: %v", len(sources), sources)
	}
	source := sources[0].(map[string]interface{})
	if source["type"] != "response_body" || source["jsonPath"] != "$.usage.input_tokens" {
		t.Fatalf("Unexpected source for partial fallback: %v", source)
	}

	logOutput := buf.String()
	if !strings.Contains(logOutput, "only part of a multi-field cost fallback group") {
		t.Fatalf("Expected a warning about the incomplete fallback group, got log output: %s", logOutput)
	}
}

// TestTransformToRatelimitParams_KeyExtraction_APILevel verifies that a policy attached
// at API level (provider-wide / globalPolicies) keys quotas on apiname so all resources
// of the provider share one bucket, mirroring basic-ratelimit's own apiname switch.
func TestTransformToRatelimitParams_KeyExtraction_APILevel(t *testing.T) {
	params := map[string]interface{}{
		"totalTokenLimits": []interface{}{
			map[string]interface{}{"count": float64(1000), "duration": "1h"},
		},
	}

	result := transformToRatelimitParams(params, nil, policy.LevelAPI)
	quotas, ok := result["quotas"].([]interface{})
	if !ok || len(quotas) != 1 {
		t.Fatal("Expected 1 quota")
	}

	quota := quotas[0].(map[string]interface{})
	keyExtraction, ok := quota["keyExtraction"].([]interface{})
	if !ok || len(keyExtraction) != 1 {
		t.Fatalf("Expected 1 key extraction entry, got %v", quota["keyExtraction"])
	}

	entry := keyExtraction[0].(map[string]interface{})
	if entry["type"] != "apiname" {
		t.Errorf("Expected type 'apiname' for API-attached policy, got %v", entry["type"])
	}
}

// TestTransformToRatelimitParams_KeyExtraction_RouteLevel verifies that a policy attached
// at route level (operationPolicies / per-operation) keeps the existing routename keying,
// giving each resource its own independent bucket.
func TestTransformToRatelimitParams_KeyExtraction_RouteLevel(t *testing.T) {
	params := map[string]interface{}{
		"totalTokenLimits": []interface{}{
			map[string]interface{}{"count": float64(1000), "duration": "1h"},
		},
	}

	result := transformToRatelimitParams(params, nil, policy.LevelRoute)
	quotas, ok := result["quotas"].([]interface{})
	if !ok || len(quotas) != 1 {
		t.Fatal("Expected 1 quota")
	}

	quota := quotas[0].(map[string]interface{})
	keyExtraction, ok := quota["keyExtraction"].([]interface{})
	if !ok || len(keyExtraction) != 1 {
		t.Fatalf("Expected 1 key extraction entry, got %v", quota["keyExtraction"])
	}

	entry := keyExtraction[0].(map[string]interface{})
	if entry["type"] != "routename" {
		t.Errorf("Expected type 'routename' for route-attached policy, got %v", entry["type"])
	}
}

// TestTransformToRatelimitParams_KeyExtraction_APILevel_ConsumerBased verifies that
// consumerBased combines with API-level attachment: apiname + application-id metadata.
func TestTransformToRatelimitParams_KeyExtraction_APILevel_ConsumerBased(t *testing.T) {
	params := map[string]interface{}{
		"totalTokenLimits": []interface{}{
			map[string]interface{}{"count": float64(1000), "duration": "1h"},
		},
		"consumerBased": true,
	}

	result := transformToRatelimitParams(params, nil, policy.LevelAPI)
	quotas, ok := result["quotas"].([]interface{})
	if !ok || len(quotas) != 1 {
		t.Fatal("Expected 1 quota")
	}

	quota := quotas[0].(map[string]interface{})
	keyExtraction, ok := quota["keyExtraction"].([]interface{})
	if !ok || len(keyExtraction) != 2 {
		t.Fatalf("Expected 2 key extraction entries, got %v", quota["keyExtraction"])
	}

	first := keyExtraction[0].(map[string]interface{})
	if first["type"] != "apiname" {
		t.Errorf("Expected first entry type 'apiname', got %v", first["type"])
	}
	second := keyExtraction[1].(map[string]interface{})
	if second["type"] != "metadata" || second["key"] != "x-wso2-application-id" {
		t.Errorf("Expected second entry to be application-id metadata, got %v", second)
	}
}

// TestTokenBasedRateLimitPolicy_Mode_ReturnsStream verifies that Mode reports BodyModeStream.
func TestTokenBasedRateLimitPolicy_Mode_ReturnsStream(t *testing.T) {
	p := &TokenBasedRateLimitPolicy{}
	mode := p.Mode()
	if mode.ResponseBodyMode != policy.BodyModeStream {
		t.Errorf("expected ResponseBodyMode=BodyModeStream, got %v", mode.ResponseBodyMode)
	}
}

// TestTokenBasedRateLimitPolicy_NeedsMoreResponseData_ReturnsFalse verifies the streaming
// buffer hint is always false (the delegate manages its own accumulation).
func TestTokenBasedRateLimitPolicy_NeedsMoreResponseData_ReturnsFalse(t *testing.T) {
	p := &TokenBasedRateLimitPolicy{}
	if p.NeedsMoreResponseData([]byte("data: hello")) {
		t.Error("expected NeedsMoreResponseData to return false")
	}
}

// TestTokenBasedRateLimitPolicy_OnResponseBodyChunk_NoProvider verifies that a missing
// provider name in metadata is handled gracefully without panic.
func TestTokenBasedRateLimitPolicy_OnResponseBodyChunk_NoProvider(t *testing.T) {
	p := &TokenBasedRateLimitPolicy{metadata: policy.PolicyMetadata{RouteName: "r"}}
	respCtx := newTokenStreamCtx("")
	chunk := &policy.StreamBody{Chunk: []byte("data: {}"), EndOfStream: true}

	action := p.OnResponseBodyChunk(context.Background(), respCtx, chunk, nil)
	if !reflect.DeepEqual(action, policy.ForwardResponseChunk{}) {
		t.Errorf("expected empty ForwardResponseChunk, got %v", action)
	}
}

// TestTokenBasedRateLimitPolicy_OnResponseBodyChunk_NoDelegateFound verifies that a
// provider name with no cached delegate is handled gracefully.
func TestTokenBasedRateLimitPolicy_OnResponseBodyChunk_NoDelegateFound(t *testing.T) {
	p := &TokenBasedRateLimitPolicy{metadata: policy.PolicyMetadata{RouteName: "r"}}
	respCtx := newTokenStreamCtx("unknown-provider")
	chunk := &policy.StreamBody{Chunk: []byte("data: {}"), EndOfStream: true}

	action := p.OnResponseBodyChunk(context.Background(), respCtx, chunk, nil)
	if !reflect.DeepEqual(action, policy.ForwardResponseChunk{}) {
		t.Errorf("expected empty ForwardResponseChunk, got %v", action)
	}
}

// TestTokenBasedRateLimitPolicy_OnResponseBodyChunk_DelegateCalled verifies that
// OnResponseBodyChunk forwards to the cached delegate when one exists.
func TestTokenBasedRateLimitPolicy_OnResponseBodyChunk_DelegateCalled(t *testing.T) {
	stub := &stubChunkPolicer{}
	p := &TokenBasedRateLimitPolicy{metadata: policy.PolicyMetadata{RouteName: "r"}}
	p.delegates.Store("openai", stub)

	respCtx := newTokenStreamCtx("openai")
	chunks := [][]byte{
		[]byte("data: {\"usage\":{\"total_tokens\":50}}\n"),
		[]byte("data: [DONE]\n"),
	}

	for i, c := range chunks {
		eos := i == len(chunks)-1
		p.OnResponseBodyChunk(context.Background(), respCtx, &policy.StreamBody{Chunk: c, EndOfStream: eos, Index: uint64(i)}, nil)
	}

	if stub.chunkCalls != 2 {
		t.Errorf("expected delegate OnResponseBodyChunk called 2 times, got %d", stub.chunkCalls)
	}
}

// TestTransformToRatelimitParams_ConsumerBased_False verifies that when consumerBased is
// false (or absent), keyExtraction only contains the routename key.
func TestTransformToRatelimitParams_ConsumerBased_False(t *testing.T) {
	params := map[string]interface{}{
		"totalTokenLimits": []interface{}{
			map[string]interface{}{
				"count":    float64(1000),
				"duration": "1h",
			},
		},
		"consumerBased": false,
	}

	result := transformToRatelimitParams(params, nil, policy.LevelRoute)

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
		"totalTokenLimits": []interface{}{
			map[string]interface{}{
				"count":    float64(1000),
				"duration": "1h",
			},
		},
		"consumerBased": true,
	}

	result := transformToRatelimitParams(params, nil, policy.LevelRoute)

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

// stubThrottlingDelegate is a delegate stub whose request-header phase rejects with a
// fixed action, standing in for an advanced-ratelimit delegate whose quota is exhausted.
type stubThrottlingDelegate struct {
	stubChunkPolicer
	onRequestHeadersAction policy.RequestHeaderAction
}

func (s *stubThrottlingDelegate) OnRequestHeaders(context.Context, *policy.RequestHeaderContext, map[string]interface{}) policy.RequestHeaderAction {
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
	const providerName = "fault-passthrough-provider"
	const templateHandle = "fault-passthrough-template"
	store := policy.GetLazyResourceStoreInstance()
	template := &policy.LazyResource{
		ID:           templateHandle,
		ResourceType: ResourceTypeLlmProviderTemplate,
		Resource:     map[string]interface{}{"spec": map[string]interface{}{}},
	}
	for _, r := range []*policy.LazyResource{
		{
			ID:           providerName,
			ResourceType: ResourceTypeProviderTemplateMapping,
			Resource:     map[string]interface{}{"template_handle": templateHandle},
		},
		template,
	} {
		if err := store.StoreResource(r); err != nil {
			t.Fatalf("StoreResource: %v", err)
		}
		t.Cleanup(func() { _ = store.RemoveResourceByIDAndType(r.ID, r.ResourceType) })
	}

	throttled := policy.ImmediateResponse{
		StatusCode: 429,
		Body:       []byte("Message throttled out"),
		IsFault:    true,
		Fault: &policy.FaultDetails{
			Code:      "900800", // API_THROTTLE_OUT_ERROR_CODE
			Type:      "throttling",
			Direction: policy.DirectionRequest,
			Message:   "Message throttled out",
		},
	}
	p := &TokenBasedRateLimitPolicy{metadata: policy.PolicyMetadata{RouteName: "fault-route"}}
	// Cache the stub under the key resolveDelegate computes for this template, so the
	// request path reuses it instead of building a real delegate.
	p.delegates.Store(providerName, &stubThrottlingDelegate{onRequestHeadersAction: throttled})
	p.delegateCacheKeys.Store(providerName, providerName+":"+computeResourceHash(template.Resource))

	action := p.OnRequestHeaders(context.Background(), &policy.RequestHeaderContext{
		SharedContext: &policy.SharedContext{Metadata: map[string]interface{}{
			MetadataKeyProviderName: providerName,
		}},
		Headers: policy.NewHeaders(map[string][]string{}),
	}, map[string]interface{}{})

	resp, ok := action.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("expected ImmediateResponse, got %T", action)
	}
	if !resp.IsFault {
		t.Fatalf("the delegate's IsFault must reach the gateway unchanged")
	}
	if resp.Fault == nil || resp.Fault.Code != "900800" {
		t.Fatalf("the delegate's Fault must reach the gateway unchanged, got %+v", resp.Fault)
	}
}
