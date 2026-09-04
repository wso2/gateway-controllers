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
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

// ─── Helpers ─────────────────────────────────────────────────────────────────

var routeCounter atomic.Int64

// uniqueRoute keeps every test on its own budget. Memory-backed limiters are
// cached process-wide by configuration, so tests that reused a route name would
// inherit each other's spending.
func uniqueRoute(t *testing.T) string {
	t.Helper()
	return fmt.Sprintf("%s-%d", t.Name(), routeCounter.Add(1))
}

func validParams() map[string]interface{} {
	return map[string]interface{}{
		"primary":  map[string]interface{}{"model": "gpt-4o", "provider": "openai-primary"},
		"fallback": map[string]interface{}{"model": "gpt-4o-mini", "provider": "openai-fallback"},
		"budgetLimits": []interface{}{
			map[string]interface{}{"amount": 10.0, "duration": "24h"},
		},
		"requestModel": map[string]interface{}{"location": "header", "identifier": "x-model"},
	}
}

func validMultiRouteParams() map[string]interface{} {
	return map[string]interface{}{
		"modelBudgets": []interface{}{
			map[string]interface{}{
				"name":  "premium",
				"model": map[string]interface{}{"modelName": "gpt-4o", "providerName": "openai-premium"},
				"budgetLimits": []interface{}{
					map[string]interface{}{"amount": 5.0, "duration": "24h"},
				},
			},
			map[string]interface{}{
				"name":  "balanced",
				"model": map[string]interface{}{"modelName": "gpt-4o-mini", "providerName": "openai-balanced"},
				"budgetLimits": []interface{}{
					map[string]interface{}{"amount": 5.0, "duration": "24h"},
				},
			},
			map[string]interface{}{
				"name":  "economy",
				"model": map[string]interface{}{"modelName": "gpt-3.5-turbo", "providerName": "openai-economy"},
				"budgetLimits": []interface{}{
					map[string]interface{}{"amount": 5.0, "duration": "24h"},
				},
			},
		},
		"fallback":     map[string]interface{}{"modelName": "default-model", "providerName": "openai-default"},
		"requestModel": map[string]interface{}{"location": "payload", "identifier": "$.model"},
	}
}

// withFallbackBudget adds a $5 budget for the fallback model to fixtures that exercise
// successful fallback routing. Legacy fixtures are converted to modelBudgets.
func withFallbackBudget(params map[string]interface{}) map[string]interface{} {
	if primary, exists := params["primary"]; exists {
		params["modelBudgets"] = []interface{}{map[string]interface{}{
			"name": tierPrimary, "model": primary, "budgetLimits": params["budgetLimits"],
		}}
		delete(params, "primary")
		delete(params, "budgetLimits")
	}
	if params["fallback"] == nil {
		return params
	}
	params["modelBudgets"] = append(params["modelBudgets"].([]interface{}), map[string]interface{}{
		"name":         tierFallback,
		"model":        params["fallback"],
		"budgetLimits": []interface{}{map[string]interface{}{"amount": 5.0, "duration": "24h"}},
	})
	return params
}

func newPolicyWithFallbackBudget(t *testing.T, params map[string]interface{}) *CostBasedRoutingPolicy {
	t.Helper()
	return newPolicy(t, withFallbackBudget(params))
}

func newPolicy(t *testing.T, params map[string]interface{}) *CostBasedRoutingPolicy {
	t.Helper()
	return newPolicyOnRoute(t, params, uniqueRoute(t))
}

func newPolicyOnRoute(t *testing.T, params map[string]interface{}, route string) *CostBasedRoutingPolicy {
	t.Helper()
	instance, err := GetPolicy(policy.PolicyMetadata{
		RouteName:  route,
		APIName:    "test-api",
		APIVersion: "v1",
		AttachedTo: policy.LevelRoute,
	}, params)
	if err != nil {
		t.Fatalf("GetPolicy failed: %v", err)
	}
	typed, ok := instance.(*CostBasedRoutingPolicy)
	if !ok {
		t.Fatalf("GetPolicy returned %T, want *CostBasedRoutingPolicy", instance)
	}
	return typed
}

// requestHeaders runs the header phase with a fresh per-request metadata map.
func requestHeaders(p *CostBasedRoutingPolicy, path string, seed map[string]interface{}) (policy.RequestHeaderAction, map[string]interface{}) {
	metadata := map[string]interface{}{}
	for k, v := range seed {
		metadata[k] = v
	}
	action := p.OnRequestHeaders(context.Background(), &policy.RequestHeaderContext{
		SharedContext: &policy.SharedContext{Metadata: metadata},
		Path:          path,
		Headers:       policy.NewHeaders(map[string][]string{"x-model": {"gpt-4o"}}),
		Method:        "POST",
	}, nil)
	return action, metadata
}

func requestBody(p *CostBasedRoutingPolicy, metadata map[string]interface{}, body []byte) policy.RequestAction {
	return p.OnRequestBody(context.Background(), &policy.RequestContext{
		SharedContext: &policy.SharedContext{Metadata: metadata},
		Body:          &policy.Body{Content: body, Present: true, EndOfStream: true},
		Path:          "/chat/completions",
		Method:        "POST",
	}, nil)
}

// completeResponse simulates the response phase: llm-cost publishes the cost
// first (response policies run in reverse chain order), then this policy sees
// the end-of-stream chunk.
func completeResponse(p *CostBasedRoutingPolicy, metadata map[string]interface{}, cost string, status string) {
	if status != "" {
		metadata[metadataLLMCostStatus] = status
	}
	if cost != "" {
		metadata[metadataLLMCost] = cost
	}
	streamChunks(p, metadata, 1)
}

func streamChunks(p *CostBasedRoutingPolicy, metadata map[string]interface{}, chunks int) {
	respCtx := &policy.ResponseStreamContext{
		SharedContext:  &policy.SharedContext{Metadata: metadata},
		ResponseStatus: 200,
	}
	for i := 0; i < chunks; i++ {
		p.OnResponseBodyChunk(context.Background(), respCtx, &policy.StreamBody{
			Chunk:       []byte("data: chunk\n\n"),
			EndOfStream: i == chunks-1,
			Index:       uint64(i),
		}, nil)
	}
}

// requestCycle runs a complete request: route, then charge the reported cost.
// It returns the tier that served the request.
func requestCycle(p *CostBasedRoutingPolicy, cost string, seed map[string]interface{}) string {
	_, metadata := requestHeaders(p, "/chat/completions", seed)
	if p.config.RequestModel.Location == "payload" {
		requestBody(p, metadata, []byte(`{"model":"gpt-4o"}`))
	}
	tier, _ := metadata[metadataSelectedTier].(string)
	completeResponse(p, metadata, cost, llmCostStatusCalculated)
	return tier
}

func headerMods(t *testing.T, action policy.RequestHeaderAction) policy.UpstreamRequestHeaderModifications {
	t.Helper()
	mods, ok := action.(policy.UpstreamRequestHeaderModifications)
	if !ok {
		t.Fatalf("expected UpstreamRequestHeaderModifications, got %T (%+v)", action, action)
	}
	return mods
}

func bodyMods(t *testing.T, action policy.RequestAction) policy.UpstreamRequestModifications {
	t.Helper()
	mods, ok := action.(policy.UpstreamRequestModifications)
	if !ok {
		t.Fatalf("expected UpstreamRequestModifications, got %T (%+v)", action, action)
	}
	return mods
}

func payloadModel(t *testing.T, body []byte) string {
	t.Helper()
	var payload map[string]interface{}
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	model, _ := payload["model"].(string)
	return model
}

func immediate(t *testing.T, action interface{}) policy.ImmediateResponse {
	t.Helper()
	response, ok := action.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("expected ImmediateResponse, got %T (%+v)", action, action)
	}
	return response
}

// ─── Mode ────────────────────────────────────────────────────────────────────

func TestModeBuffersRequestBodyOnlyForPayloadLocation(t *testing.T) {
	payloadParams := validParams()
	payloadParams["requestModel"] = map[string]interface{}{"location": "payload", "identifier": "$.model"}
	payload := newPolicyWithFallbackBudget(t, payloadParams)
	if got := payload.Mode().RequestBodyMode; got != policy.BodyModeBuffer {
		t.Errorf("payload location request body mode = %v, want BUFFER", got)
	}

	params := validParams()
	params["requestModel"] = map[string]interface{}{"location": "header", "identifier": "x-model"}
	header := newPolicyWithFallbackBudget(t, params)
	if got := header.Mode().RequestBodyMode; got != policy.BodyModeSkip {
		t.Errorf("header location request body mode = %v, want SKIP", got)
	}

	mode := payload.Mode()
	if mode.RequestHeaderMode != policy.HeaderModeProcess {
		t.Errorf("request header mode = %v, want PROCESS", mode.RequestHeaderMode)
	}
	if mode.ResponseBodyMode != policy.BodyModeStream {
		t.Errorf("response body mode = %v, want STREAM", mode.ResponseBodyMode)
	}
}

// ─── Routing ─────────────────────────────────────────────────────────────────

func TestPrimarySelectedWhileBudgetRemains(t *testing.T) {
	p := newPolicyWithFallbackBudget(t, validParams())

	_, metadata := requestHeaders(p, "/chat/completions", nil)

	if got := metadata[metadataSelectedTier]; got != tierPrimary {
		t.Errorf("tier = %v, want primary", got)
	}
	if got := metadata[metadataSelectedModel]; got != "gpt-4o" {
		t.Errorf("model = %v, want gpt-4o", got)
	}
	if got := metadata[metadataSelectedProvider]; got != "openai-primary" {
		t.Errorf("provider = %v, want openai-primary", got)
	}
	if got := metadata[metadataTrackPrimaryCost]; got != true {
		t.Errorf("track_primary_cost = %v, want true", got)
	}
	if got := metadata[metadataProviderRouting]; got != "openai-primary" {
		t.Errorf("selected_provider = %v, want openai-primary", got)
	}
}

func TestExhaustedModelSkipsOtherModels(t *testing.T) {
	p := newPolicyWithFallbackBudget(t, validMultiRouteParams())
	if route := requestCycle(p, "6.0", nil); route != "premium" {
		t.Fatalf("selected %q", route)
	}
	_, metadata := requestHeaders(p, "/chat/completions", nil)
	mods := bodyMods(t, requestBody(p, metadata, []byte(`{"model":"gpt-4o"}`)))
	if payloadModel(t, mods.Body) != "default-model" || metadata[metadataSelectedTier] != tierFallback {
		t.Fatalf("selection: %+v", metadata)
	}
	if metadata[metadataTrackPrimaryCost] != true {
		t.Fatal("fallback must be charged to its configured budget")
	}
	for _, budget := range p.budgets[1:] {
		_, available, err := budget.store.Query(context.Background(), budget.namespace)
		if err != nil || available != 5*DefaultCostScaleFactor {
			t.Fatalf("unrelated budget changed: %d %v", available, err)
		}
	}
}

func TestRejectsExhaustedRequestedModelWhileOtherBudgetsRemain(t *testing.T) {
	params := validMultiRouteParams()
	params["onExhausted"] = onExhaustedReject
	delete(params, "fallback")
	p := newPolicyWithFallbackBudget(t, params)
	requestCycle(p, "6.0", nil)
	_, metadata := requestHeaders(p, "/chat/completions", nil)
	response := immediate(t, requestBody(p, metadata, []byte(`{"model":"gpt-4o"}`)))
	if response.StatusCode != 429 || !strings.Contains(string(response.Body), "cost_based_routing_budget_exhausted") {
		t.Fatalf("response: %+v", response)
	}
	if _, selected := metadata[metadataSelectedModel]; selected {
		t.Fatal("rejected request selected a model")
	}
}

func TestPayloadRoutingRejectsInBodyPhaseWhenEveryBudgetIsExhausted(t *testing.T) {
	params := validMultiRouteParams()

	params["onExhausted"] = onExhaustedReject
	delete(params, "fallback")
	p := newPolicyWithFallbackBudget(t, params)

	for i := range p.budgets {
		key := p.budgets[i].namespace
		if err := p.budgets[i].store.Charge(context.Background(), key, 6*DefaultCostScaleFactor); err != nil {
			t.Fatalf("exhaust route %d: %v", i, err)
		}
	}

	headerAction, metadata := requestHeaders(p, "/chat/completions", nil)
	headerMods(t, headerAction)
	response := immediate(t, requestBody(p, metadata, []byte(`{"model":"gpt-4o","messages":[]}`)))
	if response.StatusCode != 429 {
		t.Fatalf("status = %d, want 429", response.StatusCode)
	}
	if _, selected := metadata[metadataSelectedModel]; selected {
		t.Error("rejected payload request must not select an upstream model")
	}
}

func TestRequestedPayloadModelUsesItsConfiguredRouteFirst(t *testing.T) {
	params := validMultiRouteParams()

	p := newPolicyWithFallbackBudget(t, params)

	headerAction, metadata := requestHeaders(p, "/chat/completions", nil)
	if mods := headerMods(t, headerAction); mods.UpstreamName != nil {
		t.Fatalf("payload selection must be deferred, got header upstream %q", *mods.UpstreamName)
	}
	bodyAction := requestBody(p, metadata, []byte(`{"model":"gpt-3.5-turbo","messages":[]}`))
	mods := bodyMods(t, bodyAction)
	if got := metadata[metadataSelectedRoute]; got != "economy" {
		t.Fatalf("selected route = %v, want economy", got)
	}
	if mods.UpstreamName == nil || *mods.UpstreamName != "openai-economy" {
		t.Fatalf("upstream = %v, want openai-economy", mods.UpstreamName)
	}
	if got := payloadModel(t, mods.Body); got != "gpt-3.5-turbo" {
		t.Fatalf("payload model = %q, want gpt-3.5-turbo", got)
	}
}

func TestRequestedModelIsReadFromEveryNonPayloadLocation(t *testing.T) {
	tests := []struct {
		name        string
		modelConfig map[string]interface{}
		path        string
		headers     *policy.Headers
	}{
		{
			name:        "header",
			modelConfig: map[string]interface{}{"location": "header", "identifier": "x-model"},
			path:        "/chat/completions",
			headers:     policy.NewHeaders(map[string][]string{"x-model": {"gpt-3.5-turbo"}}),
		},
		{
			name:        "query parameter",
			modelConfig: map[string]interface{}{"location": "queryParam", "identifier": "model"},
			path:        "/chat/completions?model=gpt-3.5-turbo",
		},
		{
			name:        "path parameter",
			modelConfig: map[string]interface{}{"location": "pathParam", "identifier": `models/([^/]+)/invoke`},
			path:        "/models/gpt-3.5-turbo/invoke",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			params := validMultiRouteParams()

			params["requestModel"] = tt.modelConfig
			p := newPolicyWithFallbackBudget(t, params)
			metadata := map[string]interface{}{}
			action := p.OnRequestHeaders(context.Background(), &policy.RequestHeaderContext{
				SharedContext: &policy.SharedContext{Metadata: metadata},
				Headers:       tt.headers,
				Path:          tt.path,
				Method:        "POST",
			}, nil)
			mods := headerMods(t, action)
			if got := metadata[metadataSelectedRoute]; got != "economy" {
				t.Fatalf("selected route = %v, want economy", got)
			}
			if mods.UpstreamName == nil || *mods.UpstreamName != "openai-economy" {
				t.Fatalf("upstream = %v, want openai-economy", mods.UpstreamName)
			}
		})
	}
}

func TestExhaustedRequestedPayloadModelUsesConfiguredFallback(t *testing.T) {
	params := validMultiRouteParams()

	p := newPolicyWithFallbackBudget(t, params)

	_, metadata := requestHeaders(p, "/chat/completions", nil)
	requestBody(p, metadata, []byte(`{"model":"gpt-3.5-turbo"}`))
	if got := metadata[metadataSelectedRoute]; got != "economy" {
		t.Fatalf("first selected route = %v, want economy", got)
	}
	completeResponse(p, metadata, "6.0", llmCostStatusCalculated)

	_, metadata = requestHeaders(p, "/chat/completions", nil)
	bodyAction := requestBody(p, metadata, []byte(`{"model":"gpt-3.5-turbo"}`))
	mods := bodyMods(t, bodyAction)
	if got := metadata[metadataSelectedRoute]; got != tierFallback {
		t.Fatalf("fallback route = %v, want fallback", got)
	}
	if mods.UpstreamName == nil || *mods.UpstreamName != "openai-default" {
		t.Fatalf("fallback upstream = %v, want openai-default", mods.UpstreamName)
	}
	if got := payloadModel(t, mods.Body); got != "default-model" {
		t.Fatalf("fallback payload model = %q, want default-model", got)
	}
}

func TestUnknownRequestedPayloadModelUsesConfiguredFallback(t *testing.T) {
	params := validMultiRouteParams()

	p := newPolicyWithFallbackBudget(t, params)

	_, metadata := requestHeaders(p, "/chat/completions", nil)
	mods := bodyMods(t, requestBody(p, metadata, []byte(`{"model":"client-only-model"}`)))
	if got := metadata[metadataSelectedRoute]; got != tierFallback {
		t.Fatalf("selected route = %v, want fallback", got)
	}
	if got := payloadModel(t, mods.Body); got != "default-model" {
		t.Fatalf("payload model = %q, want default-model", got)
	}
}

func TestRequestedModelMatchingCannotBeDisabled(t *testing.T) {
	params := validMultiRouteParams()
	params["respectRequestedModel"] = false
	if _, err := parseConfig(params); err == nil {
		t.Fatal("removed option accepted")
	}
}

func TestFallbackSelectedWhenBudgetExhausted(t *testing.T) {
	p := newPolicyWithFallbackBudget(t, validParams())

	if tier := requestCycle(p, "12.0", nil); tier != tierPrimary {
		t.Fatalf("first request tier = %q, want primary", tier)
	}

	action, metadata := requestHeaders(p, "/chat/completions", nil)

	if got := metadata[metadataSelectedTier]; got != tierFallback {
		t.Errorf("tier = %v, want fallback", got)
	}
	if got := metadata[metadataSelectedModel]; got != "gpt-4o-mini" {
		t.Errorf("model = %v, want gpt-4o-mini", got)
	}
	if got := metadata[metadataTrackPrimaryCost]; got != true {
		t.Errorf("track_primary_cost = %v, want true", got)
	}
	// Exhaustion is a routing decision: the request continues upstream.
	mods := headerMods(t, action)
	if mods.UpstreamName == nil || *mods.UpstreamName != "openai-fallback" {
		t.Errorf("upstream name = %v, want openai-fallback", mods.UpstreamName)
	}
}

func TestPrimaryExhaustionUsesAvailableFallbackBudget(t *testing.T) {
	p := newPolicyWithFallbackBudget(t, validParams())

	requestCycle(p, "50.0", nil)

	for i := 0; i < 3; i++ {
		action, metadata := requestHeaders(p, "/chat/completions", nil)
		if response, ok := action.(policy.ImmediateResponse); ok {
			t.Fatalf("request %d was short-circuited with status %d; available fallback budget must allow the request", i, response.StatusCode)
		}
		if got := metadata[metadataSelectedTier]; got != tierFallback {
			t.Fatalf("request %d tier = %v, want fallback", i, got)
		}
	}
}

func TestPrimaryAndFallbackShareOneProvider(t *testing.T) {
	params := validParams()
	params["primary"] = map[string]interface{}{"model": "gpt-4o", "provider": "openai"}
	params["fallback"] = map[string]interface{}{"model": "gpt-4o-mini", "provider": "openai"}
	p := newPolicyWithFallbackBudget(t, params)

	action, _ := requestHeaders(p, "/chat/completions", nil)
	if name := headerMods(t, action).UpstreamName; name == nil || *name != "openai" {
		t.Fatalf("primary upstream = %v, want openai", name)
	}

	requestCycle(p, "11.0", nil)

	action, metadata := requestHeaders(p, "/chat/completions", nil)
	if name := headerMods(t, action).UpstreamName; name == nil || *name != "openai" {
		t.Fatalf("fallback upstream = %v, want openai", name)
	}
	if got := metadata[metadataSelectedModel]; got != "gpt-4o-mini" {
		t.Errorf("model = %v, want gpt-4o-mini", got)
	}
}

func TestPrimaryAndFallbackUseDifferentProviders(t *testing.T) {
	params := validParams()
	params["primary"] = map[string]interface{}{"model": "gpt-4o", "provider": "openai-provider"}
	params["fallback"] = map[string]interface{}{"model": "claude-sonnet", "provider": "anthropic-provider"}
	p := newPolicyWithFallbackBudget(t, params)

	action, _ := requestHeaders(p, "/chat/completions", nil)
	if name := headerMods(t, action).UpstreamName; name == nil || *name != "openai-provider" {
		t.Fatalf("primary upstream = %v, want openai-provider", name)
	}

	requestCycle(p, "11.0", nil)

	action, metadata := requestHeaders(p, "/chat/completions", nil)
	mods := headerMods(t, action)
	if mods.UpstreamName == nil || *mods.UpstreamName != "anthropic-provider" {
		t.Fatalf("fallback upstream = %v, want anthropic-provider", mods.UpstreamName)
	}
	if got := metadata[metadataProviderRouting]; got != "anthropic-provider" {
		t.Errorf("selected_provider = %v, want anthropic-provider", got)
	}
	if got := metadata[metadataSelectedModel]; got != "claude-sonnet" {
		t.Errorf("model = %v, want claude-sonnet", got)
	}
}

func TestDefaultProviderTargetDoesNotSetEmptyUpstreamName(t *testing.T) {
	params := validParams()
	params["primary"] = map[string]interface{}{"model": "gpt-4o"}
	params["fallback"] = map[string]interface{}{"model": "gpt-4o-mini"}
	p := newPolicyWithFallbackBudget(t, params)

	action, metadata := requestHeaders(p, "/chat/completions", nil)
	if name := headerMods(t, action).UpstreamName; name != nil {
		t.Errorf("upstream name = %q, want unset for a default-provider target", *name)
	}
	if _, exists := metadata[metadataProviderRouting]; exists {
		t.Error("selected_provider must not be published for a default-provider target")
	}
}

func TestStaleSelectedProviderIsClearedForDefaultProviderTarget(t *testing.T) {
	params := validParams()
	params["primary"] = map[string]interface{}{"model": "gpt-4o"}
	params["fallback"] = map[string]interface{}{"model": "gpt-4o-mini"}
	p := newPolicyWithFallbackBudget(t, params)

	// Another routing policy ran earlier in the chain and left its choice behind.
	_, metadata := requestHeaders(p, "/chat/completions", map[string]interface{}{
		metadataProviderRouting: "some-other-provider",
	})

	if value, exists := metadata[metadataProviderRouting]; exists {
		t.Errorf("stale selected_provider %q was not cleared", value)
	}
}

func TestFallbackWithDefaultProviderClearsPrimaryProviderRouting(t *testing.T) {
	params := validParams()
	params["fallback"] = map[string]interface{}{"model": "gpt-4o-mini"}
	p := newPolicyWithFallbackBudget(t, params)

	requestCycle(p, "11.0", nil)

	action, metadata := requestHeaders(p, "/chat/completions", map[string]interface{}{
		metadataProviderRouting: "openai-primary",
	})
	if name := headerMods(t, action).UpstreamName; name != nil {
		t.Errorf("upstream name = %q, want unset", *name)
	}
	if _, exists := metadata[metadataProviderRouting]; exists {
		t.Error("selected_provider must be cleared when the fallback uses the default provider")
	}
}

// ─── Model rewriting ─────────────────────────────────────────────────────────

func TestPayloadRewriteForBothTiers(t *testing.T) {
	params := validParams()
	params["requestModel"] = map[string]interface{}{"location": "payload", "identifier": "$.model"}
	p := newPolicyWithFallbackBudget(t, params)

	_, metadata := requestHeaders(p, "/chat/completions", nil)
	action := requestBody(p, metadata, []byte(`{"model":"gpt-4o","messages":[]}`))
	mods, ok := action.(policy.UpstreamRequestModifications)
	if !ok {
		t.Fatalf("expected UpstreamRequestModifications, got %T", action)
	}
	if model := modelFromPayload(t, mods.Body); model != "gpt-4o" {
		t.Errorf("primary payload model = %q, want gpt-4o", model)
	}
	completeResponse(p, metadata, "11.0", llmCostStatusCalculated)

	_, metadata = requestHeaders(p, "/chat/completions", nil)
	action = requestBody(p, metadata, []byte(`{"model":"gpt-4o","messages":[]}`))
	mods, _ = action.(policy.UpstreamRequestModifications)
	if model := modelFromPayload(t, mods.Body); model != "gpt-4o-mini" {
		t.Errorf("fallback payload model = %q, want gpt-4o-mini", model)
	}
}

func TestPayloadRewritePreservesOtherFields(t *testing.T) {
	params := validParams()
	params["requestModel"] = map[string]interface{}{"location": "payload", "identifier": "$.model"}
	p := newPolicyWithFallbackBudget(t, params)
	_, metadata := requestHeaders(p, "/chat/completions", nil)

	action := requestBody(p, metadata, []byte(`{"model":"x","temperature":0.7,"messages":[{"role":"user"}]}`))
	mods, _ := action.(policy.UpstreamRequestModifications)

	var payload map[string]interface{}
	if err := json.Unmarshal(mods.Body, &payload); err != nil {
		t.Fatalf("rewritten body is not valid JSON: %v", err)
	}
	if payload["temperature"] != 0.7 {
		t.Errorf("temperature = %v, want 0.7", payload["temperature"])
	}
	if _, ok := payload["messages"].([]interface{}); !ok {
		t.Errorf("messages field was lost: %+v", payload)
	}
}

func TestPayloadRewriteMalformedJSON(t *testing.T) {
	params := validParams()
	params["requestModel"] = map[string]interface{}{"location": "payload", "identifier": "$.model"}
	p := newPolicyWithFallbackBudget(t, params)
	_, metadata := requestHeaders(p, "/chat/completions", nil)

	response := immediate(t, requestBody(p, metadata, []byte(`{"model":`)))
	if response.StatusCode != 400 {
		t.Errorf("status = %d, want 400", response.StatusCode)
	}
	if !strings.Contains(string(response.Body), "malformed JSON") {
		t.Errorf("body = %s, want a malformed-JSON message", response.Body)
	}
}

func TestPayloadRewriteEmptyBody(t *testing.T) {
	params := validParams()
	params["requestModel"] = map[string]interface{}{"location": "payload", "identifier": "$.model"}
	p := newPolicyWithFallbackBudget(t, params)
	_, metadata := requestHeaders(p, "/chat/completions", nil)

	response := immediate(t, requestBody(p, metadata, nil))
	if response.StatusCode != 400 {
		t.Errorf("status = %d, want 400", response.StatusCode)
	}
}

func TestPayloadRewriteNonObjectBody(t *testing.T) {
	params := validParams()
	params["requestModel"] = map[string]interface{}{"location": "payload", "identifier": "$.model"}
	p := newPolicyWithFallbackBudget(t, params)
	_, metadata := requestHeaders(p, "/chat/completions", nil)

	response := immediate(t, requestBody(p, metadata, []byte(`["not","an","object"]`)))
	if response.StatusCode != 400 {
		t.Errorf("status = %d, want 400", response.StatusCode)
	}
}

func TestPayloadRewriteMissingJSONPath(t *testing.T) {
	params := validParams()
	params["requestModel"] = map[string]interface{}{"location": "payload", "identifier": "$.request.model"}
	p := newPolicyWithFallbackBudget(t, params)
	_, metadata := requestHeaders(p, "/chat/completions", nil)

	response := immediate(t, requestBody(p, metadata, []byte(`{"model":"gpt-4o"}`)))
	if response.StatusCode != 400 {
		t.Errorf("status = %d, want 400", response.StatusCode)
	}
	if !strings.Contains(string(response.Body), "$.request.model") {
		t.Errorf("body = %s, want the configured path named", response.Body)
	}
}

func TestRequestBodySkippedForNonPayloadLocations(t *testing.T) {
	params := validParams()
	params["requestModel"] = map[string]interface{}{"location": "header", "identifier": "x-model"}
	p := newPolicyWithFallbackBudget(t, params)
	_, metadata := requestHeaders(p, "/chat/completions", nil)

	action := requestBody(p, metadata, []byte(`{"model":"unchanged"}`))
	mods, ok := action.(policy.UpstreamRequestModifications)
	if !ok {
		t.Fatalf("expected UpstreamRequestModifications, got %T", action)
	}
	if mods.Body != nil {
		t.Errorf("body was rewritten for a header location: %s", mods.Body)
	}
}

func TestRequestBodySelectsWithoutHeaderPhaseSelection(t *testing.T) {
	params := validParams()
	params["requestModel"] = map[string]interface{}{"location": "payload", "identifier": "$.model"}
	p := newPolicyWithFallbackBudget(t, params)
	metadata := map[string]interface{}{}
	mods := bodyMods(t, requestBody(p, metadata, []byte(`{"model":"gpt-4o"}`)))
	if payloadModel(t, mods.Body) != "gpt-4o" {
		t.Fatalf("selection: %+v", metadata)
	}
}

func TestHeaderRewriteForBothTiers(t *testing.T) {
	params := validParams()
	params["requestModel"] = map[string]interface{}{"location": "header", "identifier": "x-model"}
	p := newPolicyWithFallbackBudget(t, params)

	action, metadata := requestHeaders(p, "/chat/completions", nil)
	if got := headerMods(t, action).HeadersToSet["x-model"]; got != "gpt-4o" {
		t.Errorf("primary header = %q, want gpt-4o", got)
	}
	completeResponse(p, metadata, "11.0", llmCostStatusCalculated)

	action, _ = requestHeaders(p, "/chat/completions", nil)
	if got := headerMods(t, action).HeadersToSet["x-model"]; got != "gpt-4o-mini" {
		t.Errorf("fallback header = %q, want gpt-4o-mini", got)
	}
}

func TestQueryParameterRewriteForBothTiers(t *testing.T) {
	params := validParams()
	params["requestModel"] = map[string]interface{}{"location": "queryParam", "identifier": "model"}
	p := newPolicyWithFallbackBudget(t, params)

	action, metadata := requestHeaders(p, "/v1/generate?model=gpt-4o", nil)
	if got := queryValue(t, headerMods(t, action).Path, "model"); got != "gpt-4o" {
		t.Errorf("primary query model = %q, want gpt-4o", got)
	}
	completeResponse(p, metadata, "11.0", llmCostStatusCalculated)

	action, _ = requestHeaders(p, "/v1/generate?model=gpt-4o", nil)
	if got := queryValue(t, headerMods(t, action).Path, "model"); got != "gpt-4o-mini" {
		t.Errorf("fallback query model = %q, want gpt-4o-mini", got)
	}
}

func TestQueryParameterRewritePreservesOtherParameters(t *testing.T) {
	params := validParams()
	params["requestModel"] = map[string]interface{}{"location": "queryParam", "identifier": "model"}
	p := newPolicyWithFallbackBudget(t, params)

	action, _ := requestHeaders(p, "/v1/generate?stream=true&model=gpt-4o&temperature=0.2", nil)
	path := headerMods(t, action).Path
	if path == nil {
		t.Fatal("path was not rewritten")
	}
	if !strings.HasPrefix(*path, "/v1/generate?") {
		t.Errorf("path = %q, want the original path preserved", *path)
	}
	if got := queryValue(t, path, "stream"); got != "true" {
		t.Errorf("stream = %q, want true", got)
	}
	if got := queryValue(t, path, "temperature"); got != "0.2" {
		t.Errorf("temperature = %q, want 0.2", got)
	}
	if got := queryValue(t, path, "model"); got != "gpt-4o" {
		t.Errorf("model = %q, want gpt-4o", got)
	}
}

func TestQueryParameterRewriteAddsMissingParameterAndEscapes(t *testing.T) {
	params := validParams()
	params["fallback"] = map[string]interface{}{"model": "vendor/model name+v2"}
	params["requestModel"] = map[string]interface{}{"location": "queryParam", "identifier": "model"}
	p := newPolicyWithFallbackBudget(t, params)

	action, _ := requestHeaders(p, "/v1/generate?prompt=hello%20world", nil)
	path := headerMods(t, action).Path
	if path == nil {
		t.Fatal("path was not rewritten")
	}
	if got := queryValue(t, path, "model"); got != "vendor/model name+v2" {
		t.Errorf("model = %q, want the escaped value to round-trip", got)
	}
	if got := queryValue(t, path, "prompt"); got != "hello world" {
		t.Errorf("prompt = %q, want 'hello world'", got)
	}
	if strings.Contains(*path, "model name") {
		t.Errorf("path = %q, want the space URL-escaped", *path)
	}
}

func TestPathParameterRewriteForBothTiers(t *testing.T) {
	params := validParams()
	params["requestModel"] = map[string]interface{}{"location": "pathParam", "identifier": `model/([^/]+)/invoke`}
	p := newPolicyWithFallbackBudget(t, params)

	action, metadata := requestHeaders(p, "/bedrock/model/gpt-4o/invoke", nil)
	path := headerMods(t, action).Path
	if path == nil || *path != "/bedrock/model/gpt-4o/invoke" {
		t.Fatalf("primary path = %v, want /bedrock/model/gpt-4o/invoke", path)
	}
	completeResponse(p, metadata, "11.0", llmCostStatusCalculated)

	action, _ = requestHeaders(p, "/bedrock/model/gpt-4o/invoke", nil)
	path = headerMods(t, action).Path
	if path == nil || *path != "/bedrock/model/gpt-4o-mini/invoke" {
		t.Fatalf("fallback path = %v, want /bedrock/model/gpt-4o-mini/invoke", path)
	}
}

func TestPathParameterRewritePreservesQueryString(t *testing.T) {
	params := validParams()
	params["requestModel"] = map[string]interface{}{"location": "pathParam", "identifier": `model/([^/]+)/invoke`}
	p := newPolicyWithFallbackBudget(t, params)

	action, _ := requestHeaders(p, "/bedrock/model/gpt-4o/invoke?stream=true", nil)
	path := headerMods(t, action).Path
	if path == nil || *path != "/bedrock/model/gpt-4o/invoke?stream=true" {
		t.Fatalf("path = %v, want the query string preserved", path)
	}
}

func TestPathParameterRewriteNonMatchingExpression(t *testing.T) {
	params := validParams()
	params["requestModel"] = map[string]interface{}{"location": "pathParam", "identifier": `model/([^/]+)/invoke`}
	p := newPolicyWithFallbackBudget(t, params)

	response := immediate(t, mustAction(requestHeaders(p, "/chat/completions", nil)))
	if response.StatusCode != 400 {
		t.Errorf("status = %d, want 400", response.StatusCode)
	}
	if !strings.Contains(string(response.Body), "did not match") {
		t.Errorf("body = %s, want a non-matching-expression message", response.Body)
	}
}

func TestQueryParameterRewriteInvalidPath(t *testing.T) {
	params := validParams()
	params["requestModel"] = map[string]interface{}{"location": "queryParam", "identifier": "model"}
	p := newPolicyWithFallbackBudget(t, params)

	response := immediate(t, mustAction(requestHeaders(p, "not a valid uri", nil)))
	if response.StatusCode != 400 {
		t.Errorf("status = %d, want 400", response.StatusCode)
	}
}

// ─── Cost accounting ─────────────────────────────────────────────────────────

func TestPrimaryResponseCostIsCharged(t *testing.T) {
	p := newPolicyWithFallbackBudget(t, validParams())

	requestCycle(p, "4.0", nil)

	remaining := availableDollars(t, p, p.budgetNamespace)
	if remaining < 5.99 || remaining > 6.01 {
		t.Errorf("remaining budget = %.4f, want ~6.00", remaining)
	}
}

func TestFallbackCostIsNotChargedToPrimaryBudget(t *testing.T) {
	p := newPolicyWithFallbackBudget(t, validParams())
	key := p.budgetNamespace

	requestCycle(p, "11.0", nil)
	spentAfterPrimary := availableDollars(t, p, key)

	// The next request goes to the fallback; llm-cost still prices it.
	if tier := requestCycle(p, "3.5", nil); tier != tierFallback {
		t.Fatalf("tier = %q, want fallback", tier)
	}

	if got := availableDollars(t, p, key); got != spentAfterPrimary {
		t.Errorf("remaining budget changed from %.4f to %.4f after a fallback request", spentAfterPrimary, got)
	}
}

func TestZeroCostDoesNotConsumeBudget(t *testing.T) {
	p := newPolicyWithFallbackBudget(t, validParams())
	key := p.budgetNamespace

	requestCycle(p, "0", nil)

	if got := availableDollars(t, p, key); got != 10 {
		t.Errorf("remaining budget = %.4f, want 10.00", got)
	}
}

func TestMissingCostMetadataDoesNotConsumeBudget(t *testing.T) {
	p := newPolicyWithFallbackBudget(t, validParams())
	key := p.budgetNamespace

	_, metadata := requestHeaders(p, "/chat/completions", nil)
	streamChunks(p, metadata, 1) // no llm-cost metadata at all

	if got := availableDollars(t, p, key); got != 10 {
		t.Errorf("remaining budget = %.4f, want 10.00", got)
	}
}

func TestNotCalculatedCostStatusDoesNotConsumeBudget(t *testing.T) {
	p := newPolicyWithFallbackBudget(t, validParams())
	key := p.budgetNamespace

	_, metadata := requestHeaders(p, "/chat/completions", nil)
	completeResponse(p, metadata, "0.0000000000", "not_calculated")

	if got := availableDollars(t, p, key); got != 10 {
		t.Errorf("remaining budget = %.4f, want 10.00", got)
	}
}

func TestInvalidCostValuesDoNotConsumeBudget(t *testing.T) {
	for _, cost := range []string{"-1.5", "not-a-number", "NaN", "Inf"} {
		t.Run(cost, func(t *testing.T) {
			p := newPolicyWithFallbackBudget(t, validParams())
			key := p.budgetNamespace

			_, metadata := requestHeaders(p, "/chat/completions", nil)
			completeResponse(p, metadata, cost, llmCostStatusCalculated)

			if got := availableDollars(t, p, key); got != 10 {
				t.Errorf("remaining budget = %.4f, want 10.00 for cost %q", got, cost)
			}
		})
	}
}

func TestCostIsChargedExactlyOnceAcrossManyChunks(t *testing.T) {
	p := newPolicyWithFallbackBudget(t, validParams())
	key := p.budgetNamespace

	_, metadata := requestHeaders(p, "/chat/completions", nil)
	metadata[metadataLLMCostStatus] = llmCostStatusCalculated
	metadata[metadataLLMCost] = "2.5000000000"
	streamChunks(p, metadata, 8)

	remaining := availableDollars(t, p, key)
	if remaining < 7.49 || remaining > 7.51 {
		t.Errorf("remaining budget = %.4f, want ~7.50 (charged once)", remaining)
	}
}

func TestStreamingAndBufferedHooksChargeOnlyOnce(t *testing.T) {
	p := newPolicyWithFallbackBudget(t, validParams())
	key := p.budgetNamespace

	_, metadata := requestHeaders(p, "/chat/completions", nil)
	completeResponse(p, metadata, "3.0000000000", llmCostStatusCalculated)
	// The buffered fallback hook must not deduct a second time.
	p.OnResponseBody(context.Background(), &policy.ResponseContext{
		SharedContext:  &policy.SharedContext{Metadata: metadata},
		ResponseStatus: 200,
	}, nil)

	remaining := availableDollars(t, p, key)
	if remaining < 6.99 || remaining > 7.01 {
		t.Errorf("remaining budget = %.4f, want ~7.00", remaining)
	}
}

func TestBufferedResponseChargesCost(t *testing.T) {
	p := newPolicyWithFallbackBudget(t, validParams())
	key := p.budgetNamespace

	_, metadata := requestHeaders(p, "/chat/completions", nil)
	metadata[metadataLLMCostStatus] = llmCostStatusCalculated
	metadata[metadataLLMCost] = "2.0000000000"
	p.OnResponseBody(context.Background(), &policy.ResponseContext{
		SharedContext:  &policy.SharedContext{Metadata: metadata},
		ResponseStatus: 200,
	}, nil)

	remaining := availableDollars(t, p, key)
	if remaining < 7.99 || remaining > 8.01 {
		t.Errorf("remaining budget = %.4f, want ~8.00", remaining)
	}
}

func TestChunksAreForwardedUnchanged(t *testing.T) {
	p := newPolicyWithFallbackBudget(t, validParams())
	_, metadata := requestHeaders(p, "/chat/completions", nil)

	respCtx := &policy.ResponseStreamContext{
		SharedContext:  &policy.SharedContext{Metadata: metadata},
		ResponseStatus: 200,
	}
	action := p.OnResponseBodyChunk(context.Background(), respCtx,
		&policy.StreamBody{Chunk: []byte("data: hello\n\n")}, nil)

	forward, ok := action.(policy.ForwardResponseChunk)
	if !ok {
		t.Fatalf("expected ForwardResponseChunk, got %T", action)
	}
	if forward.Body != nil {
		t.Errorf("chunk body was replaced with %q, want passthrough", forward.Body)
	}
	if forward.TerminateStream() {
		t.Error("stream must not be terminated")
	}
}

// ─── Overshoot and reset semantics ───────────────────────────────────────────

func TestRequestCrossingTheBudgetStillReturnsPrimaryAndTheNextUsesFallback(t *testing.T) {
	p := newPolicyWithFallbackBudget(t, validParams())
	key := p.budgetNamespace

	// $9.90 spent, budget $10.
	if tier := requestCycle(p, "9.90", nil); tier != tierPrimary {
		t.Fatalf("request 1 tier = %q, want primary", tier)
	}

	// This request passes the pre-check and costs $0.20 — total $10.10.
	action, metadata := requestHeaders(p, "/chat/completions", nil)
	if got := metadata[metadataSelectedTier]; got != tierPrimary {
		t.Fatalf("request 2 tier = %v, want primary", got)
	}
	if _, ok := action.(policy.ImmediateResponse); ok {
		t.Fatal("the crossing request must not be short-circuited")
	}
	completeResponse(p, metadata, "0.20", llmCostStatusCalculated)

	if got := availableDollars(t, p, key); got != 0 {
		t.Errorf("remaining budget = %.4f, want 0 after the overshoot", got)
	}

	// Only the following request is routed to the fallback.
	_, metadata = requestHeaders(p, "/chat/completions", nil)
	if got := metadata[metadataSelectedTier]; got != tierFallback {
		t.Errorf("request 3 tier = %v, want fallback", got)
	}
}

func TestPrimaryBecomesAvailableAfterWindowReset(t *testing.T) {
	params := validParams()
	params["budgetLimits"] = []interface{}{map[string]interface{}{"amount": 1.0, "duration": "200ms"}}
	p := newPolicyWithFallbackBudget(t, params)

	if tier := requestCycle(p, "2.0", nil); tier != tierPrimary {
		t.Fatalf("first request tier = %q, want primary", tier)
	}
	_, metadata := requestHeaders(p, "/chat/completions", nil)
	if got := metadata[metadataSelectedTier]; got != tierFallback {
		t.Fatalf("tier = %v, want fallback while the window is exhausted", got)
	}

	// Fixed windows are aligned to the epoch, so sleeping past one full window
	// guarantees the counter has rolled over.
	time.Sleep(450 * time.Millisecond)

	_, metadata = requestHeaders(p, "/chat/completions", nil)
	if got := metadata[metadataSelectedTier]; got != tierPrimary {
		t.Errorf("tier = %v, want primary after the window reset", got)
	}
}

func TestStrictestBudgetWindowWins(t *testing.T) {
	params := validParams()
	params["budgetLimits"] = []interface{}{
		map[string]interface{}{"amount": 2.0, "duration": "1h"},
		map[string]interface{}{"amount": 20.0, "duration": "24h"},
	}
	p := newPolicyWithFallbackBudget(t, params)

	// $3 exhausts the hourly window but leaves the daily one with $17.
	if tier := requestCycle(p, "3.0", nil); tier != tierPrimary {
		t.Fatalf("first request tier = %q, want primary", tier)
	}

	_, metadata := requestHeaders(p, "/chat/completions", nil)
	if got := metadata[metadataSelectedTier]; got != tierFallback {
		t.Errorf("tier = %v, want fallback because the hourly window is exhausted", got)
	}
}

func TestLooserWindowAloneDoesNotExhaustTheBudget(t *testing.T) {
	params := validParams()
	params["budgetLimits"] = []interface{}{
		map[string]interface{}{"amount": 2.0, "duration": "1h"},
		map[string]interface{}{"amount": 20.0, "duration": "24h"},
	}
	p := newPolicyWithFallbackBudget(t, params)

	if tier := requestCycle(p, "1.0", nil); tier != tierPrimary {
		t.Fatalf("first request tier = %q, want primary", tier)
	}
	_, metadata := requestHeaders(p, "/chat/completions", nil)
	if got := metadata[metadataSelectedTier]; got != tierPrimary {
		t.Errorf("tier = %v, want primary while both windows have capacity", got)
	}
}

// ─── Budget scope ────────────────────────────────────────────────────────────

func TestSharedBudgetIsSharedAcrossConsumers(t *testing.T) {
	p := newPolicyWithFallbackBudget(t, validParams())

	appA := map[string]interface{}{"x-wso2-application-id": "app-a"}
	appB := map[string]interface{}{"x-wso2-application-id": "app-b"}

	requestCycle(p, "11.0", appA)

	_, metadata := requestHeaders(p, "/chat/completions", appB)
	if got := metadata[metadataSelectedTier]; got != tierFallback {
		t.Errorf("app-b tier = %v, want fallback; the route budget is shared", got)
	}
}

func TestConcurrentRequestsAreRaceSafe(t *testing.T) {
	params := validParams()
	params["budgetLimits"] = []interface{}{map[string]interface{}{"amount": 100.0, "duration": "24h"}}
	p := newPolicyWithFallbackBudget(t, params)
	key := p.budgetNamespace

	const workers = 32
	var wg sync.WaitGroup
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			requestCycle(p, "1.0", nil)
		}()
	}
	wg.Wait()

	// Every charge must land: 32 × $1 against a $100 budget.
	remaining := availableDollars(t, p, key)
	if remaining < 67.99 || remaining > 68.01 {
		t.Errorf("remaining budget = %.4f, want ~68.00 after 32 concurrent $1 requests", remaining)
	}
}

func TestDocumentedRequestSequence(t *testing.T) {
	params := validParams()
	params["budgetLimits"] = []interface{}{map[string]interface{}{"amount": 10.0, "duration": "200ms"}}
	p := newPolicyWithFallbackBudget(t, params)

	if tier := requestCycle(p, "4.0", nil); tier != tierPrimary {
		t.Errorf("request 1 tier = %q, want primary", tier)
	}
	if tier := requestCycle(p, "7.0", nil); tier != tierPrimary {
		t.Errorf("request 2 tier = %q, want primary (it may overshoot to $11)", tier)
	}
	if tier := requestCycle(p, "1.0", nil); tier != tierFallback {
		t.Errorf("request 3 tier = %q, want fallback", tier)
	}

	time.Sleep(450 * time.Millisecond)

	if tier := requestCycle(p, "1.0", nil); tier != tierPrimary {
		t.Errorf("request 4 tier = %q, want primary after the window reset", tier)
	}
}

// ─── Small helpers ───────────────────────────────────────────────────────────

func mustAction(action policy.RequestHeaderAction, _ map[string]interface{}) policy.RequestHeaderAction {
	return action
}

func modelFromPayload(t *testing.T, body []byte) string {
	t.Helper()
	if body == nil {
		t.Fatal("request body was not rewritten")
	}
	var payload map[string]interface{}
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatalf("rewritten body is not valid JSON: %v", err)
	}
	model, _ := payload["model"].(string)
	return model
}

func queryValue(t *testing.T, path *string, name string) string {
	t.Helper()
	if path == nil {
		t.Fatal("path was not rewritten")
	}
	parsed, err := url.ParseRequestURI(*path)
	if err != nil {
		t.Fatalf("rewritten path %q is not a valid request URI: %v", *path, err)
	}
	return parsed.Query().Get(name)
}

// availableDollars reads the remaining budget straight from the storage layer.
func availableDollars(t *testing.T, p *CostBasedRoutingPolicy, key string) float64 {
	t.Helper()
	_, available, err := p.budget.Query(context.Background(), key)
	if err != nil {
		t.Fatalf("budget query failed: %v", err)
	}
	return float64(available) / float64(p.config.CostScaleFactor)
}

// wildcardParams puts the wildcard budget first to verify order never gives it
// priority over an exact requested-model match.
func wildcardParams(alias string) map[string]interface{} {
	params := validMultiRouteParams()
	params["modelBudgets"] = append([]interface{}{map[string]interface{}{
		"name":         "unlisted-budget",
		"model":        map[string]interface{}{"modelName": alias},
		"budgetLimits": []interface{}{map[string]interface{}{"amount": 2.0, "duration": "24h"}},
	}}, params["modelBudgets"].([]interface{})...)
	return params
}

func TestUnlistedModelBudgetIsChargedOnceThenRejects(t *testing.T) {
	for _, alias := range []string{"*", "other"} {
		t.Run(alias, func(t *testing.T) {
			p := newPolicy(t, wildcardParams(alias))
			for _, requested := range []string{"gpt-5.5", "another-model", "third-model", "gpt-5.5"} {
				_, metadata := requestHeaders(p, "/chat/completions", nil)
				body, _ := json.Marshal(map[string]string{"model": requested})
				mods := bodyMods(t, requestBody(p, metadata, body))
				if payloadModel(t, mods.Body) != requested || mods.UpstreamName != nil {
					t.Fatalf("wildcard must preserve requested model on the primary provider: %+v", mods)
				}
				if metadata[metadataSelectedRoute] != "unlisted-budget" || metadata[metadataSelectedTier] != tierWildcard {
					t.Fatalf("metadata: %+v", metadata)
				}
				completeResponse(p, metadata, "0.5", llmCostStatusCalculated)
				p.OnResponseBody(context.Background(), &policy.ResponseContext{SharedContext: &policy.SharedContext{Metadata: metadata}}, nil)
			}
			for i := 0; i < 3; i++ {
				_, metadata := requestHeaders(p, "/chat/completions", nil)
				response := immediate(t, requestBody(p, metadata, []byte(`{"model":"unknown-model"}`)))
				if response.StatusCode != 429 {
					t.Fatalf("status: %d", response.StatusCode)
				}
				if _, selected := metadata[metadataSelectedModel]; selected {
					t.Fatal("exhausted fallback selected a model")
				}
			}
			// Exhausted wildcard cannot block a known model with its own budget.
			_, metadata := requestHeaders(p, "/chat/completions", nil)
			mods := bodyMods(t, requestBody(p, metadata, []byte(`{"model":"gpt-4o"}`)))
			if payloadModel(t, mods.Body) != "gpt-4o" || metadata[metadataSelectedRoute] != "premium" {
				t.Fatalf("selection: %+v", metadata)
			}
			completeResponse(p, metadata, "1.0", llmCostStatusCalculated)
			_, available, err := p.budgets[1].store.Query(context.Background(), p.budgets[1].namespace)
			if err != nil || available != 4*DefaultCostScaleFactor {
				t.Fatalf("model budget remaining: %d, %v", available, err)
			}
		})
	}
}

func TestExhaustedConfiguredModelCannotUseWildcard(t *testing.T) {
	p := newPolicy(t, wildcardParams("*"))
	if got := requestCycle(p, "6.0", nil); got != "premium" {
		t.Fatalf("first selection: %q", got)
	}
	_, metadata := requestHeaders(p, "/chat/completions", nil)
	response := immediate(t, requestBody(p, metadata, []byte(`{"model":"gpt-4o"}`)))
	if response.StatusCode != 429 {
		t.Fatalf("status: %d", response.StatusCode)
	}
	_, available, err := p.budgets[0].store.Query(context.Background(), p.budgets[0].namespace)
	if err != nil || available != 2*DefaultCostScaleFactor {
		t.Fatalf("wildcard was used: %d %v", available, err)
	}
}

func TestFallbackOwnModelBudgetCannotBeBypassed(t *testing.T) {
	params := validMultiRouteParams()
	params["fallback"] = map[string]interface{}{"modelName": "gpt-4o-mini", "providerName": "openai-balanced"}
	p := newPolicy(t, params)
	_, metadata := requestHeaders(p, "/chat/completions", nil)
	mods := bodyMods(t, requestBody(p, metadata, []byte(`{"model":"unknown-model"}`)))
	if payloadModel(t, mods.Body) != "gpt-4o-mini" || metadata[metadataSelectedRoute] != "balanced" {
		t.Fatalf("selection: %+v", metadata)
	}
	completeResponse(p, metadata, "6.0", llmCostStatusCalculated)
	for _, requested := range []string{"unknown-model", "gpt-4o-mini"} {
		_, metadata := requestHeaders(p, "/chat/completions", nil)
		body, _ := json.Marshal(map[string]string{"model": requested})
		response := immediate(t, requestBody(p, metadata, body))
		if response.StatusCode != 429 {
			t.Fatalf("status: %d", response.StatusCode)
		}
	}
}

func TestRejectModeUsesWildcardUntilExhausted(t *testing.T) {
	params := wildcardParams("*")
	params["onExhausted"] = "reject"
	params["fallback"] = map[string]interface{}{"modelName": "gpt-4o-mini", "providerName": "openai-balanced"}
	p := newPolicy(t, params)
	_, metadata := requestHeaders(p, "/chat/completions", nil)
	mods := bodyMods(t, requestBody(p, metadata, []byte(`{"model":"gpt-5.5"}`)))
	if payloadModel(t, mods.Body) != "gpt-5.5" {
		t.Fatal("wildcard did not preserve requested model")
	}
	completeResponse(p, metadata, "3.0", llmCostStatusCalculated)
	_, metadata = requestHeaders(p, "/chat/completions", nil)
	response := immediate(t, requestBody(p, metadata, []byte(`{"model":"gpt-5.5"}`)))
	if response.StatusCode != 429 {
		t.Fatalf("status: %d", response.StatusCode)
	}
}

func TestWildcardHeaderRequestPreservesModelAndUsesPrimaryProvider(t *testing.T) {
	params := wildcardParams("*")
	params["requestModel"] = map[string]interface{}{"location": "header", "identifier": "x-model"}
	p := newPolicy(t, params)
	metadata := map[string]interface{}{}
	action := p.OnRequestHeaders(context.Background(), &policy.RequestHeaderContext{
		SharedContext: &policy.SharedContext{Metadata: metadata},
		Headers:       policy.NewHeaders(map[string][]string{"x-model": {"unknown-model"}}),
	}, nil)
	mods := headerMods(t, action)
	if mods.HeadersToSet["x-model"] != "unknown-model" || metadata[metadataProviderRouting] != nil || mods.UpstreamName != nil {
		t.Fatalf("selection: %+v, %+v", mods, metadata)
	}
	completeResponse(p, metadata, "3.0", llmCostStatusCalculated)
	response := immediate(t, p.OnRequestHeaders(context.Background(), &policy.RequestHeaderContext{
		SharedContext: &policy.SharedContext{Metadata: map[string]interface{}{}},
	}, nil))
	if response.StatusCode != 429 {
		t.Fatalf("status: %d", response.StatusCode)
	}
}

func TestWildcardBudgetStorageFailureModes(t *testing.T) {
	for _, failOpen := range []bool{false, true} {
		t.Run(fmt.Sprint(failOpen), func(t *testing.T) {
			p := newPolicy(t, wildcardParams("*"))
			stub := &failingLimiter{}
			p.budget = &budgetStore{lim: stub, tracker: stub, backend: "redis", failOpen: failOpen}
			_, metadata := requestHeaders(p, "/chat/completions", nil)
			action := requestBody(p, metadata, []byte(`{"model":"unknown-model"}`))
			if failOpen {
				if payloadModel(t, bodyMods(t, action).Body) != "unknown-model" {
					t.Fatal("wrong wildcard model")
				}
			} else if response := immediate(t, action); response.StatusCode != 503 {
				t.Fatalf("status: %d", response.StatusCode)
			}
			if stub.queries.Load() != 1 {
				t.Fatalf("fallback queried %d times", stub.queries.Load())
			}
		})
	}
}

func TestSelectionTraceIncludesActualModelAndProvider(t *testing.T) {
	var output bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&output, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(previous) })
	p := newPolicy(t, wildcardParams("*"))
	_, metadata := requestHeaders(p, "/chat/completions", nil)
	bodyMods(t, requestBody(p, metadata, []byte(`{"model":"unknown-model"}`)))
	var entry map[string]interface{}
	if err := json.Unmarshal(bytes.TrimSpace(output.Bytes()), &entry); err != nil {
		t.Fatalf("decode log: %v; %s", err, output.Bytes())
	}
	for key, want := range map[string]interface{}{
		"msg": "CostBasedRouting: selected model", "requestedModel": "unknown-model",
		"modelName": "unknown-model", "providerName": "", "modelBudget": "unlisted-budget",
		"selectionTier": "wildcard", "policyLevel": string(policy.LevelRoute),
	} {
		if entry[key] != want {
			t.Errorf("%s = %v, want %v", key, entry[key], want)
		}
	}
}

func TestMissingFallbackBudgetRejectsAcrossModelLocations(t *testing.T) {
	for _, location := range []string{"payload", "header", "queryParam", "pathParam"} {
		for _, requested := range []string{"unknown-model", "gpt-4o"} {
			t.Run(location+"/"+requested, func(t *testing.T) {
				params := validMultiRouteParams() // Fallback has neither a wildcard nor its own budget.
				identifiers := map[string]string{"payload": "$.model", "header": "x-model", "queryParam": "model", "pathParam": "models/([^/]+)/invoke"}
				params["requestModel"] = map[string]interface{}{"location": location, "identifier": identifiers[location]}
				p := newPolicy(t, params)
				if err := p.budgets[0].store.Charge(context.Background(), p.budgets[0].namespace, 6*DefaultCostScaleFactor); err != nil {
					t.Fatal(err)
				}
				metadata := map[string]interface{}{}
				path := "/chat/completions"
				if location == "queryParam" {
					path += "?model=" + requested
				}
				if location == "pathParam" {
					path = "/models/" + requested + "/invoke"
				}
				headerAction := p.OnRequestHeaders(context.Background(), &policy.RequestHeaderContext{
					SharedContext: &policy.SharedContext{Metadata: metadata},
					Path:          path,
					Headers:       policy.NewHeaders(map[string][]string{"x-model": {requested}}),
				}, nil)
				var action interface{} = headerAction
				if location == "payload" {
					headerMods(t, headerAction)
					body, _ := json.Marshal(map[string]string{"model": requested})
					action = requestBody(p, metadata, body)
				}
				response := immediate(t, action)
				if response.StatusCode != 429 {
					t.Fatalf("status = %d, want 429", response.StatusCode)
				}
				for _, key := range []string{metadataSelectedModel, metadataProviderRouting, metadataBudgetKey, metadataBudgetIndex} {
					if _, exists := metadata[key]; exists {
						t.Errorf("rejected request recorded %s", key)
					}
				}
				completeResponse(p, metadata, "1.0", llmCostStatusCalculated)
				for _, budget := range p.budgets[1:] {
					_, available, err := budget.store.Query(context.Background(), budget.namespace)
					if err != nil || available != 5*DefaultCostScaleFactor {
						t.Fatalf("unrelated model budget changed: %d, %v", available, err)
					}
				}
			})
		}
	}
}

func TestLegacyPrimaryBudgetExhaustionCannotUseUnbudgetedFallback(t *testing.T) {
	p := newPolicy(t, validParams())
	if tier := requestCycle(p, "11.0", nil); tier != tierPrimary {
		t.Fatalf("first request = %s", tier)
	}
	for i := 0; i < 3; i++ {
		action, metadata := requestHeaders(p, "/chat/completions", nil)
		if response := immediate(t, action); response.StatusCode != 429 {
			t.Fatalf("status = %d", response.StatusCode)
		}
		if _, exists := metadata[metadataSelectedModel]; exists {
			t.Fatal("unbudgeted fallback selected")
		}
	}
}

func TestWildcardExhaustionUsesFallbackOwnBudgetThenRejects(t *testing.T) {
	for _, alias := range []string{"*", "other"} {
		for _, location := range []string{"payload", "header", "queryParam", "pathParam"} {
			t.Run(alias+"/"+location, func(t *testing.T) {
				params := wildcardParams(alias)
				params["fallback"] = map[string]interface{}{"modelName": "gpt-4o-mini", "providerName": "openai-balanced"}
				identifiers := map[string]string{"payload": "$.model", "header": "x-model", "queryParam": "model", "pathParam": "models/([^/]+)/invoke"}
				params["requestModel"] = map[string]interface{}{"location": location, "identifier": identifiers[location]}
				p := newPolicy(t, params)
				route := func(requested string) (interface{}, map[string]interface{}) {
					metadata := map[string]interface{}{metadataProviderRouting: "stale-provider"}
					path := "/chat/completions"
					if location == "queryParam" {
						path += "?model=" + requested
					}
					if location == "pathParam" {
						path = "/models/" + requested + "/invoke"
					}
					action := p.OnRequestHeaders(context.Background(), &policy.RequestHeaderContext{
						SharedContext: &policy.SharedContext{Metadata: metadata}, Path: path,
						Headers: policy.NewHeaders(map[string][]string{"x-model": {requested}}),
					}, nil)
					if location == "payload" {
						headerMods(t, action)
						body, _ := json.Marshal(map[string]string{"model": requested})
						return requestBody(p, metadata, body), metadata
					}
					return action, metadata
				}
				// Four requests: consume wildcard, direct fallback-model request, and
				// two fallback requests sharing that model's remaining budget.
				for i, step := range []struct{ requested, model, tier, cost string }{
					{"gpt-5.5", "gpt-5.5", tierWildcard, "2.0"},
					{"gpt-4o-mini", "gpt-4o-mini", "balanced", "1.0"},
					{"gpt-5.5", "gpt-4o-mini", tierFallback, "3.0"},
					{"another-unlisted-model", "gpt-4o-mini", tierFallback, "1.0"},
				} {
					action, metadata := route(step.requested)
					if response, rejected := action.(policy.ImmediateResponse); rejected {
						t.Fatalf("step %d rejected: %+v", i, response)
					}
					if metadata[metadataSelectedModel] != step.model || metadata[metadataSelectedTier] != step.tier {
						t.Fatalf("step %d selection: %+v", i, metadata)
					}
					if step.tier == tierWildcard {
						if metadata[metadataProviderRouting] != nil {
							t.Fatal("wildcard retained stale provider")
						}
					} else if metadata[metadataProviderRouting] != "openai-balanced" {
						t.Fatal("fallback provider was not selected")
					}
					if location == "payload" {
						if payloadModel(t, bodyMods(t, action.(policy.RequestAction)).Body) != step.model {
							t.Fatal("payload model not rewritten")
						}
					} else {
						mods := headerMods(t, action.(policy.RequestHeaderAction))
						if location == "header" && mods.HeadersToSet["x-model"] != step.model {
							t.Fatal("header model not rewritten")
						}
						if location == "queryParam" && queryValue(t, mods.Path, "model") != step.model {
							t.Fatal("query model not rewritten")
						}
						if location == "pathParam" && (mods.Path == nil || *mods.Path != "/models/"+step.model+"/invoke") {
							t.Fatal("path model not rewritten")
						}
					}
					completeResponse(p, metadata, step.cost, llmCostStatusCalculated)
					p.OnResponseBody(context.Background(), &policy.ResponseContext{SharedContext: &policy.SharedContext{Metadata: metadata}}, nil)
				}
				for _, requested := range []string{"gpt-5.5", "gpt-4o-mini", "gpt-5.5"} {
					action, metadata := route(requested)
					if response := immediate(t, action); response.StatusCode != 429 {
						t.Fatalf("status %d", response.StatusCode)
					}
					if _, exists := metadata[metadataSelectedModel]; exists {
						t.Fatal("rejected request selected a model")
					}
				}
				// An unrelated model remains eligible even after wildcard and fallback exhaust.
				action, metadata := route("gpt-4o")
				if _, rejected := action.(policy.ImmediateResponse); rejected || metadata[metadataSelectedModel] != "gpt-4o" {
					t.Fatal("unrelated model was blocked")
				}
				_, available, err := p.budgets[1].store.Query(context.Background(), p.budgets[1].namespace)
				if err != nil || available != 5*DefaultCostScaleFactor {
					t.Fatalf("unrelated budget changed: %d %v", available, err)
				}
			})
		}
	}
}

func TestExhaustedFallbackNeverRetriesAvailableWildcard(t *testing.T) {
	params := wildcardParams("*")
	params["fallback"] = map[string]interface{}{"modelName": "gpt-4o-mini"}
	p := newPolicy(t, params)
	for _, index := range []int{1, 2} {
		if err := p.budgets[index].store.Charge(context.Background(), p.budgets[index].namespace, 6*DefaultCostScaleFactor); err != nil {
			t.Fatal(err)
		}
	}
	for _, requested := range []string{"gpt-4o", "gpt-4o-mini", "*", "other", ""} {
		_, metadata := requestHeaders(p, "/chat/completions", nil)
		body, _ := json.Marshal(map[string]string{"model": requested})
		response := immediate(t, requestBody(p, metadata, body))
		if response.StatusCode != 429 {
			t.Fatalf("requested %q status %d", requested, response.StatusCode)
		}
	}
	_, available, err := p.budgets[0].store.Query(context.Background(), p.budgets[0].namespace)
	if err != nil || available != 2*DefaultCostScaleFactor {
		t.Fatalf("wildcard used as fallback: %d %v", available, err)
	}
}
