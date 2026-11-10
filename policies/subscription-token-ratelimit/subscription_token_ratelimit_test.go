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

package subscriptiontokenratelimit

import (
	"context"
	"fmt"
	"testing"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

const usageBody = `{"usage":{"prompt_tokens":30,"completion_tokens":50,"total_tokens":80}}`

// storeTemplate registers an LLM provider template the way the gateway does.
func storeTemplate(t *testing.T, provider string, spec map[string]interface{}) {
	t.Helper()
	store := policy.GetLazyResourceStoreInstance()
	handle := provider + "-template"
	for _, r := range []*policy.LazyResource{
		{ID: provider, ResourceType: resourceTypeProviderTemplateMapping, Resource: map[string]interface{}{"template_handle": handle}},
		{ID: handle, ResourceType: resourceTypeLlmProviderTemplate, Resource: map[string]interface{}{"spec": spec}},
	} {
		if err := store.StoreResource(r); err != nil {
			t.Fatalf("StoreResource: %v", err)
		}
		r := r
		t.Cleanup(func() { _ = store.RemoveResourceByIDAndType(r.ID, r.ResourceType) })
	}
}

func openAISpec() map[string]interface{} {
	return map[string]interface{}{
		"promptTokens":     map[string]interface{}{"identifier": "$.usage.prompt_tokens", "location": "payload"},
		"completionTokens": map[string]interface{}{"identifier": "$.usage.completion_tokens", "location": "payload"},
		"totalTokens":      map[string]interface{}{"identifier": "$.usage.total_tokens", "location": "payload"},
	}
}

func tokenConditions(count int, tokenType, onExceed string) string {
	return fmt.Sprintf(`[{"id":"tokens","type":"token-count","params":{"limits":[{"count":%d,"timeAmount":1,"timeUnit":"DAY"}],"tokenType":"%s","onExceed":"%s"}}]`,
		count, tokenType, onExceed)
}

func newPolicy(t *testing.T) *SubscriptionTokenRateLimitPolicy {
	t.Helper()
	p, err := GetPolicy(policy.PolicyMetadata{RouteName: "chat", APIName: t.Name()}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return p.(*SubscriptionTokenRateLimitPolicy)
}

// call runs one LLM call through the policy and returns the request-phase action.
func call(t *testing.T, p *SubscriptionTokenRateLimitPolicy, subID, provider, conditions, body string) policy.RequestHeaderAction {
	t.Helper()
	md := map[string]interface{}{metadataKeyProviderName: provider}
	if subID != "" {
		md[metadataKeySubscriptionID] = subID
		md[metadataKeyPlanID] = "plan-1"
		md[metadataKeyPlanConditions] = conditions
	}
	shared := &policy.SharedContext{APIId: "api-1", APIName: t.Name(), APIKind: policy.APIKindLlmProvider, Metadata: md}
	action := p.OnRequestHeaders(context.Background(), &policy.RequestHeaderContext{
		SharedContext: shared,
		Headers:       policy.NewHeaders(nil),
		Method:        "POST",
		Path:          "/chat/completions",
	}, nil)
	if _, blocked := action.(policy.ImmediateResponse); blocked {
		return action
	}
	headers := policy.NewHeaders(map[string][]string{"content-type": {"application/json"}})
	p.OnResponseHeaders(context.Background(), &policy.ResponseHeaderContext{
		SharedContext:   shared,
		ResponseHeaders: headers,
		ResponseStatus:  200,
	}, nil)
	p.OnResponseBody(context.Background(), &policy.ResponseContext{
		SharedContext:   shared,
		ResponseHeaders: headers,
		ResponseBody:    &policy.Body{Content: []byte(body), Present: true, EndOfStream: true},
		ResponseStatus:  200,
	}, nil)
	return action
}

func isBlocked(action policy.RequestHeaderAction) bool {
	_, ok := action.(policy.ImmediateResponse)
	return ok
}

// callsUntilBlocked counts the calls that pass before the quota rejects one.
func callsUntilBlocked(t *testing.T, p *SubscriptionTokenRateLimitPolicy, subID, provider, conditions string) int {
	t.Helper()
	for i := 0; i < 20; i++ {
		if isBlocked(call(t, p, subID, provider, conditions, usageBody)) {
			return i
		}
	}
	t.Fatalf("never blocked")
	return -1
}

func TestTokenTypes(t *testing.T) {
	// Each call uses 30 prompt, 50 completion and 80 total tokens; the limit is 160.
	for _, tc := range []struct {
		tokenType string
		calls     int
	}{
		{"total", 2},
		{"prompt", 6},
		{"completion", 4},
		{"", 2},
	} {
		t.Run("type-"+tc.tokenType, func(t *testing.T) {
			provider := "openai-" + tc.tokenType
			storeTemplate(t, provider, openAISpec())
			p := newPolicy(t)
			if got := callsUntilBlocked(t, p, "sub-1", provider, tokenConditions(160, tc.tokenType, "reject")); got != tc.calls {
				t.Fatalf("%s: %d calls passed, want %d", tc.tokenType, got, tc.calls)
			}
		})
	}
}

func TestTotalFallsBackToPromptPlusCompletion(t *testing.T) {
	spec := openAISpec()
	delete(spec, "totalTokens")
	storeTemplate(t, "anthropic", spec)
	p := newPolicy(t)
	if got := callsUntilBlocked(t, p, "sub-1", "anthropic", tokenConditions(160, "total", "reject")); got != 2 {
		t.Fatalf("%d calls passed, want 2", got)
	}
}

func TestTokenRejectionLooksLikeV1(t *testing.T) {
	storeTemplate(t, "openai", openAISpec())
	p := newPolicy(t)
	conds := tokenConditions(80, "total", "reject")
	if isBlocked(call(t, p, "sub-1", "openai", conds, usageBody)) {
		t.Fatalf("first call should pass")
	}
	resp, ok := call(t, p, "sub-1", "openai", conds, usageBody).(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("second call should be rejected")
	}
	if resp.StatusCode != 429 || resp.Fault == nil || resp.Fault.Code != policy.FaultCodeThrottledSubscription ||
		resp.Fault.Message != "Subscription plan token limit exceeded" {
		t.Fatalf("unexpected rejection %d %#v", resp.StatusCode, resp.Fault)
	}
	if want := `{"error":"rate_limit_exceeded","message":"Subscription quota exceeded: 80 tokens per 1 day"}`; string(resp.Body) != want {
		t.Fatalf("body = %s, want %s", resp.Body, want)
	}
	if resp.Headers["X-RateLimit-Limit"] != "80" || resp.Headers["X-RateLimit-Remaining"] != "0" || resp.Headers["Retry-After"] == "" {
		t.Fatalf("unexpected headers %v", resp.Headers)
	}
}

func TestTokenOnExceedAllow(t *testing.T) {
	storeTemplate(t, "openai", openAISpec())
	p := newPolicy(t)
	for i := 0; i < 5; i++ {
		if isBlocked(call(t, p, "sub-1", "openai", tokenConditions(80, "total", "allow"), usageBody)) {
			t.Fatalf("onExceed allow must not block")
		}
	}
}

func TestTokenPassThrough(t *testing.T) {
	storeTemplate(t, "openai", openAISpec())
	p := newPolicy(t)
	noTokens := `[{"id":"requests","type":"request-count","params":{"limits":[{"count":1,"timeUnit":"MINUTE"}]}}]`
	for i := 0; i < 3; i++ {
		if isBlocked(call(t, p, "", "openai", "", usageBody)) {
			t.Fatalf("missing metadata must pass through")
		}
		if isBlocked(call(t, p, "sub-1", "openai", noTokens, usageBody)) {
			t.Fatalf("a plan without token-count must pass through")
		}
		if isBlocked(call(t, p, "sub-1", "unknown-provider", tokenConditions(1, "total", "reject"), usageBody)) {
			t.Fatalf("a provider without a template must pass through")
		}
	}
}

func TestTokenCountersPerSubscription(t *testing.T) {
	storeTemplate(t, "openai", openAISpec())
	p := newPolicy(t)
	conds := tokenConditions(80, "total", "reject")
	call(t, p, "sub-1", "openai", conds, usageBody)
	if !isBlocked(call(t, p, "sub-1", "openai", conds, usageBody)) {
		t.Fatalf("sub-1 should be limited")
	}
	if isBlocked(call(t, p, "sub-2", "openai", conds, usageBody)) {
		t.Fatalf("sub-2 has its own counter")
	}
}

func TestTokenPlanChangeAppliesNewLimits(t *testing.T) {
	storeTemplate(t, "openai", openAISpec())
	p := newPolicy(t)
	call(t, p, "sub-1", "openai", tokenConditions(80, "total", "reject"), usageBody)
	if !isBlocked(call(t, p, "sub-1", "openai", tokenConditions(80, "total", "reject"), usageBody)) {
		t.Fatalf("should be limited under the old plan")
	}
	if isBlocked(call(t, p, "sub-1", "openai", tokenConditions(1000, "total", "reject"), usageBody)) {
		t.Fatalf("the new plan's limit applies")
	}
	// A new token type is a new limit as well.
	if isBlocked(call(t, p, "sub-1", "openai", tokenConditions(80, "prompt", "reject"), usageBody)) {
		t.Fatalf("a prompt-token limit is counted apart from the total-token one")
	}
}

func TestTokenResponsePhaseWithoutDelegateIsNoop(t *testing.T) {
	p := newPolicy(t)
	shared := &policy.SharedContext{Metadata: map[string]interface{}{}}
	if a := p.OnResponseHeaders(context.Background(), &policy.ResponseHeaderContext{SharedContext: shared}, nil); a != nil {
		t.Fatalf("expected no action, got %#v", a)
	}
	if a := p.OnResponseBody(context.Background(), &policy.ResponseContext{SharedContext: shared}, nil); a != nil {
		t.Fatalf("expected no action, got %#v", a)
	}
	if _, ok := p.OnResponseBodyChunk(context.Background(), &policy.ResponseStreamContext{SharedContext: shared}, &policy.StreamBody{}, nil).(policy.ForwardResponseChunk); !ok {
		t.Fatalf("expected the chunk to be forwarded")
	}
}

func TestTokenCostSources(t *testing.T) {
	spec := map[string]interface{}{"spec": map[string]interface{}{
		"promptTokens": map[string]interface{}{"identifier": "x-prompt", "location": "header"},
		"totalTokens":  map[string]interface{}{"identifier": "total", "location": "metadata"},
	}}
	if got := tokenCostSources(spec, "prompt"); len(got) != 1 || got[0].(map[string]interface{})["type"] != "request_header" {
		t.Fatalf("unexpected prompt sources %v", got)
	}
	if got := tokenCostSources(spec, "total"); len(got) != 1 || got[0].(map[string]interface{})["type"] != "metadata" {
		t.Fatalf("unexpected total sources %v", got)
	}
	if got := tokenCostSources(spec, "completion"); got != nil {
		t.Fatalf("expected no completion sources, got %v", got)
	}
}
