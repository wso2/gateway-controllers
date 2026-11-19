/*
 *  Copyright (c) 2026, WSO2 LLC. (https://www.wso2.com).
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package modelfailover

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

// Fallbacks belong to the target a request is ACTUALLY sent to, never to the model the client
// happened to name (FR-021a). These cover the distinction, which only becomes visible when a
// routing policy sends the request somewhere other than the requested model.

func policyWithChain() *Policy {
	return NewPolicy(map[string]interface{}{
		"targets": []interface{}{map[string]interface{}{
			"model": "gpt-4o",
			"fallbacks": []interface{}{
				map[string]interface{}{"model": "claude-sonnet-4-5", "provider": "anthropic"},
			},
		}},
		ProviderClustersParam: map[string]interface{}{
			"":          "cluster_default",
			"anthropic": "cluster_anthropic",
			"mistral":   "cluster_mistral",
		},
	})
}

// requestFor builds a downstream request body asking for `model`, with an optional
// single-selection routing decision published into shared metadata.
//
// The single-selection channel carries a PROVIDER and nothing else — see the comment on
// MetadataKeySelectedProvider. It cannot express "use a different model", so a case that needs
// that must publish a ranking instead; requestForRanking below does that.
func requestFor(model, selectedProvider string) *policy.RequestContext {
	metadata := map[string]interface{}{}
	if selectedProvider != "" {
		metadata[MetadataKeySelectedProvider] = selectedProvider
	}
	return requestWithMetadata(model, metadata)
}

// requestForRanking builds a request whose routing decision arrives through the ordered-list
// contract, which is the only tier that can nominate a model other than the requested one.
func requestForRanking(model string, ranking ...map[string]string) *policy.RequestContext {
	return requestWithMetadata(model, map[string]interface{}{
		MetadataKeyPublishedRanking: ranking,
	})
}

func requestWithMetadata(model string, metadata map[string]interface{}) *policy.RequestContext {
	body, _ := json.Marshal(map[string]interface{}{"model": model})
	return &policy.RequestContext{
		SharedContext: &policy.SharedContext{Metadata: metadata},
		Body:          &policy.Body{Content: body, Present: true},
	}
}

// targetsFrom is chainFrom without the lossy join: chainFrom reports models only, so it cannot
// see a provider being overwritten, which is exactly the regression these tests exist for.
func targetsFrom(t *testing.T, p *Policy, reqCtx *policy.RequestContext) []Target {
	t.Helper()
	p.OnRequestBody(context.Background(), reqCtx, nil)
	raw, ok := reqCtx.Metadata[metadataKeyChain]
	if !ok {
		return nil
	}
	targets, ok := raw.([]Target)
	if !ok {
		t.Fatalf("published chain is %T, want []Target", raw)
	}
	return targets
}

func chainFrom(t *testing.T, p *Policy, reqCtx *policy.RequestContext) string {
	t.Helper()
	p.OnRequestBody(context.Background(), reqCtx, nil)
	raw, ok := reqCtx.Metadata[metadataKeyChain]
	if !ok {
		return ""
	}
	targets, ok := raw.([]Target)
	if !ok {
		t.Fatalf("published chain is %T, want []Target", raw)
	}
	parts := make([]string, 0, len(targets))
	for _, tg := range targets {
		parts = append(parts, tg.Model)
	}
	return strings.Join(parts, ",")
}

// No routing policy: the request goes to the model it asked for, so that target's configured
// fallbacks apply.
func TestChainSelection_NoRoutingPolicyUsesTheRequestedModelsChain(t *testing.T) {
	got := chainFrom(t, policyWithChain(), requestFor("gpt-4o", ""))
	if got != "gpt-4o,claude-sonnet-4-5" {
		t.Fatalf("chain = %q, want gpt-4o,claude-sonnet-4-5", got)
	}
}

// THE correction (2026-10-29). A routing policy sends this request to mistral-large, for which
// the publisher configured nothing. gpt-4o's fallback must NOT be borrowed: the publisher never
// said what should follow mistral-large, and inventing an answer from an unrelated chain would
// send traffic to a target nobody nominated for it.
func TestChainSelection_RoutedElsewhereDoesNotBorrowTheRequestedModelsFallbacks(t *testing.T) {
	// Published as a RANKING, deliberately. Routing to a different MODEL is a tier-1 statement:
	// the single-selection channel names only a provider, so it could not express this case and
	// writing it there would assert nothing.
	got := chainFrom(t, policyWithChain(), requestForRanking("gpt-4o",
		map[string]string{"model": "mistral-large", "provider": "mistral"}))
	if strings.Contains(got, "claude") {
		t.Fatalf("chain = %q — gpt-4o's fallback was applied to a target it was never written for", got)
	}
}

// Routed to the configured target: its own fallbacks apply, exactly as if no routing policy
// had been involved.
func TestChainSelection_RoutedToTheConfiguredTargetUsesItsFallbacks(t *testing.T) {
	got := chainFrom(t, policyWithChain(), requestFor("gpt-4o", ""))
	if got != "gpt-4o,claude-sonnet-4-5" {
		t.Fatalf("chain = %q, want gpt-4o,claude-sonnet-4-5", got)
	}
}

// A catch-all chain still matches whatever the request is routed to — the publisher wrote "*"
// precisely to say "whatever the target, this is the fallback".
func TestChainSelection_WildcardChainMatchesAnyTarget(t *testing.T) {
	p := NewPolicy(map[string]interface{}{
		"targets": []interface{}{map[string]interface{}{
			"model": "*",
			"fallbacks": []interface{}{
				map[string]interface{}{"model": "claude-sonnet-4-5", "provider": "anthropic"},
			},
		}},
		ProviderClustersParam: map[string]interface{}{"": "cluster_default", "anthropic": "cluster_anthropic"},
	})
	got := chainFrom(t, p, requestFor("gpt-4o", ""))
	if !strings.Contains(got, "claude") {
		t.Fatalf("chain = %q, want the catch-all chain's fallback to apply", got)
	}
}

// Nothing configured for the model and no routing policy: the policy is inert, exactly as
// before — an unmatched model is not an error (FR-050).
func TestChainSelection_UnmatchedModelWithNoRoutingPolicyIsInert(t *testing.T) {
	if got := chainFrom(t, policyWithChain(), requestFor("something-else", "")); got != "" {
		t.Fatalf("chain = %q, want the policy to stay inert", got)
	}
}

// A provider-only selection is the ONLY thing seven of the eight steering policies in this repo
// can say, so these two tests are what make failover usable with any of them.
//
// Before this, the consumer read "model_roundrobin.selected_provider" — model-round-robin's own
// private key. Every other steering policy writes the shared "selected_provider" convention
// that predates this feature, so their decisions were read as absent and silently discarded
// while failover published its configured order instead.

// The steered provider leads the chain, and the configured chain still supplies what follows.
//
// chainFrom reports models only, which is why this reads targets directly: a provider being
// wrong is invisible in a model list, and the whole point of a provider-only selection is the
// provider.
func TestSingleSelection_SteeredProviderLeadsTheChain(t *testing.T) {
	targets := targetsFrom(t, policyWithChain(), requestFor("gpt-4o", "mistral"))
	if len(targets) < 3 {
		t.Fatalf("chain = %+v, want three members", targets)
	}
	// Attempt 1 is where the routing policy sent it.
	if targets[0] != (Target{Model: "gpt-4o", Provider: "mistral"}) {
		t.Fatalf("attempt 1 = %+v, want gpt-4o at mistral", targets[0])
	}
	// Then the requested model's configured fallback.
	if targets[1] != (Target{Model: "claude-sonnet-4-5", Provider: "anthropic"}) {
		t.Fatalf("attempt 2 = %+v, want the configured fallback", targets[1])
	}
	// Then the configured chain's own leading member as a last resort. The steering put
	// mistral in FRONT of the publisher's chain rather than replacing it, so the primary is
	// still reachable after the configured fallbacks are spent.
	if targets[2] != (Target{Model: "gpt-4o", Provider: ""}) {
		t.Fatalf("attempt 3 = %+v, want gpt-4o at the primary as the last resort", targets[2])
	}
}

// And the requested model's fallbacks DO still apply, because the model did not change: only
// the provider did. Withholding them would mean attaching any provider-steering policy
// silently disables failover, which is the opposite of what layering is for.
func TestSingleSelection_RequestedModelsFallbacksStillApply(t *testing.T) {
	got := chainFrom(t, policyWithChain(), requestFor("gpt-4o", "mistral"))
	if !strings.Contains(got, "claude") {
		t.Fatalf("chain = %q, want gpt-4o's configured fallback to follow — a provider-only "+
			"selection changes where the model goes, not which model was asked for", got)
	}
}

// An absent or empty selection is not a selection. applyProviderRouting deletes the key when it
// picks the primary, so an empty value means no steering happened and the configured order must
// stand — treating it as a target would publish a ranking nobody asked for.
func TestSingleSelection_EmptyProviderIsNotASelection(t *testing.T) {
	p := &Policy{}
	for name, metadata := range map[string]map[string]interface{}{
		"absent":       {},
		"empty":        {MetadataKeySelectedProvider: ""},
		"whitespace":   {MetadataKeySelectedProvider: "   "},
		"not a string": {MetadataKeySelectedProvider: 42},
	} {
		t.Run(name, func(t *testing.T) {
			if got := p.publishedRanking(metadata, "gpt-4o"); got != nil {
				t.Fatalf("publishedRanking = %+v, want nil", got)
			}
		})
	}
}
