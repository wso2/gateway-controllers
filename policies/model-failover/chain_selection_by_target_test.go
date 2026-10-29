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
			"":              "cluster_default",
			"anthropic":     "cluster_anthropic",
			"mistral":       "cluster_mistral",
		},
	})
}

// requestFor builds a downstream request body asking for `model`, with an optional routing
// policy selection already published into shared metadata.
func requestFor(model, selectedModel, selectedProvider string) *policy.RequestContext {
	metadata := map[string]interface{}{}
	if selectedModel != "" {
		metadata[MetadataKeySelectedModel] = selectedModel
		metadata[MetadataKeySelectedProvider] = selectedProvider
	}
	body, _ := json.Marshal(map[string]interface{}{"model": model})
	return &policy.RequestContext{
		SharedContext: &policy.SharedContext{Metadata: metadata},
		Body:          &policy.Body{Content: body, Present: true},
	}
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
	got := chainFrom(t, policyWithChain(), requestFor("gpt-4o", "", ""))
	if got != "gpt-4o,claude-sonnet-4-5" {
		t.Fatalf("chain = %q, want gpt-4o,claude-sonnet-4-5", got)
	}
}

// THE correction (2026-10-29). A routing policy sends this request to mistral-large, for which
// the publisher configured nothing. gpt-4o's fallback must NOT be borrowed: the publisher never
// said what should follow mistral-large, and inventing an answer from an unrelated chain would
// send traffic to a target nobody nominated for it.
func TestChainSelection_RoutedElsewhereDoesNotBorrowTheRequestedModelsFallbacks(t *testing.T) {
	got := chainFrom(t, policyWithChain(), requestFor("gpt-4o", "mistral-large", "mistral"))
	if strings.Contains(got, "claude") {
		t.Fatalf("chain = %q — gpt-4o's fallback was applied to a target it was never written for", got)
	}
}

// Routed to the configured target: its own fallbacks apply, exactly as if no routing policy
// had been involved.
func TestChainSelection_RoutedToTheConfiguredTargetUsesItsFallbacks(t *testing.T) {
	got := chainFrom(t, policyWithChain(), requestFor("gpt-4o", "gpt-4o", ""))
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
	got := chainFrom(t, p, requestFor("gpt-4o", "mistral-large", ""))
	if !strings.Contains(got, "claude") {
		t.Fatalf("chain = %q, want the catch-all chain's fallback to apply", got)
	}
}

// Nothing configured for the model and no routing policy: the policy is inert, exactly as
// before — an unmatched model is not an error (FR-050).
func TestChainSelection_UnmatchedModelWithNoRoutingPolicyIsInert(t *testing.T) {
	if got := chainFrom(t, policyWithChain(), requestFor("something-else", "", "")); got != "" {
		t.Fatalf("chain = %q, want the policy to stay inert", got)
	}
}
