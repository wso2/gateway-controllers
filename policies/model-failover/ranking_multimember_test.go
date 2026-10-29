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
	"encoding/json"
	"testing"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

// MULTI-MEMBER consumption, driven through the whole policy rather than through resolveChain.
//
// resolveChain's multi-member behaviour has been covered since the merge-rule change, but every
// test reached it directly with an already-decoded []Target. Nothing asserted that a ranking
// arriving the way a real producer sends it — the pinned []map[string]string carrier — survives
// decoding AND produces the right chain. That gap is exactly where the T066b defect lived: the
// resolution logic was right and the value never got to it.

// rankedRequestFor builds a request asking for `model` with a multi-member ranking already
// published in the contract's wire representation.
func rankedRequestFor(model string, ranking []map[string]string) *policy.RequestContext {
	body, _ := json.Marshal(map[string]interface{}{"model": model})
	return &policy.RequestContext{
		SharedContext: &policy.SharedContext{Metadata: map[string]interface{}{
			MetadataKeyPublishedRanking: ranking,
		}},
		Body: &policy.Body{Content: body, Present: true},
	}
}

// policyWithMultiChain configures fallbacks for gpt-4o only, so a ranking led by something else
// is visibly not given gpt-4o's chain.
func policyWithMultiChain() *Policy {
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
			"cohere":    "cluster_cohere",
		},
	})
}

// THE multi-member rule end to end: the ranking's first target leads, its configured fallbacks
// come next, and the rest of the ranking follows as further depth.
func TestMultiMemberRanking_ConfiguredFallbacksSitBetweenRankedTargets(t *testing.T) {
	got := chainFrom(t, policyWithMultiChain(), rankedRequestFor("gpt-4o", []map[string]string{
		{"model": "gpt-4o"},
		{"model": "mistral-large", "provider": "mistral"},
		{"model": "command-r", "provider": "cohere"},
	}))
	want := "gpt-4o,claude-sonnet-4-5,mistral-large,command-r"
	if got != want {
		t.Fatalf("chain = %q, want %q — the ranking's own tail must follow the configured "+
			"fallbacks, not replace them", got, want)
	}
}

// Led by a target the publisher configured nothing for: no fallbacks are borrowed, and the
// ranking is traversed whole (FR-021a). This is the case a single-member test cannot express.
func TestMultiMemberRanking_UnconfiguredLeadBorrowsNothing(t *testing.T) {
	got := chainFrom(t, policyWithMultiChain(), rankedRequestFor("gpt-4o", []map[string]string{
		{"model": "mistral-large", "provider": "mistral"},
		{"model": "command-r", "provider": "cohere"},
	}))
	if got != "mistral-large,command-r" {
		t.Fatalf("chain = %q, want mistral-large,command-r with no borrowed fallback", got)
	}
}

// A target the ranking repeats, or that also appears as a configured fallback, is attempted
// once — at its earliest position (FR-010).
func TestMultiMemberRanking_DeduplicatesAcrossRankingAndFallbacks(t *testing.T) {
	got := chainFrom(t, policyWithMultiChain(), rankedRequestFor("gpt-4o", []map[string]string{
		{"model": "gpt-4o"},
		{"model": "claude-sonnet-4-5", "provider": "anthropic"}, // also the configured fallback
		{"model": "gpt-4o"}, // repeated by the producer
		{"model": "command-r", "provider": "cohere"},
	}))
	want := "gpt-4o,claude-sonnet-4-5,command-r"
	if got != want {
		t.Fatalf("chain = %q, want %q", got, want)
	}
}

// Provider is part of a target's identity, so the same model under two providers is two
// distinct members and both must survive de-duplication (FR-017).
func TestMultiMemberRanking_SameModelUnderDifferentProvidersAreDistinct(t *testing.T) {
	got := chainFrom(t, policyWithMultiChain(), rankedRequestFor("gpt-4o", []map[string]string{
		{"model": "shared-model", "provider": "mistral"},
		{"model": "shared-model", "provider": "cohere"},
	}))
	if got != "shared-model,shared-model" {
		t.Fatalf("chain = %q, want both provider variants kept as separate members", got)
	}
}

// A producer that has not adopted the contract publishes one selection. It must behave exactly
// like a one-element ranking (FR-023) — the compatibility guarantee the contract rests on.
func TestMultiMemberRanking_SingleSelectionBehavesAsAOneElementRanking(t *testing.T) {
	viaRanking := chainFrom(t, policyWithMultiChain(),
		rankedRequestFor("gpt-4o", []map[string]string{{"model": "gpt-4o"}}))
	viaSingleSelection := chainFrom(t, policyWithMultiChain(), requestFor("gpt-4o", "gpt-4o", ""))

	if viaRanking != viaSingleSelection {
		t.Fatalf("one-element ranking gave %q but the single-selection keys gave %q; a "+
			"non-adopting routing policy must compose identically", viaRanking, viaSingleSelection)
	}
}
