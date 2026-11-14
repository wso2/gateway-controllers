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
	"strings"
	"testing"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

// rankedPolicy configures a chain whose own targets resolve — which is what puts real priority
// groups on the route and therefore what makes an unaddressable ranking harmful rather than
// inert.
func rankedPolicy() *Policy {
	return NewPolicy(map[string]interface{}{
		"targets": []interface{}{map[string]interface{}{
			"model":     "gpt-4o",
			"fallbacks": []interface{}{map[string]interface{}{"model": "gpt-4o-mini"}},
		}},
		ProviderClustersParam: map[string]interface{}{"": "cluster_default"},
	})
}

func rankingOf(entries ...map[string]string) map[string]interface{} {
	return map[string]interface{}{MetadataKeyPublishedRanking: entries}
}

// A routing policy ranking only providers with no upstream here is REFUSED.
//
// Going inert would publish nothing, and publishing nothing does NOT mean "no failover" on
// this route: the controller built priority groups from the publisher's own resolvable
// targets, so Envoy would walk those and serve a provider the ranking never nominated, with
// the full retry budget behind it (FR-061).
func TestUnroutableRanking_RoutingPolicyRankingWithNoUpstreamIsRefused(t *testing.T) {
	action, metadata := runWithBody(t, rankedPolicy(), []byte(`{"model":"gpt-4o"}`),
		rankingOf(map[string]string{"model": "llama-3", "provider": "bedrock"}))

	resp, ok := action.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("action is %T, want a refusal: serving this would use an unranked target", action)
	}
	if resp.StatusCode != unroutableStatus {
		t.Fatalf("status = %d, want %d", resp.StatusCode, unroutableStatus)
	}
	if !resp.StopExecution() {
		t.Fatal("the refusal does not stop the chain, so the request would still be dispatched")
	}
	if !strings.Contains(string(resp.Body), unroutableCode) {
		t.Fatalf("body = %s, want code %s", resp.Body, unroutableCode)
	}
	if _, published := metadata[metadataKeyChain]; published {
		t.Fatal("a chain was published for a request that could address no ranked target")
	}
}

// The refusal body names no provider, cluster or model.
func TestUnroutableRanking_RefusalDisclosesNothing(t *testing.T) {
	action, _ := runWithBody(t, rankedPolicy(), []byte(`{"model":"gpt-4o"}`),
		rankingOf(map[string]string{"model": "llama-3", "provider": "bedrock"}))

	body := string(action.(policy.ImmediateResponse).Body)
	for _, leak := range []string{"bedrock", "llama-3", "cluster_", "gpt-4o"} {
		if strings.Contains(body, leak) {
			t.Fatalf("body %s discloses %q", body, leak)
		}
	}
}

// POSITIVE CONTROL, and the whole reason this exception is scoped. With NO routing-policy
// ranking, a publisher's own chain that resolves to nothing stays inert — never refused.
//
// That is safe precisely because the control plane makes it safe: with none of the
// publisher's targets resolvable the controller emits no cluster specifier and no retry
// policy, so the route is ordinary and there is nothing to fall back to incorrectly
// (FR-030b). Refusing here instead would turn a publisher's naming mistake into an outage.
func TestUnroutableRanking_PublisherChainWithNoClustersStaysInert(t *testing.T) {
	p := NewPolicy(map[string]interface{}{
		"targets": []interface{}{map[string]interface{}{
			"model":     "gpt-4o",
			"provider":  "bedrock",
			"fallbacks": []interface{}{map[string]interface{}{"model": "llama-3", "provider": "vertex"}},
		}},
		ProviderClustersParam: map[string]interface{}{"anthropic": "cluster_anthropic"},
	})

	action, metadata := runWithBody(t, p, []byte(`{"model":"gpt-4o"}`), nil)
	if _, refused := action.(policy.ImmediateResponse); refused {
		t.Fatal("a publisher-only chain was refused; the exception is scoped to ranked requests")
	}
	if _, published := metadata[metadataKeyChain]; published {
		t.Fatal("a chain was published when nothing resolved")
	}
}

// POSITIVE CONTROL. A ranking that is only PARTIALLY unaddressable still has somewhere to go,
// so it must be served against what remains — one unresolvable entry must not take down a
// working ranking.
func TestUnroutableRanking_PartiallyAddressableRankingIsStillServed(t *testing.T) {
	action, metadata := runWithBody(t, rankedPolicy(), []byte(`{"model":"gpt-4o"}`),
		rankingOf(
			map[string]string{"model": "llama-3", "provider": "bedrock"}, // no cluster
			map[string]string{"model": "gpt-4o"},                         // resolves
		))

	if _, refused := action.(policy.ImmediateResponse); refused {
		t.Fatal("a partially addressable ranking was refused; only a TOTAL drop may be")
	}
	if _, published := metadata[metadataKeyChain]; !published {
		t.Fatal("no chain published for a ranking that still had a resolvable member")
	}
}
