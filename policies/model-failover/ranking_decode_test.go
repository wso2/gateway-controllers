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

import "testing"

// producerTarget stands in for a target type declared in a PRODUCER's own module. It is
// structurally identical to Target and deliberately a distinct named type — that distinction is
// the entire defect this file exists to pin down.
//
// The old consumer did `raw.([]Target)`. Go type assertions match identical named types, not
// structurally compatible ones, so []producerTarget could never satisfy it and a routing policy
// doing exactly the right thing degraded silently to the single-selection path. A test written
// with the package's own []Target passes against that broken reader and proves nothing, which is
// precisely why the defect survived.
type producerTarget struct {
	Model    string
	Provider string
}

// asContract renders the producer's own targets into the pinned wire representation.
func (t producerTarget) asContract() map[string]string {
	entry := map[string]string{"model": t.Model}
	if t.Provider != "" {
		entry["provider"] = t.Provider
	}
	return entry
}

func assertTargets(t *testing.T, got []Target, want ...Target) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("position %d = %+v, want %+v (full %+v)", i, got[i], want[i], got)
		}
	}
}

// THE REGRESSION. A producer in another module publishes the pinned representation; the consumer
// must read it. Written from a foreign type on purpose.
func TestDecodeRanking_FromAForeignProducerType(t *testing.T) {
	published := []producerTarget{
		{Model: "gpt-4o"},
		{Model: "claude-sonnet-4-5-20250929", Provider: "anthropic"},
	}

	ranking := make([]map[string]string, 0, len(published))
	for _, p := range published {
		ranking = append(ranking, p.asContract())
	}

	// Through publishedRanking, NOT decodeRanking — the consumer is what has to accept this.
	// A test calling the decoder directly passes against the broken reader too, since the
	// defect was in the call site, so it would not have caught anything.
	p := &Policy{}
	assertTargets(t, p.publishedRanking(map[string]interface{}{
		MetadataKeyPublishedRanking: ranking,
	}),
		Target{Model: "gpt-4o"},
		Target{Model: "claude-sonnet-4-5-20250929", Provider: "anthropic"},
	)
}

// The whole point is that this reaches the policy, not just the decoder — publishedRanking is
// what the request path actually calls.
func TestPublishedRanking_AcceptsTheContractRepresentation(t *testing.T) {
	p := &Policy{}
	metadata := map[string]interface{}{
		MetadataKeyPublishedRanking: []map[string]string{
			{"model": "gpt-4o"},
			{"model": "mistral-large", "provider": "mistral"},
		},
		// Present and deliberately different: a ranking must win over the single-selection
		// keys, or a producer that sets both silently loses its order.
		MetadataKeySelectedModel: "something-else",
	}
	assertTargets(t, p.publishedRanking(metadata),
		Target{Model: "gpt-4o"},
		Target{Model: "mistral-large", Provider: "mistral"},
	)
}

// A producer assembling the list generically produces []any of maps. Both forms decode the same.
func TestDecodeRanking_AcceptsGenericallyBuiltLists(t *testing.T) {
	t.Run("[]any of map[string]string", func(t *testing.T) {
		raw := []interface{}{
			map[string]string{"model": "gpt-4o"},
			map[string]string{"model": "claude-3", "provider": "anthropic"},
		}
		assertTargets(t, decodeRanking(raw),
			Target{Model: "gpt-4o"}, Target{Model: "claude-3", Provider: "anthropic"})
	})

	t.Run("[]any of map[string]any", func(t *testing.T) {
		raw := []interface{}{
			map[string]interface{}{"model": "gpt-4o"},
			map[string]interface{}{"model": "claude-3", "provider": "anthropic"},
		}
		assertTargets(t, decodeRanking(raw),
			Target{Model: "gpt-4o"}, Target{Model: "claude-3", Provider: "anthropic"})
	})
}

// Order is the only thing a ranking carries. If decoding reordered it the contract would be
// meaningless, so it is asserted rather than assumed.
func TestDecodeRanking_PreservesPublishedOrder(t *testing.T) {
	raw := []map[string]string{{"model": "c"}, {"model": "a"}, {"model": "b"}}
	assertTargets(t, decodeRanking(raw),
		Target{Model: "c"}, Target{Model: "a"}, Target{Model: "b"})
}

// One malformed entry costs that entry, not the producer's whole ranking — dropping the order
// because of a single bad element would be a worse outcome than ignoring the element.
func TestDecodeRanking_SkipsEntriesWithNoModel(t *testing.T) {
	raw := []map[string]string{
		{"model": "gpt-4o"},
		{"provider": "anthropic"}, // no model — unusable
		{"model": ""},             // explicitly empty
		{"model": "claude-3"},
	}
	assertTargets(t, decodeRanking(raw), Target{Model: "gpt-4o"}, Target{Model: "claude-3"})
}

// An unreadable ranking degrades to the single-selection path. It must never fail the request:
// a producer publishing nonsense is a producer bug, not a reason to drop the caller's traffic.
func TestPublishedRanking_UnreadableValueDegradesToSingleSelection(t *testing.T) {
	p := &Policy{}
	for name, bad := range map[string]interface{}{
		"a string":          "gpt-4o",
		"a map":             map[string]string{"model": "gpt-4o"},
		"a slice of string": []string{"gpt-4o"},
		"nil":               nil,
		"empty list":        []map[string]string{},
	} {
		t.Run(name, func(t *testing.T) {
			metadata := map[string]interface{}{
				MetadataKeyPublishedRanking: bad,
				MetadataKeySelectedModel:    "gpt-4o",
				MetadataKeySelectedProvider: "openai",
			}
			assertTargets(t, p.publishedRanking(metadata),
				Target{Model: "gpt-4o", Provider: "openai"})
		})
	}
}

// The consumer half of the cross-module key pin; see the matching test in model-round-robin.
// Neither module can import the other's constant, so these literals are the only thing holding
// the contract together — a rename on either side compiles and silently no-ops.
//
// Pinned against specs/001-model-failover-policy/contracts/target-preference-list.md. Changing
// either value means changing the contract document and the producer in the same PR.
func TestContractKeysArePinned(t *testing.T) {
	if MetadataKeyPublishedRanking != "model_routing.published_ranking" {
		t.Fatalf("ranking key = %q; the producer is a separate module and writes the literal",
			MetadataKeyPublishedRanking)
	}
}
