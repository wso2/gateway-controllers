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
	"time"
)

// These cover resolveChain, which had NO direct test before 2026-10-29 — which is why the
// merge rule could be changed without a single failure. It is the heart of "failover obeys the
// order other policies decided", so it is worth exercising directly.

func m(model string) Target { return Target{Model: model} }

func names(chain []Target) string {
	parts := make([]string, 0, len(chain))
	for _, t := range chain {
		parts = append(parts, t.Model)
	}
	return strings.Join(parts, ",")
}

func openHealth() HealthStore {
	s := testSuspension()
	s.DurationSeconds = 0 // suspension disabled: these tests are about ordering only
	s.clamp()
	return NewHealthStore(s)
}

func resolved(published []Target, target Target, fallbacks []Target) string {
	return names(resolveChain(published, target, fallbacks, openHealth(), time.Now()))
}

// THE rule, as decided 2026-10-29: when A fails the retry goes to B — the fallback the
// publisher wrote for it — not to D, the routing policy's next choice. D and C still follow,
// as further depth once the configured fallbacks are spent.
func TestResolveChain_ConfiguredFallbacksBeatTheRoutingOrder(t *testing.T) {
	got := resolved([]Target{m("A"), m("D"), m("C")}, m("A"), []Target{m("B")})
	if got != "A,B,D,C" {
		t.Fatalf("chain = %q, want A,B,D,C", got)
	}
}

// The routing policy still chooses what leads — that is what it exists to do. Discarding its
// pick would silently disable round-robin's load spreading.
func TestResolveChain_RoutingPolicyChoosesTheFirstTarget(t *testing.T) {
	got := resolved([]Target{m("D"), m("C")}, m("A"), []Target{m("B")})
	if !strings.HasPrefix(got, "D,") {
		t.Fatalf("chain = %q, want the routing policy's pick to lead", got)
	}
	// A is still reachable at the tail: it is the model the client asked for.
	if !strings.Contains(got, "A") {
		t.Fatalf("chain = %q, want the configured target to remain reachable", got)
	}
}

// With no routing policy the configured chain is the whole story.
func TestResolveChain_NoRoutingPolicy(t *testing.T) {
	got := resolved(nil, m("A"), []Target{m("B"), m("C")})
	if got != "A,B,C" {
		t.Fatalf("chain = %q, want A,B,C", got)
	}
}

// Nothing configured to honour, so the ranking is used in full — it is the only depth there is.
func TestResolveChain_NoFallbacksMeansTheRankingIsUsedWhole(t *testing.T) {
	got := resolved([]Target{m("A"), m("D"), m("C")}, m("A"), nil)
	if got != "A,D,C" {
		t.Fatalf("chain = %q, want A,D,C", got)
	}
}

// A target named in both places appears once, in its earliest position.
func TestResolveChain_NoDuplicates(t *testing.T) {
	got := resolved([]Target{m("A"), m("B"), m("C")}, m("A"), []Target{m("B")})
	if got != "A,B,C" {
		t.Fatalf("chain = %q, want A,B,C with B appearing once", got)
	}
}

// A suspended target is excluded wherever it appears, including as the routing policy's pick.
func TestResolveChain_SuspendedTargetsAreExcluded(t *testing.T) {
	s := testSuspension()
	s.DurationSeconds = 60
	s.ConsecutiveFailures = 1
	s.clamp()
	health := NewHealthStore(s)

	now := time.Now()
	health.RecordFailure(m("A"), 0, now) // A is now suspended

	got := names(resolveChain([]Target{m("A"), m("D")}, m("A"), []Target{m("B")}, health, now))
	if strings.Contains(got, "A") {
		t.Fatalf("chain = %q, want the suspended target excluded", got)
	}
	if got != "B,D" {
		t.Fatalf("chain = %q, want B,D once A is out", got)
	}
}

// An unresolvable entry is skipped rather than failing the request (FR-006a).
func TestResolveChain_InvalidTargetsAreSkipped(t *testing.T) {
	got := resolved([]Target{m("A")}, m("A"), []Target{{Model: ""}, m("B")})
	if got != "A,B" {
		t.Fatalf("chain = %q, want the empty entry skipped", got)
	}
}
