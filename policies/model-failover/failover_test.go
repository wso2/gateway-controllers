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

package modelfailover

import (
	"context"
	"testing"
	"time"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

func testTargets() []Target {
	return []Target{
		{Model: "gpt-4o", Provider: "openai"},
		{Model: "claude-sonnet-4", Provider: "anthropic"},
	}
}

// respond drives one response phase with a given final status and attempt count.
func respond(p *Policy, chain []Target, status, attempts int) {
	headers := map[string][]string{}
	if attempts > 0 {
		headers[attemptCountHeader] = []string{itoa(attempts)}
	}
	respCtx := &policy.ResponseHeaderContext{
		SharedContext: &policy.SharedContext{
			Metadata: map[string]interface{}{
				metadataKeyChain:        chain,
				metadataKeyRequestStart: p.now(),
			},
		},
		ResponseHeaders: policy.NewHeaders(headers),
		ResponseStatus:  status,
	}
	p.OnResponseHeaders(context.Background(), respCtx, nil)
}

// consecutiveFailuresFor reads the private counter for a target, which is the only way to
// distinguish "graded as failed" from "never graded at all" — both leave the target healthy
// until the threshold is crossed.
func consecutiveFailuresFor(store HealthStore, target Target) int {
	m := store.(*memoryHealthStore)
	m.mu.Lock()
	defer m.mu.Unlock()
	h, ok := m.targets[target.Key()]
	if !ok {
		return 0
	}
	return h.consecutiveFailures
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	digits := ""
	for n > 0 {
		digits = string(rune('0'+n%10)) + digits
		n /= 10
	}
	return digits
}

// A rescued request must credit the SUCCESS to the target that produced it and the FAILURE to
// the target that was retried away from.
//
// This is the bug the attempt-count header exists to prevent: the response phase runs once and
// sees only the final response, so grading chain[0] unconditionally would record a 200 for a
// target that actually failed. A target failing on every request would then look permanently
// healthy for as long as failover kept rescuing it, and would never be suspended.
func TestOnResponseHeaders_AttributesOutcomeToTheAttemptingTarget(t *testing.T) {
	clock := time.Now()
	p := NewPolicy(map[string]interface{}{})
	p.now = func() time.Time { return clock }

	chain := testTargets()
	respond(p, chain, 200, 2)

	// Target 1 was retried away from, so it failed; target 2 answered.
	if !p.health.Healthy(chain[1], clock) {
		t.Fatal("the target that produced the 200 must be healthy")
	}
	failures := consecutiveFailuresFor(p.health, chain[0])
	if failures != 1 {
		t.Fatalf("first target consecutive failures = %d, want 1 — a rescued request must "+
			"still record the failure that caused the rescue", failures)
	}
}

// A single attempt grades only the first target, and nothing else in the chain.
func TestOnResponseHeaders_SingleAttemptGradesOnlyTheFirstTarget(t *testing.T) {
	clock := time.Now()
	p := NewPolicy(map[string]interface{}{})
	p.now = func() time.Time { return clock }

	chain := testTargets()
	respond(p, chain, 200, 1)

	if got := consecutiveFailuresFor(p.health, chain[0]); got != 0 {
		t.Fatalf("first target failures = %d, want 0", got)
	}
	if got := consecutiveFailuresFor(p.health, chain[1]); got != 0 {
		t.Fatalf("second target must not be graded at all, got %d failures", got)
	}
}

// A missing header means one attempt: grade the first target, invent nothing for the rest
// (FR-030j). Reading it as "the whole chain was tried" would manufacture failures for targets
// the request may never have reached.
func TestOnResponseHeaders_MissingAttemptCountGradesOneTarget(t *testing.T) {
	clock := time.Now()
	p := NewPolicy(map[string]interface{}{})
	p.now = func() time.Time { return clock }

	chain := testTargets()
	respond(p, chain, 429, 0) // 0 => header omitted entirely

	if got := consecutiveFailuresFor(p.health, chain[0]); got != 1 {
		t.Fatalf("first target failures = %d, want 1", got)
	}
	if got := consecutiveFailuresFor(p.health, chain[1]); got != 0 {
		t.Fatalf("second target must not be graded when the attempt count is unknown, got %d", got)
	}
}

// The point of correct attribution: a target that fails on every request reaches suspension
// even though failover hides every one of those failures from the client (SC-014a).
func TestOnResponseHeaders_ConsistentlyFailingTargetIsEventuallySuspended(t *testing.T) {
	clock := time.Now()
	// Suspension is opt-in under the reviewed schema: suspendDuration defaults to 0, which
	// disables tracking entirely. A publisher who wants members taken out of rotation sets it.
	p := NewPolicy(map[string]interface{}{
		"suspendDuration":      float64(30),
		"suspendAfterFailures": float64(3),
	})
	p.now = func() time.Time { return clock }

	chain := testTargets()
	// Every request is rescued: the client always sees 200, and the first target always
	// failed to produce it.
	for i := 0; i < p.params.Suspension.ConsecutiveFailures; i++ {
		respond(p, chain, 200, 2)
		clock = clock.Add(time.Second)
	}

	if p.health.Healthy(chain[0], clock) {
		t.Fatal("a target that failed on every rescued request must be suspended; " +
			"otherwise failover masks the failure forever and the target is retried indefinitely")
	}
	if !p.health.Healthy(chain[1], clock) {
		t.Fatal("the rescuing target must remain healthy")
	}
}

// A client-input error is the client's problem, not the provider's: the target answered.
func TestOnResponseHeaders_NonFailoverWorthyStatusCountsAsSuccess(t *testing.T) {
	clock := time.Now()
	p := NewPolicy(map[string]interface{}{})
	p.now = func() time.Time { return clock }

	chain := testTargets()
	for i := 0; i < p.params.Suspension.ConsecutiveFailures+2; i++ {
		respond(p, chain, 400, 1)
		clock = clock.Add(time.Second)
	}

	if !p.health.Healthy(chain[0], clock) {
		t.Fatal("repeated 400s must never suspend a target — the provider answered every time")
	}
}

// An inert request wrote no chain, so the response phase has nothing to grade and must not
// panic or invent health state.
func TestOnResponseHeaders_NoChainIsANoOp(t *testing.T) {
	p := NewPolicy(map[string]interface{}{})
	respCtx := &policy.ResponseHeaderContext{
		SharedContext:   &policy.SharedContext{Metadata: map[string]interface{}{}},
		ResponseHeaders: policy.NewHeaders(map[string][]string{}),
		ResponseStatus:  200,
	}
	if action := p.OnResponseHeaders(context.Background(), respCtx, nil); action == nil {
		t.Fatal("expected a passthrough action")
	}
}
