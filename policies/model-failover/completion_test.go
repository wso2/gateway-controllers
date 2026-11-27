/*
 *  Copyright (c) 2026, WSO2 LLC. (http://www.wso2.org) All Rights Reserved.
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
 *
 */

package modelfailover

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

const testCluster = "upstream_openai"

// completionPolicy builds a policy whose correlation store already knows this request, as it
// would after the chain was published.
func completionPolicy(t *testing.T, target Target, suspendAfter int) (*Policy, time.Time) {
	t.Helper()
	now := time.Date(2026, 11, 6, 10, 0, 0, 0, time.UTC)
	p := NewPolicy(map[string]interface{}{})
	p.health = NewHealthStore(Suspension{ConsecutiveFailures: suspendAfter, DurationSeconds: 30})
	p.now = func() time.Time { return now }
	p.correlation.Remember("req-1", []Target{target}, nil, map[string]string{target.Provider: testCluster})
	return p, now
}

func verdict(code uint32, cluster string) *policy.AttemptCompletionContext {
	return &policy.AttemptCompletionContext{
		RequestID:       "req-1",
		RouteName:       "POST:/chat",
		UpstreamCluster: cluster,
		ResponseFlags:   []string{"UPE"},
		ResponseCode:    code,
		Duration:        3 * time.Second,
	}
}

// The headline behaviour: a target that commits 200 and then dies must be graded as FAILING.
// Without this it is recorded a success, which clears the consecutive-failure count and
// immunises a target that truncates everything (FR-030n).
func TestOnAttemptComplete_SuspendsATargetThatTruncatesAfterCommitting(t *testing.T) {
	target := Target{Model: "gpt-4o", Provider: "openai"}
	p, now := completionPolicy(t, target, 2)

	if !healthy(p.health, target, now) {
		t.Fatal("precondition: target starts healthy")
	}

	p.OnAttemptComplete(context.Background(), verdict(200, testCluster), nil)
	p.correlation.Remember("req-1", []Target{target}, nil, map[string]string{target.Provider: testCluster})
	p.OnAttemptComplete(context.Background(), verdict(200, testCluster), nil)

	if healthy(p.health, target, now) {
		t.Error("two post-commitment failures must reach suspendAfterFailures=2 and suspend the target")
	}
}

// A pre-commitment failure reached the client as a 5xx, which the response phase already graded.
// Grading it again here would count one failure twice and suspend at half the configured
// threshold — a target taken out of rotation for half the evidence an operator asked for.
func TestOnAttemptComplete_IgnoresFailuresTheResponsePhaseAlreadySaw(t *testing.T) {
	target := Target{Model: "gpt-4o", Provider: "openai"}
	p, now := completionPolicy(t, target, 1)

	p.OnAttemptComplete(context.Background(), verdict(502, testCluster), nil)

	if !healthy(p.health, target, now) {
		t.Error("a 502 was already graded by the response phase; grading it again double-counts")
	}
}

// The verdict names a cluster, which does not identify a target. An unrecorded request must
// record NOTHING rather than guess — FR-030p's conservative rule.
func TestOnAttemptComplete_RecordsNothingWhenTheRequestIsUnknown(t *testing.T) {
	target := Target{Model: "gpt-4o", Provider: "openai"}
	p, now := completionPolicy(t, target, 1)

	unknownRequest := verdict(200, testCluster)
	unknownRequest.RequestID = "never-published"
	p.OnAttemptComplete(context.Background(), unknownRequest, nil)
	if !healthy(p.health, target, now) {
		t.Error("a verdict for a request this policy never published must not grade anything")
	}

	p.OnAttemptComplete(context.Background(), verdict(200, "some_other_cluster"), nil)
	if !healthy(p.health, target, now) {
		t.Error("a verdict naming a cluster outside this request's chain must not grade anything")
	}
}

func TestOnAttemptComplete_SurvivesAMissingContext(t *testing.T) {
	p, _ := completionPolicy(t, Target{Model: "gpt-4o", Provider: "openai"}, 1)
	// Runs on the access-log stream with the request already finished: there is nothing to
	// fail, and a panic would take verdict delivery down for every route.
	p.OnAttemptComplete(context.Background(), nil, nil)
}

// The latency sample must be the real duration. Zero is not neutral — it reads as an unusually
// fast response and drags the p95 down, so a target that truncated after thirty seconds would
// make the latency rule LESS likely to fire.
func TestOnAttemptComplete_FeedsTheRealDurationToTheLatencyWindow(t *testing.T) {
	target := Target{Model: "gpt-4o", Provider: "openai"}
	now := time.Date(2026, 11, 6, 10, 0, 0, 0, time.UTC)
	p := NewPolicy(map[string]interface{}{})
	p.health = NewHealthStore(Suspension{
		P95LatencyMs: 1000, MinimumRequests: 1, WindowSeconds: 60, DurationSeconds: 30,
	})
	p.now = func() time.Time { return now }
	p.correlation.Remember("req-1", []Target{target}, nil, map[string]string{target.Provider: testCluster})

	slow := verdict(200, testCluster)
	slow.Duration = 30 * time.Second
	p.OnAttemptComplete(context.Background(), slow, nil)

	if healthy(p.health, target, now) {
		t.Error("a 30s attempt must land in the latency window as 30s and trip a 1000ms p95 rule")
	}
}

// The correlation store must not grow without bound: most entries are never read, because a
// request that completes normally produces no verdict at all.
func TestAttemptCorrelation_ExpiresEntriesItIsNeverAskedAbout(t *testing.T) {
	now := time.Date(2026, 11, 6, 10, 0, 0, 0, time.UTC)
	clock := now
	store := newAttemptCorrelation(func() time.Time { return clock })
	target := Target{Model: "m", Provider: "p"}
	store.Remember("req-1", []Target{target}, nil, map[string]string{"p": testCluster})

	if _, ok := store.Lookup("req-1", testCluster, 1); !ok {
		t.Fatal("precondition: entry is readable while fresh")
	}

	clock = now.Add(correlationTTL + time.Second)
	if _, ok := store.Lookup("req-1", testCluster, 1); ok {
		t.Error("an expired entry must not be returned")
	}
}

// Attempt 1 on a shared cluster is the FIRST of the two members. True by index now, where it
// used to be true only because the fallback map happened to keep the first one.
func TestAttemptCorrelation_SharedClusterResolvesToTheEarlierMember(t *testing.T) {
	store := newAttemptCorrelation(nil)
	first := Target{Model: "gpt-4o", Provider: "openai"}
	second := Target{Model: "gpt-4o-mini", Provider: "openai"}
	store.Remember("req-1", []Target{first, second}, nil, map[string]string{"openai": testCluster})

	got, ok := store.Lookup("req-1", testCluster, 1)
	if !ok || got.Target != first {
		t.Errorf("expected the first member on the shared cluster, got %+v (ok=%v)", got, ok)
	}
}

// TestOnAttemptComplete_GradesThroughTheRealPublishPath drives the whole path the gateway does:
// publish a chain via OnRequestBody, then deliver the verdict.
//
// The other tests in this file seed the correlation store directly, which leaves the ONE line
// that records it during a real request uncovered — delete that line and every one of them still
// passes while the feature does nothing at all. This test is what fails instead.
func TestOnAttemptComplete_GradesThroughTheRealPublishPath(t *testing.T) {
	const cluster = "upstream_anthropic"
	target := Target{Model: "claude", Provider: "anthropic"}
	now := time.Date(2026, 11, 6, 10, 0, 0, 0, time.UTC)

	p := NewPolicy(map[string]interface{}{
		"targets": []interface{}{
			map[string]interface{}{"model": "gpt-4o", "fallbacks": []interface{}{
				map[string]interface{}{"model": "claude", "provider": "anthropic"},
			}},
		},
		ProviderClustersParam: map[string]interface{}{"anthropic": cluster, "": "upstream_openai"},
	})
	p.health = NewHealthStore(Suspension{ConsecutiveFailures: 1, DurationSeconds: 30})
	p.now = func() time.Time { return now }

	body, _ := json.Marshal(map[string]interface{}{"model": "gpt-4o"})
	reqCtx := &policy.RequestContext{
		SharedContext: &policy.SharedContext{Metadata: map[string]interface{}{}},
		Headers:       headersWith(map[string][]string{requestIDHeader: {"req-real"}}),
		Body:          &policy.Body{Content: body, Present: true},
	}
	p.OnRequestBody(context.Background(), reqCtx, nil)

	if _, ok := reqCtx.Metadata[metadataKeyChain]; !ok {
		t.Fatal("precondition: the policy must have published a chain for this request")
	}

	p.OnAttemptComplete(context.Background(), &policy.AttemptCompletionContext{
		RequestID:       "req-real",
		UpstreamCluster: cluster,
		ResponseFlags:   []string{"UPE"},
		ResponseCode:    200,
		Duration:        2 * time.Second,
	}, nil)

	if healthy(p.health, target, now) {
		t.Error("the fallback target truncated after committing its response and must be suspended; " +
			"if this fails, the correlation recorded during OnRequestBody is missing")
	}
}

// A streamed probe is credited the moment its headers arrive — it has to be, or a target whose
// responses are all streamed could never leave the half-open state (FR-030p). That credit is a
// guess about a body that did not exist yet, and this is where the guess is settled.
//
// The store knows how to take the credit back; this test is about the wiring. The verdict has
// to carry the reservation the stream ran on, which means the correlation store has to have
// kept it. Pass the zero Admission from here — or forget to store it in Remember — and the
// reversal silently does nothing while every store-level test still passes.
func TestOnAttemptComplete_ReversesTheCreditAStreamedProbeWasGivenEarly(t *testing.T) {
	target := Target{Model: "gpt-4o", Provider: "openai"}
	now := time.Date(2026, 11, 6, 10, 0, 0, 0, time.UTC)
	p := NewPolicy(map[string]interface{}{})
	// One clean probe is a full recovery, so the optimistic credit restores the target
	// outright and the reversal has a visible state change to undo.
	//
	// suspendAfterFailures is deliberately high: a single ordinary failure must not be able
	// to suspend this target. That is what makes the assertion specific — if the verdict is
	// graded as an ordinary failure against a recovered target it changes nothing, and only
	// the reversal, which puts the target back in the half-open state first, can suspend it.
	p.health = NewHealthStore(Suspension{
		ConsecutiveFailures:   5,
		DurationSeconds:       30,
		RecoverAfterSuccesses: 1,
	})
	p.now = func() time.Time { return now }

	// Suspend it, then step past the window so the next admission is a probe.
	for i := 0; i < 5; i++ {
		p.health.RecordFailure(target, Admission{}, 0, now)
	}
	if healthy(p.health, target, now) {
		t.Fatal("precondition: the target should be suspended")
	}
	now = now.Add(31 * time.Second)

	probe, admitted := p.health.Admit(target, now)
	if !admitted || !probe.Probe {
		t.Fatal("precondition: the ended window should admit a probe")
	}
	// This is what the request path records, and the receipt has to travel with it.
	p.correlation.Remember("req-1", []Target{target}, []Admission{probe},
		map[string]string{target.Provider: testCluster})

	// The response phase sees a streamed 200 and banks the probe.
	if recovered := p.health.RecordUnverified(target, probe, now); recovered == nil {
		t.Fatal("precondition: a provisional outcome should complete a one-probe run")
	}
	if !healthy(p.health, target, now) || !healthy(p.health, target, now) {
		t.Fatal("precondition: the credit should have returned the target to full rotation")
	}

	// The body then died, and the access-log verdict says so.
	p.OnAttemptComplete(context.Background(), verdict(200, testCluster), nil)

	if healthy(p.health, target, now) {
		t.Fatal("the target is still in rotation: the probe that restored it was credited on " +
			"a status its body never earned, and the verdict failed to take that back")
	}
}

// The defect this positional lookup exists for. A cluster names a PROVIDER, so for
// [openai/gpt-4o, openai/gpt-4o-mini] both members' verdicts arrive naming one cluster. Keyed by
// cluster, the later member's post-commitment failure is charged to the earlier one — suspending
// a model that was never contacted, while the one that actually truncated keeps its clean window
// and all of the traffic.
//
// Mutant: ignore AttemptCount and fall back to byCluster. Attempt 2 then resolves to gpt-4o.
func TestAttemptCorrelation_LaterMemberOnASharedClusterIsGradedAsItself(t *testing.T) {
	store := newAttemptCorrelation(nil)
	first := Target{Model: "gpt-4o", Provider: "openai"}
	second := Target{Model: "gpt-4o-mini", Provider: "openai"}
	store.Remember("req-1", []Target{first, second}, nil, map[string]string{"openai": testCluster})

	got, ok := store.Lookup("req-1", testCluster, 2)
	if !ok {
		t.Fatal("attempt 2 was not resolved at all")
	}
	if got.Target != second {
		t.Errorf("attempt 2 resolved to %+v, want the SECOND member %+v — charging it to the "+
			"first suspends a model that was never contacted", got.Target, second)
	}
}

// Zero is a real sentinel, not a position: the gateway reports it when the request never reached
// an upstream, and an older gateway reports it always. It must fall back to the CLUSTER-keyed
// guess, which is what this store did before the count existed.
//
// The chain here deliberately starts with a member on a DIFFERENT cluster than the verdict names.
// A fixture whose first member is also the expected answer cannot tell the two behaviours apart:
// clamping a zero count to chain[0] and falling back by cluster would both return it, and the
// test would pass while the sentinel was gone. The distinguishing shape is the whole point —
// see T106.
//
// Mutant: drop the sentinel and clamp the index. The gemini verdict then grades anthropic.
func TestAttemptCorrelation_NoAttemptIdentityFallsBackToTheCluster(t *testing.T) {
	store := newAttemptCorrelation(nil)
	claude := Target{Model: "claude-opus-4-1", Provider: "anthropic"}
	gemini := Target{Model: "gemini-2.5-pro", Provider: "google"}
	store.Remember("req-1", []Target{claude, gemini}, nil, map[string]string{
		"anthropic": "c_claude",
		"google":    "c_gemini",
	})

	got, ok := store.Lookup("req-1", "c_gemini", 0)
	if !ok {
		t.Fatal("a verdict with no attempt identity must still grade by cluster")
	}
	if got.Target != gemini {
		t.Errorf("fallback resolved to %+v, want %+v — the cluster names the provider that "+
			"actually served, where chain[0] is simply the first member", got.Target, gemini)
	}
}

// The same sentinel, on a shared-provider chain, where the cluster-keyed fallback is the only
// answer available: both members are behind one cluster, so first-wins is the documented guess.
func TestAttemptCorrelation_NoAttemptIdentityOnASharedClusterTakesTheFirstMember(t *testing.T) {
	store := newAttemptCorrelation(nil)
	first := Target{Model: "gpt-4o", Provider: "openai"}
	second := Target{Model: "gpt-4o-mini", Provider: "openai"}
	store.Remember("req-1", []Target{first, second}, nil, map[string]string{"openai": testCluster})

	got, ok := store.Lookup("req-1", testCluster, 0)
	if !ok || got.Target != first {
		t.Errorf("got %+v (ok=%v), want the first member %+v", got.Target, ok, first)
	}
}

// An attempt count past the end of the remembered chain cannot index it. Reachable if the two
// ever disagree about which members were published, which is exactly when trusting the index
// would grade the wrong target.
func TestAttemptCorrelation_AttemptPastTheChainFallsBackToTheCluster(t *testing.T) {
	store := newAttemptCorrelation(nil)
	target := Target{Model: "gpt-4o", Provider: "openai"}
	store.Remember("req-1", []Target{target}, nil, map[string]string{"openai": testCluster})

	got, ok := store.Lookup("req-1", testCluster, 7)
	if !ok || got.Target != target {
		t.Errorf("got %+v (ok=%v), want the cluster-keyed fallback %+v", got.Target, ok, target)
	}
}

// The cluster cross-checks the position rather than being ignored once a count is present. If
// they disagree the correspondence has broken, and the verdict's own cluster is the gateway's
// account of what actually served the attempt — so grading falls back to it rather than trusting
// an index that is demonstrably describing a different target.
//
// Mutant: delete the cross-check. The gemini verdict is then charged to anthropic.
func TestAttemptCorrelation_PositionDisagreeingWithTheClusterGradesByCluster(t *testing.T) {
	store := newAttemptCorrelation(nil)
	claude := Target{Model: "claude-opus-4-1", Provider: "anthropic"}
	gemini := Target{Model: "gemini-2.5-pro", Provider: "google"}
	store.Remember("req-1", []Target{claude, gemini}, nil, map[string]string{
		"anthropic": "c_claude",
		"google":    "c_gemini",
	})

	// Position 1 is anthropic, but the verdict says the attempt ran against gemini.
	got, ok := store.Lookup("req-1", "c_gemini", 1)
	if !ok {
		t.Fatal("a disagreeing verdict must still be graded by its own cluster")
	}
	if got.Target != gemini {
		t.Errorf("graded %+v, want %+v — the cluster is what actually served the attempt",
			got.Target, gemini)
	}
}

// End to end through the hook, not just the store: a post-commitment truncation on the SECOND
// member of a shared-provider chain must suspend that member and leave the first one healthy.
func TestOnAttemptComplete_ChargesTheLaterSharedProviderMember(t *testing.T) {
	now := time.Date(2026, 11, 6, 10, 0, 0, 0, time.UTC)
	first := Target{Model: "gpt-4o", Provider: "openai"}
	second := Target{Model: "gpt-4o-mini", Provider: "openai"}

	p := NewPolicy(map[string]interface{}{})
	p.health = NewHealthStore(Suspension{ConsecutiveFailures: 1, DurationSeconds: 30})
	p.now = func() time.Time { return now }
	p.correlation.Remember("req-1", []Target{first, second}, nil,
		map[string]string{"openai": testCluster})

	v := verdict(200, testCluster)
	v.AttemptCount = 2
	p.OnAttemptComplete(context.Background(), v, nil)

	if healthy(p.health, second, now) {
		t.Error("the member that actually truncated was not suspended")
	}
	if !healthy(p.health, first, now) {
		t.Error("a member that was never contacted was suspended in its place")
	}
}
