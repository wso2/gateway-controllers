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
	"fmt"
	"sync"
	"testing"
	"time"
)

var (
	targetA = Target{Model: "gpt-4o", Provider: "openai"}
	targetB = Target{Model: "gpt-4o", Provider: "azure-sweden"}
)

func testSuspension() Suspension {
	s := Suspension{
		ConsecutiveFailures: 3,
		DurationSeconds:     30,
		MaxDurationSeconds:  120,
		BackoffResetSeconds: 600,
		ErrorRatePercent:    50,
		WindowSeconds:       60,
		MinimumRequests:     20,
		P95LatencyMs:        0,
	}
	s.clamp()
	return s
}

// Three failures in a row suspend; a success in between resets the count, so a target that
// fails intermittently is never caught by this rule — which is exactly why the windowed rate
// rule exists alongside it.
func TestHealth_ConsecutiveFailuresSuspend(t *testing.T) {
	store := NewHealthStore(testSuspension())
	now := time.Now()

	if ev := store.RecordFailure(targetA, Admission{}, 0, now); ev != nil {
		t.Fatal("one failure must not suspend")
	}
	store.RecordSuccess(targetA, Admission{}, 0, now)
	if ev := store.RecordFailure(targetA, Admission{}, 0, now); ev != nil {
		t.Fatal("the success must have reset the consecutive count")
	}

	store.RecordFailure(targetA, Admission{}, 0, now)
	ev := store.RecordFailure(targetA, Admission{}, 0, now)
	if ev == nil {
		t.Fatal("three consecutive failures must suspend")
	}
	if ev.Reason != ReasonConsecutiveFailures {
		t.Errorf("expected reason %q, got %q", ReasonConsecutiveFailures, ev.Reason)
	}
	if ev.DurationSeconds != 30 {
		t.Errorf("first suspension must use the base duration, got %d", ev.DurationSeconds)
	}
	if healthy(store, targetA, now) {
		t.Error("a suspended target must not be healthy")
	}
}

// A target failing roughly one request in three never produces a run of three, so only the
// windowed rate rule can catch it. This is the blind spot the rule was added to close.
func TestHealth_IntermittentFailuresCaughtByErrorRate(t *testing.T) {
	s := testSuspension()
	s.ConsecutiveFailures = 3
	s.ErrorRatePercent = 30
	s.MinimumRequests = 20
	store := NewHealthStore(s)
	now := time.Now()

	var suspended *SuspensionEvent
	// One failure every third request: the consecutive counter never exceeds 1.
	for i := 0; i < 30 && suspended == nil; i++ {
		if i%3 == 0 {
			suspended = store.RecordFailure(targetA, Admission{}, 0, now)
		} else {
			store.RecordSuccess(targetA, Admission{}, 0, now)
		}
	}

	if suspended == nil {
		t.Fatal("a target failing ~1 in 3 must be suspended by the windowed rate rule")
	}
	if suspended.Reason != ReasonErrorRate {
		t.Errorf("expected reason %q, got %q", ReasonErrorRate, suspended.Reason)
	}
	if suspended.SampleSize < s.MinimumRequests {
		t.Errorf("the rule must not fire below the minimum sample size, got %d", suspended.SampleSize)
	}
}

// Below the minimum sample size the rate rule stays inert, so two failures out of two
// requests overnight do not read as a 100% error rate.
func TestHealth_RateRuleInertBelowMinimumSample(t *testing.T) {
	s := testSuspension()
	s.ConsecutiveFailures = 0 // isolate the rate rule
	s.ErrorRatePercent = 50
	s.MinimumRequests = 20
	store := NewHealthStore(s)
	now := time.Now()

	for i := 0; i < 5; i++ {
		if ev := store.RecordFailure(targetA, Admission{}, 0, now); ev != nil {
			t.Fatalf("suspended on a sample of %d, below the minimum of %d", i+1, s.MinimumRequests)
		}
	}
}

// A target whose p95 crosses the threshold is suspended even though no single request
// exceeded the per-attempt timeout — the creeping-slowness case a timeout-only rule misses.
func TestHealth_LatencyPercentileSuspends(t *testing.T) {
	s := testSuspension()
	s.ConsecutiveFailures = 0
	s.ErrorRatePercent = 0
	s.P95LatencyMs = 1000
	s.MinimumRequests = 20
	store := NewHealthStore(s)
	now := time.Now()

	// Every request succeeds, all of them slow. Nothing times out; nothing errors — so the
	// success that carries the window past minimumRequests is what trips the rule. A
	// trailing failure is deliberately NOT used to trigger it: needing one would mean the
	// rule could never fire for a target that is slow and working, which is the only
	// target it exists for.
	var suspended *SuspensionEvent
	for i := 0; i < 25 && suspended == nil; i++ {
		_, suspended = store.RecordSuccess(targetA, Admission{}, 2*time.Second, now)
	}

	if suspended == nil {
		t.Fatal("a sustained p95 above the threshold must suspend the target")
	}
	if suspended.Reason != ReasonLatency {
		t.Errorf("expected reason %q, got %q", ReasonLatency, suspended.Reason)
	}
	if suspended.SampleSize < s.MinimumRequests {
		t.Errorf("suspended on %d samples, below the configured minimum of %d",
			suspended.SampleSize, s.MinimumRequests)
	}
}

// Each re-suspension doubles the duration, and the cap stops it growing forever.
func TestHealth_BackoffDoublesAndCaps(t *testing.T) {
	s := testSuspension()
	s.DurationSeconds = 30
	s.MaxDurationSeconds = 120
	store := NewHealthStore(s)
	now := time.Now()

	// Capture the FIRST suspension of the run, not the last. Once a target has been
	// suspended, a window that ends leaves it half-open, and a single failed probe
	// re-suspends it immediately (FR-019d) — so later failures in the same run land on an
	// already-suspended target and report nothing.
	suspendOnce := func(at time.Time) *SuspensionEvent {
		var first *SuspensionEvent
		for i := 0; i < s.ConsecutiveFailures; i++ {
			if ev := store.RecordFailure(targetA, Admission{}, 0, at); ev != nil && first == nil {
				first = ev
			}
		}
		return first
	}

	want := []int{30, 60, 120, 120} // base, doubled, capped, still capped
	at := now
	for step, wantDuration := range want {
		ev := suspendOnce(at)
		if ev == nil {
			t.Fatalf("step %d: expected a suspension", step+1)
		}
		if ev.DurationSeconds != wantDuration {
			t.Errorf("step %d: expected duration %ds, got %ds", step+1, wantDuration, ev.DurationSeconds)
		}
		// Move past the suspension so the target returns to full rotation, then fail it again.
		at = at.Add(time.Duration(ev.DurationSeconds)*time.Second + time.Second)
		if !healthy(store, targetA, at) {
			t.Fatalf("step %d: target must return to rotation once the suspension expires", step+1)
		}
	}
}

// Staying healthy for the reset period returns the next suspension to the base duration. A
// target that keeps flapping never earns this.
func TestHealth_BackoffResetsAfterHealthyPeriod(t *testing.T) {
	s := testSuspension()
	s.BackoffResetSeconds = 100
	store := NewHealthStore(s)
	now := time.Now()

	for i := 0; i < s.ConsecutiveFailures; i++ {
		store.RecordFailure(targetA, Admission{}, 0, now)
	}
	// Expire the suspension, then stay healthy well past the reset period.
	later := now.Add(time.Duration(s.DurationSeconds)*time.Second + time.Second)
	probe, admitted := store.Admit(targetA, later)
	if !admitted {
		t.Fatal("expected the target back in rotation")
	}
	// One clean probe completes recovery (RecoverAfterSuccesses is 1 here), and THAT is when
	// the healthy clock starts — not when the window ended. The target has to then stay
	// healthy for BackoffResetSeconds to earn its way back to the base duration.
	store.RecordSuccess(targetA, probe, 0, later)

	recovered := later.Add(time.Duration(s.BackoffResetSeconds)*time.Second + time.Second)
	store.RecordSuccess(targetA, Admission{}, 0, recovered)

	var ev *SuspensionEvent
	for i := 0; i < s.ConsecutiveFailures; i++ {
		ev = store.RecordFailure(targetA, Admission{}, 0, recovered)
	}
	if ev == nil {
		t.Fatal("expected a suspension")
	}
	if ev.DurationSeconds != s.DurationSeconds {
		t.Errorf("after the healthy reset period the duration must return to the base %ds, got %ds",
			s.DurationSeconds, ev.DurationSeconds)
	}
}

// Identity is the (model, provider) pair: suspending one region must not suspend the same
// model elsewhere. This is what makes regional failover work.
func TestHealth_SameModelDifferentProvidersAreIndependent(t *testing.T) {
	store := NewHealthStore(testSuspension())
	now := time.Now()

	for i := 0; i < 3; i++ {
		store.RecordFailure(targetA, Admission{}, 0, now)
	}

	if healthy(store, targetA, now) {
		t.Error("targetA must be suspended")
	}
	if !healthy(store, targetB, now) {
		t.Error("the same model on a different provider must be unaffected")
	}
}

// Suspension disabled means a target never leaves the healthy state, however badly it fails.
func TestHealth_SuspensionDisabled(t *testing.T) {
	s := Suspension{ConsecutiveFailures: 0, ErrorRatePercent: 0, P95LatencyMs: 0,
		DurationSeconds: 30, MaxDurationSeconds: 120, BackoffResetSeconds: 600,
		WindowSeconds: 60, MinimumRequests: 20}
	s.clamp()
	store := NewHealthStore(s)
	now := time.Now()

	for i := 0; i < 50; i++ {
		if ev := store.RecordFailure(targetA, Admission{}, 0, now); ev != nil {
			t.Fatal("no criterion is enabled, so nothing may suspend")
		}
	}
	if !healthy(store, targetA, now) {
		t.Error("target must stay healthy when suspension is disabled")
	}
}

// Concurrent failures must not escalate a target twice for the same outage: the doubling is
// driven by distinct suspensions, not by how many requests happened to be in flight.
func TestHealth_ConcurrentFailuresSuspendOnce(t *testing.T) {
	store := NewHealthStore(testSuspension())
	now := time.Now()

	var (
		wg     sync.WaitGroup
		mu     sync.Mutex
		events []*SuspensionEvent
	)
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if ev := store.RecordFailure(targetA, Admission{}, 0, now); ev != nil {
				mu.Lock()
				events = append(events, ev)
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	if len(events) != 1 {
		t.Fatalf("expected exactly one suspension from a burst of concurrent failures, got %d", len(events))
	}
	if events[0].DurationSeconds != 30 {
		t.Errorf("a single outage must not escalate past the base duration, got %ds",
			events[0].DurationSeconds)
	}
}

// HealthyTargets is what routing policies rank over, so a suspended target must not appear.
func TestHealth_HealthyTargetsFiltersSuspended(t *testing.T) {
	store := NewHealthStore(testSuspension())
	now := time.Now()

	for i := 0; i < 3; i++ {
		store.RecordFailure(targetA, Admission{}, 0, now)
	}

	healthy := store.HealthyTargets([]Target{targetA, targetB}, now)
	if len(healthy) != 1 || !healthy[0].Equal(targetB) {
		t.Errorf("expected only targetB to be healthy, got %+v", healthy)
	}
}

// ---------------------------------------------------------------------------
// Half-open recovery (recoverAfterSuccesses) — the approved design's probe phase.
// ---------------------------------------------------------------------------

// healthy answers the admission question and discards the receipt, for the many tests that only
// care whether a target is in rotation.
//
// Discarding is deliberate and is itself part of the contract: a probe admitted this way has no
// receipt, so an outcome later recorded with the zero Admission will NOT resolve its run. A test
// about probe accounting keeps the receipt by calling Admit directly.
func healthy(store HealthStore, target Target, now time.Time) bool {
	_, ok := store.Admit(target, now)
	return ok
}

func halfOpenSuspension(recoverAfter int) Suspension {
	s := testSuspension()
	s.RecoverAfterSuccesses = recoverAfter
	s.clamp()
	return s
}

func suspend(store HealthStore, s Suspension, at time.Time) {
	for i := 0; i < s.ConsecutiveFailures; i++ {
		store.RecordFailure(targetA, Admission{}, 0, at)
	}
}

// The whole point of the probe phase: a window ending must NOT restore a full share of
// traffic in one step. Only one request at a time may touch the target until it has proved
// itself, so a target that is still broken costs one attempt, not a burst of them.
func TestHealth_HalfOpenAdmitsOneProbeAtATime(t *testing.T) {
	s := halfOpenSuspension(3)
	store := NewHealthStore(s)
	now := time.Now()
	suspend(store, s, now)

	after := now.Add(time.Duration(s.DurationSeconds)*time.Second + time.Second)

	if !healthy(store, targetA, after) {
		t.Fatal("the first request after the window must be admitted as a probe")
	}
	if healthy(store, targetA, after) {
		t.Fatal("a second concurrent request must NOT be admitted while a probe is in flight")
	}
}

// A clean probe does not restore the target on its own — the full run has to land.
func TestHealth_HalfOpenRestoresOnlyAfterTheFullRun(t *testing.T) {
	s := halfOpenSuspension(3)
	store := NewHealthStore(s)
	now := time.Now()
	suspend(store, s, now)
	at := now.Add(time.Duration(s.DurationSeconds)*time.Second + time.Second)

	for i := 1; i <= 3; i++ {
		probe, admitted := store.Admit(targetA, at)
		if !admitted {
			t.Fatalf("probe %d was not admitted", i)
		}
		// Graded against the receipt the admission returned. Passing the zero Admission
		// here would leave the run at zero for ever, which is the point of the receipt.
		store.RecordSuccess(targetA, probe, 0, at)
		at = at.Add(time.Second)
	}

	// Restored: two requests in a row are now admitted, which never happens while half-open.
	if !healthy(store, targetA, at) || !healthy(store, targetA, at) {
		t.Fatal("after the full run of successful probes the target must be back in normal rotation")
	}
}

// "Any failed probe suspends the target again" — and it does so immediately, without waiting
// for suspendAfterFailures, because the probe WAS the evidence.
func TestHealth_FailedProbeReSuspendsImmediately(t *testing.T) {
	s := halfOpenSuspension(3)
	store := NewHealthStore(s)
	now := time.Now()
	suspend(store, s, now)
	at := now.Add(time.Duration(s.DurationSeconds)*time.Second + time.Second)

	probe, admitted := store.Admit(targetA, at)
	if !admitted {
		t.Fatal("probe not admitted")
	}
	ev := store.RecordFailure(targetA, probe, 0, at)
	if ev == nil {
		t.Fatal("a failed probe must re-suspend the target on its own")
	}
	if ev.DurationSeconds != 2*s.DurationSeconds {
		t.Fatalf("re-suspension must double the window: got %ds, want %ds",
			ev.DurationSeconds, 2*s.DurationSeconds)
	}
	if healthy(store, targetA, at) {
		t.Fatal("the target must be out of rotation again")
	}
}

// A partial run is not progress to bank. Failing on probe 2 of 3 starts the next run at zero,
// otherwise a target that alternates pass/fail would creep back into rotation.
func TestHealth_PartialProbeRunIsNotBanked(t *testing.T) {
	s := halfOpenSuspension(3)
	store := NewHealthStore(s)
	now := time.Now()
	suspend(store, s, now)

	at := now.Add(time.Duration(s.DurationSeconds)*time.Second + time.Second)
	first, _ := store.Admit(targetA, at)
	store.RecordSuccess(targetA, first, 0, at) // 1 of 3
	second, _ := store.Admit(targetA, at)
	store.RecordFailure(targetA, second, 0, at) // fails — run discarded

	at = at.Add(time.Duration(2*s.DurationSeconds)*time.Second + time.Second)
	third, _ := store.Admit(targetA, at)
	store.RecordSuccess(targetA, third, 0, at) // 1 of 3 again, NOT 2 of 3

	if healthy(store, targetA, at) && healthy(store, targetA, at) {
		t.Fatal("target restored after a single success — the earlier partial run was banked")
	}
}

// An outcome can go missing: the request was abandoned, or the chain never reached this
// member. Without a lease expiry the one-at-a-time gate would stay shut forever and the
// target would never recover.
func TestHealth_ProbeLeaseExpiryReleasesTheGate(t *testing.T) {
	s := halfOpenSuspension(3)
	store := NewHealthStore(s)
	now := time.Now()
	suspend(store, s, now)
	at := now.Add(time.Duration(s.DurationSeconds)*time.Second + time.Second)

	if !healthy(store, targetA, at) {
		t.Fatal("probe not admitted")
	}
	// No outcome is ever recorded for it.
	if healthy(store, targetA, at.Add(probeLeaseSeconds*time.Second-time.Second)) {
		t.Fatal("the gate must stay shut while the lease is live")
	}
	if !healthy(store, targetA, at.Add(probeLeaseSeconds*time.Second+time.Second)) {
		t.Fatal("the gate must reopen once the lease expires, or the target can never recover")
	}
}

// Publishing the healthy set to routing policies must not consume a probe slot — asking what
// is healthy is not an attempt. It also must not advertise a half-open target as healthy.
func TestHealth_PublicationDoesNotConsumeAProbe(t *testing.T) {
	s := halfOpenSuspension(3)
	store := NewHealthStore(s)
	now := time.Now()
	suspend(store, s, now)
	at := now.Add(time.Duration(s.DurationSeconds)*time.Second + time.Second)

	if got := store.HealthyTargets([]Target{targetA}, at); len(got) != 0 {
		t.Fatalf("a half-open target must not be published as healthy, got %v", got)
	}
	if !healthy(store, targetA, at) {
		t.Fatal("publication consumed the probe slot")
	}
}

// A recovery that is never reported leaves the suspension line looking permanent, so an
// operator tracking a flapping provider needs both ends of the cycle.
func TestHealth_RecoveryIsReportedOnceWhenTheProbeRunCompletes(t *testing.T) {
	s := testSuspension()
	s.DurationSeconds = 60
	s.ConsecutiveFailures = 1
	s.clamp()
	store := NewHealthStore(s)
	target := Target{Model: "claude-3", Provider: "anthropic"}

	start := time.Now()
	store.RecordFailure(target, Admission{}, 0, start)

	later := start.Add(61 * time.Second)
	required := s.RecoverAfterSuccesses

	var events int
	var last *RecoveryEvent
	for i := 0; i < required; i++ {
		probe, admitted := store.Admit(target, later)
		if !admitted {
			t.Fatalf("probe %d was not admitted", i+1)
		}
		if event, _ := store.RecordSuccess(target, probe, 0, later); event != nil {
			events++
			last = event
		}
	}

	// Once, on the LAST probe. Reporting every successful probe would read as several
	// recoveries where there was one.
	if events != 1 {
		t.Fatalf("got %d recovery events over %d probes, want exactly 1", events, required)
	}
	if last.Target != target {
		t.Fatalf("event names %+v, want %+v", last.Target, target)
	}
	if last.ProbesRequired != required {
		t.Fatalf("probes_required = %d, want %d — a reader cannot otherwise tell a one-probe "+
			"recovery from the run that actually happened", last.ProbesRequired, required)
	}
	if last.SuspendedForSeconds != 60 {
		t.Fatalf("suspended_for_seconds = %d, want 60 so the line matches the suspension it ends",
			last.SuspendedForSeconds)
	}
}

// A plain success on a healthy target is not a recovery, or every request would report one.
func TestHealth_NoRecoveryEventWithoutASuspension(t *testing.T) {
	store := NewHealthStore(testSuspension())
	if event, _ := store.RecordSuccess(Target{Model: "gpt-4o"}, Admission{}, 0, time.Now()); event != nil {
		t.Fatalf("got a recovery event for a target that was never suspended: %+v", event)
	}
}

// FR-018e and SC-011b: "a target whose p95 triples while EVERY REQUEST STILL COMPLETES under
// perAttemptTimeoutMs is suspended — the case a timeout-only rule never sees."
//
// Distinct from TestHealth_LatencyPercentileSuspends above, which reaches the rule through a
// failure. That one proves the threshold arithmetic; this one proves the rule is reachable at
// all for the condition it was written for. A target that is merely slow never fails, so if
// only a failure can trigger evaluation the rule is unreachable in production and the
// requirement is not met by the arithmetic alone.
func TestHealth_SustainedSlownessSuspendsWithNoFailureAtAll(t *testing.T) {
	s := testSuspension()
	s.ConsecutiveFailures = 0
	s.ErrorRatePercent = 0
	s.P95LatencyMs = 1000
	s.MinimumRequests = 20
	store := NewHealthStore(s)
	now := time.Now()

	// Every request succeeds, every one of them slow. No timeouts, no errors — exactly the
	// degradation a timeout-only rule cannot see.
	for i := 0; i < 25; i++ {
		store.RecordSuccess(targetA, Admission{}, 2*time.Second, now)
	}

	if healthy(store, targetA, now) {
		t.Fatal("a target whose p95 is twice the configured threshold is still taking traffic; " +
			"the latency rule is unreachable without a failure, so FR-018e never fires for the case it exists for")
	}
}

// The other half of SC-011b: "a single outlier-slow request against an otherwise fast target
// suspends nothing." Now that a success can suspend, this is the regression that matters —
// the rule has to stay an aggregate judgement and must not become one-slow-request-condemns.
func TestHealth_OneSlowRequestAmongFastOnesSuspendsNothing(t *testing.T) {
	s := testSuspension()
	s.ConsecutiveFailures = 0
	s.ErrorRatePercent = 0
	s.P95LatencyMs = 1000
	s.MinimumRequests = 20
	store := NewHealthStore(s)
	now := time.Now()

	store.RecordSuccess(targetA, Admission{}, 9*time.Second, now) // the outlier
	for i := 0; i < 39; i++ {
		if _, suspended := store.RecordSuccess(targetA, Admission{}, 10*time.Millisecond, now); suspended != nil {
			t.Fatalf("a fast target was suspended after one slow request: p95 read as %v over %d samples",
				suspended.Observed, suspended.SampleSize)
		}
	}
	if !healthy(store, targetA, now) {
		t.Fatal("a target whose requests are fast apart from one outlier must keep taking traffic")
	}
}

// The asymmetry is deliberate and worth pinning: a success feeds the error-rate window but
// never evaluates it, because a success can only push a rate DOWN. If that ever changes, the
// change should be a decision rather than a side effect of touching this file.
func TestHealth_SuccessDoesNotEvaluateTheErrorRateRule(t *testing.T) {
	s := testSuspension()
	s.ConsecutiveFailures = 0
	s.ErrorRatePercent = 50
	s.P95LatencyMs = 0
	s.MinimumRequests = 10
	store := NewHealthStore(s)
	now := time.Now()

	// Nine failures, then a success takes the window to the minimum sample size with the
	// rate still at 90%. The success must not be what suspends it.
	for i := 0; i < 9; i++ {
		store.RecordFailure(targetA, Admission{}, 0, now)
	}
	if _, suspended := store.RecordSuccess(targetA, Admission{}, 0, now); suspended != nil {
		t.Fatalf("a success evaluated the error-rate rule and suspended the target: %+v", suspended)
	}
}

// The target map must not grow without bound.
//
// A wildcard member resolves the CLIENT's model into the health key, so every distinct model a
// caller names created a permanent entry and nothing removed it — unbounded by any quantity an
// operator controls. Idle, stateless entries are now evicted.
func TestHealthStore_EvictsIdleEntriesButKeepsSuspendedOnes(t *testing.T) {
	s := testSuspension()
	s.ConsecutiveFailures = 1
	// Long enough to still be ACTIVE when the sweep runs. With a shorter window the
	// suspension has already expired by then, another guard protects the entry, and the test
	// would pass even if the suspended-target guard were deleted.
	s.DurationSeconds = 7200
	s.MaxDurationSeconds = 7200
	s.clamp()
	m := NewHealthStore(s).(*memoryHealthStore)
	now := time.Now()

	// One target that is genuinely suspended, and must survive any sweep.
	suspended := Target{Model: "gpt-4o", Provider: "openai"}
	m.RecordFailure(suspended, Admission{}, 5*time.Millisecond, now)
	if healthy(m, suspended, now) {
		t.Fatal("fixture is wrong: the target should be suspended")
	}

	// Past the threshold with idle, stateless entries, all older than the TTL.
	for i := 0; i < healthSweepThreshold+50; i++ {
		healthy(m, Target{Model: fmt.Sprintf("wildcard-model-%d", i), Provider: "openai"}, now)
	}
	grown := len(m.targets)
	if grown <= healthSweepThreshold {
		t.Fatalf("fixture is wrong: only %d entries, expected to exceed the threshold", grown)
	}

	// Long enough later that the idle entries are evictable and the sweep interval has passed.
	later := now.Add(healthIdleTTL + healthSweepInterval + time.Minute)
	healthy(m, Target{Model: "one-more", Provider: "openai"}, later)

	if len(m.targets) >= grown {
		t.Fatalf("no eviction: %d entries before, %d after", grown, len(m.targets))
	}
	if _, stillThere := m.targets[suspended.Key()]; !stillThere {
		t.Fatal("the suspended target's entry was evicted outright")
	}
	if healthy(m, suspended, later) {
		t.Fatal("the suspended target was evicted; its suspension would be cleared and a " +
			"failing provider would get its traffic back")
	}
}

// Which guards actually protect a suspended entry at sweep time.
//
// Pins the state the eviction test depends on, because the two relevant guards are redundant
// with each other here: a single-guard mutation still passes, and only removing both evicts the
// entry. Without this, a later change that quietly drops one guard would look safe.
func TestHealthStore_SuspendedEntryStateAtSweepTime(t *testing.T) {
	s := testSuspension()
	s.ConsecutiveFailures = 1
	s.DurationSeconds = 7200
	s.MaxDurationSeconds = 7200
	s.clamp()
	m := NewHealthStore(s).(*memoryHealthStore)
	now := time.Now()
	target := Target{Model: "gpt-4o", Provider: "openai"}
	m.RecordFailure(target, Admission{}, 5*time.Millisecond, now)

	h := m.targets[target.Key()]
	later := now.Add(healthIdleTTL + healthSweepInterval + time.Minute)
	total, _ := h.window.counts(later)

	// TWO guards hold a suspended entry, independently: the suspension itself, and the
	// escalation step the suspension left behind. The window has aged out by now and the
	// consecutive count was reset when the suspension was applied, so neither of those is
	// doing the work. Removing either one alone still keeps the entry; removing both evicts
	// it. Recorded so a future reader does not delete one as redundant — it is the other that
	// is covering it, and only for a target suspended by the consecutive-failure criterion.
	if !h.suspendedUntil.After(later) {
		t.Fatal("suspension is not active at sweep time; the fixture no longer tests the guard")
	}
	if h.escalationStep == 0 {
		t.Fatal("escalation step is zero; the second guard is no longer present")
	}
	if h.consecutiveFailures != 0 || total != 0 {
		t.Fatalf("fixture drifted: consecutiveFailures=%d windowCount=%d, expected both zero so "+
			"the two guards under test are the only protection", h.consecutiveFailures, total)
	}
}

// A chain admits every member it keeps, but Envoy attempts them one at a time and usually
// stops at the first. The members below the serving one were reserved and never tried, and
// holding their slots for the full lease excludes them from a later request that genuinely
// needs them — on the strength of a request that never reached them.
func TestHealth_ReleasingAnUnusedProbeReopensTheGateAtOnce(t *testing.T) {
	s := halfOpenSuspension(3)
	store := NewHealthStore(s)
	now := time.Now()
	suspend(store, s, now)
	at := now.Add(time.Duration(s.DurationSeconds)*time.Second + time.Second)

	probe, admitted := store.Admit(targetA, at)
	if !admitted {
		t.Fatal("precondition: the window has ended, so a probe must be admitted")
	}
	// Control: while the reservation stands, nobody else gets in.
	if healthy(store, targetA, at) {
		t.Fatal("precondition: a live reservation must keep the gate shut")
	}

	store.ReleaseProbe(targetA, probe, at)

	// Immediately, not probeLeaseSeconds later. The clock has not moved.
	if !healthy(store, targetA, at) {
		t.Fatal("a released reservation must reopen the gate at once, or an unattempted " +
			"fallback stays excluded for the whole lease")
	}
}

// Releasing is itself identity-checked. A receipt that no longer names the live reservation
// must not open a gate somebody else is holding, or the release path becomes a way to run two
// probes at once against a target that is still being judged one request at a time.
func TestHealth_ReleasingAStaleReceiptDoesNotOpenAnotherProbesGate(t *testing.T) {
	s := halfOpenSuspension(3)
	store := NewHealthStore(s)
	now := time.Now()
	suspend(store, s, now)
	at := now.Add(time.Duration(s.DurationSeconds)*time.Second + time.Second)

	stale, admitted := store.Admit(targetA, at)
	if !admitted {
		t.Fatal("precondition: first probe not admitted")
	}
	// Let the lease lapse so a second reservation can be issued, then take one.
	expired := at.Add(probeLeaseSeconds*time.Second + time.Second)
	live, admitted := store.Admit(targetA, expired)
	if !admitted {
		t.Fatal("precondition: the lapsed lease must let a second probe in")
	}
	if live.ID == stale.ID {
		t.Fatal("precondition: a replacement reservation must have its own identity")
	}

	store.ReleaseProbe(targetA, stale, expired)

	if healthy(store, targetA, expired) {
		t.Fatal("a stale receipt released the live probe's gate — two probes can now run " +
			"against a target that may still be broken")
	}
}

// The same identity check on the outcome path. An outcome that arrives after its own lease
// expired belongs to a reservation that no longer exists; counting it releases the gate of the
// probe that replaced it and credits that run with an answer from minutes ago.
func TestHealth_AStaleOutcomeDoesNotResolveTheProbeThatReplacedIt(t *testing.T) {
	s := halfOpenSuspension(2)
	store := NewHealthStore(s)
	now := time.Now()
	suspend(store, s, now)
	at := now.Add(time.Duration(s.DurationSeconds)*time.Second + time.Second)

	stale, admitted := store.Admit(targetA, at)
	if !admitted {
		t.Fatal("precondition: first probe not admitted")
	}
	expired := at.Add(probeLeaseSeconds*time.Second + time.Second)
	if _, admitted = store.Admit(targetA, expired); !admitted {
		t.Fatal("precondition: the lapsed lease must let a second probe in")
	}

	if recovered, _ := store.RecordSuccess(targetA, stale, 0, expired); recovered != nil {
		t.Fatal("a stale outcome reported a recovery for a run it was never part of")
	}
	// The gate is the observable half: if the stale success had been counted it would have
	// released the live probe, letting a third request through while the second is still out.
	if healthy(store, targetA, expired) {
		t.Fatal("a stale outcome released the live probe's gate")
	}
}

// A streamed probe is credited when its headers arrive, because withholding that would leave a
// target whose responses are all streamed suspended for ever (FR-030p). The credit is therefore
// optimistic, and a completion verdict naming the SAME reservation has to be able to take it
// back — otherwise the stream that died mid-body is graded against a target its own headers
// already returned to rotation.
func TestHealth_AStreamThatDiesAfterItsHeadersUndoesTheProbeCredit(t *testing.T) {
	s := halfOpenSuspension(1) // one clean probe is a full recovery, so the credit restores it
	store := NewHealthStore(s)
	now := time.Now()
	suspend(store, s, now)
	at := now.Add(time.Duration(s.DurationSeconds)*time.Second + time.Second)

	probe, admitted := store.Admit(targetA, at)
	if !admitted {
		t.Fatal("precondition: probe not admitted")
	}
	if recovered := store.RecordUnverified(targetA, probe, at); recovered == nil {
		t.Fatal("precondition: a provisional outcome must complete a one-probe run (FR-030p)")
	}
	// Control: the optimistic credit really did restore it — two admissions in a row, which
	// never happens while half-open.
	if !healthy(store, targetA, at) || !healthy(store, targetA, at) {
		t.Fatal("precondition: the probe credit should have returned the target to rotation")
	}

	// The body then died. The verdict names the reservation the stream ran on.
	event := store.RecordFailure(targetA, probe, 0, at)

	if event == nil {
		t.Fatal("the completion verdict must re-suspend the target: the probe it was graded " +
			"against had already been credited on a status that the body never earned")
	}
	if healthy(store, targetA, at) {
		t.Fatal("the target is still in rotation after its probe failed")
	}
}

// And the reversal is identity-checked too: a verdict for some OTHER reservation must not take
// back a credit it has nothing to do with.
func TestHealth_AnUnrelatedVerdictDoesNotUndoAProbeCredit(t *testing.T) {
	s := halfOpenSuspension(1)
	s.ConsecutiveFailures = 5 // high, so an ordinary failure cannot suspend on its own here
	s.clamp()
	store := NewHealthStore(s)
	now := time.Now()
	for i := 0; i < s.ConsecutiveFailures; i++ {
		store.RecordFailure(targetA, Admission{}, 0, now)
	}
	at := now.Add(time.Duration(s.DurationSeconds)*time.Second + time.Second)

	probe, admitted := store.Admit(targetA, at)
	if !admitted {
		t.Fatal("precondition: probe not admitted")
	}
	if recovered := store.RecordUnverified(targetA, probe, at); recovered == nil {
		t.Fatal("precondition: the provisional outcome should have completed the run")
	}

	// A verdict carrying a receipt that was never issued for this target.
	if event := store.RecordFailure(targetA, Admission{Probe: true, ID: probe.ID + 1000}, 0, at); event != nil {
		t.Fatal("an unrelated verdict re-suspended a target whose own probe is still credited")
	}
	if !healthy(store, targetA, at) {
		t.Fatal("an unrelated verdict pushed the target out of rotation")
	}
}
