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

	if ev := store.RecordFailure(targetA, 0, now); ev != nil {
		t.Fatal("one failure must not suspend")
	}
	store.RecordSuccess(targetA, 0, now)
	if ev := store.RecordFailure(targetA, 0, now); ev != nil {
		t.Fatal("the success must have reset the consecutive count")
	}

	store.RecordFailure(targetA, 0, now)
	ev := store.RecordFailure(targetA, 0, now)
	if ev == nil {
		t.Fatal("three consecutive failures must suspend")
	}
	if ev.Reason != ReasonConsecutiveFailures {
		t.Errorf("expected reason %q, got %q", ReasonConsecutiveFailures, ev.Reason)
	}
	if ev.DurationSeconds != 30 {
		t.Errorf("first suspension must use the base duration, got %d", ev.DurationSeconds)
	}
	if store.Healthy(targetA, now) {
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
			suspended = store.RecordFailure(targetA, 0, now)
		} else {
			store.RecordSuccess(targetA, 0, now)
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
		if ev := store.RecordFailure(targetA, 0, now); ev != nil {
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

	// Every request succeeds, all of them slow. Nothing times out; nothing errors.
	var suspended *SuspensionEvent
	for i := 0; i < 25; i++ {
		store.RecordSuccess(targetA, 2*time.Second, now)
	}
	// A failure is what triggers evaluation; the latency rule then fires on the window.
	suspended = store.RecordFailure(targetA, 2*time.Second, now)

	if suspended == nil {
		t.Fatal("a sustained p95 above the threshold must suspend the target")
	}
	if suspended.Reason != ReasonLatency {
		t.Errorf("expected reason %q, got %q", ReasonLatency, suspended.Reason)
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
			if ev := store.RecordFailure(targetA, 0, at); ev != nil && first == nil {
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
		if !store.Healthy(targetA, at) {
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
		store.RecordFailure(targetA, 0, now)
	}
	// Expire the suspension, then stay healthy well past the reset period.
	later := now.Add(time.Duration(s.DurationSeconds)*time.Second + time.Second)
	if !store.Healthy(targetA, later) {
		t.Fatal("expected the target back in rotation")
	}
	// One clean probe completes recovery (RecoverAfterSuccesses is 1 here), and THAT is when
	// the healthy clock starts — not when the window ended. The target has to then stay
	// healthy for BackoffResetSeconds to earn its way back to the base duration.
	store.RecordSuccess(targetA, 0, later)

	recovered := later.Add(time.Duration(s.BackoffResetSeconds)*time.Second + time.Second)
	store.RecordSuccess(targetA, 0, recovered)

	var ev *SuspensionEvent
	for i := 0; i < s.ConsecutiveFailures; i++ {
		ev = store.RecordFailure(targetA, 0, recovered)
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
		store.RecordFailure(targetA, 0, now)
	}

	if store.Healthy(targetA, now) {
		t.Error("targetA must be suspended")
	}
	if !store.Healthy(targetB, now) {
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
		if ev := store.RecordFailure(targetA, 0, now); ev != nil {
			t.Fatal("no criterion is enabled, so nothing may suspend")
		}
	}
	if !store.Healthy(targetA, now) {
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
			if ev := store.RecordFailure(targetA, 0, now); ev != nil {
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
		store.RecordFailure(targetA, 0, now)
	}

	healthy := store.HealthyTargets([]Target{targetA, targetB}, now)
	if len(healthy) != 1 || !healthy[0].Equal(targetB) {
		t.Errorf("expected only targetB to be healthy, got %+v", healthy)
	}
}

// ---------------------------------------------------------------------------
// Half-open recovery (recoverAfterSuccesses) — the approved design's probe phase.
// ---------------------------------------------------------------------------

func halfOpenSuspension(recoverAfter int) Suspension {
	s := testSuspension()
	s.RecoverAfterSuccesses = recoverAfter
	s.clamp()
	return s
}

func suspend(store HealthStore, s Suspension, at time.Time) {
	for i := 0; i < s.ConsecutiveFailures; i++ {
		store.RecordFailure(targetA, 0, at)
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

	if !store.Healthy(targetA, after) {
		t.Fatal("the first request after the window must be admitted as a probe")
	}
	if store.Healthy(targetA, after) {
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
		if !store.Healthy(targetA, at) {
			t.Fatalf("probe %d was not admitted", i)
		}
		store.RecordSuccess(targetA, 0, at)
		at = at.Add(time.Second)
	}

	// Restored: two requests in a row are now admitted, which never happens while half-open.
	if !store.Healthy(targetA, at) || !store.Healthy(targetA, at) {
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

	if !store.Healthy(targetA, at) {
		t.Fatal("probe not admitted")
	}
	ev := store.RecordFailure(targetA, 0, at)
	if ev == nil {
		t.Fatal("a failed probe must re-suspend the target on its own")
	}
	if ev.DurationSeconds != 2*s.DurationSeconds {
		t.Fatalf("re-suspension must double the window: got %ds, want %ds",
			ev.DurationSeconds, 2*s.DurationSeconds)
	}
	if store.Healthy(targetA, at) {
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
	store.Healthy(targetA, at)
	store.RecordSuccess(targetA, 0, at) // 1 of 3
	store.Healthy(targetA, at)
	store.RecordFailure(targetA, 0, at) // fails — run discarded

	at = at.Add(time.Duration(2*s.DurationSeconds)*time.Second + time.Second)
	store.Healthy(targetA, at)
	store.RecordSuccess(targetA, 0, at) // 1 of 3 again, NOT 2 of 3

	if store.Healthy(targetA, at) && store.Healthy(targetA, at) {
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

	if !store.Healthy(targetA, at) {
		t.Fatal("probe not admitted")
	}
	// No outcome is ever recorded for it.
	if store.Healthy(targetA, at.Add(probeLeaseSeconds*time.Second-time.Second)) {
		t.Fatal("the gate must stay shut while the lease is live")
	}
	if !store.Healthy(targetA, at.Add(probeLeaseSeconds*time.Second+time.Second)) {
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
	if !store.Healthy(targetA, at) {
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
	store.RecordFailure(target, 0, start)

	later := start.Add(61 * time.Second)
	required := s.RecoverAfterSuccesses

	var events int
	var last *RecoveryEvent
	for i := 0; i < required; i++ {
		if !store.Healthy(target, later) {
			t.Fatalf("probe %d was not admitted", i+1)
		}
		if event := store.RecordSuccess(target, 0, later); event != nil {
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
	if event := store.RecordSuccess(Target{Model: "gpt-4o"}, 0, time.Now()); event != nil {
		t.Fatalf("got a recovery event for a target that was never suspended: %+v", event)
	}
}
