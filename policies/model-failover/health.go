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
	"time"
)

// SuspensionReason names which criterion suspended a target. It is carried into the
// suspension record so an operator can tell a hard outage from intermittent degradation from
// creeping slowness, without reconstructing it from raw logs (FR-018d).
type SuspensionReason string

const (
	ReasonConsecutiveFailures SuspensionReason = "consecutive_failures"
	ReasonErrorRate           SuspensionReason = "error_rate"
	ReasonLatency             SuspensionReason = "latency_p95"
)

// RecoveryEvent reports a target returning to normal rotation after suspension.
//
// Emitted only on the LAST probe of the run, not on each one: a target is either in rotation
// or not, and reporting every successful probe would read as several recoveries where there
// was one. ProbesRequired is carried so a reader can tell a one-probe recovery from the
// several-probe run that actually happened.
type RecoveryEvent struct {
	Target         Target
	ProbesRequired int
	// SuspendedForSeconds is the duration that had been applied, so a recovery line can be
	// matched to the suspension line it ends.
	SuspendedForSeconds int
	// EscalationStep is where the target sits on the backoff ladder as it returns. A target
	// recovering at step 3 has been round this loop before and is worth attention even
	// though it is, right now, healthy.
	EscalationStep int
}

// SuspensionEvent describes one suspension, for telemetry.
type SuspensionEvent struct {
	Target Target
	Reason SuspensionReason
	// Observed is the value that crossed the threshold: the consecutive count, the error
	// rate percentage, or the p95 in milliseconds.
	Observed int
	// SampleSize is the number of requests in the window, for the windowed criteria. It is
	// what distinguishes "50% of 2 requests" from "50% of 2000".
	SampleSize int
	// DurationSeconds is the suspension applied, after any doubling.
	DurationSeconds int
	// EscalationStep is how many times this target has been suspended without earning a
	// reset. Step 1 is the base duration; each later step doubles until the cap.
	EscalationStep int
}

// targetHealth is the per-target runtime state.
type targetHealth struct {
	consecutiveFailures int
	suspendedUntil      time.Time
	// currentDurationSeconds is the duration applied to the NEXT suspension. It doubles on
	// each re-suspension up to the cap, and resets to the base after a healthy period.
	currentDurationSeconds int
	escalationStep         int
	// healthySince is when the target last became healthy. Staying healthy for
	// BackoffResetSeconds is what earns the reset to base.
	healthySince time.Time
	window       *rollingWindow

	// --- half-open probing, once a suspension window has ended ---
	//
	// halfOpen means the window has ended but the target has NOT earned its place back.
	// It is admitted one request at a time until RecoverAfterSuccesses succeed in a row.
	halfOpen bool
	// probeSuccesses counts the run so far. Any failure resets it by re-suspending.
	probeSuccesses int
	// probeInFlight is the "one at a time" gate: while a probe is out, every other request
	// sees the target as unavailable.
	probeInFlight bool
	// probeLeaseUntil bounds that gate. An outcome can go missing — the request was
	// abandoned, the chain never reached this member, the stream died — and without an
	// expiry a lost outcome would hold the gate shut forever and the target would never
	// recover.
	probeLeaseUntil time.Time
}

// probeLeaseSeconds is how long a reserved probe slot is held when no outcome arrives.
//
// Short, because a lost outcome delays recovery by exactly this long. Not shorter, because
// it must comfortably exceed a normal upstream round trip or two probes would run at once.
const probeLeaseSeconds = 30

// HealthStore tracks per-target health for one operation.
//
// State is held per gateway instance and nothing is shared between replicas (FR-020). The
// consequence is deliberate and documented: each instance learns a failing target
// independently, so across N instances a target can absorb up to N times the configured
// threshold before every instance suspends it.
//
// Everything outside this type goes through the small interface below, so a shared
// cross-instance implementation can replace it later without touching the policy's
// configuration, its per-request semantics, or its telemetry (FR-020a).
type HealthStore interface {
	// Healthy reports whether the target may receive traffic now.
	Healthy(target Target, now time.Time) bool
	// RecordSuccess clears the consecutive-failure count and feeds the window.
	//
	// It returns AT MOST ONE of two events, never both: a recovery when this success
	// completed a probe run and returned the target to rotation, or a suspension when the
	// success carried the latency window over its threshold.
	//
	// A success suspending a target reads oddly until you look at what the latency rule
	// measures. A target that is merely slow never fails, so its samples are all successes —
	// if only a failure could trigger evaluation, FR-018e would be unreachable for exactly
	// the degradation it was written to catch ("every request still completes under
	// perAttemptTimeoutMs"). The error-rate rule is NOT evaluated here: a success can only
	// push a rate down, so there is nothing for it to discover.
	RecordSuccess(target Target, latency time.Duration, now time.Time) (*RecoveryEvent, *SuspensionEvent)
	// RecordUnverified records that the target answered without judging whether the
	// answer COMPLETED. Used when the status line is provisional -- a streamed response
	// commits its 200 before the body exists, so a stream cut mid-body still reaches the
	// response phase as the success it started as (FR-030n, FR-030p).
	//
	// It deliberately does NOT clear the consecutive-failure count and does NOT add a
	// sample to the window. Recording a provisional success as a real one is what lets a
	// provider that truncates everything immunise itself: the reset wipes the counter its
	// real failures were accumulating, and the sample dilutes the error rate below the
	// threshold. Recording nothing leaves both to be decided by outcomes we can see.
	//
	// Probe accounting is the one exception, and it is deliberate: a half-open probe that
	// answers still counts toward recovery, because withholding that too would leave a
	// target whose responses are all streamed suspended forever (FR-030p).
	RecordUnverified(target Target, now time.Time) *RecoveryEvent
	// RecordFailure feeds every suspension criterion and returns a non-nil event if this
	// outcome suspended the target.
	RecordFailure(target Target, latency time.Duration, now time.Time) *SuspensionEvent
	// HealthyTargets filters a list down to the targets that may receive traffic, without
	// reserving a probe slot. Read-only: asking is never an attempt.
	//
	// Not published anywhere. Health is this policy's own per-instance state and stays
	// private — a routing policy consuming it would be depending on a view it cannot
	// reason about, and it buys nothing, since resolveChain already filters suspended
	// targets out of the chain wherever they appear.
	HealthyTargets(targets []Target, now time.Time) []Target
}

// memoryHealthStore is the in-memory, per-instance implementation.
type memoryHealthStore struct {
	mu         sync.Mutex
	targets    map[string]*targetHealth
	suspension Suspension
}

// NewHealthStore returns the per-instance health store described by FR-020.
func NewHealthStore(suspension Suspension) HealthStore {
	return &memoryHealthStore{
		targets:    make(map[string]*targetHealth),
		suspension: suspension,
	}
}

// suspensionDisabled reports whether a member can ever leave the healthy state.
//
// suspendDuration is the master switch, per the reviewed schema: "Set to 0 to disable
// suspension tracking entirely." A zero-length suspension would otherwise fire every criterion
// and expire instantly, burning bookkeeping to no effect. Failover still works with suspension
// off — a failing member is simply re-attempted on every request rather than skipped.
//
// With a duration set, a member is still immune when every criterion is itself off.
func (s Suspension) suspensionDisabled() bool {
	if s.DurationSeconds <= 0 {
		return true
	}
	return s.ConsecutiveFailures == 0 && s.ErrorRatePercent == 0 && s.P95LatencyMs == 0
}

func (m *memoryHealthStore) state(target Target, now time.Time) *targetHealth {
	key := target.Key()
	h, ok := m.targets[key]
	if !ok {
		h = &targetHealth{
			currentDurationSeconds: m.suspension.DurationSeconds,
			healthySince:           now,
			window:                 newRollingWindow(time.Duration(m.suspension.WindowSeconds) * time.Second),
		}
		m.targets[key] = h
	}
	return h
}

func (m *memoryHealthStore) Healthy(target Target, now time.Time) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.admitLocked(target, now)
}

// transitionLocked applies the time-based state changes: a suspension window ending, and a
// probe lease expiring. Both are "nothing happened, but time passed" transitions, so they
// belong in one place rather than being re-derived at every call site.
func (m *memoryHealthStore) transitionLocked(h *targetHealth, now time.Time) {
	if !h.suspendedUntil.IsZero() && now.After(h.suspendedUntil) {
		// The window has ended. The target does NOT go straight back to full rotation: it
		// enters the half-open state and has to earn its place back one request at a time
		// (FR-019d). Restoring it in one step would send it a full share of traffic before
		// anything had checked whether it is still broken.
		h.suspendedUntil = time.Time{}
		h.halfOpen = true
		h.probeSuccesses = 0
		h.probeInFlight = false
		h.consecutiveFailures = 0
		h.window.reset()
	}
	if h.probeInFlight && now.After(h.probeLeaseUntil) {
		// The probe's outcome never arrived. Release the gate so recovery can continue.
		h.probeInFlight = false
	}
}

// admitLocked decides whether this request may use the target, and reserves the probe slot
// when it is a half-open one. It has a side effect by design: "may I use it" and "I am using
// it" are the same question when only one probe may be outstanding.
func (m *memoryHealthStore) admitLocked(target Target, now time.Time) bool {
	h := m.state(target, now)
	m.transitionLocked(h, now)

	if !h.suspendedUntil.IsZero() {
		return false
	}
	if !h.halfOpen {
		return true
	}
	if h.probeInFlight {
		return false
	}
	h.probeInFlight = true
	h.probeLeaseUntil = now.Add(probeLeaseSeconds * time.Second)
	return true
}

// reportableLocked answers the same question as the admission check WITHOUT reserving
// anything. Reading health must not consume a half-open target's single probe slot: that slot
// belongs to a real request, and spending it on a query would stop the target ever recovering.
func (m *memoryHealthStore) reportableLocked(target Target, now time.Time) bool {
	h := m.state(target, now)
	m.transitionLocked(h, now)
	return h.suspendedUntil.IsZero() && !h.halfOpen
}

func (m *memoryHealthStore) RecordSuccess(target Target, latency time.Duration, now time.Time) (*RecoveryEvent, *SuspensionEvent) {
	m.mu.Lock()
	defer m.mu.Unlock()

	h := m.state(target, now)
	m.transitionLocked(h, now)
	h.consecutiveFailures = 0
	h.window.add(now, false, latency)

	if h.halfOpen {
		// A probe came back clean. Release the gate and count it; the target returns to
		// normal rotation only once the whole run is in (FR-019d).
		h.probeInFlight = false
		h.probeSuccesses++
		if h.probeSuccesses >= m.suspension.RecoverAfterSuccesses {
			h.halfOpen = false
			h.probeSuccesses = 0
			h.healthySince = now
			return &RecoveryEvent{
				Target:              target,
				ProbesRequired:      m.suspension.RecoverAfterSuccesses,
				SuspendedForSeconds: h.currentDurationSeconds,
				EscalationStep:      h.escalationStep,
			}, nil
		}
		return nil, nil
	}

	// A target that has stayed healthy long enough earns its escalation back to the base
	// duration. A target that keeps flapping never reaches this and keeps doubling toward
	// the cap (FR-019c).
	if !h.healthySince.IsZero() &&
		now.Sub(h.healthySince) >= time.Duration(m.suspension.BackoffResetSeconds)*time.Second {
		h.currentDurationSeconds = m.suspension.DurationSeconds
		h.escalationStep = 0
	}

	return nil, m.evaluateLatencyLocked(h, target, now)
}

// evaluateLatencyLocked applies the latency rule to the window as it now stands.
//
// Split out because it is the one criterion a SUCCESS can carry over its threshold, so it has
// to be reachable from both record paths; the consecutive and error-rate rules are about
// failures and stay where failures are counted.
func (m *memoryHealthStore) evaluateLatencyLocked(h *targetHealth, target Target,
	now time.Time) *SuspensionEvent {

	if m.suspension.suspensionDisabled() || m.suspension.P95LatencyMs <= 0 {
		return nil
	}
	// Already suspended, or waiting on a probe: not a second verdict on the same outage,
	// and never a verdict on the probe that is trying to clear it.
	if h.halfOpen || (!h.suspendedUntil.IsZero() && now.Before(h.suspendedUntil)) {
		return nil
	}
	total, _ := h.window.counts(now)
	if total < m.suspension.MinimumRequests {
		// The same sample-size guard as the error-rate rule (FR-018b): a percentile over
		// three requests describes nothing.
		return nil
	}
	if p95 := int(h.window.percentile(now, 0.95) / time.Millisecond); p95 >= m.suspension.P95LatencyMs {
		return m.suspendLocked(h, target, ReasonLatency, p95, total, now)
	}
	return nil
}

func (m *memoryHealthStore) RecordUnverified(target Target, now time.Time) *RecoveryEvent {
	m.mu.Lock()
	defer m.mu.Unlock()

	h := m.state(target, now)
	m.transitionLocked(h, now)

	// No window sample and no counter reset: see the interface comment. The only state this
	// advances is the probe run, because a suspended target has to be able to come back.
	if !h.halfOpen {
		return nil
	}
	h.probeInFlight = false
	h.probeSuccesses++
	if h.probeSuccesses < m.suspension.RecoverAfterSuccesses {
		return nil
	}
	h.halfOpen = false
	h.probeSuccesses = 0
	h.healthySince = now
	return &RecoveryEvent{
		Target:              target,
		ProbesRequired:      m.suspension.RecoverAfterSuccesses,
		SuspendedForSeconds: h.currentDurationSeconds,
		EscalationStep:      h.escalationStep,
	}
}

func (m *memoryHealthStore) RecordFailure(target Target, latency time.Duration, now time.Time) *SuspensionEvent {
	m.mu.Lock()
	defer m.mu.Unlock()

	h := m.state(target, now)
	m.transitionLocked(h, now)
	h.consecutiveFailures++
	h.window.add(now, true, latency)

	if h.halfOpen && !m.suspension.suspensionDisabled() {
		// A failed probe re-suspends at once, whatever suspendAfterFailures says. The
		// target was already suspended; this attempt was the evidence that it is still
		// broken, and that is the whole point of probing one request at a time.
		h.probeInFlight = false
		h.halfOpen = false
		h.probeSuccesses = 0
		return m.suspendLocked(h, target, ReasonConsecutiveFailures, h.consecutiveFailures, 0, now)
	}

	if m.suspension.suspensionDisabled() {
		return nil
	}
	// Already suspended: a late failure from an in-flight request must not escalate the
	// target a second time for the same outage.
	if !h.suspendedUntil.IsZero() && now.Before(h.suspendedUntil) {
		return nil
	}

	// The criteria are independent and either can suspend (FR-018c). Consecutive failures
	// catch a hard-down target fastest, so they are checked first; the windowed rules catch
	// the degradation that never produces a run.
	if m.suspension.ConsecutiveFailures > 0 && h.consecutiveFailures >= m.suspension.ConsecutiveFailures {
		return m.suspendLocked(h, target, ReasonConsecutiveFailures, h.consecutiveFailures, 0, now)
	}

	total, failures := h.window.counts(now)
	if total >= m.suspension.MinimumRequests {
		// The minimum sample size is what stops two failures out of two requests reading as
		// a 100% error rate and suspending a healthy target during a quiet period (FR-018b).
		if m.suspension.ErrorRatePercent > 0 {
			rate := failures * 100 / total
			if rate >= m.suspension.ErrorRatePercent {
				return m.suspendLocked(h, target, ReasonErrorRate, rate, total, now)
			}
		}
	}

	return m.evaluateLatencyLocked(h, target, now)
}

// suspendLocked applies the escalating backoff and returns the event describing it.
func (m *memoryHealthStore) suspendLocked(h *targetHealth, target Target, reason SuspensionReason,
	observed, sampleSize int, now time.Time) *SuspensionEvent {

	if h.escalationStep > 0 {
		// Re-suspension doubles the previous duration (FR-019a), capped so a target is never
		// held out of service indefinitely (FR-019b).
		h.currentDurationSeconds *= 2
		if h.currentDurationSeconds > m.suspension.MaxDurationSeconds {
			h.currentDurationSeconds = m.suspension.MaxDurationSeconds
		}
	}
	h.escalationStep++
	h.suspendedUntil = now.Add(time.Duration(h.currentDurationSeconds) * time.Second)
	h.consecutiveFailures = 0
	h.healthySince = time.Time{}
	h.window.reset()

	return &SuspensionEvent{
		Target:          target,
		Reason:          reason,
		Observed:        observed,
		SampleSize:      sampleSize,
		DurationSeconds: h.currentDurationSeconds,
		EscalationStep:  h.escalationStep,
	}
}

func (m *memoryHealthStore) HealthyTargets(targets []Target, now time.Time) []Target {
	m.mu.Lock()
	defer m.mu.Unlock()

	healthy := make([]Target, 0, len(targets))
	for _, target := range targets {
		if m.reportableLocked(target, now) {
			healthy = append(healthy, target)
		}
	}
	return healthy
}
