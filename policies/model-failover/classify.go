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
	"strings"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

// isFailoverWorthy reports whether a response status should count as a failure for health
// tracking.
//
// Only the configured statuses count. A status outside the list — an authentication error, a
// validation error, a 404 — is returned to the client unchanged and does not mark the target
// unhealthy. Retrying those elsewhere would fail identically, or worse, mask a genuine client
// bug behind a second billed inference call (FR-003, FR-038).
//
// Transport failures are handled separately: they trigger regardless of this list, because a
// connection that was refused or reset produced no status at all (FR-009).
func (p *Policy) isFailoverWorthy(status int) bool {
	for _, code := range p.params.FailureConditions.StatusCodes {
		if status == code {
			return true
		}
	}
	return false
}

// ACCEPTED LIMIT: a transport failure is graded only through some reply that does reach the
// response phase.
//
// There is deliberately no isTransportFailure here, and the reason is narrower than "no call
// happens". A refused attempt DOES sometimes reach the per-attempt position — Probe T2 measured
// the upstream filter invoked for a cluster whose port refuses, on roughly half of otherwise
// identical requests. But that position is REQUEST-ONLY: the call happens on the way out, before
// the connection fails, and carries no outcome. Nothing ever hands this file a transport failure
// to classify, so a predicate that looked like it handled one would be dead code that reads as
// coverage.
//
// What that does NOT mean is that such failures go unrecorded. Grading happens once, downstream,
// on whatever reply finally travels back, and the attempt count attributes it across the chain:
//
//   - Failover itself is unaffected. Envoy's retry policy lists connect-failure, reset and
//     refused-stream unconditionally, so a transport-dead member is retried away from without
//     the policy being involved at all.
//   - A transport-dead member IS charged whenever any later attempt produces a reply, because
//     the response phase then runs and attempts 1..N-1 are recorded as failures WITHOUT
//     consulting the status — being retried is itself the evidence they failed (see
//     attemptCount in failover.go).
//   - That includes a chain where EVERY member is transport-dead. Envoy's own terminal 503
//     travels back through the downstream chain like any other response, so the phase runs and
//     all N members are charged. Measured 2026-10-28 (poc-results.md, "What the policy can and
//     cannot see"): three dead members produced three suspensions. An earlier version of this
//     comment claimed the opposite — it was reasoned, never measured. Pinned now by
//     TestOnResponseHeaders_ExhaustedChainChargesEveryMember.
//
// The one asymmetry worth knowing: only the FINAL attempt is judged on its status, and Envoy's
// retry_on is wider than this policy's statusCodes — it carries `5xx` unconditionally. Narrow
// statusCodes to exclude 503 and attempts 1..N-1 are still charged while the last one reads as
// having answered. Reachable only by deliberately narrowing the list, since the default covers
// everything `5xx` retries; pinned by TestOnResponseHeaders_NarrowedStatusCodesSpareTheFinalTarget.
//
// What is genuinely uncovered is a host that does not RESOLVE. That produces a local reply with
// nothing to retry FROM, so the request never fails over at all, let alone gets graded. A member
// that resolves and refuses behaves normally.
//
// Probe F (specs/001-model-failover-policy/poc-results.md) ruled out avoiding the dial with Envoy
// outlier detection: ejection is cosmetic under the default panic threshold, and disabling panic
// mode makes the ejected cluster return a non-retryable "no healthy upstream" that breaks
// failover outright.

// isProvisionalStatus reports whether the response status cannot be taken as the final
// outcome of the attempt.
//
// True when the upstream declared a streamed response — chunked framing or
// text/event-stream — and the body had still to come. Envoy commits the status line
// downstream before the stream completes, so an upstream that resets mid-body reaches this
// phase indistinguishable from one that answered in full; Envoy reports the difference
// afterwards, as "upstream_reset_after_response_started", on a channel this phase cannot see
// (FR-030n).
//
// Measured 2026-11-05: a reset BEFORE the response is committed arrives here as a clean 5xx
// instead, because nothing had reached the client yet. So this is narrowly about responses
// already in flight, not about streaming in general.
//
// The rule mirrors the engine's own streaming detection. It is restated here rather than
// shared because the engine's helper is internal to a different repository; the two must be
// kept in step, and a disagreement shows up as a target graded on a status the engine knew
// was provisional.
func isProvisionalStatus(respCtx *policy.ResponseHeaderContext) bool {
	if respCtx == nil || respCtx.ResponseHeaders == nil {
		return false
	}
	for _, te := range respCtx.ResponseHeaders.Get("transfer-encoding") {
		if strings.Contains(strings.ToLower(te), "chunked") {
			return true
		}
	}
	for _, ct := range respCtx.ResponseHeaders.Get("content-type") {
		if strings.Contains(strings.ToLower(ct), "text/event-stream") {
			return true
		}
	}
	return false
}
