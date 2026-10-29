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

// ACCEPTED LIMIT: transport failures fail over, but never suspend on their own.
//
// There is deliberately no isTransportFailure here. Envoy does not invoke ext_proc for the
// replies it generates itself, and a connection failure, reset, or per-attempt timeout is
// exactly that — a locally generated reply. The policy is never called for one, so it cannot
// classify or record it. A predicate that looked like it handled this would be dead code that
// reads as coverage.
//
// What still works, and why this limit is acceptable:
//
//   - Failover itself is unaffected. Envoy's retry policy lists connect-failure, reset and
//     refused-stream unconditionally, so a transport-dead member is retried away from without
//     the policy being involved at all.
//   - A transport-dead member IS recorded as failed whenever a LATER attempt returns a real
//     response, because the response phase then runs and the attempt count attributes attempts
//     1..N-1 as failures (see attemptCount in failover.go). So the common case — a dead member
//     followed by a healthy one — still drives that member to suspension.
//
// What is genuinely uncovered is a chain where EVERY member fails at transport level: no real
// response exists, the policy is never invoked, and nothing is recorded. Suspension would save
// a dial there but has nowhere healthier to send the traffic.
//
// Probe F (specs/001-model-failover-policy/poc-results.md) ruled out closing this with Envoy
// outlier detection: ejection is cosmetic under the default panic threshold, and disabling
// panic mode makes the ejected cluster return a non-retryable "no healthy upstream" that breaks
// failover outright.
