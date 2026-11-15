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
	"log/slog"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

// requestIDHeader is the gateway's per-request correlation id, and the only key tying a
// completion verdict back to what this policy recorded while the request was in flight.
const requestIDHeader = "x-request-id"

// requestIDFrom reads the correlation id from a request's headers.
func requestIDFrom(headers *policy.Headers) string {
	if headers == nil {
		return ""
	}
	values := headers.Get(requestIDHeader)
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

// OnAttemptComplete grades an attempt that failed AFTER the client was told it had succeeded.
//
// This is the failure no other hook can see. OnResponseHeaders runs while the response is still
// in flight and sees only `200` and a content type; a target that then dies mid-body is
// indistinguishable there from one that streamed the whole answer. Recording that as a success
// is worse than recording nothing — it clears the consecutive-failure count and adds a healthy
// sample to the error-rate window, immunising a target that truncates everything against the
// suspension its real failures would trigger (FR-030n).
//
// Only post-commitment failures are graded here. A failure BEFORE commitment reached the client
// as a 5xx, which the response phase already saw and graded; grading it again would count one
// failure twice and suspend a target at half the configured threshold.
func (p *Policy) OnAttemptComplete(_ context.Context, attemptCtx *policy.AttemptCompletionContext,
	_ map[string]interface{}) {

	if attemptCtx == nil || !attemptCtx.CommittedBeforeFailing() {
		return
	}

	// The attempt count selects WHICH member of the chain this verdict describes; the cluster
	// cross-checks it, and carries the lookup alone when the count is absent. A cluster names a
	// provider, so two members on one vendor are indistinguishable by it — see Lookup.
	correlated, ok := p.correlation.Lookup(attemptCtx.RequestID, attemptCtx.UpstreamCluster,
		attemptCtx.AttemptCount)
	if !ok {
		// Ordinary, not an error: the verdict may belong to a request this policy never
		// published a chain for, or one whose entry has aged out. Nothing is recorded,
		// which is the conservative outcome FR-030p asks for.
		slog.Debug("ModelFailover: no target recorded for completion verdict",
			"request_id", attemptCtx.RequestID,
			"cluster", attemptCtx.UpstreamCluster,
			"attempt", attemptCtx.AttemptCount)
		return
	}
	// One verdict per request, so the entry has done its job.
	p.correlation.Forget(attemptCtx.RequestID)

	target := correlated.Target
	// The receipt matters here, not just the target. A streamed probe was credited
	// optimistically when its headers arrived; passing the reservation it ran on is what lets
	// that credit be taken back, so this failure is graded against the probe it actually was
	// rather than against a target the same response already returned to rotation (FR-030p).
	event := p.health.RecordFailure(target, correlated.Admission, attemptCtx.Duration, p.now())

	slog.Warn("ModelFailover: target failed after committing its response",
		"model", target.Model,
		"provider", target.Provider,
		"cluster", attemptCtx.UpstreamCluster,
		"attempt", attemptCtx.AttemptCount,
		"response_flags", attemptCtx.ResponseFlags,
		"duration", attemptCtx.Duration,
		"request_id", attemptCtx.RequestID)

	if event != nil {
		slog.Warn("ModelFailover: target suspended",
			"model", target.Model,
			"provider", target.Provider,
			"reason", event.Reason,
			"observed", event.Observed,
			"for_seconds", event.DurationSeconds)
	}
}
