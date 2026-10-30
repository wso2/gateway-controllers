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
	"log/slog"
	"strings"
)

// Analytics keys. Namespaced with the policy's own prefix so a record cannot collide with
// another policy's fields in the shared analytics map, and so an operator can select every
// field this policy contributes with one prefix match.
const (
	analyticsKeyAttempts       = "failover:attempts"
	analyticsKeyOutcome        = "failover:outcome"
	analyticsKeyServingModel   = "failover:serving_model"
	analyticsKeyServingUpstrm  = "failover:serving_provider"
	analyticsKeyRequestedModel = "failover:requested_model"
	analyticsKeyRankingSource  = "failover:ranking_source"
	analyticsKeyChainLength    = "failover:chain_length"
	analyticsKeyFailedTargets  = "failover:failed_targets"
	analyticsKeySkippedTargets = "failover:skipped_targets"
)

// Outcomes. One request produces exactly one of these, so they can be counted without
// double-attributing a request that failed over before succeeding.
const (
	// outcomeServed: the leading target answered. No failover occurred.
	outcomeServed = "served"
	// outcomeRescued: a target failed and a later one answered. The client saw success; the
	// failure is invisible to them and visible only here.
	outcomeRescued = "rescued"
	// outcomeExhausted: every target in the chain failed and the client got the error.
	outcomeExhausted = "exhausted"
)

// Ranking sources, so an operator reading a record can tell WHY the chain was ordered the way
// it was. A chain that looks wrong is a different investigation depending on whether the
// publisher wrote that order or a routing policy chose it per request.
const (
	rankingSourceConfigured    = "configured"
	rankingSourceRoutingPolicy = "routing_policy"
)

// attemptRecord is what one client request contributes to telemetry: what was tried, what
// happened, and what served it.
//
// REQUEST-LEVEL, not attempt-level (FR-032). The downstream chain is entered once per client
// request, so this is emitted once no matter how many upstream attempts the request took. A
// request that failed over twice is one record with Attempts=3, never three records — the
// alternative would multiply every per-request measure a consumer aggregates, which is the
// specific way failover telemetry misleads if it is got wrong.
type attemptRecord struct {
	RequestedModel string
	Attempts       int
	ChainLength    int
	Outcome        string
	ServingTarget  Target
	RankingSource  string
	// FailedTargets are the ones this request actually attempted and that failed. A target
	// the request never reached is absent, not listed as a non-failure.
	FailedTargets []Target
	// SkippedTargets were in the chain's candidate set but suspended, so they were never
	// attempted. Reported because their absence is otherwise invisible: a short chain reads
	// the same whether it was configured short or whittled down by health.
	SkippedTargets []Target
}

// targetLabel renders a target for telemetry as "provider:model", with the primary provider's
// empty name shown explicitly rather than as a bare colon.
//
// Only the model and provider NAMES ever appear. They are publisher configuration, not secrets
// and not user content (FR-034).
func targetLabel(t Target) string {
	provider := t.Provider
	if provider == "" {
		provider = "default"
	}
	return provider + ":" + t.Model
}

func targetLabels(targets []Target) string {
	if len(targets) == 0 {
		return ""
	}
	parts := make([]string, 0, len(targets))
	for _, t := range targets {
		parts = append(parts, targetLabel(t))
	}
	return strings.Join(parts, ",")
}

// analytics renders the record for the analytics pipeline.
//
// WHAT IS DELIBERATELY ABSENT (FR-034): request or response headers, the authorization header,
// any credential, and any prompt or completion content. The fields below are model names,
// provider names, counts and a fixed set of outcome words — nothing here is derived from the
// request body or from a header. That is a property of what this function builds, not a filter
// applied afterwards, so there is no path by which content reaches analytics through it.
func (r attemptRecord) analytics() map[string]interface{} {
	out := map[string]interface{}{
		analyticsKeyAttempts:       r.Attempts,
		analyticsKeyChainLength:    r.ChainLength,
		analyticsKeyOutcome:        r.Outcome,
		analyticsKeyServingModel:   r.ServingTarget.Model,
		analyticsKeyServingUpstrm:  r.ServingTarget.Provider,
		analyticsKeyRankingSource:  r.RankingSource,
		analyticsKeyRequestedModel: r.RequestedModel,
	}
	// Omitted rather than sent empty: an absent key reads as "none", where an empty string
	// reads as "unknown" to most consumers.
	if labels := targetLabels(r.FailedTargets); labels != "" {
		out[analyticsKeyFailedTargets] = labels
	}
	if labels := targetLabels(r.SkippedTargets); labels != "" {
		out[analyticsKeySkippedTargets] = labels
	}
	return out
}

// log writes the same record to the log, at a level that matches what happened.
//
// A rescued request is INFO: nothing is wrong from the client's side, but an operator needs to
// know a provider is failing — this is the only place that failure is visible at all, since the
// client received a success. Exhaustion is WARN: the client got an error. A plain success is
// DEBUG, since one line per healthy request would drown the two cases worth seeing.
func (r attemptRecord) log() {
	attrs := []any{
		"requested_model", r.RequestedModel,
		"attempts", r.Attempts,
		"chain_length", r.ChainLength,
		"serving_model", r.ServingTarget.Model,
		"serving_provider", r.ServingTarget.Provider,
		"ranking_source", r.RankingSource,
	}
	if labels := targetLabels(r.FailedTargets); labels != "" {
		attrs = append(attrs, "failed_targets", labels)
	}
	if labels := targetLabels(r.SkippedTargets); labels != "" {
		attrs = append(attrs, "skipped_targets", labels)
	}

	switch r.Outcome {
	case outcomeExhausted:
		slog.Warn("ModelFailover: every target in the chain failed", attrs...)
	case outcomeRescued:
		slog.Info("ModelFailover: request rescued by a later target", attrs...)
	default:
		slog.Debug("ModelFailover: served by the leading target", attrs...)
	}
}
