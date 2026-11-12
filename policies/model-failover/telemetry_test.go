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
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

// A failover is only reconstructable after the fact if the record names what was tried, what
// failed, what served, and what was never reached. These drive the whole policy rather than
// the record struct, because the fields that matter most are the ones carried from the request
// phase, and a unit test on the struct alone would not notice if that carrying broke.

const (
	secretKey    = "sk-live-must-never-appear"
	promptText   = "my private prompt body"
	authHeaderIn = "Bearer " + secretKey
)

// telemetryFor drives one request and its response through the policy and returns the
// analytics the response phase emitted.
func telemetryFor(t *testing.T, p *Policy, requestedModel string, status int,
	attemptCount string) map[string]interface{} {

	t.Helper()
	metadata := map[string]interface{}{}

	body, _ := json.Marshal(map[string]interface{}{
		"model": requestedModel, "messages": []map[string]string{{"content": promptText}},
	})
	reqCtx := &policy.RequestContext{
		SharedContext: &policy.SharedContext{Metadata: metadata},
		Headers:       policy.NewHeaders(map[string][]string{"authorization": {authHeaderIn}}),
		Body:          &policy.Body{Content: body, Present: true},
	}
	p.OnRequestBody(context.Background(), reqCtx, nil)

	respCtx := &policy.ResponseHeaderContext{
		SharedContext:   &policy.SharedContext{Metadata: metadata},
		ResponseStatus:  status,
		ResponseHeaders: policy.NewHeaders(map[string][]string{attemptCountHeader: {attemptCount}}),
	}
	action := p.OnResponseHeaders(context.Background(), respCtx, nil)

	return analyticsOf(t, action)
}

// analyticsOf pulls the record off whichever action the response phase returned.
//
// Both carry one: an exhausted chain short-circuits with ImmediateResponse and takes its
// analytics with it, everything else forwards the upstream response and attaches them. These
// tests are about the CONTENT of the record, so the carrier is not their subject — which
// action each outcome produces is asserted in exhaustion_test.go.
func analyticsOf(t *testing.T, action policy.ResponseHeaderAction) map[string]interface{} {
	t.Helper()
	switch a := action.(type) {
	case policy.DownstreamResponseHeaderModifications:
		return a.AnalyticsMetadata
	case policy.ImmediateResponse:
		return a.AnalyticsMetadata
	default:
		t.Fatalf("response action is %T, want a modification or an immediate response", action)
		return nil
	}
}

func field(t *testing.T, got map[string]interface{}, key string) interface{} {
	t.Helper()
	value, ok := got[key]
	if !ok {
		t.Fatalf("no %q in the record; got keys %v", key, keysOf(got))
	}
	return value
}

func keysOf(m map[string]interface{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// A request the leading target served: one attempt, nothing failed, outcome "served".
func TestTelemetry_ServedByTheLeadingTarget(t *testing.T) {
	got := telemetryFor(t, policyWithChain(), "gpt-4o", 200, "1")

	if v := field(t, got, analyticsKeyOutcome); v != outcomeServed {
		t.Fatalf("outcome = %v, want %q", v, outcomeServed)
	}
	if v := field(t, got, analyticsKeyAttempts); v != 1 {
		t.Fatalf("attempts = %v, want 1", v)
	}
	if v := field(t, got, analyticsKeyServingModel); v != "gpt-4o" {
		t.Fatalf("serving model = %v, want gpt-4o", v)
	}
	if _, present := got[analyticsKeyFailedTargets]; present {
		t.Fatalf("failed targets reported for a request that never failed: %v", got)
	}
}

// THE case the feature exists for: the client saw a 200, so this record is the ONLY place the
// first target's failure is visible at all.
func TestTelemetry_RescuedNamesTheTargetThatFailedAndTheOneThatServed(t *testing.T) {
	got := telemetryFor(t, policyWithChain(), "gpt-4o", 200, "2")

	if v := field(t, got, analyticsKeyOutcome); v != outcomeRescued {
		t.Fatalf("outcome = %v, want %q — a 200 after two attempts is a rescue, not a plain success", v, outcomeRescued)
	}
	if v := field(t, got, analyticsKeyServingModel); v != "claude-sonnet-4-5" {
		t.Fatalf("serving model = %v, want the fallback that actually answered", v)
	}
	failed := fmt.Sprint(field(t, got, analyticsKeyFailedTargets))
	if !strings.Contains(failed, "gpt-4o") {
		t.Fatalf("failed targets = %q, want the first target named", failed)
	}
	if strings.Contains(failed, "claude") {
		t.Fatalf("failed targets = %q — the target that answered must not be listed as failed", failed)
	}
}

// Every target failed and the client got the error. Distinct from "rescued" so the two can be
// counted apart: one is a provider problem the client never saw, the other is an outage.
func TestTelemetry_ExhaustedIsADistinctOutcome(t *testing.T) {
	got := telemetryFor(t, policyWithChain(), "gpt-4o", 503, "2")

	if v := field(t, got, analyticsKeyOutcome); v != outcomeExhausted {
		t.Fatalf("outcome = %v, want %q", v, outcomeExhausted)
	}
	failed := fmt.Sprint(field(t, got, analyticsKeyFailedTargets))
	if !strings.Contains(failed, "gpt-4o") || !strings.Contains(failed, "claude") {
		t.Fatalf("failed targets = %q, want every attempted target named", failed)
	}
}

// Where the order came from changes what an operator should investigate when a chain looks
// wrong, so the record says which it was.
func TestTelemetry_NamesWhereTheOrderCameFrom(t *testing.T) {
	configured := telemetryFor(t, policyWithChain(), "gpt-4o", 200, "1")
	if v := field(t, configured, analyticsKeyRankingSource); v != rankingSourceConfigured {
		t.Fatalf("ranking source = %v, want %q", v, rankingSourceConfigured)
	}

	p := policyWithChain()
	metadata := map[string]interface{}{
		MetadataKeyPublishedRanking: []map[string]string{{"model": "gpt-4o"}},
	}
	body, _ := json.Marshal(map[string]interface{}{"model": "gpt-4o"})
	p.OnRequestBody(context.Background(), &policy.RequestContext{
		SharedContext: &policy.SharedContext{Metadata: metadata},
		Body:          &policy.Body{Content: body, Present: true},
	}, nil)
	action := p.OnResponseHeaders(context.Background(), &policy.ResponseHeaderContext{
		SharedContext:   &policy.SharedContext{Metadata: metadata},
		ResponseStatus:  200,
		ResponseHeaders: policy.NewHeaders(map[string][]string{attemptCountHeader: {"1"}}),
	}, nil)
	routed := action.(policy.DownstreamResponseHeaderModifications).AnalyticsMetadata
	if v := field(t, routed, analyticsKeyRankingSource); v != rankingSourceRoutingPolicy {
		t.Fatalf("ranking source = %v, want %q", v, rankingSourceRoutingPolicy)
	}
}

// A suspended target is never attempted, so its absence is invisible in the chain. Without
// this field an operator cannot tell a chain that was configured short from one whittled down
// by health, which are very different incidents.
func TestTelemetry_ReportsTargetsSkippedOnHealth(t *testing.T) {
	p := policyWithChain()
	s := testSuspension()
	s.DurationSeconds = 300
	s.ConsecutiveFailures = 1
	s.clamp()
	p.health = NewHealthStore(s)

	// Suspend the leading target, then drive a fresh request past it.
	now := p.now()
	p.health.RecordFailure(Target{Model: "gpt-4o"}, 0, now)

	got := telemetryFor(t, p, "gpt-4o", 200, "1")
	skipped := fmt.Sprint(field(t, got, analyticsKeySkippedTargets))
	if !strings.Contains(skipped, "gpt-4o") {
		t.Fatalf("skipped targets = %q, want the suspended target named", skipped)
	}
}

// FR-034. The record is built only from model names, provider names, counts and a fixed set of
// outcome words, so there is no path by which a credential or prompt content reaches analytics
// through it. Asserted against a request carrying both.
func TestTelemetry_CarriesNoCredentialOrPromptContent(t *testing.T) {
	for name, got := range map[string]map[string]interface{}{
		"served":    telemetryFor(t, policyWithChain(), "gpt-4o", 200, "1"),
		"rescued":   telemetryFor(t, policyWithChain(), "gpt-4o", 200, "2"),
		"exhausted": telemetryFor(t, policyWithChain(), "gpt-4o", 503, "2"),
	} {
		t.Run(name, func(t *testing.T) {
			rendered := fmt.Sprint(got)
			for _, forbidden := range []string{secretKey, promptText, "Bearer", "authorization"} {
				if strings.Contains(rendered, forbidden) {
					t.Fatalf("record contains %q: %s", forbidden, rendered)
				}
			}
		})
	}
}

// One client request produces exactly ONE record however many upstream attempts it took
// (FR-032). Emitting per attempt would multiply every per-request measure a consumer
// aggregates downstream — the specific way failover telemetry misleads when it is wrong.
func TestTelemetry_OneRecordPerClientRequestNotPerAttempt(t *testing.T) {
	got := telemetryFor(t, policyWithChain(), "gpt-4o", 200, "2")

	if v := field(t, got, analyticsKeyAttempts); v != 2 {
		t.Fatalf("attempts = %v, want the count carried as a FIELD of one record", v)
	}
	if v := field(t, got, analyticsKeyChainLength); v != 2 {
		t.Fatalf("chain length = %v, want 2", v)
	}
}

// The primary provider's empty name would render as a bare leading colon, which reads as a
// missing value rather than as the default provider.
func TestTelemetry_TargetLabelNamesTheDefaultProvider(t *testing.T) {
	if got := targetLabel(Target{Model: "gpt-4o"}); got != "default:gpt-4o" {
		t.Fatalf("label = %q, want default:gpt-4o", got)
	}
	if got := targetLabel(Target{Model: "claude", Provider: "anthropic"}); got != "anthropic:claude" {
		t.Fatalf("label = %q, want anthropic:claude", got)
	}
}

// FR-056a. A member dropped for having no resolvable cluster is reported, and reported
// SEPARATELY from one skipped on health.
//
// The two look identical in the published ranking — both are simply absent — but they need
// different responses. A skip is health withholding a usable target for a while and resolves
// itself; a drop means the target cannot be named at all on this API, which is a configuration
// or version-skew problem and needs an operator. Collapsing them into one field would hide the
// second behind the first.
func TestTelemetry_ReportsTargetsDroppedForHavingNoCluster(t *testing.T) {
	record := attemptRecord{
		RequestedModel: "gpt-4o",
		Attempts:       1,
		ChainLength:    1,
		Outcome:        outcomeServed,
		ServingTarget:  Target{Model: "gpt-4o", Provider: "openai"},
		SkippedTargets: []Target{{Model: "gpt-4o", Provider: "azure-eu"}},
		DroppedTargets: []Target{{Model: "claude-sonnet-4", Provider: "typo-provider"}},
	}

	got := record.analytics()

	dropped := fmt.Sprint(field(t, got, analyticsKeyDroppedTargets))
	if !strings.Contains(dropped, "typo-provider") {
		t.Fatalf("dropped targets = %q, want the unresolvable provider named", dropped)
	}
	// Not folded into the skipped field, which is the whole point of a separate key.
	if skipped := fmt.Sprint(field(t, got, analyticsKeySkippedTargets)); strings.Contains(skipped, "typo-provider") {
		t.Fatalf("skipped targets = %q, must not absorb a dropped member", skipped)
	}
}

// A record with nothing dropped carries no dropped field at all, so the common case adds no
// weight to every analytics event.
func TestTelemetry_OmitsDroppedWhenNothingWasDropped(t *testing.T) {
	record := attemptRecord{
		RequestedModel: "gpt-4o",
		Attempts:       1,
		ChainLength:    1,
		Outcome:        outcomeServed,
		ServingTarget:  Target{Model: "gpt-4o", Provider: "openai"},
	}

	if _, present := record.analytics()[analyticsKeyDroppedTargets]; present {
		t.Fatal("dropped field present with nothing dropped")
	}
}
