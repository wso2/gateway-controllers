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
	"encoding/json"
	"strings"
	"testing"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

// respondTo drives one request/response pair through the policy and returns the response
// action, so a test can assert on what the CLIENT receives rather than only on the record.
func respondTo(p *Policy, requestedModel string, status int, attemptCount string) policy.ResponseHeaderAction {
	metadata := map[string]interface{}{}
	body, _ := json.Marshal(map[string]interface{}{"model": requestedModel})
	p.OnRequestBody(context.Background(), &policy.RequestContext{
		SharedContext: &policy.SharedContext{Metadata: metadata},
		Body:          &policy.Body{Content: body, Present: true},
	}, nil)
	return p.OnResponseHeaders(context.Background(), &policy.ResponseHeaderContext{
		SharedContext:   &policy.SharedContext{Metadata: metadata},
		ResponseStatus:  status,
		ResponseHeaders: policy.NewHeaders(map[string][]string{attemptCountHeader: {attemptCount}}),
	}, nil)
}

func immediate(t *testing.T, action interface{}) policy.ImmediateResponse {
	t.Helper()
	resp, ok := action.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("action is %T, want ImmediateResponse", action)
	}
	return resp
}

// THE disclosure case. Without this the client receives whatever the last provider wrote —
// which in practice names the account, the region, or the key that was refused.
func TestExhaustion_ReplacesTheFinalUpstreamsError(t *testing.T) {
	resp := immediate(t, respondTo(policyWithChain(), "gpt-4o", 503, "2"))

	if resp.StatusCode != exhaustionStatus {
		t.Fatalf("status = %d, want %d", resp.StatusCode, exhaustionStatus)
	}
	rendered := string(resp.Body)
	for _, forbidden := range []string{"gpt-4o", "claude", "anthropic", "cluster_"} {
		if strings.Contains(rendered, forbidden) {
			t.Fatalf("exhaustion body names %q, which is publisher configuration the caller was never shown: %s", forbidden, rendered)
		}
	}
	var decoded map[string]interface{}
	if err := json.Unmarshal(resp.Body, &decoded); err != nil {
		t.Fatalf("exhaustion body is not JSON: %v (%s)", err, rendered)
	}
	if decoded["error"] != exhaustionError {
		t.Fatalf("error = %v, want %q — the condition must be identifiable (FR-014)", decoded["error"], exhaustionError)
	}
}

// SC-006: "100% of requests receive the SAME consistent exhaustion error". A chain that ends
// on a 429 must not surface as a 429, or a caller reads it as their own rate limit and backs
// off against a gateway that simply had nowhere left to send the request.
func TestExhaustion_IsIdenticalWhateverTheLastTargetAnswered(t *testing.T) {
	first := immediate(t, respondTo(policyWithChain(), "gpt-4o", 503, "2"))
	for _, status := range []int{500, 502, 429} {
		p := NewPolicy(map[string]interface{}{
			"targets": []interface{}{map[string]interface{}{
				"model": "gpt-4o",
				"fallbacks": []interface{}{
					map[string]interface{}{"model": "claude-sonnet-4-5", "provider": "anthropic"},
				},
			}},
			"failureConditions":   map[string]interface{}{"statusCodes": []interface{}{500, 502, 503, 429}},
			ProviderClustersParam: map[string]interface{}{"": "cluster_default", "anthropic": "cluster_anthropic"},
		})
		got := immediate(t, respondTo(p, "gpt-4o", status, "2"))
		if got.StatusCode != first.StatusCode || string(got.Body) != string(first.Body) {
			t.Fatalf("a chain ending on %d returned %d %s, want the same error as every other exhaustion: %d %s",
				status, got.StatusCode, got.Body, first.StatusCode, first.Body)
		}
	}
}

// The edge case that stops this from changing unrelated operations: "A chain with one target
// behaves exactly like no failover — one attempt, response returned as-is".
func TestExhaustion_SingleTargetChainReturnsItsOwnResponse(t *testing.T) {
	p := NewPolicy(map[string]interface{}{
		"targets":             []interface{}{map[string]interface{}{"model": "gpt-4o"}},
		ProviderClustersParam: map[string]interface{}{"": "cluster_default"},
	})

	action := respondTo(p, "gpt-4o", 503, "1")
	if _, short := action.(policy.ImmediateResponse); short {
		t.Fatal("a single-target chain was given the exhaustion error; it has nothing to fail over to, so its own response must pass through unchanged")
	}
}

// ...but a chain that is DOWN to one member because health removed the others has genuinely
// run out, and must not be mistaken for a single-target configuration.
func TestExhaustion_ChainWhittledDownByHealthStillExhausts(t *testing.T) {
	p := policyWithChain()
	s := testSuspension()
	s.ConsecutiveFailures = 1
	s.DurationSeconds = 300
	s.clamp()
	p.health = NewHealthStore(s)
	p.health.RecordFailure(Target{Model: "gpt-4o"}, 0, p.now())

	// Only the anthropic fallback survives into the chain, and it fails too.
	resp := immediate(t, respondTo(p, "gpt-4o", 503, "1"))
	if resp.StatusCode != exhaustionStatus {
		t.Fatalf("status = %d, want %d", resp.StatusCode, exhaustionStatus)
	}
}

// A status outside the failure conditions is the caller's problem, not the chain's. It must
// reach them intact — collapsing a 400 into a 503 would hide a client bug behind an outage.
func TestExhaustion_DoesNotFireForANonFailoverWorthyStatus(t *testing.T) {
	action := respondTo(policyWithChain(), "gpt-4o", 400, "1")
	if _, short := action.(policy.ImmediateResponse); short {
		t.Fatal("a 400 was replaced with the exhaustion error; only a failover-worthy status exhausts a chain")
	}
}

// FR-014's other half, and the reason this is not bookkeeping: with every target suspended the
// policy used to publish nothing and go inert, which sent the request to its configured
// upstream — one of the suspended targets. Suspension that still routes traffic to the
// suspended target is not suspension.
func TestExhaustion_EverySuspendedTargetIsRejectedWithoutAnAttempt(t *testing.T) {
	p := policyWithChain()
	s := testSuspension()
	s.ConsecutiveFailures = 1
	s.DurationSeconds = 300
	s.clamp()
	p.health = NewHealthStore(s)
	now := p.now()
	p.health.RecordFailure(Target{Model: "gpt-4o"}, 0, now)
	p.health.RecordFailure(Target{Model: "claude-sonnet-4-5", Provider: "anthropic"}, 0, now)

	metadata := map[string]interface{}{}
	body, _ := json.Marshal(map[string]interface{}{"model": "gpt-4o"})
	action := p.OnRequestBody(context.Background(), &policy.RequestContext{
		SharedContext: &policy.SharedContext{Metadata: metadata},
		Body:          &policy.Body{Content: body, Present: true},
	}, nil)

	resp := immediate(t, action)
	if resp.StatusCode != exhaustionStatus {
		t.Fatalf("status = %d, want %d", resp.StatusCode, exhaustionStatus)
	}
	if !action.(policy.ImmediateResponse).StopExecution() {
		t.Fatal("the rejection does not stop the chain, so the request would still be dispatched")
	}
	if _, published := metadata[metadataKeyChain]; published {
		t.Fatal("a chain was published for a request that must not be attempted at all")
	}

	// Counted apart from a chain that was tried and failed: the fix for this one is in the
	// suspension settings, not at the providers.
	got := resp.AnalyticsMetadata
	if v := got[analyticsKeyOutcome]; v != outcomeUnavailable {
		t.Fatalf("outcome = %v, want %q", v, outcomeUnavailable)
	}
	if v := got[analyticsKeyAttempts]; v != 0 {
		t.Fatalf("attempts = %v, want 0 — nothing was dispatched", v)
	}
	skipped, _ := got[analyticsKeySkippedTargets].(string)
	if !strings.Contains(skipped, "gpt-4o") || !strings.Contains(skipped, "claude-sonnet-4-5") {
		t.Fatalf("skipped targets = %q, want every withheld target named — it is the whole of what happened here", skipped)
	}
}

// Short-circuiting must not cost the grading the response phase exists for: the chain is only
// ever re-ranked because failures were recorded against it.
func TestExhaustion_StillRecordsTheFailuresThatCausedIt(t *testing.T) {
	p := policyWithChain()
	s := testSuspension()
	s.ConsecutiveFailures = 1
	s.DurationSeconds = 300
	s.clamp()
	p.health = NewHealthStore(s)

	immediate(t, respondTo(p, "gpt-4o", 503, "2"))

	now := p.now()
	for _, target := range []Target{
		{Model: "gpt-4o"},
		{Model: "claude-sonnet-4-5", Provider: "anthropic"},
	} {
		if p.health.Healthy(target, now) {
			t.Fatalf("%s was not recorded as failed, so an exhausted chain would be re-attempted in the same order next request", targetLabel(target))
		}
	}
}
