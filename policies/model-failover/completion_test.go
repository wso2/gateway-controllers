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
	p.correlation.Remember("req-1", []Target{target}, map[string]string{target.Provider: testCluster})
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

	if !p.health.Healthy(target, now) {
		t.Fatal("precondition: target starts healthy")
	}

	p.OnAttemptComplete(context.Background(), verdict(200, testCluster), nil)
	p.correlation.Remember("req-1", []Target{target}, map[string]string{target.Provider: testCluster})
	p.OnAttemptComplete(context.Background(), verdict(200, testCluster), nil)

	if p.health.Healthy(target, now) {
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

	if !p.health.Healthy(target, now) {
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
	if !p.health.Healthy(target, now) {
		t.Error("a verdict for a request this policy never published must not grade anything")
	}

	p.OnAttemptComplete(context.Background(), verdict(200, "some_other_cluster"), nil)
	if !p.health.Healthy(target, now) {
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
	p.correlation.Remember("req-1", []Target{target}, map[string]string{target.Provider: testCluster})

	slow := verdict(200, testCluster)
	slow.Duration = 30 * time.Second
	p.OnAttemptComplete(context.Background(), slow, nil)

	if p.health.Healthy(target, now) {
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
	store.Remember("req-1", []Target{target}, map[string]string{"p": testCluster})

	if _, ok := store.Lookup("req-1", testCluster); !ok {
		t.Fatal("precondition: entry is readable while fresh")
	}

	clock = now.Add(correlationTTL + time.Second)
	if _, ok := store.Lookup("req-1", testCluster); ok {
		t.Error("an expired entry must not be returned")
	}
}

// Two members on one provider share a cluster, and the verdict cannot tell them apart. Grading
// the one the chain would have reached FIRST matches the attempt order; picking arbitrarily
// would suspend whichever member happened to be iterated last.
func TestAttemptCorrelation_SharedClusterResolvesToTheEarlierMember(t *testing.T) {
	store := newAttemptCorrelation(nil)
	first := Target{Model: "gpt-4o", Provider: "openai"}
	second := Target{Model: "gpt-4o-mini", Provider: "openai"}
	store.Remember("req-1", []Target{first, second}, map[string]string{"openai": testCluster})

	got, ok := store.Lookup("req-1", testCluster)
	if !ok || got != first {
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

	if p.health.Healthy(target, now) {
		t.Error("the fallback target truncated after committing its response and must be suspended; " +
			"if this fails, the correlation recorded during OnRequestBody is missing")
	}
}
