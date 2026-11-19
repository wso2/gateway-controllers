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
	"encoding/json"
	"testing"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

// rankedEntry is one published attempt_models entry, as the metadata carries it.
type rankedEntry struct {
	cluster string
	model   string
}

// attemptMetadata builds the two namespaces a per-attempt chain actually sees, in the shapes they
// actually arrive in. They travel by different routes and that matters: the engine writes
// wso2.attempt in-process, so its number is a Go int, while this policy's own wso2.failover goes
// out to Envoy and comes back through structpb, so its list is []interface{} of
// map[string]interface{}. A fixture that used plain Go maps for the second would pass while the
// runtime shape failed to parse.
func attemptMetadata(attempt int, cluster string, ranking []rankedEntry) map[string]interface{} {
	metadata := map[string]interface{}{}
	if cluster != "" {
		metadata[attemptMetadataNamespace] = map[string]interface{}{
			attemptMetadataCluster: cluster,
			attemptMetadataNumber:  attempt,
		}
	}
	if len(ranking) > 0 {
		entries := make([]interface{}, 0, len(ranking))
		for _, e := range ranking {
			entries = append(entries, map[string]interface{}{
				attemptModelCluster: e.cluster,
				attemptModelModel:   e.model,
			})
		}
		metadata[FailoverMetadataNamespace] = map[string]interface{}{attemptModelsKey: entries}
	}
	return metadata
}

// attemptCtx is the single-member case at attempt 1 -- the shape most of these tests need.
func attemptCtx(cluster, model, body string) *policy.RequestContext {
	return &policy.RequestContext{
		SharedContext: &policy.SharedContext{
			Metadata: attemptMetadata(1, cluster, []rankedEntry{{cluster: cluster, model: model}}),
		},
		Body: &policy.Body{Content: []byte(body), Present: true},
	}
}

func rewrittenModel(t *testing.T, action policy.RequestAction) (string, bool) {
	t.Helper()
	mods, ok := action.(policy.UpstreamRequestModifications)
	if !ok {
		t.Fatalf("action = %T, want UpstreamRequestModifications", action)
	}
	if mods.Body == nil {
		return "", false
	}
	var payload map[string]interface{}
	if err := json.Unmarshal(mods.Body, &payload); err != nil {
		t.Fatalf("rewritten body is not JSON: %v", err)
	}
	model, _ := payload["model"].(string)
	return model, true
}

// This is what makes the feature a MODEL failover rather than a provider failover: the attempt
// reaches the fallback provider, but unless the payload names that member's model it still asks
// for the primary's — which the fallback may not serve at all.
func TestSubstituteAttemptModel_RewritesToTheTargetsModel(t *testing.T) {
	p := &Policy{}
	ctx := attemptCtx("upstream_anthropic", "claude-sonnet-4-5", `{"model":"gpt-4o","max_tokens":50}`)

	model, rewritten := rewrittenModel(t, p.substituteAttemptModel(ctx, 1, "upstream_anthropic"))
	if !rewritten {
		t.Fatal("body was not rewritten")
	}
	if model != "claude-sonnet-4-5" {
		t.Fatalf("model = %q, want claude-sonnet-4-5", model)
	}
}

// The rest of the payload has to survive — this runs ahead of the vendor transformer.
func TestSubstituteAttemptModel_PreservesTheRestOfThePayload(t *testing.T) {
	p := &Policy{}
	ctx := attemptCtx("c", "m2", `{"model":"m1","max_tokens":50,"messages":[{"role":"user","content":"hi"}]}`)

	mods := p.substituteAttemptModel(ctx, 1, "c").(policy.UpstreamRequestModifications)
	var payload map[string]interface{}
	if err := json.Unmarshal(mods.Body, &payload); err != nil {
		t.Fatalf("not JSON: %v", err)
	}
	if payload["max_tokens"] != float64(50) {
		t.Fatalf("max_tokens = %v", payload["max_tokens"])
	}
	if _, ok := payload["messages"].([]interface{}); !ok {
		t.Fatalf("messages lost: %v", payload["messages"])
	}
}

// An attempt aimed at a target this policy never nominated is not this policy's to rewrite —
// another routing policy may own it. Caught by the cross-check: position 1 names a cluster this
// attempt is not aimed at.
func TestSubstituteAttemptModel_UnknownClusterLeavesBodyAlone(t *testing.T) {
	p := &Policy{}
	ctx := attemptCtx("upstream_anthropic", "claude-sonnet-4-5", `{"model":"gpt-4o"}`)

	if _, rewritten := rewrittenModel(t, p.substituteAttemptModel(ctx, 1, "upstream_somewhere_else")); rewritten {
		t.Fatal("rewrote the body for a cluster the ranking never named")
	}
}

// Already correct means nothing to do — no pointless re-serialisation of the payload.
func TestSubstituteAttemptModel_NoOpWhenModelAlreadyMatches(t *testing.T) {
	p := &Policy{}
	ctx := attemptCtx("c", "m1", `{"model":"m1"}`)

	if _, rewritten := rewrittenModel(t, p.substituteAttemptModel(ctx, 1, "c")); rewritten {
		t.Fatal("rewrote a body that already named the right model")
	}
}

// Failover still works at the transport level for a non-JSON payload; only the rewrite is skipped.
func TestSubstituteAttemptModel_NonJSONBodyIsLeftAlone(t *testing.T) {
	p := &Policy{}
	ctx := attemptCtx("c", "m2", `not json at all`)

	if _, rewritten := rewrittenModel(t, p.substituteAttemptModel(ctx, 1, "c")); rewritten {
		t.Fatal("rewrote a non-JSON body")
	}
}

func TestSubstituteAttemptModel_AbsentBodyIsLeftAlone(t *testing.T) {
	p := &Policy{}
	ctx := attemptCtx("c", "m2", "")
	ctx.Body = &policy.Body{Present: false}

	if _, rewritten := rewrittenModel(t, p.substituteAttemptModel(ctx, 1, "c")); rewritten {
		t.Fatal("rewrote an absent body")
	}
}

// The reserved namespace is also how the policy tells the two positions apart: the downstream
// pass must keep publishing the ranking, not try to substitute a model.
func TestAttemptCluster_IdentifiesThePosition(t *testing.T) {
	if _, ok := attemptCluster(nil); ok {
		t.Fatal("nil metadata reported as per-attempt")
	}
	if _, ok := attemptCluster(map[string]interface{}{}); ok {
		t.Fatal("downstream metadata reported as per-attempt")
	}
	if _, ok := attemptCluster(map[string]interface{}{
		attemptMetadataNamespace: map[string]interface{}{attemptMetadataCluster: ""},
	}); ok {
		t.Fatal("empty cluster reported as per-attempt")
	}
	cluster, ok := attemptCluster(map[string]interface{}{
		attemptMetadataNamespace: map[string]interface{}{attemptMetadataCluster: "c"},
	})
	if !ok || cluster != "c" {
		t.Fatalf("cluster = %q, ok = %v", cluster, ok)
	}
}

// The defect this whole positional scheme exists for: two members on ONE provider. Keyed by
// cluster they collapse onto one entry and the last one wins, so attempt 1 asks for the LAST
// member's model -- the first model is never requested at all, and attempt 2 repeats attempt 1
// byte for byte against the same upstream, which is not a failover.
//
// Mutant: collapse the list back to a cluster-keyed map. Attempt 1 then reads opus.
func TestSubstituteAttemptModel_SharedProviderGetsItsOwnModelPerAttempt(t *testing.T) {
	p := &Policy{}
	// [claude/sonnet, gemini, claude/opus] -- the first and third share a cluster.
	ranking := []rankedEntry{
		{cluster: "c_claude", model: "claude-sonnet-4-5"},
		{cluster: "c_gemini", model: "gemini-2.5-pro"},
		{cluster: "c_claude", model: "claude-opus-4-1"},
	}

	for _, tc := range []struct {
		attempt int
		cluster string
		want    string
	}{
		{1, "c_claude", "claude-sonnet-4-5"},
		{2, "c_gemini", "gemini-2.5-pro"},
		{3, "c_claude", "claude-opus-4-1"},
	} {
		ctx := &policy.RequestContext{
			SharedContext: &policy.SharedContext{
				Metadata: attemptMetadata(tc.attempt, tc.cluster, ranking),
			},
			Body: &policy.Body{Content: []byte(`{"model":"gpt-4o"}`), Present: true},
		}
		model, rewritten := rewrittenModel(t, p.substituteAttemptModel(ctx, tc.attempt, tc.cluster))
		if !rewritten {
			t.Fatalf("attempt %d: body was not rewritten", tc.attempt)
		}
		if model != tc.want {
			t.Fatalf("attempt %d: model = %q, want %q", tc.attempt, model, tc.want)
		}
	}
}

// A wildcard member holds its POSITION with an empty model rather than being omitted. Omitting it
// would shift every later member up one, so the attempt after it would ask for its neighbour's
// model -- a wrong model sent to a real provider, which is worse than not substituting.
//
// Mutant: omit the wildcard instead of holing it. Attempt 3 then reads entry 2 and sends gemini's
// model to anthropic.
func TestSubstituteAttemptModel_WildcardHolesItsPositionWithoutShifting(t *testing.T) {
	p := &Policy{}
	ranking := []rankedEntry{
		{cluster: "c_openai", model: ""}, // wildcard: whatever the client asked for
		{cluster: "c_gemini", model: "gemini-2.5-pro"},
		{cluster: "c_claude", model: "claude-opus-4-1"},
	}

	// The wildcard position itself substitutes nothing.
	wildcardCtx := &policy.RequestContext{
		SharedContext: &policy.SharedContext{Metadata: attemptMetadata(1, "c_openai", ranking)},
		Body:          &policy.Body{Content: []byte(`{"model":"gpt-4o"}`), Present: true},
	}
	if _, rewritten := rewrittenModel(t, p.substituteAttemptModel(wildcardCtx, 1, "c_openai")); rewritten {
		t.Fatal("substituted over a wildcard member, erasing the client's own model")
	}

	// And the members after it are still at their own indices.
	laterCtx := &policy.RequestContext{
		SharedContext: &policy.SharedContext{Metadata: attemptMetadata(3, "c_claude", ranking)},
		Body:          &policy.Body{Content: []byte(`{"model":"gpt-4o"}`), Present: true},
	}
	model, rewritten := rewrittenModel(t, p.substituteAttemptModel(laterCtx, 3, "c_claude"))
	if !rewritten || model != "claude-opus-4-1" {
		t.Fatalf("attempt 3 model = %q (rewritten=%v), want claude-opus-4-1", model, rewritten)
	}
}

// The cluster is carried as a CROSS-CHECK, not as the key. If the entry at this position names a
// different target than the engine says the attempt is aimed at, the positional correspondence
// has broken and substituting anyway would rewrite the payload for the wrong provider.
//
// Mutant: delete the cross-check. The anthropic attempt is then given gemini's model.
func TestSubstituteAttemptModel_DeclinesWhenTheRankedClusterDisagrees(t *testing.T) {
	p := &Policy{}
	ranking := []rankedEntry{
		{cluster: "c_gemini", model: "gemini-2.5-pro"},
	}
	ctx := &policy.RequestContext{
		// Engine says this attempt is aimed at anthropic; position 1 says gemini.
		SharedContext: &policy.SharedContext{Metadata: attemptMetadata(1, "c_claude", ranking)},
		Body:          &policy.Body{Content: []byte(`{"model":"gpt-4o"}`), Present: true},
	}

	if _, rewritten := rewrittenModel(t, p.substituteAttemptModel(ctx, 1, "c_claude")); rewritten {
		t.Fatal("substituted a model from a position that names a different cluster")
	}
}

// Without an attempt number there is no way to tell two members on one provider apart, so the
// lookup declines rather than guessing -- guessing is exactly what the cluster-keyed map did.
func TestSubstituteAttemptModel_NoAttemptNumberLeavesTheBodyAlone(t *testing.T) {
	if _, ok := attemptNumber(map[string]interface{}{
		attemptMetadataNamespace: map[string]interface{}{attemptMetadataCluster: "c"},
	}); ok {
		t.Fatal("missing attempt number reported as usable")
	}
	if _, ok := attemptNumber(map[string]interface{}{
		attemptMetadataNamespace: map[string]interface{}{attemptMetadataNumber: 0},
	}); ok {
		t.Fatal("attempt 0 reported as usable; the list is 1-based")
	}
	// The engine writes a Go int in-process. float64 is accepted too, since a representation
	// change on either side would otherwise silently disable substitution.
	for _, raw := range []interface{}{2, int64(2), float64(2), uint32(2)} {
		n, ok := attemptNumber(map[string]interface{}{
			attemptMetadataNamespace: map[string]interface{}{attemptMetadataNumber: raw},
		})
		if !ok || n != 2 {
			t.Fatalf("attemptNumber(%T) = %d, %v; want 2, true", raw, n, ok)
		}
	}
}

// Envoy stays on the LAST group once attempts exceed the group count, so an attempt past the end
// of the ranking has nothing to substitute. Reading the last entry instead would reintroduce the
// collapse this list replaced.
func TestSubstituteAttemptModel_AttemptPastTheRankingLeavesTheBodyAlone(t *testing.T) {
	p := &Policy{}
	ranking := []rankedEntry{{cluster: "c_claude", model: "claude-opus-4-1"}}
	ctx := &policy.RequestContext{
		SharedContext: &policy.SharedContext{Metadata: attemptMetadata(4, "c_claude", ranking)},
		Body:          &policy.Body{Content: []byte(`{"model":"gpt-4o"}`), Present: true},
	}

	if _, rewritten := rewrittenModel(t, p.substituteAttemptModel(ctx, 4, "c_claude")); rewritten {
		t.Fatal("substituted for an attempt past the end of the published ranking")
	}
}

// A JSON `null` body unmarshals to a NIL map, which assignment panics on. It is the one
// unreadable body whose error the unmarshal does not report, so it has to be caught after.
func TestSubstituteAttemptModel_NullBodyDoesNotPanic(t *testing.T) {
	p := policyWithChain()
	// The metadata MUST name a model for this cluster, or substituteAttemptModel returns at
	// its first guard and never reaches the body at all — which would make this test vacuous.
	meta := attemptMetadata(1, "cluster_anthropic", []rankedEntry{
		{cluster: "cluster_anthropic", model: "claude-sonnet-4-5"},
	})
	if _, ok := modelForAttempt(meta, 1, "cluster_anthropic"); !ok {
		t.Fatal("fixture does not reach the body path; the test would prove nothing")
	}
	ctx := &policy.RequestContext{
		SharedContext: &policy.SharedContext{Metadata: meta},
		Body:          &policy.Body{Content: []byte("null"), Present: true},
	}
	// Must return unchanged rather than panic on the nil map.
	if act := p.substituteAttemptModel(ctx, 1, "cluster_anthropic"); act == nil {
		t.Fatal("expected an action, got nil")
	}
}
