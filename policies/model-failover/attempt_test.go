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

func attemptCtx(cluster, model, body string) *policy.RequestContext {
	metadata := map[string]interface{}{}
	if cluster != "" {
		metadata[attemptMetadataNamespace] = map[string]interface{}{attemptMetadataCluster: cluster}
	}
	if model != "" {
		metadata[FailoverMetadataNamespace] = map[string]interface{}{
			attemptModelsKey: map[string]interface{}{cluster: model},
		}
	}
	return &policy.RequestContext{
		SharedContext: &policy.SharedContext{Metadata: metadata},
		Body:          &policy.Body{Content: []byte(body), Present: true},
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

	model, rewritten := rewrittenModel(t, p.substituteAttemptModel(ctx, "upstream_anthropic"))
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

	mods := p.substituteAttemptModel(ctx, "c").(policy.UpstreamRequestModifications)
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
// another routing policy may own it.
func TestSubstituteAttemptModel_UnknownClusterLeavesBodyAlone(t *testing.T) {
	p := &Policy{}
	ctx := attemptCtx("upstream_anthropic", "claude-sonnet-4-5", `{"model":"gpt-4o"}`)

	if _, rewritten := rewrittenModel(t, p.substituteAttemptModel(ctx, "upstream_somewhere_else")); rewritten {
		t.Fatal("rewrote the body for a cluster the ranking never named")
	}
}

// Already correct means nothing to do — no pointless re-serialisation of the payload.
func TestSubstituteAttemptModel_NoOpWhenModelAlreadyMatches(t *testing.T) {
	p := &Policy{}
	ctx := attemptCtx("c", "m1", `{"model":"m1"}`)

	if _, rewritten := rewrittenModel(t, p.substituteAttemptModel(ctx, "c")); rewritten {
		t.Fatal("rewrote a body that already named the right model")
	}
}

// Failover still works at the transport level for a non-JSON payload; only the rewrite is skipped.
func TestSubstituteAttemptModel_NonJSONBodyIsLeftAlone(t *testing.T) {
	p := &Policy{}
	ctx := attemptCtx("c", "m2", `not json at all`)

	if _, rewritten := rewrittenModel(t, p.substituteAttemptModel(ctx, "c")); rewritten {
		t.Fatal("rewrote a non-JSON body")
	}
}

func TestSubstituteAttemptModel_AbsentBodyIsLeftAlone(t *testing.T) {
	p := &Policy{}
	ctx := attemptCtx("c", "m2", "")
	ctx.Body = &policy.Body{Present: false}

	if _, rewritten := rewrittenModel(t, p.substituteAttemptModel(ctx, "c")); rewritten {
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

// A wildcard member carries whatever the client asked for, so publishing "" would erase it.
func TestBuildAttemptModels_SkipsUnresolvableMembers(t *testing.T) {
	clusters := map[string]string{"anthropic": "upstream_anthropic", "ghost": ""}
	models := buildAttemptModels([]Target{
		{Provider: "anthropic", Model: "claude"},
		{Provider: "anthropic", Model: ""},      // wildcard — nothing to substitute
		{Provider: "ghost", Model: "m"},         // no cluster resolved
		{Provider: "unmapped", Model: "m"},      // not in the cluster map at all
	}, clusters)

	if len(models) != 1 || models["upstream_anthropic"] != "claude" {
		t.Fatalf("models = %v, want only upstream_anthropic->claude", models)
	}
}
