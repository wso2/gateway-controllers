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

package modelroundrobin

import (
	"context"
	"strings"
	"testing"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

// This policy is the FIRST adopter of the target preference list contract
// (specs/001-model-failover-policy/contracts/target-preference-list.md). It publishes its full
// rotation so a failover policy's retries follow round-robin's own order rather than a
// separately configured list.

func rotationPolicy(t *testing.T, models []interface{}) *ModelRoundRobinPolicy {
	t.Helper()
	p, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{
		"models": models,
		// payload location: the model lives in the request body, which is the shape an
		// LlmProxy uses. Selection still happens in the header phase either way.
		"requestModel":    map[string]interface{}{"location": "payload", "identifier": "$.model"},
		"suspendDuration": 0,
	})
	if err != nil {
		t.Fatalf("GetPolicy: %v", err)
	}
	rr, ok := p.(*ModelRoundRobinPolicy)
	if !ok {
		t.Fatalf("GetPolicy returned %T", p)
	}
	return rr
}

func model(name, provider string) interface{} {
	entry := map[string]interface{}{"model": name}
	if provider != "" {
		entry["provider"] = provider
	}
	return entry
}

// publishedRotation runs one request through the header phase and renders the published
// rotation as "model@provider" strings, so order is readable in a failure message.
func publishedRotation(t *testing.T, p *ModelRoundRobinPolicy) string {
	t.Helper()
	reqCtx := &policy.RequestHeaderContext{
		SharedContext: &policy.SharedContext{Metadata: map[string]interface{}{}},
	}
	p.OnRequestHeaders(context.Background(), reqCtx, nil)

	raw, ok := reqCtx.Metadata[MetadataKeyPublishedRanking]
	if !ok {
		return ""
	}
	// The contract pins []map[string]string. Asserting the concrete type here is the point:
	// a struct would be unreadable to a consumer in another module, which is exactly the
	// defect this contract was written to prevent.
	list, ok := raw.([]map[string]string)
	if !ok {
		t.Fatalf("published value is %T, want []map[string]string — the pinned carrier", raw)
	}
	parts := make([]string, 0, len(list))
	for _, entry := range list {
		if provider := entry["provider"]; provider != "" {
			parts = append(parts, entry["model"]+"@"+provider)
			continue
		}
		parts = append(parts, entry["model"])
	}
	return strings.Join(parts, ",")
}

// The rotation leads with the target THIS request goes to, then continues in configured order
// and wraps. A list that did not start at the selection would describe an order no request
// actually takes.
func TestPublishRotation_StartsAtTheSelectedTargetAndWraps(t *testing.T) {
	p := rotationPolicy(t, []interface{}{model("a", ""), model("b", ""), model("c", "")})

	for i, want := range []string{"a,b,c", "b,c,a", "c,a,b", "a,b,c"} {
		if got := publishedRotation(t, p); got != want {
			t.Fatalf("request %d published %q, want %q", i+1, got, want)
		}
	}
}

// The leading entry must be the same target the single-selection keys name. If the two
// disagreed, a consumer reading one would route somewhere the other never chose.
func TestPublishRotation_LeadingEntryMatchesTheSingleSelection(t *testing.T) {
	p := rotationPolicy(t, []interface{}{model("a", ""), model("b", "anthropic")})

	for i := 0; i < 4; i++ {
		reqCtx := &policy.RequestHeaderContext{
			SharedContext: &policy.SharedContext{Metadata: map[string]interface{}{}},
		}
		p.OnRequestHeaders(context.Background(), reqCtx, nil)

		list, _ := reqCtx.Metadata[MetadataKeyPublishedRanking].([]map[string]string)
		if len(list) == 0 {
			t.Fatalf("request %d published no rotation", i+1)
		}
		selectedModel, _ := reqCtx.Metadata[MetadataKeySelectedModel].(string)
		selectedProvider, _ := reqCtx.Metadata[MetadataKeySelectedProvider].(string)

		if list[0]["model"] != selectedModel || list[0]["provider"] != selectedProvider {
			t.Fatalf("request %d: rotation leads with %v but the selection keys say %s/%s",
				i+1, list[0], selectedModel, selectedProvider)
		}
	}
}

// Provider is part of a target's identity, and the same model under two providers is two
// distinct entries — a rotation that collapsed them would hide half the configuration.
func TestPublishRotation_CarriesProviderPerEntry(t *testing.T) {
	p := rotationPolicy(t, []interface{}{
		model("shared", "anthropic"), model("shared", "bedrock"), model("solo", ""),
	})
	if got := publishedRotation(t, p); got != "shared@anthropic,shared@bedrock,solo" {
		t.Fatalf("published %q, want each provider variant kept separate", got)
	}
}

// A single-model configuration still publishes, so a consumer never has to tell "one model"
// apart from "this policy did not adopt the contract".
func TestPublishRotation_SingleModelStillPublishes(t *testing.T) {
	p := rotationPolicy(t, []interface{}{model("only", "")})
	if got := publishedRotation(t, p); got != "only" {
		t.Fatalf("published %q, want the one-element rotation", got)
	}
}

// The single-selection keys keep working untouched. Every existing consumer reads those, and a
// policy that has not adopted the contract must be unaffected by this change (FR-026c).
func TestPublishRotation_DoesNotDisturbTheSingleSelectionKeys(t *testing.T) {
	p := rotationPolicy(t, []interface{}{model("a", ""), model("b", "anthropic")})

	reqCtx := &policy.RequestHeaderContext{
		SharedContext: &policy.SharedContext{Metadata: map[string]interface{}{}},
	}
	p.OnRequestHeaders(context.Background(), reqCtx, nil)

	if reqCtx.Metadata[MetadataKeySelectedModel] != "a" {
		t.Fatalf("selected_model = %v, want a", reqCtx.Metadata[MetadataKeySelectedModel])
	}
	if _, ok := reqCtx.Metadata[MetadataKeyHeadersProcessed]; !ok {
		t.Fatalf("headers_processed was not set; the existing contract must be untouched")
	}
}

// The key and the carrier are a CROSS-MODULE contract, and the consumer is a separate Go
// module — it cannot import this constant, so nothing but these literals keeps the two sides
// aligned. A rename on either side compiles perfectly and silently stops the contract working:
// the consumer finds no key, degrades to the single-selection path, and every test on both
// sides still passes.
//
// Pinned here and in the consumer's own suite, against the literals in
// specs/001-model-failover-policy/contracts/target-preference-list.md. If you are changing
// these, change the contract document and the consumer in the same PR.
func TestPublishRotation_ContractKeyIsPinned(t *testing.T) {
	if MetadataKeyPublishedRanking != "model_routing.published_ranking" {
		t.Fatalf("ranking key = %q; the consumer is a separate module and reads the literal",
			MetadataKeyPublishedRanking)
	}
}
