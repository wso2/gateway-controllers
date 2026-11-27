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
	"testing"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

// catchAllPolicy configures a chain whose ONLY entry is the "*" catch-all, with a cluster map
// that would resolve it. If a model-less request reaches chain selection, this is what absorbs
// it — so this fixture is what makes the guard observable.
func catchAllPolicy() *Policy {
	return NewPolicy(map[string]interface{}{
		"targets": []interface{}{map[string]interface{}{
			"model": "*",
			"fallbacks": []interface{}{
				map[string]interface{}{"model": "*", "provider": "anthropic"},
			},
		}},
		ProviderClustersParam: map[string]interface{}{
			"":          "cluster_default",
			"anthropic": "cluster_anthropic",
		},
	})
}

// runWithBody drives one request with a raw body and returns the action and the metadata it
// wrote. A nil body models a request that carried none at all.
func runWithBody(t *testing.T, p *Policy, raw []byte, metadata map[string]interface{}) (policy.RequestAction, map[string]interface{}) {
	t.Helper()
	if metadata == nil {
		metadata = map[string]interface{}{}
	}
	var body *policy.Body
	if raw != nil {
		body = &policy.Body{Content: raw, Present: true}
	}
	action := p.OnRequestBody(context.Background(), &policy.RequestContext{
		SharedContext: &policy.SharedContext{Metadata: metadata},
		Body:          body,
	}, nil)
	return action, metadata
}

// assertInert fails unless the policy did nothing observable: no chain published and no
// immediate response. FR-030b's bar is "indistinguishable from not being attached".
func assertInert(t *testing.T, action policy.RequestAction, metadata map[string]interface{}) {
	t.Helper()
	if _, refused := action.(policy.ImmediateResponse); refused {
		t.Fatal("the policy answered the request; a model-less request must pass through untouched")
	}
	if _, published := metadata[metadataKeyChain]; published {
		t.Fatal("a chain was published for a request that named no model")
	}
	if _, retries := metadata[metadataKeySelectedModel]; retries {
		t.Fatal("a model was selected for a request that named none")
	}
}

// A request whose body carries no `model` key must not be absorbed by the catch-all.
//
// requestedModelFrom returns "" for it, and selectChain matches "*" on ANY requested model
// including "" — so before FR-060 this was treated as unmatched traffic. It is not: a
// catch-all is a publisher's "send the REST here" for a model that was named and matched
// nothing (FR-050), not "apply failover to anything at all".
func TestModelLessRequest_BodyWithNoModelKeyIsNotCaughtByTheWildcard(t *testing.T) {
	action, metadata := runWithBody(t, catchAllPolicy(), []byte(`{"messages":[{"role":"user"}]}`), nil)
	assertInert(t, action, metadata)
}

// A body that is not JSON at all reaches requestedModelFrom's unmarshal failure, which also
// returns "". Fanning a malformed request across every provider in the chain turns one bad
// request into as many upstream calls as the chain is long.
func TestModelLessRequest_UnparseableBodyIsNotCaughtByTheWildcard(t *testing.T) {
	action, metadata := runWithBody(t, catchAllPolicy(), []byte(`not json at all`), nil)
	assertInert(t, action, metadata)
}

// No body at all — the shape an API kind with no model concept produces (an A2A agent card
// read, a GraphQL query). FR-030b requires the policy to be inert on such a kind, and a
// catch-all must not override that.
func TestModelLessRequest_AbsentBodyIsNotCaughtByTheWildcard(t *testing.T) {
	action, metadata := runWithBody(t, catchAllPolicy(), nil, nil)
	assertInert(t, action, metadata)
}

// A `model` present but not a string also yields "" from requestedModelFrom.
func TestModelLessRequest_NonStringModelIsNotCaughtByTheWildcard(t *testing.T) {
	action, metadata := runWithBody(t, catchAllPolicy(), []byte(`{"model":{"name":"gpt-4o"}}`), nil)
	assertInert(t, action, metadata)
}

// POSITIVE CONTROL. The catch-all must still do its job: a model that WAS named and matches no
// chain is exactly what it exists for (FR-050). A guard that swallowed this too would silently
// disable catch-all failover for every request.
func TestModelLessRequest_NamedButUnmatchedModelStillUsesTheWildcard(t *testing.T) {
	action, metadata := runWithBody(t, catchAllPolicy(), []byte(`{"model":"some-model-nobody-named"}`), nil)

	if _, refused := action.(policy.ImmediateResponse); refused {
		t.Fatal("a named unmatched model was refused; the catch-all must serve it")
	}
	if _, published := metadata[metadataKeyChain]; !published {
		t.Fatal("no chain published for a named model the catch-all covers")
	}
}

// POSITIVE CONTROL for the second half of the guard. A routing policy's ranking names its own
// models and is valid for a request whose body named none, so it must still be honoured —
// which is why the guard requires BOTH an empty model and no published ranking.
func TestModelLessRequest_RoutingPolicyRankingIsStillHonoured(t *testing.T) {
	metadata := map[string]interface{}{
		MetadataKeyPublishedRanking: []map[string]string{
			{"model": "claude-3-5-sonnet-20241022", "provider": "anthropic"},
		},
	}
	action, metadata := runWithBody(t, catchAllPolicy(), []byte(`{"messages":[]}`), metadata)

	if _, refused := action.(policy.ImmediateResponse); refused {
		t.Fatal("a routing policy's ranking was refused because the body named no model")
	}
	if _, published := metadata[metadataKeyChain]; !published {
		t.Fatal("the routing policy's ranking was dropped because the body named no model")
	}
}
