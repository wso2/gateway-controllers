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

import "testing"

// reviewedShape is the parameter layout from the approved design document: chains keyed by the
// client-requested model, each with its own fallbacks.
func reviewedShape() map[string]interface{} {
	return map[string]interface{}{
		"targets": []interface{}{
			map[string]interface{}{
				"model": "gpt-4o",
				"fallbacks": []interface{}{
					map[string]interface{}{"model": "gpt-4o-mini"},
					map[string]interface{}{"model": "claude-3-5-sonnet-20241022", "provider": "anthropic"},
				},
			},
			map[string]interface{}{
				"model": "gpt-4.1",
				"fallbacks": []interface{}{
					map[string]interface{}{"model": "gpt-4.1", "provider": "azure-openai"},
				},
			},
			map[string]interface{}{
				"model": "*",
				"fallbacks": []interface{}{
					map[string]interface{}{"model": "*", "provider": "azure-openai"},
				},
			},
		},
	}
}

func TestParseChains_ReadsTheReviewedShape(t *testing.T) {
	params := parseParams(reviewedShape())
	if len(params.Chains) != 3 {
		t.Fatalf("chains = %d, want 3", len(params.Chains))
	}
	first := params.Chains[0]
	if first.RequestedModel != "gpt-4o" {
		t.Fatalf("first chain key = %q", first.RequestedModel)
	}
	// The chain's own model/provider ARE its first member.
	if first.Target.Model != "gpt-4o" {
		t.Fatalf("first member = %q, want gpt-4o", first.Target.Model)
	}
	if len(first.Fallbacks) != 2 {
		t.Fatalf("fallbacks = %d, want 2", len(first.Fallbacks))
	}
}

// An exact entry always wins over the catch-all (FR-046).
func TestSelectChain_ExactMatchBeatsWildcard(t *testing.T) {
	chains := parseParams(reviewedShape()).Chains

	chain, ok := selectChain(chains, "gpt-4.1")
	if !ok || chain.RequestedModel != "gpt-4.1" {
		t.Fatalf("selected %q (ok=%v), want the exact gpt-4.1 chain", chain.RequestedModel, ok)
	}
}

func TestSelectChain_UnnamedModelFallsToWildcard(t *testing.T) {
	chains := parseParams(reviewedShape()).Chains

	chain, ok := selectChain(chains, "some-model-nobody-named")
	if !ok || chain.RequestedModel != WildcardModel {
		t.Fatalf("selected %q (ok=%v), want the catch-all", chain.RequestedModel, ok)
	}
}

// With no catch-all configured, an unmatched model is not an error: the request proceeds
// unchanged to its normal upstream (FR-050).
func TestSelectChain_NoMatchAndNoWildcardIsNotAnError(t *testing.T) {
	chains := parseParams(map[string]interface{}{
		"targets": []interface{}{
			map[string]interface{}{"model": "gpt-4o"},
		},
	}).Chains

	if _, ok := selectChain(chains, "claude-opus"); ok {
		t.Fatal("expected no chain to match")
	}
}

// A "*" member passes the client's own model through unchanged — the mechanism for failing the
// same model over to another provider (FR-047).
func TestChainMembers_WildcardMemberKeepsTheClientsModel(t *testing.T) {
	chains := parseParams(reviewedShape()).Chains
	chain, _ := selectChain(chains, "llama-3-70b")

	members := chain.Members("llama-3-70b")
	if len(members) != 2 {
		t.Fatalf("members = %d, want 2", len(members))
	}
	if members[0].Model != "llama-3-70b" || members[0].Provider != "" {
		t.Fatalf("first member = %+v, want the client's model on the primary", members[0])
	}
	if members[1].Model != "llama-3-70b" || members[1].Provider != "azure-openai" {
		t.Fatalf("second member = %+v, want the same model on azure-openai", members[1])
	}
}

// A fallback with no provider inherits the CHAIN'S target provider, not the proxy primary
// (FR-048). Getting this wrong silently sends a cross-provider fallback to the wrong backend.
func TestParseChains_FallbackInheritsTheChainsProvider(t *testing.T) {
	params := parseParams(map[string]interface{}{
		"targets": []interface{}{
			map[string]interface{}{
				"model":    "claude-sonnet-4",
				"provider": "anthropic",
				"fallbacks": []interface{}{
					map[string]interface{}{"model": "claude-opus-4"},
					map[string]interface{}{"model": "gpt-4o", "provider": "openai-primary"},
				},
			},
		},
	})
	chain := params.Chains[0]

	if got := chain.Fallbacks[0].Provider; got != "anthropic" {
		t.Fatalf("fallback with no provider = %q, want the chain's own provider anthropic", got)
	}
	if got := chain.Fallbacks[1].Provider; got != "openai-primary" {
		t.Fatalf("explicitly named provider = %q, want openai-primary", got)
	}
}

// maxSuspendMultiplier is authored as a MULTIPLE of the base, not an absolute ceiling.
func TestParseParams_MultiplierBecomesAnAbsoluteCeiling(t *testing.T) {
	params := parseParams(map[string]interface{}{
		"targets":              []interface{}{map[string]interface{}{"model": "gpt-4o"}},
		"suspendDuration":      float64(30),
		"maxSuspendMultiplier": float64(8),
	})
	if params.Suspension.MaxDurationSeconds != 240 {
		t.Fatalf("ceiling = %d, want 240 (30 x 8)", params.Suspension.MaxDurationSeconds)
	}
}

// perTryTimeout is authored in seconds; everything downstream works in milliseconds.
func TestParseParams_PerTryTimeoutIsSeconds(t *testing.T) {
	params := parseParams(map[string]interface{}{
		"targets":       []interface{}{map[string]interface{}{"model": "gpt-4o"}},
		"perTryTimeout": float64(15),
	})
	if params.PerAttemptTimeoutMs != 15000 {
		t.Fatalf("per-attempt timeout = %dms, want 15000", params.PerAttemptTimeoutMs)
	}
}

// statusCodes REPLACES the default list rather than extending it.
func TestParseParams_StatusCodesReplaceTheDefault(t *testing.T) {
	params := parseParams(map[string]interface{}{
		"targets":     []interface{}{map[string]interface{}{"model": "gpt-4o"}},
		"statusCodes": []interface{}{float64(429)},
	})
	if len(params.FailureConditions.StatusCodes) != 1 || params.FailureConditions.StatusCodes[0] != 429 {
		t.Fatalf("status codes = %v, want exactly [429]", params.FailureConditions.StatusCodes)
	}
}

// The four fallback shapes a publisher can author. Model and provider vary independently on
// every member, so each of these is expressible — and this test is the living record of that
// contract, since the schema alone does not make the combinations obvious.
func TestChainShapes_ModelAndProviderVaryIndependently(t *testing.T) {
	cases := []struct {
		name        string
		params      map[string]interface{}
		requested   string
		wantMembers []Target
	}{
		{
			name: "same model, different provider — regional failover",
			params: map[string]interface{}{"targets": []interface{}{
				map[string]interface{}{
					"model": "gpt-4o", "provider": "azure-sweden",
					"fallbacks": []interface{}{
						map[string]interface{}{"model": "gpt-4o", "provider": "azure-spain"},
					},
				},
			}},
			requested: "gpt-4o",
			wantMembers: []Target{
				{Model: "gpt-4o", Provider: "azure-sweden"},
				{Model: "gpt-4o", Provider: "azure-spain"},
			},
		},
		{
			name: "different model, same provider — downgrade",
			params: map[string]interface{}{"targets": []interface{}{
				map[string]interface{}{
					"model": "gpt-4o",
					"fallbacks": []interface{}{
						map[string]interface{}{"model": "gpt-4o-mini"},
					},
				},
			}},
			requested: "gpt-4o",
			wantMembers: []Target{
				{Model: "gpt-4o"},
				{Model: "gpt-4o-mini"},
			},
		},
		{
			name: "different model and provider — cross-vendor",
			params: map[string]interface{}{"targets": []interface{}{
				map[string]interface{}{
					"model": "gpt-4o",
					"fallbacks": []interface{}{
						map[string]interface{}{"model": "claude-sonnet-4", "provider": "anthropic"},
					},
				},
			}},
			requested: "gpt-4o",
			wantMembers: []Target{
				{Model: "gpt-4o"},
				{Model: "claude-sonnet-4", Provider: "anthropic"},
			},
		},
		{
			name: "client's own model on another provider — one chain covers every model",
			params: map[string]interface{}{"targets": []interface{}{
				map[string]interface{}{
					"model": "*",
					"fallbacks": []interface{}{
						map[string]interface{}{"model": "*", "provider": "azure"},
					},
				},
			}},
			requested: "llama-3-70b",
			wantMembers: []Target{
				{Model: "llama-3-70b"},
				{Model: "llama-3-70b", Provider: "azure"},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			chains := parseParams(tc.params).Chains
			chain, ok := selectChain(chains, tc.requested)
			if !ok {
				t.Fatalf("no chain matched %q", tc.requested)
			}
			got := chain.Members(tc.requested)
			if len(got) != len(tc.wantMembers) {
				t.Fatalf("members = %+v, want %+v", got, tc.wantMembers)
			}
			for i := range got {
				if got[i] != tc.wantMembers[i] {
					t.Fatalf("member %d = %+v, want %+v", i, got[i], tc.wantMembers[i])
				}
			}
		})
	}
}
