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

// The group name and metadata namespace are a CROSS-REPOSITORY contract with the gateway
// controller in wso2/api-platform. The controller names each configured priority group; this
// policy republishes those names in its per-request order.
//
// A mismatch is silent. Envoy finds no group matching a published name, falls back to the
// configured order, and the request still succeeds — so no test that only asserts "failover
// works" can catch a rename. The literals below are pinned identically in the controller's
// TestFailoverGroupName_CrossRepoContract. Changing either side breaks a test rather than
// quietly disabling per-request ordering in production.
func TestGroupName_CrossRepoContract(t *testing.T) {
	if got := groupName(Target{Model: "gpt-4o", Provider: "openai"}); got != "t:openai:gpt-4o" {
		t.Fatalf("group name = %q, want %q — the controller's FailoverGroupName() must "+
			"produce the identical string", got, "t:openai:gpt-4o")
	}

	// A target with no provider names the API's own main upstream. Both sides substitute
	// the same placeholder, or the two spellings never meet.
	if got := groupName(Target{Model: "gpt-4o"}); got != "t:default:gpt-4o" {
		t.Fatalf("group name without provider = %q, want %q", got, "t:default:gpt-4o")
	}

	if FailoverMetadataNamespace != "wso2.failover" {
		t.Fatalf("metadata namespace = %q, want wso2.failover — the controller reads this "+
			"namespace by literal name", FailoverMetadataNamespace)
	}
	if priorityGroupsKey != "priority_groups" {
		t.Fatalf("priority groups key = %q, want priority_groups", priorityGroupsKey)
	}
}

// Without the controller's map nothing can be named, so nothing is published and the policy
// goes inert for the request. Probe G is why: Envoy does not SKIP an unresolvable group, it
// substitutes the configured group at that POSITION, so a bare name sends the attempt to a
// target the ranking never nominated and spends the whole budget there. A shorter list is safe
// where a wrong one is not (FR-056, FR-056a).
//
// This is the degraded path -- an older controller paired with a newer policy, or a ranking
// naming a provider this API has no upstream for -- not the intended one; see
// TestBuildPriorityGroups_CarriesClusters.
func TestBuildPriorityGroups_DropsMembersWithNoCluster(t *testing.T) {
	chain := []Target{
		{Model: "gpt-4o", Provider: "openai"},
		{Model: "claude-sonnet-4", Provider: "anthropic"},
	}

	groups, _, dropped := buildPriorityGroups(chain, nil)

	if groups != nil {
		t.Fatalf("groups = %v, want nil: an unresolvable member must not be published", groups)
	}
	// Reported, not merely omitted. A drop is invisible in the result -- the ranking is just
	// shorter -- so the caller can only say so if this hands it back.
	if len(dropped) != 2 {
		t.Fatalf("dropped = %d, want 2", len(dropped))
	}
	for i, target := range chain {
		if !dropped[i].Equal(target) {
			t.Fatalf("dropped[%d] = %v, want %v", i, dropped[i], target)
		}
	}
}

// A member the map CAN name is published while its unnameable sibling is dropped, so one bad
// reference shortens the ranking instead of voiding it.
func TestBuildPriorityGroups_DropsOnlyTheUnresolvableMember(t *testing.T) {
	chain := []Target{
		{Model: "gpt-4o", Provider: "openai"},
		{Model: "claude-sonnet-4", Provider: "typo-provider"},
	}

	groups, _, dropped := buildPriorityGroups(chain, map[string]string{"openai": "cluster_openai"})

	if len(groups) != 1 {
		t.Fatalf("groups = %d, want 1", len(groups))
	}
	if name := groups[0].(map[string]any)["name"]; name != "t:openai:gpt-4o" {
		t.Fatalf("published group = %v, want the resolvable member", name)
	}
	if len(dropped) != 1 || dropped[0].Provider != "typo-provider" {
		t.Fatalf("dropped = %v, want the unresolvable member only", dropped)
	}
}

// Order is the whole contract: attempt N takes group N. Asserted with every member resolvable,
// since an unresolvable one is dropped rather than held in place (FR-056).
func TestBuildPriorityGroups_PreservesChainOrder(t *testing.T) {
	chain := []Target{
		{Model: "a", Provider: "p1"},
		{Model: "b", Provider: "p2"},
		{Model: "c", Provider: "p3"},
	}
	clusters := map[string]string{"p1": "c1", "p2": "c2", "p3": "c3"}

	groups, _, dropped := buildPriorityGroups(chain, clusters)

	if len(dropped) != 0 {
		t.Fatalf("dropped = %v, want none: every member resolves here", dropped)
	}
	if len(groups) != len(chain) {
		t.Fatalf("groups = %d, want %d", len(groups), len(chain))
	}
	for i, target := range chain {
		got := groups[i].(map[string]any)["name"]
		if got != groupName(target) {
			t.Fatalf("group %d = %v, want %v", i, got, groupName(target))
		}
	}
}

// An empty chain publishes nothing at all, so Envoy uses the route's configured order and the
// operation behaves exactly as if the policy were not attached (FR-030b, FR-030e).
func TestBuildFailoverMetadata_EmptyChainIsInert(t *testing.T) {
	if metadata, _ := buildFailoverMetadata(nil, nil); metadata != nil {
		t.Fatalf("expected nil metadata for an empty chain, got %v", metadata)
	}
	if groups, _, _ := buildPriorityGroups(nil, nil); groups != nil {
		t.Fatalf("expected nil groups for an empty chain, got %v", groups)
	}
}

func TestBuildFailoverMetadata_NestsUnderTheNamespace(t *testing.T) {
	// A resolvable member, since an unresolvable one is dropped and publishes nothing at all
	// (TestBuildPriorityGroups_DropsMembersWithNoCluster).
	metadata, _ := buildFailoverMetadata(
		[]Target{{Model: "gpt-4o", Provider: "openai"}},
		map[string]string{"openai": "upstream_LlmProxy_abc_openai"})
	namespace, ok := metadata[FailoverMetadataNamespace]
	if !ok {
		t.Fatalf("metadata has no %q namespace: %v", FailoverMetadataNamespace, metadata)
	}
	groups, ok := namespace[priorityGroupsKey].([]any)
	if !ok || len(groups) != 1 {
		t.Fatalf("namespace[%q] = %v", priorityGroupsKey, namespace[priorityGroupsKey])
	}
}

// The intended path: a controller-supplied provider-to-cluster map lets the policy publish a
// COMPLETE group, so a (provider, model) the control plane never enumerated still resolves.
func TestBuildPriorityGroups_CarriesClusters(t *testing.T) {
	clusters := map[string]string{
		"":          "upstream_main_host_8080",
		"anthropic": "upstream_LlmProxy_abc_anthropic",
	}
	groups, _, _ := buildPriorityGroups([]Target{
		{Model: "gpt-4o"},
		{Model: "claude-sonnet-4", Provider: "anthropic"},
	}, clusters)

	first := groups[0].(map[string]any)
	list, ok := first["clusters"].([]any)
	if !ok || len(list) != 1 {
		t.Fatalf("first group carries no cluster list: %v", first)
	}
	entry := list[0].(map[string]any)
	if entry["cluster_name"] != "upstream_main_host_8080" {
		t.Fatalf("cluster_name = %v, want the main upstream for an empty provider", entry["cluster_name"])
	}
	// Weight must be integral — the specifier reads it as a number and rejects below 1, so a
	// string or float here silently leaves the group with no clusters.
	if w, ok := entry["weight"].(int); !ok || w < 1 {
		t.Fatalf("weight = %#v, want an integer >= 1", entry["weight"])
	}

	second := groups[1].(map[string]any)["clusters"].([]any)[0].(map[string]any)
	if second["cluster_name"] != "upstream_LlmProxy_abc_anthropic" {
		t.Fatalf("second cluster = %v", second["cluster_name"])
	}
}

// The case the whole change exists for: a wildcard member resolves to a model nobody configured,
// and must still carry a cluster. Under name-only publication the controller configures
// "t:azure:*" while the policy publishes "t:azure:<requested>", so the names never match and
// Probe G's position-fallback silently misroutes the request.
func TestBuildPriorityGroups_WildcardMemberStillResolves(t *testing.T) {
	chains := parseParams(map[string]interface{}{
		"targets": []interface{}{
			map[string]interface{}{
				"model": "*",
				"fallbacks": []interface{}{
					map[string]interface{}{"model": "*", "provider": "azure"},
				},
			},
		},
	}).Chains

	chain, ok := selectChain(chains, "a-model-nobody-configured")
	if !ok {
		t.Fatal("the catch-all chain must match")
	}
	members := chain.Members("a-model-nobody-configured")
	groups, _, _ := buildPriorityGroups(members, map[string]string{
		"":      "upstream_main_host_8080",
		"azure": "upstream_LlmProxy_abc_azure",
	})

	second := groups[1].(map[string]any)
	if second["name"] != "t:azure:a-model-nobody-configured" {
		t.Fatalf("group name = %v, want the client's model substituted", second["name"])
	}
	list, ok := second["clusters"].([]any)
	if !ok || len(list) != 1 {
		t.Fatal("a wildcard member must carry its cluster, or it can never resolve")
	}
	if list[0].(map[string]any)["cluster_name"] != "upstream_LlmProxy_abc_azure" {
		t.Fatalf("wildcard cluster = %v", list[0])
	}
}

// The injected map is platform-supplied, never authored.
func TestParseProviderClusters_ReadsTheInjectedMap(t *testing.T) {
	params := parseParams(map[string]interface{}{
		"targets": []interface{}{map[string]interface{}{"model": "gpt-4o"}},
		ProviderClustersParam: map[string]interface{}{
			"":      "upstream_main",
			"azure": "upstream_azure",
			"bad":   123,
		},
	})
	if params.ProviderClusters["azure"] != "upstream_azure" {
		t.Fatalf("azure = %q", params.ProviderClusters["azure"])
	}
	if _, present := params.ProviderClusters["bad"]; present {
		t.Fatal("a non-string cluster must be dropped, not coerced")
	}
}

// The cheap structural guard, and the shape that would have caught both cluster-keyed defects
// before they shipped: a chain whose members SHARE a provider, plus a member that is dropped.
//
// Three lists have to stay the same length and the same order -- the published groups, the
// published models, and the members the caller treats as servable. Every way of getting the model
// list wrong changes one of those lengths or one of those positions:
//
//	collapse the list back into a cluster-keyed map -> two members behind one cluster become one
//	build it from the PRE-drop chain                 -> longer than the groups, and shifted after
//	                                                    the drop
//	omit a wildcard instead of holing it             -> shorter, and shifted after the wildcard
//	let the drop predicates drift apart              -> groups and servable disagree
//
// Which is why it is asserted structurally rather than one defect at a time.
func TestBuildPriorityGroups_ModelsStayParallelToGroups(t *testing.T) {
	clusters := map[string]string{
		"anthropic": "c_claude",
		"google":    "c_gemini",
		"openai":    "c_openai",
		// "ghost" is deliberately absent: its member must be dropped from BOTH lists.
	}
	chain := []Target{
		{Provider: "anthropic", Model: "claude-sonnet-4-5"},
		{Provider: "ghost", Model: "nowhere"}, // dropped: no cluster
		{Provider: "google", Model: "gemini-2.5-pro"},
		{Provider: "anthropic", Model: "claude-opus-4-1"}, // SAME provider as member 0
		{Provider: "openai", Model: ""},                   // wildcard: a hole, not an omission
	}

	groups, models, dropped := buildPriorityGroups(chain, clusters)

	// What the caller independently computes as servable, by the same predicate.
	var servable []Target
	for _, target := range chain {
		if _, ok := servableCluster(clusters, target.Provider); ok {
			servable = append(servable, target)
		}
	}

	if len(dropped) != 1 || dropped[0].Provider != "ghost" {
		t.Fatalf("dropped = %v, want the ghost member only", dropped)
	}
	if len(groups) != len(servable) || len(models) != len(servable) {
		t.Fatalf("lengths disagree: groups = %d, models = %d, servable = %d",
			len(groups), len(models), len(servable))
	}

	for i, target := range servable {
		cluster, _ := servableCluster(clusters, target.Provider)

		entry, ok := models[i].(map[string]any)
		if !ok {
			t.Fatalf("models[%d] = %T, want an entry map", i, models[i])
		}
		if got := entry[attemptModelCluster]; got != cluster {
			t.Fatalf("models[%d] cluster = %v, want %v", i, got, cluster)
		}
		// The model at position i must be THIS member's, not a sibling's on the same cluster.
		if got := entry[attemptModelModel]; got != target.Model {
			t.Fatalf("models[%d] model = %v, want %q (member %v)", i, got, target.Model, target)
		}

		group := groups[i].(map[string]any)
		if got := group["name"]; got != groupName(target) {
			t.Fatalf("groups[%d] name = %v, want %v", i, got, groupName(target))
		}
		groupCluster := group["clusters"].([]any)[0].(map[string]any)["cluster_name"]
		if groupCluster != entry[attemptModelCluster] {
			t.Fatalf("position %d: group cluster %v != model cluster %v",
				i, groupCluster, entry[attemptModelCluster])
		}
	}
}

// The two members on one provider must appear as TWO entries carrying different models. Stated
// separately from the structural guard because it is the defect in one line: keyed by cluster
// these collapse, and whichever one wins, the other is never requested.
func TestBuildFailoverMetadata_RepeatedProviderKeepsBothModels(t *testing.T) {
	metadata, _ := buildFailoverMetadata([]Target{
		{Provider: "anthropic", Model: "claude-sonnet-4-5"},
		{Provider: "anthropic", Model: "claude-opus-4-1"},
	}, map[string]string{"anthropic": "c_claude"})

	models, ok := metadata[FailoverMetadataNamespace][attemptModelsKey].([]any)
	if !ok {
		t.Fatalf("attempt_models = %T, want an ordered list",
			metadata[FailoverMetadataNamespace][attemptModelsKey])
	}
	if len(models) != 2 {
		t.Fatalf("attempt_models = %d entries, want 2: both members share one cluster and "+
			"must still be told apart", len(models))
	}
	if got := models[0].(map[string]any)[attemptModelModel]; got != "claude-sonnet-4-5" {
		t.Fatalf("attempt 1 model = %v, want claude-sonnet-4-5", got)
	}
	if got := models[1].(map[string]any)[attemptModelModel]; got != "claude-opus-4-1" {
		t.Fatalf("attempt 2 model = %v, want claude-opus-4-1", got)
	}
}
