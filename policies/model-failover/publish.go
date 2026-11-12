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

const (
	// FailoverMetadataNamespace is the dynamic-metadata namespace the generated
	// priority_group cluster specifier reads its per-request groups from. It must match
	// the controller's FailoverOverrideMetadataNamespace exactly, or Envoy silently falls
	// back to the configured group order and the published ranking is ignored.
	FailoverMetadataNamespace = "wso2.failover"

	// priorityGroupsKey is the field the specifier looks for inside that namespace.
	priorityGroupsKey = "priority_groups"

	// attemptModelsKey carries this request's cluster-to-model mapping alongside the groups,
	// so the per-attempt instance of this policy can substitute the model its own target
	// expects. A sibling key rather than a field inside each group: the specifier parses
	// priority_groups, and nothing is gained by handing it a shape it did not ask for.
	//
	// Keyed by CLUSTER, not by position. An index into the ranking goes wrong the moment a
	// member is suspended or skipped, whereas the cluster names the target directly -- the
	// same reasoning as the engine's wso2.attempt namespace.
	attemptModelsKey = "attempt_models"

	// groupNamePrefix names the per-request groups. Names only have to be unique and
	// stable within the request; the specifier selects by position, not by name.
	groupNamePrefix = "t:"

	// ProviderClustersParam is the controller-injected provider-to-cluster map. Must match
	// the controller's constant of the same name.
	ProviderClustersParam = "__providerClusters"
)

// groupName is the deterministic name of the priority group serving one target.
//
// It MUST match the controller's FailoverGroupName exactly. The controller names each
// configured group for its target; the policy reorders those groups per request by publishing
// their names. A mismatch is silent — Envoy simply falls back to the configured order, the
// request still succeeds, and the only symptom is that the published ranking is ignored.
//
// Publishing names rather than clusters is deliberate. Cluster names are derived from the
// upstream hostname or upstream-definition name, not from the provider alias the policy knows,
// so the policy cannot construct them. Envoy resolves a name-only group against the clusters
// the controller configured.
func groupName(target Target) string {
	provider := target.Provider
	if provider == "" {
		provider = "default"
	}
	return groupNamePrefix + provider + ":" + target.Model
}

// buildPriorityGroups renders a resolved chain as the structure the priority_group cluster
// specifier expects: an ordered list of groups, each naming one cluster.
//
// Attempt N takes group N. Once attempts exceed the group count Envoy stays on the LAST
// group rather than reaching for an unranked cluster, which is why a target excluded from
// this list — a suspended one — cannot receive traffic even if the attempt budget is
// miscounted.
//
// Values are plain Go maps and slices because the kernel passes the namespace through
// structpb.NewStruct, which converts nested maps, slices, strings and numbers directly.
// Anything it cannot represent makes the whole namespace fail to build, so the policy
// degrades to inert rather than emitting a malformed structure.
//
// Note weights are emitted as integers but arrive at Envoy as protobuf numbers (float64).
// The specifier parses weight from a number value and rejects anything below 1, so integral
// values are required — a weight expressed as a string would be dropped silently, leaving a
// group with no clusters.
// It also returns the members it DROPPED for having no resolvable cluster. A drop is invisible
// in the published result -- the ranking is simply shorter than the one the chain described -- so
// returning it is what lets the caller say so. Same reasoning as resolveChain returning its
// health-skipped targets: a short chain reads identically whether it was configured short,
// whittled down by health, or silently truncated here (FR-056a).
func buildPriorityGroups(chain []Target, providerClusters map[string]string) ([]any, []Target) {
	if len(chain) == 0 {
		return nil, nil
	}

	var dropped []Target
	groups := make([]any, 0, len(chain))
	for _, target := range chain {
		group := map[string]any{"name": groupName(target)}

		// Carry the cluster when the controller told us one. This is what lets a group
		// resolve for a (provider, model) the control plane never enumerated — a wildcard
		// member whose model is only known at request time, or a target a routing policy
		// alone nominated.
		//
		// Without it the group is a bare name, which resolves only against a pre-configured
		// group of the same name. Probe G measured what happens when it does not resolve:
		// Envoy does NOT skip the entry, it substitutes the configured group at that
		// position, which can route the request to a target the ranking never nominated and
		// burn the whole attempt budget there.
		cluster, ok := providerClusters[target.Provider]
		if !ok {
			// DROPPED, not published as a bare name (FR-056). A name-only group resolves
			// only against a pre-configured group of the same name, and Probe G measured
			// what Envoy does when it does not resolve: it substitutes the configured
			// group at that POSITION. So publishing an unresolvable entry is worse than
			// omitting it -- the attempt lands on whatever target happens to sit at that
			// index, which the ranking never nominated and health may have suspended,
			// and the whole per-attempt budget is spent there.
			//
			// Omitting shortens the list instead, and a shorter list is safe by
			// construction: once attempts exceed the group count Envoy stays on the LAST
			// group rather than reaching for an unranked cluster.
			//
			// Defence in depth. Since the controller supplies a provider-to-cluster map,
			// every member it enumerated resolves here, so this is reachable only when the
			// map is absent -- an older controller paired with a newer policy -- or when
			// a ranking names a provider this API has no upstream for, which a routing
			// policy can do because the controller never saw its target list.
			dropped = append(dropped, target)
			continue
		}
		group["clusters"] = []any{
			// Weight must be an integer: the specifier reads it as a number and
			// rejects anything below 1, so a group with a malformed weight ends up
			// with no clusters at all.
			map[string]any{"cluster_name": cluster, "weight": 1},
		}
		groups = append(groups, group)
	}
	if len(groups) == 0 {
		// Nothing resolved. Return nil rather than an empty list so the caller takes the
		// inert path and writes no metadata at all: publishing an empty priority_groups
		// would be a malformed ranking, where writing nothing leaves Envoy on the route's
		// configured order, which is exactly how the policy behaves when unattached
		// (FR-030b, FR-030e).
		return nil, dropped
	}
	return groups, dropped
}

// buildFailoverMetadata returns the dynamic-metadata payload for one request, or nil when
// there is nothing to publish.
//
// Returning nil is the inert path: no metadata is written, so Envoy uses the route's
// configured group order and the operation behaves exactly as if the policy were not
// attached. Nothing is logged or counted about being inert — an inert policy is
// indistinguishable from an absent one (FR-030b, FR-030e).
func buildFailoverMetadata(chain []Target, providerClusters map[string]string) (map[string]map[string]any, []Target) {
	groups, dropped := buildPriorityGroups(chain, providerClusters)
	if groups == nil {
		return nil, dropped
	}
	payload := map[string]any{priorityGroupsKey: groups}
	if models := buildAttemptModels(chain, providerClusters); len(models) > 0 {
		payload[attemptModelsKey] = models
	}
	return map[string]map[string]any{FailoverMetadataNamespace: payload}, dropped
}

// buildAttemptModels maps each member's target cluster to the model that member asks for.
//
// This is what makes failover a MODEL failover rather than a provider failover: attempt 2 reaches
// the fallback provider, but unless the payload also names that member's model it still asks for
// the primary's -- a model the fallback may not serve at all.
//
// A member with no resolved cluster is omitted: no attempt can be routed to it, so no attempt can
// read it back. A member with an empty model is omitted too -- a wildcard member carries whatever
// the client asked for, and substituting "" would erase it.
func buildAttemptModels(chain []Target, providerClusters map[string]string) map[string]any {
	models := map[string]any{}
	for _, target := range chain {
		cluster, ok := providerClusters[target.Provider]
		if !ok || cluster == "" || target.Model == "" {
			continue
		}
		models[cluster] = target.Model
	}
	return models
}

// Contract keys shared with the routing policies.
const (
	// MetadataKeyPublishedRanking is where a routing policy that has adopted the ordered
	// preference list contract publishes its ranking for this request.
	MetadataKeyPublishedRanking = "model_routing.published_ranking"

	// MetadataKeySelectedProvider is the single-selection key every steering policy in the
	// repo already writes, and every openai-to-* transformer already reads, since
	// 77dcac0 (2026-07-09) — three months before this feature. A policy that has not
	// adopted the ordered list is read through it, yielding a one-element ranking (FR-023).
	//
	// It carries a PROVIDER and nothing else, deliberately. No transformer derives a model
	// from it: each resolves the model from the request body, falling back to its own
	// configured override. So a selection here means "the model the client asked for, at
	// this provider", and that is exactly the Target this consumer builds from it.
	//
	// This key is NOT namespaced by producer, and that is the point. This consumer
	// previously read "model_roundrobin.selected_provider" — model-round-robin's own
	// private key, which no other steering policy writes — so every other routing policy's
	// decision was silently dropped whenever failover was attached. A consumer of a
	// cross-policy channel must read the channel's shared address, never one producer's.
	MetadataKeySelectedProvider = "selected_provider"
)
