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

	// attemptModelsKey carries this request's per-member models alongside the groups, so the
	// per-attempt instance of this policy can substitute the model its own target expects. A
	// sibling key rather than a field inside each group: the specifier parses priority_groups,
	// and nothing is gained by handing it a shape it did not ask for.
	//
	// An ORDERED LIST, positionally parallel to priority_groups: entry N describes the member
	// attempt N is routed to. It was a cluster-keyed map, which is wrong because a cluster
	// names a PROVIDER and a member is a provider AND a model. Two members on one vendor --
	// `gpt-4o` then `gpt-4o-mini`, an ordinary cost-control chain -- collapsed onto one key and
	// the last one won, so attempt 1 asked for the LAST member's model: the first model was
	// never requested, and attempt 2 was a byte-identical request to the identical upstream,
	// which is no failover at all.
	//
	// The position cannot be keyed by (provider, model) instead, because the model is the thing
	// being looked up -- a lookup cannot be keyed by its own output. What the reader CAN know
	// is which attempt it is, from the engine's wso2.attempt.number, so the list is indexed by
	// that. Each entry still carries its cluster, not as the key but as a cross-check.
	attemptModelsKey = "attempt_models"

	// Fields of one attempt_models entry.
	//
	// attemptModelCluster is the cluster the ranking expects this position to be routed to. It
	// is a CROSS-CHECK, never the lookup key: if it disagrees with the cluster the engine says
	// this attempt is aimed at, the positional contract has broken and the reader declines to
	// substitute rather than rewriting the payload for the wrong target.
	attemptModelCluster = "cluster"
	// attemptModelModel is the model to substitute, or "" for a wildcard member -- one whose
	// model is whatever the client asked for. An empty entry is a HOLE, deliberately published
	// rather than omitted: omitting it would shift every later member's index by one.
	attemptModelModel = "model"

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

// servableCluster resolves the cluster that will serve a chain member, reporting false when the
// member cannot be served at all and must be dropped from this request's ranking.
//
// ONE predicate, called from every place that decides whether a member is part of the ranking:
// the group builder here, the servable filter in OnRequestBody, and the correlation store. They
// used to spell it three slightly different ways -- `!ok`, `ok && cluster != ""`, and
// `!ok || cluster == ""` -- which agree only because BuildProviderClusterMap never writes an
// empty value. They are unified because the published list is now POSITIONAL: the moment two of
// them disagree about one member, the groups and the model list have different lengths and every
// index past the disagreement names a different member in each. Unreachable today, and exactly
// the drift that would make the positional contract unsafe later.
func servableCluster(providerClusters map[string]string, provider string) (string, bool) {
	cluster, ok := providerClusters[provider]
	if !ok || cluster == "" {
		return "", false
	}
	return cluster, true
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
func buildPriorityGroups(chain []Target, providerClusters map[string]string) ([]any, []any, []Target) {
	if len(chain) == 0 {
		return nil, nil, nil
	}

	var dropped []Target
	groups := make([]any, 0, len(chain))
	// Built in the SAME pass as the groups, and that is load-bearing rather than tidy. The model
	// list used to be built from the PRE-drop chain while the groups were post-drop, which is
	// harmless for a map keyed by cluster and fatal for a positional list: one dropped middle
	// member shifts every later entry, so every later attempt would substitute its neighbour's
	// model. Sharing the loop makes the two lists parallel by construction, not by agreement.
	models := make([]any, 0, len(chain))
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
		cluster, ok := servableCluster(providerClusters, target.Provider)
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

		// One entry per published group, ALWAYS -- including a wildcard member, whose
		// empty model means "do not substitute, the client's own model stands". Skipping
		// it would shift every later index by one and make each later attempt ask for its
		// neighbour's model.
		models = append(models, map[string]any{
			attemptModelCluster: cluster,
			attemptModelModel:   target.Model,
		})
	}
	if len(groups) == 0 {
		// Nothing resolved. Return nil rather than an empty list so the caller takes the
		// inert path and writes no metadata at all: publishing an empty priority_groups
		// would be a malformed ranking, where writing nothing leaves Envoy on the route's
		// configured order, which is exactly how the policy behaves when unattached
		// (FR-030b, FR-030e).
		return nil, nil, dropped
	}
	return groups, models, dropped
}

// buildFailoverMetadata returns the dynamic-metadata payload for one request, or nil when
// there is nothing to publish.
//
// Returning nil is the inert path: no metadata is written, so Envoy uses the route's
// configured group order and the operation behaves exactly as if the policy were not
// attached. Nothing is logged or counted about being inert — an inert policy is
// indistinguishable from an absent one (FR-030b, FR-030e).
func buildFailoverMetadata(chain []Target, providerClusters map[string]string) (map[string]map[string]any, []Target) {
	groups, models, dropped := buildPriorityGroups(chain, providerClusters)
	if groups == nil {
		return nil, dropped
	}
	// Published unconditionally alongside the groups, never under a len() guard. The two lists
	// come out of one loop with one entry each per published member, so a guard here could only
	// ever hide a desynchronisation -- and a model list SHORTER than the group list is precisely
	// the bug the positional contract has to exclude.
	return map[string]map[string]any{FailoverMetadataNamespace: {
		priorityGroupsKey: groups,
		attemptModelsKey:  models,
	}}, dropped
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
