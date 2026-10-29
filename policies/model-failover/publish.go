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
func buildPriorityGroups(chain []Target, providerClusters map[string]string) []any {
	if len(chain) == 0 {
		return nil
	}

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
		if cluster, ok := providerClusters[target.Provider]; ok {
			group["clusters"] = []any{
				// Weight must be an integer: the specifier reads it as a number and
				// rejects anything below 1, so a group with a malformed weight ends up
				// with no clusters at all.
				map[string]any{"cluster_name": cluster, "weight": 1},
			}
		}
		groups = append(groups, group)
	}
	return groups
}

// buildFailoverMetadata returns the dynamic-metadata payload for one request, or nil when
// there is nothing to publish.
//
// Returning nil is the inert path: no metadata is written, so Envoy uses the route's
// configured group order and the operation behaves exactly as if the policy were not
// attached. Nothing is logged or counted about being inert — an inert policy is
// indistinguishable from an absent one (FR-030b, FR-030e).
func buildFailoverMetadata(chain []Target, providerClusters map[string]string) map[string]map[string]any {
	groups := buildPriorityGroups(chain, providerClusters)
	if groups == nil {
		return nil
	}
	payload := map[string]any{priorityGroupsKey: groups}
	if models := buildAttemptModels(chain, providerClusters); len(models) > 0 {
		payload[attemptModelsKey] = models
	}
	return map[string]map[string]any{FailoverMetadataNamespace: payload}
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

	// MetadataKeySelectedModel and MetadataKeySelectedProvider are the single-selection keys
	// routing policies already set today. A policy that has not adopted the ordered list is
	// read through these, yielding a one-element ranking (FR-023).
	MetadataKeySelectedModel    = "model_roundrobin.selected_model"
	MetadataKeySelectedProvider = "model_roundrobin.selected_provider"
)
