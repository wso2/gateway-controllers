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
	"log/slog"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

const (
	// attemptMetadataNamespace is the reserved namespace the engine writes on every
	// per-attempt chain. Its presence is also how this policy knows which position it is
	// running at: the downstream pass never sees it.
	//
	// Must match the engine's constants.AttemptMetadataNamespace exactly. The two modules
	// share no type, so a rename on either side is only caught by this policy quietly
	// reverting to its downstream behaviour.
	attemptMetadataNamespace = "wso2.attempt"

	// attemptMetadataCluster names the target THIS attempt is aimed at.
	attemptMetadataCluster = "cluster"

	// attemptMetadataNumber is the 1-based attempt index -- 1 is the original try.
	//
	// Must match the engine's constants.AttemptMetadataNumber. Published on every attempt
	// since the per-attempt position existed and never read until now; it is what lets the
	// model lookup be positional instead of keyed by a cluster that does not identify a
	// member.
	attemptMetadataNumber = "number"
)

// attemptCluster reports the cluster this attempt targets, and whether the policy is running at
// the per-attempt position at all.
func attemptCluster(metadata map[string]interface{}) (string, bool) {
	fields, ok := attemptNamespace(metadata)
	if !ok {
		return "", false
	}
	cluster, ok := fields[attemptMetadataCluster].(string)
	if !ok || cluster == "" {
		return "", false
	}
	return cluster, true
}

// attemptNamespace returns the engine's reserved wso2.attempt fields, and whether the policy is
// running at the per-attempt position at all. The downstream pass never sees this namespace.
func attemptNamespace(metadata map[string]interface{}) (map[string]interface{}, bool) {
	if metadata == nil {
		return nil, false
	}
	raw, ok := metadata[attemptMetadataNamespace]
	if !ok {
		return nil, false
	}
	fields, ok := raw.(map[string]interface{})
	if !ok {
		return nil, false
	}
	return fields, true
}

// attemptNumber reports which attempt this is, 1-based.
//
// The engine writes this in-process as a Go int, where the policy's own published metadata
// arrives back through Envoy and structpb as float64. Both are accepted because the two
// namespaces travel by different routes, and a representation change on either side would
// otherwise silently disable model substitution rather than fail.
func attemptNumber(metadata map[string]interface{}) (int, bool) {
	fields, ok := attemptNamespace(metadata)
	if !ok {
		return 0, false
	}
	var n int
	switch raw := fields[attemptMetadataNumber].(type) {
	case int:
		n = raw
	case int32:
		n = int(raw)
	case int64:
		n = int(raw)
	case uint32:
		n = int(raw)
	case float64:
		n = int(raw)
	default:
		return 0, false
	}
	if n < 1 {
		return 0, false
	}
	return n, true
}

// modelForAttempt reads back the model this request's ranking assigned to attempt N.
//
// The ranking is read from the policy's own published metadata rather than recomputed, so the
// attempt uses the order that was actually installed in Envoy. Recomputing here would let health
// state that changed mid-request disagree with the groups the request is already routing through.
//
// Selection is POSITIONAL -- entry N-1 for attempt N -- and that is what makes it correct for a
// chain whose members share a provider. A cluster names a provider, so `gpt-4o` then
// `gpt-4o-mini` on one vendor are two members behind one cluster name: keyed by cluster they
// collapse onto one entry and every attempt asks for the same model. The position tells them
// apart because the engine publishes it.
//
// Indexing is sound here, not a guess: the correspondence attempt N <-> published position N is
// already load-bearing elsewhere in this policy -- OnResponseHeaders grades chain[attempts-1] by
// exactly it, and a prior bug fixed in this file exists to protect it. The published groups carry
// their clusters inline and unresolvable members are dropped BEFORE publication, so Envoy's
// group-substitution behaviour (which can make an index right about position and wrong about
// target) cannot apply to this list.
//
// The cluster is still checked, as a guard rather than a key. If the entry at this position names
// a different target than the engine says the attempt is aimed at, the correspondence this lookup
// rests on has broken; substituting anyway would rewrite the payload for the wrong provider, so
// it declines and says so.
func modelForAttempt(metadata map[string]interface{}, attempt int, cluster string) (string, bool) {
	if metadata == nil || attempt < 1 {
		return "", false
	}
	namespace, ok := metadata[FailoverMetadataNamespace].(map[string]interface{})
	if !ok {
		return "", false
	}
	// A list, not a map. It arrives back through Envoy and structpb, so the element type is
	// []interface{} of map[string]interface{} whatever it was built as.
	models, ok := namespace[attemptModelsKey].([]interface{})
	if !ok || attempt > len(models) {
		// Past the end of the ranking. Envoy stays on the LAST group once attempts exceed
		// the group count, so this is reachable only if the budget outlived the ranking --
		// nothing to substitute, and guessing the last entry would be exactly the collapse
		// this list replaced.
		return "", false
	}
	entry, ok := models[attempt-1].(map[string]interface{})
	if !ok {
		return "", false
	}

	// Cross-check before trusting the entry.
	if expected, _ := entry[attemptModelCluster].(string); expected != cluster {
		slog.Warn("ModelFailover: published ranking disagrees with the attempt's target, "+
			"so this attempt's model is left alone",
			"attempt", attempt, "attempt_cluster", cluster, "ranked_cluster", expected)
		return "", false
	}

	model, ok := entry[attemptModelModel].(string)
	if !ok || model == "" {
		// A HOLE: a wildcard member, whose model is whatever the client asked for. Present
		// in the list purely to hold its position, and explicitly not a substitution.
		return "", false
	}
	return model, true
}

// substituteAttemptModel rewrites the payload's model to the one this attempt's target expects.
//
// This is what makes the feature a MODEL failover rather than a provider failover. Attempt 2
// reaches the fallback provider with the fallback's credential and in the fallback's wire format,
// but unless the payload also names that member's model it still asks for the primary's — which
// the fallback may not serve at all.
//
// Runs BEFORE the provider's transformer in the per-attempt chain, so the transformer translates
// a payload that already names the right model.
//
// Every unresolved case returns unchanged rather than erroring: an attempt whose target this
// policy never nominated (another routing policy's, or the original try) is not this policy's to
// rewrite.
func (p *Policy) substituteAttemptModel(reqCtx *policy.RequestContext, attempt int, cluster string) policy.RequestAction {
	model, ok := modelForAttempt(reqCtx.Metadata, attempt, cluster)
	if !ok {
		return policy.UpstreamRequestModifications{}
	}

	if reqCtx.Body == nil || !reqCtx.Body.Present || len(reqCtx.Body.Content) == 0 {
		return policy.UpstreamRequestModifications{}
	}

	var payload map[string]interface{}
	if err := json.Unmarshal(reqCtx.Body.Content, &payload); err != nil {
		// Not JSON, so there is no model field to substitute. Failover still works at the
		// transport level; only the model rewrite is skipped.
		return policy.UpstreamRequestModifications{}
	}
	if payload == nil {
		// `null` is valid JSON and unmarshals to a nil map. Assigning into it panics, so this
		// is the one unreadable body that must be rejected AFTER the unmarshal rather than by
		// its error. Same outcome as every other body with no writable model field.
		return policy.UpstreamRequestModifications{}
	}
	if existing, _ := payload["model"].(string); existing == model {
		return policy.UpstreamRequestModifications{}
	}

	payload["model"] = model
	rewritten, err := json.Marshal(payload)
	if err != nil {
		return policy.UpstreamRequestModifications{}
	}

	slog.Debug("ModelFailover: substituted model for attempt",
		"attempt", attempt, "cluster", cluster, "model", model)

	return policy.UpstreamRequestModifications{Body: rewritten}
}
