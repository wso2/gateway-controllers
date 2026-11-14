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
)

// attemptCluster reports the cluster this attempt targets, and whether the policy is running at
// the per-attempt position at all.
func attemptCluster(metadata map[string]interface{}) (string, bool) {
	if metadata == nil {
		return "", false
	}
	raw, ok := metadata[attemptMetadataNamespace]
	if !ok {
		return "", false
	}
	fields, ok := raw.(map[string]interface{})
	if !ok {
		return "", false
	}
	cluster, ok := fields[attemptMetadataCluster].(string)
	if !ok || cluster == "" {
		return "", false
	}
	return cluster, true
}

// modelForCluster reads back the model this request's ranking assigned to a given target.
//
// The ranking is read from the policy's own published metadata rather than recomputed, so the
// attempt uses the order that was actually installed in Envoy. Recomputing here would let health
// state that changed mid-request disagree with the groups the request is already routing through.
func modelForCluster(metadata map[string]interface{}, cluster string) (string, bool) {
	if metadata == nil {
		return "", false
	}
	namespace, ok := metadata[FailoverMetadataNamespace].(map[string]interface{})
	if !ok {
		return "", false
	}
	models, ok := namespace[attemptModelsKey].(map[string]interface{})
	if !ok {
		return "", false
	}
	model, ok := models[cluster].(string)
	if !ok || model == "" {
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
func (p *Policy) substituteAttemptModel(reqCtx *policy.RequestContext, cluster string) policy.RequestAction {
	model, ok := modelForCluster(reqCtx.Metadata, cluster)
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
		"cluster", cluster, "model", model)

	return policy.UpstreamRequestModifications{Body: rewritten}
}
