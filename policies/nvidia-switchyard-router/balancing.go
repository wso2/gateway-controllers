/*
 *  Copyright (c) 2026, WSO2 LLC. (http://www.wso2.org) All Rights Reserved.
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
 *
 */

package nvidiaswitchyardrouter

import (
	"encoding/json"
	"hash/fnv"
	"strings"
	"sync/atomic"
)

// How a tier with several models chooses one.
const (
	// balancingFirst always uses the tier's first model; the others are spares
	// for the operator to promote.
	balancingFirst = "first"
	// balancingRoundRobin rotates through the tier's models in proportion to
	// their weights.
	balancingRoundRobin = "round_robin"
	// balancingSession keeps each session on one model of the tier, chosen in
	// proportion to the weights, so a provider's prompt cache stays warm.
	// Requests without a session ID rotate as with round_robin.
	balancingSession = "session_affinity"

	defaultWeight = 1
	maxWeight     = 100
)

// tierPool is the models of one tier and the rotation state shared by all
// requests the policy instance handles.
type tierPool struct {
	models []poolEntry
	total  uint64
	next   atomic.Uint64
}

func (t *tierPool) add(entry poolEntry) {
	t.models = append(t.models, entry)
	t.total += uint64(entry.Weight)
}

// pick chooses a model of the tier. sessionID is used by session_affinity.
func (t *tierPool) pick(balancing, sessionID string) poolEntry {
	if len(t.models) == 1 || balancing == balancingFirst {
		return t.models[0]
	}
	var n uint64
	if balancing == balancingSession && sessionID != "" {
		h := fnv.New64a()
		h.Write([]byte(sessionID))
		n = h.Sum64()
	} else {
		n = t.next.Add(1) - 1
	}
	return t.at(n % t.total)
}

// at returns the model whose share of the total weight contains slot.
func (t *tierPool) at(slot uint64) poolEntry {
	for _, entry := range t.models {
		if slot < uint64(entry.Weight) {
			return entry
		}
		slot -= uint64(entry.Weight)
	}
	return t.models[len(t.models)-1]
}

// sessionKey is the session ID switchyard-server will take from the
// forwarded headers, following its precedence order (switchyard-protocol
// 0.3.0, metadata.rs), or empty when there is none.
func sessionKey(headers map[string]string) string {
	for _, name := range []string{"x-switchyard-session-id", "x-claude-code-session-id", "x-nemo-relay-session-id", "x-session-id"} {
		if id := headers[name]; id != "" {
			return id
		}
	}
	var codex struct {
		SessionID string `json:"session_id"`
	}
	if raw := headers["x-codex-turn-metadata"]; raw != "" && json.Unmarshal([]byte(raw), &codex) == nil {
		if id := strings.TrimSpace(codex.SessionID); id != "" {
			return id
		}
	}
	return headers["session-id"]
}
