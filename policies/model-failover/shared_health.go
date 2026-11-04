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

import (
	"fmt"
	"sync"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

// One operation's health, shared by every chain this policy is attached to for that operation.
//
// WHY THIS EXISTS. The registry calls the factory once per chain entry — "the factory may
// return a new instance or a cached one, this is up to the policy implementation" — so the
// response chain and the fault chain each get their own *Policy. Without sharing, the fault
// chain's instance would own an EMPTY health store: it would grade every failing response into
// a store nothing reads, while the store that actually orders the chain learned nothing. The
// whole fault-path fix would be silently inert, which is worse than not having it.
//
// WHAT IS SHARED, AND WHAT IS NOT. Only the store. Each instance keeps its own parsed
// parameters, so nothing else crosses between chains.
//
// SCOPE IS UNCHANGED. The key is the attachment — this API, this route — so health remains
// per-operation exactly as before: one API's targets never affect another's, and two
// operations on the same API keep separate circuits.
var sharedHealth = struct {
	mu      sync.Mutex
	byRoute map[string]*sharedHealthEntry
}{byRoute: make(map[string]*sharedHealthEntry)}

type sharedHealthEntry struct {
	// suspensionKey is what the store was built with. A store captures its suspension
	// settings at construction, so reusing one after an operator changed them would silently
	// keep enforcing the old windows and thresholds — a redeploy that appeared to do nothing.
	suspensionKey string
	store         HealthStore
}

// healthStoreFor returns the store for this attachment, creating it on first use and REPLACING
// it when the suspension configuration has changed.
//
// Replacing rather than accumulating is what bounds this map: there is at most one entry per
// (API, route) for the life of the process, never one per redeploy. An entry for a route that
// is later deleted does linger — the SDK gives a policy no teardown hook to notice — but it is
// one small struct per distinct route ever deployed, not per request or per deployment.
func healthStoreFor(metadata policy.PolicyMetadata, suspension Suspension) HealthStore {
	key := metadata.APIId + "\x00" + metadata.RouteName
	fingerprint := fmt.Sprintf("%+v", suspension)

	sharedHealth.mu.Lock()
	defer sharedHealth.mu.Unlock()

	if entry, ok := sharedHealth.byRoute[key]; ok && entry.suspensionKey == fingerprint {
		return entry.store
	}
	entry := &sharedHealthEntry{suspensionKey: fingerprint, store: NewHealthStore(suspension)}
	sharedHealth.byRoute[key] = entry
	return entry.store
}

// sharedHealthTestKey builds the map key the way healthStoreFor does, for assertions.
func sharedHealthTestKey(apiID, route string) string { return apiID + "\x00" + route }
