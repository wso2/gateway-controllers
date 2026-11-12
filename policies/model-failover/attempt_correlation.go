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

package modelfailover

import (
	"sync"
	"time"
)

// correlationTTL bounds how long a request's chain is remembered.
//
// An entry is written when the chain is published and read when the completion verdict arrives,
// which the gateway delivers off the access-log stream roughly a second after the request ends.
// Most entries are therefore never read at all — a request that completes normally produces no
// verdict — so nothing deletes on a "last" event, because there is no such event. The TTL is the
// only thing between this store and an unbounded leak, set well above any plausible route
// timeout plus the access-log flush interval.
const correlationTTL = 5 * time.Minute

// correlationSweepThreshold is the size at which a write sweeps expired entries.
//
// Swept on write rather than from a goroutine: a policy instance has no lifecycle hook to stop
// one, and the work is cheap and only matters when entries are actually accumulating.
const correlationSweepThreshold = 1024

// attemptCorrelation remembers, per request, which target each cluster was serving.
//
// It exists because a completion verdict names a CLUSTER, and a cluster does not identify a
// target. Health is keyed by {Model, Provider} and several models reach the same provider, so
// one cluster can serve several targets. Worse, reconstructing a target from a cluster would
// have to invent the Provider field, where "" legitimately means "the primary provider" — a
// reconstructed key would simply not match the configured one, and grading would silently do
// nothing at all.
//
// So the mapping is RECORDED while the request is in flight, where the resolved chain is known
// exactly, and read back when the verdict arrives.
type attemptCorrelation struct {
	mu      sync.Mutex
	entries map[string]correlationEntry
	// now is injectable so tests can drive expiry without sleeping.
	now func() time.Time
}

type correlationEntry struct {
	// byCluster maps the cluster serving a member to that member.
	byCluster map[string]Target
	expires   time.Time
}

func newAttemptCorrelation(now func() time.Time) *attemptCorrelation {
	if now == nil {
		now = time.Now
	}
	return &attemptCorrelation{
		entries: make(map[string]correlationEntry),
		now:     now,
	}
}

// Remember records the clusters this request's resolved chain can reach.
//
// A member whose provider has no cluster is skipped: no attempt can be routed to it, so no
// verdict can ever name it.
func (c *attemptCorrelation) Remember(requestID string, chain []Target, providerClusters map[string]string) {
	if c == nil || requestID == "" || len(chain) == 0 {
		return
	}

	byCluster := make(map[string]Target, len(chain))
	for _, target := range chain {
		cluster, ok := providerClusters[target.Provider]
		if !ok || cluster == "" {
			continue
		}
		// First member wins for a shared cluster. Two members on one provider differ only by
		// model, and the verdict cannot tell them apart — so grading the one the chain would
		// have reached FIRST is the only defensible choice, and matches the attempt order.
		if _, seen := byCluster[cluster]; seen {
			continue
		}
		byCluster[cluster] = target
	}
	if len(byCluster) == 0 {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.entries) >= correlationSweepThreshold {
		c.sweepLocked()
	}
	c.entries[requestID] = correlationEntry{
		byCluster: byCluster,
		expires:   c.now().Add(correlationTTL),
	}
}

// Lookup returns the target the given cluster was serving for this request.
func (c *attemptCorrelation) Lookup(requestID, cluster string) (Target, bool) {
	if c == nil || requestID == "" || cluster == "" {
		return Target{}, false
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	entry, ok := c.entries[requestID]
	if !ok || !c.now().Before(entry.expires) {
		return Target{}, false
	}
	target, ok := entry.byCluster[cluster]
	return target, ok
}

// Forget drops a request's entry.
//
// Called once a verdict has been graded: a request produces at most one, so keeping the entry
// afterwards only delays the TTL doing the same job. Not relied upon for correctness — the vast
// majority of entries are never looked up and expire instead.
func (c *attemptCorrelation) Forget(requestID string) {
	if c == nil || requestID == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.entries, requestID)
}

func (c *attemptCorrelation) sweepLocked() {
	now := c.now()
	for id, entry := range c.entries {
		if !now.Before(entry.expires) {
			delete(c.entries, id)
		}
	}
}
