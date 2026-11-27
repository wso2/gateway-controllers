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
	"log/slog"
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

// correlationSweepInterval is the shortest gap between two sweeps, whatever the size.
//
// A fraction of correlationTTL: long enough that steady traffic pays for the scan rarely rather
// than on every write, short enough that expired entries cannot accumulate for a meaningful part
// of their lifetime before being reclaimed.
const correlationSweepInterval = 30 * time.Second

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
	// lastSweep bounds how often a write pays for the scan. Without it, a store that stays
	// above the size threshold sweeps on EVERY write, and because entries live for
	// correlationTTL a busy route keeps it above the threshold indefinitely — so steady
	// traffic rescans the same mostly-live entries, turning an O(1) write into O(n).
	lastSweep time.Time
	// now is injectable so tests can drive expiry without sleeping.
	now func() time.Time
}

type correlationEntry struct {
	// chain is this request's published members IN ORDER, so a verdict carrying an attempt
	// count can name exactly one of them. This is the primary index: attempt N is member N.
	chain []correlatedTarget

	// byCluster maps the cluster serving a member to that member, FIRST MEMBER WINS.
	//
	// Kept only for a verdict that carries no attempt identity -- a gateway too old to report
	// the count, or a request that never reached an upstream at all. It cannot be the primary
	// index because a cluster names a PROVIDER: two members on one vendor differ only by model
	// and collapse onto one key here, so a failure on the later one is charged to the earlier,
	// which may never have been contacted.
	byCluster map[string]correlatedTarget
	expires   time.Time
}

// correlatedTarget is a chain member together with the probe receipt it was admitted on.
//
// The receipt travels with the target because a completion verdict is graded through
// HealthStore.RecordFailure, and that call needs to know which reservation the attempt ran
// against: a streamed probe is credited optimistically at the response phase, and only a
// verdict naming the SAME reservation may take that credit back.
type correlatedTarget struct {
	Target    Target
	Admission Admission

	// Cluster is the cluster this member was published against. Carried so a positional
	// lookup can CHECK itself against the cluster the verdict names, rather than trusting the
	// index blindly.
	Cluster string
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

// Remember records this request's resolved chain, in order, with the cluster serving each member.
//
// A member whose provider has no cluster is skipped: no attempt can be routed to it, so no
// verdict can ever name it. Skipping keeps this list in step with the published priority groups,
// which drop the same members by the same predicate — the ordering is only an index if the two
// agree about which members exist.
func (c *attemptCorrelation) Remember(requestID string, chain []Target, admissions []Admission,
	providerClusters map[string]string) {

	if c == nil || requestID == "" || len(chain) == 0 {
		return
	}

	ordered := make([]correlatedTarget, 0, len(chain))
	byCluster := make(map[string]correlatedTarget, len(chain))
	for i, target := range chain {
		cluster, ok := servableCluster(providerClusters, target.Provider)
		if !ok {
			continue
		}
		correlated := correlatedTarget{
			Target:    target,
			Admission: admissionAt(admissions, i),
			Cluster:   cluster,
		}
		ordered = append(ordered, correlated)
		// First member wins in the FALLBACK index only. Two members on one provider differ
		// only by model, so a verdict with no attempt identity cannot tell them apart —
		// grading the one the chain would have reached first is the only defensible guess,
		// and it matches the attempt order. A verdict that DOES carry an identity never
		// reaches this map.
		if _, seen := byCluster[cluster]; !seen {
			byCluster[cluster] = correlated
		}
	}
	if len(ordered) == 0 {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	// Size says a sweep MIGHT be worth it; the interval says it is not worth it yet. An
	// expired entry costs only memory until the next sweep, and the TTL already bounds how
	// much.
	if now := c.now(); len(c.entries) >= correlationSweepThreshold &&
		now.Sub(c.lastSweep) >= correlationSweepInterval {
		c.sweepLocked()
		c.lastSweep = now
	}
	c.entries[requestID] = correlationEntry{
		chain:     ordered,
		byCluster: byCluster,
		expires:   c.now().Add(correlationTTL),
	}
}

// Lookup returns the chain member this verdict describes, with the probe receipt the attempt was
// admitted on.
//
// attempt is Envoy's 1-based upstream attempt count, and selecting by it is what makes this
// correct for a chain whose members share a provider. The cluster alone names a PROVIDER: for
// [claude/sonnet, gemini, claude/opus], a truncation on opus and one on sonnet arrive with the
// same cluster, and charging opus's failure to sonnet suspends a model that was never contacted
// while the one that actually failed keeps its clean window and all the traffic.
//
// Why the count is enough to index with: the gateway stops retrying the instant an attempt
// commits its response, so a post-commitment verdict always describes the LAST attempt — which
// makes the total count that member's position. The in-flight response phase already grades on
// exactly this correspondence.
//
// attempt == 0 means the verdict carries no identity: the request never reached an upstream, or
// an older gateway is paired with this policy. That falls back to the cluster-keyed guess, which
// is what this store did before the count was available.
func (c *attemptCorrelation) Lookup(requestID, cluster string, attempt uint32) (correlatedTarget, bool) {
	if c == nil || requestID == "" || cluster == "" {
		return correlatedTarget{}, false
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	entry, ok := c.entries[requestID]
	if !ok || !c.now().Before(entry.expires) {
		return correlatedTarget{}, false
	}

	if attempt >= 1 && int(attempt) <= len(entry.chain) {
		candidate := entry.chain[attempt-1]
		if candidate.Cluster == cluster {
			return candidate, true
		}
		// The position and the verdict disagree about which target this was, so the
		// correspondence this index rests on has broken. Fall back rather than decline: the
		// cluster is Envoy's own account of what served the attempt, so the fallback still
		// grades a member genuinely on that provider — a worse answer than the index, never
		// a worse one than recording nothing.
		slog.Warn("ModelFailover: attempt position disagrees with the cluster the verdict "+
			"names, so this failure is graded by cluster instead",
			"request_id", requestID, "attempt", attempt,
			"verdict_cluster", cluster, "ranked_cluster", candidate.Cluster)
	}

	correlated, ok := entry.byCluster[cluster]
	return correlated, ok
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
