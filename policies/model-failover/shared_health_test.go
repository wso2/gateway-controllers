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
	"testing"
	"time"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

func attachment(apiID, route string) policy.PolicyMetadata {
	return policy.PolicyMetadata{APIId: apiID, RouteName: route}
}

func chainParams() map[string]interface{} {
	return map[string]interface{}{
		"suspendAfterFailures": 1,
		"suspendDuration":      300,
		"targets": []interface{}{map[string]interface{}{
			"model": "gpt-4o",
			"fallbacks": []interface{}{
				map[string]interface{}{"model": "claude-sonnet-4-5", "provider": "anthropic"},
			},
		}},
	}
}

// THE reason shared_health.go exists. The registry calls the factory once per CHAIN entry, so
// the response chain and the fault chain get different *Policy values for one operation. If
// they did not share a store, the fault chain would grade into a store nothing reads and the
// whole fault-path fix would be silently inert.
func TestSharedHealth_BothChainsOfOneOperationSeeTheSameHealth(t *testing.T) {
	responseChain, err := GetPolicy(attachment("api-1", "route-1"), chainParams())
	if err != nil {
		t.Fatalf("factory: %v", err)
	}
	faultChain, err := GetPolicy(attachment("api-1", "route-1"), chainParams())
	if err != nil {
		t.Fatalf("factory: %v", err)
	}
	a, b := responseChain.(*Policy), faultChain.(*Policy)
	if a == b {
		t.Fatal("the factory returned one instance; this test is no longer exercising what it claims")
	}

	now := time.Now()
	a.health.RecordFailure(Target{Model: "gpt-4o"}, 0, now)

	if b.health.Healthy(Target{Model: "gpt-4o"}, now) {
		t.Fatal("a failure recorded by one chain is invisible to the other, so grading on the fault path would change nothing")
	}
}

// Health is per-operation and must stay that way: one API's outage must not suspend another's
// targets, and two operations on the same API keep separate circuits.
func TestSharedHealth_IsScopedToTheAttachment(t *testing.T) {
	now := time.Now()
	for _, other := range []policy.PolicyMetadata{
		attachment("api-2", "route-1"), // different API, same route name
		attachment("api-1", "route-2"), // same API, different route
	} {
		mine, _ := GetPolicy(attachment("api-1", "route-1"), chainParams())
		theirs, _ := GetPolicy(other, chainParams())
		mine.(*Policy).health.RecordFailure(Target{Model: "gpt-4o"}, 0, now)

		if !theirs.(*Policy).health.Healthy(Target{Model: "gpt-4o"}, now) {
			t.Fatalf("health leaked to %+v — one operation's outage suspended another's target", other)
		}
	}
}

// A store captures its suspension settings at construction. Reusing one after an operator
// changed them would keep enforcing the old windows and thresholds, so a redeploy would appear
// to do nothing.
func TestSharedHealth_ConfigChangeReplacesTheStore(t *testing.T) {
	meta := attachment("api-cfg", "route-1")
	first, _ := GetPolicy(meta, chainParams())
	first.(*Policy).health.RecordFailure(Target{Model: "gpt-4o"}, 0, time.Now())

	changed := chainParams()
	changed["suspendDuration"] = 900

	second, _ := GetPolicy(meta, changed)
	if !second.(*Policy).health.Healthy(Target{Model: "gpt-4o"}, time.Now()) {
		t.Fatal("the store survived a suspension-config change, so the new settings are not in force")
	}

	// ...and replaced, not accumulated: one entry per attachment, however many redeploys.
	sharedHealth.mu.Lock()
	defer sharedHealth.mu.Unlock()
	if _, ok := sharedHealth.byRoute[sharedHealthTestKey("api-cfg", "route-1")]; !ok {
		t.Fatal("no entry for the attachment")
	}
	count := 0
	for key := range sharedHealth.byRoute {
		if key == sharedHealthTestKey("api-cfg", "route-1") {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("%d entries for one attachment, want 1 — the map grows per redeploy", count)
	}
}

// A redeploy that repoints an alias at a different cluster must NOT inherit the previous store.
//
// Suspension settings alone cannot identify a store. With the same settings and a changed
// topology, the old store came back — so a (model, provider) target suspended on the strength of
// the OLD cluster's failures kept a healthy new upstream out of rotation until that window
// expired, which is a suspension the new cluster never earned.
func TestSharedStoresFor_ReplacedWhenTheProviderTopologyChanges(t *testing.T) {
	meta := policy.PolicyMetadata{APIId: "api-1", RouteName: "route-1"}
	susp := testSuspension()

	first, _ := sharedStoresFor(meta, susp, map[string]string{"anthropic": "cluster_old"})
	again, _ := sharedStoresFor(meta, susp, map[string]string{"anthropic": "cluster_old"})
	if first != again {
		t.Fatal("same settings and same topology must reuse the store, or every request rebuilds health")
	}

	repointed, _ := sharedStoresFor(meta, susp, map[string]string{"anthropic": "cluster_new"})
	if repointed == first {
		t.Fatal("the alias was repointed at a different cluster and the old store came back; " +
			"its suspensions would exclude an upstream that never earned them")
	}
}

// The fingerprint must not depend on map iteration order, or the stores are replaced on every
// call and health never accumulates.
func TestTopologyFingerprint_IsStableAcrossIterationOrder(t *testing.T) {
	m := map[string]string{"a": "1", "b": "2", "c": "3", "d": "4", "e": "5"}
	want := topologyFingerprint(m)
	for i := 0; i < 50; i++ {
		if got := topologyFingerprint(map[string]string{"e": "5", "c": "3", "a": "1", "d": "4", "b": "2"}); got != want {
			t.Fatalf("fingerprint varies with iteration order: %q vs %q", got, want)
		}
	}
}
