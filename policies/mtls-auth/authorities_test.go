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
package mtlsauth

import (
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

// countingBuild wraps buildAuthoritySet, counting calls.
func countingBuild(calls *atomic.Int32) func(map[string]*policy.LazyResource, uint64) *authoritySet {
	return func(resources map[string]*policy.LazyResource, version uint64) *authoritySet {
		calls.Add(1)
		return buildAuthoritySet(resources, version)
	}
}

// readConcurrently calls cache.get from n goroutines released together, and
// returns every set they got.
func readConcurrently(cache *authorityCache, n int) []*authoritySet {
	var start, done sync.WaitGroup
	start.Add(1)
	sets := make([]*authoritySet, n)
	for i := 0; i < n; i++ {
		done.Add(1)
		go func(i int) {
			defer done.Done()
			start.Wait()
			sets[i] = cache.get()
		}(i)
	}
	start.Done()
	done.Wait()
	return sets
}

func TestAuthorityCache_RebuildsOncePerStoreVersionUnderConcurrentReads(t *testing.T) {
	rootA := newRootCA(t, "Partner A Root CA")
	store := policy.NewLazyResourceStore()
	var builds atomic.Int32
	cache := newAuthorityCache(store, countingBuild(&builds))

	for snapshot := 1; snapshot <= 3; snapshot++ {
		if err := store.ReplaceAll([]*policy.LazyResource{
			authorityResource(authoritySpec{name: "partner-a", role: roleClient, certs: []*testEntity{rootA}}),
		}); err != nil {
			t.Fatal(err)
		}
		for _, set := range readConcurrently(cache, 64) {
			if set == nil {
				t.Fatal("get() returned no set")
			}
			if _, ok := set.clients["partner-a"]; !ok {
				t.Fatalf("get() returned a set without partner-a: %+v", set)
			}
		}
		if got := cache.get().version; got != store.Version() {
			t.Fatalf("after snapshot %d the cache holds version %d, want %d", snapshot, got, store.Version())
		}
		if got := builds.Load(); got != int32(snapshot) {
			t.Fatalf("after snapshot %d the set was built %d times, want %d (once per store version)", snapshot, got, snapshot)
		}
	}

	for i := 0; i < 10; i++ {
		cache.get()
	}
	if got := builds.Load(); got != 3 {
		t.Fatalf("reads with no new snapshot rebuilt the set: %d builds, want 3", got)
	}
}

func TestAuthorityCache_ReadersDuringRebuildUseThePreviousCompleteSet(t *testing.T) {
	rootA := newRootCA(t, "Partner A Root CA")
	rootB := newRootCA(t, "Partner B Root CA")
	store := policy.NewLazyResourceStore()

	started := make(chan struct{})
	release := make(chan struct{})
	var blockNext atomic.Bool
	cache := newAuthorityCache(store, func(resources map[string]*policy.LazyResource, version uint64) *authoritySet {
		if blockNext.CompareAndSwap(true, false) {
			close(started)
			<-release
		}
		return buildAuthoritySet(resources, version)
	})

	publish := func(specs ...authoritySpec) {
		t.Helper()
		resources := make([]*policy.LazyResource, len(specs))
		for i, spec := range specs {
			resources[i] = authorityResource(spec)
		}
		if err := store.ReplaceAll(resources); err != nil {
			t.Fatal(err)
		}
	}

	publish(authoritySpec{name: "partner-a", role: roleClient, certs: []*testEntity{rootA}})
	previous := cache.get()

	publish(
		authoritySpec{name: "partner-a", role: roleClient, certs: []*testEntity{rootA}},
		authoritySpec{name: "partner-b", role: roleClient, certs: []*testEntity{rootB}},
	)
	blockNext.Store(true)
	rebuilt := make(chan *authoritySet)
	go func() { rebuilt <- cache.get() }()
	<-started

	// The rebuild is parked mid-build: every other reader gets the previous,
	// complete set straight away rather than waiting or seeing a partial one.
	for i := 0; i < 16; i++ {
		got := cache.get()
		if got != previous {
			t.Fatalf("a reader during the rebuild got %p (version %d), want the previous set %p (version %d)", got, got.version, previous, previous.version)
		}
		if _, ok := got.clients["partner-a"]; !ok || len(got.clients) != 1 {
			t.Fatalf("the previous set is not intact: %v", got.clients)
		}
	}

	close(release)
	next := <-rebuilt
	if next.version != store.Version() || len(next.clients) != 2 {
		t.Fatalf("the rebuilt set has version %d and %d clients, want version %d and 2 clients", next.version, len(next.clients), store.Version())
	}
	if got := cache.get(); got != next {
		t.Fatalf("after the rebuild readers get %p, want the new set %p", got, next)
	}
}

func TestAuthorityCache_FirstReadersWaitForTheFirstSet(t *testing.T) {
	store := policy.NewLazyResourceStore()
	var builds atomic.Int32
	build := countingBuild(&builds)
	cache := newAuthorityCache(store, func(resources map[string]*policy.LazyResource, version uint64) *authoritySet {
		time.Sleep(20 * time.Millisecond) // widen the window in which other first readers arrive
		return build(resources, version)
	})

	sets := readConcurrently(cache, 32)
	for _, set := range sets {
		if set == nil || set != sets[0] {
			t.Fatalf("first readers got different sets (%p vs %p); all must wait for and share the first build", set, sets[0])
		}
	}
	if got := builds.Load(); got != 1 {
		t.Fatalf("the first set was built %d times, want 1", got)
	}
}

func TestBuildAuthoritySet_SkipsAnUnreadableEntryAndKeepsTheRest(t *testing.T) {
	rootA := newRootCA(t, "Partner A Root CA")
	relayCA := newRootCA(t, "Edge LB CA")
	resources := map[string]*policy.LazyResource{
		"partner-a": authorityResource(authoritySpec{name: "partner-a", role: roleClient, certs: []*testEntity{rootA}}),
		"edge-lb":   authorityResource(authoritySpec{name: "edge-lb", role: roleRelay, certs: []*testEntity{relayCA}, dnsSANs: []string{"lb.internal"}}),
		"not-pem": {ID: "not-pem", ResourceType: clientAuthorityResourceType, Resource: map[string]interface{}{
			"role": roleClient, "certificates": []interface{}{"not a PEM certificate"},
		}},
		"no-certificates": {ID: "no-certificates", ResourceType: clientAuthorityResourceType, Resource: map[string]interface{}{
			"role": roleClient, "certificates": []interface{}{},
		}},
		"unknown-role": {ID: "unknown-role", ResourceType: clientAuthorityResourceType, Resource: map[string]interface{}{
			"role": "admin", "certificates": entitiesToPEMInterfaces([]*testEntity{rootA}),
		}},
		"bad-match": {ID: "bad-match", ResourceType: clientAuthorityResourceType, Resource: map[string]interface{}{
			"role": roleRelay, "certificates": entitiesToPEMInterfaces([]*testEntity{relayCA}),
			"match": map[string]interface{}{"uriSANs": "spiffe://scalar"},
		}},
	}

	var set *authoritySet
	output := captureSlog(t, func() { set = buildAuthoritySet(resources, 7) })

	if set.version != 7 {
		t.Errorf("version = %d, want 7", set.version)
	}
	if len(set.clients) != 1 || set.clients["partner-a"] == nil {
		t.Errorf("clients = %v, want only partner-a", set.clients)
	}
	if len(set.relays) != 1 || set.relays[0].name != "edge-lb" || !slicesEqual(set.relays[0].dnsSANs, []string{"lb.internal"}) {
		t.Errorf("relays = %+v, want only edge-lb narrowed to lb.internal", set.relays)
	}
	if len(set.inherited) != 1 || set.inherited[0].ca != "partner-a" {
		t.Errorf("inherited = %+v, want only partner-a", set.inherited)
	}
	for _, name := range []string{"not-pem", "no-certificates", "unknown-role", "bad-match"} {
		if !strings.Contains(output, "ca="+name) {
			t.Errorf("expected a warning naming the unreadable entry %q, got:\n%s", name, output)
		}
	}
	if strings.Contains(output, "BEGIN CERTIFICATE") {
		t.Errorf("a warning carried certificate material:\n%s", output)
	}
}

func slicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestMtlsAuthPolicy_AcceptNameAbsentFromThePoolDenies(t *testing.T) {
	rootA := newRootCA(t, "Partner A Root CA")
	rootB := newRootCA(t, "Partner B Root CA")
	clientA := newLeaf(t, rootA, "client-a", certOpts{})

	// The chain names partner-a but the pool holds only partner-b, as when a
	// chain reaches the engine ahead of its pool entry.
	publishAuthorities(t, authoritySpec{name: "partner-b", role: roleClient, certs: []*testEntity{rootB}})
	p := mustPolicy(t, buildParams([]entrySpec{{ca: "partner-a"}}))

	output := captureSlog(t, func() {
		assertDenied(t, p, reqCtxWithTLS(downstreamTLSFromLeaf(clientA, true)), reasonAuthorityNotAccepted)
		assertDenied(t, p, reqCtxWithTLS(downstreamTLSFromLeaf(clientA, true)), reasonAuthorityNotAccepted)
	})
	if got := strings.Count(output, "none of the client certificate authorities this API accepts"); got != 1 {
		t.Fatalf("drift WARN logged %d times across repeated requests on one pool version, want 1:\n%s", got, output)
	}
	if !strings.Contains(output, "level=WARN") || !strings.Contains(output, "accept=partner-a") {
		t.Fatalf("expected a WARN naming the accept list, got:\n%s", output)
	}

	// The next snapshot is a new version: the drift is reported again once.
	publishAuthorities(t, authoritySpec{name: "partner-b", role: roleClient, certs: []*testEntity{rootB}})
	output = captureSlog(t, func() {
		assertDenied(t, p, reqCtxWithTLS(downstreamTLSFromLeaf(clientA, true)), reasonAuthorityNotAccepted)
		assertDenied(t, p, reqCtxWithTLS(downstreamTLSFromLeaf(clientA, true)), reasonAuthorityNotAccepted)
	})
	if got := strings.Count(output, "none of the client certificate authorities this API accepts"); got != 1 {
		t.Fatalf("drift WARN logged %d times on the next pool version, want 1:\n%s", got, output)
	}

	// Once the pool holds partner-a, the same bound instance allows.
	publishAuthorities(t, authoritySpec{name: "partner-a", role: roleClient, certs: []*testEntity{rootA}})
	assertAuthenticated(t, p, reqCtxWithTLS(downstreamTLSFromLeaf(clientA, true)), 0)
}

func TestMtlsAuthPolicy_AbsentAcceptEntryIsSkippedWhileOthersMatch(t *testing.T) {
	rootA := newRootCA(t, "Partner A Root CA")
	clientA := newLeaf(t, rootA, "client-a", certOpts{})
	publishAuthorities(t, authoritySpec{name: "partner-a", role: roleClient, certs: []*testEntity{rootA}})
	p := mustPolicy(t, buildParams([]entrySpec{{ca: "removed-partner"}, {ca: "partner-a"}}))

	output := captureSlog(t, func() {
		result := assertAuthenticated(t, p, reqCtxWithTLS(downstreamTLSFromLeaf(clientA, true)), 1)
		if result.issuerCA != "partner-a" {
			t.Errorf("issuerCA = %q, want partner-a", result.issuerCA)
		}
	})
	if strings.Contains(output, "none of the client certificate authorities") {
		t.Fatalf("no drift WARN is due while another accepted entry is in the pool:\n%s", output)
	}
}

func TestMtlsAuthPolicy_NamedRelayEntryIsNeverAcceptedAsAClient(t *testing.T) {
	relayCA := newRootCA(t, "Edge LB CA")
	edgeLB := newLeaf(t, relayCA, "edge-lb", certOpts{})
	publishAuthorities(t, authoritySpec{name: "edge-lb-ca", role: roleRelay, certs: []*testEntity{relayCA}})
	p := mustPolicy(t, buildParams([]entrySpec{{ca: "edge-lb-ca"}}))

	assertDenied(t, p, reqCtxWithTLS(downstreamTLSFromLeaf(edgeLB, true)), reasonAuthorityNotAccepted)
}

func TestMtlsAuthPolicy_OmittedAcceptResolvesToThePoolsClientEntries(t *testing.T) {
	rootA := newRootCA(t, "Partner A Root CA")
	rootB := newRootCA(t, "Partner B Root CA")
	relayCA := newRootCA(t, "Edge LB CA")
	clientA := newLeaf(t, rootA, "client-a", certOpts{})
	clientB := newLeaf(t, rootB, "client-b", certOpts{})
	edgeLB := newLeaf(t, relayCA, "edge-lb", certOpts{})

	publishAuthorities(t,
		authoritySpec{name: "b-partner", role: roleClient, certs: []*testEntity{rootB}},
		authoritySpec{name: "a-partner", role: roleClient, certs: []*testEntity{rootA}},
		authoritySpec{name: "edge-lb-ca", role: roleRelay, certs: []*testEntity{relayCA}},
	)
	p := mustPolicy(t, nil) // no accept param at all: the author omitted accept

	if result := assertAuthenticated(t, p, reqCtxWithTLS(downstreamTLSFromLeaf(clientA, true)), 0); result.issuerCA != "a-partner" {
		t.Errorf("issuerCA = %q, want a-partner (entries resolve in name order)", result.issuerCA)
	}
	if result := assertAuthenticated(t, p, reqCtxWithTLS(downstreamTLSFromLeaf(clientB, true)), 1); result.issuerCA != "b-partner" {
		t.Errorf("issuerCA = %q, want b-partner", result.issuerCA)
	}
	assertDenied(t, p, reqCtxWithTLS(downstreamTLSFromLeaf(edgeLB, true)), reasonAuthorityNotAccepted)

	// A pool change reaches the bound instance on its next request.
	publishAuthorities(t,
		authoritySpec{name: "a-partner", role: roleClient, certs: []*testEntity{rootA}},
		authoritySpec{name: "edge-lb-ca", role: roleRelay, certs: []*testEntity{relayCA}},
	)
	assertDenied(t, p, reqCtxWithTLS(downstreamTLSFromLeaf(clientB, true)), reasonAuthorityNotAccepted)
}

func TestMtlsAuthPolicy_EmptyAcceptIsNotInheritance(t *testing.T) {
	rootA := newRootCA(t, "Partner A Root CA")
	clientA := newLeaf(t, rootA, "client-a", certOpts{})
	publishAuthorities(t, authoritySpec{name: "partner-a", role: roleClient, certs: []*testEntity{rootA}})
	p := mustPolicy(t, buildParams(nil)) // accept present, but empty

	assertDenied(t, p, reqCtxWithTLS(downstreamTLSFromLeaf(clientA, true)), reasonAuthorityNotAccepted)
}

func TestMtlsAuthPolicy_UnreadablePoolEntryDoesNotPoisonThePool(t *testing.T) {
	rootA := newRootCA(t, "Partner A Root CA")
	clientA := newLeaf(t, rootA, "client-a", certOpts{})
	publishResources(t,
		authorityResource(authoritySpec{name: "partner-a", role: roleClient, certs: []*testEntity{rootA}}),
		&policy.LazyResource{ID: "corrupt", ResourceType: clientAuthorityResourceType, Resource: map[string]interface{}{
			"role": roleClient, "certificates": []interface{}{"not a PEM certificate"},
		}},
	)
	accepted := mustPolicy(t, buildParams([]entrySpec{{ca: "partner-a"}}))
	corrupt := mustPolicy(t, buildParams([]entrySpec{{ca: "corrupt"}}))

	output := captureSlog(t, func() {
		for i := 0; i < 3; i++ {
			assertAuthenticated(t, accepted, reqCtxWithTLS(downstreamTLSFromLeaf(clientA, true)), 0)
			assertDenied(t, corrupt, reqCtxWithTLS(downstreamTLSFromLeaf(clientA, true)), reasonAuthorityNotAccepted)
		}
	})
	if got := strings.Count(output, "could not be read"); got != 1 {
		t.Fatalf("the unreadable entry was reported %d times on one pool version, want 1:\n%s", got, output)
	}
}

func TestMtlsAuthPolicy_ConcurrentRequestsAcrossSnapshots(t *testing.T) {
	rootA := newRootCA(t, "Partner A Root CA")
	relayCA := newRootCA(t, "Edge LB CA")
	clientA := newLeaf(t, rootA, "client-a", certOpts{})
	edgeLB := newLeaf(t, relayCA, "edge-lb", certOpts{})
	pool := []authoritySpec{
		{name: "partner-a", role: roleClient, certs: []*testEntity{rootA}},
		{name: "edge-lb-ca", role: roleRelay, certs: []*testEntity{relayCA}},
	}
	publishAuthorities(t, pool...)
	p := mustPolicy(t, buildParams([]entrySpec{{ca: "partner-a"}}))
	// Load this pool before the requests start, so a reader served the previous
	// set during a rebuild gets this pool, not an earlier test's.
	clientAuthorities.get()

	var wg sync.WaitGroup
	stop := make(chan struct{})
	failures := make(chan string, 64)
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(relayed bool) {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				reqCtx := reqCtxWithTLS(downstreamTLSFromLeaf(clientA, true))
				if relayed {
					reqCtx = reqCtxWithTLSAndHeader(downstreamTLSFromLeaf(edgeLB, true), defaultHeaderName, urlEncodedPEMHeaderValue(clientA))
				}
				if result := p.evaluate(reqCtx, nil); !result.authenticated {
					select {
					case failures <- result.reason:
					default:
					}
				}
			}
		}(i%2 == 1)
	}

	// Snapshots carrying the same pool keep arriving while requests run.
	for i := 0; i < 50; i++ {
		publishAuthorities(t, pool...)
	}
	close(stop)
	wg.Wait()
	close(failures)
	for reason := range failures {
		t.Errorf("a request was denied (%s) while snapshots of an unchanged pool arrived", reason)
	}
}
