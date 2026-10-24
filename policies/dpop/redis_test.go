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

package dpop

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/redis/go-redis/v9"
	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

// fakeRedis implements the one command the replay store uses, SET NX with an
// expiry, with Redis's semantics: the first SET of a key wins, later ones report
// false. down makes every command fail as an unreachable server would.
type fakeRedis struct {
	mu   sync.Mutex
	ttls map[string]time.Duration
	down bool
}

// newFakeRedis returns an empty, reachable fake.
func newFakeRedis() *fakeRedis { return &fakeRedis{ttls: map[string]time.Duration{}} }

// SetNX stores key if absent, recording its TTL, as SET key value NX PX ttl does.
func (f *fakeRedis) SetNX(_ context.Context, key string, _ interface{}, ttl time.Duration) *redis.BoolCmd {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.down {
		return redis.NewBoolResult(false, errors.New("dial tcp: connection refused"))
	}
	if _, ok := f.ttls[key]; ok {
		return redis.NewBoolResult(false, nil)
	}
	f.ttls[key] = ttl
	return redis.NewBoolResult(true, nil)
}

// replicaWithRedis is one gateway replica: its own memory store, a shared Redis.
func replicaWithRedis(t *testing.T, r setNXer, failureMode string) *DPoPPolicy {
	t.Helper()
	p := newTestPolicy(t, nil)
	p.replay = &redisReplayStore{client: r, prefix: "dpop:v0:", failureMode: failureMode, local: newReplayStore(1000)}
	return p
}

// TestRedisReplayAcrossReplicas refuses on one replica a proof another replica accepted.
func TestRedisReplayAcrossReplicas(t *testing.T) {
	r := newFakeRedis()
	a, b := replicaWithRedis(t, r, redisFailureClosed), replicaWithRedis(t, r, redisFailureClosed)
	key := newKey(t, "ES256")
	proof := key.sign(t, nil)
	expectAllowed(t, run(a, dpopRequest(key, proof)))
	// The same proof sent to another replica is a replay.
	expectRejected(t, run(b, dpopRequest(key, proof)), "invalid_dpop_proof")

	// Exactly one key, prefixed, expiring with the proof (iat + proofMaxAge + clockSkew).
	if len(r.ttls) != 1 {
		t.Fatalf("Redis holds %d keys, want 1", len(r.ttls))
	}
	for k, ttl := range r.ttls {
		if !strings.HasPrefix(k, "dpop:v0:") {
			t.Errorf("key %q lacks the prefix", k)
		}
		if ttl != 90*time.Second {
			t.Errorf("key TTL = %v, want 90s", ttl)
		}
	}
}

// TestRedisConcurrentReplayAcrossReplicas accepts exactly one copy of a proof sent to several replicas at once.
func TestRedisConcurrentReplayAcrossReplicas(t *testing.T) {
	r := newFakeRedis()
	replicas := []*DPoPPolicy{replicaWithRedis(t, r, redisFailureClosed), replicaWithRedis(t, r, redisFailureClosed), replicaWithRedis(t, r, redisFailureClosed)}
	key := newKey(t, "ES256")
	proof := key.sign(t, nil)
	var wg sync.WaitGroup
	var mu sync.Mutex
	accepted := 0
	for i := 0; i < 30; i++ {
		wg.Add(1)
		go func(p *DPoPPolicy) {
			defer wg.Done()
			if _, ok := run(p, dpopRequest(key, proof)).(policy.UpstreamRequestHeaderModifications); ok {
				mu.Lock()
				accepted++
				mu.Unlock()
			}
		}(replicas[i%len(replicas)])
	}
	wg.Wait()
	if accepted != 1 {
		t.Fatalf("accepted %d copies of one proof across replicas, want 1", accepted)
	}
}

// TestRedisUnavailableFailsClosed answers 503 while Redis is down in closed mode.
func TestRedisUnavailableFailsClosed(t *testing.T) {
	r := newFakeRedis()
	r.down = true
	p := replicaWithRedis(t, r, redisFailureClosed)
	key := newKey(t, "ES256")
	resp, ok := run(p, dpopRequest(key, key.sign(t, nil))).(policy.ImmediateResponse)
	if !ok || resp.StatusCode != 503 {
		t.Fatalf("Redis down, failureMode closed: got %+v, want 503", resp)
	}
}

// TestRedisUnavailableFallsBackToLocal keeps serving, and refusing replays, while Redis is down in local mode.
func TestRedisUnavailableFallsBackToLocal(t *testing.T) {
	r := newFakeRedis()
	r.down = true
	p := replicaWithRedis(t, r, redisFailureLocal)
	key := newKey(t, "ES256")
	proof := key.sign(t, nil)
	expectAllowed(t, run(p, dpopRequest(key, proof)))
	// The replica's own store still refuses the replay.
	expectRejected(t, run(p, dpopRequest(key, proof)), "invalid_dpop_proof")
}

// TestRedisLocalFallbackKeepsHistory crosses Redis outages in local mode: a proof
// accepted while Redis is up is refused during an outage on the same replica, and a
// proof accepted during an outage is refused after Redis recovers.
func TestRedisLocalFallbackKeepsHistory(t *testing.T) {
	r := newFakeRedis()
	p := replicaWithRedis(t, r, redisFailureLocal)
	key := newKey(t, "ES256")

	before := key.sign(t, nil)
	expectAllowed(t, run(p, dpopRequest(key, before)))
	r.down = true
	expectRejected(t, run(p, dpopRequest(key, before)), "invalid_dpop_proof")

	during := key.sign(t, nil)
	expectAllowed(t, run(p, dpopRequest(key, during)))
	r.down = false
	expectRejected(t, run(p, dpopRequest(key, during)), "invalid_dpop_proof")
}

// TestRedisLocalModeFullLocalRecordRefuses refuses a proof in local mode when the
// replica's own record is full, even though Redis would accept it: accepted without
// a local entry, it could be replayed on this replica during a later outage.
func TestRedisLocalModeFullLocalRecordRefuses(t *testing.T) {
	r := newFakeRedis()
	p := replicaWithRedis(t, r, redisFailureLocal)
	p.replay.(*redisReplayStore).local = newReplayStore(1)
	key := newKey(t, "ES256")
	expectAllowed(t, run(p, dpopRequest(key, key.sign(t, nil))))

	second := key.sign(t, nil)
	resp, ok := run(p, dpopRequest(key, second)).(policy.ImmediateResponse)
	if !ok || resp.StatusCode != 503 {
		t.Fatalf("full local record: got %+v, want 503", resp)
	}
	if len(r.ttls) != 1 {
		t.Errorf("refused proof was recorded in Redis: %d keys, want 1", len(r.ttls))
	}
}

// TestRedisClosedModeKeepsNoLocalRecord checks that the default mode leaves the
// replica's memory alone: Redis is the only record.
func TestRedisClosedModeKeepsNoLocalRecord(t *testing.T) {
	r := newFakeRedis()
	p := replicaWithRedis(t, r, redisFailureClosed)
	key := newKey(t, "ES256")
	expectAllowed(t, run(p, dpopRequest(key, key.sign(t, nil))))
	if n := p.replay.(*redisReplayStore).local.size(); n != 0 {
		t.Errorf("closed mode recorded %d proofs locally, want 0", n)
	}
}

// TestRedisConfiguredThroughParams builds the store from system parameters with the
// real go-redis client, pointed at a port nothing listens on: the policy deploys,
// and requests follow failureMode.
func TestRedisConfiguredThroughParams(t *testing.T) {
	params := map[string]interface{}{
		"replayStore": "redis",
		"redis": map[string]interface{}{
			"host": "127.0.0.1", "port": float64(1), "keyPrefix": "gw1:dpop:",
			"connectionTimeout": "200ms", "readTimeout": "200ms",
		},
	}
	pol, err := GetPolicy(policy.PolicyMetadata{}, params)
	if err != nil {
		t.Fatal(err)
	}
	p := pol.(*DPoPPolicy)
	store, ok := p.replay.(*redisReplayStore)
	if !ok || store.prefix != "gw1:dpop:" || store.failureMode != redisFailureClosed {
		t.Fatalf("replay store = %#v", p.replay)
	}
	if _, ok := store.client.(*redis.Client); !ok {
		t.Fatalf("client is %T, want *redis.Client", store.client)
	}
	p.now = func() time.Time { return testNow }
	key := newKey(t, "ES256")
	if resp, ok := run(p, dpopRequest(key, key.sign(t, nil))).(policy.ImmediateResponse); !ok || resp.StatusCode != 503 {
		t.Fatalf("unreachable Redis: got %+v, want 503", resp)
	}
}

// TestRedisConfigValidation refuses unusable Redis settings and defaults to the memory store.
func TestRedisConfigValidation(t *testing.T) {
	bad := []map[string]interface{}{
		{"replayStore": "memcached"},
		{"replayStore": "redis", "redis": map[string]interface{}{"failureMode": "open"}},
		{"replayStore": "redis", "redis": map[string]interface{}{"port": float64(70000)}},
		{"replayStore": "redis", "redis": map[string]interface{}{"readTimeout": "fast"}},
		{"replayStore": "redis", "redis": map[string]interface{}{"tls": map[string]interface{}{"enabled": true, "certFile": "/x.pem"}}},
		{"replayStore": "redis", "redis": map[string]interface{}{"tls": map[string]interface{}{"enabled": true, "caFile": "/does/not/exist.pem"}}},
	}
	for _, params := range bad {
		if _, err := GetPolicy(policy.PolicyMetadata{}, params); err == nil {
			t.Errorf("GetPolicy accepted %v", params)
		}
	}
	if pol, err := GetPolicy(policy.PolicyMetadata{}, nil); err != nil {
		t.Fatal(err)
	} else if _, ok := pol.(*DPoPPolicy).replay.(*replayStore); !ok {
		t.Errorf("default replay store is %T, want memory", pol.(*DPoPPolicy).replay)
	}
}

// reloadRuns counts runs of TestConcurrentTrafficDuringReload, to move each run's clock.
var reloadRuns int

// TestConcurrentTrafficDuringReload replays proofs from many goroutines while others
// rebuild policy instances, as a configuration reload does: each proof is accepted
// exactly once, and the shared stores stay consistent under the race detector.
func TestConcurrentTrafficDuringReload(t *testing.T) {
	r := newFakeRedis()
	local := replicaWithRedis(t, r, redisFailureLocal)
	closed := replicaWithRedis(t, r, redisFailureClosed)
	memory := newTestPolicy(t, nil)
	memory.replay = sharedReplayStore(1000) // the store reloads resize
	// Each run gets its own clock, an hour after the last, so entries earlier runs
	// left in the shared store expire instead of filling it.
	reloadRuns++
	now := testNow.Add(time.Duration(reloadRuns) * time.Hour)
	for _, p := range []*DPoPPolicy{local, closed, memory} {
		p.now = func() time.Time { return now }
	}
	key := newKey(t, "ES256")
	proofs := make([]string, 40)
	for i := range proofs {
		proofs[i] = key.sign(t, func(c jwt.MapClaims, _ map[string]interface{}) { c["iat"] = now.Unix() })
	}

	var wg sync.WaitGroup
	stop := make(chan struct{})
	for g := 0; g < 2; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; ; i++ {
				select {
				case <-stop:
					return
				default:
				}
				params := map[string]interface{}{"replayCacheMaxSize": float64(1000 + (i+g)%7)}
				if _, err := GetPolicy(policy.PolicyMetadata{APIName: "orders"}, params); err != nil {
					t.Error(err)
					return
				}
			}
		}(g)
	}

	for name, p := range map[string]*DPoPPolicy{"redis local": local, "redis closed": closed, "memory": memory} {
		var mu sync.Mutex
		accepted := map[int]int{}
		var traffic sync.WaitGroup
		for c := 0; c < 4; c++ {
			for i := range proofs {
				traffic.Add(1)
				go func(i int) {
					defer traffic.Done()
					if _, ok := run(p, dpopRequest(key, proofs[i])).(policy.UpstreamRequestHeaderModifications); ok {
						mu.Lock()
						accepted[i]++
						mu.Unlock()
					}
				}(i)
			}
		}
		traffic.Wait()
		for i := range proofs {
			if accepted[i] != 1 {
				t.Errorf("%s: proof %d accepted %d times, want 1", name, i, accepted[i])
			}
		}
		r.mu.Lock()
		r.ttls = map[string]time.Duration{}
		r.mu.Unlock()
	}
	close(stop)
	wg.Wait()
}
