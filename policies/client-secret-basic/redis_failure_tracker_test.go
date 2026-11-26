package clientsecretbasic

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

func newTestRedisTracker(t *testing.T, mr *miniredis.Miniredis) *failureTracker {
	t.Helper()
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { rdb.Close() })
	return &failureTracker{
		redis: &failureRedisConfig{
			rdb:            rdb,
			keyPrefix:      "test:",
			failOpen:       true,
			requestTimeout: time.Second,
		},
	}
}

func TestRedisFailureTracker_BlocksAfterLimit(t *testing.T) {
	mr := miniredis.RunT(t)
	ft := newTestRedisTracker(t, mr)
	ctx := context.Background()
	limit, window := 3, 30*time.Second

	for i := 0; i < limit; i++ {
		rsv, err := ft.checkAndReserve(ctx, "client1", limit, window)
		if err != nil {
			t.Fatalf("unexpected error on call %d: %v", i+1, err)
		}
		_ = rsv // keep slot (simulates wrong creds)
	}
	_, err := ft.checkAndReserve(ctx, "client1", limit, window)
	if _, ok := err.(throttleError); !ok {
		t.Fatalf("expected throttleError after limit, got %T: %v", err, err)
	}
}

func TestRedisFailureTracker_ReleaseOnSuccess(t *testing.T) {
	mr := miniredis.RunT(t)
	ft := newTestRedisTracker(t, mr)
	ctx := context.Background()
	limit, window := 2, 30*time.Second

	// Reserve one slot (wrong creds — keep it)
	_, _ = ft.checkAndReserve(ctx, "client1", limit, window)

	// Reserve + release (simulates correct creds)
	rsv, err := ft.checkAndReserve(ctx, "client1", limit, window)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	ft.releaseReservation(ctx, "client1", rsv)

	// Should be able to reserve again (slot was returned)
	_, err = ft.checkAndReserve(ctx, "client1", limit, window)
	if err != nil {
		t.Errorf("expected no error after release, got: %v", err)
	}
}

func TestRedisFailureTracker_ConditionalDecrNoNegativeKey(t *testing.T) {
	mr := miniredis.RunT(t)
	ft := newTestRedisTracker(t, mr)
	ctx := context.Background()
	limit := 3
	window := time.Second // 1-second window so we can expire it quickly

	rsv, err := ft.checkAndReserve(ctx, "client1", limit, window)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Advance miniredis clock past the window so the key expires
	mr.FastForward(2 * time.Second)

	// Release after expiry — the conditional DECR Lua script must not create a -1 key
	ft.releaseReservation(ctx, "client1", rsv)

	// Key must not exist (or be >= 0 if it somehow exists)
	checkRdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer checkRdb.Close()
	val, getErr := checkRdb.Get(ctx, rsv.redisKey).Int64()
	if getErr == nil && val < 0 {
		t.Errorf("DECR after expiry left key at %d (expected key absent or >= 0)", val)
	}
}

func TestRedisFailureTracker_FallbackToMemoryWhenRedisDown(t *testing.T) {
	mr := miniredis.RunT(t)
	ft := newTestRedisTracker(t, mr) // failOpen=true
	ctx := context.Background()
	limit, window := 2, 30*time.Second

	mr.Close() // take down Redis

	// With Redis down and failOpen=true, should fall back to in-memory counting
	for i := 0; i < limit; i++ {
		_, err := ft.checkAndReserve(ctx, "client1", limit, window)
		if err != nil {
			t.Fatalf("unexpected error during fallback on call %d: %v", i+1, err)
		}
	}
	// In-memory limit should be enforced
	_, err := ft.checkAndReserve(ctx, "client1", limit, window)
	if _, ok := err.(throttleError); !ok {
		t.Fatalf("expected throttleError from in-memory fallback, got %T: %v", err, err)
	}
}

func TestRedisFailureTracker_FailClosedReturnsNetworkError(t *testing.T) {
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	ft := &failureTracker{
		redis: &failureRedisConfig{
			rdb:            rdb,
			keyPrefix:      "test:",
			failOpen:       false, // fail-closed
			requestTimeout: 100 * time.Millisecond,
		},
	}
	t.Cleanup(func() { rdb.Close() })
	mr.Close() // take down Redis
	ctx := context.Background()
	_, err := ft.checkAndReserve(ctx, "client1", 3, 30*time.Second)
	if _, ok := err.(networkError); !ok {
		t.Fatalf("expected networkError with failOpen=false, got %T: %v", err, err)
	}
}

func TestRedisFailureTracker_IsThrottledReturnsTrueWhenAtLimit(t *testing.T) {
	mr := miniredis.RunT(t)
	ft := newTestRedisTracker(t, mr)
	ctx := context.Background()
	limit, window := 2, 30*time.Second

	// Fill all slots
	for i := 0; i < limit; i++ {
		_, _ = ft.checkAndReserve(ctx, "client1", limit, window)
	}

	throttled, retryAfter := ft.isThrottled(ctx, "client1", limit, window)
	if !throttled {
		t.Error("expected isThrottled=true after all slots taken")
	}
	if retryAfter <= 0 {
		t.Errorf("expected positive retryAfter, got %v", retryAfter)
	}
}

func TestGetPolicy_Redis_CreatesValidPolicy(t *testing.T) {
	mr := miniredis.RunT(t)
	host, port := mr.Host(), 0
	fmt.Sscanf(mr.Port(), "%d", &port)

	// Use a mock token endpoint
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"access_token":"tok","expires_in":3600}`)) //nolint:errcheck
	}))
	defer ts.Close()

	params := map[string]interface{}{
		"tokenEndpoint":  ts.URL,
		"failureBackend": "redis",
		"redis": map[string]interface{}{
			"host":           host,
			"port":           float64(port),
			"keyPrefix":      "test:csbv2:",
			"failureMode":    "open",
			"requestTimeout": "500ms",
		},
	}

	p, err := GetPolicy(policy.PolicyMetadata{}, params)
	if err != nil {
		t.Fatalf("GetPolicy failed: %v", err)
	}
	if p == nil {
		t.Fatal("expected non-nil policy")
	}

	// Verify the policy actually works (hits the mock IdP)
	impl := p.(*ClientSecretBasicPolicy)
	if impl.state.backend != "redis" {
		t.Errorf("expected backend=redis, got %q", impl.state.backend)
	}
}

func TestGetPolicy_Redis_FailClosed_PingFail_ReturnsError(t *testing.T) {
	params := map[string]interface{}{
		"tokenEndpoint":  "http://idp.example.com/token",
		"failureBackend": "redis",
		"redis": map[string]interface{}{
			"host":              "127.0.0.1",
			"port":              float64(19999), // nothing listening here
			"failureMode":       "closed",
			"requestTimeout":    "100ms",
			"connectionTimeout": "200ms",
		},
	}

	_, err := GetPolicy(policy.PolicyMetadata{}, params)
	if err == nil {
		t.Error("expected error when Redis ping fails with failureMode=closed")
	}
}

func TestGetPolicy_Redis_FailOpen_PingFail_Succeeds(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"access_token":"tok","expires_in":3600}`)) //nolint:errcheck
	}))
	defer ts.Close()

	params := map[string]interface{}{
		"tokenEndpoint":  ts.URL,
		"failureBackend": "redis",
		"redis": map[string]interface{}{
			"host":              "127.0.0.1",
			"port":              float64(19998), // nothing listening
			"failureMode":       "open",
			"requestTimeout":    "100ms",
			"connectionTimeout": "200ms",
		},
	}

	p, err := GetPolicy(policy.PolicyMetadata{}, params)
	if err != nil {
		t.Fatalf("expected GetPolicy to succeed with failureMode=open, got: %v", err)
	}
	if p == nil {
		t.Fatal("expected non-nil policy")
	}
}

func TestGetOrCreateEndpointState_BackendMismatchWarns(t *testing.T) {
	endpoint := "http://idp.example.test/unique-warn-test"
	// Register with memory backend first
	s1 := getOrCreateEndpointState(endpoint, "memory", nil)
	if s1 == nil {
		t.Fatal("expected non-nil state")
	}
	// Second registration with redis backend — should return existing, log warning
	s2 := getOrCreateEndpointState(endpoint, "redis", nil)
	if s1 != s2 {
		t.Error("expected same state object to be returned on second call")
	}
	if s2.backend != "memory" {
		t.Errorf("expected existing backend=memory, got %q", s2.backend)
	}
}

// TestRedisRelease_SkipsWhenWindowExpired verifies that releaseReservationRedis
// skips the conditional DECR when the reservation's windowEnd is already in the
// past — preventing counter corruption in a newer failure window.
func TestRedisRelease_SkipsWhenWindowExpired(t *testing.T) {
	mr := miniredis.RunT(t)
	ft := newTestRedisTracker(t, mr)
	ctx := context.Background()

	rsv, err := ft.checkAndReserve(ctx, "client-window-test", 3, 30*time.Second)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rsv.redisKey == "" {
		t.Fatal("expected non-empty redisKey from Redis path")
	}

	// Backdate windowEnd to simulate the window having already expired
	rsv.windowEnd = time.Now().Add(-2 * time.Second)

	// Release — the guard should skip the DECR
	ft.releaseReservation(ctx, "client-window-test", rsv)

	// Counter must still be 1 (DECR was not issued)
	checkRdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { checkRdb.Close() })
	val, getErr := checkRdb.Get(ctx, rsv.redisKey).Result()
	if getErr != nil {
		t.Fatalf("failed to read Redis counter: %v", getErr)
	}
	if val != "1" {
		t.Errorf("expected counter=1 (DECR skipped by windowEnd guard), got %q", val)
	}
}

// TestGetPolicy_Redis_FailClosed_CachedClient_PingFail_ReturnsError verifies that
// when GetPolicy is called a second time with failureMode=closed and the Redis
// client is already cached (created=false), an explicit ping is still issued and
// the call fails when Redis is unreachable.
func TestGetPolicy_Redis_FailClosed_CachedClient_PingFail_ReturnsError(t *testing.T) {
	mr := miniredis.RunT(t)
	host, port := mr.Host(), 0
	fmt.Sscanf(mr.Port(), "%d", &port)

	params := map[string]interface{}{
		"tokenEndpoint":  "https://idp-cached-ping-test.example.com/token",
		"failureBackend": "redis",
		"redis": map[string]interface{}{
			"host":              host,
			"port":              float64(port),
			"failureMode":       "closed",
			"requestTimeout":    "200ms",
			"connectionTimeout": "500ms",
		},
	}

	// First call: Redis is up — created=true, initial ping passes, policy loads.
	_, err := GetPolicy(policy.PolicyMetadata{}, params)
	if err != nil {
		t.Fatalf("first GetPolicy should succeed: %v", err)
	}

	// Take Redis down.
	mr.Close()

	// Second call: same connKey → created=false; explicit ping for closed mode
	// fires and must fail because Redis is now unreachable.
	_, err = GetPolicy(policy.PolicyMetadata{}, params)
	if err == nil {
		t.Error("expected error on second GetPolicy when Redis is down with failureMode=closed")
	}
}
