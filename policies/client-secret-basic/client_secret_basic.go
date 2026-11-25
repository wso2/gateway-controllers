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

package clientsecretbasic

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

// failureIncrScript atomically increments a Redis counter, sets its expiry on
// creation, and enforces a per-window limit. Returns [count, ttl_seconds] on
// success (count ≥ 1), or [-1, ttl_seconds] when the counter is already at
// the limit (the increment is immediately reversed so the key is not inflated).
var failureIncrScript = redis.NewScript(`
local count = redis.call('INCR', KEYS[1])
if count == 1 then
    redis.call('EXPIRE', KEYS[1], tonumber(ARGV[2]))
end
local ttl = redis.call('TTL', KEYS[1])
if count > tonumber(ARGV[1]) then
    redis.call('DECR', KEYS[1])
    return {-1, ttl}
end
return {count, ttl}
`)

const (
	authType = "ClientCredentials"

	// applicationIDMetadataKey is the shared-context key subscription-validation
	// reads when the request carries no Subscription-Key header. jwt-application-id
	// writes the same key for JWT flows; api-key-auth writes it for API key flows.
	applicationIDMetadataKey = "x-wso2-application-id"
	defaultTokenMetadataKey  = "upstream-access-token"

	defaultTokenRequestTimeout = 10 * time.Second
	defaultExpiryBuffer        = 30 * time.Second
	defaultMaxCacheTTL         = 5 * time.Minute
	defaultTokenTTLFallback    = time.Hour
	defaultFailureWindow       = 30 * time.Second
	defaultFailureRateLimit    = 3 // IdP calls per clientId per window before 429

	// maxWrongCredEntries caps the wrong-credential pair cache.
	// When full, expired entries are swept first; if still full, the specific pair
	// is not stored but the per-clientId throttle counter still increments, so
	// throttling continues to engage even under cache pressure.
	maxWrongCredEntries = 2048

	// maxClientCounterEntries caps the per-clientId throttle counter map.
	// When full, expired entries are swept first; if still full, new client IDs are
	// counted against a shared overflow counter so the limit still engages.
	// Each entry is a small struct (~80 bytes), so 100,000 entries ≈ 10 MB.
	maxClientCounterEntries = 100_000

	// maxDynamicClientIDLen rejects oversized client IDs in dynamic mode before they
	// reach the throttle map or IdP. Unbounded client IDs can grow the counter map
	// even after the hash key is capped, since the hash must be computed first.
	maxDynamicClientIDLen = 256

	maxTokenResponseBytes = 1 << 20 // 1 MiB

	// sharedTransportMaxConns is the per-host connection cap on the shared transport.
	// It limits both idle connections held in the pool and total concurrent connections
	// to the token endpoint, preventing port exhaustion under load.
	sharedTransportMaxConns = 64
)

// endpointState holds the shared in-process state for one token endpoint.
// All policy instances that point at the same endpoint share one of these,
// so the failure counter, wrong-credential cache, success cache, and singleflight
// group are global per IdP — not per operation or per API.
type endpointState struct {
	cache    sync.Map // cacheKey(clientId,secret) → validationEntry
	failures failureTracker
	sf       sfGroup
}

var (
	endpointStatesMu sync.Mutex
	endpointStates   = map[string]*endpointState{}
)

// getOrCreateEndpointState returns the shared state for the given token endpoint.
// On first call, the state is initialized with redisCfg (may be nil for in-memory).
// Subsequent calls return the existing state; redisCfg is ignored after first creation
// so the first registered instance's backend configuration takes effect.
func getOrCreateEndpointState(endpoint string, redisCfg *failureRedisConfig) *endpointState {
	endpointStatesMu.Lock()
	defer endpointStatesMu.Unlock()
	if s, ok := endpointStates[endpoint]; ok {
		return s
	}
	s := &endpointState{}
	s.failures.redis = redisCfg
	endpointStates[endpoint] = s
	return s
}

// sharedTransport is shared by all policy instances so connections to the token
// endpoint are pooled across operations and APIs. The default transport keeps only
// 2 idle connections per host, which causes port exhaustion under load.
var sharedTransport = &http.Transport{
	MaxIdleConns:        sharedTransportMaxConns * 2,
	MaxIdleConnsPerHost: sharedTransportMaxConns,
	MaxConnsPerHost:     sharedTransportMaxConns,
	IdleConnTimeout:     90 * time.Second,
}

// validationMode selects how credentials are verified at request time.
type validationMode int

const (
	modeStatic  validationMode = iota // validate against stored credential pairs
	modeDynamic                       // validate by attempting an OAuth2 token request
)

// PolicyConfig holds the resolved, immutable configuration for one policy instance.
type PolicyConfig struct {
	// modeStatic only
	Credentials map[string]string // clientId → clientSecret

	// modeDynamic only
	TokenEndpoint    string
	TokenTimeout     time.Duration
	ExpiryBuffer     time.Duration
	MaxCacheTTL      time.Duration
	FailureRateLimit int
	FailureWindow    time.Duration
	// When non-empty, the access token returned by the IdP is stored in
	// SharedContext.Metadata under this key after a successful dynamic validation.
	// Downstream policies (e.g. header-transform) can read it with
	// {{ metadata["<key>"] }}. Has no effect in static mode.
	TokenMetadataKey string

	Mode validationMode

	// SubscriptionKeyHeader is the header name that subscription-validation reads
	// as the subscription key. Any request carrying this header is rejected with 401
	// before subscription-validation runs, so the subscription cannot be detached
	// from the authenticated client identity.
	SubscriptionKeyHeader string

	// SubscriptionKeyCookie, when non-empty, names a cookie that subscription-validation
	// is configured to accept as a subscription key. Requests carrying this cookie are
	// rejected with 401 for the same reason as SubscriptionKeyHeader.
	SubscriptionKeyCookie string

	// failureRedis holds the wired-up Redis client and settings for distributed
	// failure counting. Nil means in-memory counting only.
	failureRedis *failureRedisConfig
}

// failureRedisConfig carries the Redis connection and key-space settings for the
// distributed failure counter. It is populated once at GetPolicy time and shared
// across all policy instances pointing at the same token endpoint.
type failureRedisConfig struct {
	rdb       *redis.Client
	keyPrefix string
	failOpen  bool // when true, Redis errors allow requests through
}

// validationEntry is a cache record produced by a successful dynamic validation.
type validationEntry struct {
	expiresAt   time.Time
	accessToken string // the access token returned by the IdP; empty when TokenMetadataKey is unset
}

// wrongCredEntry caches a confirmed bad credential pair so repeats never reach the IdP.
type wrongCredEntry struct {
	expiresAt time.Time
}

// clientThrottleEntry tracks how many distinct new failed credentials have been tried
// for a clientId within the current tumbling window.
type clientThrottleEntry struct {
	count     int
	windowEnd time.Time
}

// throttleError indicates the per-clientId failure rate limit was reached.
// Maps to 429 Too Many Requests. retryAfter is the time until the window resets.
type throttleError struct {
	clientId   string
	retryAfter time.Duration
}

func (e throttleError) Error() string {
	return fmt.Sprintf("failure rate limit reached for client %q", e.clientId)
}

// networkError wraps transport/server-side failures that map to 503 Service Unavailable.
type networkError struct{ err error }

func (e networkError) Error() string { return e.err.Error() }
func (e networkError) Unwrap() error { return e.err }

// failureTracker tracks per-credential-pair rejections and per-clientId throttle counters.
//
// Two-layer protection:
//  1. wrongCreds: a confirmed bad (clientId, secret) pair always returns 401 without an IdP
//     call, capped at maxWrongCredEntries with lazy expiry sweep.
//  2. clientCounters: once a clientId's failure count within the current window exceeds
//     FailureRateLimit, further attempts return 429 — even when the specific pair is not
//     in wrongCreds (e.g. because the cache was full).
//
// Unlike a pure per-clientId block, one wrong secret does not block requests with the
// correct secret: legitimate calls that miss the success cache still reach the IdP as long
// as the per-clientId limit is not exhausted. When the limit is hit, 429 (not 401) signals
// throttling so callers know their secret may be valid.
type failureTracker struct {
	mu              sync.Mutex
	wrongCreds      map[string]wrongCredEntry
	clientCounters  map[string]clientThrottleEntry
	overflowCounter overflowThrottleEntry // counts new IDs when the map is full
	lastSweep       time.Time             // throttles the full-map expired-entry sweep

	// redis is non-nil when the failure backend is Redis. When set, client counters
	// are stored in Redis so all gateway replicas share one limit per token endpoint.
	// Wrong-cred pairs remain in-memory (they are a performance optimisation, not a
	// security boundary — the IdP rejects them regardless).
	redis *failureRedisConfig
}

// overflowThrottleEntry is a single shared counter used when clientCounters is at capacity.
// New client IDs that arrive when the map is full are counted here rather than let through.
type overflowThrottleEntry struct {
	count     int
	windowEnd time.Time
}

// reservation identifies which counter was incremented by checkAndReserve so that
// releaseReservation can decrement the correct counter and verify the window is still active.
// For the in-memory path, isOverflow/windowEnd identify the slot. For the Redis path,
// redisKey names the key to DECR; both overflow and windowEnd are zero in that case.
type reservation struct {
	isOverflow bool
	windowEnd  time.Time
	redisKey   string // non-empty: slot came from Redis
}

// failureCounterKey returns the Redis key for the per-clientId failure counter.
func (f *failureTracker) failureCounterKey(clientId string) string {
	return f.redis.keyPrefix + "fc:" + clientCounterKey(clientId)
}

// isThrottledRedis is a non-authoritative fast path that reads the Redis counter.
// It never increments — that happens inside checkAndReserveRedis.
func (f *failureTracker) isThrottledRedis(clientId string, limit int) (bool, time.Duration) {
	key := f.failureCounterKey(clientId)
	ctx := context.Background()
	val, err := f.redis.rdb.Get(ctx, key).Int64()
	if err != nil {
		return false, 0
	}
	if val < int64(limit) {
		return false, 0
	}
	ttl, err := f.redis.rdb.TTL(ctx, key).Result()
	if err != nil || ttl <= 0 {
		return true, time.Second
	}
	if ttl < time.Second {
		ttl = time.Second
	}
	return true, ttl
}

// checkAndReserveRedis increments the Redis counter atomically and enforces the
// per-clientId limit. The Lua script ensures the increment and limit check are
// a single atomic operation. Returns a reservation that holds the Redis key so
// releaseReservationRedis can DECR it on success or network error.
func (f *failureTracker) checkAndReserveRedis(clientId string, limit int, window time.Duration) (reservation, error) {
	key := f.failureCounterKey(clientId)
	windowSecs := int64(window.Seconds())
	if windowSecs < 1 {
		windowSecs = 1
	}
	ctx := context.Background()
	res, err := failureIncrScript.Run(ctx, f.redis.rdb, []string{key}, int64(limit), windowSecs).Int64Slice()
	if err != nil {
		if f.redis.failOpen {
			slog.Debug("client-secret-basic: Redis failure counter unavailable, allowing request (failureMode=open)", "error", err)
			return reservation{}, nil // zero reservation: nothing to release
		}
		return reservation{}, networkError{fmt.Errorf("Redis failure counter: %w", err)}
	}
	count := res[0]
	ttlSecs := res[1]
	if count < 0 {
		retryAfter := time.Duration(ttlSecs) * time.Second
		if retryAfter < time.Second {
			retryAfter = time.Second
		}
		return reservation{}, throttleError{clientId: clientId, retryAfter: retryAfter}
	}
	return reservation{redisKey: key}, nil
}

// releaseReservationRedis decrements the Redis counter. Called on IdP success or
// network error so those outcomes do not consume a failure quota slot.
func (f *failureTracker) releaseReservationRedis(rsv reservation) {
	if rsv.redisKey == "" {
		return // zero reservation from a fail-open Redis miss: nothing to release
	}
	ctx := context.Background()
	if err := f.redis.rdb.Decr(ctx, rsv.redisKey).Err(); err != nil {
		slog.Debug("client-secret-basic: Redis DECR failed during reservation release", "error", err)
	}
}

// isWrongCred returns true if key is a confirmed bad credential pair still within its TTL.
func (f *failureTracker) isWrongCred(key string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.wrongCreds == nil {
		return false
	}
	e, ok := f.wrongCreds[key]
	if !ok {
		return false
	}
	if time.Now().After(e.expiresAt) {
		delete(f.wrongCreds, key)
		return false
	}
	return true
}

// isThrottled is a non-authoritative fast-path check used before entering the
// singleflight. It returns (true, remaining) if the clientId is currently throttled,
// or (false, 0) otherwise. It does not increment the counter — that happens inside
// checkAndReserve, which is the authoritative check.
func (f *failureTracker) isThrottled(clientId string, limit int, _ time.Duration) (bool, time.Duration) {
	if f.redis != nil {
		return f.isThrottledRedis(clientId, limit)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.clientCounters == nil {
		return false, 0
	}
	ckey := clientCounterKey(clientId)
	e, ok := f.clientCounters[ckey]
	if !ok {
		return false, 0
	}
	now := time.Now()
	if now.After(e.windowEnd) {
		delete(f.clientCounters, ckey)
		return false, 0
	}
	if e.count < limit {
		return false, 0
	}
	remaining := e.windowEnd.Sub(now)
	if remaining < time.Second {
		remaining = time.Second
	}
	return true, remaining
}

// checkAndReserve atomically checks the per-clientId failure counter and, if the
// limit has not been reached, increments it by one. This must be called inside the
// singleflight fn() so that each distinct IdP call is counted exactly once,
// regardless of how many goroutines are waiting on the same credential pair.
//
// Returns (reservation, nil) on success. The reservation identifies which counter was
// incremented and its active window so releaseReservation can release the right one.
// Returns (zero, throttleError) if the limit is reached.
// The caller MUST call releaseReservation if the IdP accepts the credentials or
// returns a network error so successful requests don't consume failure quota.
func (f *failureTracker) checkAndReserve(clientId string, limit int, window time.Duration) (reservation, error) {
	if f.redis != nil {
		return f.checkAndReserveRedis(clientId, limit, window)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.clientCounters == nil {
		f.clientCounters = make(map[string]clientThrottleEntry)
	}
	ckey := clientCounterKey(clientId)
	now := time.Now()
	e, ok := f.clientCounters[ckey]

	if ok && !now.After(e.windowEnd) {
		// Window is active.
		if e.count >= limit {
			remaining := e.windowEnd.Sub(now)
			if remaining < time.Second {
				remaining = time.Second
			}
			return reservation{}, throttleError{clientId: clientId, retryAfter: remaining}
		}
		e.count++
		f.clientCounters[ckey] = e
		return reservation{windowEnd: e.windowEnd}, nil
	}

	// No entry or window expired: start a fresh window. Sweep map if at capacity,
	// but at most once per second — sweeping on every request under full-map pressure
	// (up to ~1,850 req/s per instance) would hold the lock for the full iteration
	// each time. One sweep per second is enough to reclaim expired entries promptly.
	if len(f.clientCounters) >= maxClientCounterEntries {
		if now.Sub(f.lastSweep) >= time.Second {
			for k, v := range f.clientCounters {
				if now.After(v.windowEnd) {
					delete(f.clientCounters, k)
				}
			}
			f.lastSweep = now
		}
	}
	if len(f.clientCounters) >= maxClientCounterEntries {
		// Map is still full after sweeping expired entries. Count this new client ID
		// against a shared overflow counter so the limit still engages rather than
		// letting unknown clients through unchecked.
		ov := f.overflowCounter
		if now.After(ov.windowEnd) {
			// Overflow window expired — start fresh.
			ov = overflowThrottleEntry{count: 1, windowEnd: now.Add(window)}
			f.overflowCounter = ov
			return reservation{isOverflow: true, windowEnd: ov.windowEnd}, nil
		}
		if ov.count >= limit {
			remaining := ov.windowEnd.Sub(now)
			if remaining < time.Second {
				remaining = time.Second
			}
			return reservation{}, throttleError{clientId: clientId, retryAfter: remaining}
		}
		ov.count++
		f.overflowCounter = ov
		return reservation{isOverflow: true, windowEnd: ov.windowEnd}, nil
	}
	exp := now.Add(window)
	f.clientCounters[ckey] = clientThrottleEntry{count: 1, windowEnd: exp}
	return reservation{windowEnd: exp}, nil
}

// releaseReservation decrements the counter identified by rsv. Call this when the
// IdP accepts the credentials or returns a network error — those outcomes should not
// consume a failure slot. Only releases if the stored window still matches the
// reservation's window to avoid corrupting a later window when a slow request outlasts
// its failureWindow.
func (f *failureTracker) releaseReservation(clientId string, rsv reservation) {
	if f.redis != nil {
		f.releaseReservationRedis(rsv)
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if rsv.isOverflow {
		ov := f.overflowCounter
		if ov.windowEnd == rsv.windowEnd && ov.count > 0 {
			ov.count--
			f.overflowCounter = ov
		}
		return
	}
	if f.clientCounters == nil {
		return
	}
	ckey := clientCounterKey(clientId)
	e, ok := f.clientCounters[ckey]
	if !ok || e.windowEnd != rsv.windowEnd {
		return
	}
	if e.count > 0 {
		e.count--
		if e.count == 0 {
			delete(f.clientCounters, ckey)
		} else {
			f.clientCounters[ckey] = e
		}
	}
}

// storeWrongCred adds the specific bad credential pair to the wrong-cred cache.
// This is called after an auth rejection so repeats of the exact same wrong secret
// never reach the IdP again.
func (f *failureTracker) storeWrongCred(key string, window time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.wrongCreds == nil {
		f.wrongCreds = make(map[string]wrongCredEntry)
	}
	if _, exists := f.wrongCreds[key]; exists {
		return
	}
	now := time.Now()
	exp := now.Add(window)
	if len(f.wrongCreds) >= maxWrongCredEntries {
		for k, v := range f.wrongCreds {
			if now.After(v.expiresAt) {
				delete(f.wrongCreds, k)
			}
		}
	}
	if len(f.wrongCreds) < maxWrongCredEntries {
		f.wrongCreds[key] = wrongCredEntry{expiresAt: exp}
	}
	// If still full, the wrong-cred pair is not cached, but the per-clientId counter
	// was already incremented by checkAndReserve, so throttling still engages.
}

// sfResult carries the outcome of one successful singleflight token call.
// expiresAt is the absolute cache expiry computed inside the callback so all waiting
// goroutines share the same value instead of each computing it at their own resume time.
type sfResult struct {
	accessToken string
	expiresAt   time.Time
}

// sfCall is an in-flight singleflight request.
type sfCall struct {
	wg  sync.WaitGroup
	val sfResult
	err error
}

// sfGroup deduplicates concurrent identical token requests by cache key so that
// N simultaneous first requests for the same credential pair produce only one IdP call.
type sfGroup struct {
	mu   sync.Mutex
	work map[string]*sfCall
}

func (g *sfGroup) do(key string, fn func() (sfResult, error)) (sfResult, error) {
	g.mu.Lock()
	if g.work == nil {
		g.work = make(map[string]*sfCall)
	}
	if c, ok := g.work[key]; ok {
		g.mu.Unlock()
		c.wg.Wait()
		return c.val, c.err
	}
	c := &sfCall{}
	c.wg.Add(1)
	g.work[key] = c
	g.mu.Unlock()

	c.val, c.err = fn()
	c.wg.Done()

	g.mu.Lock()
	delete(g.work, key)
	g.mu.Unlock()

	return c.val, c.err
}

// ClientSecretBasicPolicy validates credentials from the Authorization: Basic header.
type ClientSecretBasicPolicy struct {
	cfg        PolicyConfig
	httpClient *http.Client
	state      *endpointState // shared state for the token endpoint; nil in static mode
}

// GetPolicy is the v1alpha2 factory entry point.
func GetPolicy(
	metadata policy.PolicyMetadata,
	params map[string]interface{},
) (policy.Policy, error) {
	cfg, err := buildConfig(params)
	if err != nil {
		return nil, err
	}
	p := &ClientSecretBasicPolicy{cfg: cfg}
	if cfg.Mode == modeDynamic {
		p.httpClient = &http.Client{
			Timeout:   cfg.TokenTimeout,
			Transport: sharedTransport,
		}

		var redisCfg *failureRedisConfig
		if failureBackend := stringParam(params, "failureBackend"); failureBackend == "redis" {
			redisHost := stringParam(params, "redis.host")
			if redisHost == "" {
				redisHost = "localhost"
			}
			redisPort := 6379
			if v, ok := params["redis.port"]; ok {
				if n, ok := v.(float64); ok && n > 0 {
					redisPort = int(n)
				}
			}
			redisPassword := stringParam(params, "redis.password")
			redisUsername := stringParam(params, "redis.username")
			redisDB := 0
			if v, ok := params["redis.db"]; ok {
				if n, ok := v.(float64); ok && n >= 0 {
					redisDB = int(n)
				}
			}
			failureMode := stringParam(params, "redis.failureMode")
			if failureMode == "" {
				failureMode = "open"
			}
			keyPrefix := stringParam(params, "redis.keyPrefix")
			if keyPrefix == "" {
				keyPrefix = "csb:failure:"
			}
			connTimeout := parseDurationParam(params, "redis.connectionTimeout", 5*time.Second)
			readTimeout := parseDurationParam(params, "redis.readTimeout", 3*time.Second)
			writeTimeout := parseDurationParam(params, "redis.writeTimeout", 3*time.Second)
			poolSize := 0
			if v, ok := params["redis.poolSize"]; ok {
				if n, ok := v.(float64); ok && n >= 0 {
					poolSize = int(n)
				}
			}
			tlsEnabled, _ := params["redis.tls.enabled"].(bool)
			tlsCAFile := stringParam(params, "redis.tls.caFile")
			tlsServerName := stringParam(params, "redis.tls.serverName")
			tlsInsecureSkip, _ := params["redis.tls.insecureSkipVerify"].(bool)
			tlsCertFile := stringParam(params, "redis.tls.certFile")
			tlsKeyFile := stringParam(params, "redis.tls.keyFile")

			tlsCfg, err := csbBuildTLSConfig(tlsEnabled, tlsCAFile, tlsServerName, tlsCertFile, tlsKeyFile, tlsInsecureSkip)
			if err != nil {
				return nil, err
			}
			if tlsEnabled && tlsInsecureSkip {
				slog.Warn("client-secret-basic: Redis TLS certificate verification is disabled (redis.tls.insecureSkipVerify); do not use in production",
					"addr", fmt.Sprintf("%s:%d", redisHost, redisPort))
			}

			connKey := csbRedisConnKey{
				addr:            fmt.Sprintf("%s:%d", redisHost, redisPort),
				username:        redisUsername,
				passwordHash:    csbHashPassword(redisPassword),
				db:              redisDB,
				dialTimeout:     connTimeout,
				readTimeout:     readTimeout,
				writeTimeout:    writeTimeout,
				poolSize:        poolSize,
				tlsEnabled:      tlsEnabled,
				tlsInsecureSkip: tlsInsecureSkip,
				tlsCAFile:       tlsCAFile,
				tlsServerName:   tlsServerName,
				tlsCertFile:     tlsCertFile,
				tlsKeyFile:      tlsKeyFile,
			}
			rdb, created, pingErr := getOrCreateCsbRedisClient(&redis.Options{
				Addr:         connKey.addr,
				Username:     redisUsername,
				Password:     redisPassword,
				DB:           redisDB,
				DialTimeout:  connTimeout,
				ReadTimeout:  readTimeout,
				WriteTimeout: writeTimeout,
				PoolSize:     poolSize,
				TLSConfig:    tlsCfg,
			}, connKey, connTimeout)
			if created && pingErr != nil {
				if failureMode != "open" {
					return nil, fmt.Errorf("client-secret-basic: Redis ping failed and failureMode=closed: %w", pingErr)
				}
				slog.Warn("client-secret-basic: Redis ping failed but failureMode=open; proceeding with in-memory fallback until Redis recovers", "error", pingErr)
			}
			redisCfg = &failureRedisConfig{
				rdb:       rdb,
				keyPrefix: keyPrefix,
				failOpen:  failureMode == "open",
			}
		}

		p.state = getOrCreateEndpointState(cfg.TokenEndpoint, redisCfg)
	}
	return p, nil
}

// buildConfig resolves params into a PolicyConfig.
func buildConfig(params map[string]interface{}) (PolicyConfig, error) {
	cfg := PolicyConfig{
		TokenTimeout:     defaultTokenRequestTimeout,
		ExpiryBuffer:     defaultExpiryBuffer,
		MaxCacheTTL:      defaultMaxCacheTTL,
		FailureRateLimit: defaultFailureRateLimit,
		FailureWindow:    defaultFailureWindow,
	}
	if params == nil {
		return cfg, fmt.Errorf("client-secret-basic: params are required")
	}

	if s := stringParam(params, "tokenRequestTimeout"); s != "" {
		d, err := time.ParseDuration(s)
		if err != nil || d <= 0 {
			return cfg, fmt.Errorf("client-secret-basic: invalid tokenRequestTimeout %q: must be a positive Go duration string (e.g. \"10s\")", s)
		}
		cfg.TokenTimeout = d
	}
	if s := stringParam(params, "expiryBuffer"); s != "" {
		d, err := time.ParseDuration(s)
		if err != nil || d < 0 {
			return cfg, fmt.Errorf("client-secret-basic: invalid expiryBuffer %q: must be a non-negative Go duration string (e.g. \"30s\", \"0s\")", s)
		}
		cfg.ExpiryBuffer = d
	}
	if s := stringParam(params, "maxCacheTTL"); s != "" {
		d, err := time.ParseDuration(s)
		if err != nil || d <= 0 {
			return cfg, fmt.Errorf("client-secret-basic: invalid maxCacheTTL %q: must be a positive Go duration string (e.g. \"5m\")", s)
		}
		cfg.MaxCacheTTL = d
	}
	if s := stringParam(params, "failureWindow"); s != "" {
		d, err := time.ParseDuration(s)
		if err != nil || d <= 0 {
			return cfg, fmt.Errorf("client-secret-basic: invalid failureWindow %q: must be a positive Go duration string (e.g. \"30s\", \"1m\")", s)
		}
		cfg.FailureWindow = d
	}
	if v, ok := params["failureRateLimit"]; ok {
		switch n := v.(type) {
		case float64:
			if int(n) < 1 {
				return cfg, fmt.Errorf("client-secret-basic: 'failureRateLimit' must be at least 1, got %d", int(n))
			}
			cfg.FailureRateLimit = int(n)
		case int:
			if n < 1 {
				return cfg, fmt.Errorf("client-secret-basic: 'failureRateLimit' must be at least 1, got %d", n)
			}
			cfg.FailureRateLimit = n
		}
	}

	cfg.TokenMetadataKey = defaultTokenMetadataKey
	if s := stringParam(params, "tokenMetadataKey"); s != "" {
		if s == applicationIDMetadataKey {
			return cfg, fmt.Errorf("client-secret-basic: 'tokenMetadataKey' cannot be %q — it is reserved for the authenticated application identity", applicationIDMetadataKey)
		}
		cfg.TokenMetadataKey = s
	}

	cfg.SubscriptionKeyHeader = "Subscription-Key"
	if s := stringParam(params, "subscriptionKeyHeader"); s != "" {
		cfg.SubscriptionKeyHeader = s
	}
	cfg.SubscriptionKeyCookie = stringParam(params, "subscriptionKeyCookie")

	// Reject ambiguous mixed-mode configuration before any mode detection.
	_, hasCredentials := params["credentials"]
	_, hasClientId := params["clientId"]
	_, hasClientSecret := params["clientSecret"]
	ep := stringParam(params, "tokenEndpoint")
	if hasCredentials && (hasClientId || hasClientSecret) {
		return cfg, fmt.Errorf("client-secret-basic: 'credentials' and flat 'clientId'/'clientSecret' are mutually exclusive — configure one form only")
	}
	if (hasCredentials || hasClientId || hasClientSecret) && ep != "" {
		return cfg, fmt.Errorf("client-secret-basic: 'tokenEndpoint' and static credentials (credentials/clientId/clientSecret) are mutually exclusive — configure one mode only")
	}

	// Dynamic mode: tokenEndpoint present → validate via token request.
	if ep != "" {
		if _, err := url.ParseRequestURI(ep); err != nil {
			return cfg, fmt.Errorf("client-secret-basic: tokenEndpoint %q is not a valid URL: %w", ep, err)
		}
		cfg.TokenEndpoint = ep
		cfg.Mode = modeDynamic
		return cfg, nil
	}

	// Static mode: must have credentials array or flat clientId/clientSecret.
	cfg.Mode = modeStatic
	cfg.Credentials = make(map[string]string)

	if raw, ok := params["credentials"]; ok {
		entries, ok := raw.([]interface{})
		if !ok || len(entries) == 0 {
			return cfg, fmt.Errorf("client-secret-basic: 'credentials' must be a non-empty array")
		}
		for i, e := range entries {
			entry, ok := e.(map[string]interface{})
			if !ok {
				return cfg, fmt.Errorf("client-secret-basic: credentials[%d] must be an object", i)
			}
			idRaw, hasID := entry["clientId"]
			secretRaw, hasSecret := entry["clientSecret"]
			if !hasID || idRaw == nil {
				return cfg, fmt.Errorf("client-secret-basic: credentials[%d].clientId is missing", i)
			}
			if !hasSecret || secretRaw == nil {
				return cfg, fmt.Errorf("client-secret-basic: credentials[%d].clientSecret is missing", i)
			}
			id, idOk := idRaw.(string)
			secret, secretOk := secretRaw.(string)
			if !idOk || id == "" {
				return cfg, fmt.Errorf("client-secret-basic: credentials[%d].clientId must be a non-empty string", i)
			}
			if !secretOk || secret == "" {
				return cfg, fmt.Errorf("client-secret-basic: credentials[%d].clientSecret must be a non-empty string", i)
			}
			if _, dup := cfg.Credentials[id]; dup {
				return cfg, fmt.Errorf("client-secret-basic: duplicate clientId %q in credentials", id)
			}
			cfg.Credentials[id] = secret
		}
		return cfg, nil
	}

	id, idOk := params["clientId"].(string)
	secret, secretOk := params["clientSecret"].(string)
	if !idOk || id == "" {
		return cfg, fmt.Errorf("client-secret-basic: required param 'clientId' is missing or empty")
	}
	if !secretOk || secret == "" {
		return cfg, fmt.Errorf("client-secret-basic: required param 'clientSecret' is missing or empty")
	}
	cfg.Credentials[id] = secret
	return cfg, nil
}

func stringParam(params map[string]interface{}, key string) string {
	if v, ok := params[key]; ok {
		if s, ok := v.(string); ok {
			return strings.TrimSpace(s)
		}
	}
	return ""
}

func parseDurationParam(params map[string]interface{}, key string, defaultVal time.Duration) time.Duration {
	s := stringParam(params, key)
	if s == "" {
		return defaultVal
	}
	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 {
		return defaultVal
	}
	return d
}

// Mode returns the processing mode — only request headers are needed.
func (p *ClientSecretBasicPolicy) Mode() policy.ProcessingMode {
	return policy.ProcessingMode{
		RequestHeaderMode:  policy.HeaderModeProcess,
		RequestBodyMode:    policy.BodyModeSkip,
		ResponseHeaderMode: policy.HeaderModeSkip,
		ResponseBodyMode:   policy.BodyModeSkip,
	}
}

// extractBasicCredentials parses clientId and clientSecret from an
// Authorization: Basic <base64(clientId:clientSecret)> header value.
// Per RFC 6749 §2.3.1, the decoded values are URL-decoded (form-encoding).
func extractBasicCredentials(headers *policy.Headers) (clientId, clientSecret string, err error) {
	authVals := headers.Get("Authorization")
	if len(authVals) == 0 {
		slog.Debug("client-secret-basic: missing Authorization header")
		return "", "", fmt.Errorf("missing Authorization header")
	}

	auth := strings.TrimSpace(authVals[0])
	const basicPrefix = "basic "
	if !strings.HasPrefix(strings.ToLower(auth), basicPrefix) {
		slog.Debug("client-secret-basic: Authorization header is not Basic scheme")
		return "", "", fmt.Errorf("Authorization header must use Basic scheme")
	}

	encoded := strings.TrimSpace(auth[len(basicPrefix):])
	decoded, decErr := base64.StdEncoding.DecodeString(encoded)
	if decErr != nil {
		slog.Debug("client-secret-basic: malformed Basic credentials", "error", decErr)
		return "", "", fmt.Errorf("malformed Basic credentials")
	}
	parts := strings.SplitN(string(decoded), ":", 2)
	if len(parts) != 2 || parts[0] == "" {
		slog.Debug("client-secret-basic: Basic credential not in clientId:clientSecret format")
		return "", "", fmt.Errorf("Basic credential format must be clientId:clientSecret")
	}

	clientId, err = url.QueryUnescape(parts[0])
	if err != nil {
		slog.Debug("client-secret-basic: invalid percent-encoding in client ID")
		return "", "", fmt.Errorf("malformed Basic credentials")
	}
	clientSecret, err = url.QueryUnescape(parts[1])
	if err != nil {
		slog.Debug("client-secret-basic: invalid percent-encoding in client secret")
		return "", "", fmt.Errorf("malformed Basic credentials")
	}
	return clientId, clientSecret, nil
}

// OnRequestHeaders validates the Authorization: Basic credential and, on success,
// strips the Authorization and Subscription-Key headers and injects the client identity.
func (p *ClientSecretBasicPolicy) OnRequestHeaders(
	ctx context.Context,
	reqCtx *policy.RequestHeaderContext,
	params map[string]interface{},
) policy.RequestHeaderAction {
	if ctx == nil || reqCtx == nil || reqCtx.SharedContext == nil {
		return unauthorizedResponse("request context is missing")
	}

	headers := reqCtx.Headers
	if headers == nil {
		return unauthorizedResponse("no request headers available")
	}

	// Reject subscription key injection before subscription-validation can read it.
	// subscription-validation checks the subscription key header first; a client with
	// no subscription can send another subscription's key and get that plan's
	// entitlements. Rejecting here ties the subscription to the authenticated identity.
	if len(headers.Get(p.cfg.SubscriptionKeyHeader)) > 0 {
		slog.Debug("client-secret-basic: request carries subscription key header, rejecting",
			"header", p.cfg.SubscriptionKeyHeader)
		return unauthorizedResponse("subscription key header is not permitted")
	}
	if p.cfg.SubscriptionKeyCookie != "" {
		cookieLines := headers.Get("Cookie")
		if len(cookieLines) > 0 {
			fakeReq := &http.Request{Header: http.Header{"Cookie": cookieLines}}
			if c, _ := fakeReq.Cookie(p.cfg.SubscriptionKeyCookie); c != nil {
				slog.Debug("client-secret-basic: request carries subscription cookie, rejecting",
					"cookie", p.cfg.SubscriptionKeyCookie)
				return unauthorizedResponse("subscription cookie is not permitted")
			}
		}
	}

	clientId, clientSecret, err := extractBasicCredentials(headers)
	if err != nil {
		return unauthorizedResponse(err.Error())
	}

	var accessToken string
	switch p.cfg.Mode {
	case modeDynamic:
		// Capture the raw Authorization header to forward unchanged to the IdP,
		// avoiding a double-decode of percent-encoded characters (RFC 6749 §2.3.1).
		rawAuth := headers.Get("Authorization")[0]
		var err error
		accessToken, err = p.validateDynamic(ctx, clientId, clientSecret, rawAuth)
		if err != nil {
			var netErr networkError
			if errors.As(err, &netErr) {
				slog.Warn("client-secret-basic: IdP/network outage", "clientId", clientId, "error", err)
				return serviceUnavailableResponse("service temporarily unavailable")
			}
			var throttleErr throttleError
			if errors.As(err, &throttleErr) {
				slog.Debug("client-secret-basic: failure rate limit reached", "clientId", clientId)
				return tooManyRequestsResponse("too many failed attempts — retry after the rate-limit window resets", throttleErr.retryAfter)
			}
			slog.Debug("client-secret-basic: dynamic validation failed", "clientId", clientId)
			return unauthorizedResponse("invalid credentials")
		}
	default:
		if err := p.validateStatic(clientId, clientSecret); err != nil {
			slog.Debug("client-secret-basic: static validation failed", "clientId", clientId)
			return unauthorizedResponse("invalid credentials")
		}
	}

	return p.successResponse(reqCtx.SharedContext, clientId, accessToken)
}

// validateStatic checks the credential pair against the configured map using
// constant-time comparison to prevent timing attacks.
func (p *ClientSecretBasicPolicy) validateStatic(clientId, clientSecret string) error {
	expected, found := p.cfg.Credentials[clientId]
	if !found {
		return fmt.Errorf("unknown client")
	}
	if subtle.ConstantTimeCompare([]byte(clientSecret), []byte(expected)) != 1 {
		return fmt.Errorf("mismatched credentials")
	}
	return nil
}

// validateDynamic checks the in-process cache first. On a miss it applies two layers of
// failure protection before making an IdP call:
//  1. Wrong-credential pair cache: a confirmed bad (clientId, secret) pair returns 401
//     immediately without an IdP call. Repeats of the same wrong secret never hit the IdP.
//  2. Per-clientId throttle: each distinct new wrong credential for a clientId reserves
//     one slot from a per-window counter inside the singleflight fn(). When the counter
//     reaches FailureRateLimit, further attempts return throttleError (→ 429) until the
//     window resets. The reservation is released on success or network error so valid
//     requests don't consume failure quota.
//
// Concurrent requests for the same credential pair are deduplicated via singleflight so
// only one IdP call is made per unique (clientId, secret) burst. The counter increments
// exactly once per singleflight group — not once per waiting goroutine.
// Only HTTP 400/401 responses from the token endpoint are treated as rejections; 429 and
// other 4xx/5xx return networkError (→ 503) and are never cached.
func (p *ClientSecretBasicPolicy) validateDynamic(ctx context.Context, clientId, clientSecret, rawAuth string) (string, error) {
	// Reject over-long client IDs before they reach the throttle map or IdP.
	// Oversized IDs can bloat the counter map (the hash must be computed first).
	if len(clientId) > maxDynamicClientIDLen {
		return "", fmt.Errorf("client ID too long")
	}

	key := cacheKey(clientId, clientSecret)

	// Check success cache.
	if v, ok := p.state.cache.Load(key); ok {
		entry := v.(validationEntry)
		if time.Now().Before(entry.expiresAt) {
			return entry.accessToken, nil
		}
		p.state.cache.Delete(key)
	}

	// Layer 1: exact wrong-credential pair cache — no IdP call for known-bad credentials.
	if p.state.failures.isWrongCred(key) {
		return "", fmt.Errorf("credentials rejected (cached)")
	}

	// Layer 2: fast-path throttle check (non-authoritative; avoids singleflight overhead).
	// The authoritative check+increment happens inside the singleflight fn().
	if throttled, remaining := p.state.failures.isThrottled(clientId, p.cfg.FailureRateLimit, p.cfg.FailureWindow); throttled {
		return "", throttleError{clientId: clientId, retryAfter: remaining}
	}

	// Deduplicate concurrent first requests for the same credential pair. The throttle
	// reservation happens inside fn() so exactly one slot is consumed per IdP call,
	// regardless of how many goroutines are waiting on this credential pair.
	result, err := p.state.sf.do(key, func() (sfResult, error) {
		// Re-check the success cache at callback start. A request that passed the
		// outer cache check before a completed flight published its entry can enter
		// here after the flight is removed but before the outer store runs. Finding
		// the entry now avoids a redundant token request.
		if v, ok := p.state.cache.Load(key); ok {
			entry := v.(validationEntry)
			if time.Now().Before(entry.expiresAt) {
				return sfResult{accessToken: entry.accessToken, expiresAt: entry.expiresAt}, nil
			}
			p.state.cache.Delete(key)
		}
		// Re-check wrongCreds inside the singleflight fn. A request that arrives just
		// as a prior IdP call for the same wrong credential finishes can miss both the
		// singleflight group and the outer wrongCreds check; checking here closes that
		// gap so it never starts a redundant IdP call.
		if p.state.failures.isWrongCred(key) {
			return sfResult{}, fmt.Errorf("credentials rejected (cached)")
		}
		// Atomically check and reserve a failure slot. Each singleflight group is one
		// distinct credential attempt, so the counter increments once per IdP call.
		rsv, reserveErr := p.state.failures.checkAndReserve(clientId, p.cfg.FailureRateLimit, p.cfg.FailureWindow)
		if reserveErr != nil {
			return sfResult{}, reserveErr
		}

		accessToken, expiresIn, err := p.doTokenRequest(ctx, rawAuth)
		if err != nil {
			var netErr networkError
			if errors.As(err, &netErr) {
				// Network/server error: return the slot so it doesn't count as a failure.
				p.state.failures.releaseReservation(clientId, rsv)
			} else {
				// Auth rejection: keep the slot, store the specific bad pair.
				p.state.failures.storeWrongCred(key, p.cfg.FailureWindow)
			}
			return sfResult{}, err
		}
		// Success: return the slot (it was a speculative increment).
		p.state.failures.releaseReservation(clientId, rsv)

		// Compute absolute cache expiry inside the callback so all waiting goroutines
		// reuse the same value rather than each computing it at their own resume time.
		//
		// Three cases:
		//   expiresIn absent (nil)   → 1-hour fallback minus buffer
		//   expiresIn ≤ 0            → token is already expired; store with past expiry
		//                              so the entry is treated as a cache miss immediately
		//   expiresIn > 0            → use it minus buffer (minimum 1 second)
		now := time.Now()
		var expiresAt time.Time
		if expiresIn == nil {
			ttl := defaultTokenTTLFallback - p.cfg.ExpiryBuffer
			if ttl <= 0 {
				ttl = defaultFailureWindow
			}
			expiresAt = now.Add(ttl)
		} else if *expiresIn <= 0 {
			expiresAt = now // immediate expiry — do not cache
		} else {
			ttl := time.Duration(*expiresIn*float64(time.Second)) - p.cfg.ExpiryBuffer
			if ttl <= 0 {
				ttl = time.Second
			}
			expiresAt = now.Add(ttl)
		}
		if p.cfg.MaxCacheTTL > 0 {
			if maxExpiry := now.Add(p.cfg.MaxCacheTTL); expiresAt.After(maxExpiry) {
				expiresAt = maxExpiry
			}
		}
		// Store the entry inside the callback — before singleflight removes the flight
		// from its work map — so any concurrent request that misses the flight finds
		// the populated cache entry instead of starting another token request.
		p.state.cache.Store(key, validationEntry{expiresAt: expiresAt, accessToken: accessToken})
		return sfResult{accessToken: accessToken, expiresAt: expiresAt}, nil
	})
	if err != nil {
		return "", err
	}

	return result.accessToken, nil
}

// tokenResponseJSON is the subset of an RFC 6749 §5.1 response this policy needs.
// ExpiresIn is a pointer to distinguish an absent field from an explicit zero value.
type tokenResponseJSON struct {
	AccessToken string   `json:"access_token"`
	ExpiresIn   *float64 `json:"expires_in"`
}

// doTokenRequest POSTs a client_credentials grant to the token endpoint, forwarding
// the client's Authorization: Basic header unchanged so percent-encoded characters
// are not double-decoded (RFC 6749 §2.3.1). Transport failures, 429, and non-400/401
// 4xx/5xx responses return networkError (maps to 503 and are not cached). Only HTTP
// 400 and 401 (the statuses RFC 6749 §5.2 defines for invalid_client) return a plain
// error (maps to 401 and is cached per clientId).
func (p *ClientSecretBasicPolicy) doTokenRequest(ctx context.Context, rawAuth string) (string, *float64, error) {
	form := url.Values{"grant_type": {"client_credentials"}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.cfg.TokenEndpoint,
		strings.NewReader(form.Encode()))
	if err != nil {
		return "", nil, networkError{fmt.Errorf("building token request: %w", err)}
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", rawAuth)

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return "", nil, networkError{fmt.Errorf("token request failed: %w", err)}
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxTokenResponseBytes))
	if err != nil {
		return "", nil, networkError{fmt.Errorf("reading token response: %w", err)}
	}

	if resp.StatusCode == http.StatusOK {
		var tok tokenResponseJSON
		if err := json.Unmarshal(body, &tok); err != nil {
			return "", nil, networkError{fmt.Errorf("parsing token response: %w", err)}
		}
		if tok.AccessToken == "" {
			return "", nil, networkError{fmt.Errorf("token endpoint returned no access_token")}
		}
		return tok.AccessToken, tok.ExpiresIn, nil
	}

	// RFC 6749 §5.2: 400 Bad Request and 401 Unauthorized signal an invalid client.
	// These are cacheable auth rejections. All other failures (429 Too Many Requests,
	// other 4xx, 5xx) are transient and must not be cached.
	if resp.StatusCode == http.StatusBadRequest || resp.StatusCode == http.StatusUnauthorized {
		return "", nil, fmt.Errorf("token endpoint rejected credentials: HTTP %d", resp.StatusCode)
	}
	return "", nil, networkError{fmt.Errorf("token endpoint returned status %d", resp.StatusCode)}
}

// cacheKey returns a stable, non-reversible key for the (clientId, clientSecret) pair.
// Length-prefixed encoding avoids collisions when clientId or clientSecret contains the
// separator character — e.g. ("a:b", "c") and ("a", "b:c") must hash to different keys.
func cacheKey(clientId, clientSecret string) string {
	h := sha256.Sum256([]byte(fmt.Sprintf("%d\x00%s\x00%s", len(clientId), clientId, clientSecret)))
	return fmt.Sprintf("%x", h)
}

// clientCounterKey returns a stable, non-reversible key for the per-clientId throttle
// counter. Hashing bounds the key size regardless of how long the raw clientId is,
// preventing memory growth from oversized client IDs.
func clientCounterKey(clientId string) string {
	h := sha256.Sum256([]byte(clientId))
	return fmt.Sprintf("%x", h)
}

// successResponse populates auth context, sets the application identity, and strips
// the Authorization and Subscription-Key headers before forwarding upstream.
// The authenticated clientId always overwrites any prior x-wso2-application-id value
// so subscription-validation sees the credential that was actually authenticated.
// token is the access token returned by the IdP (dynamic mode only; empty in static
// mode). When TokenMetadataKey is configured and token is non-empty it is stored in
// SharedContext.Metadata so downstream policies (e.g. header-transform) can read it.
func (p *ClientSecretBasicPolicy) successResponse(
	shared *policy.SharedContext,
	clientId string,
	token string,
) policy.RequestHeaderAction {
	shared.AuthContext = &policy.AuthContext{
		Authenticated: true,
		AuthType:      authType,
		Subject:       clientId,
		CredentialID:  clientId,
		Previous:      shared.AuthContext,
		Properties: map[string]string{
			"ClientId": clientId,
		},
	}

	if shared.Metadata == nil {
		shared.Metadata = make(map[string]interface{})
	}
	shared.Metadata[applicationIDMetadataKey] = clientId

	if p.cfg.TokenMetadataKey != "" && token != "" {
		shared.Metadata[p.cfg.TokenMetadataKey] = token
	}

	return policy.UpstreamRequestHeaderModifications{
		HeadersToRemove: []string{"Authorization", p.cfg.SubscriptionKeyHeader},
		AnalyticsMetadata: map[string]any{
			"clientId":               clientId,
			applicationIDMetadataKey: clientId,
		},
	}
}

// OnResponseHeaders is a no-op — this policy only acts on the request.
func (p *ClientSecretBasicPolicy) OnResponseHeaders(
	ctx context.Context,
	respCtx *policy.ResponseHeaderContext,
	params map[string]interface{},
) policy.ResponseHeaderAction {
	return policy.DownstreamResponseHeaderModifications{}
}

func unauthorizedResponse(detail string) policy.RequestHeaderAction {
	msg := "Unauthorized"
	if detail != "" {
		msg = fmt.Sprintf("Unauthorized: %s", detail)
	}
	body, err := json.Marshal(map[string]string{
		"error":   "unauthorized",
		"message": msg,
	})
	if err != nil {
		body = []byte(`{"error":"unauthorized","message":"authentication failed"}`)
	}
	return policy.ImmediateResponse{
		StatusCode: http.StatusUnauthorized,
		Headers: map[string]string{
			"Content-Type":     "application/json",
			"WWW-Authenticate": `Basic realm="API Gateway"`,
		},
		Body: body,
	}
}

func serviceUnavailableResponse(detail string) policy.RequestHeaderAction {
	msg := "Service Unavailable"
	if detail != "" {
		msg = detail
	}
	body, err := json.Marshal(map[string]string{
		"error":   "service_unavailable",
		"message": msg,
	})
	if err != nil {
		body = []byte(`{"error":"service_unavailable","message":"Service Unavailable"}`)
	}
	return policy.ImmediateResponse{
		StatusCode: http.StatusServiceUnavailable,
		Headers: map[string]string{
			"Content-Type": "application/json",
		},
		Body: body,
	}
}

func tooManyRequestsResponse(detail string, retryAfter time.Duration) policy.RequestHeaderAction {
	msg := "Too Many Requests"
	if detail != "" {
		msg = detail
	}
	body, err := json.Marshal(map[string]string{
		"error":   "too_many_requests",
		"message": msg,
	})
	if err != nil {
		body = []byte(`{"error":"too_many_requests","message":"Too Many Requests"}`)
	}
	// Round up so a client that waits exactly Retry-After seconds doesn't retry
	// before the window has actually reset.
	secs := int(math.Ceil(retryAfter.Seconds()))
	if secs < 1 {
		secs = 1
	}
	return policy.ImmediateResponse{
		StatusCode: http.StatusTooManyRequests,
		Headers: map[string]string{
			"Content-Type": "application/json",
			"Retry-After":  fmt.Sprintf("%d", secs),
		},
		Body: body,
	}
}
