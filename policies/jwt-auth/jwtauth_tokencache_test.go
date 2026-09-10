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

package jwtauth

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// expectedCacheKey reconstructs the cache key OnRequestHeaders would compute for a given
// verification config, so tests can inspect the cache directly. The cache key carries no API
// identity — see TestTokenCache_SharedAcrossAPIs_ConstraintsStillEnforcedPerAPI.
//
// This helper (and anything that calls it) depends on tokenConfigFingerprint's current,
// API-identity-free signature, so it cannot build against a pre-refactor baseline; that is why
// this file and jwtauth_scopeclaim_test.go, its other caller, are both in benchmark.sh's
// BASELINE_EXCLUDE. createMockRequestHeaderContextWithAPI and clearJWKSFetchCache live in
// jwtauth_hardening_test.go instead, precisely so the *other* tests that use them (which do not
// depend on this signature) stay baseline-buildable.
//
// tokenCacheTtl and negativeCacheTtl default to OnRequestHeaders' own defaults (5m/30s) so
// existing callers that don't configure them keep computing the same key; a caller that sets
// either param must pass the matching duration here too, or the reconstructed key won't match
// what OnRequestHeaders actually used (see tokenConfigFingerprintFromDigest).
func expectedCacheKey(params map[string]interface{}, token string, validateIssuer bool, issuers []string, leeway time.Duration) string {
	return expectedCacheKeyWithTTLs(params, token, validateIssuer, issuers, leeway, defaultTokenCacheTtl, defaultNegativeCacheTtl)
}

// expectedCacheKeyWithTTLs is expectedCacheKey for a test that configures a non-default
// tokenCacheTtl and/or negativeCacheTtl, both of which are now folded into the fingerprint (see
// tokenConfigFingerprintFromDigest) so routes with different TTLs never share a cache entry.
func expectedCacheKeyWithTTLs(params map[string]interface{}, token string, validateIssuer bool, issuers []string, leeway, tokenCacheTtl, negativeCacheTtl time.Duration) string {
	fingerprint := tokenConfigFingerprint(params["keyManagers"], validateIssuer, issuers, leeway, tokenCacheTtl, negativeCacheTtl)
	return buildTokenCacheKey(fingerprint, token)
}

func TestTokenCache_PositiveHit_SkipsVerification(t *testing.T) {
	resetJWTAuthSingletonCache(t)

	privateKey, publicKey := generateTestKeys(t)
	var fetchCount int32
	jwksServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/jwks.json" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		atomic.AddInt32(&fetchCount, 1)
		writeJWKSResponse(t, w, publicKey, "test-kid")
	}))

	params := newRemoteParams(jwksServer.URL + "/jwks.json")
	token := createTestToken(t, privateKey, map[string]interface{}{
		"sub": "user-cache-1",
		"iss": "https://issuer.example.com",
	})

	p := mustGetPolicy(t, params)

	ctx1 := createMockRequestHeaderContext(authHeader("Authorization", "Bearer", token))
	action1 := p.(*JwtAuthPolicy).OnRequestHeaders(context.Background(), ctx1, params)
	assertAuthSuccess(t, ctx1, action1)
	if got := atomic.LoadInt32(&fetchCount); got != 1 {
		t.Fatalf("expected exactly 1 JWKS fetch after the first request, got %d", got)
	}

	// Clear the unrelated JWKS-fetch cache and take down the endpoint, so that anything which
	// falls through to full re-verification is forced to hit the (now-dead) network.
	clearJWKSFetchCache()
	jwksServer.Close()

	ctx2 := createMockRequestHeaderContext(authHeader("Authorization", "Bearer", token))
	action2 := p.(*JwtAuthPolicy).OnRequestHeaders(context.Background(), ctx2, params)
	assertAuthSuccess(t, ctx2, action2)

	// A different API identity, with otherwise identical verification config, must also hit the
	// same shared verdict cache entry rather than attempt full re-verification: the cache key
	// carries no API identity (see TestTokenCache_SharedAcrossAPIs_ConstraintsStillEnforcedPerAPI).
	ctx3 := createMockRequestHeaderContextWithAPI(authHeader("Authorization", "Bearer", token), "api-2", "OtherAPI")
	action3 := p.(*JwtAuthPolicy).OnRequestHeaders(context.Background(), ctx3, params)
	assertAuthSuccess(t, ctx3, action3)
}

// TestTokenCache_SharedAcrossAPIs_ConstraintsStillEnforcedPerAPI proves the property that makes
// sharing the verdict cache across APIs safe: the cached signature verdict is reused regardless
// of API identity, but audience/scope/claim constraints are per-request config kept out of the
// cache key (see finishAuthentication), so they are still enforced independently for every API.
func TestTokenCache_SharedAcrossAPIs_ConstraintsStillEnforcedPerAPI(t *testing.T) {
	resetJWTAuthSingletonCache(t)

	privateKey, publicKey := generateTestKeys(t)
	var fetchCount int32
	jwksServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/jwks.json" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		atomic.AddInt32(&fetchCount, 1)
		writeJWKSResponse(t, w, publicKey, "test-kid")
	}))
	defer jwksServer.Close()

	token := createTestToken(t, privateKey, map[string]interface{}{
		"sub": "user-shared",
		"iss": "https://issuer.example.com",
		"aud": "api-x-audience",
	})

	// Identical verification config (keyManagers, issuers, validateIssuer, leeway) for both APIs
	// is what makes the cache key collide; audiences is per-API and not part of that config.
	paramsX := newRemoteParams(jwksServer.URL + "/jwks.json")
	paramsY := newRemoteParams(jwksServer.URL + "/jwks.json")
	paramsY["audiences"] = []interface{}{"api-y-audience"}

	p := mustGetPolicy(t, paramsX)

	// API X: no audience constraint — accepted, and the verdict is cached.
	ctxX := createMockRequestHeaderContextWithAPI(authHeader("Authorization", "Bearer", token), "api-x", "APIX")
	actionX := p.(*JwtAuthPolicy).OnRequestHeaders(context.Background(), ctxX, paramsX)
	assertAuthSuccess(t, ctxX, actionX)
	if got := atomic.LoadInt32(&fetchCount); got != 1 {
		t.Fatalf("expected exactly 1 JWKS fetch after API X's request, got %d", got)
	}

	// Unlike the sibling tests in this file, the JWKS endpoint stays live from here on: a verdict
	// cache hit and a verdict cache miss both end up 401 for API Y (X's audience-free verdict is
	// fine for Y's stricter config either way, since Y's own audience check denies it regardless
	// of which path produced the claims), so killing the server would make a miss fail for the
	// wrong reason — masking exactly the regression this test exists to catch, one that
	// reintroduces API identity into the cache key and turns every cross-API lookup into a miss.
	// Clearing the unrelated JWKS-fetch cache (see clearJWKSFetchCache) is still needed, though:
	// otherwise a verdict-cache miss would silently succeed off X's already-warm fetched keys for
	// this URI, and fetchCount would stay flat regardless of which path Y actually took. With it
	// cleared, a verdict-cache miss is forced to fetch fresh over the still-live network — an
	// extra fetch the assertion below catches — while a verdict-cache hit skips verification (and
	// so this fetch) entirely.
	clearJWKSFetchCache()

	// API Y: same verification config as X (so the same cache key), but its own audience
	// constraint the token does not satisfy. It must reuse X's cached signature verdict — no new
	// JWKS fetch — and still be denied by its own audience check.
	ctxY := createMockRequestHeaderContextWithAPI(authHeader("Authorization", "Bearer", token), "api-y", "APIY")
	actionY := p.(*JwtAuthPolicy).OnRequestHeaders(context.Background(), ctxY, paramsY)
	assertAuthFailure(t, ctxY, actionY, 401)
	if got := atomic.LoadInt32(&fetchCount); got != 1 {
		t.Fatalf("expected no new JWKS fetch for API Y (should reuse X's cached verdict), got %d fetches", got)
	}

	// API X, presented again, is still allowed: API Y's failing audience check did not corrupt or
	// consume the shared cache entry, and it is still served from cache rather than refetched.
	ctxX2 := createMockRequestHeaderContextWithAPI(authHeader("Authorization", "Bearer", token), "api-x", "APIX")
	actionX2 := p.(*JwtAuthPolicy).OnRequestHeaders(context.Background(), ctxX2, paramsX)
	assertAuthSuccess(t, ctxX2, actionX2)
	if got := atomic.LoadInt32(&fetchCount); got != 1 {
		t.Fatalf("expected no new JWKS fetch for API X's second request, got %d fetches", got)
	}
}

func TestTokenCache_NegativeHit_Expired(t *testing.T) {
	resetJWTAuthSingletonCache(t)

	privateKey, publicKey := generateTestKeys(t)
	jwksServer := createJWKSServer(t, publicKey, "test-kid")
	defer jwksServer.Close()

	params := newRemoteParams(jwksServer.URL + "/jwks.json")
	expiredToken := createTestTokenWithExpiry(t, privateKey, map[string]interface{}{
		"sub": "user-expired",
		"iss": "https://issuer.example.com",
	}, time.Now().Add(-time.Hour))

	p := mustGetPolicy(t, params)

	ctx1 := createMockRequestHeaderContext(authHeader("Authorization", "Bearer", expiredToken))
	action1 := p.(*JwtAuthPolicy).OnRequestHeaders(context.Background(), ctx1, params)
	assertAuthFailure(t, ctx1, action1, 401)

	key := expectedCacheKey(params, expiredToken, true, []string{}, 30*time.Second)
	verdict, hit := ins.getCachedVerdict(context.Background(), key)
	if !hit {
		t.Fatalf("expected a cached verdict for the expired token")
	}
	if verdict.ok {
		t.Fatalf("expected a negative verdict, got a positive one")
	}
	const wantReason = "token validation failed: token expired"
	if verdict.reason != wantReason {
		t.Fatalf("expected reason %q, got %q", wantReason, verdict.reason)
	}

	// Second identical request must be served from the negative cache.
	ctx2 := createMockRequestHeaderContext(authHeader("Authorization", "Bearer", expiredToken))
	action2 := p.(*JwtAuthPolicy).OnRequestHeaders(context.Background(), ctx2, params)
	assertAuthFailure(t, ctx2, action2, 401)
}

func TestTokenCache_NegativeHit_Malformed(t *testing.T) {
	resetJWTAuthSingletonCache(t)

	_, publicKey := generateTestKeys(t)
	jwksServer := createJWKSServer(t, publicKey, "test-kid")
	defer jwksServer.Close()

	params := newRemoteParams(jwksServer.URL + "/jwks.json")
	malformedToken := "not-a-jwt-token"

	p := mustGetPolicy(t, params)

	ctx1 := createMockRequestHeaderContext(authHeader("Authorization", "Bearer", malformedToken))
	action1 := p.(*JwtAuthPolicy).OnRequestHeaders(context.Background(), ctx1, params)
	assertAuthFailure(t, ctx1, action1, 401)

	key := expectedCacheKey(params, malformedToken, true, []string{}, 30*time.Second)
	verdict, hit := ins.getCachedVerdict(context.Background(), key)
	if !hit || verdict.ok || verdict.reason != "invalid token format" {
		t.Fatalf("expected cached negative verdict with reason %q, got hit=%v verdict=%+v", "invalid token format", hit, verdict)
	}

	ctx2 := createMockRequestHeaderContext(authHeader("Authorization", "Bearer", malformedToken))
	action2 := p.(*JwtAuthPolicy).OnRequestHeaders(context.Background(), ctx2, params)
	assertAuthFailure(t, ctx2, action2, 401)
}

func TestTokenCache_SignatureMismatch_NotCached(t *testing.T) {
	resetJWTAuthSingletonCache(t)

	_, publicKey := generateTestKeys(t)
	wrongPrivateKey, _ := generateTestKeys(t)

	jwksServer := createJWKSServer(t, publicKey, "test-kid")
	defer jwksServer.Close()

	params := newRemoteParams(jwksServer.URL + "/jwks.json")
	token := createTestToken(t, wrongPrivateKey, map[string]interface{}{
		"sub": "user-bad-sig",
		"iss": "https://issuer.example.com",
	})

	p := mustGetPolicy(t, params)
	ctx := createMockRequestHeaderContext(authHeader("Authorization", "Bearer", token))
	action := p.(*JwtAuthPolicy).OnRequestHeaders(context.Background(), ctx, params)
	assertAuthFailure(t, ctx, action, 401)

	key := expectedCacheKey(params, token, true, []string{}, 30*time.Second)
	if _, hit := ins.getCachedVerdict(context.Background(), key); hit {
		t.Fatalf("signature-mismatch failures must not be negatively cached")
	}
}

func TestTokenCache_JWKSFetchFailure_NotCached(t *testing.T) {
	resetJWTAuthSingletonCache(t)

	privateKey, _ := generateTestKeys(t)

	params := newRemoteParams("http://127.0.0.1:1/jwks.json") // reserved port, connection refused
	token := createTestToken(t, privateKey, map[string]interface{}{
		"sub": "user-fetch-fail",
		"iss": "https://issuer.example.com",
	})

	p := mustGetPolicy(t, params)
	ctx := createMockRequestHeaderContext(authHeader("Authorization", "Bearer", token))
	action := p.(*JwtAuthPolicy).OnRequestHeaders(context.Background(), ctx, params)
	assertAuthFailure(t, ctx, action, 401)

	key := expectedCacheKey(params, token, true, []string{}, 30*time.Second)
	if _, hit := ins.getCachedVerdict(context.Background(), key); hit {
		t.Fatalf("JWKS fetch failures must not be negatively cached")
	}
}

func TestTokenCache_NotYetValid_NotCached(t *testing.T) {
	resetJWTAuthSingletonCache(t)

	privateKey, publicKey := generateTestKeys(t)
	jwksServer := createJWKSServer(t, publicKey, "test-kid")
	defer jwksServer.Close()

	params := newRemoteParams(jwksServer.URL + "/jwks.json")
	token := createTestToken(t, privateKey, map[string]interface{}{
		"sub": "user-nbf",
		"iss": "https://issuer.example.com",
		"nbf": time.Now().Add(time.Hour).Unix(),
	})

	p := mustGetPolicy(t, params)
	ctx := createMockRequestHeaderContext(authHeader("Authorization", "Bearer", token))
	action := p.(*JwtAuthPolicy).OnRequestHeaders(context.Background(), ctx, params)
	assertAuthFailure(t, ctx, action, 401)

	key := expectedCacheKey(params, token, true, []string{}, 30*time.Second)
	if _, hit := ins.getCachedVerdict(context.Background(), key); hit {
		t.Fatalf("not-yet-valid (nbf) failures must not be negatively cached")
	}
}

func TestTokenCache_Disabled_NoCacheEntries(t *testing.T) {
	resetJWTAuthSingletonCache(t)

	privateKey, publicKey := generateTestKeys(t)
	jwksServer := createJWKSServer(t, publicKey, "test-kid")
	defer jwksServer.Close()

	params := newRemoteParams(jwksServer.URL + "/jwks.json")
	params["tokenCaching"] = false

	token := createTestToken(t, privateKey, map[string]interface{}{
		"sub": "user-disabled",
		"iss": "https://issuer.example.com",
	})

	p := mustGetPolicy(t, params)
	for i := 0; i < 2; i++ {
		ctx := createMockRequestHeaderContext(authHeader("Authorization", "Bearer", token))
		action := p.(*JwtAuthPolicy).OnRequestHeaders(context.Background(), ctx, params)
		assertAuthSuccess(t, ctx, action)
	}

	if got := ins.currentTokenCache().GetStats().Size; got != 0 {
		t.Fatalf("expected no cache entries when tokenCaching=false, got %d", got)
	}
}

func TestTokenCache_PositiveTTL_CappedByTokenCacheTtl(t *testing.T) {
	resetJWTAuthSingletonCache(t)

	privateKey, publicKey := generateTestKeys(t)
	jwksServer := createJWKSServer(t, publicKey, "test-kid")

	params := newRemoteParams(jwksServer.URL + "/jwks.json")
	params["tokenCacheTtl"] = "300ms"

	// Token exp is far in the future, so the cap must come from tokenCacheTtl, not the token.
	token := createTestToken(t, privateKey, map[string]interface{}{
		"sub": "user-ttl-cap",
		"iss": "https://issuer.example.com",
	})

	p := mustGetPolicy(t, params)

	before := time.Now()
	ctx := createMockRequestHeaderContext(authHeader("Authorization", "Bearer", token))
	action := p.(*JwtAuthPolicy).OnRequestHeaders(context.Background(), ctx, params)
	assertAuthSuccess(t, ctx, action)

	key := expectedCacheKeyWithTTLs(params, token, true, []string{}, 30*time.Second, 300*time.Millisecond, defaultNegativeCacheTtl)
	verdict, hit := ins.getCachedVerdict(context.Background(), key)
	if !hit || !verdict.ok {
		t.Fatalf("expected a cached positive verdict")
	}
	if verdict.expiresAt.After(before.Add(1 * time.Second)) {
		t.Fatalf("expected cache expiry capped near tokenCacheTtl (300ms), got expiresAt=%v (now=%v)", verdict.expiresAt, before)
	}

	time.Sleep(500 * time.Millisecond)
	// Clear the unrelated JWKS-fetch cache and take down the endpoint: if the verdict-cache
	// entry had survived, the second call would still succeed regardless of these two lines.
	clearJWKSFetchCache()
	jwksServer.Close()

	ctx2 := createMockRequestHeaderContext(authHeader("Authorization", "Bearer", token))
	action2 := p.(*JwtAuthPolicy).OnRequestHeaders(context.Background(), ctx2, params)
	assertAuthFailure(t, ctx2, action2, 401)
}

func TestTokenCache_PositiveTTL_NeverExceedsTokenExpiry(t *testing.T) {
	resetJWTAuthSingletonCache(t)

	privateKey, publicKey := generateTestKeys(t)
	jwksServer := createJWKSServer(t, publicKey, "test-kid")
	defer jwksServer.Close()

	params := newRemoteParams(jwksServer.URL + "/jwks.json")
	// tokenCacheTtl stays at its 5m default; the token itself expires in 3s, so the cache
	// entry's expiry must be bounded by the token's exp, not the far larger 5m cap.
	params["leeway"] = "0s"
	token := createTestToken(t, privateKey, map[string]interface{}{
		"sub": "user-short-exp",
		"iss": "https://issuer.example.com",
		"exp": time.Now().Add(3 * time.Second).Unix(),
	})

	p := mustGetPolicy(t, params)
	ctx := createMockRequestHeaderContext(authHeader("Authorization", "Bearer", token))
	action := p.(*JwtAuthPolicy).OnRequestHeaders(context.Background(), ctx, params)
	assertAuthSuccess(t, ctx, action)

	key := expectedCacheKey(params, token, true, []string{}, 0)
	verdict, hit := ins.getCachedVerdict(context.Background(), key)
	if !hit || !verdict.ok {
		t.Fatalf("expected a cached positive verdict")
	}
	if verdict.expiresAt.After(time.Now().Add(4 * time.Second)) {
		t.Fatalf("expected cache expiry bounded by the token's short exp, not the 5m tokenCacheTtl default; got %v", verdict.expiresAt)
	}
}

func TestTokenCache_NegativeTTL_ExpiresAfterWindow(t *testing.T) {
	resetJWTAuthSingletonCache(t)

	privateKey, publicKey := generateTestKeys(t)
	jwksServer := createJWKSServer(t, publicKey, "test-kid")
	defer jwksServer.Close()

	params := newRemoteParams(jwksServer.URL + "/jwks.json")
	params["negativeCacheTtl"] = "300ms"

	expiredToken := createTestTokenWithExpiry(t, privateKey, map[string]interface{}{
		"sub": "user-neg-ttl",
		"iss": "https://issuer.example.com",
	}, time.Now().Add(-time.Hour))

	p := mustGetPolicy(t, params)
	ctx := createMockRequestHeaderContext(authHeader("Authorization", "Bearer", expiredToken))
	action := p.(*JwtAuthPolicy).OnRequestHeaders(context.Background(), ctx, params)
	assertAuthFailure(t, ctx, action, 401)

	key := expectedCacheKeyWithTTLs(params, expiredToken, true, []string{}, 30*time.Second, defaultTokenCacheTtl, 300*time.Millisecond)
	if _, hit := ins.getCachedVerdict(context.Background(), key); !hit {
		t.Fatalf("expected a negative cache entry immediately after the failed request")
	}

	time.Sleep(500 * time.Millisecond)

	if _, hit := ins.getCachedVerdict(context.Background(), key); hit {
		t.Fatalf("expected the negative cache entry to have expired after negativeCacheTtl")
	}
}

func TestTokenConfigFingerprint_ChangesInvalidateCache(t *testing.T) {
	km := []interface{}{
		map[string]interface{}{
			"name":   "km-primary",
			"issuer": "https://issuer.example.com",
			"jwks": map[string]interface{}{
				"remote": map[string]interface{}{"uri": "https://idp.example/jwks.json"},
			},
		},
	}
	base := tokenConfigFingerprint(km, true, []string{"km-primary"}, 30*time.Second, 5*time.Minute, 30*time.Second)

	cases := []struct {
		name string
		fp   string
	}{
		{"different validateIssuer", tokenConfigFingerprint(km, false, []string{"km-primary"}, 30*time.Second, 5*time.Minute, 30*time.Second)},
		{"different issuers", tokenConfigFingerprint(km, true, []string{"other"}, 30*time.Second, 5*time.Minute, 30*time.Second)},
		{"different leeway", tokenConfigFingerprint(km, true, []string{"km-primary"}, time.Minute, 5*time.Minute, 30*time.Second)},
		// tokenCacheTtl/negativeCacheTtl determine nothing about the verdict itself, but a cached
		// verdict's expiresAt is set from the writing route's TTLs (see OnRequestHeaders), so two
		// routes with different TTLs must not collide on the same cache entry — see
		// TestTokenCache_DifferentTokenCacheTtl_DoesNotShareCacheEntry for the end-to-end behavior.
		{"different tokenCacheTtl", tokenConfigFingerprint(km, true, []string{"km-primary"}, 30*time.Second, time.Hour, 30*time.Second)},
		{"different negativeCacheTtl", tokenConfigFingerprint(km, true, []string{"km-primary"}, 30*time.Second, 5*time.Minute, time.Minute)},
	}
	for _, tc := range cases {
		if tc.fp == base {
			t.Errorf("%s: expected a different fingerprint, got the same value", tc.name)
		}
	}

	kmChanged := []interface{}{
		map[string]interface{}{
			"name":   "km-primary",
			"issuer": "https://issuer.example.com",
			"jwks": map[string]interface{}{
				"remote": map[string]interface{}{"uri": "https://idp.example/OTHER.json"},
			},
		},
	}
	if fp := tokenConfigFingerprint(kmChanged, true, []string{"km-primary"}, 30*time.Second, 5*time.Minute, 30*time.Second); fp == base {
		t.Errorf("different key manager config: expected a different fingerprint, got the same value")
	}

	if again := tokenConfigFingerprint(km, true, []string{"km-primary"}, 30*time.Second, 5*time.Minute, 30*time.Second); again != base {
		t.Errorf("expected tokenConfigFingerprint to be deterministic for identical inputs")
	}

	// API identity is deliberately excluded: it determines nothing about the verdict, so no
	// apiId/apiName parameter exists to vary here — see TestTokenCache_SharedAcrossAPIs_ConstraintsStillEnforcedPerAPI
	// for the corresponding end-to-end behavior.
}

func TestGetPolicy_TokenCacheMaxSizeApplied(t *testing.T) {
	resetJWTAuthSingletonCache(t)
	t.Cleanup(func() {
		ins.ensureTokenCache(defaultTokenCacheMaxSize)
	})

	params := newRemoteParams("http://127.0.0.1:1/jwks.json")
	params["cacheMaxSize"] = 5

	mustGetPolicy(t, params)

	if got := ins.currentTokenCache().GetStats().MaxSize; got != 5 {
		t.Fatalf("expected token cache MaxSize=5, got %d", got)
	}
}

func TestCacheMaxSize_GloballyBounded_TokenCache(t *testing.T) {
	resetJWTAuthSingletonCache(t)
	t.Cleanup(func() {
		ins.ensureTokenCache(defaultTokenCacheMaxSize)
	})

	privateKey, publicKey := generateTestKeys(t)
	jwksServer := createJWKSServer(t, publicKey, "test-kid")
	defer jwksServer.Close()

	params := newRemoteParams(jwksServer.URL + "/jwks.json")
	params["cacheMaxSize"] = 2

	p := mustGetPolicy(t, params)

	for i := 0; i < 5; i++ {
		token := createTestToken(t, privateKey, map[string]interface{}{
			"sub": fmt.Sprintf("user-bound-%d", i),
			"iss": "https://issuer.example.com",
		})
		ctx := createMockRequestHeaderContext(authHeader("Authorization", "Bearer", token))
		action := p.(*JwtAuthPolicy).OnRequestHeaders(context.Background(), ctx, params)
		assertAuthSuccess(t, ctx, action)
	}

	stats := ins.currentTokenCache().GetStats()
	if stats.Size > 2 {
		t.Fatalf("expected cache size bounded at 2, got %d", stats.Size)
	}
	if stats.EvictCount == 0 {
		t.Fatalf("expected at least one eviction once 5 distinct tokens exceeded the size-2 bound")
	}
}

// TestTokenCache_DifferentTokenCacheTtl_DoesNotShareCacheEntry locks in the fix for the TTL-bleed
// bug: two routes with identical verification config but different tokenCacheTtl must not collide
// on the same cache entry. Before tokenCacheTtl/negativeCacheTtl were folded into the fingerprint,
// route A (tokenCacheTtl=1h) and route B (tokenCacheTtl=200ms) computed the *same* cache key, so
// B's request would reuse A's hour-long entry and skip verification for up to an hour — exactly
// the exposure window tokenCacheTtl exists to bound (see policy-definition.yaml). With the fix,
// they compute different keys and each route's own TTL governs its own entry.
func TestTokenCache_DifferentTokenCacheTtl_DoesNotShareCacheEntry(t *testing.T) {
	resetJWTAuthSingletonCache(t)

	privateKey, publicKey := generateTestKeys(t)
	jwksServer := createJWKSServer(t, publicKey, "test-kid")
	defer jwksServer.Close()

	token := createTestToken(t, privateKey, map[string]interface{}{
		"sub": "user-ttl-bleed",
		"iss": "https://issuer.example.com",
	})

	// Route A and route B share every verification-relevant field except tokenCacheTtl.
	paramsA := newRemoteParams(jwksServer.URL + "/jwks.json")
	paramsA["tokenCacheTtl"] = "1h"
	paramsB := newRemoteParams(jwksServer.URL + "/jwks.json")
	paramsB["tokenCacheTtl"] = "200ms"

	keyA := expectedCacheKeyWithTTLs(paramsA, token, true, []string{}, 30*time.Second, time.Hour, defaultNegativeCacheTtl)
	keyB := expectedCacheKeyWithTTLs(paramsB, token, true, []string{}, 30*time.Second, 200*time.Millisecond, defaultNegativeCacheTtl)
	if keyA == keyB {
		t.Fatalf("expected different cache keys for different tokenCacheTtl, got the same key %q", keyA)
	}

	p := mustGetPolicy(t, paramsA)

	// Route A verifies and caches the verdict under its own (long-TTL) key.
	ctxA := createMockRequestHeaderContext(authHeader("Authorization", "Bearer", token))
	actionA := p.(*JwtAuthPolicy).OnRequestHeaders(context.Background(), ctxA, paramsA)
	assertAuthSuccess(t, ctxA, actionA)

	verdictA, hitA := ins.getCachedVerdict(context.Background(), keyA)
	if !hitA || !verdictA.ok {
		t.Fatalf("expected route A's positive verdict to be cached under its own key")
	}
	if verdictA.expiresAt.Before(time.Now().Add(30 * time.Minute)) {
		t.Fatalf("expected route A's entry to reflect its own 1h tokenCacheTtl, got expiresAt=%v", verdictA.expiresAt)
	}

	// Route B's key must have no entry yet: pre-fix, this would already be a hit — inherited from
	// route A's write — because the two routes computed the identical cache key.
	if _, hitB := ins.getCachedVerdict(context.Background(), keyB); hitB {
		t.Fatalf("route B must not inherit route A's cache entry merely because tokenCacheTtl differs")
	}

	// Route B verifies independently (JWKS server is still up) and caches its own short-TTL entry.
	ctxB := createMockRequestHeaderContext(authHeader("Authorization", "Bearer", token))
	actionB := p.(*JwtAuthPolicy).OnRequestHeaders(context.Background(), ctxB, paramsB)
	assertAuthSuccess(t, ctxB, actionB)

	verdictB, hitB := ins.getCachedVerdict(context.Background(), keyB)
	if !hitB || !verdictB.ok {
		t.Fatalf("expected route B's positive verdict to be cached under its own key")
	}
	if verdictB.expiresAt.After(time.Now().Add(1 * time.Second)) {
		t.Fatalf("expected route B's entry to reflect its own 200ms tokenCacheTtl, got expiresAt=%v", verdictB.expiresAt)
	}

	time.Sleep(300 * time.Millisecond)

	// Route B's short-lived entry has expired, but route A's hour-long entry is untouched:
	// each route's TTL governs only its own entry.
	if _, hitB := ins.getCachedVerdict(context.Background(), keyB); hitB {
		t.Fatalf("expected route B's entry to have expired after its 200ms tokenCacheTtl")
	}
	if _, hitA := ins.getCachedVerdict(context.Background(), keyA); !hitA {
		t.Fatalf("expected route A's entry to still be live; it must not have been affected by route B's short TTL")
	}
}

// TestConfigMemoizationCaches_ClearedByReset locks in that resetJWTAuthSingletonCache clears all
// three config-lifetime memoization caches, so memoized constraints/keys from one test cannot
// leak into the next (previously these had no reset hook at all). The caches themselves are
// deliberately left unbounded: an entry corresponds to one distinct certificate/scopes/claims
// configuration an operator deploys, never to anything a request can vary, so they grow only
// with config churn.
func TestConfigMemoizationCaches_ClearedByReset(t *testing.T) {
	resetJWTAuthSingletonCache(t)

	parsedPublicKeys.Store("pem-1", parsedPublicKey{})
	resolveScopeConstraintsCache.Store("scope-1", resolvedScopeConstraints{})
	resolveClaimConstraintsCache.Store("claim-1", resolvedClaimConstraints{})

	resetJWTAuthSingletonCache(t)

	for name, m := range map[string]*sync.Map{
		"parsedPublicKeys":             &parsedPublicKeys,
		"resolveScopeConstraintsCache": &resolveScopeConstraintsCache,
		"resolveClaimConstraintsCache": &resolveClaimConstraintsCache,
	} {
		count := 0
		m.Range(func(_, _ interface{}) bool {
			count++
			return true
		})
		if count != 0 {
			t.Fatalf("expected %s cleared by resetJWTAuthSingletonCache, got %d entries", name, count)
		}
	}
}
