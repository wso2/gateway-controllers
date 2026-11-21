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
	"testing"
	"time"
)

// withScopeClaim configures the single key manager created by newRemoteParams to read scopes
// from a specific claim, optionally with a custom separator.
func withScopeClaim(t *testing.T, params map[string]interface{}, claim, separator string) {
	t.Helper()
	kms, ok := params["keyManagers"].([]interface{})
	if !ok || len(kms) == 0 {
		t.Fatalf("expected at least one key manager in params")
	}
	km := kms[0].(map[string]interface{})
	km["scopeClaim"] = claim
	if separator != "" {
		km["scopeClaimSeparator"] = separator
	}
}

// assertScopeSet asserts that scope set got contains exactly want (order-independent).
func assertScopeSet(t *testing.T, got map[string]bool, want ...string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("expected %d scopes %v, got %v", len(want), want, got)
	}
	for _, s := range want {
		if !got[s] {
			t.Fatalf("expected scope %q to be present, got %v", s, got)
		}
	}
}

// assertScopeSliceSet asserts that slice got contains exactly want (order-independent).
func assertScopeSliceSet(t *testing.T, got []string, want ...string) {
	t.Helper()
	m := make(map[string]bool, len(got))
	for _, s := range got {
		m[s] = true
	}
	assertScopeSet(t, m, want...)
}

// TestJWTAuthPolicy_ScopeClaim_StringCustomSeparator verifies a key manager configured with a
// custom string scope claim and separator reads scopes from that claim only. The standard "scope"
// claim carries a value that would fail the requiredScopes check if it were (wrongly) consulted.
func TestJWTAuthPolicy_ScopeClaim_StringCustomSeparator(t *testing.T) {
	resetJWTAuthSingletonCache(t)

	privateKey, publicKey := generateTestKeys(t)
	jwksServer := createJWKSServer(t, publicKey, "test-kid")
	defer jwksServer.Close()

	token := createTestToken(t, privateKey, map[string]interface{}{
		"sub":        "user-123",
		"iss":        "https://issuer.example.com",
		"scope":      "denied",
		"scope_list": "api:read,api:write,api:admin",
	})

	params := newRemoteParams(jwksServer.URL + "/jwks.json")
	withScopeClaim(t, params, "scope_list", ",")
	params["requiredScopes"] = []interface{}{"api:write"}

	ctx, action := executeOnRequestHeaders(t, params, authHeader("Authorization", "Bearer", token))
	assertAuthSuccess(t, ctx, action)
	// The ":" inside each scope is part of the scope name and must survive the "," split.
	assertScopeSet(t, ctx.SharedContext.AuthContext.Scopes, "api:read", "api:write", "api:admin")
}

// TestJWTAuthPolicy_ScopeClaim_ArrayClaim verifies a key manager configured with a custom claim
// whose value is a string array reads the array elements as scopes (the separator is irrelevant).
func TestJWTAuthPolicy_ScopeClaim_ArrayClaim(t *testing.T) {
	resetJWTAuthSingletonCache(t)

	privateKey, publicKey := generateTestKeys(t)
	jwksServer := createJWKSServer(t, publicKey, "test-kid")
	defer jwksServer.Close()

	token := createTestToken(t, privateKey, map[string]interface{}{
		"sub":   "user-123",
		"iss":   "https://issuer.example.com",
		"scope": "denied",
		"roles": []interface{}{"api:read", "api:write"},
	})

	params := newRemoteParams(jwksServer.URL + "/jwks.json")
	// No separator configured: it does not apply to an array-valued claim.
	withScopeClaim(t, params, "roles", "")
	params["requiredScopes"] = []interface{}{"api:write"}

	ctx, action := executeOnRequestHeaders(t, params, authHeader("Authorization", "Bearer", token))
	assertAuthSuccess(t, ctx, action)
	assertScopeSet(t, ctx.SharedContext.AuthContext.Scopes, "api:read", "api:write")
}

// TestJWTAuthPolicy_ScopeClaim_MissingClaimDenies verifies fail-closed behavior: when a scopeClaim
// is configured but absent from the token, scopes resolve to the empty set and a requiredScopes
// check denies the request. The standard "scope" claim does contain the required scope, proving
// the policy does not silently fall back to it once a scopeClaim is configured.
func TestJWTAuthPolicy_ScopeClaim_MissingClaimDenies(t *testing.T) {
	resetJWTAuthSingletonCache(t)

	privateKey, publicKey := generateTestKeys(t)
	jwksServer := createJWKSServer(t, publicKey, "test-kid")
	defer jwksServer.Close()

	token := createTestToken(t, privateKey, map[string]interface{}{
		"sub":   "user-123",
		"iss":   "https://issuer.example.com",
		"scope": "api:read",
	})

	params := newRemoteParams(jwksServer.URL + "/jwks.json")
	withScopeClaim(t, params, "scope_list", ",")
	params["requiredScopes"] = []interface{}{"api:read"}

	ctx, action := executeOnRequestHeaders(t, params, authHeader("Authorization", "Bearer", token))
	assertAuthFailure(t, ctx, action, 401)
}

// TestJWTAuthPolicy_ScopeClaim_CacheHitPreservesResolvedScopes verifies the token verdict cache
// stores the scopes resolved from the matched key manager's scopeClaim, so a cache hit — which
// cannot re-derive the matched key manager — enforces scopes and populates AuthContext.Scopes
// identically to the cache-miss path.
func TestJWTAuthPolicy_ScopeClaim_CacheHitPreservesResolvedScopes(t *testing.T) {
	resetJWTAuthSingletonCache(t)

	privateKey, publicKey := generateTestKeys(t)
	jwksServer := createJWKSServer(t, publicKey, "test-kid")

	token := createTestToken(t, privateKey, map[string]interface{}{
		"sub":        "user-cache-scope",
		"iss":        "https://issuer.example.com",
		"scope":      "denied",
		"scope_list": "api:read,api:write",
	})

	params := newRemoteParams(jwksServer.URL + "/jwks.json")
	withScopeClaim(t, params, "scope_list", ",")
	params["requiredScopes"] = []interface{}{"api:write"}

	p := mustGetPolicy(t, params)

	// First request: cache miss, full verification, scopes resolved from the custom claim.
	ctx1 := createMockRequestHeaderContext(authHeader("Authorization", "Bearer", token))
	action1 := p.(*JwtAuthPolicy).OnRequestHeaders(context.Background(), ctx1, params)
	assertAuthSuccess(t, ctx1, action1)
	assertScopeSet(t, ctx1.SharedContext.AuthContext.Scopes, "api:read", "api:write")

	// The cached verdict must carry the resolved (custom-claim) scopes, not the standard "scope".
	key := expectedCacheKey(params, token, true, []string{}, 30*time.Second)
	verdict, hit := ins.getCachedVerdict(context.Background(), key)
	if !hit || !verdict.ok {
		t.Fatalf("expected a positive cached verdict, got hit=%v ok=%v", hit, verdict.ok)
	}
	assertScopeSliceSet(t, verdict.scopes, "api:read", "api:write")

	// Take down the endpoint and clear the JWKS-fetch cache so any fall-through to full
	// re-verification would fail. A verdict-cache hit must still succeed using the stored scopes.
	clearJWKSFetchCache()
	jwksServer.Close()

	ctx2 := createMockRequestHeaderContext(authHeader("Authorization", "Bearer", token))
	action2 := p.(*JwtAuthPolicy).OnRequestHeaders(context.Background(), ctx2, params)
	assertAuthSuccess(t, ctx2, action2)
	assertScopeSet(t, ctx2.SharedContext.AuthContext.Scopes, "api:read", "api:write")
}

// TestJWTAuthPolicy_ScopeClaim_DefaultSpaceSeparator covers the most common production shape:
// a string scope claim delimited by spaces (the OAuth2 standard for the "scope" claim) whose
// scope names are namespaced with ":". No explicit separator is configured, so the default space
// separator applies and the ":" inside each scope name must be preserved.
func TestJWTAuthPolicy_ScopeClaim_DefaultSpaceSeparator(t *testing.T) {
	resetJWTAuthSingletonCache(t)

	privateKey, publicKey := generateTestKeys(t)
	jwksServer := createJWKSServer(t, publicKey, "test-kid")
	defer jwksServer.Close()

	token := createTestToken(t, privateKey, map[string]interface{}{
		"sub":          "user-123",
		"iss":          "https://issuer.example.com",
		"scope":        "denied",
		"custom_scope": "api:read api:write api:admin",
	})

	params := newRemoteParams(jwksServer.URL + "/jwks.json")
	// Separator omitted → defaults to a single space.
	withScopeClaim(t, params, "custom_scope", "")
	params["requiredScopes"] = []interface{}{"api:admin"}

	ctx, action := executeOnRequestHeaders(t, params, authHeader("Authorization", "Bearer", token))
	assertAuthSuccess(t, ctx, action)
	assertScopeSet(t, ctx.SharedContext.AuthContext.Scopes, "api:read", "api:write", "api:admin")
}
