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
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

// withApplicationIDClaim configures the single key manager created by newRemoteParams to read the
// application identity from claim.
func withApplicationIDClaim(t *testing.T, params map[string]interface{}, claim string) {
	t.Helper()
	kms, ok := params["keyManagers"].([]interface{})
	if !ok || len(kms) == 0 {
		t.Fatalf("expected at least one key manager in params")
	}
	kms[0].(map[string]interface{})["applicationIdClaim"] = claim
}

// assertApplicationID asserts both the shared-context metadata and the analytics metadata carry
// want. An empty want asserts that neither was set.
func assertApplicationID(t *testing.T, reqCtx *policy.RequestHeaderContext, action policy.RequestHeaderAction, want string) {
	t.Helper()
	mods, ok := action.(policy.UpstreamRequestHeaderModifications)
	if !ok {
		t.Fatalf("expected UpstreamRequestHeaderModifications, got %T", action)
	}
	got, present := reqCtx.SharedContext.Metadata[applicationIDMetadataKey]
	analytics, analyticsPresent := mods.AnalyticsMetadata[applicationIDMetadataKey]
	if want == "" {
		if present {
			t.Fatalf("expected no %s metadata, got %v", applicationIDMetadataKey, got)
		}
		if analyticsPresent {
			t.Fatalf("expected no %s analytics metadata, got %v", applicationIDMetadataKey, analytics)
		}
		return
	}
	if got != want {
		t.Fatalf("expected %s metadata %q, got %v (present=%v)", applicationIDMetadataKey, want, got, present)
	}
	if analytics != want {
		t.Fatalf("expected %s analytics metadata %q, got %v (present=%v)", applicationIDMetadataKey, want, analytics, analyticsPresent)
	}
}

// TestJWTAuthPolicy_ApplicationID_OffByDefault verifies the feature is opt-in: a token carrying
// client_id sets no application identity unless the key manager names the claim.
func TestJWTAuthPolicy_ApplicationID_OffByDefault(t *testing.T) {
	resetJWTAuthSingletonCache(t)

	privateKey, publicKey := generateTestKeys(t)
	jwksServer := createJWKSServer(t, publicKey, "test-kid")
	defer jwksServer.Close()

	token := createTestToken(t, privateKey, map[string]interface{}{
		"sub":       "user-123",
		"iss":       "https://issuer.example.com",
		"client_id": "client-abc",
	})

	params := newRemoteParams(jwksServer.URL + "/jwks.json")

	ctx, action := executeOnRequestHeaders(t, params, authHeader("Authorization", "Bearer", token))
	assertAuthSuccess(t, ctx, action)
	assertApplicationID(t, ctx, action, "")
}

// TestJWTAuthPolicy_ApplicationID_FromConfiguredClaim verifies the configured claim's value becomes
// the application identity, in both the shared metadata and analytics, for the default-style
// client_id claim and a custom one.
func TestJWTAuthPolicy_ApplicationID_FromConfiguredClaim(t *testing.T) {
	for _, tc := range []struct {
		name  string
		claim string
		want  string
	}{
		{name: "client_id", claim: "client_id", want: "client-abc"},
		{name: "custom azp", claim: "azp", want: "azp-xyz"},
		{name: "value is trimmed", claim: "padded", want: "padded-app"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resetJWTAuthSingletonCache(t)

			privateKey, publicKey := generateTestKeys(t)
			jwksServer := createJWKSServer(t, publicKey, "test-kid")
			defer jwksServer.Close()

			token := createTestToken(t, privateKey, map[string]interface{}{
				"sub":       "user-123",
				"iss":       "https://issuer.example.com",
				"client_id": "client-abc",
				"azp":       "azp-xyz",
				"padded":    "  padded-app  ",
			})

			params := newRemoteParams(jwksServer.URL + "/jwks.json")
			withApplicationIDClaim(t, params, tc.claim)

			ctx, action := executeOnRequestHeaders(t, params, authHeader("Authorization", "Bearer", token))
			assertAuthSuccess(t, ctx, action)
			assertApplicationID(t, ctx, action, tc.want)
		})
	}
}

// TestJWTAuthPolicy_ApplicationID_CredentialIDUnchanged verifies CredentialID keeps coming from the
// client_id claim when applicationIdClaim names a different claim with a different value, so OPA's
// consumerKey, backend-jwt's credential_id and analytics see no change.
func TestJWTAuthPolicy_ApplicationID_CredentialIDUnchanged(t *testing.T) {
	resetJWTAuthSingletonCache(t)

	privateKey, publicKey := generateTestKeys(t)
	jwksServer := createJWKSServer(t, publicKey, "test-kid")
	defer jwksServer.Close()

	token := createTestToken(t, privateKey, map[string]interface{}{
		"sub":       "user-123",
		"iss":       "https://issuer.example.com",
		"client_id": "client-abc",
		"azp":       "azp-xyz",
	})

	params := newRemoteParams(jwksServer.URL + "/jwks.json")
	withApplicationIDClaim(t, params, "azp")

	ctx, action := executeOnRequestHeaders(t, params, authHeader("Authorization", "Bearer", token))
	assertAuthSuccess(t, ctx, action)
	assertApplicationID(t, ctx, action, "azp-xyz")
	if got := ctx.SharedContext.AuthContext.CredentialID; got != "client-abc" {
		t.Fatalf("expected CredentialID to stay %q (from client_id), got %q", "client-abc", got)
	}
}

// TestJWTAuthPolicy_ApplicationID_PerKeyManager verifies the claim is taken from the key manager that
// verified the token, when key managers configure different claims.
func TestJWTAuthPolicy_ApplicationID_PerKeyManager(t *testing.T) {
	resetJWTAuthSingletonCache(t)

	privateKey, publicKey := generateTestKeys(t)
	jwksServer := createJWKSServer(t, publicKey, "test-kid")
	defer jwksServer.Close()

	params := newRemoteParams(jwksServer.URL + "/jwks.json")
	params["keyManagers"] = []interface{}{
		map[string]interface{}{
			"name":               "km-a",
			"issuer":             "https://issuer-a.example.com",
			"applicationIdClaim": "azp",
			"jwks":               map[string]interface{}{"remote": map[string]interface{}{"uri": jwksServer.URL + "/jwks.json"}},
		},
		map[string]interface{}{
			"name":               "km-b",
			"issuer":             "https://issuer-b.example.com",
			"applicationIdClaim": "cid",
			"jwks":               map[string]interface{}{"remote": map[string]interface{}{"uri": jwksServer.URL + "/jwks.json"}},
		},
	}

	for _, tc := range []struct {
		issuer string
		want   string
	}{
		{issuer: "https://issuer-a.example.com", want: "azp-value"},
		{issuer: "https://issuer-b.example.com", want: "cid-value"},
	} {
		token := createTestToken(t, privateKey, map[string]interface{}{
			"sub": "user-123",
			"iss": tc.issuer,
			"azp": "azp-value",
			"cid": "cid-value",
		})
		ctx, action := executeOnRequestHeaders(t, params, authHeader("Authorization", "Bearer", token))
		assertAuthSuccess(t, ctx, action)
		assertApplicationID(t, ctx, action, tc.want)
	}
}

// TestJWTAuthPolicy_ApplicationID_UnusableClaimValue verifies a missing, non-string or blank claim
// sets no application identity and does not fail authentication: subscription-validation decides.
func TestJWTAuthPolicy_ApplicationID_UnusableClaimValue(t *testing.T) {
	for _, tc := range []struct {
		name  string
		value interface{}
	}{
		{name: "missing", value: nil},
		{name: "number", value: 12345},
		{name: "array", value: []interface{}{"app-1", "app-2"}},
		{name: "object", value: map[string]interface{}{"id": "app-1"}},
		{name: "blank", value: "   "},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resetJWTAuthSingletonCache(t)

			privateKey, publicKey := generateTestKeys(t)
			jwksServer := createJWKSServer(t, publicKey, "test-kid")
			defer jwksServer.Close()

			claims := map[string]interface{}{
				"sub": "user-123",
				"iss": "https://issuer.example.com",
			}
			if tc.value != nil {
				claims["app_claim"] = tc.value
			}
			token := createTestToken(t, privateKey, claims)

			params := newRemoteParams(jwksServer.URL + "/jwks.json")
			withApplicationIDClaim(t, params, "app_claim")

			ctx, action := executeOnRequestHeaders(t, params, authHeader("Authorization", "Bearer", token))
			assertAuthSuccess(t, ctx, action)
			assertApplicationID(t, ctx, action, "")
		})
	}
}

// TestJWTAuthPolicy_ApplicationID_RegisteredClaimIgnored verifies a registered claim configured as
// applicationIdClaim is ignored — authentication still succeeds and no identity is set — and is
// reported with a single warning however many times the key managers are parsed.
func TestJWTAuthPolicy_ApplicationID_RegisteredClaimIgnored(t *testing.T) {
	resetJWTAuthSingletonCache(t)

	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
	defer slog.SetDefault(prev)

	privateKey, publicKey := generateTestKeys(t)
	jwksServer := createJWKSServer(t, publicKey, "test-kid")
	defer jwksServer.Close()

	token := createTestToken(t, privateKey, map[string]interface{}{
		"sub": "user-123",
		"iss": "https://issuer.example.com",
	})

	params := newRemoteParams(jwksServer.URL + "/jwks.json")
	// A key-manager name unique to this test, since the warn-once record outlives the test.
	params["keyManagers"].([]interface{})[0].(map[string]interface{})["name"] = "km-registered-claim-test"
	withApplicationIDClaim(t, params, "sub")
	// Disable the verdict cache so every request re-parses the key managers.
	params["tokenCaching"] = false

	for i := 0; i < 3; i++ {
		ctx, action := executeOnRequestHeaders(t, params, authHeader("Authorization", "Bearer", token))
		assertAuthSuccess(t, ctx, action)
		assertApplicationID(t, ctx, action, "")
	}

	if n := strings.Count(buf.String(), "applicationIdClaim is a registered JWT claim"); n != 1 {
		t.Fatalf("expected exactly one warning for the registered claim, got %d; logs:\n%s", n, buf.String())
	}
}

// TestJWTAuthPolicy_ApplicationID_ExistingIdentityKept verifies an application identity an earlier
// policy (api-key-auth) already set is not overwritten, and jwt-auth adds no analytics value for it.
func TestJWTAuthPolicy_ApplicationID_ExistingIdentityKept(t *testing.T) {
	resetJWTAuthSingletonCache(t)

	privateKey, publicKey := generateTestKeys(t)
	jwksServer := createJWKSServer(t, publicKey, "test-kid")
	defer jwksServer.Close()

	token := createTestToken(t, privateKey, map[string]interface{}{
		"sub":       "user-123",
		"iss":       "https://issuer.example.com",
		"client_id": "client-abc",
	})

	params := newRemoteParams(jwksServer.URL + "/jwks.json")
	withApplicationIDClaim(t, params, "client_id")

	p := mustGetPolicy(t, params)
	ctx := createMockRequestHeaderContext(authHeader("Authorization", "Bearer", token))
	ctx.SharedContext.Metadata[applicationIDMetadataKey] = "app-from-api-key"
	action := p.(*JwtAuthPolicy).OnRequestHeaders(context.Background(), ctx, params)
	assertAuthSuccess(t, ctx, action)

	if got := ctx.SharedContext.Metadata[applicationIDMetadataKey]; got != "app-from-api-key" {
		t.Fatalf("expected the earlier identity to be kept, got %v", got)
	}
	if v, ok := action.(policy.UpstreamRequestHeaderModifications).AnalyticsMetadata[applicationIDMetadataKey]; ok {
		t.Fatalf("expected no analytics value when the identity was already set, got %v", v)
	}
}

// TestJWTAuthPolicy_ApplicationID_EmptyExistingIdentityReplaced verifies an empty identity left by an
// earlier policy (api-key-auth for a key with no linked application) does not block the JWT's.
func TestJWTAuthPolicy_ApplicationID_EmptyExistingIdentityReplaced(t *testing.T) {
	resetJWTAuthSingletonCache(t)

	privateKey, publicKey := generateTestKeys(t)
	jwksServer := createJWKSServer(t, publicKey, "test-kid")
	defer jwksServer.Close()

	token := createTestToken(t, privateKey, map[string]interface{}{
		"sub":       "user-123",
		"iss":       "https://issuer.example.com",
		"client_id": "client-abc",
	})

	params := newRemoteParams(jwksServer.URL + "/jwks.json")
	withApplicationIDClaim(t, params, "client_id")

	p := mustGetPolicy(t, params)
	ctx := createMockRequestHeaderContext(authHeader("Authorization", "Bearer", token))
	ctx.SharedContext.Metadata[applicationIDMetadataKey] = ""
	action := p.(*JwtAuthPolicy).OnRequestHeaders(context.Background(), ctx, params)
	assertAuthSuccess(t, ctx, action)
	assertApplicationID(t, ctx, action, "client-abc")
}

// TestJWTAuthPolicy_ApplicationID_NilMetadata verifies the identity is set when the shared context
// carries no metadata map yet.
func TestJWTAuthPolicy_ApplicationID_NilMetadata(t *testing.T) {
	resetJWTAuthSingletonCache(t)

	privateKey, publicKey := generateTestKeys(t)
	jwksServer := createJWKSServer(t, publicKey, "test-kid")
	defer jwksServer.Close()

	token := createTestToken(t, privateKey, map[string]interface{}{
		"sub":       "user-123",
		"iss":       "https://issuer.example.com",
		"client_id": "client-abc",
	})

	params := newRemoteParams(jwksServer.URL + "/jwks.json")
	withApplicationIDClaim(t, params, "client_id")

	p := mustGetPolicy(t, params)
	ctx := createMockRequestHeaderContext(authHeader("Authorization", "Bearer", token))
	ctx.SharedContext.Metadata = nil
	action := p.(*JwtAuthPolicy).OnRequestHeaders(context.Background(), ctx, params)
	assertAuthSuccess(t, ctx, action)
	assertApplicationID(t, ctx, action, "client-abc")
}

// TestJWTAuthPolicy_ApplicationID_CacheHit verifies the cached verdict carries the identity resolved
// from the matched key manager, so a cache hit — which cannot re-derive the key manager — sets the
// same identity as the cache-miss path.
func TestJWTAuthPolicy_ApplicationID_CacheHit(t *testing.T) {
	resetJWTAuthSingletonCache(t)

	privateKey, publicKey := generateTestKeys(t)
	jwksServer := createJWKSServer(t, publicKey, "test-kid")

	token := createTestToken(t, privateKey, map[string]interface{}{
		"sub":       "user-123",
		"iss":       "https://issuer.example.com",
		"client_id": "client-abc",
	})

	params := newRemoteParams(jwksServer.URL + "/jwks.json")
	withApplicationIDClaim(t, params, "client_id")
	p := mustGetPolicy(t, params)

	ctx1 := createMockRequestHeaderContext(authHeader("Authorization", "Bearer", token))
	action1 := p.(*JwtAuthPolicy).OnRequestHeaders(context.Background(), ctx1, params)
	assertAuthSuccess(t, ctx1, action1)
	assertApplicationID(t, ctx1, action1, "client-abc")

	key := expectedCacheKey(params, token, true, []string{}, 30*time.Second)
	verdict, hit := ins.getCachedVerdict(context.Background(), key)
	if !hit || !verdict.ok {
		t.Fatalf("expected a positive cached verdict, got hit=%v ok=%v", hit, verdict.ok)
	}
	if verdict.applicationID != "client-abc" {
		t.Fatalf("expected cached applicationID %q, got %q", "client-abc", verdict.applicationID)
	}

	// Any fall-through to full re-verification would now fail, so success proves a cache hit.
	clearJWKSFetchCache()
	jwksServer.Close()

	ctx2 := createMockRequestHeaderContext(authHeader("Authorization", "Bearer", token))
	action2 := p.(*JwtAuthPolicy).OnRequestHeaders(context.Background(), ctx2, params)
	assertAuthSuccess(t, ctx2, action2)
	assertApplicationID(t, ctx2, action2, "client-abc")
}

// TestJWTAuthPolicy_ApplicationID_ClaimChangeMissesCache verifies changing applicationIdClaim changes
// the cache key, so a verdict cached under the old claim is never served with a stale identity.
func TestJWTAuthPolicy_ApplicationID_ClaimChangeMissesCache(t *testing.T) {
	resetJWTAuthSingletonCache(t)

	privateKey, publicKey := generateTestKeys(t)
	jwksServer := createJWKSServer(t, publicKey, "test-kid")
	defer jwksServer.Close()

	token := createTestToken(t, privateKey, map[string]interface{}{
		"sub":       "user-123",
		"iss":       "https://issuer.example.com",
		"client_id": "client-abc",
		"azp":       "azp-xyz",
	})

	before := newRemoteParams(jwksServer.URL + "/jwks.json")
	withApplicationIDClaim(t, before, "client_id")
	ctx1, action1 := executeOnRequestHeaders(t, before, authHeader("Authorization", "Bearer", token))
	assertAuthSuccess(t, ctx1, action1)
	assertApplicationID(t, ctx1, action1, "client-abc")

	after := newRemoteParams(jwksServer.URL + "/jwks.json")
	withApplicationIDClaim(t, after, "azp")
	if expectedCacheKey(before, token, true, []string{}, 30*time.Second) == expectedCacheKey(after, token, true, []string{}, 30*time.Second) {
		t.Fatalf("expected a different cache key after changing applicationIdClaim")
	}
	ctx2, action2 := executeOnRequestHeaders(t, after, authHeader("Authorization", "Bearer", token))
	assertAuthSuccess(t, ctx2, action2)
	assertApplicationID(t, ctx2, action2, "azp-xyz")
}

// TestJWTAuthPolicy_ApplicationID_NotSetOnFailure verifies a token rejected after signature
// verification (here, on audience) sets no identity, and the rejection's fault is unchanged.
func TestJWTAuthPolicy_ApplicationID_NotSetOnFailure(t *testing.T) {
	resetJWTAuthSingletonCache(t)

	privateKey, publicKey := generateTestKeys(t)
	jwksServer := createJWKSServer(t, publicKey, "test-kid")
	defer jwksServer.Close()

	token := createTestToken(t, privateKey, map[string]interface{}{
		"sub":       "user-123",
		"iss":       "https://issuer.example.com",
		"aud":       "other-api",
		"client_id": "client-abc",
	})

	params := newRemoteParams(jwksServer.URL + "/jwks.json")
	withApplicationIDClaim(t, params, "client_id")
	params["audiences"] = []interface{}{"expected-api"}

	ctx, action := executeOnRequestHeaders(t, params, authHeader("Authorization", "Bearer", token))
	assertAuthFailure(t, ctx, action, 401)

	if v, ok := ctx.SharedContext.Metadata[applicationIDMetadataKey]; ok {
		t.Fatalf("expected no application identity on failure, got %v", v)
	}
	resp := action.(policy.ImmediateResponse)
	if !resp.IsFault || resp.Fault == nil {
		t.Fatalf("expected the rejection to declare a fault, got IsFault=%v Fault=%v", resp.IsFault, resp.Fault)
	}
	if resp.Fault.Code != policy.FaultCodeAuthInvalidCredentials || resp.Fault.Type != policy.FaultTypeAuthentication {
		t.Fatalf("expected fault %s/%s, got %s/%s", policy.FaultCodeAuthInvalidCredentials, policy.FaultTypeAuthentication, resp.Fault.Code, resp.Fault.Type)
	}
	if string(resp.Body) != `{"error":"Unauthorized","message":"Authentication failed"}` {
		t.Fatalf("expected the unchanged error body, got %s", resp.Body)
	}
}
