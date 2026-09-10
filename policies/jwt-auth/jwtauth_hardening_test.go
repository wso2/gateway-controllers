package jwtauth

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

func TestJWTAuthPolicy_HappyPath_RemoteJWKS_IssuerNameAudienceScope(t *testing.T) {
	resetJWTAuthSingletonCache(t)

	privateKey, publicKey := generateTestKeys(t)
	jwksServer := createJWKSServer(t, publicKey, "test-kid")
	defer jwksServer.Close()

	token := createTestToken(t, privateKey, map[string]interface{}{
		"sub":   "user-123",
		"iss":   "https://issuer.example.com",
		"aud":   "api-audience",
		"scope": "read write",
	})

	params := newRemoteParams(jwksServer.URL + "/jwks.json")
	params["issuers"] = []interface{}{"km-primary"}
	params["audiences"] = []interface{}{"api-audience"}
	params["requiredScopes"] = []interface{}{"read"}

	ctx, action := executeOnRequestHeaders(t, params, authHeader("Authorization", "Bearer", token))
	assertAuthSuccess(t, ctx, action)
}

func TestJWTAuthPolicy_HappyPath_AudienceArray_AndScpArray(t *testing.T) {
	resetJWTAuthSingletonCache(t)

	privateKey, publicKey := generateTestKeys(t)
	jwksServer := createJWKSServer(t, publicKey, "test-kid")
	defer jwksServer.Close()

	token := createRS256TokenWithKid(t, privateKey, map[string]interface{}{
		"sub": "user-123",
		"iss": "https://issuer.example.com",
		"aud": []interface{}{"api-audience", "secondary-audience"},
		"scp": []interface{}{"read", "write"},
	}, "test-kid")

	params := newRemoteParams(jwksServer.URL + "/jwks.json")
	params["audiences"] = []interface{}{"api-audience"}
	params["requiredScopes"] = []interface{}{"write"}

	ctx, action := executeOnRequestHeaders(t, params, authHeader("Authorization", "Bearer", token))
	assertAuthSuccess(t, ctx, action)
}

func TestJWTAuthPolicy_RequiredScopes_OR_MatchesOne(t *testing.T) {
	resetJWTAuthSingletonCache(t)

	privateKey, publicKey := generateTestKeys(t)
	jwksServer := createJWKSServer(t, publicKey, "test-kid")
	defer jwksServer.Close()

	// Token has only "read"; policy requires either "read" or "admin". OR
	// semantics means one match is enough.
	token := createTestToken(t, privateKey, map[string]interface{}{
		"sub":   "user-123",
		"iss":   "https://issuer.example.com",
		"scope": "read",
	})

	params := newRemoteParams(jwksServer.URL + "/jwks.json")
	params["issuers"] = []interface{}{"km-primary"}
	params["requiredScopes"] = []interface{}{"read", "admin"}

	ctx, action := executeOnRequestHeaders(t, params, authHeader("Authorization", "Bearer", token))
	assertAuthSuccess(t, ctx, action)
}

func TestJWTAuthPolicy_RequiredScopes_OR_MatchesNone(t *testing.T) {
	resetJWTAuthSingletonCache(t)

	privateKey, publicKey := generateTestKeys(t)
	jwksServer := createJWKSServer(t, publicKey, "test-kid")
	defer jwksServer.Close()

	// Token has neither of the required scopes → auth fails.
	token := createTestToken(t, privateKey, map[string]interface{}{
		"sub":   "user-123",
		"iss":   "https://issuer.example.com",
		"scope": "read",
	})

	params := newRemoteParams(jwksServer.URL + "/jwks.json")
	params["issuers"] = []interface{}{"km-primary"}
	params["requiredScopes"] = []interface{}{"write", "admin"}

	ctx, action := executeOnRequestHeaders(t, params, authHeader("Authorization", "Bearer", token))
	assertAuthFailure(t, ctx, action, 401)
}

func TestJWTAuthPolicy_HappyPath_CustomHeaderName_AndPrefix(t *testing.T) {
	resetJWTAuthSingletonCache(t)

	privateKey, publicKey := generateTestKeys(t)
	jwksServer := createJWKSServer(t, publicKey, "test-kid")
	defer jwksServer.Close()

	token := createTestToken(t, privateKey, map[string]interface{}{
		"sub": "user-123",
		"iss": "https://issuer.example.com",
	})

	params := newRemoteParams(jwksServer.URL + "/jwks.json")
	params["headerName"] = "X-Auth-Token"
	params["authHeaderPrefix"] = "JWT"

	ctx, action := executeOnRequestHeaders(t, params, authHeader("X-Auth-Token", "JWT", token))
	assertAuthSuccess(t, ctx, action)
}

func TestJWTAuthPolicy_HappyPath_LocalCert_WithClaimMappings_AndUserIdClaim(t *testing.T) {
	resetJWTAuthSingletonCache(t)

	privateKey, publicKey := generateTestKeys(t)
	token := createRS256TokenWithKid(t, privateKey, map[string]interface{}{
		"sub":      "user-123",
		"iss":      "https://issuer.example.com",
		"username": "alice",
		"email":    "alice@example.com",
	}, "test-kid")

	params := newRemoteParams("http://invalid.local/jwks.json")
	params["keyManagers"] = []interface{}{
		map[string]interface{}{
			"name":   "km-local",
			"issuer": "https://issuer.example.com",
			"jwks": map[string]interface{}{
				"local": map[string]interface{}{
					"inline": publicKeyToPEM(t, publicKey),
				},
			},
		},
	}
	params["claimMappings"] = map[string]interface{}{
		"email": "X-User-Email",
	}
	params["userIdClaim"] = "username"

	ctx, action := executeOnRequestHeaders(t, params, authHeader("Authorization", "Bearer", token))
	assertAuthSuccess(t, ctx, action)

	mods, ok := action.(policy.UpstreamRequestHeaderModifications)
	if !ok {
		t.Fatalf("expected UpstreamRequestHeaderModifications, got %T", action)
	}
	if mods.HeadersToSet["X-User-Email"] != "alice@example.com" {
		t.Fatalf("expected X-User-Email header to be set")
	}
	if ctx.SharedContext.AuthContext == nil || ctx.SharedContext.AuthContext.Subject != "alice" {
		t.Fatalf("expected AuthContext.Subject to be set from userIdClaim")
	}
}

func TestJWTAuthPolicy_ClaimMappingClearsDownstreamHeaderWhenClaimIsMissing(t *testing.T) {
	resetJWTAuthSingletonCache(t)

	privateKey, publicKey := generateTestKeys(t)
	token := createRS256TokenWithKid(t, privateKey, map[string]interface{}{
		"sub": "user-123",
		"iss": "https://issuer.example.com",
	}, "test-kid")

	params := newRemoteParams("http://invalid.local/jwks.json")
	params["keyManagers"] = []interface{}{
		map[string]interface{}{
			"name":   "km-local",
			"issuer": "https://issuer.example.com",
			"jwks": map[string]interface{}{
				"local": map[string]interface{}{
					"inline": publicKeyToPEM(t, publicKey),
				},
			},
		},
	}
	params["claimMappings"] = map[string]interface{}{
		"email": "X-User-Email",
	}

	headers := authHeader("Authorization", "Bearer", token)
	headers["x-user-email"] = []string{"anonymous@example.com"}
	ctx, action := executeOnRequestHeaders(t, params, headers)
	assertAuthSuccess(t, ctx, action)

	mods, ok := action.(policy.UpstreamRequestHeaderModifications)
	if !ok {
		t.Fatalf("expected UpstreamRequestHeaderModifications, got %T", action)
	}
	value, ok := mods.HeadersToSet["X-User-Email"]
	if !ok {
		t.Fatal("expected the mapped header to be overwritten when the JWT claim is missing")
	}
	if value != "" {
		t.Fatalf("expected the mapped header to be empty, got %q", value)
	}
	for _, headerName := range mods.HeadersToRemove {
		if strings.EqualFold(headerName, "X-User-Email") {
			t.Fatal("expected the mapped header to be set to empty rather than removed")
		}
	}
}

func TestJWTAuthPolicy_ClaimMappingPresentClaimWinsForSharedHeader(t *testing.T) {
	resetJWTAuthSingletonCache(t)

	privateKey, publicKey := generateTestKeys(t)
	token := createRS256TokenWithKid(t, privateKey, map[string]interface{}{
		"sub":   "user-123",
		"iss":   "https://issuer.example.com",
		"email": "user@example.com",
	}, "test-kid")

	params := newRemoteParams("http://invalid.local/jwks.json")
	params["keyManagers"] = []interface{}{
		map[string]interface{}{
			"name":   "km-local",
			"issuer": "https://issuer.example.com",
			"jwks": map[string]interface{}{
				"local": map[string]interface{}{
					"inline": publicKeyToPEM(t, publicKey),
				},
			},
		},
	}
	params["claimMappings"] = map[string]interface{}{
		"email":    "X-User-Identity",
		"username": "x-user-identity",
	}

	headers := authHeader("Authorization", "Bearer", token)
	headers["x-user-identity"] = []string{"attacker"}
	ctx, action := executeOnRequestHeaders(t, params, headers)
	assertAuthSuccess(t, ctx, action)

	mods, ok := action.(policy.UpstreamRequestHeaderModifications)
	if !ok {
		t.Fatalf("expected UpstreamRequestHeaderModifications, got %T", action)
	}
	if value := mods.HeadersToSet["X-User-Identity"]; value != "user@example.com" {
		t.Fatalf("expected the present claim to win for the shared header, got %q", value)
	}
	if _, ok := mods.HeadersToSet["x-user-identity"]; ok {
		t.Fatal("expected case-insensitive mapping destinations to be consolidated")
	}
	for _, headerName := range mods.HeadersToRemove {
		if strings.EqualFold(headerName, "X-User-Identity") {
			t.Fatal("expected a present claim to prevent removal of the shared mapped header")
		}
	}
}

func TestJWTAuthPolicy_Negative_MissingAuthorizationHeader(t *testing.T) {
	resetJWTAuthSingletonCache(t)

	params := newRemoteParams("http://localhost:8080/jwks.json")
	params["onFailureStatusCode"] = 403
	params["errorMessageFormat"] = "plain"
	params["errorMessage"] = "missing auth"

	ctx, action := executeOnRequestHeaders(t, params, map[string][]string{})
	assertAuthFailure(t, ctx, action, 403)

	resp := action.(policy.ImmediateResponse)
	if string(resp.Body) != "missing auth" {
		t.Fatalf("expected plain error body")
	}
}

func TestJWTAuthPolicy_Negative_WrongAuthorizationScheme(t *testing.T) {
	resetJWTAuthSingletonCache(t)

	privateKey, publicKey := generateTestKeys(t)
	jwksServer := createJWKSServer(t, publicKey, "test-kid")
	defer jwksServer.Close()

	token := createTestToken(t, privateKey, map[string]interface{}{
		"sub": "user-123",
		"iss": "https://issuer.example.com",
	})

	params := newRemoteParams(jwksServer.URL + "/jwks.json")
	params["authHeaderScheme"] = "Bearer"

	ctx, action := executeOnRequestHeaders(t, params, authHeader("Authorization", "JWT", token))
	assertAuthFailure(t, ctx, action, 401)
}

func TestJWTAuthPolicy_Negative_MalformedJWT(t *testing.T) {
	resetJWTAuthSingletonCache(t)

	params := newRemoteParams("http://localhost:8080/jwks.json")
	ctx, action := executeOnRequestHeaders(t, params, authHeader("Authorization", "Bearer", "not.a.jwt"))
	assertAuthFailure(t, ctx, action, 401)
}

func TestJWTAuthPolicy_Negative_MissingAlgHeader(t *testing.T) {
	resetJWTAuthSingletonCache(t)

	privateKey, publicKey := generateTestKeys(t)
	jwksServer := createJWKSServer(t, publicKey, "test-kid")
	defer jwksServer.Close()

	token := createTokenWithoutAlgHeader(t, privateKey, map[string]interface{}{
		"sub": "user-123",
		"iss": "https://issuer.example.com",
	}, "test-kid")

	params := newRemoteParams(jwksServer.URL + "/jwks.json")
	ctx, action := executeOnRequestHeaders(t, params, authHeader("Authorization", "Bearer", token))
	assertAuthFailure(t, ctx, action, 401)
}

// TestJWTAuthPolicy_Negative_DisallowedAlgorithm verifies that algorithms outside the
// hardcoded supported set (RS256, PS256, ES256) are rejected even when a valid key is present.
// RS384 is chosen as a representative unsupported-but-parseable algorithm.
func TestJWTAuthPolicy_Negative_DisallowedAlgorithm(t *testing.T) {
	resetJWTAuthSingletonCache(t)

	privateKey, publicKey := generateTestKeys(t)
	jwksServer := createJWKSServer(t, publicKey, "test-kid")
	defer jwksServer.Close()

	// Mint an RS384 token (not in the hardcoded supportedAlgorithms set).
	claims := normalizeClaims(map[string]interface{}{
		"sub": "user-123",
		"iss": "https://issuer.example.com",
	})
	tok := jwt.NewWithClaims(jwt.SigningMethodRS384, jwt.MapClaims(claims))
	tok.Header["kid"] = "test-kid"
	tokenString, err := tok.SignedString(privateKey)
	if err != nil {
		t.Fatalf("failed to sign RS384 token: %v", err)
	}

	params := newRemoteParams(jwksServer.URL + "/jwks.json")
	ctx, action := executeOnRequestHeaders(t, params, authHeader("Authorization", "Bearer", tokenString))
	assertAuthFailure(t, ctx, action, 401)
}

func TestJWTAuthPolicy_Negative_KidNotFoundInJWKS(t *testing.T) {
	resetJWTAuthSingletonCache(t)

	privateKey, publicKey := generateTestKeys(t)
	jwksServer := createJWKSServer(t, publicKey, "known-kid")
	defer jwksServer.Close()

	token := createRS256TokenWithKid(t, privateKey, map[string]interface{}{
		"sub": "user-123",
		"iss": "https://issuer.example.com",
	}, "missing-kid")

	params := newRemoteParams(jwksServer.URL + "/jwks.json")
	ctx, action := executeOnRequestHeaders(t, params, authHeader("Authorization", "Bearer", token))
	assertAuthFailure(t, ctx, action, 401)
}

func TestJWTAuthPolicy_Edge_ExpWithinLeeway_Accepts(t *testing.T) {
	resetJWTAuthSingletonCache(t)

	privateKey, publicKey := generateTestKeys(t)
	jwksServer := createJWKSServer(t, publicKey, "test-kid")
	defer jwksServer.Close()

	token := createRS256TokenWithKid(t, privateKey, map[string]interface{}{
		"sub": "user-123",
		"iss": "https://issuer.example.com",
		"exp": time.Now().Add(-10 * time.Second).Unix(),
	}, "test-kid")

	params := newRemoteParams(jwksServer.URL + "/jwks.json")
	params["leeway"] = "30s"

	ctx, action := executeOnRequestHeaders(t, params, authHeader("Authorization", "Bearer", token))
	assertAuthSuccess(t, ctx, action)
}

func TestJWTAuthPolicy_Edge_ExpBeyondLeeway_Rejects(t *testing.T) {
	resetJWTAuthSingletonCache(t)

	privateKey, publicKey := generateTestKeys(t)
	jwksServer := createJWKSServer(t, publicKey, "test-kid")
	defer jwksServer.Close()

	token := createRS256TokenWithKid(t, privateKey, map[string]interface{}{
		"sub": "user-123",
		"iss": "https://issuer.example.com",
		"exp": time.Now().Add(-45 * time.Second).Unix(),
	}, "test-kid")

	params := newRemoteParams(jwksServer.URL + "/jwks.json")
	params["leeway"] = "30s"

	ctx, action := executeOnRequestHeaders(t, params, authHeader("Authorization", "Bearer", token))
	assertAuthFailure(t, ctx, action, 401)
}

func TestJWTAuthPolicy_Edge_NbfWithinLeeway_Accepts(t *testing.T) {
	resetJWTAuthSingletonCache(t)

	privateKey, publicKey := generateTestKeys(t)
	jwksServer := createJWKSServer(t, publicKey, "test-kid")
	defer jwksServer.Close()

	token := createRS256TokenWithKid(t, privateKey, map[string]interface{}{
		"sub": "user-123",
		"iss": "https://issuer.example.com",
		"nbf": time.Now().Add(10 * time.Second).Unix(),
	}, "test-kid")

	params := newRemoteParams(jwksServer.URL + "/jwks.json")
	params["leeway"] = "30s"

	ctx, action := executeOnRequestHeaders(t, params, authHeader("Authorization", "Bearer", token))
	assertAuthSuccess(t, ctx, action)
}

func TestJWTAuthPolicy_Edge_NbfBeyondLeeway_Rejects(t *testing.T) {
	resetJWTAuthSingletonCache(t)

	privateKey, publicKey := generateTestKeys(t)
	jwksServer := createJWKSServer(t, publicKey, "test-kid")
	defer jwksServer.Close()

	token := createRS256TokenWithKid(t, privateKey, map[string]interface{}{
		"sub": "user-123",
		"iss": "https://issuer.example.com",
		"nbf": time.Now().Add(45 * time.Second).Unix(),
	}, "test-kid")

	params := newRemoteParams(jwksServer.URL + "/jwks.json")
	params["leeway"] = "30s"

	ctx, action := executeOnRequestHeaders(t, params, authHeader("Authorization", "Bearer", token))
	assertAuthFailure(t, ctx, action, 401)
}

func TestJWTAuthPolicy_Edge_NegativeRetryCount_NoPanic(t *testing.T) {
	resetJWTAuthSingletonCache(t)

	privateKey, publicKey := generateTestKeys(t)
	jwksServer := createJWKSServer(t, publicKey, "test-kid")
	defer jwksServer.Close()

	token := createTestToken(t, privateKey, map[string]interface{}{
		"sub": "user-123",
		"iss": "https://issuer.example.com",
	})

	params := newRemoteParams(jwksServer.URL + "/jwks.json")
	params["jwksFetchRetryCount"] = -1
	params["jwksFetchTimeout"] = "20ms"
	params["jwksFetchRetryInterval"] = "1ms"

	var (
		ctx    *policy.RequestHeaderContext
		action policy.RequestHeaderAction
	)

	defer func() {
		if recovered := recover(); recovered != nil {
			t.Fatalf("OnRequestHeaders must not panic for invalid retry count: %v", recovered)
		}
		assertAuthFailure(t, ctx, action, 401)
	}()

	ctx, action = executeOnRequestHeaders(t, params, authHeader("Authorization", "Bearer", token))
}

func TestJWTAuthPolicy_Edge_RetryEventuallySucceeds(t *testing.T) {
	resetJWTAuthSingletonCache(t)

	privateKey, publicKey := generateTestKeys(t)
	var requestCount int32

	jwksServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/jwks.json" {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		count := atomic.AddInt32(&requestCount, 1)
		if count <= 2 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		writeJWKSResponse(t, w, publicKey, "test-kid")
	}))
	defer jwksServer.Close()

	token := createTestToken(t, privateKey, map[string]interface{}{
		"sub": "user-123",
		"iss": "https://issuer.example.com",
	})

	params := newRemoteParams(jwksServer.URL + "/jwks.json")
	params["jwksFetchRetryCount"] = 3
	params["jwksFetchRetryInterval"] = "1ms"
	params["jwksFetchTimeout"] = "100ms"

	ctx, action := executeOnRequestHeaders(t, params, authHeader("Authorization", "Bearer", token))
	assertAuthSuccess(t, ctx, action)

	if got := atomic.LoadInt32(&requestCount); got != 3 {
		t.Fatalf("expected 3 JWKS fetch attempts, got %d", got)
	}
}

func TestJWTAuthPolicy_Edge_JWKSCacheHit_SkipsRefetch(t *testing.T) {
	resetJWTAuthSingletonCache(t)

	privateKey, publicKey := generateTestKeys(t)
	var requestCount int32

	jwksServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/jwks.json" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		atomic.AddInt32(&requestCount, 1)
		writeJWKSResponse(t, w, publicKey, "test-kid")
	}))
	defer jwksServer.Close()

	params := newRemoteParams(jwksServer.URL + "/jwks.json")
	params["jwksCacheTtl"] = "1m"

	token := createTestToken(t, privateKey, map[string]interface{}{
		"sub": "user-123",
		"iss": "https://issuer.example.com",
	})

	p := mustGetPolicy(t, params)

	ctx1 := createMockRequestHeaderContext(authHeader("Authorization", "Bearer", token))
	action1 := p.(*JwtAuthPolicy).OnRequestHeaders(context.Background(), ctx1, params)
	assertAuthSuccess(t, ctx1, action1)

	ctx2 := createMockRequestHeaderContext(authHeader("Authorization", "Bearer", token))
	action2 := p.(*JwtAuthPolicy).OnRequestHeaders(context.Background(), ctx2, params)
	assertAuthSuccess(t, ctx2, action2)

	if got := atomic.LoadInt32(&requestCount); got != 1 {
		t.Fatalf("expected exactly one JWKS fetch due to cache hit, got %d", got)
	}
}

func TestJWTAuthPolicy_Edge_JWKSCacheExpiry_Refetches(t *testing.T) {
	resetJWTAuthSingletonCache(t)

	privateKey, publicKey := generateTestKeys(t)
	var requestCount int32

	jwksServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/jwks.json" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		atomic.AddInt32(&requestCount, 1)
		writeJWKSResponse(t, w, publicKey, "test-kid")
	}))
	defer jwksServer.Close()

	params := newRemoteParams(jwksServer.URL + "/jwks.json")
	params["jwksCacheTtl"] = "15ms"
	// Disable the token verdict cache so the second identical request re-verifies the
	// signature (and therefore re-fetches JWKS) instead of being served from cache — this
	// test is specifically exercising JWKS-level cache expiry, not token-verdict caching.
	params["tokenCaching"] = false

	token := createTestToken(t, privateKey, map[string]interface{}{
		"sub": "user-123",
		"iss": "https://issuer.example.com",
	})

	p := mustGetPolicy(t, params)

	ctx1 := createMockRequestHeaderContext(authHeader("Authorization", "Bearer", token))
	action1 := p.(*JwtAuthPolicy).OnRequestHeaders(context.Background(), ctx1, params)
	assertAuthSuccess(t, ctx1, action1)

	time.Sleep(25 * time.Millisecond)

	ctx2 := createMockRequestHeaderContext(authHeader("Authorization", "Bearer", token))
	action2 := p.(*JwtAuthPolicy).OnRequestHeaders(context.Background(), ctx2, params)
	assertAuthSuccess(t, ctx2, action2)

	if got := atomic.LoadInt32(&requestCount); got < 2 {
		t.Fatalf("expected JWKS refetch after cache expiry, got %d fetches", got)
	}
}

func TestJWTAuthPolicy_Security_AlgNoneRejected(t *testing.T) {
	resetJWTAuthSingletonCache(t)

	_, publicKey := generateTestKeys(t)
	jwksServer := createJWKSServer(t, publicKey, "test-kid")
	defer jwksServer.Close()

	token := createUnsignedNoneToken(t, map[string]interface{}{
		"sub": "user-123",
		"iss": "https://issuer.example.com",
	})

	params := newRemoteParams(jwksServer.URL + "/jwks.json")
	ctx, action := executeOnRequestHeaders(t, params, authHeader("Authorization", "Bearer", token))
	assertAuthFailure(t, ctx, action, 401)
}

func TestJWTAuthPolicy_Security_ValidateIssuerTrue_RejectsUnknownIssuer(t *testing.T) {
	resetJWTAuthSingletonCache(t)

	privateKey, publicKey := generateTestKeys(t)
	jwksServer := createJWKSServer(t, publicKey, "test-kid")
	defer jwksServer.Close()

	token := createTestToken(t, privateKey, map[string]interface{}{
		"sub": "user-123",
		"iss": "https://unknown.example.com",
	})

	params := newRemoteParams(jwksServer.URL + "/jwks.json")
	params["validateIssuer"] = true

	ctx, action := executeOnRequestHeaders(t, params, authHeader("Authorization", "Bearer", token))
	assertAuthFailure(t, ctx, action, 401)
}

func TestJWTAuthPolicy_Security_ValidateIssuerFalse_AllowsIssuerMismatch_WithValidSignature(t *testing.T) {
	resetJWTAuthSingletonCache(t)

	privateKey, publicKey := generateTestKeys(t)
	jwksServer := createJWKSServer(t, publicKey, "test-kid")
	defer jwksServer.Close()

	token := createTestToken(t, privateKey, map[string]interface{}{
		"sub": "user-123",
		"iss": "https://unknown.example.com",
	})

	params := newRemoteParams(jwksServer.URL + "/jwks.json")
	params["validateIssuer"] = false

	ctx, action := executeOnRequestHeaders(t, params, authHeader("Authorization", "Bearer", token))
	assertAuthSuccess(t, ctx, action)
}

func TestJWTAuthPolicy_Security_UserIssuers_MultipleManagers_TriesFallbackManager(t *testing.T) {
	resetJWTAuthSingletonCache(t)

	goodPrivateKey, goodPublicKey := generateTestKeys(t)
	_, badPublicKey := generateTestKeys(t)

	token := createRS256TokenWithKid(t, goodPrivateKey, map[string]interface{}{
		"sub": "user-123",
		"iss": "https://issuer.example.com",
	}, "test-kid")

	params := newRemoteParams("http://unused/jwks.json")
	params["keyManagers"] = []interface{}{
		map[string]interface{}{
			"name": "km-bad",
			"jwks": map[string]interface{}{
				"local": map[string]interface{}{
					"inline": publicKeyToPEM(t, badPublicKey),
				},
			},
		},
		map[string]interface{}{
			"name": "km-good",
			"jwks": map[string]interface{}{
				"local": map[string]interface{}{
					"inline": publicKeyToPEM(t, goodPublicKey),
				},
			},
		},
	}
	params["issuers"] = []interface{}{"km-bad", "km-good"}

	ctx, action := executeOnRequestHeaders(t, params, authHeader("Authorization", "Bearer", token))
	assertAuthSuccess(t, ctx, action)
}

func TestJWTAuthPolicy_Security_MissingIss_ValidateIssuerToggle(t *testing.T) {
	resetJWTAuthSingletonCache(t)

	privateKey, publicKey := generateTestKeys(t)
	jwksServer := createJWKSServer(t, publicKey, "test-kid")
	defer jwksServer.Close()

	token := createRS256TokenWithKid(t, privateKey, map[string]interface{}{
		"sub": "user-123",
	}, "test-kid")

	tests := []struct {
		name       string
		validate   bool
		expectPass bool
		statusCode int
	}{
		{name: "validateIssuer_true_rejects", validate: true, expectPass: false, statusCode: 401},
		{name: "validateIssuer_false_allows", validate: false, expectPass: true, statusCode: 0},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resetJWTAuthSingletonCache(t)

			params := newRemoteParams(jwksServer.URL + "/jwks.json")
			params["validateIssuer"] = tc.validate

			ctx, action := executeOnRequestHeaders(t, params, authHeader("Authorization", "Bearer", token))
			if tc.expectPass {
				assertAuthSuccess(t, ctx, action)
			} else {
				assertAuthFailure(t, ctx, action, tc.statusCode)
			}
		})
	}
}

func TestJWTAuthPolicy_Security_AuthorizationSchemeCaseInsensitive(t *testing.T) {
	resetJWTAuthSingletonCache(t)

	privateKey, publicKey := generateTestKeys(t)
	jwksServer := createJWKSServer(t, publicKey, "test-kid")
	defer jwksServer.Close()

	token := createTestToken(t, privateKey, map[string]interface{}{
		"sub": "user-123",
		"iss": "https://issuer.example.com",
	})

	params := newRemoteParams(jwksServer.URL + "/jwks.json")
	ctx, action := executeOnRequestHeaders(t, params, authHeader("Authorization", "bearer", token))
	assertAuthSuccess(t, ctx, action)
}

func TestJWTAuthPolicy_Regression_ErrorFormats_JsonPlainMinimal(t *testing.T) {
	resetJWTAuthSingletonCache(t)

	tests := []struct {
		name           string
		format         string
		expectedType   string
		expectBodyText string
		expectEmpty    bool
	}{
		{
			name:         "json",
			format:       "json",
			expectedType: "application/json",
		},
		{
			name:           "plain",
			format:         "plain",
			expectedType:   "text/plain",
			expectBodyText: "custom error message",
		},
		{
			name:           "minimal",
			format:         "minimal",
			expectedType:   "application/json",
			expectBodyText: "Unauthorized",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resetJWTAuthSingletonCache(t)

			params := newRemoteParams("http://localhost:8080/jwks.json")
			params["errorMessageFormat"] = tc.format
			params["errorMessage"] = "custom error message"
			params["onFailureStatusCode"] = 401

			ctx, action := executeOnRequestHeaders(t, params, map[string][]string{})
			assertAuthFailure(t, ctx, action, 401)

			resp := action.(policy.ImmediateResponse)
			if resp.Headers["content-type"] != tc.expectedType {
				t.Fatalf("expected content-type %s, got %s", tc.expectedType, resp.Headers["content-type"])
			}

			if tc.expectBodyText != "" && string(resp.Body) != tc.expectBodyText {
				t.Fatalf("expected body %q, got %q", tc.expectBodyText, string(resp.Body))
			}

			if tc.expectEmpty && len(resp.Body) != 0 {
				t.Fatalf("expected empty response body, got %q", string(resp.Body))
			}
		})
	}
}

func TestJWTAuthPolicy_Regression_OnFailureStatusCodeHonored(t *testing.T) {
	resetJWTAuthSingletonCache(t)

	params := newRemoteParams("http://localhost:8080/jwks.json")
	params["onFailureStatusCode"] = 403
	ctx, action := executeOnRequestHeaders(t, params, map[string][]string{})
	assertAuthFailure(t, ctx, action, 403)
}

func TestJWTAuthPolicy_Regression_MetadataSetOnSuccessAndFailure(t *testing.T) {
	resetJWTAuthSingletonCache(t)

	t.Run("success_metadata", func(t *testing.T) {
		resetJWTAuthSingletonCache(t)

		privateKey, publicKey := generateTestKeys(t)
		jwksServer := createJWKSServer(t, publicKey, "test-kid")
		defer jwksServer.Close()

		token := createTestToken(t, privateKey, map[string]interface{}{
			"sub": "user-123",
			"iss": "https://issuer.example.com",
		})
		params := newRemoteParams(jwksServer.URL + "/jwks.json")

		ctx, action := executeOnRequestHeaders(t, params, authHeader("Authorization", "Bearer", token))
		assertAuthSuccess(t, ctx, action)

		if ctx.SharedContext.AuthContext == nil || ctx.SharedContext.AuthContext.AuthType != "jwt" {
			t.Fatalf("expected auth type to be jwt")
		}
	})

	t.Run("failure_metadata", func(t *testing.T) {
		resetJWTAuthSingletonCache(t)

		params := newRemoteParams("http://localhost:8080/jwks.json")
		ctx, action := executeOnRequestHeaders(t, params, map[string][]string{})
		assertAuthFailure(t, ctx, action, 401)

		// On failure, AuthContext should indicate not authenticated
		if ctx.SharedContext.AuthContext != nil && ctx.SharedContext.AuthContext.Authenticated {
			t.Fatalf("did not expect authenticated context on failure path")
		}
	})
}

func TestJWTAuthPolicy_Regression_ModeContract(t *testing.T) {
	resetJWTAuthSingletonCache(t)

	p := mustGetPolicy(t, map[string]interface{}{})
	jwtPolicy, ok := p.(*JwtAuthPolicy)
	if !ok {
		t.Fatalf("expected *JwtAuthPolicy, got %T", p)
	}

	mode := jwtPolicy.Mode()
	if mode.RequestHeaderMode != policy.HeaderModeProcess {
		t.Fatalf("expected RequestHeaderMode to be process")
	}
	if mode.RequestBodyMode != policy.BodyModeSkip {
		t.Fatalf("expected RequestBodyMode to be skip")
	}
	if mode.ResponseHeaderMode != policy.HeaderModeSkip {
		t.Fatalf("expected ResponseHeaderMode to be skip")
	}
	if mode.ResponseBodyMode != policy.BodyModeSkip {
		t.Fatalf("expected ResponseBodyMode to be skip")
	}
}

func TestJWTAuthPolicy_Regression_RequiredClaimsTypeMismatch(t *testing.T) {
	resetJWTAuthSingletonCache(t)

	privateKey, publicKey := generateTestKeys(t)
	jwksServer := createJWKSServer(t, publicKey, "test-kid")
	defer jwksServer.Close()

	token := createRS256TokenWithKid(t, privateKey, map[string]interface{}{
		"sub":  "user-123",
		"iss":  "https://issuer.example.com",
		"role": []interface{}{"admin"},
	}, "test-kid")

	params := newRemoteParams(jwksServer.URL + "/jwks.json")
	params["requiredClaims"] = map[string]interface{}{
		"role": "admin",
	}

	ctx, action := executeOnRequestHeaders(t, params, authHeader("Authorization", "Bearer", token))
	assertAuthFailure(t, ctx, action, 401)
}

func TestJWTAuthPolicy_Regression_extractTokenVariants(t *testing.T) {
	tests := []struct {
		name     string
		header   string
		scheme   string
		expected string
	}{
		{
			name:     "scheme_match",
			header:   "Bearer abc.def.ghi",
			scheme:   "Bearer",
			expected: "abc.def.ghi",
		},
		{
			name:     "raw_token_without_scheme",
			header:   "abc.def.ghi",
			scheme:   "",
			expected: "abc.def.ghi",
		},
		{
			name:     "strip_unknown_scheme_when_not_enforced",
			header:   "JWT abc.def.ghi",
			scheme:   "",
			expected: "abc.def.ghi",
		},
		{
			name:     "scheme_case_insensitive_match",
			header:   "bearer abc.def.ghi",
			scheme:   "Bearer",
			expected: "abc.def.ghi",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := extractToken(tc.header, tc.scheme)
			if got != tc.expected {
				t.Fatalf("expected %q, got %q", tc.expected, got)
			}
		})
	}
}

func TestJWTAuthPolicy_Regression_parseAudienceVariants(t *testing.T) {
	tests := []struct {
		name     string
		claim    interface{}
		expected []string
	}{
		{name: "single_string", claim: "a1", expected: []string{"a1"}},
		{name: "array_values", claim: []interface{}{"a1", "a2"}, expected: []string{"a1", "a2"}},
		{name: "mixed_array", claim: []interface{}{"a1", 123}, expected: []string{"a1"}},
		{name: "invalid_type", claim: 123, expected: []string{}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := parseAudience(tc.claim)
			if len(got) != len(tc.expected) {
				t.Fatalf("expected %v, got %v", tc.expected, got)
			}
			for i := range got {
				if got[i] != tc.expected[i] {
					t.Fatalf("expected %v, got %v", tc.expected, got)
				}
			}
		})
	}
}

func TestJWTAuthPolicy_Regression_claimValueToStringAndGetKeyIds(t *testing.T) {
	if got := claimValueToString(float64(42)); got != "42" {
		t.Fatalf("expected numeric conversion, got %q", got)
	}
	if got := claimValueToString(true); got != "true" {
		t.Fatalf("expected bool conversion, got %q", got)
	}
	if got := claimValueToString([]interface{}{"a", "b"}); got != `["a","b"]` {
		t.Fatalf("expected json conversion for array, got %q", got)
	}

	key1 := &rsa.PublicKey{N: rsa.PublicKey{}.N, E: 65537}
	key2 := &rsa.PublicKey{N: rsa.PublicKey{}.N, E: 65537}
	keys := map[string]crypto.PublicKey{
		"kid-1": key1,
		"kid-2": key2,
	}
	ids := getKeyIds(keys)
	if len(ids) != 2 {
		t.Fatalf("expected 2 key IDs, got %d", len(ids))
	}
}

// createMockRequestHeaderContextWithAPI is like createMockRequestHeaderContext but sets an API
// identity, used to prove properties of how the verdict cache treats API identity.
func createMockRequestHeaderContextWithAPI(headers map[string][]string, apiId, apiName string) *policy.RequestHeaderContext {
	return &policy.RequestHeaderContext{
		SharedContext: &policy.SharedContext{
			RequestID: "test-request-id",
			Metadata:  make(map[string]interface{}),
			APIId:     apiId,
			APIName:   apiName,
		},
		Headers: policy.NewHeaders(headers),
		Path:    "/api/test",
		Method:  "GET",
	}
}

// clearJWKSFetchCache wipes the unrelated, pre-existing JWKS-fetch cache (cacheStore/cacheTTLs)
// without touching the token verdict cache. Tests that prove the verdict cache is what's being
// exercised must clear this too — otherwise a token-verdict-cache miss can still "succeed"
// because the JWKS keys for that URI are separately warm from an earlier request.
func clearJWKSFetchCache() {
	ins.cacheMutex.Lock()
	defer ins.cacheMutex.Unlock()
	ins.cacheStore = make(map[string]*CachedJWKS)
	ins.cacheTTLs = make(map[string]time.Time)
}

// clearConfigMemoizationCaches wipes the three config-lifetime memoization caches
// (parsedPublicKeys, resolveScopeConstraintsCache, resolveClaimConstraintsCache) so memoized
// constraints/keys from one test cannot leak into the next.
func clearConfigMemoizationCaches() {
	for _, m := range []*sync.Map{&parsedPublicKeys, &resolveScopeConstraintsCache, &resolveClaimConstraintsCache} {
		m.Range(func(k, _ interface{}) bool {
			m.Delete(k)
			return true
		})
	}
}

func resetJWTAuthSingletonCache(t *testing.T) {
	t.Helper()

	ins.cacheMutex.Lock()
	ins.cacheStore = make(map[string]*CachedJWKS)
	ins.cacheTTLs = make(map[string]time.Time)
	ins.cacheMutex.Unlock()
	_ = ins.currentTokenCache().Clear(context.Background())
	clearConfigMemoizationCaches()

	t.Cleanup(func() {
		ins.cacheMutex.Lock()
		ins.cacheStore = make(map[string]*CachedJWKS)
		ins.cacheTTLs = make(map[string]time.Time)
		ins.cacheMutex.Unlock()
		_ = ins.currentTokenCache().Clear(context.Background())
		clearConfigMemoizationCaches()
	})
}

func executeOnRequestHeaders(t *testing.T, params map[string]interface{}, headers map[string][]string) (*policy.RequestHeaderContext, policy.RequestHeaderAction) {
	t.Helper()
	p := mustGetPolicy(t, params)
	ctx := createMockRequestHeaderContext(headers)
	return ctx, p.(*JwtAuthPolicy).OnRequestHeaders(context.Background(), ctx, params)
}

func mustGetPolicy(t *testing.T, params map[string]interface{}) policy.Policy {
	t.Helper()
	p, err := GetPolicy(policy.PolicyMetadata{}, params)
	if err != nil {
		t.Fatalf("GetPolicy failed: %v", err)
	}
	return p
}

func newRemoteParams(jwksURI string) map[string]interface{} {
	return map[string]interface{}{
		"headerName":             "Authorization",
		"authHeaderScheme":       "Bearer",
		"onFailureStatusCode":    401,
		"errorMessageFormat":     "json",
		"errorMessage":           "Authentication failed",
		"leeway":                 "30s",
		"jwksCacheTtl":           "5m",
		"jwksFetchTimeout":       "100ms",
		"jwksFetchRetryCount":    0,
		"jwksFetchRetryInterval": "1ms",
		"validateIssuer":         true,
		"keyManagers": []interface{}{
			map[string]interface{}{
				"name":   "km-primary",
				"issuer": "https://issuer.example.com",
				"jwks": map[string]interface{}{
					"remote": map[string]interface{}{
						"uri": jwksURI,
					},
				},
			},
		},
	}
}

func authHeader(headerName, scheme, token string) map[string][]string {
	header := strings.ToLower(headerName)
	return map[string][]string{
		header: {fmt.Sprintf("%s %s", scheme, token)},
	}
}

func assertAuthSuccess(t *testing.T, reqCtx *policy.RequestHeaderContext, action policy.RequestHeaderAction) {
	t.Helper()

	if reqCtx == nil {
		t.Fatalf("request context cannot be nil")
	}
	if reqCtx.SharedContext.AuthContext == nil || !reqCtx.SharedContext.AuthContext.Authenticated {
		t.Fatalf("expected auth success, got unauthenticated context")
	}
	if _, ok := action.(policy.UpstreamRequestHeaderModifications); !ok {
		t.Fatalf("expected UpstreamRequestHeaderModifications, got %T", action)
	}
}

func assertAuthFailure(t *testing.T, reqCtx *policy.RequestHeaderContext, action policy.RequestHeaderAction, statusCode int) {
	t.Helper()

	if reqCtx == nil {
		t.Fatalf("request context cannot be nil")
	}
	if reqCtx.SharedContext.AuthContext != nil && reqCtx.SharedContext.AuthContext.Authenticated {
		t.Fatalf("expected auth failure, got authenticated context")
	}

	resp, ok := action.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("expected ImmediateResponse, got %T", action)
	}
	if resp.StatusCode != statusCode {
		t.Fatalf("expected status code %d, got %d", statusCode, resp.StatusCode)
	}
}

func createRS256TokenWithKid(t *testing.T, privateKey *rsa.PrivateKey, claims map[string]interface{}, kid string) string {
	t.Helper()
	claims = normalizeClaims(claims)

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims(claims))
	token.Header["kid"] = kid

	tokenString, err := token.SignedString(privateKey)
	if err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}
	return tokenString
}

func createUnsignedNoneToken(t *testing.T, claims map[string]interface{}) string {
	t.Helper()
	claims = normalizeClaims(claims)

	token := jwt.NewWithClaims(jwt.SigningMethodNone, jwt.MapClaims(claims))

	tokenString, err := token.SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatalf("failed to create unsigned token: %v", err)
	}
	return tokenString
}

func createTokenWithoutAlgHeader(t *testing.T, privateKey *rsa.PrivateKey, claims map[string]interface{}, kid string) string {
	t.Helper()
	claims = normalizeClaims(claims)

	headerJSON, err := json.Marshal(map[string]string{"typ": "JWT", "kid": kid})
	if err != nil {
		t.Fatalf("failed to marshal header: %v", err)
	}
	payloadJSON, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("failed to marshal claims: %v", err)
	}

	header := base64.RawURLEncoding.EncodeToString(headerJSON)
	payload := base64.RawURLEncoding.EncodeToString(payloadJSON)
	signingInput := header + "." + payload

	hashed := sha256.Sum256([]byte(signingInput))
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hashed[:])
	if err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}

	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func normalizeClaims(claims map[string]interface{}) map[string]interface{} {
	if _, ok := claims["exp"]; !ok {
		claims["exp"] = time.Now().Add(time.Hour).Unix()
	}
	if _, ok := claims["iat"]; !ok {
		claims["iat"] = time.Now().Unix()
	}
	return claims
}

// TestJWTAuthPolicy_Security_HMACConfusionRejected verifies that HS256 tokens are rejected
// because HS256 is not in the hardcoded supported algorithm set.
func TestJWTAuthPolicy_Security_HMACConfusionRejected(t *testing.T) {
	resetJWTAuthSingletonCache(t)

	_, publicKey := generateTestKeys(t)
	jwksServer := createJWKSServer(t, publicKey, "test-kid")
	defer jwksServer.Close()

	pubDER, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		t.Fatalf("failed to marshal public key: %v", err)
	}

	claims := normalizeClaims(map[string]interface{}{
		"sub": "user-123",
		"iss": "https://issuer.example.com",
	})
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims(claims))
	tok.Header["kid"] = "test-kid"
	tokenString, err := tok.SignedString(pubDER)
	if err != nil {
		t.Fatalf("failed to sign HS256 token: %v", err)
	}

	params := newRemoteParams(jwksServer.URL + "/jwks.json")
	ctx, action := executeOnRequestHeaders(t, params, authHeader("Authorization", "Bearer", tokenString))
	assertAuthFailure(t, ctx, action, 401)
}

// TestJWTAuthPolicy_Security_PS256Accepted verifies that PS256 (RSASSA-PSS) tokens are accepted
// when the JWKS contains the corresponding RSA public key.
func TestJWTAuthPolicy_Security_PS256Accepted(t *testing.T) {
	resetJWTAuthSingletonCache(t)

	privateKey, publicKey := generateTestKeys(t)
	jwksServer := createJWKSServer(t, publicKey, "test-kid")
	defer jwksServer.Close()

	claims := normalizeClaims(map[string]interface{}{
		"sub": "user-123",
		"iss": "https://issuer.example.com",
	})
	tok := jwt.NewWithClaims(jwt.SigningMethodPS256, jwt.MapClaims(claims))
	tok.Header["kid"] = "test-kid"
	tokenString, err := tok.SignedString(privateKey)
	if err != nil {
		t.Fatalf("failed to sign PS256 token: %v", err)
	}

	params := newRemoteParams(jwksServer.URL + "/jwks.json")
	ctx, action := executeOnRequestHeaders(t, params, authHeader("Authorization", "Bearer", tokenString))
	assertAuthSuccess(t, ctx, action)
}

// generateTestECKeys generates a P-256 ECDSA key pair for testing.
func generateTestECKeys(t *testing.T) (*ecdsa.PrivateKey, *ecdsa.PublicKey) {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate EC key: %v", err)
	}
	return privateKey, &privateKey.PublicKey
}

// createECJWKSServer creates a test HTTP server that serves a JWKS with a P-256 EC public key.
func createECJWKSServer(t *testing.T, publicKey *ecdsa.PublicKey, kid string) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/jwks.json" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		xB64 := base64.RawURLEncoding.EncodeToString(publicKey.X.Bytes())
		yB64 := base64.RawURLEncoding.EncodeToString(publicKey.Y.Bytes())
		jwks := map[string]interface{}{
			"keys": []map[string]interface{}{
				{
					"kty": "EC",
					"kid": kid,
					"use": "sig",
					"alg": "ES256",
					"crv": "P-256",
					"x":   xB64,
					"y":   yB64,
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(jwks); err != nil {
			t.Logf("failed to encode EC JWKS: %v", err)
		}
	}))
	return server
}

// createES256Token mints an ES256 JWT signed with the given EC private key.
func createES256Token(t *testing.T, privateKey *ecdsa.PrivateKey, claims map[string]interface{}, kid string) string {
	t.Helper()
	claims = normalizeClaims(claims)
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims(claims))
	tok.Header["kid"] = kid
	tokenString, err := tok.SignedString(privateKey)
	if err != nil {
		t.Fatalf("failed to sign ES256 token: %v", err)
	}
	return tokenString
}

// TestJWTAuthPolicy_Security_ES256Accepted verifies end-to-end ES256 support:
// the JWKS parser stores an EC key, the Keyfunc binds it to ECDSA, and the token passes.
func TestJWTAuthPolicy_Security_ES256Accepted(t *testing.T) {
	resetJWTAuthSingletonCache(t)

	ecPriv, ecPub := generateTestECKeys(t)
	jwksServer := createECJWKSServer(t, ecPub, "ec-kid")
	defer jwksServer.Close()

	token := createES256Token(t, ecPriv, map[string]interface{}{
		"sub": "user-456",
		"iss": "https://issuer.example.com",
	}, "ec-kid")

	params := newRemoteParams(jwksServer.URL + "/jwks.json")
	ctx, action := executeOnRequestHeaders(t, params, authHeader("Authorization", "Bearer", token))
	assertAuthSuccess(t, ctx, action)
}

// TestJWTAuthPolicy_Security_ES256WithRSAKeyRejected verifies that an ES256 token is rejected
// when the JWKS only contains an RSA key — the Keyfunc must refuse the method/key-type mismatch.
func TestJWTAuthPolicy_Security_ES256WithRSAKeyRejected(t *testing.T) {
	resetJWTAuthSingletonCache(t)

	// RSA JWKS
	_, rsaPub := generateTestKeys(t)
	rsaJWKSServer := createJWKSServer(t, rsaPub, "rsa-kid")
	defer rsaJWKSServer.Close()

	// EC private key — token claims ES256 but JWKS has RSA
	ecPriv, _ := generateTestECKeys(t)
	token := createES256Token(t, ecPriv, map[string]interface{}{
		"sub": "user-789",
		"iss": "https://issuer.example.com",
	}, "rsa-kid") // deliberately uses the RSA kid so key lookup succeeds, Keyfunc must then reject

	params := newRemoteParams(rsaJWKSServer.URL + "/jwks.json")
	ctx, action := executeOnRequestHeaders(t, params, authHeader("Authorization", "Bearer", token))
	assertAuthFailure(t, ctx, action, 401)
}

// TestJWTAuthPolicy_Security_UnsupportedAlgRejected verifies that algorithms outside the fixed
// set (RS256, PS256, ES256) are rejected by WithValidMethods before the Keyfunc is reached.
// RS384 is used: the JWKS key material matches the token's key, so the only reason for
// rejection is that RS384 is not in supportedAlgorithms.
func TestJWTAuthPolicy_Security_UnsupportedAlgRejected(t *testing.T) {
	resetJWTAuthSingletonCache(t)

	privateKey, publicKey := generateTestKeys(t)
	jwksServer := createJWKSServer(t, publicKey, "test-kid")
	defer jwksServer.Close()

	claims := normalizeClaims(map[string]interface{}{
		"sub": "user-123",
		"iss": "https://issuer.example.com",
	})
	tok := jwt.NewWithClaims(jwt.SigningMethodRS384, jwt.MapClaims(claims))
	tok.Header["kid"] = "test-kid"
	tokenString, err := tok.SignedString(privateKey)
	if err != nil {
		t.Fatalf("failed to sign RS384 token: %v", err)
	}

	params := newRemoteParams(jwksServer.URL + "/jwks.json")
	ctx, action := executeOnRequestHeaders(t, params, authHeader("Authorization", "Bearer", tokenString))
	assertAuthFailure(t, ctx, action, 401)
}

func writeJWKSResponse(t *testing.T, w http.ResponseWriter, publicKey *rsa.PublicKey, kid string) {
	t.Helper()
	nBytes := publicKey.N.Bytes()
	nB64 := base64.RawURLEncoding.EncodeToString(nBytes)

	eBytes := make([]byte, 4)
	eBytes[0] = byte((publicKey.E >> 24) & 0xFF)
	eBytes[1] = byte((publicKey.E >> 16) & 0xFF)
	eBytes[2] = byte((publicKey.E >> 8) & 0xFF)
	eBytes[3] = byte(publicKey.E & 0xFF)
	for len(eBytes) > 1 && eBytes[0] == 0 {
		eBytes = eBytes[1:]
	}
	eB64 := base64.RawURLEncoding.EncodeToString(eBytes)

	jwks := map[string]interface{}{
		"keys": []map[string]interface{}{
			{
				"kty": "RSA",
				"kid": kid,
				"use": "sig",
				"alg": "RS256",
				"n":   nB64,
				"e":   eB64,
			},
		},
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(jwks); err != nil {
		t.Logf("Failed to encode JWKS: %v", err)
	}
}

// ============================================================================
// scopes / claims (new params) — unit tests for the pure resolution/evaluation
// helpers, plus integration tests through OnRequestHeaders.
// ============================================================================

// ifaceStrings converts a string list into the []interface{} form config values arrive as.
func ifaceStrings(ss ...string) []interface{} {
	out := make([]interface{}, len(ss))
	for i, s := range ss {
		out[i] = s
	}
	return out
}

// claimMatcherParam builds a raw {claim, values:[…]} matcher as it appears in config.
func claimMatcherParam(claim string, values ...string) map[string]interface{} {
	return map[string]interface{}{"claim": claim, "values": ifaceStrings(values...)}
}

// setScopes sets the new `scopes` param on params (nil slice → that side omitted).
func setScopes(params map[string]interface{}, allOf, anyOf []string) {
	m := map[string]interface{}{}
	if allOf != nil {
		m["allOf"] = ifaceStrings(allOf...)
	}
	if anyOf != nil {
		m["anyOf"] = ifaceStrings(anyOf...)
	}
	params["scopes"] = m
}

// setClaims sets the new `claims` param on params (nil slice → that side omitted).
func setClaims(params map[string]interface{}, allOf, anyOf []map[string]interface{}) {
	m := map[string]interface{}{}
	if allOf != nil {
		arr := make([]interface{}, len(allOf))
		for i, e := range allOf {
			arr[i] = e
		}
		m["allOf"] = arr
	}
	if anyOf != nil {
		arr := make([]interface{}, len(anyOf))
		for i, e := range anyOf {
			arr[i] = e
		}
		m["anyOf"] = arr
	}
	params["claims"] = m
}

func TestResolveScopeConstraints(t *testing.T) {
	tests := []struct {
		name    string
		params  map[string]interface{}
		want    ScopeConstraints
		wantErr bool
	}{
		{
			name:   "new only",
			params: map[string]interface{}{"scopes": map[string]interface{}{"allOf": ifaceStrings("api:read"), "anyOf": ifaceStrings("api:write", "api:update")}},
			want:   ScopeConstraints{AllOf: []string{"api:read"}, AnyOf: []string{"api:write", "api:update"}},
		},
		{
			name:   "old only maps to anyOf",
			params: map[string]interface{}{"requiredScopes": ifaceStrings("api:read", "api:write")},
			want:   ScopeConstraints{AnyOf: []string{"api:read", "api:write"}},
		},
		{
			name: "new wins over old",
			params: map[string]interface{}{
				"scopes":         map[string]interface{}{"allOf": ifaceStrings("api:read")},
				"requiredScopes": ifaceStrings("api:write"),
			},
			want: ScopeConstraints{AllOf: []string{"api:read"}},
		},
		{
			name: "empty new falls back to old (D1)",
			params: map[string]interface{}{
				"scopes":         map[string]interface{}{},
				"requiredScopes": ifaceStrings("api:read"),
			},
			want: ScopeConstraints{AnyOf: []string{"api:read"}},
		},
		{
			name:   "neither",
			params: map[string]interface{}{},
			want:   ScopeConstraints{},
		},
		{
			name:    "malformed new (D2)",
			params:  map[string]interface{}{"scopes": "not-an-object"},
			wantErr: true,
		},
		{
			name:    "malformed new array item (D2)",
			params:  map[string]interface{}{"scopes": map[string]interface{}{"allOf": []interface{}{123}}},
			wantErr: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := resolveScopeConstraints(tc.params)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil (result %+v)", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("got %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestResolveClaimConstraints(t *testing.T) {
	tests := []struct {
		name    string
		params  map[string]interface{}
		want    ClaimConstraints
		wantErr bool
	}{
		{
			name: "new only",
			params: map[string]interface{}{"claims": map[string]interface{}{
				"anyOf": []interface{}{claimMatcherParam("department", "platform", "engineering")},
				"allOf": []interface{}{claimMatcherParam("status", "suspended")},
			}},
			want: ClaimConstraints{
				AllOf: []ClaimMatcher{{Claim: "status", Values: []string{"suspended"}}},
				AnyOf: []ClaimMatcher{{Claim: "department", Values: []string{"platform", "engineering"}}},
			},
		},
		{
			name:   "old only maps to allOf with legacy flag",
			params: map[string]interface{}{"requiredClaims": map[string]interface{}{"role": "admin"}},
			want:   ClaimConstraints{AllOf: []ClaimMatcher{{Claim: "role", Values: []string{"admin"}, legacyExactString: true}}},
		},
		{
			name: "new wins over old",
			params: map[string]interface{}{
				"claims":         map[string]interface{}{"allOf": []interface{}{claimMatcherParam("role", "admin")}},
				"requiredClaims": map[string]interface{}{"role": "user"},
			},
			want: ClaimConstraints{AllOf: []ClaimMatcher{{Claim: "role", Values: []string{"admin"}}}},
		},
		{
			name: "empty new falls back to old (D1)",
			params: map[string]interface{}{
				"claims":         map[string]interface{}{},
				"requiredClaims": map[string]interface{}{"role": "admin"},
			},
			want: ClaimConstraints{AllOf: []ClaimMatcher{{Claim: "role", Values: []string{"admin"}, legacyExactString: true}}},
		},
		{
			name:    "malformed: missing values (D2)",
			params:  map[string]interface{}{"claims": map[string]interface{}{"allOf": []interface{}{map[string]interface{}{"claim": "role"}}}},
			wantErr: true,
		},
		{
			name:    "malformed: empty values (D2)",
			params:  map[string]interface{}{"claims": map[string]interface{}{"allOf": []interface{}{map[string]interface{}{"claim": "role", "values": []interface{}{}}}}},
			wantErr: true,
		},
		{
			name:    "malformed: entry not object (D2)",
			params:  map[string]interface{}{"claims": map[string]interface{}{"anyOf": []interface{}{"nope"}}},
			wantErr: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := resolveClaimConstraints(tc.params)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil (result %+v)", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("got %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestEvaluateScopeConstraints(t *testing.T) {
	set := func(ss ...string) map[string]bool {
		m := map[string]bool{}
		for _, s := range ss {
			m[s] = true
		}
		return m
	}
	tests := []struct {
		name   string
		sc     ScopeConstraints
		scopes map[string]bool
		want   bool
	}{
		{"allOf all present", ScopeConstraints{AllOf: []string{"api:read", "api:deploy"}}, set("api:read", "api:deploy", "extra"), true},
		{"allOf missing one", ScopeConstraints{AllOf: []string{"api:read", "api:deploy"}}, set("api:read"), false},
		{"anyOf one present", ScopeConstraints{AnyOf: []string{"api:write", "api:update"}}, set("api:update"), true},
		{"anyOf none present", ScopeConstraints{AnyOf: []string{"api:write", "api:update"}}, set("api:read"), false},
		{"both satisfied", ScopeConstraints{AllOf: []string{"api:read", "api:deploy"}, AnyOf: []string{"api:write", "api:update"}}, set("api:read", "api:deploy", "api:write"), true},
		{"both, anyOf fails", ScopeConstraints{AllOf: []string{"api:read", "api:deploy"}, AnyOf: []string{"api:write", "api:update"}}, set("api:read", "api:deploy"), false},
		{"both, allOf fails", ScopeConstraints{AllOf: []string{"api:read", "api:deploy"}, AnyOf: []string{"api:write"}}, set("api:read", "api:write"), false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got, _ := evaluateScopeConstraints(tc.sc, tc.scopes); got != tc.want {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestEvaluateClaimConstraints(t *testing.T) {
	mc := func(m map[string]interface{}) jwt.MapClaims { return jwt.MapClaims(m) }
	tests := []struct {
		name   string
		cc     ClaimConstraints
		claims jwt.MapClaims
		want   bool
	}{
		{
			name:   "anyOf matches one value",
			cc:     ClaimConstraints{AnyOf: []ClaimMatcher{{Claim: "department", Values: []string{"platform", "engineering"}}}},
			claims: mc(map[string]interface{}{"department": "engineering"}),
			want:   true,
		},
		{
			name:   "anyOf no match",
			cc:     ClaimConstraints{AnyOf: []ClaimMatcher{{Claim: "department", Values: []string{"platform"}}}},
			claims: mc(map[string]interface{}{"department": "sales"}),
			want:   false,
		},
		{
			name: "allOf all match",
			cc: ClaimConstraints{AllOf: []ClaimMatcher{
				{Claim: "status", Values: []string{"suspended"}},
				{Claim: "role", Values: []string{"internal"}},
			}},
			claims: mc(map[string]interface{}{"status": "suspended", "role": "internal"}),
			want:   true,
		},
		{
			name: "allOf one fails",
			cc: ClaimConstraints{AllOf: []ClaimMatcher{
				{Claim: "status", Values: []string{"suspended"}},
				{Claim: "role", Values: []string{"internal"}},
			}},
			claims: mc(map[string]interface{}{"status": "suspended", "role": "external"}),
			want:   false,
		},
		{
			name:   "multi-valued claim intersects",
			cc:     ClaimConstraints{AllOf: []ClaimMatcher{{Claim: "roles", Values: []string{"internal"}}}},
			claims: mc(map[string]interface{}{"roles": []interface{}{"external", "internal"}}),
			want:   true,
		},
		{
			name:   "missing claim fails closed",
			cc:     ClaimConstraints{AllOf: []ClaimMatcher{{Claim: "role", Values: []string{"internal"}}}},
			claims: mc(map[string]interface{}{}),
			want:   false,
		},
		{
			name:   "legacy exact string does not match array",
			cc:     ClaimConstraints{AllOf: []ClaimMatcher{{Claim: "role", Values: []string{"admin"}, legacyExactString: true}}},
			claims: mc(map[string]interface{}{"role": []interface{}{"admin"}}),
			want:   false,
		},
		{
			name:   "legacy exact string matches scalar",
			cc:     ClaimConstraints{AllOf: []ClaimMatcher{{Claim: "role", Values: []string{"admin"}, legacyExactString: true}}},
			claims: mc(map[string]interface{}{"role": "admin"}),
			want:   true,
		},
		{
			name: "full example: claims AND",
			cc: ClaimConstraints{
				AnyOf: []ClaimMatcher{{Claim: "department", Values: []string{"platform", "engineering"}}},
				AllOf: []ClaimMatcher{
					{Claim: "status", Values: []string{"suspended"}},
					{Claim: "role", Values: []string{"internal"}},
				},
			},
			claims: mc(map[string]interface{}{"department": "platform", "status": "suspended", "role": "internal"}),
			want:   true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got, _ := evaluateClaimConstraints(tc.cc, tc.claims); got != tc.want {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestLogDeprecatedParamUsage(t *testing.T) {
	capture := func(params map[string]interface{}) string {
		var buf bytes.Buffer
		prev := slog.Default()
		slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
		defer slog.SetDefault(prev)
		logDeprecatedParamUsage(params)
		return buf.String()
	}

	// New params only → no deprecation warning (decision D3).
	if out := capture(map[string]interface{}{
		"scopes": map[string]interface{}{"allOf": ifaceStrings("api:read")},
	}); strings.Contains(out, "deprecated") {
		t.Fatalf("expected no deprecation warning, got: %s", out)
	}

	// Old requiredScopes only → migrate warning.
	if out := capture(map[string]interface{}{"requiredScopes": ifaceStrings("api:read")}); !strings.Contains(out, "'requiredScopes' is deprecated; migrate") {
		t.Fatalf("expected migrate warning, got: %s", out)
	}

	// Old + new (same dimension) → "ignored" variant.
	if out := capture(map[string]interface{}{
		"requiredScopes": ifaceStrings("api:read"),
		"scopes":         map[string]interface{}{"allOf": ifaceStrings("api:read")},
	}); !strings.Contains(out, "ignored because 'scopes' is configured") {
		t.Fatalf("expected 'ignored' warning, got: %s", out)
	}

	// Old requiredClaims → warning.
	if out := capture(map[string]interface{}{"requiredClaims": map[string]interface{}{"role": "admin"}}); !strings.Contains(out, "'requiredClaims' is deprecated") {
		t.Fatalf("expected requiredClaims warning, got: %s", out)
	}
}

// ---------- integration tests through OnRequestHeaders ----------

func TestJWTAuthPolicy_Scopes_AllOf_PassAndFail(t *testing.T) {
	resetJWTAuthSingletonCache(t)
	privateKey, publicKey := generateTestKeys(t)
	jwksServer := createJWKSServer(t, publicKey, "test-kid")
	defer jwksServer.Close()

	makeToken := func(scope string) string {
		return createTestToken(t, privateKey, map[string]interface{}{
			"sub": "user-1", "iss": "https://issuer.example.com", "scope": scope,
		})
	}

	// All required scopes present → success.
	params := newRemoteParams(jwksServer.URL + "/jwks.json")
	setScopes(params, []string{"api:read", "api:deploy"}, nil)
	ctx, action := executeOnRequestHeaders(t, params, authHeader("Authorization", "Bearer", makeToken("api:read api:deploy api:write")))
	assertAuthSuccess(t, ctx, action)

	// Missing one of the allOf scopes → deny.
	params2 := newRemoteParams(jwksServer.URL + "/jwks.json")
	setScopes(params2, []string{"api:read", "api:deploy"}, nil)
	ctx2, action2 := executeOnRequestHeaders(t, params2, authHeader("Authorization", "Bearer", makeToken("api:read")))
	assertAuthFailure(t, ctx2, action2, 401)
}

func TestJWTAuthPolicy_Scopes_Combined_Example(t *testing.T) {
	resetJWTAuthSingletonCache(t)
	privateKey, publicKey := generateTestKeys(t)
	jwksServer := createJWKSServer(t, publicKey, "test-kid")
	defer jwksServer.Close()

	// scopes: allOf [api:read, api:deploy] AND anyOf [api:write, api:update]
	newParams := func() map[string]interface{} {
		p := newRemoteParams(jwksServer.URL + "/jwks.json")
		setScopes(p, []string{"api:read", "api:deploy"}, []string{"api:write", "api:update"})
		return p
	}
	tok := func(scope string) string {
		return createTestToken(t, privateKey, map[string]interface{}{
			"sub": "user-1", "iss": "https://issuer.example.com", "scope": scope,
		})
	}

	// allOf satisfied and one anyOf present → success.
	ctx, action := executeOnRequestHeaders(t, newParams(), authHeader("Authorization", "Bearer", tok("api:read api:deploy api:update")))
	assertAuthSuccess(t, ctx, action)

	// allOf satisfied but no anyOf present → deny.
	ctx2, action2 := executeOnRequestHeaders(t, newParams(), authHeader("Authorization", "Bearer", tok("api:read api:deploy")))
	assertAuthFailure(t, ctx2, action2, 401)
}

func TestJWTAuthPolicy_Claims_Example(t *testing.T) {
	resetJWTAuthSingletonCache(t)
	privateKey, publicKey := generateTestKeys(t)
	jwksServer := createJWKSServer(t, publicKey, "test-kid")
	defer jwksServer.Close()

	// claims: anyOf [department in {platform, engineering}] AND allOf [status=suspended, role=internal]
	newParams := func() map[string]interface{} {
		p := newRemoteParams(jwksServer.URL + "/jwks.json")
		setClaims(p,
			[]map[string]interface{}{claimMatcherParam("status", "suspended"), claimMatcherParam("role", "internal")},
			[]map[string]interface{}{claimMatcherParam("department", "platform", "engineering")},
		)
		return p
	}

	// All satisfied → success.
	okToken := createTestToken(t, privateKey, map[string]interface{}{
		"sub": "user-1", "iss": "https://issuer.example.com",
		"department": "platform", "status": "suspended", "role": "internal",
	})
	ctx, action := executeOnRequestHeaders(t, newParams(), authHeader("Authorization", "Bearer", okToken))
	assertAuthSuccess(t, ctx, action)

	// One allOf matcher fails (role) → deny.
	badToken := createTestToken(t, privateKey, map[string]interface{}{
		"sub": "user-1", "iss": "https://issuer.example.com",
		"department": "platform", "status": "suspended", "role": "external",
	})
	ctx2, action2 := executeOnRequestHeaders(t, newParams(), authHeader("Authorization", "Bearer", badToken))
	assertAuthFailure(t, ctx2, action2, 401)

	// anyOf fails (department not in set) → deny.
	badDept := createTestToken(t, privateKey, map[string]interface{}{
		"sub": "user-1", "iss": "https://issuer.example.com",
		"department": "sales", "status": "suspended", "role": "internal",
	})
	ctx3, action3 := executeOnRequestHeaders(t, newParams(), authHeader("Authorization", "Bearer", badDept))
	assertAuthFailure(t, ctx3, action3, 401)
}

func TestJWTAuthPolicy_Precedence_ScopesOverRequiredScopes(t *testing.T) {
	resetJWTAuthSingletonCache(t)
	privateKey, publicKey := generateTestKeys(t)
	jwksServer := createJWKSServer(t, publicKey, "test-kid")
	defer jwksServer.Close()

	// Token has api:read only. Old requiredScopes:[api:read] would PASS; new scopes.allOf:[api:deploy]
	// FAILS. Both set → new must win → deny.
	token := createTestToken(t, privateKey, map[string]interface{}{
		"sub": "user-1", "iss": "https://issuer.example.com", "scope": "api:read",
	})
	params := newRemoteParams(jwksServer.URL + "/jwks.json")
	params["requiredScopes"] = ifaceStrings("api:read")
	setScopes(params, []string{"api:deploy"}, nil)

	ctx, action := executeOnRequestHeaders(t, params, authHeader("Authorization", "Bearer", token))
	assertAuthFailure(t, ctx, action, 401)
}

func TestJWTAuthPolicy_Precedence_ClaimsOverRequiredClaims(t *testing.T) {
	resetJWTAuthSingletonCache(t)
	privateKey, publicKey := generateTestKeys(t)
	jwksServer := createJWKSServer(t, publicKey, "test-kid")
	defer jwksServer.Close()

	// Old requiredClaims:{role:admin} PASSES; new claims.allOf:[{role:[superadmin]}] FAILS.
	// Both set → new must win → deny.
	token := createTestToken(t, privateKey, map[string]interface{}{
		"sub": "user-1", "iss": "https://issuer.example.com", "role": "admin",
	})
	params := newRemoteParams(jwksServer.URL + "/jwks.json")
	params["requiredClaims"] = map[string]interface{}{"role": "admin"}
	setClaims(params, []map[string]interface{}{claimMatcherParam("role", "superadmin")}, nil)

	ctx, action := executeOnRequestHeaders(t, params, authHeader("Authorization", "Bearer", token))
	assertAuthFailure(t, ctx, action, 401)
}

func TestJWTAuthPolicy_Mixed_NewScopes_OldClaims(t *testing.T) {
	resetJWTAuthSingletonCache(t)
	privateKey, publicKey := generateTestKeys(t)
	jwksServer := createJWKSServer(t, publicKey, "test-kid")
	defer jwksServer.Close()

	// New scopes for the scope dimension (passes) + deprecated requiredClaims for the claim
	// dimension (fails). Each dimension is enforced independently → deny on the claim check.
	token := createTestToken(t, privateKey, map[string]interface{}{
		"sub": "user-1", "iss": "https://issuer.example.com",
		"scope": "api:read", "role": "user",
	})
	params := newRemoteParams(jwksServer.URL + "/jwks.json")
	setScopes(params, []string{"api:read"}, nil)
	params["requiredClaims"] = map[string]interface{}{"role": "admin"}

	ctx, action := executeOnRequestHeaders(t, params, authHeader("Authorization", "Bearer", token))
	assertAuthFailure(t, ctx, action, 401)
}

func TestJWTAuthPolicy_MalformedScopes_Denies(t *testing.T) {
	resetJWTAuthSingletonCache(t)
	privateKey, publicKey := generateTestKeys(t)
	jwksServer := createJWKSServer(t, publicKey, "test-kid")
	defer jwksServer.Close()

	// scopes present but malformed (not an object) → fail closed (decision D2).
	token := createTestToken(t, privateKey, map[string]interface{}{
		"sub": "user-1", "iss": "https://issuer.example.com", "scope": "api:read",
	})
	params := newRemoteParams(jwksServer.URL + "/jwks.json")
	params["scopes"] = "not-an-object"

	ctx, action := executeOnRequestHeaders(t, params, authHeader("Authorization", "Bearer", token))
	assertAuthFailure(t, ctx, action, 401)
}

func TestJWTAuthPolicy_EmptyNewScopes_FallsBackToOld(t *testing.T) {
	resetJWTAuthSingletonCache(t)
	privateKey, publicKey := generateTestKeys(t)
	jwksServer := createJWKSServer(t, publicKey, "test-kid")
	defer jwksServer.Close()

	// scopes present but empty ({}) → treated as unset (D1); deprecated requiredScopes applies.
	token := createTestToken(t, privateKey, map[string]interface{}{
		"sub": "user-1", "iss": "https://issuer.example.com", "scope": "api:read",
	})
	params := newRemoteParams(jwksServer.URL + "/jwks.json")
	params["scopes"] = map[string]interface{}{}
	params["requiredScopes"] = ifaceStrings("api:read")

	ctx, action := executeOnRequestHeaders(t, params, authHeader("Authorization", "Bearer", token))
	assertAuthSuccess(t, ctx, action)
}

// TestJWTAuthPolicy_NewScopes_And_NewClaims exercises both new params on one operation: both
// dimensions must pass.
func TestJWTAuthPolicy_NewScopes_And_NewClaims(t *testing.T) {
	resetJWTAuthSingletonCache(t)
	privateKey, publicKey := generateTestKeys(t)
	jwksServer := createJWKSServer(t, publicKey, "test-kid")
	defer jwksServer.Close()

	newParams := func() map[string]interface{} {
		p := newRemoteParams(jwksServer.URL + "/jwks.json")
		setScopes(p, []string{"api:read"}, nil)
		setClaims(p, []map[string]interface{}{claimMatcherParam("role", "internal")}, nil)
		return p
	}

	// Both satisfied → success.
	okToken := createTestToken(t, privateKey, map[string]interface{}{
		"sub": "u", "iss": "https://issuer.example.com", "scope": "api:read", "role": "internal",
	})
	ctx, action := executeOnRequestHeaders(t, newParams(), authHeader("Authorization", "Bearer", okToken))
	assertAuthSuccess(t, ctx, action)

	// Scope ok but claim fails → deny.
	badClaim := createTestToken(t, privateKey, map[string]interface{}{
		"sub": "u", "iss": "https://issuer.example.com", "scope": "api:read", "role": "external",
	})
	ctx2, action2 := executeOnRequestHeaders(t, newParams(), authHeader("Authorization", "Bearer", badClaim))
	assertAuthFailure(t, ctx2, action2, 401)

	// Claim ok but scope fails → deny.
	badScope := createTestToken(t, privateKey, map[string]interface{}{
		"sub": "u", "iss": "https://issuer.example.com", "scope": "api:other", "role": "internal",
	})
	ctx3, action3 := executeOnRequestHeaders(t, newParams(), authHeader("Authorization", "Bearer", badScope))
	assertAuthFailure(t, ctx3, action3, 401)
}

// TestJWTAuthPolicy_Mixed_OldScopes_NewClaims is the reverse mix of
// TestJWTAuthPolicy_Mixed_NewScopes_OldClaims: the deprecated requiredScopes governs the scope
// dimension while the new claims governs the claim dimension; both are enforced independently.
func TestJWTAuthPolicy_Mixed_OldScopes_NewClaims(t *testing.T) {
	resetJWTAuthSingletonCache(t)
	privateKey, publicKey := generateTestKeys(t)
	jwksServer := createJWKSServer(t, publicKey, "test-kid")
	defer jwksServer.Close()

	newParams := func() map[string]interface{} {
		p := newRemoteParams(jwksServer.URL + "/jwks.json")
		p["requiredScopes"] = ifaceStrings("api:read")
		setClaims(p, []map[string]interface{}{claimMatcherParam("role", "internal")}, nil)
		return p
	}

	// Both dimensions pass → success.
	okToken := createTestToken(t, privateKey, map[string]interface{}{
		"sub": "u", "iss": "https://issuer.example.com", "scope": "api:read", "role": "internal",
	})
	ctx, action := executeOnRequestHeaders(t, newParams(), authHeader("Authorization", "Bearer", okToken))
	assertAuthSuccess(t, ctx, action)

	// New claim dimension fails (old scope dimension still passes) → deny.
	badClaim := createTestToken(t, privateKey, map[string]interface{}{
		"sub": "u", "iss": "https://issuer.example.com", "scope": "api:read", "role": "external",
	})
	ctx2, action2 := executeOnRequestHeaders(t, newParams(), authHeader("Authorization", "Bearer", badClaim))
	assertAuthFailure(t, ctx2, action2, 401)

	// Old scope dimension fails (new claim dimension passes) → deny.
	badScope := createTestToken(t, privateKey, map[string]interface{}{
		"sub": "u", "iss": "https://issuer.example.com", "scope": "api:other", "role": "internal",
	})
	ctx3, action3 := executeOnRequestHeaders(t, newParams(), authHeader("Authorization", "Bearer", badScope))
	assertAuthFailure(t, ctx3, action3, 401)
}

// TestJWTAuthPolicy_BothFormats_NewWinsBothDimensions defines all four params (deprecated and new
// for both dimensions) on one operation and confirms the new params win both dimensions.
func TestJWTAuthPolicy_BothFormats_NewWinsBothDimensions(t *testing.T) {
	resetJWTAuthSingletonCache(t)
	privateKey, publicKey := generateTestKeys(t)
	jwksServer := createJWKSServer(t, publicKey, "test-kid")
	defer jwksServer.Close()

	newParams := func() map[string]interface{} {
		p := newRemoteParams(jwksServer.URL + "/jwks.json")
		p["requiredScopes"] = ifaceStrings("api:legacy")
		p["requiredClaims"] = map[string]interface{}{"role": "legacy"}
		setScopes(p, []string{"api:read"}, nil)
		setClaims(p, []map[string]interface{}{claimMatcherParam("role", "internal")}, nil)
		return p
	}

	// Passes the NEW params (and fails the OLD ones, which are ignored) → success.
	newOK := createTestToken(t, privateKey, map[string]interface{}{
		"sub": "u", "iss": "https://issuer.example.com", "scope": "api:read", "role": "internal",
	})
	ctx, action := executeOnRequestHeaders(t, newParams(), authHeader("Authorization", "Bearer", newOK))
	assertAuthSuccess(t, ctx, action)

	// Passes the OLD params but fails the NEW ones → deny (new wins both dimensions).
	oldOnly := createTestToken(t, privateKey, map[string]interface{}{
		"sub": "u", "iss": "https://issuer.example.com", "scope": "api:legacy", "role": "legacy",
	})
	ctx2, action2 := executeOnRequestHeaders(t, newParams(), authHeader("Authorization", "Bearer", oldOnly))
	assertAuthFailure(t, ctx2, action2, 401)
}
