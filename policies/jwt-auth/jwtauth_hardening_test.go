package jwtauth

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	policy "github.com/wso2/api-platform/sdk/gateway/policy/v1alpha"
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

	ctx, action := executeOnRequest(t, params, authHeader("Authorization", "Bearer", token))
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

	ctx, action := executeOnRequest(t, params, authHeader("Authorization", "Bearer", token))
	assertAuthSuccess(t, ctx, action)
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

	ctx, action := executeOnRequest(t, params, authHeader("X-Auth-Token", "JWT", token))
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

	ctx, action := executeOnRequest(t, params, authHeader("Authorization", "Bearer", token))
	assertAuthSuccess(t, ctx, action)

	mods, ok := action.(policy.UpstreamRequestModifications)
	if !ok {
		t.Fatalf("expected UpstreamRequestModifications, got %T", action)
	}
	if mods.SetHeaders["X-User-Email"] != "alice@example.com" {
		t.Fatalf("expected X-User-Email header to be set")
	}
	if ctx.SharedContext.AuthContext[AuthContextKeyUserID] != "alice" {
		t.Fatalf("expected %s to be set from userIdClaim", AuthContextKeyUserID)
	}
}

func TestJWTAuthPolicy_Negative_MissingAuthorizationHeader(t *testing.T) {
	resetJWTAuthSingletonCache(t)

	params := newRemoteParams("http://localhost:8080/jwks.json")
	params["onFailureStatusCode"] = 403
	params["errorMessageFormat"] = "plain"
	params["errorMessage"] = "missing auth"

	ctx, action := executeOnRequest(t, params, map[string][]string{})
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

	ctx, action := executeOnRequest(t, params, authHeader("Authorization", "JWT", token))
	assertAuthFailure(t, ctx, action, 401)
}

func TestJWTAuthPolicy_Negative_MalformedJWT(t *testing.T) {
	resetJWTAuthSingletonCache(t)

	params := newRemoteParams("http://localhost:8080/jwks.json")
	ctx, action := executeOnRequest(t, params, authHeader("Authorization", "Bearer", "not.a.jwt"))
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
	ctx, action := executeOnRequest(t, params, authHeader("Authorization", "Bearer", token))
	assertAuthFailure(t, ctx, action, 401)
}

func TestJWTAuthPolicy_Negative_DisallowedAlgorithm(t *testing.T) {
	resetJWTAuthSingletonCache(t)

	privateKey, publicKey := generateTestKeys(t)
	jwksServer := createJWKSServer(t, publicKey, "test-kid")
	defer jwksServer.Close()

	token := createTestToken(t, privateKey, map[string]interface{}{
		"sub": "user-123",
		"iss": "https://issuer.example.com",
	})

	params := newRemoteParams(jwksServer.URL + "/jwks.json")
	params["allowedAlgorithms"] = []interface{}{"ES256"}

	ctx, action := executeOnRequest(t, params, authHeader("Authorization", "Bearer", token))
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
	ctx, action := executeOnRequest(t, params, authHeader("Authorization", "Bearer", token))
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

	ctx, action := executeOnRequest(t, params, authHeader("Authorization", "Bearer", token))
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

	ctx, action := executeOnRequest(t, params, authHeader("Authorization", "Bearer", token))
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

	ctx, action := executeOnRequest(t, params, authHeader("Authorization", "Bearer", token))
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

	ctx, action := executeOnRequest(t, params, authHeader("Authorization", "Bearer", token))
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
		ctx    *policy.RequestContext
		action policy.RequestAction
	)

	defer func() {
		if recovered := recover(); recovered != nil {
			t.Fatalf("OnRequest must not panic for invalid retry count: %v", recovered)
		}
		assertAuthFailure(t, ctx, action, 401)
	}()

	ctx, action = executeOnRequest(t, params, authHeader("Authorization", "Bearer", token))
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

	ctx, action := executeOnRequest(t, params, authHeader("Authorization", "Bearer", token))
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

	ctx1 := createMockRequestContext(authHeader("Authorization", "Bearer", token))
	action1 := p.OnRequest(ctx1, params)
	assertAuthSuccess(t, ctx1, action1)

	ctx2 := createMockRequestContext(authHeader("Authorization", "Bearer", token))
	action2 := p.OnRequest(ctx2, params)
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

	token := createTestToken(t, privateKey, map[string]interface{}{
		"sub": "user-123",
		"iss": "https://issuer.example.com",
	})

	p := mustGetPolicy(t, params)

	ctx1 := createMockRequestContext(authHeader("Authorization", "Bearer", token))
	action1 := p.OnRequest(ctx1, params)
	assertAuthSuccess(t, ctx1, action1)

	time.Sleep(25 * time.Millisecond)

	ctx2 := createMockRequestContext(authHeader("Authorization", "Bearer", token))
	action2 := p.OnRequest(ctx2, params)
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
	params["allowedAlgorithms"] = []interface{}{"RS256"}

	ctx, action := executeOnRequest(t, params, authHeader("Authorization", "Bearer", token))
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

	ctx, action := executeOnRequest(t, params, authHeader("Authorization", "Bearer", token))
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

	ctx, action := executeOnRequest(t, params, authHeader("Authorization", "Bearer", token))
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

	ctx, action := executeOnRequest(t, params, authHeader("Authorization", "Bearer", token))
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

			ctx, action := executeOnRequest(t, params, authHeader("Authorization", "Bearer", token))
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
	ctx, action := executeOnRequest(t, params, authHeader("Authorization", "bearer", token))
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

			ctx, action := executeOnRequest(t, params, map[string][]string{})
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
	ctx, action := executeOnRequest(t, params, map[string][]string{})
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

		ctx, action := executeOnRequest(t, params, authHeader("Authorization", "Bearer", token))
		assertAuthSuccess(t, ctx, action)

		if ctx.Metadata[MetadataKeyAuthMethod] != "jwt" {
			t.Fatalf("expected auth method metadata to be jwt")
		}
		if _, ok := ctx.Metadata[MetadataKeyTokenClaims]; !ok {
			t.Fatalf("expected token claims metadata to be set")
		}
		if _, ok := ctx.Metadata[MetadataValidatedClaims]; !ok {
			t.Fatalf("expected validated claims metadata to be set")
		}
	})

	t.Run("failure_metadata", func(t *testing.T) {
		resetJWTAuthSingletonCache(t)

		params := newRemoteParams("http://localhost:8080/jwks.json")
		ctx, action := executeOnRequest(t, params, map[string][]string{})
		assertAuthFailure(t, ctx, action, 401)

		if ctx.Metadata[MetadataKeyAuthMethod] != "jwt" {
			t.Fatalf("expected auth method metadata to be jwt")
		}
		if _, ok := ctx.Metadata[MetadataValidatedClaims]; ok {
			t.Fatalf("did not expect validated claims on failure path")
		}
	})
}

func TestJWTAuthPolicy_Regression_ModeAndOnResponseContract(t *testing.T) {
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

	if action := jwtPolicy.OnResponse(&policy.ResponseContext{}, map[string]interface{}{}); action != nil {
		t.Fatalf("expected nil response action, got %T", action)
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

	ctx, action := executeOnRequest(t, params, authHeader("Authorization", "Bearer", token))
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
	keys := map[string]*rsa.PublicKey{
		"kid-1": key1,
		"kid-2": key2,
	}
	ids := getKeyIds(keys)
	if len(ids) != 2 {
		t.Fatalf("expected 2 key IDs, got %d", len(ids))
	}
}

func resetJWTAuthSingletonCache(t *testing.T) {
	t.Helper()

	ins.cacheMutex.Lock()
	ins.cacheStore = make(map[string]*CachedJWKS)
	ins.cacheTTLs = make(map[string]time.Time)
	ins.cacheMutex.Unlock()

	t.Cleanup(func() {
		ins.cacheMutex.Lock()
		ins.cacheStore = make(map[string]*CachedJWKS)
		ins.cacheTTLs = make(map[string]time.Time)
		ins.cacheMutex.Unlock()
	})
}

func executeOnRequest(t *testing.T, params map[string]interface{}, headers map[string][]string) (*policy.RequestContext, policy.RequestAction) {
	t.Helper()
	p := mustGetPolicy(t, params)
	ctx := createMockRequestContext(headers)
	return ctx, p.OnRequest(ctx, params)
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
		"allowedAlgorithms":      []interface{}{"RS256"},
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

func assertAuthSuccess(t *testing.T, ctx *policy.RequestContext, action policy.RequestAction) {
	t.Helper()

	if ctx == nil {
		t.Fatalf("request context cannot be nil")
	}
	if ctx.Metadata[MetadataKeyAuthSuccess] != true {
		t.Fatalf("expected auth success, got %v", ctx.Metadata[MetadataKeyAuthSuccess])
	}
	if _, ok := action.(policy.UpstreamRequestModifications); !ok {
		t.Fatalf("expected UpstreamRequestModifications, got %T", action)
	}
}

func assertAuthFailure(t *testing.T, ctx *policy.RequestContext, action policy.RequestAction, statusCode int) {
	t.Helper()

	if ctx == nil {
		t.Fatalf("request context cannot be nil")
	}
	if ctx.Metadata[MetadataKeyAuthSuccess] != false {
		t.Fatalf("expected auth failure, got %v", ctx.Metadata[MetadataKeyAuthSuccess])
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

	normalizedClaims := normalizeClaims(claims)
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims(normalizedClaims))
	if kid != "" {
		token.Header["kid"] = kid
	}

	tokenString, err := token.SignedString(privateKey)
	if err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}
	return tokenString
}

func createUnsignedNoneToken(t *testing.T, claims map[string]interface{}) string {
	t.Helper()

	normalizedClaims := normalizeClaims(claims)
	token := jwt.NewWithClaims(jwt.SigningMethodNone, jwt.MapClaims(normalizedClaims))
	token.Header["kid"] = "none-kid"

	tokenString, err := token.SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatalf("failed to sign none token: %v", err)
	}
	return tokenString
}

func createTokenWithoutAlgHeader(t *testing.T, privateKey *rsa.PrivateKey, claims map[string]interface{}, kid string) string {
	t.Helper()

	normalizedClaims := normalizeClaims(claims)
	header := map[string]interface{}{
		"typ": "JWT",
	}
	if kid != "" {
		header["kid"] = kid
	}

	headerJSON, err := json.Marshal(header)
	if err != nil {
		t.Fatalf("failed to marshal header: %v", err)
	}
	payloadJSON, err := json.Marshal(normalizedClaims)
	if err != nil {
		t.Fatalf("failed to marshal claims: %v", err)
	}

	headerEncoded := base64.RawURLEncoding.EncodeToString(headerJSON)
	payloadEncoded := base64.RawURLEncoding.EncodeToString(payloadJSON)
	signingInput := headerEncoded + "." + payloadEncoded

	digest := sha256.Sum256([]byte(signingInput))
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatalf("failed to create signature: %v", err)
	}

	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func normalizeClaims(claims map[string]interface{}) map[string]interface{} {
	normalized := make(map[string]interface{}, len(claims)+2)
	for k, v := range claims {
		normalized[k] = v
	}
	if _, ok := normalized["exp"]; !ok {
		normalized["exp"] = time.Now().Add(time.Hour).Unix()
	}
	if _, ok := normalized["iat"]; !ok {
		normalized["iat"] = time.Now().Unix()
	}
	return normalized
}

func writeJWKSResponse(t *testing.T, w http.ResponseWriter, publicKey *rsa.PublicKey, kid string) {
	t.Helper()

	nB64 := base64.RawURLEncoding.EncodeToString(publicKey.N.Bytes())

	e := publicKey.E
	eBytes := make([]byte, 0, 4)
	for e > 0 {
		eBytes = append([]byte{byte(e & 0xFF)}, eBytes...)
		e >>= 8
	}
	if len(eBytes) == 0 {
		eBytes = []byte{0}
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
		t.Fatalf("failed to encode JWKS response: %v", err)
	}
}
