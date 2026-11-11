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

package backendjwt

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
	"github.com/wso2/api-platform/sdk/core/utils/cache"
)

// ─── Helpers ─────────────────────────────────────────────────────────────────

func generateRSAKey(t *testing.T) (*rsa.PrivateKey, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
	return key, string(pemBytes)
}


func newRequestContext(authCtx *policy.AuthContext) *policy.RequestHeaderContext {
	return &policy.RequestHeaderContext{
		SharedContext: &policy.SharedContext{
			RequestID:   "test-request-id",
			Metadata:    make(map[string]interface{}),
			AuthContext: authCtx,
		},
		Headers: policy.NewHeaders(map[string][]string{}),
		Path:    "/api/test",
		Method:  "GET",
	}
}

func baseParams(pemKey string) map[string]interface{} {
	return map[string]interface{}{
		"signingKey": map[string]interface{}{
			"inline": pemKey,
		},
		"algorithm":   "SHA256withRSA",
		"issuer":      "https://gateway.example.com",
		"tokenExpiry": "15m",
	}
}

func decodeJWT(t *testing.T, tokenStr string, verifyKey interface{}) jwt.MapClaims {
	t.Helper()
	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		return verifyKey, nil
	})
	if err != nil {
		t.Fatalf("parse/verify JWT: %v", err)
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		t.Fatal("claims are not MapClaims")
	}
	return claims
}

func generateECKey(t *testing.T) (*ecdsa.PrivateKey, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ECDSA key: %v", err)
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal ECDSA key: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
	return key, string(pemBytes)
}

func newTestPolicy() *BackendJWTPolicy {
	return &BackendJWTPolicy{
		tokenCache:     newTokenCache(defaultCacheMaxSize),
		currentMaxSize: defaultCacheMaxSize,
	}
}

// tokenCount returns the number of entries currently held in the policy's token cache. The SDK
// cache exposes no key iteration, but every cache-key test uses a dedicated policy instance
// scoped to a single API (APIName ""), so the global entry count equals the number of distinct
// tokens cached for that API. The apiName argument is retained for call-site readability.
func tokenCount(p *BackendJWTPolicy, _ string) int {
	return p.tokenCache.GetStats().Size
}

// ─── Tests ────────────────────────────────────────────────────────────────────

func TestGetPolicySingleton(t *testing.T) {
	p1, err := GetPolicy(policy.PolicyMetadata{}, nil)
	if err != nil {
		t.Fatalf("GetPolicy returned error: %v", err)
	}
	p2, err := GetPolicy(policy.PolicyMetadata{}, nil)
	if err != nil {
		t.Fatalf("GetPolicy returned error: %v", err)
	}
	if p1 != p2 {
		t.Error("GetPolicy must return the same singleton instance")
	}
}

func TestGetPolicy_SystemParamsReadFlat(t *testing.T) {
	// cacheMaxSize is a system parameter: the gateway resolves it from config.toml and
	// injects it flat into params, at the same level as signingKey and algorithm — not
	// nested under "systemParameters". GetPolicy applies it to the shared cache's maximum.
	_, keyPEM := generateRSAKey(t)
	params := baseParams(keyPEM)
	params["cacheMaxSize"] = 75

	origMax := ins.currentMaxSize
	t.Cleanup(func() { ins.ensureTokenCache(origMax) })

	if _, err := GetPolicy(policy.PolicyMetadata{APIName: "param-test-api"}, params); err != nil {
		t.Fatalf("GetPolicy returned error: %v", err)
	}

	if max := ins.tokenCache.GetStats().MaxSize; max != 75 {
		t.Errorf("expected shared cache maximum=75, got %d", max)
	}
}

func TestGetPolicy_CacheMaxSizeIsGlobalDefault(t *testing.T) {
	// cacheMaxSize=0 (or unset) maps to the default global bound rather than unbounded.
	_, keyPEM := generateRSAKey(t)
	params := baseParams(keyPEM) // no cacheMaxSize

	origMax := ins.currentMaxSize
	t.Cleanup(func() { ins.ensureTokenCache(origMax) })

	if _, err := GetPolicy(policy.PolicyMetadata{APIName: "default-size-api"}, params); err != nil {
		t.Fatalf("GetPolicy returned error: %v", err)
	}

	if max := ins.tokenCache.GetStats().MaxSize; max != defaultCacheMaxSize {
		t.Errorf("expected shared cache maximum=%d (default), got %d", defaultCacheMaxSize, max)
	}
}

func TestCacheMaxSize_GloballyBounded(t *testing.T) {
	// The shared cache enforces a single global bound across all APIs: its LRU policy evicts
	// the least-recently-used entries once full, so the total live entry count never exceeds
	// the maximum regardless of how many APIs or distinct tokens are generated.
	const maxSize = 5
	_, keyPEM := generateRSAKey(t)
	p := &BackendJWTPolicy{tokenCache: newTokenCache(maxSize), currentMaxSize: maxSize}
	params := baseParams(keyPEM)

	// Spread distinct tokens across several APIs — the bound is global, not per-API.
	for _, api := range []string{"api-a", "api-b", "api-c"} {
		for i := 0; i < 20; i++ {
			authCtx := &policy.AuthContext{
				Authenticated: true, AuthType: "jwt", Subject: "user", TokenId: fmt.Sprintf("tok-%d", i),
			}
			reqCtx := newRequestContext(authCtx)
			reqCtx.APIName = api
			p.OnRequestHeaders(context.Background(), reqCtx, params)
		}
	}

	if total := p.tokenCache.GetStats().Size; total > maxSize {
		t.Errorf("global maximum=%d must cap total entries across all APIs, got %d", maxSize, total)
	}
}

func TestTokenCache_PopulatedOnFirstRequest(t *testing.T) {
	_, keyPEM := generateRSAKey(t)
	p := newTestPolicy()

	p.OnRequestHeaders(context.Background(), newRequestContext(&policy.AuthContext{
		Authenticated: true, AuthType: "jwt", Subject: "dave", TokenId: "tok-d",
	}), baseParams(keyPEM))

	if count := tokenCount(p, ""); count != 1 {
		t.Errorf("expected 1 cached token after first request, got %d", count)
	}
}

func TestMode(t *testing.T) {
	p := newTestPolicy()
	mode := p.Mode()
	if mode.RequestHeaderMode != policy.HeaderModeProcess {
		t.Errorf("expected RequestHeaderMode=HeaderModeProcess, got %v", mode.RequestHeaderMode)
	}
	if mode.RequestBodyMode != policy.BodyModeSkip {
		t.Errorf("expected RequestBodyMode=BodyModeSkip, got %v", mode.RequestBodyMode)
	}
	if mode.ResponseHeaderMode != policy.HeaderModeSkip {
		t.Errorf("expected ResponseHeaderMode=HeaderModeSkip, got %v", mode.ResponseHeaderMode)
	}
	if mode.ResponseBodyMode != policy.BodyModeSkip {
		t.Errorf("expected ResponseBodyMode=BodyModeSkip, got %v", mode.ResponseBodyMode)
	}
}


func TestNoAuthContext_NoRequireAuth(t *testing.T) {
	rsaKey, keyPEM := generateRSAKey(t)
	p := newTestPolicy()
	params := baseParams(keyPEM)

	reqCtx := newRequestContext(nil)
	result := p.OnRequestHeaders(context.Background(), reqCtx, params)

	mods, ok := result.(policy.UpstreamRequestHeaderModifications)
	if !ok {
		t.Fatalf("expected UpstreamRequestHeaderModifications, got %T", result)
	}
	tokenStr, ok := mods.HeadersToSet[defaultHeader]
	if !ok || tokenStr == "" {
		t.Fatalf("expected backend JWT to be generated even without auth context")
	}

	// Parse without verification to inspect claims (we have the key, use it).
	claims := decodeJWT(t, tokenStr, &rsaKey.PublicKey)

	// System claims must be present.
	if claims["iss"] != "https://gateway.example.com" {
		t.Errorf("expected iss=https://gateway.example.com, got %v", claims["iss"])
	}
	if _, ok := claims["iat"]; !ok {
		t.Error("iat claim must be present")
	}
	if _, ok := claims["exp"]; !ok {
		t.Error("exp claim must be present")
	}

	// Auth-derived claims must be absent when there is no auth context.
	if _, ok := claims["sub"]; ok {
		t.Errorf("sub must be absent when no auth context, got %v", claims["sub"])
	}
	if _, ok := claims["auth_type"]; ok {
		t.Errorf("auth_type must be absent when no auth context, got %v", claims["auth_type"])
	}
}


func TestGeneratesJWTWithSubject(t *testing.T) {
	rsaKey, keyPEM := generateRSAKey(t)
	p := newTestPolicy()
	params := baseParams(keyPEM)

	reqCtx := newRequestContext(&policy.AuthContext{
		Authenticated: true,
		AuthType:      "jwt",
		Subject:       "alice",
		Issuer:        "https://idp.example.com",
	})

	result := p.OnRequestHeaders(context.Background(), reqCtx, params)
	mods, ok := result.(policy.UpstreamRequestHeaderModifications)
	if !ok {
		t.Fatalf("expected UpstreamRequestHeaderModifications, got %T", result)
	}

	tokenStr, ok := mods.HeadersToSet[defaultHeader]
	if !ok {
		t.Fatalf("expected header %q to be set", defaultHeader)
	}

	claims := decodeJWT(t, tokenStr, &rsaKey.PublicKey)
	if claims["sub"] != "alice" {
		t.Errorf("expected sub=alice, got %v", claims["sub"])
	}
	if claims["auth_type"] != "jwt" {
		t.Errorf("expected auth_type=jwt, got %v", claims["auth_type"])
	}
	if claims["iss"] != "https://gateway.example.com" {
		t.Errorf("expected iss=https://gateway.example.com, got %v", claims["iss"])
	}
}

func TestCustomClaims(t *testing.T) {
	rsaKey, keyPEM := generateRSAKey(t)
	p := newTestPolicy()
	params := baseParams(keyPEM)
	params["customClaims"] = map[string]interface{}{
		"env":     "production",
		"version": "v2",
	}

	reqCtx := newRequestContext(&policy.AuthContext{
		Authenticated: true,
		AuthType:      "basic",
		Subject:       "bob",
	})

	result := p.OnRequestHeaders(context.Background(), reqCtx, params)
	mods := result.(policy.UpstreamRequestHeaderModifications)
	claims := decodeJWT(t, mods.HeadersToSet[defaultHeader], &rsaKey.PublicKey)

	if claims["env"] != "production" {
		t.Errorf("expected env=production, got %v", claims["env"])
	}
	if claims["version"] != "v2" {
		t.Errorf("expected version=v2, got %v", claims["version"])
	}
}


func TestTokenExpiry(t *testing.T) {
	rsaKey, keyPEM := generateRSAKey(t)
	p := newTestPolicy()
	params := baseParams(keyPEM)
	params["tokenExpiry"] = "5m"

	// Truncate to whole seconds: iat/exp are Unix timestamps (second precision).
	before := time.Now().Truncate(time.Second)
	reqCtx := newRequestContext(&policy.AuthContext{Authenticated: true, AuthType: "jwt", Subject: "dave"})
	result := p.OnRequestHeaders(context.Background(), reqCtx, params)
	mods := result.(policy.UpstreamRequestHeaderModifications)
	after := time.Now().Truncate(time.Second).Add(time.Second)
	claims := decodeJWT(t, mods.HeadersToSet[defaultHeader], &rsaKey.PublicKey)

	expRaw, ok := claims["exp"].(float64)
	if !ok {
		t.Fatal("exp claim missing or not a number")
	}
	iatRaw, ok := claims["iat"].(float64)
	if !ok {
		t.Fatal("iat claim missing or not a number")
	}

	expTime := time.Unix(int64(expRaw), 0)
	iatTime := time.Unix(int64(iatRaw), 0)
	diff := expTime.Sub(iatTime)

	if diff < 4*time.Minute || diff > 6*time.Minute {
		t.Errorf("expected exp-iat≈5m, got %v", diff)
	}
	if iatTime.Before(before) || iatTime.After(after) {
		t.Errorf("iat %v is outside [%v, %v]", iatTime, before, after)
	}
}

func TestTokenExpiry_UserOverridesSystem(t *testing.T) {
	// Simulate the engine merge: system sets tokenExpiry="15m", user API sets "2m".
	// User value must win — the flat params map carries the merged result.
	rsaKey, keyPEM := generateRSAKey(t)
	p := newTestPolicy()
	params := baseParams(keyPEM)
	params["tokenExpiry"] = "2m" // user-level override

	reqCtx := newRequestContext(&policy.AuthContext{Authenticated: true, AuthType: "jwt", Subject: "dave"})
	result := p.OnRequestHeaders(context.Background(), reqCtx, params)
	mods := result.(policy.UpstreamRequestHeaderModifications)
	claims := decodeJWT(t, mods.HeadersToSet[defaultHeader], &rsaKey.PublicKey)

	expRaw, ok := claims["exp"].(float64)
	if !ok {
		t.Fatal("exp claim missing or not a number")
	}
	iatRaw, ok := claims["iat"].(float64)
	if !ok {
		t.Fatal("iat claim missing or not a number")
	}
	diff := time.Unix(int64(expRaw), 0).Sub(time.Unix(int64(iatRaw), 0))
	if diff < 1*time.Minute || diff > 3*time.Minute {
		t.Errorf("user tokenExpiry override: expected exp-iat≈2m, got %v", diff)
	}
}

func TestSHA256withRSASigning(t *testing.T) {
	rsaKey, keyPEM := generateRSAKey(t)
	p := newTestPolicy()
	params := baseParams(keyPEM)

	reqCtx := newRequestContext(&policy.AuthContext{Authenticated: true, AuthType: "jwt", Subject: "rsa-user"})
	result := p.OnRequestHeaders(context.Background(), reqCtx, params)
	mods := result.(policy.UpstreamRequestHeaderModifications)

	tokenStr, ok := mods.HeadersToSet[defaultHeader]
	if !ok {
		t.Fatal("no JWT header set")
	}

	token, _, err := jwt.NewParser().ParseUnverified(tokenStr, jwt.MapClaims{})
	if err != nil {
		t.Fatalf("parse unverified: %v", err)
	}
	if token.Method != jwt.SigningMethodRS256 {
		t.Errorf("SHA256withRSA must produce RS256 token, got %v", token.Method.Alg())
	}
	decodeJWT(t, tokenStr, &rsaKey.PublicKey)
}


func TestES256Signing(t *testing.T) {
	ecKey, keyPEM := generateECKey(t)
	p := newTestPolicy()
	params := map[string]interface{}{
		"signingKey": map[string]interface{}{"inline": keyPEM},
		"algorithm":  "ES256",
		"issuer":     "https://gateway.example.com",
	}

	reqCtx := newRequestContext(&policy.AuthContext{Authenticated: true, AuthType: "jwt", Subject: "ec-user"})
	result := p.OnRequestHeaders(context.Background(), reqCtx, params)
	mods := result.(policy.UpstreamRequestHeaderModifications)

	tokenStr, ok := mods.HeadersToSet[defaultHeader]
	if !ok {
		t.Fatal("no JWT header set")
	}
	token, _, err := jwt.NewParser().ParseUnverified(tokenStr, jwt.MapClaims{})
	if err != nil {
		t.Fatalf("parse unverified: %v", err)
	}
	if token.Method != jwt.SigningMethodES256 {
		t.Errorf("expected ES256 signing method, got %v", token.Method.Alg())
	}
	decodeJWT(t, tokenStr, &ecKey.PublicKey)
}

func TestMismatchedAlgorithmAndKey(t *testing.T) {
	_, ecKeyPEM := generateECKey(t)
	p := newTestPolicy()
	params := map[string]interface{}{
		"signingKey": map[string]interface{}{"inline": ecKeyPEM},
		"algorithm":  "SHA256withRSA", // EC key with RSA algorithm
	}

	reqCtx := newRequestContext(&policy.AuthContext{Authenticated: true, AuthType: "jwt", Subject: "henry"})
	result := p.OnRequestHeaders(context.Background(), reqCtx, params)

	resp, ok := result.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("expected ImmediateResponse on key/algorithm mismatch, got %T", result)
	}
	if resp.StatusCode != 500 {
		t.Errorf("expected status 500, got %d", resp.StatusCode)
	}
}

func TestCustomHeader(t *testing.T) {
	_, keyPEM := generateRSAKey(t)
	p := newTestPolicy()
	params := baseParams(keyPEM)
	params["header"] = "x-custom-backend-token"

	reqCtx := newRequestContext(&policy.AuthContext{Authenticated: true, AuthType: "jwt", Subject: "frank"})
	result := p.OnRequestHeaders(context.Background(), reqCtx, params)
	mods := result.(policy.UpstreamRequestHeaderModifications)

	if _, ok := mods.HeadersToSet[defaultHeader]; ok {
		t.Errorf("default header %q must not be set when custom header is configured", defaultHeader)
	}
	if _, ok := mods.HeadersToSet["x-custom-backend-token"]; !ok {
		t.Error("custom header x-custom-backend-token must be set")
	}
}

func TestInvalidPrivateKey(t *testing.T) {
	p := newTestPolicy()
	params := map[string]interface{}{
		"signingKey": map[string]interface{}{
			"inline": "not-a-valid-pem-key",
		},
		"algorithm": "SHA256withRSA",
	}

	reqCtx := newRequestContext(&policy.AuthContext{Authenticated: true, AuthType: "jwt", Subject: "grace"})
	result := p.OnRequestHeaders(context.Background(), reqCtx, params)

	resp, ok := result.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("expected ImmediateResponse on invalid key, got %T", result)
	}
	if resp.StatusCode != 500 {
		t.Errorf("expected status 500, got %d", resp.StatusCode)
	}
}


func TestValidate_TokenExpiry_Invalid(t *testing.T) {
	_, keyPEM := generateRSAKey(t)
	p := newTestPolicy()
	err := p.Validate(map[string]interface{}{
		"signingKey":  map[string]interface{}{"inline": keyPEM},
		"tokenExpiry": "notaduration",
	})
	if err == nil {
		t.Error("Validate must return error for unparseable tokenExpiry")
	}
}

func TestValidate_TokenExpiry_Zero(t *testing.T) {
	_, keyPEM := generateRSAKey(t)
	p := newTestPolicy()
	err := p.Validate(map[string]interface{}{
		"signingKey":  map[string]interface{}{"inline": keyPEM},
		"tokenExpiry": "0s",
	})
	if err == nil {
		t.Error("Validate must return error for zero tokenExpiry")
	}
}

func TestValidate_TokenExpiry_Negative(t *testing.T) {
	_, keyPEM := generateRSAKey(t)
	p := newTestPolicy()
	err := p.Validate(map[string]interface{}{
		"signingKey":  map[string]interface{}{"inline": keyPEM},
		"tokenExpiry": "-5m",
	})
	if err == nil {
		t.Error("Validate must return error for negative tokenExpiry")
	}
}

func TestValidate_MissingKey(t *testing.T) {
	p := newTestPolicy()
	err := p.Validate(map[string]interface{}{})
	if err == nil {
		t.Error("Validate must return error when signingKey is absent")
	}
}

func TestValidate_InvalidKeyMaterial(t *testing.T) {
	p := newTestPolicy()
	err := p.Validate(map[string]interface{}{
		"signingKey": map[string]interface{}{
			"inline": "-----BEGIN RSA PRIVATE KEY-----\nbaddata\n-----END RSA PRIVATE KEY-----",
		},
	})
	if err == nil {
		t.Error("Validate must return error for invalid key material")
	}
}

func TestValidate_ValidKey(t *testing.T) {
	_, keyPEM := generateRSAKey(t)
	p := newTestPolicy()
	err := p.Validate(map[string]interface{}{
		"signingKey": map[string]interface{}{"inline": keyPEM},
	})
	if err != nil {
		t.Errorf("Validate must not return error for valid key: %v", err)
	}
}

func TestKeyFilePath(t *testing.T) {
	rsaKey, keyPEM := generateRSAKey(t)
	f, err := os.CreateTemp("", "backend-jwt-test-key-*.pem")
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}
	defer os.Remove(f.Name())
	if _, err := f.WriteString(keyPEM); err != nil {
		t.Fatalf("write key file: %v", err)
	}
	f.Close()

	p := newTestPolicy()
	params := map[string]interface{}{
		"signingKey": map[string]interface{}{"path": f.Name()},
		"algorithm":  "SHA256withRSA",
	}

	reqCtx := newRequestContext(&policy.AuthContext{Authenticated: true, AuthType: "jwt", Subject: "irene"})
	result := p.OnRequestHeaders(context.Background(), reqCtx, params)
	mods, ok := result.(policy.UpstreamRequestHeaderModifications)
	if !ok {
		t.Fatalf("expected UpstreamRequestHeaderModifications, got %T", result)
	}

	decodeJWT(t, mods.HeadersToSet[defaultHeader], &rsaKey.PublicKey)
}

func TestPEMFileCachedAfterFirstRead(t *testing.T) {
	_, keyPEM := generateRSAKey(t)
	f, err := os.CreateTemp("", "backend-jwt-pem-cache-*.pem")
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}
	defer os.Remove(f.Name())
	if _, err := f.WriteString(keyPEM); err != nil {
		t.Fatalf("write key file: %v", err)
	}
	f.Close()

	p := newTestPolicy()
	params := map[string]interface{}{
		"signingKey": map[string]interface{}{"path": f.Name()},
		"algorithm":  "SHA256withRSA",
	}

	// First call — populates pemCache.
	reqCtx1 := newRequestContext(&policy.AuthContext{Authenticated: true, AuthType: "jwt", Subject: "user-a"})
	p.OnRequestHeaders(context.Background(), reqCtx1, params)

	if _, cached := p.pemCache.Load(f.Name()); !cached {
		t.Fatal("expected PEM bytes to be cached after first path read")
	}

	// Delete the file — a second call must succeed using cached bytes.
	os.Remove(f.Name())
	reqCtx2 := newRequestContext(&policy.AuthContext{Authenticated: true, AuthType: "jwt", Subject: "user-b"})
	result := p.OnRequestHeaders(context.Background(), reqCtx2, params)
	if _, ok := result.(policy.UpstreamRequestHeaderModifications); !ok {
		t.Errorf("expected success from pemCache after file deletion, got %T", result)
	}
}

func TestKeyCaching(t *testing.T) {
	_, keyPEM := generateRSAKey(t)
	p := newTestPolicy()
	params := baseParams(keyPEM)

	authCtx := &policy.AuthContext{Authenticated: true, AuthType: "jwt", Subject: "judy"}

	// Call twice; second call should hit the cache (no observable difference, but must not error).
	for i := 0; i < 2; i++ {
		reqCtx := newRequestContext(authCtx)
		result := p.OnRequestHeaders(context.Background(), reqCtx, params)
		if _, ok := result.(policy.UpstreamRequestHeaderModifications); !ok {
			t.Fatalf("call %d: expected UpstreamRequestHeaderModifications, got %T", i+1, result)
		}
	}

	// Verify only one key is cached.
	keyCount := 0
	p.keyCache.Range(func(_, _ any) bool { keyCount++; return true })
	if keyCount != 1 {
		t.Errorf("expected 1 cached key, got %d", keyCount)
	}
}

func TestAudienceAndCredentialID(t *testing.T) {
	rsaKey, keyPEM := generateRSAKey(t)
	p := newTestPolicy()
	params := baseParams(keyPEM)

	reqCtx := newRequestContext(&policy.AuthContext{
		Authenticated: true,
		AuthType:      "apikey",
		Subject:       "ken",
		Audience:      []string{"service-a", "service-b"},
		CredentialID:  "client-abc",
	})

	result := p.OnRequestHeaders(context.Background(), reqCtx, params)
	mods := result.(policy.UpstreamRequestHeaderModifications)
	claims := decodeJWT(t, mods.HeadersToSet[defaultHeader], &rsaKey.PublicKey)

	if claims["credential_id"] != "client-abc" {
		t.Errorf("expected credential_id=client-abc, got %v", claims["credential_id"])
	}
	audRaw, ok := claims["aud"]
	if !ok {
		t.Fatal("aud claim missing")
	}
	_ = audRaw // audience is present; exact type depends on JWT library serialisation
}

// ─── Algorithm Tests ──────────────────────────────────────────────────────────

func TestAlgorithm_NONE(t *testing.T) {
	p := newTestPolicy()
	params := map[string]interface{}{
		"algorithm":   "NONE",
		"tokenExpiry": "15m",
	}

	reqCtx := newRequestContext(&policy.AuthContext{Authenticated: true, AuthType: "jwt", Subject: "alice"})
	result := p.OnRequestHeaders(context.Background(), reqCtx, params)
	mods, ok := result.(policy.UpstreamRequestHeaderModifications)
	if !ok {
		t.Fatalf("expected UpstreamRequestHeaderModifications, got %T", result)
	}

	tokenStr := mods.HeadersToSet[defaultHeader]
	if tokenStr == "" {
		t.Fatal("expected non-empty token for NONE algorithm")
	}
	token, _, err := jwt.NewParser().ParseUnverified(tokenStr, jwt.MapClaims{})
	if err != nil {
		t.Fatalf("parse unverified: %v", err)
	}
	if token.Method != jwt.SigningMethodNone {
		t.Errorf("NONE algorithm must produce unsigned token, got alg=%v", token.Method.Alg())
	}
}

func TestAlgorithm_NONE_ValidateSkipsKey(t *testing.T) {
	p := newTestPolicy()
	err := p.Validate(map[string]interface{}{
		"algorithm": "NONE",
		// no signingKey — must not error
	})
	if err != nil {
		t.Errorf("Validate with NONE algorithm must not require a signing key, got: %v", err)
	}
}

func TestAlgorithm_UnknownReturns500(t *testing.T) {
	_, keyPEM := generateRSAKey(t)
	p := newTestPolicy()
	params := map[string]interface{}{
		"signingKey": map[string]interface{}{"inline": keyPEM},
		"algorithm":  "SuperAlgorithmXYZ",
	}

	reqCtx := newRequestContext(&policy.AuthContext{Authenticated: true, AuthType: "jwt", Subject: "bob"})
	result := p.OnRequestHeaders(context.Background(), reqCtx, params)
	resp, ok := result.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("unknown algorithm must return 500, got %T", result)
	}
	if resp.StatusCode != 500 {
		t.Errorf("expected status 500, got %d", resp.StatusCode)
	}
}

// ─── Token Cache Tests ────────────────────────────────────────────────────────

func TestTokenCache_HitReturnsSameToken(t *testing.T) {
	rsaKey, keyPEM := generateRSAKey(t)
	p := newTestPolicy()
	params := baseParams(keyPEM)
	authCtx := &policy.AuthContext{Authenticated: true, AuthType: "jwt", Subject: "alice", CredentialID: "client-1"}

	result1 := p.OnRequestHeaders(context.Background(), newRequestContext(authCtx), params)
	result2 := p.OnRequestHeaders(context.Background(), newRequestContext(authCtx), params)

	mods1 := result1.(policy.UpstreamRequestHeaderModifications)
	mods2 := result2.(policy.UpstreamRequestHeaderModifications)
	tok1 := mods1.HeadersToSet[defaultHeader]
	tok2 := mods2.HeadersToSet[defaultHeader]

	if tok1 == "" || tok2 == "" {
		t.Fatal("expected non-empty tokens")
	}
	if tok1 != tok2 {
		t.Error("cache hit must return the same signed token string")
	}

	// Verify the cached token is a valid JWT.
	decodeJWT(t, tok1, &rsaKey.PublicKey)
}

func TestTokenCache_MissOnDifferentSubject(t *testing.T) {
	_, keyPEM := generateRSAKey(t)
	p := newTestPolicy()
	params := baseParams(keyPEM)

	r1 := p.OnRequestHeaders(context.Background(), newRequestContext(&policy.AuthContext{
		Authenticated: true, AuthType: "jwt", Subject: "alice",
	}), params)
	r2 := p.OnRequestHeaders(context.Background(), newRequestContext(&policy.AuthContext{
		Authenticated: true, AuthType: "jwt", Subject: "bob",
	}), params)

	tok1 := r1.(policy.UpstreamRequestHeaderModifications).HeadersToSet[defaultHeader]
	tok2 := r2.(policy.UpstreamRequestHeaderModifications).HeadersToSet[defaultHeader]
	if tok1 == tok2 {
		t.Error("different subjects must produce different tokens (separate cache entries)")
	}
}

func TestTokenCache_MissOnDifferentPath(t *testing.T) {
	_, keyPEM := generateRSAKey(t)
	p := newTestPolicy()
	params := baseParams(keyPEM)
	authCtx := &policy.AuthContext{Authenticated: true, AuthType: "jwt", Subject: "carol"}

	makeCtx := func(path string) *policy.RequestHeaderContext {
		return &policy.RequestHeaderContext{
			SharedContext: &policy.SharedContext{
				RequestID:   "test",
				Metadata:    make(map[string]interface{}),
				AuthContext: authCtx,
			},
			Headers: policy.NewHeaders(map[string][]string{}),
			Path:    path,
			Method:  "GET",
		}
	}

	p.OnRequestHeaders(context.Background(), makeCtx("/petstore/v1/pets"), params)
	p.OnRequestHeaders(context.Background(), makeCtx("/orders/v1/orders"), params)

	// Different paths → different cache keys → two separate cache entries.
	count := tokenCount(p, "")
	if count != 2 {
		t.Errorf("expected 2 cache entries for 2 different paths, got %d", count)
	}
}

func TestTokenCache_QueryParamsIgnored(t *testing.T) {
	// Requests to the same path with different query strings must share one cache entry.
	_, keyPEM := generateRSAKey(t)
	p := newTestPolicy()
	params := baseParams(keyPEM)
	authCtx := &policy.AuthContext{Authenticated: true, AuthType: "jwt", Subject: "alice", TokenId: "token-xyz"}

	makeCtx := func(path string) *policy.RequestHeaderContext {
		return &policy.RequestHeaderContext{
			SharedContext: &policy.SharedContext{RequestID: "x", Metadata: make(map[string]interface{}), AuthContext: authCtx},
			Headers:       policy.NewHeaders(map[string][]string{}),
			Path:          path, Method: "GET",
		}
	}

	p.OnRequestHeaders(context.Background(), makeCtx("/api/v1/pets?page=1&limit=10"), params)
	p.OnRequestHeaders(context.Background(), makeCtx("/api/v1/pets?page=2&limit=10"), params)
	p.OnRequestHeaders(context.Background(), makeCtx("/api/v1/pets"), params)

	count := tokenCount(p, "")
	if count != 1 {
		t.Errorf("different query strings on the same path must share one cache entry, got %d", count)
	}
}

func TestTokenCache_MissOnDifferentCustomClaim(t *testing.T) {
	_, keyPEM := generateRSAKey(t)
	p := newTestPolicy()
	authCtx := &policy.AuthContext{Authenticated: true, AuthType: "jwt", Subject: "dave"}

	params := map[string]interface{}{
		"signingKey":   map[string]interface{}{"inline": keyPEM},
		"algorithm":    "SHA256withRSA",
		"customClaims": map[string]interface{}{"tenantId": "$ctx:request.header.x-tenant-id"},
	}

	makeReqCtx := func(tenantHeader string) *policy.RequestHeaderContext {
		return &policy.RequestHeaderContext{
			SharedContext: &policy.SharedContext{
				RequestID: "x", Metadata: make(map[string]interface{}), AuthContext: authCtx,
			},
			Headers: policy.NewHeaders(map[string][]string{"x-tenant-id": {tenantHeader}}),
			Path:    "/api", Method: "GET",
		}
	}

	r1 := p.OnRequestHeaders(context.Background(), makeReqCtx("acme"), params)
	r2 := p.OnRequestHeaders(context.Background(), makeReqCtx("globex"), params)

	tok1 := r1.(policy.UpstreamRequestHeaderModifications).HeadersToSet[defaultHeader]
	tok2 := r2.(policy.UpstreamRequestHeaderModifications).HeadersToSet[defaultHeader]
	if tok1 == tok2 {
		t.Error("different resolved custom claim values must produce different cache entries")
	}
}

func TestTokenCache_ExpiryRespected(t *testing.T) {
	// Verify getCachedToken returns miss for an expired entry and hit for a live one.
	// We test this at the helper level (not via OnRequestHeaders) because RSA PKCS1v15
	// is deterministic — re-signing the same claims in the same second produces the
	// same token string, making "different string" an unreliable expiry signal.
	p := newTestPolicy()
	ctx := context.Background()

	p.putCachedToken(ctx, "key-a", "sentinel-live", time.Hour)
	// key-b gets a tiny expiry (ttl → ~1ms), then we wait it out so it is past its window.
	p.putCachedToken(ctx, "key-b", "sentinel-expired", 2*time.Millisecond)
	time.Sleep(10 * time.Millisecond)

	got, ok := p.getCachedToken(ctx, "key-a")
	if !ok || got != "sentinel-live" {
		t.Errorf("expected cache hit for live entry, got (%q, %v)", got, ok)
	}

	got, ok = p.getCachedToken(ctx, "key-b")
	if ok || got != "" {
		t.Errorf("expected cache miss for expired entry, got (%q, %v)", got, ok)
	}
}

func TestTokenCache_ExpiredEntryRemovedOnRead(t *testing.T) {
	// The SDK cache is created with ttl=0, so it never expires entries on its own clock; expiry
	// is self-managed in getCachedToken, which deletes an entry past its window on read and
	// reports a miss. After reading both, only the live entry should remain.
	p := newTestPolicy()
	ctx := context.Background()

	p.putCachedToken(ctx, "expired", "old", 2*time.Millisecond)
	p.putCachedToken(ctx, "live", "current", time.Hour)
	time.Sleep(10 * time.Millisecond)

	if _, ok := p.getCachedToken(ctx, "expired"); ok {
		t.Error("expired entry must be reported as a miss")
	}
	if got, ok := p.getCachedToken(ctx, "live"); !ok || got != "current" {
		t.Errorf("live entry must be a hit, got (%q, %v)", got, ok)
	}
	if size := p.tokenCache.GetStats().Size; size != 1 {
		t.Errorf("expired entry must be deleted on read, leaving 1 entry, got %d", size)
	}
}

func TestPutCachedToken_TTLNeverOutlivesToken(t *testing.T) {
	// The cache TTL must always be strictly less than the token's own validity, otherwise
	// the cache could serve a JWT whose exp has already passed. This must hold even for
	// short expiries where the minCacheTTL (30s) floor would otherwise dominate.
	p := newTestPolicy()
	ctx := context.Background()

	cases := []time.Duration{
		5 * time.Second,  // half=2.5s; floor must NOT apply (would be 30s > 5s)
		20 * time.Second, // half=10s;  floor must NOT apply (would be 30s > 20s)
		30 * time.Second, // half=15s;  floor must NOT apply (30s == expiry is not strictly inside)
		45 * time.Second, // half=22.5s; floor applies (30s < 45s) → 30s, still inside
		90 * time.Second, // half=45s;  above the floor entirely
		15 * time.Minute, // default; well above the floor
	}

	for _, exp := range cases {
		p.putCachedToken(ctx, "k", "signed-token", exp)
		entry, ok := p.tokenCache.Get(ctx, cache.CacheKey{Key: "k"})
		if !ok {
			t.Fatalf("expiry=%v: expected a cached entry", exp)
		}
		// The entry's remaining lifetime (≈ the configured cache TTL) must stay strictly below
		// the token's own validity, so a cached token always has a safety margin before its exp.
		if ttl := time.Until(entry.expiresAt); ttl >= exp {
			t.Errorf("expiry=%v: cache TTL %v must be strictly less than token validity", exp, ttl)
		}
		_ = p.tokenCache.Delete(ctx, cache.CacheKey{Key: "k"})
	}
}

// ─── Cache Key Strategy Tests ────────────────────────────────────────────────

func TestTokenCacheKey_StaticClaimsAffectKey(t *testing.T) {
	// The full configured claim set — including static (non-$ctx) customClaims and claimMappings
	// destinations — must be folded into the cache key, so an API redeployed with different claim
	// config never serves a token built from the old config.
	authCtx := &policy.AuthContext{Authenticated: true, AuthType: "jwt", Subject: "alice", TokenId: "tok-1"}
	ns := keyNamespace{apiName: "api", algorithm: "SHA256withRSA"}

	none := buildTokenCacheKey(ns, authCtx, "/api/test", "GET", resolvedClaims{})
	gold := buildTokenCacheKey(ns, authCtx, "/api/test", "GET", resolvedClaims{stringClaims: map[string]string{"tier": "gold"}})
	platinum := buildTokenCacheKey(ns, authCtx, "/api/test", "GET", resolvedClaims{stringClaims: map[string]string{"tier": "platinum"}})
	// A non-string custom claim (rawClaims) must contribute too.
	raw := buildTokenCacheKey(ns, authCtx, "/api/test", "GET", resolvedClaims{rawClaims: map[string]interface{}{"level": 5}})

	if gold == platinum {
		t.Error("different static claim values must produce different cache keys")
	}
	for name, k := range map[string]string{"gold": gold, "platinum": platinum, "raw": raw} {
		if k == none {
			t.Errorf("configuring a static claim (%s) must change the key versus no claims", name)
		}
	}
}

func TestTokenCacheKey_NamespaceFieldsAffectKey(t *testing.T) {
	// apiName keeps each API's entries isolated; issuer/algorithm/dialect/excludedClaims are the
	// token-shaping config folded into the key in place of the old generation-counter invalidation.
	// Changing any one of them on redeploy must yield a different key (a cache miss), so a stale
	// token built from the old config is never served.
	authCtx := &policy.AuthContext{Authenticated: true, AuthType: "jwt", Subject: "alice", TokenId: "tok-1"}
	base := keyNamespace{apiName: "api-a", issuer: "iss-a", algorithm: "SHA256withRSA", dialect: "", excluded: nil}
	baseKey := buildTokenCacheKey(base, authCtx, "/api/test", "GET", resolvedClaims{})

	variants := map[string]keyNamespace{
		"apiName":        {apiName: "api-b", issuer: "iss-a", algorithm: "SHA256withRSA"},
		"issuer":         {apiName: "api-a", issuer: "iss-b", algorithm: "SHA256withRSA"},
		"algorithm":      {apiName: "api-a", issuer: "iss-a", algorithm: "ES256"},
		"dialect":        {apiName: "api-a", issuer: "iss-a", algorithm: "SHA256withRSA", dialect: "http://wso2.org/claims/"},
		"excludedClaims": {apiName: "api-a", issuer: "iss-a", algorithm: "SHA256withRSA", excluded: []string{"role"}},
	}
	for field, ns := range variants {
		if got := buildTokenCacheKey(ns, authCtx, "/api/test", "GET", resolvedClaims{}); got == baseKey {
			t.Errorf("changing %s must produce a different cache key", field)
		}
	}

	// Same namespace + same identity must still hit the same key (no spurious fragmentation).
	if buildTokenCacheKey(base, authCtx, "/api/test", "GET", resolvedClaims{}) != baseKey {
		t.Error("identical namespace and identity must produce a stable key")
	}
}

func TestTokenCacheKey_JWT_JTIRotation(t *testing.T) {
	// Different jti on same subject/issuer must produce separate cache entries.
	_, keyPEM := generateRSAKey(t)
	p := newTestPolicy()
	params := baseParams(keyPEM)

	p.OnRequestHeaders(context.Background(), newRequestContext(&policy.AuthContext{
		Authenticated: true, AuthType: "jwt", Subject: "alice", Issuer: "https://idp.example.com",
		TokenId: "token-aaa",
	}), params)
	p.OnRequestHeaders(context.Background(), newRequestContext(&policy.AuthContext{
		Authenticated: true, AuthType: "jwt", Subject: "alice", Issuer: "https://idp.example.com",
		TokenId: "token-bbb",
	}), params)

	count := tokenCount(p, "")
	if count != 2 {
		t.Errorf("different jti must produce separate cache entries, got %d", count)
	}
}

func TestTokenCacheKey_JWT_SameJTI_HitsCache(t *testing.T) {
	// Same jti must hit the cache regardless of other fields.
	_, keyPEM := generateRSAKey(t)
	p := newTestPolicy()
	params := baseParams(keyPEM)
	authCtx := &policy.AuthContext{
		Authenticated: true, AuthType: "jwt", Subject: "alice", TokenId: "token-xyz",
	}

	p.OnRequestHeaders(context.Background(), newRequestContext(authCtx), params)
	p.OnRequestHeaders(context.Background(), newRequestContext(authCtx), params)

	count := tokenCount(p, "")
	if count != 1 {
		t.Errorf("same jti must share one cache entry, got %d", count)
	}
}

func TestTokenCacheKey_JWT_SameJTI_DifferentHeaderMisses(t *testing.T) {
	// Same jti but different resolved dynamic claim ($ctx:request.header.*) must not share a cache entry.
	_, keyPEM := generateRSAKey(t)
	p := newTestPolicy()
	params := baseParams(keyPEM)
	params["customClaims"] = map[string]interface{}{"tenantId": "$ctx:request.header.x-tenant-id"}
	authCtx := &policy.AuthContext{Authenticated: true, AuthType: "jwt", Subject: "alice", TokenId: "token-xyz"}

	makeReqCtx := func(tenant string) *policy.RequestHeaderContext {
		return &policy.RequestHeaderContext{
			SharedContext: &policy.SharedContext{RequestID: "x", Metadata: make(map[string]interface{}), AuthContext: authCtx},
			Headers:       policy.NewHeaders(map[string][]string{"x-tenant-id": {tenant}}),
			Path:          "/api", Method: "GET",
		}
	}

	p.OnRequestHeaders(context.Background(), makeReqCtx("acme"), params)
	p.OnRequestHeaders(context.Background(), makeReqCtx("globex"), params)

	count := tokenCount(p, "")
	if count != 2 {
		t.Errorf("same jti with different dynamic header values must produce separate cache entries, got %d", count)
	}
}

func TestTokenCacheKey_JWT_CrossIssuerNoJTI(t *testing.T) {
	// Without jti, tokens from different issuers with the same subject must not collide.
	_, keyPEM := generateRSAKey(t)
	p := newTestPolicy()
	params := baseParams(keyPEM)

	p.OnRequestHeaders(context.Background(), newRequestContext(&policy.AuthContext{
		Authenticated: true, AuthType: "jwt", Subject: "alice", Issuer: "https://idp-a.example.com",
	}), params)
	p.OnRequestHeaders(context.Background(), newRequestContext(&policy.AuthContext{
		Authenticated: true, AuthType: "jwt", Subject: "alice", Issuer: "https://idp-b.example.com",
	}), params)

	count := tokenCount(p, "")
	if count != 2 {
		t.Errorf("same subject from different issuers (no jti) must produce separate cache entries, got %d", count)
	}
}

func TestTokenCacheKey_APIKey_DifferentApplicationID(t *testing.T) {
	// Different API key ApplicationIDs must produce separate cache entries.
	_, keyPEM := generateRSAKey(t)
	p := newTestPolicy()
	params := baseParams(keyPEM)

	p.OnRequestHeaders(context.Background(), newRequestContext(&policy.AuthContext{
		Authenticated: true, AuthType: "apikey",
		Properties: map[string]string{"ApplicationID": "app-001", "ApplicationName": "App One"},
	}), params)
	p.OnRequestHeaders(context.Background(), newRequestContext(&policy.AuthContext{
		Authenticated: true, AuthType: "apikey",
		Properties: map[string]string{"ApplicationID": "app-002", "ApplicationName": "App Two"},
	}), params)

	count := tokenCount(p, "")
	if count != 2 {
		t.Errorf("different ApplicationIDs must produce separate cache entries, got %d", count)
	}
}

func TestTokenCacheKey_APIKey_SameApplicationID_HitsCache(t *testing.T) {
	// Identical auth context must share one cache entry.
	_, keyPEM := generateRSAKey(t)
	p := newTestPolicy()
	params := baseParams(keyPEM)
	authCtx := &policy.AuthContext{
		Authenticated: true, AuthType: "apikey",
		Properties: map[string]string{"ApplicationID": "app-001", "ApplicationName": "MyApp"},
	}

	p.OnRequestHeaders(context.Background(), newRequestContext(authCtx), params)
	p.OnRequestHeaders(context.Background(), newRequestContext(authCtx), params)

	count := tokenCount(p, "")
	if count != 1 {
		t.Errorf("identical auth context must share one cache entry, got %d", count)
	}
}

func TestTokenCacheKey_NoAuth_SharedEntry(t *testing.T) {
	// Multiple unauthenticated requests to the same API must share one cache entry.
	_, keyPEM := generateRSAKey(t)
	p := newTestPolicy()
	params := baseParams(keyPEM)

	p.OnRequestHeaders(context.Background(), newRequestContext(nil), params)
	p.OnRequestHeaders(context.Background(), newRequestContext(nil), params)

	count := tokenCount(p, "")
	if count != 1 {
		t.Errorf("multiple unauthenticated requests must share one cache entry, got %d", count)
	}
}

func TestTokenCaching_Disabled_NoCacheEntries(t *testing.T) {
	// With tokenCaching=false, repeated identical requests must not populate the cache.
	_, keyPEM := generateRSAKey(t)
	p := newTestPolicy()
	params := baseParams(keyPEM)
	params["tokenCaching"] = false
	authCtx := &policy.AuthContext{Authenticated: true, AuthType: "jwt", Subject: "alice", TokenId: "token-xyz"}

	p.OnRequestHeaders(context.Background(), newRequestContext(authCtx), params)
	p.OnRequestHeaders(context.Background(), newRequestContext(authCtx), params)

	count := tokenCount(p, "")
	if count != 0 {
		t.Errorf("tokenCaching=false must not populate the cache, got %d entries", count)
	}
}

// ─── Context Claims Tests ─────────────────────────────────────────────────────

func TestContextClaims_StaticPassthrough(t *testing.T) {
	rsaKey, keyPEM := generateRSAKey(t)
	p := newTestPolicy()
	params := baseParams(keyPEM)
	params["customClaims"] = map[string]interface{}{"env": "production"}

	reqCtx := newRequestContext(&policy.AuthContext{Authenticated: true, AuthType: "jwt", Subject: "leo"})
	result := p.OnRequestHeaders(context.Background(), reqCtx, params)
	mods := result.(policy.UpstreamRequestHeaderModifications)
	claims := decodeJWT(t, mods.HeadersToSet[defaultHeader], &rsaKey.PublicKey)

	if claims["env"] != "production" {
		t.Errorf("expected env=production, got %v", claims["env"])
	}
}

func TestContextClaims_RequestPath(t *testing.T) {
	rsaKey, keyPEM := generateRSAKey(t)
	p := newTestPolicy()
	params := baseParams(keyPEM)
	params["customClaims"] = map[string]interface{}{"req_path": "$ctx:request.path"}

	reqCtx := &policy.RequestHeaderContext{
		SharedContext: &policy.SharedContext{
			RequestID:   "r1",
			Metadata:    make(map[string]interface{}),
			AuthContext: &policy.AuthContext{Authenticated: true, AuthType: "jwt", Subject: "mia"},
		},
		Headers: policy.NewHeaders(map[string][]string{}),
		Path:    "/petstore/v1/pets/42",
		Method:  "GET",
	}

	result := p.OnRequestHeaders(context.Background(), reqCtx, params)
	mods := result.(policy.UpstreamRequestHeaderModifications)
	claims := decodeJWT(t, mods.HeadersToSet[defaultHeader], &rsaKey.PublicKey)

	if claims["req_path"] != "/petstore/v1/pets/42" {
		t.Errorf("expected req_path=/petstore/v1/pets/42, got %v", claims["req_path"])
	}
}

func TestContextClaims_RequestHeader(t *testing.T) {
	rsaKey, keyPEM := generateRSAKey(t)
	p := newTestPolicy()
	params := baseParams(keyPEM)
	params["customClaims"] = map[string]interface{}{"tenant": "$ctx:request.header.x-tenant-id"}

	reqCtx := &policy.RequestHeaderContext{
		SharedContext: &policy.SharedContext{
			RequestID:   "r2",
			Metadata:    make(map[string]interface{}),
			AuthContext: &policy.AuthContext{Authenticated: true, AuthType: "jwt", Subject: "noah"},
		},
		Headers: policy.NewHeaders(map[string][]string{"x-tenant-id": {"acme-corp"}}),
		Path:    "/api/v1/data",
		Method:  "GET",
	}

	result := p.OnRequestHeaders(context.Background(), reqCtx, params)
	mods := result.(policy.UpstreamRequestHeaderModifications)
	claims := decodeJWT(t, mods.HeadersToSet[defaultHeader], &rsaKey.PublicKey)

	if claims["tenant"] != "acme-corp" {
		t.Errorf("expected tenant=acme-corp, got %v", claims["tenant"])
	}
}

func TestContextClaims_APIName(t *testing.T) {
	rsaKey, keyPEM := generateRSAKey(t)
	p := newTestPolicy()
	params := baseParams(keyPEM)
	params["customClaims"] = map[string]interface{}{"api": "$ctx:api.name"}

	reqCtx := &policy.RequestHeaderContext{
		SharedContext: &policy.SharedContext{
			RequestID:   "r3",
			Metadata:    make(map[string]interface{}),
			APIName:     "PetStoreAPI",
			AuthContext: &policy.AuthContext{Authenticated: true, AuthType: "jwt", Subject: "olivia"},
		},
		Headers: policy.NewHeaders(map[string][]string{}),
		Path:    "/api/v1",
		Method:  "GET",
	}

	result := p.OnRequestHeaders(context.Background(), reqCtx, params)
	mods := result.(policy.UpstreamRequestHeaderModifications)
	claims := decodeJWT(t, mods.HeadersToSet[defaultHeader], &rsaKey.PublicKey)

	if claims["api"] != "PetStoreAPI" {
		t.Errorf("expected api=PetStoreAPI, got %v", claims["api"])
	}
}

func TestContextClaims_AuthCredentialID(t *testing.T) {
	rsaKey, keyPEM := generateRSAKey(t)
	p := newTestPolicy()
	params := baseParams(keyPEM)
	params["customClaims"] = map[string]interface{}{"clientId": "$ctx:auth.credential_id"}

	reqCtx := newRequestContext(&policy.AuthContext{
		Authenticated: true,
		AuthType:      "apikey",
		Subject:       "peter",
		CredentialID:  "cred-xyz-999",
	})

	result := p.OnRequestHeaders(context.Background(), reqCtx, params)
	mods := result.(policy.UpstreamRequestHeaderModifications)
	claims := decodeJWT(t, mods.HeadersToSet[defaultHeader], &rsaKey.PublicKey)

	if claims["clientId"] != "cred-xyz-999" {
		t.Errorf("expected clientId=cred-xyz-999, got %v", claims["clientId"])
	}
}

func TestContextClaims_AuthProperty(t *testing.T) {
	rsaKey, keyPEM := generateRSAKey(t)
	p := newTestPolicy()
	params := baseParams(keyPEM)
	params["customClaims"] = map[string]interface{}{"clientName": "$ctx:auth.property.client_name"}

	reqCtx := newRequestContext(&policy.AuthContext{
		Authenticated: true,
		AuthType:      "jwt",
		Subject:       "quinn",
		Properties:    map[string]string{"client_name": "MyService"},
	})

	result := p.OnRequestHeaders(context.Background(), reqCtx, params)
	mods := result.(policy.UpstreamRequestHeaderModifications)
	claims := decodeJWT(t, mods.HeadersToSet[defaultHeader], &rsaKey.PublicKey)

	if claims["clientName"] != "MyService" {
		t.Errorf("expected clientName=MyService, got %v", claims["clientName"])
	}
}

func TestContextClaims_AuthProperty_MixedCaseKey(t *testing.T) {
	// Properties keys are case-sensitive; the $ctx: prefix must not be lowercased
	// past the fixed "auth.property." boundary.
	rsaKey, keyPEM := generateRSAKey(t)
	p := newTestPolicy()
	params := baseParams(keyPEM)
	params["customClaims"] = map[string]interface{}{"role": "$ctx:auth.property.ClientRole"}

	reqCtx := newRequestContext(&policy.AuthContext{
		Authenticated: true,
		AuthType:      "jwt",
		Subject:       "quinn",
		Properties:    map[string]string{"ClientRole": "admin"},
	})

	result := p.OnRequestHeaders(context.Background(), reqCtx, params)
	mods := result.(policy.UpstreamRequestHeaderModifications)
	claims := decodeJWT(t, mods.HeadersToSet[defaultHeader], &rsaKey.PublicKey)

	if claims["role"] != "admin" {
		t.Errorf("mixed-case property key: expected role=admin, got %v", claims["role"])
	}
}

func TestContextClaims_MissingHeader(t *testing.T) {
	rsaKey, keyPEM := generateRSAKey(t)
	p := newTestPolicy()
	params := baseParams(keyPEM)
	params["customClaims"] = map[string]interface{}{"tenant": "$ctx:request.header.x-tenant-id"}

	reqCtx := newRequestContext(&policy.AuthContext{Authenticated: true, AuthType: "jwt", Subject: "ryan"})
	// x-tenant-id header is not set

	result := p.OnRequestHeaders(context.Background(), reqCtx, params)
	mods := result.(policy.UpstreamRequestHeaderModifications)
	claims := decodeJWT(t, mods.HeadersToSet[defaultHeader], &rsaKey.PublicKey)

	if _, present := claims["tenant"]; present {
		t.Error("claim for missing header must be silently skipped")
	}
}

func TestContextClaims_UnknownVariable(t *testing.T) {
	rsaKey, keyPEM := generateRSAKey(t)
	p := newTestPolicy()
	params := baseParams(keyPEM)
	params["customClaims"] = map[string]interface{}{"x": "$ctx:unknown.variable.name"}

	reqCtx := newRequestContext(&policy.AuthContext{Authenticated: true, AuthType: "jwt", Subject: "sam"})

	result := p.OnRequestHeaders(context.Background(), reqCtx, params)
	mods := result.(policy.UpstreamRequestHeaderModifications)
	claims := decodeJWT(t, mods.HeadersToSet[defaultHeader], &rsaKey.PublicKey)

	if _, present := claims["x"]; present {
		t.Error("claim for unknown $ctx variable must be silently skipped")
	}
}

func TestContextClaims_NilAuthContext(t *testing.T) {
	// resolveClaimValue must return ("", false) for auth.* when AuthContext is nil —
	// verify this directly since the full pipeline requires an authenticated context.
	reqCtx := &policy.RequestHeaderContext{
		SharedContext: &policy.SharedContext{
			RequestID: "r9",
			Metadata:  make(map[string]interface{}),
			// AuthContext is deliberately nil
		},
		Headers: policy.NewHeaders(map[string][]string{}),
		Path:    "/test",
		Method:  "GET",
	}

	authVars := []string{
		"$ctx:auth.credential_id",
		"$ctx:auth.subject",
		"$ctx:auth.type",
		"$ctx:auth.property.foo",
	}
	for _, v := range authVars {
		resolved, ok := resolveClaimValue(v, reqCtx)
		if ok || resolved != "" {
			t.Errorf("resolveClaimValue(%q) with nil AuthContext: expected (\"\", false), got (%q, %v)", v, resolved, ok)
		}
	}
}

func TestCustomClaims_RestrictedClaimsSkippedWithWarn(t *testing.T) {
	rsaKey, keyPEM := generateRSAKey(t)
	p := newTestPolicy()
	params := baseParams(keyPEM)
	params["customClaims"] = map[string]interface{}{
		"iss": "https://custom-issuer.example.com",
		"sub": "overridden-subject",
		"env": "production", // non-restricted, must still be present
	}

	reqCtx := newRequestContext(&policy.AuthContext{
		Authenticated: true,
		AuthType:      "jwt",
		Subject:       "alice",
	})

	result := p.OnRequestHeaders(context.Background(), reqCtx, params)
	mods := result.(policy.UpstreamRequestHeaderModifications)
	claims := decodeJWT(t, mods.HeadersToSet[defaultHeader], &rsaKey.PublicKey)

	// Restricted claims must NOT be overridden — standard values win.
	if claims["iss"] == "https://custom-issuer.example.com" {
		t.Errorf("iss must not be overridden by customClaims; restricted claim should be skipped")
	}
	if claims["sub"] != "alice" {
		t.Errorf("sub must equal AuthContext.Subject (alice), got %v", claims["sub"])
	}
	// Non-restricted claims must still be set.
	if claims["env"] != "production" {
		t.Errorf("non-restricted claim env must still be set, got %v", claims["env"])
	}
}

func TestClaimMappings_Basic(t *testing.T) {
	rsaKey, keyPEM := generateRSAKey(t)
	p := newTestPolicy()
	params := baseParams(keyPEM)
	params["claimMappings"] = map[string]interface{}{
		"clientEmail": "email",
		"clientRole":  "role",
	}

	reqCtx := newRequestContext(&policy.AuthContext{
		Authenticated: true,
		AuthType:      "jwt",
		Subject:       "alice",
		Properties:    map[string]string{"email": "alice@example.com", "role": "admin"},
	})

	result := p.OnRequestHeaders(context.Background(), reqCtx, params)
	mods := result.(policy.UpstreamRequestHeaderModifications)
	claims := decodeJWT(t, mods.HeadersToSet[defaultHeader], &rsaKey.PublicKey)

	if claims["clientEmail"] != "alice@example.com" {
		t.Errorf("clientEmail must be mapped from Properties[email], got %v", claims["clientEmail"])
	}
	if claims["clientRole"] != "admin" {
		t.Errorf("clientRole must be mapped from Properties[role], got %v", claims["clientRole"])
	}
}

func TestClaimMappings_MissingPropertySkipped(t *testing.T) {
	rsaKey, keyPEM := generateRSAKey(t)
	p := newTestPolicy()
	params := baseParams(keyPEM)
	params["claimMappings"] = map[string]interface{}{
		"orgId": "organization", // "organization" not in Properties
	}

	reqCtx := newRequestContext(&policy.AuthContext{
		Authenticated: true,
		AuthType:      "jwt",
		Subject:       "alice",
		Properties:    map[string]string{"email": "alice@example.com"},
	})

	result := p.OnRequestHeaders(context.Background(), reqCtx, params)
	mods := result.(policy.UpstreamRequestHeaderModifications)
	claims := decodeJWT(t, mods.HeadersToSet[defaultHeader], &rsaKey.PublicKey)

	if _, present := claims["orgId"]; present {
		t.Errorf("orgId should be absent when source property is missing, got %v", claims["orgId"])
	}
}

func TestClaimMappings_RestrictedDestinationSkipped(t *testing.T) {
	rsaKey, keyPEM := generateRSAKey(t)
	p := newTestPolicy()
	params := baseParams(keyPEM)
	params["claimMappings"] = map[string]interface{}{
		"sub": "injected_subject", // "sub" is restricted
	}

	reqCtx := newRequestContext(&policy.AuthContext{
		Authenticated: true,
		AuthType:      "jwt",
		Subject:       "alice",
		Properties:    map[string]string{"injected_subject": "mallory"},
	})

	result := p.OnRequestHeaders(context.Background(), reqCtx, params)
	mods := result.(policy.UpstreamRequestHeaderModifications)
	claims := decodeJWT(t, mods.HeadersToSet[defaultHeader], &rsaKey.PublicKey)

	if claims["sub"] != "alice" {
		t.Errorf("sub must equal AuthContext.Subject (alice) when claimMapping target is restricted, got %v", claims["sub"])
	}
}

// ─── JWT Claims Passthrough Tests ─────────────────────────────────────────────

func TestJWTClaimsPassthrough_PropertiesForwarded(t *testing.T) {
	// All non-standard JWT claims in Properties must appear in the backend JWT
	// under their original names when auth type is jwt.
	rsaKey, keyPEM := generateRSAKey(t)
	p := newTestPolicy()
	params := baseParams(keyPEM)

	reqCtx := newRequestContext(&policy.AuthContext{
		Authenticated: true,
		AuthType:      "jwt",
		Subject:       "alice",
		Properties:    map[string]string{"email": "alice@example.com", "role": "admin", "org": "acme"},
	})

	result := p.OnRequestHeaders(context.Background(), reqCtx, params)
	mods := result.(policy.UpstreamRequestHeaderModifications)
	claims := decodeJWT(t, mods.HeadersToSet[defaultHeader], &rsaKey.PublicKey)

	if claims["email"] != "alice@example.com" {
		t.Errorf("email must be forwarded from Properties, got %v", claims["email"])
	}
	if claims["role"] != "admin" {
		t.Errorf("role must be forwarded from Properties, got %v", claims["role"])
	}
	if claims["org"] != "acme" {
		t.Errorf("org must be forwarded from Properties, got %v", claims["org"])
	}
}

func TestJWTClaimsPassthrough_ScopesForwarded(t *testing.T) {
	// Scopes must be forwarded as a space-delimited "scope" claim.
	rsaKey, keyPEM := generateRSAKey(t)
	p := newTestPolicy()
	params := baseParams(keyPEM)

	reqCtx := newRequestContext(&policy.AuthContext{
		Authenticated: true,
		AuthType:      "jwt",
		Subject:       "alice",
		Scopes:        map[string]bool{"read": true, "write": true},
	})

	result := p.OnRequestHeaders(context.Background(), reqCtx, params)
	mods := result.(policy.UpstreamRequestHeaderModifications)
	claims := decodeJWT(t, mods.HeadersToSet[defaultHeader], &rsaKey.PublicKey)

	scopeVal, ok := claims["scope"]
	if !ok {
		t.Fatal("scope claim must be present when AuthContext.Scopes is non-empty")
	}
	scopeStr, ok := scopeVal.(string)
	if !ok {
		t.Fatalf("scope claim must be a string, got %T", scopeVal)
	}
	// Values are sorted, so "read write" is deterministic.
	if scopeStr != "read write" {
		t.Errorf("expected scope=\"read write\", got %q", scopeStr)
	}
}

func TestJWTClaimsPassthrough_CustomClaimsOverrideProperty(t *testing.T) {
	// customClaims must override auto-forwarded Properties for the same key.
	rsaKey, keyPEM := generateRSAKey(t)
	p := newTestPolicy()
	params := baseParams(keyPEM)
	params["customClaims"] = map[string]interface{}{"role": "superadmin"}

	reqCtx := newRequestContext(&policy.AuthContext{
		Authenticated: true,
		AuthType:      "jwt",
		Subject:       "alice",
		Properties:    map[string]string{"role": "viewer"},
	})

	result := p.OnRequestHeaders(context.Background(), reqCtx, params)
	mods := result.(policy.UpstreamRequestHeaderModifications)
	claims := decodeJWT(t, mods.HeadersToSet[defaultHeader], &rsaKey.PublicKey)

	if claims["role"] != "superadmin" {
		t.Errorf("customClaims must override auto-forwarded Property, got %v", claims["role"])
	}
}

func TestJWTClaimsPassthrough_NotForwardedForNonJWTAuth(t *testing.T) {
	// Properties must NOT be auto-forwarded for non-JWT auth types (e.g. basic).
	rsaKey, keyPEM := generateRSAKey(t)
	p := newTestPolicy()
	params := baseParams(keyPEM)

	reqCtx := newRequestContext(&policy.AuthContext{
		Authenticated: true,
		AuthType:      "basic",
		Subject:       "bob",
		Properties:    map[string]string{"email": "bob@example.com"},
	})

	result := p.OnRequestHeaders(context.Background(), reqCtx, params)
	mods := result.(policy.UpstreamRequestHeaderModifications)
	claims := decodeJWT(t, mods.HeadersToSet[defaultHeader], &rsaKey.PublicKey)

	if _, present := claims["email"]; present {
		t.Error("Properties must not be auto-forwarded for basic auth; use claimMappings or customClaims instead")
	}
}

func TestTokenCacheKey_JWT_DifferentProperties_NoJTI(t *testing.T) {
	// Without jti, tokens with same identity but different custom claims must produce
	// separate cache entries (because the backend JWT content differs).
	_, keyPEM := generateRSAKey(t)
	p := newTestPolicy()
	params := baseParams(keyPEM)

	p.OnRequestHeaders(context.Background(), newRequestContext(&policy.AuthContext{
		Authenticated: true, AuthType: "jwt", Subject: "alice", Issuer: "https://idp.example.com",
		Properties: map[string]string{"role": "viewer"},
	}), params)
	p.OnRequestHeaders(context.Background(), newRequestContext(&policy.AuthContext{
		Authenticated: true, AuthType: "jwt", Subject: "alice", Issuer: "https://idp.example.com",
		Properties: map[string]string{"role": "admin"},
	}), params)

	count := tokenCount(p, "")
	if count != 2 {
		t.Errorf("same identity but different Properties (no jti) must produce separate cache entries, got %d", count)
	}
}

func TestClaimMappings_CustomClaimsOverride(t *testing.T) {
	rsaKey, keyPEM := generateRSAKey(t)
	p := newTestPolicy()
	params := baseParams(keyPEM)
	params["claimMappings"] = map[string]interface{}{
		"role": "role", // maps Properties["role"] → "role"
	}
	params["customClaims"] = map[string]interface{}{
		"role": "superadmin", // customClaims must win over claimMappings
	}

	reqCtx := newRequestContext(&policy.AuthContext{
		Authenticated: true,
		AuthType:      "jwt",
		Subject:       "alice",
		Properties:    map[string]string{"role": "viewer"},
	})

	result := p.OnRequestHeaders(context.Background(), reqCtx, params)
	mods := result.(policy.UpstreamRequestHeaderModifications)
	claims := decodeJWT(t, mods.HeadersToSet[defaultHeader], &rsaKey.PublicKey)

	if claims["role"] != "superadmin" {
		t.Errorf("customClaims must override claimMappings for same key, got %v", claims["role"])
	}
}

// ─── Dialect Tests ────────────────────────────────────────────────────────────

func TestDialect_PrefixesForwardedClaims(t *testing.T) {
	// Dialect must prefix auto-forwarded original-JWT claims; the bare key must be absent.
	rsaKey, keyPEM := generateRSAKey(t)
	p := newTestPolicy()
	params := baseParams(keyPEM)
	params["dialect"] = "http://wso2.org/claims/"

	reqCtx := newRequestContext(&policy.AuthContext{
		Authenticated: true,
		AuthType:      "jwt",
		Subject:       "alice",
		Properties:    map[string]string{"email": "alice@example.com", "role": "admin"},
	})

	result := p.OnRequestHeaders(context.Background(), reqCtx, params)
	mods := result.(policy.UpstreamRequestHeaderModifications)
	claims := decodeJWT(t, mods.HeadersToSet[defaultHeader], &rsaKey.PublicKey)

	// Prefixed keys must be present.
	if claims["http://wso2.org/claims/email"] != "alice@example.com" {
		t.Errorf("expected prefixed claim http://wso2.org/claims/email=alice@example.com, got %v", claims["http://wso2.org/claims/email"])
	}
	if claims["http://wso2.org/claims/role"] != "admin" {
		t.Errorf("expected prefixed claim http://wso2.org/claims/role=admin, got %v", claims["http://wso2.org/claims/role"])
	}
	// Bare keys must not be present.
	if _, present := claims["email"]; present {
		t.Errorf("bare key 'email' must not appear when dialect is set; only the prefixed form should")
	}
	if _, present := claims["role"]; present {
		t.Errorf("bare key 'role' must not appear when dialect is set; only the prefixed form should")
	}
}

func TestDialect_PrefixesConfiguredClaims(t *testing.T) {
	// dialect must prefix customClaims and claimMappings destinations as well as auto-forwarded claims.
	// Standard claims (sub, scope, iss, etc.) set by the policy itself must never be prefixed.
	rsaKey, keyPEM := generateRSAKey(t)
	p := newTestPolicy()
	params := baseParams(keyPEM)
	params["dialect"] = "http://wso2.org/claims/"
	params["customClaims"] = map[string]interface{}{"org": "acme"}
	params["claimMappings"] = map[string]interface{}{"clientEmail": "email"}

	reqCtx := newRequestContext(&policy.AuthContext{
		Authenticated: true,
		AuthType:      "jwt",
		Subject:       "alice",
		Scopes:        map[string]bool{"read": true},
		Properties:    map[string]string{"email": "alice@example.com"},
	})

	result := p.OnRequestHeaders(context.Background(), reqCtx, params)
	mods := result.(policy.UpstreamRequestHeaderModifications)
	claims := decodeJWT(t, mods.HeadersToSet[defaultHeader], &rsaKey.PublicKey)

	// Standard claims must use their standard names — never prefixed.
	if claims["sub"] != "alice" {
		t.Errorf("sub must not be prefixed, got %v", claims["sub"])
	}
	if claims["scope"] != "read" {
		t.Errorf("scope must not be prefixed, got %v", claims["scope"])
	}
	// customClaims destination must be prefixed.
	if claims["http://wso2.org/claims/org"] != "acme" {
		t.Errorf("customClaim 'org' must be prefixed, got %v", claims["http://wso2.org/claims/org"])
	}
	if _, present := claims["org"]; present {
		t.Errorf("bare customClaim key 'org' must not appear when dialect is set")
	}
	// claimMappings destination must be prefixed.
	if claims["http://wso2.org/claims/clientEmail"] != "alice@example.com" {
		t.Errorf("claimMapping destination 'clientEmail' must be prefixed, got %v", claims["http://wso2.org/claims/clientEmail"])
	}
	if _, present := claims["clientEmail"]; present {
		t.Errorf("bare claimMapping destination 'clientEmail' must not appear when dialect is set")
	}
}

// ─── ExcludedClaims Tests ─────────────────────────────────────────────────────

func TestExcludedClaims_DropsListedClaims(t *testing.T) {
	// Listed claims must not appear; non-listed claims must still be forwarded.
	rsaKey, keyPEM := generateRSAKey(t)
	p := newTestPolicy()
	params := baseParams(keyPEM)
	params["excludedClaims"] = []interface{}{"role"}

	reqCtx := newRequestContext(&policy.AuthContext{
		Authenticated: true,
		AuthType:      "jwt",
		Subject:       "alice",
		Properties:    map[string]string{"email": "alice@example.com", "role": "admin", "org": "acme"},
	})

	result := p.OnRequestHeaders(context.Background(), reqCtx, params)
	mods := result.(policy.UpstreamRequestHeaderModifications)
	claims := decodeJWT(t, mods.HeadersToSet[defaultHeader], &rsaKey.PublicKey)

	if _, present := claims["role"]; present {
		t.Errorf("excluded claim 'role' must not be forwarded to the backend JWT")
	}
	// Non-excluded claims must still be forwarded.
	if claims["email"] != "alice@example.com" {
		t.Errorf("non-excluded claim 'email' must still be forwarded, got %v", claims["email"])
	}
	if claims["org"] != "acme" {
		t.Errorf("non-excluded claim 'org' must still be forwarded, got %v", claims["org"])
	}
}

// ─── Combined Dialect + ExcludedClaims Tests ─────────────────────────────────

func TestDialectAndExcludedClaims_Combined(t *testing.T) {
	// Excluded claim must be absent even with dialect set; remaining claims must be prefixed.
	rsaKey, keyPEM := generateRSAKey(t)
	p := newTestPolicy()
	params := baseParams(keyPEM)
	params["dialect"] = "http://wso2.org/claims/"
	params["excludedClaims"] = []interface{}{"role"}

	reqCtx := newRequestContext(&policy.AuthContext{
		Authenticated: true,
		AuthType:      "jwt",
		Subject:       "alice",
		Properties:    map[string]string{"email": "alice@example.com", "role": "admin"},
	})

	result := p.OnRequestHeaders(context.Background(), reqCtx, params)
	mods := result.(policy.UpstreamRequestHeaderModifications)
	claims := decodeJWT(t, mods.HeadersToSet[defaultHeader], &rsaKey.PublicKey)

	// Excluded claim must be absent in both prefixed and bare form.
	if _, present := claims["role"]; present {
		t.Errorf("excluded claim 'role' (bare) must not appear")
	}
	if _, present := claims["http://wso2.org/claims/role"]; present {
		t.Errorf("excluded claim 'role' (prefixed) must not appear")
	}
	// Non-excluded claim must appear under the prefixed key.
	if claims["http://wso2.org/claims/email"] != "alice@example.com" {
		t.Errorf("non-excluded claim must appear prefixed, got %v", claims["http://wso2.org/claims/email"])
	}
	// Bare non-excluded key must not appear.
	if _, present := claims["email"]; present {
		t.Errorf("bare 'email' must not appear when dialect is set")
	}
}

// ─── Empty Defaults Regression Guard ─────────────────────────────────────────

func TestDialectAndExcludedClaims_EmptyDefaults_PreserveCurrentBehavior(t *testing.T) {
	// With no dialect and no excludedClaims, forwarding behavior must be identical
	// to the pre-feature baseline: bare original claim names forwarded unchanged.
	rsaKey, keyPEM := generateRSAKey(t)
	p := newTestPolicy()
	params := baseParams(keyPEM)
	// Explicitly set empty values (matching the param defaults).
	params["dialect"] = ""
	params["excludedClaims"] = []interface{}{}

	reqCtx := newRequestContext(&policy.AuthContext{
		Authenticated: true,
		AuthType:      "jwt",
		Subject:       "alice",
		Properties:    map[string]string{"email": "alice@example.com", "role": "admin"},
	})

	result := p.OnRequestHeaders(context.Background(), reqCtx, params)
	mods := result.(policy.UpstreamRequestHeaderModifications)
	claims := decodeJWT(t, mods.HeadersToSet[defaultHeader], &rsaKey.PublicKey)

	if claims["email"] != "alice@example.com" {
		t.Errorf("empty dialect: 'email' must be forwarded as-is, got %v", claims["email"])
	}
	if claims["role"] != "admin" {
		t.Errorf("empty dialect: 'role' must be forwarded as-is, got %v", claims["role"])
	}
	if claims["sub"] != "alice" {
		t.Errorf("sub must be present, got %v", claims["sub"])
	}
}

func TestClaimMapping_SourceNotDuplicated(t *testing.T) {
	// A claim that is remapped via claimMappings must appear ONLY under its destination
	// name — the original source key must not also appear in the backend JWT.
	rsaKey, keyPEM := generateRSAKey(t)
	p := newTestPolicy()
	params := baseParams(keyPEM)
	params["claimMappings"] = map[string]interface{}{
		"user_email": "email", // source "email" → dest "user_email"
	}

	reqCtx := newRequestContext(&policy.AuthContext{
		Authenticated: true,
		AuthType:      "jwt",
		Subject:       "alice",
		Properties:    map[string]string{"email": "alice@example.com", "role": "admin"},
	})

	result := p.OnRequestHeaders(context.Background(), reqCtx, params)
	mods := result.(policy.UpstreamRequestHeaderModifications)
	claims := decodeJWT(t, mods.HeadersToSet[defaultHeader], &rsaKey.PublicKey)

	if claims["user_email"] != "alice@example.com" {
		t.Errorf("claimMapping destination 'user_email' must be present, got %v", claims["user_email"])
	}
	if _, ok := claims["email"]; ok {
		t.Errorf("claimMapping source 'email' must not appear in the backend JWT (got %v)", claims["email"])
	}
	// Non-remapped claims still forwarded normally.
	if claims["role"] != "admin" {
		t.Errorf("non-mapped claim 'role' must still be forwarded, got %v", claims["role"])
	}
}

// TestGenerationFailureDeclaresFault covers the fault declaration on the paths where the
// backend JWT cannot be built. Each refuses the request, so each must be a fault: an
// unusable parameter is a configuration fault, a token that cannot be signed a mediation one.
func TestGenerationFailureDeclaresFault(t *testing.T) {
	tests := []struct {
		name     string
		params   map[string]interface{}
		wantType string
	}{
		{
			name:     "unsupported algorithm",
			params:   map[string]interface{}{"algorithm": "NotAnAlgorithm"},
			wantType: policy.FaultTypeConfiguration,
		},
		{
			name:     "unparseable signing key",
			params:   map[string]interface{}{"signingKey": map[string]interface{}{"inline": "not a PEM key"}},
			wantType: policy.FaultTypeMediation,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &BackendJWTPolicy{}
			reqCtx := newRequestContext(&policy.AuthContext{
				Authenticated: true, AuthType: "jwt", Subject: "henry",
			})
			result := p.OnRequestHeaders(context.Background(), reqCtx, tt.params)

			resp, ok := result.(policy.ImmediateResponse)
			if !ok {
				t.Fatalf("expected ImmediateResponse, got %T", result)
			}
			if !resp.IsFault {
				t.Fatalf("expected IsFault=true when the backend JWT cannot be built")
			}
			if resp.Fault == nil {
				t.Fatalf("expected Error to be populated")
			}
			if resp.Fault.Code != policy.FaultCodeMediationFailed {
				t.Fatalf("expected Error.Code=%q, got %q", policy.FaultCodeMediationFailed, resp.Fault.Code)
			}
			if resp.Fault.Type != tt.wantType {
				t.Fatalf("expected Error.Type=%q, got %q", tt.wantType, resp.Fault.Type)
			}
			if resp.Fault.Description == "" {
				t.Fatalf("expected Error.Description to carry the internal reason")
			}
			// The gateway's own diagnostic must not reach the caller's body.
			if strings.Contains(string(resp.Body), resp.Fault.Description) {
				t.Fatalf("Description leaked into the client body: %q", resp.Fault.Description)
			}
		})
	}
}
