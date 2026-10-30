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

package oauth2generator

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

// ─── helpers ─────────────────────────────────────────────────────────────────

func validParams() map[string]interface{} {
	return map[string]interface{}{
		"tokenEndpoint": "https://idp.example.com/oauth2/token",
		"clientId":      "gateway-client",
		"clientSecret":  "s3cr3t",
	}
}

func newRequestHeaderCtx() *policy.RequestHeaderContext {
	return &policy.RequestHeaderContext{
		SharedContext: &policy.SharedContext{},
		Headers:       policy.NewHeaders(map[string][]string{}),
		Path:          "/v1/chat/completions",
		Method:        http.MethodPost,
		Authority:     "gateway.example.com",
		Scheme:        "https",
	}
}

func newTestPolicy() *Policy {
	return &Policy{
		mode:          ModeTokenEndpoint,
		tokenEndpoint: "https://idp.example.com/oauth2/token",
		clientID:      "gateway-client",
		headerName:    defaultHeaderName,
		valuePrefix:   defaultValuePrefix,
	}
}

// fakeTokenSource is a tokenProvider test double that counts Purge() calls.
type fakeTokenSource struct {
	purgeCalls int
}

func (f *fakeTokenSource) Token(context.Context) (*Token, error) {
	return &Token{AccessToken: "unused"}, nil
}

func (f *fakeTokenSource) Purge() {
	f.purgeCalls++
}

func newResponseHeaderCtx(status int) *policy.ResponseHeaderContext {
	return &policy.ResponseHeaderContext{
		SharedContext:   &policy.SharedContext{},
		ResponseHeaders: policy.NewHeaders(map[string][]string{}),
		ResponseStatus:  status,
	}
}

// ─── GetPolicy / param validation ────────────────────────────────────────────

func TestGetPolicy_ValidParams(t *testing.T) {
	p, err := GetPolicy(policy.PolicyMetadata{}, validParams())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	oa, ok := p.(*Policy)
	if !ok {
		t.Fatalf("expected *Policy, got %T", p)
	}
	if oa.tokenEndpoint != "https://idp.example.com/oauth2/token" {
		t.Errorf("unexpected tokenEndpoint: %q", oa.tokenEndpoint)
	}
	if oa.clientID != "gateway-client" {
		t.Errorf("unexpected clientID: %q", oa.clientID)
	}
	if oa.grantType != GrantTypeClientCredentials {
		t.Errorf("expected grantType to default to %q when omitted, got %q", GrantTypeClientCredentials, oa.grantType)
	}
}

// Omitting systemParameters entirely must never construct a Redis client - cacheStrategy defaults to "memory".
func TestGetPolicy_DefaultCacheStrategy_NeverTouchesRedis(t *testing.T) {
	p, err := GetPolicy(policy.PolicyMetadata{}, validParams())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	src, ok := p.(*Policy).tokenSource.(*redisCachingTokenSource)
	if !ok {
		t.Fatalf("expected *redisCachingTokenSource, got %T", p.(*Policy).tokenSource)
	}
	if src.redisClient != nil {
		t.Error("expected no redis client to be constructed under the default cacheStrategy: memory")
	}
}

func TestGetPolicy_ExplicitCacheStrategyRedis_ConstructsRedisClient(t *testing.T) {
	params := validParams()
	params["cacheStrategy"] = "redis"
	params["redis"] = map[string]interface{}{"host": "127.0.0.1", "port": 6399}
	p, err := GetPolicy(policy.PolicyMetadata{}, params)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	src := p.(*Policy).tokenSource.(*redisCachingTokenSource)
	if src.redisClient == nil {
		t.Error("expected a redis client to be constructed under cacheStrategy: redis")
	}
}

func TestGetPolicy_ExplicitGrantType(t *testing.T) {
	params := validParams()
	params["grantType"] = GrantTypeClientCredentials
	p, err := GetPolicy(policy.PolicyMetadata{}, params)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	oa := p.(*Policy)
	if oa.grantType != GrantTypeClientCredentials {
		t.Errorf("unexpected grantType: %q", oa.grantType)
	}
}

func TestGetPolicy_UnsupportedGrantType(t *testing.T) {
	// An unrecognized grantType must fail loudly, not silently fall back to client_credentials.
	params := validParams()
	params["grantType"] = "authorization_code"
	_, err := GetPolicy(policy.PolicyMetadata{}, params)
	if err == nil {
		t.Fatal("expected error for unsupported grantType, got nil")
	}
	if !strings.Contains(err.Error(), "grantType") {
		t.Errorf("expected error to mention grantType, got: %v", err)
	}
}

// ─── clientAuthMethod ────────────────────────────────────────────────────────

func TestGetPolicy_ClientAuthMethod_DefaultsToBasic(t *testing.T) {
	p, err := GetPolicy(policy.PolicyMetadata{}, validParams())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	oa := p.(*Policy)
	if oa.clientAuthMethod != ClientAuthMethodBasic {
		t.Errorf("expected clientAuthMethod to default to %q when omitted, got %q", ClientAuthMethodBasic, oa.clientAuthMethod)
	}
}

func TestGetPolicy_ClientAuthMethod_ExplicitPost(t *testing.T) {
	params := validParams()
	params["clientAuthMethod"] = ClientAuthMethodPost
	p, err := GetPolicy(policy.PolicyMetadata{}, params)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	oa := p.(*Policy)
	if oa.clientAuthMethod != ClientAuthMethodPost {
		t.Errorf("unexpected clientAuthMethod: %q", oa.clientAuthMethod)
	}
}

func TestGetPolicy_ClientAuthMethod_InvalidValue(t *testing.T) {
	params := validParams()
	params["clientAuthMethod"] = "client_secret_jwt"
	_, err := GetPolicy(policy.PolicyMetadata{}, params)
	if err == nil {
		t.Fatal("expected error for unsupported clientAuthMethod, got nil")
	}
	if !strings.Contains(err.Error(), "clientAuthMethod") {
		t.Errorf("expected error to mention clientAuthMethod, got: %v", err)
	}
}

// ─── tokenRequestTimeout / defaultTokenTTL ───────────────────────────────────

func TestValidateAndExtractParams_TimeoutAndTTLDefaults(t *testing.T) {
	p, err := validateAndExtractParams(validParams())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.tokenRequestTimeout != defaultTokenRequestTimeout {
		t.Errorf("expected tokenRequestTimeout to default to %s, got %s", defaultTokenRequestTimeout, p.tokenRequestTimeout)
	}
	if p.defaultTokenTTL != defaultTokenTTLFallback {
		t.Errorf("expected defaultTokenTTL to default to %s, got %s", defaultTokenTTLFallback, p.defaultTokenTTL)
	}
}

func TestValidateAndExtractParams_TimeoutAndTTLExplicitOverride(t *testing.T) {
	params := validParams()
	params["tokenRequestTimeout"] = "2500ms"
	params["defaultTokenTTL"] = "30m"

	p, err := validateAndExtractParams(params)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.tokenRequestTimeout != 2500*time.Millisecond {
		t.Errorf("unexpected tokenRequestTimeout: %s", p.tokenRequestTimeout)
	}
	if p.defaultTokenTTL != 30*time.Minute {
		t.Errorf("unexpected defaultTokenTTL: %s", p.defaultTokenTTL)
	}
}

func TestValidateAndExtractParams_TimeoutAndTTLUnparsable_FallsBackToDefault(t *testing.T) {
	params := validParams()
	params["tokenRequestTimeout"] = "not-a-duration"
	params["defaultTokenTTL"] = "also-not-a-duration"

	p, err := validateAndExtractParams(params)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.tokenRequestTimeout != defaultTokenRequestTimeout {
		t.Errorf("expected unparsable tokenRequestTimeout to fall back to default %s, got %s", defaultTokenRequestTimeout, p.tokenRequestTimeout)
	}
	if p.defaultTokenTTL != defaultTokenTTLFallback {
		t.Errorf("expected unparsable defaultTokenTTL to fall back to default %s, got %s", defaultTokenTTLFallback, p.defaultTokenTTL)
	}
}

// A zero/negative value must fall back to the default, not be honored as-is - http.Client treats
// Timeout <= 0 as "no timeout", and a <= 0 TTL would expire a token before it's even cached.
func TestValidateAndExtractParams_TimeoutAndTTLNonPositive_FallsBackToDefault(t *testing.T) {
	for _, tt := range []struct {
		name  string
		value string
	}{
		{"zero", "0s"},
		{"negative", "-1s"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			params := validParams()
			params["tokenRequestTimeout"] = tt.value
			params["defaultTokenTTL"] = tt.value

			p, err := validateAndExtractParams(params)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if p.tokenRequestTimeout != defaultTokenRequestTimeout {
				t.Errorf("expected non-positive tokenRequestTimeout %q to fall back to default %s, got %s",
					tt.value, defaultTokenRequestTimeout, p.tokenRequestTimeout)
			}
			if p.defaultTokenTTL != defaultTokenTTLFallback {
				t.Errorf("expected non-positive defaultTokenTTL %q to fall back to default %s, got %s",
					tt.value, defaultTokenTTLFallback, p.defaultTokenTTL)
			}
		})
	}
}

// ─── expiryBuffer ─────────────────────────────────────────────────────────────

func TestValidateAndExtractParams_ExpiryBufferDefaults(t *testing.T) {
	p, err := validateAndExtractParams(validParams())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.expiryBuffer != defaultExpiryBuffer {
		t.Errorf("expected expiryBuffer to default to %s, got %s", defaultExpiryBuffer, p.expiryBuffer)
	}
}

func TestValidateAndExtractParams_ExpiryBufferExplicitOverride(t *testing.T) {
	params := validParams()
	params["expiryBuffer"] = "45s"

	p, err := validateAndExtractParams(params)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.expiryBuffer != 45*time.Second {
		t.Errorf("unexpected expiryBuffer: %s", p.expiryBuffer)
	}
}

func TestValidateAndExtractParams_ExpiryBufferUnparsable_FallsBackToDefault(t *testing.T) {
	params := validParams()
	params["expiryBuffer"] = "not-a-duration"

	p, err := validateAndExtractParams(params)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.expiryBuffer != defaultExpiryBuffer {
		t.Errorf("expected unparsable expiryBuffer to fall back to default %s, got %s", defaultExpiryBuffer, p.expiryBuffer)
	}
}

// A negative buffer would invert tokenFreshEnough's check, so it must fall back to the default.
func TestValidateAndExtractParams_ExpiryBufferNegative_FallsBackToDefault(t *testing.T) {
	params := validParams()
	params["expiryBuffer"] = "-5s"

	p, err := validateAndExtractParams(params)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.expiryBuffer != defaultExpiryBuffer {
		t.Errorf("expected negative expiryBuffer to fall back to default %s, got %s", defaultExpiryBuffer, p.expiryBuffer)
	}
}

// Proves tokenRequestTimeout actually bounds the token-endpoint call, so a hung IdP can't block a fetch indefinitely.
func TestClientCredentials_TokenRequestTimeout_BoundsHungIdP(t *testing.T) {
	const idpDelay = 2 * time.Second
	const configuredTimeout = 100 * time.Millisecond
	// Comfortably covers the unreachable-Redis retry overhead while staying well under idpDelay.
	const maxAcceptableElapsed = 1500 * time.Millisecond

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(idpDelay)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "should-never-be-returned",
			"token_type":   "Bearer",
			"expires_in":   300,
		})
	}))
	defer server.Close()

	params := validParams()
	params["tokenEndpoint"] = server.URL
	params["tokenRequestTimeout"] = configuredTimeout.String()
	// Redis pinned unreachable - see TestPasswordGrant_EndToEnd.
	params["redis"] = map[string]interface{}{"host": "127.0.0.1", "port": 1}

	p, err := GetPolicy(policy.PolicyMetadata{}, params)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	pol := p.(*Policy)

	reqCtx := newRequestHeaderCtx()
	start := time.Now()
	action := pol.OnRequestHeaders(context.Background(), reqCtx, nil)
	elapsed := time.Since(start)

	if elapsed >= maxAcceptableElapsed {
		t.Errorf("expected the %s timeout to abort the request well before the IdP's %s delay, took %s", configuredTimeout, idpDelay, elapsed)
	}

	resp, ok := action.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("expected ImmediateResponse (timeout should fail the request), got %T", action)
	}
	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("expected 502 Bad Gateway, got %d", resp.StatusCode)
	}
}

// client_secret_post must send client_id/client_secret as form fields, not a Basic auth header.
func TestClientCredentials_ClientSecretPost_EndToEnd(t *testing.T) {
	var gotAuthHeader, gotClientID, gotClientSecret string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatalf("failed to parse form: %v", err)
		}
		gotAuthHeader = r.Header.Get("Authorization")
		gotClientID = r.PostForm.Get("client_id")
		gotClientSecret = r.PostForm.Get("client_secret")

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "cc-post-token-xyz",
			"token_type":   "Bearer",
			"expires_in":   300,
		})
	}))
	defer server.Close()

	params := validParams()
	params["tokenEndpoint"] = server.URL
	params["clientAuthMethod"] = ClientAuthMethodPost
	// Redis pinned unreachable - see TestPasswordGrant_EndToEnd.
	params["redis"] = map[string]interface{}{"host": "127.0.0.1", "port": 1}

	p, err := GetPolicy(policy.PolicyMetadata{}, params)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	pol := p.(*Policy)

	reqCtx := newRequestHeaderCtx()
	action := pol.OnRequestHeaders(context.Background(), reqCtx, nil)
	mods, ok := action.(policy.UpstreamRequestHeaderModifications)
	if !ok {
		t.Fatalf("expected UpstreamRequestHeaderModifications, got %T", action)
	}
	if mods.HeadersToSet["Authorization"] != "Bearer cc-post-token-xyz" {
		t.Errorf("unexpected Authorization header: %q", mods.HeadersToSet["Authorization"])
	}

	if gotAuthHeader != "" {
		t.Errorf("expected no Basic auth header with client_secret_post, got %q", gotAuthHeader)
	}
	if gotClientID != "gateway-client" {
		t.Errorf("expected client_id=gateway-client in form body, got %q", gotClientID)
	}
	if gotClientSecret != "s3cr3t" {
		t.Errorf("expected client_secret=s3cr3t in form body, got %q", gotClientSecret)
	}
}

// client_secret_post must apply identically to the password grant.
func TestPasswordGrant_ClientSecretPost_EndToEnd(t *testing.T) {
	var gotAuthHeader, gotClientID, gotClientSecret string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatalf("failed to parse form: %v", err)
		}
		gotAuthHeader = r.Header.Get("Authorization")
		gotClientID = r.PostForm.Get("client_id")
		gotClientSecret = r.PostForm.Get("client_secret")

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "password-post-token-xyz",
			"token_type":   "Bearer",
			"expires_in":   300,
		})
	}))
	defer server.Close()

	params := passwordGrantParams()
	params["tokenEndpoint"] = server.URL
	params["clientAuthMethod"] = ClientAuthMethodPost
	params["redis"] = map[string]interface{}{"host": "127.0.0.1", "port": 1}

	p, err := GetPolicy(policy.PolicyMetadata{}, params)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	pol := p.(*Policy)

	reqCtx := newRequestHeaderCtx()
	action := pol.OnRequestHeaders(context.Background(), reqCtx, nil)
	mods, ok := action.(policy.UpstreamRequestHeaderModifications)
	if !ok {
		t.Fatalf("expected UpstreamRequestHeaderModifications, got %T", action)
	}
	if mods.HeadersToSet["Authorization"] != "Bearer password-post-token-xyz" {
		t.Errorf("unexpected Authorization header: %q", mods.HeadersToSet["Authorization"])
	}

	if gotAuthHeader != "" {
		t.Errorf("expected no Basic auth header with client_secret_post, got %q", gotAuthHeader)
	}
	if gotClientID != "gateway-client" {
		t.Errorf("expected client_id=gateway-client in form body, got %q", gotClientID)
	}
	if gotClientSecret != "s3cr3t" {
		t.Errorf("expected client_secret=s3cr3t in form body, got %q", gotClientSecret)
	}
}

// ─── password grant (RFC 6749 Section 4.3) ──────────────────────────────────

func passwordGrantParams() map[string]interface{} {
	return map[string]interface{}{
		"grantType":     GrantTypePassword,
		"tokenEndpoint": "https://idp.example.com/oauth2/token",
		"clientId":      "gateway-client",
		"clientSecret":  "s3cr3t",
		"username":      "resource-owner",
		"password":      "hunter2",
	}
}

func TestGetPolicy_PasswordGrant_ValidParams(t *testing.T) {
	p, err := GetPolicy(policy.PolicyMetadata{}, passwordGrantParams())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	pol := p.(*Policy)
	if pol.grantType != GrantTypePassword {
		t.Errorf("unexpected grantType: %q", pol.grantType)
	}
}

func TestGetPolicy_PasswordGrant_MissingUsername(t *testing.T) {
	params := passwordGrantParams()
	delete(params, "username")
	_, err := GetPolicy(policy.PolicyMetadata{}, params)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "username") {
		t.Errorf("expected error to mention username, got: %v", err)
	}
}

func TestGetPolicy_PasswordGrant_MissingPassword(t *testing.T) {
	params := passwordGrantParams()
	delete(params, "password")
	_, err := GetPolicy(policy.PolicyMetadata{}, params)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "password") {
		t.Errorf("expected error to mention password, got: %v", err)
	}
}

func TestGetPolicy_ClientCredentials_UsernamePasswordNotRequired(t *testing.T) {
	// username/password are password-grant-only; client_credentials (the
	// default grantType) must not require them.
	params := validParams()
	if _, ok := params["username"]; ok {
		t.Fatal("test fixture unexpectedly sets username")
	}
	_, err := GetPolicy(policy.PolicyMetadata{}, params)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// Exercises the real password-grant token-fetch path end to end against an httptest server.
func TestPasswordGrant_EndToEnd(t *testing.T) {
	var gotGrantType, gotUsername, gotPassword string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatalf("failed to parse form: %v", err)
		}
		gotGrantType = r.PostForm.Get("grant_type")
		gotUsername = r.PostForm.Get("username")
		gotPassword = r.PostForm.Get("password")

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "password-grant-token-abc",
			"token_type":   "Bearer",
			"expires_in":   300,
		})
	}))
	defer server.Close()

	params := passwordGrantParams()
	params["tokenEndpoint"] = server.URL
	params["username"] = "resource-owner"
	params["password"] = "hunter2"
	// Pin Redis to an unreachable address so this test can't silently read back a stray local Redis's cached token.
	params["redis"] = map[string]interface{}{"host": "127.0.0.1", "port": 1}

	p, err := GetPolicy(policy.PolicyMetadata{}, params)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	pol := p.(*Policy)

	reqCtx := newRequestHeaderCtx()
	action := pol.OnRequestHeaders(context.Background(), reqCtx, nil)
	mods, ok := action.(policy.UpstreamRequestHeaderModifications)
	if !ok {
		t.Fatalf("expected UpstreamRequestHeaderModifications, got %T", action)
	}
	if mods.HeadersToSet["Authorization"] != "Bearer password-grant-token-abc" {
		t.Errorf("unexpected Authorization header: %q", mods.HeadersToSet["Authorization"])
	}

	if gotGrantType != "password" {
		t.Errorf("expected token endpoint to receive grant_type=password, got %q", gotGrantType)
	}
	if gotUsername != "resource-owner" {
		t.Errorf("expected username=resource-owner, got %q", gotUsername)
	}
	if gotPassword != "hunter2" {
		t.Errorf("expected password=hunter2, got %q", gotPassword)
	}
}

func TestGetPolicy_MissingRequiredParams(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(map[string]interface{})
		wantErr string
	}{
		{
			name:    "missing tokenEndpoint",
			mutate:  func(p map[string]interface{}) { delete(p, "tokenEndpoint") },
			wantErr: "'tokenEndpoint' parameter is required",
		},
		{
			name:    "missing clientId",
			mutate:  func(p map[string]interface{}) { delete(p, "clientId") },
			wantErr: "'clientId' parameter is required",
		},
		{
			name:    "missing clientSecret",
			mutate:  func(p map[string]interface{}) { delete(p, "clientSecret") },
			wantErr: "'clientSecret' parameter is required",
		},
		{
			name:    "empty tokenEndpoint",
			mutate:  func(p map[string]interface{}) { p["tokenEndpoint"] = "   " },
			wantErr: "'tokenEndpoint' cannot be empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			params := validParams()
			tt.mutate(params)
			_, err := GetPolicy(policy.PolicyMetadata{}, params)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error %q does not contain %q", err.Error(), tt.wantErr)
			}
		})
	}
}

// ─── auth path selection (token vs tokenEndpoint/clientId/clientSecret) ─────

func TestGetPolicy_NeitherAuthPathConfigured(t *testing.T) {
	_, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{})
	if err == nil {
		t.Fatal("expected error when neither 'bearerToken' nor the token-endpoint fields are configured")
	}
	if !strings.Contains(err.Error(), "'bearerToken'") || !strings.Contains(err.Error(), "tokenEndpoint") {
		t.Errorf("expected error to mention both auth paths, got: %v", err)
	}
}

func TestGetPolicy_BothAuthPathsConfigured(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(map[string]interface{})
	}{
		{"bearerToken plus full token-endpoint block", func(p map[string]interface{}) { p["bearerToken"] = "static-abc123" }},
		{"bearerToken plus clientId only", func(p map[string]interface{}) {
			p["bearerToken"] = "static-abc123"
			delete(p, "tokenEndpoint")
			delete(p, "clientSecret")
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			params := validParams()
			tt.mutate(params)
			_, err := GetPolicy(policy.PolicyMetadata{}, params)
			if err == nil {
				t.Fatal("expected error when both auth paths are configured, got nil")
			}
			if !strings.Contains(err.Error(), "cannot be combined") {
				t.Errorf("expected a mutual-exclusion error, got: %v", err)
			}
		})
	}
}

func TestGetPolicy_StaticToken_ValidParams(t *testing.T) {
	p, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{"bearerToken": "static-abc123"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	oa := p.(*Policy)
	if oa.mode != ModeStaticToken {
		t.Errorf("expected mode %q, got %q", ModeStaticToken, oa.mode)
	}
	if len(oa.purgeStatusCodes) != 0 {
		t.Errorf("expected purgeStatusCodes to be forced empty for the static-token path, got %v", oa.purgeStatusCodes)
	}
	tok, err := oa.tokenFunc(context.Background())
	if err != nil {
		t.Fatalf("unexpected error fetching the static token: %v", err)
	}
	if tok.AccessToken != "static-abc123" {
		t.Errorf("expected the configured token to be returned as-is, got %q", tok.AccessToken)
	}
}

func TestGetPolicy_StaticToken_OnRequestHeaders_EndToEnd(t *testing.T) {
	// Unlike the token-endpoint path, this never spins up an httptest server -
	// there is nothing to call; the configured value is injected as-is.
	p, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{"bearerToken": "static-abc123"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	oa := p.(*Policy)

	reqCtx := newRequestHeaderCtx()
	action := oa.OnRequestHeaders(context.Background(), reqCtx, nil)
	mods, ok := action.(policy.UpstreamRequestHeaderModifications)
	if !ok {
		t.Fatalf("expected UpstreamRequestHeaderModifications, got %T", action)
	}
	if got := mods.HeadersToSet["Authorization"]; got != "Bearer static-abc123" {
		t.Errorf("unexpected Authorization header: %q", got)
	}
	if reqCtx.SharedContext.AuthContext.AuthType != AuthTypeStaticToken {
		t.Errorf("expected AuthType %q, got %q", AuthTypeStaticToken, reqCtx.SharedContext.AuthContext.AuthType)
	}
}

func TestGetPolicy_StaticToken_Mode_SkipsResponseHeaders(t *testing.T) {
	// tokenPurgeStatusCodes has no effect on the static-token path - there is
	// no fresher token to fetch on a rejection - so response-header
	// processing must stay off even if it's explicitly configured.
	p, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{
		"bearerToken":           "static-abc123",
		"tokenPurgeStatusCodes": []interface{}{401},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	mode := p.(*Policy).Mode()
	if mode.ResponseHeaderMode != policy.HeaderModeSkip {
		t.Errorf("expected response header processing to stay off for the static-token path, got %v", mode.ResponseHeaderMode)
	}
}

// ─── headerName / valuePrefix ────────────────────────────────────────────────

func TestGetPolicy_HeaderName_DefaultsToAuthorization(t *testing.T) {
	p, err := GetPolicy(policy.PolicyMetadata{}, validParams())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if oa := p.(*Policy); oa.headerName != "Authorization" {
		t.Errorf("expected headerName to default to %q, got %q", "Authorization", oa.headerName)
	}
}

func TestGetPolicy_ValuePrefix_DefaultsToBearer(t *testing.T) {
	p, err := GetPolicy(policy.PolicyMetadata{}, validParams())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if oa := p.(*Policy); oa.valuePrefix != "Bearer" {
		t.Errorf("expected valuePrefix to default to %q, got %q", "Bearer", oa.valuePrefix)
	}
}

func TestOnRequestHeaders_CustomHeaderNameAndPrefix(t *testing.T) {
	p, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{
		"bearerToken": "static-abc123",
		"headerName":  "X-Api-Token",
		"valuePrefix": "Token",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	oa := p.(*Policy)

	reqCtx := newRequestHeaderCtx()
	action := oa.OnRequestHeaders(context.Background(), reqCtx, nil)
	mods := action.(policy.UpstreamRequestHeaderModifications)

	if _, hasAuth := mods.HeadersToSet["Authorization"]; hasAuth {
		t.Error("expected no Authorization header when headerName is overridden")
	}
	if got := mods.HeadersToSet["X-Api-Token"]; got != "Token static-abc123" {
		t.Errorf("unexpected X-Api-Token header: %q", got)
	}
}

func TestOnRequestHeaders_EmptyValuePrefix_NoScheme(t *testing.T) {
	// An explicitly empty valuePrefix must be honored as "no prefix" rather
	// than silently reverting to the "Bearer" default - see
	// getStringParamOrDefault.
	p, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{
		"bearerToken": "static-abc123",
		"valuePrefix": "",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	oa := p.(*Policy)
	if oa.valuePrefix != "" {
		t.Fatalf("expected valuePrefix to stay empty, got %q", oa.valuePrefix)
	}

	reqCtx := newRequestHeaderCtx()
	action := oa.OnRequestHeaders(context.Background(), reqCtx, nil)
	mods := action.(policy.UpstreamRequestHeaderModifications)
	if got := mods.HeadersToSet["Authorization"]; got != "static-abc123" {
		t.Errorf("expected the raw credential with no scheme prefix, got %q", got)
	}
}

func TestGetStringMapParam(t *testing.T) {
	tests := []struct {
		name   string
		params map[string]interface{}
		want   map[string]string
	}{
		{
			name:   "absent",
			params: map[string]interface{}{},
			want:   nil,
		},
		{
			name:   "wrong type",
			params: map[string]interface{}{"tokenRequestParams": "scope=read"},
			want:   nil,
		},
		{
			name:   "single string value",
			params: map[string]interface{}{"tokenRequestParams": map[string]interface{}{"scope": "read write"}},
			want:   map[string]string{"scope": "read write"},
		},
		{
			name: "multiple values, trimmed",
			params: map[string]interface{}{"tokenRequestParams": map[string]interface{}{
				"scope":    "  read write  ",
				"resource": "https://api.example.com",
			}},
			want: map[string]string{
				"scope":    "read write",
				"resource": "https://api.example.com",
			},
		},
		{
			name:   "non-string value dropped",
			params: map[string]interface{}{"tokenRequestParams": map[string]interface{}{"scope": 123}},
			want:   nil,
		},
		{
			name:   "blank value dropped",
			params: map[string]interface{}{"tokenRequestParams": map[string]interface{}{"scope": "   "}},
			want:   nil,
		},
		{
			name:   "empty map",
			params: map[string]interface{}{"tokenRequestParams": map[string]interface{}{}},
			want:   nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := getStringMapParam(tt.params, "tokenRequestParams")
			if len(got) != len(tt.want) {
				t.Fatalf("got %#v, want %#v", got, tt.want)
			}
			for k, v := range tt.want {
				if got[k] != v {
					t.Errorf("key %q: got %q, want %q", k, got[k], v)
				}
			}
		})
	}
}

func TestGetPurgeStatusCodesParam(t *testing.T) {
	def := []int{401}
	tests := []struct {
		name   string
		params map[string]interface{}
		want   map[int]struct{}
	}{
		{
			name:   "absent falls back to default",
			params: map[string]interface{}{},
			want:   map[int]struct{}{401: {}},
		},
		{
			name:   "wrong type falls back to default",
			params: map[string]interface{}{"tokenPurgeStatusCodes": "401"},
			want:   map[int]struct{}{401: {}},
		},
		{
			name:   "custom list",
			params: map[string]interface{}{"tokenPurgeStatusCodes": []interface{}{401, 403}},
			want:   map[int]struct{}{401: {}, 403: {}},
		},
		{
			// An explicit empty list is honored as-is (disabling purging),
			// unlike an absent key - it must NOT fall back to the default.
			name:   "explicit empty list disables rather than falling back",
			params: map[string]interface{}{"tokenPurgeStatusCodes": []interface{}{}},
			want:   map[int]struct{}{},
		},
		{
			name:   "float64 and numeric-string entries coerced",
			params: map[string]interface{}{"tokenPurgeStatusCodes": []interface{}{float64(401), "403"}},
			want:   map[int]struct{}{401: {}, 403: {}},
		},
		{
			name:   "non-numeric string entries dropped",
			params: map[string]interface{}{"tokenPurgeStatusCodes": []interface{}{401, "not-a-code"}},
			want:   map[int]struct{}{401: {}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := getPurgeStatusCodesParam(tt.params, "tokenPurgeStatusCodes", def)
			if len(got) != len(tt.want) {
				t.Fatalf("got %#v, want %#v", got, tt.want)
			}
			for k := range tt.want {
				if _, ok := got[k]; !ok {
					t.Errorf("missing expected code %d in %#v", k, got)
				}
			}
		})
	}
}

func TestGetPolicy_ParamsIsOptional(t *testing.T) {
	params := validParams()
	params["tokenRequestParams"] = map[string]interface{}{"scope": "chat.completions embeddings"}
	p, err := GetPolicy(policy.PolicyMetadata{}, params)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	_ = p
}

func TestClientCredentials_EndToEnd_ParamsReachTokenEndpoint(t *testing.T) {
	var gotScope, gotResource string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatalf("failed to parse form: %v", err)
		}
		gotScope = r.PostForm.Get("scope")
		gotResource = r.PostForm.Get("resource")

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "cc-grant-token-xyz",
			"token_type":   "Bearer",
			"expires_in":   300,
		})
	}))
	defer server.Close()

	params := validParams()
	params["tokenEndpoint"] = server.URL
	params["tokenRequestParams"] = map[string]interface{}{
		"scope":    "read write",
		"resource": "https://api.example.com",
	}
	// Redis pinned unreachable - see TestPasswordGrant_EndToEnd.
	params["redis"] = map[string]interface{}{"host": "127.0.0.1", "port": 1}

	p, err := GetPolicy(policy.PolicyMetadata{}, params)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	pol := p.(*Policy)

	reqCtx := newRequestHeaderCtx()
	action := pol.OnRequestHeaders(context.Background(), reqCtx, nil)
	mods, ok := action.(policy.UpstreamRequestHeaderModifications)
	if !ok {
		t.Fatalf("expected UpstreamRequestHeaderModifications, got %T", action)
	}
	if mods.HeadersToSet["Authorization"] != "Bearer cc-grant-token-xyz" {
		t.Errorf("unexpected Authorization header: %q", mods.HeadersToSet["Authorization"])
	}

	if gotScope != "read write" {
		t.Errorf("expected token endpoint to receive scope=%q, got %q", "read write", gotScope)
	}
	if gotResource != "https://api.example.com" {
		t.Errorf("expected token endpoint to receive resource=%q, got %q", "https://api.example.com", gotResource)
	}
}

// ─── doTokenRequest / tokenRequestHeaders ────────────────────────────────────

func TestDoTokenRequest_AddsConfiguredHeaders(t *testing.T) {
	var got string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("X-Api-Key")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"access_token": "tok", "token_type": "Bearer"})
	}))
	defer server.Close()

	form := url.Values{"grant_type": {GrantTypeClientCredentials}}
	if _, err := doTokenRequest(context.Background(), server.Client(), server.URL, authStyleInHeader,
		"id", "secret", form, map[string]string{"X-Api-Key": "secret-123"}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "secret-123" {
		t.Errorf("expected X-Api-Key header to reach the token endpoint, got %q", got)
	}
}

// tokenRequestHeaders must not override Authorization/Content-Type, or it could break client_secret_basic or corrupt the body.
func TestDoTokenRequest_IgnoresAuthorizationAndContentTypeOverrides(t *testing.T) {
	var gotAuth, gotContentType, gotAllowed string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotContentType = r.Header.Get("Content-Type")
		gotAllowed = r.Header.Get("X-Allowed")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"access_token": "tok", "token_type": "Bearer"})
	}))
	defer server.Close()

	form := url.Values{"grant_type": {GrantTypeClientCredentials}}
	if _, err := doTokenRequest(context.Background(), server.Client(), server.URL, authStyleInHeader,
		"real-id", "real-secret", form, map[string]string{
			"Authorization": "Bearer should-not-apply",
			"Content-Type":  "application/json",
			"X-Allowed":     "yes",
		}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.HasPrefix(gotAuth, "Basic ") {
		t.Errorf("expected the real client_secret_basic Authorization header to survive, got %q", gotAuth)
	}
	if gotContentType != "application/x-www-form-urlencoded" {
		t.Errorf("expected the real Content-Type to survive, got %q", gotContentType)
	}
	if gotAllowed != "yes" {
		t.Errorf("expected a non-reserved header to still be applied, got %q", gotAllowed)
	}
}

// Proves tokenRequestHeaders reaches the real token-endpoint call through GetPolicy/buildTokenSource.
func TestClientCredentials_EndToEnd_HeadersReachTokenEndpoint(t *testing.T) {
	var gotHeader string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeader = r.Header.Get("Ocp-Apim-Subscription-Key")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "header-test-token",
			"token_type":   "Bearer",
			"expires_in":   300,
		})
	}))
	defer server.Close()

	params := validParams()
	params["tokenEndpoint"] = server.URL
	params["tokenRequestHeaders"] = map[string]interface{}{"Ocp-Apim-Subscription-Key": "abc-123"}
	params["redis"] = map[string]interface{}{"host": "127.0.0.1", "port": 1}

	p, err := GetPolicy(policy.PolicyMetadata{}, params)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	pol := p.(*Policy)

	reqCtx := newRequestHeaderCtx()
	action := pol.OnRequestHeaders(context.Background(), reqCtx, nil)
	mods, ok := action.(policy.UpstreamRequestHeaderModifications)
	if !ok {
		t.Fatalf("expected UpstreamRequestHeaderModifications, got %T", action)
	}
	if mods.HeadersToSet["Authorization"] != "Bearer header-test-token" {
		t.Errorf("unexpected Authorization header: %q", mods.HeadersToSet["Authorization"])
	}
	if gotHeader != "abc-123" {
		t.Errorf("expected the token endpoint to receive Ocp-Apim-Subscription-Key=%q, got %q", "abc-123", gotHeader)
	}
}

// tokenRequestParams.scope must be honored for the password grant too.
func TestPasswordGrant_ScopeReachesTokenEndpoint(t *testing.T) {
	var gotScope string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatalf("failed to parse form: %v", err)
		}
		gotScope = r.PostForm.Get("scope")

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "password-grant-token-with-scope",
			"token_type":   "Bearer",
			"expires_in":   300,
		})
	}))
	defer server.Close()

	params := passwordGrantParams()
	params["tokenEndpoint"] = server.URL
	params["username"] = "resource-owner"
	params["password"] = "hunter2"
	params["tokenRequestParams"] = map[string]interface{}{"scope": "profile email"}
	params["redis"] = map[string]interface{}{"host": "127.0.0.1", "port": 1}

	p, err := GetPolicy(policy.PolicyMetadata{}, params)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	pol := p.(*Policy)

	reqCtx := newRequestHeaderCtx()
	action := pol.OnRequestHeaders(context.Background(), reqCtx, nil)
	mods, ok := action.(policy.UpstreamRequestHeaderModifications)
	if !ok {
		t.Fatalf("expected UpstreamRequestHeaderModifications, got %T", action)
	}
	if mods.HeadersToSet["Authorization"] != "Bearer password-grant-token-with-scope" {
		t.Errorf("unexpected Authorization header: %q", mods.HeadersToSet["Authorization"])
	}
	if gotScope != "profile email" {
		t.Errorf("expected token endpoint to receive scope=%q, got %q", "profile email", gotScope)
	}
}

// A non-"scope" tokenRequestParams entry (e.g. an IdP-specific "resource") must also reach the password grant.
func TestPasswordGrant_NonScopeParamsReachTokenEndpoint(t *testing.T) {
	var gotResource string
	var sawResourceKey bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatalf("failed to parse form: %v", err)
		}
		_, sawResourceKey = r.PostForm["resource"]
		gotResource = r.PostForm.Get("resource")

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "password-grant-token-with-resource",
			"token_type":   "Bearer",
			"expires_in":   300,
		})
	}))
	defer server.Close()

	params := passwordGrantParams()
	params["tokenEndpoint"] = server.URL
	params["username"] = "resource-owner"
	params["password"] = "hunter2"
	params["tokenRequestParams"] = map[string]interface{}{"resource": "https://api.example.com"}
	params["redis"] = map[string]interface{}{"host": "127.0.0.1", "port": 1}

	p, err := GetPolicy(policy.PolicyMetadata{}, params)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	pol := p.(*Policy)

	reqCtx := newRequestHeaderCtx()
	action := pol.OnRequestHeaders(context.Background(), reqCtx, nil)
	mods, ok := action.(policy.UpstreamRequestHeaderModifications)
	if !ok {
		t.Fatalf("expected UpstreamRequestHeaderModifications, got %T", action)
	}
	if mods.HeadersToSet["Authorization"] != "Bearer password-grant-token-with-resource" {
		t.Errorf("unexpected Authorization header: %q", mods.HeadersToSet["Authorization"])
	}
	if !sawResourceKey || gotResource != "https://api.example.com" {
		t.Errorf("expected resource=%q to reach the token endpoint for the password grant, got present=%v value=%q",
			"https://api.example.com", sawResourceKey, gotResource)
	}
}

// A same-named tokenRequestParams entry must never override the real grant_type/username/password.
func TestPasswordGrant_TokenRequestParamsCannotOverrideCredentials(t *testing.T) {
	var gotGrantType, gotUsername, gotPassword string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatalf("failed to parse form: %v", err)
		}
		gotGrantType = r.PostForm.Get("grant_type")
		gotUsername = r.PostForm.Get("username")
		gotPassword = r.PostForm.Get("password")

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "password-grant-token-not-overridden",
			"token_type":   "Bearer",
			"expires_in":   300,
		})
	}))
	defer server.Close()

	params := passwordGrantParams()
	params["tokenEndpoint"] = server.URL
	params["username"] = "resource-owner"
	params["password"] = "hunter2"
	params["tokenRequestParams"] = map[string]interface{}{
		"grant_type": "client_credentials",
		"username":   "attacker",
		"password":   "attacker-controlled",
	}
	params["redis"] = map[string]interface{}{"host": "127.0.0.1", "port": 1}

	p, err := GetPolicy(policy.PolicyMetadata{}, params)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	pol := p.(*Policy)

	reqCtx := newRequestHeaderCtx()
	action := pol.OnRequestHeaders(context.Background(), reqCtx, nil)
	mods, ok := action.(policy.UpstreamRequestHeaderModifications)
	if !ok {
		t.Fatalf("expected UpstreamRequestHeaderModifications, got %T", action)
	}
	if mods.HeadersToSet["Authorization"] != "Bearer password-grant-token-not-overridden" {
		t.Errorf("unexpected Authorization header: %q", mods.HeadersToSet["Authorization"])
	}
	if gotGrantType != GrantTypePassword {
		t.Errorf("expected grant_type=%q to survive, got %q", GrantTypePassword, gotGrantType)
	}
	if gotUsername != "resource-owner" {
		t.Errorf("expected username=%q to survive, got %q", "resource-owner", gotUsername)
	}
	if gotPassword != "hunter2" {
		t.Errorf("expected password=%q to survive, got %q", "hunter2", gotPassword)
	}
}

// ─── Mode ────────────────────────────────────────────────────────────────────

// A nil/empty purgeStatusCodes must skip response-phase processing entirely.
func TestMode(t *testing.T) {
	p := newTestPolicy()
	mode := p.Mode()
	if mode.RequestHeaderMode != policy.HeaderModeProcess {
		t.Errorf("expected RequestHeaderMode PROCESS, got %v", mode.RequestHeaderMode)
	}
	if mode.RequestBodyMode != policy.BodyModeSkip {
		t.Errorf("expected RequestBodyMode SKIP (no body needed to inject a bearer token), got %v", mode.RequestBodyMode)
	}
	if mode.ResponseHeaderMode != policy.HeaderModeSkip || mode.ResponseBodyMode != policy.BodyModeSkip {
		t.Errorf("expected response phase to be skipped entirely")
	}
}

// A non-empty purgeStatusCodes must turn on response-header processing, but never the response body.
func TestMode_PurgeEnabled_ProcessesResponseHeadersOnly(t *testing.T) {
	p := newTestPolicy()
	p.purgeStatusCodes = map[int]struct{}{http.StatusUnauthorized: {}}
	mode := p.Mode()
	if mode.ResponseHeaderMode != policy.HeaderModeProcess {
		t.Errorf("expected ResponseHeaderMode PROCESS when purgeStatusCodes is non-empty, got %v", mode.ResponseHeaderMode)
	}
	if mode.ResponseBodyMode != policy.BodyModeSkip {
		t.Errorf("expected ResponseBodyMode SKIP - purging only needs the status code, got %v", mode.ResponseBodyMode)
	}
}

// ─── OnResponseHeaders ───────────────────────────────────────────────────────

func TestOnResponseHeaders_PurgesOnConfiguredStatus(t *testing.T) {
	fake := &fakeTokenSource{}
	p := newTestPolicy()
	p.tokenSource = fake
	p.purgeStatusCodes = map[int]struct{}{http.StatusUnauthorized: {}}

	action := p.OnResponseHeaders(context.Background(), newResponseHeaderCtx(http.StatusUnauthorized), nil)

	if _, ok := action.(policy.DownstreamResponseHeaderModifications); !ok {
		t.Fatalf("expected DownstreamResponseHeaderModifications (pass-through), got %T", action)
	}
	if fake.purgeCalls != 1 {
		t.Errorf("expected exactly one Purge() call, got %d", fake.purgeCalls)
	}
}

func TestOnResponseHeaders_NoPurgeOnUnconfiguredStatus(t *testing.T) {
	fake := &fakeTokenSource{}
	p := newTestPolicy()
	p.tokenSource = fake
	p.purgeStatusCodes = map[int]struct{}{http.StatusUnauthorized: {}}

	// 403 (insufficient scope) is deliberately not purged by default - see
	// defaultPurgeStatusCodes.
	p.OnResponseHeaders(context.Background(), newResponseHeaderCtx(http.StatusForbidden), nil)

	if fake.purgeCalls != 0 {
		t.Errorf("expected no Purge() call for a status not in purgeStatusCodes, got %d", fake.purgeCalls)
	}
}

func TestOnResponseHeaders_NoPurgeOnSuccess(t *testing.T) {
	fake := &fakeTokenSource{}
	p := newTestPolicy()
	p.tokenSource = fake
	p.purgeStatusCodes = map[int]struct{}{http.StatusUnauthorized: {}}

	p.OnResponseHeaders(context.Background(), newResponseHeaderCtx(http.StatusOK), nil)

	if fake.purgeCalls != 0 {
		t.Errorf("expected no Purge() call on a successful response, got %d", fake.purgeCalls)
	}
}

func TestOnResponseHeaders_DisabledWhenPurgeStatusCodesEmpty(t *testing.T) {
	fake := &fakeTokenSource{}
	p := newTestPolicy()
	p.tokenSource = fake
	p.purgeStatusCodes = map[int]struct{}{} // explicitly disabled

	p.OnResponseHeaders(context.Background(), newResponseHeaderCtx(http.StatusUnauthorized), nil)

	if fake.purgeCalls != 0 {
		t.Errorf("expected no Purge() call when purgeStatusCodes is empty, got %d", fake.purgeCalls)
	}
}

// Wires the real redisCachingTokenSource through a prime -> reuse -> upstream-401 -> purge -> refetch cycle.
func TestGetPolicy_PurgeOnUpstreamStatus_EndToEnd(t *testing.T) {
	var tokenCalls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenCalls++
		accessToken := "token-1"
		if tokenCalls > 1 {
			accessToken = "token-2"
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": accessToken,
			"token_type":   "Bearer",
			// 3600s, not the usual 300s fixture value - must clear defaultExpiryBuffer
			// (5m) with room to spare, or the cache-reuse assertion below is testing
			// nothing: a token expiring inside the buffer window is never "fresh".
			"expires_in": 3600,
		})
	}))
	defer server.Close()

	params := validParams()
	params["tokenEndpoint"] = server.URL
	// Redis pinned unreachable - see TestPasswordGrant_EndToEnd.
	params["redis"] = map[string]interface{}{"host": "127.0.0.1", "port": 1}

	p, err := GetPolicy(policy.PolicyMetadata{}, params)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	pol := p.(*Policy)

	firstAction := pol.OnRequestHeaders(context.Background(), newRequestHeaderCtx(), nil)
	firstMods, ok := firstAction.(policy.UpstreamRequestHeaderModifications)
	if !ok {
		t.Fatalf("expected UpstreamRequestHeaderModifications, got %T", firstAction)
	}
	if firstMods.HeadersToSet["Authorization"] != "Bearer token-1" {
		t.Fatalf("unexpected first Authorization header: %q", firstMods.HeadersToSet["Authorization"])
	}

	secondAction := pol.OnRequestHeaders(context.Background(), newRequestHeaderCtx(), nil)
	secondMods := secondAction.(policy.UpstreamRequestHeaderModifications)
	if secondMods.HeadersToSet["Authorization"] != "Bearer token-1" {
		t.Fatalf("expected the second request to reuse the cached token, got %q", secondMods.HeadersToSet["Authorization"])
	}
	if tokenCalls != 1 {
		t.Fatalf("expected exactly 1 token-endpoint call before the purge, got %d", tokenCalls)
	}

	respAction := pol.OnResponseHeaders(context.Background(), newResponseHeaderCtx(http.StatusUnauthorized), nil)
	if _, ok := respAction.(policy.DownstreamResponseHeaderModifications); !ok {
		t.Fatalf("expected DownstreamResponseHeaderModifications, got %T", respAction)
	}

	thirdAction := pol.OnRequestHeaders(context.Background(), newRequestHeaderCtx(), nil)
	thirdMods := thirdAction.(policy.UpstreamRequestHeaderModifications)
	if thirdMods.HeadersToSet["Authorization"] != "Bearer token-2" {
		t.Errorf("expected a fresh token after the purge, got %q", thirdMods.HeadersToSet["Authorization"])
	}
	if tokenCalls != 2 {
		t.Errorf("expected exactly 2 token-endpoint calls total (initial + post-purge), got %d", tokenCalls)
	}
}

// ─── OnRequestHeaders ────────────────────────────────────────────────────────

func TestOnRequestHeaders_Success(t *testing.T) {
	p := newTestPolicy()
	var calls int
	p.tokenFunc = func(context.Context) (*Token, error) {
		calls++
		return &Token{AccessToken: "abc123", TokenType: "Bearer"}, nil
	}

	reqCtx := newRequestHeaderCtx()
	action := p.OnRequestHeaders(context.Background(), reqCtx, nil)

	mods, ok := action.(policy.UpstreamRequestHeaderModifications)
	if !ok {
		t.Fatalf("expected UpstreamRequestHeaderModifications, got %T", action)
	}
	if got := mods.HeadersToSet["Authorization"]; got != "Bearer abc123" {
		t.Errorf("unexpected Authorization header: %q", got)
	}
	if calls != 1 {
		t.Errorf("expected exactly one token fetch, got %d", calls)
	}

	if reqCtx.SharedContext.AuthContext == nil {
		t.Fatal("expected AuthContext to be set")
	}
	if !reqCtx.SharedContext.AuthContext.Authenticated {
		t.Error("expected Authenticated=true on success")
	}
	if reqCtx.SharedContext.AuthContext.AuthType != AuthType {
		t.Errorf("unexpected AuthType: %q", reqCtx.SharedContext.AuthContext.AuthType)
	}
	if reqCtx.SharedContext.AuthContext.CredentialID != "gateway-client" {
		t.Errorf("unexpected CredentialID: %q", reqCtx.SharedContext.AuthContext.CredentialID)
	}
}

// Proves OnRequestHeaders calls through tokenFunc once per request, not more.
func TestOnRequestHeaders_ReusesCachedToken(t *testing.T) {
	p := newTestPolicy()
	var calls int
	p.tokenFunc = func(context.Context) (*Token, error) {
		calls++
		return &Token{AccessToken: "reused-token"}, nil
	}

	for i := 0; i < 3; i++ {
		action := p.OnRequestHeaders(context.Background(), newRequestHeaderCtx(), nil)
		mods := action.(policy.UpstreamRequestHeaderModifications)
		if mods.HeadersToSet["Authorization"] != "Bearer reused-token" {
			t.Fatalf("request %d: unexpected Authorization header", i)
		}
	}
	if calls != 3 {
		t.Errorf("expected tokenFunc called once per request (3), got %d", calls)
	}
}

func TestOnRequestHeaders_TokenFetchFailure(t *testing.T) {
	p := newTestPolicy()
	p.tokenFunc = func(context.Context) (*Token, error) {
		return nil, errors.New("token endpoint returned invalid_client")
	}

	reqCtx := newRequestHeaderCtx()
	action := p.OnRequestHeaders(context.Background(), reqCtx, nil)

	resp, ok := action.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("expected ImmediateResponse on failure, got %T", action)
	}
	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("expected 502 Bad Gateway, got %d", resp.StatusCode)
	}
	if strings.Contains(string(resp.Body), "invalid_client") {
		t.Error("response body must not leak the underlying token-endpoint error detail")
	}
	if !strings.Contains(string(resp.Body), "failed to authenticate request to upstream service") {
		t.Errorf("expected generic failure message in body, got %q", resp.Body)
	}

	if reqCtx.SharedContext.AuthContext == nil || reqCtx.SharedContext.AuthContext.Authenticated {
		t.Error("expected AuthContext.Authenticated=false on failure")
	}
}

func TestOnRequestHeaders_PreservesPreviousAuthContext(t *testing.T) {
	p := newTestPolicy()
	p.tokenFunc = func(context.Context) (*Token, error) {
		return &Token{AccessToken: "abc123"}, nil
	}

	reqCtx := newRequestHeaderCtx()
	reqCtx.SharedContext.AuthContext = &policy.AuthContext{
		Authenticated: true,
		AuthType:      "jwt",
		Subject:       "end-user-123",
	}

	p.OnRequestHeaders(context.Background(), reqCtx, nil)

	got := reqCtx.SharedContext.AuthContext
	if got.AuthType != AuthType {
		t.Errorf("expected current AuthType %q, got %q", AuthType, got.AuthType)
	}
	if got.Previous == nil || got.Previous.AuthType != "jwt" || got.Previous.Subject != "end-user-123" {
		t.Fatal("expected the prior inbound auth context to be preserved via Previous")
	}
}

// ─── buildTokenEndpointTransport ─────────────────────────────────────────────

// generateTestCACert returns a throwaway self-signed cert's PEM content directly - tlsCaCert holds content, not a path.
func generateTestCACert(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate test key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "oauth2-generator-test-ca"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IsCA:         true,
		KeyUsage:     x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("failed to create test certificate: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func TestBuildTokenEndpointTransport_DefaultsToProxyFromEnvironment(t *testing.T) {
	transport, err := buildTokenEndpointTransport(oauth2Params{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if transport.Proxy == nil {
		t.Fatal("expected a default Proxy func (http.ProxyFromEnvironment) to always be set")
	}
	if transport.TLSClientConfig != nil {
		t.Errorf("expected no TLSClientConfig when neither tlsCaCert nor tlsInsecureSkipVerify is set, got %+v", transport.TLSClientConfig)
	}
}

func TestBuildTokenEndpointTransport_ExplicitProxyURLOverridesEnvironment(t *testing.T) {
	transport, err := buildTokenEndpointTransport(oauth2Params{proxyURL: "http://proxy.internal:8080"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://idp.example.com/token", nil)
	if err != nil {
		t.Fatalf("unexpected error building the probe request: %v", err)
	}
	got, err := transport.Proxy(req)
	if err != nil {
		t.Fatalf("unexpected error resolving proxy: %v", err)
	}
	if got == nil || got.Host != "proxy.internal:8080" {
		t.Errorf("expected the configured proxyURL to be used, got %v", got)
	}
}

func TestBuildTokenEndpointTransport_InvalidProxyURL(t *testing.T) {
	if _, err := buildTokenEndpointTransport(oauth2Params{proxyURL: "://not-a-valid-url"}); err == nil {
		t.Fatal("expected an error for an invalid proxyURL")
	}
}

// A malformed-but-credentialed proxyURL must never leak its userinfo into the returned error - see redactURLCredentials.
func TestBuildTokenEndpointTransport_InvalidProxyURL_DoesNotLeakCredentials(t *testing.T) {
	// A control character makes url.Parse fail while the credential-bearing userinfo is still present.
	_, err := buildTokenEndpointTransport(oauth2Params{proxyURL: "http://secret-user:secret-pass@proxy.internal:8080/\x7f"})
	if err == nil {
		t.Fatal("expected an error for an invalid proxyURL")
	}
	if strings.Contains(err.Error(), "secret-user") || strings.Contains(err.Error(), "secret-pass") {
		t.Errorf("expected proxyURL credentials to be redacted from the error, got: %v", err)
	}
	if !strings.Contains(err.Error(), "[REDACTED]") {
		t.Errorf("expected a [REDACTED] marker in the error, got: %v", err)
	}
}

// ─── redactURLCredentials ────────────────────────────────────────────────────

func TestRedactURLCredentials(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"no url", "just a plain error message", "just a plain error message"},
		{"url with no credentials", "dial tcp proxy.internal:8080: connection refused", "dial tcp proxy.internal:8080: connection refused"},
		{
			"credentials embedded in a wrapped parse error",
			`parse "http://user:pass@proxy.internal:8080/x": net/url: invalid control character in URL`,
			`parse "http://[REDACTED]@proxy.internal:8080/x": net/url: invalid control character in URL`,
		},
		{"bare credentialed url", "https://alice:s3cr3t@idp.example.com/token", "https://[REDACTED]@idp.example.com/token"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := redactURLCredentials(tt.in); got != tt.want {
				t.Errorf("redactURLCredentials(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

// ─── sanitizeEndpointForLogging ──────────────────────────────────────────────

func TestSanitizeEndpointForLogging(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"plain endpoint, nothing to strip", "https://idp.example.com/token", "https://idp.example.com/token"},
		{"query string stripped", "https://idp.example.com/token?api_key=s3cr3t&x=1", "https://idp.example.com/token"},
		{"embedded userinfo stripped", "https://alice:s3cr3t@idp.example.com/token", "https://idp.example.com/token"},
		{"fragment stripped", "https://idp.example.com/token#accessTokenAbc123", "https://idp.example.com/token"},
		{"userinfo and query both stripped", "https://alice:s3cr3t@idp.example.com/token?api_key=xyz", "https://idp.example.com/token"},
		{"not a URL at all", "not a url", "[unparsable-endpoint]"},
		{"empty string", "", "[unparsable-endpoint]"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := sanitizeEndpointForLogging(tt.in); got != tt.want {
				t.Errorf("sanitizeEndpointForLogging(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

// Proxy must still be set whenever TLSClientConfig is - jwt-auth/opaque-token-auth both silently dropped proxy support this way.
func TestBuildTokenEndpointTransport_TLSConfigStillSetsProxy(t *testing.T) {
	transport, err := buildTokenEndpointTransport(oauth2Params{tlsInsecureSkipVerify: true})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if transport.TLSClientConfig == nil || !transport.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("expected TLSClientConfig.InsecureSkipVerify to be true")
	}
	if transport.Proxy == nil {
		t.Fatal("expected Proxy to still be set even though a custom TLSClientConfig was built")
	}
}

func TestBuildTokenEndpointTransport_InvalidCACertContent(t *testing.T) {
	if _, err := buildTokenEndpointTransport(oauth2Params{tlsCaCert: "not a valid PEM certificate"}); err == nil {
		t.Fatal("expected an error for content with no valid PEM certificate in it")
	}
}

func TestBuildTokenEndpointTransport_ValidCACertContent(t *testing.T) {
	transport, err := buildTokenEndpointTransport(oauth2Params{tlsCaCert: generateTestCACert(t)})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if transport.TLSClientConfig == nil || transport.TLSClientConfig.RootCAs == nil {
		t.Fatal("expected RootCAs to be populated from the CA cert content")
	}
}

// tlsCaCert must support a bundle of several concatenated PEM certificates, not just the first.
func TestBuildTokenEndpointTransport_MultipleCACertsInOneValue(t *testing.T) {
	bundle := generateTestCACert(t) + generateTestCACert(t)
	pool, err := parseCACertPool(bundle)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(pool.Subjects()) != 2 { //nolint:staticcheck // Subjects() is deprecated but still the simplest way to assert count in a test
		t.Errorf("expected both concatenated certificates to be parsed into the pool, got %d", len(pool.Subjects()))
	}
}

// ─── getOrCreateTokenEndpointTransport CA cert keying ────────────────────────

// Two configs with different CA cert content must never share a cached Transport built from the wrong trust pool.
func TestGetOrCreateTokenEndpointTransport_DifferentCACertContent_GetsDifferentTransport(t *testing.T) {
	p1 := oauth2Params{tlsCaCert: generateTestCACert(t)}
	p2 := oauth2Params{tlsCaCert: generateTestCACert(t)}

	t1, err := getOrCreateTokenEndpointTransport(p1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	t2, err := getOrCreateTokenEndpointTransport(p2)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if t1 == t2 {
		t.Error("expected two configs with different CA cert content to get different *http.Transport values, not share one")
	}
}

// Byte-identical CA cert content must share one Transport, same as proxyURL already does.
func TestGetOrCreateTokenEndpointTransport_SameCACertContent_SharesTransport(t *testing.T) {
	cert := generateTestCACert(t)
	p1 := oauth2Params{tlsCaCert: cert}
	p2 := oauth2Params{tlsCaCert: cert}

	t1, err := getOrCreateTokenEndpointTransport(p1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	t2, err := getOrCreateTokenEndpointTransport(p2)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if t1 != t2 {
		t.Error("expected two configs with identical CA cert content to share one *http.Transport")
	}
}

func TestGetOrCreateTokenEndpointTransport_SharesTransportForIdenticalConfig(t *testing.T) {
	p1 := oauth2Params{proxyURL: "http://shared-proxy:8080"}
	p2 := oauth2Params{proxyURL: "http://shared-proxy:8080"}
	t1, err := getOrCreateTokenEndpointTransport(p1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	t2, err := getOrCreateTokenEndpointTransport(p2)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if t1 != t2 {
		t.Error("expected two configs with identical proxy/TLS settings to share one *http.Transport")
	}
}

// ─── isRetryableTokenError / retryBackoff ────────────────────────────────────

func TestIsRetryableTokenError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"plain network error", errors.New("dial tcp: connection refused"), true},
		{"429 too many requests", &TokenError{StatusCode: http.StatusTooManyRequests}, true},
		{"500 internal server error", &TokenError{StatusCode: http.StatusInternalServerError}, true},
		{"503 service unavailable", &TokenError{StatusCode: http.StatusServiceUnavailable}, true},
		{"400 invalid_request", &TokenError{StatusCode: http.StatusBadRequest, ErrorCode: "invalid_request"}, false},
		{"401 invalid_client", &TokenError{StatusCode: http.StatusUnauthorized, ErrorCode: "invalid_client"}, false},
		{"403 forbidden", &TokenError{StatusCode: http.StatusForbidden, ErrorCode: "access_denied"}, false},
		{"malformed JSON body", &nonRetryableTokenError{err: errors.New("decoding token response: unexpected EOF")}, false},
		{"missing access_token", &nonRetryableTokenError{err: errors.New("token endpoint response is missing access_token")}, false},
		{"wrapped nonRetryableTokenError", fmt.Errorf("doTokenRequest: %w", &nonRetryableTokenError{err: errors.New("missing access_token")}), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isRetryableTokenError(tt.err); got != tt.want {
				t.Errorf("isRetryableTokenError(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}

func TestRetryBackoff_WithinExpectedBounds(t *testing.T) {
	for attempt := 1; attempt <= 6; attempt++ {
		d := retryBackoff(attempt)
		if d < retryBaseDelay {
			t.Errorf("attempt %d: backoff %s below base delay %s", attempt, d, retryBaseDelay)
		}
		if d > retryMaxDelay+retryMaxDelay/2 {
			t.Errorf("attempt %d: backoff %s exceeds expected cap+jitter (%s)", attempt, d, retryMaxDelay+retryMaxDelay/2)
		}
	}
}

// ─── resilientTokenSource ────────────────────────────────────────────────────

// flakyTokenSource fails failTimes calls before succeeding with token - a test double for the retry path.
type flakyTokenSource struct {
	failTimes int
	calls     int
	token     *Token
	failErr   error
}

func (f *flakyTokenSource) Token(context.Context) (*Token, error) {
	f.calls++
	if f.calls <= f.failTimes {
		return nil, f.failErr
	}
	return f.token, nil
}

var errTransient = &TokenError{StatusCode: http.StatusServiceUnavailable}

func TestResilientTokenSource_RetriesTransientFailureThenSucceeds(t *testing.T) {
	inner := &flakyTokenSource{failTimes: 2, failErr: errTransient, token: &Token{AccessToken: "eventually-ok"}}
	src := &resilientTokenSource{inner: inner, maxRetries: 2}

	tok, err := src.Token(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tok.AccessToken != "eventually-ok" {
		t.Errorf("unexpected access token: %q", tok.AccessToken)
	}
	if inner.calls != 3 {
		t.Errorf("expected 3 total attempts (1 initial + 2 retries), got %d", inner.calls)
	}
}

func TestResilientTokenSource_GivesUpAfterMaxRetries(t *testing.T) {
	inner := &flakyTokenSource{failTimes: 100, failErr: errTransient}
	src := &resilientTokenSource{inner: inner, maxRetries: 2}

	if _, err := src.Token(context.Background()); err == nil {
		t.Fatal("expected an error after exhausting all retries")
	}
	if inner.calls != 3 {
		t.Errorf("expected exactly 3 attempts (1 initial + 2 retries), got %d", inner.calls)
	}
}

func TestResilientTokenSource_NonRetryableErrorStopsImmediately(t *testing.T) {
	nonRetryable := &TokenError{StatusCode: http.StatusBadRequest, ErrorCode: "invalid_request"}
	inner := &flakyTokenSource{failTimes: 100, failErr: nonRetryable}
	src := &resilientTokenSource{inner: inner, maxRetries: 2}

	if _, err := src.Token(context.Background()); err == nil {
		t.Fatal("expected an error")
	}
	if inner.calls != 1 {
		t.Errorf("expected exactly 1 attempt - a non-retryable error must not be retried, got %d calls", inner.calls)
	}
}

// N concurrent Token() calls arriving while a fetch is in flight must share that one fetch and its result.
func TestResilientTokenSource_ConcurrentCalls_ShareOneFetchAndResult(t *testing.T) {
	var calls int32
	inner := tokenFetcherFunc(func(ctx context.Context) (*Token, error) {
		atomic.AddInt32(&calls, 1)
		time.Sleep(20 * time.Millisecond) // wide join window for every goroutine below
		return &Token{AccessToken: "shared-token"}, nil
	})
	src := &resilientTokenSource{inner: inner, maxRetries: 2}

	const n = 20
	results := make([]*Token, n)
	errs := make([]error, n)
	var wg sync.WaitGroup
	wg.Add(n)
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			<-start
			results[i], errs[i] = src.Token(context.Background())
		}(i)
	}
	close(start)
	wg.Wait()

	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Errorf("expected exactly 1 real fetch shared across %d concurrent callers, got %d", n, got)
	}
	for i := range results {
		if errs[i] != nil {
			t.Errorf("caller %d: unexpected error: %v", i, errs[i])
		}
		if results[i] == nil || results[i].AccessToken != "shared-token" {
			t.Errorf("caller %d: unexpected result: %+v", i, results[i])
		}
	}
}

// Concurrent callers against a failing IdP must share one retry sequence, not each run their own.
func TestResilientTokenSource_ConcurrentFailures_ShareOneRetrySequence(t *testing.T) {
	var calls int32
	inner := tokenFetcherFunc(func(ctx context.Context) (*Token, error) {
		atomic.AddInt32(&calls, 1)
		time.Sleep(20 * time.Millisecond) // wide join window for every goroutine below
		return nil, errTransient
	})
	src := &resilientTokenSource{inner: inner, maxRetries: 2}

	const n = 20
	var wg sync.WaitGroup
	wg.Add(n)
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			<-start
			if _, err := src.Token(context.Background()); err == nil {
				t.Error("expected an error - inner always fails")
			}
		}()
	}
	close(start)
	wg.Wait()

	if got := atomic.LoadInt32(&calls); got == 0 || got > 3 {
		t.Errorf("expected between 1 and 3 real fetch attempts (1 initial + up to 2 retries) shared across %d concurrent callers, got %d", n, got)
	}
}

// A caller joining an in-flight sequence must bail out on its own ctx expiry without aborting it for others.
func TestResilientTokenSource_JoiningCallerContextCancellation_ReturnsEarlyWithoutAffectingSharedFetch(t *testing.T) {
	inner := tokenFetcherFunc(func(ctx context.Context) (*Token, error) {
		time.Sleep(150 * time.Millisecond)
		return &Token{AccessToken: "slow-token"}, nil
	})
	src := &resilientTokenSource{inner: inner, maxRetries: 0}

	var ownerTok *Token
	var ownerErr error
	ownerDone := make(chan struct{})
	go func() {
		defer close(ownerDone)
		ownerTok, ownerErr = src.Token(context.Background())
	}()

	time.Sleep(20 * time.Millisecond) // let the owner start and register inFlight

	joinerCtx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := src.Token(joinerCtx)
	elapsed := time.Since(start)

	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("expected the joining caller to get context.DeadlineExceeded, got %v", err)
	}
	if elapsed > 100*time.Millisecond {
		t.Errorf("expected the joining caller to return promptly on its own ctx expiry, took %s", elapsed)
	}

	<-ownerDone
	if ownerErr != nil || ownerTok == nil || ownerTok.AccessToken != "slow-token" {
		t.Errorf("expected the owner's shared fetch to still complete successfully despite the joiner's ctx expiring, got tok=%+v err=%v", ownerTok, ownerErr)
	}
}

// ─── reuseTokenSource ────────────────────────────────────────────────────────

func TestReuseTokenSource_ServesCachedTokenWithoutRefetchingWhileFresh(t *testing.T) {
	var calls int32
	fresh := tokenFetcherFunc(func(ctx context.Context) (*Token, error) {
		atomic.AddInt32(&calls, 1)
		return &Token{AccessToken: "tok", Expiry: time.Now().Add(time.Hour)}, nil
	})
	src := newReuseTokenSource(fresh, 5*time.Minute)

	for i := 0; i < 3; i++ {
		tok, err := src.Token(context.Background())
		if err != nil {
			t.Fatalf("call %d: unexpected error: %v", i, err)
		}
		if tok.AccessToken != "tok" {
			t.Errorf("call %d: unexpected token: %+v", i, tok)
		}
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Errorf("expected exactly 1 real fetch while the token stays fresh, got %d", got)
	}
}

func TestReuseTokenSource_RefetchesOnceStale(t *testing.T) {
	var calls int32
	fresh := tokenFetcherFunc(func(ctx context.Context) (*Token, error) {
		n := atomic.AddInt32(&calls, 1)
		return &Token{AccessToken: fmt.Sprintf("tok-%d", n), Expiry: time.Now().Add(time.Hour)}, nil
	})
	src := newReuseTokenSource(fresh, 5*time.Minute)

	first, err := src.Token(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	src.tok.Expiry = time.Now() // force staleness without waiting out a real buffer

	second, err := src.Token(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if first.AccessToken == second.AccessToken {
		t.Errorf("expected a refetch once the cached token went stale, got the same token twice: %q", first.AccessToken)
	}
	if got := atomic.LoadInt32(&calls); got != 2 {
		t.Errorf("expected exactly 2 real fetches (initial + one refetch), got %d", got)
	}
}

// N concurrent Token() calls arriving while the cached token is stale must share one refetch.
func TestReuseTokenSource_ConcurrentCallsWhileStale_ShareOneFetch(t *testing.T) {
	var calls int32
	fresh := tokenFetcherFunc(func(ctx context.Context) (*Token, error) {
		atomic.AddInt32(&calls, 1)
		time.Sleep(20 * time.Millisecond) // wide join window for every goroutine below
		return &Token{AccessToken: "shared-token", Expiry: time.Now().Add(time.Hour)}, nil
	})
	src := newReuseTokenSource(fresh, 5*time.Minute)

	const n = 20
	results := make([]*Token, n)
	errs := make([]error, n)
	var wg sync.WaitGroup
	wg.Add(n)
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			<-start
			results[i], errs[i] = src.Token(context.Background())
		}(i)
	}
	close(start)
	wg.Wait()

	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Errorf("expected exactly 1 real fetch shared across %d concurrent callers, got %d", n, got)
	}
	for i := range results {
		if errs[i] != nil {
			t.Errorf("caller %d: unexpected error: %v", i, errs[i])
		}
		if results[i] == nil || results[i].AccessToken != "shared-token" {
			t.Errorf("caller %d: unexpected result: %+v", i, results[i])
		}
	}
}

// Regression test for the whole-branch review's concurrency finding: a caller joining an
// in-flight refetch must bail out on its own ctx expiry rather than being blocked behind
// whichever caller is running the fetch, and the shared fetch itself must still complete and
// populate the cache for later callers.
func TestReuseTokenSource_JoiningCallerContextCancellation_ReturnsEarlyWithoutBlockingOnFetch(t *testing.T) {
	fresh := tokenFetcherFunc(func(ctx context.Context) (*Token, error) {
		time.Sleep(150 * time.Millisecond)
		return &Token{AccessToken: "slow-token", Expiry: time.Now().Add(time.Hour)}, nil
	})
	src := newReuseTokenSource(fresh, 5*time.Minute)

	var ownerTok *Token
	var ownerErr error
	ownerDone := make(chan struct{})
	go func() {
		defer close(ownerDone)
		ownerTok, ownerErr = src.Token(context.Background())
	}()

	time.Sleep(20 * time.Millisecond) // let the owner start and register inFlight

	joinerCtx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := src.Token(joinerCtx)
	elapsed := time.Since(start)

	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("expected the joining caller to get context.DeadlineExceeded, got %v", err)
	}
	if elapsed > 100*time.Millisecond {
		t.Errorf("expected the joining caller to return promptly on its own ctx expiry instead of blocking on the fetch, took %s", elapsed)
	}

	<-ownerDone
	if ownerErr != nil || ownerTok == nil || ownerTok.AccessToken != "slow-token" {
		t.Errorf("expected the owner's shared fetch to still complete successfully despite the joiner's ctx expiring, got tok=%+v err=%v", ownerTok, ownerErr)
	}

	// A later caller must see the token the owner's fetch just populated, not refetch again.
	cached, err := src.Token(context.Background())
	if err != nil || cached == nil || cached.AccessToken != "slow-token" {
		t.Errorf("expected a later caller to reuse the token the owner's fetch populated, got tok=%+v err=%v", cached, err)
	}
}

// TestBuildHeaderValue verifies prefix formatting for trailing spaces and tabs,
// empty prefixes, and custom prefixes.
func TestBuildHeaderValue(t *testing.T) {
	tests := []struct {
		name   string
		prefix string
		want   string
	}{
		{name: "default prefix", prefix: "Bearer", want: "Bearer tok"},
		{name: "trailing space", prefix: "Bearer ", want: "Bearer tok"},
		{name: "multiple trailing spaces", prefix: "Bearer   ", want: "Bearer tok"},
		{name: "trailing tab", prefix: "Bearer\t", want: "Bearer tok"},
		{name: "mixed trailing whitespace", prefix: "Bearer \t ", want: "Bearer tok"},
		{name: "empty prefix", prefix: "", want: "tok"},
		{name: "whitespace only prefix", prefix: " \t ", want: "tok"},
		{name: "custom prefix", prefix: "Token ", want: "Token tok"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildHeaderValue(tt.prefix, "tok")

			if got != tt.want {
				t.Errorf("prefix %q: got %q, want %q", tt.prefix, got, tt.want)
			}
		})
	}
}

// TestOnRequestHeaders_TrailingSpaceInValuePrefix verifies header injection
// with a trailing-space prefix. GetPolicy already trims this input; the
// helper's own normalization is covered by TestBuildHeaderValue.
func TestOnRequestHeaders_TrailingSpaceInValuePrefix(t *testing.T) {
	p, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{
		"bearerToken": "tok",
		"valuePrefix": "Bearer ",
	})
	if err != nil {
		t.Fatalf("GetPolicy() failed: %v", err)
	}

	action := p.(*Policy).OnRequestHeaders(
		context.Background(),
		newRequestHeaderCtx(),
		nil,
	)

	mods, ok := action.(policy.UpstreamRequestHeaderModifications)
	if !ok {
		t.Fatalf("expected UpstreamRequestHeaderModifications, got %T", action)
	}

	got := mods.HeadersToSet["Authorization"]
	if got != "Bearer tok" {
		t.Errorf("Authorization header = %q, want %q", got, "Bearer tok")
	}
}
