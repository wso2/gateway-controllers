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
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

// ─── Test helpers ──────────────────────────────────────────────────────────────

func createTestHeaders(headers map[string]string) *policy.Headers {
	m := make(map[string][]string, len(headers))
	for k, v := range headers {
		m[k] = []string{v}
	}
	return policy.NewHeaders(m)
}

func newReqCtx(headers map[string]string) *policy.RequestHeaderContext {
	return &policy.RequestHeaderContext{
		SharedContext: &policy.SharedContext{
			RequestID: "test-req-1",
			Metadata:  map[string]interface{}{},
		},
		Headers: createTestHeaders(headers),
	}
}

// basicAuthHeader returns the value for Authorization: Basic <base64(id:secret)>.
func basicAuthHeader(id, secret string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(id+":"+secret))
}

func staticParams() map[string]interface{} {
	return map[string]interface{}{
		"clientId":     "test-client",
		"clientSecret": "test-secret",
	}
}

func multiClientParams() map[string]interface{} {
	return map[string]interface{}{
		"credentials": []interface{}{
			map[string]interface{}{"clientId": "app-one", "clientSecret": "secret1"},
			map[string]interface{}{"clientId": "app-two", "clientSecret": "secret2"},
		},
	}
}

func assertUnauthorized(t *testing.T, result policy.RequestHeaderAction, wantMsgSubstr string) {
	t.Helper()
	resp, ok := result.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("expected ImmediateResponse, got %T", result)
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("StatusCode = %d, want 401", resp.StatusCode)
	}
	if ct := resp.Headers["Content-Type"]; ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	var body map[string]string
	if err := json.Unmarshal(resp.Body, &body); err != nil {
		t.Fatalf("response body is not valid JSON: %v — body: %q", err, resp.Body)
	}
	if body["error"] != "unauthorized" {
		t.Errorf("body error = %q, want unauthorized", body["error"])
	}
	if wantMsgSubstr != "" && !contains(body["message"], wantMsgSubstr) {
		t.Errorf("body message = %q, want it to contain %q", body["message"], wantMsgSubstr)
	}
}

func contains(s, sub string) bool {
	return len(sub) == 0 || len(s) >= len(sub) && (s == sub || len(s) > 0 && containsStr(s, sub))
}
func containsStr(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// ─── Factory — static mode ────────────────────────────────────────────────────

func TestGetPolicy_StaticSingle_Valid(t *testing.T) {
	p, err := GetPolicy(policy.PolicyMetadata{}, staticParams())
	if err != nil || p == nil {
		t.Fatalf("unexpected error: %v", err)
	}
	impl := p.(*ClientSecretBasicPolicy)
	if impl.cfg.Mode != modeStatic {
		t.Errorf("expected modeStatic, got %v", impl.cfg.Mode)
	}
}

func TestGetPolicy_StaticMulti_Valid(t *testing.T) {
	p, err := GetPolicy(policy.PolicyMetadata{}, multiClientParams())
	if err != nil || p == nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestGetPolicy_StaticMulti_DuplicateClientId_ReturnsError(t *testing.T) {
	params := map[string]interface{}{
		"credentials": []interface{}{
			map[string]interface{}{"clientId": "dup", "clientSecret": "s1"},
			map[string]interface{}{"clientId": "dup", "clientSecret": "s2"},
		},
	}
	_, err := GetPolicy(policy.PolicyMetadata{}, params)
	if err == nil {
		t.Fatal("expected error for duplicate clientId")
	}
}

func TestGetPolicy_MissingClientId_ReturnsError(t *testing.T) {
	_, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{"clientSecret": "s"})
	if err == nil {
		t.Fatal("expected error for missing clientId")
	}
}

func TestGetPolicy_MissingClientSecret_ReturnsError(t *testing.T) {
	_, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{"clientId": "c"})
	if err == nil {
		t.Fatal("expected error for missing clientSecret")
	}
}

func TestGetPolicy_NilParams_ReturnsError(t *testing.T) {
	_, err := GetPolicy(policy.PolicyMetadata{}, nil)
	if err == nil {
		t.Fatal("expected error for nil params")
	}
}

func TestGetPolicy_BothStaticAndDynamic_ReturnsError(t *testing.T) {
	params := map[string]interface{}{
		"tokenEndpoint": "https://idp.example.com/token",
		"clientId":      "some-client",
		"clientSecret":  "some-secret",
	}
	_, err := GetPolicy(policy.PolicyMetadata{}, params)
	if err == nil {
		t.Fatal("expected error when tokenEndpoint and static credentials are both set")
	}
}

func TestGetPolicy_BothStaticCredentialsArrayAndDynamic_ReturnsError(t *testing.T) {
	params := map[string]interface{}{
		"tokenEndpoint": "https://idp.example.com/token",
		"credentials": []interface{}{
			map[string]interface{}{"clientId": "c", "clientSecret": "s"},
		},
	}
	_, err := GetPolicy(policy.PolicyMetadata{}, params)
	if err == nil {
		t.Fatal("expected error when tokenEndpoint and credentials array are both set")
	}
}

// ─── Factory — dynamic mode ───────────────────────────────────────────────────

func TestGetPolicy_Dynamic_ValidEndpoint(t *testing.T) {
	params := map[string]interface{}{
		"tokenEndpoint": "https://idp.example.com/oauth2/token",
	}
	p, err := GetPolicy(policy.PolicyMetadata{}, params)
	if err != nil || p == nil {
		t.Fatalf("unexpected error: %v", err)
	}
	impl := p.(*ClientSecretBasicPolicy)
	if impl.cfg.Mode != modeDynamic {
		t.Errorf("expected modeDynamic, got %v", impl.cfg.Mode)
	}
	if impl.httpClient == nil {
		t.Error("httpClient should be initialized in dynamic mode")
	}
}

func TestGetPolicy_Dynamic_InvalidEndpoint_ReturnsError(t *testing.T) {
	params := map[string]interface{}{
		"tokenEndpoint": "not-a-url",
	}
	_, err := GetPolicy(policy.PolicyMetadata{}, params)
	if err == nil {
		t.Fatal("expected error for invalid tokenEndpoint URL")
	}
}

func TestGetPolicy_Dynamic_CustomTimeouts(t *testing.T) {
	params := map[string]interface{}{
		"tokenEndpoint":       "https://idp.example.com/oauth2/token",
		"tokenRequestTimeout": "30s",
		"expiryBuffer":        "2m",
		"maxCacheTTL":         "10m",
	}
	p, _ := GetPolicy(policy.PolicyMetadata{}, params)
	impl := p.(*ClientSecretBasicPolicy)
	if impl.cfg.TokenTimeout != 30*time.Second {
		t.Errorf("TokenTimeout = %v, want 30s", impl.cfg.TokenTimeout)
	}
	if impl.cfg.ExpiryBuffer != 2*time.Minute {
		t.Errorf("ExpiryBuffer = %v, want 2m", impl.cfg.ExpiryBuffer)
	}
	if impl.cfg.MaxCacheTTL != 10*time.Minute {
		t.Errorf("MaxCacheTTL = %v, want 10m", impl.cfg.MaxCacheTTL)
	}
}

// ─── Mode ─────────────────────────────────────────────────────────────────────

func TestMode(t *testing.T) {
	p, _ := GetPolicy(policy.PolicyMetadata{}, staticParams())
	m := p.(*ClientSecretBasicPolicy).Mode()
	if m.RequestHeaderMode != policy.HeaderModeProcess {
		t.Errorf("RequestHeaderMode = %v, want HeaderModeProcess", m.RequestHeaderMode)
	}
	if m.RequestBodyMode != policy.BodyModeSkip {
		t.Errorf("RequestBodyMode = %v, want BodyModeSkip", m.RequestBodyMode)
	}
	if m.ResponseHeaderMode != policy.HeaderModeSkip {
		t.Errorf("ResponseHeaderMode = %v, want HeaderModeSkip", m.ResponseHeaderMode)
	}
}

// ─── extractBasicCredentials ──────────────────────────────────────────────────

func TestExtractBasicCredentials_URLEncodedSpecialChars(t *testing.T) {
	// RFC 6749 §2.3.1: client ID and secret in Basic credentials must be URL-decoded.
	// Use percent-encoded characters: %40 → '@', %21 → '!'
	rawId := "client%40corp"
	rawSecret := "secret%21val"
	combined := rawId + ":" + rawSecret
	encoded := base64.StdEncoding.EncodeToString([]byte(combined))

	headers := createTestHeaders(map[string]string{"Authorization": "Basic " + encoded})
	id, secret, err := extractBasicCredentials(headers)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id != "client@corp" {
		t.Errorf("clientId = %q, want %q", id, "client@corp")
	}
	if secret != "secret!val" {
		t.Errorf("clientSecret = %q, want %q", secret, "secret!val")
	}
}

// ─── OnRequestHeaders — static mode ──────────────────────────────────────────

func TestOnRequestHeaders_Static_ValidCredentials(t *testing.T) {
	p, _ := GetPolicy(policy.PolicyMetadata{}, staticParams())
	ctx := newReqCtx(map[string]string{"Authorization": basicAuthHeader("test-client", "test-secret")})
	result := p.(*ClientSecretBasicPolicy).OnRequestHeaders(context.Background(), ctx, staticParams())
	if _, ok := result.(policy.UpstreamRequestHeaderModifications); !ok {
		t.Fatalf("expected UpstreamRequestHeaderModifications, got %T", result)
	}
	ac := ctx.SharedContext.AuthContext
	if ac == nil || !ac.Authenticated {
		t.Fatal("AuthContext should be populated and authenticated")
	}
	if ac.Subject != "test-client" {
		t.Errorf("Subject = %q, want test-client", ac.Subject)
	}
	if ac.CredentialID != "test-client" {
		t.Errorf("CredentialID = %q, want test-client", ac.CredentialID)
	}
	if ac.TokenId != "" {
		t.Error("TokenId should not be set (derived from secret is a security risk)")
	}
}

func TestOnRequestHeaders_Static_MissingAuthorization_Returns401(t *testing.T) {
	p, _ := GetPolicy(policy.PolicyMetadata{}, staticParams())
	ctx := newReqCtx(map[string]string{})
	assertUnauthorized(t, p.(*ClientSecretBasicPolicy).OnRequestHeaders(context.Background(), ctx, staticParams()), "missing Authorization header")
}

func TestOnRequestHeaders_Static_NonBasicScheme_Returns401(t *testing.T) {
	p, _ := GetPolicy(policy.PolicyMetadata{}, staticParams())
	ctx := newReqCtx(map[string]string{"Authorization": "Bearer sometoken"})
	assertUnauthorized(t, p.(*ClientSecretBasicPolicy).OnRequestHeaders(context.Background(), ctx, staticParams()), "Basic scheme")
}

func TestOnRequestHeaders_Static_InvalidBase64_Returns401(t *testing.T) {
	p, _ := GetPolicy(policy.PolicyMetadata{}, staticParams())
	ctx := newReqCtx(map[string]string{"Authorization": "Basic not!!valid==base64"})
	assertUnauthorized(t, p.(*ClientSecretBasicPolicy).OnRequestHeaders(context.Background(), ctx, staticParams()), "malformed Basic credentials")
}

func TestOnRequestHeaders_Static_NoColonSeparator_Returns401(t *testing.T) {
	p, _ := GetPolicy(policy.PolicyMetadata{}, staticParams())
	ctx := newReqCtx(map[string]string{"Authorization": "Basic " + base64.StdEncoding.EncodeToString([]byte("noclientidsecret"))})
	assertUnauthorized(t, p.(*ClientSecretBasicPolicy).OnRequestHeaders(context.Background(), ctx, staticParams()), "clientId:clientSecret")
}

func TestOnRequestHeaders_Static_WrongCredentials_Returns401(t *testing.T) {
	p, _ := GetPolicy(policy.PolicyMetadata{}, staticParams())
	ctx := newReqCtx(map[string]string{"Authorization": basicAuthHeader("test-client", "wrong")})
	assertUnauthorized(t, p.(*ClientSecretBasicPolicy).OnRequestHeaders(context.Background(), ctx, staticParams()), "invalid credentials")
}

func TestOnRequestHeaders_Static_AuthorizationAndSubscriptionKeyStripped(t *testing.T) {
	p, _ := GetPolicy(policy.PolicyMetadata{}, staticParams())
	ctx := newReqCtx(map[string]string{"Authorization": basicAuthHeader("test-client", "test-secret")})
	result := p.(*ClientSecretBasicPolicy).OnRequestHeaders(context.Background(), ctx, staticParams())
	mods := result.(policy.UpstreamRequestHeaderModifications)
	found := map[string]bool{}
	for _, h := range mods.HeadersToRemove {
		found[h] = true
	}
	if !found["Authorization"] {
		t.Error("Authorization should be in HeadersToRemove")
	}
	if !found["Subscription-Key"] {
		t.Error("Subscription-Key should be in HeadersToRemove")
	}
}

func TestOnRequestHeaders_SubscriptionKeyHeader_Returns401(t *testing.T) {
	p, _ := GetPolicy(policy.PolicyMetadata{}, staticParams())
	ctx := newReqCtx(map[string]string{
		"Authorization":    basicAuthHeader("test-client", "test-secret"),
		"Subscription-Key": "some-subscription-key",
	})
	assertUnauthorized(t, p.(*ClientSecretBasicPolicy).OnRequestHeaders(context.Background(), ctx, staticParams()), "subscription key header is not permitted")
}

func TestOnRequestHeaders_SubscriptionKeyHeader_CustomName_Returns401(t *testing.T) {
	params := map[string]interface{}{
		"clientId":            "test-client",
		"clientSecret":        "test-secret",
		"subscriptionKeyHeader": "X-Api-Subscription",
	}
	p, _ := GetPolicy(policy.PolicyMetadata{}, params)
	ctx := newReqCtx(map[string]string{
		"Authorization":    basicAuthHeader("test-client", "test-secret"),
		"X-Api-Subscription": "some-key",
	})
	assertUnauthorized(t, p.(*ClientSecretBasicPolicy).OnRequestHeaders(context.Background(), ctx, params), "subscription key header is not permitted")
}

func TestOnRequestHeaders_SubscriptionKeyHeader_DefaultDoesNotBlockOtherHeaders(t *testing.T) {
	p, _ := GetPolicy(policy.PolicyMetadata{}, staticParams())
	ctx := newReqCtx(map[string]string{
		"Authorization": basicAuthHeader("test-client", "test-secret"),
		"X-Custom":      "value",
	})
	result := p.(*ClientSecretBasicPolicy).OnRequestHeaders(context.Background(), ctx, staticParams())
	if _, ok := result.(policy.ImmediateResponse); ok {
		t.Error("unexpected rejection for request with no subscription key header")
	}
}

func TestOnRequestHeaders_SubscriptionCookie_Returns401(t *testing.T) {
	params := map[string]interface{}{
		"clientId":              "test-client",
		"clientSecret":          "test-secret",
		"subscriptionKeyCookie": "subscription_token",
	}
	p, _ := GetPolicy(policy.PolicyMetadata{}, params)
	ctx := newReqCtx(map[string]string{
		"Authorization": basicAuthHeader("test-client", "test-secret"),
		"Cookie":        "subscription_token=abc123; session=xyz",
	})
	assertUnauthorized(t, p.(*ClientSecretBasicPolicy).OnRequestHeaders(context.Background(), ctx, params), "subscription cookie is not permitted")
}

func TestOnRequestHeaders_SubscriptionCookie_OtherCookiesNotBlocked(t *testing.T) {
	params := map[string]interface{}{
		"clientId":              "test-client",
		"clientSecret":          "test-secret",
		"subscriptionKeyCookie": "subscription_token",
	}
	p, _ := GetPolicy(policy.PolicyMetadata{}, params)
	ctx := newReqCtx(map[string]string{
		"Authorization": basicAuthHeader("test-client", "test-secret"),
		"Cookie":        "session=xyz; pref=dark",
	})
	result := p.(*ClientSecretBasicPolicy).OnRequestHeaders(context.Background(), ctx, params)
	if _, ok := result.(policy.ImmediateResponse); ok {
		t.Error("unexpected rejection when only unrelated cookies are present")
	}
}

func TestOnRequestHeaders_SubscriptionCookieNotConfigured_CookieAllowed(t *testing.T) {
	p, _ := GetPolicy(policy.PolicyMetadata{}, staticParams())
	ctx := newReqCtx(map[string]string{
		"Authorization": basicAuthHeader("test-client", "test-secret"),
		"Cookie":        "subscription_token=abc123",
	})
	result := p.(*ClientSecretBasicPolicy).OnRequestHeaders(context.Background(), ctx, staticParams())
	if _, ok := result.(policy.ImmediateResponse); ok {
		t.Error("unexpected rejection when subscriptionKeyCookie is not configured")
	}
}

func TestOnRequestHeaders_401_HasWWWAuthenticate(t *testing.T) {
	p, _ := GetPolicy(policy.PolicyMetadata{}, staticParams())
	ctx := newReqCtx(map[string]string{}) // no Authorization header
	result := p.(*ClientSecretBasicPolicy).OnRequestHeaders(context.Background(), ctx, staticParams())
	resp, ok := result.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("expected ImmediateResponse, got %T", result)
	}
	want := `Basic realm="API Gateway"`
	if resp.Headers["WWW-Authenticate"] != want {
		t.Errorf("WWW-Authenticate = %q, want %q", resp.Headers["WWW-Authenticate"], want)
	}
}

func TestOnRequestHeaders_Static_MultiClient_FirstEntry(t *testing.T) {
	p, _ := GetPolicy(policy.PolicyMetadata{}, multiClientParams())
	ctx := newReqCtx(map[string]string{"Authorization": basicAuthHeader("app-one", "secret1")})
	result := p.(*ClientSecretBasicPolicy).OnRequestHeaders(context.Background(), ctx, multiClientParams())
	if _, ok := result.(policy.UpstreamRequestHeaderModifications); !ok {
		t.Fatalf("expected success, got %T", result)
	}
	if ctx.SharedContext.AuthContext.Properties["ClientId"] != "app-one" {
		t.Errorf("ClientId = %q, want app-one", ctx.SharedContext.AuthContext.Properties["ClientId"])
	}
}

func TestOnRequestHeaders_Static_MultiClient_SecondEntry(t *testing.T) {
	p, _ := GetPolicy(policy.PolicyMetadata{}, multiClientParams())
	ctx := newReqCtx(map[string]string{"Authorization": basicAuthHeader("app-two", "secret2")})
	result := p.(*ClientSecretBasicPolicy).OnRequestHeaders(context.Background(), ctx, multiClientParams())
	if _, ok := result.(policy.UpstreamRequestHeaderModifications); !ok {
		t.Fatalf("expected success, got %T", result)
	}
}

// ─── Application-ID injection ─────────────────────────────────────────────────

func TestOnRequestHeaders_SetsApplicationIDMetadata(t *testing.T) {
	p, _ := GetPolicy(policy.PolicyMetadata{}, staticParams())
	ctx := newReqCtx(map[string]string{"Authorization": basicAuthHeader("test-client", "test-secret")})
	p.(*ClientSecretBasicPolicy).OnRequestHeaders(context.Background(), ctx, staticParams())
	got, ok := ctx.SharedContext.Metadata[applicationIDMetadataKey]
	if !ok {
		t.Fatalf("expected %s in metadata", applicationIDMetadataKey)
	}
	if got != "test-client" {
		t.Errorf("%s = %q, want test-client", applicationIDMetadataKey, got)
	}
}

func TestOnRequestHeaders_OverwritesExistingApplicationID(t *testing.T) {
	// The authenticated clientId must always win — a prior value from an earlier
	// policy in the chain could belong to a different identity and would cause
	// subscription-validation to check the wrong application.
	p, _ := GetPolicy(policy.PolicyMetadata{}, staticParams())
	ctx := newReqCtx(map[string]string{"Authorization": basicAuthHeader("test-client", "test-secret")})
	ctx.SharedContext.Metadata[applicationIDMetadataKey] = "prior-app-id"
	p.(*ClientSecretBasicPolicy).OnRequestHeaders(context.Background(), ctx, staticParams())
	if got := ctx.SharedContext.Metadata[applicationIDMetadataKey]; got != "test-client" {
		t.Errorf("expected authenticated clientId %q, got %v", "test-client", got)
	}
}

func TestOnRequestHeaders_FailedAuth_DoesNotSetApplicationID(t *testing.T) {
	p, _ := GetPolicy(policy.PolicyMetadata{}, staticParams())
	ctx := newReqCtx(map[string]string{"Authorization": basicAuthHeader("wrong", "wrong")})
	p.(*ClientSecretBasicPolicy).OnRequestHeaders(context.Background(), ctx, staticParams())
	if _, ok := ctx.SharedContext.Metadata[applicationIDMetadataKey]; ok {
		t.Error("app ID should not be set on failed auth")
	}
}

// ─── OnRequestHeaders — dynamic mode ─────────────────────────────────────────

// fakeTokenServer returns a configurable OAuth2-like token endpoint.
func fakeTokenServer(statusCode int, expiresIn int) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if statusCode != http.StatusOK {
			w.WriteHeader(statusCode)
			fmt.Fprintf(w, `{"error":"invalid_client"}`)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"access_token":"test-token","token_type":"Bearer","expires_in":%d}`, expiresIn)
	}))
}

func dynamicParams(endpoint string) map[string]interface{} {
	return map[string]interface{}{
		"tokenEndpoint": endpoint,
		"expiryBuffer":  "0s", // no buffer so cache entries don't expire instantly in tests
	}
}

func TestOnRequestHeaders_Dynamic_ValidCredentials_ReturnsSuccess(t *testing.T) {
	srv := fakeTokenServer(http.StatusOK, 3600)
	defer srv.Close()

	p, _ := GetPolicy(policy.PolicyMetadata{}, dynamicParams(srv.URL))
	ctx := newReqCtx(map[string]string{"Authorization": basicAuthHeader("client1", "secret1")})
	result := p.(*ClientSecretBasicPolicy).OnRequestHeaders(context.Background(), ctx, dynamicParams(srv.URL))
	if _, ok := result.(policy.UpstreamRequestHeaderModifications); !ok {
		t.Fatalf("expected success, got %T: %v", result, result)
	}
}

func TestOnRequestHeaders_Dynamic_InvalidCredentials_Returns401(t *testing.T) {
	srv := fakeTokenServer(http.StatusUnauthorized, 0)
	defer srv.Close()

	p, _ := GetPolicy(policy.PolicyMetadata{}, dynamicParams(srv.URL))
	ctx := newReqCtx(map[string]string{"Authorization": basicAuthHeader("bad", "wrong")})
	result := p.(*ClientSecretBasicPolicy).OnRequestHeaders(context.Background(), ctx, dynamicParams(srv.URL))
	assertUnauthorized(t, result, "invalid credentials")
}

func TestOnRequestHeaders_Dynamic_NetworkError_Returns503(t *testing.T) {
	params := map[string]interface{}{
		"tokenEndpoint":       "http://127.0.0.1:1", // connection refused
		"expiryBuffer":        "0s",
		"tokenRequestTimeout": "2s",
	}
	p, _ := GetPolicy(policy.PolicyMetadata{}, params)
	ctx := newReqCtx(map[string]string{"Authorization": basicAuthHeader("c1", "s1")})
	result := p.(*ClientSecretBasicPolicy).OnRequestHeaders(context.Background(), ctx, params)
	resp, ok := result.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("expected ImmediateResponse, got %T", result)
	}
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("expected 503 for network error, got %d", resp.StatusCode)
	}
}

func TestOnRequestHeaders_Dynamic_ServerError_Returns503(t *testing.T) {
	srv := fakeTokenServer(http.StatusInternalServerError, 0)
	defer srv.Close()

	p, _ := GetPolicy(policy.PolicyMetadata{}, dynamicParams(srv.URL))
	ctx := newReqCtx(map[string]string{"Authorization": basicAuthHeader("c1", "s1")})
	result := p.(*ClientSecretBasicPolicy).OnRequestHeaders(context.Background(), ctx, dynamicParams(srv.URL))
	resp, ok := result.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("expected ImmediateResponse, got %T", result)
	}
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("expected 503 for server error, got %d", resp.StatusCode)
	}
}

func TestOnRequestHeaders_Dynamic_CacheHit_SkipsTokenRequest(t *testing.T) {
	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"access_token":"tok","expires_in":3600}`)
	}))
	defer srv.Close()

	p, _ := GetPolicy(policy.PolicyMetadata{}, dynamicParams(srv.URL))
	impl := p.(*ClientSecretBasicPolicy)
	headers := map[string]string{"Authorization": basicAuthHeader("c1", "s1")}

	impl.OnRequestHeaders(context.Background(), newReqCtx(headers), dynamicParams(srv.URL))
	impl.OnRequestHeaders(context.Background(), newReqCtx(headers), dynamicParams(srv.URL))

	if callCount != 1 {
		t.Errorf("token endpoint called %d times, want 1 (cache should absorb second call)", callCount)
	}
}

func TestOnRequestHeaders_Dynamic_FailureCaching_ReducesIdPCalls(t *testing.T) {
	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprintf(w, `{"error":"invalid_client"}`)
	}))
	defer srv.Close()

	p, _ := GetPolicy(policy.PolicyMetadata{}, dynamicParams(srv.URL))
	impl := p.(*ClientSecretBasicPolicy)
	headers := map[string]string{"Authorization": basicAuthHeader("bad", "creds")}

	r1 := impl.OnRequestHeaders(context.Background(), newReqCtx(headers), dynamicParams(srv.URL))
	assertUnauthorized(t, r1, "invalid credentials")

	r2 := impl.OnRequestHeaders(context.Background(), newReqCtx(headers), dynamicParams(srv.URL))
	assertUnauthorized(t, r2, "")

	if callCount != 1 {
		t.Errorf("failure cache should prevent second IdP call: got %d calls, want 1", callCount)
	}
}

func TestOnRequestHeaders_Dynamic_ConcurrentRequests_SingleflightDeduplication(t *testing.T) {
	var mu sync.Mutex
	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		callCount++
		mu.Unlock()
		time.Sleep(50 * time.Millisecond) // give goroutines time to pile up
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"access_token":"tok","expires_in":3600}`)
	}))
	defer srv.Close()

	p, _ := GetPolicy(policy.PolicyMetadata{}, dynamicParams(srv.URL))
	impl := p.(*ClientSecretBasicPolicy)

	const n = 10
	results := make([]policy.RequestHeaderAction, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ctx := newReqCtx(map[string]string{"Authorization": basicAuthHeader("c1", "s1")})
			results[i] = impl.OnRequestHeaders(context.Background(), ctx, dynamicParams(srv.URL))
		}(i)
	}
	wg.Wait()

	for i, r := range results {
		if _, ok := r.(policy.UpstreamRequestHeaderModifications); !ok {
			t.Errorf("goroutine %d: expected success, got %T", i, r)
		}
	}
	mu.Lock()
	calls := callCount
	mu.Unlock()
	if calls != 1 {
		t.Errorf("singleflight: expected 1 token call for %d concurrent requests, got %d", n, calls)
	}
}

func TestOnRequestHeaders_Dynamic_MaxCacheTTL_CapsSuccessCacheTTL(t *testing.T) {
	srv := fakeTokenServer(http.StatusOK, 3600) // IdP says valid for 1h
	defer srv.Close()

	params := map[string]interface{}{
		"tokenEndpoint": srv.URL,
		"expiryBuffer":  "0s",
		"maxCacheTTL":   "1m", // cap at 1 minute regardless
	}
	p, _ := GetPolicy(policy.PolicyMetadata{}, params)
	impl := p.(*ClientSecretBasicPolicy)

	impl.OnRequestHeaders(context.Background(), newReqCtx(map[string]string{"Authorization": basicAuthHeader("c1", "s1")}), params)

	key := cacheKey("c1", "s1")
	v, ok := impl.cache.Load(key)
	if !ok {
		t.Fatal("expected cache entry after successful validation")
	}
	entry := v.(validationEntry)
	remaining := time.Until(entry.expiresAt)
	if remaining > 70*time.Second {
		t.Errorf("maxCacheTTL not enforced: cache entry expires in %v, want ≤1m", remaining)
	}
}

func TestOnRequestHeaders_Dynamic_ExpiredCacheEntry_RetriggersTokenRequest(t *testing.T) {
	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"access_token":"tok","expires_in":3600}`)
	}))
	defer srv.Close()

	params := map[string]interface{}{
		"tokenEndpoint": srv.URL,
		"expiryBuffer":  "0s",
	}
	p, _ := GetPolicy(policy.PolicyMetadata{}, params)
	impl := p.(*ClientSecretBasicPolicy)

	key := cacheKey("c1", "s1")
	impl.cache.Store(key, validationEntry{expiresAt: time.Now().Add(-time.Second)}) // already expired

	headers := map[string]string{"Authorization": basicAuthHeader("c1", "s1")}
	impl.OnRequestHeaders(context.Background(), newReqCtx(headers), params)

	if callCount != 1 {
		t.Errorf("expected 1 token request after expired cache, got %d", callCount)
	}
}

func TestOnRequestHeaders_Dynamic_SetsApplicationIDMetadata(t *testing.T) {
	srv := fakeTokenServer(http.StatusOK, 3600)
	defer srv.Close()

	p, _ := GetPolicy(policy.PolicyMetadata{}, dynamicParams(srv.URL))
	ctx := newReqCtx(map[string]string{"Authorization": basicAuthHeader("dyn-client", "dyn-secret")})
	p.(*ClientSecretBasicPolicy).OnRequestHeaders(context.Background(), ctx, dynamicParams(srv.URL))

	got, ok := ctx.SharedContext.Metadata[applicationIDMetadataKey]
	if !ok || got != "dyn-client" {
		t.Errorf("expected x-wso2-application-id = dyn-client, got %v", got)
	}
}

// ─── Failure tracker — per-credential pair + per-clientId throttle ────────────

func TestOnRequestHeaders_Dynamic_FailureTracker_ThrottlesAfterLimit(t *testing.T) {
	// Two-layer failure protection:
	// 1. Wrong-credential pair cache: a known-bad (clientId, secret) pair returns 401
	//    immediately without an IdP call (the exact pair is cached).
	// 2. Per-clientId throttle: after failureRateLimit unique wrong secrets, further
	//    requests for that clientId return 429 (no IdP call) until the window resets.
	//
	// A single wrong secret cannot block the correct secret: it consumes one slot but
	// leaves room for legitimate calls as long as the per-clientId limit is not exhausted.
	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprintf(w, `{"error":"invalid_client"}`)
	}))
	defer srv.Close()

	p, _ := GetPolicy(policy.PolicyMetadata{}, dynamicParams(srv.URL))
	impl := p.(*ClientSecretBasicPolicy)

	const limit = defaultFailureRateLimit // 3 by default

	// First <limit> unique wrong passwords → each reaches the IdP → 401.
	for i := 0; i < limit; i++ {
		r := impl.OnRequestHeaders(context.Background(),
			newReqCtx(map[string]string{"Authorization": basicAuthHeader("victim", fmt.Sprintf("wrong-%d", i))}),
			dynamicParams(srv.URL))
		assertUnauthorized(t, r, "")
	}
	if callCount != limit {
		t.Errorf("first %d unique wrong passwords: want %d IdP calls, got %d", limit, limit, callCount)
	}

	// Additional unique wrong passwords → 429 (throttled, no IdP call).
	for i := limit; i < 20; i++ {
		r := impl.OnRequestHeaders(context.Background(),
			newReqCtx(map[string]string{"Authorization": basicAuthHeader("victim", fmt.Sprintf("wrong-%d", i))}),
			dynamicParams(srv.URL))
		resp, ok := r.(policy.ImmediateResponse)
		if !ok || resp.StatusCode != http.StatusTooManyRequests {
			status := 0
			if ok {
				status = resp.StatusCode
			}
			t.Errorf("wrong-%d: expected 429 when throttled, got %T / status %d", i, r, status)
		}
	}
	if callCount != limit {
		t.Errorf("after throttle: IdP calls should still be %d, got %d", limit, callCount)
	}

	// Repeat a known-bad password → 401 from wrongCreds cache, no IdP call.
	r := impl.OnRequestHeaders(context.Background(),
		newReqCtx(map[string]string{"Authorization": basicAuthHeader("victim", "wrong-0")}),
		dynamicParams(srv.URL))
	// wrongCreds cache is checked before the throttle, so this returns 401 not 429.
	assertUnauthorized(t, r, "")
	if callCount != limit {
		t.Errorf("repeat of known-bad password: want %d total IdP calls (wrongCreds cache hit), got %d", limit, callCount)
	}
}

// ─── IdP 429 → 503, not cached ────────────────────────────────────────────────

func TestOnRequestHeaders_Dynamic_IdP429_Returns503_NotCached(t *testing.T) {
	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.WriteHeader(http.StatusTooManyRequests)
		fmt.Fprintf(w, `{"error":"rate_limited"}`)
	}))
	defer srv.Close()

	p, _ := GetPolicy(policy.PolicyMetadata{}, dynamicParams(srv.URL))
	impl := p.(*ClientSecretBasicPolicy)
	headers := map[string]string{"Authorization": basicAuthHeader("c1", "s1")}

	// First request: 429 → 503.
	r1 := impl.OnRequestHeaders(context.Background(), newReqCtx(headers), dynamicParams(srv.URL))
	resp1, ok := r1.(policy.ImmediateResponse)
	if !ok || resp1.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("expected 503 for IdP 429, got %T / %v", r1, r1)
	}

	// Second request: must NOT be served from a failure cache (429 is not cached).
	r2 := impl.OnRequestHeaders(context.Background(), newReqCtx(headers), dynamicParams(srv.URL))
	resp2, ok := r2.(policy.ImmediateResponse)
	if !ok || resp2.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("expected 503 on second request too, got %T / %v", r2, r2)
	}

	if callCount != 2 {
		t.Errorf("429 must not be cached: want 2 IdP calls, got %d", callCount)
	}
}

func TestOnRequestHeaders_Dynamic_IdP400_Returns401_IsCached(t *testing.T) {
	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, `{"error":"invalid_client"}`)
	}))
	defer srv.Close()

	p, _ := GetPolicy(policy.PolicyMetadata{}, dynamicParams(srv.URL))
	impl := p.(*ClientSecretBasicPolicy)
	headers := map[string]string{"Authorization": basicAuthHeader("c1", "s1")}

	r1 := impl.OnRequestHeaders(context.Background(), newReqCtx(headers), dynamicParams(srv.URL))
	assertUnauthorized(t, r1, "invalid credentials")

	r2 := impl.OnRequestHeaders(context.Background(), newReqCtx(headers), dynamicParams(srv.URL))
	assertUnauthorized(t, r2, "")

	if callCount != 1 {
		t.Errorf("400 should be cached: want 1 IdP call, got %d", callCount)
	}
}

// ─── Cache TTL fallback only when expires_in is absent ───────────────────────

func TestOnRequestHeaders_Dynamic_ShortToken_ClampedToOneSecond_NotFallback(t *testing.T) {
	// A 60-second token with 5m expiryBuffer would yield ttl = -240s.
	// The fix clamps this to 1s — not the 1-hour fallback.
	srv := fakeTokenServer(http.StatusOK, 60) // 60s token
	defer srv.Close()

	params := map[string]interface{}{
		"tokenEndpoint": srv.URL,
		"expiryBuffer":  "5m", // deliberately larger than the token lifetime to exercise clamping
	}
	p, _ := GetPolicy(policy.PolicyMetadata{}, params)
	impl := p.(*ClientSecretBasicPolicy)

	impl.OnRequestHeaders(context.Background(),
		newReqCtx(map[string]string{"Authorization": basicAuthHeader("c1", "s1")}), params)

	key := cacheKey("c1", "s1")
	v, ok := impl.cache.Load(key)
	if !ok {
		t.Fatal("expected cache entry")
	}
	remaining := time.Until(v.(validationEntry).expiresAt)
	if remaining > 10*time.Second {
		t.Errorf("short token should be clamped to ~1s, not fall back to 1h: remaining=%v", remaining)
	}
}

func TestOnRequestHeaders_Dynamic_MissingExpiresIn_Uses1hFallback(t *testing.T) {
	// When expires_in is absent (zero), the 1-hour fallback is correct.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"access_token":"tok"}`) // no expires_in field
	}))
	defer srv.Close()

	params := map[string]interface{}{
		"tokenEndpoint": srv.URL,
		"expiryBuffer":  "0s",
		"maxCacheTTL":   "2h", // raise cap so we can see the fallback
	}
	p, _ := GetPolicy(policy.PolicyMetadata{}, params)
	impl := p.(*ClientSecretBasicPolicy)

	impl.OnRequestHeaders(context.Background(),
		newReqCtx(map[string]string{"Authorization": basicAuthHeader("c1", "s1")}), params)

	key := cacheKey("c1", "s1")
	v, ok := impl.cache.Load(key)
	if !ok {
		t.Fatal("expected cache entry")
	}
	remaining := time.Until(v.(validationEntry).expiresAt)
	if remaining < 50*time.Minute {
		t.Errorf("missing expires_in should use ~1h fallback, got remaining=%v", remaining)
	}
}

// ─── Authorization header forwarded unchanged to IdP ─────────────────────────

func TestOnRequestHeaders_Dynamic_RawAuthHeaderForwardedUnchanged(t *testing.T) {
	// A secret containing '+' must reach the IdP as '+' (not decoded to ' '),
	// because the original Authorization header is forwarded unchanged.
	var receivedAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"access_token":"tok","expires_in":3600}`)
	}))
	defer srv.Close()

	// Secret with '+' — form-encoded by a client that follows RFC 6749.
	// base64("client1:pass%2Bword") — the IdP must receive this exact header.
	rawHeader := "Basic " + base64.StdEncoding.EncodeToString([]byte("client1:pass%2Bword"))

	p, _ := GetPolicy(policy.PolicyMetadata{}, dynamicParams(srv.URL))
	impl := p.(*ClientSecretBasicPolicy)
	ctx := &policy.RequestHeaderContext{
		SharedContext: &policy.SharedContext{Metadata: map[string]interface{}{}},
		Headers:       policy.NewHeaders(map[string][]string{"Authorization": {rawHeader}}),
	}
	impl.OnRequestHeaders(context.Background(), ctx, dynamicParams(srv.URL))

	if receivedAuth != rawHeader {
		t.Errorf("IdP received Authorization=%q, want %q (raw header must be forwarded unchanged)", receivedAuth, rawHeader)
	}
}

// ─── OnResponseHeaders ────────────────────────────────────────────────────────

func TestOnResponseHeaders_IsNoop(t *testing.T) {
	p, _ := GetPolicy(policy.PolicyMetadata{}, staticParams())
	result := p.(*ClientSecretBasicPolicy).OnResponseHeaders(
		context.Background(),
		&policy.ResponseHeaderContext{SharedContext: &policy.SharedContext{}},
		staticParams(),
	)
	mods, ok := result.(policy.DownstreamResponseHeaderModifications)
	if !ok {
		t.Fatalf("expected DownstreamResponseHeaderModifications, got %T", result)
	}
	if len(mods.HeadersToSet) != 0 || len(mods.HeadersToRemove) != 0 {
		t.Errorf("expected no-op, got headers %v", mods)
	}
}

// ─── New tests for the three bug fixes ────────────────────────────────────────

// Fix 1: concurrent different wrong secrets — throttle engages after failureRateLimit
// IdP calls, not after failureRateLimit×concurrency calls.
func TestOnRequestHeaders_Dynamic_ConcurrentDifferentSecrets_ThrottleKicksIn(t *testing.T) {
	var mu sync.Mutex
	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		callCount++
		mu.Unlock()
		time.Sleep(20 * time.Millisecond) // give goroutines time to pile up
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprintf(w, `{"error":"invalid_client"}`)
	}))
	defer srv.Close()

	params := map[string]interface{}{
		"tokenEndpoint":    srv.URL,
		"expiryBuffer":     "0s",
		"failureRateLimit": float64(3),
		"failureWindow":    "30s",
	}
	p, _ := GetPolicy(policy.PolicyMetadata{}, params)
	impl := p.(*ClientSecretBasicPolicy)

	const n = 20 // 20 concurrent requests, all with different wrong secrets
	results := make([]policy.RequestHeaderAction, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ctx := newReqCtx(map[string]string{
				"Authorization": basicAuthHeader("victim", fmt.Sprintf("concurrent-wrong-%d", i)),
			})
			results[i] = impl.OnRequestHeaders(context.Background(), ctx, params)
		}(i)
	}
	wg.Wait()

	mu.Lock()
	calls := callCount
	mu.Unlock()

	// With the fix: exactly failureRateLimit=3 IdP calls, the rest are throttled.
	// Before the fix: all 20 (or many more) could reach the IdP.
	if calls > 3 {
		t.Errorf("concurrent different secrets: want ≤3 IdP calls (failureRateLimit), got %d — throttle did not engage in time", calls)
	}

	// Count 429 responses
	throttledCount := 0
	for _, r := range results {
		resp, ok := r.(policy.ImmediateResponse)
		if ok && resp.StatusCode == http.StatusTooManyRequests {
			throttledCount++
		}
	}
	if throttledCount == 0 {
		t.Error("expected some requests to be throttled (429) when limit is exceeded concurrently")
	}
}

// Fix 2: concurrent same wrong secret — singleflight deduplicates to 1 IdP call,
// and the counter increments exactly once (not once per waiting goroutine).
func TestOnRequestHeaders_Dynamic_ConcurrentSameWrongSecret_CounterIncrementsOnce(t *testing.T) {
	var mu sync.Mutex
	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		callCount++
		mu.Unlock()
		time.Sleep(50 * time.Millisecond) // let goroutines pile up in singleflight
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprintf(w, `{"error":"invalid_client"}`)
	}))
	defer srv.Close()

	params := map[string]interface{}{
		"tokenEndpoint":    srv.URL,
		"expiryBuffer":     "0s",
		"failureRateLimit": float64(3),
		"failureWindow":    "30s",
	}
	p, _ := GetPolicy(policy.PolicyMetadata{}, params)
	impl := p.(*ClientSecretBasicPolicy)

	const n = 10
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			impl.OnRequestHeaders(context.Background(),
				newReqCtx(map[string]string{"Authorization": basicAuthHeader("theclient", "samewrong")}),
				params)
		}()
	}
	wg.Wait()

	mu.Lock()
	calls := callCount
	mu.Unlock()
	if calls != 1 {
		t.Errorf("singleflight should produce 1 IdP call for %d concurrent same-secret requests, got %d", n, calls)
	}

	// Counter should be 1 (not 10). Two more unique wrong secrets should still reach the IdP.
	srv2CallCount := 0
	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		srv2CallCount++
		mu.Unlock()
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprintf(w, `{"error":"invalid_client"}`)
	}))
	defer srv2.Close()
	params2 := map[string]interface{}{
		"tokenEndpoint":    srv.URL,
		"expiryBuffer":     "0s",
		"failureRateLimit": float64(3),
		"failureWindow":    "30s",
	}
	// Use same policy instance (same failure tracker) to test counter value.
	// Counter is 1; two more unique wrong secrets (total 3) should reach the IdP.
	for i := 0; i < 2; i++ {
		r := impl.OnRequestHeaders(context.Background(),
			newReqCtx(map[string]string{"Authorization": basicAuthHeader("theclient", fmt.Sprintf("another-wrong-%d", i))}),
			params2)
		assertUnauthorized(t, r, "")
	}
	// Now counter should be 3 == limit; next unique wrong secret → 429.
	r := impl.OnRequestHeaders(context.Background(),
		newReqCtx(map[string]string{"Authorization": basicAuthHeader("theclient", "yet-another-wrong")}),
		params)
	resp, ok := r.(policy.ImmediateResponse)
	if !ok || resp.StatusCode != http.StatusTooManyRequests {
		t.Errorf("after 3 unique failures (counter incremented once per singleflight), want 429, got %T / %v", r, r)
	}
}

// Fix 3a: Retry-After header is present and positive on 429 responses.
func TestOnRequestHeaders_Dynamic_429_HasRetryAfterHeader(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprintf(w, `{"error":"invalid_client"}`)
	}))
	defer srv.Close()

	params := map[string]interface{}{
		"tokenEndpoint":    srv.URL,
		"expiryBuffer":     "0s",
		"failureRateLimit": float64(1),
		"failureWindow":    "60s",
	}
	p, _ := GetPolicy(policy.PolicyMetadata{}, params)
	impl := p.(*ClientSecretBasicPolicy)

	// First wrong secret exhausts the limit (failureRateLimit=1).
	impl.OnRequestHeaders(context.Background(),
		newReqCtx(map[string]string{"Authorization": basicAuthHeader("c", "wrong1")}), params)

	// Second attempt → 429.
	r := impl.OnRequestHeaders(context.Background(),
		newReqCtx(map[string]string{"Authorization": basicAuthHeader("c", "wrong2")}), params)

	resp, ok := r.(policy.ImmediateResponse)
	if !ok || resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %T / %v", r, r)
	}
	ra := resp.Headers["Retry-After"]
	if ra == "" {
		t.Fatal("Retry-After header missing on 429 response")
	}
	var secs int
	if _, err := fmt.Sscanf(ra, "%d", &secs); err != nil || secs < 1 {
		t.Errorf("Retry-After = %q, want a positive integer (seconds)", ra)
	}
	if secs > 60 {
		t.Errorf("Retry-After = %d, want ≤ window=60s", secs)
	}
}

// Fix 3b: oversized client IDs are rejected before reaching the counter map.
func TestOnRequestHeaders_Dynamic_LongClientID_Returns401(t *testing.T) {
	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprintf(w, `{"error":"invalid_client"}`)
	}))
	defer srv.Close()

	params := map[string]interface{}{"tokenEndpoint": srv.URL, "expiryBuffer": "0s"}
	p, _ := GetPolicy(policy.PolicyMetadata{}, params)
	impl := p.(*ClientSecretBasicPolicy)

	longID := string(make([]byte, maxDynamicClientIDLen+1))
	for i := range longID {
		longID = longID[:i] + "a" + longID[i+1:]
	}

	r := impl.OnRequestHeaders(context.Background(),
		newReqCtx(map[string]string{"Authorization": basicAuthHeader(longID, "s")}), params)

	assertUnauthorized(t, r, "")
	if callCount != 0 {
		t.Errorf("oversized clientId must be rejected before IdP call, got %d calls", callCount)
	}
}

// Fix 4: invalid duration params return an error at policy-load time.
func TestGetPolicy_Dynamic_InvalidDuration_ReturnsError(t *testing.T) {
	cases := []struct {
		param string
		value string
	}{
		{"failureWindow", "abc"},
		{"failureWindow", "-5s"},
		{"tokenRequestTimeout", "not-a-duration"},
		{"maxCacheTTL", "0"},
		{"expiryBuffer", "bad"},
	}
	for _, tc := range cases {
		params := map[string]interface{}{
			"tokenEndpoint": "https://idp.example.com/token",
			tc.param:        tc.value,
		}
		_, err := GetPolicy(policy.PolicyMetadata{}, params)
		if err == nil {
			t.Errorf("param %s=%q: expected error for invalid duration, got nil", tc.param, tc.value)
		}
	}
}
