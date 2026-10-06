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

package oauthtokenexchange

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
	"github.com/wso2/api-platform/sdk/core/utils"
)

func newTestPolicy() *OAuthTokenExchangePolicy {
	return &OAuthTokenExchangePolicy{
		tokenCache:     newTokenCache(defaultCacheMaxSize),
		currentMaxSize: defaultCacheMaxSize,
	}
}

func newSharedContext() *policy.SharedContext {
	return &policy.SharedContext{
		RequestID: "test-request-id",
		APIName:   "test-api",
		Metadata:  make(map[string]interface{}),
	}
}

func newRequestContext(headers map[string][]string, path string) *policy.RequestContext {
	return &policy.RequestContext{
		SharedContext: newSharedContext(),
		Headers:       policy.NewHeaders(headers),
		Path:          path,
		Method:        "GET",
	}
}

// newRequestContextSharing is like newRequestContext but reuses an existing
// *policy.SharedContext — needed to simulate the kernel carrying the same
// SharedContext (and its Metadata) from the header phase into the body phase.
func newRequestContextSharing(shared *policy.SharedContext, headers map[string][]string, path string) *policy.RequestContext {
	return &policy.RequestContext{
		SharedContext: shared,
		Headers:       policy.NewHeaders(headers),
		Path:          path,
		Method:        "GET",
	}
}

func newRequestHeaderContext(shared *policy.SharedContext, headers map[string][]string, path string) *policy.RequestHeaderContext {
	return &policy.RequestHeaderContext{
		SharedContext: shared,
		Headers:       policy.NewHeaders(headers),
		Path:          path,
		Method:        "GET",
	}
}

func baseParams(tokenEndpoint string) map[string]interface{} {
	return map[string]interface{}{
		"tokenEndpoint": tokenEndpoint,
		"clientId":      "test-client",
		"clientSecret":  "test-secret",
	}
}

// ─── OnRequestBody: success paths ────────────────────────────────────────

func TestOnRequestBody_TokenExchange_Success(t *testing.T) {
	var hits int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		if err := r.ParseForm(); err != nil {
			t.Fatalf("parse form: %v", err)
		}
		if got := r.PostForm.Get("grant_type"); got != grantTypeTokenExchangeURN {
			t.Errorf("grant_type = %q, want %q", got, grantTypeTokenExchangeURN)
		}
		if got := r.PostForm.Get("subject_token"); got != "original-client-token" {
			t.Errorf("subject_token = %q, want original-client-token", got)
		}
		if got := r.PostForm.Get("subject_token_type"); got != "urn:ietf:params:oauth:token-type:access_token" {
			t.Errorf("subject_token_type = %q", got)
		}
		user, pass, ok := r.BasicAuth()
		if !ok || user != "test-client" || pass != "test-secret" {
			t.Errorf("expected ClientSecretBasic auth, got user=%q pass=%q ok=%v", user, pass, ok)
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "exchanged-token",
			"expires_in":   300,
		})
	}))
	defer server.Close()
	utils.SetSharedHTTPClient(server.Client())
	defer utils.SetSharedHTTPClient(nil)

	p := newTestPolicy()
	reqCtx := newRequestContext(map[string][]string{"Authorization": {"Bearer original-client-token"}}, "/pets")
	result := p.OnRequestBody(context.Background(), reqCtx, baseParams(server.URL))

	action, ok := result.(policy.UpstreamRequestModifications)
	if !ok {
		t.Fatalf("expected UpstreamRequestModifications, got %T: %+v", result, result)
	}
	if got := action.HeadersToSet["Authorization"]; got != "Bearer exchanged-token" {
		t.Errorf("Authorization = %q, want %q", got, "Bearer exchanged-token")
	}
	if atomic.LoadInt32(&hits) != 1 {
		t.Errorf("expected exactly 1 token endpoint call, got %d", hits)
	}
}

func TestOnRequestBody_HeaderPrefix_MissingTrailingSpace(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "exchanged-token",
			"expires_in":   300,
		})
	}))
	defer server.Close()
	utils.SetSharedHTTPClient(server.Client())
	defer utils.SetSharedHTTPClient(nil)

	p := newTestPolicy()
	reqCtx := newRequestContext(map[string][]string{"Authorization": {"Bearer original-client-token"}}, "/pets")
	params := baseParams(server.URL)
	params["headerPrefix"] = "Bearer" // no trailing space
	result := p.OnRequestBody(context.Background(), reqCtx, params)

	action, ok := result.(policy.UpstreamRequestModifications)
	if !ok {
		t.Fatalf("expected UpstreamRequestModifications, got %T: %+v", result, result)
	}
	if got := action.HeadersToSet["Authorization"]; got != "Bearer exchanged-token" {
		t.Errorf("Authorization = %q, want %q", got, "Bearer exchanged-token")
	}
}

func TestOnRequestBody_HeaderPrefix_Empty(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "exchanged-token",
			"expires_in":   300,
		})
	}))
	defer server.Close()
	utils.SetSharedHTTPClient(server.Client())
	defer utils.SetSharedHTTPClient(nil)

	p := newTestPolicy()
	reqCtx := newRequestContext(map[string][]string{"Authorization": {"Bearer original-client-token"}}, "/pets")
	params := baseParams(server.URL)
	params["headerPrefix"] = ""
	result := p.OnRequestBody(context.Background(), reqCtx, params)

	action, ok := result.(policy.UpstreamRequestModifications)
	if !ok {
		t.Fatalf("expected UpstreamRequestModifications, got %T: %+v", result, result)
	}
	if got := action.HeadersToSet["Authorization"]; got != "exchanged-token" {
		t.Errorf("Authorization = %q, want %q", got, "exchanged-token")
	}
}

func TestOnRequestBody_JwtBearer_Success(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatalf("parse form: %v", err)
		}
		if got := r.PostForm.Get("grant_type"); got != grantTypeJwtBearerURN {
			t.Errorf("grant_type = %q, want %q", got, grantTypeJwtBearerURN)
		}
		if got := r.PostForm.Get("assertion"); got != "original-client-token" {
			t.Errorf("assertion = %q, want original-client-token", got)
		}
		if r.PostForm.Has("subject_token_type") {
			t.Errorf("subject_token_type must not be sent for JwtBearer grant")
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"access_token": "exchanged-token", "expires_in": 300})
	}))
	defer server.Close()
	utils.SetSharedHTTPClient(server.Client())
	defer utils.SetSharedHTTPClient(nil)

	p := newTestPolicy()
	params := baseParams(server.URL)
	params["grantType"] = "JwtBearer"
	reqCtx := newRequestContext(map[string][]string{"Authorization": {"Bearer original-client-token"}}, "/pets")
	result := p.OnRequestBody(context.Background(), reqCtx, params)

	if _, ok := result.(policy.UpstreamRequestModifications); !ok {
		t.Fatalf("expected UpstreamRequestModifications, got %T: %+v", result, result)
	}
}

func TestOnRequestBody_CacheHitAvoidsSecondCall(t *testing.T) {
	var hits int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"access_token": "exchanged-token", "expires_in": 300})
	}))
	defer server.Close()
	utils.SetSharedHTTPClient(server.Client())
	defer utils.SetSharedHTTPClient(nil)

	p := newTestPolicy()
	params := baseParams(server.URL)
	reqCtx := newRequestContext(map[string][]string{"Authorization": {"Bearer original-client-token"}}, "/pets")

	for i := 0; i < 2; i++ {
		result := p.OnRequestBody(context.Background(), reqCtx, params)
		if _, ok := result.(policy.UpstreamRequestModifications); !ok {
			t.Fatalf("call %d: expected UpstreamRequestModifications, got %T", i, result)
		}
	}
	if atomic.LoadInt32(&hits) != 1 {
		t.Errorf("expected exactly 1 token endpoint call across 2 requests, got %d", hits)
	}
}

func TestOnRequestBody_ClientSecretPost(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatalf("parse form: %v", err)
		}
		if _, _, ok := r.BasicAuth(); ok {
			t.Errorf("expected no Basic auth header for ClientSecretPost")
		}
		if got := r.PostForm.Get("client_id"); got != "test-client" {
			t.Errorf("client_id = %q", got)
		}
		if got := r.PostForm.Get("client_secret"); got != "test-secret" {
			t.Errorf("client_secret = %q", got)
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"access_token": "exchanged-token", "expires_in": 300})
	}))
	defer server.Close()
	utils.SetSharedHTTPClient(server.Client())
	defer utils.SetSharedHTTPClient(nil)

	p := newTestPolicy()
	params := baseParams(server.URL)
	params["clientAuthMethod"] = "ClientSecretPost"
	reqCtx := newRequestContext(map[string][]string{"Authorization": {"Bearer original-client-token"}}, "/pets")
	result := p.OnRequestBody(context.Background(), reqCtx, params)
	if _, ok := result.(policy.UpstreamRequestModifications); !ok {
		t.Fatalf("expected UpstreamRequestModifications, got %T", result)
	}
}

// ─── OnRequestBody: fail-closed paths ────────────────────────────────────

func TestOnRequestBody_MissingSubjectToken_ReturnsUnauthorized(t *testing.T) {
	p := newTestPolicy()
	reqCtx := newRequestContext(map[string][]string{}, "/pets")
	result := p.OnRequestBody(context.Background(), reqCtx, baseParams("https://example.com/token"))

	resp, ok := result.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("expected ImmediateResponse, got %T", result)
	}
	if resp.StatusCode != 401 {
		t.Errorf("status = %d, want 401", resp.StatusCode)
	}
	if string(resp.Body) != `{"error":"unauthorized","message":"Invalid or expired credentials."}` {
		t.Errorf("unexpected body leaking detail: %s", resp.Body)
	}
}

func TestOnRequestBody_TokenEndpointNon2xx_ReturnsBadGatewayNoLeak(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "super secret internal stack trace and DB dsn", http.StatusInternalServerError)
	}))
	defer server.Close()
	utils.SetSharedHTTPClient(server.Client())
	defer utils.SetSharedHTTPClient(nil)

	p := newTestPolicy()
	reqCtx := newRequestContext(map[string][]string{"Authorization": {"Bearer original-client-token"}}, "/pets")
	result := p.OnRequestBody(context.Background(), reqCtx, baseParams(server.URL))

	resp, ok := result.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("expected ImmediateResponse, got %T", result)
	}
	if resp.StatusCode != 502 {
		t.Errorf("status = %d, want 502", resp.StatusCode)
	}
	if got := string(resp.Body); strings.Contains(got, "secret") || strings.Contains(got, "DB dsn") || strings.Contains(got, "stack") {
		t.Errorf("response body leaked upstream detail: %s", got)
	}
}

func TestOnRequestBody_MalformedJSON_ReturnsBadGateway(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("not json"))
	}))
	defer server.Close()
	utils.SetSharedHTTPClient(server.Client())
	defer utils.SetSharedHTTPClient(nil)

	p := newTestPolicy()
	reqCtx := newRequestContext(map[string][]string{"Authorization": {"Bearer original-client-token"}}, "/pets")
	result := p.OnRequestBody(context.Background(), reqCtx, baseParams(server.URL))

	resp, ok := result.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("expected ImmediateResponse, got %T", result)
	}
	if resp.StatusCode != 502 {
		t.Errorf("status = %d, want 502", resp.StatusCode)
	}
}

func TestOnRequestBody_MissingAccessToken_ReturnsBadGateway(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"token_type": "Bearer"})
	}))
	defer server.Close()
	utils.SetSharedHTTPClient(server.Client())
	defer utils.SetSharedHTTPClient(nil)

	p := newTestPolicy()
	reqCtx := newRequestContext(map[string][]string{"Authorization": {"Bearer original-client-token"}}, "/pets")
	result := p.OnRequestBody(context.Background(), reqCtx, baseParams(server.URL))

	resp, ok := result.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("expected ImmediateResponse, got %T", result)
	}
	if resp.StatusCode != 502 {
		t.Errorf("status = %d, want 502", resp.StatusCode)
	}
}

// TestOnRequestBody_NilSharedHTTPClient_FallsBackAndBlocksLoopback verifies
// that a nil shared client no longer hard-fails: performTokenExchange falls
// back to fallbackHTTPClient instead. That fallback client still enforces
// the SSRF dial-time guard, so it refuses to connect to the httptest server
// here (bound to the loopback address) — this still surfaces as a 502, but
// now because the guard blocked the destination, not because no client was
// configured. See TestFallbackHTTPClient_BlocksLoopbackDestination below for
// a direct test of the guard itself.
func TestOnRequestBody_NilSharedHTTPClient_FallsBackAndBlocksLoopback(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("token endpoint should never be reached: fallback client must block loopback destinations")
	}))
	defer server.Close()
	utils.SetSharedHTTPClient(nil)

	p := newTestPolicy()
	reqCtx := newRequestContext(map[string][]string{"Authorization": {"Bearer original-client-token"}}, "/pets")
	result := p.OnRequestBody(context.Background(), reqCtx, baseParams(server.URL))

	resp, ok := result.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("expected ImmediateResponse, got %T", result)
	}
	if resp.StatusCode != 502 {
		t.Errorf("status = %d, want 502", resp.StatusCode)
	}
}

// ─── OnRequestHeaders: optimistic header-phase attempt ──────────────────────

func TestOnRequestHeaders_Success_SetsHeaderAndMarksSucceeded(t *testing.T) {
	var hits int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"access_token": "exchanged-token", "expires_in": 300})
	}))
	defer server.Close()
	utils.SetSharedHTTPClient(server.Client())
	defer utils.SetSharedHTTPClient(nil)

	p := newTestPolicy()
	shared := newSharedContext()
	headerCtx := newRequestHeaderContext(shared, map[string][]string{"Authorization": {"Bearer original-client-token"}}, "/pets")
	result := p.OnRequestHeaders(context.Background(), headerCtx, baseParams(server.URL))

	action, ok := result.(policy.UpstreamRequestHeaderModifications)
	if !ok {
		t.Fatalf("expected UpstreamRequestHeaderModifications, got %T: %+v", result, result)
	}
	if got := action.HeadersToSet["Authorization"]; got != "Bearer exchanged-token" {
		t.Errorf("Authorization = %q, want %q", got, "Bearer exchanged-token")
	}
	if atomic.LoadInt32(&hits) != 1 {
		t.Errorf("expected exactly 1 token endpoint call, got %d", hits)
	}
	if !headerPhaseSucceeded(shared) {
		t.Error("expected headerPhaseSucceeded to be true after a successful header-phase exchange")
	}
}

func TestOnRequestHeaders_SubjectTokenMissing_DefersWithoutRejecting(t *testing.T) {
	p := newTestPolicy()
	shared := newSharedContext()
	headerCtx := newRequestHeaderContext(shared, map[string][]string{}, "/pets")
	result := p.OnRequestHeaders(context.Background(), headerCtx, baseParams("https://example.com/token"))

	action, ok := result.(policy.UpstreamRequestHeaderModifications)
	if !ok {
		t.Fatalf("expected UpstreamRequestHeaderModifications (never a rejection), got %T: %+v", result, result)
	}
	if len(action.HeadersToSet) != 0 {
		t.Errorf("expected no headers to be set, got %+v", action.HeadersToSet)
	}
	if headerPhaseSucceeded(shared) {
		t.Error("expected headerPhaseSucceeded to be false when the subject token is missing")
	}
	if got := shared.Metadata[metadataKeyHeaderPhaseOutcome]; got != headerPhaseOutcomeDeferred {
		t.Errorf("headerPhaseOutcome = %v, want %q", got, headerPhaseOutcomeDeferred)
	}
}

// TestOnRequestHeaders_ExchangeFails_RejectsImmediately verifies the
// distinction this dual-phase design draws between the two ways the header
// phase can come up empty: a missing subject token is routine deferral (it
// may simply arrive later), but a credential that WAS present and still
// failed the call to the token endpoint is rejected immediately, right here
// — an ImmediateResponse at the header phase short-circuits the whole
// chain, so OnRequestBody never even runs for this request.
func TestOnRequestHeaders_ExchangeFails_RejectsImmediately(t *testing.T) {
	var hits int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		http.Error(w, "token endpoint down", http.StatusInternalServerError)
	}))
	defer server.Close()
	utils.SetSharedHTTPClient(server.Client())
	defer utils.SetSharedHTTPClient(nil)

	p := newTestPolicy()
	shared := newSharedContext()
	headerCtx := newRequestHeaderContext(shared, map[string][]string{"Authorization": {"Bearer original-client-token"}}, "/pets")
	result := p.OnRequestHeaders(context.Background(), headerCtx, baseParams(server.URL))

	resp, ok := result.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("expected ImmediateResponse, got %T: %+v", result, result)
	}
	if resp.StatusCode != 502 {
		t.Errorf("status = %d, want 502", resp.StatusCode)
	}
	if headerPhaseSucceeded(shared) {
		t.Error("expected headerPhaseSucceeded to be false when the exchange call fails")
	}
	if atomic.LoadInt32(&hits) != 1 {
		t.Errorf("expected exactly 1 token endpoint call, got %d", hits)
	}
}

func TestOnRequestHeaders_InvalidConfig_RejectsImmediately(t *testing.T) {
	p := newTestPolicy()
	shared := newSharedContext()
	headerCtx := newRequestHeaderContext(shared, map[string][]string{"Authorization": {"Bearer original-client-token"}}, "/pets")
	params := baseParams("https://example.com/token")
	params["grantType"] = "NotAGrantType"
	result := p.OnRequestHeaders(context.Background(), headerCtx, params)

	resp, ok := result.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("expected ImmediateResponse, got %T: %+v", result, result)
	}
	if resp.StatusCode != 500 {
		t.Errorf("status = %d, want 500", resp.StatusCode)
	}
	if headerPhaseSucceeded(shared) {
		t.Error("expected headerPhaseSucceeded to be false on invalid config")
	}
}

// ─── OnRequestHeaders + OnRequestBody: dual-phase interaction ───────────────

func TestOnRequestBody_SkipsExchangeWhenHeaderPhaseSucceeded(t *testing.T) {
	var hits int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"access_token": "exchanged-token", "expires_in": 300})
	}))
	defer server.Close()
	utils.SetSharedHTTPClient(server.Client())
	defer utils.SetSharedHTTPClient(nil)

	p := newTestPolicy()
	shared := newSharedContext()
	headers := map[string][]string{"Authorization": {"Bearer original-client-token"}}
	params := baseParams(server.URL)

	headerCtx := newRequestHeaderContext(shared, headers, "/pets")
	if _, ok := p.OnRequestHeaders(context.Background(), headerCtx, params).(policy.UpstreamRequestHeaderModifications); !ok {
		t.Fatal("expected the header phase to succeed")
	}
	if atomic.LoadInt32(&hits) != 1 {
		t.Fatalf("expected exactly 1 token endpoint call after the header phase, got %d", hits)
	}

	// The kernel carries the same SharedContext into the body phase.
	bodyCtx := newRequestContextSharing(shared, headers, "/pets")
	result := p.OnRequestBody(context.Background(), bodyCtx, params)

	action, ok := result.(policy.UpstreamRequestModifications)
	if !ok {
		t.Fatalf("expected UpstreamRequestModifications, got %T: %+v", result, result)
	}
	if len(action.HeadersToSet) != 0 {
		t.Errorf("expected OnRequestBody to set no headers once the header phase already succeeded, got %+v", action.HeadersToSet)
	}
	if atomic.LoadInt32(&hits) != 1 {
		t.Errorf("expected no additional token endpoint call from OnRequestBody, got %d total", hits)
	}
}

// TestOnRequestBody_RetriesAfterHeaderPhaseDeferred_Success simulates the
// scenario this dual-phase design exists for: the subject token is supplied
// by a body-phase auth policy earlier in the chain (e.g. mcp-auth forwarding
// a validated token under an operator-configured header) that has not run
// yet when OnRequestHeaders executes, so the header phase defers — then by
// the time OnRequestBody runs, that earlier policy has added the header to
// the live request state, and the retry succeeds.
func TestOnRequestBody_RetriesAfterHeaderPhaseDeferred_Success(t *testing.T) {
	var hits int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"access_token": "exchanged-token", "expires_in": 300})
	}))
	defer server.Close()
	utils.SetSharedHTTPClient(server.Client())
	defer utils.SetSharedHTTPClient(nil)

	p := newTestPolicy()
	shared := newSharedContext()
	params := baseParams(server.URL)

	headerCtx := newRequestHeaderContext(shared, map[string][]string{}, "/pets")
	if _, ok := p.OnRequestHeaders(context.Background(), headerCtx, params).(policy.UpstreamRequestHeaderModifications); !ok {
		t.Fatal("expected the header phase to defer, not reject")
	}
	if headerPhaseSucceeded(shared) {
		t.Fatal("expected headerPhaseSucceeded to be false after deferral")
	}
	if atomic.LoadInt32(&hits) != 0 {
		t.Fatalf("expected no token endpoint call while the subject token was absent, got %d", hits)
	}

	// An earlier-in-chain body-phase policy has since added the credential.
	bodyCtx := newRequestContextSharing(shared, map[string][]string{"Authorization": {"Bearer original-client-token"}}, "/pets")
	result := p.OnRequestBody(context.Background(), bodyCtx, params)

	action, ok := result.(policy.UpstreamRequestModifications)
	if !ok {
		t.Fatalf("expected UpstreamRequestModifications, got %T: %+v", result, result)
	}
	if got := action.HeadersToSet["Authorization"]; got != "Bearer exchanged-token" {
		t.Errorf("Authorization = %q, want %q", got, "Bearer exchanged-token")
	}
	if atomic.LoadInt32(&hits) != 1 {
		t.Errorf("expected exactly 1 token endpoint call (from the body-phase retry), got %d", hits)
	}
}

func TestOnRequestBody_RetriesAfterHeaderPhaseDeferred_StillMissing_ReturnsUnauthorized(t *testing.T) {
	p := newTestPolicy()
	shared := newSharedContext()
	params := baseParams("https://example.com/token")

	headerCtx := newRequestHeaderContext(shared, map[string][]string{}, "/pets")
	p.OnRequestHeaders(context.Background(), headerCtx, params)

	bodyCtx := newRequestContextSharing(shared, map[string][]string{}, "/pets")
	result := p.OnRequestBody(context.Background(), bodyCtx, params)

	resp, ok := result.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("expected ImmediateResponse, got %T", result)
	}
	if resp.StatusCode != 401 {
		t.Errorf("status = %d, want 401", resp.StatusCode)
	}
}

func TestMode_RequestHeaderModeIsProcess(t *testing.T) {
	p := newTestPolicy()
	if got := p.Mode().RequestHeaderMode; got != policy.HeaderModeProcess {
		t.Errorf("RequestHeaderMode = %v, want %v", got, policy.HeaderModeProcess)
	}
}

// ─── fallbackHTTPClient / isDeniedDestination ───────────────────────────────

func TestFallbackHTTPClient_BlocksLoopbackDestination(t *testing.T) {
	client := fallbackHTTPClient()
	req, err := http.NewRequest(http.MethodGet, "http://127.0.0.1:1/", nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	if _, err := client.Do(req); err == nil {
		t.Error("expected fallback client to refuse dialing a loopback address")
	}
}

func TestFallbackHTTPClient_NeverAutoFollowsRedirects(t *testing.T) {
	client := fallbackHTTPClient()
	if client.CheckRedirect == nil {
		t.Fatal("expected CheckRedirect to be set")
	}
	if err := client.CheckRedirect(&http.Request{}, nil); err != http.ErrUseLastResponse {
		t.Errorf("CheckRedirect = %v, want http.ErrUseLastResponse", err)
	}
}

func TestIsDeniedDestination(t *testing.T) {
	denied := []string{
		"127.0.0.1", "10.1.2.3", "172.16.0.5", "192.168.1.1",
		"169.254.169.254", "::1", "fe80::1", "fd12:3456:789a::1",
	}
	for _, ip := range denied {
		if !isDeniedDestination(net.ParseIP(ip)) {
			t.Errorf("isDeniedDestination(%q) = false, want true", ip)
		}
	}

	allowed := []string{"93.184.216.34", "8.8.8.8", "2001:4860:4860::8888"}
	for _, ip := range allowed {
		if isDeniedDestination(net.ParseIP(ip)) {
			t.Errorf("isDeniedDestination(%q) = true, want false", ip)
		}
	}
}

func TestOnRequestBody_InvalidConfig_ReturnsInternalError(t *testing.T) {
	p := newTestPolicy()
	reqCtx := newRequestContext(map[string][]string{"Authorization": {"Bearer original-client-token"}}, "/pets")
	params := baseParams("https://example.com/token")
	params["grantType"] = "NotAGrantType"
	result := p.OnRequestBody(context.Background(), reqCtx, params)

	resp, ok := result.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("expected ImmediateResponse, got %T", result)
	}
	if resp.StatusCode != 500 {
		t.Errorf("status = %d, want 500", resp.StatusCode)
	}
}

// ─── extractSubjectToken ─────────────────────────────────────────────────────

func TestExtractSubjectToken_Header(t *testing.T) {
	reqCtx := newRequestContext(map[string][]string{"Authorization": {"Bearer abc123"}}, "/pets")
	tok, ok := extractSubjectToken(reqCtx.Headers, reqCtx.Path, subjectTokenSource{kind: "header", name: "Authorization", prefix: "Bearer "})
	if !ok || tok != "abc123" {
		t.Errorf("got (%q, %v), want (abc123, true)", tok, ok)
	}
}

func TestExtractSubjectToken_Header_WrongPrefix(t *testing.T) {
	reqCtx := newRequestContext(map[string][]string{"Authorization": {"Basic abc123"}}, "/pets")
	_, ok := extractSubjectToken(reqCtx.Headers, reqCtx.Path, subjectTokenSource{kind: "header", name: "Authorization", prefix: "Bearer "})
	if ok {
		t.Error("expected no match when prefix doesn't match")
	}
}

// TestExtractSubjectToken_Header_CaseInsensitive guards against a known
// engine gap: the body-phase header-modification merge does not lowercase
// keys the way the header-phase merge does, so an earlier body-phase policy
// forwarding a token under its configured casing (e.g. "X-Forwarded-
// Authorization", the canonical form Go's http.CanonicalHeaderKey always
// produces) can land in the live header map under that exact mixed case.
// extractSubjectToken must still find it even though Headers.Get() itself
// only matches lowercased keys.
func TestExtractSubjectToken_Header_CaseInsensitive(t *testing.T) {
	reqCtx := newRequestContext(map[string][]string{}, "/pets")
	reqCtx.Headers.UnsafeInternalValues()["X-Forwarded-Authorization"] = []string{"abc123"}

	tok, ok := extractSubjectToken(reqCtx.Headers, reqCtx.Path, subjectTokenSource{kind: "header", name: "x-forwarded-authorization"})
	if !ok || tok != "abc123" {
		t.Errorf("got (%q, %v), want (abc123, true)", tok, ok)
	}
}

func TestExtractSubjectToken_Cookie(t *testing.T) {
	reqCtx := newRequestContext(map[string][]string{"Cookie": {"session=abc123; other=xyz"}}, "/pets")
	tok, ok := extractSubjectToken(reqCtx.Headers, reqCtx.Path, subjectTokenSource{kind: "cookie", name: "session"})
	if !ok || tok != "abc123" {
		t.Errorf("got (%q, %v), want (abc123, true)", tok, ok)
	}
}

func TestExtractSubjectToken_QueryParameter(t *testing.T) {
	reqCtx := newRequestContext(map[string][]string{}, "/pets?access_token=abc123&other=1")
	tok, ok := extractSubjectToken(reqCtx.Headers, reqCtx.Path, subjectTokenSource{kind: "queryParameter", name: "access_token"})
	if !ok || tok != "abc123" {
		t.Errorf("got (%q, %v), want (abc123, true)", tok, ok)
	}
}

// ─── Validate / parseConfig ──────────────────────────────────────────────────

func TestValidate_RejectsHTTPTokenEndpoint_ByDefault(t *testing.T) {
	p := newTestPolicy()
	err := p.Validate(baseParams("http://example.com/token"))
	if err == nil {
		t.Error("expected error rejecting http:// tokenEndpoint by default")
	}
}

func TestValidate_AllowsHTTPTokenEndpoint_WhenOverrideSet(t *testing.T) {
	p := newTestPolicy()
	params := baseParams("http://example.com/token")
	params["allowInsecureTokenEndpoint"] = true
	if err := p.Validate(params); err != nil {
		t.Errorf("unexpected error with allowInsecureTokenEndpoint set: %v", err)
	}
}

func TestValidate_MissingClientCredentials(t *testing.T) {
	p := newTestPolicy()
	err := p.Validate(map[string]interface{}{"tokenEndpoint": "https://example.com/token"})
	if err == nil {
		t.Error("expected error for missing clientId/clientSecret")
	}
}

func TestValidate_RejectsUnknownGrantType(t *testing.T) {
	p := newTestPolicy()
	params := baseParams("https://example.com/token")
	params["grantType"] = "AuthorizationCode"
	if err := p.Validate(params); err == nil {
		t.Error("expected error for unsupported grantType")
	}
}

func TestValidate_RejectsUnknownScheme(t *testing.T) {
	p := newTestPolicy()
	err := p.Validate(baseParams("ftp://example.com/token"))
	if err == nil {
		t.Error("expected error for non-http(s) scheme")
	}
}

func TestValidate_RejectsMissingHost(t *testing.T) {
	p := newTestPolicy()
	err := p.Validate(baseParams("https:///token"))
	if err == nil {
		t.Error("expected error for tokenEndpoint with no host")
	}
}

func TestValidate_ValidConfig(t *testing.T) {
	p := newTestPolicy()
	if err := p.Validate(baseParams("https://example.com/token")); err != nil {
		t.Errorf("unexpected error for valid config: %v", err)
	}
}

// ─── buildCacheKey ────────────────────────────────────────────────────────

func TestBuildCacheKey_DifferentSubjectTokensDifferentKeys(t *testing.T) {
	cfg := &exchangeConfig{tokenEndpoint: mustParseURL(t, "https://example.com/token"), clientID: "c", grantType: "TokenExchange"}
	k1 := buildCacheKey("api", cfg, "token-a")
	k2 := buildCacheKey("api", cfg, "token-b")
	if k1 == k2 {
		t.Error("expected different cache keys for different subject tokens")
	}
}

func mustParseURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}
	return u
}
