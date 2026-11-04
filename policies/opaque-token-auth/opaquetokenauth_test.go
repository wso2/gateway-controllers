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

package opaquetokenauth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"regexp"
	"sync/atomic"
	"testing"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
	"github.com/wso2/api-platform/sdk/core/utils/cache"
)

// ─── Test helpers ────────────────────────────────────────────────────────────

func newPolicy() *OpaqueTokenAuthPolicy {
	return &OpaqueTokenAuthPolicy{
		cache: cache.NewInMemoryCache[*cachedIntrospection](cacheName, cacheMaxSize, 0, cache.LRUEvictionPolicy, slog.Default()),
	}
}

// activeResponder writes the given introspection claims as a JSON response.
func activeResponder(claims map[string]interface{}) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(claims)
	}
}

func newServer(t *testing.T, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	s := httptest.NewServer(handler)
	t.Cleanup(s.Close)
	return s
}

// provider builds a single introspection provider config map.
func provider(name, uri string, introspectionExtra map[string]interface{}) map[string]interface{} {
	introspection := map[string]interface{}{"uri": uri}
	for k, v := range introspectionExtra {
		introspection[k] = v
	}
	return map[string]interface{}{"name": name, "introspection": introspection}
}

// baseParams wraps providers into a params map.
func baseParams(providers ...map[string]interface{}) map[string]interface{} {
	list := make([]interface{}, 0, len(providers))
	for _, p := range providers {
		list = append(list, p)
	}
	return map[string]interface{}{"introspectionProviders": list}
}

func bearerHeader(token string) map[string][]string {
	return map[string][]string{"authorization": {"Bearer " + token}}
}

func execute(t *testing.T, p *OpaqueTokenAuthPolicy, params map[string]interface{}, headers map[string][]string) (*policy.RequestHeaderContext, policy.RequestHeaderAction) {
	t.Helper()
	reqCtx := &policy.RequestHeaderContext{
		SharedContext: &policy.SharedContext{},
		Headers:       policy.NewHeaders(headers),
	}
	action := p.OnRequestHeaders(context.Background(), reqCtx, params)
	return reqCtx, action
}

func assertSuccess(t *testing.T, reqCtx *policy.RequestHeaderContext, action policy.RequestHeaderAction) policy.UpstreamRequestHeaderModifications {
	t.Helper()
	mods, ok := action.(policy.UpstreamRequestHeaderModifications)
	if !ok {
		t.Fatalf("expected UpstreamRequestHeaderModifications, got %T", action)
	}
	if reqCtx.AuthContext == nil || !reqCtx.AuthContext.Authenticated {
		t.Fatalf("expected authenticated AuthContext, got %+v", reqCtx.AuthContext)
	}
	return mods
}

func assertFailure(t *testing.T, reqCtx *policy.RequestHeaderContext, action policy.RequestHeaderAction, statusCode int) policy.ImmediateResponse {
	t.Helper()
	ir, ok := action.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("expected ImmediateResponse, got %T", action)
	}
	if ir.StatusCode != statusCode {
		t.Fatalf("expected status %d, got %d", statusCode, ir.StatusCode)
	}
	if reqCtx.AuthContext == nil || reqCtx.AuthContext.Authenticated {
		t.Fatalf("expected unauthenticated AuthContext, got %+v", reqCtx.AuthContext)
	}
	// Every rejection this policy makes must reach the gateway's fault flow and describe
	// itself well enough for a renderer and for analytics categorisation.
	if !ir.IsFault {
		t.Fatalf("expected IsFault=true on an auth rejection")
	}
	if ir.Fault == nil {
		t.Fatalf("expected Error to be populated on an auth rejection")
	}
	if ir.Fault.Code == "" {
		t.Fatalf("expected Error.Code to be set")
	}
	if ir.Fault.Direction != policy.DirectionRequest {
		t.Fatalf("expected Error.Direction=%q, got %q", policy.DirectionRequest, ir.Fault.Direction)
	}
	return ir
}

// assertRejectionCode asserts the rejection declares a fault and carries exactly the
// wanted code and type, and that the client receives the configured body with none of the
// internal reason in it.
func assertRejectionCode(t *testing.T, ir policy.ImmediateResponse, wantCode, wantType string) {
	t.Helper()
	if want := `{"error":"Unauthorized","message":"Authentication failed"}`; string(ir.Body) != want {
		t.Fatalf("body = %s, want %s", ir.Body, want)
	}
	if ir.Fault.Code != wantCode {
		t.Fatalf("expected Error.Code=%q, got %q", wantCode, ir.Fault.Code)
	}
	if ir.Fault.Type != wantType {
		t.Fatalf("expected Error.Type=%q, got %q", wantType, ir.Fault.Type)
	}
}

// ─── Tests ───────────────────────────────────────────────────────────────────

func TestActiveTokenSucceeds(t *testing.T) {
	srv := newServer(t, activeResponder(map[string]interface{}{
		"active":    true,
		"sub":       "user-123",
		"iss":       "https://idp.example",
		"client_id": "app-1",
		"scope":     "read write",
		"aud":       "my-api",
		"org":       "acme",
	}))
	params := baseParams(provider("idp", srv.URL, nil))

	reqCtx, action := execute(t, newPolicy(), params, bearerHeader("opaque-abc"))
	assertSuccess(t, reqCtx, action)

	ac := reqCtx.AuthContext
	if ac.AuthType != AuthType {
		t.Errorf("AuthType = %q, want %q", ac.AuthType, AuthType)
	}
	if ac.Subject != "user-123" {
		t.Errorf("Subject = %q, want user-123", ac.Subject)
	}
	if ac.Issuer != "https://idp.example" {
		t.Errorf("Issuer = %q", ac.Issuer)
	}
	if ac.CredentialID != "app-1" {
		t.Errorf("CredentialID = %q, want app-1", ac.CredentialID)
	}
	if !ac.Scopes["read"] || !ac.Scopes["write"] {
		t.Errorf("Scopes = %v, want read+write", ac.Scopes)
	}
	if ac.Properties["org"] != "acme" {
		t.Errorf("Properties[org] = %q, want acme", ac.Properties["org"])
	}
}

func TestTokenIdIsTokenSha256(t *testing.T) {
	srv := newServer(t, activeResponder(map[string]interface{}{"active": true, "sub": "u", "jti": "ignored-jti"}))
	params := baseParams(provider("idp", srv.URL, nil))

	reqCtx, action := execute(t, newPolicy(), params, bearerHeader("opaque-xyz"))
	assertSuccess(t, reqCtx, action)

	want := sha256.Sum256([]byte("opaque-xyz"))
	if got := reqCtx.AuthContext.TokenId; got != hex.EncodeToString(want[:]) {
		t.Errorf("TokenId = %q, want sha256(token) %q", got, hex.EncodeToString(want[:]))
	}
}

func TestTokenIdDiffersPerToken(t *testing.T) {
	srv := newServer(t, activeResponder(map[string]interface{}{"active": true, "sub": "u"}))
	params := baseParams(provider("idp", srv.URL, nil))
	p := newPolicy()

	reqCtxA, actionA := execute(t, p, params, bearerHeader("token-A"))
	assertSuccess(t, reqCtxA, actionA)
	reqCtxB, actionB := execute(t, p, params, bearerHeader("token-B"))
	assertSuccess(t, reqCtxB, actionB)

	if reqCtxA.AuthContext.TokenId == reqCtxB.AuthContext.TokenId {
		t.Errorf("TokenId should differ per token, both = %q", reqCtxA.AuthContext.TokenId)
	}
}

func TestInactiveTokenFails(t *testing.T) {
	srv := newServer(t, activeResponder(map[string]interface{}{"active": false}))
	params := baseParams(provider("idp", srv.URL, nil))

	reqCtx, action := execute(t, newPolicy(), params, bearerHeader("opaque-abc"))
	assertFailure(t, reqCtx, action, 401)
}

func TestClientSecretBasic(t *testing.T) {
	var gotUser, gotPass string
	var gotOK bool
	srv := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotUser, gotPass, gotOK = r.BasicAuth()
		activeResponder(map[string]interface{}{"active": true, "sub": "u"})(w, r)
	})
	params := baseParams(provider("idp", srv.URL, map[string]interface{}{
		"clientId": "client-x", "clientSecret": "secret-y", "authStyle": "basic",
	}))

	reqCtx, action := execute(t, newPolicy(), params, bearerHeader("tok"))
	assertSuccess(t, reqCtx, action)
	if !gotOK || gotUser != "client-x" || gotPass != "secret-y" {
		t.Errorf("basic auth = (%q,%q,%v), want (client-x,secret-y,true)", gotUser, gotPass, gotOK)
	}
}

func TestClientSecretPost(t *testing.T) {
	var gotClientID, gotSecret, gotAuthHeader string
	srv := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		gotClientID = r.PostFormValue("client_id")
		gotSecret = r.PostFormValue("client_secret")
		gotAuthHeader = r.Header.Get("Authorization")
		activeResponder(map[string]interface{}{"active": true, "sub": "u"})(w, r)
	})
	params := baseParams(provider("idp", srv.URL, map[string]interface{}{
		"clientId": "client-x", "clientSecret": "secret-y", "authStyle": "post",
	}))

	reqCtx, action := execute(t, newPolicy(), params, bearerHeader("tok"))
	assertSuccess(t, reqCtx, action)
	if gotClientID != "client-x" || gotSecret != "secret-y" {
		t.Errorf("post creds = (%q,%q), want (client-x,secret-y)", gotClientID, gotSecret)
	}
	if gotAuthHeader != "" {
		t.Errorf("Authorization header should be empty for client_secret_post, got %q", gotAuthHeader)
	}
}

func TestStaticBearerToken(t *testing.T) {
	var gotAuth string
	srv := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		activeResponder(map[string]interface{}{"active": true, "sub": "u"})(w, r)
	})
	params := baseParams(provider("idp", srv.URL, map[string]interface{}{
		"bearerToken": "introspect-token",
	}))

	reqCtx, action := execute(t, newPolicy(), params, bearerHeader("tok"))
	assertSuccess(t, reqCtx, action)
	if gotAuth != "Bearer introspect-token" {
		t.Errorf("Authorization = %q, want 'Bearer introspect-token'", gotAuth)
	}
}

func TestTokenAndHintSent(t *testing.T) {
	var gotToken, gotHint string
	srv := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		gotToken = r.PostFormValue("token")
		gotHint = r.PostFormValue("token_type_hint")
		if r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
			t.Errorf("Content-Type = %q", r.Header.Get("Content-Type"))
		}
		activeResponder(map[string]interface{}{"active": true, "sub": "u"})(w, r)
	})
	params := baseParams(provider("idp", srv.URL, nil))

	reqCtx, action := execute(t, newPolicy(), params, bearerHeader("opaque-xyz"))
	assertSuccess(t, reqCtx, action)
	if gotToken != "opaque-xyz" {
		t.Errorf("token = %q, want opaque-xyz", gotToken)
	}
	if gotHint != "access_token" {
		t.Errorf("token_type_hint = %q, want access_token (default)", gotHint)
	}
}

func TestMissingHeaderFails(t *testing.T) {
	srv := newServer(t, activeResponder(map[string]interface{}{"active": true}))
	params := baseParams(provider("idp", srv.URL, nil))

	reqCtx, action := execute(t, newPolicy(), params, map[string][]string{})
	assertFailure(t, reqCtx, action, 401)
}

func TestWrongSchemeFails(t *testing.T) {
	srv := newServer(t, activeResponder(map[string]interface{}{"active": true}))
	params := baseParams(provider("idp", srv.URL, nil))

	headers := map[string][]string{"authorization": {"Basic dXNlcjpwYXNz"}}
	reqCtx, action := execute(t, newPolicy(), params, headers)
	assertFailure(t, reqCtx, action, 401)
}

func TestForwardTokenStripped(t *testing.T) {
	srv := newServer(t, activeResponder(map[string]interface{}{"active": true, "sub": "u"}))
	params := baseParams(provider("idp", srv.URL, nil))
	params["forwardToken"] = false

	reqCtx, action := execute(t, newPolicy(), params, bearerHeader("tok"))
	mods := assertSuccess(t, reqCtx, action)
	if !contains(mods.HeadersToRemove, "Authorization") {
		t.Errorf("expected Authorization to be removed, got %v", mods.HeadersToRemove)
	}
}

func TestForwardTokenMoved(t *testing.T) {
	srv := newServer(t, activeResponder(map[string]interface{}{"active": true, "sub": "u"}))
	params := baseParams(provider("idp", srv.URL, nil))
	// defaults: forwardToken true, forwardedTokenHeader x-forwarded-authorization

	reqCtx, action := execute(t, newPolicy(), params, bearerHeader("tok"))
	mods := assertSuccess(t, reqCtx, action)
	if mods.HeadersToSet["X-Forwarded-Authorization"] != "Bearer tok" {
		t.Errorf("forwarded header = %q, want 'Bearer tok'", mods.HeadersToSet["X-Forwarded-Authorization"])
	}
	if !contains(mods.HeadersToRemove, "Authorization") {
		t.Errorf("expected original Authorization removed, got %v", mods.HeadersToRemove)
	}
}


func TestScopeEnforcement(t *testing.T) {
	// All four scope formats: scope/scp × string/array.
	formats := []struct {
		name   string
		claims map[string]interface{}
	}{
		{"scope as string", map[string]interface{}{"active": true, "sub": "u", "scope": "read write"}},
		{"scope as array", map[string]interface{}{"active": true, "sub": "u", "scope": []interface{}{"read", "write"}}},
		{"scp as string", map[string]interface{}{"active": true, "sub": "u", "scp": "read write"}},
		{"scp as array", map[string]interface{}{"active": true, "sub": "u", "scp": []interface{}{"read", "write"}}},
	}
	for _, tc := range formats {
		t.Run(tc.name+"/pass", func(t *testing.T) {
			srv := newServer(t, activeResponder(tc.claims))
			params := baseParams(provider("idp", srv.URL, nil))
			params["requiredScopes"] = []interface{}{"read"}
			reqCtx, action := execute(t, newPolicy(), params, bearerHeader("tok"))
			assertSuccess(t, reqCtx, action)
		})
		t.Run(tc.name+"/fail", func(t *testing.T) {
			srv := newServer(t, activeResponder(tc.claims))
			params := baseParams(provider("idp", srv.URL, nil))
			params["requiredScopes"] = []interface{}{"admin"}
			reqCtx, action := execute(t, newPolicy(), params, bearerHeader("tok"))
			assertFailure(t, reqCtx, action, 401)
		})
	}

	// OR semantics: token has "read"; requiring ["read","admin"] passes because
	// at least one required scope is present.
	t.Run("OR semantics/one match passes", func(t *testing.T) {
		srv := newServer(t, activeResponder(map[string]interface{}{
			"active": true, "sub": "u", "scope": "read",
		}))
		params := baseParams(provider("idp", srv.URL, nil))
		params["requiredScopes"] = []interface{}{"read", "admin"}
		reqCtx, action := execute(t, newPolicy(), params, bearerHeader("tok"))
		assertSuccess(t, reqCtx, action)
	})

	// OR semantics: token has neither required scope → fails.
	t.Run("OR semantics/no match fails", func(t *testing.T) {
		srv := newServer(t, activeResponder(map[string]interface{}{
			"active": true, "sub": "u", "scope": "read",
		}))
		params := baseParams(provider("idp", srv.URL, nil))
		params["requiredScopes"] = []interface{}{"write", "admin"}
		reqCtx, action := execute(t, newPolicy(), params, bearerHeader("tok"))
		assertFailure(t, reqCtx, action, 401)
	})
}

func TestAudienceEnforcement(t *testing.T) {
	srv := newServer(t, activeResponder(map[string]interface{}{
		"active": true, "sub": "u", "aud": []interface{}{"api-a", "api-b"},
	}))

	t.Run("pass", func(t *testing.T) {
		params := baseParams(provider("idp", srv.URL, nil))
		params["audiences"] = []interface{}{"api-b"}
		reqCtx, action := execute(t, newPolicy(), params, bearerHeader("tok"))
		assertSuccess(t, reqCtx, action)
	})
	t.Run("fail", func(t *testing.T) {
		params := baseParams(provider("idp", srv.URL, nil))
		params["audiences"] = []interface{}{"api-c"}
		reqCtx, action := execute(t, newPolicy(), params, bearerHeader("tok"))
		assertFailure(t, reqCtx, action, 401)
	})
}

func TestRequiredClaims(t *testing.T) {
	srv := newServer(t, activeResponder(map[string]interface{}{
		"active": true, "sub": "u", "tenant": "acme",
	}))

	t.Run("pass", func(t *testing.T) {
		params := baseParams(provider("idp", srv.URL, nil))
		params["requiredClaims"] = map[string]interface{}{"tenant": "acme"}
		reqCtx, action := execute(t, newPolicy(), params, bearerHeader("tok"))
		assertSuccess(t, reqCtx, action)
	})
	t.Run("fail", func(t *testing.T) {
		params := baseParams(provider("idp", srv.URL, nil))
		params["requiredClaims"] = map[string]interface{}{"tenant": "other"}
		reqCtx, action := execute(t, newPolicy(), params, bearerHeader("tok"))
		assertFailure(t, reqCtx, action, 401)
	})
}

func TestProviderFallback(t *testing.T) {
	inactive := newServer(t, activeResponder(map[string]interface{}{"active": false}))
	active := newServer(t, activeResponder(map[string]interface{}{"active": true, "sub": "u2"}))
	params := baseParams(
		provider("idp-a", inactive.URL, nil),
		provider("idp-b", active.URL, nil),
	)

	reqCtx, action := execute(t, newPolicy(), params, bearerHeader("tok"))
	assertSuccess(t, reqCtx, action)
	if reqCtx.AuthContext.Subject != "u2" {
		t.Errorf("Subject = %q, want u2 (from second provider)", reqCtx.AuthContext.Subject)
	}
}

func TestIssuerSelection(t *testing.T) {
	var aCount, bCount int64
	srvA := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&aCount, 1)
		activeResponder(map[string]interface{}{"active": true, "sub": "ua"})(w, r)
	})
	srvB := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&bCount, 1)
		activeResponder(map[string]interface{}{"active": true, "sub": "ub"})(w, r)
	})
	params := baseParams(
		provider("idp-a", srvA.URL, nil),
		provider("idp-b", srvB.URL, nil),
	)
	params["issuers"] = []interface{}{"idp-b"}

	reqCtx, action := execute(t, newPolicy(), params, bearerHeader("tok"))
	assertSuccess(t, reqCtx, action)
	if reqCtx.AuthContext.Subject != "ub" {
		t.Errorf("Subject = %q, want ub", reqCtx.AuthContext.Subject)
	}
	if atomic.LoadInt64(&aCount) != 0 {
		t.Errorf("provider idp-a should not be called, got %d calls", aCount)
	}
	if atomic.LoadInt64(&bCount) != 1 {
		t.Errorf("provider idp-b calls = %d, want 1", bCount)
	}
}

func TestNoProvidersConfiguredFails(t *testing.T) {
	params := map[string]interface{}{}
	reqCtx, action := execute(t, newPolicy(), params, bearerHeader("tok"))
	assertFailure(t, reqCtx, action, 401)
}

func TestIssuerSelectionNoMatchFails(t *testing.T) {
	srv := newServer(t, activeResponder(map[string]interface{}{"active": true}))
	params := baseParams(provider("idp", srv.URL, nil))
	params["issuers"] = []interface{}{"nonexistent"}

	reqCtx, action := execute(t, newPolicy(), params, bearerHeader("tok"))
	assertFailure(t, reqCtx, action, 401)
}

func TestMode(t *testing.T) {
	m := newPolicy().Mode()
	if m.RequestHeaderMode != policy.HeaderModeProcess {
		t.Errorf("RequestHeaderMode = %v, want PROCESS", m.RequestHeaderMode)
	}
	if m.RequestBodyMode != policy.BodyModeSkip || m.ResponseHeaderMode != policy.HeaderModeSkip || m.ResponseBodyMode != policy.BodyModeSkip {
		t.Errorf("expected all non-request-header modes to be SKIP, got %+v", m)
	}
}

func TestGetPolicy(t *testing.T) {
	p, err := GetPolicy(policy.PolicyMetadata{}, nil)
	if err != nil || p == nil {
		t.Fatalf("GetPolicy returned (%v, %v)", p, err)
	}
}

// ─── Negative caching tests ───────────────────────────────────────────────────

func TestNegativeCachingCachesInactiveResponse(t *testing.T) {
	var hitCount int64
	srv := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&hitCount, 1)
		activeResponder(map[string]interface{}{"active": false})(w, r)
	})
	params := baseParams(provider("idp", srv.URL, nil))
	params["introspectionNegativeCacheTtl"] = "30s"

	p := newPolicy()
	// First request — cache miss, hits the server.
	reqCtx1, action1 := execute(t, p, params, bearerHeader("inactive-tok"))
	assertFailure(t, reqCtx1, action1, 401)

	// Second request with same token — should be served from negative cache.
	reqCtx2, action2 := execute(t, p, params, bearerHeader("inactive-tok"))
	assertFailure(t, reqCtx2, action2, 401)

	if got := atomic.LoadInt64(&hitCount); got != 1 {
		t.Errorf("introspection endpoint called %d times, want 1 (negative cache should serve second request)", got)
	}
}

func TestNegativeCachingDisabledWhenZero(t *testing.T) {
	var hitCount int64
	srv := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&hitCount, 1)
		activeResponder(map[string]interface{}{"active": false})(w, r)
	})
	params := baseParams(provider("idp", srv.URL, nil))
	params["introspectionNegativeCacheTtl"] = "0s"

	p := newPolicy()
	execute(t, p, params, bearerHeader("inactive-tok"))
	execute(t, p, params, bearerHeader("inactive-tok"))

	if got := atomic.LoadInt64(&hitCount); got != 2 {
		t.Errorf("introspection endpoint called %d times, want 2 (negative cache disabled)", got)
	}
}

func TestNegativeCachingNotAppliedOnTransportError(t *testing.T) {
	// Use a server that closes connections immediately to simulate a transport error.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Close with a non-200 status to trigger the "status != 200" error path.
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	t.Cleanup(srv.Close)

	params := baseParams(provider("idp", srv.URL, nil))
	params["introspectionNegativeCacheTtl"] = "30s"
	params["introspectionRetryCount"] = 0

	p := newPolicy()
	// Both requests should hit the server — errors must not be negatively cached.
	var serverCalls int64
	srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&serverCalls, 1)
		w.WriteHeader(http.StatusServiceUnavailable)
	})

	execute(t, p, params, bearerHeader("some-tok"))
	execute(t, p, params, bearerHeader("some-tok"))

	if got := atomic.LoadInt64(&serverCalls); got != 2 {
		t.Errorf("introspection endpoint called %d times, want 2 (errors must not be cached)", got)
	}
}

// ─── Token pattern routing ────────────────────────────────────────────────────

func TestTokenPatternRoutesToMatchingProvider(t *testing.T) {
	var localCount, asgardeoCount int64
	localSrv := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&localCount, 1)
		activeResponder(map[string]interface{}{"active": true, "sub": "local-user"})(w, r)
	})
	asgardeoSrv := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&asgardeoCount, 1)
		activeResponder(map[string]interface{}{"active": true, "sub": "asgardeo-user"})(w, r)
	})

	localProvider := provider("local-mock", localSrv.URL, nil)
	localProvider["tokenPattern"] = "^opaque_"
	asgardeoProvider := provider("asgardeo", asgardeoSrv.URL, nil)
	asgardeoProvider["tokenPattern"] = "^[0-9a-f]{8}-" // UUID-like prefix

	params := baseParams(localProvider, asgardeoProvider)

	t.Run("opaque prefix routes to local", func(t *testing.T) {
		atomic.StoreInt64(&localCount, 0)
		atomic.StoreInt64(&asgardeoCount, 0)
		reqCtx, action := execute(t, newPolicy(), params, bearerHeader("opaque_abc123"))
		assertSuccess(t, reqCtx, action)
		if reqCtx.AuthContext.Subject != "local-user" {
			t.Errorf("Subject = %q, want local-user", reqCtx.AuthContext.Subject)
		}
		if atomic.LoadInt64(&localCount) != 1 {
			t.Errorf("local provider calls = %d, want 1", localCount)
		}
		if atomic.LoadInt64(&asgardeoCount) != 0 {
			t.Errorf("asgardeo provider should not be called, got %d calls", asgardeoCount)
		}
	})

	t.Run("UUID prefix routes to asgardeo", func(t *testing.T) {
		atomic.StoreInt64(&localCount, 0)
		atomic.StoreInt64(&asgardeoCount, 0)
		reqCtx, action := execute(t, newPolicy(), params, bearerHeader("a1b2c3d4-e5f6-7890-abcd-ef1234567890"))
		assertSuccess(t, reqCtx, action)
		if reqCtx.AuthContext.Subject != "asgardeo-user" {
			t.Errorf("Subject = %q, want asgardeo-user", reqCtx.AuthContext.Subject)
		}
		if atomic.LoadInt64(&localCount) != 0 {
			t.Errorf("local provider should not be called, got %d calls", localCount)
		}
		if atomic.LoadInt64(&asgardeoCount) != 1 {
			t.Errorf("asgardeo provider calls = %d, want 1", asgardeoCount)
		}
	})
}

func TestTokenPatternNoMatchFails(t *testing.T) {
	srv := newServer(t, activeResponder(map[string]interface{}{"active": true, "sub": "u"}))
	p := provider("idp", srv.URL, nil)
	p["tokenPattern"] = "^opaque_" // only matches tokens starting with "opaque_"
	params := baseParams(p)

	reqCtx, action := execute(t, newPolicy(), params, bearerHeader("jwt.does.not.match"))
	assertFailure(t, reqCtx, action, 401)
}

func TestTokenPatternAbsentMatchesAll(t *testing.T) {
	srv := newServer(t, activeResponder(map[string]interface{}{"active": true, "sub": "u"}))
	// No tokenPattern set — provider should accept any token (backward compat).
	params := baseParams(provider("idp", srv.URL, nil))

	reqCtx, action := execute(t, newPolicy(), params, bearerHeader("any-token-shape"))
	assertSuccess(t, reqCtx, action)
}

func TestTokenPatternInvalidRegexFails(t *testing.T) {
	srv := newServer(t, activeResponder(map[string]interface{}{"active": true}))
	p := provider("idp", srv.URL, nil)
	p["tokenPattern"] = "[invalid(regex"
	params := baseParams(p)

	// Invalid regex → parseIntrospectionProviders errors → auth failure.
	reqCtx, action := execute(t, newPolicy(), params, bearerHeader("tok"))
	assertFailure(t, reqCtx, action, 401)
}

// TestFilterProvidersByToken exercises the helper directly.
func TestFilterProvidersByToken(t *testing.T) {
	withPattern := func(pattern string) *IntrospectionProvider {
		re, _ := regexp.Compile(pattern)
		return &IntrospectionProvider{TokenPattern: pattern, tokenRegexp: re}
	}
	noPattern := &IntrospectionProvider{}

	all := []*IntrospectionProvider{
		withPattern("^opaque_"),
		withPattern("^uuid-"),
		noPattern,
	}

	t.Run("opaque token selects matching + no-pattern", func(t *testing.T) {
		got := filterProvidersByToken(all, "opaque_abc")
		if len(got) != 2 {
			t.Fatalf("got %d providers, want 2", len(got))
		}
		if got[0].TokenPattern != "^opaque_" {
			t.Errorf("first provider pattern = %q, want ^opaque_", got[0].TokenPattern)
		}
		if got[1].TokenPattern != "" {
			t.Errorf("second provider should be the no-pattern one")
		}
	})

	t.Run("unmatched token selects only no-pattern", func(t *testing.T) {
		got := filterProvidersByToken(all, "other-token")
		if len(got) != 1 || got[0].TokenPattern != "" {
			t.Errorf("got %d providers, want only the no-pattern provider", len(got))
		}
	})

	t.Run("all have patterns and none match returns empty", func(t *testing.T) {
		got := filterProvidersByToken(all[:2], "other-token")
		if len(got) != 0 {
			t.Errorf("got %d providers, want 0", len(got))
		}
	})
}

// ─── Identity claims surfaced in Properties ───────────────────────────────────

func TestUsernameAndWSO2ClaimsInProperties(t *testing.T) {
	srv := newServer(t, activeResponder(map[string]interface{}{
		"active":     true,
		"sub":        "550e8400-e29b-41d4-a716-446655440000",
		"username":   "alice@example.com",
		"token_type": "Bearer",
		"org_id":     "org-123",
		"org_handle": "acme-corp",
		"aut":        "APPLICATION_USER",
	}))
	params := baseParams(provider("idp", srv.URL, nil))

	reqCtx, action := execute(t, newPolicy(), params, bearerHeader("tok"))
	assertSuccess(t, reqCtx, action)

	ac := reqCtx.AuthContext
	if ac.Properties["username"] != "alice@example.com" {
		t.Errorf("Properties[username] = %q, want alice@example.com", ac.Properties["username"])
	}
	if ac.Properties["token_type"] != "Bearer" {
		t.Errorf("Properties[token_type] = %q, want Bearer", ac.Properties["token_type"])
	}
	if ac.Properties["org_handle"] != "acme-corp" {
		t.Errorf("Properties[org_handle] = %q, want acme-corp", ac.Properties["org_handle"])
	}
	if ac.Properties["aut"] != "APPLICATION_USER" {
		t.Errorf("Properties[aut] = %q, want APPLICATION_USER", ac.Properties["aut"])
	}
	if ac.Properties["org_id"] != "org-123" {
		t.Errorf("Properties[org_id] = %q, want org-123", ac.Properties["org_id"])
	}
}

func TestRejectionErrorCodes(t *testing.T) {
	t.Run("no authorization header", func(t *testing.T) {
		srv := newServer(t, activeResponder(map[string]interface{}{"active": true}))
		params := baseParams(provider("idp", srv.URL, nil))
		reqCtx, action := execute(t, newPolicy(), params, map[string][]string{})
		ir := assertFailure(t, reqCtx, action, 401)
		assertRejectionCode(t, ir, policy.FaultCodeAuthMissingCredentials, policy.FaultTypeAuthentication)
	})

	t.Run("wrong scheme", func(t *testing.T) {
		srv := newServer(t, activeResponder(map[string]interface{}{"active": true}))
		params := baseParams(provider("idp", srv.URL, nil))
		headers := map[string][]string{"authorization": {"Basic dXNlcjpwYXNz"}}
		reqCtx, action := execute(t, newPolicy(), params, headers)
		ir := assertFailure(t, reqCtx, action, 401)
		assertRejectionCode(t, ir, policy.FaultCodeAuthInvalidCredentials, policy.FaultTypeAuthentication)
	})

	t.Run("token reported inactive", func(t *testing.T) {
		srv := newServer(t, activeResponder(map[string]interface{}{"active": false}))
		params := baseParams(provider("idp", srv.URL, nil))
		reqCtx, action := execute(t, newPolicy(), params, bearerHeader("tok"))
		ir := assertFailure(t, reqCtx, action, 401)
		assertRejectionCode(t, ir, policy.FaultCodeAuthTokenInactive, policy.FaultTypeAuthentication)
	})

	t.Run("no introspection providers configured", func(t *testing.T) {
		params := map[string]interface{}{"introspectionProviders": []interface{}{}}
		reqCtx, action := execute(t, newPolicy(), params, bearerHeader("tok"))
		ir := assertFailure(t, reqCtx, action, 401)
		assertRejectionCode(t, ir, policy.FaultCodeMediationFailed, policy.FaultTypeConfiguration)
	})

	t.Run("no provider matches the configured issuers", func(t *testing.T) {
		srv := newServer(t, activeResponder(map[string]interface{}{"active": true}))
		params := baseParams(provider("idp", srv.URL, nil))
		params["issuers"] = []interface{}{"nonexistent"}
		reqCtx, action := execute(t, newPolicy(), params, bearerHeader("tok"))
		ir := assertFailure(t, reqCtx, action, 401)
		assertRejectionCode(t, ir, policy.FaultCodeMediationFailed, policy.FaultTypeConfiguration)
	})

	unavailable := func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusServiceUnavailable) }

	t.Run("no authorization server answers", func(t *testing.T) {
		srv := newServer(t, unavailable)
		params := baseParams(provider("idp", srv.URL, nil))
		params["introspectionRetryCount"] = 0
		reqCtx, action := execute(t, newPolicy(), params, bearerHeader("tok"))
		ir := assertFailure(t, reqCtx, action, 401)
		assertRejectionCode(t, ir, policy.FaultCodeMediationFailed, policy.FaultTypeMediation)
	})

	// One server failing must not hide another's answer: the token was judged inactive.
	t.Run("one server fails and another reports the token inactive", func(t *testing.T) {
		down := newServer(t, unavailable)
		up := newServer(t, activeResponder(map[string]interface{}{"active": false}))
		params := baseParams(provider("down", down.URL, nil), provider("up", up.URL, nil))
		params["introspectionRetryCount"] = 0
		reqCtx, action := execute(t, newPolicy(), params, bearerHeader("tok"))
		ir := assertFailure(t, reqCtx, action, 401)
		assertRejectionCode(t, ir, policy.FaultCodeAuthTokenInactive, policy.FaultTypeAuthentication)
	})
}
