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

package oauth2tokenexchange

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
	"github.com/wso2/api-platform/sdk/core/utils"
)

func newTestPolicy() *OAuth2TokenExchangePolicy {
	return &OAuth2TokenExchangePolicy{
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

// applyHeaderModifications mimics the kernel's own merge in
// ChainExecutor.ExecuteRequestHeaderPolicies: HeadersToSet keys are
// lower-cased and win, then HeadersToRemove deletes by lower-cased key. Body
// phase tests must run OnRequestBody against headers produced this way — the
// real kernel carries the SAME mutated header map from the header phase into
// the body phase, it never reconstructs it from the pre-header-phase values.
func applyHeaderModifications(headers map[string][]string, mod policy.UpstreamRequestHeaderModifications) map[string][]string {
	out := make(map[string][]string, len(headers))
	for k, v := range headers {
		out[strings.ToLower(k)] = v
	}
	for k, v := range mod.HeadersToSet {
		out[strings.ToLower(k)] = []string{v}
	}
	for _, k := range mod.HeadersToRemove {
		delete(out, strings.ToLower(k))
	}
	return out
}

func baseParams(tokenEndpoint string) map[string]interface{} {
	return map[string]interface{}{
		"tokenEndpoint": tokenEndpoint,
		"clientId":      "test-client",
		"clientSecret":  "test-secret",
	}
}

// assertFault asserts resp is declared as a fault with wantCode and wantType.
func assertFault(t *testing.T, resp policy.ImmediateResponse, wantCode, wantType string) {
	t.Helper()
	if !resp.IsFault {
		t.Error("IsFault = false, want true")
	}
	if resp.Fault == nil {
		t.Fatal("Fault = nil, want a fault description")
	}
	if resp.Fault.Code != wantCode {
		t.Errorf("Fault.Code = %q, want %q", resp.Fault.Code, wantCode)
	}
	if resp.Fault.Type != wantType {
		t.Errorf("Fault.Type = %q, want %q", resp.Fault.Type, wantType)
	}
	if resp.Fault.Direction != policy.DirectionRequest {
		t.Errorf("Fault.Direction = %q, want %q", resp.Fault.Direction, policy.DirectionRequest)
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

// TestOnRequestBody_ClientSecretBasic_FormEncodesCredentials guards against
// passing clientId/clientSecret to SetBasicAuth raw: RFC 6749 §2.3.1 requires
// each to be application/x-www-form-urlencoded before use as the Basic Auth
// username/password. Without that, an embedded ':' in clientID could be
// misread as the username/password separator, and a '+' in clientSecret
// would decode incorrectly on a conforming server.
func TestOnRequestBody_ClientSecretBasic_FormEncodesCredentials(t *testing.T) {
	const rawClientID = "cli:ent"
	const rawClientSecret = "sec+ret id"

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok {
			t.Fatal("expected Basic Auth credentials")
		}
		if want := url.QueryEscape(rawClientID); user != want {
			t.Errorf("username = %q, want %q (form-encoded clientID)", user, want)
		}
		if want := url.QueryEscape(rawClientSecret); pass != want {
			t.Errorf("password = %q, want %q (form-encoded clientSecret)", pass, want)
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"access_token": "exchanged-token", "expires_in": 300})
	}))
	defer server.Close()
	utils.SetSharedHTTPClient(server.Client())
	defer utils.SetSharedHTTPClient(nil)

	p := newTestPolicy()
	params := baseParams(server.URL)
	params["clientId"] = rawClientID
	params["clientSecret"] = rawClientSecret
	reqCtx := newRequestContext(map[string][]string{"Authorization": {"Bearer original-client-token"}}, "/pets")
	result := p.OnRequestBody(context.Background(), reqCtx, params)

	if _, ok := result.(policy.UpstreamRequestModifications); !ok {
		t.Fatalf("expected UpstreamRequestModifications, got %T: %+v", result, result)
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

// ─── OnRequestBody: subjectTokenSource.forwardToken / removal ──────────────

// newSuccessServer returns an httptest server that always exchanges
// successfully, and wires it in as the shared HTTP client. Callers must
// `defer server.Close()` and `defer utils.SetSharedHTTPClient(nil)`.
func newSuccessServer(t *testing.T) *httptest.Server {
	t.Helper()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"access_token": "exchanged-token", "expires_in": 300})
	}))
	utils.SetSharedHTTPClient(server.Client())
	return server
}

func TestOnRequestBody_RemovesMismatchedHeaderSource(t *testing.T) {
	server := newSuccessServer(t)
	defer server.Close()
	defer utils.SetSharedHTTPClient(nil)

	p := newTestPolicy()
	params := baseParams(server.URL)
	params["subjectTokenSource"] = map[string]interface{}{"type": "header", "name": "X-Original-Token", "prefix": ""}
	reqCtx := newRequestContext(map[string][]string{"X-Original-Token": {"original-client-token"}}, "/pets")
	result := p.OnRequestBody(context.Background(), reqCtx, params)

	action, ok := result.(policy.UpstreamRequestModifications)
	if !ok {
		t.Fatalf("expected UpstreamRequestModifications, got %T: %+v", result, result)
	}
	if got := action.HeadersToSet["Authorization"]; got != "Bearer exchanged-token" {
		t.Errorf("Authorization = %q, want %q", got, "Bearer exchanged-token")
	}
	if len(action.HeadersToRemove) != 1 || action.HeadersToRemove[0] != "X-Original-Token" {
		t.Errorf("HeadersToRemove = %v, want [X-Original-Token]", action.HeadersToRemove)
	}
}

// TestOnRequestBody_NoRedundantRemovalWhenSourceEqualsUpstreamHeader guards
// against ever placing the same canonical header name in both HeadersToSet
// and HeadersToRemove: when subjectTokenSource and the upstream header are
// the same name (the default config), HeadersToSet already overwrites the
// original value, so no removal entry should be added alongside it.
func TestOnRequestBody_NoRedundantRemovalWhenSourceEqualsUpstreamHeader(t *testing.T) {
	server := newSuccessServer(t)
	defer server.Close()
	defer utils.SetSharedHTTPClient(nil)

	p := newTestPolicy()
	reqCtx := newRequestContext(map[string][]string{"Authorization": {"Bearer original-client-token"}}, "/pets")
	result := p.OnRequestBody(context.Background(), reqCtx, baseParams(server.URL))

	action, ok := result.(policy.UpstreamRequestModifications)
	if !ok {
		t.Fatalf("expected UpstreamRequestModifications, got %T: %+v", result, result)
	}
	if len(action.HeadersToRemove) != 0 {
		t.Errorf("expected no HeadersToRemove when subjectTokenSource and header share a name, got %v", action.HeadersToRemove)
	}
}

func TestOnRequestBody_RemovesQueryParameterSource(t *testing.T) {
	server := newSuccessServer(t)
	defer server.Close()
	defer utils.SetSharedHTTPClient(nil)

	p := newTestPolicy()
	params := baseParams(server.URL)
	params["subjectTokenSource"] = map[string]interface{}{"type": "queryParameter", "name": "access_token"}
	reqCtx := newRequestContext(map[string][]string{}, "/pets?access_token=original-client-token")
	result := p.OnRequestBody(context.Background(), reqCtx, params)

	action, ok := result.(policy.UpstreamRequestModifications)
	if !ok {
		t.Fatalf("expected UpstreamRequestModifications, got %T: %+v", result, result)
	}
	if len(action.QueryParametersToRemove) != 1 || action.QueryParametersToRemove[0] != "access_token" {
		t.Errorf("QueryParametersToRemove = %v, want [access_token]", action.QueryParametersToRemove)
	}
}

func TestOnRequestBody_RemovesCookieSource_SingleCookie(t *testing.T) {
	server := newSuccessServer(t)
	defer server.Close()
	defer utils.SetSharedHTTPClient(nil)

	p := newTestPolicy()
	params := baseParams(server.URL)
	params["subjectTokenSource"] = map[string]interface{}{"type": "cookie", "name": "session"}
	reqCtx := newRequestContext(map[string][]string{"Cookie": {"session=original-client-token"}}, "/pets")
	result := p.OnRequestBody(context.Background(), reqCtx, params)

	action, ok := result.(policy.UpstreamRequestModifications)
	if !ok {
		t.Fatalf("expected UpstreamRequestModifications, got %T: %+v", result, result)
	}
	if len(action.HeadersToRemove) != 1 || action.HeadersToRemove[0] != "Cookie" {
		t.Errorf("HeadersToRemove = %v, want [Cookie]", action.HeadersToRemove)
	}
	if _, set := action.HeadersToSet["Cookie"]; set {
		t.Errorf("expected no Cookie override when nothing remains, got %q", action.HeadersToSet["Cookie"])
	}
}

func TestOnRequestBody_RemovesCookieSource_PreservesOtherCookies(t *testing.T) {
	server := newSuccessServer(t)
	defer server.Close()
	defer utils.SetSharedHTTPClient(nil)

	p := newTestPolicy()
	params := baseParams(server.URL)
	params["subjectTokenSource"] = map[string]interface{}{"type": "cookie", "name": "session"}
	reqCtx := newRequestContext(map[string][]string{"Cookie": {"session=original-client-token; other=xyz"}}, "/pets")
	result := p.OnRequestBody(context.Background(), reqCtx, params)

	action, ok := result.(policy.UpstreamRequestModifications)
	if !ok {
		t.Fatalf("expected UpstreamRequestModifications, got %T: %+v", result, result)
	}
	if len(action.HeadersToRemove) != 0 {
		t.Errorf("expected no HeadersToRemove, got %v", action.HeadersToRemove)
	}
	if got := action.HeadersToSet["Cookie"]; got != "other=xyz" {
		t.Errorf("Cookie = %q, want %q", got, "other=xyz")
	}
}

func TestOnRequestBody_KeepsSubjectTokenSource_WhenForwardTokenEnabled(t *testing.T) {
	server := newSuccessServer(t)
	defer server.Close()
	defer utils.SetSharedHTTPClient(nil)

	p := newTestPolicy()
	params := baseParams(server.URL)
	params["subjectTokenSource"] = map[string]interface{}{
		"type":         "header",
		"name":         "X-Original-Token",
		"prefix":       "",
		"forwardToken": true,
	}
	reqCtx := newRequestContext(map[string][]string{"X-Original-Token": {"original-client-token"}}, "/pets")
	result := p.OnRequestBody(context.Background(), reqCtx, params)

	action, ok := result.(policy.UpstreamRequestModifications)
	if !ok {
		t.Fatalf("expected UpstreamRequestModifications, got %T: %+v", result, result)
	}
	if len(action.HeadersToRemove) != 0 {
		t.Errorf("expected no HeadersToRemove when forwardToken is true, got %v", action.HeadersToRemove)
	}
	if len(action.QueryParametersToRemove) != 0 {
		t.Errorf("expected no QueryParametersToRemove when forwardToken is true, got %v", action.QueryParametersToRemove)
	}
	if _, set := action.HeadersToSet["Cookie"]; set {
		t.Error("expected no Cookie override when forwardToken is true")
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
	assertFault(t, resp, policy.FaultCodeAuthMissingCredentials, policy.FaultTypeAuthentication)
}

// A subject header under another scheme is a credential that was presented and
// rejected, not a missing one. The client still receives the same 401 body.
func TestOnRequestBody_SubjectTokenWrongScheme_ReturnsUnauthorized(t *testing.T) {
	p := newTestPolicy()
	reqCtx := newRequestContext(map[string][]string{"Authorization": {"Basic dXNlcjpwYXNz"}}, "/pets")
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
	assertFault(t, resp, policy.FaultCodeAuthInvalidCredentials, policy.FaultTypeAuthentication)
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
	assertFault(t, resp, policy.FaultCodeMediationFailed, policy.FaultTypeMediation)
	var body struct {
		Message    string `json:"message"`
		TrackingID string `json:"tracking_id"`
	}
	if err := json.Unmarshal(resp.Body, &body); err != nil {
		t.Fatalf("body is not JSON: %v", err)
	}
	if resp.Fault.Message != body.Message {
		t.Errorf("Fault.Message = %q, want the body's message %q", resp.Fault.Message, body.Message)
	}
	if want := "token exchange failed, tracking_id " + body.TrackingID; resp.Fault.Description != want {
		t.Errorf("Fault.Description = %q, want %q", resp.Fault.Description, want)
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

// TestOnRequestBody_NilSharedHTTPClient_FallsBackAndSucceeds verifies that a
// nil shared client (e.g. this policy invoked before the engine finishes
// startup wiring) does not hard-fail the request: performTokenExchange falls
// back to fallbackHTTPClient, which still completes the exchange. Uses a
// plain (non-TLS) server since fallbackHTTPClient has no custom TLS trust
// store for a self-signed cert.
func TestOnRequestBody_NilSharedHTTPClient_FallsBackAndSucceeds(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"access_token": "exchanged-token", "expires_in": 300})
	}))
	defer server.Close()
	utils.SetSharedHTTPClient(nil)

	p := newTestPolicy()
	params := baseParams(server.URL)
	params["allowInsecureTokenEndpoint"] = true

	reqCtx := newRequestContext(map[string][]string{"Authorization": {"Bearer original-client-token"}}, "/pets")
	result := p.OnRequestBody(context.Background(), reqCtx, params)

	action, ok := result.(policy.UpstreamRequestModifications)
	if !ok {
		t.Fatalf("expected UpstreamRequestModifications, got %T: %+v", result, result)
	}
	if got := action.HeadersToSet["Authorization"]; got != "Bearer exchanged-token" {
		t.Errorf("Authorization = %q, want %q", got, "Bearer exchanged-token")
	}
}

// TestOnRequestBody_RefusesCrossOriginRedirectFromTokenEndpoint is an
// end-to-end check that redirectGuardedClient is actually wired into the
// real token-endpoint call: a configured tokenEndpoint that redirects
// cross-origin must never have its request body (carrying the subject
// token) replayed against the redirect target.
func TestOnRequestBody_RefusesCrossOriginRedirectFromTokenEndpoint(t *testing.T) {
	var attackerHits int32
	attacker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&attackerHits, 1)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"access_token": "leaked-token", "expires_in": 300})
	}))
	defer attacker.Close()

	tokenEndpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, attacker.URL+"/collect", http.StatusTemporaryRedirect)
	}))
	defer tokenEndpoint.Close()

	utils.SetSharedHTTPClient(&http.Client{})
	defer utils.SetSharedHTTPClient(nil)

	p := newTestPolicy()
	params := baseParams(tokenEndpoint.URL)
	params["allowInsecureTokenEndpoint"] = true

	reqCtx := newRequestContext(map[string][]string{"Authorization": {"Bearer original-client-token"}}, "/pets")
	result := p.OnRequestBody(context.Background(), reqCtx, params)

	resp, ok := result.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("expected ImmediateResponse, got %T: %+v", result, result)
	}
	if resp.StatusCode != 502 {
		t.Errorf("status = %d, want 502", resp.StatusCode)
	}
	if atomic.LoadInt32(&attackerHits) != 0 {
		t.Errorf("expected the cross-origin redirect target never to be reached, got %d hits", attackerHits)
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
	if !subjectTokenHashMatches(shared, "original-client-token") {
		t.Error("expected the stored subject token hash to match the token actually exchanged")
	}
	if subjectTokenHashMatches(shared, "a-different-token") {
		t.Error("expected the stored subject token hash not to match a different token")
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
	assertFault(t, resp, policy.FaultCodeMediationFailed, policy.FaultTypeMediation)
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
	assertFault(t, resp, policy.FaultCodeMediationFailed, policy.FaultTypeConfiguration)
	if headerPhaseSucceeded(shared) {
		t.Error("expected headerPhaseSucceeded to be false on invalid config")
	}
}

// TestOnRequestHeaders_RemovesMismatchedHeaderSource verifies the header
// phase computes its own removal mods independently of
// OnRequestBody/upstreamAction — it builds the UpstreamRequestHeaderModifications
// action directly rather than delegating to upstreamAction.
func TestOnRequestHeaders_RemovesMismatchedHeaderSource(t *testing.T) {
	server := newSuccessServer(t)
	defer server.Close()
	defer utils.SetSharedHTTPClient(nil)

	p := newTestPolicy()
	shared := newSharedContext()
	params := baseParams(server.URL)
	params["subjectTokenSource"] = map[string]interface{}{"type": "header", "name": "X-Original-Token", "prefix": ""}
	headerCtx := newRequestHeaderContext(shared, map[string][]string{"X-Original-Token": {"original-client-token"}}, "/pets")
	result := p.OnRequestHeaders(context.Background(), headerCtx, params)

	action, ok := result.(policy.UpstreamRequestHeaderModifications)
	if !ok {
		t.Fatalf("expected UpstreamRequestHeaderModifications, got %T: %+v", result, result)
	}
	if got := action.HeadersToSet["Authorization"]; got != "Bearer exchanged-token" {
		t.Errorf("Authorization = %q, want %q", got, "Bearer exchanged-token")
	}
	if len(action.HeadersToRemove) != 1 || action.HeadersToRemove[0] != "X-Original-Token" {
		t.Errorf("HeadersToRemove = %v, want [X-Original-Token]", action.HeadersToRemove)
	}
}

// ─── OnRequestHeaders + OnRequestBody: dual-phase interaction ───────────────

// TestOnRequestBody_SkipsExchangeWhenHeaderPhaseSucceeded covers the default
// configuration: subjectTokenSource names the same header as cfg.header
// (both "Authorization"), so the header phase's own HeadersToSet overwrites
// the very field it read the subject token from. The body-phase headers
// passed in here must reflect that self-overwrite the way the real kernel's
// ChainExecutor does (via applyHeaderModifications), not the pre-header-phase
// value — otherwise this test cannot see the self-overwrite staleness bug at
// all (it would still read back "original-client-token", never the
// already-exchanged one).
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
	headerResult, ok := p.OnRequestHeaders(context.Background(), headerCtx, params).(policy.UpstreamRequestHeaderModifications)
	if !ok {
		t.Fatal("expected the header phase to succeed")
	}
	if atomic.LoadInt32(&hits) != 1 {
		t.Fatalf("expected exactly 1 token endpoint call after the header phase, got %d", hits)
	}

	// The kernel carries the same SharedContext, AND the header-phase
	// mutations it already applied, into the body phase.
	mutatedHeaders := applyHeaderModifications(headers, headerResult)
	bodyCtx := newRequestContextSharing(shared, mutatedHeaders, "/pets")
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

// TestOnRequestBody_SkipsExchangeWhenHeaderPhaseSucceeded_CustomSubjectHeaderRemovedBySelf
// covers the jwt-auth -> oauth2-token-exchange chain configuration:
// subjectTokenSource names a DIFFERENT header than cfg.header (e.g.
// "X-Forwarded-Authorization" feeding "Authorization"), so the header
// phase's own subjectTokenRemovalMods strips that field entirely rather than
// overwriting it. Body-phase headers must reflect that removal, the same way
// applyHeaderModifications simulates the same-name overwrite case above.
// Before the self-removal tracking fix, OnRequestBody could not tell this
// expected, self-caused absence apart from the credential genuinely
// disappearing, and failed every request closed with 401.
func TestOnRequestBody_SkipsExchangeWhenHeaderPhaseSucceeded_CustomSubjectHeaderRemovedBySelf(t *testing.T) {
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
	headers := map[string][]string{"X-Forwarded-Authorization": {"Bearer original-client-token"}}
	params := baseParams(server.URL)
	params["subjectTokenSource"] = map[string]interface{}{
		"type": "header",
		"name": "x-forwarded-authorization",
	}

	headerCtx := newRequestHeaderContext(shared, headers, "/pets")
	headerResult, ok := p.OnRequestHeaders(context.Background(), headerCtx, params).(policy.UpstreamRequestHeaderModifications)
	if !ok {
		t.Fatal("expected the header phase to succeed")
	}
	if got := headerResult.HeadersToSet["Authorization"]; got != "Bearer exchanged-token" {
		t.Errorf("header-phase Authorization = %q, want %q", got, "Bearer exchanged-token")
	}
	if atomic.LoadInt32(&hits) != 1 {
		t.Fatalf("expected exactly 1 token endpoint call after the header phase, got %d", hits)
	}

	mutatedHeaders := applyHeaderModifications(headers, headerResult)
	if _, present := mutatedHeaders["x-forwarded-authorization"]; present {
		t.Fatalf("test setup error: expected the header phase to have removed x-forwarded-authorization, got %+v", mutatedHeaders)
	}

	bodyCtx := newRequestContextSharing(shared, mutatedHeaders, "/pets")
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

// runHeaderThenBody drives OnRequestHeaders, applies its mutations plus
// any extra body-phase mutation, then runs OnRequestBody on the result. It
// returns the body-phase action and the total token endpoint call count.
func runHeaderThenBody(t *testing.T, headers map[string][]string, configure func(map[string]interface{}), between func(map[string][]string) map[string][]string) (policy.RequestAction, int32) {
	t.Helper()
	var hits int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"access_token": "exchanged-token", "expires_in": 300})
	}))
	t.Cleanup(server.Close)
	utils.SetSharedHTTPClient(server.Client())
	t.Cleanup(func() { utils.SetSharedHTTPClient(nil) })

	p := newTestPolicy()
	shared := newSharedContext()
	params := baseParams(server.URL)
	configure(params)

	headerResult, ok := p.OnRequestHeaders(context.Background(), newRequestHeaderContext(shared, headers, "/pets"), params).(policy.UpstreamRequestHeaderModifications)
	if !ok {
		t.Fatal("expected the header phase to succeed")
	}
	mutated := applyHeaderModifications(headers, headerResult)
	if between != nil {
		mutated = between(mutated)
	}
	result := p.OnRequestBody(context.Background(), newRequestContextSharing(shared, mutated, "/pets"), params)
	return result, atomic.LoadInt32(&hits)
}

// Same header in and out with forwardToken enabled: the header phase still
// overwrites the field, so the body phase must recognize its own write
// instead of exchanging the exchanged token again.
func TestOnRequestBody_SkipsExchange_SameHeaderWithForwardToken(t *testing.T) {
	result, hits := runHeaderThenBody(t,
		map[string][]string{"Authorization": {"Bearer original-client-token"}},
		func(params map[string]interface{}) {
			params["subjectTokenSource"] = map[string]interface{}{"type": "header", "name": "Authorization", "forwardToken": true}
		}, nil)

	action, ok := result.(policy.UpstreamRequestModifications)
	if !ok {
		t.Fatalf("expected UpstreamRequestModifications, got %T: %+v", result, result)
	}
	if len(action.HeadersToSet) != 0 {
		t.Errorf("expected no body-phase headers, got %+v", action.HeadersToSet)
	}
	if hits != 1 {
		t.Errorf("expected exactly 1 token endpoint call, got %d", hits)
	}
}

// Same header in and out with different source/output prefixes: the body
// phase cannot re-extract the written value with the source prefix, so it
// must compare the whole written value instead of failing with 401.
func TestOnRequestBody_SkipsExchange_SameHeaderDifferentPrefixes(t *testing.T) {
	result, hits := runHeaderThenBody(t,
		map[string][]string{"Authorization": {"Token original-client-token"}},
		func(params map[string]interface{}) {
			params["subjectTokenSource"] = map[string]interface{}{"type": "header", "name": "Authorization", "prefix": "Token "}
		}, nil)

	action, ok := result.(policy.UpstreamRequestModifications)
	if !ok {
		t.Fatalf("expected UpstreamRequestModifications, got %T: %+v", result, result)
	}
	if len(action.HeadersToSet) != 0 {
		t.Errorf("expected no body-phase headers, got %+v", action.HeadersToSet)
	}
	if hits != 1 {
		t.Errorf("expected exactly 1 token endpoint call, got %d", hits)
	}
}

// A body-phase policy earlier in the chain removed the exchanged output
// header after the header phase stripped the subject field. The body phase
// must not skip and forward the request without a credential; with the
// subject gone it fails closed.
func TestOnRequestBody_FailsClosed_WhenOutputHeaderRemovedAfterHeaderPhase(t *testing.T) {
	result, hits := runHeaderThenBody(t,
		map[string][]string{"X-Forwarded-Authorization": {"Bearer original-client-token"}},
		func(params map[string]interface{}) {
			params["subjectTokenSource"] = map[string]interface{}{"type": "header", "name": "X-Forwarded-Authorization"}
		},
		func(h map[string][]string) map[string][]string {
			for k := range h {
				if http.CanonicalHeaderKey(k) == "Authorization" {
					delete(h, k)
				}
			}
			return h
		})

	resp, ok := result.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("expected ImmediateResponse, got %T: %+v", result, result)
	}
	if resp.StatusCode != 401 {
		t.Errorf("status = %d, want 401", resp.StatusCode)
	}
	if hits != 1 {
		t.Errorf("expected no additional token endpoint call, got %d total", hits)
	}
}

// The exchanged output header was removed, but the subject token is still
// present (forwardToken): the body phase re-exchanges and re-sets it.
func TestOnRequestBody_ReSetsOutputHeader_WhenRemovedAndSubjectStillPresent(t *testing.T) {
	result, _ := runHeaderThenBody(t,
		map[string][]string{"X-Forwarded-Authorization": {"Bearer original-client-token"}},
		func(params map[string]interface{}) {
			params["subjectTokenSource"] = map[string]interface{}{"type": "header", "name": "X-Forwarded-Authorization", "forwardToken": true}
		},
		func(h map[string][]string) map[string][]string {
			for k := range h {
				if http.CanonicalHeaderKey(k) == "Authorization" {
					delete(h, k)
				}
			}
			return h
		})

	action, ok := result.(policy.UpstreamRequestModifications)
	if !ok {
		t.Fatalf("expected UpstreamRequestModifications, got %T: %+v", result, result)
	}
	if got := action.HeadersToSet["Authorization"]; got != "Bearer exchanged-token" {
		t.Errorf("Authorization = %q, want %q", got, "Bearer exchanged-token")
	}
}

// TestOnRequestBody_ReExchangesWhenSubjectTokenChangedSinceHeaderPhase covers
// the staleness scenario storeSubjectTokenHash/subjectTokenHashMatches exist
// to close: an earlier-in-chain body-phase policy rewrites the same header
// the header phase already exchanged from, after that header-phase exchange
// already ran and attached its result upstream. OnRequestBody must detect
// the mismatch and re-exchange against the new value rather than trusting
// the stale one.
func TestOnRequestBody_ReExchangesWhenSubjectTokenChangedSinceHeaderPhase(t *testing.T) {
	var hits int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		if err := r.ParseForm(); err != nil {
			t.Fatalf("parse form: %v", err)
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "exchanged-" + r.PostForm.Get("subject_token"),
			"expires_in":   300,
		})
	}))
	defer server.Close()
	utils.SetSharedHTTPClient(server.Client())
	defer utils.SetSharedHTTPClient(nil)

	p := newTestPolicy()
	shared := newSharedContext()
	params := baseParams(server.URL)

	headerCtx := newRequestHeaderContext(shared, map[string][]string{"Authorization": {"Bearer original-client-token"}}, "/pets")
	headerResult, ok := p.OnRequestHeaders(context.Background(), headerCtx, params).(policy.UpstreamRequestHeaderModifications)
	if !ok {
		t.Fatal("expected the header phase to succeed")
	}
	if got := headerResult.HeadersToSet["Authorization"]; got != "Bearer exchanged-original-client-token" {
		t.Errorf("header-phase Authorization = %q, want %q", got, "Bearer exchanged-original-client-token")
	}
	if atomic.LoadInt32(&hits) != 1 {
		t.Fatalf("expected exactly 1 token endpoint call after the header phase, got %d", hits)
	}

	// An earlier-in-chain body-phase policy has since rewritten the same
	// header to a different credential.
	bodyCtx := newRequestContextSharing(shared, map[string][]string{"Authorization": {"Bearer rotated-client-token"}}, "/pets")
	result := p.OnRequestBody(context.Background(), bodyCtx, params)

	action, ok := result.(policy.UpstreamRequestModifications)
	if !ok {
		t.Fatalf("expected UpstreamRequestModifications, got %T: %+v", result, result)
	}
	if got := action.HeadersToSet["Authorization"]; got != "Bearer exchanged-rotated-client-token" {
		t.Errorf("Authorization = %q, want %q", got, "Bearer exchanged-rotated-client-token")
	}
	if atomic.LoadInt32(&hits) != 2 {
		t.Errorf("expected a second token endpoint call for the changed subject token, got %d total", hits)
	}
}

// TestOnRequestBody_ReExchangesWhenSubjectTokenDisappearedSinceHeaderPhase
// covers the symmetric case: the credential the header phase successfully
// exchanged is no longer present at all by the body phase (e.g. an
// earlier-in-chain policy stripped it). OnRequestBody must not trust the
// stale header-phase result and must fail closed instead.
func TestOnRequestBody_ReExchangesWhenSubjectTokenDisappearedSinceHeaderPhase(t *testing.T) {
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

	headerCtx := newRequestHeaderContext(shared, map[string][]string{"Authorization": {"Bearer original-client-token"}}, "/pets")
	if _, ok := p.OnRequestHeaders(context.Background(), headerCtx, params).(policy.UpstreamRequestHeaderModifications); !ok {
		t.Fatal("expected the header phase to succeed")
	}
	if atomic.LoadInt32(&hits) != 1 {
		t.Fatalf("expected exactly 1 token endpoint call after the header phase, got %d", hits)
	}

	// An earlier-in-chain body-phase policy has since removed the header.
	bodyCtx := newRequestContextSharing(shared, map[string][]string{}, "/pets")
	result := p.OnRequestBody(context.Background(), bodyCtx, params)

	resp, ok := result.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("expected ImmediateResponse, got %T: %+v", result, result)
	}
	if resp.StatusCode != 401 {
		t.Errorf("status = %d, want 401", resp.StatusCode)
	}
	if atomic.LoadInt32(&hits) != 1 {
		t.Errorf("expected no additional token endpoint call once the subject token disappeared, got %d total", hits)
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

// ─── fallbackHTTPClient ──────────────────────────────────────────────────────

func TestFallbackHTTPClient_NeverAutoFollowsRedirects(t *testing.T) {
	client := fallbackHTTPClient()
	if client.CheckRedirect == nil {
		t.Fatal("expected CheckRedirect to be set")
	}
	if err := client.CheckRedirect(&http.Request{}, nil); err != http.ErrUseLastResponse {
		t.Errorf("CheckRedirect = %v, want http.ErrUseLastResponse", err)
	}
}

// ─── redirectGuardedClient ───────────────────────────────────────────────────

func TestRedirectGuardedClient_BlocksCrossHostRedirect(t *testing.T) {
	client := redirectGuardedClient(&http.Client{})
	original, _ := http.NewRequest(http.MethodGet, "https://token.example.com/oauth2/token", nil)
	redirectTarget, _ := http.NewRequest(http.MethodGet, "https://attacker.example.com/collect", nil)

	if err := client.CheckRedirect(redirectTarget, []*http.Request{original}); err != http.ErrUseLastResponse {
		t.Errorf("CheckRedirect = %v, want http.ErrUseLastResponse for a cross-host redirect", err)
	}
}

func TestRedirectGuardedClient_BlocksSchemeDowngrade(t *testing.T) {
	client := redirectGuardedClient(&http.Client{})
	original, _ := http.NewRequest(http.MethodGet, "https://token.example.com/oauth2/token", nil)
	redirectTarget, _ := http.NewRequest(http.MethodGet, "http://token.example.com/oauth2/token", nil)

	if err := client.CheckRedirect(redirectTarget, []*http.Request{original}); err != http.ErrUseLastResponse {
		t.Errorf("CheckRedirect = %v, want http.ErrUseLastResponse for a scheme change", err)
	}
}

// TestRedirectGuardedClient_SameOriginComparisonIsCaseInsensitive guards
// against a false-positive "cross-origin" rejection: both scheme and host
// are case-insensitive per RFC 3986, so a redirect target that only differs
// in case from the original request must still be treated as same-origin.
func TestRedirectGuardedClient_SameOriginComparisonIsCaseInsensitive(t *testing.T) {
	client := redirectGuardedClient(&http.Client{})
	original, _ := http.NewRequest(http.MethodGet, "https://Token.Example.com/oauth2/token", nil)
	redirectTarget, _ := http.NewRequest(http.MethodGet, "HTTPS://token.example.com/oauth2/token2", nil)

	if err := client.CheckRedirect(redirectTarget, []*http.Request{original}); err != nil {
		t.Errorf("unexpected error for a same-origin redirect differing only in case: %v", err)
	}
}

func TestRedirectGuardedClient_AllowsSameOriginRedirect(t *testing.T) {
	client := redirectGuardedClient(&http.Client{})
	original, _ := http.NewRequest(http.MethodGet, "https://token.example.com/oauth2/token", nil)
	redirectTarget, _ := http.NewRequest(http.MethodGet, "https://token.example.com/oauth2/token2", nil)

	if err := client.CheckRedirect(redirectTarget, []*http.Request{original}); err != nil {
		t.Errorf("unexpected error for a same-origin redirect: %v", err)
	}
}

// TestRedirectGuardedClient_PreservesExistingPolicyForSameOrigin verifies the
// wrapper only narrows what the original client already allowed, rather than
// replacing its policy outright, for same-origin redirects.
func TestRedirectGuardedClient_PreservesExistingPolicyForSameOrigin(t *testing.T) {
	var calledWith *http.Request
	base := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			calledWith = req
			return errors.New("custom policy rejected it")
		},
	}
	client := redirectGuardedClient(base)
	original, _ := http.NewRequest(http.MethodGet, "https://token.example.com/oauth2/token", nil)
	redirectTarget, _ := http.NewRequest(http.MethodGet, "https://token.example.com/oauth2/token2", nil)

	err := client.CheckRedirect(redirectTarget, []*http.Request{original})
	if err == nil || err.Error() != "custom policy rejected it" {
		t.Errorf("expected the original CheckRedirect policy to run for a same-origin redirect, got %v", err)
	}
	if calledWith != redirectTarget {
		t.Error("expected the original CheckRedirect to be invoked with the redirect target request")
	}
}

func TestRedirectGuardedClient_DoesNotMutateOriginalClient(t *testing.T) {
	original := &http.Client{}
	_ = redirectGuardedClient(original)
	if original.CheckRedirect != nil {
		t.Error("expected redirectGuardedClient not to mutate the original client's CheckRedirect")
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
	if string(resp.Body) != `{"error":"Internal Server Error"}` {
		t.Errorf("body = %s, want the unchanged internal error body", resp.Body)
	}
	assertFault(t, resp, policy.FaultCodeMediationFailed, policy.FaultTypeConfiguration)
	if !strings.HasPrefix(resp.Fault.Description, "invalid policy configuration: ") {
		t.Errorf("Fault.Description = %q, want the configuration error", resp.Fault.Description)
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

// TestExtractSubjectToken_Header_PrefixCaseInsensitive guards against RFC
// 7235: the HTTP auth-scheme token is case-insensitive, so a client sending
// "bearer <token>" (or any other casing) must still be recognized.
func TestExtractSubjectToken_Header_PrefixCaseInsensitive(t *testing.T) {
	reqCtx := newRequestContext(map[string][]string{"Authorization": {"bearer abc123"}}, "/pets")
	tok, ok := extractSubjectToken(reqCtx.Headers, reqCtx.Path, subjectTokenSource{kind: "header", name: "Authorization", prefix: "Bearer "})
	if !ok || tok != "abc123" {
		t.Errorf("got (%q, %v), want (abc123, true)", tok, ok)
	}
}

// TestExtractSubjectToken_Header_PrefixTooShort guards against a panic when
// the header value is shorter than the configured prefix — slicing
// v[:len(src.prefix)] requires an explicit length check first.
func TestExtractSubjectToken_Header_PrefixTooShort(t *testing.T) {
	reqCtx := newRequestContext(map[string][]string{"Authorization": {"Bear"}}, "/pets")
	_, ok := extractSubjectToken(reqCtx.Headers, reqCtx.Path, subjectTokenSource{kind: "header", name: "Authorization", prefix: "Bearer "})
	if ok {
		t.Error("expected no match when the header value is shorter than the configured prefix")
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

// ─── stripCookieByName ───────────────────────────────────────────────────────

func TestStripCookieByName_RemovesOnlyMatchingCookie(t *testing.T) {
	remaining, removedAll := stripCookieByName([]string{"session=abc123; other=xyz"}, "session")
	if removedAll {
		t.Fatal("expected removedAll = false, since other=xyz remains")
	}
	if remaining != "other=xyz" {
		t.Errorf("remaining = %q, want %q", remaining, "other=xyz")
	}
}

func TestStripCookieByName_RemovesAllWhenOnlyCookiePresent(t *testing.T) {
	remaining, removedAll := stripCookieByName([]string{"session=abc123"}, "session")
	if !removedAll {
		t.Fatal("expected removedAll = true when no cookies remain")
	}
	if remaining != "" {
		t.Errorf("remaining = %q, want empty string", remaining)
	}
}

func TestStripCookieByName_NoMatch_LeavesAllCookiesIntact(t *testing.T) {
	remaining, removedAll := stripCookieByName([]string{"other=xyz"}, "session")
	if removedAll {
		t.Fatal("expected removedAll = false when the named cookie isn't present")
	}
	if remaining != "other=xyz" {
		t.Errorf("remaining = %q, want %q", remaining, "other=xyz")
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

// ─── storeSubjectTokenHash / subjectTokenHashMatches ────────────────────────

func TestSubjectTokenHashMatches_NoStoredHash(t *testing.T) {
	shared := newSharedContext()
	if subjectTokenHashMatches(shared, "any-token") {
		t.Error("expected no match when no hash has been stored yet")
	}
}

func TestSubjectTokenHashMatches_NilSharedContext(t *testing.T) {
	if subjectTokenHashMatches(nil, "any-token") {
		t.Error("expected no match against a nil SharedContext")
	}
}

func TestStoreSubjectTokenHash_RoundTrips(t *testing.T) {
	shared := newSharedContext()
	storeSubjectTokenHash(shared, "abc123")

	if !subjectTokenHashMatches(shared, "abc123") {
		t.Error("expected the stored hash to match the same token")
	}
	if subjectTokenHashMatches(shared, "different-token") {
		t.Error("expected the stored hash not to match a different token")
	}
}

func TestStoreSubjectTokenHash_NilSharedContext_DoesNotPanic(t *testing.T) {
	storeSubjectTokenHash(nil, "abc123") // must not panic
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

// TestBuildCacheKey_DifferentClientSecretsDifferentKeys guards against
// rotating clientSecret silently continuing to serve a token cached under
// the previous secret: the cache key must change when only the secret does,
// even though clientID and every other field stay the same.
func TestBuildCacheKey_DifferentClientSecretsDifferentKeys(t *testing.T) {
	base := &exchangeConfig{tokenEndpoint: mustParseURL(t, "https://example.com/token"), clientID: "c", clientSecret: "secret-a", grantType: "TokenExchange"}
	rotated := &exchangeConfig{tokenEndpoint: mustParseURL(t, "https://example.com/token"), clientID: "c", clientSecret: "secret-b", grantType: "TokenExchange"}
	k1 := buildCacheKey("api", base, "token-a")
	k2 := buildCacheKey("api", rotated, "token-a")
	if k1 == k2 {
		t.Error("expected different cache keys when only clientSecret changes")
	}
}

// TestBuildCacheKey_ScopeListSerializationIsUnambiguous guards against a
// comma-joined serialization collision: a single scope "a,b" and two
// separate scopes "a", "b" must not produce the same cache key, even though
// strings.Join(sortedCopy(scopes), ",") would render both as "a,b".
func TestBuildCacheKey_ScopeListSerializationIsUnambiguous(t *testing.T) {
	oneScopeWithComma := &exchangeConfig{tokenEndpoint: mustParseURL(t, "https://example.com/token"), clientID: "c", grantType: "TokenExchange", scopes: []string{"a,b"}}
	twoSeparateScopes := &exchangeConfig{tokenEndpoint: mustParseURL(t, "https://example.com/token"), clientID: "c", grantType: "TokenExchange", scopes: []string{"a", "b"}}
	k1 := buildCacheKey("api", oneScopeWithComma, "token")
	k2 := buildCacheKey("api", twoSeparateScopes, "token")
	if k1 == k2 {
		t.Error("expected different cache keys for a single scope containing a comma vs two separate scopes")
	}
}

// TestBuildCacheKey_AudienceListSerializationIsUnambiguous is the audiences
// analogue of TestBuildCacheKey_ScopeListSerializationIsUnambiguous.
func TestBuildCacheKey_AudienceListSerializationIsUnambiguous(t *testing.T) {
	oneAudienceWithComma := &exchangeConfig{tokenEndpoint: mustParseURL(t, "https://example.com/token"), clientID: "c", grantType: "TokenExchange", audiences: []string{"a,b"}}
	twoSeparateAudiences := &exchangeConfig{tokenEndpoint: mustParseURL(t, "https://example.com/token"), clientID: "c", grantType: "TokenExchange", audiences: []string{"a", "b"}}
	k1 := buildCacheKey("api", oneAudienceWithComma, "token")
	k2 := buildCacheKey("api", twoSeparateAudiences, "token")
	if k1 == k2 {
		t.Error("expected different cache keys for a single audience containing a comma vs two separate audiences")
	}
}

// TestBuildCacheKey_ResourceListSerializationIsUnambiguous is the resources
// analogue of TestBuildCacheKey_ScopeListSerializationIsUnambiguous.
func TestBuildCacheKey_ResourceListSerializationIsUnambiguous(t *testing.T) {
	oneResourceWithComma := &exchangeConfig{tokenEndpoint: mustParseURL(t, "https://example.com/token"), clientID: "c", grantType: "TokenExchange", resources: []string{"a,b"}}
	twoSeparateResources := &exchangeConfig{tokenEndpoint: mustParseURL(t, "https://example.com/token"), clientID: "c", grantType: "TokenExchange", resources: []string{"a", "b"}}
	k1 := buildCacheKey("api", oneResourceWithComma, "token")
	k2 := buildCacheKey("api", twoSeparateResources, "token")
	if k1 == k2 {
		t.Error("expected different cache keys for a single resource containing a comma vs two separate resources")
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
