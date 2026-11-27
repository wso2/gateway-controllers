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
 */

package intelligentmodelrouting

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wso2/api-platform/sdk/ai/azureauthentication"
	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

// testClientID is a well-formed client ID.
const testClientID = "11111111-2222-3333-4444-555555555555"

func TestReadAzureAuth(t *testing.T) {
	tests := []struct {
		name    string
		params  map[string]interface{}
		want    authentication
		wantErr string
	}{
		{name: "absent", params: map[string]interface{}{}, want: authentication{typ: authenticationTypeAPIKey}},
		{name: "nil", params: map[string]interface{}{"azureAuth": nil}, want: authentication{typ: authenticationTypeAPIKey}},
		{name: "empty object", params: map[string]interface{}{"azureAuth": map[string]interface{}{}}, want: authentication{typ: authenticationTypeAPIKey}},
		{
			name: "api-key ignores leftover identity fields",
			params: map[string]interface{}{"azureAuth": map[string]interface{}{
				"authenticationType": "api-key", "clientId": "x", "scope": "y",
			}},
			want: authentication{typ: authenticationTypeAPIKey},
		},
		{
			name:   "workload identity gets the default scope",
			params: map[string]interface{}{"azureAuth": map[string]interface{}{"authenticationType": "workload-identity"}},
			want:   authentication{typ: "workload-identity", tokenScope: defaultTokenScope},
		},
		{
			name: "custom scope kept and fields trimmed",
			params: map[string]interface{}{"azureAuth": map[string]interface{}{
				"authenticationType": " managed-identity ", "clientId": " " + testClientID + " ", "scope": " https://x.example/.default ",
			}},
			want: authentication{typ: "managed-identity", clientID: testClientID, tokenScope: "https://x.example/.default"},
		},
		{name: "not an object", params: map[string]interface{}{"azureAuth": "x"}, wantErr: "'azureAuth' must be an object"},
		{
			name:    "unknown type",
			params:  map[string]interface{}{"azureAuth": map[string]interface{}{"authenticationType": "bogus"}},
			wantErr: "'azureAuth.authenticationType' must be",
		},
		{
			name: "client ID not a GUID",
			params: map[string]interface{}{"azureAuth": map[string]interface{}{
				"authenticationType": "managed-identity", "clientId": "nope",
			}},
			wantErr: "'azureAuth.clientId' is invalid",
		},
		{
			name: "scope without /.default",
			params: map[string]interface{}{"azureAuth": map[string]interface{}{
				"authenticationType": "workload-identity", "scope": "https://x.example",
			}},
			wantErr: "'azureAuth.scope' is invalid",
		},
		{
			name:    "non-string field",
			params:  map[string]interface{}{"azureAuth": map[string]interface{}{"authenticationType": 3}},
			wantErr: "must be a string",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := readAzureAuth(tt.params)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error = %v, want containing %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("got %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestCheckAllowedType(t *testing.T) {
	list := func(entries ...interface{}) map[string]interface{} {
		return map[string]interface{}{allowedAuthTypesParam: entries}
	}
	tests := []struct {
		name    string
		params  map[string]interface{}
		typ     string
		wantErr string
	}{
		{name: "absent list", params: map[string]interface{}{}, typ: "api-key"},
		{name: "empty list", params: list(), typ: "workload-identity"},
		{name: "listed type", params: list("workload-identity"), typ: "workload-identity"},
		{name: "unlisted type", params: list("workload-identity"), typ: "api-key", wantErr: "is not allowed on this gateway"},
		{name: "bad entry beside a match", params: list("api-key", "bogus"), typ: "api-key", wantErr: "is not an authentication type"},
		{name: "not an array", params: map[string]interface{}{allowedAuthTypesParam: "api-key"}, typ: "api-key", wantErr: "must be an array of strings"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := checkAllowedType(tt.params, tt.typ)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error = %v, want containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestCheckAllowedEndpoint(t *testing.T) {
	const e = "https://res.openai.azure.com/openai/deployments/d/chat/completions?api-version=2024-10-21"
	tests := []struct {
		name     string
		entries  []string
		endpoint string
		wantErr  string
	}{
		{name: "no list", endpoint: e},
		{name: "resource listed", entries: []string{"https://res.openai.azure.com"}, endpoint: e},
		{name: "other deployment, same resource", entries: []string{"https://res.openai.azure.com"}, endpoint: "https://res.openai.azure.com/openai/deployments/other/chat/completions?api-version=2025-01-01"},
		{name: "trailing slash", entries: []string{"https://res.openai.azure.com/"}, endpoint: e},
		{name: "upper case", entries: []string{"HTTPS://Res.OpenAI.Azure.com"}, endpoint: e},
		{name: "default port", entries: []string{"https://res.openai.azure.com:443"}, endpoint: e},
		{name: "http default port", entries: []string{"http://testbench:80"}, endpoint: "http://testbench/openai/deployments/d/chat/completions?api-version=x"},
		{name: "other host", entries: []string{"https://other.openai.azure.com"}, endpoint: e, wantErr: "is not allowed on this gateway"},
		{name: "other port", entries: []string{"http://testbench:3004"}, endpoint: "http://testbench:3002/openai/deployments/d/chat/completions?api-version=x", wantErr: "is not allowed on this gateway"},
		{name: "other scheme", entries: []string{"http://res.openai.azure.com"}, endpoint: e, wantErr: "is not allowed on this gateway"},
		{name: "endpoint is not a URL", entries: []string{"https://res.openai.azure.com"}, endpoint: "not a url", wantErr: "is not allowed on this gateway"},
		{name: "userinfo before another host", entries: []string{"https://res.openai.azure.com"}, endpoint: "https://res.openai.azure.com@evil.example/openai/deployments/d/chat/completions?api-version=x", wantErr: "is not allowed on this gateway"},
		{name: "trailing dot makes another host", entries: []string{"http://testbench:3008"}, endpoint: "http://testbench.:3008/openai/deployments/d/chat/completions?api-version=x", wantErr: "is not allowed on this gateway"},
		{name: "unicode look-alike host", entries: []string{"https://myai.openai.azure.com"}, endpoint: "https://myaİ.openai.azure.com/openai/deployments/d/chat/completions?api-version=x", wantErr: "is not allowed on this gateway"},
		{name: "non-ASCII entry", entries: []string{"https://myaİ.openai.azure.com"}, endpoint: e, wantErr: "is not a resource URL"},
		{name: "entry with path", entries: []string{"https://res.openai.azure.com/openai"}, endpoint: e, wantErr: "is not a resource URL"},
		{name: "entry with query", entries: []string{"https://res.openai.azure.com?x=1"}, endpoint: e, wantErr: "is not a resource URL"},
		{name: "entry with fragment", entries: []string{"https://res.openai.azure.com#f"}, endpoint: e, wantErr: "is not a resource URL"},
		{name: "entry not absolute", entries: []string{"res.openai.azure.com"}, endpoint: e, wantErr: "is not a resource URL"},
		{name: "bad entry beside a match", entries: []string{"https://res.openai.azure.com", "ftp://x"}, endpoint: e, wantErr: "is not a resource URL"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			params := map[string]interface{}{}
			if tt.entries != nil {
				params[allowedEndpointsParam] = tt.entries
			}
			err := checkAllowedEndpoint(params, tt.endpoint)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error = %v, want containing %q", err, tt.wantErr)
			}
		})
	}
}

// fakeTokens is a tokenSource that hands out a set token or error and records what it was asked.
type fakeTokens struct {
	token string
	err   error

	mu      sync.Mutex
	calls   int
	scope   string
	timeout time.Duration
	ctx     context.Context
}

func (f *fakeTokens) Token(ctx context.Context, scope string, timeout time.Duration) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	f.scope, f.timeout, f.ctx = scope, timeout, ctx
	return f.token, f.err
}

// useFakeTokens makes getTokenSource hand out f for every identity until the test ends.
func useFakeTokens(t *testing.T, f *fakeTokens) {
	t.Helper()
	orig := getTokenSource
	getTokenSource = func(azureauthentication.Identity) (tokenSource, error) { return f, nil }
	t.Cleanup(func() { getTokenSource = orig })
}

// azureParams returns params for an AZURE_OPENAI classifier with the gateway's key, merged with
// extra; a nil value in extra deletes that key.
func azureParams(extra map[string]interface{}) map[string]interface{} {
	params := map[string]interface{}{
		"routingRules": []interface{}{
			map[string]interface{}{"name": "coding", "context": "Programming questions", "model": "coding-model"},
		},
		"defaultModel": "default-model",
		"requestModel": map[string]interface{}{"location": "payload", "identifier": "$.model"},
		"llmProvider":  "AZURE_OPENAI",
		"llmEndpoint":  "https://res.openai.azure.com/openai/deployments/chat/chat/completions?api-version=2024-10-21",
		"llmApiKey":    "gateway-key",
	}
	for k, v := range extra {
		if v == nil {
			delete(params, k)
			continue
		}
		params[k] = v
	}
	return params
}

// identity returns an azureAuth value of typ.
func identity(typ string) map[string]interface{} {
	return map[string]interface{}{"authenticationType": typ}
}

// buildPolicy runs GetPolicy and returns the policy it built.
func buildPolicy(t *testing.T, params map[string]interface{}) (*IntelligentModelRoutingPolicy, error) {
	t.Helper()
	impl, err := GetPolicy(policy.PolicyMetadata{}, params)
	if err != nil {
		return nil, err
	}
	p, ok := impl.(*IntelligentModelRoutingPolicy)
	if !ok {
		t.Fatalf("GetPolicy returned %T", impl)
	}
	return p, nil
}

// mustFail runs GetPolicy, which must fail, and returns its error text.
func mustFail(t *testing.T, params map[string]interface{}) string {
	t.Helper()
	_, err := buildPolicy(t, params)
	if err == nil {
		t.Fatal("GetPolicy succeeded; want an error")
	}
	return err.Error()
}

func TestGetPolicyIdentityModeNeedsNoKey(t *testing.T) {
	useFakeTokens(t, &fakeTokens{token: "tok"})
	p, err := buildPolicy(t, azureParams(map[string]interface{}{"azureAuth": identity("workload-identity"), "llmApiKey": nil}))
	if err != nil {
		t.Fatalf("GetPolicy: %v", err)
	}
	if p.auth.typ != "workload-identity" || p.auth.tokenScope != defaultTokenScope {
		t.Errorf("auth = %+v, want workload-identity with the default scope", p.auth)
	}
	if p.llmConfig.APIKey != "" {
		t.Errorf("APIKey = %q, want none", p.llmConfig.APIKey)
	}
	if p.tokens == nil {
		t.Error("tokens is nil; want the identity's credential")
	}
}

func TestGetPolicyIdentityModeDropsTheKey(t *testing.T) {
	useFakeTokens(t, &fakeTokens{token: "tok"})
	p, err := buildPolicy(t, azureParams(map[string]interface{}{"azureAuth": identity("managed-identity")}))
	if err != nil {
		t.Fatalf("GetPolicy: %v", err)
	}
	if p.llmConfig.APIKey != "" {
		t.Errorf("APIKey = %q, want the gateway's key dropped", p.llmConfig.APIKey)
	}
}

func TestGetPolicyAPIKeyModeStillNeedsAKey(t *testing.T) {
	if msg := mustFail(t, azureParams(map[string]interface{}{"llmApiKey": nil})); !strings.Contains(msg, "'llmApiKey' parameter is required") {
		t.Errorf("error = %q", msg)
	}
}

func TestGetPolicyAPIKeyModeIgnoresLeftoverIdentityFields(t *testing.T) {
	p, err := buildPolicy(t, azureParams(map[string]interface{}{
		"azureAuth": map[string]interface{}{"authenticationType": "api-key", "clientId": testClientID, "scope": "x"},
	}))
	if err != nil {
		t.Fatalf("GetPolicy: %v", err)
	}
	if p.auth.typ != authenticationTypeAPIKey || p.tokens != nil || p.llmConfig.APIKey != "gateway-key" {
		t.Errorf("auth = %+v, tokens = %v, key = %q; want api-key with the gateway's key", p.auth, p.tokens, p.llmConfig.APIKey)
	}
}

func TestGetPolicyRefusesAnUnlistedType(t *testing.T) {
	msg := mustFail(t, azureParams(map[string]interface{}{
		"azureAuth": identity("container-apps"), "llmAllowedAuthTypes": []interface{}{"api-key"},
	}))
	if !strings.Contains(msg, `authentication type "container-apps" is not allowed on this gateway`) {
		t.Errorf("error = %q", msg)
	}
}

func TestGetPolicyRefusesAnUnlistedEndpoint(t *testing.T) {
	msg := mustFail(t, azureParams(map[string]interface{}{
		"llmApiKey": "secret-key-value-123", "llmAllowedEndpoints": []interface{}{"https://other.openai.azure.com"},
	}))
	if !strings.Contains(msg, "is not allowed on this gateway") || strings.Contains(msg, "secret-key-value-123") {
		t.Errorf("error = %q; want the endpoint refused without the key", msg)
	}
}

func TestGetPolicyRejectsAnIdentityWithOpenAI(t *testing.T) {
	useFakeTokens(t, &fakeTokens{token: "tok"})
	msg := mustFail(t, azureParams(map[string]interface{}{
		"llmProvider": "OPENAI", "llmModel": "gpt-4o-mini", "llmEndpoint": "https://api.openai.com/v1/chat/completions",
		"azureAuth": identity("workload-identity"),
	}))
	if !strings.Contains(msg, "workload-identity") || !strings.Contains(msg, "only supported for the AZURE_OPENAI LLM provider") {
		t.Errorf("error = %q", msg)
	}
}

func TestGetPolicyFailsWhenTheContainerAppIdentityIsUnavailable(t *testing.T) {
	t.Setenv("IDENTITY_ENDPOINT", "")
	t.Setenv("IDENTITY_HEADER", "")
	msg := mustFail(t, azureParams(map[string]interface{}{"azureAuth": identity("container-apps"), "llmApiKey": nil}))
	if !strings.Contains(msg, `authentication type "container-apps" can't be used`) || !strings.Contains(msg, "IDENTITY_ENDPOINT") {
		t.Errorf("error = %q", msg)
	}
}

// captureLogs routes slog.Default() to a JSON buffer for the test and restores it afterwards.
// Tests that use it must not run in parallel.
func captureLogs(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return &buf
}

func logRecords(t *testing.T, buf *bytes.Buffer) []map[string]interface{} {
	t.Helper()
	var records []map[string]interface{}
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		if line == "" {
			continue
		}
		var rec map[string]interface{}
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("bad log line %q: %v", line, err)
		}
		records = append(records, rec)
	}
	return records
}

// recordsAt returns the records logged at level (DEBUG, INFO, WARN or ERROR).
func recordsAt(recs []map[string]interface{}, level string) []map[string]interface{} {
	var out []map[string]interface{}
	for _, rec := range recs {
		if rec["level"] == level {
			out = append(out, rec)
		}
	}
	return out
}

// mentioning returns the records whose JSON contains text anywhere.
func mentioning(t *testing.T, recs []map[string]interface{}, text string) []map[string]interface{} {
	t.Helper()
	var out []map[string]interface{}
	for _, rec := range recs {
		b, err := json.Marshal(rec)
		if err != nil {
			t.Fatalf("marshal record: %v", err)
		}
		if strings.Contains(string(b), text) {
			out = append(out, rec)
		}
	}
	return out
}

const (
	tokenReason    = "Azure Container Apps answered 400"
	refusedAnswer  = "audience is incorrect for client 1111"
	fallbackMsg    = "IntelligentModelRouting: LLM call failed, using default model"
	noTokenMsg     = "IntelligentModelRouting: could not obtain an access token for the LLM provider"
	refusedMsg     = "IntelligentModelRouting: the LLM provider refused the access token"
	endedMsg       = "IntelligentModelRouting: the request ended before an access token was available"
	appIdentityID  = "00000000-0000-0000-0000-000000000001"
	classifyPrompt = `{"model":"original","messages":[{"role":"user","content":"write a python function"}]}`
)

func tokenErr(cached bool) error {
	return &azureauthentication.TokenError{Reason: tokenReason, Cached: cached}
}

// llmServer is a classifier endpoint that answers with status and body and records what it got.
type llmServer struct {
	*httptest.Server
	mu      sync.Mutex
	hits    int
	headers http.Header
}

func newLLMServer(t *testing.T, status int, body string) *llmServer {
	t.Helper()
	s := &llmServer{}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		s.hits++
		s.headers = r.Header.Clone()
		s.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(s.Close)
	return s
}

// answering is a classifier answer naming rule.
func answering(rule string) string {
	return `{"choices":[{"message":{"content":"` + rule + `"}}]}`
}

// endpointOf is an Azure OpenAI chat completions URL on server.
func endpointOf(server *httptest.Server) string {
	return server.URL + "/openai/deployments/chat/chat/completions?api-version=2024-10-21"
}

type ctxKey struct{}

// classify sends the prompt through OnRequestBody with ctx and returns the model it routed to.
func classify(t *testing.T, ctx context.Context, p *IntelligentModelRoutingPolicy) string {
	t.Helper()
	req := &policy.RequestContext{SharedContext: &policy.SharedContext{}, Body: &policy.Body{Content: []byte(classifyPrompt)}}
	mods, ok := p.OnRequestBody(ctx, req, nil).(policy.UpstreamRequestModifications)
	if !ok {
		t.Fatal("OnRequestBody did not return UpstreamRequestModifications")
	}
	var body struct {
		Model string `json:"model"`
	}
	if err := json.Unmarshal(mods.Body, &body); err != nil {
		t.Fatalf("routed body %q: %v", mods.Body, err)
	}
	return body.Model
}

// identityPolicy builds a policy that calls server with auth, with the gateway's key present.
func identityPolicy(t *testing.T, server *httptest.Server, auth map[string]interface{}, tokens *fakeTokens) *IntelligentModelRoutingPolicy {
	t.Helper()
	useFakeTokens(t, tokens)
	extra := map[string]interface{}{"llmEndpoint": endpointOf(server)}
	if auth != nil {
		extra["azureAuth"] = auth
	}
	p, err := buildPolicy(t, azureParams(extra))
	if err != nil {
		t.Fatalf("GetPolicy: %v", err)
	}
	return p
}

var containerAppsAuth = map[string]interface{}{"authenticationType": "container-apps", "clientId": appIdentityID}

func TestCallLLMIdentityModeSendsBearerOnly(t *testing.T) {
	server := newLLMServer(t, http.StatusOK, answering("coding"))
	tokens := &fakeTokens{token: "tok-123"}
	p := identityPolicy(t, server.Server, identity("workload-identity"), tokens)

	ctx := context.WithValue(context.Background(), ctxKey{}, "request-1")
	if got := classify(t, ctx, p); got != "coding-model" {
		t.Errorf("routed to %q, want coding-model", got)
	}
	if got := server.headers.Get("Authorization"); got != "Bearer tok-123" {
		t.Errorf("Authorization = %q, want the identity's token", got)
	}
	if got := server.headers.Get("api-key"); got != "" {
		t.Errorf("api-key = %q, want none in an identity mode", got)
	}
	if tokens.scope != defaultTokenScope || tokens.timeout != azureauthentication.DefaultTokenTimeout {
		t.Errorf("token asked for scope %q, timeout %v", tokens.scope, tokens.timeout)
	}
	if tokens.ctx == nil || tokens.ctx.Value(ctxKey{}) != "request-1" {
		t.Error("the token was not fetched with the request's context")
	}
}

func TestCallLLMRefusesARedirect(t *testing.T) {
	for name, auth := range map[string]map[string]interface{}{"api-key": nil, "workload-identity": identity("workload-identity")} {
		t.Run(name, func(t *testing.T) {
			target := newLLMServer(t, http.StatusOK, answering("coding"))
			var redirects atomic.Int32
			redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				redirects.Add(1)
				http.Redirect(w, r, endpointOf(target.Server), http.StatusTemporaryRedirect)
			}))
			t.Cleanup(redirect.Close)
			p := identityPolicy(t, redirect, auth, &fakeTokens{token: "tok-123"})

			if got := classify(t, context.Background(), p); got != "default-model" {
				t.Errorf("routed to %q, want default-model", got)
			}
			if got := redirects.Load(); got != 1 {
				t.Errorf("the redirecting endpoint got %d requests, want 1", got)
			}
			if target.hits != 0 {
				t.Errorf("the redirect target got %d requests, want none", target.hits)
			}
		})
	}
}

func TestOnRequestBodyTokenFailureLogsErrorAndUsesTheDefaultModel(t *testing.T) {
	server := newLLMServer(t, http.StatusOK, answering("coding"))
	p := identityPolicy(t, server.Server, containerAppsAuth, &fakeTokens{err: tokenErr(false)})
	buf := captureLogs(t)

	if got := classify(t, context.Background(), p); got != "default-model" {
		t.Errorf("routed to %q, want default-model", got)
	}
	if server.hits != 0 {
		t.Errorf("the classifier got %d requests without a token, want none", server.hits)
	}
	recs := logRecords(t, buf)
	errs := recordsAt(recs, "ERROR")
	if len(errs) != 1 || errs[0]["msg"] != noTokenMsg || errs[0]["reason"] != tokenReason ||
		errs[0]["authenticationType"] != "container-apps" || errs[0]["clientId"] != appIdentityID {
		t.Errorf("ERROR records = %v, want one %q with the reason, type and client ID", errs, noTokenMsg)
	}
	if warns := recordsAt(recs, "WARN"); len(warns) != 0 {
		t.Errorf("WARN records = %v, want none", warns)
	}
}

func TestOnRequestBodyCachedTokenFailureLogsOnlyAtDebug(t *testing.T) {
	server := newLLMServer(t, http.StatusOK, answering("coding"))
	p := identityPolicy(t, server.Server, containerAppsAuth, &fakeTokens{err: tokenErr(true)})
	buf := captureLogs(t)

	if got := classify(t, context.Background(), p); got != "default-model" {
		t.Errorf("routed to %q, want default-model", got)
	}
	recs := logRecords(t, buf)
	if loud := append(recordsAt(recs, "ERROR"), recordsAt(recs, "WARN")...); len(loud) != 0 {
		t.Errorf("ERROR/WARN records = %v, want none for a cached failure", loud)
	}
	if got := mentioning(t, recordsAt(recs, "DEBUG"), noTokenMsg); len(got) != 1 {
		t.Errorf("DEBUG records with %q = %v, want one", noTokenMsg, got)
	}
}

func TestOnRequestBodyEndedRequestLogsOnlyAtDebug(t *testing.T) {
	server := newLLMServer(t, http.StatusOK, answering("coding"))
	p := identityPolicy(t, server.Server, containerAppsAuth, &fakeTokens{err: tokenErr(false)})
	buf := captureLogs(t)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if got := classify(t, ctx, p); got != "default-model" {
		t.Errorf("routed to %q, want default-model", got)
	}
	recs := logRecords(t, buf)
	if loud := append(recordsAt(recs, "ERROR"), recordsAt(recs, "WARN")...); len(loud) != 0 {
		t.Errorf("ERROR/WARN records = %v, want none for a request that ended", loud)
	}
	if got := mentioning(t, recordsAt(recs, "DEBUG"), endedMsg); len(got) != 1 {
		t.Errorf("DEBUG records with %q = %v, want one", endedMsg, got)
	}
}

func TestOnRequestBodyRefusedTokenKeepsTheAnswerAtDebug(t *testing.T) {
	for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			server := newLLMServer(t, status, refusedAnswer)
			p := identityPolicy(t, server.Server, identity("workload-identity"), &fakeTokens{token: "tok-123"})
			buf := captureLogs(t)

			if got := classify(t, context.Background(), p); got != "default-model" {
				t.Errorf("routed to %q, want default-model", got)
			}
			recs := logRecords(t, buf)
			errs := recordsAt(recs, "ERROR")
			if len(errs) != 1 || errs[0]["msg"] != refusedMsg || errs[0]["status"] != float64(status) {
				t.Errorf("ERROR records = %v, want one %q with status %d", errs, refusedMsg, status)
			}
			if loud := mentioning(t, append(recordsAt(recs, "ERROR"), recordsAt(recs, "WARN")...), refusedAnswer); len(loud) != 0 {
				t.Errorf("Azure's answer reached ERROR/WARN: %v", loud)
			}
			if got := mentioning(t, recordsAt(recs, "DEBUG"), refusedAnswer); len(got) == 0 {
				t.Error("Azure's answer is not at DEBUG")
			}
		})
	}
}

// assertUnchangedFailure checks the v0.9 logging of a classifier failure: one DEBUG line with the error.
func assertUnchangedFailure(t *testing.T, buf *bytes.Buffer, wantError string) {
	t.Helper()
	recs := logRecords(t, buf)
	if loud := append(recordsAt(recs, "ERROR"), recordsAt(recs, "WARN")...); len(loud) != 0 {
		t.Errorf("ERROR/WARN records = %v, want none", loud)
	}
	got := mentioning(t, recordsAt(recs, "DEBUG"), fallbackMsg)
	if len(got) != 1 || !strings.Contains(got[0]["error"].(string), wantError) {
		t.Errorf("DEBUG records with %q = %v, want one whose error has %q", fallbackMsg, got, wantError)
	}
}

func TestOnRequestBodyAPIKeyFailureIsUnchanged(t *testing.T) {
	server := newLLMServer(t, http.StatusUnauthorized, refusedAnswer)
	p := identityPolicy(t, server.Server, nil, &fakeTokens{})
	buf := captureLogs(t)

	if got := classify(t, context.Background(), p); got != "default-model" {
		t.Errorf("routed to %q, want default-model", got)
	}
	assertUnchangedFailure(t, buf, "LLM returned status 401: "+refusedAnswer)
}

func TestOnRequestBodyIdentityServerErrorIsUnchanged(t *testing.T) {
	server := newLLMServer(t, http.StatusInternalServerError, "boom")
	p := identityPolicy(t, server.Server, identity("workload-identity"), &fakeTokens{token: "tok-123"})
	buf := captureLogs(t)

	if got := classify(t, context.Background(), p); got != "default-model" {
		t.Errorf("routed to %q, want default-model", got)
	}
	assertUnchangedFailure(t, buf, "LLM returned status 500: boom")
}
