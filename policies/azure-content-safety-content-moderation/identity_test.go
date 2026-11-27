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

package azurecontentsafetycontentmoderation

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/wso2/api-platform/sdk/ai/azureauthentication"
	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
	"gopkg.in/yaml.v3"
)

const (
	testClientID   = "11111111-2222-3333-4444-555555555555"
	testGatewayKey = "gateway-key"
)

// tokenCall is one Token call a fakeTokens received.
type tokenCall struct {
	scope   string
	timeout time.Duration
}

// fakeTokens stands in for the gateway's Azure identity: it answers every Token call with token,
// or with err when that is set.
type fakeTokens struct {
	token string
	err   error

	mu    sync.Mutex
	calls []tokenCall
}

func (f *fakeTokens) Token(ctx context.Context, scope string, timeout time.Duration) (string, error) {
	f.mu.Lock()
	f.calls = append(f.calls, tokenCall{scope: scope, timeout: timeout})
	f.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return "", &azureauthentication.TokenError{Reason: "timed out obtaining an access token from Microsoft Entra ID"}
	}
	if f.err != nil {
		return "", f.err
	}
	return f.token, nil
}

func (f *fakeTokens) tokenCalls() []tokenCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]tokenCall(nil), f.calls...)
}

// useFakeIdentity makes GetPolicy use tokens for every identity and returns the identities it
// asked for.
func useFakeIdentity(t *testing.T, tokens *fakeTokens) *[]azureauthentication.Identity {
	t.Helper()
	var asked []azureauthentication.Identity
	prev := getTokenSource
	getTokenSource = func(id azureauthentication.Identity) (tokenSource, error) {
		asked = append(asked, id)
		return tokens, nil
	}
	t.Cleanup(func() { getTokenSource = prev })
	return &asked
}

// captureLogs sends the default logger's records, Debug and up, to a buffer for one test.
func captureLogs(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return &buf
}

// logRecords returns the records with message msg, decoded.
func logRecords(t *testing.T, buf *bytes.Buffer, msg string) []map[string]any {
	t.Helper()
	var records []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		if line == "" {
			continue
		}
		var r map[string]any
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			t.Fatalf("log line %q: %v", line, err)
		}
		if r["msg"] == msg {
			records = append(records, r)
		}
	}
	return records
}

// contentSafetyServer answers every analyze call with a clean verdict and records the
// credential headers each call carried.
type contentSafetyServer struct {
	*httptest.Server
	mu      sync.Mutex
	calls   int
	keys    []string
	bearers []string
}

func newContentSafetyServer(t *testing.T, status func(call int) int) *contentSafetyServer {
	t.Helper()
	s := &contentSafetyServer{}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		s.calls++
		call := s.calls
		s.keys = append(s.keys, r.Header.Get("Ocp-Apim-Subscription-Key"))
		s.bearers = append(s.bearers, r.Header.Get("Authorization"))
		s.mu.Unlock()
		if code := status(call); code != http.StatusOK {
			w.WriteHeader(code)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"categoriesAnalysis":[{"category":"Hate","severity":0}]}`))
	}))
	t.Cleanup(s.Close)
	return s
}

// seen returns the number of calls so far and the key and Authorization header each carried.
func (s *contentSafetyServer) seen() (calls int, keys, bearers []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls, append([]string(nil), s.keys...), append([]string(nil), s.bearers...)
}

func alwaysOK(int) int { return http.StatusOK }

// azureAuth is an API's azureAuth object: the authentication type, then key/value pairs.
func azureAuth(typ string, kv ...interface{}) map[string]interface{} {
	auth := map[string]interface{}{"authenticationType": typ}
	for i := 0; i < len(kv); i += 2 {
		auth[kv[i].(string)] = kv[i+1]
	}
	return auth
}

// checkParams are the merged params of a request-side check: a gateway with an endpoint and a
// key, and an API that sets azureAuth to auth (no azureAuth when auth is nil). Further gateway
// settings or API params come as key/value pairs, and a nil value removes the key.
func checkParams(endpoint string, auth interface{}, kv ...interface{}) map[string]interface{} {
	params := map[string]interface{}{
		"azureContentSafetyEndpoint": endpoint,
		"azureContentSafetyKey":      testGatewayKey,
		"request":                    map[string]interface{}{"jsonPath": "$.text"},
	}
	if auth != nil {
		params["azureAuth"] = auth
	}
	for i := 0; i < len(kv); i += 2 {
		if kv[i+1] == nil {
			delete(params, kv[i].(string))
			continue
		}
		params[kv[i].(string)] = kv[i+1]
	}
	return params
}

func TestAuthenticationSettingsAreChecked(t *testing.T) {
	useFakeIdentity(t, &fakeTokens{token: "tok-1"})
	const endpoint = "https://cs.example.com"
	const scope = "https://cognitiveservices.azure.com/.default"

	valid := []struct {
		name   string
		params map[string]interface{}
	}{
		{"api-key without azureAuth", checkParams(endpoint, nil)},
		{"api-key named", checkParams(endpoint, azureAuth("api-key"))},
		{"an empty azureAuth means api-key", checkParams(endpoint, map[string]interface{}{})},
		{"an empty type means api-key", checkParams(endpoint, azureAuth(""))},
		{"a null type means api-key", checkParams(endpoint, map[string]interface{}{"authenticationType": nil})},
		// The policy ignores an identity's fields with api-key; the schema still checks their format.
		{"api-key ignores identity fields", checkParams(endpoint, azureAuth("api-key", "clientId", "not-a-guid", "scope", "not-a-scope"))},
		{"workload identity without a gateway key", checkParams(endpoint, azureAuth("workload-identity"), "azureContentSafetyKey", nil)},
		{"managed identity with a client ID", checkParams(endpoint, azureAuth("managed-identity", "clientId", testClientID))},
		{"Container Apps with a scope", checkParams(endpoint, azureAuth("container-apps", "scope", scope))},
	}
	for _, tt := range valid {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := GetPolicy(policy.PolicyMetadata{}, tt.params); err != nil {
				t.Fatalf("GetPolicy: %v", err)
			}
		})
	}

	invalid := []struct {
		name   string
		params map[string]interface{}
		want   []string
	}{
		{"azureAuth that isn't an object", checkParams(endpoint, "workload-identity"), []string{"'azureAuth' must be an object"}},
		{
			"an unknown type", checkParams(endpoint, azureAuth("client-secret")),
			[]string{"'azureAuth.authenticationType' must be", `"api-key", "workload-identity", "managed-identity" or "container-apps"`},
		},
		{"a type that isn't a string", checkParams(endpoint, azureAuth("api-key", "authenticationType", 1)), []string{"'azureAuth.authenticationType' must be a string"}},
		{"api-key without a gateway key", checkParams(endpoint, nil, "azureContentSafetyKey", nil), []string{"'azureContentSafetyKey' parameter is required"}},
		{"api-key with an empty gateway key", checkParams(endpoint, azureAuth("api-key"), "azureContentSafetyKey", ""), []string{"'azureContentSafetyKey' cannot be empty"}},
		{"a client ID that isn't a GUID", checkParams(endpoint, azureAuth("managed-identity", "clientId", "my-app")), []string{"'azureAuth.clientId' is invalid", "GUID"}},
		{"a client ID that isn't a string", checkParams(endpoint, azureAuth("managed-identity", "clientId", 7)), []string{"'azureAuth.clientId' must be a string"}},
		{"a scope without /.default", checkParams(endpoint, azureAuth("workload-identity", "scope", "https://cognitiveservices.azure.com")), []string{"'azureAuth.scope' is invalid", "/.default"}},
		{"two scopes", checkParams(endpoint, azureAuth("workload-identity", "scope", "https://a/.default https://b/.default")), []string{"'azureAuth.scope' is invalid"}},
		{"a scope that isn't a string", checkParams(endpoint, azureAuth("workload-identity", "scope", true)), []string{"'azureAuth.scope' must be a string"}},
	}
	for _, tt := range invalid {
		t.Run(tt.name, func(t *testing.T) {
			_, err := GetPolicy(policy.PolicyMetadata{}, tt.params)
			if err == nil {
				t.Fatal("GetPolicy succeeded, want an error")
			}
			for _, want := range tt.want {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error = %q, want it to contain %q", err, want)
				}
			}
		})
	}
}

// The gateway's allowlist limits the authentication type an API may use, counting an API without
// azureAuth as api-key, and is checked before any identity is asked for.
func TestTheAllowlistLimitsTheType(t *testing.T) {
	const endpoint = "https://cs.example.com"
	const key = "azureContentSafetyAllowedAuthTypes"
	for _, tt := range []struct {
		name    string
		allowed interface{}
		auth    interface{}
		want    []string // error fragments; none means the API deploys
	}{
		{name: "no list allows any type", auth: azureAuth("managed-identity")},
		{name: "an empty list allows any type", allowed: []interface{}{}, auth: azureAuth("container-apps")},
		{name: "a listed identity", allowed: []interface{}{"workload-identity"}, auth: azureAuth("workload-identity")},
		{name: "a list of strings", allowed: []string{"api-key", "workload-identity"}, auth: azureAuth("workload-identity")},
		{name: "api-key listed, no azureAuth", allowed: []interface{}{"api-key"}},
		{
			name: "no azureAuth counts as api-key", allowed: []interface{}{"workload-identity"},
			want: []string{`authentication type "api-key" is not allowed on this gateway`, `'azureContentSafetyAllowedAuthTypes' allows "workload-identity"`},
		},
		{
			name: "an identity not listed", allowed: []interface{}{"api-key", "workload-identity"}, auth: azureAuth("managed-identity"),
			want: []string{`authentication type "managed-identity" is not allowed on this gateway`, `allows "api-key" or "workload-identity"`},
		},
		{
			name: "an unknown entry fails even for an allowed type", allowed: []interface{}{"api-key", "client-secret"},
			want: []string{`'azureContentSafetyAllowedAuthTypes' entry "client-secret" is not an authentication type`},
		},
		{name: "a list that isn't an array", allowed: "api-key", want: []string{"'azureContentSafetyAllowedAuthTypes' must be an array of strings"}},
		{name: "an entry that isn't a string", allowed: []interface{}{"api-key", 3}, want: []string{"'azureContentSafetyAllowedAuthTypes' must be an array of strings"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			asked := useFakeIdentity(t, &fakeTokens{token: "tok-1"})
			params := checkParams(endpoint, tt.auth)
			if tt.allowed != nil {
				params[key] = tt.allowed
			}
			_, err := GetPolicy(policy.PolicyMetadata{}, params)
			if len(tt.want) == 0 {
				if err != nil {
					t.Fatalf("GetPolicy: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("GetPolicy succeeded, want the allowlist to refuse it")
			}
			for _, want := range tt.want {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error = %q, want it to contain %q", err, want)
				}
			}
			if len(*asked) != 0 {
				t.Errorf("identities asked for = %+v, want none for a refused API", *asked)
			}
		})
	}
}

// The gateway's allowlist of endpoints is checked against the endpoint in effect, which an API can
// override, in every authentication mode and before any identity is asked for, so neither the
// gateway's key nor a token for its identity goes to an endpoint the gateway hasn't listed.
func TestTheEndpointAllowlistLimitsWhereCredentialsGo(t *testing.T) {
	const key = "azureContentSafetyAllowedEndpoints"
	const listed = "https://cs.example.com"
	for _, tt := range []struct {
		name     string
		endpoint string
		allowed  interface{}
		auth     interface{}
		want     []string // error fragments; none means the API deploys
	}{
		{name: "no list allows any endpoint", endpoint: "https://other.example.com"},
		{name: "an empty list allows any endpoint", endpoint: "https://other.example.com", allowed: []interface{}{}},
		{name: "a listed endpoint", endpoint: listed, allowed: []interface{}{listed}},
		{name: "a list of strings", endpoint: listed, allowed: []string{"https://a.example.com", listed}},
		{name: "a trailing slash on either side", endpoint: listed + "/", allowed: []interface{}{"https://a.example.com/", listed + "/"}},
		{name: "the host in another case", endpoint: "https://CS.Example.com", allowed: []interface{}{listed}},
		{name: "a listed endpoint with an identity", endpoint: listed, allowed: []interface{}{listed}, auth: azureAuth("workload-identity")},
		{
			name: "an endpoint not on the list, with the key", endpoint: "https://evil.example.com", allowed: []interface{}{listed},
			want: []string{`endpoint "https://evil.example.com" is not allowed on this gateway`, `'azureContentSafetyAllowedEndpoints' allows "https://cs.example.com"`},
		},
		{
			name: "an endpoint not on the list, with an identity", endpoint: "https://evil.example.com", allowed: []interface{}{listed},
			auth: azureAuth("managed-identity"), want: []string{`endpoint "https://evil.example.com" is not allowed on this gateway`},
		},
		{
			name: "a path is part of the endpoint", endpoint: listed + "/other", allowed: []interface{}{listed},
			want: []string{"is not allowed on this gateway"},
		},
		{
			name: "an entry that isn't a URL fails even for a listed endpoint", endpoint: listed, allowed: []interface{}{listed, "cs.example.com"},
			want: []string{`'azureContentSafetyAllowedEndpoints' entry "cs.example.com" is not an endpoint URL`},
		},
		{name: "a list that isn't an array", endpoint: listed, allowed: listed, want: []string{"'azureContentSafetyAllowedEndpoints' must be an array of strings"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			asked := useFakeIdentity(t, &fakeTokens{token: "tok-1"})
			params := checkParams(tt.endpoint, tt.auth)
			if tt.allowed != nil {
				params[key] = tt.allowed
			}
			_, err := GetPolicy(policy.PolicyMetadata{}, params)
			if len(tt.want) == 0 {
				if err != nil {
					t.Fatalf("GetPolicy: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("GetPolicy succeeded, want the endpoint allowlist to refuse it")
			}
			for _, want := range tt.want {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error = %q, want it to contain %q", err, want)
				}
			}
			if len(*asked) != 0 {
				t.Errorf("identities asked for = %+v, want none for a refused API", *asked)
			}
		})
	}
}

// Each identity mode asks for the gateway's identity of that type and the API's client ID, never
// with a tenant, and asks for tokens for Content Safety's scope unless the API names another.
func TestIdentityModesUseTheGatewaysIdentity(t *testing.T) {
	for _, tt := range []struct {
		typ, clientID, scope, wantScope string
	}{
		{typ: "workload-identity", wantScope: "https://cognitiveservices.azure.com/.default"},
		{typ: "managed-identity", clientID: testClientID, wantScope: "https://cognitiveservices.azure.com/.default"},
		{typ: "container-apps", scope: "api://content-safety/.default", wantScope: "api://content-safety/.default"},
	} {
		t.Run(tt.typ, func(t *testing.T) {
			tokens := &fakeTokens{token: "tok-1"}
			asked := useFakeIdentity(t, tokens)
			srv := newContentSafetyServer(t, alwaysOK)
			auth := azureAuth(tt.typ)
			if tt.clientID != "" {
				auth["clientId"] = tt.clientID
			}
			if tt.scope != "" {
				auth["scope"] = tt.scope
			}

			p := mustGetAzurePolicy(t, checkParams(srv.URL, auth))
			if want := (azureauthentication.Identity{Type: tt.typ, ClientID: tt.clientID}); len(*asked) != 1 || (*asked)[0] != want {
				t.Fatalf("identities asked for = %+v, want [%+v]", *asked, want)
			}
			action := p.OnRequestBody(context.Background(), azureRequestContext(`{"text":"hello"}`), nil)
			if _, ok := action.(policy.UpstreamRequestModifications); !ok {
				t.Fatalf("action = %T, want the request to pass", action)
			}
			if calls := tokens.tokenCalls(); len(calls) != 1 || calls[0].scope != tt.wantScope || calls[0].timeout != azureauthentication.DefaultTokenTimeout {
				t.Fatalf("token calls = %+v, want one for %s within %s", calls, tt.wantScope, azureauthentication.DefaultTokenTimeout)
			}
		})
	}
}

// GetPolicy fails, and the API with it, when the host can't provide the identity.
func TestAnUnavailableIdentityFailsTheDeployment(t *testing.T) {
	prev := getTokenSource
	getTokenSource = func(azureauthentication.Identity) (tokenSource, error) {
		return nil, errors.New("Container Apps managed identity is not available: IDENTITY_ENDPOINT and IDENTITY_HEADER are not set")
	}
	t.Cleanup(func() { getTokenSource = prev })

	_, err := GetPolicy(policy.PolicyMetadata{}, checkParams("https://cs.example.com", azureAuth("container-apps")))
	if err == nil || !strings.Contains(err.Error(), "IDENTITY_ENDPOINT and IDENTITY_HEADER are not set") {
		t.Fatalf("GetPolicy = %v, want the identity's error", err)
	}
}

// Without the fake, GetPolicy asks the real package, which checks the host's environment.
func TestContainerAppsWithoutItsEndpointFailsTheDeployment(t *testing.T) {
	t.Setenv("IDENTITY_ENDPOINT", "")
	t.Setenv("IDENTITY_HEADER", "")

	_, err := GetPolicy(policy.PolicyMetadata{}, checkParams("https://cs.example.com", azureAuth("container-apps")))
	if err == nil || !strings.Contains(err.Error(), "Container Apps managed identity is not available") {
		t.Fatalf("GetPolicy = %v, want Container Apps managed identity not available", err)
	}
}

// APIs on one gateway can authenticate differently: an identity mode sends the token and never
// the gateway's key, and api-key sends the gateway's key and no token.
func TestEachAPIUsesItsOwnMode(t *testing.T) {
	useFakeIdentity(t, &fakeTokens{token: "tok-1"})

	srv := newContentSafetyServer(t, alwaysOK)
	identity := mustGetAzurePolicy(t, checkParams(srv.URL, azureAuth("managed-identity")))
	identity.OnRequestBody(context.Background(), azureRequestContext(`{"text":"hello"}`), nil)
	if calls, keys, bearers := srv.seen(); calls != 1 || bearers[0] != "Bearer tok-1" || keys[0] != "" {
		t.Fatalf("calls = %d, Authorization = %q, key = %q; want one call with the bearer token and no key", calls, bearers, keys)
	}

	for _, auth := range []interface{}{nil, azureAuth("api-key")} {
		keySrv := newContentSafetyServer(t, alwaysOK)
		apiKey := mustGetAzurePolicy(t, checkParams(keySrv.URL, auth))
		apiKey.OnRequestBody(context.Background(), azureRequestContext(`{"text":"hello"}`), nil)
		if calls, keys, bearers := keySrv.seen(); calls != 1 || keys[0] != testGatewayKey || bearers[0] != "" {
			t.Fatalf("azureAuth %v: calls = %d, key = %q, Authorization = %q; want one call with the gateway's key and no token", auth, calls, keys, bearers)
		}
	}
}

// The token is fetched once per check: a call that is retried after a 5xx reuses it.
func TestOneTokenPerCheck(t *testing.T) {
	tokens := &fakeTokens{token: "tok-1"}
	useFakeIdentity(t, tokens)
	srv := newContentSafetyServer(t, func(call int) int {
		if call == 1 {
			return http.StatusServiceUnavailable
		}
		return http.StatusOK
	})

	p := mustGetAzurePolicy(t, checkParams(srv.URL, azureAuth("workload-identity")))
	action := p.OnRequestBody(context.Background(), azureRequestContext(`{"text":"hello"}`), nil)
	if _, ok := action.(policy.UpstreamRequestModifications); !ok {
		t.Fatalf("action = %T, want the request to pass after the retry", action)
	}
	calls, _, bearers := srv.seen()
	if calls != 2 || len(tokens.tokenCalls()) != 1 {
		t.Fatalf("Content Safety calls = %d, token calls = %d; want 2 calls with one token", calls, len(tokens.tokenCalls()))
	}
	if bearers[0] != "Bearer tok-1" || bearers[1] != "Bearer tok-1" {
		t.Fatalf("Authorization = %q, want the token on both calls", bearers)
	}
}

func TestATokenFailureFollowsPassthroughOnError(t *testing.T) {
	const reason = "the Container Apps identity endpoint rejected the token request (HTTP 400)"
	tokenErr := &azureauthentication.TokenError{Reason: reason, Rejected: true}

	for _, isResponse := range []bool{false, true} {
		phase := "request"
		if isResponse {
			phase = "response"
		}
		t.Run(phase, func(t *testing.T) {
			useFakeIdentity(t, &fakeTokens{err: tokenErr})
			srv := newContentSafetyServer(t, alwaysOK)
			run := func(settings map[string]interface{}) interface{} {
				settings["jsonPath"] = "$.text"
				params := checkParams(srv.URL, azureAuth("container-apps"), "request", nil)
				params[phase] = settings
				p := mustGetAzurePolicy(t, params)
				if isResponse {
					return p.OnResponseBody(context.Background(), azureResponseContext(`{"text":"hello"}`), nil)
				}
				return p.OnRequestBody(context.Background(), azureRequestContext(`{"text":"hello"}`), nil)
			}

			// passthroughOnError lets the content through unchecked.
			switch got := run(map[string]interface{}{"passthroughOnError": true}).(type) {
			case policy.UpstreamRequestModifications, policy.DownstreamResponseModifications:
				if d, ok := got.(policy.DownstreamResponseModifications); ok && d.StatusCode != nil {
					t.Fatalf("passthrough set status %d", *d.StatusCode)
				}
			default:
				t.Fatalf("passthroughOnError: action = %T, want the content to pass", got)
			}

			// Without it, the check fails the way a failed Content Safety call does, with the
			// token reason in the fault's description only.
			direction := "REQUEST"
			wantDirection := policy.DirectionRequest
			if isResponse {
				direction, wantDirection = "RESPONSE", policy.DirectionResponse
			}
			wantBody := `{"message":{"action":"GUARDRAIL_INTERVENED","actionReason":"Error calling Azure Content Safety API","direction":"` + direction + `","interveningGuardrail":"AzureContentSafetyContentModeration"},"type":"AZURE_CONTENT_SAFETY_CONTENT_MODERATION"}`
			got := run(map[string]interface{}{})
			assertNoVerdictFault(t, got, wantBody, policy.FaultCodeMediationFailed, policy.FaultTypeMediation, wantDirection)
			if d := faultOf(t, got).Description; !strings.Contains(d, reason) {
				t.Errorf("fault description = %q, want the token reason", d)
			}

			// showAssessment shows the generic text, never the reason.
			wantBody = `{"message":{"action":"GUARDRAIL_INTERVENED","actionReason":"Error calling Azure Content Safety API","assessments":["Could not obtain an access token for Azure Content Safety"],"direction":"` + direction + `","interveningGuardrail":"AzureContentSafetyContentModeration"},"type":"AZURE_CONTENT_SAFETY_CONTENT_MODERATION"}`
			assertNoVerdictFault(t, run(map[string]interface{}{"showAssessment": true}), wantBody, policy.FaultCodeMediationFailed, policy.FaultTypeMediation, wantDirection)

			if calls, _, _ := srv.seen(); calls != 0 {
				t.Fatalf("Content Safety calls = %d, want none without a token", calls)
			}
		})
	}
}

func faultOf(t *testing.T, action interface{}) *policy.FaultDetails {
	t.Helper()
	switch a := action.(type) {
	case policy.ImmediateResponse:
		return a.Fault
	case policy.DownstreamResponseModifications:
		return a.Fault
	}
	t.Fatalf("action %T has no fault", action)
	return nil
}

// A token failure is logged at ERROR even when passthroughOnError hides it from the client,
// except a rejection answered from the cache, which was logged when it happened, and a request
// that ended before the token arrived, which is not an identity failure.
func TestTokenFailureLogs(t *testing.T) {
	const msg = "AzureContentSafety: could not obtain an access token for Azure Content Safety"
	const reason = "Microsoft Entra ID rejected the token request (HTTP 401, invalid_client)"
	for _, tt := range []struct {
		name      string
		err       error
		ctx       func() context.Context
		wantLevel string
	}{
		{name: "a failure", err: &azureauthentication.TokenError{Reason: reason, Rejected: true}, wantLevel: "ERROR"},
		{name: "a cached rejection", err: &azureauthentication.TokenError{Reason: reason, Rejected: true, Cached: true}, wantLevel: "DEBUG"},
		{name: "a request that ended", err: nil, ctx: func() context.Context {
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			return ctx
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			logs := captureLogs(t)
			useFakeIdentity(t, &fakeTokens{token: "tok-1", err: tt.err})
			srv := newContentSafetyServer(t, alwaysOK)
			p := mustGetAzurePolicy(t, checkParams(srv.URL, azureAuth("managed-identity", "clientId", testClientID),
				"request", map[string]interface{}{"jsonPath": "$.text", "passthroughOnError": true}))
			ctx := context.Background()
			if tt.ctx != nil {
				ctx = tt.ctx()
			}
			p.OnRequestBody(ctx, azureRequestContext(`{"text":"hello"}`), nil)

			records := logRecords(t, logs, msg)
			if tt.wantLevel == "" {
				if len(records) != 0 {
					t.Fatalf("records = %v, want no token failure logged for a request that ended", records)
				}
				return
			}
			if len(records) != 1 || records[0]["level"] != tt.wantLevel {
				t.Fatalf("records = %v, want one at %s", records, tt.wantLevel)
			}
			r := records[0]
			if r["reason"] != reason || r["clientId"] != testClientID || r["authenticationType"] != "managed-identity" {
				t.Errorf("record = %v, want the reason, client ID and authentication type", r)
			}
		})
	}
}

// policyDefinition is the part of policy-definition.yaml the code depends on.
type policyDefinition struct {
	Parameters struct {
		AdditionalProperties *bool `yaml:"additionalProperties"`
		Properties           map[string]struct {
			Default              interface{} `yaml:"default"`
			AdditionalProperties *bool       `yaml:"additionalProperties"`
			Properties           map[string]struct {
				Enum    []string `yaml:"enum"`
				Default *string  `yaml:"default"`
			} `yaml:"properties"`
		} `yaml:"properties"`
	} `yaml:"parameters"`
	SystemParameters struct {
		Properties map[string]struct {
			Items struct {
				Enum []string `yaml:"enum"`
			} `yaml:"items"`
			Default string `yaml:"wso2/defaultValue"`
		} `yaml:"properties"`
		Required []string `yaml:"required"`
	} `yaml:"systemParameters"`
}

// The schema has to agree with the code: the types it offers, the default, the gateway settings,
// and no API params beyond the ones it lists, since an API's params override the gateway's (Q17).
// An API may override the endpoint and key (Q18), but never the allowlists.
func TestThePolicyDefinitionMatchesTheCode(t *testing.T) {
	raw, err := os.ReadFile("policy-definition.yaml")
	if err != nil {
		t.Fatalf("read policy-definition.yaml: %v", err)
	}
	var def policyDefinition
	if err := yaml.Unmarshal(raw, &def); err != nil {
		t.Fatalf("parse policy-definition.yaml: %v", err)
	}
	types := append([]string{authenticationTypeAPIKey}, azureauthentication.Types()...)

	if ap := def.Parameters.AdditionalProperties; ap == nil || *ap {
		t.Error("parameters must set additionalProperties: false, or an API can set the gateway's settings itself")
	}
	auth, ok := def.Parameters.Properties["azureAuth"]
	if !ok {
		t.Fatal("parameters has no azureAuth")
	}
	if ap := auth.AdditionalProperties; ap == nil || *ap {
		t.Error("azureAuth must set additionalProperties: false")
	}
	if got := auth.Properties["authenticationType"].Enum; !slices.Equal(got, types) {
		t.Errorf("azureAuth.authenticationType enum = %q, want %q", got, types)
	}
	if d := auth.Properties["authenticationType"].Default; d == nil || *d != authenticationTypeAPIKey {
		t.Errorf("azureAuth.authenticationType default = %v, want %q", d, authenticationTypeAPIKey)
	}
	for _, name := range []string{"clientId", "scope"} {
		if _, ok := auth.Properties[name]; !ok {
			t.Errorf("azureAuth has no %s", name)
		}
	}

	// An API's override of a gateway setting has the setting's name and no default: a default
	// would replace the gateway's value on every API.
	for _, name := range []string{"azureContentSafetyEndpoint", "azureContentSafetyKey"} {
		override, ok := def.Parameters.Properties[name]
		if !ok {
			t.Errorf("parameters has no %s, so an API can't override it", name)
		} else if override.Default != nil {
			t.Errorf("parameters.%s has a default, which would replace the gateway's on every API", name)
		}
	}
	for _, name := range []string{"azureContentSafetyAllowedAuthTypes", "azureContentSafetyAllowedEndpoints"} {
		if _, ok := def.Parameters.Properties[name]; ok {
			t.Errorf("parameters lists %s, so an API could lift the gateway's allowlist", name)
		}
	}

	wantSystem := map[string]string{
		"azureContentSafetyEndpoint":         "${config.azurecontentsafety_endpoint}",
		"azureContentSafetyKey":              "${config.azurecontentsafety_key}",
		"azureContentSafetyAllowedAuthTypes": "${config.azurecontentsafety_allowed_auth_types}",
		"azureContentSafetyAllowedEndpoints": "${config.azurecontentsafety_allowed_endpoints}",
	}
	if len(def.SystemParameters.Properties) != len(wantSystem) {
		t.Errorf("system parameters = %d, want %d: %v", len(def.SystemParameters.Properties), len(wantSystem), wantSystem)
	}
	for name, want := range wantSystem {
		if got := def.SystemParameters.Properties[name].Default; got != want {
			t.Errorf("%s wso2/defaultValue = %q, want %q", name, got, want)
		}
	}
	if got := def.SystemParameters.Properties["azureContentSafetyAllowedAuthTypes"].Items.Enum; !slices.Equal(got, types) {
		t.Errorf("azureContentSafetyAllowedAuthTypes items enum = %q, want %q", got, types)
	}
	if !slices.Equal(def.SystemParameters.Required, []string{"azureContentSafetyEndpoint"}) {
		t.Errorf("required system parameters = %q, want only the endpoint", def.SystemParameters.Required)
	}
}
