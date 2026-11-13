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

package azureauthentication

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"os"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

func newRequestHeaderContext(shared *policy.SharedContext) *policy.RequestHeaderContext {
	if shared == nil {
		shared = &policy.SharedContext{RequestID: "req-1", APIName: "foundry"}
	}
	return &policy.RequestHeaderContext{
		SharedContext: shared,
		Headers:       policy.NewHeaders(map[string][]string{}),
		Path:          "/models/chat/completions",
		Method:        http.MethodPost,
		Authority:     "gateway.example.com",
		Scheme:        "https",
	}
}

func mustGetPolicy(t *testing.T, params map[string]interface{}) *Policy {
	t.Helper()
	p, err := GetPolicy(policy.PolicyMetadata{RouteName: "route-1", APIName: "foundry"}, params)
	if err != nil {
		t.Fatalf("GetPolicy: %v", err)
	}
	return p.(*Policy)
}

func requireHeaderMods(t *testing.T, action policy.RequestHeaderAction) policy.UpstreamRequestHeaderModifications {
	t.Helper()
	mods, ok := action.(policy.UpstreamRequestHeaderModifications)
	if !ok {
		t.Fatalf("action = %#v, want UpstreamRequestHeaderModifications", action)
	}
	return mods
}

func requireFailure(t *testing.T, action policy.RequestHeaderAction) policy.ImmediateResponse {
	t.Helper()
	resp, ok := action.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("action = %#v, want ImmediateResponse", action)
	}
	return resp
}

type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func captureLogs(t *testing.T) *lockedBuffer {
	t.Helper()
	buf := &lockedBuffer{}
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return buf
}

func TestGetPolicyRejectsInvalidParams(t *testing.T) {
	setWorkloadIdentityEnv(t, "federated-token")
	useFakeAzure(t, answer(http.StatusOK, entraToken("tok")))

	valid := func(extra map[string]interface{}) map[string]interface{} {
		params := map[string]interface{}{"authenticationType": "workload-identity"}
		for k, v := range extra {
			params[k] = v
		}
		return params
	}

	tests := []struct {
		name        string
		params      map[string]interface{}
		wantInError string
	}{
		{name: "missing authenticationType", params: map[string]interface{}{}, wantInError: "authenticationType"},
		{name: "non-string authenticationType", params: map[string]interface{}{"authenticationType": 1}, wantInError: "authenticationType"},
		{name: "unsupported authenticationType", params: map[string]interface{}{"authenticationType": "client-secret"}, wantInError: `"workload-identity", "managed-identity" or "container-apps"`},
		{name: "container-apps with tenantId", params: map[string]interface{}{"authenticationType": "container-apps", "tenantId": "contoso.onmicrosoft.com"}, wantInError: `'tenantId' is not used with authenticationType "container-apps"`},
		{name: "container-apps with a clientId that is not a GUID", params: map[string]interface{}{"authenticationType": "container-apps", "clientId": "my-app"}, wantInError: "clientId"},
		{name: "managed-identity with tenantId", params: map[string]interface{}{"authenticationType": "managed-identity", "tenantId": "contoso.onmicrosoft.com"}, wantInError: `'tenantId' is not used with authenticationType "managed-identity"`},
		{name: "managed-identity with a clientId that is not a GUID", params: map[string]interface{}{"authenticationType": "managed-identity", "clientId": "my-app"}, wantInError: "clientId"},
		{name: "scope without .default", params: valid(map[string]interface{}{"scope": "https://ai.azure.com"}), wantInError: "scope"},
		{name: "two scopes", params: valid(map[string]interface{}{"scope": "https://ai.azure.com/.default https://graph.microsoft.com/.default"}), wantInError: "scope"},
		{name: "non-string scope", params: valid(map[string]interface{}{"scope": 42}), wantInError: "scope"},
		{name: "clientId not a GUID", params: valid(map[string]interface{}{"clientId": "my-app"}), wantInError: "clientId"},
		{name: "tenantId with a slash", params: valid(map[string]interface{}{"tenantId": "a/b"}), wantInError: "tenantId"},
		{name: "tenantId with a dot dot", params: valid(map[string]interface{}{"tenantId": "contoso..com"}), wantInError: "tenantId"},
		{name: "empty headerName", params: valid(map[string]interface{}{"headerName": ""}), wantInError: "headerName"},
		{name: "headerName with a space", params: valid(map[string]interface{}{"headerName": "Bad Header"}), wantInError: "headerName"},
		{name: "pseudo-header", params: valid(map[string]interface{}{"headerName": ":authority"}), wantInError: "headerName"},
		{name: "valuePrefix with a line break", params: valid(map[string]interface{}{"valuePrefix": "Bearer\r\nX-Injected: 1"}), wantInError: "valuePrefix"},
		{name: "unparsable timeout", params: valid(map[string]interface{}{"tokenRequestTimeout": "soon"}), wantInError: "tokenRequestTimeout"},
		{name: "zero timeout", params: valid(map[string]interface{}{"tokenRequestTimeout": "0s"}), wantInError: "tokenRequestTimeout"},
		{name: "negative timeout", params: valid(map[string]interface{}{"tokenRequestTimeout": "-1s"}), wantInError: "tokenRequestTimeout"},
		{name: "timeout over 30s", params: valid(map[string]interface{}{"tokenRequestTimeout": "45s"}), wantInError: "tokenRequestTimeout"},
		{name: "non-string timeout", params: valid(map[string]interface{}{"tokenRequestTimeout": 10}), wantInError: "tokenRequestTimeout"},
		{name: "fractional seconds timeout", params: valid(map[string]interface{}{"tokenRequestTimeout": "1.5s"}), wantInError: "tokenRequestTimeout"},
		{name: "minutes timeout", params: valid(map[string]interface{}{"tokenRequestTimeout": "1m"}), wantInError: "tokenRequestTimeout"},
		{name: "timeout with a leading zero", params: valid(map[string]interface{}{"tokenRequestTimeout": "05s"}), wantInError: "tokenRequestTimeout"},
		{name: "timeout over 30000ms", params: valid(map[string]interface{}{"tokenRequestTimeout": "30001ms"}), wantInError: "tokenRequestTimeout"},
		{name: "misspelled headerName", params: valid(map[string]interface{}{"headerNmae": "X-Token"}), wantInError: "'headerNmae' is not a parameter"},
		{name: "clientId in the wrong case", params: map[string]interface{}{"authenticationType": "managed-identity", "clientID": testClientID}, wantInError: "'clientID' is not a parameter"},
		{name: "unknown key set to null", params: valid(map[string]interface{}{"scopes": nil}), wantInError: "'scopes' is not a parameter"},
		{name: "two unknown keys", params: valid(map[string]interface{}{"tenantID": "contoso.onmicrosoft.com", "headerNmae": "X-Token"}), wantInError: "'headerNmae', 'tenantID' are not parameters"},
		{name: "authenticationType misspelled", params: map[string]interface{}{"authType": "workload-identity"}, wantInError: "'authType' is not a parameter"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := GetPolicy(policy.PolicyMetadata{}, tt.params)
			if err == nil {
				t.Fatal("expected an error")
			}
			if !strings.Contains(err.Error(), tt.wantInError) {
				t.Fatalf("error %q does not mention %q", err, tt.wantInError)
			}
		})
	}
}

// An unknown key is reported with the parameters the policy has, so a typo in an LLM provider's
// upstream.auth, which the controller does not check, names the fix.
func TestUnknownParamErrorListsTheParameters(t *testing.T) {
	_, err := extractParams(map[string]interface{}{"authenticationType": "workload-identity", "headerNmae": "X-Token"})
	if err == nil {
		t.Fatal("expected an error")
	}
	want := "'headerNmae' is not a parameter of the azure-authentication policy; its parameters are " +
		"authenticationType, scope, clientId, tenantId, headerName, valuePrefix and tokenRequestTimeout"
	if err.Error() != want {
		t.Fatalf("error = %q, want %q", err, want)
	}
}

// The gateway controller adds attachedTo to the params of every policy it attaches, so it must not
// be rejected as an unknown parameter.
func TestGetPolicyAcceptsTheGatewaysAttachedToParam(t *testing.T) {
	setWorkloadIdentityEnv(t, "federated-token")
	useFakeAzure(t, answer(http.StatusOK, entraToken("tok-1")))

	for _, level := range []string{"api", "route"} {
		p := mustGetPolicy(t, map[string]interface{}{"authenticationType": "workload-identity", "attachedTo": level})
		requireHeaderMods(t, p.OnRequestHeaders(context.Background(), newRequestHeaderContext(nil), nil))
	}
}

// paramNames must list exactly the parameters of policy-definition.yaml, in order, or a parameter
// added there would be rejected as unknown when it arrives through upstream.auth.
func TestParamNamesMatchThePolicyDefinition(t *testing.T) {
	data, err := os.ReadFile("policy-definition.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var defined []string
	inParameters := false
	property := regexp.MustCompile(`^    ([A-Za-z]+):\s*$`)
	for _, line := range strings.Split(string(data), "\n") {
		if len(line) > 0 && line[0] != ' ' && line[0] != '#' {
			inParameters = strings.HasPrefix(line, "parameters:")
			continue
		}
		if m := property.FindStringSubmatch(line); inParameters && m != nil {
			defined = append(defined, m[1])
		}
	}
	if len(defined) == 0 {
		t.Fatal("found no parameters in policy-definition.yaml")
	}
	if !reflect.DeepEqual(paramNames, defined) {
		t.Fatalf("paramNames = %v, policy-definition.yaml defines %v", paramNames, defined)
	}
}

// TestTokenRequestTimeoutFormats pins the formats the policy definition's pattern admits, so a
// value given through an LLM provider's upstream.auth, which the controller does not validate,
// behaves exactly like one on an API.
func TestTokenRequestTimeoutFormats(t *testing.T) {
	for value, want := range map[string]time.Duration{
		"":        defaultTokenRequestTimeout,
		"1s":      time.Second,
		"30s":     30 * time.Second,
		"1ms":     time.Millisecond,
		"500ms":   500 * time.Millisecond,
		"30000ms": 30 * time.Second,
	} {
		raw := map[string]interface{}{"authenticationType": "workload-identity"}
		if value != "" {
			raw["tokenRequestTimeout"] = value
		}
		p, err := extractParams(raw)
		if err != nil {
			t.Fatalf("tokenRequestTimeout %q: unexpected error %v", value, err)
		}
		if p.tokenRequestTimeout != want {
			t.Fatalf("tokenRequestTimeout %q = %v, want %v", value, p.tokenRequestTimeout, want)
		}
	}
}

func TestGetPolicyFailsWithoutWorkloadIdentityEnvironment(t *testing.T) {
	setWorkloadIdentityEnv(t, "federated-token")
	unsetEnv(t, "AZURE_FEDERATED_TOKEN_FILE")
	useFakeAzure(t, answer(http.StatusOK, entraToken("tok")))

	_, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{"authenticationType": "workload-identity"})
	if err == nil || !strings.Contains(err.Error(), "AZURE_FEDERATED_TOKEN_FILE") {
		t.Fatalf("error = %v, want one naming AZURE_FEDERATED_TOKEN_FILE", err)
	}
}

func TestOnRequestHeadersSetsBearerToken(t *testing.T) {
	setWorkloadIdentityEnv(t, "federated-token")
	f := useFakeAzure(t, answer(http.StatusOK, entraToken("tok-1")))

	p := mustGetPolicy(t, map[string]interface{}{"authenticationType": "  workload-identity  "})
	mods := requireHeaderMods(t, p.OnRequestHeaders(context.Background(), newRequestHeaderContext(nil), nil))

	if len(mods.HeadersToSet) != 1 || mods.HeadersToSet["Authorization"] != "Bearer tok-1" {
		t.Fatalf("HeadersToSet = %v, want Authorization: Bearer tok-1", mods.HeadersToSet)
	}
	if len(mods.HeadersToRemove) != 0 || len(mods.HeadersToAppend) != 0 {
		t.Fatalf("unexpected header changes: %+v", mods)
	}
	if reqs := f.tokenRequests(); len(reqs) != 1 || !strings.HasPrefix(reqs[0].form.Get("scope"), "https://ai.azure.com/.default") {
		t.Fatalf("token requests = %+v, want one for the Foundry default scope", reqs)
	}
}

func TestOnRequestHeadersUsesConfiguredHeaderPrefixAndScope(t *testing.T) {
	tests := []struct {
		name       string
		params     map[string]interface{}
		wantHeader string
		wantValue  string
		wantScope  string
	}{
		{
			name:       "custom header without prefix",
			params:     map[string]interface{}{"headerName": "X-Upstream-Token", "valuePrefix": ""},
			wantHeader: "X-Upstream-Token", wantValue: "tok-1", wantScope: "https://ai.azure.com/.default",
		},
		{
			name:       "custom prefix",
			params:     map[string]interface{}{"valuePrefix": "Token"},
			wantHeader: "Authorization", wantValue: "Token tok-1", wantScope: "https://ai.azure.com/.default",
		},
		{
			name:       "cognitive services scope",
			params:     map[string]interface{}{"scope": "https://cognitiveservices.azure.com/.default"},
			wantHeader: "Authorization", wantValue: "Bearer tok-1", wantScope: "https://cognitiveservices.azure.com/.default",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setWorkloadIdentityEnv(t, "federated-token")
			f := useFakeAzure(t, answer(http.StatusOK, entraToken("tok-1")))
			tt.params["authenticationType"] = "workload-identity"

			p := mustGetPolicy(t, tt.params)
			mods := requireHeaderMods(t, p.OnRequestHeaders(context.Background(), newRequestHeaderContext(nil), nil))

			if len(mods.HeadersToSet) != 1 || mods.HeadersToSet[tt.wantHeader] != tt.wantValue {
				t.Fatalf("HeadersToSet = %v, want %s: %s", mods.HeadersToSet, tt.wantHeader, tt.wantValue)
			}
			if scope := f.tokenRequests()[0].form.Get("scope"); strings.Fields(scope)[0] != tt.wantScope {
				t.Fatalf("scope = %q, want %q first", scope, tt.wantScope)
			}
		})
	}
}

func TestIdentityParamsOverrideTheEnvironment(t *testing.T) {
	setWorkloadIdentityEnv(t, "federated-token")
	f := useFakeAzure(t, answer(http.StatusOK, entraToken("tok-1")))

	p := mustGetPolicy(t, map[string]interface{}{
		"authenticationType": "workload-identity",
		"clientId":           "99999999-8888-7777-6666-555555555555",
		"tenantId":           "contoso.onmicrosoft.com",
	})
	requireHeaderMods(t, p.OnRequestHeaders(context.Background(), newRequestHeaderContext(nil), nil))

	r := f.tokenRequests()[0]
	if !strings.HasPrefix(r.url.Path, "/contoso.onmicrosoft.com/") || r.form.Get("client_id") != "99999999-8888-7777-6666-555555555555" {
		t.Fatalf("token request to %s for client %q, want the overrides", r.url, r.form.Get("client_id"))
	}
}

func TestTokenRequestTimeoutParamBoundsTheFetch(t *testing.T) {
	setWorkloadIdentityEnv(t, "federated-token")
	useFakeAzure(t, func(ctx context.Context, _ tokenRequest) (int, any) {
		<-ctx.Done()
		return http.StatusOK, entraToken("too-late")
	})

	p := mustGetPolicy(t, map[string]interface{}{"authenticationType": "workload-identity", "tokenRequestTimeout": "100ms"})
	start := time.Now()
	resp := requireFailure(t, p.OnRequestHeaders(context.Background(), newRequestHeaderContext(nil), nil))

	if resp.Fault == nil || resp.Fault.Description != "timed out obtaining an access token from Microsoft Entra ID" {
		t.Fatalf("fault = %+v, want a timeout", resp.Fault)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("the request took %v, want about 100ms", elapsed)
	}
}

func TestOnRequestHeadersRecordsAuthContext(t *testing.T) {
	setWorkloadIdentityEnv(t, "federated-token")
	useFakeAzure(t, answer(http.StatusOK, entraToken("tok-1")))
	inbound := &policy.AuthContext{Authenticated: true, AuthType: "apikey", CredentialID: "app-1"}
	shared := &policy.SharedContext{RequestID: "req-1", AuthContext: inbound}

	p := mustGetPolicy(t, map[string]interface{}{"authenticationType": "workload-identity"})
	requireHeaderMods(t, p.OnRequestHeaders(context.Background(), newRequestHeaderContext(shared), nil))

	got := shared.AuthContext
	if got == nil || !got.Authenticated || got.AuthType != "azure-workload-identity" || got.CredentialID != testClientID {
		t.Fatalf("AuthContext = %+v", got)
	}
	wantProps := map[string]string{
		"authenticationType": "workload-identity",
		"scope":              "https://ai.azure.com/.default",
		"tenantId":           testTenantID,
	}
	if !reflect.DeepEqual(got.Properties, wantProps) {
		t.Fatalf("Properties = %v, want %v", got.Properties, wantProps)
	}
	if got.Previous != inbound {
		t.Fatal("the inbound AuthContext was not kept as Previous")
	}
}

func TestOnRequestHeadersFailureReturnsDeclaredFault(t *testing.T) {
	setWorkloadIdentityEnv(t, "federated-token")
	useFakeAzure(t, answer(http.StatusUnauthorized, oauthError("invalid_client",
		"AADSTS700016: Application with identifier 'x' was not found in the directory 'contoso'.", 700016)))
	inbound := &policy.AuthContext{Authenticated: true, AuthType: "apikey"}
	shared := &policy.SharedContext{RequestID: "req-1", AuthContext: inbound}

	p := mustGetPolicy(t, map[string]interface{}{"authenticationType": "workload-identity"})
	resp := requireFailure(t, p.OnRequestHeaders(context.Background(), newRequestHeaderContext(shared), nil))

	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("status = %d, want 502", resp.StatusCode)
	}
	if resp.Headers["Content-Type"] != "application/json" {
		t.Errorf("headers = %v", resp.Headers)
	}
	if got, want := string(resp.Body), `{"error":"Bad Gateway","message":"failed to authenticate request to upstream Azure service"}`; got != want {
		t.Errorf("body = %s\nwant   %s", got, want)
	}
	if !resp.IsFault || resp.Fault == nil {
		t.Fatal("the rejection does not declare a fault")
	}
	f := resp.Fault
	if f.Code != policy.FaultCodeMediationFailed || f.Type != policy.FaultTypeMediation || f.Direction != policy.DirectionRequest {
		t.Errorf("fault = %+v", f)
	}
	if f.Message != "failed to authenticate request to upstream Azure service" {
		t.Errorf("fault message = %q", f.Message)
	}
	if f.Description != "Microsoft Entra ID rejected the token request (HTTP 401, invalid_client)" {
		t.Errorf("fault description = %q", f.Description)
	}
	if shared.AuthContext == nil || shared.AuthContext.Authenticated || shared.AuthContext.Previous != inbound {
		t.Errorf("AuthContext = %+v, want unauthenticated with the inbound context as Previous", shared.AuthContext)
	}
}

// A caller that leaves before the token arrives is not an Entra ID or IMDS failure, so it is logged
// at Debug with its own reason and does not mark the request unauthenticated.
func TestARequestThatEndsFirstIsNotAnIdentityFailure(t *testing.T) {
	setWorkloadIdentityEnv(t, "federated-token")
	logs := captureLogs(t)
	useFakeAzure(t, func(ctx context.Context, _ tokenRequest) (int, any) {
		<-ctx.Done()
		return http.StatusOK, entraToken("too-late")
	})
	inbound := &policy.AuthContext{Authenticated: true, AuthType: "apikey"}
	shared := &policy.SharedContext{RequestID: "req-1", AuthContext: inbound}
	p := mustGetPolicy(t, map[string]interface{}{"authenticationType": "workload-identity"})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	resp := requireFailure(t, p.OnRequestHeaders(ctx, newRequestHeaderContext(shared), nil))
	if resp.StatusCode != http.StatusBadGateway || !resp.IsFault || resp.Fault == nil {
		t.Fatalf("response = %+v, want a declared 502", resp)
	}
	if resp.Fault.Description != "the request ended before an access token was available" {
		t.Fatalf("description = %q", resp.Fault.Description)
	}
	if strings.Contains(logs.String(), "level=ERROR") {
		t.Fatalf("a request that ended first was logged as an error:\n%s", logs)
	}
	if shared.AuthContext != inbound {
		t.Fatalf("AuthContext = %+v, want the inbound one untouched", shared.AuthContext)
	}
}

// Requests that get a cached rejection fail the same way but log at Debug, so a misconfigured
// identity logs one ERROR per token request, not one per API request.
func TestARejectionIsLoggedOnceWhileCached(t *testing.T) {
	setWorkloadIdentityEnv(t, "federated-token")
	logs := captureLogs(t)
	f := useFakeAzure(t, answer(http.StatusUnauthorized, oauthError("invalid_client", "AADSTS700213", 700213)))
	p := mustGetPolicy(t, map[string]interface{}{"authenticationType": "workload-identity"})

	for i := range 3 {
		resp := requireFailure(t, p.OnRequestHeaders(context.Background(), newRequestHeaderContext(nil), nil))
		if resp.Fault == nil || resp.Fault.Description != "Microsoft Entra ID rejected the token request (HTTP 401, invalid_client)" {
			t.Fatalf("request %d: fault = %+v, want the rejection", i+1, resp.Fault)
		}
	}
	if n := len(f.tokenRequests()); n != 1 {
		t.Fatalf("token requests = %d, want 1", n)
	}
	out := logs.String()
	if n := strings.Count(out, "level=ERROR"); n != 1 {
		t.Fatalf("ERROR lines = %d, want 1:\n%s", n, out)
	}
	if n := strings.Count(out, "could not obtain an access token from Microsoft Entra ID"); n != 3 {
		t.Fatalf("failure log lines = %d, want 3 (1 ERROR, 2 Debug):\n%s", n, out)
	}
}

func TestPoliciesWithTheSameIdentityShareOneToken(t *testing.T) {
	setWorkloadIdentityEnv(t, "federated-token")
	f := useFakeAzure(t, answer(http.StatusOK, entraToken("tok-1")))
	params := map[string]interface{}{"authenticationType": "workload-identity"}

	for range 3 { // e.g. three routes of one LLM provider
		p := mustGetPolicy(t, params)
		requireHeaderMods(t, p.OnRequestHeaders(context.Background(), newRequestHeaderContext(nil), nil))
	}
	if n := len(f.tokenRequests()); n != 1 {
		t.Fatalf("token requests = %d, want 1", n)
	}

	other := mustGetPolicy(t, map[string]interface{}{"authenticationType": "workload-identity", "scope": "https://cognitiveservices.azure.com/.default"})
	requireHeaderMods(t, other.OnRequestHeaders(context.Background(), newRequestHeaderContext(nil), nil))
	if n := len(f.tokenRequests()); n != 2 {
		t.Fatalf("token requests = %d, want 2 (a different scope needs its own token)", n)
	}
}

func TestWorkloadAndManagedIdentitiesDoNotShareTokens(t *testing.T) {
	setWorkloadIdentityEnv(t, "federated-token")
	f := useFakeAzure(t, func(_ context.Context, r tokenRequest) (int, any) {
		if r.form == nil {
			return http.StatusOK, imdsToken("imds-tok", "https://ai.azure.com")
		}
		return http.StatusOK, entraToken("entra-tok")
	})

	for _, tt := range []struct{ authenticationType, want string }{
		{"workload-identity", "Bearer entra-tok"},
		{"managed-identity", "Bearer imds-tok"},
	} {
		p := mustGetPolicy(t, map[string]interface{}{"authenticationType": tt.authenticationType, "scope": uniqueScope(t)})
		mods := requireHeaderMods(t, p.OnRequestHeaders(context.Background(), newRequestHeaderContext(nil), nil))
		if got := mods.HeadersToSet["Authorization"]; got != tt.want {
			t.Fatalf("%s: Authorization = %q, want %q", tt.authenticationType, got, tt.want)
		}
	}
	if n := len(f.tokenRequests()); n != 2 {
		t.Fatalf("token requests = %d, want 2 (each authentication type has its own token)", n)
	}
}

func TestGetPolicyBuildsManagedIdentityWithoutWorkloadIdentityEnvironment(t *testing.T) {
	for _, name := range []string{"AZURE_TENANT_ID", "AZURE_CLIENT_ID", "AZURE_FEDERATED_TOKEN_FILE", "AZURE_AUTHORITY_HOST"} {
		unsetEnv(t, name)
	}
	f := useFakeAzure(t, answer(http.StatusOK, imdsToken("tok-1", "https://ai.azure.com")))

	p := mustGetPolicy(t, map[string]interface{}{"authenticationType": "managed-identity", "scope": uniqueScope(t)})
	requireHeaderMods(t, p.OnRequestHeaders(context.Background(), newRequestHeaderContext(nil), nil))
	if reqs := f.tokenRequests(); len(reqs) != 1 || reqs[0].url.Host != "169.254.169.254" {
		t.Fatalf("token requests = %+v, want one to IMDS", reqs)
	}
}

func TestManagedIdentityFailureNamesTheEndpoint(t *testing.T) {
	setWorkloadIdentityEnv(t, "federated-token")
	useFakeAzure(t, answer(http.StatusBadRequest, oauthError("invalid_request", "Identity not found")))
	workload := requireFailure(t, mustGetPolicy(t, map[string]interface{}{"authenticationType": "workload-identity"}).
		OnRequestHeaders(context.Background(), newRequestHeaderContext(nil), nil))

	logs := captureLogs(t)
	p := mustGetPolicy(t, map[string]interface{}{"authenticationType": "managed-identity", "clientId": testClientID, "scope": uniqueScope(t)})
	resp := requireFailure(t, p.OnRequestHeaders(context.Background(), newRequestHeaderContext(nil), nil))

	if resp.StatusCode != workload.StatusCode || !reflect.DeepEqual(resp.Headers, workload.Headers) || !bytes.Equal(resp.Body, workload.Body) {
		t.Fatalf("response = %d %v %s, want the workload-identity failure %d %v %s",
			resp.StatusCode, resp.Headers, resp.Body, workload.StatusCode, workload.Headers, workload.Body)
	}
	if !resp.IsFault || resp.Fault == nil || resp.Fault.Code != policy.FaultCodeMediationFailed {
		t.Fatalf("fault = %+v, want a declared %s", resp.Fault, policy.FaultCodeMediationFailed)
	}
	if want := "the managed identity endpoint rejected the token request (HTTP 400, invalid_request)"; resp.Fault.Description != want {
		t.Fatalf("description = %q, want %q", resp.Fault.Description, want)
	}
	out := logs.String()
	if !strings.Contains(out, "could not obtain an access token from the managed identity endpoint") || !strings.Contains(out, testClientID) {
		t.Fatalf("log does not name the endpoint and the identity:\n%s", out)
	}
}

func TestOnRequestHeadersRecordsManagedIdentityAuthContext(t *testing.T) {
	tests := []struct {
		name             string
		params           map[string]interface{}
		wantCredentialID string
	}{
		{"user-assigned", map[string]interface{}{"authenticationType": "managed-identity", "clientId": testClientID}, testClientID},
		// Without clientId, IMDS picks the host's system-assigned identity, or its only
		// user-assigned identity, so the policy cannot tell which one it got.
		{"host's default identity", map[string]interface{}{"authenticationType": "managed-identity"}, "host-default"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			useFakeAzure(t, answer(http.StatusOK, imdsToken("tok-1", "https://ai.azure.com")))
			inbound := &policy.AuthContext{Authenticated: true, AuthType: "apikey", CredentialID: "app-1"}
			shared := &policy.SharedContext{RequestID: "req-1", AuthContext: inbound}
			scope := uniqueScope(t)
			tt.params["scope"] = scope

			p := mustGetPolicy(t, tt.params)
			requireHeaderMods(t, p.OnRequestHeaders(context.Background(), newRequestHeaderContext(shared), nil))

			got := shared.AuthContext
			if got == nil || !got.Authenticated || got.AuthType != "azure-managed-identity" || got.CredentialID != tt.wantCredentialID {
				t.Fatalf("AuthContext = %+v", got)
			}
			wantProps := map[string]string{"authenticationType": "managed-identity", "scope": scope}
			if !reflect.DeepEqual(got.Properties, wantProps) {
				t.Fatalf("Properties = %v, want %v", got.Properties, wantProps)
			}
			if got.Previous != inbound {
				t.Fatal("the inbound AuthContext was not kept as Previous")
			}
		})
	}
}

// Without its endpoint the SDK would fall back to IMDS, which Container Apps doesn't have, and every
// request would wait out its timeout, so container-apps fails when the policy is created instead.
func TestContainerAppsNeedsItsEndpoint(t *testing.T) {
	tests := []struct {
		name string
		env  map[string]string
		want string
		// managed-identity takes whatever endpoint the environment offers, IMDS included.
		managedIdentityBuilds bool
	}{
		{name: "no managed identity on the app", want: "IDENTITY_ENDPOINT and IDENTITY_HEADER are not set", managedIdentityBuilds: true},
		{name: "no IDENTITY_HEADER", env: map[string]string{"IDENTITY_ENDPOINT": testIdentityEndpoint}, want: "IDENTITY_HEADER is not set", managedIdentityBuilds: true},
		{name: "no IDENTITY_ENDPOINT", env: map[string]string{"IDENTITY_HEADER": testIdentityHeader}, want: "IDENTITY_ENDPOINT is not set", managedIdentityBuilds: true},
		{
			name: "a Service Fabric endpoint",
			env:  map[string]string{"IDENTITY_ENDPOINT": testIdentityEndpoint, "IDENTITY_HEADER": testIdentityHeader, "IDENTITY_SERVER_THUMBPRINT": "0123456789ABCDEF"},
			want: "IDENTITY_SERVER_THUMBPRINT is set",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			useFakeAzure(t, answer(http.StatusOK, imdsToken("tok-1", "https://ai.azure.com")))
			for name, value := range tt.env {
				t.Setenv(name, value)
			}

			_, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{"authenticationType": "container-apps"})
			if err == nil || !strings.Contains(err.Error(), "Container Apps managed identity is not available") || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("err = %v, want Container Apps managed identity not available: %s", err, tt.want)
			}
			if tt.managedIdentityBuilds {
				if _, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{"authenticationType": "managed-identity"}); err != nil {
					t.Fatalf("managed-identity: %v", err)
				}
			}
		})
	}
}

func TestOnRequestHeadersRecordsContainerAppsAuthContext(t *testing.T) {
	tests := []struct {
		name             string
		params           map[string]interface{}
		wantCredentialID string
	}{
		{"user-assigned", map[string]interface{}{"authenticationType": "container-apps", "clientId": testClientID}, testClientID},
		{"system-assigned", map[string]interface{}{"authenticationType": "container-apps"}, "host-default"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			useFakeAzure(t, answer(http.StatusOK, containerAppsToken("tok-1", "https://ai.azure.com", testClientID)))
			setContainerAppsEnv(t)
			inbound := &policy.AuthContext{Authenticated: true, AuthType: "apikey", CredentialID: "app-1"}
			shared := &policy.SharedContext{RequestID: "req-1", AuthContext: inbound}
			scope := uniqueScope(t)
			tt.params["scope"] = scope

			p := mustGetPolicy(t, tt.params)
			mods := requireHeaderMods(t, p.OnRequestHeaders(context.Background(), newRequestHeaderContext(shared), nil))
			if got := mods.HeadersToSet["Authorization"]; got != "Bearer tok-1" {
				t.Fatalf("Authorization = %q, want Bearer tok-1", got)
			}

			got := shared.AuthContext
			if got == nil || !got.Authenticated || got.AuthType != "azure-container-apps" || got.CredentialID != tt.wantCredentialID {
				t.Fatalf("AuthContext = %+v", got)
			}
			wantProps := map[string]string{"authenticationType": "container-apps", "scope": scope}
			if !reflect.DeepEqual(got.Properties, wantProps) {
				t.Fatalf("Properties = %v, want %v", got.Properties, wantProps)
			}
			if got.Previous != inbound {
				t.Fatal("the inbound AuthContext was not kept as Previous")
			}
		})
	}
}

// IDENTITY_HEADER keeps anything but the app itself from minting tokens at the identity endpoint,
// so it must never reach a log line or a fault.
func TestTheIdentityHeaderIsNeverLogged(t *testing.T) {
	logs := captureLogs(t)
	var descriptions []string
	for _, tt := range []struct {
		status int
		body   any
	}{
		{http.StatusBadRequest, containerAppsError(http.StatusBadRequest, "Unable to load the proper Managed Identity.")},
		{http.StatusForbidden, rawBody("")},
		{http.StatusInternalServerError, containerAppsError(http.StatusInternalServerError, "An error occurred.")},
		{0, nil},
	} {
		useFakeAzure(t, answer(tt.status, tt.body))
		setContainerAppsEnv(t)
		p := mustGetPolicy(t, map[string]interface{}{"authenticationType": "container-apps", "scope": uniqueScope(t)})
		resp := requireFailure(t, p.OnRequestHeaders(context.Background(), newRequestHeaderContext(nil), nil))
		descriptions = append(descriptions, resp.Fault.Description)
	}

	out := logs.String()
	if !strings.Contains(out, "could not obtain an access token from the Container Apps identity endpoint") {
		t.Fatalf("the failures were not logged:\n%s", out)
	}
	for _, text := range append(descriptions, out) {
		if strings.Contains(text, testIdentityHeader) {
			t.Fatalf("the identity header appears in:\n%s", text)
		}
	}
}

func TestModeProcessesOnlyRequestHeaders(t *testing.T) {
	setWorkloadIdentityEnv(t, "federated-token")
	useFakeAzure(t, answer(http.StatusOK, entraToken("tok")))

	got := mustGetPolicy(t, map[string]interface{}{"authenticationType": "workload-identity"}).Mode()
	want := policy.ProcessingMode{
		RequestHeaderMode:  policy.HeaderModeProcess,
		RequestBodyMode:    policy.BodyModeSkip,
		ResponseHeaderMode: policy.HeaderModeSkip,
		ResponseBodyMode:   policy.BodyModeSkip,
	}
	if got != want {
		t.Fatalf("Mode() = %+v, want %+v", got, want)
	}
}

// When the SDK can't decode a token response, its error quotes the response body, token and all.
// The log keeps the error but not the token.
func TestTokensInAnUndecodableResponseAreNotLogged(t *testing.T) {
	logs := captureLogs(t)
	setWorkloadIdentityEnv(t, "federated-token")
	const jwt = "eyJhbGciOiJSUzI1NiJ9.eyJhdWQiOiJodHRwczovL2FpLmF6dXJlLmNvbSJ9.c2lnbmF0dXJl"
	useFakeAzure(t, answer(http.StatusOK, map[string]any{
		"token_type":   "Bearer",
		"access_token": "access-token-secret",
		"id_token":     jwt,
		"expires_in":   map[string]any{"not": "a number"},
	}))

	p := mustGetPolicy(t, map[string]interface{}{"authenticationType": "workload-identity"})
	requireFailure(t, p.OnRequestHeaders(context.Background(), newRequestHeaderContext(nil), nil))

	out := logs.String()
	if !strings.Contains(out, "could not obtain an access token from Microsoft Entra ID") || !strings.Contains(out, "[REDACTED]") {
		t.Fatalf("the failure was not logged with a redacted response:\n%s", out)
	}
	for _, secret := range []string{"access-token-secret", jwt} {
		if strings.Contains(out, secret) {
			t.Errorf("logs contain %q:\n%s", secret, out)
		}
	}
}

// The failure log carries the SDK's error, with Entra ID's error codes, but never the access token
// or the federated token.
func TestSecretsAreNotLogged(t *testing.T) {
	logs := captureLogs(t)
	setWorkloadIdentityEnv(t, "federated-token-secret")
	useFakeAzure(t, func(_ context.Context, r tokenRequest) (int, any) {
		if strings.HasPrefix(r.form.Get("scope"), "https://cognitiveservices.azure.com/") {
			return http.StatusUnauthorized, oauthError("invalid_client", "AADSTS700213: No matching federated identity record found.", 700213)
		}
		return http.StatusOK, entraToken("access-token-secret")
	})

	ok := mustGetPolicy(t, map[string]interface{}{"authenticationType": "workload-identity"})
	requireHeaderMods(t, ok.OnRequestHeaders(context.Background(), newRequestHeaderContext(nil), nil))
	failing := mustGetPolicy(t, map[string]interface{}{"authenticationType": "workload-identity", "scope": "https://cognitiveservices.azure.com/.default"})
	requireFailure(t, failing.OnRequestHeaders(context.Background(), newRequestHeaderContext(nil), nil))

	out := logs.String()
	if !strings.Contains(out, "700213") {
		t.Errorf("the failure was not logged with Entra ID's error:\n%s", out)
	}
	for _, secret := range []string{"access-token-secret", "federated-token-secret"} {
		if strings.Contains(out, secret) {
			t.Errorf("logs contain %q:\n%s", secret, out)
		}
	}
}
