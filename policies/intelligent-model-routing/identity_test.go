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
	"context"
	"strings"
	"sync"
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
