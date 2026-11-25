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
	"cmp"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	sdkauth "github.com/wso2/api-platform/sdk/ai/azureauthentication"
	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

const (
	testTenantID = "72f988bf-86f1-41af-91ab-2d7cd011db47"
	testClientID = "11111111-2222-3333-4444-555555555555"

	// What Container Apps sets in a container app with a managed identity.
	testIdentityEndpoint = "http://localhost:12356/msi/token"
	testIdentityHeader   = "4f8c2b6e-9d31-4a7e-b5c0-identity-hdr"
)

// tokenCall is one Token call a fake token source answered.
type tokenCall struct {
	scope   string
	timeout time.Duration
}

// fakeTokens stands in for an identity's credential. It answers with token or err, or, when block
// is set, waits for the request to end.
type fakeTokens struct {
	token   string
	err     error
	block   bool
	service string

	mu    sync.Mutex
	calls []tokenCall
}

func (f *fakeTokens) Token(ctx context.Context, scope string, timeout time.Duration) (string, error) {
	f.mu.Lock()
	f.calls = append(f.calls, tokenCall{scope: scope, timeout: timeout})
	f.mu.Unlock()
	if f.block {
		<-ctx.Done()
		return "", &sdkauth.TokenError{Reason: "timed out obtaining an access token from " + f.Service()}
	}
	if f.err != nil {
		return "", f.err
	}
	return f.token, nil
}

func (f *fakeTokens) Service() string { return cmp.Or(f.service, "Microsoft Entra ID") }

func (f *fakeTokens) tokenCalls() []tokenCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]tokenCall(nil), f.calls...)
}

// useFakeTokens gives every policy the test builds f as its credential, and returns the identities
// the policies asked for.
func useFakeTokens(t *testing.T, f *fakeTokens) *[]sdkauth.Identity {
	t.Helper()
	var asked []sdkauth.Identity
	prev := getTokenSource
	getTokenSource = func(id sdkauth.Identity) (tokenSource, error) {
		asked = append(asked, id)
		return f, nil
	}
	t.Cleanup(func() { getTokenSource = prev })
	return &asked
}

// setWorkloadIdentityEnv sets what the AKS Workload Identity webhook injects, and writes the
// federated token to a file.
func setWorkloadIdentityEnv(t *testing.T, clientID string) {
	t.Helper()
	tokenFile := filepath.Join(t.TempDir(), "azure-identity-token")
	if err := os.WriteFile(tokenFile, []byte("federated-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AZURE_TENANT_ID", testTenantID)
	t.Setenv("AZURE_CLIENT_ID", clientID)
	t.Setenv("AZURE_FEDERATED_TOKEN_FILE", tokenFile)
}

// clearHostIdentityEnv removes the variables that point the SDK at a managed identity endpoint
// other than IMDS.
func clearHostIdentityEnv(t *testing.T) {
	t.Helper()
	for _, name := range []string{"IDENTITY_ENDPOINT", "IDENTITY_HEADER", "IDENTITY_SERVER_THUMBPRINT", "IMDS_ENDPOINT", "MSI_ENDPOINT", "MSI_SECRET"} {
		unsetEnv(t, name)
	}
}

var clientCount atomic.Int64

// uniqueClientID returns a client ID no other test uses. The SDK keeps one credential per identity
// for the whole process, so a test that must build its own credential needs its own identity.
func uniqueClientID() string {
	return fmt.Sprintf("00000000-0000-0000-0000-%012d", clientCount.Add(1))
}

// unsetEnv removes name for one test and restores it afterwards.
func unsetEnv(t *testing.T, name string) {
	t.Helper()
	t.Setenv(name, "")
	os.Unsetenv(name)
}

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
	setWorkloadIdentityEnv(t, testClientID)
	useFakeTokens(t, &fakeTokens{token: "tok"})

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
		{name: "headerName", params: valid(map[string]interface{}{"headerName": "Authorization"}), wantInError: "'headerName' is not a parameter"},
		{name: "valuePrefix", params: valid(map[string]interface{}{"valuePrefix": "Bearer"}), wantInError: "'valuePrefix' is not a parameter"},
		{name: "unparsable timeout", params: valid(map[string]interface{}{"tokenRequestTimeout": "soon"}), wantInError: "tokenRequestTimeout"},
		{name: "zero timeout", params: valid(map[string]interface{}{"tokenRequestTimeout": "0s"}), wantInError: "tokenRequestTimeout"},
		{name: "negative timeout", params: valid(map[string]interface{}{"tokenRequestTimeout": "-1s"}), wantInError: "tokenRequestTimeout"},
		{name: "timeout over 30s", params: valid(map[string]interface{}{"tokenRequestTimeout": "45s"}), wantInError: "tokenRequestTimeout"},
		{name: "non-string timeout", params: valid(map[string]interface{}{"tokenRequestTimeout": 10}), wantInError: "tokenRequestTimeout"},
		{name: "fractional seconds timeout", params: valid(map[string]interface{}{"tokenRequestTimeout": "1.5s"}), wantInError: "tokenRequestTimeout"},
		{name: "minutes timeout", params: valid(map[string]interface{}{"tokenRequestTimeout": "1m"}), wantInError: "tokenRequestTimeout"},
		{name: "timeout with a leading zero", params: valid(map[string]interface{}{"tokenRequestTimeout": "05s"}), wantInError: "tokenRequestTimeout"},
		{name: "timeout over 30000ms", params: valid(map[string]interface{}{"tokenRequestTimeout": "30001ms"}), wantInError: "tokenRequestTimeout"},
		{name: "misspelled tokenRequestTimeout", params: valid(map[string]interface{}{"tokenRequestTimout": "5s"}), wantInError: "'tokenRequestTimout' is not a parameter"},
		{name: "clientId in the wrong case", params: map[string]interface{}{"authenticationType": "managed-identity", "clientID": testClientID}, wantInError: "'clientID' is not a parameter"},
		{name: "unknown key set to null", params: valid(map[string]interface{}{"scopes": nil}), wantInError: "'scopes' is not a parameter"},
		{name: "two unknown keys", params: valid(map[string]interface{}{"tenantID": "contoso.onmicrosoft.com", "tokenRequestTimout": "5s"}), wantInError: "'tenantID', 'tokenRequestTimout' are not parameters"},
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
	_, err := extractParams(map[string]interface{}{"authenticationType": "workload-identity", "tokenRequestTimout": "5s"})
	if err == nil {
		t.Fatal("expected an error")
	}
	want := "'tokenRequestTimout' is not a parameter of the azure-authentication policy; its parameters are " +
		"authenticationType, scope, clientId, tenantId and tokenRequestTimeout"
	if err.Error() != want {
		t.Fatalf("error = %q, want %q", err, want)
	}
}

// The gateway controller adds attachedTo to the params of every policy it attaches, so it must not
// be rejected as an unknown parameter.
func TestGetPolicyAcceptsTheGatewaysAttachedToParam(t *testing.T) {
	setWorkloadIdentityEnv(t, testClientID)
	useFakeTokens(t, &fakeTokens{token: "tok-1"})

	for _, level := range []string{"api", "route"} {
		p := mustGetPolicy(t, map[string]interface{}{"authenticationType": "workload-identity", "attachedTo": level})
		requireHeaderMods(t, p.OnRequestHeaders(context.Background(), newRequestHeaderContext(nil), nil))
	}
}

// The policy checks its own params, as those in upstream.auth reach it unvalidated, so paramNames
// and its patterns must match policy-definition.yaml, or the two paths would accept different values.
func TestParamsMatchThePolicyDefinition(t *testing.T) {
	data, err := os.ReadFile("policy-definition.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var defined []string
	patterns := map[string]string{}
	inParameters := false
	property := regexp.MustCompile(`^    ([A-Za-z0-9_]+):\s*$`)
	pattern := regexp.MustCompile(`^      pattern:\s*(.+?)\s*$`)
	for _, line := range strings.Split(string(data), "\n") {
		if len(line) > 0 && line[0] != ' ' && line[0] != '#' {
			inParameters = strings.HasPrefix(line, "parameters:")
			continue
		}
		if !inParameters {
			continue
		}
		if m := property.FindStringSubmatch(line); m != nil {
			defined = append(defined, m[1])
		} else if m := pattern.FindStringSubmatch(line); m != nil && len(defined) > 0 {
			patterns[defined[len(defined)-1]] = yamlScalar(t, m[1])
		} else if item := strings.TrimSpace(line); len(line) > 4 && strings.HasPrefix(line, "    ") && line[4] != ' ' &&
			line[4] != '#' && item != "-" && !strings.HasPrefix(item, "- ") {
			// A parameter this loop can't read would otherwise be left out of the comparison; only
			// list entries ("- name") and comments are skipped.
			t.Fatalf("policy-definition.yaml: can't read parameter line %q", line)
		}
	}
	if len(defined) == 0 {
		t.Fatal("found no parameters in policy-definition.yaml")
	}
	if !reflect.DeepEqual(paramNames, defined) {
		t.Fatalf("paramNames = %v, policy-definition.yaml defines %v", paramNames, defined)
	}
	for name, re := range map[string]*regexp.Regexp{
		"clientId":            guidPattern,
		"tenantId":            tenantPattern,
		"tokenRequestTimeout": tokenRequestTimeoutPattern,
	} {
		if patterns[name] != re.String() {
			t.Errorf("%s: policy-definition.yaml's pattern is %q, the policy's is %q", name, patterns[name], re.String())
		}
	}
}

// yamlScalar returns a quoted YAML scalar's value.
func yamlScalar(t *testing.T, s string) string {
	t.Helper()
	switch {
	case len(s) >= 2 && s[0] == '\'' && s[len(s)-1] == '\'':
		return strings.ReplaceAll(s[1:len(s)-1], "''", "'")
	case len(s) >= 2 && s[0] == '"':
		v, err := strconv.Unquote(s)
		if err != nil {
			t.Fatalf("pattern %s: %v", s, err)
		}
		return v
	}
	return s
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

// Every authentication type sdk/ai offers needs an AuthContext.AuthType here.
func TestEveryAuthenticationTypeHasAnAuthType(t *testing.T) {
	var names, authTypes []string
	for _, k := range authenticationKinds {
		names = append(names, k.name)
		authTypes = append(authTypes, k.authType)
	}
	if !reflect.DeepEqual(names, sdkauth.Types()) {
		t.Fatalf("authentication types = %v, sdk/ai has %v", names, sdkauth.Types())
	}
	if want := []string{"azure-workload-identity", "azure-managed-identity", "azure-container-apps"}; !reflect.DeepEqual(authTypes, want) {
		t.Fatalf("AuthTypes = %v, want %v", authTypes, want)
	}
	if k := kindOf(AuthenticationTypeWorkloadIdentity); k == nil || !k.usesTenant {
		t.Fatal("workload-identity must take a tenant")
	}
	for _, name := range []string{AuthenticationTypeManagedIdentity, AuthenticationTypeContainerApps} {
		if k := kindOf(name); k == nil || k.usesTenant {
			t.Fatalf("%s must not take a tenant", name)
		}
	}
}

func TestGetPolicyFailsWithoutWorkloadIdentityEnvironment(t *testing.T) {
	setWorkloadIdentityEnv(t, uniqueClientID())
	unsetEnv(t, "AZURE_FEDERATED_TOKEN_FILE")

	_, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{"authenticationType": "workload-identity"})
	if err == nil || !strings.Contains(err.Error(), "workload identity is not available") || !strings.Contains(err.Error(), "AZURE_FEDERATED_TOKEN_FILE") {
		t.Fatalf("error = %v, want workload identity not available, naming AZURE_FEDERATED_TOKEN_FILE", err)
	}
}

// The AZURE_* variables are optional: a value that is set is checked, because workload identity
// would use it, while an unset one is left to the SDK, and params make them unnecessary.
func TestAMalformedAzureEnvironmentFailsTheDeployment(t *testing.T) {
	tests := []struct {
		name   string
		env    map[string]string // "" unsets the variable
		params map[string]interface{}
		fake   bool
		want   string // "" means GetPolicy succeeds
	}{
		{name: "AZURE_CLIENT_ID not a GUID", env: map[string]string{"AZURE_CLIENT_ID": "not-a-guid"}, fake: true, want: "AZURE_CLIENT_ID"},
		{name: "AZURE_TENANT_ID with a slash", env: map[string]string{"AZURE_TENANT_ID": "a/b"}, fake: true, want: "AZURE_TENANT_ID"},
		{
			name:   "both malformed but both params set",
			env:    map[string]string{"AZURE_CLIENT_ID": "not-a-guid", "AZURE_TENANT_ID": "a/b"},
			params: map[string]interface{}{"clientId": testClientID, "tenantId": testTenantID},
			fake:   true,
		},
		{name: "AZURE_CLIENT_ID unset", env: map[string]string{"AZURE_CLIENT_ID": ""}, params: map[string]interface{}{"tenantId": "unset-client.example.com"}, want: "no client ID specified"},
		{name: "AZURE_TENANT_ID unset", env: map[string]string{"AZURE_TENANT_ID": ""}, params: map[string]interface{}{"clientId": uniqueClientID()}, want: "no tenant ID specified"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setWorkloadIdentityEnv(t, uniqueClientID())
			for name, value := range tt.env {
				if value == "" {
					unsetEnv(t, name)
				} else {
					t.Setenv(name, value)
				}
			}
			if tt.fake {
				useFakeTokens(t, &fakeTokens{token: "tok"})
			}
			params := map[string]interface{}{"authenticationType": "workload-identity"}
			for k, v := range tt.params {
				params[k] = v
			}

			_, err := GetPolicy(policy.PolicyMetadata{}, params)
			switch {
			case tt.want == "" && err != nil:
				t.Fatalf("GetPolicy: %v", err)
			case tt.want != "" && (err == nil || !strings.Contains(err.Error(), tt.want)):
				t.Fatalf("error = %v, want one naming %s", err, tt.want)
			}
		})
	}
}

func TestOnRequestHeadersSetsBearerToken(t *testing.T) {
	setWorkloadIdentityEnv(t, testClientID)
	logs := captureLogs(t)
	f := &fakeTokens{token: "tok-1"}
	asked := useFakeTokens(t, f)

	p := mustGetPolicy(t, map[string]interface{}{"authenticationType": "  workload-identity  "})
	mods := requireHeaderMods(t, p.OnRequestHeaders(context.Background(), newRequestHeaderContext(nil), nil))
	if strings.Contains(logs.String(), "tok-1") {
		t.Fatalf("the access token was logged:\n%s", logs)
	}

	if len(mods.HeadersToSet) != 1 || mods.HeadersToSet["Authorization"] != "Bearer tok-1" {
		t.Fatalf("HeadersToSet = %v, want Authorization: Bearer tok-1", mods.HeadersToSet)
	}
	if len(mods.HeadersToRemove) != 0 || len(mods.HeadersToAppend) != 0 {
		t.Fatalf("unexpected header changes: %+v", mods)
	}
	if want := []tokenCall{{scope: "https://ai.azure.com/.default", timeout: 10 * time.Second}}; !reflect.DeepEqual(f.tokenCalls(), want) {
		t.Fatalf("token calls = %+v, want %+v", f.tokenCalls(), want)
	}
	if want := []sdkauth.Identity{{Type: "workload-identity", ClientID: testClientID, TenantID: testTenantID}}; !reflect.DeepEqual(*asked, want) {
		t.Fatalf("identities = %+v, want %+v", *asked, want)
	}
}

func TestOnRequestHeadersUsesConfiguredScope(t *testing.T) {
	setWorkloadIdentityEnv(t, testClientID)
	f := &fakeTokens{token: "tok-1"}
	useFakeTokens(t, f)

	p := mustGetPolicy(t, map[string]interface{}{
		"authenticationType": "workload-identity",
		"scope":              "https://cognitiveservices.azure.com/.default",
	})
	mods := requireHeaderMods(t, p.OnRequestHeaders(context.Background(), newRequestHeaderContext(nil), nil))

	if len(mods.HeadersToSet) != 1 || mods.HeadersToSet["Authorization"] != "Bearer tok-1" {
		t.Fatalf("HeadersToSet = %v, want Authorization: Bearer tok-1", mods.HeadersToSet)
	}
	if calls := f.tokenCalls(); len(calls) != 1 || calls[0].scope != "https://cognitiveservices.azure.com/.default" {
		t.Fatalf("token calls = %+v, want one for https://cognitiveservices.azure.com/.default", calls)
	}
}

// An LLM provider's upstream.auth reaches the policy unchecked, where an empty or blank scope
// means the default, as for the other optional params.
func TestAnEmptyScopeMeansTheDefault(t *testing.T) {
	for name, scope := range map[string]string{"empty": "", "blank": "   "} {
		t.Run(name, func(t *testing.T) {
			setWorkloadIdentityEnv(t, testClientID)
			f := &fakeTokens{token: "tok-1"}
			useFakeTokens(t, f)

			p := mustGetPolicy(t, map[string]interface{}{"authenticationType": "workload-identity", "scope": scope})
			requireHeaderMods(t, p.OnRequestHeaders(context.Background(), newRequestHeaderContext(nil), nil))
			if calls := f.tokenCalls(); len(calls) != 1 || calls[0].scope != "https://ai.azure.com/.default" {
				t.Fatalf("token calls = %+v, want one for https://ai.azure.com/.default", calls)
			}
		})
	}
}

func TestIdentityParamsOverrideTheEnvironment(t *testing.T) {
	setWorkloadIdentityEnv(t, testClientID)
	asked := useFakeTokens(t, &fakeTokens{token: "tok-1"})

	mustGetPolicy(t, map[string]interface{}{
		"authenticationType": "workload-identity",
		"clientId":           "99999999-8888-7777-6666-555555555555",
		"tenantId":           "contoso.onmicrosoft.com",
	})

	want := []sdkauth.Identity{{Type: "workload-identity", ClientID: "99999999-8888-7777-6666-555555555555", TenantID: "contoso.onmicrosoft.com"}}
	if !reflect.DeepEqual(*asked, want) {
		t.Fatalf("identities = %+v, want %+v", *asked, want)
	}
}

func TestTokenRequestTimeoutParamBoundsTheFetch(t *testing.T) {
	setWorkloadIdentityEnv(t, testClientID)
	f := &fakeTokens{token: "tok-1"}
	useFakeTokens(t, f)

	p := mustGetPolicy(t, map[string]interface{}{"authenticationType": "workload-identity", "tokenRequestTimeout": "2500ms"})
	requireHeaderMods(t, p.OnRequestHeaders(context.Background(), newRequestHeaderContext(nil), nil))

	if calls := f.tokenCalls(); len(calls) != 1 || calls[0].timeout != 2500*time.Millisecond {
		t.Fatalf("token calls = %+v, want one bounded by 2.5s", calls)
	}
}

func TestOnRequestHeadersRecordsAuthContext(t *testing.T) {
	setWorkloadIdentityEnv(t, testClientID)
	useFakeTokens(t, &fakeTokens{token: "tok-1"})
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
	setWorkloadIdentityEnv(t, testClientID)
	const reason = "Microsoft Entra ID rejected the token request (HTTP 401, invalid_client)"
	useFakeTokens(t, &fakeTokens{err: &sdkauth.TokenError{Reason: reason, Rejected: true}})
	inbound := &policy.AuthContext{Authenticated: true, AuthType: "apikey"}
	shared := &policy.SharedContext{RequestID: "req-1", AuthContext: inbound}

	p := mustGetPolicy(t, map[string]interface{}{"authenticationType": "workload-identity"})
	resp := requireFailure(t, p.OnRequestHeaders(context.Background(), newRequestHeaderContext(shared), nil))

	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("status = %d, want 502", resp.StatusCode)
	}
	if !reflect.DeepEqual(resp.Headers, map[string]string{"Content-Type": "application/json"}) {
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
	if f.Description != reason {
		t.Errorf("fault description = %q, want %q", f.Description, reason)
	}
	if shared.AuthContext == nil || shared.AuthContext.Authenticated || shared.AuthContext.Previous != inbound {
		t.Errorf("AuthContext = %+v, want unauthenticated with the inbound context as Previous", shared.AuthContext)
	}
}

// A token source should only fail with a *TokenError, but any other error still fails the request
// rather than sending it upstream without a token.
func TestAnErrorThatIsNotATokenErrorStillFails(t *testing.T) {
	setWorkloadIdentityEnv(t, testClientID)
	logs := captureLogs(t)
	useFakeTokens(t, &fakeTokens{err: errors.New("boom")})

	p := mustGetPolicy(t, map[string]interface{}{"authenticationType": "workload-identity"})
	resp := requireFailure(t, p.OnRequestHeaders(context.Background(), newRequestHeaderContext(nil), nil))

	if resp.StatusCode != http.StatusBadGateway || !resp.IsFault || resp.Fault == nil {
		t.Fatalf("response = %+v, want a declared 502", resp)
	}
	if want := "could not obtain an access token from Microsoft Entra ID"; resp.Fault.Description != want {
		t.Fatalf("description = %q, want %q", resp.Fault.Description, want)
	}
	if out := logs.String(); !strings.Contains(out, "level=ERROR") || !strings.Contains(out, "boom") {
		t.Fatalf("the failure was not logged at ERROR with its error:\n%s", out)
	}
}

// A caller that leaves before the token arrives is not an Entra ID or IMDS failure, so it is logged
// at Debug with its own reason and does not mark the request unauthenticated.
func TestARequestThatEndsFirstIsNotAnIdentityFailure(t *testing.T) {
	setWorkloadIdentityEnv(t, testClientID)
	logs := captureLogs(t)
	useFakeTokens(t, &fakeTokens{block: true})
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
	setWorkloadIdentityEnv(t, testClientID)
	logs := captureLogs(t)
	const reason = "Microsoft Entra ID rejected the token request (HTTP 401, invalid_client)"
	f := &fakeTokens{err: &sdkauth.TokenError{Reason: reason, Rejected: true}}
	useFakeTokens(t, f)
	p := mustGetPolicy(t, map[string]interface{}{"authenticationType": "workload-identity"})

	for i := range 3 {
		resp := requireFailure(t, p.OnRequestHeaders(context.Background(), newRequestHeaderContext(nil), nil))
		if resp.Fault == nil || resp.Fault.Description != reason {
			t.Fatalf("request %d: fault = %+v, want the rejection", i+1, resp.Fault)
		}
		f.err = &sdkauth.TokenError{Reason: reason, Rejected: true, Cached: true}
	}
	out := logs.String()
	if n := strings.Count(out, "level=ERROR"); n != 1 {
		t.Fatalf("ERROR lines = %d, want 1:\n%s", n, out)
	}
	if n := strings.Count(out, "could not obtain an access token from Microsoft Entra ID"); n != 3 {
		t.Fatalf("failure log lines = %d, want 3 (1 ERROR, 2 Debug):\n%s", n, out)
	}
}

// Policies with the same identity get one credential, so its tokens are shared, whatever the scope.
func TestPoliciesWithTheSameIdentityShareOneCredential(t *testing.T) {
	setWorkloadIdentityEnv(t, uniqueClientID())
	params := map[string]interface{}{"authenticationType": "workload-identity"}

	first := mustGetPolicy(t, params)
	for range 2 { // e.g. three routes of one LLM provider
		if p := mustGetPolicy(t, params); p.tokens != first.tokens {
			t.Fatal("two routes with one identity got different credentials")
		}
	}
	other := mustGetPolicy(t, map[string]interface{}{"authenticationType": "workload-identity", "scope": "https://cognitiveservices.azure.com/.default"})
	if other.tokens != first.tokens {
		t.Fatal("a route with another scope got another credential for the same identity")
	}
}

// A route that leaves clientId and tenantId to the webhook's AZURE_* variables and a route that
// names the same identity use one identity, so they share its credential.
func TestAWorkloadIdentityNamedOrLeftToTheEnvironmentSharesOneCredential(t *testing.T) {
	clientID := uniqueClientID()
	setWorkloadIdentityEnv(t, clientID)

	var first *Policy
	for _, params := range []map[string]interface{}{
		{"authenticationType": "workload-identity"},
		{"authenticationType": "workload-identity", "clientId": clientID},
		{"authenticationType": "workload-identity", "tenantId": testTenantID},
		{"authenticationType": "workload-identity", "clientId": clientID, "tenantId": testTenantID},
	} {
		p := mustGetPolicy(t, params)
		if first == nil {
			first = p
		} else if p.tokens != first.tokens {
			t.Fatalf("params %v got another credential than the route that left them to the environment", params)
		}
	}
}

// AZURE_CLIENT_ID names the federated identity, which need not be assigned to the host, so a host's
// identity without clientId stays the host's default even where AZURE_CLIENT_ID is set.
func TestAHostsIdentityWithoutClientIDIgnoresAzureClientID(t *testing.T) {
	for _, authenticationType := range []string{"managed-identity", "container-apps"} {
		t.Run(authenticationType, func(t *testing.T) {
			setWorkloadIdentityEnv(t, testClientID)
			asked := useFakeTokens(t, &fakeTokens{token: "tok-1"})

			p := mustGetPolicy(t, map[string]interface{}{"authenticationType": authenticationType})

			if want := []sdkauth.Identity{{Type: authenticationType}}; !reflect.DeepEqual(*asked, want) {
				t.Fatalf("identities = %+v, want %+v", *asked, want)
			}
			if p.credentialID() != hostDefaultCredentialID {
				t.Fatalf("credential ID = %q, want %q", p.credentialID(), hostDefaultCredentialID)
			}
		})
	}
}

func TestWorkloadAndManagedIdentitiesDoNotShareACredential(t *testing.T) {
	clearHostIdentityEnv(t)
	clientID := uniqueClientID()
	setWorkloadIdentityEnv(t, clientID)

	workload := mustGetPolicy(t, map[string]interface{}{"authenticationType": "workload-identity"})
	managed := mustGetPolicy(t, map[string]interface{}{"authenticationType": "managed-identity", "clientId": clientID})
	if workload.tokens == managed.tokens {
		t.Fatal("workload-identity and managed-identity share a credential")
	}
	if workload.tokens.Service() != "Microsoft Entra ID" || managed.tokens.Service() != "the managed identity endpoint" {
		t.Fatalf("services = %q, %q", workload.tokens.Service(), managed.tokens.Service())
	}
}

func TestGetPolicyBuildsManagedIdentityWithoutWorkloadIdentityEnvironment(t *testing.T) {
	clearHostIdentityEnv(t)
	for _, name := range []string{"AZURE_TENANT_ID", "AZURE_CLIENT_ID", "AZURE_FEDERATED_TOKEN_FILE", "AZURE_AUTHORITY_HOST"} {
		unsetEnv(t, name)
	}

	p := mustGetPolicy(t, map[string]interface{}{"authenticationType": "managed-identity", "clientId": uniqueClientID()})
	if p.tokens.Service() != "the managed identity endpoint" {
		t.Fatalf("service = %q, want the managed identity endpoint", p.tokens.Service())
	}
}

func TestAFailureLogNamesTheTokenService(t *testing.T) {
	setWorkloadIdentityEnv(t, testClientID)
	useFakeTokens(t, &fakeTokens{err: &sdkauth.TokenError{Reason: "Microsoft Entra ID rejected the token request (HTTP 401, invalid_client)", Rejected: true}})
	workload := requireFailure(t, mustGetPolicy(t, map[string]interface{}{"authenticationType": "workload-identity"}).
		OnRequestHeaders(context.Background(), newRequestHeaderContext(nil), nil))

	logs := captureLogs(t)
	const reason = "the managed identity endpoint rejected the token request (HTTP 400, invalid_request)"
	useFakeTokens(t, &fakeTokens{service: "the managed identity endpoint", err: &sdkauth.TokenError{Reason: reason, Rejected: true}})
	p := mustGetPolicy(t, map[string]interface{}{"authenticationType": "managed-identity", "clientId": testClientID})
	resp := requireFailure(t, p.OnRequestHeaders(context.Background(), newRequestHeaderContext(nil), nil))

	if resp.StatusCode != workload.StatusCode || !reflect.DeepEqual(resp.Headers, workload.Headers) || !bytes.Equal(resp.Body, workload.Body) {
		t.Fatalf("response = %d %v %s, want the workload-identity failure %d %v %s",
			resp.StatusCode, resp.Headers, resp.Body, workload.StatusCode, workload.Headers, workload.Body)
	}
	if !resp.IsFault || resp.Fault == nil || resp.Fault.Code != policy.FaultCodeMediationFailed {
		t.Fatalf("fault = %+v, want a declared %s", resp.Fault, policy.FaultCodeMediationFailed)
	}
	if resp.Fault.Description != reason {
		t.Fatalf("description = %q, want %q", resp.Fault.Description, reason)
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
		clientID         string
	}{
		{"user-assigned", map[string]interface{}{"authenticationType": "managed-identity", "clientId": testClientID}, testClientID, testClientID},
		// Without clientId, IMDS picks the host's system-assigned identity, or its only
		// user-assigned identity, so the policy cannot tell which one it got.
		{"host's default identity", map[string]interface{}{"authenticationType": "managed-identity"}, "host-default", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			asked := useFakeTokens(t, &fakeTokens{token: "tok-1"})
			inbound := &policy.AuthContext{Authenticated: true, AuthType: "apikey", CredentialID: "app-1"}
			shared := &policy.SharedContext{RequestID: "req-1", AuthContext: inbound}
			tt.params["scope"] = "https://cognitiveservices.azure.com/.default"

			p := mustGetPolicy(t, tt.params)
			if want := []sdkauth.Identity{{Type: "managed-identity", ClientID: tt.clientID}}; !reflect.DeepEqual(*asked, want) {
				t.Fatalf("identities = %+v, want %+v", *asked, want)
			}
			requireHeaderMods(t, p.OnRequestHeaders(context.Background(), newRequestHeaderContext(shared), nil))

			got := shared.AuthContext
			if got == nil || !got.Authenticated || got.AuthType != "azure-managed-identity" || got.CredentialID != tt.wantCredentialID {
				t.Fatalf("AuthContext = %+v", got)
			}
			wantProps := map[string]string{"authenticationType": "managed-identity", "scope": "https://cognitiveservices.azure.com/.default"}
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
			clearHostIdentityEnv(t)
			for name, value := range tt.env {
				t.Setenv(name, value)
			}
			clientID := uniqueClientID()

			_, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{"authenticationType": "container-apps", "clientId": clientID})
			if err == nil || !strings.Contains(err.Error(), "Container Apps managed identity is not available") || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("err = %v, want Container Apps managed identity not available: %s", err, tt.want)
			}
			if tt.managedIdentityBuilds {
				if _, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{"authenticationType": "managed-identity", "clientId": clientID}); err != nil {
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
		clientID         string
	}{
		{"user-assigned", map[string]interface{}{"authenticationType": "container-apps", "clientId": testClientID}, testClientID, testClientID},
		{"system-assigned", map[string]interface{}{"authenticationType": "container-apps"}, "host-default", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			asked := useFakeTokens(t, &fakeTokens{token: "tok-1", service: "the Container Apps identity endpoint"})
			inbound := &policy.AuthContext{Authenticated: true, AuthType: "apikey", CredentialID: "app-1"}
			shared := &policy.SharedContext{RequestID: "req-1", AuthContext: inbound}
			tt.params["scope"] = "https://cognitiveservices.azure.com/.default"

			p := mustGetPolicy(t, tt.params)
			if want := []sdkauth.Identity{{Type: "container-apps", ClientID: tt.clientID}}; !reflect.DeepEqual(*asked, want) {
				t.Fatalf("identities = %+v, want %+v", *asked, want)
			}
			mods := requireHeaderMods(t, p.OnRequestHeaders(context.Background(), newRequestHeaderContext(shared), nil))
			if got := mods.HeadersToSet["Authorization"]; got != "Bearer tok-1" {
				t.Fatalf("Authorization = %q, want Bearer tok-1", got)
			}

			got := shared.AuthContext
			if got == nil || !got.Authenticated || got.AuthType != "azure-container-apps" || got.CredentialID != tt.wantCredentialID {
				t.Fatalf("AuthContext = %+v", got)
			}
			wantProps := map[string]string{"authenticationType": "container-apps", "scope": "https://cognitiveservices.azure.com/.default"}
			if !reflect.DeepEqual(got.Properties, wantProps) {
				t.Fatalf("Properties = %v, want %v", got.Properties, wantProps)
			}
			if got.Previous != inbound {
				t.Fatal("the inbound AuthContext was not kept as Previous")
			}
		})
	}
}

func TestModeProcessesOnlyRequestHeaders(t *testing.T) {
	setWorkloadIdentityEnv(t, testClientID)
	useFakeTokens(t, &fakeTokens{token: "tok"})

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
