/*
 * Copyright (c) 2026, WSO2 LLC. (https://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package steps

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cucumber/godog"

	"github.com/wso2/api-platform/tests/framework/core/util/httpx"
)

// TestRegisterBindsThePolicySteps runs the mint step through godog to show it is bound: with no
// topology it fails (godog turns the panic into a step failure). An unbound step would fail with
// the same status, so the output must not report it as undefined.
func TestRegisterBindsThePolicySteps(t *testing.T) {
	dir := t.TempDir()
	feature := "Feature: the policy steps\n  Scenario: the mint step is bound\n" +
		"    When I mint a JWT token from the testbench OIDC provider expiring in 60 seconds and store it as \"token\" with claims:\n" +
		"      \"\"\"\n      {}\n      \"\"\"\n"
	if err := os.WriteFile(filepath.Join(dir, "steps.feature"), []byte(feature), 0o600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	suite := godog.TestSuite{
		ScenarioInitializer: func(sc *godog.ScenarioContext) { Register(sc, nil) },
		Options:             &godog.Options{Format: "pretty", Paths: []string{dir}, Strict: true, NoColors: true, Output: &out},
	}
	if status := suite.Run(); status != 1 {
		t.Fatalf("expected the bound step to fail without a testbench, status %d", status)
	}
	if strings.Contains(out.String(), "undefined") {
		t.Fatalf("the mint step is not bound:\n%s", out.String())
	}
}

// TestMintTokenSendsClaimsWithExpiry checks the request the step sends and the token it returns.
func TestMintTokenSendsClaimsWithExpiry(t *testing.T) {
	var got map[string]any
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/mint" {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		dec := json.NewDecoder(r.Body)
		dec.UseNumber()
		if err := dec.Decode(&got); err != nil {
			t.Errorf("decoding the claims: %v", err)
		}
		_, _ = w.Write([]byte(`{"token":"a.b.c"}`))
	}))
	defer srv.Close()

	exp := time.Unix(1_800_000_000, 0)
	token, err := mintToken(context.Background(), clientFor(t, srv), srv.URL+"/", `{"iss":"https://nobody.example.com"}`, exp)
	if err != nil {
		t.Fatal(err)
	}
	if token != "a.b.c" {
		t.Fatalf("token %q", token)
	}
	if got["iss"] != "https://nobody.example.com" {
		t.Errorf("iss %v", got["iss"])
	}
	if got["exp"].(json.Number).String() != "1800000000" {
		t.Errorf("exp %v", got["exp"])
	}
	if got["iat"].(json.Number).String() != "1799996400" {
		t.Errorf("iat %v, want one hour before exp", got["iat"])
	}
}

// TestMintTokenAllowsEmptyClaims shows an empty DocString mints a token with only exp and iat.
func TestMintTokenAllowsEmptyClaims(t *testing.T) {
	var got map[string]any
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&got)
		_, _ = w.Write([]byte(`{"token":"x.y.z"}`))
	}))
	defer srv.Close()
	if _, err := mintToken(context.Background(), clientFor(t, srv), srv.URL, "", time.Now()); err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("claims %v, want only exp and iat", got)
	}
}

// TestMintTokenRejectsBadInput covers claims the step refuses and answers it cannot use.
func TestMintTokenRejectsBadInput(t *testing.T) {
	ok := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"token":"a.b.c"}`))
	}))
	defer ok.Close()
	failing := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer failing.Close()
	empty := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{}`))
	}))
	defer empty.Close()

	cases := []struct {
		name, claims, want string
		srv                *httptest.Server
	}{
		{"exp set", `{"exp":1}`, `must not set "exp"`, ok},
		{"iat set", `{"iat":1}`, `must not set "iat"`, ok},
		{"not JSON", `{`, "parsing the claims", ok},
		{"server error", `{}`, "failed: 500", failing},
		{"no token", `{}`, "has no token", empty},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := mintToken(context.Background(), clientFor(t, c.srv), c.srv.URL, c.claims, time.Now())
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("error %v, want %q", err, c.want)
			}
		})
	}
}

// clientFor returns an httpx client that trusts only the test server's certificate, the way the
// step trusts only the identity provider's.
func clientFor(t *testing.T, srv *httptest.Server) *httpx.Client {
	t.Helper()
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	tlsConfig, err := identityProviderTLSConfig(certPEM)
	if err != nil {
		t.Fatal(err)
	}
	return httpx.NewClient(httpx.Options{TLSClientConfig: tlsConfig})
}

// TestIdentityProviderTLSConfig shows the framework certificate loads and anything else is refused.
func TestIdentityProviderTLSConfig(t *testing.T) {
	if _, err := identityProviderClient(); err != nil {
		t.Fatal(err)
	}
	if _, err := identityProviderTLSConfig([]byte("not a certificate")); err == nil {
		t.Fatal("expected an error for a bad certificate")
	}
}
