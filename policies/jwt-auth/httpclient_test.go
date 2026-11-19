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
package jwtauth

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/wso2/api-platform/sdk/core/utils"
)

// engineLikeRoundTripper mimics httpkit: the shared client's transport is a
// wrapper around an *http.Transport, never a bare one.
type engineLikeRoundTripper struct {
	calls atomic.Int32
	next  http.RoundTripper
}

func (c *engineLikeRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	c.calls.Add(1)
	return c.next.RoundTrip(r)
}

func installSharedClient(t *testing.T, c *http.Client) {
	t.Helper()
	utils.SetSharedHTTPClient(c)
	t.Cleanup(func() { utils.SetSharedHTTPClient(nil) })
}

func captureSlog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return &buf
}

func keyManagerParams(jwksURI string, extra map[string]interface{}) map[string]interface{} {
	params := newRemoteParams(jwksURI)
	remote := params["keyManagers"].([]interface{})[0].(map[string]interface{})["jwks"].(map[string]interface{})["remote"].(map[string]interface{})
	for k, v := range extra {
		remote[k] = v
	}
	params["jwksFetchTimeout"] = "5s"
	return params
}

func pemOf(srv *httptest.Server) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
}

func TestClientWithTLS_FallbackAppliesTLSOnClone(t *testing.T) {
	utils.SetSharedHTTPClient(nil)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()

	if resp, err := clientWithTLS(nil).Get(srv.URL); err == nil {
		resp.Body.Close()
		t.Fatal("expected certificate error without the TLS override")
	}
	client := clientWithTLS(&tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}) //nolint:gosec // test
	resp, err := client.Get(srv.URL)
	if err != nil {
		t.Fatalf("expected skip-verify to apply on the fallback client: %v", err)
	}
	resp.Body.Close()
	if fallbackHTTPClient().Transport.(*http.Transport).TLSClientConfig != nil {
		t.Fatal("fallback transport was mutated")
	}
}

func TestClientWithTLS_FallbackWrongCAFails(t *testing.T) {
	utils.SetSharedHTTPClient(nil)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	pool := x509.NewCertPool() // trusts nothing
	resp, err := clientWithTLS(&tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}).Get(srv.URL)
	if err == nil {
		resp.Body.Close()
		t.Fatal("expected failure with the wrong CA")
	}
	ok, err := clientWithTLS(&tls.Config{RootCAs: srv.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs, MinVersion: tls.VersionTLS12}).Get(srv.URL)
	if err != nil {
		t.Fatalf("expected the right CA to succeed: %v", err)
	}
	ok.Body.Close()
}

func TestSharedClient_UsedAsIsAndNotMutated(t *testing.T) {
	rt := &engineLikeRoundTripper{next: http.DefaultTransport}
	shared := &http.Client{Transport: rt}
	installSharedClient(t, shared)

	got := clientWithTLS(&tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}) //nolint:gosec // test
	if got == shared {
		t.Fatal("expected a copy of the shared client")
	}
	if got.Transport != http.RoundTripper(rt) {
		t.Fatal("shared transport must be used untouched")
	}
	if shared.Transport != http.RoundTripper(rt) || shared.Timeout != 0 {
		t.Fatal("shared client was mutated")
	}
}

func TestJWKSFetch_SharedClientWithSkipTLSVerifyWorksAndWarnsOnce(t *testing.T) {
	resetJWTAuthSingletonCache(t)
	privateKey, publicKey := generateTestKeys(t)
	jwksServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJWKSResponse(t, w, publicKey, "test-kid")
	}))
	defer jwksServer.Close()

	rt := &engineLikeRoundTripper{next: http.DefaultTransport}
	shared := &http.Client{Transport: rt}
	installSharedClient(t, shared)
	logs := captureSlog(t)

	params := keyManagerParams(jwksServer.URL+"/jwks.json", map[string]interface{}{"skipTlsVerify": true})
	token := createTestToken(t, privateKey, map[string]interface{}{"sub": "user-123", "iss": "https://issuer.example.com"})
	p := mustGetPolicy(t, params)
	ctx := createMockRequestHeaderContext(authHeader("Authorization", "Bearer", token))
	action := p.(*JwtAuthPolicy).OnRequestHeaders(context.Background(), ctx, params)
	assertAuthSuccess(t, ctx, action)
	// A second request must not warn again.
	ctx = createMockRequestHeaderContext(authHeader("Authorization", "Bearer", token))
	p.(*JwtAuthPolicy).OnRequestHeaders(context.Background(), ctx, params)

	if rt.calls.Load() == 0 {
		t.Fatal("JWKS fetch did not go through the shared HTTP client")
	}
	if n := strings.Count(logs.String(), "is ignored because the gateway's shared HTTP client is in use"); n != 1 {
		t.Fatalf("expected exactly one ignored-setting warning, got %d: %s", n, logs.String())
	}
	if shared.Transport != http.RoundTripper(rt) {
		t.Fatal("shared client was mutated")
	}
}

func TestJWKSFetch_SharedClientWithCertificatePathWorks(t *testing.T) {
	resetJWTAuthSingletonCache(t)
	privateKey, publicKey := generateTestKeys(t)
	jwksServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJWKSResponse(t, w, publicKey, "test-kid")
	}))
	defer jwksServer.Close()

	certPath := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(certPath, pemOf(jwksServer), 0o600); err != nil {
		t.Fatal(err)
	}
	// The shared client trusts the server (engine-level TLS root).
	rt := &engineLikeRoundTripper{next: jwksServer.Client().Transport}
	installSharedClient(t, &http.Client{Transport: rt})
	logs := captureSlog(t)

	params := keyManagerParams(jwksServer.URL+"/jwks.json", map[string]interface{}{"certificatePath": certPath})
	token := createTestToken(t, privateKey, map[string]interface{}{"sub": "user-123", "iss": "https://issuer.example.com"})
	p := mustGetPolicy(t, params)
	ctx := createMockRequestHeaderContext(authHeader("Authorization", "Bearer", token))
	assertAuthSuccess(t, ctx, p.(*JwtAuthPolicy).OnRequestHeaders(context.Background(), ctx, params))
	if !strings.Contains(logs.String(), "ignored because the gateway's shared HTTP client is in use") {
		t.Fatalf("expected the ignored-setting warning: %s", logs.String())
	}
	if strings.Contains(logs.String(), certPath) {
		t.Fatal("warning must not include the setting value")
	}
}

func TestJWKSFetch_FallbackAppliesSkipTLSVerify(t *testing.T) {
	resetJWTAuthSingletonCache(t)
	utils.SetSharedHTTPClient(nil)
	privateKey, publicKey := generateTestKeys(t)
	jwksServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJWKSResponse(t, w, publicKey, "test-kid")
	}))
	defer jwksServer.Close()

	params := keyManagerParams(jwksServer.URL+"/jwks.json", map[string]interface{}{"skipTlsVerify": true})
	token := createTestToken(t, privateKey, map[string]interface{}{"sub": "user-123", "iss": "https://issuer.example.com"})
	p := mustGetPolicy(t, params)
	ctx := createMockRequestHeaderContext(authHeader("Authorization", "Bearer", token))
	assertAuthSuccess(t, ctx, p.(*JwtAuthPolicy).OnRequestHeaders(context.Background(), ctx, params))
}
