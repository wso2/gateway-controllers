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

package oauth2generator

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wso2/api-platform/sdk/core/utils"
)

// engineLikeTransport mimics httpkit: the shared client's transport is a
// wrapper around an *http.Transport, never a bare one.
type engineLikeTransport struct {
	calls atomic.Int32
	next  http.RoundTripper
}

func (e *engineLikeTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	e.calls.Add(1)
	return e.next.RoundTrip(r)
}

// installSharedClient installs an engine-like shared client for the test and
// restores the nil default afterwards.
func installSharedClient(t *testing.T) (*http.Client, *engineLikeTransport) {
	t.Helper()
	inner := http.DefaultTransport.(*http.Transport).Clone()
	inner.Proxy = nil
	rt := &engineLikeTransport{next: inner}
	client := &http.Client{Transport: rt, Timeout: 42 * time.Second}
	utils.SetSharedHTTPClient(client)
	t.Cleanup(func() { utils.SetSharedHTTPClient(nil) })
	return client, rt
}

func captureSlog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return &buf
}

func serverCAPEM(srv *httptest.Server) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}))
}

func get(t *testing.T, client *http.Client, url string) error {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	_ = resp.Body.Close()
	return nil
}

func TestOutboundClient_UsesSharedClientWithoutMutatingIt(t *testing.T) {
	shared, rt := installSharedClient(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer srv.Close()

	client, err := outboundClient(outboundOptions{}, 7*time.Second)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if client == shared {
		t.Fatal("expected a copy of the shared client, not the shared client itself")
	}
	if client.Transport != http.RoundTripper(rt) {
		t.Error("expected the shared transport to be reused")
	}
	if client.Timeout != 7*time.Second || shared.Timeout != 42*time.Second {
		t.Errorf("timeout must apply to the copy only, got copy=%v shared=%v", client.Timeout, shared.Timeout)
	}
	if err := get(t, client, srv.URL); err != nil {
		t.Fatalf("request failed: %v", err)
	}
	if rt.calls.Load() == 0 {
		t.Error("expected the request to go through the shared client's transport")
	}
}

func TestOutboundClient_SharedClientIgnoresOverrides(t *testing.T) {
	shared, rt := installSharedClient(t)
	client, err := outboundClient(outboundOptions{proxyURL: "http://proxy.internal:8080", tlsCACert: "x", insecure: true}, time.Second)
	if err != nil {
		t.Fatalf("overrides must not error with the shared client: %v", err)
	}
	if client.Transport != http.RoundTripper(rt) || shared.Transport != http.RoundTripper(rt) {
		t.Fatal("shared transport must be used untouched")
	}
}

func TestOutboundClient_NoSharedClient_UsesFallback(t *testing.T) {
	utils.SetSharedHTTPClient(nil)
	client, err := outboundClient(outboundOptions{}, time.Second)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if client.Transport != fallbackHTTPClient().Transport {
		t.Error("expected the fallback transport when no shared client is installed")
	}
	if client == http.DefaultClient || client.Transport == http.DefaultTransport {
		t.Error("must never use http.DefaultClient")
	}
}

func TestOutboundClient_Fallback_CustomCAApplies(t *testing.T) {
	utils.SetSharedHTTPClient(nil)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer srv.Close()

	plain, err := outboundClient(outboundOptions{}, 5*time.Second)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := get(t, plain, srv.URL); err == nil {
		t.Fatal("expected an untrusted-certificate failure without the custom CA")
	}
	withCA, err := outboundClient(outboundOptions{tlsCACert: serverCAPEM(srv)}, 5*time.Second)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := get(t, withCA, srv.URL); err != nil {
		t.Fatalf("expected the custom CA to be trusted: %v", err)
	}
	if cfg := fallbackHTTPClient().Transport.(*http.Transport).TLSClientConfig; cfg != nil {
		t.Error("the fallback transport must not be mutated")
	}
}

func TestOutboundClient_Fallback_WrongCAFails(t *testing.T) {
	utils.SetSharedHTTPClient(nil)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer srv.Close()
	// A valid PEM that did not sign the server certificate.
	other, _ := x509ForTest(t)
	client, err := outboundClient(outboundOptions{tlsCACert: other}, 5*time.Second)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := get(t, client, srv.URL); err == nil {
		t.Fatal("expected failure with a CA that did not sign the server")
	}
}

func TestOutboundClient_Fallback_InsecureSkipVerifyApplies(t *testing.T) {
	utils.SetSharedHTTPClient(nil)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer srv.Close()
	client, err := outboundClient(outboundOptions{insecure: true}, 5*time.Second)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := get(t, client, srv.URL); err != nil {
		t.Fatalf("expected insecureSkipVerify to accept the self-signed certificate: %v", err)
	}
}

func TestOutboundClient_Fallback_ProxyRoutesThroughProxy(t *testing.T) {
	utils.SetSharedHTTPClient(nil)
	var viaProxy atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		viaProxy.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer proxy.Close()
	client, err := outboundClient(outboundOptions{proxyURL: proxy.URL}, 5*time.Second)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := get(t, client, "http://idp.invalid/token"); err != nil {
		t.Fatalf("request through the proxy failed: %v", err)
	}
	if viaProxy.Load() != 1 {
		t.Fatalf("expected the request to reach the proxy, got %d", viaProxy.Load())
	}
}

func TestOutboundClient_Fallback_DerivedTransportIsCachedPerOptions(t *testing.T) {
	utils.SetSharedHTTPClient(nil)
	a, _ := outboundClient(outboundOptions{proxyURL: "http://p1:8080"}, time.Second)
	b, _ := outboundClient(outboundOptions{proxyURL: "http://p1:8080"}, 2*time.Second)
	c, _ := outboundClient(outboundOptions{proxyURL: "http://p2:8080"}, time.Second)
	if a.Transport != b.Transport {
		t.Error("identical overrides must share one derived transport so connections are pooled")
	}
	if a.Transport == c.Transport {
		t.Error("different overrides must not share a transport")
	}
}

func TestOutboundOptions_Validate(t *testing.T) {
	if err := (outboundOptions{tlsCACert: "not pem"}).validate(); err == nil {
		t.Error("expected an error for an invalid CA bundle")
	}
	err := (outboundOptions{proxyURL: "http://secret-user:secret-pass@proxy.internal:8080/\x7f"}).validate()
	if err == nil {
		t.Fatal("expected an error for an invalid proxyURL")
	}
	if strings.Contains(err.Error(), "secret-user") || strings.Contains(err.Error(), "secret-pass") {
		t.Errorf("proxy credentials leaked into the error: %v", err)
	}
	if err := (outboundOptions{}).validate(); err != nil {
		t.Errorf("empty options must be valid: %v", err)
	}
}

func TestRedirectGuardedClient_RefusesCrossOriginRedirect(t *testing.T) {
	var hits atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { hits.Add(1) }))
	defer target.Close()
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusFound)
	}))
	defer origin.Close()

	base := &http.Client{}
	guarded := redirectGuardedClient(base)
	if base.CheckRedirect != nil {
		t.Fatal("the base client must not be mutated")
	}
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, origin.URL, nil)
	resp, err := guarded.Do(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusFound || hits.Load() != 0 {
		t.Errorf("cross-origin redirect must not be followed: status=%d hits=%d", resp.StatusCode, hits.Load())
	}
}

func TestBuildTokenSource_SharedClientWithOverridesWorksAndWarnsOnce(t *testing.T) {
	_, rt := installSharedClient(t)
	logs := captureSlog(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"access_token":"at","token_type":"Bearer","expires_in":0}`))
	}))
	defer srv.Close()

	const secretProxy = "http://proxy-user:proxy-pass@proxy.internal:8080"
	src, err := buildTokenSource(oauth2Params{
		grantType: GrantTypeClientCredentials, tokenEndpoint: srv.URL, clientID: "c", clientSecret: "s",
		tokenRequestTimeout: 5 * time.Second, proxyURL: secretProxy, tlsInsecureSkipVerify: true,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for i := 0; i < 2; i++ {
		tok, err := src.Token(context.Background())
		if err != nil || tok.AccessToken != "at" {
			t.Fatalf("expected a token via the shared client, got %v (err %v)", tok, err)
		}
	}
	if rt.calls.Load() == 0 {
		t.Error("expected the call to go through the shared client")
	}
	out := logs.String()
	if n := strings.Count(out, "are ignored because the gateway's shared HTTP client is in use"); n != 1 {
		t.Fatalf("expected exactly one warning, got %d: %s", n, out)
	}
	if strings.Contains(out, "proxy-pass") || strings.Contains(out, "proxy.internal") {
		t.Error("warning must not include setting values")
	}
}

func TestBuildTokenSource_Fallback_CustomTLS(t *testing.T) {
	utils.SetSharedHTTPClient(nil)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"access_token":"at","token_type":"Bearer","expires_in":3600}`))
	}))
	defer srv.Close()

	src, err := buildTokenSource(oauth2Params{
		grantType: GrantTypeClientCredentials, tokenEndpoint: srv.URL, clientID: "c", clientSecret: "s",
		tokenRequestTimeout: 5 * time.Second, tlsCaCert: serverCAPEM(srv),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	tok, err := src.Token(context.Background())
	if err != nil || tok.AccessToken != "at" {
		t.Fatalf("expected a token with the custom CA on the fallback client, got %v (err %v)", tok, err)
	}
}

func TestBuildTokenSource_InvalidTransportConfig(t *testing.T) {
	if _, err := buildTokenSource(oauth2Params{grantType: GrantTypeClientCredentials, tlsCaCert: "not pem"}); err == nil {
		t.Fatal("expected an error for an invalid CA bundle")
	}
}

// x509ForTest returns a PEM CA certificate unrelated to any test server.
func x509ForTest(t *testing.T) (string, error) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "unrelated"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), nil
}
