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
	"context"
	"encoding/pem"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wso2/api-platform/sdk/core/utils"
)

// installSharedClient installs a counting shared client for the test and
// restores the nil default afterwards.
func installSharedClient(t *testing.T) (*http.Client, *atomic.Int32) {
	t.Helper()
	var dials atomic.Int32
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		dials.Add(1)
		return (&net.Dialer{}).DialContext(ctx, network, addr)
	}
	client := &http.Client{Transport: transport, Timeout: 42 * time.Second}
	utils.SetSharedHTTPClient(client)
	t.Cleanup(func() { utils.SetSharedHTTPClient(nil) })
	return client, &dials
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
	shared, dials := installSharedClient(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer srv.Close()

	client, err := outboundClient(outboundOptions{}, 7*time.Second)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if client == shared {
		t.Fatal("expected a copy of the shared client, not the shared client itself")
	}
	if client.Transport != shared.Transport {
		t.Error("expected the shared transport to be reused when no override is configured")
	}
	if client.Timeout != 7*time.Second || shared.Timeout != 42*time.Second {
		t.Errorf("timeout must apply to the copy only, got copy=%v shared=%v", client.Timeout, shared.Timeout)
	}
	if err := get(t, client, srv.URL); err != nil {
		t.Fatalf("request failed: %v", err)
	}
	if dials.Load() == 0 {
		t.Error("expected the request to dial through the shared client's transport")
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

func TestOutboundClient_CustomCAApplies_AndKeepsDialGuard(t *testing.T) {
	shared, dials := installSharedClient(t)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer srv.Close()

	plain, err := outboundClient(outboundOptions{}, 5*time.Second)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := get(t, plain, srv.URL); err == nil {
		t.Fatal("expected an untrusted-certificate failure without the custom CA")
	}

	before := dials.Load()
	withCA, err := outboundClient(outboundOptions{tlsCACert: serverCAPEM(srv)}, 5*time.Second)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := get(t, withCA, srv.URL); err != nil {
		t.Fatalf("expected the custom CA to be trusted: %v", err)
	}
	if dials.Load() <= before {
		t.Error("expected the derived transport to keep the shared client's dial hook")
	}
	if cfg := shared.Transport.(*http.Transport).TLSClientConfig; cfg != nil && (cfg.RootCAs != nil || cfg.InsecureSkipVerify) {
		t.Error("the shared transport must not be mutated")
	}
}

func TestOutboundClient_InsecureSkipVerifyApplies(t *testing.T) {
	installSharedClient(t)
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

func TestOutboundClient_ProxyOverrideApplies(t *testing.T) {
	installSharedClient(t)
	client, err := outboundClient(outboundOptions{proxyURL: "http://proxy.internal:8080"}, time.Second)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://idp.example.com/token", nil)
	got, err := client.Transport.(*http.Transport).Proxy(req)
	if err != nil || got == nil || got.Host != "proxy.internal:8080" {
		t.Errorf("expected the configured proxy, got %v (err %v)", got, err)
	}
}

func TestOutboundClient_DerivedTransportIsCachedPerOptions(t *testing.T) {
	installSharedClient(t)
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

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestOutboundClient_NonHTTPTransportWithOverride_Errors(t *testing.T) {
	utils.SetSharedHTTPClient(&http.Client{Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) { return nil, nil })})
	t.Cleanup(func() { utils.SetSharedHTTPClient(nil) })
	if _, err := outboundClient(outboundOptions{insecure: true}, time.Second); err == nil {
		t.Fatal("expected an error rather than silently dropping the TLS override")
	}
	if _, err := outboundClient(outboundOptions{}, time.Second); err != nil {
		t.Fatalf("no override requested, expected no error: %v", err)
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

func TestBuildTokenSource_UsesSharedClient_AndCustomTLS(t *testing.T) {
	_, dials := installSharedClient(t)
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
		t.Fatalf("expected a token via the shared client with the custom CA, got %v (err %v)", tok, err)
	}
	if dials.Load() == 0 {
		t.Error("expected the call to go through the shared client's dial hook")
	}
}

func TestBuildTokenSource_InvalidTransportConfig(t *testing.T) {
	if _, err := buildTokenSource(oauth2Params{grantType: GrantTypeClientCredentials, tlsCaCert: "not pem"}); err == nil {
		t.Fatal("expected an error for an invalid CA bundle")
	}
}
