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
package opaquetokenauth

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/wso2/api-platform/sdk/core/utils"
)

type countingRoundTripper struct {
	calls atomic.Int32
	next  http.RoundTripper
}

func (c *countingRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
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

func newTLSServer(t *testing.T) *httptest.Server {
	t.Helper()
	s := httptest.NewTLSServer(activeResponder(map[string]interface{}{"active": true, "sub": "u"}))
	t.Cleanup(s.Close)
	return s
}

func TestClientWithTLS_FallbackAppliesTLSOnClone(t *testing.T) {
	utils.SetSharedHTTPClient(nil)
	srv := newTLSServer(t)

	if resp, err := clientWithTLS(nil).Get(srv.URL); err == nil {
		resp.Body.Close()
		t.Fatal("expected certificate error without the TLS override")
	}
	resp, err := clientWithTLS(&tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}).Get(srv.URL) //nolint:gosec // test
	if err != nil {
		t.Fatalf("expected skip-verify to apply on the fallback client: %v", err)
	}
	resp.Body.Close()
	if fallbackHTTPClient().Transport.(*http.Transport).TLSClientConfig != nil {
		t.Fatal("fallback transport was mutated")
	}
	if resp, err := clientWithTLS(&tls.Config{RootCAs: x509.NewCertPool(), MinVersion: tls.VersionTLS12}).Get(srv.URL); err == nil {
		resp.Body.Close()
		t.Fatal("expected failure with a CA pool that does not trust the server")
	}
}

func TestSharedClient_UsedAsIsAndNotMutated(t *testing.T) {
	rt := &countingRoundTripper{next: http.DefaultTransport}
	shared := &http.Client{Transport: rt}
	installSharedClient(t, shared)

	got := clientWithTLS(&tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}) //nolint:gosec // test
	if got == shared || got.Transport != http.RoundTripper(rt) {
		t.Fatal("expected a copy of the shared client with its transport untouched")
	}
	if shared.Transport != http.RoundTripper(rt) || shared.Timeout != 0 {
		t.Fatal("shared client was mutated")
	}
}

func TestIntrospection_SharedClientWithTLSSettingsWorksAndWarns(t *testing.T) {
	for name, extra := range map[string]map[string]interface{}{
		"skipTlsVerify":   {"skipTlsVerify": true},
		"certificatePath": {"certificatePath": ""},
	} {
		t.Run(name, func(t *testing.T) {
			srv := newTLSServer(t)
			if name == "certificatePath" {
				extra["certificatePath"] = writeCertPEM(t, srv.Certificate())
			}
			// The engine-level client trusts the server and wraps the transport.
			rt := &countingRoundTripper{next: srv.Client().Transport}
			shared := &http.Client{Transport: rt}
			installSharedClient(t, shared)
			logs := captureSlog(t)

			p := newPolicy()
			reqCtx, action := execute(t, p, baseParams(provider("idp", srv.URL, extra)), bearerHeader("opaque-abc"))
			assertSuccess(t, reqCtx, action)
			reqCtx, action = execute(t, p, baseParams(provider("idp", srv.URL, extra)), bearerHeader("opaque-abc"))
			assertSuccess(t, reqCtx, action)

			if rt.calls.Load() == 0 {
				t.Fatal("introspection did not go through the shared HTTP client")
			}
			if n := strings.Count(logs.String(), "is ignored because the gateway's shared HTTP client is in use"); n != 1 {
				t.Fatalf("expected exactly one warning, got %d: %s", n, logs.String())
			}
			if v, _ := extra["certificatePath"].(string); v != "" && strings.Contains(logs.String(), v) {
				t.Fatal("warning must not include the setting value")
			}
			if shared.Transport != http.RoundTripper(rt) {
				t.Fatal("shared client was mutated")
			}
		})
	}
}

func TestIntrospection_UsesSharedHTTPClient(t *testing.T) {
	srv := newServer(t, activeResponder(map[string]interface{}{"active": true, "sub": "u"}))
	rt := &countingRoundTripper{next: http.DefaultTransport}
	installSharedClient(t, &http.Client{Transport: rt})

	reqCtx, action := execute(t, newPolicy(), baseParams(provider("idp", srv.URL, nil)), bearerHeader("opaque-abc"))
	assertSuccess(t, reqCtx, action)
	if rt.calls.Load() == 0 {
		t.Fatal("introspection did not go through the shared HTTP client")
	}
}

func TestIntrospection_DoesNotFollowCrossOriginRedirect(t *testing.T) {
	var hit atomic.Int32
	other := newServer(t, func(w http.ResponseWriter, r *http.Request) { hit.Add(1) })
	srv := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL, http.StatusTemporaryRedirect)
	})
	installSharedClient(t, &http.Client{Transport: http.DefaultTransport})

	reqCtx, action := execute(t, newPolicy(), baseParams(provider("idp", srv.URL, map[string]interface{}{"clientId": "c", "clientSecret": "s"})), bearerHeader("opaque-abc"))
	assertFailure(t, reqCtx, action, 401)
	if hit.Load() != 0 {
		t.Fatal("credentialed introspection request was redirected to another origin")
	}
}
