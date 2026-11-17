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
package opapolicy

import (
	"bytes"
	"context"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/wso2/api-platform/sdk/core/utils"
)

func installSharedClient(t *testing.T, c *http.Client) {
	t.Helper()
	utils.SetSharedHTTPClient(c)
	t.Cleanup(func() { utils.SetSharedHTTPClient(nil) })
}

func TestOPA_UsesSharedHTTPClient(t *testing.T) {
	srv := opaServer(t, 200, `{"result": true}`, nil)
	var dials atomic.Int32
	installSharedClient(t, &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			dials.Add(1)
			return (&net.Dialer{}).DialContext(ctx, network, addr)
		},
	}})

	p := newPolicy(t, map[string]interface{}{"serverUrl": srv.URL + "/v1/data", "policy": "authz/policy"})
	if _, err := p.callOPA(t.Context(), []byte(`{}`)); err != nil {
		t.Fatalf("callOPA: %v", err)
	}
	if dials.Load() == 0 {
		t.Fatal("OPA call did not go through the shared client's transport")
	}
}

func captureSlog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return &buf
}

type wrappingRoundTripper struct {
	calls atomic.Int32
	next  http.RoundTripper
}

func (w *wrappingRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	w.calls.Add(1)
	return w.next.RoundTrip(r)
}

func TestOPA_SharedClientWithMaxOpenConnectionsWorksAndWarnsOnce(t *testing.T) {
	srv := opaServer(t, 200, `{"result": true}`, nil)
	rt := &wrappingRoundTripper{next: &http.Transport{MaxConnsPerHost: 7}}
	shared := &http.Client{Transport: rt}
	installSharedClient(t, shared)
	logs := captureSlog(t)

	p := newPolicy(t, map[string]interface{}{"serverUrl": srv.URL + "/v1/data", "policy": "authz/policy", "maxOpenConnections": 3})
	for i := 0; i < 2; i++ {
		if _, err := p.callOPA(t.Context(), []byte(`{}`)); err != nil {
			t.Fatalf("callOPA: %v", err)
		}
	}
	if rt.calls.Load() != 2 {
		t.Fatalf("expected calls through the shared client, got %d", rt.calls.Load())
	}
	if p.client.Transport != http.RoundTripper(rt) {
		t.Fatal("policy must use the shared transport untouched")
	}
	if n := strings.Count(logs.String(), "maxOpenConnections is ignored because the gateway's shared HTTP client is in use"); n != 1 {
		t.Fatalf("expected exactly one warning, got %d: %s", n, logs.String())
	}
	if shared.Transport != http.RoundTripper(rt) || shared.Timeout != 0 {
		t.Fatal("shared client was mutated")
	}
}

func TestOPA_SharedClientWithDefaultConfigDoesNotWarn(t *testing.T) {
	rt := &wrappingRoundTripper{next: http.DefaultTransport}
	installSharedClient(t, &http.Client{Transport: rt})
	logs := captureSlog(t)
	newPolicy(t, map[string]interface{}{"serverUrl": "http://example.invalid/v1/data", "policy": "authz/policy"})
	if logs.Len() != 0 {
		t.Fatalf("unexpected warning: %s", logs.String())
	}
}

func TestOPA_FallbackAppliesMaxOpenConnectionsOnClone(t *testing.T) {
	utils.SetSharedHTTPClient(nil)
	p := newPolicy(t, map[string]interface{}{"serverUrl": "http://example.invalid/v1/data", "policy": "authz/policy", "maxOpenConnections": 3})
	got, ok := p.client.Transport.(*http.Transport)
	if !ok || got == fallbackHTTPClient().Transport {
		t.Fatal("expected a cloned fallback transport")
	}
	if got.MaxConnsPerHost != 3 || got.MaxIdleConnsPerHost != 3 {
		t.Fatalf("connection limits not applied: %d/%d", got.MaxConnsPerHost, got.MaxIdleConnsPerHost)
	}
	if fallbackHTTPClient().Transport.(*http.Transport).MaxConnsPerHost != 0 {
		t.Fatal("fallback transport was mutated")
	}
}

func TestOPA_DoesNotFollowRedirect(t *testing.T) {
	var hit atomic.Int32
	other := opaServer(t, 200, `{"result": true}`, func(*http.Request, map[string]interface{}) { hit.Add(1) })
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL, http.StatusTemporaryRedirect)
	}))
	defer srv.Close()
	installSharedClient(t, &http.Client{Transport: http.DefaultTransport})

	p := newPolicy(t, map[string]interface{}{"serverUrl": srv.URL + "/v1/data", "policy": "authz/policy"})
	if _, err := p.callOPA(t.Context(), []byte(`{}`)); err == nil {
		t.Fatal("expected the 3xx response to be rejected")
	}
	if hit.Load() != 0 {
		t.Fatal("OPA request was redirected")
	}
}
