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
package interceptorservice

import (
	"bytes"
	"context"
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

func TestInterceptor_UsesSharedHTTPClient(t *testing.T) {
	srv := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		writeReply(t, w, map[string]interface{}{})
	})
	defer srv.Close()
	rt := &countingRoundTripper{next: http.DefaultTransport}
	installSharedClient(t, &http.Client{Transport: rt})

	p := mustGetPolicy(t, map[string]interface{}{"endpoint": srv.URL, "request": map[string]interface{}{}})
	p.OnRequestBody(context.Background(), reqCtx(`{"hi":1}`), nil)
	if rt.calls.Load() == 0 {
		t.Fatal("interceptor call did not go through the shared HTTP client")
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

func newTLSInterceptor(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeReply(t, w, map[string]interface{}{})
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestInterceptor_SharedClientWithSkipVerifyWorksAndWarnsOnce(t *testing.T) {
	srv := newTLSInterceptor(t)
	// Engine-like client: wrapped transport that already trusts the server.
	rt := &countingRoundTripper{next: srv.Client().Transport}
	shared := &http.Client{Transport: rt}
	installSharedClient(t, shared)
	logs := captureSlog(t)

	p := mustGetPolicy(t, map[string]interface{}{"endpoint": srv.URL, "tlsSkipVerify": true, "request": map[string]interface{}{}})
	for i := 0; i < 2; i++ {
		if _, err := p.callInterceptor(context.Background(), srv.URL, map[string]interface{}{}); err != nil {
			t.Fatalf("call through the shared client failed: %v", err)
		}
	}
	if rt.calls.Load() != 2 {
		t.Fatalf("expected both calls through the shared client, got %d", rt.calls.Load())
	}
	if n := strings.Count(logs.String(), "tlsSkipVerify is ignored because the gateway's shared HTTP client is in use"); n != 1 {
		t.Fatalf("expected exactly one warning, got %d: %s", n, logs.String())
	}
	if shared.Transport != http.RoundTripper(rt) || shared.Timeout != 0 {
		t.Fatal("shared client was mutated")
	}
}

func TestInterceptor_FallbackAppliesSkipVerify(t *testing.T) {
	utils.SetSharedHTTPClient(nil)
	srv := newTLSInterceptor(t)

	reachable := func(skip bool) bool {
		p := mustGetPolicy(t, map[string]interface{}{"endpoint": srv.URL, "tlsSkipVerify": skip, "request": map[string]interface{}{}})
		_, err := p.callInterceptor(context.Background(), srv.URL, map[string]interface{}{})
		return err == nil
	}
	if reachable(false) {
		t.Fatal("expected a certificate error without tlsSkipVerify")
	}
	if !reachable(true) {
		t.Fatal("expected tlsSkipVerify to apply on the fallback client")
	}
	if fallbackHTTPClient().Transport.(*http.Transport).TLSClientConfig != nil {
		t.Fatal("fallback transport was mutated")
	}
}

func TestInterceptor_DoesNotFollowCrossOriginRedirect(t *testing.T) {
	var hit atomic.Int32
	other := newServer(t, func(w http.ResponseWriter, r *http.Request) { hit.Add(1) })
	srv := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL, http.StatusTemporaryRedirect)
	})
	installSharedClient(t, &http.Client{Transport: http.DefaultTransport})

	p := mustGetPolicy(t, map[string]interface{}{"endpoint": srv.URL, "request": map[string]interface{}{}})
	_, _ = p.callInterceptor(context.Background(), srv.URL, map[string]interface{}{})
	if hit.Load() != 0 {
		t.Fatal("request payload was redirected to another origin")
	}
}
