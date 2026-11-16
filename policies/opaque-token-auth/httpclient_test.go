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
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
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

func TestBaseHTTPClient_FallbackWhenNoSharedClient(t *testing.T) {
	utils.SetSharedHTTPClient(nil)
	if baseHTTPClient() != fallbackHTTPClient() {
		t.Fatal("expected fallback client when no shared client is installed")
	}
}

func TestClientWithTLS_OverridesTLSOnCloneAndKeepsDialGuard(t *testing.T) {
	var dials atomic.Int32
	baseTransport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			dials.Add(1)
			return (&net.Dialer{}).DialContext(ctx, network, addr)
		},
	}
	base := &http.Client{Transport: baseTransport}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()

	// Without the override the self-signed server must be rejected.
	if resp, err := base.Get(srv.URL); err == nil {
		resp.Body.Close()
		t.Fatal("expected certificate error on the unmodified base client")
	}
	dials.Store(0)

	client, err := clientWithTLS(base, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}) //nolint:gosec // test
	if err != nil {
		t.Fatalf("clientWithTLS: %v", err)
	}
	resp, err := client.Get(srv.URL)
	if err != nil {
		t.Fatalf("expected TLS override to apply: %v", err)
	}
	resp.Body.Close()
	if dials.Load() == 0 {
		t.Fatal("derived client did not go through the base transport's DialContext")
	}
	if baseTransport.TLSClientConfig != nil || base.Transport != http.RoundTripper(baseTransport) {
		t.Fatal("shared base client was mutated")
	}
}

func TestClientWithTLS_ErrorsWhenTransportCannotBeCloned(t *testing.T) {
	base := &http.Client{Transport: &countingRoundTripper{next: http.DefaultTransport}}
	if _, err := clientWithTLS(base, &tls.Config{MinVersion: tls.VersionTLS12}); err == nil {
		t.Fatal("expected an error rather than silently dropping the TLS setting")
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
