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
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
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

func TestInterceptor_SkipVerifyAppliesOnCloneAndKeepsDialGuard(t *testing.T) {
	var dials atomic.Int32
	baseTransport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			dials.Add(1)
			return (&net.Dialer{}).DialContext(ctx, network, addr)
		},
	}
	installSharedClient(t, &http.Client{Transport: baseTransport})
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeReply(t, w, map[string]interface{}{})
	}))
	defer srv.Close()

	reachable := func(skip bool) bool {
		dials.Store(0)
		p := mustGetPolicy(t, map[string]interface{}{"endpoint": srv.URL, "tlsSkipVerify": skip, "request": map[string]interface{}{}})
		_, err := p.callInterceptor(context.Background(), srv.URL, map[string]interface{}{})
		return err == nil
	}
	if reachable(false) {
		t.Fatal("expected a certificate error without tlsSkipVerify")
	}
	if !reachable(true) {
		t.Fatal("expected tlsSkipVerify to apply")
	}
	if dials.Load() == 0 {
		t.Fatal("derived client did not use the shared transport's DialContext")
	}
	if baseTransport.TLSClientConfig != nil {
		t.Fatal("shared transport was mutated")
	}
}

func TestInterceptor_SkipVerifyWithUnclonableTransportFails(t *testing.T) {
	installSharedClient(t, &http.Client{Transport: &countingRoundTripper{next: http.DefaultTransport}})
	_, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{"endpoint": "http://example.invalid", "tlsSkipVerify": true, "request": map[string]interface{}{}})
	if err == nil {
		t.Fatal("expected an error rather than silently dropping tlsSkipVerify")
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
