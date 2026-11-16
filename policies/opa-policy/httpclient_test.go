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
	"context"
	"net"
	"net/http"
	"net/http/httptest"
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

func TestOPA_ConnectionLimitsApplyOnCloneOnly(t *testing.T) {
	shared := &http.Transport{MaxConnsPerHost: 7}
	installSharedClient(t, &http.Client{Transport: shared})

	p := newPolicy(t, map[string]interface{}{"serverUrl": "http://example.invalid/v1/data", "policy": "authz/policy", "maxOpenConnections": 3})
	got, ok := p.client.Transport.(*http.Transport)
	if !ok || got == shared {
		t.Fatal("expected a cloned transport")
	}
	if got.MaxConnsPerHost != 3 || got.MaxIdleConnsPerHost != 3 {
		t.Fatalf("connection limits not applied: %d/%d", got.MaxConnsPerHost, got.MaxIdleConnsPerHost)
	}
	if shared.MaxConnsPerHost != 7 {
		t.Fatal("shared transport was mutated")
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
