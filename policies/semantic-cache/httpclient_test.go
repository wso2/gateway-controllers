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

package semanticcache

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/wso2/api-platform/sdk/core/utils"
)

type countingTransport struct{ calls int }

func (c *countingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	c.calls++
	return http.DefaultTransport.RoundTrip(r)
}

func TestPolicyHTTPClientUsesSharedClient(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }))
	defer srv.Close()

	tr := &countingTransport{}
	shared := &http.Client{Transport: tr, Timeout: time.Hour}
	utils.SetSharedHTTPClient(shared)
	defer utils.SetSharedHTTPClient(nil)

	c := newPolicyHTTPClient(3*time.Second, true)
	if c == shared {
		t.Fatal("derived client must be a copy of the shared client")
	}
	if c.Timeout != 3*time.Second || shared.Timeout != time.Hour || shared.CheckRedirect != nil {
		t.Fatal("shared client must not be mutated")
	}
	resp, err := c.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if tr.calls != 1 {
		t.Fatalf("expected the shared transport to be used, got %d calls", tr.calls)
	}
}

func TestPolicyHTTPClientRedirects(t *testing.T) {
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }))
	defer other.Close()
	src := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL, http.StatusFound)
	}))
	defer src.Close()
	utils.SetSharedHTTPClient(nil)

	for _, refuse := range []bool{true, false} {
		resp, err := newPolicyHTTPClient(0, refuse).Get(src.URL)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusFound {
			t.Fatalf("refuse=%v: redirect must not be followed, got %d", refuse, resp.StatusCode)
		}
	}
}
