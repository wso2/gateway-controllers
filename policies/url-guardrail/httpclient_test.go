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
package urlguardrail

import (
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

func TestCheckURL_UsesSharedHTTPClient(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	defer srv.Close()
	rt := &countingRoundTripper{next: http.DefaultTransport}
	shared := &http.Client{Transport: rt}
	utils.SetSharedHTTPClient(shared)
	defer utils.SetSharedHTTPClient(nil)

	p := &URLGuardrailPolicy{}
	if !p.checkURL(srv.URL, 1000) {
		t.Fatal("expected checkURL to pass")
	}
	if rt.calls.Load() == 0 {
		t.Fatal("checkURL did not go through the shared HTTP client")
	}
	if shared.Timeout != 0 {
		t.Fatal("shared client was mutated")
	}
}

func TestBaseHTTPClient_FallbackWhenNoSharedClient(t *testing.T) {
	utils.SetSharedHTTPClient(nil)
	if baseHTTPClient() != fallbackHTTPClient() {
		t.Fatal("expected fallback client when no shared client is installed")
	}
}
