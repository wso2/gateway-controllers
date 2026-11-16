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
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/wso2/api-platform/sdk/core/utils"
)

var (
	fallbackClientOnce sync.Once
	fallbackClient     *http.Client
)

// fallbackHTTPClient returns a process-wide *http.Client used only when
// utils.SharedHTTPClient() has not been installed yet (e.g. this policy
// invoked before the policy engine finishes startup wiring). It exists only
// so that narrow startup-ordering gap degrades to a client with sane
// connection limits and no silent redirect-following, rather than an
// unbounded http.DefaultClient.
func fallbackHTTPClient() *http.Client {
	fallbackClientOnce.Do(func() {
		dialer := &net.Dialer{Timeout: 5 * time.Second}
		fallbackClient = &http.Client{
			Transport: &http.Transport{
				Proxy:               nil, // never honor environment proxies
				DialContext:         dialer.DialContext,
				TLSHandshakeTimeout: 5 * time.Second,
				MaxIdleConns:        100,
				IdleConnTimeout:     90 * time.Second,
			},
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse // never auto-follow a redirect
			},
		}
	})
	return fallbackClient
}

// newPolicyHTTPClient returns the *http.Client a policy instance uses for its
// outbound calls. It starts from the process-wide utils.SharedHTTPClient()
// (or fallbackHTTPClient when the engine has not installed one) and returns a
// shallow copy, so the shared client itself is never mutated and its
// Transport — with the engine's dial-time guard and connection pool — is
// reused as-is.
//
// A positive timeout is set as the copy's overall Timeout (zero leaves the
// base client's value). When refuseRedirects is true no redirect is followed
// at all; otherwise only same-scheme, same-host redirects are followed, so a
// request carrying a credential header is never re-sent to another origin.
//
// Call it once per policy instance, not per request, so pooling is retained.
func newPolicyHTTPClient(timeout time.Duration, refuseRedirects bool) *http.Client {
	base := utils.SharedHTTPClient()
	if base == nil {
		slog.Warn("shared HTTP client not configured, using fallback client", "policy", "semanticcache")
		base = fallbackHTTPClient()
	}
	derived := *base
	if timeout > 0 {
		derived.Timeout = timeout
	}
	original := base.CheckRedirect
	derived.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if refuseRedirects {
			return http.ErrUseLastResponse
		}
		if len(via) > 0 && (!strings.EqualFold(req.URL.Scheme, via[0].URL.Scheme) || !strings.EqualFold(req.URL.Host, via[0].URL.Host)) {
			return http.ErrUseLastResponse
		}
		if original != nil {
			return original(req, via)
		}
		if len(via) >= 10 {
			return fmt.Errorf("stopped after 10 redirects")
		}
		return nil
	}
	return &derived
}
