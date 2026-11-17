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
	"log/slog"
	"net"
	"net/http"
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

// sharedClientInstalled reports whether the gateway's shared outbound HTTP
// client (sdk/core/utils.SharedHTTPClient) is in use.
func sharedClientInstalled() bool {
	return utils.SharedHTTPClient() != nil
}

// derivedClient returns a shallow copy of the outbound client (never mutating
// it) with the given per-policy timeout. With the gateway's shared client
// installed the transport is used untouched and tune is ignored: pooling, TLS
// and proxy settings belong to [policy_engine.http_client]. On the fallback
// client tune adjusts a clone of the fallback's own transport.
func derivedClient(timeout time.Duration, tune func(*http.Transport)) *http.Client {
	if shared := utils.SharedHTTPClient(); shared != nil {
		derived := *shared
		derived.Timeout = timeout
		return &derived
	}
	slog.Warn("OPA Policy: shared HTTP client not configured, using fallback client")
	fb := fallbackHTTPClient()
	derived := *fb
	derived.Timeout = timeout
	if tune != nil {
		clone := fb.Transport.(*http.Transport).Clone()
		tune(clone)
		derived.Transport = clone
	}
	return &derived
}
