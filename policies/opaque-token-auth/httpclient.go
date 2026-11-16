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
	"crypto/tls"
	"errors"
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

// baseHTTPClient returns the process-wide outbound client
// (sdk/core/utils.SharedHTTPClient), which the policy engine configures with
// its own pooling, timeouts, proxy and dial-time SSRF guard. When the engine
// has not installed one yet it logs a warning and returns fallbackHTTPClient.
// The returned client may be shared with other policies: callers must treat it
// as read-only and derive a copy for any per-policy change.
func baseHTTPClient() *http.Client {
	if client := utils.SharedHTTPClient(); client != nil {
		return client
	}
	slog.Warn("Opaque Token Auth Policy: shared HTTP client not configured, using fallback client")
	return fallbackHTTPClient()
}

type tlsTransportKey struct {
	cfg  *tls.Config
	base *http.Transport
}

// tlsTransports caches the per-TLS-config transport clones so connections to
// an endpoint with custom TLS are pooled across calls instead of a fresh
// transport being built per request.
var tlsTransports sync.Map

// clientWithTLS returns a shallow copy of base (never mutating it) that uses
// cfg for TLS. The transport is a clone of base's, so the engine's dial-time
// guard, proxy and pooling settings are preserved and only TLSClientConfig is
// overridden. A nil cfg returns a plain copy. It fails if base's transport
// cannot be cloned, rather than silently dropping the TLS setting.
func clientWithTLS(base *http.Client, cfg *tls.Config) (*http.Client, error) {
	derived := *base
	if cfg == nil {
		return &derived, nil
	}
	bt, ok := base.Transport.(*http.Transport)
	if !ok || bt == nil {
		return nil, errors.New("outbound HTTP client transport does not support TLS overrides")
	}
	key := tlsTransportKey{cfg: cfg, base: bt}
	cached, ok := tlsTransports.Load(key)
	if !ok {
		clone := bt.Clone()
		clone.TLSClientConfig = cfg
		cached, _ = tlsTransports.LoadOrStore(key, clone)
	}
	derived.Transport = cached.(*http.Transport)
	return &derived, nil
}

// redirectGuardedClient returns a shallow copy of client — never mutating
// client itself, which may be the process-wide utils.SharedHTTPClient()
// shared by every other policy in the engine — whose CheckRedirect refuses
// to follow a redirect to a different scheme or host than the original
// request, so credentials and payloads in the request are never re-sent to
// a destination the redirect names. A same-origin redirect still goes through
// client's own CheckRedirect policy when it has one, or the standard net/http
// 10-hop cap when it doesn't.
func redirectGuardedClient(client *http.Client) *http.Client {
	original := client.CheckRedirect
	guarded := *client
	guarded.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) > 0 && (!strings.EqualFold(req.URL.Scheme, via[0].URL.Scheme) || !strings.EqualFold(req.URL.Host, via[0].URL.Host)) {
			// Cross-origin redirect — refuse it. ErrUseLastResponse stops
			// here without erroring the call; the 3xx status that results
			// is then rejected by the normal non-2xx status check.
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
	return &guarded
}
