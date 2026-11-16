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

package oauth2generator

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
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

// baseHTTPClient returns the process-wide utils.SharedHTTPClient(), or the
// fallback client (with a warning) when the engine has not installed one yet.
// The result must never be mutated: callers copy it.
func baseHTTPClient() *http.Client {
	if client := utils.SharedHTTPClient(); client != nil {
		return client
	}
	slog.Warn("OAuth2 policy: shared HTTP client not configured, using fallback client")
	return fallbackHTTPClient()
}

// outboundOptions are the per-policy transport overrides applied on top of the
// shared client. It is comparable so it can key the derived-transport cache.
type outboundOptions struct {
	proxyURL  string
	tlsCACert string
	insecure  bool
}

func (o outboundOptions) needsOverride() bool {
	return o.proxyURL != "" || o.tlsCACert != "" || o.insecure
}

// validate checks the overrides parse, so a bad proxyURL or CA bundle fails
// at policy creation rather than on the first request.
func (o outboundOptions) validate() error {
	_, _, err := o.parse()
	return err
}

func (o outboundOptions) parse() (*url.URL, *tls.Config, error) {
	var proxy *url.URL
	if o.proxyURL != "" {
		u, err := url.Parse(o.proxyURL)
		if err != nil {
			// url.Error embeds the raw input verbatim, which could leak the proxy's userinfo.
			return nil, nil, fmt.Errorf("invalid proxyURL: %s", redactURLCredentials(err.Error()))
		}
		proxy = u
	}
	var tlsConfig *tls.Config
	if o.tlsCACert != "" || o.insecure {
		tlsConfig = &tls.Config{InsecureSkipVerify: o.insecure} //nolint:gosec // opt-in, logged at config parse time
		if o.tlsCACert != "" {
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM([]byte(o.tlsCACert)) {
				return nil, nil, fmt.Errorf("tlsCaCert: no valid PEM certificates found")
			}
			tlsConfig.RootCAs = pool
		}
	}
	return proxy, tlsConfig, nil
}

type derivedTransportKey struct {
	base *http.Transport
	opts outboundOptions
}

// derivedTransports caches the transport cloned from a base transport for a
// given override set, so repeated requests keep pooling connections instead
// of building a fresh transport each time.
var derivedTransports = newKeyedSingleton[derivedTransportKey, *http.Transport]()

// outboundClient returns a copy of the shared (or fallback) client with the
// policy's timeout and, when opts asks for them, its own proxy / TLS settings.
// Overrides are applied to a clone of the base *http.Transport, which keeps the
// engine's dial-time guard (DialContext); the shared client itself is never
// mutated. It errors rather than silently dropping a TLS or proxy setting when
// the base transport cannot be cloned.
func outboundClient(opts outboundOptions, timeout time.Duration) (*http.Client, error) {
	client := *baseHTTPClient()
	client.Timeout = timeout
	if !opts.needsOverride() {
		return &client, nil
	}

	var base *http.Transport
	switch t := client.Transport.(type) {
	case *http.Transport:
		base = t
	case nil:
		base, _ = http.DefaultTransport.(*http.Transport)
	}
	if base == nil {
		return nil, fmt.Errorf("outbound HTTP client transport does not support TLS or proxy overrides")
	}

	transport, _, err := derivedTransports.getOrCreate(derivedTransportKey{base: base, opts: opts}, func() (*http.Transport, error) {
		proxy, tlsConfig, err := opts.parse()
		if err != nil {
			return nil, err
		}
		clone := base.Clone()
		if proxy != nil {
			clone.Proxy = http.ProxyURL(proxy)
		}
		if tlsConfig != nil {
			clone.TLSClientConfig = tlsConfig
		}
		return clone, nil
	})
	if err != nil {
		return nil, err
	}
	client.Transport = transport
	return &client, nil
}

// redirectGuardedClient returns a shallow copy of client — never mutating
// client itself, which may be the process-wide utils.SharedHTTPClient() —
// whose CheckRedirect refuses to follow a redirect to a different scheme or
// host than the original request, so credentials sent in the request are not
// replayed elsewhere. A same-origin redirect still goes through client's own
// CheckRedirect policy when it has one, or the standard 10-hop cap.
func redirectGuardedClient(client *http.Client) *http.Client {
	original := client.CheckRedirect
	guarded := *client
	guarded.CheckRedirect = func(req *http.Request, via []*http.Request) error {
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
	return &guarded
}
