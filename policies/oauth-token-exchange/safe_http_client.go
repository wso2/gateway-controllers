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

package oauthtokenexchange

import (
	"fmt"
	"net"
	"net/http"
	"sync"
	"syscall"
	"time"
)

// deniedCIDRs are the private, loopback, link-local, and cloud-metadata
// ranges fallbackHTTPClient refuses to dial into, per ssrf-prevention.md
// directive 2 — the IPv4 RFC 1918 ranges, IPv6 unique local addresses
// (fc00::/7, RFC 4193 — the IPv6 analogue of RFC 1918), loopback, link-local,
// and the AWS/GCP/Azure metadata addresses.
var deniedCIDRs = mustParseCIDRs(
	"127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
	"169.254.0.0/16", "::1/128", "fe80::/10", "fd00:ec2::254/128",
	"fc00::/7",
)

func mustParseCIDRs(cidrs ...string) []*net.IPNet {
	nets := make([]*net.IPNet, 0, len(cidrs))
	for _, c := range cidrs {
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			panic(fmt.Sprintf("oauth-token-exchange: invalid built-in denied CIDR %q: %v", c, err))
		}
		nets = append(nets, n)
	}
	return nets
}

func isDeniedDestination(ip net.IP) bool {
	for _, n := range deniedCIDRs {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

var (
	fallbackClientOnce sync.Once
	fallbackClient     *http.Client
)

// fallbackHTTPClient returns a process-wide *http.Client used only when
// utils.SharedHTTPClient() has not been installed yet (e.g. this policy
// invoked before the policy engine finishes startup wiring). It exists so
// that case degrades to a still SSRF-guarded client instead of either
// failing the request outright or dropping to a fully unguarded
// http.DefaultClient, which ssrf-prevention.md directive 1 and
// SharedHTTPClient's own doc comment both explicitly forbid for a
// tenant-configured destination such as cfg.tokenEndpoint.
//
// The dial-time IP check below (directive 2) is enforced regardless of
// what the hostname string looks like, closing the DNS-rebinding gap a
// one-time string check would leave open. Scheme allowlisting (https-only
// unless allowInsecureTokenEndpoint is set) is already enforced earlier in
// parseConfig, and redirects are never auto-followed (directive 2).
func fallbackHTTPClient() *http.Client {
	fallbackClientOnce.Do(func() {
		dialer := &net.Dialer{
			Timeout: 5 * time.Second,
			Control: func(_, address string, _ syscall.RawConn) error {
				host, _, err := net.SplitHostPort(address)
				if err != nil {
					return err
				}
				ip := net.ParseIP(host)
				if ip == nil {
					return fmt.Errorf("refusing to dial unresolved host")
				}
				if isDeniedDestination(ip) {
					return fmt.Errorf("destination is not allowed")
				}
				return nil
			},
		}
		fallbackClient = &http.Client{
			Transport: &http.Transport{DialContext: dialer.DialContext},
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse // never auto-follow a redirect
			},
		}
	})
	return fallbackClient
}
