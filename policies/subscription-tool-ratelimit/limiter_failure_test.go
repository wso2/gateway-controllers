/*
 * Copyright (c) 2026, WSO2 LLC. (https://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package subscriptiontoolratelimit

import (
	"bufio"
	"context"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
	ratelimit "github.com/wso2/gateway-controllers/policies/advanced-ratelimit"
)

// unreachableRedis is a Redis that answers only PING, so the rate-limit delegate can be created on
// it, and then goes away (down), so every limit check fails.
type unreachableRedis struct {
	ln    net.Listener
	mu    sync.Mutex
	conns []net.Conn
}

func startUnreachableRedis(t *testing.T) *unreachableRedis {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	r := &unreachableRedis{ln: ln}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			r.mu.Lock()
			r.conns = append(r.conns, c)
			r.mu.Unlock()
			go serveRESP(c)
		}
	}()
	t.Cleanup(r.down)
	return r
}

// serveRESP reads RESP commands and answers PING with PONG and anything else with an error.
func serveRESP(c net.Conn) {
	in := bufio.NewReader(c)
	for {
		line, err := in.ReadString('\n')
		if err != nil {
			return
		}
		n, _ := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, "*")))
		var cmd string
		for i := 0; i < n; i++ {
			if _, err := in.ReadString('\n'); err != nil { // $<length>
				return
			}
			arg, err := in.ReadString('\n')
			if err != nil {
				return
			}
			if i == 0 {
				cmd = strings.ToUpper(strings.TrimSpace(arg))
			}
		}
		reply := "-ERR unavailable\r\n"
		if cmd == "PING" {
			reply = "+PONG\r\n"
		}
		if _, err := c.Write([]byte(reply)); err != nil {
			return
		}
	}
}

// down closes the listener and every open connection.
func (r *unreachableRedis) down() {
	_ = r.ln.Close()
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, c := range r.conns {
		_ = c.Close()
	}
	r.conns = nil
}

// TestFailClosedLimiterIsNotOverage runs the real rate-limit delegate on a Redis that goes away,
// with failureMode closed. The delegate then answers 429 as it does for a used-up quota, but the
// request must not be recorded as over the quota, and with onExceed allow it is not overage.
func TestFailClosedLimiterIsNotOverage(t *testing.T) {
	redis := startUnreachableRedis(t)
	host, portText, err := net.SplitHostPort(redis.ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	system := map[string]interface{}{
		"backend": "redis",
		"redis": map[string]interface{}{
			"host": host, "port": float64(port), "failureMode": "closed",
			"connectionTimeout": "200ms", "readTimeout": "200ms", "writeTimeout": "200ms",
		},
	}
	ec := enforcedCondition{ID: "c1", Windows: []window{{Count: 1, Duration: time.Minute}}, Reject: true, Signature: t.Name()}
	delegate, err := ratelimit.GetPolicy(policy.PolicyMetadata{RouteName: t.Name(), APIName: t.Name(), AttachedTo: policy.LevelAPI},
		delegateParams(ec, nil, system))
	if err != nil {
		t.Fatalf("delegate: %v", err)
	}
	redis.down()

	reqCtx := &policy.RequestHeaderContext{
		SharedContext: &policy.SharedContext{APIId: "api-1", APIName: t.Name(),
			Metadata: map[string]interface{}{metadataKeySubscriptionID: "sub-1"}},
		Headers: policy.NewHeaders(nil),
		Method:  "GET",
	}
	check := func(ec enforcedCondition) (*policy.ImmediateResponse, map[string]any) {
		return checkLimit(context.Background(), reqCtx, delegate, ec, "sub-1", "requests", "")
	}

	// Reject: the limiter's own 429 is kept, with no quota status.
	resp, md := check(ec)
	if resp == nil || resp.StatusCode != 429 || len(resp.AnalyticsMetadata) != 0 || md != nil {
		t.Fatalf("reject, Redis down: got %#v, %#v; want the limiter's 429 without quota metadata", resp, md)
	}
	// Allow: the request passes and is not recorded as overage.
	allow := ec
	allow.Reject = false
	if resp, md := check(allow); resp != nil || md != nil {
		t.Fatalf("allow, Redis down: got %#v, %#v; want nil, nil", resp, md)
	}
}
