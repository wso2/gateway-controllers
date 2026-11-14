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
	"context"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
	ratelimit "github.com/wso2/gateway-controllers/policies/advanced-ratelimit"
)

// TestFailClosedLimiterIsNotOverage runs the real rate-limit delegate on a Redis that goes away,
// with failureMode closed. The delegate then answers 429 as it does for a used-up quota, but the
// request must not be recorded as over the quota, and with onExceed allow it is not overage.
func TestFailClosedLimiterIsNotOverage(t *testing.T) {
	mr := miniredis.RunT(t)
	host, portText, err := net.SplitHostPort(mr.Addr())
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
	reqCtx := &policy.RequestHeaderContext{
		SharedContext: &policy.SharedContext{APIId: "api-1", APIName: t.Name(),
			Metadata: map[string]interface{}{metadataKeySubscriptionID: "sub-1"}},
		Headers: policy.NewHeaders(nil),
		Method:  "GET",
	}
	check := func(ec enforcedCondition) (*policy.ImmediateResponse, map[string]any) {
		return checkLimit(context.Background(), reqCtx, delegate, ec, "sub-1", "requests", "")
	}

	// Redis up: the first request is within the quota, the second goes over it.
	if resp, md := check(ec); resp != nil || md[quotaStatusKeyPrefix+"c1"] != quotaWithin {
		t.Fatalf("first request: got %#v, %#v; want it let through within the quota", resp, md)
	}
	if resp, md := check(ec); resp == nil || resp.StatusCode != 429 || md[quotaStatusKeyPrefix+"c1"] != quotaOver {
		t.Fatalf("second request: got %#v, %#v; want a 429 over the quota", resp, md)
	}

	mr.Close()

	// Redis down, reject: the limiter's own 429 is kept, with no quota status.
	resp, md := check(ec)
	if resp == nil || resp.StatusCode != 429 || len(resp.AnalyticsMetadata) != 0 || md != nil {
		t.Fatalf("reject, Redis down: got %#v, %#v; want the limiter's 429 without quota metadata", resp, md)
	}
	// Redis down, allow: the request passes and is not recorded as overage.
	allow := ec
	allow.Reject = false
	if resp, md := check(allow); resp != nil || md != nil {
		t.Fatalf("allow, Redis down: got %#v, %#v; want nil, nil", resp, md)
	}
}
