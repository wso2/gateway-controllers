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

package timebasedmodelrouting

import (
	"context"
	"testing"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

// Every rejection declares the fault and describes it with an SDK code, while the body the
// client receives is unchanged.
func TestRejectionsDeclareFault(t *testing.T) {
	fixedNow(t, "2026-08-30T01:00:00Z") // 06:30 in Asia/Colombo, inside the morning schedule.
	raw, err := GetPolicy(policy.PolicyMetadata{}, testParams())
	if err != nil {
		t.Fatal(err)
	}
	p := raw.(*TimeBasedModelRoutingPolicy)

	cases := []struct {
		name        string
		requestBody string
		status      int
		code        string
		faultTyp    string
		body        string
		message     string
	}{
		{"empty body", "", 400, policy.FaultCodeInvalidRequestBody, policy.FaultTypeValidation,
			`{"error":"request body must contain a JSON object"}`, "request body must contain a JSON object"},
		{"malformed JSON", `{"model":`, 400, policy.FaultCodeInvalidRequestBody, policy.FaultTypeValidation,
			`{"error":"request body contains malformed JSON"}`, "request body contains malformed JSON"},
		{"not a JSON object", `[]`, 400, policy.FaultCodeInvalidRequestBody, policy.FaultTypeValidation,
			`{"error":"request body must be a JSON object"}`, "request body must be a JSON object"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			action := p.OnRequestBody(context.Background(), requestContext(c.requestBody), nil)
			resp, ok := action.(policy.ImmediateResponse)
			if !ok {
				t.Fatalf("expected ImmediateResponse, got %T", action)
			}
			if resp.StatusCode != c.status {
				t.Fatalf("status = %d, want %d", resp.StatusCode, c.status)
			}
			if string(resp.Body) != c.body || resp.Headers["Content-Type"] != "application/json" {
				t.Fatalf("client response changed: headers %v, body %s", resp.Headers, resp.Body)
			}
			if !resp.IsFault || resp.Fault == nil {
				t.Fatalf("expected a declared fault, got IsFault=%v Fault=%v", resp.IsFault, resp.Fault)
			}
			if resp.Fault.Code != c.code || resp.Fault.Type != c.faultTyp {
				t.Errorf("fault = %s/%s, want %s/%s", resp.Fault.Code, resp.Fault.Type, c.code, c.faultTyp)
			}
			if resp.Fault.Direction != policy.DirectionRequest || resp.Fault.Message != c.message {
				t.Errorf("direction %q, message %q, want %q", resp.Fault.Direction, resp.Fault.Message, c.message)
			}
		})
	}
}
