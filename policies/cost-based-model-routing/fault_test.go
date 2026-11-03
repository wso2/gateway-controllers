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

package costbasedmodelrouting

import (
	"testing"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

// Every rejection declares the fault and describes it with an SDK code, while the body the
// client receives is unchanged.
func TestRejectionsDeclareFault(t *testing.T) {
	cases := []struct {
		name     string
		resp     policy.ImmediateResponse
		status   int
		code     string
		faultTyp string
		body     string
	}{
		{"bad request", badRequest("request body must be a JSON object"), 400, policy.FaultCodeInvalidRequestBody, policy.FaultTypeValidation,
			`{"error":"request body must be a JSON object"}`},
		{"budget state unavailable", serviceUnavailable("budget state is unavailable"), 503, policy.FaultCodeMediationFailed, policy.FaultTypeMediation,
			`{"error":"budget state is unavailable"}`},
		{"budget exhausted", budgetExhaustedResponse(), 429, policy.FaultCodeThrottledCustomPolicy, policy.FaultTypeThrottling,
			`{"code":"cost_based_model_routing_budget_exhausted","error":"requested model has no available budget or the fallback budget is missing or exhausted"}`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if c.resp.StatusCode != c.status {
				t.Fatalf("status = %d, want %d", c.resp.StatusCode, c.status)
			}
			if !c.resp.IsFault || c.resp.Fault == nil {
				t.Fatalf("expected a declared fault, got IsFault=%v Fault=%v", c.resp.IsFault, c.resp.Fault)
			}
			if c.resp.Fault.Code != c.code || c.resp.Fault.Type != c.faultTyp {
				t.Errorf("fault = %s/%s, want %s/%s", c.resp.Fault.Code, c.resp.Fault.Type, c.code, c.faultTyp)
			}
			if c.resp.Fault.Direction != policy.DirectionRequest || c.resp.Fault.Message == "" {
				t.Errorf("direction %q, message %q", c.resp.Fault.Direction, c.resp.Fault.Message)
			}
			if string(c.resp.Body) != c.body {
				t.Errorf("body = %s, want %s", c.resp.Body, c.body)
			}
		})
	}
}
