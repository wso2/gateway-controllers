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

package typesafejevmcptoolintentverification

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

// assertJSONRPCFault checks the fault agrees with the JSON-RPC error the client receives.
func assertJSONRPCFault(t *testing.T, resp policy.ImmediateResponse, wantCode, wantType string) {
	t.Helper()
	if !resp.IsFault || resp.Fault == nil {
		t.Fatalf("expected a declared fault, got IsFault=%v Fault=%+v", resp.IsFault, resp.Fault)
	}
	f := resp.Fault
	if f.Code != wantCode || f.Type != wantType || f.Direction != policy.DirectionRequest {
		t.Fatalf("fault = %+v, want code %s type %s", f, wantCode, wantType)
	}
	id, code, message, _ := decodeError(t, resp)
	if f.JSONRPC == nil || f.JSONRPC.Code == nil || *f.JSONRPC.Code != code {
		t.Fatalf("fault JSON-RPC detail %+v disagrees with the body code %d", f.JSONRPC, code)
	}
	if f.Message != message {
		t.Fatalf("fault message %q disagrees with the body message %q", f.Message, message)
	}
	described, _ := json.Marshal(f.JSONRPC.ID)
	if string(described) != string(id) {
		t.Fatalf("fault id %s disagrees with the body id %s", described, id)
	}
}

func TestFault_BlockedCallIsAGuardrailFault(t *testing.T) {
	jev := newMockJev(t, answering(map[string]float64{"destructive": 0.98}))
	p := newPolicy(t, jev.server.URL, nil)

	resp := mustImmediate(t, p.OnRequestBody(context.Background(), mcpRequest(toolCallDrop, nil), nil))
	assertJSONRPCFault(t, resp, policy.GuardrailCodeIntervened, policy.FaultTypeGuardrail)
	g := resp.Fault.Guardrail
	if g == nil || g.InterveningGuardrail != guardrailName || g.Action != policy.GuardrailActionIntervened {
		t.Fatalf("guardrail details = %+v", g)
	}
	if g.Assessments != nil {
		t.Fatalf("assessments must stay empty without showAssessment, got %v", g.Assessments)
	}
	if !strings.Contains(resp.Fault.Description, "run_sql") || !strings.Contains(resp.Fault.Description, "destructive") {
		t.Fatalf("description = %q, want the tool and the failed question", resp.Fault.Description)
	}
	// The body is what it was before the fault contract.
	want := `{"error":{"code":-32000,"message":"MCP tool call blocked by guardrail"},"id":7,"jsonrpc":"2.0"}`
	if string(resp.Body) != want || resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("client response changed: %d %s", resp.StatusCode, resp.Body)
	}
}

func TestFault_AssessmentsFollowShowAssessment(t *testing.T) {
	jev := newMockJev(t, answering(map[string]float64{"destructive": 0.98}))
	p := newPolicy(t, jev.server.URL, map[string]interface{}{"showAssessment": true})

	resp := mustImmediate(t, p.OnRequestBody(context.Background(), mcpRequest(toolCallDrop, nil), nil))
	if resp.Fault == nil || resp.Fault.Guardrail == nil || resp.Fault.Guardrail.Assessments == nil {
		t.Fatalf("expected assessments with showAssessment=true, got %+v", resp.Fault)
	}
}

func TestFault_CheckThatCouldNotRunIsTheGatewaysFailure(t *testing.T) {
	jev := newMockJev(t, func(w http.ResponseWriter, _ int32) { w.WriteHeader(http.StatusInternalServerError) })
	p := newPolicy(t, jev.server.URL, nil)

	resp := mustImmediate(t, p.OnRequestBody(context.Background(), mcpRequest(toolCallDrop, nil), nil))
	assertJSONRPCFault(t, resp, policy.FaultCodeMediationFailed, policy.FaultTypeMediation)
	if resp.Fault.Guardrail != nil {
		t.Fatalf("a check that could not run is not a guardrail verdict: %+v", resp.Fault.Guardrail)
	}
	if !strings.Contains(resp.Fault.Description, "500") {
		t.Fatalf("description = %q, want the cause", resp.Fault.Description)
	}
}

func TestFault_UnreadableBodyIsAnInvalidRequest(t *testing.T) {
	jev := newMockJev(t, answering(benignAnswers))
	p := newPolicy(t, jev.server.URL, nil)

	for _, body := range []string{
		`{"method":"tools/call",`,
		`{"id":1,"method":"tools/call","params":{"arguments":{}}}`,
		`{"id":"a","method":"tools/call","Params":{"name":"x"}}`,
	} {
		resp := mustImmediate(t, p.OnRequestBody(context.Background(), mcpRequest(body, nil), nil))
		assertJSONRPCFault(t, resp, policy.FaultCodeInvalidRequestBody, policy.FaultTypeValidation)
	}
}

func TestFault_PassthroughsAreNotFaults(t *testing.T) {
	jev := newMockJev(t, answering(map[string]float64{"destructive": 0.98}))
	p := newPolicy(t, jev.server.URL, map[string]interface{}{"mode": "monitor"})
	mods := mustPassthrough(t, p.OnRequestBody(context.Background(), mcpRequest(toolCallDrop, nil), nil))
	if mods.AnalyticsMetadata["isGuardrailHit"] != true {
		t.Fatalf("expected the monitor-mode hit to be recorded, got %v", mods.AnalyticsMetadata)
	}
}
