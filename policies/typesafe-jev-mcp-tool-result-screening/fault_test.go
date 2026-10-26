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

package typesafejevmcptoolresultscreening

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

func TestFault_WithheldResultIsAGuardrailFault(t *testing.T) {
	jev := newMockJev(t, injected)
	p := newPolicy(t, jev.server.URL, nil)

	mods := mustModifications(t, p.OnResponseBody(context.Background(), jsonResponse(fetchCall, injectedResult), nil))
	if !mods.IsFault || mods.Fault == nil {
		t.Fatalf("a withheld result keeps its 200, so it must declare the fault: IsFault=%v %+v", mods.IsFault, mods.Fault)
	}
	f := mods.Fault
	if f.Code != policy.GuardrailCodePromptInjection || f.Type != policy.FaultTypeGuardrail || f.Direction != policy.DirectionResponse {
		t.Fatalf("fault = %+v", f)
	}
	if f.Guardrail == nil || f.Guardrail.InterveningGuardrail != guardrailName || f.Guardrail.Assessments != nil {
		t.Fatalf("guardrail details = %+v, want no assessments without showAssessment", f.Guardrail)
	}
	if f.JSONRPC == nil || f.JSONRPC.Code != nil {
		t.Fatalf("JSON-RPC detail = %+v, want the request id and no error code", f.JSONRPC)
	}
	if id, _ := json.Marshal(f.JSONRPC.ID); string(id) != "7" {
		t.Fatalf("JSON-RPC detail = %+v, want the request id and no error code", f.JSONRPC)
	}
	if !strings.Contains(f.Description, "fetch_url") {
		t.Fatalf("description = %q, want the tool", f.Description)
	}
	// The body is what it was before the fault contract.
	want := `{"id":7,"jsonrpc":"2.0","result":{"content":[{"text":"` + withheldText + `","type":"text"}],"isError":true}}`
	if string(mods.Body) != want || mods.StatusCode != nil {
		t.Fatalf("client response changed: %v %s", mods.StatusCode, mods.Body)
	}
}

func TestFault_AssessmentsFollowShowAssessment(t *testing.T) {
	jev := newMockJev(t, injected)
	p := newPolicy(t, jev.server.URL, map[string]interface{}{"showAssessment": true})
	mods := mustModifications(t, p.OnResponseBody(context.Background(), jsonResponse(fetchCall, injectedResult), nil))
	if mods.Fault == nil || mods.Fault.Guardrail == nil || mods.Fault.Guardrail.Assessments == nil {
		t.Fatalf("expected assessments with showAssessment=true, got %+v", mods.Fault)
	}
}

func TestFault_WithheldEventStreamResultIsAFault(t *testing.T) {
	jev := newMockJev(t, injected)
	p := newPolicy(t, jev.server.URL, nil)
	stream := "event: message\ndata: " + injectedResult + "\n\n"
	mods := mustModifications(t, p.OnResponseBody(context.Background(), mcpResponse(fetchCall, stream, "text/event-stream"), nil))
	if !mods.IsFault || mods.Fault == nil || mods.Fault.Code != policy.GuardrailCodePromptInjection {
		t.Fatalf("IsFault=%v fault=%+v", mods.IsFault, mods.Fault)
	}
}

func TestFault_CheckThatCouldNotRunIsTheGatewaysFailure(t *testing.T) {
	failing := func(w http.ResponseWriter, _ int32) { w.WriteHeader(http.StatusInternalServerError) }
	closed := map[string]interface{}{"passthroughOnError": false}

	tests := []struct {
		name     string
		handler  func(w http.ResponseWriter, call int32)
		result   string
		ctx      func(string) *policy.ResponseContext
		wantType string
	}{
		{name: "Jev error", handler: failing, result: injectedResult, wantType: policy.FaultTypeMediation},
		{name: "unreadable response", handler: injected, result: "\x1f\x8b\x08\x00", wantType: policy.FaultTypeMediation},
		{name: "unreadable event stream", handler: injected, result: "\x1f\x8b\x08\x00",
			ctx:      func(body string) *policy.ResponseContext { return mcpResponse(fetchCall, body, "text/event-stream") },
			wantType: policy.FaultTypeMediation},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			jev := newMockJev(t, tt.handler)
			p := newPolicy(t, jev.server.URL, closed)
			respCtx := jsonResponse(fetchCall, tt.result)
			if tt.ctx != nil {
				respCtx = tt.ctx(tt.result)
			}
			mods := mustModifications(t, p.OnResponseBody(context.Background(), respCtx, nil))
			if !mods.IsFault || mods.Fault == nil {
				t.Fatalf("expected a declared fault, got IsFault=%v", mods.IsFault)
			}
			f := mods.Fault
			if f.Code != policy.FaultCodeMediationFailed || f.Type != tt.wantType || f.Direction != policy.DirectionResponse {
				t.Fatalf("fault = %+v", f)
			}
			if f.Guardrail != nil || f.Message != uncheckedText {
				t.Fatalf("fault = %+v, want no guardrail verdict and the client's text as message", f)
			}
		})
	}
}

func TestFault_PassthroughsAreNotFaults(t *testing.T) {
	failing := func(w http.ResponseWriter, _ int32) { w.WriteHeader(http.StatusInternalServerError) }
	for name, tc := range map[string]struct {
		handler func(w http.ResponseWriter, call int32)
		extra   map[string]interface{}
	}{
		"benign":               {handler: benign},
		"monitor-mode hit":     {handler: injected, extra: map[string]interface{}{"mode": "monitor"}},
		"Jev error, fail open": {handler: failing},
		"Jev error, monitor":   {handler: failing, extra: map[string]interface{}{"passthroughOnError": false, "mode": "monitor"}},
	} {
		t.Run(name, func(t *testing.T) {
			jev := newMockJev(t, tc.handler)
			p := newPolicy(t, jev.server.URL, tc.extra)
			mods := mustPassthrough(t, p.OnResponseBody(context.Background(), jsonResponse(fetchCall, injectedResult), nil))
			if mods.IsFault || mods.Fault != nil {
				t.Fatalf("a passed-through result is not a fault: %+v", mods.Fault)
			}
		})
	}
}
