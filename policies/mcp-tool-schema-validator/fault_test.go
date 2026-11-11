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

package mcptoolschemavalidator

import (
	"encoding/json"
	"strings"
	"testing"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

// assertFault checks a declared fault's code, type, direction and JSON-RPC detail.
func assertFault(t *testing.T, isFault bool, f *policy.FaultDetails, code, direction string, rpcCode int, rpcID string) {
	t.Helper()
	if !isFault || f == nil {
		t.Fatalf("IsFault %v Fault %v", isFault, f)
	}
	if f.Code != code || f.Type != policy.FaultTypeValidation || f.Direction != direction {
		t.Errorf("fault = %s/%s/%s, want %s/%s/%s", f.Code, f.Type, f.Direction, code, policy.FaultTypeValidation, direction)
	}
	if f.Message == "" || f.Description == "" {
		t.Errorf("message %q description %q", f.Message, f.Description)
	}
	if f.JSONRPC == nil || f.JSONRPC.Code == nil || *f.JSONRPC.Code != rpcCode {
		t.Fatalf("JSON-RPC code not carried: %+v", f.JSONRPC)
	}
	if rpcID == "" {
		if f.JSONRPC.ID != nil {
			t.Errorf("JSON-RPC id = %#v, want nil", f.JSONRPC.ID)
		}
	} else if id, ok := f.JSONRPC.ID.(json.RawMessage); !ok || string(id) != rpcID {
		t.Errorf("JSON-RPC id = %#v, want %s", f.JSONRPC.ID, rpcID)
	}
}

// Every request rejection declares a validation fault on the caller's payload, carrying the
// JSON-RPC code the body carries.
func TestRequestRejectionsDeclareFaults(t *testing.T) {
	p := testPolicy(t)
	n := decoderMaxDepth + 5
	tests := []struct {
		name    string
		body    string
		rpcCode int
		rpcID   string
	}{
		{name: "schema mismatch", body: callBody("1", "get_weather", `{"city":42}`), rpcCode: codeInvalidParams, rpcID: "1"},
		{name: "arguments not an object", body: callBody(`"a"`, "ping", `[1]`), rpcCode: codeInvalidParams, rpcID: `"a"`},
		{name: "arguments too deep", body: callBody("1", "ping", `{"n":`+strings.Repeat("[", maxJSONDepth)+strings.Repeat("]", maxJSONDepth)+`}`), rpcCode: codeInvalidParams, rpcID: "1"},
		{name: "payload too large", body: callBody("1", "get_weather", `{"city":"x","pad":"`+strings.Repeat("a", maxBodyBytes)+`"}`), rpcCode: codeInvalidParams, rpcID: "1"},
		{name: "ambiguous arguments", body: `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_weather","arguments":{"city":"x"},"arguments":{}}}`, rpcCode: codeInvalidRequest, rpcID: "1"},
		{name: "ambiguous call", body: `{"jsonrpc":"2.0","id":1,"method":"tools/list","method":"tools/call","params":{"name":"get_weather"}}`, rpcCode: codeInvalidRequest},
		{name: "beyond the decoder limit", body: callBody("1", "get_weather", `{"n":`+strings.Repeat("[", n)+strings.Repeat("]", n)+`}`), rpcCode: codeInvalidRequest},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resp, rpc := rejected(t, runRequest(p, newRequestCtx(tc.body, nil)))
			assertFault(t, resp.IsFault, resp.Fault, policy.FaultCodeInvalidRequestBody, policy.DirectionRequest, tc.rpcCode, tc.rpcID)
			if resp.Fault.Message != rpc.Error.Message {
				t.Errorf("fault message %q, body message %q", resp.Fault.Message, rpc.Error.Message)
			}
		})
	}
}

// Declaring the fault leaves the body the client receives as it was.
func TestRequestRejectionBodyUnchanged(t *testing.T) {
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/list","method":"tools/call","params":{"name":"get_weather"}}`
	resp, _ := rejected(t, runRequest(testPolicy(t), newRequestCtx(body, nil)))
	want := `{"error":{"code":-32600,"message":"Request body names a member more than once"},"id":null,"jsonrpc":"2.0"}`
	if string(resp.Body) != want || resp.Headers["Content-Type"] != "application/json" {
		t.Errorf("body %s headers %v", resp.Body, resp.Headers)
	}
}

// A forwarded call is not a fault.
func TestValidRequestIsNotFault(t *testing.T) {
	action := runRequest(testPolicy(t), newRequestCtx(callBody("1", "get_weather", `{"city":"Colombo"}`), nil))
	if _, stop := action.(policy.ImmediateResponse); stop {
		t.Fatalf("valid call rejected: %#v", action)
	}
}

// A replaced tool result is a fault on the response despite its 200 status; a valid or skipped
// result is not.
func TestResponseRejectionDeclaresFault(t *testing.T) {
	p := testPolicy(t)
	for _, tc := range []struct{ name, contentType, body string }{
		{name: "schema mismatch", contentType: "application/json", body: resultBody("7", structured(`{"condition":"x"}`))},
		{name: "missing structuredContent", contentType: "application/json", body: resultBody("7", `{"content":[]}`)},
		{name: "empty body", contentType: "application/json", body: ""},
		{name: "SSE", contentType: "text/event-stream", body: "event: message\ndata: " + resultBody("7", structured(`{}`)) + "\n\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mods := replaced(t, runResponse(p, newResponseCtx("get_weather", "7", tc.contentType, tc.body)))
			assertFault(t, mods.IsFault, mods.Fault, policy.FaultCodeMediationFailed, policy.DirectionResponse, codeInvalidToolResult, "7")
			if mods.Fault.Message != messageResultInvalid {
				t.Errorf("message = %q", mods.Fault.Message)
			}
		})
	}

	for _, tc := range []struct{ name, body string }{
		{name: "valid", body: resultBody("7", structured(`{"temperature":31.5,"condition":"sunny"}`))},
		{name: "tool error", body: resultBody("7", `{"isError":true,"content":[]}`)},
		{name: "JSON-RPC error", body: `{"jsonrpc":"2.0","id":7,"error":{"code":-32603,"message":"x"}}`},
	} {
		t.Run(tc.name+" is not a fault", func(t *testing.T) {
			action := runResponse(p, newResponseCtx("get_weather", "7", "application/json", tc.body))
			if mods, ok := action.(policy.DownstreamResponseModifications); ok && (mods.IsFault || mods.Fault != nil) {
				t.Errorf("non-failure declared a fault: %+v", mods.Fault)
			}
		})
	}
}
