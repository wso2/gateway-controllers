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
package mcpspecvalidation

import (
	"encoding/json"
	"reflect"
	"testing"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

// A rejection declares the fault and carries the JSON-RPC detail only this policy knows: the
// code it chose and the request id it read.
func TestErrorResponseDeclaresFault(t *testing.T) {
	resp := errorResponse(policy.NewHeaders(nil), codeInvalidRequest,
		"Request body is not a single JSON-RPC request object", "7", nil, policy.FaultCodeInvalidRequestBody)

	if resp.StatusCode != 400 || !resp.IsFault || resp.Fault == nil {
		t.Fatalf("status %d IsFault %v Fault %v", resp.StatusCode, resp.IsFault, resp.Fault)
	}
	f := resp.Fault
	if f.Code != policy.FaultCodeInvalidRequestBody || f.Type != policy.FaultTypeValidation {
		t.Errorf("fault = %s/%s", f.Code, f.Type)
	}
	if f.Direction != policy.DirectionRequest {
		t.Errorf("direction = %v, want %v", f.Direction, policy.DirectionRequest)
	}
	if f.Message != "Request body is not a single JSON-RPC request object" {
		t.Errorf("message = %q", f.Message)
	}
	if f.JSONRPC == nil || f.JSONRPC.Code == nil || *f.JSONRPC.Code != codeInvalidRequest {
		t.Fatalf("JSON-RPC code not carried: %+v", f.JSONRPC)
	}
	if id, ok := f.JSONRPC.ID.(json.RawMessage); !ok || string(id) != "7" {
		t.Errorf("JSON-RPC id = %#v, want the raw token 7", f.JSONRPC.ID)
	}
}

// An id the policy never saw stays unset rather than being guessed.
func TestErrorResponseWithoutRequestID(t *testing.T) {
	resp := errorResponse(policy.NewHeaders(nil), codeParseError, "Request body is not valid JSON", "", nil,
		policy.FaultCodeInvalidRequestBody)
	if resp.Fault == nil || resp.Fault.JSONRPC == nil || resp.Fault.JSONRPC.ID != nil {
		t.Fatalf("JSON-RPC id should be nil, got %+v", resp.Fault)
	}
}

// Every header rejection reports FaultCodeInvalidRequestHeader and every body rejection keeps
// FaultCodeInvalidRequestBody. The fault code is the only difference: the client receives what
// errorResponse rendered before it took a fault code.
func TestRejectionsNameTheHeaderOrTheBody(t *testing.T) {
	p := newPolicy(t)
	modern := func(extra map[string]string) map[string]string {
		headers := map[string]string{headerProtocolVersion: modernVersion}
		for k, v := range extra {
			headers[k] = v
		}
		return headers
	}
	headerCases := []struct {
		name    string
		headers map[string]string
		attrs   map[string]string
	}{
		{"MCP-Protocol-Version with a forbidden character",
			map[string]string{headerProtocolVersion: "2026-07-28\r\nX-Injected: 1"}, nil},
		{"MCP-Protocol-Version not a date", map[string]string{headerProtocolVersion: "draft"}, nil},
		{"Mcp-Method with a forbidden character",
			modern(map[string]string{headerMcpMethod: "tools/call\r\nX-Injected: 1"}), nil},
		{"Mcp-Name with a forbidden character",
			modern(map[string]string{headerMcpMethod: "tools/list", headerMcpName: "stray\nvalue"}), nil},
		{"Mcp-Method missing", modern(nil), nil},
		{"Mcp-Name missing for tools/call", modern(map[string]string{headerMcpMethod: "tools/call"}), nil},
		{"Mcp-Name a malformed sentinel",
			modern(map[string]string{headerMcpMethod: "tools/call", headerMcpName: "=?base64?not!base64?="}),
			modernAttrs(map[string]string{attrBodyMethod: "tools/call"})},
		{"MCP-Protocol-Version disagrees with the body", modern(map[string]string{headerMcpMethod: "tools/list"}),
			map[string]string{attrBodyMethod: "tools/list", attrBodyProtocolVersion: legacyVersion}},
		{"Mcp-Method disagrees with the body", modern(map[string]string{headerMcpMethod: "tools/list"}),
			modernAttrs(map[string]string{attrBodyMethod: "tools/call"})},
		{"Mcp-Name disagrees with the body",
			modern(map[string]string{headerMcpMethod: "tools/call", headerMcpName: "get_forecast"}),
			modernAttrs(map[string]string{attrBodyMethod: "tools/call", attrBodyCapabilityName: "delete_everything"})},
	}
	for _, tc := range headerCases {
		t.Run(tc.name, func(t *testing.T) {
			resp, ok := run(t, p, newRequest(tc.headers, tc.attrs)).(policy.ImmediateResponse)
			if !ok {
				t.Fatal("expected the request to be rejected")
			}
			assertFaultOnly(t, resp, policy.FaultCodeInvalidRequestHeader, codeHeaderMismatch)
		})
	}

	t.Run("body the resolver could not read", func(t *testing.T) {
		resp, ok := run(t, p, newRequest(modern(nil),
			map[string]string{attrBodyUnusable: reasonAmbiguous})).(policy.ImmediateResponse)
		if !ok {
			t.Fatal("expected the request to be rejected")
		}
		assertFaultOnly(t, resp, policy.FaultCodeInvalidRequestBody, codeInvalidRequest)
	})

	t.Run("body unreadable without the resolver", func(t *testing.T) {
		resp, ok := runBody(t, p, newBodyRequest(`{"jsonrpc":"2.0","method":`)).(policy.ImmediateResponse)
		if !ok {
			t.Fatal("expected the request to be rejected")
		}
		assertFaultOnly(t, resp, policy.FaultCodeInvalidRequestBody, codeParseError)
	})
}

// assertFaultOnly checks the fault's code, type and JSON-RPC code, and that the status, headers
// and body match errorResponse's output for the same rejection under the body code.
func assertFaultOnly(t *testing.T, resp policy.ImmediateResponse, wantCode string, wantRPC int) {
	t.Helper()
	f := resp.Fault
	if f == nil || f.Code != wantCode || f.Type != policy.FaultTypeValidation {
		t.Fatalf("fault = %+v, want %s/%s", f, wantCode, policy.FaultTypeValidation)
	}
	if f.JSONRPC == nil || f.JSONRPC.Code == nil || *f.JSONRPC.Code != wantRPC {
		t.Fatalf("JSON-RPC detail = %+v, want code %d", f.JSONRPC, wantRPC)
	}
	want := errorResponse(policy.NewHeaders(nil), wantRPC, f.Message, "", nil, policy.FaultCodeInvalidRequestBody)
	if resp.StatusCode != want.StatusCode || !reflect.DeepEqual(resp.Headers, want.Headers) ||
		string(resp.Body) != string(want.Body) {
		t.Fatalf("response = %d %v %s, want %d %v %s",
			resp.StatusCode, resp.Headers, resp.Body, want.StatusCode, want.Headers, want.Body)
	}
}
