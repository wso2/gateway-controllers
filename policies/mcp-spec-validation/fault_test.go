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
	"testing"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

// A rejection declares the fault and carries the JSON-RPC detail only this policy knows: the
// code it chose and the request id it read.
func TestErrorResponseDeclaresFault(t *testing.T) {
	resp := errorResponse(policy.NewHeaders(nil), codeInvalidRequest,
		"Request body is not a single JSON-RPC request object", "7", nil)

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
	resp := errorResponse(policy.NewHeaders(nil), codeParseError, "Request body is not valid JSON", "", nil)
	if resp.Fault == nil || resp.Fault.JSONRPC == nil || resp.Fault.JSONRPC.ID != nil {
		t.Fatalf("JSON-RPC id should be nil, got %+v", resp.Fault)
	}
}
