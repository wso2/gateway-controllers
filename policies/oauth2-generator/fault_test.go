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
package oauth2generator

import (
	"context"
	"errors"
	"strings"
	"testing"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

// A credential-acquisition failure is the gateway's own: it declares the fault as a
// mediation failure, keeps the reason out of the client body, and never carries the cause.
func TestAuthFailureDeclaresFault(t *testing.T) {
	p := &Policy{mode: ModeTokenEndpoint}
	action := p.authFailure(&policy.SharedContext{}, "failed to obtain upstream credential",
		errors.New("token endpoint said: client_secret=hunter2 rejected"))

	resp, ok := action.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("expected ImmediateResponse, got %T", action)
	}
	if resp.StatusCode != 502 || !resp.IsFault || resp.Fault == nil {
		t.Fatalf("status %d IsFault %v Fault %v", resp.StatusCode, resp.IsFault, resp.Fault)
	}
	f := resp.Fault
	if f.Code != policy.FaultCodeMediationFailed || f.Type != policy.FaultTypeMediation {
		t.Errorf("fault = %s/%s", f.Code, f.Type)
	}
	if f.Description != "failed to obtain upstream credential" {
		t.Errorf("description = %q", f.Description)
	}
	for _, s := range []string{f.Message, f.Description, string(resp.Body)} {
		if strings.Contains(s, "hunter2") {
			t.Fatalf("the cause leaked into the fault: %q", s)
		}
	}
}

// The request-header handler returns authFailure's response when it cannot obtain a token,
// so the fault declaration reaches the client path, not only the helper.
func TestOnRequestHeaders_TokenFetchFailureDeclaresFault(t *testing.T) {
	p := newTestPolicy()
	p.tokenFunc = func(context.Context) (*Token, error) {
		return nil, errors.New("token endpoint returned invalid_client")
	}

	action := p.OnRequestHeaders(context.Background(), newRequestHeaderCtx(), nil)
	resp, ok := action.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("expected ImmediateResponse, got %T", action)
	}
	if !resp.IsFault || resp.Fault == nil {
		t.Fatalf("expected fault metadata, got IsFault=%v Fault=%v", resp.IsFault, resp.Fault)
	}
	if resp.Fault.Code != policy.FaultCodeMediationFailed || resp.Fault.Type != policy.FaultTypeMediation {
		t.Errorf("fault = %s/%s", resp.Fault.Code, resp.Fault.Type)
	}
}
