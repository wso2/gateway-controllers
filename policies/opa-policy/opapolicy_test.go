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

package opapolicy

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

func newReqCtx() *policy.RequestHeaderContext {
	return &policy.RequestHeaderContext{
		SharedContext: &policy.SharedContext{
			RequestID:     "req-1",
			APIId:         "api-1",
			APIName:       "PetStore",
			APIVersion:    "v1",
			APIContext:    "/petstore",
			OperationPath: "/pets/{id}",
			Metadata:      map[string]interface{}{"tenant": "acme"},
			AuthContext: &policy.AuthContext{
				Authenticated: true,
				AuthType:      "jwt",
				Subject:       "alice",
				Issuer:        "https://idp",
				CredentialID:  "client-1",
				Scopes:        map[string]bool{"read": true, "write": true},
			},
		},
		Headers: policy.NewHeaders(map[string][]string{
			"authorization":   {"Bearer tok-123"},
			"x-forwarded-for": {"10.1.2.3, 10.9.9.9"},
			"x-custom":        {"a", "b"},
		}),
		Method: "GET",
		Path:   "/petstore/v1/pets/42",
	}
}

func newPolicy(t *testing.T, params map[string]interface{}) *OPAPolicy {
	t.Helper()
	if _, ok := params["rule"]; !ok {
		params["rule"] = "allow"
	}
	p, err := GetPolicy(policy.PolicyMetadata{}, params)
	if err != nil {
		t.Fatalf("GetPolicy: %v", err)
	}
	return p.(*OPAPolicy)
}

func opaServer(t *testing.T, status int, response string, onReq func(r *http.Request, body map[string]interface{})) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var body map[string]interface{}
		_ = json.Unmarshal(raw, &body)
		if onReq != nil {
			onReq(r, body)
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(response))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestGetPolicy_Validation(t *testing.T) {
	cases := map[string]map[string]interface{}{
		"missing serverUrl":   {"policy": "authz", "rule": "allow"},
		"missing policy":      {"serverUrl": "http://opa:8181/v1/data", "rule": "allow"},
		"missing rule":        {"serverUrl": "http://opa", "policy": "authz"},
		"empty rule":          {"serverUrl": "http://opa", "policy": "authz", "rule": "  "},
		"bad scheme":          {"serverUrl": "ftp://opa", "policy": "authz", "rule": "allow"},
		"bad rule type":       {"serverUrl": "http://opa", "policy": "authz", "rule": 5},
		"bad timeout":         {"serverUrl": "http://opa", "policy": "authz", "rule": "allow", "connectionTimeout": 0},
		"bad max connections": {"serverUrl": "http://opa", "policy": "authz", "rule": "allow", "maxOpenConnections": 1000},
		"bad additional":      {"serverUrl": "http://opa", "policy": "authz", "rule": "allow", "additionalProperties": []interface{}{1}},
	}
	for name, params := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := GetPolicy(policy.PolicyMetadata{}, params); err == nil {
				t.Fatalf("expected error")
			}
		})
	}
}

func TestBuildRequestURL(t *testing.T) {
	if got := buildRequestURL("http://opa:8181/v1/data/", "authz/policy", "allow"); got != "http://opa:8181/v1/data/authz/policy/allow" {
		t.Fatalf("unexpected url %s", got)
	}
}

func TestMode(t *testing.T) {
	p := newPolicy(t, map[string]interface{}{"serverUrl": "http://opa", "policy": "authz"})
	m := p.Mode()
	if m.RequestHeaderMode != policy.HeaderModeProcess || m.RequestBodyMode != policy.BodyModeSkip ||
		m.ResponseHeaderMode != policy.HeaderModeSkip || m.ResponseBodyMode != policy.BodyModeSkip {
		t.Fatalf("unexpected mode %+v", m)
	}
}

func TestOnRequestHeaders_Allow_SendsExpectedInput(t *testing.T) {
	var gotPath, gotAuth, gotCT string
	var gotBody map[string]interface{}
	srv := opaServer(t, 200, `{"result": true}`, func(r *http.Request, body map[string]interface{}) {
		gotPath, gotAuth, gotCT = r.URL.Path, r.Header.Get("Authorization"), r.Header.Get("Content-Type")
		gotBody = body
	})

	p := newPolicy(t, map[string]interface{}{
		"serverUrl":            srv.URL + "/v1/data",
		"policy":               "authz/policy",
		"rule":                 "allow",
		"accessKey":            "opa-key",
		"sendAccessToken":      true,
		"additionalProperties": []interface{}{"tenant", "missing"},
	})

	action := p.OnRequestHeaders(context.Background(), newReqCtx(), nil)
	if _, ok := action.(policy.UpstreamRequestHeaderModifications); !ok {
		t.Fatalf("expected pass-through, got %#v", action)
	}
	if gotPath != "/v1/data/authz/policy/allow" {
		t.Fatalf("path %s", gotPath)
	}
	if gotAuth != "Bearer opa-key" || gotCT != "application/json" {
		t.Fatalf("headers auth=%q ct=%q", gotAuth, gotCT)
	}

	input, ok := gotBody["input"].(map[string]interface{})
	if !ok {
		t.Fatalf("no input: %v", gotBody)
	}
	checks := map[string]string{
		"requestOrigin":   "10.1.2.3",
		"requestMethod":   "GET",
		"requestPath":     "/petstore/v1/pets/42",
		"electedResource": "/pets/{id}",
		"tenant":          "acme",
	}
	for k, want := range checks {
		if input[k] != want {
			t.Fatalf("input[%s]=%v want %s", k, input[k], want)
		}
	}
	if _, present := input["missing"]; present {
		t.Fatalf("absent additional property must be skipped")
	}
	hdrs := input["transportHeaders"].(map[string]interface{})
	if hdrs["x-custom"] != "a,b" {
		t.Fatalf("headers %v", hdrs)
	}
	apiCtx := input["apiContext"].(map[string]interface{})
	if apiCtx["apiName"] != "PetStore" || apiCtx["username"] != "alice" || apiCtx["consumerKey"] != "client-1" ||
		apiCtx["isAuthenticated"] != true || apiCtx["accessToken"] != "tok-123" {
		t.Fatalf("apiContext %v", apiCtx)
	}
}

func TestOnRequestHeaders_AccessTokenNotSentByDefault(t *testing.T) {
	var gotBody map[string]interface{}
	srv := opaServer(t, 200, `{"result": true}`, func(_ *http.Request, body map[string]interface{}) { gotBody = body })
	p := newPolicy(t, map[string]interface{}{"serverUrl": srv.URL, "policy": "authz"})
	p.OnRequestHeaders(context.Background(), newReqCtx(), nil)

	apiCtx := gotBody["input"].(map[string]interface{})["apiContext"].(map[string]interface{})
	if _, present := apiCtx["accessToken"]; present {
		t.Fatalf("access token must not be sent unless enabled")
	}
}

func TestOnRequestHeaders_Deny(t *testing.T) {
	srv := opaServer(t, 200, `{"result": false}`, nil)
	p := newPolicy(t, map[string]interface{}{"serverUrl": srv.URL, "policy": "authz"})

	resp, ok := p.OnRequestHeaders(context.Background(), newReqCtx(), nil).(policy.ImmediateResponse)
	if !ok || resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403, got %#v", resp)
	}
	if want := `{"error":"Forbidden","message":"The request was rejected by the OPA policy validation"}`; string(resp.Body) != want {
		t.Errorf("body = %s, want %s", resp.Body, want)
	}
	assertFault(t, resp, policy.FaultCodeAuthForbidden, policy.FaultTypeAuthorization)
	if want := `OPA policy "authz" rule "allow" denied the request`; resp.Fault.Description != want {
		t.Errorf("Fault.Description = %q, want %q", resp.Fault.Description, want)
	}
}

// assertFault asserts resp is declared as a fault with wantCode and wantType.
func assertFault(t *testing.T, resp policy.ImmediateResponse, wantCode, wantType string) {
	t.Helper()
	if !resp.IsFault {
		t.Error("IsFault = false, want true")
	}
	if resp.Fault == nil {
		t.Fatal("Fault = nil, want a fault description")
	}
	if resp.Fault.Code != wantCode {
		t.Errorf("Fault.Code = %q, want %q", resp.Fault.Code, wantCode)
	}
	if resp.Fault.Type != wantType {
		t.Errorf("Fault.Type = %q, want %q", resp.Fault.Type, wantType)
	}
	if resp.Fault.Direction != policy.DirectionRequest {
		t.Errorf("Fault.Direction = %q, want %q", resp.Fault.Direction, policy.DirectionRequest)
	}
	if resp.Fault.Description == "" {
		t.Error("Fault.Description is empty, want the internal reason")
	}
}

func TestOnRequestHeaders_Errors(t *testing.T) {
	cases := map[string]struct {
		status int
		body   string
	}{
		"undefined decision": {200, `{}`},
		"null decision":      {200, `{"result": null}`},
		"non boolean":        {200, `{"result": "yes"}`},
		"invalid json":       {200, `not-json`},
		"server error":       {503, `{"result": true}`},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			srv := opaServer(t, tc.status, tc.body, nil)
			p := newPolicy(t, map[string]interface{}{"serverUrl": srv.URL, "policy": "authz"})
			resp, ok := p.OnRequestHeaders(context.Background(), newReqCtx(), nil).(policy.ImmediateResponse)
			if !ok || resp.StatusCode != http.StatusInternalServerError {
				t.Fatalf("expected 500, got %#v", resp)
			}
			if want := `{"error":"Internal Server Error","message":"Unable to validate the request with the OPA policy engine"}`; string(resp.Body) != want {
				t.Errorf("body = %s, want %s", resp.Body, want)
			}
			assertFault(t, resp, policy.FaultCodeMediationFailed, policy.FaultTypeMediation)
		})
	}
}

func TestOnRequestHeaders_UnreachableServer(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	url := srv.URL
	srv.Close()

	p := newPolicy(t, map[string]interface{}{"serverUrl": url, "policy": "authz"})
	resp, ok := p.OnRequestHeaders(context.Background(), newReqCtx(), nil).(policy.ImmediateResponse)
	if !ok || resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %#v", resp)
	}
	assertFault(t, resp, policy.FaultCodeMediationFailed, policy.FaultTypeMediation)
}

func TestOnRequestHeaders_Timeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-time.After(3 * time.Second):
		case <-r.Context().Done():
		}
	}))
	t.Cleanup(srv.Close)

	p := newPolicy(t, map[string]interface{}{"serverUrl": srv.URL, "policy": "authz", "connectionTimeout": 1})
	resp, ok := p.OnRequestHeaders(context.Background(), newReqCtx(), nil).(policy.ImmediateResponse)
	if !ok || resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %#v", resp)
	}
}

func TestOnRequestHeaders_RedirectNotFollowed(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("redirect target must not be reached")
	}))
	t.Cleanup(target.Close)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Redirect(w, &http.Request{}, target.URL+"/elsewhere", http.StatusFound)
	}))
	t.Cleanup(srv.Close)

	p := newPolicy(t, map[string]interface{}{"serverUrl": srv.URL, "policy": "authz", "accessKey": "secret"})
	resp, ok := p.OnRequestHeaders(context.Background(), newReqCtx(), nil).(policy.ImmediateResponse)
	if !ok || resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("expected 500 on non-200 redirect response, got %#v", resp)
	}
}

func TestHandleResponse(t *testing.T) {
	p := newPolicy(t, map[string]interface{}{"serverUrl": "http://opa", "policy": "authz"})

	if allowed, err := p.handleResponse([]byte(`{"result": true}`)); err != nil || !allowed {
		t.Fatalf("expected allow, got %v %v", allowed, err)
	}
	if allowed, err := p.handleResponse([]byte(`{"result": false}`)); err != nil || allowed {
		t.Fatalf("expected deny, got %v %v", allowed, err)
	}
	if _, err := p.handleResponse([]byte(`{"result": null}`)); err == nil {
		t.Fatalf("null result must be an error")
	}
	// An object result means the rule is not a boolean rule: reject it.
	if _, err := p.handleResponse([]byte(`{"result": {"allow": true}}`)); err == nil {
		t.Fatalf("object result must be an error")
	}
}

func TestOnRequestHeaders_NoAuthContext(t *testing.T) {
	var gotBody map[string]interface{}
	srv := opaServer(t, 200, `{"result": true}`, func(_ *http.Request, body map[string]interface{}) { gotBody = body })
	p := newPolicy(t, map[string]interface{}{"serverUrl": srv.URL, "policy": "authz"})

	rc := newReqCtx()
	rc.SharedContext.AuthContext = nil
	p.OnRequestHeaders(context.Background(), rc, nil)

	apiCtx := gotBody["input"].(map[string]interface{})["apiContext"].(map[string]interface{})
	if apiCtx["isAuthenticated"] != false {
		t.Fatalf("expected unauthenticated, got %v", apiCtx)
	}
}
