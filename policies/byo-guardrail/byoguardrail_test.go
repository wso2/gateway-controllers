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

package byoguardrail

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

const testToken = "s3cr3t-guardrail-token"

// guardrailServer is a mock guardrail service. handler receives the decoded
// request and writes the reply; the last request and its Authorization
// header are captured for assertions.
type guardrailServer struct {
	*httptest.Server
	calls atomic.Int32

	mu       sync.Mutex
	lastReq  evaluateRequest
	lastAuth string
}

func newGuardrailServer(t *testing.T, handler func(w http.ResponseWriter, req evaluateRequest)) *guardrailServer {
	t.Helper()
	gs := &guardrailServer{}
	gs.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gs.calls.Add(1)
		body, _ := io.ReadAll(r.Body)
		var req evaluateRequest
		if err := json.Unmarshal(body, &req); err != nil {
			t.Errorf("mock guardrail: bad request body: %v", err)
		}
		gs.mu.Lock()
		gs.lastReq, gs.lastAuth = req, r.Header.Get("Authorization")
		gs.mu.Unlock()
		handler(w, req)
	}))
	t.Cleanup(gs.Close)
	return gs
}

func reply(body string) func(http.ResponseWriter, evaluateRequest) {
	return func(w http.ResponseWriter, _ evaluateRequest) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, body)
	}
}

func newPolicy(t *testing.T, params map[string]interface{}) *BYOGuardrailPolicy {
	t.Helper()
	p, err := GetPolicy(policy.PolicyMetadata{}, params)
	if err != nil {
		t.Fatalf("GetPolicy: %v", err)
	}
	return p.(*BYOGuardrailPolicy)
}

func baseParams(endpoint string) map[string]interface{} {
	return map[string]interface{}{
		"endpoint": endpoint,
		"auth":     map[string]interface{}{"type": "bearer", "token": testToken},
		"request":  map[string]interface{}{},
	}
}

func chatRequest(content string) []byte {
	b, _ := json.Marshal(map[string]interface{}{
		"model":       "gpt-4o",
		"temperature": 0.2,
		"user_id":     json.Number("12345678901234567890"),
		"messages": []interface{}{
			map[string]interface{}{"role": "system", "content": "Be helpful."},
			map[string]interface{}{"role": "user", "content": content},
		},
	})
	return b
}

func shared() *policy.SharedContext {
	return &policy.SharedContext{RequestID: "req-123", APIName: "chat-api", APIVersion: "v1"}
}

func runRequest(p *BYOGuardrailPolicy, sc *policy.SharedContext, body []byte) policy.RequestAction {
	return p.OnRequestBody(context.Background(), &policy.RequestContext{
		SharedContext: sc,
		Body:          &policy.Body{Content: body, Present: true},
	}, nil)
}

func runResponse(p *BYOGuardrailPolicy, sc *policy.SharedContext, status int, body []byte) policy.ResponseAction {
	return p.OnResponseBody(context.Background(), &policy.ResponseContext{
		SharedContext:  sc,
		ResponseStatus: status,
		ResponseBody:   &policy.Body{Content: body, Present: true},
	}, nil)
}

func mustImmediate(t *testing.T, action policy.RequestAction) policy.ImmediateResponse {
	t.Helper()
	resp, ok := action.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("expected ImmediateResponse, got %T", action)
	}
	if resp.StatusCode != GuardrailErrorCode {
		t.Fatalf("expected status %d, got %d", GuardrailErrorCode, resp.StatusCode)
	}
	return resp
}

func mustPass(t *testing.T, action policy.RequestAction) policy.UpstreamRequestModifications {
	t.Helper()
	mods, ok := action.(policy.UpstreamRequestModifications)
	if !ok {
		t.Fatalf("expected UpstreamRequestModifications, got %T", action)
	}
	return mods
}

func decodeMessage(t *testing.T, body []byte) map[string]interface{} {
	t.Helper()
	var parsed struct {
		Type    string                 `json:"type"`
		Message map[string]interface{} `json:"message"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		t.Fatalf("block body is not JSON: %v", err)
	}
	if parsed.Type != errorResponseType {
		t.Fatalf("unexpected type %q", parsed.Type)
	}
	return parsed.Message
}

func metaRecord(t *testing.T, sc *policy.SharedContext, phase string) map[string]interface{} {
	t.Helper()
	rec, ok := sc.Metadata[metaKeyPrefix+phase].(map[string]interface{})
	if !ok {
		t.Fatalf("no metadata recorded for phase %q: %v", phase, sc.Metadata)
	}
	return rec
}

// --- Configuration ---

func TestGetPolicy_Defaults(t *testing.T) {
	p := newPolicy(t, map[string]interface{}{
		"endpoint": "https://guardrail.example.com/evaluate",
		"request":  map[string]interface{}{},
		"response": map[string]interface{}{},
	})
	if p.timeout != defaultTimeout || p.mode != modeEnforce || p.onError != onErrorBlock {
		t.Fatalf("unexpected defaults: timeout=%s mode=%s onError=%s", p.timeout, p.mode, p.onError)
	}
	if p.authHeader != "" {
		t.Fatalf("expected no auth header when auth is omitted")
	}
	if !p.requestParams.Enabled || p.requestParams.JSONPath != requestDefaultJSONPath || p.requestParams.ShowAssessment {
		t.Fatalf("unexpected request defaults: %+v", p.requestParams)
	}
	if !p.responseParams.Enabled || p.responseParams.JSONPath != responseDefaultJSONPath ||
		p.responseParams.StreamingJSONPath != streamingDefaultJSONPath {
		t.Fatalf("unexpected response defaults: %+v", p.responseParams)
	}
}

func TestGetPolicy_ExplicitConfig(t *testing.T) {
	p := newPolicy(t, map[string]interface{}{
		"endpoint": "http://localhost:9000/v1/check?tenant=a",
		"auth":     map[string]interface{}{"type": "bearer", "token": " " + testToken + " "},
		"timeout":  "1500ms",
		"mode":     "monitor",
		"onError":  "allow",
		"request":  map[string]interface{}{"enabled": false},
		"response": map[string]interface{}{"jsonPath": "$.output.text", "showAssessment": true, "streamingJsonPath": "$.delta.text"},
	})
	if p.authHeader != "Bearer "+testToken {
		t.Fatalf("token not trimmed")
	}
	if p.timeout != 1500*time.Millisecond || p.mode != modeMonitor || p.onError != onErrorAllow {
		t.Fatalf("unexpected config: %+v", p)
	}
	if p.requestEnabled() || !p.responseEnabled() {
		t.Fatalf("unexpected enabled phases")
	}
	if p.responseParams.JSONPath != "$.output.text" || p.responseParams.StreamingJSONPath != "$.delta.text" || !p.responseParams.ShowAssessment {
		t.Fatalf("unexpected response params: %+v", p.responseParams)
	}
}

func TestGetPolicy_Validation(t *testing.T) {
	valid := func(mutate func(map[string]interface{})) map[string]interface{} {
		params := baseParams("https://guardrail.example.com/evaluate")
		mutate(params)
		return params
	}
	tests := []struct {
		name    string
		params  map[string]interface{}
		wantErr string
	}{
		{"missing endpoint", valid(func(m map[string]interface{}) { delete(m, "endpoint") }), "'endpoint' parameter is required"},
		{"endpoint wrong type", valid(func(m map[string]interface{}) { m["endpoint"] = 5 }), "'endpoint' must be a non-empty string"},
		{"endpoint bad scheme", valid(func(m map[string]interface{}) { m["endpoint"] = "ftp://x/evaluate" }), "http or https"},
		{"endpoint relative", valid(func(m map[string]interface{}) { m["endpoint"] = "/evaluate" }), "http or https"},
		{"endpoint no host", valid(func(m map[string]interface{}) { m["endpoint"] = "https:///evaluate" }), "must include a host"},
		{"endpoint with userinfo", valid(func(m map[string]interface{}) { m["endpoint"] = "https://u:p@x/evaluate" }), "must not contain user credentials"},
		{"auth not object", valid(func(m map[string]interface{}) { m["auth"] = "Bearer x" }), "'auth' must be an object"},
		{"auth unknown type", valid(func(m map[string]interface{}) { m["auth"] = map[string]interface{}{"type": "basic", "token": "x"} }), "'auth.type' must be"},
		{"auth missing token", valid(func(m map[string]interface{}) { m["auth"] = map[string]interface{}{"type": "bearer"} }), "'auth.token' is required"},
		{"auth blank token", valid(func(m map[string]interface{}) { m["auth"] = map[string]interface{}{"type": "bearer", "token": "  "} }), "'auth.token' is required"},
		{"auth token newline", valid(func(m map[string]interface{}) {
			m["auth"] = map[string]interface{}{"type": "bearer", "token": "a\r\nX-Evil: 1"}
		}), "line breaks"},
		{"timeout not string", valid(func(m map[string]interface{}) { m["timeout"] = 5 }), "'timeout' must be a duration"},
		{"timeout unparseable", valid(func(m map[string]interface{}) { m["timeout"] = "five" }), "'timeout' must be a duration"},
		{"timeout zero", valid(func(m map[string]interface{}) { m["timeout"] = "0s" }), "greater than 0"},
		{"timeout too long", valid(func(m map[string]interface{}) { m["timeout"] = "31s" }), "at most 30s"},
		{"bad mode", valid(func(m map[string]interface{}) { m["mode"] = "audit" }), "'mode' must be one of"},
		{"bad onError", valid(func(m map[string]interface{}) { m["onError"] = "passthrough" }), "'onError' must be one of"},
		{"neither phase", valid(func(m map[string]interface{}) { delete(m, "request") }), "at least one of 'request' or 'response'"},
		{"request not object", valid(func(m map[string]interface{}) { m["request"] = true }), "invalid request parameters"},
		{"enabled not bool", valid(func(m map[string]interface{}) { m["request"] = map[string]interface{}{"enabled": "yes"} }), "'enabled' must be a boolean"},
		{"showAssessment not bool", valid(func(m map[string]interface{}) { m["request"] = map[string]interface{}{"showAssessment": 1} }), "'showAssessment' must be a boolean"},
		{"jsonPath not string", valid(func(m map[string]interface{}) { m["request"] = map[string]interface{}{"jsonPath": 1} }), "'jsonPath' must be a string"},
		{"jsonPath no root", valid(func(m map[string]interface{}) { m["request"] = map[string]interface{}{"jsonPath": "messages[0]"} }), "must start with"},
		{"jsonPath wildcard", valid(func(m map[string]interface{}) {
			m["request"] = map[string]interface{}{"jsonPath": "$.messages.*.content"}
		}), "wildcards are not supported"},
		{"jsonPath bad index", valid(func(m map[string]interface{}) {
			m["request"] = map[string]interface{}{"jsonPath": "$.messages[last].content"}
		}), "key or key[index]"},
		{"jsonPath empty segment", valid(func(m map[string]interface{}) { m["request"] = map[string]interface{}{"jsonPath": "$.a..b"} }), "empty segment"},
		{"streamingJsonPath empty", valid(func(m map[string]interface{}) { m["response"] = map[string]interface{}{"streamingJsonPath": ""} }), "'streamingJsonPath' must be a non-empty string"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := GetPolicy(policy.PolicyMetadata{}, tt.params)
			if err == nil {
				t.Fatalf("expected error containing %q", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error %q does not contain %q", err.Error(), tt.wantErr)
			}
			if strings.Contains(err.Error(), testToken) {
				t.Fatalf("error exposes the token: %q", err.Error())
			}
		})
	}
}

func TestGetPolicy_AuthTypeDefaultsToBearer(t *testing.T) {
	p := newPolicy(t, map[string]interface{}{
		"endpoint": "https://guardrail.example.com/evaluate",
		"auth":     map[string]interface{}{"token": testToken},
		"request":  map[string]interface{}{},
	})
	if p.authHeader != "Bearer "+testToken {
		t.Fatalf("expected the token to be sent as a bearer token")
	}
}

func TestGetPolicy_AuthTypeRaw(t *testing.T) {
	p := newPolicy(t, map[string]interface{}{
		"endpoint": "https://guardrail.example.com/evaluate",
		"auth":     map[string]interface{}{"type": "raw", "token": " " + testToken + " "},
		"request":  map[string]interface{}{},
	})
	if p.authHeader != testToken {
		t.Fatalf("expected the raw token with no Bearer prefix, got %q", p.authHeader)
	}
}

func TestGetPolicy_EmptyJSONPathAllowed(t *testing.T) {
	p := newPolicy(t, map[string]interface{}{
		"endpoint": "https://guardrail.example.com/evaluate",
		"request":  map[string]interface{}{"jsonPath": ""},
	})
	if p.requestParams.JSONPath != "" {
		t.Fatalf("expected empty jsonPath to select the whole body")
	}
}

func TestMode(t *testing.T) {
	tests := []struct {
		name         string
		params       map[string]interface{}
		wantRequest  policy.BodyProcessingMode
		wantResponse policy.BodyProcessingMode
	}{
		// Request-only must skip the response body so streaming stays intact.
		{"request only", map[string]interface{}{"request": map[string]interface{}{}}, policy.BodyModeBuffer, policy.BodyModeSkip},
		{"response only", map[string]interface{}{"response": map[string]interface{}{}}, policy.BodyModeSkip, policy.BodyModeBuffer},
		{"response disabled", map[string]interface{}{"request": map[string]interface{}{}, "response": map[string]interface{}{"enabled": false}}, policy.BodyModeBuffer, policy.BodyModeSkip},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.params["endpoint"] = "https://guardrail.example.com/evaluate"
			got := newPolicy(t, tt.params).Mode()
			if got.RequestBodyMode != tt.wantRequest || got.ResponseBodyMode != tt.wantResponse {
				t.Fatalf("unexpected mode: %+v", got)
			}
		})
	}
}

// --- Contract: what the gateway sends ---

func TestRequestSentToGuardrail_RawAuth(t *testing.T) {
	gs := newGuardrailServer(t, reply(`{"action":"allow"}`))
	params := baseParams(gs.URL + "/evaluate")
	params["auth"] = map[string]interface{}{"type": "raw", "token": testToken}
	p := newPolicy(t, params)

	mustPass(t, runRequest(p, shared(), chatRequest("hello there")))

	if gs.lastAuth != testToken {
		t.Fatalf("unexpected Authorization header: %q", gs.lastAuth)
	}
}

func TestRequestSentToGuardrail(t *testing.T) {
	gs := newGuardrailServer(t, reply(`{"action":"allow"}`))
	p := newPolicy(t, baseParams(gs.URL+"/evaluate"))

	mustPass(t, runRequest(p, shared(), chatRequest("hello there")))

	if gs.lastAuth != "Bearer "+testToken {
		t.Fatalf("unexpected Authorization header: %q", gs.lastAuth)
	}
	want := evaluateRequest{
		ContractVersion: ContractVersion,
		InputType:       "request",
		Texts:           []string{"hello there"},
		Metadata:        evaluateMetadata{APIName: "chat-api", APIVersion: "v1", RequestID: "req-123"},
	}
	if got, _ := json.Marshal(gs.lastReq); string(got) != mustJSON(want) {
		t.Fatalf("unexpected guardrail request:\n got %s\nwant %s", got, mustJSON(want))
	}
}

func TestNoAuthHeaderWithoutAuth(t *testing.T) {
	gs := newGuardrailServer(t, reply(`{"action":"allow"}`))
	params := baseParams(gs.URL)
	delete(params, "auth")
	mustPass(t, runRequest(newPolicy(t, params), shared(), chatRequest("hi")))
	if gs.lastAuth != "" {
		t.Fatalf("expected no Authorization header, got %q", gs.lastAuth)
	}
}

func TestContentPartsSentAsTexts(t *testing.T) {
	gs := newGuardrailServer(t, reply(`{"action":"allow"}`))
	p := newPolicy(t, baseParams(gs.URL))
	body := []byte(`{"messages":[{"role":"user","content":[
		{"type":"text","text":"first"},
		{"type":"image_url","image_url":{"url":"https://img.example.com/a.png"}},
		{"type":"text","text":"second"}]}]}`)

	mustPass(t, runRequest(p, shared(), body))
	if strings.Join(gs.lastReq.Texts, "|") != "first|second" {
		t.Fatalf("expected only text parts, got %q", gs.lastReq.Texts)
	}
}

func mustJSON(v interface{}) string {
	b, _ := json.Marshal(v)
	return string(b)
}

// --- Decisions ---

func TestAllow(t *testing.T) {
	gs := newGuardrailServer(t, reply(`{"action":"allow","reason":"looks fine"}`))
	sc := shared()
	mods := mustPass(t, runRequest(newPolicy(t, baseParams(gs.URL)), sc, chatRequest("hello")))
	if mods.Body != nil || mods.AnalyticsMetadata != nil {
		t.Fatalf("allow must not change the request: %+v", mods)
	}
	if rec := metaRecord(t, sc, "request"); rec["decision"] != "allow" || rec["outcome"] != "passed" {
		t.Fatalf("unexpected metadata: %v", rec)
	}
}

func TestBlock(t *testing.T) {
	gs := newGuardrailServer(t, reply(`{"action":"block","reason":"Restricted content"}`))

	t.Run("without assessment", func(t *testing.T) {
		sc := shared()
		resp := mustImmediate(t, runRequest(newPolicy(t, baseParams(gs.URL)), sc, chatRequest("bad")))
		msg := decodeMessage(t, resp.Body)
		if msg["actionReason"] != actionReasonViolation || msg["direction"] != "REQUEST" {
			t.Fatalf("unexpected message: %v", msg)
		}
		if _, ok := msg["assessments"]; ok {
			t.Fatalf("assessment must be hidden by default: %v", msg)
		}
		if resp.AnalyticsMetadata["isGuardrailHit"] != true || resp.AnalyticsMetadata["guardrailName"] != guardrailName {
			t.Fatalf("unexpected analytics: %v", resp.AnalyticsMetadata)
		}
		if rec := metaRecord(t, sc, "request"); rec["decision"] != "block" || rec["outcome"] != "blocked" {
			t.Fatalf("unexpected metadata: %v", rec)
		}
		if _, ok := metaRecord(t, sc, "request")["reason"]; ok {
			t.Fatalf("the guardrail's reason must not be recorded in metadata")
		}
	})

	t.Run("with assessment", func(t *testing.T) {
		params := baseParams(gs.URL)
		params["request"] = map[string]interface{}{"showAssessment": true}
		resp := mustImmediate(t, runRequest(newPolicy(t, params), shared(), chatRequest("bad")))
		if msg := decodeMessage(t, resp.Body); msg["assessments"] != "Restricted content" {
			t.Fatalf("expected the guardrail's reason, got %v", msg)
		}
	})
}

func TestModifyPreservesUnrelatedFields(t *testing.T) {
	gs := newGuardrailServer(t, reply(`{"action":"modify","texts":["My card is [REDACTED] & <ok>"]}`))
	sc := shared()
	mods := mustPass(t, runRequest(newPolicy(t, baseParams(gs.URL)), sc, chatRequest("My card is 4111 1111 1111 1111")))
	if mods.Body == nil {
		t.Fatalf("expected a modified body")
	}

	var got map[string]interface{}
	dec := json.NewDecoder(bytes.NewReader(mods.Body))
	dec.UseNumber()
	if err := dec.Decode(&got); err != nil {
		t.Fatalf("modified body is not JSON: %v", err)
	}
	msgs := got["messages"].([]interface{})
	if c := msgs[1].(map[string]interface{})["content"]; c != "My card is [REDACTED] & <ok>" {
		t.Fatalf("content not replaced: %v", c)
	}
	if c := msgs[0].(map[string]interface{})["content"]; c != "Be helpful." {
		t.Fatalf("unrelated message changed: %v", c)
	}
	if got["model"] != "gpt-4o" || got["temperature"] != json.Number("0.2") {
		t.Fatalf("unrelated fields changed: %v", got)
	}
	// A large integer must survive re-encoding without float rounding.
	if got["user_id"] != json.Number("12345678901234567890") {
		t.Fatalf("large number not preserved: %v", got["user_id"])
	}
	if bytes.Contains(mods.Body, []byte(`\u0026`)) {
		t.Fatalf("body was HTML-escaped: %s", mods.Body)
	}
	if rec := metaRecord(t, sc, "request"); rec["decision"] != "modify" || rec["outcome"] != "modified" {
		t.Fatalf("unexpected metadata: %v", rec)
	}
}

func TestModifyContentParts(t *testing.T) {
	gs := newGuardrailServer(t, reply(`{"action":"modify","texts":["one","two"]}`))
	body := []byte(`{"messages":[{"role":"user","content":[
		{"type":"text","text":"first"},
		{"type":"image_url","image_url":{"url":"https://img.example.com/a.png"}},
		{"type":"text","text":"second"}]}]}`)
	mods := mustPass(t, runRequest(newPolicy(t, baseParams(gs.URL)), shared(), body))

	var got struct {
		Messages []struct {
			Content []map[string]interface{} `json:"content"`
		} `json:"messages"`
	}
	if err := json.Unmarshal(mods.Body, &got); err != nil {
		t.Fatalf("modified body is not JSON: %v", err)
	}
	parts := got.Messages[0].Content
	if parts[0]["text"] != "one" || parts[2]["text"] != "two" || parts[1]["type"] != "image_url" {
		t.Fatalf("unexpected parts: %v", parts)
	}
}

func TestModifyWholeBody(t *testing.T) {
	gs := newGuardrailServer(t, reply(`{"action":"modify","texts":["clean text"]}`))
	params := baseParams(gs.URL)
	params["request"] = map[string]interface{}{"jsonPath": ""}
	mods := mustPass(t, runRequest(newPolicy(t, params), shared(), []byte("raw text body")))
	if string(mods.Body) != "clean text" {
		t.Fatalf("unexpected body: %q", mods.Body)
	}
	if gs.lastReq.Texts[0] != "raw text body" {
		t.Fatalf("expected the whole body to be sent, got %q", gs.lastReq.Texts)
	}
}

// --- Invalid guardrail responses ---

func TestInvalidGuardrailResponses(t *testing.T) {
	tests := []struct {
		name   string
		status int
		body   string
	}{
		{"malformed JSON", 200, `{"action":`},
		{"not an object", 200, `["allow"]`},
		{"null body", 200, `null`},
		{"empty body", 200, ``},
		{"missing action", 200, `{"reason":"x"}`},
		{"action wrong type", 200, `{"action":true}`},
		{"unknown action", 200, `{"action":"ALLOW"}`},
		{"empty action", 200, `{"action":""}`},
		{"modify missing texts", 200, `{"action":"modify"}`},
		{"modify null texts", 200, `{"action":"modify","texts":null}`},
		{"modify too few texts", 200, `{"action":"modify","texts":[]}`},
		{"modify too many texts", 200, `{"action":"modify","texts":["a","b"]}`},
		{"modify non-string text", 200, `{"action":"modify","texts":[1]}`},
		{"modify null text", 200, `{"action":"modify","texts":[null]}`},
		{"modify texts not array", 200, `{"action":"modify","texts":"a"}`},
		{"allow with texts", 200, `{"action":"allow","texts":["a"]}`},
		{"block with texts", 200, `{"action":"block","texts":["a"]}`},
		{"status 500", 500, `{"action":"allow"}`},
		{"status 403", 403, `{"action":"allow"}`},
		{"status 204", 204, ``},
		{"status 201", 201, `{"action":"allow"}`},
		{"redirect not followed", 302, ``},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gs := newGuardrailServer(t, func(w http.ResponseWriter, _ evaluateRequest) {
				if tt.status == 302 {
					w.Header().Set("Location", "https://elsewhere.example.com/")
				}
				w.WriteHeader(tt.status)
				_, _ = io.WriteString(w, tt.body)
			})
			sc := shared()
			resp := mustImmediate(t, runRequest(newPolicy(t, baseParams(gs.URL)), sc, chatRequest("hello")))
			if msg := decodeMessage(t, resp.Body); msg["actionReason"] != actionReasonError {
				t.Fatalf("unexpected actionReason: %v", msg)
			}
			rec := metaRecord(t, sc, "request")
			if rec["decision"] != "error" || rec["outcome"] != "blocked" {
				t.Fatalf("unexpected metadata: %v", rec)
			}
			wantKind := errKindInvalidResponse
			if tt.status != 200 {
				wantKind = errKindHTTPStatus
			}
			if rec["errorType"] != wantKind {
				t.Fatalf("errorType = %v, want %s", rec["errorType"], wantKind)
			}
		})
	}
}

func TestOversizedResponseRejected(t *testing.T) {
	gs := newGuardrailServer(t, reply(`{"action":"allow","pad":"`+strings.Repeat("x", maxGuardrailResponseBytes)+`"}`))
	sc := shared()
	mustImmediate(t, runRequest(newPolicy(t, baseParams(gs.URL)), sc, chatRequest("hello")))
	if rec := metaRecord(t, sc, "request"); rec["errorType"] != errKindInvalidResponse {
		t.Fatalf("unexpected metadata: %v", rec)
	}
}

func TestUnknownResponseFieldsIgnored(t *testing.T) {
	gs := newGuardrailServer(t, reply(`{"action":"allow","debug":{"score":0.01}}`))
	mustPass(t, runRequest(newPolicy(t, baseParams(gs.URL)), shared(), chatRequest("hello")))
}

// --- Service failures, fail-open and fail-closed ---

func TestTimeout(t *testing.T) {
	release := make(chan struct{})
	gs := newGuardrailServer(t, func(w http.ResponseWriter, _ evaluateRequest) {
		<-release
		_, _ = io.WriteString(w, `{"action":"allow"}`)
	})
	t.Cleanup(func() { close(release) })

	for _, onError := range []string{onErrorBlock, onErrorAllow} {
		t.Run(onError, func(t *testing.T) {
			params := baseParams(gs.URL)
			params["timeout"] = "50ms"
			params["onError"] = onError
			sc := shared()
			start := time.Now()
			action := runRequest(newPolicy(t, params), sc, chatRequest("hello"))
			if elapsed := time.Since(start); elapsed > 2*time.Second {
				t.Fatalf("timeout not enforced: took %s", elapsed)
			}
			rec := metaRecord(t, sc, "request")
			if rec["decision"] != "error" || rec["errorType"] != errKindTimeout {
				t.Fatalf("unexpected metadata: %v", rec)
			}
			if onError == onErrorBlock {
				mustImmediate(t, action)
				if rec["outcome"] != "blocked" {
					t.Fatalf("unexpected outcome: %v", rec)
				}
				return
			}
			mods := mustPass(t, action)
			if mods.Body != nil || mods.AnalyticsMetadata != nil {
				t.Fatalf("fail-open must pass the request unchanged: %+v", mods)
			}
			// Passing through on an error must never be reported as an allow.
			if rec["outcome"] != "passed" || rec["decision"] == "allow" {
				t.Fatalf("unexpected outcome: %v", rec)
			}
		})
	}
}

func TestConnectionFailure(t *testing.T) {
	gs := newGuardrailServer(t, reply(`{"action":"allow"}`))
	endpoint := gs.URL
	gs.Close() // nothing listens on endpoint any more

	for _, onError := range []string{onErrorBlock, onErrorAllow} {
		t.Run(onError, func(t *testing.T) {
			params := baseParams(endpoint)
			params["onError"] = onError
			sc := shared()
			action := runRequest(newPolicy(t, params), sc, chatRequest("hello"))
			if onError == onErrorBlock {
				mustImmediate(t, action)
			} else {
				mustPass(t, action)
			}
			if rec := metaRecord(t, sc, "request"); rec["errorType"] != errKindConnection {
				t.Fatalf("unexpected metadata: %v", rec)
			}
		})
	}
}

func TestExtractionFailureHonoursOnError(t *testing.T) {
	gs := newGuardrailServer(t, reply(`{"action":"allow"}`))
	for _, onError := range []string{onErrorBlock, onErrorAllow} {
		t.Run(onError, func(t *testing.T) {
			params := baseParams(gs.URL)
			params["onError"] = onError
			sc := shared()
			action := runRequest(newPolicy(t, params), sc, []byte(`{"prompt":"no messages here"}`))
			if onError == onErrorBlock {
				mustImmediate(t, action)
			} else {
				mustPass(t, action)
			}
			if rec := metaRecord(t, sc, "request"); rec["errorType"] != errKindExtraction {
				t.Fatalf("unexpected metadata: %v", rec)
			}
		})
	}
	if gs.calls.Load() != 0 {
		t.Fatalf("guardrail must not be called when extraction fails")
	}
}

func TestErrorAssessmentIsContentFree(t *testing.T) {
	gs := newGuardrailServer(t, func(w http.ResponseWriter, _ evaluateRequest) {
		w.WriteHeader(500)
		_, _ = io.WriteString(w, `internal detail: secret-stack-trace`)
	})
	params := baseParams(gs.URL)
	params["request"] = map[string]interface{}{"showAssessment": true}
	resp := mustImmediate(t, runRequest(newPolicy(t, params), shared(), chatRequest("hello")))
	if msg := decodeMessage(t, resp.Body); msg["assessments"] != errorReasons[errKindHTTPStatus] {
		t.Fatalf("unexpected assessment: %v", msg)
	}
	if bytes.Contains(resp.Body, []byte("secret-stack-trace")) {
		t.Fatalf("service response leaked to client: %s", resp.Body)
	}
}

// --- Monitor mode ---

func TestMonitorMode(t *testing.T) {
	tests := []struct {
		name         string
		reply        string
		wantDecision string
		wantAnalytic bool
	}{
		{"block", `{"action":"block","reason":"x"}`, "block", true},
		{"modify", `{"action":"modify","texts":["changed"]}`, "modify", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gs := newGuardrailServer(t, reply(tt.reply))
			params := baseParams(gs.URL)
			params["mode"] = "monitor"
			sc := shared()
			mods := mustPass(t, runRequest(newPolicy(t, params), sc, chatRequest("hello")))
			if mods.Body != nil {
				t.Fatalf("monitor mode must not modify the body")
			}
			if got := mods.AnalyticsMetadata["isGuardrailHit"] == true; got != tt.wantAnalytic {
				t.Fatalf("analytics hit = %v, want %v", got, tt.wantAnalytic)
			}
			rec := metaRecord(t, sc, "request")
			if rec["decision"] != tt.wantDecision || rec["outcome"] != "passed" {
				t.Fatalf("unexpected metadata: %v", rec)
			}
		})
	}
}

func TestMonitorModeNeverBlocksOnError(t *testing.T) {
	gs := newGuardrailServer(t, func(w http.ResponseWriter, _ evaluateRequest) { w.WriteHeader(503) })
	params := baseParams(gs.URL)
	params["mode"] = "monitor"
	params["onError"] = "block"
	sc := shared()
	mustPass(t, runRequest(newPolicy(t, params), sc, chatRequest("hello")))
	if rec := metaRecord(t, sc, "request"); rec["decision"] != "error" || rec["outcome"] != "passed" {
		t.Fatalf("unexpected metadata: %v", rec)
	}
}

// --- Skipped checks ---

func TestNothingToCheck(t *testing.T) {
	gs := newGuardrailServer(t, reply(`{"action":"block"}`))
	p := newPolicy(t, baseParams(gs.URL))
	for name, body := range map[string][]byte{
		"empty body":    nil,
		"null content":  []byte(`{"messages":[{"role":"assistant","content":null}]}`),
		"blank content": []byte(`{"messages":[{"role":"user","content":"   "}]}`),
		"image only":    []byte(`{"messages":[{"role":"user","content":[{"type":"image_url","image_url":{"url":"x"}}]}]}`),
	} {
		t.Run(name, func(t *testing.T) {
			mustPass(t, runRequest(p, shared(), body))
		})
	}
	if gs.calls.Load() != 0 {
		t.Fatalf("guardrail called %d times for content with no text", gs.calls.Load())
	}
}

func TestDisabledPhaseSkipped(t *testing.T) {
	gs := newGuardrailServer(t, reply(`{"action":"block"}`))
	params := baseParams(gs.URL)
	params["request"] = map[string]interface{}{"enabled": false}
	mustPass(t, runRequest(newPolicy(t, params), shared(), chatRequest("hello")))
	if gs.calls.Load() != 0 {
		t.Fatalf("disabled phase called the guardrail")
	}
}

// --- Response phase ---

func responseParams(endpoint string) map[string]interface{} {
	return map[string]interface{}{
		"endpoint": endpoint,
		"response": map[string]interface{}{"showAssessment": true},
	}
}

func TestResponseBlock(t *testing.T) {
	gs := newGuardrailServer(t, reply(`{"action":"block","reason":"Leaked secret"}`))
	sc := shared()
	action := runResponse(newPolicy(t, responseParams(gs.URL)), sc, 200,
		[]byte(`{"id":"c1","choices":[{"message":{"role":"assistant","content":"the password is hunter2"}}]}`))
	mods, ok := action.(policy.DownstreamResponseModifications)
	if !ok || mods.StatusCode == nil || *mods.StatusCode != GuardrailErrorCode {
		t.Fatalf("expected 422 response modifications, got %+v", action)
	}
	msg := decodeMessage(t, mods.Body)
	if msg["direction"] != "RESPONSE" || msg["assessments"] != "Leaked secret" {
		t.Fatalf("unexpected message: %v", msg)
	}
	if gs.lastReq.InputType != "response" || gs.lastReq.Texts[0] != "the password is hunter2" {
		t.Fatalf("unexpected guardrail request: %+v", gs.lastReq)
	}
	if rec := metaRecord(t, sc, "response"); rec["outcome"] != "blocked" {
		t.Fatalf("unexpected metadata: %v", rec)
	}
}

func TestResponseModify(t *testing.T) {
	gs := newGuardrailServer(t, reply(`{"action":"modify","texts":["redacted"]}`))
	action := runResponse(newPolicy(t, responseParams(gs.URL)), shared(), 200,
		[]byte(`{"id":"c1","usage":{"total_tokens":7},"choices":[{"message":{"role":"assistant","content":"secret"}}]}`))
	mods := action.(policy.DownstreamResponseModifications)
	var got map[string]interface{}
	if err := json.Unmarshal(mods.Body, &got); err != nil {
		t.Fatalf("modified body is not JSON: %v", err)
	}
	content := got["choices"].([]interface{})[0].(map[string]interface{})["message"].(map[string]interface{})["content"]
	if content != "redacted" || got["id"] != "c1" || got["usage"].(map[string]interface{})["total_tokens"] != float64(7) {
		t.Fatalf("unexpected body: %s", mods.Body)
	}
}

func TestResponseUpstreamErrorNotChecked(t *testing.T) {
	gs := newGuardrailServer(t, reply(`{"action":"block"}`))
	action := runResponse(newPolicy(t, responseParams(gs.URL)), shared(), 500, []byte(`{"error":"upstream down"}`))
	if mods := action.(policy.DownstreamResponseModifications); mods.StatusCode != nil || mods.Body != nil {
		t.Fatalf("upstream error response must pass unchanged: %+v", mods)
	}
	if gs.calls.Load() != 0 {
		t.Fatalf("guardrail called for an upstream error response")
	}
}

const sseStream = "data: {\"choices\":[{\"delta\":{\"role\":\"assistant\"}}]}\n\n" +
	"data: {\"choices\":[{\"delta\":{\"content\":\"Hello \"}}]}\n\n" +
	"data: {\"choices\":[{\"delta\":{\"content\":\"world\"}}]}\n\n" +
	"data: [DONE]\n\n"

func TestStreamedResponse(t *testing.T) {
	t.Run("reassembled and allowed", func(t *testing.T) {
		gs := newGuardrailServer(t, reply(`{"action":"allow"}`))
		action := runResponse(newPolicy(t, responseParams(gs.URL)), shared(), 200, []byte(sseStream))
		if mods := action.(policy.DownstreamResponseModifications); mods.Body != nil || mods.StatusCode != nil {
			t.Fatalf("allowed stream must pass unchanged: %+v", mods)
		}
		if len(gs.lastReq.Texts) != 1 || gs.lastReq.Texts[0] != "Hello world" {
			t.Fatalf("stream not reassembled: %q", gs.lastReq.Texts)
		}
	})

	t.Run("blocked", func(t *testing.T) {
		gs := newGuardrailServer(t, reply(`{"action":"block"}`))
		action := runResponse(newPolicy(t, responseParams(gs.URL)), shared(), 200, []byte(sseStream))
		if mods := action.(policy.DownstreamResponseModifications); mods.StatusCode == nil || *mods.StatusCode != GuardrailErrorCode {
			t.Fatalf("expected the stream to be blocked: %+v", mods)
		}
	})

	t.Run("modify cannot be applied, so blocks", func(t *testing.T) {
		gs := newGuardrailServer(t, reply(`{"action":"modify","texts":["Hi"]}`))
		sc := shared()
		action := runResponse(newPolicy(t, responseParams(gs.URL)), sc, 200, []byte(sseStream))
		mods := action.(policy.DownstreamResponseModifications)
		if mods.StatusCode == nil || *mods.StatusCode != GuardrailErrorCode {
			t.Fatalf("expected a block, got %+v", mods)
		}
		if bytes.Contains(mods.Body, []byte("Hello world")) {
			t.Fatalf("original stream content leaked into the block body")
		}
		if rec := metaRecord(t, sc, "response"); rec["decision"] != "modify" || rec["outcome"] != "blocked" {
			t.Fatalf("unexpected metadata: %v", rec)
		}
	})

	t.Run("path matches no event is an extraction error", func(t *testing.T) {
		gs := newGuardrailServer(t, reply(`{"action":"allow"}`))
		params := responseParams(gs.URL)
		params["response"] = map[string]interface{}{"streamingJsonPath": "$.delta.text"}
		sc := shared()
		action := runResponse(newPolicy(t, params), sc, 200, []byte(sseStream))
		if mods := action.(policy.DownstreamResponseModifications); mods.StatusCode == nil {
			t.Fatalf("expected fail-closed block: %+v", mods)
		}
		if rec := metaRecord(t, sc, "response"); rec["errorType"] != errKindExtraction {
			t.Fatalf("unexpected metadata: %v", rec)
		}
	})
}

// --- Logging hygiene ---

func TestLogsDoNotExposeSecretsOrContent(t *testing.T) {
	var logs bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })

	const scanned = "my-very-private-prompt-text"
	const serviceSecret = "service-internal-detail"
	replies := []func(http.ResponseWriter, evaluateRequest){
		reply(`{"action":"block","reason":"` + serviceSecret + `"}`),
		reply(`{"action":"modify","texts":["` + serviceSecret + `"]}`),
		reply(`{"action":"bogus","echo":"` + scanned + `"}`),
		func(w http.ResponseWriter, _ evaluateRequest) {
			w.WriteHeader(500)
			_, _ = io.WriteString(w, serviceSecret+" "+scanned)
		},
	}
	for _, mode := range []string{modeEnforce, modeMonitor} {
		for _, r := range replies {
			gs := newGuardrailServer(t, r)
			params := baseParams(gs.URL + "/evaluate?api_key=query-secret")
			params["mode"] = mode
			params["onError"] = "allow"
			runRequest(newPolicy(t, params), shared(), chatRequest(scanned))
		}
	}
	// A transport failure, whose error would otherwise carry the endpoint URL.
	params := baseParams("http://127.0.0.1:1/evaluate?api_key=query-secret")
	runRequest(newPolicy(t, params), shared(), chatRequest(scanned))

	out := logs.String()
	if out == "" {
		t.Fatalf("expected log output")
	}
	for _, secret := range []string{testToken, scanned, serviceSecret, "query-secret"} {
		if strings.Contains(out, secret) {
			t.Fatalf("logs contain %q:\n%s", secret, out)
		}
	}
	if !strings.Contains(out, "requestId=req-123") {
		t.Fatalf("expected the request ID in failure logs:\n%s", out)
	}
}

// --- Malformed SSE ---

const malformedEvent = "data: {\"choices\":[{\"delta\":{\"content\":\"leaky-content\"\n\n"

func TestExtractSSEText_MalformedEvents(t *testing.T) {
	tests := []struct {
		name    string
		payload string
	}{
		{"only a malformed event", malformedEvent},
		{"valid text then a malformed event",
			"data: {\"choices\":[{\"delta\":{\"content\":\"Hello\"}}]}\n\n" + malformedEvent + "data: [DONE]\n\n"},
		{"non-JSON text", "data: leaky-content\n\n"},
		{"JSON that is not an object", "data: \"leaky-content\"\n\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			text, err := extractSSEText([]byte(tt.payload), streamingDefaultJSONPath)
			if err == nil {
				t.Fatalf("expected an extraction error, got text %q", text)
			}
			if text != "" {
				t.Fatalf("no text may be returned with the error, got %q", text)
			}
			if strings.Contains(err.Error(), "leaky-content") {
				t.Fatalf("error exposes event content: %q", err.Error())
			}
		})
	}
}

func TestExtractSSEText_ValidStreams(t *testing.T) {
	tests := []struct {
		name    string
		payload string
		want    string
	}{
		{"text then control events",
			"data: {\"choices\":[{\"delta\":{\"content\":\"Hello \"}}]}\n\n" +
				"data: {\"choices\":[{\"delta\":{\"content\":\"world\"}}]}\n\n" +
				"data: {\"choices\":[{\"delta\":{},\"finish_reason\":\"stop\"}]}\n\n" +
				"data: {\"usage\":{\"total_tokens\":7}}\n\n",
			"Hello world"},
		{"empty data, [DONE], comments, and other fields ignored",
			": keep-alive comment\n" +
				"event: message\n" +
				"id: 1\n" +
				"data:\n\n" +
				"data:   \n\n" +
				"data: {\"choices\":[{\"delta\":{\"content\":\"Hi\"}}]}\r\n\r\n" +
				"data: [DONE]\n\n",
			"Hi"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			text, err := extractSSEText([]byte(tt.payload), streamingDefaultJSONPath)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if text != tt.want {
				t.Fatalf("got %q, want %q", text, tt.want)
			}
		})
	}
}

func TestMalformedStreamedResponse(t *testing.T) {
	stream := []byte("data: {\"choices\":[{\"delta\":{\"content\":\"Hello\"}}]}\n\n" + malformedEvent + "data: [DONE]\n\n")

	t.Run("enforce with onError block rejects", func(t *testing.T) {
		gs := newGuardrailServer(t, reply(`{"action":"allow"}`))
		params := responseParams(gs.URL)
		params["onError"] = "block"
		sc := shared()
		mods := runResponse(newPolicy(t, params), sc, 200, stream).(policy.DownstreamResponseModifications)
		if mods.StatusCode == nil || *mods.StatusCode != GuardrailErrorCode {
			t.Fatalf("expected a 422 block, got %+v", mods)
		}
		if msg := decodeMessage(t, mods.Body); msg["assessments"] != errorReasons[errKindExtraction] {
			t.Fatalf("unexpected message: %v", msg)
		}
		if bytes.Contains(mods.Body, []byte("leaky-content")) || bytes.Contains(mods.Body, []byte("Hello")) {
			t.Fatalf("stream content leaked into the block body: %s", mods.Body)
		}
		rec := metaRecord(t, sc, "response")
		if rec["decision"] != "error" || rec["errorType"] != errKindExtraction || rec["outcome"] != "blocked" {
			t.Fatalf("unexpected metadata: %v", rec)
		}
		if gs.calls.Load() != 0 {
			t.Fatalf("a partially parsed stream must not be sent for checking")
		}
	})

	t.Run("monitor passes unchanged and records the error", func(t *testing.T) {
		gs := newGuardrailServer(t, reply(`{"action":"block"}`))
		params := responseParams(gs.URL)
		params["mode"] = "monitor"
		sc := shared()
		mods := runResponse(newPolicy(t, params), sc, 200, stream).(policy.DownstreamResponseModifications)
		if mods.StatusCode != nil || mods.Body != nil || mods.AnalyticsMetadata != nil {
			t.Fatalf("monitor mode must pass the stream unchanged: %+v", mods)
		}
		rec := metaRecord(t, sc, "response")
		if rec["decision"] != "error" || rec["errorType"] != errKindExtraction || rec["outcome"] != "passed" {
			t.Fatalf("unexpected metadata: %v", rec)
		}
		if gs.calls.Load() != 0 {
			t.Fatalf("a partially parsed stream must not be sent for checking")
		}
	})
}
