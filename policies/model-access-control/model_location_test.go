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

package modelaccesscontrol

import (
	"errors"
	"testing"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

func location(t *testing.T, raw map[string]any) modelLocation {
	t.Helper()
	loc, err := parseModelLocation(raw, true)
	if err != nil {
		t.Fatalf("parseModelLocation() error = %v", err)
	}
	return loc
}

func TestHeaderLocation(t *testing.T) {
	loc := location(t, map[string]any{"location": "header", "identifier": "X-Model"})
	tests := []struct {
		name    string
		headers map[string][]string
		model   string
		found   bool
		err     error
	}{
		{"present", map[string][]string{"x-model": {"gpt-4o"}}, "gpt-4o", true, nil},
		{"absent", nil, "", false, nil},
		{"blank", map[string][]string{"x-model": {"  "}}, "  ", false, nil},
		{"duplicate", map[string][]string{"x-model": {"a", "b"}}, "", false, errAmbiguousModel},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			model, found, err := loc.extractFromRequestLine(policy.NewHeaders(tt.headers), "/chat")
			if model != tt.model || found != tt.found || !errors.Is(err, tt.err) {
				t.Fatalf("extract = %q, %v, %v; want %q, %v, %v", model, found, err, tt.model, tt.found, tt.err)
			}
		})
	}
	headers, path, err := loc.rewriteRequestLine("/chat", "gpt-4o")
	if err != nil || path != nil || headers["x-model"] != "gpt-4o" {
		t.Fatalf("rewrite = %v, %v, %v", headers, path, err)
	}
}

func TestQueryLocation(t *testing.T) {
	loc := location(t, map[string]any{"location": "queryParam", "identifier": "model"})
	tests := []struct {
		name  string
		path  string
		model string
		found bool
		err   error
	}{
		{"present", "/chat?api-version=1&model=gpt-4o", "gpt-4o", true, nil},
		{"encoded", "/chat?model=claude%20sonnet%2Bx", "claude sonnet+x", true, nil},
		{"plus is space", "/chat?model=a+b", "a b", true, nil},
		{"encoded key", "/chat?mod%65l=gpt-4o", "gpt-4o", true, nil},
		{"absent", "/chat?other=1", "", false, nil},
		{"no query", "/chat", "", false, nil},
		{"empty value", "/chat?model=", "", false, nil},
		{"duplicate", "/chat?model=a&model=b", "", false, errAmbiguousModel},
		{"duplicate through encoding", "/chat?model=a&mod%65l=b", "", false, errAmbiguousModel},
		{"bad value encoding", "/chat?model=%zz", "", false, errMalformedModel},
		{"bad key encoding", "/chat?%zz=1&model=a", "", false, errMalformedModel},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			model, found, err := loc.extractFromRequestLine(policy.NewHeaders(nil), tt.path)
			if model != tt.model || found != tt.found || !errors.Is(err, tt.err) {
				t.Fatalf("extract = %q, %v, %v; want %q, %v, %v", model, found, err, tt.model, tt.found, tt.err)
			}
		})
	}

	_, path, err := loc.rewriteRequestLine("/chat?z=%2F&model=old&a=1", "new model/x")
	if err != nil || path == nil {
		t.Fatalf("rewrite error = %v", err)
	}
	if want := "/chat?z=%2F&model=new+model%2Fx&a=1"; *path != want {
		t.Errorf("rewritten path = %q, want %q (order and other escapes kept)", *path, want)
	}
	if _, _, err := loc.rewriteRequestLine("/chat?model=a&model=b", "x"); !errors.Is(err, errAmbiguousModel) {
		t.Errorf("rewrite of a duplicate = %v, want errAmbiguousModel", err)
	}
}

func TestPathLocation(t *testing.T) {
	loc := location(t, map[string]any{"location": "pathParam", "identifier": "/models/([^/]+)/chat"})
	tests := []struct {
		name  string
		path  string
		model string
		found bool
		err   error
	}{
		{"present", "/proxy/models/gpt-4o/chat?x=1", "gpt-4o", true, nil},
		{"encoded", "/proxy/models/claude%3Av1/chat", "claude:v1", true, nil},
		{"absent", "/proxy/health", "", false, nil},
		{"query ignored", "/proxy/health?p=/models/x/chat", "", false, nil},
		{"bad encoding", "/proxy/models/%zz/chat", "", false, errMalformedModel},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			model, found, err := loc.extractFromRequestLine(policy.NewHeaders(nil), tt.path)
			if model != tt.model || found != tt.found || !errors.Is(err, tt.err) {
				t.Fatalf("extract = %q, %v, %v; want %q, %v, %v", model, found, err, tt.model, tt.found, tt.err)
			}
		})
	}

	_, path, err := loc.rewriteRequestLine("/a%2Fb/models/claude%3Av1/chat?model=keep", "anthropic.claude v2")
	if err != nil || path == nil {
		t.Fatalf("rewrite error = %v", err)
	}
	if want := "/a%2Fb/models/anthropic.claude%20v2/chat?model=keep"; *path != want {
		t.Errorf("rewritten path = %q, want %q", *path, want)
	}
	if _, _, err := loc.rewriteRequestLine("/health", "x"); err == nil {
		t.Error("rewrite of a path the expression does not match should fail")
	}
}

func TestPayloadLocation(t *testing.T) {
	loc := location(t, payloadModel())
	tests := []struct {
		name  string
		body  string
		model string
		found bool
		err   error
	}{
		{"present", `{"model":"gpt-4o","messages":[]}`, "gpt-4o", true, nil},
		{"absent", `{"messages":[]}`, "", false, nil},
		{"not string", `{"model":42}`, "", false, nil},
		{"blank", `{"model":"  "}`, "  ", false, nil},
		{"null", `{"model":null}`, "", false, nil},
		{"malformed", `{"model":`, "", false, errMalformedModel},
		{"array", `[{"model":"gpt-4o"}]`, "", false, errMalformedModel},
		{"trailing data", `{"model":"a"}{"model":"b"}`, "", false, errMalformedModel},
		{"duplicate key", `{"model":"gpt-4o","model":"other"}`, "", false, errAmbiguousModel},
		{"duplicate elsewhere is fine", `{"model":"gpt-4o","meta":{"k":1,"k":2}}`, "gpt-4o", true, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload, err := loc.decodePayload([]byte(tt.body))
			if !errors.Is(err, tt.err) {
				t.Fatalf("decode error = %v, want %v", err, tt.err)
			}
			if err != nil {
				return
			}
			model, found := loc.extractFromPayload(payload)
			if found != tt.found || (found && model != tt.model) {
				t.Fatalf("extract = %q, %v; want %q, %v", model, found, tt.model, tt.found)
			}
		})
	}
}

func TestPayloadNestedPathDuplicates(t *testing.T) {
	loc := location(t, map[string]any{"location": "payload", "identifier": "$.request.items[1].model"})
	if _, err := loc.decodePayload([]byte(`{"request":{"items":[{"model":"a","model":"b"},{"model":"c"}]}}`)); err != nil {
		t.Errorf("duplicate off the path (items[0]) = %v, want nil", err)
	}
	if _, err := loc.decodePayload([]byte(`{"request":{"items":[{},{"model":"c","model":"d"}]}}`)); !errors.Is(err, errAmbiguousModel) {
		t.Errorf("duplicate on the path = %v, want errAmbiguousModel", err)
	}
	if _, err := loc.decodePayload([]byte(`{"request":{"items":[]},"request":{}}`)); !errors.Is(err, errAmbiguousModel) {
		t.Errorf("duplicate parent key = %v, want errAmbiguousModel", err)
	}
	payload, err := loc.decodePayload([]byte(`{"request":{"items":[{},{"model":"c"}]}}`))
	if err != nil {
		t.Fatal(err)
	}
	if model, found := loc.extractFromPayload(payload); !found || model != "c" {
		t.Errorf("extract = %q, %v", model, found)
	}
}

func TestPayloadRewriteKeepsNumbersAndText(t *testing.T) {
	loc := location(t, payloadModel())
	payload, err := loc.decodePayload([]byte(`{"model":"old","temperature":0.70,"seed":12345678901234567890,"messages":[{"role":"user","content":"<b>&</b>"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	body, err := loc.rewritePayload(payload, "gpt-4o")
	if err != nil {
		t.Fatal(err)
	}
	want := `{"messages":[{"content":"<b>&</b>","role":"user"}],"model":"gpt-4o","seed":12345678901234567890,"temperature":0.70}`
	if string(body) != want {
		t.Errorf("rewritten body = %s\nwant %s", body, want)
	}
}

// The awsbedrock template's expression runs on a path whose %2F stays encoded, so an
// inference-profile ARN is read whole, as Bedrock reads it, and rewritten whole.
func TestPathLocation_EncodedSlashInModel(t *testing.T) {
	loc := location(t, map[string]any{"location": "pathParam", "identifier": `model/([A-Za-z0-9.:%-]+)/`})
	raw := "/model/arn%3Aaws%3Abedrock%3Aus-east-1%3A111122223333%3Aapplication-inference-profile%2Fabc123/converse"
	model, found, err := loc.extractFromRequestLine(policy.NewHeaders(nil), raw)
	want := "arn:aws:bedrock:us-east-1:111122223333:application-inference-profile/abc123"
	if err != nil || !found || model != want {
		t.Fatalf("extract = %q, %v, %v; want %q", model, found, err, want)
	}
	_, path, err := loc.rewriteRequestLine(raw, "us.amazon.nova-lite-v1:0")
	if err != nil || path == nil || *path != "/model/us.amazon.nova-lite-v1:0/converse" {
		t.Fatalf("rewrite = %v, %v", path, err)
	}
	if model, _, _ := loc.extractFromRequestLine(policy.NewHeaders(nil), "/model/a%252Fb/converse"); model != "a%2Fb" {
		t.Errorf("double-encoded model = %q, want a%%2Fb (decoded once)", model)
	}

	// An expression that cannot read past an encoded slash must not check a prefix.
	narrow := location(t, map[string]any{"location": "pathParam", "identifier": `model/([A-Za-z0-9.:-]+)`})
	for _, p := range []string{
		"/model/arn%3Aaws%3Abedrock%3Ax%3Ainference-profile%2Fabc/converse",
		"/model/abc%25def/converse",
	} {
		if _, _, err := narrow.extractFromRequestLine(policy.NewHeaders(nil), p); !errors.Is(err, errMalformedModel) {
			t.Errorf("%s: err = %v, want errMalformedModel", p, err)
		}
	}
}
