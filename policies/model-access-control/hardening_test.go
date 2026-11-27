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
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/url"
	"strings"
	"testing"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

// The tests in this file try to get a model past the policy that an upstream would
// read differently: every request either reaches the upstream with a model the rule
// permits, or is rejected. "forward" means the request passes the policy unchanged.

const forward = 0

// strictSkip permits gpt-4o only and skips requests without a model, the attachment
// that is easiest to slip past: anything the policy does not recognise as a model
// request is forwarded.
func strictSkip(t *testing.T, location map[string]any) *Policy {
	t.Helper()
	return mustPolicy(t, map[string]any{
		"requestModel": location,
		"access":       map[string]any{"mode": "allow", "models": []any{"gpt-4o"}, "onMissingModel": "skip"},
	})
}

// denyList denies gpt-4-32k and permits every other model.
func denyList(t *testing.T, location map[string]any) *Policy {
	t.Helper()
	return mustPolicy(t, map[string]any{
		"requestModel": location,
		"access":       map[string]any{"mode": "deny", "models": []any{"gpt-4-32k"}},
	})
}

// wantStatus checks an action: forward means unchanged, anything else an immediate
// response with that status, a declared fault and one of the policy's fixed bodies.
func wantStatus(t *testing.T, action any, status int) {
	t.Helper()
	if status == forward {
		switch a := action.(type) {
		case policy.UpstreamRequestModifications:
			if a.Body != nil {
				t.Errorf("body was rewritten: %q", a.Body)
			}
		case policy.UpstreamRequestHeaderModifications:
			if a.Path != nil || len(a.HeadersToSet) > 0 {
				t.Errorf("request was rewritten: path %v headers %v", a.Path, a.HeadersToSet)
			}
		default:
			t.Fatalf("action = %T (%+v), want the request forwarded", action, action)
		}
		return
	}
	resp := immediate(t, action)
	if resp.StatusCode != status {
		t.Fatalf("status = %d (%s), want %d", resp.StatusCode, resp.Fault.Description, status)
	}
	assertFixedFault(t, resp)
}

// assertFixedFault checks what holds for every rejection: a declared fault, and a body
// that is one of the fixed bodies, so nothing from the request is echoed.
func assertFixedFault(t *testing.T, resp policy.ImmediateResponse) {
	t.Helper()
	want := map[int][]byte{statusModelNotFound: bodyModelNotFound, statusInvalidModel: bodyInvalidModel, statusRoutingError: bodyRoutingError}[resp.StatusCode]
	if want == nil {
		t.Fatalf("unexpected status %d", resp.StatusCode)
	}
	if string(resp.Body) != string(want) {
		t.Errorf("body = %s, want %s", resp.Body, want)
	}
	if !resp.IsFault || resp.Fault == nil || resp.Fault.Code == "" || resp.Fault.Type == "" || resp.Fault.Message == "" {
		t.Errorf("fault not declared: IsFault %v Fault %+v", resp.IsFault, resp.Fault)
	}
	if resp.Fault != nil && (resp.Fault.Policy != "" || resp.Fault.Direction != policy.DirectionRequest) {
		t.Errorf("fault Policy %q Direction %q", resp.Fault.Policy, resp.Fault.Direction)
	}
}

func onHeaders(p *Policy, ctx *policy.RequestHeaderContext) policy.RequestHeaderAction {
	return p.OnRequestHeaders(context.Background(), ctx, nil)
}

// ─── JSON bodies ─────────────────────────────────────────────────────────────

func TestHardening_JSONBodies(t *testing.T) {
	deep := `{"model":"gpt-4o","x":` + strings.Repeat("[", 20000) + strings.Repeat("]", 20000) + `}`
	tests := []struct {
		name   string
		ctype  string
		body   string
		status int
	}{
		{"key written with a unicode escape", "application/json", `{"\u006dodel":"llama-3"}`, 404},
		{"same key twice, once escaped", "application/json", `{"model":"gpt-4o","\u006dodel":"llama-3"}`, 400},
		{"case-variant key, escaped", "application/json", `{"model":"gpt-4o","\u004dODEL":"llama-3"}`, 400},
		{"case-variant key next to null", "application/json", `{"model":null,"MODEL":"llama-3"}`, 400},
		{"only a case-variant key", "application/json", `{"Model":"llama-3"}`, 400},
		{"value written with a unicode escape", "application/json", `{"model":"gpt-4\u006f"}`, forward},
		{"top-level array", "application/json", `[{"model":"llama-3"}]`, 400},
		{"two JSON documents", "application/json", `{"model":"gpt-4o"}{"model":"llama-3"}`, 400},
		{"comment", "application/json", `{"model":"gpt-4o" /* "model":"llama-3" */}`, 400},
		{"single quotes", "application/json", `{'model':'llama-3'}`, 400},
		{"NUL inside the model", "application/json", `{"model":"gpt-4o\u0000"}`, 400},
		{"escape inside the model", "application/json", `{"model":"gpt-4o\u001b"}`, 400},
		{"invalid UTF-8 inside the model", "application/json", "{\"model\":\"gpt-4o\xff\"}", 400},
		{"model is an array", "application/json", `{"model":["gpt-4o"]}`, 400},
		{"model is an object", "application/json", `{"model":{"id":"gpt-4o"}}`, 400},
		{"model is a boolean", "application/json", `{"model":true}`, 400},
		{"empty object", "application/json", `{}`, 400},
		{"nesting deeper than any decoder allows", "application/json", deep, 400},
		{"model with surrounding spaces", "application/json", `{"model":"  gpt-4o  "}`, forward},
		{"model in upper case", "application/json", `{"model":"GPT-4O"}`, forward},
		// Encodings a lenient upstream detects by the first bytes.
		{"UTF-16LE with a byte order mark", "application/octet-stream", "\xff\xfe{\x00\"\x00m\x00\"\x00}\x00", 400},
		{"UTF-16BE with a byte order mark", "application/octet-stream", "\xfe\xff\x00{\x00\"\x00m\x00\"\x00}", 400},
		{"UTF-16BE without a byte order mark", "application/octet-stream", "\x00{\x00\"\x00m\x00\"\x00}", 400},
		{"UTF-32LE with a byte order mark", "application/octet-stream", "\xff\xfe\x00\x00{\x00\x00\x00", 400},
		{"NUL bytes before JSON", "", "\x00\x00{\"model\":\"llama-3\"}", 400},
		{"JSON without a content type", "", `{"model":"llama-3"}`, 404},
		{"JSON as text/plain", "text/plain", `{"model":"llama-3"}`, 404},
		{"JSON as application/vnd.api+json", "application/vnd.api+json", `{"model":"llama-3"}`, 404},
		{"two content types", "", `{"model":"llama-3"}`, 404},
		// Not JSON and not a form: forwarded under skip, unless it is text.
		{"binary upload", "application/octet-stream", "\x89PNG\r\n\x1a\n", forward},
		{"text that is not JSON", "text/plain", "model: llama-3", 400},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := bodyContext("POST", tt.ctype, tt.body)
			if tt.name == "two content types" {
				ctx.Headers = policy.NewHeaders(map[string][]string{"content-type": {"application/octet-stream", "application/json"}})
			}
			wantStatus(t, strictSkip(t, payloadModel()).OnRequestBody(context.Background(), ctx, nil), tt.status)
		})
	}
}

func TestHardening_NestedJSONPath(t *testing.T) {
	p := strictSkip(t, map[string]any{"location": "payload", "identifier": "$.request.items[1].model"})
	tests := []struct {
		name, body string
		status     int
	}{
		{"permitted", `{"request":{"items":[{"model":"llama-3"},{"model":"gpt-4o"}]}}`, forward},
		{"denied", `{"request":{"items":[{"model":"gpt-4o"},{"model":"llama-3"}]}}`, 404},
		{"case-variant parent", `{"request":{"items":[{},{"model":"gpt-4o"}]},"REQUEST":{"items":[{},{"model":"llama-3"}]}}`, 400},
		{"duplicate parent", `{"request":{"items":[{},{"model":"gpt-4o"}]},"request":{"items":[{},{"model":"llama-3"}]}}`, 400},
		{"duplicate key in the indexed object", `{"request":{"items":[{},{"model":"gpt-4o","model":"llama-3"}]}}`, 400},
		{"index out of range", `{"request":{"items":[{"model":"gpt-4o"}]}}`, 400},
		{"parent is not an object", `{"request":"gpt-4o"}`, 400},
		{"duplicates off the path are ignored", `{"request":{"items":[{"x":1,"x":2},{"model":"gpt-4o"}]},"y":{"z":1,"z":2}}`, forward},
		// Any repeated key in an object on the path is refused, not only the path's own.
		{"duplicate sibling of the path", `{"request":{"items":[{},{"model":"gpt-4o"}]},"y":1,"y":2}`, 400},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wantStatus(t, onBody(t, p, jsonBody(tt.body)), tt.status)
		})
	}
}

// A deny list permits everything it does not name, so a variant of a denied name must
// never read as "another model".
func TestHardening_DenyListVariants(t *testing.T) {
	p := denyList(t, payloadModel())
	tests := []struct {
		model  string
		status int
	}{
		{"gpt-4-32k", 404},
		{"GPT-4-32K", 404},
		{"  gpt-4-32k\t", 404},
		{" gpt-4-32k ", 404}, // non-breaking spaces are trimmed like other spaces
		{"gpt-4-32k\u0000", 400},
		{"gpt-4-32k\r\n", 404}, // trailing CR LF is whitespace and is trimmed
		{"gpt-4-32k\u0085", 404},
		{"gpt-4-32k\u0007", 400},
		{"gpt-4-32k�", 400},
		{"gpt-4-32k-turbo", forward},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("%q", tt.model), func(t *testing.T) {
			model, err := json.Marshal(tt.model)
			if err != nil {
				t.Fatal(err)
			}
			wantStatus(t, onBody(t, p, jsonBody(`{"model":`+string(model)+`}`)), tt.status)
		})
	}
}

// ─── Form bodies ─────────────────────────────────────────────────────────────

func TestHardening_URLEncodedForms(t *testing.T) {
	tests := []struct {
		name, ctype, body string
		status            int
	}{
		{"permitted", "application/x-www-form-urlencoded", "model=gpt-4o&file=x", forward},
		{"denied", "application/x-www-form-urlencoded", "model=llama-3", 404},
		{"content type in upper case with a charset", "APPLICATION/X-WWW-FORM-URLENCODED; charset=UTF-8", "model=llama-3", 404},
		{"key written with escapes", "application/x-www-form-urlencoded", "mod%65l=llama-3", 404},
		{"value written with escapes", "application/x-www-form-urlencoded", "model=gpt%2D4o", forward},
		{"plus is a space", "application/x-www-form-urlencoded", "model=+gpt-4o+", forward},
		{"only a case-variant key", "application/x-www-form-urlencoded", "MODEL=llama-3", 400},
		{"case-variant key beside the key", "application/x-www-form-urlencoded", "model=gpt-4o&Model=llama-3", 400},
		{"semicolon separator", "application/x-www-form-urlencoded", "x=1;model=llama-3", 400},
		{"semicolon inside the value", "application/x-www-form-urlencoded", "model=gpt-4o;model=llama-3", 400},
		{"array syntax", "application/x-www-form-urlencoded", "model[]=llama-3", 400},
		{"array syntax beside the key", "application/x-www-form-urlencoded", "model=gpt-4o&model[0]=llama-3", 400},
		{"space around the key", "application/x-www-form-urlencoded", "+model=llama-3", 400},
		{"key twice", "application/x-www-form-urlencoded", "model=gpt-4o&model=gpt-4o", 400},
		{"key without a value", "application/x-www-form-urlencoded", "model&x=1", forward},
		{"undecodable value", "application/x-www-form-urlencoded", "model=%zz", 400},
		{"NUL in the value", "application/x-www-form-urlencoded", "model=gpt-4o%00", 400},
		{"encoded ampersand stays in the value", "application/x-www-form-urlencoded", "model=gpt-4o%26model%3Dllama-3", 404},
		{"no model field", "application/x-www-form-urlencoded", "purpose=batch", forward},
		{"similar key is not the model", "application/x-www-form-urlencoded", "models=llama-3&model_name=llama-3", forward},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wantStatus(t, onBody(t, strictSkip(t, payloadModel()), bodyContext("POST", tt.ctype, tt.body)), tt.status)
		})
	}
}

func TestHardening_MultipartForms(t *testing.T) {
	mp := "multipart/form-data; boundary=b"
	part := func(headers, value string) string { return "--b\r\n" + headers + "\r\n\r\n" + value + "\r\n" }
	named := func(name, value string) string {
		return part(`Content-Disposition: form-data; name="`+name+`"`, value)
	}
	end := "--b--\r\n"
	tests := []struct {
		name, ctype, body string
		status            int
	}{
		{"permitted", mp, named("model", "gpt-4o") + named("file", "x") + end, forward},
		{"denied", mp, named("model", "llama-3") + end, 404},
		{"content type in upper case", "MULTIPART/FORM-DATA; BOUNDARY=b", named("model", "llama-3") + end, 404},
		{"multipart/mixed", "multipart/mixed; boundary=b", named("model", "llama-3") + end, 404},
		{"quoted boundary", `multipart/form-data; boundary="b"`, named("model", "llama-3") + end, 404},
		{"unquoted name", mp, part("Content-Disposition: form-data; name=model", "llama-3") + end, 404},
		{"header names in lower case", mp, part(`content-disposition: form-data; name="model"`, "llama-3") + end, 404},
		{"model sent as a file", mp, part(`Content-Disposition: form-data; name="model"; filename="m.txt"`, "llama-3") + end, 404},
		{"LF line endings", mp, "--b\nContent-Disposition: form-data; name=\"model\"\n\nllama-3\n--b--\n", 404},
		{"model part with a content type", mp, part("Content-Disposition: form-data; name=\"model\"\r\nContent-Type: text/plain", "llama-3") + end, 404},
		{"model in the preamble is not a part", mp, "Content-Disposition: form-data; name=\"model\"\r\n\r\nllama-3\r\n" + named("model", "gpt-4o") + end, forward},
		{"model in the epilogue is not a part", mp, named("model", "gpt-4o") + end + named("model", "llama-3"), forward},
		{"only a case-variant name", mp, named("MODEL", "llama-3") + end, 400},
		{"case-variant name beside the name", mp, named("model", "gpt-4o") + named("Model", "llama-3") + end, 400},
		{"space inside the quoted name", mp, named(" model", "llama-3") + end, 400},
		{"name twice", mp, named("model", "gpt-4o") + named("model", "gpt-4o") + end, 400},
		{"base64 transfer encoding", mp, part("Content-Disposition: form-data; name=\"model\"\r\nContent-Transfer-Encoding: base64", "bGxhbWEtMw==") + end, 400},
		{"repeated boundary parameter", "multipart/form-data; boundary=b; boundary=c", named("model", "llama-3") + end, 400},
		{"no boundary parameter", "multipart/form-data", named("model", "llama-3") + end, 400},
		{"boundary that is not in the body", "multipart/form-data; boundary=zzz", named("model", "llama-3") + end, 400},
		{"no part at all", mp, end, 400},
		{"empty body under multipart", mp, " ", forward},
		{"truncated before the closing boundary", mp, part(`Content-Disposition: form-data; name="model"`, "llama-3"), 400},
		{"not form-data", mp, part(`Content-Disposition: attachment; name="model"`, "llama-3") + end, 400},
		{"unterminated quote in the name", mp, part(`Content-Disposition: form-data; name="model`, "llama-3") + end, 400},
		{"model longer than the limit", mp, named("model", strings.Repeat("a", maxModelLength+1)) + end, 400},
		{"NUL in the model", mp, named("model", "gpt-4o\x00") + end, 400},
		{"no model field", mp, named("purpose", "batch") + part(`Content-Disposition: form-data; name="file"; filename="a.jsonl"`, "{\"model\":\"llama-3\"}") + end, forward},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wantStatus(t, onBody(t, strictSkip(t, payloadModel()), bodyContext("POST", tt.ctype, tt.body)), tt.status)
		})
	}
}

// A file part is copied byte for byte when the model part is rewritten: binary data,
// CR LF inside the content and a fake boundary line without its CR LF all survive.
func TestHardening_MultipartRewriteKeepsOtherParts(t *testing.T) {
	p := mustPolicy(t, map[string]any{
		"requestModel": payloadModel(),
		"access":       allowOnly("whisper-1"),
		"fallback":     map[string]any{"mappingPatterns": []any{literalRule("whisper-large", "whisper-1", "")}},
	})
	file := "\x00\x01\xff\r\nline two\r\n-b not a boundary\n--bb\r\n"
	body := "--b\r\nContent-Disposition: form-data; name=\"file\"; filename=\"a.wav\"\r\nContent-Type: audio/wav\r\n\r\n" + file + "\r\n" +
		"--b\r\nContent-Disposition: form-data; name=\"model\"\r\n\r\nwhisper-large\r\n--b--\r\n"
	got := string(bodyMods(t, onBody(t, p, bodyContext("POST", "multipart/form-data; boundary=b", body))).Body)
	if !strings.Contains(got, "\r\n\r\n"+file+"\r\n--b\r\n") {
		t.Errorf("file part changed: %q", got)
	}
	if !strings.Contains(got, "\r\n\r\nwhisper-1\r\n--b--") || strings.Contains(got, "whisper-large") {
		t.Errorf("model part not rewritten: %q", got)
	}
}

// ─── Request line ────────────────────────────────────────────────────────────

func TestHardening_QueryParameter(t *testing.T) {
	tests := []struct {
		name, method, query string
		status              int
	}{
		{"permitted", "POST", "model=gpt-4o&api-version=1", forward},
		{"denied", "POST", "model=llama-3", 404},
		{"only a case-variant key", "GET", "Model=llama-3", 400},
		{"case-variant key beside the key", "POST", "model=gpt-4o&MODEL=llama-3", 400},
		{"semicolon separator", "POST", "model=gpt-4o;model=llama-3", 400},
		{"array syntax", "GET", "model[]=llama-3", 400},
		{"key written with escapes", "POST", "mod%65l=llama-3", 404},
		{"encoded ampersand stays in the value", "POST", "model=gpt-4o%26model%3Dllama-3", 404},
		{"undecodable value is never skipped", "GET", "model=llama-3%zz", 400},
		{"undecodable key is never skipped", "GET", "x%zz=1", 400},
		{"NUL in the value", "POST", "model=gpt-4o%00", 400},
		{"empty value is no model", "GET", "model=", forward},
		{"no query under skip", "GET", "", forward},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := "/proxy/chat/completions"
			if tt.query != "" {
				path += "?" + tt.query
			}
			wantStatus(t, onHeaders(strictSkip(t, queryModel()), headerContext(tt.method, path, nil)), tt.status)
		})
	}
}

func TestHardening_PathParameter(t *testing.T) {
	tests := []struct {
		name, method, path string
		status             int
	}{
		{"permitted", "POST", "/proxy/models/gpt-4o/chat", forward},
		{"denied", "POST", "/proxy/models/llama-3/chat", 404},
		{"model written with escapes", "POST", "/proxy/models/gpt%2D4o/chat", forward},
		{"two model segments", "POST", "/proxy/models/gpt-4o/chat/models/llama-3/chat", 400},
		{"dot segments after the model", "POST", "/proxy/models/gpt-4o/chat/../../llama-3/chat", 400},
		{"encoded dot segments", "POST", "/proxy/models/gpt-4o/chat/%2e%2e/%2E%2E/llama-3/chat", 400},
		{"dot segments behind an encoded slash", "POST", "/proxy/models/gpt-4o/chat/x%2F..%2F..%2F..%2Fmodels%2Fllama-3%2Fchat", 400},
		{"single dot segment", "POST", "/proxy/./models/gpt-4o/chat", 400},
		{"dots inside a model are fine", "POST", "/proxy/models/gpt-4o..x/chat", 404},
		{"encoded slash inside the model", "POST", "/proxy/models/gpt-4o%2Fx/chat", 404},
		{"undecodable escape is never skipped", "GET", "/proxy/models/gpt-4o/chat/%zz", 400},
		{"NUL in the model", "POST", "/proxy/models/gpt-4o%00/chat", 400},
		{"other route under skip", "GET", "/proxy/files", forward},
		{"model hidden behind encoded slashes", "GET", "/proxy/models%2Fllama-3%2Fchat", 400},
		{"second model behind encoded slashes", "POST", "/proxy/models/gpt-4o/chat%2Fmodels%2Fllama-3%2Fchat", 400},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wantStatus(t, onHeaders(strictSkip(t, pathModel()), headerContext(tt.method, tt.path, nil)), tt.status)
		})
	}
}

func TestHardening_HeaderValue(t *testing.T) {
	tests := []struct {
		name    string
		method  string
		headers map[string][]string
		status  int
	}{
		{"permitted", "POST", map[string][]string{"x-model": {"gpt-4o"}}, forward},
		{"denied", "POST", map[string][]string{"x-model": {"llama-3"}}, 404},
		{"two headers", "POST", map[string][]string{"x-model": {"gpt-4o", "llama-3"}}, 400},
		{"two models joined with a comma", "POST", map[string][]string{"x-model": {"gpt-4o, llama-3"}}, 400},
		{"joined headers are never skipped", "GET", map[string][]string{"x-model": {"gpt-4o,llama-3"}}, 400},
		{"control character", "POST", map[string][]string{"x-model": {"gpt-4o\x01"}}, 400},
		{"empty header under skip", "GET", map[string][]string{"x-model": {" "}}, forward},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wantStatus(t, onHeaders(strictSkip(t, headerModel()), headerContext(tt.method, "/proxy/chat", tt.headers)), tt.status)
		})
	}
	// A deny list cannot be passed with a joined value either.
	wantStatus(t, onHeaders(denyList(t, headerModel()), headerContext("POST", "/proxy/chat", map[string][]string{"x-model": {"gpt-4o,gpt-4-32k"}})), 400)
}

// ─── Fallback targets ────────────────────────────────────────────────────────

// Whatever the fallback target, the upstream reads exactly that model, and nothing
// else in the request changes.
func TestHardening_RewrittenTargetsReadBackExactly(t *testing.T) {
	for _, target := range []string{"gpt-4o", "a b", "a&b=c", "a/b", "a?b#c", "é-模型", "arn:aws:bedrock:us-east-1:1:inference-profile/us.x", "100%", "<script>"} {
		t.Run(target, func(t *testing.T) {
			cfg := func(location map[string]any) *Policy {
				return mustPolicy(t, map[string]any{
					"requestModel": location,
					"access":       allowOnly("x"),
					"fallback":     map[string]any{"mappingPatterns": []any{literalRule("old", target, "")}},
				})
			}

			body := bodyMods(t, onBody(t, cfg(payloadModel()), jsonBody(`{"model":"old","n":1.50}`))).Body
			if got := bodyModel(t, body); got != target || !strings.Contains(string(body), `"n":1.50`) {
				t.Errorf("payload = %s", body)
			}

			form := string(bodyMods(t, onBody(t, cfg(payloadModel()), bodyContext("POST", "application/x-www-form-urlencoded", "a=%2F&model=old&z=1"))).Body)
			if values, err := url.ParseQuery(form); err != nil || values.Get("model") != target || values.Get("a") != "/" || !strings.HasPrefix(form, "a=%2F&") {
				t.Errorf("form = %q (%v)", form, err)
			}

			query := onHeaders(cfg(queryModel()), headerContext("POST", "/p/chat?a=%2F&model=old&z=1", nil)).(policy.UpstreamRequestHeaderModifications)
			raw := strings.SplitN(*query.Path, "?", 2)[1]
			if values, err := url.ParseQuery(raw); err != nil || values.Get("model") != target || !strings.HasPrefix(raw, "a=%2F&") {
				t.Errorf("query = %q (%v)", raw, err)
			}

			path := onHeaders(cfg(pathModel()), headerContext("POST", "/p/models/old/chat?x=1", nil)).(policy.UpstreamRequestHeaderModifications)
			segments := strings.Split(strings.SplitN(*path.Path, "?", 2)[0], "/")
			if got, err := url.PathUnescape(segments[3]); err != nil || got != target || len(segments) != 5 || !strings.HasSuffix(*path.Path, "/chat?x=1") {
				t.Errorf("path = %q", *path.Path)
			}
		})
	}
}

// A capture fallback cannot turn a client-chosen value into a dot segment or a
// control character in the rewritten request.
func TestHardening_CaptureTargetsCannotInjectIntoThePath(t *testing.T) {
	p := mustPolicy(t, map[string]any{
		"requestModel": pathModel(),
		"access":       map[string]any{"mode": "deny", "models": []any{"x"}, "modelPatterns": []any{`legacy-.*`}},
		"fallback":     map[string]any{"mappingPatterns": []any{patternRule(`legacy-(.*)`, "$1", "")}},
	})
	resp := immediate(t, onHeaders(p, headerContext("POST", "/p/models/legacy-../chat", nil)))
	if resp.StatusCode != 500 {
		t.Errorf("status = %d, want the rewrite refused", resp.StatusCode)
	}
	resp = immediate(t, onHeaders(p, headerContext("POST", "/p/models/legacy-%2e/chat", nil)))
	if resp.StatusCode != 500 {
		t.Errorf("status = %d, want the rewrite refused", resp.StatusCode)
	}
	// Dot segments hidden behind an encoded slash are refused before any rewrite.
	wantStatus(t, onHeaders(p, headerContext("POST", "/p/models/legacy-a%2F..%2Fb/chat", nil)), 400)
	mods := onHeaders(p, headerContext("POST", "/p/models/legacy-a%2Fb/chat", nil)).(policy.UpstreamRequestHeaderModifications)
	if *mods.Path != "/p/models/a%2Fb/chat" {
		t.Errorf("path = %q, want the slash kept escaped", *mods.Path)
	}
}

// Bedrock model IDs are ARNs with an encoded slash, and some contain "model/" themselves.
// Each is still one model, read whole.
func TestHardening_BedrockARNsAreOneModel(t *testing.T) {
	bedrock := map[string]any{"location": "pathParam", "identifier": `model/([A-Za-z0-9.:%-]+)/`}
	for _, arn := range []string{
		"arn:aws:bedrock:us-east-1:123456789012:custom-model/amazon.titan/abc123",
		"arn:aws:bedrock:us-east-1:123456789012:provisioned-model/abc123",
		"arn:aws:bedrock:us-east-1:123456789012:imported-model/abc123",
		"arn:aws:bedrock:us-east-1:123456789012:application-inference-profile/abc123",
		"us.anthropic.claude-3-5-sonnet-20241022-v2:0",
	} {
		t.Run(arn, func(t *testing.T) {
			p := mustPolicy(t, map[string]any{"requestModel": bedrock, "access": allowOnly(arn)})
			path := "/proxy/model/" + url.PathEscape(arn) + "/converse"
			wantStatus(t, onHeaders(p, headerContext("POST", path, nil)), forward)
			model, found, err := p.cfg.requestModel.extractFromRequestLine(policy.NewHeaders(nil), path)
			if err != nil || !found || model != arn {
				t.Errorf("read %q (found %v, err %v), want the whole ARN", model, found, err)
			}
		})
	}
}

// A capture fallback cannot write the multipart boundary into the model part, which
// would end the part or the form early for the upstream.
func TestHardening_CaptureTargetCannotForgeAMultipartBoundary(t *testing.T) {
	p := mustPolicy(t, map[string]any{
		"requestModel": payloadModel(),
		"access":       map[string]any{"mode": "deny", "models": []any{"x"}, "modelPatterns": []any{`legacy-.*`}},
		"fallback":     map[string]any{"mappingPatterns": []any{patternRule(`legacy-(.*)`, "$1", "")}},
	})
	mp := "multipart/form-data; boundary=b"
	for _, model := range []string{"legacy---b", "legacy---b--", "legacy-x--b"} {
		body := "--b\r\nContent-Disposition: form-data; name=\"model\"\r\n\r\n" + model + "\r\n--b--\r\n"
		wantStatus(t, onBody(t, p, bodyContext("POST", mp, body)), 500)
	}
	body := "--b\r\nContent-Disposition: form-data; name=\"model\"\r\n\r\nlegacy-gpt-4o\r\n--b--\r\n"
	if got := string(bodyMods(t, onBody(t, p, bodyContext("POST", mp, body))).Body); !strings.Contains(got, "\r\n\r\ngpt-4o\r\n--b--") {
		t.Errorf("rewritten = %q", got)
	}
}

// TestFallbackTargetIsReadBackExactly writes each fallback target into every model
// location and reads it back with a standard parser. Each case states its outcome:
// a configuration error, a status in a location, or else the exact target read back.
// The targets include inputs that once broke a location ("$$", "$0", a lone invalid
// byte, the multipart boundary, a 4 KB name).
func TestFallbackTargetIsReadBackExactly(t *testing.T) {
	tests := []struct {
		target    string
		configErr bool
		want      string         // the model read back, when the rewrite succeeds
		status    map[string]int // locations where the request is rejected instead
	}{
		{target: "gpt-4o", want: "gpt-4o"},
		{target: "a b", want: "a b"},
		{target: "a&b=c;d", want: "a&b=c;d"},
		{target: "a/b", want: "a/b"},
		{target: "..", want: "..", status: map[string]int{"path": statusRoutingError}},
		{target: "100%", want: "100%"},
		{target: "é", want: "é"},
		{target: "a,b", want: "a,b", status: map[string]int{"header": statusRoutingError}},
		{target: "<x>", want: "<x>"},
		{target: "$$", want: "$"}, // "$$" is a literal dollar, not a capture reference
		// "$0" inserts the client's own model, which must pass the access rule and does not.
		{target: "$0", status: map[string]int{
			"payload": statusModelNotFound, "form": statusModelNotFound, "multipart": statusModelNotFound,
			"query": statusModelNotFound, "path": statusModelNotFound, "header": statusModelNotFound,
		}},
		{target: "\xc5", configErr: true},
		{target: "--b", want: "--b", status: map[string]int{"multipart": statusRoutingError}},
		{target: "00" + strings.Repeat("R", 4070) + "000000 " + strings.Repeat("!", 15) + "0" + strings.Repeat("!", 6), configErr: true},
	}
	for _, tt := range tests {
		policyFor := func(location map[string]any) (*Policy, error) {
			p, err := GetPolicy(policy.PolicyMetadata{}, map[string]any{
				"requestModel": location,
				"access":       map[string]any{"mode": "allow", "models": []any{"x"}},
				"fallback":     map[string]any{"mappingPatterns": []any{map[string]any{"fromPattern": "old", "to": tt.target}}},
			})
			if err != nil {
				return nil, err
			}
			return p.(*Policy), nil
		}
		p, err := policyFor(payloadModel())
		if tt.configErr {
			if err == nil {
				t.Errorf("target %q: configuration accepted, want an error", tt.target)
			}
			continue
		}
		if err != nil {
			t.Errorf("target %q: configuration error %v", tt.target, err)
			continue
		}
		readBack := func(location string, action any, got func() []string) {
			t.Helper()
			wantStatus, rejected := tt.status[location]
			if resp, ok := action.(policy.ImmediateResponse); ok {
				if !rejected || resp.StatusCode != wantStatus {
					t.Errorf("target %q, %s: status %d, want %d", tt.target, location, resp.StatusCode, wantStatus)
				}
				return
			}
			if rejected {
				t.Errorf("target %q, %s: forwarded, want status %d", tt.target, location, wantStatus)
				return
			}
			if models := got(); len(models) != 1 || models[0] != tt.want {
				t.Errorf("target %q, %s: upstream reads %q, want %q", tt.target, location, models, tt.want)
			}
		}

		action := p.OnRequestBody(context.Background(), jsonBody(`{"model":"old"}`), nil)
		readBack("payload", action, func() []string {
			var body map[string]any
			if err := json.Unmarshal(action.(policy.UpstreamRequestModifications).Body, &body); err != nil {
				return nil
			}
			m, _ := body["model"].(string)
			return []string{m}
		})

		action = p.OnRequestBody(context.Background(), bodyContext("POST", "application/x-www-form-urlencoded", "a=1&model=old"), nil)
		readBack("form", action, func() []string {
			values, _ := url.ParseQuery(string(action.(policy.UpstreamRequestModifications).Body))
			return values["model"]
		})

		action = p.OnRequestBody(context.Background(), bodyContext("POST", "multipart/form-data; boundary=b", "--b\r\nContent-Disposition: form-data; name=\"model\"\r\n\r\nold\r\n--b--\r\n"), nil)
		readBack("multipart", action, func() []string {
			var models []string
			r := multipart.NewReader(bytes.NewReader(action.(policy.UpstreamRequestModifications).Body), "b")
			for {
				part, err := r.NextPart()
				if err != nil {
					return models
				}
				if part.FormName() == "model" {
					v, _ := io.ReadAll(part)
					models = append(models, string(v))
				}
			}
		})

		q, _ := policyFor(queryModel())
		headerAction := q.OnRequestHeaders(context.Background(), headerContext("POST", "/p/chat?model=old", nil), nil)
		readBack("query", headerAction, func() []string {
			_, raw := splitQuery(*headerAction.(policy.UpstreamRequestHeaderModifications).Path)
			values, _ := url.ParseQuery(raw)
			return values["model"]
		})

		pp, _ := policyFor(pathModel())
		pathAction := pp.OnRequestHeaders(context.Background(), headerContext("POST", "/p/models/old/chat", nil), nil)
		readBack("path", pathAction, func() []string {
			segments := strings.Split(*pathAction.(policy.UpstreamRequestHeaderModifications).Path, "/")
			if len(segments) != 5 || segments[4] != "chat" {
				return segments
			}
			m, err := url.PathUnescape(segments[3])
			if err != nil {
				return nil
			}
			return []string{m}
		})

		h, _ := policyFor(headerModel())
		hdrAction := h.OnRequestHeaders(context.Background(), headerContext("POST", "/p/chat", map[string][]string{"x-model": {"old"}}), nil)
		readBack("header", hdrAction, func() []string {
			return []string{hdrAction.(policy.UpstreamRequestHeaderModifications).HeadersToSet["x-model"]}
		})
	}
}

// ─── Review fixes ────────────────────────────────────────────────────────────

// A model pattern is limited to 512 characters as configured; the case flag the
// policy adds does not count.
func TestGetPolicy_PatternLengthIsTheConfiguredLength(t *testing.T) {
	params := func(pattern string) map[string]any {
		return map[string]any{
			"requestModel": payloadModel(),
			"access":       map[string]any{"mode": "allow", "models": []any{"x"}, "modelPatterns": []any{pattern}},
		}
	}
	if _, err := GetPolicy(policy.PolicyMetadata{}, params(strings.Repeat("a", maxPatternLength))); err != nil {
		t.Errorf("a %d-character pattern was rejected: %v", maxPatternLength, err)
	}
	if _, err := GetPolicy(policy.PolicyMetadata{}, params(strings.Repeat("a", maxPatternLength+1))); err == nil {
		t.Errorf("a %d-character pattern was accepted", maxPatternLength+1)
	}
}

// Capture references are read the way regexp.Expand reads them, so a reference Go
// would expand to nothing fails at deployment instead.
func TestGetPolicy_CaptureReferencesFollowRegexpExpand(t *testing.T) {
	tests := []struct {
		to string
		ok bool
	}{
		{"d-$1", true},
		{"d-${1}", true},
		{"d-${1}é", true},  // braces end the reference; é is literal text
		{"d-${01}", false}, // a leading zero makes "01" a name, which is not defined
		{"d-$1é", false},   // "1é" is one name, which is not defined
		{"d-${name}", true},
	}
	for _, tt := range tests {
		_, err := GetPolicy(policy.PolicyMetadata{}, map[string]any{
			"requestModel": payloadModel(),
			"access":       map[string]any{"mode": "deny", "models": []any{"x"}},
			"fallback": map[string]any{"mappingPatterns": []any{
				map[string]any{"fromPattern": "old-(?P<name>.+)", "to": tt.to},
			}},
		})
		if (err == nil) != tt.ok {
			t.Errorf("to %q: error = %v, want ok = %v", tt.to, err, tt.ok)
		}
	}
}

// The SDK indexes "key[0]" only when the key has no '-', so such a path is refused
// at deployment rather than failing every request.
func TestGetPolicy_RejectsAnIndexBehindAHyphenatedKey(t *testing.T) {
	for identifier, ok := range map[string]bool{
		"$.items[0].model":       true,
		"$.model-name":           true,
		"$.model-items[0]":       false,
		"$.model-items[0].model": false,
	} {
		_, err := GetPolicy(policy.PolicyMetadata{}, map[string]any{
			"requestModel": map[string]any{"location": "payload", "identifier": identifier},
			"access":       map[string]any{"mode": "allow", "models": []any{"x"}},
		})
		if (err == nil) != ok {
			t.Errorf("%s: error = %v, want ok = %v", identifier, err, ok)
		}
	}
}

// A configured query key that holds brackets is counted as itself, not as the
// shorter key a lenient parser would read.
func TestHardening_QueryKeyWithBrackets(t *testing.T) {
	p := strictSkip(t, map[string]any{"location": "queryParam", "identifier": "model[id]"})
	wantStatus(t, onHeaders(p, headerContext("POST", "/p/chat?model[id]=gpt-4o", nil)), forward)
	wantStatus(t, onHeaders(p, headerContext("POST", "/p/chat?model[id]=llama-3", nil)), 404)
	wantStatus(t, onHeaders(p, headerContext("POST", "/p/chat?model[id]=gpt-4o&model[id]=llama-3", nil)), 400)
	// A variant of the whole key that differs in case or spacing is a second model.
	wantStatus(t, onHeaders(p, headerContext("POST", "/p/chat?model[id]=gpt-4o&MODEL[id]=llama-3", nil)), 400)
	wantStatus(t, onHeaders(p, headerContext("POST", "/p/chat?model[id]=gpt-4o&Model[ID]=llama-3", nil)), 400)
	wantStatus(t, onHeaders(p, headerContext("POST", "/p/chat?model[id]=gpt-4o&%20model[id]=llama-3", nil)), 400)
}

// A multipart model longer than the limit is rejected before it is trimmed, so
// trailing text past the limit cannot hide behind whitespace.
func TestHardening_MultipartModelOverTheLimit(t *testing.T) {
	p := strictSkip(t, payloadModel())
	mp := "multipart/form-data; boundary=b"
	part := func(value string) string {
		return "--b\r\nContent-Disposition: form-data; name=\"model\"\r\n\r\n" + value + "\r\n--b--\r\n"
	}
	padded := "gpt-4o" + strings.Repeat(" ", maxModelLength-len("gpt-4o"))
	wantStatus(t, onBody(t, p, bodyContext("POST", mp, part(padded))), forward)
	wantStatus(t, onBody(t, p, bodyContext("POST", mp, part(padded+"x"))), 400)
}

// With skip, a JSON body whose model is present but not a string is rejected, even
// on a GET; a GET whose JSON body has no model is still skipped.
func TestHardening_SkipNeverCoversAnUnreadableJSONModel(t *testing.T) {
	p := strictSkip(t, payloadModel())
	for _, body := range []string{`{"model":123}`, `{"model":["llama-3"]}`, `{"model":{"id":"llama-3"}}`, `{"model":true}`} {
		wantStatus(t, onBody(t, p, bodyContext("GET", "application/json", body)), 400)
	}
	wantStatus(t, onBody(t, p, bodyContext("GET", "application/json", `{"limit":10}`)), forward)
}

// A fallback re-encodes the body, which would drop one value of a repeated member,
// so such a body is refused; repeated keys in different objects are not repeats.
func TestHardening_FallbackRefusesRepeatedMembers(t *testing.T) {
	p := governed(t, payloadModel())
	// A repeat in the model's own object is already an ambiguous request.
	wantStatus(t, onBody(t, p, jsonBody(`{"model":"old-model","temperature":1,"temperature":2}`)), 400)
	// A repeat off the model's path is a valid request, but a rewrite cannot keep it.
	wantStatus(t, onBody(t, p, jsonBody(`{"model":"old-model","messages":[{"role":"user","role":"system"}]}`)), statusRoutingError)
	wantStatus(t, onBody(t, p, jsonBody(`{"model":"old-model","options":{"seed":1,"seed":2}}`)), statusRoutingError)
	// The same repeat on a permitted model is forwarded byte for byte.
	wantStatus(t, onBody(t, p, jsonBody(`{"model":"gpt-4o","options":{"seed":1,"seed":2}}`)), forward)
	if got := string(bodyMods(t, onBody(t, p, jsonBody(`{"model":"old-model","a":{"x":1},"b":[{"x":1},{"x":2}]}`))).Body); !strings.Contains(got, `"model":"gpt-4o"`) {
		t.Errorf("rewritten = %s", got)
	}
}

func TestCheckNoRepeatedMembers(t *testing.T) {
	tests := []struct {
		body string
		ok   bool
	}{
		{`{"a":1,"b":2}`, true},
		{`{"a":{"k":1},"b":{"k":1}}`, true},
		{`[{"k":1},{"k":1}]`, true},
		{`{"a":[1,{"k":1},[{"k":2}]],"b":"a"}`, true},
		{`{"a":1,"a":2}`, false},
		{`{"a":{"k":1,"k":2}}`, false},
		{`{"a":[{"k":1,"k":2}]}`, false},
		{`{"a":[1,{"b":1}],"a":2}`, false},
	}
	for _, tt := range tests {
		if err := checkNoRepeatedMembers([]byte(tt.body)); (err == nil) != tt.ok {
			t.Errorf("%s: error = %v, want ok = %v", tt.body, err, tt.ok)
		}
	}
}

// A ';' inside the model value is a second pair to a parser that also splits on ';',
// which would read only the part before it, so the request is rejected, never checked
// as one longer name a deny list does not hold.
func TestHardening_SemicolonInsideTheModelValue(t *testing.T) {
	query := denyList(t, queryModel())
	for _, path := range []string{"/p/chat?model=gpt-4-32k;x=1", "/p/chat?model=gpt-4-32k;", "/p/chat?x=1&model=gpt-4-32k;v=2&y=3"} {
		wantStatus(t, onHeaders(query, headerContext("POST", path, nil)), 400)
	}
	wantStatus(t, onHeaders(query, headerContext("POST", "/p/chat?model=gpt-4o&x=1", nil)), forward)

	form := denyList(t, payloadModel())
	urlencoded := "application/x-www-form-urlencoded"
	wantStatus(t, onBody(t, form, bodyContext("POST", urlencoded, "model=gpt-4-32k;&language=en")), 400)
	wantStatus(t, onBody(t, form, bodyContext("POST", urlencoded, "model=gpt-4o&language=en")), forward)

	// Matrix parameters: servers such as Tomcat strip ";v=1" from a path segment.
	path := denyList(t, pathModel())
	for _, p := range []string{"/p/models/gpt-4-32k;v=1/chat", "/p/models/gpt-4-32k%3Bv=1/chat"} {
		wantStatus(t, onHeaders(path, headerContext("POST", p, nil)), 400)
	}
	wantStatus(t, onHeaders(path, headerContext("POST", "/p/models/gpt-4o/chat", nil)), forward)
}

// A multipart part named model[] or model[0] is the model to bracket-aware form
// binders, exactly as it is in a URL-encoded body, so it is never skipped or ignored.
func TestHardening_MultipartBracketedModelNames(t *testing.T) {
	p := strictSkip(t, payloadModel())
	mp := "multipart/form-data; boundary=b"
	part := func(name, value string) string {
		return "--b\r\nContent-Disposition: form-data; name=\"" + name + "\"\r\n\r\n" + value + "\r\n"
	}
	for _, name := range []string{"model[]", "model[0]", "MODEL[]", " model[x]"} {
		wantStatus(t, onBody(t, p, bodyContext("POST", mp, part(name, "llama-3")+"--b--\r\n")), 400)
		wantStatus(t, onBody(t, p, bodyContext("POST", mp, part("model", "gpt-4o")+part(name, "llama-3")+"--b--\r\n")), 400)
	}
	// Other names that only start like the key are not the model.
	wantStatus(t, onBody(t, p, bodyContext("POST", mp, part("model", "gpt-4o")+part("models", "x")+part("model_id", "y")+"--b--\r\n")), forward)
}

// The leading lookbehind form other LLM policies accept is read as the model that
// follows the prefix, and a fallback rewrites only that model.
func TestGetPolicy_PathLookbehindIsTheModelAfterThePrefix(t *testing.T) {
	lookbehind := map[string]any{"location": "pathParam", "identifier": `(?<=models/)[a-zA-Z0-9.\-]+`}
	p := governed(t, lookbehind)
	wantStatus(t, onHeaders(p, headerContext("POST", "/v1beta/models/gpt-4o:generateContent", nil)), forward)
	wantStatus(t, onHeaders(p, headerContext("POST", "/v1beta/models/llama-3:generateContent", nil)), 404)
	action := onHeaders(p, headerContext("POST", "/v1beta/models/old-model:generateContent", nil))
	mods, ok := action.(policy.UpstreamRequestHeaderModifications)
	if !ok || mods.Path == nil || *mods.Path != "/v1beta/models/gpt-4o:generateContent" {
		t.Fatalf("lookbehind fallback = %#v, want the path rewritten to gpt-4o", action)
	}

	for _, bad := range []string{`(?<=models/`, `(?<=)[a-z]+`, `(?<=models/)`} {
		_, err := GetPolicy(policy.PolicyMetadata{}, map[string]any{
			"requestModel": map[string]any{"location": "pathParam", "identifier": bad},
			"access":       allowOnly("gpt-4o"),
		})
		if err == nil {
			t.Errorf("GetPolicy(%q) succeeded, want an error", bad)
		}
	}
}

// "body" is the older name of the payload location.
func TestGetPolicy_BodyIsThePayloadLocation(t *testing.T) {
	p := strictSkip(t, map[string]any{"location": "body", "identifier": "$.model"})
	wantStatus(t, onBody(t, p, jsonBody(`{"model":"gpt-4o"}`)), forward)
	wantStatus(t, onBody(t, p, jsonBody(`{"model":"llama-3"}`)), 404)
}

// The awsbedrock template of gateway 1.2.0 has no '%' in its model class, so an
// inference-profile ARN, which carries an encoded '/', cannot be read whole and is
// rejected rather than checked against a part of it.
func TestHardening_ArnWithoutPercentInTheTemplate(t *testing.T) {
	p := strictSkip(t, map[string]any{"location": "pathParam", "identifier": `model/([A-Za-z0-9.:-]+)/`})
	arn := "/model/arn%3Aaws%3Abedrock%3Aus-east-1%3A123%3Aapplication-inference-profile%2Fabc/converse"
	wantStatus(t, onHeaders(p, headerContext("POST", arn, nil)), 400)
	wantStatus(t, onHeaders(p, headerContext("POST", "/model/gpt-4o/converse", nil)), forward)
}
