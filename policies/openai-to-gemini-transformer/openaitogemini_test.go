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

package openaitogemini

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

// TestGetPolicy_ValidatesParams guards the shape of the params, not their
// presence: `model` is optional, and an unset model means each request names
// its own. Non-string values are still rejected.
func TestGetPolicy_ValidatesParams(t *testing.T) {
	if _, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{}); err != nil {
		t.Fatalf("model override should be optional: %v", err)
	}
	if _, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{
		"model": "gemini-2.5-flash", "providerId": "gemini-provider",
	}); err != nil {
		t.Fatalf("unexpected error for valid params: %v", err)
	}
	for _, params := range []map[string]interface{}{
		{"model": 42},
		{"model": "gemini-2.5-flash", "providerId": true},
	} {
		if _, err := GetPolicy(policy.PolicyMetadata{}, params); err == nil {
			t.Errorf("expected invalid params to fail: %#v", params)
		}
	}
}

func TestTranslateBody_ContentsAndSystem(t *testing.T) {
	payload := map[string]interface{}{
		"messages": []interface{}{
			map[string]interface{}{"role": "system", "content": "be brief"},
			map[string]interface{}{"role": "user", "content": "hi"},
		},
	}
	mods, err := translateBody(payload, "gemini-2.5-flash", PolicyParams{Model: "gemini-2.5-flash", APIVersion: "v1beta"}, false)
	if err != nil {
		t.Fatalf("translateBody failed: %v", err)
	}

	if mods.Path == nil || *mods.Path != "/v1beta/models/gemini-2.5-flash:generateContent" {
		t.Fatalf("unexpected path: %v", mods.Path)
	}
	var body map[string]interface{}
	if err := json.Unmarshal(mods.Body, &body); err != nil {
		t.Fatalf("body is not valid JSON: %v", err)
	}
	// System message must map to Gemini's systemInstruction, not contents.
	if body["systemInstruction"] == nil {
		t.Error("expected systemInstruction to be set from the system message")
	}
	contents, ok := body["contents"].([]interface{})
	if !ok || len(contents) == 0 {
		t.Fatalf("expected non-empty contents, got %v", body["contents"])
	}
	// OpenAI 'messages' must not leak through to the Gemini body.
	if _, leaked := body["messages"]; leaked {
		t.Error("OpenAI 'messages' must not appear in the Gemini body")
	}
}

func TestTranslateResponse_JSONShape(t *testing.T) {
	gemini := `{"candidates":[{"content":{"role":"model","parts":[{"text":"Hi there"}]},` +
		`"finishReason":"STOP","index":0}],` +
		`"usageMetadata":{"promptTokenCount":5,"candidatesTokenCount":3,"totalTokenCount":8}}`
	action := translateResponse([]byte(gemini), 200, "gemini-2.5-flash")

	mods, ok := action.(policy.DownstreamResponseModifications)
	if !ok {
		t.Fatalf("expected DownstreamResponseModifications, got %T", action)
	}
	var out map[string]interface{}
	if err := json.Unmarshal(mods.Body, &out); err != nil {
		t.Fatalf("translated body not JSON: %v", err)
	}
	choices, _ := out["choices"].([]interface{})
	if len(choices) != 1 {
		t.Fatalf("expected 1 choice, got %v", out["choices"])
	}
	choice := choices[0].(map[string]interface{})
	msg := choice["message"].(map[string]interface{})
	if msg["content"] != "Hi there" {
		t.Errorf("unexpected content: %v", msg["content"])
	}
	if choice["finish_reason"] != "stop" {
		t.Errorf("expected finish_reason=stop, got %v", choice["finish_reason"])
	}
}

// TestConfiguredModelIsFallback pins the compatibility guarantee that survives
// the payload-first rule: a proxy that sets `model` behaves exactly as it did
// for every request whose payload names no model. A request that does name one
// is covered by TestResolveModel — it is served the client's model, which is the
// one intended behaviour change.
func TestConfiguredModelIsFallback(t *testing.T) {
	const configured = "gemini-2.5-pro"
	p := &TranslatorPolicy{params: PolicyParams{Model: configured, APIVersion: DefaultAPIVersion}}
	shared := &policy.SharedContext{RequestID: "req-1234", Metadata: map[string]interface{}{}}

	// With no model in the payload, the configured one drives everything.
	req := &policy.RequestContext{SharedContext: shared, Body: &policy.Body{Present: true, Content: []byte(
		`{"messages":[{"role":"user","content":"hello"}]}`)}}
	action := p.OnRequestBody(context.Background(), req, nil)
	mods, isUpstream := action.(policy.UpstreamRequestModifications)
	if !isUpstream {
		t.Fatalf("expected UpstreamRequestModifications, got %T", action)
	}
	if mods.Path == nil || !strings.Contains(*mods.Path, configured) {
		t.Errorf("upstream path = %v, want it to carry the configured %q", mods.Path, configured)
	}

	// The buffered response reports it.
	respCtx := &policy.ResponseContext{
		SharedContext:  shared,
		ResponseStatus: 200,
		ResponseBody: &policy.Body{Present: true, Content: []byte(
			`{"candidates":[{"content":{"role":"model","parts":[{"text":"Hi there"}]},` +
				`"finishReason":"STOP","index":0}],` +
				`"usageMetadata":{"promptTokenCount":5,"candidatesTokenCount":3,"totalTokenCount":8}}`)},
	}
	respAction := p.OnResponseBody(context.Background(), respCtx, nil)
	respMods, isDownstream := respAction.(policy.DownstreamResponseModifications)
	if !isDownstream {
		t.Fatalf("expected DownstreamResponseModifications, got %T", respAction)
	}
	var buffered map[string]interface{}
	if err := json.Unmarshal(respMods.Body, &buffered); err != nil {
		t.Fatalf("translated response is not JSON: %v", err)
	}
	if buffered["model"] != configured {
		t.Errorf("buffered response model = %v, want %q", buffered["model"], configured)
	}

	// So does every streamed chunk.
	out, terminated := feed(t, p, []string{geminiTextStream()})
	if terminated {
		t.Fatal("a well-formed stream must not terminate early")
	}
	for i, chunk := range parseChunks(t, out) {
		if chunk["model"] != configured {
			t.Errorf("streamed chunk %d model = %v, want %q", i, chunk["model"], configured)
		}
	}
	if !strings.Contains(out, "[DONE]") {
		t.Error("stream did not terminate with [DONE]")
	}
}

// TestResolveModel covers every row of the resolution table: the request's own
// model wins when it names one, the configured model is the fallback used only
// when it does not, and a request that names no usable model is rejected naming
// both sources.
func TestResolveModel(t *testing.T) {
	const configured = "gemini-2.5-pro"
	const requested = "gemini-2.5-flash"

	cases := []struct {
		name       string
		configured string
		payload    string
		wantModel  string // empty means the request must be rejected
		wantErr    string
	}{
		{"request overrides the configured model", configured, `{"model":"` + requested + `","messages":[{"role":"user","content":"hi"}]}`, requested, ""},
		{"configured model is the fallback when the request names none", configured, `{"messages":[{"role":"user","content":"hi"}]}`, configured, ""},
		{"empty request model falls back to the configured model", configured, `{"model":"","messages":[{"role":"user","content":"hi"}]}`, configured, ""},
		{"null request model falls back to the configured model", configured, `{"model":null,"messages":[{"role":"user","content":"hi"}]}`, configured, ""},
		{"request model used when none is configured", "", `{"model":"` + requested + `","messages":[{"role":"user","content":"hi"}]}`, requested, ""},
		{"padded request model is trimmed, not rejected", "", `{"model":"  ` + requested + `  ","messages":[{"role":"user","content":"hi"}]}`, requested, ""},
		{"neither source supplies one", "", `{"messages":[{"role":"user","content":"hi"}]}`, "", "either the policy configuration or request body"},
		{"empty request model with nothing configured", "", `{"model":"","messages":[{"role":"user","content":"hi"}]}`, "", "either the policy configuration or request body"},
		{"whitespace-only request model is malformed", "", `{"model":"   ","messages":[{"role":"user","content":"hi"}]}`, "", "must not be blank"},
		{"whitespace-only is malformed even with a configured model", configured, `{"model":"   ","messages":[{"role":"user","content":"hi"}]}`, "", "must not be blank"},
		{"non-string request model is a bad request", "", `{"model":123,"messages":[{"role":"user","content":"hi"}]}`, "", "must be a string"},
		{"non-string is a bad request even with a configured model", configured, `{"model":123,"messages":[{"role":"user","content":"hi"}]}`, "", "must be a string"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := &TranslatorPolicy{params: PolicyParams{Model: tc.configured, APIVersion: DefaultAPIVersion}}
			req := &policy.RequestContext{
				SharedContext: &policy.SharedContext{Metadata: map[string]interface{}{}},
				Body:          &policy.Body{Present: true, Content: []byte(tc.payload)},
			}

			action := p.OnRequestBody(context.Background(), req, nil)

			if tc.wantModel == "" {
				rejected, isImmediate := action.(policy.ImmediateResponse)
				if !isImmediate {
					t.Fatalf("expected the request to be rejected, got %T", action)
				}
				if rejected.StatusCode != 400 {
					t.Errorf("status = %d, want 400", rejected.StatusCode)
				}
				if !strings.Contains(string(rejected.Body), tc.wantErr) {
					t.Errorf("error body = %s, want it to mention %q", rejected.Body, tc.wantErr)
				}
				return
			}

			mods, isUpstream := action.(policy.UpstreamRequestModifications)
			if !isUpstream {
				t.Fatalf("expected UpstreamRequestModifications, got %T", action)
			}
			if got := upstreamModelFromPath(t, mods.Path); got != tc.wantModel {
				t.Errorf("model sent upstream = %q, want %q", got, tc.wantModel)
			}
		})
	}
}

// Gemini carries the model in the upstream path (/{apiVersion}/models/{model}:{method}).
func upstreamModelFromPath(t *testing.T, path *string) string {
	t.Helper()
	if path == nil {
		t.Fatal("expected the request path to be rewritten")
	}
	_, after, found := strings.Cut(*path, "/models/")
	if !found {
		t.Fatalf("path %q does not name a model", *path)
	}
	model, _, _ := strings.Cut(after, ":")
	return model
}

const geminiBufferedBody = `{"candidates":[{"content":{"role":"model","parts":[{"text":"Hi there"}]},` +
	`"finishReason":"STOP","index":0}],` +
	`"usageMetadata":{"promptTokenCount":5,"candidatesTokenCount":3,"totalTokenCount":8}}`

// geminiStreamWithoutModel omits modelVersion, so the stream never learns a
// model from the upstream and must report the one the state was built with.
func geminiStreamWithoutModel() string {
	return sseFrame(`{"candidates":[{"content":{"role":"model","parts":[{"text":"Hello"}]},"finishReason":"STOP","index":0}]}`)
}

// TestEffectiveModel_ReportsModelThatServedRequest covers both resolution paths
// in both response modes: whatever model actually served the request is what
// the response reports.
func TestEffectiveModel_ReportsModelThatServedRequest(t *testing.T) {
	cases := []struct {
		name       string
		configured string
		requested  string
		want       string
	}{
		{"request-supplied model is reported", "", "gemini-2.5-flash", "gemini-2.5-flash"},
		{"request-supplied model wins over the configured one", "gemini-2.5-pro", "gemini-2.5-flash", "gemini-2.5-flash"},
		{"configured fallback is reported when the request names none", "gemini-2.5-pro", "", "gemini-2.5-pro"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := &TranslatorPolicy{params: PolicyParams{Model: tc.configured, APIVersion: DefaultAPIVersion}}
			shared := &policy.SharedContext{RequestID: "req-1234", Metadata: map[string]interface{}{}}

			payload := `{"messages":[{"role":"user","content":"hi"}]}`
			if tc.requested != "" {
				payload = `{"model":"` + tc.requested + `","messages":[{"role":"user","content":"hi"}]}`
			}
			req := &policy.RequestContext{SharedContext: shared, Body: &policy.Body{Present: true, Content: []byte(payload)}}
			if action := p.OnRequestBody(context.Background(), req, nil); action == nil {
				t.Fatal("request phase returned no action")
			}
			if got := shared.Metadata[MetadataKeyEffectiveModel]; got != tc.want {
				t.Fatalf("effective model recorded = %v, want %q", got, tc.want)
			}

			if got := bufferedModel(t, p, shared, geminiBufferedBody); got != tc.want {
				t.Errorf("buffered response model = %q, want %q", got, tc.want)
			}
			for i, chunk := range parseChunks(t, feedWithShared(t, p, shared, geminiStreamWithoutModel())) {
				if chunk["model"] != tc.want {
					t.Errorf("streamed chunk %d model = %v, want %q", i, chunk["model"], tc.want)
				}
			}
		})
	}
}

// TestEffectiveModel_FallsBackToConfigured is the guard that no response path
// can report nothing: with no effective model recorded — a response reaching
// this policy without its request phase having run — the configured model is
// reported.
func TestEffectiveModel_FallsBackToConfigured(t *testing.T) {
	const configured = "gemini-2.5-pro"
	p := &TranslatorPolicy{params: PolicyParams{Model: configured, APIVersion: DefaultAPIVersion}}
	shared := &policy.SharedContext{RequestID: "req-1234", Metadata: map[string]interface{}{}}

	if got := bufferedModel(t, p, shared, geminiBufferedBody); got != configured {
		t.Errorf("buffered response model = %q, want the configured fallback %q", got, configured)
	}
	for i, chunk := range parseChunks(t, feedWithShared(t, p, shared, geminiStreamWithoutModel())) {
		if chunk["model"] != configured {
			t.Errorf("streamed chunk %d model = %v, want %q", i, chunk["model"], configured)
		}
	}
	if got := effectiveModel(nil, configured); got != configured {
		t.Errorf("nil shared context: model = %q, want %q", got, configured)
	}
}

func bufferedModel(t *testing.T, p *TranslatorPolicy, shared *policy.SharedContext, body string) string {
	t.Helper()
	action := p.OnResponseBody(context.Background(), &policy.ResponseContext{
		SharedContext:  shared,
		ResponseStatus: 200,
		ResponseBody:   &policy.Body{Present: true, Content: []byte(body)},
	}, nil)
	mods, isDownstream := action.(policy.DownstreamResponseModifications)
	if !isDownstream {
		t.Fatalf("expected DownstreamResponseModifications, got %T", action)
	}
	var translated map[string]interface{}
	if err := json.Unmarshal(mods.Body, &translated); err != nil {
		t.Fatalf("translated response is not JSON: %v", err)
	}
	model, _ := translated["model"].(string)
	return model
}

// feedWithShared drives the streaming lifecycle over one transport chunk using
// a caller-supplied shared context, so a test can carry an effective model
// recorded by the request phase into the stream.
func feedWithShared(t *testing.T, p *TranslatorPolicy, shared *policy.SharedContext, chunk string) string {
	t.Helper()
	respCtx := &policy.ResponseStreamContext{
		SharedContext:   shared,
		ResponseHeaders: sseHeaders(),
		ResponseStatus:  200,
	}
	action := p.OnResponseBodyChunk(context.Background(), respCtx,
		&policy.StreamBody{Chunk: []byte(chunk), EndOfStream: true, Index: 0}, nil)
	switch typed := action.(type) {
	case policy.ForwardResponseChunk:
		return string(typed.Body)
	case policy.TerminateResponseChunk:
		t.Fatalf("stream terminated early: %s", typed.Body)
	default:
		t.Fatalf("unexpected streaming action %T", action)
	}
	return ""
}

// TestBuildGeminiPath covers both the shape of the path and its safety: the
// model can arrive from the request payload, so it must not be able to alter
// the path structure, while an ordinary model name produces the same path as
// before.
func TestBuildGeminiPath(t *testing.T) {
	cases := []struct {
		name   string
		model  string
		stream bool
		want   string
	}{
		{"non-streaming path", "gemini-2.5-flash", false, "/v1beta/models/gemini-2.5-flash:generateContent"},
		{"streaming path", "gemini-2.5-flash", true, "/v1beta/models/gemini-2.5-flash:streamGenerateContent?alt=sse"},
		{"ordinary model is unchanged", "gemini-2.5-pro", false, "/v1beta/models/gemini-2.5-pro:generateContent"},
		{"ordinary model streaming is unchanged", "gemini-2.5-pro", true, "/v1beta/models/gemini-2.5-pro:streamGenerateContent?alt=sse"},
		{"path separator cannot add a segment", "../../admin/models/x", false, "/v1beta/models/..%2F..%2Fadmin%2Fmodels%2Fx:generateContent"},
		{"query separator cannot add a query", "gemini?alt=json", false, "/v1beta/models/gemini%3Falt=json:generateContent"},
		{"fragment cannot truncate the path", "gemini#frag", false, "/v1beta/models/gemini%23frag:generateContent"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := buildGeminiPath(DefaultAPIVersion, tc.model, tc.stream); got != tc.want {
				t.Errorf("buildGeminiPath(%q) = %q, want %q", tc.model, got, tc.want)
			}
		})
	}
}

// TestErrResponseDirectionAndCode covers what this translator refuses and how it labels it.
//
// Direction is the point: a payload the caller sent that will not convert is a
// request-side refusal, while a provider reply that will not translate back is a
// response-side one. They share a helper and nothing else, and only the caller knows which
// it made — so it is passed in rather than inferred from the status.
func TestErrResponseDirectionAndCode(t *testing.T) {
	t.Run("request side", func(t *testing.T) {
		resp := errResponse(400, "Request body is empty.",
			policy.FaultCodeInvalidRequestBody, policy.DirectionRequest, policy.FaultTypeValidation)
		if !resp.IsFault {
			t.Fatalf("expected IsFault=true on a refused request")
		}
		if resp.Fault == nil {
			t.Fatalf("expected Error to be populated")
		}
		if resp.Fault.Code != policy.FaultCodeInvalidRequestBody {
			t.Fatalf("expected Error.Code=%q, got %q", policy.FaultCodeInvalidRequestBody, resp.Fault.Code)
		}
		if resp.Fault.Direction != policy.DirectionRequest {
			t.Fatalf("expected Error.Direction=%q, got %q", policy.DirectionRequest, resp.Fault.Direction)
		}
		if resp.Fault.Type != policy.FaultTypeValidation {
			t.Fatalf("expected Error.Type=%q, got %q", policy.FaultTypeValidation, resp.Fault.Type)
		}
	})

	t.Run("response side", func(t *testing.T) {
		resp := errResponse(500, "failed to translate response",
			policy.FaultCodeMediationFailed, policy.DirectionResponse, policy.FaultTypeMediation)
		if !resp.IsFault {
			t.Fatalf("expected IsFault=true on a failed translation")
		}
		if resp.Fault == nil {
			t.Fatalf("expected Error to be populated")
		}
		if resp.Fault.Code != policy.FaultCodeMediationFailed {
			t.Fatalf("expected Error.Code=%q, got %q", policy.FaultCodeMediationFailed, resp.Fault.Code)
		}
		if resp.Fault.Direction != policy.DirectionResponse {
			t.Fatalf("expected Error.Direction=%q, got %q", policy.DirectionResponse, resp.Fault.Direction)
		}
	})
}

// TestOnRequestBody_RejectionsDeclareFault drives each request rejection through
// OnRequestBody and checks the fault it declares, and that the client body is unchanged.
func TestOnRequestBody_RejectionsDeclareFault(t *testing.T) {
	cases := []struct {
		name       string
		body       *policy.Body
		bodyPrefix string
	}{
		{"missing body", nil, `{"error":"Request body is empty."}`},
		{"empty body", &policy.Body{Present: true}, `{"error":"Request body is empty."}`},
		{"invalid JSON", &policy.Body{Present: true, Content: []byte(`{"messages":`)}, `{"error":"Invalid JSON in request body: `},
		{"unresolvable model", &policy.Body{Present: true, Content: []byte(`{"model":42,"messages":[]}`)}, `{"error":"request field 'model' must be a string"}`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := &TranslatorPolicy{params: PolicyParams{APIVersion: DefaultAPIVersion}}
			action := p.OnRequestBody(context.Background(), &policy.RequestContext{
				SharedContext: &policy.SharedContext{Metadata: map[string]interface{}{}},
				Body:          c.body,
			}, nil)
			resp, ok := action.(policy.ImmediateResponse)
			if !ok || resp.StatusCode != 400 {
				t.Fatalf("expected a 400 ImmediateResponse, got %#v", action)
			}
			if resp.Headers["Content-Type"] != "application/json" || !strings.HasPrefix(string(resp.Body), c.bodyPrefix) {
				t.Fatalf("client response changed: headers %v, body %s", resp.Headers, resp.Body)
			}
			if !resp.IsFault || resp.Fault == nil {
				t.Fatalf("expected IsFault=true and Fault set")
			}
			if resp.Fault.Code != policy.FaultCodeInvalidRequestBody ||
				resp.Fault.Type != policy.FaultTypeValidation ||
				resp.Fault.Direction != policy.DirectionRequest {
				t.Fatalf("unexpected fault code/type/direction: %q/%q/%q",
					resp.Fault.Code, resp.Fault.Type, resp.Fault.Direction)
			}
		})
	}
}
