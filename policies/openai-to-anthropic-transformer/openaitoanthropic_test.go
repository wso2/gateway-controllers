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

package openaitoanthropic

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
		"model": "claude", "providerId": "anthropic-provider",
	}); err != nil {
		t.Fatalf("unexpected error for valid params: %v", err)
	}
	for _, params := range []map[string]interface{}{
		{"model": 42},
		{"model": "claude", "providerId": true},
	} {
		if _, err := GetPolicy(policy.PolicyMetadata{}, params); err == nil {
			t.Errorf("expected invalid params to fail: %#v", params)
		}
	}
}

func TestTranslateBody_MessagesShape(t *testing.T) {
	payload := map[string]interface{}{
		"model": "gpt-4o",
		"messages": []interface{}{
			map[string]interface{}{"role": "system", "content": "be brief"},
			map[string]interface{}{"role": "user", "content": "hi"},
		},
		"temperature": 0.5,
	}
	mods, err := translateBody(payload, "claude", PolicyParams{Model: "claude", AnthropicVersion: DefaultAnthropicVersion})
	if err != nil {
		t.Fatalf("translateBody failed: %v", err)
	}

	if mods.Path == nil || *mods.Path != AnthropicMessagesPath {
		t.Fatalf("expected path %q, got %v", AnthropicMessagesPath, mods.Path)
	}
	if mods.HeadersToSet["anthropic-version"] != DefaultAnthropicVersion {
		t.Errorf("expected anthropic-version header, got %v", mods.HeadersToSet)
	}

	var body map[string]interface{}
	if err := json.Unmarshal(mods.Body, &body); err != nil {
		t.Fatalf("body is not valid JSON: %v", err)
	}
	if body["model"] != "claude" {
		t.Errorf("expected model=claude, got %v", body["model"])
	}
	if body["system"] != "be brief" {
		t.Errorf("expected system text extracted, got %v", body["system"])
	}
	// Anthropic requires max_tokens — the translator must inject the default.
	if body["max_tokens"] == nil {
		t.Error("expected max_tokens to be set (Anthropic requires it)")
	}
	msgs, ok := body["messages"].([]interface{})
	if !ok || len(msgs) != 1 {
		t.Fatalf("expected 1 non-system message, got %v", body["messages"])
	}
	if first := msgs[0].(map[string]interface{}); first["role"] != "user" {
		t.Errorf("expected first message role=user, got %v", first["role"])
	}
}

func TestTranslateBody_ToolsConverted(t *testing.T) {
	payload := map[string]interface{}{
		"messages": []interface{}{
			map[string]interface{}{"role": "user", "content": "weather?"},
		},
		"tools": []interface{}{
			map[string]interface{}{
				"type": "function",
				"function": map[string]interface{}{
					"name":        "get_weather",
					"description": "Get weather",
					"parameters":  map[string]interface{}{"type": "object"},
				},
			},
		},
	}
	mods, err := translateBody(payload, "claude", PolicyParams{Model: "claude"})
	if err != nil {
		t.Fatalf("translateBody failed: %v", err)
	}

	var body map[string]interface{}
	if err := json.Unmarshal(mods.Body, &body); err != nil {
		t.Fatalf("body is not valid JSON: %v", err)
	}
	tools, ok := body["tools"].([]interface{})
	if !ok || len(tools) != 1 {
		t.Fatalf("expected 1 tool, got %v", body["tools"])
	}
	tool := tools[0].(map[string]interface{})
	if tool["name"] != "get_weather" {
		t.Errorf("expected tool name=get_weather, got %v", tool["name"])
	}
	// OpenAI's "parameters" must be remapped to Anthropic's "input_schema".
	if tool["input_schema"] == nil {
		t.Errorf("expected input_schema on the converted tool, got %v", tool)
	}
}

func TestTranslateBody_ToolChoiceNoneDropsTools(t *testing.T) {
	payload := map[string]interface{}{
		"messages": []interface{}{map[string]interface{}{"role": "user", "content": "hi"}},
		"tools": []interface{}{
			map[string]interface{}{"type": "function", "function": map[string]interface{}{"name": "f"}},
		},
		"tool_choice": "none",
	}
	mods, err := translateBody(payload, "claude", PolicyParams{Model: "claude"})
	if err != nil {
		t.Fatalf("translateBody failed: %v", err)
	}

	var body map[string]interface{}
	if err := json.Unmarshal(mods.Body, &body); err != nil {
		t.Fatalf("body is not valid JSON: %v", err)
	}
	if _, hasTools := body["tools"]; hasTools {
		t.Error("tool_choice=none must drop tools entirely (no Anthropic negative form)")
	}
}

func TestTranslateResponse_JSONShape(t *testing.T) {
	anthropic := `{"id":"msg_1","type":"message","role":"assistant",` +
		`"content":[{"type":"text","text":"Hi there"}],` +
		`"stop_reason":"end_turn","usage":{"input_tokens":5,"output_tokens":3}}`
	action := translateResponse([]byte(anthropic), 200, "claude")

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

// TestConvertUserContent_MalformedBlocks ensures content blocks with a missing
// or non-string "type" are skipped rather than panicking — the block list comes
// straight from an untrusted request body.
func TestConvertUserContent_MalformedBlocks(t *testing.T) {
	content := []interface{}{
		map[string]interface{}{"text": "no type field"},
		map[string]interface{}{"type": 42, "text": "non-string type"},
		"not an object",
		map[string]interface{}{"type": "text", "text": "valid"},
	}
	result := convertUserContent(content)

	blocks, ok := result.([]interface{})
	if !ok {
		t.Fatalf("expected []interface{}, got %T", result)
	}
	if len(blocks) != 1 {
		t.Fatalf("expected only the 1 valid block to survive, got %d: %v", len(blocks), blocks)
	}
	if block := blocks[0].(map[string]interface{}); block["text"] != "valid" {
		t.Errorf("unexpected surviving block: %v", block)
	}
}

// TestLooksLikeSSE distinguishes streaming SSE bodies (passed through
// untouched, since translating SSE needs a stateful chunk-level policy) from
// JSON bodies (translated to OpenAI shape).
func TestLooksLikeSSE(t *testing.T) {
	sse := []byte("event: message_start\ndata: {\"type\":\"message_start\"}\n\n")
	if !looksLikeSSE(sse) {
		t.Error("expected an event-stream body to be detected as SSE")
	}
	jsonBody := []byte(`{"id":"msg_1","content":[{"type":"text","text":"hi"}]}`)
	if looksLikeSSE(jsonBody) {
		t.Error("expected a JSON body not to be detected as SSE")
	}
}

// TestConfiguredModelIsFallback pins the compatibility guarantee that survives
// the payload-first rule: a proxy that sets `model` behaves exactly as it did
// for every request whose payload names no model. A request that does name one
// is covered by TestResolveModel — it is served the client's model, which is the
// one intended behaviour change.
func TestConfiguredModelIsFallback(t *testing.T) {
	const configured = "claude-sonnet-4-20250514"
	p := &TranslatorPolicy{params: PolicyParams{
		Model: configured, AnthropicVersion: DefaultAnthropicVersion,
	}}
	shared := &policy.SharedContext{RequestID: "req-1234", Metadata: map[string]interface{}{}}

	// With no model in the payload, the configured one drives everything.
	req := &policy.RequestContext{SharedContext: shared, Body: &policy.Body{Present: true, Content: []byte(
		`{"messages":[{"role":"user","content":"hello"}]}`)}}
	action := p.OnRequestBody(context.Background(), req, nil)
	mods, isUpstream := action.(policy.UpstreamRequestModifications)
	if !isUpstream {
		t.Fatalf("expected UpstreamRequestModifications, got %T", action)
	}
	var upstream map[string]interface{}
	if err := json.Unmarshal(mods.Body, &upstream); err != nil {
		t.Fatalf("upstream body is not JSON: %v", err)
	}
	if upstream["model"] != configured {
		t.Errorf("upstream model = %v, want the configured fallback %q", upstream["model"], configured)
	}

	// The buffered response reports it.
	respCtx := &policy.ResponseContext{
		SharedContext:  shared,
		ResponseStatus: 200,
		ResponseBody: &policy.Body{Present: true, Content: []byte(
			`{"id":"msg_1","type":"message","role":"assistant",` +
				`"content":[{"type":"text","text":"hi"}],"stop_reason":"end_turn",` +
				`"usage":{"input_tokens":5,"output_tokens":3}}`)},
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
	out, terminated := feed(t, p, []string{anthropicTextStream()})
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
	const configured = "claude-sonnet-4-20250514"
	const requested = "claude-opus-4-1"

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
			p := &TranslatorPolicy{params: PolicyParams{Model: tc.configured, AnthropicVersion: DefaultAnthropicVersion}}
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
			if got := upstreamModelFromBody(t, mods.Body); got != tc.wantModel {
				t.Errorf("model sent upstream = %q, want %q", got, tc.wantModel)
			}
		})
	}
}

func upstreamModelFromBody(t *testing.T, body []byte) string {
	t.Helper()
	var upstream map[string]interface{}
	if err := json.Unmarshal(body, &upstream); err != nil {
		t.Fatalf("upstream body is not JSON: %v", err)
	}
	model, _ := upstream["model"].(string)
	return model
}

const anthropicBufferedBody = `{"id":"msg_1","type":"message","role":"assistant",` +
	`"content":[{"type":"text","text":"hi"}],"stop_reason":"end_turn",` +
	`"usage":{"input_tokens":5,"output_tokens":3}}`

// anthropicStreamWithoutModel omits message_start, so the stream never learns a
// model from the upstream and must report the one the state was built with.
func anthropicStreamWithoutModel() string {
	return sseFrame("content_block_start", `{"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}`) +
		sseFrame("content_block_delta", `{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Hello"}}`) +
		sseFrame("content_block_stop", `{"type":"content_block_stop","index":0}`) +
		sseFrame("message_stop", `{"type":"message_stop"}`)
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
		{"request-supplied model is reported", "", "claude-opus-4-1", "claude-opus-4-1"},
		{"request-supplied model wins over the configured one", "claude-sonnet-4-20250514", "claude-opus-4-1", "claude-opus-4-1"},
		{"configured fallback is reported when the request names none", "claude-sonnet-4-20250514", "", "claude-sonnet-4-20250514"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := &TranslatorPolicy{params: PolicyParams{
				Model: tc.configured, AnthropicVersion: DefaultAnthropicVersion,
			}}
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

			if got := bufferedModel(t, p, shared, anthropicBufferedBody); got != tc.want {
				t.Errorf("buffered response model = %q, want %q", got, tc.want)
			}
			for i, chunk := range parseChunks(t, feedWithShared(t, p, shared, anthropicStreamWithoutModel())) {
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
	const configured = "claude-sonnet-4-20250514"
	p := &TranslatorPolicy{params: PolicyParams{Model: configured, AnthropicVersion: DefaultAnthropicVersion}}
	shared := &policy.SharedContext{RequestID: "req-1234", Metadata: map[string]interface{}{}}

	if got := bufferedModel(t, p, shared, anthropicBufferedBody); got != configured {
		t.Errorf("buffered response model = %q, want the configured %q", got, configured)
	}
	for i, chunk := range parseChunks(t, feedWithShared(t, p, shared, anthropicStreamWithoutModel())) {
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
