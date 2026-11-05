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

package openaitomistral

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

// streamCtx builds a response stream context with the given content-type and
// shared metadata, mirroring what the kernel supplies on the streaming path.
func streamCtx(contentType string, metadata map[string]interface{}, status int) *policy.ResponseStreamContext {
	headers := policy.NewHeaders(map[string][]string{})
	if contentType != "" {
		headers = policy.NewHeaders(map[string][]string{"content-type": {contentType}})
	}
	return &policy.ResponseStreamContext{
		SharedContext:   newSharedCtx(metadata),
		ResponseHeaders: headers,
		ResponseStatus:  status,
	}
}

// TestMode_DeclaresResponseStreaming is the regression guard for the defect
// this streaming phase exists to fix. A BodyModeBuffer declaration here sets
// SupportsResponseStreaming=false for the whole policy chain, which switched
// off incremental delivery for every other provider sharing the route.
func TestMode_DeclaresResponseStreaming(t *testing.T) {
	mode := (&TranslatorPolicy{}).Mode()
	if mode.ResponseBodyMode != policy.BodyModeStream {
		t.Fatalf("ResponseBodyMode = %v, want BodyModeStream: a BUFFER declaration "+
			"disables response streaming for every policy on the route", mode.ResponseBodyMode)
	}
	var p policy.Policy = &TranslatorPolicy{}
	if _, ok := p.(policy.StreamingResponsePolicy); !ok {
		t.Fatal("declaring BodyModeStream without implementing StreamingResponsePolicy " +
			"makes the kernel fall back to buffered for the whole chain")
	}
}

// TestNeedsMoreResponseData covers the two regimes: an event stream is released
// as it arrives (that is what restores token-by-token delivery), anything else
// is held until the upstream closes so it can be translated as one document.
func TestNeedsMoreResponseData(t *testing.T) {
	p := &TranslatorPolicy{}
	cases := []struct {
		name        string
		accumulated string
		want        bool
	}{
		{"empty", "", false},
		{"sse data frame released immediately", "data: {\"id\":\"c\"}\n\n", false},
		{"sse partial frame still released", "data: {\"id\"", false},
		{"sse comment keep-alive released", ": ping\n\n", false},
		{"sse id field released", "id: 42\ndata: {}\n\n", false},
		{"sse retry field released", "retry: 1000\n\n", false},
		{"partial json held", `{"id":"cmpl-1","cho`, true},
		{"complete json held until close", `{"id":"cmpl-1"}`, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := p.NeedsMoreResponseData([]byte(tc.accumulated)); got != tc.want {
				t.Errorf("NeedsMoreResponseData(%q) = %v, want %v", tc.accumulated, got, tc.want)
			}
		})
	}
}

// TestOnResponseBodyChunk_SSEForwardedUntouched is the core streaming promise:
// Mistral's SSE frames are already OpenAI chunks, so every flush must reach the
// client byte for byte and without waiting for the next one.
func TestOnResponseBodyChunk_SSEForwardedUntouched(t *testing.T) {
	p := &TranslatorPolicy{params: PolicyParams{Model: "mistral-large-latest"}}
	respCtx := streamCtx("text/event-stream", map[string]interface{}{}, 200)

	frames := []string{
		"data: {\"id\":\"c\",\"choices\":[{\"delta\":{\"role\":\"assistant\"}}]}\n\n",
		"data: {\"id\":\"c\",\"choices\":[{\"delta\":{\"content\":\"Hi\"}}]}\n\n",
		"data: [DONE]\n\n",
	}
	for i, frame := range frames {
		action := p.OnResponseBodyChunk(context.Background(), respCtx,
			&policy.StreamBody{Chunk: []byte(frame), EndOfStream: i == len(frames)-1, Index: uint64(i)}, nil)
		fwd, ok := action.(policy.ForwardResponseChunk)
		if !ok {
			t.Fatalf("frame %d: expected ForwardResponseChunk, got %T", i, action)
		}
		if fwd.Body != nil {
			t.Errorf("frame %d: SSE must be forwarded untouched, got rewritten body %q", i, string(fwd.Body))
		}
	}
}

// TestOnResponseBodyChunk_MidFrameChunkStaysOnStreamPath pins the reason the
// verdict is cached. Only the first chunk is guaranteed to start on a frame
// boundary; a later one beginning mid-frame must not be re-classified as a JSON
// document and handed to the buffered translator.
func TestOnResponseBodyChunk_MidFrameChunkStaysOnStreamPath(t *testing.T) {
	p := &TranslatorPolicy{params: PolicyParams{Model: "mistral-large-latest"}}
	// No content-type at all, so the verdict can only come from the first bytes.
	respCtx := streamCtx("", map[string]interface{}{}, 200)

	first := p.OnResponseBodyChunk(context.Background(), respCtx,
		&policy.StreamBody{Chunk: []byte("data: {\"id\":\"c\"}\n\n"), Index: 0}, nil)
	if _, ok := first.(policy.ForwardResponseChunk); !ok {
		t.Fatalf("first chunk: expected ForwardResponseChunk, got %T", first)
	}

	// Starts mid-frame and looks nothing like SSE on its own.
	midFrame := []byte("\"choices\":[{\"delta\":{\"content\":\"Hi\"}}]}\n\n")
	second := p.OnResponseBodyChunk(context.Background(), respCtx,
		&policy.StreamBody{Chunk: midFrame, EndOfStream: true, Index: 1}, nil)
	fwd, ok := second.(policy.ForwardResponseChunk)
	if !ok {
		t.Fatalf("mid-frame chunk: expected ForwardResponseChunk, got %T", second)
	}
	if fwd.Body != nil {
		t.Errorf("mid-frame chunk must be forwarded untouched, got %q", string(fwd.Body))
	}
}

// TestOnResponseBodyChunk_ChunkedJSONErrorIsTranslated is the bug the streaming
// path has to cover: an error body framed chunked never reaches OnResponseBody,
// so without this the client would receive Mistral's envelope untranslated.
func TestOnResponseBodyChunk_ChunkedJSONErrorIsTranslated(t *testing.T) {
	p := &TranslatorPolicy{params: PolicyParams{Model: "mistral-large-latest"}}
	respCtx := streamCtx("application/json", map[string]interface{}{}, 429)

	body := []byte(`{"message":"Requests rate limit exceeded","type":"rate_limit","code":"3505"}`)
	action := p.OnResponseBodyChunk(context.Background(), respCtx,
		&policy.StreamBody{Chunk: body, EndOfStream: true, Index: 0}, nil)

	fwd, ok := action.(policy.ForwardResponseChunk)
	if !ok {
		t.Fatalf("expected ForwardResponseChunk, got %T", action)
	}
	if fwd.Body == nil {
		t.Fatal("expected the error envelope to be translated, got an untouched body")
	}
	var got struct {
		Error struct {
			Type    string `json:"type"`
			Message string `json:"message"`
			Code    string `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal(fwd.Body, &got); err != nil {
		t.Fatalf("translated error body is not JSON: %v (%s)", err, string(fwd.Body))
	}
	if got.Error.Message != "Requests rate limit exceeded" {
		t.Errorf("message = %q, want the upstream message", got.Error.Message)
	}
	if got.Error.Type != "rate_limit" {
		t.Errorf("type = %q, want %q", got.Error.Type, "rate_limit")
	}
	if got.Error.Code != "3505" {
		t.Errorf("code = %q, want %q", got.Error.Code, "3505")
	}
}

// TestOnResponseBodyChunk_ChunkedJSONSuccessBackfillsModel: the success body is
// already OpenAI-shaped, so the only translation owed is the model backfill —
// and it must still happen when the body arrives on the streaming path.
func TestOnResponseBodyChunk_ChunkedJSONSuccessBackfillsModel(t *testing.T) {
	p := &TranslatorPolicy{params: PolicyParams{Model: "mistral-large-latest"}}
	respCtx := streamCtx("application/json",
		map[string]interface{}{MetadataKeyEffectiveModel: "mistral-medium-latest"}, 200)

	body := []byte(`{"id":"cmpl-1","object":"chat.completion","model":"",` +
		`"choices":[{"index":0,"message":{"role":"assistant","content":"Hi"},"finish_reason":"stop"}]}`)
	action := p.OnResponseBodyChunk(context.Background(), respCtx,
		&policy.StreamBody{Chunk: body, EndOfStream: true, Index: 0}, nil)

	fwd, ok := action.(policy.ForwardResponseChunk)
	if !ok {
		t.Fatalf("expected ForwardResponseChunk, got %T", action)
	}
	var got map[string]interface{}
	if err := json.Unmarshal(fwd.Body, &got); err != nil {
		t.Fatalf("translated body is not JSON: %v", err)
	}
	if got["model"] != "mistral-medium-latest" {
		t.Errorf("model = %v, want the model that served the request", got["model"])
	}
}

// TestTranslateBufferedFlush_AccumulatorCapReportsError: when the kernel's
// accumulator cap fires the document is cut mid-body. The status and headers
// are long gone, so the close has to carry an OpenAI error envelope — an empty
// body would reach the client as a successful zero-length reply.
func TestTranslateBufferedFlush_AccumulatorCapReportsError(t *testing.T) {
	p := &TranslatorPolicy{params: PolicyParams{Model: "mistral-large-latest"}}
	respCtx := streamCtx("application/json", map[string]interface{}{}, 200)

	action := p.OnResponseBodyChunk(context.Background(), respCtx,
		&policy.StreamBody{Chunk: []byte(`{"id":"cmpl-1","choices":[{"mess`), EndOfStream: false, Index: 0}, nil)

	term, ok := action.(policy.TerminateResponseChunk)
	if !ok {
		t.Fatalf("expected TerminateResponseChunk on a truncated body, got %T", action)
	}
	if len(term.Body) == 0 {
		t.Fatal("a truncated response must close with an error envelope, not an empty body")
	}
	var got struct {
		Error struct {
			Type    string `json:"type"`
			Message string `json:"message"`
			Code    string `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal(term.Body, &got); err != nil {
		t.Fatalf("terminating body is not an OpenAI error envelope: %v (%s)", err, string(term.Body))
	}
	if got.Error.Code != "response_too_large" {
		t.Errorf("code = %q, want %q", got.Error.Code, "response_too_large")
	}
	if got.Error.Message == "" {
		t.Error("expected a human-readable message on the truncation error")
	}
}

// TestOnResponseBodyChunk_UnselectedProviderPassesThrough: on a multi-provider
// route every translator sees the chunk, so one that was not selected must
// leave it alone.
func TestOnResponseBodyChunk_UnselectedProviderPassesThrough(t *testing.T) {
	p := &TranslatorPolicy{params: PolicyParams{Model: "mistral-large-latest", ProviderID: "mistral-provider"}}
	respCtx := streamCtx("application/json",
		map[string]interface{}{MetadataKeySelectedProvider: "anthropic-provider"}, 429)

	action := p.OnResponseBodyChunk(context.Background(), respCtx,
		&policy.StreamBody{Chunk: []byte(`{"message":"nope"}`), EndOfStream: true, Index: 0}, nil)

	fwd, ok := action.(policy.ForwardResponseChunk)
	if !ok {
		t.Fatalf("expected ForwardResponseChunk, got %T", action)
	}
	if fwd.Body != nil {
		t.Errorf("an unselected translator must not rewrite the body, got %q", string(fwd.Body))
	}
}

// TestClassifyEventStream pins the precedence: the declared content-type wins,
// and the bytes decide only when it is absent or says nothing useful.
func TestClassifyEventStream(t *testing.T) {
	cases := []struct {
		name        string
		contentType string
		firstChunk  string
		want        bool
	}{
		{"declared sse", "text/event-stream; charset=utf-8", `{"id":"x"}`, true},
		{"declared json wins over sse-looking bytes", "application/json", "data: {}\n\n", false},
		{"no content-type, sse bytes", "", "data: {}\n\n", true},
		{"no content-type, comment keep-alive", "", ": ping\n\n", true},
		{"no content-type, json bytes", "", `{"id":"x"}`, false},
		{"unknown content-type falls back to bytes", "text/plain", "data: {}\n\n", true},
		{"unknown content-type, json bytes", "text/plain", `{"id":"x"}`, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			headers := policy.NewHeaders(map[string][]string{})
			if tc.contentType != "" {
				headers = policy.NewHeaders(map[string][]string{"content-type": {tc.contentType}})
			}
			if got := classifyEventStream(headers, []byte(tc.firstChunk)); got != tc.want {
				t.Errorf("classifyEventStream(%q, %q) = %v, want %v",
					tc.contentType, tc.firstChunk, got, tc.want)
			}
		})
	}
}

// TestLooksLikeSSE_CoversEveryOpeningLineType guards the widened sniff. A
// provider that opens with a keep-alive comment or an id/retry field is still
// an event stream, and reading it as a document would buffer a live stream.
func TestLooksLikeSSE_CoversEveryOpeningLineType(t *testing.T) {
	sse := []string{
		"data: {}\n\n",
		"event: message\ndata: {}\n\n",
		": ping\n\n",
		":\n\n",
		"id: 1\ndata: {}\n\n",
		"retry: 1000\n\n",
		"\n\n  data: {}\n\n",
		"\ufeffdata: {}\n\n",
	}
	for _, body := range sse {
		if !looksLikeSSE([]byte(body)) {
			t.Errorf("looksLikeSSE(%q) = false, want true", body)
		}
	}
	notSSE := []string{
		"",
		"   ",
		`{"id":"cmpl-1"}`,
		"\n  {\"id\":\"cmpl-1\"}",
		`["a","b"]`,
		"Internal Server Error",
	}
	for _, body := range notSSE {
		if looksLikeSSE([]byte(body)) {
			t.Errorf("looksLikeSSE(%q) = true, want false", body)
		}
	}
}

// TestBufferedActionToChunk_ImmediateResponseBecomesOpenAIEnvelope: the status
// an ImmediateResponse carries cannot be applied once headers are committed, so
// its flat {"error":"..."} body has to be re-rendered as the nested envelope an
// OpenAI client recognises.
func TestBufferedActionToChunk_ImmediateResponseBecomesOpenAIEnvelope(t *testing.T) {
	action := bufferedActionToChunk(errResponse(500, "failed to translate Mistral error: boom",
		policy.FaultCodeMediationFailed, policy.DirectionResponse, policy.FaultTypeMediation))

	term, ok := action.(policy.TerminateResponseChunk)
	if !ok {
		t.Fatalf("expected TerminateResponseChunk, got %T", action)
	}
	var got struct {
		Error struct {
			Type    string `json:"type"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(term.Body, &got); err != nil {
		t.Fatalf("body is not an OpenAI error envelope: %v (%s)", err, string(term.Body))
	}
	if !strings.Contains(got.Error.Message, "failed to translate Mistral error") {
		t.Errorf("message = %q, want the original failure text carried through", got.Error.Message)
	}
	if got.Error.Type != "server_error" {
		t.Errorf("type = %q, want %q", got.Error.Type, "server_error")
	}
}

// TestOnResponseBodyChunk_NilSharedContextDegradesSafely: the kernel always
// supplies a shared context, but without one the policy must still not panic.
func TestOnResponseBodyChunk_NilSharedContextDegradesSafely(t *testing.T) {
	p := &TranslatorPolicy{params: PolicyParams{Model: "mistral-large-latest"}}
	respCtx := &policy.ResponseStreamContext{
		ResponseHeaders: policy.NewHeaders(map[string][]string{"content-type": {"text/event-stream"}}),
		ResponseStatus:  200,
	}
	action := p.OnResponseBodyChunk(context.Background(), respCtx,
		&policy.StreamBody{Chunk: []byte("data: {}\n\n"), EndOfStream: true, Index: 0}, nil)
	if _, ok := action.(policy.ForwardResponseChunk); !ok {
		t.Fatalf("expected ForwardResponseChunk, got %T", action)
	}
}
