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
	"regexp"
	"strings"
	"sync"
	"testing"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

// ─── Fixtures / helpers ───────────────────────────────────────────────────────

func sseFrame(eventName, data string) string {
	return "event: " + eventName + "\ndata: " + data + "\n\n"
}

// anthropicTextStream is a complete Anthropic text response, including the ping
// and content_block_stop events that carry nothing translatable.
func anthropicTextStream() string {
	return sseFrame("message_start", `{"type":"message_start","message":{"id":"msg_01ABC","type":"message","role":"assistant","model":"claude-sonnet-4-20250514","content":[],"stop_reason":null,"usage":{"input_tokens":25,"cache_read_input_tokens":10,"cache_creation_input_tokens":5}}}`) +
		sseFrame("content_block_start", `{"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}`) +
		sseFrame("ping", `{"type":"ping"}`) +
		sseFrame("content_block_delta", `{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Hello"}}`) +
		sseFrame("content_block_delta", `{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":" world"}}`) +
		sseFrame("content_block_stop", `{"type":"content_block_stop","index":0}`) +
		sseFrame("message_delta", `{"type":"message_delta","delta":{"stop_reason":"end_turn","stop_sequence":null},"usage":{"output_tokens":15}}`) +
		sseFrame("message_stop", `{"type":"message_stop"}`)
}

// anthropicToolStream interleaves a text block with two tool_use blocks so the
// content-block index and the OpenAI tool_calls index deliberately diverge.
func anthropicToolStream() string {
	return sseFrame("message_start", `{"type":"message_start","message":{"id":"msg_02XYZ","type":"message","role":"assistant","model":"claude-sonnet-4-20250514","content":[],"usage":{"input_tokens":8}}}`) +
		sseFrame("content_block_start", `{"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}`) +
		sseFrame("content_block_delta", `{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Checking"}}`) +
		sseFrame("content_block_stop", `{"type":"content_block_stop","index":0}`) +
		sseFrame("content_block_start", `{"type":"content_block_start","index":1,"content_block":{"type":"tool_use","id":"toolu_01","name":"get_weather","input":{}}}`) +
		sseFrame("content_block_delta", `{"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"{\"location\":"}}`) +
		sseFrame("content_block_delta", `{"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"\"Paris\"}"}}`) +
		sseFrame("content_block_stop", `{"type":"content_block_stop","index":1}`) +
		sseFrame("content_block_start", `{"type":"content_block_start","index":2,"content_block":{"type":"tool_use","id":"toolu_02","name":"get_time","input":{}}}`) +
		sseFrame("content_block_delta", `{"type":"content_block_delta","index":2,"delta":{"type":"input_json_delta","partial_json":"{}"}}`) +
		sseFrame("message_delta", `{"type":"message_delta","delta":{"stop_reason":"tool_use"},"usage":{"output_tokens":40}}`) +
		sseFrame("message_stop", `{"type":"message_stop"}`)
}

// createdField matches the time-derived "created" value in an emitted chunk.
var createdField = regexp.MustCompile(`"created":\d+`)

// normalizeCreated rewrites "created" to a constant. streamState stamps it from
// time.Now().Unix() once per stream, so two streams generated either side of a
// second boundary differ by that field alone. Byte-exact comparisons between
// separately generated streams normalize it first.
func normalizeCreated(s string) string {
	return createdField.ReplaceAllString(s, `"created":0`)
}

func sseHeaders() *policy.Headers {
	return policy.NewHeaders(map[string][]string{"content-type": {"text/event-stream"}})
}

func testPolicy() *TranslatorPolicy {
	return &TranslatorPolicy{params: PolicyParams{
		Model: "claude-sonnet-4-20250514", AnthropicVersion: DefaultAnthropicVersion,
	}}
}

// feed drives the policy's streaming lifecycle over the given transport chunks
// exactly as the kernel would, and returns the concatenated downstream output.
func feed(t *testing.T, p *TranslatorPolicy, chunks []string) (string, bool) {
	t.Helper()
	respCtx := &policy.ResponseStreamContext{
		SharedContext:   &policy.SharedContext{RequestID: "req-1234", Metadata: map[string]interface{}{}},
		ResponseHeaders: sseHeaders(),
		ResponseStatus:  200,
	}

	var out strings.Builder
	for i, chunk := range chunks {
		action := p.OnResponseBodyChunk(context.Background(), respCtx, &policy.StreamBody{
			Chunk:       []byte(chunk),
			EndOfStream: i == len(chunks)-1,
			Index:       uint64(i),
		}, nil)

		switch typed := action.(type) {
		case policy.ForwardResponseChunk:
			out.Write(typed.Body)
		case policy.TerminateResponseChunk:
			out.Write(typed.Body)
			return out.String(), true
		default:
			t.Fatalf("unexpected streaming action %T", action)
		}
	}
	return out.String(), false
}

// parseChunks decodes every `data:` payload of the emitted stream, asserting the
// exact `data: {...}\n\n` framing and that [DONE] appears exactly once, last.
func parseChunks(t *testing.T, out string) []map[string]interface{} {
	t.Helper()
	if out == "" {
		return nil
	}
	if !strings.HasSuffix(out, "\n\n") {
		t.Fatalf("stream must end on an SSE boundary, got %q", out)
	}

	var chunks []map[string]interface{}
	events := strings.Split(strings.TrimSuffix(out, "\n\n"), "\n\n")
	for i, event := range events {
		payload, found := strings.CutPrefix(event, "data: ")
		if !found {
			t.Fatalf("event %d is not framed as %q: %q", i, "data: ", event)
		}
		if payload == "[DONE]" {
			if i != len(events)-1 {
				t.Fatalf("[DONE] must be the final event, found at %d of %d", i, len(events))
			}
			continue
		}
		var decoded map[string]interface{}
		if err := json.Unmarshal([]byte(payload), &decoded); err != nil {
			t.Fatalf("event %d is not valid JSON (%v): %q", i, err, payload)
		}
		chunks = append(chunks, decoded)
	}
	return chunks
}

func countDone(out string) int {
	return strings.Count(out, sseDonePayload)
}

// splitEvery cuts s into fixed-size transport chunks, deliberately slicing
// through SSE frames.
func splitEvery(s string, size int) []string {
	var chunks []string
	for start := 0; start < len(s); start += size {
		end := start + size
		if end > len(s) {
			end = len(s)
		}
		chunks = append(chunks, s[start:end])
	}
	return chunks
}

func firstChoice(t *testing.T, chunk map[string]interface{}) map[string]interface{} {
	t.Helper()
	choices, ok := chunk["choices"].([]interface{})
	if !ok || len(choices) == 0 {
		return nil
	}
	choice, _ := choices[0].(map[string]interface{})
	return choice
}

// collectContent joins every delta.content fragment in order.
func collectContent(t *testing.T, chunks []map[string]interface{}) string {
	t.Helper()
	var text strings.Builder
	for _, chunk := range chunks {
		choice := firstChoice(t, chunk)
		if choice == nil {
			continue
		}
		delta, _ := choice["delta"].(map[string]interface{})
		if content, ok := delta["content"].(string); ok {
			text.WriteString(content)
		}
	}
	return text.String()
}

// ─── Text streaming ───────────────────────────────────────────────────────────

func TestStream_TextInSingleChunk(t *testing.T) {
	out, terminated := feed(t, testPolicy(), []string{anthropicTextStream()})
	if terminated {
		t.Fatal("a well-formed stream must not terminate early")
	}
	chunks := parseChunks(t, out)

	if got := collectContent(t, chunks); got != "Hello world" {
		t.Errorf("streamed content = %q, want %q", got, "Hello world")
	}
	if countDone(out) != 1 {
		t.Errorf("expected exactly one [DONE], got %d in:\n%s", countDone(out), out)
	}

	// The first chunk must announce the assistant role and nothing else.
	role := firstChoice(t, chunks[0])
	delta, _ := role["delta"].(map[string]interface{})
	if delta["role"] != "assistant" {
		t.Errorf("first chunk delta = %v, want role=assistant", delta)
	}
	if _, hasContent := delta["content"]; hasContent {
		t.Errorf("role chunk must not carry content, got %v", delta)
	}

	for _, chunk := range chunks {
		if chunk["object"] != objectChatCompletionChunk {
			t.Errorf("object = %v, want %q", chunk["object"], objectChatCompletionChunk)
		}
	}
}

// TestStream_RoleEmittedOnce guards against a duplicate role chunk when the
// provider repeats message_start.
func TestStream_RoleEmittedOnce(t *testing.T) {
	stream := anthropicTextStream() +
		sseFrame("message_start", `{"type":"message_start","message":{"id":"msg_01ABC","usage":{"input_tokens":1}}}`)

	chunks := parseChunks(t, mustFeed(t, stream))
	roleChunks := 0
	for _, chunk := range chunks {
		choice := firstChoice(t, chunk)
		if choice == nil {
			continue
		}
		delta, _ := choice["delta"].(map[string]interface{})
		if _, hasRole := delta["role"]; hasRole {
			roleChunks++
		}
	}
	if roleChunks != 1 {
		t.Errorf("role chunks = %d, want 1", roleChunks)
	}
}

// ─── Transport splitting ──────────────────────────────────────────────────────

// TestStream_SplitAcrossTransportChunks feeds the same stream at every chunk
// size, including one byte at a time, and requires byte-identical output.
func TestStream_SplitAcrossTransportChunks(t *testing.T) {
	stream := anthropicTextStream()
	want := mustFeed(t, stream)

	for _, size := range []int{1, 2, 3, 7, 13, 64, 512} {
		got, terminated := feed(t, testPolicy(), splitEvery(stream, size))
		if terminated {
			t.Fatalf("chunk size %d terminated the stream unexpectedly", size)
		}
		if normalizeCreated(got) != normalizeCreated(want) {
			t.Errorf("chunk size %d produced different output\ngot:\n%s\nwant:\n%s", size, got, want)
		}
		if countDone(got) != 1 {
			t.Errorf("chunk size %d emitted %d [DONE] markers, want 1", size, countDone(got))
		}
	}
}

// TestStream_MultipleEventsInOneChunk covers the opposite extreme: many provider
// events arriving in a single transport flush.
func TestStream_MultipleEventsInOneChunk(t *testing.T) {
	stream := anthropicTextStream()
	half := strings.Index(stream, "event: content_block_delta")
	if half <= 0 {
		t.Fatal("fixture is missing a content_block_delta event")
	}

	got, _ := feed(t, testPolicy(), []string{stream[:half], stream[half:]})
	if want := mustFeed(t, stream); normalizeCreated(got) != normalizeCreated(want) {
		t.Errorf("two-flush output differs from single-flush output\ngot:\n%s\nwant:\n%s", got, want)
	}
}

// TestStream_PartialFrameHeldUntilComplete verifies that a flush ending mid-frame
// emits nothing for that frame and completes it on the next flush.
func TestStream_PartialFrameHeldUntilComplete(t *testing.T) {
	p := testPolicy()
	respCtx := &policy.ResponseStreamContext{
		SharedContext:   &policy.SharedContext{RequestID: "req-partial", Metadata: map[string]interface{}{}},
		ResponseHeaders: sseHeaders(),
		ResponseStatus:  200,
	}
	full := sseFrame("content_block_delta", `{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Hi"}}`)
	cut := len(full) - 10

	first := p.OnResponseBodyChunk(context.Background(), respCtx,
		&policy.StreamBody{Chunk: []byte(full[:cut])}, nil).(policy.ForwardResponseChunk)
	if len(first.Body) != 0 {
		t.Fatalf("partial frame must emit nothing, got %q", first.Body)
	}

	second := p.OnResponseBodyChunk(context.Background(), respCtx,
		&policy.StreamBody{Chunk: []byte(full[cut:]), Index: 1}, nil).(policy.ForwardResponseChunk)
	if !strings.Contains(string(second.Body), `"content":"Hi"`) {
		t.Fatalf("completed frame not emitted, got %q", second.Body)
	}
}

func TestStream_CRLFFraming(t *testing.T) {
	stream := strings.ReplaceAll(anthropicTextStream(), "\n", "\r\n")
	chunks := parseChunks(t, mustFeed(t, stream))
	if got := collectContent(t, chunks); got != "Hello world" {
		t.Errorf("CRLF-framed content = %q, want %q", got, "Hello world")
	}
}

// ─── Tool calls ───────────────────────────────────────────────────────────────

func TestStream_ToolCallArgumentDeltas(t *testing.T) {
	chunks := parseChunks(t, mustFeed(t, anthropicToolStream()))

	// Reassemble each tool call from its deltas, keyed by OpenAI tool index.
	names := map[float64]string{}
	ids := map[float64]string{}
	args := map[float64]string{}
	for _, chunk := range chunks {
		choice := firstChoice(t, chunk)
		if choice == nil {
			continue
		}
		delta, _ := choice["delta"].(map[string]interface{})
		toolCalls, _ := delta["tool_calls"].([]interface{})
		for _, raw := range toolCalls {
			call, _ := raw.(map[string]interface{})
			index, _ := call["index"].(float64)
			if id, ok := call["id"].(string); ok {
				ids[index] = id
			}
			fn, _ := call["function"].(map[string]interface{})
			if name, ok := fn["name"].(string); ok && name != "" {
				names[index] = name
			}
			if arg, ok := fn["arguments"].(string); ok {
				args[index] += arg
			}
		}
	}

	// Anthropic blocks 1 and 2 must become OpenAI tool indices 0 and 1 — the
	// leading text block must not consume an index.
	if names[0] != "get_weather" || names[1] != "get_time" {
		t.Errorf("tool names = %v, want index0=get_weather index1=get_time", names)
	}
	if ids[0] != "toolu_01" || ids[1] != "toolu_02" {
		t.Errorf("tool ids = %v, want index0=toolu_01 index1=toolu_02", ids)
	}
	if args[0] != `{"location":"Paris"}` {
		t.Errorf("tool 0 arguments = %q, want %q", args[0], `{"location":"Paris"}`)
	}
	if !json.Valid([]byte(args[0])) {
		t.Errorf("reassembled arguments must be valid JSON, got %q", args[0])
	}
	if args[1] != "{}" {
		t.Errorf("tool 1 arguments = %q, want %q", args[1], "{}")
	}
	if got := collectContent(t, chunks); got != "Checking" {
		t.Errorf("text content = %q, want %q", got, "Checking")
	}
}

// TestStream_ToolIndicesStableAcrossTransportSplits ensures the block→tool index
// mapping survives arbitrary chunk boundaries.
func TestStream_ToolIndicesStableAcrossTransportSplits(t *testing.T) {
	stream := anthropicToolStream()
	want := mustFeed(t, stream)
	for _, size := range []int{1, 5, 31, 256} {
		got, _ := feed(t, testPolicy(), splitEvery(stream, size))
		if normalizeCreated(got) != normalizeCreated(want) {
			t.Errorf("tool stream at chunk size %d differs\ngot:\n%s\nwant:\n%s", size, got, want)
		}
	}
}

// ─── Finish reasons ───────────────────────────────────────────────────────────

func TestStream_FinishReasonMapping(t *testing.T) {
	cases := map[string]string{
		"end_turn":      openaiFinishStop,
		"stop_sequence": openaiFinishStop,
		"max_tokens":    openaiFinishLength,
		"tool_use":      openaiFinishToolCalls,
	}

	for stopReason, want := range cases {
		stream := sseFrame("message_start", `{"type":"message_start","message":{"id":"msg_x","usage":{"input_tokens":1}}}`) +
			sseFrame("message_delta", `{"type":"message_delta","delta":{"stop_reason":"`+stopReason+`"},"usage":{"output_tokens":2}}`) +
			sseFrame("message_stop", `{"type":"message_stop"}`)

		got := ""
		for _, chunk := range parseChunks(t, mustFeed(t, stream)) {
			choice := firstChoice(t, chunk)
			if choice == nil {
				continue
			}
			if reason, ok := choice["finish_reason"].(string); ok {
				got = reason
			}
		}
		if normalizeCreated(got) != normalizeCreated(want) {
			t.Errorf("stop_reason %q → finish_reason %q, want %q", stopReason, got, want)
		}
	}
}

func TestStream_FinishReasonEmittedOnce(t *testing.T) {
	stream := anthropicTextStream() +
		sseFrame("message_delta", `{"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":15}}`)

	finishes := 0
	for _, chunk := range parseChunks(t, mustFeed(t, stream)) {
		choice := firstChoice(t, chunk)
		if choice == nil {
			continue
		}
		if reason, ok := choice["finish_reason"].(string); ok && reason != "" {
			finishes++
		}
	}
	if finishes != 1 {
		t.Errorf("finish_reason chunks = %d, want 1", finishes)
	}
}

// ─── Usage ────────────────────────────────────────────────────────────────────

func TestStream_UsageAndCacheTokens(t *testing.T) {
	chunks := parseChunks(t, mustFeed(t, anthropicTextStream()))

	var usage map[string]interface{}
	usageChunks := 0
	for _, chunk := range chunks {
		if candidate, ok := chunk["usage"].(map[string]interface{}); ok {
			usage = candidate
			usageChunks++
		}
	}
	if usageChunks != 1 {
		t.Fatalf("usage chunks = %d, want 1", usageChunks)
	}

	// input_tokens from message_start, output_tokens from message_delta.
	if usage["prompt_tokens"] != float64(25) || usage["completion_tokens"] != float64(15) {
		t.Errorf("usage = %v, want prompt=25 completion=15", usage)
	}
	if usage["total_tokens"] != float64(40) {
		t.Errorf("total_tokens = %v, want 40", usage["total_tokens"])
	}
	details, ok := usage["prompt_tokens_details"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected prompt_tokens_details, got %v", usage)
	}
	if details["cached_tokens"] != float64(10) || details["cache_creation_tokens"] != float64(5) {
		t.Errorf("cache details = %v, want cached=10 cache_creation=5", details)
	}
}

// TestStream_UsageChunkCarriesEmptyChoices matches the OpenAI convention for the
// terminal usage-only chunk.
func TestStream_UsageChunkCarriesEmptyChoices(t *testing.T) {
	for _, chunk := range parseChunks(t, mustFeed(t, anthropicTextStream())) {
		if _, hasUsage := chunk["usage"]; !hasUsage {
			continue
		}
		choices, ok := chunk["choices"].([]interface{})
		if !ok || len(choices) != 0 {
			t.Errorf("usage chunk choices = %v, want an empty array", chunk["choices"])
		}
	}
}

// ─── Identity stability ───────────────────────────────────────────────────────

func TestStream_StableIDModelAndCreated(t *testing.T) {
	chunks := parseChunks(t, mustFeed(t, anthropicTextStream()))
	if len(chunks) < 2 {
		t.Fatal("expected several chunks")
	}

	id, model, created := chunks[0]["id"], chunks[0]["model"], chunks[0]["created"]
	if id != "chatcmpl-01ABC" {
		t.Errorf("id = %v, want the message_start id rewritten to chatcmpl-01ABC", id)
	}
	if model != "claude-sonnet-4-20250514" {
		t.Errorf("model = %v, want the model reported by message_start", model)
	}
	for i, chunk := range chunks {
		if chunk["id"] != id {
			t.Errorf("chunk %d id = %v, want %v", i, chunk["id"], id)
		}
		if chunk["model"] != model {
			t.Errorf("chunk %d model = %v, want %v", i, chunk["model"], model)
		}
		if chunk["created"] != created {
			t.Errorf("chunk %d created = %v, want %v", i, chunk["created"], created)
		}
	}
	if _, isNumber := created.(float64); !isNumber {
		t.Errorf("created = %v, want a unix timestamp", created)
	}
}

// TestStream_IDFallsBackToRequestID covers a stream whose message_start carries
// no id: the id must still be stable across chunks.
func TestStream_IDFallsBackToRequestID(t *testing.T) {
	stream := sseFrame("message_start", `{"type":"message_start","message":{"model":"claude-x","usage":{"input_tokens":1}}}`) +
		sseFrame("content_block_delta", `{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"hi"}}`) +
		sseFrame("message_stop", `{"type":"message_stop"}`)

	chunks := parseChunks(t, mustFeed(t, stream))
	if chunks[0]["id"] != "chatcmpl-req1234" {
		t.Errorf("id = %v, want it derived from the request id", chunks[0]["id"])
	}
	for i, chunk := range chunks {
		if chunk["id"] != chunks[0]["id"] {
			t.Errorf("chunk %d id = %v, want %v", i, chunk["id"], chunks[0]["id"])
		}
	}
}

// ─── Errors and malformed input ───────────────────────────────────────────────

func TestStream_ProviderError(t *testing.T) {
	stream := sseFrame("message_start", `{"type":"message_start","message":{"id":"msg_e","usage":{"input_tokens":1}}}`) +
		sseFrame("error", `{"type":"error","error":{"type":"overloaded_error","message":"Overloaded"}}`)

	out, terminated := feed(t, testPolicy(), []string{stream})
	if !terminated {
		t.Error("a provider error must terminate the stream")
	}
	if countDone(out) != 0 {
		t.Errorf("an errored stream must not be terminated with [DONE], got:\n%s", out)
	}

	last := lastEventPayload(t, out)
	var decoded struct {
		Error struct {
			Type    string `json:"type"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal([]byte(last), &decoded); err != nil {
		t.Fatalf("final event is not JSON: %v (%q)", err, last)
	}
	if decoded.Error.Type != "overloaded_error" || decoded.Error.Message != "Overloaded" {
		t.Errorf("error event = %+v, want the upstream type and message preserved", decoded.Error)
	}
}

// TestStream_MalformedEventIsNotForwarded is the core safety property: provider
// bytes we cannot parse must never reach the client as an OpenAI chunk.
func TestStream_MalformedEventIsNotForwarded(t *testing.T) {
	stream := sseFrame("message_start", `{"type":"message_start","message":{"id":"msg_m","usage":{"input_tokens":1}}}`) +
		sseFrame("content_block_delta", `{"type":"content_block_delta",`) +
		sseFrame("content_block_delta", `{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"never"}}`)

	out, terminated := feed(t, testPolicy(), []string{stream})
	if !terminated {
		t.Error("a malformed event must terminate the stream")
	}
	if strings.Contains(out, `{"type":"content_block_delta",`) {
		t.Errorf("malformed provider bytes were forwarded verbatim:\n%s", out)
	}
	if strings.Contains(out, "never") {
		t.Errorf("events after a malformed one must not be emitted:\n%s", out)
	}
	if !strings.Contains(out, `"error"`) {
		t.Errorf("expected an OpenAI-style error event, got:\n%s", out)
	}
	// Every emitted event must still be well-formed OpenAI SSE.
	for _, event := range strings.Split(strings.TrimSuffix(out, "\n\n"), "\n\n") {
		payload, found := strings.CutPrefix(event, "data: ")
		if !found || !json.Valid([]byte(payload)) {
			t.Errorf("emitted malformed OpenAI event: %q", event)
		}
	}
}

// TestStream_TruncatedTailIsDropped covers an upstream stream cut off mid-frame:
// the partial frame must not produce partial OpenAI JSON.
func TestStream_TruncatedTailIsDropped(t *testing.T) {
	stream := sseFrame("message_start", `{"type":"message_start","message":{"id":"msg_t","usage":{"input_tokens":3}}}`) +
		sseFrame("content_block_delta", `{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"partial"}}`) +
		`event: content_block_delta` + "\n" + `data: {"type":"content_bl`

	out, terminated := feed(t, testPolicy(), []string{stream})
	if terminated {
		t.Error("a truncated tail should end the stream cleanly, not as a provider error")
	}
	if strings.Contains(out, "content_bl") {
		t.Errorf("truncated provider bytes leaked downstream:\n%s", out)
	}
	if countDone(out) != 1 {
		t.Errorf("expected exactly one [DONE], got %d in:\n%s", countDone(out), out)
	}
	parseChunks(t, out)
}

// TestStream_ErrorPreservesUpstreamStatus checks that a failed upstream response
// keeps its status code in the emitted OpenAI error.
func TestStream_ErrorPreservesUpstreamStatus(t *testing.T) {
	p := testPolicy()
	respCtx := &policy.ResponseStreamContext{
		SharedContext:   &policy.SharedContext{RequestID: "req-429", Metadata: map[string]interface{}{}},
		ResponseHeaders: sseHeaders(),
		ResponseStatus:  429,
	}
	frame := sseFrame("content_block_delta", `{"type":"content_block_delta"`)

	action := p.OnResponseBodyChunk(context.Background(), respCtx,
		&policy.StreamBody{Chunk: []byte(frame), EndOfStream: true}, nil)
	terminate, ok := action.(policy.TerminateResponseChunk)
	if !ok {
		t.Fatalf("expected TerminateResponseChunk, got %T", action)
	}
	if !strings.Contains(string(terminate.Body), `"code":"429"`) {
		t.Errorf("error event must preserve the upstream status, got %s", terminate.Body)
	}
	if !strings.Contains(string(terminate.Body), `"rate_limit_error"`) {
		t.Errorf("error type should map from status 429, got %s", terminate.Body)
	}
}

// ─── Kernel contract ──────────────────────────────────────────────────────────

func TestNeedsMoreResponseData_SSEBoundaries(t *testing.T) {
	p := testPolicy()
	frame := sseFrame("ping", `{"type":"ping"}`)

	if p.NeedsMoreResponseData([]byte(frame)) {
		t.Error("a complete frame should not request more data")
	}
	if !p.NeedsMoreResponseData([]byte(frame[:len(frame)-2])) {
		t.Error("a frame missing its blank-line terminator should request more data")
	}
	if p.NeedsMoreResponseData(nil) {
		t.Error("an empty accumulator should not request more data")
	}
	if p.NeedsMoreResponseData([]byte(`{"error":{"message":"boom"}}`)) {
		t.Error("non-SSE data must not stall the stream")
	}
	if !p.NeedsMoreResponseData([]byte(strings.ReplaceAll(frame, "\n", "\r\n")[:len(frame)])) {
		t.Error("a partial CRLF frame should request more data")
	}
}

func TestOnResponseHeaders_RewritesStreamingHeaders(t *testing.T) {
	p := testPolicy()

	action := p.OnResponseHeaders(context.Background(), &policy.ResponseHeaderContext{
		SharedContext:   &policy.SharedContext{Metadata: map[string]interface{}{}},
		ResponseHeaders: policy.NewHeaders(map[string][]string{"content-type": {"text/event-stream; charset=utf-8"}}),
	}, nil)
	mods, ok := action.(policy.DownstreamResponseHeaderModifications)
	if !ok {
		t.Fatalf("expected header modifications, got %T", action)
	}
	if mods.HeadersToSet["content-type"] != "text/event-stream" {
		t.Errorf("content-type = %v, want text/event-stream", mods.HeadersToSet)
	}
	if len(mods.HeadersToRemove) != 1 || mods.HeadersToRemove[0] != "content-length" {
		t.Errorf("HeadersToRemove = %v, want [content-length]", mods.HeadersToRemove)
	}

	jsonAction := p.OnResponseHeaders(context.Background(), &policy.ResponseHeaderContext{
		SharedContext:   &policy.SharedContext{Metadata: map[string]interface{}{}},
		ResponseHeaders: policy.NewHeaders(map[string][]string{"content-type": {"application/json"}}),
	}, nil)
	if mods := jsonAction.(policy.DownstreamResponseHeaderModifications); len(mods.HeadersToSet) != 0 {
		t.Errorf("JSON responses must keep their headers, got %v", mods.HeadersToSet)
	}
}

// TestStream_NonSSEChunksPassThrough guards the buffered-fallback boundary: a
// non-stream body must not be mangled by the chunk path.
func TestStream_NonSSEChunksPassThrough(t *testing.T) {
	p := testPolicy()
	respCtx := &policy.ResponseStreamContext{
		SharedContext:   &policy.SharedContext{RequestID: "req-json", Metadata: map[string]interface{}{}},
		ResponseHeaders: policy.NewHeaders(map[string][]string{"content-type": {"application/json"}}),
		ResponseStatus:  200,
	}

	action := p.OnResponseBodyChunk(context.Background(), respCtx,
		&policy.StreamBody{Chunk: []byte(`{"id":"msg_1"}`), EndOfStream: true}, nil)
	forward, ok := action.(policy.ForwardResponseChunk)
	if !ok {
		t.Fatalf("expected ForwardResponseChunk, got %T", action)
	}
	if forward.Body != nil {
		t.Errorf("non-SSE chunks must pass through untouched, got %q", forward.Body)
	}
}

func TestPolicyPhases_HandleNilSharedContext(t *testing.T) {
	p := testPolicy()

	if _, ok := p.OnResponseHeaders(context.Background(),
		&policy.ResponseHeaderContext{}, nil).(policy.DownstreamResponseHeaderModifications); !ok {
		t.Fatal("response-header phase must handle a nil SharedContext")
	}
	if _, ok := p.OnResponseBody(context.Background(),
		&policy.ResponseContext{}, nil).(policy.DownstreamResponseModifications); !ok {
		t.Fatal("response phase must handle a nil SharedContext")
	}
	if _, ok := p.OnResponseBodyChunk(context.Background(), &policy.ResponseStreamContext{},
		&policy.StreamBody{EndOfStream: true}, nil).(policy.ForwardResponseChunk); !ok {
		t.Fatal("streaming response phase must handle a nil SharedContext")
	}
	if _, ok := p.OnRequestBody(context.Background(),
		&policy.RequestContext{}, nil).(policy.ImmediateResponse); !ok {
		t.Fatal("request phase must handle a nil SharedContext")
	}
}

// TestStream_StateIsolatedPerRequest runs concurrent streams through one shared
// policy instance — the kernel reuses a single instance across requests, so all
// per-stream state must live in the per-request SharedContext.
func TestStream_StateIsolatedPerRequest(t *testing.T) {
	p := testPolicy()
	want := mustFeed(t, anthropicTextStream())

	var wg sync.WaitGroup
	results := make([]string, 16)
	for i := range results {
		wg.Add(1)
		go func(slot int) {
			defer wg.Done()
			respCtx := &policy.ResponseStreamContext{
				SharedContext:   &policy.SharedContext{RequestID: "req-1234", Metadata: map[string]interface{}{}},
				ResponseHeaders: sseHeaders(),
				ResponseStatus:  200,
			}
			var out strings.Builder
			chunks := splitEvery(anthropicTextStream(), 9)
			for j, chunk := range chunks {
				action := p.OnResponseBodyChunk(context.Background(), respCtx, &policy.StreamBody{
					Chunk:       []byte(chunk),
					EndOfStream: j == len(chunks)-1,
					Index:       uint64(j),
				}, nil)
				out.Write(action.(policy.ForwardResponseChunk).Body)
			}
			results[slot] = out.String()
		}(i)
	}
	wg.Wait()

	for i, got := range results {
		if normalizeCreated(got) != normalizeCreated(want) {
			t.Fatalf("concurrent stream %d differs from the sequential result\ngot:\n%s\nwant:\n%s", i, got, want)
		}
	}
}

// ─── Buffered fallback ────────────────────────────────────────────────────────

// TestOnResponseBody_TranslatesBufferedSSE ensures a chain that cannot stream
// still yields OpenAI SSE rather than native Anthropic events.
func TestOnResponseBody_TranslatesBufferedSSE(t *testing.T) {
	p := testPolicy()
	action := p.OnResponseBody(context.Background(), &policy.ResponseContext{
		SharedContext:   &policy.SharedContext{RequestID: "req-buffered", Metadata: map[string]interface{}{}},
		ResponseHeaders: sseHeaders(),
		ResponseBody:    &policy.Body{Content: []byte(anthropicTextStream()), Present: true},
		ResponseStatus:  200,
	}, nil)

	mods, ok := action.(policy.DownstreamResponseModifications)
	if !ok {
		t.Fatalf("expected response modifications, got %T", action)
	}
	out := string(mods.Body)
	if strings.Contains(out, "event: message_start") {
		t.Errorf("buffered SSE must be translated, not passed through:\n%s", out)
	}
	if countDone(out) != 1 {
		t.Errorf("expected exactly one [DONE], got %d", countDone(out))
	}
	if got := collectContent(t, parseChunks(t, out)); got != "Hello world" {
		t.Errorf("buffered content = %q, want %q", got, "Hello world")
	}
	if mods.HeadersToSet["content-type"] != "text/event-stream" {
		t.Errorf("content-type = %v, want text/event-stream", mods.HeadersToSet)
	}
	if len(mods.HeadersToRemove) != 1 || mods.HeadersToRemove[0] != "content-length" {
		t.Errorf("HeadersToRemove = %v, want [content-length]", mods.HeadersToRemove)
	}
}

// TestOnResponseBody_NonStreamingUnchanged is the no-regression guard for the
// existing buffered JSON path.
func TestOnResponseBody_NonStreamingUnchanged(t *testing.T) {
	body := `{"id":"msg_01","type":"message","role":"assistant","model":"claude-sonnet-4-20250514",` +
		`"content":[{"type":"text","text":"Hello"}],"stop_reason":"end_turn",` +
		`"usage":{"input_tokens":10,"output_tokens":5}}`

	action := testPolicy().OnResponseBody(context.Background(), &policy.ResponseContext{
		SharedContext:   &policy.SharedContext{RequestID: "req-json", Metadata: map[string]interface{}{}},
		ResponseHeaders: policy.NewHeaders(map[string][]string{"content-type": {"application/json"}}),
		ResponseBody:    &policy.Body{Content: []byte(body), Present: true},
		ResponseStatus:  200,
	}, nil)

	mods, ok := action.(policy.DownstreamResponseModifications)
	if !ok {
		t.Fatalf("expected response modifications, got %T", action)
	}
	var decoded map[string]interface{}
	if err := json.Unmarshal(mods.Body, &decoded); err != nil {
		t.Fatalf("translated body is not JSON: %v", err)
	}
	if decoded["object"] != "chat.completion" {
		t.Errorf("object = %v, want chat.completion (non-streaming must be unchanged)", decoded["object"])
	}
	if mods.HeadersToSet["content-type"] != "application/json" {
		t.Errorf("content-type = %v, want application/json", mods.HeadersToSet)
	}
}

// ─── Unit-level framing ───────────────────────────────────────────────────────

func TestSplitSSEEvents(t *testing.T) {
	frames, residual := splitSSEEvents([]byte("data: a\n\ndata: b\r\n\r\ndata: par"))
	if len(frames) != 2 {
		t.Fatalf("frames = %d, want 2", len(frames))
	}
	if got := sseDataPayload(frames[0]); got != "a" {
		t.Errorf("frame 0 payload = %q, want %q", got, "a")
	}
	if got := sseDataPayload(frames[1]); got != "b" {
		t.Errorf("frame 1 payload = %q, want %q", got, "b")
	}
	if string(residual) != "data: par" {
		t.Errorf("residual = %q, want %q", residual, "data: par")
	}
}

func TestSSEDataPayload_JoinsAndIgnoresOtherFields(t *testing.T) {
	frame := []byte(": comment\nevent: message_delta\nid: 7\ndata: {\"a\":1}\ndata: {\"b\":2}")
	if got := sseDataPayload(frame); got != "{\"a\":1}\n{\"b\":2}" {
		t.Errorf("payload = %q, want the data lines joined with a newline", got)
	}
	if got := sseDataPayload([]byte(": heartbeat")); got != "" {
		t.Errorf("comment-only frame payload = %q, want empty", got)
	}
}

// ─── Helpers used by the tests above ──────────────────────────────────────────

func mustFeed(t *testing.T, stream string) string {
	t.Helper()
	out, _ := feed(t, testPolicy(), []string{stream})
	return out
}

func lastEventPayload(t *testing.T, out string) string {
	t.Helper()
	events := strings.Split(strings.TrimSuffix(out, "\n\n"), "\n\n")
	last := events[len(events)-1]
	payload, found := strings.CutPrefix(last, "data: ")
	if !found {
		t.Fatalf("final event is not framed as a data line: %q", last)
	}
	return payload
}

// ─── Extended thinking and multibyte content ──────────────────────────────────

// TestStream_ThinkingDeltasExcluded pins the documented behaviour that extended
// thinking has no OpenAI Chat Completions streaming equivalent: it must not
// surface as assistant content, and must not break the surrounding stream.
func TestStream_ThinkingDeltasExcluded(t *testing.T) {
	stream := sseFrame("message_start", `{"type":"message_start","message":{"id":"msg_th","model":"claude-x","usage":{"input_tokens":5}}}`) +
		sseFrame("content_block_start", `{"type":"content_block_start","index":0,"content_block":{"type":"thinking","thinking":""}}`) +
		sseFrame("content_block_delta", `{"type":"content_block_delta","index":0,"delta":{"type":"thinking_delta","thinking":"secret chain of thought"}}`) +
		sseFrame("content_block_delta", `{"type":"content_block_delta","index":0,"delta":{"type":"signature_delta","signature":"abc123sig"}}`) +
		sseFrame("content_block_stop", `{"type":"content_block_stop","index":0}`) +
		sseFrame("content_block_start", `{"type":"content_block_start","index":1,"content_block":{"type":"text","text":""}}`) +
		sseFrame("content_block_delta", `{"type":"content_block_delta","index":1,"delta":{"type":"text_delta","text":"visible answer"}}`) +
		sseFrame("message_delta", `{"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":9}}`) +
		sseFrame("message_stop", `{"type":"message_stop"}`)

	out := mustFeed(t, stream)
	if strings.Contains(out, "secret chain of thought") || strings.Contains(out, "abc123sig") {
		t.Errorf("thinking content must never reach the client:\n%s", out)
	}
	chunks := parseChunks(t, out)
	if got := collectContent(t, chunks); got != "visible answer" {
		t.Errorf("content = %q, want %q", got, "visible answer")
	}
	// A thinking block must not consume a tool_calls index.
	for _, chunk := range chunks {
		choice := firstChoice(t, chunk)
		if choice == nil {
			continue
		}
		delta, _ := choice["delta"].(map[string]interface{})
		if _, hasTools := delta["tool_calls"]; hasTools {
			t.Errorf("thinking blocks must not produce tool_calls: %v", delta)
		}
	}
	if countDone(out) != 1 {
		t.Errorf("expected exactly one [DONE], got %d", countDone(out))
	}
}

// TestStream_MultibyteContentSurvivesByteSplits feeds a stream containing
// multi-byte UTF-8 one byte at a time, so code points are deliberately torn
// across transport chunks. The splitter is byte-based, so this proves
// reassembly happens before any JSON decoding.
func TestStream_MultibyteContentSurvivesByteSplits(t *testing.T) {
	const text = "こんにちは 🌏 café naïve — ünïcödé"
	encoded, err := json.Marshal(text)
	if err != nil {
		t.Fatal(err)
	}
	stream := sseFrame("message_start", `{"type":"message_start","message":{"id":"msg_mb","model":"claude-x","usage":{"input_tokens":1}}}`) +
		sseFrame("content_block_delta", `{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":`+string(encoded)+`}}`) +
		sseFrame("message_delta", `{"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":2}}`) +
		sseFrame("message_stop", `{"type":"message_stop"}`)

	whole := mustFeed(t, stream)
	if got := collectContent(t, parseChunks(t, whole)); got != text {
		t.Fatalf("multibyte content = %q, want %q", got, text)
	}
	// One byte at a time tears every multi-byte code point across callbacks.
	for _, size := range []int{1, 2, 3} {
		got, _ := feed(t, testPolicy(), splitEvery(stream, size))
		if normalizeCreated(got) != normalizeCreated(whole) {
			t.Errorf("chunk size %d corrupted multibyte content\ngot:\n%s\nwant:\n%s", size, got, whole)
		}
		if decoded := collectContent(t, parseChunks(t, got)); decoded != text {
			t.Errorf("chunk size %d decoded content = %q, want %q", size, decoded, text)
		}
	}
}

// TestStream_NilSharedContextForwardsUnchanged guards the degradation path: with
// no per-request store the residual buffer and once-only flags cannot survive
// between chunks, so the policy must forward provider bytes untouched rather
// than emit duplicated role events and multiple [DONE] markers.
func TestStream_NilSharedContextForwardsUnchanged(t *testing.T) {
	p := testPolicy()
	respCtx := &policy.ResponseStreamContext{ResponseHeaders: sseHeaders(), ResponseStatus: 200}

	stream := anthropicTextStream()
	chunks := splitEvery(stream, 9)
	var out strings.Builder
	for i, chunk := range chunks {
		action := p.OnResponseBodyChunk(context.Background(), respCtx, &policy.StreamBody{
			Chunk:       []byte(chunk),
			EndOfStream: i == len(chunks)-1,
			Index:       uint64(i),
		}, nil)
		forward, ok := action.(policy.ForwardResponseChunk)
		if !ok {
			t.Fatalf("chunk %d: expected ForwardResponseChunk, got %T", i, action)
		}
		if forward.Body != nil {
			t.Fatalf("chunk %d: expected passthrough (nil body), got %q", i, forward.Body)
		}
		out.WriteString(chunk)
	}
	if out.String() != stream {
		t.Error("passthrough must not alter the provider bytes")
	}
	if n := strings.Count(out.String(), "data: [DONE]"); n != 0 {
		t.Errorf("passthrough must not synthesise [DONE], got %d", n)
	}
}

// TestStreamFailureFaults pins the fault a terminated stream declares, on both the streaming
// and the buffered path. A provider error event is FaultCodeProviderStreamFailed; a frame the
// translator cannot parse is its own failure, FaultCodeMediationFailed. The buffered path sends
// the same bytes as the streaming one, and a stream that ends cleanly declares no fault.
func TestStreamFailureFaults(t *testing.T) {
	cases := []struct {
		name     string
		stream   string
		wantCode string
	}{
		{"provider error event", sseFrame("error", `{"type":"error","error":{"type":"overloaded_error","message":"Overloaded"}}`), policy.FaultCodeProviderStreamFailed},
		{"malformed frame", sseFrame("content_block_delta", `{"type":"content_block_delta"`), policy.FaultCodeMediationFailed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stream := sseFrame("message_start", `{"type":"message_start","message":{"id":"msg_f","usage":{"input_tokens":3}}}`) + tc.stream
			action := testPolicy().OnResponseBodyChunk(context.Background(), &policy.ResponseStreamContext{
				SharedContext:   &policy.SharedContext{RequestID: "req-fault", Metadata: map[string]interface{}{}},
				ResponseHeaders: sseHeaders(),
				ResponseStatus:  200,
			}, &policy.StreamBody{Chunk: []byte(stream), EndOfStream: true}, nil)
			terminate, ok := action.(policy.TerminateResponseChunk)
			if !ok {
				t.Fatalf("expected TerminateResponseChunk, got %T", action)
			}
			assertStreamFault(t, terminate.IsFault, terminate.Fault, tc.wantCode)

			buffered := testPolicy().OnResponseBody(context.Background(), &policy.ResponseContext{
				SharedContext:   &policy.SharedContext{RequestID: "req-fault", Metadata: map[string]interface{}{}},
				ResponseHeaders: sseHeaders(),
				ResponseBody:    &policy.Body{Content: []byte(stream), Present: true},
				ResponseStatus:  200,
			}, nil)
			mods, ok := buffered.(policy.DownstreamResponseModifications)
			if !ok {
				t.Fatalf("expected DownstreamResponseModifications, got %T", buffered)
			}
			assertStreamFault(t, mods.IsFault, mods.Fault, tc.wantCode)
			if normalizeCreated(string(mods.Body)) != normalizeCreated(string(terminate.Body)) {
				t.Errorf("buffered body differs from the streamed one:\n%s\nvs\n%s", mods.Body, terminate.Body)
			}
			if mods.StatusCode != nil {
				t.Errorf("the buffered path must not change the status, got %d", *mods.StatusCode)
			}
		})
	}

	t.Run("clean stream", func(t *testing.T) {
		buffered := testPolicy().OnResponseBody(context.Background(), &policy.ResponseContext{
			SharedContext:   &policy.SharedContext{RequestID: "req-clean", Metadata: map[string]interface{}{}},
			ResponseHeaders: sseHeaders(),
			ResponseBody:    &policy.Body{Content: []byte(anthropicTextStream()), Present: true},
			ResponseStatus:  200,
		}, nil)
		mods := buffered.(policy.DownstreamResponseModifications)
		if mods.IsFault || mods.Fault != nil {
			t.Errorf("a clean stream must not declare a fault, got %+v", mods.Fault)
		}
	})
}

func assertStreamFault(t *testing.T, isFault bool, fault *policy.FaultDetails, wantCode string) {
	t.Helper()
	if !isFault || fault == nil {
		t.Fatalf("expected a fault, got IsFault=%v Fault=%v", isFault, fault)
	}
	if fault.Code != wantCode || fault.Type != policy.FaultTypeMediation || fault.Direction != policy.DirectionResponse {
		t.Errorf("fault = %s/%s/%s, want %s/%s/%s", fault.Code, fault.Type, fault.Direction,
			wantCode, policy.FaultTypeMediation, policy.DirectionResponse)
	}
}
