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
	"regexp"
	"strings"
	"sync"
	"testing"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

// ─── Fixtures / helpers ───────────────────────────────────────────────────────

func sseFrame(data string) string {
	return "data: " + data + "\n\n"
}

// geminiTextStream is a complete Gemini text response, including a thought part
// that must never reach the client as assistant content.
func geminiTextStream() string {
	return sseFrame(`{"candidates":[{"content":{"role":"model","parts":[{"text":"Hello"}]},"index":0}],"modelVersion":"gemini-2.5-pro","responseId":"resp-abc"}`) +
		sseFrame(`{"candidates":[{"content":{"role":"model","parts":[{"text":"thinking out loud","thought":true}]},"index":0}],"modelVersion":"gemini-2.5-pro"}`) +
		sseFrame(`{"candidates":[{"content":{"role":"model","parts":[{"text":" world"}]},"index":0}],"modelVersion":"gemini-2.5-pro"}`) +
		sseFrame(`{"candidates":[{"content":{"role":"model","parts":[{"text":"!"}]},"finishReason":"STOP","index":0}],"usageMetadata":{"promptTokenCount":12,"candidatesTokenCount":6,"totalTokenCount":26,"cachedContentTokenCount":4,"thoughtsTokenCount":8},"modelVersion":"gemini-2.5-pro"}`)
}

// geminiMultiCandidateStream interleaves two candidates across chunks.
func geminiMultiCandidateStream() string {
	return sseFrame(`{"candidates":[{"content":{"role":"model","parts":[{"text":"first-a"}]},"index":0},{"content":{"role":"model","parts":[{"text":"second-a"}]},"index":1}],"modelVersion":"gemini-2.5-pro","responseId":"resp-multi"}`) +
		sseFrame(`{"candidates":[{"content":{"role":"model","parts":[{"text":"second-b"}]},"index":1}],"modelVersion":"gemini-2.5-pro"}`) +
		sseFrame(`{"candidates":[{"content":{"role":"model","parts":[{"text":"first-b"}]},"finishReason":"STOP","index":0},{"content":{"role":"model","parts":[]},"finishReason":"MAX_TOKENS","index":1}],"usageMetadata":{"promptTokenCount":5,"candidatesTokenCount":4,"totalTokenCount":9},"modelVersion":"gemini-2.5-pro"}`)
}

func geminiToolStream() string {
	return sseFrame(`{"candidates":[{"content":{"role":"model","parts":[{"text":"Looking up"}]},"index":0}],"modelVersion":"gemini-2.5-pro","responseId":"resp-tool"}`) +
		sseFrame(`{"candidates":[{"content":{"role":"model","parts":[{"functionCall":{"name":"get_weather","args":{"location":"Paris","unit":"c"}}},{"functionCall":{"name":"get_time","args":{}}}]},"finishReason":"STOP","index":0}],"usageMetadata":{"promptTokenCount":9,"candidatesTokenCount":11,"totalTokenCount":20},"modelVersion":"gemini-2.5-pro"}`)
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
	return &TranslatorPolicy{params: PolicyParams{Model: "gemini-2.5-pro", APIVersion: DefaultAPIVersion}}
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

func mustFeed(t *testing.T, stream string) string {
	t.Helper()
	out, _ := feed(t, testPolicy(), []string{stream})
	return out
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

// contentByChoice joins every delta.content fragment, keyed by choice index.
func contentByChoice(t *testing.T, chunks []map[string]interface{}) map[int]string {
	t.Helper()
	content := map[int]string{}
	for _, chunk := range chunks {
		choice := firstChoice(t, chunk)
		if choice == nil {
			continue
		}
		index, _ := choice["index"].(float64)
		delta, _ := choice["delta"].(map[string]interface{})
		if text, ok := delta["content"].(string); ok {
			content[int(index)] += text
		}
	}
	return content
}

// ─── Text streaming ───────────────────────────────────────────────────────────

func TestStream_TextInSingleChunk(t *testing.T) {
	out, terminated := feed(t, testPolicy(), []string{geminiTextStream()})
	if terminated {
		t.Fatal("a well-formed stream must not terminate early")
	}
	chunks := parseChunks(t, out)

	if got := contentByChoice(t, chunks)[0]; got != "Hello world!" {
		t.Errorf("streamed content = %q, want %q", got, "Hello world!")
	}
	if countDone(out) != 1 {
		t.Errorf("expected exactly one [DONE], got %d in:\n%s", countDone(out), out)
	}

	role := firstChoice(t, chunks[0])
	delta, _ := role["delta"].(map[string]interface{})
	if delta["role"] != "assistant" {
		t.Errorf("first chunk delta = %v, want role=assistant", delta)
	}
	for _, chunk := range chunks {
		if chunk["object"] != objectChatCompletionChunk {
			t.Errorf("object = %v, want %q", chunk["object"], objectChatCompletionChunk)
		}
	}
}

// TestStream_ThoughtPartsExcluded is the guard that reasoning never leaks into
// visible assistant content.
func TestStream_ThoughtPartsExcluded(t *testing.T) {
	out := mustFeed(t, geminiTextStream())
	if strings.Contains(out, "thinking out loud") {
		t.Errorf("thought parts must not be emitted as content:\n%s", out)
	}
}

func TestStream_RoleEmittedOncePerChoice(t *testing.T) {
	chunks := parseChunks(t, mustFeed(t, geminiMultiCandidateStream()))

	roles := map[int]int{}
	for _, chunk := range chunks {
		choice := firstChoice(t, chunk)
		if choice == nil {
			continue
		}
		index, _ := choice["index"].(float64)
		delta, _ := choice["delta"].(map[string]interface{})
		if _, hasRole := delta["role"]; hasRole {
			roles[int(index)]++
		}
	}
	if roles[0] != 1 || roles[1] != 1 {
		t.Errorf("role chunks per choice = %v, want exactly one each for 0 and 1", roles)
	}
}

// ─── Multiple candidates ──────────────────────────────────────────────────────

func TestStream_MultipleCandidatesKeepTheirIndices(t *testing.T) {
	chunks := parseChunks(t, mustFeed(t, geminiMultiCandidateStream()))
	content := contentByChoice(t, chunks)

	if content[0] != "first-afirst-b" {
		t.Errorf("choice 0 content = %q, want %q", content[0], "first-afirst-b")
	}
	if content[1] != "second-asecond-b" {
		t.Errorf("choice 1 content = %q, want %q", content[1], "second-asecond-b")
	}

	// Each candidate's finish reason must land on its own choice index.
	finishes := map[int]string{}
	for _, chunk := range chunks {
		choice := firstChoice(t, chunk)
		if choice == nil {
			continue
		}
		index, _ := choice["index"].(float64)
		if reason, ok := choice["finish_reason"].(string); ok && reason != "" {
			finishes[int(index)] = reason
		}
	}
	if finishes[0] != openaiFinishStop || finishes[1] != openaiFinishLength {
		t.Errorf("finish reasons = %v, want choice0=stop choice1=length", finishes)
	}
}

// ─── Transport splitting ──────────────────────────────────────────────────────

func TestStream_SplitAcrossTransportChunks(t *testing.T) {
	stream := geminiTextStream()
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

func TestStream_MultipleEventsInOneChunk(t *testing.T) {
	stream := geminiTextStream()
	// Deliver frames 1-2 in one flush and the rest in another.
	split := strings.Index(stream[1:], "data: ") + 1
	split = strings.Index(stream[split+1:], "data: ") + split + 1

	got, _ := feed(t, testPolicy(), []string{stream[:split], stream[split:]})
	if want := mustFeed(t, stream); normalizeCreated(got) != normalizeCreated(want) {
		t.Errorf("two-flush output differs from single-flush output\ngot:\n%s\nwant:\n%s", got, want)
	}
}

func TestStream_PartialFrameHeldUntilComplete(t *testing.T) {
	p := testPolicy()
	respCtx := &policy.ResponseStreamContext{
		SharedContext:   &policy.SharedContext{RequestID: "req-partial", Metadata: map[string]interface{}{}},
		ResponseHeaders: sseHeaders(),
		ResponseStatus:  200,
	}
	full := sseFrame(`{"candidates":[{"content":{"role":"model","parts":[{"text":"Hi"}]},"index":0}]}`)
	cut := len(full) - 12

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
	stream := strings.ReplaceAll(geminiTextStream(), "\n", "\r\n")
	if got := contentByChoice(t, parseChunks(t, mustFeed(t, stream)))[0]; got != "Hello world!" {
		t.Errorf("CRLF-framed content = %q, want %q", got, "Hello world!")
	}
}

// ─── Tool calls ───────────────────────────────────────────────────────────────

func TestStream_FunctionCallsBecomeToolCalls(t *testing.T) {
	chunks := parseChunks(t, mustFeed(t, geminiToolStream()))

	type toolCall struct {
		id, name, args string
	}
	calls := map[float64]*toolCall{}
	for _, chunk := range chunks {
		choice := firstChoice(t, chunk)
		if choice == nil {
			continue
		}
		delta, _ := choice["delta"].(map[string]interface{})
		toolCalls, _ := delta["tool_calls"].([]interface{})
		for _, raw := range toolCalls {
			entry, _ := raw.(map[string]interface{})
			index, _ := entry["index"].(float64)
			if calls[index] == nil {
				calls[index] = &toolCall{}
			}
			if id, ok := entry["id"].(string); ok {
				calls[index].id = id
			}
			fn, _ := entry["function"].(map[string]interface{})
			if name, ok := fn["name"].(string); ok {
				calls[index].name = name
			}
			if args, ok := fn["arguments"].(string); ok {
				calls[index].args += args
			}
		}
	}

	if len(calls) != 2 {
		t.Fatalf("tool calls = %d, want 2", len(calls))
	}
	if calls[0].name != "get_weather" || calls[1].name != "get_time" {
		t.Errorf("tool names = %q/%q, want get_weather/get_time", calls[0].name, calls[1].name)
	}
	// arguments must be a JSON *string*, not an embedded object.
	var decoded map[string]interface{}
	if err := json.Unmarshal([]byte(calls[0].args), &decoded); err != nil {
		t.Fatalf("tool arguments must be a JSON string: %v (%q)", err, calls[0].args)
	}
	if decoded["location"] != "Paris" || decoded["unit"] != "c" {
		t.Errorf("decoded arguments = %v, want location=Paris unit=c", decoded)
	}
	if calls[1].args != "{}" {
		t.Errorf("empty args = %q, want %q", calls[1].args, "{}")
	}
	for index, call := range calls {
		if !strings.HasPrefix(call.id, "call_") {
			t.Errorf("tool %v id = %q, want a call_ prefix", index, call.id)
		}
	}
}

// TestStream_FunctionCallsFinishAsToolCalls covers the finish-reason override:
// a candidate that produced function calls must report tool_calls.
func TestStream_FunctionCallsFinishAsToolCalls(t *testing.T) {
	got := ""
	for _, chunk := range parseChunks(t, mustFeed(t, geminiToolStream())) {
		choice := firstChoice(t, chunk)
		if choice == nil {
			continue
		}
		if reason, ok := choice["finish_reason"].(string); ok && reason != "" {
			got = reason
		}
	}
	if got != openaiFinishToolCalls {
		t.Errorf("finish_reason = %q, want %q", got, openaiFinishToolCalls)
	}
}

// ─── Finish reasons ───────────────────────────────────────────────────────────

func TestStream_FinishReasonMapping(t *testing.T) {
	cases := map[string]string{
		geminiFinishStop:       openaiFinishStop,
		geminiFinishMaxTokens:  openaiFinishLength,
		geminiFinishSafety:     openaiFinishContentFilter,
		geminiFinishProhibited: openaiFinishContentFilter,
		geminiFinishBlocklist:  openaiFinishContentFilter,
		geminiFinishSPII:       openaiFinishContentFilter,
		geminiFinishRecitation: openaiFinishContentFilter,
		geminiFinishOther:      openaiFinishStop,
	}

	for reason, want := range cases {
		stream := sseFrame(`{"candidates":[{"content":{"role":"model","parts":[{"text":"x"}]},"finishReason":"` +
			reason + `","index":0}],"modelVersion":"gemini-2.5-pro"}`)

		got := ""
		for _, chunk := range parseChunks(t, mustFeed(t, stream)) {
			choice := firstChoice(t, chunk)
			if choice == nil {
				continue
			}
			if value, ok := choice["finish_reason"].(string); ok && value != "" {
				got = value
			}
		}
		if normalizeCreated(got) != normalizeCreated(want) {
			t.Errorf("finishReason %q → %q, want %q", reason, got, want)
		}
	}
}

// TestStream_FinishReasonMatchesNonStreaming pins the streaming mapping to the
// buffered translator so the two can never drift.
func TestStream_FinishReasonMatchesNonStreaming(t *testing.T) {
	for _, reason := range []string{
		geminiFinishStop, geminiFinishMaxTokens, geminiFinishSafety, geminiFinishRecitation,
		geminiFinishBlocklist, geminiFinishProhibited, geminiFinishSPII, geminiFinishImageRecit,
		geminiFinishLanguage, geminiFinishMalfunction, geminiFinishUnspecified, geminiFinishOther,
	} {
		for _, hasToolCalls := range []bool{false, true} {
			state := newStreamState("gemini-2.5-pro", "req", 200)
			candidate := geminiCandidate{FinishReason: reason}
			choice := state.choiceState(0)
			choice.sawToolCall = hasToolCalls

			out := string(state.translateCandidate(&candidate, 0))
			want := finishReasonToOpenAI(reason, hasToolCalls)
			if !strings.Contains(out, `"finish_reason":"`+want+`"`) {
				t.Errorf("streaming finish for %q (tools=%v) = %s, want %q", reason, hasToolCalls, out, want)
			}
		}
	}
}

func TestStream_FinishReasonEmittedOnce(t *testing.T) {
	stream := geminiTextStream() +
		sseFrame(`{"candidates":[{"content":{"role":"model","parts":[]},"finishReason":"STOP","index":0}]}`)

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

func TestStream_BlockedPromptBecomesContentFilter(t *testing.T) {
	stream := sseFrame(`{"promptFeedback":{"blockReason":"SAFETY"},"modelVersion":"gemini-2.5-pro"}`)

	got := ""
	for _, chunk := range parseChunks(t, mustFeed(t, stream)) {
		choice := firstChoice(t, chunk)
		if choice == nil {
			continue
		}
		if reason, ok := choice["finish_reason"].(string); ok && reason != "" {
			got = reason
		}
	}
	if got != openaiFinishContentFilter {
		t.Errorf("blocked prompt finish_reason = %q, want %q", got, openaiFinishContentFilter)
	}
}

// ─── Usage ────────────────────────────────────────────────────────────────────

func TestStream_UsageCachedAndReasoningTokens(t *testing.T) {
	chunks := parseChunks(t, mustFeed(t, geminiTextStream()))

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

	if usage["prompt_tokens"] != float64(12) {
		t.Errorf("prompt_tokens = %v, want 12", usage["prompt_tokens"])
	}
	// completion_tokens includes thought tokens, matching the buffered path.
	if usage["completion_tokens"] != float64(14) {
		t.Errorf("completion_tokens = %v, want 14 (candidates 6 + thoughts 8)", usage["completion_tokens"])
	}
	if usage["total_tokens"] != float64(26) {
		t.Errorf("total_tokens = %v, want 26", usage["total_tokens"])
	}
	promptDetails, ok := usage["prompt_tokens_details"].(map[string]interface{})
	if !ok || promptDetails["cached_tokens"] != float64(4) {
		t.Errorf("prompt_tokens_details = %v, want cached_tokens=4", usage["prompt_tokens_details"])
	}
	completionDetails, ok := usage["completion_tokens_details"].(map[string]interface{})
	if !ok || completionDetails["reasoning_tokens"] != float64(8) {
		t.Errorf("completion_tokens_details = %v, want reasoning_tokens=8", usage["completion_tokens_details"])
	}
}

func TestStream_UsageChunkCarriesEmptyChoices(t *testing.T) {
	for _, chunk := range parseChunks(t, mustFeed(t, geminiTextStream())) {
		if _, hasUsage := chunk["usage"]; !hasUsage {
			continue
		}
		choices, ok := chunk["choices"].([]interface{})
		if !ok || len(choices) != 0 {
			t.Errorf("usage chunk choices = %v, want an empty array", chunk["choices"])
		}
	}
}

// TestStream_NoUsageChunkWhenProviderReportsNone avoids inventing zeroed usage.
func TestStream_NoUsageChunkWhenProviderReportsNone(t *testing.T) {
	stream := sseFrame(`{"candidates":[{"content":{"role":"model","parts":[{"text":"hi"}]},"finishReason":"STOP","index":0}]}`)
	for _, chunk := range parseChunks(t, mustFeed(t, stream)) {
		if _, hasUsage := chunk["usage"]; hasUsage {
			t.Errorf("no usage metadata was reported, so no usage chunk should be emitted: %v", chunk)
		}
	}
}

// ─── Identity stability ───────────────────────────────────────────────────────

func TestStream_StableIDModelAndCreated(t *testing.T) {
	chunks := parseChunks(t, mustFeed(t, geminiTextStream()))
	if len(chunks) < 2 {
		t.Fatal("expected several chunks")
	}

	id, model, created := chunks[0]["id"], chunks[0]["model"], chunks[0]["created"]
	if id != "chatcmpl-resp-abc" {
		t.Errorf("id = %v, want it derived from responseId", id)
	}
	if model != "gemini-2.5-pro" {
		t.Errorf("model = %v, want the modelVersion reported by the provider", model)
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

// TestStream_IDIgnoresLaterResponseIDs keeps the completion id stable even if
// the provider varies responseId mid-stream.
func TestStream_IDIgnoresLaterResponseIDs(t *testing.T) {
	stream := sseFrame(`{"candidates":[{"content":{"role":"model","parts":[{"text":"a"}]},"index":0}],"responseId":"first"}`) +
		sseFrame(`{"candidates":[{"content":{"role":"model","parts":[{"text":"b"}]},"finishReason":"STOP","index":0}],"responseId":"second"}`)

	for _, chunk := range parseChunks(t, mustFeed(t, stream)) {
		if chunk["id"] != "chatcmpl-first" {
			t.Errorf("id = %v, want chatcmpl-first for every chunk", chunk["id"])
		}
	}
}

func TestStream_IDFallsBackToRequestID(t *testing.T) {
	stream := sseFrame(`{"candidates":[{"content":{"role":"model","parts":[{"text":"hi"}]},"finishReason":"STOP","index":0}]}`)
	chunks := parseChunks(t, mustFeed(t, stream))
	if chunks[0]["id"] != "chatcmpl-req1234" {
		t.Errorf("id = %v, want it derived from the request id", chunks[0]["id"])
	}
}

// ─── Errors and malformed input ───────────────────────────────────────────────

func TestStream_ProviderError(t *testing.T) {
	stream := sseFrame(`{"candidates":[{"content":{"role":"model","parts":[{"text":"partial"}]},"index":0}]}`) +
		sseFrame(`{"error":{"code":429,"message":"Resource exhausted","status":"RESOURCE_EXHAUSTED"}}`)

	out, terminated := feed(t, testPolicy(), []string{stream})
	if !terminated {
		t.Error("a provider error must terminate the stream")
	}
	if countDone(out) != 0 {
		t.Errorf("an errored stream must not be terminated with [DONE], got:\n%s", out)
	}

	var decoded struct {
		Error struct {
			Type    string `json:"type"`
			Message string `json:"message"`
			Code    string `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal([]byte(lastEventPayload(t, out)), &decoded); err != nil {
		t.Fatalf("final event is not JSON: %v", err)
	}
	if decoded.Error.Type != "RESOURCE_EXHAUSTED" || decoded.Error.Message != "Resource exhausted" {
		t.Errorf("error event = %+v, want the upstream status and message preserved", decoded.Error)
	}
	if decoded.Error.Code != "429" {
		t.Errorf("error code = %q, want 429", decoded.Error.Code)
	}
}

func TestStream_MalformedEventIsNotForwarded(t *testing.T) {
	stream := sseFrame(`{"candidates":[{"content":{"role":"model","parts":[{"text":"ok"}]},"index":0}]}`) +
		sseFrame(`{"candidates":[{"content":`) +
		sseFrame(`{"candidates":[{"content":{"role":"model","parts":[{"text":"never"}]},"index":0}]}`)

	out, terminated := feed(t, testPolicy(), []string{stream})
	if !terminated {
		t.Error("a malformed event must terminate the stream")
	}
	if strings.Contains(out, `{"candidates":[{"content":`) {
		t.Errorf("malformed provider bytes were forwarded verbatim:\n%s", out)
	}
	if strings.Contains(out, "never") {
		t.Errorf("events after a malformed one must not be emitted:\n%s", out)
	}
	if !strings.Contains(out, `"error"`) {
		t.Errorf("expected an OpenAI-style error event, got:\n%s", out)
	}
	for _, event := range strings.Split(strings.TrimSuffix(out, "\n\n"), "\n\n") {
		payload, found := strings.CutPrefix(event, "data: ")
		if !found || !json.Valid([]byte(payload)) {
			t.Errorf("emitted malformed OpenAI event: %q", event)
		}
	}
}

func TestStream_TruncatedTailIsDropped(t *testing.T) {
	stream := sseFrame(`{"candidates":[{"content":{"role":"model","parts":[{"text":"partial"}]},"index":0}],"usageMetadata":{"promptTokenCount":1,"candidatesTokenCount":1,"totalTokenCount":2}}`) +
		`data: {"candidates":[{"cont`

	out, terminated := feed(t, testPolicy(), []string{stream})
	if terminated {
		t.Error("a truncated tail should end the stream cleanly, not as a provider error")
	}
	if strings.Contains(out, `{"candidates":[{"cont`) {
		t.Errorf("truncated provider bytes leaked downstream:\n%s", out)
	}
	if countDone(out) != 1 {
		t.Errorf("expected exactly one [DONE], got %d in:\n%s", countDone(out), out)
	}
	parseChunks(t, out)
}

func TestStream_ErrorPreservesUpstreamStatus(t *testing.T) {
	p := testPolicy()
	respCtx := &policy.ResponseStreamContext{
		SharedContext:   &policy.SharedContext{RequestID: "req-500", Metadata: map[string]interface{}{}},
		ResponseHeaders: sseHeaders(),
		ResponseStatus:  503,
	}

	action := p.OnResponseBodyChunk(context.Background(), respCtx,
		&policy.StreamBody{Chunk: []byte(sseFrame(`{"candidates":`)), EndOfStream: true}, nil)
	terminate, ok := action.(policy.TerminateResponseChunk)
	if !ok {
		t.Fatalf("expected TerminateResponseChunk, got %T", action)
	}
	if !strings.Contains(string(terminate.Body), `"code":"503"`) {
		t.Errorf("error event must preserve the upstream status, got %s", terminate.Body)
	}
	if !strings.Contains(string(terminate.Body), `"server_error"`) {
		t.Errorf("error type should map from status 503, got %s", terminate.Body)
	}
}

// ─── Kernel contract ──────────────────────────────────────────────────────────

func TestNeedsMoreResponseData_SSEBoundaries(t *testing.T) {
	p := testPolicy()
	frame := sseFrame(`{"candidates":[]}`)

	if p.NeedsMoreResponseData([]byte(frame)) {
		t.Error("a complete frame should not request more data")
	}
	if !p.NeedsMoreResponseData([]byte(frame[:len(frame)-2])) {
		t.Error("a frame missing its blank-line terminator should request more data")
	}
	if p.NeedsMoreResponseData(nil) {
		t.Error("an empty accumulator should not request more data")
	}
	if !p.NeedsMoreResponseData([]byte(`{"error":{"message":"boom"}}`)) {
		t.Error("a body that is not an event stream must accumulate until the upstream closes")
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

// TestStream_NonSSEBodyIsTranslated covers the framing the gateway cannot tell
// apart from a stream: an ordinary JSON reply sent without content-length is
// routed through the chunk path, and must still be translated rather than
// forwarded in the provider's own format.
func TestStream_NonSSEBodyIsTranslated(t *testing.T) {
	p := testPolicy()
	respCtx := &policy.ResponseStreamContext{
		SharedContext:   &policy.SharedContext{RequestID: "req-json", Metadata: map[string]interface{}{}},
		ResponseHeaders: policy.NewHeaders(map[string][]string{"content-type": {"application/json"}}),
		ResponseStatus:  200,
	}

	action := p.OnResponseBodyChunk(context.Background(), respCtx,
		&policy.StreamBody{Chunk: []byte(geminiBufferedBody), EndOfStream: true}, nil)
	forward, ok := action.(policy.ForwardResponseChunk)
	if !ok {
		t.Fatalf("expected ForwardResponseChunk, got %T", action)
	}
	if forward.Body == nil {
		t.Fatal("a non-stream JSON body must be translated, not forwarded untouched")
	}
	var out map[string]interface{}
	if err := json.Unmarshal(forward.Body, &out); err != nil {
		t.Fatalf("translated body is not JSON: %v", err)
	}
	if out["object"] != "chat.completion" {
		t.Errorf("object = %v, want chat.completion", out["object"])
	}
	choices, _ := out["choices"].([]interface{})
	if len(choices) != 1 {
		t.Fatalf("choices = %v, want one entry", out["choices"])
	}
	msg, _ := choices[0].(map[string]interface{})["message"].(map[string]interface{})
	if msg["content"] != "Hi there" {
		t.Errorf("content = %v, want \"Hi there\"", msg["content"])
	}
}

// TestStream_NonSSEBodyTruncatedByAccumulatorCap covers the one case where a
// non-stream body reaches the chunk path incomplete: the policy engine's stream
// accumulator cap forces a flush before the upstream closes. The document is cut
// mid-body, so the stream is closed rather than a fragment emitted.
func TestStream_NonSSEBodyTruncatedByAccumulatorCap(t *testing.T) {
	p := testPolicy()
	respCtx := &policy.ResponseStreamContext{
		SharedContext:   &policy.SharedContext{RequestID: "req-trunc", Metadata: map[string]interface{}{}},
		ResponseHeaders: policy.NewHeaders(map[string][]string{"content-type": {"application/json"}}),
		ResponseStatus:  200,
	}

	action := p.OnResponseBodyChunk(context.Background(), respCtx,
		&policy.StreamBody{Chunk: []byte(geminiBufferedBody[:20]), EndOfStream: false}, nil)
	term, ok := action.(policy.TerminateResponseChunk)
	if !ok {
		t.Fatalf("expected TerminateResponseChunk for a truncated body, got %T", action)
	}
	if term.Body == nil {
		t.Error("Body must be an empty slice, not nil: a nil body leaves the chain " +
			"carrying the truncated document and delivers it to the client")
	}
	if len(term.Body) != 0 {
		t.Errorf("a truncated body must not be forwarded, got %q", term.Body)
	}
	// The status went out with the headers and is almost always 200, so IsFault
	// is the only thing that tells the fault flow this response failed.
	if !term.IsFault {
		t.Error("a truncated body is a failure and must be declared to the fault flow")
	}
	if term.Fault == nil {
		t.Fatal("expected Fault to be populated")
	}
	if term.Fault.Code != policy.FaultCodeMediationFailed {
		t.Errorf("Fault.Code = %q, want %q", term.Fault.Code, policy.FaultCodeMediationFailed)
	}
	if term.Fault.Type != policy.FaultTypeMediation {
		t.Errorf("Fault.Type = %q, want %q", term.Fault.Type, policy.FaultTypeMediation)
	}
	if term.Fault.Direction != policy.DirectionResponse {
		t.Errorf("Fault.Direction = %q, want %q", term.Fault.Direction, policy.DirectionResponse)
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
	want := mustFeed(t, geminiMultiCandidateStream())

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
			chunks := splitEvery(geminiMultiCandidateStream(), 11)
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

func TestOnResponseBody_TranslatesBufferedSSE(t *testing.T) {
	p := testPolicy()
	action := p.OnResponseBody(context.Background(), &policy.ResponseContext{
		SharedContext:   &policy.SharedContext{RequestID: "req-buffered", Metadata: map[string]interface{}{}},
		ResponseHeaders: sseHeaders(),
		ResponseBody:    &policy.Body{Content: []byte(geminiTextStream()), Present: true},
		ResponseStatus:  200,
	}, nil)

	mods, ok := action.(policy.DownstreamResponseModifications)
	if !ok {
		t.Fatalf("expected response modifications, got %T", action)
	}
	out := string(mods.Body)
	if strings.Contains(out, `"candidates"`) {
		t.Errorf("buffered SSE must be translated, not passed through:\n%s", out)
	}
	if countDone(out) != 1 {
		t.Errorf("expected exactly one [DONE], got %d", countDone(out))
	}
	if got := contentByChoice(t, parseChunks(t, out))[0]; got != "Hello world!" {
		t.Errorf("buffered content = %q, want %q", got, "Hello world!")
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
	body := `{"candidates":[{"content":{"role":"model","parts":[{"text":"Hello"}]},"finishReason":"STOP","index":0}],` +
		`"usageMetadata":{"promptTokenCount":10,"candidatesTokenCount":5,"totalTokenCount":15},` +
		`"modelVersion":"gemini-2.5-pro","responseId":"resp-1"}`

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

func TestSSEDataPayload_IgnoresCommentsAndOtherFields(t *testing.T) {
	frame := []byte(": keep-alive\nevent: message\nid: 3\ndata: {\"a\":1}")
	if got := sseDataPayload(frame); got != `{"a":1}` {
		t.Errorf("payload = %q, want the data line only", got)
	}
	if got := sseDataPayload([]byte(": heartbeat")); got != "" {
		t.Errorf("comment-only frame payload = %q, want empty", got)
	}
}

// ─── Helpers used by the tests above ──────────────────────────────────────────

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

// ─── Multibyte content ────────────────────────────────────────────────────────

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
	stream := sseFrame(`{"candidates":[{"content":{"role":"model","parts":[{"text":` + string(encoded) + `}]},"finishReason":"STOP","index":0}],"modelVersion":"gemini-2.5-pro","responseId":"resp-mb","usageMetadata":{"promptTokenCount":1,"candidatesTokenCount":2,"totalTokenCount":3}}`)

	whole := mustFeed(t, stream)
	if got := contentByChoice(t, parseChunks(t, whole))[0]; got != text {
		t.Fatalf("multibyte content = %q, want %q", got, text)
	}
	for _, size := range []int{1, 2, 3} {
		got, _ := feed(t, testPolicy(), splitEvery(stream, size))
		if normalizeCreated(got) != normalizeCreated(whole) {
			t.Errorf("chunk size %d corrupted multibyte content\ngot:\n%s\nwant:\n%s", size, got, whole)
		}
		if decoded := contentByChoice(t, parseChunks(t, got))[0]; decoded != text {
			t.Errorf("chunk size %d decoded content = %q, want %q", size, decoded, text)
		}
	}
}

// TestStream_ThoughtPartsNeverLeakAcrossSplits re-checks the thought:true
// exclusion under byte-level transport splitting, where the "thought" flag and
// its text can land in different callbacks.
func TestStream_ThoughtPartsNeverLeakAcrossSplits(t *testing.T) {
	for _, size := range []int{1, 3, 17} {
		out, _ := feed(t, testPolicy(), splitEvery(geminiTextStream(), size))
		if strings.Contains(out, "thinking out loud") {
			t.Errorf("chunk size %d leaked a thought part:\n%s", size, out)
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

	stream := geminiTextStream()
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
		{"provider error event", sseFrame(`{"error":{"code":503,"message":"Overloaded","status":"UNAVAILABLE"}}`), policy.FaultCodeProviderStreamFailed},
		{"malformed frame", sseFrame(`{"candidates":`), policy.FaultCodeMediationFailed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stream := sseFrame(`{"candidates":[{"content":{"role":"model","parts":[{"text":"Hi"}]},"index":0}],"modelVersion":"gemini-2.5-pro","responseId":"resp-f"}`) + tc.stream
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
			ResponseBody:    &policy.Body{Content: []byte(geminiTextStream()), Present: true},
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
