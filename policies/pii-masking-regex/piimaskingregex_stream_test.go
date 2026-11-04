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

package piimaskingregex

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

// ─── harness ─────────────────────────────────────────────────────────────────

// driveResponseStream drives the policy exactly as the policy-engine kernel
// does: chunks are accumulated while any policy asks for more data
// (NeedsMoreResponseData), and only the assembled buffer is handed to
// OnResponseBodyChunk. The bytes sent downstream are reconstructed using the
// SDK action semantics: ForwardResponseChunk.Body nil = forward the flushed
// buffer unchanged, non-nil = replace it (empty slice = emit nothing).
func driveResponseStream(t *testing.T, p *PIIMaskingRegexPolicy, respCtx *policy.ResponseStreamContext, chunks []string) string {
	t.Helper()
	var out strings.Builder
	var acc []byte
	flushes := 0
	for i, c := range chunks {
		eos := i == len(chunks)-1
		acc = append(acc, c...)
		if !eos && p.NeedsMoreResponseData(acc) {
			continue
		}
		sb := &policy.StreamBody{
			Chunk:       acc,
			EndOfStream: eos,
			Index:       uint64(flushes),
		}
		flushes++
		action := p.OnResponseBodyChunk(context.Background(), respCtx, sb, nil)
		fwd, ok := action.(policy.ForwardResponseChunk)
		if !ok {
			t.Fatalf("flush %d: expected ForwardResponseChunk, got %T", flushes-1, action)
		}
		if fwd.Body == nil {
			out.Write(acc)
		} else {
			out.Write(fwd.Body)
		}
		acc = nil
	}
	return out.String()
}

func streamingRespCtx(contentType string, mapping map[string]string) *policy.ResponseStreamContext {
	metadata := map[string]interface{}{}
	if mapping != nil {
		metadata[MetadataKeyPIIEntities] = mapping
	}
	ctx := &policy.ResponseStreamContext{
		SharedContext: &policy.SharedContext{RequestID: "req-id", Metadata: metadata},
	}
	if contentType != "" {
		ctx.ResponseHeaders = policy.NewHeaders(map[string][]string{"content-type": {contentType}})
	}
	return ctx
}

// splitEvery breaks s into chunks of at most n bytes, mimicking arbitrary
// chunked-transfer framing boundaries.
func splitEvery(s string, n int) []string {
	var chunks []string
	for len(s) > n {
		chunks = append(chunks, s[:n])
		s = s[n:]
	}
	if len(s) > 0 {
		chunks = append(chunks, s)
	}
	return chunks
}

func sseEvent(content string) string {
	ev, _ := json.Marshal(map[string]any{
		"id":      "chatcmpl-sse",
		"object":  "chat.completion.chunk",
		"choices": []any{map[string]any{"index": 0, "delta": map[string]any{"content": content}}},
	})
	return "data: " + string(ev) + "\n\n"
}

// assembleSSEContent concatenates delta.content across every data event.
func assembleSSEContent(t *testing.T, raw string) string {
	t.Helper()
	var sb strings.Builder
	for _, line := range strings.Split(raw, "\n") {
		if !strings.HasPrefix(line, "data: ") {
			continue
		}
		payload := strings.TrimPrefix(line, "data: ")
		if payload == "[DONE]" {
			continue
		}
		sb.WriteString(extractFirstDeltaContent(payload, DefaultStreamingJSONPaths))
	}
	return sb.String()
}

const maskedJSONBody = `{
  "id": "chatcmpl-ECLSc2xRestoreTest",
  "object": "chat.completion",
  "choices": [
    {
      "index": 0,
      "message": {
        "role": "assistant",
        "content": "Confirmation sent to [EMAIL_0000]. Call [PHONE_0001] if anything changes."
      },
      "finish_reason": "stop"
    }
  ]
}
`

// ─── non-SSE (plain JSON over chunked transfer) ──────────────────────────────

// The core regression: the body arrives in small chunks that split placeholders
// across boundaries. Every byte must survive and every placeholder must be
// restored, at any chunk size.
func TestNonSSE_RestoresAcrossEveryChunkBoundary(t *testing.T) {
	want := strings.NewReplacer(
		"[EMAIL_0000]", "guest@example.com",
		"[PHONE_0001]", "212-555-0175",
	).Replace(maskedJSONBody)

	for _, size := range []int{1, 2, 3, 5, 7, 11, 27, 64, 4096} {
		p := mustGetPIIPolicy(t, map[string]interface{}{"email": true, "phone": true})
		respCtx := streamingRespCtx("application/json", map[string]string{
			"guest@example.com": "[EMAIL_0000]",
			"212-555-0175":      "[PHONE_0001]",
		})
		got := driveResponseStream(t, p, respCtx, splitEvery(maskedJSONBody, size))
		if got != want {
			t.Errorf("chunk size %d: body mismatch\n got: %q\nwant: %q", size, got, want)
		}
	}
}

// A response with no placeholder in it must be forwarded byte-for-byte.
func TestNonSSE_NoPlaceholderIsForwardedIntact(t *testing.T) {
	body := `{"id":"chatcmpl-x","choices":[{"message":{"content":"How can I help you today?"}}]}` + "\n"
	for _, size := range []int{1, 7, 27, 4096} {
		p := mustGetPIIPolicy(t, map[string]interface{}{"phone": true})
		respCtx := streamingRespCtx("application/json", map[string]string{"212-555-0175": "[PHONE_0000]"})
		if got := driveResponseStream(t, p, respCtx, splitEvery(body, size)); got != body {
			t.Errorf("chunk size %d: body altered\n got: %q\nwant: %q", size, got, body)
		}
	}
}

// A separate empty EndOfStream sentinel must flush the accumulated body.
func TestNonSSE_EmptyEndOfStreamSentinelFlushesCarry(t *testing.T) {
	p := mustGetPIIPolicy(t, map[string]interface{}{"email": true})
	respCtx := streamingRespCtx("application/json", map[string]string{"guest@example.com": "[EMAIL_0000]"})

	chunks := append(splitEvery(maskedJSONBody, 9), "")
	got := driveResponseStream(t, p, respCtx, chunks)
	want := strings.Replace(maskedJSONBody, "[EMAIL_0000]", "guest@example.com", 1)
	if got != want {
		t.Fatalf("sentinel flush mismatch\n got: %q\nwant: %q", got, want)
	}
}

// A body whose tail genuinely looks like the start of a placeholder must not be
// swallowed — an incomplete body is still released at end of stream.
func TestNonSSE_TrailingPlaceholderPrefixIsNotSwallowed(t *testing.T) {
	body := `{"content":"an unclosed bracket [EMA`
	p := mustGetPIIPolicy(t, map[string]interface{}{"email": true})
	respCtx := streamingRespCtx("application/json", map[string]string{"guest@example.com": "[EMAIL_0000]"})
	if got := driveResponseStream(t, p, respCtx, splitEvery(body, 4)); got != body {
		t.Fatalf("trailing prefix lost\n got: %q\nwant: %q", got, body)
	}
}

// An unclosed '[' must not hold the stream open forever. Prose that opens a
// bracket and continues with ordinary words proves no placeholder is arriving —
// the very next fragment settles it, with no need to count events.
func TestSSE_UnclosedBracketInProseReleasesImmediately(t *testing.T) {
	p := mustGetPIIPolicy(t, map[string]interface{}{"email": true})

	var acc strings.Builder
	acc.WriteString(sseEvent("see ["))
	if !p.NeedsMoreResponseData([]byte(acc.String())) {
		t.Fatal("expected the policy to wait on a trailing unclosed bracket")
	}
	acc.WriteString(sseEvent("word "))
	if p.NeedsMoreResponseData([]byte(acc.String())) {
		t.Fatal("still waiting after prose followed the bracket; nothing could complete a placeholder")
	}
}

// A bracket opening onto text that never stops looking like an entity name must
// still be released, or an operator-configured long name would let prose stall
// the stream up to the kernel's accumulator ceiling.
func TestSSE_UnclosedBracketReleasesAtTailCeiling(t *testing.T) {
	p := mustGetPIIPolicy(t, map[string]interface{}{"email": true})

	var acc strings.Builder
	acc.WriteString(sseEvent("see ["))
	acc.WriteString(sseEvent(strings.Repeat("A", maxPlaceholderTailBytes)))
	if !p.NeedsMoreResponseData([]byte(acc.String())) {
		t.Fatal("released at exactly the ceiling; a name of this length could still complete")
	}
	acc.WriteString(sseEvent("A"))
	if p.NeedsMoreResponseData([]byte(acc.String())) {
		t.Fatalf("still waiting past %d bytes of tail", maxPlaceholderTailBytes)
	}
}

// driveResponseStreamPerEvent is driveResponseStream with the chunk boundaries
// aligned to event boundaries — one SSE event per chunk, which is what a real
// upstream flushing per event produces.
//
// This is the framing the rest of the SSE tests do NOT exercise: they call
// splitEvery(stream, 40), which coalesces several events into each chunk, so a
// per-event bound is never reached and a placeholder tokenised one character at
// a time still arrives inside a single buffer. The event-count bound this policy
// used to have was green under 40-byte framing and leaked under this one.
func driveResponseStreamPerEvent(t *testing.T, p *PIIMaskingRegexPolicy, respCtx *policy.ResponseStreamContext, events []string) string {
	t.Helper()
	return driveResponseStream(t, p, respCtx, events)
}

// The originally-reported case: an upstream that emits one SSE event per chunk
// and one character per event, so "[EMAIL_0000]" spans 12 events. Restoration
// must not depend on how finely the upstream tokenises, nor on chunk boundaries
// happening to coalesce events.
func TestSSE_RestoresWhenChunksAlignToEventsAtEveryTokenisation(t *testing.T) {
	perChar := []string{"mail "}
	for _, r := range "[EMAIL_0000]" {
		perChar = append(perChar, string(r))
	}
	perChar = append(perChar, " ok")

	cases := []struct {
		name  string
		frags []string
	}{
		{"whole placeholder in one event", []string{"mail ", "[EMAIL_0000]", " ok"}},
		{"four fragments", []string{"mail ", "[EMA", "IL_0", "000]", " ok"}},
		{"five fragments", []string{"mail ", "[", "EMAIL", "_", "0000", "]", " ok"}},
		{"one character per event (12 events)", perChar},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := mustGetPIIPolicy(t, map[string]interface{}{"email": true})
			respCtx := streamingRespCtx("text/event-stream", map[string]string{"guest@example.com": "[EMAIL_0000]"})

			events := make([]string, 0, len(tc.frags)+1)
			for _, f := range tc.frags {
				events = append(events, sseEvent(f))
			}
			events = append(events, "data: [DONE]\n\n")

			out := driveResponseStreamPerEvent(t, p, respCtx, events)

			if got, want := assembleSSEContent(t, out), "mail guest@example.com ok"; got != want {
				t.Errorf("assembled content mismatch\n got: %q\nwant: %q", got, want)
			}
			if strings.Contains(out, "[EMAIL_0000]") {
				t.Errorf("placeholder leaked to client:\n%s", out)
			}
		})
	}
}

// The same per-event framing for Anthropic, whose text lives at delta.text —
// defect 1 and the event-alignment defect interacting.
func TestSSE_AnthropicRestoresWhenChunksAlignToEvents(t *testing.T) {
	frags := []string{"mail "}
	for _, r := range "[EMAIL_0000]" {
		frags = append(frags, string(r))
	}
	frags = append(frags, " ok")

	p := mustGetPIIPolicy(t, map[string]interface{}{"email": true})
	respCtx := streamingRespCtx("text/event-stream", map[string]string{"guest@example.com": "[EMAIL_0000]"})

	events := []string{"event: message_start\ndata: {\"type\":\"message_start\"}\n\n"}
	for _, f := range frags {
		events = append(events, anthropicDeltaEvent(f))
	}
	events = append(events, "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n")

	out := driveResponseStreamPerEvent(t, p, respCtx, events)

	if got, want := assembleAnthropicContent(t, out), "mail guest@example.com ok"; got != want {
		t.Errorf("assembled content mismatch\n got: %q\nwant: %q", got, want)
	}
	if strings.Contains(out, "[EMAIL_0000]") {
		t.Errorf("placeholder leaked to client:\n%s", out)
	}
	assertWellFormedSSEBlocks(t, 0, out)
}

// Prose must not be held hostage by the wait: a bracket that cannot become a
// placeholder is released on the event that proves it, so tokens keep flowing.
func TestSSE_ProseWithBracketsStreamsWithoutStalling(t *testing.T) {
	p := mustGetPIIPolicy(t, map[string]interface{}{"email": true})
	respCtx := streamingRespCtx("text/event-stream", map[string]string{"guest@example.com": "[EMAIL_0000]"})

	events := []string{}
	for _, f := range []string{"see ", "[", "1", "]", " and ", "[", "text", "]", "(url)", " plus [ this"} {
		events = append(events, sseEvent(f))
	}
	out := driveResponseStreamPerEvent(t, p, respCtx, events)

	if got, want := assembleSSEContent(t, out), "see [1] and [text](url) plus [ this"; got != want {
		t.Errorf("prose corrupted\n got: %q\nwant: %q", got, want)
	}
}

// ─── SSE ─────────────────────────────────────────────────────────────────────

// A placeholder split across delta events must be restored, however finely the
// upstream tokenises it — including far beyond the old 5-data-line lookahead.
func TestSSE_RestoresPlaceholderSplitAcrossEvents(t *testing.T) {
	fragments := [][]string{
		{"send ", "it ", "to ", "[EMAIL_0000]", " please"},
		{"send ", "it ", "to ", "[", "EMAIL", "_", "0000", "]", " please"},
		{"send ", "it ", "to ", "[", "E", "M", "A", "I", "L", "_", "0", "0", "0", "0", "]", " please"},
	}
	for i, frags := range fragments {
		p := mustGetPIIPolicy(t, map[string]interface{}{"email": true})
		respCtx := streamingRespCtx("text/event-stream", map[string]string{"guest@example.com": "[EMAIL_0000]"})

		var stream strings.Builder
		for _, f := range frags {
			stream.WriteString(sseEvent(f))
		}
		stream.WriteString("data: [DONE]\n\n")

		out := driveResponseStream(t, p, respCtx, splitEvery(stream.String(), 40))
		got := assembleSSEContent(t, out)
		const want = "send it to guest@example.com please"
		if got != want {
			t.Errorf("case %d: assembled content mismatch\n got: %q\nwant: %q", i, got, want)
		}
		if strings.Contains(out, "[EMAIL_0000]") {
			t.Errorf("case %d: placeholder leaked to client:\n%s", i, out)
		}
		if !strings.Contains(out, "data: [DONE]") {
			t.Errorf("case %d: [DONE] terminator missing:\n%s", i, out)
		}
	}
}

// A leading SSE comment/heartbeat must be forwarded in place, before the first
// data event — never reordered to the end of the stream.
func TestSSE_LeadingHeartbeatKeepsItsPosition(t *testing.T) {
	p := mustGetPIIPolicy(t, map[string]interface{}{"email": true})
	respCtx := streamingRespCtx("text/event-stream", map[string]string{"guest@example.com": "[EMAIL_0000]"})

	chunks := []string{
		": keep-alive\n\n",
		sseEvent("hello "),
		sseEvent("[EMAIL_0000]"),
		"data: [DONE]\n\n",
	}
	out := driveResponseStream(t, p, respCtx, chunks)

	if !strings.Contains(out, ": keep-alive") {
		t.Fatalf("heartbeat dropped:\n%s", out)
	}
	hb := strings.Index(out, ": keep-alive")
	firstData := strings.Index(out, "data: ")
	done := strings.Index(out, "data: [DONE]")
	if hb > firstData {
		t.Errorf("heartbeat reordered after the first data event:\n%s", out)
	}
	if hb > done {
		t.Errorf("heartbeat emitted after [DONE]:\n%s", out)
	}
	if got := assembleSSEContent(t, out); got != "hello guest@example.com" {
		t.Errorf("content mismatch: got %q", got)
	}
}

// Ordinary prose whose brackets are already closed must not stall the stream:
// there is nothing a later event could complete, so the flush happens now.
func TestSSE_ClosedBracketInProseDoesNotWithhold(t *testing.T) {
	p := mustGetPIIPolicy(t, map[string]interface{}{"email": true})
	chunk := sseEvent("see [1] and [2] for details")
	if p.NeedsMoreResponseData([]byte(chunk)) {
		t.Fatal("stream withheld despite every bracket being closed")
	}
}

// An SSE stream must stay on the SSE path even when a chunk carries no data
// line at all, and content must not be corrupted by mid-frame chunk splits.
func TestSSE_SurvivesArbitraryChunkSplits(t *testing.T) {
	var stream strings.Builder
	stream.WriteString(": keep-alive\n\n")
	for _, f := range []string{"call ", "[", "PHONE", "_", "0000", "]", " now"} {
		stream.WriteString(sseEvent(f))
	}
	stream.WriteString("data: [DONE]\n\n")

	for _, size := range []int{1, 3, 17, 64, 4096} {
		p := mustGetPIIPolicy(t, map[string]interface{}{"phone": true})
		respCtx := streamingRespCtx("text/event-stream", map[string]string{"212-555-0175": "[PHONE_0000]"})
		out := driveResponseStream(t, p, respCtx, splitEvery(stream.String(), size))
		if got := assembleSSEContent(t, out); got != "call 212-555-0175 now" {
			t.Errorf("chunk size %d: content mismatch: got %q", size, got)
		}
		if strings.Contains(out, "[PHONE_0000]") {
			t.Errorf("chunk size %d: placeholder leaked:\n%s", size, out)
		}
	}
}

// ─── contract guards ─────────────────────────────────────────────────────────

// The kernel owns accumulation. This policy asks it to keep buffering only
// while a placeholder could still be incomplete — an unparseable JSON body, or
// SSE assistant text ending in an unclosed '['.
func TestNeedsMoreResponseData(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want bool
	}{
		{"empty", "", true},
		{"truncated json", "{", true},
		{"complete json", `{"a":"b"}`, false},
		{"json with trailing whitespace", `{"a":"b"}` + "\n", false},
		{"sse with no bracket", sseEvent("hello there"), false},
		{"sse with closed bracket", sseEvent("see [1] for details"), false},
		{"sse with unclosed bracket", sseEvent("mail ["), true},
		{"sse with placeholder split across events", sseEvent("mail [") + sseEvent("EMAIL"), true},
		{"sse with completed placeholder", sseEvent("mail [") + sseEvent("EMAIL_0000]"), false},
		{"sse cut mid-event", strings.TrimSuffix(sseEvent("hello there"), "}\n\n"), true},
		{"crlf sse event", sseEventCRLF("hello there"), false},
	}
	p := mustGetPIIPolicy(t, map[string]interface{}{"email": true})
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := p.NeedsMoreResponseData([]byte(tc.in)); got != tc.want {
				t.Errorf("NeedsMoreResponseData(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

// Redaction is one-way — nothing is restored on the response path, so the
// policy must never ask the kernel to hold response bytes back.
func TestNeedsMoreResponseData_RedactModeNeverBuffers(t *testing.T) {
	p := mustGetPIIPolicy(t, map[string]interface{}{"email": true, "redactPII": true})
	for _, in := range []string{"", "{", sseEvent("mail [")} {
		if p.NeedsMoreResponseData([]byte(in)) {
			t.Errorf("NeedsMoreResponseData(%q) = true in redact mode, want false", in)
		}
	}
}

// Requests that masked nothing must stream through untouched.
func TestNoMetadata_StreamsThroughUnchanged(t *testing.T) {
	p := mustGetPIIPolicy(t, map[string]interface{}{"email": true})
	respCtx := streamingRespCtx("application/json", nil)
	if got := driveResponseStream(t, p, respCtx, splitEvery(maskedJSONBody, 33)); got != maskedJSONBody {
		t.Fatalf("body altered when no PII was masked:\n%s", got)
	}
}

// ─── Anthropic SSE wire format ───────────────────────────────────────────────

// anthropicDeltaEvent builds an Anthropic content_block_delta frame, whose
// assistant text lives at delta.text rather than choices[].delta.content.
func anthropicDeltaEvent(text string) string {
	ev, _ := json.Marshal(map[string]any{
		"type":  "content_block_delta",
		"index": 0,
		"delta": map[string]any{"type": "text_delta", "text": text},
	})
	return "event: content_block_delta\ndata: " + string(ev) + "\n\n"
}

// assembleAnthropicContent concatenates delta.text across every data event.
func assembleAnthropicContent(t *testing.T, raw string) string {
	t.Helper()
	var sb strings.Builder
	for _, line := range strings.Split(raw, "\n") {
		if !strings.HasPrefix(line, "data: ") {
			continue
		}
		payload := strings.TrimPrefix(line, "data: ")
		var data map[string]any
		if json.Unmarshal([]byte(payload), &data) != nil {
			continue
		}
		delta, _ := data["delta"].(map[string]any)
		text, _ := delta["text"].(string)
		sb.WriteString(text)
	}
	return sb.String()
}

// Anthropic streams carry assistant text as delta.text on content_block_delta,
// with no "choices" array at all. Extraction that only understood the OpenAI
// shape found no content, so nothing was ever restored and the placeholder was
// delivered to the client — on every encoding, compression irrelevant. Found by
// running the mock Anthropic backend through the real gateway.
func TestSSE_AnthropicFormatRestoresAcrossEvents(t *testing.T) {
	fragments := [][]string{
		{"send ", "it ", "to ", "[EMAIL_0000]", " please"},
		{"send ", "it ", "to ", "[", "EMAIL", "_", "0000", "]", " please"},
		{"send ", "it ", "to ", "[", "E", "M", "A", "I", "L", "_", "0", "0", "0", "0", "]", " please"},
	}
	for i, frags := range fragments {
		p := mustGetPIIPolicy(t, map[string]interface{}{"email": true})
		respCtx := streamingRespCtx("text/event-stream", map[string]string{"guest@example.com": "[EMAIL_0000]"})

		var stream strings.Builder
		stream.WriteString("event: message_start\ndata: {\"type\":\"message_start\"}\n\n")
		stream.WriteString(": heartbeat\n\n")
		for _, f := range frags {
			stream.WriteString(anthropicDeltaEvent(f))
		}
		stream.WriteString("event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n")

		out := driveResponseStream(t, p, respCtx, splitEvery(stream.String(), 40))

		if got, want := assembleAnthropicContent(t, out), "send it to guest@example.com please"; got != want {
			t.Errorf("case %d: assembled content mismatch\n got: %q\nwant: %q", i, got, want)
		}
		if strings.Contains(out, "[EMAIL_0000]") {
			t.Errorf("case %d: placeholder leaked to client:\n%s", i, out)
		}
		if !strings.Contains(out, "message_stop") {
			t.Errorf("case %d: terminal event missing:\n%s", i, out)
		}
		assertWellFormedSSEBlocks(t, i, out)
	}
}

// assertWellFormedSSEBlocks checks the framing of a merged stream, not just its
// assembled text. Dropping a merged content event used to remove only its
// "data:" line, orphaning the "event:" line that introduced it; the assembled
// content looked correct while the wire format was malformed. Every block must
// carry at most one "event:" field, and any block declaring one must also carry
// a "data:" line.
func assertWellFormedSSEBlocks(t *testing.T, caseIdx int, out string) {
	t.Helper()
	for blockIdx, block := range strings.Split(out, "\n\n") {
		if strings.TrimSpace(block) == "" {
			continue
		}
		var events, datas int
		for _, line := range strings.Split(block, "\n") {
			switch {
			case strings.HasPrefix(line, "event:"):
				events++
			case strings.HasPrefix(line, "data: "):
				datas++
			}
		}
		if events > 1 {
			t.Errorf("case %d block %d: %d \"event:\" lines in one block, want at most 1:\n%s",
				caseIdx, blockIdx, events, block)
		}
		if events == 1 && datas == 0 {
			t.Errorf("case %d block %d: \"event:\" line with no \"data:\" line (orphaned by a merge):\n%s",
				caseIdx, blockIdx, block)
		}
	}
}

// Gemini's streaming shape is covered by the defaults, and a provider that no
// default covers is supported by configuration alone. Together these are the
// claim that this policy is not bound to one vendor's wire format.
func TestSSE_ProviderShapesAreDataDriven(t *testing.T) {
	cases := []struct {
		name     string
		params   map[string]interface{}
		event    func(text string) string
		assemble func(raw string) string
	}{
		{
			name:   "gemini-default-path",
			params: map[string]interface{}{"email": true},
			event: func(text string) string {
				ev, _ := json.Marshal(map[string]any{
					"candidates": []any{map[string]any{
						"content": map[string]any{"parts": []any{map[string]any{"text": text}}},
					}},
				})
				return "data: " + string(ev) + "\n\n"
			},
			assemble: func(raw string) string {
				var sb strings.Builder
				for _, line := range strings.Split(raw, "\n") {
					if !strings.HasPrefix(line, "data: ") {
						continue
					}
					var d map[string]any
					if json.Unmarshal([]byte(strings.TrimPrefix(line, "data: ")), &d) != nil {
						continue
					}
					cands, _ := d["candidates"].([]any)
					for _, c := range cands {
						cm, _ := c.(map[string]any)
						content, _ := cm["content"].(map[string]any)
						parts, _ := content["parts"].([]any)
						for _, pt := range parts {
							pm, _ := pt.(map[string]any)
							s, _ := pm["text"].(string)
							sb.WriteString(s)
						}
					}
				}
				return sb.String()
			},
		},
		{
			// OpenAI Responses API: the text is a plain string at the top-level
			// "delta" key, matched by the trailing "$.delta" fallback.
			name:   "openai-responses-api-default-path",
			params: map[string]interface{}{"email": true},
			event: func(text string) string {
				ev, _ := json.Marshal(map[string]any{
					"type":          "response.output_text.delta",
					"item_id":       "msg_1",
					"output_index":  0,
					"content_index": 0,
					"delta":         text,
				})
				return "data: " + string(ev) + "\n\n"
			},
			assemble: func(raw string) string {
				var sb strings.Builder
				for _, line := range strings.Split(raw, "\n") {
					if !strings.HasPrefix(line, "data: ") {
						continue
					}
					var d map[string]any
					if json.Unmarshal([]byte(strings.TrimPrefix(line, "data: ")), &d) != nil {
						continue
					}
					s, _ := d["delta"].(string)
					sb.WriteString(s)
				}
				return sb.String()
			},
		},
		{
			name:   "bedrock-converse-default-path",
			params: map[string]interface{}{"email": true},
			event: func(text string) string {
				ev, _ := json.Marshal(map[string]any{
					"contentBlockDelta": map[string]any{
						"contentBlockIndex": 0,
						"delta":             map[string]any{"text": text},
					},
				})
				return "data: " + string(ev) + "\n\n"
			},
			assemble: func(raw string) string {
				var sb strings.Builder
				for _, line := range strings.Split(raw, "\n") {
					if !strings.HasPrefix(line, "data: ") {
						continue
					}
					var d map[string]any
					if json.Unmarshal([]byte(strings.TrimPrefix(line, "data: ")), &d) != nil {
						continue
					}
					cbd, _ := d["contentBlockDelta"].(map[string]any)
					delta, _ := cbd["delta"].(map[string]any)
					s, _ := delta["text"].(string)
					sb.WriteString(s)
				}
				return sb.String()
			},
		},
		{
			name:   "openai-default-path",
			params: map[string]interface{}{"email": true},
			event: func(text string) string {
				ev, _ := json.Marshal(map[string]any{
					"choices": []any{map[string]any{
						"index": 0,
						"delta": map[string]any{"content": text},
					}},
				})
				return "data: " + string(ev) + "\n\n"
			},
			assemble: func(raw string) string {
				var sb strings.Builder
				for _, line := range strings.Split(raw, "\n") {
					if !strings.HasPrefix(line, "data: ") {
						continue
					}
					var d map[string]any
					if json.Unmarshal([]byte(strings.TrimPrefix(line, "data: ")), &d) != nil {
						continue
					}
					chs, _ := d["choices"].([]any)
					for _, c := range chs {
						cm, _ := c.(map[string]any)
						delta, _ := cm["delta"].(map[string]any)
						s, _ := delta["content"].(string)
						sb.WriteString(s)
					}
				}
				return sb.String()
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := mustGetPIIPolicy(t, tc.params)
			respCtx := streamingRespCtx("text/event-stream", map[string]string{"guest@example.com": "[EMAIL_0000]"})

			// Split the placeholder one character per event — the hard case.
			var stream strings.Builder
			for _, f := range []string{"mail ", "[", "E", "M", "A", "I", "L", "_", "0", "0", "0", "0", "]", " ok"} {
				stream.WriteString(tc.event(f))
			}

			out := driveResponseStream(t, p, respCtx, splitEvery(stream.String(), 40))

			if got, want := tc.assemble(out), "mail guest@example.com ok"; got != want {
				t.Errorf("assembled content mismatch\n got: %q\nwant: %q", got, want)
			}
			if strings.Contains(out, "[EMAIL_0000]") {
				t.Errorf("placeholder leaked to client:\n%s", out)
			}
		})
	}
}

// TestDefaultPaths_BindToExpectedShape pins which JSONPath each provider frame
// resolves to. The list is order-sensitive: "$.delta" is a deliberate trailing
// fallback for the OpenAI Responses API, and must never shadow the more
// specific paths above it — most importantly Anthropic's "$.delta.text".
func TestDefaultPaths_BindToExpectedShape(t *testing.T) {
	cases := []struct {
		name     string
		frame    string
		wantText string
		wantPath string
	}{
		{
			name:     "anthropic binds to $.delta.text, not the $.delta fallback",
			frame:    `{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Hi"}}`,
			wantText: "Hi",
			wantPath: "$.delta.text",
		},
		{
			name:     "openai responses api binds to the $.delta fallback",
			frame:    `{"type":"response.output_text.delta","output_index":0,"delta":"Hello"}`,
			wantText: "Hello",
			wantPath: "$.delta",
		},
		{
			name:     "openai chat completions binds to choices[0].delta.content",
			frame:    `{"choices":[{"index":0,"delta":{"content":"Hey"}}]}`,
			wantText: "Hey",
			wantPath: "$.choices[0].delta.content",
		},
		{
			name:     "bedrock converse binds to contentBlockDelta.delta.text",
			frame:    `{"contentBlockDelta":{"contentBlockIndex":0,"delta":{"text":"Yo"}}}`,
			wantText: "Yo",
			wantPath: "$.contentBlockDelta.delta.text",
		},
		{
			name:     "gemini binds to candidates[0].content.parts[0].text",
			frame:    `{"candidates":[{"content":{"parts":[{"text":"Sup"}]}}]}`,
			wantText: "Sup",
			wantPath: "$.candidates[0].content.parts[0].text",
		},
		{
			name:     "an unrecognised shape matches nothing and is forwarded intact",
			frame:    `{"output":{"message":{"chunk":"Nope"}}}`,
			wantText: "",
			wantPath: "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			text, path := extractFirstDeltaContentKeyed(tc.frame, DefaultStreamingJSONPaths)
			if text != tc.wantText || path != tc.wantPath {
				t.Errorf("got (%q, %q), want (%q, %q)", text, path, tc.wantText, tc.wantPath)
			}
		})
	}
}

// ─── SSE line terminators and [DONE] detection ───────────────────────────────

// sseEventCRLF is sseEvent with the spec-legal CRLF terminators some providers
// and proxies emit.
func sseEventCRLF(content string) string {
	return strings.ReplaceAll(sseEvent(content), "\n", "\r\n")
}

// A CRLF-delimited stream must be parsed as SSE, not mistaken for a JSON body:
// a complete, placeholder-free CRLF event has to be released immediately rather
// than accumulated until the body happens to parse as JSON (which it never will).
func TestSSE_CRLFEventsAreReleasedBeforeEndOfStream(t *testing.T) {
	p := mustGetPIIPolicy(t, map[string]interface{}{"email": true})
	if p.NeedsMoreResponseData([]byte(sseEventCRLF("Hello there."))) {
		t.Fatal("complete CRLF event was withheld; client receives nothing until EOS")
	}
}

// The full CRLF stream must still restore a placeholder split across events.
func TestSSE_CRLFStreamRestoresSplitPlaceholder(t *testing.T) {
	p := mustGetPIIPolicy(t, map[string]interface{}{"email": true})
	respCtx := streamingRespCtx("text/event-stream", map[string]string{"guest@example.com": "[EMAIL_0000]"})

	got := driveResponseStream(t, p, respCtx, []string{
		sseEventCRLF("Confirmation sent to "),
		sseEventCRLF("[EMA"),
		sseEventCRLF("IL_0"),
		sseEventCRLF("000]."),
		"data: [DONE]\r\n\r\n",
	})

	if strings.Contains(got, "[EMAIL_0000]") {
		t.Errorf("placeholder leaked to client: %q", got)
	}
	assembled := assembleSSEContent(t, strings.ReplaceAll(got, "\r", ""))
	if want := "Confirmation sent to guest@example.com."; assembled != want {
		t.Errorf("assembled content = %q, want %q", assembled, want)
	}
}

// Assistant text that merely mentions "data: [DONE]" must not be mistaken for
// the stream terminator — doing so releases a half-buffered placeholder as a
// visible leak.
func TestSSE_DoneInAssistantTextIsNotTerminal(t *testing.T) {
	p := mustGetPIIPolicy(t, map[string]interface{}{"email": true})
	respCtx := streamingRespCtx("text/event-stream", map[string]string{"guest@example.com": "[EMAIL_0000]"})

	got := driveResponseStream(t, p, respCtx, []string{
		sseEvent("The stream ends with the line data: [DONE] — then mail ") + sseEvent("[EMA"),
		sseEvent("IL_0000]."),
		"data: [DONE]\n\n",
	})

	if strings.Contains(got, "[EMAIL_0000]") {
		t.Errorf("placeholder leaked to client: %q", got)
	}
	assembled := assembleSSEContent(t, got)
	want := "The stream ends with the line data: [DONE] — then mail guest@example.com."
	if assembled != want {
		t.Errorf("assembled content = %q, want %q", assembled, want)
	}
}

// TestPIIMaskingRegex_MediationFailureDeclaresFault covers the one rejection this policy
// makes. Masking failed, so unmasked content would otherwise have been forwarded — exactly
// the failure an operator wants a fault policy to see.
func TestPIIMaskingRegex_MediationFailureDeclaresFault(t *testing.T) {
	p := &PIIMaskingRegexPolicy{}

	action := p.buildErrorResponse("error extracting value from JSONPath: no match")
	resp, ok := action.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("expected ImmediateResponse, got %T", action)
	}
	if !resp.IsFault {
		t.Fatalf("expected IsFault=true when masking fails")
	}
	if resp.Fault == nil {
		t.Fatalf("expected Error to be populated")
	}
	if resp.Fault.Code != policy.FaultCodeMediationFailed {
		t.Fatalf("expected Error.Code=%q, got %q", policy.FaultCodeMediationFailed, resp.Fault.Code)
	}
	if resp.Fault.Code == "900967" {
		t.Fatalf("900967 is a control-plane code and must not be used here")
	}
	if resp.Fault.Type != policy.FaultTypeMediation {
		t.Fatalf("expected Error.Type=%q, got %q", policy.FaultTypeMediation, resp.Fault.Type)
	}
	if resp.Fault.Direction != policy.DirectionRequest {
		t.Fatalf("expected Error.Direction=%q, got %q", policy.DirectionRequest, resp.Fault.Direction)
	}
	// This policy already returns the reason to the caller in the body, so it is
	// client-safe and belongs in Message. Description must stay empty rather than restate
	// an already-published string as though a renderer would withhold it.
	if !strings.Contains(resp.Fault.Message, "no match") {
		t.Fatalf("expected Error.Message to carry the reason, got %q", resp.Fault.Message)
	}
	if resp.Fault.Description != "" {
		t.Fatalf("expected Error.Description to stay empty, got %q", resp.Fault.Description)
	}
}

// TestPIIMaskingRegex_SuccessfulMaskingIsNotAFault covers the ordinary path: this policy
// rewrites the body on every masked response. That is a transformation, not a failure.
func TestPIIMaskingRegex_SuccessfulMaskingIsNotAFault(t *testing.T) {
	p := &PIIMaskingRegexPolicy{}
	respCtx := &policy.ResponseContext{
		SharedContext: &policy.SharedContext{
			RequestID: "req-id",
			Metadata: map[string]interface{}{
				MetadataKeyPIIEntities: map[string]string{"a.user@example.com": "[EMAIL_0000]"},
			},
		},
		ResponseBody: &policy.Body{Content: []byte(`{"answer":"Found [EMAIL_0000]"}`), Present: true},
	}
	action := p.OnResponseBody(context.Background(), respCtx, nil)
	mods, ok := action.(policy.DownstreamResponseModifications)
	if !ok {
		t.Fatalf("expected DownstreamResponseModifications, got %T", action)
	}
	if !strings.Contains(string(mods.Body), "a.user@example.com") {
		t.Fatalf("expected the placeholder to be restored, got %s", mods.Body)
	}
	if mods.IsFault || mods.Fault != nil {
		t.Fatalf("a restored response must not be a fault")
	}
}

// TestPIIMaskingRegex_ClientBodyIsUnchanged pins the OTHER half of the code decision above,
// and it is the half a reader is most likely to assume rather than check.
//
// This policy now carries TWO codes for one failure: 900967 in the body the client parses,
// and 960700 in the FaultDetails the fault flow and analytics read. That is deliberate —
func TestPIIMaskingRegex_ClientBodyIsUnchanged(t *testing.T) {
	p := &PIIMaskingRegexPolicy{}

	action := p.buildErrorResponse("error extracting value from JSONPath: no match")
	resp, ok := action.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("expected ImmediateResponse, got %T", action)
	}

	if resp.StatusCode != APIMInternalErrorCode {
		t.Errorf("status = %d, want %d — unchanged from before the fault flow",
			resp.StatusCode, APIMInternalErrorCode)
	}

	var body map[string]interface{}
	if err := json.Unmarshal(resp.Body, &body); err != nil {
		t.Fatalf("body is not JSON: %v (%s)", err, resp.Body)
	}

	// A number, not a string: json.Unmarshal gives float64 for a JSON number, and would
	// give string if someone switched the body onto the string-typed fault code.
	code, isNumber := body["code"].(float64)
	if !isNumber {
		t.Fatalf("body code is %T (%v), want a JSON number — a client comparing "+
			"code === 900967 breaks if this becomes a string", body["code"], body["code"])
	}
	if int(code) != APIMInternalExceptionCode {
		t.Errorf("body code = %d, want %d — the client-visible code must not move to the "+
			"fault code (%s); the two are deliberately different",
			int(code), APIMInternalExceptionCode, policy.FaultCodeMediationFailed)
	}

	wantMsg := "Error occurred during pii-masking-regex mediation: error extracting value from JSONPath: no match"
	if body["message"] != wantMsg {
		t.Errorf("body message = %q, want %q", body["message"], wantMsg)
	}
	if _, hasType := body["type"]; hasType {
		t.Errorf(`the success path's body has no "type" key (only the marshal-failure `+
			`fallback does), got %v`, body)
	}
}
