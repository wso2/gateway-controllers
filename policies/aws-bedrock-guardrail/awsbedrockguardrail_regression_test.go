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

package awsbedrockguardrail

// Regression tests for the streamed-response and masking fixes. Each Test* here
// failed on the code before the fix; the ones named as controls pass on both.

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime/types"
	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

// scriptedClient returns its outputs and errors in call order, repeating the last.
type scriptedClient struct {
	outs  []*bedrockruntime.ApplyGuardrailOutput
	errs  []error
	calls int
	texts []string
}

func (c *scriptedClient) ApplyGuardrail(_ context.Context, params *bedrockruntime.ApplyGuardrailInput, _ ...func(*bedrockruntime.Options)) (*bedrockruntime.ApplyGuardrailOutput, error) {
	i := c.calls
	c.calls++
	for _, content := range params.Content {
		if text, ok := content.(*types.GuardrailContentBlockMemberText); ok {
			c.texts = append(c.texts, aws.ToString(text.Value.Text))
		}
	}
	if i >= len(c.outs) {
		i = len(c.outs) - 1
	}
	return c.outs[i], c.errs[i]
}

// blockOnClient blocks any text containing needle and passes the rest.
type blockOnClient struct {
	needle string
	texts  []string
}

func (c *blockOnClient) ApplyGuardrail(_ context.Context, params *bedrockruntime.ApplyGuardrailInput, _ ...func(*bedrockruntime.Options)) (*bedrockruntime.ApplyGuardrailOutput, error) {
	for _, content := range params.Content {
		if text, ok := content.(*types.GuardrailContentBlockMemberText); ok {
			s := aws.ToString(text.Value.Text)
			c.texts = append(c.texts, s)
			if strings.Contains(s, c.needle) {
				return makeContentViolationOutput(), nil
			}
		}
	}
	return makeNoInterventionOutput(), nil
}

// bufferedResponse builds a whole 200 response, with the given Content-Type when
// one is set.
func bufferedResponse(md map[string]interface{}, contentType, body string) *policy.ResponseContext {
	ctx := &policy.ResponseContext{
		SharedContext:  &policy.SharedContext{Metadata: md},
		ResponseStatus: 200,
		ResponseBody:   &policy.Body{Content: []byte(body), EndOfStream: true, Present: true},
	}
	if contentType != "" {
		ctx.ResponseHeaders = policy.NewHeaders(map[string][]string{"content-type": {contentType}})
	}
	return ctx
}

// streamCtxWithType is streamCtx with a response Content-Type.
func streamCtxWithType(contentType string) *policy.ResponseStreamContext {
	ctx := streamCtx()
	ctx.ResponseHeaders = policy.NewHeaders(map[string][]string{"content-type": {contentType}})
	return ctx
}

// letterFlushes is six flushes of twelve events each ("aaa ", "bbb ", ...) and a
// final [DONE] flush.
func letterFlushes() []string {
	var flushes []string
	for f := 0; f < 6; f++ {
		var sb strings.Builder
		for i := 0; i < 12; i++ {
			sb.WriteString(sseEvent(strings.Repeat(string(rune('a'+f)), 3) + " "))
		}
		flushes = append(flushes, sb.String())
	}
	return append(flushes, "data: [DONE]\n\n")
}

// ─── an SSE-looking line no longer skips the assessment ─────────────────

func TestRegression_PlainTextBodyWithSSELookingLineIsAssessed(t *testing.T) {
	for _, contentType := range []string{"", "text/plain"} {
		client := &countingBedrockClient{output: makeContentViolationOutput()}
		p := streamingPolicy(client, func(pp *AWSBedrockGuardrailPolicyParams) { pp.JsonPath = "" })
		body := "Here is the forbidden answer.\nid: step-1 do the forbidden thing\n"
		mods := p.OnResponseBody(context.Background(), bufferedResponse(map[string]interface{}{}, contentType, body), nil).(policy.DownstreamResponseModifications)
		if client.calls != 1 || mods.StatusCode == nil {
			t.Fatalf("content-type %q: plain-text body passed unassessed: calls=%d status=%v", contentType, client.calls, mods.StatusCode)
		}
	}
}

func TestRegression_PlainTextBodyWithSSELookingLineFailsClosedOnDefaultPath(t *testing.T) {
	client := &countingBedrockClient{output: makeNoInterventionOutput()}
	p := streamingPolicy(client, nil) // default jsonPath, which plain text cannot match
	body := "Here is the answer.\nid: step-1\n"
	mods := p.OnResponseBody(context.Background(), bufferedResponse(map[string]interface{}{}, "text/plain", body), nil).(policy.DownstreamResponseModifications)
	if mods.StatusCode == nil || *mods.StatusCode != GuardrailErrorCode {
		t.Fatalf("an unreadable body must fail closed, got status %v", mods.StatusCode)
	}
	if !mods.IsFault || mods.Fault == nil || mods.Fault.Code != policy.FaultCodeMediationFailed {
		t.Fatalf("want a mediation fault, got IsFault=%v Fault=%+v", mods.IsFault, mods.Fault)
	}
}

func TestRegression_StreamedPlainTextWithSSELookingLineIsAssessed(t *testing.T) {
	client := &countingBedrockClient{output: makeContentViolationOutput()}
	p := streamingPolicy(client, func(pp *AWSBedrockGuardrailPolicyParams) { pp.JsonPath = "" })
	a := p.OnResponseBodyChunk(context.Background(), streamCtx(), &policy.StreamBody{
		Chunk: []byte("forbidden answer\n: and more forbidden text\n"), EndOfStream: true}, nil)
	if client.calls == 0 || !a.TerminateStream() {
		t.Fatalf("streamed plain text passed unassessed: calls=%d action=%#v", client.calls, a)
	}
}

// An upstream that labels a body text/event-stream but puts text outside any
// event: the text cannot be read, so it is refused rather than delivered.
func TestRegression_EventStreamWithTextOutsideEventsFailsClosed(t *testing.T) {
	body := "Here is the forbidden answer.\n" + sseEvent("ok") + "data: [DONE]\n\n"

	client := &countingBedrockClient{output: makeNoInterventionOutput()}
	p := streamingPolicy(client, nil)
	mods := p.OnResponseBody(context.Background(), bufferedResponse(map[string]interface{}{}, "text/event-stream", body), nil).(policy.DownstreamResponseModifications)
	if mods.StatusCode == nil {
		t.Fatalf("buffered: text outside any event was delivered")
	}

	client2 := &countingBedrockClient{output: makeNoInterventionOutput()}
	p2 := streamingPolicy(client2, nil)
	a := p2.OnResponseBodyChunk(context.Background(), streamCtxWithType("text/event-stream"),
		&policy.StreamBody{Chunk: []byte(body), EndOfStream: true}, nil)
	term, ok := a.(policy.TerminateResponseChunk)
	if !ok || !term.IsFault || term.Fault == nil || term.Fault.Code != policy.FaultCodeMediationFailed {
		t.Fatalf("streaming: want a mediation-fault termination, got %#v", a)
	}
}

// A real token stream still passes when its Content-Type says SSE.
func TestRegression_EventStreamContentTypeStillStreams(t *testing.T) {
	client := &countingBedrockClient{output: makeNoInterventionOutput()}
	p := streamingPolicy(client, nil)
	body := sseEvent("Hello ") + sseEvent("world.") + "data: [DONE]\n\n"
	a := p.OnResponseBodyChunk(context.Background(), streamCtxWithType("text/event-stream"),
		&policy.StreamBody{Chunk: []byte(body), EndOfStream: true}, nil)
	fwd, ok := a.(policy.ForwardResponseChunk)
	if !ok || string(fwd.Body) != body || client.calls != 1 {
		t.Fatalf("want the stream delivered unchanged after one call, got %#v (calls=%d)", a, client.calls)
	}
}

// ─── two attachments keep their own stream state ────────────────────────

func TestRegression_TwoAttachmentsDeliverTheStreamUnchanged(t *testing.T) {
	mk := func() *AWSBedrockGuardrailPolicy {
		return streamingPolicy(&countingBedrockClient{output: makeNoInterventionOutput()}, func(pp *AWSBedrockGuardrailPolicyParams) {
			pp.StreamingTextUnitChars = 100
		})
	}
	a, b := mk(), mk()
	rc := streamCtx()
	flushes := letterFlushes()
	want := strings.Join(flushes, "")

	var got strings.Builder
	for i, f := range flushes {
		eos := i == len(flushes)-1
		chunk := &policy.StreamBody{Chunk: []byte(f), EndOfStream: eos, Index: uint64(i)}
		// The kernel chains attachments: A's output is B's input, on one context.
		for _, p := range []*AWSBedrockGuardrailPolicy{a, b} {
			switch x := p.OnResponseBodyChunk(context.Background(), rc, chunk, nil).(type) {
			case policy.ForwardResponseChunk:
				if x.Body != nil {
					chunk = &policy.StreamBody{Chunk: x.Body, EndOfStream: eos, Index: uint64(i)}
				}
			case policy.TerminateResponseChunk:
				t.Fatalf("terminated: %s", x.Body)
			}
		}
		got.Write(chunk.Chunk)
	}
	if got.String() != want {
		t.Fatalf("two attachments changed the stream:\n got %q\nwant %q", got.String(), want)
	}
}

func TestRegression_SecondAttachmentStillBlocksWhatItsGuardrailRejects(t *testing.T) {
	a := streamingPolicy(&countingBedrockClient{output: makeNoInterventionOutput()}, func(pp *AWSBedrockGuardrailPolicyParams) { pp.StreamingTextUnitChars = 100 })
	bc := &blockOnClient{needle: "fff"}
	b := streamingPolicy(bc, func(pp *AWSBedrockGuardrailPolicyParams) { pp.StreamingTextUnitChars = 100 })
	rc := streamCtx()
	flushes := letterFlushes()
	var delivered strings.Builder
	terminated := false
	for i, f := range flushes {
		eos := i == len(flushes)-1
		chunk := &policy.StreamBody{Chunk: []byte(f), EndOfStream: eos}
		for _, p := range []*AWSBedrockGuardrailPolicy{a, b} {
			act := p.OnResponseBodyChunk(context.Background(), rc, chunk, nil)
			if x, ok := act.(policy.ForwardResponseChunk); ok && x.Body != nil {
				chunk = &policy.StreamBody{Chunk: x.Body, EndOfStream: eos}
			}
			if x, ok := act.(policy.TerminateResponseChunk); ok {
				chunk = &policy.StreamBody{Chunk: x.Body, EndOfStream: true}
				terminated = true
				break
			}
		}
		delivered.Write(chunk.Chunk)
		if terminated {
			break
		}
	}
	if !terminated || strings.Contains(delivered.String(), `"fff "`) {
		t.Fatalf("B must end the stream before any 'fff' frame (terminated=%v)", terminated)
	}
}

// ─── JSON-RPC event streams are assessed on the streaming path ──────────

const jsonRPCForbiddenEvent = "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"forbidden tool output\"}]}}\n\n"

func TestRegression_StreamedJSONRPCEventIsAssessed(t *testing.T) {
	client := &countingBedrockClient{output: makeContentViolationOutput()}
	p := streamingPolicy(client, func(pp *AWSBedrockGuardrailPolicyParams) { pp.JsonPath = "$.result.content[*].text" })
	a := p.OnResponseBodyChunk(context.Background(), streamCtxWithType("text/event-stream"),
		&policy.StreamBody{Chunk: []byte(jsonRPCForbiddenEvent), EndOfStream: true}, nil)
	term, ok := a.(policy.TerminateResponseChunk)
	if client.calls != 1 || !ok {
		t.Fatalf("streamed JSON-RPC SSE delivered unassessed: calls=%d action=%#v", client.calls, a)
	}
	if !term.IsFault || term.Fault == nil || term.Fault.Type != policy.FaultTypeGuardrail {
		t.Fatalf("want a guardrail fault, got %+v", term.Fault)
	}
	if !strings.HasPrefix(string(term.Body), "data: ") {
		t.Fatalf("the verdict must be delivered as an SSE event, got %q", term.Body)
	}
}

func TestRegression_StreamedJSONRPCEventIsHeldUntilComplete(t *testing.T) {
	client := &countingBedrockClient{output: makeNoInterventionOutput()}
	p := streamingPolicy(client, func(pp *AWSBedrockGuardrailPolicyParams) { pp.JsonPath = "$.result.content[*].text" })
	rc := streamCtxWithType("text/event-stream")
	clean := strings.Replace(jsonRPCForbiddenEvent, "forbidden", "harmless", 1)
	cut := len(clean) / 2

	first := p.OnResponseBodyChunk(context.Background(), rc, &policy.StreamBody{Chunk: []byte(clean[:cut])}, nil)
	if fwd, ok := first.(policy.ForwardResponseChunk); !ok || fwd.Body == nil || len(fwd.Body) != 0 {
		t.Fatalf("half an event must be withheld, got %#v", first)
	}
	second := p.OnResponseBodyChunk(context.Background(), rc, &policy.StreamBody{Chunk: []byte(clean[cut:]), EndOfStream: true}, nil)
	fwd, ok := second.(policy.ForwardResponseChunk)
	if !ok || string(fwd.Body) != clean || client.calls != 1 {
		t.Fatalf("want the whole event after one call, got %#v (calls=%d)", second, client.calls)
	}
}

// ─── passthrough keeps the redaction earlier units asked for ────────────

func TestRegression_PassthroughErrorInLaterUnitKeepsEarlierRedaction(t *testing.T) {
	const pii = "john@example.com"
	client := &scriptedClient{
		outs: []*bedrockruntime.ApplyGuardrailOutput{makePIIIntervenedOutput(pii), nil},
		errs: []error{nil, errors.New("throttled")},
	}
	p := streamingPolicy(client, func(pp *AWSBedrockGuardrailPolicyParams) {
		pp.PassthroughOnError = true
		pp.RedactPII = true
	})
	var sb strings.Builder
	sb.WriteString(sseEvent("mail " + pii + " now. "))
	for i := 0; i < 300; i++ {
		sb.WriteString(sseEvent("word "))
	}
	a := p.OnResponseBodyChunk(context.Background(), streamCtx(), &policy.StreamBody{Chunk: []byte(sb.String()), EndOfStream: true}, nil)
	if client.calls != 2 {
		t.Fatalf("expected two unit calls, got %d", client.calls)
	}
	body := string(a.(policy.ForwardResponseChunk).Body)
	if strings.Contains(body, pii) {
		t.Fatalf("the first unit's redaction was dropped after a later unit failed")
	}
	if !strings.Contains(body, "word ") {
		t.Fatalf("the unassessed remainder must still be delivered under passthroughOnError")
	}
}

// ─── a data payload that is not JSON is refused, not skipped ────────────

func TestRegression_MultiLineDataEventFailsClosed(t *testing.T) {
	body := "data: {\"choices\":[{\"delta\":\ndata: {\"content\":\"forbidden text\"}}]}\n\ndata: [DONE]\n\n"

	client := &countingBedrockClient{output: makeNoInterventionOutput()}
	p := streamingPolicy(client, nil)
	a := p.OnResponseBodyChunk(context.Background(), streamCtx(), &policy.StreamBody{Chunk: []byte(body), EndOfStream: true}, nil)
	if !a.TerminateStream() {
		t.Fatalf("streaming: an event that cannot be read was delivered: %#v", a)
	}

	client2 := &countingBedrockClient{output: makeNoInterventionOutput()}
	p2 := streamingPolicy(client2, nil)
	mods := p2.OnResponseBody(context.Background(), bufferedResponse(map[string]interface{}{}, "text/event-stream", body), nil).(policy.DownstreamResponseModifications)
	if mods.StatusCode == nil {
		t.Fatalf("buffered: an event that cannot be read was delivered")
	}
}

func TestRegression_MultiLineDataEventPassesThroughWhenConfigured(t *testing.T) {
	body := "data: {\"choices\":[{\"delta\":\ndata: {\"content\":\"text\"}}]}\n\n"
	p := streamingPolicy(&countingBedrockClient{output: makeNoInterventionOutput()}, func(pp *AWSBedrockGuardrailPolicyParams) {
		pp.PassthroughOnError = true
	})
	a := p.OnResponseBodyChunk(context.Background(), streamCtx(), &policy.StreamBody{Chunk: []byte(body), EndOfStream: true}, nil)
	fwd, ok := a.(policy.ForwardResponseChunk)
	if !ok || string(fwd.Body) != body {
		t.Fatalf("passthroughOnError must deliver the stream unchanged, got %#v", a)
	}
}

// ─── flows that worked before keep working ──────────────────────────────────

// driveStream feeds flushes in order, the last as end of stream, and returns
// what reached the client and whether the stream was ended.
func driveStream(p *AWSBedrockGuardrailPolicy, respCtx *policy.ResponseStreamContext, flushes []string) (string, bool) {
	var out strings.Builder
	for i, f := range flushes {
		action := p.OnResponseBodyChunk(context.Background(), respCtx, &policy.StreamBody{
			Chunk: []byte(f), EndOfStream: i == len(flushes)-1, Index: uint64(i),
		}, nil)
		switch a := action.(type) {
		case policy.ForwardResponseChunk:
			if a.Body == nil {
				out.WriteString(f)
			} else {
				out.Write(a.Body)
			}
		case policy.TerminateResponseChunk:
			out.Write(a.Body)
			return out.String(), true
		}
	}
	return out.String(), false
}

// An unreadable line under passthroughOnError is delivered as before, but the
// readable text around it is still assessed: it must not ride out with the line.
func TestRegression_PassthroughUnreadableLineStillAssessesReadableText(t *testing.T) {
	client := &blockOnClient{needle: "FORBIDDEN"}
	p := streamingPolicy(client, func(pp *AWSBedrockGuardrailPolicyParams) { pp.PassthroughOnError = true })
	got, terminated := driveStream(p, streamCtxWithType("text/event-stream"), []string{
		sseEvent("FORBIDDEN secret. "),
		"data: ping\n\n",
		sseEvent("more. ") + "data: [DONE]\n\n",
	})
	if strings.Contains(got, "FORBIDDEN") || !terminated {
		t.Fatalf("readable text must be assessed and blocked (terminated=%v, assessed=%q): %q", terminated, client.texts, got)
	}
}

// A stream cut off in the middle of its last line ends as it did before: the
// text before the cut is assessed, and the unfinished line -- which an SSE
// client discards -- does not end a clean response.
func TestRegression_UnfinishedLastLineDoesNotEndTheStream(t *testing.T) {
	truncated := `data: {"choices":[{"delta":{"cont`
	for _, passthrough := range []bool{false, true} {
		client := &blockOnClient{needle: "FORBIDDEN"}
		p := streamingPolicy(client, func(pp *AWSBedrockGuardrailPolicyParams) { pp.PassthroughOnError = passthrough })
		got, terminated := driveStream(p, streamCtxWithType("text/event-stream"),
			[]string{sseEvent("FORBIDDEN secret. "), truncated})
		if strings.Contains(got, "FORBIDDEN") || !terminated {
			t.Errorf("passthrough=%v: violating text before the cut must be blocked, got %q", passthrough, got)
		}

		clean := &blockOnClient{needle: "FORBIDDEN"}
		p = streamingPolicy(clean, func(pp *AWSBedrockGuardrailPolicyParams) { pp.PassthroughOnError = passthrough })
		got, terminated = driveStream(p, streamCtxWithType("text/event-stream"),
			[]string{sseEvent("Hello there. "), truncated})
		if terminated || !strings.Contains(got, "Hello there.") {
			t.Errorf("passthrough=%v: clean text before the cut must be delivered, got terminated=%v %q", passthrough, terminated, got)
		}
	}
}

// An event stream labelled with another type is still read as one, as on
// before, so its frames are withheld until assessed rather than forwarded.
func TestRegression_MislabelledEventStreamIsWithheldAndAssessed(t *testing.T) {
	var flush strings.Builder
	for i := 0; i < 50; i++ {
		flush.WriteString(sseEvent("FORBIDDEN word "))
	}
	for _, contentType := range []string{"application/json", "text/plain", "application/octet-stream"} {
		client := &blockOnClient{needle: "FORBIDDEN"}
		p := streamingPolicy(client, nil)
		got, terminated := driveStream(p, streamCtxWithType(contentType), []string{flush.String(), "data: [DONE]\n\n"})
		if strings.Contains(got, "FORBIDDEN") || !terminated {
			t.Errorf("%s: event stream text delivered unassessed (terminated=%v)", contentType, terminated)
		}
	}
}

// Lines the SSE specification tells a client to strip or ignore do not end the
// stream, and the text around them is still assessed.
func TestRegression_SpecAllowedLinesKeepTheStream(t *testing.T) {
	events := sseEvent("Hello ") + sseEvent("world.")
	cases := map[string]string{
		"byte order mark":     "\uFEFF" + events + "data: [DONE]\n\n",
		"field with no colon": events + "data\n\n" + "event\n\n" + "data: [DONE]\n\n",
		"whitespace line":     events + " \n\n" + "data: [DONE]\n\n",
	}
	for name, body := range cases {
		client := &blockOnClient{needle: "NEVER"}
		p := streamingPolicy(client, nil)
		got, terminated := driveStream(p, streamCtxWithType("text/event-stream"), []string{body, ""})
		if terminated || got != body {
			t.Errorf("%s: the stream must be delivered unchanged, got terminated=%v %q", name, terminated, got)
		}
		if joined := strings.Join(client.texts, ""); !strings.Contains(joined, "Hello world.") {
			t.Errorf("%s: the text must still be assessed, assessed %q", name, client.texts)
		}
	}
}

// Text outside any event still ends the stream: the exemption is for field
// lines, not prose.
func TestRegression_ProseOutsideEventsStillEndsTheStream(t *testing.T) {
	client := &blockOnClient{needle: "NEVER"}
	p := streamingPolicy(client, nil)
	got, terminated := driveStream(p, streamCtxWithType("text/event-stream"),
		[]string{sseEvent("Hello. ") + "Here is the FORBIDDEN answer.\n\n", ""})
	if !terminated || strings.Contains(got, "FORBIDDEN") {
		t.Fatalf("prose outside any event must not be delivered, got terminated=%v %q", terminated, got)
	}
}

// A JSON-RPC message beside token deltas leaves the stream an LLM stream, as on
// before, so the deltas are still assessed.
func TestRegression_TokenDeltasBesideAJSONRPCEventAreAssessed(t *testing.T) {
	rpc := "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"harmless\"}]}}\n\n"
	client := &blockOnClient{needle: "FORBIDDEN"}
	p := streamingPolicy(client, func(pp *AWSBedrockGuardrailPolicyParams) { pp.JsonPath = "$.result.content[*].text" })
	got, terminated := driveStream(p, streamCtxWithType("text/event-stream"), []string{rpc + sseEvent("FORBIDDEN token"), ""})
	if strings.Contains(got, "FORBIDDEN") || !terminated {
		t.Fatalf("token deltas must be assessed (terminated=%v, assessed=%q): %q", terminated, client.texts, got)
	}
}

// ─── a value split over token events is masked, not cut off ─────────────

func TestRegression_StreamedPIIOverSeveralTokensIsMasked(t *testing.T) {
	const pii = "support@acme.com"
	client := &reportsPIIWhenPresentClient{pii: pii}
	p := streamingPolicy(client, nil)
	body := sseEvent("Write to support") + sseEvent("@acme") + sseEvent(".com for help.") + "data: [DONE]\n\n"
	a := p.OnResponseBodyChunk(context.Background(), streamCtx(), &policy.StreamBody{Chunk: []byte(body), EndOfStream: true}, nil)
	fwd, ok := a.(policy.ForwardResponseChunk)
	if !ok {
		t.Fatalf("stream ended instead of masking an email split over tokens: %#v", a)
	}
	want := sseEvent("Write to {EMAIL}") + sseEvent("") + sseEvent(" for help.") + "data: [DONE]\n\n"
	if string(fwd.Body) != want {
		t.Fatalf("masked stream:\n got %q\nwant %q", fwd.Body, want)
	}
}

func TestRegression_BufferedSSEPIIOverSeveralTokensIsMasked(t *testing.T) {
	const pii = "support@acme.com"
	p := streamingPolicy(&reportsPIIWhenPresentClient{pii: pii}, nil)
	body := sseEvent("Write to support") + sseEvent("@acme") + sseEvent(".com for help.") + "data: [DONE]\n\n"
	mods := p.OnResponseBody(context.Background(), bufferedResponse(map[string]interface{}{}, "text/event-stream", body), nil).(policy.DownstreamResponseModifications)
	if mods.StatusCode != nil {
		t.Fatalf("buffered SSE rejected instead of masked: %s", mods.Body)
	}
	if strings.Contains(string(mods.Body), "support") || !strings.Contains(string(mods.Body), "{EMAIL}") {
		t.Fatalf("buffered SSE not masked: %q", mods.Body)
	}
}

func TestFindReplacementSpans_MatchesTheReplacer(t *testing.T) {
	replacements := []piiReplacement{
		{match: "john@example.com", replacement: "{EMAIL}"},
		{match: "john", replacement: "{NAME}"},
		{match: "0000", replacement: "{NUM}"},
	}
	for _, text := range []string{
		"",
		"nothing here",
		"john@example.com and john and 00000000",
		"johnjohn@example.com",
		"x0000john@example.comjohn",
	} {
		var b strings.Builder
		pos := 0
		for _, sp := range findReplacementSpans(text, replacements) {
			b.WriteString(text[pos:sp.start])
			b.WriteString(sp.replacement)
			pos = sp.end
		}
		b.WriteString(text[pos:])
		if want := applyPIIReplacements(text, replacements); b.String() != want {
			t.Errorf("spans of %q give %q, the replacer gives %q", text, b.String(), want)
		}
	}
}

// ─── a restored value is escaped ────────────────────────────────────────

func TestRegression_RestoredValueIsJSONEscaped(t *testing.T) {
	for _, original := range []string{"12 Main St\nSpringfield", `12 "Main" Street`, `12 Main St\Springfield`} {
		client := &countingBedrockClient{output: makeNoInterventionOutput()}
		p := streamingPolicy(client, nil)
		md := map[string]interface{}{MetadataKeyPIIEntities: map[string]string{original: "ADDRESS_0000"}}
		mods := p.OnResponseBody(context.Background(), bufferedResponse(md, "application/json",
			`{"choices":[{"message":{"content":"Shipping to ADDRESS_0000"}}]}`), nil).(policy.DownstreamResponseModifications)
		if mods.StatusCode != nil {
			t.Fatalf("%q: clean response rejected with %d after restoration: %s", original, *mods.StatusCode, mods.Body)
		}
		doc, err := decodeJSON(mods.Body)
		if err != nil {
			t.Fatalf("%q: restored body is not JSON: %q", original, mods.Body)
		}
		got := doc.(map[string]interface{})["choices"].([]interface{})[0].(map[string]interface{})["message"].(map[string]interface{})["content"]
		if got != "Shipping to "+original {
			t.Fatalf("%q: restored content = %q", original, got)
		}
		if client.calls != 1 {
			t.Fatalf("%q: the restored response must still be assessed, calls=%d", original, client.calls)
		}
	}
}

func TestRegression_RestoredValueInBufferedSSEIsJSONEscaped(t *testing.T) {
	p := streamingPolicy(&countingBedrockClient{output: makeNoInterventionOutput()}, nil)
	md := map[string]interface{}{MetadataKeyPIIEntities: map[string]string{`12 "Main" Street`: "ADDRESS_0000"}}
	body := sseEvent("Shipping to ADDRESS_0000") + "data: [DONE]\n\n"
	mods := p.OnResponseBody(context.Background(), bufferedResponse(md, "text/event-stream", body), nil).(policy.DownstreamResponseModifications)
	want := sseEvent(`Shipping to 12 "Main" Street`) + "data: [DONE]\n\n"
	if mods.StatusCode != nil || string(mods.Body) != want {
		t.Fatalf("restored SSE:\n got %q (status %v)\nwant %q", mods.Body, mods.StatusCode, want)
	}
}

func TestRegression_BodyWithoutPlaceholdersIsLeftByteForByte(t *testing.T) {
	p := streamingPolicy(&countingBedrockClient{output: makeNoInterventionOutput()}, nil)
	md := map[string]interface{}{MetadataKeyPIIEntities: map[string]string{"john@example.com": "EMAIL_0000"}}
	body := `{"z":1,  "choices":[{"message":{"content":"hello"}}]}`
	mods := p.OnResponseBody(context.Background(), bufferedResponse(md, "application/json", body), nil).(policy.DownstreamResponseModifications)
	if mods.StatusCode != nil || mods.Body != nil {
		t.Fatalf("a body with no placeholder must pass unchanged, got status %v body %q", mods.StatusCode, mods.Body)
	}
}

// ─── a value repeated past the batch boundary is masked by its own batch ─

func TestRegression_RepeatedValuePastTheBatchBoundaryIsMasked(t *testing.T) {
	const pii = "john@example.com"
	p := streamingPolicy(&reportsPIIWhenPresentClient{pii: pii}, func(pp *AWSBedrockGuardrailPolicyParams) {
		pp.RedactPII = true
		pp.StreamingTextUnitChars = 100
	})
	rc := streamCtx()
	var sb strings.Builder
	sb.WriteString(sseEvent("Contact " + pii + " today. "))
	for i := 0; i < 16; i++ {
		sb.WriteString(sseEvent("filler "))
	}
	sb.WriteString(sseEvent("again " + pii + " please. "))
	flushes := []string{sb.String(), "data: [DONE]\n\n"}

	var delivered strings.Builder
	for i, f := range flushes {
		a := p.OnResponseBodyChunk(context.Background(), rc, &policy.StreamBody{Chunk: []byte(f), EndOfStream: i == len(flushes)-1}, nil)
		if a.TerminateStream() {
			t.Fatalf("flush %d: stream ended although every occurrence could be masked by its own batch", i)
		}
		if fwd := a.(policy.ForwardResponseChunk); fwd.Body != nil {
			delivered.Write(fwd.Body)
		} else {
			delivered.WriteString(f)
		}
	}
	out := delivered.String()
	if strings.Contains(out, pii) || strings.Count(out, "*****") != 2 {
		t.Fatalf("want both occurrences masked, got %q", out)
	}
	if strings.Count(out, "filler ") != 16 || !strings.HasSuffix(out, "data: [DONE]\n\n") {
		t.Fatalf("events lost: %q", out)
	}
}

// ─── a rewritten frame keeps large integers ────────────────────────────

func TestRegression_FrameRewriteKeepsIntegerPrecision(t *testing.T) {
	frame := "data: {\"id\":9007199254740993,\"choices\":[{\"delta\":{\"content\":\"EMAIL_0000\"}}]}\n\n"
	out, changed := rewriteSSEDeltaContent(frame, ResponseDefaultStreamingJSONPath, func(string) string { return "x@y.z" })
	if !changed || !strings.Contains(out, "9007199254740993") || !strings.Contains(out, "x@y.z") {
		t.Fatalf("integer field corrupted by frame rewrite: %q", out)
	}
	out, changed = rewriteAcrossFrames(frame, ResponseDefaultStreamingJSONPath, []piiReplacement{{match: "EMAIL_0000", replacement: "{EMAIL}"}})
	if !changed || !strings.Contains(out, "9007199254740993") {
		t.Fatalf("integer field corrupted by the cross-frame rewrite: %q", out)
	}
}

// ─── second review round ─────────────────────────────────────────────────────

// A unit that fails under passthroughOnError must not drop the masking carried
// for a withheld frame from the batch before it.
func TestRegression_PassthroughFailureKeepsCarriedMasking(t *testing.T) {
	const pii = "john@example.com"
	client := &scriptedClient{
		outs: []*bedrockruntime.ApplyGuardrailOutput{makePIIIntervenedOutput(pii), nil},
		errs: []error{nil, errors.New("throttled")},
	}
	p := streamingPolicy(client, func(pp *AWSBedrockGuardrailPolicyParams) {
		pp.RedactPII = true
		pp.PassthroughOnError = true
		pp.StreamingTextUnitChars = 100
	})
	first := sseEvent(strings.Repeat("lorem ", 12)) + sseEvent("Mail "+pii+" now. and then a lot more words keep on going here")
	got, terminated := driveStream(p, streamCtxWithType("text/event-stream"),
		[]string{first, sseEvent(" tail words.") + "data: [DONE]\n\n"})
	if terminated || strings.Contains(got, pii) || !strings.Contains(got, "Mail ***** now.") {
		t.Fatalf("the reported value must stay masked when a later unit fails (terminated=%v, calls=%d): %q", terminated, client.calls, got)
	}
}

// A JSON document labelled text/event-stream is read with jsonPath, as in v1.4:
// assessed whether or not it ends in a newline, and passed when it is clean.
func TestRegression_JSONDocumentLabelledEventStreamIsReadWithJSONPath(t *testing.T) {
	for _, body := range []string{
		`{"choices":[{"message":{"content":"FORBIDDEN answer"}}]}`,
		`{"choices":[{"message":{"content":"FORBIDDEN answer"}}]}` + "\n",
		"{\n  \"choices\": [{\"message\": {\"content\": \"FORBIDDEN answer\"}}]\n}\n",
	} {
		client := &blockOnClient{needle: "FORBIDDEN"}
		p := streamingPolicy(client, nil)
		mods := p.OnResponseBody(context.Background(), bufferedResponse(map[string]interface{}{}, "text/event-stream", body), nil).(policy.DownstreamResponseModifications)
		if mods.StatusCode == nil || mods.Fault == nil || mods.Fault.Type != policy.FaultTypeGuardrail {
			t.Errorf("buffered %q: want a guardrail verdict, got status=%v fault=%+v", body, mods.StatusCode, mods.Fault)
		}
		got, terminated := driveStream(p, streamCtxWithType("text/event-stream"), []string{body})
		if !terminated || strings.Contains(got, "FORBIDDEN answer") {
			t.Errorf("streamed %q: want the guardrail verdict, got terminated=%v %q", body, terminated, got)
		}

		clean := strings.Replace(body, "FORBIDDEN answer", "fine answer", 1)
		mods = streamingPolicy(&blockOnClient{needle: "FORBIDDEN"}, nil).OnResponseBody(context.Background(),
			bufferedResponse(map[string]interface{}{}, "text/event-stream", clean), nil).(policy.DownstreamResponseModifications)
		if mods.StatusCode != nil {
			t.Errorf("clean %q: must pass, got %s", clean, mods.Body)
		}
	}
}

// Prose in an event stream's unterminated last line is not exempt: only an SSE
// field cut off there is.
func TestRegression_ProseInTheLastLineEndsTheStream(t *testing.T) {
	body := sseEvent("Hello. ") + "Here is the FORBIDDEN answer."
	p := streamingPolicy(&blockOnClient{needle: "NEVER"}, nil)
	mods := p.OnResponseBody(context.Background(), bufferedResponse(map[string]interface{}{}, "text/event-stream", body), nil).(policy.DownstreamResponseModifications)
	if mods.StatusCode == nil {
		t.Errorf("buffered: prose in the last line must be refused")
	}
	got, terminated := driveStream(streamingPolicy(&blockOnClient{needle: "NEVER"}, nil), streamCtxWithType("text/event-stream"), []string{body})
	if !terminated || strings.Contains(got, "FORBIDDEN") {
		t.Errorf("streamed: prose in the last line must be refused, got terminated=%v %q", terminated, got)
	}
}

// Lines ended by a bare carriage return are not split by this reader, so their
// text cannot be read; the stream is refused rather than delivered.
func TestRegression_CarriageReturnLineEndingsAreRefused(t *testing.T) {
	body := strings.ReplaceAll(sseEvent("Hello ")+sseEvent("FORBIDDEN world."), "\n", "\r") + "data: [DONE]\r\r"
	got, terminated := driveStream(streamingPolicy(&blockOnClient{needle: "NEVER"}, nil), streamCtxWithType("text/event-stream"), []string{body, ""})
	if !terminated || strings.Contains(got, "FORBIDDEN") {
		t.Fatalf("a CR-only stream must be refused, got terminated=%v %q", terminated, got)
	}
}

// Restoring a placeholder changes only the placeholder: layout, key order and
// escapes stay as the upstream wrote them, and a placeholder used as a key is
// restored too.
func TestRegression_RestoreKeepsTheBodyLayout(t *testing.T) {
	md := map[string]interface{}{MetadataKeyPIIEntities: map[string]string{"john@example.com": "EMAIL_0000"}}
	in := "{\n  \"zeta\": 1.50,\n  \"choices\": [{\"message\": {\"content\": \"mail EMAIL_0000\"}}],\n  \"contacts\": {\"EMAIL_0000\": {\"tier\": \"gold\"}},\n  \"alpha\": \"caf\\u00e9 \\/ x\"\n}"
	want := strings.ReplaceAll(in, "EMAIL_0000", "john@example.com")
	p := streamingPolicy(&blockOnClient{needle: "NEVER"}, func(pp *AWSBedrockGuardrailPolicyParams) { pp.JsonPath = "$.choices[0].message.content" })
	mods := p.OnResponseBody(context.Background(), bufferedResponse(md, "application/json", in), nil).(policy.DownstreamResponseModifications)
	if mods.StatusCode != nil || string(mods.Body) != want {
		t.Fatalf("restored body:\n got %q\nwant %q", mods.Body, want)
	}
}

// Once passthroughOnError releases a body too large to withhold, the rest of it
// passes as it is: nothing more is accumulated, and nothing is appended to a
// response the client already has.
func TestRegression_PassthroughReleaseStopsAccumulating(t *testing.T) {
	p := streamingPolicy(&blockOnClient{needle: "FORBIDDEN"}, func(pp *AWSBedrockGuardrailPolicyParams) {
		pp.JsonPath = ""
		pp.PassthroughOnError = true
	})
	rc := streamCtxWithType("text/plain")
	mib := strings.Repeat("x", 1<<20)
	var flushes []string
	for i := 0; i < 8; i++ {
		flushes = append(flushes, mib)
	}
	flushes = append(flushes, "a FORBIDDEN tail")
	got, terminated := driveStream(p, rc, flushes)
	if terminated {
		t.Errorf("nothing may be appended after the body was released")
	}
	if got != strings.Join(flushes, "") {
		t.Errorf("every byte must be delivered once, got %d of %d bytes", len(got), len(strings.Join(flushes, "")))
	}
	if _, kept := rc.Metadata[p.stateKey(metaKeyAccStreamedJSONBody)]; kept {
		t.Errorf("nothing may be kept after the release")
	}
}

// Every way the JSON-RPC stream path ends a stream declares a mediation fault.
func TestRegression_JSONRPCStreamRejectionsDeclareFaults(t *testing.T) {
	rpc := "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"harmless\"}]}}\n\n"
	big := "data: {\"jsonrpc\":\"2.0\",\"id\":3,\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"" + strings.Repeat("x", maxHeldFlushBytes+1)
	cases := map[string][]string{
		"event over the withheld-bytes limit": {rpc, big, ""},
		"unreadable line":                     {rpc, "Here is some prose.\n\n", ""},
		"token deltas after JSON-RPC":         {rpc, sseEvent("FORBIDDEN token"), ""},
	}
	for name, flushes := range cases {
		p := streamingPolicy(&blockOnClient{needle: "NEVER"}, func(pp *AWSBedrockGuardrailPolicyParams) { pp.JsonPath = "$.result.content[*].text" })
		rc := streamCtxWithType("text/event-stream")
		var last policy.StreamingResponseAction
		for i, f := range flushes {
			last = p.OnResponseBodyChunk(context.Background(), rc, &policy.StreamBody{Chunk: []byte(f), EndOfStream: i == len(flushes)-1}, nil)
			if last.TerminateStream() {
				break
			}
		}
		term, ok := last.(policy.TerminateResponseChunk)
		if !ok {
			t.Errorf("%s: want the stream ended, got %#v", name, last)
			continue
		}
		if !term.IsFault || term.Fault == nil || term.Fault.Code != policy.FaultCodeMediationFailed ||
			term.Fault.Type != policy.FaultTypeMediation || term.Fault.Direction != policy.DirectionResponse {
			t.Errorf("%s: want a mediation fault, got IsFault=%v %+v", name, term.IsFault, term.Fault)
		}
	}
}

// ─── third review round ──────────────────────────────────────────────────────

// An MCP event stream that opens with a byte order mark is still read as
// JSON-RPC and assessed, buffered and streamed.
func TestRegression_JSONRPCStreamWithAByteOrderMarkIsAssessed(t *testing.T) {
	body := "\uFEFFdata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"FORBIDDEN tool output\"}]}}\n\n"
	params := func(pp *AWSBedrockGuardrailPolicyParams) { pp.JsonPath = "$.result.content[0].text" }

	client := &blockOnClient{needle: "FORBIDDEN"}
	mods := streamingPolicy(client, params).OnResponseBody(context.Background(),
		bufferedResponse(map[string]interface{}{}, "text/event-stream", body), nil).(policy.DownstreamResponseModifications)
	if mods.StatusCode == nil || len(client.texts) == 0 {
		t.Errorf("buffered: want the tool output assessed and blocked, got status=%v assessed=%q", mods.StatusCode, client.texts)
	}

	client = &blockOnClient{needle: "FORBIDDEN"}
	got, terminated := driveStream(streamingPolicy(client, params), streamCtxWithType("text/event-stream"), []string{body, ""})
	if !terminated || strings.Contains(got, "FORBIDDEN tool output") {
		t.Errorf("streamed: want the tool output assessed and blocked, got terminated=%v %q", terminated, got)
	}
}

// Text that only opens like an SSE field is not an event stream unless it
// carries a data line: it is read with jsonPath (here the whole body), as before.
func TestRegression_TextOpeningLikeAFieldIsAssessedAsText(t *testing.T) {
	for _, body := range []string{
		"id: 42\nname: John\nanswer: here is the FORBIDDEN thing\n",
		":) Sure, here is the FORBIDDEN answer.\nIt is fine.\n",
	} {
		client := &blockOnClient{needle: "FORBIDDEN"}
		p := streamingPolicy(client, func(pp *AWSBedrockGuardrailPolicyParams) { pp.JsonPath = "" })
		mods := p.OnResponseBody(context.Background(), bufferedResponse(map[string]interface{}{}, "text/plain", body), nil).(policy.DownstreamResponseModifications)
		if mods.StatusCode == nil || mods.Fault == nil || mods.Fault.Type != policy.FaultTypeGuardrail {
			t.Errorf("buffered %q: want a guardrail verdict, got status=%v fault=%+v", body, mods.StatusCode, mods.Fault)
		}

		clean := strings.Replace(body, "FORBIDDEN", "fine", 1)
		mods = streamingPolicy(&blockOnClient{needle: "FORBIDDEN"}, func(pp *AWSBedrockGuardrailPolicyParams) { pp.JsonPath = "" }).
			OnResponseBody(context.Background(), bufferedResponse(map[string]interface{}{}, "text/plain", clean), nil).(policy.DownstreamResponseModifications)
		if mods.StatusCode != nil {
			t.Errorf("clean %q: must pass, got %s", clean, mods.Body)
		}
	}
}

// A chunked body that is neither JSON nor an event stream is withheld until the
// end and assessed whole, so a violation leaks nothing and request placeholders
// are restored, as when the response is buffered.
func TestRegression_ChunkedPlainTextIsWithheldUntilAssessed(t *testing.T) {
	filler := strings.Repeat("plain text filler. ", 260) // ~4.9 KB, past the pacer
	params := func(pp *AWSBedrockGuardrailPolicyParams) { pp.JsonPath = "" }

	got, terminated := driveStream(streamingPolicy(&blockOnClient{needle: "FORBIDDEN"}, params),
		streamCtxWithType("text/plain"), []string{filler, "and a FORBIDDEN ending."})
	if !terminated || strings.Contains(got, "filler") || strings.Contains(got, "FORBIDDEN ending") {
		t.Errorf("violation: nothing of the body may be delivered, got terminated=%v %d bytes", terminated, len(got))
	}

	rc := streamCtxWithType("text/plain")
	rc.Metadata[MetadataKeyPIIEntities] = map[string]string{"john@example.com": "EMAIL_0000"}
	got, terminated = driveStream(streamingPolicy(&blockOnClient{needle: "FORBIDDEN"}, params), rc,
		[]string{filler, "Reply to EMAIL_0000 now."})
	if terminated || got != filler+"Reply to john@example.com now." {
		t.Errorf("restoration: want the whole body once, restored; got terminated=%v tail %q", terminated, got[max(0, len(got)-40):])
	}
}

// A body too large to withhold ends with a fault, or is released under
// passthroughOnError.
func TestRegression_OversizedNonSSEBodyIsBounded(t *testing.T) {
	big := strings.Repeat("x", maxNonSSEHeldBytes+1)
	got, terminated := driveStream(streamingPolicy(&blockOnClient{needle: "NEVER"}, func(pp *AWSBedrockGuardrailPolicyParams) { pp.JsonPath = "" }),
		streamCtxWithType("text/plain"), []string{big, "tail"})
	if !terminated || strings.Contains(got, "xxxx") {
		t.Errorf("without passthrough: want the stream ended with nothing delivered, got terminated=%v %d bytes", terminated, len(got))
	}
	got, terminated = driveStream(streamingPolicy(&blockOnClient{needle: "NEVER"}, func(pp *AWSBedrockGuardrailPolicyParams) {
		pp.JsonPath = ""
		pp.PassthroughOnError = true
	}), streamCtxWithType("text/plain"), []string{big, "tail"})
	if terminated || got != big+"tail" {
		t.Errorf("with passthrough: want the body released once, got terminated=%v %d bytes", terminated, len(got))
	}
}

// reportsEntityClient reports match as an ANONYMIZED entity of the given type
// whenever the assessed text contains it.
type reportsEntityClient struct {
	match      string
	entityType types.GuardrailPiiEntityType
}

func (c *reportsEntityClient) ApplyGuardrail(_ context.Context, params *bedrockruntime.ApplyGuardrailInput, _ ...func(*bedrockruntime.Options)) (*bedrockruntime.ApplyGuardrailOutput, error) {
	for _, content := range params.Content {
		if text, ok := content.(*types.GuardrailContentBlockMemberText); ok && strings.Contains(aws.ToString(text.Value.Text), c.match) {
			out := makePIIIntervenedOutput(c.match)
			out.Assessments[0].SensitiveInformationPolicy.PiiEntities[0].Type = c.entityType
			return out, nil
		}
	}
	return makeNoInterventionOutput(), nil
}

// A request value Bedrock reports with a narrower boundary in the response is
// restored, not masked again -- but new PII that merely appears inside a request
// value, or of a different type, is still masked.
func TestRegression_PartOfARestoredValueIsNotMaskedAgain(t *testing.T) {
	respond := func(entities map[string]string, client bedrockGuardrailClient, content string) string {
		md := map[string]interface{}{MetadataKeyPIIEntities: entities}
		mods := streamingPolicy(client, nil).OnResponseBody(context.Background(), bufferedResponse(md, "application/json",
			`{"choices":[{"message":{"content":"`+content+`"}}]}`), nil).(policy.DownstreamResponseModifications)
		if mods.StatusCode != nil {
			t.Fatalf("unexpected rejection: %s", mods.Body)
		}
		return string(mods.Body)
	}

	name := map[string]string{"John Smith": "NAME_0000"}
	if got := respond(name, &reportsEntityClient{"John", types.GuardrailPiiEntityTypeName}, "Hello NAME_0000, welcome."); !strings.Contains(got, "Hello John Smith, welcome.") {
		t.Errorf("part of the restored name must not be masked again, got %s", got)
	}
	if got := respond(name, &reportsEntityClient{"John", types.GuardrailPiiEntityTypeName}, "Hello NAME_0000, John Doe called."); strings.Contains(got, "John Doe") {
		t.Errorf("a different John elsewhere in the response must be masked, got %s", got)
	}
	address := map[string]string{"Flat 1234, 56 Elm Road": "ADDRESS_0000"}
	if got := respond(address, &reportsEntityClient{"1234", types.GuardrailPiiEntityTypePin}, "Your new PIN is 1234."); strings.Contains(got, "1234") {
		t.Errorf("new PII contained in a request value must be masked, got %s", got)
	}
}

// On a JSON-RPC event stream, a data payload that is not JSON is refused even
// beside a JSON-RPC event, on the buffered and the streamed path; a JSON-RPC
// message split over several data lines is still read.
func TestRegression_JSONRPCStreamRefusesUnreadableEvents(t *testing.T) {
	rpc := "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"fine\"}]}}\n\n"
	params := func(pp *AWSBedrockGuardrailPolicyParams) { pp.JsonPath = "$.result.content[*].text" }
	for _, extra := range []string{"event: message\ndata: FORBIDDEN plain text\n\n", "FORBIDDEN outside any event\n\n"} {
		body := rpc + extra
		mods := streamingPolicy(&blockOnClient{needle: "NEVER"}, params).OnResponseBody(context.Background(),
			bufferedResponse(map[string]interface{}{}, "text/event-stream", body), nil).(policy.DownstreamResponseModifications)
		if mods.StatusCode == nil || mods.Fault == nil || mods.Fault.Code != policy.FaultCodeMediationFailed {
			t.Errorf("buffered %q: want a mediation fault, got status=%v fault=%+v", extra, mods.StatusCode, mods.Fault)
		}
		got, terminated := driveStream(streamingPolicy(&blockOnClient{needle: "NEVER"}, params), streamCtxWithType("text/event-stream"), []string{body, ""})
		if !terminated || strings.Contains(got, "FORBIDDEN") {
			t.Errorf("streamed %q: want the stream ended, got terminated=%v %q", extra, terminated, got)
		}
	}

	multi := "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\ndata: \"result\":{\"content\":[{\"type\":\"text\",\"text\":\"fine\"}]}}\n\n"
	mods := streamingPolicy(&blockOnClient{needle: "NEVER"}, params).OnResponseBody(context.Background(),
		bufferedResponse(map[string]interface{}{}, "text/event-stream", multi), nil).(policy.DownstreamResponseModifications)
	if mods.StatusCode != nil {
		t.Errorf("a JSON-RPC message over several data lines must still be read, got %s", mods.Body)
	}
}

// A last line with no terminator is only exempt when it is a field cut off
// there; a data line carrying plain text is still refused.
func TestRegression_UnterminatedPlainDataLineIsRefused(t *testing.T) {
	body := sseEvent("Hello. ") + "data: FORBIDDEN plain text"
	mods := streamingPolicy(&blockOnClient{needle: "NEVER"}, nil).OnResponseBody(context.Background(),
		bufferedResponse(map[string]interface{}{}, "text/event-stream", body), nil).(policy.DownstreamResponseModifications)
	if mods.StatusCode == nil {
		t.Errorf("an unterminated non-JSON data line must be refused")
	}
}

// A line that is not one of the fields the SSE specification defines is refused,
// buffered and streamed: an EventSource ignores it, but other clients show it.
func TestRegression_LinesOutsideTheSSEFieldsAreRefused(t *testing.T) {
	for _, body := range []string{
		"Name: John\nSSN: 123-45-6789\n",
		sseEvent("Here you go.") + "123-45-6789\n4111111111111111\n\n" + "data: [DONE]\n\n",
		"x-trace: abc\n" + sseEvent("Hello.") + "data: [DONE]\n\n",
	} {
		mods := streamingPolicy(&blockOnClient{needle: "NEVER"}, nil).OnResponseBody(context.Background(),
			bufferedResponse(map[string]interface{}{}, "text/event-stream", body), nil).(policy.DownstreamResponseModifications)
		if mods.StatusCode == nil || mods.Fault == nil || mods.Fault.Code != policy.FaultCodeMediationFailed {
			t.Errorf("buffered %q: want a mediation fault, got status=%v fault=%+v", body, mods.StatusCode, mods.Fault)
		}
		got, terminated := driveStream(streamingPolicy(&blockOnClient{needle: "NEVER"}, nil), streamCtxWithType("text/event-stream"), []string{body, ""})
		if !terminated || strings.Contains(got, "123-45-6789") {
			t.Errorf("streamed %q: want the stream ended, got terminated=%v %q", body, terminated, got)
		}
	}
}

// ─── fourth review round ─────────────────────────────────────────────────────

// A token stream that streamingJsonPath does not describe -- a provider's own
// format, or JSON that is not an object -- is refused rather than delivered as
// if it carried no text; streams it does describe, including ones with no text
// at that path in some events, are not.
func TestRegression_StreamThatStreamingJsonPathDoesNotDescribeIsRefused(t *testing.T) {
	anthropic := "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\"FORBIDDEN how-to\"}}\n\n"
	for _, body := range []string{anthropic, "data: \"FORBIDDEN token\"\n\n"} {
		got, terminated := driveStream(streamingPolicy(&blockOnClient{needle: "FORBIDDEN"}, nil), streamCtxWithType("text/event-stream"), []string{body, ""})
		if !terminated || strings.Contains(got, "FORBIDDEN") {
			t.Errorf("streamed %q: want the stream ended, got terminated=%v %q", body, terminated, got)
		}
		mods := streamingPolicy(&blockOnClient{needle: "FORBIDDEN"}, nil).OnResponseBody(context.Background(),
			bufferedResponse(map[string]interface{}{}, "text/event-stream", body), nil).(policy.DownstreamResponseModifications)
		if mods.StatusCode == nil {
			t.Errorf("buffered %q: want a refusal", body)
		}
		got, terminated = driveStream(streamingPolicy(&blockOnClient{needle: "NEVER"}, func(pp *AWSBedrockGuardrailPolicyParams) { pp.PassthroughOnError = true }),
			streamCtxWithType("text/event-stream"), []string{body, ""})
		if terminated || got != body {
			t.Errorf("passthrough %q: want it delivered as before, got terminated=%v", body, terminated)
		}
	}

	for name, body := range map[string]string{
		"role delta first": "data: {\"choices\":[{\"delta\":{\"role\":\"assistant\"}}]}\n\n" + sseEvent("Hello.") + "data: [DONE]\n\n",
		"tool calls only":  "data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"function\":{\"arguments\":\"{}\"}}]}}]}\n\ndata: [DONE]\n\n",
		"provider error":   "data: {\"error\":{\"message\":\"rate limited\"}}\n\n",
	} {
		got, terminated := driveStream(streamingPolicy(&blockOnClient{needle: "NEVER"}, nil), streamCtxWithType("text/event-stream"), []string{body, ""})
		if terminated || got != body {
			t.Errorf("%s: must be delivered unchanged, got terminated=%v %q", name, terminated, got)
		}
	}
}

// On the JSON-RPC stream path, a batch whose JSON event is not itself a
// JSON-RPC message is still read with jsonPath.
func TestRegression_JSONRPCStreamBatchWithoutAJSONRPCMessageIsAssessed(t *testing.T) {
	rpc := "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"fine\"}]}}\n\n"
	odd := "data: {\"result\":{\"content\":[{\"text\":\"FORBIDDEN\"}]}}\n\n"
	got, terminated := driveStream(streamingPolicy(&blockOnClient{needle: "FORBIDDEN"}, func(pp *AWSBedrockGuardrailPolicyParams) { pp.JsonPath = "$.result.content[*].text" }),
		streamCtxWithType("text/event-stream"), []string{rpc, odd, ""})
	if !terminated || strings.Contains(got, "FORBIDDEN") {
		t.Fatalf("want the event assessed and the stream ended, got terminated=%v %q", terminated, got)
	}
}

// A type an event stream is not mislabelled as is taken at its word: YAML whose
// first line is "id:" and that has a "data:" line is read with jsonPath, as in
// v1.4.
func TestRegression_OtherContentTypesAreNotSniffed(t *testing.T) {
	body := "id: 42\nname: widget\ndata: ok\n"
	client := &blockOnClient{needle: "NEVER"}
	mods := streamingPolicy(client, func(pp *AWSBedrockGuardrailPolicyParams) { pp.JsonPath = "" }).OnResponseBody(context.Background(),
		bufferedResponse(map[string]interface{}{}, "application/yaml", body), nil).(policy.DownstreamResponseModifications)
	if mods.StatusCode != nil || len(client.texts) == 0 {
		t.Fatalf("want the YAML assessed and passed, got status=%v assessed=%q", mods.StatusCode, client.texts)
	}
}

// A body released unassessed under passthroughOnError still has the request's
// placeholders put back.
func TestRegression_PassthroughReleaseIsRestored(t *testing.T) {
	rc := streamCtxWithType("text/plain")
	rc.Metadata[MetadataKeyPIIEntities] = map[string]string{"john@x.com": "EMAIL_0000"}
	part := strings.Repeat("y", 1<<20) + " EMAIL_0000 "
	var flushes []string
	for i := 0; i < 5; i++ {
		flushes = append(flushes, part)
	}
	got, terminated := driveStream(streamingPolicy(&blockOnClient{needle: "NEVER"}, func(pp *AWSBedrockGuardrailPolicyParams) {
		pp.JsonPath = ""
		pp.PassthroughOnError = true
	}), rc, flushes)
	if terminated || strings.Contains(got, "EMAIL_0000") || strings.Count(got, "john@x.com") != 5 {
		t.Fatalf("want every placeholder restored, got terminated=%v placeholders=%d restored=%d", terminated, strings.Count(got, "EMAIL_0000"), strings.Count(got, "john@x.com"))
	}
}

// A response that could not be assessed tells the client so, rather than
// reporting a violation no guardrail made.
func TestRegression_UnassessableResponseSaysSo(t *testing.T) {
	got, terminated := driveStream(streamingPolicy(&blockOnClient{needle: "NEVER"}, nil), streamCtxWithType("text/event-stream"),
		[]string{sseEvent("Hello.") + "data: not json\n\n", ""})
	if !terminated || !strings.Contains(got, "Response content could not be assessed") || strings.Contains(got, "Violation") {
		t.Fatalf("want the reason to say the content could not be assessed, got %q", got)
	}
}

// A format whose first events lack the member streamingJsonPath starts with
// (Anthropic's message_start and content_block_start) streams normally when the
// path is configured for it: those events wait for the first one that has it.
func TestRegression_StreamOpeningWithoutThePathMemberIsNotRefused(t *testing.T) {
	ev := func(json string) string { return "data: " + json + "\n\n" }
	flushes := func(text string) []string {
		return []string{
			"event: message_start\n" + ev(`{"type":"message_start","message":{"id":"m","role":"assistant"}}`),
			"event: content_block_start\n" + ev(`{"type":"content_block_start","index":0}`) + "event: ping\n" + ev(`{"type":"ping"}`),
			"event: content_block_delta\n" + ev(`{"type":"content_block_delta","delta":{"type":"text_delta","text":"`+text+`"}}`),
			"event: message_stop\n" + ev(`{"type":"message_stop"}`),
		}
	}
	params := func(pp *AWSBedrockGuardrailPolicyParams) { pp.StreamingJsonPath = "$.delta.text" }

	clean := flushes("Hello there.")
	got, terminated := driveStream(streamingPolicy(&blockOnClient{needle: "FORBIDDEN"}, params), streamCtxWithType("text/event-stream"), clean)
	if terminated || got != strings.Join(clean, "") {
		t.Errorf("clean stream: want it delivered unchanged, got terminated=%v %q", terminated, got)
	}
	got, terminated = driveStream(streamingPolicy(&blockOnClient{needle: "FORBIDDEN"}, params), streamCtxWithType("text/event-stream"), flushes("FORBIDDEN text."))
	if !terminated || strings.Contains(got, "FORBIDDEN text") {
		t.Errorf("violating stream: want it blocked, got terminated=%v %q", terminated, got)
	}
}

// anthropicStream is a whole Anthropic-style event stream: its deltas sit under
// delta.text, which the default streamingJsonPath does not address.
func anthropicStream(text string) string {
	return "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"" + text + "\"}}\n\n" +
		"event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n"
}

// An empty jsonPath assesses the whole payload, an event stream included, as in
// v1.4: the stream is not read with streamingJsonPath.
func TestRegression_EmptyJSONPathAssessesAnEventStreamWhole(t *testing.T) {
	emptyPath := func(pp *AWSBedrockGuardrailPolicyParams) { pp.JsonPath = "" }
	for _, ct := range []string{"text/event-stream", "text/plain", ""} {
		for _, body := range []string{anthropicStream("Hello there"), "data: hello world\n\n"} {
			client := &blockOnClient{needle: "NEVER"}
			mods := streamingPolicy(client, emptyPath).OnResponseBody(context.Background(),
				bufferedResponse(map[string]interface{}{}, ct, body), nil).(policy.DownstreamResponseModifications)
			if mods.StatusCode != nil || mods.Body != nil || len(client.texts) != 1 || !strings.Contains(client.texts[0], "data: ") {
				t.Errorf("buffered %q %q: want the whole body assessed once and passed, got status=%v body=%q assessed=%q",
					ct, body, mods.StatusCode, mods.Body, client.texts)
			}
		}
	}

	client := &blockOnClient{needle: "FORBIDDEN"}
	mods := streamingPolicy(client, emptyPath).OnResponseBody(context.Background(),
		bufferedResponse(map[string]interface{}{}, "text/event-stream", anthropicStream("FORBIDDEN")), nil).(policy.DownstreamResponseModifications)
	if mods.StatusCode == nil || *mods.StatusCode != 422 || !mods.IsFault {
		t.Errorf("buffered violation: want 422 with a fault, got status=%v fault=%v", mods.StatusCode, mods.IsFault)
	}

	body := anthropicStream("Hello there")
	client = &blockOnClient{needle: "NEVER"}
	got, terminated := driveStream(streamingPolicy(client, emptyPath), streamCtxWithType("text/event-stream"),
		[]string{body[:40], body[40:], ""})
	if terminated || got != body || len(client.texts) != 1 || client.texts[0] != strings.TrimSpace(body) {
		t.Errorf("streamed: want the whole body assessed once and delivered, got terminated=%v %q assessed=%q", terminated, got, client.texts)
	}
	got, terminated = driveStream(streamingPolicy(&blockOnClient{needle: "FORBIDDEN"}, emptyPath), streamCtxWithType("text/event-stream"),
		[]string{anthropicStream("FORBIDDEN"), ""})
	if !terminated || strings.Contains(got, "text_delta") {
		t.Errorf("streamed violation: want the stream ended before any of it was delivered, got terminated=%v %q", terminated, got)
	}
}

// A JSON-RPC message that carries content the jsonPath does not reach is an
// extraction error, as in v1.4; only content-free messages (initialize, lists,
// notifications and their results) pass unassessed.
func TestRegression_JSONRPCContentThePathMissesIsNotPassed(t *testing.T) {
	const argsPath = "$.params.arguments.query"
	call := `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"run_sql","arguments":{"sql":"FORBIDDEN"}}}`
	client := &blockOnClient{needle: "FORBIDDEN"}
	if resp, ok := sendRequest(requestPolicy(client, argsPath), map[string]interface{}{}, call).(policy.ImmediateResponse); !ok || resp.StatusCode != 422 || !resp.IsFault ||
		resp.Fault == nil || len(client.texts) != 0 {
		t.Errorf("tools/call the path misses: want 422 with a fault and no assessment, got ok=%v status=%d assessed=%q", ok, resp.StatusCode, client.texts)
	}

	passthrough := requestPolicy(&blockOnClient{needle: "FORBIDDEN"}, argsPath)
	passthrough.requestParams.PassthroughOnError = true
	if _, blocked := sendRequest(passthrough, map[string]interface{}{}, call).(policy.ImmediateResponse); blocked {
		t.Errorf("tools/call the path misses, passthroughOnError: want it passed")
	}

	for _, msg := range []string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","clientInfo":{"name":"c","version":"1"}}}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","method":"notifications/progress","params":{"progressToken":1,"progress":5}}`,
	} {
		client := &blockOnClient{needle: "NEVER"}
		if _, blocked := sendRequest(requestPolicy(client, argsPath), map[string]interface{}{}, msg).(policy.ImmediateResponse); blocked || len(client.texts) != 0 {
			t.Errorf("content-free %s: want it passed unassessed, got blocked=%v assessed=%q", msg, blocked, client.texts)
		}
	}

	const resultPath = "$.result.content[*].text"
	for _, msg := range []string{
		`{"jsonrpc":"2.0","id":7,"result":{"structuredContent":{"rows":"FORBIDDEN"}}}`,
		`{"jsonrpc":"2.0","id":7,"result":{"content":[{"type":"resource","resource":{"text":"FORBIDDEN"}}]}}`,
		`{"jsonrpc":"2.0","id":7,"error":{"code":-32000,"message":"failed","data":"FORBIDDEN"}}`,
		`{"jsonrpc":"2.0","method":"notifications/message","params":{"level":"info","data":"FORBIDDEN"}}`,
	} {
		p := streamingPolicy(&blockOnClient{needle: "FORBIDDEN"}, func(pp *AWSBedrockGuardrailPolicyParams) { pp.JsonPath = resultPath })
		mods := p.OnResponseBody(context.Background(), bufferedResponse(map[string]interface{}{}, "application/json", msg), nil).(policy.DownstreamResponseModifications)
		if mods.StatusCode == nil || *mods.StatusCode != 422 || !mods.IsFault {
			t.Errorf("response %s: want 422 with a fault, got status=%v", msg, mods.StatusCode)
		}
		sse := "event: message\ndata: " + msg + "\n\n"
		got, terminated := driveStream(streamingPolicy(&blockOnClient{needle: "FORBIDDEN"}, func(pp *AWSBedrockGuardrailPolicyParams) { pp.JsonPath = resultPath }),
			streamCtxWithType("text/event-stream"), []string{sse, ""})
		if !terminated || strings.Contains(got, "FORBIDDEN") {
			t.Errorf("streamed %s: want the stream ended, got terminated=%v %q", msg, terminated, got)
		}
	}

	for _, msg := range []string{
		`{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18","capabilities":{},"serverInfo":{"name":"s","version":"1"}}}`,
		`{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"run_sql","description":"Runs SQL"}]}}`,
		`{"jsonrpc":"2.0","id":3,"result":{}}`,
		`{"jsonrpc":"2.0","id":4,"error":{"code":-32601,"message":"Method not found"}}`,
	} {
		client := &blockOnClient{needle: "NEVER"}
		p := streamingPolicy(client, func(pp *AWSBedrockGuardrailPolicyParams) { pp.JsonPath = resultPath })
		mods := p.OnResponseBody(context.Background(), bufferedResponse(map[string]interface{}{}, "application/json", msg), nil).(policy.DownstreamResponseModifications)
		if mods.StatusCode != nil || len(client.texts) != 0 {
			t.Errorf("content-free response %s: want it passed unassessed, got status=%v assessed=%q", msg, mods.StatusCode, client.texts)
		}
		sse := "event: message\ndata: " + msg + "\n\n"
		got, terminated := driveStream(streamingPolicy(&blockOnClient{needle: "NEVER"}, func(pp *AWSBedrockGuardrailPolicyParams) { pp.JsonPath = resultPath }),
			streamCtxWithType("text/event-stream"), []string{sse, ""})
		if terminated || got != sse {
			t.Errorf("streamed content-free %s: want it delivered, got terminated=%v %q", msg, terminated, got)
		}
	}
}
