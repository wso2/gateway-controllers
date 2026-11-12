/*
 *  Copyright (c) 2026, WSO2 LLC. (http://www.wso2.com) All Rights Reserved.
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

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime/types"
	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

// The policy must satisfy the streaming contract for the kernel to upgrade the
// route; declaring BodyModeStream without it only logs a warning at chain build
// and silently falls back to buffered.
var _ policy.StreamingResponsePolicy = (*AWSBedrockGuardrailPolicy)(nil)

// countingBedrockClient records how many ApplyGuardrail calls a stream makes.
// The count is the regression guard for the window: a policy that validates per
// chunk instead of per window still passes every behavioural assertion below
// while billing one AWS call per token.
type countingBedrockClient struct {
	output *bedrockruntime.ApplyGuardrailOutput
	err    error
	calls  int
	texts  []string
}

// ApplyGuardrail records the call and the text it carried, so a test can assert
// how many billable assessments a stream made and what was sent.
func (c *countingBedrockClient) ApplyGuardrail(_ context.Context, params *bedrockruntime.ApplyGuardrailInput, _ ...func(*bedrockruntime.Options)) (*bedrockruntime.ApplyGuardrailOutput, error) {
	c.calls++
	for _, content := range params.Content {
		if text, ok := content.(*types.GuardrailContentBlockMemberText); ok {
			c.texts = append(c.texts, aws.ToString(text.Value.Text))
		}
	}
	return c.output, c.err
}

// makeNoInterventionOutput is the "no violation" decision.
func makeNoInterventionOutput() *bedrockruntime.ApplyGuardrailOutput {
	return &bedrockruntime.ApplyGuardrailOutput{Action: types.GuardrailActionNone}
}

// makeContentViolationOutput is a content-policy block, the decision that must
// end a stream.
func makeContentViolationOutput() *bedrockruntime.ApplyGuardrailOutput {
	return &bedrockruntime.ApplyGuardrailOutput{
		Action:      types.GuardrailActionGuardrailIntervened,
		Assessments: []types.GuardrailAssessment{{}},
	}
}

// streamingPolicy builds an instance configured the way an API author enabling
// streaming on the response flow would get it.
func streamingPolicy(client bedrockGuardrailClient, mutate func(*AWSBedrockGuardrailPolicyParams)) *AWSBedrockGuardrailPolicy {
	params := AWSBedrockGuardrailPolicyParams{
		Enabled:                true,
		JsonPath:               ResponseDefaultJSONPath,
		StreamingJsonPath:      ResponseDefaultStreamingJSONPath,
		StreamingTextUnitChars: DefaultStreamingTextUnitChars,
	}
	if mutate != nil {
		mutate(&params)
	}
	return &AWSBedrockGuardrailPolicy{
		region:            "us-east-1",
		guardrailID:       "gr-123",
		guardrailVersion:  "DRAFT",
		hasResponseParams: true,
		responseParams:    params,
		loadAWSConfigFunc: func(_ context.Context, _ string) (aws.Config, error) {
			return aws.Config{}, nil
		},
		newBedrockClientFunc: func(_ aws.Config) bedrockGuardrailClient {
			return client
		},
	}
}

// streamCtx is a response-stream context with the 200 status the streaming path
// gates on, and empty metadata for the per-stream state to accumulate in.
func streamCtx() *policy.ResponseStreamContext {
	return &policy.ResponseStreamContext{
		SharedContext:  &policy.SharedContext{Metadata: map[string]interface{}{}},
		ResponseStatus: 200,
	}
}

// sseEvent renders one OpenAI-shaped streaming delta frame.
func sseEvent(text string) string {
	return fmt.Sprintf("data: {\"choices\":[{\"delta\":{\"content\":%q}}]}\n\n", text)
}

// feedStream drives chunks through the kernel's contract: accumulate while
// NeedsMoreResponseData says so, then deliver one flush. Reproducing the
// kernel's loop here is what makes the window observable — calling
// OnResponseBodyChunk directly would test a flush pattern the kernel never
// produces.
func feedStream(t *testing.T, p *AWSBedrockGuardrailPolicy, respCtx *policy.ResponseStreamContext, chunks []string) []policy.StreamingResponseAction {
	t.Helper()

	var actions []policy.StreamingResponseAction
	var accumulated string
	for i, c := range chunks {
		accumulated += c
		endOfStream := i == len(chunks)-1
		if !endOfStream && p.NeedsMoreResponseData([]byte(accumulated)) {
			continue
		}
		action := p.OnResponseBodyChunk(context.Background(), respCtx, &policy.StreamBody{
			Chunk:       []byte(accumulated),
			EndOfStream: endOfStream,
			Index:       uint64(i),
		}, map[string]interface{}{})
		actions = append(actions, action)
		accumulated = ""
		if action.TerminateStream() {
			break
		}
	}
	return actions
}

// TestMode_FollowsConfiguration is the regression guard for the defect behind
// this version: a flow the attachment does not use must declare SKIP, because a
// BUFFER declaration demotes every other policy on the route to buffered.
func TestMode_FollowsConfiguration(t *testing.T) {
	cases := []struct {
		name                      string
		hasRequest, hasResponse   bool
		requestOn, responseOn     bool
		wantRequest, wantResponse policy.BodyProcessingMode
	}{
		{
			// The v1.1.0 default shape: both flows present, response disabled.
			// The response must not be buffered for a flow that never runs —
			// buffering it is what demoted the whole chain.
			name:       "request only",
			hasRequest: true, requestOn: true,
			hasResponse: true, responseOn: false,
			wantRequest: policy.BodyModeBuffer, wantResponse: policy.BodyModeSkip,
		},
		{
			// An enabled response flow declares STREAM. That is not a decision to
			// stream: the engine upgrades a route only when the upstream response
			// is actually chunked or SSE, and uses the buffered path otherwise.
			name:       "response enabled",
			hasRequest: true, requestOn: true,
			hasResponse: true, responseOn: true,
			wantRequest: policy.BodyModeBuffer, wantResponse: policy.BodyModeStream,
		},
		{
			name:       "response only",
			hasRequest: true, requestOn: false,
			hasResponse: true, responseOn: true,
			wantRequest: policy.BodyModeSkip, wantResponse: policy.BodyModeStream,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := &AWSBedrockGuardrailPolicy{
				hasRequestParams:  tc.hasRequest,
				hasResponseParams: tc.hasResponse,
				requestParams:     AWSBedrockGuardrailPolicyParams{Enabled: tc.requestOn},
				responseParams:    AWSBedrockGuardrailPolicyParams{Enabled: tc.responseOn},
			}
			got := p.Mode()
			if got.RequestBodyMode != tc.wantRequest {
				t.Errorf("request body mode: got %s, want %s", got.RequestBodyMode, tc.wantRequest)
			}
			if got.ResponseBodyMode != tc.wantResponse {
				t.Errorf("response body mode: got %s, want %s", got.ResponseBodyMode, tc.wantResponse)
			}
			if got.RequestHeaderMode != policy.HeaderModeSkip || got.ResponseHeaderMode != policy.HeaderModeSkip {
				t.Errorf("header modes must stay SKIP, got %+v", got)
			}
		})
	}
}

// TestNeedsMoreResponseData_WindowAndEventBoundary covers the flush pacer: the
// byte floor, the SSE event boundary that keeps a flush from being cut mid-event,
// and the unary JSON body that is held whole.
func TestNeedsMoreResponseData_WindowAndEventBoundary(t *testing.T) {
	p := streamingPolicy(&countingBedrockClient{output: makeNoInterventionOutput()}, nil)

	short := sseEvent("hi")
	if !p.NeedsMoreResponseData([]byte(short)) {
		t.Errorf("below the window the policy must keep accumulating")
	}

	full := strings.Repeat(sseEvent("0123456789"), 120)
	if p.NeedsMoreResponseData([]byte(full)) {
		t.Errorf("at the window and on an event boundary the policy must release")
	}

	// Past the window but cut mid-event: releasing here hands the policy a
	// truncated `data:` line, which is the JSONPath extraction failure this
	// whole path exists to avoid.
	midEvent := full + "data: {\"choices\":[{\"delta\":{\"con"
	if !p.NeedsMoreResponseData([]byte(midEvent)) {
		t.Errorf("a flush cut mid-event must not be released")
	}

	// CRLF framing is an event boundary too. Matching LF alone treats a CRLF
	// stream as one event that never ends.
	crlf := strings.Repeat("data: {\"choices\":[{\"delta\":{\"content\":\"0123456789\"}}]}\r\n\r\n", 120)
	if p.NeedsMoreResponseData([]byte(crlf)) {
		t.Errorf("CRLF event boundary must be recognised as a boundary")
	}

	// A unary JSON body accumulates whole, so nothing unvalidated reaches the
	// client; the kernel's end-of-stream flush is what releases it.
	if !p.NeedsMoreResponseData([]byte(`{"choices":[{"message":{"content":"hello"}}]}`)) {
		t.Errorf("a unary JSON body must accumulate to end of stream")
	}
	// Even past the window — a half-received document is not validatable.
	if !p.NeedsMoreResponseData([]byte(`{"x":"` + strings.Repeat("y", streamFlushPacerBytes+10))) {
		t.Errorf("a partial JSON document must keep accumulating past the window")
	}

	// A disabled response flow must never ask the kernel to accumulate: other
	// policies may have made the route streaming, and this instance assesses
	// nothing.
	disabled := streamingPolicy(&countingBedrockClient{}, func(params *AWSBedrockGuardrailPolicyParams) {
		params.Enabled = false
	})
	if disabled.NeedsMoreResponseData([]byte(short)) {
		t.Errorf("a disabled response flow must not accumulate")
	}
}

// TestStreaming_CleanStreamForwardsUnchangedAndValidatesPerWindow asserts a
// passing stream is delivered byte-for-byte, and assessed in batches rather than
// once per chunk.
func TestStreaming_CleanStreamForwardsUnchangedAndValidatesPerWindow(t *testing.T) {
	client := &countingBedrockClient{output: makeNoInterventionOutput()}
	p := streamingPolicy(client, func(params *AWSBedrockGuardrailPolicyParams) {
		params.StreamingTextUnitChars = MinStreamingTextUnitChars
	})

	// One SSE event per chunk — the framing a real upstream flushing per event
	// produces. Coalescing events into larger chunks is what hides window and
	// boundary defects.
	var chunks []string
	for i := 0; i < 40; i++ {
		chunks = append(chunks, sseEvent("token"))
	}

	actions := feedStream(t, p, streamCtx(), chunks)

	// The delivered stream must be byte-identical to what arrived. Asserting a
	// nil body instead would pin the mechanism rather than the property: this
	// path withholds a trailing incomplete line and re-emits it with the next
	// flush, so it sets the body explicitly even when nothing is rewritten.
	var delivered string
	for i, action := range actions {
		forward, ok := action.(policy.ForwardResponseChunk)
		if !ok {
			t.Fatalf("flush %d: expected ForwardResponseChunk, got %T", i, action)
		}
		if forward.Body == nil {
			delivered += string(chunks[i])
			continue
		}
		delivered += string(forward.Body)
	}
	if want := strings.Join(chunks, ""); delivered != want {
		t.Errorf("a clean stream must be delivered unchanged:\n got %d bytes\nwant %d bytes", len(delivered), len(want))
	}

	if client.calls == 0 {
		t.Fatalf("expected the guardrail to be called")
	}
	// 40 events of ~50 bytes against a 256-byte window: a handful of calls.
	// Per-chunk validation would be 40.
	if client.calls >= len(chunks) {
		t.Errorf("expected windowed validation, got %d calls for %d chunks", client.calls, len(chunks))
	}
	for _, text := range client.texts {
		if strings.Contains(text, "data:") || strings.Contains(text, "choices") {
			t.Errorf("SSE framing was sent to the guardrail instead of the assistant text: %q", text)
		}
	}
}

func TestStreaming_ViolationTerminatesWithSSEErrorEvent(t *testing.T) {
	client := &countingBedrockClient{output: makeContentViolationOutput()}
	p := streamingPolicy(client, func(params *AWSBedrockGuardrailPolicyParams) {
		params.StreamingTextUnitChars = MinStreamingTextUnitChars
		params.ShowAssessment = true
	})

	chunks := []string{strings.Repeat(sseEvent("blocked content"), 10), sseEvent("more")}
	actions := feedStream(t, p, streamCtx(), chunks)

	last := actions[len(actions)-1]
	terminate, ok := last.(policy.TerminateResponseChunk)
	if !ok {
		t.Fatalf("expected TerminateResponseChunk on violation, got %T", last)
	}
	if !terminate.TerminateStream() {
		t.Fatalf("a violation must end the stream")
	}
	body := string(terminate.Body)
	if !strings.HasPrefix(body, sseDataPrefix) || !strings.HasSuffix(body, "\n\n") {
		t.Errorf("the final event must be a well-formed SSE frame, got %q", body)
	}
	if !strings.Contains(body, "AWS_BEDROCK_GUARDRAIL") {
		t.Errorf("the final event must carry the guardrail payload, got %q", body)
	}
	if terminate.AnalyticsMetadata["isGuardrailHit"] != true {
		t.Errorf("a terminated stream must be attributed as a guardrail hit, got %+v", terminate.AnalyticsMetadata)
	}
}

func TestStreaming_PassthroughOnErrorForwardsInsteadOfTerminating(t *testing.T) {
	failing := &countingBedrockClient{err: fmt.Errorf("bedrock unavailable")}

	blocking := streamingPolicy(failing, func(params *AWSBedrockGuardrailPolicyParams) {
		params.StreamingTextUnitChars = MinStreamingTextUnitChars
	})
	chunks := []string{strings.Repeat(sseEvent("hello"), 10), sseEvent("more")}
	actions := feedStream(t, blocking, streamCtx(), chunks)
	if _, ok := actions[len(actions)-1].(policy.TerminateResponseChunk); !ok {
		t.Fatalf("a guardrail call failure must end the stream when passthroughOnError is false, got %T", actions[len(actions)-1])
	}

	permissive := streamingPolicy(failing, func(params *AWSBedrockGuardrailPolicyParams) {
		params.StreamingTextUnitChars = MinStreamingTextUnitChars
		params.PassthroughOnError = true
	})
	for i, action := range feedStream(t, permissive, streamCtx(), chunks) {
		if _, ok := action.(policy.ForwardResponseChunk); !ok {
			t.Fatalf("flush %d: passthroughOnError must forward, got %T", i, action)
		}
	}
}

// TestStreaming_RestoresMaskedPIIInFrames covers masking mode, where the request
// flow replaced a value upstream and the response must put it back frame by frame.
func TestStreaming_RestoresMaskedPIIInFrames(t *testing.T) {
	client := &countingBedrockClient{output: makeNoInterventionOutput()}
	p := streamingPolicy(client, func(params *AWSBedrockGuardrailPolicyParams) {
		params.StreamingTextUnitChars = MinStreamingTextUnitChars
	})

	respCtx := streamCtx()
	// What the request flow leaves behind when it masks rather than redacts.
	respCtx.Metadata[MetadataKeyPIIEntities] = map[string]string{
		"john@example.com": "EMAIL_0000",
	}

	chunks := []string{strings.Repeat(sseEvent("contact EMAIL_0000 today"), 6), sseEvent("bye")}
	actions := feedStream(t, p, respCtx, chunks)

	var restored bool
	for _, action := range actions {
		forward, ok := action.(policy.ForwardResponseChunk)
		if !ok {
			t.Fatalf("expected ForwardResponseChunk, got %T", action)
		}
		if forward.Body == nil {
			continue
		}
		body := string(forward.Body)
		if strings.Contains(body, "john@example.com") {
			restored = true
		}
		if strings.Contains(body, "EMAIL_0000") {
			t.Errorf("placeholder survived restoration: %q", body)
		}
		// The rewrite must keep the frames well-formed, not just the text right.
		if !strings.HasPrefix(body, sseDataPrefix) {
			t.Errorf("rewritten flush lost its SSE framing: %q", body)
		}
	}
	if !restored {
		t.Fatalf("expected the masked value to be restored in the forwarded frames")
	}
}

func TestStreaming_RedactsPIIInFrames(t *testing.T) {
	client := &countingBedrockClient{output: makePIIIntervenedOutput("john@example.com")}
	p := streamingPolicy(client, func(params *AWSBedrockGuardrailPolicyParams) {
		params.StreamingTextUnitChars = MinStreamingTextUnitChars
		params.RedactPII = true
	})

	chunks := []string{strings.Repeat(sseEvent("mail john@example.com now"), 6), sseEvent("bye")}

	var sawRedaction bool
	for _, action := range feedStream(t, p, streamCtx(), chunks) {
		forward, ok := action.(policy.ForwardResponseChunk)
		if !ok {
			t.Fatalf("redaction must not end the stream, got %T", action)
		}
		if forward.Body == nil {
			continue
		}
		body := string(forward.Body)
		if strings.Contains(body, "john@example.com") {
			t.Errorf("PII survived redaction: %q", body)
		}
		if strings.Contains(body, "*****") {
			sawRedaction = true
		}
	}
	if !sawRedaction {
		t.Fatalf("expected redacted frames to be forwarded")
	}
}

// TestStreaming_NonSSEBodyIsValidatedWholeAtEndOfStream keeps the buffered
// guarantee for a unary body that arrives over chunked transfer: it is held and
// assessed whole, so nothing unassessed reaches the client.
func TestStreaming_NonSSEBodyIsValidatedWholeAtEndOfStream(t *testing.T) {
	client := &countingBedrockClient{output: makeContentViolationOutput()}
	p := streamingPolicy(client, func(params *AWSBedrockGuardrailPolicyParams) {
		params.JsonPath = "$.choices[0].message.content"
	})

	// Plain JSON over chunked transfer, split so no single chunk parses.
	chunks := []string{`{"choices":[{"message":`, `{"content":"blocked"}}]}`}
	actions := feedStream(t, p, streamCtx(), chunks)

	if len(actions) != 1 {
		t.Fatalf("a non-SSE body must be released once, at end of stream; got %d flushes", len(actions))
	}
	terminate, ok := actions[0].(policy.TerminateResponseChunk)
	if !ok {
		t.Fatalf("expected the violation to end the stream, got %T", actions[0])
	}
	if !strings.Contains(string(terminate.Body), "AWS_BEDROCK_GUARDRAIL") {
		t.Errorf("expected the guardrail payload as the final body, got %q", string(terminate.Body))
	}
	if client.calls != 1 {
		t.Errorf("expected exactly one validation of the whole body, got %d", client.calls)
	}
}

// TestStreaming_FramingOnlyFlushIsNotSentToTheGuardrail pins that wire framing is
// never billed as guardrail text, and cannot trip a filter on its own.
func TestStreaming_FramingOnlyFlushIsNotSentToTheGuardrail(t *testing.T) {
	client := &countingBedrockClient{output: makeNoInterventionOutput()}
	p := streamingPolicy(client, nil)

	// The opening role delta, a keep-alive and [DONE] carry no assistant text.
	framing := "data: {\"choices\":[{\"delta\":{\"role\":\"assistant\"}}]}\n\n" +
		": keep-alive\n\n" +
		"data: [DONE]\n\n"

	action := p.OnResponseBodyChunk(context.Background(), streamCtx(), &policy.StreamBody{
		Chunk:       []byte(framing),
		EndOfStream: true,
	}, map[string]interface{}{})

	if _, ok := action.(policy.ForwardResponseChunk); !ok {
		t.Fatalf("framing must be forwarded, got %T", action)
	}
	if client.calls != 0 {
		t.Errorf("framing must not be billed to the guardrail, got %d calls", client.calls)
	}
}

// TestStreaming_DisabledInstanceIsInert covers an attachment whose response flow
// is off while other policies make the route streaming: it must neither assess
// nor interfere.
func TestStreaming_DisabledInstanceIsInert(t *testing.T) {
	client := &countingBedrockClient{output: makeContentViolationOutput()}
	p := streamingPolicy(client, func(params *AWSBedrockGuardrailPolicyParams) {
		params.Enabled = false
	})

	action := p.OnResponseBodyChunk(context.Background(), streamCtx(), &policy.StreamBody{
		Chunk:       []byte(sseEvent("anything")),
		EndOfStream: true,
	}, map[string]interface{}{})

	if _, ok := action.(policy.ForwardResponseChunk); !ok {
		t.Fatalf("a disabled response flow must forward, got %T", action)
	}
	if client.calls != 0 {
		t.Errorf("a disabled response flow must not call the guardrail, got %d calls", client.calls)
	}
}

// TestParseRequestResponseParams_StreamingParams covers the defaults, the
// accepted numeric shapes (YAML and JSON deliver a float64), and the rejections.
func TestParseRequestResponseParams_StreamingParams(t *testing.T) {
	t.Run("response defaults", func(t *testing.T) {
		got, err := parseRequestResponseParams(map[string]interface{}{"enabled": true}, true)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got.StreamingJsonPath != ResponseDefaultStreamingJSONPath {
			t.Errorf("unexpected default streaming path: %q", got.StreamingJsonPath)
		}
		if got.StreamingTextUnitChars != DefaultStreamingTextUnitChars {
			t.Errorf("unexpected default text unit: %d", got.StreamingTextUnitChars)
		}
	})

	t.Run("accepts configured values", func(t *testing.T) {
		// A window arriving from YAML/JSON is a float64, not an int.
		got, err := parseRequestResponseParams(map[string]interface{}{
			"enabled":                true,
			"streamingJsonPath":      "$.delta.text",
			"streamingTextUnitChars": float64(4096),
		}, true)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got.StreamingJsonPath != "$.delta.text" || got.StreamingTextUnitChars != 4096 {
			t.Errorf("unexpected params: %+v", got)
		}
	})

	t.Run("rejects invalid values", func(t *testing.T) {
		cases := []map[string]interface{}{
			{"streamingJsonPath": ""},
			{"streamingJsonPath": 1},
			{"streamingTextUnitChars": float64(16)}, // below the minimum, and not 0
			{"streamingTextUnitChars": "big"},
		}
		for _, params := range cases {
			if _, err := parseRequestResponseParams(params, true); err == nil {
				t.Errorf("expected an error for %+v", params)
			}
		}
	})

	t.Run("boundary matches the schema constraint", func(t *testing.T) {
		// policy-definition.yaml allows 0 or >= 100 via
		// oneOf: [enum: [0], minimum: 100]. The two must agree, or a value the
		// schema accepts fails later at policy construction instead of at
		// configuration time.
		for _, accepted := range []float64{0, 100, 1000} {
			if _, err := parseRequestResponseParams(map[string]interface{}{
				"enabled": true, "streamingTextUnitChars": accepted,
			}, true); err != nil {
				t.Errorf("%v must be accepted: %v", accepted, err)
			}
		}
		for _, rejected := range []float64{1, 50, 99, -1} {
			if _, err := parseRequestResponseParams(map[string]interface{}{
				"enabled": true, "streamingTextUnitChars": rejected,
			}, true); err == nil {
				t.Errorf("%v must be rejected", rejected)
			}
		}
	})

	t.Run("zero means assess the whole response", func(t *testing.T) {
		// Distinct from a window: nothing is assessed until the stream ends, so
		// nothing is delivered until then either. Documented as such rather than
		// rejected by the minimum, which only bounds a window.
		got, err := parseRequestResponseParams(map[string]interface{}{
			"enabled": true, "streamingTextUnitChars": float64(0),
		}, true)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got.StreamingTextUnitChars != 0 {
			t.Errorf("expected 0 to be accepted, got %d", got.StreamingTextUnitChars)
		}
	})

	t.Run("rejects streaming params on the request flow", func(t *testing.T) {
		for _, key := range []string{"streamingJsonPath", "streamingTextUnitChars"} {
			if _, err := parseRequestResponseParams(map[string]interface{}{key: true}, false); err == nil {
				t.Errorf("expected %q to be rejected on the request flow", key)
			}
		}
	})
}

func TestStreaming_HonoursApplicableStatusCodes(t *testing.T) {
	client := &countingBedrockClient{output: makeContentViolationOutput()}
	ranges, err := parseStatusCodes("200")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	p := streamingPolicy(client, func(params *AWSBedrockGuardrailPolicyParams) {
		params.StreamingTextUnitChars = MinStreamingTextUnitChars
		params.ApplicableStatusCodes = ranges
	})

	// A 500 is outside the configured codes, so the stream must pass through
	// unvalidated — the same decision the buffered path makes in OnResponseBody.
	respCtx := streamCtx()
	respCtx.ResponseStatus = 500

	action := p.OnResponseBodyChunk(context.Background(), respCtx, &policy.StreamBody{
		Chunk:       []byte(strings.Repeat(sseEvent("blocked content"), 10)),
		EndOfStream: true,
	}, map[string]interface{}{})

	if _, ok := action.(policy.ForwardResponseChunk); !ok {
		t.Fatalf("a status outside applicableStatusCodes must forward, got %T", action)
	}
	if client.calls != 0 {
		t.Errorf("a status outside applicableStatusCodes must not be validated, got %d calls", client.calls)
	}

	// The same stream on a configured status is validated and blocked.
	client.calls = 0
	if action := p.OnResponseBodyChunk(context.Background(), streamCtx(), &policy.StreamBody{
		Chunk:       []byte(strings.Repeat(sseEvent("blocked content"), 10)),
		EndOfStream: true,
	}, map[string]interface{}{}); !action.TerminateStream() {
		t.Fatalf("a configured status must be validated, got %T", action)
	}
	if client.calls == 0 {
		t.Errorf("expected the guardrail to be called for a configured status")
	}
}

// encodeAmazonEventStreamFrame builds a byte sequence shaped like one Amazon
// event-stream frame: a 4-byte total length, a 4-byte header length, then opaque
// bytes. Only the framing shape matters here — the point is that these bytes are
// neither SSE nor JSON.
func encodeAmazonEventStreamFrame(payload string) []byte {
	frame := []byte{0x00, 0x00, 0x01, 0x2c, 0x00, 0x00, 0x00, 0x3c, 0x7a, 0x1f, 0x00, 0x00}
	frame = append(frame, payload...)
	return frame
}

// TestNeedsMoreResponseData_RawProviderFramingIsReleasedAtTheWindow pins the
// distinction between what the two streaming hooks are given.
//
// NeedsMoreResponseData receives the RAW accumulated upstream bytes, before any
// policy runs. On a Bedrock-backed route that is Amazon's binary event-stream
// framing, not SSE — the OpenAI SSE this policy validates only exists after
// openai-to-bedrock-transformer has rewritten the flush, which happens later, in
// OnResponseBodyChunk.
//
// So this hook must not decide "not SSE, therefore accumulate": that holds every
// Bedrock stream to end of stream and reproduces the bug this policy is meant to
// fix. Frame integrity is the transformer's job — it declares its own
// NeedsMoreResponseData for a partial frame, and the kernel flushes only when no
// policy wants more data.
func TestNeedsMoreResponseData_RawProviderFramingIsReleasedAtTheWindow(t *testing.T) {
	p := streamingPolicy(&countingBedrockClient{output: makeNoInterventionOutput()}, func(params *AWSBedrockGuardrailPolicyParams) {
		params.StreamingTextUnitChars = MinStreamingTextUnitChars
	})

	short := encodeAmazonEventStreamFrame("contentBlockDelta")
	if !p.NeedsMoreResponseData(short) {
		t.Errorf("below the window, raw provider framing must still accumulate")
	}

	var accumulated []byte
	for len(accumulated) < streamFlushPacerBytes+64 {
		accumulated = append(accumulated, encodeAmazonEventStreamFrame("contentBlockDelta")...)
	}
	if p.NeedsMoreResponseData(accumulated) {
		t.Fatalf("raw provider framing must be released at the window; holding it buffers the whole response and defeats streaming")
	}
}

// TestStreaming_ValidatesTransformerOutputNotRawFraming is the other half: the
// chunk OnResponseBodyChunk receives on such a route is the transformer's OpenAI
// SSE, so the default streamingJsonPath applies to it.
func TestStreaming_ValidatesTransformerOutputNotRawFraming(t *testing.T) {
	client := &countingBedrockClient{output: makeContentViolationOutput()}
	p := streamingPolicy(client, func(params *AWSBedrockGuardrailPolicyParams) {
		params.StreamingTextUnitChars = MinStreamingTextUnitChars
	})

	// What openai-to-bedrock-transformer emits: data: {"choices":[{"index":0,
	// "delta":{"content":"..."},"finish_reason":null}]}\n\n
	// Enough events to exceed one text unit, so the batch is assessed mid-stream.
	transformed := strings.Repeat(
		"data: {\"id\":\"chatcmpl-1\",\"object\":\"chat.completion.chunk\",\"model\":\"claude\","+
			"\"choices\":[{\"index\":0,\"delta\":{\"content\":\"blocked \"},\"finish_reason\":null}]}\n\n", 200)

	action := p.OnResponseBodyChunk(context.Background(), streamCtx(), &policy.StreamBody{
		Chunk:       []byte(transformed),
		EndOfStream: false,
	}, map[string]interface{}{})

	if !action.TerminateStream() {
		t.Fatalf("expected the transformer's SSE output to be validated, got %T", action)
	}
	if client.calls != 1 {
		t.Fatalf("expected one validation call, got %d", client.calls)
	}
	if got := client.texts[0]; !strings.Contains(got, "blocked") || strings.Contains(got, "choices") {
		t.Errorf("expected the extracted delta text, got %q", got)
	}
}

// ─── Text-unit batching (AWS streaming guidance) ─────────────────────────────

// TestStreaming_DoesNotBillAnUnderfilledTextUnit is the cost regression guard.
// A text unit is ~1000 characters AND the Bedrock billing unit, so a 40-character
// call costs exactly as much as a full one. Batching on wire bytes under-fills
// every call by more than an order of magnitude — one SSE event is ~150 bytes of
// framing around a few characters of text.
func TestStreaming_DoesNotBillAnUnderfilledTextUnit(t *testing.T) {
	client := &countingBedrockClient{output: makeNoInterventionOutput()}
	p := streamingPolicy(client, nil) // default 1000-character text unit

	// ~20 events, ~40 characters of text, several kilobytes of SSE framing.
	flush := strings.Repeat(sseEvent("hi "), 20)

	action := p.OnResponseBodyChunk(context.Background(), streamCtx(), &policy.StreamBody{
		Chunk:       []byte(flush),
		EndOfStream: false,
	}, map[string]interface{}{})

	if _, ok := action.(policy.ForwardResponseChunk); !ok {
		t.Fatalf("a batch below one text unit must be forwarded, got %T", action)
	}
	if client.calls != 0 {
		t.Errorf("a batch of ~40 characters must not be sent: a call is billed as a full "+
			"1000-character text unit either way; got %d calls", client.calls)
	}
}

// TestStreaming_AssessesOncePerTextUnit is the cost guard: roughly one call per
// text unit, and no call below the configured floor.
func TestStreaming_AssessesOncePerTextUnit(t *testing.T) {
	client := &countingBedrockClient{output: makeNoInterventionOutput()}
	p := streamingPolicy(client, nil)
	respCtx := streamCtx()

	// 300 events x 10 characters = ~3000 characters => about three text units.
	for i := 0; i < 300; i++ {
		p.OnResponseBodyChunk(context.Background(), respCtx, &policy.StreamBody{
			Chunk:       []byte(sseEvent("word rest ")),
			EndOfStream: false,
		}, map[string]interface{}{})
	}

	if client.calls < 2 || client.calls > 4 {
		t.Errorf("expected roughly one call per 1000-character text unit (2-4 for ~3000 chars), got %d", client.calls)
	}
	for _, text := range client.texts {
		if n := len([]rune(text)); n < MinStreamingTextUnitChars {
			t.Errorf("a batch of %d characters was sent; batches should fill a text unit: %q", n, text)
		}
	}
}

// TestStreaming_FinalBatchIsAssessedAtEndOfStream covers AWS's requirement that
// the last batch is evaluated even though it never reaches a full text unit.
func TestStreaming_FinalBatchIsAssessedAtEndOfStream(t *testing.T) {
	client := &countingBedrockClient{output: makeContentViolationOutput()}
	p := streamingPolicy(client, nil)
	respCtx := streamCtx()

	// Below a text unit, so nothing is assessed yet.
	if action := p.OnResponseBodyChunk(context.Background(), respCtx, &policy.StreamBody{
		Chunk:       []byte(strings.Repeat(sseEvent("short "), 5)),
		EndOfStream: false,
	}, map[string]interface{}{}); action.TerminateStream() {
		t.Fatalf("nothing should be assessed below a text unit mid-stream")
	}
	if client.calls != 0 {
		t.Fatalf("expected no call before end of stream, got %d", client.calls)
	}

	// End of stream: the remainder must still be assessed, and a violation in it
	// must still end the stream.
	action := p.OnResponseBodyChunk(context.Background(), respCtx, &policy.StreamBody{
		Chunk:       []byte("data: [DONE]\n\n"),
		EndOfStream: true,
	}, map[string]interface{}{})

	if !action.TerminateStream() {
		t.Fatalf("the final batch must be assessed and its violation acted on, got %T", action)
	}
	if client.calls != 1 {
		t.Errorf("expected exactly one final call, got %d", client.calls)
	}
}

// TestSplitAtTextUnit_DoesNotSplitWordsOrSentences pins AWS's "batches don't
// split words or sentences, carrying over any necessary context" rule. A phrase
// cut in half and assessed as two batches can pass where the whole would not.
func TestSplitAtTextUnit_DoesNotSplitWordsOrSentences(t *testing.T) {
	t.Run("cuts at a sentence end", func(t *testing.T) {
		text := "First sentence here. Second sentence trails on"
		batch, carry := splitAtTextUnit(text, 30, false)
		if batch != "First sentence here." {
			t.Errorf("expected the cut at the sentence end, got %q", batch)
		}
		if carry != " Second sentence trails on" {
			t.Errorf("unexpected carry %q", carry)
		}
	})

	t.Run("falls back to a word end", func(t *testing.T) {
		text := "aaaa bbbb cccc dddd eeee ffff"
		batch, carry := splitAtTextUnit(text, 12, false)
		if strings.HasSuffix(strings.TrimRight(batch, " "), "cc") && !strings.HasSuffix(batch, " ") {
			t.Errorf("batch ended mid-word: %q", batch)
		}
		if batch+carry != text {
			t.Errorf("split lost text: %q + %q != %q", batch, carry, text)
		}
	})

	t.Run("holds everything below a unit", func(t *testing.T) {
		batch, carry := splitAtTextUnit("too short", 1000, false)
		if batch != "" || carry != "too short" {
			t.Errorf("expected all text carried, got batch %q carry %q", batch, carry)
		}
	})

	t.Run("releases a short remainder at end of stream", func(t *testing.T) {
		batch, carry := splitAtTextUnit("trailing words", 1000, true)
		if batch != "trailing words" || carry != "" {
			t.Errorf("end of stream must assess the remainder, got batch %q carry %q", batch, carry)
		}
	})

	t.Run("still cuts at the unit at end of stream", func(t *testing.T) {
		// So a caller looping over this assesses several unit-sized calls rather
		// than one oversized one.
		batch, carry := splitAtTextUnit(strings.Repeat("word ", 600), 1000, true)
		if len([]rune(batch)) > 1000 {
			t.Errorf("end-of-stream batch must still be bounded by the unit, got %d", len([]rune(batch)))
		}
		if carry == "" {
			t.Errorf("expected a remainder to be carried for the next iteration")
		}
	})

	t.Run("boundary-free text cannot grow the carry without bound", func(t *testing.T) {
		text := strings.Repeat("x", 5000)
		batch, carry := splitAtTextUnit(text, 1000, false)
		if len(batch) != 1000 {
			t.Errorf("expected a cut at the unit when no boundary exists, got %d", len(batch))
		}
		if len(carry) != 4000 {
			t.Errorf("unexpected carry length %d", len(carry))
		}
	})
}

// TestStreaming_CarriesTheRemainderIntoTheNextBatch asserts the carried text is
// assessed with the batch that follows it, not dropped.
func TestStreaming_CarriesTheRemainderIntoTheNextBatch(t *testing.T) {
	client := &countingBedrockClient{output: makeNoInterventionOutput()}
	p := streamingPolicy(client, nil)
	respCtx := streamCtx()

	p.OnResponseBodyChunk(context.Background(), respCtx, &policy.StreamBody{
		Chunk:       []byte(sseEvent("CARRIED_MARKER ")),
		EndOfStream: false,
	}, map[string]interface{}{})
	if client.calls != 0 {
		t.Fatalf("expected the first short flush to be held, got %d calls", client.calls)
	}

	p.OnResponseBodyChunk(context.Background(), respCtx, &policy.StreamBody{
		Chunk:       []byte(strings.Repeat(sseEvent("filler text "), 120)),
		EndOfStream: false,
	}, map[string]interface{}{})

	if client.calls == 0 {
		t.Fatalf("expected a batch to be assessed once a text unit accumulated")
	}
	if !strings.Contains(client.texts[0], "CARRIED_MARKER") {
		t.Errorf("the carried remainder must be assessed with the next batch; got %q", client.texts[0][:60])
	}
}

// TestStreaming_RedactsOnRelease covers redaction now that it batches like
// everything else. It used to assess every flush, on the reasoning that it
// rewrites the frames in hand and could not defer a finding past them — but no
// flush is forwarded until its batch is assessed, so that reason is gone.
func TestStreaming_RedactsOnRelease(t *testing.T) {
	client := &countingBedrockClient{output: makePIIIntervenedOutput("john@example.com")}
	p := streamingPolicy(client, func(params *AWSBedrockGuardrailPolicyParams) {
		params.RedactPII = true
	})

	action := p.OnResponseBodyChunk(context.Background(), streamCtx(), &policy.StreamBody{
		Chunk: []byte(sseEvent("mail john@example.com now")), EndOfStream: true,
	}, map[string]interface{}{})

	if client.calls != 1 {
		t.Fatalf("expected the batch to be assessed once, got %d calls", client.calls)
	}
	forward, ok := action.(policy.ForwardResponseChunk)
	if !ok {
		t.Fatalf("expected ForwardResponseChunk, got %T", action)
	}
	if body := string(forward.Body); strings.Contains(body, "john@example.com") || !strings.Contains(body, "*****") {
		t.Errorf("expected the value redacted on release, got %q", body)
	}
}

// TestStreaming_RedactsAValueSplitAcrossFlushes is why the special case had to
// go. Assessing each flush alone meant a value the model emitted across two
// flushes was in neither flush's text, so neither assessment reported it and it
// went to the client unredacted. Batching joins the text first.
//
// The value also spans two frames here, so it cannot be written back in place —
// the stream fails closed instead, which is the documented outcome. What must
// never happen is the value being delivered.
func TestStreaming_RedactsAValueSplitAcrossFlushes(t *testing.T) {
	client := &countingBedrockClient{output: makePIIIntervenedOutput("john@example.com")}
	p := streamingPolicy(client, func(params *AWSBedrockGuardrailPolicyParams) {
		params.RedactPII = true
	})
	respCtx := streamCtx()

	var delivered string
	for _, chunk := range []struct {
		body string
		eos  bool
	}{
		{sseEvent("mail john@"), false},
		{sseEvent("example.com now"), true},
	} {
		action := p.OnResponseBodyChunk(context.Background(), respCtx, &policy.StreamBody{
			Chunk: []byte(chunk.body), EndOfStream: chunk.eos,
		}, map[string]interface{}{})
		switch v := action.(type) {
		case policy.ForwardResponseChunk:
			delivered += string(v.Body)
		case policy.TerminateResponseChunk:
			delivered += string(v.Body)
		}
	}

	// Reassemble what a client's SSE parser would produce. Checking the raw bytes
	// is not enough: with the halves in separate frames, JSON framing sits
	// between them and the value never appears contiguously on the wire even
	// when the client ends up with it.
	seen := extractSSEDeltaContent(delivered, ResponseDefaultStreamingJSONPath)
	if strings.Contains(seen, "john@example.com") {
		t.Errorf("a value split across flushes must not reach the client unredacted: %q", seen)
	}
}

// TestStreaming_AssessesEveryUnitInOneFlush covers a flush that carries several
// text units at once — the shape the testbench's mock model produces, since it
// writes a whole stream in a single flush, and one a real upstream can produce
// by coalescing. Assessing only the first unit per flush would leave the rest
// unassessed behind a carry, and at end of stream would send one oversized call.
func TestStreaming_AssessesEveryUnitInOneFlush(t *testing.T) {
	client := &countingBedrockClient{output: makeNoInterventionOutput()}
	p := streamingPolicy(client, nil) // 1000-character text unit

	// One flush, ~3000 characters of text => three units.
	flush := strings.Repeat(sseEvent("filler text "), 250)

	action := p.OnResponseBodyChunk(context.Background(), streamCtx(), &policy.StreamBody{
		Chunk:       []byte(flush),
		EndOfStream: true,
	}, map[string]interface{}{})

	if _, ok := action.(policy.ForwardResponseChunk); !ok {
		t.Fatalf("expected the flush to be forwarded, got %T", action)
	}
	if client.calls < 3 {
		t.Errorf("expected one call per text unit in the flush (>=3 for ~3000 chars), got %d", client.calls)
	}
	for i, text := range client.texts {
		if n := len([]rune(text)); n > DefaultStreamingTextUnitChars+maxBoundarySearchRunes {
			t.Errorf("call %d carried %d characters; batches must stay near one text unit", i, n)
		}
	}
}

// TestStreaming_ViolationInALaterUnitOfTheSameFlushTerminates makes sure the loop
// does not stop assessing after the first clean unit.
func TestStreaming_ViolationInALaterUnitOfTheSameFlushTerminates(t *testing.T) {
	client := &countingBedrockClient{output: makeNoInterventionOutput()}
	p := streamingPolicy(client, nil)

	// The mock answers clean for the first call and blocks on the second.
	calls := 0
	p.newBedrockClientFunc = func(_ aws.Config) bedrockGuardrailClient {
		calls++
		if calls >= 2 {
			return &countingBedrockClient{output: makeContentViolationOutput()}
		}
		return client
	}

	flush := strings.Repeat(sseEvent("filler text "), 250)
	action := p.OnResponseBodyChunk(context.Background(), streamCtx(), &policy.StreamBody{
		Chunk:       []byte(flush),
		EndOfStream: true,
	}, map[string]interface{}{})

	if !action.TerminateStream() {
		t.Fatalf("a violation in a later unit of the same flush must end the stream, got %T", action)
	}
}

// ─── SSE field parsing and stream classification ─────────────────────────────

// TestIsSSEChunk_AcceptsEverySSEFieldForm covers the framing variants a real
// upstream emits. The space after the colon is optional in the specification, so
// matching "data: " as a literal prefix skips every event from an upstream that
// omits it, and a flush of keep-alives or id:/retry: lines is still SSE.
func TestIsSSEChunk_AcceptsEverySSEFieldForm(t *testing.T) {
	cases := map[string]bool{
		"data: {\"a\":1}\n\n":                    true,
		"data:{\"a\":1}\n\n":                     true, // no space — same event
		"event: message\ndata: {\"a\":1}\n\n":    true,
		": keep-alive\n\n":                       true, // comment only
		"id: 42\n\n":                             true,
		"retry: 3000\n\n":                        true,
		"{\"choices\":[{\"message\":{}}]}":       false,
		"":                                       false,
		strings.Repeat("x", 40) + "\nplain text": false,
	}
	for input, want := range cases {
		if got := isSSEChunk(input); got != want {
			t.Errorf("isSSEChunk(%q) = %v, want %v", input, got, want)
		}
	}

	// A data line beyond the first few lines must still classify the flush: an
	// upstream can open with several comments before its first event.
	late := strings.Repeat(": keep-alive\n\n", 8) + "data: {\"a\":1}\n\n"
	if !isSSEChunk(late) {
		t.Errorf("a data line after several comments must still classify as SSE")
	}
}

// TestSSEDataPayload_ConsumesOneSpaceOnly pins that only the single optional
// space is stripped. Further whitespace belongs to the value, and the prefix is
// returned so a rewritten event keeps the form the upstream wrote.
func TestSSEDataPayload_ConsumesOneSpaceOnly(t *testing.T) {
	cases := []struct{ line, payload, prefix string }{
		{"data: {\"a\":1}", "{\"a\":1}", "data: "},
		{"data:{\"a\":1}", "{\"a\":1}", "data:"},
		{"data:  {\"a\":1}", " {\"a\":1}", "data: "}, // second space is value
	}
	for _, c := range cases {
		payload, prefix, ok := sseDataPayload(c.line)
		if !ok || payload != c.payload || prefix != c.prefix {
			t.Errorf("sseDataPayload(%q) = (%q, %q, %v), want (%q, %q, true)",
				c.line, payload, prefix, ok, c.payload, c.prefix)
		}
	}
	if _, _, ok := sseDataPayload("event: message"); ok {
		t.Errorf("a non-data line must not parse as a data line")
	}
}

// TestStreaming_ExtractsFromSpacelessDataLines is the end-to-end form of the
// above: an upstream writing "data:{...}" must still have its text assessed.
func TestStreaming_ExtractsFromSpacelessDataLines(t *testing.T) {
	client := &countingBedrockClient{output: makeContentViolationOutput()}
	p := streamingPolicy(client, nil)

	spaceless := strings.Repeat(
		"data:{\"choices\":[{\"index\":0,\"delta\":{\"content\":\"blocked \"}}]}\n\n", 200)

	action := p.OnResponseBodyChunk(context.Background(), streamCtx(), &policy.StreamBody{
		Chunk:       []byte(spaceless),
		EndOfStream: false,
	}, map[string]interface{}{})

	if !action.TerminateStream() {
		t.Fatalf("text from spaceless data lines must be assessed, got %T", action)
	}
	if client.calls == 0 || !strings.Contains(client.texts[0], "blocked") {
		t.Errorf("expected the extracted delta text, got %d calls %q", client.calls, client.texts)
	}
}

// TestStreaming_KeepsTheSSEPathAcrossUnclassifiableFlushes covers a flush that
// carries only a keep-alive. Judged alone it is not a data flush, and before the
// remembered classification it took the non-SSE path, where the stream's
// accumulated text was assessed as if it were a JSON body.
func TestStreaming_KeepsTheSSEPathAcrossUnclassifiableFlushes(t *testing.T) {
	client := &countingBedrockClient{output: makeNoInterventionOutput()}
	p := streamingPolicy(client, nil)
	respCtx := streamCtx()

	p.OnResponseBodyChunk(context.Background(), respCtx, &policy.StreamBody{
		Chunk: []byte(sseEvent("first words ")), EndOfStream: false,
	}, map[string]interface{}{})

	if sse, _ := respCtx.Metadata[metaKeySSEStream].(bool); !sse {
		t.Fatalf("the stream should have been classified as SSE")
	}

	// Keep-alive only: must stay on the SSE path and not be accumulated as a body.
	p.OnResponseBodyChunk(context.Background(), respCtx, &policy.StreamBody{
		Chunk: []byte(": keep-alive\n\n"), EndOfStream: false,
	}, map[string]interface{}{})

	if _, ok := respCtx.Metadata[metaKeyAccStreamedJSONBody]; ok {
		t.Errorf("a keep-alive flush must not be accumulated as a non-SSE body")
	}
}

// ─── Empty end-of-stream sentinel ────────────────────────────────────────────

// TestStreaming_EmptyEndOfStreamChunkAssessesPendingText covers the sentinel
// many streaming frameworks send after the last event. Returning early on an
// empty chunk dropped the final batch, which AWS's guidance requires be
// assessed — and which this policy's own documentation claims it is.
func TestStreaming_EmptyEndOfStreamChunkAssessesPendingText(t *testing.T) {
	client := &countingBedrockClient{output: makeContentViolationOutput()}
	p := streamingPolicy(client, nil)
	respCtx := streamCtx()

	// Below a text unit, so nothing is assessed yet; text is held in pending.
	p.OnResponseBodyChunk(context.Background(), respCtx, &policy.StreamBody{
		Chunk: []byte(strings.Repeat(sseEvent("short "), 5)), EndOfStream: false,
	}, map[string]interface{}{})
	if client.calls != 0 {
		t.Fatalf("expected nothing assessed before end of stream, got %d", client.calls)
	}

	// The empty sentinel arrives. The held text must still be assessed.
	action := p.OnResponseBodyChunk(context.Background(), respCtx, &policy.StreamBody{
		Chunk: []byte{}, EndOfStream: true,
	}, map[string]interface{}{})

	if client.calls != 1 {
		t.Fatalf("an empty end-of-stream chunk must assess the pending text, got %d calls", client.calls)
	}
	if !action.TerminateStream() {
		t.Errorf("a violation in the final batch must end the stream, got %T", action)
	}
}

// TestStreaming_EmptyMidStreamChunkIsStillANoOp keeps the other half: only the
// end-of-stream sentinel is meaningful, an empty mid-stream chunk is not.
func TestStreaming_EmptyMidStreamChunkIsStillANoOp(t *testing.T) {
	client := &countingBedrockClient{output: makeContentViolationOutput()}
	p := streamingPolicy(client, nil)

	action := p.OnResponseBodyChunk(context.Background(), streamCtx(), &policy.StreamBody{
		Chunk: []byte{}, EndOfStream: false,
	}, map[string]interface{}{})

	if _, ok := action.(policy.ForwardResponseChunk); !ok {
		t.Fatalf("an empty mid-stream chunk must forward, got %T", action)
	}
	if client.calls != 0 {
		t.Errorf("an empty mid-stream chunk must not be assessed, got %d calls", client.calls)
	}
}

// TestStreaming_EmptyEndOfStreamChunkDoesNotResendANonSSEBody covers the
// non-SSE case: the accumulated body is assessed at end of stream, but a
// modification cannot be applied to an empty final chunk — returning the body
// there would deliver the whole response a second time.
func TestStreaming_EmptyEndOfStreamChunkDoesNotResendANonSSEBody(t *testing.T) {
	client := &countingBedrockClient{output: makePIIIntervenedOutput("john@example.com")}
	p := streamingPolicy(client, func(params *AWSBedrockGuardrailPolicyParams) {
		params.JsonPath = "$.msg"
		params.RedactPII = true
	})
	respCtx := streamCtx()

	p.OnResponseBodyChunk(context.Background(), respCtx, &policy.StreamBody{
		Chunk: []byte(`{"msg":"mail john@example.com"}`), EndOfStream: false,
	}, map[string]interface{}{})

	action := p.OnResponseBodyChunk(context.Background(), respCtx, &policy.StreamBody{
		Chunk: []byte{}, EndOfStream: true,
	}, map[string]interface{}{})

	forward, ok := action.(policy.ForwardResponseChunk)
	if !ok {
		t.Fatalf("expected ForwardResponseChunk, got %T", action)
	}
	if forward.Body != nil {
		t.Errorf("an empty final chunk must not be replaced with the accumulated body, got %q", string(forward.Body))
	}
}

// ─── Assess before delivering ────────────────────────────────────────────────

// TestStreaming_WithholdsUntilAssessed is the guarantee: a flush
// whose text has not been assessed is answered with an empty body, so the engine
// forwards an empty chunk and the client receives nothing.
func TestStreaming_WithholdsUntilAssessed(t *testing.T) {
	client := &countingBedrockClient{output: makeNoInterventionOutput()}
	p := streamingPolicy(client, nil)
	respCtx := streamCtx()

	for i := 0; i < 5; i++ {
		action := p.OnResponseBodyChunk(context.Background(), respCtx, &policy.StreamBody{
			Chunk: []byte(sseEvent("held text ")), EndOfStream: false,
		}, map[string]interface{}{})

		forward, ok := action.(policy.ForwardResponseChunk)
		if !ok {
			t.Fatalf("flush %d: expected ForwardResponseChunk, got %T", i, action)
		}
		if forward.Body == nil {
			t.Fatalf("flush %d: a nil body passes the bytes through — it must be an empty body", i)
		}
		if len(forward.Body) != 0 {
			t.Errorf("flush %d: nothing may be delivered before assessment, got %q", i, string(forward.Body))
		}
	}
	if client.calls != 0 {
		t.Errorf("below a text unit nothing should be assessed yet, got %d calls", client.calls)
	}
}

// TestStreaming_ReleasesExactlyTheAssessedBytes covers the release:
// once the batch passes, the withheld bytes are delivered verbatim, and the
// bytes of the flush that triggered the assessment are held for the next batch.
func TestStreaming_ReleasesExactlyTheAssessedBytes(t *testing.T) {
	client := &countingBedrockClient{output: makeNoInterventionOutput()}
	p := streamingPolicy(client, nil) // 1000-character unit
	respCtx := streamCtx()

	// ~110 characters of text per flush, so a unit is reached after ~10 flushes.
	flush := strings.Repeat(sseEvent("ten chars "), 11)
	var released string
	for i := 0; i < 12; i++ {
		action := p.OnResponseBodyChunk(context.Background(), respCtx, &policy.StreamBody{
			Chunk: []byte(flush), EndOfStream: false,
		}, map[string]interface{}{})
		forward := action.(policy.ForwardResponseChunk)
		released += string(forward.Body)
	}

	if client.calls != 1 {
		t.Fatalf("expected one assessment once a text unit accumulated, got %d", client.calls)
	}
	if n := len([]rune(client.texts[0])); n > DefaultStreamingTextUnitChars {
		t.Errorf("a batch assessed before delivery must stay within one text unit, got %d characters", n)
	}
	if released == "" {
		t.Fatalf("the assessed bytes must be released once the batch passes")
	}
	if !strings.HasPrefix(released, "data: ") || !strings.HasSuffix(released, "\n\n") {
		t.Errorf("released bytes must be the original frames verbatim, got %q…%q",
			released[:20], released[len(released)-10:])
	}
}

// TestStreaming_DiscardsBytesOnViolation is the point of the mode:
// a failing batch is never delivered, so the client sees the guardrail event and
// none of the text that violated.
func TestStreaming_DiscardsBytesOnViolation(t *testing.T) {
	client := &countingBedrockClient{output: makeContentViolationOutput()}
	p := streamingPolicy(client, nil)
	respCtx := streamCtx()

	var delivered string
	for i := 0; i < 12; i++ {
		action := p.OnResponseBodyChunk(context.Background(), respCtx, &policy.StreamBody{
			Chunk: []byte(strings.Repeat(sseEvent("blocked xx"), 11)), EndOfStream: false,
		}, map[string]interface{}{})

		if term, ok := action.(policy.TerminateResponseChunk); ok {
			body := string(term.Body)
			if !strings.Contains(body, "AWS_BEDROCK_GUARDRAIL") {
				t.Errorf("expected the guardrail event as the final body, got %q", body)
			}
			if strings.Contains(body, "blocked") {
				t.Errorf("the violating text must not be delivered, got %q", body)
			}
			if strings.Contains(delivered, "blocked") {
				t.Fatalf("violating text reached the client before the verdict: %q", delivered)
			}
			return
		}
		delivered += string(action.(policy.ForwardResponseChunk).Body)
	}
	t.Fatalf("expected the stream to be terminated once the batch was assessed")
}

// TestStreaming_ReleasesTheRemainderAtEndOfStream covers the tail:
// a batch below a unit is still assessed when the stream ends, and its bytes are
// delivered rather than lost.
func TestStreaming_ReleasesTheRemainderAtEndOfStream(t *testing.T) {
	client := &countingBedrockClient{output: makeNoInterventionOutput()}
	p := streamingPolicy(client, nil)
	respCtx := streamCtx()

	p.OnResponseBodyChunk(context.Background(), respCtx, &policy.StreamBody{
		Chunk: []byte(sseEvent("short tail ")), EndOfStream: false,
	}, map[string]interface{}{})
	if client.calls != 0 {
		t.Fatalf("expected nothing assessed below a unit, got %d calls", client.calls)
	}

	action := p.OnResponseBodyChunk(context.Background(), respCtx, &policy.StreamBody{
		Chunk: []byte("data: [DONE]\n\n"), EndOfStream: true,
	}, map[string]interface{}{})

	forward, ok := action.(policy.ForwardResponseChunk)
	if !ok {
		t.Fatalf("expected the remainder to be released, got %T", action)
	}
	if client.calls != 1 {
		t.Errorf("the final batch must still be assessed, got %d calls", client.calls)
	}
	if !strings.Contains(string(forward.Body), "short tail") {
		t.Errorf("the withheld frames must be delivered at end of stream, got %q", string(forward.Body))
	}
	if !strings.Contains(string(forward.Body), "[DONE]") {
		t.Errorf("the terminating event must be delivered too, got %q", string(forward.Body))
	}
}

// TestStreaming_PassthroughOnErrorStillReleases keeps the stream from
// stalling: if the guardrail cannot be reached and passthroughOnError is set, the
// withheld bytes are delivered rather than held indefinitely.
func TestStreaming_PassthroughOnErrorStillReleases(t *testing.T) {
	client := &countingBedrockClient{err: fmt.Errorf("bedrock unavailable")}
	p := streamingPolicy(client, func(params *AWSBedrockGuardrailPolicyParams) {
		params.PassthroughOnError = true
	})
	respCtx := streamCtx()

	var delivered string
	for i := 0; i < 12; i++ {
		action := p.OnResponseBodyChunk(context.Background(), respCtx, &policy.StreamBody{
			Chunk: []byte(strings.Repeat(sseEvent("ten chars "), 11)), EndOfStream: false,
		}, map[string]interface{}{})
		forward, ok := action.(policy.ForwardResponseChunk)
		if !ok {
			t.Fatalf("passthroughOnError must not end the stream, got %T", action)
		}
		delivered += string(forward.Body)
	}
	if delivered == "" {
		t.Errorf("withheld bytes must be released when the assessment cannot run")
	}
}

// TestStreaming_RestoresMaskedPIIOnRelease pins that the released
// bytes go through the same placeholder restoration as the delivered-as-you-go
// path, rather than bypassing it.
func TestStreaming_RestoresMaskedPIIOnRelease(t *testing.T) {
	client := &countingBedrockClient{output: makeNoInterventionOutput()}
	p := streamingPolicy(client, nil)
	respCtx := streamCtx()
	respCtx.Metadata[MetadataKeyPIIEntities] = map[string]string{"john@example.com": "EMAIL_0000"}

	p.OnResponseBodyChunk(context.Background(), respCtx, &policy.StreamBody{
		Chunk: []byte(sseEvent("write to EMAIL_0000 ")), EndOfStream: false,
	}, map[string]interface{}{})

	action := p.OnResponseBodyChunk(context.Background(), respCtx, &policy.StreamBody{
		Chunk: []byte("data: [DONE]\n\n"), EndOfStream: true,
	}, map[string]interface{}{})

	body := string(action.(policy.ForwardResponseChunk).Body)
	if !strings.Contains(body, "john@example.com") {
		t.Errorf("the masked value must be restored on release, got %q", body)
	}
	if strings.Contains(body, "EMAIL_0000") {
		t.Errorf("the placeholder must not survive release, got %q", body)
	}
}

// ─── Flushes that stop mid-line ──────────────────────────────────────────────

// TestSplitTrailingPartialLine_DividesAtTheLastTerminator pins the split used to
// retain an incomplete line.
func TestSplitTrailingPartialLine_DividesAtTheLastTerminator(t *testing.T) {
	complete, partial := splitTrailingPartialLine("data: {\"a\":1}\n\ndata: {\"b\":")
	if complete != "data: {\"a\":1}\n\n" || partial != "data: {\"b\":" {
		t.Errorf("unexpected split: complete %q, partial %q", complete, partial)
	}
	if c, p := splitTrailingPartialLine("no terminator at all"); c != "" || p != "no terminator at all" {
		t.Errorf("a flush with no terminator is wholly incomplete, got %q / %q", c, p)
	}
}

// TestStreaming_RetainsADataLineSplitAcrossFlushes is the defect this guards: a
// truncated "data:" payload is unparseable JSON, so before the retained
// fragment the text was extracted from neither flush and never assessed. The
// engine force-flushes at its accumulator ceiling regardless of event
// boundaries, and an upstream whose writes do not align with them produces the
// same shape.
func TestStreaming_RetainsADataLineSplitAcrossFlushes(t *testing.T) {
	client := &countingBedrockClient{output: makeNoInterventionOutput()}
	p := streamingPolicy(client, func(params *AWSBedrockGuardrailPolicyParams) {
		params.StreamingTextUnitChars = MinStreamingTextUnitChars
	})
	respCtx := streamCtx()

	// Enough complete events to reach the batch, then one cut mid-payload.
	first := strings.Repeat(sseEvent("padding xx"), 11) +
		"data: {\"choices\":[{\"delta\":{\"content\":\"SPLITMARK"
	second := "ER\"}}]}\n\n"

	p.OnResponseBodyChunk(context.Background(), respCtx, &policy.StreamBody{
		Chunk: []byte(first), EndOfStream: false,
	}, map[string]interface{}{})

	if got, _ := respCtx.Metadata[metaKeyPartialLine].(string); got == "" {
		t.Fatalf("the incomplete line must be retained for the next flush")
	}

	p.OnResponseBodyChunk(context.Background(), respCtx, &policy.StreamBody{
		Chunk: []byte(second), EndOfStream: true,
	}, map[string]interface{}{})

	var assessed string
	for _, text := range client.texts {
		assessed += text
	}
	if !strings.Contains(assessed, "SPLITMARKER") {
		t.Errorf("text from a split data line must be assessed, not skipped; assessed %q", assessed)
	}
}

// TestStreaming_DoesNotLoseAnOverlongPartialLine bounds the retained fragment: a
// stream carrying no line terminator must not grow it without limit. Past the
// limit it stops being held *as a fragment* and joins the withheld bytes, so it
// is still delivered once a batch is assessed — bounding memory must not lose
// bytes the client is owed.
func TestStreaming_DoesNotLoseAnOverlongPartialLine(t *testing.T) {
	p := streamingPolicy(&countingBedrockClient{output: makeNoInterventionOutput()}, nil)
	respCtx := streamCtx()
	respCtx.Metadata[metaKeySSEStream] = true

	oversized := "data: " + strings.Repeat("x", maxPartialLineBytes+100)
	a1 := p.OnResponseBodyChunk(context.Background(), respCtx, &policy.StreamBody{
		Chunk: []byte(oversized), EndOfStream: false,
	}, map[string]interface{}{})

	if got, _ := respCtx.Metadata[metaKeyPartialLine].(string); got != "" {
		t.Errorf("an over-limit fragment must not stay held as a fragment, got %d bytes", len(got))
	}

	// End of stream releases everything withheld.
	a2 := p.OnResponseBodyChunk(context.Background(), respCtx, &policy.StreamBody{
		Chunk: []byte{}, EndOfStream: true,
	}, map[string]interface{}{})

	delivered := string(a1.(policy.ForwardResponseChunk).Body) +
		string(a2.(policy.ForwardResponseChunk).Body)
	if delivered != oversized {
		t.Errorf("the fragment must be delivered in full, got %d of %d bytes",
			len(delivered), len(oversized))
	}
}

// ─── Non-SSE finalisation ────────────────────────────────────────────────────

// TestStreaming_EmptyNonSSEBodyIsNotRejected covers a streamed response that
// carries no body: there is nothing to assess, and handing it to validatePayload
// failed extraction and rejected the response.
func TestStreaming_EmptyNonSSEBodyIsNotRejected(t *testing.T) {
	client := &countingBedrockClient{output: makeContentViolationOutput()}
	p := streamingPolicy(client, nil)

	action := p.OnResponseBodyChunk(context.Background(), streamCtx(), &policy.StreamBody{
		Chunk: []byte("   "), EndOfStream: true,
	}, map[string]interface{}{})

	if _, ok := action.(policy.ForwardResponseChunk); !ok {
		t.Fatalf("an empty body must be forwarded, not rejected, got %T", action)
	}
	if client.calls != 0 {
		t.Errorf("an empty body must not be assessed, got %d calls", client.calls)
	}
}

// TestStreaming_DoesNotResendANonSSEBodyAfterAForcedFlush covers the other way a
// rewrite becomes undeliverable: once a flush has gone downstream, replacing a
// later chunk with the accumulated body would repeat every byte already sent.
func TestStreaming_DoesNotResendANonSSEBodyAfterAForcedFlush(t *testing.T) {
	client := &countingBedrockClient{output: makePIIIntervenedOutput("john@example.com")}
	p := streamingPolicy(client, func(params *AWSBedrockGuardrailPolicyParams) {
		params.JsonPath = "$.msg"
		params.RedactPII = true
	})
	respCtx := streamCtx()

	// A mid-stream flush: the engine force-flushed, so these bytes are delivered.
	p.OnResponseBodyChunk(context.Background(), respCtx, &policy.StreamBody{
		Chunk: []byte(`{"msg":"mail john`), EndOfStream: false,
	}, map[string]interface{}{})
	if forwarded, _ := respCtx.Metadata[metaKeyNonSSEForwarded].(bool); !forwarded {
		t.Fatalf("a mid-stream non-SSE flush must be recorded as forwarded")
	}

	action := p.OnResponseBodyChunk(context.Background(), respCtx, &policy.StreamBody{
		Chunk: []byte(`@example.com"}`), EndOfStream: true,
	}, map[string]interface{}{})

	forward, ok := action.(policy.ForwardResponseChunk)
	if !ok {
		t.Fatalf("expected ForwardResponseChunk, got %T", action)
	}
	if forward.Body != nil {
		t.Errorf("the accumulated body must not be re-sent after an earlier flush, got %q", string(forward.Body))
	}
}

// ─── Redaction across frame boundaries ───────────────────────────────────────

// TestStreaming_FailsClosedWhenRedactionSpansFrames is the leak guard. Redaction
// is written back frame by frame, so a value the model emitted across two events
// is present in neither frame's text and is replaced in neither. Forwarding it
// would defeat the one thing redaction mode exists for, so the stream ends
// instead.
func TestStreaming_FailsClosedWhenRedactionSpansFrames(t *testing.T) {
	client := &countingBedrockClient{output: makePIIIntervenedOutput("john@example.com")}
	p := streamingPolicy(client, func(params *AWSBedrockGuardrailPolicyParams) {
		params.RedactPII = true
	})

	// The address is split: "john@" in one event, "example.com" in the next.
	flush := sseEvent("mail john@") + sseEvent("example.com now")

	action := p.OnResponseBodyChunk(context.Background(), streamCtx(), &policy.StreamBody{
		Chunk: []byte(flush), EndOfStream: true,
	}, map[string]interface{}{})

	term, ok := action.(policy.TerminateResponseChunk)
	if !ok {
		t.Fatalf("an unredactable value must end the stream, got %T", action)
	}
	if strings.Contains(string(term.Body), "john@example.com") {
		t.Errorf("the value must not appear in the final event, got %q", string(term.Body))
	}
}

// TestStreaming_RedactsWhenTheValueIsWithinOneFrame keeps the ordinary case
// working: a value contained in a single event is redacted and delivered.
func TestStreaming_RedactsWhenTheValueIsWithinOneFrame(t *testing.T) {
	client := &countingBedrockClient{output: makePIIIntervenedOutput("john@example.com")}
	p := streamingPolicy(client, func(params *AWSBedrockGuardrailPolicyParams) {
		params.RedactPII = true
	})

	action := p.OnResponseBodyChunk(context.Background(), streamCtx(), &policy.StreamBody{
		Chunk: []byte(sseEvent("mail john@example.com now")), EndOfStream: true,
	}, map[string]interface{}{})

	forward, ok := action.(policy.ForwardResponseChunk)
	if !ok {
		t.Fatalf("a redactable value must be delivered redacted, got %T", action)
	}
	body := string(forward.Body)
	if strings.Contains(body, "john@example.com") || !strings.Contains(body, "*****") {
		t.Errorf("expected the value redacted in place, got %q", body)
	}
}

// TestStreaming_RewritesAPlaceholderSplitAcrossFlushes is the other half of
// retaining an incomplete line. Retaining it for assessment alone is not enough:
// if its bytes are forwarded with the flush that cut it, the frame this policy
// never got to rewrite is already at the client. Before the bytes were held too,
// both flushes passed through untouched and EMAIL_0000 was delivered verbatim.
func TestStreaming_RewritesAPlaceholderSplitAcrossFlushes(t *testing.T) {
	client := &countingBedrockClient{output: makeNoInterventionOutput()}
	p := streamingPolicy(client, nil)
	respCtx := streamCtx()
	respCtx.Metadata[MetadataKeyPIIEntities] = map[string]string{"john@example.com": "EMAIL_0000"}

	// The event is cut mid-payload, inside the placeholder itself.
	first := "data: {\"choices\":[{\"delta\":{\"content\":\"write EMAIL_0"
	second := "000 now\"}}]}\n\n"

	a1 := p.OnResponseBodyChunk(context.Background(), respCtx, &policy.StreamBody{
		Chunk: []byte(first), EndOfStream: false,
	}, map[string]interface{}{})
	a2 := p.OnResponseBodyChunk(context.Background(), respCtx, &policy.StreamBody{
		Chunk: []byte(second), EndOfStream: true,
	}, map[string]interface{}{})

	delivered := string(a1.(policy.ForwardResponseChunk).Body) +
		string(a2.(policy.ForwardResponseChunk).Body)

	if strings.Contains(delivered, "EMAIL_0000") {
		t.Errorf("the placeholder survived a split flush: %q", delivered)
	}
	if !strings.Contains(delivered, "john@example.com") {
		t.Errorf("the masked value must be restored once the line completes, got %q", delivered)
	}
	// Nothing may be lost or duplicated by the withholding.
	if want := first + second; len(delivered) < len(want)-len("EMAIL_0000")+len("john@example.com") {
		t.Errorf("delivered stream is shorter than the frames that arrived: %q", delivered)
	}
}

// TestStreaming_BoundsTheWithheldBuffer covers a stream whose events
// carry no assessable text — SSE keep-alives, role deltas, usage frames. The
// batch boundary is a character count, so such a stream never reaches it, and
// without a byte limit the withheld buffer grows for as long as the stream runs
// while the client receives nothing.
func TestStreaming_BoundsTheWithheldBuffer(t *testing.T) {
	client := &countingBedrockClient{output: makeNoInterventionOutput()}
	p := streamingPolicy(client, nil)
	respCtx := streamCtx()

	keepAlive := strings.Repeat(": keep-alive\n\n", 100) // ~1.4 KB per flush
	var delivered int
	for i := 0; i < 400; i++ { // ~560 KB, well past the limit
		action := p.OnResponseBodyChunk(context.Background(), respCtx, &policy.StreamBody{
			Chunk: []byte(keepAlive), EndOfStream: false,
		}, map[string]interface{}{})
		delivered += len(action.(policy.ForwardResponseChunk).Body)
	}

	held, _ := respCtx.Metadata[metaKeyHeldBytes].(string)
	if len(held) > maxHeldFlushBytes {
		t.Errorf("the withheld buffer must stay within its limit, got %d bytes", len(held))
	}
	if delivered == 0 {
		t.Errorf("a stream carrying no assessable text must still be delivered, not withheld forever")
	}
}

// TestSplitHeldAtTextBoundary_CutsAtFrameBoundaries pins the mapping from an
// assessed character count back to releasable bytes.
func TestSplitHeldAtTextBoundary_CutsAtFrameBoundaries(t *testing.T) {
	held := sseEvent("one ") + sseEvent("two ") + sseEvent("three")
	path := ResponseDefaultStreamingJSONPath

	t.Run("boundary inside a frame retains that frame whole", func(t *testing.T) {
		// "one two " is 8 characters; 10 falls inside the third frame.
		release, retain, covered := splitHeldAtTextBoundary(held, path, 10)
		if release != sseEvent("one ")+sseEvent("two ") {
			t.Errorf("expected the two covered frames, got %q", release)
		}
		if retain != sseEvent("three") {
			t.Errorf("expected the straddling frame retained, got %q", retain)
		}
		if covered != 8 {
			t.Errorf("expected the released frames to report 8 covered characters, got %d", covered)
		}
	})

	t.Run("nothing assessed releases nothing", func(t *testing.T) {
		if release, retain, _ := splitHeldAtTextBoundary(held, path, 0); release != "" || retain != held {
			t.Errorf("expected all retained, got release %q", release)
		}
	})

	t.Run("everything assessed releases everything", func(t *testing.T) {
		if release, retain, _ := splitHeldAtTextBoundary(held, path, 100); release != held || retain != "" {
			t.Errorf("expected all released, got retain %q", retain)
		}
	})

	t.Run("an introducer is retained with its data line", func(t *testing.T) {
		withEvent := sseEvent("one ") + "event: message\n" + "data: {\"choices\":[{\"delta\":{\"content\":\"two\"}}]}\n\n"
		release, retain, _ := splitHeldAtTextBoundary(withEvent, path, 4)
		if strings.Contains(release, "event: message") {
			t.Errorf("an event: line must not be released without its payload, got %q", release)
		}
		if !strings.HasPrefix(retain, "event: message") {
			t.Errorf("the introducer must travel with its retained block, got %q", retain)
		}
	})
}

// TestStreaming_TrimsBatchesToSentenceBoundaries is the point of the
// mapping: a phrase assessed as two halves can pass where the whole would not,
// so the safe mode must align batches the same way the immediate-delivery mode
// does rather than cutting wherever a flush happened to end.
func TestStreaming_TrimsBatchesToSentenceBoundaries(t *testing.T) {
	client := &countingBedrockClient{output: makeNoInterventionOutput()}
	p := streamingPolicy(client, func(params *AWSBedrockGuardrailPolicyParams) {
		params.StreamingTextUnitChars = MinStreamingTextUnitChars // 100
	})
	respCtx := streamCtx()

	// Just under the unit, ending mid-sentence, then a flush that carries the
	// sentence's end. The batch must stop at the full stop, not at the flush.
	p.OnResponseBodyChunk(context.Background(), respCtx, &policy.StreamBody{
		Chunk:       []byte(strings.Repeat(sseEvent("filler. "), 12) + sseEvent("a split phra")),
		EndOfStream: false,
	}, map[string]interface{}{})
	p.OnResponseBodyChunk(context.Background(), respCtx, &policy.StreamBody{
		Chunk:       []byte(sseEvent("se ends here. ") + strings.Repeat(sseEvent("more. "), 12)),
		EndOfStream: false,
	}, map[string]interface{}{})

	if client.calls == 0 {
		t.Fatalf("expected at least one batch to be assessed")
	}
	for i, text := range client.texts {
		trimmed := strings.TrimSpace(text)
		if trimmed == "" {
			continue
		}
		last := trimmed[len(trimmed)-1]
		if last != '.' && last != '!' && last != '?' {
			t.Errorf("batch %d ended mid-sentence at %q", i, tail(trimmed, 24))
		}
	}
	// No phrase may be assessed in halves.
	for _, text := range client.texts {
		if strings.Contains(text, "a split phra") && !strings.Contains(text, "a split phrase") {
			t.Errorf("a phrase was assessed split in half: %q", tail(text, 40))
		}
	}
}

// tail returns the last n characters of s, for readable failure messages.
func tail(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return "…" + s[len(s)-n:]
}

// TestSplitHeldAtTextBoundary_NeverReleasesAnUnterminatedFrame is the guarantee's
// edge. A frame still arriving has a truncated payload, so its text cannot be
// read — and reading zero characters out of it must not be mistaken for it
// carrying none, which released it with its text never assessed.
func TestSplitHeldAtTextBoundary_NeverReleasesAnUnterminatedFrame(t *testing.T) {
	path := ResponseDefaultStreamingJSONPath
	held := sseEvent("one ") + sseEvent("two ") +
		"data: {\"choices\":[{\"delta\":{\"content\":\"thr"

	release, retain, covered := splitHeldAtTextBoundary(held, path, 8) // "one two "

	if strings.Contains(release, "thr") {
		t.Errorf("an unterminated frame must not be released: %q", release)
	}
	if release != sseEvent("one ")+sseEvent("two ") {
		t.Errorf("expected only the complete frames released, got %q", release)
	}
	if !strings.HasPrefix(retain, "data: ") || !strings.Contains(retain, "thr") {
		t.Errorf("the unterminated frame must be retained, got %q", retain)
	}
	if covered != 8 {
		t.Errorf("expected 8 covered characters, got %d", covered)
	}
}

// TestStreaming_CountsAssessedTextLeftInRetainedFrames covers the boundary
// accounting. The trim point falls inside a frame, so that frame is retained
// with part of its text already assessed. That prefix is deliberately not in
// pending — it must not be billed twice — so it has to be counted toward the
// next boundary instead.
//
// Frames here carry ~420 characters each, a large share of the 1,000-character
// unit, which is what makes the deficit visible: with token-sized frames the
// prefix is a few characters against a budget of a thousand and the lag
// self-corrects every round. With large frames the uncounted prefix compounds,
// the withheld buffer grows for as long as the stream runs, and delivery falls
// further behind — measured at 1,864, 3,728 and 4,660 bytes after 20, 40 and 60
// flushes before this was counted.
func TestStreaming_CountsAssessedTextLeftInRetainedFrames(t *testing.T) {
	client := &countingBedrockClient{output: makeNoInterventionOutput()}
	p := streamingPolicy(client, nil) // 1,000-character unit
	respCtx := streamCtx()

	frame := sseEvent(strings.Repeat("sentence here. ", 28)) // ~420 characters of text
	const flushes = 60

	var sizes []int
	for i := 1; i <= flushes; i++ {
		p.OnResponseBodyChunk(context.Background(), respCtx, &policy.StreamBody{
			Chunk: []byte(frame), EndOfStream: false,
		}, map[string]interface{}{})
		if i%20 == 0 {
			held, _ := respCtx.Metadata[metaKeyHeldBytes].(string)
			sizes = append(sizes, len(held))
		}
	}

	if assessed, _ := respCtx.Metadata[metaKeyAssessedInHeld].(int); assessed < 0 {
		t.Errorf("the carried count must never go negative, got %d", assessed)
	}

	// Bounded, not growing: the last sample must not exceed the first by more
	// than one batch's worth of frames.
	if sizes[len(sizes)-1] > sizes[0]+2*len(frame) {
		t.Errorf("withheld bytes grew across the stream: %v after %d flushes", sizes, flushes)
	}
	if ceiling := 4 * len(frame); sizes[len(sizes)-1] > ceiling {
		t.Errorf("withheld bytes %d exceed one batch plus a flush (%d)", sizes[len(sizes)-1], ceiling)
	}

	// And nothing is billed twice.
	var billed int
	for _, text := range client.texts {
		billed += len([]rune(text))
	}
	if produced := flushes * 28 * len("sentence here. "); billed > produced {
		t.Errorf("more characters were assessed than the stream produced: %d billed, %d produced",
			billed, produced)
	}
}

// TestStreaming_DeliversByteExactAcrossMidLineSplits is the invariant that makes
// the withheld bytes safe to reason about, whichever side it is enforced from.
//
// Two implementations satisfy it: accumulate only complete lines into the
// withheld buffer and carry the trailing fragment separately, or accumulate the
// raw flush and refuse to release past the last complete line. This policy does
// the latter, so the property needs asserting rather than assuming — the risk of
// holding raw bytes is that the fragment is counted twice or dropped at the
// seam.
//
// Chunk sizes are chosen so most cuts land mid-line, including inside a JSON
// payload, and the whole delivered stream is compared to the input: in order,
// nothing duplicated, nothing lost.
func TestStreaming_DeliversByteExactAcrossMidLineSplits(t *testing.T) {
	var input string
	for i := 0; i < 40; i++ {
		input += sseEvent("some words here. ")
	}

	for _, size := range []int{7, 13, 29, 64, 157, 400} {
		t.Run(fmt.Sprintf("chunk=%d", size), func(t *testing.T) {
			p := streamingPolicy(&countingBedrockClient{output: makeNoInterventionOutput()},
				func(params *AWSBedrockGuardrailPolicyParams) {
					params.StreamingTextUnitChars = MinStreamingTextUnitChars
				})
			respCtx := streamCtx()
			respCtx.Metadata[metaKeySSEStream] = true

			var delivered string
			for off := 0; off < len(input); off += size {
				end := off + size
				if end > len(input) {
					end = len(input)
				}
				action := p.OnResponseBodyChunk(context.Background(), respCtx, &policy.StreamBody{
					Chunk:       []byte(input[off:end]),
					EndOfStream: end == len(input),
				}, map[string]interface{}{})

				forward, ok := action.(policy.ForwardResponseChunk)
				if !ok {
					t.Fatalf("offset %d: unexpected %T", off, action)
				}
				if forward.Body == nil {
					delivered += input[off:end]
					continue
				}
				delivered += string(forward.Body)
			}

			if delivered == input {
				return
			}
			switch {
			case len(delivered) > len(input):
				t.Errorf("bytes duplicated at the seam: delivered %d, input %d", len(delivered), len(input))
			case len(delivered) < len(input):
				t.Errorf("bytes lost at the seam: delivered %d, input %d", len(delivered), len(input))
			default:
				t.Errorf("bytes reordered: same length, different content")
			}
		})
	}
}

// TestStreaming_WholeResponseAssessmentHoldsUntilEndOfStream covers
// streamingTextUnitChars: 0. Nothing is assessed, and so nothing is delivered,
// until the stream ends — the closest thing to the buffered path's semantics
// while still being able to read a streamed body.
//
// Each AWS call stays bounded even so: an unbounded batch would send one
// oversized request, which is the case the long-context half of AWS's guidance
// says to chunk.
func TestStreaming_WholeResponseAssessmentHoldsUntilEndOfStream(t *testing.T) {
	client := &countingBedrockClient{output: makeNoInterventionOutput()}
	p := streamingPolicy(client, func(params *AWSBedrockGuardrailPolicyParams) {
		params.StreamingTextUnitChars = 0
	})
	respCtx := streamCtx()

	flush := strings.Repeat(sseEvent("words here. "), 50) // 600 characters each
	var delivered int
	for i := 0; i < 5; i++ {
		action := p.OnResponseBodyChunk(context.Background(), respCtx, &policy.StreamBody{
			Chunk: []byte(flush), EndOfStream: false,
		}, map[string]interface{}{})
		delivered += len(action.(policy.ForwardResponseChunk).Body)
	}

	if client.calls != 0 {
		t.Errorf("nothing may be assessed before the stream ends, got %d calls", client.calls)
	}
	if delivered != 0 {
		t.Errorf("nothing may be delivered before the stream ends, got %d bytes", delivered)
	}

	action := p.OnResponseBodyChunk(context.Background(), respCtx, &policy.StreamBody{
		Chunk: []byte("data: [DONE]\n\n"), EndOfStream: true,
	}, map[string]interface{}{})

	if client.calls == 0 {
		t.Fatalf("the whole response must be assessed at end of stream")
	}
	// Bounded per call despite the unbounded batch.
	for i, text := range client.texts {
		if n := len([]rune(text)); n > DefaultStreamingTextUnitChars+maxBoundarySearchRunes {
			t.Errorf("call %d carried %d characters; each call must stay near a text unit", i, n)
		}
	}
	if body := action.(policy.ForwardResponseChunk).Body; len(body) == 0 {
		t.Errorf("the withheld response must be delivered at end of stream")
	}
}

// TestStreaming_NeverReleasesAPartialLineAtTheHeldLimit covers the withheld-byte
// limit. It assesses what has accumulated and releases, but the text of a
// trailing incomplete line was never readable and so is not in that assessment —
// its bytes must stay withheld for the flush that completes it, or an
// unassessed half-frame goes to the client.
func TestStreaming_NeverReleasesAPartialLineAtTheHeldLimit(t *testing.T) {
	client := &countingBedrockClient{output: makeNoInterventionOutput()}
	p := streamingPolicy(client, nil)
	respCtx := streamCtx()
	respCtx.Metadata[metaKeySSEStream] = true

	// Fill the withheld buffer with framing that carries no assessable text, so
	// the character boundary is never reached and the byte limit is what fires.
	filler := strings.Repeat(": keep-alive\n\n", 2000) // ~28 KB per flush
	for i := 0; i < 9; i++ {
		p.OnResponseBodyChunk(context.Background(), respCtx, &policy.StreamBody{
			Chunk: []byte(filler), EndOfStream: false,
		}, map[string]interface{}{})
	}

	// The next flush trips the limit and ends mid-line.
	action := p.OnResponseBodyChunk(context.Background(), respCtx, &policy.StreamBody{
		Chunk:       []byte(filler + "data: {\"choices\":[{\"delta\":{\"content\":\"SECRET"),
		EndOfStream: false,
	}, map[string]interface{}{})

	forward, ok := action.(policy.ForwardResponseChunk)
	if !ok {
		t.Fatalf("expected ForwardResponseChunk, got %T", action)
	}
	if strings.Contains(string(forward.Body), "SECRET") {
		t.Errorf("an unassessed partial line was released at the byte limit")
	}
	if retained, _ := respCtx.Metadata[metaKeyHeldBytes].(string); !strings.Contains(retained, "SECRET") {
		t.Errorf("the partial line must stay withheld, got %q", retained)
	}
}

// ─── Verdict correctness ─────────────────────────────────────────────────────

// blockedPIIOutput reports a PII entity the guardrail was configured to BLOCK,
// not anonymise — AWS_ACCESS_KEY, say.
func blockedPIIOutput(match string) *bedrockruntime.ApplyGuardrailOutput {
	return &bedrockruntime.ApplyGuardrailOutput{
		Action: types.GuardrailActionGuardrailIntervened,
		Assessments: []types.GuardrailAssessment{{
			SensitiveInformationPolicy: &types.GuardrailSensitiveInformationPolicyAssessment{
				PiiEntities: []types.GuardrailPiiEntityFilter{{
					Action: types.GuardrailSensitiveInformationPolicyActionBlocked,
					Match:  aws.String(match),
					Type:   types.GuardrailPiiEntityTypeAwsAccessKey,
				}},
			},
		}},
	}
}

// injectionWithPIIOutput is the assessment AWS returns for a prompt attack that
// also contains an email: the content filter BLOCKED, the email ANONYMIZED.
func injectionWithPIIOutput(email string) *bedrockruntime.ApplyGuardrailOutput {
	return &bedrockruntime.ApplyGuardrailOutput{
		Action: types.GuardrailActionGuardrailIntervened,
		Assessments: []types.GuardrailAssessment{{
			ContentPolicy: &types.GuardrailContentPolicyAssessment{
				Filters: []types.GuardrailContentFilter{{
					Type:       types.GuardrailContentFilterTypePromptAttack,
					Confidence: types.GuardrailContentFilterConfidenceHigh,
					Action:     types.GuardrailContentPolicyActionBlocked,
				}},
			},
			SensitiveInformationPolicy: &types.GuardrailSensitiveInformationPolicyAssessment{
				PiiEntities: []types.GuardrailPiiEntityFilter{{
					Action: types.GuardrailSensitiveInformationPolicyActionAnonymized,
					Match:  aws.String(email),
					Type:   types.GuardrailPiiEntityTypeEmail,
				}},
			},
		}},
	}
}

// TestEvaluate_BlockedFindingsBlock covers the verdict bug. Any PII entity in
// the assessment was treated as "masking was applied" and the content allowed
// through, so a prompt attack reported alongside an email was let past, and a
// PII type configured to BLOCK was masked and delivered instead of blocked.
func TestEvaluate_BlockedFindingsBlock(t *testing.T) {
	p := &AWSBedrockGuardrailPolicy{}

	t.Run("prompt attack reported with an anonymisable email", func(t *testing.T) {
		violation, _, err := p.evaluateGuardrailResponse(
			injectionWithPIIOutput("john@example.com"), "attack text john@example.com",
			false, true, map[string]interface{}{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !violation {
			t.Errorf("a BLOCKED content filter must block even when PII in the same text is anonymisable")
		}
	})

	t.Run("PII type configured to block", func(t *testing.T) {
		violation, modified, err := p.evaluateGuardrailResponse(
			blockedPIIOutput("AKIAIOSFODNN7EXAMPLE"), "key AKIAIOSFODNN7EXAMPLE",
			false, true, map[string]interface{}{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !violation {
			t.Errorf("a PII entity with action BLOCKED must block, not be masked")
		}
		if modified != "" {
			t.Errorf("a blocked finding must not produce masked content, got %q", modified)
		}
	})

	t.Run("anonymisable findings still mask", func(t *testing.T) {
		metadata := map[string]interface{}{}
		violation, modified, err := p.evaluateGuardrailResponse(
			makePIIIntervenedOutput("john@example.com"), "mail john@example.com",
			false, true, metadata)
		if err != nil || violation {
			t.Fatalf("an anonymisable finding must not block: violation=%v err=%v", violation, err)
		}
		if !strings.Contains(modified, "EMAIL_") {
			t.Errorf("expected the value masked, got %q", modified)
		}
		if _, ok := metadata[MetadataKeyPIIEntities]; !ok {
			t.Errorf("the placeholder map must be recorded for the response to restore")
		}
	})
}

// TestBufferedPath_AssessesARestoredResponse covers the response whose
// placeholders were put back. It used to be returned at that point and never
// assessed, so a response could carry anything past the guardrail as long as its
// own request had masked something.
func TestBufferedPath_AssessesARestoredResponse(t *testing.T) {
	client := &countingBedrockClient{output: makeContentViolationOutput()}
	p := streamingPolicy(client, func(params *AWSBedrockGuardrailPolicyParams) {
		params.JsonPath = "$.msg"
	})

	respCtx := &policy.ResponseContext{
		SharedContext: &policy.SharedContext{Metadata: map[string]interface{}{
			MetadataKeyPIIEntities: map[string]string{"john@example.com": "EMAIL_0000"},
		}},
		ResponseBody: &policy.Body{Content: []byte(`{"msg":"write to EMAIL_0000"}`)},
	}

	result := p.OnResponseBody(context.Background(), respCtx, map[string]interface{}{})
	mod, ok := result.(policy.DownstreamResponseModifications)
	if !ok {
		t.Fatalf("expected DownstreamResponseModifications, got %T", result)
	}
	if client.calls == 0 {
		t.Fatalf("a restored response must still be assessed")
	}
	if mod.StatusCode == nil || *mod.StatusCode != GuardrailErrorCode {
		t.Errorf("a violation in a restored response must be blocked, got status %v", mod.StatusCode)
	}
	if strings.Contains(client.texts[0], "EMAIL_0000") {
		t.Errorf("the assessment must see the restored text, not the placeholder: %q", client.texts[0])
	}
}

// TestBufferedPath_ReadsAnSSEBody covers an SSE response arriving on the
// buffered path, which happens whenever another policy on the route declares
// BUFFER and the engine demotes the whole chain. jsonPath addresses a
// non-streamed shape and cannot match it, which answered 422 for a response the
// upstream had returned 200 for — the original defect, in the one configuration
// the streaming path does not cover.
func TestBufferedPath_ReadsAnSSEBody(t *testing.T) {
	t.Run("clean SSE body is not rejected", func(t *testing.T) {
		client := &countingBedrockClient{output: makeNoInterventionOutput()}
		p := streamingPolicy(client, nil)

		respCtx := &policy.ResponseContext{
			SharedContext: &policy.SharedContext{Metadata: map[string]interface{}{}},
			ResponseBody:  &policy.Body{Content: []byte(sseEvent("hello there") + "data: [DONE]\n\n")},
		}

		result := p.OnResponseBody(context.Background(), respCtx, map[string]interface{}{})
		mod, ok := result.(policy.DownstreamResponseModifications)
		if !ok {
			t.Fatalf("expected DownstreamResponseModifications, got %T", result)
		}
		if mod.StatusCode != nil {
			t.Errorf("a clean SSE body must not be rejected, got status %d", *mod.StatusCode)
		}
		if client.calls != 1 || !strings.Contains(client.texts[0], "hello there") {
			t.Errorf("expected the delta text assessed, got %d calls %q", client.calls, client.texts)
		}
	})

	t.Run("violating SSE body blocks with a status", func(t *testing.T) {
		client := &countingBedrockClient{output: makeContentViolationOutput()}
		p := streamingPolicy(client, nil)

		respCtx := &policy.ResponseContext{
			SharedContext: &policy.SharedContext{Metadata: map[string]interface{}{}},
			ResponseBody:  &policy.Body{Content: []byte(sseEvent("blocked content"))},
		}

		mod, ok := p.OnResponseBody(context.Background(), respCtx, map[string]interface{}{}).(policy.DownstreamResponseModifications)
		if !ok {
			t.Fatalf("expected DownstreamResponseModifications")
		}
		// The buffered path can still answer a status, unlike the streaming one.
		if mod.StatusCode == nil || *mod.StatusCode != GuardrailErrorCode {
			t.Errorf("expected the violation answered with %d, got %v", GuardrailErrorCode, mod.StatusCode)
		}
	})
}

// TestStreaming_BoundsEveryCallToOneTextUnit covers a configured batch far
// larger than a text unit. The batch decides when to assess and deliver; it must
// not decide how much goes into one request. Before this, the withheld-bytes
// limit bounded the buffer but not the call, and a very large batch sent 55,199
// characters in a single request — the long-context case AWS's guidance says to
// chunk. Splitting costs nothing: input is billed per text unit either way.
func TestStreaming_BoundsEveryCallToOneTextUnit(t *testing.T) {
	client := &countingBedrockClient{output: makeNoInterventionOutput()}
	p := streamingPolicy(client, func(params *AWSBedrockGuardrailPolicyParams) {
		params.StreamingTextUnitChars = 1000000
	})
	respCtx := streamCtx()

	flush := strings.Repeat(sseEvent("words here. "), 100)
	for i := 0; i < 400; i++ {
		p.OnResponseBodyChunk(context.Background(), respCtx, &policy.StreamBody{
			Chunk: []byte(flush), EndOfStream: false,
		}, map[string]interface{}{})
	}

	if client.calls == 0 {
		t.Fatalf("expected the withheld-bytes limit to force assessment")
	}
	ceiling := DefaultStreamingTextUnitChars + maxBoundarySearchRunes
	for i, text := range client.texts {
		if n := len([]rune(text)); n > ceiling {
			t.Errorf("call %d carried %d characters; every call must stay within one text unit (%d)",
				i, n, ceiling)
		}
	}
}
