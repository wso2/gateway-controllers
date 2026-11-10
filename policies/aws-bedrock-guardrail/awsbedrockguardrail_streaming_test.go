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

func (c *countingBedrockClient) ApplyGuardrail(_ context.Context, params *bedrockruntime.ApplyGuardrailInput, _ ...func(*bedrockruntime.Options)) (*bedrockruntime.ApplyGuardrailOutput, error) {
	c.calls++
	for _, content := range params.Content {
		if text, ok := content.(*types.GuardrailContentBlockMemberText); ok {
			c.texts = append(c.texts, aws.ToString(text.Value.Text))
		}
	}
	return c.output, c.err
}

func makeNoInterventionOutput() *bedrockruntime.ApplyGuardrailOutput {
	return &bedrockruntime.ApplyGuardrailOutput{Action: types.GuardrailActionNone}
}

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
		Enabled:              true,
		JsonPath:             ResponseDefaultJSONPath,
		Streaming:            true,
		StreamingJsonPath:    ResponseDefaultStreamingJSONPath,
		StreamingWindowBytes: DefaultStreamingWindowBytes,
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

func streamCtx() *policy.ResponseStreamContext {
	return &policy.ResponseStreamContext{
		SharedContext: &policy.SharedContext{Metadata: map[string]interface{}{}},
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

func TestMode_FollowsConfiguration(t *testing.T) {
	cases := []struct {
		name                      string
		hasRequest, hasResponse   bool
		requestOn, responseOn     bool
		streaming                 bool
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
			// Backward compatibility: a response flow that has not opted into
			// streaming keeps buffering, exactly as in v1.1.0.
			name:       "response buffered by default",
			hasRequest: true, requestOn: true,
			hasResponse: true, responseOn: true,
			wantRequest: policy.BodyModeBuffer, wantResponse: policy.BodyModeBuffer,
		},
		{
			name:       "response streaming opted in",
			hasRequest: true, requestOn: true,
			hasResponse: true, responseOn: true, streaming: true,
			wantRequest: policy.BodyModeBuffer, wantResponse: policy.BodyModeStream,
		},
		{
			name:       "response only",
			hasRequest: true, requestOn: false,
			hasResponse: true, responseOn: true, streaming: true,
			wantRequest: policy.BodyModeSkip, wantResponse: policy.BodyModeStream,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := &AWSBedrockGuardrailPolicy{
				hasRequestParams:  tc.hasRequest,
				hasResponseParams: tc.hasResponse,
				requestParams:     AWSBedrockGuardrailPolicyParams{Enabled: tc.requestOn},
				responseParams:    AWSBedrockGuardrailPolicyParams{Enabled: tc.responseOn, Streaming: tc.streaming},
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

func TestNeedsMoreResponseData_WindowAndEventBoundary(t *testing.T) {
	p := streamingPolicy(&countingBedrockClient{output: makeNoInterventionOutput()}, func(params *AWSBedrockGuardrailPolicyParams) {
		params.StreamingWindowBytes = 256
	})

	short := sseEvent("hi")
	if !p.NeedsMoreResponseData([]byte(short)) {
		t.Errorf("below the window the policy must keep accumulating")
	}

	full := strings.Repeat(sseEvent("0123456789"), 20)
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
	crlf := strings.Repeat("data: {\"choices\":[{\"delta\":{\"content\":\"0123456789\"}}]}\r\n\r\n", 20)
	if p.NeedsMoreResponseData([]byte(crlf)) {
		t.Errorf("CRLF event boundary must be recognised as a boundary")
	}

	// A non-SSE body accumulates whole, so nothing unvalidated reaches the
	// client; the kernel's end-of-stream flush is what releases it.
	if !p.NeedsMoreResponseData([]byte(`{"choices":[{"message":{"content":"hello"}}]}`)) {
		t.Errorf("a non-SSE body must accumulate to end of stream")
	}

	// A buffered instance must never ask the kernel to accumulate.
	buffered := streamingPolicy(&countingBedrockClient{}, func(params *AWSBedrockGuardrailPolicyParams) {
		params.Streaming = false
	})
	if buffered.NeedsMoreResponseData([]byte(short)) {
		t.Errorf("a non-streaming instance must not accumulate")
	}
}

func TestStreaming_CleanStreamForwardsUnchangedAndValidatesPerWindow(t *testing.T) {
	client := &countingBedrockClient{output: makeNoInterventionOutput()}
	p := streamingPolicy(client, func(params *AWSBedrockGuardrailPolicyParams) {
		params.StreamingWindowBytes = 256
	})

	// One SSE event per chunk — the framing a real upstream flushing per event
	// produces. Coalescing events into larger chunks is what hides window and
	// boundary defects.
	var chunks []string
	for i := 0; i < 40; i++ {
		chunks = append(chunks, sseEvent("token"))
	}

	actions := feedStream(t, p, streamCtx(), chunks)

	for i, action := range actions {
		forward, ok := action.(policy.ForwardResponseChunk)
		if !ok {
			t.Fatalf("flush %d: expected ForwardResponseChunk, got %T", i, action)
		}
		if forward.Body != nil {
			t.Errorf("flush %d: a clean stream must pass through untouched, got a rewritten body", i)
		}
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
		params.StreamingWindowBytes = MinStreamingWindowBytes
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
		params.StreamingWindowBytes = MinStreamingWindowBytes
	})
	chunks := []string{strings.Repeat(sseEvent("hello"), 10), sseEvent("more")}
	actions := feedStream(t, blocking, streamCtx(), chunks)
	if _, ok := actions[len(actions)-1].(policy.TerminateResponseChunk); !ok {
		t.Fatalf("a guardrail call failure must end the stream when passthroughOnError is false, got %T", actions[len(actions)-1])
	}

	permissive := streamingPolicy(failing, func(params *AWSBedrockGuardrailPolicyParams) {
		params.StreamingWindowBytes = MinStreamingWindowBytes
		params.PassthroughOnError = true
	})
	for i, action := range feedStream(t, permissive, streamCtx(), chunks) {
		if _, ok := action.(policy.ForwardResponseChunk); !ok {
			t.Fatalf("flush %d: passthroughOnError must forward, got %T", i, action)
		}
	}
}

func TestStreaming_RestoresMaskedPIIInFrames(t *testing.T) {
	client := &countingBedrockClient{output: makeNoInterventionOutput()}
	p := streamingPolicy(client, func(params *AWSBedrockGuardrailPolicyParams) {
		params.StreamingWindowBytes = MinStreamingWindowBytes
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
		params.StreamingWindowBytes = MinStreamingWindowBytes
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

func TestParseRequestResponseParams_StreamingParams(t *testing.T) {
	t.Run("response defaults", func(t *testing.T) {
		got, err := parseRequestResponseParams(map[string]interface{}{"enabled": true}, true)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got.Streaming {
			t.Errorf("streaming must be off unless opted into")
		}
		if got.StreamingJsonPath != ResponseDefaultStreamingJSONPath {
			t.Errorf("unexpected default streaming path: %q", got.StreamingJsonPath)
		}
		if got.StreamingWindowBytes != DefaultStreamingWindowBytes {
			t.Errorf("unexpected default window: %d", got.StreamingWindowBytes)
		}
	})

	t.Run("accepts configured values", func(t *testing.T) {
		// A window arriving from YAML/JSON is a float64, not an int.
		got, err := parseRequestResponseParams(map[string]interface{}{
			"enabled":              true,
			"streaming":            true,
			"streamingJsonPath":    "$.delta.text",
			"streamingWindowBytes": float64(4096),
		}, true)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !got.Streaming || got.StreamingJsonPath != "$.delta.text" || got.StreamingWindowBytes != 4096 {
			t.Errorf("unexpected params: %+v", got)
		}
	})

	t.Run("rejects invalid values", func(t *testing.T) {
		cases := []map[string]interface{}{
			{"streaming": "yes"},
			{"streamingJsonPath": ""},
			{"streamingJsonPath": 1},
			{"streamingWindowBytes": float64(16)},
			{"streamingWindowBytes": "big"},
		}
		for _, params := range cases {
			if _, err := parseRequestResponseParams(params, true); err == nil {
				t.Errorf("expected an error for %+v", params)
			}
		}
	})

	t.Run("rejects streaming params on the request flow", func(t *testing.T) {
		for _, key := range []string{"streaming", "streamingJsonPath", "streamingWindowBytes"} {
			if _, err := parseRequestResponseParams(map[string]interface{}{key: true}, false); err == nil {
				t.Errorf("expected %q to be rejected on the request flow", key)
			}
		}
	})
}
