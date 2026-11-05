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
	"log/slog"
	"strings"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

// ─── Streaming response phase ─────────────────────────────────────────────────
//
// Mistral speaks OpenAI on the way back, so unlike the Anthropic, Gemini and
// Bedrock translators this one has no events to rewrite. The streaming phase
// exists for two other reasons: to keep the route's streaming capability intact
// (see Mode), and to handle the case the buffered path cannot reach — a
// complete JSON document delivered in pieces because the upstream framed it
// chunked.

// NeedsMoreResponseData tells the kernel when to keep accumulating instead of
// delivering what it has.
//
// An event stream is forwarded byte for byte, so nothing is gained by holding
// it: every chunk is released as it arrives, which is what restores
// token-by-token delivery to the client. A body that is not an event stream is
// held until the upstream closes, because the gateway routes a response through
// this path whenever the upstream framing is chunked — and an ordinary JSON
// reply is framed that way whenever the provider omits content-length. Releasing
// those pieces would hand OnResponseBodyChunk a fragment of a JSON document it
// cannot parse; holding them reassembles the document so the buffered
// translation can run on it.
func (p *TranslatorPolicy) NeedsMoreResponseData(accumulated []byte) bool {
	if len(accumulated) == 0 {
		return false
	}
	if looksLikeSSE(accumulated) {
		return false
	}
	return true
}

// OnResponseBodyChunk routes each flush by what the response turned out to be.
// An event stream is forwarded untouched — Mistral's SSE frames are already
// OpenAI chat.completion.chunk events, so translating them would only risk
// corrupting them. Anything else is a document that NeedsMoreResponseData has
// reassembled, and it goes through the same translation the buffered path uses.
func (p *TranslatorPolicy) OnResponseBodyChunk(
	_ context.Context,
	respCtx *policy.ResponseStreamContext,
	chunk *policy.StreamBody,
	_ map[string]interface{},
) policy.StreamingResponseAction {
	if !p.shouldRunForSelected(selectedProviderFromStream(respCtx)) {
		return policy.ForwardResponseChunk{}
	}
	if p.responseIsEventStream(respCtx, chunk) {
		return policy.ForwardResponseChunk{}
	}
	return p.translateBufferedFlush(respCtx, chunk)
}

// translateBufferedFlush translates a complete, non-event-stream response body
// that was delivered on the streaming path. NeedsMoreResponseData keeps the
// kernel accumulating such a body until the upstream closes, so the flush that
// reaches here is normally the whole document. The one exception is the kernel's
// stream accumulator cap, which forces a flush mid-body.
func (p *TranslatorPolicy) translateBufferedFlush(
	respCtx *policy.ResponseStreamContext, chunk *policy.StreamBody,
) policy.StreamingResponseAction {
	if !chunk.EndOfStream {
		// The accumulator cap fired. The document is cut mid-body, so there is
		// nothing correct to forward. The status line and the headers went out
		// before the first byte of body, so the body is the only place left to
		// report the failure — hence an error envelope rather than an empty
		// close, which would reach the client as a successful zero-length reply
		// that no OpenAI SDK can parse.
		slog.Warn(PolicyName+": response exceeded the policy engine's stream accumulator "+
			"limit before the upstream closed; the body is truncated and cannot be translated",
			"flush_bytes", len(chunk.Chunk), "status", respCtx.ResponseStatus)
		return policy.TerminateResponseChunk{
			Body: openAIErrorBody(
				"server_error",
				"The upstream response exceeded the gateway's response buffer before it "+
					"completed, so it could not be translated.",
				"response_too_large",
			),
			IsFault: true,
			Fault: &policy.FaultDetails{
				Code:        policy.FaultCodeMediationFailed,
				Type:        policy.FaultTypeMediation,
				Direction:   policy.DirectionResponse,
				Message:     "The upstream response could not be translated.",
				Description: "response exceeded the stream accumulator limit before the upstream closed",
			},
		}
	}
	if len(chunk.Chunk) == 0 {
		return policy.ForwardResponseChunk{}
	}

	slog.Debug(PolicyName+": translating a buffered response on the streaming path",
		"status", respCtx.ResponseStatus, "bytes", len(chunk.Chunk))
	return bufferedActionToChunk(translateResponse(chunk.Chunk, respCtx.ResponseStatus,
		effectiveModel(respCtx.SharedContext, p.params.Model)))
}

// bufferedActionToChunk adapts an action from the buffered translator to the
// streaming path, where the status and the headers are already committed and
// only the body can still change. A modification contributes its new body, a
// pass-through (nil body) leaves the provider bytes alone, and an immediate
// response can only be delivered as a final body before the stream closes.
func bufferedActionToChunk(action policy.ResponseAction) policy.StreamingResponseAction {
	switch a := action.(type) {
	case policy.DownstreamResponseModifications:
		if a.Body == nil {
			return policy.ForwardResponseChunk{}
		}
		return policy.ForwardResponseChunk{Body: a.Body}
	case policy.ImmediateResponse:
		// errResponse builds a flat {"error": "<message>"} body, which an OpenAI
		// client does not recognise as an error. The status it carries cannot be
		// applied here either, so re-render the message as the nested envelope
		// the client does understand before closing the stream.
		return policy.TerminateResponseChunk{
			Body: openAIErrorBody(
				mapStatusToOpenAIErrorType(a.StatusCode),
				messageFromErrResponse(a.Body),
				"response_translation_failed",
			),
			// The body is re-rendered, but the fault the buffered translator
			// declared describes the same failure — carry it across unchanged.
			IsFault: a.IsFault,
			Fault:   a.Fault,
		}
	}
	return policy.ForwardResponseChunk{}
}

// responseIsEventStream classifies the response once, on the first chunk, and
// reuses that verdict for every chunk after it.
//
// Classifying each flush on its own would be wrong: only the first chunk of an
// event stream is guaranteed to begin at a frame boundary, so a later one
// starting mid-frame would be misread as a document and sent to the buffered
// translator. The verdict is cached in the shared context, which is the same
// instance across every phase of a request.
func (p *TranslatorPolicy) responseIsEventStream(
	respCtx *policy.ResponseStreamContext, chunk *policy.StreamBody,
) bool {
	shared := respCtx.SharedContext
	if shared == nil {
		// Without a per-request store the verdict cannot survive between chunks.
		// Classify this flush on its own; a single-chunk response is still
		// handled correctly, and a multi-chunk one degrades to passthrough
		// rather than to a mis-parse.
		return classifyEventStream(respCtx.ResponseHeaders, chunk.Chunk)
	}
	if shared.Metadata == nil {
		shared.Metadata = map[string]interface{}{}
	}
	if cached, ok := shared.Metadata[MetadataKeyResponseIsEventStream].(bool); ok {
		return cached
	}
	verdict := classifyEventStream(respCtx.ResponseHeaders, chunk.Chunk)
	shared.Metadata[MetadataKeyResponseIsEventStream] = verdict
	return verdict
}

// classifyEventStream decides whether the response is an event stream, trusting
// the declared content-type ahead of the bytes.
//
// Both mistakes are survivable here, which is why the byte sniff is kept as a
// fallback rather than dropped: a stream misread as a document is reassembled
// and passed through unchanged by the buffered translator (buffered, but
// intact), while a document misread as a stream is forwarded unchanged (which
// for Mistral's already-OpenAI-shaped success bodies differs only in the model
// backfill). Preferring the header keeps a chunked JSON error — the case this
// whole path exists for — out of the stream branch.
func classifyEventStream(headers *policy.Headers, firstChunk []byte) bool {
	contentType := strings.ToLower(headerValue(headers, "content-type"))
	switch {
	case strings.Contains(contentType, "text/event-stream"):
		return true
	case strings.Contains(contentType, "application/json"):
		return false
	}
	return looksLikeSSE(firstChunk)
}

// selectedProviderFromStream reads the routed provider from the streaming
// response context. SharedContext is embedded by pointer, so it is read through
// an explicit nil check rather than the promoted field, which would panic.
func selectedProviderFromStream(respCtx *policy.ResponseStreamContext) string {
	if respCtx == nil || respCtx.SharedContext == nil {
		return ""
	}
	return selectedProviderFromMetadata(respCtx.SharedContext, respCtx.SharedContext.Metadata)
}

func headerValue(headers *policy.Headers, name string) string {
	if headers == nil {
		return ""
	}
	values := headers.Get(name)
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

// messageFromErrResponse pulls the message out of the flat {"error": "..."}
// envelope errResponse builds, so it can be re-rendered in OpenAI shape.
func messageFromErrResponse(body []byte) string {
	var flat struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(body, &flat); err == nil && flat.Error != "" {
		return flat.Error
	}
	return "The upstream response could not be translated."
}
