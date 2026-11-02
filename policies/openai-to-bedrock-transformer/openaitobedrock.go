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

// Package openaitobedrock translates OpenAI Chat Completions traffic to and
// from the AWS Bedrock Converse API. Requests are rewritten to the Converse
// wire format (path + body); responses are rewritten back to OpenAI shape.
// Bedrock streams responses with the binary Amazon event-stream framing, which
// this policy decodes and re-emits as OpenAI-style Server-Sent Events.
package openaitobedrock

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"math"
	"net/url"
	"strings"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

const (
	PolicyName                  = "openai-to-bedrock-transformer"
	MetadataKeySelectedProvider = "selected_provider"
	MetadataKeyEffectiveModel   = "openai_to_bedrock_effective_model"
)

// Compile-time proof that this policy participates in every phase it declares
// in Mode(), including chunk-by-chunk response streaming.
var (
	_ policy.Policy                  = (*TranslatorPolicy)(nil)
	_ policy.RequestPolicy           = (*TranslatorPolicy)(nil)
	_ policy.ResponseHeaderPolicy    = (*TranslatorPolicy)(nil)
	_ policy.ResponsePolicy          = (*TranslatorPolicy)(nil)
	_ policy.StreamingResponsePolicy = (*TranslatorPolicy)(nil)
)

type PolicyParams struct {
	Model      string
	ProviderID string
}

type TranslatorPolicy struct {
	params PolicyParams
}

// GetPolicy is the exported factory the gateway calls to instantiate the policy.
func GetPolicy(_ policy.PolicyMetadata, rawParams map[string]interface{}) (policy.Policy, error) {
	parsed, err := parseParams(rawParams)
	if err != nil {
		return nil, fmt.Errorf("%s: invalid params: %w", PolicyName, err)
	}
	return &TranslatorPolicy{params: parsed}, nil
}

// Mode buffers the (small) request body for translation, processes response
// headers so streaming content-type can be corrected, and asks for STREAM mode
// on the response body so Bedrock's event stream can be decoded chunk-by-chunk.
// The kernel falls back to the buffered OnResponseBody path automatically when
// the upstream response is not a stream.
func (p *TranslatorPolicy) Mode() policy.ProcessingMode {
	return policy.ProcessingMode{
		RequestHeaderMode:  policy.HeaderModeSkip,
		RequestBodyMode:    policy.BodyModeBuffer,
		ResponseHeaderMode: policy.HeaderModeProcess,
		ResponseBodyMode:   policy.BodyModeStream,
	}
}

// ─── Request phase ────────────────────────────────────────────────────────────

func (p *TranslatorPolicy) OnRequestBody(
	_ context.Context,
	reqCtx *policy.RequestContext,
	_ map[string]interface{},
) policy.RequestAction {
	if !p.shouldRun(selectedProvider(reqCtx.SharedContext)) {
		return policy.UpstreamRequestModifications{}
	}

	if reqCtx.Body == nil || !reqCtx.Body.Present || len(reqCtx.Body.Content) == 0 {
		return errResponse(400, "Request body is empty.",
			policy.FaultCodeInvalidRequestBody, policy.DirectionRequest, policy.FaultTypeValidation)
	}

	var payload map[string]interface{}
	if err := json.Unmarshal(reqCtx.Body.Content, &payload); err != nil {
		return errResponse(400, fmt.Sprintf("Invalid JSON in request body: %s", err.Error()),
			policy.FaultCodeInvalidRequestBody, policy.DirectionRequest, policy.FaultTypeValidation)
	}

	model, err := p.resolveModel(payload)
	if err != nil {
		return errResponse(400, err.Error(),
			policy.FaultCodeInvalidRequestBody, policy.DirectionRequest, policy.FaultTypeValidation)
	}
	storeEffectiveModel(reqCtx.SharedContext, model)

	streaming := boolValue(payload["stream"])
	path := bedrockConversePath(model, streaming)
	slog.Debug(PolicyName+": translating request",
		"providerId", p.params.ProviderID, "model", model, "streaming", streaming, "path", path)

	mods, err := translateRequest(payload)
	if err != nil {
		return errResponse(400, err.Error(),
			policy.FaultCodeInvalidRequestBody, policy.DirectionRequest, policy.FaultTypeValidation)
	}
	mods.Path = &path
	if p.params.ProviderID != "" && mods.UpstreamName == nil {
		upstream := p.params.ProviderID
		mods.UpstreamName = &upstream
	}
	return mods
}

// bedrockConversePath builds the Converse endpoint path. The model id carries
// the model selection (the awsbedrock provider template extracts it from the
// path), so it is never placed in the body.
func bedrockConversePath(model string, streaming bool) string {
	// The model is reachable from the request payload, so it is escaped before
	// it enters the path: a value carrying "/" or "?" must not be able to add a
	// segment or a query of its own. Bedrock model ids ("us.amazon.nova-lite-v1:0")
	// contain nothing PathEscape touches, so their paths are unchanged.
	escaped := url.PathEscape(model)
	if streaming {
		return "/model/" + escaped + "/converse-stream"
	}
	return "/model/" + escaped + "/converse"
}

// ─── Response phase ───────────────────────────────────────────────────────────

// OnResponseHeaders rewrites the upstream content-type for translated event
// streams (application/vnd.amazon.eventstream) to text/event-stream so
// downstream OpenAI clients recognise the Server-Sent Events we emit. JSON
// responses are left untouched.
func (p *TranslatorPolicy) OnResponseHeaders(
	_ context.Context,
	respCtx *policy.ResponseHeaderContext,
	_ map[string]interface{},
) policy.ResponseHeaderAction {
	if !p.shouldRun(selectedProvider(respCtx.SharedContext)) {
		return policy.DownstreamResponseHeaderModifications{}
	}
	if !isEventStreamContentType(headerValue(respCtx.ResponseHeaders, "content-type")) {
		return policy.DownstreamResponseHeaderModifications{}
	}
	return policy.DownstreamResponseHeaderModifications{
		HeadersToSet:    map[string]string{"content-type": "text/event-stream"},
		HeadersToRemove: []string{"content-length"},
	}
}

// OnResponseBody is the buffered fallback used when the upstream response is not
// detected as a stream (no chunked / text-event-stream headers). It handles both
// a Converse JSON response and a fully buffered Amazon event stream.
func (p *TranslatorPolicy) OnResponseBody(
	_ context.Context,
	respCtx *policy.ResponseContext,
	_ map[string]interface{},
) policy.ResponseAction {
	if !p.shouldRun(selectedProvider(respCtx.SharedContext)) {
		return policy.DownstreamResponseModifications{}
	}
	if respCtx.ResponseBody == nil || !respCtx.ResponseBody.Present || len(respCtx.ResponseBody.Content) == 0 {
		return policy.DownstreamResponseModifications{}
	}

	body := respCtx.ResponseBody.Content
	contentType := headerValue(respCtx.ResponseHeaders, "content-type")
	model := effectiveModel(respCtx.SharedContext, p.params.Model)

	if isEventStreamContentType(contentType) || looksLikeEventStream(body) {
		sse := eventStreamToSSE(body, true, p.completionID(requestID(respCtx.SharedContext)), model)
		mods := policy.DownstreamResponseModifications{
			Body: sse,
			HeadersToSet: map[string]string{
				"content-type": "text/event-stream",
			},
			HeadersToRemove: []string{"content-length"},
		}
		if exceptionType, failed := streamException(body); failed {
			mods.IsFault = true
			mods.Fault = streamExceptionFault(exceptionType)
		}
		return mods
	}

	slog.Debug(PolicyName+": translating buffered JSON response", "status", respCtx.ResponseStatus)
	return translateConverseResponse(body, respCtx.ResponseStatus, model,
		p.completionID(requestID(respCtx.SharedContext)))
}

// ─── Streaming response phase ─────────────────────────────────────────────────

// NeedsMoreResponseData tells the kernel when to keep accumulating instead of
// delivering what it has.
//
// For an event stream it holds until the buffer ends on a clean frame boundary.
// That guarantees OnResponseBodyChunk always receives a whole number of complete
// frames and never a split one, so no cross-chunk carry buffer (which would be
// unsafe on a shared policy instance) is required.
//
// For a body that is not event-stream framed it holds until the upstream closes.
// The gateway routes a response through this path whenever the upstream framing
// is chunked, and an ordinary Converse JSON reply is framed that way whenever the
// provider omits content-length — so a complete, non-streamed document arrives
// here in pieces. Releasing those pieces would hand OnResponseBodyChunk a
// fragment of a JSON document it cannot parse; holding them reassembles the
// document so the buffered translation can run on it.
func (p *TranslatorPolicy) NeedsMoreResponseData(accumulated []byte) bool {
	if len(accumulated) == 0 {
		return false
	}
	_, hasPartial, ok := eventStreamBoundary(accumulated)
	if !ok {
		// Not event-stream framing — accumulate the whole body and translate it
		// once, rather than emit fragments of a document that is not a stream.
		return true
	}
	return hasPartial
}

// OnResponseBodyChunk decodes the complete frames delivered in this flush and
// re-emits them as OpenAI SSE events, replacing the raw binary bytes. On the
// final chunk it appends the terminating `data: [DONE]` event.
func (p *TranslatorPolicy) OnResponseBodyChunk(
	_ context.Context,
	respCtx *policy.ResponseStreamContext,
	chunk *policy.StreamBody,
	_ map[string]interface{},
) policy.StreamingResponseAction {
	if !p.shouldRun(selectedProvider(respCtx.SharedContext)) {
		return policy.ForwardResponseChunk{}
	}

	if !isEventStreamFlush(respCtx, chunk) {
		// A Converse JSON body, not a ConverseStream event stream.
		// NeedsMoreResponseData holds such a body until the upstream closes, so
		// this flush carries the complete document.
		return p.translateBufferedFlush(respCtx, chunk)
	}

	model := effectiveModel(respCtx.SharedContext, p.params.Model)
	sse := eventStreamToSSE(chunk.Chunk, chunk.EndOfStream,
		p.completionID(requestID(respCtx.SharedContext)), model)
	// Always return a non-nil body so the raw Amazon event-stream bytes are
	// replaced (nil would pass them through untranslated). An empty slice emits
	// nothing for this flush, which is correct when a frame carried no delta.
	if sse == nil {
		sse = []byte{}
	}
	return policy.ForwardResponseChunk{Body: sse}
}

// isEventStreamFlush reports whether this flush belongs to an Amazon event
// stream rather than a buffered Converse JSON body. The content-type decides it
// when the upstream sets one; otherwise the bytes are sniffed. An empty flush
// counts as event-stream framing, because that is how the upstream's close
// arrives and it still has to emit the terminating [DONE].
func isEventStreamFlush(
	respCtx *policy.ResponseStreamContext, chunk *policy.StreamBody,
) bool {
	if isEventStreamContentType(headerValue(respCtx.ResponseHeaders, "content-type")) {
		return true
	}
	if len(chunk.Chunk) == 0 {
		return true
	}
	return looksLikeEventStream(chunk.Chunk)
}

// translateBufferedFlush translates a complete, non-event-stream response body
// that was delivered on the streaming path. NeedsMoreResponseData keeps the
// kernel accumulating such a body until the upstream closes, so the flush that
// reaches here is the whole document. The one exception is the kernel's stream
// accumulator cap, which forces a flush mid-body and can only hand over a
// truncated document.
func (p *TranslatorPolicy) translateBufferedFlush(
	respCtx *policy.ResponseStreamContext, chunk *policy.StreamBody,
) policy.StreamingResponseAction {
	if !chunk.EndOfStream {
		// The accumulator cap fired. The document is cut mid-body, so there is
		// nothing correct to emit — close the stream rather than forward a
		// fragment the client cannot parse. The status and the headers went out
		// long ago, so this is the only way left to report the failure.
		slog.Warn(PolicyName+": response exceeded the policy engine's stream accumulator "+
			"limit before the upstream closed; the body is truncated and cannot be translated",
			"flush_bytes", len(chunk.Chunk), "status", respCtx.ResponseStatus)
		// Body is an explicitly empty slice, not nil: the chain executor only
		// replaces the bytes it is carrying when an action supplies a non-nil
		// body, so a nil here would deliver the truncated document to the client
		// instead of suppressing it.
		//
		// The policy SDK pinned here (sdk/core v0.2.14) has no IsFault on this
		// action, so the close cannot be declared a failure to the fault flow;
		// the warning above is the record of it.
		return policy.TerminateResponseChunk{Body: []byte{}}
	}
	if len(chunk.Chunk) == 0 {
		return policy.ForwardResponseChunk{}
	}

	slog.Debug(PolicyName+": translating a buffered response on the streaming path",
		"status", respCtx.ResponseStatus, "bytes", len(chunk.Chunk))
	return bufferedActionToChunk(translateConverseResponse(chunk.Chunk, respCtx.ResponseStatus,
		effectiveModel(respCtx.SharedContext, p.params.Model),
		p.completionID(requestID(respCtx.SharedContext))))
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
		return policy.TerminateResponseChunk{Body: a.Body}
	}
	return policy.ForwardResponseChunk{}
}

// ─── Routing / selection ──────────────────────────────────────────────────────

func (p *TranslatorPolicy) shouldRun(selected string) bool {
	if selected == "" {
		// Single-provider mode: no router selected a provider, so run.
		return true
	}
	return strings.EqualFold(selected, p.params.ProviderID)
}

func selectedProvider(shared *policy.SharedContext) string {
	if shared == nil || shared.Metadata == nil {
		return ""
	}
	raw, ok := shared.Metadata[MetadataKeySelectedProvider]
	if !ok {
		return ""
	}
	value, isString := raw.(string)
	if !isString {
		return ""
	}
	return strings.TrimSpace(value)
}

// resolveModel returns the model that will serve this request. The model named
// in the request payload takes priority; the configured model is a fallback,
// used only when the payload names none. A payload model that is absent, null
// or an empty string counts as none; a whitespace-only one is malformed and is
// rejected even when a fallback exists.
func (p *TranslatorPolicy) resolveModel(payload map[string]interface{}) (string, error) {
	if raw, present := payload["model"]; present && raw != nil {
		model, isString := raw.(string)
		if !isString {
			return "", fmt.Errorf("request field 'model' must be a string")
		}
		if trimmed := strings.TrimSpace(model); trimmed != "" {
			return trimmed, nil
		} else if model != "" {
			return "", fmt.Errorf("request field 'model' must not be blank")
		}
	}

	if p.params.Model != "" {
		return p.params.Model, nil
	}
	return "", fmt.Errorf("a Bedrock model must be provided in either the policy configuration or request body")
}

func storeEffectiveModel(shared *policy.SharedContext, model string) {
	// A nil shared context is not reachable through the policy engine, which
	// gives every phase the same instance — the provider selection this policy
	// already reads in shouldRun travels the same way, as does multi-provider
	// routing generally. The guard is defensive only. Were it ever nil, the sole
	// consequence here is that a response omitting "model" is passed through
	// without the backfill; the request itself is still served with the model the
	// client asked for. Rejecting such a request instead would defeat the point
	// of resolving the model from the payload in the first place.
	if shared == nil {
		return
	}
	if shared.Metadata == nil {
		shared.Metadata = map[string]interface{}{}
	}
	shared.Metadata[MetadataKeyEffectiveModel] = model
}

func effectiveModel(shared *policy.SharedContext, configured string) string {
	if shared != nil && shared.Metadata != nil {
		if model, ok := shared.Metadata[MetadataKeyEffectiveModel].(string); ok && model != "" {
			return model
		}
	}
	return configured
}

func requestID(shared *policy.SharedContext) string {
	if shared == nil {
		return ""
	}
	return shared.RequestID
}

// completionID derives a stable OpenAI completion id from the per-request id so
// every SSE chunk of one response shares it, without holding per-request state
// on the shared policy instance. Falls back to a random id when unavailable.
func (p *TranslatorPolicy) completionID(requestID string) string {
	if requestID != "" {
		return "chatcmpl-" + strings.ReplaceAll(requestID, "-", "")
	}
	return newChatCompletionID()
}

// ─── Param parsing ────────────────────────────────────────────────────────────

func parseParams(params map[string]interface{}) (PolicyParams, error) {
	result := PolicyParams{}

	model, err := optionalString(params, "model")
	if err != nil {
		return result, err
	}
	result.Model = model

	if providerID, err := optionalString(params, "providerId"); err != nil {
		return result, err
	} else {
		result.ProviderID = providerID
	}

	return result, nil
}

func optionalString(params map[string]interface{}, key string) (string, error) {
	raw, ok := params[key]
	if !ok || raw == nil {
		return "", nil
	}
	value, isString := raw.(string)
	if !isString {
		return "", fmt.Errorf("'%s' must be a string", key)
	}
	return strings.TrimSpace(value), nil
}

func toInt(v interface{}) (int, bool) {
	switch n := v.(type) {
	case int:
		return n, true
	case int64:
		return int(n), true
	case float64:
		if math.IsNaN(n) || math.IsInf(n, 0) || n != math.Trunc(n) {
			return 0, false
		}
		return int(n), true
	case json.Number:
		if i, err := n.Int64(); err == nil {
			return int(i), true
		}
	}
	return 0, false
}

func boolValue(v interface{}) bool {
	b, ok := v.(bool)
	return ok && b
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

func isEventStreamContentType(contentType string) bool {
	ct := strings.ToLower(contentType)
	return strings.Contains(ct, "vnd.amazon.eventstream") || strings.Contains(ct, "application/octet-stream")
}

// looksLikeEventStream sniffs a buffered body for Amazon event-stream framing:
// binary (not starting with a JSON delimiter) whose leading 4 bytes advertise a
// plausible frame length.
func looksLikeEventStream(body []byte) bool {
	if len(body) < preludeWithCRCLen {
		return false
	}
	trimmed := strings.TrimLeft(string(body[:1]), " \r\n\t")
	if strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[") {
		return false
	}
	_, _, ok := eventStreamBoundary(body)
	return ok
}

// errResponse refuses the exchange and describes why.
//
// direction states which side was refused: DirectionRequest when the caller's payload could
// not be read or converted, DirectionResponse when the provider's could not be translated
// back. Those are operationally different events that share nothing but this function, and
// only the caller knows which it is — which is why it is a parameter rather than inferred
// from the status.
func errResponse(statusCode int, message, code, direction, errorType string) policy.ImmediateResponse {
	body, _ := json.Marshal(map[string]interface{}{
		"error": map[string]string{"message": message, "type": "invalid_request_error"},
	})
	return policy.ImmediateResponse{
		StatusCode: statusCode,
		Headers:    map[string]string{"Content-Type": "application/json"},
		Body:       body,
		IsFault:    true,
		Fault: &policy.FaultDetails{
			Code:      code,
			Type:      errorType,
			Direction: direction,
			// message already goes to the client as the body's error text.
			Message: message,
		},
	}
}
