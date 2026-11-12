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
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

const (
	objectChatCompletionChunk = "chat.completion.chunk"
	sseDonePayload            = "data: [DONE]\n\n"

	// streamStateMetadataKey namespaces this policy's per-request streaming
	// state inside the shared metadata map.
	streamStateMetadataKey = "openai_to_anthropic_stream_state"
)

// ─── Per-request streaming state ──────────────────────────────────────────────

// streamState carries everything one translated Anthropic stream needs between
// chunk callbacks: the residual bytes of a partially delivered SSE frame, the
// response identity that must stay stable across every emitted chunk, and the
// flags that keep role / finish_reason / usage / [DONE] emitted exactly once.
//
// It lives in SharedContext.Metadata — which is per request — rather than on
// TranslatorPolicy, which the kernel shares across concurrent requests.
type streamState struct {
	id      string
	model   string
	created int64
	status  int

	// residual holds the tail of the last flush that did not yet form a complete
	// SSE frame. It is prepended to the next chunk.
	residual []byte

	// failure records why translation terminated the stream, so the caller can describe
	// the fault: the provider reporting an error, or a frame this translator could not read.
	failure streamFailure

	roleSent   bool
	finishSent bool
	usageSent  bool
	doneSent   bool

	// toolIndexByBlock maps an Anthropic content-block index to a contiguous
	// zero-based OpenAI tool_calls index. Anthropic numbers every content block
	// (text blocks included); OpenAI numbers only the tool calls.
	toolIndexByBlock map[int]int
	nextToolIndex    int

	usage    anthropicUsage
	hasUsage bool
}

func newStreamState(model, requestID string, status int) *streamState {
	return &streamState{
		id:               completionIDFromRequest(requestID),
		model:            model,
		created:          time.Now().Unix(),
		status:           status,
		toolIndexByBlock: map[int]int{},
	}
}

// completionIDFromRequest derives a stable OpenAI completion id from the
// per-request id so every chunk of one response shares it even before
// message_start arrives (Anthropic's own message id replaces it once it does).
func completionIDFromRequest(requestID string) string {
	if requestID != "" {
		return "chatcmpl-" + strings.ReplaceAll(requestID, "-", "")
	}
	return newChatCompletionID()
}

// ─── SSE framing ──────────────────────────────────────────────────────────────

// endsOnSSEBoundary reports whether data ends exactly on an SSE event terminator
// (a blank line), meaning it holds no partially delivered frame.
func endsOnSSEBoundary(data []byte) bool {
	return bytes.HasSuffix(data, []byte("\n\n")) || bytes.HasSuffix(data, []byte("\r\n\r\n"))
}

// splitSSEEvents splits data into complete SSE frames and returns the trailing
// bytes that do not yet form one. Both LF and CRLF terminators are accepted. A
// blank line can never occur inside a frame's JSON payload (JSON strings escape
// newlines), so this split is unambiguous.
func splitSSEEvents(data []byte) ([][]byte, []byte) {
	var frames [][]byte
	start, i := 0, 0
	for i < len(data) {
		if data[i] != '\n' {
			i++
			continue
		}
		switch {
		case i+1 < len(data) && data[i+1] == '\n':
			frames = append(frames, data[start:i])
			i += 2
		case i+2 < len(data) && data[i+1] == '\r' && data[i+2] == '\n':
			frames = append(frames, data[start:i])
			i += 3
		default:
			i++
			continue
		}
		start = i
	}
	return frames, data[start:]
}

// sseDataPayload concatenates the `data:` lines of one SSE frame per the SSE
// spec. Comments (`:`) and the `event:` / `id:` fields are ignored — Anthropic
// repeats the event name in the JSON payload's "type" field.
func sseDataPayload(frame []byte) string {
	var payload strings.Builder
	for _, line := range strings.Split(string(frame), "\n") {
		line = strings.TrimSuffix(line, "\r")
		if !strings.HasPrefix(line, "data:") {
			continue
		}
		value := strings.TrimPrefix(strings.TrimPrefix(line, "data:"), " ")
		if payload.Len() > 0 {
			payload.WriteByte('\n')
		}
		payload.WriteString(value)
	}
	return payload.String()
}

// ─── Anthropic stream events ──────────────────────────────────────────────────

// anthropicStreamEvent is the union of the Anthropic Messages streaming events
// this policy understands. Fields absent from a given event stay zero-valued.
type anthropicStreamEvent struct {
	Type    string `json:"type"`
	Index   int    `json:"index"`
	Message *struct {
		ID    string         `json:"id"`
		Model string         `json:"model"`
		Usage anthropicUsage `json:"usage"`
	} `json:"message"`
	ContentBlock *anthropicContentBlock `json:"content_block"`
	Delta        *struct {
		Type        string `json:"type"`
		Text        string `json:"text"`
		PartialJSON string `json:"partial_json"`
		StopReason  string `json:"stop_reason"`
	} `json:"delta"`
	Usage *anthropicUsage `json:"usage"`
	Error struct {
		Type    string `json:"type"`
		Message string `json:"message"`
	} `json:"error"`
}

// streamFailure is why a translated stream was terminated.
type streamFailure int

const (
	streamNoFailure streamFailure = iota
	// streamProviderError is the provider sending an error mid-stream.
	streamProviderError
	// streamMalformedFrame is a provider frame this translator could not parse.
	streamMalformedFrame
)

// translateSSEChunk converts the Anthropic SSE bytes delivered in one callback
// into OpenAI chat.completion.chunk events. Bytes forming only a partial
// trailing frame are held in state until that frame completes, so this is safe
// for arbitrary transport splits. terminate is true when a provider error or an
// unreadable frame ended the stream.
func translateSSEChunk(state *streamState, data []byte, endOfStream bool) (out []byte, terminate bool) {
	buffered := data
	if len(state.residual) > 0 {
		buffered = append(state.residual, data...)
	}

	frames, residual := splitSSEEvents(buffered)
	state.residual = append([]byte(nil), residual...)

	for _, frame := range frames {
		rendered, stop := state.translateFrame(frame)
		out = append(out, rendered...)
		if stop {
			state.residual = nil
			return out, true
		}
	}

	if endOfStream {
		// A trailing frame that never completed means the upstream stream was cut
		// short. It cannot be rendered as valid OpenAI JSON, so it is dropped
		// rather than emitted partially.
		if len(state.residual) > 0 {
			slog.Debug(PolicyName+": discarding truncated trailing SSE frame",
				"bytes", len(state.residual))
			state.residual = nil
		}
		out = append(out, state.finalize()...)
	}
	return out, false
}

// translateFrame maps one Anthropic SSE frame onto zero or more OpenAI SSE
// events. The bool result requests stream termination.
func (s *streamState) translateFrame(frame []byte) ([]byte, bool) {
	payload := sseDataPayload(frame)
	if strings.TrimSpace(payload) == "" {
		// Comment or heartbeat frame — nothing to translate.
		return nil, false
	}

	var event anthropicStreamEvent
	if err := json.Unmarshal([]byte(payload), &event); err != nil {
		// Never forward provider bytes we could not parse as if they were OpenAI
		// chunks; surface a typed error and stop the stream instead.
		slog.Warn(PolicyName+": malformed Anthropic stream event", "error", err)
		s.failure = streamMalformedFrame
		return s.errorEvent("", "malformed Anthropic stream event: "+err.Error()), true
	}

	switch event.Type {
	case "message_start":
		return s.onMessageStart(&event), false
	case "content_block_start":
		return s.onContentBlockStart(&event), false
	case "content_block_delta":
		return s.onContentBlockDelta(&event), false
	case "message_delta":
		return s.onMessageDelta(&event), false
	case "message_stop":
		return s.finalize(), false
	case "error":
		s.failure = streamProviderError
		return s.errorEvent(event.Error.Type, event.Error.Message), true
	}

	// ping, content_block_stop and any event Anthropic adds later have no OpenAI
	// Chat Completions streaming equivalent — see the policy README.
	return nil, false
}

func (s *streamState) onMessageStart(event *anthropicStreamEvent) []byte {
	if event.Message != nil {
		if event.Message.ID != "" {
			// Rewrite Anthropic's "msg_*" id to "chatcmpl-*" so prefix-aware
			// clients still match, mirroring the non-streaming translation.
			s.id = "chatcmpl-" + strings.TrimPrefix(event.Message.ID, "msg_")
		}
		if event.Message.Model != "" {
			s.model = event.Message.Model
		}
		s.mergeUsage(event.Message.Usage)
	}
	if s.roleSent {
		return nil
	}
	s.roleSent = true
	return sseData(s.deltaChunk(map[string]interface{}{"role": "assistant"}, nil))
}

func (s *streamState) onContentBlockStart(event *anthropicStreamEvent) []byte {
	block := event.ContentBlock
	if block == nil || block.Type != "tool_use" {
		return nil
	}
	return sseData(s.deltaChunk(map[string]interface{}{
		"tool_calls": []interface{}{map[string]interface{}{
			"index": s.toolIndexFor(event.Index),
			"id":    block.ID,
			"type":  "function",
			"function": map[string]interface{}{
				"name":      block.Name,
				"arguments": "",
			},
		}},
	}, nil))
}

func (s *streamState) onContentBlockDelta(event *anthropicStreamEvent) []byte {
	if event.Delta == nil {
		return nil
	}
	switch event.Delta.Type {
	case "text_delta":
		if event.Delta.Text == "" {
			return nil
		}
		return sseData(s.deltaChunk(map[string]interface{}{"content": event.Delta.Text}, nil))
	case "input_json_delta":
		return sseData(s.deltaChunk(map[string]interface{}{
			"tool_calls": []interface{}{map[string]interface{}{
				"index":    s.toolIndexFor(event.Index),
				"function": map[string]interface{}{"arguments": event.Delta.PartialJSON},
			}},
		}, nil))
	}
	// thinking_delta and signature_delta carry extended-thinking content, which
	// OpenAI Chat Completions chunks cannot represent — see the policy README.
	return nil
}

func (s *streamState) onMessageDelta(event *anthropicStreamEvent) []byte {
	if event.Usage != nil {
		s.mergeUsage(*event.Usage)
	}
	if event.Delta == nil || event.Delta.StopReason == "" || s.finishSent {
		return nil
	}
	s.finishSent = true
	return sseData(s.deltaChunk(map[string]interface{}{},
		stopReasonToFinish(event.Delta.StopReason, false)))
}

// finalize emits what the provider never sent before the stream ended: the usage
// chunk (when usage was reported) and exactly one terminating [DONE].
func (s *streamState) finalize() []byte {
	var out []byte
	if !s.usageSent && s.hasUsage {
		s.usageSent = true
		chunk := s.baseChunk()
		chunk["choices"] = []interface{}{}
		chunk["usage"] = streamUsage(s.usage)
		out = append(out, sseData(chunk)...)
	}
	if !s.doneSent {
		s.doneSent = true
		out = append(out, sseDonePayload...)
	}
	return out
}

// toolIndexFor maps an Anthropic content-block index onto a contiguous OpenAI
// tool_calls index, allocating on first sight so text blocks never consume a
// tool-call index. The mapping is stable for the life of the stream.
func (s *streamState) toolIndexFor(blockIndex int) int {
	if s.toolIndexByBlock == nil {
		s.toolIndexByBlock = map[int]int{}
	}
	if index, seen := s.toolIndexByBlock[blockIndex]; seen {
		return index
	}
	index := s.nextToolIndex
	s.toolIndexByBlock[blockIndex] = index
	s.nextToolIndex++
	return index
}

// mergeUsage folds the usage Anthropic splits across message_start (input and
// cache tokens) and message_delta (final cumulative output tokens) into one
// total. Zero fields never overwrite a value already seen.
func (s *streamState) mergeUsage(usage anthropicUsage) {
	if usage.InputTokens > 0 {
		s.usage.InputTokens = usage.InputTokens
	}
	if usage.OutputTokens > 0 {
		s.usage.OutputTokens = usage.OutputTokens
	}
	if usage.CacheReadInputTokens > 0 {
		s.usage.CacheReadInputTokens = usage.CacheReadInputTokens
	}
	if usage.CacheCreationInputTokens > 0 {
		s.usage.CacheCreationInputTokens = usage.CacheCreationInputTokens
	}
	s.hasUsage = true
}

// streamUsage mirrors the non-streaming usage translation so a client sees the
// same fields whether or not it streamed.
func streamUsage(usage anthropicUsage) map[string]interface{} {
	result := map[string]interface{}{
		"prompt_tokens":     usage.InputTokens,
		"completion_tokens": usage.OutputTokens,
		"total_tokens":      usage.InputTokens + usage.OutputTokens,
	}
	if usage.CacheReadInputTokens > 0 || usage.CacheCreationInputTokens > 0 {
		result["prompt_tokens_details"] = map[string]interface{}{
			"cached_tokens":         usage.CacheReadInputTokens,
			"cache_creation_tokens": usage.CacheCreationInputTokens,
		}
	}
	return result
}

// ─── OpenAI chunk rendering ───────────────────────────────────────────────────

func (s *streamState) baseChunk() map[string]interface{} {
	return map[string]interface{}{
		"id":      s.id,
		"object":  objectChatCompletionChunk,
		"created": s.created,
		"model":   s.model,
	}
}

func (s *streamState) deltaChunk(delta map[string]interface{}, finishReason interface{}) map[string]interface{} {
	chunk := s.baseChunk()
	chunk["choices"] = []interface{}{map[string]interface{}{
		"index":         0,
		"delta":         delta,
		"finish_reason": finishReason,
	}}
	return chunk
}

// errorEvent renders an OpenAI-style error object as one SSE event, preserving
// the upstream status when the response itself failed. A stream ending this way
// gets no [DONE]: it is not a successful completion.
func (s *streamState) errorEvent(errType, message string) []byte {
	if errType == "" {
		errType = mapStatusToOpenAIErrorType(s.status)
	}
	if message == "" {
		message = "anthropic stream error"
	}
	errorBody := map[string]interface{}{"type": errType, "message": message}
	if s.status >= 400 {
		errorBody["code"] = fmt.Sprintf("%d", s.status)
	}
	return sseData(map[string]interface{}{"error": errorBody})
}

// sseData renders one OpenAI SSE event: `data: <json>\n\n`.
func sseData(payload map[string]interface{}) []byte {
	encoded, err := json.Marshal(payload)
	if err != nil {
		return nil
	}
	out := make([]byte, 0, len(encoded)+8)
	out = append(out, "data: "...)
	out = append(out, encoded...)
	out = append(out, "\n\n"...)
	return out
}

// ─── Context helpers ──────────────────────────────────────────────────────────

// streamStateFor returns the per-request translation state, creating it the
// first time a response is seen. It returns nil when the response is not an
// Anthropic event stream, in which case the chunk must be forwarded untouched.
// The stream/non-stream decision is taken once — from the response content-type,
// or by sniffing the first chunk when headers are not visible — and afterwards
// implied by the presence of the state, so later chunks cannot be reclassified.
func (p *TranslatorPolicy) streamStateFor(
	respCtx *policy.ResponseStreamContext, chunk *policy.StreamBody,
) *streamState {
	shared := respCtx.SharedContext
	if shared == nil {
		// Without a per-request store the residual buffer and the once-only
		// role / finish_reason / usage / [DONE] flags cannot survive between
		// chunks, so a multi-chunk stream would be translated into duplicated
		// and truncated events. Forwarding the provider bytes unchanged is the
		// safer degradation.
		return nil
	}
	if shared.Metadata == nil {
		shared.Metadata = map[string]interface{}{}
	}
	if existing, ok := shared.Metadata[streamStateMetadataKey].(*streamState); ok {
		return existing
	}

	if !isSSEResponse(headerValue(respCtx.ResponseHeaders, "content-type"), chunk.Chunk) {
		return nil
	}

	state := newStreamState(effectiveModel(shared, p.params.Model), requestID(shared), respCtx.ResponseStatus)
	shared.Metadata[streamStateMetadataKey] = state
	return state
}

// isSSEResponse reports whether a response body is Server-Sent Events, trusting
// the content-type when present and otherwise sniffing the leading bytes.
func isSSEResponse(contentType string, body []byte) bool {
	if isSSEContentType(contentType) {
		return true
	}
	return contentType == "" && looksLikeSSE(body)
}

func isSSEContentType(contentType string) bool {
	return strings.Contains(strings.ToLower(contentType), "text/event-stream")
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

func requestID(shared *policy.SharedContext) string {
	if shared == nil {
		return ""
	}
	return shared.RequestID
}
