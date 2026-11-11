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
	streamStateMetadataKey = "openai_to_gemini_stream_state"
)

// ─── Per-request streaming state ──────────────────────────────────────────────

// streamState carries everything one translated Gemini stream needs between
// chunk callbacks: the residual bytes of a partially delivered SSE frame, the
// response identity that must stay stable across every emitted chunk, and the
// per-candidate bookkeeping that keeps role, finish_reason, usage and [DONE]
// emitted exactly once.
//
// It lives in SharedContext.Metadata — which is per request — rather than on
// TranslatorPolicy, which the kernel shares across concurrent requests.
type streamState struct {
	id             string
	idFromProvider bool
	model          string
	created        int64
	status         int

	// residual holds the tail of the last flush that did not yet form a complete
	// SSE frame. It is prepended to the next chunk.
	residual []byte

	// failure records why translation terminated the stream, so the caller can describe
	// the fault: the provider reporting an error, or a frame this translator could not read.
	failure streamFailure

	// choices is keyed by OpenAI choice index (Gemini's candidate index).
	choices map[int]*choiceState

	usage     *geminiUsageMetadata
	usageSent bool
	doneSent  bool
}

// choiceState tracks one candidate's progress. Gemini interleaves candidates
// across chunks, so each needs its own role/finish flags and tool-call counter.
type choiceState struct {
	roleSent      bool
	finishSent    bool
	sawToolCall   bool
	nextToolIndex int
}

func newStreamState(model, requestID string, status int) *streamState {
	return &streamState{
		id:      completionIDFromRequest(requestID),
		model:   model,
		created: time.Now().Unix(),
		status:  status,
		choices: map[int]*choiceState{},
	}
}

// completionIDFromRequest derives a stable OpenAI completion id from the
// per-request id so every chunk of one response shares it even before Gemini
// reports a responseId (which replaces it once seen).
func completionIDFromRequest(requestID string) string {
	if requestID != "" {
		return "chatcmpl-" + strings.ReplaceAll(requestID, "-", "")
	}
	return newChatCompletionID()
}

func (s *streamState) choiceState(index int) *choiceState {
	if s.choices == nil {
		s.choices = map[int]*choiceState{}
	}
	if existing, ok := s.choices[index]; ok {
		return existing
	}
	choice := &choiceState{}
	s.choices[index] = choice
	return choice
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
// spec. Comments (`:`) and the `event:` / `id:` fields are ignored — Gemini
// sends each GenerateContentResponse as a bare data line.
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

// ─── Gemini stream events ─────────────────────────────────────────────────────

// geminiStreamEvent is one streamed GenerateContentResponse. Gemini reports
// mid-stream failures by replacing the response with an "error" object, so both
// shapes are decoded together.
type geminiStreamEvent struct {
	geminiResponse
	Error *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
		Status  string `json:"status"`
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

// translateSSEChunk converts the Gemini SSE bytes delivered in one callback into
// OpenAI chat.completion.chunk events. Bytes forming only a partial trailing
// frame are held in state until that frame completes, so this is safe for
// arbitrary transport splits. terminate is true when a provider error or an
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

// translateFrame maps one streamed GenerateContentResponse onto zero or more
// OpenAI SSE events. The bool result requests stream termination.
func (s *streamState) translateFrame(frame []byte) ([]byte, bool) {
	payload := sseDataPayload(frame)
	if strings.TrimSpace(payload) == "" {
		// Comment or heartbeat frame — nothing to translate.
		return nil, false
	}

	var event geminiStreamEvent
	if err := json.Unmarshal([]byte(payload), &event); err != nil {
		// Never forward provider bytes we could not parse as if they were OpenAI
		// chunks; surface a typed error and stop the stream instead.
		slog.Warn(PolicyName+": malformed Gemini stream event", "error", err)
		s.failure = streamMalformedFrame
		return s.errorEvent("", "malformed Gemini stream event: "+err.Error(), 0), true
	}

	if event.Error != nil {
		s.failure = streamProviderError
		return s.errorEvent(event.Error.Status, event.Error.Message, event.Error.Code), true
	}

	// Identity is taken from the first event that reports it and then held fixed.
	if event.ModelVersion != "" {
		s.model = event.ModelVersion
	}
	if event.ResponseID != "" && !s.idFromProvider {
		s.id = "chatcmpl-" + event.ResponseID
		s.idFromProvider = true
	}
	// usageMetadata is cumulative; the newest report wins.
	if event.UsageMetadata != nil {
		s.usage = event.UsageMetadata
	}

	var out []byte
	if event.PromptFeedback != nil && event.PromptFeedback.BlockReason != "" {
		out = append(out, s.blockedPromptChunks()...)
	}
	for i := range event.Candidates {
		out = append(out, s.translateCandidate(&event.Candidates[i], i)...)
	}
	return out, false
}

// translateCandidate renders one candidate's parts as OpenAI deltas on the
// choice index that matches its Gemini candidate index.
func (s *streamState) translateCandidate(candidate *geminiCandidate, position int) []byte {
	index := candidateIndex(candidate, position)
	choice := s.choiceState(index)

	var out []byte
	out = append(out, s.roleChunk(index, choice)...)

	if candidate.Content != nil {
		for i := range candidate.Content.Parts {
			part := &candidate.Content.Parts[i]
			switch {
			case part.FunctionCall != nil:
				choice.sawToolCall = true
				toolIndex := choice.nextToolIndex
				choice.nextToolIndex++
				out = append(out, sseData(s.deltaChunk(index, map[string]interface{}{
					"tool_calls": []interface{}{map[string]interface{}{
						"index": toolIndex,
						"id":    "call_" + shortRandomID(),
						"type":  "function",
						"function": map[string]interface{}{
							"name":      part.FunctionCall.Name,
							"arguments": functionCallArguments(part.FunctionCall),
						},
					}},
				}, nil))...)
			case part.Text != "" && !part.Thought:
				out = append(out, sseData(s.deltaChunk(index,
					map[string]interface{}{"content": part.Text}, nil))...)
			}
			// Parts flagged thought:true are the model's reasoning, which OpenAI
			// Chat Completions chunks cannot represent — see the policy README.
		}
	}

	if candidate.FinishReason != "" && !choice.finishSent {
		choice.finishSent = true
		out = append(out, sseData(s.deltaChunk(index, map[string]interface{}{},
			finishReasonToOpenAI(candidate.FinishReason, choice.sawToolCall)))...)
	}
	return out
}

// candidateIndex mirrors the non-streaming translator: Gemini omits "index" for
// candidate 0, so fall back to the candidate's position in the array.
func candidateIndex(candidate *geminiCandidate, position int) int {
	if candidate.Index == 0 && position > 0 {
		return position
	}
	return candidate.Index
}

func (s *streamState) roleChunk(index int, choice *choiceState) []byte {
	if choice.roleSent {
		return nil
	}
	choice.roleSent = true
	return sseData(s.deltaChunk(index, map[string]interface{}{"role": "assistant"}, nil))
}

// blockedPromptChunks reports a prompt rejected by Gemini's safety filters as a
// content_filter finish on choice 0, which is the only channel OpenAI streaming
// offers for a blocked prompt.
func (s *streamState) blockedPromptChunks() []byte {
	choice := s.choiceState(0)
	if choice.finishSent {
		return nil
	}
	out := s.roleChunk(0, choice)
	choice.finishSent = true
	return append(out, sseData(s.deltaChunk(0, map[string]interface{}{}, openaiFinishContentFilter))...)
}

// finalize emits what the provider never sent before the stream ended: the usage
// chunk (when usage metadata was reported) and exactly one terminating [DONE].
func (s *streamState) finalize() []byte {
	var out []byte
	if !s.usageSent && s.usage != nil {
		s.usageSent = true
		chunk := s.baseChunk()
		chunk["choices"] = []interface{}{}
		chunk["usage"] = buildOpenAIUsage(s.usage)
		out = append(out, sseData(chunk)...)
	}
	if !s.doneSent {
		s.doneSent = true
		out = append(out, sseDonePayload...)
	}
	return out
}

// functionCallArguments serialises a Gemini functionCall's args as the JSON
// string OpenAI's tool-call wire format expects. Gemini delivers each call whole
// rather than as argument deltas, so one chunk carries the complete arguments.
func functionCallArguments(call *geminiFunctionCall) string {
	if call.Args == nil {
		return "{}"
	}
	encoded, err := json.Marshal(call.Args)
	if err != nil {
		return "{}"
	}
	return string(encoded)
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

func (s *streamState) deltaChunk(
	index int, delta map[string]interface{}, finishReason interface{},
) map[string]interface{} {
	chunk := s.baseChunk()
	chunk["choices"] = []interface{}{map[string]interface{}{
		"index":         index,
		"delta":         delta,
		"finish_reason": finishReason,
	}}
	return chunk
}

// errorEvent renders an OpenAI-style error object as one SSE event, preserving
// the upstream status and message. A stream ending this way gets no [DONE]: it
// is not a successful completion.
func (s *streamState) errorEvent(errType, message string, code int) []byte {
	if code <= 0 {
		code = s.status
	}
	if errType == "" {
		errType = mapStatusToOpenAIErrorType(code)
	}
	if message == "" {
		message = "gemini stream error"
	}
	errorBody := map[string]interface{}{"type": errType, "message": message}
	if code >= 400 {
		errorBody["code"] = fmt.Sprintf("%d", code)
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
// first time a response is seen. It returns nil when the response is not a
// Gemini event stream, in which case the chunk must be forwarded untouched.
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
