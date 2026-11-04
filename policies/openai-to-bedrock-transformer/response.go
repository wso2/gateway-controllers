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

package openaitobedrock

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

const (
	objectChatCompletion      = "chat.completion"
	objectChatCompletionChunk = "chat.completion.chunk"
	sseDonePayload            = "data: [DONE]\n\n"
)

// ─── Non-streaming (Converse JSON → OpenAI ChatCompletion) ────────────────────

type converseResponse struct {
	Output struct {
		Message struct {
			Role    string                 `json:"role"`
			Content []converseContentBlock `json:"content"`
		} `json:"message"`
	} `json:"output"`
	StopReason string        `json:"stopReason"`
	Usage      converseUsage `json:"usage"`
}

type converseContentBlock struct {
	Text    string `json:"text,omitempty"`
	ToolUse *struct {
		ToolUseID string          `json:"toolUseId"`
		Name      string          `json:"name"`
		Input     json.RawMessage `json:"input"`
	} `json:"toolUse,omitempty"`
}

type converseUsage struct {
	InputTokens           int           `json:"inputTokens"`
	OutputTokens          int           `json:"outputTokens"`
	TotalTokens           int           `json:"totalTokens"`
	CacheReadInputTokens  int           `json:"cacheReadInputTokens"`
	CacheWriteInputTokens int           `json:"cacheWriteInputTokens"`
	CacheDetails          []cacheDetail `json:"cacheDetails"`
}

type cacheDetail struct {
	TTL         string `json:"ttl"`
	InputTokens int    `json:"inputTokens"`
}

func translateConverseResponse(body []byte, status int, model, id string) policy.ResponseAction {
	if status < 200 || status >= 300 {
		return translateErrorResponse(body, status)
	}

	var resp converseResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		// 2xx but not Converse JSON — forward unchanged rather than masking it.
		return policy.DownstreamResponseModifications{}
	}

	var textParts []string
	var toolCalls []map[string]interface{}
	for i := range resp.Output.Message.Content {
		block := &resp.Output.Message.Content[i]
		if block.Text != "" {
			textParts = append(textParts, block.Text)
		}
		if block.ToolUse != nil {
			toolCalls = append(toolCalls, map[string]interface{}{
				"id":   block.ToolUse.ToolUseID,
				"type": "function",
				"function": map[string]interface{}{
					"name":      block.ToolUse.Name,
					"arguments": rawInputToArguments(block.ToolUse.Input),
				},
			})
		}
	}

	message := map[string]interface{}{
		"role":    "assistant",
		"content": strings.Join(textParts, ""),
	}
	if len(toolCalls) > 0 {
		message["tool_calls"] = toolCalls
	}

	openAIResp := map[string]interface{}{
		"id":      id,
		"object":  objectChatCompletion,
		"created": time.Now().Unix(),
		"model":   model,
		"choices": []map[string]interface{}{{
			"index":         0,
			"message":       message,
			"finish_reason": stopReasonToFinish(resp.StopReason, len(toolCalls) > 0),
		}},
		"usage": openAIUsage(resp.Usage),
	}

	newBody, err := json.Marshal(openAIResp)
	if err != nil {
		return errResponse(500, "failed to translate Bedrock response: "+err.Error(),
			policy.FaultCodeMediationFailed, policy.DirectionResponse, policy.FaultTypeMediation)
	}
	return policy.DownstreamResponseModifications{
		Body: newBody,
		HeadersToSet: map[string]string{
			"content-type":   "application/json",
			"content-length": fmt.Sprintf("%d", len(newBody)),
		},
	}
}

func translateErrorResponse(body []byte, status int) policy.ResponseAction {
	message := string(body)
	var bedrockErr struct {
		Message string `json:"message"`
	}
	if err := json.Unmarshal(body, &bedrockErr); err == nil && bedrockErr.Message != "" {
		message = bedrockErr.Message
	}

	openaiErr := map[string]interface{}{
		"error": map[string]interface{}{
			"type":    mapStatusToOpenAIErrorType(status),
			"message": message,
			"code":    fmt.Sprintf("%d", status),
		},
	}
	newBody, err := json.Marshal(openaiErr)
	if err != nil {
		return errResponse(500, "failed to translate Bedrock error: "+err.Error(),
			policy.FaultCodeMediationFailed, policy.DirectionResponse, policy.FaultTypeMediation)
	}
	return policy.DownstreamResponseModifications{
		Body: newBody,
		HeadersToSet: map[string]string{
			"content-type":   "application/json",
			"content-length": fmt.Sprintf("%d", len(newBody)),
		},
	}
}

// ─── Streaming (Amazon event stream → OpenAI SSE) ─────────────────────────────

// eventStreamToSSE decodes every complete event-stream frame in data and renders
// the OpenAI Server-Sent Events for them. When endOfStream is true it appends the
// terminating `data: [DONE]` marker. Bytes that form only a partial trailing
// frame are ignored (the kernel re-delivers them with the next flush).
func eventStreamToSSE(data []byte, endOfStream bool, id, model string) []byte {
	created := time.Now().Unix()
	var out []byte

	frames, _, ok := decodeEventStreamFrames(data)
	if ok {
		for i := range frames {
			out = append(out, streamFrameToSSE(&frames[i], id, model, created)...)
		}
	} else {
		out = append(out, data...)
	}

	if endOfStream {
		out = append(out, sseDonePayload...)
	}
	return out
}

// streamException returns the exception type of the first exception frame among the
// complete frames in data, and whether there is one. Bedrock ends a Converse stream after an
// exception, so one means the provider broke off the response.
func streamException(data []byte) (string, bool) {
	frames, _, ok := decodeEventStreamFrames(data)
	if !ok {
		return "", false
	}
	for i := range frames {
		if frames[i].MessageType == "exception" || frames[i].ExceptionType != "" {
			return frames[i].ExceptionType, true
		}
	}
	return "", false
}

// streamExceptionFault describes a Converse stream the provider ended with an exception:
// the provider breaking mid-response, FaultCodeProviderStreamFailed as docs/error-codes.md directs.
// The translated error event already carries the provider's message to the client; the
// fault adds only the exception type.
func streamExceptionFault(exceptionType string) *policy.FaultDetails {
	return &policy.FaultDetails{
		Code:        policy.FaultCodeProviderStreamFailed,
		Type:        policy.FaultTypeMediation,
		Direction:   policy.DirectionResponse,
		Message:     "The upstream stream ended with an error.",
		Description: "Bedrock stream exception: " + exceptionType,
	}
}

// streamFrameToSSE maps a single Converse stream event to zero or more OpenAI
// SSE events.
func streamFrameToSSE(frame *eventStreamFrame, id, model string, created int64) []byte {
	if frame.MessageType == "exception" || frame.ExceptionType != "" {
		return sseData(map[string]interface{}{
			"error": map[string]interface{}{
				"type":    "server_error",
				"message": exceptionMessage(frame),
			},
		})
	}

	var event map[string]interface{}
	if len(frame.Payload) > 0 {
		_ = json.Unmarshal(frame.Payload, &event)
	}

	switch frame.EventType {
	case "messageStart":
		return sseData(streamChunk(id, model, created, map[string]interface{}{"role": "assistant"}, nil))

	case "contentBlockStart":
		start, _ := event["start"].(map[string]interface{})
		toolUse, _ := start["toolUse"].(map[string]interface{})
		if toolUse == nil {
			return nil
		}
		delta := map[string]interface{}{
			"tool_calls": []interface{}{map[string]interface{}{
				"index": blockIndex(event),
				"id":    toolUse["toolUseId"],
				"type":  "function",
				"function": map[string]interface{}{
					"name":      toolUse["name"],
					"arguments": "",
				},
			}},
		}
		return sseData(streamChunk(id, model, created, delta, nil))

	case "contentBlockDelta":
		delta, _ := event["delta"].(map[string]interface{})
		if text, ok := delta["text"].(string); ok {
			return sseData(streamChunk(id, model, created, map[string]interface{}{"content": text}, nil))
		}
		if toolUse, ok := delta["toolUse"].(map[string]interface{}); ok {
			input, _ := toolUse["input"].(string)
			toolDelta := map[string]interface{}{
				"tool_calls": []interface{}{map[string]interface{}{
					"index":    blockIndex(event),
					"function": map[string]interface{}{"arguments": input},
				}},
			}
			return sseData(streamChunk(id, model, created, toolDelta, nil))
		}
		return nil

	case "messageStop":
		stopReason, _ := event["stopReason"].(string)
		return sseData(streamChunk(id, model, created, map[string]interface{}{},
			stopReasonToFinish(stopReason, false)))

	case "metadata":
		usage, ok := event["usage"].(map[string]interface{})
		if !ok {
			return nil
		}
		chunk := streamChunk(id, model, created, nil, nil)
		chunk["choices"] = []interface{}{}
		chunk["usage"] = openAIUsage(converseUsage{
			InputTokens:           numberField(usage, "inputTokens"),
			OutputTokens:          numberField(usage, "outputTokens"),
			TotalTokens:           numberField(usage, "totalTokens"),
			CacheReadInputTokens:  numberField(usage, "cacheReadInputTokens"),
			CacheWriteInputTokens: numberField(usage, "cacheWriteInputTokens"),
			CacheDetails:          cacheDetailsField(usage),
		})
		return sseData(chunk)
	}
	return nil
}

func streamChunk(id, model string, created int64, delta map[string]interface{}, finishReason interface{}) map[string]interface{} {
	chunk := map[string]interface{}{
		"id":      id,
		"object":  objectChatCompletionChunk,
		"created": created,
		"model":   model,
	}
	if delta != nil {
		chunk["choices"] = []interface{}{map[string]interface{}{
			"index":         0,
			"delta":         delta,
			"finish_reason": finishReason,
		}}
	}
	return chunk
}

// ─── Shared helpers ───────────────────────────────────────────────────────────

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

func rawInputToArguments(input json.RawMessage) string {
	if len(input) == 0 {
		return "{}"
	}
	return string(input)
}

func totalTokens(usage converseUsage) int {
	cacheWrite5m, cacheWrite1h := cacheWritesByTTL(usage)
	inclusiveTotal := usage.InputTokens + usage.CacheReadInputTokens +
		cacheWrite5m + cacheWrite1h + usage.OutputTokens
	if usage.TotalTokens > inclusiveTotal {
		return usage.TotalTokens
	}
	return inclusiveTotal
}

func cacheWritesByTTL(usage converseUsage) (int, int) {
	if len(usage.CacheDetails) == 0 {
		return usage.CacheWriteInputTokens, 0
	}

	var cacheWrite5m, cacheWrite1h int
	for _, detail := range usage.CacheDetails {
		switch detail.TTL {
		case "5m":
			cacheWrite5m += detail.InputTokens
		case "1h":
			cacheWrite1h += detail.InputTokens
		}
	}
	if classified := cacheWrite5m + cacheWrite1h; usage.CacheWriteInputTokens > classified {
		cacheWrite5m += usage.CacheWriteInputTokens - classified
	}
	return cacheWrite5m, cacheWrite1h
}

// openAIUsage preserves Converse cache usage while translating to the OpenAI
// shape. prompt_tokens is inclusive, cached_tokens identifies the discounted
// cache reads, and cache-write totals plus their TTL breakdown are retained for
// llm-cost's Bedrock calculator even though they are not standard OpenAI fields.
func openAIUsage(usage converseUsage) map[string]interface{} {
	cacheWrite5m, cacheWrite1h := cacheWritesByTTL(usage)
	cacheWriteTotal := cacheWrite5m + cacheWrite1h
	return map[string]interface{}{
		"prompt_tokens": usage.InputTokens + usage.CacheReadInputTokens +
			cacheWriteTotal,
		"completion_tokens": usage.OutputTokens,
		"total_tokens":      totalTokens(usage),
		"prompt_tokens_details": map[string]interface{}{
			"cached_tokens":         usage.CacheReadInputTokens,
			"cache_write_tokens":    cacheWriteTotal,
			"cache_write_5m_tokens": cacheWrite5m,
			"cache_write_1h_tokens": cacheWrite1h,
		},
	}
}

func blockIndex(event map[string]interface{}) int {
	if n, ok := toInt(event["contentBlockIndex"]); ok {
		return n
	}
	return 0
}

func numberField(m map[string]interface{}, key string) int {
	if n, ok := toInt(m[key]); ok {
		return n
	}
	return 0
}

func cacheDetailsField(m map[string]interface{}) []cacheDetail {
	rawDetails, _ := m["cacheDetails"].([]interface{})
	details := make([]cacheDetail, 0, len(rawDetails))
	for _, rawDetail := range rawDetails {
		detail, _ := rawDetail.(map[string]interface{})
		ttl, _ := detail["ttl"].(string)
		if ttl == "" {
			continue
		}
		details = append(details, cacheDetail{
			TTL:         ttl,
			InputTokens: numberField(detail, "inputTokens"),
		})
	}
	return details
}

func exceptionMessage(frame *eventStreamFrame) string {
	var payload struct {
		Message string `json:"message"`
	}
	if err := json.Unmarshal(frame.Payload, &payload); err == nil && payload.Message != "" {
		return payload.Message
	}
	if frame.ExceptionType != "" {
		return frame.ExceptionType
	}
	return "bedrock stream error"
}

func stopReasonToFinish(stopReason string, hasToolCalls bool) string {
	switch stopReason {
	case "max_tokens":
		return "length"
	case "tool_use":
		return "tool_calls"
	case "end_turn", "stop_sequence":
		return "stop"
	case "content_filtered", "guardrail_intervened":
		return "content_filter"
	default:
		if hasToolCalls {
			return "tool_calls"
		}
		return "stop"
	}
}

func mapStatusToOpenAIErrorType(status int) string {
	switch {
	case status == 400:
		return "invalid_request_error"
	case status == 401:
		return "authentication_error"
	case status == 403:
		return "permission_error"
	case status == 404:
		return "not_found_error"
	case status == 413:
		return "request_too_large"
	case status == 429:
		return "rate_limit_error"
	case status >= 500:
		return "server_error"
	default:
		return "api_error"
	}
}

func newChatCompletionID() string {
	var b [12]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("chatcmpl-%d", time.Now().UnixNano())
	}
	return "chatcmpl-" + hex.EncodeToString(b[:])
}
