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
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

const (
	PolicyName                  = "openai-to-anthropic-transformer"
	AnthropicMessagesPath       = "/v1/messages"
	DefaultAnthropicVersion     = "2023-06-01"
	DefaultMaxTokens            = 4096
	MetadataKeySelectedProvider = "selected_provider"
	MetadataKeyEffectiveModel   = "openai_to_anthropic_effective_model"
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
	Model            string
	AnthropicVersion string
	ProviderID       string
}

type TranslatorPolicy struct {
	params PolicyParams
}

func GetPolicy(_ policy.PolicyMetadata, rawParams map[string]interface{}) (policy.Policy, error) {
	parsed, err := parseParams(rawParams)
	if err != nil {
		return nil, fmt.Errorf("%s: invalid params: %w", PolicyName, err)
	}
	return &TranslatorPolicy{params: parsed}, nil
}

// Mode buffers the (small) request body for translation, processes response
// headers so the streaming content-type can be corrected, and asks for STREAM
// mode on the response body so Anthropic's SSE events can be translated
// chunk-by-chunk. The kernel falls back to the buffered OnResponseBody path
// automatically when the upstream response is not a stream.
func (p *TranslatorPolicy) Mode() policy.ProcessingMode {
	return policy.ProcessingMode{
		RequestHeaderMode:  policy.HeaderModeSkip,
		RequestBodyMode:    policy.BodyModeBuffer,
		ResponseHeaderMode: policy.HeaderModeProcess,
		ResponseBodyMode:   policy.BodyModeStream,
	}
}

func (p *TranslatorPolicy) OnRequestBody(
	_ context.Context,
	reqCtx *policy.RequestContext,
	_ map[string]interface{},
) policy.RequestAction {
	if !p.shouldRun(reqCtx) {
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

	slog.Debug(PolicyName+": translating request",
		"providerId", p.params.ProviderID, "model", model, "path", AnthropicMessagesPath)

	mods, err := translateBody(payload, model, p.params)
	if err != nil {
		return errResponse(500, "failed to marshal Anthropic body: "+err.Error(),
			policy.FaultCodeMediationFailed, policy.DirectionRequest, policy.FaultTypeMediation)
	}
	if p.params.ProviderID != "" && mods.UpstreamName == nil {
		upstream := p.params.ProviderID
		mods.UpstreamName = &upstream
	}
	return mods
}

// OnResponseHeaders marks a translated Anthropic event stream as
// text/event-stream for downstream OpenAI clients and drops the now-stale
// content-length. Buffered JSON responses are left untouched.
func (p *TranslatorPolicy) OnResponseHeaders(
	_ context.Context,
	respCtx *policy.ResponseHeaderContext,
	_ map[string]interface{},
) policy.ResponseHeaderAction {
	if !p.shouldRunForSelected(selectedProvider(respCtx.SharedContext)) {
		return policy.DownstreamResponseHeaderModifications{}
	}
	if !isSSEContentType(headerValue(respCtx.ResponseHeaders, "content-type")) {
		return policy.DownstreamResponseHeaderModifications{}
	}
	return policy.DownstreamResponseHeaderModifications{
		HeadersToSet:    map[string]string{"content-type": "text/event-stream"},
		HeadersToRemove: []string{"content-length"},
	}
}

// OnResponseBody is the buffered fallback used when the chain cannot stream
// (some other response policy is not streaming-capable) or the upstream response
// was not chunked. A fully buffered Anthropic event stream is run through the
// same converter as the chunked path, so the downstream client sees identical
// OpenAI SSE either way.
func (p *TranslatorPolicy) OnResponseBody(
	_ context.Context,
	respCtx *policy.ResponseContext,
	_ map[string]interface{},
) policy.ResponseAction {
	if !p.shouldRunForSelected(selectedProvider(respCtx.SharedContext)) {
		return policy.DownstreamResponseModifications{}
	}

	if respCtx.ResponseBody == nil || !respCtx.ResponseBody.Present || len(respCtx.ResponseBody.Content) == 0 {
		return policy.DownstreamResponseModifications{}
	}

	body := respCtx.ResponseBody.Content
	if isSSEResponse(headerValue(respCtx.ResponseHeaders, "content-type"), body) {
		slog.Debug(PolicyName+": translating buffered SSE response", "status", respCtx.ResponseStatus)
		state := newStreamState(effectiveModel(respCtx.SharedContext, p.params.Model),
			requestID(respCtx.SharedContext), respCtx.ResponseStatus)
		sse, terminate := translateSSEChunk(state, body, true)
		mods := policy.DownstreamResponseModifications{
			Body:            sse,
			HeadersToSet:    map[string]string{"content-type": "text/event-stream"},
			HeadersToRemove: []string{"content-length"},
		}
		if terminate {
			// The same failure the streaming path reports, on the same bytes: the
			// translated error event is already the body, so only the fault is added.
			mods.IsFault = true
			mods.Fault = streamFault(state.failure)
		}
		return mods
	}

	slog.Debug(PolicyName+": translating response", "status", respCtx.ResponseStatus)
	return translateResponse(body, respCtx.ResponseStatus,
		effectiveModel(respCtx.SharedContext, p.params.Model))
}

// ─── Streaming response phase ─────────────────────────────────────────────────

// NeedsMoreResponseData keeps the kernel accumulating until its buffer ends on an
// SSE frame boundary, so OnResponseBodyChunk normally receives whole events. The
// per-request residual buffer still covers the cases where the kernel flushes
// early (accumulator cap, end of stream).
func (p *TranslatorPolicy) NeedsMoreResponseData(accumulated []byte) bool {
	if len(accumulated) == 0 {
		return false
	}
	if !looksLikeSSE(accumulated) {
		// Not SSE (e.g. a JSON error body streamed through) — don't stall the
		// stream waiting for a boundary that will never come.
		return false
	}
	return !endsOnSSEBoundary(accumulated)
}

// OnResponseBodyChunk translates the Anthropic SSE events delivered in this
// flush into OpenAI chat.completion.chunk events, replacing the native bytes. On
// the final chunk it appends the usage chunk and the terminating [DONE].
func (p *TranslatorPolicy) OnResponseBodyChunk(
	_ context.Context,
	respCtx *policy.ResponseStreamContext,
	chunk *policy.StreamBody,
	_ map[string]interface{},
) policy.StreamingResponseAction {
	if !p.shouldRunForSelected(selectedProvider(respCtx.SharedContext)) {
		return policy.ForwardResponseChunk{}
	}

	state := p.streamStateFor(respCtx, chunk)
	if state == nil {
		// Not an event stream — the buffered OnResponseBody path owns this
		// response; forward the bytes untouched.
		return policy.ForwardResponseChunk{}
	}

	sse, terminate := translateSSEChunk(state, chunk.Chunk, chunk.EndOfStream)
	// Always return a non-nil body so the native Anthropic bytes are replaced
	// (nil would pass them through untranslated). An empty slice emits nothing
	// for this flush, which is correct when a frame carried no delta.
	if sse == nil {
		sse = []byte{}
	}
	if terminate {
		// Response headers are already committed, so a provider error can only be
		// delivered as a final SSE event before the stream is closed.
		//
		// terminate is set on exactly two conditions, and both are failures: the provider
		// sent an error event, or it sent a frame this translator could not parse. A clean
		// end of stream returns false and is forwarded, not terminated — so unlike the
		// general streaming case, every termination here is a fault.
		return policy.TerminateResponseChunk{
			Body:    sse,
			IsFault: true,
			Fault:   streamFault(state.failure),
		}
	}
	return policy.ForwardResponseChunk{Body: sse}
}

// streamFault describes a terminated stream by why it terminated. A provider error event
// is the provider breaking mid-response, FaultCodeProviderStreamFailed as docs/error-codes.md
// directs; a frame the translator could not parse is its own failure, FaultCodeMediationFailed.
// The final SSE event already carries the detail to the client; nothing is withheld here.
func streamFault(failure streamFailure) *policy.FaultDetails {
	if failure == streamMalformedFrame {
		return &policy.FaultDetails{
			Code:        policy.FaultCodeMediationFailed,
			Type:        policy.FaultTypeMediation,
			Direction:   policy.DirectionResponse,
			Message:     "The upstream stream could not be translated.",
			Description: "malformed Anthropic stream event",
		}
	}
	return &policy.FaultDetails{
		Code:      policy.FaultCodeProviderStreamFailed,
		Type:      policy.FaultTypeMediation,
		Direction: policy.DirectionResponse,
		Message:   "The upstream stream ended with an error.",
	}
}

// ─── Routing / selection ──────────────────────────────────────────────────────

func (p *TranslatorPolicy) shouldRun(reqCtx *policy.RequestContext) bool {
	return p.shouldRunForSelected(selectedProvider(reqCtx.SharedContext))
}

func (p *TranslatorPolicy) shouldRunForSelected(selected string) bool {
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
	rawSelectedProvider, hasSelectedProvider := shared.Metadata[MetadataKeySelectedProvider]
	if !hasSelectedProvider {
		return ""
	}
	selectedProvider, isString := rawSelectedProvider.(string)
	if !isString {
		return ""
	}
	return strings.TrimSpace(selectedProvider)
}

// storeEffectiveModel records the model that served this request so the
// response phase can report it rather than the configured value, which may be
// empty. Mirrors the Bedrock implementation; these policies share no package.
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

// effectiveModel reads back what storeEffectiveModel recorded, falling back to
// the configured model so no response path can report nothing.
func effectiveModel(shared *policy.SharedContext, configured string) string {
	if shared != nil && shared.Metadata != nil {
		if model, ok := shared.Metadata[MetadataKeyEffectiveModel].(string); ok && model != "" {
			return model
		}
	}
	return configured
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
	return "", fmt.Errorf("an Anthropic model must be provided in either the policy configuration or request body")
}

func parseParams(params map[string]interface{}) (PolicyParams, error) {
	result := PolicyParams{AnthropicVersion: DefaultAnthropicVersion}

	model, err := optionalString(params, "model")
	if err != nil {
		return result, err
	}
	// Optional: an unset model means each request supplies its own.
	result.Model = model

	if providerID, err := optionalString(params, "providerId"); err != nil {
		return result, err
	} else {
		result.ProviderID = providerID
	}

	if anthropicVersion, err := optionalString(params, "anthropicVersion"); err != nil {
		return result, err
	} else if anthropicVersion != "" {
		result.AnthropicVersion = anthropicVersion
	}

	return result, nil
}

func optionalString(params map[string]interface{}, key string) (string, error) {
	rawValue, hasValue := params[key]
	if !hasValue || rawValue == nil {
		return "", nil
	}
	value, isString := rawValue.(string)
	if !isString {
		return "", fmt.Errorf("'%s' must be a string", key)
	}
	return strings.TrimSpace(value), nil
}

// errResponse refuses the exchange and describes why.
//
// direction states which side was refused: DirectionRequest when the caller's payload could
// not be read or converted, DirectionResponse when the provider's could not be translated
// back. Those are operationally different events that share nothing but this function, and
// only the caller knows which it is — which is why it is a parameter rather than inferred
// from the status.
func errResponse(statusCode int, message, code, direction, errorType string) policy.ImmediateResponse {
	body, _ := json.Marshal(map[string]string{"error": message})
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

// translateBody converts an OpenAI Chat Completions request payload into an
// Anthropic Messages request and returns the upstream modifications. A marshal
// failure is returned as an error so the caller can fail the request rather
// than forward an error document upstream as the request body.
func translateBody(
	payload map[string]interface{}, model string, params PolicyParams,
) (policy.UpstreamRequestModifications, error) {
	anthropicBody := map[string]interface{}{"model": model}

	if messages, hasMessages := payload["messages"].([]interface{}); hasMessages {
		systemText, anthropicMessages := convertMessages(messages)
		if systemText != "" {
			anthropicBody["system"] = systemText
		}
		if len(anthropicMessages) > 0 {
			anthropicBody["messages"] = anthropicMessages
		}
	}

	// Anthropic requires max_tokens; OpenAI's newer max_completion_tokens wins
	// over legacy max_tokens, matching OpenAI's own precedence.
	if maxCompletionTokens, hasMaxCompletionTokens := payload["max_completion_tokens"]; hasMaxCompletionTokens {
		anthropicBody["max_tokens"] = maxCompletionTokens
	} else if maxTokens, hasMaxTokens := payload["max_tokens"]; hasMaxTokens {
		anthropicBody["max_tokens"] = maxTokens
	} else {
		anthropicBody["max_tokens"] = DefaultMaxTokens
	}

	if temperature, hasTemperature := payload["temperature"]; hasTemperature {
		anthropicBody["temperature"] = temperature
	}
	if topP, hasTopP := payload["top_p"]; hasTopP {
		anthropicBody["top_p"] = topP
	}
	if stream, hasStream := payload["stream"]; hasStream {
		anthropicBody["stream"] = stream
	}

	if stop, hasStop := payload["stop"]; hasStop && stop != nil {
		switch stopValue := stop.(type) {
		case string:
			anthropicBody["stop_sequences"] = []string{stopValue}
		case []interface{}:
			anthropicBody["stop_sequences"] = stopValue
		}
	}

	if tools, hasTools := payload["tools"].([]interface{}); hasTools && len(tools) > 0 {
		if anthropicTools := convertTools(tools); len(anthropicTools) > 0 {
			anthropicBody["tools"] = anthropicTools
		}
	}

	// "none" has no Anthropic equivalent — drop tools entirely so the model
	// cannot call any.
	if toolChoice, hasToolChoice := payload["tool_choice"]; hasToolChoice && toolChoice != nil {
		if anthropicToolChoice := convertToolChoice(toolChoice); anthropicToolChoice == nil {
			delete(anthropicBody, "tools")
		} else {
			anthropicBody["tool_choice"] = anthropicToolChoice
		}
	}

	newBody, err := json.Marshal(anthropicBody)
	if err != nil {
		return policy.UpstreamRequestModifications{}, err
	}

	newPath := AnthropicMessagesPath
	return policy.UpstreamRequestModifications{
		Body: newBody,
		Path: &newPath,
		HeadersToSet: map[string]string{
			"content-type":      "application/json",
			"anthropic-version": params.AnthropicVersion,
		},
	}, nil
}

// convertMessages extracts system text and rewrites messages into Anthropic
// role/content blocks. Consecutive tool messages collapse into one user
// message of tool_result blocks (Anthropic groups them together).
func convertMessages(messages []interface{}) (string, []map[string]interface{}) {
	var systemParts []string
	var anthropicMessages []map[string]interface{}

	for messageIndex := 0; messageIndex < len(messages); messageIndex++ {
		message, isObject := messages[messageIndex].(map[string]interface{})
		if !isObject {
			continue
		}
		role, _ := message["role"].(string)

		switch role {
		case "system", "developer":
			if text := extractTextContent(message["content"]); text != "" {
				systemParts = append(systemParts, text)
			}
		case "user":
			anthropicMessages = append(anthropicMessages, map[string]interface{}{
				"role":    "user",
				"content": convertUserContent(message["content"]),
			})
		case "assistant":
			anthropicMessages = append(anthropicMessages, map[string]interface{}{
				"role":    "assistant",
				"content": convertAssistantContent(message),
			})
		case "tool":
			var toolResults []interface{}
			for messageIndex < len(messages) {
				toolMessage, isObject := messages[messageIndex].(map[string]interface{})
				if !isObject {
					break
				}
				if toolMessageRole, _ := toolMessage["role"].(string); toolMessageRole != "tool" {
					break
				}
				toolCallID, _ := toolMessage["tool_call_id"].(string)
				toolResults = append(toolResults, map[string]interface{}{
					"type":        "tool_result",
					"tool_use_id": toolCallID,
					"content":     extractTextContent(toolMessage["content"]),
				})
				messageIndex++
			}
			// Outer loop will increment; rewind so we revisit the terminator.
			messageIndex--
			anthropicMessages = append(anthropicMessages, map[string]interface{}{
				"role":    "user",
				"content": toolResults,
			})
		}
	}

	return strings.Join(systemParts, "\n"), anthropicMessages
}

func extractTextContent(content interface{}) string {
	switch typedContent := content.(type) {
	case string:
		return typedContent
	case []interface{}:
		var parts []string
		for _, contentPart := range typedContent {
			contentBlock, isObject := contentPart.(map[string]interface{})
			if !isObject || contentBlock["type"] != "text" {
				continue
			}
			if text, isString := contentBlock["text"].(string); isString {
				parts = append(parts, text)
			}
		}
		return strings.Join(parts, "")
	}
	return ""
}

func convertUserContent(content interface{}) interface{} {
	switch typedContent := content.(type) {
	case string:
		return typedContent
	case []interface{}:
		var blocks []interface{}
		for _, contentPart := range typedContent {
			contentBlock, isObject := contentPart.(map[string]interface{})
			if !isObject {
				continue
			}
			blockType, isString := contentBlock["type"].(string)
			if !isString {
				continue
			}
			switch blockType {
			case "text":
				blocks = append(blocks, map[string]interface{}{
					"type": "text",
					"text": contentBlock["text"],
				})
			case "image_url":
				if block := convertImage(contentBlock); block != nil {
					blocks = append(blocks, block)
				}
			}
		}
		if len(blocks) > 0 {
			return blocks
		}
		return content
	}
	return content
}

func convertAssistantContent(message map[string]interface{}) interface{} {
	toolCalls, hasToolCalls := message["tool_calls"].([]interface{})
	textContent := extractTextContent(message["content"])

	if !hasToolCalls || len(toolCalls) == 0 {
		if textContent != "" {
			return textContent
		}
		return message["content"]
	}

	var blocks []interface{}
	if textContent != "" {
		blocks = append(blocks, map[string]interface{}{
			"type": "text",
			"text": textContent,
		})
	}

	for _, rawToolCall := range toolCalls {
		toolCall, isObject := rawToolCall.(map[string]interface{})
		if !isObject {
			continue
		}
		id, _ := toolCall["id"].(string)
		functionDefinition, _ := toolCall["function"].(map[string]interface{})
		if functionDefinition == nil {
			continue
		}
		name, _ := functionDefinition["name"].(string)
		argumentsString, _ := functionDefinition["arguments"].(string)

		// OpenAI wire format is a JSON string; Anthropic wants the decoded
		// object inline. Fall back to empty object on parse failure so the
		// request still validates.
		var input interface{}
		if argumentsString != "" {
			if err := json.Unmarshal([]byte(argumentsString), &input); err != nil {
				input = map[string]interface{}{}
			}
		} else {
			input = map[string]interface{}{}
		}
		blocks = append(blocks, map[string]interface{}{
			"type":  "tool_use",
			"id":    id,
			"name":  name,
			"input": input,
		})
	}

	return blocks
}

func convertImage(contentBlock map[string]interface{}) map[string]interface{} {
	imageObject, isObject := contentBlock["image_url"].(map[string]interface{})
	if !isObject {
		return nil
	}
	imageURL, isString := imageObject["url"].(string)
	if !isString || imageURL == "" {
		return nil
	}

	if strings.HasPrefix(imageURL, "data:") {
		parts := strings.SplitN(imageURL, ",", 2)
		if len(parts) != 2 {
			return nil
		}
		meta := strings.TrimPrefix(parts[0], "data:")
		metaParts := strings.SplitN(meta, ";", 2)
		return map[string]interface{}{
			"type": "image",
			"source": map[string]interface{}{
				"type":       "base64",
				"media_type": metaParts[0],
				"data":       parts[1],
			},
		}
	}

	return map[string]interface{}{
		"type": "image",
		"source": map[string]interface{}{
			"type": "url",
			"url":  imageURL,
		},
	}
}

func convertTools(tools []interface{}) []map[string]interface{} {
	var result []map[string]interface{}
	for _, rawTool := range tools {
		tool, isObject := rawTool.(map[string]interface{})
		if !isObject {
			continue
		}
		functionDefinition, isObject := tool["function"].(map[string]interface{})
		if !isObject {
			continue
		}
		anthropicTool := map[string]interface{}{"name": functionDefinition["name"]}
		if description, hasDescription := functionDefinition["description"]; hasDescription {
			anthropicTool["description"] = description
		}
		if parameters, hasParameters := functionDefinition["parameters"]; hasParameters {
			anthropicTool["input_schema"] = parameters
		} else {
			anthropicTool["input_schema"] = map[string]interface{}{
				"type":       "object",
				"properties": map[string]interface{}{},
			}
		}
		result = append(result, anthropicTool)
	}
	return result
}

// convertToolChoice returns nil for "none" — the caller drops tools[] entirely
// since Anthropic has no negative tool_choice form.
func convertToolChoice(toolChoice interface{}) interface{} {
	switch typedToolChoice := toolChoice.(type) {
	case string:
		switch typedToolChoice {
		case "auto":
			return map[string]interface{}{"type": "auto"}
		case "none":
			return nil
		case "required":
			return map[string]interface{}{"type": "any"}
		}
	case map[string]interface{}:
		if functionDefinition, hasFunction := typedToolChoice["function"].(map[string]interface{}); hasFunction {
			if name, hasName := functionDefinition["name"].(string); hasName {
				return map[string]interface{}{"type": "tool", "name": name}
			}
		}
	}
	return map[string]interface{}{"type": "auto"}
}
