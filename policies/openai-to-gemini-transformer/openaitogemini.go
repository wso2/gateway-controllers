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

// Package openaitogemini translates OpenAI Chat Completions requests/responses
// to and from the Google Gemini generateContent API.
package openaitogemini

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/url"
	"strings"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

const (
	PolicyName                  = "openai-to-gemini-transformer"
	DefaultAPIVersion           = "v1beta"
	MethodGenerateContent       = "generateContent"
	MethodStreamGenerateContent = "streamGenerateContent"
	MetadataKeySelectedProvider = "selected_provider"
	MetadataKeyEffectiveModel   = "openai_to_gemini_effective_model"
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
	APIVersion string
	// ProviderID is the upstream provider this translator targets. It is both the
	// upstream cluster the request is routed to and the key matched
	// (case-insensitive) against SharedContext.Metadata["selected_provider"]
	// in multi-provider mode.
	ProviderID string
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
// mode on the response body so Gemini's SSE events can be translated
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

	stream := false
	if v, ok := payload["stream"].(bool); ok {
		stream = v
	}

	mods, err := translateBody(payload, model, p.params, stream)
	if err != nil {
		return errResponse(500, "failed to marshal Gemini body: "+err.Error(),
			policy.FaultCodeMediationFailed, policy.DirectionRequest, policy.FaultTypeMediation)
	}
	if p.params.ProviderID != "" && mods.UpstreamName == nil {
		upstream := p.params.ProviderID
		mods.UpstreamName = &upstream
	}

	slog.Debug(PolicyName+": translating request",
		"providerId", p.params.ProviderID, "model", model, "stream", stream)
	return mods
}

// OnResponseHeaders marks a translated Gemini event stream as text/event-stream
// for downstream OpenAI clients and drops the now-stale content-length. Buffered
// JSON responses are left untouched.
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
// was not chunked. A fully buffered Gemini event stream is run through the same
// converter as the chunked path, so the downstream client sees identical OpenAI
// SSE either way.
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

// OnResponseBodyChunk translates the Gemini SSE events delivered in this flush
// into OpenAI chat.completion.chunk events, replacing the native bytes. On the
// final chunk it appends the usage chunk and the terminating [DONE].
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
	// Always return a non-nil body so the native Gemini bytes are replaced (nil
	// would pass them through untranslated). An empty slice emits nothing for
	// this flush, which is correct when a frame carried no delta.
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
			Description: "malformed Gemini stream event",
		}
	}
	return &policy.FaultDetails{
		Code:      policy.FaultCodeProviderStreamFailed,
		Type:      policy.FaultTypeMediation,
		Direction: policy.DirectionResponse,
		Message:   "The upstream stream ended with an error.",
	}
}

// shouldRun reports whether the request should be translated. When no upstream
// router (e.g. llm-header-router) has published a selected provider into the
// metadata, the proxy is in single-provider mode and the translator always
// runs. When a provider has been selected, the translator runs only if that
// selection matches its own "providerId".
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
	raw, ok := shared.Metadata[MetadataKeySelectedProvider]
	if !ok {
		return ""
	}
	v, ok := raw.(string)
	if !ok {
		return ""
	}
	return strings.TrimSpace(v)
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
	return "", fmt.Errorf("a Gemini model must be provided in either the policy configuration or request body")
}

func parseParams(params map[string]interface{}) (PolicyParams, error) {
	result := PolicyParams{APIVersion: DefaultAPIVersion}

	model, err := optionalString(params, "model")
	if err != nil {
		return result, err
	}
	// Optional: an unset model means each request supplies its own.
	result.Model = model

	if v, err := optionalString(params, "providerId"); err != nil {
		return result, err
	} else {
		result.ProviderID = v
	}

	if v, err := optionalString(params, "apiVersion"); err != nil {
		return result, err
	} else if v != "" {
		result.APIVersion = v
	}

	return result, nil
}

func optionalString(params map[string]interface{}, key string) (string, error) {
	raw, ok := params[key]
	if !ok || raw == nil {
		return "", nil
	}
	v, ok := raw.(string)
	if !ok {
		return "", fmt.Errorf("'%s' must be a string", key)
	}
	return strings.TrimSpace(v), nil
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

// translateBody converts an OpenAI Chat Completions payload into a Gemini
// generateContent request and returns the upstream modifications. A marshal
// failure is returned as an error so the caller can fail the request rather
// than forward an error document upstream as the request body.
func translateBody(
	payload map[string]interface{}, model string, params PolicyParams, stream bool,
) (policy.UpstreamRequestModifications, error) {
	geminiBody := map[string]interface{}{}

	if msgs, ok := payload["messages"].([]interface{}); ok {
		systemParts, contents := convertMessages(msgs)
		if len(systemParts) > 0 {
			geminiBody["systemInstruction"] = map[string]interface{}{"parts": systemParts}
		}
		if len(contents) > 0 {
			geminiBody["contents"] = contents
		}
	}

	if cfg := buildGenerationConfig(payload); len(cfg) > 0 {
		geminiBody["generationConfig"] = cfg
	}

	if tools, ok := payload["tools"].([]interface{}); ok && len(tools) > 0 {
		if geminiTools := convertTools(tools); len(geminiTools) > 0 {
			geminiBody["tools"] = geminiTools
		}
	}

	// "none" has no Gemini equivalent in the tool list; drop tools entirely
	// and set functionCallingConfig.mode=NONE.
	if tc, ok := payload["tool_choice"]; ok && tc != nil {
		toolConfig, drop := convertToolChoice(tc)
		if drop {
			delete(geminiBody, "tools")
		}
		if toolConfig != nil {
			geminiBody["toolConfig"] = toolConfig
		}
	}

	newBody, err := json.Marshal(geminiBody)
	if err != nil {
		return policy.UpstreamRequestModifications{}, err
	}

	newPath := buildGeminiPath(params.APIVersion, model, stream)
	return policy.UpstreamRequestModifications{
		Body: newBody,
		Path: &newPath,
		HeadersToSet: map[string]string{
			"content-type": "application/json",
		},
	}, nil
}

func buildGeminiPath(apiVersion, model string, stream bool) string {
	method := MethodGenerateContent
	suffix := ""
	if stream {
		method = MethodStreamGenerateContent
		suffix = "?alt=sse"
	}
	// The model can come from the request payload, so it is escaped before it
	// enters the path: a value carrying "/" or "?" must not be able to add a
	// segment or a query of its own. Ordinary model names contain nothing
	// PathEscape touches, so their paths are byte-identical to before.
	return fmt.Sprintf("/%s/models/%s:%s%s", apiVersion, url.PathEscape(model), method, suffix)
}

// convertMessages walks OpenAI messages[] and produces Gemini systemInstruction
// parts and contents[]. Consecutive user/tool parts flush into one Gemini
// "user" content; assistant messages flush as a "model" content.
func convertMessages(msgs []interface{}) ([]interface{}, []interface{}) {
	var systemParts []interface{}
	var contents []interface{}
	var pendingUserParts []interface{}

	flushUser := func() {
		if len(pendingUserParts) == 0 {
			return
		}
		contents = append(contents, map[string]interface{}{
			"role":  "user",
			"parts": pendingUserParts,
		})
		pendingUserParts = nil
	}

	for _, raw := range msgs {
		msg, ok := raw.(map[string]interface{})
		if !ok {
			continue
		}
		role, _ := msg["role"].(string)

		switch role {
		case "system", "developer":
			if parts := convertTextOrPartsToGemini(msg["content"]); len(parts) > 0 {
				systemParts = append(systemParts, parts...)
			}
		case "user":
			if parts := convertUserContent(msg["content"]); len(parts) > 0 {
				pendingUserParts = append(pendingUserParts, parts...)
			}
		case "tool":
			toolCallID, _ := msg["tool_call_id"].(string)
			text := extractTextContent(msg["content"])
			pendingUserParts = append(pendingUserParts, map[string]interface{}{
				"functionResponse": map[string]interface{}{
					"name":     toolCallID,
					"response": map[string]interface{}{"output": text},
				},
			})
		case "assistant":
			flushUser()
			contents = append(contents, map[string]interface{}{
				"role":  "model",
				"parts": convertAssistantParts(msg),
			})
		}
	}
	flushUser()

	return systemParts, contents
}

func convertTextOrPartsToGemini(content interface{}) []interface{} {
	switch c := content.(type) {
	case string:
		if c == "" {
			return nil
		}
		return []interface{}{map[string]interface{}{"text": c}}
	case []interface{}:
		var parts []interface{}
		for _, p := range c {
			m, ok := p.(map[string]interface{})
			if !ok || m["type"] != "text" {
				continue
			}
			if text, ok := m["text"].(string); ok && text != "" {
				parts = append(parts, map[string]interface{}{"text": text})
			}
		}
		return parts
	}
	return nil
}

func convertUserContent(content interface{}) []interface{} {
	switch c := content.(type) {
	case string:
		if c == "" {
			return nil
		}
		return []interface{}{map[string]interface{}{"text": c}}
	case []interface{}:
		var parts []interface{}
		for _, p := range c {
			m, ok := p.(map[string]interface{})
			if !ok {
				continue
			}
			switch m["type"].(string) {
			case "text":
				if text, ok := m["text"].(string); ok && text != "" {
					parts = append(parts, map[string]interface{}{"text": text})
				}
			case "image_url":
				if part := convertImage(m); part != nil {
					parts = append(parts, part)
				}
			}
		}
		return parts
	}
	return nil
}

func extractTextContent(content interface{}) string {
	switch c := content.(type) {
	case string:
		return c
	case []interface{}:
		var parts []string
		for _, p := range c {
			m, ok := p.(map[string]interface{})
			if !ok || m["type"] != "text" {
				continue
			}
			if text, ok := m["text"].(string); ok {
				parts = append(parts, text)
			}
		}
		return strings.Join(parts, "")
	}
	return ""
}

// convertAssistantParts builds the Gemini "model" parts list from an OpenAI
// assistant message: text becomes a text part; each tool_call becomes a
// functionCall part with arguments parsed back into an object.
func convertAssistantParts(msg map[string]interface{}) []interface{} {
	var parts []interface{}

	if text := extractTextContent(msg["content"]); text != "" {
		parts = append(parts, map[string]interface{}{"text": text})
	}

	toolCalls, _ := msg["tool_calls"].([]interface{})
	for _, tc := range toolCalls {
		toolCall, ok := tc.(map[string]interface{})
		if !ok {
			continue
		}
		fn, _ := toolCall["function"].(map[string]interface{})
		if fn == nil {
			continue
		}
		name, _ := fn["name"].(string)
		argsStr, _ := fn["arguments"].(string)

		// OpenAI wire format is a JSON string; Gemini wants an object. Fall
		// back to empty object on parse failure so the request still validates.
		var args map[string]interface{}
		if argsStr != "" {
			if err := json.Unmarshal([]byte(argsStr), &args); err != nil {
				args = map[string]interface{}{}
			}
		} else {
			args = map[string]interface{}{}
		}
		parts = append(parts, map[string]interface{}{
			"functionCall": map[string]interface{}{
				"name": name,
				"args": args,
			},
		})
	}

	return parts
}

func convertImage(m map[string]interface{}) map[string]interface{} {
	imgObj, ok := m["image_url"].(map[string]interface{})
	if !ok {
		return nil
	}
	imageURL, ok := imgObj["url"].(string)
	if !ok || imageURL == "" {
		return nil
	}

	if strings.HasPrefix(imageURL, "data:") {
		comma := strings.SplitN(imageURL, ",", 2)
		if len(comma) != 2 {
			return nil
		}
		meta := strings.TrimPrefix(comma[0], "data:")
		metaParts := strings.SplitN(meta, ";", 2)
		return map[string]interface{}{
			"inlineData": map[string]interface{}{
				"mimeType": metaParts[0],
				"data":     comma[1],
			},
		}
	}

	// Remote URL — Gemini accepts fileData with file_uri. mimeType defaults
	// to image/jpeg when the URL has no recognizable extension.
	mimeType := "image/jpeg"
	lower := strings.ToLower(imageURL)
	switch {
	case strings.HasSuffix(lower, ".png"):
		mimeType = "image/png"
	case strings.HasSuffix(lower, ".gif"):
		mimeType = "image/gif"
	case strings.HasSuffix(lower, ".webp"):
		mimeType = "image/webp"
	}
	return map[string]interface{}{
		"fileData": map[string]interface{}{
			"mimeType": mimeType,
			"fileUri":  imageURL,
		},
	}
}

func buildGenerationConfig(payload map[string]interface{}) map[string]interface{} {
	cfg := map[string]interface{}{}

	if v, ok := payload["temperature"]; ok {
		cfg["temperature"] = v
	}
	if v, ok := payload["top_p"]; ok {
		cfg["topP"] = v
	}
	if v, ok := payload["max_completion_tokens"]; ok {
		cfg["maxOutputTokens"] = v
	} else if v, ok := payload["max_tokens"]; ok {
		cfg["maxOutputTokens"] = v
	}
	if v, ok := payload["stop"]; ok && v != nil {
		switch s := v.(type) {
		case string:
			cfg["stopSequences"] = []string{s}
		case []interface{}:
			cfg["stopSequences"] = s
		}
	}
	if v, ok := payload["n"]; ok {
		cfg["candidateCount"] = v
	}
	if v, ok := payload["seed"]; ok {
		cfg["seed"] = v
	}
	if v, ok := payload["frequency_penalty"]; ok {
		cfg["frequencyPenalty"] = v
	}
	if v, ok := payload["presence_penalty"]; ok {
		cfg["presencePenalty"] = v
	}

	return cfg
}

func convertTools(tools []interface{}) []map[string]interface{} {
	var decls []map[string]interface{}
	for _, t := range tools {
		tool, ok := t.(map[string]interface{})
		if !ok {
			continue
		}
		fn, ok := tool["function"].(map[string]interface{})
		if !ok {
			continue
		}
		decl := map[string]interface{}{"name": fn["name"]}
		if desc, ok := fn["description"]; ok {
			decl["description"] = desc
		}
		if params, ok := fn["parameters"]; ok {
			decl["parameters"] = params
		}
		decls = append(decls, decl)
	}
	if len(decls) == 0 {
		return nil
	}
	return []map[string]interface{}{
		{"functionDeclarations": decls},
	}
}

// convertToolChoice returns (toolConfig, dropTools). dropTools=true tells the
// caller to remove the tools[] field — used for the "none" choice where
// Gemini also expects mode=NONE.
func convertToolChoice(tc interface{}) (map[string]interface{}, bool) {
	switch v := tc.(type) {
	case string:
		switch v {
		case "auto":
			return map[string]interface{}{
				"functionCallingConfig": map[string]interface{}{"mode": "AUTO"},
			}, false
		case "required":
			return map[string]interface{}{
				"functionCallingConfig": map[string]interface{}{"mode": "ANY"},
			}, false
		case "none":
			return map[string]interface{}{
				"functionCallingConfig": map[string]interface{}{"mode": "NONE"},
			}, true
		}
	case map[string]interface{}:
		if fn, ok := v["function"].(map[string]interface{}); ok {
			if name, ok := fn["name"].(string); ok {
				return map[string]interface{}{
					"functionCallingConfig": map[string]interface{}{
						"mode":                 "ANY",
						"allowedFunctionNames": []string{name},
					},
				}, false
			}
		}
	}
	return map[string]interface{}{
		"functionCallingConfig": map[string]interface{}{"mode": "AUTO"},
	}, false
}
