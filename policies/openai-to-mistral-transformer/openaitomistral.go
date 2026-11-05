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

// Package openaitomistral translates OpenAI Chat Completions requests for
// Mistral's OpenAI-compatible chat completions endpoint.
package openaitomistral

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

const (
	PolicyName                  = "openai-to-mistral-transformer"
	MistralChatCompletionsPath  = "/v1/chat/completions"
	MetadataKeySelectedProvider = "selected_provider"
	MetadataKeyEffectiveModel   = "openai_to_mistral_effective_model"
	// MetadataKeyResponseIsEventStream caches the one-time verdict on whether
	// the upstream response is an event stream, so every chunk after the first
	// is routed the same way as the first. See responseIsEventStream.
	MetadataKeyResponseIsEventStream = "openai_to_mistral_response_is_event_stream"
)

// unsupportedRequestFields lists OpenAI fields Mistral's API rejects. Keep in
// sync with https://docs.mistral.ai/api/.
var unsupportedRequestFields = []string{
	"logprobs",
	"top_logprobs",
	"logit_bias",
	"n",
	"service_tier",
	"store",
	"metadata",
	"user",
}

type PolicyParams struct {
	// Model is the fallback used when the request payload names no model. It
	// never overrides a model the client named — see resolveModel.
	Model string
	// ProviderID is the upstream provider this translator targets. It serves two
	// purposes: it is the upstream cluster the request is routed to, and it
	// is the key matched (case-insensitive) against
	// SharedContext.Metadata["selected_provider"] in multi-provider mode.
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

// Mode declares the response body as STREAM rather than BUFFER even though
// Mistral speaks OpenAI already and needs no event translation.
//
// The declaration is not about this policy's own needs. The kernel computes one
// streaming capability for the whole chain: a single policy declaring
// BodyModeBuffer sets SupportsResponseStreaming=false for every policy on the
// route (BuildPolicyChain in the engine's body_mode.go), which makes the engine
// ask Envoy for a BUFFERED response body. On a multi-provider proxy that pairs
// Mistral with a translator that does stream — Anthropic, Gemini, Bedrock — a
// BUFFER declaration here therefore switched off incremental delivery for all
// of them, and the client saw nothing until the upstream closed. That flag is
// computed once at chain-build time from Mode() alone, so the per-provider
// "selected_provider" condition cannot undo it: a Mistral translator that never
// runs still silenced the stream.
//
// Declaring STREAM keeps the route streaming and moves the choice to where it
// can be made per response: OnResponseBodyChunk forwards event streams
// untouched and reassembles anything else for the buffered translator.
func (p *TranslatorPolicy) Mode() policy.ProcessingMode {
	return policy.ProcessingMode{
		RequestHeaderMode:  policy.HeaderModeSkip,
		RequestBodyMode:    policy.BodyModeBuffer,
		ResponseHeaderMode: policy.HeaderModeSkip,
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

	payload["model"] = model
	for _, key := range unsupportedRequestFields {
		delete(payload, key)
	}

	newBody, err := json.Marshal(payload)
	if err != nil {
		return errResponse(500, "failed to marshal Mistral body: "+err.Error(),
			policy.FaultCodeMediationFailed, policy.DirectionRequest, policy.FaultTypeMediation)
	}

	newPath := MistralChatCompletionsPath
	slog.Debug(PolicyName+": translating request",
		"providerId", p.params.ProviderID, "model", model, "path", newPath)

	mods := policy.UpstreamRequestModifications{
		Body:         newBody,
		Path:         &newPath,
		HeadersToSet: map[string]string{"content-type": "application/json"},
	}
	if p.params.ProviderID != "" {
		upstream := p.params.ProviderID
		mods.UpstreamName = &upstream
	}
	return mods
}

// OnResponseBody normalises the Mistral response into OpenAI shape. Mistral
// already emits OpenAI-shaped success bodies, so the work here is mostly
// error-envelope translation and ensuring the response model is non-empty.
// SSE streaming bodies pass through untouched.
func (p *TranslatorPolicy) OnResponseBody(
	_ context.Context,
	respCtx *policy.ResponseContext,
	_ map[string]interface{},
) policy.ResponseAction {
	if !p.shouldRunResponse(respCtx) {
		return policy.DownstreamResponseModifications{}
	}

	if respCtx.ResponseBody == nil || !respCtx.ResponseBody.Present || len(respCtx.ResponseBody.Content) == 0 {
		return policy.DownstreamResponseModifications{}
	}

	body := respCtx.ResponseBody.Content
	if looksLikeSSE(body) {
		slog.Debug(PolicyName+": SSE response passthrough", "status", respCtx.ResponseStatus)
		return policy.DownstreamResponseModifications{}
	}

	slog.Debug(PolicyName+": translating response", "status", respCtx.ResponseStatus)
	return translateResponse(body, respCtx.ResponseStatus,
		effectiveModel(respCtx.SharedContext, p.params.Model))
}

// shouldRun reports whether the request should be translated. When no upstream
// router (e.g. llm-header-router) has published a selected provider into the
// metadata, the proxy is in single-provider mode and the translator always
// runs. When a provider has been selected, the translator runs only if that
// selection matches its own "providerId".
func (p *TranslatorPolicy) shouldRun(reqCtx *policy.RequestContext) bool {
	return p.shouldRunForSelected(selectedProviderFromMetadata(reqCtx.SharedContext, reqCtx.Metadata))
}

func (p *TranslatorPolicy) shouldRunResponse(respCtx *policy.ResponseContext) bool {
	return p.shouldRunForSelected(selectedProviderFromMetadata(respCtx.SharedContext, respCtx.Metadata))
}

func (p *TranslatorPolicy) shouldRunForSelected(selected string) bool {
	if selected == "" {
		// Single-provider mode: no router selected a provider, so run.
		return true
	}
	return strings.EqualFold(selected, p.params.ProviderID)
}

func selectedProviderFromMetadata(shared *policy.SharedContext, metadata map[string]interface{}) string {
	if shared == nil || metadata == nil {
		return ""
	}
	raw, ok := metadata[MetadataKeySelectedProvider]
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
	return "", fmt.Errorf("a Mistral model must be provided in either the policy configuration or request body")
}

func parseParams(params map[string]interface{}) (PolicyParams, error) {
	result := PolicyParams{}

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
