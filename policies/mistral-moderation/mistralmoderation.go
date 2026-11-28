/*
 *  Copyright (c) 2026, WSO2 LLC. (http://www.wso2.org) All Rights Reserved.
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

// Package mistralmoderation moderates request and response content with the Mistral
// moderation API (mistral-moderation-2603): POST /v1/moderations for raw text, or
// POST /v1/chat/moderations for a conversation.
package mistralmoderation

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

// guardrailName identifies this guardrail in GuardrailDetails.InterveningGuardrail and in the
// error response body.
const guardrailName = "mistral-moderation"

const (
	GuardrailErrorCode      = 422
	errorResponseType       = "MISTRAL_MODERATION"
	analyticsGuardrailName  = "MistralModeration"
	requestDefaultJSONPath  = "$.messages[-1].content"
	responseDefaultJSONPath = "$.choices[0].message.content"

	violationReason  = "Violation of Mistral moderation detected."
	extractionReason = "Error extracting value from JSONPath"
	apiErrorReason   = "Error calling Mistral moderation API"
)

// MistralModerationPolicy moderates content with Mistral's moderation API.
type MistralModerationPolicy struct {
	client *moderationClient

	// hasRequestParams and hasResponseParams are true when the phase is configured and enabled.
	hasRequestParams  bool
	hasResponseParams bool
	requestParams     phaseParams
	responseParams    phaseParams
}

// GetPolicy is the v1alpha2 factory entry point (loaded by v1alpha2 kernels).
func GetPolicy(
	metadata policy.PolicyMetadata,
	params map[string]interface{},
) (policy.Policy, error) {
	sys, err := parseSystemConfig(params)
	if err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}

	p := &MistralModerationPolicy{
		client: newModerationClient(sys.endpoint, sys.apiKey, sys.model),
	}

	// A phase that is configured but disabled is still validated, so turning it back on cannot
	// surface a configuration error later.
	configured := false
	if requestParamsRaw, ok := params["request"].(map[string]interface{}); ok {
		requestParams, err := parsePhaseParams(requestParamsRaw, requestDefaultJSONPath)
		if err != nil {
			return nil, fmt.Errorf("invalid request parameters: %w", err)
		}
		configured = true
		p.hasRequestParams = requestParams.Enabled
		p.requestParams = requestParams
	}

	if responseParamsRaw, ok := params["response"].(map[string]interface{}); ok {
		responseParams, err := parsePhaseParams(responseParamsRaw, responseDefaultJSONPath)
		if err != nil {
			return nil, fmt.Errorf("invalid response parameters: %w", err)
		}
		configured = true
		p.hasResponseParams = responseParams.Enabled
		p.responseParams = responseParams
	}

	if !configured {
		return nil, fmt.Errorf("at least one of 'request' or 'response' parameters must be provided")
	}

	slog.Debug("MistralModeration: Policy initialized", "endpoint", sys.endpoint, "model", sys.model,
		"hasRequestParams", p.hasRequestParams, "hasResponseParams", p.hasResponseParams)

	return p, nil
}

// Mode buffers only the phases that are configured. Buffering the response body disables
// streaming for the whole route, so a request-only attachment skips the response body.
func (p *MistralModerationPolicy) Mode() policy.ProcessingMode {
	mode := policy.ProcessingMode{
		RequestHeaderMode:  policy.HeaderModeSkip,
		RequestBodyMode:    policy.BodyModeSkip,
		ResponseHeaderMode: policy.HeaderModeSkip,
		ResponseBodyMode:   policy.BodyModeSkip,
	}
	if p.hasRequestParams {
		mode.RequestBodyMode = policy.BodyModeBuffer
	}
	if p.hasResponseParams {
		mode.ResponseBodyMode = policy.BodyModeBuffer
		// Conversation mode reads the request's messages as context for the reply.
		if p.responseParams.ModerationMode == moderationModeConversation {
			mode.RequestBodyMode = policy.BodyModeBuffer
		}
	}
	return mode
}

// OnRequestBody moderates the request body before it reaches the upstream.
func (p *MistralModerationPolicy) OnRequestBody(ctx context.Context, reqCtx *policy.RequestContext, _ map[string]interface{}) policy.RequestAction {
	if !p.hasRequestParams {
		return policy.UpstreamRequestModifications{}
	}
	var content []byte
	if reqCtx.Body != nil {
		content = reqCtx.Body.Content
	}
	return p.moderate(ctx, content, nil, p.requestParams, false).(policy.RequestAction)
}

// OnResponseBody moderates the upstream's response before it reaches the client. An upstream
// error response carries no model output, so it is passed through unmoderated rather than
// being masked by a JSONPath extraction failure.
func (p *MistralModerationPolicy) OnResponseBody(ctx context.Context, respCtx *policy.ResponseContext, _ map[string]interface{}) policy.ResponseAction {
	if !p.hasResponseParams {
		return policy.DownstreamResponseModifications{}
	}
	if status := respCtx.ResponseStatus; status != 0 && (status < 200 || status >= 300) {
		slog.Debug("MistralModeration: Upstream response is not a success, skipping moderation", "status", status)
		return policy.DownstreamResponseModifications{}
	}
	var content, requestContent []byte
	if respCtx.ResponseBody != nil {
		content = respCtx.ResponseBody.Content
	}
	if respCtx.RequestBody != nil {
		requestContent = respCtx.RequestBody.Content
	}
	return p.moderate(ctx, content, requestContent, p.responseParams, true).(policy.ResponseAction)
}

// moderate runs one phase's check and returns the phase's action: a pass-through, or an error
// response that declares its fault. requestPayload is the original request body, read on the
// response phase in conversation mode as context for the reply.
func (p *MistralModerationPolicy) moderate(ctx context.Context, payload, requestPayload []byte, params phaseParams, isResponse bool) interface{} {
	if len(params.Thresholds) == 0 {
		slog.Debug("MistralModeration: No categories enabled, passing through", "isResponse", isResponse)
		return passThrough(isResponse)
	}
	if len(payload) == 0 {
		return passThrough(isResponse)
	}

	var result *moderationResult
	var err error
	if params.ModerationMode == moderationModeConversation {
		messages, ok, extractErr := buildConversation(payload, requestPayload, params, isResponse)
		if extractErr != nil {
			return handleExtractionFailure(extractErr, params, isResponse)
		}
		if !ok {
			slog.Debug("MistralModeration: Conversation has no message to classify, skipping moderation", "isResponse", isResponse)
			return passThrough(isResponse)
		}
		result, err = p.client.moderateChat(ctx, messages, params.Timeout)
	} else {
		var text string
		var extractErr error
		if isResponse {
			text, extractErr = extractReply(payload, params)
		} else {
			text, extractErr = extractText(payload, params.JSONPath)
		}
		if extractErr != nil {
			return handleExtractionFailure(extractErr, params, isResponse)
		}
		text = strings.TrimSpace(text)
		// Mistral rejects an empty input with HTTP 400, and there is nothing to moderate.
		if text == "" {
			slog.Debug("MistralModeration: Extracted content is empty, skipping moderation", "isResponse", isResponse)
			return passThrough(isResponse)
		}
		result, err = p.client.moderate(ctx, text, params.Timeout)
	}
	if err != nil {
		return p.handleCheckFailure(err, params, isResponse)
	}

	eval, err := evaluateThresholds(params.Thresholds, result)
	if err != nil {
		return p.handleCheckFailure(&serviceError{Kind: errKindInvalidResponse, Err: err}, params, isResponse)
	}

	if !eval.violated() {
		slog.Debug("MistralModeration: Validation passed", "isResponse", isResponse)
		return passThrough(isResponse)
	}

	slog.Debug("MistralModeration: Violation detected", "categories", eval.categoryNames(), "isResponse", isResponse)
	var assessments map[string]interface{}
	if params.ShowAssessment {
		assessments = violationAssessments(eval)
	}
	body := errorBody(violationReason, isResponse, assessmentsOrNil(assessments))
	return errorAction(body, isResponse, violationFault(eval, isResponse, assessments))
}

// buildConversation assembles the conversation for /v1/chat/moderations. ok is false when
// there is no message to classify.
//
// On the request, the conversation is the request's messages, and Mistral classifies the last
// one (normally the new user turn) in the context of the earlier ones.
//
// On the response, the reply at jsonPath is appended as an assistant message to the request's
// messages, so the reply is judged against the prompt that produced it. The request's
// messages are context only: when they cannot be read the reply is classified on its own,
// rather than failing a check whose subject, the reply, was read.
func buildConversation(payload, requestPayload []byte, params phaseParams, isResponse bool) (messages []chatMessage, ok bool, err error) {
	if !isResponse {
		messages, lastHasText, err := extractConversation(payload, params.MessagesPath)
		if err != nil {
			return nil, false, err
		}
		return messages, lastHasText && hasClassifiableTurn(messages), nil
	}

	reply, err := extractReply(payload, params)
	if err != nil {
		return nil, false, err
	}
	if strings.TrimSpace(reply) == "" {
		return nil, false, nil
	}
	if len(requestPayload) > 0 {
		history, _, ctxErr := extractConversation(requestPayload, params.MessagesPath)
		if ctxErr != nil {
			slog.Debug("MistralModeration: Request messages unreadable, classifying the reply without context", "messagesPath", params.MessagesPath, "error", ctxErr)
		} else {
			messages = history
		}
	}
	return append(messages, chatMessage{Role: "assistant", Content: reply}), true, nil
}

// handleExtractionFailure applies passthroughOnError to content that could not be read.
func handleExtractionFailure(err error, params phaseParams, isResponse bool) interface{} {
	if params.PassthroughOnError {
		slog.Debug("MistralModeration: Content extraction error, passthrough enabled", "error", err, "isResponse", isResponse)
		return passThrough(isResponse)
	}
	slog.Debug("MistralModeration: Error extracting content", "error", err, "isResponse", isResponse)
	body := errorBody(extractionReason, isResponse, assessmentsForError(params.ShowAssessment, "The content to moderate could not be read from the payload"))
	return errorAction(body, isResponse, extractionFault(err, isResponse))
}

// handleCheckFailure applies passthroughOnError to a check that produced no verdict. It never
// sees a violation, so passthroughOnError cannot let violating content through.
func (p *MistralModerationPolicy) handleCheckFailure(err error, params phaseParams, isResponse bool) interface{} {
	clientMessage := (&serviceError{Kind: errKindInvalidResponse}).ClientMessage()
	var svcErr *serviceError
	if errors.As(err, &svcErr) {
		clientMessage = svcErr.ClientMessage()
	}
	if params.PassthroughOnError {
		slog.Debug("MistralModeration: API call error, passthrough enabled", "error", err, "isResponse", isResponse)
		return passThrough(isResponse)
	}
	slog.Debug("MistralModeration: Error calling Mistral moderation API", "error", err, "isResponse", isResponse)
	body := errorBody(apiErrorReason, isResponse, assessmentsForError(params.ShowAssessment, clientMessage))
	return errorAction(body, isResponse, checkFailureFault(clientMessage, isResponse))
}

func passThrough(isResponse bool) interface{} {
	if isResponse {
		return policy.DownstreamResponseModifications{}
	}
	return policy.UpstreamRequestModifications{}
}

// errorAction wraps an error body in the phase's action and declares the fault.
func errorAction(body []byte, isResponse bool, fault *policy.FaultDetails) interface{} {
	analyticsMetadata := map[string]interface{}{
		"isGuardrailHit": true,
		"guardrailName":  analyticsGuardrailName,
	}
	if isResponse {
		statusCode := GuardrailErrorCode
		return policy.DownstreamResponseModifications{
			StatusCode:        &statusCode,
			Body:              body,
			AnalyticsMetadata: analyticsMetadata,
			HeadersToSet: map[string]string{
				"Content-Type": "application/json",
			},
			IsFault: true,
			Fault:   fault,
		}
	}
	return policy.ImmediateResponse{
		StatusCode:        GuardrailErrorCode,
		AnalyticsMetadata: analyticsMetadata,
		Headers: map[string]string{
			"Content-Type": "application/json",
		},
		Body:    body,
		IsFault: true,
		Fault:   fault,
	}
}

// errorBody builds the client-facing error body. It never holds the moderated content, the
// endpoint, the key or the service's own error text.
func errorBody(reason string, isResponse bool, assessments interface{}) []byte {
	message := map[string]interface{}{
		"action":               policy.GuardrailActionIntervened,
		"interveningGuardrail": guardrailName,
		"direction":            directionLabel(isResponse),
		"actionReason":         reason,
	}
	if assessments != nil {
		message["assessments"] = assessments
	}
	bodyBytes, err := json.Marshal(map[string]interface{}{
		"type":    errorResponseType,
		"message": message,
	})
	if err != nil {
		return []byte(`{"type":"MISTRAL_MODERATION","message":"Internal error"}`)
	}
	return bodyBytes
}

func directionLabel(isResponse bool) string {
	if isResponse {
		return "RESPONSE"
	}
	return "REQUEST"
}

func faultDirection(isResponse bool) string {
	if isResponse {
		return policy.DirectionResponse
	}
	return policy.DirectionRequest
}

// violationAssessments lists the violating categories with their scores and thresholds. It
// deliberately leaves out the inspected content.
func violationAssessments(eval evaluation) map[string]interface{} {
	categories := make([]map[string]interface{}, 0, len(eval.Violations))
	for _, v := range eval.Violations {
		categories = append(categories, map[string]interface{}{
			"category":  v.Category,
			"score":     v.Score,
			"threshold": v.Threshold,
			"result":    "FAIL",
		})
	}
	return map[string]interface{}{"categories": categories}
}

// assessmentsOrNil keeps a nil map from marshalling as "assessments": null.
func assessmentsOrNil(assessments map[string]interface{}) interface{} {
	if assessments == nil {
		return nil
	}
	return assessments
}

func assessmentsForError(showAssessment bool, message string) interface{} {
	if !showAssessment {
		return nil
	}
	return []string{message}
}

// violationFault describes a guardrail verdict. The highest-scoring violating category
// decides the code.
func violationFault(eval evaluation, isResponse bool, assessments map[string]interface{}) *policy.FaultDetails {
	guardrail := &policy.GuardrailDetails{
		InterveningGuardrail: guardrailName,
		Action:               policy.GuardrailActionIntervened,
		ActionReason:         violationReason,
	}
	// Populated only where the operator opted in through showAssessment, the same gate the
	// response body uses.
	if assessments != nil {
		guardrail.Assessments = assessments
	}
	return &policy.FaultDetails{
		Code:        guardrailCodeFor(eval.Violations[0].Category),
		Type:        policy.FaultTypeGuardrail,
		Direction:   faultDirection(isResponse),
		Message:     "Content moderation guardrail intervened",
		Description: fmt.Sprintf("Mistral moderation threshold reached for: %s", strings.Join(eval.categoryNames(), ", ")),
		Guardrail:   guardrail,
	}
}

// extractionFault describes a rejection made because the value at jsonPath could not be read,
// so no check ran. On a request the payload is the caller's, so it is an invalid request body;
// on a response it is the upstream's, and the policy could not do its job.
func extractionFault(err error, isResponse bool) *policy.FaultDetails {
	if isResponse {
		return &policy.FaultDetails{
			Code:        policy.FaultCodeMediationFailed,
			Type:        policy.FaultTypeMediation,
			Direction:   policy.DirectionResponse,
			Message:     "The response body could not be read for the guardrail check",
			Description: extractionReason + ": " + err.Error(),
		}
	}
	return &policy.FaultDetails{
		Code:        policy.FaultCodeInvalidRequestBody,
		Type:        policy.FaultTypeValidation,
		Direction:   policy.DirectionRequest,
		Message:     "The request body could not be read for the guardrail check",
		Description: extractionReason + ": " + err.Error(),
	}
}

// checkFailureFault describes a rejection made because the moderation call produced no
// verdict. Description carries the client-safe classification only; the raw error, which
// can name the endpoint, stays in the debug log.
func checkFailureFault(clientMessage string, isResponse bool) *policy.FaultDetails {
	return &policy.FaultDetails{
		Code:        policy.FaultCodeMediationFailed,
		Type:        policy.FaultTypeMediation,
		Direction:   faultDirection(isResponse),
		Message:     "The guardrail check could not be completed",
		Description: apiErrorReason + ": " + clientMessage,
	}
}
