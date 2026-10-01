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

// Package mcptoolpoisoningguardrail inspects MCP tools/list responses for tool
// poisoning — instructions hidden in tool metadata that target the agent rather
// than describing the tool — and filters, blocks or flags them before the
// metadata reaches the client.
//
// The model does not run in the gateway. Tool metadata text is sent to a
// separately deployed classifier service (POST {endpoint}/classify) that serves
// the wso2/tool-poisoning-detection SetFit model; static detectors run locally.
//
// Discovery filtering is not authorization: removing a tool from a tools/list
// response hides it from the client, it does not stop a client that already
// knows the name from calling it. Tool execution permissions must be enforced
// by the MCP access-control policies (mcp-acl-list, mcp-authz).
//
// Concurrency: the gateway shares one policy instance across every request on
// the route. The instance holds only immutable configuration and the classifier
// client; all per-request state lives in locals of the phase callbacks, and the
// only state carried from the request phase to the response phase travels in
// that request's own SharedContext.Metadata.
package mcptoolpoisoningguardrail

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

const policyDisplayName = "MCP Tool Poisoning Guardrail"

// Metadata keys used to correlate a tools/list request with its response.
// Namespaced to this policy so it never depends on, or interferes with, the
// keys other MCP policies publish.
const (
	metadataInspectKey   = "mcp.toolPoisoning.inspect"
	metadataRequestIDKey = "mcp.toolPoisoning.requestID"
	metadataBatchKey     = "mcp.toolPoisoning.batch"
)

// JSON-RPC error codes returned by this policy. -32000 onwards is the
// implementation-defined server error range; -32603 is the reserved internal
// error code. They are deliberately distinct: a client, an operator and an
// alert rule must be able to tell a poisoning verdict from an outage.
const (
	// jsonRPCCodePoisoning: poisoning was detected and the action blocks it.
	jsonRPCCodePoisoning = -32000
	// jsonRPCCodeInspectionUnavailable: inspection could not run or complete —
	// classifier failure, timeout, cancellation, a missing body, a batch.
	jsonRPCCodeInspectionUnavailable = -32001
	// jsonRPCCodeMalformedResponse: the response could not safely be processed.
	jsonRPCCodeMalformedResponse = -32603
)

// Analytics metadata keys.
const (
	analyticsErrorCodeKey         = "mcpErrorCode"
	analyticsActionKey            = "mcpToolPoisoningAction"
	analyticsAppliedKey           = "mcpToolPoisoningApplied"
	analyticsInspectionKey        = "mcpToolPoisoningInspection"
	analyticsInspectedToolsKey    = "mcpToolPoisoningInspectedTools"
	analyticsViolationsKey        = "mcpToolPoisoningViolations"
	analyticsRemovedToolsKey      = "mcpToolPoisoningRemovedTools"
	analyticsModelKey             = "mcpToolPoisoningModel"
	analyticsRevisionKey          = "mcpToolPoisoningModelRevision"
	analyticsLatencyKey           = "mcpToolPoisoningLatencyMs"
	analyticsDegradedKey          = "mcpToolPoisoningDegraded"
	analyticsClassifierActionKey  = "mcpToolPoisoningClassifierAction"
	analyticsModelDetectionsKey   = "mcpToolPoisoningModelDetections"
	analyticsAdvisoryDetectionKey = "mcpToolPoisoningAdvisoryDetections"
)

// Inspection states recorded in analytics. An inspection that could not be
// completed is never recorded as safe.
const (
	inspectionCompleted = "completed"
	inspectionDegraded  = "degraded"
	inspectionFailed    = "failed"
)

// Applied outcomes recorded in analytics.
const (
	appliedNone      = "none"
	appliedFiltered  = "filtered"
	appliedBlocked   = "blocked"
	appliedFlagged   = "flagged"
	appliedPreserved = "preserved"
)

// executorDeadlineMargin is kept back from the gateway's own deadline for the
// request, so that a slow classifier produces this policy's JSON-RPC error
// rather than a gateway timeout.
const executorDeadlineMargin = 250 * time.Millisecond

// McpToolPoisoningGuardrailPolicy inspects MCP tool discovery metadata.
type McpToolPoisoningGuardrailPolicy struct {
	params     PolicyParams
	system     SystemParams
	classifier *classifierClient
}

// GetPolicy is the v1alpha2 factory entry point. Invalid configuration fails
// here, so the deployment is rejected instead of running with a silent
// fallback. Errors never contain the API key.
func GetPolicy(
	metadata policy.PolicyMetadata,
	params map[string]interface{},
) (policy.Policy, error) {
	systemParams, err := parseSystemParams(params)
	if err != nil {
		return nil, fmt.Errorf("invalid system configuration: %w", err)
	}

	policyParams, err := parsePolicyParams(params)
	if err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	slog.Debug("MCP Tool Poisoning Guardrail Policy: Parsed configuration",
		"action", policyParams.Action,
		"classifierAction", policyParams.ClassifierAction,
		"classifierThreshold", policyParams.ClassifierThreshold,
		"onClassifierError", policyParams.OnClassifierError,
		"showAssessment", policyParams.ShowAssessment,
		"staticDetectorsEnabled", policyParams.Static.Enabled,
		"staticDetectorSeverity", policyParams.Static.MinSeverity,
		"endpoint", systemParams.Endpoint,
		"requestTimeout", systemParams.RequestTimeout,
		"classificationDeadline", systemParams.ClassificationDeadline,
		"batchSize", systemParams.BatchSize,
		"maxConcurrentBatches", systemParams.MaxConcurrentBatches)

	return &McpToolPoisoningGuardrailPolicy{
		params:     policyParams,
		system:     systemParams,
		classifier: newClassifierClient(systemParams),
	}, nil
}

// Mode buffers both bodies: the request body carries the tools/list method that
// selects a response for inspection, and the response body carries the metadata.
func (p *McpToolPoisoningGuardrailPolicy) Mode() policy.ProcessingMode {
	return policy.ProcessingMode{
		RequestHeaderMode:  policy.HeaderModeSkip,
		RequestBodyMode:    policy.BodyModeBuffer,
		ResponseHeaderMode: policy.HeaderModeSkip,
		ResponseBodyMode:   policy.BodyModeBuffer,
	}
}

// OnRequestBody recognises tools/list requests and records the JSON-RPC id so
// the response phase can correlate the matching response. The request itself is
// never modified or rejected by this policy.
func (p *McpToolPoisoningGuardrailPolicy) OnRequestBody(_ context.Context, reqCtx *policy.RequestContext, _ map[string]any) policy.RequestAction {
	passthrough := policy.UpstreamRequestModifications{}
	if reqCtx == nil || reqCtx.SharedContext == nil {
		return passthrough
	}

	downstream := reqCtx.DownstreamRequest()
	method := downstream.Method
	if method == "" {
		method = reqCtx.Method
	}
	if !isMcpPostRequest(method, reqCtx.OperationPath) {
		return passthrough
	}
	if reqCtx.Body == nil || len(reqCtx.Body.Content) == 0 {
		return passthrough
	}

	// Read the framing from the downstream snapshot so the request is parsed
	// the way the client actually sent it, not the way a peer policy rewrote it.
	headers := downstream.Headers
	if headers == nil {
		headers = reqCtx.Headers
	}
	payload, err := parseRequestPayload(reqCtx.Body.Content, isEventStream(headers))
	if err != nil {
		slog.Debug("MCP Tool Poisoning Guardrail Policy: Request body is not a JSON-RPC payload")
		return passthrough
	}

	if reqCtx.Metadata == nil {
		reqCtx.Metadata = make(map[string]any)
	}

	switch typed := payload.(type) {
	case []any:
		// A JSON-RPC batch. Its response is an array this policy does not
		// rewrite, so a batch containing tools/list is marked and then handled
		// as uninspectable instead of passing through unseen.
		for _, entry := range typed {
			if isToolsListRequest(entry) {
				reqCtx.Metadata[metadataInspectKey] = true
				reqCtx.Metadata[metadataBatchKey] = true
				reqCtx.Metadata[metadataRequestIDKey] = "null"
				slog.Debug("MCP Tool Poisoning Guardrail Policy: JSON-RPC batch containing tools/list marked as uninspectable")
				break
			}
		}
	case map[string]any:
		if !isToolsListRequest(typed) {
			return passthrough
		}
		encodedID, ok := encodeJSONRPCID(typed)
		if !ok {
			// A notification: no response will come back.
			slog.Debug("MCP Tool Poisoning Guardrail Policy: tools/list has no JSON-RPC id, skipping correlation")
			return passthrough
		}
		reqCtx.Metadata[metadataInspectKey] = true
		reqCtx.Metadata[metadataRequestIDKey] = encodedID
		slog.Debug("MCP Tool Poisoning Guardrail Policy: tools/list request marked for response inspection",
			"requestID", logSafe(encodedID))
	}
	return passthrough
}

// OnResponseBody inspects the correlated tools/list response before its tool
// metadata is delivered to the client.
func (p *McpToolPoisoningGuardrailPolicy) OnResponseBody(ctx context.Context, respCtx *policy.ResponseContext, _ map[string]any) (action policy.ResponseAction) {
	if respCtx == nil || respCtx.SharedContext == nil {
		return nil
	}
	downstream := respCtx.DownstreamRequest()
	method := downstream.Method
	if method == "" {
		method = respCtx.RequestMethod
	}
	if !isMcpPostRequest(method, respCtx.OperationPath) {
		return nil
	}
	if inspect, _ := respCtx.Metadata[metadataInspectKey].(bool); !inspect {
		return nil
	}
	encodedRequestID, _ := respCtx.Metadata[metadataRequestIDKey].(string)
	if encodedRequestID == "" {
		return nil
	}

	upstream := respCtx.UpstreamResponse()
	status := upstream.StatusCode
	if status == 0 {
		status = respCtx.ResponseStatus
	}
	// Transport-level failures are the upstream's answer, not tool metadata.
	if status < 200 || status > 299 {
		slog.Debug("MCP Tool Poisoning Guardrail Policy: Upstream returned a non-2xx status, passing through",
			"status", status)
		return nil
	}

	responseHeaders := upstream.Headers
	if responseHeaders == nil {
		responseHeaders = respCtx.ResponseHeaders
	}
	sse := isEventStream(responseHeaders)
	sessionID := getSessionID(responseHeaders)
	if sessionID == "" {
		requestHeaders := downstream.Headers
		if requestHeaders == nil {
			requestHeaders = respCtx.RequestHeaders
		}
		sessionID = getSessionID(requestHeaders)
	}
	requestID := requestIDForEcho(encodedRequestID)

	// Never deliver an uninspected response because of a bug. Only the panic
	// value's type is logged: its message could quote tool metadata.
	defer func() {
		if recovered := recover(); recovered != nil {
			slog.Error("MCP Tool Poisoning Guardrail Policy: Unexpected error while inspecting tools/list",
				"panic", fmt.Sprintf("%T", recovered))
			action = p.handleUninspectable(sse, sessionID, requestID,
				jsonRPCCodeInspectionUnavailable,
				"MCP tool metadata inspection unavailable",
				"Tool metadata inspection is unavailable.",
				fmt.Sprintf("unexpected %T", recovered))
		}
	}()

	return p.inspectResponse(ctx, respCtx, sse, sessionID, requestID, encodedRequestID)
}

func (p *McpToolPoisoningGuardrailPolicy) inspectResponse(
	ctx context.Context,
	respCtx *policy.ResponseContext,
	sse bool,
	sessionID string,
	requestID rawJSON,
	encodedRequestID string,
) policy.ResponseAction {
	if batch, _ := respCtx.Metadata[metadataBatchKey].(bool); batch {
		return p.handleUninspectable(sse, sessionID, "null",
			jsonRPCCodeInspectionUnavailable,
			"MCP tool metadata inspection unavailable",
			"JSON-RPC batch tools/list responses are not inspected.",
			"tools/list was sent in a JSON-RPC batch")
	}

	if respCtx.ResponseBody == nil || !respCtx.ResponseBody.Present {
		// The kernel did not hand this policy a body to inspect. Whatever the
		// cause, the tool metadata in this response was not inspected, so it is
		// preserved and recorded under flag and refused under filter and block.
		return p.handleUninspectable(sse, sessionID, requestID,
			jsonRPCCodeInspectionUnavailable,
			"MCP tool metadata inspection unavailable",
			"The tools/list response body was not available for inspection.",
			"tools/list response body unavailable")
	}

	// Bound the raw body before decoding it. Every other limit is applied to
	// extracted text, which a response can avoid contributing to entirely: an
	// upstream returning millions of numeric or empty members produces no text
	// fields at all, yet still costs a full decode and walk.
	content := respCtx.ResponseBody.Content
	if size := len(content); size > p.system.MaxResponseBytes {
		return p.handleUninspectable(sse, sessionID, requestID,
			jsonRPCCodeMalformedResponse,
			"Malformed MCP tools/list response",
			"The tools/list response was too large to inspect.",
			fmt.Sprintf("tools/list response of %d bytes exceeds the %d byte inspection limit", size, p.system.MaxResponseBytes))
	}

	target, err := locateResponsePayload(content, sse, encodedRequestID)
	if err != nil {
		return p.handleMalformed(sse, sessionID, requestID, err.Error())
	}

	if isJSONRPCError(target.payload) {
		slog.Debug("MCP Tool Poisoning Guardrail Policy: Upstream returned a JSON-RPC error, passing through")
		return nil
	}

	result, ok := target.payload["result"].(map[string]any)
	if !ok {
		return p.handleMalformed(sse, sessionID, requestID, "tools/list response has no result object")
	}
	toolsRaw, exists := result[resultToolsKey]
	if !exists {
		return p.handleMalformed(sse, sessionID, requestID, "tools/list result has no tools array")
	}
	tools, ok := toolsRaw.([]any)
	if !ok {
		return p.handleMalformed(sse, sessionID, requestID, "tools/list result tools is not an array")
	}

	inspectCtx, cancel := p.classificationContext(ctx)
	defer cancel()

	outcome, err := p.inspect(inspectCtx, tools)
	if err != nil {
		slog.Warn("MCP Tool Poisoning Guardrail Policy: Refusing tools/list response, inspection could not complete",
			"error", err.Error())
		var data any
		if p.params.ShowAssessment {
			data = orderedObject{
				{"interveningGuardrail", policyDisplayName},
				{"actionReason", "Tool metadata inspection is unavailable."},
				{"action", p.params.Action},
				{"onClassifierError", p.params.OnClassifierError},
			}
		}
		return buildErrorResponse(sse, sessionID, jsonRPCCodeInspectionUnavailable,
			"MCP tool metadata inspection unavailable", requestID, data,
			map[string]any{
				analyticsErrorCodeKey:  jsonRPCCodeInspectionUnavailable,
				analyticsActionKey:     p.params.Action,
				analyticsAppliedKey:    appliedBlocked,
				analyticsInspectionKey: inspectionFailed,
				analyticsDegradedKey:   true,
			})
	}

	return p.enforce(outcome, target, tools, sse, sessionID, requestID)
}

// classificationContext derives the single classification deadline for one
// response: classificationDeadlineMillis from now, but never later than the
// gateway's own deadline for the request less a small margin, so the policy
// answers with its JSON-RPC error before the gateway gives up on it.
// Cancellation of ctx propagates.
func (p *McpToolPoisoningGuardrailPolicy) classificationContext(ctx context.Context) (context.Context, context.CancelFunc) {
	deadline := time.Now().Add(p.system.ClassificationDeadline)
	if gatewayDeadline, ok := ctx.Deadline(); ok {
		if bounded := gatewayDeadline.Add(-executorDeadlineMargin); bounded.Before(deadline) {
			deadline = bounded
		}
	}
	return context.WithDeadline(ctx, deadline)
}

// enforce applies the configured action to an inspected tools/list response.
func (p *McpToolPoisoningGuardrailPolicy) enforce(
	outcome inspectionOutcome,
	target responseTarget,
	tools []any,
	sse bool,
	sessionID string,
	requestID rawJSON,
) policy.ResponseAction {
	if outcome.ViolationCount == 0 {
		p.logOutcome(outcome, appliedNone)
		return policy.DownstreamResponseModifications{
			AnalyticsMetadata: p.analytics(outcome, appliedNone, 0),
		}
	}

	switch p.params.Action {
	case ActionFlag:
		p.logOutcome(outcome, appliedFlagged)
		return policy.DownstreamResponseModifications{
			AnalyticsMetadata: p.analytics(outcome, appliedFlagged, 0),
		}

	case ActionBlock:
		p.logOutcome(outcome, appliedBlocked)
		var data any
		if p.params.ShowAssessment {
			data = p.assessment(outcome, "Tool poisoning detected in MCP tool metadata.")
		}
		analytics := p.analytics(outcome, appliedBlocked, 0)
		analytics[analyticsErrorCodeKey] = jsonRPCCodePoisoning
		return buildErrorResponse(sse, sessionID, jsonRPCCodePoisoning,
			"MCP tool metadata failed tool poisoning inspection", requestID, data, analytics)

	default: // ActionFilter
		violating := outcome.violatingIndexes()
		body, err := target.rebuild(violating, len(tools))
		if err != nil {
			slog.Error("MCP Tool Poisoning Guardrail Policy: Failed to rebuild the filtered response",
				"error", err.Error())
			analytics := p.analytics(outcome, appliedBlocked, 0)
			analytics[analyticsErrorCodeKey] = jsonRPCCodeMalformedResponse
			analytics[analyticsInspectionKey] = inspectionFailed
			return buildErrorResponse(sse, sessionID, jsonRPCCodeMalformedResponse,
				"Failed to rewrite the MCP tools/list response", requestID, nil, analytics)
		}

		p.logOutcome(outcome, appliedFiltered)
		return policy.DownstreamResponseModifications{
			Body:              body,
			AnalyticsMetadata: p.analytics(outcome, appliedFiltered, len(violating)),
		}
	}
}

// handleMalformed decides what to do with a tools/list response the guardrail
// cannot read.
func (p *McpToolPoisoningGuardrailPolicy) handleMalformed(sse bool, sessionID string, requestID rawJSON, cause string) policy.ResponseAction {
	return p.handleUninspectable(sse, sessionID, requestID,
		jsonRPCCodeMalformedResponse,
		"Malformed MCP tools/list response",
		"The tools/list response could not be inspected.",
		cause)
}

// handleUninspectable decides what to do with a correlated tools/list response
// whose tool metadata could not be inspected at all. Enforcement actions refuse
// it, since an uninspected response cannot be certified safe and forwarding it
// would defeat the action; flag preserves it and records the failure. In
// neither case is the inspection recorded as having completed.
func (p *McpToolPoisoningGuardrailPolicy) handleUninspectable(
	sse bool,
	sessionID string,
	requestID rawJSON,
	code int,
	message string,
	reason string,
	cause string,
) policy.ResponseAction {
	analytics := map[string]any{
		analyticsActionKey:     p.params.Action,
		analyticsInspectionKey: inspectionFailed,
		analyticsDegradedKey:   true,
	}

	if p.params.Action == ActionFlag {
		slog.Warn("MCP Tool Poisoning Guardrail Policy: tools/list response could not be inspected, preserving it in flag mode",
			"cause", cause)
		analytics[analyticsAppliedKey] = appliedPreserved
		return policy.DownstreamResponseModifications{AnalyticsMetadata: analytics}
	}

	slog.Warn("MCP Tool Poisoning Guardrail Policy: Refusing an uninspectable tools/list response",
		"cause", cause,
		"action", p.params.Action)
	analytics[analyticsAppliedKey] = appliedBlocked
	analytics[analyticsErrorCodeKey] = code

	var data any
	if p.params.ShowAssessment {
		data = orderedObject{
			{"interveningGuardrail", policyDisplayName},
			{"actionReason", reason},
			{"action", p.params.Action},
		}
	}
	return buildErrorResponse(sse, sessionID, code, message, requestID, data, analytics)
}

// analytics renders the structured record of one inspection.
func (p *McpToolPoisoningGuardrailPolicy) analytics(outcome inspectionOutcome, applied string, removed int) map[string]any {
	inspection := inspectionCompleted
	if outcome.Degraded() {
		inspection = inspectionDegraded
	}

	analytics := map[string]any{
		analyticsActionKey:           p.params.Action,
		analyticsClassifierActionKey: p.params.ClassifierAction,
		analyticsAppliedKey:          applied,
		analyticsInspectionKey:       inspection,
		analyticsInspectedToolsKey:   outcome.InspectedTools,
		analyticsViolationsKey:       outcome.ViolationCount,
		// Model detections are recorded whether or not they enforced, so an
		// operator running the default flag mode can see what the model would
		// have removed before opting into enforcement.
		analyticsModelDetectionsKey:   outcome.ModelDetections,
		analyticsAdvisoryDetectionKey: outcome.AdvisoryDetections,
		analyticsLatencyKey:           outcome.LatencyMs,
		analyticsDegradedKey:          outcome.Degraded(),
	}
	if removed > 0 {
		analytics[analyticsRemovedToolsKey] = removed
	}
	if outcome.Model != "" {
		analytics[analyticsModelKey] = outcome.Model
		analytics[analyticsRevisionKey] = outcome.Revision
	}
	return analytics
}

// responseTarget is the located JSON-RPC payload inside a response body,
// together with everything needed to write it back in the original framing.
type responseTarget struct {
	payload map[string]any
	// source is the JSON text the payload was decoded from: the whole body, or
	// the answering event's data.
	source string
	layout jsonLayout
	// events is nil for JSON framing.
	events     []sseEvent
	eventIndex int
}

// rebuild writes the response back without the removed result.tools entries.
//
// The tools array is rebuilt from the upstream's own bytes for every kept
// entry, and everything outside the array is left byte for byte as received —
// the JSON-RPC id, pagination cursors, number literals and unrelated fields
// cannot be rewritten because they are never re-encoded. In an event stream only
// the answering event is rewritten; every other event, and its framing, is
// written back exactly as received.
func (t responseTarget) rebuild(removed map[int]struct{}, toolCount int) ([]byte, error) {
	if !t.layout.hasTools || len(t.layout.toolEntries) != toolCount {
		return nil, errors.New("the tools array could not be located in the response")
	}

	var builder strings.Builder
	builder.Grow(len(t.source))
	builder.WriteString(t.source[:t.layout.tools.start])
	builder.WriteByte('[')
	written := 0
	for index, entry := range t.layout.toolEntries {
		if _, remove := removed[index]; remove {
			continue
		}
		if written > 0 {
			builder.WriteByte(',')
		}
		builder.WriteString(t.source[entry.start:entry.end])
		written++
	}
	builder.WriteByte(']')
	builder.WriteString(t.source[t.layout.tools.end:])
	data := builder.String()

	if t.events == nil {
		return []byte(data), nil
	}
	var stream strings.Builder
	for index, event := range t.events {
		if index == t.eventIndex {
			stream.WriteString(buildEvent(event, data))
			continue
		}
		stream.WriteString(event.raw)
	}
	return []byte(stream.String()), nil
}

// locateResponsePayload finds the JSON-RPC payload that answers the recorded
// request id.
//
// An event stream may carry unrelated events — notifications, pings, progress —
// so only the event whose id matches is a candidate. Exactly one event may
// answer: if a second one does, or one that cannot be read strictly (duplicate
// keys) does, or a batch array carries the answer, or one carries an id a
// client could coerce onto the recorded one (see payloadMayBeConfused), a
// client could act on metadata this policy did not inspect, so the stream is
// refused as malformed.
func locateResponsePayload(body []byte, sse bool, encodedRequestID string) (responseTarget, error) {
	if !sse {
		payload, layout, err := decodeJSONObject(string(body), false)
		if err != nil {
			return responseTarget{}, err
		}
		if !matchesJSONRPCID(payload, encodedRequestID) {
			return responseTarget{}, malformed("response JSON-RPC id does not match the tools/list request")
		}
		return responseTarget{payload: payload, source: string(body), layout: layout, eventIndex: -1}, nil
	}

	events, err := parseEventStream(string(body))
	if err != nil {
		return responseTarget{}, err
	}

	var answering []responseTarget
	ambiguous := false
	for index, event := range events {
		if event.data == "" {
			continue
		}
		value, layout, err := decodeJSON(event.data, false)
		if err != nil {
			lenient, _, lenientErr := decodeJSON(event.data, true)
			if lenientErr == nil && (payloadAnswers(lenient, encodedRequestID) || payloadMayBeConfused(lenient, encodedRequestID)) {
				ambiguous = true
			}
			continue
		}
		if object, ok := value.(map[string]any); ok && matchesJSONRPCID(object, encodedRequestID) {
			answering = append(answering, responseTarget{
				payload: object, source: event.data, layout: layout, events: events, eventIndex: index,
			})
		} else if payloadAnswers(value, encodedRequestID) || payloadMayBeConfused(value, encodedRequestID) {
			ambiguous = true
		}
	}

	if ambiguous || len(answering) > 1 {
		return responseTarget{}, malformed("more than one event in the stream could answer the tools/list request")
	}
	if len(answering) == 0 {
		return responseTarget{}, malformed("no event in the stream answers the tools/list request id")
	}
	return answering[0], nil
}

// payloadMayBeConfused reports whether a decoded value is, or contains, a
// JSON-RPC response that a client could read as the answer to the recorded
// request even though its id is not the recorded literal.
//
// This is the weaker test payloadAnswers cannot make. This policy compares ids
// as exact JSON literals, which is the strictest reading; a client need not.
// The MCP TypeScript SDK correlates with Number(response.id), so `5.0`, `5e0`
// and the string `"5"` all answer a request this policy recorded as `5`. Such
// an event is not the exact match, so it would be passed through uninspected
// while the client acted on it. Treat it as a second possible answer instead.
//
// An id that no coercion brings to the recorded one — a response to a genuinely
// different request — is unaffected: a stream may carry those, and they are not
// this policy's to rewrite.
func payloadMayBeConfused(value any, encodedRequestID string) bool {
	switch typed := value.(type) {
	case map[string]any:
		return idMayBeConfused(typed, encodedRequestID)
	case []any:
		for _, entry := range typed {
			if object, ok := entry.(map[string]any); ok && idMayBeConfused(object, encodedRequestID) {
				return true
			}
		}
	}
	return false
}

// idMayBeConfused reports whether one payload's id could be coerced onto the
// recorded id. The exact match is not confusable — it is the answer.
func idMayBeConfused(payload map[string]any, encodedRequestID string) bool {
	// Only a response competes to be the answer. A server-initiated request or
	// a notification carries method, and a client routes it by that.
	if _, isRequest := payload["method"]; isRequest {
		return false
	}
	_, hasResult := payload["result"]
	_, hasError := payload["error"]
	if !hasResult && !hasError {
		return false
	}

	encoded, ok := encodeJSONRPCID(payload)
	if !ok || encoded == encodedRequestID {
		return false
	}

	wanted, wantedOK := decodeIDAsNumber(encodedRequestID)
	got, gotOK := coerceIDToNumber(payload["id"])
	return wantedOK && gotOK && wanted == got
}

// decodeIDAsNumber coerces a stored (already canonical JSON) id.
func decodeIDAsNumber(encodedID string) (float64, bool) {
	value, _, err := decodeJSON(encodedID, false)
	if err != nil {
		return 0, false
	}
	return coerceIDToNumber(value)
}

// coerceIDToNumber renders a JSON-RPC id the way a client that correlates
// responses numerically sees it, following ECMAScript Number(): a numeric
// string is its number, an empty one is zero, as are null and false, and true
// is one. ok is false for an id no such client could match on a number.
func coerceIDToNumber(id any) (float64, bool) {
	switch typed := id.(type) {
	case json.Number:
		number, err := strconv.ParseFloat(string(typed), 64)
		return number, err == nil
	case string:
		trimmed := strings.TrimSpace(typed)
		if trimmed == "" {
			return 0, true
		}
		number, err := strconv.ParseFloat(trimmed, 64)
		return number, err == nil
	case nil:
		return 0, true
	case bool:
		if typed {
			return 1, true
		}
		return 0, true
	}
	return 0, false
}

// payloadAnswers reports whether a decoded value answers the request id. A
// batch array carrying the answer is still an answer: it must not be overlooked
// because it is not a single object.
func payloadAnswers(value any, encodedRequestID string) bool {
	switch typed := value.(type) {
	case map[string]any:
		return matchesJSONRPCID(typed, encodedRequestID)
	case []any:
		for _, entry := range typed {
			if object, ok := entry.(map[string]any); ok && matchesJSONRPCID(object, encodedRequestID) {
				return true
			}
		}
	}
	return false
}
