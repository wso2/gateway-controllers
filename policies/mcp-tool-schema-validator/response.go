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

package mcptoolschemavalidator

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"strings"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

// verdict is the policy's judgement of one JSON-RPC message in a response body.
type verdict struct {
	// answers is false for a message that is not the response to the recorded call: a
	// notification, a progress event, or a response with another id. Such messages pass untouched.
	answers bool
	// skipped names why a matching response was not validated; "" when it was.
	skipped string
	// failed names why validation failed; "" when it passed or was skipped.
	failed string
	errs   []assessmentError
}

// OnResponseBody validates the tool result's structuredContent against the tool's output schema.
// A valid result is forwarded byte for byte; an invalid one is replaced by a JSON-RPC error in
// the framing the server used.
func (p *McpToolSchemaValidatorPolicy) OnResponseBody(
	_ context.Context,
	respCtx *policy.ResponseContext,
	_ map[string]interface{},
) policy.ResponseAction {
	if respCtx == nil || respCtx.SharedContext == nil || respCtx.Metadata == nil {
		return nil
	}
	if armed, _ := respCtx.Metadata[metadataValidateResponse].(bool); !armed {
		return nil
	}
	toolName, _ := respCtx.Metadata[metadataTool].(string)
	rule := p.tools[toolName]
	if rule == nil || rule.Output == nil {
		return nil
	}
	requestID, ok := respCtx.Metadata[metadataRequestID].(string)
	if !ok {
		return nil
	}
	// A non-2xx status is a transport failure, not a tool result.
	if respCtx.ResponseStatus < http.StatusOK || respCtx.ResponseStatus >= http.StatusMultipleChoices {
		return nil
	}

	contentType := strings.ToLower(firstHeader(respCtx.UpstreamHeaders(), "content-type"))
	isSSE := strings.Contains(contentType, "text/event-stream")
	isJSON := strings.Contains(contentType, "json")

	var body []byte
	if respCtx.ResponseBody != nil {
		body = respCtx.ResponseBody.Content
	}

	failWhole := func(reason, message string) policy.ResponseAction {
		return p.resultError(rule, requestID, reason, []assessmentError{{Path: "", Message: message}},
			func(envelope []byte) []byte {
				if isSSE {
					return sseFrame(envelope)
				}
				return envelope
			})
	}

	if len(bytes.TrimSpace(body)) == 0 {
		if isSSE || isJSON {
			return failWhole(reasonMissingStructuredContent, "response carries no tool result")
		}
		return nil
	}
	if len(body) > maxBodyBytes {
		return failWhole(reasonPayloadTooLarge, "payload is too large to validate")
	}

	if isSSE {
		for _, event := range parseEventStream(body) {
			if strings.TrimSpace(event.data) == "" {
				continue
			}
			v := p.judge(rule, []byte(event.data), requestID)
			if !v.answers {
				continue
			}
			return p.act(rule, requestID, v, func(envelope []byte) []byte {
				return replaceEventData(body, event, envelope)
			})
		}
		return nil
	}

	// JSON, or an unlabelled body that parses as one JSON-RPC message.
	v := p.judge(rule, body, requestID)
	if !v.answers {
		return nil
	}
	return p.act(rule, requestID, v, func(envelope []byte) []byte { return envelope })
}

// judge decides what to do with one message.
func (p *McpToolSchemaValidatorPolicy) judge(rule *ToolRule, data []byte, requestID string) verdict {
	msg, ok := parseResponse(data)
	if !ok {
		// Unparseable because too deep: it may well be the answer, and a client with a deeper
		// parser would read it, so it is refused rather than passed as unrelated.
		if exceedsDepth(data, decoderMaxDepth) {
			return verdict{answers: true, failed: reasonTooDeep,
				errs: []assessmentError{{Path: "", Message: "response is nested too deeply"}}}
		}
		return verdict{}
	}
	if !msg.answers(requestID) {
		return verdict{}
	}
	if msg.ambiguous {
		return verdict{answers: true, failed: reasonAmbiguousPayload,
			errs: []assessmentError{{Path: "", Message: "response names a member more than once"}}}
	}
	if msg.hasError {
		return verdict{answers: true, skipped: reasonJSONRPCError}
	}
	if msg.isError {
		// A tool failure is reported in content, not structuredContent; it is not a result.
		return verdict{answers: true, skipped: reasonToolError}
	}
	if !msg.resultIsObject || msg.structuredContent == nil {
		return verdict{answers: true, failed: reasonMissingStructuredContent,
			errs: []assessmentError{{Path: "", Message: "result has no structuredContent"}}}
	}
	if exceedsDepth(msg.structuredContent, maxJSONDepth) {
		return verdict{answers: true, failed: reasonTooDeep,
			errs: []assessmentError{{Path: "", Message: "structuredContent is nested too deeply"}}}
	}
	instance, errs := decodeInstance(msg.structuredContent, "structuredContent is not valid JSON")
	if errs != nil {
		return verdict{answers: true, failed: reasonSchemaMismatch, errs: errs}
	}
	result := validate(rule.Output.Schema, instance)
	if !result.valid() {
		return verdict{answers: true, failed: reasonSchemaMismatch, errs: result.errors}
	}
	return verdict{answers: true}
}

// act turns a verdict on the matching message into the response action. frame places the error
// envelope into the body the way the server framed its own message.
func (p *McpToolSchemaValidatorPolicy) act(rule *ToolRule, requestID string, v verdict, frame func([]byte) []byte) policy.ResponseAction {
	switch {
	case v.failed != "":
		return p.resultError(rule, requestID, v.failed, v.errs, frame)
	case v.skipped != "":
		return policy.DownstreamResponseModifications{
			AnalyticsMetadata: analytics(rule.Name, directionResponse, resultSkipped, v.skipped, 0),
		}
	default:
		// Body left nil: the original bytes go to the client unchanged.
		return policy.DownstreamResponseModifications{
			AnalyticsMetadata: analytics(rule.Name, directionResponse, resultPass, "", 0),
		}
	}
}

// resultError replaces the tool result with a JSON-RPC error. The status is 200: the HTTP
// exchange succeeded, and the failure is reported at the JSON-RPC layer where the client reads it.
func (p *McpToolSchemaValidatorPolicy) resultError(
	rule *ToolRule,
	requestID string,
	reason string,
	errs []assessmentError,
	frame func([]byte) []byte,
) policy.ResponseAction {
	slog.Debug("MCP Tool Schema Validator: tool result failed validation",
		"tool", rule.Name, "reason", reason, "errorCount", len(errs))
	data := &errorData{Tool: rule.Name, Direction: directionResponse}
	if reason != reasonSchemaMismatch {
		data.Reason = reason
	}
	if rule.Output.ShowAssessment {
		data.Errors = capErrors(errs)
	}
	status := http.StatusOK
	meta := analytics(rule.Name, directionResponse, resultFail, reason, len(errs))
	meta["mcpErrorCode"] = codeInvalidToolResult
	code := codeInvalidToolResult
	return policy.DownstreamResponseModifications{
		Body:              frame(errorEnvelope(requestID, codeInvalidToolResult, messageResultInvalid, data)),
		StatusCode:        &status,
		AnalyticsMetadata: meta,
		// A failure despite the 200: the client receives an error instead of the tool's result.
		// The upstream returned the bad result, so this is the policy unable to deliver one,
		// not a caller error.
		IsFault: true,
		Fault: &policy.FaultDetails{
			Code:        policy.FaultCodeMediationFailed,
			Type:        policy.FaultTypeValidation,
			Direction:   policy.DirectionResponse,
			Message:     messageResultInvalid,
			Description: faultDescription(rule.Name, "result", reason, len(errs)),
			JSONRPC:     &policy.JSONRPCError{Code: &code, ID: jsonRPCID(requestID)},
		},
	}
}

// firstHeader returns a header's first value, or "" when absent.
func firstHeader(headers *policy.Headers, name string) string {
	values := headers.Get(name)
	if len(values) == 0 {
		return ""
	}
	return values[0]
}
