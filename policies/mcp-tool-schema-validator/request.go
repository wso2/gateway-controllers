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

// OnRequestBody validates a tools/call's arguments against the tool's input schema, and records
// the call for the response phase.
func (p *McpToolSchemaValidatorPolicy) OnRequestBody(
	_ context.Context,
	reqCtx *policy.RequestContext,
	_ map[string]interface{},
) policy.RequestAction {
	if reqCtx == nil || !strings.EqualFold(reqCtx.Method, http.MethodPost) {
		return nil
	}
	if reqCtx.Body == nil || len(bytes.TrimSpace(reqCtx.Body.Content)) == 0 {
		return nil
	}
	body := reqCtx.Body.Content
	headers := reqCtx.DownstreamHeaders()

	// Bodies this policy cannot read are left to mcp-spec-validation by parseRequest below.
	// A readable call to a governed tool is always validated, whatever the resolver concluded.
	call, outcome := parseRequest(body)
	switch outcome {
	case parseUnreadable:
		// Too deep for encoding/json means no one here can tell which tool it calls. Refuse
		// rather than forward a possibly governed call unvalidated.
		if exceedsDepth(body, decoderMaxDepth) {
			slog.Debug("MCP Tool Schema Validator: rejecting request nested beyond the decoder limit")
			return requestError(headers, "", codeInvalidRequest, messageTooDeep, nil, nil,
				"request body is nested beyond the decoder limit")
		}
		return nil
	case parseOther:
		return nil
	case parseAmbiguous:
		slog.Debug("MCP Tool Schema Validator: rejecting ambiguous tools/call")
		// No id: an ambiguous body has no single id to echo.
		return requestError(headers, "", codeInvalidRequest, messageAmbiguous, nil, nil,
			"tools/call names a member more than once")
	}

	rule := p.tools[call.name]
	if rule == nil {
		return nil
	}
	recordCall(reqCtx.SharedContext, call, rule)

	if rule.Input == nil {
		return nil
	}
	if call.argumentsAmbiguous {
		slog.Debug("MCP Tool Schema Validator: rejecting tools/call with ambiguous arguments", "tool", rule.Name)
		return requestError(headers, call.id, codeInvalidRequest, messageAmbiguous, nil,
			analytics(rule.Name, directionRequest, resultFail, reasonAmbiguousPayload, 1),
			"arguments of tool "+rule.Name+" name a member more than once")
	}

	fail := func(reason string, errs []assessmentError) policy.RequestAction {
		slog.Debug("MCP Tool Schema Validator: tool arguments failed validation",
			"tool", rule.Name, "reason", reason, "errorCount", len(errs))
		data := &errorData{Tool: rule.Name, Direction: directionRequest}
		if reason != reasonSchemaMismatch {
			data.Reason = reason
		}
		if rule.Input.ShowAssessment {
			data.Errors = capErrors(errs)
		}
		return requestError(headers, call.id, codeInvalidParams, messageArgumentsInvalid, data,
			analytics(rule.Name, directionRequest, resultFail, reason, len(errs)),
			faultDescription(rule.Name, "arguments", reason, len(errs)))
	}

	if len(body) > maxBodyBytes {
		return fail(reasonPayloadTooLarge, []assessmentError{{Path: "", Message: "payload is too large to validate"}})
	}

	args := bytes.TrimSpace(call.arguments)
	var instance any
	switch {
	case len(args) == 0 || isNull(args):
		// MCP makes arguments optional; an absent argument list is an empty one.
		instance = map[string]any{}
	case args[0] != '{':
		return fail(reasonArgumentsNotObject, []assessmentError{{Path: "", Message: "arguments must be an object"}})
	case exceedsDepth(args, maxJSONDepth):
		return fail(reasonTooDeep, []assessmentError{{Path: "", Message: "arguments are nested too deeply"}})
	default:
		// objectMembers already accepted the JSON, so in practice only an imprecise number fails here.
		decoded, errs := decodeInstance(args, "arguments are not valid JSON")
		if errs != nil {
			return fail(reasonSchemaMismatch, errs)
		}
		instance = decoded
	}

	result := validate(rule.Input.Schema, instance)
	if !result.valid() {
		return fail(reasonSchemaMismatch, result.errors)
	}
	return policy.UpstreamRequestModifications{
		AnalyticsMetadata: analytics(rule.Name, directionRequest, resultPass, "", 0),
	}
}

// recordCall leaves what the response phase needs in the request's metadata. A notification
// gets no response, so nothing is armed for one.
func recordCall(shared *policy.SharedContext, call toolCall, rule *ToolRule) {
	if shared == nil {
		return
	}
	if shared.Metadata == nil {
		shared.Metadata = make(map[string]interface{})
	}
	shared.Metadata[metadataTool] = rule.Name
	shared.Metadata[metadataValidateResponse] = rule.Output != nil && call.hasID
	if call.hasID {
		shared.Metadata[metadataRequestID] = call.id
	}
}
