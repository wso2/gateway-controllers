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

// Package mcpacllist blocks MCP capabilities an ACL denies, and filters denied entries out of
// */list responses.
//
// The operation it governs comes from one source per era, never both:
//
//	modern (2026-07-28+)  the mirrored Mcp-Method / Mcp-Name headers; the body is not read
//	legacy                the body, via the route's resolver or this policy's own parse
//
// Checking that a modern request's headers describe its body is mcp-spec-validation's job.
package mcpacllist

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

const (
	mcpPathSegment            = "/mcp"
	metadataMcpCapabilityType = "mcp.capabilityType"
	metadataMcpAction         = "mcp.action"
	mcpSessionHeader          = "mcp-session-id"
	defaultAclMode            = "deny"

	// A required MCP 2026-07-28 mirrored header is missing.
	jsonRpcErrCodeHeaderMismatch = -32020

	reasonSyntaxError       = "syntax-error"
	reasonInvalidMemberType = "invalid-member-type"
	reasonNotAnObject       = "not-an-object"
	reasonAmbiguous         = "ambiguous"
)

type AclConfig struct {
	Enabled    bool
	Mode       string
	Exceptions map[string]struct{}
}

type McpAclListPolicy struct {
	tools     AclConfig
	resources AclConfig
	prompts   AclConfig
}

type sseEvent struct {
	fields []string
	data   string
}

// GetPolicy is the v1alpha2 factory entry point (loaded by v1alpha2 kernels).
func GetPolicy(
	metadata policy.PolicyMetadata,
	params map[string]interface{},
) (policy.Policy, error) {
	slog.Debug("MCP ACL List Policy: GetPolicy called")

	ins := &McpAclListPolicy{}

	toolsConfig, err := parseAclConfig(params, "tools")
	if err != nil {
		slog.Debug("MCP ACL List Policy: Invalid tools configuration", "error", err)
		return nil, fmt.Errorf("invalid tools configuration: %w", err)
	}

	resourcesConfig, err := parseAclConfig(params, "resources")
	if err != nil {
		slog.Debug("MCP ACL List Policy: Invalid resources configuration", "error", err)
		return nil, fmt.Errorf("invalid resources configuration: %w", err)
	}

	promptsConfig, err := parseAclConfig(params, "prompts")
	if err != nil {
		slog.Debug("MCP ACL List Policy: Invalid prompts configuration", "error", err)
		return nil, fmt.Errorf("invalid prompts configuration: %w", err)
	}

	ins.tools = toolsConfig
	ins.resources = resourcesConfig
	ins.prompts = promptsConfig

	slog.Debug("MCP ACL List Policy: Parsed configuration",
		"toolsEnabled", ins.tools.Enabled,
		"toolsMode", ins.tools.Mode,
		"toolsExceptions", len(ins.tools.Exceptions),
		"resourcesEnabled", ins.resources.Enabled,
		"resourcesMode", ins.resources.Mode,
		"resourcesExceptions", len(ins.resources.Exceptions),
		"promptsEnabled", ins.prompts.Enabled,
		"promptsMode", ins.prompts.Mode,
		"promptsExceptions", len(ins.prompts.Exceptions),
	)

	return ins, nil
}

func (p *McpAclListPolicy) Mode() policy.ProcessingMode {
	return policy.ProcessingMode{
		RequestHeaderMode:  policy.HeaderModeProcess,
		RequestBodyMode:    policy.BodyModeBuffer,
		ResponseHeaderMode: policy.HeaderModeSkip,
		ResponseBodyMode:   policy.BodyModeBuffer,
	}
}

// parseAclConfig parses ACL configuration for a capability type.
func parseAclConfig(params map[string]any, capabilityType string) (AclConfig, error) {
	config := AclConfig{
		Exceptions: make(map[string]struct{}),
	}

	raw, ok := params[capabilityType]
	if !ok {
		return config, nil
	}

	entry, ok := raw.(map[string]any)
	if !ok {
		slog.Debug("MCP ACL List Policy: Invalid capability config", "capabilityType", capabilityType, "error", "not an object")
		return config, fmt.Errorf("%s must be an object", capabilityType)
	}

	mode := defaultAclMode
	if modeRaw, ok := entry["mode"]; ok {
		modeString, isString := modeRaw.(string)
		if !isString {
			slog.Debug("MCP ACL List Policy: Invalid mode type", "capabilityType", capabilityType, "mode", modeRaw)
			return config, fmt.Errorf("%s.mode must be 'allow' or 'deny'", capabilityType)
		}
		mode = strings.ToLower(strings.TrimSpace(modeString))
		if mode != "allow" && mode != "deny" {
			slog.Debug("MCP ACL List Policy: Invalid mode", "capabilityType", capabilityType, "mode", modeString)
			return config, fmt.Errorf("%s.mode must be 'allow' or 'deny'", capabilityType)
		}
	}

	config.Enabled = true
	config.Mode = mode

	exceptionsRaw, ok := entry["exceptions"]
	if !ok || exceptionsRaw == nil {
		return config, nil
	}

	list, ok := exceptionsRaw.([]any)
	if !ok {
		slog.Debug("MCP ACL List Policy: Invalid exceptions", "capabilityType", capabilityType, "error", "not an array")
		return config, fmt.Errorf("%s.exceptions must be an array", capabilityType)
	}

	for i, item := range list {
		value, ok := item.(string)
		trimmed := strings.TrimSpace(value)
		if !ok || trimmed == "" {
			slog.Debug("MCP ACL List Policy: Invalid exception", "capabilityType", capabilityType, "index", i, "error", "not a non-empty string")
			return config, fmt.Errorf("%s.exceptions[%d] must be a non-empty string", capabilityType, i)
		}

		config.Exceptions[trimmed] = struct{}{}
	}

	return config, nil
}

// getAclConfig returns the ACL config for a capability type.
func (p *McpAclListPolicy) getAclConfig(capabilityType string) AclConfig {
	switch capabilityType {
	case "tools":
		return p.tools
	case "resources":
		return p.resources
	case "prompts":
		return p.prompts
	default:
		return AclConfig{}
	}
}

// isAllowedByAcl checks whether a capability identifier is allowed by ACL.
func isAllowedByAcl(config AclConfig, key string) bool {
	_, isException := config.Exceptions[key]
	if config.Mode == "allow" {
		// allow-all but deny this
		return !isException
	}
	// deny-all but allow this
	return isException
}

// filterListItems filters list items according to ACL mode and exceptions.
func filterListItems(items []any, capabilityType string, config AclConfig) ([]any, bool) {
	keyField := getParamKey(capabilityType)
	filtered := make([]any, 0, len(items))
	changed := false

	for _, item := range items {
		entry, ok := item.(map[string]any)
		if !ok {
			if config.Mode == "allow" {
				filtered = append(filtered, item)
			} else {
				changed = true
			}
			continue
		}
		key, ok := entry[keyField].(string)
		if !ok || strings.TrimSpace(key) == "" {
			if config.Mode == "allow" {
				filtered = append(filtered, item)
			} else {
				changed = true
			}
			continue
		}
		allowed := isAllowedByAcl(config, key)
		if allowed {
			slog.Debug("MCP ACL List Policy: Allowing list item", "type", capabilityType, "keyField", keyField, "key", key)
			filtered = append(filtered, item)
		} else {
			slog.Debug("MCP ACL List Policy: Removing list item", "type", capabilityType, "keyField", keyField, "key", key)
			changed = true
		}
	}

	if len(filtered) != len(items) {
		changed = true
	}

	return filtered, changed
}

// parseMcpMethod splits an MCP method into capability type and action.
func parseMcpMethod(method string) (string, string, bool) {
	parts := strings.Split(method, "/")
	if len(parts) != 2 {
		return "", "", false
	}

	capabilityType := parts[0]
	action := parts[1]
	switch capabilityType {
	case "tools", "resources", "prompts":
		return capabilityType, action, true
	default:
		return "", "", false
	}
}

// getParamKey returns the parameter name used for the capability identifier.
func getParamKey(capabilityType string) string {
	if capabilityType == "resources" {
		return "uri"
	}
	return "name"
}

// parseEventStream splits an SSE payload into events.
func parseEventStream(body []byte) []sseEvent {
	lines := strings.Split(string(body), "\n")
	events := make([]sseEvent, 0)
	var fields []string
	var dataLines []string

	flush := func() {
		if len(fields) == 0 && len(dataLines) == 0 {
			return
		}
		event := sseEvent{
			fields: append([]string(nil), fields...),
			data:   strings.Join(dataLines, "\n"),
		}
		events = append(events, event)
		fields = nil
		dataLines = nil
	}

	for _, line := range lines {
		line = strings.TrimSuffix(line, "\r")
		if line == "" {
			flush()
			continue
		}
		if strings.HasPrefix(line, "data:") {
			data := strings.TrimPrefix(line, "data:")
			data = strings.TrimPrefix(data, " ")
			dataLines = append(dataLines, data)
			continue
		}
		fields = append(fields, line)
	}
	flush()

	return events
}

// buildEventStream builds a raw SSE payload from events.
func buildEventStream(events []sseEvent) []byte {
	var builder strings.Builder
	for _, event := range events {
		for _, field := range event.fields {
			builder.WriteString(field)
			builder.WriteString("\n")
		}
		if event.data != "" {
			for _, line := range strings.Split(event.data, "\n") {
				builder.WriteString("data: ")
				builder.WriteString(line)
				builder.WriteString("\n")
			}
		}
		builder.WriteString("\n")
	}
	return []byte(builder.String())
}

// parseRequestPayload extracts the JSON-RPC payload, handling SSE bodies.
func parseRequestPayload(body []byte, isSse bool) (map[string]any, []sseEvent, int, error) {
	if !isSse {
		var payload map[string]any
		if err := json.Unmarshal(body, &payload); err != nil {
			return nil, nil, -1, err
		}
		return payload, nil, -1, nil
	}

	events := parseEventStream(body)
	for i, event := range events {
		if strings.TrimSpace(event.data) == "" {
			continue
		}
		var payload map[string]any
		if err := json.Unmarshal([]byte(event.data), &payload); err != nil {
			continue
		}
		return payload, events, i, nil
	}
	return nil, events, -1, fmt.Errorf("no JSON payload found in event stream")
}

// isApplicableOnRequest reports whether request ACL checks apply.
func isApplicableOnRequest(capabilityType, action string) bool {
	switch capabilityType {
	case "tools":
		return action == "call"
	case "resources":
		return action == "read"
	case "prompts":
		return action == "get"
	default:
		return false
	}
}

// isMcpPostRequest reports whether the request targets the MCP endpoint.
func isMcpPostRequest(method, path string) bool {
	if !strings.EqualFold(method, "POST") {
		return false
	}
	cleanPath := strings.TrimSpace(path)
	if idx := strings.Index(cleanPath, "?"); idx >= 0 {
		cleanPath = cleanPath[:idx]
	}
	return cleanPath == mcpPathSegment || strings.HasPrefix(cleanPath, mcpPathSegment+"/")
}

// OnRequestHeaders enforces the ACL where a resolver supplies the capability without a body.
func (p *McpAclListPolicy) OnRequestHeaders(ctx context.Context, reqCtx *policy.RequestHeaderContext, _ map[string]any) policy.RequestHeaderAction {
	ds := reqCtx.DownstreamRequest()
	routePath := ds.Path
	if reqCtx.SharedContext != nil && reqCtx.OperationPath != "" {
		routePath = reqCtx.OperationPath
	}
	if !isMcpPostRequest(ds.Method, routePath) {
		return nil
	}

	if shouldParseBody(reqCtx.SharedContext) {
		return nil
	}

	facts := mcpFacts(reqCtx.Headers, reqCtx.SharedContext)
	if facts.IsModernRequest {
		return p.governFromMirroredHeaders(reqCtx, facts)
	}
	return p.governFromResolvedBody(reqCtx, facts)
}

// governFromMirroredHeaders applies the ACL to a modern request from Mcp-Method and Mcp-Name. The
// body is not read here at all, not even for whether the resolver could read it; that check and
// the headers-match-body check are both mcp-spec-validation's job.
func (p *McpAclListPolicy) governFromMirroredHeaders(
	reqCtx *policy.RequestHeaderContext,
	facts mcpRequestFacts,
) policy.RequestHeaderAction {
	// 2026-07-28 requires Mcp-Method, and MRTR removes the method-less JSON-RPC response the
	// legacy path lets through, so a modern request without one is malformed.
	if !facts.HasMethod() {
		slog.Debug("MCP ACL List Policy: Rejecting a modern request that mirrored no method")
		return p.buildRequestErrorResponse(reqCtx.Headers, 400, jsonRpcErrCodeHeaderMismatch,
			headerMcpMethod+" header is required", nil,
			policy.FaultCodeInvalidRequestHeader, policy.FaultTypeValidation)
	}
	// Mcp-Name is required on the three capability methods; an undecodable one counts as missing.
	// Left in, the empty name would match no capability rule, "*" included.
	if facts.MissingRequiredName() {
		slog.Debug("MCP ACL List Policy: Rejecting a modern request that mirrored no capability name",
			"method", facts.Method)
		return p.buildRequestErrorResponse(reqCtx.Headers, 400, jsonRpcErrCodeHeaderMismatch,
			headerMcpName+" header is required for "+facts.Method, nil,
			policy.FaultCodeInvalidRequestHeader, policy.FaultTypeValidation)
	}
	return p.applyAcl(reqCtx, facts)
}

// governFromResolvedBody applies the ACL to a legacy request from the body the resolver read.
func (p *McpAclListPolicy) governFromResolvedBody(
	reqCtx *policy.RequestHeaderContext,
	facts mcpRequestFacts,
) policy.RequestHeaderAction {
	// Bytes the resolver could not read are refused: this policy's own parse is case-sensitive
	// where the server's is not, so the ACL would apply to the wrong operation.
	if reason := unusableBodyReason(reqCtx.SharedContext); reason != "" {
		slog.Debug("MCP ACL List Policy: Rejecting request whose body the resolver could not read", "reason", reason)
		return p.handleUnusableBody(reqCtx.Headers, reason)
	}
	// No body, so nothing named an operation. Pass it through, as above.
	if !facts.IsRequestBodyPresent {
		slog.Debug("MCP ACL List Policy: Skipping a request that carried no body")
		return nil
	}
	return p.applyAcl(reqCtx, facts)
}

// applyAcl checks an established operation against the ACL, whichever era established it.
func (p *McpAclListPolicy) applyAcl(
	reqCtx *policy.RequestHeaderContext,
	facts mcpRequestFacts,
) policy.RequestHeaderAction {
	nameFor := func(string) (string, bool) { return facts.Name, true }
	if resp := p.govern(reqCtx.SharedContext, reqCtx.Headers, facts.Method, facts.RequestID, nameFor); resp != nil {
		return *resp
	}
	return nil
}

// OnRequestBody enforces ACL rules on the MCP request body.
func (p *McpAclListPolicy) OnRequestBody(ctx context.Context, reqCtx *policy.RequestContext, _ map[string]any) policy.RequestAction {
	// Already decided at the header phase on a resolver route. Mode asks for both phases, so
	// this guard is what stops a second decision here.
	if !shouldParseBody(reqCtx.SharedContext) {
		return policy.UpstreamRequestModifications{}
	}

	ds := reqCtx.DownstreamRequest()
	routePath := ds.Path
	if reqCtx.SharedContext != nil && reqCtx.OperationPath != "" {
		routePath = reqCtx.OperationPath
	}
	if !isMcpPostRequest(ds.Method, routePath) {
		return policy.UpstreamRequestModifications{}
	}
	slog.Debug("MCP ACL List Policy: OnRequest started")

	if reqCtx.Body == nil || len(reqCtx.Body.Content) == 0 {
		return policy.UpstreamRequestModifications{}
	}

	if reqCtx.SharedContext == nil {
		reqCtx.SharedContext = &policy.SharedContext{}
	}

	// Read Content-Type and the session id (used for error responses) from the
	// downstream snapshot so gating and its diagnostics reflect what
	// the client actually sent, not a value a peer policy rewrote during the
	// header phase.
	requestPayload, _, _, err := parseRequestPayload(reqCtx.Body.Content, isEventStream(ds.Headers))
	if err != nil {
		slog.Debug("MCP ACL List Policy: Failed to parse MCP request", "error", err, "path", ds.Path)
		return p.handleUnusableBody(ds.Headers, reasonSyntaxError)
	}

	requestID := requestPayload["id"]
	method, _ := requestPayload["method"].(string)

	// false lets govern report a bad params in the released order, after the group is
	// known — reporting sooner turns an unconfigured family into a 400.
	nameFor := func(capabilityType string) (string, bool) {
		paramsRaw, ok := requestPayload["params"].(map[string]any)
		if !ok {
			return "", false
		}
		name, _ := paramsRaw[getParamKey(capabilityType)].(string)
		return name, true
	}

	if resp := p.govern(reqCtx.SharedContext, ds.Headers, method, requestID, nameFor); resp != nil {
		return *resp
	}
	return policy.UpstreamRequestModifications{}
}

// govern is the ACL decision, shared by both request phases so the two cannot drift. nameFor
// resolves the name once the family is known; false means params was not an object.
func (p *McpAclListPolicy) govern(shared *policy.SharedContext, headers *policy.Headers,
	method string, requestID any, nameFor func(capabilityType string) (string, bool)) *policy.ImmediateResponse {

	capabilityType, action, ok := parseMcpMethod(method)
	if !ok {
		return nil
	}

	// The note OnResponseBody gates on, written before the checks below: a listing fails
	// them and a listing is exactly what the response phase filters.
	if shared.Metadata == nil {
		shared.Metadata = make(map[string]any)
	}
	shared.Metadata[metadataMcpCapabilityType] = capabilityType
	shared.Metadata[metadataMcpAction] = action

	if !isApplicableOnRequest(capabilityType, action) {
		return nil
	}

	config := p.getAclConfig(capabilityType)
	if !config.Enabled {
		return nil
	}

	capabilityName, paramsReadable := nameFor(capabilityType)
	if !paramsReadable {
		slog.Debug("MCP ACL List Policy: Invalid request params", "capabilityType", capabilityType, "requestID", requestID, "error", "params not a map")
		resp := p.buildRequestErrorResponse(headers, 400, -32602, "Invalid MCP request params", requestID,
			policy.FaultCodeInvalidRequestBody, policy.FaultTypeValidation)
		return &resp
	}

	if strings.TrimSpace(capabilityName) == "" {
		slog.Debug("MCP ACL List Policy: Missing capability name", "capabilityType", capabilityType, "requestID", requestID)
		resp := p.buildRequestErrorResponse(headers, 400, -32602, fmt.Sprintf("Missing MCP %s name", capabilityType), requestID,
			policy.FaultCodeInvalidRequestBody, policy.FaultTypeValidation)
		return &resp
	}

	if !isAllowedByAcl(config, capabilityName) {
		slog.Debug("MCP ACL List Policy: Capability denied by policy", "capabilityType", capabilityType, "capabilityName", capabilityName, "requestID", requestID)
		resp := p.buildRequestErrorResponse(headers, 400, -32000, "MCP capability not allowed", requestID,
			policy.FaultCodeAuthForbidden, policy.FaultTypeAuthorization)
		return &resp
	}

	return nil
}

// OnResponseBody enforces ACL rules on the MCP response body.
func (p *McpAclListPolicy) OnResponseBody(ctx context.Context, respCtx *policy.ResponseContext, _ map[string]any) policy.ResponseAction {
	ds := respCtx.DownstreamRequest()
	routePath := ds.Path
	if respCtx.SharedContext != nil && respCtx.OperationPath != "" {
		routePath = respCtx.OperationPath
	}
	if !isMcpPostRequest(ds.Method, routePath) {
		return nil
	}
	slog.Debug("MCP ACL List Policy: OnResponseBody started")

	if respCtx.SharedContext == nil || respCtx.Metadata == nil {
		return nil
	}

	capabilityType, _ := respCtx.Metadata[metadataMcpCapabilityType].(string)
	action, _ := respCtx.Metadata[metadataMcpAction].(string)
	if capabilityType == "" || action != "list" {
		slog.Debug("MCP ACL List Policy: OnResponseBody skipped, action is not list", "capabilityType", capabilityType, "action", action)
		return nil
	}

	config := p.getAclConfig(capabilityType)
	if !config.Enabled {
		return nil
	}

	if respCtx.ResponseBody == nil || !respCtx.ResponseBody.Present {
		return nil
	}

	if isEventStream(respCtx.UpstreamHeaders()) {
		events := parseEventStream(respCtx.ResponseBody.Content)
		updated := false
		for i, event := range events {
			if strings.TrimSpace(event.data) == "" {
				continue
			}
			var responsePayload map[string]any
			if err := json.Unmarshal([]byte(event.data), &responsePayload); err != nil {
				continue
			}
			if _, hasError := responsePayload["error"]; hasError {
				slog.Debug("MCP ACL List Policy: Upstream response contains error", "capabilityType", capabilityType)
				continue
			}
			resultRaw, ok := responsePayload["result"].(map[string]any)
			if !ok {
				slog.Debug("MCP ACL List Policy: Invalid MCP response result", "capabilityType", capabilityType, "error", "result not an object")
				continue
			}

			listKey := capabilityType
			existing, ok := resultRaw[listKey].([]any)
			if !ok {
				continue
			}
			filtered, changed := filterListItems(existing, capabilityType, config)
			if !changed {
				slog.Debug("MCP ACL List Policy: No changes in list items", "capabilityType", capabilityType)
				continue
			}

			resultRaw[listKey] = filtered
			responsePayload["result"] = resultRaw

			updatedPayload, err := json.Marshal(responsePayload)
			if err != nil {
				slog.Debug("MCP ACL List Policy: Failed to marshal updated response", "capabilityType", capabilityType, "error", err)
				continue
			}
			events[i].data = string(updatedPayload)
			updated = true
		}

		if !updated {
			return nil
		}
		return policy.DownstreamResponseModifications{
			Body: buildEventStream(events),
		}
	}

	var responsePayload map[string]any
	if err := json.Unmarshal(respCtx.ResponseBody.Content, &responsePayload); err != nil {
		slog.Debug("MCP ACL List Policy: Failed to parse MCP response", "capabilityType", capabilityType, "error", err)
		return nil
	}

	if _, hasError := responsePayload["error"]; hasError {
		slog.Debug("MCP ACL List Policy: Upstream response contains error", "capabilityType", capabilityType)
		return nil
	}

	resultRaw, ok := responsePayload["result"].(map[string]any)
	if !ok {
		slog.Debug("MCP ACL List Policy: Invalid MCP response result", "capabilityType", capabilityType, "error", "result not an object")
		return nil
	}

	listKey := capabilityType
	existing, ok := resultRaw[listKey].([]any)
	if !ok {
		return nil
	}

	filtered, changed := filterListItems(existing, capabilityType, config)
	if !changed {
		slog.Debug("MCP ACL List Policy: No changes in list items", "capabilityType", capabilityType)
		return nil
	}

	resultRaw[listKey] = filtered
	responsePayload["result"] = resultRaw

	updatedPayload, err := json.Marshal(responsePayload)
	if err != nil {
		slog.Debug("MCP ACL List Policy: Failed to marshal updated response", "capabilityType", capabilityType, "error", err)
		return nil
	}

	return policy.DownstreamResponseModifications{
		Body: updatedPayload,
	}
}

// getSessionID extracts the MCP session ID from v1alpha2 headers.
func getSessionID(headers *policy.Headers) string {
	if headers == nil {
		return ""
	}
	for key, values := range headers.GetAll() {
		if strings.ToLower(key) == mcpSessionHeader {
			if len(values) > 0 {
				return values[0]
			}
		}
	}
	return ""
}

// handleUnusableBody renders a reason the body could not be read. Both paths call it.
func (p *McpAclListPolicy) handleUnusableBody(headers *policy.Headers, reason string) policy.ImmediateResponse {
	code, message := -32600, "Invalid MCP request"
	switch reason {
	case reasonSyntaxError:
		code, message = -32700, "Invalid JSON"
	case reasonInvalidMemberType:
		message = "Request body has a member of the wrong type"
	case reasonNotAnObject:
		message = "Request body is not a single JSON-RPC request object"
	case reasonAmbiguous:
		// The one this policy cannot detect itself — its map[string]any is case-sensitive.
		message = "Ambiguous MCP request: body names a member more than once"
	}
	return p.buildRequestErrorResponse(headers, 400, code, message, nil,
		policy.FaultCodeInvalidRequestBody, policy.FaultTypeValidation)
}

// buildRequestErrorResponse builds a v1alpha2 error response for a request.
func (p *McpAclListPolicy) buildRequestErrorResponse(headers *policy.Headers, statusCode int, jsonRpcCode int, reason string, requestID any, code, errorType string) policy.ImmediateResponse {
	body, contentType := buildJsonRpcErrorBody(jsonRpcCode, reason, requestID, isEventStream(headers))

	responseHeaders := map[string]string{"Content-Type": contentType}
	if sessionID := getSessionID(headers); sessionID != "" {
		responseHeaders[mcpSessionHeader] = sessionID
	}

	return policy.ImmediateResponse{
		StatusCode: statusCode,
		Headers:    responseHeaders,
		Body:       body,
		AnalyticsMetadata: map[string]any{
			"mcpErrorCode": jsonRpcCode,
		},
		IsFault: true,
		Fault: &policy.FaultDetails{
			Code:      code,
			Type:      errorType,
			Direction: policy.DirectionRequest,
			// reason becomes the JSON-RPC error message.
			Message: reason,
			JSONRPC: &policy.JSONRPCError{Code: &jsonRpcCode, ID: requestID},
		},
	}
}

// buildJsonRpcErrorBody renders the JSON-RPC error envelope this policy has always sent,
// SSE-framed when the caller posted an event stream. The content type is returned alongside
// it so the two cannot drift apart.
//
// This is the fallback body, not the gateway's rendering — see buildRequestErrorResponse.
// It stays byte-for-byte what the policy sent before the fault contract existed, so
// upgrading the policy on its own changes nothing a client receives.
func buildJsonRpcErrorBody(jsonRpcCode int, reason string, requestID any, sse bool) ([]byte, string) {
	body, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      requestID,
		"error": map[string]any{
			"code":    jsonRpcCode,
			"message": reason,
		},
	})
	if err != nil {
		// requestID reached here from the caller's own payload, so a value that will not
		// marshal is possible; null is the JSON-RPC answer for an unrecoverable id.
		slog.Debug("MCP ACL List Policy: Failed to marshal error response", "error", err)
		idBytes, idErr := json.Marshal(requestID)
		if idErr != nil {
			idBytes = []byte("null")
		}
		body = fmt.Appendf(nil, `{"jsonrpc":"2.0","id":%s,"error":{"code":-32603,"message":"Unexpected error"}}`, string(idBytes))
	}

	if sse {
		return buildEventStream([]sseEvent{{data: string(body)}}), "text/event-stream"
	}
	return body, "application/json"
}

// isEventStream reports whether v1alpha2 headers indicate an SSE payload.
func isEventStream(headers *policy.Headers) bool {
	if headers == nil {
		return false
	}
	for key, values := range headers.GetAll() {
		if strings.ToLower(key) == "content-type" {
			for _, value := range values {
				if strings.Contains(strings.ToLower(value), "text/event-stream") {
					return true
				}
			}
		}
	}
	return false
}
