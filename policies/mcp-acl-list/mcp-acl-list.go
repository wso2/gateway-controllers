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

package mcpacllist

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"

	policy "github.com/wso2/api-platform/sdk/gateway/policy/v1alpha"
)

const (
	mcpPathSegment            = "/mcp"
	metadataMcpCapabilityType = "mcp.capabilityType"
	metadataMcpAction         = "mcp.action"
	mcpSessionHeader          = "mcp-session-id"
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

func GetPolicy(
	metadata policy.PolicyMetadata,
	params map[string]any,
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

	modeRaw, ok := entry["mode"].(string)
	if !ok {
		slog.Debug("MCP ACL List Policy: Missing or invalid mode", "capabilityType", capabilityType)
		return config, fmt.Errorf("%s.mode is required", capabilityType)
	}

	mode := strings.ToLower(strings.TrimSpace(modeRaw))
	if mode != "allow" && mode != "deny" {
		slog.Debug("MCP ACL List Policy: Invalid mode", "capabilityType", capabilityType, "mode", modeRaw)
		return config, fmt.Errorf("%s.mode must be 'allow' or 'deny'", capabilityType)
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
		if !ok || strings.TrimSpace(value) == "" {
			slog.Debug("MCP ACL List Policy: Invalid exception", "capabilityType", capabilityType, "index", i, "error", "not a non-empty string")
			return config, fmt.Errorf("%s.exceptions[%d] must be a non-empty string", capabilityType, i)
		}

		config.Exceptions[value] = struct{}{}
	}

	return config, nil
}

func (p *McpAclListPolicy) Mode() policy.ProcessingMode {
	return policy.ProcessingMode{
		RequestHeaderMode:  policy.HeaderModeSkip,
		RequestBodyMode:    policy.BodyModeBuffer,
		ResponseHeaderMode: policy.HeaderModeSkip,
		ResponseBodyMode:   policy.BodyModeBuffer,
	}
}

func (p *McpAclListPolicy) OnRequest(ctx *policy.RequestContext, params map[string]any) policy.RequestAction {
	if !isMcpPostRequest(ctx.Method, ctx.Path) {
		return nil
	}
	slog.Debug("MCP ACL List Policy: OnRequest started")

	if ctx.Body == nil || len(ctx.Body.Content) == 0 {
		return nil
	}

	requestPayload, _, _, err := parseRequestPayload(ctx.Body.Content, isEventStream(ctx.Headers))
	if err != nil {
		slog.Debug("MCP ACL List Policy: Failed to parse MCP request", "error", err, "path", ctx.Path)
		return p.buildRequestErrorResponse(ctx, 400, -32700, "Invalid JSON", nil)
	}

	requestID := requestPayload["id"]

	method, _ := requestPayload["method"].(string)
	capabilityType, action, ok := parseMcpMethod(method)
	if !ok {
		return nil
	}

	if ctx.Metadata == nil {
		ctx.Metadata = make(map[string]any)
	}
	ctx.Metadata[metadataMcpCapabilityType] = capabilityType
	ctx.Metadata[metadataMcpAction] = action

	if !isApplicableOnRequest(capabilityType, action) {
		return nil
	}

	config := p.getAclConfig(capabilityType)
	if !config.Enabled {
		return nil
	}

	paramsRaw, ok := requestPayload["params"].(map[string]any)
	if !ok {
		slog.Debug("MCP ACL List Policy: Invalid request params", "capabilityType", capabilityType, "requestID", requestID, "error", "params not a map")
		return p.buildRequestErrorResponse(ctx, 400, -32602, "Invalid MCP request params", requestID)
	}

	paramKey := getParamKey(capabilityType)
	capabilityName, _ := paramsRaw[paramKey].(string)
	if strings.TrimSpace(capabilityName) == "" {
		slog.Debug("MCP ACL List Policy: Missing capability name", "capabilityType", capabilityType, "requestID", requestID, "paramKey", paramKey)
		return p.buildRequestErrorResponse(ctx, 400, -32602, fmt.Sprintf("Missing MCP %s name", capabilityType), requestID)
	}

	if !isAllowedByAcl(config, capabilityName) {
		slog.Debug("MCP ACL List Policy: Capability denied by policy", "capabilityType", capabilityType, "capabilityName", capabilityName, "requestID", requestID)
		return p.buildRequestErrorResponse(ctx, 400, -32000, "MCP capability not allowed", requestID)
	}

	return nil
}

func (p *McpAclListPolicy) OnResponse(ctx *policy.ResponseContext, params map[string]any) policy.ResponseAction {
	if !isMcpPostRequest(ctx.RequestMethod, ctx.RequestPath) {
		return nil
	}
	slog.Debug("MCP ACL List Policy: OnResponse started")

	if ctx.Metadata == nil {
		return nil
	}

	capabilityType, _ := ctx.Metadata[metadataMcpCapabilityType].(string)
	action, _ := ctx.Metadata[metadataMcpAction].(string)
	if capabilityType == "" || action != "list" {
		slog.Debug("MCP ACL List Policy: OnResponse skipped, action is not list", "capabilityType", capabilityType, "action", action)
		return nil
	}

	config := p.getAclConfig(capabilityType)
	if !config.Enabled {
		return nil
	}

	if ctx.ResponseBody == nil || !ctx.ResponseBody.Present {
		return nil
	}

	if isEventStream(ctx.ResponseHeaders) {
		events := parseEventStream(ctx.ResponseBody.Content)
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
		return policy.UpstreamResponseModifications{
			Body: buildEventStream(events),
		}
	}

	var responsePayload map[string]any
	if err := json.Unmarshal(ctx.ResponseBody.Content, &responsePayload); err != nil {
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

	return policy.UpstreamResponseModifications{
		Body: updatedPayload,
	}
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

// isEventStream reports whether headers indicate an SSE payload.
func isEventStream(headers *policy.Headers) bool {
	if headers == nil {
		return false
	}
	values := headers.Get("content-type")
	if len(values) == 0 {
		values = headers.Get("Content-Type")
	}
	for _, value := range values {
		if strings.Contains(strings.ToLower(value), "text/event-stream") {
			return true
		}
	}
	return false
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

// buildRequestErrorResponse builds an error response for a request.
func (p *McpAclListPolicy) buildRequestErrorResponse(ctx *policy.RequestContext, statusCode int, jsonRpcCode int, reason string, requestID any) policy.RequestAction {
	sessionID := getSessionID(ctx.Headers)
	if isEventStream(ctx.Headers) {
		return p.buildEventStreamErrorResponse(statusCode, jsonRpcCode, reason, requestID, sessionID)
	}
	return p.buildErrorResponse(statusCode, jsonRpcCode, reason, requestID, sessionID)
}

// buildEventStreamErrorResponse builds an SSE error response.
func (p *McpAclListPolicy) buildEventStreamErrorResponse(statusCode int, jsonRpcCode int, reason string, requestID any, sessionID string) policy.RequestAction {
	responseBody := map[string]any{
		"jsonrpc": "2.0",
		"id":      requestID,
		"error": map[string]any{
			"code":    jsonRpcCode,
			"message": reason,
		},
	}
	body, err := json.Marshal(responseBody)
	if err != nil {
		slog.Debug("MCP ACL List Policy: Failed to marshal event-stream error response", "error", err)
		idBytes, idErr := json.Marshal(requestID)
		if idErr != nil {
			idBytes = []byte("null")
		}
		body = fmt.Appendf(nil, `{"jsonrpc":"2.0","id":%s,"error":{"code":-32603,"message":"Unexpected error"}}`, string(idBytes))
	}

	event := sseEvent{data: string(body)}
	streamBody := buildEventStream([]sseEvent{event})

	headers := map[string]string{
		"Content-Type": "text/event-stream",
	}
	if sessionID != "" {
		headers[mcpSessionHeader] = sessionID
	}

	return policy.ImmediateResponse{
		StatusCode: statusCode,
		Headers:    headers,
		Body:       streamBody,
	}
}

// isMcpPostRequest reports whether the request targets the MCP endpoint.
func isMcpPostRequest(method, path string) bool {
	return strings.EqualFold(method, "POST") && strings.Contains(path, mcpPathSegment)
}

// buildErrorResponse builds a JSON error response.
func (p *McpAclListPolicy) buildErrorResponse(statusCode int, jsonRpcCode int, reason string, requestID any, sessionID string) policy.RequestAction {
	responseBody := map[string]any{
		"jsonrpc": "2.0",
		"id":      requestID,
		"error": map[string]any{
			"code":    jsonRpcCode,
			"message": reason,
		},
	}
	body, err := json.Marshal(responseBody)
	if err != nil {
		slog.Debug("MCP ACL List Policy: Failed to marshal error response", "error", err)
		idBytes, idErr := json.Marshal(requestID)
		if idErr != nil {
			idBytes = []byte("null")
		}
		body = fmt.Appendf(nil, `{"jsonrpc":"2.0","id":%s,"error":{"code":-32603,"message":"Unexpected error"}}`, string(idBytes))
	}

	headers := map[string]string{
		"Content-Type": "application/json",
	}
	if sessionID != "" {
		headers[mcpSessionHeader] = sessionID
	}

	return policy.ImmediateResponse{
		StatusCode: statusCode,
		Headers:    headers,
		Body:       body,
	}
}

// getSessionID extracts the MCP session ID from headers.
func getSessionID(headers *policy.Headers) string {
	if headers == nil {
		return ""
	}
	values := headers.Get(mcpSessionHeader)
	if len(values) == 0 {
		return ""
	}
	return values[0]
}
