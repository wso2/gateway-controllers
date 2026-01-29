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

package mcprewrite

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

type CapabilityEntry struct {
	Key      string
	Target   string
	Response map[string]any
}

type CapabilityConfig struct {
	Enabled      bool
	Entries      []CapabilityEntry
	Lookup       map[string]CapabilityEntry
	TargetLookup map[string]CapabilityEntry
}

type McpRewritePolicy struct {
	tools     CapabilityConfig
	resources CapabilityConfig
	prompts   CapabilityConfig
}

type sseEvent struct {
	fields []string
	data   string
}

func GetPolicy(
	metadata policy.PolicyMetadata,
	params map[string]any,
) (policy.Policy, error) {
	slog.Debug("MCP Rewrite Policy: GetPolicy called")

	ins := &McpRewritePolicy{}

	toolsConfig, err := parseCapabilityConfig(params, "tools")
	if err != nil {
		slog.Debug("MCP Rewrite Policy: Invalid tools configuration", "error", err)
		return nil, fmt.Errorf("invalid tools configuration: %w", err)
	}

	resourcesConfig, err := parseCapabilityConfig(params, "resources")
	if err != nil {
		slog.Debug("MCP Rewrite Policy: Invalid resources configuration", "error", err)
		return nil, fmt.Errorf("invalid resources configuration: %w", err)
	}

	promptsConfig, err := parseCapabilityConfig(params, "prompts")
	if err != nil {
		slog.Debug("MCP Rewrite Policy: Invalid prompts configuration", "error", err)
		return nil, fmt.Errorf("invalid prompts configuration: %w", err)
	}

	ins.tools = toolsConfig
	ins.resources = resourcesConfig
	ins.prompts = promptsConfig

	slog.Debug("MCP Rewrite Policy: Parsed configuration",
		"toolsEnabled", ins.tools.Enabled,
		"toolsCount", len(ins.tools.Entries),
		"resourcesEnabled", ins.resources.Enabled,
		"resourcesCount", len(ins.resources.Entries),
		"promptsEnabled", ins.prompts.Enabled,
		"promptsCount", len(ins.prompts.Entries),
	)

	return ins, nil
}

// parseCapabilityConfig parses capability-specific configuration entries.
func parseCapabilityConfig(params map[string]any, capabilityType string) (CapabilityConfig, error) {
	config := CapabilityConfig{
		Lookup:       make(map[string]CapabilityEntry),
		TargetLookup: make(map[string]CapabilityEntry),
	}

	raw, ok := params[capabilityType]
	if !ok {
		return config, nil
	}

	list, ok := raw.([]any)
	if !ok {
		slog.Debug("MCP Rewrite Policy: Invalid capability config", "capabilityType", capabilityType, "error", "not an array")
		return config, fmt.Errorf("%s must be an array", capabilityType)
	}

	config.Enabled = true

	if len(list) == 0 {
		return config, nil
	}
	for i, item := range list {
		entryMap, ok := item.(map[string]any)
		if !ok {
			slog.Debug("MCP Rewrite Policy: Invalid capability entry", "capabilityType", capabilityType, "index", i, "error", "not an object")
			return config, fmt.Errorf("%s[%d] must be an object", capabilityType, i)
		}

		requiredFields := []string{"name"}
		switch capabilityType {
		case "tools":
			requiredFields = append(requiredFields, "description", "inputSchema")
		case "resources":
			requiredFields = append(requiredFields, "uri")
		}

		for _, field := range requiredFields {
			valueRaw, exists := entryMap[field]
			if !exists {
				slog.Debug("MCP Rewrite Policy: Missing required field", "capabilityType", capabilityType, "index", i, "field", field)
				return config, fmt.Errorf("%s[%d].%s is required", capabilityType, i, field)
			}
			value, ok := valueRaw.(string)
			if !ok || strings.TrimSpace(value) == "" {
				slog.Debug("MCP Rewrite Policy: Invalid field value", "capabilityType", capabilityType, "index", i, "field", field, "error", "not a non-empty string")
				return config, fmt.Errorf("%s[%d].%s must be a non-empty string", capabilityType, i, field)
			}
		}

		name, _ := entryMap["name"].(string)

		target := ""
		if targetRaw, ok := entryMap["target"]; ok {
			targetStr, ok := targetRaw.(string)
			if !ok {
				slog.Debug("MCP Rewrite Policy: Invalid field value", "capabilityType", capabilityType, "index", i, "field", "target", "error", "not a string")
				return config, fmt.Errorf("%s[%d].target must be a string", capabilityType, i)
			}
			target = targetStr
		}

		uri := ""
		if uriRaw, ok := entryMap["uri"]; ok {
			uri, _ = uriRaw.(string)
		}

		if strings.TrimSpace(target) == "" {
			if capabilityType == "resources" && strings.TrimSpace(uri) != "" {
				target = uri
			} else {
				target = name
			}
		}

		response := make(map[string]any, len(entryMap))
		for k, v := range entryMap {
			if k == "target" {
				continue
			}
			switch value := v.(type) {
			case string:
				trimmed := strings.TrimSpace(value)
				if trimmed != "" {
					first := trimmed[0]
					if first == '{' || first == '[' {
						var vAny any
						if err := json.Unmarshal([]byte(trimmed), &vAny); err == nil {
							response[k] = vAny
							continue
						}
					}
				}
				response[k] = value
			case []byte:
				trimmed := strings.TrimSpace(string(value))
				if trimmed != "" {
					first := trimmed[0]
					if first == '{' || first == '[' {
						var vAny any
						if err := json.Unmarshal([]byte(trimmed), &vAny); err == nil {
							response[k] = vAny
							continue
						}
					}
				}
				response[k] = value
			default:
				response[k] = v
			}
		}

		entryKey := name
		if capabilityType == "resources" {
			entryKey = uri
		}

		entry := CapabilityEntry{
			Key:      entryKey,
			Target:   target,
			Response: response,
		}

		config.Entries = append(config.Entries, entry)
		if strings.TrimSpace(entry.Key) != "" {
			config.Lookup[entry.Key] = entry
		}
		if strings.TrimSpace(entry.Target) != "" {
			config.TargetLookup[entry.Target] = entry
		}
	}

	return config, nil
}

func (p *McpRewritePolicy) Mode() policy.ProcessingMode {
	return policy.ProcessingMode{
		RequestHeaderMode:  policy.HeaderModeSkip,
		RequestBodyMode:    policy.BodyModeBuffer,
		ResponseHeaderMode: policy.HeaderModeSkip,
		ResponseBodyMode:   policy.BodyModeBuffer,
	}
}

func (p *McpRewritePolicy) OnRequest(ctx *policy.RequestContext, params map[string]any) policy.RequestAction {
	if !isMcpPostRequest(ctx.Method, ctx.Path) {
		return nil
	}
	slog.Debug("MCP Rewrite Policy: OnRequest started")

	if ctx.Body == nil || len(ctx.Body.Content) == 0 {
		return nil
	}

	requestPayload, requestEvents, requestEventIndex, err := parseRequestPayload(ctx.Body.Content, isEventStream(ctx.Headers))
	if err != nil {
		slog.Debug("MCP Rewrite Policy: Failed to parse MCP request", "error", err, "path", ctx.Path)
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

	if !rewriteApplicable(capabilityType, action) {
		return nil
	}

	config := p.getCapabilityConfig(capabilityType)
	if !config.Enabled {
		return nil
	}

	if len(config.Entries) == 0 {
		return nil
	}

	paramsRaw, ok := requestPayload["params"].(map[string]any)
	if !ok {
		slog.Debug("MCP Rewrite Policy: Invalid request params", "capabilityType", capabilityType, "requestID", requestID, "error", "params not a map")
		return p.buildRequestErrorResponse(ctx, 400, -32602, "Invalid MCP request params", requestID)
	}

	paramKey := getParamKey(capabilityType)
	capabilityName, _ := paramsRaw[paramKey].(string)
	if strings.TrimSpace(capabilityName) == "" {
		slog.Debug("MCP Rewrite Policy: Missing capability name", "capabilityType", capabilityType, "requestID", requestID, "paramKey", paramKey)
		return p.buildRequestErrorResponse(ctx, 400, -32602, fmt.Sprintf("Missing MCP %s name", capabilityType), requestID)
	}

	entry, exists := config.Lookup[capabilityName]
	if !exists {
		return nil
	}

	if entry.Target != "" && entry.Target != capabilityName {
		paramsRaw[paramKey] = entry.Target
		requestPayload["params"] = paramsRaw

		updatedPayload, err := json.Marshal(requestPayload)
		if err != nil {
			slog.Debug("MCP Rewrite Policy: Failed to marshal updated request", "capabilityType", capabilityType, "capabilityName", capabilityName, "requestID", requestID, "error", err)
			return p.buildRequestErrorResponse(ctx, 500, -32603, "Failed to update MCP request", requestID)
		}

		if len(requestEvents) > 0 && requestEventIndex >= 0 {
			requestEvents[requestEventIndex].data = string(updatedPayload)
			updatedPayload = buildEventStream(requestEvents)
		}
		slog.Debug("MCP Rewrite Policy: Request rewritten", "capabilityType", capabilityType, "requestName", capabilityName, "targetName", entry.Target, "requestID", requestID)
		return policy.UpstreamRequestModifications{
			Body: updatedPayload,
		}
	}

	return nil
}

func (p *McpRewritePolicy) OnResponse(ctx *policy.ResponseContext, params map[string]any) policy.ResponseAction {
	if !isMcpPostRequest(ctx.RequestMethod, ctx.RequestPath) {
		return nil
	}
	slog.Debug("MCP Rewrite Policy: OnResponse started")

	if ctx.Metadata == nil {
		return nil
	}

	capabilityType, _ := ctx.Metadata[metadataMcpCapabilityType].(string)
	action, _ := ctx.Metadata[metadataMcpAction].(string)
	if action != "list" {
		slog.Debug("MCP Rewrite Policy: OnResponse skipped, action is not list", "capabilityType", capabilityType, "action", action)
		return nil
	}

	config := p.getCapabilityConfig(capabilityType)
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
				slog.Debug("MCP Rewrite Policy: Upstream response contains error", "capabilityType", capabilityType)
				continue
			}
			resultRaw, ok := responsePayload["result"].(map[string]any)
			if !ok {
				slog.Debug("MCP Rewrite Policy: Invalid MCP response result", "capabilityType", capabilityType, "error", "result not an object")
				continue
			}

			listKey := capabilityType
			existing, ok := resultRaw[listKey].([]any)
			if !ok {
				continue
			}

			filtered, changed := rewriteListItems(existing, capabilityType, config)
			if !changed {
				continue
			}

			resultRaw[listKey] = filtered
			responsePayload["result"] = resultRaw

			updatedPayload, err := json.Marshal(responsePayload)
			if err != nil {
				slog.Debug("MCP Rewrite Policy: Failed to marshal updated response", "capabilityType", capabilityType, "error", err)
				continue
			}
			events[i].data = string(updatedPayload)
			updated = true
		}

		if !updated {
			slog.Debug("MCP Rewrite Policy: No changes made to the response", "capabilityType", capabilityType)
			return nil
		}
		return policy.UpstreamResponseModifications{
			Body: buildEventStream(events),
		}
	}

	var responsePayload map[string]any
	if err := json.Unmarshal(ctx.ResponseBody.Content, &responsePayload); err != nil {
		slog.Debug("MCP Rewrite Policy: Failed to parse MCP response", "capabilityType", capabilityType, "error", err)
		return nil
	}

	if _, hasError := responsePayload["error"]; hasError {
		slog.Debug("MCP Rewrite Policy: Upstream response contains error", "capabilityType", capabilityType)
		return nil
	}

	resultRaw, ok := responsePayload["result"].(map[string]any)
	if !ok {
		slog.Debug("MCP Rewrite Policy: Invalid MCP response result", "capabilityType", capabilityType, "error", "result not an object")
		return nil
	}

	listKey := capabilityType
	existing, ok := resultRaw[listKey].([]any)
	if !ok {
		return nil
	}

	filtered, changed := rewriteListItems(existing, capabilityType, config)
	if !changed {
		return nil
	}

	resultRaw[listKey] = filtered
	responsePayload["result"] = resultRaw

	updatedPayload, err := json.Marshal(responsePayload)
	if err != nil {
		slog.Debug("MCP Rewrite Policy: Failed to marshal updated response", "capabilityType", capabilityType, "error", err)
		return nil
	}

	return policy.UpstreamResponseModifications{
		Body: updatedPayload,
	}
}

// rewriteListItems filters and rewrites list items based on configured entries.
func rewriteListItems(items []any, capabilityType string, config CapabilityConfig) ([]any, bool) {
	keyField := getParamKey(capabilityType)
	filtered := make([]any, 0, len(items))
	changed := false

	if len(config.Entries) == 0 {
		return []any{}, len(items) != 0
	}

	for _, item := range items {
		entry, ok := item.(map[string]any)
		if !ok {
			filtered = append(filtered, item)
			continue
		}
		key, ok := entry[keyField].(string)
		if !ok || strings.TrimSpace(key) == "" {
			filtered = append(filtered, item)
			continue
		}

		// target is the actual capability name in MCP list responses
		// so we look up by target and replace with the configured response
		if configured, ok := config.TargetLookup[key]; ok {
			slog.Debug("MCP Rewrite Policy: Rewriting list item", "type", capabilityType, "keyField", keyField, "key", key)
			filtered = append(filtered, buildResponseFromConfig(configured, keyField))
			changed = true
			continue
		}

		filtered = append(filtered, item)
	}

	if len(filtered) != len(items) {
		changed = true
	}

	return filtered, changed
}

// buildResponseFromConfig builds the list item payload from a configured entry.
func buildResponseFromConfig(entry CapabilityEntry, keyField string) map[string]any {
	if entry.Response == nil {
		return map[string]any{keyField: entry.Key}
	}
	return entry.Response
}

// getCapabilityConfig returns the config for a capability type.
func (p *McpRewritePolicy) getCapabilityConfig(capabilityType string) CapabilityConfig {
	switch capabilityType {
	case "tools":
		return p.tools
	case "resources":
		return p.resources
	case "prompts":
		return p.prompts
	default:
		return CapabilityConfig{}
	}
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

// rewriteApplicable reports whether request rewriting applies for a method.
func rewriteApplicable(capabilityType, action string) bool {
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

// buildRequestErrorResponse builds an error response for a request.
func (p *McpRewritePolicy) buildRequestErrorResponse(ctx *policy.RequestContext, statusCode int, jsonRpcCode int, reason string, requestID any) policy.RequestAction {
	sessionID := getSessionID(ctx.Headers)
	if isEventStream(ctx.Headers) {
		return p.buildEventStreamErrorResponse(statusCode, jsonRpcCode, reason, requestID, sessionID)
	}
	return p.buildErrorResponse(statusCode, jsonRpcCode, reason, requestID, sessionID)
}

// buildEventStreamErrorResponse builds an SSE error response.
func (p *McpRewritePolicy) buildEventStreamErrorResponse(statusCode int, jsonRpcCode int, reason string, requestID any, sessionID string) policy.RequestAction {
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
		slog.Debug("MCP Rewrite Policy: Failed to marshal event-stream error response", "error", err)
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
func (p *McpRewritePolicy) buildErrorResponse(statusCode int, jsonRpcCode int, reason string, requestID any, sessionID string) policy.RequestAction {
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
		slog.Debug("MCP Rewrite Policy: Failed to marshal error response", "error", err)
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
