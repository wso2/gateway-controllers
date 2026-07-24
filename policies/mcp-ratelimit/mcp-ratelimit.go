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

package mcpratelimit

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"maps"
	"strings"
	"sync"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
	ratelimit "github.com/wso2/gateway-controllers/policies/advanced-ratelimit"
)

const (
	mcpSessionHeader = "mcp-session-id"

	// Metadata keys populated for downstream policies (mirrors mcp-authz / mcp-acl-list).
	metadataMcpMethod         = "mcp.method"
	metadataMcpCapabilityType = "mcp.type"
	metadataMcpCapabilityName = "mcp.name"

	// Metadata key tracking delegates invoked during the request phase so the
	// response phase can forward to the same instances.
	metadataInvokedDelegates = "mcp-ratelimit.invoked-delegates"

	sectionTools     = "tools"
	sectionResources = "resources"
	sectionPrompts   = "prompts"
	sectionMethods   = "methods"

	jsonRpcErrCodeRateLimited = -32000
)

// limitEntry holds the parsed rule for a single capability rate-limit entry.
// limitsRaw and keyExtractionRaw are kept as raw maps so they can be passed
// through unchanged to advanced-ratelimit.
type limitEntry struct {
	section          string // tools / resources / prompts / methods
	name             string // configured name or "*"
	limitsRaw        []any  // pass-through to advanced-ratelimit quota.limits
	keyExtractionRaw []any  // pass-through to advanced-ratelimit quota.keyExtraction (optional)
}

// matchedEntry pairs a rule entry index with the resolved capability identifier
// (tool name / resource URI / prompt name / JSON-RPC method) that the request
// resolved to. The identifier becomes part of the delegate's key so that each
// distinct capability has its own bucket — even under wildcard rules.
type matchedEntry struct {
	entryIdx     int
	capabilityID string
}

// MCPRequest captures the JSON-RPC fields we read from the MCP request body.
type mcpRequest struct {
	Method string          `json:"method"`
	ID     json.RawMessage `json:"id"`
	Params struct {
		Name string `json:"name"` // tools/call, prompts/get
		URI  string `json:"uri"`  // resources/read
	} `json:"params"`
}

// McpRateLimitPolicy applies per-capability rate limits to MCP traffic by
// dispatching matched requests to dynamically-built advanced-ratelimit delegates.
type McpRateLimitPolicy struct {
	metadata policy.PolicyMetadata

	entries             []limitEntry
	globalKeyExtraction []any
	onRateLimitExceeded map[string]any
	systemParams        map[string]any

	// delegateKey ("<entryIdx>:<capabilityID>") -> policy.Policy (advanced-ratelimit instance)
	delegates sync.Map
}

// GetPolicy is the v1alpha2 factory entry point.
func GetPolicy(metadata policy.PolicyMetadata, params map[string]any) (policy.Policy, error) {
	p := &McpRateLimitPolicy{metadata: metadata}

	entries, err := parseEntries(params)
	if err != nil {
		return nil, fmt.Errorf("mcp-ratelimit: %w", err)
	}
	if len(entries) == 0 {
		return nil, fmt.Errorf("mcp-ratelimit: at least one of tools, resources, prompts, or methods must be configured")
	}
	p.entries = entries

	if gke, ok := params["keyExtraction"].([]any); ok {
		p.globalKeyExtraction = gke
	}
	if oe, ok := params["onRateLimitExceeded"].(map[string]any); ok {
		p.onRateLimitExceeded = oe
	}

	p.systemParams = make(map[string]any)
	for _, key := range []string{"algorithm", "backend", "redis", "memory", "local", "headers"} {
		if v, ok := params[key]; ok {
			p.systemParams[key] = v
		}
	}

	sectionCounts := map[string]int{}
	for _, e := range entries {
		sectionCounts[e.section]++
	}

	slog.Debug("MCP RateLimit Policy: configured",
		"route", metadata.RouteName,
		"entries", len(entries),
		"tools", sectionCounts[sectionTools],
		"resources", sectionCounts[sectionResources],
		"prompts", sectionCounts[sectionPrompts],
		"methods", sectionCounts[sectionMethods])

	return p, nil
}

func (p *McpRateLimitPolicy) Mode() policy.ProcessingMode {
	return policy.ProcessingMode{
		RequestHeaderMode:  policy.HeaderModeSkip,
		RequestBodyMode:    policy.BodyModeBuffer,
		ResponseHeaderMode: policy.HeaderModeProcess,
		ResponseBodyMode:   policy.BodyModeSkip,
	}
}

// OnRequestBody parses the MCP request envelope, finds matching rate-limit
// entries, and delegates enforcement to a per-(entry, capability) cached
// advanced-ratelimit instance.
func (p *McpRateLimitPolicy) OnRequestBody(ctx context.Context, reqCtx *policy.RequestContext, params map[string]any) policy.RequestAction {
	if !isMcpPostRequest(reqCtx.Method) {
		return policy.UpstreamRequestModifications{}
	}
	if reqCtx.Body == nil || len(reqCtx.Body.Content) == 0 {
		return policy.UpstreamRequestModifications{}
	}

	method, capType, capName, requestID, err := p.identifyCapability(reqCtx)
	if err != nil {
		slog.Debug("MCP RateLimit Policy: failed to parse MCP request", "error", err)
		return p.buildJsonRpcError(getDownstreamHeaders(reqCtx.Downstream, reqCtx.Headers), 400, -32700, "Invalid MCP request body", nil)
	}
	if method == "" {
		return policy.UpstreamRequestModifications{}
	}

	if reqCtx.Metadata == nil {
		reqCtx.Metadata = make(map[string]any)
	}
	reqCtx.Metadata[metadataMcpMethod] = method
	if capType != "" {
		reqCtx.Metadata[metadataMcpCapabilityType] = capType
	}
	if capName != "" {
		reqCtx.Metadata[metadataMcpCapabilityName] = capName
	}

	matches := p.findMatches(method, capType, capName)
	if len(matches) == 0 {
		return policy.UpstreamRequestModifications{}
	}

	type requestHeaderPolicer interface {
		OnRequestHeaders(context.Context, *policy.RequestHeaderContext, map[string]any) policy.RequestHeaderAction
	}

	headerCtx := synthesizeHeaderContext(reqCtx)
	var invoked []string

	for _, m := range matches {
		delegate, derr := p.resolveDelegate(m.entryIdx, m.capabilityID)
		if derr != nil || delegate == nil {
			slog.Warn("MCP RateLimit Policy: failed to resolve delegate",
				"entryIdx", m.entryIdx,
				"capabilityID", m.capabilityID,
				"error", derr)
			continue
		}

		rl, ok := delegate.(requestHeaderPolicer)
		if !ok {
			continue
		}

		action := rl.OnRequestHeaders(ctx, headerCtx, params)
		invoked = append(invoked, delegateKey(m.entryIdx, m.capabilityID))

		if immediate, isImmediate := action.(policy.ImmediateResponse); isImmediate {
			slog.Debug("MCP RateLimit Policy: limit exceeded",
				"section", p.entries[m.entryIdx].section,
				"rule", p.entries[m.entryIdx].name,
				"capabilityID", m.capabilityID)
			return p.rewriteRateLimitedResponse(getDownstreamHeaders(reqCtx.Downstream, reqCtx.Headers), immediate, requestID)
		}
	}

	if len(invoked) > 0 {
		if reqCtx.SharedContext.Metadata == nil {
			reqCtx.SharedContext.Metadata = make(map[string]any)
		}
		reqCtx.SharedContext.Metadata[metadataInvokedDelegates] = invoked
	}

	return policy.UpstreamRequestModifications{}
}

// OnResponseHeaders forwards to every delegate invoked during the request phase
// so each can write its rate-limit headers (RateLimit-*, X-RateLimit-*,
// Retry-After). When multiple delegates set the same header, the later
// delegate's value wins; this is an accepted simplification.
func (p *McpRateLimitPolicy) OnResponseHeaders(ctx context.Context, respCtx *policy.ResponseHeaderContext, params map[string]any) policy.ResponseHeaderAction {
	invoked, _ := respCtx.SharedContext.Metadata[metadataInvokedDelegates].([]string)
	if len(invoked) == 0 {
		return policy.DownstreamResponseHeaderModifications{}
	}

	type responseHeaderPolicer interface {
		OnResponseHeaders(context.Context, *policy.ResponseHeaderContext, map[string]any) policy.ResponseHeaderAction
	}

	merged := make(map[string]string)
	var toRemove []string
	for _, key := range invoked {
		dRaw, ok := p.delegates.Load(key)
		if !ok {
			continue
		}
		delegate, ok := dRaw.(policy.Policy)
		if !ok {
			continue
		}
		rl, ok := delegate.(responseHeaderPolicer)
		if !ok {
			continue
		}
		action := rl.OnResponseHeaders(ctx, respCtx, params)
		mods, ok := action.(policy.DownstreamResponseHeaderModifications)
		if !ok {
			continue
		}
		maps.Copy(merged, mods.HeadersToSet)
		toRemove = append(toRemove, mods.HeadersToRemove...)
	}

	return policy.DownstreamResponseHeaderModifications{
		HeadersToSet:    merged,
		HeadersToRemove: toRemove,
	}
}

// identifyCapability extracts method, capability type, capability name, and the
// JSON-RPC request id from the MCP request body. Handles both plain-JSON and
// text/event-stream-wrapped envelopes.
func (p *McpRateLimitPolicy) identifyCapability(reqCtx *policy.RequestContext) (method, capType, capName string, requestID json.RawMessage, err error) {
	body := reqCtx.Body.Content
	if isEventStream(getDownstreamHeaders(reqCtx.Downstream, reqCtx.Headers)) {
		body = extractFirstSseJSON(body)
		if len(body) == 0 {
			return "", "", "", nil, fmt.Errorf("no JSON payload found in event stream")
		}
	}

	var req mcpRequest
	if err = json.Unmarshal(body, &req); err != nil {
		return "", "", "", nil, err
	}

	method = req.Method
	if method == "" {
		return "", "", "", req.ID, nil
	}

	parts := strings.SplitN(method, "/", 2)
	if len(parts) == 2 {
		switch parts[0] {
		case "tools":
			capType = "tool"
			if parts[1] == "call" {
				capName = req.Params.Name
			}
		case "resources":
			capType = "resource"
			if parts[1] == "read" {
				capName = req.Params.URI
			}
		case "prompts":
			capType = "prompt"
			if parts[1] == "get" {
				capName = req.Params.Name
			}
		}
	}

	return method, capType, capName, req.ID, nil
}

// findMatches returns the rule entries that apply to this request, in
// enforcement order: exact-name matches first, then wildcard rules. All
// returned entries are enforced; the strictest blocks the request.
func (p *McpRateLimitPolicy) findMatches(method, capType, capName string) []matchedEntry {
	var exact, wildcard []matchedEntry

	for i, e := range p.entries {
		switch e.section {
		case sectionMethods:
			switch e.name {
			case method:
				exact = append(exact, matchedEntry{entryIdx: i, capabilityID: method})
			case "*":
				wildcard = append(wildcard, matchedEntry{entryIdx: i, capabilityID: method})
			}
		case sectionTools:
			if capType != "tool" || capName == "" {
				continue
			}
			switch e.name {
			case capName:
				exact = append(exact, matchedEntry{entryIdx: i, capabilityID: capName})
			case "*":
				wildcard = append(wildcard, matchedEntry{entryIdx: i, capabilityID: capName})
			}
		case sectionResources:
			if capType != "resource" || capName == "" {
				continue
			}
			switch e.name {
			case capName:
				exact = append(exact, matchedEntry{entryIdx: i, capabilityID: capName})
			case "*":
				wildcard = append(wildcard, matchedEntry{entryIdx: i, capabilityID: capName})
			}
		case sectionPrompts:
			if capType != "prompt" || capName == "" {
				continue
			}
			switch e.name {
			case capName:
				exact = append(exact, matchedEntry{entryIdx: i, capabilityID: capName})
			case "*":
				wildcard = append(wildcard, matchedEntry{entryIdx: i, capabilityID: capName})
			}
		}
	}

	return append(exact, wildcard...)
}

// resolveDelegate fetches or lazily builds the advanced-ratelimit instance for
// the given (entry, capability) pair. Each combination has its own delegate so
// each tool/resource/prompt under a wildcard rule keeps its own counter.
func (p *McpRateLimitPolicy) resolveDelegate(entryIdx int, capabilityID string) (policy.Policy, error) {
	key := delegateKey(entryIdx, capabilityID)
	if existing, ok := p.delegates.Load(key); ok {
		return existing.(policy.Policy), nil
	}

	entry := p.entries[entryIdx]

	// Build keyExtraction = (entry || global || [routename]) + constant(capabilityID).
	// The trailing constant keeps each capability in its own bucket even when the
	// rule name is "*".
	keyExtraction := []any{}
	switch {
	case len(entry.keyExtractionRaw) > 0:
		keyExtraction = append(keyExtraction, entry.keyExtractionRaw...)
	case len(p.globalKeyExtraction) > 0:
		keyExtraction = append(keyExtraction, p.globalKeyExtraction...)
	default:
		keyExtraction = append(keyExtraction, map[string]any{"type": "routename"})
	}
	keyExtraction = append(keyExtraction, map[string]any{
		"type": "constant",
		"key":  fmt.Sprintf("mcp:%s:%d:%s", entry.section, entryIdx, capabilityID),
	})
	slog.Debug("MCP RateLimit Policy: Resolving delegate", "key", fmt.Sprintf("mcp:%s:%d:%s", entry.section, entryIdx, capabilityID))

	quota := map[string]any{
		"name":          fmt.Sprintf("mcp-%s-%d-%s", entry.section, entryIdx, capabilityID),
		"limits":        entry.limitsRaw,
		"keyExtraction": keyExtraction,
	}

	rlParams := map[string]any{
		"quotas": []any{quota},
	}
	if p.onRateLimitExceeded != nil {
		rlParams["onRateLimitExceeded"] = p.onRateLimitExceeded
	}
	maps.Copy(rlParams, p.systemParams)

	delegate, err := ratelimit.GetPolicy(p.metadata, rlParams)
	if err != nil {
		return nil, err
	}

	actual, loaded := p.delegates.LoadOrStore(key, delegate)
	if loaded {
		return actual.(policy.Policy), nil
	}
	return delegate, nil
}

// rewriteRateLimitedResponse turns an advanced-ratelimit ImmediateResponse into
// a JSON-RPC error envelope (unless the user provided a custom body) and
// preserves the rate-limit headers set by the delegate.
func (p *McpRateLimitPolicy) rewriteRateLimitedResponse(reqHeaders *policy.Headers, immediate policy.ImmediateResponse, requestID json.RawMessage) policy.RequestAction {
	if p.hasUserDefinedBody() {
		return immediate
	}

	headers := immediate.Headers
	if headers == nil {
		headers = make(map[string]string)
	}

	sessionID := getSessionID(reqHeaders)
	if sessionID != "" {
		if _, exists := headers[mcpSessionHeader]; !exists {
			headers[mcpSessionHeader] = sessionID
		}
	}

	body, contentType := buildJsonRpcRateLimitedBody(requestID, isEventStream(reqHeaders))
	headers["content-type"] = contentType

	statusCode := immediate.StatusCode
	if statusCode == 0 {
		statusCode = 429
	}

	return policy.ImmediateResponse{
		StatusCode:        statusCode,
		Headers:           headers,
		Body:              body,
		AnalyticsMetadata: immediate.AnalyticsMetadata,
		DynamicMetadata:   immediate.DynamicMetadata,
	}
}

func (p *McpRateLimitPolicy) hasUserDefinedBody() bool {
	if p.onRateLimitExceeded == nil {
		return false
	}
	body, ok := p.onRateLimitExceeded["body"].(string)
	return ok && body != ""
}

// buildJsonRpcError constructs a JSON-RPC formatted error for malformed
// request envelopes (analogous to mcp-acl-list.buildRequestErrorResponse).
func (p *McpRateLimitPolicy) buildJsonRpcError(reqHeaders *policy.Headers, statusCode, jsonRpcCode int, message string, requestID json.RawMessage) policy.RequestAction {
	body, contentType := buildJsonRpcErrorBody(requestID, jsonRpcCode, message, isEventStream(reqHeaders))
	headers := map[string]string{"content-type": contentType}
	if sid := getSessionID(reqHeaders); sid != "" {
		headers[mcpSessionHeader] = sid
	}
	return policy.ImmediateResponse{
		StatusCode: statusCode,
		Headers:    headers,
		Body:       body,
	}
}

func delegateKey(entryIdx int, capabilityID string) string {
	return fmt.Sprintf("%d:%s", entryIdx, capabilityID)
}

func synthesizeHeaderContext(reqCtx *policy.RequestContext) *policy.RequestHeaderContext {
	return &policy.RequestHeaderContext{
		SharedContext: reqCtx.SharedContext,
		Headers:       reqCtx.Headers,
		Path:          reqCtx.Path,
		Method:        reqCtx.Method,
		Authority:     reqCtx.Authority,
		Scheme:        reqCtx.Scheme,
		Vhost:         reqCtx.Vhost,
		Downstream:    reqCtx.Downstream,
	}
}

func isMcpPostRequest(method string) bool {
	if !strings.EqualFold(method, "POST") {
		return false
	}
	return true
}

func isEventStream(headers *policy.Headers) bool {
	if headers == nil {
		return false
	}
	for key, values := range headers.GetAll() {
		if strings.EqualFold(key, "content-type") {
			for _, v := range values {
				if strings.Contains(strings.ToLower(v), "text/event-stream") {
					return true
				}
			}
		}
	}
	return false
}

func getSessionID(headers *policy.Headers) string {
	if headers == nil {
		return ""
	}
	values := headers.Get(mcpSessionHeader)
	if len(values) > 0 {
		return values[0]
	}
	return ""
}

// extractFirstSseJSON returns the first SSE `data:` JSON payload found in body.
func extractFirstSseJSON(body []byte) []byte {
	var data strings.Builder
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSuffix(line, "\r")
		if line == "" {
			if data.Len() > 0 {
				candidate := strings.TrimSpace(data.String())
				if candidate != "" {
					return []byte(candidate)
				}
				data.Reset()
			}
			continue
		}
		if strings.HasPrefix(line, "data:") {
			chunk := strings.TrimPrefix(line, "data:")
			chunk = strings.TrimPrefix(chunk, " ")
			if data.Len() > 0 {
				data.WriteString("\n")
			}
			data.WriteString(chunk)
		}
	}
	if data.Len() > 0 {
		return []byte(strings.TrimSpace(data.String()))
	}
	return nil
}

func buildJsonRpcRateLimitedBody(requestID json.RawMessage, sse bool) ([]byte, string) {
	return buildJsonRpcErrorBody(requestID, jsonRpcErrCodeRateLimited, "Rate limit exceeded. Please try again later.", sse)
}

// buildJsonRpcErrorBody constructs a JSON-RPC error envelope with the given code and message, using the requestID if available.
// If sse is true, wraps the JSON in an SSE `data:` envelope.
func buildJsonRpcErrorBody(requestID json.RawMessage, code int, message string, sse bool) ([]byte, string) {
	id := requestID
	if len(id) == 0 {
		id = json.RawMessage("null")
	}
	envelope := map[string]any{
		"jsonrpc": "2.0",
		"id":      id,
		"error": map[string]any{
			"code":    code,
			"message": message,
		},
	}
	body, err := json.Marshal(envelope)
	if err != nil {
		body = fmt.Appendf(nil, `{"jsonrpc":"2.0","id":null,"error":{"code":%d,"message":%q}}`, code, message)
	}
	if sse {
		return []byte("data: " + string(body) + "\n\n"), "text/event-stream"
	}
	return body, "application/json"
}

// parseEntries validates and parses the raw policy configuration into structured limitEntry objects.
func parseEntries(params map[string]any) ([]limitEntry, error) {
	var entries []limitEntry

	for _, section := range []string{sectionTools, sectionResources, sectionPrompts, sectionMethods} {
		raw, ok := params[section]
		if !ok {
			continue
		}
		arr, ok := raw.([]any)
		if !ok {
			return nil, fmt.Errorf("%s must be an array", section)
		}
		for i, item := range arr {
			obj, ok := item.(map[string]any)
			if !ok {
				return nil, fmt.Errorf("%s[%d] must be an object", section, i)
			}

			name, ok := obj["name"].(string)
			if !ok || strings.TrimSpace(name) == "" {
				name = "*"
			}

			limitsRaw, ok := obj["limits"].([]any)
			if !ok || len(limitsRaw) == 0 {
				return nil, fmt.Errorf("%s[%d].limits must be a non-empty array", section, i)
			}

			var keyExtractionRaw []any
			if ke, ok := obj["keyExtraction"].([]any); ok {
				keyExtractionRaw = ke
			}

			entries = append(entries, limitEntry{
				section:          section,
				name:             name,
				limitsRaw:        limitsRaw,
				keyExtractionRaw: keyExtractionRaw,
			})
		}
	}

	return entries, nil
}
