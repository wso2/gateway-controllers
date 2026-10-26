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

// Package mcpratelimit dispatches an MCP request to the rate-limit rules that target it.
//
// The operation it dispatches on comes from one source per era, never both:
//
//	modern (2026-07-28+)  the mirrored Mcp-Method / Mcp-Name headers; the body is not read
//	legacy                the body, via the route's resolver or this policy's own parse
//
// Checking that a modern request's headers describe its body is mcp-spec-validation's job.
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

	jsonRpcErrCodeRateLimited    = -32000
	jsonRpcErrCodeParseError     = -32700
	jsonRpcErrCodeInvalidRequest = -32600
	// A required MCP 2026-07-28 mirrored header is missing.
	jsonRpcErrCodeHeaderMismatch = -32020

	// The values the resolver publishes under mcp.body.unusable. Only syntax-error describes a
	// document that would not parse; the rest parsed but are not a usable request object.
	reasonSyntaxError       = "syntax-error"
	reasonInvalidMemberType = "invalid-member-type"
	reasonNotAnObject       = "not-an-object"
	reasonAmbiguous         = "ambiguous"
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

// Both request phases are asked for. Mode is read once at chain-build time and cannot know
// whether the route carries the MCP resolver, so shouldParseBody settles which phase decides.
//
// The response phase is unconditional: delegates invoked during the request replay there to
// write their RateLimit-* headers.
func (p *McpRateLimitPolicy) Mode() policy.ProcessingMode {
	return policy.ProcessingMode{
		RequestHeaderMode:  policy.HeaderModeProcess,
		RequestBodyMode:    policy.BodyModeBuffer,
		ResponseHeaderMode: policy.HeaderModeProcess,
		ResponseBodyMode:   policy.BodyModeSkip,
	}
}

// OnRequestHeaders rate-limits a POST on a route carrying an MCP operation resolver, where the
// capability arrives in the mirrored headers or the resolver's attributes rather than in a body.
// Without a resolver the capability is in the body, which has not arrived at this phase, so that
// case defers to OnRequestBody.
func (p *McpRateLimitPolicy) OnRequestHeaders(ctx context.Context, reqCtx *policy.RequestHeaderContext, params map[string]any) policy.RequestHeaderAction {
	// Match the MCP route on the immutable OperationPath (the API-definition path), consistent
	// with the MCP authorization and access-control policies. OperationPath is carried on
	// SharedContext, so fall back to the downstream request path when that is absent.
	ds := reqCtx.DownstreamRequest()
	routePath := ds.Path
	if reqCtx.SharedContext != nil && reqCtx.OperationPath != "" {
		routePath = reqCtx.OperationPath
	}
	if !isPostRequest(ds.Method) || !isMcpPath(routePath) {
		slog.Debug("MCP RateLimit Policy: not an MCP POST; skipping")
		return nil
	}

	// Without a resolver there are no facts at this phase; OnRequestBody parses the body instead.
	if shouldParseBody(reqCtx.SharedContext) {
		return nil
	}

	facts := mcpFacts(reqCtx.Headers, reqCtx.SharedContext)
	if facts.IsModernRequest {
		return p.limitFromMirroredHeaders(ctx, reqCtx, params, facts)
	}
	return p.limitFromResolvedBody(ctx, reqCtx, params, facts)
}

// limitFromMirroredHeaders limits a modern request on Mcp-Method and Mcp-Name. The body is not
// read here at all, not even for whether the resolver could read it; that check and the
// headers-match-body check are both mcp-spec-validation's job.
func (p *McpRateLimitPolicy) limitFromMirroredHeaders(ctx context.Context, reqCtx *policy.RequestHeaderContext,
	params map[string]any, facts mcpRequestFacts) policy.RequestHeaderAction {

	// 2026-07-28 requires Mcp-Method, and MRTR removes the method-less JSON-RPC response the
	// legacy path lets through, so a modern request without one is malformed.
	if !facts.HasMethod() {
		slog.Debug("MCP RateLimit Policy: rejecting a modern request that mirrored no method")
		return p.buildJsonRpcError(reqCtx.DownstreamHeaders(), 400, jsonRpcErrCodeHeaderMismatch,
			headerMcpMethod+" header is required", nil)
	}
	// Mcp-Name is required on the three capability methods; an undecodable one counts as missing.
	// Left in, the empty name would match no capability rule, "*" included.
	if facts.MissingRequiredName() {
		slog.Debug("MCP RateLimit Policy: rejecting a modern request that mirrored no capability name",
			"method", facts.Method)
		return p.buildJsonRpcError(reqCtx.DownstreamHeaders(), 400, jsonRpcErrCodeHeaderMismatch,
			headerMcpName+" header is required for "+facts.Method, nil)
	}
	return p.applyLimits(ctx, reqCtx, params, facts)
}

// limitFromResolvedBody limits a legacy request on the body the resolver read.
func (p *McpRateLimitPolicy) limitFromResolvedBody(ctx context.Context, reqCtx *policy.RequestHeaderContext,
	params map[string]any, facts mcpRequestFacts) policy.RequestHeaderAction {

	// Bytes the resolver could not read are refused: the gateway and the MCP server may read them
	// differently, and limiting on our reading would be limiting a guess.
	if reason := unusableBodyReason(reqCtx.SharedContext); reason != "" {
		slog.Debug("MCP RateLimit Policy: rejecting request whose body the resolver could not read",
			"reason", reason)
		return p.handleUnusableBody(reqCtx.DownstreamHeaders(), reason)
	}
	// A body that read fine but named no operation is conforming here: a JSON-RPC response
	// answering a server-initiated sampling call carries an id and a result and no method.
	if !facts.HasMethod() {
		slog.Debug("MCP RateLimit Policy: MCP capability could not be identified; not limited by this policy")
		return nil
	}
	return p.applyLimits(ctx, reqCtx, params, facts)
}

// applyLimits dispatches an established operation to its delegates, whichever era established it.
func (p *McpRateLimitPolicy) applyLimits(ctx context.Context, reqCtx *policy.RequestHeaderContext,
	params map[string]any, facts mcpRequestFacts) policy.RequestHeaderAction {

	// An empty name matches no tools/resources/prompts rule, "*" included. Only a legacy body
	// naming none gets here with one, and the server rejects that call itself.
	capType, capName := capabilityFrom(facts.Method, facts.Name)
	if resp := p.enforce(ctx, reqCtx, params, facts.Method, capType, capName, facts.RequestID); resp != nil {
		return *resp
	}
	return nil
}

// OnRequestBody parses the MCP request envelope, finds matching rate-limit
// entries, and delegates enforcement to a per-(entry, capability) cached
// advanced-ratelimit instance.
func (p *McpRateLimitPolicy) OnRequestBody(ctx context.Context, reqCtx *policy.RequestContext, params map[string]any) policy.RequestAction {
	// Already decided at the header phase, where the capability arrived without a body. Mode
	// asks for both phases, so this guard is what stops a second decision here.
	if !shouldParseBody(reqCtx.SharedContext) {
		return policy.UpstreamRequestModifications{}
	}

	ds := reqCtx.DownstreamRequest()
	if !isPostRequest(ds.Method) {
		return policy.UpstreamRequestModifications{}
	}
	if reqCtx.Body == nil || len(reqCtx.Body.Content) == 0 {
		return policy.UpstreamRequestModifications{}
	}

	// SharedContext is embedded in RequestContext, so a nil one makes every reqCtx.Metadata
	// access panic. Synthesizing the header context below copies this same pointer, so the
	// metadata enforce publishes lands on the real request.
	if reqCtx.SharedContext == nil {
		reqCtx.SharedContext = &policy.SharedContext{}
	}

	method, capType, capName, requestID, err := p.identifyCapability(reqCtx)
	if err != nil {
		slog.Debug("MCP RateLimit Policy: failed to parse MCP request", "error", err)
		reason := reasonSyntaxError
		if isAmbiguousMemberError(err) {
			reason = reasonAmbiguous
		}
		return p.handleUnusableBody(reqCtx.DownstreamHeaders(), reason)
	}
	if method == "" {
		return policy.UpstreamRequestModifications{}
	}

	if resp := p.enforce(ctx, synthesizeHeaderContext(reqCtx), params, method, capType, capName, requestID); resp != nil {
		return *resp
	}
	return policy.UpstreamRequestModifications{}
}

// handleUnusableBody renders a reason the body could not be read as a JSON-RPC error. Both
// request paths call it — the resolver publishes the reason, the body parse derives one from its
// own error — so identical bytes get an identical error whichever gateway read them.
//
// No facts are published alongside a reason, so there is never an id to echo.
func (p *McpRateLimitPolicy) handleUnusableBody(reqHeaders *policy.Headers, reason string) policy.ImmediateResponse {
	code, message := jsonRpcErrCodeInvalidRequest, "Invalid MCP request body"
	switch reason {
	case reasonSyntaxError:
		code, message = jsonRpcErrCodeParseError, "Request body is not valid JSON"
	case reasonInvalidMemberType:
		message = "Request body has a member of the wrong type"
	case reasonNotAnObject:
		message = "Request body is not a single JSON-RPC request object"
	case reasonAmbiguous:
		// The one a backend may not reject on its own: valid JSON it could resolve
		// differently than the gateway did.
		message = "Ambiguous MCP request: body names a member more than once"
	}
	return p.buildJsonRpcError(reqHeaders, 400, code, message, nil)
}

// enforce publishes the capability metadata other MCP policies read, finds every rule matching
// this capability, and dispatches to each rule's advanced-ratelimit delegate. Returns the
// rate-limited response when a delegate blocks, or nil to forward.
//
// Both hooks share it, so a request reaches the same delegates whichever phase identified it.
// advanced-ratelimit is itself a header-phase policy, so only the body path has to synthesize a
// header context; the header path hands it the real one.
func (p *McpRateLimitPolicy) enforce(ctx context.Context, reqCtx *policy.RequestHeaderContext, params map[string]any,
	method, capType, capName string, requestID json.RawMessage) *policy.ImmediateResponse {

	// Metadata is a field of the embedded SharedContext, so this is the same map the response
	// phase reads back.
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
		return nil
	}

	type requestHeaderPolicer interface {
		OnRequestHeaders(context.Context, *policy.RequestHeaderContext, map[string]any) policy.RequestHeaderAction
	}

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

		action := rl.OnRequestHeaders(ctx, reqCtx, params)
		invoked = append(invoked, delegateKey(m.entryIdx, m.capabilityID))

		if immediate, isImmediate := action.(policy.ImmediateResponse); isImmediate {
			slog.Debug("MCP RateLimit Policy: limit exceeded",
				"section", p.entries[m.entryIdx].section,
				"rule", p.entries[m.entryIdx].name,
				"capabilityID", m.capabilityID)
			resp := p.rewriteRateLimitedResponse(reqCtx.DownstreamHeaders(), immediate, requestID)
			return &resp
		}
	}

	if len(invoked) > 0 {
		reqCtx.Metadata[metadataInvokedDelegates] = invoked
	}

	return nil
}

// OnResponseHeaders forwards to every delegate invoked during the request phase
// so each can write its rate-limit headers (RateLimit-*, X-RateLimit-*,
// Retry-After). When multiple delegates set the same header, the later
// delegate's value wins; this is an accepted simplification.
func (p *McpRateLimitPolicy) OnResponseHeaders(ctx context.Context, respCtx *policy.ResponseHeaderContext, params map[string]any) policy.ResponseHeaderAction {
	// SharedContext is embedded in ResponseHeaderContext, so a nil one panics on the read below.
	// Nothing was invoked if nothing was shared, so there is nothing to replay.
	if respCtx.SharedContext == nil {
		return policy.DownstreamResponseHeaderModifications{}
	}

	invoked, _ := respCtx.Metadata[metadataInvokedDelegates].([]string)
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
	if isEventStream(reqCtx.DownstreamHeaders()) {
		body = extractFirstSseJSON(body)
		if len(body) == 0 {
			return "", "", "", nil, fmt.Errorf("no JSON payload found in event stream")
		}
	}

	var req mcpRequest
	if err = json.Unmarshal(body, &req); err != nil {
		return "", "", "", nil, err
	}
	if err = validateUnambiguousRequestMembers(body, req.Method); err != nil {
		return "", "", "", nil, err
	}

	method = req.Method
	if method == "" {
		return "", "", "", req.ID, nil
	}

	// params.uri for a resource, params.name for everything else — the same family-keyed
	// choice the resolver's capabilityName makes, so both paths hand capabilityFrom the same
	// name for the same body.
	//
	// Not "name, else uri". MCP defines no name for resources/*, so a params.name there is
	// client-controlled: taking it would let a decoy displace the uri the server actually
	// reads, and a rule written against that uri would stop matching.
	name := req.Params.Name
	if strings.HasPrefix(method, "resources/") {
		name = req.Params.URI
	}
	capType, capName = capabilityFrom(method, name)

	return method, capType, capName, req.ID, nil
}

// capabilityFrom maps a JSON-RPC method to the capability type it targets, and takes the
// capability name only for the three methods that name one.
func capabilityFrom(method, name string) (capType, capName string) {
	parts := strings.SplitN(method, "/", 2)
	if len(parts) != 2 {
		return "", ""
	}
	switch parts[0] {
	case "tools":
		capType = "tool"
		if parts[1] == "call" {
			capName = name
		}
	case "resources":
		capType = "resource"
		if parts[1] == "read" {
			capName = name
		}
	case "prompts":
		capType = "prompt"
		if parts[1] == "get" {
			capName = name
		}
	}
	return capType, capName
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
func (p *McpRateLimitPolicy) rewriteRateLimitedResponse(reqHeaders *policy.Headers, immediate policy.ImmediateResponse, requestID json.RawMessage) policy.ImmediateResponse {
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

	statusCode := immediate.StatusCode
	if statusCode == 0 {
		statusCode = 429
	}

	body, contentType := buildJsonRpcRateLimitedBody(requestID, isEventStream(reqHeaders))
	headers["content-type"] = contentType

	// The delegate already classified the throttle, so carry its account through rather than
	// restating it — copying field-by-field without IsFault and Fault would silently drop the
	// fault declaration. What is added here is the JSON-RPC detail the delegate has no way to
	// know: it is a protocol-agnostic rate limiter, and the id came out of the MCP envelope
	// this policy parsed.
	//
	// The body above and this description are both sent: a gateway with an error renderer
	// overwrites the body and content-type from the description, and one without it sends
	// the envelope this policy has always written. Neither leaves the caller a bare status.
	described := immediate.Fault
	if described == nil {
		described = &policy.FaultDetails{
			Type:      policy.FaultTypeThrottling,
			Direction: policy.DirectionRequest,
		}
	}
	// Copy before mutating: the delegate owns the value it returned, and a second throttled
	// request must not inherit the id from the first.
	enriched := *described
	rateLimitedCode := jsonRpcErrCodeRateLimited
	enriched.JSONRPC = &policy.JSONRPCError{
		Code: &rateLimitedCode,
		ID:   decodeRequestID(requestID),
	}
	enriched.Message = msgRateLimited
	return policy.ImmediateResponse{
		StatusCode:        statusCode,
		IsFault:           immediate.IsFault,
		Headers:           headers,
		Body:              body,
		AnalyticsMetadata: immediate.AnalyticsMetadata,
		DynamicMetadata:   immediate.DynamicMetadata,
		Fault:             &enriched,
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
func (p *McpRateLimitPolicy) buildJsonRpcError(reqHeaders *policy.Headers, statusCode, jsonRpcCode int, message string, requestID json.RawMessage) policy.ImmediateResponse {
	body, contentType := buildJsonRpcErrorBody(requestID, jsonRpcCode, message, isEventStream(reqHeaders))
	headers := map[string]string{"content-type": contentType}
	if sid := getSessionID(reqHeaders); sid != "" {
		headers[mcpSessionHeader] = sid
	}
	// Body and description both travel: the body is what a gateway without an error
	// renderer sends, and a gateway with one overwrites it from the description below.
	return policy.ImmediateResponse{
		StatusCode: statusCode,
		Headers:    headers,
		Body:       body,
		IsFault:    true,
		Fault: &policy.FaultDetails{
			Code:      policy.FaultCodeInvalidRequestBody,
			Type:      policy.FaultTypeValidation,
			Direction: policy.DirectionRequest,
			// message becomes the JSON-RPC error message.
			Message: message,
			// -32700 Parse error and -32600 Invalid request are both 400s, so the status
			// alone cannot tell them apart; only this policy knows which it hit.
			JSONRPC: &policy.JSONRPCError{Code: &jsonRpcCode, ID: decodeRequestID(requestID)},
		},
	}
}

// msgRateLimited is the throttle message an MCP caller receives. Shared by the fallback body
// and the description so the two cannot report the same rejection differently.
const msgRateLimited = "Rate limit exceeded. Please try again later."

// buildJsonRpcRateLimitedBody renders the throttle rejection this policy has always sent.
func buildJsonRpcRateLimitedBody(requestID json.RawMessage, sse bool) ([]byte, string) {
	return buildJsonRpcErrorBody(requestID, jsonRpcErrCodeRateLimited, msgRateLimited, sse)
}

// buildJsonRpcErrorBody constructs a JSON-RPC error envelope with the given code and
// message, using the requestID if available. When sse is true the JSON is wrapped in an SSE
// `data:` envelope. The content type is returned alongside the body so the two cannot drift
// apart.
//
// This is the fallback body, not the gateway's rendering: a gateway with an error renderer
// overwrites it. It stays byte-for-byte what this policy sent before the fault contract
// existed, so upgrading the policy on its own changes nothing a client receives.
func buildJsonRpcErrorBody(requestID json.RawMessage, code int, message string, sse bool) ([]byte, string) {
	id := requestID
	if len(id) == 0 {
		id = json.RawMessage("null")
	}
	body, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      id,
		"error": map[string]any{
			"code":    code,
			"message": message,
		},
	})
	if err != nil {
		body = fmt.Appendf(nil, `{"jsonrpc":"2.0","id":null,"error":{"code":%d,"message":%q}}`, code, message)
	}

	if sse {
		return []byte("data: " + string(body) + "\n\n"), "text/event-stream"
	}
	return body, "application/json"
}

// decodeRequestID turns the raw JSON-RPC id back into a value the gateway can re-emit.
//
// The id is carried as json.RawMessage because this policy never needed to interpret it, only
// to copy it into a body it wrote. Describing it instead means handing over a real value, and
// JSON-RPC permits a string, a number, or null — so the decoded form is whatever the client
// sent. An absent or unparseable id becomes nil, which renders as the null the spec requires
// for a request whose id could not be determined.
func decodeRequestID(requestID json.RawMessage) any {
	if len(requestID) == 0 {
		return nil
	}
	var id any
	if err := json.Unmarshal(requestID, &id); err != nil {
		return nil
	}
	return id
}

func delegateKey(entryIdx int, capabilityID string) string {
	return fmt.Sprintf("%d:%s", entryIdx, capabilityID)
}

func synthesizeHeaderContext(reqCtx *policy.RequestContext) *policy.RequestHeaderContext {
	ds := reqCtx.DownstreamRequest()
	return &policy.RequestHeaderContext{
		SharedContext: reqCtx.SharedContext,
		Headers:       ds.Headers,
		Path:          ds.Path,
		Method:        ds.Method,
		Authority:     ds.Authority,
		Scheme:        ds.Scheme,
		Vhost:         reqCtx.Vhost,
		Downstream:    reqCtx.Downstream,
	}
}

// isMcpPath reports whether path targets the MCP endpoint using segment-exact matching: only
// "/mcp" itself or a subpath under "/mcp/". This avoids matching unrelated paths such as
// "/resource/mcp". Mirrors the mcp-authz and mcp-acl-list policies.
func isMcpPath(path string) bool {
	cleanPath := strings.TrimSpace(path)
	if idx := strings.Index(cleanPath, "?"); idx >= 0 {
		cleanPath = cleanPath[:idx]
	}
	return cleanPath == "/mcp" || strings.HasPrefix(cleanPath, "/mcp/")
}

// isPostRequest reports the method only. Whether the request targets the MCP endpoint is
// isMcpPath's answer, and the two are asked together at every call site.
func isPostRequest(method string) bool {
	return strings.EqualFold(method, "POST")
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
