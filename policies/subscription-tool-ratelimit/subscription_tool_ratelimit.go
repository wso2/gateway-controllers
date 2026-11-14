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

// Package subscriptiontoolratelimit enforces a subscription plan's tool-call-count condition,
// counting MCP tools/call requests per subscription.
package subscriptiontoolratelimit

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
	ratelimit "github.com/wso2/gateway-controllers/policies/advanced-ratelimit"
)

const (
	methodToolsCall = "tools/call"

	mcpSessionHeader = "mcp-session-id"

	// JSON-RPC error code mcp-ratelimit uses for a throttled call.
	jsonRPCErrCodeRateLimited = -32000

	faultMessage = "Subscription plan tool call limit exceeded"
)

// SubscriptionToolRateLimitPolicy counts each MCP tools/call against the plan's limits.
type SubscriptionToolRateLimitPolicy struct {
	metadata     policy.PolicyMetadata
	systemParams map[string]interface{}
	cache        delegateCache
}

// GetPolicy is the v1alpha2 factory entry point.
func GetPolicy(metadata policy.PolicyMetadata, params map[string]interface{}) (policy.Policy, error) {
	return &SubscriptionToolRateLimitPolicy{
		metadata:     metadata,
		systemParams: pickSystemParams(params),
	}, nil
}

// Mode asks for both request phases: with the gateway's MCP resolver the call is known from the
// headers, without it the body must be read (see shouldParseBody).
func (p *SubscriptionToolRateLimitPolicy) Mode() policy.ProcessingMode {
	return policy.ProcessingMode{
		RequestHeaderMode:  policy.HeaderModeProcess,
		RequestBodyMode:    policy.BodyModeBuffer,
		ResponseHeaderMode: policy.HeaderModeSkip,
		ResponseBodyMode:   policy.BodyModeSkip,
	}
}

// OnRequestHeaders counts a tools/call the gateway's MCP resolver identified.
func (p *SubscriptionToolRateLimitPolicy) OnRequestHeaders(ctx context.Context, reqCtx *policy.RequestHeaderContext,
	_ map[string]interface{}) policy.RequestHeaderAction {
	if reqCtx == nil || !isMcpPost(reqCtx.SharedContext, reqCtx.DownstreamRequest()) {
		return nil
	}
	// Without a resolver the method is in the body; OnRequestBody decides.
	if shouldParseBody(reqCtx.SharedContext) {
		return nil
	}
	facts := mcpFacts(reqCtx.Headers, reqCtx.SharedContext)
	if facts.Method != methodToolsCall {
		return nil
	}
	resp, analytics := p.limit(ctx, reqCtx, facts.RequestID)
	if resp != nil {
		return *resp
	}
	if analytics != nil {
		return policy.UpstreamRequestHeaderModifications{AnalyticsMetadata: analytics}
	}
	return nil
}

// OnRequestBody counts a tools/call read from the body, on a gateway without the MCP resolver.
func (p *SubscriptionToolRateLimitPolicy) OnRequestBody(ctx context.Context, reqCtx *policy.RequestContext,
	_ map[string]interface{}) policy.RequestAction {
	if reqCtx == nil || reqCtx.SharedContext == nil || !shouldParseBody(reqCtx.SharedContext) {
		return nil
	}
	if !isMcpPost(reqCtx.SharedContext, reqCtx.DownstreamRequest()) {
		return nil
	}
	if reqCtx.Body == nil || len(reqCtx.Body.Content) == 0 {
		return nil
	}
	isCall, requestID := toolsCallFromBody(reqCtx.Body.Content)
	if !isCall {
		return nil
	}
	resp, analytics := p.limit(ctx, synthesizeHeaderContext(reqCtx), requestID)
	if resp != nil {
		return *resp
	}
	if analytics != nil {
		return policy.UpstreamRequestModifications{AnalyticsMetadata: analytics}
	}
	return nil
}

// limit counts one tool call; it returns the rejection to send (or nil) and the call's quota
// status for analytics (nil when the call wasn't counted).
func (p *SubscriptionToolRateLimitPolicy) limit(ctx context.Context, reqCtx *policy.RequestHeaderContext,
	requestID json.RawMessage) (*policy.ImmediateResponse, map[string]any) {
	plan, ok := readSubscriptionPlan(reqCtx.SharedContext)
	if !ok {
		slog.Debug("subscription-tool-ratelimit: no subscription in metadata (subscription-validation v2 must run first); not limiting",
			"route", p.metadata.RouteName)
		return nil, nil
	}
	cond, ok := plan.condition(conditionTypeToolCallCount)
	if !ok {
		return nil, nil
	}
	ec, err := resolveCondition(cond)
	if err != nil {
		slog.Warn("subscription-tool-ratelimit: not limiting", "error", err, "planId", plan.PlanID)
		return nil, nil
	}

	key := delegateCacheKey(plan.PlanID, ec, "")
	slot := delegateSlot(plan.PlanID, ec, "")
	delegate, err := p.cache.get(slot, key, func() (policy.Policy, error) {
		return ratelimit.GetPolicy(delegateMetadata(p.metadata, slot), delegateParams(ec, nil, p.systemParams))
	})
	if err != nil {
		slog.Warn("subscription-tool-ratelimit: failed to build limiter; not limiting", "error", err, "planId", plan.PlanID)
		return nil, nil
	}

	resp, analytics := checkLimit(ctx, reqCtx, delegate, ec, plan.SubscriptionID, "tool calls", faultMessage)
	if resp == nil {
		return nil, analytics
	}
	jsonRPC := toJSONRPC(*resp, requestID, reqCtx.DownstreamHeaders())
	return &jsonRPC, analytics
}

// toJSONRPC wraps the rejection in a JSON-RPC error envelope for the MCP client, as mcp-ratelimit
// does, keeping the rate-limit headers and the fault.
func toJSONRPC(resp policy.ImmediateResponse, requestID json.RawMessage, reqHeaders *policy.Headers) policy.ImmediateResponse {
	var original struct {
		Message string `json:"message"`
	}
	_ = json.Unmarshal(resp.Body, &original)
	id := requestID
	if len(id) == 0 || !json.Valid(id) {
		id = json.RawMessage("null")
	}
	body, err := json.Marshal(map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      id,
		"error": map[string]interface{}{
			"code":    jsonRPCErrCodeRateLimited,
			"message": original.Message,
		},
	})
	if err == nil {
		resp.Body = body
	}
	if reqHeaders != nil {
		if sid := reqHeaders.Get(mcpSessionHeader); len(sid) > 0 && sid[0] != "" {
			resp.Headers[mcpSessionHeader] = sid[0]
		}
	}
	fault := *resp.Fault
	code := jsonRPCErrCodeRateLimited
	fault.JSONRPC = &policy.JSONRPCError{Code: &code, ID: decodeRequestID(requestID)}
	resp.Fault = &fault
	return resp
}

// toolsCallFromBody reports whether a JSON-RPC body calls tools/call, and its id. Any member
// spelled like "method" naming tools/call counts, so a duplicate member cannot dodge the limit.
func toolsCallFromBody(body []byte) (bool, json.RawMessage) {
	dec := json.NewDecoder(bytes.NewReader(body))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return false, nil
	}
	isCall := false
	var id json.RawMessage
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return isCall, id
		}
		name, _ := tok.(string)
		var value json.RawMessage
		if err := dec.Decode(&value); err != nil {
			return isCall, id
		}
		switch {
		case strings.EqualFold(name, "method"):
			var method string
			if json.Unmarshal(value, &method) == nil && method == methodToolsCall {
				isCall = true
			}
		case name == "id":
			id = value
		}
	}
	return isCall, id
}

// decodeRequestID turns the raw JSON-RPC id back into a value; numbers stay exact.
func decodeRequestID(requestID json.RawMessage) any {
	if len(requestID) == 0 {
		return nil
	}
	dec := json.NewDecoder(bytes.NewReader(requestID))
	dec.UseNumber()
	var id any
	if err := dec.Decode(&id); err != nil {
		return nil
	}
	return id
}

// isMcpPost reports a POST to the MCP endpoint, matched on the API-definition path as
// mcp-ratelimit does.
func isMcpPost(shared *policy.SharedContext, ds *policy.DownstreamRequest) bool {
	routePath := ds.Path
	if shared != nil && shared.OperationPath != "" {
		routePath = shared.OperationPath
	}
	return strings.EqualFold(ds.Method, "POST") && isMcpPath(routePath)
}

// isMcpPath matches "/mcp" or a subpath under "/mcp/".
func isMcpPath(path string) bool {
	cleanPath := strings.TrimSpace(path)
	if idx := strings.Index(cleanPath, "?"); idx >= 0 {
		cleanPath = cleanPath[:idx]
	}
	return cleanPath == "/mcp" || strings.HasPrefix(cleanPath, "/mcp/")
}

// synthesizeHeaderContext gives the header-phase delegate a view of a body-phase request.
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
