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

// Package switchyardrouter implements a model routing policy that takes its
// routing decision from NVIDIA's switchyard-server and keeps the routing itself
// in the gateway. The server runs a routing profile, such as the Stage router,
// and answers with an efficient or capable tier; this policy maps that tier to
// a model in its own model pool, rewrites the request, and selects the
// upstream. Switchyard never calls the selected model.
package nvidiaswitchyardrouter

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
	utils "github.com/wso2/api-platform/sdk/core/utils"
)

const (
	tierEfficient = "efficient"
	tierCapable   = "capable"

	fallbackModeError = "error"
	fallbackModeModel = "model"

	modeEnforce     = "enforce"
	modeObserveOnly = "observe_only"

	defaultSessionHeader     = "x-switchyard-session-id"
	defaultSwitchyardTimeout = 1 * time.Second
	maxSwitchyardTimeout     = 10 * time.Second

	codeDecisionFailed = "nvidia_switchyard_router_decision_failed"
	codeRoutingFailed  = "nvidia_switchyard_router_routing_failed"

	// Response headers that tell the client how its request was routed.
	headerTier    = "x-switchyard-tier"
	headerOutcome = "x-switchyard-outcome"
	headerError   = "x-switchyard-error"

	// responseHeadersKey carries the response headers from the request phase
	// to the response phase in the shared request metadata.
	responseHeadersKey = "nvidia_switchyard_router.response_headers"
)

// Outcomes, recorded as switchyard_outcome and x-switchyard-outcome.
const (
	outcomeRouted         = "routed"
	outcomeObserved       = "observed"
	outcomeFallback       = "fallback"
	outcomeRejected       = "rejected"
	outcomeDecisionFailed = "decision_failed"
)

// harnessHeaders are the client headers switchyard-server reads to key
// session state and to tell a sub-agent's requests from its parent's
// (switchyard-protocol 0.3.0, metadata.rs). They are forwarded as sent, so
// coding agents such as Claude Code and Codex get session holds without
// sending a Switchyard header.
var harnessHeaders = []string{
	"x-switchyard-session-id", "x-switchyard-agent-id", "x-switchyard-parent-agent-id",
	"x-switchyard-is-subagent", "x-switchyard-agent-kind", "x-switchyard-agent-role",
	"x-switchyard-task-id", "x-switchyard-task-kind", "x-switchyard-turn-id", "x-switchyard-session-final",
	"x-claude-code-session-id", "x-claude-code-agent-id", "x-claude-code-parent-agent-id",
	"x-codex-turn-metadata", "x-codex-parent-thread-id", "x-openai-subagent",
	"x-nemo-relay-session-id", "x-nemo-relay-subagent-id",
	"x-dynamo-session-id", "x-dynamo-parent-session-id", "x-dynamo-session-final",
	"x-session-id", "session-id", "thread-id", "x-task-id",
	"user-agent",
}

// poolEntry is one model the router may choose.
type poolEntry struct {
	Provider string
	Model    string
	Tier     string
	Weight   int
}

// RequestModelConfig holds where the model name lives in the request.
type RequestModelConfig struct {
	Location   string
	Identifier string
}

// SwitchyardRouterPolicy routes each request to the model tier that a
// switchyard-server profile selects.
type SwitchyardRouterPolicy struct {
	pool              []poolEntry
	tiers             map[string]*tierPool
	balancing         string
	profile           string
	mode              string
	fallbackMode      string
	fallback          *poolEntry
	sessionHeader     string
	sessionFromPrompt bool
	disclosure        string
	responseHeaders   bool
	requestModel      RequestModelConfig
	client            *switchyardClient
}

// GetPolicy is the v1alpha2 factory entry point. Invalid configuration fails
// the deployment rather than individual requests.
func GetPolicy(
	metadata policy.PolicyMetadata,
	params map[string]interface{},
) (policy.Policy, error) {
	p := &SwitchyardRouterPolicy{}
	if err := parseParams(params, p); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}

	slog.Debug("SwitchyardRouter: Policy initialized",
		"models", len(p.pool),
		"profile", p.profile,
		"mode", p.mode,
		"fallbackMode", p.fallbackMode,
		"promptDisclosure", p.disclosure,
		"tierBalancing", p.balancing,
	)
	return p, nil
}

// Mode buffers the request body: Switchyard reads the conversation, and the
// policy rewrites the model inside it. Response headers are processed only to
// add the routing headers.
func (p *SwitchyardRouterPolicy) Mode() policy.ProcessingMode {
	responseHeaderMode := policy.HeaderModeSkip
	if p.responseHeaders {
		responseHeaderMode = policy.HeaderModeProcess
	}
	return policy.ProcessingMode{
		RequestHeaderMode:  policy.HeaderModeSkip,
		RequestBodyMode:    policy.BodyModeBuffer,
		ResponseHeaderMode: responseHeaderMode,
		ResponseBodyMode:   policy.BodyModeSkip,
	}
}

// OnResponseHeaders adds the routing headers recorded for this request.
func (p *SwitchyardRouterPolicy) OnResponseHeaders(
	ctx context.Context,
	respCtx *policy.ResponseHeaderContext,
	params map[string]interface{},
) policy.ResponseHeaderAction {
	if respCtx == nil || respCtx.SharedContext == nil {
		return policy.DownstreamResponseHeaderModifications{}
	}
	headers, _ := respCtx.Metadata[responseHeadersKey].(map[string]string)
	if len(headers) == 0 {
		return policy.DownstreamResponseHeaderModifications{}
	}
	return policy.DownstreamResponseHeaderModifications{HeadersToSet: headers}
}

// OnRequestBody asks switchyard-server for a tier and routes the request to
// the first pooled model of that tier.
func (p *SwitchyardRouterPolicy) OnRequestBody(
	ctx context.Context,
	reqCtx *policy.RequestContext,
	params map[string]interface{},
) policy.RequestAction {
	var content []byte
	if reqCtx.Body != nil {
		content = reqCtx.Body.Content
	}
	if len(content) == 0 {
		slog.Debug("SwitchyardRouter: Request body is empty, preserving current upstream")
		return policy.UpstreamRequestModifications{}
	}

	payload, err := decodePayload(content)
	if err != nil {
		slog.Debug("SwitchyardRouter: Request body is not a JSON object, preserving current upstream", "error", err)
		return policy.UpstreamRequestModifications{}
	}

	inputFormat, ok := inputFormatForPath(reqCtx.Path)
	if !ok {
		slog.Debug("SwitchyardRouter: Request path has no known LLM API format", "path", reqCtx.Path)
		return p.fallbackAction(reqCtx, payload, reasonUnknownFormat)
	}

	decisionBody, err := p.decisionBody(inputFormat, content)
	if err != nil {
		slog.Debug("SwitchyardRouter: Failed to build decision request", "error", err)
		return p.fallbackAction(reqCtx, payload, reasonInvalidRequest)
	}

	headers := p.decisionHeaders(reqCtx, inputFormat, payload)
	d, err := p.client.decide(ctx, inputFormat, decisionBody, headers)
	if err != nil {
		reason := failureReason(err)
		switch reason {
		case reasonProfileNotFound:
			slog.Warn("SwitchyardRouter: switchyard-server has no route for the profile", "profile", p.profile)
		case reasonTimeout:
			// A judge profile needs a longer switchyardTimeout; otherwise every
			// judged request silently takes the fallback.
			slog.Warn("SwitchyardRouter: Decision timed out; raise switchyardTimeout for profiles with a judge",
				"profile", p.profile, "timeout", p.client.timeout)
		default:
			slog.Debug("SwitchyardRouter: Decision failed", "reason", reason, "error", err)
		}
		return p.fallbackAction(reqCtx, payload, reason)
	}

	tier, ok := p.tiers[d.Selected.Target]
	if !ok {
		slog.Warn("SwitchyardRouter: Profile selected a target that is not a tier; name its targets efficient and capable",
			"profile", p.profile, "target", d.Selected.Target)
		return p.fallbackAction(reqCtx, payload, reasonInvalidDecision)
	}

	selected := tier.pick(p.balancing, sessionKey(headers))
	slog.Debug("SwitchyardRouter: Routing decided",
		"profile", p.profile, "mode", p.mode, "tier", selected.Tier, "model", selected.Model)
	if p.mode == modeObserveOnly {
		return p.observed(reqCtx, map[string]any{
			"switchyard_tier":              selected.Tier,
			"switchyard_outcome":           outcomeObserved,
			"switchyard_observed_model":    selected.Model,
			"switchyard_observed_provider": selected.Provider,
		})
	}
	return p.routeTo(reqCtx, payload, selected, map[string]any{
		"switchyard_tier":    selected.Tier,
		"switchyard_profile": p.profile,
		"switchyard_outcome": outcomeRouted,
	})
}

// observed leaves the request untouched and only records what would have
// been routed, so a profile can be evaluated on real traffic first.
func (p *SwitchyardRouterPolicy) observed(reqCtx *policy.RequestContext, analytics map[string]any) policy.RequestAction {
	analytics["switchyard_profile"] = p.profile
	analytics["switchyard_mode"] = modeObserveOnly
	p.recordResponseHeaders(reqCtx, analytics)
	return policy.UpstreamRequestModifications{AnalyticsMetadata: analytics}
}

// recordResponseHeaders keeps the routing headers for the response phase.
func (p *SwitchyardRouterPolicy) recordResponseHeaders(reqCtx *policy.RequestContext, analytics map[string]any) {
	if !p.responseHeaders || reqCtx.SharedContext == nil {
		return
	}
	if reqCtx.Metadata == nil {
		reqCtx.Metadata = make(map[string]interface{})
	}
	reqCtx.Metadata[responseHeadersKey] = responseHeaderValues(analytics)
}

func responseHeaderValues(analytics map[string]any) map[string]string {
	headers := map[string]string{}
	for header, key := range map[string]string{
		headerTier:    "switchyard_tier",
		headerOutcome: "switchyard_outcome",
		headerError:   "switchyard_error",
	} {
		if value, ok := analytics[key].(string); ok && value != "" {
			headers[header] = value
		}
	}
	return headers
}

// decisionBody is the caller's request, redacted to the disclosure level,
// with its model set to the profile so switchyard-server runs that route. The
// routed request keeps its own copy.
func (p *SwitchyardRouterPolicy) decisionBody(inputFormat string, content []byte) ([]byte, error) {
	request, err := decodePayload(content)
	if err != nil {
		return nil, err
	}
	if p.disclosure != disclosureFull {
		request = redactRequest(inputFormat, request, p.disclosure)
	}
	request["model"] = p.profile
	return json.Marshal(request)
}

// inputFormatForPath tells Switchyard how to read the request: it needs the
// wire format to find the tool calls and results in it.
func inputFormatForPath(path string) (string, bool) {
	if i := strings.IndexAny(path, "?#"); i >= 0 {
		path = path[:i]
	}
	path = strings.TrimRight(path, "/")
	switch {
	case strings.HasSuffix(path, "/chat/completions"):
		return "openai_chat", true
	case strings.HasSuffix(path, "/responses"):
		return "openai_responses", true
	case strings.HasSuffix(path, "/messages"):
		return "anthropic_messages", true
	default:
		return "", false
	}
}

// decisionHeaders forwards the client's harness headers and sets the session
// ID from the configured session header. With sessionFromPrompt, a request
// that carries no session ID at all is keyed on a hash of its first user
// message, which stays the same for every turn of a conversation. A request
// with no session ID keeps no routing history on the server.
func (p *SwitchyardRouterPolicy) decisionHeaders(reqCtx *policy.RequestContext, inputFormat string, payload map[string]interface{}) map[string]string {
	headers := map[string]string{}
	for _, name := range harnessHeaders {
		if value := firstHeader(reqCtx, name); value != "" {
			headers[name] = value
		}
	}
	if id := firstHeader(reqCtx, p.sessionHeader); id != "" {
		headers[sessionIDHeader] = id
	}
	if p.sessionFromPrompt && !hasSessionID(headers) {
		if id := p.promptSessionID(inputFormat, payload); id != "" {
			headers[sessionIDHeader] = id
		}
	}
	return headers
}

func firstHeader(reqCtx *policy.RequestContext, name string) string {
	if reqCtx.Headers == nil {
		return ""
	}
	if values := reqCtx.Headers.Get(name); len(values) > 0 {
		return strings.TrimSpace(values[0])
	}
	return ""
}

// hasSessionID reports whether switchyard-server will find a session ID in
// the forwarded headers.
func hasSessionID(headers map[string]string) bool {
	return sessionKey(headers) != ""
}

// promptSessionID is a session ID derived from the conversation's first user
// message, or empty when it has none.
func (p *SwitchyardRouterPolicy) promptSessionID(inputFormat string, payload map[string]interface{}) string {
	first := firstUserText(inputFormat, payload)
	if first == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(p.profile + "\x00" + first))
	return "prompt-" + hex.EncodeToString(sum[:16])
}

// firstUserText returns the text of the conversation's first user message in
// any of the supported API formats.
func firstUserText(inputFormat string, payload map[string]interface{}) string {
	var items []interface{}
	switch inputFormat {
	case "openai_responses":
		switch input := payload["input"].(type) {
		case string:
			return input
		case []interface{}:
			items = input
		}
	default:
		items, _ = payload["messages"].([]interface{})
	}
	for _, item := range items {
		message, ok := item.(map[string]interface{})
		if !ok || message["role"] != "user" {
			continue
		}
		return contentText(message["content"])
	}
	return ""
}

// contentText flattens a message's content, which is a string or a list of
// parts, keeping only the text parts.
func contentText(content interface{}) string {
	switch c := content.(type) {
	case string:
		return c
	case []interface{}:
		var b strings.Builder
		for _, part := range c {
			if m, ok := part.(map[string]interface{}); ok {
				if text, ok := m["text"].(string); ok {
					b.WriteString(text)
					b.WriteByte('\n')
				}
			}
		}
		return b.String()
	}
	return ""
}

// Reasons a decision was not made, recorded as switchyard_error.
const (
	reasonTimeout         = "timeout"
	reasonUnavailable     = "unavailable"
	reasonProfileNotFound = "profile_not_found"
	reasonInvalidDecision = "invalid_decision"
	reasonUnknownFormat   = "unknown_format"
	reasonInvalidRequest  = "invalid_request"
)

func failureReason(err error) string {
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return reasonTimeout
	case errors.Is(err, errProfileNotFound):
		return reasonProfileNotFound
	case errors.Is(err, errInvalidDecision):
		return reasonInvalidDecision
	default:
		return reasonUnavailable
	}
}

// fallbackAction routes to the fallback model, or rejects the request when
// fallback is "error". A request is never forwarded without a decided model.
// In observe-only mode nothing is changed or rejected; the failure is only
// recorded.
func (p *SwitchyardRouterPolicy) fallbackAction(reqCtx *policy.RequestContext, payload map[string]interface{}, reason string) policy.RequestAction {
	if p.mode == modeObserveOnly {
		return p.observed(reqCtx, map[string]any{"switchyard_outcome": outcomeDecisionFailed, "switchyard_error": reason})
	}
	if p.fallbackMode == fallbackModeModel {
		return p.routeTo(reqCtx, payload, *p.fallback, map[string]any{
			"switchyard_tier":    p.fallback.Tier,
			"switchyard_profile": p.profile,
			"switchyard_outcome": outcomeFallback,
			"switchyard_error":   reason,
		})
	}
	resp := errorResponse(http.StatusServiceUnavailable, codeDecisionFailed, "The routing decision could not be made.").(policy.ImmediateResponse)
	resp.AnalyticsMetadata = map[string]any{
		"switchyard_profile": p.profile,
		"switchyard_outcome": outcomeRejected,
		"switchyard_error":   reason,
	}
	// The response phase does not run for an immediate response, so the
	// routing headers go on it directly.
	if p.responseHeaders {
		for name, value := range responseHeaderValues(resp.AnalyticsMetadata) {
			resp.Headers[name] = value
		}
	}
	return resp
}

// routeTo rewrites the model and selects the named upstream in the same action,
// so a provider never receives a model meant for another provider.
func (p *SwitchyardRouterPolicy) routeTo(reqCtx *policy.RequestContext, payload map[string]interface{}, selected poolEntry, analytics map[string]any) policy.RequestAction {
	if err := utils.SetValueAtJSONPath(payload, p.requestModel.Identifier, selected.Model); err != nil {
		slog.Debug("SwitchyardRouter: Failed to set model in request body", "error", err)
		return errorResponse(http.StatusInternalServerError, codeRoutingFailed, "The routed request could not be written.")
	}
	body, err := json.Marshal(payload)
	if err != nil {
		slog.Debug("SwitchyardRouter: Failed to serialize routed request", "error", err)
		return errorResponse(http.StatusInternalServerError, codeRoutingFailed, "The routed request could not be written.")
	}

	p.recordResponseHeaders(reqCtx, analytics)
	mods := policy.UpstreamRequestModifications{Body: body, AnalyticsMetadata: analytics}
	// This engine-level key lets subsequent conditional auth and protocol
	// transformers identify the same provider as the named upstream override.
	if selected.Provider != "" {
		providerName := selected.Provider
		mods.UpstreamName = &providerName
		if reqCtx.Metadata == nil {
			reqCtx.Metadata = make(map[string]interface{})
		}
		reqCtx.Metadata["selected_provider"] = providerName
	}
	return mods
}

// decodePayload keeps numbers as json.Number so values such as seeds survive
// the rewrite without float rounding.
func decodePayload(content []byte) (map[string]interface{}, error) {
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.UseNumber()
	var payload map[string]interface{}
	if err := decoder.Decode(&payload); err != nil {
		return nil, err
	}
	if payload == nil {
		return nil, fmt.Errorf("body is not a JSON object")
	}
	return payload, nil
}

func errorResponse(status int, code, message string) policy.RequestAction {
	body, _ := json.Marshal(map[string]string{"error": message, "code": code})
	return policy.ImmediateResponse{
		StatusCode: status,
		Headers:    map[string]string{"content-type": "application/json"},
		Body:       body,
	}
}

// --- Parameter Parsing ---

func parseParams(params map[string]interface{}, p *SwitchyardRouterPolicy) error {
	if err := parseModelPool(params, p); err != nil {
		return err
	}
	if err := parseFallback(params, p); err != nil {
		return err
	}

	profile, ok := params["profile"].(string)
	if !ok || strings.TrimSpace(profile) == "" {
		return fmt.Errorf("'profile' parameter is required")
	}
	p.profile = strings.TrimSpace(profile)

	p.mode = modeEnforce
	if raw, exists := params["mode"]; exists {
		mode, ok := raw.(string)
		if !ok || (mode != modeEnforce && mode != modeObserveOnly) {
			return fmt.Errorf("'mode' must be 'enforce' or 'observe_only'")
		}
		p.mode = mode
	}

	if raw, exists := params["sessionFromPrompt"]; exists {
		value, ok := raw.(bool)
		if !ok {
			return fmt.Errorf("'sessionFromPrompt' must be true or false")
		}
		p.sessionFromPrompt = value
	}

	p.balancing = balancingFirst
	if raw, exists := params["tierBalancing"]; exists {
		balancing, ok := raw.(string)
		switch {
		case !ok:
			return fmt.Errorf("'tierBalancing' must be a string")
		case balancing == balancingFirst, balancing == balancingRoundRobin, balancing == balancingSession:
			p.balancing = balancing
		default:
			return fmt.Errorf("'tierBalancing' must be 'first', 'round_robin' or 'session_affinity'")
		}
	}

	p.disclosure = disclosureTaskAndToolActivity
	if raw, exists := params["promptDisclosure"]; exists {
		level, ok := raw.(string)
		switch {
		case !ok:
			return fmt.Errorf("'promptDisclosure' must be a string")
		case level == disclosureNone, level == disclosureToolActivity, level == disclosureTaskAndToolActivity, level == disclosureFull:
			p.disclosure = level
		default:
			return fmt.Errorf("'promptDisclosure' must be 'none', 'tool_activity', 'task_and_tool_activity' or 'full'")
		}
	}

	p.responseHeaders = true
	if raw, exists := params["responseHeaders"]; exists {
		value, ok := raw.(bool)
		if !ok {
			return fmt.Errorf("'responseHeaders' must be true or false")
		}
		p.responseHeaders = value
	}

	p.sessionHeader = defaultSessionHeader
	if raw, exists := params["sessionHeader"]; exists {
		header, ok := raw.(string)
		if !ok || strings.TrimSpace(header) == "" {
			return fmt.Errorf("'sessionHeader' must be a non-empty string")
		}
		p.sessionHeader = strings.TrimSpace(header)
	}

	if err := parseSwitchyard(params, p); err != nil {
		return err
	}
	return parseRequestModelConfig(params, p)
}

func parseModelPool(params map[string]interface{}, p *SwitchyardRouterPolicy) error {
	raw, ok := params["modelPool"]
	if !ok {
		return fmt.Errorf("'modelPool' parameter is required")
	}
	list, ok := raw.([]interface{})
	if !ok {
		return fmt.Errorf("'modelPool' must be an array")
	}

	p.pool = make([]poolEntry, 0, len(list))
	p.tiers = map[string]*tierPool{tierEfficient: {}, tierCapable: {}}
	seen := map[poolEntry]bool{}
	for i, item := range list {
		entryMap, ok := item.(map[string]interface{})
		if !ok {
			return fmt.Errorf("'modelPool[%d]' must be an object", i)
		}
		entry, err := parsePoolEntry(entryMap, i)
		if err != nil {
			return err
		}
		key := poolEntry{Provider: entry.Provider, Model: entry.Model}
		if seen[key] {
			return fmt.Errorf("'modelPool[%d]' repeats provider %q and model %q", i, entry.Provider, entry.Model)
		}
		seen[key] = true
		p.pool = append(p.pool, entry)
		p.tiers[entry.Tier].add(entry)
	}

	for _, tier := range []string{tierEfficient, tierCapable} {
		if len(p.tiers[tier].models) == 0 {
			return fmt.Errorf("'modelPool' needs at least one %s model", tier)
		}
	}
	return nil
}

func parsePoolEntry(entryMap map[string]interface{}, index int) (poolEntry, error) {
	var entry poolEntry

	model, ok := entryMap["model"].(string)
	if !ok || strings.TrimSpace(model) == "" {
		return entry, fmt.Errorf("'modelPool[%d].model' is required and must be a non-empty string", index)
	}
	entry.Model = strings.TrimSpace(model)

	tier, ok := entryMap["tier"].(string)
	if !ok || (tier != tierEfficient && tier != tierCapable) {
		return entry, fmt.Errorf("'modelPool[%d].tier' must be 'efficient' or 'capable'", index)
	}
	entry.Tier = tier

	provider, err := parseOptionalProvider(entryMap, "provider", fmt.Sprintf("modelPool[%d].provider", index))
	if err != nil {
		return entry, err
	}
	entry.Provider = provider

	entry.Weight = defaultWeight
	if raw, exists := entryMap["weight"]; exists {
		weight, ok := wholeNumber(raw)
		if !ok || weight < 1 || weight > maxWeight {
			return entry, fmt.Errorf("'modelPool[%d].weight' must be a whole number from 1 to %d", index, maxWeight)
		}
		entry.Weight = weight
	}
	return entry, nil
}

// wholeNumber accepts the integer forms a decoded configuration can hold.
func wholeNumber(raw interface{}) (int, bool) {
	switch v := raw.(type) {
	case int:
		return v, true
	case int64:
		return int(v), true
	case float64:
		if v == float64(int(v)) {
			return int(v), true
		}
	case json.Number:
		if n, err := v.Int64(); err == nil {
			return int(n), true
		}
	}
	return 0, false
}

// parseOptionalProvider accepts an additional-provider alias, not a provider
// type enum. Empty or omitted values preserve existing upstream selection.
func parseOptionalProvider(params map[string]interface{}, key, field string) (string, error) {
	raw, exists := params[key]
	if !exists {
		return "", nil
	}
	provider, ok := raw.(string)
	if !ok {
		return "", fmt.Errorf("'%s' must be a string", field)
	}
	return strings.TrimSpace(provider), nil
}

func parseFallback(params map[string]interface{}, p *SwitchyardRouterPolicy) error {
	p.fallbackMode = fallbackModeError
	raw, exists := params["fallback"]
	if !exists {
		return nil
	}
	fallbackMap, ok := raw.(map[string]interface{})
	if !ok {
		return fmt.Errorf("'fallback' must be an object")
	}

	if mode, exists := fallbackMap["mode"]; exists {
		modeStr, ok := mode.(string)
		if !ok || (modeStr != fallbackModeError && modeStr != fallbackModeModel) {
			return fmt.Errorf("'fallback.mode' must be 'error' or 'model'")
		}
		p.fallbackMode = modeStr
	}
	if p.fallbackMode == fallbackModeError {
		return nil
	}

	model, ok := fallbackMap["model"].(string)
	if !ok || strings.TrimSpace(model) == "" {
		return fmt.Errorf("'fallback.model' is required when 'fallback.mode' is 'model'")
	}
	provider, err := parseOptionalProvider(fallbackMap, "provider", "fallback.provider")
	if err != nil {
		return err
	}
	for i := range p.pool {
		if p.pool[i].Provider == provider && p.pool[i].Model == strings.TrimSpace(model) {
			p.fallback = &p.pool[i]
			return nil
		}
	}
	return fmt.Errorf("'fallback' must name a model in 'modelPool'")
}

func parseSwitchyard(params map[string]interface{}, p *SwitchyardRouterPolicy) error {
	endpoint, ok := params["switchyardEndpoint"].(string)
	if !ok || strings.TrimSpace(endpoint) == "" {
		return fmt.Errorf("'switchyardEndpoint' parameter is required")
	}

	apiKey := ""
	if raw, exists := params["switchyardApiKey"]; exists && raw != nil {
		value, ok := raw.(string)
		if !ok {
			return fmt.Errorf("'switchyardApiKey' must be a string")
		}
		apiKey = value
	}

	timeout := defaultSwitchyardTimeout
	if raw, exists := params["switchyardTimeout"]; exists {
		value, ok := raw.(string)
		if !ok {
			return fmt.Errorf("'switchyardTimeout' must be a duration string such as \"500ms\"")
		}
		if strings.TrimSpace(value) != "" {
			parsed, err := time.ParseDuration(strings.TrimSpace(value))
			if err != nil || parsed <= 0 || parsed > maxSwitchyardTimeout {
				return fmt.Errorf("'switchyardTimeout' must be greater than zero and at most %s", maxSwitchyardTimeout)
			}
			timeout = parsed
		}
	}

	p.client = &switchyardClient{
		endpoint:   strings.TrimSpace(endpoint),
		apiKey:     apiKey,
		timeout:    timeout,
		httpClient: switchyardHTTPClient,
	}
	return nil
}

// parseRequestModelConfig accepts only the payload location: the policy runs
// in the request body phase and rewrites the model inside the JSON body.
func parseRequestModelConfig(params map[string]interface{}, p *SwitchyardRouterPolicy) error {
	requestModel, ok := params["requestModel"]
	if !ok {
		return fmt.Errorf("'requestModel' configuration is required")
	}
	requestModelMap, ok := requestModel.(map[string]interface{})
	if !ok {
		return fmt.Errorf("'requestModel' must be an object")
	}

	location, ok := requestModelMap["location"].(string)
	if !ok || location == "" {
		return fmt.Errorf("'requestModel.location' is required")
	}
	if location != "payload" {
		return fmt.Errorf("'requestModel.location' must be 'payload'")
	}
	p.requestModel.Location = location

	identifier, ok := requestModelMap["identifier"].(string)
	if !ok || identifier == "" {
		return fmt.Errorf("'requestModel.identifier' is required")
	}
	p.requestModel.Identifier = identifier
	return nil
}
