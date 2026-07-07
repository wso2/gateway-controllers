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

package logmessage

import (
	"context"
	"encoding/json"
	"log/slog"
	"sort"
	"strconv"
	"strings"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

const (
	HeaderXRequestID      = "x-request-id"
	FieldNamePayload      = "payload"
	FieldNameHeaders      = "headers"
	ErrMsgMissingReqID    = "<request-id-unavailable>"
	MediationFlowRequest  = "REQUEST"
	MediationFlowResponse = "RESPONSE"
	MediationFlowFault    = "FAULT"

	// FieldNameEnableTrafficLogging is the boolean parameter selecting the logging
	// mode. When false (default), the policy logs inline during mediation via slog,
	// in real time and including per-chunk streaming — with no dependency on the
	// gateway collector or analytics pipeline. When true, it instead opts the API
	// into stdout traffic logging: the policy stamps a marker and the gateway's
	// traffic-logging publisher emits a single JSON line on the Envoy access-log
	// side, enriched with access-log-derived latencies. Requires [traffic_logging]
	// to be enabled.
	FieldNameEnableTrafficLogging = "enableTrafficLogging"

	// FieldNameProperties is the object parameter holding extra key→value pairs to add
	// to the emitted traffic-log line under "properties" (traffic-logging mode only).
	// String values prefixed with ctxPrefix are resolved from the request context
	// at request time; other values are passed through as-is.
	FieldNameProperties = "properties"

	// FieldNameMaskedHeaders is the array parameter listing additional header names
	// (case-insensitive) whose values should be redacted in the emitted log line.
	// These are merged with the global masked_headers list from config.toml; either
	// source alone is sufficient.
	FieldNameMaskedHeaders = "maskedHeaders"

	// ctxPrefix marks a property value as a context-variable reference to be
	// resolved at request time (mirrors the backend-jwt policy's customClaims).
	ctxPrefix = "$ctx:"

	// trafficLogMetadataKey is the analytics-metadata key under which the
	// traffic-logging marker is carried to the traffic-logging publisher. It must
	// match the key the policy-engine reads in prepareAnalyticEvent.
	trafficLogMetadataKey = "traffic_log"
)

// LogMessagePolicy implements logging of request/response payloads and headers.
// It operates in one of two modes (see the enableTrafficLogging parameter):
// inline (default; real-time slog during mediation) or traffic-logging (per-API
// opt-in signal for the stdout traffic-logging publisher, which adds latencies).
type LogMessagePolicy struct {
	// trafficLogging is true when enableTrafficLogging = true. In that mode the
	// policy is a lightweight signal: it stamps a marker in the request-header
	// phase and emits nothing inline.
	trafficLogging bool
}

type flowConfig struct {
	logPayload bool
	logHeaders bool
}

// flowDirective is the per-flow presentation config carried in the traffic-logging
// marker. Field names/tags mirror the policy-engine's TrafficLogDirective so the
// marshaled JSON round-trips.
type flowDirective struct {
	Payload bool `json:"payload"`
	Headers bool `json:"headers"`
}

// fieldsDirective selects which fields appear in the emitted line (traffic-logging
// mode). Exactly one of Only or Exclude should be set. When set, this is
// authoritative over field presence: the per-flow payload/headers toggles are
// ignored (excludeHeaders still applies). Names are top-level keys
// (e.g. "requestHeaders", "properties", "latencies").
type fieldsDirective struct {
	Only    []string `json:"only,omitempty"`
	Exclude []string `json:"exclude,omitempty"`
}

// trafficLogDirective is the full marker payload (traffic-logging mode).
type trafficLogDirective struct {
	Request  *flowDirective   `json:"request,omitempty"`
	Response *flowDirective   `json:"response,omitempty"`
	Fields   *fieldsDirective `json:"fields,omitempty"`
	// Properties holds resolved property values (context references already expanded
	// at request time). The publisher emits them as a top-level "properties" object.
	Properties map[string]any `json:"properties,omitempty"`
	// MaskedHeaders lists lower-cased header names whose values are redacted in
	// the emitted log line. Merged with the global masked_headers config at publish time.
	MaskedHeaders []string `json:"maskedHeaders,omitempty"`
}

// GetPolicy is the v1alpha2 factory entry point (loaded by v1alpha2 kernels).
// The enableTrafficLogging parameter is read here so Mode() can reflect it:
// traffic-logging mode needs only the request-header phase (no body buffering),
// while inline mode processes headers and streams bodies.
func GetPolicy(
	metadata policy.PolicyMetadata,
	params map[string]interface{},
) (policy.Policy, error) {
	enabled, _ := params[FieldNameEnableTrafficLogging].(bool)
	return &LogMessagePolicy{
		trafficLogging: enabled,
	}, nil
}

func (p *LogMessagePolicy) Mode() policy.ProcessingMode {
	if p.trafficLogging {
		// Signal mode: the marker is static per-API config, so stamping it once in
		// the request-header phase is sufficient. Skip all body/response phases to
		// avoid any buffering overhead.
		return policy.ProcessingMode{
			RequestHeaderMode:  policy.HeaderModeProcess,
			RequestBodyMode:    policy.BodyModeSkip,
			ResponseHeaderMode: policy.HeaderModeSkip,
			ResponseBodyMode:   policy.BodyModeSkip,
		}
	}
	return policy.ProcessingMode{
		RequestHeaderMode:  policy.HeaderModeProcess,
		RequestBodyMode:    policy.BodyModeStream,
		ResponseHeaderMode: policy.HeaderModeProcess,
		ResponseBodyMode:   policy.BodyModeStream,
	}
}

// LogRecord represents the structure of log data
type LogRecord struct {
	MediationFlow string                 `json:"mediation-flow"`
	RequestID     string                 `json:"request-id"`
	HTTPMethod    string                 `json:"http-method"`
	ResourcePath  string                 `json:"resource-path"`
	Payload       string                 `json:"payload,omitempty"`
	Headers       map[string]interface{} `json:"headers,omitempty"`
}

// parseFlowConfig parses flow configuration from request/response parameters.
func (p *LogMessagePolicy) parseFlowConfig(params map[string]interface{}, flowName string) flowConfig {
	flowRaw, found := params[flowName]
	if !found || flowRaw == nil {
		return flowConfig{}
	}
	flow, ok := flowRaw.(map[string]interface{})
	if !ok {
		return flowConfig{}
	}
	return flowConfig{
		logPayload: p.parseBool(flow["payload"]),
		logHeaders: p.parseBool(flow["headers"]),
	}
}

func (p *LogMessagePolicy) parseBool(raw interface{}) bool {
	parsed, _ := raw.(bool)
	return parsed
}

// stampTrafficLogMarker (traffic-logging mode) returns the analytics-metadata marker
// that opts this API into stdout traffic logging. The gateway's traffic-logging
// publisher reads the marker off the Envoy access-log entry and emits the
// enriched (latency-bearing) line; this policy emits nothing inline. The marker
// is always stamped when enableTrafficLogging is true — its presence
// is the opt-in signal — with the parsed per-flow config as its value.
func (p *LogMessagePolicy) stampTrafficLogMarker(reqCtx *policy.RequestHeaderContext, params map[string]interface{}) policy.RequestHeaderAction {
	dir := trafficLogDirective{
		Request:       buildFlowDirective(params, "request"),
		Response:      buildFlowDirective(params, "response"),
		Fields:        buildFieldsDirective(params),
		Properties:    buildProperties(reqCtx, params),
		MaskedHeaders: buildMaskedHeaders(params),
	}
	marker, err := json.Marshal(dir)
	if err != nil {
		// Should not happen for this fixed shape; fall back to an empty opt-in
		// marker so logging still occurs for the API.
		slog.Error("log-message: failed to marshal traffic-log directive", "error", err)
		marker = []byte("{}")
	}
	return policy.UpstreamRequestHeaderModifications{
		AnalyticsMetadata: map[string]any{
			trafficLogMetadataKey: string(marker),
		},
	}
}

// buildProperties resolves the properties param into a flat map for the traffic-log
// marker. String values prefixed with ctxPrefix are resolved from the request context
// (unresolvable references are skipped); other values pass through unchanged.
// Returns nil when nothing usable is configured so the marker omits the field.
func buildProperties(reqCtx *policy.RequestHeaderContext, params map[string]interface{}) map[string]any {
	raw, found := params[FieldNameProperties]
	if !found || raw == nil {
		return nil
	}
	m, ok := raw.(map[string]interface{})
	if !ok || len(m) == 0 {
		return nil
	}
	out := make(map[string]any, len(m))
	for key, val := range m {
		if strings.TrimSpace(key) == "" {
			continue
		}
		s, isStr := val.(string)
		if !isStr {
			// Non-string literals (numbers, booleans) pass through as-is.
			out[key] = val
			continue
		}
		resolved, ok := resolveContextValue(s, reqCtx)
		if !ok {
			slog.Debug("log-message: skipping property — context variable not resolvable",
				"property", key, "ref", s)
			continue
		}
		out[key] = resolved
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// resolveContextValue expands a property value. A value without ctxPrefix is a
// literal and returned unchanged. A "$ctx:<ref>" value is resolved from the request
// context; the boolean is false when the reference cannot be resolved (the caller skips
// it). Fixed accessor names are matched case-insensitively; auth.property.<key> preserves
// the original key case (Properties keys are case-sensitive). auth.* references require an
// earlier auth policy to have populated the shared AuthContext.
func resolveContextValue(value string, reqCtx *policy.RequestHeaderContext) (string, bool) {
	if !strings.HasPrefix(value, ctxPrefix) {
		return value, true
	}
	ref := strings.TrimPrefix(value, ctxPrefix)
	variable := strings.ToLower(ref)

	switch {
	case variable == "request.path":
		return reqCtx.Path, true
	case variable == "request.method":
		return reqCtx.Method, true
	case variable == "request.authority":
		return reqCtx.Authority, true
	case variable == "request.scheme":
		return reqCtx.Scheme, true
	case variable == "request.vhost":
		return reqCtx.Vhost, true
	case variable == "request.id":
		return reqCtx.RequestID, true
	case strings.HasPrefix(variable, "request.header."):
		name := strings.TrimPrefix(variable, "request.header.")
		vals := reqCtx.Headers.Get(name)
		if len(vals) == 0 {
			return "", false
		}
		return vals[0], true
	case variable == "api.id":
		return reqCtx.APIId, true
	case variable == "api.name":
		return reqCtx.APIName, true
	case variable == "api.version":
		return reqCtx.APIVersion, true
	case variable == "api.context":
		return reqCtx.APIContext, true
	case variable == "api.kind":
		return string(reqCtx.APIKind), true
	case variable == "api.operation_path":
		return reqCtx.OperationPath, true
	case variable == "project.id":
		return reqCtx.ProjectID, true
	}

	if strings.HasPrefix(variable, "auth.") {
		authCtx := reqCtx.AuthContext
		if authCtx == nil {
			return "", false
		}
		switch {
		case variable == "auth.subject":
			return authCtx.Subject, true
		case variable == "auth.type":
			return authCtx.AuthType, true
		case variable == "auth.issuer":
			return authCtx.Issuer, true
		case variable == "auth.credential_id":
			return authCtx.CredentialID, true
		case variable == "auth.token_id":
			return authCtx.TokenId, authCtx.TokenId != ""
		case variable == "auth.authenticated":
			return strconv.FormatBool(authCtx.Authenticated), true
		case variable == "auth.authorized":
			return strconv.FormatBool(authCtx.Authorized), true
		case variable == "auth.audience":
			if len(authCtx.Audience) == 0 {
				return "", false
			}
			return strings.Join(authCtx.Audience, ","), true
		case variable == "auth.scopes":
			if len(authCtx.Scopes) == 0 {
				return "", false
			}
			return joinScopes(authCtx.Scopes), true
		case strings.HasPrefix(variable, "auth.property."):
			propKey := ref[len("auth.property."):]
			val, ok := authCtx.Properties[propKey]
			return val, ok
		}
	}

	return "", false
}

// joinScopes renders a scope set as a space-separated string in a stable (sorted)
// order so log lines are deterministic.
func joinScopes(scopes map[string]bool) string {
	names := make([]string, 0, len(scopes))
	for name := range scopes {
		names = append(names, name)
	}
	sort.Strings(names)
	return strings.Join(names, " ")
}

// buildFlowDirective extracts a flow ("request" or "response") sub-object into a
// flowDirective, returning nil when the flow is absent or not an object so the
// marshaled marker omits flows the user did not configure.
func buildFlowDirective(params map[string]interface{}, flowName string) *flowDirective {
	raw, found := params[flowName]
	if !found || raw == nil {
		return nil
	}
	flow, ok := raw.(map[string]interface{})
	if !ok {
		return nil
	}
	return &flowDirective{
		Payload: parseBoolValue(flow["payload"]),
		Headers: parseBoolValue(flow["headers"]),
	}
}

func parseBoolValue(raw interface{}) bool {
	parsed, _ := raw.(bool)
	return parsed
}

// buildFieldsDirective extracts the optional `fields` selection from params. It
// returns nil when absent, malformed, or when no names are given (an empty
// selection is treated as "no projection").
func buildFieldsDirective(params map[string]interface{}) *fieldsDirective {
	raw, found := params["fields"]
	if !found || raw == nil {
		return nil
	}
	f, ok := raw.(map[string]interface{})
	if !ok {
		return nil
	}
	only := parseNameList(f["only"])
	exclude := parseNameList(f["exclude"])
	if len(only) == 0 && len(exclude) == 0 {
		return nil
	}
	return &fieldsDirective{
		Only:    only,
		Exclude: exclude,
	}
}

// buildMaskedHeaders parses the maskedHeaders param, normalizing each name to
// lower-case so the publisher can do case-insensitive matching cheaply. Returns
// nil when the param is absent or empty.
func buildMaskedHeaders(params map[string]interface{}) []string {
	raw, found := params[FieldNameMaskedHeaders]
	if !found || raw == nil {
		return nil
	}
	names := parseNameList(raw) // trims whitespace, drops empty strings
	if len(names) == 0 {
		return nil
	}
	out := make([]string, 0, len(names))
	for _, h := range names {
		out = append(out, strings.ToLower(h))
	}
	return out
}

// parseNameList parses a list of field names, trimming whitespace but preserving
// case (they match JSON keys). Tolerates []interface{} and []string.
func parseNameList(raw interface{}) []string {
	var out []string
	add := func(s string) {
		if t := strings.TrimSpace(s); t != "" {
			out = append(out, t)
		}
	}
	switch v := raw.(type) {
	case []interface{}:
		for _, e := range v {
			if s, ok := e.(string); ok {
				add(s)
			}
		}
	case []string:
		for _, s := range v {
			add(s)
		}
	}
	return out
}

// logMessage logs the structured log record using slog at INFO level
func (p *LogMessagePolicy) logMessage(record LogRecord) {
	logData, err := json.Marshal(record)
	if err != nil {
		slog.Error("Failed to marshal log record", "error", err)
		return
	}

	slog.Info(string(logData))
}

// OnRequestHeaders logs request headers in the header phase (inline mode), or —
// in traffic-logging mode — stamps the traffic-log marker and returns, emitting
// nothing inline.
func (p *LogMessagePolicy) OnRequestHeaders(ctx context.Context, reqCtx *policy.RequestHeaderContext, params map[string]interface{}) policy.RequestHeaderAction {
	if p.trafficLogging {
		return p.stampTrafficLogMarker(reqCtx, params)
	}

	config := p.parseFlowConfig(params, "request")

	if !config.logHeaders {
		return policy.UpstreamRequestHeaderModifications{}
	}

	logRecord := LogRecord{
		MediationFlow: MediationFlowRequest,
		RequestID:     p.getRequestID(reqCtx.Headers),
		HTTPMethod:    reqCtx.Method,
		ResourcePath:  reqCtx.Path,
		Headers:       p.buildHeadersMap(reqCtx.Headers),
	}

	p.logMessage(logRecord)

	return policy.UpstreamRequestHeaderModifications{}
}

// OnResponseHeaders logs response headers in the header phase.
func (p *LogMessagePolicy) OnResponseHeaders(ctx context.Context, respCtx *policy.ResponseHeaderContext, params map[string]interface{}) policy.ResponseHeaderAction {
	config := p.parseFlowConfig(params, "response")

	if !config.logHeaders {
		return policy.DownstreamResponseHeaderModifications{}
	}

	logRecord := LogRecord{
		MediationFlow: MediationFlowResponse,
		RequestID:     p.getResponseRequestIDv2(respCtx.ResponseHeaders),
		HTTPMethod:    respCtx.RequestMethod,
		ResourcePath:  respCtx.RequestPath,
		Headers:       p.buildHeadersMap(respCtx.ResponseHeaders),
	}

	p.logMessage(logRecord)

	return policy.DownstreamResponseHeaderModifications{}
}

// OnRequestBody logs the request payload.
// Header logging is handled by OnRequestHeaders.
func (p *LogMessagePolicy) OnRequestBody(ctx context.Context, reqCtx *policy.RequestContext, params map[string]interface{}) policy.RequestAction {
	config := p.parseFlowConfig(params, "request")

	// Skip logging if payload logging is disabled.
	if !config.logPayload {
		return policy.UpstreamRequestModifications{}
	}

	// Create log record
	logRecord := LogRecord{
		MediationFlow: MediationFlowRequest,
		RequestID:     p.getRequestID(reqCtx.Headers),
		HTTPMethod:    reqCtx.Method,
		ResourcePath:  reqCtx.Path,
	}

	// Log payload if present.
	if reqCtx.Body != nil && reqCtx.Body.Present && len(reqCtx.Body.Content) > 0 {
		logRecord.Payload = string(reqCtx.Body.Content)
	}

	// Log the message.
	p.logMessage(logRecord)

	// Continue with the request unchanged.
	return policy.UpstreamRequestModifications{}
}

// OnResponseBody logs the response payload.
// Header logging is handled by OnResponseHeaders.
func (p *LogMessagePolicy) OnResponseBody(ctx context.Context, respCtx *policy.ResponseContext, params map[string]interface{}) policy.ResponseAction {
	config := p.parseFlowConfig(params, "response")

	// Skip logging if payload logging is disabled.
	if !config.logPayload {
		return policy.DownstreamResponseModifications{}
	}

	// Create log record
	logRecord := LogRecord{
		MediationFlow: MediationFlowResponse,
		RequestID:     p.getResponseRequestIDv2(respCtx.ResponseHeaders),
		HTTPMethod:    respCtx.RequestMethod,
		ResourcePath:  respCtx.RequestPath,
	}

	// Log payload if present.
	if respCtx.ResponseBody != nil && respCtx.ResponseBody.Present && len(respCtx.ResponseBody.Content) > 0 {
		logRecord.Payload = string(respCtx.ResponseBody.Content)
	}

	// Log the message.
	p.logMessage(logRecord)

	// Continue with the response unchanged.
	return policy.DownstreamResponseModifications{}
}

// ─── Streaming (SSE) support ──────────────────────────────────────────────────
//
// Log-message is a read-only side-effect policy — it never modifies payloads
// or blocks the request/response flow. This makes it one of the safest and
// most natural streaming candidates: each chunk is logged as it passes through,
// providing real-time observability into streaming LLM responses without adding
// latency or requiring accumulation.
//
// NeedsMoreRequestData and NeedsMoreResponseData always return false because
// there is no accumulation requirement — individual chunks can be logged
// independently as soon as they arrive.

// NeedsMoreRequestData implements StreamingRequestPolicy.
// Always returns false — each request chunk is logged independently.
func (p *LogMessagePolicy) NeedsMoreRequestData(accumulated []byte) bool {
	return false
}

// OnRequestBodyChunk implements StreamingRequestPolicy.
// Logs each streaming request chunk as it arrives. The full request body is
// logged incrementally across chunks rather than buffered into a single record.
func (p *LogMessagePolicy) OnRequestBodyChunk(ctx context.Context, reqCtx *policy.RequestStreamContext, chunk *policy.StreamBody, params map[string]interface{}) policy.StreamingRequestAction {
	config := p.parseFlowConfig(params, "request")
	if !config.logPayload || chunk == nil || len(chunk.Chunk) == 0 {
		return policy.ForwardRequestChunk{}
	}

	logRecord := LogRecord{
		MediationFlow: MediationFlowRequest,
		RequestID:     p.getRequestID(reqCtx.Headers),
		HTTPMethod:    reqCtx.Method,
		ResourcePath:  reqCtx.Path,
		Payload:       string(chunk.Chunk),
	}
	p.logMessage(logRecord)

	return policy.ForwardRequestChunk{}
}

// NeedsMoreResponseData implements StreamingResponsePolicy.
// Always returns false — each response chunk is logged independently.
func (p *LogMessagePolicy) NeedsMoreResponseData(accumulated []byte) bool {
	return false
}

// OnResponseBodyChunk implements StreamingResponsePolicy.
// Logs each streaming response chunk as it arrives, providing real-time
// visibility into SSE token streams without buffering or latency overhead.
func (p *LogMessagePolicy) OnResponseBodyChunk(ctx context.Context, respCtx *policy.ResponseStreamContext, chunk *policy.StreamBody, params map[string]interface{}) policy.StreamingResponseAction {
	config := p.parseFlowConfig(params, "response")
	if !config.logPayload || chunk == nil || len(chunk.Chunk) == 0 {
		return policy.ForwardResponseChunk{}
	}

	logRecord := LogRecord{
		MediationFlow: MediationFlowResponse,
		RequestID:     p.getResponseRequestIDv2(respCtx.ResponseHeaders),
		HTTPMethod:    respCtx.RequestMethod,
		ResourcePath:  respCtx.RequestPath,
		Payload:       string(chunk.Chunk),
	}
	p.logMessage(logRecord)

	return policy.ForwardResponseChunk{}
}

// getRequestID extracts request ID from request headers
func (p *LogMessagePolicy) getRequestID(headers *policy.Headers) string {
	if headers == nil {
		return ErrMsgMissingReqID
	}
	if requestIDs := headers.Get(HeaderXRequestID); len(requestIDs) > 0 {
		return requestIDs[0]
	}
	return ErrMsgMissingReqID
}

// getResponseRequestID extracts request ID from response headers
func (p *LogMessagePolicy) getResponseRequestIDv2(headers *policy.Headers) string {
	if headers == nil {
		return ErrMsgMissingReqID
	}
	if requestIDs := headers.Get(HeaderXRequestID); len(requestIDs) > 0 {
		return requestIDs[0]
	}
	return ErrMsgMissingReqID
}

// buildHeadersMap builds a map of headers for logging, masking authorization by default.
func (p *LogMessagePolicy) buildHeadersMap(headers *policy.Headers) map[string]interface{} {
	headersMap := make(map[string]interface{})
	if headers == nil {
		return headersMap
	}

	headers.Iterate(func(name string, values []string) {
		lowerName := strings.ToLower(name)

		// Mask authorization header by default
		if lowerName == "authorization" {
			headersMap[name] = "***"
			return
		}

		// Add header to map
		if len(values) == 1 {
			headersMap[name] = values[0]
		} else {
			headersMap[name] = values
		}
	})

	return headersMap
}
