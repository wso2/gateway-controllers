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

	// faultPhaseKey is the params key an attachment under globalFaultPolicies uses. It is a
	// sibling of "request" and "response" and mutually exclusive with both, which the policy
	// definition's schema enforces.
	faultPhaseKey = "fault"
)

// LogMessagePolicy implements logging of request/response payloads and headers
type LogMessagePolicy struct{}

type flowConfig struct {
	logPayload      bool
	logHeaders      bool
	excludedHeaders map[string]struct{}
}

var ins = &LogMessagePolicy{}

// GetPolicy is the v1alpha2 factory entry point (loaded by v1alpha2 kernels).
func GetPolicy(
	metadata policy.PolicyMetadata,
	params map[string]interface{},
) (policy.Policy, error) {
	return ins, nil
}

func (p *LogMessagePolicy) Mode() policy.ProcessingMode {
	return policy.ProcessingMode{
		RequestHeaderMode:  policy.HeaderModeProcess,
		RequestBodyMode:    policy.BodyModeStream,
		ResponseHeaderMode: policy.HeaderModeProcess,
		ResponseBodyMode:   policy.BodyModeStream,
	}
}

// LogRecord represents the structure of log data
//
// The fault fields are omitempty so a request or response record serialises exactly as it
// did before OnFault existed; they are populated only on the fault path.
type LogRecord struct {
	MediationFlow string                 `json:"mediation-flow"`
	RequestID     string                 `json:"request-id"`
	HTTPMethod    string                 `json:"http-method"`
	ResourcePath  string                 `json:"resource-path"`
	Payload       string                 `json:"payload,omitempty"`
	Headers       map[string]interface{} `json:"headers,omitempty"`

	// Status is the status the client will receive.
	Status int `json:"status,omitempty"`
	// OriginalStatus is the upstream's own status when a policy changed it. Not otherwise
	// recoverable — once a guardrail turns a 200 into a 422, the original is gone from
	// every downstream view.
	OriginalStatus int `json:"original-status,omitempty"`
	// FaultCode and FaultType are the failing policy's own classification.
	FaultCode string `json:"error-code,omitempty"`
	FaultType string `json:"error-type,omitempty"`
	// FaultMessage is the client-facing summary. The fault's Description is deliberately
	// NOT logged here: for a guardrail it is the blocked content itself.
	FaultMessage string `json:"error-message,omitempty"`
	// FailingPolicy names the policy that caused the failure, and is empty when no policy
	// did — an infrastructure failure, for instance. Empty means "not caused by a policy",
	// never "unknown".
	FailingPolicy string `json:"failing-policy,omitempty"`
}

// parseFlowConfig parses flow configuration from request/response parameters.
func (p *LogMessagePolicy) parseFlowConfig(params map[string]interface{}, flowName string) flowConfig {
	cfg := flowConfig{
		excludedHeaders: map[string]struct{}{},
	}

	flowRaw, found := params[flowName]
	if !found || flowRaw == nil {
		return cfg
	}

	flow, ok := flowRaw.(map[string]interface{})
	if !ok {
		return cfg
	}

	cfg.logPayload = p.parseBool(flow["payload"])
	cfg.logHeaders = p.parseBool(flow["headers"])
	cfg.excludedHeaders = p.parseExcludedHeaders(flow["excludeHeaders"])
	return cfg
}

func (p *LogMessagePolicy) parseBool(raw interface{}) bool {
	parsed, _ := raw.(bool)
	return parsed
}

// parseExcludedHeaders parses a list of excluded header names.
func (p *LogMessagePolicy) parseExcludedHeaders(excludedHeadersRaw interface{}) map[string]struct{} {
	excludedHeaders := make(map[string]struct{})

	if excludedHeadersRaw == nil {
		return excludedHeaders
	}

	switch headers := excludedHeadersRaw.(type) {
	case []interface{}:
		for _, headerRaw := range headers {
			header, ok := headerRaw.(string)
			if !ok {
				continue
			}
			trimmed := strings.ToLower(strings.TrimSpace(header))
			if trimmed != "" {
				excludedHeaders[trimmed] = struct{}{}
			}
		}
	case []string:
		for _, header := range headers {
			trimmed := strings.ToLower(strings.TrimSpace(header))
			if trimmed != "" {
				excludedHeaders[trimmed] = struct{}{}
			}
		}
	}

	return excludedHeaders
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

// OnRequestHeaders logs request headers in the header phase.
func (p *LogMessagePolicy) OnRequestHeaders(ctx context.Context, reqCtx *policy.RequestHeaderContext, params map[string]interface{}) policy.RequestHeaderAction {
	config := p.parseFlowConfig(params, "request")

	if !config.logHeaders {
		return policy.UpstreamRequestHeaderModifications{}
	}

	ds := reqCtx.DownstreamRequest()
	logRecord := LogRecord{
		MediationFlow: MediationFlowRequest,
		RequestID:     p.getRequestID(reqCtx.Headers),
		HTTPMethod:    ds.Method,
		ResourcePath:  ds.Path,
		Headers:       p.buildHeadersMap(reqCtx.Headers, config.excludedHeaders),
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

	ds := respCtx.DownstreamRequest()
	logRecord := LogRecord{
		MediationFlow: MediationFlowResponse,
		RequestID:     p.getResponseRequestIDv2(respCtx.ResponseHeaders),
		HTTPMethod:    ds.Method,
		ResourcePath:  ds.Path,
		Headers:       p.buildHeadersMap(respCtx.ResponseHeaders, config.excludedHeaders),
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
	ds := reqCtx.DownstreamRequest()
	logRecord := LogRecord{
		MediationFlow: MediationFlowRequest,
		RequestID:     p.getRequestID(reqCtx.Headers),
		HTTPMethod:    ds.Method,
		ResourcePath:  ds.Path,
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
	ds := respCtx.DownstreamRequest()
	logRecord := LogRecord{
		MediationFlow: MediationFlowResponse,
		RequestID:     p.getResponseRequestIDv2(respCtx.ResponseHeaders),
		HTTPMethod:    ds.Method,
		ResourcePath:  ds.Path,
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

// OnFault implements policy.FaultPolicy, which is what makes this policy usable in an API's
// fault sequence. Recording a failure is exactly what this policy is for, so the fault path
// is the one place it has the most to say.
//
// It returns nil — "no action". This policy never modifies traffic, and on the fault path
// the client is already receiving an error; a notify-only policy has nothing to add to the
// response.
//
// It also cannot fail the request. Every read below tolerates a nil, the logging call
// already swallows its own marshal errors, and nil is returned on every path — so there is
// no way for this policy to turn one failure into a second.
func (p *LogMessagePolicy) OnFault(ctx context.Context, faultCtx *policy.FaultContext, params map[string]interface{}) *policy.FaultResponse {
	if faultCtx == nil {
		// Nothing to record, and certainly nothing worth panicking over.
		return nil
	}

	// Read from the `fault` block, never `response`. An attachment lives under either
	// `policies:` or `globalFaultPolicies:`, never both, so a fault attachment carries
	// `fault` and nothing else; the schema rejects a params object declaring both.
	//
	// The record itself is written whether or not the block is present: the operator asked
	// for this policy in the fault sequence, and a fault policy that silently does nothing
	// would be the worse surprise. The config only decides whether the error payload and
	// headers are included — and those are the parts worth an explicit opt-in, since an
	// error body can carry detail a healthy response would not.
	config := p.parseFlowConfig(params, faultPhaseKey)

	logRecord := LogRecord{
		MediationFlow:  MediationFlowFault,
		OriginalStatus: faultCtx.OriginalStatus,
		FailingPolicy:  faultCtx.Policy,
	}

	// The failure is read from faultCtx rather than re-derived: the gateway already
	// determined what failed, including for a router failure where no policy did.
	if faultCtx.Fault != nil {
		logRecord.FaultCode = faultCtx.Fault.Code
		logRecord.FaultType = faultCtx.Fault.Type
		logRecord.FaultMessage = faultCtx.Fault.Message
	}

	// FaultContext declares its response fields directly rather than embedding a response
	// context, so there is no longer a pointer to guard: reading ResponseStatus or
	// ResponseHeaders cannot panic, and both helpers below already treat a nil Headers as
	// "nothing to report". ResponseBody stays checked because it is still a pointer, and a
	// failure raised before any body existed leaves it nil.
	logRecord.Status = faultCtx.ResponseStatus

	ds := faultCtx.DownstreamRequest()
	logRecord.HTTPMethod = ds.Method
	logRecord.ResourcePath = ds.Path
	logRecord.RequestID = p.getResponseRequestIDv2(faultCtx.ResponseHeaders)

	if config.logHeaders {
		logRecord.Headers = p.buildHeadersMap(faultCtx.ResponseHeaders, config.excludedHeaders)
	}
	if config.logPayload && faultCtx.ResponseBody != nil && faultCtx.ResponseBody.Present &&
		len(faultCtx.ResponseBody.Content) > 0 {
		logRecord.Payload = string(faultCtx.ResponseBody.Content)
	}

	p.logMessage(logRecord)
	return nil
}

// Compile-time check that this policy satisfies the fault-path contract. Without it, a
// signature drift would only surface at runtime, where the gateway drops the fault entry
// with "[chain-build] skipping fault-policies policy that does not implement OnFault" — it
// fails loudly, but the policy also silently never runs.
var _ policy.FaultPolicy = (*LogMessagePolicy)(nil)

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

	ds := reqCtx.DownstreamRequest()
	logRecord := LogRecord{
		MediationFlow: MediationFlowRequest,
		RequestID:     p.getRequestID(reqCtx.Headers),
		HTTPMethod:    ds.Method,
		ResourcePath:  ds.Path,
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

	ds := respCtx.DownstreamRequest()
	logRecord := LogRecord{
		MediationFlow: MediationFlowResponse,
		RequestID:     p.getResponseRequestIDv2(respCtx.ResponseHeaders),
		HTTPMethod:    ds.Method,
		ResourcePath:  ds.Path,
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

// buildHeadersMap builds a map of headers for logging, excluding sensitive ones
func (p *LogMessagePolicy) buildHeadersMap(headers *policy.Headers, excludedHeaders map[string]struct{}) map[string]interface{} {
	headersMap := make(map[string]interface{})
	if headers == nil {
		return headersMap
	}

	headers.Iterate(func(name string, values []string) {
		lowerName := strings.ToLower(name)

		// Skip excluded headers
		if _, excluded := excludedHeaders[lowerName]; excluded {
			return // continue iteration
		}

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
