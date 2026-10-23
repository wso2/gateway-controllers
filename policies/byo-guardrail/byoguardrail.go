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

// Package byoguardrail lets users plug an existing guardrail service into the
// gateway through configuration alone. The policy extracts text from the
// request or response body, POSTs it to the configured endpoint following a
// small versioned contract, and applies the service's decision: allow, block,
// or modify (replace the checked text). Any failure to obtain a valid decision
// is a guardrail error, handled per onError, and never counts as an allow.
package byoguardrail

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
	utils "github.com/wso2/api-platform/sdk/core/utils"
)

const (
	GuardrailErrorCode = 422
	guardrailName      = "BYO Guardrail"
	errorResponseType  = "BYO_GUARDRAIL"

	// ContractVersion identifies the request/response shape exchanged with the
	// guardrail service. It changes only when that shape changes incompatibly.
	ContractVersion = "v1"

	requestDefaultJSONPath   = "$.messages[-1].content"
	responseDefaultJSONPath  = "$.choices[0].message.content"
	streamingDefaultJSONPath = "$.choices[0].delta.content"

	defaultTimeout = 5 * time.Second
	maxTimeout     = 30 * time.Second

	modeEnforce = "enforce"
	modeMonitor = "monitor"

	onErrorBlock = "block"
	onErrorAllow = "allow"

	authTypeBearer = "bearer"
	authTypeRaw    = "raw"

	actionAllow  = "allow"
	actionBlock  = "block"
	actionModify = "modify"

	// A decision is a few hundred bytes; a larger body is not a valid one.
	maxGuardrailResponseBytes = 1 << 20

	actionReasonViolation = "Violation of guardrail detected."
	actionReasonError     = "Guardrail check could not be completed."

	// SharedContext.Metadata key prefix, suffixed with the phase ("request" or
	// "response") so both phases can record without overwriting each other.
	metaKeyPrefix = "byo-guardrail:"
)

// Guardrail error kinds, recorded in metadata and logs so an operator can tell
// an outage from a misbehaving service without seeing any payload.
const (
	errKindExtraction      = "extraction"
	errKindTimeout         = "timeout"
	errKindConnection      = "connection"
	errKindHTTPStatus      = "http_status"
	errKindInvalidResponse = "invalid_response"
	errKindModification    = "modification"
)

// errorReasons are the fixed, content-free reasons shown to clients when
// showAssessment is on. Raw error text is never returned to clients.
var errorReasons = map[string]string{
	errKindExtraction:      "Error extracting text from the payload",
	errKindTimeout:         "Guardrail service timed out",
	errKindConnection:      "Error calling the guardrail service",
	errKindHTTPStatus:      "Guardrail service returned an unexpected status",
	errKindInvalidResponse: "Guardrail service returned an invalid response",
	errKindModification:    "Error applying the guardrail's modification",
}

// BYOGuardrailPolicy calls a user-operated guardrail service for request and/or
// response content.
type BYOGuardrailPolicy struct {
	endpoint   string
	authHeader string
	timeout    time.Duration
	mode       string
	onError    string
	client     *http.Client

	hasRequestParams  bool
	hasResponseParams bool
	requestParams     phaseParams
	responseParams    phaseParams
}

type phaseParams struct {
	Enabled           bool
	JSONPath          string
	StreamingJSONPath string
	ShowAssessment    bool
}

// GetPolicy is the v1alpha2 factory entry point (loaded by v1alpha2 kernels).
func GetPolicy(
	metadata policy.PolicyMetadata,
	params map[string]interface{},
) (policy.Policy, error) {
	endpoint, err := parseEndpoint(params)
	if err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}
	authHeader, err := parseAuth(params)
	if err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}
	timeout, err := parseTimeout(params)
	if err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}
	mode, err := parseEnum(params, "mode", modeEnforce, modeEnforce, modeMonitor)
	if err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}
	onError, err := parseEnum(params, "onError", onErrorBlock, onErrorBlock, onErrorAllow)
	if err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}

	transport := http.DefaultTransport.(*http.Transport).Clone()
	p := &BYOGuardrailPolicy{
		endpoint:   endpoint,
		authHeader: authHeader,
		timeout:    timeout,
		mode:       mode,
		onError:    onError,
		// Each call is bounded by timeout via context. Redirects are not
		// followed: a 3xx is an unexpected status, and the auth header is
		// never sent anywhere but the configured endpoint.
		client: &http.Client{
			Transport: transport,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}

	if raw, ok := params["request"]; ok {
		requestParams, err := parsePhaseParams(raw, requestDefaultJSONPath)
		if err != nil {
			return nil, fmt.Errorf("invalid request parameters: %w", err)
		}
		p.hasRequestParams = true
		p.requestParams = requestParams
	}
	if raw, ok := params["response"]; ok {
		responseParams, err := parsePhaseParams(raw, responseDefaultJSONPath)
		if err != nil {
			return nil, fmt.Errorf("invalid response parameters: %w", err)
		}
		p.hasResponseParams = true
		p.responseParams = responseParams
	}
	if !p.hasRequestParams && !p.hasResponseParams {
		return nil, fmt.Errorf("at least one of 'request' or 'response' parameters must be provided")
	}

	// The token is deliberately absent from this line.
	slog.Debug("BYOGuardrail: Policy initialized",
		"endpointHost", hostOf(endpoint), "auth", p.authHeader != "", "timeout", p.timeout,
		"mode", p.mode, "onError", p.onError,
		"requestEnabled", p.requestEnabled(), "responseEnabled", p.responseEnabled())

	return p, nil
}

func (p *BYOGuardrailPolicy) requestEnabled() bool {
	return p.hasRequestParams && p.requestParams.Enabled
}

func (p *BYOGuardrailPolicy) responseEnabled() bool {
	return p.hasResponseParams && p.responseParams.Enabled
}

// Mode buffers only the phases that are enabled. Buffering the response body
// disables streaming for the whole route, so a request-only attachment must
// skip the response body to leave streaming intact.
func (p *BYOGuardrailPolicy) Mode() policy.ProcessingMode {
	mode := policy.ProcessingMode{
		RequestHeaderMode:  policy.HeaderModeSkip,
		RequestBodyMode:    policy.BodyModeSkip,
		ResponseHeaderMode: policy.HeaderModeSkip,
		ResponseBodyMode:   policy.BodyModeSkip,
	}
	if p.requestEnabled() {
		mode.RequestBodyMode = policy.BodyModeBuffer
	}
	if p.responseEnabled() {
		mode.ResponseBodyMode = policy.BodyModeBuffer
	}
	return mode
}

// OnRequestBody checks the request body with the guardrail service.
func (p *BYOGuardrailPolicy) OnRequestBody(ctx context.Context, reqCtx *policy.RequestContext, _ map[string]interface{}) policy.RequestAction {
	if !p.requestEnabled() {
		return policy.UpstreamRequestModifications{}
	}
	var content []byte
	if reqCtx.Body != nil {
		content = reqCtx.Body.Content
	}
	return p.check(ctx, reqCtx.SharedContext, content, p.requestParams, false).(policy.RequestAction)
}

// OnResponseBody checks the response body with the guardrail service.
func (p *BYOGuardrailPolicy) OnResponseBody(ctx context.Context, respCtx *policy.ResponseContext, _ map[string]interface{}) policy.ResponseAction {
	if !p.responseEnabled() {
		return policy.DownstreamResponseModifications{}
	}
	// An upstream error response carries the provider's error, not generated
	// content. Checking it would fail to find the configured path and, failing
	// closed, hide the provider's error behind a guardrail block. 0 means the
	// status is unknown, so the body is checked.
	if status := respCtx.ResponseStatus; status != 0 && (status < 200 || status > 299) {
		slog.Debug("BYOGuardrail: Upstream returned an error response, not checking it", "status", status)
		return policy.DownstreamResponseModifications{}
	}
	var content []byte
	if respCtx.ResponseBody != nil {
		content = respCtx.ResponseBody.Content
	}
	return p.check(ctx, respCtx.SharedContext, content, p.responseParams, true).(policy.ResponseAction)
}

// check extracts the configured text, asks the guardrail service for a
// decision, and applies it. Returns interface{} so one implementation serves
// both phases, as the other guardrail policies do.
func (p *BYOGuardrailPolicy) check(ctx context.Context, shared *policy.SharedContext, payload []byte, params phaseParams, isResponse bool) interface{} {
	phase := "request"
	if isResponse {
		phase = "response"
	}
	passthrough := func(body []byte, analyticsMetadata map[string]interface{}) interface{} {
		if isResponse {
			return policy.DownstreamResponseModifications{Body: body, AnalyticsMetadata: analyticsMetadata}
		}
		return policy.UpstreamRequestModifications{Body: body, AnalyticsMetadata: analyticsMetadata}
	}
	// failure handles an error in the check itself, not a decision. Monitor mode
	// never blocks, so it passes through regardless of onError. Either way the
	// outcome is recorded as an error, never as an allow.
	failure := func(gerr *guardrailError) interface{} {
		blocks := p.mode == modeEnforce && p.onError == onErrorBlock
		outcome := "passed"
		if blocks {
			outcome = "blocked"
		}
		record := map[string]interface{}{"decision": "error", "outcome": outcome, "errorType": gerr.kind}
		if gerr.statusCode != 0 {
			record["statusCode"] = gerr.statusCode
		}
		setMetadata(shared, metaKeyPrefix+phase, record)
		slog.Warn("BYOGuardrail: guardrail check failed",
			"phase", phase, "errorType", gerr.kind, "statusCode", gerr.statusCode, "error", gerr.err,
			"timeout", p.timeout, "mode", p.mode, "onError", p.onError, "outcome", outcome,
			"requestId", requestID(shared))
		if !blocks {
			return passthrough(nil, nil)
		}
		return p.buildBlockResponse(isResponse, actionReasonError, errorReasons[gerr.kind], params.ShowAssessment)
	}

	// An empty body has nothing to check.
	if len(payload) == 0 {
		return passthrough(nil, nil)
	}

	ext, err := extractTexts(payload, params, isResponse)
	if err != nil {
		return failure(&guardrailError{kind: errKindExtraction, err: err})
	}
	if !hasText(ext.texts) {
		slog.Debug("BYOGuardrail: No text to check", "phase", phase)
		return passthrough(nil, nil)
	}

	d, gerr := p.evaluate(ctx, shared, phase, ext.texts)
	if gerr != nil {
		return failure(gerr)
	}

	enforced := p.mode == modeEnforce
	switch d.action {
	case actionAllow:
		setMetadata(shared, metaKeyPrefix+phase, map[string]interface{}{"decision": actionAllow, "outcome": "passed"})
		slog.Debug("BYOGuardrail: Guardrail allowed", "phase", phase)
		return passthrough(nil, nil)

	case actionModify:
		if ext.apply == nil {
			// The checked text was reassembled from a streamed response, which has
			// no single location to write a replacement to. Passing the original
			// would deliver what the guardrail asked to remove, so it is blocked.
			return p.intervene(shared, phase, actionModify, isResponse, params,
				"Guardrail modification cannot be applied to a streamed response")
		}
		if !enforced {
			setMetadata(shared, metaKeyPrefix+phase, map[string]interface{}{"decision": actionModify, "outcome": "passed"})
			slog.Info("BYOGuardrail: guardrail would modify (monitor mode, not modifying)",
				"phase", phase, "requestId", requestID(shared))
			return passthrough(nil, nil)
		}
		body, err := ext.apply(d.texts)
		if err != nil {
			return failure(&guardrailError{kind: errKindModification, err: err})
		}
		setMetadata(shared, metaKeyPrefix+phase, map[string]interface{}{"decision": actionModify, "outcome": "modified"})
		slog.Debug("BYOGuardrail: Content modified by guardrail", "phase", phase)
		return passthrough(body, nil)

	default: // actionBlock; evaluate admits no other action.
		return p.intervene(shared, phase, actionBlock, isResponse, params, d.reason)
	}
}

// intervene blocks in enforce mode, or records the would-be block in monitor
// mode. decision is what the guardrail returned; assessment is the reason shown
// to the client when showAssessment is on.
func (p *BYOGuardrailPolicy) intervene(shared *policy.SharedContext, phase, decision string, isResponse bool, params phaseParams, assessment string) interface{} {
	analyticsMetadata := map[string]interface{}{
		"isGuardrailHit": true,
		"guardrailName":  guardrailName,
	}
	if p.mode == modeMonitor {
		setMetadata(shared, metaKeyPrefix+phase, map[string]interface{}{"decision": decision, "outcome": "passed"})
		slog.Info("BYOGuardrail: guardrail would block (monitor mode, not blocking)",
			"phase", phase, "decision", decision, "requestId", requestID(shared))
		if isResponse {
			return policy.DownstreamResponseModifications{AnalyticsMetadata: analyticsMetadata}
		}
		return policy.UpstreamRequestModifications{AnalyticsMetadata: analyticsMetadata}
	}
	setMetadata(shared, metaKeyPrefix+phase, map[string]interface{}{"decision": decision, "outcome": "blocked"})
	slog.Debug("BYOGuardrail: Guardrail blocked", "phase", phase, "decision", decision)
	return p.buildBlockResponse(isResponse, actionReasonViolation, assessment, params.ShowAssessment)
}

// buildBlockResponse builds the 422 returned for a block or a fail-closed
// error, in the same shape as the other guardrail policies. assessment is
// shown only when showAssessment is on.
func (p *BYOGuardrailPolicy) buildBlockResponse(isResponse bool, actionReason, assessment string, showAssessment bool) interface{} {
	message := map[string]interface{}{
		"action":               "GUARDRAIL_INTERVENED",
		"interveningGuardrail": guardrailName,
		"actionReason":         actionReason,
	}
	if isResponse {
		message["direction"] = "RESPONSE"
	} else {
		message["direction"] = "REQUEST"
	}
	if showAssessment && assessment != "" {
		message["assessments"] = assessment
	}

	bodyBytes, err := json.Marshal(map[string]interface{}{"type": errorResponseType, "message": message})
	if err != nil {
		bodyBytes = []byte(`{"type":"` + errorResponseType + `","message":"Internal error"}`)
	}
	analyticsMetadata := map[string]interface{}{
		"isGuardrailHit": true,
		"guardrailName":  guardrailName,
	}
	headers := map[string]string{"Content-Type": "application/json"}

	if isResponse {
		statusCode := GuardrailErrorCode
		return policy.DownstreamResponseModifications{
			StatusCode:        &statusCode,
			Body:              bodyBytes,
			AnalyticsMetadata: analyticsMetadata,
			HeadersToSet:      headers,
		}
	}
	return policy.ImmediateResponse{
		StatusCode:        GuardrailErrorCode,
		Body:              bodyBytes,
		AnalyticsMetadata: analyticsMetadata,
		Headers:           headers,
	}
}

// --- Guardrail service contract ---

type evaluateRequest struct {
	ContractVersion string           `json:"contractVersion"`
	InputType       string           `json:"inputType"`
	Texts           []string         `json:"texts"`
	Metadata        evaluateMetadata `json:"metadata"`
}

type evaluateMetadata struct {
	APIName    string `json:"apiName,omitempty"`
	APIVersion string `json:"apiVersion,omitempty"`
	RequestID  string `json:"requestId,omitempty"`
}

// evaluateResponse is decoded loosely and then validated, so a missing field
// can be told apart from a zero value. Unknown fields are ignored, letting a
// service return its own diagnostics alongside the decision.
type evaluateResponse struct {
	Action *string         `json:"action"`
	Reason *string         `json:"reason"`
	Texts  json.RawMessage `json:"texts"`
}

type decision struct {
	action string
	reason string
	texts  []string
}

type guardrailError struct {
	kind       string
	statusCode int
	err        error
}

// evaluate calls the guardrail service and validates its decision against the
// contract. Anything short of a well-formed decision is a guardrailError.
func (p *BYOGuardrailPolicy) evaluate(ctx context.Context, shared *policy.SharedContext, phase string, texts []string) (*decision, *guardrailError) {
	reqBody := evaluateRequest{ContractVersion: ContractVersion, InputType: phase, Texts: texts}
	if shared != nil {
		reqBody.Metadata = evaluateMetadata{APIName: shared.APIName, APIVersion: shared.APIVersion, RequestID: shared.RequestID}
	}
	payload, err := json.Marshal(reqBody)
	if err != nil {
		return nil, &guardrailError{kind: errKindConnection, err: fmt.Errorf("marshal guardrail request: %w", err)}
	}

	ctx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, p.endpoint, bytes.NewReader(payload))
	if err != nil {
		return nil, &guardrailError{kind: errKindConnection, err: fmt.Errorf("build guardrail request: %w", err)}
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json")
	if p.authHeader != "" {
		httpReq.Header.Set("Authorization", p.authHeader)
	}

	resp, err := p.client.Do(httpReq)
	if err != nil {
		return nil, classifyTransportError(err)
	}
	defer resp.Body.Close()

	// The response body is never logged or returned: it may echo the checked text.
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxGuardrailResponseBytes+1))
	if err != nil {
		return nil, classifyTransportError(err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, &guardrailError{kind: errKindHTTPStatus, statusCode: resp.StatusCode,
			err: fmt.Errorf("guardrail service returned status %d", resp.StatusCode)}
	}
	if len(body) > maxGuardrailResponseBytes {
		return nil, &guardrailError{kind: errKindInvalidResponse, statusCode: resp.StatusCode,
			err: fmt.Errorf("guardrail response exceeds %d bytes", maxGuardrailResponseBytes)}
	}

	d, err := parseDecision(body, len(texts))
	if err != nil {
		return nil, &guardrailError{kind: errKindInvalidResponse, statusCode: resp.StatusCode, err: err}
	}
	return d, nil
}

// parseDecision validates a guardrail response body. A malformed or ambiguous
// decision is an error, never an allow.
func parseDecision(body []byte, wantTexts int) (*decision, error) {
	var parsed evaluateResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, fmt.Errorf("decode guardrail response: %w", err)
	}
	if parsed.Action == nil {
		return nil, fmt.Errorf("guardrail response is missing 'action'")
	}
	d := &decision{action: *parsed.Action}
	if parsed.Reason != nil {
		d.reason = *parsed.Reason
	}
	hasTexts := len(parsed.Texts) > 0 && string(parsed.Texts) != "null"

	switch d.action {
	case actionAllow, actionBlock:
		// Replacement text alongside allow or block leaves it unclear whether
		// the service meant to modify, so it is rejected rather than guessed.
		if hasTexts {
			return nil, fmt.Errorf("guardrail response has 'texts' with action %q; 'texts' is only valid with %q", d.action, actionModify)
		}
	case actionModify:
		if !hasTexts {
			return nil, fmt.Errorf("guardrail response with action %q is missing 'texts'", actionModify)
		}
		var raw []json.RawMessage
		if err := json.Unmarshal(parsed.Texts, &raw); err != nil {
			return nil, fmt.Errorf("guardrail response 'texts' must be an array of strings")
		}
		if len(raw) != wantTexts {
			return nil, fmt.Errorf("guardrail response 'texts' has %d entries, expected %d", len(raw), wantTexts)
		}
		d.texts = make([]string, len(raw))
		for i, entry := range raw {
			// A null entry would otherwise decode as "" and silently erase text.
			if len(entry) == 0 || entry[0] != '"' {
				return nil, fmt.Errorf("guardrail response 'texts' entry %d is not a string", i)
			}
			if err := json.Unmarshal(entry, &d.texts[i]); err != nil {
				return nil, fmt.Errorf("guardrail response 'texts' entry %d is not a string", i)
			}
		}
	default:
		return nil, fmt.Errorf("guardrail response has unknown action %q", d.action)
	}
	return d, nil
}

// classifyTransportError maps a client error to a guardrailError. The
// *url.Error wrapper is dropped because its message includes the endpoint URL,
// whose query string could carry credentials.
func classifyTransportError(err error) *guardrailError {
	inner := err
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		inner = urlErr.Err
	}
	var netErr net.Error
	if errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &netErr) && netErr.Timeout()) {
		return &guardrailError{kind: errKindTimeout, err: inner}
	}
	return &guardrailError{kind: errKindConnection, err: inner}
}

// --- Text extraction ---

// extraction is the text to check and, where the text has a single location in
// the payload, a function writing replacements back to that location.
type extraction struct {
	texts []string
	// apply returns the payload with texts replaced, leaving every other field
	// intact. nil when the text cannot be written back (a streamed response).
	apply func(replacements []string) ([]byte, error)
}

// extractTexts returns the text to check from a request or response body.
//
// The value at jsonPath may be a string (one text) or an OpenAI-style array
// of content parts (one text per text part; images and other parts are not
// inspected). A null value, such as the content of a tool-call-only reply, has
// nothing to check. A buffered response to a "stream": true request arrives as
// an SSE event stream, so its text is reassembled from each event's
// streamingJsonPath fragment.
func extractTexts(payload []byte, params phaseParams, isResponse bool) (*extraction, error) {
	if isResponse && isSSE(payload) {
		text, err := extractSSEText(payload, params.StreamingJSONPath)
		if err != nil {
			return nil, err
		}
		return &extraction{texts: []string{text}}, nil
	}

	if params.JSONPath == "" {
		return &extraction{
			texts: []string{string(payload)},
			apply: func(r []string) ([]byte, error) { return []byte(r[0]), nil },
		}, nil
	}

	// UseNumber keeps numbers such as large integer IDs exact when the body is
	// re-encoded after a modification.
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.UseNumber()
	var data map[string]interface{}
	if err := dec.Decode(&data); err != nil {
		return nil, fmt.Errorf("payload is not a JSON object: %w", err)
	}
	value, err := utils.ExtractValueFromJsonpath(data, params.JSONPath)
	if err != nil {
		return nil, err
	}

	switch v := value.(type) {
	case nil:
		return &extraction{}, nil
	case string:
		return &extraction{
			texts: []string{v},
			apply: func(r []string) ([]byte, error) {
				if err := utils.SetValueAtJSONPath(data, params.JSONPath, r[0]); err != nil {
					return nil, err
				}
				return marshalJSON(data)
			},
		}, nil
	case []interface{}:
		return extractContentParts(data, v)
	default:
		return nil, fmt.Errorf("value at JSONPath is not a string or content-part array")
	}
}

// extractContentParts collects the text parts of a content-part array. The
// array shares storage with data, so apply edits it in place.
func extractContentParts(data map[string]interface{}, parts []interface{}) (*extraction, error) {
	var texts []string
	var setters []func(string)
	for i, item := range parts {
		switch part := item.(type) {
		case string:
			idx := i
			texts = append(texts, part)
			setters = append(setters, func(s string) { parts[idx] = s })
		case map[string]interface{}:
			if text, ok := part["text"].(string); ok {
				m := part
				texts = append(texts, text)
				setters = append(setters, func(s string) { m["text"] = s })
				continue
			}
			// A typed non-text part (image_url, input_audio, ...) is not
			// inspected. An untyped object means the JSONPath points at
			// something other than content parts, which must not pass as
			// nothing to check.
			if _, typed := part["type"].(string); !typed {
				return nil, fmt.Errorf("array element %d at JSONPath is not a content part", i)
			}
		default:
			return nil, fmt.Errorf("array element %d at JSONPath is not a content part", i)
		}
	}
	return &extraction{
		texts: texts,
		apply: func(r []string) ([]byte, error) {
			for i, set := range setters {
				set(r[i])
			}
			return marshalJSON(data)
		},
	}, nil
}

// marshalJSON encodes without HTML escaping, so "<" and "&" in unrelated
// fields are not rewritten as < and &.
func marshalJSON(v interface{}) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

func hasText(texts []string) bool {
	for _, t := range texts {
		if strings.TrimSpace(t) != "" {
			return true
		}
	}
	return false
}

// isSSE reports whether payload looks like a server-sent event stream.
func isSSE(payload []byte) bool {
	trimmed := bytes.TrimLeft(payload, " \t\r\n")
	return bytes.HasPrefix(trimmed, []byte("data:")) || bytes.HasPrefix(trimmed, []byte("event:"))
}

// extractSSEText concatenates the streamingJsonPath fragment of every SSE data
// event. Comments, non-data fields, empty data lines, and the [DONE] marker
// are ignored. Every other data payload must be a JSON object: a malformed one
// is an extraction error, since skipping it would check only part of the reply,
// or none of it. Events where the path doesn't resolve (role-only deltas,
// finish and usage events) contribute nothing. If events were parsed but the
// path resolved in none of them, the stream isn't in the shape the path
// expects, so it is an extraction error rather than a reply with nothing to
// check. Errors never include event content.
func extractSSEText(payload []byte, streamingJSONPath string) (string, error) {
	var sb strings.Builder
	events, resolved := 0, 0
	for _, line := range strings.Split(string(payload), "\n") {
		line = strings.TrimRight(line, "\r")
		if !strings.HasPrefix(line, "data:") {
			continue
		}
		data := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		if data == "" || data == "[DONE]" {
			continue
		}
		events++
		var event map[string]interface{}
		// The decode error is dropped: its message can quote the payload.
		if err := json.Unmarshal([]byte(data), &event); err != nil {
			return "", fmt.Errorf("stream data event %d is not a JSON object", events)
		}
		value, err := utils.ExtractValueFromJsonpath(event, streamingJSONPath)
		if err != nil {
			continue
		}
		resolved++
		if text, ok := value.(string); ok {
			sb.WriteString(text)
		}
	}
	if events > 0 && resolved == 0 {
		return "", fmt.Errorf("streamingJsonPath %q matched none of the %d stream events", streamingJSONPath, events)
	}
	return sb.String(), nil
}

// --- Parameter parsing ---

func parseEndpoint(params map[string]interface{}) (string, error) {
	raw, ok := params["endpoint"]
	if !ok || raw == nil {
		return "", fmt.Errorf("'endpoint' parameter is required")
	}
	endpoint, ok := raw.(string)
	if !ok || strings.TrimSpace(endpoint) == "" {
		return "", fmt.Errorf("'endpoint' must be a non-empty string")
	}
	endpoint = strings.TrimSpace(endpoint)
	u, err := url.Parse(endpoint)
	if err != nil {
		return "", fmt.Errorf("'endpoint' must be a valid URL")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", fmt.Errorf("'endpoint' must use the http or https scheme")
	}
	if u.Host == "" {
		return "", fmt.Errorf("'endpoint' must include a host")
	}
	// Credentials belong in auth.token, where they are kept out of logs.
	if u.User != nil {
		return "", fmt.Errorf("'endpoint' must not contain user credentials; use 'auth' instead")
	}
	if u.Fragment != "" {
		return "", fmt.Errorf("'endpoint' must not contain a fragment")
	}
	return endpoint, nil
}

// parseAuth returns the full Authorization header value to send, or "" when
// auth is not configured.
func parseAuth(params map[string]interface{}) (string, error) {
	raw, ok := params["auth"]
	if !ok || raw == nil {
		return "", nil
	}
	auth, ok := raw.(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("'auth' must be an object")
	}
	// type defaults to bearer, matching the schema default.
	authType := authTypeBearer
	if rawType, ok := auth["type"]; ok && rawType != nil {
		t, ok := rawType.(string)
		if !ok || (t != authTypeBearer && t != authTypeRaw) {
			return "", fmt.Errorf("'auth.type' must be %q or %q", authTypeBearer, authTypeRaw)
		}
		authType = t
	}
	token, ok := auth["token"].(string)
	if !ok || strings.TrimSpace(token) == "" {
		return "", fmt.Errorf("'auth.token' is required when 'auth' is configured")
	}
	token = strings.TrimSpace(token)
	if strings.ContainsAny(token, "\r\n") {
		return "", fmt.Errorf("'auth.token' must not contain line breaks")
	}
	if authType == authTypeRaw {
		return token, nil
	}
	return "Bearer " + token, nil
}

func parseTimeout(params map[string]interface{}) (time.Duration, error) {
	raw, ok := params["timeout"]
	if !ok || raw == nil {
		return defaultTimeout, nil
	}
	s, ok := raw.(string)
	if !ok {
		return 0, fmt.Errorf("'timeout' must be a duration string such as \"5s\"")
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("'timeout' must be a duration string such as \"5s\": %w", err)
	}
	if d <= 0 || d > maxTimeout {
		return 0, fmt.Errorf("'timeout' must be greater than 0 and at most %s", maxTimeout)
	}
	return d, nil
}

func parseEnum(params map[string]interface{}, key, def string, allowed ...string) (string, error) {
	raw, ok := params[key]
	if !ok || raw == nil {
		return def, nil
	}
	s, ok := raw.(string)
	if ok {
		for _, a := range allowed {
			if s == a {
				return s, nil
			}
		}
	}
	return "", fmt.Errorf("'%s' must be one of %q", key, allowed)
}

func parsePhaseParams(raw interface{}, defaultJSONPath string) (phaseParams, error) {
	result := phaseParams{
		Enabled:           true,
		JSONPath:          defaultJSONPath,
		StreamingJSONPath: streamingDefaultJSONPath,
	}
	params, ok := raw.(map[string]interface{})
	if !ok {
		return result, fmt.Errorf("must be an object")
	}

	for key, field := range map[string]*bool{"enabled": &result.Enabled, "showAssessment": &result.ShowAssessment} {
		if v, ok := params[key]; ok {
			b, ok := v.(bool)
			if !ok {
				return result, fmt.Errorf("'%s' must be a boolean", key)
			}
			*field = b
		}
	}

	if v, ok := params["jsonPath"]; ok {
		s, ok := v.(string)
		if !ok {
			return result, fmt.Errorf("'jsonPath' must be a string")
		}
		if err := validateJSONPath(s); err != nil {
			return result, fmt.Errorf("'jsonPath': %w", err)
		}
		result.JSONPath = s
	}
	if v, ok := params["streamingJsonPath"]; ok {
		s, ok := v.(string)
		if !ok || s == "" {
			return result, fmt.Errorf("'streamingJsonPath' must be a non-empty string")
		}
		if err := validateJSONPath(s); err != nil {
			return result, fmt.Errorf("'streamingJsonPath': %w", err)
		}
		result.StreamingJSONPath = s
	}
	return result, nil
}

var arraySegmentPattern = regexp.MustCompile(`^[a-zA-Z0-9_]+\[-?\d+\]$`)

// validateJSONPath accepts the dotted subset of JSONPath the SDK resolves:
// "$", then "."-separated keys, each optionally indexed as key[n] or key[-n].
// Wildcards are rejected because a modify decision needs one location to write
// to. An empty path selects the whole body.
func validateJSONPath(path string) error {
	if path == "" {
		return nil
	}
	if !strings.HasPrefix(path, "$.") {
		return fmt.Errorf("must start with \"$.\" (or be empty to check the whole body)")
	}
	if strings.Contains(path, "*") {
		return fmt.Errorf("wildcards are not supported; select a single value")
	}
	for _, segment := range strings.Split(strings.TrimPrefix(path, "$."), ".") {
		if segment == "" {
			return fmt.Errorf("contains an empty segment")
		}
		if strings.ContainsAny(segment, "[]") && !arraySegmentPattern.MatchString(segment) {
			return fmt.Errorf("segment %q must be a key or key[index]", segment)
		}
	}
	return nil
}

// --- Helpers ---

// setMetadata records a value in SharedContext.Metadata, where later policies
// and the traffic-logging analytics publisher can read it.
func setMetadata(shared *policy.SharedContext, key string, value interface{}) {
	if shared == nil {
		return
	}
	if shared.Metadata == nil {
		shared.Metadata = make(map[string]interface{})
	}
	shared.Metadata[key] = value
}

func requestID(shared *policy.SharedContext) string {
	if shared == nil {
		return ""
	}
	return shared.RequestID
}

func hostOf(endpoint string) string {
	if u, err := url.Parse(endpoint); err == nil {
		return u.Host
	}
	return ""
}
