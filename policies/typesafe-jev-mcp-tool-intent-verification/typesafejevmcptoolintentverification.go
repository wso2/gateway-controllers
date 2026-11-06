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

// Package typesafejevmcptoolintentverification screens MCP tools/call requests using TypeSafe
// AI's Jev "System One" model (https://typesafe.ai). Before a tool call reaches the
// MCP server, the tool name and its arguments are sent to Jev as a JSON state along
// with a configurable battery of typed questions (Noul, Score, Choice). The call is
// blocked with a JSON-RPC error when any question's answer crosses its threshold —
// or, in monitor mode, only recorded.
//
// The default battery asks whether the call is destructive, irreversible, sends
// private data out, reads secrets, raises privileges, disrupts a running system,
// weakens a security control, or falls outside the scope. Everything about how a
// tool is screened is set by rules: a rule names one tool, or "*" for every tool
// without its own rule, and gives the scope that describes the agent's job (so
// effects it calls for aren't flagged and a call outside it is), the questions,
// the mode, and whether to fail open. A tool no rule matches isn't screened. The
// MCP proxy never sees the agent's conversation, so scope is judged against the
// configured text only.
package typesafejevmcptoolintentverification

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

const (
	guardrailName  = "TypesafeJevMcpToolIntentVerification"
	defaultBaseURL = "https://api.typesafe.ai"
	defaultModel   = "jev-latest"
	defaultTimeout = 5 * time.Second
	maxTimeout     = 30 * time.Second

	mcpPathSegment   = "/mcp"
	mcpSessionHeader = "mcp-session-id"
	methodToolsCall  = "tools/call"

	// A blocked call gets the same status and JSON-RPC code as a call mcp-acl-list
	// denies. A check that could not run (fail closed) is an internal error.
	statusBlocked          = http.StatusBadRequest
	statusCheckUnavailable = http.StatusServiceUnavailable
	jsonRpcErrCodeBlocked  = -32000
	jsonRpcErrCodeInternal = -32603
	jsonRpcErrCodeParse    = -32700
	jsonRpcErrCodeRequest  = -32600
	jsonRpcErrCodeParams   = -32602

	questionTypeNoul   = "noul"
	questionTypeScore  = "score"
	questionTypeChoice = "choice"

	// Jev's documented limits on criteria size per question type.
	maxScoreLevels  = 10
	maxChoiceOption = 255

	modeEnforce = "enforce"
	modeMonitor = "monitor"

	// Jev returns 429 when rate limited and 529 when overloaded; both are
	// documented as retryable. One retry with a short backoff, bounded by the
	// same per-call timeout as the first attempt.
	statusJevOverloaded = 529
	retryBackoff        = 250 * time.Millisecond

	// A Jev answer is a few kilobytes, so a larger body is not a valid answer.
	maxJevResponseBytes = 1 << 20
	// Only the start of an error body goes into error messages, which are logged.
	maxJevErrorBodyBytes = 512

	defaultThreshold = 0.7

	// SharedContext.Metadata keys, read by later policies and the traffic-logging
	// analytics publisher.
	metaKeyAssessments   = "typesafe-jev-mcp-tool-intent-verification:assessments"
	metaKeyUsage         = "typesafe-jev-mcp-tool-intent-verification:usage"
	metaKeyLowConfidence = "typesafe-jev-mcp-tool-intent-verification:low-confidence"
)

// guardrailQuestion is one entry in a configured question battery. Criteria
// applies to (and is required for) Score and Choice questions; BlockOn only
// applies to Choice. Threshold is compared against the Noul probability, the
// Score value, or the summed probability of the BlockOn options, depending
// on the question's type. ConfidenceThreshold only applies to Score: a score
// at or above Threshold blocks only when Jev's confidence also reaches it
// (0 means off).
type guardrailQuestion struct {
	Key                 string
	Type                string
	Instructions        string
	Criteria            []string
	BlockOn             []string
	Threshold           float64
	ConfidenceThreshold float64
}

// defaultBattery is the question list used when "questions" isn't configured,
// and the default the policy definition shows (keep the two identical; a test
// checks it). It was tuned against jev-1.13.0 on hand-labelled tool calls, with
// exactly this wording. Each question covers one kind of harm, since a Noul is
// most accurate on a single judgement. The questions that judge an effect exclude
// effects the scope calls for, so a support assistant replying to a customer
// isn't flagged. exfiltration, sensitive_data and security_control don't mention
// the scope, but Jev still sees it, so a job that clearly involves that data (a
// pizza ordering assistant taking a card) can lower their answers too.
var defaultBattery = []struct{ key, instructions string }{
	{"destructive", "Would running the tool call in `tool` destroy, overwrite, or damage data, files, or systems that cannot easily be recreated, in a way that `scope` does not call for?"},
	{"irreversible", "Would running the tool call in `tool` have an effect that cannot be undone, such as sending a message, moving money, or publishing something, that `scope` does not call for?"},
	{"exfiltration", "Would running the tool call in `tool` send secrets, credentials, or private data outside the organisation?"},
	{"sensitive_data", "Would running the tool call in `tool` read or reveal secrets, credentials, or payment card data?"},
	{"privilege", "Would running the tool call in `tool` grant or raise access rights or permissions in a way that `scope` does not call for?"},
	{"disruption", "Would running the tool call in `tool` stop, shut down, or take offline a running service or system in a way that `scope` does not call for?"},
	{"security_control", "Would running the tool call in `tool` turn off or weaken a security control, such as multi-factor authentication, a firewall, encryption, or audit logging?"},
	{"out_of_scope", "Is the tool call in `tool` unrelated to the purpose described in `scope`?"},
}

func defaultQuestions() []guardrailQuestion {
	questions := make([]guardrailQuestion, 0, len(defaultBattery))
	for _, d := range defaultBattery {
		questions = append(questions, guardrailQuestion{
			Key:          d.key,
			Type:         questionTypeNoul,
			Instructions: d.instructions,
			Threshold:    defaultThreshold,
		})
	}
	return questions
}

// wildcardToolName is the rule name that matches every tool without its own rule.
const wildcardToolName = "*"

// toolRule is how the calls of the tools it matches are screened.
type toolRule struct {
	scope              string
	questions          []guardrailQuestion
	mode               string
	passthroughOnError bool
}

// TypesafeJevMcpToolIntentVerificationPolicy implements a Jev-backed guardrail for MCP tool calls.
type TypesafeJevMcpToolIntentVerificationPolicy struct {
	apiKey  string
	baseURL string
	model   string
	client  *http.Client

	tools          map[string]toolRule
	anyTool        *toolRule
	timeout        time.Duration
	showAssessment bool
}

// GetPolicy is the v1alpha2 factory entry point (loaded by v1alpha2 kernels).
func GetPolicy(
	metadata policy.PolicyMetadata,
	params map[string]interface{},
) (policy.Policy, error) {
	apiKey, err := requiredStringParam(params, "apiKey")
	if err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}

	// No client-level timeout: each Jev call is bounded by the configured
	// timeout via context instead.
	p := &TypesafeJevMcpToolIntentVerificationPolicy{
		apiKey:  apiKey,
		baseURL: stringParamOrDefault(params, "baseURL", defaultBaseURL),
		model:   stringParamOrDefault(params, "model", defaultModel),
		client:  &http.Client{},
		timeout: defaultTimeout,
	}
	if err := p.parseParams(params); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}

	slog.Debug("TypesafeJevMcpToolIntentVerification: Policy initialized",
		"toolRules", len(p.tools), "wildcardRule", p.anyTool != nil)

	return p, nil
}

// Mode buffers the request body only: the tool name and arguments are read from
// the JSON-RPC body, and the response is never inspected.
func (p *TypesafeJevMcpToolIntentVerificationPolicy) Mode() policy.ProcessingMode {
	return policy.ProcessingMode{
		RequestHeaderMode:  policy.HeaderModeSkip,
		RequestBodyMode:    policy.BodyModeBuffer,
		ResponseHeaderMode: policy.HeaderModeSkip,
		ResponseBodyMode:   policy.BodyModeSkip,
	}
}

// OnRequestBody screens a tools/call request. Everything else on the proxy —
// other methods, other routes, JSON-RPC responses and notifications — passes
// through untouched.
func (p *TypesafeJevMcpToolIntentVerificationPolicy) OnRequestBody(ctx context.Context, reqCtx *policy.RequestContext, _ map[string]interface{}) policy.RequestAction {
	// Read the path and headers from the downstream snapshot, so the check and its
	// error responses reflect what the client sent, not what a peer policy rewrote.
	ds := reqCtx.DownstreamRequest()
	routePath := ds.Path
	if reqCtx.SharedContext != nil && reqCtx.OperationPath != "" {
		routePath = reqCtx.OperationPath
	}
	if !isMcpPostRequest(ds.Method, routePath) {
		return policy.UpstreamRequestModifications{}
	}
	if reqCtx.Body == nil || len(reqCtx.Body.Content) == 0 {
		return policy.UpstreamRequestModifications{}
	}

	call, errResp := parseToolCall(reqCtx.Body.Content, ds.Headers)
	if errResp != nil {
		return *errResp
	}
	if call == nil {
		return policy.UpstreamRequestModifications{}
	}
	return p.screen(ctx, reqCtx.SharedContext, ds.Headers, call)
}

// toolCallRequest is the part of a tools/call request that is screened.
type toolCallRequest struct {
	ID        json.RawMessage
	Name      string
	Arguments json.RawMessage
}

// toolCallState is the JSON state sent to Jev. Question instructions refer to
// its fields by name (`tool`, `tool.arguments`, `scope`).
type toolCallState struct {
	Tool  toolCallStateTool `json:"tool"`
	Scope string            `json:"scope,omitempty"`
}

type toolCallStateTool struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments,omitempty"`
}

// parseToolCall reads a JSON-RPC request body. It returns nil and no error for a
// message that isn't a tools/call, and an error response for a body that can't be
// read unambiguously: this policy must screen exactly the call the MCP server will
// run, so a body the server might read differently is refused rather than passed.
func parseToolCall(body []byte, headers *policy.Headers) (*toolCallRequest, *policy.ImmediateResponse) {
	reject := func(code int, message string, id json.RawMessage) (*toolCallRequest, *policy.ImmediateResponse) {
		resp := buildRequestErrorResponse(headers, statusBlocked, code, message, id, nil,
			&policy.FaultDetails{Code: policy.FaultCodeInvalidRequestBody, Type: policy.FaultTypeValidation})
		return nil, &resp
	}

	raw := body
	if isEventStream(headers) {
		data, events := eventStreamData(body)
		if events > 1 {
			return reject(jsonRpcErrCodeRequest, "Request body is not a single JSON-RPC request object", nil)
		}
		if strings.TrimSpace(string(data)) == "" {
			return reject(jsonRpcErrCodeParse, "Invalid JSON", nil)
		}
		raw = data
	}
	if !json.Valid(raw) {
		return reject(jsonRpcErrCodeParse, "Invalid JSON", nil)
	}
	if !isJSONObject(raw) {
		return reject(jsonRpcErrCodeRequest, "Request body is not a single JSON-RPC request object", nil)
	}

	members, err := objectMembers(raw)
	if err != nil {
		return reject(jsonRpcErrCodeParse, "Invalid JSON", nil)
	}
	if err := checkMemberSpelling(members, "id", "method", "params"); err != nil {
		return reject(jsonRpcErrCodeRequest, "Ambiguous MCP request: "+err.Error(), nil)
	}
	id := memberValue(members, "id")

	methodRaw := memberValue(members, "method")
	if methodRaw == nil {
		// A JSON-RPC response or a malformed message; nothing to screen.
		return nil, nil
	}
	var method string
	if err := json.Unmarshal(methodRaw, &method); err != nil {
		return reject(jsonRpcErrCodeRequest, "Request body has a member of the wrong type", id)
	}
	if method != methodToolsCall {
		return nil, nil
	}

	paramsRaw := memberValue(members, "params")
	if paramsRaw == nil || !isJSONObject(paramsRaw) {
		return reject(jsonRpcErrCodeParams, "Invalid MCP request params", id)
	}
	params, err := objectMembers(paramsRaw)
	if err != nil {
		return reject(jsonRpcErrCodeParams, "Invalid MCP request params", id)
	}
	if err := checkMemberSpelling(params, "name", "arguments"); err != nil {
		return reject(jsonRpcErrCodeRequest, "Ambiguous MCP request: "+err.Error(), id)
	}

	var name string
	if nameRaw := memberValue(params, "name"); nameRaw != nil {
		if err := json.Unmarshal(nameRaw, &name); err != nil {
			return reject(jsonRpcErrCodeParams, "Invalid MCP request params", id)
		}
	}
	if strings.TrimSpace(name) == "" {
		return reject(jsonRpcErrCodeParams, "Missing MCP tool name", id)
	}

	arguments := memberValue(params, "arguments")
	if arguments != nil && !isJSONObject(arguments) && !bytes.Equal(bytes.TrimSpace(arguments), []byte("null")) {
		return reject(jsonRpcErrCodeParams, "Invalid MCP request params", id)
	}

	return &toolCallRequest{ID: id, Name: name, Arguments: arguments}, nil
}

// screen asks Jev the configured questions about one tool call and returns either
// a passthrough or a blocking JSON-RPC error.
func (p *TypesafeJevMcpToolIntentVerificationPolicy) screen(ctx context.Context, shared *policy.SharedContext, headers *policy.Headers, call *toolCallRequest) policy.RequestAction {
	// A rule for the exact tool name wins over "*". A tool no rule matches isn't
	// screened, so it costs no Jev call.
	rule, ok := p.tools[call.Name]
	if !ok {
		if p.anyTool == nil {
			slog.Debug("TypesafeJevMcpToolIntentVerification: no rule matches tool, not screened", "tool", call.Name)
			return policy.UpstreamRequestModifications{}
		}
		rule = *p.anyTool
	}
	questions := rule.questions

	// failure handles an error in the check itself (not a violation). Monitor mode
	// never blocks, so it always passes through regardless of passthroughOnError.
	failure := func(reason string, err error) policy.RequestAction {
		if rule.mode == modeMonitor || rule.passthroughOnError {
			slog.Debug("TypesafeJevMcpToolIntentVerification: check failed, passing through",
				"reason", reason, "error", err, "mode", rule.mode, "tool", call.Name)
			return policy.UpstreamRequestModifications{}
		}
		slog.Debug("TypesafeJevMcpToolIntentVerification: check failed, failing closed",
			"reason", reason, "error", err, "tool", call.Name)
		// Not a verdict: the gateway could not reach Jev, or Jev answered malformed.
		return buildRequestErrorResponse(headers, statusCheckUnavailable, jsonRpcErrCodeInternal,
			"MCP tool call could not be checked by guardrail", call.ID, nil,
			&policy.FaultDetails{
				Code:        policy.FaultCodeMediationFailed,
				Type:        policy.FaultTypeMediation,
				Description: reason + ": " + err.Error(),
			})
	}

	state := toolCallState{
		Tool:  toolCallStateTool{Name: call.Name, Arguments: call.Arguments},
		Scope: rule.scope,
	}
	answers, usage, err := p.callJev(ctx, state, questions, p.timeout)
	if err != nil {
		return failure("Error calling Jev API", err)
	}
	if usage != nil {
		setMetadata(shared, metaKeyUsage, map[string]interface{}{
			"input_tokens": usage.InputTokens, "output_tokens": usage.OutputTokens,
		})
	}

	var failed, lowConfidence []map[string]interface{}
	for _, q := range questions {
		raw, ok := answers[q.Key]
		if !ok {
			// A partial Jev response is a failure of the check, not a pass: a
			// fail-closed operator's call must not go through on a missing answer.
			return failure("Error processing Jev response", fmt.Errorf("Jev response missing answer for question %q", q.Key))
		}
		assessment, blocks, err := evaluateAnswer(q, raw)
		if err != nil {
			return failure("Error processing Jev response", fmt.Errorf("question %q: %w", q.Key, err))
		}
		switch {
		case blocks:
			failed = append(failed, assessment)
		case assessment != nil:
			lowConfidence = append(lowConfidence, assessment)
		}
	}

	if len(lowConfidence) > 0 {
		setMetadata(shared, metaKeyLowConfidence, lowConfidence)
		slog.Debug("TypesafeJevMcpToolIntentVerification: threshold reached below confidenceThreshold, not blocking",
			"questions", lowConfidence, "tool", call.Name)
	}

	if len(failed) == 0 {
		return policy.UpstreamRequestModifications{}
	}

	setMetadata(shared, metaKeyAssessments, failed)

	if rule.mode == modeMonitor {
		slog.Info("TypesafeJevMcpToolIntentVerification: violation detected (monitor mode, not blocking)",
			"failedQuestions", failed, "tool", call.Name)
		return policy.UpstreamRequestModifications{AnalyticsMetadata: guardrailHitAnalytics()}
	}

	slog.Debug("TypesafeJevMcpToolIntentVerification: violation detected", "failedQuestions", failed, "tool", call.Name)
	var data map[string]interface{}
	if p.showAssessment {
		data = map[string]interface{}{
			"interveningGuardrail": guardrailName,
			"assessments":          failed,
		}
	}
	resp := buildRequestErrorResponse(headers, statusBlocked, jsonRpcErrCodeBlocked,
		"MCP tool call blocked by guardrail", call.ID, data, guardrailFault(call.Name, failed, data))
	for k, v := range guardrailHitAnalytics() {
		resp.AnalyticsMetadata[k] = v
	}
	return resp
}

// guardrailFault describes a blocked call. The questions are operator-defined,
// so the verdict has no more specific code than the generic guardrail one.
// The assessments are carried only where showAssessment put them in the body.
func guardrailFault(tool string, failed []map[string]interface{}, data map[string]interface{}) *policy.FaultDetails {
	questions := make([]string, 0, len(failed))
	for _, f := range failed {
		if key, ok := f["question"].(string); ok {
			questions = append(questions, key)
		}
	}
	guardrail := &policy.GuardrailDetails{
		InterveningGuardrail: guardrailName,
		Action:               policy.GuardrailActionIntervened,
		ActionReason:         "MCP tool call blocked by guardrail",
	}
	if data != nil {
		guardrail.Assessments = map[string]any{"assessments": data["assessments"]}
	}
	return &policy.FaultDetails{
		Code:        policy.GuardrailCodeIntervened,
		Type:        policy.FaultTypeGuardrail,
		Description: "tool " + tool + " failed questions: " + strings.Join(questions, ", "),
		Guardrail:   guardrail,
	}
}

func guardrailHitAnalytics() map[string]interface{} {
	return map[string]interface{}{
		"isGuardrailHit": true,
		"guardrailName":  guardrailName,
	}
}

// evaluateAnswer decodes one question's answer and returns its assessment
// entry when the answer is at or above the question's threshold, or nil when
// it isn't. blocks is false for a score that reached its threshold without
// reaching its confidenceThreshold: that assessment is only recorded.
func evaluateAnswer(q guardrailQuestion, raw json.RawMessage) (assessment map[string]interface{}, blocks bool, err error) {
	assessment = map[string]interface{}{
		"question": q.Key, "type": q.Type, "threshold": q.Threshold,
	}
	var value float64
	var confidence *float64
	switch q.Type {
	case questionTypeNoul:
		v, err := decodeNoulAnswer(raw)
		if err != nil {
			return nil, false, err
		}
		value = v
	case questionTypeScore:
		a, err := decodeScoreAnswer(raw)
		if err != nil {
			return nil, false, err
		}
		value = a.Score
		confidence = a.Confidence
		if a.Confidence != nil {
			assessment["confidence"] = *a.Confidence
		}
		// Jev always reports a Score's confidence; a missing one can't be
		// checked against the configured threshold, so it's a malformed answer.
		if q.ConfidenceThreshold > 0 && a.Confidence == nil {
			return nil, false, fmt.Errorf("answer missing 'confidence' field")
		}
	case questionTypeChoice:
		a, err := decodeChoiceAnswer(raw)
		if err != nil {
			return nil, false, err
		}
		// The blocking value is the total probability mass on the BlockOn
		// options, not just whether one of them won the argmax.
		for _, option := range q.BlockOn {
			value += a.Probabilities[option]
		}
		assessment["choice"] = a.Choice
		if a.Confidence != nil {
			assessment["confidence"] = *a.Confidence
		}
	default:
		return nil, false, fmt.Errorf("unsupported question type %q", q.Type)
	}
	if value < q.Threshold {
		return nil, false, nil
	}
	assessment["value"] = value
	if q.ConfidenceThreshold > 0 && *confidence < q.ConfidenceThreshold {
		assessment["confidenceThreshold"] = q.ConfidenceThreshold
		return assessment, false, nil
	}
	return assessment, true, nil
}

// setMetadata records a value in SharedContext.Metadata, where later
// policies and the traffic-logging analytics publisher can read it.
func setMetadata(shared *policy.SharedContext, key string, value interface{}) {
	if shared == nil {
		return
	}
	if shared.Metadata == nil {
		shared.Metadata = make(map[string]interface{})
	}
	shared.Metadata[key] = value
}

// --- MCP request handling ---

// isMcpPostRequest reports whether the request targets the MCP endpoint.
func isMcpPostRequest(method, path string) bool {
	if !strings.EqualFold(method, http.MethodPost) {
		return false
	}
	cleanPath := strings.TrimSpace(path)
	if idx := strings.Index(cleanPath, "?"); idx >= 0 {
		cleanPath = cleanPath[:idx]
	}
	return cleanPath == mcpPathSegment || strings.HasPrefix(cleanPath, mcpPathSegment+"/")
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

// eventStreamData returns the data of the first SSE event that carries any,
// joining multi-line data the way the SSE format defines, and how many events
// carry data. A POST body holds one JSON-RPC message, so a caller must refuse a
// body with more than one: screening only the first would leave the others
// unchecked.
func eventStreamData(body []byte) (data []byte, events int) {
	var first, current []string
	flush := func() {
		if len(current) == 0 {
			return
		}
		events++
		if first == nil {
			first = current
		}
		current = nil
	}
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSuffix(line, "\r")
		if line == "" {
			flush()
			continue
		}
		if strings.HasPrefix(line, "data:") {
			current = append(current, strings.TrimPrefix(strings.TrimPrefix(line, "data:"), " "))
		}
	}
	flush()
	return []byte(strings.Join(first, "\n")), events
}

// buildRequestErrorResponse builds a JSON-RPC error response, framed as SSE when
// the request was, and echoing the request id and MCP session id. fault gives the
// code, type and any detail of the rejection; the request direction, the client
// message and the JSON-RPC code and id are filled in here from what the body says.
func buildRequestErrorResponse(headers *policy.Headers, statusCode int, jsonRpcCode int, message string, requestID json.RawMessage, data map[string]interface{}, fault *policy.FaultDetails) policy.ImmediateResponse {
	errObj := map[string]interface{}{
		"code":    jsonRpcCode,
		"message": message,
	}
	if data != nil {
		errObj["data"] = data
	}
	id := requestID
	if len(id) == 0 {
		id = json.RawMessage("null")
	}
	body, err := json.Marshal(map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      id,
		"error":   errObj,
	})
	if err != nil {
		slog.Debug("TypesafeJevMcpToolIntentVerification: Failed to marshal error response", "error", err)
		body = fmt.Appendf(nil, `{"jsonrpc":"2.0","id":%s,"error":{"code":%d,"message":"Unexpected error"}}`, string(id), jsonRpcErrCodeInternal)
	}

	respHeaders := map[string]string{"Content-Type": "application/json"}
	if isEventStream(headers) {
		respHeaders["Content-Type"] = "text/event-stream"
		body = []byte("data: " + string(body) + "\n\n")
	}
	if sessionID := getSessionID(headers); sessionID != "" {
		respHeaders[mcpSessionHeader] = sessionID
	}

	fault.Direction = policy.DirectionRequest
	fault.Message = message
	var faultID any
	if len(requestID) > 0 {
		faultID = requestID
	}
	fault.JSONRPC = &policy.JSONRPCError{Code: &jsonRpcCode, ID: faultID}

	return policy.ImmediateResponse{
		StatusCode:        statusCode,
		Headers:           respHeaders,
		Body:              body,
		AnalyticsMetadata: map[string]interface{}{"mcpErrorCode": jsonRpcCode},
		IsFault:           true,
		Fault:             fault,
	}
}

// jsonMember is a single object member, kept in document order so that duplicate
// names remain visible.
type jsonMember struct {
	name  string
	value json.RawMessage
}

// objectMembers returns the members of a JSON object in document order,
// including any repeated names.
func objectMembers(raw []byte) ([]jsonMember, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	if delim, ok := tok.(json.Delim); !ok || delim != '{' {
		return nil, errors.New("expected a JSON object")
	}

	var members []jsonMember
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, err
		}
		name, ok := tok.(string)
		if !ok {
			return nil, errors.New("expected a JSON object member name")
		}
		var value json.RawMessage
		if err := dec.Decode(&value); err != nil {
			return nil, err
		}
		members = append(members, jsonMember{name: name, value: value})
	}
	return members, nil
}

// checkMemberSpelling rejects an object in which a member the policy reads is
// present more than once or under a non-canonical spelling, since the MCP server
// might resolve it to a different value than this policy screens.
func checkMemberSpelling(members []jsonMember, canonicalNames ...string) error {
	seen := make(map[string]string, len(canonicalNames))
	for _, member := range members {
		canonicalName := ""
		for _, name := range canonicalNames {
			if strings.EqualFold(member.name, name) {
				canonicalName = name
				break
			}
		}
		if canonicalName == "" {
			continue
		}
		if previous, duplicate := seen[canonicalName]; duplicate {
			return fmt.Errorf("members %q and %q both resolve to %q", previous, member.name, canonicalName)
		}
		if member.name != canonicalName {
			return fmt.Errorf("member %q must be spelled %q", member.name, canonicalName)
		}
		seen[canonicalName] = member.name
	}
	return nil
}

// memberValue returns the value of the named member, or nil when it is absent.
// Call it only after checkMemberSpelling has ruled out duplicates.
func memberValue(members []jsonMember, name string) json.RawMessage {
	for _, member := range members {
		if member.name == name {
			return member.value
		}
	}
	return nil
}

func isJSONObject(raw json.RawMessage) bool {
	trimmed := bytes.TrimLeft(raw, " \t\r\n")
	return len(trimmed) > 0 && trimmed[0] == '{'
}

// --- Jev API client ---

type jevQuestionPayload struct {
	Type         string      `json:"type"`
	Instructions string      `json:"instructions"`
	Criteria     interface{} `json:"criteria,omitempty"`
}

type jevSystemOneRequest struct {
	State     toolCallState                 `json:"state"`
	Model     string                        `json:"model"`
	Questions map[string]jevQuestionPayload `json:"questions"`
}

type jevUsage struct {
	InputTokens  int `json:"input_tokens"`
	OutputTokens int `json:"output_tokens"`
}

type jevSystemOneResponse struct {
	Answers map[string]json.RawMessage `json:"answers"`
	Usage   *jevUsage                  `json:"usage"`
}

func (p *TypesafeJevMcpToolIntentVerificationPolicy) callJev(ctx context.Context, state toolCallState, questions []guardrailQuestion, timeout time.Duration) (map[string]json.RawMessage, *jevUsage, error) {
	questionMap := make(map[string]jevQuestionPayload, len(questions))
	for _, q := range questions {
		payload := jevQuestionPayload{Type: q.Type, Instructions: q.Instructions}
		switch q.Type {
		case questionTypeScore:
			payload.Criteria = q.Criteria
		case questionTypeChoice:
			// Jev's Choice criteria is a map of option id -> description; a
			// null description means the id itself is the description.
			options := make(map[string]*string, len(q.Criteria))
			for _, option := range q.Criteria {
				options[option] = nil
			}
			payload.Criteria = options
		}
		questionMap[q.Key] = payload
	}

	reqBody := jevSystemOneRequest{State: state, Model: p.model, Questions: questionMap}
	payload, err := json.Marshal(reqBody)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal Jev request: %w", err)
	}

	if timeout <= 0 {
		timeout = defaultTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	status, body, err := p.postSystemOne(ctx, payload)
	if err == nil && (status == http.StatusTooManyRequests || status == statusJevOverloaded) {
		slog.Debug("TypesafeJevMcpToolIntentVerification: Jev rate limited or overloaded, retrying once", "status", status)
		select {
		case <-ctx.Done():
			return nil, nil, fmt.Errorf("Jev API returned status %d and timed out before retry: %w", status, ctx.Err())
		case <-time.After(retryBackoff):
		}
		status, body, err = p.postSystemOne(ctx, payload)
	}
	if err != nil {
		return nil, nil, err
	}
	if status != http.StatusOK {
		return nil, nil, fmt.Errorf("Jev API returned status %d: %s", status, errorSnippet(body))
	}

	var parsed jevSystemOneResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, nil, fmt.Errorf("failed to decode Jev response: %w", err)
	}
	return parsed.Answers, parsed.Usage, nil
}

func (p *TypesafeJevMcpToolIntentVerificationPolicy) postSystemOne(ctx context.Context, payload []byte) (int, []byte, error) {
	url := strings.TrimSuffix(p.baseURL, "/") + "/v1/systemone"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return 0, nil, fmt.Errorf("failed to create Jev HTTP request: %w", err)
	}
	httpReq.Header.Set("Authorization", "Bearer "+p.apiKey)
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := p.client.Do(httpReq)
	if err != nil {
		return 0, nil, fmt.Errorf("Jev HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxJevResponseBytes+1))
	if err != nil {
		return 0, nil, fmt.Errorf("failed to read Jev response: %w", err)
	}
	if len(body) > maxJevResponseBytes {
		// A successful answer that doesn't fit is rejected rather than decoded
		// from a truncated body. An error body only feeds a diagnostic, so it is
		// cut instead, keeping the status for the retry decision.
		if resp.StatusCode == http.StatusOK {
			return 0, nil, fmt.Errorf("Jev response exceeds %d bytes", maxJevResponseBytes)
		}
		body = body[:maxJevResponseBytes]
	}
	return resp.StatusCode, body, nil
}

// errorSnippet returns the start of a Jev error body for an error message.
func errorSnippet(body []byte) string {
	if len(body) <= maxJevErrorBodyBytes {
		return string(body)
	}
	return string(body[:maxJevErrorBodyBytes]) + "... (truncated)"
}

// decodeNoulAnswer requires the "noul" field to actually be present: a
// pointer field distinguishes "absent" from "present and 0", since a
// malformed Jev response missing this field must not silently decode as a
// confident non-violation.
func decodeNoulAnswer(raw json.RawMessage) (float64, error) {
	var a struct {
		Noul *float64 `json:"noul"`
	}
	if err := json.Unmarshal(raw, &a); err != nil {
		return 0, err
	}
	if a.Noul == nil {
		return 0, fmt.Errorf("answer missing 'noul' field")
	}
	return *a.Noul, nil
}

type scoreAnswer struct {
	Score      float64
	Confidence *float64
}

// decodeScoreAnswer mirrors decodeNoulAnswer's absent-field handling for the
// "score" field. Confidence is optional and only reported, never required.
func decodeScoreAnswer(raw json.RawMessage) (scoreAnswer, error) {
	var a struct {
		Score      *float64 `json:"score"`
		Confidence *float64 `json:"confidence"`
	}
	if err := json.Unmarshal(raw, &a); err != nil {
		return scoreAnswer{}, err
	}
	if a.Score == nil {
		return scoreAnswer{}, fmt.Errorf("answer missing 'score' field")
	}
	return scoreAnswer{Score: *a.Score, Confidence: a.Confidence}, nil
}

type choiceAnswer struct {
	Choice        string
	Probabilities map[string]float64
	Confidence    *float64
}

// decodeChoiceAnswer requires "probabilities" to be present, since the
// blocking value is computed from it; a missing distribution must not
// decode as zero probability on every blocked option.
func decodeChoiceAnswer(raw json.RawMessage) (choiceAnswer, error) {
	var a struct {
		Choice        string             `json:"choice"`
		Probabilities map[string]float64 `json:"probabilities"`
		Confidence    *float64           `json:"confidence"`
	}
	if err := json.Unmarshal(raw, &a); err != nil {
		return choiceAnswer{}, err
	}
	if a.Probabilities == nil {
		return choiceAnswer{}, fmt.Errorf("answer missing 'probabilities' field")
	}
	return choiceAnswer{Choice: a.Choice, Probabilities: a.Probabilities, Confidence: a.Confidence}, nil
}

// --- Parameter parsing ---

func requiredStringParam(params map[string]interface{}, key string) (string, error) {
	raw, ok := params[key]
	if !ok {
		return "", fmt.Errorf("'%s' parameter is required", key)
	}
	value, ok := raw.(string)
	if !ok || value == "" {
		return "", fmt.Errorf("'%s' must be a non-empty string", key)
	}
	return value, nil
}

func stringParamOrDefault(params map[string]interface{}, key, def string) string {
	if raw, ok := params[key]; ok {
		if value, ok := raw.(string); ok && value != "" {
			return value
		}
	}
	return def
}

// ruleParams are set per rule in "tools"; at the top level they would be ignored.
var ruleParams = []string{"scope", "questions", "mode", "passthroughOnError"}

func (p *TypesafeJevMcpToolIntentVerificationPolicy) parseParams(params map[string]interface{}) error {
	for _, key := range ruleParams {
		if _, ok := params[key]; ok {
			return fmt.Errorf("'%s' is set per rule in 'tools', not at the top level; for example, a rule with name \"*\" applies to every tool", key)
		}
	}

	if timeoutRaw, ok := params["timeout"]; ok {
		timeoutStr, ok := timeoutRaw.(string)
		if !ok {
			return fmt.Errorf("'timeout' must be a duration string (e.g. \"5s\")")
		}
		timeout, err := time.ParseDuration(timeoutStr)
		if err != nil {
			return fmt.Errorf("'timeout' is not a valid duration: %w", err)
		}
		if timeout <= 0 || timeout > maxTimeout {
			return fmt.Errorf("'timeout' must be greater than 0 and at most %s", maxTimeout)
		}
		p.timeout = timeout
	}

	if showAssessmentRaw, ok := params["showAssessment"]; ok {
		showAssessment, ok := showAssessmentRaw.(bool)
		if !ok {
			return fmt.Errorf("'showAssessment' must be a boolean")
		}
		p.showAssessment = showAssessment
	}

	tools, anyTool, err := parseToolRules(params["tools"])
	if err != nil {
		return err
	}
	p.tools, p.anyTool = tools, anyTool
	return nil
}

// parseQuestionList returns nil (not an error) when raw is absent or empty, so
// the caller can fall back to its default questions.
func parseQuestionList(raw interface{}) ([]guardrailQuestion, error) {
	if raw == nil {
		return nil, nil
	}
	list, ok := raw.([]interface{})
	if !ok {
		return nil, fmt.Errorf("'questions' must be an array")
	}
	if len(list) == 0 {
		return nil, nil
	}
	questions := make([]guardrailQuestion, 0, len(list))
	seenKeys := make(map[string]bool, len(list))
	for i, item := range list {
		qMap, ok := item.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("'questions[%d]' must be an object", i)
		}
		q, err := parseQuestion(qMap, i)
		if err != nil {
			return nil, err
		}
		if seenKeys[q.Key] {
			return nil, fmt.Errorf("'questions[%d].key' %q is a duplicate; question keys must be unique", i, q.Key)
		}
		seenKeys[q.Key] = true
		questions = append(questions, q)
	}
	return questions, nil
}

// parseToolRules reads the rules that choose which tools are screened and how.
// Each rule names one tool exactly, as it appears in tools/call params.name, or
// "*" for every tool without its own rule. The "*" rule is returned separately.
func parseToolRules(raw interface{}) (map[string]toolRule, *toolRule, error) {
	list, ok := raw.([]interface{})
	if raw != nil && !ok {
		return nil, nil, fmt.Errorf("'tools' must be an array")
	}
	if len(list) == 0 {
		return nil, nil, fmt.Errorf("'tools' is required: add at least one rule; a rule with name \"*\" screens every tool")
	}
	rules := make(map[string]toolRule, len(list))
	var anyTool *toolRule
	for i, item := range list {
		ruleMap, ok := item.(map[string]interface{})
		if !ok {
			return nil, nil, fmt.Errorf("'tools[%d]' must be an object", i)
		}
		name, _ := ruleMap["name"].(string)
		name = strings.TrimSpace(name)
		if name == "" {
			return nil, nil, fmt.Errorf("'tools[%d].name' is required and must be a non-empty string", i)
		}
		_, dup := rules[name]
		if dup || (name == wildcardToolName && anyTool != nil) {
			return nil, nil, fmt.Errorf("'tools[%d].name' %q is a duplicate; each tool can have only one rule", i, name)
		}
		scope, _ := ruleMap["scope"].(string)
		rule := toolRule{scope: strings.TrimSpace(scope)}
		if rule.scope == "" {
			// The default questions judge each call against the scope, so it can't be left out.
			return nil, nil, fmt.Errorf("'tools[%d].scope' is required: describe, in plain words, what the agent is meant to do with this tool, or with this MCP server for \"*\"", i)
		}
		if err := rule.parseSettings(ruleMap); err != nil {
			return nil, nil, fmt.Errorf("'tools[%d]': %w", i, err)
		}
		if name == wildcardToolName {
			anyTool = &rule
			continue
		}
		rules[name] = rule
	}
	return rules, anyTool, nil
}

// parseSettings reads a rule's questions, mode and passthroughOnError. Omitted or
// empty questions mean the default questions.
func (r *toolRule) parseSettings(ruleMap map[string]interface{}) error {
	r.mode = modeEnforce
	if modeRaw, ok := ruleMap["mode"]; ok {
		mode, ok := modeRaw.(string)
		if !ok || (mode != modeEnforce && mode != modeMonitor) {
			return fmt.Errorf("'mode' must be '%s' or '%s'", modeEnforce, modeMonitor)
		}
		r.mode = mode
	}

	if passthroughRaw, ok := ruleMap["passthroughOnError"]; ok {
		passthrough, ok := passthroughRaw.(bool)
		if !ok {
			return fmt.Errorf("'passthroughOnError' must be a boolean")
		}
		r.passthroughOnError = passthrough
	}

	questions, err := parseQuestionList(ruleMap["questions"])
	if err != nil {
		return err
	}
	if questions == nil {
		questions = defaultQuestions()
	}
	r.questions = questions
	return nil
}

func parseQuestion(qMap map[string]interface{}, index int) (guardrailQuestion, error) {
	var q guardrailQuestion

	key, ok := qMap["key"].(string)
	if !ok || key == "" {
		return q, fmt.Errorf("'questions[%d].key' is required and must be a non-empty string", index)
	}
	q.Key = key

	qType, ok := qMap["type"].(string)
	if !ok || (qType != questionTypeNoul && qType != questionTypeScore && qType != questionTypeChoice) {
		return q, fmt.Errorf("'questions[%d].type' is required and must be 'noul', 'score', or 'choice'", index)
	}
	q.Type = qType

	instructions, ok := qMap["instructions"].(string)
	if !ok || instructions == "" {
		return q, fmt.Errorf("'questions[%d].instructions' is required and must be a non-empty string", index)
	}
	q.Instructions = instructions

	threshold, err := extractFloat(qMap["threshold"])
	if err != nil {
		return q, fmt.Errorf("'questions[%d].threshold' must be a number: %w", index, err)
	}
	q.Threshold = threshold

	if raw, ok := qMap["confidenceThreshold"]; ok {
		// Noul answers carry no confidence, and Choice already blocks on the
		// combined probability of its blockOn options.
		if qType != questionTypeScore {
			return q, fmt.Errorf("'questions[%d].confidenceThreshold' only applies to type 'score'", index)
		}
		confidenceThreshold, err := extractFloat(raw)
		if err != nil {
			return q, fmt.Errorf("'questions[%d].confidenceThreshold' must be a number: %w", index, err)
		}
		if confidenceThreshold < 0 || confidenceThreshold > 1 {
			return q, fmt.Errorf("'questions[%d].confidenceThreshold' must be between 0 and 1", index)
		}
		q.ConfidenceThreshold = confidenceThreshold
	}

	// A threshold outside the range an answer can take would silently never block,
	// or always block, so it is rejected here.
	switch qType {
	case questionTypeNoul:
		if threshold <= 0 || threshold > 1 {
			return q, fmt.Errorf("'questions[%d].threshold' for type 'noul' must be a probability in (0, 1]", index)
		}
	case questionTypeScore:
		criteria, err := parseStringList(qMap["criteria"], fmt.Sprintf("questions[%d].criteria", index))
		if err != nil {
			return q, err
		}
		if len(criteria) < 2 || len(criteria) > maxScoreLevels {
			return q, fmt.Errorf("'questions[%d].criteria' is required for type 'score' and must have 2 to %d entries", index, maxScoreLevels)
		}
		// Score positions run from 0 (the first criteria entry) to len(criteria)-1.
		if maxScore := float64(len(criteria) - 1); threshold <= 0 || threshold > maxScore {
			return q, fmt.Errorf("'questions[%d].threshold' for type 'score' must be greater than 0 and at most %v, the last scale position", index, maxScore)
		}
		q.Criteria = criteria
	case questionTypeChoice:
		criteria, err := parseStringList(qMap["criteria"], fmt.Sprintf("questions[%d].criteria", index))
		if err != nil {
			return q, err
		}
		if len(criteria) < 2 || len(criteria) > maxChoiceOption {
			return q, fmt.Errorf("'questions[%d].criteria' is required for type 'choice' and must have 2 to %d entries", index, maxChoiceOption)
		}
		options := make(map[string]bool, len(criteria))
		for _, option := range criteria {
			if options[option] {
				return q, fmt.Errorf("'questions[%d].criteria' has duplicate option %q", index, option)
			}
			options[option] = true
		}
		blockOn, err := parseStringList(qMap["blockOn"], fmt.Sprintf("questions[%d].blockOn", index))
		if err != nil {
			return q, err
		}
		if len(blockOn) == 0 {
			return q, fmt.Errorf("'questions[%d].blockOn' is required for type 'choice' and must name at least one option", index)
		}
		for _, option := range blockOn {
			if !options[option] {
				return q, fmt.Errorf("'questions[%d].blockOn' option %q is not in criteria", index, option)
			}
		}
		if threshold <= 0 || threshold > 1 {
			return q, fmt.Errorf("'questions[%d].threshold' for type 'choice' must be a probability in (0, 1]", index)
		}
		q.Criteria = criteria
		q.BlockOn = blockOn
	}

	return q, nil
}

// parseStringList returns nil (not an error) when raw is absent, so callers
// can apply their own "required" check with a type-specific message.
func parseStringList(raw interface{}, field string) ([]string, error) {
	if raw == nil {
		return nil, nil
	}
	list, ok := raw.([]interface{})
	if !ok {
		return nil, fmt.Errorf("'%s' must be an array of strings", field)
	}
	result := make([]string, 0, len(list))
	for _, item := range list {
		s, ok := item.(string)
		if !ok {
			return nil, fmt.Errorf("'%s' entries must be strings", field)
		}
		result = append(result, s)
	}
	return result, nil
}

func extractFloat(value interface{}) (float64, error) {
	switch v := value.(type) {
	case float64:
		return v, nil
	case int:
		return float64(v), nil
	case nil:
		return 0, fmt.Errorf("value is required")
	default:
		return 0, fmt.Errorf("cannot convert %T to number", value)
	}
}
