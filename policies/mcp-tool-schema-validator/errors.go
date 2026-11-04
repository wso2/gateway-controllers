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

package mcptoolschemavalidator

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"strconv"
	"strings"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

// JSON-RPC error codes this policy returns.
const (
	// codeInvalidRequest is a body naming a member the policy reads more than once, or nested
	// too deeply to be read at all. Matches mcp-spec-validation.
	codeInvalidRequest = -32600

	// codeInvalidParams is tool arguments that fail the tool's input schema.
	codeInvalidParams = -32602

	// codeInvalidToolResult is a tool result that fails the tool's output schema. -32020 is taken
	// by the MCP header-mismatch error; -32021 is the next free code in the server-error range.
	codeInvalidToolResult = -32021
)

const (
	messageArgumentsInvalid = "Tool arguments failed schema validation"
	messageResultInvalid    = "Tool result failed schema validation"
	messageAmbiguous        = "Request body names a member more than once"
	messageTooDeep          = "Request body is nested too deeply"
)

// errorData is the data member of a validation error: which tool and direction, why when it was
// not a plain schema mismatch, and the individual failures when showAssessment is on.
type errorData struct {
	Tool      string            `json:"tool"`
	Direction string            `json:"direction"`
	Reason    string            `json:"reason,omitempty"`
	Errors    []assessmentError `json:"errors,omitempty"`
}

// errorEnvelope renders a JSON-RPC error message. rawID is the id exactly as the request carried
// it, so a string id stays a string and a large number keeps every digit; "" renders null.
func errorEnvelope(rawID string, code int, message string, data *errorData) []byte {
	errObj := map[string]any{"code": code, "message": message}
	if data != nil {
		errObj["data"] = data
	}
	body, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      jsonRPCID(rawID),
		"error":   errObj,
	})
	if err != nil {
		// Unreachable for these types, but a failure must still produce a well-formed error.
		slog.Debug("MCP Tool Schema Validator: failed to marshal error response", "error", err)
		body = fmt.Appendf(nil, `{"jsonrpc":"2.0","id":null,"error":{"code":%d,"message":"Unexpected error"}}`, code)
	}
	return body
}

// requestError is the immediate response to a refused request. Framed as an SSE event only when
// the caller cannot read JSON, as mcp-spec-validation frames its own errors. description is the
// internal reason, carried on the fault and never sent to the client.
func requestError(headers *policy.Headers, rawID string, code int, message string, data *errorData, meta map[string]any, description string) policy.ImmediateResponse {
	body := errorEnvelope(rawID, code, message, data)
	contentType := "application/json"
	if acceptsOnlyEventStream(headers) {
		body = sseFrame(body)
		contentType = "text/event-stream"
	}
	if meta == nil {
		meta = map[string]any{}
	}
	// Same key the other MCP policies use, so rejections are countable together.
	meta["mcpErrorCode"] = code
	return policy.ImmediateResponse{
		StatusCode:        400,
		Headers:           map[string]string{"Content-Type": contentType},
		Body:              body,
		AnalyticsMetadata: meta,
		IsFault:           true,
		Fault: &policy.FaultDetails{
			Code:        policy.FaultCodeInvalidRequestBody,
			Type:        policy.FaultTypeValidation,
			Direction:   policy.DirectionRequest,
			Message:     message,
			Description: description,
			JSONRPC:     &policy.JSONRPCError{Code: &code, ID: jsonRPCID(rawID)},
		},
	}
}

// faultDescription is the internal reason a fault carries: the tool, what failed, why, and how
// many failures validation found. It names no payload values.
func faultDescription(tool, what, reason string, errorCount int) string {
	return fmt.Sprintf("tool %s %s failed validation: %s (%d errors)", tool, what, reason, errorCount)
}

// sseFrame wraps one JSON-RPC message as a single SSE event.
func sseFrame(message []byte) []byte {
	return []byte("event: message\ndata: " + string(message) + "\n\n")
}

// jsonRPCID echoes an id verbatim. A mangled value must not produce a malformed body, so anything
// that is not a JSON string, number or null becomes null.
func jsonRPCID(raw string) any {
	raw = strings.TrimSpace(raw)
	if raw == "" || !json.Valid([]byte(raw)) {
		return nil
	}
	switch raw[0] {
	case '{', '[', 't', 'f':
		return nil
	}
	return json.RawMessage(raw)
}

// acceptsOnlyEventStream reports whether SSE is the single format the caller can read. Copied
// from mcp-spec-validation so both policies pick the same framing for the same request.
func acceptsOnlyEventStream(headers *policy.Headers) bool {
	if headers == nil {
		return false
	}
	return !acceptable(headers, "application/json") && acceptable(headers, "text/event-stream")
}

// acceptable reports whether Accept permits a media type, ranking ranges by specificity as
// RFC 9110 does, so "application/json;q=0, */*" makes JSON unacceptable.
func acceptable(headers *policy.Headers, mediaType string) bool {
	kind, _, _ := strings.Cut(mediaType, "/")
	ranks := map[string]int{mediaType: 3, kind + "/*": 2, "*/*": 1}

	best, quality := 0, 0.0
	for _, value := range headers.Get("accept") {
		for _, entry := range strings.Split(value, ",") {
			name, params, _ := strings.Cut(strings.TrimSpace(entry), ";")
			rank, matches := ranks[strings.ToLower(strings.TrimSpace(name))]
			if !matches || rank < best {
				continue
			}
			best, quality = rank, entryQuality(params)
		}
	}
	return quality > 0
}

// entryQuality returns an Accept entry's q value, defaulting to 1.
func entryQuality(params string) float64 {
	for _, param := range strings.Split(params, ";") {
		name, value, found := strings.Cut(strings.TrimSpace(param), "=")
		if !found || !strings.EqualFold(strings.TrimSpace(name), "q") {
			continue
		}
		if quality, err := strconv.ParseFloat(strings.TrimSpace(value), 64); err == nil {
			return quality
		}
	}
	return 1
}
