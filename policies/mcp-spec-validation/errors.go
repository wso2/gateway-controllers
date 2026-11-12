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

package mcpspecvalidation

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

// JSON-RPC error codes this policy returns. -32020 is from the block MCP 2026-07-28 reserves,
// so it must not be reused.
const (
	// codeParseError is a body whose JSON does not parse — in practice, truncation.
	codeParseError = -32700

	// codeInvalidRequest is a body that parses but is not a usable JSON-RPC request: a
	// batch, a bare scalar, a member of the wrong type, or a member named twice.
	codeInvalidRequest = -32600

	// codeHeaderMismatch covers every header failure this policy returns: a required mirrored
	// header missing, a value outside the permitted charset, a malformed sentinel, a value that
	// disagrees with the body, and an MCP-Protocol-Version that is not a dated revision.
	codeHeaderMismatch = -32020
)

// errorResponse renders a JSON-RPC error as the immediate response to a rejected request. The
// envelope matches the other MCP policies' own copies, so the gateway answers in one shape. data
// is attached only when non-nil; no current error carries any. faultCode names what could not be
// used — the body or a header — and reaches only the fault, never the client.
func errorResponse(
	headers *policy.Headers,
	jsonRPCCode int,
	message string,
	requestID string,
	data map[string]any,
	faultCode string,
) policy.ImmediateResponse {
	errObj := map[string]any{
		"code":    jsonRPCCode,
		"message": message,
	}
	if data != nil {
		errObj["data"] = data
	}

	body, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      jsonRPCID(requestID),
		"error":   errObj,
	})
	if err != nil {
		// Unreachable for these types, but a marshalling failure must still produce a
		// well-formed JSON-RPC error rather than an empty body.
		slog.Debug("MCP Spec Validation Policy: failed to marshal error response", "error", err)
		body = fmt.Appendf(nil,
			`{"jsonrpc":"2.0","id":null,"error":{"code":%d,"message":"Unexpected error"}}`,
			jsonRPCCode)
	}

	contentType := "application/json"
	if acceptsOnlyEventStream(headers) {
		// The caller cannot read a JSON document, so the error has to arrive as a frame.
		body = []byte("event: message\ndata: " + string(body) + "\n\n")
		contentType = "text/event-stream"
	}

	return policy.ImmediateResponse{
		StatusCode: http.StatusBadRequest,
		Headers:    map[string]string{"Content-Type": contentType},
		Body:       body,
		// Surfaces the rejection in analytics under the same key the other MCP policies
		// use, so validation failures are countable alongside authz and ACL rejections.
		AnalyticsMetadata: map[string]any{"mcpErrorCode": jsonRPCCode},
		IsFault:           true,
		Fault: &policy.FaultDetails{
			Code:      faultCode,
			Type:      policy.FaultTypeValidation,
			Direction: policy.DirectionRequest,
			Message:   message,
			JSONRPC:   &policy.JSONRPCError{Code: &jsonRPCCode, ID: jsonRPCID(requestID)},
		},
	}
}

// jsonRPCID renders the id for the error envelope.
//
// The resolver publishes it as the JSON token it arrived as — 7 for a number, "7" with its
// quotes for a string — so it is echoed back verbatim rather than re-parsed. Re-parsing is
// what used to answer `"id":"7"` with `"id":7`, which a client matching on the value cannot
// correlate. An id we never saw becomes null, which the spec permits for an uncorrelatable
// error. The validity check is defensive: a mangled attribute must not produce a malformed body.
func jsonRPCID(raw string) any {
	if !json.Valid([]byte(raw)) {
		return nil
	}
	return json.RawMessage(raw)
}

// acceptsOnlyEventStream reports whether SSE is the single format the caller can read.
//
// The spec makes a client list both application/json and text/event-stream, so Accept states what
// it can parse, not what it wants; the server picks. JSON is the pick here: an immediate error is
// one terminal message, and SSE frames a stream there is none of.
func acceptsOnlyEventStream(headers *policy.Headers) bool {
	if headers == nil {
		return false
	}
	return acceptable(headers, "application/json") == false && acceptable(headers, "text/event-stream")
}

// acceptable reports whether Accept permits a media type. RFC 9110 ranks matching ranges by
// specificity, so "application/json;q=0, */*" makes JSON unacceptable: the exact type wins over
// the wildcard, whatever order they appear in.
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

// entryQuality returns an Accept entry's q value, defaulting to 1. RFC 9110 defines q=0 as
// "not acceptable" rather than a low preference.
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
