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

// Package mcpspecvalidation validates MCP requests: the body on every request, and the mirrored
// headers on a request declaring MCP 2026-07-28 or later.
//
// Mirroring lets an intermediary enforce policy without parsing the payload, which is safe only
// while header and body agree: a caller could otherwise satisfy an ACL with the header while the
// body invokes something else. The spec makes the server check that; this policy checks it at
// the edge.
//
// On a gateway with no MCP resolver it reads the body itself and checks only that it is
// readable. It rejects a malformed MCP-Protocol-Version but accepts every dated revision, since
// which ones a proxy serves is a separate concern, and it takes no configuration.
package mcpspecvalidation

import (
	"context"
	"log/slog"
	"net/http"
	"strings"
	"time"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

// metadataBodyResolved is set to true by the engine when a resolver read the request body.
// The engine declares the same key; an older engine never sets it, which reads the same as no
// resolver.
const metadataBodyResolved = "bodyResolved"

// Request headers defined by the 2026-07-28 streamable-HTTP transport.
const (
	headerProtocolVersion = "MCP-Protocol-Version"
	headerMcpMethod       = "Mcp-Method"
	headerMcpName         = "Mcp-Name"
)

// Resolution attributes published by the engine's MCP resolver. The mcp.body. prefix keeps a
// header value distinguishable from a body value at the call sites holding both.
const (
	attrBodyMethod          = "mcp.body.method"
	attrBodyCapabilityName  = "mcp.body.capability.name"
	attrBodyTaskID          = "mcp.body.task.id"
	attrBodyProtocolVersion = "mcp.body.protocol.version"
	attrBodyJSONRPCID       = "mcp.body.jsonrpc.id"
	attrBodyUnusable        = "mcp.body.unusable"
)

// specVersionLayout is the shape of every MCP revision identifier: a date. Parsed rather than
// pattern-matched, so an impossible one like 2026-99-99 cannot pass and then sort as modern.
const specVersionLayout = "2006-01-02"

// specVersionModern is the first revision that mirrors values into headers. Dates compare
// chronologically as strings. This classifies an era; which revisions a proxy serves is a
// separate concern.
const specVersionModern = "2026-07-28"

// Reasons the resolver publishes under attrBodyUnusable, instead of the body facts and never
// alongside them: a reason present means there is nothing to compare against.
const (
	reasonSyntaxError       = "syntax-error"
	reasonInvalidMemberType = "invalid-member-type"
	reasonNotAnObject       = "not-an-object"
	reasonAmbiguous         = "ambiguous"
)

// methodsRequiringName are the operations that must send Mcp-Name; every other method
// addresses no particular capability.
var methodsRequiringName = map[string]bool{
	"tools/call":     true,
	"resources/read": true,
	"prompts/get":    true,
	// The Tasks extension (SEP-2663) requires Mcp-Name, set to params.taskId.
	"tasks/get":    true,
	"tasks/update": true,
	"tasks/cancel": true,
}

// taskMethods carry the task they address in params.taskId rather than in a capability name,
// so Mcp-Name is compared against mcp.body.task.id for them. The Tasks extension has the client
// mirror the task id, and an intermediary routes on it to reach the server instance holding the
// task, so a header naming a different task than the body is the same class of contradiction as
// a mismatched capability name.
var taskMethods = map[string]bool{
	"tasks/get":    true,
	"tasks/update": true,
	"tasks/cancel": true,
}

// McpSpecValidationPolicy holds no state: it takes no parameters, and one instance is shared
// across concurrent requests.
type McpSpecValidationPolicy struct{}

// GetPolicy is the v1alpha2 factory entry point (loaded by v1alpha2 kernels).
func GetPolicy(_ policy.PolicyMetadata, _ map[string]interface{}) (policy.Policy, error) {
	return &McpSpecValidationPolicy{}, nil
}

// Mode asks for both request phases: whether the route has the resolver is known only per request.
func (p *McpSpecValidationPolicy) Mode() policy.ProcessingMode {
	return policy.ProcessingMode{
		RequestHeaderMode:  policy.HeaderModeProcess,
		RequestBodyMode:    policy.BodyModeBuffer,
		ResponseHeaderMode: policy.HeaderModeSkip,
		ResponseBodyMode:   policy.BodyModeSkip,
	}
}

// OnRequestHeaders validates a request on a route with the MCP resolver. Steps 1-2 apply to
// every MCP request; step 3 picks the era, and steps 4-7 run only for a modern one.
func (p *McpSpecValidationPolicy) OnRequestHeaders(
	_ context.Context,
	reqCtx *policy.RequestHeaderContext,
	_ map[string]interface{},
) policy.RequestHeaderAction {
	// Only the multiplexed POST endpoint carries a JSON-RPC body and mirrored headers.
	if !strings.EqualFold(reqCtx.Method, http.MethodPost) || shouldParseBody(reqCtx.SharedContext) {
		return nil
	}

	reject := func(code int, message string) policy.RequestHeaderAction {
		slog.Debug("MCP Spec Validation Policy: rejecting request", "code", code, "reason", message)
		return errorResponse(reqCtx.Headers, code, message, p.requestID(reqCtx), nil,
			policy.FaultCodeInvalidRequestBody)
	}
	// Every header failure answers with codeHeaderMismatch; its fault names the header.
	rejectHeader := func(message string) policy.RequestHeaderAction {
		slog.Debug("MCP Spec Validation Policy: rejecting request", "code", codeHeaderMismatch, "reason", message)
		return errorResponse(reqCtx.Headers, codeHeaderMismatch, message, p.requestID(reqCtx), nil,
			policy.FaultCodeInvalidRequestHeader)
	}

	// ─── 1. Format of the version header, on the raw value ──────────────────
	//
	// Checked before anything reads it, and in both eras, because the policy acts on it: it
	// picks the branch at step 3 and is compared against the body at step 7.
	rawVersion := firstHeader(reqCtx.Headers, headerProtocolVersion)
	if rawVersion != "" && !isValidFieldValue(rawVersion) {
		return rejectHeader(headerProtocolVersion + " contains characters not permitted in an HTTP field value")
	}

	// A revision is a date. Step 3 compares this value as a string, where "draft" sorts above
	// 2026-07-28 and would be read as modern. Any well-formed date passes: which revisions a
	// proxy accepts is a separate policy's concern.
	if rawVersion != "" && !isSpecVersion(rawVersion) {
		return rejectHeader(headerProtocolVersion + " is not a valid protocol version, expected YYYY-MM-DD")
	}

	// ─── 2. Could the body be read? ─────────────────────────────────────────
	//
	// Both eras. A reason means the gateway and the backend may read these bytes differently.
	// An empty body, or one naming no operation, was read fine and carries no reason.
	if reason := reqCtx.ResolutionAttributes.Get(attrBodyUnusable); reason != "" {
		code, message := unusableBodyError(reason)
		return reject(code, message)
	}

	// ─── 3. Which era is this request? ──────────────────────────────────────
	//
	// The era is the header's value, not its presence: 2025-06-18 sends the header and mirrors
	// nothing, so branching on presence would reject every legacy request.
	if rawVersion == "" || rawVersion < specVersionModern {
		return nil
	}

	// ─── 4. Format of the mirrored headers ──────────────────────────────────
	//
	// Only a modern request defines them. Checked whenever present, required or not: the spec
	// scopes the missing-header failure to required headers, the charset one to all of them.
	for _, name := range []string{headerMcpMethod, headerMcpName} {
		if raw := firstHeader(reqCtx.Headers, name); raw != "" && !isValidFieldValue(raw) {
			return rejectHeader(name + " contains characters not permitted in an HTTP field value")
		}
	}

	// ─── 5. Presence ────────────────────────────────────────────────────────
	//
	// Which headers must be sent. Whether a sent one tells the truth is step 7: Mcp-Name is
	// optional on most methods, but any value present is still compared.
	method := firstHeader(reqCtx.Headers, headerMcpMethod)
	if method == "" {
		return rejectHeader(headerMcpMethod + " header is required")
	}
	name := firstHeader(reqCtx.Headers, headerMcpName)
	if methodsRequiringName[method] && name == "" {
		return rejectHeader(headerMcpName + " header is required for " + method)
	}

	// ─── 6. Decode the sentinel ─────────────────────────────────────────────
	decodedName, err := decodeSentinel(name)
	if err != nil {
		return rejectHeader(headerMcpName + " is not a valid base64 sentinel value")
	}

	// ─── 7. Is the body what the headers claim? ─────────────────────────────
	//
	// An absent body value fails like a differing one, since a modern client MUST mirror; only
	// the message separates them. Version first, so a header claiming modern over a body that
	// does not is reported as that.
	if bodyVersion := reqCtx.ResolutionAttributes.Get(attrBodyProtocolVersion); bodyVersion != rawVersion {
		return rejectHeader(mirrorFailure(headerProtocolVersion, "protocol version", bodyVersion))
	}

	if bodyMethod := reqCtx.ResolutionAttributes.Get(attrBodyMethod); bodyMethod != method {
		return rejectHeader(mirrorFailure(headerMcpMethod, "method", bodyMethod))
	}

	// On the raw header: a degenerate "=?base64??=" decodes to "" and would skip the
	// comparison for a header the client did send.
	if name != "" {
		// A task method mirrors params.taskId, every other method the capability name.
		subject, bodyKey := "capability name", attrBodyCapabilityName
		if taskMethods[method] {
			subject, bodyKey = "task id", attrBodyTaskID
		}

		// An engine whose resolver predates mcp.body.task.id publishes none, and a task
		// method is the one case where absence is not the client's doing. Requiring the
		// header still holds there; only the comparison waits for a body value to check.
		bodyValue := reqCtx.ResolutionAttributes.Get(bodyKey)
		if bodyValue == "" && taskMethods[method] {
			return nil
		}
		if bodyValue != decodedName {
			return rejectHeader(mirrorFailure(headerMcpName, subject, bodyValue))
		}
	}

	// Mcp-Param-* is never validated: "recognised" is defined by the tool's own inputSchema,
	// which the gateway never sees, so the spec has intermediaries forward them untouched.
	return nil
}

// OnRequestBody validates a request on a route without the MCP resolver. Such a gateway serves
// legacy proxies only, so only body readability is checked.
func (p *McpSpecValidationPolicy) OnRequestBody(
	_ context.Context,
	reqCtx *policy.RequestContext,
	_ map[string]interface{},
) policy.RequestAction {
	if !strings.EqualFold(reqCtx.Method, http.MethodPost) || !shouldParseBody(reqCtx.SharedContext) {
		return nil
	}
	var body []byte
	if reqCtx.Body != nil {
		body = reqCtx.Body.Content
	}
	reason := unusableBodyReason(body)
	if reason == "" {
		return nil
	}
	code, message := unusableBodyError(reason)
	slog.Debug("MCP Spec Validation Policy: rejecting request", "code", code, "reason", message)
	// No id, matching the resolver, which publishes none for an unreadable body.
	return errorResponse(reqCtx.Headers, code, message, "", nil, policy.FaultCodeInvalidRequestBody)
}

// shouldParseBody reports whether this policy has to read the request body itself. It does
// unless a resolver read it first, which the engine marks in Metadata; the facts from that
// single parse then reach every policy on the chain through SharedContext.
//
// A missing or non-true marker means parse: that is what an older engine, which never sets it,
// produces. The API kind is still checked, so an MCP policy on a route another protocol's
// resolver bound falls back to parsing rather than reading attributes that are not there.
func shouldParseBody(shared *policy.SharedContext) bool {
	if shared == nil || shared.APIKind != policy.APIKindMCP {
		return true
	}
	resolved, _ := shared.Metadata[metadataBodyResolved].(bool)
	return !resolved
}

// isSpecVersion reports whether the value is a calendar date, the shape of every MCP revision.
func isSpecVersion(value string) bool {
	parsed, err := time.Parse(specVersionLayout, value)
	// Parse normalises out-of-range fields, so compare the round trip to reject 2026-99-99.
	return err == nil && parsed.Format(specVersionLayout) == value
}

// unusableBodyError maps a resolver reason onto the JSON-RPC error the client should see.
// Broken syntax is a parse error, everything else an invalid request, as the released MCP
// policies already answered.
func unusableBodyError(reason string) (int, string) {
	switch reason {
	case reasonSyntaxError:
		return codeParseError, "Request body is not valid JSON"
	case reasonInvalidMemberType:
		return codeInvalidRequest, "Request body has a member of the wrong type"
	case reasonNotAnObject:
		// A JSON-RPC batch names several operations and therefore identifies none, so the
		// gateway cannot say which one its policies would be governing.
		return codeInvalidRequest, "Request body is not a single JSON-RPC request object"
	case reasonAmbiguous:
		// The dangerous one: valid JSON that the backend may resolve differently than the
		// gateway did. Unlike the others it may not be rejected upstream at all.
		return codeInvalidRequest, "Request body names a member more than once"
	default:
		// An unrecognised reason means the resolver reports something this build does not
		// know about. It still means the body could not be read, so refuse rather than
		// forward a request no policy can safely govern.
		return codeInvalidRequest, "Request body could not be read"
	}
}

// requestID returns the JSON-RPC id to correlate an error with, or "" when the body was never
// read or carried none — a notification legitimately has none, and the envelope renders null.
func (p *McpSpecValidationPolicy) requestID(reqCtx *policy.RequestHeaderContext) string {
	return reqCtx.ResolutionAttributes.Get(attrBodyJSONRPCID)
}

// mirrorFailure renders the two ways a mirrored header fails against the body. Both are -32020;
// only the message differs, since "does not match" is the wrong hunt when there is no value.
func mirrorFailure(header, subject, bodyValue string) string {
	if bodyValue == "" {
		return header + " is set but the request body carries no " + subject
	}
	return header + " does not match the " + subject + " in the request body"
}

// firstHeader returns a header's first value, or "" when absent.
func firstHeader(headers *policy.Headers, name string) string {
	values := headers.Get(name)
	if len(values) == 0 {
		return ""
	}
	return values[0]
}
