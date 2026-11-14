/*
 * Copyright (c) 2025, WSO2 LLC. (https://www.wso2.com).
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

package subscriptiontoolratelimit

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

// This file is copied into each MCP policy that reads the resolver's facts; every copy is
// identical apart from the package clause. Fix a bug in all of them, and add a fact to all of
// them, or the copies become four subtly different files.

// MCP 2026-07-28 mirrored headers, and the attributes the gateway's MCP resolver publishes.
const (
	headerProtocolVersion = "MCP-Protocol-Version"
	headerMcpMethod       = "Mcp-Method"
	headerMcpName         = "Mcp-Name"

	attrBodyMethod         = "mcp.body.method"
	attrBodyCapabilityName = "mcp.body.capability.name"
	attrBodyJSONRPCID      = "mcp.body.jsonrpc.id"
	attrBodyUnusable       = "mcp.body.unusable"
	attrBodyPresent        = "mcp.body.present" // set whenever a body arrived, readable or not

	// First revision that mirrors values into headers. Versions are dates, so string
	// comparison is chronological.
	specVersionModern = "2026-07-28"

	sentinelPrefix = "=?base64?"
	sentinelSuffix = "?="

	// Set to true by the engine when a resolver read the request body. The engine declares the
	// same key; an older engine never sets it, which reads the same as no resolver.
	metadataBodyResolved = "bodyResolved"
)

var errMalformedSentinel = errors.New("malformed base64 sentinel value")

// methodsMirroringName are the methods a modern request must also mirror into Mcp-Name.
var methodsMirroringName = map[string]bool{
	"tools/call":     true,
	"resources/read": true,
	"prompts/get":    true,
}

// mcpRequestFacts describes the MCP operation a request invokes, read from its era's one
// source: the mirrored headers on a modern request, the resolver's body facts on a legacy one.
type mcpRequestFacts struct {
	// The raw JSON token, quotes included for a string id, so an error echoes it back exactly.
	// Legacy only: empty on a modern request, whose id sits in a body this never reads, so an
	// error there renders null.
	RequestID json.RawMessage

	Method string
	Name   string

	IsModernRequest bool // declared 2026-07-28 or later, so Method and Name come from headers

	// A body reached the resolver. Legacy only: always false on a modern request, so test it
	// inside a legacy branch.
	IsRequestBodyPresent bool
}

// HasMethod reports whether the era's own source named a method. False does not mean unknown:
// a JSON-RPC response posted by the client legitimately has none.
func (f mcpRequestFacts) HasMethod() bool { return f.Method != "" }

// MissingRequiredName reports a method that must mirror a capability name with no name, absent
// or undecodable. Call it on the modern path only: a legacy body naming none is left to the server.
func (f mcpRequestFacts) MissingRequiredName() bool {
	return methodsMirroringName[f.Method] && f.Name == ""
}

// mcpFacts resolves MCP request facts from the source defined by the request era:
// mirrored headers for modern requests, and resolver-provided body attributes for legacy requests.
func mcpFacts(headers *policy.Headers, shared *policy.SharedContext) mcpRequestFacts {
	attrs := resolutionAttributes(shared)

	facts := mcpRequestFacts{IsModernRequest: isModernRequest(headers)}
	if facts.IsModernRequest {
		facts.Method, facts.Name = mirroredOperation(headers)
	} else {
		facts.Method, facts.Name = resolvedOperation(attrs)
		facts.RequestID = jsonRPCID(attrs)
		facts.IsRequestBodyPresent = attrs.Get(attrBodyPresent) == "true"
	}
	return facts
}

// mirroredOperation reads a modern request's headers. An Mcp-Name that will not decode yields
// no name, exactly as an absent one does.
func mirroredOperation(headers *policy.Headers) (method, name string) {
	method = firstHeader(headers, headerMcpMethod)
	if raw := firstHeader(headers, headerMcpName); raw != "" {
		if decoded, err := decodeSentinel(raw); err == nil {
			name = decoded
		}
	}
	return method, name
}

// resolvedOperation reads what the resolver found in a legacy request's body.
func resolvedOperation(attrs policy.ResolutionAttributes) (method, name string) {
	return attrs.Get(attrBodyMethod), attrs.Get(attrBodyCapabilityName)
}

// jsonRPCID returns the id to echo in an error; an invalid token would break the envelope.
func jsonRPCID(attrs policy.ResolutionAttributes) json.RawMessage {
	raw := attrs.Get(attrBodyJSONRPCID)
	if !json.Valid([]byte(raw)) {
		return nil
	}
	return json.RawMessage(raw)
}

// resolutionAttributes never returns nil: the zero value answers "" for every key, which is
// what a defensive path wants from an absent SharedContext.
func resolutionAttributes(shared *policy.SharedContext) policy.ResolutionAttributes {
	if shared == nil {
		return policy.ResolutionAttributes{}
	}
	return shared.ResolutionAttributes
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

// unusableBodyReason returns why the resolver could not read the body, or "" if it could. Read
// on the legacy path only: a modern request decides on its headers and never consults it.
func unusableBodyReason(shared *policy.SharedContext) string {
	return resolutionAttributes(shared).Get(attrBodyUnusable)
}

// isModernRequest reports whether the version header declares 2026-07-28 or later; an absent
// header is legacy. Compared as a string, so an unrecognised value sorting above the constant,
// such as "draft", also reads as modern. mcp-spec-validation rejects those where it is attached.
func isModernRequest(headers *policy.Headers) bool {
	return firstHeader(headers, headerProtocolVersion) >= specVersionModern
}

func firstHeader(headers *policy.Headers, name string) string {
	values := headers.Get(name)
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

// decodeSentinel unwraps MCP's "=?base64?...?=" header encoding; other values are returned
// unchanged.
func decodeSentinel(value string) (string, error) {
	if !strings.HasPrefix(value, sentinelPrefix) || !strings.HasSuffix(value, sentinelSuffix) {
		return value, nil
	}
	// "=?base64?=" matches both markers but has no payload.
	if len(value) < len(sentinelPrefix)+len(sentinelSuffix) {
		return "", errMalformedSentinel
	}
	raw, err := base64.StdEncoding.DecodeString(value[len(sentinelPrefix) : len(value)-len(sentinelSuffix)])
	if err != nil {
		return "", errMalformedSentinel
	}
	return string(raw), nil
}
