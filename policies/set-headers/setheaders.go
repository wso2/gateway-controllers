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

package setheaders

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

// Mode values controlling how configured headers are applied.
const (
	// ModeSet overwrites any existing header with the configured value.
	ModeSet = "set"
	// ModeAppend appends the configured value, preserving any existing values.
	ModeAppend = "append"

	// RequestPhaseHeader applies request headers during the header phase.
	RequestPhaseHeader = "header"
	// RequestPhaseBody applies request headers after body-derived routing metadata is available.
	RequestPhaseBody = "body"
)

// exprRe matches ${req.header.<name>}, ${resp.header.<name>}, ${meta.<key>}
var exprRe = regexp.MustCompile(`\$\{(req\.header|resp\.header|meta)\.([^}]+)\}`)

// respHeaderRe matches any ${resp.header.*} expression (used for config-time validation).
var respHeaderRe = regexp.MustCompile(`\$\{resp\.header\.[^}]+\}`)

// HeaderEntry represents a single header to be set or appended
type HeaderEntry struct {
	Name         string
	Value        string
	RemoveSource bool
}

// SetHeadersPolicy implements header setting/appending for both request and response.
type SetHeadersPolicy struct {
	requestBodyPhase bool
}

// GetPolicy is the v1alpha2 factory entry point (loaded by v1alpha2 kernels).
func GetPolicy(
	metadata policy.PolicyMetadata,
	params map[string]interface{},
) (policy.Policy, error) {
	return &SetHeadersPolicy{requestBodyPhase: requestPhaseFromParams(params) == RequestPhaseBody}, nil
}

func (p *SetHeadersPolicy) Mode() policy.ProcessingMode {
	requestBodyMode := policy.BodyModeSkip
	if p.requestBodyPhase {
		requestBodyMode = policy.BodyModeBuffer
	}
	return policy.ProcessingMode{
		RequestHeaderMode:  policy.HeaderModeProcess,
		RequestBodyMode:    requestBodyMode,
		ResponseHeaderMode: policy.HeaderModeProcess,
		ResponseBodyMode:   policy.BodyModeSkip,
	}
}

// Validate validates the policy configuration parameters
func (p *SetHeadersPolicy) Validate(params map[string]interface{}) error {
	// Mode is optional; when present it must be either "set" or "append".
	if err := p.validateMode(params); err != nil {
		return err
	}

	// At least one of request.headers or response.headers must be specified.
	// Legacy flat keys are also accepted for runtime compatibility.
	requestHeadersRaw, hasRequestHeaders, err := p.getPhaseHeaders(params, "request", "requestHeaders")
	if err != nil {
		return err
	}
	responseHeadersRaw, hasResponseHeaders, err := p.getPhaseHeaders(params, "response", "responseHeaders")
	if err != nil {
		return err
	}

	if !hasRequestHeaders && !hasResponseHeaders {
		return fmt.Errorf("at least one of 'request.headers' or 'response.headers' must be specified")
	}

	// Validate request headers if present
	if hasRequestHeaders {
		if err := p.validateHeaderEntries(requestHeadersRaw, "request.headers", false); err != nil {
			return err
		}
		if err := p.validateRequestPhase(params); err != nil {
			return err
		}
	}

	// Validate response headers if present
	if hasResponseHeaders {
		if err := p.validateHeaderEntries(responseHeadersRaw, "response.headers", true); err != nil {
			return err
		}
	}

	return nil
}

func (p *SetHeadersPolicy) validateRequestPhase(params map[string]interface{}) error {
	requestRaw, ok := params["request"]
	if !ok {
		return nil
	}
	requestMap, ok := requestRaw.(map[string]interface{})
	if !ok {
		return nil
	}
	phaseRaw, ok := requestMap["phase"]
	if !ok {
		return nil
	}
	phase, ok := phaseRaw.(string)
	if !ok {
		return fmt.Errorf("request.phase must be a string")
	}
	if phase != RequestPhaseHeader && phase != RequestPhaseBody {
		return fmt.Errorf("request.phase must be either '%s' or '%s'", RequestPhaseHeader, RequestPhaseBody)
	}
	return nil
}

// validateMode validates the optional top-level "mode" parameter.
func (p *SetHeadersPolicy) validateMode(params map[string]interface{}) error {
	modeRaw, ok := params["mode"]
	if !ok {
		return nil
	}
	mode, ok := modeRaw.(string)
	if !ok {
		return fmt.Errorf("mode must be a string")
	}
	if mode != ModeSet && mode != ModeAppend {
		return fmt.Errorf("mode must be either '%s' or '%s'", ModeSet, ModeAppend)
	}
	return nil
}

// getMode returns the configured mode, defaulting to ModeSet when absent or invalid.
func (p *SetHeadersPolicy) getMode(params map[string]interface{}) string {
	if modeRaw, ok := params["mode"]; ok {
		if mode, ok := modeRaw.(string); ok && mode == ModeAppend {
			return ModeAppend
		}
	}
	return ModeSet
}

func (p *SetHeadersPolicy) getRequestPhase(params map[string]interface{}) string {
	return requestPhaseFromParams(params)
}

func requestPhaseFromParams(params map[string]interface{}) string {
	requestRaw, ok := params["request"]
	if !ok {
		return RequestPhaseHeader
	}
	requestMap, ok := requestRaw.(map[string]interface{})
	if !ok {
		return RequestPhaseHeader
	}
	phase, ok := requestMap["phase"].(string)
	if !ok || phase != RequestPhaseBody {
		return RequestPhaseHeader
	}
	return RequestPhaseBody
}

// getPhaseHeaders extracts headers for a phase, supporting both nested
// (`request.headers`/`response.headers`) and legacy flat keys.
func (p *SetHeadersPolicy) getPhaseHeaders(
	params map[string]interface{},
	phaseKey string,
	legacyKey string,
) (interface{}, bool, error) {
	if phaseRaw, ok := params[phaseKey]; ok {
		phaseMap, ok := phaseRaw.(map[string]interface{})
		if !ok {
			return nil, false, fmt.Errorf("%s must be an object", phaseKey)
		}
		headersRaw, ok := phaseMap["headers"]
		if !ok {
			return nil, false, fmt.Errorf("%s.headers must be specified", phaseKey)
		}
		return headersRaw, true, nil
	}

	if headersRaw, ok := params[legacyKey]; ok {
		return headersRaw, true, nil
	}

	return nil, false, nil
}

// validateHeaderEntries validates a list of header entries.
// When isResponsePhase is false, entries using ${resp.header.*} expressions are rejected
// because the upstream response does not exist during the request phase.
func (p *SetHeadersPolicy) validateHeaderEntries(headersRaw interface{}, fieldName string, isResponsePhase bool) error {
	headers, ok := headersRaw.([]interface{})
	if !ok {
		return fmt.Errorf("%s must be an array", fieldName)
	}

	if len(headers) == 0 {
		return fmt.Errorf("%s cannot be empty", fieldName)
	}

	for i, headerRaw := range headers {
		headerMap, ok := headerRaw.(map[string]interface{})
		if !ok {
			return fmt.Errorf("%s[%d] must be an object with 'name' and 'value' fields", fieldName, i)
		}

		// Validate name
		nameRaw, ok := headerMap["name"]
		if !ok {
			return fmt.Errorf("%s[%d] missing required 'name' field", fieldName, i)
		}
		name, ok := nameRaw.(string)
		if !ok {
			return fmt.Errorf("%s[%d].name must be a string", fieldName, i)
		}
		if len(strings.TrimSpace(name)) == 0 {
			return fmt.Errorf("%s[%d].name cannot be empty", fieldName, i)
		}

		// Validate value
		valueRaw, ok := headerMap["value"]
		if !ok {
			return fmt.Errorf("%s[%d] missing required 'value' field", fieldName, i)
		}
		value, ok := valueRaw.(string)
		if !ok {
			return fmt.Errorf("%s[%d].value must be a string", fieldName, i)
		}

		// Reject ${resp.header.*} in request-phase entries — the upstream response does
		// not exist during the request phase and such expressions can never resolve.
		if !isResponsePhase && respHeaderRe.MatchString(value) {
			return fmt.Errorf(
				"%s[%d] (%q): ${resp.header.*} expressions are only available in the response phase",
				fieldName, i, name,
			)
		}
	}

	return nil
}

// parseHeaderEntries parses header entries from config
func (p *SetHeadersPolicy) parseHeaderEntries(headersRaw interface{}) []HeaderEntry {
	headers, ok := headersRaw.([]interface{})
	if !ok {
		return nil
	}

	entries := make([]HeaderEntry, 0, len(headers))
	for _, headerRaw := range headers {
		headerMap, ok := headerRaw.(map[string]interface{})
		if !ok {
			continue
		}

		removeSource, _ := headerMap["removeSource"].(bool)
		entry := HeaderEntry{
			Name:         strings.ToLower(strings.TrimSpace(headerMap["name"].(string))),
			Value:        headerMap["value"].(string),
			RemoveSource: removeSource,
		}

		entries = append(entries, entry)
	}

	return entries
}

// hasResidualExpr reports whether template still contains "${" after removing all
// recognised ${…} expressions — indicating an unknown scope or unclosed delimiter.
func hasResidualExpr(template string) bool {
	return strings.Contains(exprRe.ReplaceAllString(template, ""), "${")
}

// isDynamic reports whether the value contains any ${...} expression.
func isDynamic(value string) bool {
	return strings.Contains(value, "${")
}

// resolve substitutes all ${req.header.<n>}, ${resp.header.<n>}, and ${meta.<key>}
// expressions in template. Returns ("", false) when any referenced source is absent
// or the template contains an unrecognised / unclosed ${...} expression.
// Checking for residual "${" on the template (not the result) prevents a source header
// that itself contains "${" from triggering a false positive.
func resolve(template string, reqHeaders, respHeaders *policy.Headers, metadata map[string]interface{}) (string, bool) {
	if hasResidualExpr(template) {
		return "", false
	}
	missing := false
	result := exprRe.ReplaceAllStringFunc(template, func(match string) string {
		parts := exprRe.FindStringSubmatch(match)
		if len(parts) < 3 {
			missing = true
			return ""
		}
		scope, key := parts[1], parts[2]
		switch scope {
		case "req.header":
			if reqHeaders != nil {
				if vals := reqHeaders.Get(key); len(vals) > 0 {
					return vals[0]
				}
			}
		case "resp.header":
			if respHeaders != nil {
				if vals := respHeaders.Get(key); len(vals) > 0 {
					return vals[0]
				}
			}
		case "meta":
			if metadata != nil {
				if v, ok := metadata[key]; ok {
					return fmt.Sprintf("%v", v)
				}
			}
		}
		missing = true
		return ""
	})
	if missing {
		return "", false
	}
	return result, true
}

// sourceHeaderNames returns lowercased names of headers referenced by expressions
// of the given scope ("req.header" or "resp.header") within tmpl.
func sourceHeaderNames(tmpl, scope string) []string {
	var names []string
	for _, parts := range exprRe.FindAllStringSubmatch(tmpl, -1) {
		if len(parts) >= 3 && parts[1] == scope {
			names = append(names, strings.ToLower(parts[2]))
		}
	}
	return names
}

// filterNotInSet removes from removes any header that the policy is also setting or
// appending, so a header is never simultaneously removed and written by the same policy.
func filterNotInSet(removes []string, toSet map[string]string, toAppend map[string][]string) []string {
	if len(removes) == 0 {
		return removes
	}
	out := removes[:0]
	for _, r := range removes {
		if _, inSet := toSet[r]; inSet {
			continue
		}
		if _, inAppend := toAppend[r]; inAppend {
			continue
		}
		out = append(out, r)
	}
	return out
}

// buildRequestHeaderEntries extracts and parses request header entries from params.
// Returns nil if no headers are configured.
func (p *SetHeadersPolicy) buildRequestHeaderEntries(params map[string]interface{}) []HeaderEntry {
	headersRaw, ok, err := p.getPhaseHeaders(params, "request", "requestHeaders")
	if err != nil || !ok {
		return nil
	}
	return p.parseHeaderEntries(headersRaw)
}

// applyRequestEntries resolves entries against request headers and metadata.
// Dynamic entries that fail to resolve are added to headersToRemove (spoof prevention).
// Static entries are never added to headersToRemove.
func (p *SetHeadersPolicy) applyRequestEntries(
	entries []HeaderEntry,
	mode string,
	reqHeaders *policy.Headers,
	metadata map[string]interface{},
) (headersToSet map[string]string, headersToAppend map[string][]string, headersToRemove []string) {
	headersToSet = make(map[string]string, len(entries))
	headersToAppend = make(map[string][]string)

	for _, entry := range entries {
		if !isDynamic(entry.Value) {
			// Static value: behave as before (never trigger spoof-prevention removal).
			if mode == ModeAppend {
				headersToAppend[entry.Name] = append(headersToAppend[entry.Name], entry.Value)
			} else {
				headersToSet[entry.Name] = entry.Value
			}
			continue
		}
		val, ok := resolve(entry.Value, reqHeaders, nil, metadata)
		if entry.RemoveSource {
			// Collect source removals before the resolution check so that referenced
			// source headers are stripped even when the target expression fails to resolve.
			headersToRemove = append(headersToRemove, sourceHeaderNames(entry.Value, "req.header")...)
		}
		if !ok {
			// Clear any earlier assignment for this header so the failing entry
			// takes precedence (last-entry-wins in set mode).
			delete(headersToSet, entry.Name)
			// Remove target to prevent a client-supplied value from reaching the backend.
			headersToRemove = append(headersToRemove, entry.Name)
			continue
		}
		if mode == ModeAppend {
			headersToAppend[entry.Name] = append(headersToAppend[entry.Name], val)
		} else {
			headersToSet[entry.Name] = val
		}
	}
	// Never remove a header that this same policy is also setting or appending.
	headersToRemove = filterNotInSet(headersToRemove, headersToSet, headersToAppend)
	if len(headersToSet) == 0 {
		headersToSet = nil
	}
	if len(headersToAppend) == 0 {
		headersToAppend = nil
	}
	return headersToSet, headersToAppend, headersToRemove
}

// OnRequestHeaders sets or appends headers on the request (v2alpha.RequestHeaderPolicy).
func (p *SetHeadersPolicy) OnRequestHeaders(ctx context.Context, reqCtx *policy.RequestHeaderContext, params map[string]interface{}) policy.RequestHeaderAction {
	if p.getRequestPhase(params) == RequestPhaseBody {
		return policy.UpstreamRequestHeaderModifications{}
	}
	entries := p.buildRequestHeaderEntries(params)
	mode := p.getMode(params)

	var metadata map[string]interface{}
	if reqCtx.SharedContext != nil {
		metadata = reqCtx.SharedContext.Metadata
	}

	headersToSet, headersToAppend, headersToRemove := p.applyRequestEntries(entries, mode, reqCtx.Headers, metadata)
	return policy.UpstreamRequestHeaderModifications{
		HeadersToSet:    headersToSet,
		HeadersToAppend: headersToAppend,
		HeadersToRemove: headersToRemove,
	}
}

// OnRequestBody supports provider credentials that depend on a body-phase router.
func (p *SetHeadersPolicy) OnRequestBody(ctx context.Context, reqCtx *policy.RequestContext, params map[string]interface{}) policy.RequestAction {
	if p.getRequestPhase(params) != RequestPhaseBody {
		return policy.UpstreamRequestModifications{}
	}
	entries := p.buildRequestHeaderEntries(params)
	mode := p.getMode(params)

	var metadata map[string]interface{}
	if reqCtx.SharedContext != nil {
		metadata = reqCtx.SharedContext.Metadata
	}

	headersToSet, headersToAppend, headersToRemove := p.applyRequestEntries(entries, mode, reqCtx.Headers, metadata)
	return policy.UpstreamRequestModifications{
		HeadersToSet:    headersToSet,
		HeadersToAppend: headersToAppend,
		HeadersToRemove: headersToRemove,
	}
}

// buildResponseHeaderEntries extracts and parses response header entries from params.
// Returns nil if no headers are configured.
func (p *SetHeadersPolicy) buildResponseHeaderEntries(params map[string]interface{}) []HeaderEntry {
	headersRaw, ok, err := p.getPhaseHeaders(params, "response", "responseHeaders")
	if err != nil || !ok {
		return nil
	}
	return p.parseHeaderEntries(headersRaw)
}

// OnResponseHeaders sets or appends headers on the response (v2alpha.ResponseHeaderPolicy).
func (p *SetHeadersPolicy) OnResponseHeaders(ctx context.Context, respCtx *policy.ResponseHeaderContext, params map[string]interface{}) policy.ResponseHeaderAction {
	entries := p.buildResponseHeaderEntries(params)
	mode := p.getMode(params)

	var metadata map[string]interface{}
	if respCtx.SharedContext != nil {
		metadata = respCtx.SharedContext.Metadata
	}

	headersToSet := make(map[string]string, len(entries))
	headersToAppend := make(map[string][]string)
	var headersToRemove []string

	for _, entry := range entries {
		if !isDynamic(entry.Value) {
			// Static value: behave as before.
			if mode == ModeAppend {
				headersToAppend[entry.Name] = append(headersToAppend[entry.Name], entry.Value)
			} else {
				headersToSet[entry.Name] = entry.Value
			}
			continue
		}
		val, ok := resolve(entry.Value, respCtx.RequestHeaders, respCtx.ResponseHeaders, metadata)
		if entry.RemoveSource {
			// Collect source removals before the resolution check so that referenced
			// source headers are stripped even when the target expression fails to resolve.
			// Only ${resp.header.*} sources can be removed in the response phase.
			headersToRemove = append(headersToRemove, sourceHeaderNames(entry.Value, "resp.header")...)
		}
		if !ok {
			// Clear any earlier assignment for this header so the failing entry
			// takes precedence (last-entry-wins in set mode).
			delete(headersToSet, entry.Name)
			headersToRemove = append(headersToRemove, entry.Name)
			continue
		}
		if mode == ModeAppend {
			headersToAppend[entry.Name] = append(headersToAppend[entry.Name], val)
		} else {
			headersToSet[entry.Name] = val
		}
	}
	// Never remove a header that this same policy is also setting or appending.
	headersToRemove = filterNotInSet(headersToRemove, headersToSet, headersToAppend)
	if len(headersToSet) == 0 {
		headersToSet = nil
	}
	if len(headersToAppend) == 0 {
		headersToAppend = nil
	}
	return policy.DownstreamResponseHeaderModifications{
		HeadersToSet:    headersToSet,
		HeadersToAppend: headersToAppend,
		HeadersToRemove: headersToRemove,
	}
}
