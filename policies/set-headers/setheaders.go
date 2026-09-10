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

// HeaderEntry represents a single header to be set or appended
type HeaderEntry struct {
	Name  string
	Value string
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
		if err := p.validateHeaderEntries(requestHeadersRaw, "request.headers"); err != nil {
			return err
		}
		if err := p.validateRequestPhase(params); err != nil {
			return err
		}
	}

	// Validate response headers if present
	if hasResponseHeaders {
		if err := p.validateHeaderEntries(responseHeadersRaw, "response.headers"); err != nil {
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

// validateHeaderEntries validates a list of header entries
func (p *SetHeadersPolicy) validateHeaderEntries(headersRaw interface{}, fieldName string) error {
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
		_, ok = valueRaw.(string)
		if !ok {
			return fmt.Errorf("%s[%d].value must be a string", fieldName, i)
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

		entry := HeaderEntry{
			Name:  strings.ToLower(strings.TrimSpace(headerMap["name"].(string))), // Normalize to lowercase
			Value: headerMap["value"].(string),
		}

		entries = append(entries, entry)
	}

	return entries
}

// convertToSetHeaderMap converts header entries to a map for policy actions
// Returns map[string]string for SetHeaders (overwrites existing headers)
// Multiple headers with the same name will have the last value win (map behavior)
func (p *SetHeadersPolicy) convertToSetHeaderMap(entries []HeaderEntry) map[string]string {
	if len(entries) == 0 {
		return nil
	}
	headerMap := make(map[string]string)
	for _, entry := range entries {
		headerMap[entry.Name] = entry.Value // Last value wins for duplicate names
	}
	return headerMap
}

// convertToAppendHeaderMap converts header entries to a map for AppendHeaders
// (appends to existing headers). Multiple entries with the same name are all
// kept, preserving their configured order.
func (p *SetHeadersPolicy) convertToAppendHeaderMap(entries []HeaderEntry) map[string][]string {
	if len(entries) == 0 {
		return nil
	}
	headerMap := make(map[string][]string)
	for _, entry := range entries {
		headerMap[entry.Name] = append(headerMap[entry.Name], entry.Value)
	}
	return headerMap
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

// OnRequestHeaders sets or appends headers on the request (v2alpha.RequestHeaderPolicy).
func (p *SetHeadersPolicy) OnRequestHeaders(ctx context.Context, reqCtx *policy.RequestHeaderContext, params map[string]interface{}) policy.RequestHeaderAction {
	if p.getRequestPhase(params) == RequestPhaseBody {
		return policy.UpstreamRequestHeaderModifications{}
	}
	entries := p.buildRequestHeaderEntries(params)
	if p.getMode(params) == ModeAppend {
		return policy.UpstreamRequestHeaderModifications{
			HeadersToAppend: p.convertToAppendHeaderMap(entries),
		}
	}
	return policy.UpstreamRequestHeaderModifications{
		HeadersToSet: p.convertToSetHeaderMap(entries),
	}
}

// OnRequestBody supports provider credentials that depend on a body-phase router.
func (p *SetHeadersPolicy) OnRequestBody(ctx context.Context, reqCtx *policy.RequestContext, params map[string]interface{}) policy.RequestAction {
	if p.getRequestPhase(params) != RequestPhaseBody {
		return policy.UpstreamRequestModifications{}
	}
	entries := p.buildRequestHeaderEntries(params)
	if p.getMode(params) == ModeAppend {
		return policy.UpstreamRequestModifications{HeadersToAppend: p.convertToAppendHeaderMap(entries)}
	}
	return policy.UpstreamRequestModifications{HeadersToSet: p.convertToSetHeaderMap(entries)}
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
	if p.getMode(params) == ModeAppend {
		return policy.DownstreamResponseHeaderModifications{
			HeadersToAppend: p.convertToAppendHeaderMap(entries),
		}
	}
	return policy.DownstreamResponseHeaderModifications{
		HeadersToSet: p.convertToSetHeaderMap(entries),
	}
}
