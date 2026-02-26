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

package removeheaders

import (
	"fmt"
	"strings"

	policy "github.com/wso2/api-platform/sdk/gateway/policy/v1alpha"
)

// RemoveHeadersPolicy implements header removal for both request and response
type RemoveHeadersPolicy struct{}

var ins = &RemoveHeadersPolicy{}

func GetPolicy(
	metadata policy.PolicyMetadata,
	params map[string]interface{},
) (policy.Policy, error) {
	return ins, nil
}

// Mode returns the processing mode for this policy
func (p *RemoveHeadersPolicy) Mode() policy.ProcessingMode {
	return policy.ProcessingMode{
		RequestHeaderMode:  policy.HeaderModeProcess, // Can remove request headers
		RequestBodyMode:    policy.BodyModeSkip,      // Don't need request body
		ResponseHeaderMode: policy.HeaderModeProcess, // Can remove response headers
		ResponseBodyMode:   policy.BodyModeSkip,      // Don't need response body
	}
}

// Validate validates the policy configuration parameters
func (p *RemoveHeadersPolicy) Validate(params map[string]interface{}) error {
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
		if err := p.validateHeaderNames(requestHeadersRaw, "request.headers"); err != nil {
			return err
		}
	}

	// Validate response headers if present
	if hasResponseHeaders {
		if err := p.validateHeaderNames(responseHeadersRaw, "response.headers"); err != nil {
			return err
		}
	}

	return nil
}

// getPhaseHeaders extracts headers for a phase, supporting both nested
// (`request.headers`/`response.headers`) and legacy flat keys.
func (p *RemoveHeadersPolicy) getPhaseHeaders(
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

// validateHeaderNames validates a list of header name objects
func (p *RemoveHeadersPolicy) validateHeaderNames(headersRaw interface{}, fieldName string) error {
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
			return fmt.Errorf("%s[%d] must be an object with 'name' field", fieldName, i)
		}

		// Validate name field
		nameRaw, ok := headerMap["name"]
		if !ok {
			return fmt.Errorf("%s[%d] missing required 'name' field", fieldName, i)
		}

		headerName, ok := nameRaw.(string)
		if !ok {
			return fmt.Errorf("%s[%d].name must be a string", fieldName, i)
		}

		if len(strings.TrimSpace(headerName)) == 0 {
			return fmt.Errorf("%s[%d].name cannot be empty or whitespace-only", fieldName, i)
		}
	}

	return nil
}

// parseHeaderNames parses header names from config
func (p *RemoveHeadersPolicy) parseHeaderNames(headersRaw interface{}) []string {
	headers, ok := headersRaw.([]interface{})
	if !ok {
		return nil
	}

	headerNames := make([]string, 0, len(headers))
	for _, headerRaw := range headers {
		headerMap, ok := headerRaw.(map[string]interface{})
		if !ok {
			continue
		}

		// Extract name from the header object
		nameRaw, ok := headerMap["name"]
		if !ok {
			continue
		}

		headerName, ok := nameRaw.(string)
		if !ok {
			continue
		}

		// Normalize to lowercase and trim whitespace
		normalizedName := strings.ToLower(strings.TrimSpace(headerName))
		if normalizedName != "" {
			headerNames = append(headerNames, normalizedName)
		}
	}

	return headerNames
}

// OnRequest removes headers from the request
// Uses RemoveHeaders to remove specified headers from requests
func (p *RemoveHeadersPolicy) OnRequest(ctx *policy.RequestContext, params map[string]interface{}) policy.RequestAction {
	// Check if request headers are configured.
	requestHeadersRaw, ok, err := p.getPhaseHeaders(params, "request", "requestHeaders")
	if err != nil || !ok {
		// No request headers to remove, pass through
		return policy.UpstreamRequestModifications{}
	}

	// Parse header names
	headerNames := p.parseHeaderNames(requestHeadersRaw)
	if len(headerNames) == 0 {
		return policy.UpstreamRequestModifications{}
	}

	return policy.UpstreamRequestModifications{
		RemoveHeaders: headerNames,
	}
}

// OnResponse removes headers from the response
// Uses RemoveHeaders to remove specified headers from responses
func (p *RemoveHeadersPolicy) OnResponse(ctx *policy.ResponseContext, params map[string]interface{}) policy.ResponseAction {
	// Check if response headers are configured.
	responseHeadersRaw, ok, err := p.getPhaseHeaders(params, "response", "responseHeaders")
	if err != nil || !ok {
		// No response headers to remove, pass through
		return policy.UpstreamResponseModifications{}
	}

	// Parse header names
	headerNames := p.parseHeaderNames(responseHeadersRaw)
	if len(headerNames) == 0 {
		return policy.UpstreamResponseModifications{}
	}

	return policy.UpstreamResponseModifications{
		RemoveHeaders: headerNames,
	}
}
