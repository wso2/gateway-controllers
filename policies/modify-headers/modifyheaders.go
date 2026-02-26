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

package modifyheaders

import (
	"encoding/json"
	"fmt"
	"strings"

	policy "github.com/wso2/api-platform/sdk/gateway/policy/v1alpha"
)

// HeaderAction represents the action to perform on a header
type HeaderAction string

var ins = &ModifyHeadersPolicy{}

func GetPolicy(
	metadata policy.PolicyMetadata,
	params map[string]interface{},
) (policy.Policy, error) {
	return ins, nil
}

const (
	ActionSet    HeaderAction = "SET"
	ActionDelete HeaderAction = "DELETE"
)

// HeaderModification represents a single header modification operation
type HeaderModification struct {
	Action HeaderAction
	Name   string
	Value  string
}

// ModifyHeadersPolicy implements comprehensive header manipulation for both request and response
type ModifyHeadersPolicy struct{}

// Mode returns the processing mode for this policy
func (p *ModifyHeadersPolicy) Mode() policy.ProcessingMode {
	return policy.ProcessingMode{
		RequestHeaderMode:  policy.HeaderModeProcess, // Can modify request headers
		RequestBodyMode:    policy.BodyModeSkip,      // Don't need request body
		ResponseHeaderMode: policy.HeaderModeProcess, // Can modify response headers
		ResponseBodyMode:   policy.BodyModeSkip,      // Don't need response body
	}
}

// parseHeaderModifications parses header modifications from config
// Returns error if any entry is malformed to ensure fail-fast behavior
func (p *ModifyHeadersPolicy) parseHeaderModifications(headersRaw interface{}) ([]HeaderModification, error) {
	headers, ok := headersRaw.([]interface{})
	if !ok {
		return nil, fmt.Errorf("headers must be an array")
	}

	modifications := make([]HeaderModification, 0, len(headers))
	for i, headerRaw := range headers {
		headerMap, ok := headerRaw.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("header[%d] must be an object", i)
		}

		// Safe type assertion for action
		actionRaw, ok := headerMap["action"]
		if !ok {
			return nil, fmt.Errorf("header[%d] missing required 'action' field", i)
		}
		actionStr, ok := actionRaw.(string)
		if !ok {
			return nil, fmt.Errorf("header[%d].action must be a string", i)
		}

		// Safe type assertion for name
		nameRaw, ok := headerMap["name"]
		if !ok {
			return nil, fmt.Errorf("header[%d] missing required 'name' field", i)
		}
		nameStr, ok := nameRaw.(string)
		if !ok {
			return nil, fmt.Errorf("header[%d].name must be a string", i)
		}
		if nameStr == "" {
			return nil, fmt.Errorf("header[%d].name cannot be empty", i)
		}

		mod := HeaderModification{
			Action: HeaderAction(strings.ToUpper(actionStr)),
			Name:   strings.ToLower(nameStr), // Normalize to lowercase
		}

		// Safe type assertion for value
		if valueRaw, ok := headerMap["value"]; ok {
			if valueStr, ok := valueRaw.(string); ok {
				mod.Value = valueStr
			} else {
				return nil, fmt.Errorf("header[%d].value must be a string", i)
			}
		}

		modifications = append(modifications, mod)
	}

	return modifications, nil
}

// applyHeaderModifications applies header modifications and returns the result
func (p *ModifyHeadersPolicy) applyHeaderModifications(modifications []HeaderModification) (map[string]string, []string) {
	setHeaders := make(map[string]string)
	removeHeaders := []string{}

	for _, mod := range modifications {
		switch mod.Action {
		case ActionSet:
			setHeaders[mod.Name] = mod.Value
		case ActionDelete:
			removeHeaders = append(removeHeaders, mod.Name)
		}
	}

	return setHeaders, removeHeaders
}

// OnRequest modifies request headers
func (p *ModifyHeadersPolicy) OnRequest(ctx *policy.RequestContext, params map[string]interface{}) policy.RequestAction {
	// Check if requestHeaders are configured
	requestHeadersRaw, ok := params["requestHeaders"]
	if !ok {
		// No request headers to modify, pass through
		return policy.UpstreamRequestModifications{}
	}

	// Parse modifications
	modifications, err := p.parseHeaderModifications(requestHeadersRaw)
	if err != nil {
		// Configuration error - fail with 500
		errBody, _ := json.Marshal(map[string]string{
			"error":   "Configuration Error",
			"message": fmt.Sprintf("Invalid requestHeaders configuration: %s", err.Error()),
		})
		return policy.ImmediateResponse{
			StatusCode: 500,
			Headers: map[string]string{
				"content-type": "application/json",
			},
			Body: errBody,
		}
	}
	if len(modifications) == 0 {
		return policy.UpstreamRequestModifications{}
	}

	// Apply modifications
	setHeaders, removeHeaders := p.applyHeaderModifications(modifications)

	return policy.UpstreamRequestModifications{
		SetHeaders:    setHeaders,
		RemoveHeaders: removeHeaders,
	}
}

// OnResponse modifies response headers
func (p *ModifyHeadersPolicy) OnResponse(ctx *policy.ResponseContext, params map[string]interface{}) policy.ResponseAction {
	// Check if responseHeaders are configured
	responseHeadersRaw, ok := params["responseHeaders"]
	if !ok {
		// No response headers to modify, pass through
		return policy.UpstreamResponseModifications{}
	}

	// Parse modifications
	modifications, err := p.parseHeaderModifications(responseHeadersRaw)
	if err != nil {
		// Configuration error - return error response by modifying upstream response
		statusCode := 500
		errBody, _ := json.Marshal(map[string]string{
			"error":   "Configuration Error",
			"message": fmt.Sprintf("Invalid responseHeaders configuration: %s", err.Error()),
		})
		return policy.UpstreamResponseModifications{
			StatusCode: &statusCode,
			Body:       errBody,
			SetHeaders: map[string]string{
				"content-type": "application/json",
			},
		}
	}
	if len(modifications) == 0 {
		return policy.UpstreamResponseModifications{}
	}

	// Apply modifications
	setHeaders, removeHeaders := p.applyHeaderModifications(modifications)

	return policy.UpstreamResponseModifications{
		SetHeaders:    setHeaders,
		RemoveHeaders: removeHeaders,
	}
}
