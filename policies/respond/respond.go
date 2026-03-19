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

package respond

import (
	"encoding/json"
	"fmt"
	"regexp"

	policy "github.com/wso2/api-platform/sdk/gateway/policy/v1alpha"
)

const (
	defaultStatusCode = 200
	minStatusCode     = 100
	maxStatusCode     = 599
	headerNameMaxLen  = 256
	headerValueMaxLen = 8192
)

var headerNamePattern = regexp.MustCompile(`^[a-zA-Z0-9-_]+$`)

// RespondPolicy implements immediate response functionality
// This policy terminates the request processing and returns an immediate response to the client
type RespondPolicy struct{}

var ins = &RespondPolicy{}

func GetPolicy(
	metadata policy.PolicyMetadata,
	params map[string]interface{},
) (policy.Policy, error) {
	return ins, nil
}

// configError returns a 500 error response for configuration issues
func configError(message string) policy.ImmediateResponse {
	errBody, _ := json.Marshal(map[string]string{
		"error":   "Configuration Error",
		"message": message,
	})
	return policy.ImmediateResponse{
		StatusCode: 500,
		Headers: map[string]string{
			"content-type": "application/json",
		},
		Body: errBody,
	}
}

// Mode returns the processing mode for this policy
func (p *RespondPolicy) Mode() policy.ProcessingMode {
	return policy.ProcessingMode{
		RequestHeaderMode:  policy.HeaderModeProcess, // Can use request headers for context
		RequestBodyMode:    policy.BodyModeSkip,      // Don't need request body
		ResponseHeaderMode: policy.HeaderModeSkip,    // Returns immediate response
		ResponseBodyMode:   policy.BodyModeSkip,      // Returns immediate response
	}
}

// OnRequest returns an immediate response to the client
func (p *RespondPolicy) OnRequest(ctx *policy.RequestContext, params map[string]interface{}) policy.RequestAction {
	// Extract statusCode (default to 200 OK)
	statusCode := defaultStatusCode
	if statusCodeRaw, ok := params["statusCode"]; ok {
		parsedStatusCode, err := parseStatusCode(statusCodeRaw)
		if err != nil {
			return configError(err.Error())
		}
		statusCode = parsedStatusCode
	}

	// Extract body
	body := []byte{}
	if bodyRaw, ok := params["body"]; ok {
		bodyString, ok := bodyRaw.(string)
		if !ok {
			return configError("body must be a string")
		}
		body = []byte(bodyString)
	}

	// Extract headers with fail-fast validation
	headers := make(map[string]string)
	if headersRaw, ok := params["headers"]; ok {
		headersList, ok := headersRaw.([]interface{})
		if !ok {
			return configError("headers must be an array")
		}
		for i, headerRaw := range headersList {
			headerMap, ok := headerRaw.(map[string]interface{})
			if !ok {
				return configError(fmt.Sprintf("headers[%d] must be an object", i))
			}
			if err := validateHeaderObjectKeys(headerMap, i); err != nil {
				return configError(err.Error())
			}

			// Safe type assertion for name
			nameRaw, ok := headerMap["name"]
			if !ok {
				return configError(fmt.Sprintf("headers[%d] missing required 'name' field", i))
			}
			name, ok := nameRaw.(string)
			if !ok {
				return configError(fmt.Sprintf("headers[%d].name must be a string", i))
			}
			if name == "" {
				return configError(fmt.Sprintf("headers[%d].name cannot be empty", i))
			}
			if len(name) > headerNameMaxLen {
				return configError(fmt.Sprintf("headers[%d].name must not exceed %d characters", i, headerNameMaxLen))
			}
			if !headerNamePattern.MatchString(name) {
				return configError(fmt.Sprintf("headers[%d].name contains invalid characters", i))
			}

			// Safe type assertion for value
			valueRaw, ok := headerMap["value"]
			if !ok {
				return configError(fmt.Sprintf("headers[%d] missing required 'value' field", i))
			}
			value, ok := valueRaw.(string)
			if !ok {
				return configError(fmt.Sprintf("headers[%d].value must be a string", i))
			}
			if len(value) > headerValueMaxLen {
				return configError(fmt.Sprintf("headers[%d].value must not exceed %d characters", i, headerValueMaxLen))
			}

			headers[name] = value
		}
	}

	// Return immediate response action
	return policy.ImmediateResponse{
		StatusCode: statusCode,
		Headers:    headers,
		Body:       body,
	}
}

// OnResponse is not used by this policy (returns immediate response in request phase)
func (p *RespondPolicy) OnResponse(ctx *policy.ResponseContext, params map[string]interface{}) policy.ResponseAction {
	return nil // No response processing needed
}

func parseStatusCode(statusCodeRaw interface{}) (int, error) {
	var statusCode int
	switch v := statusCodeRaw.(type) {
	case float64:
		parsed := int(v)
		if float64(parsed) != v {
			return 0, fmt.Errorf("statusCode must be an integer")
		}
		statusCode = parsed
	case int:
		statusCode = v
	case int8:
		statusCode = int(v)
	case int16:
		statusCode = int(v)
	case int32:
		statusCode = int(v)
	case int64:
		statusCode = int(v)
	default:
		return 0, fmt.Errorf("statusCode must be an integer")
	}

	if statusCode < minStatusCode || statusCode > maxStatusCode {
		return 0, fmt.Errorf("statusCode must be between %d and %d", minStatusCode, maxStatusCode)
	}
	return statusCode, nil
}

func validateHeaderObjectKeys(headerMap map[string]interface{}, index int) error {
	for key := range headerMap {
		if key != "name" && key != "value" {
			return fmt.Errorf("headers[%d] contains unsupported field '%s'", index, key)
		}
	}
	return nil
}
