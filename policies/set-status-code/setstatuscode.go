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

package setstatuscode

import (
	"context"
	"fmt"
	"log/slog"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

var ins = &SetStatusCodePolicy{}

// SetStatusCodePolicy overwrites the upstream response status code before forwarding to the client.
type SetStatusCodePolicy struct{}

// GetPolicy is the v1alpha2 factory entry point (loaded by v1alpha2 kernels).
func GetPolicy(
	metadata policy.PolicyMetadata,
	params map[string]interface{},
) (policy.Policy, error) {
	return ins, nil
}

func (p *SetStatusCodePolicy) Mode() policy.ProcessingMode {
	return policy.ProcessingMode{
		RequestHeaderMode:  policy.HeaderModeSkip,
		RequestBodyMode:    policy.BodyModeSkip,
		ResponseHeaderMode: policy.HeaderModeSkip,
		ResponseBodyMode:   policy.BodyModeBuffer,
	}
}

// policyConfig holds the configuration for the set-status-code policy.
type policyConfig struct {
	StatusCode int
}

// parseConfig extracts and validates the statusCode parameter from the policy configuration.
func parseConfig(params map[string]interface{}) (*policyConfig, error) {
	if len(params) == 0 {
		return nil, fmt.Errorf("statusCode parameter is required")
	}

	raw, ok := params["statusCode"]
	if !ok {
		return nil, fmt.Errorf("statusCode parameter is required")
	}

	var statusCode int
	switch v := raw.(type) {
	case int:
		statusCode = v
	case float64:
		parsed := int(v)
		if float64(parsed) != v {
			return nil, fmt.Errorf("statusCode parameter must be an integer, got fractional value %v", v)
		}
		statusCode = parsed
	default:
		return nil, fmt.Errorf("statusCode parameter must be an integer")
	}

	if statusCode < 100 || statusCode > 599 {
		return nil, fmt.Errorf("statusCode must be between 100 and 599, got %d", statusCode)
	}

	return &policyConfig{StatusCode: statusCode}, nil
}

// OnResponseBody overwrites the upstream response status code before forwarding to the client.
func (p *SetStatusCodePolicy) OnResponseBody(ctx context.Context, respCtx *policy.ResponseContext, params map[string]interface{}) policy.ResponseAction {
	cfg, err := parseConfig(params)
	if err != nil {
		slog.Error("[Set Status Code]: Configuration error", "error", err)
		return policy.ImmediateResponse{
			StatusCode: 500,
			Headers:    map[string]string{"content-type": "application/json"},
			Body:       fmt.Appendf(nil, `{"error":"Configuration Error","message":"%s"}`, err.Error()),
		}
	}

	slog.Info("[Set Status Code]: Overwriting response status code", "from", respCtx.ResponseStatus, "to", cfg.StatusCode)

	return policy.DownstreamResponseModifications{
		StatusCode: &cfg.StatusCode,
	}
}
