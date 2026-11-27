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

package hostrewrite

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

var ins = &HostRewritePolicy{}

// HostRewritePolicy implements host header rewriting for upstream requests
type HostRewritePolicy struct{}

// GetPolicy is the v1alpha2 factory entry point (loaded by v1alpha2 kernels).
func GetPolicy(
	metadata policy.PolicyMetadata,
	params map[string]interface{},
) (policy.Policy, error) {
	return ins, nil
}

func (p *HostRewritePolicy) Mode() policy.ProcessingMode {
	return policy.ProcessingMode{
		RequestHeaderMode:  policy.HeaderModeProcess,
		RequestBodyMode:    policy.BodyModeSkip,
		ResponseHeaderMode: policy.HeaderModeSkip,
		ResponseBodyMode:   policy.BodyModeSkip,
	}
}

// policyConfig holds the configuration for the host-rewrite policy
type policyConfig struct {
	Host string `json:"host"`
}

// parseConfig extracts and validates the host parameter from the policy configuration
func parseConfig(params map[string]interface{}) (*policyConfig, error) {
	if len(params) == 0 {
		return nil, fmt.Errorf("host parameter is required")
	}

	hostRaw, ok := params["host"]
	if !ok {
		return nil, fmt.Errorf("host parameter is required")
	}

	host, ok := hostRaw.(string)
	if !ok {
		return nil, fmt.Errorf("host parameter must be a string")
	}

	host = strings.TrimSpace(host)
	if host == "" {
		return nil, fmt.Errorf("host parameter cannot be empty")
	}

	return &policyConfig{
		Host: host,
	}, nil
}

// OnRequestHeaders rewrites the Host header (authority) before forwarding the request to upstream
func (p *HostRewritePolicy) OnRequestHeaders(ctx context.Context, reqCtx *policy.RequestHeaderContext, params map[string]interface{}) policy.RequestHeaderAction {
	cfg, err := parseConfig(params)
	if err != nil {
		slog.Error("[Host Rewrite]: Configuration error", "error", err)
		return policy.ImmediateResponse{
			StatusCode: 500,
			Headers:    map[string]string{"content-type": "application/json"},
			Body:       []byte(fmt.Sprintf(`{"error":"Configuration Error","message":"%s"}`, err.Error())),
			IsFault:    true,
			Fault: &policy.FaultDetails{
				Code:      policy.FaultCodeMediationFailed,
				Type:      policy.FaultTypeConfiguration,
				Direction: policy.DirectionRequest,
				Message:   "Configuration Error",
				// err names the operator's own configuration mistake. The body above
				// has always carried it; the fault keeps it in Description, not Message.
				Description: err.Error(),
			},
		}
	}

	slog.Info("[Host Rewrite]: Rewriting host header", "from", reqCtx.Headers.Get(":authority"), "to", cfg.Host)

	return policy.UpstreamRequestHeaderModifications{
		Host: &cfg.Host,
	}
}
