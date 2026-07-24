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

package basicauth

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

const (
	AuthType = "basic"
)

// BasicAuthPolicy implements HTTP Basic Authentication
type BasicAuthPolicy struct{}

var ins = &BasicAuthPolicy{}

// GetPolicy is the v1alpha2 factory entry point (loaded by v1alpha2 kernels).
func GetPolicy(
	metadata policy.PolicyMetadata,
	params map[string]interface{},
) (policy.Policy, error) {
	return ins, nil
}


func (p *BasicAuthPolicy) Mode() policy.ProcessingMode {
	return policy.ProcessingMode{
		RequestHeaderMode:  policy.HeaderModeProcess,
		RequestBodyMode:    policy.BodyModeSkip,
		ResponseHeaderMode: policy.HeaderModeSkip,
		ResponseBodyMode:   policy.BodyModeSkip,
	}
}

// OnRequestHeaders performs Basic Authentication in the request header phase.
func (p *BasicAuthPolicy) OnRequestHeaders(ctx context.Context, reqCtx *policy.RequestHeaderContext, params map[string]interface{}) policy.RequestHeaderAction {
	expectedUsername, ok := params["username"].(string)
	if !ok || expectedUsername == "" {
		errBody, _ := json.Marshal(map[string]string{
			"error":   "Internal Server Error",
			"message": "Invalid policy configuration: username must be a non-empty string",
		})
		return policy.ImmediateResponse{
			StatusCode: 500,
			Headers:    map[string]string{"content-type": "application/json"},
			Body:       errBody,
		}
	}

	expectedPassword, ok := params["password"].(string)
	if !ok || expectedPassword == "" {
		errBody, _ := json.Marshal(map[string]string{
			"error":   "Internal Server Error",
			"message": "Invalid policy configuration: password must be a non-empty string",
		})
		return policy.ImmediateResponse{
			StatusCode: 500,
			Headers:    map[string]string{"content-type": "application/json"},
			Body:       errBody,
		}
	}

	allowUnauthenticated := false
	if allowUnauthRaw, ok := params["allowUnauthenticated"]; ok {
		if allowUnauthBool, ok := allowUnauthRaw.(bool); ok {
			allowUnauthenticated = allowUnauthBool
		}
	}

	realm := "Restricted"
	if realmRaw, ok := params["realm"]; ok {
		if realmStr, ok := realmRaw.(string); ok && realmStr != "" {
			realm = realmStr
		}
	}

	authHeaders := getDownstreamHeaders(reqCtx.Downstream, reqCtx.Headers).Get("authorization")
	if len(authHeaders) == 0 {
		return p.handleAuthFailureHeaders(reqCtx.SharedContext, allowUnauthenticated, realm)
	}

	authHeader := authHeaders[0]
	if !strings.HasPrefix(authHeader, "Basic ") {
		return p.handleAuthFailureHeaders(reqCtx.SharedContext, allowUnauthenticated, realm)
	}

	encodedCredentials := strings.TrimPrefix(authHeader, "Basic ")
	decodedBytes, err := base64.StdEncoding.DecodeString(encodedCredentials)
	if err != nil {
		return p.handleAuthFailureHeaders(reqCtx.SharedContext, allowUnauthenticated, realm)
	}

	credentials := string(decodedBytes)
	parts := strings.SplitN(credentials, ":", 2)
	if len(parts) != 2 {
		return p.handleAuthFailureHeaders(reqCtx.SharedContext, allowUnauthenticated, realm)
	}

	providedUsername := parts[0]
	providedPassword := parts[1]

	usernameMatch := subtle.ConstantTimeCompare([]byte(providedUsername), []byte(expectedUsername)) == 1
	passwordMatch := subtle.ConstantTimeCompare([]byte(providedPassword), []byte(expectedPassword)) == 1

	if !usernameMatch || !passwordMatch {
		return p.handleAuthFailureHeaders(reqCtx.SharedContext, allowUnauthenticated, realm)
	}

	reqCtx.SharedContext.AuthContext = &policy.AuthContext{
		Authenticated: true,
		AuthType:      AuthType,
		Subject:       providedUsername,
		Previous:      reqCtx.SharedContext.AuthContext,
		TokenId:	   providedUsername,
	}
	return policy.UpstreamRequestHeaderModifications{}
}

// handleAuthFailureHeaders handles authentication failure in the header phase.
func (p *BasicAuthPolicy) handleAuthFailureHeaders(shared *policy.SharedContext, allowUnauthenticated bool, realm string) policy.RequestHeaderAction {
	shared.AuthContext = &policy.AuthContext{
		Authenticated: false,
		AuthType:      AuthType,
		Previous:      shared.AuthContext,
	}

	if allowUnauthenticated {
		return policy.UpstreamRequestHeaderModifications{}
	}

	escapedRealm := strings.ReplaceAll(strings.ReplaceAll(realm, "\\", "\\\\"), "\"", "\\\"")
	headers := map[string]string{
		"www-authenticate": fmt.Sprintf("Basic realm=\"%s\"", escapedRealm),
		"content-type":     "application/json",
	}

	body, _ := json.Marshal(map[string]string{
		"error":   "Unauthorized",
		"message": "Authentication required",
	})

	return policy.ImmediateResponse{
		StatusCode: 401,
		Headers:    headers,
		Body:       body,
	}
}
