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
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	policy "github.com/wso2/api-platform/sdk/gateway/policy/v1alpha"
)


const (
	AuthType   = "basic"
	PolicyName = "basic-auth"
)

// BasicAuthPolicy implements HTTP Basic Authentication
type BasicAuthPolicy struct{}

var ins = &BasicAuthPolicy{}

func GetPolicy(
	metadata policy.PolicyMetadata,
	params map[string]interface{},
) (policy.Policy, error) {
	return ins, nil
}

// Mode returns the processing mode for this policy
func (p *BasicAuthPolicy) Mode() policy.ProcessingMode {
	return policy.ProcessingMode{
		RequestHeaderMode:  policy.HeaderModeProcess, // Process request headers for auth
		RequestBodyMode:    policy.BodyModeSkip,      // Don't need request body
		ResponseHeaderMode: policy.HeaderModeSkip,    // Don't process response headers
		ResponseBodyMode:   policy.BodyModeSkip,      // Don't need response body
	}
}

// OnRequest performs Basic Authentication
func (p *BasicAuthPolicy) OnRequest(ctx *policy.RequestContext, params map[string]interface{}) policy.RequestAction {
	// Get configuration parameters with safe type assertions
	expectedUsername, ok := params["username"].(string)
	if !ok || expectedUsername == "" {
		errBody, _ := json.Marshal(map[string]string{
			"error":   "Internal Server Error",
			"message": "Invalid policy configuration: username must be a non-empty string",
		})
		return policy.ImmediateResponse{
			StatusCode: 500,
			Headers: map[string]string{
				"content-type": "application/json",
			},
			Body: errBody,
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
			Headers: map[string]string{
				"content-type": "application/json",
			},
			Body: errBody,
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

	// Extract and validate Authorization header
	authHeaders := ctx.Headers.Get("authorization")
	if len(authHeaders) == 0 {
		return p.handleAuthFailure(ctx, allowUnauthenticated, realm, "missing authorization header")
	}

	authHeader := authHeaders[0]

	// Check if it's Basic auth
	if !strings.HasPrefix(authHeader, "Basic ") {
		return p.handleAuthFailure(ctx, allowUnauthenticated, realm, "invalid authorization scheme")
	}

	// Decode base64 credentials
	encodedCredentials := strings.TrimPrefix(authHeader, "Basic ")
	decodedBytes, err := base64.StdEncoding.DecodeString(encodedCredentials)
	if err != nil {
		return p.handleAuthFailure(ctx, allowUnauthenticated, realm, "invalid base64 encoding")
	}

	// Parse username:password
	credentials := string(decodedBytes)
	parts := strings.SplitN(credentials, ":", 2)
	if len(parts) != 2 {
		return p.handleAuthFailure(ctx, allowUnauthenticated, realm, "invalid credentials format")
	}

	providedUsername := parts[0]
	providedPassword := parts[1]

	// Validate credentials using constant-time comparison to prevent timing attacks
	usernameMatch := subtle.ConstantTimeCompare([]byte(providedUsername), []byte(expectedUsername)) == 1
	passwordMatch := subtle.ConstantTimeCompare([]byte(providedPassword), []byte(expectedPassword)) == 1

	if !usernameMatch || !passwordMatch {
		return p.handleAuthFailure(ctx, allowUnauthenticated, realm, "invalid credentials")
	}

	// Authentication successful
	return p.handleAuthSuccess(ctx, providedUsername)
}

// handleAuthSuccess handles successful authentication
func (p *BasicAuthPolicy) handleAuthSuccess(ctx *policy.RequestContext, username string) policy.RequestAction {
	ctx.SharedContext.AuthContext = &policy.AuthContext{
		Authenticated: true,
		AuthType:      AuthType,
		PolicyName:    PolicyName,
		Subject:       username,
		Previous:      ctx.SharedContext.AuthContext,
	}

	// Continue to upstream with no modifications
	return policy.UpstreamRequestModifications{}
}

// OnResponse is not used by this policy (authentication is request-only)
func (p *BasicAuthPolicy) OnResponse(ctx *policy.ResponseContext, params map[string]interface{}) policy.ResponseAction {
	return nil // No response processing needed
}

// handleAuthFailure handles authentication failure
func (p *BasicAuthPolicy) handleAuthFailure(ctx *policy.RequestContext, allowUnauthenticated bool, realm string, reason string) policy.RequestAction {
	ctx.SharedContext.AuthContext = &policy.AuthContext{
		Authenticated: false,
		AuthType:      AuthType,
		PolicyName:    PolicyName,
		Previous:      ctx.SharedContext.AuthContext,
	}

	// If allowUnauthenticated is true, allow request to proceed
	if allowUnauthenticated {
		return policy.UpstreamRequestModifications{}
	}

	// Return 401 Unauthorized response
	// Escape realm value per RFC 7235 for quoted-string compliance
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
