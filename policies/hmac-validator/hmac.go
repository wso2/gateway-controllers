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

package hmacauth

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash"
	"strings"

	policy "github.com/wso2/api-platform/sdk/gateway/policy/v1alpha"
)

const (
	// Metadata keys for context storage
	MetadataKeyAuthSuccess = "auth.success"
	MetadataKeyAuthUser    = "auth.username"
	MetadataKeyAuthMethod  = "auth.method"
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
		RequestBodyMode:    policy.BodyModeBuffer,    // Need request body for HMAC
		ResponseHeaderMode: policy.HeaderModeSkip,    // Don't process response headers
		ResponseBodyMode:   policy.BodyModeSkip,      // Don't need response body
	}
}

// OnRequest performs Basic Authentication
func (p *BasicAuthPolicy) OnRequest(ctx *policy.RequestContext, params map[string]interface{}) policy.RequestAction {
	// Get configuration parameters with safe type assertions
	expectedHeaderName, ok := params["headerName"].(string)
	if !ok || expectedHeaderName == "" {
		errBody, _ := json.Marshal(map[string]string{
			"error":   "Internal Server Error",
			"message": "Invalid policy configuration: headerName must be a non-empty string",
		})
		return policy.ImmediateResponse{
			StatusCode: 500,
			Headers: map[string]string{
				"content-type": "application/json",
			},
			Body: errBody,
		}
	}

	expectedAlgorithm, ok := params["algorithm"].(string)
	if !ok || expectedAlgorithm == "" {
		errBody, _ := json.Marshal(map[string]string{
			"error":   "Internal Server Error",
			"message": "Invalid policy configuration: algorithm must be a non-empty string",
		})
		return policy.ImmediateResponse{
			StatusCode: 500,
			Headers: map[string]string{
				"content-type": "application/json",
			},
			Body: errBody,
		}
	}

	expectedSecretKey, ok := params["secretKey"].(string)
	if !ok || expectedSecretKey == "" {
		errBody, _ := json.Marshal(map[string]string{
			"error":   "Internal Server Error",
			"message": "Invalid policy configuration: secretKey must be a non-empty string",
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

	// Extract and validate Authorization header
	authHeaders := ctx.Headers.Get(expectedHeaderName)
	if len(authHeaders) == 0 {
		return p.handleHmacFailure(ctx, allowUnauthenticated, "missing authorization header")
	}

	authHeader := authHeaders[0]

	// Split the header value by '=' to get algorithm and signature
	// Expected format: "algorithm=signature"
	parts := strings.SplitN(authHeader, "=", 2)
	if len(parts) != 2 {
		return p.handleHmacFailure(ctx, allowUnauthenticated, "invalid header format, expected 'algorithm=signature'")
	}

	providedAlgorithm := strings.TrimSpace(parts[0])
	providedSignature := strings.TrimSpace(parts[1])

	// Validate the algorithm matches the expected algorithm
	if !strings.EqualFold(providedAlgorithm, expectedAlgorithm) {
		return p.handleHmacFailure(ctx, allowUnauthenticated, fmt.Sprintf("algorithm mismatch: expected %s, got %s", expectedAlgorithm, providedAlgorithm))
	}

	// Generate HMAC using the secret key and algorithm
	// Use the request body as the message to sign
	message := string(ctx.Body.Content)

	expectedSignature, err := generateHMAC(message, expectedSecretKey, expectedAlgorithm)
	if err != nil {
		errBody, _ := json.Marshal(map[string]string{
			"error":   "Internal Server Error",
			"message": fmt.Sprintf("Failed to generate HMAC: %s", err.Error()),
		})
		return policy.ImmediateResponse{
			StatusCode: 500,
			Headers: map[string]string{
				"content-type": "application/json",
			},
			Body: errBody,
		}
	}

	// Validate the provided signature against the expected signature using constant-time comparison
	if subtle.ConstantTimeCompare([]byte(providedSignature), []byte(expectedSignature)) != 1 {
		return p.handleHmacFailure(ctx, allowUnauthenticated, "invalid HMAC signature")
	}

	// Authentication successful
	return p.handleAuthSuccess(ctx, "hmac-authenticated-user")
}

// handleAuthSuccess handles successful authentication
func (p *BasicAuthPolicy) handleAuthSuccess(ctx *policy.RequestContext, username string) policy.RequestAction {
	// Set metadata indicating successful authentication
	ctx.Metadata[MetadataKeyAuthSuccess] = true
	ctx.Metadata[MetadataKeyAuthUser] = username
	ctx.Metadata[MetadataKeyAuthMethod] = "basic"

	// Continue to upstream with no modifications
	return policy.UpstreamRequestModifications{}
}

// OnResponse is not used by this policy (authentication is request-only)
func (p *BasicAuthPolicy) OnResponse(ctx *policy.ResponseContext, params map[string]interface{}) policy.ResponseAction {
	return nil // No response processing needed
}

// generateHMAC generates an HMAC signature for the given message using the specified algorithm and secret key
func generateHMAC(message, secretKey, algorithm string) (string, error) {
	var h func() hash.Hash

	switch strings.ToLower(algorithm) {
	case "sha256", "hmac-sha256":
		h = sha256.New
	case "sha512", "hmac-sha512":
		h = sha512.New
	case "sha384", "hmac-sha384":
		h = sha512.New384
	default:
		return "", fmt.Errorf("unsupported algorithm: %s", algorithm)
	}

	mac := hmac.New(h, []byte(secretKey))
	mac.Write([]byte(message))
	signature := mac.Sum(nil)

	// Return base64-encoded signature (can also use hex encoding if preferred)
	return base64.StdEncoding.EncodeToString(signature), nil
}

// generateHMACHex generates an HMAC signature and returns it as a hex string
func generateHMACHex(message, secretKey, algorithm string) (string, error) {
	var h func() hash.Hash

	switch strings.ToLower(algorithm) {
	case "sha256", "hmac-sha256":
		h = sha256.New
	case "sha512", "hmac-sha512":
		h = sha512.New
	case "sha384", "hmac-sha384":
		h = sha512.New384
	default:
		return "", fmt.Errorf("unsupported algorithm: %s", algorithm)
	}

	mac := hmac.New(h, []byte(secretKey))
	mac.Write([]byte(message))
	signature := mac.Sum(nil)

	return hex.EncodeToString(signature), nil
}

// handleAuthFailure handles authentication failure
func (p *BasicAuthPolicy) handleHmacFailure(ctx *policy.RequestContext, allowUnauthenticated bool, reason string) policy.RequestAction {
	// Set metadata indicating failed authentication
	ctx.Metadata[MetadataKeyAuthSuccess] = false
	ctx.Metadata[MetadataKeyAuthMethod] = "hmac"

	// If allowUnauthenticated is true, allow request to proceed
	if allowUnauthenticated {
		return policy.UpstreamRequestModifications{}
	}

	// Return 401 Unauthorized response

	headers := map[string]string{
		"www-authenticate": fmt.Sprintf("Basic realm=\"%s\"", ""),
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
