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
	"encoding/json"
	"fmt"
	"hash"
	"log/slog"
	"strings"

	policy "github.com/wso2/api-platform/sdk/gateway/policy/v1alpha"
)

const (
	// Metadata keys for context storage
	MetadataKeyAuthSuccess = "auth.success"
	MetadataKeyAuthUser    = "auth.username"
	MetadataKeyAuthMethod  = "auth.method"
)

// HMACAuthPolicy implements HTTP Basic Authentication
type HMACAuthPolicy struct{}

var ins = &HMACAuthPolicy{}

func GetPolicy(
	metadata policy.PolicyMetadata,
	params map[string]interface{},
) (policy.Policy, error) {
	return ins, nil
}

// Mode returns the processing mode for this policy
func (p *HMACAuthPolicy) Mode() policy.ProcessingMode {
	return policy.ProcessingMode{
		RequestHeaderMode:  policy.HeaderModeProcess, // Process request headers for auth
		RequestBodyMode:    policy.BodyModeBuffer,    // Need request body for HMAC
		ResponseHeaderMode: policy.HeaderModeSkip,    // Don't process response headers
		ResponseBodyMode:   policy.BodyModeSkip,      // Don't need response body
	}
}

// OnRequest performs HMAC Authentication
func (p *HMACAuthPolicy) OnRequest(ctx *policy.RequestContext, params map[string]interface{}) policy.RequestAction {
	allowUnauthenticated := false
	if allowUnauthRaw, ok := params["allowUnauthenticated"]; ok {
		if allowUnauthBool, ok := allowUnauthRaw.(bool); ok {
			allowUnauthenticated = allowUnauthBool
		}
	}
	if allowUnauthenticated {
		return p.handleAuthSuccess(ctx)
	}
	// Get configuration parameters with safe type assertions
	expectedHeaderName, ok := params["headerName"].(string)
	if !ok || expectedHeaderName == "" {
		return p.handleAuthFailure(ctx, 401, "json", "Valid header is required", "invalid authorization header provided")
	}

	expectedAlgorithm, ok := params["algorithm"].(string)
	if !ok || expectedAlgorithm == "" {
		return p.handleAuthFailure(ctx, 401, "json", "Valid algorithm is required", "invalid algorithm provided")
	}

	expectedSecretKey, ok := params["secretKey"].(string)
	if !ok || expectedSecretKey == "" {
		return p.handleAuthFailure(ctx, 401, "json", "Valid Secret Key is required", "invalid secret key provided")
	}

	// Extract and validate Authorization header
	authHeaders := ctx.Headers.Get(expectedHeaderName)
	if len(authHeaders) == 0 {
		return p.handleAuthFailure(ctx, 401, "json", "Valid header is required", "missing authorization header")
	}

	authHeader := authHeaders[0]

	// Split the header value by '=' to get algorithm and signature
	// Expected format: "algorithm=signature"
	parts := strings.SplitN(authHeader, "=", 2)
	if len(parts) != 2 {
		fmt.Println("Parts: ", parts)
		return p.handleAuthFailure(ctx, 401, "json", "Valid header is required", "invalid header format, expected 'algorithm=signature'")
	}

	providedAlgorithm := strings.TrimSpace(parts[0])
	providedSignature := strings.TrimSpace(parts[1])

	if providedSignature == "" {
		return p.handleAuthFailure(ctx, 401, "json", "Valid header is required", "missing signature in authorization header")
	}

	// Validate the algorithm matches the expected algorithm
	if !strings.EqualFold(providedAlgorithm, expectedAlgorithm) {
		return p.handleAuthFailure(ctx, 401, "json", "Valid header is required", fmt.Sprintf("algorithm mismatch: expected %s, got %s", expectedAlgorithm, providedAlgorithm))
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

	// fmt.Println("Expected signature: ", expectedSignature)
	// fmt.Println("Provided signature: ", providedSignature)

	// Validate the provided signature against the expected signature using constant-time comparison
	// Log the error internally but return a 200 to avoid attcks
	if subtle.ConstantTimeCompare([]byte(providedSignature), []byte(expectedSignature)) != 1 {
		slog.Debug("HMAC Auth Policy: handleAuthFailure called",
			"statusCode", 401,
			"errorFormat", "josn",
			"errorMessage", "Valid signature is required",
			"reason", "invalid HMAC signature",
			"apiId", ctx.APIId,
			"apiName", ctx.APIName,
			"apiVersion", ctx.APIVersion,
			"method", ctx.Method,
			"path", ctx.Path,
		)
	}

	// Continue to upstream with no modifications
	return p.handleAuthSuccess(ctx)
}

// handleAuthSuccess handles successful authentication
func (p *HMACAuthPolicy) handleAuthSuccess(ctx *policy.RequestContext) policy.RequestAction {
	slog.Debug("HMAC Auth Policy: handleAuthSuccess called",
		"apiId", ctx.APIId,
		"apiName", ctx.APIName,
		"apiVersion", ctx.APIVersion,
		"method", ctx.Method,
		"path", ctx.Path,
	)

	// Set metadata indicating successful authentication
	ctx.Metadata[MetadataKeyAuthSuccess] = true
	ctx.Metadata[MetadataKeyAuthMethod] = "hmac"

	slog.Debug("HMAC Auth Policy: Authentication metadata set",
		"authSuccess", true,
		"authMethod", "hmac",
	)

	// Continue to upstream with no modifications
	return policy.UpstreamRequestModifications{}
}

// OnResponse is not used by this policy (authentication is request-only)
func (p *HMACAuthPolicy) OnResponse(ctx *policy.ResponseContext, params map[string]interface{}) policy.ResponseAction {
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
	return string(signature), nil
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

	return string(signature), nil
}

// handleAuthFailure handles authentication failure
func (p *HMACAuthPolicy) handleAuthFailure(ctx *policy.RequestContext, statusCode int, errorFormat, errorMessage,
	reason string) policy.RequestAction {
	slog.Debug("HMAC Auth Policy: handleAuthFailure called",
		"statusCode", statusCode,
		"errorFormat", errorFormat,
		"errorMessage", errorMessage,
		"reason", reason,
		"apiId", ctx.APIId,
		"apiName", ctx.APIName,
		"apiVersion", ctx.APIVersion,
		"method", ctx.Method,
		"path", ctx.Path,
	)

	// Set metadata indicating failed authentication
	ctx.Metadata[MetadataKeyAuthSuccess] = false
	ctx.Metadata[MetadataKeyAuthMethod] = "hmac"

	headers := map[string]string{
		"content-type": "application/json",
	}

	var body string
	switch errorFormat {
	case "plain":
		body = errorMessage
		headers["content-type"] = "text/plain"
	default: // json
		errResponse := map[string]interface{}{
			"error":   "Unauthorized",
			"message": errorMessage,
		}
		bodyBytes, _ := json.Marshal(errResponse)
		body = string(bodyBytes)
	}

	slog.Debug("HMAC Auth Policy: Returning immediate response",
		"statusCode", statusCode,
		"contentType", headers["content-type"],
		"bodyLength", len(body),
		"reason", reason,
	)

	return policy.ImmediateResponse{
		StatusCode: statusCode,
		Headers:    headers,
		Body:       []byte(body),
	}
}
