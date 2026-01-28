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
	"encoding/base64"
	"encoding/json"
	"hash"
	"strings"
	"testing"

	policy "github.com/wso2/api-platform/sdk/gateway/policy/v1alpha"
)

// Test constants
const (
	testSecretKey  = "my-secret-key-123"
	testHeaderName = "X-HMAC-Signature"
	testBody       = `{"message": "hello world"}`
)

// TestGetPolicy tests that GetPolicy returns a valid policy instance
func TestGetPolicy(t *testing.T) {
	p, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{})
	if err != nil {
		t.Fatalf("GetPolicy returned error: %v", err)
	}
	if p == nil {
		t.Fatal("GetPolicy returned nil policy")
	}
}

// TestMode tests the policy processing mode configuration
func TestMode(t *testing.T) {
	p := &BasicAuthPolicy{}
	mode := p.Mode()

	if mode.RequestHeaderMode != policy.HeaderModeProcess {
		t.Errorf("Expected RequestHeaderMode to be HeaderModeProcess, got %v", mode.RequestHeaderMode)
	}
	if mode.RequestBodyMode != policy.BodyModeBuffer {
		t.Errorf("Expected RequestBodyMode to be BodyModeBuffer, got %v", mode.RequestBodyMode)
	}
	if mode.ResponseHeaderMode != policy.HeaderModeSkip {
		t.Errorf("Expected ResponseHeaderMode to be HeaderModeSkip, got %v", mode.ResponseHeaderMode)
	}
	if mode.ResponseBodyMode != policy.BodyModeSkip {
		t.Errorf("Expected ResponseBodyMode to be BodyModeSkip, got %v", mode.ResponseBodyMode)
	}
}

// TestOnRequest_ValidHMAC tests successful HMAC authentication with valid signature
func TestOnRequest_ValidHMAC(t *testing.T) {
	testCases := []struct {
		name      string
		algorithm string
	}{
		{"SHA256", "sha256"},
		{"HMAC-SHA256", "hmac-sha256"},
		{"SHA512", "sha512"},
		{"HMAC-SHA512", "hmac-sha512"},
		{"SHA384", "sha384"},
		{"HMAC-SHA384", "hmac-sha384"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Generate valid HMAC signature
			signature := generateTestHMAC(t, testBody, testSecretKey, tc.algorithm)
			headerValue := tc.algorithm + "=" + signature

			ctx := createMockRequestContext(
				map[string][]string{
					testHeaderName: {headerValue},
				},
				[]byte(testBody),
			)

			params := map[string]interface{}{
				"headerName": testHeaderName,
				"algorithm":  tc.algorithm,
				"secretKey":  testSecretKey,
			}

			p := &BasicAuthPolicy{}
			action := p.OnRequest(ctx, params)

			// Verify successful authentication
			if ctx.Metadata[MetadataKeyAuthSuccess] != true {
				t.Errorf("Expected auth.success to be true, got %v", ctx.Metadata[MetadataKeyAuthSuccess])
			}

			if ctx.Metadata[MetadataKeyAuthUser] != "hmac-authenticated-user" {
				t.Errorf("Expected auth.username to be 'hmac-authenticated-user', got %v", ctx.Metadata[MetadataKeyAuthUser])
			}

			if ctx.Metadata[MetadataKeyAuthMethod] != "basic" {
				t.Errorf("Expected auth.method to be 'basic', got %v", ctx.Metadata[MetadataKeyAuthMethod])
			}

			// Verify it's an UpstreamRequestModifications action (continue to upstream)
			_, ok := action.(policy.UpstreamRequestModifications)
			if !ok {
				t.Fatalf("Expected UpstreamRequestModifications, got %T", action)
			}
		})
	}
}

// TestOnRequest_MissingHeader tests authentication failure when HMAC header is missing
func TestOnRequest_MissingHeader(t *testing.T) {
	ctx := createMockRequestContext(
		map[string][]string{},
		[]byte(testBody),
	)

	params := map[string]interface{}{
		"headerName": testHeaderName,
		"algorithm":  "sha256",
		"secretKey":  testSecretKey,
	}

	p := &BasicAuthPolicy{}
	action := p.OnRequest(ctx, params)

	// Verify authentication failed
	if ctx.Metadata[MetadataKeyAuthSuccess] != false {
		t.Errorf("Expected auth.success to be false, got %v", ctx.Metadata[MetadataKeyAuthSuccess])
	}

	if ctx.Metadata[MetadataKeyAuthMethod] != "hmac" {
		t.Errorf("Expected auth.method to be 'hmac', got %v", ctx.Metadata[MetadataKeyAuthMethod])
	}

	// Verify it's an ImmediateResponse with 401
	response, ok := action.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("Expected ImmediateResponse, got %T", action)
	}

	if response.StatusCode != 401 {
		t.Errorf("Expected status code 401, got %d", response.StatusCode)
	}

	// Verify response body
	var errBody map[string]string
	if err := json.Unmarshal(response.Body, &errBody); err != nil {
		t.Fatalf("Failed to unmarshal error body: %v", err)
	}

	if errBody["error"] != "Unauthorized" {
		t.Errorf("Expected error to be 'Unauthorized', got %s", errBody["error"])
	}
}

// TestOnRequest_InvalidHeaderFormat tests authentication failure with malformed header
func TestOnRequest_InvalidHeaderFormat(t *testing.T) {
	testCases := []struct {
		name        string
		headerValue string
	}{
		{"No equals sign", "sha256signature"},
		{"Empty value", ""},
		{"Only algorithm", "sha256="},
		{"Only signature", "=abc123"},
		{"Multiple equals", "sha256=value=extra"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := createMockRequestContext(
				map[string][]string{
					testHeaderName: {tc.headerValue},
				},
				[]byte(testBody),
			)

			params := map[string]interface{}{
				"headerName": testHeaderName,
				"algorithm":  "sha256",
				"secretKey":  testSecretKey,
			}

			p := &BasicAuthPolicy{}
			action := p.OnRequest(ctx, params)

			// Verify authentication failed
			if ctx.Metadata[MetadataKeyAuthSuccess] != false {
				t.Errorf("Expected auth.success to be false, got %v", ctx.Metadata[MetadataKeyAuthSuccess])
			}

			// Verify it's an ImmediateResponse with 401
			response, ok := action.(policy.ImmediateResponse)
			if !ok {
				t.Fatalf("Expected ImmediateResponse, got %T", action)
			}

			if response.StatusCode != 401 {
				t.Errorf("Expected status code 401, got %d", response.StatusCode)
			}
		})
	}
}

// TestOnRequest_AlgorithmMismatch tests authentication failure when algorithm doesn't match
func TestOnRequest_AlgorithmMismatch(t *testing.T) {
	signature := generateTestHMAC(t, testBody, testSecretKey, "sha256")
	headerValue := "sha512=" + signature // Using sha512 in header but signature is sha256

	ctx := createMockRequestContext(
		map[string][]string{
			testHeaderName: {headerValue},
		},
		[]byte(testBody),
	)

	params := map[string]interface{}{
		"headerName": testHeaderName,
		"algorithm":  "sha256", // Expected sha256
		"secretKey":  testSecretKey,
	}

	p := &BasicAuthPolicy{}
	action := p.OnRequest(ctx, params)

	// Verify authentication failed
	if ctx.Metadata[MetadataKeyAuthSuccess] != false {
		t.Errorf("Expected auth.success to be false, got %v", ctx.Metadata[MetadataKeyAuthSuccess])
	}

	// Verify it's an ImmediateResponse with 401
	response, ok := action.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("Expected ImmediateResponse, got %T", action)
	}

	if response.StatusCode != 401 {
		t.Errorf("Expected status code 401, got %d", response.StatusCode)
	}
}

// TestOnRequest_InvalidSignature tests authentication failure with wrong signature
func TestOnRequest_InvalidSignature(t *testing.T) {
	// Use a wrong secret key to generate an invalid signature
	invalidSignature := generateTestHMAC(t, testBody, "wrong-secret-key", "sha256")
	headerValue := "sha256=" + invalidSignature

	ctx := createMockRequestContext(
		map[string][]string{
			testHeaderName: {headerValue},
		},
		[]byte(testBody),
	)

	params := map[string]interface{}{
		"headerName": testHeaderName,
		"algorithm":  "sha256",
		"secretKey":  testSecretKey,
	}

	p := &BasicAuthPolicy{}
	action := p.OnRequest(ctx, params)

	// Verify authentication failed
	if ctx.Metadata[MetadataKeyAuthSuccess] != false {
		t.Errorf("Expected auth.success to be false, got %v", ctx.Metadata[MetadataKeyAuthSuccess])
	}

	// Verify it's an ImmediateResponse with 401
	response, ok := action.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("Expected ImmediateResponse, got %T", action)
	}

	if response.StatusCode != 401 {
		t.Errorf("Expected status code 401, got %d", response.StatusCode)
	}
}

// TestOnRequest_TamperedBody tests that changing the body invalidates signature
func TestOnRequest_TamperedBody(t *testing.T) {
	originalBody := `{"message": "hello world"}`
	tamperedBody := `{"message": "hello world modified"}`

	// Generate signature for original body
	signature := generateTestHMAC(t, originalBody, testSecretKey, "sha256")
	headerValue := "sha256=" + signature

	// But use tampered body in request
	ctx := createMockRequestContext(
		map[string][]string{
			testHeaderName: {headerValue},
		},
		[]byte(tamperedBody),
	)

	params := map[string]interface{}{
		"headerName": testHeaderName,
		"algorithm":  "sha256",
		"secretKey":  testSecretKey,
	}

	p := &BasicAuthPolicy{}
	action := p.OnRequest(ctx, params)

	// Verify authentication failed
	if ctx.Metadata[MetadataKeyAuthSuccess] != false {
		t.Errorf("Expected auth.success to be false for tampered body, got %v", ctx.Metadata[MetadataKeyAuthSuccess])
	}

	response, ok := action.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("Expected ImmediateResponse, got %T", action)
	}

	if response.StatusCode != 401 {
		t.Errorf("Expected status code 401, got %d", response.StatusCode)
	}
}

// TestOnRequest_AllowUnauthenticated tests that requests proceed when allowUnauthenticated is true
func TestOnRequest_AllowUnauthenticated(t *testing.T) {
	ctx := createMockRequestContext(
		map[string][]string{}, // No header
		[]byte(testBody),
	)

	params := map[string]interface{}{
		"headerName":           testHeaderName,
		"algorithm":            "sha256",
		"secretKey":            testSecretKey,
		"allowUnauthenticated": true,
	}

	p := &BasicAuthPolicy{}
	action := p.OnRequest(ctx, params)

	// Verify auth failed but request continues
	if ctx.Metadata[MetadataKeyAuthSuccess] != false {
		t.Errorf("Expected auth.success to be false, got %v", ctx.Metadata[MetadataKeyAuthSuccess])
	}

	// Should continue to upstream despite missing auth
	_, ok := action.(policy.UpstreamRequestModifications)
	if !ok {
		t.Fatalf("Expected UpstreamRequestModifications when allowUnauthenticated is true, got %T", action)
	}
}

// TestOnRequest_MissingConfiguration tests error handling for missing config parameters
func TestOnRequest_MissingConfiguration(t *testing.T) {
	testCases := []struct {
		name          string
		params        map[string]interface{}
		expectedError string
	}{
		{
			name:          "Missing headerName",
			params:        map[string]interface{}{"algorithm": "sha256", "secretKey": testSecretKey},
			expectedError: "headerName must be a non-empty string",
		},
		{
			name:          "Empty headerName",
			params:        map[string]interface{}{"headerName": "", "algorithm": "sha256", "secretKey": testSecretKey},
			expectedError: "headerName must be a non-empty string",
		},
		{
			name:          "Missing algorithm",
			params:        map[string]interface{}{"headerName": testHeaderName, "secretKey": testSecretKey},
			expectedError: "algorithm must be a non-empty string",
		},
		{
			name:          "Empty algorithm",
			params:        map[string]interface{}{"headerName": testHeaderName, "algorithm": "", "secretKey": testSecretKey},
			expectedError: "algorithm must be a non-empty string",
		},
		{
			name:          "Missing secretKey",
			params:        map[string]interface{}{"headerName": testHeaderName, "algorithm": "sha256"},
			expectedError: "secretKey must be a non-empty string",
		},
		{
			name:          "Empty secretKey",
			params:        map[string]interface{}{"headerName": testHeaderName, "algorithm": "sha256", "secretKey": ""},
			expectedError: "secretKey must be a non-empty string",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := createMockRequestContext(
				map[string][]string{},
				[]byte(testBody),
			)

			p := &BasicAuthPolicy{}
			action := p.OnRequest(ctx, tc.params)

			// Verify it's an ImmediateResponse with 500
			response, ok := action.(policy.ImmediateResponse)
			if !ok {
				t.Fatalf("Expected ImmediateResponse, got %T", action)
			}

			if response.StatusCode != 500 {
				t.Errorf("Expected status code 500, got %d", response.StatusCode)
			}

			// Verify error message
			var errBody map[string]string
			if err := json.Unmarshal(response.Body, &errBody); err != nil {
				t.Fatalf("Failed to unmarshal error body: %v", err)
			}

			if !strings.Contains(errBody["message"], tc.expectedError) {
				t.Errorf("Expected error message to contain '%s', got '%s'", tc.expectedError, errBody["message"])
			}
		})
	}
}

// TestOnRequest_UnsupportedAlgorithm tests error handling for unsupported algorithms
func TestOnRequest_UnsupportedAlgorithm(t *testing.T) {
	signature := "some-signature"
	headerValue := "md5=" + signature

	ctx := createMockRequestContext(
		map[string][]string{
			testHeaderName: {headerValue},
		},
		[]byte(testBody),
	)

	params := map[string]interface{}{
		"headerName": testHeaderName,
		"algorithm":  "md5", // Unsupported algorithm
		"secretKey":  testSecretKey,
	}

	p := &BasicAuthPolicy{}
	action := p.OnRequest(ctx, params)

	// Verify it's an ImmediateResponse with 500
	response, ok := action.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("Expected ImmediateResponse, got %T", action)
	}

	if response.StatusCode != 500 {
		t.Errorf("Expected status code 500, got %d", response.StatusCode)
	}

	// Verify error message mentions unsupported algorithm
	var errBody map[string]string
	if err := json.Unmarshal(response.Body, &errBody); err != nil {
		t.Fatalf("Failed to unmarshal error body: %v", err)
	}

	if !strings.Contains(errBody["message"], "Failed to generate HMAC") {
		t.Errorf("Expected error message to mention HMAC generation failure, got '%s'", errBody["message"])
	}
}

// TestOnRequest_CaseInsensitiveAlgorithm tests that algorithm comparison is case-insensitive
func TestOnRequest_CaseInsensitiveAlgorithm(t *testing.T) {
	signature := generateTestHMAC(t, testBody, testSecretKey, "sha256")
	headerValue := "SHA256=" + signature // Uppercase in header

	ctx := createMockRequestContext(
		map[string][]string{
			testHeaderName: {headerValue},
		},
		[]byte(testBody),
	)

	params := map[string]interface{}{
		"headerName": testHeaderName,
		"algorithm":  "sha256", // Lowercase in config
		"secretKey":  testSecretKey,
	}

	p := &BasicAuthPolicy{}
	action := p.OnRequest(ctx, params)

	// Verify successful authentication
	if ctx.Metadata[MetadataKeyAuthSuccess] != true {
		t.Errorf("Expected auth.success to be true, got %v", ctx.Metadata[MetadataKeyAuthSuccess])
	}

	// Verify it's an UpstreamRequestModifications action
	_, ok := action.(policy.UpstreamRequestModifications)
	if !ok {
		t.Fatalf("Expected UpstreamRequestModifications, got %T", action)
	}
}

// TestOnRequest_EmptyBody tests HMAC validation with empty request body
func TestOnRequest_EmptyBody(t *testing.T) {
	emptyBody := ""
	signature := generateTestHMAC(t, emptyBody, testSecretKey, "sha256")
	headerValue := "sha256=" + signature

	ctx := createMockRequestContext(
		map[string][]string{
			testHeaderName: {headerValue},
		},
		[]byte(emptyBody),
	)

	params := map[string]interface{}{
		"headerName": testHeaderName,
		"algorithm":  "sha256",
		"secretKey":  testSecretKey,
	}

	p := &BasicAuthPolicy{}
	action := p.OnRequest(ctx, params)

	// Verify successful authentication
	if ctx.Metadata[MetadataKeyAuthSuccess] != true {
		t.Errorf("Expected auth.success to be true, got %v", ctx.Metadata[MetadataKeyAuthSuccess])
	}

	_, ok := action.(policy.UpstreamRequestModifications)
	if !ok {
		t.Fatalf("Expected UpstreamRequestModifications, got %T", action)
	}
}

// TestOnRequest_LargeBody tests HMAC validation with large request body
func TestOnRequest_LargeBody(t *testing.T) {
	// Generate a large body (1MB)
	largeBody := strings.Repeat("abcdefghij", 100*1024)
	signature := generateTestHMAC(t, largeBody, testSecretKey, "sha256")
	headerValue := "sha256=" + signature

	ctx := createMockRequestContext(
		map[string][]string{
			testHeaderName: {headerValue},
		},
		[]byte(largeBody),
	)

	params := map[string]interface{}{
		"headerName": testHeaderName,
		"algorithm":  "sha256",
		"secretKey":  testSecretKey,
	}

	p := &BasicAuthPolicy{}
	action := p.OnRequest(ctx, params)

	// Verify successful authentication
	if ctx.Metadata[MetadataKeyAuthSuccess] != true {
		t.Errorf("Expected auth.success to be true, got %v", ctx.Metadata[MetadataKeyAuthSuccess])
	}

	_, ok := action.(policy.UpstreamRequestModifications)
	if !ok {
		t.Fatalf("Expected UpstreamRequestModifications, got %T", action)
	}
}

// TestOnResponse tests that OnResponse returns nil (no-op)
func TestOnResponse(t *testing.T) {
	p := &BasicAuthPolicy{}
	ctx := &policy.ResponseContext{
		SharedContext: &policy.SharedContext{
			RequestID: "test-request-id",
			Metadata:  make(map[string]interface{}),
		},
	}
	action := p.OnResponse(ctx, map[string]interface{}{})

	if action != nil {
		t.Errorf("Expected OnResponse to return nil, got %v", action)
	}
}

// TestGenerateHMAC tests the generateHMAC function directly
func TestGenerateHMAC(t *testing.T) {
	testCases := []struct {
		name      string
		algorithm string
		wantErr   bool
	}{
		{"sha256", "sha256", false},
		{"hmac-sha256", "hmac-sha256", false},
		{"sha512", "sha512", false},
		{"hmac-sha512", "hmac-sha512", false},
		{"sha384", "sha384", false},
		{"hmac-sha384", "hmac-sha384", false},
		{"uppercase SHA256", "SHA256", false},
		{"uppercase HMAC-SHA256", "HMAC-SHA256", false},
		{"unsupported md5", "md5", true},
		{"invalid algorithm", "invalid-algo", true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			signature, err := generateHMAC("test message", "secret", tc.algorithm)

			if tc.wantErr {
				if err == nil {
					t.Errorf("Expected error for algorithm %s, got nil", tc.algorithm)
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error for algorithm %s: %v", tc.algorithm, err)
				}
				if signature == "" {
					t.Errorf("Expected non-empty signature for algorithm %s", tc.algorithm)
				}
				// Verify it's valid base64
				if _, err := base64.StdEncoding.DecodeString(signature); err != nil {
					t.Errorf("Signature is not valid base64: %v", err)
				}
			}
		})
	}
}

// TestGenerateHMAC_Deterministic tests that HMAC generation is deterministic
func TestGenerateHMAC_Deterministic(t *testing.T) {
	message := "test message"
	secret := "test secret"
	algorithm := "sha256"

	sig1, err1 := generateHMAC(message, secret, algorithm)
	sig2, err2 := generateHMAC(message, secret, algorithm)

	if err1 != nil || err2 != nil {
		t.Fatalf("Unexpected errors: %v, %v", err1, err2)
	}

	if sig1 != sig2 {
		t.Errorf("Expected deterministic signatures, got %s and %s", sig1, sig2)
	}
}

// TestGenerateHMAC_DifferentInputs tests that different inputs produce different signatures
func TestGenerateHMAC_DifferentInputs(t *testing.T) {
	secret := "test secret"
	algorithm := "sha256"

	sig1, _ := generateHMAC("message1", secret, algorithm)
	sig2, _ := generateHMAC("message2", secret, algorithm)

	if sig1 == sig2 {
		t.Errorf("Expected different signatures for different messages")
	}

	sig3, _ := generateHMAC("message1", "secret1", algorithm)
	sig4, _ := generateHMAC("message1", "secret2", algorithm)

	if sig3 == sig4 {
		t.Errorf("Expected different signatures for different secrets")
	}
}

// TestGenerateHMACHex tests the generateHMACHex function directly
func TestGenerateHMACHex(t *testing.T) {
	testCases := []struct {
		name      string
		algorithm string
		wantErr   bool
	}{
		{"sha256", "sha256", false},
		{"sha512", "sha512", false},
		{"sha384", "sha384", false},
		{"unsupported md5", "md5", true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			signature, err := generateHMACHex("test message", "secret", tc.algorithm)

			if tc.wantErr {
				if err == nil {
					t.Errorf("Expected error for algorithm %s, got nil", tc.algorithm)
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error for algorithm %s: %v", tc.algorithm, err)
				}
				if signature == "" {
					t.Errorf("Expected non-empty signature for algorithm %s", tc.algorithm)
				}
				// Verify it's valid hex
				for _, c := range signature {
					if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
						t.Errorf("Expected hex string, got invalid character: %c", c)
						break
					}
				}
			}
		})
	}
}

// TestHandleAuthSuccess tests successful authentication metadata
func TestHandleAuthSuccess(t *testing.T) {
	ctx := createMockRequestContext(map[string][]string{}, nil)

	p := &BasicAuthPolicy{}
	action := p.handleAuthSuccess(ctx, "test-user")

	if ctx.Metadata[MetadataKeyAuthSuccess] != true {
		t.Errorf("Expected auth.success to be true")
	}
	if ctx.Metadata[MetadataKeyAuthUser] != "test-user" {
		t.Errorf("Expected auth.username to be 'test-user', got %v", ctx.Metadata[MetadataKeyAuthUser])
	}
	if ctx.Metadata[MetadataKeyAuthMethod] != "basic" {
		t.Errorf("Expected auth.method to be 'basic', got %v", ctx.Metadata[MetadataKeyAuthMethod])
	}

	_, ok := action.(policy.UpstreamRequestModifications)
	if !ok {
		t.Fatalf("Expected UpstreamRequestModifications, got %T", action)
	}
}

// TestHandleHmacFailure tests failed authentication metadata and response
func TestHandleHmacFailure(t *testing.T) {
	ctx := createMockRequestContext(map[string][]string{}, nil)

	p := &BasicAuthPolicy{}
	action := p.handleHmacFailure(ctx, false, "test failure reason")

	if ctx.Metadata[MetadataKeyAuthSuccess] != false {
		t.Errorf("Expected auth.success to be false")
	}
	if ctx.Metadata[MetadataKeyAuthMethod] != "hmac" {
		t.Errorf("Expected auth.method to be 'hmac', got %v", ctx.Metadata[MetadataKeyAuthMethod])
	}

	response, ok := action.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("Expected ImmediateResponse, got %T", action)
	}

	if response.StatusCode != 401 {
		t.Errorf("Expected status code 401, got %d", response.StatusCode)
	}

	if response.Headers["content-type"] != "application/json" {
		t.Errorf("Expected content-type to be application/json, got %s", response.Headers["content-type"])
	}
}

// Helper functions

// createMockRequestContext creates a mock request context for testing
func createMockRequestContext(headers map[string][]string, body []byte) *policy.RequestContext {
	var requestBody *policy.Body
	if body != nil {
		requestBody = &policy.Body{Content: body}
	}

	return &policy.RequestContext{
		SharedContext: &policy.SharedContext{
			RequestID: "test-request-id",
			Metadata:  make(map[string]interface{}),
		},
		Headers: policy.NewHeaders(headers),
		Body:    requestBody,
		Path:    "/api/test",
		Method:  "POST",
	}
}

// generateTestHMAC generates an HMAC signature for testing
func generateTestHMAC(t *testing.T, message, secretKey, algorithm string) string {
	t.Helper()

	var h func() hash.Hash
	switch strings.ToLower(algorithm) {
	case "sha256", "hmac-sha256":
		h = sha256.New
	case "sha512", "hmac-sha512":
		h = sha512.New
	case "sha384", "hmac-sha384":
		h = sha512.New384
	default:
		t.Fatalf("Unsupported algorithm in test: %s", algorithm)
	}

	mac := hmac.New(h, []byte(secretKey))
	mac.Write([]byte(message))
	signature := mac.Sum(nil)

	return base64.StdEncoding.EncodeToString(signature)
}
