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

package jwtauth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

// TestJWTAuthPolicy_ValidToken tests successful JWT authentication
func TestJWTAuthPolicy_ValidToken(t *testing.T) {
	// Generate test keys
	privateKey, publicKey := generateTestKeys(t)

	// Create JWKS server
	jwksServer := createJWKSServer(t, publicKey, "test-kid")
	defer jwksServer.Close()

	// Create test token
	token := createTestToken(t, privateKey, map[string]interface{}{
		"sub":   "user123",
		"iss":   "https://issuer.example.com",
		"aud":   "api-audience",
		"scope": "read write",
		"name":  "John Doe",
	})

	// Create request context with Authorization header
	ctx := createMockRequestHeaderContext(map[string][]string{
		"authorization": {fmt.Sprintf("Bearer %s", token)},
	})

	// Create params
	params := map[string]interface{}{
		"headerName":             "Authorization",
		"authHeaderScheme":       "Bearer",
		"onFailureStatusCode":    401,
		"errorMessageFormat":     "json",
		"leeway":                 "30s",
		"allowedAlgorithms":      []interface{}{"RS256", "ES256"},
		"jwksCacheTtl":           "5m",
		"jwksFetchTimeout":       "5s",
		"jwksFetchRetryCount":    3,
		"jwksFetchRetryInterval": "2s",
		"keyManagers": []interface{}{
			map[string]interface{}{
				"name":   "test-issuer",
				"issuer": "https://issuer.example.com",
				"jwks": map[string]interface{}{
					"remote": map[string]interface{}{
						"uri": jwksServer.URL + "/jwks.json",
					},
				},
			},
		},
		"audiences":      []interface{}{"api-audience"},
		"requiredScopes": []interface{}{"read"},
		"claimMappings": map[string]interface{}{
			"sub":  "X-User-ID",
			"name": "X-User-Name",
		},
	}

	p, err := GetPolicy(policy.PolicyMetadata{}, params)
	if err != nil {
		t.Fatalf("Failed to create policy: %v", err)
	}

	// Execute policy
	action := p.(*JwtAuthPolicy).OnRequestHeaders(context.Background(), ctx, params)

	// Verify successful authentication
	if ctx.SharedContext.AuthContext == nil || !ctx.SharedContext.AuthContext.Authenticated {
		t.Errorf("Expected AuthContext.Authenticated=true")
	}
	if ctx.SharedContext.AuthContext != nil && ctx.SharedContext.AuthContext.AuthType != "jwt" {
		t.Errorf("Expected AuthType='jwt', got %q", ctx.SharedContext.AuthContext.AuthType)
	}

	// Verify it's an UpstreamRequestHeaderModifications action
	modifications, ok := action.(policy.UpstreamRequestHeaderModifications)
	if !ok {
		t.Fatalf("Expected UpstreamRequestHeaderModifications, got %T", action)
	}

	// Verify claim mappings were applied as headers
	if modifications.HeadersToSet["X-User-ID"] != "user123" {
		t.Errorf("Expected X-User-ID header to be 'user123', got %s", modifications.HeadersToSet["X-User-ID"])
	}

	if modifications.HeadersToSet["X-User-Name"] != "John Doe" {
		t.Errorf("Expected X-User-Name header to be 'John Doe', got %s", modifications.HeadersToSet["X-User-Name"])
	}

	// forwardToken defaults to true and forwardedTokenHeader defaults to x-forwarded-authorization,
	// so the token is renamed: Authorization is removed and x-forwarded-authorization is set.
	foundRemoved := false
	for _, h := range modifications.HeadersToRemove {
		if strings.EqualFold(h, "Authorization") {
			foundRemoved = true
			break
		}
	}
	if !foundRemoved {
		t.Errorf("Expected Authorization header to be removed (renamed to x-forwarded-authorization), HeadersToRemove=%v", modifications.HeadersToRemove)
	}
	if modifications.HeadersToSet["X-Forwarded-Authorization"] == "" {
		t.Errorf("Expected x-forwarded-authorization header to be set with token value, HeadersToSet=%v", modifications.HeadersToSet)
	}
}

// TestJWTAuthPolicy_ForwardTokenFalse verifies the Authorization header is stripped
// from the upstream request when forwardToken=false.
func TestJWTAuthPolicy_ForwardTokenFalse(t *testing.T) {
	privateKey, publicKey := generateTestKeys(t)
	jwksServer := createJWKSServer(t, publicKey, "test-kid")
	defer jwksServer.Close()

	token := createTestToken(t, privateKey, map[string]interface{}{
		"sub": "user123",
		"iss": "https://issuer.example.com",
		"aud": "api-audience",
	})

	ctx := createMockRequestHeaderContext(map[string][]string{
		"authorization": {fmt.Sprintf("Bearer %s", token)},
	})

	params := map[string]interface{}{
		"headerName":          "Authorization",
		"authHeaderScheme":    "Bearer",
		"onFailureStatusCode": 401,
		"errorMessageFormat":  "json",
		"leeway":              "30s",
		"allowedAlgorithms":   []interface{}{"RS256", "ES256"},
		"forwardToken":        false,
		"keyManagers": []interface{}{
			map[string]interface{}{
				"name":   "test-issuer",
				"issuer": "https://issuer.example.com",
				"jwks": map[string]interface{}{
					"remote": map[string]interface{}{
						"uri": jwksServer.URL + "/jwks.json",
					},
				},
			},
		},
		"audiences": []interface{}{"api-audience"},
	}

	p, err := GetPolicy(policy.PolicyMetadata{}, params)
	if err != nil {
		t.Fatalf("Failed to create policy: %v", err)
	}

	action := p.(*JwtAuthPolicy).OnRequestHeaders(context.Background(), ctx, params)

	modifications, ok := action.(policy.UpstreamRequestHeaderModifications)
	if !ok {
		t.Fatalf("Expected UpstreamRequestHeaderModifications, got %T", action)
	}

	found := false
	for _, h := range modifications.HeadersToRemove {
		if strings.EqualFold(h, "Authorization") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Expected Authorization header to be stripped when forwardToken=false, HeadersToRemove=%v", modifications.HeadersToRemove)
	}
}

// TestJWTAuthPolicy_ForwardTokenStripScheme verifies that when forwardTokenStripScheme is true,
// the bare token value (scheme prefix stripped) is forwarded under forwardedTokenHeader.
func TestJWTAuthPolicy_ForwardTokenStripScheme(t *testing.T) {
	privateKey, publicKey := generateTestKeys(t)
	jwksServer := createJWKSServer(t, publicKey, "test-kid")
	defer jwksServer.Close()

	token := createTestToken(t, privateKey, map[string]interface{}{
		"sub": "user123",
		"iss": "https://issuer.example.com",
		"aud": "api-audience",
	})

	ctx := createMockRequestHeaderContext(map[string][]string{
		"authorization": {fmt.Sprintf("Bearer %s", token)},
	})

	params := map[string]interface{}{
		"headerName":           "Authorization",
		"authHeaderScheme":     "Bearer",
		"onFailureStatusCode":  401,
		"errorMessageFormat":   "json",
		"leeway":               "30s",
		"allowedAlgorithms":    []interface{}{"RS256", "ES256"},
		"forwardTokenStripScheme":    true,
		"forwardedTokenHeader": "X-My-Token",
		"keyManagers": []interface{}{
			map[string]interface{}{
				"name":   "test-issuer",
				"issuer": "https://issuer.example.com",
				"jwks": map[string]interface{}{
					"remote": map[string]interface{}{
						"uri": jwksServer.URL + "/jwks.json",
					},
				},
			},
		},
		"audiences": []interface{}{"api-audience"},
	}

	p, err := GetPolicy(policy.PolicyMetadata{}, params)
	if err != nil {
		t.Fatalf("Failed to create policy: %v", err)
	}

	action := p.(*JwtAuthPolicy).OnRequestHeaders(context.Background(), ctx, params)

	modifications, ok := action.(policy.UpstreamRequestHeaderModifications)
	if !ok {
		t.Fatalf("Expected UpstreamRequestHeaderModifications, got %T", action)
	}

	// The forwarded header must carry the bare token, without the "Bearer " prefix.
	got := modifications.HeadersToSet["X-My-Token"]
	if got != token {
		t.Errorf("Expected X-My-Token to be the bare token %q, got %q", token, got)
	}
	if strings.Contains(got, "Bearer") {
		t.Errorf("Expected X-My-Token to not contain the scheme prefix, got %q", got)
	}

	// The original Authorization header must be removed (renamed).
	foundRemoved := false
	for _, h := range modifications.HeadersToRemove {
		if strings.EqualFold(h, "Authorization") {
			foundRemoved = true
			break
		}
	}
	if !foundRemoved {
		t.Errorf("Expected Authorization header to be removed, HeadersToRemove=%v", modifications.HeadersToRemove)
	}
}

// TestJWTAuthPolicy_ForwardTokenStripSchemeSameHeader verifies that when forwardTokenStripScheme is
// true and the forwarded header equals the source header, the header is overwritten
// in place with the prefix-stripped value (not removed).
func TestJWTAuthPolicy_ForwardTokenStripSchemeSameHeader(t *testing.T) {
	privateKey, publicKey := generateTestKeys(t)
	jwksServer := createJWKSServer(t, publicKey, "test-kid")
	defer jwksServer.Close()

	token := createTestToken(t, privateKey, map[string]interface{}{
		"sub": "user123",
		"iss": "https://issuer.example.com",
		"aud": "api-audience",
	})

	ctx := createMockRequestHeaderContext(map[string][]string{
		"authorization": {fmt.Sprintf("Bearer %s", token)},
	})

	params := map[string]interface{}{
		"headerName":           "Authorization",
		"authHeaderScheme":     "Bearer",
		"leeway":               "30s",
		"allowedAlgorithms":    []interface{}{"RS256", "ES256"},
		"forwardTokenStripScheme":    true,
		"forwardedTokenHeader": "Authorization",
		"keyManagers": []interface{}{
			map[string]interface{}{
				"name":   "test-issuer",
				"issuer": "https://issuer.example.com",
				"jwks": map[string]interface{}{
					"remote": map[string]interface{}{
						"uri": jwksServer.URL + "/jwks.json",
					},
				},
			},
		},
		"audiences": []interface{}{"api-audience"},
	}

	p, err := GetPolicy(policy.PolicyMetadata{}, params)
	if err != nil {
		t.Fatalf("Failed to create policy: %v", err)
	}

	action := p.(*JwtAuthPolicy).OnRequestHeaders(context.Background(), ctx, params)

	modifications, ok := action.(policy.UpstreamRequestHeaderModifications)
	if !ok {
		t.Fatalf("Expected UpstreamRequestHeaderModifications, got %T", action)
	}

	if got := modifications.HeadersToSet["Authorization"]; got != token {
		t.Errorf("Expected Authorization to be overwritten with bare token %q, got %q", token, got)
	}
	for _, h := range modifications.HeadersToRemove {
		if strings.EqualFold(h, "Authorization") {
			t.Errorf("Did not expect Authorization to be removed when forwarded under the same name, HeadersToRemove=%v", modifications.HeadersToRemove)
		}
	}
}

// TestJWTAuthPolicy_ForwardTokenStripSchemeDefaultOff verifies that with forwardTokenStripScheme
// unset (default false), the full header value (including prefix) is forwarded.
func TestJWTAuthPolicy_ForwardTokenStripSchemeDefaultOff(t *testing.T) {
	privateKey, publicKey := generateTestKeys(t)
	jwksServer := createJWKSServer(t, publicKey, "test-kid")
	defer jwksServer.Close()

	token := createTestToken(t, privateKey, map[string]interface{}{
		"sub": "user123",
		"iss": "https://issuer.example.com",
		"aud": "api-audience",
	})

	ctx := createMockRequestHeaderContext(map[string][]string{
		"authorization": {fmt.Sprintf("Bearer %s", token)},
	})

	params := map[string]interface{}{
		"headerName":           "Authorization",
		"authHeaderScheme":     "Bearer",
		"leeway":               "30s",
		"allowedAlgorithms":    []interface{}{"RS256", "ES256"},
		"forwardedTokenHeader": "X-My-Token",
		"keyManagers": []interface{}{
			map[string]interface{}{
				"name":   "test-issuer",
				"issuer": "https://issuer.example.com",
				"jwks": map[string]interface{}{
					"remote": map[string]interface{}{
						"uri": jwksServer.URL + "/jwks.json",
					},
				},
			},
		},
		"audiences": []interface{}{"api-audience"},
	}

	p, err := GetPolicy(policy.PolicyMetadata{}, params)
	if err != nil {
		t.Fatalf("Failed to create policy: %v", err)
	}

	action := p.(*JwtAuthPolicy).OnRequestHeaders(context.Background(), ctx, params)

	modifications, ok := action.(policy.UpstreamRequestHeaderModifications)
	if !ok {
		t.Fatalf("Expected UpstreamRequestHeaderModifications, got %T", action)
	}

	// Default behavior forwards the full header value, including the scheme prefix.
	want := fmt.Sprintf("Bearer %s", token)
	if got := modifications.HeadersToSet["X-My-Token"]; got != want {
		t.Errorf("Expected X-My-Token to be the full header value %q, got %q", want, got)
	}
}

// TestJWTAuthPolicy_MissingToken tests authentication failure when Authorization header is missing
func TestJWTAuthPolicy_MissingToken(t *testing.T) {
	// Create request context without Authorization header
	ctx := createMockRequestHeaderContext(map[string][]string{})

	params := map[string]interface{}{
		"headerName":          "Authorization",
		"authHeaderScheme":    "Bearer",
		"onFailureStatusCode": 401,
		"errorMessageFormat":  "json",
		"leeway":              "30s",
		"allowedAlgorithms":   []interface{}{"RS256"},
		"keyManagers": []interface{}{
			map[string]interface{}{
				"name": "test-issuer",
				"jwks": map[string]interface{}{
					"remote": map[string]interface{}{
						"remote": map[string]interface{}{"uri": "http://localhost:8888/jwks.json"},
					},
				},
			},
		},
	}

	p, err := GetPolicy(policy.PolicyMetadata{}, params)
	if err != nil {
		t.Fatalf("Failed to create policy: %v", err)
	}

	action := p.(*JwtAuthPolicy).OnRequestHeaders(context.Background(), ctx, params)

	// Verify authentication failed
	if ctx.SharedContext.AuthContext == nil || ctx.SharedContext.AuthContext.Authenticated {
		t.Errorf("Expected AuthContext.Authenticated=false")
	}

	// Verify it's an ImmediateResponse
	response, ok := action.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("Expected ImmediateResponse, got %T", action)
	}

	if response.StatusCode != 401 {
		t.Errorf("Expected status code 401, got %d", response.StatusCode)
	}
}

// TestJWTAuthPolicy_InvalidTokenFormat tests with malformed token
func TestJWTAuthPolicy_InvalidTokenFormat(t *testing.T) {
	ctx := createMockRequestHeaderContext(map[string][]string{
		"authorization": {"Bearer invalid.token"},
	})

	params := map[string]interface{}{
		"headerName":          "Authorization",
		"authHeaderScheme":    "Bearer",
		"onFailureStatusCode": 401,
		"errorMessageFormat":  "json",
		"allowedAlgorithms":   []interface{}{"RS256"},
		"keyManagers": []interface{}{
			map[string]interface{}{
				"name": "test-issuer",
				"jwks": map[string]interface{}{
					"remote": map[string]interface{}{"uri": "http://localhost:8888/jwks.json"},
				},
			},
		},
	}

	p, err := GetPolicy(policy.PolicyMetadata{}, params)
	if err != nil {
		t.Fatalf("Failed to create policy: %v", err)
	}

	action := p.(*JwtAuthPolicy).OnRequestHeaders(context.Background(), ctx, params)

	if ctx.SharedContext.AuthContext == nil || ctx.SharedContext.AuthContext.Authenticated {
		t.Errorf("Expected AuthContext.Authenticated=false for invalid token format")
	}

	_, ok := action.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("Expected ImmediateResponse for invalid token, got %T", action)
	}
}

// TestJWTAuthPolicy_ExpiredToken tests with expired token
func TestJWTAuthPolicy_ExpiredToken(t *testing.T) {
	privateKey, publicKey := generateTestKeys(t)
	jwksServer := createJWKSServer(t, publicKey, "test-kid")
	defer jwksServer.Close()

	// Create expired token (expired 1 hour ago)
	expiredTime := time.Now().Add(-time.Hour)
	token := createTestTokenWithExpiry(t, privateKey, map[string]interface{}{
		"sub": "user123",
		"iss": "https://issuer.example.com",
	}, expiredTime)

	ctx := createMockRequestHeaderContext(map[string][]string{
		"authorization": {fmt.Sprintf("Bearer %s", token)},
	})

	params := map[string]interface{}{
		"headerName":        "Authorization",
		"authHeaderScheme":  "Bearer",
		"leeway":            "30s",
		"allowedAlgorithms": []interface{}{"RS256"},
		"keyManagers": []interface{}{
			map[string]interface{}{
				"name": "test-issuer",
				"jwks": map[string]interface{}{
					"remote": map[string]interface{}{"uri": jwksServer.URL + "/jwks.json"},
				},
			},
		},
	}

	p, err := GetPolicy(policy.PolicyMetadata{}, params)
	if err != nil {
		t.Fatalf("Failed to create policy: %v", err)
	}

	action := p.(*JwtAuthPolicy).OnRequestHeaders(context.Background(), ctx, params)

	if ctx.SharedContext.AuthContext == nil || ctx.SharedContext.AuthContext.Authenticated {
		t.Errorf("Expected AuthContext.Authenticated=false for expired token")
	}

	_, ok := action.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("Expected ImmediateResponse for expired token")
	}
}

// TestJWTAuthPolicy_InvalidAudience tests audience validation
func TestJWTAuthPolicy_InvalidAudience(t *testing.T) {
	privateKey, publicKey := generateTestKeys(t)
	jwksServer := createJWKSServer(t, publicKey, "test-kid")
	defer jwksServer.Close()

	token := createTestToken(t, privateKey, map[string]interface{}{
		"sub": "user123",
		"aud": "wrong-audience",
		"iss": "https://issuer.example.com",
	})

	ctx := createMockRequestHeaderContext(map[string][]string{
		"authorization": {fmt.Sprintf("Bearer %s", token)},
	})

	params := map[string]interface{}{
		"headerName":        "Authorization",
		"authHeaderScheme":  "Bearer",
		"allowedAlgorithms": []interface{}{"RS256"},
		"audiences":         []interface{}{"api-audience"},
		"keyManagers": []interface{}{
			map[string]interface{}{
				"name": "test-issuer",
				"jwks": map[string]interface{}{
					"remote": map[string]interface{}{"uri": jwksServer.URL + "/jwks.json"},
				},
			},
		},
	}

	p, err := GetPolicy(policy.PolicyMetadata{}, params)
	if err != nil {
		t.Fatalf("Failed to create policy: %v", err)
	}

	action := p.(*JwtAuthPolicy).OnRequestHeaders(context.Background(), ctx, params)

	if ctx.SharedContext.AuthContext == nil || ctx.SharedContext.AuthContext.Authenticated {
		t.Errorf("Expected AuthContext.Authenticated=false for invalid audience")
	}

	_, ok := action.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("Expected ImmediateResponse for invalid audience")
	}
}

// TestJWTAuthPolicy_CustomClaims tests custom required claims validation
func TestJWTAuthPolicy_CustomClaims(t *testing.T) {
	privateKey, publicKey := generateTestKeys(t)
	jwksServer := createJWKSServer(t, publicKey, "test-kid")
	defer jwksServer.Close()

	token := createTestToken(t, privateKey, map[string]interface{}{
		"sub":  "user123",
		"role": "admin",
		"iss":  "https://issuer.example.com",
	})

	ctx := createMockRequestHeaderContext(map[string][]string{
		"authorization": {fmt.Sprintf("Bearer %s", token)},
	})

	params := map[string]interface{}{
		"headerName":        "Authorization",
		"authHeaderScheme":  "Bearer",
		"allowedAlgorithms": []interface{}{"RS256"},
		"requiredClaims": map[string]interface{}{
			"role": "admin",
		},
		"keyManagers": []interface{}{
			map[string]interface{}{
				"name": "test-issuer",
				"jwks": map[string]interface{}{
					"remote": map[string]interface{}{"uri": jwksServer.URL + "/jwks.json"},
				},
			},
		},
	}

	p, err := GetPolicy(policy.PolicyMetadata{}, params)
	if err != nil {
		t.Fatalf("Failed to create policy: %v", err)
	}

	action := p.(*JwtAuthPolicy).OnRequestHeaders(context.Background(), ctx, params)

	if ctx.SharedContext.AuthContext == nil || !ctx.SharedContext.AuthContext.Authenticated {
		t.Errorf("Expected AuthContext.Authenticated=true when required claims match")
	}

	_, ok := action.(policy.UpstreamRequestHeaderModifications)
	if !ok {
		t.Fatalf("Expected UpstreamRequestHeaderModifications for valid token with matching claims")
	}
}

// TestJWTAuthPolicy_InvalidCustomClaims tests failure with invalid required claims
func TestJWTAuthPolicy_InvalidCustomClaims(t *testing.T) {
	privateKey, publicKey := generateTestKeys(t)
	jwksServer := createJWKSServer(t, publicKey, "test-kid")
	defer jwksServer.Close()

	token := createTestToken(t, privateKey, map[string]interface{}{
		"sub":  "user123",
		"role": "user",
		"iss":  "https://issuer.example.com",
	})

	ctx := createMockRequestHeaderContext(map[string][]string{
		"authorization": {fmt.Sprintf("Bearer %s", token)},
	})

	params := map[string]interface{}{
		"headerName":        "Authorization",
		"authHeaderScheme":  "Bearer",
		"allowedAlgorithms": []interface{}{"RS256"},
		"requiredClaims": map[string]interface{}{
			"role": "admin",
		},
		"keyManagers": []interface{}{
			map[string]interface{}{
				"name": "test-issuer",
				"jwks": map[string]interface{}{
					"remote": map[string]interface{}{"uri": jwksServer.URL + "/jwks.json"},
				},
			},
		},
	}

	p, err := GetPolicy(policy.PolicyMetadata{}, params)
	if err != nil {
		t.Fatalf("Failed to create policy: %v", err)
	}

	action := p.(*JwtAuthPolicy).OnRequestHeaders(context.Background(), ctx, params)

	if ctx.SharedContext.AuthContext == nil || ctx.SharedContext.AuthContext.Authenticated {
		t.Errorf("Expected AuthContext.Authenticated=false for mismatched required claims")
	}

	_, ok := action.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("Expected ImmediateResponse for invalid claims")
	}
}

// TestJWTAuthPolicy_InvalidSignature tests rejection of token signed with wrong key
func TestJWTAuthPolicy_InvalidSignature(t *testing.T) {
	// Generate two different key pairs
	_, validPublicKey := generateTestKeys(t)
	invalidPrivateKey, _ := generateTestKeys(t)

	// Create JWKS server with the VALID public key
	jwksServer := createJWKSServer(t, validPublicKey, "test-kid")
	defer jwksServer.Close()

	// Create token signed with the INVALID private key
	token := createTestToken(t, invalidPrivateKey, map[string]interface{}{
		"sub": "user123",
		"iss": "https://issuer.example.com",
	})

	ctx := createMockRequestHeaderContext(map[string][]string{
		"authorization": {fmt.Sprintf("Bearer %s", token)},
	})

	params := map[string]interface{}{
		"headerName":        "Authorization",
		"authHeaderScheme":  "Bearer",
		"allowedAlgorithms": []interface{}{"RS256"},
		"keyManagers": []interface{}{
			map[string]interface{}{
				"name": "test-issuer",
				"jwks": map[string]interface{}{
					"remote": map[string]interface{}{"uri": jwksServer.URL + "/jwks.json"},
				},
			},
		},
	}

	p, err := GetPolicy(policy.PolicyMetadata{}, params)
	if err != nil {
		t.Fatalf("Failed to create policy: %v", err)
	}

	action := p.(*JwtAuthPolicy).OnRequestHeaders(context.Background(), ctx, params)

	// Should fail because signature doesn't match the JWKS public key
	if ctx.SharedContext.AuthContext == nil || ctx.SharedContext.AuthContext.Authenticated {
		t.Errorf("Expected AuthContext.Authenticated=false for token signed with invalid key")
	}

	response, ok := action.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("Expected ImmediateResponse for invalid signature, got %T", action)
	}

	if response.StatusCode != 401 {
		t.Errorf("Expected status code 401, got %d", response.StatusCode)
	}
}

// TestJWTAuthPolicy_CustomHeaderPrefix tests custom Authorization header prefix
func TestJWTAuthPolicy_CustomHeaderPrefix(t *testing.T) {
	privateKey, publicKey := generateTestKeys(t)
	jwksServer := createJWKSServer(t, publicKey, "test-kid")
	defer jwksServer.Close()

	token := createTestToken(t, privateKey, map[string]interface{}{
		"sub": "user123",
		"iss": "https://issuer.example.com",
	})

	ctx := createMockRequestHeaderContext(map[string][]string{
		"authorization": {fmt.Sprintf("JWT %s", token)},
	})

	params := map[string]interface{}{
		"headerName":        "Authorization",
		"authHeaderScheme":  "Bearer", // System default
		"authHeaderPrefix":  "JWT",    // User override
		"allowedAlgorithms": []interface{}{"RS256"},
		"keyManagers": []interface{}{
			map[string]interface{}{
				"name": "test-issuer",
				"jwks": map[string]interface{}{
					"remote": map[string]interface{}{"uri": jwksServer.URL + "/jwks.json"},
				},
			},
		},
	}

	p, err := GetPolicy(policy.PolicyMetadata{}, params)
	if err != nil {
		t.Fatalf("Failed to create policy: %v", err)
	}

	action := p.(*JwtAuthPolicy).OnRequestHeaders(context.Background(), ctx, params)

	if ctx.SharedContext.AuthContext == nil || !ctx.SharedContext.AuthContext.Authenticated {
		t.Errorf("Expected AuthContext.Authenticated=true with custom prefix override")
	}

	_, ok := action.(policy.UpstreamRequestHeaderModifications)
	if !ok {
		t.Fatalf("Expected UpstreamRequestHeaderModifications with custom header prefix")
	}
}

// TestJWTAuthPolicy_ErrorResponseFormat tests different error response formats
func TestJWTAuthPolicy_ErrorResponseFormatJSON(t *testing.T) {
	ctx := createMockRequestHeaderContext(map[string][]string{})

	params := map[string]interface{}{
		"errorMessageFormat":  "json",
		"onFailureStatusCode": 401,
		"allowedAlgorithms":   []interface{}{"RS256"},
		"keyManagers": []interface{}{
			map[string]interface{}{
				"name": "test-issuer",
				"jwks": map[string]interface{}{
					"remote": map[string]interface{}{"uri": "http://localhost:8888/jwks.json"},
				},
			},
		},
	}

	p, err := GetPolicy(policy.PolicyMetadata{}, params)
	if err != nil {
		t.Fatalf("Failed to create policy: %v", err)
	}

	action := p.(*JwtAuthPolicy).OnRequestHeaders(context.Background(), ctx, params)

	response := action.(policy.ImmediateResponse)
	if response.Headers["content-type"] != "application/json" {
		t.Errorf("Expected content-type to be application/json")
	}

	var errBody map[string]interface{}
	if err := json.Unmarshal(response.Body, &errBody); err != nil {
		t.Errorf("Expected JSON error response, got: %s", string(response.Body))
	}
}

func TestJWTAuthPolicy_ErrorResponseFormatPlain(t *testing.T) {
	ctx := createMockRequestHeaderContext(map[string][]string{})

	params := map[string]interface{}{
		"errorMessageFormat":  "plain",
		"onFailureStatusCode": 401,
		"allowedAlgorithms":   []interface{}{"RS256"},
		"keyManagers": []interface{}{
			map[string]interface{}{
				"name": "test-issuer",
				"jwks": map[string]interface{}{
					"remote": map[string]interface{}{"uri": "http://localhost:8888/jwks.json"},
				},
			},
		},
	}

	p, err := GetPolicy(policy.PolicyMetadata{}, params)
	if err != nil {
		t.Fatalf("Failed to create policy: %v", err)
	}

	action := p.(*JwtAuthPolicy).OnRequestHeaders(context.Background(), ctx, params)

	response := action.(policy.ImmediateResponse)
	if response.Headers["content-type"] != "text/plain" {
		t.Errorf("Expected content-type to be text/plain")
	}
}

// TestJWTAuthPolicy_RemoteWithSelfSignedCert tests JWT validation with remote JWKS and self-signed certificate configuration
func TestJWTAuthPolicy_RemoteWithSelfSignedCert(t *testing.T) {
	// Generate test keys
	privateKey, publicKey := generateTestKeys(t)

	// Create an unstarted HTTPS server (without TLS yet)
	unstarted := createHTTPSJWKSServerUnstarted(t, publicKey, "test-kid")

	// Create a self-signed certificate for localhost (the server will be on localhost)
	certKeyPath, _, caPath := createSelfSignedCertForHost(t, "https://localhost:443")
	defer func() {
		parts := strings.Split(certKeyPath, ":")
		if len(parts) == 2 {
			os.Remove(parts[0])
			os.Remove(parts[1])
		}
		os.Remove(caPath)
	}()

	// Load the certificate and configure TLS on the server
	parts := strings.Split(certKeyPath, ":")
	if len(parts) != 2 {
		t.Fatalf("Expected cert:key format, got %s", certKeyPath)
	}

	tlsCert, err := tls.LoadX509KeyPair(parts[0], parts[1])
	if err != nil {
		t.Fatalf("Failed to load TLS certificate: %v", err)
	}

	unstarted.TLS = &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
	}

	// Now start the HTTPS server
	unstarted.StartTLS()
	jwksServer := unstarted
	defer jwksServer.Close()

	// Create test token
	token := createTestToken(t, privateKey, map[string]interface{}{
		"sub": "user123",
		"iss": "https://issuer.example.com",
		"aud": "api-audience",
	})

	// Create request context
	ctx := createMockRequestHeaderContext(map[string][]string{
		"authorization": {fmt.Sprintf("Bearer %s", token)},
	})

	// Create params with certificate path to validate self-signed JWKS endpoint
	params := map[string]interface{}{
		"headerName":          "Authorization",
		"authHeaderScheme":    "Bearer",
		"onFailureStatusCode": 401,
		"errorMessageFormat":  "json",
		"leeway":              "30s",
		"allowedAlgorithms":   []interface{}{"RS256"},
		"keyManagers": []interface{}{
			map[string]interface{}{
				"name":   "test-issuer",
				"issuer": "https://issuer.example.com",
				"jwks": map[string]interface{}{
					"remote": map[string]interface{}{
						"uri":             jwksServer.URL + "/jwks.json",
						"certificatePath": caPath, // CA certificate for validating self-signed JWKS endpoint
					},
				},
			},
		},
		"audiences": []interface{}{"api-audience"},
	}

	p, err := GetPolicy(policy.PolicyMetadata{}, params)
	if err != nil {
		t.Fatalf("Failed to create policy: %v", err)
	}

	// Execute policy
	action := p.(*JwtAuthPolicy).OnRequestHeaders(context.Background(), ctx, params)

	// Verify successful authentication - token validated against self-signed JWKS
	if ctx.SharedContext.AuthContext == nil || !ctx.SharedContext.AuthContext.Authenticated {
		t.Errorf("Expected AuthContext.Authenticated=true with self-signed certificate")
	}

	// Verify it's an UpstreamRequestHeaderModifications action
	if _, ok := action.(policy.UpstreamRequestHeaderModifications); !ok {
		t.Fatalf("Expected UpstreamRequestHeaderModifications, got %T", action)
	}
}

// TestJWTAuthPolicy_SkipTlsVerify_Success tests JWT validation when skipTlsVerify is true with self-signed JWKS endpoint
func TestJWTAuthPolicy_SkipTlsVerify_Success(t *testing.T) {
	// Generate test keys
	privateKey, publicKey := generateTestKeys(t)

	// Create an unstarted HTTPS server
	unstarted := createHTTPSJWKSServerUnstarted(t, publicKey, "test-kid")

	// Create a self-signed certificate for localhost
	certKeyPath, _, caPath := createSelfSignedCertForHost(t, "https://localhost:443")
	defer func() {
		parts := strings.Split(certKeyPath, ":")
		if len(parts) == 2 {
			os.Remove(parts[0])
			os.Remove(parts[1])
		}
		os.Remove(caPath)
	}()

	// Load the certificate and configure TLS on the server
	parts := strings.Split(certKeyPath, ":")
	if len(parts) != 2 {
		t.Fatalf("Expected cert:key format, got %s", certKeyPath)
	}

	tlsCert, err := tls.LoadX509KeyPair(parts[0], parts[1])
	if err != nil {
		t.Fatalf("Failed to load TLS certificate: %v", err)
	}

	unstarted.TLS = &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
	}

	// Start the HTTPS server
	unstarted.StartTLS()
	jwksServer := unstarted
	defer jwksServer.Close()

	// Create test token
	token := createTestToken(t, privateKey, map[string]interface{}{
		"sub": "user123",
		"iss": "https://issuer.example.com",
		"aud": "api-audience",
	})

	// Create request context
	ctx := createMockRequestHeaderContext(map[string][]string{
		"authorization": {fmt.Sprintf("Bearer %s", token)},
	})

	// Create params with skipTlsVerify=true (no certificatePath needed)
	params := map[string]interface{}{
		"headerName":          "Authorization",
		"authHeaderScheme":    "Bearer",
		"onFailureStatusCode": 401,
		"errorMessageFormat":  "json",
		"leeway":              "30s",
		"allowedAlgorithms":   []interface{}{"RS256"},
		"keyManagers": []interface{}{
			map[string]interface{}{
				"name":   "test-issuer",
				"issuer": "https://issuer.example.com",
				"jwks": map[string]interface{}{
					"remote": map[string]interface{}{
						"uri":           jwksServer.URL + "/jwks.json",
						"skipTlsVerify": true, // Skip TLS verification
					},
				},
			},
		},
		"audiences": []interface{}{"api-audience"},
	}

	p, err := GetPolicy(policy.PolicyMetadata{}, params)
	if err != nil {
		t.Fatalf("Failed to create policy: %v", err)
	}

	// Execute policy
	action := p.(*JwtAuthPolicy).OnRequestHeaders(context.Background(), ctx, params)

	// Verify successful authentication - TLS verification was skipped
	if ctx.SharedContext.AuthContext == nil || !ctx.SharedContext.AuthContext.Authenticated {
		t.Errorf("Expected AuthContext.Authenticated=true with skipTlsVerify=true")
	}

	// Verify it's an UpstreamRequestHeaderModifications action
	if _, ok := action.(policy.UpstreamRequestHeaderModifications); !ok {
		t.Fatalf("Expected UpstreamRequestHeaderModifications, got %T", action)
	}
}

// TestJWTAuthPolicy_SkipTlsVerify_False_Fails tests JWT validation fails when skipTlsVerify is false with self-signed JWKS endpoint
func TestJWTAuthPolicy_SkipTlsVerify_False_Fails(t *testing.T) {
	// Generate test keys
	privateKey, publicKey := generateTestKeys(t)

	// Create an unstarted HTTPS server
	unstarted := createHTTPSJWKSServerUnstarted(t, publicKey, "test-kid")

	// Create a self-signed certificate for localhost
	certKeyPath, _, caPath := createSelfSignedCertForHost(t, "https://localhost:443")
	defer func() {
		parts := strings.Split(certKeyPath, ":")
		if len(parts) == 2 {
			os.Remove(parts[0])
			os.Remove(parts[1])
		}
		os.Remove(caPath)
	}()

	// Load the certificate and configure TLS on the server
	parts := strings.Split(certKeyPath, ":")
	if len(parts) != 2 {
		t.Fatalf("Expected cert:key format, got %s", certKeyPath)
	}

	tlsCert, err := tls.LoadX509KeyPair(parts[0], parts[1])
	if err != nil {
		t.Fatalf("Failed to load TLS certificate: %v", err)
	}

	unstarted.TLS = &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
	}

	// Start the HTTPS server
	unstarted.StartTLS()
	jwksServer := unstarted
	defer jwksServer.Close()

	// Create test token
	token := createTestToken(t, privateKey, map[string]interface{}{
		"sub": "user123",
		"iss": "https://issuer.example.com",
		"aud": "api-audience",
	})

	// Create request context
	ctx := createMockRequestHeaderContext(map[string][]string{
		"authorization": {fmt.Sprintf("Bearer %s", token)},
	})

	// Create params WITHOUT skipTlsVerify or certificatePath - should fail TLS verification
	params := map[string]interface{}{
		"headerName":          "Authorization",
		"authHeaderScheme":    "Bearer",
		"onFailureStatusCode": 401,
		"errorMessageFormat":  "json",
		"leeway":              "30s",
		"allowedAlgorithms":   []interface{}{"RS256"},
		"keyManagers": []interface{}{
			map[string]interface{}{
				"name":   "test-issuer",
				"issuer": "https://issuer.example.com",
				"jwks": map[string]interface{}{
					"remote": map[string]interface{}{
						"uri":           jwksServer.URL + "/jwks.json",
						"skipTlsVerify": false, // Explicitly set to false (default)
					},
				},
			},
		},
		"audiences":           []interface{}{"api-audience"},
		"jwksFetchRetryCount": 0,
	}

	p, err := GetPolicy(policy.PolicyMetadata{}, params)
	if err != nil {
		t.Fatalf("Failed to create policy: %v", err)
	}

	// Execute policy
	action := p.(*JwtAuthPolicy).OnRequestHeaders(context.Background(), ctx, params)

	// Verify authentication failed - TLS verification should fail for self-signed cert
	if ctx.SharedContext.AuthContext == nil || ctx.SharedContext.AuthContext.Authenticated {
		t.Errorf("Expected AuthContext.Authenticated=false with skipTlsVerify=false and self-signed cert")
	}

	// Verify it's an ImmediateResponse (error)
	response, ok := action.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("Expected ImmediateResponse for TLS verification failure, got %T", action)
	}

	if response.StatusCode != 401 {
		t.Errorf("Expected status code 401, got %d", response.StatusCode)
	}
}

// TestJWTAuthPolicy_LocalInlineCertificate tests JWT validation with inline certificate
func TestJWTAuthPolicy_LocalInlineCertificate(t *testing.T) {
	// Generate test keys
	privateKey, publicKey := generateTestKeys(t)

	// Create test token
	token := createTestToken(t, privateKey, map[string]interface{}{
		"sub": "user123",
		"iss": "https://issuer.example.com",
		"aud": "api-audience",
	})

	// Convert public key to PEM format for inline use
	pubKeyPEM := publicKeyToPEM(t, publicKey)

	// Create request context
	ctx := createMockRequestHeaderContext(map[string][]string{
		"authorization": {fmt.Sprintf("Bearer %s", token)},
	})

	// Create params with inline certificate
	params := map[string]interface{}{
		"headerName":          "Authorization",
		"authHeaderScheme":    "Bearer",
		"onFailureStatusCode": 401,
		"errorMessageFormat":  "json",
		"leeway":              "30s",
		"allowedAlgorithms":   []interface{}{"RS256"},
		"keyManagers": []interface{}{
			map[string]interface{}{
				"name":   "test-issuer",
				"issuer": "https://issuer.example.com",
				"jwks": map[string]interface{}{
					"local": map[string]interface{}{
						"inline": pubKeyPEM,
					},
				},
			},
		},
		"audiences": []interface{}{"api-audience"},
	}

	p, err := GetPolicy(policy.PolicyMetadata{}, params)
	if err != nil {
		t.Fatalf("Failed to create policy: %v", err)
	}

	// Execute policy
	action := p.(*JwtAuthPolicy).OnRequestHeaders(context.Background(), ctx, params)

	// Verify successful authentication
	if ctx.SharedContext.AuthContext == nil || !ctx.SharedContext.AuthContext.Authenticated {
		t.Errorf("Expected AuthContext.Authenticated=true with inline certificate")
	}

	// Verify it's an UpstreamRequestHeaderModifications action
	if _, ok := action.(policy.UpstreamRequestHeaderModifications); !ok {
		t.Fatalf("Expected UpstreamRequestHeaderModifications, got %T", action)
	}
}

// TestJWTAuthPolicy_LocalCertificateFile tests JWT validation with certificate file path
func TestJWTAuthPolicy_LocalCertificateFile(t *testing.T) {
	// Generate test keys
	privateKey, publicKey := generateTestKeys(t)

	// Create test token
	token := createTestToken(t, privateKey, map[string]interface{}{
		"sub": "user123",
		"iss": "https://issuer.example.com",
		"aud": "api-audience",
	})

	// Save public key to temporary file
	certPath := writeCertificateToFile(t, publicKey)
	defer os.Remove(certPath)

	// Create request context
	ctx := createMockRequestHeaderContext(map[string][]string{
		"authorization": {fmt.Sprintf("Bearer %s", token)},
	})

	// Create params with certificate file path
	params := map[string]interface{}{
		"headerName":          "Authorization",
		"authHeaderScheme":    "Bearer",
		"onFailureStatusCode": 401,
		"errorMessageFormat":  "json",
		"leeway":              "30s",
		"allowedAlgorithms":   []interface{}{"RS256"},
		"keyManagers": []interface{}{
			map[string]interface{}{
				"name":   "test-issuer",
				"issuer": "https://issuer.example.com",
				"jwks": map[string]interface{}{
					"local": map[string]interface{}{
						"certificatePath": certPath,
					},
				},
			},
		},
		"audiences": []interface{}{"api-audience"},
	}

	p, err := GetPolicy(policy.PolicyMetadata{}, params)
	if err != nil {
		t.Fatalf("Failed to create policy: %v", err)
	}

	// Execute policy
	action := p.(*JwtAuthPolicy).OnRequestHeaders(context.Background(), ctx, params)

	// Verify successful authentication
	if ctx.SharedContext.AuthContext == nil || !ctx.SharedContext.AuthContext.Authenticated {
		t.Errorf("Expected AuthContext.Authenticated=true with certificate file")
	}

	// Verify it's an UpstreamRequestHeaderModifications action
	if _, ok := action.(policy.UpstreamRequestHeaderModifications); !ok {
		t.Fatalf("Expected UpstreamRequestHeaderModifications, got %T", action)
	}
}

// Helper functions

func generateTestKeys(t *testing.T) (*rsa.PrivateKey, *rsa.PublicKey) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}
	return privateKey, &privateKey.PublicKey
}

func createTestToken(t *testing.T, privateKey *rsa.PrivateKey, claims map[string]interface{}) string {
	return createTestTokenWithExpiry(t, privateKey, claims, time.Now().Add(time.Hour))
}

func createTestTokenWithExpiry(t *testing.T, privateKey *rsa.PrivateKey, claims map[string]interface{}, expiryTime time.Time) string {
	// Set default claims
	if _, ok := claims["exp"]; !ok {
		claims["exp"] = expiryTime.Unix()
	}
	if _, ok := claims["iat"]; !ok {
		claims["iat"] = time.Now().Unix()
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims(claims))
	token.Header["kid"] = "test-kid"

	tokenString, err := token.SignedString(privateKey)
	if err != nil {
		t.Fatalf("Failed to sign token: %v", err)
	}

	return tokenString
}

func createJWKSServer(t *testing.T, publicKey *rsa.PublicKey, kid string) *httptest.Server {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/jwks.json" {
			// Extract N and E from public key
			nBytes := publicKey.N.Bytes()
			nB64 := base64.RawURLEncoding.EncodeToString(nBytes)

			// Encode E as big-endian bytes
			eBytes := make([]byte, 4)
			eBytes[0] = byte((publicKey.E >> 24) & 0xFF)
			eBytes[1] = byte((publicKey.E >> 16) & 0xFF)
			eBytes[2] = byte((publicKey.E >> 8) & 0xFF)
			eBytes[3] = byte(publicKey.E & 0xFF)
			// Remove leading zero bytes
			for len(eBytes) > 1 && eBytes[0] == 0 {
				eBytes = eBytes[1:]
			}
			eB64 := base64.RawURLEncoding.EncodeToString(eBytes)

			jwks := map[string]interface{}{
				"keys": []map[string]interface{}{
					{
						"kty": "RSA",
						"kid": kid,
						"use": "sig",
						"alg": "RS256",
						"n":   nB64,
						"e":   eB64,
					},
				},
			}

			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(jwks); err != nil {
				t.Logf("Failed to encode JWKS: %v", err)
			}
			return
		}

		w.WriteHeader(http.StatusNotFound)
	}))

	return server
}

// createMockRequestHeaderContext creates a v1alpha2 RequestHeaderContext for OnRequestHeaders tests.
func createMockRequestHeaderContext(headers map[string][]string) *policy.RequestHeaderContext {
	return &policy.RequestHeaderContext{
		SharedContext: &policy.SharedContext{
			RequestID: "test-request-id",
			Metadata:  make(map[string]interface{}),
		},
		Headers: policy.NewHeaders(headers),
		Path:    "/api/test",
		Method:  "GET",
	}
}

// createHTTPSJWKSServerUnstarted creates an unstarted HTTPS server for initial hostname detection
func createHTTPSJWKSServerUnstarted(t *testing.T, publicKey *rsa.PublicKey, kid string) *httptest.Server {
	return httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/jwks.json" {
			nBytes := publicKey.N.Bytes()
			nB64 := base64.RawURLEncoding.EncodeToString(nBytes)

			eBytes := make([]byte, 4)
			eBytes[0] = byte((publicKey.E >> 24) & 0xFF)
			eBytes[1] = byte((publicKey.E >> 16) & 0xFF)
			eBytes[2] = byte((publicKey.E >> 8) & 0xFF)
			eBytes[3] = byte(publicKey.E & 0xFF)
			for len(eBytes) > 1 && eBytes[0] == 0 {
				eBytes = eBytes[1:]
			}
			eB64 := base64.RawURLEncoding.EncodeToString(eBytes)

			jwks := map[string]interface{}{
				"keys": []map[string]interface{}{
					{
						"kty": "RSA",
						"kid": kid,
						"use": "sig",
						"alg": "RS256",
						"n":   nB64,
						"e":   eB64,
					},
				},
			}

			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(jwks); err != nil {
				t.Logf("Failed to encode JWKS: %v", err)
			}
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
}

// createSelfSignedCertForHost creates a self-signed certificate for a specific host
func createSelfSignedCertForHost(t *testing.T, hostURL string) (string, []byte, string) {
	// Parse the host from URL
	parsedURL, err := url.Parse(hostURL)
	if err != nil {
		t.Fatalf("Failed to parse URL: %v", err)
	}

	hostname := parsedURL.Hostname()
	if hostname == "" {
		hostname = "localhost"
	}

	// Generate RSA key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}

	// Create certificate template for the specific hostname
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test"},
			CommonName:   hostname,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              []string{hostname, "localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}

	// Create self-signed certificate
	certBytes, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	// Encode certificate to PEM
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})

	// Encode private key to PEM
	privKeyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatalf("Failed to marshal private key: %v", err)
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privKeyBytes,
	})

	// Write certificate to temporary file
	certFile, err := os.CreateTemp("", "test-cert-*.pem")
	if err != nil {
		t.Fatalf("Failed to create cert temporary file: %v", err)
	}
	defer certFile.Close()

	if _, err := certFile.Write(certPEM); err != nil {
		t.Fatalf("Failed to write certificate to file: %v", err)
	}

	// Write private key to temporary file
	keyFile, err := os.CreateTemp("", "test-key-*.pem")
	if err != nil {
		t.Fatalf("Failed to create key temporary file: %v", err)
	}
	defer keyFile.Close()

	if _, err := keyFile.Write(keyPEM); err != nil {
		t.Fatalf("Failed to write key to file: %v", err)
	}

	// Write CA cert to separate temporary file (for client validation)
	caFile, err := os.CreateTemp("", "test-ca-*.pem")
	if err != nil {
		t.Fatalf("Failed to create CA temp file: %v", err)
	}
	defer caFile.Close()

	if _, err := caFile.Write(certPEM); err != nil {
		t.Fatalf("Failed to write CA cert to file: %v", err)
	}

	return certFile.Name() + ":" + keyFile.Name(), certPEM, caFile.Name()
}

// createHTTPSJWKSServer creates an HTTPS JWKS endpoint with self-signed certificate
func createHTTPSJWKSServer(t *testing.T, publicKey *rsa.PublicKey, kid string, certKeyPath string) *httptest.Server {
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/jwks.json" {
			// Extract N and E from public key
			nBytes := publicKey.N.Bytes()
			nB64 := base64.RawURLEncoding.EncodeToString(nBytes)

			// Encode E as big-endian bytes
			eBytes := make([]byte, 4)
			eBytes[0] = byte((publicKey.E >> 24) & 0xFF)
			eBytes[1] = byte((publicKey.E >> 16) & 0xFF)
			eBytes[2] = byte((publicKey.E >> 8) & 0xFF)
			eBytes[3] = byte(publicKey.E & 0xFF)
			// Remove leading zero bytes
			for len(eBytes) > 1 && eBytes[0] == 0 {
				eBytes = eBytes[1:]
			}
			eB64 := base64.RawURLEncoding.EncodeToString(eBytes)

			jwks := map[string]interface{}{
				"keys": []map[string]interface{}{
					{
						"kty": "RSA",
						"kid": kid,
						"use": "sig",
						"alg": "RS256",
						"n":   nB64,
						"e":   eB64,
					},
				},
			}

			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(jwks); err != nil {
				t.Logf("Failed to encode JWKS: %v", err)
			}
			return
		}

		w.WriteHeader(http.StatusNotFound)
	}))

	// Parse cert:key format
	parts := strings.Split(certKeyPath, ":")
	if len(parts) != 2 {
		t.Fatalf("Expected cert:key format, got %s", certKeyPath)
	}

	// Load TLS certificate
	tlsCert, err := tls.LoadX509KeyPair(parts[0], parts[1])
	if err != nil {
		t.Fatalf("Failed to load TLS certificate: %v", err)
	}

	// Configure TLS for the server
	server.TLS = &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
	}

	server.StartTLS()
	return server
}

// publicKeyToPEM converts an RSA public key to PEM format
func publicKeyToPEM(t *testing.T, publicKey *rsa.PublicKey) string {
	pubBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		t.Fatalf("Failed to marshal public key: %v", err)
	}

	pubPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubBytes,
	})

	return string(pubPEM)
}

// writeCertificateToFile writes an RSA public key to a temporary file in PEM format
func writeCertificateToFile(t *testing.T, publicKey *rsa.PublicKey) string {
	pubKeyPEM := publicKeyToPEM(t, publicKey)

	tmpFile, err := os.CreateTemp("", "test-pubkey-*.pem")
	if err != nil {
		t.Fatalf("Failed to create temporary file: %v", err)
	}
	defer tmpFile.Close()

	if _, err := tmpFile.WriteString(pubKeyPEM); err != nil {
		t.Fatalf("Failed to write public key to file: %v", err)
	}

	return tmpFile.Name()
}

// TestJWTAuthPolicy_UserIdClaim_DefaultSub tests that user ID is extracted from 'sub' claim by default
func TestJWTAuthPolicy_UserIdClaim_DefaultSub(t *testing.T) {
	privateKey, publicKey := generateTestKeys(t)
	jwksServer := createJWKSServer(t, publicKey, "test-kid")
	defer jwksServer.Close()

	token := createTestToken(t, privateKey, map[string]interface{}{
		"sub": "user-12345",
		"iss": "https://issuer.example.com",
		"aud": "api-audience",
	})

	ctx := createMockRequestHeaderContext(map[string][]string{
		"authorization": {fmt.Sprintf("Bearer %s", token)},
	})

	params := map[string]interface{}{
		"headerName":        "Authorization",
		"authHeaderScheme":  "Bearer",
		"allowedAlgorithms": []interface{}{"RS256"},
		"audiences":         []interface{}{"api-audience"},
		"keyManagers": []interface{}{
			map[string]interface{}{
				"name": "test-issuer",
				"jwks": map[string]interface{}{
					"remote": map[string]interface{}{"uri": jwksServer.URL + "/jwks.json"},
				},
			},
		},
		// userIdClaim not specified, should default to "sub"
	}

	p, err := GetPolicy(policy.PolicyMetadata{}, params)
	if err != nil {
		t.Fatalf("GetPolicy failed: %v", err)
	}

	action := p.(*JwtAuthPolicy).OnRequestHeaders(context.Background(), ctx, params)

	if ctx.SharedContext.AuthContext == nil || !ctx.SharedContext.AuthContext.Authenticated {
		t.Fatalf("Expected AuthContext.Authenticated=true")
	}

	// Verify Subject was populated from 'sub' claim
	if ctx.SharedContext.AuthContext.Subject != "user-12345" {
		t.Errorf("Expected Subject='user-12345', got %q", ctx.SharedContext.AuthContext.Subject)
	}

	_, ok := action.(policy.UpstreamRequestHeaderModifications)
	if !ok {
		t.Fatalf("Expected UpstreamRequestHeaderModifications, got %T", action)
	}
}

// TestJWTAuthPolicy_UserIdClaim_CustomClaim tests that Subject is set from the configured
// userIdClaim ('user_id') when it is present in the token.
func TestJWTAuthPolicy_UserIdClaim_CustomClaim(t *testing.T) {
	privateKey, publicKey := generateTestKeys(t)
	jwksServer := createJWKSServer(t, publicKey, "test-kid")
	defer jwksServer.Close()

	token := createTestToken(t, privateKey, map[string]interface{}{
		"sub":     "user-sub-value",
		"email":   "testuser@example.com",
		"user_id": "custom-user-9999",
		"iss":     "https://issuer.example.com",
		"aud":     "api-audience",
	})

	ctx := createMockRequestHeaderContext(map[string][]string{
		"authorization": {fmt.Sprintf("Bearer %s", token)},
	})

	params := map[string]interface{}{
		"headerName":        "Authorization",
		"authHeaderScheme":  "Bearer",
		"allowedAlgorithms": []interface{}{"RS256"},
		"audiences":         []interface{}{"api-audience"},
		"userIdClaim":       "user_id", // Extract from custom claim
		"keyManagers": []interface{}{
			map[string]interface{}{
				"name": "test-issuer",
				"jwks": map[string]interface{}{
					"remote": map[string]interface{}{"uri": jwksServer.URL + "/jwks.json"},
				},
			},
		},
	}

	p, err := GetPolicy(policy.PolicyMetadata{}, params)
	if err != nil {
		t.Fatalf("GetPolicy failed: %v", err)
	}

	action := p.(*JwtAuthPolicy).OnRequestHeaders(context.Background(), ctx, params)

	if ctx.SharedContext.AuthContext == nil || !ctx.SharedContext.AuthContext.Authenticated {
		t.Fatalf("Expected AuthContext.Authenticated=true")
	}

	// Subject should come from 'user_id' claim as configured by userIdClaim
	if ctx.SharedContext.AuthContext.Subject != "custom-user-9999" {
		t.Errorf("Expected Subject='custom-user-9999' (from user_id), got %q", ctx.SharedContext.AuthContext.Subject)
	}
	if ctx.SharedContext.AuthContext.Properties["user_id"] != "custom-user-9999" {
		t.Errorf("Expected Properties[\"user_id\"]='custom-user-9999', got %q", ctx.SharedContext.AuthContext.Properties["user_id"])
	}

	_, ok := action.(policy.UpstreamRequestHeaderModifications)
	if !ok {
		t.Fatalf("Expected UpstreamRequestHeaderModifications, got %T", action)
	}
}

// TestJWTAuthPolicy_UserIdClaim_EmailClaim tests that Subject is set from the configured
// userIdClaim ('email') when it is present in the token.
func TestJWTAuthPolicy_UserIdClaim_EmailClaim(t *testing.T) {
	privateKey, publicKey := generateTestKeys(t)
	jwksServer := createJWKSServer(t, publicKey, "test-kid")
	defer jwksServer.Close()

	token := createTestToken(t, privateKey, map[string]interface{}{
		"sub":   "subject-value",
		"email": "alice@example.com",
		"iss":   "https://issuer.example.com",
		"aud":   "api-audience",
	})

	ctx := createMockRequestHeaderContext(map[string][]string{
		"authorization": {fmt.Sprintf("Bearer %s", token)},
	})

	params := map[string]interface{}{
		"headerName":        "Authorization",
		"authHeaderScheme":  "Bearer",
		"allowedAlgorithms": []interface{}{"RS256"},
		"audiences":         []interface{}{"api-audience"},
		"userIdClaim":       "email", // Extract from email claim
		"keyManagers": []interface{}{
			map[string]interface{}{
				"name": "test-issuer",
				"jwks": map[string]interface{}{
					"remote": map[string]interface{}{"uri": jwksServer.URL + "/jwks.json"},
				},
			},
		},
	}

	p, err := GetPolicy(policy.PolicyMetadata{}, params)
	if err != nil {
		t.Fatalf("GetPolicy failed: %v", err)
	}

	action := p.(*JwtAuthPolicy).OnRequestHeaders(context.Background(), ctx, params)

	if ctx.SharedContext.AuthContext == nil || !ctx.SharedContext.AuthContext.Authenticated {
		t.Fatalf("Expected AuthContext.Authenticated=true")
	}

	// Subject should come from 'email' claim as configured by userIdClaim
	if ctx.SharedContext.AuthContext.Subject != "alice@example.com" {
		t.Errorf("Expected Subject='alice@example.com' (from email), got %q", ctx.SharedContext.AuthContext.Subject)
	}
	if ctx.SharedContext.AuthContext.Properties["email"] != "alice@example.com" {
		t.Errorf("Expected Properties[\"email\"]='alice@example.com', got %q", ctx.SharedContext.AuthContext.Properties["email"])
	}

	_, ok := action.(policy.UpstreamRequestHeaderModifications)
	if !ok {
		t.Fatalf("Expected UpstreamRequestHeaderModifications, got %T", action)
	}
}

// TestJWTAuthPolicy_UserIdClaim_MissingClaim tests that authentication succeeds when a non-existent
// custom claim is specified; Subject still comes from 'sub'
func TestJWTAuthPolicy_UserIdClaim_MissingClaim(t *testing.T) {
	privateKey, publicKey := generateTestKeys(t)
	jwksServer := createJWKSServer(t, publicKey, "test-kid")
	defer jwksServer.Close()

	token := createTestToken(t, privateKey, map[string]interface{}{
		"sub": "user-12345",
		"iss": "https://issuer.example.com",
		"aud": "api-audience",
		// Note: no 'preferred_username' claim
	})

	ctx := createMockRequestHeaderContext(map[string][]string{
		"authorization": {fmt.Sprintf("Bearer %s", token)},
	})

	params := map[string]interface{}{
		"headerName":        "Authorization",
		"authHeaderScheme":  "Bearer",
		"allowedAlgorithms": []interface{}{"RS256"},
		"audiences":         []interface{}{"api-audience"},
		"userIdClaim":       "preferred_username", // This claim doesn't exist in token
		"keyManagers": []interface{}{
			map[string]interface{}{
				"name": "test-issuer",
				"jwks": map[string]interface{}{
					"remote": map[string]interface{}{"uri": jwksServer.URL + "/jwks.json"},
				},
			},
		},
	}

	p, err := GetPolicy(policy.PolicyMetadata{}, params)
	if err != nil {
		t.Fatalf("GetPolicy failed: %v", err)
	}

	action := p.(*JwtAuthPolicy).OnRequestHeaders(context.Background(), ctx, params)

	// Authentication should still succeed even if a custom claim doesn't exist
	if ctx.SharedContext.AuthContext == nil || !ctx.SharedContext.AuthContext.Authenticated {
		t.Fatalf("Expected AuthContext.Authenticated=true")
	}

	// Subject always comes from 'sub', regardless of userIdClaim parameter
	if ctx.SharedContext.AuthContext.Subject != "user-12345" {
		t.Errorf("Expected Subject='user-12345' (from sub), got %q", ctx.SharedContext.AuthContext.Subject)
	}

	_, ok := action.(policy.UpstreamRequestHeaderModifications)
	if !ok {
		t.Fatalf("Expected UpstreamRequestHeaderModifications, got %T", action)
	}
}

// TestJWTAuthPolicy_UserIdClaim_NumericValue tests that Subject is set from the configured
// userIdClaim ('account_id') with a numeric value, stringified correctly.
func TestJWTAuthPolicy_UserIdClaim_NumericValue(t *testing.T) {
	privateKey, publicKey := generateTestKeys(t)
	jwksServer := createJWKSServer(t, publicKey, "test-kid")
	defer jwksServer.Close()

	token := createTestToken(t, privateKey, map[string]interface{}{
		"sub":        "user-12345",
		"account_id": float64(987654321), // Numeric user ID
		"iss":        "https://issuer.example.com",
		"aud":        "api-audience",
	})

	ctx := createMockRequestHeaderContext(map[string][]string{
		"authorization": {fmt.Sprintf("Bearer %s", token)},
	})

	params := map[string]interface{}{
		"headerName":        "Authorization",
		"authHeaderScheme":  "Bearer",
		"allowedAlgorithms": []interface{}{"RS256"},
		"audiences":         []interface{}{"api-audience"},
		"userIdClaim":       "account_id", // Extract from numeric claim
		"keyManagers": []interface{}{
			map[string]interface{}{
				"name": "test-issuer",
				"jwks": map[string]interface{}{
					"remote": map[string]interface{}{"uri": jwksServer.URL + "/jwks.json"},
				},
			},
		},
	}

	p, err := GetPolicy(policy.PolicyMetadata{}, params)
	if err != nil {
		t.Fatalf("GetPolicy failed: %v", err)
	}

	action := p.(*JwtAuthPolicy).OnRequestHeaders(context.Background(), ctx, params)

	if ctx.SharedContext.AuthContext == nil || !ctx.SharedContext.AuthContext.Authenticated {
		t.Fatalf("Expected AuthContext.Authenticated=true")
	}

	// Subject should come from 'account_id' claim as configured by userIdClaim (stringified)
	if ctx.SharedContext.AuthContext.Subject != "987654321" {
		t.Errorf("Expected Subject='987654321' (from account_id), got %q", ctx.SharedContext.AuthContext.Subject)
	}
	if ctx.SharedContext.AuthContext.Properties["account_id"] != "987654321" {
		t.Errorf("Expected Properties[\"account_id\"]='987654321', got %q", ctx.SharedContext.AuthContext.Properties["account_id"])
	}

	_, ok := action.(policy.UpstreamRequestHeaderModifications)
	if !ok {
		t.Fatalf("Expected UpstreamRequestHeaderModifications, got %T", action)
	}
}

// TestJWTAuthPolicy_UserIdClaim_EmptyString tests that Subject is still populated from 'sub'
// when userIdClaim parameter is empty
func TestJWTAuthPolicy_UserIdClaim_EmptyString(t *testing.T) {
	privateKey, publicKey := generateTestKeys(t)
	jwksServer := createJWKSServer(t, publicKey, "test-kid")
	defer jwksServer.Close()

	token := createTestToken(t, privateKey, map[string]interface{}{
		"sub": "user-12345",
		"iss": "https://issuer.example.com",
		"aud": "api-audience",
	})

	ctx := createMockRequestHeaderContext(map[string][]string{
		"authorization": {fmt.Sprintf("Bearer %s", token)},
	})

	params := map[string]interface{}{
		"headerName":        "Authorization",
		"authHeaderScheme":  "Bearer",
		"allowedAlgorithms": []interface{}{"RS256"},
		"audiences":         []interface{}{"api-audience"},
		"userIdClaim":       "", // Empty string - should skip extraction
		"keyManagers": []interface{}{
			map[string]interface{}{
				"name": "test-issuer",
				"jwks": map[string]interface{}{
					"remote": map[string]interface{}{"uri": jwksServer.URL + "/jwks.json"},
				},
			},
		},
	}

	p, err := GetPolicy(policy.PolicyMetadata{}, params)
	if err != nil {
		t.Fatalf("GetPolicy failed: %v", err)
	}

	action := p.(*JwtAuthPolicy).OnRequestHeaders(context.Background(), ctx, params)

	if ctx.SharedContext.AuthContext == nil || !ctx.SharedContext.AuthContext.Authenticated {
		t.Fatalf("Expected AuthContext.Authenticated=true")
	}

	// Subject is always from 'sub', even when userIdClaim param is empty
	if ctx.SharedContext.AuthContext.Subject != "user-12345" {
		t.Errorf("Expected Subject='user-12345' (from sub), got %q", ctx.SharedContext.AuthContext.Subject)
	}

	_, ok := action.(policy.UpstreamRequestHeaderModifications)
	if !ok {
		t.Fatalf("Expected UpstreamRequestHeaderModifications, got %T", action)
	}
}

// TestJWTAuthPolicy_UserIdClaim_WithClaimMappings tests that Subject is set from the configured
// userIdClaim ('username') and claimMappings continue to work alongside AuthContext.
func TestJWTAuthPolicy_UserIdClaim_WithClaimMappings(t *testing.T) {
	privateKey, publicKey := generateTestKeys(t)
	jwksServer := createJWKSServer(t, publicKey, "test-kid")
	defer jwksServer.Close()

	token := createTestToken(t, privateKey, map[string]interface{}{
		"sub":      "user-12345",
		"username": "johndoe",
		"email":    "john@example.com",
		"role":     "admin",
		"iss":      "https://issuer.example.com",
		"aud":      "api-audience",
	})

	ctx := createMockRequestHeaderContext(map[string][]string{
		"authorization": {fmt.Sprintf("Bearer %s", token)},
	})

	params := map[string]interface{}{
		"headerName":        "Authorization",
		"authHeaderScheme":  "Bearer",
		"allowedAlgorithms": []interface{}{"RS256"},
		"audiences":         []interface{}{"api-audience"},
		"userIdClaim":       "username", // Extract user ID from username claim
		"claimMappings": map[string]interface{}{
			"email": "X-User-Email",
			"role":  "X-User-Role",
		},
		"keyManagers": []interface{}{
			map[string]interface{}{
				"name": "test-issuer",
				"jwks": map[string]interface{}{
					"remote": map[string]interface{}{"uri": jwksServer.URL + "/jwks.json"},
				},
			},
		},
	}

	p, err := GetPolicy(policy.PolicyMetadata{}, params)
	if err != nil {
		t.Fatalf("GetPolicy failed: %v", err)
	}

	action := p.(*JwtAuthPolicy).OnRequestHeaders(context.Background(), ctx, params)

	if ctx.SharedContext.AuthContext == nil || !ctx.SharedContext.AuthContext.Authenticated {
		t.Fatalf("Expected AuthContext.Authenticated=true")
	}

	// Subject should come from 'username' claim as configured by userIdClaim
	if ctx.SharedContext.AuthContext.Subject != "johndoe" {
		t.Errorf("Expected Subject='johndoe' (from username), got %q", ctx.SharedContext.AuthContext.Subject)
	}

	// Verify claim mappings were also applied
	modifications, ok := action.(policy.UpstreamRequestHeaderModifications)
	if !ok {
		t.Fatalf("Expected UpstreamRequestHeaderModifications, got %T", action)
	}

	if modifications.HeadersToSet["X-User-Email"] != "john@example.com" {
		t.Errorf("Expected X-User-Email='john@example.com', got '%v'", modifications.HeadersToSet["X-User-Email"])
	}

	if modifications.HeadersToSet["X-User-Role"] != "admin" {
		t.Errorf("Expected X-User-Role='admin', got '%v'", modifications.HeadersToSet["X-User-Role"])
	}
}

// TestJWTAuthPolicy_RejectionDeclaresFault pins the fault declaration and the error code
func TestJWTAuthPolicy_RejectionDeclaresFault(t *testing.T) {
	baseParams := func() map[string]interface{} {
		return map[string]interface{}{
			"headerName":          "Authorization",
			"authHeaderScheme":    "Bearer",
			"onFailureStatusCode": 401,
			"errorMessageFormat":  "json",
			"leeway":              "30s",
			"allowedAlgorithms":   []interface{}{"RS256"},
			"keyManagers": []interface{}{
				map[string]interface{}{
					"name":   "test-issuer",
					"issuer": "https://issuer.example.com",
					"jwks": map[string]interface{}{
						"remote": map[string]interface{}{
							"uri": "http://127.0.0.1:1/jwks.json",
						},
					},
				},
			},
		}
	}

	tests := []struct {
		name     string
		headers  map[string][]string
		mutate   func(map[string]interface{})
		wantCode string
		wantType string
	}{
		{
			name:     "no authorization header",
			headers:  map[string][]string{},
			wantCode: policy.FaultCodeAuthMissingCredentials,
			wantType: policy.FaultTypeAuthentication,
		},
		{
			name:     "authorization header not Bearer",
			headers:  map[string][]string{"Authorization": {"Basic abc"}},
			wantCode: policy.FaultCodeAuthInvalidCredentials,
			wantType: policy.FaultTypeAuthentication,
		},
		{
			name:     "token is not a JWT",
			headers:  map[string][]string{"Authorization": {"Bearer not-a-jwt"}},
			wantCode: policy.FaultCodeAuthInvalidCredentials,
			wantType: policy.FaultTypeAuthentication,
		},
		{
			name:    "no key managers configured",
			headers: map[string][]string{"Authorization": {"Bearer not-a-jwt"}},
			mutate: func(m map[string]interface{}) {
				delete(m, "keyManagers")
			},
			wantCode: policy.FaultCodeAuthGeneral,
			wantType: policy.FaultTypeAuthentication,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			params := baseParams()
			if tt.mutate != nil {
				tt.mutate(params)
			}
			ctx := createMockRequestHeaderContext(tt.headers)

			p, err := GetPolicy(policy.PolicyMetadata{}, params)
			if err != nil {
				t.Fatalf("Failed to create policy: %v", err)
			}
			action := p.(*JwtAuthPolicy).OnRequestHeaders(context.Background(), ctx, params)

			resp, ok := action.(policy.ImmediateResponse)
			if !ok {
				t.Fatalf("expected ImmediateResponse, got %T", action)
			}
			if !resp.IsFault {
				t.Fatalf("expected IsFault=true on an auth rejection")
			}
			if resp.Fault == nil {
				t.Fatalf("expected Error to be populated on an auth rejection")
			}
			if resp.Fault.Code != tt.wantCode {
				t.Fatalf("expected Error.Code=%q, got %q", tt.wantCode, resp.Fault.Code)
			}
			if resp.Fault.Type != tt.wantType {
				t.Fatalf("expected Error.Type=%q, got %q", tt.wantType, resp.Fault.Type)
			}
			if resp.Fault.Direction != policy.DirectionRequest {
				t.Fatalf("expected Error.Direction=%q, got %q", policy.DirectionRequest, resp.Fault.Direction)
			}
			if resp.Fault.Description == "" {
				t.Fatalf("expected Error.Description to carry the internal reason")
			}
		})
	}
}
