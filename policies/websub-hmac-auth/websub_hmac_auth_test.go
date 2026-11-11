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

package websubhmacauth

import (
	"context"
	"crypto/hmac"
	"crypto/sha1" //nolint:gosec
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/wso2/api-platform/common/webhooksecret"
	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

const testAPIID = "test-api-id-abc123"

// ─── helpers ─────────────────────────────────────────────────────────────────

func signPayload(t *testing.T, algorithm, secret string, payload []byte) string {
	t.Helper()
	switch algorithm {
	case algorithmSHA256:
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write(payload) //nolint:errcheck
		return "sha256=" + hex.EncodeToString(mac.Sum(nil))
	case algorithmSHA1:
		mac := hmac.New(sha1.New, []byte(secret)) //nolint:gosec
		mac.Write(payload)                        //nolint:errcheck
		return "sha1=" + hex.EncodeToString(mac.Sum(nil))
	case algorithmSHA512:
		mac := hmac.New(sha512.New, []byte(secret))
		mac.Write(payload) //nolint:errcheck
		return "sha512=" + hex.EncodeToString(mac.Sum(nil))
	default:
		t.Fatalf("unknown algorithm %q in test helper", algorithm)
		return ""
	}
}

// setupStore populates the singleton store with the given name→plaintext secrets
// for testAPIID and registers cleanup to clear them after the test.
func setupStore(t *testing.T, secrets map[string]string) {
	t.Helper()
	store := webhooksecret.GetStoreInstance()
	store.ClearAll()
	for name, val := range secrets {
		if err := store.Store(testAPIID, name, val); err != nil {
			t.Fatalf("setupStore: %v", err)
		}
	}
	t.Cleanup(func() { store.ClearAll() })
}

func newRequestHeaderCtx(headers map[string][]string) *policy.RequestHeaderContext {
	return &policy.RequestHeaderContext{
		SharedContext: &policy.SharedContext{},
		Headers:       policy.NewHeaders(headers),
	}
}

func newRequestBodyCtx(headers map[string][]string, body []byte) *policy.RequestContext {
	return &policy.RequestContext{
		SharedContext: &policy.SharedContext{APIId: testAPIID},
		Headers:       policy.NewHeaders(headers),
		Body:          &policy.Body{Content: body, Present: len(body) > 0},
	}
}

func TestGetPolicy_InvalidAlgorithm(t *testing.T) {
	_, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{
		"algorithm": "md5",
	})
	if err == nil {
		t.Fatal("expected error for unsupported algorithm")
	}
}

func TestGetPolicy_DefaultsSHA256(t *testing.T) {
	p, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	wp := p.(*WebSubHMACAuthPolicy)
	if wp.algorithm != algorithmSHA256 {
		t.Errorf("expected default algorithm sha256, got %q", wp.algorithm)
	}
	if wp.signatureHeader != defaultSignatureHeader {
		t.Errorf("expected default header %q, got %q", defaultSignatureHeader, wp.signatureHeader)
	}
}

func TestGetPolicy_SHA1DefaultHeader(t *testing.T) {
	p, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{
		"algorithm": "sha1",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	wp := p.(*WebSubHMACAuthPolicy)
	if wp.signatureHeader != signatureHeaderLegacy {
		t.Errorf("expected legacy header %q for sha1, got %q", signatureHeaderLegacy, wp.signatureHeader)
	}
}

func TestGetPolicy_CustomSignatureHeader(t *testing.T) {
	p, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{
		"signatureHeader": "X-Custom-Signature",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	wp := p.(*WebSubHMACAuthPolicy)
	if wp.signatureHeader != "X-Custom-Signature" {
		t.Errorf("expected custom header, got %q", wp.signatureHeader)
	}
}

// ─── OnRequestHeaders ────────────────────────────────────────────────────────

func TestOnRequestHeaders_MissingSignatureHeader_Returns401(t *testing.T) {
	p := &WebSubHMACAuthPolicy{
		algorithm:       algorithmSHA256,
		signatureHeader: defaultSignatureHeader,
	}

	ctx := newRequestHeaderCtx(map[string][]string{})
	action := p.OnRequestHeaders(context.Background(), ctx, nil)

	resp, ok := action.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("expected ImmediateResponse, got %T", action)
	}
	if resp.StatusCode != 401 {
		t.Errorf("expected 401, got %d", resp.StatusCode)
	}
}

func TestOnRequestHeaders_SignatureHeaderPresent_Continues(t *testing.T) {
	p := &WebSubHMACAuthPolicy{
		algorithm:       algorithmSHA256,
		signatureHeader: defaultSignatureHeader,
	}

	ctx := newRequestHeaderCtx(map[string][]string{
		defaultSignatureHeader: {"sha256=abc123"},
	})
	action := p.OnRequestHeaders(context.Background(), ctx, nil)

	if _, ok := action.(policy.UpstreamRequestHeaderModifications); !ok {
		t.Fatalf("expected UpstreamRequestHeaderModifications, got %T", action)
	}
}

// ─── OnRequestBody ────────────────────────────────────────────────────────────

func TestOnRequestBody_ValidSHA256Signature(t *testing.T) {
	secret := "my-secret-key"
	setupStore(t, map[string]string{"key1": secret})

	payload := []byte(`{"topic":"https://example.com/events","content":"hello"}`)
	sig := signPayload(t, algorithmSHA256, secret, payload)

	p := &WebSubHMACAuthPolicy{
		algorithm:       algorithmSHA256,
		signatureHeader: defaultSignatureHeader,
	}

	ctx := newRequestBodyCtx(map[string][]string{
		defaultSignatureHeader: {sig},
	}, payload)

	action := p.OnRequestBody(context.Background(), ctx, nil)
	if _, ok := action.(policy.UpstreamRequestModifications); !ok {
		t.Fatalf("expected UpstreamRequestModifications (pass-through), got %T", action)
	}
}

func TestOnRequestBody_ValidSHA1Signature(t *testing.T) {
	secret := "my-secret-key"
	setupStore(t, map[string]string{"key1": secret})

	payload := []byte(`{"topic":"https://example.com/events"}`)
	sig := signPayload(t, algorithmSHA1, secret, payload)

	p := &WebSubHMACAuthPolicy{
		algorithm:       algorithmSHA1,
		signatureHeader: signatureHeaderLegacy,
	}

	ctx := newRequestBodyCtx(map[string][]string{
		signatureHeaderLegacy: {sig},
	}, payload)

	action := p.OnRequestBody(context.Background(), ctx, nil)
	if _, ok := action.(policy.UpstreamRequestModifications); !ok {
		t.Fatalf("expected pass-through, got %T", action)
	}
}

func TestOnRequestBody_ValidSHA512Signature(t *testing.T) {
	secret := "my-secret-key"
	setupStore(t, map[string]string{"key1": secret})

	payload := []byte(`{"topic":"https://example.com/events"}`)
	sig := signPayload(t, algorithmSHA512, secret, payload)

	p := &WebSubHMACAuthPolicy{
		algorithm:       algorithmSHA512,
		signatureHeader: defaultSignatureHeader,
	}

	ctx := newRequestBodyCtx(map[string][]string{
		defaultSignatureHeader: {sig},
	}, payload)

	action := p.OnRequestBody(context.Background(), ctx, nil)
	if _, ok := action.(policy.UpstreamRequestModifications); !ok {
		t.Fatalf("expected pass-through, got %T", action)
	}
}

func TestOnRequestBody_InvalidSignature_Returns401(t *testing.T) {
	setupStore(t, map[string]string{"key1": "my-secret-key"})

	payload := []byte(`{"topic":"https://example.com/events"}`)

	p := &WebSubHMACAuthPolicy{
		algorithm:       algorithmSHA256,
		signatureHeader: defaultSignatureHeader,
	}

	ctx := newRequestBodyCtx(map[string][]string{
		defaultSignatureHeader: {"sha256=deadbeef"},
	}, payload)

	action := p.OnRequestBody(context.Background(), ctx, nil)
	resp, ok := action.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("expected ImmediateResponse, got %T", action)
	}
	if resp.StatusCode != 401 {
		t.Errorf("expected 401, got %d", resp.StatusCode)
	}
}

func TestOnRequestBody_WrongSecret_Returns401(t *testing.T) {
	setupStore(t, map[string]string{"key1": "correct-secret"})

	payload := []byte(`{"topic":"https://example.com/events"}`)
	// Sign with a different secret than the one in the store
	sig := signPayload(t, algorithmSHA256, "wrong-secret", payload)

	p := &WebSubHMACAuthPolicy{
		algorithm:       algorithmSHA256,
		signatureHeader: defaultSignatureHeader,
	}

	ctx := newRequestBodyCtx(map[string][]string{
		defaultSignatureHeader: {sig},
	}, payload)

	action := p.OnRequestBody(context.Background(), ctx, nil)
	resp, ok := action.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("expected ImmediateResponse, got %T", action)
	}
	if resp.StatusCode != 401 {
		t.Errorf("expected 401, got %d", resp.StatusCode)
	}
}

func TestOnRequestBody_MissingSignatureHeader_Returns401(t *testing.T) {
	payload := []byte(`{"topic":"https://example.com/events"}`)

	p := &WebSubHMACAuthPolicy{
		algorithm:       algorithmSHA256,
		signatureHeader: defaultSignatureHeader,
	}

	ctx := newRequestBodyCtx(map[string][]string{}, payload)

	action := p.OnRequestBody(context.Background(), ctx, nil)
	resp, ok := action.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("expected ImmediateResponse, got %T", action)
	}
	if resp.StatusCode != 401 {
		t.Errorf("expected 401, got %d", resp.StatusCode)
	}
}

func TestOnRequestBody_MalformedSignatureHeader_Returns401(t *testing.T) {
	payload := []byte(`hello`)

	p := &WebSubHMACAuthPolicy{
		algorithm:       algorithmSHA256,
		signatureHeader: defaultSignatureHeader,
	}

	ctx := newRequestBodyCtx(map[string][]string{
		defaultSignatureHeader: {"notavalidsig"},
	}, payload)

	action := p.OnRequestBody(context.Background(), ctx, nil)
	resp, ok := action.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("expected ImmediateResponse, got %T", action)
	}
	if resp.StatusCode != 401 {
		t.Errorf("expected 401, got %d", resp.StatusCode)
	}
}

func TestOnRequestBody_AlgorithmMismatch_Returns401(t *testing.T) {
	secret := "my-secret-key"
	setupStore(t, map[string]string{"key1": secret})

	payload := []byte(`hello`)
	// Policy configured for sha256 but signature uses sha1 prefix
	sig := signPayload(t, algorithmSHA1, secret, payload)

	p := &WebSubHMACAuthPolicy{
		algorithm:       algorithmSHA256,
		signatureHeader: defaultSignatureHeader,
	}

	ctx := newRequestBodyCtx(map[string][]string{
		defaultSignatureHeader: {sig},
	}, payload)

	action := p.OnRequestBody(context.Background(), ctx, nil)
	resp, ok := action.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("expected ImmediateResponse, got %T", action)
	}
	if resp.StatusCode != 401 {
		t.Errorf("expected 401, got %d", resp.StatusCode)
	}
}

func TestOnRequestBody_EmptyBody_ValidSignature(t *testing.T) {
	secret := "my-secret-key"
	setupStore(t, map[string]string{"key1": secret})

	payload := []byte{}
	sig := signPayload(t, algorithmSHA256, secret, payload)

	p := &WebSubHMACAuthPolicy{
		algorithm:       algorithmSHA256,
		signatureHeader: defaultSignatureHeader,
	}

	ctx := newRequestBodyCtx(map[string][]string{
		defaultSignatureHeader: {sig},
	}, payload)

	action := p.OnRequestBody(context.Background(), ctx, nil)
	if _, ok := action.(policy.UpstreamRequestModifications); !ok {
		t.Fatalf("expected pass-through for empty body with valid sig, got %T", action)
	}
}

func TestOnRequestBody_EmptyStore_Returns401(t *testing.T) {
	setupStore(t, map[string]string{}) // no secrets

	payload := []byte(`{"topic":"https://example.com/events"}`)
	sig := signPayload(t, algorithmSHA256, "any-secret", payload)

	p := &WebSubHMACAuthPolicy{
		algorithm:       algorithmSHA256,
		signatureHeader: defaultSignatureHeader,
	}

	ctx := newRequestBodyCtx(map[string][]string{
		defaultSignatureHeader: {sig},
	}, payload)

	action := p.OnRequestBody(context.Background(), ctx, nil)
	resp, ok := action.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("expected ImmediateResponse, got %T", action)
	}
	if resp.StatusCode != 401 {
		t.Errorf("expected 401, got %d", resp.StatusCode)
	}
}

func TestOnRequestBody_MultipleSecrets_FirstMatches(t *testing.T) {
	correctSecret := "correct-secret"
	setupStore(t, map[string]string{
		"key1": correctSecret,
		"key2": "other-secret",
	})

	payload := []byte(`{"topic":"https://example.com/events"}`)
	sig := signPayload(t, algorithmSHA256, correctSecret, payload)

	p := &WebSubHMACAuthPolicy{
		algorithm:       algorithmSHA256,
		signatureHeader: defaultSignatureHeader,
	}

	ctx := newRequestBodyCtx(map[string][]string{
		defaultSignatureHeader: {sig},
	}, payload)

	action := p.OnRequestBody(context.Background(), ctx, nil)
	if _, ok := action.(policy.UpstreamRequestModifications); !ok {
		t.Fatalf("expected pass-through when first secret matches, got %T", action)
	}
}

func TestOnRequestBody_MultipleSecrets_SecondMatches(t *testing.T) {
	correctSecret := "correct-secret"
	setupStore(t, map[string]string{
		"key1": "wrong-secret",
		"key2": correctSecret,
	})

	payload := []byte(`{"topic":"https://example.com/events"}`)
	sig := signPayload(t, algorithmSHA256, correctSecret, payload)

	p := &WebSubHMACAuthPolicy{
		algorithm:       algorithmSHA256,
		signatureHeader: defaultSignatureHeader,
	}

	ctx := newRequestBodyCtx(map[string][]string{
		defaultSignatureHeader: {sig},
	}, payload)

	action := p.OnRequestBody(context.Background(), ctx, nil)
	if _, ok := action.(policy.UpstreamRequestModifications); !ok {
		t.Fatalf("expected pass-through when second secret matches, got %T", action)
	}
}

func TestOnRequestBody_MultipleSecrets_AllFail_Returns401(t *testing.T) {
	setupStore(t, map[string]string{
		"key1": "secret-one",
		"key2": "secret-two",
	})

	payload := []byte(`{"topic":"https://example.com/events"}`)
	// Sign with a secret that is not in the store
	sig := signPayload(t, algorithmSHA256, "secret-not-in-store", payload)

	p := &WebSubHMACAuthPolicy{
		algorithm:       algorithmSHA256,
		signatureHeader: defaultSignatureHeader,
	}

	ctx := newRequestBodyCtx(map[string][]string{
		defaultSignatureHeader: {sig},
	}, payload)

	action := p.OnRequestBody(context.Background(), ctx, nil)
	resp, ok := action.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("expected ImmediateResponse, got %T", action)
	}
	if resp.StatusCode != 401 {
		t.Errorf("expected 401, got %d", resp.StatusCode)
	}
}

func TestOnRequestBody_NilBody_ValidSignature(t *testing.T) {
	secret := "my-secret-key"
	setupStore(t, map[string]string{"key1": secret})

	// HMAC over nil/empty payload — same result as empty []byte
	mac := hmac.New(sha256.New, []byte(secret))
	sig := "sha256=" + hex.EncodeToString(mac.Sum(nil))

	p := &WebSubHMACAuthPolicy{
		algorithm:       algorithmSHA256,
		signatureHeader: defaultSignatureHeader,
	}

	ctx := &policy.RequestContext{
		SharedContext: &policy.SharedContext{APIId: testAPIID},
		Headers:       policy.NewHeaders(map[string][]string{defaultSignatureHeader: {sig}}),
		Body:          nil,
	}

	action := p.OnRequestBody(context.Background(), ctx, nil)
	if _, ok := action.(policy.UpstreamRequestModifications); !ok {
		t.Fatalf("expected pass-through for nil body with valid sig, got %T", action)
	}
}

func TestOnRequestBody_CaseInsensitiveAlgorithmInHeader(t *testing.T) {
	secret := "my-secret-key"
	setupStore(t, map[string]string{"key1": secret})

	payload := []byte(`{"event":"test"}`)
	// Policy is configured for lowercase "sha256"; header uses uppercase "SHA256"
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload) //nolint:errcheck
	sig := "SHA256=" + hex.EncodeToString(mac.Sum(nil))

	p := &WebSubHMACAuthPolicy{
		algorithm:       algorithmSHA256,
		signatureHeader: defaultSignatureHeader,
	}

	ctx := newRequestBodyCtx(map[string][]string{
		defaultSignatureHeader: {sig},
	}, payload)

	action := p.OnRequestBody(context.Background(), ctx, nil)
	if _, ok := action.(policy.UpstreamRequestModifications); !ok {
		t.Fatalf("expected pass-through for uppercase algorithm prefix, got %T", action)
	}
}

// ─── GetPolicy edge cases ────────────────────────────────────────────────────

func TestGetPolicy_SHA512UsesDefaultHeader(t *testing.T) {
	p, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{
		"algorithm": "sha512",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	wp := p.(*WebSubHMACAuthPolicy)
	if wp.signatureHeader != defaultSignatureHeader {
		t.Errorf("expected default header %q for sha512, got %q", defaultSignatureHeader, wp.signatureHeader)
	}
}

func TestGetPolicy_UppercaseAlgorithmNormalized(t *testing.T) {
	p, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{
		"algorithm": "SHA256",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	wp := p.(*WebSubHMACAuthPolicy)
	if wp.algorithm != algorithmSHA256 {
		t.Errorf("expected sha256 after normalisation, got %q", wp.algorithm)
	}
}

func TestGetPolicy_EmptyAlgorithmFallsBackToDefault(t *testing.T) {
	p, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{
		"algorithm": "",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	wp := p.(*WebSubHMACAuthPolicy)
	if wp.algorithm != algorithmSHA256 {
		t.Errorf("expected sha256 fallback, got %q", wp.algorithm)
	}
}

// ─── computeHMAC ─────────────────────────────────────────────────────────────

func TestComputeHMAC_UnsupportedAlgorithm(t *testing.T) {
	_, err := computeHMAC([]byte("payload"), "md5", []byte("secret"))
	if err == nil {
		t.Fatal("expected error for unsupported algorithm")
	}
}

func TestComputeHMAC_AllSupportedAlgorithms(t *testing.T) {
	payload := []byte("test-payload")
	secret := []byte("test-secret")
	for _, algo := range []string{algorithmSHA256, algorithmSHA1, algorithmSHA512} {
		mac, err := computeHMAC(payload, algo, secret)
		if err != nil {
			t.Errorf("computeHMAC(%s) unexpected error: %v", algo, err)
		}
		if len(mac) == 0 {
			t.Errorf("computeHMAC(%s) returned empty digest", algo)
		}
	}
}

// ─── Mode ────────────────────────────────────────────────────────────────────

func TestMode_ReturnsExpectedProcessingModes(t *testing.T) {
	p := &WebSubHMACAuthPolicy{algorithm: algorithmSHA256, signatureHeader: defaultSignatureHeader}
	mode := p.Mode()

	if mode.RequestHeaderMode != policy.HeaderModeProcess {
		t.Errorf("RequestHeaderMode: got %v, want %v", mode.RequestHeaderMode, policy.HeaderModeProcess)
	}
	if mode.RequestBodyMode != policy.BodyModeBuffer {
		t.Errorf("RequestBodyMode: got %v, want %v", mode.RequestBodyMode, policy.BodyModeBuffer)
	}
	if mode.ResponseHeaderMode != policy.HeaderModeSkip {
		t.Errorf("ResponseHeaderMode: got %v, want %v", mode.ResponseHeaderMode, policy.HeaderModeSkip)
	}
	if mode.ResponseBodyMode != policy.BodyModeSkip {
		t.Errorf("ResponseBodyMode: got %v, want %v", mode.ResponseBodyMode, policy.BodyModeSkip)
	}
}

// ─── parseSignatureHeader ────────────────────────────────────────────────────

func TestParseSignatureHeader(t *testing.T) {
	tests := []struct {
		input      string
		wantAlgo   string
		wantDigest string
		wantErr    bool
	}{
		{"sha256=abc123", "sha256", "abc123", false},
		{"sha1=deadbeef", "sha1", "deadbeef", false},
		{"sha512=longdigest", "sha512", "longdigest", false},
		{"notavalidsig", "", "", true},
		{"=abc", "", "", true},
		{"sha256=", "", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			algo, digest, err := parseSignatureHeader(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if algo != tt.wantAlgo {
				t.Errorf("algorithm: got %q, want %q", algo, tt.wantAlgo)
			}
			if digest != tt.wantDigest {
				t.Errorf("digest: got %q, want %q", digest, tt.wantDigest)
			}
		})
	}
}

// TestNoSecretsDeclaresConfigurationFault checks that an API with no webhook secrets is an
// operator configuration fault, not a caller authentication failure. The body is unchanged.
func TestNoSecretsDeclaresConfigurationFault(t *testing.T) {
	setupStore(t, nil)
	p := &WebSubHMACAuthPolicy{algorithm: algorithmSHA256, signatureHeader: defaultSignatureHeader}
	ctx := newRequestBodyCtx(map[string][]string{defaultSignatureHeader: {"sha256=deadbeef"}}, []byte(`{}`))

	resp, ok := p.OnRequestBody(context.Background(), ctx, nil).(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("expected ImmediateResponse")
	}
	if !resp.IsFault || resp.Fault == nil {
		t.Fatalf("expected a fault, got IsFault=%v Fault=%v", resp.IsFault, resp.Fault)
	}
	if resp.Fault.Code != policy.FaultCodeMediationFailed || resp.Fault.Type != policy.FaultTypeConfiguration {
		t.Fatalf("fault = %s/%s, want %s/%s", resp.Fault.Code, resp.Fault.Type, policy.FaultCodeMediationFailed, policy.FaultTypeConfiguration)
	}
	if want := `{"error":"Unauthorized","message":"no webhook secrets configured for this API"}`; string(resp.Body) != want {
		t.Fatalf("body = %s, want %s", resp.Body, want)
	}
}

// TestRejectionDeclaresFault pins the fault declaration and the code chosen per rejection
func TestRejectionDeclaresFault(t *testing.T) {
	setupStore(t, map[string]string{"key1": "my-secret-key"})
	payload := []byte(`{"topic":"https://example.com/events"}`)

	newPolicy := func() *WebSubHMACAuthPolicy {
		return &WebSubHMACAuthPolicy{
			algorithm:       algorithmSHA256,
			signatureHeader: defaultSignatureHeader,
		}
	}

	tests := []struct {
		name        string
		run         func(*WebSubHMACAuthPolicy) interface{}
		wantCode    string
		wantMessage string
	}{
		{
			name: "header phase, no signature header",
			run: func(p *WebSubHMACAuthPolicy) interface{} {
				return p.OnRequestHeaders(context.Background(), newRequestHeaderCtx(map[string][]string{}), nil)
			},
			wantCode:    policy.FaultCodeAuthMissingCredentials,
			wantMessage: "missing signature header: " + defaultSignatureHeader,
		},
		{
			name: "body phase, no signature header",
			run: func(p *WebSubHMACAuthPolicy) interface{} {
				return p.OnRequestBody(context.Background(), newRequestBodyCtx(map[string][]string{}, payload), nil)
			},
			wantCode:    policy.FaultCodeAuthMissingCredentials,
			wantMessage: "missing signature header: " + defaultSignatureHeader,
		},
		{
			name: "malformed signature header",
			run: func(p *WebSubHMACAuthPolicy) interface{} {
				ctx := newRequestBodyCtx(map[string][]string{defaultSignatureHeader: {"garbage"}}, payload)
				return p.OnRequestBody(context.Background(), ctx, nil)
			},
			wantCode:    policy.FaultCodeAuthInvalidCredentials,
			wantMessage: "malformed signature header",
		},
		{
			name: "signature does not match",
			run: func(p *WebSubHMACAuthPolicy) interface{} {
				ctx := newRequestBodyCtx(map[string][]string{defaultSignatureHeader: {"sha256=deadbeef"}}, payload)
				return p.OnRequestBody(context.Background(), ctx, nil)
			},
			wantCode:    policy.FaultCodeAuthInvalidCredentials,
			wantMessage: "invalid HMAC signature",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			action := tt.run(newPolicy())
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
			if resp.Fault.Type != policy.FaultTypeAuthentication {
				t.Fatalf("expected Error.Type=%q, got %q", policy.FaultTypeAuthentication, resp.Fault.Type)
			}
			if resp.Fault.Direction != policy.DirectionRequest {
				t.Fatalf("expected Error.Direction=%q, got %q", policy.DirectionRequest, resp.Fault.Direction)
			}
			if resp.Fault.Message != tt.wantMessage {
				t.Fatalf("expected Error.Message=%q, got %q", tt.wantMessage, resp.Fault.Message)
			}
			// The body the client receives is unchanged by the fault declaration.
			var body map[string]string
			if err := json.Unmarshal(resp.Body, &body); err != nil {
				t.Fatalf("response body is not JSON: %v", err)
			}
			if body["error"] != "Unauthorized" || body["message"] != tt.wantMessage {
				t.Fatalf("body = %s, want error %q and message %q", resp.Body, "Unauthorized", tt.wantMessage)
			}
		})
	}
}
