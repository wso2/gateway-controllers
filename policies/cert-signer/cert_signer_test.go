package certsigner

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

// generateTestCertAndKey creates a temporary self-signed RSA cert + key and
// returns paths to the PEM files.
func generateTestCertAndKey(t *testing.T) (certFile, keyFile string) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-gateway"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}

	cf, err := os.CreateTemp(t.TempDir(), "cert*.pem")
	if err != nil {
		t.Fatalf("temp cert file: %v", err)
	}
	if err := pem.Encode(cf, &pem.Block{Type: "CERTIFICATE", Bytes: certDER}); err != nil {
		t.Fatalf("encode cert: %v", err)
	}
	cf.Close()

	kf, err := os.CreateTemp(t.TempDir(), "key*.pem")
	if err != nil {
		t.Fatalf("temp key file: %v", err)
	}
	if err := pem.Encode(kf, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}); err != nil {
		t.Fatalf("encode key: %v", err)
	}
	kf.Close()

	return cf.Name(), kf.Name()
}

// decodeJWT splits a compact JWT and decodes the header and payload.
// Uses standard base64 (with padding).
func decodeJWT(t *testing.T, token string) (header, payload map[string]interface{}) {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("expected 3 JWT parts, got %d", len(parts))
	}
	decodeJSON := func(s string) map[string]interface{} {
		b, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			t.Fatalf("base64 decode: %v", err)
		}
		var m map[string]interface{}
		if err := json.Unmarshal(b, &m); err != nil {
			t.Fatalf("json unmarshal: %v", err)
		}
		return m
	}
	return decodeJSON(parts[0]), decodeJSON(parts[1])
}

// verifyJWTSignature checks the RS256 signature of a compact JWT using pubKey.
// Uses standard base64 (with padding).
func verifyJWTSignature(t *testing.T, token string, pubKey *rsa.PublicKey) {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("expected 3 JWT parts, got %d", len(parts))
	}
	sigInput := parts[0] + "." + parts[1]
	digest := sha256.Sum256([]byte(sigInput))
	sig, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatalf("decode signature: %v", err)
	}
	if err := rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, digest[:], sig); err != nil {
		t.Errorf("JWT signature verification failed: %v", err)
	}
}

// TestGetPolicy_MissingKeyFile verifies that a missing key file fails at GetPolicy time.

// ctxWithAppID returns a minimal RequestHeaderContext with the given application ID in Metadata.
// Most tests need this because cert-signer rejects requests that lack x-wso2-application-id.
func ctxWithAppID(appID string) *policy.RequestHeaderContext {
	return &policy.RequestHeaderContext{
		SharedContext: &policy.SharedContext{
			Metadata: map[string]interface{}{"x-wso2-application-id": appID},
		},
	}
}

func TestGetPolicy_MissingKeyFile(t *testing.T) {
	cf, _ := generateTestCertAndKey(t) // cert exists, key does not
	_, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{
		"certFile": cf,
		"keyFile":  "/nonexistent/tls.key",
	})
	if err == nil {
		t.Fatal("expected error for missing key file, got nil")
	}
}

// TestGetPolicy_MissingCertFile verifies that a missing cert file fails at GetPolicy time.
func TestGetPolicy_MissingCertFile(t *testing.T) {
	_, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{
		"certFile": "/nonexistent/tls.crt",
		"keyFile":  "/nonexistent/tls.key",
	})
	if err == nil {
		t.Fatal("expected error for missing cert file, got nil")
	}
}

// TestMode verifies the processing mode flags.
func TestMode(t *testing.T) {
	certFile, keyFile := generateTestCertAndKey(t)
	p, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{
		"certFile": certFile,
		"keyFile":  keyFile,
	})
	if err != nil {
		t.Fatalf("GetPolicy: %v", err)
	}
	m := p.(*CertSignerPolicy).Mode()
	if m.RequestHeaderMode != policy.HeaderModeProcess {
		t.Error("expected RequestHeaderMode Process")
	}
	if m.RequestBodyMode != policy.BodyModeSkip {
		t.Error("expected RequestBodyMode Skip")
	}
	if m.ResponseHeaderMode != policy.HeaderModeSkip {
		t.Error("expected ResponseHeaderMode Skip")
	}
}

// TestOnRequestHeaders_InjectsAuthorizationHeader verifies that the policy sets
// Authorization: Cert <jwt> unconditionally on every upstream request.
func TestOnRequestHeaders_InjectsAuthorizationHeader(t *testing.T) {
	certFile, keyFile := generateTestCertAndKey(t)
	raw, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{
		"certFile": certFile,
		"keyFile":  keyFile,
	})
	if err != nil {
		t.Fatalf("GetPolicy: %v", err)
	}
	cp := raw.(*CertSignerPolicy)

	reqCtx := ctxWithAppID("test-app")
	action := cp.OnRequestHeaders(context.Background(), reqCtx, nil)
	mods, ok := action.(policy.UpstreamRequestHeaderModifications)
	if !ok {
		t.Fatalf("expected UpstreamRequestHeaderModifications, got %T", action)
	}

	authVal := mods.HeadersToSet["Authorization"]
	if authVal == "" {
		t.Fatal("Authorization header not set")
	}
	if !strings.HasPrefix(authVal, "Cert ") {
		t.Errorf("expected Authorization to start with 'Cert ', got: %q", authVal)
	}

	token := strings.TrimPrefix(authVal, "Cert ")
	header, payload := decodeJWT(t, token)

	if header["alg"] != "RS256" {
		t.Errorf("expected alg RS256, got %v", header["alg"])
	}
	if _, hasTyp := header["typ"]; hasTyp {
		t.Errorf("header must not contain typ: got %v", header["typ"])
	}
	// typ:"JWT" belongs in the payload
	if payload["typ"] != "JWT" {
		t.Errorf("expected typ JWT in payload, got %v", payload["typ"])
	}
	if payload["iss"] != "test-gateway" {
		t.Errorf("expected iss test-gateway (cert CN), got %v", payload["iss"])
	}
	if payload["jti"] == nil || payload["jti"] == "" {
		t.Error("expected non-empty jti")
	}
	iat, _ := payload["iat"].(float64)
	exp, _ := payload["exp"].(float64)
	if exp <= iat {
		t.Errorf("expected exp (%v) > iat (%v)", exp, iat)
	}
	if int(exp-iat) != defaultTTLSeconds {
		t.Errorf("expected TTL %d, got %v", defaultTTLSeconds, exp-iat)
	}

	verifyJWTSignature(t, token, &cp.cfg.PrivateKey.PublicKey)
}

// TestOnRequestHeaders_CustomScheme verifies the Authorization scheme is configurable.
func TestOnRequestHeaders_CustomScheme(t *testing.T) {
	certFile, keyFile := generateTestCertAndKey(t)
	raw, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{
		"certFile": certFile,
		"keyFile":  keyFile,
		"scheme":   "TLS-Client",
	})
	if err != nil {
		t.Fatalf("GetPolicy: %v", err)
	}
	cp := raw.(*CertSignerPolicy)

	action := cp.OnRequestHeaders(context.Background(), ctxWithAppID("test-app"), nil)
	mods := action.(policy.UpstreamRequestHeaderModifications)
	if !strings.HasPrefix(mods.HeadersToSet["Authorization"], "TLS-Client ") {
		t.Errorf("expected TLS-Client scheme, got: %q", mods.HeadersToSet["Authorization"])
	}
}

// TestOnRequestHeaders_CustomSignatureHeader verifies the header name is configurable.
func TestOnRequestHeaders_CustomSignatureHeader(t *testing.T) {
	certFile, keyFile := generateTestCertAndKey(t)
	raw, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{
		"certFile":        certFile,
		"keyFile":         keyFile,
		"signatureHeader": "x-client-signature",
	})
	if err != nil {
		t.Fatalf("GetPolicy: %v", err)
	}
	cp := raw.(*CertSignerPolicy)

	action := cp.OnRequestHeaders(context.Background(), ctxWithAppID("test-app"), nil)
	mods := action.(policy.UpstreamRequestHeaderModifications)
	if mods.HeadersToSet["Authorization"] != "" {
		t.Error("Authorization header should not be set when signatureHeader overrides it")
	}
	if !strings.HasPrefix(mods.HeadersToSet["x-client-signature"], "Cert ") {
		t.Errorf("expected x-client-signature to start with 'Cert ', got: %q", mods.HeadersToSet["x-client-signature"])
	}
}

// TestOnRequestHeaders_CustomTTL verifies a custom ttlSeconds is applied to exp.
func TestOnRequestHeaders_CustomTTL(t *testing.T) {
	certFile, keyFile := generateTestCertAndKey(t)
	raw, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{
		"certFile":   certFile,
		"keyFile":    keyFile,
		"ttlSeconds": float64(60),
	})
	if err != nil {
		t.Fatalf("GetPolicy: %v", err)
	}
	cp := raw.(*CertSignerPolicy)

	action := cp.OnRequestHeaders(context.Background(), ctxWithAppID("test-app"), nil)
	mods := action.(policy.UpstreamRequestHeaderModifications)
	token := strings.TrimPrefix(mods.HeadersToSet["Authorization"], "Cert ")
	_, payload := decodeJWT(t, token)

	iat, _ := payload["iat"].(float64)
	exp, _ := payload["exp"].(float64)
	if int(exp-iat) != 60 {
		t.Errorf("expected TTL 60, got %v", exp-iat)
	}
}

// TestOnRequestHeaders_JTIFromHeader verifies the jti is read from the configured request header.
func TestOnRequestHeaders_JTIFromHeader(t *testing.T) {
	certFile, keyFile := generateTestCertAndKey(t)
	raw, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{
		"certFile":  certFile,
		"keyFile":   keyFile,
		"jtiHeader": "x-global-transaction-id",
	})
	if err != nil {
		t.Fatalf("GetPolicy: %v", err)
	}
	cp := raw.(*CertSignerPolicy)

	reqCtx := &policy.RequestHeaderContext{
		SharedContext: &policy.SharedContext{
			Metadata: map[string]interface{}{"x-wso2-application-id": "test-app"},
		},
		Headers: policy.NewHeaders(map[string][]string{
			"x-global-transaction-id": {"txn-abc-123"},
		}),
	}
	action := cp.OnRequestHeaders(context.Background(), reqCtx, nil)
	mods := action.(policy.UpstreamRequestHeaderModifications)
	token := strings.TrimPrefix(mods.HeadersToSet["Authorization"], "Cert ")
	_, payload := decodeJWT(t, token)

	if payload["jti"] != "txn-abc-123" {
		t.Errorf("expected jti txn-abc-123, got %v", payload["jti"])
	}
}

// TestOnRequestHeaders_JTIFallbackWhenHeaderAbsent verifies that a random UUID is used when the jti header is missing.
func TestOnRequestHeaders_JTIFallbackWhenHeaderAbsent(t *testing.T) {
	certFile, keyFile := generateTestCertAndKey(t)
	raw, _ := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{
		"certFile": certFile,
		"keyFile":  keyFile,
	})
	cp := raw.(*CertSignerPolicy)

	// Two requests with no jti header — should produce different jti values via random fallback.
	action1 := cp.OnRequestHeaders(context.Background(), ctxWithAppID("test-app"), nil)
	action2 := cp.OnRequestHeaders(context.Background(), ctxWithAppID("test-app"), nil)

	mods1 := action1.(policy.UpstreamRequestHeaderModifications)
	mods2 := action2.(policy.UpstreamRequestHeaderModifications)

	_, p1 := decodeJWT(t, strings.TrimPrefix(mods1.HeadersToSet["Authorization"], "Cert "))
	_, p2 := decodeJWT(t, strings.TrimPrefix(mods2.HeadersToSet["Authorization"], "Cert "))

	if p1["jti"] == p2["jti"] {
		t.Errorf("expected unique jti fallback per request, both got %v", p1["jti"])
	}
	if p1["jti"] == nil || p1["jti"] == "" {
		t.Error("expected non-empty jti fallback")
	}
}

// TestOnRequestHeaders_SubFromMetadata verifies sub is read from SharedContext.Metadata["x-wso2-application-id"].
func TestOnRequestHeaders_SubFromMetadata(t *testing.T) {
	certFile, keyFile := generateTestCertAndKey(t)
	raw, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{
		"certFile": certFile,
		"keyFile":  keyFile,
	})
	if err != nil {
		t.Fatalf("GetPolicy: %v", err)
	}
	cp := raw.(*CertSignerPolicy)

	reqCtx := &policy.RequestHeaderContext{
		SharedContext: &policy.SharedContext{
			Metadata: map[string]interface{}{
				"x-wso2-application-id": "app-id-9f3a",
			},
		},
	}
	action := cp.OnRequestHeaders(context.Background(), reqCtx, nil)
	mods, ok := action.(policy.UpstreamRequestHeaderModifications)
	if !ok {
		t.Fatalf("expected UpstreamRequestHeaderModifications, got %T", action)
	}
	token := strings.TrimPrefix(mods.HeadersToSet["Authorization"], "Cert ")
	_, payload := decodeJWT(t, token)

	if payload["sub"] != "app-id-9f3a" {
		t.Errorf("expected sub app-id-9f3a from metadata, got %v", payload["sub"])
	}
	if payload["iss"] != "test-gateway" {
		t.Errorf("expected iss test-gateway (cert CN), got %v", payload["iss"])
	}
}

// TestOnRequestHeaders_MissingAppIDRejects verifies a 401 is returned when x-wso2-application-id is absent.
func TestOnRequestHeaders_MissingAppIDRejects(t *testing.T) {
	certFile, keyFile := generateTestCertAndKey(t)
	raw, _ := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{
		"certFile": certFile,
		"keyFile":  keyFile,
	})
	cp := raw.(*CertSignerPolicy)

	// No metadata set — simulates cert-signer running before an auth policy.
	action := cp.OnRequestHeaders(context.Background(), &policy.RequestHeaderContext{}, nil)
	resp, ok := action.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("expected ImmediateResponse when app ID absent, got %T", action)
	}
	if resp.StatusCode != 401 {
		t.Errorf("expected 401, got %d", resp.StatusCode)
	}
}

// TestOnRequestHeaders_EmptyAppIDRejects verifies a 401 is returned when x-wso2-application-id is empty string.
func TestOnRequestHeaders_EmptyAppIDRejects(t *testing.T) {
	certFile, keyFile := generateTestCertAndKey(t)
	raw, _ := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{
		"certFile": certFile,
		"keyFile":  keyFile,
	})
	cp := raw.(*CertSignerPolicy)

	reqCtx := &policy.RequestHeaderContext{
		SharedContext: &policy.SharedContext{
			Metadata: map[string]interface{}{
				"x-wso2-application-id": "",
			},
		},
	}
	action := cp.OnRequestHeaders(context.Background(), reqCtx, nil)
	resp, ok := action.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("expected ImmediateResponse when app ID empty, got %T", action)
	}
	if resp.StatusCode != 401 {
		t.Errorf("expected 401, got %d", resp.StatusCode)
	}
}

// TestOnRequestHeaders_NilContext must not panic.
func TestOnRequestHeaders_NilContext(t *testing.T) {
	certFile, keyFile := generateTestCertAndKey(t)
	raw, _ := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{
		"certFile": certFile,
		"keyFile":  keyFile,
	})
	cp := raw.(*CertSignerPolicy)
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("panic on nil context: %v", r)
		}
	}()
	cp.OnRequestHeaders(context.Background(), nil, nil)
}
