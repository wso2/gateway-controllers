/*
 * cert-signer policy — gateway-to-backend certificate-based authentication.
 *
 * Uses a configured certificate + private key (pre-shared with the backend provider,
 * supplied as PEM strings or file paths) to generate a short-lived RS256-signed JWT and
 * sets it as the Authorization header on every upstream request.
 *
 * The backend holds the certificate pre-shared and verifies the JWT
 * signature using the certificate's public key.  The cert itself is never sent
 * per-request.
 *
 * Resulting Authorization header (default scheme "Cert"):
 *
 *   Authorization: Cert <compact-RS256-jwt>
 *
 * JWT claims: iss (cert CN), iat (now), exp (now+ttl), jti (random UUID).
 * Optional: sub, aud.
 *
 * Key/cert defaults: /etc/gateway/mtls/tls.crt and tls.key — the standard mount
 * path when a Kubernetes TLS secret is projected into the pod.
 */

package certsigner

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

const (
	defaultCertFile        = "/etc/gateway/mtls/tls.crt"
	defaultKeyFile         = "/etc/gateway/mtls/tls.key"
	defaultScheme          = "Cert"
	defaultSignatureHeader = "Authorization"
	defaultJTIHeader       = "x-global-transaction-id"
	defaultTTLSeconds      = 300 // 5 minutes
)

// PolicyConfig holds the resolved, deploy-time configuration.
type PolicyConfig struct {
	PrivateKey      *rsa.PrivateKey
	Issuer          string // iss claim (defaults to cert CN)
	Audience        string // aud claim (optional)
	Scheme          string // token prefix in the header value (default: Cert)
	SignatureHeader string // which request header to set (default: Authorization)
	JTIHeader       string // request header to read jti from (default: x-global-transaction-id); falls back to random UUID when absent
	TTLSeconds      int    // JWT lifetime in seconds (default: 300)
	// sub is not stored in config — it is read per-request from
	// SharedContext.Metadata["x-wso2-application-id"] (set by jwt-auth or client-secret-basic).
}

// CertSignerPolicy generates a short-lived RS256 JWT from a configured
// certificate and injects it as the Authorization header on every upstream
// request, replacing any existing Authorization header from the client.
type CertSignerPolicy struct {
	cfg PolicyConfig
}

// GetPolicy is the v1alpha2 factory entry point.  Cert and key are loaded from
// PEM strings (certPem/keyPem) or from files (certFile/keyFile).  Any
// misconfiguration fails hard at deploy time, not per-request.
func GetPolicy(metadata policy.PolicyMetadata, params map[string]interface{}) (policy.Policy, error) {
	cfg, err := parseConfig(params)
	if err != nil {
		return nil, err
	}
	return &CertSignerPolicy{cfg: cfg}, nil
}

func parseConfig(params map[string]interface{}) (PolicyConfig, error) {
	cfg := PolicyConfig{
		Scheme:          defaultScheme,
		SignatureHeader: defaultSignatureHeader,
		JTIHeader:       defaultJTIHeader,
		TTLSeconds:      defaultTTLSeconds,
	}

	if v, _ := params["scheme"].(string); strings.TrimSpace(v) != "" {
		cfg.Scheme = strings.TrimSpace(v)
	}
	if v, _ := params["signatureHeader"].(string); strings.TrimSpace(v) != "" {
		cfg.SignatureHeader = strings.TrimSpace(v)
	}
	if v, _ := params["jtiHeader"].(string); strings.TrimSpace(v) != "" {
		cfg.JTIHeader = strings.TrimSpace(v)
	}
	if v, _ := params["issuer"].(string); strings.TrimSpace(v) != "" {
		cfg.Issuer = strings.TrimSpace(v)
	}
	if v, _ := params["audience"].(string); strings.TrimSpace(v) != "" {
		cfg.Audience = strings.TrimSpace(v)
	}
	if v, ok := params["ttlSeconds"].(float64); ok && v > 0 {
		cfg.TTLSeconds = int(v)
	}

	// Load certificate (for issuer extraction).
	certPEM, _ := params["certPem"].(string)
	if strings.TrimSpace(certPEM) == "" {
		certFile, _ := params["certFile"].(string)
		if strings.TrimSpace(certFile) == "" {
			certFile = defaultCertFile
		}
		b, err := os.ReadFile(strings.TrimSpace(certFile))
		if err != nil {
			return cfg, fmt.Errorf("cert-signer: reading certFile %q: %w", certFile, err)
		}
		certPEM = string(b)
	}
	cert, err := parseCert([]byte(certPEM))
	if err != nil {
		return cfg, fmt.Errorf("cert-signer: parsing cert: %w", err)
	}
	// Derive issuer from cert CN unless explicitly overridden.
	if cfg.Issuer == "" {
		cfg.Issuer = cert.Subject.CommonName
	}

	// Load private key for signing.
	keyPEM, _ := params["keyPem"].(string)
	if strings.TrimSpace(keyPEM) == "" {
		keyFile, _ := params["keyFile"].(string)
		if strings.TrimSpace(keyFile) == "" {
			keyFile = defaultKeyFile
		}
		b, err := os.ReadFile(strings.TrimSpace(keyFile))
		if err != nil {
			return cfg, fmt.Errorf("cert-signer: reading keyFile %q: %w", keyFile, err)
		}
		keyPEM = string(b)
	}
	privKey, err := parsePrivateKey([]byte(keyPEM))
	if err != nil {
		return cfg, fmt.Errorf("cert-signer: parsing key: %w", err)
	}
	cfg.PrivateKey = privKey

	return cfg, nil
}

func parseCert(pemBytes []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in cert")
	}
	return x509.ParseCertificate(block.Bytes)
}

func parsePrivateKey(pemBytes []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in key")
	}
	switch block.Type {
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		rsaKey, ok := key.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("PKCS8 key is %T, not RSA", key)
		}
		return rsaKey, nil
	default:
		return nil, fmt.Errorf("unsupported PEM block type %q; expected RSA PRIVATE KEY or PRIVATE KEY", block.Type)
	}
}

// Mode — header phase only; body is not needed.
func (p *CertSignerPolicy) Mode() policy.ProcessingMode {
	return policy.ProcessingMode{
		RequestHeaderMode:  policy.HeaderModeProcess,
		RequestBodyMode:    policy.BodyModeSkip,
		ResponseHeaderMode: policy.HeaderModeSkip,
		ResponseBodyMode:   policy.BodyModeSkip,
	}
}

// OnRequestHeaders generates a fresh RS256 JWT and
// sets it as Authorization: <scheme> <jwt> on every upstream request,
// replacing the client's original Authorization header.
//
// sub — read from SharedContext.Metadata["x-wso2-application-id"], set by an
// upstream auth policy (jwt-auth or client-secret-basic). The request is
// rejected with 401 when this value is absent or empty.
//
// jti — read from the configured request header (default: x-global-transaction-id).
// Falls back to a random UUID when absent.
func (p *CertSignerPolicy) OnRequestHeaders(
	ctx context.Context,
	reqCtx *policy.RequestHeaderContext,
	params map[string]interface{},
) policy.RequestHeaderAction {
	if reqCtx == nil {
		slog.Warn("cert-signer: nil request context, skipping")
		return policy.UpstreamRequestHeaderModifications{}
	}

	// Read application ID set by an upstream auth policy (jwt-auth / client-secret-basic).
	// SharedContext is an embedded pointer; guard both levels before access.
	appID := ""
	if reqCtx.SharedContext != nil && reqCtx.Metadata != nil {
		if v, ok := reqCtx.Metadata["x-wso2-application-id"]; ok {
			appID, _ = v.(string)
		}
	}
	if appID == "" {
		slog.Error("cert-signer: x-wso2-application-id missing from metadata — auth policy must run before cert-signer")
		return policy.ImmediateResponse{
			StatusCode: 401,
			Body:       []byte(`{"error":"unauthorized","message":"application identity not established"}`),
			Headers:    map[string]string{"Content-Type": "application/json"},
		}
	}

	jti := ""
	if reqCtx.Headers != nil {
		if vals := reqCtx.Headers.Get(p.cfg.JTIHeader); len(vals) > 0 {
			jti = vals[0]
		}
	}

	token, err := buildJWT(p.cfg, appID, jti)
	if err != nil {
		slog.Error("cert-signer: JWT generation failed", "error", err)
		return policy.UpstreamRequestHeaderModifications{}
	}

	slog.Debug("cert-signer: injected cert JWT", "header", p.cfg.SignatureHeader, "scheme", p.cfg.Scheme, "issuer", p.cfg.Issuer, "sub", appID)

	return policy.UpstreamRequestHeaderModifications{
		HeadersToSet: map[string]string{
			p.cfg.SignatureHeader: p.cfg.Scheme + " " + token,
		},
	}
}

// OnResponseHeaders is a no-op.
func (p *CertSignerPolicy) OnResponseHeaders(
	ctx context.Context,
	respCtx *policy.ResponseHeaderContext,
	params map[string]interface{},
) policy.ResponseHeaderAction {
	return policy.DownstreamResponseHeaderModifications{}
}

// buildJWT creates a compact RS256-signed JWT from the policy configuration.
//
// Format: base64(header) . base64(payload) . base64(signature)
//
// Header: {"alg":"RS256"} — no typ field.
// Payload: typ:"JWT" in the payload body.
// Encoding: standard base64 with padding.
//
// sub is the application ID read from SharedContext.Metadata["x-wso2-application-id"].
// jtiValue is used as the jti claim; falls back to a random UUID when empty.
func buildJWT(cfg PolicyConfig, sub string, jtiValue string) (string, error) {
	now := time.Now().Unix()

	if jtiValue == "" {
		jtiValue = newJTI()
	}

	claims := map[string]interface{}{
		"iss": cfg.Issuer,
		"sub": sub,
		"typ": "JWT",
		"iat": now,
		"exp": now + int64(cfg.TTLSeconds),
		"jti": jtiValue,
	}
	if cfg.Audience != "" {
		claims["aud"] = cfg.Audience
	}

	headerJSON, _ := json.Marshal(map[string]string{"alg": "RS256"})
	payloadJSON, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("marshalling claims: %w", err)
	}

	sigInput := b64std(headerJSON) + "." + b64std(payloadJSON)
	digest := sha256.Sum256([]byte(sigInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, cfg.PrivateKey, crypto.SHA256, digest[:])
	if err != nil {
		return "", fmt.Errorf("signing JWT: %w", err)
	}

	return sigInput + "." + b64std(sig), nil
}

// b64std encodes bytes as standard base64 with padding.
func b64std(src []byte) string {
	return base64.StdEncoding.EncodeToString(src)
}

// newJTI returns a random 128-bit UUID-shaped string for use as a JWT ID.
func newJTI() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}
