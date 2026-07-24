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

// Package websubhmacauth implements HMAC signature validation for WebSub hub
// event notifications. It verifies the X-Hub-Signature-256 (or X-Hub-Signature)
// header sent by WebSub hubs against all active shared secrets stored for the
// API, accepting the request if any secret produces a matching signature.
package websubhmacauth

import (
	"context"
	"crypto/hmac"
	"crypto/sha1" //nolint:gosec // SHA-1 is required by the WebSub spec (W3C WebSub §X.509)
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash"
	"log/slog"
	"strings"

	"github.com/wso2/api-platform/common/webhooksecret"
	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

const (
	// defaultSignatureHeader is the preferred WebSub signature header (SHA-256).
	defaultSignatureHeader = "X-Hub-Signature-256"

	// signatureHeaderLegacy is the older SHA-1 based header still used by some hubs.
	signatureHeaderLegacy = "X-Hub-Signature"

	algorithmSHA256 = "sha256"
	algorithmSHA1   = "sha1"
	algorithmSHA512 = "sha512"
)

// WebSubHMACAuthPolicy validates incoming WebSub event notification requests
// by verifying the HMAC signature in the X-Hub-Signature / X-Hub-Signature-256
// header against all active shared secrets stored for the API.
type WebSubHMACAuthPolicy struct {
	algorithm       string
	signatureHeader string
}

// GetPolicy is the v1alpha2 factory entry point.
func GetPolicy(
	metadata policy.PolicyMetadata,
	params map[string]interface{},
) (policy.Policy, error) {
	p := &WebSubHMACAuthPolicy{}

	// --- algorithm (optional, default sha256) ---
	algorithm := algorithmSHA256
	if algRaw, ok := params["algorithm"]; ok {
		if algStr, ok := algRaw.(string); ok && algStr != "" {
			algorithm = strings.ToLower(algStr)
		}
	}
	switch algorithm {
	case algorithmSHA256, algorithmSHA1, algorithmSHA512:
		p.algorithm = algorithm
	default:
		return nil, fmt.Errorf("websub-hmac-auth: unsupported algorithm %q; supported values: sha256, sha1, sha512", algorithm)
	}

	// --- signatureHeader (optional) ---
	// Default to the algorithm-appropriate header if not explicitly set.
	sigHeader := defaultSignatureHeader
	if p.algorithm == algorithmSHA1 {
		sigHeader = signatureHeaderLegacy
	}
	if hdrRaw, ok := params["signatureHeader"]; ok {
		if hdrStr, ok := hdrRaw.(string); ok && hdrStr != "" {
			sigHeader = hdrStr
		}
	}
	p.signatureHeader = sigHeader

	slog.Debug("WebSubHMACAuth: policy initialised",
		"algorithm", p.algorithm,
		"signatureHeader", p.signatureHeader,
	)

	return p, nil
}

// Mode instructs the kernel to buffer the full request body so that the HMAC
// can be computed over the payload bytes, while skipping response processing.
func (p *WebSubHMACAuthPolicy) Mode() policy.ProcessingMode {
	return policy.ProcessingMode{
		RequestHeaderMode:  policy.HeaderModeProcess,
		RequestBodyMode:    policy.BodyModeBuffer,
		ResponseHeaderMode: policy.HeaderModeSkip,
		ResponseBodyMode:   policy.BodyModeSkip,
	}
}

// OnRequestHeaders performs a lightweight check that the signature header is
// present before the kernel buffers the body. This avoids buffering large
// payloads for requests that are obviously missing the required header.
func (p *WebSubHMACAuthPolicy) OnRequestHeaders(
	_ context.Context,
	reqCtx *policy.RequestHeaderContext,
	_ map[string]interface{},
) policy.RequestHeaderAction {
	vals := getDownstreamHeaders(reqCtx.Downstream, reqCtx.Headers).Get(p.signatureHeader)
	if len(vals) == 0 {
		slog.Debug("WebSubHMACAuth: signature header absent",
			"header", p.signatureHeader,
		)
		return p.immediateUnauthorized("missing signature header: " + p.signatureHeader)
	}
	return policy.UpstreamRequestHeaderModifications{}
}

// OnRequestBody verifies the HMAC signature over the buffered request body.
// It reads all active secrets for the API from the webhook secret store and
// accepts the request if any secret produces a matching signature.
func (p *WebSubHMACAuthPolicy) OnRequestBody(
	_ context.Context,
	reqCtx *policy.RequestContext,
	_ map[string]interface{},
) policy.RequestAction {
	slog.Info("WebSubHMACAuth: verifying request body HMAC signature",
		"apiId", reqCtx.APIId,
		"signatureHeader", p.signatureHeader,
	)
	// Retrieve signature header value from the downstream snapshot so
	// the HMAC is verified against what the client actually sent, not a value a
	// peer policy may have rewritten during the header phase.
	sigVals := getDownstreamHeaders(reqCtx.Downstream, reqCtx.Headers).Get(p.signatureHeader)
	if len(sigVals) == 0 {
		return p.immediateRequestUnauthorized("missing signature header: " + p.signatureHeader)
	}

	rawSig := sigVals[0]

	// Parse "algorithm=hexdigest" format (e.g. "sha256=abc123...").
	algorithm, providedHex, err := parseSignatureHeader(rawSig)
	if err != nil {
		slog.Info("WebSubHMACAuth: malformed signature header",
			"header", p.signatureHeader,
			"error", err,
		)
		return p.immediateRequestUnauthorized("malformed signature header")
	}

	// Verify the algorithm token matches what is configured.
	if !strings.EqualFold(algorithm, p.algorithm) {
		slog.Info("WebSubHMACAuth: algorithm mismatch",
			"expected", p.algorithm,
			"got", algorithm,
		)
		return p.immediateRequestUnauthorized(
			fmt.Sprintf("algorithm mismatch: expected %s, got %s", p.algorithm, algorithm))
	}

	// Determine the payload to sign.
	var payload []byte
	if reqCtx.Body != nil {
		payload = reqCtx.Body.Content
	}

	secrets := webhooksecret.GetStoreInstance().GetAllByAPI(reqCtx.APIId)
	if len(secrets) == 0 {
		slog.Info("WebSubHMACAuth: no secrets configured", "apiId", reqCtx.APIId)
		return p.immediateRequestUnauthorized("no webhook secrets configured for this API")
	}

	// Accept if any secret produces a matching HMAC; reject only when all fail.
	for _, secret := range secrets {
		mac, err := computeHMAC(payload, p.algorithm, []byte(secret))
		if err != nil {
			slog.Info("WebSubHMACAuth: HMAC computation failed", "error", err)
			continue
		}
		providedBytes, decErr := hex.DecodeString(providedHex)
		if decErr != nil {
			slog.Info("WebSubHMACAuth: invalid hex in signature header", "header", p.signatureHeader, "error", decErr)
			return p.immediateRequestUnauthorized("malformed signature hex")
		}
		if hmac.Equal(mac, providedBytes) {
			slog.Info("WebSubHMACAuth: signature verified successfully")
			return policy.UpstreamRequestModifications{}
		}
	}

	slog.Info("WebSubHMACAuth: signature mismatch against all secrets", "header", p.signatureHeader)
	return p.immediateRequestUnauthorized("invalid HMAC signature")
}

// computeHMAC returns the raw HMAC bytes for the given payload using the
// specified algorithm and secret.
func computeHMAC(payload []byte, algorithm string, secret []byte) ([]byte, error) {
	var h hash.Hash
	switch algorithm {
	case algorithmSHA256:
		h = hmac.New(sha256.New, secret)
	case algorithmSHA1:
		h = hmac.New(sha1.New, secret) //nolint:gosec // SHA-1 required by WebSub spec
	case algorithmSHA512:
		h = hmac.New(sha512.New, secret)
	default:
		return nil, fmt.Errorf("unsupported algorithm: %s", algorithm)
	}
	_, err := h.Write(payload)
	if err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}

// parseSignatureHeader splits a "algorithm=hexdigest" value into its parts.
// Example input: "sha256=abc123def456..."
func parseSignatureHeader(value string) (algorithm, digest string, err error) {
	parts := strings.SplitN(value, "=", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", fmt.Errorf("expected format <algorithm>=<hexdigest>, got: %q", value)
	}
	return parts[0], parts[1], nil
}

// immediateUnauthorized returns an ImmediateResponse for the header phase.
func (p *WebSubHMACAuthPolicy) immediateUnauthorized(reason string) policy.ImmediateResponse {
	slog.Debug("WebSubHMACAuth: rejecting request in header phase", "reason", reason)
	body, _ := json.Marshal(map[string]string{
		"error":   "Unauthorized",
		"message": reason,
	})
	return policy.ImmediateResponse{
		StatusCode: 401,
		Headers:    map[string]string{"content-type": "application/json"},
		Body:       body,
	}
}

// immediateRequestUnauthorized returns an ImmediateResponse for the body phase.
func (p *WebSubHMACAuthPolicy) immediateRequestUnauthorized(reason string) policy.ImmediateResponse {
	slog.Info("WebSubHMACAuth: rejecting request in body phase", "reason", reason)
	body, _ := json.Marshal(map[string]string{
		"error":   "Unauthorized",
		"message": reason,
	})
	return policy.ImmediateResponse{
		StatusCode: 401,
		Headers:    map[string]string{"content-type": "application/json"},
		Body:       body,
	}
}
