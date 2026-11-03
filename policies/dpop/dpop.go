/*
 * Copyright (c) 2026, WSO2 LLC. (https://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

// Package dpop implements the dpop policy, the resource-server side of OAuth
// 2.0 Demonstrating Proof of Possession (RFC 9449). It does not validate the
// access token itself: an access-token policy earlier in the chain (jwt-auth or
// opaque-token-auth) does that and records the token's claims on the
// AuthContext. This policy reads the token's confirmation claim (cnf.jkt) from
// there, verifies the DPoP proof JWT the client sent in the DPoP header against
// the current request, and checks that the proof was signed by the key the
// token is bound to and covers that exact token (ath). A DPoP-bound token
// presented as a plain bearer token is always rejected, so a stolen token
// cannot be downgraded to bearer use.
package dpop

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"time"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

const (
	// AuthType identifies this policy in the AuthContext layer it records on failure.
	AuthType = "dpop"

	modeRequired = "required"
	modeOptional = "optional"

	dpopScheme            = "DPoP"
	bearerScheme          = "Bearer"
	authorizationHeader   = "authorization"
	dpopHeader            = "dpop"
	dpopNonceHeader       = "DPoP-Nonce"
	wwwAuthenticateHeader = "WWW-Authenticate"

	// MetadataKeyThumbprint is the SharedContext.Metadata key under which a verified
	// request's JWK SHA-256 thumbprint (the key the access token is bound to) is
	// recorded for later policies.
	MetadataKeyThumbprint = "dpop.jkt"
	// metadataKeyRotateNonce marks a verified request whose nonce is past half its
	// lifetime, so the response phase hands the client the next one.
	metadataKeyRotateNonce = "dpop.rotateNonce"

	defaultMode               = modeRequired
	defaultProofMaxAge        = time.Minute
	defaultClockSkew          = 30 * time.Second
	defaultNonceLifetime      = 5 * time.Minute
	defaultReplayCacheMaxSize = 100000

	// minNonceSecretLength is the shortest nonce secret accepted: 256 bits.
	minNonceSecretLength = 32
)

// supportedAlgorithms lists, in advertising order, the asymmetric JWS algorithms a
// proof may be signed with. HMAC and none are never accepted.
var supportedAlgorithms = []string{
	"ES256", "ES384", "ES512",
	"PS256", "PS384", "PS512",
	"RS256", "RS384", "RS512",
	"EdDSA", "Ed25519",
}

// defaultAlgorithms are the algorithms accepted when allowedAlgorithms is not set:
// every supported one except RSASSA-PKCS1-v1_5 (RS256/384/512), which FAPI 2.0
// (section 5.4.1) does not allow. RS* stays available by listing it.
var defaultAlgorithms = []string{
	"ES256", "ES384", "ES512",
	"PS256", "PS384", "PS512",
	"EdDSA", "Ed25519",
}

// config is a policy instance's parsed, validated parameters.
type config struct {
	mode          string
	algorithms    []string
	algSet        map[string]bool
	algsChallenge string
	proofMaxAge   time.Duration
	clockSkew     time.Duration
	requireNonce  bool
	nonceLifetime time.Duration
	htuOrigins    []string
	forwardProof  bool
	// tokenAuthTypes are the AuthContext types whose layers count as a validated
	// access token.
	tokenAuthTypes map[string]bool
}

// DPoPPolicy verifies DPoP proofs for one API or operation.
type DPoPPolicy struct {
	cfg    config
	replay replayChecker
	nonces *nonceIssuer
	now    func() time.Time
}

// defaultAccessTokenAuthTypes are the AuthContext types of the policies that validate
// an OAuth access token: jwt-auth, opaque-token-auth, and mcp-auth (which delegates
// to jwt-auth). The accessTokenAuthTypes system parameter replaces the list, so a new
// token policy is enabled by configuration, not by changing this policy. Layers of
// any other type are ignored, so an unlisted policy fails closed: client credentials
// without a token (api-key-auth, basic-auth, mtls-auth) and credentials the gateway
// itself sends to the backend (oauth2-generator, aws-authentication) also mark their
// layers authenticated, and must never stand in for a validated access token.
var defaultAccessTokenAuthTypes = []string{"jwt", "opaque", "mcp/oauth"}

// GetPolicy parses and validates the instance's parameters. An unusable value
// fails the deployment rather than weakening verification at request time.
func GetPolicy(metadata policy.PolicyMetadata, params map[string]interface{}) (policy.Policy, error) {
	cfg, err := parseConfig(params)
	if err != nil {
		return nil, fmt.Errorf("dpop: %w", err)
	}
	maxSize, err := intParam(params, "replayCacheMaxSize", defaultReplayCacheMaxSize)
	if err != nil {
		return nil, fmt.Errorf("dpop: %w", err)
	}
	if maxSize < 1 {
		return nil, fmt.Errorf("dpop: replayCacheMaxSize must be at least 1")
	}
	secret, err := stringParam(params, "nonceSecret", "")
	if err != nil {
		return nil, fmt.Errorf("dpop: %w", err)
	}
	if secret != "" && len(secret) < minNonceSecretLength {
		return nil, fmt.Errorf("dpop: nonceSecret must be at least %d bytes", minNonceSecretLength)
	}
	if cfg.requireNonce && secret == "" {
		warnEvery("nonce-secret:"+metadata.APIName, time.Now(), "dpop: requireNonce is on without nonceSecret; nonces are signed with a per-process key, so with more than one gateway replica a nonce issued by one replica is refused by another. Set the same nonceSecret on every replica.",
			slog.String("api", metadata.APIName))
	}
	replay, err := newReplayChecker(params, maxSize)
	if err != nil {
		return nil, fmt.Errorf("dpop: %w", err)
	}
	return &DPoPPolicy{
		cfg:    cfg,
		replay: replay,
		nonces: newNonceIssuer(secret),
		now:    time.Now,
	}, nil
}

// Mode asks for the response headers only when nonces are in use, to hand the
// client its next nonce before the current one expires.
func (p *DPoPPolicy) Mode() policy.ProcessingMode {
	responseHeaders := policy.HeaderModeSkip
	if p.cfg.requireNonce {
		responseHeaders = policy.HeaderModeProcess
	}
	return policy.ProcessingMode{
		RequestHeaderMode:  policy.HeaderModeProcess,
		RequestBodyMode:    policy.BodyModeSkip,
		ResponseHeaderMode: responseHeaders,
		ResponseBodyMode:   policy.BodyModeSkip,
	}
}

// OnRequestHeaders verifies the request's DPoP proof against the access token an
// earlier policy authenticated. Headers are read from the downstream snapshot, so
// an earlier policy that renamed or stripped Authorization does not hide the
// scheme or token the client actually sent.
func (p *DPoPPolicy) OnRequestHeaders(ctx context.Context, reqCtx *policy.RequestHeaderContext, params map[string]interface{}) policy.RequestHeaderAction {
	shared := reqCtx.SharedContext
	req := reqCtx.DownstreamRequest()

	binding := tokenBinding(shared.AuthContext, p.cfg.tokenAuthTypes)
	if !binding.authenticated {
		warnEvery("misconfigured:"+shared.APIName, p.now(),
			"dpop: no access-token policy authenticated the request; attach jwt-auth, opaque-token-auth or mcp-auth before the dpop policy in the same chain. If another policy in the chain validates OAuth access tokens, add its AuthContext type to accesstokenauthtypes. Every request is refused until then.",
			slog.String("api", shared.APIName),
			slog.Any("authenticatedTypesIgnored", binding.ignored))
		return p.reject(shared, errInvalidToken("no access-token policy authenticated the request", "access token required"))
	}
	if binding.malformed != "" {
		// RFC 9449 section 6: the resource server must reliably tell whether a token is
		// bound, so an unreadable binding is refused rather than treated as unbound.
		return p.reject(shared, errInvalidToken(binding.malformed, "invalid DPoP key binding"))
	}
	jkt := binding.jkt

	// RFC 9449 section 7.2: more than one Authorization header (for example a Bearer
	// and a DPoP credential together) is an invalid request. A proxy may fold repeated
	// headers into one value joined by commas, which no token68 credential contains.
	authz := req.Headers.Get(authorizationHeader)
	if len(authz) > 1 || (len(authz) == 1 && strings.ContainsRune(authz[0], ',')) {
		return p.reject(shared, errInvalidRequest("more than one Authorization header"))
	}
	scheme, token := splitAuthorization(authz)
	proofs := req.Headers.Get(dpopHeader)

	if !strings.EqualFold(scheme, dpopScheme) {
		// RFC 9449 section 7.2: a DPoP-bound token must never be accepted as a bearer
		// token. The client chose the Bearer scheme, so the error goes in the Bearer
		// challenge, alongside a DPoP challenge naming the accepted algorithms.
		if jkt != "" {
			return p.reject(shared, errBearer("bound token presented without the DPoP scheme", "DPoP-bound access token requires the DPoP authorization scheme"))
		}
		if p.cfg.mode == modeRequired {
			return p.reject(shared, errBearer("unbound token in required mode", "DPoP-bound access token required"))
		}
		// Optional mode: an unbound bearer token passes; a stray DPoP header is dropped.
		return p.allow(len(proofs) > 0)
	}

	if jkt == "" {
		return p.reject(shared, errInvalidToken("DPoP scheme with an unbound token", "access token is not DPoP-bound"))
	}
	if token == "" {
		return p.reject(shared, errInvalidToken("empty access token", "malformed authorization header"))
	}
	// The proof's ath covers the token in Authorization; the binding comes from the
	// token the access-token policy validated. They must be the same token, or a
	// policy reading another header could validate one token while the proof
	// covers a different one.
	if !sameToken(binding.layer, token, jkt) {
		return p.reject(shared, errInvalidToken("Authorization token is not the token the access-token policy validated", "access token mismatch"))
	}

	proof, perr := singleProof(proofs)
	if perr != nil {
		return p.reject(shared, perr)
	}

	target, terr := p.requestTarget(req)
	if terr != nil {
		warnEvery("request-uri:"+shared.APIName, p.now(), "dpop: cannot determine the request URI to check htu against; configure htuOrigins",
			slog.String("api", shared.APIName), slog.String("error", terr.Error()))
		return p.reject(shared, errInvalidProofDetail("gateway cannot determine the request URI", terr.Error()))
	}

	now := p.now()
	verified, perr := p.verifyProof(ctx, proof, req.Method, target, token, jkt, now)
	if perr != nil {
		return p.reject(shared, perr)
	}

	if shared.Metadata == nil {
		shared.Metadata = make(map[string]interface{})
	}
	shared.Metadata[MetadataKeyThumbprint] = jkt
	if p.cfg.requireNonce && now.Sub(verified.nonceIssued) > p.cfg.nonceLifetime/2 {
		shared.Metadata[metadataKeyRotateNonce] = true
	}
	return p.allow(true)
}

// OnResponseHeaders hands the client its next nonce once the one it used is past
// half its lifetime, so a busy client never has to retry after a use_dpop_nonce
// challenge. A response carrying a nonce must not be cached (RFC 9449 section 8.2),
// so only those few responses are marked no-store; setting the header also replaces
// any DPoP-Nonce the upstream sent, since there must be only one.
func (p *DPoPPolicy) OnResponseHeaders(ctx context.Context, respCtx *policy.ResponseHeaderContext, params map[string]interface{}) policy.ResponseHeaderAction {
	if !p.cfg.requireNonce {
		return policy.DownstreamResponseHeaderModifications{}
	}
	if rotate, _ := respCtx.Metadata[metadataKeyRotateNonce].(bool); !rotate {
		return policy.DownstreamResponseHeaderModifications{}
	}
	return policy.DownstreamResponseHeaderModifications{
		HeadersToSet: map[string]string{
			dpopNonceHeader: p.nonces.issue(p.now()),
			"Cache-Control": "no-store",
		},
	}
}

// allow continues to the upstream, removing the DPoP header unless it is forwarded.
func (p *DPoPPolicy) allow(proofPresent bool) policy.RequestHeaderAction {
	if proofPresent && !p.cfg.forwardProof {
		return policy.UpstreamRequestHeaderModifications{HeadersToRemove: []string{"DPoP"}}
	}
	return policy.UpstreamRequestHeaderModifications{}
}

// binding is what the AuthContext chain says about the access token's DPoP binding.
type binding struct {
	authenticated bool                // an access-token policy authenticated the caller
	jkt           string              // cnf.jkt of the token; empty when the token is not DPoP-bound
	malformed     string              // why the binding could not be read, when it could not
	ignored       []string            // types of authenticated layers that are not access-token layers
	layer         *policy.AuthContext // the access-token layer the binding was read from
}

// tokenBinding walks the AuthContext chain, newest first, over the layers an
// access-token policy authenticated (types in tokenTypes), to the newest one that
// carries a cnf claim, or that declares itself a DPoP token through an introspected
// token_type. A cnf without jkt (for example an mTLS-bound token's x5t#S256) is not
// a DPoP binding.
func tokenBinding(ac *policy.AuthContext, tokenTypes map[string]bool) binding {
	var b binding
	for layer := ac; layer != nil; layer = layer.Previous {
		if !layer.Authenticated {
			continue
		}
		if !tokenTypes[layer.AuthType] {
			b.ignored = append(b.ignored, layer.AuthType)
			continue
		}
		b.authenticated = true
		jkt, present, malformed := cnfThumbprint(layer)
		if malformed != "" {
			b.malformed = malformed
			return b
		}
		if jkt != "" {
			b.jkt = jkt
			b.layer = layer
			return b
		}
		// RFC 9449 section 6.2: an introspection response for a DPoP-bound token has
		// token_type DPoP; without a cnf.jkt the binding cannot be checked.
		if strings.EqualFold(layer.Properties["token_type"], dpopScheme) {
			b.malformed = "token_type is DPoP but cnf.jkt is missing"
			return b
		}
		if present {
			return b
		}
	}
	return b
}

// cnfThumbprint reads cnf.jkt from a layer. jwt-auth keeps cnf as a structured
// TypedProperties value; opaque-token-auth flattens it to a JSON string in
// Properties. present reports a cnf claim at all; malformed reports a cnf that is
// not an object, or a jkt that is not a non-empty string.
func cnfThumbprint(layer *policy.AuthContext) (jkt string, present bool, malformed string) {
	var cnf interface{}
	if v, ok := layer.TypedProperties["cnf"]; ok {
		cnf, present = v, true
	} else if raw, ok := layer.Properties["cnf"]; ok && raw != "" {
		present = true
		if err := json.Unmarshal([]byte(raw), &cnf); err != nil {
			return "", true, "cnf is not valid JSON"
		}
	}
	if !present {
		return "", false, ""
	}
	obj, ok := cnf.(map[string]interface{})
	if !ok {
		return "", true, "cnf is not an object"
	}
	v, ok := obj["jkt"]
	if !ok {
		return "", true, ""
	}
	if s, ok := v.(string); ok && s != "" {
		return s, true, ""
	}
	return "", true, "cnf.jkt is not a non-empty string"
}

// splitAuthorization splits the first Authorization header into its scheme and
// credential. A missing or credential-less header yields an empty token.
func splitAuthorization(values []string) (scheme, token string) {
	if len(values) == 0 {
		return "", ""
	}
	parts := strings.Fields(values[0])
	switch len(parts) {
	case 0:
		return "", ""
	case 1:
		return parts[0], ""
	case 2:
		return parts[0], parts[1]
	default:
		return parts[0], ""
	}
}

// singleProof enforces RFC 9449 section 4.3 check 1: exactly one DPoP header
// carrying one value. A proxy that folded duplicate headers joins them with a
// comma, which never appears in a compact JWS.
func singleProof(values []string) (string, *dpopError) {
	if len(values) == 0 {
		return "", errInvalidProof("missing DPoP header")
	}
	if len(values) > 1 {
		return "", errInvalidProof("more than one DPoP header")
	}
	proof := strings.TrimSpace(values[0])
	if proof == "" {
		return "", errInvalidProof("empty DPoP header")
	}
	if strings.ContainsRune(proof, ',') {
		return "", errInvalidProof("more than one DPoP header value")
	}
	return proof, nil
}

// requestTarget computes the origins and normalized path an htu claim must match.
func (p *DPoPPolicy) requestTarget(req *policy.DownstreamRequest) (htuTarget, error) {
	path := req.Path
	if i := strings.IndexAny(path, "?#"); i >= 0 {
		path = path[:i]
	}
	if u, err := url.ParseRequestURI(path); err == nil {
		path = u.EscapedPath()
	}
	target := htuTarget{path: normalizePath(path)}
	if len(p.cfg.htuOrigins) > 0 {
		target.origins = p.cfg.htuOrigins
		target.configured = true
		return target, nil
	}
	scheme := strings.ToLower(req.Scheme)
	if scheme == "" {
		scheme = "https"
	}
	if req.Authority == "" {
		return htuTarget{}, fmt.Errorf("request has no :authority")
	}
	origin, err := normalizeOrigin(scheme, req.Authority)
	if err != nil {
		return htuTarget{}, err
	}
	target.origins = []string{origin}
	return target, nil
}

// dpopError is a rejection: the status, the RFC 6750 / RFC 9449 error code sent in
// the challenge, a fixed description safe to show the client, and the precise
// reason, which only reaches the debug log. A bearer error is reported in a Bearer
// challenge, because the client used the Bearer scheme.
type dpopError struct {
	status      int
	code        string
	description string
	reason      string
	bearer      bool
}

// errInvalidProof refuses a proof with a fixed description naming the failed check.
// It never contains a value from the request, so it is safe to send to the client.
func errInvalidProof(description string) *dpopError {
	return errInvalidProofDetail(description, "")
}

// errInvalidProofDetail adds a detail, which may quote the proof, for the debug log only.
func errInvalidProofDetail(description, detail string) *dpopError {
	reason := description
	if detail != "" {
		reason += ": " + detail
	}
	return &dpopError{status: 401, code: "invalid_dpop_proof", description: description, reason: reason}
}

// errInvalidToken refuses the access token itself (RFC 6750 invalid_token), in a DPoP challenge.
func errInvalidToken(reason, description string) *dpopError {
	return &dpopError{status: 401, code: "invalid_token", description: description, reason: reason}
}

// errBearer refuses a credential sent with the Bearer scheme; the error goes in a Bearer challenge.
func errBearer(reason, description string) *dpopError {
	return &dpopError{status: 401, code: "invalid_token", description: description, reason: reason, bearer: true}
}

// errUseNonce asks the client to retry with the nonce sent in DPoP-Nonce (RFC 9449 section 9).
func errUseNonce(reason string) *dpopError {
	return &dpopError{status: 401, code: "use_dpop_nonce", description: "resource server requires nonce in DPoP proof", reason: reason}
}

// errInvalidRequest refuses a request that carries more than one Authorization credential (400).
func errInvalidRequest(reason string) *dpopError {
	return &dpopError{status: 400, code: "invalid_request", description: "multiple methods used to include access token", reason: reason}
}

// errReplayUnavailable refuses a valid proof that could not be recorded, because the
// replay cache is full or the shared store is unreachable. Accepting it unrecorded
// would let it be replayed, so the request fails closed.
func errReplayUnavailable(reason string) *dpopError {
	return &dpopError{status: 503, code: "temporarily_unavailable", description: "DPoP replay protection is unavailable; retry later", reason: reason}
}

// reject answers with a DPoP challenge and records the failed attempt on the
// AuthContext chain, as the other authentication policies do. When nonces are in
// use, every challenge carries a fresh nonce so the client can retry at once.
func (p *DPoPPolicy) reject(shared *policy.SharedContext, e *dpopError) policy.RequestHeaderAction {
	slog.Debug("dpop: rejecting request",
		slog.String("error", e.code),
		slog.String("reason", e.reason),
		slog.String("api", shared.APIName),
	)

	shared.AuthContext = &policy.AuthContext{
		Authenticated: false,
		AuthType:      AuthType,
		Previous:      shared.AuthContext,
	}

	headers := map[string]string{"content-type": "application/json"}
	switch e.status {
	case 503:
		headers["Retry-After"] = "1"
	case 400:
		headers[wwwAuthenticateHeader] = p.challenge(e)
	default:
		headers[wwwAuthenticateHeader] = p.challenge(e)
		if p.cfg.requireNonce {
			headers[dpopNonceHeader] = p.nonces.issue(p.now())
			headers["Cache-Control"] = "no-store"
		}
	}

	// The body repeats the challenge as an OAuth 2.0 error object (RFC 6749 section
	// 5.2), so a client or a developer reading the response sees what failed.
	body, _ := json.Marshal(map[string]string{"error": e.code, "error_description": e.description})
	return policy.ImmediateResponse{
		StatusCode: e.status,
		Headers:    headers,
		Body:       body,
	}
}

// challenge builds the WWW-Authenticate value of RFC 9449 section 7.1. An error
// about a bearer credential goes in a Bearer challenge (section 7.2), followed by
// a DPoP challenge that still names the accepted algorithms.
func (p *DPoPPolicy) challenge(e *dpopError) string {
	if e.bearer {
		return fmt.Sprintf(`%s error=%q, error_description=%q, %s algs=%q`, bearerScheme, e.code, e.description, dpopScheme, p.cfg.algsChallenge)
	}
	return fmt.Sprintf(`%s error=%q, error_description=%q, algs=%q`, dpopScheme, e.code, e.description, p.cfg.algsChallenge)
}

// parseConfig reads the user and system parameters, falling back to the schema
// defaults for any that are absent.
func parseConfig(params map[string]interface{}) (config, error) {
	cfg := config{}
	var err error

	if cfg.mode, err = stringParam(params, "mode", defaultMode); err != nil {
		return cfg, err
	}
	if cfg.mode != modeRequired && cfg.mode != modeOptional {
		return cfg, fmt.Errorf("mode must be %q or %q, got %q", modeRequired, modeOptional, cfg.mode)
	}

	algs, err := stringListParam(params, "allowedAlgorithms", defaultAlgorithms)
	if err != nil {
		return cfg, err
	}
	if len(algs) == 0 {
		return cfg, fmt.Errorf("allowedAlgorithms must list at least one algorithm")
	}
	cfg.algSet = make(map[string]bool, len(algs))
	for _, alg := range algs {
		if !isSupportedAlgorithm(alg) {
			return cfg, fmt.Errorf("allowedAlgorithms: unsupported algorithm %q (supported: %s)", alg, strings.Join(supportedAlgorithms, ", "))
		}
		if !cfg.algSet[alg] {
			cfg.algSet[alg] = true
			cfg.algorithms = append(cfg.algorithms, alg)
		}
	}
	cfg.algsChallenge = strings.Join(cfg.algorithms, " ")

	tokenTypes, err := stringListParam(params, "accessTokenAuthTypes", defaultAccessTokenAuthTypes)
	if err != nil {
		return cfg, err
	}
	cfg.tokenAuthTypes = make(map[string]bool, len(tokenTypes))
	for _, t := range tokenTypes {
		if t = strings.TrimSpace(t); t == "" {
			return cfg, fmt.Errorf("accessTokenAuthTypes must not contain an empty type")
		}
		cfg.tokenAuthTypes[t] = true
	}
	if len(cfg.tokenAuthTypes) == 0 {
		return cfg, fmt.Errorf("accessTokenAuthTypes must list at least one AuthContext type")
	}

	if cfg.proofMaxAge, err = durationParam(params, "proofMaxAge", defaultProofMaxAge); err != nil {
		return cfg, err
	}
	if cfg.clockSkew, err = durationParam(params, "clockSkew", defaultClockSkew); err != nil {
		return cfg, err
	}
	if cfg.nonceLifetime, err = durationParam(params, "nonceLifetime", defaultNonceLifetime); err != nil {
		return cfg, err
	}
	if cfg.requireNonce, err = boolParam(params, "requireNonce", false); err != nil {
		return cfg, err
	}
	if cfg.forwardProof, err = boolParam(params, "forwardProof", false); err != nil {
		return cfg, err
	}

	origins, err := stringListParam(params, "htuOrigins", nil)
	if err != nil {
		return cfg, err
	}
	for _, raw := range origins {
		origin, err := parseConfiguredOrigin(raw)
		if err != nil {
			return cfg, fmt.Errorf("htuOrigins: %w", err)
		}
		cfg.htuOrigins = append(cfg.htuOrigins, origin)
	}
	return cfg, nil
}

// isSupportedAlgorithm reports whether alg is one of the asymmetric algorithms the policy can verify.
func isSupportedAlgorithm(alg string) bool {
	for _, a := range supportedAlgorithms {
		if a == alg {
			return true
		}
	}
	return false
}

// parseConfiguredOrigin accepts an absolute http(s) URL with no path beyond "/",
// query, fragment or user info, and returns its normalized origin.
func parseConfiguredOrigin(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", fmt.Errorf("%q is not a URL: %w", raw, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", fmt.Errorf("%q must use http or https", raw)
	}
	if u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return "", fmt.Errorf("%q must be an origin of the form scheme://host[:port]", raw)
	}
	return normalizeOrigin(u.Scheme, u.Host)
}

// stringParam reads a string parameter, returning def when it is absent and an error when it has another type.
func stringParam(params map[string]interface{}, key, def string) (string, error) {
	v, ok := params[key]
	if !ok || v == nil {
		return def, nil
	}
	s, ok := v.(string)
	if !ok {
		return "", fmt.Errorf("%s must be a string", key)
	}
	return s, nil
}

// boolParam reads a boolean parameter, returning def when it is absent.
func boolParam(params map[string]interface{}, key string, def bool) (bool, error) {
	v, ok := params[key]
	if !ok || v == nil {
		return def, nil
	}
	b, ok := v.(bool)
	if !ok {
		return false, fmt.Errorf("%s must be a boolean", key)
	}
	return b, nil
}

// intParam reads an integer parameter, which arrives as a JSON number (float64), returning def when it is absent.
func intParam(params map[string]interface{}, key string, def int) (int, error) {
	v, ok := params[key]
	if !ok || v == nil {
		return def, nil
	}
	switch n := v.(type) {
	case int:
		return n, nil
	case int64:
		return int(n), nil
	case float64:
		if n != float64(int(n)) {
			return 0, fmt.Errorf("%s must be an integer", key)
		}
		return int(n), nil
	default:
		return 0, fmt.Errorf("%s must be an integer", key)
	}
}

// durationParam reads a positive Go duration string (e.g. "60s"), returning def when it is absent or empty.
func durationParam(params map[string]interface{}, key string, def time.Duration) (time.Duration, error) {
	s, err := stringParam(params, key, "")
	if err != nil {
		return 0, err
	}
	if s == "" {
		return def, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", key, err)
	}
	if d <= 0 {
		return 0, fmt.Errorf("%s must be positive", key)
	}
	return d, nil
}

// stringListParam reads a list of strings, returning def when it is absent.
func stringListParam(params map[string]interface{}, key string, def []string) ([]string, error) {
	v, ok := params[key]
	if !ok || v == nil {
		return def, nil
	}
	switch list := v.(type) {
	case []string:
		return list, nil
	case []interface{}:
		out := make([]string, 0, len(list))
		for _, item := range list {
			s, ok := item.(string)
			if !ok {
				return nil, fmt.Errorf("%s must be a list of strings", key)
			}
			out = append(out, s)
		}
		return out, nil
	default:
		return nil, fmt.Errorf("%s must be a list of strings", key)
	}
}
