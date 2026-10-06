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

// Package oauthtokenexchange implements RFC 8693 (Token Exchange) and RFC 7523
// (JWT Bearer) so a gateway can swap the caller's own credential for a
// backend-specific token minted by an external OAuth2 authorization server,
// before the request is forwarded upstream. Unlike backend-jwt (which mints a
// gateway-signed assertion), the token attached here is issued by the
// backend's own authorization server, so it carries whatever trust that
// server places in the exchange — not the gateway's own signing key.
//
// The exchange is attempted twice. OnRequestHeaders makes an optimistic,
// best-effort attempt in the request-header phase, before the kernel has
// buffered the request body or run any body-phase policy attached earlier in
// the chain (e.g. mcp-auth, which authenticates POST /mcp traffic in its own
// OnRequestBody once it can parse the JSON-RPC method). A failure there —
// subject token not yet present, or the exchange call itself failing — is
// never fatal: it is recorded in SharedContext.Metadata and the request
// proceeds, so an earlier-in-chain, body-phase auth policy still gets to run
// and, if it forwards the credential under a different header, supply what
// the header phase could not find. OnRequestBody then makes the sole
// authoritative attempt: if the header phase already succeeded it does
// nothing further, and otherwise it repeats the extraction-and-exchange
// against the now-fully-formed live request state and, only at that point,
// fails the request if it still cannot complete the exchange.
//
// This policy still implements policy.RequestPolicy (OnRequestBody), so the
// kernel still buffers the complete request body for every route it is
// attached to regardless of whether the header-phase attempt succeeds — the
// body-phase retry has to be available as the final word before the request
// can be allowed to fail.
package oauthtokenexchange

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
	"github.com/wso2/api-platform/sdk/core/utils"
	"github.com/wso2/api-platform/sdk/core/utils/cache"
)

const (
	defaultHeader           = "Authorization"
	defaultHeaderPrefix     = "Bearer "
	defaultGrantType        = "TokenExchange"
	defaultClientAuthMethod = "ClientSecretBasic"
	defaultSubjectTokenType = "AccessToken"
	defaultRequestTimeout   = 5 * time.Second
	defaultMaxResponseBytes = 64 * 1024 // token responses are small JSON documents
	defaultExpiresIn        = 5 * time.Minute
	minCacheTTL             = 30 * time.Second
	defaultCacheMaxSize     = 100_000

	grantTypeTokenExchangeURN = "urn:ietf:params:oauth:grant-type:token-exchange"
	grantTypeJwtBearerURN     = "urn:ietf:params:oauth:grant-type:jwt-bearer"
)

// tokenTypeURNs maps the friendly names exposed in policy-definition.yaml to the
// RFC 8693 token-type URNs actually sent on the wire.
var tokenTypeURNs = map[string]string{
	"AccessToken": "urn:ietf:params:oauth:token-type:access_token",
	"Jwt":         "urn:ietf:params:oauth:token-type:jwt",
	"IdToken":     "urn:ietf:params:oauth:token-type:id_token",
}

// cachedToken is an exchanged token paired with the instant after which it
// must no longer be served — same pattern as backend-jwt's cachedToken.
type cachedToken struct {
	token     string
	expiresAt time.Time
}

// SharedContext.Metadata key recording what OnRequestHeaders decided, so
// OnRequestBody — which always runs, since this policy implements
// policy.RequestPolicy — knows whether it has anything left to do.
//
// Only a missing subject token is ever recorded here as headerPhaseOutcomeDeferred.
// Every other failure (invalid config, or a subject token that WAS present
// but failed the exchange call) is final and non-retryable — the same
// inputs would fail identically a second time — so OnRequestHeaders rejects
// those immediately with its own ImmediateResponse. That short-circuits the
// whole chain: the kernel never buffers the body or runs OnRequestBody (or
// any later policy) for that request at all.
const (
	metadataKeyHeaderPhaseOutcome = "oauthTokenExchange.headerPhaseOutcome"

	// headerPhaseOutcomeSucceeded means the header phase already resolved and
	// attached the exchanged token upstream; OnRequestBody is a no-op.
	headerPhaseOutcomeSucceeded = "succeeded"

	// headerPhaseOutcomeDeferred means the subject token was not yet present
	// on the request at the header phase. This is the only outcome worth
	// retrying: the credential may simply not have arrived yet (e.g. a
	// body-phase auth policy earlier in the chain hasn't forwarded it under
	// this header yet), so OnRequestBody repeats the full attempt once that
	// policy has had its chance to run.
	headerPhaseOutcomeDeferred = "deferred"
)

func markHeaderPhaseOutcome(shared *policy.SharedContext, outcome string) {
	if shared == nil {
		return
	}
	if shared.Metadata == nil {
		shared.Metadata = map[string]interface{}{}
	}
	shared.Metadata[metadataKeyHeaderPhaseOutcome] = outcome
}

func headerPhaseSucceeded(shared *policy.SharedContext) bool {
	if shared == nil || shared.Metadata == nil {
		return false
	}
	outcome, _ := shared.Metadata[metadataKeyHeaderPhaseOutcome].(string)
	return outcome == headerPhaseOutcomeSucceeded
}

// OAuthTokenExchangePolicy exchanges the caller's inbound credential for a
// backend-specific token at an external OAuth2 authorization server and
// attaches it to the upstream request. It never forwards the original
// subject token upstream, and it never forwards it to the client — on any
// exchange failure the request is rejected rather than falling back to the
// original credential.
type OAuthTokenExchangePolicy struct {
	// cacheMu guards the tokenCache pointer and currentMaxSize, following the
	// same swap-on-resize pattern as backend-jwt's token cache: the SDK cache
	// fixes its size at construction, so a changed cacheMaxSize is applied by
	// building a new cache and swapping the pointer under the write lock.
	cacheMu        sync.RWMutex
	tokenCache     *cache.InMemoryCache[cachedToken]
	currentMaxSize int
}

func newTokenCache(maxSize int) *cache.InMemoryCache[cachedToken] {
	return cache.NewInMemoryCache[cachedToken]("oauth-token-exchange-tokens", maxSize, 0, cache.LRUEvictionPolicy, slog.Default())
}

var ins = &OAuthTokenExchangePolicy{
	tokenCache:     newTokenCache(defaultCacheMaxSize),
	currentMaxSize: defaultCacheMaxSize,
}

// GetPolicy is the v1alpha2 factory entry point. Called on each API deployment;
// applies the global cacheMaxSize system parameter to the shared token cache.
func GetPolicy(_ policy.PolicyMetadata, params map[string]interface{}) (policy.Policy, error) {
	maxSize := getInt(params, "cacheMaxSize", defaultCacheMaxSize)
	if maxSize <= 0 {
		maxSize = defaultCacheMaxSize
	}
	ins.ensureTokenCache(maxSize)
	return ins, nil
}

func (p *OAuthTokenExchangePolicy) ensureTokenCache(maxSize int) {
	p.cacheMu.RLock()
	if p.tokenCache != nil && p.currentMaxSize == maxSize {
		p.cacheMu.RUnlock()
		return
	}
	p.cacheMu.RUnlock()

	p.cacheMu.Lock()
	defer p.cacheMu.Unlock()
	if p.tokenCache != nil && p.currentMaxSize == maxSize {
		return
	}
	p.tokenCache = newTokenCache(maxSize)
	p.currentMaxSize = maxSize
}

func (p *OAuthTokenExchangePolicy) currentTokenCache() *cache.InMemoryCache[cachedToken] {
	p.cacheMu.RLock()
	defer p.cacheMu.RUnlock()
	return p.tokenCache
}

func (p *OAuthTokenExchangePolicy) Mode() policy.ProcessingMode {
	return policy.ProcessingMode{
		RequestHeaderMode:  policy.HeaderModeProcess,
		RequestBodyMode:    policy.BodyModeBuffer,
		ResponseHeaderMode: policy.HeaderModeSkip,
		ResponseBodyMode:   policy.BodyModeSkip,
	}
}

// Validate performs eager config checks (same convention as backend-jwt's own
// Validate). It is not invoked by the kernel today, so OnRequestBody always
// re-validates via parseConfig on every request rather than assuming this ran.
func (p *OAuthTokenExchangePolicy) Validate(params map[string]interface{}) error {
	_, err := parseConfig(params)
	return err
}

// subjectTokenSource describes where to read the caller's credential from.
type subjectTokenSource struct {
	kind   string // "header", "cookie", or "queryParameter"
	name   string
	prefix string // only meaningful for kind == "header" (e.g. "Bearer ")
}

// exchangeConfig is the fully parsed, validated policy configuration for one
// call to OnRequestBody.
type exchangeConfig struct {
	tokenEndpoint              *url.URL
	grantType                  string
	clientID                   string
	clientSecret               string
	clientAuthMethod           string
	subjectSource              subjectTokenSource
	subjectTokenType           string // URN
	requestedTokenType         string // URN; "" when unset (TokenExchange only)
	audiences                  []string
	scopes                     []string
	resources                  []string
	header                     string
	headerPrefix               string
	tokenCaching               bool
	requestTimeout             time.Duration
	maxResponseBytes           int64
	allowInsecureTokenEndpoint bool
}

// parseConfig validates params and is the single source of truth for both
// Validate (eager, deploy-time) and OnRequestBody (per-request, since
// nothing guarantees Validate ran first).
func parseConfig(params map[string]interface{}) (*exchangeConfig, error) {
	cfg := &exchangeConfig{
		grantType:                  getString(params, "grantType", defaultGrantType),
		clientID:                   getString(params, "clientId", ""),
		clientSecret:               getString(params, "clientSecret", ""),
		clientAuthMethod:           getString(params, "clientAuthMethod", defaultClientAuthMethod),
		header:                     getString(params, "header", defaultHeader),
		headerPrefix:               getStringOrDefault(params, "headerPrefix", defaultHeaderPrefix),
		tokenCaching:               getBool(params, "tokenCaching", true),
		audiences:                  getStringSlice(params, "audiences"),
		scopes:                     getStringSlice(params, "scopes"),
		resources:                  getStringSlice(params, "resources"),
		requestTimeout:             parseDurationParam(params, "requestTimeout", defaultRequestTimeout),
		maxResponseBytes:           int64(getInt(params, "maxResponseBytes", defaultMaxResponseBytes)),
		allowInsecureTokenEndpoint: getBool(params, "allowInsecureTokenEndpoint", false),
	}

	// A non-empty prefix needs a trailing separator before the token, or the
	// two run together (e.g. "Bearer"+token -> "Bearereyj..."). An empty
	// prefix means "no prefix" and is left as-is.
	if cfg.headerPrefix != "" && !strings.HasSuffix(cfg.headerPrefix, " ") {
		cfg.headerPrefix += " "
	}

	if cfg.grantType != "TokenExchange" && cfg.grantType != "JwtBearer" {
		return nil, fmt.Errorf("unsupported grantType %q; supported: TokenExchange, JwtBearer", cfg.grantType)
	}
	if cfg.clientAuthMethod != "ClientSecretBasic" && cfg.clientAuthMethod != "ClientSecretPost" {
		return nil, fmt.Errorf("unsupported clientAuthMethod %q; supported: ClientSecretBasic, ClientSecretPost", cfg.clientAuthMethod)
	}
	if cfg.clientID == "" {
		return nil, fmt.Errorf("clientId is required")
	}
	if cfg.clientSecret == "" {
		return nil, fmt.Errorf("clientSecret is required")
	}
	if cfg.requestTimeout <= 0 {
		cfg.requestTimeout = defaultRequestTimeout
	}
	if cfg.maxResponseBytes <= 0 {
		cfg.maxResponseBytes = defaultMaxResponseBytes
	}

	rawEndpoint := getString(params, "tokenEndpoint", "")
	if rawEndpoint == "" {
		return nil, fmt.Errorf("tokenEndpoint is required")
	}
	endpoint, err := url.Parse(rawEndpoint)
	if err != nil || endpoint.Host == "" {
		return nil, fmt.Errorf("tokenEndpoint must be an absolute URL")
	}
	switch endpoint.Scheme {
	case "https":
		// always allowed
	case "http":
		// Off-by-default admin opt-in per ssrf-prevention.md directive 5 — never
		// widen the scheme allowlist implicitly.
		if !cfg.allowInsecureTokenEndpoint {
			return nil, fmt.Errorf("tokenEndpoint must use https unless allowInsecureTokenEndpoint is enabled")
		}
	default:
		return nil, fmt.Errorf("tokenEndpoint scheme must be http or https")
	}
	cfg.tokenEndpoint = endpoint

	sourceRaw := objectParam(params, "subjectTokenSource")
	cfg.subjectSource = subjectTokenSource{
		kind:   getStringFromMap(sourceRaw, "type", "header"),
		name:   getStringFromMap(sourceRaw, "name", defaultHeader),
		prefix: getStringFromMapOrDefault(sourceRaw, "prefix", defaultHeaderPrefix),
	}
	switch cfg.subjectSource.kind {
	case "header", "cookie", "queryParameter":
	default:
		return nil, fmt.Errorf("unsupported subjectTokenSource.type %q; supported: header, cookie, queryParameter", cfg.subjectSource.kind)
	}

	subjectFriendly := getString(params, "subjectTokenType", defaultSubjectTokenType)
	subjectURN, ok := tokenTypeURNs[subjectFriendly]
	if !ok {
		return nil, fmt.Errorf("unsupported subjectTokenType %q; supported: AccessToken, Jwt, IdToken", subjectFriendly)
	}
	cfg.subjectTokenType = subjectURN

	if requestedFriendly := getString(params, "requestedTokenType", ""); requestedFriendly != "" {
		requestedURN, ok := tokenTypeURNs[requestedFriendly]
		if !ok {
			return nil, fmt.Errorf("unsupported requestedTokenType %q; supported: AccessToken, Jwt, IdToken", requestedFriendly)
		}
		cfg.requestedTokenType = requestedURN
	}

	return cfg, nil
}

// OnRequestHeaders makes an optimistic attempt at the exchange during the
// header phase, before the kernel has buffered the request body or run any
// body-phase policy attached earlier in the chain.
//
// Only a missing subject token defers to OnRequestBody, recorded in
// SharedContext.Metadata — that is the one case where waiting can actually
// change the outcome (a body-phase auth policy earlier in the chain, e.g.
// mcp-auth, may still forward the credential once it runs). An invalid
// config or a failed call to the token endpoint is rejected immediately with
// this phase's own ImmediateResponse instead: neither would come out
// differently on a second attempt with the same inputs, and returning
// ImmediateResponse here short-circuits the whole chain — the kernel never
// buffers the body or runs OnRequestBody for this request at all.
func (p *OAuthTokenExchangePolicy) OnRequestHeaders(ctx context.Context, reqCtx *policy.RequestHeaderContext, params map[string]interface{}) policy.RequestHeaderAction {
	cfg, err := parseConfig(params)
	if err != nil {
		slog.Error("OAuth token exchange: invalid policy configuration", "phase", "header", "error", err)
		return internalError()
	}

	apiName := ""
	if reqCtx.SharedContext != nil {
		apiName = reqCtx.SharedContext.APIName
	}

	token, subjectToken, subjectMissing, exchangeErr := p.resolveSubjectAndToken(ctx, "header", apiName, cfg, reqCtx.Headers, reqCtx.Path)
	if subjectMissing {
		// Expected whenever the subject token is only supplied by a
		// body-phase policy earlier in the chain (e.g. mcp-auth) that has
		// not run yet — routine deferral, not a failure of this phase.
		slog.Debug("OAuth token exchange: subject token not yet available at header phase, deferring to body phase",
			"api", apiName,
			"source", cfg.subjectSource.kind,
			"name", cfg.subjectSource.name,
			"liveHeaderNames", headerNamesForLog(reqCtx.Headers),
		)
		markHeaderPhaseOutcome(reqCtx.SharedContext, headerPhaseOutcomeDeferred)
		return policy.UpstreamRequestHeaderModifications{}
	}
	if exchangeErr != nil {
		// The credential WAS present; only the call to the token endpoint
		// failed. Repeating an identical call in the body phase would not
		// produce a different result (e.g. bad client credentials fail the
		// same way every time), so this is rejected here and now rather than
		// deferred — the kernel short-circuits the rest of the chain.
		trackingID := newTrackingID()
		slog.Error("OAuth token exchange: exchange failed",
			"phase", "header",
			"trackingId", trackingID,
			"tokenEndpointHost", cfg.tokenEndpoint.Host,
			"grantType", cfg.grantType,
			"subjectToken", maskToken(subjectToken),
			"error", exchangeErr,
		)
		return badGatewayResponse(trackingID)
	}

	markHeaderPhaseOutcome(reqCtx.SharedContext, headerPhaseOutcomeSucceeded)
	return policy.UpstreamRequestHeaderModifications{
		HeadersToSet: map[string]string{cfg.header: cfg.headerPrefix + token},
	}
}

// OnRequestBody is the sole remaining point from which a request can be
// rejected once the header phase has deferred it — every other failure mode
// (invalid config, or an exchange call that actually failed) was already
// rejected directly in OnRequestHeaders and never reaches here at all. If
// the header phase already succeeded, there is nothing left to do — the
// upstream header was already set there. Otherwise this makes the full,
// authoritative attempt against the now-fully-formed live request state,
// and on failure rejects the request: the original subject token is never
// forwarded upstream, and no internal detail (upstream error body, resolved
// host, stack trace) reaches the client.
func (p *OAuthTokenExchangePolicy) OnRequestBody(ctx context.Context, reqCtx *policy.RequestContext, params map[string]interface{}) policy.RequestAction {
	if headerPhaseSucceeded(reqCtx.SharedContext) {
		return policy.UpstreamRequestModifications{}
	}

	cfg, err := parseConfig(params)
	if err != nil {
		slog.Error("OAuth token exchange: invalid policy configuration", "phase", "body", "error", err)
		return internalError()
	}

	token, subjectToken, subjectMissing, exchangeErr := p.resolveSubjectAndToken(ctx, "body", reqCtx.APIName, cfg, reqCtx.Headers, reqCtx.Path)
	if subjectMissing {
		slog.Warn("OAuth token exchange: subject token missing or empty",
			"api", reqCtx.APIName,
			"source", cfg.subjectSource.kind,
			"name", cfg.subjectSource.name,
			// Names only, never values — lets an operator see whether the
			// configured header truly never arrived, or arrived under a
			// different name/case than subjectTokenSource.name expects
			// (e.g. an earlier auth policy forwarding it under a header
			// this config doesn't match, or a policy chain/phase ordering
			// issue where the forwarding policy hasn't run yet).
			"liveHeaderNames", headerNamesForLog(reqCtx.Headers),
		)
		return unauthorized()
	}
	if exchangeErr != nil {
		trackingID := newTrackingID()
		slog.Error("OAuth token exchange: exchange failed",
			"phase", "body",
			"trackingId", trackingID,
			"tokenEndpointHost", cfg.tokenEndpoint.Host,
			"grantType", cfg.grantType,
			"subjectToken", maskToken(subjectToken),
			"error", exchangeErr,
		)
		return badGatewayResponse(trackingID)
	}

	slog.Debug("OAuth token exchange: exchange succeeded", "phase", "body", "api", reqCtx.APIName, "grantType", cfg.grantType)
	return upstreamAction(cfg, token)
}

// badGatewayResponse is the sterile, tracking-ID-bearing 502 payload used by
// both phases when the exchange call itself fails. ImmediateResponse
// implements both RequestHeaderAction and RequestAction, so this one helper
// serves OnRequestHeaders and OnRequestBody alike.
func badGatewayResponse(trackingID string) policy.ImmediateResponse {
	return policy.ImmediateResponse{
		StatusCode: 502,
		Headers:    map[string]string{"content-type": "application/json"},
		Body:       fmt.Appendf(nil, `{"error":"bad_gateway","message":"Unable to obtain a backend credential.","tracking_id":%q}`, trackingID),
	}
}

// resolveSubjectAndToken extracts the subject token from the live request
// state and resolves the backend token to attach upstream — from cache when
// possible, otherwise via a fresh call to the token endpoint. It performs no
// rejection and builds no response: phase is used only to tag log lines, so
// an operator can tell which phase actually performed (or attempted) the
// exchange; the two callers above decide how to act on the result.
//
// subjectMissing is true only when no credential could be extracted from the
// request at all. exchangeErr is non-nil only when a credential was found
// but the call to the token endpoint did not succeed. Exactly one of
// (subjectMissing, exchangeErr != nil, token != "") holds.
func (p *OAuthTokenExchangePolicy) resolveSubjectAndToken(ctx context.Context, phase, apiName string, cfg *exchangeConfig, headers *policy.Headers, path string) (token, subjectToken string, subjectMissing bool, exchangeErr error) {
	subjectToken, ok := extractSubjectToken(headers, path, cfg.subjectSource)
	if !ok {
		return "", "", true, nil
	}
	slog.Debug("OAuth token exchange: subject token extracted",
		"phase", phase,
		"api", apiName,
		"source", cfg.subjectSource.kind,
		"name", cfg.subjectSource.name,
	)

	cacheKey := buildCacheKey(apiName, cfg, subjectToken)
	if cfg.tokenCaching {
		if tok, ok := p.getCachedToken(ctx, cacheKey); ok {
			slog.Debug("OAuth token exchange: cache hit", "phase", phase, "api", apiName, "grantType", cfg.grantType)
			return tok, subjectToken, false, nil
		}
	}

	slog.Debug("OAuth token exchange: calling token endpoint",
		"phase", phase,
		"api", apiName,
		"tokenEndpointHost", cfg.tokenEndpoint.Host,
		"grantType", cfg.grantType,
	)
	tok, expiresIn, err := performTokenExchange(ctx, cfg, subjectToken)
	if err != nil {
		return "", subjectToken, false, err
	}

	if cfg.tokenCaching {
		p.putCachedToken(ctx, cacheKey, tok, expiresIn)
	}
	return tok, subjectToken, false, nil
}

func upstreamAction(cfg *exchangeConfig, token string) policy.RequestAction {
	return policy.UpstreamRequestModifications{
		HeadersToSet: map[string]string{
			cfg.header: cfg.headerPrefix + token,
		},
	}
}

// extractSubjectToken reads the caller's credential from the live,
// kernel-mutated request state (headers / path) rather than the
// pre-mutation downstream snapshot, so that a header/query rewrite made by
// an earlier policy in the same chain (e.g. mcp-auth forwarding a validated
// token under an operator-configured header such as
// "X-Forwarded-Authorization") is what gets exchanged. This is a deliberate
// departure from policy-data-model.md §3.3/§9's general guidance to prefer
// the snapshot for authentication-relevant decisions: it trusts the chain's
// own earlier policies to have already produced the correct value in the
// live headers, and it is required here because a forwarded header exists
// ONLY in the live state — the downstream snapshot is captured before any
// policy runs and never contains it.
func extractSubjectToken(headers *policy.Headers, path string, src subjectTokenSource) (string, bool) {
	switch src.kind {
	case "header":
		vals := getHeaderCaseInsensitive(headers, src.name)
		if len(vals) == 0 {
			return "", false
		}
		v := vals[0]
		// Masked per authentication_authorization.md GO-AUTH-003 — this header
		// carries a bearer credential, so only a short prefix/suffix and the
		// length are logged, never the raw value. That's enough to tell
		// whether a "Bearer " prefix is actually present, or the value is
		// something unexpected (empty, truncated, wrong claim altogether).
		slog.Debug("OAuth token exchange: header value found",
			"name", src.name,
			"valuePreview", maskToken(v),
			"valueLength", len(v),
		)
		if src.prefix != "" {
			if !strings.HasPrefix(v, src.prefix) {
				// The header IS present — this is a prefix mismatch, not a
				// visibility/ordering gap. Logging the configured prefix (a
				// static config string, never the credential itself) makes
				// that distinction visible without exposing v.
				slog.Warn("OAuth token exchange: header present but does not start with the configured prefix",
					"name", src.name,
					"configuredPrefix", src.prefix,
					"valuePreview", maskToken(v),
				)
				return "", false
			}
			v = strings.TrimPrefix(v, src.prefix)
		}
		v = strings.TrimSpace(v)
		return v, v != ""

	case "cookie":
		cookieVals := getHeaderCaseInsensitive(headers, "cookie")
		if len(cookieVals) == 0 {
			return "", false
		}
		header := http.Header{}
		for _, v := range cookieVals {
			header.Add("Cookie", v)
		}
		c, err := (&http.Request{Header: header}).Cookie(src.name)
		if err != nil || c.Value == "" {
			return "", false
		}
		return c.Value, true

	case "queryParameter":
		v := queryFromPath(path).Get(src.name)
		return v, v != ""

	default:
		return "", false
	}
}

// getHeaderCaseInsensitive reads a header by name, falling back to a manual
// case-insensitive scan when the fast path finds nothing.
//
// Headers.Get() always lowercases the name it is asked for, but a header set
// by an earlier body-phase policy (e.g. an auth policy forwarding a token
// under an operator-configured name such as "X-Forwarded-Authorization") can
// land in the live header map under its original, non-lowercased key if the
// engine's body-phase header-modification merge does not itself normalize
// case the way the request-header-phase merge does. In that situation the
// header is present but Get() cannot find it by its lowercased name alone.
// This fallback makes extraction resilient to that gap regardless of its
// cause, without assuming which body-phase policy ran before this one.
func getHeaderCaseInsensitive(headers *policy.Headers, name string) []string {
	if vals := headers.Get(name); len(vals) > 0 {
		return vals
	}
	var found []string
	headers.Iterate(func(hName string, values []string) {
		if found == nil && strings.EqualFold(hName, name) {
			found = values
		}
	})
	return found
}

// headerNamesForLog lists the header names present on the live request, for
// diagnostic logging only — never the values, which may carry credentials.
// This is what lets an operator tell, from logs alone, whether a configured
// subjectTokenSource.name genuinely never arrived versus arrived under a
// name/case the config doesn't match.
func headerNamesForLog(headers *policy.Headers) []string {
	var names []string
	headers.Iterate(func(name string, _ []string) {
		names = append(names, name)
	})
	sort.Strings(names)
	return names
}

func queryFromPath(path string) url.Values {
	i := strings.IndexByte(path, '?')
	if i == -1 {
		return url.Values{}
	}
	vals, err := url.ParseQuery(path[i+1:])
	if err != nil {
		return url.Values{}
	}
	return vals
}

// performTokenExchange calls the token endpoint via the process-wide,
// SSRF-guarded HTTP client (sdk/core/utils.SharedHTTPClient) — never a
// hand-rolled, unguarded client — per ssrf-prevention.md directives 1-2. If
// the engine hasn't installed a shared client yet, it falls back to
// fallbackHTTPClient, which applies the same dial-time SSRF guard rather
// than dropping to http.DefaultClient (see that function's doc comment).
// The response is read through a bounded reader before decoding, per
// directive 3.
func performTokenExchange(ctx context.Context, cfg *exchangeConfig, subjectToken string) (string, time.Duration, error) {
	client := utils.SharedHTTPClient()
	if client == nil {
		slog.Warn("OAuth token exchange: shared HTTP client not configured, using guarded fallback client")
		client = fallbackHTTPClient()
	}

	form := url.Values{}
	switch cfg.grantType {
	case "TokenExchange":
		form.Set("grant_type", grantTypeTokenExchangeURN)
		form.Set("subject_token", subjectToken)
		form.Set("subject_token_type", cfg.subjectTokenType)
		if cfg.requestedTokenType != "" {
			form.Set("requested_token_type", cfg.requestedTokenType)
		}
	case "JwtBearer":
		form.Set("grant_type", grantTypeJwtBearerURN)
		form.Set("assertion", subjectToken)
	}
	for _, a := range cfg.audiences {
		form.Add("audience", a)
	}
	for _, r := range cfg.resources {
		form.Add("resource", r)
	}
	if len(cfg.scopes) > 0 {
		form.Set("scope", strings.Join(cfg.scopes, " "))
	}
	if cfg.clientAuthMethod == "ClientSecretPost" {
		form.Set("client_id", cfg.clientID)
		form.Set("client_secret", cfg.clientSecret)
	}

	callCtx, cancel := context.WithTimeout(ctx, cfg.requestTimeout)
	defer cancel()

	httpReq, err := http.NewRequestWithContext(callCtx, http.MethodPost, cfg.tokenEndpoint.String(), strings.NewReader(form.Encode()))
	if err != nil {
		return "", 0, fmt.Errorf("build token request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	httpReq.Header.Set("Accept", "application/json")
	if cfg.clientAuthMethod == "ClientSecretBasic" {
		httpReq.SetBasicAuth(cfg.clientID, cfg.clientSecret)
	}

	resp, err := client.Do(httpReq)
	if err != nil {
		return "", 0, fmt.Errorf("token endpoint request failed: %w", err)
	}
	defer resp.Body.Close()

	limited := io.LimitReader(resp.Body, cfg.maxResponseBytes+1)
	body, err := io.ReadAll(limited)
	if err != nil {
		return "", 0, fmt.Errorf("reading token response: %w", err)
	}
	if int64(len(body)) > cfg.maxResponseBytes {
		return "", 0, fmt.Errorf("token response exceeds maximum allowed size")
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", 0, fmt.Errorf("token endpoint returned status %d", resp.StatusCode)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return "", 0, fmt.Errorf("malformed token response: %w", err)
	}
	accessToken, _ := parsed["access_token"].(string)
	if accessToken == "" {
		return "", 0, fmt.Errorf("token response missing access_token")
	}

	expiresIn := defaultExpiresIn
	switch v := parsed["expires_in"].(type) {
	case float64:
		if v > 0 {
			expiresIn = time.Duration(v) * time.Second
		}
	case string:
		if secs, err := strconv.ParseInt(v, 10, 64); err == nil && secs > 0 {
			expiresIn = time.Duration(secs) * time.Second
		}
	}

	return accessToken, expiresIn, nil
}

// buildCacheKey returns a fixed-length SHA-256 digest covering every field
// that shapes the exchanged token, plus the subject token itself — mirrors
// backend-jwt's buildTokenCacheKey idiom. The raw subject token is folded
// into the hash, never stored verbatim as a cache key.
func buildCacheKey(apiName string, cfg *exchangeConfig, subjectToken string) string {
	var buf bytes.Buffer
	buf.WriteString(apiName)
	buf.WriteByte(0)
	buf.WriteString(cfg.tokenEndpoint.String())
	buf.WriteByte(0)
	buf.WriteString(cfg.clientID)
	buf.WriteByte(0)
	buf.WriteString(cfg.grantType)
	buf.WriteByte(0)
	buf.WriteString(strings.Join(sortedCopy(cfg.audiences), ","))
	buf.WriteByte(0)
	buf.WriteString(strings.Join(sortedCopy(cfg.scopes), ","))
	buf.WriteByte(0)
	buf.WriteString(strings.Join(sortedCopy(cfg.resources), ","))
	buf.WriteByte(0)
	buf.WriteString(subjectToken)

	sum := sha256.Sum256(buf.Bytes())
	return hex.EncodeToString(sum[:])
}

func sortedCopy(s []string) []string {
	out := append([]string(nil), s...)
	sort.Strings(out)
	return out
}

// getCachedToken returns a previously exchanged token if present and not yet
// expired. Because the SDK cache never expires entries on its own (ttl=0),
// expiry is enforced here against the stored expiresAt.
func (p *OAuthTokenExchangePolicy) getCachedToken(ctx context.Context, key string) (string, bool) {
	tc := p.currentTokenCache()
	if tc == nil {
		return "", false
	}
	cacheKey := cache.CacheKey{Key: key}
	v, ok := tc.Get(ctx, cacheKey)
	if !ok {
		return "", false
	}
	if !time.Now().Before(v.expiresAt) {
		_ = tc.Delete(ctx, cacheKey)
		return "", false
	}
	return v.token, true
}

// putCachedToken stores an exchanged token with a TTL of half its reported
// lifetime, floored at minCacheTTL only when that floor still fits strictly
// inside the token's real lifetime — the cache TTL must never reach or
// exceed expiresIn, or the cache could serve a token that has already expired.
func (p *OAuthTokenExchangePolicy) putCachedToken(ctx context.Context, key, token string, expiresIn time.Duration) {
	tc := p.currentTokenCache()
	if tc == nil {
		return
	}
	ttl := expiresIn / 2
	if ttl < minCacheTTL && minCacheTTL < expiresIn {
		ttl = minCacheTTL
	}
	if ttl <= 0 {
		return // lifetime too short to leave a safety margin — don't cache it
	}
	_ = tc.Set(ctx, cache.CacheKey{Key: key}, cachedToken{token: token, expiresAt: time.Now().Add(ttl)})
}

// newTrackingID returns a high-entropy, source-free correlation identifier —
// crypto/rand only, never a source-tagged string or a bare timestamp, per
// error-handling.md directive 3.
func newTrackingID() string {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "unavailable"
	}
	return hex.EncodeToString(buf)
}

// maskToken renders only a short prefix/suffix of a credential for log lines,
// per authentication_authorization.md GO-AUTH-003 — the raw subject token
// must never be logged in full.
func maskToken(token string) string {
	if len(token) <= 8 {
		return "[MASKED]"
	}
	return token[:4] + "..." + token[len(token)-4:]
}

func unauthorized() policy.ImmediateResponse {
	return policy.ImmediateResponse{
		StatusCode: 401,
		Headers:    map[string]string{"content-type": "application/json"},
		Body:       []byte(`{"error":"unauthorized","message":"Invalid or expired credentials."}`),
	}
}

func internalError() policy.ImmediateResponse {
	return policy.ImmediateResponse{
		StatusCode: 500,
		Headers:    map[string]string{"content-type": "application/json"},
		Body:       []byte(`{"error":"Internal Server Error"}`),
	}
}

func getString(params map[string]interface{}, key, defaultVal string) string {
	if v, ok := params[key]; ok {
		if s, ok := v.(string); ok && s != "" {
			return s
		}
	}
	return defaultVal
}

// getStringOrDefault is like getString but treats an explicit empty string as
// a meaningful override (used for headerPrefix, where "" means "no prefix").
func getStringOrDefault(params map[string]interface{}, key, defaultVal string) string {
	if v, ok := params[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return defaultVal
}

func getStringFromMap(m map[string]interface{}, key, defaultVal string) string {
	if m == nil {
		return defaultVal
	}
	if v, ok := m[key]; ok {
		if s, ok := v.(string); ok && s != "" {
			return s
		}
	}
	return defaultVal
}

func getStringFromMapOrDefault(m map[string]interface{}, key, defaultVal string) string {
	if m == nil {
		return defaultVal
	}
	if v, ok := m[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return defaultVal
}

func getBool(params map[string]interface{}, key string, defaultVal bool) bool {
	if v, ok := params[key]; ok {
		if b, ok := v.(bool); ok {
			return b
		}
	}
	return defaultVal
}

func getInt(params map[string]interface{}, key string, defaultVal int) int {
	if v, ok := params[key]; ok {
		switch n := v.(type) {
		case int:
			return n
		case int64:
			return int(n)
		case float64: // JSON numbers unmarshal as float64
			return int(n)
		}
	}
	return defaultVal
}

func getStringSlice(params map[string]interface{}, key string) []string {
	raw, ok := params[key]
	if !ok {
		return nil
	}
	arr, ok := raw.([]interface{})
	if !ok {
		return nil
	}
	out := make([]string, 0, len(arr))
	for _, e := range arr {
		if s, ok := e.(string); ok && s != "" {
			out = append(out, s)
		}
	}
	return out
}

func objectParam(params map[string]interface{}, key string) map[string]interface{} {
	if raw, ok := params[key]; ok {
		if m, ok := raw.(map[string]interface{}); ok {
			return m
		}
	}
	return nil
}

func parseDurationParam(params map[string]interface{}, key string, fallback time.Duration) time.Duration {
	s := getString(params, key, "")
	if s == "" {
		return fallback
	}
	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 {
		return fallback
	}
	return d
}
