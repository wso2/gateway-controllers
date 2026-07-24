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

package opaquetokenauth

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
	"github.com/wso2/api-platform/sdk/core/utils/cache"
)

const (
	// AuthType identifies this authentication mechanism in AuthContext.
	AuthType = "opaque"

	// cacheName labels the introspection cache in SDK cache statistics.
	cacheName = "opaque-token-introspection"

	// cacheMaxSize bounds the number of cached introspection results (LRU eviction).
	cacheMaxSize = 100000
)

// standardIntrospectionClaims lists RFC 7662 introspection response members that
// are surfaced as typed AuthContext fields or are status-only booleans, excluded
// from Properties. username and token_type are intentionally omitted so they flow
// into Properties — WSO2/Asgardeo always returns username, and jwt-auth does not
// exclude these members either.
var standardIntrospectionClaims = map[string]bool{
	"active": true, "scope": true, "scp": true, "client_id": true,
	"exp": true, "iat": true, "nbf": true,
	"sub": true, "aud": true, "iss": true, "jti": true,
}

// OpaqueTokenAuthPolicy validates opaque OAuth 2.0 access tokens via RFC 7662
// token introspection, caching active responses to reduce load on the
// authorization server.
type OpaqueTokenAuthPolicy struct {
	// cache stores introspection results keyed by sha256(providerName \x00 token).
	// The SDK cache is constructed with no TTL (entries are bounded by their own
	// expiresAt, which is min(configured TTL, token exp)) and an LRU size cap.
	cache cache.Cache[*cachedIntrospection]

	// provOnce ensures the provider list is parsed exactly once from config.toml,
	// which is loaded at startup and does not change at runtime.
	provOnce  sync.Once
	providers []*IntrospectionProvider
	provErr   error
}

// cachedIntrospection holds an active introspection result with its expiry.
type cachedIntrospection struct {
	result    *IntrospectionResult
	expiresAt time.Time // min(now+TTL, token exp)
}

// IntrospectionProvider describes an authorization server's introspection
// endpoint and how the gateway authenticates itself to it.
type IntrospectionProvider struct {
	Name          string           // Unique provider name (referenced by user `issuers`)
	Issuer        string           // Optional issuer value (also matchable via `issuers`)
	TokenPattern  string           // Optional regex; when set, only tokens matching it are sent to this provider
	URI           string           // RFC 7662 introspection endpoint URL
	ClientID      string           // OAuth2 client id for client authentication
	ClientSecret  string           // OAuth2 client secret for client authentication
	AuthStyle     string           // "basic" (client_secret_basic) | "post" (client_secret_post)
	BearerToken   string           // Static bearer token alternative to client credentials
	TokenTypeHint string           // RFC 7662 token_type_hint (default "access_token")
	tokenRegexp   *regexp.Regexp   // Compiled TokenPattern; nil when TokenPattern is ""
	httpTransport *http.Transport  // Reused across requests for TCP connection pooling; nil = DefaultTransport
}

// IntrospectionResult is the RFC 7662 introspection response. Typed fields cover
// the registered members; raw retains every member for claim mappings/properties.
type IntrospectionResult struct {
	Active    bool        `json:"active"`
	Scope     string      `json:"scope"`
	ClientID  string      `json:"client_id"`
	Username  string      `json:"username"`
	TokenType string      `json:"token_type"`
	Exp       int64       `json:"exp"`
	Iat       int64       `json:"iat"`
	Nbf       int64       `json:"nbf"`
	Sub       string      `json:"sub"`
	Aud       interface{} `json:"aud"` // string or []string
	Iss       string      `json:"iss"`
	Jti       string      `json:"jti"`
	raw       map[string]interface{}
}

var ins = &OpaqueTokenAuthPolicy{
	cache: cache.NewInMemoryCache[*cachedIntrospection](cacheName, cacheMaxSize, 0, cache.LRUEvictionPolicy, slog.Default()),
}

// GetPolicy is the v1alpha2 factory entry point (loaded by v1alpha2 kernels).
func GetPolicy(
	metadata policy.PolicyMetadata,
	params map[string]interface{},
) (policy.Policy, error) {
	return ins, nil
}

func (p *OpaqueTokenAuthPolicy) Mode() policy.ProcessingMode {
	return policy.ProcessingMode{
		RequestHeaderMode:  policy.HeaderModeProcess,
		RequestBodyMode:    policy.BodyModeSkip,
		ResponseHeaderMode: policy.HeaderModeSkip,
		ResponseBodyMode:   policy.BodyModeSkip,
	}
}

// OnRequestHeaders performs opaque token introspection in the request header phase.
func (p *OpaqueTokenAuthPolicy) OnRequestHeaders(ctx context.Context, reqCtx *policy.RequestHeaderContext, params map[string]interface{}) policy.RequestHeaderAction {
	slog.Debug("Opaque Token Auth Policy: OnRequestHeaders started")

	headerName := getStringParam(params, "headerName", "Authorization")
	authHeaderScheme := getStringParam(params, "authHeaderScheme", "Bearer")
	onFailureStatusCode := getIntParam(params, "onFailureStatusCode", 401)
	errorMessageFormat := getStringParam(params, "errorMessageFormat", "json")
	errorMessage := getStringParam(params, "errorMessage", "Authentication failed")
	leewayStr := getStringParam(params, "leeway", "30s")
	cacheTtlStr := getStringParam(params, "introspectionCacheTtl", "60s")
	negativeCacheTtlStr := getStringParam(params, "introspectionNegativeCacheTtl", "30s")
	timeoutStr := getStringParam(params, "introspectionTimeout", "5s")
	retryCount := getIntParam(params, "introspectionRetryCount", 2)
	retryIntervalStr := getStringParam(params, "introspectionRetryInterval", "1s")

	leeway := parseDurationOrDefault(leewayStr, 30*time.Second)
	cacheTtl := parseDurationOrDefault(cacheTtlStr, 60*time.Second)
	negativeCacheTtl := parseDurationOrDefault(negativeCacheTtlStr, 30*time.Second)
	timeout := parseDurationOrDefault(timeoutStr, 5*time.Second)
	retryInterval := parseDurationOrDefault(retryIntervalStr, time.Second)

	// User/route-level assertions.
	userIssuers := getStringArrayParam(params, "issuers", []string{})
	userAudiences := getStringArrayParam(params, "audiences", []string{})
	userRequiredScopes := getStringArrayParam(params, "requiredScopes", []string{})
	userRequiredClaims := getStringMapParam(params, "requiredClaims", map[string]string{})
	userIdClaim := getStringParam(params, "userIdClaim", "sub")
	userAuthHeaderPrefix := getStringParam(params, "authHeaderPrefix", "")
	forwardToken := getBoolParam(params, "forwardToken", true)
	forwardedTokenHeader := getStringParam(params, "forwardedTokenHeader", "x-forwarded-authorization")

	if userAuthHeaderPrefix != "" {
		authHeaderScheme = userAuthHeaderPrefix
	}

	providers, err := p.getProviders(params)
	if err != nil {
		slog.Debug("Opaque Token Auth Policy: Failed to parse introspection providers", "error", err)
		return p.handleAuthFailureHeaders(reqCtx.SharedContext, onFailureStatusCode, errorMessageFormat, errorMessage, fmt.Sprintf("invalid introspection configuration: %v", err))
	}
	if len(providers) == 0 {
		slog.Debug("Opaque Token Auth Policy: No introspection providers configured")
		return p.handleAuthFailureHeaders(reqCtx.SharedContext, onFailureStatusCode, errorMessageFormat, errorMessage, "introspection providers not configured")
	}

	selected := selectProviders(providers, userIssuers)
	if len(selected) == 0 {
		slog.Debug("Opaque Token Auth Policy: No provider matches configured issuers", "issuers", userIssuers)
		return p.handleAuthFailureHeaders(reqCtx.SharedContext, onFailureStatusCode, errorMessageFormat, errorMessage, "no introspection provider matches configured issuers")
	}

	authHeaders := getDownstreamHeaders(reqCtx.Downstream, reqCtx.Headers).Get(strings.ToLower(headerName))
	if len(authHeaders) == 0 {
		slog.Debug("Opaque Token Auth Policy: Missing authorization header", "headerName", headerName)
		return p.handleAuthFailureHeaders(reqCtx.SharedContext, onFailureStatusCode, errorMessageFormat, errorMessage, "missing authorization header")
	}
	authHeader := authHeaders[0]

	token := extractToken(authHeader, authHeaderScheme)
	if token == "" {
		slog.Debug("Opaque Token Auth Policy: Failed to extract token from authorization header", "authHeaderScheme", authHeaderScheme)
		return p.handleAuthFailureHeaders(reqCtx.SharedContext, onFailureStatusCode, errorMessageFormat, errorMessage, "invalid authorization header format")
	}

	selected = filterProvidersByToken(selected, token)
	if len(selected) == 0 {
		slog.Debug("Opaque Token Auth Policy: No provider tokenPattern matches token")
		return p.handleAuthFailureHeaders(reqCtx.SharedContext, onFailureStatusCode, errorMessageFormat, errorMessage, "no introspection provider matches token pattern")
	}

	// Introspect against each selected provider until one reports the token active.
	var result *IntrospectionResult
	var lastErr error
	for _, provider := range selected {
		res, err := p.introspect(ctx, token, provider, cacheTtl, negativeCacheTtl, timeout, retryCount, retryInterval)
		if err != nil {
			slog.Debug("Opaque Token Auth Policy: Introspection call failed", "provider", provider.Name, "error", err)
			lastErr = err
			continue
		}
		if res.Active {
			slog.Debug("Opaque Token Auth Policy: Token reported active", "provider", provider.Name)
			result = res
			break
		}
		slog.Debug("Opaque Token Auth Policy: Token reported inactive", "provider", provider.Name)
	}

	if result == nil {
		reason := "token inactive or unrecognized"
		if lastErr != nil {
			reason = fmt.Sprintf("introspection failed: %v", lastErr)
		}
		return p.handleAuthFailureHeaders(reqCtx.SharedContext, onFailureStatusCode, errorMessageFormat, errorMessage, reason)
	}

	// Defense-in-depth: re-check nbf/exp locally with leeway. The authorization
	// server is authoritative, but cached entries are bounded only by exp.
	now := time.Now()
	if result.Exp > 0 && now.After(time.Unix(result.Exp, 0).Add(leeway)) {
		return p.handleAuthFailureHeaders(reqCtx.SharedContext, onFailureStatusCode, errorMessageFormat, errorMessage, "token expired")
	}
	if result.Nbf > 0 && now.Before(time.Unix(result.Nbf, 0).Add(-leeway)) {
		return p.handleAuthFailureHeaders(reqCtx.SharedContext, onFailureStatusCode, errorMessageFormat, errorMessage, "token not yet valid")
	}

	// Audience assertion.
	if len(userAudiences) > 0 {
		aud := parseAudience(result.raw["aud"])
		if !anyMatch(userAudiences, aud) {
			slog.Debug("Opaque Token Auth Policy: No valid audience found", "tokenAudiences", aud)
			return p.handleAuthFailureHeaders(reqCtx.SharedContext, onFailureStatusCode, errorMessageFormat, errorMessage, "no valid audience found in token")
		}
	}

	// Scope assertion: passes when the token contains at least one required scope (OR).
	if len(userRequiredScopes) > 0 {
		scopes := parseScopes(result.raw["scope"], result.raw["scp"])
		if !anyMatch(userRequiredScopes, scopes) {
			slog.Debug("Opaque Token Auth Policy: No required scope found in token", "requiredScopes", userRequiredScopes)
			return p.handleAuthFailureHeaders(reqCtx.SharedContext, onFailureStatusCode, errorMessageFormat, errorMessage, "token does not contain any required scope")
		}
	}

	// Required-claim assertions.
	for claimName, expectedValue := range userRequiredClaims {
		if claimValueToString(result.raw[claimName]) != expectedValue {
			slog.Debug("Opaque Token Auth Policy: Required claim validation failed", "claimName", claimName)
			return p.handleAuthFailureHeaders(reqCtx.SharedContext, onFailureStatusCode, errorMessageFormat, errorMessage, fmt.Sprintf("claim '%s' validation failed", claimName))
		}
	}

	slog.Debug("Opaque Token Auth Policy: All validations passed, authentication successful")
	return p.handleAuthSuccessHeaders(reqCtx.SharedContext, result, token, userIdClaim, headerName, authHeader, forwardToken, forwardedTokenHeader)
}

// introspect returns the (possibly cached) introspection result for a token at a
// provider. Active responses are cached bounded by min(cacheTtl, token exp).
// Inactive (active:false) HTTP-200 responses are cached for negativeCacheTtl when
// > 0; transport errors and non-200 responses are never cached.
func (p *OpaqueTokenAuthPolicy) introspect(ctx context.Context, token string, provider *IntrospectionProvider, cacheTtl, negativeCacheTtl, timeout time.Duration, retryCount int, retryInterval time.Duration) (*IntrospectionResult, error) {
	if retryCount < 0 {
		return nil, fmt.Errorf("invalid introspection retry count: %d", retryCount)
	}

	cacheKey := cache.CacheKey{Key: introspectionCacheKey(provider, token)}

	// The SDK cache has no TTL of its own; each entry carries its own expiresAt
	// (bounded by the token's exp), so a stale hit is treated as a miss.
	if cached, ok := p.cache.Get(ctx, cacheKey); ok && time.Now().Before(cached.expiresAt) {
		slog.Debug("Opaque Token Auth Policy: Introspection cache hit", "provider", provider.Name)
		return cached.result, nil
	}
	slog.Debug("Opaque Token Auth Policy: Introspection cache miss", "provider", provider.Name)

	var lastErr error
	for attempt := 0; attempt <= retryCount; attempt++ {
		slog.Debug("Opaque Token Auth Policy: Introspection attempt", "provider", provider.Name, "attempt", attempt+1, "maxAttempts", retryCount+1)
		result, err := p.doIntrospect(ctx, token, provider, timeout)
		if err == nil {
			var expiresAt time.Time
			if result.Active {
				expiresAt = time.Now().Add(cacheTtl)
				if result.Exp > 0 {
					if tokenExp := time.Unix(result.Exp, 0); tokenExp.Before(expiresAt) {
						expiresAt = tokenExp
					}
				}
			} else if negativeCacheTtl > 0 {
				expiresAt = time.Now().Add(negativeCacheTtl)
			}
			if !expiresAt.IsZero() && expiresAt.After(time.Now()) {
				slog.Debug("Opaque Token Auth Policy: Caching introspection result", "provider", provider.Name, "active", result.Active, "expiresAt", expiresAt)
				_ = p.cache.Set(ctx, cacheKey, &cachedIntrospection{result: result, expiresAt: expiresAt})
			}
			return result, nil
		}
		slog.Debug("Opaque Token Auth Policy: Introspection attempt failed", "provider", provider.Name, "attempt", attempt+1, "error", err)
		lastErr = err
		if attempt < retryCount {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(retryInterval):
			}
		}
	}

	if lastErr == nil {
		return nil, fmt.Errorf("introspection failed: no attempts executed")
	}
	return nil, lastErr
}

// doIntrospect performs a single RFC 7662 introspection POST request.
func (p *OpaqueTokenAuthPolicy) doIntrospect(ctx context.Context, token string, provider *IntrospectionProvider, timeout time.Duration) (*IntrospectionResult, error) {
	form := url.Values{}
	form.Set("token", token)
	if provider.TokenTypeHint != "" {
		form.Set("token_type_hint", provider.TokenTypeHint)
	}
	if provider.AuthStyle == "post" && provider.ClientID != "" {
		form.Set("client_id", provider.ClientID)
		form.Set("client_secret", provider.ClientSecret)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, provider.URI, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to build introspection request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	authMethod := "none"
	switch {
	case provider.BearerToken != "":
		req.Header.Set("Authorization", "Bearer "+provider.BearerToken)
		authMethod = "bearer"
	case provider.AuthStyle == "post" && provider.ClientID != "":
		// credentials already added to form body above
		authMethod = "client_secret_post"
	case provider.AuthStyle != "post" && provider.ClientID != "":
		req.SetBasicAuth(provider.ClientID, provider.ClientSecret)
		authMethod = "client_secret_basic"
	}
	slog.Debug("Opaque Token Auth Policy: Sending introspection request", "provider", provider.Name, "uri", provider.URI, "authMethod", authMethod, "timeout", timeout)

	client := &http.Client{Timeout: timeout}
	if provider.httpTransport != nil {
		client.Transport = provider.httpTransport
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("introspection request failed: %w", err)
	}
	defer resp.Body.Close()
	slog.Debug("Opaque Token Auth Policy: Received introspection response", "provider", provider.Name, "status", resp.StatusCode)

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("introspection endpoint returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read introspection response: %w", err)
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("failed to parse introspection response: %w", err)
	}
	// Best-effort: populate typed convenience fields (active, exp, sub, etc.).
	// Errors are ignored because polymorphic members like scope/aud may not match
	// the struct field types; raw is the authoritative source for all claim access.
	var result IntrospectionResult
	_ = json.Unmarshal(body, &result)
	result.raw = raw
	slog.Debug("Opaque Token Auth Policy: Parsed introspection result", "provider", provider.Name, "active", result.Active, "exp", result.Exp)
	return &result, nil
}

// handleAuthSuccessHeaders populates AuthContext and request-header modifications
// after a successful introspection.
func (p *OpaqueTokenAuthPolicy) handleAuthSuccessHeaders(shared *policy.SharedContext, result *IntrospectionResult, token string,
	userIdClaim string, headerName string, authHeaderValue string, forwardToken bool, forwardedTokenHeader string) policy.RequestHeaderAction {

	subject := result.Sub
	if userIdClaim != "" && userIdClaim != "sub" {
		if v, ok := result.raw[userIdClaim]; ok {
			candidate := strings.TrimSpace(claimValueToString(v))
			if candidate != "" && candidate != "null" {
				subject = candidate
			}
		}
	}

	slog.Debug("Opaque Token Auth Policy: Building auth context", "issuer", result.Iss, "forwardToken", forwardToken, "forwardedTokenHeader", forwardedTokenHeader)
	shared.AuthContext = &policy.AuthContext{
		Authenticated: true,
		AuthType:      AuthType,
		Subject:       subject,
		Issuer:        result.Iss,
		Audience:      parseAudience(result.raw["aud"]),
		Scopes:        buildScopesMap(result.raw),
		CredentialID:  result.ClientID,
		// TokenId is a SHA-256 fingerprint of the opaque token: a stable, globally
		// unique, non-reversible identifier (the raw token is a bearer secret and must
		// not be propagated). Downstream policies such as backend-jwt use it as a cache key.
		TokenId:    tokenFingerprint(token),
		Properties: buildProperties(result.raw),
		Previous:   shared.AuthContext,
	}

	modifications := policy.UpstreamRequestHeaderModifications{
		HeadersToSet: make(map[string]string),
	}

	canonicalIn := http.CanonicalHeaderKey(headerName)
	canonicalOut := http.CanonicalHeaderKey(forwardedTokenHeader)

	if !forwardToken {
		modifications.HeadersToRemove = []string{canonicalIn}
	} else if canonicalOut != canonicalIn {
		modifications.HeadersToSet[canonicalOut] = authHeaderValue
		modifications.HeadersToRemove = []string{canonicalIn}
	}

	return modifications
}

// handleAuthFailureHeaders sets an unauthenticated AuthContext and returns an
// immediate error response.
func (p *OpaqueTokenAuthPolicy) handleAuthFailureHeaders(shared *policy.SharedContext, statusCode int, errorFormat, errorMessage, reason string) policy.RequestHeaderAction {
	slog.Debug("Opaque Token Auth Policy: Authentication failed", "statusCode", statusCode, "reason", reason)

	shared.AuthContext = &policy.AuthContext{
		Authenticated: false,
		AuthType:      AuthType,
		Previous:      shared.AuthContext,
	}

	headers := map[string]string{
		"content-type": "application/json",
	}

	var body string
	switch errorFormat {
	case "plain":
		body = errorMessage
		headers["content-type"] = "text/plain"
	case "minimal":
		body = "Unauthorized"
		headers["content-type"] = "text/plain"
	default:
		errResponse := map[string]interface{}{
			"error":   "Unauthorized",
			"message": errorMessage,
		}
		bodyBytes, _ := json.Marshal(errResponse)
		body = string(bodyBytes)
	}

	return policy.ImmediateResponse{
		StatusCode: statusCode,
		Headers:    headers,
		Body:       []byte(body),
	}
}

// ─── Configuration parsing ───────────────────────────────────────────────────

// parseIntrospectionProviders builds the provider list from the system params.
func parseIntrospectionProviders(params map[string]interface{}) ([]*IntrospectionProvider, error) {
	raw, ok := params["introspectionProviders"]
	if !ok {
		return nil, nil
	}
	list, ok := raw.([]interface{})
	if !ok {
		return nil, fmt.Errorf("introspectionProviders must be an array")
	}

	providers := make([]*IntrospectionProvider, 0, len(list))
	seenNames := make(map[string]struct{}, len(list))
	for _, item := range list {
		pm, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		name := getString(pm["name"])
		if name == "" {
			slog.Debug("Opaque Token Auth Policy: Skipping provider with empty name")
			continue
		}
		if _, exists := seenNames[name]; exists {
			return nil, fmt.Errorf("duplicate introspection provider name %q", name)
		}
		seenNames[name] = struct{}{}
		introspection, ok := pm["introspection"].(map[string]interface{})
		if !ok {
			slog.Debug("Opaque Token Auth Policy: Skipping provider without introspection config", "name", name)
			continue
		}
		uri := getString(introspection["uri"])
		if uri == "" {
			slog.Debug("Opaque Token Auth Policy: Skipping provider without introspection uri", "name", name)
			continue
		}

		tokenPattern := getString(pm["tokenPattern"])
		var tokenRegexp *regexp.Regexp
		if tokenPattern != "" {
			compiled, err := regexp.Compile(tokenPattern)
			if err != nil {
				return nil, fmt.Errorf("provider %q: invalid tokenPattern: %w", name, err)
			}
			tokenRegexp = compiled
		}

		provider := &IntrospectionProvider{
			Name:          name,
			Issuer:        getString(pm["issuer"]),
			TokenPattern:  tokenPattern,
			URI:           uri,
			ClientID:      getString(introspection["clientId"]),
			ClientSecret:  getString(introspection["clientSecret"]),
			AuthStyle:     getString(introspection["authStyle"]),
			BearerToken:   getString(introspection["bearerToken"]),
			TokenTypeHint: getStringOrDefault(introspection["tokenTypeHint"], "access_token"),
			tokenRegexp:   tokenRegexp,
		}

		if provider.BearerToken != "" && provider.ClientID != "" {
			return nil, fmt.Errorf("provider %q: bearerToken and clientId are mutually exclusive", name)
		}

		certPath := getString(introspection["certificatePath"])
		skipTlsVerify := getBool(introspection["skipTlsVerify"])
		if certPath != "" || skipTlsVerify {
			tlsConfig, err := buildTLSConfig(certPath, skipTlsVerify)
			if err != nil {
				return nil, fmt.Errorf("provider %q: %w", name, err)
			}
			provider.httpTransport = &http.Transport{TLSClientConfig: tlsConfig}
		}

		providers = append(providers, provider)
	}
	return providers, nil
}

// getProviders returns the provider list, parsing it exactly once from the
// startup config. config.toml is not reloaded at runtime so this is safe.
func (p *OpaqueTokenAuthPolicy) getProviders(params map[string]interface{}) ([]*IntrospectionProvider, error) {
	p.provOnce.Do(func() {
		p.providers, p.provErr = parseIntrospectionProviders(params)
		slog.Debug("Opaque Token Auth Policy: Provider list parsed", "count", len(p.providers))
	})
	return p.providers, p.provErr
}

// selectProviders narrows the provider list by the user-supplied issuers (matched
// against provider name or issuer). With no issuers configured, all are returned.
func selectProviders(providers []*IntrospectionProvider, issuers []string) []*IntrospectionProvider {
	if len(issuers) == 0 {
		return providers
	}
	var selected []*IntrospectionProvider
	for _, provider := range providers {
		if contains(issuers, provider.Name) || (provider.Issuer != "" && contains(issuers, provider.Issuer)) {
			selected = append(selected, provider)
		}
	}
	return selected
}

// filterProvidersByToken drops providers whose tokenPattern does not match token.
// Providers with no pattern (tokenRegexp == nil) match all tokens.
func filterProvidersByToken(providers []*IntrospectionProvider, token string) []*IntrospectionProvider {
	var out []*IntrospectionProvider
	for _, p := range providers {
		if p.tokenRegexp == nil || p.tokenRegexp.MatchString(token) {
			out = append(out, p)
		}
	}
	return out
}

// buildTLSConfig builds a TLS config from an optional custom CA certificate file
// and an optional skip-verify flag.
func buildTLSConfig(certPath string, skipTlsVerify bool) (*tls.Config, error) {
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if certPath != "" {
		certData, err := os.ReadFile(certPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read certificate file: %w", err)
		}
		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(certData) {
			return nil, fmt.Errorf("failed to parse PEM certificate from %s", certPath)
		}
		cfg.RootCAs = caCertPool
	}
	if skipTlsVerify {
		cfg.InsecureSkipVerify = true
	}
	return cfg, nil
}

// introspectionCacheKey returns a hex SHA-256 keyed on the provider name and
// the raw token, scoped per-provider so negative cache entries from one
// provider do not suppress introspection attempts at another.
func introspectionCacheKey(provider *IntrospectionProvider, token string) string {
	h := sha256.New()
	h.Write([]byte(provider.Name))
	h.Write([]byte{0})
	h.Write([]byte(token))
	return hex.EncodeToString(h.Sum(nil))
}

// tokenFingerprint returns a hex SHA-256 of the token, used as AuthContext.TokenId.
// Unlike introspectionCacheKey it is not provider-scoped, so the same token yields
// the same downstream cache key regardless of which provider validated it.
func tokenFingerprint(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// ─── Generic helpers ─────────────────────────────────────────────────────────

func parseDurationOrDefault(s string, def time.Duration) time.Duration {
	d, err := time.ParseDuration(s)
	if err != nil {
		slog.Debug("Opaque Token Auth Policy: Failed to parse duration, using default", "value", s, "default", def)
		return def
	}
	return d
}

// extractToken extracts the token from an authorization header value.
func extractToken(authHeader, scheme string) string {
	authHeader = strings.TrimSpace(authHeader)
	if scheme != "" {
		parts := strings.Fields(authHeader)
		if len(parts) == 2 && strings.EqualFold(parts[0], scheme) {
			return parts[1]
		}
		return ""
	}
	parts := strings.Fields(authHeader)
	if len(parts) == 0 {
		return ""
	}
	if len(parts) > 1 {
		return parts[1]
	}
	return parts[0]
}

// parseAudience parses an audience value which can be a string or array.
func parseAudience(audClaim interface{}) []string {
	if audStr, ok := audClaim.(string); ok {
		return []string{audStr}
	}
	if audArr, ok := audClaim.([]interface{}); ok {
		var result []string
		for _, a := range audArr {
			if aStr, ok := a.(string); ok {
				result = append(result, aStr)
			}
		}
		return result
	}
	return []string{}
}

// parseScopes parses scopes from `scope` and/or `scp` introspection members.
// Each can be either a space-delimited string or an array of strings.
func parseScopes(scopeClaim, scpClaim interface{}) []string {
	var scopes []string
	scopes = append(scopes, parseScopeValue(scopeClaim)...)
	scopes = append(scopes, parseScopeValue(scpClaim)...)
	return scopes
}

// parseScopeValue accepts a scope value that is either a space-delimited string
// or an array of strings.
func parseScopeValue(v interface{}) []string {
	switch val := v.(type) {
	case string:
		return strings.Fields(val)
	case []interface{}:
		result := make([]string, 0, len(val))
		for _, s := range val {
			if str, ok := s.(string); ok {
				result = append(result, str)
			}
		}
		return result
	}
	return nil
}

// buildScopesMap converts scope/scp values into a set for AuthContext.Scopes.
func buildScopesMap(raw map[string]interface{}) map[string]bool {
	scopes := parseScopes(raw["scope"], raw["scp"])
	if len(scopes) == 0 {
		return nil
	}
	result := make(map[string]bool, len(scopes))
	for _, s := range scopes {
		result[s] = true
	}
	return result
}

// buildProperties extracts non-standard members into AuthContext.Properties.
func buildProperties(raw map[string]interface{}) map[string]string {
	var props map[string]string
	for k, v := range raw {
		if standardIntrospectionClaims[k] {
			continue
		}
		if props == nil {
			props = make(map[string]string)
		}
		props[k] = claimValueToString(v)
	}
	return props
}

func contains(list []string, target string) bool {
	for _, v := range list {
		if v == target {
			return true
		}
	}
	return false
}

func anyMatch(a, b []string) bool {
	for _, x := range a {
		if contains(b, x) {
			return true
		}
	}
	return false
}

func getString(v interface{}) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func getStringOrDefault(v interface{}, def string) string {
	if s, ok := v.(string); ok && s != "" {
		return s
	}
	return def
}

func getBool(v interface{}) bool {
	if b, ok := v.(bool); ok {
		return b
	}
	return false
}

func getBoolParam(params map[string]interface{}, key string, defaultValue bool) bool {
	if v, ok := params[key]; ok {
		if b, ok := v.(bool); ok {
			return b
		}
	}
	return defaultValue
}

func getStringParam(params map[string]interface{}, key, defaultValue string) string {
	if v, ok := params[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return defaultValue
}

func getIntParam(params map[string]interface{}, key string, defaultValue int) int {
	if v, ok := params[key]; ok {
		if i, ok := v.(int); ok {
			return i
		}
		if f, ok := v.(float64); ok {
			return int(f)
		}
	}
	return defaultValue
}

func getStringArrayParam(params map[string]interface{}, key string, defaultValue []string) []string {
	if v, ok := params[key]; ok {
		if arr, ok := v.([]interface{}); ok {
			var result []string
			for _, item := range arr {
				if s, ok := item.(string); ok {
					result = append(result, s)
				}
			}
			if len(result) > 0 {
				return result
			}
		}
	}
	return defaultValue
}

func getStringMapParam(params map[string]interface{}, key string, defaultValue map[string]string) map[string]string {
	if v, ok := params[key]; ok {
		if m, ok := v.(map[string]interface{}); ok {
			result := make(map[string]string)
			for k, val := range m {
				if s, ok := val.(string); ok {
					result[k] = s
				}
			}
			if len(result) > 0 {
				return result
			}
		}
	}
	return defaultValue
}

func claimValueToString(v interface{}) string {
	switch val := v.(type) {
	case nil:
		return ""
	case string:
		return val
	case float64:
		return strconv.FormatFloat(val, 'f', -1, 64)
	case bool:
		return fmt.Sprintf("%v", val)
	default:
		bytes, _ := json.Marshal(val)
		return string(bytes)
	}
}
