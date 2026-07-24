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

package backendjwt

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log/slog"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
	"github.com/wso2/api-platform/sdk/core/utils/cache"
)

const (
	defaultHeader      = "x-jwt-assertion"
	defaultTokenExpiry = 15 * time.Minute
	defaultAlgorithm   = "SHA256withRSA"
	minCacheTTL        = 30 * time.Second

	// defaultCacheMaxSize bounds the total number of cached tokens across all APIs. 
	// The SDK cache fixes its size at construction, so a changed cacheMaxSize is
	// applied by rebuilding the cache (see ensureTokenCache).
	defaultCacheMaxSize = 100_000
)

// resolvedClaims holds the extra claims derived from customClaims, split by type
// so the cache key and JWT population can share the same resolved values.
type resolvedClaims struct {
	stringClaims  map[string]string      // resolved string claims: static + $ctx: customClaims and claimMappings destinations
	rawClaims     map[string]interface{} // non-string customClaims (numbers, booleans) preserved as-is
	mappedSources map[string]bool        // Properties keys consumed by claimMappings; skip in auto-forward
}

// BackendJWTPolicy generates a signed JWT from the authenticated user context
// and injects it into the upstream request header. It is designed to run after
// an authentication policy (e.g. jwt-auth, basic-auth, api-key-auth).
type BackendJWTPolicy struct {
	keyCache sync.Map // hex(sha256 fingerprint) → crypto.PrivateKey; config-lifetime, unbounded
	pemCache sync.Map // path → []byte PEM bytes; config-lifetime, unbounded

	// cacheMu guards the tokenCache pointer and currentMaxSize. The SDK cache fixes its size at
	// construction (no live resize), so a changed cacheMaxSize is applied by swapping in a new
	// cache. Reads take the RLock and copy the pointer so an in-flight request keeps using a
	// consistent cache even if a concurrent deployment rebuilds it.
	cacheMu        sync.RWMutex
	tokenCache     *cache.InMemoryCache[cachedToken] // single shared token cache for all APIs; globally bounded by cacheMaxSize
	currentMaxSize int
}

// cachedToken is a signed JWT paired with the instant after which it must no longer be served.
// The SDK cache exposes only a uniform per-cache TTL, but token lifetimes vary per API, so the
// expiry travels in the value and is enforced on read (see getCachedToken); the cache itself is
// created with ttl=0 (never expires entries on its own clock).
type cachedToken struct {
	signed    string
	expiresAt time.Time
}

// newTokenCache builds the shared token cache, globally bounded by maxSize across all APIs.
// ttl is 0 because expiry is enforced per entry in getCachedToken; once full, the cache's LRU
// policy evicts the least-recently-used entry across all APIs, enforcing a single global bound.
// The cache is given the policy's default slog logger so its own debug lines flow through the
// same logging pipeline; slog gates them by level, so they appear only when debug logging is
// enabled (pass nil instead to force them off regardless of level).
func newTokenCache(maxSize int) *cache.InMemoryCache[cachedToken] {
	return cache.NewInMemoryCache[cachedToken]("backend-jwt-tokens", maxSize, 0, cache.LRUEvictionPolicy, slog.Default())
}

// keyNamespace carries the per-deployment configuration that shapes the generated token but is
// not part of the caller identity. Folding it into the cache key makes the key a complete
// function of the token: a redeploy that changes any of these fields yields a different key
// (a cache miss), so a stale token built from the old config is never served — no separate
// invalidation step is needed. apiName keeps each API's entries isolated even when two APIs see
// identical identity/path/claims but differ in signing config.
type keyNamespace struct {
	apiName   string
	issuer    string
	algorithm string
	dialect   string
	excluded  []string // sorted excludedClaims
}

// prefix renders the namespace as a deterministic key prefix. excluded is expected pre-sorted.
func (ns keyNamespace) prefix() string {
	return ns.apiName + "\x00" + ns.issuer + "\x00" + ns.algorithm + "\x00" +
		ns.dialect + "\x00" + strings.Join(ns.excluded, ",") + "\x00"
}

// algorithmEntry describes a supported JWT signing algorithm.
// To add a new algorithm: add a single entry to the algorithms map below.
type algorithmEntry struct {
	method  jwt.SigningMethod
	keyType string // "rsa", "ecdsa", or "none"
}

// algorithms is the single source of truth for supported signing algorithms.
var algorithms = map[string]algorithmEntry{
	"SHA256withRSA": {jwt.SigningMethodRS256, "rsa"},
	"ES256":         {jwt.SigningMethodES256, "ecdsa"},
	"NONE":          {jwt.SigningMethodNone, "none"},
}

var ins = &BackendJWTPolicy{
	tokenCache:     newTokenCache(defaultCacheMaxSize),
	currentMaxSize: defaultCacheMaxSize,
}

// GetPolicy is the v1alpha2 factory entry point. It is called on each API deployment and applies
// the global cacheMaxSize from systemParameters to the shared token cache. Redeploy invalidation
// is handled implicitly by the cache key: it folds in every token-shaping field (identity,
// operation, claims, issuer, algorithm, dialect, excludedClaims), so a redeploy that changes any
// of them simply misses the old entries — no explicit flush needed.
func GetPolicy(_ policy.PolicyMetadata, params map[string]interface{}) (policy.Policy, error) {
	// cacheMaxSize is a single global bound across all APIs; there is no unbounded mode. A missing
	// or invalid value falls back to the default bound.
	maxSize := getInt(params, "cacheMaxSize", defaultCacheMaxSize)
	if maxSize <= 0 {
		maxSize = defaultCacheMaxSize
	}
	ins.ensureTokenCache(maxSize)
	return ins, nil
}

// ensureTokenCache (re)builds the shared token cache when the configured global size changes.
// The SDK cache fixes its size at construction (there is no live resize), so applying a new
// cacheMaxSize means replacing the cache, which flushes all entries. This happens only on the
// first deployment or a genuine cacheMaxSize change — steady-state redeploys leave it untouched
// and only bump the generation.
func (p *BackendJWTPolicy) ensureTokenCache(maxSize int) {
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

// currentTokenCache returns the live token cache pointer under the read lock, so callers operate
// on a consistent instance even if a concurrent deployment rebuilds the cache.
func (p *BackendJWTPolicy) currentTokenCache() *cache.InMemoryCache[cachedToken] {
	p.cacheMu.RLock()
	defer p.cacheMu.RUnlock()
	return p.tokenCache
}

func (p *BackendJWTPolicy) Mode() policy.ProcessingMode {
	return policy.ProcessingMode{
		RequestHeaderMode:  policy.HeaderModeProcess,
		RequestBodyMode:    policy.BodyModeSkip,
		ResponseHeaderMode: policy.HeaderModeSkip,
		ResponseBodyMode:   policy.BodyModeSkip,
	}
}

// Validate checks the algorithm is supported and, for key-based algorithms,
// that the signing key is present and parseable at config load time.
func (p *BackendJWTPolicy) Validate(params map[string]interface{}) error {
	alg := getString(params, "algorithm", defaultAlgorithm)
	entry, ok := algorithms[alg]
	if !ok {
		return fmt.Errorf("unsupported algorithm %q; supported: %s", alg, algorithmList())
	}

	if s := getString(params, "tokenExpiry", ""); s != "" {
		d, err := time.ParseDuration(s)
		if err != nil {
			return fmt.Errorf("invalid tokenExpiry %q: %w", s, err)
		}
		if d <= 0 {
			return fmt.Errorf("tokenExpiry must be a positive duration, got %q", s)
		}
	}

	if entry.keyType == "none" {
		return nil
	}
	pemBytes, err := p.extractSigningKeyPEM(params)
	if err != nil {
		return fmt.Errorf("invalid signingKey: %w", err)
	}
	key, err := parsePrivateKey(pemBytes)
	if err != nil {
		return fmt.Errorf("invalid signingKey: %w", err)
	}
	return checkKeyType(key, entry.keyType, alg)
}

// OnRequestHeaders generates a signed JWT from the auth context and sets it on the upstream request.
func (p *BackendJWTPolicy) OnRequestHeaders(ctx context.Context, reqCtx *policy.RequestHeaderContext, params map[string]interface{}) policy.RequestHeaderAction {
	authCtx := reqCtx.SharedContext.AuthContext

	alg := getString(params, "algorithm", defaultAlgorithm)
	entry, ok := algorithms[alg]
	if !ok {
		slog.Error("Backend JWT: unsupported algorithm", "algorithm", alg)
		return internalError()
	}
	issuer := getString(params, "issuer", "")
	expiry := parseDuration(getString(params, "tokenExpiry", ""), defaultTokenExpiry)
	headerName := getString(params, "header", defaultHeader)

	tokenCaching := getBool(params, "tokenCaching", true)
	dialect := getString(params, "dialect", "")
	excluded := getStringSet(params, "excludedClaims")

	// Resolve extra claims once — used for both the cache key and JWT population.
	extras := resolveExtraClaims(reqCtx, params)

	var cacheKey string
	if tokenCaching {
		ns := keyNamespace{
			apiName:   reqCtx.APIName,
			issuer:    issuer,
			algorithm: alg,
			dialect:   dialect,
			excluded:  sortedSetKeys(excluded),
		}
		cacheKey = buildTokenCacheKey(ns, authCtx, reqCtx.Path, reqCtx.Method, extras)
		if signed, ok := p.getCachedToken(ctx, cacheKey); ok {
			slog.Debug("Backend JWT: cache hit", "authType", authTypeLabel(authCtx))
			return policy.UpstreamRequestHeaderModifications{
				HeadersToSet: map[string]string{headerName: signed},
			}
		}
	}

	signingMethod := entry.method
	var signKey interface{}
	if entry.keyType == "none" {
		signKey = jwt.UnsafeAllowNoneSignatureType
	} else {
		pemBytes, err := p.extractSigningKeyPEM(params)
		if err != nil {
			slog.Error("Backend JWT: failed to extract signing key", "error", err)
			return internalError()
		}
		key, err := p.loadKey(pemBytes)
		if err != nil {
			slog.Error("Backend JWT: failed to parse signing key", "error", err)
			return internalError()
		}
		if err := checkKeyType(key, entry.keyType, alg); err != nil {
			slog.Error("Backend JWT: key type mismatch", "algorithm", alg, "error", err)
			return internalError()
		}
		signKey = key
	}

	claims := buildClaims(authCtx, issuer, dialect, expiry, excluded, extras, time.Now())

	token := jwt.NewWithClaims(signingMethod, claims)
	signed, err := token.SignedString(signKey)
	if err != nil {
		slog.Error("Backend JWT: failed to sign token", "error", err)
		return internalError()
	}

	if tokenCaching {
		p.putCachedToken(ctx, cacheKey, signed, expiry)
	}
	slog.Debug("Backend JWT: generated token", "header", headerName, "authType", authTypeLabel(authCtx))

	return policy.UpstreamRequestHeaderModifications{
		HeadersToSet: map[string]string{
			headerName: signed,
		},
	}
}

// buildClaims assembles the JWT claim set: the standard registered claims (iat/exp/iss),
// identity claims derived from the auth context, the auto-forwarded original-JWT claims (jwt
// auth only), and the resolved custom and mapped claims. The dialect prefix is applied to
// user-configured and auto-forwarded claim names; standard claims the policy sets itself are
// never prefixed. now anchors iat and exp.
func buildClaims(authCtx *policy.AuthContext, issuer, dialect string, expiry time.Duration, excluded map[string]bool, extras resolvedClaims, now time.Time) jwt.MapClaims {
	claims := jwt.MapClaims{
		"iat": now.Unix(),
		"exp": now.Add(expiry).Unix(),
	}
	if issuer != "" {
		claims["iss"] = issuer
	}

	if authCtx != nil {
		if authCtx.Subject != "" {
			claims["sub"] = authCtx.Subject
		}
		if authCtx.AuthType != "" {
			claims["auth_type"] = authCtx.AuthType
		}
		if len(authCtx.Audience) > 0 {
			claims["aud"] = authCtx.Audience
		}
		if authCtx.CredentialID != "" {
			claims["credential_id"] = authCtx.CredentialID
		}

		// For JWT auth, forward the incoming token's non-standard claims under their original
		// names. Reserved, excluded, and already-mapped claims are skipped; the claimMappings
		// and customClaims applied below can still add aliases or override.
		if authCtx.AuthType == "jwt" {
			for k, v := range authCtx.Properties {
				if restrictedClaims[k] || excluded[k] || extras.mappedSources[k] {
					continue
				}
				claims[dialect+k] = v
			}
			if scope := sortedScopeString(authCtx.Scopes); scope != "" {
				claims["scope"] = scope
			}
		}
	}

	for k, v := range extras.stringClaims {
		claims[dialect+k] = v
	}
	for k, v := range extras.rawClaims {
		claims[dialect+k] = v
	}
	return claims
}

// loadKey returns a cached private key, parsing and caching it on first use.
func (p *BackendJWTPolicy) loadKey(pemBytes []byte) (crypto.PrivateKey, error) {
	fingerprint := fmt.Sprintf("%x", sha256.Sum256(pemBytes))

	if key, ok := p.keyCache.Load(fingerprint); ok {
		return key.(crypto.PrivateKey), nil
	}

	parsed, err := parsePrivateKey(pemBytes)
	if err != nil {
		return nil, err
	}

	p.keyCache.Store(fingerprint, parsed)

	return parsed, nil
}

// restrictedClaims are set by the policy itself; custom claims must not override them.
var restrictedClaims = map[string]bool{
	"iss": true,
	"sub": true,
	"aud": true,
	"exp": true,
	"iat": true,
	"nbf": true,
	"jti": true,
}

// resolveExtraClaims resolves claimMappings and customClaims from params into a resolvedClaims.
// claimMappings are processed first; customClaims run after and take precedence.
// stringClaims holds resolved string values (including $ctx: refs and mapped properties).
// rawClaims holds non-string customClaims preserved as their original types for JWT population.
func resolveExtraClaims(reqCtx *policy.RequestHeaderContext, params map[string]interface{}) resolvedClaims {
	result := resolvedClaims{
		stringClaims:  make(map[string]string),
		rawClaims:     make(map[string]interface{}),
		mappedSources: make(map[string]bool),
	}
	result.applyClaimMappings(objectParam(params, "claimMappings"), reqCtx.SharedContext.AuthContext)
	result.applyCustomClaims(objectParam(params, "customClaims"), reqCtx)
	return result
}

// applyClaimMappings copies authenticated-context properties into destination claim names per the
// claimMappings config. Reserved destinations are skipped with a warning; non-string or empty
// entries and missing source properties are silently skipped. Each consumed source is recorded in
// mappedSources so the auto-forward loop in buildClaims won't also emit it under its original name.
func (r resolvedClaims) applyClaimMappings(mappings map[string]interface{}, authCtx *policy.AuthContext) {
	for dest, srcRaw := range mappings {
		src, ok := srcRaw.(string)
		if !ok || src == "" {
			continue
		}
		if restrictedClaims[dest] {
			slog.Warn("Backend JWT: claimMapping targets a reserved claim; skipping", "claim", dest)
			continue
		}
		if authCtx == nil {
			continue
		}
		val, ok := authCtx.Properties[src]
		if !ok {
			continue
		}
		r.stringClaims[dest] = val
		r.mappedSources[src] = true
	}
}

// applyCustomClaims adds the configured customClaims, which take precedence over claimMappings.
// Reserved names are skipped with a warning. Non-string values are preserved as-is in rawClaims;
// string values are resolved through resolveClaimValue ($ctx: refs), skipping any that don't
// resolve.
func (r resolvedClaims) applyCustomClaims(custom map[string]interface{}, reqCtx *policy.RequestHeaderContext) {
	for k, v := range custom {
		if restrictedClaims[k] {
			slog.Warn("Backend JWT: customClaim targets a reserved claim; skipping", "claim", k)
			continue
		}
		strVal, ok := v.(string)
		if !ok {
			r.rawClaims[k] = v
			continue
		}
		resolved, ok := resolveClaimValue(strVal, reqCtx)
		if !ok {
			slog.Debug("Backend JWT: skipping claim — context variable not resolvable",
				"claim", k, "ref", strVal)
			continue
		}
		r.stringClaims[k] = resolved
	}
}

// buildTokenCacheKey returns a cache key for the token cache. Every component is concatenated
// into a single buffer and SHA256-hashed, so the key is a fixed-length digest of everything
// regardless of identity shape:
//
//   - TokenId present:  namespace + TokenId + path + method (+ claims).
//   - authCtx nil:      namespace + path + method (+ claims).
//   - otherwise:        namespace + all identity fields + path + method (+ claims).
//
// The key is a complete function of the token: ns folds in the API namespace plus the
// token-shaping config that is not part of the caller identity (issuer, algorithm, dialect,
// excludedClaims), and the full configured claim set is included too — static and $ctx:-resolved
// customClaims, claimMappings destinations, and non-string custom claims. So redeploying an API
// with any token-affecting change yields a different key (a cache miss) and never serves a token
// built from the old config; no separate invalidation step is needed. Per-identity values (e.g.
// mapped Properties) are already captured by the identity fields, but including the resolved
// claim names/values also captures destination-name changes.
func buildTokenCacheKey(ns keyNamespace, authCtx *policy.AuthContext, path, method string, extras resolvedClaims) string {
	if i := strings.IndexByte(path, '?'); i != -1 {
		path = path[:i]
	}

	claimPairs := keyClaims(extras)

	var buf bytes.Buffer

	// Namespace: API plus the token-shaping config that is not part of the caller identity.
	buf.WriteString(ns.prefix())

	var keyType string
	switch {
	case authCtx != nil && authCtx.TokenId != "":
		keyType = "tokenId"
		buf.WriteString(authCtx.TokenId)
		buf.WriteByte('|')
		buf.WriteString(path)
		buf.WriteByte('|')
		buf.WriteString(method)

	case authCtx == nil:
		keyType = "no-auth"
		buf.WriteString(path)
		buf.WriteByte('|')
		buf.WriteString(method)

	default:
		// Non-nil authCtx without TokenId: include all available identity fields.
		keyType = "identity"
		buf.WriteString(authCtx.AuthType)
		buf.WriteByte('|')
		buf.WriteString(authCtx.Issuer)
		buf.WriteByte('|')
		buf.WriteString(authCtx.Subject)
		buf.WriteByte('|')
		buf.WriteString(authCtx.CredentialID)
		buf.WriteByte('|')
		buf.WriteString(strings.Join(sortedSlice(authCtx.Audience), ","))
		propKeys := make([]string, 0, len(authCtx.Properties))
		for k := range authCtx.Properties {
			propKeys = append(propKeys, k)
		}
		sort.Strings(propKeys)
		for _, k := range propKeys {
			buf.WriteByte('|')
			buf.WriteString(k)
			buf.WriteByte('=')
			buf.WriteString(authCtx.Properties[k])
		}
		if scope := sortedScopeString(authCtx.Scopes); scope != "" {
			buf.WriteByte('|')
			buf.WriteString("scope=")
			buf.WriteString(scope)
		}
		buf.WriteByte('|')
		buf.WriteString(path)
		buf.WriteByte('|')
		buf.WriteString(method)
	}

	appendClaims(&buf, claimPairs)

	sum := sha256.Sum256(buf.Bytes())
	key := fmt.Sprintf("%x", sum)
	slog.Debug("Backend JWT: cache key",
		"keyType", keyType,
		"path", path,
		"method", method,
		"claims", claimPairs,
		"cacheKey", key,
	)
	return key
}

// keyClaims returns the configured claim contributions to fold into the cache key, as a sorted
// slice of "name=value" strings covering the full resolved claim set — static and $ctx: custom
// claims, claimMappings destinations, and non-string custom claims (formatted via fmt). Returns
// nil when no claims are configured, enabling the no-hash fast path. Sorting the assembled pairs
// keeps the key deterministic regardless of map iteration order.
func keyClaims(extras resolvedClaims) []string {
	if len(extras.stringClaims) == 0 && len(extras.rawClaims) == 0 {
		return nil
	}
	pairs := make([]string, 0, len(extras.stringClaims)+len(extras.rawClaims))
	for k, v := range extras.stringClaims {
		pairs = append(pairs, k+"="+v)
	}
	for k, v := range extras.rawClaims {
		pairs = append(pairs, k+"="+fmt.Sprintf("%v", v))
	}
	sort.Strings(pairs)
	return pairs
}

func appendClaims(buf *bytes.Buffer, pairs []string) {
	for _, p := range pairs {
		buf.WriteByte('|')
		buf.WriteString(p)
	}
}

func sortedSlice(s []string) []string {
	out := make([]string, len(s))
	copy(out, s)
	sort.Strings(out)
	return out
}

// sortedScopeString renders the scope set as the JWT "scope" claim: scope names sorted for
// determinism and joined by a single space. Returns "" when there are no scopes.
func sortedScopeString(scopes map[string]bool) string {
	if len(scopes) == 0 {
		return ""
	}
	names := make([]string, 0, len(scopes))
	for s := range scopes {
		names = append(names, s)
	}
	sort.Strings(names)
	return strings.Join(names, " ")
}

// sortedSetKeys returns the keys of a string set as a sorted slice, for deterministic key building.
func sortedSetKeys(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func authTypeLabel(authCtx *policy.AuthContext) string {
	if authCtx == nil {
		return "none"
	}
	return authCtx.AuthType
}

// getCachedToken returns a previously signed token if it exists and has not yet expired. key is
// the complete cache key from buildTokenCacheKey (which already folds in the API namespace and
// token-shaping config). Because the SDK cache never expires entries on its own (ttl=0), expiry
// is enforced here against the token's stored expiresAt: an entry past its safety window is
// deleted and reported as a miss, so an expired token is never served.
func (p *BackendJWTPolicy) getCachedToken(ctx context.Context, key string) (string, bool) {
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
	return v.signed, true
}

// putCachedToken stores a signed token with a TTL of half the token expiry. Caching for half
// the validity means a token served from the cache always retains a safety margin before its
// exp. The minCacheTTL floor widens that window for short-lived tokens, but is applied only
// when it still fits strictly inside the token's lifetime — the cache TTL must never reach or
// exceed tokenExpiry, or the cache could serve a JWT whose exp has already passed.
// key is the complete cache key from buildTokenCacheKey; when the shared cache is full, its LRU
// policy evicts the least-recently-used entry across all APIs to make room.
func (p *BackendJWTPolicy) putCachedToken(ctx context.Context, key, signed string, tokenExpiry time.Duration) {
	tc := p.currentTokenCache()
	if tc == nil {
		return
	}
	ttl := tokenExpiry / 2
	if ttl < minCacheTTL && minCacheTTL < tokenExpiry {
		ttl = minCacheTTL
	}
	_ = tc.Set(ctx, cache.CacheKey{Key: key}, cachedToken{signed: signed, expiresAt: time.Now().Add(ttl)})
}

// extractSigningKeyPEM reads PEM bytes from params["signingKey"].inline or params["signingKey"].path.
// Path-based keys are cached after the first read so that token cache misses under high load do not
// repeatedly hit the filesystem. Key rotation requires a gateway restart.
func (p *BackendJWTPolicy) extractSigningKeyPEM(params map[string]interface{}) ([]byte, error) {
	signingKeyRaw, ok := params["signingKey"]
	if !ok {
		return nil, fmt.Errorf("signingKey is required")
	}
	signingKeyMap, ok := signingKeyRaw.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("signingKey must be an object with 'inline' or 'path'")
	}

	if inlineRaw, ok := signingKeyMap["inline"]; ok {
		inline, ok := inlineRaw.(string)
		if !ok || inline == "" {
			return nil, fmt.Errorf("signingKey.inline must be a non-empty string")
		}
		return []byte(inline), nil
	}

	if pathRaw, ok := signingKeyMap["path"]; ok {
		path, ok := pathRaw.(string)
		if !ok || path == "" {
			return nil, fmt.Errorf("signingKey.path must be a non-empty string")
		}

		if cached, ok := p.pemCache.Load(path); ok {
			return cached.([]byte), nil
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("reading key file %q: %w", path, err)
		}

		p.pemCache.Store(path, data)

		return data, nil
	}

	return nil, fmt.Errorf("signingKey must specify either 'inline' or 'path'")
}

// parsePrivateKey decodes and parses a PEM-encoded RSA or ECDSA private key.
func parsePrivateKey(pemBytes []byte) (crypto.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("no valid PEM block found in signing key")
	}

	switch block.Type {
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(block.Bytes)
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		switch k := key.(type) {
		case *rsa.PrivateKey:
			return k, nil
		case *ecdsa.PrivateKey:
			return k, nil
		default:
			return nil, fmt.Errorf("unsupported PKCS8 key type: %T", key)
		}
	default:
		return nil, fmt.Errorf("unsupported PEM block type %q; expected RSA PRIVATE KEY, EC PRIVATE KEY, or PRIVATE KEY", block.Type)
	}
}

// checkKeyType verifies that key matches the type required by the given algorithm.
func checkKeyType(key crypto.PrivateKey, keyType, algorithm string) error {
	switch keyType {
	case "rsa":
		if _, ok := key.(*rsa.PrivateKey); !ok {
			return fmt.Errorf("%s requires an RSA private key, got %T", algorithm, key)
		}
	case "ecdsa":
		if _, ok := key.(*ecdsa.PrivateKey); !ok {
			return fmt.Errorf("%s requires an ECDSA private key, got %T", algorithm, key)
		}
	}
	return nil
}

// algorithmList returns a sorted, comma-separated list of supported algorithm names.
func algorithmList() string {
	names := make([]string, 0, len(algorithms))
	for k := range algorithms {
		names = append(names, k)
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
}

func getString(params map[string]interface{}, key, defaultVal string) string {
	if v, ok := params[key]; ok {
		if s, ok := v.(string); ok && s != "" {
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

// objectParam returns params[key] as a map[string]interface{}, or nil when the key is absent or
// not an object. Ranging over the nil result is a no-op, so callers need no separate presence check.
func objectParam(params map[string]interface{}, key string) map[string]interface{} {
	if raw, ok := params[key]; ok {
		if m, ok := raw.(map[string]interface{}); ok {
			return m
		}
	}
	return nil
}

// getStringSet reads a string-array param into a lookup set. Non-string
// elements are skipped. Returns an empty (non-nil) set when absent.
func getStringSet(params map[string]interface{}, key string) map[string]bool {
	out := make(map[string]bool)
	if raw, ok := params[key]; ok {
		if arr, ok := raw.([]interface{}); ok {
			for _, e := range arr {
				if s, ok := e.(string); ok && s != "" {
					out[s] = true
				}
			}
		}
	}
	return out
}


func parseDuration(s string, fallback time.Duration) time.Duration {
	if s == "" {
		return fallback
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return fallback
	}
	return d
}

const ctxPrefix = "$ctx:"

// resolveClaimValue returns the value to use for a custom JWT claim.
// Values prefixed with "$ctx:" are resolved from the request context at runtime.
// Returns ("", false) when a context variable cannot be resolved — the caller
// silently skips the claim rather than treating it as an error.
func resolveClaimValue(value string, reqCtx *policy.RequestHeaderContext) (string, bool) {
	if !strings.HasPrefix(value, ctxPrefix) {
		return value, true
	}
	ref := strings.TrimPrefix(value, ctxPrefix)
	variable := strings.ToLower(ref)

	switch {
	case variable == "request.path":
		return reqCtx.Path, true
	case variable == "request.method":
		return reqCtx.Method, true
	case variable == "request.authority":
		return reqCtx.Authority, true
	case variable == "request.scheme":
		return reqCtx.Scheme, true
	case strings.HasPrefix(variable, "request.header."):
		name := strings.TrimPrefix(variable, "request.header.")
		vals := getDownstreamHeaders(reqCtx.Downstream, reqCtx.Headers).Get(name)
		if len(vals) == 0 {
			return "", false
		}
		return vals[0], true
	case variable == "api.id":
		return reqCtx.APIId, true
	case variable == "api.name":
		return reqCtx.APIName, true
	case variable == "api.version":
		return reqCtx.APIVersion, true
	case variable == "api.context":
		return reqCtx.APIContext, true
	case variable == "auth.subject":
		if reqCtx.SharedContext.AuthContext == nil {
			return "", false
		}
		return reqCtx.SharedContext.AuthContext.Subject, true
	case variable == "auth.type":
		if reqCtx.SharedContext.AuthContext == nil {
			return "", false
		}
		return reqCtx.SharedContext.AuthContext.AuthType, true
	case variable == "auth.credential_id":
		if reqCtx.SharedContext.AuthContext == nil {
			return "", false
		}
		return reqCtx.SharedContext.AuthContext.CredentialID, true
	case strings.HasPrefix(variable, "auth.property."):
		if reqCtx.SharedContext.AuthContext == nil {
			return "", false
		}
		// Use the original (non-lowercased) suffix — Properties keys are case-sensitive.
		key := ref[len("auth.property."):]
		val, ok := reqCtx.SharedContext.AuthContext.Properties[key]
		return val, ok
	default:
		return "", false
	}
}

func internalError() policy.ImmediateResponse {
	return policy.ImmediateResponse{
		StatusCode: 500,
		Headers:    map[string]string{"content-type": "application/json"},
		Body:       []byte(`{"error":"Internal Server Error"}`),
	}
}
