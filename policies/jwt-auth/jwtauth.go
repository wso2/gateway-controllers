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
	"bytes"
	"context"
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
	"github.com/wso2/api-platform/sdk/core/utils/cache"
)

const (
	AuthType = "jwt"

	// defaultTokenCacheMaxSize bounds the total number of cached verdicts (positive and
	// negative) across all APIs. The SDK cache fixes its size at construction, so a changed
	// cacheMaxSize is applied by rebuilding the cache (see ensureTokenCache).
	defaultTokenCacheMaxSize = 100_000

	// defaultTokenCacheTtl caps how long a successfully verified token is trusted from cache,
	// bounding the revocation/staleness window (see cachedVerdict).
	defaultTokenCacheTtl = 5 * time.Minute

	// defaultNegativeCacheTtl caps how long a deterministic verification failure (expired or
	// malformed token) is served from cache without re-verification. Kept short since it is
	// purely a DoS/retry-absorption optimization.
	defaultNegativeCacheTtl = 30 * time.Second
)

// errTokenExpired is returned by validateTokenWithSignature's exp check so callers can
// distinguish it, via errors.Is, from other verification failures: an expired token can never
// become valid again, so (unlike e.g. a JWKS fetch error or a not-yet-valid nbf) it is safe to
// negatively cache.
var errTokenExpired = errors.New("token expired")

// standardJWTClaims lists registered JWT claim names (RFC 7519) and common OAuth2 claims.
// These are represented as typed fields on AuthContext and excluded from Properties.
var standardJWTClaims = map[string]bool{
	"iss": true, "sub": true, "aud": true,
	"exp": true, "nbf": true, "iat": true, "jti": true,
	"scope": true, "scp": true,
}

// supportedAlgorithms is the fixed, code-enforced allowlist. Asymmetric only.
// HMAC, none, EdDSA, and any other algorithm are rejected unconditionally.
var supportedAlgorithms = []string{"RS256", "PS256", "ES256"}

// defaultScopeClaimSeparator is the separator applied to a string-valued scope claim when a
// key manager configures a ScopeClaim without an explicit ScopeClaimSeparator.
const defaultScopeClaimSeparator = " "

// signatureKeyFunc returns a jwt.Keyfunc that binds the token's signing method to the
// actual key type. An RSA key may only verify RSA/PSS tokens; an EC key may only verify
// ECDSA tokens. Any mismatch — including HMAC-confusion attacks — is rejected.
func signatureKeyFunc(pubKey crypto.PublicKey) jwt.Keyfunc {
	return func(token *jwt.Token) (interface{}, error) {
		switch pubKey.(type) {
		case *rsa.PublicKey:
			switch token.Method.(type) {
			case *jwt.SigningMethodRSA, *jwt.SigningMethodRSAPSS:
				return pubKey, nil
			}
		case *ecdsa.PublicKey:
			if _, ok := token.Method.(*jwt.SigningMethodECDSA); ok {
				return pubKey, nil
			}
		}
		return nil, fmt.Errorf("signing method %q not permitted for key type %T", token.Header["alg"], pubKey)
	}
}

// JwtAuthPolicy implements JWT Authentication with JWKS support
type JwtAuthPolicy struct {
	cacheMutex sync.RWMutex
	cacheStore map[string]*CachedJWKS
	cacheTTLs  map[string]time.Time
	httpClient *http.Client

	// tokenCacheMu guards the tokenCache pointer and tokenCacheSize. The SDK cache fixes its
	// size at construction (no live resize), so a changed cacheMaxSize is applied by swapping
	// in a new cache. Reads take the RLock and copy the pointer so an in-flight request keeps
	// using a consistent cache even if a concurrent deployment rebuilds it.
	tokenCacheMu   sync.RWMutex
	tokenCache     *cache.InMemoryCache[cachedVerdict] // shared verdict cache for all APIs; globally bounded by cacheMaxSize
	tokenCacheSize int
}

// CachedJWKS stores cached JWKS data
type CachedJWKS struct {
	Keys map[string]crypto.PublicKey
}

// cachedVerdict stores the outcome of a signature verification, keyed by a hash of the
// verification config and the raw token (see buildTokenCacheKey). ok=true is a successful
// verification (claims holds the verified claim set); ok=false is a deterministic, permanently
// invalid failure (expired or malformed token only — see errTokenExpired) that is safe to
// short-circuit on repeat presentation. expiresAt is enforced on read (see getCachedVerdict)
// since the SDK cache itself is created with ttl=0.

// scopes contains resolved token scopes, cached with claims so both cache-hit and cache-miss paths enforce
// scopes and populate AuthContext.Scopes consistently without re-running verification.
type cachedVerdict struct {
	ok     bool
	claims jwt.MapClaims
	scopes    []string
	reason    string
	expiresAt time.Time
}

// KeyManager represents a key manager with either remote JWKS or local certificate
type KeyManager struct {
	Name   string      // Unique name for this key manager
	Issuer string      // Optional issuer value
	JWKS   *JWKSConfig // JWKS configuration (remote and/or local)
	ScopeClaim string // Token claim used to read scopes; if unset, falls back to the legacy "scope" and "scp" claims.
	ScopeClaimSeparator string // Separator for string-valued ScopeClaim; defaults to a space and is ignored for array claims.
}

// JWKSConfig holds both remote and local key configurations
type JWKSConfig struct {
	Remote *RemoteJWKS // Remote JWKS endpoint configuration
	Local  *LocalCert  // Local certificate configuration
}

// RemoteJWKS holds remote JWKS endpoint configuration
type RemoteJWKS struct {
	URI             string      // JWKS endpoint URL
	CertificatePath string      // Optional CA certificate path for self-signed endpoints
	SkipTlsVerify   bool        // Skip TLS certificate verification (use with caution)
	tlsConfig       *tls.Config // Cached TLS config for this endpoint
}

// LocalCert holds local certificate configuration
type LocalCert struct {
	Inline          string           // Inline PEM-encoded certificate
	CertificatePath string           // Path to certificate file
	PublicKey       crypto.PublicKey // Parsed public key (RSA or ECDSA)
}

// JWKSKeySet represents the JWKS response from server
type JWKSKeySet struct {
	Keys []JWKSKey `json:"keys"`
}

// JWKSKey represents a single key in JWKS
type JWKSKey struct {
	Kty string `json:"kty"` // Key type (RSA, EC, etc.)
	Use string `json:"use"` // Public key use
	Kid string `json:"kid"` // Key ID
	N   string `json:"n"`   // RSA modulus
	E   string `json:"e"`   // RSA exponent
	Alg string `json:"alg"` // Algorithm
	Crv string `json:"crv"` // EC curve name (P-256, P-384, P-521)
	X   string `json:"x"`   // EC x coordinate (base64url)
	Y   string `json:"y"`   // EC y coordinate (base64url)
}

var ins = &JwtAuthPolicy{
	cacheStore: make(map[string]*CachedJWKS),
	cacheTTLs:  make(map[string]time.Time),
	httpClient: &http.Client{
		Timeout: 5 * time.Second,
	},
	tokenCache:     newTokenCache(defaultTokenCacheMaxSize),
	tokenCacheSize: defaultTokenCacheMaxSize,
}

// newTokenCache builds the shared verdict cache, globally bounded by maxSize across all APIs.
// ttl is 0 because expiry is enforced per entry in getCachedVerdict; once full, the cache's LRU
// policy evicts the least-recently-used entry across all APIs, enforcing a single global bound.
func newTokenCache(maxSize int) *cache.InMemoryCache[cachedVerdict] {
	return cache.NewInMemoryCache[cachedVerdict]("jwt-auth-validated-tokens", maxSize, 0, cache.LRUEvictionPolicy, slog.Default())
}

// ensureTokenCache (re)builds the shared token cache when the configured global size changes.
// The SDK cache fixes its size at construction (there is no live resize), so applying a new
// cacheMaxSize means replacing the cache, which flushes all entries. This happens only on the
// first deployment or a genuine cacheMaxSize change — steady-state redeploys leave it untouched.
func (p *JwtAuthPolicy) ensureTokenCache(maxSize int) {
	p.tokenCacheMu.RLock()
	if p.tokenCache != nil && p.tokenCacheSize == maxSize {
		p.tokenCacheMu.RUnlock()
		return
	}
	p.tokenCacheMu.RUnlock()

	p.tokenCacheMu.Lock()
	defer p.tokenCacheMu.Unlock()
	if p.tokenCache != nil && p.tokenCacheSize == maxSize {
		return
	}
	slog.Debug("JWT Auth Policy: Rebuilding token verdict cache due to cacheMaxSize change, all cached verdicts flushed",
		"previousMaxSize", p.tokenCacheSize,
		"newMaxSize", maxSize,
	)
	p.tokenCache = newTokenCache(maxSize)
	p.tokenCacheSize = maxSize
}

// currentTokenCache returns the live token cache pointer under the read lock, so callers operate
// on a consistent instance even if a concurrent deployment rebuilds the cache.
func (p *JwtAuthPolicy) currentTokenCache() *cache.InMemoryCache[cachedVerdict] {
	p.tokenCacheMu.RLock()
	defer p.tokenCacheMu.RUnlock()
	return p.tokenCache
}

// getCachedVerdict returns a previously cached verification verdict (positive or negative) if it
// exists and has not yet expired. Because the SDK cache never expires entries on its own
// (ttl=0), expiry is enforced here against the verdict's stored expiresAt: an entry past its
// window is deleted and reported as a miss.
func (p *JwtAuthPolicy) getCachedVerdict(ctx context.Context, key string) (cachedVerdict, bool) {
	tc := p.currentTokenCache()
	if tc == nil {
		return cachedVerdict{}, false
	}
	cacheKey := cache.CacheKey{Key: key}
	v, ok := tc.Get(ctx, cacheKey)
	if !ok {
		return cachedVerdict{}, false
	}
	if !time.Now().Before(v.expiresAt) {
		slog.Debug("JWT Auth Policy: Cached verdict found but expired, evicting",
			"cacheKey", key,
			"expiresAt", v.expiresAt,
		)
		_ = tc.Delete(ctx, cacheKey)
		return cachedVerdict{}, false
	}
	return v, true
}

// putVerdict stores a verification verdict (positive or negative) under key. When the shared
// cache is full, its LRU policy evicts the least-recently-used entry across all APIs to make room.
func (p *JwtAuthPolicy) putVerdict(ctx context.Context, key string, verdict cachedVerdict) {
	tc := p.currentTokenCache()
	if tc == nil {
		return
	}
	_ = tc.Set(ctx, cache.CacheKey{Key: key}, verdict)
}

// buildTokenCacheKey returns a cache key that is a complete function of the verification
// verdict: fingerprint folds in everything that determines the verdict but is not part of the
// token itself (API identity plus verification config), and the token supplies the rest. The
// token is hashed (never stored or logged raw) to keep the bearer secret out of cache keys and
// bound key length.
func buildTokenCacheKey(fingerprint, token string) string {
	sum := sha256.Sum256([]byte(fingerprint + "\x00" + token))
	return fmt.Sprintf("%x", sum)
}

// tokenConfigFingerprint renders the token-shaping/verification configuration as a deterministic
// string. apiId/apiName isolate the shared singleton cache per API even when two APIs would
// otherwise see identical tokens. keyManagersRaw is JSON-marshalled as configured (not the
// parsed/expensive form), so computing the fingerprint never requires cert/TLS parsing — that
// parsing happens only on a cache miss. A redeploy that changes any of these fields yields a
// different fingerprint (a cache miss), so a token is never trusted under stale config.
func tokenConfigFingerprint(apiId, apiName string, keyManagersRaw interface{}, validateIssuer bool, issuers []string, leeway time.Duration) string {
	kmBytes, err := json.Marshal(keyManagersRaw)
	if err != nil {
		// Should not happen for values decoded from JSON config, but never let a marshal
		// failure silently collapse the fingerprint to a shared/colliding key.
		kmBytes = []byte(fmt.Sprintf("%v", keyManagersRaw))
	}
	var buf bytes.Buffer
	buf.WriteString(apiId)
	buf.WriteByte('|')
	buf.WriteString(apiName)
	buf.WriteByte('|')
	buf.Write(kmBytes)
	buf.WriteByte('|')
	buf.WriteString(strconv.FormatBool(validateIssuer))
	buf.WriteByte('|')
	buf.WriteString(strings.Join(issuers, ","))
	buf.WriteByte('|')
	buf.WriteString(leeway.String())
	return buf.String()
}

// GetPolicy is the v1alpha2 factory entry point (loaded by v1alpha2 kernels). It applies the
// global cacheMaxSize from systemParameters to the shared verdict cache. Redeploy invalidation
// of individual entries is handled implicitly by the cache key (see tokenConfigFingerprint); a
// changed cacheMaxSize additionally rebuilds the whole cache (see ensureTokenCache).
func GetPolicy(
	metadata policy.PolicyMetadata,
	params map[string]interface{},
) (policy.Policy, error) {
	maxSize := getIntParam(params, "cacheMaxSize", defaultTokenCacheMaxSize)
	if maxSize <= 0 {
		maxSize = defaultTokenCacheMaxSize
	}
	ins.ensureTokenCache(maxSize)
	logDeprecatedParamUsage(params)
	return ins, nil
}

func (p *JwtAuthPolicy) Mode() policy.ProcessingMode {
	return policy.ProcessingMode{
		RequestHeaderMode:  policy.HeaderModeProcess,
		RequestBodyMode:    policy.BodyModeSkip,
		ResponseHeaderMode: policy.HeaderModeSkip,
		ResponseBodyMode:   policy.BodyModeSkip,
	}
}

// validateTokenWithSignature validates JWT signature using JWKS
func (p *JwtAuthPolicy) validateTokenWithSignature(tokenString string, unverifiedToken *jwt.Token,
	keyManagers map[string]*KeyManager, userIssuers []string, validateIssuer bool,
	leeway time.Duration, cacheTTL time.Duration, fetchTimeout time.Duration, retryCount int, retryInterval time.Duration) (jwt.MapClaims, *KeyManager, error) {

	slog.Debug("JWT Auth Policy: Starting token signature validation",
		"keyManagersCount", len(keyManagers),
		"userIssuersCount", len(userIssuers),
		"validateIssuer", validateIssuer,
	)

	unverifiedClaims, ok := unverifiedToken.Claims.(jwt.MapClaims)
	if !ok {
		slog.Debug("JWT Auth Policy: Invalid token claims format")
		return nil, nil, fmt.Errorf("invalid token claims format")
	}

	// Validate exp and nbf with leeway
	now := time.Now()
	if exp, ok := unverifiedClaims["exp"].(float64); ok {
		expTime := time.Unix(int64(exp), 0)
		slog.Debug("JWT Auth Policy: Checking token expiration",
			"expTime", expTime,
			"now", now,
			"leeway", leeway,
		)
		if now.After(expTime.Add(leeway)) {
			slog.Debug("JWT Auth Policy: Token has expired",
				"expTime", expTime,
				"now", now,
			)
			return nil, nil, errTokenExpired
		}
		slog.Debug("JWT Auth Policy: Token expiration check passed")
	} else {
		slog.Debug("JWT Auth Policy: No 'exp' claim found in token")
	}

	if nbf, ok := unverifiedClaims["nbf"].(float64); ok {
		nbfTime := time.Unix(int64(nbf), 0)
		slog.Debug("JWT Auth Policy: Checking token not-before time",
			"nbfTime", nbfTime,
			"now", now,
			"leeway", leeway,
		)
		if now.Before(nbfTime.Add(-leeway)) {
			slog.Debug("JWT Auth Policy: Token not yet valid",
				"nbfTime", nbfTime,
				"now", now,
			)
			return nil, nil, fmt.Errorf("token not yet valid")
		}
		slog.Debug("JWT Auth Policy: Token not-before check passed")
	} else {
		slog.Debug("JWT Auth Policy: No 'nbf' claim found in token")
	}

	// Get issuer from token
	tokenIssuer := getString(unverifiedClaims["iss"])
	slog.Debug("JWT Auth Policy: Token issuer",
		"issuer", tokenIssuer,
	)

	// Determine which key managers to use
	var applicableKeyManagers []*KeyManager
	if len(userIssuers) > 0 {
		// User specified issuers - these could be actual issuer values or key manager names.
		// Keep all compatible candidates in user-provided order for fallback verification.
		slog.Debug("JWT Auth Policy: User-specified issuers provided",
			"userIssuers", userIssuers,
			"tokenIssuer", tokenIssuer,
		)

		seenKeyManagers := make(map[string]struct{})
		for _, userIssuer := range userIssuers {
			// 1) Treat as key manager name.
			if km, ok := keyManagers[userIssuer]; ok {
				if km.Issuer == "" || km.Issuer == tokenIssuer {
					if _, seen := seenKeyManagers[km.Name]; !seen {
						applicableKeyManagers = append(applicableKeyManagers, km)
						seenKeyManagers[km.Name] = struct{}{}
					}
					slog.Debug("JWT Auth Policy: Added key manager candidate by name",
						"keyManager", km.Name,
						"userIssuer", userIssuer,
						"tokenIssuer", tokenIssuer,
						"kmIssuer", km.Issuer,
					)
				} else {
					slog.Debug("JWT Auth Policy: Key manager found by name but issuer mismatch",
						"keyManager", km.Name,
						"userIssuer", userIssuer,
						"tokenIssuer", tokenIssuer,
						"expectedIssuer", km.Issuer,
					)
				}
			}

			// 2) Treat as actual issuer value.
			if tokenIssuer == userIssuer {
				for _, km := range keyManagers {
					if km.Issuer == userIssuer {
						if _, seen := seenKeyManagers[km.Name]; seen {
							continue
						}
						applicableKeyManagers = append(applicableKeyManagers, km)
						seenKeyManagers[km.Name] = struct{}{}
						slog.Debug("JWT Auth Policy: Added key manager candidate by issuer value",
							"keyManager", km.Name,
							"issuer", userIssuer,
						)
					}
				}
			}
		}

		// If still no applicable key managers found, reject the token
		if len(applicableKeyManagers) == 0 {
			slog.Debug("JWT Auth Policy: No matching key manager found for user-specified issuers",
				"tokenIssuer", tokenIssuer,
				"userIssuers", userIssuers,
			)
			return nil, nil, fmt.Errorf("token issuer '%s' does not match any configured issuer or key manager", tokenIssuer)
		}
	} else if tokenIssuer != "" {
		// No user issuers specified, but token has issuer claim
		slog.Debug("JWT Auth Policy: Matching token issuer to key managers",
			"tokenIssuer", tokenIssuer,
			"validateIssuer", validateIssuer,
		)
		for _, km := range keyManagers {
			if km.Issuer == tokenIssuer {
				applicableKeyManagers = append(applicableKeyManagers, km)
				slog.Debug("JWT Auth Policy: Found matching key manager by issuer",
					"keyManager", km.Name,
					"issuer", km.Issuer,
				)
				break
			}
		}

		// If no issuer match found
		if len(applicableKeyManagers) == 0 {
			if validateIssuer {
				// Strict mode: reject if token issuer doesn't match any key manager unless wildcard key managers exist
				for _, km := range keyManagers {
					if km.Issuer == "" {
						applicableKeyManagers = append(applicableKeyManagers, km)
					}
				}
				if len(applicableKeyManagers) == 0 {
					slog.Debug("JWT Auth Policy: No key manager found for token issuer (validateIssuer=true)",
						"tokenIssuer", tokenIssuer,
					)
					return nil, nil, fmt.Errorf("no key manager configured for token issuer '%s'", tokenIssuer)
				}
				slog.Debug("JWT Auth Policy: Using key managers without issuer for token validation",
					"tokenIssuer", tokenIssuer,
					"count", len(applicableKeyManagers),
				)
			} else {
				// Lenient mode: try all key managers
				slog.Debug("JWT Auth Policy: No issuer match found, using all key managers (validateIssuer=false)")
				for _, km := range keyManagers {
					applicableKeyManagers = append(applicableKeyManagers, km)
				}
			}
		}
	} else {
		// No issuer in token
		if validateIssuer {
			slog.Debug("JWT Auth Policy: Token has no issuer claim (validateIssuer=true)")
			return nil, nil, fmt.Errorf("token does not contain an issuer claim")
		}
		// Lenient mode: try all key managers
		slog.Debug("JWT Auth Policy: No issuer in token, using all key managers (validateIssuer=false)")
		for _, km := range keyManagers {
			applicableKeyManagers = append(applicableKeyManagers, km)
		}
	}

	slog.Debug("JWT Auth Policy: Applicable key managers determined",
		"count", len(applicableKeyManagers),
	)

	// Get kid from token header
	kid, ok := unverifiedToken.Header["kid"].(string)
	if !ok {
		// Kid is optional for certificate-based validation
		kid = ""
		slog.Debug("JWT Auth Policy: No 'kid' found in token header")
	} else {
		slog.Debug("JWT Auth Policy: Token key ID found",
			"kid", kid,
		)
	}

	parser := jwt.NewParser(jwt.WithLeeway(leeway), jwt.WithValidMethods(supportedAlgorithms))

	// Try to verify signature with applicable key managers
	var lastErr error
	for _, km := range applicableKeyManagers {
		slog.Debug("JWT Auth Policy: Attempting signature verification with key manager",
			"keyManager", km.Name,
			"issuer", km.Issuer,
		)

		if km.JWKS == nil {
			slog.Debug("JWT Auth Policy: Key manager has no JWKS configuration, skipping",
				"keyManager", km.Name,
			)
			continue
		}

		// Try local certificate validation first if available
		if km.JWKS.Local != nil && km.JWKS.Local.PublicKey != nil {
			slog.Debug("JWT Auth Policy: Attempting signature verification with local certificate",
				"keyManager", km.Name,
			)
			verifiedToken, err := parser.ParseWithClaims(tokenString, jwt.MapClaims{}, signatureKeyFunc(km.JWKS.Local.PublicKey))

			if err == nil {
				// Signature verified successfully with local certificate
				slog.Debug("JWT Auth Policy: Signature verified successfully with local certificate",
					"keyManager", km.Name,
				)
				if claims, ok := verifiedToken.Claims.(jwt.MapClaims); ok {
					return claims, km, nil
				}
			}
			slog.Debug("JWT Auth Policy: Signature verification failed with local certificate",
				"keyManager", km.Name,
				"error", err,
			)
			lastErr = fmt.Errorf("signature verification failed with local certificate: %w", err)
			continue
		}

		// Fall back to remote JWKS-based validation
		if km.JWKS.Remote != nil {
			slog.Debug("JWT Auth Policy: Attempting signature verification with remote JWKS",
				"keyManager", km.Name,
				"jwksUri", km.JWKS.Remote.URI,
			)
			// Get JWKS with retry logic
			jwks, err := p.fetchJWKSWithRetry(km.JWKS.Remote, cacheTTL, fetchTimeout, retryCount, retryInterval)
			if err != nil {
				slog.Debug("JWT Auth Policy: Failed to fetch JWKS",
					"keyManager", km.Name,
					"jwksUri", km.JWKS.Remote.URI,
					"error", err,
				)
				lastErr = fmt.Errorf("failed to fetch JWKS from %s: %w", km.JWKS.Remote.URI, err)
				continue
			}

			slog.Debug("JWT Auth Policy: JWKS fetched successfully",
				"keyManager", km.Name,
				"keysCount", len(jwks.Keys),
			)

			// If kid is present, find the key with matching kid
			if kid != "" {
				slog.Debug("JWT Auth Policy: Looking for key with matching kid",
					"kid", kid,
				)
				publicKey, ok := jwks.Keys[kid]
				if !ok {
					slog.Debug("JWT Auth Policy: Key ID not found in JWKS",
						"kid", kid,
						"availableKids", getKeyIds(jwks.Keys),
					)
					lastErr = fmt.Errorf("key id '%s' not found in JWKS from %s", kid, km.JWKS.Remote.URI)
					continue
				}

				slog.Debug("JWT Auth Policy: Found key with matching kid, verifying signature",
					"kid", kid,
				)
				// Verify signature
				verifiedToken, err := parser.ParseWithClaims(tokenString, jwt.MapClaims{}, signatureKeyFunc(publicKey))

				if err != nil {
					slog.Debug("JWT Auth Policy: Signature verification failed",
						"kid", kid,
						"error", err,
					)
					lastErr = fmt.Errorf("signature verification failed: %w", err)
					continue
				}

				// Signature verified successfully
				slog.Debug("JWT Auth Policy: Signature verified successfully with kid",
					"kid", kid,
					"keyManager", km.Name,
				)
				if claims, ok := verifiedToken.Claims.(jwt.MapClaims); ok {
					return claims, km, nil
				}
			} else {
				// No kid, try all keys in JWKS
				slog.Debug("JWT Auth Policy: No kid in token, trying all keys in JWKS",
					"keysCount", len(jwks.Keys),
				)
				for keyId, publicKey := range jwks.Keys {
					slog.Debug("JWT Auth Policy: Trying key from JWKS",
						"keyId", keyId,
					)
					verifiedToken, err := parser.ParseWithClaims(tokenString, jwt.MapClaims{}, signatureKeyFunc(publicKey))

					if err == nil {
						// Signature verified successfully
						slog.Debug("JWT Auth Policy: Signature verified successfully",
							"keyId", keyId,
							"keyManager", km.Name,
						)
						if claims, ok := verifiedToken.Claims.(jwt.MapClaims); ok {
							return claims, km, nil
						}
					} else {
						slog.Debug("JWT Auth Policy: Signature verification failed with key",
							"keyId", keyId,
							"error", err,
						)
					}
				}
				lastErr = fmt.Errorf("token signature verification failed with all keys from %s", km.JWKS.Remote.URI)
				slog.Debug("JWT Auth Policy: Failed to verify signature with any key from JWKS",
					"keyManager", km.Name,
				)
			}
		}
	}

	// If no key manager succeeded
	if lastErr != nil {
		slog.Debug("JWT Auth Policy: All key managers failed to verify signature",
			"lastError", lastErr,
		)
		return nil, nil, lastErr
	}
	slog.Debug("JWT Auth Policy: Unable to verify token signature with any available key manager")
	return nil, nil, fmt.Errorf("unable to verify token signature with available key managers")
}

// fetchJWKSWithRetry fetches JWKS with caching and retry logic
func (p *JwtAuthPolicy) fetchJWKSWithRetry(remote *RemoteJWKS, cacheTTL time.Duration, fetchTimeout time.Duration, retryCount int, retryInterval time.Duration) (*CachedJWKS, error) {
	slog.Debug("JWT Auth Policy: fetchJWKSWithRetry called",
		"uri", remote.URI,
		"cacheTTL", cacheTTL,
		"fetchTimeout", fetchTimeout,
		"retryCount", retryCount,
		"retryInterval", retryInterval,
	)

	if retryCount < 0 {
		return nil, fmt.Errorf("invalid jwks fetch retry count: %d", retryCount)
	}

	// Check cache first
	p.cacheMutex.RLock()
	if cached, ok := p.cacheStore[remote.URI]; ok {
		if ttl, ok := p.cacheTTLs[remote.URI]; ok && time.Now().Before(ttl) {
			p.cacheMutex.RUnlock()
			slog.Debug("JWT Auth Policy: JWKS cache hit",
				"uri", remote.URI,
				"cacheExpiry", ttl,
				"keysCount", len(cached.Keys),
			)
			return cached, nil
		}
		slog.Debug("JWT Auth Policy: JWKS cache expired",
			"uri", remote.URI,
		)
	} else {
		slog.Debug("JWT Auth Policy: JWKS not in cache",
			"uri", remote.URI,
		)
	}
	p.cacheMutex.RUnlock()

	// Not in cache or expired, fetch from server
	var lastErr error
	for attempt := 0; attempt <= retryCount; attempt++ {
		slog.Debug("JWT Auth Policy: Fetching JWKS from server",
			"uri", remote.URI,
			"attempt", attempt+1,
			"maxAttempts", retryCount+1,
		)
		jwks, err := p.fetchJWKS(remote, fetchTimeout)
		if err == nil {
			// Cache the result
			p.cacheMutex.Lock()
			p.cacheStore[remote.URI] = jwks
			p.cacheTTLs[remote.URI] = time.Now().Add(cacheTTL)
			p.cacheMutex.Unlock()
			slog.Debug("JWT Auth Policy: JWKS fetched and cached successfully",
				"uri", remote.URI,
				"keysCount", len(jwks.Keys),
				"cacheExpiry", time.Now().Add(cacheTTL),
			)
			return jwks, nil
		}

		slog.Debug("JWT Auth Policy: JWKS fetch attempt failed",
			"uri", remote.URI,
			"attempt", attempt+1,
			"error", err,
		)
		lastErr = err
		if attempt < retryCount {
			slog.Debug("JWT Auth Policy: Waiting before retry",
				"retryInterval", retryInterval,
			)
			time.Sleep(retryInterval)
		}
	}

	slog.Debug("JWT Auth Policy: All JWKS fetch attempts failed",
		"uri", remote.URI,
		"lastError", lastErr,
	)
	if lastErr == nil {
		return nil, fmt.Errorf("failed to fetch JWKS: no fetch attempts executed")
	}
	return nil, lastErr
}

// fetchJWKS fetches JWKS from the given remote configuration
func (p *JwtAuthPolicy) fetchJWKS(remote *RemoteJWKS, fetchTimeout time.Duration) (*CachedJWKS, error) {
	slog.Debug("JWT Auth Policy: fetchJWKS called",
		"uri", remote.URI,
		"timeout", fetchTimeout,
		"hasTlsConfig", remote.tlsConfig != nil,
	)

	// Create a new HTTP client per request to avoid race conditions on shared state
	var client *http.Client
	if remote.tlsConfig != nil {
		// Create a new client with custom TLS config
		slog.Debug("JWT Auth Policy: Creating HTTP client with custom TLS config",
			"uri", remote.URI,
		)
		customTransport := &http.Transport{
			TLSClientConfig: remote.tlsConfig,
		}
		client = &http.Client{
			Transport: customTransport,
			Timeout:   fetchTimeout,
		}
	} else {
		// Create a new client with default transport
		slog.Debug("JWT Auth Policy: Creating HTTP client with default transport",
			"uri", remote.URI,
		)
		client = &http.Client{
			Timeout: fetchTimeout,
		}
	}

	slog.Debug("JWT Auth Policy: Sending HTTP GET request to JWKS endpoint",
		"uri", remote.URI,
	)
	resp, err := client.Get(remote.URI)
	if err != nil {
		slog.Debug("JWT Auth Policy: HTTP request to JWKS endpoint failed",
			"uri", remote.URI,
			"error", err,
		)
		return nil, fmt.Errorf("failed to fetch JWKS: %w", err)
	}
	defer resp.Body.Close()

	slog.Debug("JWT Auth Policy: JWKS endpoint response received",
		"uri", remote.URI,
		"statusCode", resp.StatusCode,
	)

	if resp.StatusCode != http.StatusOK {
		slog.Debug("JWT Auth Policy: JWKS endpoint returned non-OK status",
			"uri", remote.URI,
			"statusCode", resp.StatusCode,
		)
		return nil, fmt.Errorf("JWKS endpoint returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		slog.Debug("JWT Auth Policy: Failed to read JWKS response body",
			"uri", remote.URI,
			"error", err,
		)
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	slog.Debug("JWT Auth Policy: JWKS response body read successfully",
		"uri", remote.URI,
		"bodyLength", len(body),
	)

	var keySet JWKSKeySet
	if err := json.Unmarshal(body, &keySet); err != nil {
		slog.Debug("JWT Auth Policy: Failed to parse JWKS JSON",
			"uri", remote.URI,
			"error", err,
		)
		return nil, fmt.Errorf("failed to parse JWKS: %w", err)
	}

	slog.Debug("JWT Auth Policy: JWKS JSON parsed successfully",
		"uri", remote.URI,
		"keysInResponse", len(keySet.Keys),
	)

	// Convert JWKS keys to public keys (RSA and EC supported)
	cachedJWKS := &CachedJWKS{
		Keys: make(map[string]crypto.PublicKey),
	}

	for _, key := range keySet.Keys {
		slog.Debug("JWT Auth Policy: Processing JWKS key",
			"kid", key.Kid,
			"kty", key.Kty,
			"alg", key.Alg,
			"use", key.Use,
		)
		if key.Kid == "" {
			slog.Debug("JWT Auth Policy: Skipping key without kid")
			continue // Skip keys without kid
		}

		if key.Kty == "RSA" {
			// Parse RSA public key from N and E
			publicKey, err := parseRSAPublicKey(key.N, key.E)
			if err != nil {
				slog.Debug("JWT Auth Policy: Failed to parse RSA public key",
					"kid", key.Kid,
					"error", err,
				)
				continue // Skip invalid keys
			}
			cachedJWKS.Keys[key.Kid] = publicKey
			slog.Debug("JWT Auth Policy: RSA public key parsed successfully",
				"kid", key.Kid,
			)
		} else if key.Kty == "EC" {
			// Parse EC public key from Crv, X, Y
			publicKey, err := parseECPublicKey(key.Crv, key.X, key.Y)
			if err != nil {
				slog.Debug("JWT Auth Policy: Failed to parse EC public key",
					"kid", key.Kid,
					"crv", key.Crv,
					"error", err,
				)
				continue // Skip invalid keys
			}
			cachedJWKS.Keys[key.Kid] = publicKey
			slog.Debug("JWT Auth Policy: EC public key parsed successfully",
				"kid", key.Kid,
				"crv", key.Crv,
			)
		} else {
			slog.Debug("JWT Auth Policy: Skipping key with unsupported kty",
				"kid", key.Kid,
				"kty", key.Kty,
			)
		}
	}

	if len(cachedJWKS.Keys) == 0 {
		slog.Debug("JWT Auth Policy: No valid public keys found in JWKS",
			"uri", remote.URI,
		)
		return nil, fmt.Errorf("no valid public keys found in JWKS")
	}

	slog.Debug("JWT Auth Policy: JWKS processing complete",
		"uri", remote.URI,
		"validKeysCount", len(cachedJWKS.Keys),
	)

	return cachedJWKS, nil
}

// extractToken extracts JWT token from authorization header
func extractToken(authHeader, scheme string) string {
	authHeader = strings.TrimSpace(authHeader)
	if scheme != "" {
		parts := strings.Fields(authHeader)
		if len(parts) == 2 && strings.EqualFold(parts[0], scheme) {
			return parts[1]
		}
		// If scheme is specified but not found, return empty
		return ""
	}
	// If no scheme specified, accept raw token or try to strip known schemes
	parts := strings.Fields(authHeader)
	if len(parts) == 0 {
		return ""
	}
	if len(parts) > 1 {
		return parts[1]
	}
	return parts[0]
}

// parseRSAPublicKey parses RSA public key from modulus and exponent
func parseRSAPublicKey(nStr, eStr string) (*rsa.PublicKey, error) {
	// Decode modulus from base64url
	nBytes, err := decodeBase64URL(nStr)
	if err != nil {
		return nil, fmt.Errorf("failed to decode modulus: %w", err)
	}

	// Decode exponent from base64url
	eBytes, err := decodeBase64URL(eStr)
	if err != nil {
		return nil, fmt.Errorf("failed to decode exponent: %w", err)
	}

	// Convert bytes to big integers
	n := new(big.Int).SetBytes(nBytes)
	e := bytesToInt(eBytes)

	return &rsa.PublicKey{
		N: n,
		E: e,
	}, nil
}

// parseECPublicKey parses an EC public key from JWKS curve name and base64url-encoded X/Y coordinates
func parseECPublicKey(crv, xStr, yStr string) (*ecdsa.PublicKey, error) {
	var curve elliptic.Curve
	var ecdhCurve ecdh.Curve
	switch crv {
	case "P-256":
		curve = elliptic.P256()
		ecdhCurve = ecdh.P256()
	case "P-384":
		curve = elliptic.P384()
		ecdhCurve = ecdh.P384()
	case "P-521":
		curve = elliptic.P521()
		ecdhCurve = ecdh.P521()
	default:
		return nil, fmt.Errorf("unsupported EC curve: %q", crv)
	}

	xBytes, err := decodeBase64URL(xStr)
	if err != nil {
		return nil, fmt.Errorf("failed to decode EC x coordinate: %w", err)
	}
	yBytes, err := decodeBase64URL(yStr)
	if err != nil {
		return nil, fmt.Errorf("failed to decode EC y coordinate: %w", err)
	}

	// Validate the point is on the curve using crypto/ecdh (uncompressed point: 0x04 || x || y).
	byteLen := (curve.Params().BitSize + 7) / 8
	point := make([]byte, 1+2*byteLen)
	point[0] = 0x04
	copy(point[1:1+byteLen], xBytes)
	copy(point[1+byteLen:], yBytes)
	if _, err := ecdhCurve.NewPublicKey(point); err != nil {
		return nil, fmt.Errorf("EC point is not on curve %q: %w", crv, err)
	}

	x := new(big.Int).SetBytes(xBytes)
	y := new(big.Int).SetBytes(yBytes)

	return &ecdsa.PublicKey{
		Curve: curve,
		X:     x,
		Y:     y,
	}, nil
}

// decodeBase64URL decodes base64url encoded string
func decodeBase64URL(s string) ([]byte, error) {
	// Add padding if necessary
	switch len(s) % 4 {
	case 2:
		s += "=="
	case 3:
		s += "="
	}

	// Replace URL-safe characters
	s = strings.ReplaceAll(s, "-", "+")
	s = strings.ReplaceAll(s, "_", "/")

	return base64.StdEncoding.DecodeString(s)
}

// bytesToInt converts bytes to int
func bytesToInt(b []byte) int {
	result := 0
	for _, byte := range b {
		result = (result << 8) | int(byte)
	}
	return result
}

// parseAudience parses audience claim which can be string or array
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

// parseScopes parses scope claim (space-delimited string or array). This is the legacy fallback
// used when a key manager does not configure an explicit ScopeClaim.
func parseScopes(scopeClaim, scpClaim interface{}) []string {
	var scopes []string

	// Check scope claim (space-delimited)
	if scopeStr, ok := scopeClaim.(string); ok {
		scopes = append(scopes, strings.Fields(scopeStr)...)
	}

	// Check scp claim (array)
	if scpArr, ok := scpClaim.([]interface{}); ok {
		for _, s := range scpArr {
			if sStr, ok := s.(string); ok {
				scopes = append(scopes, sStr)
			}
		}
	}

	return scopes
}

// Resolves token scopes using the matched key manager's scope-claim configuration, 
// falling back to the legacy "scope"/"scp" claims when none is configured.
func resolveScopes(claims jwt.MapClaims, km *KeyManager) []string {
	if km != nil && km.ScopeClaim != "" {
		return parseScopeClaim(claims[km.ScopeClaim], km.ScopeClaimSeparator)
	}
	return parseScopes(claims["scope"], claims["scp"])
}

// parseScopeClaim extracts scopes from a single configured claim value. A string value is split
// by separator (defaulting to defaultScopeClaimSeparator); a string-array value is taken as-is.
// Empty tokens are discarded so a trailing/duplicate separator does not yield blank scopes.
func parseScopeClaim(claimValue interface{}, separator string) []string {
	if separator == "" {
		separator = defaultScopeClaimSeparator
	}
	var scopes []string
	switch v := claimValue.(type) {
	case string:
		for _, s := range strings.Split(v, separator) {
			if s = strings.TrimSpace(s); s != "" {
				scopes = append(scopes, s)
			}
		}
	case []interface{}:
		for _, item := range v {
			if s, ok := item.(string); ok {
				if s = strings.TrimSpace(s); s != "" {
					scopes = append(scopes, s)
				}
			}
		}
	}
	return scopes
}

// buildScopesMap converts a resolved scope slice to a map[string]bool for AuthContext.Scopes.
func buildScopesMap(scopes []string) map[string]bool {
	if len(scopes) == 0 {
		return nil
	}
	result := make(map[string]bool, len(scopes))
	for _, s := range scopes {
		result[s] = true
	}
	return result
}

// ScopeConstraints defines required scopes using AllOf and/or 
// AnyOf; empty means no constraints and supersedes deprecated requiredScopes.
type ScopeConstraints struct {
	AllOf []string
	AnyOf []string
}

func (s ScopeConstraints) isEmpty() bool { return len(s.AllOf) == 0 && len(s.AnyOf) == 0 }

// ClaimMatcher matches a single claim: satisfied when the token's value for Claim is one of Values
// (OR within Values; for a multi-valued token claim, a non-empty intersection).
type ClaimMatcher struct {
	Claim  string
	Values []string
	legacyExactString bool // Preserves legacy requiredClaims semantics by matching only exact scalar string claims.
}

// ClaimConstraints defines required claim matchers using AllOf and/or 
// AnyOf; empty means no constraints and supersedes deprecated requiredClaims.
type ClaimConstraints struct {
	AllOf []ClaimMatcher
	AnyOf []ClaimMatcher
}

func (c ClaimConstraints) isEmpty() bool { return len(c.AllOf) == 0 && len(c.AnyOf) == 0 }

// stringArrayField extracts a []string from m[key]. An absent key yields nil. A present value that
// is not an array of strings is an error (fail-closed, decision D2). Blank entries are dropped.
func stringArrayField(m map[string]interface{}, key string) ([]string, error) {
	v, ok := m[key]
	if !ok || v == nil {
		return nil, nil
	}
	arr, ok := v.([]interface{})
	if !ok {
		return nil, fmt.Errorf("%q must be an array", key)
	}
	var out []string
	for _, item := range arr {
		s, ok := item.(string)
		if !ok {
			return nil, fmt.Errorf("%q entries must be strings", key)
		}
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out, nil
}

// Parses `scopes`; empty values trigger the legacy requiredScopes fallback, 
// while malformed values return an error to fail closed.
func parseScopeConstraints(params map[string]interface{}) (ScopeConstraints, error) {
	raw, present := params["scopes"]
	if !present || raw == nil {
		return ScopeConstraints{}, nil
	}
	m, ok := raw.(map[string]interface{})
	if !ok {
		return ScopeConstraints{}, fmt.Errorf("scopes must be an object")
	}
	allOf, err := stringArrayField(m, "allOf")
	if err != nil {
		return ScopeConstraints{}, fmt.Errorf("scopes.%w", err)
	}
	anyOf, err := stringArrayField(m, "anyOf")
	if err != nil {
		return ScopeConstraints{}, fmt.Errorf("scopes.%w", err)
	}
	return ScopeConstraints{AllOf: allOf, AnyOf: anyOf}, nil
}

// Parses claim matchers; returns nil if absent and errors on any invalid or incomplete structure..
func parseClaimMatchers(raw interface{}, field string) ([]ClaimMatcher, error) {
	if raw == nil {
		return nil, nil
	}
	arr, ok := raw.([]interface{})
	if !ok {
		return nil, fmt.Errorf("%s must be an array", field)
	}
	var out []ClaimMatcher
	for _, item := range arr {
		mm, ok := item.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("%s entries must be objects", field)
		}
		claim := strings.TrimSpace(getString(mm["claim"]))
		if claim == "" {
			return nil, fmt.Errorf("%s entries must have a non-empty 'claim'", field)
		}
		values, err := stringArrayField(mm, "values")
		if err != nil {
			return nil, fmt.Errorf("%s claim %q %w", field, claim, err)
		}
		if len(values) == 0 {
			return nil, fmt.Errorf("%s claim %q must have at least one value", field, claim)
		}
		out = append(out, ClaimMatcher{Claim: claim, Values: values})
	}
	return out, nil
}

// parseClaimConstraints reads the `claims` param. Same absent/empty/malformed contract as
// parseScopeConstraints.
func parseClaimConstraints(params map[string]interface{}) (ClaimConstraints, error) {
	raw, present := params["claims"]
	if !present || raw == nil {
		return ClaimConstraints{}, nil
	}
	m, ok := raw.(map[string]interface{})
	if !ok {
		return ClaimConstraints{}, fmt.Errorf("claims must be an object")
	}
	allOf, err := parseClaimMatchers(m["allOf"], "claims.allOf")
	if err != nil {
		return ClaimConstraints{}, err
	}
	anyOf, err := parseClaimMatchers(m["anyOf"], "claims.anyOf")
	if err != nil {
		return ClaimConstraints{}, err
	}
	return ClaimConstraints{AllOf: allOf, AnyOf: anyOf}, nil
}

// scopeConstraintsFromRequiredScopes maps the deprecated requiredScopes (any-match / OR) onto the
// new structure so both the new and deprecated paths share a single evaluator.
func scopeConstraintsFromRequiredScopes(rs []string) ScopeConstraints {
	return ScopeConstraints{AnyOf: rs}
}

// claimConstraintsFromRequiredClaims maps the deprecated requiredClaims (every claim must equal its
// configured value / AND) onto the new structure.
func claimConstraintsFromRequiredClaims(rc map[string]string) ClaimConstraints {
	matchers := make([]ClaimMatcher, 0, len(rc))
	for claim, value := range rc {
		matchers = append(matchers, ClaimMatcher{Claim: claim, Values: []string{value}, legacyExactString: true})
	}
	return ClaimConstraints{AllOf: matchers}
}

// resolveScopeConstraints applies precedence: the new `scopes` wins when non-empty; otherwise the
// deprecated requiredScopes is used. A malformed `scopes` returns an error so the caller fails
// closed.
func resolveScopeConstraints(params map[string]interface{}) (ScopeConstraints, error) {
	sc, err := parseScopeConstraints(params)
	if err != nil {
		return ScopeConstraints{}, err
	}
	if !sc.isEmpty() {
		return sc, nil
	}
	if old := getStringArrayParam(params, "requiredScopes", nil); len(old) > 0 {
		return scopeConstraintsFromRequiredScopes(old), nil
	}
	return ScopeConstraints{}, nil
}

// resolveClaimConstraints applies precedence: the new `claims` wins when non-empty; otherwise the
// deprecated requiredClaims is used. A malformed `claims` returns an error so the caller fails
// closed.
func resolveClaimConstraints(params map[string]interface{}) (ClaimConstraints, error) {
	cc, err := parseClaimConstraints(params)
	if err != nil {
		return ClaimConstraints{}, err
	}
	if !cc.isEmpty() {
		return cc, nil
	}
	if old := getStringMapParam(params, "requiredClaims", nil); len(old) > 0 {
		return claimConstraintsFromRequiredClaims(old), nil
	}
	return ClaimConstraints{}, nil
}

// claimValuesAsStrings renders a token claim value as a slice of strings: a scalar becomes one
// element, an array becomes many. Uses claimValueToString so numeric/bool claims stringify
// consistently with how they are surfaced elsewhere. Blank results are dropped.
func claimValuesAsStrings(v interface{}) []string {
	switch val := v.(type) {
	case nil:
		return nil
	case []interface{}:
		var out []string
		for _, item := range val {
			if s := claimValueToString(item); s != "" {
				out = append(out, s)
			}
		}
		return out
	default:
		if s := claimValueToString(v); s != "" {
			return []string{s}
		}
		return nil
	}
}

// claimMatcherMatches reports whether the token satisfies a single matcher. A matcher with no
// values, or a claim absent/blank in the token, never matches (fail-closed).
func claimMatcherMatches(m ClaimMatcher, claims jwt.MapClaims) bool {
	if len(m.Values) == 0 {
		return false
	}
	want := make(map[string]bool, len(m.Values))
	for _, v := range m.Values {
		want[v] = true
	}
	if m.legacyExactString {
		// Legacy requiredClaims matches only exact scalar string 
		// claims; arrays and non-string claims never match.
		got := getString(claims[m.Claim])
		return got != "" && want[got]
	}
	tokenVals := claimValuesAsStrings(claims[m.Claim])
	for _, tv := range tokenVals {
		if want[tv] {
			return true
		}
	}
	return false
}

// evaluateScopeConstraints reports whether the token's scope set satisfies sc. The returned string
// is an internal-only reason for debug logging (never returned to the client).
func evaluateScopeConstraints(sc ScopeConstraints, tokenScopes map[string]bool) (bool, string) {
	for _, s := range sc.AllOf {
		if !tokenScopes[s] {
			return false, fmt.Sprintf("required scope %q not present", s)
		}
	}
	if len(sc.AnyOf) > 0 {
		found := false
		for _, s := range sc.AnyOf {
			if tokenScopes[s] {
				found = true
				break
			}
		}
		if !found {
			return false, fmt.Sprintf("none of the any-of scopes %v present", sc.AnyOf)
		}
	}
	return true, ""
}

// evaluateClaimConstraints reports whether the token's claims satisfy cc. The returned string is an
// internal-only reason for debug logging (never returned to the client).
func evaluateClaimConstraints(cc ClaimConstraints, claims jwt.MapClaims) (bool, string) {
	for _, m := range cc.AllOf {
		if !claimMatcherMatches(m, claims) {
			return false, fmt.Sprintf("required claim %q not satisfied", m.Claim)
		}
	}
	if len(cc.AnyOf) > 0 {
		found := false
		for _, m := range cc.AnyOf {
			if claimMatcherMatches(m, claims) {
				found = true
				break
			}
		}
		if !found {
			return false, "none of the any-of claim matchers satisfied"
		}
	}
	return true, ""
}

// Logs warnings for deprecated config params used during policy load, noting when they're ignored in favor of new ones.
func logDeprecatedParamUsage(params map[string]interface{}) {
	if len(getStringArrayParam(params, "requiredScopes", nil)) > 0 {
		if sc, err := parseScopeConstraints(params); err == nil && !sc.isEmpty() {
			slog.Warn("JWT Auth Policy: 'requiredScopes' is deprecated and ignored because 'scopes' is configured; remove 'requiredScopes' and use 'scopes' (allOf/anyOf).")
		} else {
			slog.Warn("JWT Auth Policy: 'requiredScopes' is deprecated; migrate to 'scopes' (allOf/anyOf).")
		}
	}
	if len(getStringMapParam(params, "requiredClaims", nil)) > 0 {
		if cc, err := parseClaimConstraints(params); err == nil && !cc.isEmpty() {
			slog.Warn("JWT Auth Policy: 'requiredClaims' is deprecated and ignored because 'claims' is configured; remove 'requiredClaims' and use 'claims' (allOf/anyOf).")
		} else {
			slog.Warn("JWT Auth Policy: 'requiredClaims' is deprecated; migrate to 'claims' (allOf/anyOf).")
		}
	}
}

// buildProperties extracts non-standard claims into a map[string]string for AuthContext.Properties.
func buildProperties(claims jwt.MapClaims) map[string]string {
	var props map[string]string
	for k, v := range claims {
		if standardJWTClaims[k] {
			continue
		}
		if props == nil {
			props = make(map[string]string)
		}
		props[k] = claimValueToString(v)
	}
	return props
}

// buildTypedProperties extracts non-standard claims into a map[string]interface{}, preserving each
// claim's native type (string, []interface{}, map[string]interface{}, etc.) so downstream policies
// (e.g. mcp-authz) can match array-valued claims as sets or process structured data. Unlike
// buildProperties, it does not flatten values into a serialized string.
func buildTypedProperties(claims jwt.MapClaims) map[string]interface{} {
	var out map[string]interface{}
	for k, v := range claims {
		if standardJWTClaims[k] {
			continue
		}
		if v == nil {
			continue
		}
		if out == nil {
			out = make(map[string]interface{})
		}
		out[k] = v
	}
	return out
}

// Helper functions for type assertions
func getString(v interface{}) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
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
	case string:
		return val
	case float64:
		return fmt.Sprintf("%v", int64(val))
	case bool:
		return fmt.Sprintf("%v", val)
	default:
		bytes, _ := json.Marshal(val)
		return string(bytes)
	}
}

// getKeyIds returns a slice of key IDs from a map of public keys
func getKeyIds(keys map[string]crypto.PublicKey) []string {
	ids := make([]string, 0, len(keys))
	for id := range keys {
		ids = append(ids, id)
	}
	return ids
}

// loadTLSConfig loads TLS configuration from a certificate file for validating self-signed certificates
// When a custom CA certificate is provided, hostname verification is skipped to allow
// self-signed certificates with any hostname to be used (useful for development/testing)
func loadTLSConfig(certPath string) (*tls.Config, error) {
	slog.Debug("JWT Auth Policy: loadTLSConfig called",
		"certPath", certPath,
	)

	certData, err := os.ReadFile(certPath)
	if err != nil {
		slog.Debug("JWT Auth Policy: Failed to read certificate file",
			"certPath", certPath,
			"error", err,
		)
		return nil, fmt.Errorf("failed to read certificate file: %w", err)
	}

	slog.Debug("JWT Auth Policy: Certificate file read successfully",
		"certPath", certPath,
		"dataLength", len(certData),
	)

	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(certData) {
		slog.Debug("JWT Auth Policy: Failed to parse PEM certificate",
			"certPath", certPath,
		)
		return nil, fmt.Errorf("failed to parse PEM certificate from %s", certPath)
	}

	slog.Debug("JWT Auth Policy: TLS config created successfully",
		"certPath", certPath,
	)

	return &tls.Config{
		RootCAs:    caCertPool,
		MinVersion: tls.VersionTLS12,
	}, nil
}

// loadPublicKeyFromCertificate loads a public key (RSA or ECDSA) from a certificate file
func loadPublicKeyFromCertificate(certPath string) (crypto.PublicKey, error) {
	slog.Debug("JWT Auth Policy: loadPublicKeyFromCertificate called",
		"certPath", certPath,
	)

	certData, err := os.ReadFile(certPath)
	if err != nil {
		slog.Debug("JWT Auth Policy: Failed to read certificate file for public key",
			"certPath", certPath,
			"error", err,
		)
		return nil, fmt.Errorf("failed to read certificate file: %w", err)
	}

	slog.Debug("JWT Auth Policy: Certificate file read for public key extraction",
		"certPath", certPath,
		"dataLength", len(certData),
	)

	return parsePublicKeyFromString(string(certData))
}

// parsePublicKeyFromString parses a public key (RSA or ECDSA) from a PEM-encoded string
func parsePublicKeyFromString(pemData string) (crypto.PublicKey, error) {
	slog.Debug("JWT Auth Policy: parsePublicKeyFromString called",
		"dataLength", len(pemData),
	)

	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		slog.Debug("JWT Auth Policy: Failed to decode PEM block")
		return nil, fmt.Errorf("failed to decode PEM block from certificate data")
	}

	slog.Debug("JWT Auth Policy: PEM block decoded successfully",
		"blockType", block.Type,
	)

	// Try to parse as a certificate first
	cert, err := x509.ParseCertificate(block.Bytes)
	if err == nil {
		slog.Debug("JWT Auth Policy: Parsed as X.509 certificate",
			"subject", cert.Subject.String(),
			"issuer", cert.Issuer.String(),
		)
		// Extract public key from certificate (RSA or ECDSA)
		switch pub := cert.PublicKey.(type) {
		case *rsa.PublicKey:
			slog.Debug("JWT Auth Policy: Extracted RSA public key from certificate")
			return pub, nil
		case *ecdsa.PublicKey:
			slog.Debug("JWT Auth Policy: Extracted ECDSA public key from certificate")
			return pub, nil
		}
		slog.Debug("JWT Auth Policy: Certificate does not contain a supported public key type")
		return nil, fmt.Errorf("certificate does not contain a supported public key (RSA or ECDSA)")
	}

	slog.Debug("JWT Auth Policy: Not a certificate, trying to parse as public key directly",
		"parseError", err,
	)

	// If certificate parsing fails, try to parse as a public key directly
	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		slog.Debug("JWT Auth Policy: Failed to parse as PKIX public key",
			"error", err,
		)
		return nil, fmt.Errorf("failed to parse public key from certificate data: %w", err)
	}

	switch pub := publicKey.(type) {
	case *rsa.PublicKey:
		slog.Debug("JWT Auth Policy: Parsed PKIX RSA public key successfully")
		return pub, nil
	case *ecdsa.PublicKey:
		slog.Debug("JWT Auth Policy: Parsed PKIX ECDSA public key successfully")
		return pub, nil
	}

	slog.Debug("JWT Auth Policy: Parsed key is not a supported type")
	return nil, fmt.Errorf("certificate data does not contain a supported public key (RSA or ECDSA)")
}

// OnRequestHeaders performs JWT validation in the request header phase.
func (p *JwtAuthPolicy) OnRequestHeaders(ctx context.Context, reqCtx *policy.RequestHeaderContext, params map[string]interface{}) policy.RequestHeaderAction {
	slog.Debug("JWT Auth Policy: OnRequestHeaders started")

	headerName := getStringParam(params, "headerName", "Authorization")
	authHeaderScheme := getStringParam(params, "authHeaderScheme", "Bearer")
	onFailureStatusCode := getIntParam(params, "onFailureStatusCode", 401)
	errorMessageFormat := getStringParam(params, "errorMessageFormat", "json")
	errorMessage := getStringParam(params, "errorMessage", "Authentication failed")
	leewayStr := getStringParam(params, "leeway", "30s")
	jwksCacheTtlStr := getStringParam(params, "jwksCacheTtl", "5m")
	jwksFetchTimeoutStr := getStringParam(params, "jwksFetchTimeout", "5s")
	jwksFetchRetryCount := getIntParam(params, "jwksFetchRetryCount", 3)
	jwksFetchRetryIntervalStr := getStringParam(params, "jwksFetchRetryInterval", "2s")
	validateIssuer := getBoolParam(params, "validateIssuer", true)
	tokenCaching := getBoolParam(params, "tokenCaching", true)
	tokenCacheTtlStr := getStringParam(params, "tokenCacheTtl", "5m")
	negativeCacheTtlStr := getStringParam(params, "negativeCacheTtl", "30s")

	slog.Debug("JWT Auth Policy: Configuration loaded",
		"headerName", headerName,
		"authHeaderScheme", authHeaderScheme,
		"onFailureStatusCode", onFailureStatusCode,
		"errorMessageFormat", errorMessageFormat,
		"errorMessage", errorMessage,
		"leeway", leewayStr,
		"supportedAlgorithms", supportedAlgorithms,
		"jwksCacheTtl", jwksCacheTtlStr,
		"jwksFetchTimeout", jwksFetchTimeoutStr,
		"jwksFetchRetryCount", jwksFetchRetryCount,
		"jwksFetchRetryInterval", jwksFetchRetryIntervalStr,
		"validateIssuer", validateIssuer,
		"tokenCaching", tokenCaching,
		"tokenCacheTtl", tokenCacheTtlStr,
		"negativeCacheTtl", negativeCacheTtlStr,
	)

	leeway, err := time.ParseDuration(leewayStr)
	if err != nil {
		slog.Debug("JWT Auth Policy: Failed to parse leeway duration, using default",
			"leewayStr", leewayStr,
			"error", err,
			"defaultLeeway", "30s",
		)
		leeway = 30 * time.Second
	}
	jwksCacheTtl, err := time.ParseDuration(jwksCacheTtlStr)
	if err != nil {
		slog.Debug("JWT Auth Policy: Failed to parse jwksCacheTtl duration, using default",
			"jwksCacheTtlStr", jwksCacheTtlStr,
			"error", err,
			"defaultCacheTtl", "5m",
		)
		jwksCacheTtl = 5 * time.Minute
	}
	jwksFetchTimeout, err := time.ParseDuration(jwksFetchTimeoutStr)
	if err != nil {
		slog.Debug("JWT Auth Policy: Failed to parse jwksFetchTimeout duration, using default",
			"jwksFetchTimeoutStr", jwksFetchTimeoutStr,
			"error", err,
			"defaultTimeout", "5s",
		)
		jwksFetchTimeout = 5 * time.Second
	}
	jwksFetchRetryInterval, err := time.ParseDuration(jwksFetchRetryIntervalStr)
	if err != nil {
		slog.Debug("JWT Auth Policy: Failed to parse jwksFetchRetryInterval duration, using default",
			"jwksFetchRetryIntervalStr", jwksFetchRetryIntervalStr,
			"error", err,
			"defaultInterval", "2s",
		)
		jwksFetchRetryInterval = 2 * time.Second
	}
	tokenCacheTtl, err := time.ParseDuration(tokenCacheTtlStr)
	if err != nil {
		slog.Debug("JWT Auth Policy: Failed to parse tokenCacheTtl duration, using default",
			"tokenCacheTtlStr", tokenCacheTtlStr,
			"error", err,
			"defaultTokenCacheTtl", defaultTokenCacheTtl,
		)
		tokenCacheTtl = defaultTokenCacheTtl
	}
	negativeCacheTtl, err := time.ParseDuration(negativeCacheTtlStr)
	if err != nil {
		slog.Debug("JWT Auth Policy: Failed to parse negativeCacheTtl duration, using default",
			"negativeCacheTtlStr", negativeCacheTtlStr,
			"error", err,
			"defaultNegativeCacheTtl", defaultNegativeCacheTtl,
		)
		negativeCacheTtl = defaultNegativeCacheTtl
	}

	slog.Debug("JWT Auth Policy: Parsed duration values",
		"leeway", leeway,
		"jwksCacheTtl", jwksCacheTtl,
		"jwksFetchTimeout", jwksFetchTimeout,
		"jwksFetchRetryInterval", jwksFetchRetryInterval,
		"tokenCacheTtl", tokenCacheTtl,
		"negativeCacheTtl", negativeCacheTtl,
	)

	keyManagersRaw, ok := params["keyManagers"]
	if !ok {
		slog.Debug("JWT Auth Policy: Key managers not configured in params")
		return p.handleAuthFailureHeaders(reqCtx.SharedContext, onFailureStatusCode, errorMessageFormat, errorMessage, "key managers not configured")
	}

	userIssuers := getStringArrayParam(params, "issuers", []string{})
	userAudiences := getStringArrayParam(params, "audiences", []string{})
	// scopes/claims (new) take precedence over requiredScopes/requiredClaims (deprecated). A
	// malformed new param denies the request rather than silently dropping a security constraint.
	scopeConstraints, scopeErr := resolveScopeConstraints(params)
	if scopeErr != nil {
		slog.Warn("JWT Auth Policy: invalid 'scopes' configuration; denying request", "error", scopeErr)
		return p.handleAuthFailureHeaders(reqCtx.SharedContext, onFailureStatusCode, errorMessageFormat, errorMessage, "invalid scopes configuration")
	}
	claimConstraints, claimErr := resolveClaimConstraints(params)
	if claimErr != nil {
		slog.Warn("JWT Auth Policy: invalid 'claims' configuration; denying request", "error", claimErr)
		return p.handleAuthFailureHeaders(reqCtx.SharedContext, onFailureStatusCode, errorMessageFormat, errorMessage, "invalid claims configuration")
	}
	userClaimMappings := getStringMapParam(params, "claimMappings", map[string]string{})
	userIdClaim := getStringParam(params, "userIdClaim", "sub")
	userAuthHeaderPrefix := getStringParam(params, "authHeaderPrefix", "")
	forwardToken := getBoolParam(params, "forwardToken", true)
	forwardedTokenHeader := getStringParam(params, "forwardedTokenHeader", "x-forwarded-authorization")
	forwardTokenStripScheme := getBoolParam(params, "forwardTokenStripScheme", false)

	slog.Debug("JWT Auth Policy: User configuration loaded",
		"issuers", userIssuers,
		"audiences", userAudiences,
		"scopeAllOf", scopeConstraints.AllOf,
		"scopeAnyOf", scopeConstraints.AnyOf,
		"claimMatcherCount", len(claimConstraints.AllOf)+len(claimConstraints.AnyOf),
		"claimMappingsCount", len(userClaimMappings),
		"userIdClaim", userIdClaim,
		"authHeaderPrefix", userAuthHeaderPrefix,
		"forwardTokenStripScheme", forwardTokenStripScheme,
	)

	if userAuthHeaderPrefix != "" {
		slog.Debug("JWT Auth Policy: Overriding auth header scheme with user prefix",
			"originalScheme", authHeaderScheme,
			"newScheme", userAuthHeaderPrefix,
		)
		authHeaderScheme = userAuthHeaderPrefix
	}

	authHeaders := getDownstreamHeaders(reqCtx.Downstream, reqCtx.Headers).Get(strings.ToLower(headerName))
	if len(authHeaders) == 0 {
		slog.Debug("JWT Auth Policy: Missing authorization header",
			"headerName", headerName,
		)
		return p.handleAuthFailureHeaders(reqCtx.SharedContext, onFailureStatusCode, errorMessageFormat, errorMessage, "missing authorization header")
	}

	authHeader := authHeaders[0]
	slog.Debug("JWT Auth Policy: Authorization header found",
		"headerName", headerName,
		"headerValueLength", len(authHeader),
	)

	token := extractToken(authHeader, authHeaderScheme)
	if token == "" {
		slog.Debug("JWT Auth Policy: Failed to extract token from authorization header",
			"authHeaderScheme", authHeaderScheme,
		)
		return p.handleAuthFailureHeaders(reqCtx.SharedContext, onFailureStatusCode, errorMessageFormat, errorMessage, "invalid authorization header format")
	}

	slog.Debug("JWT Auth Policy: Token extracted successfully",
		"tokenLength", len(token),
	)

	// Cache boundary: everything above is cheap (header/param reads). Everything below —
	// unverified parsing, key-manager/certificate/TLS parsing, and signature verification — is
	// exactly what the verdict cache exists to skip on a repeat presentation of the same token
	// under the same verification config (see tokenConfigFingerprint).
	var cacheKey string
	if tokenCaching {
		fingerprint := tokenConfigFingerprint(reqCtx.APIId, reqCtx.APIName, keyManagersRaw, validateIssuer, userIssuers, leeway)
		cacheKey = buildTokenCacheKey(fingerprint, token)
		if verdict, hit := p.getCachedVerdict(ctx, cacheKey); hit {
			if verdict.ok {
				slog.Debug("JWT Auth Policy: Token verdict cache hit (verified)",
					"cacheKey", cacheKey,
					"expiresAt", verdict.expiresAt,
				)
				return p.finishAuthentication(reqCtx, verdict.claims, verdict.scopes, onFailureStatusCode, errorMessageFormat, errorMessage,
					userAudiences, scopeConstraints, claimConstraints, userClaimMappings, userIdClaim,
					headerName, authHeader, token, forwardToken, forwardedTokenHeader, forwardTokenStripScheme)
			}
			slog.Debug("JWT Auth Policy: Token verdict cache hit (failure)",
				"cacheKey", cacheKey,
				"reason", verdict.reason,
				"expiresAt", verdict.expiresAt,
			)
			return p.handleAuthFailureHeaders(reqCtx.SharedContext, onFailureStatusCode, errorMessageFormat, errorMessage, verdict.reason)
		}
		slog.Debug("JWT Auth Policy: Token verdict cache miss, proceeding to full verification",
			"cacheKey", cacheKey,
		)
	} else {
		slog.Debug("JWT Auth Policy: Token verdict caching disabled, performing full verification")
	}

	slog.Debug("JWT Auth Policy: Starting to parse key managers configuration")

	keyManagers := make(map[string]*KeyManager)
	keyManagersList, ok := keyManagersRaw.([]interface{})
	if ok {
		for _, km := range keyManagersList {
			if kmMap, ok := km.(map[string]interface{}); ok {
				name := getString(kmMap["name"])
				issuer := getString(kmMap["issuer"])
				if name == "" {
					slog.Debug("JWT Auth Policy: Skipping key manager with empty name")
					continue
				}

				// Per-key-manager scope claim configuration. When scopeClaim is empty the legacy
				// fallback applies downstream (read both "scope" and "scp"); when set, the separator
				// defaults to defaultScopeClaimSeparator unless the operator overrides it.
				scopeClaim := getString(kmMap["scopeClaim"])
				scopeClaimSeparator := getString(kmMap["scopeClaimSeparator"])
				if scopeClaim != "" && scopeClaimSeparator == "" {
					scopeClaimSeparator = defaultScopeClaimSeparator
				}
				if scopeClaim == "" && scopeClaimSeparator != "" {
					slog.Debug("JWT Auth Policy: scopeClaimSeparator ignored because scopeClaim is not set",
						"keyManager", name,
					)
				}

				slog.Debug("JWT Auth Policy: Processing key manager",
					"name", name,
					"issuer", issuer,
					"scopeClaim", scopeClaim,
				)

				keyManager := &KeyManager{
					Name:                name,
					Issuer:              issuer,
					ScopeClaim:          scopeClaim,
					ScopeClaimSeparator: scopeClaimSeparator,
				}
				if jwksRaw, ok := kmMap["jwks"].(map[string]interface{}); ok {
					jwksConfig := &JWKSConfig{}
					if remoteRaw, ok := jwksRaw["remote"].(map[string]interface{}); ok {
						uri := getString(remoteRaw["uri"])
						certPath := getString(remoteRaw["certificatePath"])
						skipTlsVerify := getBool(remoteRaw["skipTlsVerify"])
						if uri != "" {
							slog.Debug("JWT Auth Policy: Configuring remote JWKS",
								"keyManager", name,
								"uri", uri,
								"certificatePath", certPath,
								"skipTlsVerify", skipTlsVerify,
							)
							remoteJWKS := &RemoteJWKS{URI: uri, CertificatePath: certPath, SkipTlsVerify: skipTlsVerify}
							if certPath != "" {
								tlsConfig, err := loadTLSConfig(certPath)
								if err != nil {
									slog.Debug("JWT Auth Policy: Failed to load TLS config for remote JWKS",
										"keyManager", name,
										"certificatePath", certPath,
										"error", err,
									)
									continue
								}
								slog.Debug("JWT Auth Policy: Successfully loaded TLS config for remote JWKS",
									"keyManager", name,
									"certificatePath", certPath,
								)
								remoteJWKS.tlsConfig = tlsConfig
							} else if skipTlsVerify {
								slog.Debug("JWT Auth Policy: Configuring TLS to skip verification",
									"keyManager", name,
								)
								remoteJWKS.tlsConfig = &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}
							}
							jwksConfig.Remote = remoteJWKS
						}
					}
					if localRaw, ok := jwksRaw["local"].(map[string]interface{}); ok {
						inline := getString(localRaw["inline"])
						certPath := getString(localRaw["certificatePath"])

						slog.Debug("JWT Auth Policy: Processing local certificate configuration",
							"keyManager", name,
							"hasInline", inline != "",
							"certificatePath", certPath,
						)

						if inline != "" || certPath != "" {
							localCert := &LocalCert{Inline: inline, CertificatePath: certPath}
							var publicKey crypto.PublicKey
							var certErr error
							if inline != "" {
								slog.Debug("JWT Auth Policy: Parsing inline certificate",
									"keyManager", name,
								)
								publicKey, certErr = parsePublicKeyFromString(inline)
							} else if certPath != "" {
								slog.Debug("JWT Auth Policy: Loading certificate from file",
									"keyManager", name,
									"certificatePath", certPath,
								)
								publicKey, certErr = loadPublicKeyFromCertificate(certPath)
							}
							if certErr != nil {
								slog.Debug("JWT Auth Policy: Failed to load local certificate",
									"keyManager", name,
									"error", certErr,
								)
								continue
							}
							slog.Debug("JWT Auth Policy: Successfully loaded local certificate",
								"keyManager", name,
							)
							localCert.PublicKey = publicKey
							jwksConfig.Local = localCert
						}
					}
					if jwksConfig.Remote != nil || jwksConfig.Local != nil {
						keyManager.JWKS = jwksConfig
						keyManagers[name] = keyManager
						slog.Debug("JWT Auth Policy: Key manager added successfully",
							"keyManager", name,
							"hasRemote", jwksConfig.Remote != nil,
							"hasLocal", jwksConfig.Local != nil,
						)
					} else {
						slog.Debug("JWT Auth Policy: Key manager skipped - no remote or local JWKS configured",
							"keyManager", name,
						)
					}
				}
			}
		}
	}

	if len(keyManagers) == 0 {
		slog.Debug("JWT Auth Policy: No key managers configured after parsing")
		return p.handleAuthFailureHeaders(reqCtx.SharedContext, onFailureStatusCode, errorMessageFormat, errorMessage, "no key managers configured")
	}

	slog.Debug("JWT Auth Policy: Key managers configured",
		"count", len(keyManagers),
	)

	unverifiedToken, _, err := jwt.NewParser().ParseUnverified(token, jwt.MapClaims{})
	if err != nil {
		slog.Debug("JWT Auth Policy: Failed to parse token",
			"error", err,
		)
		if tokenCaching {
			slog.Debug("JWT Auth Policy: Caching negative verdict (malformed token)",
				"cacheKey", cacheKey,
				"negativeCacheTtl", negativeCacheTtl,
			)
			p.putVerdict(ctx, cacheKey, cachedVerdict{ok: false, reason: "invalid token format", expiresAt: time.Now().Add(negativeCacheTtl)})
		}
		return p.handleAuthFailureHeaders(reqCtx.SharedContext, onFailureStatusCode, errorMessageFormat, errorMessage, "invalid token format")
	}

	slog.Debug("JWT Auth Policy: Token parsed successfully",
		"algorithm", unverifiedToken.Header["alg"],
		"keyId", unverifiedToken.Header["kid"],
		"type", unverifiedToken.Header["typ"],
	)

	claims, matchedKeyManager, err := p.validateTokenWithSignature(token, unverifiedToken, keyManagers, userIssuers, validateIssuer,
		leeway, jwksCacheTtl, jwksFetchTimeout, jwksFetchRetryCount, jwksFetchRetryInterval)
	if err != nil {
		slog.Debug("JWT Auth Policy: Token validation failed",
			"error", err,
		)
		failureReason := fmt.Sprintf("token validation failed: %v", err)
		if tokenCaching && errors.Is(err, errTokenExpired) {
			slog.Debug("JWT Auth Policy: Caching negative verdict (token expired)",
				"cacheKey", cacheKey,
				"negativeCacheTtl", negativeCacheTtl,
			)
			p.putVerdict(ctx, cacheKey, cachedVerdict{ok: false, reason: failureReason, expiresAt: time.Now().Add(negativeCacheTtl)})
		} else if tokenCaching {
			slog.Debug("JWT Auth Policy: Token validation failure not cached (not a conservatively-cacheable reason)",
				"cacheKey", cacheKey,
			)
		}
		return p.handleAuthFailureHeaders(reqCtx.SharedContext, onFailureStatusCode, errorMessageFormat, errorMessage, failureReason)
	}

	slog.Debug("JWT Auth Policy: Token signature validated successfully")

    // Resolve and cache scopes while the matched key manager is known to keep cache-hit behavior consistent.
	scopes := resolveScopes(claims, matchedKeyManager)

	if tokenCaching {
		// expiresAt is capped at the sooner of "now + tokenCacheTtl" and the token's own
		// exp (minus leeway), so a live cache entry is always still within the token's
		// validity window — a hit therefore needs no crypto or exp/nbf re-check.
		expiresAt := time.Now().Add(tokenCacheTtl)
		if expFloat, ok := claims["exp"].(float64); ok {
			tokenExpiry := time.Unix(int64(expFloat), 0).Add(-leeway)
			if tokenExpiry.Before(expiresAt) {
				expiresAt = tokenExpiry
			}
		}
		if expiresAt.After(time.Now()) {
			slog.Debug("JWT Auth Policy: Caching positive verdict",
				"cacheKey", cacheKey,
				"expiresAt", expiresAt,
			)
			p.putVerdict(ctx, cacheKey, cachedVerdict{ok: true, claims: claims, scopes: scopes, expiresAt: expiresAt})
		} else {
			slog.Debug("JWT Auth Policy: Skipping positive cache write, computed expiry is not in the future",
				"cacheKey", cacheKey,
				"expiresAt", expiresAt,
			)
		}
	}

	return p.finishAuthentication(reqCtx, claims, scopes, onFailureStatusCode, errorMessageFormat, errorMessage,
		userAudiences, scopeConstraints, claimConstraints, userClaimMappings, userIdClaim,
		headerName, authHeader, token, forwardToken, forwardedTokenHeader, forwardTokenStripScheme)
}

// finishAuthentication runs the checks that must always be re-evaluated even on a verdict-cache
// hit — audience, required scopes, required claims — since they depend on per-request config
// deliberately kept out of the cache key, and then builds the upstream header modifications on
// success. Shared by both the cache-hit and cache-miss paths in OnRequestHeaders so the two
// converge on identical downstream behavior.
func (p *JwtAuthPolicy) finishAuthentication(reqCtx *policy.RequestHeaderContext, claims jwt.MapClaims, scopes []string,
	onFailureStatusCode int, errorMessageFormat, errorMessage string,
	userAudiences []string, scopeConstraints ScopeConstraints, claimConstraints ClaimConstraints, userClaimMappings map[string]string,
	userIdClaim, headerName, authHeader, token string,
	forwardToken bool, forwardedTokenHeader string, forwardTokenStripScheme bool) policy.RequestHeaderAction {

	if len(userAudiences) > 0 {
		aud := parseAudience(claims["aud"])
		slog.Debug("JWT Auth Policy: Validating audience",
			"tokenAudiences", aud,
			"requiredAudiences", userAudiences,
		)
		found := false
		for _, userAud := range userAudiences {
			for _, tokenAud := range aud {
				if tokenAud == userAud {
					found = true
					break
				}
			}
			if found {
				break
			}
		}
		if !found {
			slog.Debug("JWT Auth Policy: No valid audience found in token",
				"tokenAudiences", aud,
			)
			return p.handleAuthFailureHeaders(reqCtx.SharedContext, onFailureStatusCode, errorMessageFormat, errorMessage, "no valid audience found in token")
		}
		slog.Debug("JWT Auth Policy: Audience validation passed")
	}

	if !scopeConstraints.isEmpty() {
		slog.Debug("JWT Auth Policy: Validating scope constraints",
			"tokenScopes", scopes,
			"allOf", scopeConstraints.AllOf,
			"anyOf", scopeConstraints.AnyOf,
		)
		if ok, reason := evaluateScopeConstraints(scopeConstraints, buildScopesMap(scopes)); !ok {
			slog.Debug("JWT Auth Policy: Scope constraint not satisfied",
				"reason", reason,
				"tokenScopes", scopes,
			)
			// Client message is generic; the specific reason stays in the debug log only.
			return p.handleAuthFailureHeaders(reqCtx.SharedContext, onFailureStatusCode, errorMessageFormat, errorMessage, "required scopes not satisfied")
		}
		slog.Debug("JWT Auth Policy: Scope validation passed")
	}

	if !claimConstraints.isEmpty() {
		slog.Debug("JWT Auth Policy: Validating claim constraints",
			"allOfCount", len(claimConstraints.AllOf),
			"anyOfCount", len(claimConstraints.AnyOf),
		)
		if ok, reason := evaluateClaimConstraints(claimConstraints, claims); !ok {
			slog.Debug("JWT Auth Policy: Claim constraint not satisfied",
				"reason", reason,
			)
			return p.handleAuthFailureHeaders(reqCtx.SharedContext, onFailureStatusCode, errorMessageFormat, errorMessage, "required claims not satisfied")
		}
		slog.Debug("JWT Auth Policy: Claim validation passed")
	}

	slog.Debug("JWT Auth Policy: All validations passed, authentication successful")

	return p.handleAuthSuccessHeaders(reqCtx.SharedContext, claims, scopes, userClaimMappings, userIdClaim, headerName, authHeader, token,
		forwardToken, forwardedTokenHeader, forwardTokenStripScheme)
}

// handleAuthSuccessHeaders handles successful JWT authentication in the header phase.
func (p *JwtAuthPolicy) handleAuthSuccessHeaders(shared *policy.SharedContext, claims jwt.MapClaims, scopes []string, claimMappings map[string]string,
	userIdClaim string, headerName string, authHeaderValue string, tokenValue string, forwardToken bool, forwardedTokenHeader string,
	forwardTokenStripScheme bool) policy.RequestHeaderAction {
	sub, _ := claims["sub"].(string)
	iss, _ := claims["iss"].(string)
	jti, _ := claims["jti"].(string)
	credential_id, _ := claims["client_id"].(string)

	subject := sub
	if userIdClaim != "" && userIdClaim != "sub" {
		if v, ok := claims[userIdClaim]; ok {
			candidate := strings.TrimSpace(claimValueToString(v))
			if candidate != "" && candidate != "null" {
				subject = candidate
			}
		}
	}

	shared.AuthContext = &policy.AuthContext{
		Authenticated:   true,
		AuthType:        AuthType,
		Subject:         subject,
		Issuer:          iss,
		Audience:        parseAudience(claims["aud"]),
		Scopes:          buildScopesMap(scopes),
		Properties:      buildProperties(claims),
		TypedProperties: buildTypedProperties(claims),
		TokenId:         jti,
		CredentialID:    credential_id,
		Previous:        shared.AuthContext,
	}

	modifications := policy.UpstreamRequestHeaderModifications{
		HeadersToSet: make(map[string]string),
	}

	canonicalIn := http.CanonicalHeaderKey(headerName)
	canonicalOut := http.CanonicalHeaderKey(forwardedTokenHeader)

	if !forwardToken {
		modifications.HeadersToRemove = []string{canonicalIn}
	} else {
		// Forward either the bare token or the full
		// original header value, depending on forwardTokenStripScheme.
		forwardValue := authHeaderValue
		if forwardTokenStripScheme {
			forwardValue = tokenValue
		}
		if canonicalOut != canonicalIn {
			modifications.HeadersToSet[canonicalOut] = forwardValue
			modifications.HeadersToRemove = []string{canonicalIn}
		} else if forwardTokenStripScheme {
			// Same header name, but the prefix must be stripped, so overwrite it.
			modifications.HeadersToSet[canonicalOut] = forwardValue
		}
	}

	type mappedHeader struct {
		name  string
		value string
	}
	mappedHeaders := make(map[string]mappedHeader, len(claimMappings))
	for claimName, configuredHeaderName := range claimMappings {
		canonicalHeaderName := http.CanonicalHeaderKey(configuredHeaderName)
		if forwardToken && canonicalHeaderName == canonicalOut {
			continue
		}

		header, initialized := mappedHeaders[canonicalHeaderName]
		if !initialized {
			header.name = configuredHeaderName
		}
		if claimValue, ok := claims[claimName]; ok {
			header.value = claimValueToString(claimValue)
		}
		mappedHeaders[canonicalHeaderName] = header
	}

	for _, header := range mappedHeaders {
		modifications.HeadersToSet[header.name] = header.value
	}

	return modifications
}

// handleAuthFailureHeaders handles JWT authentication failure in the header phase.
func (p *JwtAuthPolicy) handleAuthFailureHeaders(shared *policy.SharedContext, statusCode int, errorFormat, errorMessage, reason string) policy.RequestHeaderAction {
	slog.Debug("JWT Auth Policy: handleAuthFailureHeaders called",
		"statusCode", statusCode,
		"reason", reason,
	)

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
