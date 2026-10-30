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

package oauth2generator

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

const (
	// defaultTokenRequestTimeout bounds a token-endpoint HTTP call so a hung IdP can't block indefinitely.
	defaultTokenRequestTimeout = 10 * time.Second

	// defaultTokenTTLFallback is used when the token response omits expires_in.
	defaultTokenTTLFallback = time.Hour

	// defaultHeaderName is the header the generated credential is injected into when headerName is omitted.
	defaultHeaderName = "Authorization"

	// defaultValuePrefix is prepended to the credential value when valuePrefix is omitted; an
	// explicitly configured empty string is honored as "no prefix".
	defaultValuePrefix = "Bearer"

	// defaultTokenRequestMaxRetries bounds resilientTokenSource's retries on a transient token-endpoint error.
	defaultTokenRequestMaxRetries = 2

	// retryBaseDelay/retryMaxDelay bound resilientTokenSource's exponential backoff, with jitter
	// so replicas don't retry a struggling IdP in lockstep.
	retryBaseDelay = 100 * time.Millisecond
	retryMaxDelay  = 2 * time.Second

	// defaultExpiryBuffer is how far ahead of expiry a token is treated as stale, for both the
	// caching layer (tokenFreshEnough) and the token source's own reuse (reuseTokenSource) - both
	// must agree on the same value.
	defaultExpiryBuffer = 5 * time.Minute

	// maxTokenResponseBytes bounds how much of a token response is read, regardless of
	// Content-Length, so a misbehaving IdP can't exhaust memory.
	maxTokenResponseBytes = 1 << 20 // 1MiB
)

// defaultPurgeStatusCodes is applied when tokenPurgeStatusCodes is omitted. 401 is the standard
// signal (RFC 6750 §3) that a bearer token was rejected as invalid.
var defaultPurgeStatusCodes = []int{http.StatusUnauthorized}

const (
	// GrantTypeClientCredentials (RFC 6749 §4.4) is the standard machine-to-machine grant.
	GrantTypeClientCredentials = "client_credentials"

	// GrantTypePassword (RFC 6749 §4.3) bridges legacy IdPs that only support this grant.
	GrantTypePassword = "password"

	// AuthType is the AuthContext.AuthType for the token-endpoint path.
	AuthType = "oauth2"

	// AuthTypeStaticToken is the AuthContext.AuthType for the directly-supplied-token path.
	AuthTypeStaticToken = "static-token"

	// ModeTokenEndpoint and ModeStaticToken identify which mutually exclusive auth path a
	// policy instance was configured for.
	ModeTokenEndpoint = "token-endpoint"
	ModeStaticToken   = "static-token"

	// ClientAuthMethodBasic (client_secret_basic) sends client ID/secret via HTTP Basic auth -
	// RFC 6749's preferred convention, and this policy's default.
	ClientAuthMethodBasic = "client_secret_basic"

	// ClientAuthMethodPost (client_secret_post) sends client ID/secret as form fields instead.
	ClientAuthMethodPost = "client_secret_post"
)

// Token is the subset of an RFC 6749 §5.1 token response this policy needs.
type Token struct {
	AccessToken  string
	TokenType    string
	RefreshToken string
	Expiry       time.Time
}

// TokenSource supplies the current access token, fetching or reusing a cached one as it sees fit.
type TokenSource interface {
	Token(ctx context.Context) (*Token, error)
}

// TokenError represents an RFC 6749 §5.2 error response FROM the token endpoint, as opposed to a
// network-level failure that never got a response at all.
type TokenError struct {
	StatusCode       int
	ErrorCode        string
	ErrorDescription string
}

// nonRetryableTokenError wraps a token-response error that retrying can never fix: a malformed
// body or a well-formed-but-incomplete response. Distinct from *TokenError (a definitive rejection
// FROM the token endpoint, retryable only on 429/5xx) and from a plain network/build-request
// error (retryable by default) - see isRetryableTokenError.
type nonRetryableTokenError struct {
	err error
}

func (e *nonRetryableTokenError) Error() string { return e.err.Error() }
func (e *nonRetryableTokenError) Unwrap() error { return e.err }

func (e *TokenError) Error() string {
	switch {
	case e.ErrorDescription != "":
		return fmt.Sprintf("token endpoint returned %d %s: %s", e.StatusCode, e.ErrorCode, e.ErrorDescription)
	case e.ErrorCode != "":
		return fmt.Sprintf("token endpoint returned %d %s", e.StatusCode, e.ErrorCode)
	default:
		return fmt.Sprintf("token endpoint returned status %d", e.StatusCode)
	}
}

// clientAuthStyle mirrors clientAuthMethod as a type doTokenRequest can switch on.
type clientAuthStyle int

const (
	authStyleInHeader clientAuthStyle = iota // client_secret_basic: HTTP Basic auth
	authStyleInParams                        // client_secret_post: client_id/client_secret as form fields
)

// authStyleFor maps clientAuthMethod to the style doTokenRequest consumes.
func authStyleFor(method string) clientAuthStyle {
	if method == ClientAuthMethodPost {
		return authStyleInParams
	}
	return authStyleInHeader
}

// tokenJSON is the raw shape of an RFC 6749 §5.1 token response. ExpiresIn is left as
// json.RawMessage since some IdPs send it as a JSON string instead of a number.
type tokenJSON struct {
	AccessToken  string          `json:"access_token"`
	TokenType    string          `json:"token_type"`
	RefreshToken string          `json:"refresh_token"`
	ExpiresIn    json.RawMessage `json:"expires_in"`
}

func (t tokenJSON) expiresInSeconds() (int64, bool) {
	if len(t.ExpiresIn) == 0 {
		return 0, false
	}
	var n int64
	if err := json.Unmarshal(t.ExpiresIn, &n); err == nil {
		return n, true
	}
	var s string
	if err := json.Unmarshal(t.ExpiresIn, &s); err == nil {
		if n, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64); err == nil {
			return n, true
		}
	}
	return 0, false
}

// doTokenRequest POSTs form to tokenEndpoint and parses the response. style selects how the
// client authenticates (HTTP Basic header vs client_id/client_secret form fields); extraHeaders
// is applied last, skipping Authorization/Content-Type so it can never override them.
// clientID/clientSecret are form-urlencoded before being combined into the Basic credential
// (RFC 6749 Appendix B) - a raw base64(id+":"+secret) would mishandle a colon in either value.
func doTokenRequest(ctx context.Context, httpClient *http.Client, tokenEndpoint string, style clientAuthStyle,
	clientID, clientSecret string, form url.Values, extraHeaders map[string]string) (*Token, error) {
	if style == authStyleInParams {
		form.Set("client_id", clientID)
		form.Set("client_secret", clientSecret)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("build token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	for k, v := range extraHeaders {
		if strings.EqualFold(k, "Authorization") || strings.EqualFold(k, "Content-Type") {
			continue
		}
		req.Header.Set(k, v)
	}
	if style == authStyleInHeader {
		req.SetBasicAuth(url.QueryEscape(clientID), url.QueryEscape(clientSecret))
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("token request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxTokenResponseBytes+1))
	if err != nil {
		return nil, fmt.Errorf("reading token response: %w", err)
	}
	if len(body) > maxTokenResponseBytes {
		return nil, fmt.Errorf("token response exceeded %d bytes", maxTokenResponseBytes)
	}

	if resp.StatusCode != http.StatusOK {
		tokErr := &TokenError{StatusCode: resp.StatusCode}
		var errBody struct {
			Error            string `json:"error"`
			ErrorDescription string `json:"error_description"`
		}
		if json.Unmarshal(body, &errBody) == nil {
			tokErr.ErrorCode = errBody.Error
			tokErr.ErrorDescription = errBody.ErrorDescription
		}
		return nil, tokErr
	}

	var parsed tokenJSON
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, &nonRetryableTokenError{err: fmt.Errorf("decoding token response: %w", err)}
	}
	if parsed.AccessToken == "" {
		return nil, &nonRetryableTokenError{err: fmt.Errorf("token endpoint response is missing access_token")}
	}

	tok := &Token{
		AccessToken:  parsed.AccessToken,
		TokenType:    parsed.TokenType,
		RefreshToken: parsed.RefreshToken,
	}
	if tok.TokenType == "" {
		tok.TokenType = "Bearer"
	}
	if secs, ok := parsed.expiresInSeconds(); ok {
		tok.Expiry = time.Now().Add(time.Duration(secs) * time.Second)
	}
	return tok, nil
}

// fetchClientCredentialsToken implements RFC 6749 §4.4. tokenRequestParams (e.g. scope, audience)
// is forwarded verbatim into the request body.
func fetchClientCredentialsToken(ctx context.Context, httpClient *http.Client, p oauth2Params, style clientAuthStyle) (*Token, error) {
	form := toURLValues(p.tokenRequestParams)
	if form == nil {
		form = url.Values{}
	}
	form.Set("grant_type", GrantTypeClientCredentials)
	return doTokenRequest(ctx, httpClient, p.tokenEndpoint, style, p.clientID, p.clientSecret, form, p.tokenRequestHeaders)
}

// fetchPasswordToken implements the Resource Owner Password Credentials grant (RFC 6749 §4.3).
// grant_type/username/password are set after merging tokenRequestParams so they can't be overridden.
func fetchPasswordToken(ctx context.Context, httpClient *http.Client, p oauth2Params, style clientAuthStyle) (*Token, error) {
	form := toURLValues(p.tokenRequestParams)
	if form == nil {
		form = url.Values{}
	}
	form.Set("grant_type", GrantTypePassword)
	form.Set("username", p.username)
	form.Set("password", p.password)
	return doTokenRequest(ctx, httpClient, p.tokenEndpoint, style, p.clientID, p.clientSecret, form, p.tokenRequestHeaders)
}

// tokenFetcherFunc adapts a plain fetch function to TokenSource.
type tokenFetcherFunc func(ctx context.Context) (*Token, error)

func (f tokenFetcherFunc) Token(ctx context.Context) (*Token, error) { return f(ctx) }

// reuseTokenSource wraps a raw, IdP-fetching TokenSource with reuse: the same token is served
// until it's within buffer of expiry, at which point one caller refetches while the rest share its
// result via the same single-flight pattern as resilientTokenSource (see tokenCall) - the fetch
// itself runs with the lock released, so a waiting caller's own ctx cancellation is honored
// immediately instead of being blocked behind whichever caller is holding the lock.
type reuseTokenSource struct {
	mu     sync.Mutex
	fresh  TokenSource
	tok    *Token
	buffer time.Duration

	inFlight *tokenCall // non-nil while a refetch is running
}

func newReuseTokenSource(fresh TokenSource, buffer time.Duration) *reuseTokenSource {
	return &reuseTokenSource{fresh: fresh, buffer: buffer}
}

func (s *reuseTokenSource) Token(ctx context.Context) (*Token, error) {
	s.mu.Lock()
	if tokenFreshEnough(s.tok, s.buffer) {
		tok := s.tok
		s.mu.Unlock()
		return tok, nil
	}
	if call := s.inFlight; call != nil {
		s.mu.Unlock()
		select {
		case <-call.done:
			return call.tok, call.err
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	call := &tokenCall{done: make(chan struct{})}
	s.inFlight = call
	s.mu.Unlock()

	call.tok, call.err = s.fresh.Token(ctx)

	s.mu.Lock()
	if call.err == nil {
		s.tok = call.tok
	}
	s.inFlight = nil
	s.mu.Unlock()
	close(call.done)

	return call.tok, call.err
}

// oauth2Params bundles all extracted, validated policy params.
type oauth2Params struct {
	// bearerToken is the directly-supplied credential for the static-token auth path. Non-empty
	// here means the token-endpoint fields below are unused.
	bearerToken string

	grantType        string
	tokenEndpoint    string
	clientID         string
	clientSecret     string
	clientAuthMethod string
	username         string
	password         string

	// tokenRequestParams carries the whole map into the token request body.
	tokenRequestParams map[string]string

	// tokenRequestHeaders are extra headers sent with the token-endpoint request;
	// Authorization/Content-Type are dropped rather than honored.
	tokenRequestHeaders map[string]string

	// tokenRequestTimeout bounds the token-endpoint HTTP call.
	tokenRequestTimeout time.Duration

	// defaultTokenTTL is applied when the token response omits expires_in.
	defaultTokenTTL time.Duration

	// expiryBuffer is how far ahead of expiry a token is treated as stale, so a request never
	// goes upstream with a credential expiring mid-flight. Must match the caching layer's own
	// threshold (token_cache.go's tokenFreshEnough), or the two layers could disagree on
	// freshness. Unused when bearerToken is set.
	expiryBuffer time.Duration

	// tokenPurgeStatusCodes are the upstream response codes that purge the cached token. Forced
	// empty by GetPolicy when bearerToken is set.
	tokenPurgeStatusCodes map[int]struct{}

	// headerName and valuePrefix control where and how the credential is injected; apply to both auth paths.
	headerName  string
	valuePrefix string

	// proxyURL/tlsCaCert/tlsInsecureSkipVerify configure the token-endpoint HTTP client's
	// Transport; unused when bearerToken is set. tlsCaCert is the PEM CA content itself
	// (typically via {{ secret "handle" }}), not a filesystem path.
	proxyURL              string
	tlsCaCert             string
	tlsInsecureSkipVerify bool

	// tokenRequestMaxRetries bounds resilientTokenSource's retry of the token-endpoint fetch.
	tokenRequestMaxRetries int
}

// mode reports which of the two mutually exclusive auth paths p represents.
func (p oauth2Params) mode() string {
	if p.bearerToken != "" {
		return ModeStaticToken
	}
	return ModeTokenEndpoint
}

// Policy generates an upstream credential - either fetched via an OAuth2 grant
// (client_credentials or password) or a directly-supplied static one - and
// injects it into a configurable request header before forwarding.
type Policy struct {
	// mode records which of the two mutually exclusive auth paths this instance was configured for.
	mode string

	grantType        string
	tokenEndpoint    string
	clientID         string
	clientAuthMethod string

	// headerName and valuePrefix control where and how the credential is injected.
	headerName  string
	valuePrefix string

	// tokenSource supplies the credential to inject: a *redisCachingTokenSource for the
	// token-endpoint path, or a *staticTokenSource that always returns the configured token.
	tokenSource tokenProvider

	// Test seam - production code calls tokenSource.Token() directly; unit tests override this to
	// avoid a real network call, mirroring the retrieveCredentialsFunc pattern in aws-authentication.
	tokenFunc func(ctx context.Context) (*Token, error)

	// purgeStatusCodes are the upstream response codes that purge the cached token via
	// tokenSource.Purge(). Empty disables response-phase processing entirely (see Mode()).
	purgeStatusCodes map[int]struct{}
}

// staticTokenSource always returns the same configured token, no endpoint call or caching
// involved. Purge is a no-op: nothing cached to clear.
type staticTokenSource struct {
	bearerToken string
}

func (s *staticTokenSource) Token(context.Context) (*Token, error) {
	return &Token{AccessToken: s.bearerToken, TokenType: "Bearer"}, nil
}

func (s *staticTokenSource) Purge() {}

// credentialedURLPattern captures a "scheme://" prefix immediately followed by a "userinfo@"
// segment, so redactURLCredentials can strip just the latter.
var credentialedURLPattern = regexp.MustCompile(`([a-zA-Z][a-zA-Z0-9+.-]*://)[^/@\s]+@`)

// redactURLCredentials scrubs any "scheme://user:pass@" userinfo out of s, replacing it with
// "[REDACTED]" while leaving the rest of s intact. proxyURL supports embedded credentials, so
// this guards against a credential-bearing URL surfacing in an error message.
func redactURLCredentials(s string) string {
	return credentialedURLPattern.ReplaceAllString(s, "${1}[REDACTED]@")
}

// sanitizeEndpointForLogging reduces an operator-configured endpoint URL to scheme+host+path
// before it's logged. tokenEndpoint is user configuration and can carry sensitive URL components
// (embedded userinfo credentials, an API key or token in the query string), so log lines never
// emit it verbatim - only this reduced form. Falls back to a fixed placeholder rather than log the
// raw value when it doesn't even parse as a URL.
func sanitizeEndpointForLogging(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "[unparsable-endpoint]"
	}
	u.User = nil
	u.RawQuery = ""
	u.Fragment = ""
	return u.String()
}

// buildHeaderValue combines the prefix and credential with one space separator.
// Trailing spaces and tabs are removed here so callers do not need to normalize
// the prefix first. An empty prefix returns the raw credential.
func buildHeaderValue(prefix, token string) string {
	prefix = strings.TrimRight(prefix, " \t")

	if prefix == "" {
		return token
	}
	return prefix + " " + token
}

// GetPolicy is the v1alpha2 factory entry point (loaded by v1alpha2 kernels).
func GetPolicy(metadata policy.PolicyMetadata, params map[string]interface{}) (policy.Policy, error) {
	slog.Debug("OAuth2Generator: constructing policy from params")

	p, err := validateAndExtractParams(params)
	if err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}
	mode := p.mode()
	slog.Debug("OAuth2Generator: validated params", "mode", mode,
		"grantType", p.grantType, "tokenEndpoint", sanitizeEndpointForLogging(p.tokenEndpoint), "clientId", p.clientID,
		"clientAuthMethod", p.clientAuthMethod, "headerName", p.headerName)

	var tokenSource tokenProvider
	if mode == ModeStaticToken {
		// Nothing to fetch or cache. Also force tokenPurgeStatusCodes off - there's no fresher
		// token to fetch on a rejection.
		tokenSource = &staticTokenSource{bearerToken: p.bearerToken}
		p.tokenPurgeStatusCodes = map[int]struct{}{}
	} else {
		innerSource, err := buildTokenSource(p)
		if err != nil {
			return nil, err
		}
		tokenSource = newRedisCachingTokenSource(innerSource, extractCacheParams(params), p)
	}

	pol := &Policy{
		mode:             mode,
		grantType:        p.grantType,
		tokenEndpoint:    p.tokenEndpoint,
		clientID:         p.clientID,
		clientAuthMethod: p.clientAuthMethod,
		headerName:       p.headerName,
		valuePrefix:      p.valuePrefix,
		tokenSource:      tokenSource,
		purgeStatusCodes: p.tokenPurgeStatusCodes,
	}
	pol.tokenFunc = pol.tokenSource.Token

	slog.Debug("OAuth2Generator: policy initialized", "mode", pol.mode,
		"grantType", pol.grantType, "tokenEndpoint", sanitizeEndpointForLogging(pol.tokenEndpoint), "clientId", pol.clientID,
		"clientAuthMethod", pol.clientAuthMethod, "headerName", pol.headerName)

	return pol, nil
}

// buildTokenSource constructs the token source for the given grantType, wrapping the raw
// HTTP-fetching function in reuseTokenSource. Each new grant gets its own case here.
func buildTokenSource(p oauth2Params) (TokenSource, error) {
	style := authStyleFor(p.clientAuthMethod)

	// The Transport itself is shared across policy instances/rebuilds; only the *http.Client
	// wrapper (cheap) is rebuilt here.
	transport, err := getOrCreateTokenEndpointTransport(p)
	if err != nil {
		return nil, fmt.Errorf("invalid token endpoint transport config: %w", err)
	}
	httpClient := &http.Client{Timeout: p.tokenRequestTimeout, Transport: transport}

	switch p.grantType {
	case GrantTypeClientCredentials:
		raw := tokenFetcherFunc(func(ctx context.Context) (*Token, error) {
			return fetchClientCredentialsToken(ctx, httpClient, p, style)
		})
		return newReuseTokenSource(raw, p.expiryBuffer), nil

	case GrantTypePassword:
		raw := tokenFetcherFunc(func(ctx context.Context) (*Token, error) {
			return fetchPasswordToken(ctx, httpClient, p, style)
		})
		return newReuseTokenSource(raw, p.expiryBuffer), nil

	default:
		// Unreachable - validateAndExtractParams already rejects any other value.
		return nil, fmt.Errorf("unsupported grantType %q", p.grantType)
	}
}

// tokenEndpointTransportKey identifies a distinct token-endpoint HTTP client configuration.
// tlsCACert is the raw PEM content, not hashed - it's not sensitive like a client secret.
type tokenEndpointTransportKey struct {
	proxyURL              string
	tlsCACert             string
	tlsInsecureSkipVerify bool
}

// tokenEndpointTransports is the process-wide registry of shared *http.Transport values for the
// token-endpoint HTTP client, keyed by proxy/TLS configuration - mirrors redisClients (redis_clients.go).
var tokenEndpointTransports = newKeyedSingleton[tokenEndpointTransportKey, *http.Transport]()

// getOrCreateTokenEndpointTransport returns the process-wide shared Transport for this
// proxy/TLS configuration, building it on first use.
func getOrCreateTokenEndpointTransport(p oauth2Params) (*http.Transport, error) {
	key := tokenEndpointTransportKey{
		proxyURL:              p.proxyURL,
		tlsCACert:             p.tlsCaCert,
		tlsInsecureSkipVerify: p.tlsInsecureSkipVerify,
	}

	// build runs outside keyedSingleton's lock, so a slow build can't stall other instances.
	transport, _, err := tokenEndpointTransports.getOrCreate(key, func() (*http.Transport, error) {
		return buildTokenEndpointTransport(p)
	})
	return transport, err
}

// buildTokenEndpointTransport wires proxyURL and TLS settings into one Transport, setting Proxy
// explicitly alongside TLSClientConfig - an unset Transport.Proxy means "never proxy", it does
// not fall back to ProxyFromEnvironment. jwt-auth and opaque-token-auth each lost proxy support
// this exact way by setting only TLSClientConfig.
func buildTokenEndpointTransport(p oauth2Params) (*http.Transport, error) {
	proxyFunc := http.ProxyFromEnvironment
	if p.proxyURL != "" {
		proxyURL, err := url.Parse(p.proxyURL)
		if err != nil {
			// url.Error embeds the raw input verbatim, which could leak proxyURL's userinfo - scrub before wrapping.
			return nil, fmt.Errorf("invalid proxyURL: %s", redactURLCredentials(err.Error()))
		}
		proxyFunc = http.ProxyURL(proxyURL)
	}

	transport := &http.Transport{Proxy: proxyFunc}

	if p.tlsCaCert != "" || p.tlsInsecureSkipVerify {
		tlsConfig := &tls.Config{InsecureSkipVerify: p.tlsInsecureSkipVerify} //nolint:gosec // opt-in, logged at extraction time
		if p.tlsCaCert != "" {
			pool, err := parseCACertPool(p.tlsCaCert)
			if err != nil {
				return nil, fmt.Errorf("tlsCaCert: %w", err)
			}
			tlsConfig.RootCAs = pool
		}
		transport.TLSClientConfig = tlsConfig
	}

	return transport, nil
}

// parseCACertPool parses PEM-encoded CA certificate content into a pool that trusts only these
// CA(s), not the system's default public CAs - a deliberate, tighter trust boundary.
func parseCACertPool(pemContent string) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(pemContent)) {
		return nil, fmt.Errorf("no valid PEM certificates found in tlsCaCert")
	}
	return pool, nil
}

// resilientTokenSource wraps a real, IDP-fetching TokenSource with bounded retry for transient
// failures. Concurrent Token() calls are single-flighted: only one goroutine runs the
// retry-with-backoff sequence at a time, and every other caller shares its result instead of each
// launching a full retry loop against an already-struggling IdP. The shared fetch runs on the
// owner's ctx, so a joiner's own cancellation only affects itself, but the owner's cancellation
// ends the fetch for every joiner too.
type resilientTokenSource struct {
	inner      TokenSource
	maxRetries int

	mu       sync.Mutex
	inFlight *tokenCall // non-nil while a fetch-with-retry sequence is running
}

// tokenCall represents one in-flight (or just-completed) fetch-with-retry sequence, shared by
// every caller that arrived while it was running.
type tokenCall struct {
	done chan struct{}
	tok  *Token
	err  error
}

func (r *resilientTokenSource) Token(ctx context.Context) (*Token, error) {
	r.mu.Lock()
	if call := r.inFlight; call != nil {
		r.mu.Unlock()
		select {
		case <-call.done:
			return call.tok, call.err
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	call := &tokenCall{done: make(chan struct{})}
	r.inFlight = call
	r.mu.Unlock()

	call.tok, call.err = r.fetchWithRetry(ctx)

	r.mu.Lock()
	r.inFlight = nil
	r.mu.Unlock()
	close(call.done)

	return call.tok, call.err
}

// fetchWithRetry runs the actual retry-with-backoff sequence.
func (r *resilientTokenSource) fetchWithRetry(ctx context.Context) (*Token, error) {
	var lastErr error
	for attempt := 0; attempt <= r.maxRetries; attempt++ {
		if attempt > 0 {
			select {
			case <-time.After(retryBackoff(attempt)):
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		tok, err := r.inner.Token(ctx)
		if err == nil {
			return tok, nil
		}
		lastErr = err
		if !isRetryableTokenError(err) {
			return nil, err
		}
	}
	return nil, lastErr
}

// isRetryableTokenError classifies a token-fetch error as worth retrying. A *nonRetryableTokenError
// (malformed/incomplete response body) never succeeds by retrying unchanged. A *TokenError is only
// retryable on 429/5xx. Any other error (network failure, request build failure) didn't get a
// definitive rejection from the IdP and is retried by default.
func isRetryableTokenError(err error) bool {
	var nonRetryable *nonRetryableTokenError
	if errors.As(err, &nonRetryable) {
		return false
	}
	var tokErr *TokenError
	if errors.As(err, &tokErr) {
		return tokErr.StatusCode == http.StatusTooManyRequests || tokErr.StatusCode >= 500
	}
	return true
}

// retryBackoff returns the delay before retry attempt n (n >= 1): exponential from
// retryBaseDelay, capped at retryMaxDelay, plus up to 50% jitter to avoid lockstep retries.
func retryBackoff(attempt int) time.Duration {
	backoff := retryBaseDelay * time.Duration(uint64(1)<<uint(attempt-1))
	if backoff > retryMaxDelay || backoff <= 0 {
		backoff = retryMaxDelay
	}
	jitter := time.Duration(rand.Int63n(int64(backoff)/2 + 1))
	return backoff + jitter
}

// toURLValues converts a flat string map into url.Values, returning nil (not an empty map) when
// there's nothing to add.
func toURLValues(m map[string]string) url.Values {
	if len(m) == 0 {
		return nil
	}
	v := make(url.Values, len(m))
	for key, val := range m {
		v.Set(key, val)
	}
	return v
}

// Mode returns the processing mode. Response headers are processed only when purgeStatusCodes is non-empty.
func (p *Policy) Mode() policy.ProcessingMode {
	responseHeaderMode := policy.HeaderModeSkip
	if len(p.purgeStatusCodes) > 0 {
		responseHeaderMode = policy.HeaderModeProcess
	}
	return policy.ProcessingMode{
		RequestHeaderMode:  policy.HeaderModeProcess,
		RequestBodyMode:    policy.BodyModeSkip,
		ResponseHeaderMode: responseHeaderMode,
		ResponseBodyMode:   policy.BodyModeSkip,
	}
}

// getStringParam safely extracts a string parameter, returning "" if absent or the wrong type.
// Leading/trailing whitespace is trimmed since pasted credentials often carry a stray newline.
func getStringParam(params map[string]interface{}, key string) string {
	if val, ok := params[key]; ok {
		if str, ok := val.(string); ok {
			return strings.TrimSpace(str)
		}
	}
	return ""
}

// getStringParamOrDefault extracts a string parameter, falling back to def when the key is
// absent or the wrong type - but not when it's an explicitly empty string.
func getStringParamOrDefault(params map[string]interface{}, key, def string) string {
	val, ok := params[key]
	if !ok {
		return def
	}
	str, ok := val.(string)
	if !ok {
		return def
	}
	return strings.TrimSpace(str)
}

// getRequiredStringParam extracts a required, non-empty string parameter, trimmed per getStringParam.
func getRequiredStringParam(params map[string]interface{}, key string) (string, error) {
	val, ok := params[key]
	if !ok {
		return "", fmt.Errorf("'%s' parameter is required", key)
	}
	str, ok := val.(string)
	if !ok {
		return "", fmt.Errorf("'%s' must be a string", key)
	}
	str = strings.TrimSpace(str)
	if str == "" {
		return "", fmt.Errorf("'%s' cannot be empty", key)
	}
	return str, nil
}

// getBoolParam extracts an optional boolean parameter, falling back to def if absent or the wrong type.
func getBoolParam(params map[string]interface{}, key string, def bool) bool {
	if val, ok := params[key]; ok {
		if b, ok := val.(bool); ok {
			return b
		}
	}
	return def
}

// getIntParam extracts an optional integer parameter, tolerating int/int64/float64, falling back
// to def if absent, the wrong type, or negative.
func getIntParam(params map[string]interface{}, key string, def int) int {
	val, ok := params[key]
	if !ok {
		return def
	}
	var n int
	switch v := val.(type) {
	case int:
		n = v
	case int64:
		n = int(v)
	case float64:
		n = int(v)
	default:
		return def
	}
	if n < 0 {
		return def
	}
	return n
}

// getDurationParam extracts an optional Go-duration-formatted string parameter (e.g. "10s"),
// falling back to def if absent, the wrong type, or unparsable.
func getDurationParam(params map[string]interface{}, key string, def time.Duration) time.Duration {
	if val, ok := params[key]; ok {
		if str, ok := val.(string); ok {
			if d, err := time.ParseDuration(strings.TrimSpace(str)); err == nil {
				return d
			}
		}
	}
	return def
}

// getPositiveDurationParam is getDurationParam plus a non-positive guard, falling back to def
// when the parsed duration is <= 0. expiryBuffer deliberately doesn't use this - 0 is a valid
// value there (no early-refresh margin), unlike the durations that do.
func getPositiveDurationParam(params map[string]interface{}, key string, def time.Duration) time.Duration {
	d := getDurationParam(params, key, def)
	if d <= 0 {
		return def
	}
	return d
}

// getStringMapParam extracts an optional flat string-to-string map parameter by key. Absent or
// wrong-shaped input yields no entries rather than an error.
func getStringMapParam(params map[string]interface{}, key string) map[string]string {
	raw, ok := params[key]
	if !ok {
		return nil
	}
	m, ok := raw.(map[string]interface{})
	if !ok {
		return nil
	}
	out := make(map[string]string, len(m))
	for k, v := range m {
		if s, ok := v.(string); ok {
			if trimmed := strings.TrimSpace(s); trimmed != "" {
				out[k] = trimmed
			}
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// getPurgeStatusCodesParam extracts "tokenPurgeStatusCodes", falling back to def when absent or
// wrong-shaped. An explicit empty list ([]) is honored as-is, disabling purging entirely.
func getPurgeStatusCodesParam(params map[string]interface{}, key string, def []int) map[int]struct{} {
	codes := def
	if raw, ok := params[key]; ok {
		if arr, ok := raw.([]interface{}); ok {
			parsed := make([]int, 0, len(arr))
			for _, v := range arr {
				switch n := v.(type) {
				case int:
					parsed = append(parsed, n)
				case int64:
					parsed = append(parsed, int(n))
				case float64:
					parsed = append(parsed, int(n))
				case string:
					if code, err := strconv.Atoi(strings.TrimSpace(n)); err == nil {
						parsed = append(parsed, code)
					}
				}
			}
			codes = parsed
		}
	}
	set := make(map[int]struct{}, len(codes))
	for _, c := range codes {
		set[c] = struct{}{}
	}
	return set
}

// validateAndExtractParams validates and extracts all policy params. bearerToken and
// tokenEndpoint/clientId/clientSecret are mutually exclusive auth paths. grantType defaults to
// client_credentials; username/password are required only when grantType is password.
func validateAndExtractParams(params map[string]interface{}) (oauth2Params, error) {
	var p oauth2Params

	p.bearerToken = getStringParam(params, "bearerToken")
	tokenEndpointRaw := getStringParam(params, "tokenEndpoint")
	clientIDRaw := getStringParam(params, "clientId")
	clientSecretRaw := getStringParam(params, "clientSecret")
	hasTokenEndpointFields := tokenEndpointRaw != "" || clientIDRaw != "" || clientSecretRaw != ""

	switch {
	case p.bearerToken != "" && hasTokenEndpointFields:
		return oauth2Params{}, fmt.Errorf(
			"'bearerToken' cannot be combined with 'tokenEndpoint'/'clientId'/'clientSecret' - configure exactly one authentication path")
	case p.bearerToken == "" && !hasTokenEndpointFields:
		return oauth2Params{}, fmt.Errorf(
			"either 'bearerToken' or 'tokenEndpoint'+'clientId'+'clientSecret' must be configured")
	}

	p.headerName = getStringParamOrDefault(params, "headerName", defaultHeaderName)
	if p.headerName == "" {
		// Defensive only: policy-definition.yaml's minLength: 1 should already reject this.
		p.headerName = defaultHeaderName
	}
	p.valuePrefix = getStringParamOrDefault(params, "valuePrefix", defaultValuePrefix)

	if p.bearerToken != "" {
		return p, nil
	}

	p.grantType = getStringParam(params, "grantType")
	if p.grantType == "" {
		p.grantType = GrantTypeClientCredentials
	}
	if p.grantType != GrantTypeClientCredentials && p.grantType != GrantTypePassword {
		return oauth2Params{}, fmt.Errorf("'grantType' must be one of %q, %q", GrantTypeClientCredentials, GrantTypePassword)
	}

	p.clientAuthMethod = getStringParam(params, "clientAuthMethod")
	if p.clientAuthMethod == "" {
		p.clientAuthMethod = ClientAuthMethodBasic
	}
	if p.clientAuthMethod != ClientAuthMethodBasic && p.clientAuthMethod != ClientAuthMethodPost {
		return oauth2Params{}, fmt.Errorf("'clientAuthMethod' must be one of %q, %q", ClientAuthMethodBasic, ClientAuthMethodPost)
	}

	var err error
	p.tokenEndpoint, err = getRequiredStringParam(params, "tokenEndpoint")
	if err != nil {
		return oauth2Params{}, err
	}
	p.clientID, err = getRequiredStringParam(params, "clientId")
	if err != nil {
		return oauth2Params{}, err
	}
	p.clientSecret, err = getRequiredStringParam(params, "clientSecret")
	if err != nil {
		return oauth2Params{}, err
	}
	p.tokenRequestParams = getStringMapParam(params, "tokenRequestParams")
	p.tokenRequestHeaders = getStringMapParam(params, "tokenRequestHeaders")
	p.tokenRequestTimeout = getPositiveDurationParam(params, "tokenRequestTimeout", defaultTokenRequestTimeout)
	p.defaultTokenTTL = getPositiveDurationParam(params, "defaultTokenTTL", defaultTokenTTLFallback)
	p.expiryBuffer = getDurationParam(params, "expiryBuffer", defaultExpiryBuffer)
	if p.expiryBuffer < 0 {
		// A negative buffer has no sane meaning - fall back rather than invert the freshness check.
		p.expiryBuffer = defaultExpiryBuffer
	}
	p.tokenPurgeStatusCodes = getPurgeStatusCodesParam(params, "tokenPurgeStatusCodes", defaultPurgeStatusCodes)

	p.proxyURL = getStringParam(params, "proxyURL")
	p.tlsCaCert = getStringParam(params, "tlsCaCert")
	p.tlsInsecureSkipVerify = getBoolParam(params, "tlsInsecureSkipVerify", false)
	if p.tlsInsecureSkipVerify {
		slog.Warn("OAuth2Generator: tlsInsecureSkipVerify is enabled - TLS certificate verification for the token endpoint is disabled; this must never be used against a real identity provider")
	}

	p.tokenRequestMaxRetries = getIntParam(params, "tokenRequestMaxRetries", defaultTokenRequestMaxRetries)

	if p.grantType == GrantTypePassword {
		p.username, err = getRequiredStringParam(params, "username")
		if err != nil {
			return oauth2Params{}, err
		}
		p.password, err = getRequiredStringParam(params, "password")
		if err != nil {
			return oauth2Params{}, err
		}
	}

	return p, nil
}

// OnRequestHeaders obtains the credential and injects it into headerName before the request is
// forwarded to the upstream backend.
func (p *Policy) OnRequestHeaders(ctx context.Context, reqCtx *policy.RequestHeaderContext, _ map[string]interface{}) policy.RequestHeaderAction {
	slog.Debug("OAuth2Generator: authenticating outbound request", "method", reqCtx.Method, "path", reqCtx.Path,
		"mode", p.mode, "grantType", p.grantType, "tokenEndpoint", sanitizeEndpointForLogging(p.tokenEndpoint), "clientId", p.clientID)

	tok, err := p.retrieveToken(ctx)
	if err != nil {
		return p.authFailure(reqCtx.SharedContext, "failed to obtain upstream credential", err)
	}

	p.authSuccess(reqCtx.SharedContext)

	return policy.UpstreamRequestHeaderModifications{
		HeadersToSet: map[string]string{
			p.headerName: buildHeaderValue(p.valuePrefix, tok.AccessToken),
		},
	}
}

// OnResponseHeaders purges the cached token when the upstream responds with one of
// purgeStatusCodes (default: 401). Doesn't retry the current request; only reached when
// purgeStatusCodes is non-empty.
func (p *Policy) OnResponseHeaders(ctx context.Context, respCtx *policy.ResponseHeaderContext, _ map[string]interface{}) policy.ResponseHeaderAction {
	if _, purge := p.purgeStatusCodes[respCtx.ResponseStatus]; purge {
		slog.Warn("OAuth2Generator: upstream rejected the cached token, purging it for the next request",
			"status", respCtx.ResponseStatus, "grantType", p.grantType, "tokenEndpoint", sanitizeEndpointForLogging(p.tokenEndpoint), "clientId", p.clientID)
		p.tokenSource.Purge()
	}
	return policy.DownstreamResponseHeaderModifications{}
}

// retrieveToken fetches the current (possibly cached/refreshed) access token from the token
// source built once in GetPolicy.
func (p *Policy) retrieveToken(ctx context.Context) (*Token, error) {
	fetch := p.tokenFunc
	if fetch == nil {
		fetch = p.tokenSource.Token
	}
	return fetch(ctx)
}

// authType returns the AuthContext.AuthType value for this instance's mode.
func (p *Policy) authType() string {
	if p.mode == ModeStaticToken {
		return AuthTypeStaticToken
	}
	return AuthType
}

// credentialID returns the AuthContext.CredentialID value for this instance's mode.
func (p *Policy) credentialID() string {
	if p.mode == ModeStaticToken {
		return "static-token"
	}
	return p.clientID
}

// authProperties returns the AuthContext.Properties for this instance's mode.
func (p *Policy) authProperties() map[string]string {
	props := map[string]string{"mode": p.mode}
	if p.mode == ModeTokenEndpoint {
		props["grantType"] = p.grantType
		props["tokenEndpoint"] = p.tokenEndpoint
	}
	return props
}

// authFailure builds a 502 Bad Gateway ImmediateResponse for gateway-side credential-acquisition
// failures. 502 (not 401) is deliberate: it's the gateway's own upstream credentials or the token
// endpoint that failed, not a client-auth rejection.
func (p *Policy) authFailure(shared *policy.SharedContext, reason string, cause error) policy.RequestHeaderAction {
	slog.Error("OAuth2Generator: credential acquisition failed", "reason", reason, "error", redactURLCredentials(cause.Error()),
		"mode", p.mode, "grantType", p.grantType, "tokenEndpoint", sanitizeEndpointForLogging(p.tokenEndpoint), "clientId", p.clientID)

	shared.AuthContext = &policy.AuthContext{
		Authenticated: false,
		AuthType:      p.authType(),
		CredentialID:  p.credentialID(),
		Properties:    p.authProperties(),
		Previous:      shared.AuthContext,
	}

	body, _ := json.Marshal(map[string]string{
		"error":   "Bad Gateway",
		"message": "failed to authenticate request to upstream service",
	})
	return policy.ImmediateResponse{
		StatusCode: http.StatusBadGateway,
		Headers:    map[string]string{"Content-Type": "application/json"},
		Body:       body,
	}
}

// authSuccess records a successful credential injection in the shared AuthContext, preserving
// any existing chain via Previous.
func (p *Policy) authSuccess(shared *policy.SharedContext) {
	shared.AuthContext = &policy.AuthContext{
		Authenticated: true,
		AuthType:      p.authType(),
		CredentialID:  p.credentialID(),
		Properties:    p.authProperties(),
		Previous:      shared.AuthContext,
	}
}
