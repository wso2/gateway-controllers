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

package cors

import (
	"context"
	"fmt"
	"log/slog"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

type CorsPolicy struct {
	AllowedOrigins         []string
	CompiledAllowedOrigins []*regexp.Regexp
	AllowedMethods         []string
	AllowedHeaders         []string
	ExposedHeaders         []string
	MaxAge                 *int
	AllowCredentials       *bool
	ForwardPreflight       bool
	// RejectDisallowedOrigins answers a non-preflight request whose Origin is not
	// allowed with 403 instead of forwarding it without CORS headers. Browsers
	// apply CORS only to what a page may read, not to whether the request reaches
	// the backend, and never to a WebSocket handshake — so this is what stops a
	// page on another origin from using a user's cookies against the API
	// (cross-site WebSocket hijacking, or a cross-origin request with side effects).
	RejectDisallowedOrigins bool
	// RejectMissingOrigin also answers a request with no Origin header with 403.
	// Browsers send Origin on every WebSocket handshake and cross-origin request,
	// but omit it on ordinary same-origin GET and HEAD requests (page navigations
	// among them), so this can turn away browser traffic as well as non-browser
	// clients.
	RejectMissingOrigin bool
}

// GetPolicy is the v1alpha2 factory entry point (loaded by v1alpha2 kernels).
func GetPolicy(
	metadata policy.PolicyMetadata,
	params map[string]interface{},
) (policy.Policy, error) {
	slog.Debug("Cors Policy: GetPolicy called")
	p := &CorsPolicy{}
	p.AllowedOrigins = getStringArrayParam(params, "allowedOrigins", []string{"*"})
	if slices.Contains(p.AllowedOrigins, "*") {
		slog.Debug("Ignoring other origins as wildcard is included")
		p.AllowedOrigins = []string{"*"}
	}
	p.AllowedMethods = getStringArrayParam(params, "allowedMethods", []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"})
	p.AllowedHeaders = getStringArrayParam(params, "allowedHeaders", []string{})
	if slices.Contains(p.AllowedHeaders, "*") {
		slog.Debug("Ignoring other headers as wildcard is included")
		p.AllowedHeaders = []string{"*"}
	}
	p.ExposedHeaders = getStringArrayParam(params, "exposedHeaders", nil)

	if v, ok := params["maxAge"]; ok {
		if i, ok := v.(int); ok {
			val := i
			p.MaxAge = &val
		} else if f, ok := v.(float64); ok {
			val := int(f)
			p.MaxAge = &val
		}
	}

	val, ok := params["allowCredentials"]
	if ok {
		if b, ok := val.(bool); ok {
			p.AllowCredentials = &b
		}
	}

	if p.AllowCredentials != nil && *p.AllowCredentials {
		// As per CORS spec, wildcard cannot be used with allow-credentials
		if len(p.AllowedOrigins) == 1 && p.AllowedOrigins[0] == "*" {
			slog.Debug("Cannot have wildcard origin with allowCredentials set to true")
			return nil, fmt.Errorf("cannot have wildcard origin with allowCredentials set to true")
		} else if len(p.AllowedHeaders) == 1 && p.AllowedHeaders[0] == "*" {
			slog.Debug("Cannot have wildcard headers with allowCredentials set to true")
			return nil, fmt.Errorf("cannot have wildcard headers with allowCredentials set to true")
		} else if len(p.AllowedMethods) == 1 && p.AllowedMethods[0] == "*" {
			slog.Debug("Cannot have wildcard methods with allowCredentials set to true")
			return nil, fmt.Errorf("cannot have wildcard methods with allowCredentials set to true")
		} else if len(p.ExposedHeaders) == 1 && p.ExposedHeaders[0] == "*" {
			slog.Debug("Cannot have wildcard exposed headers with allowCredentials set to true")
			return nil, fmt.Errorf("cannot have wildcard exposed headers with allowCredentials set to true")
		}
	}

	val, ok = params["forwardPreflight"]
	if ok {
		if b, ok := val.(bool); ok {
			p.ForwardPreflight = b
		}
	} else {
		p.ForwardPreflight = false
	}

	p.RejectDisallowedOrigins = getBoolParam(params, "rejectDisallowedOrigins")
	p.RejectMissingOrigin = getBoolParam(params, "rejectMissingOrigin")
	if p.RejectDisallowedOrigins && len(p.AllowedOrigins) == 1 && p.AllowedOrigins[0] == "*" {
		// Rejecting disallowed origins while allowing every origin rejects nothing:
		// refuse it rather than let it look like an active defence.
		return nil, fmt.Errorf("rejectDisallowedOrigins requires allowedOrigins to list origins instead of \"*\"")
	}

	for _, origin := range p.AllowedOrigins {
		if origin == "*" {
			continue
		}
		if p.RejectDisallowedOrigins {
			if err := validateEnforcedOrigin(origin); err != nil {
				return nil, fmt.Errorf("invalid allowed origin %q: %w", origin, err)
			}
		}
		regex, err := compileAllowedOrigin(origin)
		if err != nil {
			slog.Debug("Invalid allowed origin", "origin", origin, "error", err)
			return nil, fmt.Errorf("invalid allowed origin %q: %w", origin, err)
		}
		p.CompiledAllowedOrigins = append(p.CompiledAllowedOrigins, regex)
	}

	return p, nil
}

// getBoolParam reads an optional boolean parameter, false when absent.
func getBoolParam(params map[string]interface{}, key string) bool {
	b, _ := params[key].(bool)
	return b
}

// validateEnforcedOrigin requires an allowed origin to be a serialized origin as
// a browser sends it — an http or https scheme and a host, optionally a port,
// with nothing else — or the subdomain-wildcard form of one. Once requests are
// rejected on a mismatch, an entry with a path, query or trailing slash would
// silently admit nothing, and "null" — sent by sandboxed and file:// documents —
// would admit any such page.
func validateEnforcedOrigin(origin string) error {
	if strings.EqualFold(origin, "null") {
		return fmt.Errorf("the \"null\" origin cannot be allowed while rejectDisallowedOrigins is set")
	}
	candidate := origin
	if scheme, suffix, isWildcard := strings.Cut(origin, "://*."); isWildcard {
		if suffix == "" || strings.HasPrefix(suffix, ":") {
			return fmt.Errorf("must be scheme://host[:port] with no path, query, fragment or credentials")
		}
		candidate = scheme + "://wildcard." + suffix
	}
	u, err := url.Parse(candidate)
	if err != nil {
		return err
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("scheme must be http or https")
	}
	// A browser never puts an IPv6 zone identifier in an Origin, so an entry
	// with one could never match.
	if u.Hostname() == "" || strings.Contains(u.Hostname(), "%") || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return fmt.Errorf("must be scheme://host[:port] with no path, query, fragment or credentials")
	}
	// A browser serializes the port as a plain decimal number, so an entry with
	// an out-of-range port, a leading zero or an empty port could never match.
	if port := u.Port(); port != "" || strings.HasSuffix(u.Host, ":") {
		if n, err := strconv.Atoi(port); err != nil || n > 65535 || (len(port) > 1 && port[0] == '0') {
			return fmt.Errorf("port must be a number from 0 to 65535 with no leading zeros")
		}
	}
	return nil
}

// compileAllowedOrigin matches configured origins literally, except for
// scheme-specific subdomain wildcards. Every expression is anchored so a
// matching origin cannot be embedded in a different host, path, or query.
func compileAllowedOrigin(origin string) (*regexp.Regexp, error) {
	if pattern, isWildcard := subdomainWildcardPattern(origin); isWildcard {
		return regexp.Compile(`\A(?:` + pattern + `)\z`)
	}

	pattern := regexp.QuoteMeta(origin)
	return regexp.Compile(`\A(?:` + pattern + `)\z`)
}

// subdomainWildcardPattern converts <scheme>://*.example.com[:port] into a
// full-match pattern. The configured scheme and suffix remain literal, while
// the wildcard accepts one or more subdomain levels but no URL delimiters.
func subdomainWildcardPattern(origin string) (string, bool) {
	const wildcardMarker = "://*."
	scheme, suffix, isWildcard := strings.Cut(origin, wildcardMarker)
	if !isWildcard || scheme == "" || suffix == "" {
		return "", false
	}

	const subdomains = `[^/:?#@]+`
	pattern := regexp.QuoteMeta(scheme) + `://` + subdomains + `\.` + regexp.QuoteMeta(suffix)
	return pattern, true
}

func (p *CorsPolicy) Mode() policy.ProcessingMode {
	return policy.ProcessingMode{
		RequestHeaderMode:  policy.HeaderModeProcess,
		RequestBodyMode:    policy.BodyModeSkip,
		ResponseHeaderMode: policy.HeaderModeProcess,
		ResponseBodyMode:   policy.BodyModeSkip,
	}
}

func getStringArrayParam(params map[string]any, key string, defaultValue []string) []string {
	if v, ok := params[key]; ok {
		if arr, ok := v.([]any); ok {
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

// OnRequestHeaders handles CORS in the request header phase.
func (p *CorsPolicy) OnRequestHeaders(ctx context.Context, reqCtx *policy.RequestHeaderContext, params map[string]any) policy.RequestHeaderAction {
	// Base the Origin / preflight decision on the downstream snapshot so
	// a peer policy that rewrites Origin during the header phase cannot change the
	// CORS verdict for what the client actually sent.
	ds := reqCtx.DownstreamRequest()
	if strings.EqualFold(ds.Method, "options") {
		// Only an OPTIONS carrying Access-Control-Request-Method is a CORS
		// preflight. Any other OPTIONS is an ordinary request, so the reject
		// options apply to it as they do to every non-preflight method.
		if len(ds.Headers.Get("Access-Control-Request-Method")) == 0 && p.rejectsOrigin(ds.Headers) {
			slog.Debug("CORS: Rejecting non-preflight OPTIONS from a disallowed or missing origin")
			return rejectedOriginResponse()
		}
		// A failed preflight is answered without CORS headers, which browsers
		// already treat as a refusal. With forwardPreflight it would instead
		// reach the backend, which a disallowed origin must not do while
		// rejectDisallowedOrigins is set.
		if p.ForwardPreflight && p.RejectDisallowedOrigins {
			if origin := ds.Headers.Get("Origin"); len(origin) > 0 && !p.isOriginAllowed(origin[0]) {
				slog.Debug("CORS: Rejecting forwarded preflight from a disallowed origin")
				return rejectedOriginResponse()
			}
		}
		slog.Debug("CORS: Preflight request detected in header phase; handling preflight")
		return p.handlePreflightHeaders(ds.Headers)
	}
	if p.rejectsOrigin(ds.Headers) {
		slog.Debug("CORS: Rejecting non-preflight request from a disallowed or missing origin")
		return rejectedOriginResponse()
	}
	corsHeaders, ok := p.handleNonPreflightHeaders(ds.Headers)
	if ok {
		slog.Debug("CORS: Adding CORS headers to non-preflight request")
		reqCtx.Metadata["cors_headers"] = corsHeaders
	} else {
		slog.Debug("CORS: No CORS headers to add for non-preflight request")
		if ds.Headers.Has("Origin") {
			reqCtx.Metadata["cors_strip"] = true
		}
	}
	return policy.UpstreamRequestHeaderModifications{}
}

// rejectsOrigin reports whether a non-preflight request must be refused: a
// missing Origin when RejectMissingOrigin is set, or an Origin that is not
// allowed when RejectDisallowedOrigins is set. Only the first Origin value is
// considered; a request legitimately carries at most one.
func (p *CorsPolicy) rejectsOrigin(headers *policy.Headers) bool {
	origin := headers.Get("Origin")
	if len(origin) == 0 {
		return p.RejectMissingOrigin
	}
	if !p.RejectDisallowedOrigins {
		return false
	}
	return !p.isOriginAllowed(origin[0])
}

// rejectedOriginResponse is the single answer to every rejected origin — missing
// or disallowed — so it never reveals which origins are allowed.
func rejectedOriginResponse() policy.ImmediateResponse {
	return policy.ImmediateResponse{
		StatusCode: 403,
		Headers:    map[string]string{"content-type": "application/json"},
		Body:       []byte(`{"error":"forbidden","message":"Origin not allowed."}`),
	}
}

// OnResponseHeaders sets CORS headers on the response in the header phase.
func (p *CorsPolicy) OnResponseHeaders(ctx context.Context, respCtx *policy.ResponseHeaderContext, params map[string]any) policy.ResponseHeaderAction {
	corsHeaders, ok := respCtx.Metadata["cors_headers"].(map[string]string)
	if ok {
		slog.Debug("CORS: Adding CORS headers to response in header phase")
		return policy.DownstreamResponseHeaderModifications{
			HeadersToSet: corsHeaders,
		}
	}
	if _, strip := respCtx.Metadata["cors_strip"]; strip {
		slog.Debug("CORS: Stripping upstream CORS headers for disallowed origin in header phase")
		return policy.DownstreamResponseHeaderModifications{
			HeadersToRemove: []string{
				"Access-Control-Allow-Origin",
				"Access-Control-Allow-Credentials",
				"Access-Control-Expose-Headers",
			},
		}
	}
	slog.Debug("CORS: No CORS headers to add to response in header phase")
	return policy.DownstreamResponseHeaderModifications{}
}

// handlePreflightHeaders processes CORS preflight (OPTIONS) requests using raw headers.
func (p *CorsPolicy) handlePreflightHeaders(requestHeaders *policy.Headers) policy.RequestHeaderAction {
	origin := requestHeaders.Get("Origin")

	isCorsFailure := false
	headers := make(map[string]string)

	requestedMethod := requestHeaders.Get("Access-Control-Request-Method")
	requestedHeaders := requestHeaders.Get("Access-Control-Request-Headers")

	originAllowed := false
	if len(p.AllowedOrigins) > 0 {
		if p.AllowedOrigins[0] == "*" {
			headers["Access-Control-Allow-Origin"] = "*"
			originAllowed = true
		} else if len(origin) > 0 && p.isOriginAllowed(origin[0]) {
			headers["Access-Control-Allow-Origin"] = origin[0]
			headers["Vary"] = "Origin"
			originAllowed = true
		}
	}
	if !originAllowed {
		isCorsFailure = true
	}

	methodAllowed := false
	if len(p.AllowedMethods) > 0 {
		if p.AllowedMethods[0] == "*" {
			headers["Access-Control-Allow-Methods"] = "*"
			methodAllowed = true
		} else if len(requestedMethod) > 0 {
			if slices.Contains(p.AllowedMethods, requestedMethod[0]) {
				headers["Access-Control-Allow-Methods"] = strings.Join(p.AllowedMethods, ",")
				methodAllowed = true
			}
		}
	}
	if !methodAllowed {
		isCorsFailure = true
	}

	headersAllowed := false
	if len(p.AllowedHeaders) > 0 {
		if p.AllowedHeaders[0] == "*" {
			if len(requestedHeaders) > 0 {
				headers["Access-Control-Allow-Headers"] = requestedHeaders[0]
			}
			headersAllowed = true
		} else if len(requestedHeaders) > 0 {
			var checkedHeaders []string
			requestedList := strings.Split(requestedHeaders[0], ",")
			allowedCount := 0
			for _, allowedHeader := range p.AllowedHeaders {
				for _, requestedHeader := range requestedList {
					if strings.EqualFold(strings.TrimSpace(allowedHeader), strings.TrimSpace(requestedHeader)) {
						checkedHeaders = append(checkedHeaders, allowedHeader)
						allowedCount++
					}
				}
			}
			if len(requestedList) == allowedCount {
				headers["Access-Control-Allow-Headers"] = strings.Join(checkedHeaders, ",")
				headersAllowed = true
			}
		}
	}

	if !headersAllowed && len(requestedHeaders) > 0 {
		isCorsFailure = true
	}

	if p.MaxAge != nil {
		headers["Access-Control-Max-Age"] = fmt.Sprintf("%d", *p.MaxAge)
	}

	if p.AllowCredentials != nil {
		headers["Access-Control-Allow-Credentials"] = fmt.Sprintf("%t", *p.AllowCredentials)
	}

	if isCorsFailure {
		headers = make(map[string]string)
		if p.ForwardPreflight {
			return policy.UpstreamRequestHeaderModifications{}
		}
	}

	return policy.ImmediateResponse{
		StatusCode: 204,
		Headers:    headers,
		Body:       nil,
	}
}

// handleNonPreflightHeaders adds CORS headers for actual (non-preflight) requests using raw headers.
func (p *CorsPolicy) handleNonPreflightHeaders(requestHeaders *policy.Headers) (map[string]string, bool) {
	headersToInclude := make(map[string]string)

	origin := requestHeaders.Get("Origin")

	originAllowed := false
	if len(p.AllowedOrigins) > 0 {
		if p.AllowedOrigins[0] == "*" {
			headersToInclude["Access-Control-Allow-Origin"] = "*"
			originAllowed = true
		} else if len(origin) > 0 && p.isOriginAllowed(origin[0]) {
			headersToInclude["Access-Control-Allow-Origin"] = origin[0]
			headersToInclude["Vary"] = "Origin"
			originAllowed = true
		}
	}

	if !originAllowed {
		return nil, false
	}

	if len(p.ExposedHeaders) > 0 {
		headersToInclude["Access-Control-Expose-Headers"] = strings.Join(p.ExposedHeaders, ",")
	}

	if p.AllowCredentials != nil {
		headersToInclude["Access-Control-Allow-Credentials"] = fmt.Sprintf("%t", *p.AllowCredentials)
	}

	return headersToInclude, true
}

func (p *CorsPolicy) isOriginAllowed(origin string) bool {
	for _, allowedOrigin := range p.CompiledAllowedOrigins {
		if allowedOrigin.MatchString(origin) {
			return true
		}
	}
	return false
}
