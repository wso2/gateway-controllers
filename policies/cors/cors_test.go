package cors

import (
	"context"
	"os"
	"reflect"
	"regexp"
	"strings"
	"testing"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

func TestCorsPolicy_GetPolicy_Defaults(t *testing.T) {
	p := mustGetCorsPolicy(t, map[string]any{})

	if !reflect.DeepEqual(p.AllowedOrigins, []string{"*"}) {
		t.Fatalf("unexpected allowedOrigins: %v", p.AllowedOrigins)
	}
	if !reflect.DeepEqual(p.AllowedMethods, []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"}) {
		t.Fatalf("unexpected allowedMethods: %v", p.AllowedMethods)
	}
	if !reflect.DeepEqual(p.AllowedHeaders, []string{}) {
		t.Fatalf("unexpected allowedHeaders: %v", p.AllowedHeaders)
	}
	if p.ExposedHeaders != nil {
		t.Fatalf("expected exposedHeaders=nil by runtime default, got %v", p.ExposedHeaders)
	}
	if p.MaxAge != nil {
		t.Fatalf("expected maxAge=nil by runtime default, got %v", *p.MaxAge)
	}
	if p.AllowCredentials != nil {
		t.Fatalf("expected allowCredentials=nil by runtime default, got %v", *p.AllowCredentials)
	}
	if p.ForwardPreflight {
		t.Fatalf("expected forwardPreflight=false by default")
	}
}

func TestCorsPolicy_GetPolicy_NormalizesWildcardLists(t *testing.T) {
	p := mustGetCorsPolicy(t, map[string]any{
		"allowedOrigins": []any{"https://a.example.com", "*", "https://b.example.com"},
		"allowedHeaders": []any{"X-Trace-Id", "*", "Authorization"},
	})

	if !reflect.DeepEqual(p.AllowedOrigins, []string{"*"}) {
		t.Fatalf("expected wildcard-only origins, got %v", p.AllowedOrigins)
	}
	if !reflect.DeepEqual(p.AllowedHeaders, []string{"*"}) {
		t.Fatalf("expected wildcard-only headers, got %v", p.AllowedHeaders)
	}
}

func TestCorsPolicy_GetPolicy_AllowCredentialsWildcardRejections(t *testing.T) {
	tests := []struct {
		name           string
		params         map[string]any
		wantErrContain string
	}{
		{
			name: "origins wildcard",
			params: map[string]any{
				"allowCredentials": true,
				"allowedOrigins":   []any{"*"},
				"allowedMethods":   []any{"GET"},
				"allowedHeaders":   []any{"x-api-key"},
			},
			wantErrContain: "cannot have wildcard origin",
		},
		{
			name: "headers wildcard",
			params: map[string]any{
				"allowCredentials": true,
				"allowedOrigins":   []any{"https://allowed.example.com"},
				"allowedMethods":   []any{"GET"},
				"allowedHeaders":   []any{"*"},
			},
			wantErrContain: "cannot have wildcard headers",
		},
		{
			name: "methods wildcard",
			params: map[string]any{
				"allowCredentials": true,
				"allowedOrigins":   []any{"https://allowed.example.com"},
				"allowedMethods":   []any{"*"},
				"allowedHeaders":   []any{"x-api-key"},
			},
			wantErrContain: "cannot have wildcard methods",
		},
		{
			name: "exposed headers wildcard",
			params: map[string]any{
				"allowCredentials": true,
				"allowedOrigins":   []any{"https://allowed.example.com"},
				"allowedMethods":   []any{"GET"},
				"allowedHeaders":   []any{"x-api-key"},
				"exposedHeaders":   []any{"*"},
			},
			wantErrContain: "cannot have wildcard exposed headers",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := GetPolicy(policy.PolicyMetadata{}, tt.params)
			if err == nil {
				t.Fatalf("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tt.wantErrContain) {
				t.Fatalf("error mismatch: got %q, want contain %q", err.Error(), tt.wantErrContain)
			}
		})
	}
}

func TestCorsPolicy_GetPolicy_ExactOriginDoesNotMatchLookalikes(t *testing.T) {
	p := mustGetCorsPolicy(t, map[string]any{
		"allowedOrigins": []any{"https://abc.xyz.com"},
	})

	tests := []struct {
		origin  string
		allowed bool
	}{
		{origin: "https://abc.xyz.com", allowed: true},
		{origin: "https://abc.xyz.com.evil.io", allowed: false},
		{origin: "https://abcXxyz.com", allowed: false},
		{origin: "https://evil.com/?x=https://abc.xyz.com", allowed: false},
	}

	for _, tt := range tests {
		t.Run(tt.origin, func(t *testing.T) {
			if got := p.isOriginAllowed(tt.origin); got != tt.allowed {
				t.Fatalf("isOriginAllowed(%q) = %t, want %t", tt.origin, got, tt.allowed)
			}
		})
	}
}

func TestCorsPolicy_GetPolicy_SubdomainWildcard(t *testing.T) {
	p := mustGetCorsPolicy(t, map[string]any{
		"allowedOrigins": []any{"http://*.abc.com"},
	})

	tests := []struct {
		origin  string
		allowed bool
	}{
		{origin: "http://api.abc.com", allowed: true},
		{origin: "http://one.two.abc.com", allowed: true},
		{origin: "https://api.abc.com", allowed: false},
		{origin: "http://abc.com", allowed: false},
		{origin: "http://api.abc.com:8443", allowed: false},
		{origin: "http://api.abc.com.evil.io", allowed: false},
		{origin: "http://evilabc.com", allowed: false},
		{origin: "http://evil.com?x=api.abc.com", allowed: false},
		{origin: "http://evil.com/api.abc.com", allowed: false},
	}

	for _, tt := range tests {
		t.Run(tt.origin, func(t *testing.T) {
			if got := p.isOriginAllowed(tt.origin); got != tt.allowed {
				t.Fatalf("isOriginAllowed(%q) = %t, want %t", tt.origin, got, tt.allowed)
			}
		})
	}
}

func TestCorsPolicy_GetPolicy_SubdomainWildcardWithPort(t *testing.T) {
	p := mustGetCorsPolicy(t, map[string]any{
		"allowedOrigins": []any{"https://*.abc.com:8443"},
	})

	tests := []struct {
		origin  string
		allowed bool
	}{
		{origin: "https://one.two.abc.com:8443", allowed: true},
		{origin: "http://api.abc.com:8443", allowed: false},
		{origin: "https://api.abc.com", allowed: false},
		{origin: "https://api.abc.com:9443", allowed: false},
		{origin: "https://abc.com:8443", allowed: false},
	}

	for _, tt := range tests {
		t.Run(tt.origin, func(t *testing.T) {
			if got := p.isOriginAllowed(tt.origin); got != tt.allowed {
				t.Fatalf("isOriginAllowed(%q) = %t, want %t", tt.origin, got, tt.allowed)
			}
		})
	}
}

func TestCorsPolicy_GetPolicy_MaxAgeFromFloatAndInt(t *testing.T) {
	p1 := mustGetCorsPolicy(t, map[string]any{"maxAge": 120})
	if p1.MaxAge == nil || *p1.MaxAge != 120 {
		t.Fatalf("expected maxAge=120 from int, got %v", p1.MaxAge)
	}

	p2 := mustGetCorsPolicy(t, map[string]any{"maxAge": float64(90)})
	if p2.MaxAge == nil || *p2.MaxAge != 90 {
		t.Fatalf("expected maxAge=90 from float64, got %v", p2.MaxAge)
	}
}

func TestCorsPolicy_OnRequestHeaders_PreflightSuccess(t *testing.T) {
	p := mustGetCorsPolicy(t, map[string]any{
		"allowedOrigins":   []any{"*"},
		"allowedMethods":   []any{"GET", "POST"},
		"allowedHeaders":   []any{"*"},
		"allowCredentials": false,
		"maxAge":           3600,
	})

	ctx := newCorsRequestHeaderContext("OPTIONS", map[string][]string{
		"Origin":                        {"https://client.example.com"},
		"Access-Control-Request-Method": {"GET"},
		"Access-Control-Request-Headers": {
			"x-api-key, x-trace-id",
		},
	})

	action := p.OnRequestHeaders(context.Background(), ctx, nil)
	resp, ok := action.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("expected ImmediateResponse, got %T", action)
	}
	if resp.StatusCode != 204 {
		t.Fatalf("expected 204, got %d", resp.StatusCode)
	}
	if resp.Headers["Access-Control-Allow-Origin"] != "*" {
		t.Fatalf("unexpected allow-origin header: %q", resp.Headers["Access-Control-Allow-Origin"])
	}
	if resp.Headers["Access-Control-Allow-Methods"] != "GET,POST" {
		t.Fatalf("unexpected allow-methods header: %q", resp.Headers["Access-Control-Allow-Methods"])
	}
	if resp.Headers["Access-Control-Allow-Headers"] != "x-api-key, x-trace-id" {
		t.Fatalf("unexpected allow-headers: %q", resp.Headers["Access-Control-Allow-Headers"])
	}
	if resp.Headers["Access-Control-Max-Age"] != "3600" {
		t.Fatalf("unexpected max-age: %q", resp.Headers["Access-Control-Max-Age"])
	}
	if resp.Headers["Access-Control-Allow-Credentials"] != "false" {
		t.Fatalf("unexpected allow-credentials: %q", resp.Headers["Access-Control-Allow-Credentials"])
	}
}

func TestCorsPolicy_OnRequestHeaders_PreflightSpecificOriginIncludesVary(t *testing.T) {
	p := mustGetCorsPolicy(t, map[string]any{
		"allowedOrigins": []any{"https://allowed.example.com"},
		"allowedMethods": []any{"GET"},
	})

	ctx := newCorsRequestHeaderContext("OPTIONS", map[string][]string{
		"Origin":                        {"https://allowed.example.com"},
		"Access-Control-Request-Method": {"GET"},
	})

	action := p.OnRequestHeaders(context.Background(), ctx, nil)
	resp, ok := action.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("expected ImmediateResponse, got %T", action)
	}
	if resp.Headers["Access-Control-Allow-Origin"] != "https://allowed.example.com" {
		t.Fatalf("unexpected allow-origin header: %q", resp.Headers["Access-Control-Allow-Origin"])
	}
	if resp.Headers["Vary"] != "Origin" {
		t.Fatalf("expected Vary=Origin, got %q", resp.Headers["Vary"])
	}
}

func TestCorsPolicy_OnRequestHeaders_PreflightFailure_NotForwarded(t *testing.T) {
	p := mustGetCorsPolicy(t, map[string]any{
		"allowedOrigins": []any{"https://allowed.example.com"},
		"allowedMethods": []any{"GET"},
		"allowedHeaders": []any{"x-api-key"},
	})

	ctx := newCorsRequestHeaderContext("OPTIONS", map[string][]string{
		"Origin":                        {"https://blocked.example.com"},
		"Access-Control-Request-Method": {"DELETE"},
		"Access-Control-Request-Headers": {
			"x-not-allowed",
		},
	})

	action := p.OnRequestHeaders(context.Background(), ctx, nil)
	resp, ok := action.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("expected ImmediateResponse, got %T", action)
	}
	if resp.StatusCode != 204 {
		t.Fatalf("expected 204, got %d", resp.StatusCode)
	}
	if len(resp.Headers) != 0 {
		t.Fatalf("expected empty headers on failed preflight, got %v", resp.Headers)
	}
}

func TestCorsPolicy_OnRequestHeaders_PreflightRejectsExactOriginLookalike(t *testing.T) {
	p := mustGetCorsPolicy(t, map[string]any{
		"allowedOrigins": []any{"https://abc.xyz.com"},
		"allowedMethods": []any{"GET"},
	})

	ctx := newCorsRequestHeaderContext("OPTIONS", map[string][]string{
		"Origin":                        {"https://abc.xyz.com.evil.io"},
		"Access-Control-Request-Method": {"GET"},
	})

	action := p.OnRequestHeaders(context.Background(), ctx, nil)
	resp, ok := action.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("expected ImmediateResponse, got %T", action)
	}
	if len(resp.Headers) != 0 {
		t.Fatalf("expected empty headers for lookalike origin, got %v", resp.Headers)
	}
}

func TestCorsPolicy_OnRequestHeaders_PreflightFailure_Forwarded(t *testing.T) {
	p := mustGetCorsPolicy(t, map[string]any{
		"allowedOrigins":   []any{"https://allowed.example.com"},
		"allowedMethods":   []any{"GET"},
		"allowedHeaders":   []any{"x-api-key"},
		"forwardPreflight": true,
	})

	ctx := newCorsRequestHeaderContext("OPTIONS", map[string][]string{
		"Origin":                        {"https://blocked.example.com"},
		"Access-Control-Request-Method": {"DELETE"},
		"Access-Control-Request-Headers": {
			"x-not-allowed",
		},
	})

	action := p.OnRequestHeaders(context.Background(), ctx, nil)
	if _, ok := action.(policy.UpstreamRequestHeaderModifications); !ok {
		t.Fatalf("expected UpstreamRequestHeaderModifications, got %T", action)
	}
}

// With forwardPreflight, a failed preflight is forwarded to the backend; a
// disallowed origin's preflight must not be while rejectDisallowedOrigins is
// set. An allowed origin's failed preflight is still forwarded, and without
// forwardPreflight the usual 204 answer is unchanged.
func TestCorsPolicy_OnRequestHeaders_PreflightRejectsDisallowedOriginWhenForwarding(t *testing.T) {
	preflight := func(origin string) *policy.RequestHeaderContext {
		return newCorsRequestHeaderContext("OPTIONS", map[string][]string{
			"Origin":                        {origin},
			"Access-Control-Request-Method": {"DELETE"},
		})
	}
	params := map[string]any{
		"allowedOrigins":          []any{"https://allowed.example.com"},
		"allowedMethods":          []any{"GET"},
		"forwardPreflight":        true,
		"rejectDisallowedOrigins": true,
	}
	p := mustGetCorsPolicy(t, params)

	resp, ok := p.OnRequestHeaders(context.Background(), preflight("https://blocked.example.com"), nil).(policy.ImmediateResponse)
	if !ok || resp.StatusCode != 403 {
		t.Fatalf("expected a 403 for a disallowed origin's preflight, got %#v", resp)
	}

	if _, ok := p.OnRequestHeaders(context.Background(), preflight("https://allowed.example.com"), nil).(policy.UpstreamRequestHeaderModifications); !ok {
		t.Fatalf("an allowed origin's failed preflight should still be forwarded")
	}

	params["forwardPreflight"] = false
	p = mustGetCorsPolicy(t, params)
	resp, ok = p.OnRequestHeaders(context.Background(), preflight("https://blocked.example.com"), nil).(policy.ImmediateResponse)
	if !ok || resp.StatusCode != 204 || len(resp.Headers) != 0 {
		t.Fatalf("without forwardPreflight a disallowed preflight keeps the 204 with no CORS headers, got %#v", resp)
	}
}

// An OPTIONS without Access-Control-Request-Method is not a CORS preflight, so
// the reject options apply to it; a real preflight keeps the preflight answer.
func TestCorsPolicy_OnRequestHeaders_NonPreflightOptionsFollowsRejectOptions(t *testing.T) {
	strict := mustGetCorsPolicy(t, map[string]any{
		"allowedOrigins":          []any{"https://allowed.example.com"},
		"rejectDisallowedOrigins": true,
		"rejectMissingOrigin":     true,
	})
	for name, headers := range map[string]map[string][]string{
		"no Origin":         nil,
		"disallowed Origin": {"Origin": {"https://blocked.example.com"}},
	} {
		resp, ok := strict.OnRequestHeaders(context.Background(), newCorsRequestHeaderContext("OPTIONS", headers), nil).(policy.ImmediateResponse)
		if !ok || resp.StatusCode != 403 {
			t.Errorf("%s: expected a 403 for a non-preflight OPTIONS, got %#v", name, resp)
		}
	}

	preflight := newCorsRequestHeaderContext("OPTIONS", map[string][]string{"Access-Control-Request-Method": {"GET"}})
	if resp, ok := strict.OnRequestHeaders(context.Background(), preflight, nil).(policy.ImmediateResponse); !ok || resp.StatusCode != 204 {
		t.Errorf("a preflight keeps the preflight answer, got %#v", resp)
	}

	lenient := mustGetCorsPolicy(t, map[string]any{"allowedOrigins": []any{"https://allowed.example.com"}})
	if resp, ok := lenient.OnRequestHeaders(context.Background(), newCorsRequestHeaderContext("OPTIONS", nil), nil).(policy.ImmediateResponse); !ok || resp.StatusCode != 204 {
		t.Errorf("without the reject options an OPTIONS is handled as before, got %#v", resp)
	}
}

func TestCorsPolicy_OnRequestHeaders_NonPreflightAllowedOrigin(t *testing.T) {
	p := mustGetCorsPolicy(t, map[string]any{
		"allowedOrigins":   []any{"https://allowed.example.com"},
		"exposedHeaders":   []any{"X-Trace-Id", "X-RateLimit-Remaining"},
		"allowCredentials": true,
	})

	ctx := newCorsRequestHeaderContext("GET", map[string][]string{
		"Origin": {"https://allowed.example.com"},
	})

	action := p.OnRequestHeaders(context.Background(), ctx, nil)
	if _, ok := action.(policy.UpstreamRequestHeaderModifications); !ok {
		t.Fatalf("expected UpstreamRequestHeaderModifications for non-preflight request, got %T", action)
	}

	corsHeaders, ok := ctx.Metadata["cors_headers"].(map[string]string)
	if !ok {
		t.Fatalf("expected cors_headers metadata to be present")
	}
	if corsHeaders["Access-Control-Allow-Origin"] != "https://allowed.example.com" {
		t.Fatalf("unexpected allow-origin: %q", corsHeaders["Access-Control-Allow-Origin"])
	}
	if corsHeaders["Vary"] != "Origin" {
		t.Fatalf("expected Vary=Origin, got %q", corsHeaders["Vary"])
	}
	if corsHeaders["Access-Control-Expose-Headers"] != "X-Trace-Id,X-RateLimit-Remaining" {
		t.Fatalf("unexpected expose headers: %q", corsHeaders["Access-Control-Expose-Headers"])
	}
	if corsHeaders["Access-Control-Allow-Credentials"] != "true" {
		t.Fatalf("unexpected allow-credentials: %q", corsHeaders["Access-Control-Allow-Credentials"])
	}
}

func TestCorsPolicy_OnRequestHeaders_NonPreflightAllowedSubdomainWildcard(t *testing.T) {
	p := mustGetCorsPolicy(t, map[string]any{
		"allowedOrigins": []any{"https://*.abc.com"},
	})

	ctx := newCorsRequestHeaderContext("GET", map[string][]string{
		"Origin": {"https://one.two.abc.com"},
	})

	_ = p.OnRequestHeaders(context.Background(), ctx, nil)
	corsHeaders, ok := ctx.Metadata["cors_headers"].(map[string]string)
	if !ok {
		t.Fatal("expected cors_headers metadata to be present")
	}
	if corsHeaders["Access-Control-Allow-Origin"] != "https://one.two.abc.com" {
		t.Fatalf("unexpected allow-origin: %q", corsHeaders["Access-Control-Allow-Origin"])
	}
	if corsHeaders["Vary"] != "Origin" {
		t.Fatalf("expected Vary=Origin, got %q", corsHeaders["Vary"])
	}
}

func TestCorsPolicy_OnRequestHeaders_NonPreflightDisallowedOriginSetsStrip(t *testing.T) {
	p := mustGetCorsPolicy(t, map[string]any{
		"allowedOrigins": []any{"https://allowed.example.com"},
	})

	ctx := newCorsRequestHeaderContext("GET", map[string][]string{
		"Origin": {"https://blocked.example.com"},
	})

	action := p.OnRequestHeaders(context.Background(), ctx, nil)
	if _, ok := action.(policy.UpstreamRequestHeaderModifications); !ok {
		t.Fatalf("expected UpstreamRequestHeaderModifications for non-preflight request, got %T", action)
	}
	if ctx.Metadata["cors_strip"] != true {
		t.Fatalf("expected cors_strip=true, got %v", ctx.Metadata["cors_strip"])
	}
	if _, ok := ctx.Metadata["cors_headers"]; ok {
		t.Fatalf("did not expect cors_headers when origin is disallowed")
	}
}

func TestCorsPolicy_OnRequestHeaders_NonPreflightWithoutOriginNoStrip(t *testing.T) {
	p := mustGetCorsPolicy(t, map[string]any{
		"allowedOrigins": []any{"https://allowed.example.com"},
	})

	ctx := newCorsRequestHeaderContext("GET", nil)
	_ = p.OnRequestHeaders(context.Background(), ctx, nil)

	if _, ok := ctx.Metadata["cors_strip"]; ok {
		t.Fatalf("did not expect cors_strip metadata when Origin is absent")
	}
	if _, ok := ctx.Metadata["cors_headers"]; ok {
		t.Fatalf("did not expect cors_headers metadata when Origin is absent")
	}
}

func TestCorsPolicy_OnResponseHeaders_FromCorsHeadersMetadata(t *testing.T) {
	p := &CorsPolicy{}
	ctx := &policy.ResponseHeaderContext{
		SharedContext: &policy.SharedContext{
			RequestID: "req-1",
			Metadata: map[string]interface{}{
				"cors_headers": map[string]string{
					"Access-Control-Allow-Origin": "*",
				},
			},
		},
	}

	action := p.OnResponseHeaders(context.Background(), ctx, nil)
	mods, ok := action.(policy.DownstreamResponseHeaderModifications)
	if !ok {
		t.Fatalf("expected DownstreamResponseHeaderModifications, got %T", action)
	}
	if mods.HeadersToSet["Access-Control-Allow-Origin"] != "*" {
		t.Fatalf("unexpected set headers: %v", mods.HeadersToSet)
	}
}

func TestCorsPolicy_OnResponseHeaders_FromCorsStripMetadata(t *testing.T) {
	p := &CorsPolicy{}
	ctx := &policy.ResponseHeaderContext{
		SharedContext: &policy.SharedContext{
			RequestID: "req-1",
			Metadata: map[string]interface{}{
				"cors_strip": true,
			},
		},
	}

	action := p.OnResponseHeaders(context.Background(), ctx, nil)
	mods, ok := action.(policy.DownstreamResponseHeaderModifications)
	if !ok {
		t.Fatalf("expected DownstreamResponseHeaderModifications, got %T", action)
	}
	want := []string{
		"Access-Control-Allow-Origin",
		"Access-Control-Allow-Credentials",
		"Access-Control-Expose-Headers",
	}
	if !reflect.DeepEqual(mods.HeadersToRemove, want) {
		t.Fatalf("unexpected remove headers: got %v, want %v", mods.HeadersToRemove, want)
	}
}

func TestCorsPolicy_OnResponseHeaders_NoMetadata(t *testing.T) {
	p := &CorsPolicy{}
	ctx := &policy.ResponseHeaderContext{
		SharedContext: &policy.SharedContext{
			RequestID: "req-1",
			Metadata:  map[string]interface{}{},
		},
	}

	action := p.OnResponseHeaders(context.Background(), ctx, nil)
	if _, ok := action.(policy.DownstreamResponseHeaderModifications); !ok {
		t.Fatalf("expected DownstreamResponseHeaderModifications, got %T", action)
	}
}

func TestCorsPolicy_OnRequestHeaders_PreflightSpecificAllowedHeadersCaseInsensitive(t *testing.T) {
	p := mustGetCorsPolicy(t, map[string]any{
		"allowedOrigins": []any{"*"},
		"allowedMethods": []any{"GET"},
		"allowedHeaders": []any{"X-Token", "X-Trace-Id"},
	})

	ctx := newCorsRequestHeaderContext("OPTIONS", map[string][]string{
		"Origin":                        {"https://client.example.com"},
		"Access-Control-Request-Method": {"GET"},
		"Access-Control-Request-Headers": {
			"x-token, x-trace-id",
		},
	})

	action := p.OnRequestHeaders(context.Background(), ctx, nil)
	resp, ok := action.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("expected ImmediateResponse, got %T", action)
	}
	if resp.Headers["Access-Control-Allow-Headers"] != "X-Token,X-Trace-Id" {
		t.Fatalf("unexpected allow-headers: %q", resp.Headers["Access-Control-Allow-Headers"])
	}
}

func mustGetCorsPolicy(t *testing.T, params map[string]any) *CorsPolicy {
	t.Helper()
	p, err := GetPolicy(policy.PolicyMetadata{}, params)
	if err != nil {
		t.Fatalf("GetPolicy failed: %v", err)
	}
	cp, ok := p.(*CorsPolicy)
	if !ok {
		t.Fatalf("expected *CorsPolicy, got %T", p)
	}
	return cp
}

func newCorsRequestHeaderContext(method string, headers map[string][]string) *policy.RequestHeaderContext {
	if headers == nil {
		headers = map[string][]string{}
	}
	return &policy.RequestHeaderContext{
		SharedContext: &policy.SharedContext{
			RequestID: "req-1",
			Metadata:  map[string]interface{}{},
		},
		Headers: policy.NewHeaders(headers),
		Method:  method,
	}
}

func TestCorsPolicy_GetPolicy_RejectDisallowedOriginsConfig(t *testing.T) {
	for _, origins := range [][]any{
		{"*"},
		{"https://app.example.com", "*"},
		{"null"},
		{"https://app.example.com/"},
		{"https://app.example.com/path"},
		{"https://app.example.com?x=1"},
		{"https://user@app.example.com"},
		{"app.example.com"},
		{"ftp://app.example.com"},
		{"https://:8443"},
		{"https://*.:8443"},
		{"https://[1:2:3]"},
		{"https://[1.2.3.4]"},
		{"https://*.[::1]"},
		{"https://[fe80::1%25eth0]"},
		{"https://app.example.com:65536"},
		{"https://app.example.com:08443"},
		{"https://app.example.com:"},
		{"https://bad%zz.example"},
	} {
		if _, err := GetPolicy(policy.PolicyMetadata{}, map[string]any{
			"allowedOrigins": origins, "rejectDisallowedOrigins": true,
		}); err == nil {
			t.Errorf("expected allowedOrigins %v to be refused with rejectDisallowedOrigins", origins)
		}
	}

	p := mustGetCorsPolicy(t, map[string]any{
		"allowedOrigins":          []any{"https://app.example.com", "http://localhost:3000", "https://*.example.org", "http://[::1]:8443"},
		"rejectDisallowedOrigins": true,
	})
	if !p.RejectDisallowedOrigins || p.RejectMissingOrigin {
		t.Fatalf("unexpected flags: reject=%t missing=%t", p.RejectDisallowedOrigins, p.RejectMissingOrigin)
	}

	// Without rejection the existing, lenient handling of entries is unchanged.
	mustGetCorsPolicy(t, map[string]any{"allowedOrigins": []any{"https://app.example.com/"}})
}

func TestCorsPolicy_OnRequestHeaders_RejectDisallowedOrigins(t *testing.T) {
	p := mustGetCorsPolicy(t, map[string]any{
		"allowedOrigins":          []any{"https://app.example.com", "https://*.example.org"},
		"rejectDisallowedOrigins": true,
	})

	for _, origin := range []string{"https://app.example.com", "https://chat.example.org"} {
		ctx := newCorsRequestHeaderContext("GET", map[string][]string{"Origin": {origin}})
		if _, ok := p.OnRequestHeaders(context.Background(), ctx, nil).(policy.UpstreamRequestHeaderModifications); !ok {
			t.Errorf("origin %q: expected the request to be forwarded", origin)
		}
		if _, ok := ctx.Metadata["cors_headers"]; !ok {
			t.Errorf("origin %q: expected CORS headers for an allowed origin", origin)
		}
	}

	for _, origin := range []string{
		"https://evil.example.net",
		"https://app.example.com.evil.net",
		"https://evil.net/?x=https://app.example.com",
		"http://app.example.com",
		"null",
	} {
		ctx := newCorsRequestHeaderContext("GET", map[string][]string{"Origin": {origin}})
		resp, ok := p.OnRequestHeaders(context.Background(), ctx, nil).(policy.ImmediateResponse)
		if !ok {
			t.Errorf("origin %q: expected an immediate 403", origin)
			continue
		}
		if resp.StatusCode != 403 {
			t.Errorf("origin %q: expected 403, got %d", origin, resp.StatusCode)
		}
		if strings.Contains(string(resp.Body), origin) {
			t.Errorf("origin %q: the rejection must not echo the origin, got %s", origin, resp.Body)
		}
	}

	ctx := newCorsRequestHeaderContext("GET", nil)
	if _, ok := p.OnRequestHeaders(context.Background(), ctx, nil).(policy.UpstreamRequestHeaderModifications); !ok {
		t.Errorf("a request without Origin is allowed unless rejectMissingOrigin is set")
	}
}

func TestCorsPolicy_OnRequestHeaders_RejectMissingOrigin(t *testing.T) {
	strict := mustGetCorsPolicy(t, map[string]any{
		"allowedOrigins":          []any{"https://app.example.com"},
		"rejectDisallowedOrigins": true,
		"rejectMissingOrigin":     true,
	})
	resp, ok := strict.OnRequestHeaders(context.Background(), newCorsRequestHeaderContext("GET", nil), nil).(policy.ImmediateResponse)
	if !ok || resp.StatusCode != 403 {
		t.Fatalf("expected a missing Origin to be rejected with 403, got %#v", resp)
	}

	// rejectMissingOrigin works on its own too, even with every origin allowed.
	anyOrigin := mustGetCorsPolicy(t, map[string]any{"allowedOrigins": []any{"*"}, "rejectMissingOrigin": true})
	if _, ok := anyOrigin.OnRequestHeaders(context.Background(), newCorsRequestHeaderContext("GET", nil), nil).(policy.ImmediateResponse); !ok {
		t.Errorf("expected a missing Origin to be rejected")
	}
	ctx := newCorsRequestHeaderContext("GET", map[string][]string{"Origin": {"https://anything.example"}})
	if _, ok := anyOrigin.OnRequestHeaders(context.Background(), ctx, nil).(policy.UpstreamRequestHeaderModifications); !ok {
		t.Errorf("with allowedOrigins \"*\" any present Origin passes")
	}
}

// Defaults keep the existing behaviour: a disallowed origin is forwarded with
// CORS headers stripped, and preflight handling is untouched by the new options.
func TestCorsPolicy_RejectOptionsOffByDefaultAndPreflightUnchanged(t *testing.T) {
	lenient := mustGetCorsPolicy(t, map[string]any{"allowedOrigins": []any{"https://app.example.com"}})
	ctx := newCorsRequestHeaderContext("GET", map[string][]string{"Origin": {"https://evil.example.net"}})
	if _, ok := lenient.OnRequestHeaders(context.Background(), ctx, nil).(policy.UpstreamRequestHeaderModifications); !ok {
		t.Fatalf("without rejectDisallowedOrigins a disallowed origin is still forwarded")
	}
	if ctx.Metadata["cors_strip"] != true {
		t.Fatalf("expected cors_strip for the forwarded disallowed origin")
	}

	strict := mustGetCorsPolicy(t, map[string]any{
		"allowedOrigins": []any{"https://app.example.com"}, "rejectDisallowedOrigins": true, "rejectMissingOrigin": true,
	})
	preflight := newCorsRequestHeaderContext("OPTIONS", map[string][]string{
		"Origin":                        {"https://app.example.com"},
		"Access-Control-Request-Method": {"GET"},
	})
	if _, ok := strict.OnRequestHeaders(context.Background(), preflight, nil).(policy.ImmediateResponse); !ok {
		t.Fatalf("an allowed preflight is still answered by the policy")
	}
}

// The policy-definition schema refuses enforced origins when an API is
// deployed, and validateEnforcedOrigin refuses them when the policy loads; the
// two must agree, or an origin passes one check and fails the other.
func TestCorsPolicy_EnforcedOriginSchemaMatchesValidation(t *testing.T) {
	raw, err := os.ReadFile("policy-definition.yaml")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?m)^\s*pattern: '([^']+)'`).FindSubmatch(raw)
	if m == nil {
		t.Fatal("no allowedOrigins pattern in policy-definition.yaml")
	}
	schema := regexp.MustCompile(string(m[1]))
	for _, origin := range []string{
		"https://app.example.com", "http://localhost:3000", "https://app.example.com:8443",
		"https://*.example.org", "https://*.example.org:443", "http://[::1]", "https://[::1]:8443",
		"https://[2001:db8::1]", "https://[::ffff:192.0.2.1]", "http://[::]",
		"https://:8443", "https://*.:8443", "https://[1:2:3]", "https://[:::]", "https://[...]",
		"https://[1.2.3.4]", "https://*.[::1]", "https://[::1", "https://[fe80::1%25eth0]",
		"https://[1:2:3:4:5:6:7:8:9]", "https://[::ffff:256.0.0.1]",
		"https://app.example.com/", "https://user@app.example.com", "ftp://app.example.com", "null",
		"https://app.example.com:0", "https://app.example.com:65535", "https://app.example.com:65536",
		"https://app.example.com:99999", "https://app.example.com:08443", "https://app.example.com:",
		"https://[::1]:70000", "https://[::1]:", "https://*.example.org:99999",
		"https://bad%zz.example", "https://bad%41.example",
	} {
		schemaOK := schema.MatchString(origin)
		codeOK := validateEnforcedOrigin(origin) == nil
		if schemaOK != codeOK {
			t.Errorf("%q: schema accepts=%t, validateEnforcedOrigin accepts=%t", origin, schemaOK, codeOK)
		}
	}
}
