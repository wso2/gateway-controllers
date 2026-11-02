package cors

import (
	"context"
	"testing"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

type originCase struct {
	origin  string
	allowed bool
}

func assertOriginCases(t *testing.T, p *CorsPolicy, tests []originCase) {
	t.Helper()
	for _, tt := range tests {
		t.Run(tt.origin, func(t *testing.T) {
			if got := p.isOriginAllowed(tt.origin); got != tt.allowed {
				t.Fatalf("isOriginAllowed(%q) = %t, want %t", tt.origin, got, tt.allowed)
			}
		})
	}
}

func TestCorsPolicy_GetPolicy_RegexOrigin(t *testing.T) {
	p := mustGetCorsPolicy(t, map[string]any{
		"allowedOrigins": []any{`https://.*\.example\.com`},
	})

	assertOriginCases(t, p, []originCase{
		{origin: "https://api.example.com", allowed: true},
		{origin: "https://one.two.example.com", allowed: true},
		{origin: "http://api.example.com", allowed: false},
		{origin: "https://example.com", allowed: false},
		{origin: "https://apiXexample.com", allowed: false},
		{origin: "https://api.example.com.evil.io", allowed: false},
		{origin: "https://api.example.com:8443", allowed: false},
	})
}

func TestCorsPolicy_GetPolicy_RegexOriginWithExplicitAnchors(t *testing.T) {
	p := mustGetCorsPolicy(t, map[string]any{
		"allowedOrigins": []any{`^https://(api|www)\.example\.com$`},
	})

	assertOriginCases(t, p, []originCase{
		{origin: "https://api.example.com", allowed: true},
		{origin: "https://www.example.com", allowed: true},
		{origin: "https://app.example.com", allowed: false},
		{origin: "https://api.example.com.evil.io", allowed: false},
	})
}

func TestCorsPolicy_GetPolicy_RegexOriginIsFullyAnchored(t *testing.T) {
	p := mustGetCorsPolicy(t, map[string]any{
		"allowedOrigins": []any{`http://localhost:\d+`},
	})

	assertOriginCases(t, p, []originCase{
		{origin: "http://localhost:3000", allowed: true},
		{origin: "http://localhost:8080", allowed: true},
		{origin: "http://localhost", allowed: false},
		{origin: "https://localhost:3000", allowed: false},
		{origin: "http://localhost:3000.evil.io", allowed: false},
		{origin: "http://evil.io/http://localhost:3000", allowed: false},
	})
}

func TestCorsPolicy_GetPolicy_RegexOriginAlternationIsAnchoredAsAWhole(t *testing.T) {
	// Without grouping the anchors, "a|b" would let either branch match a
	// substring of an untrusted origin.
	p := mustGetCorsPolicy(t, map[string]any{
		"allowedOrigins": []any{`https://a\.example\.com|https://b\.example\.com`},
	})

	assertOriginCases(t, p, []originCase{
		{origin: "https://a.example.com", allowed: true},
		{origin: "https://b.example.com", allowed: true},
		{origin: "https://a.example.com.evil.io", allowed: false},
		{origin: "https://evil.io.https://b.example.com", allowed: false},
	})
}

func TestCorsPolicy_GetPolicy_MixedExactWildcardAndRegexOrigins(t *testing.T) {
	p := mustGetCorsPolicy(t, map[string]any{
		"allowedOrigins": []any{
			"https://exact.example.org",
			"https://*.wildcard.example.net",
			`https://(dev|qa)-[0-9]+\.regex\.example\.io`,
		},
	})

	assertOriginCases(t, p, []originCase{
		// Exact origin is matched literally.
		{origin: "https://exact.example.org", allowed: true},
		{origin: "https://exactXexample.org", allowed: false},
		{origin: "https://sub.exact.example.org", allowed: false},
		// Subdomain wildcard.
		{origin: "https://api.wildcard.example.net", allowed: true},
		{origin: "https://one.two.wildcard.example.net", allowed: true},
		{origin: "https://wildcard.example.net", allowed: false},
		{origin: "http://api.wildcard.example.net", allowed: false},
		// Go regex.
		{origin: "https://dev-1.regex.example.io", allowed: true},
		{origin: "https://qa-42.regex.example.io", allowed: true},
		{origin: "https://prod-1.regex.example.io", allowed: false},
		{origin: "https://dev-x.regex.example.io", allowed: false},
		// Unrelated.
		{origin: "https://evil.io", allowed: false},
	})
}

func TestCorsPolicy_GetPolicy_InvalidRegexOriginFallsBackToExactMatch(t *testing.T) {
	p := mustGetCorsPolicy(t, map[string]any{
		"allowedOrigins": []any{"https://(broken.example.com"},
	})

	assertOriginCases(t, p, []originCase{
		{origin: "https://(broken.example.com", allowed: true},
		{origin: "https://broken.example.com", allowed: false},
	})
}

func TestCorsPolicy_GetPolicy_BracketedIPv6OriginMatchedLiterally(t *testing.T) {
	p := mustGetCorsPolicy(t, map[string]any{
		"allowedOrigins": []any{"http://[::1]:8080"},
	})

	assertOriginCases(t, p, []originCase{
		{origin: "http://[::1]:8080", allowed: true},
		{origin: "http://1:8080", allowed: false},
		{origin: "http://::8080", allowed: false},
	})
}

func TestCorsPolicy_IsRegexOrigin(t *testing.T) {
	tests := []struct {
		origin string
		regex  bool
	}{
		{origin: "https://api.example.com", regex: false},
		{origin: "http://localhost:8080", regex: false},
		{origin: "http://[::1]:8080", regex: false},
		{origin: "https://*.example.com", regex: true},
		{origin: `https://.*\.example\.com`, regex: true},
		{origin: `^https://api\.example\.com$`, regex: true},
		{origin: "https://(a|b).example.com", regex: true},
		{origin: "http://localhost:[0-9]+", regex: true},
		{origin: "https://a{1,3}.example.com", regex: true},
		{origin: "https://api.example.com?", regex: true},
	}

	for _, tt := range tests {
		t.Run(tt.origin, func(t *testing.T) {
			if got := isRegexOrigin(tt.origin); got != tt.regex {
				t.Fatalf("isRegexOrigin(%q) = %t, want %t", tt.origin, got, tt.regex)
			}
		})
	}
}

func TestCorsPolicy_OnRequestHeaders_PreflightAllowedRegexOrigin(t *testing.T) {
	p := mustGetCorsPolicy(t, map[string]any{
		"allowedOrigins": []any{`https://.*\.example\.com`},
		"allowedMethods": []any{"GET", "POST"},
	})

	ctx := newCorsRequestHeaderContext("OPTIONS", map[string][]string{
		"Origin":                        {"https://app.example.com"},
		"Access-Control-Request-Method": {"POST"},
	})

	action := p.OnRequestHeaders(context.Background(), ctx, nil)
	resp, ok := action.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("expected ImmediateResponse, got %T", action)
	}
	if resp.StatusCode != 204 {
		t.Fatalf("expected 204, got %d", resp.StatusCode)
	}
	if resp.Headers["Access-Control-Allow-Origin"] != "https://app.example.com" {
		t.Fatalf("unexpected allow-origin: %q", resp.Headers["Access-Control-Allow-Origin"])
	}
	if resp.Headers["Vary"] != "Origin" {
		t.Fatalf("expected Vary=Origin, got %q", resp.Headers["Vary"])
	}
	if resp.Headers["Access-Control-Allow-Methods"] != "GET,POST" {
		t.Fatalf("unexpected allow-methods: %q", resp.Headers["Access-Control-Allow-Methods"])
	}
}

func TestCorsPolicy_OnRequestHeaders_PreflightRejectsRegexOriginMismatch(t *testing.T) {
	p := mustGetCorsPolicy(t, map[string]any{
		"allowedOrigins": []any{`https://.*\.example\.com`},
		"allowedMethods": []any{"GET"},
	})

	ctx := newCorsRequestHeaderContext("OPTIONS", map[string][]string{
		"Origin":                        {"https://app.example.com.evil.io"},
		"Access-Control-Request-Method": {"GET"},
	})

	action := p.OnRequestHeaders(context.Background(), ctx, nil)
	resp, ok := action.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("expected ImmediateResponse, got %T", action)
	}
	if len(resp.Headers) != 0 {
		t.Fatalf("expected empty headers for disallowed origin, got %v", resp.Headers)
	}
}

func TestCorsPolicy_OnRequestHeaders_NonPreflightAllowedRegexOrigin(t *testing.T) {
	p := mustGetCorsPolicy(t, map[string]any{
		"allowedOrigins":   []any{`http://localhost:\d+`},
		"allowCredentials": true,
	})

	ctx := newCorsRequestHeaderContext("GET", map[string][]string{
		"Origin": {"http://localhost:5173"},
	})

	_ = p.OnRequestHeaders(context.Background(), ctx, nil)
	corsHeaders, ok := ctx.Metadata["cors_headers"].(map[string]string)
	if !ok {
		t.Fatal("expected cors_headers metadata to be present")
	}
	if corsHeaders["Access-Control-Allow-Origin"] != "http://localhost:5173" {
		t.Fatalf("unexpected allow-origin: %q", corsHeaders["Access-Control-Allow-Origin"])
	}
	if corsHeaders["Vary"] != "Origin" {
		t.Fatalf("expected Vary=Origin, got %q", corsHeaders["Vary"])
	}
	if corsHeaders["Access-Control-Allow-Credentials"] != "true" {
		t.Fatalf("unexpected allow-credentials: %q", corsHeaders["Access-Control-Allow-Credentials"])
	}
}

func TestCorsPolicy_OnRequestHeaders_NonPreflightDisallowedRegexOriginSetsStrip(t *testing.T) {
	p := mustGetCorsPolicy(t, map[string]any{
		"allowedOrigins": []any{`http://localhost:\d+`},
	})

	ctx := newCorsRequestHeaderContext("GET", map[string][]string{
		"Origin": {"http://localhost.evil.io:5173"},
	})

	_ = p.OnRequestHeaders(context.Background(), ctx, nil)
	if ctx.Metadata["cors_strip"] != true {
		t.Fatalf("expected cors_strip=true, got %v", ctx.Metadata["cors_strip"])
	}
	if _, ok := ctx.Metadata["cors_headers"]; ok {
		t.Fatalf("did not expect cors_headers when origin is disallowed")
	}
}
