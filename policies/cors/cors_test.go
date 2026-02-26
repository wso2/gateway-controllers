package cors

import (
	"reflect"
	"strings"
	"testing"

	policy "github.com/wso2/api-platform/sdk/gateway/policy/v1alpha"
)

func TestCorsPolicy_Mode(t *testing.T) {
	p := &CorsPolicy{}
	got := p.Mode()
	want := policy.ProcessingMode{
		RequestHeaderMode:  policy.HeaderModeProcess,
		RequestBodyMode:    policy.BodyModeSkip,
		ResponseHeaderMode: policy.HeaderModeProcess,
		ResponseBodyMode:   policy.BodyModeSkip,
	}

	if got != want {
		t.Fatalf("unexpected mode: got %+v, want %+v", got, want)
	}
}

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

func TestCorsPolicy_GetPolicy_InvalidOriginRegex(t *testing.T) {
	_, err := GetPolicy(policy.PolicyMetadata{}, map[string]any{
		"allowedOrigins": []any{"[invalid-regex"},
	})
	if err == nil {
		t.Fatalf("expected invalid origin regex error")
	}
	if !strings.Contains(err.Error(), "invalid origin regex") {
		t.Fatalf("unexpected error: %v", err)
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

func TestCorsPolicy_OnRequest_PreflightSuccess(t *testing.T) {
	p := mustGetCorsPolicy(t, map[string]any{
		"allowedOrigins":   []any{"*"},
		"allowedMethods":   []any{"GET", "POST"},
		"allowedHeaders":   []any{"*"},
		"allowCredentials": false,
		"maxAge":           3600,
	})

	ctx := newCorsRequestContext("OPTIONS", map[string][]string{
		"Origin":                        {"https://client.example.com"},
		"Access-Control-Request-Method": {"GET"},
		"Access-Control-Request-Headers": {
			"x-api-key, x-trace-id",
		},
	})

	action := p.OnRequest(ctx, nil)
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

func TestCorsPolicy_OnRequest_PreflightFailure_NotForwarded(t *testing.T) {
	p := mustGetCorsPolicy(t, map[string]any{
		"allowedOrigins": []any{"https://allowed.example.com"},
		"allowedMethods": []any{"GET"},
		"allowedHeaders": []any{"x-api-key"},
	})

	ctx := newCorsRequestContext("OPTIONS", map[string][]string{
		"Origin":                        {"https://blocked.example.com"},
		"Access-Control-Request-Method": {"DELETE"},
		"Access-Control-Request-Headers": {
			"x-not-allowed",
		},
	})

	action := p.OnRequest(ctx, nil)
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

func TestCorsPolicy_OnRequest_PreflightFailure_Forwarded(t *testing.T) {
	p := mustGetCorsPolicy(t, map[string]any{
		"allowedOrigins":   []any{"https://allowed.example.com"},
		"allowedMethods":   []any{"GET"},
		"allowedHeaders":   []any{"x-api-key"},
		"forwardPreflight": true,
	})

	ctx := newCorsRequestContext("OPTIONS", map[string][]string{
		"Origin":                        {"https://blocked.example.com"},
		"Access-Control-Request-Method": {"DELETE"},
		"Access-Control-Request-Headers": {
			"x-not-allowed",
		},
	})

	action := p.OnRequest(ctx, nil)
	if _, ok := action.(policy.UpstreamRequestModifications); !ok {
		t.Fatalf("expected UpstreamRequestModifications, got %T", action)
	}
}

func TestCorsPolicy_OnRequest_NonPreflightAllowedOrigin(t *testing.T) {
	p := mustGetCorsPolicy(t, map[string]any{
		"allowedOrigins":   []any{"^https://allowed\\.example\\.com$"},
		"exposedHeaders":   []any{"X-Trace-Id", "X-RateLimit-Remaining"},
		"allowCredentials": true,
	})

	ctx := newCorsRequestContext("GET", map[string][]string{
		"Origin": {"https://allowed.example.com"},
	})

	action := p.OnRequest(ctx, nil)
	if action != nil {
		t.Fatalf("expected nil action for non-preflight request, got %T", action)
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

func TestCorsPolicy_OnRequest_NonPreflightDisallowedOriginSetsStrip(t *testing.T) {
	p := mustGetCorsPolicy(t, map[string]any{
		"allowedOrigins": []any{"^https://allowed\\.example\\.com$"},
	})

	ctx := newCorsRequestContext("GET", map[string][]string{
		"Origin": {"https://blocked.example.com"},
	})

	action := p.OnRequest(ctx, nil)
	if action != nil {
		t.Fatalf("expected nil action for non-preflight request, got %T", action)
	}
	if ctx.Metadata["cors_strip"] != true {
		t.Fatalf("expected cors_strip=true, got %v", ctx.Metadata["cors_strip"])
	}
	if _, ok := ctx.Metadata["cors_headers"]; ok {
		t.Fatalf("did not expect cors_headers when origin is disallowed")
	}
}

func TestCorsPolicy_OnRequest_NonPreflightWithoutOriginNoStrip(t *testing.T) {
	p := mustGetCorsPolicy(t, map[string]any{
		"allowedOrigins": []any{"^https://allowed\\.example\\.com$"},
	})

	ctx := newCorsRequestContext("GET", nil)
	_ = p.OnRequest(ctx, nil)

	if _, ok := ctx.Metadata["cors_strip"]; ok {
		t.Fatalf("did not expect cors_strip metadata when Origin is absent")
	}
	if _, ok := ctx.Metadata["cors_headers"]; ok {
		t.Fatalf("did not expect cors_headers metadata when Origin is absent")
	}
}

func TestCorsPolicy_OnResponse_FromCorsHeadersMetadata(t *testing.T) {
	p := &CorsPolicy{}
	ctx := &policy.ResponseContext{
		SharedContext: &policy.SharedContext{
			RequestID: "req-1",
			Metadata: map[string]interface{}{
				"cors_headers": map[string]string{
					"Access-Control-Allow-Origin": "*",
				},
			},
		},
	}

	action := p.OnResponse(ctx, nil)
	mods, ok := action.(policy.UpstreamResponseModifications)
	if !ok {
		t.Fatalf("expected UpstreamResponseModifications, got %T", action)
	}
	if mods.SetHeaders["Access-Control-Allow-Origin"] != "*" {
		t.Fatalf("unexpected set headers: %v", mods.SetHeaders)
	}
}

func TestCorsPolicy_OnResponse_FromCorsStripMetadata(t *testing.T) {
	p := &CorsPolicy{}
	ctx := &policy.ResponseContext{
		SharedContext: &policy.SharedContext{
			RequestID: "req-1",
			Metadata: map[string]interface{}{
				"cors_strip": true,
			},
		},
	}

	action := p.OnResponse(ctx, nil)
	mods, ok := action.(policy.UpstreamResponseModifications)
	if !ok {
		t.Fatalf("expected UpstreamResponseModifications, got %T", action)
	}
	want := []string{
		"Access-Control-Allow-Origin",
		"Access-Control-Allow-Credentials",
		"Access-Control-Expose-Headers",
	}
	if !reflect.DeepEqual(mods.RemoveHeaders, want) {
		t.Fatalf("unexpected remove headers: got %v, want %v", mods.RemoveHeaders, want)
	}
}

func TestCorsPolicy_OnResponse_NoMetadata(t *testing.T) {
	p := &CorsPolicy{}
	ctx := &policy.ResponseContext{
		SharedContext: &policy.SharedContext{
			RequestID: "req-1",
			Metadata:  map[string]interface{}{},
		},
	}

	action := p.OnResponse(ctx, nil)
	if action != nil {
		t.Fatalf("expected nil, got %T", action)
	}
}

func TestCorsPolicy_OnRequest_PreflightSpecificAllowedHeadersCaseInsensitive(t *testing.T) {
	p := mustGetCorsPolicy(t, map[string]any{
		"allowedOrigins": []any{"*"},
		"allowedMethods": []any{"GET"},
		"allowedHeaders": []any{"X-Token", "X-Trace-Id"},
	})

	ctx := newCorsRequestContext("OPTIONS", map[string][]string{
		"Origin":                        {"https://client.example.com"},
		"Access-Control-Request-Method": {"GET"},
		"Access-Control-Request-Headers": {
			"x-token, x-trace-id",
		},
	})

	action := p.OnRequest(ctx, nil)
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

func newCorsRequestContext(method string, headers map[string][]string) *policy.RequestContext {
	if headers == nil {
		headers = map[string][]string{}
	}
	return &policy.RequestContext{
		SharedContext: &policy.SharedContext{
			RequestID: "req-1",
			Metadata:  map[string]interface{}{},
		},
		Headers: policy.NewHeaders(headers),
		Method:  method,
	}
}
