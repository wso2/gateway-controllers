package requestrewrite

import (
	"encoding/json"
	"net/url"
	"reflect"
	"strings"
	"testing"

	policy "github.com/wso2/api-platform/sdk/gateway/policy/v1alpha"
)

func newHeaders(values map[string][]string) *policy.Headers {
	if values == nil {
		return policy.NewHeaders(map[string][]string{})
	}
	return policy.NewHeaders(values)
}

func mustRequestMods(t *testing.T, action policy.RequestAction) policy.UpstreamRequestModifications {
	t.Helper()
	mods, ok := action.(policy.UpstreamRequestModifications)
	if !ok {
		t.Fatalf("expected UpstreamRequestModifications, got %T", action)
	}
	return mods
}

func mustImmediateResponse(t *testing.T, action policy.RequestAction) policy.ImmediateResponse {
	t.Helper()
	resp, ok := action.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("expected ImmediateResponse, got %T", action)
	}
	return resp
}

func parsePathQuery(t *testing.T, raw string) (string, url.Values) {
	t.Helper()
	u, err := url.ParseRequestURI(raw)
	if err != nil {
		t.Fatalf("failed to parse rewritten path %q: %v", raw, err)
	}
	return u.Path, u.Query()
}

func assertConfigErrorBody(t *testing.T, body []byte) {
	t.Helper()
	var payload map[string]string
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatalf("failed to unmarshal error body: %v", err)
	}
	if payload["error"] != "Configuration Error" {
		t.Fatalf("expected error type Configuration Error, got %q", payload["error"])
	}
	if payload["message"] == "" {
		t.Fatalf("expected non-empty message in error payload")
	}
}

func TestGetPolicy(t *testing.T) {
	p1, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{})
	if err != nil {
		t.Fatalf("GetPolicy failed: %v", err)
	}
	p2, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{})
	if err != nil {
		t.Fatalf("GetPolicy failed: %v", err)
	}
	if p1 != p2 {
		t.Fatalf("expected singleton policy instance")
	}
}

func TestMode(t *testing.T) {
	p := &RequestRewritePolicy{}
	mode := p.Mode()
	expected := policy.ProcessingMode{
		RequestHeaderMode:  policy.HeaderModeProcess,
		RequestBodyMode:    policy.BodyModeSkip,
		ResponseHeaderMode: policy.HeaderModeSkip,
		ResponseBodyMode:   policy.BodyModeSkip,
	}
	if mode != expected {
		t.Fatalf("unexpected mode: got %+v want %+v", mode, expected)
	}
}

func TestOnResponseReturnsNil(t *testing.T) {
	p := &RequestRewritePolicy{}
	if got := p.OnResponse(&policy.ResponseContext{}, map[string]interface{}{}); got != nil {
		t.Fatalf("expected nil response action, got %T", got)
	}
}

func TestParseConfig(t *testing.T) {
	t.Run("nil params", func(t *testing.T) {
		cfg, err := parseConfig(nil)
		if err != nil {
			t.Fatalf("parseConfig failed: %v", err)
		}
		if cfg != nil {
			t.Fatalf("expected nil config for nil params")
		}
	})

	t.Run("empty params", func(t *testing.T) {
		cfg, err := parseConfig(map[string]interface{}{})
		if err != nil {
			t.Fatalf("parseConfig failed: %v", err)
		}
		if cfg != nil {
			t.Fatalf("expected nil config for empty params")
		}
	})

	t.Run("valid params", func(t *testing.T) {
		cfg, err := parseConfig(map[string]interface{}{
			"methodRewrite": "POST",
			"pathRewrite": map[string]interface{}{
				"type":            "ReplaceFullPath",
				"replaceFullPath": "/new",
			},
		})
		if err != nil {
			t.Fatalf("parseConfig failed: %v", err)
		}
		if cfg == nil {
			t.Fatalf("expected non-nil config")
		}
		if cfg.MethodRewrite != "POST" {
			t.Fatalf("expected method rewrite POST, got %q", cfg.MethodRewrite)
		}
		if cfg.PathRewrite == nil || cfg.PathRewrite.ReplaceFullPath != "/new" {
			t.Fatalf("unexpected pathRewrite: %+v", cfg.PathRewrite)
		}
	})

	t.Run("serialization error", func(t *testing.T) {
		_, err := parseConfig(map[string]interface{}{
			"methodRewrite": func() {},
		})
		if err == nil {
			t.Fatalf("expected parseConfig serialization error")
		}
	})

	t.Run("parse error from incompatible type", func(t *testing.T) {
		_, err := parseConfig(map[string]interface{}{
			"methodRewrite": true,
		})
		if err == nil {
			t.Fatalf("expected parseConfig parse error")
		}
	})
}

func TestMatchHeader(t *testing.T) {
	ctx := &policy.RequestContext{
		Headers: newHeaders(map[string][]string{
			"x-env":   {"prod"},
			"x-trace": {"trace-123"},
		}),
	}

	tests := []struct {
		name    string
		matcher headerMatcher
		want    bool
	}{
		{name: "present true", matcher: headerMatcher{Name: "x-env", Type: "Present"}, want: true},
		{name: "present false", matcher: headerMatcher{Name: "x-missing", Type: "Present"}, want: false},
		{name: "exact true", matcher: headerMatcher{Name: "x-env", Type: "Exact", Value: "prod"}, want: true},
		{name: "exact false", matcher: headerMatcher{Name: "x-env", Type: "Exact", Value: "dev"}, want: false},
		{name: "regex true", matcher: headerMatcher{Name: "x-trace", Type: "Regex", Value: `^trace-[0-9]+$`}, want: true},
		{name: "regex false", matcher: headerMatcher{Name: "x-trace", Type: "Regex", Value: `^id-[0-9]+$`}, want: false},
		{name: "invalid regex", matcher: headerMatcher{Name: "x-trace", Type: "Regex", Value: `[`}, want: false},
		{name: "unsupported type", matcher: headerMatcher{Name: "x-env", Type: "Unknown"}, want: false},
		{name: "header name case-insensitive", matcher: headerMatcher{Name: "X-Env", Type: "Exact", Value: "prod"}, want: true},
		{name: "empty name", matcher: headerMatcher{Name: "", Type: "Present"}, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := matchHeader(ctx, tt.matcher)
			if got != tt.want {
				t.Fatalf("matchHeader() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMatchQueryParam(t *testing.T) {
	values := url.Values{
		"user":  {"alice"},
		"roles": {"admin", "dev"},
	}

	tests := []struct {
		name    string
		matcher queryParamMatch
		want    bool
	}{
		{name: "present true", matcher: queryParamMatch{Name: "user", Type: "Present"}, want: true},
		{name: "present false", matcher: queryParamMatch{Name: "missing", Type: "Present"}, want: false},
		{name: "exact true", matcher: queryParamMatch{Name: "roles", Type: "Exact", Value: "dev"}, want: true},
		{name: "exact false", matcher: queryParamMatch{Name: "roles", Type: "Exact", Value: "ops"}, want: false},
		{name: "regex true", matcher: queryParamMatch{Name: "user", Type: "Regex", Value: `^ali.*`}, want: true},
		{name: "regex false", matcher: queryParamMatch{Name: "user", Type: "Regex", Value: `^bob`}, want: false},
		{name: "invalid regex", matcher: queryParamMatch{Name: "user", Type: "Regex", Value: `[`}, want: false},
		{name: "unsupported type", matcher: queryParamMatch{Name: "user", Type: "Else"}, want: false},
		{name: "empty name", matcher: queryParamMatch{Name: "", Type: "Present"}, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := matchQueryParam(values, tt.matcher)
			if got != tt.want {
				t.Fatalf("matchQueryParam() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMatchesRequest(t *testing.T) {
	ctx := &policy.RequestContext{
		Path: "/v1/items?region=us&role=admin",
		Headers: newHeaders(map[string][]string{
			"x-tenant": {"gold"},
		}),
	}

	if !matchesRequest(ctx, nil) {
		t.Fatalf("expected nil matcher to pass")
	}

	if !matchesRequest(ctx, &matchConfig{}) {
		t.Fatalf("expected empty matcher to pass")
	}

	cfg := &matchConfig{
		Headers:     []headerMatcher{{Name: "x-tenant", Type: "Exact", Value: "gold"}},
		QueryParams: []queryParamMatch{{Name: "region", Type: "Exact", Value: "us"}},
	}
	if !matchesRequest(ctx, cfg) {
		t.Fatalf("expected combined matchers to pass")
	}

	cfg.Headers = append(cfg.Headers, headerMatcher{Name: "x-env", Type: "Present"})
	if matchesRequest(ctx, cfg) {
		t.Fatalf("expected matcher set with missing header to fail")
	}

	t.Run("malformed path query fallback causes query mismatch", func(t *testing.T) {
		malformed := &policy.RequestContext{
			Path:    "/v1/%zz?region=us",
			Headers: newHeaders(nil),
		}
		queryCfg := &matchConfig{
			QueryParams: []queryParamMatch{{Name: "region", Type: "Exact", Value: "us"}},
		}
		if matchesRequest(malformed, queryCfg) {
			t.Fatalf("expected malformed path query extraction to fail match")
		}
	})
}

func TestApplyPathRewrite(t *testing.T) {
	ctx := &policy.RequestContext{
		SharedContext: &policy.SharedContext{
			OperationPath: "/orders/*",
		},
	}

	t.Run("replace prefix", func(t *testing.T) {
		got := applyPathRewrite(ctx, "/orders/42", &pathRewrite{Type: "ReplacePrefixMatch", ReplacePrefixMatch: "/customers"})
		if got != "/customers/42" {
			t.Fatalf("expected /customers/42, got %q", got)
		}
	})

	t.Run("replace prefix with empty operation path", func(t *testing.T) {
		got := applyPathRewrite(&policy.RequestContext{SharedContext: &policy.SharedContext{}}, "/orders/42", &pathRewrite{Type: "ReplacePrefixMatch", ReplacePrefixMatch: "/customers"})
		if got != "/orders/42" {
			t.Fatalf("expected original path, got %q", got)
		}
	})

	t.Run("replace full path", func(t *testing.T) {
		got := applyPathRewrite(ctx, "/orders/42", &pathRewrite{Type: "ReplaceFullPath", ReplaceFullPath: "/invoices/99"})
		if got != "/invoices/99" {
			t.Fatalf("expected /invoices/99, got %q", got)
		}
	})

	t.Run("replace full path empty replacement keeps original", func(t *testing.T) {
		got := applyPathRewrite(ctx, "/orders/42", &pathRewrite{Type: "ReplaceFullPath", ReplaceFullPath: ""})
		if got != "/orders/42" {
			t.Fatalf("expected original path, got %q", got)
		}
	})

	t.Run("replace regex", func(t *testing.T) {
		got := applyPathRewrite(ctx, "/orders/42", &pathRewrite{
			Type: "ReplaceRegexMatch",
			ReplaceRegexMatch: &regexReplacement{
				Pattern:      `^/orders/(.+)$`,
				Substitution: `/members/\1`,
			},
		})
		if got != "/members/42" {
			t.Fatalf("expected /members/42, got %q", got)
		}
	})

	t.Run("replace regex invalid pattern", func(t *testing.T) {
		got := applyPathRewrite(ctx, "/orders/42", &pathRewrite{
			Type:              "ReplaceRegexMatch",
			ReplaceRegexMatch: &regexReplacement{Pattern: `[`},
		})
		if got != "/orders/42" {
			t.Fatalf("expected original path, got %q", got)
		}
	})

	t.Run("replace regex with empty substitution removes match", func(t *testing.T) {
		got := applyPathRewrite(ctx, "/orders/42", &pathRewrite{
			Type: "ReplaceRegexMatch",
			ReplaceRegexMatch: &regexReplacement{
				Pattern:      `^/orders/[0-9]+$`,
				Substitution: "",
			},
		})
		if got != "" {
			t.Fatalf("expected empty rewritten path, got %q", got)
		}
	})

	t.Run("replace prefix non-matching path keeps original", func(t *testing.T) {
		got := applyPathRewrite(ctx, "/users/42", &pathRewrite{Type: "ReplacePrefixMatch", ReplacePrefixMatch: "/customers"})
		if got != "/users/42" {
			t.Fatalf("expected original path, got %q", got)
		}
	})

	t.Run("replace prefix exact operation path should not rewrite", func(t *testing.T) {
		got := applyPathRewrite(ctx, "/orders", &pathRewrite{Type: "ReplacePrefixMatch", ReplacePrefixMatch: "/customers"})
		if got != "/orders" {
			t.Fatalf("expected exact operation path to remain unchanged, got %q", got)
		}
	})

	t.Run("replace prefix boundary mismatch should not rewrite", func(t *testing.T) {
		got := applyPathRewrite(ctx, "/orders123", &pathRewrite{Type: "ReplacePrefixMatch", ReplacePrefixMatch: "/customers"})
		if got != "/orders123" {
			t.Fatalf("expected boundary-safe prefix behavior, got %q", got)
		}
	})

	t.Run("unsupported type", func(t *testing.T) {
		got := applyPathRewrite(ctx, "/orders/42", &pathRewrite{Type: "Nope"})
		if got != "/orders/42" {
			t.Fatalf("expected original path, got %q", got)
		}
	})
}

func TestApplyQueryRewrite(t *testing.T) {
	t.Run("all supported actions", func(t *testing.T) {
		values := url.Values{
			"id":   {"1", "2"},
			"tag":  {"old"},
			"keep": {"yes"},
		}

		err := applyQueryRewrite(values, &queryRewrite{Rules: []queryRule{
			{Action: "Replace", Name: "tag", Value: "new"},
			{Action: "Remove", Name: "keep"},
			{Action: "Add", Name: "extra", Value: "x"},
			{Action: "Append", Name: "id", Value: "9", Separator: "-"},
			{Action: "ReplaceRegexMatch", Name: "id", Pattern: `^([0-9]+)-9$`, Substitution: `id-\1`},
		}})
		if err != nil {
			t.Fatalf("applyQueryRewrite failed: %v", err)
		}

		expected := url.Values{
			"id":    {"id-1", "id-2"},
			"tag":   {"new"},
			"extra": {"x"},
		}
		if !reflect.DeepEqual(values, expected) {
			t.Fatalf("unexpected query values: got %#v want %#v", values, expected)
		}
	})

	t.Run("append on missing value creates key", func(t *testing.T) {
		values := url.Values{}
		err := applyQueryRewrite(values, &queryRewrite{Rules: []queryRule{{Action: "Append", Name: "id", Value: "10", Separator: ","}}})
		if err != nil {
			t.Fatalf("applyQueryRewrite failed: %v", err)
		}
		if got := values.Get("id"); got != "10" {
			t.Fatalf("expected id=10, got %q", got)
		}
	})

	t.Run("empty rule name", func(t *testing.T) {
		values := url.Values{}
		err := applyQueryRewrite(values, &queryRewrite{Rules: []queryRule{{Action: "Replace", Name: "   ", Value: "x"}}})
		if err == nil {
			t.Fatalf("expected error for empty query rule name")
		}
	})

	t.Run("unsupported action", func(t *testing.T) {
		values := url.Values{}
		err := applyQueryRewrite(values, &queryRewrite{Rules: []queryRule{{Action: "X", Name: "id", Value: "x"}}})
		if err == nil {
			t.Fatalf("expected error for unsupported action")
		}
	})

	t.Run("invalid regex pattern", func(t *testing.T) {
		values := url.Values{"id": {"1"}}
		err := applyQueryRewrite(values, &queryRewrite{Rules: []queryRule{{Action: "ReplaceRegexMatch", Name: "id", Pattern: "["}}})
		if err == nil {
			t.Fatalf("expected error for invalid regex pattern")
		}
	})

	t.Run("ordered multi-rule behavior on same key", func(t *testing.T) {
		tests := []struct {
			name     string
			initial  url.Values
			rules    []queryRule
			expected url.Values
		}{
			{
				name:    "remove then add keeps added value",
				initial: url.Values{"mode": {"old"}},
				rules: []queryRule{
					{Action: "Remove", Name: "mode"},
					{Action: "Add", Name: "mode", Value: "new"},
				},
				expected: url.Values{"mode": {"new"}},
			},
			{
				name:    "add then remove clears all values",
				initial: url.Values{"mode": {"old"}},
				rules: []queryRule{
					{Action: "Add", Name: "mode", Value: "new"},
					{Action: "Remove", Name: "mode"},
				},
				expected: url.Values{},
			},
			{
				name:    "append then replace collapses to single value",
				initial: url.Values{"id": {"1", "2"}},
				rules: []queryRule{
					{Action: "Append", Name: "id", Value: "x", Separator: "-"},
					{Action: "Replace", Name: "id", Value: "final"},
				},
				expected: url.Values{"id": {"final"}},
			},
			{
				name:    "regex rewrite applies after add on all values",
				initial: url.Values{"tag": {"alpha"}},
				rules: []queryRule{
					{Action: "Add", Name: "tag", Value: "beta"},
					{Action: "ReplaceRegexMatch", Name: "tag", Pattern: `^(.*)$`, Substitution: `p-\1`},
				},
				expected: url.Values{"tag": {"p-alpha", "p-beta"}},
			},
			{
				name:    "regex rewrite on missing key is no-op",
				initial: url.Values{},
				rules: []queryRule{
					{Action: "ReplaceRegexMatch", Name: "missing", Pattern: `^x$`, Substitution: `y`},
				},
				expected: url.Values{},
			},
				{
					name:    "mixed-case actions are accepted",
					initial: url.Values{"q": {"a"}},
					rules: []queryRule{
						{Action: "aDd", Name: "q", Value: "b"},
						{Action: "ApPeNd", Name: "q", Value: "x", Separator: "-"},
					},
					expected: url.Values{"q": {"a-x", "b-x"}},
				},
				{
					name:    "cross-key chain keeps duplicate values",
					initial: url.Values{"a": {"1", "2"}},
					rules: []queryRule{
						{Action: "ReplaceRegexMatch", Name: "missing", Pattern: `^x$`, Substitution: `y`},
						{Action: "Add", Name: "b", Value: "new"},
						{Action: "Remove", Name: "b"},
						{Action: "Append", Name: "a", Value: "x", Separator: "-"},
						{Action: "Replace", Name: "a", Value: "final"},
						{Action: "Add", Name: "a", Value: "tail"},
					},
					expected: url.Values{"a": {"final", "tail"}},
				},
			}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				values := tt.initial
				err := applyQueryRewrite(values, &queryRewrite{Rules: tt.rules})
				if err != nil {
					t.Fatalf("applyQueryRewrite failed: %v", err)
				}
				if !reflect.DeepEqual(values, tt.expected) {
					t.Fatalf("unexpected query values: got %#v want %#v", values, tt.expected)
				}
			})
		}
	})
}

func TestPathHelpers(t *testing.T) {
	pathOnly, query, err := splitPathAndQuery("/v1/items?id=1&id=2")
	if err != nil {
		t.Fatalf("splitPathAndQuery failed: %v", err)
	}
	if pathOnly != "/v1/items" {
		t.Fatalf("expected /v1/items, got %q", pathOnly)
	}
	if len(query["id"]) != 2 {
		t.Fatalf("expected two id values, got %#v", query["id"])
	}

	fallbackPath, _, err := splitPathAndQuery("/v1/%zz")
	if err == nil {
		t.Fatalf("expected parse error for invalid path")
	}
	if fallbackPath != "/v1/%zz" {
		t.Fatalf("expected fallback path to match input, got %q", fallbackPath)
	}

	base, relative := splitBasePath(&policy.RequestContext{SharedContext: &policy.SharedContext{APIContext: "/v1"}}, "/v1/orders/1")
	if base != "/v1" || relative != "/orders/1" {
		t.Fatalf("unexpected splitBasePath result: base=%q relative=%q", base, relative)
	}
	if got := joinBaseAndRelative(base, relative); got != "/v1/orders/1" {
		t.Fatalf("unexpected joinBaseAndRelative result: %q", got)
	}
	base, relative = splitBasePath(&policy.RequestContext{}, "/v1/orders/1")
	if base != "" || relative != "/v1/orders/1" {
		t.Fatalf("expected nil SharedContext fallback, got base=%q relative=%q", base, relative)
	}
	base, relative = splitBasePath(nil, "/v1/orders/1")
	if base != "" || relative != "/v1/orders/1" {
		t.Fatalf("expected nil context fallback, got base=%q relative=%q", base, relative)
	}
	base, relative = splitBasePath(&policy.RequestContext{SharedContext: &policy.SharedContext{APIContext: "/"}}, "/v1/orders/1")
	if base != "" || relative != "/v1/orders/1" {
		t.Fatalf("expected root API context to be ignored, got base=%q relative=%q", base, relative)
	}
	base, relative = splitBasePath(&policy.RequestContext{SharedContext: &policy.SharedContext{APIContext: "v1"}}, "/v1/orders/1")
	if base != "/v1" || relative != "/orders/1" {
		t.Fatalf("expected API context normalization, got base=%q relative=%q", base, relative)
	}
	base, relative = splitBasePath(&policy.RequestContext{SharedContext: &policy.SharedContext{APIContext: "/v1"}}, "/v2/orders/1")
	if base != "" || relative != "/v2/orders/1" {
		t.Fatalf("expected non-prefix path fallback, got base=%q relative=%q", base, relative)
	}
	if got := joinBaseAndRelative(base, relative); got != "/v2/orders/1" {
		t.Fatalf("expected join with empty base to return relative path, got %q", got)
	}
	if got := joinBaseAndRelative("/v1", "/"); got != "/v1" {
		t.Fatalf("expected /v1 for slash-relative join, got %q", got)
	}
	if got := joinBaseAndRelative("/v1", "orders/1"); got != "/v1/orders/1" {
		t.Fatalf("expected /v1/orders/1 for missing slash relative join, got %q", got)
	}
	if got := buildPath("/v1/orders/1", url.Values{"x": {"1"}}); got != "/v1/orders/1?x=1" {
		t.Fatalf("unexpected buildPath result: %q", got)
	}
}

func TestNormalizeRegexSubstitution(t *testing.T) {
	if got := normalizeRegexSubstitution(`\1-\2`); got != `$1-$2` {
		t.Fatalf("unexpected normalized substitution: %q", got)
	}
	if got := normalizeRegexSubstitution(""); got != "" {
		t.Fatalf("expected empty substitution to stay empty")
	}
}

func TestIsAllowedMethod(t *testing.T) {
	if !isAllowedMethod("PATCH") {
		t.Fatalf("expected PATCH to be allowed")
	}
	if isAllowedMethod("TRACE") {
		t.Fatalf("expected TRACE to be rejected")
	}
}

func TestOnRequestNoConfigPassThrough(t *testing.T) {
	p := &RequestRewritePolicy{}
	action := p.OnRequest(&policy.RequestContext{Headers: newHeaders(nil), Path: "/v1/orders"}, map[string]interface{}{})
	mods := mustRequestMods(t, action)
	if len(mods.SetHeaders) != 0 || len(mods.DynamicMetadata) != 0 {
		t.Fatalf("expected no modifications, got %+v", mods)
	}
}

func TestOnRequestInvalidConfigReturnsImmediateResponse(t *testing.T) {
	p := &RequestRewritePolicy{}
	action := p.OnRequest(&policy.RequestContext{Headers: newHeaders(nil), Path: "/v1/orders"}, map[string]interface{}{
		"methodRewrite": func() {},
	})
	resp := mustImmediateResponse(t, action)
	if resp.StatusCode != 500 {
		t.Fatalf("expected status 500, got %d", resp.StatusCode)
	}
	if resp.Headers["content-type"] != "application/json" {
		t.Fatalf("expected content-type application/json, got %q", resp.Headers["content-type"])
	}
	assertConfigErrorBody(t, resp.Body)
}

func TestOnRequestMatchNotMetSkipsRewrite(t *testing.T) {
	p := &RequestRewritePolicy{}
	ctx := &policy.RequestContext{
		Headers: newHeaders(map[string][]string{"x-env": {"dev"}}),
		Path:    "/v1/orders/42",
	}
	action := p.OnRequest(ctx, map[string]interface{}{
		"match": map[string]interface{}{
			"headers": []interface{}{
				map[string]interface{}{"name": "x-env", "type": "Exact", "value": "prod"},
			},
		},
		"pathRewrite": map[string]interface{}{
			"type":            "ReplaceFullPath",
			"replaceFullPath": "/rewritten",
		},
	})
	mods := mustRequestMods(t, action)
	if len(mods.SetHeaders) != 0 || len(mods.DynamicMetadata) != 0 {
		t.Fatalf("expected no modifications when match fails, got %+v", mods)
	}
}

func TestOnRequestPathRewriteReplacePrefixMatch(t *testing.T) {
	p := &RequestRewritePolicy{}
	ctx := &policy.RequestContext{
		SharedContext: &policy.SharedContext{
			APIContext:    "/v1",
			OperationPath: "/orders/*",
		},
		Headers: newHeaders(nil),
		Path:    "/v1/orders/42?view=full",
	}
	action := p.OnRequest(ctx, map[string]interface{}{
		"pathRewrite": map[string]interface{}{
			"type":               "ReplacePrefixMatch",
			"replacePrefixMatch": "/customers",
		},
	})
	mods := mustRequestMods(t, action)
	if got := mods.SetHeaders[":path"]; got != "/v1/customers/42?view=full" {
		t.Fatalf("unexpected rewritten path: %q", got)
	}
}

func TestOnRequestPathRewriteReplaceFullPathPreservesQuery(t *testing.T) {
	p := &RequestRewritePolicy{}
	ctx := &policy.RequestContext{
		SharedContext: &policy.SharedContext{
			APIContext:    "/v1",
			OperationPath: "/orders/*",
		},
		Headers: newHeaders(nil),
		Path:    "/v1/orders/42?id=1&kind=fast",
	}
	action := p.OnRequest(ctx, map[string]interface{}{
		"pathRewrite": map[string]interface{}{
			"type":            "ReplaceFullPath",
			"replaceFullPath": "/invoices/99",
		},
	})
	mods := mustRequestMods(t, action)
	path, query := parsePathQuery(t, mods.SetHeaders[":path"])
	if path != "/v1/invoices/99" {
		t.Fatalf("unexpected rewritten path: %q", path)
	}
	if query.Get("id") != "1" || query.Get("kind") != "fast" {
		t.Fatalf("expected original query params to be preserved, got %#v", query)
	}
}

func TestOnRequestPathRewriteReplaceRegexMatch(t *testing.T) {
	p := &RequestRewritePolicy{}
	ctx := &policy.RequestContext{
		SharedContext: &policy.SharedContext{
			APIContext:    "/v1",
			OperationPath: "/orders/*",
		},
		Headers: newHeaders(nil),
		Path:    "/v1/orders/42?keep=yes",
	}
	action := p.OnRequest(ctx, map[string]interface{}{
		"pathRewrite": map[string]interface{}{
			"type": "ReplaceRegexMatch",
			"replaceRegexMatch": map[string]interface{}{
				"pattern":      `^/orders/(.+)$`,
				"substitution": `/members/\1`,
			},
		},
	})
	mods := mustRequestMods(t, action)
	if got := mods.SetHeaders[":path"]; got != "/v1/members/42?keep=yes" {
		t.Fatalf("unexpected rewritten path: %q", got)
	}
}

func TestOnRequestQueryRewriteAllActions(t *testing.T) {
	p := &RequestRewritePolicy{}
	ctx := &policy.RequestContext{
		SharedContext: &policy.SharedContext{
			APIContext: "/v1",
		},
		Headers: newHeaders(nil),
		Path:    "/v1/search?id=1&id=2&tag=old&keep=yes",
	}
	action := p.OnRequest(ctx, map[string]interface{}{
		"queryRewrite": map[string]interface{}{
			"rules": []interface{}{
				map[string]interface{}{"action": "Replace", "name": "tag", "value": "new"},
				map[string]interface{}{"action": "Remove", "name": "keep"},
				map[string]interface{}{"action": "Add", "name": "extra", "value": "x"},
				map[string]interface{}{"action": "Append", "name": "id", "value": "9", "separator": "-"},
				map[string]interface{}{"action": "ReplaceRegexMatch", "name": "id", "pattern": `^([0-9]+)-9$`, "substitution": `id-\1`},
			},
		},
	})
	mods := mustRequestMods(t, action)
	path, query := parsePathQuery(t, mods.SetHeaders[":path"])
	if path != "/v1/search" {
		t.Fatalf("unexpected path after query rewrite: %q", path)
	}
	if got := query["id"]; !reflect.DeepEqual(got, []string{"id-1", "id-2"}) {
		t.Fatalf("unexpected id values: %#v", got)
	}
	if query.Get("tag") != "new" || query.Get("extra") != "x" {
		t.Fatalf("unexpected query values: %#v", query)
	}
	if _, exists := query["keep"]; exists {
		t.Fatalf("expected keep to be removed, got %#v", query)
	}
}

func TestOnRequestQueryRewriteInvalidRuleReturnsImmediateResponse(t *testing.T) {
	p := &RequestRewritePolicy{}
	ctx := &policy.RequestContext{
		SharedContext: &policy.SharedContext{},
		Headers:       newHeaders(nil),
		Path:          "/v1/search?id=1",
	}
	action := p.OnRequest(ctx, map[string]interface{}{
		"queryRewrite": map[string]interface{}{
			"rules": []interface{}{
				map[string]interface{}{"action": "Replace", "name": "   ", "value": "x"},
			},
		},
	})
	resp := mustImmediateResponse(t, action)
	if resp.StatusCode != 500 {
		t.Fatalf("expected status 500, got %d", resp.StatusCode)
	}
	assertConfigErrorBody(t, resp.Body)
}

func TestOnRequestQueryRewriteInvalidRegexReturnsImmediateResponse(t *testing.T) {
	p := &RequestRewritePolicy{}
	ctx := &policy.RequestContext{
		SharedContext: &policy.SharedContext{},
		Headers:       newHeaders(nil),
		Path:          "/v1/search?id=1",
	}
	action := p.OnRequest(ctx, map[string]interface{}{
		"queryRewrite": map[string]interface{}{
			"rules": []interface{}{
				map[string]interface{}{"action": "ReplaceRegexMatch", "name": "id", "pattern": "[", "substitution": "x"},
			},
		},
	})
	resp := mustImmediateResponse(t, action)
	if resp.StatusCode != 500 {
		t.Fatalf("expected status 500, got %d", resp.StatusCode)
	}
	assertConfigErrorBody(t, resp.Body)
}

func TestOnRequestQueryRewriteOrderedRulesExtensive(t *testing.T) {
	p := &RequestRewritePolicy{}
	ctx := &policy.RequestContext{
		SharedContext: &policy.SharedContext{
			APIContext: "/v1",
		},
		Headers: newHeaders(nil),
		Path:    "/v1/items?a=1&a=2&b=raw&c=keep",
	}
	action := p.OnRequest(ctx, map[string]interface{}{
		"queryRewrite": map[string]interface{}{
			"rules": []interface{}{
				map[string]interface{}{"action": "Remove", "name": "c"},
				map[string]interface{}{"action": "Append", "name": "a", "value": "x", "separator": "-"},
				map[string]interface{}{"action": "ReplaceRegexMatch", "name": "a", "pattern": `^([0-9]+)-x$`, "substitution": `n-\1`},
				map[string]interface{}{"action": "Add", "name": "a", "value": "n-3"},
				map[string]interface{}{"action": "Replace", "name": "b", "value": "clean"},
			},
		},
	})
	mods := mustRequestMods(t, action)
	path, query := parsePathQuery(t, mods.SetHeaders[":path"])
	if path != "/v1/items" {
		t.Fatalf("unexpected path after query rewrite: %q", path)
	}
	if got := query["a"]; !reflect.DeepEqual(got, []string{"n-1", "n-2", "n-3"}) {
		t.Fatalf("unexpected a values: %#v", got)
	}
	if query.Get("b") != "clean" {
		t.Fatalf("unexpected b value: %#v", query["b"])
	}
	if _, exists := query["c"]; exists {
		t.Fatalf("expected c to be removed, got %#v", query)
	}
}

func TestOnRequestQueryRewriteMultiRuleFailureReturnsImmediateResponse(t *testing.T) {
	p := &RequestRewritePolicy{}
	ctx := &policy.RequestContext{
		SharedContext: &policy.SharedContext{
			APIContext: "/v1",
		},
		Headers: newHeaders(nil),
		Path:    "/v1/search?tag=old",
	}
	action := p.OnRequest(ctx, map[string]interface{}{
		"queryRewrite": map[string]interface{}{
			"rules": []interface{}{
				map[string]interface{}{"action": "Replace", "name": "tag", "value": "new"},
				map[string]interface{}{"action": "ReplaceRegexMatch", "name": "tag", "pattern": "[", "substitution": "x"},
			},
		},
		"pathRewrite": map[string]interface{}{
			"type":            "ReplaceFullPath",
			"replaceFullPath": "/rewritten",
		},
	})
	resp := mustImmediateResponse(t, action)
	if resp.StatusCode != 500 {
		t.Fatalf("expected status 500, got %d", resp.StatusCode)
	}
	assertConfigErrorBody(t, resp.Body)
}

func TestOnRequestQueryRewriteNoOpDoesNotRewritePath(t *testing.T) {
	p := &RequestRewritePolicy{}
	ctx := &policy.RequestContext{
		SharedContext: &policy.SharedContext{
			APIContext: "/v1",
		},
		Headers: newHeaders(nil),
		Path:    "/v1/search?b=2&a=1",
	}
	action := p.OnRequest(ctx, map[string]interface{}{
		"queryRewrite": map[string]interface{}{
			"rules": []interface{}{
				map[string]interface{}{"action": "ReplaceRegexMatch", "name": "missing", "pattern": `^x$`, "substitution": "y"},
			},
		},
	})
	mods := mustRequestMods(t, action)
	if got := mods.SetHeaders[":path"]; got != "" {
		t.Fatalf("expected no path rewrite for semantic no-op query rewrite, got %q", got)
	}
}

func TestOnRequestInvalidMatcherRegexSkipsRewrite(t *testing.T) {
	p := &RequestRewritePolicy{}
	ctx := &policy.RequestContext{
		SharedContext: &policy.SharedContext{
			APIContext:    "/v1",
			OperationPath: "/orders/*",
		},
		Headers: newHeaders(map[string][]string{"x-id": {"123"}}),
		Path:    "/v1/orders/42?mode=test",
	}
	action := p.OnRequest(ctx, map[string]interface{}{
		"match": map[string]interface{}{
			"headers": []interface{}{
				map[string]interface{}{"name": "x-id", "type": "Regex", "value": "["},
			},
		},
		"pathRewrite": map[string]interface{}{
			"type":            "ReplaceFullPath",
			"replaceFullPath": "/rewritten",
		},
	})
	mods := mustRequestMods(t, action)
	if len(mods.SetHeaders) != 0 || len(mods.DynamicMetadata) != 0 {
		t.Fatalf("expected no modifications when matcher regex is invalid, got %+v", mods)
	}
}

func TestOnRequestCombinedRewriteAndMethodWithMatchPass(t *testing.T) {
	p := &RequestRewritePolicy{}
	ctx := &policy.RequestContext{
		SharedContext: &policy.SharedContext{
			APIContext:    "/v1",
			OperationPath: "/orders/*",
		},
		Headers: newHeaders(map[string][]string{"x-env": {"prod"}}),
		Path:    "/v1/orders/42?stage=beta&id=1",
	}
	action := p.OnRequest(ctx, map[string]interface{}{
		"match": map[string]interface{}{
			"headers": []interface{}{
				map[string]interface{}{"name": "x-env", "type": "Exact", "value": "prod"},
			},
			"queryParams": []interface{}{
				map[string]interface{}{"name": "stage", "type": "Exact", "value": "beta"},
			},
		},
		"pathRewrite": map[string]interface{}{
			"type":               "ReplacePrefixMatch",
			"replacePrefixMatch": "/purchases",
		},
		"queryRewrite": map[string]interface{}{
			"rules": []interface{}{
				map[string]interface{}{"action": "Append", "name": "id", "value": "9", "separator": "-"},
				map[string]interface{}{"action": "ReplaceRegexMatch", "name": "id", "pattern": `^([0-9]+)-9$`, "substitution": `id-\1`},
				map[string]interface{}{"action": "Add", "name": "trace", "value": "yes"},
			},
		},
		"methodRewrite": "post",
	})
	mods := mustRequestMods(t, action)
	path, query := parsePathQuery(t, mods.SetHeaders[":path"])
	if path != "/v1/purchases/42" {
		t.Fatalf("unexpected combined rewritten path: %q", path)
	}
	if got := query["id"]; !reflect.DeepEqual(got, []string{"id-1"}) {
		t.Fatalf("unexpected id values in combined flow: %#v", got)
	}
	if query.Get("stage") != "beta" || query.Get("trace") != "yes" {
		t.Fatalf("unexpected query values in combined flow: %#v", query)
	}
	if mods.DynamicMetadata[dynamicMetadataNamespace]["request_transformation.target_method"] != "POST" {
		t.Fatalf("expected method rewrite POST in combined flow, got %+v", mods.DynamicMetadata)
	}
}

func TestOnRequestCombinedRewriteAndMethodWithMatchFail(t *testing.T) {
	p := &RequestRewritePolicy{}
	ctx := &policy.RequestContext{
		SharedContext: &policy.SharedContext{
			APIContext:    "/v1",
			OperationPath: "/orders/*",
		},
		Headers: newHeaders(map[string][]string{"x-env": {"dev"}}),
		Path:    "/v1/orders/42?stage=beta&id=1",
	}
	action := p.OnRequest(ctx, map[string]interface{}{
		"match": map[string]interface{}{
			"headers": []interface{}{
				map[string]interface{}{"name": "x-env", "type": "Exact", "value": "prod"},
			},
		},
		"pathRewrite": map[string]interface{}{
			"type":               "ReplacePrefixMatch",
			"replacePrefixMatch": "/purchases",
		},
		"queryRewrite": map[string]interface{}{
			"rules": []interface{}{
				map[string]interface{}{"action": "Replace", "name": "id", "value": "2"},
			},
		},
		"methodRewrite": "post",
	})
	mods := mustRequestMods(t, action)
	if len(mods.SetHeaders) != 0 || len(mods.DynamicMetadata) != 0 {
		t.Fatalf("expected no modifications when combined flow match fails, got %+v", mods)
	}
}

func TestOnRequestMethodRewriteOnly(t *testing.T) {
	p := &RequestRewritePolicy{}
	ctx := &policy.RequestContext{
		SharedContext: &policy.SharedContext{},
		Headers:       newHeaders(nil),
		Path:          "/v1/orders",
	}
	action := p.OnRequest(ctx, map[string]interface{}{
		"methodRewrite": " patch ",
	})
	mods := mustRequestMods(t, action)
	if len(mods.SetHeaders) != 0 {
		t.Fatalf("expected no path rewrite headers, got %+v", mods.SetHeaders)
	}
	if mods.DynamicMetadata[dynamicMetadataNamespace]["request_transformation.target_method"] != "PATCH" {
		t.Fatalf("expected method rewrite PATCH, got %+v", mods.DynamicMetadata)
	}
}

func TestOnRequestInvalidMethodRewriteReturnsImmediateResponse(t *testing.T) {
	p := &RequestRewritePolicy{}
	ctx := &policy.RequestContext{
		SharedContext: &policy.SharedContext{},
		Headers:       newHeaders(nil),
		Path:          "/v1/orders",
	}
	action := p.OnRequest(ctx, map[string]interface{}{
		"methodRewrite": "TRACE",
	})
	resp := mustImmediateResponse(t, action)
	if resp.StatusCode != 500 {
		t.Fatalf("expected status 500, got %d", resp.StatusCode)
	}
	assertConfigErrorBody(t, resp.Body)
}

func TestOnRequestPathAndMethodRewriteTogether(t *testing.T) {
	p := &RequestRewritePolicy{}
	ctx := &policy.RequestContext{
		SharedContext: &policy.SharedContext{
			APIContext:    "/v1",
			OperationPath: "/orders/*",
		},
		Headers: newHeaders(nil),
		Path:    "/v1/orders/42",
	}
	action := p.OnRequest(ctx, map[string]interface{}{
		"pathRewrite": map[string]interface{}{
			"type":            "ReplaceFullPath",
			"replaceFullPath": "/invoices/100",
		},
		"methodRewrite": "post",
	})
	mods := mustRequestMods(t, action)
	if got := mods.SetHeaders[":path"]; got != "/v1/invoices/100" {
		t.Fatalf("unexpected rewritten path: %q", got)
	}
	if mods.DynamicMetadata[dynamicMetadataNamespace]["request_transformation.target_method"] != "POST" {
		t.Fatalf("expected method rewrite POST, got %+v", mods.DynamicMetadata)
	}
}

func TestOnRequestRewriteWithoutSharedContextDoesNotPanic(t *testing.T) {
	p := &RequestRewritePolicy{}
	ctx := &policy.RequestContext{
		Headers: newHeaders(nil),
		Path:    "/orders/42?view=full",
	}
	action := p.OnRequest(ctx, map[string]interface{}{
		"pathRewrite": map[string]interface{}{
			"type":            "ReplaceFullPath",
			"replaceFullPath": "/members/42",
		},
	})
	mods := mustRequestMods(t, action)
	if got := mods.SetHeaders[":path"]; got != "/members/42?view=full" {
		t.Fatalf("unexpected rewritten path without shared context: %q", got)
	}
}

func TestBugHunt_MalformedPathQueryRewriteDoesNotCorruptPath(t *testing.T) {
	p := &RequestRewritePolicy{}
	ctx := &policy.RequestContext{
		SharedContext: &policy.SharedContext{
			APIContext: "/v1",
		},
		Headers: newHeaders(nil),
		Path:    "/v1/%zz?a=1",
	}

	action := p.OnRequest(ctx, map[string]interface{}{
		"queryRewrite": map[string]interface{}{
			"rules": []interface{}{
				map[string]interface{}{"action": "Add", "name": "b", "value": "2"},
			},
		},
	})
	mods := mustRequestMods(t, action)
	got := mods.SetHeaders[":path"]
	if strings.Count(got, "?") > 1 {
		t.Fatalf("BUG: malformed path rewrite produced invalid query delimiter sequence: %q", got)
	}
}

func TestBugHunt_QueryRewriteShouldPreserveEncodedPathSegments(t *testing.T) {
	p := &RequestRewritePolicy{}
	ctx := &policy.RequestContext{
		SharedContext: &policy.SharedContext{
			APIContext: "/v1",
		},
		Headers: newHeaders(nil),
		Path:    "/v1/orders%2F42?x=1",
	}

	action := p.OnRequest(ctx, map[string]interface{}{
		"queryRewrite": map[string]interface{}{
			"rules": []interface{}{
				map[string]interface{}{"action": "Add", "name": "y", "value": "2"},
			},
		},
	})
	mods := mustRequestMods(t, action)
	got := mods.SetHeaders[":path"]
	if !strings.HasPrefix(got, "/v1/orders%2F42?") {
		t.Fatalf("BUG: encoded slash in path was normalized/decoded unexpectedly: %q", got)
	}
}

func TestBugHunt_QueryRewriteShouldNotInjectControlCharsIntoPath(t *testing.T) {
	p := &RequestRewritePolicy{}
	ctx := &policy.RequestContext{
		SharedContext: &policy.SharedContext{
			APIContext: "/v1",
		},
		Headers: newHeaders(nil),
		Path:    "/v1/%0Aabc",
	}

	action := p.OnRequest(ctx, map[string]interface{}{
		"queryRewrite": map[string]interface{}{
			"rules": []interface{}{
				map[string]interface{}{"action": "Add", "name": "x", "value": "1"},
			},
		},
	})
	mods := mustRequestMods(t, action)
	got := mods.SetHeaders[":path"]
	if strings.ContainsRune(got, '\n') || strings.ContainsRune(got, '\r') {
		t.Fatalf("BUG: rewritten :path contains control character(s): %q", got)
	}
}

func TestBugHunt_PathRewriteShouldPreserveOriginalQueryOrdering(t *testing.T) {
	p := &RequestRewritePolicy{}
	ctx := &policy.RequestContext{
		SharedContext: &policy.SharedContext{
			APIContext:    "/v1",
			OperationPath: "/orders/*",
		},
		Headers: newHeaders(nil),
		Path:    "/v1/orders/42?b=2&a=1",
	}

	action := p.OnRequest(ctx, map[string]interface{}{
		"pathRewrite": map[string]interface{}{
			"type":            "ReplaceFullPath",
			"replaceFullPath": "/new",
		},
	})
	mods := mustRequestMods(t, action)
	got := mods.SetHeaders[":path"]
	if got != "/v1/new?b=2&a=1" {
		t.Fatalf("BUG: query ordering changed during path-only rewrite: %q", got)
	}
}

func TestBugHunt_InvalidPathRegexShouldReturnConfigError(t *testing.T) {
	p := &RequestRewritePolicy{}
	ctx := &policy.RequestContext{
		SharedContext: &policy.SharedContext{
			APIContext: "/v1",
		},
		Headers: newHeaders(nil),
		Path:    "/v1/orders/42",
	}

	action := p.OnRequest(ctx, map[string]interface{}{
		"pathRewrite": map[string]interface{}{
			"type": "ReplaceRegexMatch",
			"replaceRegexMatch": map[string]interface{}{
				"pattern":      "[",
				"substitution": "/x",
			},
		},
	})

	if _, ok := action.(policy.ImmediateResponse); !ok {
		t.Fatalf("BUG: invalid path regex should fail closed with config error, got %T", action)
	}
}

func TestBugHunt_UnsupportedPathRewriteTypeShouldReturnConfigError(t *testing.T) {
	p := &RequestRewritePolicy{}
	ctx := &policy.RequestContext{
		SharedContext: &policy.SharedContext{
			APIContext: "/v1",
		},
		Headers: newHeaders(nil),
		Path:    "/v1/orders/42",
	}

	action := p.OnRequest(ctx, map[string]interface{}{
		"pathRewrite": map[string]interface{}{
			"type":            "TypoRewriteType",
			"replaceFullPath": "/x",
		},
	})
	if _, ok := action.(policy.ImmediateResponse); !ok {
		t.Fatalf("BUG: unsupported pathRewrite.type silently ignored, got %T", action)
	}
}

func TestBugHunt_NilRequestContextShouldNotPanic(t *testing.T) {
	p := &RequestRewritePolicy{}
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("BUG: nil RequestContext causes panic: %v", r)
		}
	}()

	action := p.OnRequest(nil, map[string]interface{}{"methodRewrite": "GET"})
	if _, ok := action.(policy.ImmediateResponse); !ok {
		t.Fatalf("expected fail-closed response for nil context, got %T", action)
	}
}
