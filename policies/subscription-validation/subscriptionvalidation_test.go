package subscriptionvalidation

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"
	"testing"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
	policyenginev1 "github.com/wso2/api-platform/sdk/core/policyengine"
)

// --- helpers -----------------------------------------------------------------

func newStore(entries []policyenginev1.SubscriptionData) *policyenginev1.SubscriptionStore {
	s := policyenginev1.NewSubscriptionStore()
	s.ReplaceAll(entries)
	return s
}

func newPolicy(cfg PolicyConfig, store *policyenginev1.SubscriptionStore) *SubscriptionValidationPolicy {
	return &SubscriptionValidationPolicy{
		cfg:         cfg,
		store:       store,
		rateLimitMu: sharedRateLimitMu,
		rateLimits:  make(map[string]*rateLimitEntry),
	}
}

func defaultCfg() PolicyConfig {
	return PolicyConfig{
		SubscriptionKeyHeader: defaultSubscriptionKeyHeader,
		SubscriptionKeyCookie: defaultSubscriptionKeyCookie,
	}
}

func headerCtxWithToken(apiID, token, headerName string) *policy.RequestHeaderContext {
	if headerName == "" {
		headerName = defaultSubscriptionKeyHeader
	}
	return &policy.RequestHeaderContext{
		SharedContext: &policy.SharedContext{
			APIId:    apiID,
			Metadata: map[string]interface{}{},
		},
		Headers: policy.NewHeaders(map[string][]string{
			headerName: {token},
		}),
	}
}

func headerCtxWithAppID(apiID, appID string) *policy.RequestHeaderContext {
	return &policy.RequestHeaderContext{
		SharedContext: &policy.SharedContext{
			APIId: apiID,
			Metadata: map[string]interface{}{
				applicationIDMetadataKey: appID,
			},
		},
		Headers: policy.NewHeaders(nil),
	}
}

func headerCtxWithCookie(apiID, token, cookieName string) *policy.RequestHeaderContext {
	return &policy.RequestHeaderContext{
		SharedContext: &policy.SharedContext{
			APIId:    apiID,
			Metadata: map[string]interface{}{},
		},
		Headers: policy.NewHeaders(map[string][]string{
			"Cookie": {cookieName + "=" + token},
		}),
	}
}

func assertSuccess(t *testing.T, action policy.RequestHeaderAction) {
	t.Helper()
	if _, ok := action.(policy.UpstreamRequestHeaderModifications); !ok {
		t.Fatalf("expected UpstreamRequestHeaderModifications (allow), got %#v", action)
	}
}

func assertHeaderRemoved(t *testing.T, action policy.RequestHeaderAction, header string) {
	t.Helper()
	mod, ok := action.(policy.UpstreamRequestHeaderModifications)
	if !ok {
		t.Fatalf("expected UpstreamRequestHeaderModifications, got %#v", action)
	}
	header = strings.ToLower(strings.TrimSpace(header))
	for _, h := range mod.HeadersToRemove {
		if strings.ToLower(strings.TrimSpace(h)) == header {
			return
		}
	}
	t.Fatalf("expected header %q to be removed; got HeadersToRemove=%v", header, mod.HeadersToRemove)
}

func assertCookieStripped(t *testing.T, action policy.RequestHeaderAction, cookieName string) {
	t.Helper()
	mod, ok := action.(policy.UpstreamRequestHeaderModifications)
	if !ok {
		t.Fatalf("expected UpstreamRequestHeaderModifications, got %#v", action)
	}
	// Either Cookie is fully removed...
	for _, h := range mod.HeadersToRemove {
		if strings.EqualFold(strings.TrimSpace(h), "cookie") {
			return
		}
	}
	// ...or rewritten without the cookieName.
	cookieHeader, ok := mod.HeadersToSet["cookie"]
	if !ok {
		cookieHeader, ok = mod.HeadersToSet["Cookie"]
	}
	if !ok {
		t.Fatalf("expected cookie to be removed or rewritten; got HeadersToRemove=%v HeadersToSet=%v", mod.HeadersToRemove, mod.HeadersToSet)
	}
	if strings.Contains(strings.ToLower(cookieHeader), strings.ToLower(cookieName)+"=") {
		t.Fatalf("expected cookie %q to be stripped; got Cookie header %q", cookieName, cookieHeader)
	}
}

func assertImmediate(t *testing.T, action policy.RequestHeaderAction, wantStatus int, wantErrorKey string) {
	t.Helper()
	resp, ok := action.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("expected ImmediateResponse, got %T", action)
	}
	if resp.StatusCode != wantStatus {
		t.Fatalf("expected status %d, got %d", wantStatus, resp.StatusCode)
	}
	var body map[string]interface{}
	if err := json.Unmarshal(resp.Body, &body); err != nil {
		t.Fatalf("failed to unmarshal body: %v", err)
	}
	if body["error"] != wantErrorKey {
		t.Fatalf("expected error=%q, got %q", wantErrorKey, body["error"])
	}
	// Every rejection this policy makes must reach the gateway's fault flow and describe
	// itself well enough for a renderer and for analytics categorisation.
	if !resp.IsFault {
		t.Fatalf("expected IsFault=true on a rejection")
	}
	if resp.Fault == nil {
		t.Fatalf("expected Error to be populated on a rejection")
	}
	if resp.Fault.Code == "" {
		t.Fatalf("expected Error.Code to be set")
	}
	if resp.Fault.Direction != policy.DirectionRequest {
		t.Fatalf("expected Error.Direction=%q, got %q", policy.DirectionRequest, resp.Fault.Direction)
	}
}

func assertRateLimitHeaders(t *testing.T, resp policy.ImmediateResponse, wantLimit, wantRemaining int) {
	t.Helper()
	if resp.Headers == nil {
		t.Fatalf("expected headers to be set")
	}
	assertIntHeader := func(key string, want int) {
		gotRaw, ok := resp.Headers[key]
		if !ok {
			t.Fatalf("missing rate-limit header %q", key)
		}
		got, err := strconv.Atoi(gotRaw)
		if err != nil {
			t.Fatalf("rate-limit header %q value %q is not an int: %v", key, gotRaw, err)
		}
		if got != want {
			t.Fatalf("rate-limit header %q expected %d, got %d", key, want, got)
		}
	}

	if ct, ok := resp.Headers["Content-Type"]; !ok || ct != "application/json" {
		t.Fatalf("expected Content-Type=application/json, got %q (ok=%v)", ct, ok)
	}

	assertIntHeader("X-RateLimit-Limit", wantLimit)
	assertIntHeader("X-RateLimit-Remaining", wantRemaining)
	assertIntHeader("RateLimit-Limit", wantLimit)
	assertIntHeader("RateLimit-Remaining", wantRemaining)

	// Reset-related headers can be time-sensitive; assert they are present and parse.
	parseInt64Header := func(key string) int64 {
		gotRaw, ok := resp.Headers[key]
		if !ok {
			t.Fatalf("missing rate-limit header %q", key)
		}
		got, err := strconv.ParseInt(gotRaw, 10, 64)
		if err != nil {
			t.Fatalf("rate-limit header %q value %q is not an int64: %v", key, gotRaw, err)
		}
		return got
	}

	xResetUnix := parseInt64Header("X-RateLimit-Reset")
	if xResetUnix < 0 {
		t.Fatalf("expected X-RateLimit-Reset >= 0, got %d", xResetUnix)
	}
	_ = parseInt64Header("X-RateLimit-Full-Quota-Reset")

	rResetSeconds := parseInt64Header("RateLimit-Reset")
	if rResetSeconds < 0 {
		t.Fatalf("expected RateLimit-Reset >= 0, got %d", rResetSeconds)
	}
	_ = parseInt64Header("RateLimit-Full-Quota-Reset")

	if policyValue, ok := resp.Headers["RateLimit-Policy"]; !ok || policyValue == "" {
		t.Fatalf("missing/empty rate-limit header %q", "RateLimit-Policy")
	}

	retryAfter := parseInt64Header("Retry-After")
	if retryAfter < 1 {
		t.Fatalf("expected Retry-After >= 1, got %d", retryAfter)
	}
}

// --- mergeConfig tests -------------------------------------------------------

func TestMergeConfig_Defaults(t *testing.T) {
	cfg := mergeConfig(defaultCfg(), nil)
	if cfg.SubscriptionKeyHeader != defaultSubscriptionKeyHeader {
		t.Fatalf("expected default header=%q, got %q", defaultSubscriptionKeyHeader, cfg.SubscriptionKeyHeader)
	}
}

func TestMergeConfig_Overrides(t *testing.T) {
	cfg := mergeConfig(defaultCfg(), map[string]interface{}{
		"subscriptionKeyHeader": "X-My-Key",
		"subscriptionKeyCookie": "sub-key",
	})
	if cfg.SubscriptionKeyHeader != "X-My-Key" {
		t.Fatalf("expected header=X-My-Key, got %q", cfg.SubscriptionKeyHeader)
	}
	if cfg.SubscriptionKeyCookie != "sub-key" {
		t.Fatalf("expected cookie=sub-key, got %q", cfg.SubscriptionKeyCookie)
	}
}

// --- token path (primary) ----------------------------------------------------

func TestOnRequestHeaders_AllowsValidToken(t *testing.T) {
	store := newStore([]policyenginev1.SubscriptionData{
		{APIId: "api-1", SubscriptionToken: policyenginev1.HashSubscriptionToken("tok-1"), Status: "ACTIVE"},
	})
	p := newPolicy(defaultCfg(), store)
	ctx := headerCtxWithToken("api-1", "tok-1", "")
	action := p.OnRequestHeaders(context.Background(), ctx, make(map[string]interface{}))
	assertSuccess(t, action)
	assertHeaderRemoved(t, action, defaultSubscriptionKeyHeader)
}

func TestOnRequestHeaders_DeniesInvalidToken(t *testing.T) {
	store := newStore([]policyenginev1.SubscriptionData{
		{APIId: "api-1", SubscriptionToken: policyenginev1.HashSubscriptionToken("tok-1"), Status: "ACTIVE"},
	})
	p := newPolicy(defaultCfg(), store)
	ctx := headerCtxWithToken("api-1", "wrong-token", "")
	assertImmediate(t, p.OnRequestHeaders(context.Background(), ctx, make(map[string]interface{})), 403, "forbidden")
}

func TestOnRequestHeaders_DeniesInactiveToken(t *testing.T) {
	store := newStore([]policyenginev1.SubscriptionData{
		{APIId: "api-1", SubscriptionToken: policyenginev1.HashSubscriptionToken("tok-1"), Status: "INACTIVE"},
	})
	p := newPolicy(defaultCfg(), store)
	ctx := headerCtxWithToken("api-1", "tok-1", "")
	assertImmediate(t, p.OnRequestHeaders(context.Background(), ctx, make(map[string]interface{})), 403, "forbidden")
}

func TestOnRequestHeaders_CustomHeaderName(t *testing.T) {
	store := newStore([]policyenginev1.SubscriptionData{
		{APIId: "api-1", SubscriptionToken: policyenginev1.HashSubscriptionToken("tok-1"), Status: "ACTIVE"},
	})
	cfg := defaultCfg()
	cfg.SubscriptionKeyHeader = "X-Custom-Sub"
	p := newPolicy(cfg, store)

	ctx := headerCtxWithToken("api-1", "tok-1", "X-Custom-Sub")
	action := p.OnRequestHeaders(context.Background(), ctx, make(map[string]interface{}))
	assertSuccess(t, action)
	assertHeaderRemoved(t, action, "X-Custom-Sub")
}

// --- cookie path -------------------------------------------------------------

func TestOnRequestHeaders_AllowsValidTokenFromCookie(t *testing.T) {
	store := newStore([]policyenginev1.SubscriptionData{
		{APIId: "api-1", SubscriptionToken: policyenginev1.HashSubscriptionToken("tok-1"), Status: "ACTIVE"},
	})
	cfg := defaultCfg()
	cfg.SubscriptionKeyCookie = "sub-key"
	p := newPolicy(cfg, store)
	ctx := headerCtxWithCookie("api-1", "tok-1", "sub-key")
	action := p.OnRequestHeaders(context.Background(), ctx, make(map[string]interface{}))
	assertSuccess(t, action)
	assertCookieStripped(t, action, "sub-key")
}

func TestOnRequestHeaders_CookieDeniesInvalidToken(t *testing.T) {
	store := newStore([]policyenginev1.SubscriptionData{
		{APIId: "api-1", SubscriptionToken: policyenginev1.HashSubscriptionToken("tok-1"), Status: "ACTIVE"},
	})
	cfg := defaultCfg()
	cfg.SubscriptionKeyCookie = "sub-key"
	p := newPolicy(cfg, store)
	ctx := headerCtxWithCookie("api-1", "wrong-token", "sub-key")
	assertImmediate(t, p.OnRequestHeaders(context.Background(), ctx, make(map[string]interface{})), 403, "forbidden")
}

func TestOnRequestHeaders_HeaderTakesPrecedenceOverCookie(t *testing.T) {
	store := newStore([]policyenginev1.SubscriptionData{
		{APIId: "api-1", SubscriptionToken: policyenginev1.HashSubscriptionToken("tok-1"), Status: "ACTIVE"},
	})
	cfg := defaultCfg()
	cfg.SubscriptionKeyCookie = "sub-key"
	p := newPolicy(cfg, store)
	ctx := &policy.RequestHeaderContext{
		SharedContext: &policy.SharedContext{
			APIId:    "api-1",
			Metadata: map[string]interface{}{},
		},
		Headers: policy.NewHeaders(map[string][]string{
			defaultSubscriptionKeyHeader: {"tok-1"},
			"Cookie":                     {"sub-key=wrong-token"},
		}),
	}
	// Header value should be used; tok-1 is valid
	action := p.OnRequestHeaders(context.Background(), ctx, make(map[string]interface{}))
	assertSuccess(t, action)
	assertHeaderRemoved(t, action, defaultSubscriptionKeyHeader)
}

func TestOnRequestHeaders_CookieUsedWhenHeaderMissing(t *testing.T) {
	store := newStore([]policyenginev1.SubscriptionData{
		{APIId: "api-1", SubscriptionToken: policyenginev1.HashSubscriptionToken("tok-1"), Status: "ACTIVE"},
	})
	cfg := defaultCfg()
	cfg.SubscriptionKeyCookie = "sub-key"
	p := newPolicy(cfg, store)
	ctx := headerCtxWithCookie("api-1", "tok-1", "sub-key")
	action := p.OnRequestHeaders(context.Background(), ctx, make(map[string]interface{}))
	assertSuccess(t, action)
	assertCookieStripped(t, action, "sub-key")
}

func TestGetCookieValue(t *testing.T) {
	tests := []struct {
		name    string
		headers map[string][]string
		cookie  string
		want    string
	}{
		{"single cookie", map[string][]string{"Cookie": {"sub-key=tok-1"}}, "sub-key", "tok-1"},
		{"multiple cookies", map[string][]string{"Cookie": {"a=1; sub-key=tok-1; b=2"}}, "sub-key", "tok-1"},
		{"missing cookie", map[string][]string{"Cookie": {"other=val"}}, "sub-key", ""},
		{"no cookie header", map[string][]string{}, "sub-key", ""},
		{"case insensitive name", map[string][]string{"Cookie": {"Sub-Key=tok-1"}}, "sub-key", "tok-1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := policy.NewHeaders(tt.headers)
			got := getCookieValue(h, tt.cookie)
			if got != tt.want {
				t.Fatalf("getCookieValue(%q) = %q, want %q", tt.cookie, got, tt.want)
			}
		})
	}
}

// --- appId fallback (legacy) -------------------------------------------------

func TestOnRequestHeaders_FallbackAppIdAllows(t *testing.T) {
	store := newStore([]policyenginev1.SubscriptionData{
		{APIId: "api-1", ApplicationId: "app-1", Status: "ACTIVE"},
	})
	p := newPolicy(defaultCfg(), store)
	ctx := headerCtxWithAppID("api-1", "app-1")
	assertSuccess(t, p.OnRequestHeaders(context.Background(), ctx, make(map[string]interface{})))
}

func TestOnRequestHeaders_FallbackAppIdDenies(t *testing.T) {
	store := newStore([]policyenginev1.SubscriptionData{
		{APIId: "api-1", ApplicationId: "app-1", Status: "ACTIVE"},
	})
	p := newPolicy(defaultCfg(), store)
	ctx := headerCtxWithAppID("api-1", "app-wrong")
	assertImmediate(t, p.OnRequestHeaders(context.Background(), ctx, make(map[string]interface{})), 403, "forbidden")
}

// --- no identity at all ------------------------------------------------------

func TestOnRequestHeaders_DeniesWhenNoIdentity(t *testing.T) {
	store := newStore(nil)
	p := newPolicy(defaultCfg(), store)
	ctx := &policy.RequestHeaderContext{
		SharedContext: &policy.SharedContext{
			APIId:    "api-1",
			Metadata: map[string]interface{}{},
		},
		Headers: policy.NewHeaders(nil),
	}
	assertImmediate(t, p.OnRequestHeaders(context.Background(), ctx, make(map[string]interface{})), 403, "forbidden")
}

// --- missing apiId fails closed ----------------------------------------------

func TestOnRequestHeaders_FailsClosedWhenAPIIdMissing(t *testing.T) {
	store := newStore(nil)
	p := newPolicy(defaultCfg(), store)
	ctx := &policy.RequestHeaderContext{
		SharedContext: &policy.SharedContext{
			APIId:    "",
			Metadata: map[string]interface{}{},
		},
		Headers: policy.NewHeaders(nil),
	}
	assertImmediate(t, p.OnRequestHeaders(context.Background(), ctx, make(map[string]interface{})), 403, "forbidden")
}

// --- rate limiting -----------------------------------------------------------

func TestOnRequestHeaders_RateLimitEnforced(t *testing.T) {
	store := newStore([]policyenginev1.SubscriptionData{
		{
			APIId:              "api-1",
			SubscriptionToken:  policyenginev1.HashSubscriptionToken("tok-1"),
			Status:             "ACTIVE",
			ThrottleLimitCount: 3,
			ThrottleLimitUnit:  "Min",
			StopOnQuotaReach:   true,
		},
	})
	p := newPolicy(defaultCfg(), store)

	for i := 0; i < 3; i++ {
		ctx := headerCtxWithToken("api-1", "tok-1", "")
		action := p.OnRequestHeaders(context.Background(), ctx, make(map[string]interface{}))
		assertSuccess(t, action)
		assertHeaderRemoved(t, action, defaultSubscriptionKeyHeader)
	}

	ctx := headerCtxWithToken("api-1", "tok-1", "")
	action := p.OnRequestHeaders(context.Background(), ctx, make(map[string]interface{}))
	resp, ok := action.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("expected ImmediateResponse, got %T", action)
	}
	if resp.StatusCode != 429 {
		t.Fatalf("expected status 429, got %d", resp.StatusCode)
	}
	var body map[string]interface{}
	if err := json.Unmarshal(resp.Body, &body); err != nil {
		t.Fatalf("failed to unmarshal body: %v", err)
	}
	if body["error"] != "rate_limit_exceeded" {
		t.Fatalf("expected error=%q, got %q", "rate_limit_exceeded", body["error"])
	}
	assertRateLimitHeaders(t, resp, 3, 0)
}

func TestOnRequestHeaders_RateLimitNotEnforcedWhenStopOnQuotaFalse(t *testing.T) {
	store := newStore([]policyenginev1.SubscriptionData{
		{
			APIId:              "api-1",
			SubscriptionToken:  policyenginev1.HashSubscriptionToken("tok-1"),
			Status:             "ACTIVE",
			ThrottleLimitCount: 1,
			ThrottleLimitUnit:  "Min",
			StopOnQuotaReach:   false,
		},
	})
	p := newPolicy(defaultCfg(), store)

	for i := 0; i < 5; i++ {
		ctx := headerCtxWithToken("api-1", "tok-1", "")
		action := p.OnRequestHeaders(context.Background(), ctx, make(map[string]interface{}))
		if _, ok := action.(policy.UpstreamRequestHeaderModifications); !ok {
			t.Fatalf("request %d should be allowed (stopOnQuotaReach=false), got %#v", i+1, action)
		}
	}
}

func TestOnRequestHeaders_NoRateLimitWithoutPlan(t *testing.T) {
	store := newStore([]policyenginev1.SubscriptionData{
		{APIId: "api-1", SubscriptionToken: policyenginev1.HashSubscriptionToken("tok-1"), Status: "ACTIVE"},
	})
	p := newPolicy(defaultCfg(), store)

	for i := 0; i < 100; i++ {
		ctx := headerCtxWithToken("api-1", "tok-1", "")
		action := p.OnRequestHeaders(context.Background(), ctx, make(map[string]interface{}))
		if _, ok := action.(policy.UpstreamRequestHeaderModifications); !ok {
			t.Fatalf("request %d should be allowed (no throttle plan), got %#v", i+1, action)
		}
	}
}

// --- token takes precedence over appId ---------------------------------------

func TestOnRequestHeaders_TokenTakesPrecedenceOverAppId(t *testing.T) {
	store := newStore([]policyenginev1.SubscriptionData{
		{APIId: "api-1", SubscriptionToken: policyenginev1.HashSubscriptionToken("tok-1"), Status: "ACTIVE"},
		{APIId: "api-1", ApplicationId: "app-1", Status: "ACTIVE"},
	})
	p := newPolicy(defaultCfg(), store)

	ctx := &policy.RequestHeaderContext{
		SharedContext: &policy.SharedContext{
			APIId: "api-1",
			Metadata: map[string]interface{}{
				applicationIDMetadataKey: "app-1",
			},
		},
		Headers: policy.NewHeaders(map[string][]string{
			defaultSubscriptionKeyHeader: {"wrong-token"},
		}),
	}
	// Token path should be tried first and should fail (wrong token),
	// even though appId path would succeed.
	assertImmediate(t, p.OnRequestHeaders(context.Background(), ctx, make(map[string]interface{})), 403, "forbidden")
}

// --- nil context / nil store guards ------------------------------------------

func TestOnRequestHeaders_NilContext(t *testing.T) {
	p := newPolicy(defaultCfg(), policyenginev1.NewSubscriptionStore())
	assertImmediate(t, p.OnRequestHeaders(context.Background(), nil, make(map[string]interface{})), 403, "forbidden")
}

func TestOnRequestHeaders_NilStore(t *testing.T) {
	p := newPolicy(defaultCfg(), nil)
	ctx := headerCtxWithToken("api-1", "tok-1", "")
	assertImmediate(t, p.OnRequestHeaders(context.Background(), ctx, make(map[string]interface{})), 403, "forbidden")
}

// --- billing metadata in SharedContext.Metadata -----------------------------

func billingStr(s string) *string { return &s }

func TestOnRequestHeaders_WritesBillingMetadataOnTokenSuccess(t *testing.T) {
	custID := "cust-123"
	subID := "sub-456"
	store := newStore([]policyenginev1.SubscriptionData{
		{
			APIId:                 "api-1",
			SubscriptionToken:     policyenginev1.HashSubscriptionToken("tok-1"),
			Status:                "ACTIVE",
			PlanName:              "Pro",
			BillingCustomerId:     billingStr(custID),
			BillingSubscriptionId: billingStr(subID),
		},
	})
	p := newPolicy(defaultCfg(), store)
	ctx := headerCtxWithToken("api-1", "tok-1", "")
	action := p.OnRequestHeaders(context.Background(), ctx, make(map[string]interface{}))
	assertSuccess(t, action)

	md := ctx.SharedContext.Metadata
	if got, ok := md[billingCustomerIDMetadataKey].(string); !ok || got != custID {
		t.Fatalf("expected %s=%q in metadata, got %v", billingCustomerIDMetadataKey, custID, md[billingCustomerIDMetadataKey])
	}
	if got, ok := md[billingSubscriptionIDMetadataKey].(string); !ok || got != subID {
		t.Fatalf("expected %s=%q in metadata, got %v", billingSubscriptionIDMetadataKey, subID, md[billingSubscriptionIDMetadataKey])
	}
	if got, ok := md[subscriptionStatusMetadataKey].(string); !ok || got != "ACTIVE" {
		t.Fatalf("expected %s=%q in metadata, got %v", subscriptionStatusMetadataKey, "ACTIVE", md[subscriptionStatusMetadataKey])
	}
	if got, ok := md[subscriptionPlanNameMetadataKey].(string); !ok || got != "Pro" {
		t.Fatalf("expected %s=%q in metadata, got %v", subscriptionPlanNameMetadataKey, "Pro", md[subscriptionPlanNameMetadataKey])
	}
}

func TestOnRequestHeaders_WritesBillingMetadataOnCookieSuccess(t *testing.T) {
	custID := "cust-cookie"
	store := newStore([]policyenginev1.SubscriptionData{
		{
			APIId:             "api-1",
			SubscriptionToken: policyenginev1.HashSubscriptionToken("tok-1"),
			Status:            "ACTIVE",
			PlanName:          "Basic",
			BillingCustomerId: billingStr(custID),
		},
	})
	cfg := defaultCfg()
	cfg.SubscriptionKeyCookie = "sub-key"
	p := newPolicy(cfg, store)
	ctx := headerCtxWithCookie("api-1", "tok-1", "sub-key")
	action := p.OnRequestHeaders(context.Background(), ctx, make(map[string]interface{}))
	assertSuccess(t, action)

	md := ctx.SharedContext.Metadata
	if got, ok := md[billingCustomerIDMetadataKey].(string); !ok || got != custID {
		t.Fatalf("expected %s=%q in metadata, got %v", billingCustomerIDMetadataKey, custID, md[billingCustomerIDMetadataKey])
	}
	if got, ok := md[subscriptionPlanNameMetadataKey].(string); !ok || got != "Basic" {
		t.Fatalf("expected %s=%q in metadata, got %v", subscriptionPlanNameMetadataKey, "Basic", md[subscriptionPlanNameMetadataKey])
	}
}

func TestOnRequestHeaders_WritesBillingMetadataOnAppIDSuccess(t *testing.T) {
	subID := "sub-app"
	store := newStore([]policyenginev1.SubscriptionData{
		{
			APIId:                 "api-1",
			ApplicationId:         "app-1",
			Status:                "ACTIVE",
			BillingSubscriptionId: billingStr(subID),
		},
	})
	p := newPolicy(defaultCfg(), store)
	ctx := headerCtxWithAppID("api-1", "app-1")
	action := p.OnRequestHeaders(context.Background(), ctx, make(map[string]interface{}))
	assertSuccess(t, action)

	md := ctx.SharedContext.Metadata
	if got, ok := md[billingSubscriptionIDMetadataKey].(string); !ok || got != subID {
		t.Fatalf("expected %s=%q in metadata, got %v", billingSubscriptionIDMetadataKey, subID, md[billingSubscriptionIDMetadataKey])
	}
}

func TestOnRequestHeaders_NoBillingMetadataOnFailure(t *testing.T) {
	store := newStore([]policyenginev1.SubscriptionData{
		{APIId: "api-1", SubscriptionToken: policyenginev1.HashSubscriptionToken("tok-1"), Status: "ACTIVE"},
	})
	p := newPolicy(defaultCfg(), store)
	ctx := headerCtxWithToken("api-1", "wrong-token", "")
	action := p.OnRequestHeaders(context.Background(), ctx, make(map[string]interface{}))
	assertImmediate(t, action, 403, "forbidden")

	md := ctx.SharedContext.Metadata
	if _, ok := md[billingCustomerIDMetadataKey]; ok {
		t.Fatalf("expected no billing metadata on failure, got %v", md[billingCustomerIDMetadataKey])
	}
}

func TestOnRequestHeaders_PartialBillingMetadata(t *testing.T) {
	// Only PlanName is set; nil billing IDs must not appear in metadata.
	store := newStore([]policyenginev1.SubscriptionData{
		{
			APIId:             "api-1",
			SubscriptionToken: policyenginev1.HashSubscriptionToken("tok-1"),
			Status:            "ACTIVE",
			PlanName:          "Free",
		},
	})
	p := newPolicy(defaultCfg(), store)
	ctx := headerCtxWithToken("api-1", "tok-1", "")
	p.OnRequestHeaders(context.Background(), ctx, make(map[string]interface{}))

	md := ctx.SharedContext.Metadata
	if got, ok := md[subscriptionPlanNameMetadataKey].(string); !ok || got != "Free" {
		t.Fatalf("expected plan name in metadata, got %v", md[subscriptionPlanNameMetadataKey])
	}
	if _, ok := md[billingCustomerIDMetadataKey]; ok {
		t.Fatalf("expected billingCustomerID absent when nil, got %v", md[billingCustomerIDMetadataKey])
	}
	if _, ok := md[billingSubscriptionIDMetadataKey]; ok {
		t.Fatalf("expected billingSubscriptionID absent when nil, got %v", md[billingSubscriptionIDMetadataKey])
	}
}

// TestRejectionErrorCodes pins the code chosen per rejection condition. The code, not the
// status, is what tells one condition from another.
func TestRejectionErrorCodes(t *testing.T) {
	t.Run("no active subscription", func(t *testing.T) {
		store := newStore([]policyenginev1.SubscriptionData{
			{APIId: "api-1", SubscriptionToken: policyenginev1.HashSubscriptionToken("tok-1"), Status: "ACTIVE"},
		})
		p := newPolicy(defaultCfg(), store)
		ctx := headerCtxWithToken("api-1", "tok-wrong", "")
		resp := mustImmediate(t, p.OnRequestHeaders(context.Background(), ctx, make(map[string]interface{})))
		assertBody(t, resp, `{"error":"forbidden","message":"Subscription required for this API"}`)
		if resp.Fault.Code != policy.FaultCodeSubscriptionInactive {
			t.Fatalf("expected Error.Code=%q, got %q", policy.FaultCodeSubscriptionInactive, resp.Fault.Code)
		}
		if resp.Fault.Type != policy.FaultTypeAuthentication {
			t.Fatalf("expected Error.Type=%q, got %q", policy.FaultTypeAuthentication, resp.Fault.Type)
		}
	})

	t.Run("subscription plan limit exceeded", func(t *testing.T) {
		store := newStore([]policyenginev1.SubscriptionData{
			{
				APIId:              "api-1",
				SubscriptionToken:  policyenginev1.HashSubscriptionToken("tok-1"),
				Status:             "ACTIVE",
				ThrottleLimitCount: 1,
				ThrottleLimitUnit:  "Min",
				StopOnQuotaReach:   true,
			},
		})
		p := newPolicy(defaultCfg(), store)
		p.OnRequestHeaders(context.Background(), headerCtxWithToken("api-1", "tok-1", ""), make(map[string]interface{}))

		ctx := headerCtxWithToken("api-1", "tok-1", "")
		resp := mustImmediate(t, p.OnRequestHeaders(context.Background(), ctx, make(map[string]interface{})))
		if resp.StatusCode != 429 {
			t.Fatalf("expected the throttled response, got status %d", resp.StatusCode)
		}
		assertBody(t, resp, `{"error":"rate_limit_exceeded","message":"Subscription quota exceeded: 1 requests per Min"}`)
		if resp.Fault.Code != policy.FaultCodeThrottledSubscription {
			t.Fatalf("expected Error.Code=%q, got %q", policy.FaultCodeThrottledSubscription, resp.Fault.Code)
		}
		if resp.Fault.Type != policy.FaultTypeThrottling {
			t.Fatalf("expected Error.Type=%q, got %q", policy.FaultTypeThrottling, resp.Fault.Type)
		}
	})

	t.Run("no identity presented", func(t *testing.T) {
		p := newPolicy(defaultCfg(), newStore(nil))
		ctx := headerCtxWithToken("api-1", "", "")
		resp := mustImmediate(t, p.OnRequestHeaders(context.Background(), ctx, make(map[string]interface{})))
		assertBody(t, resp, `{"error":"forbidden","message":"Subscription required for this API: no subscription token or application identity provided"}`)
		if resp.Fault.Code != policy.FaultCodeAuthMissingCredentials {
			t.Fatalf("expected Error.Code=%q, got %q", policy.FaultCodeAuthMissingCredentials, resp.Fault.Code)
		}
		if resp.Fault.Type != policy.FaultTypeAuthentication {
			t.Fatalf("expected Error.Type=%q, got %q", policy.FaultTypeAuthentication, resp.Fault.Type)
		}
	})

	// The gateway not supplying what the policy needs is the policy failing to do its
	// job, not the caller failing to authenticate.
	for name, tc := range map[string]struct {
		store   *policyenginev1.SubscriptionStore
		apiID   string
		message string
	}{
		"API id is missing":                   {newStore(nil), "", "Subscription required for this API: API id is missing"},
		"subscription store is not available": {nil, "api-1", "Subscription required for this API: subscription store is not available"},
	} {
		t.Run(name, func(t *testing.T) {
			p := newPolicy(defaultCfg(), tc.store)
			ctx := headerCtxWithToken(tc.apiID, "tok-1", "")
			resp := mustImmediate(t, p.OnRequestHeaders(context.Background(), ctx, make(map[string]interface{})))
			assertBody(t, resp, `{"error":"forbidden","message":"`+tc.message+`"}`)
			if resp.Fault.Code != policy.FaultCodeMediationFailed || resp.Fault.Type != policy.FaultTypeMediation {
				t.Fatalf("fault = %s/%s, want %s/%s", resp.Fault.Code, resp.Fault.Type, policy.FaultCodeMediationFailed, policy.FaultTypeMediation)
			}
		})
	}
}

// assertBody asserts the client receives exactly want: declaring the fault must not change
// the body.
func assertBody(t *testing.T, resp policy.ImmediateResponse, want string) {
	t.Helper()
	if string(resp.Body) != want {
		t.Fatalf("body = %s, want %s", resp.Body, want)
	}
}

func mustImmediate(t *testing.T, action policy.RequestHeaderAction) policy.ImmediateResponse {
	t.Helper()
	resp, ok := action.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("expected ImmediateResponse, got %T", action)
	}
	if !resp.IsFault {
		t.Fatalf("expected IsFault=true on a rejection")
	}
	if resp.Fault == nil {
		t.Fatalf("expected Error to be populated on a rejection")
	}
	return resp
}
