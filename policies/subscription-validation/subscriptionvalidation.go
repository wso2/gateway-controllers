package subscriptionvalidation

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"time"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
	policyenginev1 "github.com/wso2/api-platform/sdk/core/policyengine"
)

const (
	defaultSubscriptionKeyHeader     = "Subscription-Key"
	defaultSubscriptionKeyCookie     = ""
	applicationIDMetadataKey         = "x-wso2-application-id"
	forbiddenStatusCode              = 403
	forbiddenMessage                 = "Subscription required for this API"
	billingCustomerIDMetadataKey     = "x-wso2-billing-customer-id"
	billingSubscriptionIDMetadataKey = "x-wso2-billing-subscription-id"
	subscriptionStatusMetadataKey    = "x-wso2-subscription-status"
	subscriptionPlanNameMetadataKey  = "x-wso2-subscription-plan-name"

	// Eviction TTL: entries not seen in this duration are removed to prevent unbounded growth.
	rateLimitEvictionTTL     = 2 * time.Hour
	rateLimitCleanupInterval = 10 * time.Minute
)

// PolicyConfig holds the resolved configuration for the subscriptionValidation policy.
type PolicyConfig struct {
	SubscriptionKeyHeader string
	SubscriptionKeyCookie string
}

// rateLimitEntry tracks per-token request counts within a time window.
type rateLimitEntry struct {
	windowStart time.Time
	count       int
	lastSeen    time.Time // used for TTL eviction
}

// SubscriptionValidationPolicy validates that the caller has an active
// subscription for the requested API and enforces plan-based rate limits.
type SubscriptionValidationPolicy struct {
	cfg   PolicyConfig
	store *policyenginev1.SubscriptionStore

	rateLimitMu *sync.Mutex
	rateLimits  map[string]*rateLimitEntry // key: "apiId:token"
}

var (
	sharedRateLimitMu = &sync.Mutex{}
	ins               = &SubscriptionValidationPolicy{
		cfg: PolicyConfig{
			SubscriptionKeyHeader: defaultSubscriptionKeyHeader,
			SubscriptionKeyCookie: defaultSubscriptionKeyCookie,
		},
		store:       policyenginev1.GetSubscriptionStoreInstance(),
		rateLimitMu: sharedRateLimitMu,
		rateLimits:  make(map[string]*rateLimitEntry),
	}
)

func init() {
	go runRateLimitCleaner()
}

// runRateLimitCleaner periodically evicts stale entries from the shared rateLimits map.
func runRateLimitCleaner() {
	ticker := time.NewTicker(rateLimitCleanupInterval)
	defer ticker.Stop()
	for range ticker.C {
		ins.rateLimitMu.Lock()
		cutoff := time.Now().Add(-rateLimitEvictionTTL)
		for key, e := range ins.rateLimits {
			if e != nil && e.lastSeen.Before(cutoff) {
				delete(ins.rateLimits, key)
			}
		}
		ins.rateLimitMu.Unlock()
	}
}

// GetPolicy is the v1alpha2 factory entry point (loaded by v1alpha2 kernels).
func GetPolicy(
	metadata policy.PolicyMetadata,
	params map[string]interface{},
) (policy.Policy, error) {
	p := &SubscriptionValidationPolicy{
		cfg:         mergeConfig(ins.cfg, params),
		store:       ins.store,
		rateLimitMu: ins.rateLimitMu,
		rateLimits:  ins.rateLimits,
	}
	return p, nil
}

// mergeConfig merges raw parameters from the policy configuration into a base config.
func mergeConfig(base PolicyConfig, params map[string]interface{}) PolicyConfig {
	cfg := base
	if params == nil {
		return cfg
	}

	if raw, ok := params["subscriptionKeyHeader"]; ok {
		if s, ok := raw.(string); ok && strings.TrimSpace(s) != "" {
			cfg.SubscriptionKeyHeader = strings.TrimSpace(s)
		}
	}

	if raw, ok := params["subscriptionKeyCookie"]; ok {
		if s, ok := raw.(string); ok {
			cfg.SubscriptionKeyCookie = strings.TrimSpace(s)
		}
	}

	return cfg
}

// windowDuration converts a throttle unit string to a time.Duration.
func windowDuration(unit string) time.Duration {
	switch strings.ToLower(unit) {
	case "min":
		return time.Minute
	case "hour":
		return time.Hour
	case "day":
		return 24 * time.Hour
	case "month":
		return 30 * 24 * time.Hour
	default:
		return 0
	}
}

// entryThrottleUnitString returns a human-friendly unit string for the throttling window.
// We avoid exposing the exact unit parsing logic externally.
func entryThrottleUnitString(window time.Duration) string {
	switch window {
	case time.Minute:
		return "Min"
	case time.Hour:
		return "Hour"
	case 24 * time.Hour:
		return "Day"
	default:
		return window.String()
	}
}

func normalizeHeaderName(name string) string {
	return strings.ToLower(strings.TrimSpace(name))
}

// stripCookie removes the cookie with the given name from Cookie header values.
// It returns the updated Cookie header (single header value) and whether a removal occurred.
func stripCookie(cookieHeaderValues []string, cookieName string) (string, bool) {
	if cookieName == "" || len(cookieHeaderValues) == 0 {
		return "", false
	}

	parts := make([]string, 0, 8)
	removed := false

	for _, raw := range cookieHeaderValues {
		for _, part := range strings.Split(raw, ";") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			idx := strings.Index(part, "=")
			if idx < 0 {
				parts = append(parts, part)
				continue
			}
			name := strings.TrimSpace(part[:idx])
			if strings.EqualFold(name, cookieName) {
				removed = true
				continue
			}
			parts = append(parts, part)
		}
	}

	if !removed {
		return "", false
	}
	return strings.Join(parts, "; "), true
}

// Mode returns the processing mode for this policy.
func (p *SubscriptionValidationPolicy) Mode() policy.ProcessingMode {
	return policy.ProcessingMode{
		RequestHeaderMode:  policy.HeaderModeProcess,
		RequestBodyMode:    policy.BodyModeSkip,
		ResponseHeaderMode: policy.HeaderModeSkip,
		ResponseBodyMode:   policy.BodyModeSkip,
	}
}

// OnRequestHeaders validates the subscription in the request header phase.
func (p *SubscriptionValidationPolicy) OnRequestHeaders(ctx context.Context, reqCtx *policy.RequestHeaderContext, params map[string]interface{}) policy.RequestHeaderAction {
	if ctx == nil || reqCtx == nil || reqCtx.SharedContext == nil {
		return p.forbiddenResponse("request context is missing").(policy.ImmediateResponse)
	}

	apiID := reqCtx.SharedContext.APIId
	if strings.TrimSpace(apiID) == "" {
		slog.Error("subscriptionValidation: APIId is empty in SharedContext; failing validation")
		return p.forbiddenResponse("API id is missing").(policy.ImmediateResponse)
	}

	if p.store == nil {
		slog.Error("subscriptionValidation: subscription store is not initialized")
		return p.forbiddenResponse("subscription store is not available").(policy.ImmediateResponse)
	}

	if reqCtx.Headers != nil {
		// Extract the subscription credential from the downstream snapshot
		// so the entitlement decision is made against what the client
		// actually sent, not a value a peer policy rewrote in the header phase.
		ds := getDownstreamHeaders(reqCtx.Downstream, reqCtx.Headers)
		headerValues := ds.Get(p.cfg.SubscriptionKeyHeader)
		if len(headerValues) > 0 {
			token := strings.TrimSpace(headerValues[0])
			if token != "" {
				block, subscription := p.validateByToken(apiID, token)
				if block == nil {
					writeSubscriptionMetadata(reqCtx.SharedContext, subscription)
					return policy.UpstreamRequestHeaderModifications{
						HeadersToRemove: []string{normalizeHeaderName(p.cfg.SubscriptionKeyHeader)},
					}
				}
				return block.(policy.ImmediateResponse)
			}
		}
		if p.cfg.SubscriptionKeyCookie != "" {
			if token := getCookieValue(ds, p.cfg.SubscriptionKeyCookie); token != "" {
				block, subscription := p.validateByToken(apiID, token)
				if block == nil {
					writeSubscriptionMetadata(reqCtx.SharedContext, subscription)
					// The Cookie header is read from the live set here (not the
					// snapshot) because the result is used to rewrite the cookie
					// forwarded upstream — mutations must act on live headers.
					cookieValues := reqCtx.Headers.Get("Cookie")
					updated, removed := stripCookie(cookieValues, p.cfg.SubscriptionKeyCookie)
					if removed {
						if updated == "" {
							return policy.UpstreamRequestHeaderModifications{
								HeadersToRemove: []string{"cookie"},
							}
						}
						return policy.UpstreamRequestHeaderModifications{
							HeadersToSet: map[string]string{"cookie": updated},
						}
					}
					return policy.UpstreamRequestHeaderModifications{}
				}
				return block.(policy.ImmediateResponse)
			}
		}
	}

	metadata := reqCtx.SharedContext.Metadata
	if metadata != nil {
		if rawAppID, ok := metadata[applicationIDMetadataKey]; ok {
			appID := strings.TrimSpace(fmt.Sprint(rawAppID))
			if appID != "" {
				block, subscription := p.validateByApplication(apiID, appID)
				if block == nil {
					writeSubscriptionMetadata(reqCtx.SharedContext, subscription)
					return policy.UpstreamRequestHeaderModifications{}
				}
				return block.(policy.ImmediateResponse)
			}
		}
	}

	return p.forbiddenResponse("no subscription token or application identity provided").(policy.ImmediateResponse)
}

// forbiddenResponse constructs an ImmediateResponse with status 403.
func (p *SubscriptionValidationPolicy) forbiddenResponse(detail string) policy.RequestAction {
	message := forbiddenMessage
	if detail != "" {
		message = fmt.Sprintf("%s: %s", message, detail)
	}

	payload := map[string]string{
		"error":   "forbidden",
		"message": message,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		body = []byte(`{"error":"forbidden","message":"subscription validation failed"}`)
	}

	return policy.ImmediateResponse{
		StatusCode: forbiddenStatusCode,
		Headers: map[string]string{
			"Content-Type": "application/json",
		},
		Body: body,
	}
}

// validateByToken looks up the subscription entry for the given token and enforces
// plan-based rate limits. Returns (nil, entry) on success, (action, nil) on failure.
func (p *SubscriptionValidationPolicy) validateByToken(apiID, token string) (policy.RequestAction, *policyenginev1.SubscriptionEntry) {
	hashedToken := policyenginev1.HashSubscriptionToken(token)
	active, entry := p.store.IsActiveByToken(apiID, hashedToken)
	if !active {
		slog.Info("subscriptionValidation: no active subscription found (token)",
			"apiId", apiID)
		return p.forbiddenResponse(""), nil
	}

	if entry != nil && entry.ThrottleLimitCount > 0 && entry.ThrottleLimitUnit != "" {
		if blocked := p.checkRateLimit(apiID, token, entry); blocked != nil {
			return blocked, nil
		}
	}

	return nil, entry
}

// checkRateLimit enforces the plan's throttle limit for the given token.
func (p *SubscriptionValidationPolicy) checkRateLimit(apiID, token string, entry *policyenginev1.SubscriptionEntry) policy.RequestAction {
	window := windowDuration(entry.ThrottleLimitUnit)
	if window == 0 {
		return nil
	}

	key := apiID + ":" + token
	now := time.Now()

	p.rateLimitMu.Lock()
	rl, exists := p.rateLimits[key]
	if !exists || now.Sub(rl.windowStart) >= window {
		p.rateLimits[key] = &rateLimitEntry{windowStart: now, count: 1, lastSeen: now}
		p.rateLimitMu.Unlock()
		return nil
	}

	rl.count++
	rl.lastSeen = now
	exceeded := rl.count > entry.ThrottleLimitCount
	resetAt := rl.windowStart.Add(window)
	limit := entry.ThrottleLimitCount
	remaining := limit - rl.count
	if remaining < 0 {
		remaining = 0
	}
	p.rateLimitMu.Unlock()

	if exceeded {
		if entry.StopOnQuotaReach {
			return p.rateLimitResponse(limit, remaining, resetAt, window)
		}
		slog.Warn("subscriptionValidation: quota exceeded but stopOnQuotaReach is false, allowing",
			"apiId", apiID)
	}

	return nil
}

// validateByApplication looks up the subscription entry for the given application ID and
// enforces plan-based rate limits. Returns (nil, entry) on success, (action, nil) on failure.
func (p *SubscriptionValidationPolicy) validateByApplication(apiID, appID string) (policy.RequestAction, *policyenginev1.SubscriptionEntry) {
	active, entry := p.store.IsActiveByApplication(apiID, appID)
	if !active {
		slog.Info("subscriptionValidation: no active subscription found (appId fallback)",
			"apiId", apiID,
			"applicationId", appID)
		return p.forbiddenResponse(""), nil
	}

	if entry != nil && entry.ThrottleLimitCount > 0 && entry.ThrottleLimitUnit != "" {
		if blocked := p.checkRateLimit(apiID, appID, entry); blocked != nil {
			return blocked, nil
		}
	}

	return nil, entry
}

// writeSubscriptionMetadata copies billing and plan fields from entry into
// sc.Metadata so downstream policies can access them without an additional store
// lookup. It is a no-op when sc or entry is nil.
func writeSubscriptionMetadata(sc *policy.SharedContext, entry *policyenginev1.SubscriptionEntry) {
	if sc == nil || entry == nil {
		return
	}
	if sc.Metadata == nil {
		sc.Metadata = make(map[string]interface{})
	}
	if entry.BillingCustomerID != nil {
		sc.Metadata[billingCustomerIDMetadataKey] = *entry.BillingCustomerID
	}
	if entry.BillingSubscriptionID != nil {
		sc.Metadata[billingSubscriptionIDMetadataKey] = *entry.BillingSubscriptionID
	}
	if entry.Status != "" {
		sc.Metadata[subscriptionStatusMetadataKey] = entry.Status
	}
	if entry.PlanName != "" {
		sc.Metadata[subscriptionPlanNameMetadataKey] = entry.PlanName
	}
}

// getCookieValue parses the Cookie header and returns the value for the given cookie name.
// Returns empty string if the cookie is not found or Cookie header is missing.
func getCookieValue(headers *policy.Headers, name string) string {
	if headers == nil || name == "" {
		return ""
	}
	vals := headers.Get("Cookie")
	if len(vals) == 0 {
		return ""
	}
	// Cookie header format: "name1=value1; name2=value2"
	for _, raw := range vals {
		for _, part := range strings.Split(raw, ";") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			idx := strings.Index(part, "=")
			if idx < 0 {
				continue
			}
			cookieName := strings.TrimSpace(part[:idx])
			if strings.EqualFold(cookieName, name) {
				return strings.TrimSpace(part[idx+1:])
			}
		}
	}
	return ""
}

// rateLimitResponse constructs a 429 Too Many Requests response.
func (p *SubscriptionValidationPolicy) rateLimitResponse(limit, remaining int, resetAt time.Time, window time.Duration) policy.RequestAction {
	payload := map[string]interface{}{
		"error":   "rate_limit_exceeded",
		"message": fmt.Sprintf("Subscription quota exceeded: %d requests per %s", limit, entryThrottleUnitString(window)),
	}
	body, err := json.Marshal(payload)
	if err != nil {
		body = []byte(`{"error":"rate_limit_exceeded","message":"subscription quota exceeded"}`)
	}

	resetUnix := resetAt.Unix()
	resetSeconds := int64(time.Until(resetAt).Seconds())
	if resetSeconds < 0 {
		resetSeconds = 0
	}
	retryAfterSeconds := resetSeconds
	if retryAfterSeconds < 1 {
		retryAfterSeconds = 1
	}
	windowSeconds := int64(window.Seconds())
	if windowSeconds < 1 {
		windowSeconds = 1
	}
	policyValue := fmt.Sprintf("%d;w=%d", limit, windowSeconds)

	return policy.ImmediateResponse{
		StatusCode: 429,
		Headers: map[string]string{
			"Content-Type": "application/json",
			// X-RateLimit-* (de facto standard)
			"X-RateLimit-Limit":            strconv.Itoa(limit),
			"X-RateLimit-Remaining":        strconv.Itoa(remaining),
			"X-RateLimit-Reset":            strconv.FormatInt(resetUnix, 10),
			"X-RateLimit-Full-Quota-Reset": strconv.FormatInt(resetUnix, 10),
			// RateLimit-* (IETF draft)
			"RateLimit-Limit":            strconv.Itoa(limit),
			"RateLimit-Remaining":        strconv.Itoa(remaining),
			"RateLimit-Reset":            strconv.FormatInt(resetSeconds, 10),
			"RateLimit-Full-Quota-Reset": strconv.FormatInt(resetSeconds, 10),
			"RateLimit-Policy":           policyValue,
			// RFC 7231
			"Retry-After": strconv.FormatInt(retryAfterSeconds, 10),
		},
		Body: body,
	}
}
