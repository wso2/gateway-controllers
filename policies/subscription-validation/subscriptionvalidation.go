package subscriptionvalidation

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	policy "github.com/wso2/api-platform/sdk/gateway/policy/v1alpha"
	policyenginev1 "github.com/wso2/api-platform/sdk/gateway/policyengine/v1"
)

const (
	defaultSubscriptionKeyHeader = "Subscription-Key"
	defaultSubscriptionKeyCookie = ""
	applicationIDMetadataKey     = "x-wso2-application-id"
	forbiddenStatusCode          = 403
	forbiddenMessage             = "Subscription required for this API"

	// Eviction TTL: entries not seen in this duration are removed to prevent unbounded growth.
	rateLimitEvictionTTL    = 2 * time.Hour
	rateLimitCleanupInterval = 10 * time.Minute
)

// PolicyConfig holds the resolved configuration for the subscriptionValidation policy.
type PolicyConfig struct {
	Enabled                bool
	SubscriptionKeyHeader  string
	SubscriptionKeyCookie  string
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
			Enabled:               true,
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

// GetPolicy returns a per-route instance of SubscriptionValidationPolicy.
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

	if raw, ok := params["enabled"]; ok {
		if b, ok := raw.(bool); ok {
			cfg.Enabled = b
		} else if s, ok := raw.(string); ok {
			lower := strings.ToLower(strings.TrimSpace(s))
			cfg.Enabled = lower == "true" || lower == "1" || lower == "yes"
		}
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

// Mode returns the processing mode for this policy.
func (p *SubscriptionValidationPolicy) Mode() policy.ProcessingMode {
	return policy.ProcessingMode{
		RequestHeaderMode:  policy.HeaderModeProcess,
		RequestBodyMode:    policy.BodyModeSkip,
		ResponseHeaderMode: policy.HeaderModeSkip,
		ResponseBodyMode:   policy.BodyModeSkip,
	}
}

// OnRequest validates the subscription (token-first, appId-fallback)
// and enforces plan-based rate limiting when applicable.
func (p *SubscriptionValidationPolicy) OnRequest(ctx *policy.RequestContext, params map[string]interface{}) policy.RequestAction {
	if !p.cfg.Enabled {
		return nil
	}
	if ctx == nil || ctx.SharedContext == nil {
		return p.forbiddenResponse("request context is missing")
	}

	apiID := ctx.SharedContext.APIId
	if strings.TrimSpace(apiID) == "" {
		slog.Error("subscriptionValidation: APIId is empty in SharedContext; failing validation")
		return p.forbiddenResponse("API id is missing")
	}

	if p.store == nil {
		slog.Error("subscriptionValidation: subscription store is not initialized")
		return p.forbiddenResponse("subscription store is not available")
	}

	// Path 1: Check Subscription-Key header (token-based, primary)
	if ctx.Headers != nil {
		headerValues := ctx.Headers.Get(p.cfg.SubscriptionKeyHeader)
		if len(headerValues) > 0 {
			token := strings.TrimSpace(headerValues[0])
			if token != "" {
				return p.validateByToken(apiID, token)
			}
		}
		// Path 1b: Check subscription key cookie if configured
		if p.cfg.SubscriptionKeyCookie != "" {
			if token := getCookieValue(ctx.Headers, p.cfg.SubscriptionKeyCookie); token != "" {
				return p.validateByToken(apiID, token)
			}
		}
	}

	// Path 2: Fallback to application ID from auth metadata (legacy)
	metadata := ctx.SharedContext.Metadata
	if metadata != nil {
		if rawAppID, ok := metadata[applicationIDMetadataKey]; ok {
			appID := strings.TrimSpace(fmt.Sprint(rawAppID))
			if appID != "" {
				return p.validateByApplication(apiID, appID)
			}
		}
	}

	// Neither token nor application ID was provided
	return p.forbiddenResponse("no subscription token or application identity provided")
}

// validateByToken checks the token against the store, then enforces rate limits.
// The store uses hashed tokens; we hash the incoming token before lookup.
func (p *SubscriptionValidationPolicy) validateByToken(apiID, token string) policy.RequestAction {
	hashedToken := policyenginev1.HashSubscriptionToken(token)
	active, entry := p.store.IsActiveByToken(apiID, hashedToken)
	if !active {
		slog.Info("subscriptionValidation: no active subscription found (token)",
			"apiId", apiID)
		return p.forbiddenResponse("")
	}

	if entry != nil && entry.ThrottleLimitCount > 0 && entry.ThrottleLimitUnit != "" {
		if blocked := p.checkRateLimit(apiID, token, entry); blocked != nil {
			return blocked
		}
	}

	return nil
}

// validateByApplication checks the application ID against the store, then enforces rate limits.
// This is the legacy path; it now recovers quota/throttle metadata from the store.
func (p *SubscriptionValidationPolicy) validateByApplication(apiID, appID string) policy.RequestAction {
	active, entry := p.store.IsActiveByApplication(apiID, appID)
	if !active {
		slog.Info("subscriptionValidation: no active subscription found (appId fallback)",
			"apiId", apiID,
			"applicationId", appID)
		return p.forbiddenResponse("")
	}

	if entry != nil && entry.ThrottleLimitCount > 0 && entry.ThrottleLimitUnit != "" {
		if blocked := p.checkRateLimit(apiID, appID, entry); blocked != nil {
			return blocked
		}
	}

	return nil
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
	p.rateLimitMu.Unlock()

	if exceeded {
		if entry.StopOnQuotaReach {
			return p.rateLimitResponse(entry.ThrottleLimitCount, entry.ThrottleLimitUnit)
		}
		slog.Warn("subscriptionValidation: quota exceeded but stopOnQuotaReach is false, allowing",
			"apiId", apiID)
	}

	return nil
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

// OnResponse is a no-op for this policy.
func (p *SubscriptionValidationPolicy) OnResponse(ctx *policy.ResponseContext, params map[string]interface{}) policy.ResponseAction {
	return nil
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

// rateLimitResponse constructs a 429 Too Many Requests response.
func (p *SubscriptionValidationPolicy) rateLimitResponse(limit int, unit string) policy.RequestAction {
	payload := map[string]interface{}{
		"error":   "rate_limit_exceeded",
		"message": fmt.Sprintf("Subscription quota exceeded: %d requests per %s", limit, unit),
	}
	body, err := json.Marshal(payload)
	if err != nil {
		body = []byte(`{"error":"rate_limit_exceeded","message":"subscription quota exceeded"}`)
	}

	return policy.ImmediateResponse{
		StatusCode: 429,
		Headers: map[string]string{
			"Content-Type": "application/json",
		},
		Body: body,
	}
}
