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

package ratelimit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
	_ "github.com/wso2/gateway-controllers/policies/advanced-ratelimit/algorithms/fixedwindow" // Register Fixed Window algorithm
	_ "github.com/wso2/gateway-controllers/policies/advanced-ratelimit/algorithms/gcra"        // Register GCRA algorithm
	"github.com/wso2/gateway-controllers/policies/advanced-ratelimit/limiter"
)

// contextKey is used for storing values in context
type contextKey string

const (
	requestIDKey contextKey = "request_id"
)

// limiterEntry holds a limiter instance with its reference count.
type limiterEntry struct {
	lim      limiter.Limiter
	refCount int
}

// limiterCache provides thread-safe caching of memory-backed limiters.
// Only memory backend limiters are cached; Redis-backed limiters maintain state externally.
type limiterCache struct {
	mu sync.Mutex
	// byQuotaKey maps quota cache keys to limiter entries with reference counts
	byQuotaKey map[string]*limiterEntry
	// quotaKeysByBaseKey tracks which quota keys exist for each policy instance, keyed by a
	// reconcileKey (see reconcileKeyFor) rather than the bare baseCacheKey. This enables
	// automatic cleanup of stale limiters when a policy instance's quota configuration changes,
	// without one policy instance evicting a limiter that another instance on the same route
	// legitimately shares.
	quotaKeysByBaseKey map[string]map[string]struct{}
}

// globalLimiterCache is the singleton cache for memory-backed limiters.
var globalLimiterCache = &limiterCache{
	byQuotaKey:         make(map[string]*limiterEntry),
	quotaKeysByBaseKey: make(map[string]map[string]struct{}),
}

// KeyComponent represents a single component for building rate limit keys
type KeyComponent struct {
	Type       string // "header", "metadata", "ip", "apiname", "apiversion", "routename", "cel"
	Key        string // header name or metadata key (required for header/metadata)
	Expression string // CEL expression (required for cel type)
	Fallback   string // value to use when the key is missing (optional; defaults to a "_missing_*_" placeholder)
}

// LimitConfig holds parsed rate limit configuration
type LimitConfig struct {
	Limit    int64
	Duration time.Duration
	Burst    int64
}

// QuotaRuntime holds per-quota runtime configuration and limiter instance.
// Each quota is a self-contained rate limit dimension with its own key extraction,
// cost extraction, and limiter.
type QuotaRuntime struct {
	Name                  string          // Optional name for logging/headers
	Limits                []LimitConfig   // Rate limits for this quota
	KeyExtraction         []KeyComponent  // Per-quota key extraction
	Limiter               limiter.Limiter // Limiter instance for this quota
	CostExtractor         *CostExtractor  // Per-quota cost extractor
	CostExtractionEnabled bool            // Whether cost extraction is enabled
}

// RateLimitPolicy defines the policy for rate limiting
type RateLimitPolicy struct {
	quotas         []QuotaRuntime // Per-quota configurations with independent limiters
	routeName      string         // From metadata, used as default key
	apiId          string         // From metadata, API identifier
	apiName        string         // From metadata, API name for scope-based caching
	apiVersion     string         // From metadata, API version
	attachedTo     policy.Level   // From metadata, whether policy is attached at API or route level
	baseCacheKey   string         // Base cache key for tracking limiters in memory backend
	instanceID     string         // Unique per-instance suffix for SharedContext.Metadata keys
	statusCode     int
	responseBody   string
	responseFormat string
	backend        string
	redisClient    *redis.Client
	redisFailOpen  bool
	includeXRL     bool
	includeIETF    bool
	includeRetry   bool
}

// redisBacked reports whether the backend talks to Redis — the synchronous "redis"
// backend or the local-first "redis-local-async" backend. The request/response error
// paths use this so failureMode=open is honored for BOTH: redis-local-async inherits the
// synchronous cost-extraction methods (GetAvailable/ConsumeOrClampN/ConsumeN), which can
// still return Redis errors that must fail open when configured to.
func (p *RateLimitPolicy) redisBacked() bool {
	return p.backend == "redis" || p.backend == "redis-local-async"
}

// GetPolicy is the v1alpha2 factory entry point (loaded by v1alpha2 kernels).
func GetPolicy(
	metadata policy.PolicyMetadata,
	params map[string]interface{},
) (policy.Policy, error) {
	slog.Debug("Creating rate limit policy",
		"route", metadata.RouteName,
		"apiName", metadata.APIName,
		"apiVersion", metadata.APIVersion)

	// Store route name for default key
	routeName := metadata.RouteName
	if routeName == "" {
		routeName = "unknown-route"
	}

	// Extract API metadata for scope-based caching. These feed getBaseCacheKey /
	// getQuotaCacheKey so that apiname-scoped quotas share one limiter per API (and,
	// crucially, do NOT collide across different APIs that happen to use the same
	// quota shape — without this the cache key degenerates to "apiScope:" for everyone).
	apiId := metadata.APIId
	apiName := metadata.APIName
	apiVersion := metadata.APIVersion

	// Parse onRateLimitExceeded (optional)
	statusCode := 429
	responseBody := `{"error": "Too Many Requests", "message": "Rate limit exceeded. Please try again later."}`
	responseFormat := "json"
	if exceeded, ok := params["onRateLimitExceeded"].(map[string]interface{}); ok {
		if sc, ok := exceeded["statusCode"].(float64); ok {
			statusCode = int(sc)
		}
		if body, ok := exceeded["body"].(string); ok {
			responseBody = body
		}
		if format, ok := exceeded["bodyFormat"].(string); ok {
			responseFormat = format
		}
	}

	// Parse system parameters
	algorithm := getStringParam(params, "algorithm", "fixed-window")
	backend := getStringParam(params, "backend", "memory")

	// Header configuration
	includeXRL := getBoolParam(params, "headers.includeXRateLimit", true)
	includeIETF := getBoolParam(params, "headers.includeIETF", true)
	includeRetry := getBoolParam(params, "headers.includeRetryAfter", true)

	// Parse global keyExtraction (used as default for quotas missing keyExtraction)
	globalKeyExtraction, err := parseKeyExtraction(params["keyExtraction"])
	if err != nil {
		return nil, fmt.Errorf("invalid keyExtraction: %w", err)
	}

	// Default keyExtraction when nothing is specified
	defaultKeyExtraction := []KeyComponent{{Type: "routename"}}

	// Parse quotas config (required)
	quotas, err := parseQuotas(params)
	if err != nil {
		return nil, err
	}

	if len(quotas) == 0 {
		return nil, fmt.Errorf("quotas configuration is required")
	}

	// Fill in missing keyExtraction from global or default
	for i := range quotas {
		if len(quotas[i].KeyExtraction) == 0 {
			if len(globalKeyExtraction) > 0 {
				quotas[i].KeyExtraction = globalKeyExtraction
			} else {
				quotas[i].KeyExtraction = defaultKeyExtraction
			}
		}
	}

	// Initialize limiters for each quota based on backend.
	// "redis"             -> shared Redis counter, one limiter per quota (no local cache).
	// "redis-local-async" -> local-first counting + async Redis reconcile; needs the Redis
	//                        client AND the shared limiter cache (holds a flusher goroutine).
	// "memory"            -> per-replica counting via the shared limiter cache.
	var redisClient *redis.Client
	redisFailOpen := true
	redisKeyPrefix := getStringParam(params, "redis.keyPrefix", "ratelimit:v1:")
	localSyncInterval := getDurationParam(params, "local.syncInterval", 50*time.Millisecond)
	localFlushWorkers := getIntParam(params, "local.flushWorkers", 0)
	localMaxPipelineCommands := getIntParam(params, "local.maxPipelineCommands", 0)
	localMaxLocalEntries := getIntParam(params, "local.maxLocalEntries", 0)
	var baseCacheKey string // Set for cache-backed backends (memory, redis-local-async)

	usesRedis := backend == "redis" || backend == "redis-local-async"

	slog.Debug("Initializing rate limiter backend",
		"backend", backend,
		"algorithm", algorithm,
		"quotaCount", len(quotas))

	if usesRedis {
		// Parse Redis configuration
		redisHost := getStringParam(params, "redis.host", "localhost")
		redisPort := getIntParam(params, "redis.port", 6379)
		redisPassword := getStringParam(params, "redis.password", "")
		redisUsername := getStringParam(params, "redis.username", "")
		redisDB := getIntParam(params, "redis.db", 0)
		failureMode := getStringParam(params, "redis.failureMode", "open")
		redisFailOpen = (failureMode == "open")

		connTimeout := getDurationParam(params, "redis.connectionTimeout", 5*time.Second)
		readTimeout := getDurationParam(params, "redis.readTimeout", 3*time.Second)
		writeTimeout := getDurationParam(params, "redis.writeTimeout", 3*time.Second)
		poolSize := getIntParam(params, "redis.poolSize", 0)

		// Get-or-create the process-wide shared client for this connection config.
		// Sharing one pool across all policy instances (and reloads) avoids the
		// per-instance client/connection explosion. Ping happens once, on creation.
		var created bool
		var pingErr error
		redisClient, created, pingErr = getOrCreateRedisClient(&redis.Options{
			Addr:         fmt.Sprintf("%s:%d", redisHost, redisPort),
			Username:     redisUsername,
			Password:     redisPassword,
			DB:           redisDB,
			DialTimeout:  connTimeout,
			ReadTimeout:  readTimeout,
			WriteTimeout: writeTimeout,
			PoolSize:     poolSize,
		}, connTimeout)
		// Fail-fast only when we created the client and it failed to connect; a reused
		// client is assumed healthy (go-redis reconnects lazily).
		if created && pingErr != nil {
			if !redisFailOpen {
				return nil, fmt.Errorf("redis connection failed and failureMode=closed: %w", pingErr)
			}
			slog.Warn("Redis connection failed but failureMode=open", "error", pingErr)
		}
	}

	if backend == "redis" {
		// Create a limiter per quota (Redis holds the state; no local cache needed)
		for i := range quotas {
			q := &quotas[i]
			limiterLimits := make([]limiter.LimitConfig, len(q.Limits))
			for j, lim := range q.Limits {
				limiterLimits[j] = limiter.LimitConfig{
					Limit:    lim.Limit,
					Duration: lim.Duration,
					Burst:    lim.Burst,
				}
			}

			rlLimiter, err := limiter.CreateLimiter(limiter.Config{
				Algorithm:       algorithm,
				Limits:          limiterLimits,
				Backend:         backend,
				RedisClient:     redisClient,
				KeyPrefix:       redisKeyPrefix,
				CleanupInterval: 0, // Not used for Redis
			})
			if err != nil {
				quotaName := q.Name
				if quotaName == "" {
					quotaName = fmt.Sprintf("quota-%d", i)
				}
				return nil, fmt.Errorf("failed to create Redis limiter for quota %q: %w", quotaName, err)
			}

			q.Limiter = rlLimiter
		}
	} else {
		// Cache-backed backends (memory, redis-local-async): create a shared, ref-counted
		// limiter per quota. redis-local-async holds a per-replica counter + flusher
		// goroutine, so it MUST be a shared singleton (cached) and Close()d on reload.
		cleanupInterval := getDurationParam(params, "memory.cleanupInterval", 5*time.Minute)
		baseCacheKey = getBaseCacheKey(routeName, apiName, algorithm, backend, params)

		// Compute desired quota keys before acquiring lock
		type quotaInfo struct {
			index         int
			cacheKey      string
			limiterLimits []limiter.LimitConfig
		}
		quotaInfos := make([]quotaInfo, len(quotas))
		desiredQuotaKeys := make(map[string]struct{}, len(quotas))

		for i := range quotas {
			q := &quotas[i]
			limiterLimits := make([]limiter.LimitConfig, len(q.Limits))
			for j, lim := range q.Limits {
				limiterLimits[j] = limiter.LimitConfig{
					Limit:    lim.Limit,
					Duration: lim.Duration,
					Burst:    lim.Burst,
				}
			}
			quotaCacheKey := getQuotaCacheKey(baseCacheKey, apiName, q, i)
			quotaInfos[i] = quotaInfo{index: i, cacheKey: quotaCacheKey, limiterLimits: limiterLimits}
			desiredQuotaKeys[quotaCacheKey] = struct{}{}
		}

		// reconcileKey identifies THIS policy instance's limiter bucket for the stale-cleanup
		// bookkeeping below. It must be unique per policy instance on a route: an API-level
		// (global) policy and a route-level (operation) policy attached to the same route must
		// NOT share a reconciliation bucket, or building one would evict (Close) the other's
		// cached limiter — non-deterministically breaking apiname-scoped cross-route sharing.
		// baseCacheKey alone collides for them (it hashes route + shared params, not the
		// attachment level), so we extend it with AttachedTo.
		reconcileKey := reconcileKeyFor(baseCacheKey, metadata.AttachedTo)

		// Single lock for all cache operations - ensures atomicity
		globalLimiterCache.mu.Lock()
		defer globalLimiterCache.mu.Unlock()

		// Get previous quota keys for this policy instance (may be nil)
		oldQuotaKeys := globalLimiterCache.quotaKeysByBaseKey[reconcileKey]

		// Reconcile: process each quota
		for _, info := range quotaInfos {
			q := &quotas[info.index]

			if entry, exists := globalLimiterCache.byQuotaKey[info.cacheKey]; exists {
				// Reuse cached limiter
				q.Limiter = entry.lim
				// Only increment refCount if this is a new reference (not already tracked for this baseKey)
				if _, wasTracked := oldQuotaKeys[info.cacheKey]; !wasTracked {
					entry.refCount++
				}
				slog.Debug("Reusing cached memory limiter",
					"route", routeName, "apiName", apiName,
					"quota", q.Name, "cacheKey", info.cacheKey[:16],
					"refCount", entry.refCount)
			} else {
				// Create new limiter
				limiterConfig := limiter.Config{
					Algorithm:       algorithm,
					Limits:          info.limiterLimits,
					Backend:         backend,
					CleanupInterval: cleanupInterval,
				}
				// redis-local-async needs the Redis client + key prefix for its async
				// flush, plus the local tuning (sync interval, fail-open) passed through
				// AlgorithmConfig.
				if backend == "redis-local-async" {
					limiterConfig.RedisClient = redisClient
					limiterConfig.KeyPrefix = redisKeyPrefix
					limiterConfig.AlgorithmConfig = map[string]interface{}{
						"syncInterval":        localSyncInterval,
						"failOpen":            redisFailOpen,
						"flushWorkers":        localFlushWorkers,
						"maxPipelineCommands": localMaxPipelineCommands,
						"maxLocalEntries":     localMaxLocalEntries,
					}
				}
				rlLimiter, err := limiter.CreateLimiter(limiterConfig)
				if err != nil {
					quotaName := q.Name
					if quotaName == "" {
						quotaName = fmt.Sprintf("quota-%d", info.index)
					}
					return nil, fmt.Errorf("failed to create memory limiter for quota %q: %w", quotaName, err)
				}

				// Store in cache with ref count = 1
				globalLimiterCache.byQuotaKey[info.cacheKey] = &limiterEntry{
					lim:      rlLimiter,
					refCount: 1,
				}
				q.Limiter = rlLimiter
				slog.Debug("Created and cached new memory limiter",
					"route", routeName, "apiName", apiName,
					"quota", q.Name, "cacheKey", info.cacheKey[:16])
			}
		}

		// Clean up stale limiters: quota keys that were previously used but are no longer needed
		for oldQuotaKey := range oldQuotaKeys {
			if _, stillUsed := desiredQuotaKeys[oldQuotaKey]; !stillUsed {
				if entry, exists := globalLimiterCache.byQuotaKey[oldQuotaKey]; exists {
					entry.refCount--
					if entry.refCount <= 0 {
						// Close the limiter and remove from cache
						if err := entry.lim.Close(); err != nil {
							slog.Warn("Failed to close stale limiter",
								"cacheKey", oldQuotaKey[:16], "error", err)
						}
						delete(globalLimiterCache.byQuotaKey, oldQuotaKey)
						slog.Debug("Cleaned up stale memory limiter",
							"route", routeName, "apiName", apiName,
							"cacheKey", oldQuotaKey[:16])
					} else {
						slog.Debug("Decremented ref count for shared memory limiter",
							"route", routeName, "apiName", apiName,
							"cacheKey", oldQuotaKey[:16],
							"refCount", entry.refCount)
					}
				}
			}
		}

		// Update the index with current quota keys for this policy instance
		globalLimiterCache.quotaKeysByBaseKey[reconcileKey] = desiredQuotaKeys
	}

	// Log quota details including cost extraction status
	for i, q := range quotas {
		slog.Debug("Quota configuration",
			"index", i,
			"name", q.Name,
			"costExtractionEnabled", q.CostExtractionEnabled,
			"hasCostExtractor", q.CostExtractor != nil,
			"hasResponsePhaseSources", q.CostExtractor != nil && q.CostExtractor.HasResponsePhaseSources())
	}

	slog.Debug("Rate limit policy created successfully",
		"route", routeName,
		"backend", backend,
		"algorithm", algorithm,
		"quotaCount", len(quotas))

	// Compute a short deterministic instance ID from the quota names and key extraction
	// types. This namespaces all SharedContext.Metadata keys so that multiple
	// advanced-ratelimit instances in the same request chain do not overwrite each other.
	var idBuf strings.Builder
	for i, q := range quotas {
		idBuf.WriteString(q.Name)
		idBuf.WriteString(":")
		for _, ke := range q.KeyExtraction {
			idBuf.WriteString(ke.Type)
			idBuf.WriteString(ke.Key)
		}
		if i < len(quotas)-1 {
			idBuf.WriteString("|")
		}
	}
	idHash := sha256.Sum256([]byte(idBuf.String()))
	instanceID := hex.EncodeToString(idHash[:])[:8]

	// Return configured policy instance
	return &RateLimitPolicy{
		quotas:         quotas,
		routeName:      routeName,
		apiId:          apiId,
		apiName:        apiName,
		apiVersion:     apiVersion,
		attachedTo:     metadata.AttachedTo,
		baseCacheKey:   baseCacheKey,
		instanceID:     instanceID,
		statusCode:     statusCode,
		responseBody:   responseBody,
		responseFormat: responseFormat,
		backend:        backend,
		redisClient:    redisClient,
		redisFailOpen:  redisFailOpen,
		includeXRL:     includeXRL,
		includeIETF:    includeIETF,
		includeRetry:   includeRetry,
	}, nil
}

// metaKey returns an instance-specific metadata key to avoid collisions when
// multiple advanced-ratelimit instances are present in the same request chain.
func (p *RateLimitPolicy) metaKey(base string) string {
	if p.instanceID == "" {
		return base
	}
	return base + ":" + p.instanceID
}

func (p *RateLimitPolicy) Mode() policy.ProcessingMode {
	requestBodyMode := policy.BodyModeSkip
	responseBodyMode := policy.BodyModeSkip

	if p.requiresRequestBody() {
		requestBodyMode = policy.BodyModeBuffer
	}
	if p.requiresAnyResponseBodyMode() {
		responseBodyMode = policy.BodyModeStream
	}

	return policy.ProcessingMode{
		RequestHeaderMode:  policy.HeaderModeProcess,
		RequestBodyMode:    requestBodyMode,
		ResponseHeaderMode: policy.HeaderModeProcess,
		ResponseBodyMode:   responseBodyMode,
	}
}

// Metadata keys for storing data across request/response phases
const (
	rateLimitResultKey        = "ratelimit:result"
	rateLimitKeysKey          = "ratelimit:keys"           // Store extracted keys for post-response cost extraction
	rateLimitHeaderHandledKey = "ratelimit:header_handled" // Quota names fully handled in header phase
	rateLimitStreamStateKey   = "ratelimit:stream_state"   // Per-request SSE/JSON streaming accumulation state
)

// upstreamRateLimitHeaders are provider-specific rate-limit headers that should
// never be forwarded to API consumers. They leak upstream quota details, conflict
// with gateway-issued ratelimit headers, and pollute the x-ratelimit-* namespace.
var upstreamRateLimitHeaders = []string{
	"x-ratelimit-limit-requests",
	"x-ratelimit-limit-tokens",
	"x-ratelimit-remaining-requests",
	"x-ratelimit-remaining-tokens",
	"x-ratelimit-reset-requests",
	"x-ratelimit-reset-tokens",
}

// quotaResult stores the result of checking a single quota
type quotaResult struct {
	QuotaName string
	Result    *limiter.Result
	Key       string
	Duration  time.Duration // Window duration for IETF RateLimit-Policy header
}

// streamQuotaState holds per-request accumulation state for one quota while the
// response body is being processed chunk-by-chunk in streaming mode.
// A separate instance is stored per quota name inside rateLimitStreamStateKey so
// that multiple quotas on the same request track their state independently.
//
// Raw response bytes are accumulated once per chunk (regardless of how many
// response-phase sources the quota configures) and cost extraction runs once at
// EOS via ExtractResponseCost. extractFromBodyBytes already handles both plain
// JSON and SSE bodies transparently, so no per-format or per-source tracking is
// needed here.
type streamQuotaState struct {
	accumulated []byte // raw body bytes gathered across all chunks; extracted once at EOS
}

// quotaNameFor returns the display/lookup name for a quota.
// Used consistently across streaming methods to avoid duplicating the fallback logic.
func quotaNameFor(q *QuotaRuntime, index int) string {
	if q.Name != "" {
		return q.Name
	}
	return fmt.Sprintf("quota-%d", index)
}

// buildMultiQuotaHeaders creates rate limit headers for all quotas.
// For IETF headers, uses Structured Fields format to report all quotas.
// For X-RateLimit-* headers, uses the most restrictive quota (legacy compatibility).
// Reference: draft-ietf-httpapi-ratelimit-headers-10
func (p *RateLimitPolicy) buildMultiQuotaHeaders(
	allResults []quotaResult,
	rateLimited bool,
	violatedQuota string,
) map[string]string {
	headers := make(map[string]string)

	if len(allResults) == 0 {
		return headers
	}

	// Find the most restrictive result for X-RateLimit-* headers (legacy)
	var mostRestrictive *quotaResult
	for i := range allResults {
		r := &allResults[i]
		if r.Result == nil {
			continue
		}
		if mostRestrictive == nil || r.Result.Remaining < mostRestrictive.Result.Remaining {
			mostRestrictive = r
		}
	}

	// X-RateLimit-* headers (de facto standard) - most restrictive only for backward compatibility
	if p.includeXRL && mostRestrictive != nil && mostRestrictive.Result != nil {
		headers["x-ratelimit-limit"] = strconv.FormatInt(mostRestrictive.Result.Limit, 10)
		headers["x-ratelimit-remaining"] = strconv.FormatInt(mostRestrictive.Result.Remaining, 10)
		headers["x-ratelimit-reset"] = strconv.FormatInt(mostRestrictive.Result.Reset.Unix(), 10)
	}

	// IETF RateLimit headers (draft standard) - all quotas using Structured Fields format
	// Format: RateLimit-Policy: "quota1";q=100;w=60, "quota2";q=1000;w=86400
	// Format: RateLimit: "quota1";r=90;t=45, "quota2";r=950;t=3600
	if p.includeIETF {
		var policyParts []string
		var limitParts []string

		for _, qr := range allResults {
			if qr.Result == nil {
				continue
			}

			// Sanitize quota name for use in Structured Fields string
			quotaName := qr.QuotaName
			if quotaName == "" {
				quotaName = "default"
			}

			// RateLimit-Policy: "<name>";q=<limit>;w=<window>
			windowSeconds := int64(qr.Duration.Seconds())
			if windowSeconds <= 0 && qr.Result.Duration > 0 {
				windowSeconds = int64(qr.Result.Duration.Seconds())
			}
			policyPart := fmt.Sprintf(`"%s";q=%d;w=%d`,
				quotaName,
				qr.Result.Limit,
				windowSeconds)
			policyParts = append(policyParts, policyPart)

			// RateLimit: "<name>";r=<remaining>;t=<reset_seconds>
			resetSeconds := int64(time.Until(qr.Result.Reset).Seconds())
			if resetSeconds < 0 {
				resetSeconds = 0
			}
			limitPart := fmt.Sprintf(`"%s";r=%d;t=%d`,
				quotaName,
				qr.Result.Remaining,
				resetSeconds)
			limitParts = append(limitParts, limitPart)
		}

		if len(policyParts) > 0 {
			headers["ratelimit-policy"] = strings.Join(policyParts, ", ")
		}
		if len(limitParts) > 0 {
			headers["ratelimit"] = strings.Join(limitParts, ", ")
		}
	}

	// Retry-After header (only on 429 responses) - use violated quota or most restrictive
	if rateLimited && p.includeRetry {
		var retryResult *limiter.Result

		// Prefer the violated quota for retry-after
		if violatedQuota != "" {
			for _, qr := range allResults {
				if qr.QuotaName == violatedQuota && qr.Result != nil {
					retryResult = qr.Result
					break
				}
			}
		}

		// Fall back to most restrictive
		if retryResult == nil && mostRestrictive != nil {
			retryResult = mostRestrictive.Result
		}

		if retryResult != nil && retryResult.RetryAfter > 0 {
			seconds := int64(retryResult.RetryAfter.Seconds())
			if seconds < 1 {
				seconds = 1
			}
			headers["retry-after"] = strconv.FormatInt(seconds, 10)
		}
	}

	return headers
}

func (p *RateLimitPolicy) buildRateLimitResponse(
	violatedResult *limiter.Result,
	violatedQuotaName string,
	allResults []quotaResult,
) policy.ImmediateResponse {
	// If we have all results, use the multi-quota header builder
	var headers map[string]string
	if len(allResults) > 0 {
		// Add the violated quota to the results if not already present
		hasViolated := false
		for _, qr := range allResults {
			if qr.QuotaName == violatedQuotaName {
				hasViolated = true
				break
			}
		}
		if !hasViolated && violatedResult != nil {
			allResults = append(allResults, quotaResult{
				QuotaName: violatedQuotaName,
				Result:    violatedResult,
				Duration:  violatedResult.Duration,
			})
		}
		headers = p.buildMultiQuotaHeaders(allResults, true, violatedQuotaName)
	} else if violatedResult != nil {
		// Fallback to single result
		headers = p.buildMultiQuotaHeaders([]quotaResult{
			{
				QuotaName: violatedQuotaName,
				Result:    violatedResult,
				Duration:  violatedResult.Duration,
			},
		}, true, violatedQuotaName)
	} else {
		headers = make(map[string]string)
	}

	// Set content-type based on format
	if p.responseFormat == "json" {
		headers["content-type"] = "application/json"
	} else {
		headers["content-type"] = "text/plain"
	}

	// Add violated quota name to headers for debugging
	if violatedQuotaName != "" {
		headers["x-ratelimit-quota"] = violatedQuotaName
	}

	return policy.ImmediateResponse{
		StatusCode: p.statusCode,
		Headers:    headers,
		Body:       []byte(p.responseBody),
	}
}

// parseQuotas parses the new "quotas" array. If absent, returns nil, nil.
func parseQuotas(params map[string]interface{}) ([]QuotaRuntime, error) {
	raw, ok := params["quotas"]
	if !ok || raw == nil {
		return nil, nil
	}

	items, ok := raw.([]interface{})
	if !ok {
		return nil, fmt.Errorf("quotas must be an array")
	}

	quotas := make([]QuotaRuntime, 0, len(items))
	for i, item := range items {
		m, ok := item.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("quotas[%d] must be an object", i)
		}

		// Name (optional)
		name, _ := m["name"].(string)

		// Parse limits array (required)
		limitsRaw, hasLimits := m["limits"]
		if !hasLimits {
			return nil, fmt.Errorf("quotas[%d].limits is required", i)
		}

		limits, err := parseLimits(limitsRaw)
		if err != nil {
			return nil, fmt.Errorf("invalid quotas[%d].limits: %w", i, err)
		}
		if len(limits) == 0 {
			return nil, fmt.Errorf("quotas[%d].limits must not be empty", i)
		}

		// Per-quota keyExtraction
		quotaKeyExtraction, err := parseKeyExtraction(m["keyExtraction"])
		if err != nil {
			return nil, fmt.Errorf("invalid quotas[%d].keyExtraction: %w", i, err)
		}

		// Per-quota costExtraction
		ceCfg, err := parseCostExtractionConfig(m["costExtraction"])
		if err != nil {
			return nil, fmt.Errorf("invalid quotas[%d].costExtraction: %w", i, err)
		}

		var ce *CostExtractor
		enabled := false
		if ceCfg != nil && ceCfg.Enabled {
			ce = NewCostExtractor(*ceCfg)
			enabled = true
		}

		quotas = append(quotas, QuotaRuntime{
			Name:                  name,
			Limits:                limits,
			KeyExtraction:         quotaKeyExtraction,
			CostExtractor:         ce,
			CostExtractionEnabled: enabled,
		})
	}

	return quotas, nil
}

// parseSingleLimit parses a single limit configuration
func parseSingleLimit(limitVal, durationVal, burstVal interface{}) (*LimitConfig, error) {
	limitFloat, ok := limitVal.(float64)
	if !ok {
		return nil, fmt.Errorf("limit must be a number")
	}
	limit := int64(limitFloat)

	durationStr, ok := durationVal.(string)
	if !ok {
		return nil, fmt.Errorf("duration must be a string")
	}
	duration, err := time.ParseDuration(durationStr)
	if err != nil {
		return nil, fmt.Errorf("invalid duration: %w", err)
	}

	// Parse burst (optional, defaults to limit)
	burst := limit
	if burstVal != nil {
		burstFloat, ok := burstVal.(float64)
		if !ok {
			return nil, fmt.Errorf("burst must be a number")
		}
		burst = int64(burstFloat)
	}

	return &LimitConfig{
		Limit:    limit,
		Duration: duration,
		Burst:    burst,
	}, nil
}

// parseLimits parses the limits array from parameters
func parseLimits(raw interface{}) ([]LimitConfig, error) {
	if raw == nil {
		return nil, nil
	}

	limitsArray, ok := raw.([]interface{})
	if !ok {
		return nil, fmt.Errorf("limits must be an array")
	}

	if len(limitsArray) == 0 {
		return nil, nil
	}

	limits := make([]LimitConfig, 0, len(limitsArray))
	for i, limitRaw := range limitsArray {
		limitMap, ok := limitRaw.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("limits[%d] must be an object", i)
		}

		// Parse limit (required)
		limitVal, ok := limitMap["limit"]
		if !ok {
			return nil, fmt.Errorf("limits[%d].limit is required", i)
		}

		limit, err := parseSingleLimit(limitVal, limitMap["duration"], limitMap["burst"])
		if err != nil {
			return nil, fmt.Errorf("invalid limits[%d]: %w", i, err)
		}

		limits = append(limits, *limit)
	}

	return limits, nil
}

// parseKeyExtraction parses the keyExtraction array
func parseKeyExtraction(raw interface{}) ([]KeyComponent, error) {
	if raw == nil {
		return []KeyComponent{}, nil
	}

	keArray, ok := raw.([]interface{})
	if !ok {
		return nil, fmt.Errorf("keyExtraction must be an array")
	}

	components := make([]KeyComponent, 0, len(keArray))
	for i, compRaw := range keArray {
		compMap, ok := compRaw.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("keyExtraction[%d] must be an object", i)
		}

		compType, ok := compMap["type"].(string)
		if !ok {
			return nil, fmt.Errorf("keyExtraction[%d].type is required", i)
		}

		comp := KeyComponent{Type: compType}
		if keyRaw, ok := compMap["key"]; ok {
			if keyStr, ok := keyRaw.(string); ok {
				comp.Key = keyStr
			} else {
				return nil, fmt.Errorf("keyExtraction[%d].key must be a string", i)
			}
		}

		// Parse expression for CEL type
		if exprRaw, ok := compMap["expression"]; ok {
			if exprStr, ok := exprRaw.(string); ok {
				comp.Expression = exprStr
			} else {
				return nil, fmt.Errorf("keyExtraction[%d].expression must be a string", i)
			}
		}

		// Parse optional fallback value
		if fallbackRaw, ok := compMap["fallback"]; ok {
			if fallbackStr, ok := fallbackRaw.(string); ok {
				comp.Fallback = fallbackStr
			} else {
				return nil, fmt.Errorf("keyExtraction[%d].fallback must be a string", i)
			}
		}

		// Validate: CEL type requires expression
		if compType == "cel" && comp.Expression == "" {
			return nil, fmt.Errorf("keyExtraction[%d]: type 'cel' requires 'expression' field", i)
		}

		components = append(components, comp)
	}

	return components, nil
}

// Helper functions for extracting parameters with defaults

func getStringParam(params map[string]interface{}, key string, defaultVal string) string {
	// Support nested keys like "redis.host"
	keys := strings.Split(key, ".")
	current := params

	for i, k := range keys {
		if i == len(keys)-1 {
			// Last key - get the value
			if val, ok := current[k].(string); ok {
				return val
			}
			return defaultVal
		}

		// Navigate to next level
		if next, ok := current[k].(map[string]interface{}); ok {
			current = next
		} else {
			return defaultVal
		}
	}

	return defaultVal
}

func getIntParam(params map[string]interface{}, key string, defaultVal int) int {
	keys := strings.Split(key, ".")
	current := params

	for i, k := range keys {
		if i == len(keys)-1 {
			if val, ok := current[k].(float64); ok {
				return int(val)
			}
			if val, ok := current[k].(int); ok {
				return val
			}
			return defaultVal
		}

		if next, ok := current[k].(map[string]interface{}); ok {
			current = next
		} else {
			return defaultVal
		}
	}

	return defaultVal
}

func getBoolParam(params map[string]interface{}, key string, defaultVal bool) bool {
	keys := strings.Split(key, ".")
	current := params

	for i, k := range keys {
		if i == len(keys)-1 {
			if val, ok := current[k].(bool); ok {
				return val
			}
			return defaultVal
		}

		if next, ok := current[k].(map[string]interface{}); ok {
			current = next
		} else {
			return defaultVal
		}
	}

	return defaultVal
}

func getDurationParam(params map[string]interface{}, key string, defaultVal time.Duration) time.Duration {
	keys := strings.Split(key, ".")
	current := params

	for i, k := range keys {
		if i == len(keys)-1 {
			if val, ok := current[k].(string); ok {
				if duration, err := time.ParseDuration(val); err == nil {
					return duration
				}
			}
			return defaultVal
		}

		if next, ok := current[k].(map[string]interface{}); ok {
			current = next
		} else {
			return defaultVal
		}
	}

	return defaultVal
}

// requiresRequestBody returns true if any quota requires request body processing.
func (p *RateLimitPolicy) requiresRequestBody() bool {
	for _, q := range p.quotas {
		if q.CostExtractionEnabled && q.CostExtractor != nil {
			if q.CostExtractor.HasRequestBodyPhase() {
				return true
			}
		}
		for _, comp := range q.KeyExtraction {
			if comp.Type == "cel" {
				return true
			}
		}
	}
	return false
}

// requiresAnyResponseBodyMode returns true if any quota has a response-phase cost
// source that is not response_header. This is the single gating check used by
// Mode() to request BodyModeStream and by OnResponseBody to guard the buffered
// fallback path.
//
// response_header-only quotas are fully handled in OnResponseHeaders and are
// excluded here to avoid requesting an unnecessary body phase.
func (p *RateLimitPolicy) requiresAnyResponseBodyMode() bool {
	for _, q := range p.quotas {
		if !q.CostExtractionEnabled || q.CostExtractor == nil {
			continue
		}
		// Skip quotas whose only response sources are response_header — those are
		// consumed entirely in OnResponseHeaders with no body involvement.
		if q.CostExtractor.HasResponseHeaderOnlyCostSources() {
			continue
		}
		if q.CostExtractor.HasResponsePhaseSources() {
			return true
		}
	}
	return false
}

// hasStreamingResponseSourceForQuota returns true if the given quota has any
// response-phase cost source that should be processed in the streaming path
// (i.e. anything other than response_header, which is handled earlier).
// Used in finalizeAndConsumeStreamingCosts to skip quotas that were already
// fully consumed in OnResponseHeaders.
func (p *RateLimitPolicy) hasStreamingResponseSourceForQuota(q *QuotaRuntime) bool {
	if q.CostExtractor == nil {
		return false
	}
	if q.CostExtractor.HasResponseHeaderOnlyCostSources() {
		return false
	}
	return q.CostExtractor.HasResponsePhaseSources()
}

// isStreamingResponse returns true if the upstream response headers indicate a streaming
// body — either Server-Sent Events (content-type: text/event-stream) or chunked transfer
// encoding. These are the same signals the kernel uses to activate FULL_DUPLEX_STREAMED
// mode, which routes body data through OnResponseBodyChunk instead of OnResponseBody and
// commits response headers before the first chunk arrives.
func isStreamingResponse(headers *policy.Headers) bool {
	if headers == nil {
		return false
	}
	ct := headers.Get("content-type")
	if len(ct) > 0 && strings.Contains(ct[0], "text/event-stream") {
		return true
	}
	te := headers.Get("transfer-encoding")
	for _, v := range te {
		if strings.Contains(strings.ToLower(v), "chunked") {
			return true
		}
	}
	return false
}

// getLimitFromQuota returns the limit from a quota's first limit config, or 0 if none
func getLimitFromQuota(q *QuotaRuntime) int64 {
	if len(q.Limits) > 0 {
		return q.Limits[0].Limit
	}
	return 0
}

// getDurationFromQuota returns the duration from a quota's first limit config, or 0 if none
func getDurationFromQuota(q *QuotaRuntime) time.Duration {
	if len(q.Limits) > 0 {
		return q.Limits[0].Duration
	}
	return 0
}

// getBaseCacheKey computes a stable hash key base for caching memory-backed limiters.
// This includes shared aspects like algorithm, headers config, etc.
func getBaseCacheKey(routeName, apiName, algorithm, backend string, params map[string]interface{}) string {
	h := sha256.New()

	h.Write([]byte("route:"))
	h.Write([]byte(routeName))
	h.Write([]byte("|"))

	h.Write([]byte("api:"))
	h.Write([]byte(apiName))
	h.Write([]byte("|"))

	h.Write([]byte("algo:"))
	h.Write([]byte(algorithm))
	h.Write([]byte("|"))

	// Include backend so a memory and a redis-local-async limiter for the same
	// route+algorithm get distinct cache entries (both use this cache path).
	h.Write([]byte("backend:"))
	h.Write([]byte(backend))
	h.Write([]byte("|"))

	// For redis-local-async, fold the Redis endpoint and local tuning into the key so a
	// config reload that changes them rebuilds the cached limiter instead of silently
	// reusing the old one. (Counts survive in Redis; the coordinator's global settings
	// are first-registrant-wins regardless.)
	if backend == "redis-local-async" {
		h.Write([]byte(fmt.Sprintf("redis:%s/%d|local:%s,w=%d,pipe=%d,max=%d|",
			getStringParam(params, "redis.host", "localhost"),
			getIntParam(params, "redis.db", 0),
			getDurationParam(params, "local.syncInterval", 50*time.Millisecond),
			getIntParam(params, "local.flushWorkers", 0),
			getIntParam(params, "local.maxPipelineCommands", 0),
			getIntParam(params, "local.maxLocalEntries", 0))))
	}

	// Include memory cleanup interval
	cleanupInterval := getDurationParam(params, "memory.cleanupInterval", 5*time.Minute)
	h.Write([]byte("cleanup:"))
	h.Write([]byte(cleanupInterval.String()))
	h.Write([]byte("|"))

	// Include header configuration
	includeXRL := getBoolParam(params, "headers.includeXRateLimit", true)
	includeIETF := getBoolParam(params, "headers.includeIETF", true)
	includeRetry := getBoolParam(params, "headers.includeRetryAfter", true)
	h.Write([]byte(fmt.Sprintf("headers:xrl=%t,ietf=%t,retry=%t|", includeXRL, includeIETF, includeRetry)))

	// Include response configuration
	if exceeded, ok := params["onRateLimitExceeded"].(map[string]interface{}); ok {
		h.Write([]byte("exceeded:"))
		keys := make([]string, 0, len(exceeded))
		for k := range exceeded {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			h.Write([]byte(fmt.Sprintf("%s=%v,", k, exceeded[k])))
		}
		h.Write([]byte("|"))
	}

	return hex.EncodeToString(h.Sum(nil))
}

// reconcileKeyFor derives the bookkeeping key under which a policy instance's active quota cache
// keys are tracked for stale-limiter cleanup. It extends baseCacheKey with the policy's attachment
// level so that two rate-limit policies on the SAME route but attached at different levels — an
// API-level (global) quota and a route-level (operation) quota — do NOT share a cleanup bucket and
// evict each other's cached limiters. baseCacheKey alone collides for them: it hashes route +
// shared params but not the attachment, so building the operation policy would treat the global
// policy's shared apiname limiter as "stale" and Close it (breaking cross-route sharing). AttachedTo
// is stable across config reloads, so a limit-only change to a single policy still reuses its bucket
// and cleans up its old limiter (unlike keying on the mutable quota set).
func reconcileKeyFor(baseCacheKey string, attachedTo policy.Level) string {
	return baseCacheKey + "|attachedTo:" + string(attachedTo)
}

// getQuotaCacheKey produces final key per quota using base + quota-specific config.
// apiName is passed separately to enable API-scoped cache keys for quotas using apiname keyExtraction.
func getQuotaCacheKey(base, apiName string, q *QuotaRuntime, index int) string {
	h := sha256.New()

	// Determine scope from keyExtraction
	hasApiName := false
	hasRouteName := false
	for _, comp := range q.KeyExtraction {
		if comp.Type == "apiname" {
			hasApiName = true
		}
		if comp.Type == "routename" {
			hasRouteName = true
		}
	}

	// For API-scoped quotas (apiname key extraction without routename),
	// use a stable API-based cache key so all routes under the same API share the limiter.
	// Otherwise, use the route-specific base cache key.
	if hasApiName && !hasRouteName {
		// API-scoped: use apiName instead of route-specific base
		h.Write([]byte("apiScope:"))
		h.Write([]byte(apiName))
		h.Write([]byte("|"))
	} else {
		// Route-scoped: use the full base key (includes route name)
		h.Write([]byte(base))
	}

	h.Write([]byte("|quota:"))
	if q.Name != "" {
		h.Write([]byte(q.Name))
	} else {
		h.Write([]byte(fmt.Sprintf("idx-%d", index)))
	}
	h.Write([]byte("|"))

	// Include limits
	h.Write([]byte("limits:"))
	for i, lim := range q.Limits {
		h.Write([]byte(fmt.Sprintf("[%d:l=%d,d=%s,b=%d]", i, lim.Limit, lim.Duration, lim.Burst)))
	}
	h.Write([]byte("|"))

	// Include key extraction
	h.Write([]byte("keyExtraction:"))
	for i, comp := range q.KeyExtraction {
		h.Write([]byte(fmt.Sprintf("[%d:t=%s,k=%s]", i, comp.Type, comp.Key)))
	}
	h.Write([]byte("|"))

	return hex.EncodeToString(h.Sum(nil))
}

// OnRequestHeaders performs the rate limit check in the header phase for quotas that do not
// require request body or CEL-based key extraction. Quotas needing the body (cost extraction
// from request_body / request_cel) or CEL key extraction are deferred to OnRequest.
func (p *RateLimitPolicy) OnRequestHeaders(ctx context.Context, reqCtx *policy.RequestHeaderContext, params map[string]interface{}) policy.RequestHeaderAction {
	slog.Debug("Rate limit header phase check started",
		"route", p.routeName,
		"quotaCount", len(p.quotas))

	var quotaResults []quotaResult
	quotaKeys := make(map[string]string)
	handledQuotas := make(map[string]bool)

	for i := range p.quotas {
		q := &p.quotas[i]
		quotaName := q.Name
		if quotaName == "" {
			quotaName = fmt.Sprintf("quota-%d", i)
		}

		// Defer quotas with CEL key extraction — requires full RequestContext
		hasCELKey := false
		for _, comp := range q.KeyExtraction {
			if comp.Type == "cel" {
				hasCELKey = true
				break
			}
		}
		if hasCELKey {
			slog.Debug("Deferring quota to body phase: CEL key extraction", "quota", quotaName)
			continue
		}

		key := p.extractQuotaKeyFromHeaderCtx(reqCtx, q)
		quotaKeys[quotaName] = key

		if q.CostExtractionEnabled && q.CostExtractor != nil {
			if q.CostExtractor.HasRequestHeaderOnlyCostSources() {
				// request_header sources only — all values are available now, consume immediately.
				// No body buffering needed.
				requestCost, extracted := q.CostExtractor.ExtractRequestHeaderOnlyCost(reqCtx)
				if !extracted {
					slog.Debug("Header cost extraction failed, using default",
						"quota", quotaName, "key", key, "defaultCost", requestCost)
				} else {
					slog.Debug("Header cost extracted",
						"quota", quotaName, "key", key, "cost", requestCost)
				}
				if requestCost < 0 {
					requestCost = 0
				}
				if requestCost == 0 {
					available, err := q.Limiter.GetAvailable(context.Background(), key)
					if err != nil {
						if p.redisBacked() && p.redisFailOpen {
							slog.Warn("Rate limit state lookup failed (fail-open)", "error", err, "quota", quotaName)
							continue
						}
						slog.Error("Rate limit state lookup failed (fail-closed)", "error", err, "quota", quotaName)
						return p.buildRateLimitResponse(nil, quotaName, quotaResults)
					}
					duration := getDurationFromQuota(q)
					quotaResults = append(quotaResults, quotaResult{
						QuotaName: quotaName,
						Result: &limiter.Result{
							Allowed:   available > 0,
							Limit:     getLimitFromQuota(q),
							Remaining: available,
							Reset:     time.Now().Add(duration),
							Duration:  duration,
						},
						Key:      key,
						Duration: duration,
					})
					handledQuotas[quotaName] = true
					continue
				}
				cost := int64(requestCost)
				result, err := q.Limiter.AllowN(context.Background(), key, cost)
				if err != nil {
					if p.redisBacked() && p.redisFailOpen {
						slog.Warn("Rate limit check failed (fail-open)", "error", err, "quota", quotaName)
						continue
					}
					slog.Error("Rate limit check failed (fail-closed)", "error", err, "quota", quotaName)
					return p.buildRateLimitResponse(nil, quotaName, quotaResults)
				}
				if !result.Allowed {
					slog.Debug("Rate limit exceeded in header phase",
						"quota", quotaName, "key", key, "cost", cost)
					return p.buildRateLimitResponse(result, quotaName, quotaResults)
				}
				slog.Debug("Rate limit check passed",
					"quota", quotaName, "key", key, "cost", cost, "remaining", result.Remaining)

				quotaResults = append(quotaResults, quotaResult{
					QuotaName: quotaName,
					Result:    result,
					Key:       key,
					Duration:  result.Duration,
				})
				handledQuotas[quotaName] = true
			} else {
				// body/metadata/CEL/response sources — pre-check availability only;
				// actual consumption is deferred to OnRequestBody or OnResponse.
				available, err := q.Limiter.GetAvailable(context.Background(), key)
				if err != nil {
					if p.redisBacked() && p.redisFailOpen {
						slog.Warn("Rate limit pre-check failed (fail-open)", "error", err, "quota", quotaName)
						continue
					}
					slog.Error("Rate limit pre-check failed (fail-closed)", "error", err, "quota", quotaName)
					return p.buildRateLimitResponse(nil, quotaName, quotaResults)
				}
				if available <= 0 {
					slog.Debug("Cost extraction mode: quota exhausted in header phase",
						"quota", quotaName, "key", key)
					duration := getDurationFromQuota(q)
					result := &limiter.Result{
						Allowed:   false,
						Limit:     getLimitFromQuota(q),
						Remaining: 0,
						Reset:     time.Now().Add(duration),
						Duration:  duration,
					}
					return p.buildRateLimitResponse(result, quotaName, quotaResults)
				}
				// Store a placeholder so the response phase can find this quota in
				// storedResultsMap. Actual consumption and result are populated in
				// OnRequestBody or OnResponse.
				quotaResults = append(quotaResults, quotaResult{
					QuotaName: quotaName,
					Result:    nil,
					Key:       key,
					Duration:  getDurationFromQuota(q),
				})
			}
		} else {
			// Standard mode (no cost extraction): consume 1 token per request
			cost := int64(1)
			result, err := q.Limiter.AllowN(context.Background(), key, cost)
			if err != nil {
				if p.redisBacked() && p.redisFailOpen {
					slog.Warn("Rate limit check failed (fail-open)", "error", err, "quota", quotaName)
					continue
				}
				slog.Error("Rate limit check failed (fail-closed)", "error", err, "quota", quotaName)
				return p.buildRateLimitResponse(nil, quotaName, quotaResults)
			}

			if !result.Allowed {
				slog.Debug("Rate limit exceeded", "key", key, "quota", quotaName)
				return p.buildRateLimitResponse(result, quotaName, quotaResults)
			}

			quotaResults = append(quotaResults, quotaResult{
				QuotaName: quotaName,
				Result:    result,
				Key:       key,
				Duration:  result.Duration,
			})
			handledQuotas[quotaName] = true
		}
	}

	reqCtx.Metadata[p.metaKey(rateLimitResultKey)] = quotaResults
	reqCtx.Metadata[p.metaKey(rateLimitKeysKey)] = quotaKeys
	reqCtx.Metadata[p.metaKey(rateLimitHeaderHandledKey)] = handledQuotas

	return policy.UpstreamRequestHeaderModifications{}
}

// extractQuotaKeyFromHeaderCtx builds the rate limit key from header-phase context.
// Supports all key types except "cel" (which requires full RequestContext).
func (p *RateLimitPolicy) extractQuotaKeyFromHeaderCtx(reqCtx *policy.RequestHeaderContext, q *QuotaRuntime) string {
	if len(q.KeyExtraction) == 0 {
		slog.Debug("No key extraction configured, using route name",
			"routeName", p.routeName)
		return p.routeName
	}

	if len(q.KeyExtraction) == 1 {
		key := p.extractKeyComponentFromHeaderCtx(reqCtx, q.KeyExtraction[0])
		slog.Debug("Single component key extracted",
			"type", q.KeyExtraction[0].Type,
			"key", key)
		return key
	}

	// Multiple components - join with ':' in the order specified
	parts := make([]string, 0, len(q.KeyExtraction))
	for _, comp := range q.KeyExtraction {
		part := p.extractKeyComponentFromHeaderCtx(reqCtx, comp)
		parts = append(parts, part)
	}
	key := strings.Join(parts, ":")
	slog.Debug("Multi-component key extracted",
		"componentCount", len(q.KeyExtraction),
		"key", key)
	return key
}

// extractKeyComponentFromHeaderCtx extracts a single key component from header-phase context.
func (p *RateLimitPolicy) extractKeyComponentFromHeaderCtx(reqCtx *policy.RequestHeaderContext, comp KeyComponent) string {
	switch comp.Type {
	case "header":
		values := getDownstreamHeaders(reqCtx.Downstream, reqCtx.Headers).Get(strings.ToLower(comp.Key))
		if len(values) > 0 && values[0] != "" {
			return values[0]
		}
		placeholder := fmt.Sprintf("_missing_header_%s_", comp.Key)
		slog.Warn("Header not found for rate limit key, using placeholder", "header", comp.Key, "type", comp.Type, "placeholder", placeholder)
		return placeholder

	case "constant":
		return comp.Key

	case "metadata":
		if val, ok := reqCtx.Metadata[comp.Key]; ok {
			if strVal, ok := val.(string); ok && strVal != "" {
				return strVal
			}
		}
		if comp.Fallback != "" {
			return comp.Fallback
		}
		placeholder := fmt.Sprintf("_missing_metadata_%s_", comp.Key)
		slog.Warn("Metadata key not found for rate limit key, using placeholder", "key", comp.Key, "type", comp.Type, "placeholder", placeholder)
		return placeholder

	case "ip":
		return p.extractIPAddress(getDownstreamHeaders(reqCtx.Downstream, reqCtx.Headers))

	case "apiname":
		if reqCtx.APIName != "" {
			return reqCtx.APIName
		}
		slog.Warn("APIName not available for rate limit key, using empty string")
		return ""

	case "apiversion":
		if reqCtx.APIVersion != "" {
			return reqCtx.APIVersion
		}
		slog.Warn("APIVersion not available for rate limit key, using empty string")
		return ""

	case "routename":
		return p.routeName

	case "cel":
		// extractQuotaKeyFromHeaderCtx is never called for a quota with CEL key extraction
		// Only a defensive fallback in case that invariant is ever violated
		// CEL key extraction is not supported in the header phase. OnRequestHeaders always
		// defers quotas with CEL keys to the body phase, so this case is unreachable.
		slog.Warn("CEL key extraction reached in header phase unexpectedly, returning placeholder",
			"expression", comp.Expression)
		return "_cel_not_supported_in_header_phase_"

	default:
		slog.Warn("Unknown key component type, using empty string", "type", comp.Type)
		return ""
	}
}

// OnRequestBody performs rate limit check across all quotas.
func (p *RateLimitPolicy) OnRequestBody(ctx context.Context, reqCtx *policy.RequestContext,
	_ map[string]interface{},
) policy.RequestAction {
	if p.requiresRequestBody() {
		slog.Debug("Rate limit check started",
			"route", p.routeName,
			"apiName", p.apiName,
			"apiVersion", p.apiVersion,
			"quotaCount", len(p.quotas),
			"backend", p.backend)

		// Retrieve results stored by OnRequestHeaders so header-only quota results
		// (consumed in OnRequestHeaders) can be carried forward.
		storedResultsMap := make(map[string]quotaResult)
		if prev, ok := reqCtx.Metadata[p.metaKey(rateLimitResultKey)].([]quotaResult); ok {
			for _, r := range prev {
				storedResultsMap[r.QuotaName] = r
			}
		}

		// Load the set of quotas fully consumed in OnRequestHeaders (standard-mode and
		// request_header-only cost quotas). Standard-mode quotas call AllowN(1) in the
		// header phase unconditionally, so if OnRequestBody also runs (because another
		// quota needs the body), they must not be charged again.
		handledInHeaderPhase := make(map[string]bool)
		if prev, ok := reqCtx.Metadata[p.metaKey(rateLimitHeaderHandledKey)].(map[string]bool); ok {
			handledInHeaderPhase = prev
		}

		var quotaResults []quotaResult
		var quotaKeys = make(map[string]string) // Store keys for response phase

		for i := range p.quotas {
			q := &p.quotas[i]

			// Extract rate limit key for this quota
			key := p.extractQuotaKey(reqCtx, q)
			quotaName := q.Name
			if quotaName == "" {
				quotaName = fmt.Sprintf("quota-%d", i)
			}
			quotaKeys[quotaName] = key

			slog.Debug("Rate limit key extracted",
				"quota", quotaName,
				"key", key,
				"keyComponents", len(q.KeyExtraction))

			// If cost extraction is enabled, handle based on whether we have request-phase or response-phase sources
			if q.CostExtractionEnabled && q.CostExtractor != nil {
				// request_header-only quotas are fully consumed in OnRequestHeaders —
				// carry forward the stored result for response-phase header building.
				if q.CostExtractor.HasRequestHeaderOnlyCostSources() {
					if stored, ok := storedResultsMap[quotaName]; ok {
						quotaResults = append(quotaResults, stored)
					}
					continue
				}
				// Check if this quota has request-phase sources (can be processed now)
				if q.CostExtractor.HasRequestPhaseSources() {
					slog.Debug("Processing request-phase cost extraction",
						"quota", quotaName,
						"key", key)

					// Extract cost from request (headers, metadata, or body)
					requestCost, extracted := q.CostExtractor.ExtractRequestCost(reqCtx)
					if !extracted {
						slog.Debug("Request cost extraction failed, using default",
							"key", key, "quota", quotaName, "defaultCost", requestCost)
					} else {
						slog.Debug("Request cost extracted",
							"quota", quotaName,
							"key", key,
							"cost", requestCost)
					}

					// Clamp cost to minimum of 0
					if requestCost < 0 {
						slog.Debug("Request cost negative, clamping to 0",
							"quota", quotaName,
							"originalCost", requestCost)
						requestCost = 0
					}
					if requestCost == 0 {
						available, err := q.Limiter.GetAvailable(context.Background(), key)
						if err != nil {
							if p.redisBacked() && p.redisFailOpen {
								slog.Warn("Rate limit state lookup failed (fail-open)", "error", err, "quota", quotaName)
								continue
							}
							slog.Error("Rate limit state lookup failed (fail-closed)", "error", err, "quota", quotaName)
							return p.buildRateLimitResponse(nil, quotaName, quotaResults)
						}
						duration := getDurationFromQuota(q)
						quotaResults = append(quotaResults, quotaResult{
							QuotaName: quotaName,
							Result: &limiter.Result{
								Allowed:   available > 0,
								Limit:     getLimitFromQuota(q),
								Remaining: available,
								Reset:     time.Now().Add(duration),
								Duration:  duration,
							},
							Key:      key,
							Duration: duration,
						})
						continue
					}

					// Consume tokens based on extracted request cost
					cost := int64(requestCost)
					result, err := q.Limiter.AllowN(context.Background(), key, cost)
					if err != nil {
						if p.redisBacked() && p.redisFailOpen {
							slog.Warn("Rate limit check failed (fail-open)", "error", err, "quota", quotaName)
							continue
						}
						slog.Error("Rate limit check failed (fail-closed)", "error", err, "quota", quotaName)
						return p.buildRateLimitResponse(nil, quotaName, quotaResults)
					}

					if !result.Allowed {
						slog.Debug("Rate limit exceeded",
							"key", key,
							"cost", cost,
							"quota", quotaName,
							"remaining", result.Remaining,
							"limit", result.Limit)
						return p.buildRateLimitResponse(result, quotaName, quotaResults)
					}

					slog.Debug("Rate limit check passed",
						"quota", quotaName,
						"key", key,
						"cost", cost,
						"remaining", result.Remaining,
						"limit", result.Limit)

					quotaResults = append(quotaResults, quotaResult{
						QuotaName: quotaName,
						Result:    result,
						Key:       key,
						Duration:  result.Duration,
					})
					continue
				}

				// Response-phase cost extraction: pre-check if quota is already exhausted
				// Use GetAvailable to check remaining without consuming tokens
				available, err := q.Limiter.GetAvailable(context.Background(), key)
				if err != nil {
					if p.redisBacked() && p.redisFailOpen {
						slog.Warn("Rate limit pre-check failed (fail-open)", "error", err, "key", key, "quota", quotaName)
						continue
					}
					slog.Error("Rate limit pre-check failed (fail-closed)", "error", err, "key", key, "quota", quotaName)
					return p.buildRateLimitResponse(nil, quotaName, quotaResults)
				}

				// If available <= 0, quota is exhausted - block the request
				if available <= 0 {
					slog.Debug("Cost extraction mode: quota exhausted, blocking request",
						"key", key, "available", available, "quota", quotaName)
					// Build a result for the exhausted quota
					duration := getDurationFromQuota(q)
					result := &limiter.Result{
						Allowed:   false,
						Limit:     getLimitFromQuota(q),
						Remaining: 0,
						Reset:     time.Now().Add(duration),
						Duration:  duration,
					}
					return p.buildRateLimitResponse(result, quotaName, quotaResults)
				}

				// Store a placeholder result for the response phase
				// The actual consumption and result will be determined in OnResponse
				quotaResults = append(quotaResults, quotaResult{
					QuotaName: quotaName,
					Result:    nil, // Will be populated in OnResponse
					Key:       key,
					Duration:  getDurationFromQuota(q),
				})
				continue
			}

			// Standard mode (no cost extraction): consume 1 token per request.
			// Guard against double-charging: OnRequestHeaders always calls AllowN(1)
			// for standard-mode quotas, so skip re-consumption if that already happened.
			if handledInHeaderPhase[quotaName] {
				if stored, ok := storedResultsMap[quotaName]; ok {
					quotaResults = append(quotaResults, stored)
				}
				continue
			}
			cost := int64(1)

			result, err := q.Limiter.AllowN(context.Background(), key, cost)
			if err != nil {
				if p.redisBacked() && p.redisFailOpen {
					slog.Warn("Rate limit check failed (fail-open)", "error", err, "quota", quotaName)
					continue
				}
				slog.Error("Rate limit check failed (fail-closed)", "error", err, "quota", quotaName)
				return p.buildRateLimitResponse(nil, quotaName, quotaResults)
			}

			if !result.Allowed {
				slog.Debug("Rate limit exceeded", "key", key, "quota", quotaName)
				return p.buildRateLimitResponse(result, quotaName, quotaResults)
			}

			quotaResults = append(quotaResults, quotaResult{
				QuotaName: quotaName,
				Result:    result,
				Key:       key,
				Duration:  result.Duration,
			})
		}

		// Store results and keys in metadata for response phase
		reqCtx.Metadata[p.metaKey(rateLimitResultKey)] = quotaResults
		reqCtx.Metadata[p.metaKey(rateLimitKeysKey)] = quotaKeys

		return policy.UpstreamRequestModifications{}
	} else {
		return policy.UpstreamRequestModifications{}
	}
}

// OnResponseHeaders adds rate limit headers in the response header phase using results
// already available from the request phase. Response-phase cost extraction quotas will
// have their final values updated by OnResponse once the body is processed.
func (p *RateLimitPolicy) OnResponseHeaders(ctx context.Context, respCtx *policy.ResponseHeaderContext, params map[string]interface{}) policy.ResponseHeaderAction {
	slog.Debug("Processing rate limit response phase",
		"route", p.routeName,
		"status", respCtx.ResponseStatus,
		"quotaCount", len(p.quotas))

	// Retrieve stored keys for cost extraction
	quotaKeysRaw, hasKeys := respCtx.Metadata[p.metaKey(rateLimitKeysKey)]
	quotaKeys := make(map[string]string)
	if hasKeys {
		if keys, ok := quotaKeysRaw.(map[string]string); ok {
			quotaKeys = keys
		}
	}

	// Detect whether the upstream response is streaming (SSE or chunked transfer).
	// The kernel activates FULL_DUPLEX_STREAMED mode under the same conditions, which
	// means OnResponseBodyChunk will be used instead of OnResponseBody, and response
	// headers will be committed before any body chunks arrive.
	//
	// Read from the upstream snapshot so the streaming-mode decision
	// reflects the content-type/transfer-encoding the upstream actually returned,
	// not a value a peer policy rewrote during the response header phase.
	isStreaming := isStreamingResponse(getUpstreamHeaders(respCtx.Upstream, respCtx.ResponseHeaders))

	// Retrieve stored results from request phase
	resultsRaw, hasResults := respCtx.Metadata[p.metaKey(rateLimitResultKey)]
	var storedResults []quotaResult
	if hasResults {
		if results, ok := resultsRaw.([]quotaResult); ok {
			storedResults = results
		}
	}

	// Create a map for quick lookup of stored results (preserving full quotaResult)
	storedResultsMap := make(map[string]quotaResult)
	for _, r := range storedResults {
		storedResultsMap[r.QuotaName] = r
	}

	// Process each quota for post-response cost extraction
	// Collect full quotaResult structs to preserve quota names and durations for headers
	var allQuotaResults []quotaResult

	for i := range p.quotas {
		q := &p.quotas[i]
		quotaName := q.Name
		if quotaName == "" {
			quotaName = fmt.Sprintf("quota-%d", i)
		}

		// Handle post-response cost extraction for quotas that have it enabled.
		// Skip quotas that require the response body — those are handled exclusively
		// in OnResponseBody to avoid double consumption.
		if q.CostExtractionEnabled && q.CostExtractor != nil &&
			q.CostExtractor.HasResponsePhaseSources() && q.CostExtractor.HasResponseHeaderOnlyCostSources() {
			slog.Debug("Processing response-header-phase cost extraction",
				"quota", quotaName)

			key := quotaKeys[quotaName]
			if key == "" {
				slog.Warn("Rate limit key not found for cost extraction", "quota", quotaName)
				continue
			}

			// Extract actual cost from response
			// OnResponseHeaders only has ResponseHeaderContext, so construct a ResponseContext
			// with available fields (ResponseBody will be nil at this phase).
			responseCtx := &policy.ResponseContext{
				SharedContext:   respCtx.SharedContext,
				RequestHeaders:  respCtx.RequestHeaders,
				RequestBody:     respCtx.RequestBody,
				RequestPath:     respCtx.RequestPath,
				RequestMethod:   respCtx.RequestMethod,
				ResponseHeaders: respCtx.ResponseHeaders,
				ResponseStatus:  respCtx.ResponseStatus,
				// Propagate the snapshots so header-based cost extraction
				// reads the original upstream response (and downstream request) values.
				Downstream: respCtx.Downstream,
				Upstream:   respCtx.Upstream,
			}
			actualCost, extracted := q.CostExtractor.ExtractResponseCost(responseCtx)
			if !extracted {
				slog.Debug("Cost extraction failed, using default", "key", key, "quota", quotaName, "defaultCost", actualCost)
			}

			// Clamp cost to minimum of 0 (allow 0 cost for free operations)
			if actualCost < 0 {
				actualCost = 0
			}

			// Skip if cost is 0
			if actualCost == 0 {
				// Still include stored result for headers if available
				if stored, ok := storedResultsMap[quotaName]; ok && stored.Result != nil {
					allQuotaResults = append(allQuotaResults, stored)
				} else {
					// For response-phase cost extraction with 0 cost, get current state
					// Use GetAvailable to check remaining without consuming
					available, err := q.Limiter.GetAvailable(context.Background(), key)
					if err == nil {
						duration := getDurationFromQuota(q)
						allQuotaResults = append(allQuotaResults, quotaResult{
							QuotaName: quotaName,
							Result: &limiter.Result{
								Allowed:   available > 0,
								Limit:     getLimitFromQuota(q),
								Remaining: available,
								Reset:     time.Now().Add(duration),
								Duration:  duration,
							},
							Key:      key,
							Duration: duration,
						})
					}
				}
				continue
			}

			// Consume tokens now. Use ConsumeN for accurate cost tracking if the
			// limiter supports it, otherwise fall back to ConsumeOrClampN.
			var (
				result *limiter.Result
				err    error
			)
			if tracker, ok := q.Limiter.(limiter.CostTracker); ok {
				result, err = tracker.ConsumeN(context.Background(), key, int64(actualCost))
			} else {
				result, err = q.Limiter.ConsumeOrClampN(context.Background(), key, int64(actualCost))
			}
			if err != nil {
				if p.redisBacked() && p.redisFailOpen {
					slog.Warn("Post-response rate limit check failed (fail-open)",
						"error", err, "key", key, "cost", actualCost, "quota", quotaName)
					continue
				}
				slog.Error("Post-response rate limit check failed (fail-closed)",
					"error", err, "key", key, "cost", actualCost, "quota", quotaName)
				continue
			}

			if result != nil && !result.Allowed {
				slog.Warn("Rate limit exceeded post-response",
					"key", key, "cost", actualCost, "limit", result.Limit,
					"remaining", result.Remaining, "consumed", result.Consumed,
					"overflow", result.Overflow, "quota", quotaName)
			}

			allQuotaResults = append(allQuotaResults, quotaResult{
				QuotaName: quotaName,
				Result:    result,
				Key:       key,
				Duration:  result.Duration,
			})
		} else {
			// Use stored result from request phase.
			if stored, ok := storedResultsMap[quotaName]; ok && stored.Result != nil {
				allQuotaResults = append(allQuotaResults, stored)
			} else if isStreaming {
				// stored.Result is nil (pre-check placeholder) AND the response is
				// streaming (SSE / chunked). Response headers are committed to the client
				// before the first body chunk arrives, so OnResponseBodyChunk /
				// finalizeAndConsumeStreamingCosts cannot update them. Use GetAvailable
				// to produce a pre-consumption snapshot so the client sees useful
				// rate-limit information. The value reflects remaining BEFORE this
				// request's token cost is deducted; it decreases correctly across
				// successive requests as each EOS deduction is applied.
				// For buffered responses this branch is intentionally skipped —
				// OnResponseBody will set accurate post-consumption values instead.
				key := quotaKeys[quotaName]
				if key != "" {
					available, err := q.Limiter.GetAvailable(context.Background(), key)
					if err == nil {
						duration := getDurationFromQuota(q)
						allQuotaResults = append(allQuotaResults, quotaResult{
							QuotaName: quotaName,
							Result: &limiter.Result{
								Allowed:   available > 0,
								Limit:     getLimitFromQuota(q),
								Remaining: available,
								Reset:     time.Now().Add(duration),
								Duration:  duration,
							},
							Key:      key,
							Duration: duration,
						})
					}
				}
			}
		}
	}

	// Store updated results so OnResponseBody can carry forward response_header
	// quota results and avoid re-consuming them.
	respCtx.Metadata[p.metaKey(rateLimitResultKey)] = allQuotaResults

	// For buffered responses with body-phase sources, defer header emission to
	// OnResponseBody which has the full body and can report accurate post-consumption
	// remaining. For streaming responses, headers are already committed by the time
	// chunks arrive so we must emit them here using the pre-consumption snapshot built
	// above — skip the early return in that case.
	if p.requiresAnyResponseBodyMode() && !isStreaming {
		return nil
	}

	if len(allQuotaResults) == 0 {
		return nil
	}

	headers := p.buildMultiQuotaHeaders(allQuotaResults, false, "")
	if len(headers) == 0 {
		return nil
	}

	return policy.DownstreamResponseHeaderModifications{
		HeadersToSet:    headers,
		HeadersToRemove: upstreamRateLimitHeaders,
	}
}

// OnResponseBody processes response-phase cost extraction and emits rate limit headers.
// This mirrors the logic in OnResponse (v1alpha) but uses v1alpha2 context types.
// It must run AFTER any policy that populates response metadata used as cost sources
// (e.g. llm-cost sets x-llm-cost in SharedContext.Metadata). The executor runs
// response policies in reverse chain order, so policies appended after this one
// run first — ensuring cost metadata is available when this method executes.
//
// Note: this method also handles non-body response-phase sources (e.g.
// response_metadata) even though they don't require the body bytes. Those sources
// could not be resolved in OnResponseHeaders because the metadata they read
// (e.g. x-llm-cost) is populated by upstream policies that run in the body phase.
// By the time this method is called, those policies have already executed.
func (p *RateLimitPolicy) OnResponseBody(ctx context.Context, respCtx *policy.ResponseContext,
	_ map[string]interface{},
) policy.ResponseAction {
	if p.requiresAnyResponseBodyMode() {
		slog.Debug("Processing rate limit response phase",
			"route", p.routeName,
			"status", respCtx.ResponseStatus,
			"quotaCount", len(p.quotas))

		// Retrieve stored keys for cost extraction
		quotaKeysRaw, hasKeys := respCtx.Metadata[p.metaKey(rateLimitKeysKey)]
		quotaKeys := make(map[string]string)
		if hasKeys {
			if keys, ok := quotaKeysRaw.(map[string]string); ok {
				quotaKeys = keys
			}
		}

		// Retrieve stored results from request phase
		resultsRaw, hasResults := respCtx.Metadata[p.metaKey(rateLimitResultKey)]
		var storedResults []quotaResult
		if hasResults {
			if results, ok := resultsRaw.([]quotaResult); ok {
				storedResults = results
			}
		}

		// Create a map for quick lookup of stored results (preserving full quotaResult)
		storedResultsMap := make(map[string]quotaResult)
		for _, r := range storedResults {
			storedResultsMap[r.QuotaName] = r
		}

		// Process each quota for post-response cost extraction
		// Collect full quotaResult structs to preserve quota names and durations for headers
		var allQuotaResults []quotaResult

		for i := range p.quotas {
			q := &p.quotas[i]
			quotaName := q.Name
			if quotaName == "" {
				quotaName = fmt.Sprintf("quota-%d", i)
			}

			// response_header-only quotas are fully consumed in OnResponseHeaders —
			// carry forward the stored result to avoid re-consumption.
			if q.CostExtractionEnabled && q.CostExtractor != nil && q.CostExtractor.HasResponseHeaderOnlyCostSources() {
				if stored, ok := storedResultsMap[quotaName]; ok {
					allQuotaResults = append(allQuotaResults, stored)
				}
				continue
			}

			// Handle post-response cost extraction for quotas that have it enabled
			if q.CostExtractionEnabled && q.CostExtractor != nil && q.CostExtractor.HasResponsePhaseSources() {
				slog.Debug("Processing response-phase cost extraction",
					"quota", quotaName)

				key := quotaKeys[quotaName]
				if key == "" {
					slog.Warn("Rate limit key not found for cost extraction", "quota", quotaName)
					continue
				}

				// Extract actual cost from response
				actualCost, extracted := q.CostExtractor.ExtractResponseCost(respCtx)
				if !extracted {
					slog.Debug("Cost extraction failed, using default", "key", key, "quota", quotaName, "defaultCost", actualCost)
				}

				// Clamp cost to minimum of 0 (allow 0 cost for free operations)
				if actualCost < 0 {
					actualCost = 0
				}

				// Skip if cost is 0
				if actualCost == 0 {
					// Still include stored result for headers if available
					if stored, ok := storedResultsMap[quotaName]; ok && stored.Result != nil {
						allQuotaResults = append(allQuotaResults, stored)
					} else {
						// For response-phase cost extraction with 0 cost, get current state
						// Use GetAvailable to check remaining without consuming
						available, err := q.Limiter.GetAvailable(context.Background(), key)
						if err == nil {
							duration := getDurationFromQuota(q)
							allQuotaResults = append(allQuotaResults, quotaResult{
								QuotaName: quotaName,
								Result: &limiter.Result{
									Allowed:   available > 0,
									Limit:     getLimitFromQuota(q),
									Remaining: available,
									Reset:     time.Now().Add(duration),
									Duration:  duration,
								},
								Key:      key,
								Duration: duration,
							})
						}
					}
					continue
				}

				// Consume tokens now. Use ConsumeN for accurate cost tracking if the
				// limiter supports it, otherwise fall back to ConsumeOrClampN.
				var (
					result *limiter.Result
					err    error
				)
				if tracker, ok := q.Limiter.(limiter.CostTracker); ok {
					result, err = tracker.ConsumeN(context.Background(), key, int64(actualCost))
				} else {
					result, err = q.Limiter.ConsumeOrClampN(context.Background(), key, int64(actualCost))
				}
				if err != nil {
					if p.redisBacked() && p.redisFailOpen {
						slog.Warn("Post-response rate limit check failed (fail-open)",
							"error", err, "key", key, "cost", actualCost, "quota", quotaName)
						continue
					}
					slog.Error("Post-response rate limit check failed (fail-closed)",
						"error", err, "key", key, "cost", actualCost, "quota", quotaName)
					continue
				}

				if result != nil && !result.Allowed {
					slog.Warn("Rate limit exceeded post-response",
						"key", key, "cost", actualCost, "limit", result.Limit,
						"remaining", result.Remaining, "consumed", result.Consumed,
						"overflow", result.Overflow, "quota", quotaName)
				}

				allQuotaResults = append(allQuotaResults, quotaResult{
					QuotaName: quotaName,
					Result:    result,
					Key:       key,
					Duration:  result.Duration,
				})
			} else {
				// Use stored result from request phase
				if stored, ok := storedResultsMap[quotaName]; ok && stored.Result != nil {
					allQuotaResults = append(allQuotaResults, stored)
				}
			}
		}

		// Build headers for all quotas using the new multi-quota function
		if len(allQuotaResults) == 0 {
			return nil
		}

		headers := p.buildMultiQuotaHeaders(allQuotaResults, false, "")
		if len(headers) == 0 {
			return nil
		}

		return policy.DownstreamResponseModifications{
			HeadersToSet:    headers,
			HeadersToRemove: upstreamRateLimitHeaders,
		}
	}
	return policy.DownstreamResponseModifications{
		HeadersToRemove: upstreamRateLimitHeaders,
	}
}

func (p *RateLimitPolicy) extractQuotaKey(reqCtx *policy.RequestContext, q *QuotaRuntime) string {
	if len(q.KeyExtraction) == 0 {
		slog.Debug("No key extraction configured, using route name",
			"routeName", p.routeName)
		return p.routeName
	}

	if len(q.KeyExtraction) == 1 {
		key := p.extractKeyComponent(reqCtx, q.KeyExtraction[0])
		slog.Debug("Single component key extracted",
			"type", q.KeyExtraction[0].Type,
			"key", key)
		return key
	}

	// Multiple components - join with ':' in the order specified
	parts := make([]string, 0, len(q.KeyExtraction))
	for _, comp := range q.KeyExtraction {
		part := p.extractKeyComponent(reqCtx, comp)
		parts = append(parts, part)
	}
	key := strings.Join(parts, ":")
	slog.Debug("Multi-component key extracted",
		"componentCount", len(q.KeyExtraction),
		"key", key)
	return key
}

// extractKeyComponent extracts a single component value
func (p *RateLimitPolicy) extractKeyComponent(reqCtx *policy.RequestContext, comp KeyComponent) string {
	switch comp.Type {
	case "header":
		values := getDownstreamHeaders(reqCtx.Downstream, reqCtx.Headers).Get(strings.ToLower(comp.Key))
		if len(values) > 0 && values[0] != "" {
			return values[0]
		}
		placeholder := fmt.Sprintf("_missing_header_%s_", comp.Key)
		slog.Warn("Header not found for rate limit key, using placeholder", "header", comp.Key, "type", comp.Type, "placeholder", placeholder)
		return placeholder

	case "constant":
		return comp.Key

	case "metadata":
		if val, ok := reqCtx.Metadata[comp.Key]; ok {
			if strVal, ok := val.(string); ok && strVal != "" {
				return strVal
			}
		}
		if comp.Fallback != "" {
			return comp.Fallback
		}
		placeholder := fmt.Sprintf("_missing_metadata_%s_", comp.Key)
		slog.Warn("Metadata key not found for rate limit key, using placeholder", "key", comp.Key, "type", comp.Type, "placeholder", placeholder)
		return placeholder

	case "ip":
		return p.extractIPAddress(getDownstreamHeaders(reqCtx.Downstream, reqCtx.Headers))

	case "apiname":
		if reqCtx.APIName != "" {
			return reqCtx.APIName
		}
		slog.Warn("APIName not available for rate limit key, using empty string")
		return ""

	case "apiversion":
		if reqCtx.APIVersion != "" {
			return reqCtx.APIVersion
		}
		slog.Warn("APIVersion not available for rate limit key, using empty string")
		return ""

	case "routename":
		return p.routeName

	case "cel":
		evaluator, err := GetCELEvaluator()
		if err != nil {
			slog.Error("Failed to get CEL evaluator for key extraction", "error", err)
			return "_cel_error_"
		}
		slog.Debug("Evaluating CEL expression for key extraction",
			"expression", comp.Expression)
		result, err := evaluator.EvaluateKeyExpression(comp.Expression, reqCtx, p.routeName)
		if err != nil {
			slog.Warn("CEL key extraction failed, using placeholder", "expression", comp.Expression, "error", err)
			return "_cel_eval_error_"
		}
		return result

	default:
		slog.Warn("Unknown key component type, using empty string", "type", comp.Type)
		return ""
	}
}

// extractIPAddress extracts client IP from headers
func (p *RateLimitPolicy) extractIPAddress(headers *policy.Headers) string {
	// Try X-Forwarded-For first (most common)
	if xff := headers.Get("x-forwarded-for"); len(xff) > 0 && xff[0] != "" {
		// Take the first IP (client)
		ips := strings.Split(xff[0], ",")
		if len(ips) > 0 {
			ip := strings.TrimSpace(ips[0])
			if ip != "" {
				return ip
			}
		}
	}

	// Try X-Real-IP
	if xri := headers.Get("x-real-ip"); len(xri) > 0 && xri[0] != "" {
		return xri[0]
	}

	slog.Warn("Could not extract IP address for rate limit key, using 'unknown'")
	return "unknown"
}

// ─── Streaming response body (StreamingResponsePolicy) ───────────────────────

// getOrInitStreamState loads the per-request streaming state map from shared metadata,
// creating and storing it if this is the first chunk of the request.
// Each quota gets its own streamQuotaState entry keyed by quota name.
func (p *RateLimitPolicy) getOrInitStreamState(metadata map[string]interface{}) map[string]*streamQuotaState {
	if existing, ok := metadata[p.metaKey(rateLimitStreamStateKey)].(map[string]*streamQuotaState); ok {
		return existing
	}
	state := make(map[string]*streamQuotaState, len(p.quotas))
	for i := range p.quotas {
		state[quotaNameFor(&p.quotas[i], i)] = &streamQuotaState{}
	}
	metadata[p.metaKey(rateLimitStreamStateKey)] = state
	return state
}

// OnResponseBodyChunk is called by the kernel for every response body chunk when the
// chain runs in FULL_DUPLEX_STREAMED mode (every policy returned BodyModeStream).
//
// Raw bytes are accumulated once per quota per chunk into streamQuotaState.accumulated.
// All cost extraction — both plain JSON (JSONPath) and SSE (last-match-wins via the
// extractFromBodyBytes SSE fallback) — is deferred to EOS inside
// finalizeAndConsumeStreamingCosts. Accumulating once per quota (rather than once
// per source) ensures that quotas with multiple response_body/response_cel sources
// always receive the correct, un-duplicated body bytes.
//
// The chunk is always passed through unmodified — this policy only observes the stream.
// Token consumption happens in finalizeAndConsumeStreamingCosts at EOS.
func (p *RateLimitPolicy) OnResponseBodyChunk(
	ctx context.Context,
	respCtx *policy.ResponseStreamContext,
	chunk *policy.StreamBody,
	_ map[string]interface{},
) policy.StreamingResponseAction {
	state := p.getOrInitStreamState(respCtx.Metadata)

	for i := range p.quotas {
		q := &p.quotas[i]
		if !q.CostExtractionEnabled || q.CostExtractor == nil {
			continue
		}
		// Only accumulate bytes for quotas that need body content. Quotas whose
		// sources are exclusively response_header or response_metadata need no
		// per-chunk work — they are handled in OnResponseHeaders or read directly
		// from shared metadata at EOS.
		if !q.CostExtractor.RequiresResponseBody() {
			continue
		}

		quotaName := quotaNameFor(q, i)
		qs := state[quotaName]
		qs.accumulated = append(qs.accumulated, chunk.Chunk...)
		state[quotaName] = qs
	}
	// Persist updated state so the next chunk call sees the accumulated bytes for each quota.
	respCtx.Metadata[p.metaKey(rateLimitStreamStateKey)] = state

	// EOS: all chunks have arrived. Finalize JSON extraction (SSE values are
	// already up-to-date from per-chunk parsing) and consume tokens.
	if chunk.EndOfStream {
		p.finalizeAndConsumeStreamingCosts(ctx, respCtx, state)
	}

	return policy.ForwardResponseChunk{} // passthrough — do not modify the chunk
}

// NeedsMoreResponseData always returns false.
// Raw bytes are accumulated manually in streamQuotaState.accumulated and
// extracted at EOS. The kernel does not need to buffer a minimum number of
// bytes before invoking OnResponseBodyChunk.
func (p *RateLimitPolicy) NeedsMoreResponseData(_ []byte) bool {
	return false
}

// finalizeAndConsumeStreamingCosts is called once when chunk.EndOfStream is true.
//
// A synthetic ResponseContext is built from the stream context plus the bytes
// accumulated in streamQuotaState.accumulated, then ExtractResponseCost is called for
// each quota. ExtractResponseCost dispatches to the appropriate handler for each
// source type (JSONPath, CEL, metadata lookup) and its extractFromBodyBytes helper
// transparently handles both plain JSON bodies and SSE streams — for SSE it falls back
// to extractFromSSEBodyBytes which applies last-match-wins semantics over the buffered
// events, identical to what per-chunk SSE parsing previously achieved.
//
// Note: response headers are already committed to the client before the first chunk
// arrives, so rate-limit headers cannot be updated here. The pre-request availability
// check in OnRequestHeaders still blocks requests when the quota is fully exhausted.
func (p *RateLimitPolicy) finalizeAndConsumeStreamingCosts(
	ctx context.Context,
	respCtx *policy.ResponseStreamContext,
	state map[string]*streamQuotaState,
) {
	// quotaKeys were written to metadata during the request phase (OnRequestHeaders /
	// OnRequestBody) and carry the rate-limit key for each quota into the response phase.
	quotaKeys, _ := respCtx.Metadata[p.metaKey(rateLimitKeysKey)].(map[string]string)

	for i := range p.quotas {
		q := &p.quotas[i]
		if !q.CostExtractionEnabled || q.CostExtractor == nil {
			continue
		}
		// Only process quotas with non-header response sources. response_header quotas
		// are fully consumed in OnResponseHeaders and must not be charged again.
		if !p.hasStreamingResponseSourceForQuota(q) {
			continue
		}

		quotaName := quotaNameFor(q, i)
		key := quotaKeys[quotaName]
		qs := state[quotaName]

		var (
			actualCost float64
			extracted  bool
		)

		// Build a synthetic ResponseContext so that ExtractResponseCost can dispatch
		// to the correct handler for each source type without duplicating logic here.
		//
		// ResponseBody.Content holds the bytes accumulated across all chunks.
		// extractFromBodyBytes (called inside ExtractResponseCost for response_body
		// sources) tries JSONPath first; if the body is not valid JSON (e.g. SSE
		// format), it falls back to extractFromSSEBodyBytes which applies
		// last-match-wins over each buffered data: line — preserving the correct
		// final usage value from the provider's last usage event.
		// For response_metadata, Content will be empty — ExtractResponseCost reads
		// from synthCtx.Metadata (which is the shared SharedContext.Metadata already
		// populated by upstream policies during the stream).
		bodyBytes := []byte(nil)
		if qs != nil {
			bodyBytes = qs.accumulated
		}
		synthCtx := &policy.ResponseContext{
			SharedContext:   respCtx.SharedContext,
			RequestHeaders:  respCtx.RequestHeaders,
			RequestBody:     respCtx.RequestBody,
			RequestPath:     respCtx.RequestPath,
			RequestMethod:   respCtx.RequestMethod,
			ResponseHeaders: respCtx.ResponseHeaders,
			ResponseStatus:  respCtx.ResponseStatus,
			// Propagate the snapshots so header-based cost extraction
			// reads the original upstream response (and downstream request) values.
			Downstream: respCtx.Downstream,
			Upstream:   respCtx.Upstream,
			ResponseBody: &policy.Body{
				Content:     bodyBytes,
				Present:     len(bodyBytes) > 0,
				EndOfStream: true,
			},
		}
		actualCost, extracted = q.CostExtractor.ExtractResponseCost(synthCtx)
		if !extracted {
			slog.Debug("Streaming EOS cost extraction failed, using default",
				"quota", quotaName, "key", key, "default", actualCost)
		}

		if actualCost < 0 {
			actualCost = 0
		}
		if actualCost == 0 {
			// Zero cost: skip the limiter call entirely to avoid unnecessary overhead.
			continue
		}

		// Consume tokens against the limiter.
		// ConsumeN (CostTracker) tracks overflow and consumed metrics accurately.
		// ConsumeOrClampN is the safe fallback for limiters that do not implement
		// CostTracker; it clamps the deduction to the available balance.
		if tracker, ok := q.Limiter.(limiter.CostTracker); ok {
			if _, err := tracker.ConsumeN(ctx, key, int64(actualCost)); err != nil {
				if p.redisBacked() && p.redisFailOpen {
					slog.Warn("Streaming EOS cost consumption failed (fail-open)",
						"error", err, "quota", quotaName, "key", key, "cost", actualCost)
					continue
				}
				slog.Error("Streaming EOS cost consumption failed (fail-closed)",
					"error", err, "quota", quotaName, "key", key, "cost", actualCost)
				continue
			}
		} else {
			if _, err := q.Limiter.ConsumeOrClampN(ctx, key, int64(actualCost)); err != nil {
				if p.redisBacked() && p.redisFailOpen {
					slog.Warn("Streaming EOS cost consumption failed (fail-open)",
						"error", err, "quota", quotaName, "key", key, "cost", actualCost)
					continue
				}
				slog.Error("Streaming EOS cost consumption failed (fail-closed)",
					"error", err, "quota", quotaName, "key", key, "cost", actualCost)
				continue
			}
		}

		slog.Debug("Streaming EOS cost consumed",
			"quota", quotaName,
			"key", key,
			"cost", actualCost)
	}
}
