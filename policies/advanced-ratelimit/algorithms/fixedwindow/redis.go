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

package fixedwindow

import (
	"context"
	_ "embed"
	"fmt"
	"log/slog"
	"math/rand"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/wso2/gateway-controllers/policies/advanced-ratelimit/limiter"
)

// RedisLimiter implements fixed window rate limiting with Redis backend
type RedisLimiter struct {
	client    redis.UniversalClient
	policy    *Policy
	script    *redis.Script
	keyPrefix string
	clock     limiter.Clock
}

//go:embed fixedwindow.lua
var fixedWindowLuaScript string

// NewRedisLimiter creates a new Redis-backed fixed window rate limiter
// client: Redis client for storage
// policy: Rate limit policy defining limit and window duration
// keyPrefix: Prefix for all Redis keys (e.g., "ratelimit:v1:")
func NewRedisLimiter(client redis.UniversalClient, policy *Policy, keyPrefix string) *RedisLimiter {
	if keyPrefix == "" {
		keyPrefix = "ratelimit:v1:"
	}

	return &RedisLimiter{
		client:    client,
		policy:    policy,
		script:    redis.NewScript(fixedWindowLuaScript),
		keyPrefix: keyPrefix,
		clock:     &limiter.SystemClock{},
	}
}

// WithClock sets a custom clock (for testing)
func (r *RedisLimiter) WithClock(clock limiter.Clock) *RedisLimiter {
	r.clock = clock
	return r
}

// Allow checks if a single request is allowed for the given key
func (r *RedisLimiter) Allow(ctx context.Context, key string) (*limiter.Result, error) {
	return r.AllowN(ctx, key, 1)
}

// AllowN checks if N requests are allowed for the given key
// Uses atomic INCRBY in Redis - no Lua script needed
func (r *RedisLimiter) AllowN(ctx context.Context, key string, n int64) (*limiter.Result, error) {
	now := r.clock.Now()
	windowStart := r.policy.WindowStart(now)
	windowEnd := r.policy.WindowEnd(now)

	// Build window-specific key with timestamp
	// e.g., "ratelimit:v1:user123:1704067200000000000"
	redisKey := fmt.Sprintf("%s%s:%d", r.keyPrefix, key, windowStart.UnixNano())

	slog.Debug("FixedWindow(Redis): checking rate limit",
		"key", key,
		"redisKey", redisKey,
		"cost", n,
		"windowStart", windowStart,
		"windowEnd", windowEnd)

	var newCount int64
	var err error

	// For peek operations (n=0), use GET to avoid creating keys or resetting TTL
	if n == 0 {
		val, getErr := r.client.Get(ctx, redisKey).Int64()
		if getErr == redis.Nil {
			// Key doesn't exist - no requests in this window yet
			newCount = 0
		} else if getErr != nil {
			return nil, fmt.Errorf("redis GET failed: %w", getErr)
		} else {
			newCount = val
		}
	} else {
		// Atomic increment - this is the core of fixed window
		newCount, err = r.client.IncrBy(ctx, redisKey, n).Result()
		if err != nil {
			return nil, fmt.Errorf("redis INCRBY failed: %w", err)
		}

		// Set TTL only on first request in window (when newCount == n)
		// This avoids calling EXPIRE on every request
		if newCount == n {
			// Add jitter (0-5s) to spread expiration load across Redis
			// Prevents "thundering herd" of expirations at window boundaries
			jitter := time.Duration(rand.Int63n(int64(5 * time.Second)))
			ttl := time.Until(windowEnd) + jitter

			// Set expiration and handle potential error to avoid keys without TTL
			if err := r.client.Expire(ctx, redisKey, ttl).Err(); err != nil {
				// Log with context; surface error so callers can decide (fail-open/closed)
				slog.Error("redis EXPIRE failed for rate limit key", "redisKey", redisKey, "ttl", ttl, "error", err)
				return nil, fmt.Errorf("redis EXPIRE failed for key %s ttl %s: %w", redisKey, ttl.String(), err)
			}
		}
	}

	// Check if allowed
	allowed := newCount <= r.policy.Limit

	// Calculate remaining capacity
	var remaining int64
	if allowed {
		remaining = r.policy.Limit - newCount
	} else {
		remaining = 0
	}

	slog.Debug("FixedWindow(Redis): rate limit check result",
		"key", key,
		"redisKey", redisKey,
		"allowed", allowed,
		"newCount", newCount,
		"limit", r.policy.Limit,
		"remaining", remaining)

	// Build result
	result := &limiter.Result{
		Allowed:   allowed,
		Limit:     r.policy.Limit,
		Remaining: remaining,
		Reset:     windowEnd,
		Duration:  r.policy.Duration,
		Policy:    r.policy,
	}

	// Set retry-after if denied
	if !allowed {
		result.RetryAfter = time.Until(windowEnd)
		if result.RetryAfter < 0 {
			result.RetryAfter = 0
		}
	}

	return result, nil
}

// ConsumeOrClampN consumes up to n tokens atomically in Redis.
// If n exceeds available capacity, it consumes the remaining tokens and returns denied.
func (r *RedisLimiter) ConsumeOrClampN(ctx context.Context, key string, n int64) (*limiter.Result, error) {
	if n < 0 {
		n = 0
	}

	now := r.clock.Now()
	windowStart := r.policy.WindowStart(now)
	windowEnd := r.policy.WindowEnd(now)
	redisKey := fmt.Sprintf("%s%s:%d", r.keyPrefix, key, windowStart.UnixNano())

	jitter := time.Duration(rand.Int63n(int64(5 * time.Second)))
	ttl := time.Until(windowEnd) + jitter
	if ttl <= 0 {
		ttl = time.Second
	}

	result, err := r.script.Run(ctx, r.client, []string{redisKey},
		r.policy.Limit,     // ARGV[1]: limit
		n,                  // ARGV[2]: requested cost
		ttl.Milliseconds(), // ARGV[3]: TTL in milliseconds
		1,                  // ARGV[4]: clamp mode
	).Result()
	if err != nil {
		if strings.Contains(err.Error(), "NOSCRIPT") {
			if _, loadErr := r.script.Load(ctx, r.client).Result(); loadErr != nil {
				return nil, fmt.Errorf("failed to load fixed window Lua script: %w", loadErr)
			}
			result, err = r.script.Run(ctx, r.client, []string{redisKey},
				r.policy.Limit,
				n,
				ttl.Milliseconds(),
				1,
			).Result()
		}
		if err != nil {
			return nil, fmt.Errorf("fixed window clamp script execution failed: %w", err)
		}
	}

	values := result.([]interface{})
	allowed := values[0].(int64) == 1
	remaining := values[1].(int64)
	consumed := values[3].(int64)
	overflow := values[4].(int64)

	rlResult := &limiter.Result{
		Allowed:   allowed,
		Requested: n,
		Consumed:  consumed,
		Overflow:  overflow,
		Limit:     r.policy.Limit,
		Remaining: remaining,
		Reset:     windowEnd,
		Duration:  r.policy.Duration,
		Policy:    r.policy,
	}

	if !allowed {
		rlResult.RetryAfter = time.Until(windowEnd)
		if rlResult.RetryAfter < 0 {
			rlResult.RetryAfter = 0
		}
	}

	return rlResult, nil
}

// GetAvailable returns the available tokens for the given key without consuming
func (r *RedisLimiter) GetAvailable(ctx context.Context, key string) (int64, error) {
	now := r.clock.Now()
	windowStart := r.policy.WindowStart(now)

	// Use Redis key with window start
	redisKey := fmt.Sprintf("%s%s:%d", r.keyPrefix, key, windowStart.UnixNano())

	// Get current count from Redis
	count, err := r.client.Get(ctx, redisKey).Int64()
	if err == redis.Nil {
		count = 0
	} else if err != nil {
		return 0, fmt.Errorf("redis get failed: %w", err)
	}

	// Calculate remaining
	remaining := r.policy.Limit - count
	if remaining < 0 {
		remaining = 0
	}

	return remaining, nil
}

// Close releases resources (no-op for Redis as connections are managed externally)
// Safe to call multiple times
func (r *RedisLimiter) Close() error {
	// Redis client is managed externally, so we don't close it
	// This method exists to satisfy the Limiter interface
	return nil
}
