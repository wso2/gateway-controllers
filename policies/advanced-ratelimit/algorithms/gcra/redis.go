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

package gcra

import (
	"context"
	_ "embed"
	"fmt"
	"log/slog"
	"math"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/wso2/gateway-controllers/policies/advanced-ratelimit/limiter"
)

// RedisLimiter implements GCRA rate limiting with Redis backend
type RedisLimiter struct {
	client    redis.UniversalClient
	policy    *Policy
	script    *redis.Script
	keyPrefix string
	clock     limiter.Clock
	closeOnce sync.Once
}

//go:embed gcra.lua
var gcraLuaScript string

// NewRedisLimiter creates a new Redis-backed GCRA rate limiter
// client: Redis client (supports both redis.Client and redis.ClusterClient)
// policy: Rate limit policy defining limits and burst capacity
// keyPrefix: Prefix prepended to all keys (e.g., "ratelimit:v1:")
func NewRedisLimiter(client redis.UniversalClient, policy *Policy, keyPrefix string) *RedisLimiter {
	if keyPrefix == "" {
		keyPrefix = "ratelimit:v1:"
	}

	return &RedisLimiter{
		client:    client,
		policy:    policy,
		keyPrefix: keyPrefix,
		script:    redis.NewScript(gcraLuaScript),
		clock:     &limiter.SystemClock{},
	}
}

// Allow checks if a single request is allowed for the given key
func (r *RedisLimiter) Allow(ctx context.Context, key string) (*limiter.Result, error) {
	return r.AllowN(ctx, key, 1)
}

// AllowN checks if N requests are allowed for the given key
// Atomically consumes N request tokens if allowed
func (r *RedisLimiter) AllowN(ctx context.Context, key string, n int64) (*limiter.Result, error) {
	return r.runScript(ctx, key, n, false)
}

// ConsumeOrClampN consumes up to n tokens atomically.
// If n exceeds available capacity, it consumes available capacity and returns denied.
func (r *RedisLimiter) ConsumeOrClampN(ctx context.Context, key string, n int64) (*limiter.Result, error) {
	return r.runScript(ctx, key, n, true)
}

func (r *RedisLimiter) runScript(ctx context.Context, key string, n int64, clamp bool) (*limiter.Result, error) {
	now := r.clock.Now()
	fullKey := r.keyPrefix + key

	if n < 0 {
		n = 0
	}

	slog.Debug("GCRA(Redis): checking rate limit",
		"key", key,
		"fullKey", fullKey,
		"cost", n,
		"clamp", clamp,
		"now", now)

	emissionInterval := r.policy.EmissionInterval()
	burstAllowance := r.policy.BurstAllowance()
	expirationSeconds := int64((r.policy.Duration + burstAllowance).Seconds())
	clampFlag := int64(0)
	if clamp {
		clampFlag = 1
	}

	slog.Debug("GCRA(Redis): executing Lua script",
		"key", key,
		"fullKey", fullKey,
		"emissionInterval", emissionInterval,
		"burstAllowance", burstAllowance,
		"burst", r.policy.Burst,
		"clamp", clamp)

	result, err := r.script.Run(ctx, r.client,
		[]string{fullKey},
		now.UnixNano(),                 // ARGV[1]: current time in nanoseconds
		emissionInterval.Nanoseconds(), // ARGV[2]: emission interval in nanoseconds
		burstAllowance.Nanoseconds(),   // ARGV[3]: burst allowance in nanoseconds
		r.policy.Burst,                 // ARGV[4]: burst capacity
		expirationSeconds,              // ARGV[5]: expiration in seconds
		n,                              // ARGV[6]: requested count
		clampFlag,                      // ARGV[7]: clamp mode
	).Result()

	if err != nil {
		if strings.Contains(err.Error(), "NOSCRIPT") {
			_, loadErr := r.script.Load(ctx, r.client).Result()
			if loadErr != nil {
				return nil, fmt.Errorf("failed to load Lua script: %w", loadErr)
			}
			result, err = r.script.Run(ctx, r.client,
				[]string{fullKey},
				now.UnixNano(),
				emissionInterval.Nanoseconds(),
				burstAllowance.Nanoseconds(),
				r.policy.Burst,
				expirationSeconds,
				n,
				clampFlag,
			).Result()
		}
		if err != nil {
			return nil, fmt.Errorf("script execution failed: %w", err)
		}
	}

	// Returns: {allowed, remaining, reset_nanos, retry_after_nanos, full_quota_at_nanos, consumed, overflow}
	values := result.([]interface{})
	allowed := values[0].(int64) == 1
	remaining := values[1].(int64)
	resetNanos := values[2].(int64)
	retryAfterNanos := values[3].(int64)
	fullQuotaAtNanos := values[4].(int64)
	consumed := values[5].(int64)
	overflow := values[6].(int64)

	slog.Debug("GCRA(Redis): script execution result",
		"key", key,
		"fullKey", fullKey,
		"allowed", allowed,
		"remaining", remaining,
		"consumed", consumed,
		"overflow", overflow,
		"reset", time.Unix(0, resetNanos))

	return &limiter.Result{
		Allowed:     allowed,
		Requested:   n,
		Consumed:    consumed,
		Overflow:    overflow,
		Limit:       r.policy.Limit,
		Remaining:   remaining,
		Reset:       time.Unix(0, resetNanos),
		RetryAfter:  time.Duration(retryAfterNanos),
		FullQuotaAt: time.Unix(0, fullQuotaAtNanos),
		Duration:    r.policy.Duration,
		Policy:      r.policy,
	}, nil
}

// GetAvailable returns the available tokens for the given key without consuming
// For GCRA, we use a Lua script to compute remaining without updating state
func (r *RedisLimiter) GetAvailable(ctx context.Context, key string) (int64, error) {
	now := r.clock.Now()
	emissionInterval := r.policy.EmissionInterval()
	burstAllowance := r.policy.BurstAllowance()

	fullKey := r.keyPrefix + key

	// Get current TAT from Redis
	tatBytes, err := r.client.Get(ctx, fullKey).Bytes()
	if err == redis.Nil {
		// No previous request - full burst capacity available
		return r.policy.Burst, nil
	} else if err != nil {
		return 0, fmt.Errorf("redis get failed: %w", err)
	}

	tatNanos, err := strconv.ParseInt(string(tatBytes), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("failed to parse TAT: %w", err)
	}

	tat := time.Unix(0, tatNanos)

	// Calculate remaining capacity without modifying TAT
	remaining := calculateRemainingGCRA(tat, now, emissionInterval, burstAllowance, r.policy.Burst)
	return remaining, nil
}

// Close closes the Redis connection
// Safe to call multiple times
func (r *RedisLimiter) Close() error {
	var err error
	r.closeOnce.Do(func() {
		err = r.client.Close()
	})
	return err
}

// calculateRemainingGCRA computes how many requests can still be made
// Formula: remaining = burst - ceil((tat - now) / emissionInterval)
func calculateRemainingGCRA(tat, now time.Time, emissionInterval, burstAllowance time.Duration, burst int64) int64 {
	if tat.Before(now) || tat.Equal(now) {
		// All burst capacity available
		return burst
	}

	usedBurst := tat.Sub(now)
	if usedBurst > burstAllowance {
		return 0
	}

	remaining := burst - int64(math.Ceil(float64(usedBurst)/float64(emissionInterval)))
	if remaining < 0 {
		return 0
	}

	return remaining
}
