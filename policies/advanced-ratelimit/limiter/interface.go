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

package limiter

import (
	"context"
	"time"
)

// Limiter is the main rate limiter interface (common to all algorithms)
type Limiter interface {
	// Allow checks if a request is allowed for the given key
	// Returns a Result with rate limit information
	Allow(ctx context.Context, key string) (*Result, error)

	// AllowN checks if N requests are allowed for the given key
	AllowN(ctx context.Context, key string, n int64) (*Result, error)

	// ConsumeOrClampN consumes up to N tokens atomically.
	// If N exceeds available capacity, it consumes the available remainder (clamps to zero)
	// and returns a denied result with overflow details in Result.
	ConsumeOrClampN(ctx context.Context, key string, n int64) (*Result, error)

	// GetAvailable returns the available tokens for the given key without consuming
	// This is useful for checking remaining capacity before making a request
	GetAvailable(ctx context.Context, key string) (int64, error)

	// Close cleans up limiter resources
	Close() error
}

// CostTracker is an optional interface that limiters can implement to support
// accurate post-response cost tracking. ConsumeN always records the full cost
// even if it exceeds the limit, unlike ConsumeOrClampN which clamps to remaining
// capacity. Callers should check for this interface via type assertion.
type CostTracker interface {
	// ConsumeN always consumes N tokens regardless of whether it exceeds the limit.
	// This is used for post-response cost extraction where the upstream has already
	// processed the request and the actual cost must be recorded accurately.
	ConsumeN(ctx context.Context, key string, n int64) (*Result, error)
}

// LimitConfig is algorithm-agnostic limit configuration
type LimitConfig struct {
	Limit    int64
	Duration time.Duration
	Burst    int64 // Optional, interpretation depends on algorithm
}
