/*
 * Copyright (c) 2026, WSO2 LLC. (https://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package costbasedrouting

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"math"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
	_ "github.com/wso2/gateway-controllers/policies/advanced-ratelimit/algorithms/fixedwindow" // register fixed-window
	_ "github.com/wso2/gateway-controllers/policies/advanced-ratelimit/algorithms/gcra"        // register GCRA
	"github.com/wso2/gateway-controllers/policies/advanced-ratelimit/limiter"
)

// budgetState is the typed outcome of a pre-request budget query. It exists so
// that a storage failure is never mistaken for genuine budget exhaustion: those
// two cases take different routing decisions.
type budgetState int

const (
	// budgetAvailable means the primary model still has spending capacity.
	budgetAvailable budgetState = iota
	// budgetExhausted means every configured window reports zero capacity, or
	// at least one of them does. This is a routing signal, never a 429.
	budgetExhausted
	// budgetUnknown means the storage backend could not be queried.
	budgetUnknown
)

func (s budgetState) String() string {
	switch s {
	case budgetAvailable:
		return "available"
	case budgetExhausted:
		return "exhausted"
	default:
		return "unknown"
	}
}

// budgetStore wraps a shared advanced-ratelimit limiter with the two operations
// this policy needs: a non-consuming capacity query before routing, and an
// unconditional cost charge after the upstream response completes.
//
// Both operations come from the published advanced-ratelimit contract —
// limiter.Limiter.GetAvailable and limiter.CostTracker.ConsumeN — so no
// independent budget storage is introduced here.
type budgetStore struct {
	lim      limiter.Limiter
	tracker  limiter.CostTracker
	backend  string
	failOpen bool
}

// Query reports whether the primary budget has capacity left. It never consumes
// quota, so the returned state reflects spending recorded by *previous*
// requests only — the cost of the current request is not known until its
// response completes.
func (b *budgetStore) Query(ctx context.Context, key string) (budgetState, int64, error) {
	available, err := b.lim.GetAvailable(ctx, key)
	if err != nil {
		return budgetUnknown, 0, err
	}
	if available <= 0 {
		return budgetExhausted, available, nil
	}
	return budgetAvailable, available, nil
}

// Charge records n scaled units against the budget. ConsumeN deliberately
// records the full amount even when it exceeds the remaining capacity, so the
// request that crosses the limit is accounted for accurately and the *next*
// request sees an exhausted budget.
func (b *budgetStore) Charge(ctx context.Context, key string, n int64) error {
	if n <= 0 {
		return nil
	}
	if b.tracker == nil {
		return fmt.Errorf("budget storage does not support post-response cost tracking")
	}
	_, err := b.tracker.ConsumeN(ctx, key, n)
	return err
}

// newBudgetStore builds (or reuses) the storage for one budgeted route.
func newBudgetStore(cfg config, route costRoute, metadata policy.PolicyMetadata) (*budgetStore, error) {
	limits := make([]limiter.LimitConfig, len(route.BudgetLimits))
	for i, budget := range route.BudgetLimits {
		limits[i] = limiter.LimitConfig{
			Limit:    budget.Scaled,
			Duration: budget.Duration,
			// GCRA treats Burst as the accumulated capacity. Matching it to the
			// limit keeps a full window's budget spendable in one burst, which
			// is what a monetary budget means.
			Burst: budget.Scaled,
		}
	}

	// GCRA has no local-async implementation. Its cost query and charge paths
	// are synchronous anyway, so treat redis-local-async as Redis rather than
	// allowing the GCRA factory to fall through to its memory backend.
	effectiveBackend := cfg.Backend
	if cfg.Algorithm == "gcra" && cfg.Backend == "redis-local-async" {
		effectiveBackend = "redis"
	}

	limiterConfig := limiter.Config{
		Algorithm:       cfg.Algorithm,
		Limits:          limits,
		Backend:         effectiveBackend,
		KeyPrefix:       cfg.Redis.KeyPrefix,
		CleanupInterval: cfg.MemoryCleanupInterval,
	}

	if cfg.Backend == "redis" || cfg.Backend == "redis-local-async" {
		client, created, pingErr := getOrCreateRedisClient(&redis.Options{
			Addr:         fmt.Sprintf("%s:%d", cfg.Redis.Host, cfg.Redis.Port),
			Username:     cfg.Redis.Username,
			Password:     cfg.Redis.Password,
			DB:           cfg.Redis.DB,
			DialTimeout:  cfg.Redis.ConnectionTimeout,
			ReadTimeout:  cfg.Redis.ReadTimeout,
			WriteTimeout: cfg.Redis.WriteTimeout,
			PoolSize:     cfg.Redis.PoolSize,
		}, cfg.Redis.ConnectionTimeout)
		// Fail fast only when this call created the client and it could not
		// connect; a reused client is assumed healthy because go-redis
		// reconnects lazily.
		if created && pingErr != nil {
			if !cfg.Redis.FailOpen {
				return nil, fmt.Errorf("redis connection failed and redis.failureMode is closed: %w", pingErr)
			}
			slog.Warn("CostBasedRouting: redis connection failed but redis.failureMode is open",
				"route", metadata.RouteName, "error", pingErr)
		}
		limiterConfig.RedisClient = client
		if cfg.Backend == "redis-local-async" {
			limiterConfig.AlgorithmConfig = map[string]interface{}{
				"syncInterval":        cfg.Local.SyncInterval,
				"failOpen":            cfg.Redis.FailOpen,
				"flushWorkers":        cfg.Local.FlushWorkers,
				"maxPipelineCommands": cfg.Local.MaxPipelineCommands,
				"maxLocalEntries":     cfg.Local.MaxLocalEntries,
			}
		}
	}

	var (
		lim limiter.Limiter
		err error
	)
	if effectiveBackend == "redis" {
		// Redis holds the counters, so every instance can build its own view.
		lim, err = limiter.CreateLimiter(limiterConfig)
	} else {
		// memory and redis-local-async keep per-process state (and, for
		// redis-local-async, a flusher goroutine), so instances that share a
		// configuration must share one limiter. Otherwise a config reload would
		// silently reset the budget or leak a goroutine.
		lim, err = sharedLimiter(cacheKeyFor(cfg, route, metadata), reconcileKeyFor(metadata, route), limiterConfig)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to create budget storage: %w", err)
	}

	tracker, _ := lim.(limiter.CostTracker)
	if tracker == nil {
		return nil, fmt.Errorf("budget storage for algorithm %q does not support post-response cost tracking", cfg.Algorithm)
	}

	return &budgetStore{
		lim:      lim,
		tracker:  tracker,
		backend:  cfg.Backend,
		failOpen: cfg.Backend == "memory" || cfg.Redis.FailOpen,
	}, nil
}

// budgetKey builds the storage key for a request. Without consumerBased the
// route shares one budget; with it, each application gets an independent one.
// Requests that carry no application id share the consumerFallbackID scope
// rather than escaping the budget altogether.
func budgetKey(namespace string, consumerBased bool, metadata map[string]interface{}) string {
	if !consumerBased {
		return namespace
	}
	applicationID := consumerFallbackID
	if raw, ok := metadata[applicationIDMetadataKey]; ok {
		if value, ok := raw.(string); ok && value != "" {
			applicationID = value
		}
	}
	return namespace + ":" + applicationID
}

// budgetNamespaceFor isolates persistent counters belonging to different APIs,
// attachment levels, and budget configurations. Route names are only unique
// within their API context, while a Redis key prefix is commonly shared by the
// whole gateway deployment.
func budgetNamespaceFor(metadata policy.PolicyMetadata, cfg config, route costRoute) string {
	var builder strings.Builder
	if metadata.APIId != "" {
		builder.WriteString("api-id=")
		builder.WriteString(metadata.APIId)
	} else {
		builder.WriteString("api-name=")
		builder.WriteString(metadata.APIName)
	}
	builder.WriteString("|api-version=")
	builder.WriteString(metadata.APIVersion)
	builder.WriteString("|route=")
	builder.WriteString(metadata.RouteName)
	builder.WriteString("|attached-to=")
	builder.WriteString(string(metadata.AttachedTo))
	builder.WriteString("|cost-route=")
	builder.WriteString(route.Name)
	builder.WriteString("|target-model=")
	builder.WriteString(route.Target.Model)
	builder.WriteString("|target-provider=")
	builder.WriteString(route.Target.Provider)
	builder.WriteString("|algorithm=")
	builder.WriteString(cfg.Algorithm)
	builder.WriteString("|consumer-based=")
	builder.WriteString(strconv.FormatBool(cfg.ConsumerBased))
	builder.WriteString("|scale=")
	builder.WriteString(strconv.FormatInt(cfg.CostScaleFactor, 10))
	for _, budget := range route.BudgetLimits {
		builder.WriteString("|limit=")
		builder.WriteString(strconv.FormatInt(budget.Scaled, 10))
		builder.WriteString("@")
		builder.WriteString(budget.Duration.String())
	}
	sum := sha256.Sum256([]byte(builder.String()))
	return "cbr:" + hex.EncodeToString(sum[:])
}

// scaleCost converts a dollar cost reported by llm-cost into the integer unit
// used by the storage backend. A value large enough to overflow int64 is
// clamped rather than dropped, so an implausible cost still exhausts the budget
// instead of being silently ignored.
func scaleCost(cost float64, scaleFactor int64) (int64, bool) {
	if math.IsNaN(cost) || math.IsInf(cost, 0) || cost < 0 {
		return 0, false
	}
	scaled := cost * float64(scaleFactor)
	if scaled >= float64(math.MaxInt64) {
		return math.MaxInt64, true
	}
	return int64(scaled), true
}

// parseReportedCost reads the cost published by the llm-cost system policy.
// It returns ok=false when the cost is absent, was not calculated, or is not a
// usable non-negative number — in every one of those cases the caller must skip
// the charge rather than guess, so a pricing gap can never exhaust the budget.
func parseReportedCost(metadata map[string]interface{}) (float64, string, bool) {
	status := ""
	if raw, ok := metadata[metadataLLMCostStatus]; ok {
		if value, ok := raw.(string); ok {
			status = value
		}
	}
	if status != "" && status != llmCostStatusCalculated {
		return 0, status, false
	}

	raw, exists := metadata[metadataLLMCost]
	if !exists {
		return 0, status, false
	}

	var cost float64
	switch value := raw.(type) {
	case string:
		parsed, err := strconv.ParseFloat(strings.TrimSpace(value), 64)
		if err != nil {
			return 0, status, false
		}
		cost = parsed
	case float64:
		cost = value
	case float32:
		cost = float64(value)
	case int:
		cost = float64(value)
	case int64:
		cost = float64(value)
	default:
		return 0, status, false
	}

	if math.IsNaN(cost) || math.IsInf(cost, 0) || cost < 0 {
		return 0, status, false
	}
	return cost, status, true
}

// ─── Shared limiter cache ────────────────────────────────────────────────────

type limiterEntry struct {
	lim      limiter.Limiter
	refCount int
}

// limiterCache keeps one limiter per distinct budget configuration so that
// per-process counters survive policy reloads. reconcile tracks which cache
// entry each policy instance currently holds, so a reconfigured instance
// releases (and closes) the limiter it used before.
var limiterCache = struct {
	mu        sync.Mutex
	entries   map[string]*limiterEntry
	reconcile map[string]string
}{
	entries:   make(map[string]*limiterEntry),
	reconcile: make(map[string]string),
}

func sharedLimiter(cacheKey, reconcileKey string, cfg limiter.Config) (limiter.Limiter, error) {
	limiterCache.mu.Lock()
	defer limiterCache.mu.Unlock()

	previousKey, hadPrevious := limiterCache.reconcile[reconcileKey]

	entry, exists := limiterCache.entries[cacheKey]
	if exists {
		if !hadPrevious || previousKey != cacheKey {
			entry.refCount++
		}
	} else {
		lim, err := limiter.CreateLimiter(cfg)
		if err != nil {
			return nil, err
		}
		entry = &limiterEntry{lim: lim, refCount: 1}
		limiterCache.entries[cacheKey] = entry
	}
	limiterCache.reconcile[reconcileKey] = cacheKey

	// Release the entry this instance held under a previous configuration.
	if hadPrevious && previousKey != cacheKey {
		if stale, ok := limiterCache.entries[previousKey]; ok {
			stale.refCount--
			if stale.refCount <= 0 {
				if err := stale.lim.Close(); err != nil {
					slog.Warn("CostBasedRouting: failed to close stale budget limiter", "error", err)
				}
				delete(limiterCache.entries, previousKey)
			}
		}
	}

	return entry.lim, nil
}

// cacheKeyFor identifies a distinct budget configuration. Two policy instances
// share storage only when their limits, algorithm, backend, and scope match.
func cacheKeyFor(cfg config, args ...interface{}) string {
	var route costRoute
	var metadata policy.PolicyMetadata
	switch len(args) {
	case 1:
		metadata = args[0].(policy.PolicyMetadata)
		if len(cfg.Routes) > 0 {
			route = cfg.Routes[0]
		} else {
			route = costRoute{Name: tierPrimary, Target: cfg.Primary, BudgetLimits: cfg.BudgetLimits}
		}
	case 2:
		route = args[0].(costRoute)
		metadata = args[1].(policy.PolicyMetadata)
	default:
		panic("cacheKeyFor requires metadata or route plus metadata")
	}

	var builder strings.Builder
	builder.WriteString(metadata.APIId)
	builder.WriteString("|")
	builder.WriteString(metadata.RouteName)
	builder.WriteString("|")
	builder.WriteString(metadata.APIName)
	builder.WriteString("|")
	builder.WriteString(metadata.APIVersion)
	builder.WriteString("|")
	builder.WriteString(cfg.Algorithm)
	builder.WriteString("|")
	builder.WriteString(cfg.Backend)
	builder.WriteString("|")
	builder.WriteString(strconv.FormatBool(cfg.ConsumerBased))
	builder.WriteString("|")
	builder.WriteString(strconv.FormatInt(cfg.CostScaleFactor, 10))
	builder.WriteString("|route-name=")
	builder.WriteString(route.Name)
	builder.WriteString("|target=")
	builder.WriteString(route.Target.Model)
	builder.WriteString("@")
	builder.WriteString(route.Target.Provider)
	if cfg.Backend == "memory" {
		builder.WriteString("|cleanup=")
		builder.WriteString(cfg.MemoryCleanupInterval.String())
	}
	if cfg.Backend == "redis-local-async" {
		builder.WriteString("|redis-prefix=")
		builder.WriteString(cfg.Redis.KeyPrefix)
		builder.WriteString("|redis-address=")
		builder.WriteString(cfg.Redis.Host)
		builder.WriteString(":")
		builder.WriteString(strconv.Itoa(cfg.Redis.Port))
		builder.WriteString("|redis-username=")
		builder.WriteString(cfg.Redis.Username)
		builder.WriteString("|redis-password=")
		builder.WriteString(hashRedisPassword(cfg.Redis.Password))
		builder.WriteString("|redis-db=")
		builder.WriteString(strconv.Itoa(cfg.Redis.DB))
		builder.WriteString("|redis-fail-open=")
		builder.WriteString(strconv.FormatBool(cfg.Redis.FailOpen))
		builder.WriteString("|redis-timeouts=")
		builder.WriteString(cfg.Redis.ConnectionTimeout.String())
		builder.WriteString(",")
		builder.WriteString(cfg.Redis.ReadTimeout.String())
		builder.WriteString(",")
		builder.WriteString(cfg.Redis.WriteTimeout.String())
		builder.WriteString("|redis-pool-size=")
		builder.WriteString(strconv.Itoa(cfg.Redis.PoolSize))
		builder.WriteString("|local=")
		builder.WriteString(cfg.Local.SyncInterval.String())
		builder.WriteString(",")
		builder.WriteString(strconv.Itoa(cfg.Local.FlushWorkers))
		builder.WriteString(",")
		builder.WriteString(strconv.Itoa(cfg.Local.MaxPipelineCommands))
		builder.WriteString(",")
		builder.WriteString(strconv.Itoa(cfg.Local.MaxLocalEntries))
	}
	for _, budget := range route.BudgetLimits {
		builder.WriteString("|")
		builder.WriteString(strconv.FormatInt(budget.Scaled, 10))
		builder.WriteString("@")
		builder.WriteString(budget.Duration.String())
	}
	sum := sha256.Sum256([]byte(builder.String()))
	return hex.EncodeToString(sum[:])
}

// reconcileKeyFor identifies one policy instance across reloads. An API-level
// and an operation-level attachment on the same route are distinct instances
// and must not evict each other's limiter.
func reconcileKeyFor(metadata policy.PolicyMetadata, route costRoute) string {
	return metadata.APIId + "|" + metadata.RouteName + "|" + metadata.APIName + "|" + metadata.APIVersion + "|" + string(metadata.AttachedTo) + "|" + route.Name
}

// ─── Shared Redis clients ────────────────────────────────────────────────────

type redisConnKey struct {
	addr         string
	username     string
	passwordHash string // sha256 hex; keeps the secret out of the in-process map key
	db           int
	dialTimeout  time.Duration
	readTimeout  time.Duration
	writeTimeout time.Duration
	poolSize     int
}

// redisClients is the process-wide registry of shared Redis clients. Without it
// every policy instance and every config reload would build a fresh connection
// pool, leaking pools and exploding Redis connections at scale.
var redisClients = struct {
	mu sync.Mutex
	m  map[redisConnKey]*redis.Client
}{m: make(map[redisConnKey]*redis.Client)}

func hashRedisPassword(password string) string {
	if password == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(password))
	return hex.EncodeToString(sum[:])
}

// getOrCreateRedisClient returns the process-wide shared client for these
// connection settings, creating (and pinging once) it on first use. created
// reports whether this call created the client; pingErr is non-nil only when
// created and the initial ping failed. The client is registered and returned
// even on ping failure because go-redis reconnects lazily.
func getOrCreateRedisClient(opts *redis.Options, pingTimeout time.Duration) (client *redis.Client, created bool, pingErr error) {
	key := redisConnKey{
		addr:         opts.Addr,
		username:     opts.Username,
		passwordHash: hashRedisPassword(opts.Password),
		db:           opts.DB,
		dialTimeout:  opts.DialTimeout,
		readTimeout:  opts.ReadTimeout,
		writeTimeout: opts.WriteTimeout,
		poolSize:     opts.PoolSize,
	}

	redisClients.mu.Lock()
	defer redisClients.mu.Unlock()

	if existing, ok := redisClients.m[key]; ok {
		return existing, false, nil
	}

	created_ := redis.NewClient(opts)
	redisClients.m[key] = created_

	if pingTimeout <= 0 {
		pingTimeout = 5 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), pingTimeout)
	defer cancel()
	pingErr = created_.Ping(ctx).Err()
	return created_, true, pingErr
}
