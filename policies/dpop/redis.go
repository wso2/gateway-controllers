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
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package dpop

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/wso2/gateway-controllers/policies/advanced-ratelimit/redistls"
)

const (
	replayStoreMemory = "memory"
	replayStoreRedis  = "redis"

	// redisFailureClosed refuses DPoP requests while Redis cannot be reached;
	// redisFailureLocal also records every proof in this replica's memory, and
	// relies on that record alone while Redis cannot be reached.
	redisFailureClosed = "closed"
	redisFailureLocal  = "local"
)

// replayChecker records proof identifiers. replayStore (one replica's memory) and
// redisReplayStore (shared by every replica) implement it.
type replayChecker interface {
	checkAndStore(ctx context.Context, key [32]byte, expiry, now time.Time) replayResult
}

// setNXer is the one Redis command the replay store needs; *redis.Client implements it.
type setNXer interface {
	SetNX(ctx context.Context, key string, value interface{}, expiration time.Duration) *redis.BoolCmd
}

// redisReplayStore records proof identifiers in Redis, so a proof accepted by one
// gateway replica is refused by every other one. SET NX with an expiry is a single
// atomic command: of two concurrent copies of a proof, on any replicas, exactly one
// is stored.
type redisReplayStore struct {
	client      setNXer
	prefix      string
	failureMode string
	local       *replayStore
}

// checkAndStore records the proof key in Redis with SET NX and an expiry, following failureMode when Redis fails.
func (r *redisReplayStore) checkAndStore(ctx context.Context, key [32]byte, expiry, now time.Time) replayResult {
	// In local mode the replica also keeps its own record of every proof it accepts,
	// whether Redis is up or not, so its history stays continuous: a proof accepted
	// before an outage is still refused during it, and one accepted during an
	// outage is still refused after Redis returns.
	// The local record is required, not best effort: a proof accepted without it
	// could be replayed on this replica during a later outage, so a full record
	// refuses the request, as the memory store does.
	localResult := replayStored
	if r.failureMode == redisFailureLocal {
		if localResult = r.local.checkAndStore(ctx, key, expiry, now); localResult != replayStored {
			return localResult
		}
	}

	ttl := expiry.Sub(now)
	if ttl < time.Millisecond {
		ttl = time.Millisecond
	}
	stored, err := r.client.SetNX(ctx, r.prefix+hex.EncodeToString(key[:]), 1, ttl).Result()
	if err == nil {
		if stored {
			return replayStored
		}
		return replaySeen
	}
	warnEvery("redis-unavailable", now, "dpop: cannot record proof identifiers in Redis",
		slog.String("failureMode", r.failureMode), slog.String("error", err.Error()))
	if r.failureMode == redisFailureLocal {
		return localResult
	}
	return replayUnavailable
}

// redisConfig mirrors the dpop redis system parameters.
type redisConfig struct {
	host, username, password, keyPrefix, failureMode string
	port, db, poolSize                               int
	connectionTimeout, readTimeout, writeTimeout     time.Duration
	tls                                              redistls.Config
}

// newReplayChecker builds the replay store the system parameters select.
func newReplayChecker(params map[string]interface{}, maxSize int) (replayChecker, error) {
	kind, err := stringParam(params, "replayStore", replayStoreMemory)
	if err != nil {
		return nil, err
	}
	local := sharedReplayStore(maxSize)
	switch kind {
	case replayStoreMemory:
		return local, nil
	case replayStoreRedis:
	default:
		return nil, fmt.Errorf("replayStore must be %q or %q, got %q", replayStoreMemory, replayStoreRedis, kind)
	}

	raw, _ := params["redis"].(map[string]interface{})
	rc, err := parseRedisConfig(raw)
	if err != nil {
		return nil, err
	}
	tlsConfig, tlsFingerprint, err := rc.tls.Build()
	if err != nil {
		return nil, err
	}
	if rc.tls.Enabled && rc.tls.InsecureSkipVerify {
		warnEvery("redis-tls-insecure", time.Now(), "dpop: redis.tls.insecureSkipVerify is on; the Redis server certificate is not verified")
	}
	opts := &redis.Options{
		Addr:         net.JoinHostPort(rc.host, strconv.Itoa(rc.port)),
		Username:     rc.username,
		Password:     rc.password,
		DB:           rc.db,
		DialTimeout:  rc.connectionTimeout,
		ReadTimeout:  rc.readTimeout,
		WriteTimeout: rc.writeTimeout,
		PoolSize:     rc.poolSize,
		TLSConfig:    tlsConfig,
	}
	client, created, pingErr := sharedRedisClient(opts, tlsFingerprint, rc.connectionTimeout)
	if created && pingErr != nil {
		warnEvery("redis-unreachable-at-start:"+opts.Addr, time.Now(), "dpop: Redis replay store is not reachable yet; requests follow failureMode until it is",
			slog.String("addr", opts.Addr), slog.String("failureMode", rc.failureMode), slog.String("error", pingErr.Error()))
	}
	return &redisReplayStore{client: client, prefix: rc.keyPrefix, failureMode: rc.failureMode, local: local}, nil
}

// parseRedisConfig reads the redis system parameters, applying the documented defaults.
func parseRedisConfig(raw map[string]interface{}) (redisConfig, error) {
	if raw == nil {
		raw = map[string]interface{}{}
	}
	rc := redisConfig{}
	var err error
	if rc.host, err = stringParam(raw, "host", "localhost"); err != nil {
		return rc, fmt.Errorf("redis.%w", err)
	}
	if rc.port, err = intParam(raw, "port", 6379); err != nil {
		return rc, fmt.Errorf("redis.%w", err)
	}
	if rc.port < 1 || rc.port > 65535 {
		return rc, fmt.Errorf("redis.port must be between 1 and 65535")
	}
	if rc.username, err = stringParam(raw, "username", ""); err != nil {
		return rc, fmt.Errorf("redis.%w", err)
	}
	if rc.password, err = stringParam(raw, "password", ""); err != nil {
		return rc, fmt.Errorf("redis.%w", err)
	}
	if rc.db, err = intParam(raw, "db", 0); err != nil {
		return rc, fmt.Errorf("redis.%w", err)
	}
	if rc.keyPrefix, err = stringParam(raw, "keyPrefix", "dpop:v0:"); err != nil {
		return rc, fmt.Errorf("redis.%w", err)
	}
	if rc.failureMode, err = stringParam(raw, "failureMode", redisFailureClosed); err != nil {
		return rc, fmt.Errorf("redis.%w", err)
	}
	if rc.failureMode != redisFailureClosed && rc.failureMode != redisFailureLocal {
		return rc, fmt.Errorf("redis.failureMode must be %q or %q, got %q", redisFailureClosed, redisFailureLocal, rc.failureMode)
	}
	if rc.connectionTimeout, err = durationParam(raw, "connectionTimeout", 5*time.Second); err != nil {
		return rc, fmt.Errorf("redis.%w", err)
	}
	if rc.readTimeout, err = durationParam(raw, "readTimeout", time.Second); err != nil {
		return rc, fmt.Errorf("redis.%w", err)
	}
	if rc.writeTimeout, err = durationParam(raw, "writeTimeout", time.Second); err != nil {
		return rc, fmt.Errorf("redis.%w", err)
	}
	if rc.poolSize, err = intParam(raw, "poolSize", 0); err != nil {
		return rc, fmt.Errorf("redis.%w", err)
	}

	tlsRaw, _ := raw["tls"].(map[string]interface{})
	if tlsRaw == nil {
		tlsRaw = map[string]interface{}{}
	}
	if rc.tls.Enabled, err = boolParam(tlsRaw, "enabled", false); err != nil {
		return rc, fmt.Errorf("redis.tls.%w", err)
	}
	if rc.tls.InsecureSkipVerify, err = boolParam(tlsRaw, "insecureSkipVerify", false); err != nil {
		return rc, fmt.Errorf("redis.tls.%w", err)
	}
	for key, dst := range map[string]*string{
		"caFile": &rc.tls.CAFile, "serverName": &rc.tls.ServerName,
		"certFile": &rc.tls.CertFile, "keyFile": &rc.tls.KeyFile,
	} {
		if *dst, err = stringParam(tlsRaw, key, ""); err != nil {
			return rc, fmt.Errorf("redis.tls.%w", err)
		}
	}
	return rc, nil
}

// redisClientKey identifies a distinct Redis connection configuration, so policy
// instances with the same settings share one client and its connection pool.
type redisClientKey struct {
	addr, username, passwordHash, tlsFingerprint string
	db, poolSize                                 int
	dialTimeout, readTimeout, writeTimeout       time.Duration
}

var redisClients = struct {
	mu sync.Mutex
	m  map[redisClientKey]*redis.Client
}{m: make(map[redisClientKey]*redis.Client)}

// sharedRedisClient returns the process-wide client for these settings, creating and
// pinging it once on first use. Without the registry every policy instance, and every
// configuration reload, would open a new connection pool. Clients live for the process.
func sharedRedisClient(opts *redis.Options, tlsFingerprint string, pingTimeout time.Duration) (*redis.Client, bool, error) {
	passwordHash := ""
	if opts.Password != "" {
		sum := sha256.Sum256([]byte(opts.Password))
		passwordHash = hex.EncodeToString(sum[:])
	}
	key := redisClientKey{
		addr: opts.Addr, username: opts.Username, passwordHash: passwordHash, tlsFingerprint: tlsFingerprint,
		db: opts.DB, poolSize: opts.PoolSize,
		dialTimeout: opts.DialTimeout, readTimeout: opts.ReadTimeout, writeTimeout: opts.WriteTimeout,
	}
	redisClients.mu.Lock()
	defer redisClients.mu.Unlock()
	if c, ok := redisClients.m[key]; ok {
		return c, false, nil
	}
	c := redis.NewClient(opts)
	redisClients.m[key] = c
	ctx, cancel := context.WithTimeout(context.Background(), pingTimeout)
	defer cancel()
	return c, true, c.Ping(ctx).Err()
}
