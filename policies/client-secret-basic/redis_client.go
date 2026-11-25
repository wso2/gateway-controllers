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

package clientsecretbasic

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

// csbRedisConnKey identifies a unique Redis connection configuration. Two policy
// instances with identical settings share one *redis.Client (one pool).
type csbRedisConnKey struct {
	addr               string
	username           string
	passwordHash       string
	db                 int
	dialTimeout        time.Duration
	readTimeout        time.Duration
	writeTimeout       time.Duration
	poolSize           int
	tlsEnabled         bool
	tlsInsecureSkip    bool
	tlsCAFile          string
	tlsServerName      string
	tlsCertFile        string
	tlsKeyFile         string
}

var csbRedisClients = struct {
	mu sync.Mutex
	m  map[csbRedisConnKey]*redis.Client
}{m: make(map[csbRedisConnKey]*redis.Client)}

func csbHashPassword(p string) string {
	if p == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(p))
	return hex.EncodeToString(sum[:])
}

// csbBuildTLSConfig constructs a *tls.Config from the given TLS params.
// Returns nil when tlsEnabled is false.
func csbBuildTLSConfig(enabled bool, caFile, serverName, certFile, keyFile string, insecureSkip bool) (*tls.Config, error) {
	if !enabled {
		return nil, nil
	}
	cfg := &tls.Config{
		InsecureSkipVerify: insecureSkip, //nolint:gosec
		ServerName:         serverName,
	}
	if caFile != "" {
		pem, err := os.ReadFile(caFile) //nolint:gosec
		if err != nil {
			return nil, fmt.Errorf("client-secret-basic: reading Redis CA file %q: %w", caFile, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("client-secret-basic: no valid certificates found in Redis CA file %q", caFile)
		}
		cfg.RootCAs = pool
	}
	if certFile != "" || keyFile != "" {
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, fmt.Errorf("client-secret-basic: loading Redis TLS client certificate: %w", err)
		}
		cfg.Certificates = []tls.Certificate{cert}
	}
	return cfg, nil
}

// getOrCreateCsbRedisClient returns the shared Redis client for these connection
// settings, creating (and pinging once) it on first use. The client lives for the
// process lifetime and is never closed. created is true only on the first call for
// this config; pingErr is non-nil only when the initial ping failed on creation.
func getOrCreateCsbRedisClient(opts *redis.Options, key csbRedisConnKey, pingTimeout time.Duration) (client *redis.Client, created bool, pingErr error) {
	csbRedisClients.mu.Lock()
	defer csbRedisClients.mu.Unlock()

	if c, ok := csbRedisClients.m[key]; ok {
		return c, false, nil
	}

	c := redis.NewClient(opts)
	csbRedisClients.m[key] = c

	ctx, cancel := context.WithTimeout(context.Background(), pingTimeout)
	defer cancel()
	pingErr = c.Ping(ctx).Err()
	return c, true, pingErr
}
