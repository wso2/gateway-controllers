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

// Package common contains reusable integration-suite step mechanics.
package common

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"strings"
	"sync"

	"github.com/wso2/api-platform/tests/framework/core/util/tcontext"
	"github.com/wso2/api-platform/tests/framework/core/util/unique"
)

var configureExpansion sync.Once

// ConfigureExpansion installs context-backed expansion for suite placeholders.
func ConfigureExpansion() {
	configureExpansion.Do(func() {
		unique.ContextValue = func(ctx context.Context, name string) (string, error) {
			return tcontext.ResolveString(ctx, name)
		}
	})
}

// Expand resolves unique-name and context-value placeholders in a suite value.
func Expand(ctx context.Context, value string) (string, error) {
	ConfigureExpansion()
	return unique.Expand(ctx, value)
}

// GenerateAndStore creates a unique value and stores it in the runner's local scope.
func GenerateAndStore(ctx context.Context, base, key string) error {
	return generateAndStore(ctx, key, func() (string, error) {
		return unique.Unique(ctx, base)
	})
}

// GenerateResourceAndStore creates a unique name accepted by DNS-style resource APIs.
func GenerateResourceAndStore(ctx context.Context, base, key string) error {
	return generateAndStore(ctx, key, func() (string, error) {
		value, err := unique.Unique(ctx, base)
		if err != nil {
			return "", err
		}
		return strings.ToLower(strings.ReplaceAll(value, "_", "-")), nil
	})
}

// GenerateAPIVersionAndStore stores a unique semantic API version.
func GenerateAPIVersionAndStore(ctx context.Context, base, key string) error {
	return generateAndStore(ctx, key, func() (string, error) {
		value, err := unique.Unique(ctx, base)
		if err != nil {
			return "", err
		}
		checksum := sha256.Sum256([]byte(value))
		patch := binary.BigEndian.Uint64(checksum[:8])%999999 + 1
		return fmt.Sprintf("v1.0.%d", patch), nil
	})
}

// GenerateContextAndStore creates a unique API context and stores it in runner-local scope.
func GenerateContextAndStore(ctx context.Context, base, key string) error {
	return generateAndStore(ctx, key, func() (string, error) {
		return unique.UniqueContext(ctx, base)
	})
}

// maxPayloadKiB bounds a generated payload so a mistyped size cannot exhaust the runner's memory.
const maxPayloadKiB = 10 * 1024

// payloadPattern is repeated to fill a generated payload. It is plain ASCII, so the payload's
// size in bytes equals its length, and it needs no escaping inside a JSON string.
const payloadPattern = "0123456789abcdefghijklmnopqrstuvwxyz"

// GeneratePayloadAndStore stores a deterministic ASCII payload of exactly kib KiB in the runner's
// local scope. The same size always yields the same payload, so a scenario can assert values
// derived from it, such as its hash.
func GeneratePayloadAndStore(ctx context.Context, kib int, key string) error {
	return generateAndStore(ctx, key, func() (string, error) {
		if kib <= 0 || kib > maxPayloadKiB {
			return "", fmt.Errorf("payload size must be between 1 and %d KiB, got %d", maxPayloadKiB, kib)
		}
		size := kib * 1024
		return strings.Repeat(payloadPattern, size/len(payloadPattern)+1)[:size], nil
	})
}

func generateAndStore(ctx context.Context, key string, generate func() (string, error)) error {
	key = strings.TrimSpace(key)
	if key == "" {
		return fmt.Errorf("cannot store a generated value with an empty key")
	}
	local, ok := tcontext.LocalOf(ctx)
	if !ok || local == nil {
		return fmt.Errorf("cannot store generated value %q without runner context", key)
	}
	value, err := generate()
	if err != nil {
		return err
	}
	local.Set(key, value)
	return nil
}

// MaxRepeatedKiB is the largest value GenerateRepeatedAndStore builds.
const MaxRepeatedKiB = 1024

// GenerateRepeatedAndStore stores exactly kib KiB of fill, repeated, under key, so a scenario can
// use an oversized value without writing it out.
func GenerateRepeatedAndStore(ctx context.Context, kib int, fill, key string) error {
	return generateAndStore(ctx, key, func() (string, error) {
		return Repeated(kib, fill)
	})
}

// Repeated returns exactly kib KiB of fill, repeated and cut to size.
func Repeated(kib int, fill string) (string, error) {
	if kib <= 0 || kib > MaxRepeatedKiB {
		return "", fmt.Errorf("the generated value must be between 1 and %d KiB, got %d", MaxRepeatedKiB, kib)
	}
	if fill == "" {
		return "", fmt.Errorf("the generated value's fill must not be empty")
	}
	size := kib * 1024
	return strings.Repeat(fill, size/len(fill)+1)[:size], nil
}

// StoredValue returns a generated or otherwise runner-scoped string value.
func StoredValue(ctx context.Context, key string) (string, error) {
	return tcontext.ResolveString(ctx, key)
}
