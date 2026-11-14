/*
 *  Copyright (c) 2026, WSO2 LLC. (https://www.wso2.com).
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
 */

package modelfailover

import (
	"fmt"
	"testing"
	"time"
)

// Above the size threshold, a write must not sweep every time.
//
// Entries live for correlationTTL, so a busy route stays above the threshold indefinitely and the
// unbounded version rescanned the same mostly-live entries on every write — an O(1) write turned
// O(n) for as long as traffic continued.
func TestRemember_DoesNotSweepOnEveryWriteAboveTheThreshold(t *testing.T) {
	now := time.Now()
	c := &attemptCorrelation{entries: map[string]correlationEntry{}, now: func() time.Time { return now }}

	// Fill past the threshold with entries that are already expired, so a sweep is visible as
	// a drop in size.
	for i := 0; i < correlationSweepThreshold+10; i++ {
		c.entries[fmt.Sprintf("old-%d", i)] = correlationEntry{expires: now.Add(-time.Minute)}
	}
	before := len(c.entries)

	chain := []Target{{Model: "gpt-4o"}}
	clusters := map[string]string{"": "cluster_default"}
	c.Remember("req-a", chain, nil, clusters)
	swept := len(c.entries)
	if swept >= before {
		t.Fatalf("the first write above the threshold must sweep: %d -> %d", before, swept)
	}

	// Refill and write again at the SAME instant: the interval has not elapsed, so no sweep.
	for i := 0; i < correlationSweepThreshold+10; i++ {
		c.entries[fmt.Sprintf("old2-%d", i)] = correlationEntry{expires: now.Add(-time.Minute)}
	}
	refilled := len(c.entries)
	c.Remember("req-b", chain, nil, clusters)
	if len(c.entries) < refilled {
		t.Fatalf("a second write within the interval swept again: %d -> %d", refilled, len(c.entries))
	}

	// Past the interval, it sweeps again.
	now = now.Add(correlationSweepInterval + time.Second)
	c.Remember("req-c", chain, nil, clusters)
	if len(c.entries) >= refilled {
		t.Fatalf("no sweep after the interval elapsed: %d -> %d", refilled, len(c.entries))
	}
}
