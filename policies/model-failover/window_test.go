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
	"testing"
	"time"
)

// An unmeasured sample must not drag the percentile down.
//
// Only the attempt that produced the response in hand has a latency of its own. The earlier
// attempts of a failover were never timed individually, and recording them as 0 would make the
// p95 of a slow target look fast — the mirror of the bug this replaced, where they were recorded
// as the WHOLE request's duration and made a fast target look slow.
func TestRollingWindow_PercentileIgnoresUnmeasuredSamples(t *testing.T) {
	now := time.Now()
	w := newRollingWindow(time.Minute)

	for i := 0; i < 3; i++ {
		w.add(now, false, 900*time.Millisecond)
	}
	measuredOnly := w.percentile(now, 0.95)
	if measuredOnly < 800*time.Millisecond {
		t.Fatalf("p95 of three 900ms samples = %s, want ~900ms", measuredOnly)
	}

	// MANY more unmeasured than measured, deliberately: with only a few of them the p95 index
	// still lands on a measured sample and the test would pass whether or not they are
	// excluded. At this ratio, counting them as 0 drags the p95 to 0.
	for i := 0; i < 60; i++ {
		w.add(now, true, unknownLatency)
	}
	if got := w.percentile(now, 0.95); got != measuredOnly {
		t.Fatalf("unmeasured samples changed p95: %s -> %s; a duration nobody observed is not evidence",
			measuredOnly, got)
	}
}

// A window holding ONLY unmeasured samples has no percentile to report.
func TestRollingWindow_PercentileIsZeroWhenNothingWasMeasured(t *testing.T) {
	now := time.Now()
	w := newRollingWindow(time.Minute)
	for i := 0; i < 10; i++ {
		w.add(now, true, unknownLatency)
	}
	if got := w.percentile(now, 0.95); got != 0 {
		t.Fatalf("p95 = %s with nothing measured, want 0", got)
	}
}

// An unmeasured sample still counts for the ERROR RATE — it is a failure that happened, even
// though nobody timed it.
func TestRollingWindow_UnmeasuredSamplesStillCountAsFailures(t *testing.T) {
	now := time.Now()
	w := newRollingWindow(time.Minute)
	for i := 0; i < 5; i++ {
		w.add(now, true, unknownLatency)
	}
	for i := 0; i < 5; i++ {
		w.add(now, false, 10*time.Millisecond)
	}
	total, failures := w.counts(now)
	if total != 10 || failures != 5 {
		t.Fatalf("counts = %d failures of %d, want 5 of 10 — an untimed failure is still a failure",
			failures, total)
	}
}
