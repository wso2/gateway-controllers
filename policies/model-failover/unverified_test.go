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

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

func headersWith(pairs map[string][]string) *policy.Headers {
	return policy.NewHeaders(pairs)
}

// A streamed response commits its status before the body exists, so the status is not
// evidence the target served the request.
func TestIsProvisionalStatus_DetectsStreamedResponses(t *testing.T) {
	cases := []struct {
		name    string
		headers map[string][]string
		want    bool
	}{
		{"sse", map[string][]string{"content-type": {"text/event-stream"}}, true},
		{"sse with charset", map[string][]string{"content-type": {"text/event-stream; charset=utf-8"}}, true},
		{"chunked", map[string][]string{"transfer-encoding": {"chunked"}}, true},
		{"plain json", map[string][]string{"content-type": {"application/json"}}, false},
		{"no headers at all", map[string][]string{}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := &policy.ResponseHeaderContext{ResponseHeaders: headersWith(tc.headers)}
			if got := isProvisionalStatus(ctx); got != tc.want {
				t.Fatalf("isProvisionalStatus = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestIsProvisionalStatus_NilSafe(t *testing.T) {
	if isProvisionalStatus(nil) {
		t.Error("a nil context must not be treated as provisional")
	}
	if isProvisionalStatus(&policy.ResponseHeaderContext{}) {
		t.Error("a context with no headers must not be treated as provisional")
	}
}

// THE POINT OF THE WHOLE CHANGE. A provider that truncates everything AND fails outright
// some of the time is, today, shielded from suspension by the truncations: each one resets
// the consecutive-failure count and adds a healthy sample that dilutes the error rate.
//
// Recording the truncations as nothing leaves only the real failures, which suspend it.
func TestRecordUnverified_DoesNotShieldATargetFromItsRealFailures(t *testing.T) {
	store := NewHealthStore(testSuspension()) // ConsecutiveFailures: 3
	now := time.Now()

	// Two real failures with a truncated "success" between them, twice over. If the
	// provisional outcome counted as a success, the counter would never reach three.
	for i := 0; i < 2; i++ {
		store.RecordFailure(targetA, 0, now)
		store.RecordUnverified(targetA, now)
	}
	if ev := store.RecordFailure(targetA, 0, now); ev == nil {
		t.Fatal("the third real failure must suspend: a provisional outcome must not " +
			"reset the consecutive-failure count, which is what lets a truncating " +
			"provider immunise itself against its own failures")
	}
}

// The same immunity, via the other criterion: a provisional outcome must not add a healthy
// sample to the rolling window, or the error rate is diluted below the threshold.
func TestRecordUnverified_DoesNotDiluteTheErrorRateWindow(t *testing.T) {
	s := testSuspension()
	s.ConsecutiveFailures = 0 // isolate the rate rule
	s.clamp()
	store := NewHealthStore(s) // ErrorRatePercent 50, MinimumRequests 20
	now := time.Now()

	// 20 real failures, interleaved with 40 truncations. Counted as successes that is a
	// 33% error rate -- under the threshold. Counted as nothing it is 100%.
	var suspended bool
	for i := 0; i < 20; i++ {
		if ev := store.RecordFailure(targetA, 0, now); ev != nil {
			suspended = true
		}
		store.RecordUnverified(targetA, now)
		store.RecordUnverified(targetA, now)
	}
	if !suspended {
		t.Fatal("the rate rule must fire: provisional outcomes must not enter the window " +
			"as healthy samples")
	}
}

// The carve-out. Without it a target whose responses are all streamed could satisfy no
// recovery rule and would stay suspended permanently -- trading a false-success bug for a
// false-suspension one.
func TestRecordUnverified_StillAdvancesProbeRecovery(t *testing.T) {
	s := testSuspension()
	s.clamp()
	s.RecoverAfterSuccesses = 2 // after clamp, so the clamp cannot put a default back
	store := NewHealthStore(s)
	now := time.Now()

	// Three failures suspend it for the 30s base duration.
	var suspension *SuspensionEvent
	for i := 0; i < 3; i++ {
		if ev := store.RecordFailure(targetA, 0, now); ev != nil {
			suspension = ev
		}
	}
	if suspension == nil {
		t.Fatal("precondition: three failures should have suspended the target")
	}

	// Past the window. Asserted by driving the store rather than by reading Healthy,
	// which ADMITS a probe rather than merely reporting -- using it here would consume
	// the very slot the test is about.
	later := now.Add(31 * time.Second)

	if ev := store.RecordUnverified(targetA, later); ev != nil {
		t.Fatal("one probe must not complete a two-probe recovery run")
	}
	if ev := store.RecordUnverified(targetA, later); ev == nil {
		t.Fatal("a streamed response must still count toward recovery, or a target that " +
			"only ever streams can never come back")
	}
}
