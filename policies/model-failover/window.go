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

package modelfailover

import (
	"sort"
	"time"
)

// maxWindowSamples bounds the memory one target's window can hold. A busy target would
// otherwise accumulate an unbounded slice between evictions. When full, the oldest sample is
// dropped: the window is a recent-behaviour estimate, not an audit log.
const maxWindowSamples = 4096

type windowSample struct {
	at      time.Time
	failure bool
	latency time.Duration
}

// rollingWindow holds recent request outcomes for one target, supporting the two aggregated
// suspension criteria: error rate and latency percentile.
//
// Samples expire by TIME, not by count. That distinction matters: a count-based window on a
// quiet target would keep failures from hours ago alive and suspend it long after it
// recovered.
type rollingWindow struct {
	duration time.Duration
	samples  []windowSample
}

func newRollingWindow(duration time.Duration) *rollingWindow {
	if duration <= 0 {
		duration = time.Duration(DefaultWindowSeconds) * time.Second
	}
	return &rollingWindow{duration: duration}
}

func (w *rollingWindow) add(now time.Time, failure bool, latency time.Duration) {
	w.evict(now)
	if len(w.samples) >= maxWindowSamples {
		w.samples = w.samples[1:]
	}
	w.samples = append(w.samples, windowSample{at: now, failure: failure, latency: latency})
}

// evict drops samples older than the window. Samples are appended in time order, so the
// expired ones are always a prefix.
func (w *rollingWindow) evict(now time.Time) {
	cutoff := now.Add(-w.duration)
	i := 0
	for i < len(w.samples) && w.samples[i].at.Before(cutoff) {
		i++
	}
	if i > 0 {
		w.samples = w.samples[i:]
	}
}

// counts returns the total and failing sample counts within the window.
//
// A window with no requests returns (0, 0). The caller must treat that as "rate undefined"
// rather than "rate zero" — and the minimum-sample-size check does exactly that, since 0 is
// never >= a minimum of at least 1.
func (w *rollingWindow) counts(now time.Time) (total, failures int) {
	w.evict(now)
	for _, s := range w.samples {
		total++
		if s.failure {
			failures++
		}
	}
	return total, failures
}

// percentile returns the requested latency percentile across the window, or 0 when there are
// no samples.
//
// This is what separates "one unusually slow request" from "this target has become slow". A
// single outlier barely moves p95; a target whose p95 has tripled is degrading even while
// every individual request still completes under the per-attempt timeout (FR-018e, FR-018f).
func (w *rollingWindow) percentile(now time.Time, q float64) time.Duration {
	w.evict(now)
	if len(w.samples) == 0 {
		return 0
	}

	latencies := make([]time.Duration, 0, len(w.samples))
	for _, s := range w.samples {
		latencies = append(latencies, s.latency)
	}
	sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })

	idx := int(float64(len(latencies)-1) * q)
	if idx < 0 {
		idx = 0
	}
	if idx >= len(latencies) {
		idx = len(latencies) - 1
	}
	return latencies[idx]
}

// reset clears the window. Called when a target is suspended or returns to service, so a
// recovered target is judged on fresh evidence rather than the failures that suspended it.
func (w *rollingWindow) reset() {
	w.samples = w.samples[:0]
}
