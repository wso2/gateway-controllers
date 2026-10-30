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

package runsuites

import (
	"encoding/json"
	"os"
	"runtime"
	"sort"
	"sync"
	"time"
)

// TimelineSchema is the version of the timeline file layout.
const TimelineSchema = 1

// Timeline is the record of one run: how long each block took and when it started.
type Timeline struct {
	SchemaVersion  int        `json:"schemaVersion"`
	GatewayVersion string     `json:"gatewayVersion"`
	BlockParallel  int        `json:"blockParallel"`
	BuildSeconds   float64    `json:"buildSeconds,omitempty"`
	WallMs         int64      `json:"wallMs"`
	Cores          int        `json:"cores"`
	Blocks         []BlockRun `json:"blocks"`
	Compiles       []Compile  `json:"compiles"`
	Skipped        []string   `json:"skipped"`
	Samples        []Sample   `json:"samples"`
}

// BlockRun is one block of a suite and how long it ran, and the lane (Slot, from 1) that ran it.
// The time of a policy's first blocks includes the wait for its test binary to compile.
type BlockRun struct {
	Slot       int    `json:"slot"`
	Policy     string `json:"policy"`
	Block      string `json:"block"`
	StartMs    int64  `json:"startMs"`
	DurationMs int64  `json:"durationMs"`
	Passed     bool   `json:"passed"`
}

// Compile is the time it took to compile the test binary of a policy.
type Compile struct {
	Policy     string `json:"policy"`
	DurationMs int64  `json:"durationMs"`
	Passed     bool   `json:"passed"`
}

// Recorder collects the timings of a run. It is safe for concurrent use.
type Recorder struct {
	mu       sync.Mutex
	start    time.Time
	blocks   []BlockRun
	compiles []Compile
	skipped  []string
	samples  []Sample
}

// NewRecorder starts the clock of a run.
func NewRecorder() *Recorder {
	return &Recorder{start: time.Now()}
}

// Block records a block that lane slot ran, which began at started and ended now.
func (r *Recorder) Block(slot int, policy, block string, started time.Time, passed bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.blocks = append(r.blocks, BlockRun{
		Slot:       slot,
		Policy:     policy,
		Block:      block,
		StartMs:    started.Sub(r.start).Milliseconds(),
		DurationMs: time.Since(started).Milliseconds(),
		Passed:     passed,
	})
}

// Compile records the compilation of a policy's test binary that began at started and ended now.
func (r *Recorder) Compile(policy string, started time.Time, passed bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.compiles = append(r.compiles, Compile{Policy: policy, DurationMs: time.Since(started).Milliseconds(), Passed: passed})
}

// Skip records a suite the selected gateway version leaves nothing to run.
func (r *Recorder) Skip(policy string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.skipped = append(r.skipped, policy)
}

// Timeline returns what the run recorded so far, with the blocks in the order they started.
func (r *Recorder) Timeline(gatewayVersion string, blockParallel int, buildSeconds float64) Timeline {
	r.mu.Lock()
	defer r.mu.Unlock()
	blocks := append([]BlockRun{}, r.blocks...)
	sort.SliceStable(blocks, func(i, j int) bool { return blocks[i].StartMs < blocks[j].StartMs })
	compiles := append([]Compile{}, r.compiles...)
	sort.Slice(compiles, func(i, j int) bool { return compiles[i].Policy < compiles[j].Policy })
	skipped := append([]string{}, r.skipped...)
	sort.Strings(skipped)
	samples := append([]Sample{}, r.samples...)
	return Timeline{
		SchemaVersion:  TimelineSchema,
		GatewayVersion: gatewayVersion,
		BlockParallel:  blockParallel,
		BuildSeconds:   buildSeconds,
		WallMs:         time.Since(r.start).Milliseconds(),
		Blocks:         blocks,
		Compiles:       compiles,
		Skipped:        skipped,
		Cores:          runtime.NumCPU(),
		Samples:        samples,
	}
}

// WriteTimeline writes timeline to path as JSON.
func WriteTimeline(path string, timeline Timeline) error {
	data, err := json.MarshalIndent(timeline, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o644)
}
