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
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/wso2/api-platform/tests/framework/core/catalog"
	"github.com/wso2/api-platform/tests/framework/core/components"
	"github.com/wso2/api-platform/tests/framework/core/topology"
)

// gauge tracks how many jobs run at the same time.
type gauge struct {
	mu      sync.Mutex
	current int
	peak    int
}

func (g *gauge) enter() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.current++
	g.peak = max(g.peak, g.current)
}

func (g *gauge) leave() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.current--
}

func names(count int) []Job {
	jobs := make([]Job, count)
	for i := range jobs {
		jobs[i] = Job{Name: fmt.Sprintf("job-%02d", i)}
	}
	return jobs
}

func TestScheduleRunsEveryJobOnceWithinTheLimit(t *testing.T) {
	var g gauge
	var mu sync.Mutex
	ran := map[string]int{}

	failed := Schedule(names(20), 4, func(job Job) error {
		g.enter()
		defer g.leave()
		time.Sleep(5 * time.Millisecond)
		mu.Lock()
		ran[job.Name]++
		mu.Unlock()
		return nil
	})

	if len(failed) != 0 {
		t.Fatalf("failed = %v, want none", failed)
	}
	if g.peak > 4 {
		t.Fatalf("peak = %d jobs at once, want at most 4", g.peak)
	}
	if g.peak < 4 {
		t.Fatalf("peak = %d jobs at once, want the limit of 4 to be reached", g.peak)
	}
	for _, job := range names(20) {
		if ran[job.Name] != 1 {
			t.Errorf("job %s ran %d times, want once", job.Name, ran[job.Name])
		}
	}
}

func TestScheduleStartsTheNextJobAsSoonAsAnyJobEnds(t *testing.T) {
	jobs := []Job{{Name: "short"}, {Name: "long-1"}, {Name: "long-2"}, {Name: "late"}}
	started := make(chan string, len(jobs))
	release := make(chan struct{})

	done := make(chan []string)
	go func() {
		done <- Schedule(jobs, 3, func(job Job) error {
			started <- job.Name
			if job.Name != "short" {
				<-release
			}
			return nil
		})
	}()

	seen := map[string]bool{}
	for range jobs {
		select {
		case name := <-started:
			seen[name] = true
		case <-time.After(5 * time.Second):
			t.Fatalf("started %v while the long jobs still held two slots, want all four", seen)
		}
	}
	close(release)
	<-done
	if !seen["late"] {
		t.Fatal("the job behind the limit never started before the long jobs ended")
	}
}

func TestScheduleGivesEveryJobTheNumberOfTheLaneThatRunsIt(t *testing.T) {
	var mu sync.Mutex
	slots := map[int][]string{}
	Schedule(names(30), 4, func(job Job) error {
		time.Sleep(time.Millisecond)
		mu.Lock()
		slots[job.Slot] = append(slots[job.Slot], job.Name)
		mu.Unlock()
		return nil
	})

	total := 0
	for slot, ran := range slots {
		if slot < 1 || slot > 4 {
			t.Errorf("a job ran on lane %d, want 1 to 4", slot)
		}
		total += len(ran)
	}
	if total != 30 {
		t.Fatalf("%d jobs ran, want 30", total)
	}
}

func TestScheduleRunsOnlyOneJobAtATimeOnALane(t *testing.T) {
	var mu sync.Mutex
	active := map[int]int{}
	overlapped := false
	Schedule(names(24), 3, func(job Job) error {
		mu.Lock()
		active[job.Slot]++
		overlapped = overlapped || active[job.Slot] > 1
		mu.Unlock()
		time.Sleep(2 * time.Millisecond)
		mu.Lock()
		active[job.Slot]--
		mu.Unlock()
		return nil
	})
	if overlapped {
		t.Fatal("a lane ran two jobs at the same time")
	}
}

func TestScheduleRunsJobsOneAtATimeWhenTheLimitIsBelowOne(t *testing.T) {
	for _, limit := range []int{0, -3} {
		var g gauge
		Schedule(names(4), limit, func(Job) error {
			g.enter()
			defer g.leave()
			time.Sleep(5 * time.Millisecond)
			return nil
		})
		if g.peak != 1 {
			t.Fatalf("limit %d: peak = %d jobs at once, want 1", limit, g.peak)
		}
	}
}

func TestScheduleStartsTheHighestPriorityFirst(t *testing.T) {
	jobs := []Job{{Name: "low", Priority: 1}, {Name: "high-a", Priority: 5}, {Name: "middle", Priority: 3}, {Name: "high-b", Priority: 5}}
	var order []string
	Schedule(jobs, 1, func(job Job) error {
		order = append(order, job.Name)
		return nil
	})
	if want := []string{"high-a", "high-b", "middle", "low"}; !reflect.DeepEqual(order, want) {
		t.Fatalf("order = %v, want %v", order, want)
	}
}

func TestScheduleReturnsTheFailedJobsInNameOrder(t *testing.T) {
	jobs := []Job{{Name: "c"}, {Name: "a"}, {Name: "b"}, {Name: "d"}}
	failed := Schedule(jobs, 4, func(job Job) error {
		if job.Name == "d" {
			return nil
		}
		return errors.New("boom")
	})
	if want := []string{"a", "b", "c"}; !reflect.DeepEqual(failed, want) {
		t.Fatalf("failed = %v, want %v", failed, want)
	}
}

func TestScheduleHandlesNoJobsAndAnOversizedLimit(t *testing.T) {
	if failed := Schedule(nil, 3, func(Job) error { return errors.New("never") }); len(failed) != 0 {
		t.Fatalf("failed = %v, want none", failed)
	}
	var g gauge
	Schedule(names(2), 50, func(Job) error {
		g.enter()
		defer g.leave()
		time.Sleep(5 * time.Millisecond)
		return nil
	})
	if g.peak > 2 {
		t.Fatalf("peak = %d jobs at once, want at most the 2 jobs there are", g.peak)
	}
}

const suiteFile = `suite: sample
defaults:
  parallel: 1
  components:
    platform-gateway:
      db: sqlite
      dbCompatibility:
        sqlserver: "gateway-version>=1.2.0"
blocks:
  - name: first
    parallel: 1
    components:
      - name: platform-gateway
        db:
          matrix: [sqlite, postgres, sqlserver]
      - name: testbench
    runners:
      - name: one
        features:
          - features/one.feature
      - name: two
        features:
          - features/two.feature
  - name: second
    parallel: 1
    components:
      - name: platform-gateway
        db:
          matrix: [sqlite, postgres, sqlserver]
      - name: testbench
    runners:
      - name: only
        features:
          - features/only.feature
`

const gatedSuiteFile = `suite: gated
defaults:
  parallel: 1
  components:
    platform-gateway:
      db: sqlite
blocks:
  - name: gated
    parallel: 1
    components:
      - name: platform-gateway
      - name: testbench
    runners:
      - name: newer
        tags: "gateway-version>=1.2.0"
        features:
          - features/newer.feature
`

func registry(t *testing.T) *components.Registry {
	t.Helper()
	r, err := catalog.Registry()
	if err != nil {
		t.Fatalf("building the component registry: %v", err)
	}
	return r
}

func writeSuite(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "it-suite.yaml")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("writing the suite file: %v", err)
	}
	return path
}

func blockNames(blocks []Block) []string {
	out := make([]string, len(blocks))
	for i, block := range blocks {
		out[i] = block.Name
	}
	slices.Sort(out)
	return out
}

func TestBlocksExpandTheDatabaseMatrixAndDropExcludedVariants(t *testing.T) {
	path := writeSuite(t, suiteFile)
	tests := []struct {
		name      string
		selection topology.Selection
		want      []string
	}{
		{"current release", topology.Selection{GatewayVersion: "1.2.0"},
			[]string{"first/postgres", "first/sqlite", "first/sqlserver", "second/postgres", "second/sqlite", "second/sqlserver"}},
		{"release without sqlserver", topology.Selection{GatewayVersion: "1.1.0"},
			[]string{"first/postgres", "first/sqlite", "second/postgres", "second/sqlite"}},
		{"latest", topology.Selection{GatewayVersion: "latest"},
			[]string{"first/postgres", "first/sqlite", "first/sqlserver", "second/postgres", "second/sqlite", "second/sqlserver"}},
		{"one variant", topology.Selection{GatewayVersion: "1.2.0", Blocks: []string{"first/sqlite"}},
			[]string{"first/sqlite"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			blocks, err := Blocks(registry(t), path, tt.selection)
			if err != nil {
				t.Fatalf("Blocks: %v", err)
			}
			if got := blockNames(blocks); !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("blocks = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestBlocksCountTheRunnersOfEachBlock(t *testing.T) {
	blocks, err := Blocks(registry(t), writeSuite(t, suiteFile), topology.Selection{GatewayVersion: "1.2.0", Blocks: []string{"first/sqlite", "second/sqlite"}})
	if err != nil {
		t.Fatalf("Blocks: %v", err)
	}
	runners := map[string]int{}
	for _, block := range blocks {
		runners[block.Name] = block.Runners
	}
	if want := map[string]int{"first/sqlite": 2, "second/sqlite": 1}; !reflect.DeepEqual(runners, want) {
		t.Fatalf("runners = %v, want %v", runners, want)
	}
}

func TestBlocksOfASuiteTheGatewayVersionExcludesAreEmpty(t *testing.T) {
	blocks, err := Blocks(registry(t), writeSuite(t, gatedSuiteFile), topology.Selection{GatewayVersion: "1.1.0"})
	if err != nil {
		t.Fatalf("Blocks: %v", err)
	}
	if len(blocks) != 0 {
		t.Fatalf("blocks = %v, want none", blocks)
	}
	if blocks, err = Blocks(registry(t), writeSuite(t, gatedSuiteFile), topology.Selection{GatewayVersion: "1.2.0"}); err != nil || len(blocks) != 1 {
		t.Fatalf("blocks = %v, error = %v, want the one block on 1.2.0", blocks, err)
	}
}

func TestBlocksReportAnUnreadableSuite(t *testing.T) {
	if _, err := Blocks(registry(t), filepath.Join(t.TempDir(), "missing.yaml"), topology.Selection{}); err == nil {
		t.Fatal("Blocks of a missing file returned no error")
	}
	if _, err := Blocks(registry(t), writeSuite(t, "not: [a suite"), topology.Selection{}); err == nil {
		t.Fatal("Blocks of a malformed file returned no error")
	}
}

func TestLineWriterPrefixesWholeLinesAndHoldsAPartialLine(t *testing.T) {
	var out bytes.Buffer
	var mu sync.Mutex
	w := NewLineWriter(&out, &mu, "[a] ")

	if _, err := w.Write([]byte("one\ntwo")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if got, want := out.String(), "[a] one\n"; got != want {
		t.Fatalf("after the first write = %q, want %q", got, want)
	}
	if _, err := w.Write([]byte(" more\nthree\n")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if got, want := out.String(), "[a] one\n[a] two more\n[a] three\n"; got != want {
		t.Fatalf("after the second write = %q, want %q", got, want)
	}
}

func TestLineWriterFlushEndsAnUnfinishedLine(t *testing.T) {
	var out bytes.Buffer
	var mu sync.Mutex
	w := NewLineWriter(&out, &mu, "> ")
	if err := w.Flush(); err != nil || out.Len() != 0 {
		t.Fatalf("Flush of nothing wrote %q, error %v", out.String(), err)
	}
	w.Write([]byte("tail"))
	if err := w.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if got, want := out.String(), "> tail\n"; got != want {
		t.Fatalf("output = %q, want %q", got, want)
	}
}

func TestLineWritersSharingAMutexNeverSplitALine(t *testing.T) {
	var out bytes.Buffer
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, prefix := range []string{"[a] ", "[b] ", "[c] "} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			w := NewLineWriter(&out, &mu, prefix)
			for range 200 {
				w.Write([]byte("a whole line of output\n"))
			}
		}()
	}
	wg.Wait()

	lines := strings.Split(strings.TrimSuffix(out.String(), "\n"), "\n")
	if len(lines) != 600 {
		t.Fatalf("got %d lines, want 600", len(lines))
	}
	for _, line := range lines {
		if line != "[a] a whole line of output" && line != "[b] a whole line of output" && line != "[c] a whole line of output" {
			t.Fatalf("a line was split or mixed: %q", line)
		}
	}
}

func TestRecorderOrdersBlocksByStartAndReportsTheRun(t *testing.T) {
	r := NewRecorder()
	now := time.Now()
	r.Block(2, "cors", "cors/postgres", now.Add(20*time.Millisecond), true)
	r.Block(1, "basic-auth", "basic-auth/sqlite", now.Add(-10*time.Millisecond), false)
	r.Compile("cors", now, true)
	r.Compile("basic-auth", now, false)
	r.Skip("jwt-auth")
	r.Skip("auth-a")

	timeline := r.Timeline("1.2.0", 7, 190.4)

	if timeline.SchemaVersion != TimelineSchema || timeline.GatewayVersion != "1.2.0" || timeline.BlockParallel != 7 || timeline.BuildSeconds != 190.4 {
		t.Fatalf("timeline header = %+v", timeline)
	}
	if got := []string{timeline.Blocks[0].Block, timeline.Blocks[1].Block}; !reflect.DeepEqual(got, []string{"basic-auth/sqlite", "cors/postgres"}) {
		t.Fatalf("blocks = %v, want them in the order they started", got)
	}
	if timeline.Blocks[0].Slot != 1 || timeline.Blocks[1].Slot != 2 {
		t.Fatalf("slots = %d %d, want 1 then 2", timeline.Blocks[0].Slot, timeline.Blocks[1].Slot)
	}
	if timeline.Blocks[0].Passed || !timeline.Blocks[1].Passed {
		t.Fatalf("results = %v %v, want the failed one first", timeline.Blocks[0].Passed, timeline.Blocks[1].Passed)
	}
	if timeline.Compiles[0].Policy != "basic-auth" || timeline.Compiles[1].Policy != "cors" {
		t.Fatalf("compiles = %+v, want them in name order", timeline.Compiles)
	}
	if want := []string{"auth-a", "jwt-auth"}; !reflect.DeepEqual(timeline.Skipped, want) {
		t.Fatalf("skipped = %v, want %v", timeline.Skipped, want)
	}
	if timeline.WallMs < 0 {
		t.Fatalf("wall = %d ms, want it not to be negative", timeline.WallMs)
	}
}

func TestRecorderIsSafeForConcurrentUse(t *testing.T) {
	r := NewRecorder()
	var wg sync.WaitGroup
	for i := range 50 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r.Block(i%3+1, "p", fmt.Sprintf("p/%d", i), time.Now(), true)
			r.Compile("p", time.Now(), true)
		}()
	}
	wg.Wait()
	timeline := r.Timeline("latest", 3, 0)
	if len(timeline.Blocks) != 50 || len(timeline.Compiles) != 50 {
		t.Fatalf("recorded %d blocks and %d compiles, want 50 of each", len(timeline.Blocks), len(timeline.Compiles))
	}
}

func TestWriteTimelineWritesTheJSONTheRendererReads(t *testing.T) {
	r := NewRecorder()
	r.Block(1, "cors", "cors/sqlite", time.Now(), true)
	path := filepath.Join(t.TempDir(), "timeline.json")

	if err := WriteTimeline(path, r.Timeline("1.1.0", 4, 0)); err != nil {
		t.Fatalf("WriteTimeline: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading the timeline: %v", err)
	}
	var fields map[string]any
	if err := json.Unmarshal(data, &fields); err != nil {
		t.Fatalf("the timeline is not JSON: %v", err)
	}
	for _, key := range []string{"schemaVersion", "gatewayVersion", "blockParallel", "wallMs", "cores", "blocks", "compiles", "skipped", "samples"} {
		if _, ok := fields[key]; !ok {
			t.Errorf("the timeline has no %q", key)
		}
	}
	if _, ok := fields["buildSeconds"]; ok {
		t.Error("an unknown build time should be left out")
	}
	block := fields["blocks"].([]any)[0].(map[string]any)
	for _, key := range []string{"slot", "policy", "block", "startMs", "durationMs", "passed"} {
		if _, ok := block[key]; !ok {
			t.Errorf("a block has no %q", key)
		}
	}
	if err := WriteTimeline(filepath.Join(t.TempDir(), "missing", "timeline.json"), Timeline{}); err == nil {
		t.Error("WriteTimeline into a missing folder returned no error")
	}
}

const procStatSample = "cpu  100 10 50 800 40 5 5 0 0 0\ncpu0 50 5 25 400 20 2 3 0 0 0\nintr 1 2 3\n"

func TestReadCPUCountsEverythingButIdleAndWaitingAsBusy(t *testing.T) {
	got, err := readCPU(strings.NewReader(procStatSample))
	if err != nil {
		t.Fatalf("readCPU: %v", err)
	}
	if got.total != 1010 || got.busy != 170 {
		t.Fatalf("readCPU = %+v, want total 1010 and busy 170", got)
	}
}

func TestReadCPURejectsWhatIsNotAProcessorLine(t *testing.T) {
	for name, input := range map[string]string{
		"empty":      "",
		"other line": "intr 1 2 3 4 5 6\n",
		"too short":  "cpu 1 2\n",
		"not number": "cpu 1 2 3 x 5\n",
	} {
		if _, err := readCPU(strings.NewReader(input)); err == nil {
			t.Errorf("%s: readCPU returned no error", name)
		}
	}
}

func TestCPUPercentIsTheBusyShareBetweenTwoReadings(t *testing.T) {
	before := cpuTimes{busy: 170, total: 1010}
	if got := cpuPercent(before, cpuTimes{busy: 270, total: 1210}); got != 50 {
		t.Fatalf("cpuPercent = %v, want 50", got)
	}
	if got := cpuPercent(before, before); got != 0 {
		t.Fatalf("cpuPercent of an unchanged reading = %v, want 0", got)
	}
	if got := cpuPercent(before, cpuTimes{busy: 100, total: 900}); got != 0 {
		t.Fatalf("cpuPercent of a reading that went back = %v, want 0", got)
	}
}

func TestReadMemoryReturnsTheTotalAndTheAvailableMegabytes(t *testing.T) {
	total, available, err := readMemory(strings.NewReader("MemTotal:       16384000 kB\nMemFree: 1 kB\nMemAvailable:    8192000 kB\nBuffers: 5 kB\n"))
	if err != nil {
		t.Fatalf("readMemory: %v", err)
	}
	if total != 16000 || available != 8000 {
		t.Fatalf("readMemory = %d, %d, want 16000 and 8000", total, available)
	}
}

func TestReadMemoryRejectsIncompleteInformation(t *testing.T) {
	for name, input := range map[string]string{
		"empty":             "",
		"no available line": "MemTotal: 1024 kB\n",
		"no value":          "MemTotal:\nMemAvailable: 1 kB\n",
		"not a number":      "MemTotal: x kB\nMemAvailable: 1 kB\n",
	} {
		if _, _, err := readMemory(strings.NewReader(input)); err == nil {
			t.Errorf("%s: readMemory returned no error", name)
		}
	}
}

func writeProc(t *testing.T, stat string, availableKB int) (statPath, meminfoPath string) {
	t.Helper()
	dir := t.TempDir()
	statPath = filepath.Join(dir, "stat")
	meminfoPath = filepath.Join(dir, "meminfo")
	if err := os.WriteFile(statPath, []byte(stat), 0o644); err != nil {
		t.Fatalf("writing the processor file: %v", err)
	}
	meminfo := fmt.Sprintf("MemTotal: 16384000 kB\nMemAvailable: %d kB\n", availableKB)
	if err := os.WriteFile(meminfoPath, []byte(meminfo), 0o644); err != nil {
		t.Fatalf("writing the memory file: %v", err)
	}
	return statPath, meminfoPath
}

func TestTakeSampleReportsTheLoadSinceTheLastReading(t *testing.T) {
	statPath, meminfoPath := writeProc(t, procStatSample, 8192000)
	_, first, err := takeSample(statPath, meminfoPath, cpuTimes{}, 0)
	if err != nil {
		t.Fatalf("takeSample: %v", err)
	}
	if err := os.WriteFile(statPath, []byte("cpu  200 10 50 900 40 5 5 0 0 0\n"), 0o644); err != nil {
		t.Fatalf("writing the processor file: %v", err)
	}

	sample, _, err := takeSample(statPath, meminfoPath, first, 5*time.Second)
	if err != nil {
		t.Fatalf("takeSample: %v", err)
	}
	if sample.AtMs != 5000 || sample.CPUPercent != 50 || sample.MemUsedMB != 8000 || sample.MemTotalMB != 16000 {
		t.Fatalf("sample = %+v, want 5000 ms, 50%%, 8000 of 16000 MB", sample)
	}
}

func TestTakeSampleReportsAnUnreadableFile(t *testing.T) {
	statPath, meminfoPath := writeProc(t, procStatSample, 1)
	missing := filepath.Join(t.TempDir(), "missing")
	if _, _, err := takeSample(missing, meminfoPath, cpuTimes{}, 0); err == nil {
		t.Error("a missing processor file returned no error")
	}
	if _, _, err := takeSample(statPath, missing, cpuTimes{}, 0); err == nil {
		t.Error("a missing memory file returned no error")
	}
}

func TestRecorderSamplesTheMachineUntilStopped(t *testing.T) {
	statPath, meminfoPath := writeProc(t, procStatSample, 8192000)
	r := NewRecorder()
	stop := r.startSampling(statPath, meminfoPath, 5*time.Millisecond)

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		r.mu.Lock()
		count := len(r.samples)
		r.mu.Unlock()
		if count >= 3 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	stop()
	timeline := r.Timeline("1.2.0", 4, 0)
	if len(timeline.Samples) < 3 {
		t.Fatalf("recorded %d samples, want at least 3", len(timeline.Samples))
	}
	for i := 1; i < len(timeline.Samples); i++ {
		if timeline.Samples[i].AtMs < timeline.Samples[i-1].AtMs {
			t.Fatalf("samples are not in time order: %+v", timeline.Samples)
		}
	}
	if timeline.Cores < 1 {
		t.Fatalf("cores = %d, want at least 1", timeline.Cores)
	}

	count := len(timeline.Samples)
	time.Sleep(30 * time.Millisecond)
	if after := len(r.Timeline("1.2.0", 4, 0).Samples); after != count {
		t.Fatalf("sampling went on after stop: %d samples became %d", count, after)
	}
}

func TestRecorderRecordsNothingWhereTheMachineCannotBeRead(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing")
	r := NewRecorder()
	stop := r.startSampling(missing, missing, time.Millisecond)
	time.Sleep(10 * time.Millisecond)
	stop()
	if samples := r.Timeline("1.2.0", 1, 0).Samples; len(samples) != 0 {
		t.Fatalf("samples = %v, want none", samples)
	}
}
