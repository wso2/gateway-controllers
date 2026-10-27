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
	jobs := []Job{{"low", 1}, {"high-a", 5}, {"middle", 3}, {"high-b", 5}}
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
