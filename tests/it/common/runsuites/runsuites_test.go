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
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/wso2/api-platform/tests/framework/core/catalog"
	"github.com/wso2/api-platform/tests/framework/core/components"
	"github.com/wso2/api-platform/tests/framework/core/topology"
)

// load tracks the weight of the jobs running at the same time.
type load struct {
	mu      sync.Mutex
	current int
	peak    int
}

func (l *load) enter(weight int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.current += weight
	l.peak = max(l.peak, l.current)
}

func (l *load) leave(weight int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.current -= weight
}

func TestScheduleKeepsTheRunningWeightWithinTheLimit(t *testing.T) {
	jobs := []Job{{"a", 3}, {"b", 3}, {"c", 2}, {"d", 2}, {"e", 1}, {"f", 1}}
	var l load
	ran := map[string]int{}
	var ranMu sync.Mutex

	failed := Schedule(jobs, 4, func(job Job) error {
		l.enter(job.Weight)
		defer l.leave(job.Weight)
		time.Sleep(20 * time.Millisecond)
		ranMu.Lock()
		ran[job.Name]++
		ranMu.Unlock()
		return nil
	})

	if len(failed) != 0 {
		t.Fatalf("failed = %v, want none", failed)
	}
	if l.peak > 4 {
		t.Fatalf("peak weight = %d, want at most 4", l.peak)
	}
	for _, job := range jobs {
		if ran[job.Name] != 1 {
			t.Errorf("job %s ran %d times, want once", job.Name, ran[job.Name])
		}
	}
}

func TestScheduleRunsEveryJobAtOnceWhenTheyFit(t *testing.T) {
	jobs := []Job{{"a", 3}, {"b", 2}, {"c", 1}}
	started := make(chan string, len(jobs))
	release := make(chan struct{})

	done := make(chan []string)
	go func() {
		done <- Schedule(jobs, 6, func(job Job) error {
			started <- job.Name
			<-release
			return nil
		})
	}()

	for range jobs {
		select {
		case <-started:
		case <-time.After(5 * time.Second):
			t.Fatal("the jobs did not all start while the others were still running")
		}
	}
	close(release)
	<-done
}

func TestScheduleRunsJobsOneAtATimeWithoutALimit(t *testing.T) {
	var l load
	jobs := []Job{{"a", 1}, {"b", 1}, {"c", 1}}
	Schedule(jobs, 0, func(job Job) error {
		l.enter(job.Weight)
		defer l.leave(job.Weight)
		time.Sleep(10 * time.Millisecond)
		return nil
	})
	if l.peak != 1 {
		t.Fatalf("peak weight = %d, want 1", l.peak)
	}
}

func TestScheduleClampsAJobHeavierThanTheLimit(t *testing.T) {
	var l load
	var seen []int
	var mu sync.Mutex
	Schedule([]Job{{"big", 10}, {"zero", 0}, {"negative", -3}}, 3, func(job Job) error {
		l.enter(job.Weight)
		defer l.leave(job.Weight)
		mu.Lock()
		seen = append(seen, job.Weight)
		mu.Unlock()
		time.Sleep(10 * time.Millisecond)
		return nil
	})
	if l.peak > 3 {
		t.Fatalf("peak weight = %d, want at most 3", l.peak)
	}
	for _, weight := range seen {
		if weight < 1 || weight > 3 {
			t.Errorf("a job ran with weight %d, want 1 to 3", weight)
		}
	}
}

func TestScheduleStartsTheHeaviestJobsFirstAndFillsTheRoomWithLighterOnes(t *testing.T) {
	var order []string
	var mu sync.Mutex
	Schedule([]Job{{"light", 1}, {"heavy", 3}, {"middle", 2}}, 3, func(job Job) error {
		mu.Lock()
		order = append(order, job.Name)
		mu.Unlock()
		return nil
	})
	if len(order) != 3 {
		t.Fatalf("ran %v, want all three", order)
	}
	if order[0] != "heavy" {
		t.Fatalf("started %v first, want heavy", order[0])
	}
}

func TestScheduleReturnsTheFailedJobsInNameOrder(t *testing.T) {
	jobs := []Job{{"c", 1}, {"a", 1}, {"b", 1}, {"d", 1}}
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

func TestScheduleWithNoJobsReturnsNothing(t *testing.T) {
	if failed := Schedule(nil, 3, func(Job) error { return errors.New("never") }); len(failed) != 0 {
		t.Fatalf("failed = %v, want none", failed)
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
      - name: first
        features:
          - features/first.feature
  - name: second
    parallel: 1
    components:
      - name: platform-gateway
        db:
          matrix: [sqlite, postgres, sqlserver]
      - name: testbench
    runners:
      - name: second
        features:
          - features/second.feature
`

func writeSuite(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "it-suite.yaml")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("writing the suite file: %v", err)
	}
	return path
}

func registry(t *testing.T) *components.Registry {
	t.Helper()
	r, err := catalog.Registry()
	if err != nil {
		t.Fatalf("building the component registry: %v", err)
	}
	return r
}

func TestBlockCountExpandsTheDatabaseMatrixAndDropsExcludedVariants(t *testing.T) {
	path := writeSuite(t, suiteFile)
	tests := []struct {
		name      string
		selection topology.Selection
		want      int
	}{
		{"current release", topology.Selection{GatewayVersion: "1.2.0"}, 6},
		{"release without sqlserver", topology.Selection{GatewayVersion: "1.1.0"}, 4},
		{"latest", topology.Selection{GatewayVersion: "latest"}, 6},
		{"one block's database", topology.Selection{GatewayVersion: "1.2.0", Blocks: []string{"first/sqlite"}}, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := BlockCount(registry(t), path, tt.selection)
			if err != nil {
				t.Fatalf("BlockCount: %v", err)
			}
			if got != tt.want {
				t.Fatalf("BlockCount = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestBlockCountReportsAnUnreadableSuite(t *testing.T) {
	if _, err := BlockCount(registry(t), filepath.Join(t.TempDir(), "missing.yaml"), topology.Selection{}); err == nil {
		t.Fatal("BlockCount of a missing file returned no error")
	}
	if _, err := BlockCount(registry(t), writeSuite(t, "not: [a suite"), topology.Selection{}); err == nil {
		t.Fatal("BlockCount of a malformed file returned no error")
	}
}

func TestBlockCountReportsASelectionThatMatchesNothing(t *testing.T) {
	path := writeSuite(t, suiteFile)
	if _, err := BlockCount(registry(t), path, topology.Selection{GatewayVersion: "1.2.0", Blocks: []string{"missing/sqlite"}}); err == nil {
		t.Fatal("BlockCount of an unknown block returned no error")
	}
}
