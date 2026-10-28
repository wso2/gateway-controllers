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

// Command run-suites runs the integration suites of the named policies against the gateway the
// environment names. It runs every block of every suite under a go test of its own and keeps
// -block-parallel of them running at the same time until none is left to start.
//
//	go run ./cmd/run-suites -policies-dir ../../policies -policies basic-auth,cors -version 1.2.0 -block-parallel 6
package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/wso2/api-platform/tests/framework/core/catalog"
	"github.com/wso2/api-platform/tests/framework/core/suiterun"
	"github.com/wso2/api-platform/tests/framework/core/topology"

	"github.com/wso2/gateway-controllers/tests/it/common/gateway"
	"github.com/wso2/gateway-controllers/tests/it/common/runsuites"
)

// buildSecondsVariable carries the time the gateway build took from build-gateway, through the
// environment file the suites boot from, so the timeline can report it.
const buildSecondsVariable = "IT_GATEWAY_BUILD_SECONDS"

// sampleInterval is how often the machine's processor and memory use is recorded.
const sampleInterval = 5 * time.Second

func main() {
	os.Exit(run())
}

func run() int {
	policiesDir := flag.String("policies-dir", "", "the folder that holds the policy folders")
	policies := flag.String("policies", "", "comma-separated policies whose suites to run")
	version := flag.String("version", "", "the gateway version the suites run against")
	host := flag.String("host", "", "the image repository prefix of the gateway's images")
	db := flag.String("db", "", "limit each suite to one database (sqlite, postgres or sqlserver)")
	blockParallel := flag.Int("block-parallel", 1, "the most blocks that run at the same time across all suites")
	timeout := flag.Duration("timeout", 40*time.Minute, "the time limit of each block")
	timeline := flag.String("timeline", "", "the file to write the time each block took to, as JSON")
	flag.Parse()

	names := splitList(*policies)
	if len(names) == 0 || *version == "" || *policiesDir == "" || *blockParallel < 1 {
		fmt.Fprintln(os.Stderr, "run-suites: -policies-dir, -policies and -version are required, and -block-parallel must be at least 1")
		return 2
	}
	registry, err := catalog.Registry()
	if err != nil {
		fmt.Fprintln(os.Stderr, "run-suites:", err)
		return 1
	}
	scratch, err := os.MkdirTemp("", "suite-builds-")
	if err != nil {
		fmt.Fprintln(os.Stderr, "run-suites:", err)
		return 1
	}
	defer os.RemoveAll(scratch)

	r := &runner{
		policiesDir: *policiesDir,
		scratch:     scratch,
		version:     *version,
		host:        *host,
		timeout:     *timeout,
		builds:      map[string]*build{},
		items:       map[string]item{},
		recorder:    runsuites.NewRecorder(),
	}

	var jobs []runsuites.Job
	var broken []string
	for _, policy := range names {
		suiteFile := filepath.Join(*policiesDir, policy, gateway.IntegrationDir, suiterun.DefaultSuiteFile)
		blocks, err := runsuites.Blocks(registry, suiteFile, topology.Selection{GatewayVersion: *version, GatewayHost: *host})
		if err != nil {
			r.say("[%s] cannot list the blocks: %v\n", policy, err)
			broken = append(broken, policy)
			continue
		}
		blocks = onlyDatabase(blocks, *db)
		if len(blocks) == 0 {
			r.say("[%s] nothing to run on gateway %s\n", policy, *version)
			r.recorder.Skip(policy)
			continue
		}
		for _, block := range blocks {
			name := displayName(policy, block.Name)
			r.items[name] = item{policy: policy, block: block.Name}
			jobs = append(jobs, runsuites.Job{Name: name, Priority: block.Runners})
		}
	}
	r.say("running %d blocks of %d suites on gateway %s, at most %d at the same time\n", len(jobs), len(names)-len(broken), *version, *blockParallel)

	stopSampling := r.recorder.StartSampling(sampleInterval)
	failed := runsuites.Schedule(jobs, *blockParallel, r.run)
	stopSampling()
	failed = append(failed, broken...)
	if *timeline != "" {
		buildSeconds, _ := strconv.ParseFloat(os.Getenv(buildSecondsVariable), 64)
		if err := runsuites.WriteTimeline(*timeline, r.recorder.Timeline(*version, *blockParallel, buildSeconds)); err != nil {
			fmt.Fprintln(os.Stderr, "run-suites: writing the timeline:", err)
		}
	}
	if len(failed) > 0 {
		fmt.Printf("Failed integration blocks: %s\n", strings.Join(failed, " "))
		return 1
	}
	return 0
}

// item is the policy and block a job runs.
type item struct {
	policy string
	block  string
}

// build is the one compilation of a policy's suite.
type build struct {
	once sync.Once
	err  error
}

// runner runs the blocks of the suites.
type runner struct {
	policiesDir string
	scratch     string
	version     string
	host        string
	timeout     time.Duration

	// items maps a job name to what it runs. It is complete before the first job starts.
	items map[string]item

	recorder *runsuites.Recorder

	// printing keeps the lines of blocks that run at the same time from splitting each other.
	printing sync.Mutex

	mu     sync.Mutex
	builds map[string]*build
}

// run runs the block of the job under a go test of its own, streaming its output with the block's
// name in front of every line. Every block runs under its own go test, not as a child of this
// command: testcontainers ties the containers and networks a test process starts to its parent
// process, and removes them when that parent ends. Children of this command would share one
// parent, and nothing would be removed until the whole run ended.
func (r *runner) run(job runsuites.Job) error {
	it := r.items[job.Name]
	out := runsuites.NewLineWriter(os.Stdout, &r.printing, "["+job.Name+"] ")
	defer out.Flush()

	started := time.Now()
	if err := r.warm(it.policy); err != nil {
		fmt.Fprintf(out, "cannot build the suite: %v\n", err)
		r.recorder.Block(job.Slot, it.policy, it.block, started, false)
		return err
	}
	args := []string{
		"test", ".", "-count=1", "-timeout=" + r.timeout.String(), "-v", "-run", "^TestIntegrationSuite$",
		"-args", "-blocks=" + it.block, "-gateway-version=" + r.version,
	}
	if r.host != "" {
		args = append(args, "-host="+r.host)
	}
	cmd := exec.Command("go", args...)
	cmd.Dir = r.policyDir(it.policy)
	cmd.Stdout = out
	cmd.Stderr = out

	fmt.Fprintf(out, "=== started on gateway %s ===\n", r.version)
	err := cmd.Run()
	result := "passed"
	if err != nil {
		result = "failed: " + err.Error()
	}
	fmt.Fprintf(out, "=== %s in %.0fs ===\n", result, time.Since(started).Seconds())
	r.recorder.Block(job.Slot, it.policy, it.block, started, err == nil)
	return err
}

// warm compiles the policy's suite once, on first use, so that the go test of each of its blocks
// finds everything it needs in the build cache instead of compiling it again at the same time.
// Blocks of the same policy wait for that one compilation.
func (r *runner) warm(policy string) error {
	r.mu.Lock()
	b, ok := r.builds[policy]
	if !ok {
		b = &build{}
		r.builds[policy] = b
	}
	r.mu.Unlock()

	b.once.Do(func() {
		out := runsuites.NewLineWriter(os.Stdout, &r.printing, "["+policy+" build] ")
		defer out.Flush()
		cmd := exec.Command("go", "test", "-c", "-o", filepath.Join(r.scratch, policy+".test"), ".")
		cmd.Dir = r.policyDir(policy)
		cmd.Stdout = out
		cmd.Stderr = out
		started := time.Now()
		b.err = cmd.Run()
		r.recorder.Compile(policy, started, b.err == nil)
	})
	return b.err
}

func (r *runner) policyDir(policy string) string {
	return filepath.Join(r.policiesDir, policy, gateway.IntegrationDir)
}

func (r *runner) say(format string, args ...any) {
	r.printing.Lock()
	defer r.printing.Unlock()
	fmt.Printf(format, args...)
}

// displayName names a block in the output: the block's own name when it begins with the policy's,
// otherwise the policy and the block.
func displayName(policy, block string) string {
	if block == policy || strings.HasPrefix(block, policy+"/") || strings.HasPrefix(block, policy+"-") {
		return block
	}
	return policy + "/" + block
}

// onlyDatabase keeps the matrix variants that run on database. An empty database keeps every block.
func onlyDatabase(blocks []runsuites.Block, database string) []runsuites.Block {
	if database == "" {
		return blocks
	}
	var kept []runsuites.Block
	for _, block := range blocks {
		if strings.HasSuffix(block.Name, "/"+database) {
			kept = append(kept, block)
		}
	}
	return kept
}

func splitList(value string) []string {
	var out []string
	for _, part := range strings.FieldsFunc(value, func(c rune) bool { return c == ',' || c == ' ' }) {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}
