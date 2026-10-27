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
// environment names. It runs every block of every suite as a process of its own and keeps
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
	"strings"
	"sync"
	"time"

	"github.com/wso2/api-platform/tests/framework/core/catalog"
	"github.com/wso2/api-platform/tests/framework/core/suiterun"
	"github.com/wso2/api-platform/tests/framework/core/topology"

	"github.com/wso2/gateway-controllers/tests/it/common/gateway"
	"github.com/wso2/gateway-controllers/tests/it/common/runsuites"
)

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
	binaries, err := os.MkdirTemp("", "suite-binaries-")
	if err != nil {
		fmt.Fprintln(os.Stderr, "run-suites:", err)
		return 1
	}
	defer os.RemoveAll(binaries)

	r := &runner{
		policiesDir: *policiesDir,
		binaries:    binaries,
		version:     *version,
		host:        *host,
		timeout:     *timeout,
		builds:      map[string]*build{},
		items:       map[string]item{},
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
			continue
		}
		for _, block := range blocks {
			name := displayName(policy, block.Name)
			r.items[name] = item{policy: policy, block: block.Name}
			jobs = append(jobs, runsuites.Job{Name: name, Priority: block.Runners})
		}
	}
	r.say("running %d blocks of %d suites on gateway %s, at most %d at the same time\n", len(jobs), len(names)-len(broken), *version, *blockParallel)

	failed := runsuites.Schedule(jobs, *blockParallel, r.run)
	failed = append(failed, broken...)
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

// build is the test binary of one policy, compiled once.
type build struct {
	once sync.Once
	path string
	err  error
}

// runner runs the blocks of the suites.
type runner struct {
	policiesDir string
	binaries    string
	version     string
	host        string
	timeout     time.Duration

	// items maps a job name to what it runs. It is complete before the first job starts.
	items map[string]item

	// printing keeps the lines of blocks that run at the same time from splitting each other.
	printing sync.Mutex

	mu     sync.Mutex
	builds map[string]*build
}

// run runs the block of the job in a process of its own, streaming its output with the block's
// name in front of every line.
func (r *runner) run(job runsuites.Job) error {
	it := r.items[job.Name]
	out := runsuites.NewLineWriter(os.Stdout, &r.printing, "["+job.Name+"] ")
	defer out.Flush()

	binary, err := r.binary(it.policy)
	if err != nil {
		fmt.Fprintf(out, "cannot build the suite: %v\n", err)
		return err
	}
	args := []string{
		"-test.v", "-test.run=^TestIntegrationSuite$", "-test.timeout=" + r.timeout.String(),
		"-blocks=" + it.block, "-gateway-version=" + r.version,
	}
	if r.host != "" {
		args = append(args, "-host="+r.host)
	}
	cmd := exec.Command(binary, args...)
	cmd.Dir = r.policyDir(it.policy)
	cmd.Stdout = out
	cmd.Stderr = out

	fmt.Fprintf(out, "=== started on gateway %s ===\n", r.version)
	started := time.Now()
	err = cmd.Run()
	result := "passed"
	if err != nil {
		result = "failed: " + err.Error()
	}
	fmt.Fprintf(out, "=== %s in %.0fs ===\n", result, time.Since(started).Seconds())
	return err
}

// binary returns the compiled test binary of the policy, compiling it on first use. Blocks of the
// same policy wait for that one compilation.
func (r *runner) binary(policy string) (string, error) {
	r.mu.Lock()
	b, ok := r.builds[policy]
	if !ok {
		b = &build{}
		r.builds[policy] = b
	}
	r.mu.Unlock()

	b.once.Do(func() {
		b.path = filepath.Join(r.binaries, policy+".test")
		out := runsuites.NewLineWriter(os.Stdout, &r.printing, "["+policy+" build] ")
		defer out.Flush()
		cmd := exec.Command("go", "test", "-c", "-o", b.path, ".")
		cmd.Dir = r.policyDir(policy)
		cmd.Stdout = out
		cmd.Stderr = out
		b.err = cmd.Run()
	})
	return b.path, b.err
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
