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
// environment names, keeping the number of blocks that boot at the same time under -block-parallel.
// Without it the suites run one at a time and each keeps the block parallelism its suite file declares.
//
//	go run ./cmd/run-suites -policies-dir ../../policies -policies basic-auth,cors -version 1.2.0 -block-parallel 6
package main

import (
	"bytes"
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
	"github.com/wso2/api-platform/tests/framework/core/components"
	"github.com/wso2/api-platform/tests/framework/core/suiterun"
	"github.com/wso2/api-platform/tests/framework/core/topology"

	"github.com/wso2/gateway-controllers/tests/it/common/gateway"
	"github.com/wso2/gateway-controllers/tests/it/common/runsuites"
)

func main() {
	policiesDir := flag.String("policies-dir", "", "the folder that holds the policy folders")
	policies := flag.String("policies", "", "comma-separated policies whose suites to run")
	version := flag.String("version", "", "the gateway version the suites run against")
	host := flag.String("host", "", "the image repository prefix of the gateway's images")
	db := flag.String("db", "", "limit each suite to one database (sqlite, postgres or sqlserver)")
	blockParallel := flag.Int("block-parallel", 0, "the most blocks that boot at the same time across all suites; 0 runs the suites one at a time")
	timeout := flag.Duration("timeout", 40*time.Minute, "the time limit of each suite")
	flag.Parse()

	names := splitList(*policies)
	if len(names) == 0 || *version == "" || *policiesDir == "" || *blockParallel < 0 {
		fmt.Fprintln(os.Stderr, "run-suites: -policies-dir, -policies and -version are required, and -block-parallel cannot be negative")
		os.Exit(2)
	}

	r := runner{
		policiesDir: *policiesDir,
		version:     *version,
		host:        *host,
		db:          *db,
		timeout:     *timeout,
		override:    *blockParallel > 0,
	}
	limit := *blockParallel
	if r.override {
		registry, err := catalog.Registry()
		if err != nil {
			fmt.Fprintln(os.Stderr, "run-suites:", err)
			os.Exit(1)
		}
		r.registry = registry
	}
	jobs := make([]runsuites.Job, 0, len(names))
	for _, name := range names {
		weight := 1
		if r.override {
			weight = min(r.blocks(name), limit)
		}
		jobs = append(jobs, runsuites.Job{Name: name, Weight: weight})
	}
	if r.override {
		fmt.Printf("running %d suites with at most %d blocks at the same time\n", len(jobs), limit)
	}

	failed := runsuites.Schedule(jobs, limit, r.run)
	if len(failed) > 0 {
		fmt.Printf("Failed integration suites: %s\n", strings.Join(failed, " "))
		os.Exit(1)
	}
}

// runner runs the suite of one policy.
type runner struct {
	policiesDir string
	version     string
	host        string
	db          string
	timeout     time.Duration

	// override is set when -block-parallel replaces the block parallelism of the suite files.
	override bool

	// registry resolves the suite files when override is set.
	registry *components.Registry

	// printing keeps the output of two suites from interleaving.
	printing sync.Mutex
}

// selection is how a run of the policy's suite selects blocks.
func (r *runner) selection(policy string) topology.Selection {
	selection := topology.Selection{GatewayVersion: r.version, GatewayHost: r.host}
	if r.db != "" {
		selection.Blocks = []string{policy + "/" + r.db}
	}
	return selection
}

// blocks returns how many blocks the policy's suite boots. A suite that cannot be judged here
// counts as one block, and runs with whatever it finds to do.
func (r *runner) blocks(policy string) int {
	suiteFile := filepath.Join(r.policiesDir, policy, gateway.IntegrationDir, suiterun.DefaultSuiteFile)
	count, err := runsuites.BlockCount(r.registry, suiteFile, r.selection(policy))
	if err != nil || count < 1 {
		return 1
	}
	return count
}

// run runs the suite of the job's policy and prints its output when it ends.
func (r *runner) run(job runsuites.Job) error {
	args := []string{"test", ".", "-count=1", "-timeout=" + r.timeout.String(), "-v", "-run", "TestIntegrationSuite", "-args"}
	if r.db != "" {
		args = append(args, "-blocks="+job.Name+"/"+r.db)
	}
	if r.override {
		args = append(args, "-block-parallel="+strconv.Itoa(job.Weight))
	}
	args = append(args, "-gateway-version="+r.version)
	if r.host != "" {
		args = append(args, "-host="+r.host)
	}

	var output bytes.Buffer
	cmd := exec.Command("go", args...)
	cmd.Dir = filepath.Join(r.policiesDir, job.Name, gateway.IntegrationDir)
	cmd.Stdout = &output
	cmd.Stderr = &output

	if r.override {
		r.print("=== Integration suite of %s on gateway %s started, %d blocks at once ===\n", job.Name, r.version, job.Weight)
	} else {
		r.print("=== Integration suite of %s on gateway %s started ===\n", job.Name, r.version)
	}
	started := time.Now()
	err := cmd.Run()

	result := "passed"
	if err != nil {
		result = "failed: " + err.Error()
	}
	r.printing.Lock()
	defer r.printing.Unlock()
	fmt.Printf("=== Integration suite of %s on gateway %s ===\n%s", job.Name, r.version, output.String())
	fmt.Printf("=== %s %s in %.0fs ===\n", job.Name, result, time.Since(started).Seconds())
	return err
}

func (r *runner) print(format string, args ...any) {
	r.printing.Lock()
	defer r.printing.Unlock()
	fmt.Printf(format, args...)
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
