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

package gateway

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/wso2/api-platform/tests/framework/core/builder"
	"github.com/wso2/api-platform/tests/framework/core/catalog/platformgateway"
	"github.com/wso2/api-platform/tests/framework/core/catalog/shared"
	"github.com/wso2/api-platform/tests/framework/core/topology"
)

const (
	// EnvController and EnvRuntime name the environment variables through which the framework
	// takes the gateway controller and runtime images a suite boots.
	EnvController = shared.EnvImageGatewayController
	EnvRuntime    = shared.EnvImageGatewayRuntime

	controllerRepository = "local/apip-it-gateway-controller"
	runtimeRepository    = "local/apip-it-gateway-runtime"
)

// Images are the gateway controller and runtime images a suite boots.
type Images struct {
	Controller string
	Runtime    string
}

// Environment returns the variables that make the framework boot these images.
func (i Images) Environment() map[string]string {
	return map[string]string{EnvController: i.Controller, EnvRuntime: i.Runtime}
}

// Prebuilt returns the images the environment names, and whether it names both.
func Prebuilt() (Images, bool) {
	images := Images{
		Controller: strings.TrimSpace(os.Getenv(EnvController)),
		Runtime:    strings.TrimSpace(os.Getenv(EnvRuntime)),
	}
	return images, images.Controller != "" && images.Runtime != ""
}

// CheckVersion reports an error unless both images carry the tag of the gateway version a run
// selects. The framework rewrites an image's tag to that version, so an image tagged otherwise is
// never the one the gateway boots.
func (i Images) CheckVersion(version string) error {
	version = normalizeVersion(version)
	for _, ref := range []string{i.Controller, i.Runtime} {
		if tag(ref) != version {
			return fmt.Errorf("the prebuilt gateway image %q is not tagged %q, the version this run selects", ref, version)
		}
	}
	return nil
}

// BuildOptions describe one gateway build.
type BuildOptions struct {
	// PoliciesDir is the folder that holds the policy folders. Required.
	PoliciesDir string

	// Policies names the policies to build into the gateway. Empty means every policy of PoliciesDir.
	Policies []string

	// Version is the released gateway the policies are built on, or latest. Required.
	Version string

	// Host replaces the image repository prefix of the gateway's base images. Empty means
	// the release registry.
	Host string

	// Runner runs the docker commands. Empty means the host's docker.
	Runner builder.Runner

	// Coverage builds the policy engine with Go coverage instrumentation of every policy, so a
	// run of the suites writes the coverage of the policies' code to the runtime's /coverage. Only
	// the gateway-builder of the latest gateway supports it, so it requires Version latest.
	Coverage bool
}

// Build builds the gateway controller and runtime images that carry the selected policies, on
// the base images of opts.Version, and tags them with that version so the framework boots them
// for a run that selects it.
func Build(ctx context.Context, opts BuildOptions) (Images, error) {
	version := normalizeVersion(opts.Version)
	if version == "" {
		return Images{}, fmt.Errorf("the gateway version to build on is required")
	}
	if strings.TrimSpace(opts.PoliciesDir) == "" {
		return Images{}, fmt.Errorf("the policies folder is required")
	}
	if opts.Coverage && version != "latest" {
		return Images{}, fmt.Errorf("coverage needs gateway version latest: the gateway-builder of %s cannot instrument the policy engine", version)
	}
	names := uniqueSorted(opts.Policies)
	if len(opts.Policies) == 0 {
		all, err := PolicyNames(opts.PoliciesDir)
		if err != nil {
			return Images{}, err
		}
		names = all
	}
	if len(names) == 0 {
		return Images{}, errNoPolicies
	}
	runner := opts.Runner
	if runner == nil {
		runner = builder.ExecRunner{}
	}

	if opts.Coverage {
		runner = coverageRunner{runner}
	}

	workspace, err := os.MkdirTemp("", "gateway-policies-")
	if err != nil {
		return Images{}, err
	}
	defer os.RemoveAll(workspace)
	if _, err := Stage(opts.PoliciesDir, workspace, names...); err != nil {
		return Images{}, err
	}

	registry := strings.TrimRight(strings.TrimSpace(opts.Host), "/")
	if registry == "" {
		registry = shared.GatewayReleaseRegistry
	}
	derived, err := platformgateway.BuildVersionedWithPolicies(ctx, workspace, version, "policies",
		registry+"/gateway-controller:"+version, registry+"/gateway-runtime:"+version, runner, false)
	if err != nil {
		return Images{}, err
	}

	images := Images{Controller: controllerRepository + ":" + version, Runtime: runtimeRepository + ":" + version}
	for source, target := range map[string]string{derived.Controller: images.Controller, derived.Runtime: images.Runtime} {
		if err := runner.Run(ctx, builder.Command{Directory: workspace, Args: []string{"docker", "tag", source, target}}); err != nil {
			return Images{}, fmt.Errorf("tagging %s: %w", target, err)
		}
	}
	return images, nil
}

// normalizeVersion trims a gateway version and spells latest the way the framework does.
func normalizeVersion(version string) string {
	version = strings.TrimSpace(version)
	if strings.EqualFold(version, topology.LatestGatewayVersion) {
		return topology.LatestGatewayVersion
	}
	return version
}

// tag returns the tag of an image reference.
func tag(ref string) string {
	slash := strings.LastIndexByte(ref, '/')
	colon := strings.LastIndexByte(ref, ':')
	if colon <= slash {
		return ""
	}
	return ref[colon+1:]
}

// CoveragePackages is what a coverage build instruments, as a comma-separated -coverpkg list.
//   - The code of every policy: each is a Go module of its own that the policy engine pulls in as a
//     dependency, which a plain -cover build would leave out.
//   - The policy engine's main package. Go registers the code that writes the counters when the
//     process exits from the instrumented main package, so a build that instruments only the
//     policies has counters and never writes them.
//
// The report keeps only the policies (see scripts/coverage/it-coverage-report.sh).
const CoveragePackages = "github.com/wso2/gateway-controllers/policies/...," +
	"github.com/wso2/api-platform/gateway/gateway-runtime/policy-engine/cmd/policy-engine"

// EnvCollectCoverage names the variable that makes a suite give the gateway's containers a
// GOCOVERDIR, the folder where the coverage-instrumented policy engine writes its counters when it
// stops. tests/it/cmd/run-suites sets it for a run with -coverage-out.
const EnvCollectCoverage = "IT_COLLECT_COVERAGE"

// CollectCoverage reports whether this run collects the gateway's coverage counters.
func CollectCoverage() bool {
	value := strings.TrimSpace(os.Getenv(EnvCollectCoverage))
	return value == "1" || strings.EqualFold(value, "true")
}

// EnableCoverageCollection makes the framework hand GOCOVERDIR=/coverage to the gateway's
// containers when the run collects coverage. The framework adds it only when its coverage mode
// is on, which it otherwise turns on with a flag that cannot be combined with the gateway
// version a suite selects, and it reads the mode as it builds the catalog, after a suite starts.
func EnableCoverageCollection(t interface{ Setenv(key, value string) }) {
	if CollectCoverage() {
		t.Setenv(shared.EnvCoverageMode, "true")
	}
}

// coverageVolume is where the instrumented policy engine writes its counters. The runtime image
// declares it a volume so that a container sharing it keeps the counters after the framework has
// removed the runtime container; see package itcoverage.
const coverageVolume = "/coverage"

// coverageRunner changes the two commands that make the runtime instrumented. The framework
// starts the gateway-builder without the coverage switches, and offers no option to add them to a
// build from a released gateway, so the command is changed on its way to docker:
//   - the builder run, which compiles the policy engine, gets COVERAGE and COVERPKG;
//   - the build of the runtime image has the volume declared in its Dockerfile.
//
// Every other command passes through.
type coverageRunner struct{ builder.Runner }

func (r coverageRunner) Run(ctx context.Context, command builder.Command) error {
	args := command.Args
	switch {
	case len(args) >= 3 && args[0] == "docker" && args[1] == "run":
		command.Args = append([]string{"docker", "run", "-e", "COVERAGE=true", "-e", "COVERPKG=" + CoveragePackages}, args[2:]...)
	case len(args) >= 3 && args[0] == "docker" && args[1] == "buildx":
		if i := slices.Index(args, "-f"); i >= 0 && i+1 < len(args) && isRuntimeDockerfile(args[i+1]) {
			if err := declareCoverageVolume(args[i+1]); err != nil {
				return err
			}
		}
	}
	return r.Runner.Run(ctx, command)
}

// isRuntimeDockerfile reports whether path is the Dockerfile the gateway-builder generated for
// the gateway runtime image.
func isRuntimeDockerfile(path string) bool {
	path = filepath.ToSlash(path)
	return strings.HasSuffix(path, "/gateway-runtime/Dockerfile")
}

// declareCoverageVolume appends the coverage volume to the runtime image's Dockerfile.
func declareCoverageVolume(dockerfile string) error {
	file, err := os.OpenFile(dockerfile, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		return fmt.Errorf("declaring the coverage volume: %w", err)
	}
	_, werr := fmt.Fprintf(file, "\n# Added for a coverage run: counters survive the container.\nVOLUME %s\n", coverageVolume)
	if cerr := file.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		return fmt.Errorf("declaring the coverage volume: %w", werr)
	}
	return nil
}
