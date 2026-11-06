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

// Package suite runs the integration suite of one gateway policy on the shared step definitions.
// A policy keeps its suite file, features and own steps in policies/<name>/it, a Go module of its
// own, and its test entry point hands them to this package.
//
// The suites of a run boot one gateway image set, built once by tests/it/cmd/build-gateway and
// named through the environment (see package gateway). A suite run alone, without that
// environment, builds the set itself from the policy under test and the policies the gateway
// controller itself needs.
package suite

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/cucumber/godog"

	"github.com/wso2/api-platform/tests/framework/core/catalog"
	"github.com/wso2/api-platform/tests/framework/core/catalog/testbench"
	frameworkruntime "github.com/wso2/api-platform/tests/framework/core/runtime"
	"github.com/wso2/api-platform/tests/framework/core/suiterun"
	"github.com/wso2/api-platform/tests/framework/core/topology"

	"github.com/wso2/gateway-controllers/tests/it/common/gateway"
	"github.com/wso2/gateway-controllers/tests/it/common/resources"
	"github.com/wso2/gateway-controllers/tests/it/common/steps"
	"github.com/wso2/gateway-controllers/tests/it/common/steps/platformgateway"
)

// overlaysDir is the folder inside a policy's it folder that holds the gateway configuration
// overlays its suite file names. Staging copies it to the workspace root, so a component's
// `overlay: overlays/<file>.toml` reads relative to the it folder, like its feature paths.
const overlaysDir = "overlays"

// ControllerPolicies are the policies the gateway controller requires to create LLM providers, LLM
// proxies and their authentication: it attaches them to the resources it generates and rejects a
// resource when one is missing from the gateway. A gateway built for one suite carries them.
var ControllerPolicies = []string{"api-key-auth", "host-rewrite", "oauth2-generator", "respond", "set-headers"}

// Config describes one policy's suite.
type Config struct {
	// Companions names further policies of this repository to build into the gateway of a suite
	// run alone, because the policy's scenarios use them beside it, for example a policy that
	// composes with another. It is optional.
	Companions []string

	// Register binds the steps only this policy needs, after the shared steps are bound. It is
	// optional. A step defined here must not repeat a shared one.
	Register func(sc *godog.ScenarioContext, topo *frameworkruntime.Topology)

	// RegisterWithBase is Register for steps that build on the shared request steps. It also
	// receives the shared steps' base, and runs after Register. It is optional.
	RegisterWithBase func(sc *godog.ScenarioContext, base *steps.Base, topo *frameworkruntime.Topology)
}

// Main parses the suite flags and runs the tests. Call it from TestMain.
func Main(m *testing.M, cfg Config) {
	pinTestbenchImage()
	suiterun.Main(m, options(cfg))
}

const (
	testbenchRepository = "ghcr.io/wso2/api-platform/testbench"
	frameworkModule     = "github.com/wso2/api-platform/tests/framework"
)

// releasedVersion matches a tagged release, not a pre-release or an untagged revision.
var releasedVersion = regexp.MustCompile(`^v(\d+\.\d+\.\d+)$`)

// pinTestbenchImage points the framework at the testbench image published with the framework
// release the suites run on, unless the environment already names one. The framework chooses that
// image from the module versions embedded in the running binary, and a binary built by `go test`
// embeds none, so left alone it asks for an image that only a local build creates. The release is
// the one the Go workspace resolves (`make it-workspace` generates it): a suite's own go.mod does
// not name the framework, only tests/it/go.mod does.
func pinTestbenchImage() {
	if os.Getenv(testbench.EnvImageTestbench) != "" {
		return
	}
	listing, err := exec.Command("go", "list", "-m", "-json", frameworkModule).Output()
	if err != nil {
		return
	}
	if image, ok := pinnedTestbenchImage(listing); ok {
		os.Setenv(testbench.EnvImageTestbench, image)
	}
}

// pinnedTestbenchImage returns the testbench image of the released framework that the output of
// `go list -m -json` describes. A framework replaced with a local checkout or another module, or
// at an untagged revision or a pre-release, has none: the framework then uses the image that
// checkout builds.
func pinnedTestbenchImage(listing []byte) (string, bool) {
	var module struct {
		Version string
		Replace *struct{ Path, Version string }
	}
	if err := json.Unmarshal(listing, &module); err != nil {
		return "", false
	}
	version := module.Version
	if module.Replace != nil {
		if module.Replace.Path != frameworkModule {
			return "", false
		}
		version = module.Replace.Version
	}
	match := releasedVersion.FindStringSubmatch(version)
	if match == nil {
		return "", false
	}
	return testbenchRepository + ":" + match[1], true
}

// Run executes the suite declared in it-suite.yaml in the working directory, which `go test` sets
// to the policy's it folder. The gateway it boots is the prebuilt image set the environment names,
// or, when none is named, one built from the policy, ControllerPolicies and cfg.Companions. The
// suite's overlays folder is staged in a temporary workspace.
func Run(t *testing.T, cfg Config) {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("locating the suite directory: %v", err)
	}
	workspace := t.TempDir()
	if err := StageOverlays(dir, workspace); err != nil {
		t.Fatalf("staging the overlays: %v", err)
	}
	if err := stagePlatformAPI(filepath.Join(dir, suiterun.DefaultSuiteFile), workspace); err != nil {
		t.Fatalf("staging the platform-api files: %v", err)
	}
	if reason := excludedEverywhere(suiterun.Selection(), filepath.Join(dir, suiterun.DefaultSuiteFile)); reason != nil {
		t.Skipf("nothing to run: %v", reason)
	}
	if err := provideGateway(t, dir, cfg); err != nil {
		t.Fatalf("providing the gateway: %v", err)
	}
	opts := options(cfg)
	opts.Dir = dir
	opts.WorkspaceRoot = workspace
	suiterun.Run(t, opts)
}

// provideGateway makes the framework boot a gateway that carries the suite's policies: the
// prebuilt image set when the environment names one, otherwise a set built here for this suite.
func provideGateway(t *testing.T, suiteDir string, cfg Config) error {
	selection := suiterun.Selection()
	version := strings.TrimSpace(selection.GatewayVersion)
	if version == "" {
		return errors.New("run the suite with -gateway-version")
	}
	if images, ok := gateway.Prebuilt(); ok {
		return images.CheckVersion(version)
	}
	if filepath.Base(suiteDir) != gateway.IntegrationDir {
		return fmt.Errorf("%q is not a policy's %s folder", suiteDir, gateway.IntegrationDir)
	}
	policyDir := filepath.Dir(suiteDir)
	policiesDir, policy := gateway.PolicyOf(policyDir)
	policies := slices.Concat([]string{policy}, ControllerPolicies, cfg.Companions)
	images, err := gateway.Build(t.Context(), gateway.BuildOptions{
		PoliciesDir: policiesDir,
		Policies:    policies,
		Version:     version,
		Host:        selection.GatewayHost,
	})
	if err != nil {
		return err
	}
	for key, value := range images.Environment() {
		t.Setenv(key, value)
	}
	return nil
}

// excludedEverywhere returns why the selected gateway version leaves the suite nothing to run,
// or nil when something runs or the suite cannot be judged here. A policy that needs a newer
// gateway gates its runners with gateway-version tags, and a run against an older gateway
// should skip it. The framework reports that as ErrNothingToRun only for a selection by policy
// name, which a suite of declared runners never uses; otherwise it returns a plain error.
func excludedEverywhere(selection topology.Selection, suiteFile string) error {
	registry, err := catalog.Registry()
	if err != nil {
		return nil
	}
	resolved, err := topology.LoadFile(suiteFile, registry)
	if err != nil {
		return nil
	}
	_, err = selection.Apply(resolved)
	if errors.Is(err, topology.ErrNothingToRun) ||
		err != nil && (strings.Contains(err.Error(), "the selection has no compatible blocks") ||
			strings.Contains(err.Error(), "the selection has no compatible runners")) {
		return err
	}
	return nil
}

// StageOverlays copies the overlays folder of suiteDir, when it has one, to
// <workspace>/overlays. The framework resolves a component's overlay path against the workspace,
// which holds no it folder.
func StageOverlays(suiteDir, workspace string) error {
	source := filepath.Join(suiteDir, overlaysDir)
	info, err := os.Stat(source)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("%q is not a folder", source)
	}
	return gateway.CopyTree(source, filepath.Join(workspace, overlaysDir))
}

var platformAPIComponent = regexp.MustCompile(`(?m)^\s*-\s*name:\s*platform-api\s*$`)

// stagePlatformAPI stages the shared Platform API files at the workspace root when the suite file
// runs the platform-api component, which the framework module cannot run without them.
func stagePlatformAPI(suiteFile, workspace string) error {
	content, err := os.ReadFile(suiteFile)
	if err != nil {
		return err
	}
	if !platformAPIComponent.Match(content) {
		return nil
	}
	for name, path := range resources.PlatformAPIFiles {
		file, err := resources.PlatformAPI.ReadFile("platformapi/" + name)
		if err != nil {
			return err
		}
		target := filepath.Join(workspace, filepath.FromSlash(path))
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(target, file, 0o644); err != nil {
			return err
		}
	}
	return nil
}

func options(cfg Config) suiterun.Options {
	return suiterun.Options{
		Steps: func(topo *frameworkruntime.Topology, featureRoot string) (frameworkruntime.StepRegistrar, error) {
			shared, err := steps.New(topo, featureRoot)
			if err != nil {
				return nil, err
			}
			return func(sc *godog.ScenarioContext) {
				shared.Register(sc)
				if cfg.Register != nil {
					cfg.Register(sc, topo)
				}
				if cfg.RegisterWithBase != nil {
					cfg.RegisterWithBase(sc, shared.Base, topo)
				}
			}, nil
		},
		CleanupDeleters: platformgateway.RegisterDeleters,
	}
}
