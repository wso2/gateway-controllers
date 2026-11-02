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

package suite

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/wso2/api-platform/tests/framework/core/catalog/testbench"
	"github.com/wso2/api-platform/tests/framework/core/topology"
)

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
	require.NoError(t, os.WriteFile(path, []byte(content), 0o644))
}

func TestStageOverlaysCopiesTheSuiteOverlaysToTheWorkspaceRoot(t *testing.T) {
	suiteDir := filepath.Join(t.TempDir(), "policies", "sample-policy", "it")
	writeFile(t, filepath.Join(suiteDir, "overlays", "gateway.toml"), "[a]\nb = true\n")
	workspace := t.TempDir()

	require.NoError(t, StageOverlays(suiteDir, workspace))
	content, err := os.ReadFile(filepath.Join(workspace, "overlays", "gateway.toml"))
	require.NoError(t, err)
	require.Equal(t, "[a]\nb = true\n", string(content))

	// A suite without overlays stages nothing.
	empty := t.TempDir()
	require.NoError(t, StageOverlays(t.TempDir(), empty))
	require.NoDirExists(t, filepath.Join(empty, "overlays"))
}

const gatedSuite = `
suite: gated
defaults:
  parallel: 1
  components:
    platform-gateway:
      db: sqlite
      dbCompatibility:
        sqlserver: "gateway-version>=1.2.0"
blocks:
  - name: gated
    parallel: 1
    components:
      - name: platform-gateway
        db:
          matrix: [sqlite, sqlserver]
      - name: testbench
    runners:
      - name: gated
        tags: "gateway-version>=1.2.0"
        features:
          - features/gated.feature
`

func TestExcludedEverywhereSkipsASuiteGatedAwayFromTheSelectedGateway(t *testing.T) {
	suiteFile := filepath.Join(t.TempDir(), "it-suite.yaml")
	writeFile(t, suiteFile, gatedSuite)

	reason := excludedEverywhere(topology.Selection{GatewayVersion: "1.1.0"}, suiteFile)
	require.Error(t, reason, "a run on 1.1.0 has nothing to run")

	require.NoError(t, excludedEverywhere(topology.Selection{GatewayVersion: "1.2.0"}, suiteFile))
	require.NoError(t, excludedEverywhere(topology.Selection{GatewayVersion: "latest"}, suiteFile))
}

func TestExcludedEverywhereLeavesOtherProblemsToTheRunner(t *testing.T) {
	require.NoError(t, excludedEverywhere(topology.Selection{}, filepath.Join(t.TempDir(), "missing.yaml")),
		"an unreadable suite is reported by the runner, not skipped")

	suiteFile := filepath.Join(t.TempDir(), "it-suite.yaml")
	writeFile(t, suiteFile, gatedSuite)
	require.NoError(t, excludedEverywhere(topology.Selection{Blocks: []string{"unknown"}}, suiteFile),
		"a selection that names no block is an error for the runner to report")
}

func TestPinnedTestbenchImageFollowsTheFrameworkVersionTheWorkspaceResolves(t *testing.T) {
	tests := []struct {
		name      string
		listing   string
		want      string
		wantFound bool
	}{
		{name: "a released framework",
			listing: `{"Path":"github.com/wso2/api-platform/tests/framework","Version":"v0.1.0"}`,
			want:    "ghcr.io/wso2/api-platform/testbench:0.1.0", wantFound: true},
		{name: "a version replaced by another release of the framework",
			listing: `{"Path":"github.com/wso2/api-platform/tests/framework","Version":"v0.4.2",` +
				`"Replace":{"Path":"github.com/wso2/api-platform/tests/framework","Version":"v0.4.1"}}`,
			want: "ghcr.io/wso2/api-platform/testbench:0.4.1", wantFound: true},
		{name: "replaced by a local checkout",
			listing: `{"Path":"github.com/wso2/api-platform/tests/framework","Version":"v0.1.0",` +
				`"Replace":{"Path":"../framework","Dir":"/src/framework"}}`},
		{name: "replaced by another module",
			listing: `{"Path":"github.com/wso2/api-platform/tests/framework","Version":"v0.1.0",` +
				`"Replace":{"Path":"github.com/fork/framework","Version":"v0.1.0"}}`},
		{name: "an untagged revision",
			listing: `{"Path":"github.com/wso2/api-platform/tests/framework","Version":"v0.1.1-0.20261014000000-abcdef123456"}`},
		{name: "a pre-release",
			listing: `{"Path":"github.com/wso2/api-platform/tests/framework","Version":"v0.2.0-rc1"}`},
		{name: "no version", listing: `{"Path":"github.com/wso2/api-platform/tests/framework"}`},
		{name: "output that is not a module", listing: "go: not a module"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			image, found := pinnedTestbenchImage([]byte(tt.listing))
			require.Equal(t, tt.wantFound, found)
			require.Equal(t, tt.want, image)
		})
	}
}

func TestPinTestbenchImageNamesTheReleaseTheModuleResolves(t *testing.T) {
	t.Setenv(testbench.EnvImageTestbench, "")

	pinTestbenchImage()

	require.Regexp(t, `^ghcr\.io/wso2/api-platform/testbench:\d+\.\d+\.\d+$`, os.Getenv(testbench.EnvImageTestbench))
}

func TestPinTestbenchImageLeavesAnImageTheEnvironmentNames(t *testing.T) {
	t.Setenv(testbench.EnvImageTestbench, "example.com/testbench:custom")

	pinTestbenchImage()

	require.Equal(t, "example.com/testbench:custom", os.Getenv(testbench.EnvImageTestbench))
}

func TestControllerPoliciesAreTheOnesTheControllerRequires(t *testing.T) {
	require.ElementsMatch(t,
		[]string{"api-key-auth", "host-rewrite", "oauth2-generator", "respond", "set-headers"}, ControllerPolicies)
}
