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

func TestPinnedTestbenchImageFollowsTheFrameworkVersionTheModulePins(t *testing.T) {
	const required = "module x\n\nrequire (\n\tgithub.com/cucumber/godog v0.16.0\n\tgithub.com/wso2/api-platform/tests/framework v0.1.0\n)\n"
	tests := []struct {
		name      string
		goMod     string
		want      string
		wantFound bool
	}{
		{name: "a released framework", goMod: required,
			want: "ghcr.io/wso2/api-platform/testbench:0.1.0", wantFound: true},
		{name: "a single-line require", goMod: "require github.com/wso2/api-platform/tests/framework v1.20.3\n",
			want: "ghcr.io/wso2/api-platform/testbench:1.20.3", wantFound: true},
		{name: "replaced by a local checkout",
			goMod: required + "replace github.com/wso2/api-platform/tests/framework => ../../../api-platform/tests/framework\n"},
		{name: "replaced for one version",
			goMod: required + "replace github.com/wso2/api-platform/tests/framework v0.1.0 => ../framework\n"},
		{name: "replaced inside a replace block",
			goMod: required + "replace (\n\tgithub.com/wso2/gateway-controllers/tests/it => ../../../tests/it\n\tgithub.com/wso2/api-platform/tests/framework => ../framework\n)\n"},
		{name: "replaced for one version inside a replace block",
			goMod: required + "replace (\n\tgithub.com/wso2/api-platform/tests/framework v0.1.0 => ../framework\n)\n"},
		{name: "another module replaced",
			goMod: required + "replace github.com/wso2/gateway-controllers/tests/it => ../../../tests/it\n",
			want:  "ghcr.io/wso2/api-platform/testbench:0.1.0", wantFound: true},
		{name: "a commented-out replace",
			goMod: required + "// replace github.com/wso2/api-platform/tests/framework => ../framework\n",
			want:  "ghcr.io/wso2/api-platform/testbench:0.1.0", wantFound: true},
		{name: "an untagged revision",
			goMod: "require github.com/wso2/api-platform/tests/framework v0.1.1-0.20261014000000-abcdef123456\n"},
		{name: "a pre-release", goMod: "require github.com/wso2/api-platform/tests/framework v0.2.0-rc1\n"},
		{name: "another module of the repository",
			goMod: "require github.com/wso2/api-platform/sdk/core v0.4.3\n"},
		{name: "no framework", goMod: "module x\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			image, found := pinnedTestbenchImage([]byte(tt.goMod))
			require.Equal(t, tt.wantFound, found)
			require.Equal(t, tt.want, image)
		})
	}
}

func TestControllerPoliciesAreTheOnesTheControllerRequires(t *testing.T) {
	require.ElementsMatch(t,
		[]string{"api-key-auth", "host-rewrite", "oauth2-generator", "respond", "set-headers"}, ControllerPolicies)
}
