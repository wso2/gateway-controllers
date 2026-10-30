#!/usr/bin/env python3
"""
Create the integration test suite skeleton for a policy.

  python3 scripts/it/scaffold.py <policy>      (or: make it-scaffold POLICY=<policy>)

Writes the policy's suite into policies/<policy>/it: it-suite.yaml, a Go module (go.mod, tidied
with `go mod tidy`), suite_test.go, the policy's own step definitions in steps/ (register.go,
<policy>_steps.go and steps_test.go) and features/<policy>.feature. The feature deploys a REST API with the policy attached and an empty
parameter set; fill in the policy's configuration and the assertions. Nothing is overwritten: if
any file exists the command stops and changes nothing.
"""

import re
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
POLICIES_DIR = "policies"
NAME_RE = re.compile(r"^[a-z0-9][a-z0-9-]*$")
VERSION_RE = re.compile(r"^version:\s*v?(\d+)\.", re.MULTILINE)

LICENSE_HEADER = """\
# --------------------------------------------------------------------
# Copyright (c) 2026, WSO2 LLC. (https://www.wso2.com).
#
# WSO2 LLC. licenses this file to you under the Apache License,
# Version 2.0 (the "License"); you may not use this file except
# in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.
# --------------------------------------------------------------------
"""

GO_LICENSE_HEADER = """\
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
"""

SUITE = """\
# The integration suite of the @NAME@ policy. The gateway under test is built from this policy and
# the policies the gateway controller requires (tests/it/common/suite), staged as the policy tree
# that addPoliciesFrom names. Feature paths are relative to this directory. Give a runner a tags
# entry, "gateway-version>=X.Y.Z", only when the policy needs a gateway release newer than the
# oldest one tested.

suite: @NAME@

defaults:
  parallel: 1
  components:
    platform-gateway:
      db: sqlite
      dbCompatibility:
        sqlserver: "gateway-version>=1.2.0"
  timeouts:
    boot: 5m
    propagation: 60s

blocks:
  - name: @NAME@
    parallel: 1
    components:
      - name: platform-gateway
        db:
          matrix: [sqlite, postgres, sqlserver]
        addPoliciesFrom: policies
      - name: testbench
    runners:
      - name: @NAME@
        features:
          - features/@FEATURE_FILE@
"""

GO_MOD = """\
module github.com/wso2/gateway-controllers/policies/@NAME@/it

go 1.26.5

require (
	github.com/cucumber/godog v0.16.0
	github.com/wso2/api-platform/tests/framework v0.3.1
	github.com/wso2/gateway-controllers/tests/it v0.0.0
)

replace github.com/wso2/gateway-controllers/tests/it => ../../../tests/it
"""

SUITE_TEST = """\
// Package it_test runs the integration tests of the @NAME@ policy.
package it_test

import (
	"testing"

	"github.com/wso2/gateway-controllers/tests/it/common/suite"

	"github.com/wso2/gateway-controllers/policies/@NAME@/it/steps"
)

var config = suite.Config{Register: steps.Register}

func TestMain(m *testing.M) {
	suite.Main(m, config)
}

// TestIntegrationSuite runs the suite declared in it-suite.yaml.
func TestIntegrationSuite(t *testing.T) {
	suite.Run(t, config)
}
"""

REGISTER = """\
// Package steps holds the step definitions only the @NAME@ policy's scenarios need. The shared
// steps in tests/it/common/steps are bound before these, so search them first and do not repeat
// one here.
package steps

import (
	"github.com/cucumber/godog"

	frameworkruntime "github.com/wso2/api-platform/tests/framework/core/runtime"
)

// Register binds the policy's own steps to the scenario.
func Register(sc *godog.ScenarioContext, topo *frameworkruntime.Topology) {
	newPolicySteps(topo).register(sc)
}
"""

POLICY_STEPS = """\
package steps

import (
	"context"

	"github.com/cucumber/godog"

	frameworkruntime "github.com/wso2/api-platform/tests/framework/core/runtime"
)

// policySteps holds the state the @NAME@ policy's steps share within one runner.
type policySteps struct {
	topo *frameworkruntime.Topology
}

func newPolicySteps(topo *frameworkruntime.Topology) *policySteps {
	return &policySteps{topo: topo}
}

// register binds the steps below. Add a step here only when no shared step expresses the
// behaviour, and give it a unit test in steps_test.go. Delete the example when the first real
// step exists.
func (s *policySteps) register(sc *godog.ScenarioContext) {
	sc.Step(`^the @NAME@ policy example step runs$`, s.exampleStep)
}

// exampleStep marks where a step of this policy goes. No feature uses it.
func (s *policySteps) exampleStep(_ context.Context) error {
	return nil
}
"""

STEPS_TEST = """\
package steps

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/cucumber/godog"
)

func TestRegisterBindsThePolicySteps(t *testing.T) {
	dir := t.TempDir()
	feature := "Feature: the policy steps\\n  Scenario: the example step is bound\\n    Given the @NAME@ policy example step runs\\n"
	if err := os.WriteFile(filepath.Join(dir, "example.feature"), []byte(feature), 0o600); err != nil {
		t.Fatal(err)
	}
	suite := godog.TestSuite{
		ScenarioInitializer: func(sc *godog.ScenarioContext) { Register(sc, nil) },
		Options:             &godog.Options{Format: "progress", Paths: []string{dir}, Strict: true, NoColors: true},
	}
	if status := suite.Run(); status != 0 {
		t.Fatalf("the example scenario did not pass, status %d", status)
	}
}
"""

FEATURE = """\
@{name}
Feature: {title} policy
  As an API developer
  I want the {name} policy to behave as documented
  So that a change to it is caught before it reaches a release

  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"

  Scenario: The policy applies to a deployed API
    Given I generate a unique value from "{name}" and store it as "apiName"
    And I generate a unique API version from "{name}" and store it as "apiVersion"
    And I generate a unique API context from "/{name}" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${{CTX:gatewaySpecVersion}} |
      | name                   | ${{CTX:apiName}}            |
      | spec.displayName       | ${{CTX:apiName}}            |
      | spec.version           | ${{CTX:apiVersion}}         |
      | spec.context           | ${{CTX:apiContext}}/$version |
      | spec.upstream.main.url | http://testbench:3000       |
      | spec.operations        | [{{"method":"GET","path":"/get","policies":[{{"name":"{name}","version":"v{major}","params":{{}}}}]}}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${{CTX:apiContext}}/${{CTX:apiVersion}}/get" until status 200
    # Put the policy's parameters in params above, then assert what the policy changes.

    When I delete the API "${{CTX:apiName}}"
    Then the response should be successful
"""


class ScaffoldError(Exception):
    """The skeleton cannot be created; nothing was written."""


def scaffold(repo_root, name, tidy=True):
    """Create the suite skeleton for policy `name` and return the paths written.

    `tidy` runs `go mod tidy` in the new module, which needs Go and network access.
    """
    if not NAME_RE.match(name):
        raise ScaffoldError(f"'{name}' is not a policy name (lowercase letters, digits and '-')")
    policy_dir = Path(repo_root) / POLICIES_DIR / name
    definition = policy_dir / "policy-definition.yaml"
    if not definition.is_file():
        raise ScaffoldError(f"policies/{name}/policy-definition.yaml does not exist")
    match = VERSION_RE.search(definition.read_text(encoding="utf-8"))
    if not match:
        raise ScaffoldError(f"policies/{name}/policy-definition.yaml has no version")

    feature_file = name.replace("-", "_") + ".feature"
    it = policy_dir / "it"

    def fill(template):
        return template.replace("@NAME@", name).replace("@FEATURE_FILE@", feature_file)

    targets = {
        it / "it-suite.yaml": LICENSE_HEADER + "\n" + fill(SUITE),
        it / "go.mod": fill(GO_MOD),
        it / "suite_test.go": GO_LICENSE_HEADER + "\n" + fill(SUITE_TEST),
        it / "steps" / "register.go": GO_LICENSE_HEADER + "\n" + fill(REGISTER),
        it / "steps" / f"{feature_file[:-len('.feature')]}_steps.go": GO_LICENSE_HEADER + "\n" + fill(POLICY_STEPS),
        it / "steps" / "steps_test.go": GO_LICENSE_HEADER + "\n" + fill(STEPS_TEST),
        it / "features" / feature_file: LICENSE_HEADER + "\n" + FEATURE.format(
            name=name, title=name.replace("-", " ").capitalize(), major=match.group(1)
        ),
    }
    existing = [str(path.relative_to(repo_root)) for path in targets if path.exists()]
    if existing:
        raise ScaffoldError("refusing to overwrite: " + ", ".join(existing))

    for path, text in targets.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    written = list(targets)
    if tidy:
        result = subprocess.run(["go", "mod", "tidy"], cwd=it, capture_output=True, text=True)
        if result.returncode != 0:
            raise ScaffoldError(
                f"created policies/{name}/it, but `go mod tidy` failed there: {result.stderr.strip()}"
            )
        written += [it / "go.sum"]
    return written


def main(argv):
    if len(argv) != 2:
        print("usage: scaffold.py <policy name>", file=sys.stderr)
        return 2
    try:
        written = scaffold(REPO_ROOT, argv[1])
    except ScaffoldError as error:
        print(f"scaffold: {error}", file=sys.stderr)
        return 1
    for path in written:
        print(f"created {path.relative_to(REPO_ROOT)}")
    print("Fill in the policy's parameters and assertions, then run: make it POLICIES=" + argv[1])
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
