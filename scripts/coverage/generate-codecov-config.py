#!/usr/bin/env python3
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
"""Generate the per-policy Codecov components in codecov.yml from the policy Go modules.

One component per policy module: policies/<name> and, for a major version released beside v1,
policies/<name>/v<N> (component id <name>-v<N>). The list is written between the
BEGIN/END GENERATED markers of codecov.yml; the rest of the file is hand-written.

A policy that has a nested version module owns only its own files: its component lists the
root *.go files and its own package directories, not the nested module's directory.

Usage:
  generate-codecov-config.py            # rewrite the component list in codecov.yml
  generate-codecov-config.py --validate # exit 1 if codecov.yml is out of date
"""

import os
import re
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
CODECOV = os.path.join(ROOT, "codecov.yml")
POLICIES = os.path.join(ROOT, "policies")
BEGIN = "    # >>> BEGIN GENERATED POLICY COMPONENTS (scripts/coverage/generate-codecov-config.py)"
END = "    # <<< END GENERATED POLICY COMPONENTS"


def policy_modules():
    """Return the repository-relative directory of every policy Go module, sorted."""
    modules = []
    for dirpath, dirnames, filenames in os.walk(POLICIES):
        # An "it" directory is the integration suite, a separate module that is not policy code.
        dirnames[:] = sorted(d for d in dirnames if d != "it" and not d.startswith("."))
        if "go.mod" in filenames:
            modules.append(os.path.relpath(dirpath, ROOT).replace(os.sep, "/"))
    return sorted(modules)


def component_paths(module, modules):
    """Return the path globs that belong to `module` and not to a module nested in it."""
    nested = [m for m in modules if m != module and m.startswith(module + "/")]
    if not nested:
        return [f"{module}/**"]
    paths = [f"{module}/*.go"]
    for entry in sorted(os.listdir(os.path.join(ROOT, module))):
        child = f"{module}/{entry}"
        if not os.path.isdir(os.path.join(ROOT, child)) or entry == "it" or entry.startswith("."):
            continue
        if any(m == child or m.startswith(child + "/") for m in nested):
            continue
        paths.append(f"{child}/**")
    return paths


def render(modules):
    lines = []
    for module in modules:
        name = module[len("policies/"):].replace("/", "-")
        lines.append(f"    - component_id: {name}")
        lines.append(f"      name: {name}")
        lines.append("      paths:")
        lines.extend(f"        - {path}" for path in component_paths(module, modules))
    return "\n".join(lines)


def generate(current):
    pattern = re.compile(re.escape(BEGIN) + r"\n.*?" + re.escape(END), re.DOTALL)
    if not pattern.search(current):
        sys.exit(f"{CODECOV}: BEGIN/END GENERATED POLICY COMPONENTS markers not found")
    block = f"{BEGIN}\n{render(policy_modules())}\n{END}"
    return pattern.sub(lambda _: block, current)


def main(argv):
    with open(CODECOV, encoding="utf-8") as f:
        current = f.read()
    updated = generate(current)
    if "--validate" in argv:
        if updated != current:
            print("codecov.yml is out of date. Run: make generate-codecov-config", file=sys.stderr)
            return 1
        print("codecov.yml is up to date")
        return 0
    with open(CODECOV, "w", encoding="utf-8") as f:
        f.write(updated)
    print(f"wrote {len(policy_modules())} policy components to codecov.yml")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
