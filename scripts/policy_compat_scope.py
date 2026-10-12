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
"""Decide whether a pull request needs api-platform's policy error compatibility blocks.

The blocks build a gateway with every policy in this checkout, which costs far more than the
scenarios themselves, so the run is skipped when it cannot catch anything:

- none of the changed policies, or the policies that delegate to them, has a scenario; or
- on a released gateway, the release ships none of them, so none would be built.

A scenario's policy is the first word of its title in api-platform's
tests/framework/suites/it/features/gateway/policy-errors/*.feature. A policy delegates to
another when its go.mod requires the other's module.

Anything the script cannot narrow safely runs the blocks: no list of changed files, a change
under policies/ outside a policy's own directory, a change to the workflow or this script, or a
released gateway whose build manifest could not be read.

Prints "run=true" or "run=false", for $GITHUB_OUTPUT, and the reason on stderr.

Usage:
    python3 scripts/policy_compat_scope.py --policies policies \\
        --features ../api-platform/tests/framework/suites/it/features/gateway/policy-errors \\
        [--changed-files changed.txt] [--release-manifest build-manifest.yaml]
"""

import argparse
import re
import sys
from pathlib import Path

# Changes that alter how the blocks run, so every scenario must run.
ALWAYS_RUN_FILES = {".github/workflows/it.yml", "scripts/policy_compat_scope.py"}

SCENARIO = re.compile(r"^\s*Scenario(?: Outline)?:\s*(\S+)")
MODULE = re.compile(r"^module\s+(\S+)", re.MULTILINE)
MANIFEST_NAME = re.compile(r"^\s*-\s*name:\s*([A-Za-z0-9._-]+)\s*$", re.MULTILINE)


def scenario_policies(features_dir):
    """Returns the policies the compat scenarios cover."""
    names = set()
    for feature in sorted(Path(features_dir).glob("*.feature")):
        for line in feature.read_text(encoding="utf-8").splitlines():
            match = SCENARIO.match(line)
            if match:
                names.add(match.group(1))
    return names


def changed_policies(changed_files):
    """Returns the changed policy directories, or None when a change is not confined to one."""
    changed = set()
    for path in changed_files:
        if path in ALWAYS_RUN_FILES:
            return None
        parts = path.split("/")
        if parts[0] != "policies":
            continue
        if len(parts) < 3:
            return None
        changed.add(parts[1])
    return changed


def go_modules(policies_dir):
    """Returns each Go policy's module path and the text of its go.mod."""
    modules = {}
    for gomod in sorted(Path(policies_dir).glob("*/go.mod")):
        text = gomod.read_text(encoding="utf-8")
        match = MODULE.search(text)
        if match:
            modules[gomod.parent.name] = (match.group(1), text)
    return modules


def with_delegators(changed, modules):
    """Adds every policy that requires a changed policy's module, transitively."""
    affected = set(changed)
    grew = True
    while grew:
        grew = False
        required = {modules[name][0] for name in affected if name in modules}
        for name, (own, text) in modules.items():
            if name in affected:
                continue
            for module in required:
                if module == own:
                    continue
                if re.search(r"(?m)^\s*(?:require\s+)?" + re.escape(module) + r"\s+v", text):
                    affected.add(name)
                    grew = True
                    break
    return affected


def released_policies(manifest_path):
    """Returns the policies a released gateway's build manifest lists, or None if unreadable."""
    try:
        text = Path(manifest_path).read_text(encoding="utf-8")
    except OSError:
        return None
    names = set(MANIFEST_NAME.findall(text))
    return names or None


def decide(args):
    """Returns (run, reason)."""
    if args.changed_files is None:
        return True, "no list of changed files; running every scenario"
    try:
        lines = Path(args.changed_files).read_text(encoding="utf-8").splitlines()
    except OSError:
        return True, "the changed files could not be read; running every scenario"
    changed = changed_policies([line.strip() for line in lines if line.strip()])
    if changed is None:
        return True, "the change is not confined to individual policies; running every scenario"

    affected = with_delegators(changed, go_modules(args.policies))
    covered = scenario_policies(args.features)
    if not covered:
        return True, "no compat scenarios were found; running every scenario"
    relevant = affected & covered
    if not relevant:
        return False, "no changed policy, or policy delegating to one, has a compat scenario: " + (
            ", ".join(sorted(affected)) or "none changed")

    if args.release_manifest is not None:
        shipped = released_policies(args.release_manifest)
        if shipped is None:
            return True, "the release's build manifest could not be read; running every scenario"
        relevant &= shipped
        if not relevant:
            return False, "this release ships none of the changed policies with a compat scenario"
    return True, "compat scenarios cover: " + ", ".join(sorted(relevant))


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--policies", required=True, help="this repository's policies directory")
    parser.add_argument("--features", required=True, help="api-platform's policy-errors feature directory")
    parser.add_argument("--changed-files", help="file listing the pull request's changed paths, one per line")
    parser.add_argument("--release-manifest", help="the released gateway's build-manifest.yaml")
    run, reason = decide(parser.parse_args())
    print(reason, file=sys.stderr)
    print("run=" + ("true" if run else "false"))


if __name__ == "__main__":
    main()
