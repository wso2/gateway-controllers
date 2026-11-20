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
"""Summarise Go coverage profiles as a policy-wise Markdown table plus the global figure.

Reads the merged profile written by run-unit-coverage.sh (or any Go cover profile whose file
paths are module paths under github.com/wso2/gateway-controllers/policies/) and prints Markdown
suitable for $GITHUB_STEP_SUMMARY. This mirrors what Codecov reports per component, so the same
figures are readable straight from the run, including on pull requests from forks where the
Codecov upload has no token.

Coverage is statement-weighted: covered statements over all statements. The global figure is
computed over every statement of every policy, not as the mean of the policy percentages, so a
large policy weighs more than a small one, as it does in Codecov.

Usage:
  summarize-coverage.py coverage/coverage.txt >> "$GITHUB_STEP_SUMMARY"
"""

import re
import sys
from collections import defaultdict

# policies/<name>/<file-or-package>... or, for a major version released beside v1,
# policies/<name>/v<N>/<file-or-package>... A v<N> directory directly under a policy is always a
# version module: Go source files in a policy's root never are named like that.
POLICY_PATH = re.compile(r"policies/(?P<name>[^/]+)(?:/(?P<version>v\d+)(?=/))?/")
BLOCK = re.compile(r"^(?P<file>.+):\d+\.\d+,\d+\.\d+ (?P<stmts>\d+) (?P<count>\d+)$")


def policy_of(path):
    match = POLICY_PATH.search(path)
    if not match:
        return None
    name = match.group("name")
    return f"{name}/{match.group('version')}" if match.group("version") else name


def parse(lines):
    """Return {policy: [covered, total]} from the lines of a Go cover profile."""
    blocks = {}
    for line in lines:
        line = line.strip()
        if not line or line.startswith("mode:"):
            continue
        match = BLOCK.match(line)
        if not match:
            continue
        key = line.rsplit(" ", 2)[0]
        stmts, count = int(match.group("stmts")), int(match.group("count"))
        previous = blocks.get(key)
        blocks[key] = (match.group("file"), stmts, max(count, previous[2]) if previous else count)

    totals = defaultdict(lambda: [0, 0])
    for file, stmts, count in blocks.values():
        policy = policy_of(file)
        if policy is None:
            continue
        totals[policy][1] += stmts
        if count > 0:
            totals[policy][0] += stmts
    return totals


def percent(covered, total):
    return 100.0 * covered / total if total else 0.0


def render(totals):
    covered = sum(c for c, _ in totals.values())
    total = sum(t for _, t in totals.values())
    out = [
        "## Policy unit-test coverage",
        "",
        f"**Global coverage: {percent(covered, total):.1f}%** "
        f"({covered:,} of {total:,} statements, {len(totals)} policies)",
        "",
        "| Policy | Coverage | Covered / statements |",
        "| --- | ---: | ---: |",
    ]
    for policy in sorted(totals):
        c, t = totals[policy]
        out.append(f"| {policy} | {percent(c, t):.1f}% | {c:,} / {t:,} |")
    out.append("")
    return "\n".join(out)


def main(argv):
    if len(argv) != 2:
        print(__doc__, file=sys.stderr)
        return 2
    with open(argv[1], encoding="utf-8") as profile:
        totals = parse(profile)
    if not totals:
        print(f"no policy coverage found in {argv[1]}", file=sys.stderr)
        return 1
    print(render(totals))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
