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
"""Build the coverage profile in which each policy is covered only by its own integration suite.

Every suite runs on one gateway that carries all the policies, so the counters of a run also record
code of policies the suite merely uses (set-headers on another policy's API) or that runs whenever
the gateway starts. Crediting those to the policies would report coverage nobody wrote a test for.

Inputs, in <dir> (written by it-coverage-report.sh from the counters of the runs):
  all.txt          the profile of every run merged: it lists every block of every policy
  suite/<name>.txt the profile of the runs that one policy's suite started, <name> being the
                   policy with a slash written as "__" (backend-jwt/v2 is backend-jwt__v2)

For every block in all.txt, the output takes the count from the suite of the policy that owns the
block, and 0 when that policy has no suite or its suite left no counters. A policy therefore stays
in the report, at 0%, instead of dropping out of it.

Usage:
  own-suite-profile.py <dir> <out-file>
"""

import importlib.util
import os
import pathlib
import sys

_spec = importlib.util.spec_from_file_location(
    "summarize_coverage", pathlib.Path(__file__).with_name("summarize-coverage.py")
)
summarize = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(summarize)


def split(line):
    """(file, key, count) of a profile line, or None. The key names the block: file, range, statements."""
    line = line.strip()
    match = summarize.BLOCK.match(line)
    if not match:
        return None
    return match.group("file"), line.rsplit(" ", 1)[0], int(match.group("count"))


def own_counts(lines, policy):
    """{block key: count} of the blocks of `policy` in a profile."""
    counts = {}
    for line in lines:
        parsed = split(line)
        if parsed and summarize.policy_of(parsed[0]) == policy:
            counts[parsed[1]] = max(counts.get(parsed[1], 0), parsed[2])
    return counts


def build(all_lines, suites):
    """The profile lines. `suites` maps a policy to the lines of the profile of its suite's runs."""
    own = {policy: own_counts(lines, policy) for policy, lines in suites.items()}
    out, mode = [], "mode: atomic"
    for line in all_lines:
        if line.startswith("mode:"):
            mode = line.strip()
            continue
        parsed = split(line)
        if not parsed:
            continue
        file, key, _ = parsed
        counts = own.get(summarize.policy_of(file))
        out.append(f"{key} {counts.get(key, 0) if counts else 0}")
    return [mode, *out]


def main(argv):
    if len(argv) != 3:
        print(__doc__, file=sys.stderr)
        return 2
    base, target = pathlib.Path(argv[1]), argv[2]
    all_lines = (base / "all.txt").read_text(encoding="utf-8").splitlines()
    suites = {}
    for path in sorted((base / "suite").glob("*.txt")):
        policy = path.stem.replace("__", "/")
        suites[policy] = path.read_text(encoding="utf-8").splitlines()
    profile = build(all_lines, suites)
    with open(target, "w", encoding="utf-8") as out:
        out.write("\n".join(profile) + "\n")

    totals = summarize.parse(profile)
    credited = {p for p in suites if own_counts(suites[p], p)}
    for policy in sorted(suites):
        if policy not in credited:
            print(f"own-suite-profile: the suite of {policy} left no counters for its own code", file=sys.stderr)
    without = sorted(set(totals) - set(suites))
    print(f"own-suite-profile: {len(credited)} policies credited from their own suite, "
          f"{len(without)} without a suite of their own reported at 0%")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
