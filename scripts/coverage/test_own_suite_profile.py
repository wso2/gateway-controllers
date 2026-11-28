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
"""Tests for own-suite-profile.py."""

import importlib.util
import pathlib
import subprocess
import sys
import tempfile
import unittest

_spec = importlib.util.spec_from_file_location(
    "own_suite_profile", pathlib.Path(__file__).with_name("own-suite-profile.py")
)
own = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(own)
summarize = own.summarize

MOD = "github.com/wso2/gateway-controllers/policies"

# Every block of every policy, as the merged profile of all runs lists it: set-headers is counted
# as run (7) because another policy's suite attaches it, and so is a block of basic-auth.
ALL = [
    "mode: atomic",
    f"{MOD}/basic-auth/a.go:1.1,2.1 4 5",
    f"{MOD}/basic-auth/a.go:3.1,4.1 6 2",
    f"{MOD}/set-headers/s.go:1.1,2.1 10 7",
    f"{MOD}/backend-jwt/j.go:1.1,2.1 3 9",
    f"{MOD}/backend-jwt/v2/j.go:1.1,2.1 5 9",
]
# What the suite of basic-auth recorded: its own block 1 ran, block 2 did not, and it also ran
# set-headers' block, which must not be credited to set-headers.
BASIC_AUTH = [
    "mode: atomic",
    f"{MOD}/basic-auth/a.go:1.1,2.1 4 3",
    f"{MOD}/basic-auth/a.go:3.1,4.1 6 0",
    f"{MOD}/set-headers/s.go:1.1,2.1 10 4",
]
V2 = [
    "mode: atomic",
    f"{MOD}/backend-jwt/v2/j.go:1.1,2.1 5 1",
    f"{MOD}/backend-jwt/j.go:1.1,2.1 3 1",
]


class OwnSuiteProfileTest(unittest.TestCase):
    def totals(self, suites):
        return summarize.parse(own.build(ALL, suites))

    def test_a_policy_is_covered_by_its_own_suite_only(self):
        totals = self.totals({"basic-auth": BASIC_AUTH})
        self.assertEqual(totals["basic-auth"], [4, 10])

    def test_a_policy_without_a_suite_stays_in_the_report_at_zero(self):
        totals = self.totals({"basic-auth": BASIC_AUTH})
        self.assertEqual(totals["set-headers"], [0, 10])
        self.assertEqual(totals["backend-jwt"], [0, 3])

    def test_a_policy_whose_suite_left_no_counters_is_zero_not_dropped(self):
        totals = self.totals({"basic-auth": ["mode: atomic"]})
        self.assertEqual(totals["basic-auth"], [0, 10])

    def test_a_version_module_is_its_own_policy(self):
        totals = self.totals({"backend-jwt/v2": V2})
        self.assertEqual(totals["backend-jwt/v2"], [5, 5])
        self.assertEqual(totals["backend-jwt"], [0, 3], "v2's suite does not credit v1")

    def test_the_mode_of_the_merged_profile_is_kept(self):
        self.assertEqual(own.build(ALL, {})[0], "mode: atomic")
        self.assertEqual(own.build(["mode: set", *ALL[1:]], {})[0], "mode: set")

    def test_the_command_reads_the_folder_and_writes_the_profile(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = pathlib.Path(tmp)
            (base / "suite").mkdir()
            (base / "all.txt").write_text("\n".join(ALL) + "\n")
            (base / "suite" / "basic-auth.txt").write_text("\n".join(BASIC_AUTH) + "\n")
            (base / "suite" / "backend-jwt__v2.txt").write_text("\n".join(V2) + "\n")
            target = base / "coverage.txt"
            done = subprocess.run(
                [sys.executable, str(pathlib.Path(__file__).with_name("own-suite-profile.py")), str(base), str(target)],
                capture_output=True, text=True,
            )
            self.assertEqual(done.returncode, 0, done.stderr)
            totals = summarize.parse(target.read_text().splitlines())
            self.assertEqual(totals["basic-auth"], [4, 10])
            self.assertEqual(totals["backend-jwt/v2"], [5, 5])
            self.assertEqual(totals["set-headers"], [0, 10])
            self.assertIn("2 policies credited", done.stdout)


if __name__ == "__main__":
    unittest.main()
