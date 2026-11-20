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
"""Tests for summarize-coverage.py."""

import importlib.util
import pathlib
import unittest

_spec = importlib.util.spec_from_file_location(
    "summarize_coverage", pathlib.Path(__file__).with_name("summarize-coverage.py")
)
summarize = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(summarize)

MOD = "github.com/wso2/gateway-controllers/policies"

PROFILE = f"""mode: set
{MOD}/basic-auth/basicauth.go:10.2,12.1 4 1
{MOD}/basic-auth/basicauth.go:14.2,16.1 6 0
{MOD}/backend-jwt/backendjwt.go:10.2,12.1 10 1
{MOD}/backend-jwt/v2/backendjwt.go:10.2,12.1 5 0
{MOD}/backend-jwt/v2/util/util.go:3.2,4.1 5 1
{MOD}/untested/untested.go:3.2,4.1 8 0
"""


class SummarizeTest(unittest.TestCase):
    def test_policy_of(self):
        self.assertEqual(summarize.policy_of(f"{MOD}/basic-auth/basicauth.go"), "basic-auth")
        self.assertEqual(summarize.policy_of(f"{MOD}/backend-jwt/backendjwt.go"), "backend-jwt")
        self.assertEqual(summarize.policy_of(f"{MOD}/backend-jwt/v2/util/util.go"), "backend-jwt/v2")
        self.assertIsNone(summarize.policy_of("github.com/other/module/file.go"))

    def test_parse_groups_statements_per_policy(self):
        totals = summarize.parse(PROFILE.splitlines())
        self.assertEqual(totals["basic-auth"], [4, 10])
        self.assertEqual(totals["backend-jwt"], [10, 10])
        self.assertEqual(totals["backend-jwt/v2"], [5, 10])
        self.assertEqual(totals["untested"], [0, 8])

    def test_duplicate_blocks_count_once_and_keep_the_highest_count(self):
        profile = [
            "mode: set",
            f"{MOD}/a/a.go:1.1,2.1 3 0",
            f"{MOD}/a/a.go:1.1,2.1 3 2",
        ]
        self.assertEqual(summarize.parse(profile)["a"], [3, 3])

    def test_global_is_statement_weighted_not_a_mean_of_percentages(self):
        report = summarize.render(summarize.parse(PROFILE.splitlines()))
        # 19 of 38 statements: 50.0%. The mean of 40/100/50/0 would be 47.5%.
        self.assertIn("**Global coverage: 50.0%** (19 of 38 statements, 4 policies)", report)
        self.assertIn("| basic-auth | 40.0% | 4 / 10 |", report)
        self.assertIn("| untested | 0.0% | 0 / 8 |", report)

    def test_lists_policies_below_the_minimum_lowest_first(self):
        report = summarize.render(summarize.parse(PROFILE.splitlines()))
        self.assertIn("**3 of 4 policies are below the 80% minimum:**", report)
        self.assertLess(report.index("- untested: 0.0%"), report.index("- basic-auth: 40.0%"))
        self.assertNotIn("- backend-jwt: ", report)

    def test_reports_when_every_policy_meets_the_minimum(self):
        report = summarize.render(summarize.parse([f"{MOD}/a/a.go:1.1,2.1 5 1"]))
        self.assertIn("Every policy meets the 80% minimum.", report)

    def test_collapse_folds_the_table_but_not_the_global_figure(self):
        report = summarize.render(summarize.parse(PROFILE.splitlines()), collapse=True)
        self.assertLess(report.index("**Global coverage"), report.index("<details>"))
        self.assertLess(report.index("<details>"), report.index("| basic-auth |"))
        self.assertTrue(report.rstrip().endswith("</details>"))


if __name__ == "__main__":
    unittest.main()
