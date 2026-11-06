#!/usr/bin/env python3
"""Tests for generate-workspace.py. Run: python3 scripts/it/test_generate_workspace.py"""

import importlib.util
import os
import tempfile
import unittest
from pathlib import Path

SPEC = importlib.util.spec_from_file_location(
    "generate_workspace", Path(__file__).resolve().parent / "generate-workspace.py"
)
gw = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gw)


def write(root, relative, text="x\n"):
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def repo(root, suites=("jwt-auth", "cors")):
    write(root, "tests/it/go.mod", "module github.com/wso2/gateway-controllers/tests/it\n\ngo 1.26.5\n")
    for name in suites:
        write(root, f"policies/{name}/it/go.mod", f"module x/{name}/it\n\ngo 1.26.5\n")


class GenerateWorkspaceTests(unittest.TestCase):
    def setUp(self):
        self._dir = tempfile.TemporaryDirectory()
        self.root = Path(self._dir.name)
        self.addCleanup(self._dir.cleanup)

    def test_lists_tests_it_and_every_suite_in_order(self):
        repo(self.root)

        self.assertEqual(
            "go 1.26.5\n\nuse (\n\t.\n\t../../policies/cors/it\n\t../../policies/jwt-auth/it\n)\n",
            gw.render(self.root),
        )

    def test_lists_a_major_version_suite_beside_v1(self):
        repo(self.root, suites=("backend-jwt",))
        write(self.root, "policies/backend-jwt/v2/it/go.mod", "module x/backend-jwt/v2/it\n\ngo 1.26.5\n")

        self.assertEqual(["backend-jwt", "backend-jwt/v2"], gw.suite_names(self.root))
        self.assertIn("\t../../policies/backend-jwt/v2/it\n", gw.render(self.root))

    def test_takes_the_go_version_from_tests_it(self):
        repo(self.root)
        write(self.root, "tests/it/go.mod", "module x\n\ngo 1.27.1\n")

        self.assertTrue(gw.render(self.root).startswith("go 1.27.1\n"))

    def test_leaves_out_policies_without_a_suite_and_the_policy_module_itself(self):
        repo(self.root, suites=("cors",))
        write(self.root, "policies/cors/go.mod")
        write(self.root, "policies/no-suite/go.mod")
        write(self.root, "policies/no-suite/policy-definition.yaml")

        self.assertEqual(["cors"], gw.suite_names(self.root))

    def test_a_suite_added_later_is_picked_up_without_any_edit(self):
        repo(self.root, suites=("cors",))
        self.assertNotIn("new-policy", gw.render(self.root))

        write(self.root, "policies/new-policy/it/go.mod")

        self.assertIn("\t../../policies/new-policy/it\n", gw.render(self.root))

    def test_requires_the_go_directive_of_tests_it(self):
        write(self.root, "tests/it/go.mod", "module x\n")

        with self.assertRaises(ValueError):
            gw.render(self.root)

    def test_writes_the_file_and_leaves_an_unchanged_one_alone(self):
        repo(self.root)
        path = gw.write(self.root)
        self.assertEqual(self.root / "tests/it/it.work", path)
        self.assertEqual(gw.render(self.root), path.read_text())

        os.utime(path, (1_000_000, 1_000_000))
        gw.write(self.root)
        self.assertEqual(1_000_000, int(path.stat().st_mtime), "an unchanged file is not rewritten")

        write(self.root, "policies/new-policy/it/go.mod")
        gw.write(self.root)
        self.assertIn("new-policy", path.read_text())


if __name__ == "__main__":
    unittest.main()
