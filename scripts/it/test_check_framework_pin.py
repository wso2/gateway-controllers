#!/usr/bin/env python3
"""Tests for check-framework-pin.py. Run: python3 scripts/it/test_check_framework_pin.py"""

import importlib.util
import tempfile
import unittest
from pathlib import Path

SPEC = importlib.util.spec_from_file_location(
    "check_framework_pin", Path(__file__).resolve().parent / "check-framework-pin.py"
)
cfp = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(cfp)

FRAMEWORK = "github.com/wso2/api-platform/tests/framework"


def write(root, relative, text):
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def framework_mod(version="v0.4.2", extra=""):
    return f"module github.com/wso2/gateway-controllers/tests/it\n\ngo 1.26.5\n\nrequire {FRAMEWORK} {version}\n{extra}"


def suite_mod(name, extra=""):
    return f"module github.com/wso2/gateway-controllers/policies/{name}/it\n\ngo 1.26.5\n{extra}"


def repo(root, suites=("cors", "jwt-auth"), tests_mod=None, suite_extra=None):
    write(root, "tests/it/go.mod", tests_mod if tests_mod is not None else framework_mod())
    for name in suites:
        write(root, f"policies/{name}/it/go.mod", suite_mod(name, (suite_extra or {}).get(name, "")))


class FrameworkLinesTests(unittest.TestCase):
    def test_finds_a_require_in_a_block_and_on_one_line(self):
        self.assertEqual((["v0.4.2"], 0), cfp.framework_lines(f"require (\n\t{FRAMEWORK} v0.4.2\n)\n"))
        self.assertEqual((["v1.0.0"], 0), cfp.framework_lines(f"require {FRAMEWORK} v1.0.0\n"))

    def test_counts_replace_lines_in_every_form(self):
        text = f"replace {FRAMEWORK} => ../framework\nreplace (\n\t{FRAMEWORK} v0.4.2 => ../framework\n)\n"
        self.assertEqual(([], 2), cfp.framework_lines(text))

    def test_ignores_comments_and_packages_of_the_framework(self):
        text = f"// require {FRAMEWORK} v0.4.2\ntool {FRAMEWORK}/cmd/standards\n{FRAMEWORK}/core v0.4.2\n"
        self.assertEqual(([], 0), cfp.framework_lines(text))


class CheckTests(unittest.TestCase):
    def check(self, **kwargs):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo(root, **kwargs)
            return cfp.check(root)

    def test_a_repository_with_one_pin_passes(self):
        self.assertEqual([], self.check())

    def test_a_suite_that_names_the_framework_again_fails(self):
        problems = self.check(suite_extra={"cors": f"\nrequire {FRAMEWORK} v0.4.2\n"})
        self.assertEqual(1, len(problems))
        self.assertIn("policies/cors/it/go.mod mentions", problems[0])

    def test_a_suite_that_replaces_the_framework_fails(self):
        problems = self.check(suite_extra={"jwt-auth": f"\nreplace {FRAMEWORK} => ../../../../framework\n"})
        self.assertIn("policies/jwt-auth/it/go.mod mentions", problems[0])

    def test_tests_it_must_require_the_framework_once(self):
        problems = self.check(tests_mod="module x\n\ngo 1.26.5\n")
        self.assertIn("exactly once", problems[0])

    def test_tests_it_must_pin_a_tagged_release(self):
        for version in ("v0.4.3-rc1", "v0.1.1-0.20261014000000-abcdef123456"):
            with self.subTest(version=version):
                problems = self.check(tests_mod=framework_mod(version))
                self.assertIn("not a tagged release", problems[0])

    def test_tests_it_must_not_replace_the_framework(self):
        problems = self.check(tests_mod=framework_mod(extra=f"replace {FRAMEWORK} => ../../../api-platform/tests/framework\n"))
        self.assertIn("replaces", problems[0])

    def test_the_repository_itself_passes(self):
        self.assertEqual([], cfp.check(cfp.REPO_ROOT))


if __name__ == "__main__":
    unittest.main()
