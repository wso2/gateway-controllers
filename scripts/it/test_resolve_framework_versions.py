#!/usr/bin/env python3
"""Tests for resolve-framework-versions.py. Run: python3 scripts/it/test_resolve_framework_versions.py"""

import contextlib
import importlib.util
import io
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

SPEC = importlib.util.spec_from_file_location(
    "resolve_framework_versions", Path(__file__).resolve().parent / "resolve-framework-versions.py"
)
rfv = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(rfv)

LATEST = "v0.4.2"


class FakeGo:
    """Stands in for the go command: each policy's module sits on a version, and get moves it."""

    def __init__(self, versions, latest=LATEST, newest_in_line=None):
        self.versions = dict(versions)
        self.latest = latest
        self.newest_in_line = newest_in_line or {}
        self.gets = []

    def __call__(self, directory, *args, capture=False):
        policy = directory.parent.name
        if args[0] == "list":
            return self.versions[policy] if capture else ""
        target = args[1].split("@", 1)[1]
        self.gets.append((policy, target))
        self.versions[policy] = self.latest if target == "latest" else self.newest_in_line[target]
        return ""


def make_policy(root, name, mode_file=None):
    directory = root / "policies" / name / "it"
    directory.mkdir(parents=True)
    if mode_file is not None:
        (directory / rfv.MODE_FILE).write_text(mode_file, encoding="utf-8")


def run_main(root, policies, fake):
    out = io.StringIO()
    with mock.patch.object(rfv, "go", fake), contextlib.redirect_stdout(out):
        code = rfv.main([policies, "--repo-root", str(root)])
    return code, out.getvalue()


class ModeTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.path = Path(self.dir.name) / rfv.MODE_FILE
        self.addCleanup(self.dir.cleanup)

    def write(self, text):
        self.path.write_text(text, encoding="utf-8")

    def test_missing_file_is_latest(self):
        self.assertEqual("latest", rfv.read_mode(self.path))

    def test_empty_and_comment_only_files_are_latest(self):
        for text in ("", "\n\n", "# only a comment\n", "  # indented\n\n"):
            self.write(text)
            self.assertEqual("latest", rfv.read_mode(self.path), repr(text))

    def test_mode_after_comments_and_blank_lines(self):
        self.write("# How CI picks the version.\n# minor: the newest patch.\n\nminor\n")
        self.assertEqual("minor", rfv.read_mode(self.path))

    def test_trailing_comment_and_spaces_are_ignored(self):
        self.write("  pinned   # keep it\n")
        self.assertEqual("pinned", rfv.read_mode(self.path))

    def test_first_mode_wins(self):
        self.write("minor\nlatest\n")
        self.assertEqual("minor", rfv.read_mode(self.path))

    def test_unknown_value_is_returned_for_the_caller_to_reject(self):
        self.write("sometimes\n")
        self.assertEqual("sometimes", rfv.read_mode(self.path))


class MinorLineTests(unittest.TestCase):
    def test_minor_line(self):
        self.assertEqual("v0.4", rfv.minor_line("v0.4.1"))
        self.assertEqual("v1.12", rfv.minor_line("v1.12.0"))
        self.assertEqual("v0.4", rfv.minor_line("v0.4.2-rc.1"))

    def test_unreadable_version_is_an_error(self):
        with self.assertRaises(rfv.ResolveError):
            rfv.minor_line("master")


class ResolveTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.root = Path(self.dir.name)
        self.addCleanup(self.dir.cleanup)

    def resolve(self, policy, fake):
        with mock.patch.object(rfv, "go", fake):
            return rfv.resolve(self.root, policy)

    def test_no_file_follows_latest(self):
        make_policy(self.root, "cors")
        fake = FakeGo({"cors": "v0.4.1"})
        self.assertEqual(("latest", "v0.4.1", "v0.4.2"), self.resolve("cors", fake))
        self.assertEqual([("cors", "latest")], fake.gets)

    def test_latest_goes_to_the_newest_release(self):
        make_policy(self.root, "cors", "latest\n")
        fake = FakeGo({"cors": "v0.3.9"}, latest="v0.5.0")
        self.assertEqual(("latest", "v0.3.9", "v0.5.0"), self.resolve("cors", fake))

    def test_minor_stays_on_the_pinned_line(self):
        make_policy(self.root, "cors", "# note\nminor\n")
        fake = FakeGo({"cors": "v0.4.1"}, latest="v0.5.0", newest_in_line={"v0.4": "v0.4.7"})
        self.assertEqual(("minor", "v0.4.1", "v0.4.7"), self.resolve("cors", fake))
        self.assertEqual([("cors", "v0.4")], fake.gets)

    def test_pinned_runs_no_go_get(self):
        make_policy(self.root, "cors", "pinned\n")
        fake = FakeGo({"cors": "v0.4.1"})
        self.assertEqual(("pinned", "v0.4.1", "v0.4.1"), self.resolve("cors", fake))
        self.assertEqual([], fake.gets)

    def test_unknown_mode_names_the_file_and_runs_no_go(self):
        make_policy(self.root, "cors", "sometimes\n")
        fake = FakeGo({"cors": "v0.4.1"})
        with self.assertRaises(rfv.ResolveError) as raised:
            self.resolve("cors", fake)
        self.assertEqual("policies/cors/it/framework-version", raised.exception.file)
        self.assertIn("sometimes", str(raised.exception))
        self.assertEqual([], fake.gets)

    def test_missing_policy_is_an_error(self):
        with self.assertRaises(rfv.ResolveError) as raised:
            self.resolve("nope", FakeGo({}))
        self.assertIn("policies/nope/it", str(raised.exception))


class MainTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.root = Path(self.dir.name)
        self.addCleanup(self.dir.cleanup)

    def test_each_policy_is_resolved_by_its_own_mode(self):
        make_policy(self.root, "cors", "pinned\n")
        make_policy(self.root, "basic-auth")
        fake = FakeGo({"cors": "v0.4.1", "basic-auth": "v0.4.1"})
        code, output = run_main(self.root, "cors, basic-auth,,", fake)
        self.assertEqual(0, code)
        self.assertEqual(
            ["cors: pinned, framework v0.4.1 -> v0.4.1", "basic-auth: latest, framework v0.4.1 -> v0.4.2"],
            output.splitlines(),
        )

    def test_unknown_mode_fails_with_an_annotation_and_stops(self):
        make_policy(self.root, "cors", "sometimes\n")
        make_policy(self.root, "basic-auth")
        fake = FakeGo({"cors": "v0.4.1", "basic-auth": "v0.4.1"})
        code, output = run_main(self.root, "cors,basic-auth", fake)
        self.assertEqual(1, code)
        self.assertEqual(
            "::error file=policies/cors/it/framework-version::unknown mode 'sometimes', use latest, minor, pinned",
            output.strip(),
        )
        self.assertEqual([], fake.gets)

    def test_missing_policy_fails_with_an_annotation(self):
        code, output = run_main(self.root, "nope", FakeGo({}))
        self.assertEqual(1, code)
        self.assertEqual("::error::policies/nope/it does not exist", output.strip())

    def test_a_failing_go_command_fails_the_run(self):
        make_policy(self.root, "cors")

        def failing(directory, *args, capture=False):
            raise subprocess.CalledProcessError(1, ["go", *args])

        code, output = run_main(self.root, "cors", failing)
        self.assertEqual(1, code)
        self.assertIn("::error::cors: go list failed", output)

    def test_no_policy_is_a_usage_error(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as raised:
            rfv.main([" , ", "--repo-root", str(self.root)])
        self.assertEqual(2, raised.exception.code)


if __name__ == "__main__":
    unittest.main()
