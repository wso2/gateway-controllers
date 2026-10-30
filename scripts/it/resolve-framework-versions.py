#!/usr/bin/env python3
"""
Resolve the test framework version each selected policy's integration suite runs on.

Each policy's suite is a Go module in policies/<name>/it that records one exact framework version in
its go.mod. A policy picks how its suite follows framework releases in policies/<name>/it/framework-version,
a file whose first line that is not blank or a comment holds one of:

  latest  the newest framework release overall; the default, also when the file is missing or empty
  minor   the newest release of the minor line its go.mod pins, v0.4.1 becoming the newest v0.4.x
  pinned  the version already in its go.mod

latest and minor run go get in the policy's it module. The result stays in the workspace and is
never committed back. Any other value fails the run.

Usage: resolve-framework-versions.py <policy>[,<policy>...]
"""

import argparse
import re
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
FRAMEWORK = "github.com/wso2/api-platform/tests/framework"
MODE_FILE = "framework-version"
DEFAULT_MODE = "latest"
MODES = ("latest", "minor", "pinned")

# The major and minor of a version, v0.4.2 giving v0.4.
MINOR_RE = re.compile(r"^(v\d+\.\d+)\.")


class ResolveError(Exception):
    """A failure to report as a GitHub annotation, on file when it names one."""

    def __init__(self, message, file=None):
        super().__init__(message)
        self.file = file


def go(directory, *args, capture=False):
    """Run the go command in directory, returning its output when capture is set."""
    result = subprocess.run(["go", *args], cwd=directory, check=True, text=True, stdout=subprocess.PIPE if capture else None)
    return result.stdout.strip() if capture else ""


def read_mode(path):
    """The mode a policy's framework-version file names: its first line that is not blank or a comment."""
    if path.is_file():
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.split("#", 1)[0].strip()
            if line:
                return line
    return DEFAULT_MODE


def minor_line(version):
    """The major and minor of a version, which go get reads as the newest release of that line."""
    match = MINOR_RE.match(version)
    if not match:
        raise ResolveError(f"cannot read the minor line of framework version {version!r}")
    return match.group(1)


def module_version(directory):
    return go(directory, "list", "-m", "-f", "{{.Version}}", FRAMEWORK, capture=True)


def resolve(repo_root, policy):
    """Move the policy's suite module to the framework version its mode picks, and report what happened."""
    directory = repo_root / "policies" / policy / "it"
    if not directory.is_dir():
        raise ResolveError(f"policies/{policy}/it does not exist")

    mode_file = f"policies/{policy}/it/{MODE_FILE}"
    mode = read_mode(directory / MODE_FILE)
    if mode not in MODES:
        raise ResolveError(f"unknown mode '{mode}', use {', '.join(MODES)}", mode_file)

    before = module_version(directory)
    if mode == "latest":
        go(directory, "get", f"{FRAMEWORK}@latest")
    elif mode == "minor":
        go(directory, "get", f"{FRAMEWORK}@{minor_line(before)}")
    return mode, before, module_version(directory)


def annotation(error):
    where = f" file={error.file}" if error.file else ""
    return f"::error{where}::{error}"


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("policies", help="comma-separated policies whose suites to resolve")
    parser.add_argument("--repo-root", type=Path, default=REPO_ROOT)
    args = parser.parse_args(argv)

    names = [name.strip() for name in args.policies.split(",") if name.strip()]
    if not names:
        parser.error("no policy given")

    for policy in names:
        try:
            mode, before, after = resolve(args.repo_root, policy)
        except ResolveError as error:
            print(annotation(error))
            return 1
        except subprocess.CalledProcessError as error:
            print(f"::error::{policy}: go {error.cmd[1]} failed with exit code {error.returncode}")
            return 1
        print(f"{policy}: {mode}, framework {before} -> {after}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
