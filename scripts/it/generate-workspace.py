#!/usr/bin/env python3
"""
Write the Go workspace file that joins tests/it and every policy's integration suite module.

  python3 scripts/it/generate-workspace.py      (or: make it-workspace)

All suites run on one version of the test framework, the one tests/it/go.mod requires, and a suite's
own go.mod does not name it. The workspace file tests/it/it.work is what lets Go resolve the framework
for a suite from tests/it/go.mod. It lists tests/it and every policies/<name>/it that has a go.mod, so
it is generated from the folders on every run of the make targets and is not committed: a new suite is
picked up without editing anything. It is not named go.work, so a go command run in a policy's own
module, which the workspace does not list, is left alone. The Go version is the one tests/it/go.mod
declares. The file is rewritten only when its content changes.
"""

import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
WORKSPACE = Path("tests/it/it.work")
GO_VERSION_RE = re.compile(r"^go\s+(\S+)\s*$", re.MULTILINE)


def suite_names(repo_root):
    """Suite ids: <name>, and <name>/v<N> for a major version released beside v1."""
    policies = Path(repo_root) / "policies"
    found = [path.parent.parent for path in policies.glob("*/it/go.mod")]
    found += [path.parent.parent for path in policies.glob("*/v[0-9]*/it/go.mod")]
    return sorted(path.relative_to(policies).as_posix() for path in found)


def render(repo_root):
    """Return the text of the workspace file for the suites under repo_root."""
    go_mod = Path(repo_root) / "tests" / "it" / "go.mod"
    match = GO_VERSION_RE.search(go_mod.read_text(encoding="utf-8")) if go_mod.is_file() else None
    if not match:
        raise ValueError("tests/it/go.mod has no go directive")
    lines = [f"go {match.group(1)}", "", "use (", "\t."]
    lines += [f"\t../../policies/{name}/it" for name in suite_names(repo_root)]
    lines.append(")")
    return "\n".join(lines) + "\n"


def write(repo_root):
    """Write the workspace file if it differs, and return its path."""
    path = Path(repo_root) / WORKSPACE
    text = render(repo_root)
    if not path.is_file() or path.read_text(encoding="utf-8") != text:
        path.write_text(text, encoding="utf-8")
    return path


def main():
    try:
        write(REPO_ROOT)
    except ValueError as error:
        print(f"generate-workspace: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
