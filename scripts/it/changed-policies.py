#!/usr/bin/env python3
"""
Select the policies whose integration tests a pull request should run.

Each policy owns an integration suite in policies/<name>/it, declared by
policies/<name>/it/it-suite.yaml and built on the shared steps in tests/it/common. A major version
of a policy released beside its v1 lives in policies/<name>/v<N> with its own module and suite
(policies/<name>/v<N>/it/it-suite.yaml); it is selected and run as the policy id "<name>/v<N>". A pull
request runs the suites of every policy it changes in one workflow run.

Selection:
  * every policies/<name>/ directory touched by the diff against --base, whichever file in it
    changed, including a policy that is new in the pull request; a file under policies/<name>/v<N>/
    selects only "<name>/v<N>", never the v1 beside it;
  * plus every policy that depends on one of them through a go.mod require line,
    directly or transitively;
  * limited to policies that have an it/it-suite.yaml.

A change that only touches the integration workflow, these scripts, the shared steps
(tests/it) or the Makefile selects the smoke policies instead. --policies overrides the diff
("all" selects every policy with tests), which is how workflow_dispatch runs are driven.

Writes policies (comma-separated) and has_tests to $GITHUB_OUTPUT when it is set.
"""

import argparse
import os
import re
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
POLICIES_DIR = "policies"
DESCRIPTOR = "it/it-suite.yaml"

# Run when only the integration plumbing changed, so a workflow edit still exercises the flow.
SMOKE_POLICIES = ["time-based-model-routing"]
INFRA_PATHS = (".github/workflows/it.yml", "scripts/it/", "tests/it/", "Makefile")

# An intra-repo policy dependency in a go.mod require line, e.g.
#   github.com/wso2/gateway-controllers/policies/advanced-ratelimit v1.1.0
# or, for a major version released beside v1:
#   github.com/wso2/gateway-controllers/policies/backend-jwt/v2 v2.0.0
# The policy id is the name, with the /v<N> suffix for a major version directory.
DEP_RE = re.compile(r"github\.com/wso2/gateway-controllers/policies/([^/\s]+(?:/v\d+)?)\s+v\d")
NAME_RE = re.compile(r"^[a-z0-9][a-z0-9-]*$")
VERSION_DIR_RE = re.compile(r"^v\d+$")


def policy_names(repo_root):
    """Policy ids: every policies/<name>, plus <name>/v<N> for each major version directory."""
    root = repo_root / POLICIES_DIR
    names = []
    for p in root.iterdir():
        if not (p.is_dir() and NAME_RE.match(p.name)):
            continue
        names.append(p.name)
        # A v<N> folder is a policy of its own only when it holds a policy-definition.yaml; any other
        # v<N> folder is part of the policy around it.
        names.extend(
            f"{p.name}/{v.name}"
            for v in p.iterdir()
            if v.is_dir() and VERSION_DIR_RE.match(v.name) and (v / "policy-definition.yaml").is_file()
        )
    return sorted(names)


def has_tests(repo_root, name):
    return (repo_root / POLICIES_DIR / name / DESCRIPTOR).is_file()


def parse_dependencies(go_mod_text, own_name):
    """Policies named by require lines, without the policy's own module line."""
    return {m.group(1) for m in DEP_RE.finditer(go_mod_text)} - {own_name}


def dependents_closure(changed, dependencies):
    """Changed policies plus every policy that requires one of them, transitively."""
    selected = set(changed)
    grew = True
    while grew:
        grew = False
        for name, deps in dependencies.items():
            if name not in selected and deps & selected:
                selected.add(name)
                grew = True
    return selected


def changed_policies(changed_files, existing):
    names = set()
    for path in changed_files:
        parts = Path(path).parts
        if len(parts) < 2 or parts[0] != POLICIES_DIR:
            continue
        versioned = f"{parts[1]}/{parts[2]}" if len(parts) >= 3 else None
        if versioned in existing:
            names.add(versioned)
        elif parts[1] in existing:
            names.add(parts[1])
    return names


def only_infra_changed(changed_files):
    return bool(changed_files) and all(
        any(path == p or path.startswith(p) for p in INFRA_PATHS) for path in changed_files
    )


def read_dependencies(repo_root, names):
    dependencies = {}
    for name in names:
        go_mod = repo_root / POLICIES_DIR / name / "go.mod"
        dependencies[name] = (
            parse_dependencies(go_mod.read_text(encoding="utf-8"), name) if go_mod.is_file() else set()
        )
    return dependencies


def git_changed_files(repo_root, base):
    out = subprocess.run(
        ["git", "diff", "--name-only", f"{base}...HEAD"],
        cwd=repo_root, check=True, capture_output=True, text=True,
    ).stdout
    return [line for line in out.splitlines() if line]


def select(repo_root, base=None, requested=None):
    """Return (policies to run, policies skipped for having no tests, reason)."""
    existing = policy_names(repo_root)
    if requested:
        if requested == ["all"]:
            wanted = set(existing)
            reason = "all policies requested"
        else:
            unknown = sorted(set(requested) - set(existing))
            if unknown:
                raise SystemExit(f"unknown policies: {', '.join(unknown)}")
            wanted = set(requested)
            reason = "policies requested"
    else:
        files = git_changed_files(repo_root, base)
        wanted = changed_policies(files, set(existing))
        reason = "policies changed in the diff"
        if not wanted and only_infra_changed(files):
            wanted = set(SMOKE_POLICIES) & set(existing)
            reason = "integration plumbing changed, running the smoke policies"
        wanted = dependents_closure(wanted, read_dependencies(repo_root, existing))

    selected = sorted(n for n in wanted if has_tests(repo_root, n))
    # "all" means every policy that has tests, so the others are not worth reporting.
    skipped = [] if requested == ["all"] else sorted(n for n in wanted if not has_tests(repo_root, n))
    return selected, skipped, reason


def write_outputs(selected):
    lines = [
        f"policies={','.join(selected)}",
        f"has_tests={'true' if selected else 'false'}",
    ]
    target = os.environ.get("GITHUB_OUTPUT")
    if target:
        with open(target, "a", encoding="utf-8") as handle:
            handle.write("\n".join(lines) + "\n")
    return lines


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--base", help="base commit or ref the pull request is compared with")
    parser.add_argument("--policies", default="", help="comma-separated policies, or 'all'; overrides the diff")
    parser.add_argument("--repo-root", type=Path, default=REPO_ROOT)
    args = parser.parse_args(argv)

    requested = [p.strip() for p in args.policies.split(",") if p.strip()]
    if not requested and not args.base:
        parser.error("--base is required unless --policies is given")

    selected, skipped, reason = select(args.repo_root, args.base, requested)
    print(f"Selection: {reason}")
    print(f"Policies with integration tests to run: {', '.join(selected) or '(none)'}")
    if skipped:
        print(f"Policies selected but without {DESCRIPTOR}: {', '.join(skipped)}")
    for line in write_outputs(selected):
        print(line)
    return 0


if __name__ == "__main__":
    sys.exit(main())
