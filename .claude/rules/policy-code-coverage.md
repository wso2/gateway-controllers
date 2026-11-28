# Rule: Tracking Policy Code Coverage (codecov.yml) and the 80% Minimum Before Submitting

## Context & Scope

Apply this rule whenever adding a new policy under `policies/`, adding a new version module beside v1 (`policies/<name>/v<N>`), adding source files or packages to an existing policy, or changing the code of a policy that is going to `main`.

Coverage is that of the integration suites (`policies/<name>/it`), not of unit tests. The gateway is built with every policy's code instrumented, the suites run against it, and the counters the gateway writes when it stops are merged into one report that is uploaded to Codecov. `codecov.yml` holds one component for each policy Go module, and Codecov rolls them up into the repository-wide (global) figure. A policy that has no component is not tracked, and its coverage is missing from the per-policy report on the pull request. Every suite runs on one gateway that carries all the policies, so the counters of a run also record policies the suite merely uses (set-headers attached to another policy's API) and code that runs at start-up. The report therefore credits a policy with the runs of its own suite alone, and a policy with no suite of its own reports 0%. The component list is generated from the policy modules by `scripts/coverage/generate-codecov-config.py`; CI fails when `codecov.yml` is out of date (the `Select policies` job of `.github/workflows/it.yml`). Pull requests report their coverage from the latest-gateway leg of that workflow; `.github/workflows/coverage.yml` keeps the coverage of `main` current.

## Directives

1. **Register a new policy in `codecov.yml`.** After creating `policies/<name>` (or `policies/<name>/v<N>`) with its own `go.mod`, run `make generate-codecov-config` and commit the changed `codecov.yml` with the policy. Do not hand-edit the lines between the `BEGIN`/`END GENERATED POLICY COMPONENTS` markers; the next run overwrites them. A new policy is tracked as `<name>`, a version module as `<name>-v<N>`.

2. **Check that a new feature file is tracked.**
   - A new `.go` file or package inside a policy is already tracked: the policy's component covers `policies/<name>/**`.
   - A policy that has a version module nested in it (for example `backend-jwt` and `backend-jwt/v2`) lists its own root files and package directories explicitly, so run `make generate-codecov-config` after adding a package directory to it, and after adding a version module.
   - Policy code outside `policies/<name>/` (a new shared directory, a new top-level module) is not tracked by any component. Extend `scripts/coverage/generate-codecov-config.py` to emit one; do not add a hand-written component that the generator would drop.
   - Code under `policies/*/it/` and `tests/` is test code and is deliberately ignored by `codecov.yml`; do not put policy logic there.

3. **Run the coverage locally before submitting.** Docker is required (see `tests/it/CLAUDE.md`). For every policy the change adds or modifies, run:

   ```bash
   make it-coverage POLICIES=<name>[,<name>/v<N>,...] DB=sqlite
   make coverage-summary
   ```

   `it-coverage` builds the latest gateway with every policy instrumented, runs the named policies' integration suites against it, and writes `coverage/coverage.txt` (ignored by git); `coverage-summary` prints the policy-wise percentage. The instrumented policy engine exists only on the latest gateway, so this always runs there, and `DB=sqlite` limits the run to one database, which does not change which policy code runs. The summary lists every policy that ran or was built into the gateway, so read the row of the policy you changed. With `POLICIES` narrowed, the global figure covers only the suites that ran; run `make it-coverage` with no `POLICIES` to see the repository-wide figure the change leaves behind. See "Policy code coverage" in `tests/it/CLAUDE.md` for how it works and for what to do when it fails.

4. **Reach at least 80% coverage for each policy.** Every new or modified policy must show 80% or more in `make coverage-summary` before the change is submitted to `main`. A policy below 80% is not ready: add scenarios for the uncovered paths, starting with the rejection and error branches.
   - Do not lower the bar to pass it: no ignoring files or packages in `codecov.yml`, no moving logic into an ignored directory, no scenarios that send requests without asserting on the result.
   - The suites must also pass. A block that fails or whose gateway does not stop cleanly writes no counters, so a policy missing from the summary or far below its usual figure is a failure to fix, not a pass.
   - A policy with no `it/it-suite.yaml` reports 0% and fails this directive; add its suite first (`make it-scaffold POLICY=<name>`). Other policies' suites do not count towards it: a block name must also be unique across suites, because `run-suites` credits counters to the policy that owns the block and refuses a name two suites share.

5. **State the numbers in the pull request.** List each touched policy with its local coverage percentage, and note any policy that stays under 80% with the reason.

## Example

```bash
# New policy "my-policy" and a change to "backend-jwt/v2"
make generate-codecov-config                      # adds the my-policy component to codecov.yml
make validate-codecov-config                      # must print: codecov.yml is up to date
make it-coverage POLICIES=my-policy,backend-jwt/v2 DB=sqlite
make coverage-summary
# | my-policy      | 86.4% | ...   -> at least 80%, ready
# | backend-jwt/v2 | 74.0% | ...   -> below 80%, add scenarios before submitting
```

> **Verification Checklist before outputting code:**
> * Is a new policy or version module in `codecov.yml`, produced by `make generate-codecov-config`, and does `make validate-codecov-config` pass?
> * Is every new source file or package covered by a component, with the nested-version-module and outside-`policies/` cases checked?
> * Did `make it-coverage POLICIES=...` and `make coverage-summary` run locally for every new or modified policy?
> * Is each of those policies at 80% or more, with passing suites, and not reached by ignoring code or writing scenarios that assert nothing?
> * Does the pull request description state the per-policy coverage?
