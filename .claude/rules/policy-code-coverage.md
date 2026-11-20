# Rule: Tracking Policy Code Coverage (codecov.yml) and the 80% Minimum Before Submitting

## Context & Scope

Apply this rule whenever adding a new policy under `policies/`, adding a new version module beside v1 (`policies/<name>/v<N>`), adding source files or packages to an existing policy, or changing the code of a policy that is going to `main`.

Coverage is reported to Codecov per policy: `codecov.yml` holds one component for each policy Go module, and Codecov rolls them up into the repository-wide (global) figure. A policy that has no component is not tracked, and its coverage is missing from the per-policy report on the pull request. The component list is generated from the policy modules by `scripts/coverage/generate-codecov-config.py`; CI (`.github/workflows/coverage.yml`) fails when `codecov.yml` is out of date.

## Directives

1. **Register a new policy in `codecov.yml`.** After creating `policies/<name>` (or `policies/<name>/v<N>`) with its own `go.mod`, run `make generate-codecov-config` and commit the changed `codecov.yml` with the policy. Do not hand-edit the lines between the `BEGIN`/`END GENERATED POLICY COMPONENTS` markers; the next run overwrites them. A new policy is tracked as `<name>`, a version module as `<name>-v<N>`.

2. **Check that a new feature file is tracked.**
   - A new `.go` file or package inside a policy is already tracked: the policy's component covers `policies/<name>/**`.
   - A policy that has a version module nested in it (for example `backend-jwt` and `backend-jwt/v2`) lists its own root files and package directories explicitly, so run `make generate-codecov-config` after adding a package directory to it, and after adding a version module.
   - Policy code outside `policies/<name>/` (a new shared directory, a new top-level module) is not tracked by any component. Extend `scripts/coverage/generate-codecov-config.py` to emit one; do not add a hand-written component that the generator would drop.
   - Code under `policies/*/it/` and `tests/` is test code and is deliberately ignored by `codecov.yml`; do not put policy logic there.

3. **Run the coverage locally before submitting.** For every policy the change adds or modifies, run:

   ```bash
   make unit-coverage POLICIES=<name>[,<name>/v<N>,...]
   make coverage-summary
   ```

   `POLICIES` is a comma-separated list; a version module is `<name>/v<N>`. The first command runs the unit tests of those modules and writes `coverage/coverage.txt` (ignored by git); the second prints the policy-wise percentage. With `POLICIES` narrowed, the global figure covers only the selected policies. Run `make unit-coverage` with no `POLICIES` to see the repository-wide figure the change leaves behind.

4. **Reach at least 80% coverage for each policy.** Every new or modified policy must show 80% or more in `make coverage-summary` before the change is submitted to `main`. A policy below 80% is not ready: add tests for the uncovered paths, starting with the rejection and error branches.
   - Do not lower the bar to pass it: no ignoring files or packages in `codecov.yml`, no moving logic into an ignored directory, no tests that run code without asserting on it.
   - Unit tests must also pass. A module whose tests fail or crash writes no usable report, and a policy missing from the summary is a failure to fix, not a pass.
   - A policy with no tests reports 0% and fails this directive.

5. **State the numbers in the pull request.** List each touched policy with its local coverage percentage, and note any policy that stays under 80% with the reason.

6. **Know what the figure measures.** The percentage comes from the policies' unit tests (`make unit-coverage`). The integration suites under `policies/*/it` run against a built gateway and are not part of it, so they neither raise nor replace this figure; a policy still needs its integration suite as the other rules require.

## Example

```bash
# New policy "my-policy" and a change to "backend-jwt/v2"
make generate-codecov-config                      # adds the my-policy component to codecov.yml
make validate-codecov-config                      # must print: codecov.yml is up to date
make unit-coverage POLICIES=my-policy,backend-jwt/v2
make coverage-summary
# | my-policy      | 86.4% | ...   -> at least 80%, ready
# | backend-jwt/v2 | 74.0% | ...   -> below 80%, add tests before submitting
```

> **Verification Checklist before outputting code:**
> * Is a new policy or version module in `codecov.yml`, produced by `make generate-codecov-config`, and does `make validate-codecov-config` pass?
> * Is every new source file or package covered by a component, with the nested-version-module and outside-`policies/` cases checked?
> * Did `make unit-coverage POLICIES=...` and `make coverage-summary` run locally for every new or modified policy?
> * Is each of those policies at 80% or more, with passing tests, and not reached by ignoring code or writing assertion-free tests?
> * Does the pull request description state the per-policy coverage?
