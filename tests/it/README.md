# Policy integration tests

Integration tests for the gateway policies in this repository. Each policy owns its suite in
`policies/<name>/it/`: a suite file, its scenarios, its own step definitions and a Go module. The
suite boots the gateway of its run and runs the scenarios against it, so a pull request that changes
a policy updates and runs its tests together. A run builds that gateway once, from every policy of
the repository, and every suite of the run boots it. A pull request to `main` that changes
`policies/`, `tests/it`, `scripts/it`, the Makefile or the workflow runs the suite of every policy,
in one workflow run, on gateway 1.2.0, 1.1.0 and the latest image.

This directory, `tests/it`, holds what every policy's suite shares: the step definitions, the
canonical resource templates and the code that runs a suite. They began as copies of the
[test framework's](https://github.com/wso2/api-platform/tree/main/tests/framework) Platform Gateway
steps and are owned here, so a policy's tests never need api-platform's step code. The framework
itself, a Go module published by api-platform, supplies the engine that boots the containers. One
version of it serves every suite and is written once, in `tests/it/go.mod`; the suites' own `go.mod`
files do not name it (see the framework dependency in [CLAUDE.md](CLAUDE.md)). Its testbench image
is pulled from GHCR on the first run, and is rebuilt under the same version tag when the testbench
changes.

**[CLAUDE.md](CLAUDE.md) is the guide**: how to run the tests, how to add tests to a policy that
has none, how to write scenarios and steps, and what a pull request runs.

## Layout

```
policies/<name>/it/
  it-suite.yaml      the suite: the gateway it boots, databases, runners
  features/          Gherkin feature files
  steps/             step definitions only this policy needs
  suite_test.go      test entry; runs the suite through tests/it/common/suite
  go.mod, go.sum     the suite's Go module (it does not name the framework)
  resources/         templates that differ from the shared ones (added when needed)
tests/it/
  go.mod             the shared module: the one place that pins the framework version
  it.work            the Go workspace that joins tests/it and every suite's module (generated, not committed)
  common/steps/      step definitions every policy shares
  common/resources/  canonical resource templates every policy shares
  common/suite/      runs one policy's suite
```

## Commands

```bash
make it POLICIES=time-based-model-routing GATEWAY_VERSION=1.2.0   # run (1.2.0, 1.1.0 or latest)
make it POLICIES=a,b BLOCK_PARALLEL=6                             # 6 blocks at a time across the suites (default 12)
make it-scaffold POLICY=<name>                                    # start tests for a policy
make it-standards                                                 # check steps, features, suites and the framework pin
make it-workspace                                                 # generate the Go workspace file (the other targets do it)
make it-unit                                                      # unit tests of the steps
```

Docker is required; see CLAUDE.md for the Rancher Desktop and Colima settings.
