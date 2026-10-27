# Policy integration tests: how to add and run them

This guide is for anyone, human or agent, adding integration tests to a gateway policy or
running them. Each policy owns a suite in its own folder. The suite boots a real gateway built
from that policy and runs Gherkin scenarios against it, so adding, changing or running a policy's
tests needs only that policy's folder and the shared code in `tests/it/common`.

## Where things live

| What | Where |
| --- | --- |
| A policy's suite: its databases and its runners | `policies/<name>/it/it-suite.yaml` |
| A policy's scenarios | `policies/<name>/it/features/*.feature` |
| Steps only that policy needs | `policies/<name>/it/steps/` |
| The policy suite's Go module and test entry | `policies/<name>/it/go.mod`, `policies/<name>/it/suite_test.go` |
| Templates only that policy needs | `policies/<name>/it/resources/templates/` |
| Steps every policy shares | `tests/it/common/steps/` |
| Canonical resource templates every policy shares | `tests/it/common/resources/templates/` |
| The code that runs a policy's suite on the shared steps | `tests/it/common/suite/` |
| The code that builds the gateway the suites boot | `tests/it/common/gateway/`, `tests/it/cmd/build-gateway/` |
| Selecting the policies a pull request runs | `scripts/it/changed-policies.py` |
| The pull request workflow | `.github/workflows/it.yml` |

A suite has one block, named for the policy. It names no policy tree: the gateway it boots is not
built by the suite. `make it` builds the gateway once per gateway version
(`tests/it/cmd/build-gateway`), from every policy of the repository on the base images of that
version, and every selected suite boots that build. It hands the build to the suites through the
framework's `IT_IMAGE_GATEWAY_CONTROLLER` and `IT_IMAGE_GATEWAY_RUNTIME`, as images tagged with the
version (`local/apip-it-gateway-controller:<version>`). A suite run directly with `go test`, without
those variables, builds a gateway of its own from the policy under test and the policies the gateway
controller itself requires to create LLM providers and proxies (`api-key-auth`, `host-rewrite`,
`oauth2-generator`, `respond` and `set-headers`). A policy whose scenarios use further policies
lists them in its `suite_test.go` for that run:
`suite.Config{Register: steps.Register, Companions: []string{"<other policy>"}}`. A policy's `it/`
folder is a Go module of its own, `github.com/wso2/gateway-controllers/policies/<name>/it`, so its
test dependencies never reach the policy's own `go.mod`, and the gateway build and the policy's
release both leave `it/` out.

The engine that boots the containers (topology, components, the runner, the testbench) is the test
framework, a Go module published by api-platform and pinned in each suite's `go.mod`
(`github.com/wso2/api-platform/tests/framework`). The step definitions and the canonical templates
are not imported from it. `tests/it/common` holds copies of the framework's Platform Gateway
steps, trimmed to what a gateway policy needs (no Platform API, API portal or AI workspace steps),
so a policy developer never reads or changes api-platform. They are owned here and changed here.

## Run the tests

You need Go, Docker and network access to GHCR. With Rancher Desktop or Colima, point the tools at
the VM's socket first (Docker Desktop needs nothing):

```bash
export DOCKER_HOST=unix://$HOME/.rd/docker.sock
export TESTCONTAINERS_DOCKER_SOCKET_OVERRIDE=/var/run/docker.sock
```

```bash
make it POLICIES=time-based-model-routing GATEWAY_VERSION=1.2.0
```

`make it` builds the gateway once, then runs the suite of each named policy in turn against it and
fails if any of them fails. To run one suite directly, from its folder (it builds its own gateway):

```bash
cd policies/time-based-model-routing/it
go test . -count=1 -timeout=40m -v -run TestIntegrationSuite -args -gateway-version=1.2.0
```

| Variable | Meaning |
| --- | --- |
| `POLICIES` | Comma-separated policies. Defaults to every policy that has an `it/it-suite.yaml`. |
| `GATEWAY_VERSION` | `1.2.0`, `1.1.0` or `latest`. Default `1.2.0`. |
| `GATEWAY_HOST` | Image repository prefix for the gateway controller, runtime and builder images when they are not under `ghcr.io/wso2/api-platform`. The 1.1.0 images are patched, because the stock 1.1.0 builder cannot build policies that need a newer Go, so 1.1.0 runs use `docker.io/isurangaws`, which publishes all three. |
| `GATEWAY_POLICIES` | Comma-separated policies to build into the shared gateway. Defaults to every policy of the repository. |
| `DB` | Limit the run to `sqlite`, `postgres` or `sqlserver`. All three run by default. |

- `latest` is the gateway built from api-platform `main`; it can change between two runs, and its
  `main-<sha>` tag identifies what a run used. It is pulled again on every run.
- A runner gated to other gateway versions is skipped, not failed. Gating a runner to
  `gateway-version>=1.2.0` and running against `1.1.0` reports "nothing to run".
- Other targets: `make it-standards` checks the shared steps and each policy's steps, features and
  suite file against the framework standards; `make it-unit` runs the unit tests of the shared
  steps and of each policy's own steps. Both take `POLICIES` too.

## Add tests to a policy that has none

A policy without `it/it-suite.yaml` has no integration tests, and the pull request workflow skips it.

1. Start from the scaffold:

   ```bash
   make it-scaffold POLICY=<name>
   ```

   It creates the whole suite in `policies/<name>/it/` and runs `go mod tidy` there, and it
   refuses to overwrite anything:

   | File | Purpose |
   | --- | --- |
   | `it-suite.yaml` | the suite: gateway built from this policy, database matrix, one runner |
   | `go.mod`, `go.sum` | the suite's Go module |
   | `suite_test.go` | the test entry; it hands the suite to `tests/it/common/suite` |
   | `steps/register.go` | binds the policy's own steps |
   | `steps/<name>_steps.go` | the policy's own step definitions, with one example to replace |
   | `steps/steps_test.go` | unit tests of those steps |
   | `features/<name>.feature` | a scenario that deploys a REST API with the policy attached |
2. In `it-suite.yaml`, a runner has a `name`, optional `tags` and a list of `features` relative to
   the `it/` folder. Add `tags: "gateway-version>=X.Y.Z"` only when the policy needs a newer
   gateway than the oldest one tested.
3. In the feature, the scaffold deploys a REST API with the policy attached and an empty `params`.
   A policy with required parameters rejects an empty `params`, so the first run fails with a
   validation error naming the missing fields. Put the policy's real configuration in `params`,
   send the requests that show the policy's effect, and assert them.
4. Run `make it POLICIES=<name> GATEWAY_VERSION=1.2.0`, then the same for `1.1.0` and `latest`, then
   `make it-standards POLICIES=<name>`.
5. Commit the `it/` folder with the policy change. A pull request that changes any file in the
   policy's folder now runs these tests on all three gateway versions.

## Write the scenarios

- Create every resource through a canonical template and the values table:
  `I create API from "resources/templates/rest-api.yaml" with values:`. The templates are
  `rest-api`, `llm-provider`, `llm-provider-template`, `llm-proxy`, `mcp`, `agent` and
  `graphql-api`. Supply differences as table values (`spec.operations`, `spec.upstream.main.url`
  and so on), never as inline YAML.
- Give `apiVersion` the value `${CTX:gatewaySpecVersion}`. It selects the resource contract of the
  gateway under test, so one scenario runs on every version.
- Name every test-owned resource with the unique-name steps (`I generate a unique value from
  "<base>" and store it as "<key>"`, and the API version and context variants), and reuse the stored
  value. Never hard-code a name or context.
- A runner is independent of every other runner. Do not rely on another runner's data or order.
- Delete what the scenario creates, and let the framework's cleanup sweep catch what a failed
  scenario leaves behind. Do not use sleeps; poll with the `until status` request steps.
- Add scenarios to the policy's existing feature before creating another file.
- The mock backends are the testbench services (for example `http://testbench:3000`,
  `http://testbench:3008/openai/v1`). Do not start containers of your own.
- When one scenario needs a newer gateway than the rest of its runner, start it with
  `Given the gateway version satisfies ">=1.2.0"` (operators `>`, `>=`, `<`, `<=`, `=`). It skips
  the scenario on any other gateway, with the same rules as a runner tag: `latest` is newer than
  every release. Gate the runner instead when every scenario in it needs the newer gateway.
- Hold a policy's error response to a recorded one with `the response should match the expected
  error response "<id>"`. It compares the status, the contract headers and the body, with UUIDs,
  timestamps and generated names masked, against
  `policies/<name>/it/resources/expected-error-responses/<id>.json`, one file for every gateway
  version. A gateway version whose response genuinely differs gets its own
  `expected-error-responses/<version>/<id>.json`. Record a missing file by running with
  `IT_RECORD_EXPECTED_ERRORS=1` against the policy as it was before the change; record an intended
  difference beside it, as `<id>.accepted.json`, with `IT_ACCEPT_ERROR_CHANGES=1`.

## Steps and resources

1. Search first: `tests/it/common/steps`, then the policy's own `steps/`. Most behaviours are one
   existing step with different parameters.
2. If nothing fits, add the step to the policy's own `steps/<name>_steps.go`, bind it in `register`,
   and cover it with a unit test in `steps/steps_test.go`. A step another policy would also use
   belongs in `tests/it/common/steps` instead, with its unit test there.
3. A template in `policies/<name>/it/resources/templates/` replaces the shared template of the same
   name for that policy (no merging). Add one only when no canonical template can express the
   resource. A change to a shared template, in `tests/it/common/resources/templates/`, applies to
   every policy.
4. The cleanup deleters for the gateway's resource kinds are in
   `tests/it/common/steps/platformgateway/cleanup.go`.

`tests/it/common` is a copy that began as the framework's steps. A fix that lands in api-platform's
steps does not reach it by itself, so port it when a policy needs it.

## What a pull request runs

`scripts/it/changed-policies.py` selects every policy whose folder has a changed file, plus the
policies that depend on one of them through a `go.mod` require, limited to policies that have an
`it/it-suite.yaml`. A change to the workflow, these scripts, `tests/it` or the Makefile runs the
smoke policy instead. One workflow run builds the gateway once for each of gateway 1.2.0, 1.1.0 and
latest and executes the suite of every selected policy on it, each on all three databases (SQL
Server only from 1.2.0). The standards check runs on the shared steps and on the selected policies'
steps, features and suite file. A manual run takes `policies` (comma-separated, or `all`).

## The framework dependency

- Every suite's `go.mod` pins the framework version, and `tests/it/go.mod` pins it for the shared
  steps. Update them together: `go get github.com/wso2/api-platform/tests/framework@vX.Y.Z` and
  `go mod tidy` in `tests/it` and in each `policies/<name>/it`, then run the suites. The testbench
  image, `ghcr.io/wso2/api-platform/testbench:<version>`, follows the version the suite's `go.mod`
  pins: `tests/it/common/suite` sets it, and it is pulled on the first run. When the image cannot
  be pulled, build it from the pinned module's source, as the workflow's "Provide the testbench
  image" step does:
  `dir=$(cd tests/it && go list -m -f '{{.Dir}}' github.com/wso2/api-platform/tests/framework)`
  then `docker build -f "$dir/testbench/Dockerfile" -t ghcr.io/wso2/api-platform/testbench:<version> "$dir"`.
  Set `APIP_IT_IMAGE_TESTBENCH` to use any other image.

## Troubleshooting

- `testbench/manifests/...: unauthorized` when a suite boots, followed by "executed NO scenarios":
  the testbench image could not be pulled, so no block booted. Build it as described under "The
  framework dependency", and check the tag in the message against the framework version in
  `go.mod`.
- `failed to connect to the docker API` or `rootless Docker not found`: Docker is not running, or
  `DOCKER_HOST` and `TESTCONTAINERS_DOCKER_SOCKET_OVERRIDE` are not set for Rancher Desktop or
  Colima.
- `the policy selection has nothing to run` (a skipped test): every runner is gated to a newer
  gateway than the one you selected.
- A scenario that passed on 1.2.0 fails on 1.1.0: the contract differs. Gate the runner with
  `gateway-version>=1.2.0` only if the behaviour really does not exist on 1.1.0; otherwise the
  scenario needs a version-neutral form (see `${CTX:gatewaySpecVersion}`).
- `latest` fails but 1.2.0 passes: look at the `main-<sha>` tag the run pulled and at what changed
  in api-platform since the previous run.
