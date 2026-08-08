# CLAUDE.md — WSO2 Gateway Controllers (Policy Hub)

## What This Repo Is

A library repository of **independent Go policy modules** for the WSO2 API Platform Gateway. Each policy under `policies/` is a self-contained Go module with its own `go.mod`, tests, and `policy-definition.yaml`. Policies are compiled into the gateway at build time — this repo does not run as a standalone service.

## Build & Test

```bash
# Test a specific policy (this is the most common task)
cd policies/<policy-name>
go test -v -race ./...

# Build a specific policy
cd policies/<policy-name>
go build ./...

# Test all policies
for dir in policies/*/; do (cd "$dir" && go test -v -race ./...); done
```

There is no root-level build — each policy is independent.

**Integration testing** requires the `wso2/api-platform` repo. See `gateway/dev-policies/README.md` in that repo for the full procedure.

## Policy Interface

All policies implement the SDK interface from `github.com/wso2/api-platform/sdk/gateway/policy/v1alpha`:

```go
type Policy interface {
    Mode() ProcessingMode
    OnRequest(ctx *RequestContext, params map[string]interface{}) RequestAction
    OnResponse(ctx *ResponseContext, params map[string]interface{}) ResponseAction
}
```

- `Mode()` declares what the policy needs (request/response headers and/or body)
- Policies return actions (`RequestContinue`, `RequestError`, `ImmediateResponse`) — they don't modify state directly
- Parameters are defined in `policy-definition.yaml` using JSON Schema with WSO2 extensions

## Coding Conventions

- **Formatting**: `gofmt` / `goimports`
- **Copyright header**: All Go files must start with the Apache 2.0 copyright block (check existing files for format)
- **Imports**: Standard library first, then third-party. Alias the policy SDK import for clarity
- **Logging**: Use `log/slog` for structured logging — not `fmt.Println` or `log.Printf`
- **Package names**: Short, lowercase, single-word (e.g., `package apikey`, `package cors`)
- **File names**: Snake-case matching the policy name (e.g., `apikey.go`, `basicauth.go`)
- **Tests**: Co-located `*_test.go` files. Use hand-written mock structs (embed the interface, override needed methods) — no mock generation frameworks. Table-driven tests with `t.Run()`. Always run with `-race` flag.
- **Naming**: `Test{PolicyName}_{Scenario}` or `Test{PolicyName}Policy_{Action}_{Condition}`

## Key Gotchas

- Each policy is an **independent Go module** — run commands from inside `policies/<name>/`, not from the repo root
- `policy-definition.yaml` has two parameter types: `parameters` (user-configurable per API) and `systemParameters` (resolved from gateway `config.toml` at startup via `wso2/defaultValue`)
- Versions are managed per-policy via git tags: `policies/<policy-name>/v<X.Y.Z>`
- Code owners for `go.mod`/`go.sum` changes: @pubudu538, @malinthaprasan, @Krishanx92
