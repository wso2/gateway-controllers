# Policy Action Items
Policy: mcp-acl-list
Source: /Users/tharsanan/Documents/worktrees/gateway-controllers/fi-priorotized-policies/policies/mcp-acl-list

## 1) `<parameters>`
- Priority: High
- Area: Contract
- Title: Require at least one ACL branch to prevent silent no-op policy configs
- Current: `tools`, `resources`, and `prompts` are all optional with no top-level `anyOf` requirement.
- Evidence: `policies/mcp-acl-list/policy-definition.yaml` has optional capability blocks only; runtime returns disabled config when branch is missing (`mcp-acl-list.go`, `parseAclConfig`, missing key path) and skips enforcement when config is disabled (`OnRequest`, `if !config.Enabled { return nil }`).
- Issue: A security policy can be attached with an empty config and apply no restrictions, which is easy to miss in reviews.
- Action: Require at least one of `tools`, `resources`, or `prompts` at schema level.
- Suggested value/name/flag: Add
```yaml
anyOf:
  - required: [tools]
  - required: [resources]
  - required: [prompts]
```
- Compatibility: Breaking
- Migration: Ensure every `mcp-acl-list` usage configures at least one capability block.
- Validation: Verify empty `params: {}` fails validation and single-branch configs still pass.

## 2) `<systemParameters>`
- Priority: Medium
- Area: Contract
- Title: Enforce strict empty system parameter object
- Current: `systemParameters` does not declare `additionalProperties: false`.
- Evidence: `policies/mcp-acl-list/policy-definition.yaml` defines `systemParameters` with `type: object` and `properties: {}` only.
- Issue: Unknown system keys can be accepted silently, which weakens schema strictness consistency.
- Action: Make `systemParameters` strict.
- Suggested value/name/flag: `additionalProperties: false`
- Compatibility: Breaking
- Migration: Remove unknown system parameter keys from existing configs.
- Validation: Verify unknown `systemParameters` fields fail schema validation.

## 3) `<runtime.parseAclConfig.exceptions-normalization>`
- Priority: High
- Area: Runtime
- Title: Normalize or reject padded exception values to avoid ACL mismatches
- Current: Exception values are validated with `TrimSpace` only for emptiness, then stored untrimmed.
- Evidence: `mcp-acl-list.go` validates `strings.TrimSpace(value) == ""` but stores `config.Exceptions[value] = struct{}{}`.
- Issue: Values like `" toolA "` pass validation but will not match runtime capability names unless those names also contain padding, causing surprising allow/deny behavior.
- Action: Normalize exception values before storing (or explicitly reject leading/trailing whitespace in schema/runtime).
- Suggested value/name/flag: Use `trimmed := strings.TrimSpace(value)` and persist `trimmed`; if preserving exact semantics is required, reject padded values with a config error.
- Compatibility: Breaking
- Migration: Remove accidental leading/trailing whitespace in existing exception entries.
- Validation: Add tests for padded values and confirm deterministic match behavior after normalization/rejection.

## 4) `<runtime.isMcpPostRequest.path-match>`
- Priority: Medium
- Area: Runtime
- Title: Replace substring endpoint matching with segment-aware MCP path matching
- Current: MCP detection uses `strings.Contains(path, "/mcp")` for request/response gating.
- Evidence: `mcp-acl-list.go` `isMcpPostRequest` returns true for any POST path containing `/mcp`.
- Issue: Non-MCP paths that include `/mcp` as a substring can be matched unintentionally, causing policy execution on unrelated endpoints.
- Action: Make path matching segment-aware.
- Suggested value/name/flag: Use exact/prefix checks such as `path == "/mcp" || strings.HasPrefix(path, "/mcp/")` (or equivalent route-aware matcher).
- Compatibility: Breaking
- Migration: Ensure MCP APIs use canonical MCP path patterns if they currently rely on substring matching.
- Validation: Add tests for `/mcp`, `/mcp/v1`, and false-positive paths (for example `/foo-mcp-tools`).

## 5) `<docs.overview.request-enforcement-scope>`
- Priority: Medium
- Area: Docs
- Title: Clarify action-level enforcement scope in policy docs
- Current: Docs describe broad request-path enforcement without explicitly documenting action constraints.
- Evidence: `docs/mcp-acl-list/v0.2/docs/mcp-acl-list.md` overview/features are broad, while runtime applies request ACL checks only for `tools/call`, `resources/read`, `prompts/get` and response filtering for `action == list`.
- Issue: Operators may assume all MCP actions are blocked/filtered uniformly, which does not match runtime behavior.
- Action: Document exact request and response action scope.
- Suggested value/name/flag: Add explicit behavior matrix (request: call/read/get; response filtering: list only).
- Compatibility: Non-breaking
- Migration: None.
- Validation: Confirm docs examples and notes align with `isApplicableOnRequest` and response `action == "list"` behavior.

## 6) `<tests.sse-request-response-coverage>`
- Priority: High
- Area: Tests
- Title: Add SSE-path coverage for request parsing and response list filtering
- Current: Tests cover JSON request/response paths only.
- Evidence: `mcp-acl-list_test.go` has no cases with `text/event-stream` despite dedicated SSE branches in runtime (`parseRequestPayload`, `parseEventStream`, `buildEventStream`, and SSE response filtering path).
- Issue: SSE branches are complex and currently unguarded by tests, increasing regression risk for MCP streaming deployments.
- Action: Add targeted SSE tests for both request and response flows.
- Suggested value/name/flag: Add tests for (a) denied SSE request returning event-stream error body and session header propagation, (b) SSE list filtering that rewrites only list payload events.
- Compatibility: Non-breaking
- Migration: None.
- Validation: Run policy unit tests and assert event-stream content-type/body formatting for SSE cases.

## 7) `<tests.config-validation-coverage>`
- Priority: Medium
- Area: Tests
- Title: Expand config validation tests for negative and edge policy initialization paths
- Current: Tests cover one invalid exception type and a few happy-path request/response cases.
- Evidence: `mcp-acl-list_test.go` lacks direct coverage for missing mode, invalid mode values, non-object capability blocks, non-array `exceptions`, and fully omitted config behavior.
- Issue: Contract/runtime parity regressions in init parsing are likely to go unnoticed without negative-path coverage.
- Action: Add table-driven tests for `parseAclConfig` and `GetPolicy` validation outcomes.
- Suggested value/name/flag: Include cases for `{}`, missing `mode`, invalid `mode`, wrong object type, wrong `exceptions` type, and capability-specific error assertions.
- Compatibility: Non-breaking
- Migration: None.
- Validation: Ensure each invalid case returns deterministic error text and each valid case initializes expected `AclConfig` state.
