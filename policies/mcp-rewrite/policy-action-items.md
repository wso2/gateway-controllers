# Policy Action Items
Policy: mcp-rewrite
Source: /Users/tharsanan/Documents/worktrees/gateway-controllers/fi-priorotized-policies/policies/mcp-rewrite

## 1) `<runtime.rewriteListItems.filtering>`
- Priority: High
- Area: Runtime
- Title: Enforce configured-list filtering instead of pass-through for unmatched upstream entries
- Current: List responses keep unmatched upstream items and only rewrite matched ones.
- Evidence: `policies/mcp-rewrite/mcp-rewrite.go` appends unmatched entries in `rewriteListItems` (`filtered = append(filtered, item)` on lookup miss) and `OnResponse` applies that function for `action == "list"`.
- Issue: Contract/docs state that configured lists should constrain `tools/list`, `resources/list`, and `prompts/list` results to configured entries, but runtime currently allows unconfigured items through.
- Action: Change `rewriteListItems` to emit only configured entries when a capability list is configured (non-empty).
- Suggested value/name/flag: On lookup miss in `rewriteListItems`, do not append the upstream item; keep only entries resolved by `config.TargetLookup`.
- Compatibility: Breaking
- Migration: Add every intended capability to the configured list, or omit the capability block to retain allow-all behavior.
- Validation: Add per-capability tests where upstream list contains configured and unconfigured entries; assert only configured entries remain.

## 2) `<runtime.OnRequest.unlisted-capability-handling>`
- Priority: High
- Area: Runtime
- Title: Reject unlisted capability invocations when a capability list is configured
- Current: Requests for capability names/URIs not found in `config.Lookup` are passed upstream unchanged.
- Evidence: `policies/mcp-rewrite/mcp-rewrite.go` returns `nil` on `if !exists { return nil }` in `OnRequest` after parsing `tools/call`, `resources/read`, and `prompts/get`.
- Issue: Unlisted calls bypass configured allowlist intent and contradict published behavior that unlisted capabilities are rejected.
- Action: Return an immediate JSON-RPC error when config is enabled with non-empty entries and request capability is not configured.
- Suggested value/name/flag: Emit `policy.ImmediateResponse` with HTTP 403 and JSON-RPC `-32602` message like `MCP <capabilityType> '<value>' is not allowed`.
- Compatibility: Breaking
- Migration: Update clients to call configured user-facing names/URIs only; if pass-through is required, remove that capability block from params.
- Validation: Add request tests for tools/resources/prompts lookup misses (JSON and SSE) and assert deterministic error payload/header behavior.

## 3) `<policy.description>`
- Priority: High
- Area: Contract
- Title: Align empty-array (`[]`) semantics between contract text and runtime behavior
- Current: Contract text states `set [] to deny all`, while runtime treats configured empty arrays as no-op.
- Evidence: `policies/mcp-rewrite/policy-definition.yaml` description (line 4) says `set [] to deny all`; runtime returns early on `len(config.Entries) == 0` in `OnRequest` and returns unchanged items in `rewriteListItems`.
- Issue: Consumers cannot rely on advertised deny-all behavior for explicit empty lists.
- Action: Make runtime enforce deny-all semantics for explicit empty lists and keep contract/docs wording consistent.
- Suggested value/name/flag: For enabled empty lists, reject `tools/call`/`resources/read`/`prompts/get` and return empty arrays for corresponding `*/list` responses.
- Compatibility: Breaking
- Migration: Replace `[]` with omitted/null params in deployments that currently rely on allow-all behavior.
- Validation: Add tests proving `[]` blocks request actions and yields empty list results for all three capability types.

## 4) `<parameters.*.items.properties.target.minLength>`
- Priority: Medium
- Area: Contract
- Title: Remove target-empty ambiguity by matching runtime validation with schema intent
- Current: Schema requires non-empty `target` when provided, but runtime treats empty/whitespace targets as omitted and falls back to `name`/`uri`.
- Evidence: `policies/mcp-rewrite/policy-definition.yaml` sets `minLength: 1` for all `target` fields; `policies/mcp-rewrite/mcp-rewrite.go` falls back when `strings.TrimSpace(target) == ""`.
- Issue: Behavior depends on whether upstream schema validation runs; explicit-empty target handling is inconsistent.
- Action: Reject explicit empty/whitespace `target` values in runtime parsing.
- Suggested value/name/flag: In `parseCapabilityConfig`, when `target` key exists and `strings.TrimSpace(targetStr) == ""`, return `fmt.Errorf("%s[%d].target must be a non-empty string", capabilityType, i)`.
- Compatibility: Breaking
- Migration: Remove `target: ""` (or whitespace-only values) and omit `target` to use fallback mapping.
- Validation: Add `GetPolicy` negative tests for empty/whitespace `target` on `tools`, `resources`, and `prompts`.

## 5) `<docs.v0.2.overview.action-scope>`
- Priority: Medium
- Area: Docs
- Title: Document the exact MCP action scope for request and response behavior
- Current: Docs describe rewriting/filtering behavior broadly without an explicit action matrix.
- Evidence: `docs/mcp-rewrite/v0.2/docs/mcp-rewrite.md` overview states request rewriting and list filtering generally; runtime limits request rewrites to `tools/call`, `resources/read`, `prompts/get` (`rewriteApplicable`) and response processing to `action == "list"`.
- Issue: Operators can over-assume policy coverage across other MCP actions.
- Action: Add an explicit method/action behavior matrix in docs.
- Suggested value/name/flag: Add a table: request rewrite scope (`tools/call`, `resources/read`, `prompts/get`) and response rewrite/filter scope (`tools/list`, `resources/list`, `prompts/list` only).
- Compatibility: Non-breaking
- Migration: None.
- Validation: Review docs examples and ensure every scenario maps to supported runtime action paths.

## 6) `<tests.allowlist-and-validation-coverage>`
- Priority: High
- Area: Tests
- Title: Add negative and compatibility-sensitive tests for allowlist semantics
- Current: Tests cover rewrite happy paths and one no-rewrite case, but not blocking/filtering contracts or parser negatives.
- Evidence: `policies/mcp-rewrite/mcp-rewrite_test.go` lacks cases for unlisted capability calls, empty-list behavior, non-object `params`, missing capability keys, and invalid `target` values.
- Issue: Contract-runtime regressions can merge without detection.
- Action: Expand unit tests with table-driven negative and compatibility cases.
- Suggested value/name/flag: Add cases for (a) configured-list filtering, (b) unlisted request rejection, (c) empty-array deny-all behavior, (d) invalid request `params`, and (e) invalid config values at `GetPolicy`.
- Compatibility: Non-breaking
- Migration: None.
- Validation: Run `go test ./...` in `policies/mcp-rewrite` and verify each new case asserts error code/message and response shape.

## 7) `<tests.sse-path-coverage>`
- Priority: Medium
- Area: Tests
- Title: Cover SSE request/response branches used by MCP streaming traffic
- Current: No tests exercise `text/event-stream` paths.
- Evidence: `policies/mcp-rewrite/mcp-rewrite.go` has SSE-specific branches (`isEventStream`, `parseEventStream`, `buildEventStream`, SSE loops in `OnResponse`, SSE error builders), but `policies/mcp-rewrite/mcp-rewrite_test.go` has no event-stream headers/payload cases.
- Issue: Streaming behavior can regress independently from JSON-body paths.
- Action: Add focused SSE tests for request parsing/rewrite/errors and list-response rewrite/filtering.
- Suggested value/name/flag: Include assertions for event payload reconstruction and `mcp-session-id` propagation on immediate SSE error responses.
- Compatibility: Non-breaking
- Migration: None.
- Validation: Run `go test ./...` and confirm SSE fixtures validate both rewritten and error event-stream outputs.

## 8) `<process.ci-contract-parity-gate>`
- Priority: Medium
- Area: Process
- Title: Add CI gate for behavior claimed by policy contract/docs
- Current: Drift between contract/docs and runtime reached the branch without an automated parity check.
- Evidence: `policies/mcp-rewrite/policy-definition.yaml` and `docs/mcp-rewrite/v0.2/docs/mcp-rewrite.md` claim configured-list restriction semantics while runtime currently passes unlisted traffic/items.
- Issue: Similar drift is likely to recur unless contract-critical behaviors are guarded in CI.
- Action: Add a CI-required parity test suite for mcp-rewrite contract claims.
- Suggested value/name/flag: Add a focused test group (for filtering, unlisted-request blocking, and empty-list behavior) and make `go test ./...` for `policies/mcp-rewrite` a required CI check.
- Compatibility: Non-breaking
- Migration: None.
- Validation: Confirm CI fails when parity assertions are intentionally broken and passes when runtime/docs/schema stay aligned.

## 9) `<parameters.*.x-wso2-policy-advanced-param>`
- Priority: Medium
- Area: Contract
- Title: Add explicit advanced-parameter flags for rewrite configuration fields
- Current: Rewrite configuration fields are declared without `x-wso2-policy-advanced-param` annotations.
- Evidence: `policies/mcp-rewrite/policy-definition.yaml` defines `tools`, `resources`, `prompts` and their declared item fields without advanced-param flags; other policies in this repo annotate user-facing fields explicitly (for example `policies/prompt-template/policy-definition.yaml` and `policies/mcp-acl-list/policy-definition.yaml`).
- Issue: The contract does not communicate basic vs advanced UI intent, creating inconsistent policy authoring experience across policies.
- Action: Add `x-wso2-policy-advanced-param` to user-facing rewrite fields.
- Suggested value/name/flag: Add explicit true/false flags for `tools`/`resources`/`prompts` and declared item fields (`name`, `description`, `inputSchema`, `outputSchema`, `uri`, `target`), using `true` only where a field is intentionally advanced.
- Compatibility: Non-breaking
- Migration: None.
- Validation: Verify every declared user-facing rewrite field has advanced-param metadata and UI grouping remains deterministic.
