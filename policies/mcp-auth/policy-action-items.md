# Policy Action Items
Policy: mcp-auth
Source: /Users/tharsanan/Documents/worktrees/gateway-controllers/fi-priorotized-policies/policies/mcp-auth

## 1) `<systemParameters.keyManagers[].issuer>`
- Priority: High
- Area: Contract
- Title: Align issuer requiredness with well-known metadata runtime behavior
- Current: Schema marks `keyManagers[].issuer` optional, but well-known metadata generation skips entries without issuer and fails when no issuer is available.
- Evidence: `policy-definition.yaml` requires only `name` (`required: ["name"]`), while runtime skips entries when `issuer == ""` and returns auth failure if resulting issuer list is empty (`mcp-auth.go`, key-manager loop and `len(issuers) == 0` checks).
- Issue: Configurations that pass schema can still fail at runtime for `/.well-known/oauth-protected-resource`, causing contract/runtime drift.
- Action: Make issuer requirements explicit and enforceable for this policy path.
- Suggested value/name/flag: Require `issuer` in `keyManagers` for mcp-auth usage, or add runtime fallback logic that can derive `authorization_servers` without `issuer`.
- Compatibility: Breaking
- Migration: Ensure each configured key manager used by mcp-auth includes a non-empty `issuer`.
- Validation: Verify well-known endpoint succeeds with valid issuers and fails fast at validation time for missing issuers.

## 2) `<systemParameters.onFailureStatusCode>`
- Priority: High
- Area: Contract
- Title: Constrain failure status code to supported auth semantics
- Current: Schema type is integer with description implying `401` or `403`, but there is no enum/range and runtime accepts any numeric value.
- Evidence: `policy-definition.yaml` describes `401`/`403` semantics only; runtime reads via `getIntParam` and returns that status directly in `handleAuthFailure`.
- Issue: Invalid or non-auth HTTP status codes can be configured silently, producing unpredictable client behavior.
- Action: Restrict this field to supported values and reject invalid inputs.
- Suggested value/name/flag: Add `enum: [401, 403]` in schema and runtime fail-fast validation for unexpected values.
- Compatibility: Breaking
- Migration: Update existing configs using non-401/403 values.
- Validation: Add tests for accepted (`401`, `403`) and rejected values (`200`, `500`, negative).

## 3) `<systemParameters.errorMessageFormat>`
- Priority: Medium
- Area: Contract
- Title: Add explicit enum for error message format
- Current: Schema allows any string, runtime only has explicit behavior for `json`, `plain`, and `minimal`.
- Evidence: `policy-definition.yaml` has `type: string` without enum; runtime `switch` handles `plain` and `minimal`, with default fallback to JSON.
- Issue: Unsupported values are silently accepted and coerced, hiding config mistakes.
- Action: Constrain allowed format values at schema level.
- Suggested value/name/flag: Add `enum: [json, plain, minimal]`.
- Compatibility: Breaking
- Migration: Replace unsupported format values with one of the supported options.
- Validation: Verify invalid values fail schema validation and valid values preserve existing behavior.

## 4) `<runtime.OnRequest.wellKnown-path-match>`
- Priority: Medium
- Area: Runtime
- Title: Tighten protected-resource endpoint matching
- Current: Well-known handling is triggered by `strings.Contains(ctx.Path, ".well-known/oauth-protected-resource")`.
- Evidence: `mcp-auth.go` well-known branch condition uses substring matching.
- Issue: Substring matching can trigger metadata behavior on unintended paths containing the same fragment.
- Action: Use exact or segment-safe path matching.
- Suggested value/name/flag: Match exact endpoint path (or API-context-prefixed exact suffix) instead of generic substring.
- Compatibility: Breaking
- Migration: Ensure MCP routes use canonical protected-resource endpoint path.
- Validation: Add tests for exact endpoint matches and false-positive paths that should not trigger metadata mode.

## 5) `<runtime.ctx.Metadata-writes>`
- Priority: Medium
- Area: Runtime
- Title: Guard metadata writes against nil map
- Current: Runtime writes to `ctx.Metadata` without ensuring map initialization.
- Evidence: `mcp-auth.go` writes to `ctx.Metadata["gatewayHost"]` and in `handleAuthFailure` writes `auth.success`/`auth.method` directly, with no nil checks.
- Issue: If `ctx.Metadata` is nil in any execution context, policy can panic.
- Action: Initialize metadata map before writes.
- Suggested value/name/flag: Add `if ctx.Metadata == nil { ctx.Metadata = map[string]any{} }` before each metadata mutation path.
- Compatibility: Non-breaking
- Migration: None.
- Validation: Add tests with nil metadata context to confirm no panic.

## 6) `<docs.user-parameters.defaults>`
- Priority: Medium
- Area: Docs
- Title: Align user-parameter defaults with schema defaults
- Current: Docs show `-` defaults for user parameters, while schema defines explicit defaults (`[]` for arrays, `{}` for objects).
- Evidence: `docs/mcp-auth/v0.2/docs/mcp-authentication.md` user parameter table uses `-`; `policy-definition.yaml` sets defaults on `issuers`, `requiredScopes`, `audiences`, `requiredClaims`, and `claimMappings`.
- Issue: Docs under-specify runtime/default behavior and can mislead operators during configuration reviews.
- Action: Update docs default column to match schema.
- Suggested value/name/flag: Use `[]` for array defaults and `{}` for object defaults in docs tables.
- Compatibility: Non-breaking
- Migration: None.
- Validation: Cross-check docs tables against `policy-definition.yaml` defaults for v0.2.

## 7) `<tests.wellKnown-and-config-negative-coverage>`
- Priority: Medium
- Area: Tests
- Title: Add negative-path tests for schema/runtime edge behavior
- Current: Tests focus on happy path metadata generation and one JWT delegation failure path.
- Evidence: `mcp-auth_test.go` lacks cases for missing/blank issuer entries, invalid `errorMessageFormat`, unsupported `onFailureStatusCode`, false-positive well-known path matching, and nil metadata writes.
- Issue: Regressions in policy contract enforcement and edge behavior can pass unnoticed.
- Action: Expand unit tests with table-driven negative and boundary scenarios.
- Suggested value/name/flag: Add dedicated tests for issuer-required behavior, format/status validation, strict endpoint matching, and nil metadata safety.
- Compatibility: Non-breaking
- Migration: None.
- Validation: Ensure each edge case has deterministic expected status/headers/body and no panic paths.

## 8) `<parameters.*.x-wso2-policy-advanced-param>`
- Priority: Medium
- Area: Contract
- Title: Add explicit advanced-parameter flags for user-facing auth settings
- Current: User parameter fields are declared without `x-wso2-policy-advanced-param` annotations.
- Evidence: `policies/mcp-auth/policy-definition.yaml` defines `issuers`, `requiredScopes`, `audiences`, `requiredClaims`, and `claimMappings` without advanced-param flags; other policies in this repo use explicit flags on user fields (for example `policies/basic-auth/policy-definition.yaml` and `policies/mcp-acl-list/policy-definition.yaml`).
- Issue: The policy contract omits UI classification metadata, which creates inconsistent parameter presentation and review parity across policies.
- Action: Add `x-wso2-policy-advanced-param` to each user-facing leaf field under `parameters`.
- Suggested value/name/flag: Add explicit true/false flags for `issuers`, `requiredScopes`, `audiences`, `requiredClaims`, and `claimMappings` (use `false` for primary/common fields and `true` only for intentionally advanced options).
- Compatibility: Non-breaking
- Migration: None.
- Validation: Verify every user-facing field in `parameters` has explicit advanced-param metadata and that generated policy UI groups fields as expected.
