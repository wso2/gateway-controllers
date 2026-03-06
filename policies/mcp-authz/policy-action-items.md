# Policy Action Items
Policy: mcp-authz
Source: /Users/tharsanan/Documents/worktrees/gateway-controllers/fi-priorotized-policies/policies/mcp-authz

## 1) `<parameters.required>`
- Priority: High
- Area: Contract
- Title: Make `rules` required in schema to match runtime initialization contract
- Current: `parameters.properties.rules` is defined, but `parameters.required` is not declared.
- Evidence: `policies/mcp-authz/policy-definition.yaml` defines `rules` with `minItems: 1` but no top-level required list; runtime `parseRules` returns `rules parameter is required` when missing (`policies/mcp-authz/mcp-authz.go`).
- Issue: Configurations can pass schema validation yet fail at policy initialization, creating contract/runtime drift.
- Action: Declare `rules` as a required field at `parameters` level.
- Suggested value/name/flag: `required: [rules]`
- Compatibility: Breaking
- Migration: Ensure every `mcp-authz` usage includes `params.rules` with at least one rule.
- Validation: Verify `params: {}` fails schema validation and valid `rules` arrays still initialize successfully.

## 2) `<parameters.rules.items.anyOf(requiredClaims|requiredScopes)>`
- Priority: Medium
- Area: Contract
- Title: Require at least one authorization condition per rule
- Current: Rule objects require only `attribute`; both `requiredClaims` and `requiredScopes` are optional.
- Evidence: `policies/mcp-authz/policy-definition.yaml` requires only `attribute`; runtime `ruleGrantsAccess` returns success when both condition sets are empty (`policies/mcp-authz/mcp-authz.go`).
- Issue: A rule with no claims/scopes is accepted and always passes, which can hide misconfiguration in a security policy.
- Action: Enforce conditional requiredness so each rule includes at least one auth constraint.
- Suggested value/name/flag: Add under `parameters.properties.rules.items`:
```yaml
anyOf:
  - required: [requiredClaims]
  - required: [requiredScopes]
```
- Compatibility: Breaking
- Migration: Remove placeholder rules or add explicit `requiredClaims`/`requiredScopes` to each rule.
- Validation: Add schema and initialization tests for rule objects that omit both fields.

## 3) `<docs.mcp-authz.v0.2.example-4.attribute.name>`
- Priority: High
- Area: Docs
- Title: Replace unsupported resource prefix wildcard example in v0.2 docs
- Current: Example 4 uses `attribute.name: "file:///finance/*"` for resource matching.
- Evidence: `docs/mcp-authz/v0.2/docs/mcp-authorization.md` uses that pattern; runtime matching in `findMatchingRules` supports only exact name equality or full `"*"` wildcard (`policies/mcp-authz/mcp-authz.go`).
- Issue: The example implies prefix wildcard support that runtime does not implement, leading to incorrect access-control expectations.
- Action: Update the v0.2 example to use supported matching semantics or add runtime/schema support for prefix wildcards.
- Suggested value/name/flag: For docs-only alignment, use exact resource names plus `"*"` fallback, and explicitly document that only exact match or full `"*"` is supported.
- Compatibility: Non-breaking
- Migration: None.
- Validation: Replay the documented example against current runtime and verify decisions match docs.

## 4) `<docs.mcp-authz.v0.1.example-4.attribute.name>`
- Priority: High
- Area: Docs
- Title: Replace unsupported resource prefix wildcard example in v0.1 docs
- Current: Example 4 uses `attribute.name: "file:///finance/*"` for resource matching.
- Evidence: `docs/mcp-authz/v0.1/docs/mcp-authorization.md` uses that pattern; runtime matching in `findMatchingRules` supports only exact name equality or full `"*"` wildcard (`policies/mcp-authz/mcp-authz.go`).
- Issue: The example implies prefix wildcard support that runtime does not implement, leading to incorrect access-control expectations.
- Action: Update the v0.1 example to use supported matching semantics or add runtime/schema support for prefix wildcards.
- Suggested value/name/flag: For docs-only alignment, use exact resource names plus `"*"` fallback, and explicitly document that only exact match or full `"*"` is supported.
- Compatibility: Non-breaking
- Migration: None.
- Validation: Replay the documented example against current runtime and verify decisions match docs.

## 5) `<docs.mcp-authz.v0.2.parameter-table.defaults>`
- Priority: Medium
- Area: Docs
- Title: Align v0.2 parameter-table defaults with schema defaults
- Current: Docs tables describe fields but omit defaults for values that have schema defaults.
- Evidence: `docs/mcp-authz/v0.2/docs/mcp-authorization.md` tables do not publish defaults for `attribute.name`, `requiredClaims`, and `requiredScopes`; `policies/mcp-authz/policy-definition.yaml` defines defaults for these fields.
- Issue: Operators cannot infer omitted-field behavior from docs alone, increasing configuration ambiguity.
- Action: Add explicit defaults in v0.2 parameter documentation.
- Suggested value/name/flag: `attribute.name: "*"`, `requiredClaims: {}`, `requiredScopes: []`.
- Compatibility: Non-breaking
- Migration: None.
- Validation: Cross-check v0.2 docs tables against `policy-definition.yaml` defaults.

## 6) `<docs.mcp-authz.v0.1.parameter-table.defaults>`
- Priority: Medium
- Area: Docs
- Title: Align v0.1 parameter-table defaults with schema defaults
- Current: Docs tables describe fields but omit defaults for values that have schema defaults.
- Evidence: `docs/mcp-authz/v0.1/docs/mcp-authorization.md` tables do not publish defaults for `attribute.name`, `requiredClaims`, and `requiredScopes`; `policies/mcp-authz/policy-definition.yaml` defines defaults for these fields.
- Issue: Operators cannot infer omitted-field behavior from docs alone, increasing configuration ambiguity.
- Action: Add explicit defaults in v0.1 parameter documentation.
- Suggested value/name/flag: `attribute.name: "*"`, `requiredClaims: {}`, `requiredScopes: []`.
- Compatibility: Non-breaking
- Migration: None.
- Validation: Cross-check v0.1 docs tables against `policy-definition.yaml` defaults.

## 7) `<tests.mcp-authz.unit-and-negative-coverage>`
- Priority: High
- Area: Tests
- Title: Add dedicated `mcp-authz` tests for contract and authorization edge behavior
- Current: The policy has runtime and schema files but no policy-local test file.
- Evidence: `policies/mcp-authz` contains `mcp-authz.go`, `policy-definition.yaml`, `go.mod`, and `go.sum` with no `*_test.go`; repository test discovery under `policies` returns no `mcp-authz` test entries.
- Issue: Regressions in parsing, rule matching, claim/scope evaluation, and error response construction can ship without detection.
- Action: Add table-driven unit tests for initialization and request authorization behavior.
- Suggested value/name/flag: Cover missing/invalid `rules`, default `attribute.name = "*"`, method-rule matching, claim+scope conjunction, `scope` vs `scp` extraction, and deny response status/header/body assertions.
- Compatibility: Non-breaking
- Migration: None.
- Validation: Run `go test ./...` in `policies/mcp-authz` and verify deterministic expectations for positive and negative cases.

## 8) `<process.docs-schema-runtime-drift-gate>`
- Priority: Medium
- Area: Process
- Title: Add CI guardrail to detect docs/schema/runtime drift for policy contracts
- Current: Requiredness/defaults and supported match-shape semantics drifted across contract docs and runtime behavior.
- Evidence: `policies/mcp-authz/policy-definition.yaml` + `policies/mcp-authz/mcp-authz.go` + `docs/mcp-authz/v0.1/docs/mcp-authorization.md` + `docs/mcp-authz/v0.2/docs/mcp-authorization.md` contain mismatches identified above.
- Issue: Manual review alone does not reliably prevent recurring contract drift across versions.
- Action: Add an automated CI check that validates docs tables/examples against schema fields and runtime-supported match modes.
- Suggested value/name/flag: Implement a docs-contract lint step that checks parameter names, requiredness/defaults, and wildcard semantics (`exact` or `"*"` unless runtime adds pattern support).
- Compatibility: Non-breaking
- Migration: None.
- Validation: CI should fail on current drift and pass after docs/schema/runtime alignment.

## 9) `<parameters.rules.items.*.x-wso2-policy-advanced-param>`
- Priority: Medium
- Area: Contract
- Title: Add explicit advanced-parameter flags for rule configuration fields
- Current: Rule configuration fields are declared without `x-wso2-policy-advanced-param` annotations.
- Evidence: `policies/mcp-authz/policy-definition.yaml` defines `rules`, `attribute.type`, `attribute.name`, `requiredClaims`, and `requiredScopes` without advanced-param flags; other policies in this repo annotate user fields explicitly (for example `policies/basic-auth/policy-definition.yaml` and `policies/mcp-acl-list/policy-definition.yaml`).
- Issue: Missing advanced-param metadata weakens contract consistency and leads to inconsistent policy UI field classification.
- Action: Add `x-wso2-policy-advanced-param` to user-facing rule fields.
- Suggested value/name/flag: Add explicit true/false flags to `rules`, `rules[].attribute.type`, `rules[].attribute.name`, `rules[].requiredClaims`, and `rules[].requiredScopes` (default to `false` unless a field is intentionally advanced).
- Compatibility: Non-breaking
- Migration: None.
- Validation: Verify all rule-related user fields include explicit advanced-param metadata and render in expected basic/advanced groups.
