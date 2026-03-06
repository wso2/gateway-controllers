# Parameter Action Items
Policy: url-guardrail
Source: policies/url-guardrail

## 1) `<policy.description>`
- Priority: Medium
- Title: Shorten policy main description to standard length
- Current: Multi-line description exceeds the 250-character standard.
- Issue: Main descriptions should be concise, verb-first, and <= 250 characters.
- Action: Replace with a single concise verb-first description under 250 characters.
- Suggested value/name/flag: Validate URLs in request or response content using optional JSONPath extraction and DNS-only or HTTP reachability checks.
- Compatibility: Non-breaking
- Migration: None.
- Validation: Recount description length and confirm verb-first style.

## 2) `<parameters>`
- Priority: High
- Title: Enforce strict root parameter object
- Current: `parameters` has no `additionalProperties: false`.
- Issue: Unknown top-level keys can be silently accepted and ignored.
- Action: Add strict root object validation.
- Suggested value/name/flag: `additionalProperties: false`
- Compatibility: Breaking
- Migration: Remove unknown top-level keys from existing configs.
- Validation: Verify unknown root keys fail schema validation.

## 3) `<parameters.request>`
- Priority: High
- Title: Enforce strict request object and runtime fail-fast type checks
- Current: Request object is not strict; runtime ignores non-object `request` values.
- Issue: Typos and invalid request shape can silently bypass intended validation.
- Action: Add `additionalProperties: false` and return explicit policy init error when `request` exists but is not an object.
- Suggested value/name/flag: `additionalProperties: false`
- Compatibility: Breaking
- Migration: Remove unknown request keys and ensure `request` is an object.
- Validation: Verify non-object `request` fails policy initialization and unknown fields fail schema validation.

## 4) `<parameters.response>`
- Priority: High
- Title: Enforce strict response object and runtime fail-fast type checks
- Current: Response object is not strict; runtime ignores non-object `response` values.
- Issue: Typos and invalid response shape can silently bypass intended validation.
- Action: Add `additionalProperties: false` and return explicit policy init error when `response` exists but is not an object.
- Suggested value/name/flag: `additionalProperties: false`
- Compatibility: Breaking
- Migration: Remove unknown response keys and ensure `response` is an object.
- Validation: Verify non-object `response` fails policy initialization and unknown fields fail schema validation.

## 5) `<parameters.request.jsonPath>`
- Priority: Medium
- Title: Make jsonPath a non-advanced primary parameter
- Current: `jsonPath` is marked advanced.
- Issue: JSONPath selection is a primary behavior knob in guardrails and should be visible by default.
- Action: Mark request jsonPath as non-advanced.
- Suggested value/name/flag: `x-wso2-policy-advanced-param: false`
- Compatibility: Non-breaking
- Migration: None.
- Validation: Verify UI surfaces `request.jsonPath` outside advanced settings.

## 6) `<parameters.response.jsonPath>`
- Priority: Medium
- Title: Make jsonPath a non-advanced primary parameter in response flow
- Current: `jsonPath` is marked advanced.
- Issue: JSONPath selection is a primary behavior knob in guardrails and should be visible by default.
- Action: Mark response jsonPath as non-advanced.
- Suggested value/name/flag: `x-wso2-policy-advanced-param: false`
- Compatibility: Non-breaking
- Migration: None.
- Validation: Verify UI surfaces `response.jsonPath` outside advanced settings.

## 7) `<parameters.request.jsonPath>`
- Priority: Medium
- Title: Align request jsonPath default with guardrail family standard
- Current: Default is `""` (full payload).
- Issue: Current guardrail convention uses `$.messages` as default unless full payload is intentionally required.
- Action: Set request jsonPath default to `$.messages` and allow explicit empty string for full-payload mode.
- Suggested value/name/flag: `default: "$.messages"`
- Compatibility: Breaking
- Migration: Set `jsonPath: ""` explicitly where full-payload validation is required.
- Validation: Verify omitted `jsonPath` targets `$.messages` and explicit empty string still validates full payload.

## 8) `<parameters.response.jsonPath>`
- Priority: Medium
- Title: Align response jsonPath default with guardrail family standard
- Current: Default is `""` (full payload).
- Issue: Current guardrail convention uses `$.messages` as default unless full payload is intentionally required.
- Action: Set response jsonPath default to `$.messages` and allow explicit empty string for full-payload mode.
- Suggested value/name/flag: `default: "$.messages"`
- Compatibility: Breaking
- Migration: Set `jsonPath: ""` explicitly where full-payload validation is required.
- Validation: Verify omitted `jsonPath` targets `$.messages` and explicit empty string still validates full payload.

## 9) `<parameters.request.timeout>`
- Priority: Medium
- Title: Align schema validation bounds with runtime timeout checks
- Current: Runtime rejects negative timeout, but schema has no minimum constraint.
- Issue: Schema/runtime drift allows invalid values at schema level that runtime later rejects.
- Action: Add minimum bound in schema.
- Suggested value/name/flag: `minimum: 0`
- Compatibility: Non-breaking
- Migration: None.
- Validation: Verify negative timeout fails schema validation before runtime.

## 10) `<parameters.response.timeout>`
- Priority: Medium
- Title: Align schema validation bounds with runtime timeout checks in response flow
- Current: Runtime rejects negative timeout, but schema has no minimum constraint.
- Issue: Schema/runtime drift allows invalid values at schema level that runtime later rejects.
- Action: Add minimum bound in schema.
- Suggested value/name/flag: `minimum: 0`
- Compatibility: Non-breaking
- Migration: None.
- Validation: Verify negative timeout fails schema validation before runtime.

## 11) `<parameters.request>`
- Priority: Medium
- Title: Harmonize runtime numeric parsing with schema integer contract
- Current: Runtime accepts timeout as integer-like strings/floats while schema type is integer.
- Issue: Schema/runtime accepted type set is inconsistent.
- Action: Tighten runtime to accept only integer numeric types, or widen schema intentionally. Prefer tightening runtime.
- Suggested value/name/flag: Accept only integer values for `timeout` in runtime parsing.
- Compatibility: Breaking
- Migration: Replace string/float timeout values with integers in configs.
- Validation: Verify string timeout like `"3000"` is rejected if schema remains integer-only.

## 12) `<systemParameters>`
- Priority: Low
- Title: Enforce strict empty system parameter object
- Current: `systemParameters` omits `additionalProperties: false`.
- Issue: Unexpected system keys can be silently accepted.
- Action: Mark system parameter object as strict.
- Suggested value/name/flag: `additionalProperties: false`
- Compatibility: Breaking
- Migration: Remove unknown system parameter keys from existing configs.
- Validation: Verify unknown system parameter keys are rejected.
