# API Platform Policy Review Instructions

Use these instructions when the task involves auditing or reviewing an API Platform gateway policy, including rename proposals, schema/runtime validation issues, and policy integration-test fallout.

## Review Goal

Review each policy as a contract: schema, runtime parsing/validation, and observed behavior must align. Produce concrete, action-oriented findings with precise parameter paths and code references.

## Review Scope

Cover these areas unless the user explicitly narrows scope:
- Parameter naming quality
- Schema/runtime type and shape alignment
- Required/optional/default correctness
- Request vs response phase semantics
- Validation strictness and integration-test impact
- Migration and compatibility risk for proposed changes

## Workflow

1. Read contract first.
- Read `policies/<policy>/policy-definition.yaml`.
- Identify user parameters vs system parameters.
- Capture required fields, defaults, conditionals (`anyOf`/`allOf`/`if-then`), and `additionalProperties` behavior.

2. Read runtime behavior.
- Read policy implementation (`*.go`) with focus on `GetPolicy`, parsing helpers, and `OnRequest`/`OnResponse`.
- Record exact keys runtime reads and how missing/invalid values are handled.
- Verify whether policy is request-only, response-only, or dual-flow.

3. Compare schema vs runtime.
- Flag mismatches in accepted types, requiredness, defaults, and conditional behavior.
- Flag cases where schema allows config runtime rejects (or vice versa).
- Flag docs/comments that imply behavior not implemented.

4. Assess naming quality.
- Prefer explicit names over overloaded or generic keys.
- Ensure numeric parameters include unit semantics when needed.
- Ensure booleans read as toggles (`useX`, `enableX`, `allowX`).
- Ensure identity fields and display fields are clearly separated.

5. Evaluate change impact.
- Determine whether a proposed rename or refactor is breaking.
- Recommend alias/transitional handling only when needed.
- Note integration-test updates required by stricter validation.

6. Produce review output.
- Present findings first, most severe first.
- Include exact file path, parameter path, and runtime evidence.
- Keep recommendations actionable and minimal.

## Naming Rules

- Use names that match actual runtime semantics, not aspirational wording.
- Include units for unit-bound values (`*Seconds`, `*Millis`, `*Bytes`, `*Words`, `*Sentences`).
- Avoid ambiguous keys such as `name`, `key`, and `target` when meaning varies.
- Use capability-specific names when one field currently carries multiple semantics.
- Use `request.*` and `response.*` only when phase intent is real in behavior.

## Schema Rules

- Keep schema and runtime accepted shapes aligned.
- Do not rely on schema defaults that runtime ignores.
- Requiredness must match runtime assumptions.
- Scope conditional rules correctly (for example, avoid `if` conditions that match when a field is absent).
- Keep rejection behavior predictable across validation layers.

## Output Rules

When producing rename sheets (CSV or Markdown):
- Every row must be standalone.
- Avoid "Same as above".
- Reason text must state:
  - what is ambiguous today
  - what the new name makes explicit

When producing findings:
- Include severity, parameter path, evidence, and action.
- Prefer short, direct findings over long narrative.

## Final Validation

Before finalizing:
- Verify every recommendation is backed by runtime code behavior.
- Verify parameter paths exist in the current schema.
- Verify wording does not imply unsupported runtime behavior.
- If both CSV and Markdown summaries are updated, keep wording aligned.
