---
name: doc-create
description: Guide for creating documentation. Use this when asked to create documentation for a new policy or modify existing documentation.
---

# Documentation Creation Guide

Use this skill when the user asks to create **new policy documentation** or to **migrate/update existing documentation** so it follows the unified structure defined in [DOC_STRUCTURE.md](../../../DOC_STRUCTURE.md).

## Primary Requirements

### Folder Structure (Must Match Repo Convention)

For a policy named `<policy-name>` and version folder `v0.1`, documentation MUST live under:

- `docs/<policy-name>/v0.1/metadata.json`
- `docs/<policy-name>/v0.1/docs/<policy-name>.md`

Notes:
- Keep the existing folder naming conventions (kebab-case policy names, `v0.1/` version folder).

### metadata.json (Must Match Existing Structure)

Create/update `metadata.json` using this exact shape:

```json
{
  "name": "<POLICY_NAME>",
  "displayName": "<POLICY_DISPLAY_NAME>",
  "version": "<POLICY_VERSION>",
  "provider": "<PROVIDER_NAME>",
  "categories": ["CATEGORY_1"],
  "description": "<DESCRIPTION>"
}
```

Conventions observed in this repo:
- `provider` is typically `WSO2`.
- `version` is typically `0.1` for `v0.1/` docs.

### Documentation Structure (Strict)

All policy markdown docs MUST follow the structure in [DOC_STRUCTURE.md](../../../DOC_STRUCTURE.md).

Section inclusion rules:
- Required sections MUST always be present: `Overview`, `Features`, `Configuration`, `Reference Scenarios`.
- Optional sections MUST NOT be added by default.
	- For **new docs**: include an optional section only if the user explicitly specifies which optional section(s) to include.
	- For **migrations**: include an optional section only if the migration mapping (or existing doc content) requires it.

Use these headings (recommended canonical form):

```markdown
---
title: "Overview"
---

# <Policy Display Name>

## Overview

## Features

## Configuration
### User Parameters (API Definition)
### System Parameters (From config.toml) <!-- Include only if system-level parameters exist -->

## Reference Scenarios

## How it Works

## Limitations

## Notes

## Related Policies
```

Rules:
- The four required sections are: `Overview`, `Features`, `Configuration`, `Reference Scenarios`.
- Do not add extra top-level sections beyond this template.
- Optional sections are: `How it Works`, `Limitations`, `Notes`, `Related Policies`.
- Use markdown lists for `Features`.
- Put all examples (working configs, before/after transformations, error responses) under `Reference Scenarios`.
- `Configuration` MUST include a `build.yaml` integration subsection showing the policy entry snippet.

### Configuration Must Include build.yaml Entry (Mandatory)

Every policy documentation MUST include a subsection under `Configuration` that shows what should be added under `policies:` in `build.yaml`, aligned with:
- This change is done in the `api-platform` repository.
- `build.yaml` path: `/gateway/build.yaml`
- Reference: https://github.com/wso2/api-platform/blob/main/gateway/build.yaml

Use this format (replace `<policy-name>`):

```yaml
- name: <policy-name>
  gomodule: github.com/wso2/gateway-controllers/policies/<policy-name>@v0
```

Example:

```yaml
- name: add-headers
  gomodule: github.com/wso2/gateway-controllers/policies/add-headers@v0
```

## Workflow: Create New Documentation

Follow these steps when the user asks to create docs for a policy that does not yet have documentation in the new structure.

1. Determine:
	- `<policy-name>` (kebab-case)
	- display name
	- version folder (default to `v0.1/` unless the user says otherwise)
	- categories
2. Review the policy source before documenting:
	- Read `policies/<policy-name>/policy-definition.yaml`.
	- Read the relevant implementation files in `policies/<policy-name>/` (for example, main policy logic and key helpers/tests where needed) to understand actual behavior.
	- Use this understanding as the source of truth before writing docs.
3. Create the required folder structure under `docs/<policy-name>/v0.1/`.
4. Create `metadata.json` with the exact structure above.
5. Create `docs/<policy-name>.md` using the strict structure:
	- Fill in `Overview` (what it does, when to use).
	- List capabilities in `Features`.
	- In `Configuration`, document all parameters:
	  - `User Parameters (API Definition)` (per-API/route)
	  - `System Parameters (Comes from config.toml)` (gateway-level) **only if system-level parameters exist**.
	  - Mandatory `build.yaml` entry snippet under `policies:`.
	  - Use tables where appropriate (common format below).
	- In `Reference Scenarios`, include realistic, working examples.
	- Add optional sections only if the user explicitly requested them (and only those sections requested).

### Configuration Tables (Recommended Standard)

When documenting parameters, prefer this table format:

```markdown
| Parameter | Type | Required | Default | Description |
|----------|------|----------|---------|-------------|
| ...      | ...  | ...      | ...     | ...         |
```

Use `yaml` code blocks for API definition examples and `toml` for system config examples.

## Workflow: Migrate / Update Existing Documentation

Follow these steps when the user asks to update older docs so they adhere to the new template.

1. Locate the existing policy documentation markdown under `docs/<policy-name>/...`.
2. Review the policy source before updating docs:
	- Read `policies/<policy-name>/policy-definition.yaml`.
	- Read the relevant implementation files in `policies/<policy-name>/` to verify real behavior.
	- Use implementation + definition as the baseline when fixing or rewriting content.
3. Preserve existing content unless implementation changed:
	- Keep the `Features` section content from the original doc as-is unless the associated implementation has changed.
	- Keep existing tables under `Configuration` as-is unless the associated implementation has changed.
	- Keep existing sample YAMLs as-is unless the associated implementation has changed.
4. Rewrite/restructure the doc to match the strict section template:
	- Ensure required sections exist.
	- Move all examples, error responses, and transformations into `Reference Scenarios`.
5. Apply the migration mapping rules from [DOC_STRUCTURE.md](../../../DOC_STRUCTURE.md).
	- Note: the migration guide mentions “Examples”; in the new structure, that content belongs in `Reference Scenarios`.
6. Include optional sections only when required by migration:
	- If the old doc has `## Internal Architecture` (or `## How It Works`), create/use `## How it Works` and migrate the content.
	- If the old doc has `## Best Practices`, `## Security Considerations`, `## Performance Considerations`, or `## Troubleshooting`, create `## Notes` and merge the content.
	- While merging into `## Notes`, include all useful points (best practices, security guidance, performance guidance, troubleshooting tips, caveats) and avoid dropping actionable details.
	- If an optional section is absent in the source and no mapping requires it, do not add it.
7. Ensure `Configuration` includes the mandatory `build.yaml` policy entry snippet under `policies:`.
8. Remove/merge old sections as needed so the final result only has the template headings.

### Migration Mapping (From DOC_STRUCTURE.md)

| Old Section | Migration Action |
|-------------|------------------|
| `## Internal Architecture` | Rename to `## How it Works` |
| `## How It Works` | Rename to `## How it Works` |
| `## Use Cases` | Merge into `## Reference Scenarios` |
| `## Error Handling` / `## Error Response` | Move into `## Reference Scenarios` |
| `## Request/Response Flow Examples` | Merge into `## Reference Scenarios` |
| `## Policy Behavior` | Merge into `## Notes` or `## How it Works` |
| `## Best Practices` | Merge into `## Notes` |
| `## Security Considerations` | Merge into `## Notes` |
| `## Performance Considerations` | Merge into `## Notes` |
| `## Troubleshooting` | Merge into `## Notes` |
| `## System Configuration Example` | Move into `## Configuration` |
| Standalone concept sections (e.g., `## JSONPath Support`) | Move under `## Configuration` |

## Validation Checklist

Before finishing:
- The doc exists at `docs/<policy-name>/v0.1/docs/<policy-name>.md`.
- `docs/<policy-name>/v0.1/metadata.json` exists and matches the required structure.
- `policies/<policy-name>/policy-definition.yaml` and relevant implementation files were reviewed before writing/updating documentation.
- For migrations, original `Features`, existing `Configuration` tables, and sample YAMLs were preserved unless implementation changes required updates.
- Markdown includes all required sections and no extra top-level sections.
- `Configuration` includes the mandatory `build.yaml` policy entry snippet under `policies:`.
- `System Parameters (From/Comes from config.toml)` is included only when system-level parameters exist.
- For migrations, `## Notes` preserves all useful guidance merged from best-practice/security/performance/troubleshooting sections.

