---
title: "Overview"
---
# PII Masking Regex Guardrail

## Overview

The PII Masking Regex guardrail detects and protects Personally Identifiable Information (PII) in request and response payloads. It supports built-in detectors (`email`, `phone`, `ssn`) and custom regex-based detectors, with masking (reversible) or redaction (irreversible) behavior.

## Features

- Built-in PII detectors for email, phone, and SSN
- Custom regex detector support (`customPIIEntities`)
- Two protection modes: masking and redaction
- Optional JSONPath extraction before detection
- Response restoration support when masking mode is used

## Configuration

This policy uses single-level configuration in the API definition YAML.

### User Parameters (API Definition)

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `email` | boolean | Conditional | `false` | Enables built-in email detector. |
| `phone` | boolean | Conditional | `false` | Enables built-in phone detector. |
| `ssn` | boolean | Conditional | `false` | Enables built-in SSN detector. |
| `customPIIEntities` | `PIIEntityConfig[]` | Conditional | - | Custom regex detectors. |
| `jsonPath` | string | No | `"$.messages"` | JSONPath used to extract content before detection. |
| `redactPII` | boolean | No | `false` | `true` redacts with `*****`; `false` masks with reversible placeholders. |

At least one detector must be configured using one of:

- `email: true`
- `phone: true`
- `ssn: true`
- non-empty `customPIIEntities`

#### PIIEntityConfig Configuration

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `piiEntity` | string | Yes | Custom entity key (must match `^[A-Z_]+$`). |
| `piiRegex` | string | Yes | Go RE2-compatible regex for the entity. |

#### JSONPath Support

Examples:

- `$.messages`
- `$.messages[-1].content`
- `$.data.content`

If extraction fails, the policy returns an immediate error response.

**Note:**

Inside `gateway/build.yaml`, ensure the policy module is added under `policies`:

```yaml
- name: pii-masking-regex
  gomodule: github.com/wso2/gateway-controllers/policies/pii-masking-regex@v0
```

## Reference Scenarios

### Example 1: Built-In Detectors (Masking Mode)

```yaml
policies:
  - name: pii-masking-regex
    version: v0
    paths:
      - path: /chat/completions
        methods: [POST]
        params:
          email: true
          phone: true
          ssn: true
          jsonPath: "$.messages[-1].content"
          redactPII: false
```

### Example 2: Custom Detector (Redaction Mode)

```yaml
policies:
  - name: pii-masking-regex
    version: v0
    paths:
      - path: /chat/completions
        methods: [POST]
        params:
          customPIIEntities:
            - piiEntity: CREDIT_CARD
              piiRegex: "\\b(?:\\d[ -]*?){13,16}\\b"
          jsonPath: "$.messages[-1].content"
          redactPII: true
```

## How It Works

#### Request Phase

1. Extracts content from `jsonPath` (default `$.messages`).
2. Applies built-in and custom regex detectors.
3. In masking mode, replaces matches with placeholders and stores mapping in metadata.
4. In redaction mode, replaces matches with `*****`.

#### Response Phase

1. If `redactPII=false`, restores placeholders using metadata mappings.
2. If `redactPII=true`, restoration is skipped.

## Notes

- Built-in regex detectors are provided by policy logic and can be enabled independently.
- Custom regexes use Go `regexp` (RE2) syntax.
- Masking mode is suitable when downstream responses need original values restored.
- Redaction mode is irreversible and should be used when full concealment is required.
