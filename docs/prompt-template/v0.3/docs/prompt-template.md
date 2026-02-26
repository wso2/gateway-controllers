---
title: "Overview"
---
# Prompt Template

## Overview

The Prompt Template policy resolves `template://...` references in request payloads using configured templates. It supports reusable templates with query-parameter substitution and flexible behavior for missing templates or unresolved placeholders.

## Features

- Reusable named templates via `templates`
- Template references using `template://<name>?k=v`
- Placeholder substitution with `[[placeholder]]` syntax
- Optional JSONPath-scoped replacement
- Configurable handling for missing templates and unresolved placeholders
- Supports both array and JSON-string input for `templates`

## Configuration

This policy uses single-level configuration in the API definition YAML.

### User Parameters (API Definition)

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `templates` | `TemplateConfig[]` | Yes | - | List of reusable templates. |
| `jsonPath` | string | No | `""` | JSONPath to limit replacement to one string field. If empty, replacement runs on full payload text. |
| `onMissingTemplate` | string | No | `error` | Behavior when template name is not found. Values: `error`, `passthrough`. |
| `onUnresolvedPlaceholder` | string | No | `keep` | Behavior for unresolved `[[...]]` placeholders. Values: `keep`, `empty`, `error`. |

#### TemplateConfig Configuration

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `name` | string | Yes | Unique template name. Must match `^[a-zA-Z0-9_-]+$`. |
| `template` | string | Yes | Template text containing optional placeholders like `[[name]]`. |

### Template Reference Format

Template references in payloads use:

```text
template://<template-name>?<param1>=<value1>&<param2>=<value2>
```

Placeholders are written as:

```text
[[parameter-name]]
```

**Note:**

Inside `gateway/build.yaml`, ensure the policy module is added under `policies`:

```yaml
- name: prompt-template
  gomodule: github.com/wso2/gateway-controllers/policies/prompt-template@v0
```

## Reference Scenarios

### Example 1: Template Resolution Across Full Payload

```yaml
apiVersion: gateway.api-platform.wso2.com/v1alpha1
kind: LlmProvider
metadata:
  name: translation-provider
spec:
  displayName: Translation Provider
  version: v1.0
  template: openai
  vhost: openai
  upstream:
    url: "https://api.openai.com/v1"
    auth:
      type: api-key
      header: Authorization
      value: Bearer <openai-apikey>
  accessControl:
    mode: deny_all
    exceptions:
      - path: /chat/completions
        methods: [POST]
  policies:
    - name: prompt-template
      version: v0
      paths:
        - path: /chat/completions
          methods: [POST]
          params:
            templates:
              - name: translate
                template: "Translate from [[from]] to [[to]]: [[text]]"
```

Request content:

```text
template://translate?from=english&to=spanish&text=Hello
```

Resolved content:

```text
Translate from english to spanish: Hello
```

### Example 2: JSONPath-Scoped Resolution

```yaml
policies:
  - name: prompt-template
    version: v0
    paths:
      - path: /chat/completions
        methods: [POST]
        params:
          templates:
            - name: summarize
              template: "Summarize in [[length]] words: [[content]]"
          jsonPath: "$.messages[-1].content"
          onMissingTemplate: passthrough
          onUnresolvedPlaceholder: empty
```

## How It Works

#### Request Phase

1. Loads configured templates into a lookup map.
2. Finds `template://...` references in target text.
3. Parses template name and query parameters.
4. Replaces placeholders in template text.
5. Applies missing/unresolved behavior settings.
6. Writes updated content back to payload.

#### Response Phase

No response-phase processing is applied.

## Notes

- `templates` accepts both an object array and a JSON-string payload for compatibility.
- If `onMissingTemplate=passthrough`, unresolved template references are left unchanged.
- If `onUnresolvedPlaceholder=error`, request processing returns an immediate error response.
- `jsonPath` is optional; empty value preserves full-payload replacement behavior.
