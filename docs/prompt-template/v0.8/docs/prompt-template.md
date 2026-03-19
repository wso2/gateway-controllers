---
title: "Overview"
---
# Prompt Template

## Overview

The Prompt Template policy enables dynamic prompt transformation by replacing `template://` URI patterns in JSON payloads with predefined templates. Template placeholders are resolved using parameters passed in the URI query string, allowing you to standardize and reuse prompts across different API calls. This is particularly useful for AI/LLM APIs where consistent prompt formatting improves response quality and maintainability.

## Features

- Pattern-based template matching using `template://` URI format
- Parameter substitution with `[[parameter-name]]` placeholder syntax
- Multiple templates per policy configuration
- JSON-safe string replacement and escaping
- Processes entire JSON payload as string to find and replace patterns

## Configuration

This policy requires only a single-level configuration where all parameters are configured in the API definition YAML.

### User Parameters (API Definition)

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `templates` | array | Yes | - | Specifies one or more reusable prompt templates. Each template must include a unique name and template content. |
| `jsonPath` | string | No | `""` | Specifies the JSONPath to limit template resolution to a specific string field. If empty, template references are resolved across the entire request payload string. |
| `onMissingTemplate` | string | No | `"error"` | Specifies behavior when a referenced template name is not found. `error` returns an immediate error response, `passthrough` leaves the original template reference unchanged. |
| `onUnresolvedPlaceholder` | string | No | `"keep"` | Specifies behavior when placeholders remain unresolved after query substitution. `keep` keeps placeholders as-is, `empty` replaces them with an empty string, and `error` returns an immediate error response. |

#### Template Object

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `name` | string | Yes | Unique identifier for the template (used in `template://` URIs). Must match pattern `^[a-zA-Z0-9_-]+$`. |
| `template` | string | Yes | Template text with `[[parameter]]` placeholder syntax. Query parameters are substituted using these placeholders. |

### Template Configuration Format

The `templates` value is an array of template objects:

```yaml
templates:
  - name: template-name
    template: "Template text with [[placeholder]] syntax"
```

Each template object contains:
- **name**: Unique identifier for the template (used in `template://` URIs)
- **template**: The template string with `[[parameter-name]]` placeholders that will be replaced

#### Template Syntax

##### Template URI Format

Templates are referenced in JSON payloads using the following URI format:

```
template://<template-name>?<param1>=<value1>&<param2>=<value2>
```

Example:
```
template://translate?from=english&to=spanish&text=Hello world
```

##### Placeholder Syntax

Within template prompts, use double square brackets to define placeholders:

```
[[parameter-name]]
```

During resolution, placeholders are replaced with values from the URI query parameters. Parameter names are case-sensitive and must match exactly between the placeholder and the URI parameter.

Example template:
```
Translate the following text from [[from]] to [[to]]: [[text]]
```

When called with `template://translate?from=english&to=spanish&text=Hello`, the resolved prompt would be:
```
Translate the following text from english to spanish: Hello
```

**Note:**

Inside the `gateway/build.yaml`, ensure the policy module is added under `policies:`:

```yaml
- name: prompt-template
  gomodule: github.com/wso2/gateway-controllers/policies/prompt-template@v0
```

## Reference Scenarios

### Example 1: Translation Template

Deploy an LLM provider with a translation prompt template:

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
                template: "Translate the following text from [[from]] to [[to]]: [[text]]"
```

**Test the template:**

**Note**: Ensure that "openai" is mapped to the appropriate IP address (e.g., 127.0.0.1) in your `/etc/hosts` file, or remove the vhost from the LLM provider configuration and use localhost to invoke.

```bash
curl -X POST http://openai:8080/chat/completions \
  -H "Content-Type: application/json" \
  -H "Host: openai" \
  -d '{
    "model": "gpt-4",
    "messages": [
      {
        "role": "user",
        "content": "template://translate?from=english&to=spanish&text=Hello world"
      }
    ]
  }'
```

The policy will transform the request to:

```json
{
  "model": "gpt-4",
  "messages": [
    {
      "role": "user",
      "content": "Translate the following text from english to spanish: Hello world"
    }
  ]
}
```

### Example 2: Summarization Template

Create a template for summarizing content with configurable length:

```yaml
apiVersion: gateway.api-platform.wso2.com/v1alpha1
kind: LlmProvider
metadata:
  name: summarization-provider
spec:
  displayName: Summarization Provider
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
              - name: summarize
                template: "Summarize the following content in [[length]] words: [[content]]"
```

**Test with template:**

```bash
curl -X POST http://openai:8080/chat/completions \
  -H "Content-Type: application/json" \
  -H "Host: openai" \
  -d '{
    "model": "gpt-4",
    "messages": [
      {
        "role": "user",
        "content": "template://summarize?length=50&content=Artificial intelligence is a branch of computer science that aims to create intelligent machines capable of performing tasks that typically require human intelligence."
      }
    ]
  }'
```

### Example 3: Multiple Templates

Configure multiple templates in a single policy:

```yaml
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
            - name: summarize
              template: "Summarize in [[length]] words: [[content]]"
            - name: explain
              template: "Explain [[topic]] to a [[audience]] audience: [[question]]"
```

## How It Works

#### Request Phase

1. **Pattern Detection**: Scans the incoming JSON payload (or targeted field if `jsonPath` is specified) for `template://` URI patterns.
2. **Template Resolution**: Extracts template name and query parameters, then finds the matching template in `templates`.
3. **Placeholder Substitution**: Replaces `[[parameter-name]]` placeholders in the template using URL-decoded query parameter values.
4. **Missing Template Handling**: If a referenced template is not found, behavior is controlled by `onMissingTemplate` (`error` or `passthrough`).
5. **Unresolved Placeholder Handling**: If placeholders remain after substitution, behavior is controlled by `onUnresolvedPlaceholder` (`keep`, `empty`, or `error`).
6. **Safe Replacement**: JSON-escapes the resolved template and replaces the matched `template://` pattern in the payload.
7. **Forwarding**: Sends the transformed payload to the upstream API.

#### Template Pattern Matching

- **Pattern**: `template://[a-zA-Z0-9_-]+\?[^\s"']*`
- **Location**: Searches the entire JSON payload as a string.
- **Replacement**: Each matched pattern is replaced with the resolved template string (JSON-escaped).
- **Multi-match support**: Multiple `template://` patterns can exist in a single payload and are resolved independently.



## Notes

- Common use cases include standardized prompts, reusable prompt libraries, parameterized prompts, multi-language prompt generation, and centralized prompt versioning.
- Template names must match pattern `^[a-zA-Z0-9_-]+$` and are case-sensitive.
- Parameter names in placeholders `[[param]]` are case-sensitive and must match query parameter names exactly.
- Query parameter values are URL-decoded before being inserted into templates.
- The resolved template string is JSON-escaped (special characters like quotes, newlines are escaped) before replacement.
- Use `jsonPath` to limit template resolution to a specific field instead of the entire payload.
- Use `onMissingTemplate: passthrough` to leave unresolved template references unchanged instead of returning an error.
- Use `onUnresolvedPlaceholder: empty` to replace missing placeholders with empty strings, or `error` to fail on missing placeholders.
- Multiple `template://` patterns can appear in a single payload and will all be processed.
