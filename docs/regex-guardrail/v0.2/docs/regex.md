---
title: "Overview"
---
# Regex Guardrail

## Overview

The Regex Guardrail validates request or response body content against regular expression patterns. This guardrail enables pattern-based content validation, allowing you to enforce specific formats, detect prohibited patterns, or ensure content matches expected structures.

## Features

- Pattern matching using regular expressions
- Supports JSONPath extraction to validate specific fields within JSON payloads
- Configurable inverted logic to pass when pattern does not match
- Supports independent request and response phase configuration
- Optional detailed assessment information in error responses

## Configuration

This policy requires only a single-level configuration where all parameters are configured in the API definition YAML.

### User Parameters (API Definition)

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `request` | `RegexGuardRailConfig` object | No | - | Configuration for request-phase regex validation. Supports `regex`, `jsonPath`, `invert`, and `showAssessment`. |
| `response` | `RegexGuardRailConfig` object | No | - | Configuration for response-phase regex validation. Supports `regex`, `jsonPath`, `invert`, and `showAssessment`. |

#### RegexGuardRailConfig Configuration

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `regex` | string | Yes | - | Regular expression pattern to match against the content. Must be at least 1 character. |
| `jsonPath` | string | No | `""` | JSONPath expression to extract a specific value from JSON payload. If empty, validates the entire payload as a string. |
| `invert` | boolean | No | `false` | If `true`, validation passes when regex does NOT match. If `false`, validation passes when regex matches. |
| `showAssessment` | boolean | No | `false` | If `true`, includes detailed assessment information in error responses. |

#### JSONPath Support

The guardrail supports JSONPath expressions to extract and validate specific fields within JSON payloads. Common examples:

- `$.messages` - Extracts the `messages` field from the root object
- `$.data.content` - Extracts nested content from `data.content`
- `$.items[0].text` - Extracts text from the first item in an array
- `$.messages[0].content` - Extracts content from the first message in a messages array

If `jsonPath` is empty or not specified, the entire payload is treated as a string and validated.

#### Regular Expression Syntax

The guardrail uses Go's standard regexp package, which supports RE2 syntax. Key features:

- Case-sensitive matching by default
- Use `(?i)` flag for case-insensitive matching
- Anchors: `^` (start), `$` (end)
- Character classes: `[a-z]`, `[0-9]`, `\d`, `\w`, `\s`
- Quantifiers: `*`, `+`, `?`, `{n}`, `{n,m}`
- Groups and alternation: `(abc|def)`, `(?:non-capturing)`

**Note:**

Inside the `gateway/build.yaml`, ensure the policy module is added under `policies:`:

```yaml
- name: regex-guardrail
  gomodule: github.com/wso2/gateway-controllers/policies/regex-guardrail@v0
```

## Reference Scenarios

### Example 1: Email Validation

Deploy an LLM provider that protects against sensitive data leaks by blocking any payloads that mention the word "password" (case-insensitive) in either the user’s message or the LLM’s response. This is achieved by using the regex policy to validate both request and response payloads:

```yaml
apiVersion: gateway.api-platform.wso2.com/v1alpha1
kind: LlmProvider
metadata:
  name: regex-provider
spec:
  displayName: Regex Provider
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
      - path: /models
        methods: [GET]
      - path: /models/{modelId}
        methods: [GET]
  policies:
    - name: regex-guardrail
      version: v0
      paths:
        - path: /chat/completions
          methods: [POST]
          params:
            request:
              regex: "(?i).*password.*"
              invert: true
              jsonPath: "$.messages[0].content"
```

**Test the guardrail:**

**Note**: Ensure that "openai" is mapped to the appropriate IP address (e.g., 127.0.0.1) in your `/etc/hosts` file. or remove the vhost from the llm provider configuration and use localhost to invoke.

```bash
# Valid request (should pass)
curl -X POST http://openai:8080/chat/completions \
  -H "Content-Type: application/json" \
  -H "Host: openai" \
  -d '{
    "model": "gpt-4",
    "messages": [
      {
        "role": "user",
        "content": "This is a safe message without sensitive data"
      }
    ]
  }'

# Invalid request - no email (should fail with HTTP 422)
curl -X POST http://openai:8080/chat/completions \
  -H "Content-Type: application/json" \
  -H "Host: openai" \
  -d '{
    "model": "gpt-4",
    "messages": [
      {
        "role": "user",
        "content": "My password is 1234567"
      }
    ]
  }'
```

**Error Response:**

When validation fails, the guardrail returns an HTTP 422 status code with the following structure:

```json
{
  "type": "REGEX_GUARDRAIL",
  "message": {
    "action": "GUARDRAIL_INTERVENED",
    "interveningGuardrail": "regex-guardrail",
    "actionReason": "Violation of regular expression detected.",
    "direction": "REQUEST"
  }
}
```

If `showAssessment` is enabled, additional details are included:

```json
{
  "type": "REGEX_GUARDRAIL",
  "message": {
    "action": "GUARDRAIL_INTERVENED",
    "interveningGuardrail": "regex-guardrail",
    "actionReason": "Violation of regular expression detected.",
    "assessments": "Violation of regular expression detected. (?i)ignore\s+all\s+previous\s+instructions",
    "direction": "REQUEST"
  }
}
```

## How It Works

#### Request Phase

1. **Content Extraction**: Extracts content from the request body using `jsonPath` (if configured) or uses the entire payload.
2. **Pattern Evaluation**: Applies the configured `regex` pattern to the extracted content.
3. **Invert Handling**: Uses `invert` to decide whether matching or non-matching content should pass.
4. **Decision Enforcement**: Blocks with HTTP `422` when validation fails; otherwise, request proceeds upstream.

#### Response Phase

1. **Content Extraction**: Extracts content from the response body using `jsonPath` (if configured) or uses the entire payload.
2. **Pattern Evaluation**: Applies the configured `regex` pattern to the extracted content.
3. **Invert Handling**: Uses `invert` to decide whether matching or non-matching content should pass.
4. **Decision Enforcement**: Blocks with HTTP `422` when validation fails; otherwise, response is returned to the client.

#### Validation Behavior

- **Normal Mode (`invert: false`)**: Validation passes when regex matches.
- **Inverted Mode (`invert: true`)**: Validation passes when regex does not match.
- **Assessment Details**: When `showAssessment` is enabled, failure responses include regex-related assessment information.


## Notes

- Regular expressions are evaluated using Go's regexp package (RE2 syntax).
- Pattern matching is case-sensitive by default. Use `(?i)` flag for case-insensitive matching.
- Use `request` and `response` independently to validate one or both directions.
- When using JSONPath, if the path does not exist or the extracted value is not a string, validation will fail.
- Inverted logic is useful for blocking content that matches prohibited patterns.
- Complex regex patterns may impact performance; test thoroughly with expected content volumes.
