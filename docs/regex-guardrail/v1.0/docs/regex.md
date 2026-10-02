---
title: "Overview"
---
# Regex Guardrail

## Overview

The Regex Guardrail validates request or response body content against regular expression patterns. This guardrail enables pattern-based content validation, allowing you to enforce specific formats, detect prohibited patterns, or ensure content matches expected structures. It supports both buffered and SSE streaming responses, with cross-chunk pattern matching for streaming scenarios.

## Features

- Pattern matching using regular expressions
- Supports JSONPath extraction to validate specific fields within JSON payloads
- Configurable inverted logic to pass when pattern does not match
- Supports independent request and response phase configuration
- Optional detailed assessment information in error responses
- SSE streaming response validation with cross-chunk content accumulation
- Configurable streaming JSONPath for extracting delta content from SSE events

## Configuration

This policy requires only a single-level configuration where all parameters are configured in the API definition YAML.

### User Parameters (API Definition)

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `request` | object | No | - | Configuration for request-phase regex validation. At least one of `request` or `response` must be provided. |
| `response` | object | No | - | Configuration for response-phase regex validation. At least one of `request` or `response` must be provided. |

#### Request Configuration

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `enabled` | boolean | No | `true` | Enables validation for the request flow. |
| `regex` | string | Conditional | - | Regular expression pattern to match against the content. Required when `enabled: true`. Must be at least 1 character. |
| `jsonPath` | string | No | `"$.messages[-1].content"` | JSONPath expression to extract a specific value from the request JSON payload. If empty, validates the entire payload as a string. |
| `invert` | boolean | No | `false` | If `true`, validation passes when regex does NOT match. If `false`, validation passes when regex matches. |
| `showAssessment` | boolean | No | `false` | If `true`, includes detailed assessment information in error responses. |

#### Response Configuration

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `enabled` | boolean | No | `false` | Enables validation for the response flow. |
| `regex` | string | Conditional | - | Regular expression pattern to match against the content. Required when `enabled: true`. Must be at least 1 character. |
| `jsonPath` | string | No | `"$.choices[0].message.content"` | JSONPath expression to extract a specific value from the response JSON payload. If empty, validates the entire payload as a string. |
| `streamingJsonPath` | string | No | `"$.choices[0].delta.content"` | JSONPath expression to extract content from SSE streaming delta chunks. Used when the upstream returns a streaming (`stream: true`) response. |
| `invert` | boolean | No | `false` | If `true`, validation passes when regex does NOT match. If `false`, validation passes when regex matches. |
| `showAssessment` | boolean | No | `false` | If `true`, includes detailed assessment information in error responses. |

#### JSONPath Support

The guardrail supports JSONPath expressions to extract and validate specific fields within JSON payloads. Common examples:

- `$.messages` - Extracts the `messages` field from the root object
- `$.data.content` - Extracts nested content from `data.content`
- `$.items[0].text` - Extracts text from the first item in an array
- `$.messages[0].content` - Extracts content from the first message in a messages array

If `jsonPath` is empty or not specified, the entire payload is treated as a string and validated.

The path may also select an object or an array, or use a `*` segment to fan out over an object's values or an array's items (for example `$.questions.*.instructions`). Every string, number and boolean inside the selection is validated, joined with newlines, with object keys in sorted order. A path that does not resolve, or that selects no text, fails validation.

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
  gomodule: github.com/wso2/gateway-controllers/policies/regex-guardrail@v1
```

## Reference Scenarios

### Example 1: Email Validation

Deploy an LLM provider that protects against sensitive data leaks by blocking any payloads that mention the word "password" (case-insensitive) in either the user's message or the LLM's response. This is achieved by using the regex policy to validate both request and response payloads:

```yaml
apiVersion: gateway.api-platform.wso2.com/v1
kind: LlmProvider
metadata:
  name: regex-provider
spec:
  displayName: Regex Provider
  version: v1.0
  template: openai
  context: /openai
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
  operationPolicies:
    - name: regex-guardrail
      version: v1
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

```bash
# Valid request (should pass)
curl -X POST http://localhost:8080/openai/chat/completions \
  -H "Content-Type: application/json" \
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
curl -X POST http://localhost:8080/openai/chat/completions \
  -H "Content-Type: application/json" \
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

### Example 2: Streaming Response Validation

Validate streaming SSE responses with a custom delta content path:

```yaml
apiVersion: gateway.api-platform.wso2.com/v1
kind: LlmProvider
metadata:
  name: regex-streaming-provider
spec:
  displayName: Regex Streaming Provider
  version: v1.0
  template: openai
  context: /openai
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
  operationPolicies:
    - name: regex-guardrail
      version: v1
      paths:
        - path: /chat/completions
          methods: [POST]
          params:
            response:
              enabled: true
              regex: "(?i).*confidential.*"
              invert: true
              streamingJsonPath: "$.choices[0].delta.content"
```

When a streaming response violation is detected, the offending chunk is replaced with an SSE error event:

```
data: {"type":"REGEX_GUARDRAIL","message":{"action":"GUARDRAIL_INTERVENED","interveningGuardrail":"regex-guardrail","actionReason":"Violation of regular expression detected.","direction":"RESPONSE"}}
```

## How It Works

#### Request Phase

1. **Content Extraction**: Extracts content from the request body using `jsonPath` (if configured) or uses the entire payload.
2. **Pattern Evaluation**: Applies the configured `regex` pattern to the extracted content.
3. **Invert Handling**: Uses `invert` to decide whether matching or non-matching content should pass.
4. **Decision Enforcement**: Blocks with HTTP `422` when validation fails; otherwise, request proceeds upstream.

#### Response Phase (Buffered)

1. **Content Extraction**: Extracts content from the response body using `jsonPath` (if configured) or uses the entire payload.
2. **Pattern Evaluation**: Applies the configured `regex` pattern to the extracted content.
3. **Invert Handling**: Uses `invert` to decide whether matching or non-matching content should pass.
4. **Decision Enforcement**: Blocks with HTTP `422` when validation fails; otherwise, response is returned to the client.

#### Response Phase (Streaming SSE)

When the upstream returns an SSE streaming response, each SSE event arrives as a `data:` line containing a JSON payload, for example:

```
data: {"choices":[{"delta":{"content":"token"}}]}
```

The regex guardrail uses a **no-buffering pattern** for streaming. `NeedsMoreResponseData` always returns `false` -- each chunk is processed immediately as it arrives. Cross-chunk pattern matching is achieved through state accumulation via `ctx.Metadata` (a persistent key-value store shared across all chunks in a stream) rather than kernel-level buffering.

1. **Chunk Detection**: Each response chunk is inspected to determine whether it is an SSE event (contains `data: ` lines) or a plain JSON chunk.
2. **Content Accumulation**: Delta content is extracted from each SSE event using `streamingJsonPath` (default: `$.choices[0].delta.content`) and accumulated in `ctx.Metadata` across chunks. This enables cross-boundary pattern matching where a prohibited phrase may be split across multiple SSE events.
3. **Pattern Evaluation**: The full accumulated content is evaluated against the `regex` pattern after each chunk arrives.
4. **Invert Semantics**:
   - `invert: true` (blocklist): Violation is detected as soon as the pattern appears in the accumulated content. The offending chunk is replaced with an SSE error event injected into the stream.
   - `invert: false` (allowlist): The full response must match the pattern. Validation can only be confirmed at stream end (`[DONE]`), so an SSE error event is injected at the terminal chunk if no match was found. Content already forwarded to the client cannot be retracted.
5. **Error Handling**: Since HTTP response headers are already committed when streaming begins, violations cannot be reported via HTTP status codes. Instead, the offending chunk is replaced with an SSE error event in the stream.
6. **Plain JSON Chunks**: For non-SSE chunked responses (e.g., `Transfer-Encoding: chunked` without SSE), chunks are accumulated and validated as a complete body at end of stream.

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
- In streaming mode, content already forwarded to the client cannot be retracted when using `invert: false` (allowlist). This is an inherent limitation of response streaming.
- The `streamingJsonPath` parameter is only used for SSE streaming responses. For buffered responses, the `jsonPath` parameter is used instead.
