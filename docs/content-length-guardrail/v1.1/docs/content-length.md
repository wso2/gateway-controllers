---
title: "Overview"
---
# Content Length Guardrail

## Overview

The Content Length Guardrail validates the byte length of request or response body content against configurable minimum and maximum thresholds. This guardrail is essential for controlling payload sizes, preventing resource exhaustion, and ensuring efficient data transfer.

This policy supports SSE streaming responses. When the upstream returns a streaming response (`stream: true`), the guardrail accumulates SSE delta content and validates the byte length across the full streamed output, using a configurable `streamingJsonPath` to extract content from each SSE event.

## Features

- Validates byte length against minimum and maximum thresholds
- Supports JSONPath extraction to validate specific fields within JSON payloads
- Configurable inverted logic to pass when content length is outside the range
- Supports independent request and response phase configuration
- Optional detailed assessment information in error responses
- **SSE Streaming Support**: Processes streaming responses in real time using a gate-then-stream pattern, buffering until minimum thresholds are met before releasing to the client
- Configurable `streamingJsonPath` for extracting content from SSE delta chunks

## Configuration

This policy uses a single-level configuration where all parameters are configured in the API definition YAML.

### User Parameters (API Definition)

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `request` | object | No* | - | Configuration for request-phase content length validation. |
| `response` | object | No* | - | Configuration for response-phase content length validation. |

*At least one of `request` or `response` must be provided.

#### Request Configuration

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `enabled` | boolean | No | `true` | Enables validation for the request flow. |
| `min` | integer | Conditional | - | Minimum allowed byte length (inclusive). Must be >= 0. Required when `enabled` is `true`. |
| `max` | integer | Conditional | - | Maximum allowed byte length (inclusive). Must be >= 1. Required when `enabled` is `true`. |
| `jsonPath` | string | No | `"$.messages[-1].content"` | JSONPath expression to extract a specific value from the JSON payload. Set to `""` to validate the entire payload. |
| `invert` | boolean | No | `false` | If `true`, validation passes when content length is NOT within the min-max range. If `false`, validation passes when content length is within the range. |
| `showAssessment` | boolean | No | `false` | If `true`, includes detailed assessment information in error responses. |

#### Response Configuration

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `enabled` | boolean | No | `false` | Enables validation for the response flow. |
| `min` | integer | Conditional | - | Minimum allowed byte length (inclusive). Must be >= 0. Required when `enabled` is `true`. |
| `max` | integer | Conditional | - | Maximum allowed byte length (inclusive). Must be >= 1. Required when `enabled` is `true`. |
| `jsonPath` | string | No | `"$.choices[0].message.content"` | JSONPath expression to extract a specific value from the JSON payload. Set to `""` to validate the entire payload. |
| `streamingJsonPath` | string | No | `"$.choices[0].delta.content"` | JSONPath expression to extract content from SSE streaming delta chunks. Used when the upstream returns a streaming (`stream: true`) response. |
| `invert` | boolean | No | `false` | If `true`, validation passes when content length is NOT within the min-max range. If `false`, validation passes when content length is within the range. |
| `showAssessment` | boolean | No | `false` | If `true`, includes detailed assessment information in error responses. |

#### JSONPath Support

The guardrail supports JSONPath expressions to extract and validate specific fields within JSON payloads. Common examples:

- `$.messages[-1].content` - Extracts content from the last message in a messages array (default for request)
- `$.choices[0].message.content` - Extracts content from the first choice message (default for response)
- `$.choices[0].delta.content` - Extracts content from SSE delta chunks (default for streaming)
- `$.messages` - Extracts the `messages` field from the root object
- `$.data.content` - Extracts nested content from `data.content`
- `$.items[0].text` - Extracts text from the first item in an array

Set `jsonPath` to `""` to validate the entire payload as a string.

**Note:**

Inside the `gateway/build.yaml`, ensure the policy module is added under `policies:`:

```yaml
- name: content-length-guardrail
  gomodule: github.com/wso2/gateway-controllers/policies/content-length-guardrail@v1
```

## Reference Scenarios

### Example 1: Basic Content Length Validation

Deploy an LLM provider that limits request payloads to between 100 bytes and 1MB:

```yaml
apiVersion: gateway.api-platform.wso2.com/v1
kind: LlmProvider
metadata:
  name: content-length-provider
spec:
  displayName: Content Length Provider
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
    - name: content-length-guardrail
      version: v1
      paths:
        - path: /chat/completions
          methods: [POST]
          params:
            request:
              min: 100
              max: 1048576
              jsonPath: "$.messages[-1].content"
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
        "content": "Please explain artificial intelligence in simple terms for beginners"
      }
    ]
  }'

# Invalid request - too small (should fail with HTTP 422)
curl -X POST http://localhost:8080/openai/chat/completions \
  -H "Content-Type: application/json" \
  -d '{
    "model": "gpt-4",
    "messages": [
      {
        "role": "user",
        "content": "Hi"
      }
    ]
  }'
```

**In Case of Error Response:**

When validation fails, the guardrail returns an HTTP 422 status code with the following structure:

```json
{
  "type": "CONTENT_LENGTH_GUARDRAIL",
  "message": {
    "action": "GUARDRAIL_INTERVENED",
    "interveningGuardrail": "content-length-guardrail",
    "actionReason": "Violation of applied content length constraints detected.",
    "direction": "REQUEST"
  }
}
```

If `showAssessment` is enabled, additional details are included:

```json
{
  "type": "CONTENT_LENGTH_GUARDRAIL",
  "message": {
    "action": "GUARDRAIL_INTERVENED",
    "interveningGuardrail": "content-length-guardrail",
    "actionReason": "Violation of applied content length constraints detected.",
    "assessments": "Violation of content length detected. Expected between 10 and 100 bytes.",
    "direction": "REQUEST"
  }
}
```

### Example 2: Response Streaming Validation

Validate content length on streaming LLM responses using a custom streaming JSONPath:

```yaml
  operationPolicies:
    - name: content-length-guardrail
      version: v1
      paths:
        - path: /chat/completions
          methods: [POST]
          params:
            response:
              enabled: true
              min: 100
              max: 1048576
              jsonPath: "$.choices[0].message.content"
              streamingJsonPath: "$.choices[0].delta.content"
```

When the upstream returns an SSE streaming response, the guardrail accumulates delta content from each SSE event and validates the total byte length. For non-streaming responses, the standard `jsonPath` is used instead. If the byte length exceeds the maximum during streaming, an SSE error event is injected into the stream. If the byte length is below the minimum when the stream completes, an SSE error event is appended.

## How it Works

#### Request Phase

1. **Content Extraction**: Extracts content from the request body using `jsonPath` (if configured) or uses the entire payload.
2. **Byte Length Calculation**: Calculates the byte length of the extracted content using UTF-8 encoding.
3. **Range Evaluation**: Validates whether the content length is within `min` and `max` bounds.
4. **Invert Handling**: Applies `invert` logic when configured to validate outside-range behavior.
5. **Intervention on Violation**: If validation fails, returns HTTP `422` and blocks further processing.

#### Response Phase

1. **Content Extraction**: Extracts content from the response body using `jsonPath` (if configured) or uses the entire payload. For SSE streaming responses, delta content is extracted using `streamingJsonPath` instead.
2. **Byte Length Calculation**: Calculates the byte length of the extracted content using UTF-8 encoding.
3. **Range Evaluation**: Validates whether the content length is within `min` and `max` bounds.
4. **Invert Handling**: Applies `invert` logic when configured to validate outside-range behavior.
5. **Intervention on Violation**: If validation fails, returns HTTP `422` to the client. For streaming responses, an SSE error event is injected into the stream.

#### Streaming (SSE) Processing

This guardrail supports **Server-Sent Events (SSE) streaming responses** commonly used by LLM providers (e.g., OpenAI with `stream: true`).

**How SSE content extraction works:**

- The `streamingJsonPath` parameter (default: `$.choices[0].delta.content`) specifies a JSONPath expression used to extract text content from each SSE `data:` event in the response stream.
- Each SSE event is a JSON object like `data: {"choices":[{"delta":{"content":"token"}}]}`. The policy uses the JSONPath to extract the incremental token text.
- The extracted text is accumulated across all SSE events to build the full response content for byte length validation.

**Gate-then-stream buffering (`NeedsMoreResponseData`):**

- Before any response data reaches the client, the policy evaluates `NeedsMoreResponseData` on the accumulated content.
- When `NeedsMoreResponseData` returns `true`, the gateway kernel **buffers SSE chunks silently** -- the client does not receive anything yet.
- Once `NeedsMoreResponseData` returns `false` (e.g., the minimum byte length threshold is met), the gateway **releases all buffered chunks** and begins streaming subsequent chunks to the client immediately.
- This ensures the response meets the minimum byte length threshold before any data is sent to the client.

**Mode-specific gating behavior:**

- **Normal mode (`invert: false`)**: The guardrail buffers SSE events silently until the accumulated byte length reaches the configured `min`. Once the minimum is met, buffered chunks are flushed to the client. If the byte length exceeds `max` at any point during streaming, an SSE error event replaces the offending chunk. If the stream completes (the `[DONE]` sentinel arrives) with the length below `min`, an SSE error event is appended.
- **Inverted mode (`invert: true`)**: The guardrail buffers until the byte length exceeds `max` (guaranteed outside the excluded range). At stream completion, if the length falls within the excluded `[min, max]` range, an SSE error event is appended.

**Error handling in streaming:**

- Since HTTP headers are already committed once streaming begins, the policy cannot return a traditional HTTP error response.
- Instead, it injects an **SSE error event** into the stream (e.g., `data: {"type":"CONTENT_LENGTH_GUARDRAIL","message":{...}}`) to notify the client of a violation.
- Max violations are caught in real-time as chunks arrive. Min violations are caught when the `[DONE]` sentinel arrives (end of stream).

#### Validation Behavior

- **Length Measurement Rules**: Byte length is calculated on the UTF-8 encoded representation of the content.
- **Normal Mode (`invert: false`)**: Validation passes only when the content length is within the configured `[min, max]` range.
- **Inverted Mode (`invert: true`)**: Validation passes only when the content length is outside the configured `[min, max]` range.

## Notes

- Byte length is calculated on the UTF-8 encoded representation of the content.
- Use `request` and `response` independently to validate one or both directions.
- When using JSONPath, if the path does not exist or the extracted value is not a string, validation will fail.
- Inverted logic is useful for blocking content that falls outside acceptable size ranges.
- Consider network and storage constraints when setting maximum values.
- Minimum values help ensure content quality and completeness.
- The `streamingJsonPath` parameter is only used during SSE streaming responses. For non-streaming responses, the standard `jsonPath` is used.
