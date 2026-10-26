---
title: "Overview"
---
# Word Count Guardrail

## Overview

The Word Count Guardrail validates the word count of request or response body content against configurable minimum and maximum thresholds. This guardrail is useful for enforcing content length policies, ensuring responses meet quality standards, or preventing excessively long inputs that could impact system performance.

This policy supports SSE streaming responses. When the upstream returns a streaming response (`stream: true`), the guardrail accumulates SSE delta content and validates the word count across the full streamed output, using a configurable `streamingJsonPath` to extract content from each SSE event.

## Features

- Validates word count against minimum and maximum thresholds
- Supports JSONPath extraction to validate specific fields within JSON payloads
- Configurable inverted logic to pass when word count is outside the range
- Supports independent request and response phase configuration
- Optional detailed assessment information in error responses
- **SSE Streaming Support**: Processes streaming responses in real time using a gate-then-stream pattern, buffering until minimum thresholds are met before releasing to the client
- Configurable `streamingJsonPath` for extracting content from SSE delta chunks

## Configuration

This policy requires only a single-level configuration where all parameters are configured in the API definition YAML.

### User Parameters (API Definition)

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `request` | object | No* | - | Configuration for request-phase word count validation. |
| `response` | object | No* | - | Configuration for response-phase word count validation. |

*At least one of `request` or `response` must be provided.

#### Request Configuration

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `enabled` | boolean | No | `true` | Enables validation for the request flow. |
| `min` | integer | Conditional | - | Minimum allowed word count (inclusive). Must be >= 0. Required when `enabled` is `true`. |
| `max` | integer | Conditional | - | Maximum allowed word count (inclusive). Must be >= 1. Required when `enabled` is `true`. |
| `jsonPath` | string | No | `"$.messages[-1].content"` | JSONPath expression to extract a specific value from JSON payload. If empty, validates the entire payload as a string. |
| `invert` | boolean | No | `false` | If `true`, validation passes when word count is NOT within the min-max range. If `false`, validation passes when word count is within the range. |
| `showAssessment` | boolean | No | `false` | If `true`, includes detailed assessment information in error responses. |

#### Response Configuration

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `enabled` | boolean | No | `false` | Enables validation for the response flow. |
| `min` | integer | Conditional | - | Minimum allowed word count (inclusive). Must be >= 0. Required when `enabled` is `true`. |
| `max` | integer | Conditional | - | Maximum allowed word count (inclusive). Must be >= 1. Required when `enabled` is `true`. |
| `jsonPath` | string | No | `"$.choices[0].message.content"` | JSONPath expression to extract a specific value from JSON payload. If empty, validates the entire payload as a string. |
| `streamingJsonPath` | string | No | `"$.choices[0].delta.content"` | JSONPath expression to extract content from SSE streaming delta chunks. Used when the upstream returns a streaming (`stream: true`) response. |
| `invert` | boolean | No | `false` | If `true`, validation passes when word count is NOT within the min-max range. If `false`, validation passes when word count is within the range. |
| `showAssessment` | boolean | No | `false` | If `true`, includes detailed assessment information in error responses. |

#### JSONPath Support

The guardrail supports JSONPath expressions to extract and validate specific fields within JSON payloads. Common examples:

- `$.messages[-1].content` - Extracts content from the last message in a messages array (default for request)
- `$.choices[0].message.content` - Extracts content from the first choice message (default for response)
- `$.choices[0].delta.content` - Extracts content from SSE delta chunks (default for streaming)
- `$.messages` - Extracts the `messages` field from the root object
- `$.data.content` - Extracts nested content from `data.content`
- `$.items[0].text` - Extracts text from the first item in an array

If `jsonPath` is empty or not specified, the entire payload is treated as a string and validated.

**Note:**

Inside the `gateway/build.yaml`, ensure the policy module is added under `policies:`:

```yaml
- name: word-count-guardrail
  gomodule: github.com/wso2/gateway-controllers/policies/word-count-guardrail@v1
```

## Reference Scenarios

### Example 1: Basic Word Count Validation

Deploy an LLM provider that validates request messages contain between 10 and 500 words:

```yaml
apiVersion: gateway.api-platform.wso2.com/v1
kind: LlmProvider
metadata:
  name: word-count-provider
spec:
  displayName: Word Count Provider
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
    - name: word-count-guardrail
      version: v1
      paths:
        - path: /chat/completions
          methods: [POST]
          params:
            request:
              min: 5
              max: 500
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

# Invalid request - too few words (should fail with HTTP 422)
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
  "type": "WORD_COUNT_GUARDRAIL",
  "message": {
    "action": "GUARDRAIL_INTERVENED",
    "interveningGuardrail": "word-count-guardrail",
    "actionReason": "Violation of applied word count constraints detected.",
    "direction": "REQUEST"
  }
}
```

If `showAssessment` is enabled, additional details are included:

```json
{
  "type": "WORD_COUNT_GUARDRAIL",
  "message": {
    "action": "GUARDRAIL_INTERVENED",
    "interveningGuardrail": "word-count-guardrail",
    "actionReason": "Violation of applied word count constraints detected.",
    "assessments": "Violation of word count detected. Expected between 2 and 10 words.",
    "direction": "REQUEST"
  }
}
```

### Example 2: Response Streaming Validation

Validate word count on streaming LLM responses using a custom streaming JSONPath:

```yaml
  operationPolicies:
    - name: word-count-guardrail
      version: v1
      paths:
        - path: /chat/completions
          methods: [POST]
          params:
            response:
              enabled: true
              min: 10
              max: 1000
              jsonPath: "$.choices[0].message.content"
              streamingJsonPath: "$.choices[0].delta.content"
```

When the upstream returns an SSE streaming response, the guardrail accumulates delta content from each SSE event and validates the total word count. For non-streaming responses, the standard `jsonPath` is used instead. If the word count exceeds the maximum during streaming, an SSE error event is injected into the stream. If the word count is below the minimum when the stream completes, an SSE error event is appended.

## How it Works

#### Request Phase

1. **Content Extraction**: Extracts content from the request body using `jsonPath` (if configured) or uses the entire payload.
2. **Word Counting**: Counts words in the extracted content after trimming whitespace.
3. **Range Evaluation**: Validates whether the word count is within `min` and `max` bounds.
4. **Invert Handling**: Applies `invert` logic when configured to validate outside-range behavior.
5. **Intervention on Violation**: If validation fails, returns HTTP `422` and blocks further processing.

#### Response Phase

1. **Content Extraction**: Extracts content from the response body using `jsonPath` (if configured) or uses the entire payload. For SSE streaming responses, delta content is extracted using `streamingJsonPath` instead.
2. **Word Counting**: Counts words in the extracted content after trimming whitespace.
3. **Range Evaluation**: Validates whether the word count is within `min` and `max` bounds.
4. **Invert Handling**: Applies `invert` logic when configured to validate outside-range behavior.
5. **Intervention on Violation**: If validation fails, returns HTTP `422` to the client. For streaming responses, an SSE error event is injected into the stream.

#### Streaming (SSE) Processing

This guardrail supports **Server-Sent Events (SSE) streaming responses** commonly used by LLM providers (e.g., OpenAI with `stream: true`).

**How SSE content extraction works:**

- The `streamingJsonPath` parameter (default: `$.choices[0].delta.content`) specifies a JSONPath expression used to extract text content from each SSE `data:` event in the response stream.
- Each SSE event is a JSON object like `data: {"choices":[{"delta":{"content":"token"}}]}`. The policy uses the JSONPath to extract the incremental token text.
- The extracted text is accumulated across all SSE events to build the full response content for word count validation.

**Gate-then-stream buffering (`NeedsMoreResponseData`):**

- Before any response data reaches the client, the policy evaluates `NeedsMoreResponseData` on the accumulated content.
- When `NeedsMoreResponseData` returns `true`, the gateway kernel **buffers SSE chunks silently** -- the client does not receive anything yet.
- Once `NeedsMoreResponseData` returns `false` (e.g., the minimum word count threshold is met), the gateway **releases all buffered chunks** and begins streaming subsequent chunks to the client immediately.
- This ensures the response meets the minimum word count threshold before any data is sent to the client.

**Mode-specific gating behavior:**

- **Normal mode (`invert: false`)**: The guardrail buffers SSE events silently until the accumulated word count reaches the configured `min`. Once the minimum is met, buffered chunks are flushed to the client. If the word count exceeds `max` at any point during streaming, an SSE error event replaces the offending chunk. If the stream completes (the `[DONE]` sentinel arrives) with the count below `min`, an SSE error event is appended.
- **Inverted mode (`invert: true`)**: The guardrail buffers until the word count exceeds `max` (guaranteed outside the excluded range). At stream completion, if the count falls within the excluded `[min, max]` range, an SSE error event is appended.

**Error handling in streaming:**

- Since HTTP headers are already committed once streaming begins, the policy cannot return a traditional HTTP error response.
- Instead, it injects an **SSE error event** into the stream (e.g., `data: {"type":"WORD_COUNT_GUARDRAIL","message":{...}}`) to notify the client of a violation.
- Max violations are caught in real-time as chunks arrive. Min violations are caught when the `[DONE]` sentinel arrives (end of stream).

#### Validation Behavior

- **Normal Mode (`invert: false`)**: Validation passes only when the word count is within the configured `[min, max]` range.
- **Inverted Mode (`invert: true`)**: Validation passes only when the word count is outside the configured `[min, max]` range.

## Notes

- Word counting is performed on the extracted or full content after trimming whitespace.
- The validation is case-sensitive and counts all words separated by whitespace.
- Use `request` and `response` independently to validate one or both directions.
- When using JSONPath, if the path does not exist or the extracted value is not a string, validation will fail.
- Inverted logic is useful for blocking content that falls outside acceptable ranges rather than within them.
- The `streamingJsonPath` parameter is only used during SSE streaming responses. For non-streaming responses, the standard `jsonPath` is used.
