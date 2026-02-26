---
title: "Overview"
---
# Sentence Count Guardrail

## Overview

The Sentence Count Guardrail validates the sentence count of request or response body content against configurable minimum and maximum thresholds. This guardrail is useful for ensuring content completeness, controlling response verbosity, and maintaining consistent communication standards.

## Features

- Validates sentence count against minimum and maximum thresholds
- Supports JSONPath extraction to validate specific fields within JSON payloads
- Configurable inverted logic to pass when sentence count is outside the range
- Supports independent request and response phase configuration
- Optional detailed assessment information in error responses

## Configuration

This policy requires only a single-level configuration where all parameters are configured in the API definition YAML.

### User Parameters (API Definition)

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `request` | `SentenceCountGuardRailConfig` object | No | - | Configuration for request-phase sentence count validation. Supports `min`, `max`, `jsonPath`, `invert`, and `showAssessment`. |
| `response` | `SentenceCountGuardRailConfig` object | No | - | Configuration for response-phase sentence count validation. Supports `min`, `max`, `jsonPath`, `invert`, and `showAssessment`. |

#### SentenceCountGuardRailConfig Configuration

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `min` | integer | Yes | - | Minimum allowed sentence count (inclusive). Must be >= 0. |
| `max` | integer | Yes | - | Maximum allowed sentence count (inclusive). Must be >= 1. |
| `jsonPath` | string | No | `""` | JSONPath expression to extract a specific value from JSON payload. If empty, validates the entire payload as a string. |
| `invert` | boolean | No | `false` | If `true`, validation passes when sentence count is NOT within the min-max range. If `false`, validation passes when sentence count is within the range. |
| `showAssessment` | boolean | No | `false` | If `true`, includes detailed assessment information in error responses. |

#### JSONPath Support

The guardrail supports JSONPath expressions to extract and validate specific fields within JSON payloads. Common examples:

- `$.messages` - Extracts the `messages` field from the root object
- `$.data.content` - Extracts nested content from `data.content`
- `$.items[0].text` - Extracts text from the first item in an array
- `$.messages[0].content` - Extracts content from the first message in a messages array

If `jsonPath` is empty or not specified, the entire payload is treated as a string and validated.

**Note:**

Inside the `gateway/build.yaml`, ensure the policy module is added under `policies:`:

```yaml
- name: sentence-count-guardrail
  gomodule: github.com/wso2/gateway-controllers/policies/sentence-count-guardrail@v0
```

## Reference Scenarios

### Example 1: Basic Sentence Count Validation

Deploy an LLM provider that ensures requests contain between 1 and 10 sentences:

```yaml
apiVersion: gateway.api-platform.wso2.com/v1alpha1
kind: LlmProvider
metadata:
  name: sentence-count-provider
spec:
  displayName: Sentence Count Provider
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
    - name: sentence-count-guardrail
      version: v0
      paths:
        - path: /chat/completions
          methods: [POST]
          params:
            request:
              min: 2
              max: 10
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
        "content": "What is machine learning?. How does it work?. Can you explain it simply?"
      }
    ]
  }'

# Invalid request - too few sentences (should fail with HTTP 422)
curl -X POST http://openai:8080/chat/completions \
  -H "Content-Type: application/json" \
  -H "Host: openai" \
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
  "type": "SENTENCE_COUNT_GUARDRAIL",
  "message": {
    "action": "GUARDRAIL_INTERVENED",
    "interveningGuardrail": "sentence-count-guardrail",
    "actionReason": "Violation of applied sentence count constraints detected.",
    "direction": "REQUEST"
  }
}
```

If `showAssessment` is enabled, additional details are included:

```json
{
  "type": "SENTENCE_COUNT_GUARDRAIL",
  "message": {
    "action": "GUARDRAIL_INTERVENED",
    "interveningGuardrail": "sentence-count-guardrail",
    "actionReason": "Violation of applied sentence count constraints detected.",
    "assessments": "Violation of sentence count detected. Expected between 1 and 3 sentences.",
    "direction": "REQUEST"
  }
}
```

## How it Works

#### Request Phase

1. **Content Extraction**: Extracts content from the request body using `jsonPath` (if configured) or uses the entire payload.
2. **Sentence Counting**: Counts detected sentences in the extracted content after trimming whitespace.
3. **Range Evaluation**: Validates whether the sentence count is within `min` and `max` bounds.
4. **Invert Handling**: Applies `invert` logic when configured to validate outside-range behavior.
5. **Intervention on Violation**: If validation fails, returns HTTP `422` and blocks further processing.

#### Response Phase

1. **Content Extraction**: Extracts content from the response body using `jsonPath` (if configured) or uses the entire payload.
2. **Sentence Counting**: Counts detected sentences in the extracted content after trimming whitespace.
3. **Range Evaluation**: Validates whether the sentence count is within `min` and `max` bounds.
4. **Invert Handling**: Applies `invert` logic when configured to validate outside-range behavior.
5. **Intervention on Violation**: If validation fails, returns HTTP `422` to the client.

#### Validation Behavior

- **Sentence Detection Rules**: Sentences are detected using standard sentence-ending punctuation marks (`.`, `!`, `?`).
- **Normal Mode (`invert: false`)**: Validation passes only when the sentence count is within the configured `[min, max]` range.
- **Inverted Mode (`invert: true`)**: Validation passes only when the sentence count is outside the configured `[min, max]` range.

## Notes

- Sentence counting is performed on the extracted or full content after trimming whitespace.
- Sentences are identified by standard punctuation marks (., !, ?).
- Use `request` and `response` independently to validate one or both directions.
- When using JSONPath, if the path does not exist or the extracted value is not a string, validation will fail.
- Inverted logic is useful for blocking content that falls outside acceptable sentence count ranges.
- Consider the nature of your content when setting thresholds, as some content types may naturally have different sentence counts.
