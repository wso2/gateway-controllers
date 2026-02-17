---
title: "Overview"
---
# Content Length Guardrail

## Overview

The Content Length Guardrail validates the byte length of request or response body content against configurable minimum and maximum thresholds. This guardrail is essential for controlling payload sizes, preventing resource exhaustion, and ensuring efficient data transfer.

## Features

- Validates byte length against minimum and maximum thresholds
- Supports JSONPath extraction to validate specific fields within JSON payloads
- Configurable inverted logic to pass when content length is outside the range
- Supports independent request and response phase configuration
- Optional detailed assessment information in error responses

## Configuration

This policy uses a single-level configuration where all parameters are configured in the API definition YAML.

### User Parameters (API Definition)

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `request` | `ContentLengthGuardRailConfig` object | No | - | Configuration for request-phase content length validation. Supports `min`, `max`, `jsonPath`, `invert`, and `showAssessment`. |
| `response` | `ContentLengthGuardRailConfig` object | No | - | Configuration for response-phase content length validation. Supports `min`, `max`, `jsonPath`, `invert`, and `showAssessment`. |

#### ContentLengthGuardRailConfig Configuration

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `min` | integer | Yes | - | Minimum allowed byte length (inclusive). Must be >= 0. |
| `max` | integer | Yes | - | Maximum allowed byte length (inclusive). Must be >= 1. |
| `jsonPath` | string | No | `""` | JSONPath expression to extract a specific value from JSON payload. If empty, validates the entire payload as a string. |
| `invert` | boolean | No | `false` | If `true`, validation passes when content length is NOT within the min-max range. If `false`, validation passes when content length is within the range. |
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
- name: content-length-guardrail
  gomodule: github.com/wso2/gateway-controllers/policies/content-length-guardrail@v0
```

## Reference Scenarios

### Example 1: Basic Content Length Validation

Deploy an LLM provider that limits request payloads to between 100 bytes and 1MB:

```yaml
apiVersion: gateway.api-platform.wso2.com/v1alpha1
kind: LlmProvider
metadata:
  name: content-length-provider
spec:
  displayName: Content Length Provider
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
    - name: content-length-guardrail
      version: v0
      paths:
        - path: /chat/completions
          methods: [POST]
          params:
            request:
              min: 100
              max: 1048576
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
        "content": "Please explain artificial intelligence in simple terms for beginners"
      }
    ]
  }'

# Invalid request - too small (should fail with HTTP 422)
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

## How it Works

#### Request Phase

1. **Content Extraction**: Extracts content from the request body using `jsonPath` (if configured) or uses the entire payload.
2. **Byte Length Calculation**: Calculates the byte length of the extracted content using UTF-8 encoding.
3. **Range Evaluation**: Validates whether the content length is within `min` and `max` bounds.
4. **Invert Handling**: Applies `invert` logic when configured to validate outside-range behavior.
5. **Intervention on Violation**: If validation fails, returns HTTP `422` and blocks further processing.

#### Response Phase

1. **Content Extraction**: Extracts content from the response body using `jsonPath` (if configured) or uses the entire payload.
2. **Byte Length Calculation**: Calculates the byte length of the extracted content using UTF-8 encoding.
3. **Range Evaluation**: Validates whether the content length is within `min` and `max` bounds.
4. **Invert Handling**: Applies `invert` logic when configured to validate outside-range behavior.
5. **Intervention on Violation**: If validation fails, returns HTTP `422` to the client.

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
