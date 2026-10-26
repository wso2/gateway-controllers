---
title: "Overview"
---
# URL Guardrail

## Overview

The URL Guardrail validates URLs found in request or response body content by checking their reachability and validity. This guardrail helps prevent broken links, malicious URLs, and ensures that referenced resources are accessible.

This policy supports SSE streaming responses. When the upstream returns a streaming response (`stream: true`), the guardrail extracts URLs from accumulated SSE delta content and validates them, using a configurable `streamingJsonPath` to extract content from each SSE event.

## Features

- Validates URLs via DNS resolution or HTTP HEAD requests
- Supports JSONPath extraction to validate specific fields within JSON payloads
- Configurable timeout for URL validation
- Supports independent request and response phase configuration
- Optional detailed assessment information including invalid URLs in error responses
- SSE streaming support with intelligent URL boundary detection to avoid validating incomplete URLs
- Configurable `streamingJsonPath` for extracting content from SSE delta chunks

## Configuration

This policy requires only a single-level configuration where all parameters are configured in the API definition YAML.

### User Parameters (API Definition)

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `request` | object | No* | - | Configuration for request-phase URL validation. |
| `response` | object | No* | - | Configuration for response-phase URL validation. |

*At least one of `request` or `response` must be provided.

#### Request Configuration

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `enabled` | boolean | No | `false` | Enables validation for the request flow. |
| `jsonPath` | string | No | `"$.messages[-1].content"` | JSONPath expression to extract a specific value from JSON payload. Set to `""` to validate the entire payload as a string. |
| `onlyDNS` | boolean | No | `false` | If `true`, validates URLs only via DNS resolution (faster, less reliable). If `false`, validates URLs via HTTP HEAD request (slower, more reliable). |
| `timeout` | integer | No | `3000` | Timeout in milliseconds for DNS lookup or HTTP HEAD request. Minimum: 0. |
| `showAssessment` | boolean | No | `false` | If `true`, includes detailed assessment information including invalid URLs in error responses. |

#### Response Configuration

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `enabled` | boolean | No | `true` | Enables validation for the response flow. |
| `jsonPath` | string | No | `"$.choices[0].message.content"` | JSONPath expression to extract a specific value from JSON payload. Set to `""` to validate the entire payload as a string. |
| `streamingJsonPath` | string | No | `"$.choices[0].delta.content"` | JSONPath expression to extract content from SSE streaming delta chunks. Used when the upstream returns a streaming (`stream: true`) response. |
| `onlyDNS` | boolean | No | `false` | If `true`, validates URLs only via DNS resolution (faster, less reliable). If `false`, validates URLs via HTTP HEAD request (slower, more reliable). |
| `timeout` | integer | No | `3000` | Timeout in milliseconds for DNS lookup or HTTP HEAD request. Minimum: 0. |
| `showAssessment` | boolean | No | `false` | If `true`, includes detailed assessment information including invalid URLs in error responses. |

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
- name: url-guardrail
  gomodule: github.com/wso2/gateway-controllers/policies/url-guardrail@v1
```

## Reference Scenarios

### Example 1: Basic URL Validation

Deploy an LLM provider that validates URLs in request content using HTTP HEAD requests:

```yaml
apiVersion: gateway.api-platform.wso2.com/v1
kind: LlmProvider
metadata:
  name: url-guardrail-provider
spec:
  displayName: URL Guardrail Provider
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
    - name: url-guardrail
      version: v1
      paths:
        - path: /chat/completions
          methods: [POST]
          params:
            request:
              enabled: true
              jsonPath: "$.messages[-1].content"
              onlyDNS: false
              timeout: 5000

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
        "content": "Visit https://www.example.com for more information"
      }
    ]
  }'

# Invalid request - invalid URL (should fail with HTTP 422)
curl -X POST http://localhost:8080/openai/chat/completions \
  -H "Content-Type: application/json" \
  -d '{
    "model": "gpt-4",
    "messages": [
      {
        "role": "user",
        "content": "Visit https://invalid-url-that-does-not-exist-12345.com"
      }
    ]
  }'
```

**In Case of Error Response:**

When validation fails, the guardrail returns an HTTP 422 status code with the following structure:

```json
{
  "type": "URL_GUARDRAIL",
  "message": {
    "action": "GUARDRAIL_INTERVENED",
    "interveningGuardrail": "url-guardrail",
    "actionReason": "Violation of url validity detected.",
    "direction": "REQUEST"
  }
}
```

If `showAssessment` is enabled, additional details including invalid URLs are included:

```json
{
  "type": "URL_GUARDRAIL",
  "message": {
    "action": "GUARDRAIL_INTERVENED",
    "interveningGuardrail": "url-guardrail",
    "actionReason": "Violation of url validity detected.",
    "assessments": {
      "invalidUrls": [
        "http://example.com/suspicious-link",
        "https://foo.bar.baz"
      ],
      "message": "One or more URLs in the payload failed validation."
    },
    "direction": "REQUEST"
  }
}
```

### Example 2: Response Streaming URL Validation

Validate URLs in streaming LLM responses using a custom streaming JSONPath:

```yaml
  operationPolicies:
    - name: url-guardrail
      version: v1
      paths:
        - path: /chat/completions
          methods: [POST]
          params:
            response:
              enabled: true
              jsonPath: "$.choices[0].message.content"
              streamingJsonPath: "$.choices[0].delta.content"
              onlyDNS: true
              timeout: 3000
```

When the upstream returns an SSE streaming response, the guardrail accumulates delta content from each SSE event and validates URLs once they are fully received. The guardrail detects incomplete URLs at the end of accumulated content and continues buffering until the URL is complete before validating. If an invalid URL is found, an SSE error event replaces the offending chunk in the stream.

## How it Works

#### Request Phase

1. **Content Extraction**: Extracts content from the request body using `jsonPath` (if configured) or uses the entire payload.
2. **URL Detection**: Finds all URLs in the extracted content using pattern matching.
3. **Validation Execution**: Validates each detected URL using either DNS-only lookup or DNS + HTTP HEAD request based on `onlyDNS`.
4. **Timeout Enforcement**: Applies the configured `timeout` to each validation operation.
5. **Intervention on Violation**: If any URL is invalid, returns HTTP `422` and blocks further processing.

#### Response Phase

1. **Content Extraction**: Extracts content from the response body using `jsonPath` (if configured) or uses the entire payload. For SSE streaming responses, delta content is extracted using `streamingJsonPath` instead.
2. **URL Detection**: Finds all URLs in the extracted content using pattern matching.
3. **Validation Execution**: Validates each detected URL using the configured mode (`onlyDNS`).
4. **Timeout Enforcement**: Applies the configured `timeout` to each validation operation.
5. **Intervention on Violation**: If any URL is invalid, returns HTTP `422` to the client. For streaming responses, an SSE error event replaces the offending chunk.

#### Streaming (SSE) Behavior

When the upstream returns an SSE streaming response, each SSE event arrives as a `data:` line containing a JSON payload, for example:

```
data: {"choices":[{"delta":{"content":"token"}}]}
```

The URL guardrail uses a **smart boundary detection pattern** for streaming. `NeedsMoreResponseData` conditionally buffers chunks only when an incomplete URL is detected at the end of the accumulated content:

1. **Delta Content Extraction**: Content is extracted from each SSE event using `streamingJsonPath` (default: `$.choices[0].delta.content`).
2. **Incomplete URL Detection**: `NeedsMoreResponseData` checks whether the accumulated delta content ends with an incomplete URL -- anything from a bare protocol token (`http`, `https`, `https:`, `https:/`) through a URL body that has started past `://` but has no terminating whitespace (`https://example.com/path`). This prevents false positives from URLs split across SSE chunk boundaries.
3. **Conditional Buffering**: If an incomplete URL is detected, `NeedsMoreResponseData` returns `true` and the kernel continues accumulating chunks. Once all URLs are complete (terminated by whitespace or end of text), or the stream ends (`data: [DONE]`), the accumulated chunks are flushed for validation.
4. **URL Validation**: Once chunks are released, all complete URLs in the delta content are validated using the configured mode (`onlyDNS` or HTTP HEAD request).
5. **Error Handling**: Since HTTP response headers are already committed when streaming begins, violations cannot be reported via HTTP status codes. Instead, an SSE error event replaces the offending chunk in the stream.
6. **Plain JSON Chunks**: For non-SSE chunked responses (e.g., `Transfer-Encoding: chunked` without SSE), chunks are accumulated until end of stream and validated as a complete body via JSONPath.

#### URL Validation Modes

- **DNS-Only Validation (`onlyDNS: true`)**: Faster method that checks whether the domain resolves via DNS, without confirming HTTP/HTTPS accessibility.
- **HTTP HEAD Request Validation (`onlyDNS: false`)**: More thorough method that performs DNS lookup and HTTP HEAD checks to verify URL reachability.

## Notes

- URL validation extracts all URLs from the content using pattern matching.
- DNS-only validation is faster but less reliable than HTTP HEAD validation.
- Use `request` and `response` independently to validate one or both directions.
- Timeout values should be set based on network conditions and acceptable latency.
- HTTP HEAD requests may fail for URLs that require specific headers or authentication.
- Some URLs may be temporarily unavailable; consider retry logic for production use.
- When using JSONPath, if the path does not exist or the extracted value is not a string, validation will fail.
- The guardrail validates all URLs found in the content; if any URL is invalid, validation fails.
- The `streamingJsonPath` parameter is only used during SSE streaming responses. For non-streaming responses, the standard `jsonPath` is used.
