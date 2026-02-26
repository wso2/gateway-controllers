---
title: "Overview"
---
# URL Guardrail

## Overview

The URL Guardrail validates URLs found in request or response body content by checking their reachability and validity. This guardrail helps prevent broken links, malicious URLs, and ensures that referenced resources are accessible.

## Features

- Validates URLs via DNS resolution or HTTP HEAD requests
- Supports JSONPath extraction to validate specific fields within JSON payloads
- Configurable timeout for URL validation
- Supports independent request and response phase configuration
- Optional detailed assessment information including invalid URLs in error responses

## Configuration

This policy requires only a single-level configuration where all parameters are configured in the API definition YAML.

### User Parameters (API Definition)

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `request` | ```URLGuardrailConfig``` object | No | - | Configuration for request-phase URL validation. Supports `jsonPath`, `onlyDNS`, `timeout`, and `showAssessment`. |
| `response` | ```URLGuardrailConfig``` object | No | - | Configuration for response-phase URL validation. Supports `jsonPath`, `onlyDNS`, `timeout`, and `showAssessment`. |

#### URLGuardrailConfig Configuration

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `jsonPath` | string | No | `""` | JSONPath expression to extract a specific value from JSON payload. If empty, validates the entire payload as a string. |
| `onlyDNS` | boolean | No | `false` | If `true`, validates URLs only via DNS resolution (faster, less reliable). If `false`, validates URLs via HTTP HEAD request (slower, more reliable). |
| `timeout` | integer | No | `3000` | Timeout in milliseconds for DNS lookup or HTTP HEAD request. Default is 3000ms (3 seconds). |
| `showAssessment` | boolean | No | `false` | If `true`, includes detailed assessment information including invalid URLs in error responses. |

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
- name: url-guardrail
  gomodule: github.com/wso2/gateway-controllers/policies/url-guardrail@v0
```

## Reference Scenarios

### Example 1: Basic URL Validation

Deploy an LLM provider that validates URLs in request content using HTTP HEAD requests:

```yaml
apiVersion: gateway.api-platform.wso2.com/v1alpha1
kind: LlmProvider
metadata:
  name: url-guardrail-provider
spec:
  displayName: URL Guardrail Provider
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
    - name: url-guardrail
      version: v0
      paths:
        - path: /chat/completions
          methods: [POST]
          params:
            request:
              jsonPath: "$.messages[0].content"
              onlyDNS: false
              timeout: 5000

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
        "content": "Visit https://www.example.com for more information"
      }
    ]
  }'

# Invalid request - invalid URL (should fail with HTTP 422)
curl -X POST http://openai:8080/chat/completions \
  -H "Content-Type: application/json" \
  -H "Host: openai" \
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

## How it Works

#### Request Phase

1. **Content Extraction**: Extracts content from the request body using `jsonPath` (if configured) or uses the entire payload.
2. **URL Detection**: Finds all URLs in the extracted content using pattern matching.
3. **Validation Execution**: Validates each detected URL using either DNS-only lookup or DNS + HTTP HEAD request based on `onlyDNS`.
4. **Timeout Enforcement**: Applies the configured `timeout` to each validation operation.
5. **Intervention on Violation**: If any URL is invalid, returns HTTP `422` and blocks further processing.

#### Response Phase

1. **Content Extraction**: Extracts content from the response body using `jsonPath` (if configured) or uses the entire payload.
2. **URL Detection**: Finds all URLs in the extracted content using pattern matching.
3. **Validation Execution**: Validates each detected URL using the configured mode (`onlyDNS`).
4. **Timeout Enforcement**: Applies the configured `timeout` to each validation operation.
5. **Intervention on Violation**: If any URL is invalid, returns HTTP `422` to the client.

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
