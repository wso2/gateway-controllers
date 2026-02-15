---
title: "Overview"
---
# PII Masking Regex Guardrail

## Overview

The PII Masking Regex Guardrail masks or redacts Personally Identifiable Information (PII) from request and response bodies using configurable regular expression patterns. This guardrail helps protect sensitive user data by replacing PII with placeholders or redaction markers before content is processed or returned.

## Features

- Configurable PII entity detection using regular expressions
- Two modes: masking (reversible) and redaction (permanent)
- Automatic PII restoration in responses when using masking mode
- Supports JSONPath extraction to process specific fields within JSON payloads

## Configuration

This policy requires only a single-level configuration where all parameters are configured in the API definition YAML.

### User Parameters (API Definition)

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `piiEntities` | `PIIEntityConfig` array | Yes | - | Array of PII entity configurations. Each entry defines `piiEntity` and `piiRegex`. |
| `jsonPath` | string | No | `""` | JSONPath expression to extract a specific value from JSON payload. If empty, processes the entire payload as a string. |
| `redactPII` | boolean | No | `false` | If `true`, redacts PII by replacing with "*****" (permanent, cannot be restored). If `false`, masks PII with placeholders that can be restored in responses. |

### PIIEntityConfig Configuration

Each PII entity in the `piiEntities` array must contain:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `piiEntity` | string | Yes | Name/type of the PII entity (e.g., "EMAIL", "PHONE", "SSN", "CREDIT_CARD"). Must contain only uppercase letters and underscores (matches `^[A-Z_]+$`). |
| `piiRegex` | string | Yes | Regular expression pattern to match the PII entity. Must be a valid Go regexp pattern. |

#### JSONPath Support

The guardrail supports JSONPath expressions to extract and process specific fields within JSON payloads. Common examples:

- `$.message` - Extracts the `message` field from the root object
- `$.data.content` - Extracts nested content from `data.content`
- `$.items[0].text` - Extracts text from the first item in an array
- `$.messages[0].content` - Extracts content from the first message in a messages array

If `jsonPath` is empty or not specified, the entire payload is processed as a string.

**Note:**

Inside the `gateway/build.yaml`, ensure the policy module is added under `policies:`:

```yaml
- name: pii-masking-regex
  gomodule: github.com/wso2/gateway-controllers/policies/pii-masking-regex@v0
```

## Reference Scenarios

### Example 1: Basic PII Masking

Deploy an LLM provider that masks email addresses and phone numbers in requests and restores them in responses:

```yaml
apiVersion: gateway.api-platform.wso2.com/v1alpha1
kind: LlmProvider
metadata:
  name: pii-masking-provider
spec:
  displayName: PII Masking Provider
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
    - name: pii-masking-regex
      version: v0
      paths:
        - path: /chat/completions
          methods: [POST]
          params:
            piiEntities:
              - piiEntity: "EMAIL"
                piiRegex: "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"
              - piiEntity: "PHONE"
                piiRegex: "\+?[1-9]\d{1,14}"
            jsonPath: "$.messages[0].content"
            redactPII: true
```

**Test the guardrail:**

**Note**: Ensure that "openai" is mapped to the appropriate IP address (e.g., 127.0.0.1) in your `/etc/hosts` file. or remove the vhost from the llm provider configuration and use localhost to invoke.

```bash
# Request with PII (should be masked)
curl -X POST http://openai:8080/chat/completions \
  -H "Content-Type: application/json" \
  -H "Host: openai" \
  -d '{
    "model": "gpt-4",
    "messages": [
      {
        "role": "user",
        "content": "Contact me at john.doe@example.com or call +1234567890"
      }
    ]
  }'
```

 **Sample Payload after intervention from Regex PII Masking with redactPII=true**

```json
{
  "messages": [
    {
      "role": "user",
      "content": "Prepare an email with my contact information, email: *****, and website: https://example.com."
    }
  ]
}
```

## How It Works

#### Request Phase

1. **Content Extraction**: Extracts content using `jsonPath` (if configured) or uses the entire payload as a string.
2. **PII Detection**: Applies each configured `piiRegex` pattern to detect matching PII entities.
3. **Intervention**: Replaces matches with placeholders (`[ENTITY_TYPE_XXXX]`) in masking mode or with `*****` in redaction mode.
4. **Metadata Storage**: Stores placeholder-to-original mappings in request metadata when masking mode is used.
5. **Forwarding**: Sends the transformed payload to the upstream service.

#### Response Phase

1. **Mapping Check**: Checks whether masking metadata is available from request processing.
2. **Restoration**: If `redactPII: false`, replaces placeholders with original values in the response.
3. **Redaction Preservation**: If `redactPII: true`, no restoration is performed.
4. **Response Return**: Returns restored or redacted content to the client.

#### PII Modes

- **Masking Mode (`redactPII: false`)**: Uses placeholders such as `[EMAIL_0000]` and original PII values are stored temporarily in request metadata for restoration. Recommended when you need to preserve data for downstream processing or response generation
- **Redaction Mode (`redactPII: true`)**: Permanently replaces detected PII with `*****` and does not restore original values. Recommended for maximum privacy protection when original values are not needed

#### Processing Behavior

- Supports multiple entity patterns in one policy and processes each detected match by entity type.
- Placeholder format is `[ENTITY_TYPE_XXXX]`, where `XXXX` is a 4-digit hexadecimal sequence.
- Full payload processing is used when `jsonPath` is not configured.

## Notes

- Common use cases include privacy protection, compliance (GDPR/CCPA/HIPAA), data minimization, secure AI processing, and audit-friendly masking workflows.
- Regular expressions use Go's regexp package (RE2 syntax).
- PII detection is case-sensitive by default. Use `(?i)` flag for case-insensitive matching.
- The `piiEntity` name must contain only uppercase letters and underscores (e.g., "EMAIL", "PHONE_NUMBER", "SSN").
- When using masking mode, the placeholder-to-original mapping is stored in request metadata and automatically used for response restoration.
- Multiple PII entities can match the same content; each match is processed according to its entity type.
- Placeholder format is `[ENTITY_TYPE_XXXX]` where XXXX is a 4-digit hexadecimal number (e.g., `[EMAIL_0000]`, `[EMAIL_0001]`, `[PHONE_000a]`).
- When using JSONPath, if the path does not exist or the extracted value is not a string, an error response (HTTP 500) is returned.
- Redaction mode is irreversible; use masking mode if you need to restore PII in responses.
- Complex regex patterns may impact performance; test thoroughly with expected content volumes.
