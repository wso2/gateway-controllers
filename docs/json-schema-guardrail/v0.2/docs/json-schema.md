---
title: "Overview"
---
# JSON Schema Guardrail

## Overview

The JSON Schema Guardrail validates request or response body content against a JSON Schema definition. This guardrail enables structured data validation, ensuring that JSON payloads conform to expected formats, data types, and constraints.

## Features

- Validates content against JSON Schema Draft 7
- Supports JSONPath extraction to validate specific fields within JSON payloads
- Configurable inverted logic to pass when schema validation fails
- Supports independent request and response phase configuration
- Detailed validation error information in error responses

## Configuration

This policy uses a single-level configuration model where all parameters are configured per-API in the API definition YAML. This policy does not require system-level configuration.

### User Parameters (API Definition)

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `request` | `JSONSchemaGuardRailConfig` object | No | - | Configuration for request-phase schema validation. Supports `schema`, `jsonPath`, `invert`, and `showAssessment`. |
| `response` | `JSONSchemaGuardRailConfig` object | No | - | Configuration for response-phase schema validation. Supports `schema`, `jsonPath`, `invert`, and `showAssessment`. |

#### JSONSchemaGuardRailConfig Configuration

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `schema` | string | Yes | - | JSON Schema as a string (must be valid JSON). Supports JSON Schema Draft 7 features. |
| `jsonPath` | string | No | `""` | JSONPath expression to extract a specific value from JSON payload for validation. If empty, validates the entire payload against the schema. |
| `invert` | boolean | No | `false` | If `true`, validation passes when schema validation fails. If `false`, validation passes when schema validation succeeds. |
| `showAssessment` | boolean | No | `false` | If `true`, includes detailed validation error information in error responses. |

#### JSONPath Support

The guardrail supports JSONPath expressions to extract and validate specific fields within JSON payloads. Common examples:

- `$.data` - Extracts the `data` object for validation
- `$.userInfo` - Extracts user information object
- `$.items[0]` - Extracts the first item in an array
- `$.messages[0]` - Extracts the first message object

If `jsonPath` is empty or not specified, the entire payload is validated against the schema.

**Note:**

Inside the `gateway/build.yaml`, ensure the policy module is added under `policies:`:

```yaml
- name: json-schema-guardrail
  gomodule: github.com/wso2/gateway-controllers/policies/json-schema-guardrail@v0
```

## Reference Scenarios

### Example 1: Basic Object Validation

Deploy an LLM provider that validates that request contains a user object with required fields:

```yaml
apiVersion: gateway.api-platform.wso2.com/v1alpha1
kind: LlmProvider
metadata:
  name: json-schema-provider
spec:
  displayName: JSON Schema Provider
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
    - name: json-schema-guardrail
      version: v0
      paths:
        - path: /chat/completions
          methods: [POST]
          params:
            request:
              schema: |
                {
                  "type": "object",
                  "properties": {
                    "name": {"type": "string", "minLength": 1},
                    "email": {"type": "string", "format": "email"},
                    "age": {"type": "integer", "minimum": 18}
                  },
                  "required": ["name", "email"]
                }
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
        "content": "Hello"
      }
    ],
    "name": "John Doe",
    "email": "john@example.com",
    "age": 25
  }'

# Invalid request - missing required fields (should fail with HTTP 422)
curl -X POST http://openai:8080/chat/completions \
  -H "Content-Type: application/json" \
  -H "Host: openai" \
  -d '{
    "model": "gpt-4",
    "messages": [
      {
        "role": "user",
        "content": "Hello"
      }
    ]
  }'
```

**Error Response:**

When validation fails, the guardrail returns an HTTP 422 status code with the following structure:

```json
{
  "type": "JSON_SCHEMA_GUARDRAIL",
  "message": {
    "action": "GUARDRAIL_INTERVENED",
    "interveningGuardrail": "json-schema-guardrail",
    "actionReason": "Violation of JSON schema detected.",
    "direction": "REQUEST"
  }
}
```

If `showAssessment` is enabled, detailed validation errors are included:

```json
{
  "type": "JSON_SCHEMA_GUARDRAIL",
  "message": {
    "action": "GUARDRAIL_INTERVENED",
    "interveningGuardrail": "json-schema-guardrail",
    "actionReason": "Violation of JSON schema detected.",
    "assessments": [
      {
        "description": "String length must be greater than or equal to 5",
        "field": "messages.0.content",
        "value": "Hi"
      }
    ],
    "direction": "REQUEST"
  }
}
```

## How It Works

#### Request Phase

1. **Content Extraction**: Extracts content from the request body using `jsonPath` (if configured) or uses the entire payload.
2. **Schema Validation**: Validates the extracted JSON content against the configured `schema`.
3. **Invert Handling**: Uses `invert` to decide whether valid or invalid schema results should pass.
4. **Decision Enforcement**: Blocks with HTTP `422` when validation fails per configured mode; otherwise, request proceeds upstream.

#### Response Phase

1. **Content Extraction**: Extracts content from the response body using `jsonPath` (if configured) or uses the entire payload.
2. **Schema Validation**: Validates the extracted JSON content against the configured `schema`.
3. **Invert Handling**: Uses `invert` to decide whether valid or invalid schema results should pass.
4. **Decision Enforcement**: Blocks with HTTP `422` when validation fails per configured mode; otherwise, response is returned to the client.

#### Validation Behavior

- **Normal Mode (`invert: false`)**: Validation passes when schema validation succeeds.
- **Inverted Mode (`invert: true`)**: Validation passes when schema validation fails.
- **Assessment Details**: When `showAssessment` is enabled, failure responses include detailed schema validation errors.

#### JSON Schema Features

The guardrail supports JSON Schema Draft 7, including:

- **Types**: `string`, `number`, `integer`, `boolean`, `object`, `array`, `null`
- **Properties**: Define object properties and their schemas
- **Required Fields**: Specify which properties are mandatory
- **Constraints**: `minLength`, `maxLength`, `minimum`, `maximum`, `pattern`, `enum`
- **Nested Structures**: Complex nested objects and arrays
- **Conditional Logic**: `if`, `then`, `else`, `allOf`, `anyOf`, `oneOf`, `not`

## Notes

- The schema must be valid JSON. Use proper escaping when embedding in YAML.
- JSON Schema Draft 7 is supported with all standard features.
- Use `request` and `response` independently to validate one or both directions.
- When using JSONPath, if the path does not exist or the extracted value is not valid JSON, validation will fail.
- Inverted logic is useful for blocking content that matches specific schema patterns.
- Complex schemas may impact performance; test thoroughly with expected content volumes.
- The guardrail validates the structure and types but does not validate business logic or semantic meaning.
