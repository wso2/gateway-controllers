---
title: "Overview"
---
# Amazon Bedrock Guardrails

## Overview

The Amazon Bedrock Guardrails policy validates request or response body content against Amazon Bedrock Guardrails, which provide enterprise-grade content filtering, topic detection, word filtering, and PII (Personally Identifiable Information) detection and masking. This guardrail enables you to enforce content safety policies consistently across your LLM applications using Amazon Bedrock Guardrails, the managed guardrail capability of Amazon Bedrock.

The policy supports multiple authentication modes including AWS IAM role assumption, static credentials, and default credential chain, making it flexible for various AWS deployment scenarios. It can mask or redact PII entities in requests and restore them in responses, ensuring data privacy while maintaining functionality.

## Features

- **Content filtering**: Detects and blocks prohibited content based on guardrail policies
- **Topic detection**: Validates content against configured topic restrictions
- **Word filtering**: Blocks content containing prohibited words or phrases
- **PII detection and masking**: Identifies and masks PII entities (emails, phone numbers, SSNs, etc.)
- **PII restoration**: Restores masked PII in responses when configured (masking mode)
- **PII redaction**: Permanently removes PII by replacing with "*****" (redaction mode)
- **Per-attachment guardrail selection**: Each policy attachment can point at its own Amazon Bedrock guardrail (`guardrailID`/`guardrailVersion`) instead of always using the gateway-wide default
- **Multiple authentication modes**: Supports role assumption, static credentials, or default AWS credential chain
- **JSONPath support**: Extract and validate specific fields within JSON payloads
- **Separate request/response configuration**: Independent configuration for request and response phases
- **Detailed assessment information**: Optional detailed violation information in error responses

## Configuration

The Amazon Bedrock Guardrails policy uses a two-level configuration

### System Parameters (From config.toml)

These parameters are set at the gateway level in `config.toml` and apply to every Amazon Bedrock Guardrails policy instance on the gateway unless a specific attachment overrides `guardrailID`/`guardrailVersion` (see User Parameters below).

##### Amazon Bedrock Guardrails Configuration

| Parameter              | Type   | Required | Description                                                                                                                                                    |
| ---------------------- | ------ | -------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `region`             | string | Yes      | AWS region where the Amazon Bedrock guardrail is located (e.g.,`us-east-1`, `us-west-2`). Always gateway-wide - there is no per-attachment field for this.        |
| `guardrailID`        | string | No       | Gateway-wide default Amazon Bedrock guardrail identifier. Used by any attachment that doesn't set`localGuardrailID`.                                            |
| `guardrailVersion`   | string | No       | Gateway-wide default Amazon Bedrock guardrail version (e.g.,`DRAFT`, `1`, `2`). Used by any attachment that doesn't set `localGuardrailVersion`.          |
| `awsAccessKeyID`     | string | No       | AWS access key ID (for static credentials or role assumption). If omitted, runtime uses default AWS credential chain (environment variables, IAM roles, etc.). |
| `awsSecretAccessKey` | string | No       | AWS secret access key (for static credentials or role assumption). If omitted, runtime uses default AWS credential chain.                                      |
| `awsSessionToken`    | string | No       | AWS session token (optional, for temporary credentials).                                                                                                       |
| `awsRoleARN`         | string | No       | AWS IAM role ARN to assume (for role-based authentication). If specified, runtime assumes this role instead of using static credentials.                       |
| `awsRoleRegion`      | string | No       | AWS region for role assumption (required if`awsRoleARN` is specified).                                                                                       |
| `awsRoleExternalID`  | string | No       | External ID for role assumption (optional, for cross-account access security).                                                                                 |

#### Sample System Configuration

Add the following configuration section under the root level in your `config.toml` file:

```toml
awsbedrock_guardrail_region = "us-east-1"
awsbedrock_guardrail_id = "your-guardrail-id"
awsbedrock_guardrail_version = "DRAFT"
awsbedrock_access_key_id = ""
awsbedrock_secret_access_key = ""
awsbedrock_session_token = ""
awsbedrock_role_arn = ""
awsbedrock_role_region = ""
awsbedrock_role_external_id = ""
```

`awsbedrock_guardrail_id`/`awsbedrock_guardrail_version` only need to be set if at least one attachment relies on the gateway-wide default instead of setting `localGuardrailID`/`localGuardrailVersion` itself.

### User Parameters (API Definition)

| Parameter                 | Type   | Required | Default | Description                                                                                                                                                                                    |
| ------------------------- | ------ | -------- | ------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `localGuardrailID`      | string | No       | -       | Amazon Bedrock guardrail identifier for this policy attachment. Overrides the gateway-wide`guardrailID` system parameter. Leave unset to use the gateway-wide value.                            |
| `localGuardrailVersion` | string | No       | -       | Amazon Bedrock guardrail version (e.g.,`DRAFT`, `1`) for this policy attachment. Overrides the gateway-wide `guardrailVersion` system parameter. Leave unset to use the gateway-wide value. |
| `request`               | object | See note | -       | Configuration for request-phase validation.                                                                                                                                                    |
| `response`              | object | See note | -       | Configuration for response-phase validation.                                                                                                                                                   |

At least one of `request` or `response` must be provided - a policy attachment with neither configured is rejected at deploy time.

`localGuardrailID` and `localGuardrailVersion` resolve independently of each other: an attachment can set only one of them (or neither, or both) and the other falls back to its own gateway-wide system parameter. There is no requirement that both be overridden together.

#### Request Configuration

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `enabled` | boolean | No | `true` | Enables validation for the request flow. |
| `jsonPath` | string | No | `"$.messages[-1].content"` | JSONPath expression to extract a specific value from the request JSON payload. If empty, validates the entire payload as a string. |
| `redactPII` | boolean | No | `false` | If `true`, redacts PII by replacing with `*****` (permanent). If `false`, masks PII with placeholders that can be restored in responses. |
| `passthroughOnError` | boolean | No | `false` | If `true`, allows the request to proceed when the Amazon Bedrock Guardrails API call fails. If `false`, blocks on API errors. |
| `showAssessment` | boolean | No | `false` | If `true`, includes detailed assessment information from Amazon Bedrock Guardrails in error responses. |

#### Response Configuration

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `enabled` | boolean | No | `false` | Enables validation for the response flow. |
| `jsonPath` | string | No | `"$.choices[0].message.content"` | JSONPath expression to extract a specific value from the response JSON payload. If empty, validates the entire payload as a string. |
| `passthroughOnError` | boolean | No | `false` | If `true`, allows the response to proceed when the Amazon Bedrock Guardrails API call fails. If `false`, blocks on API errors. |
| `showAssessment` | boolean | No | `false` | If `true`, includes detailed assessment information from Amazon Bedrock Guardrails in error responses. |

#### JSONPath Support

The guardrail supports JSONPath expressions to extract and validate specific fields within JSON payloads. Common examples:

- `$.messages` - Extracts the `messages` field from the root object
- `$.data.content` - Extracts nested content from `data.content`
- `$.items[0].text` - Extracts text from the first item in an array
- `$.messages[0].content` - Extracts content from the first message in a messages array
- `$.messages[-1].content` - Extracts content from the last message in a messages array

If `jsonPath` is empty or not specified, the entire payload is treated as a string and validated.

**Note:**

Inside the `gateway/build.yaml`, ensure the policy module is added under `policies:`:

```yaml
- name: aws-bedrock-guardrail
  gomodule: github.com/wso2/gateway-controllers/policies/aws-bedrock-guardrail@v1
```

## Reference Scenarios

### Example 1: Basic Guardrail with Static Credentials

Deploy an LLM provider with Amazon Bedrock Guardrails validation:

```yaml
apiVersion: gateway.api-platform.wso2.com/v1
kind: LlmProvider
metadata:
  name: bedrock-guardrail-provider
spec:
  displayName: Amazon Bedrock Guardrails Provider
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
    - name: aws-bedrock-guardrail
      version: v1
      paths:
        - path: /chat/completions
          methods: [POST]
          params:
            request:
              jsonPath: "$.messages[0].content"
              redactPII: false
              showAssessment: true
            response:
              jsonPath: "$.choices[0].message.content"
              showAssessment: true
```

**Test the guardrail:**

```bash
# Request with prohibited content (should fail with HTTP 422)
curl -X POST http://localhost:8080/openai/chat/completions \
  -H "Content-Type: application/json" \
  -d '{
    "model": "gpt-4",
    "messages": [
      {
        "role": "user",
        "content": "This is prohibited content"
      }
    ]
  }'

# Request with PII (should mask PII and proceed)
curl -X POST http://localhost:8080/openai/chat/completions \
  -H "Content-Type: application/json" \
  -d '{
    "model": "gpt-4",
    "messages": [
      {
        "role": "user",
        "content": "Contact me at user@example.com or call 555-123-4567"
      }
    ]
  }'
```

### Example 2: PII Redaction Mode

Configure to redact PII:

```yaml
operationPolicies:
  - name: aws-bedrock-guardrail
    version: v1
    paths:
      - path: /chat/completions
        methods: [POST]
        params:
          request:
            jsonPath: "$.messages[0].content"
            redactPII: true  # Redact mode
            showAssessment: false
          response:
            jsonPath: "$.choices[0].message.content"
```

### Example 3: Error Response

When validation fails, the guardrail returns an HTTP 422 status code with the following structure:

```json
{
  "type": "AWS_BEDROCK_GUARDRAIL",
  "message": {
    "action": "GUARDRAIL_INTERVENED",
    "interveningGuardrail": "AWS Bedrock Guardrail",
    "actionReason": "Violation of AWS Bedrock Guardrail detected.",
    "direction": "REQUEST"
  }
}
```

If `showAssessment` is enabled, additional details are included:

```json
{
  "type": "AWS_BEDROCK_GUARDRAIL",
  "message": {
    "action": "GUARDRAIL_INTERVENED",
    "interveningGuardrail": "AWS Bedrock Guardrail",
    "actionReason": "Violation of AWS Bedrock Guardrail detected.",
    "direction": "REQUEST",
    "assessments": {
      "topicPolicy": {
        "topics": ["Topic1", "Topic2"]
      },
      "contentPolicy": {
        "filters": ["Filter1"]
      },
      "sensitiveInformationPolicy": {
        "piiEntities": [...],
        "regexes": [...]
      }
    }
  }
}
```

### Example 4: Per-Attachment Guardrail Selection

Two attachments on the same gateway, each pointing at a different Amazon Bedrock guardrail while sharing the same gateway-wide `region`:

```yaml
operationPolicies:
  - name: aws-bedrock-guardrail
    version: v1
    paths:
      - path: /chat/completions
        methods: [POST]
        params:
          localGuardrailID: "gr-tenant-a-guardrail"
          localGuardrailVersion: "1"
          request:
            jsonPath: "$.messages[-1].content"
            showAssessment: true
          response:
            enabled: true
            jsonPath: "$.choices[0].message.content"
```

A second attachment can set a different `localGuardrailID`/`localGuardrailVersion`, or omit either one to fall back to the gateway-wide `guardrailID`/`guardrailVersion`. `region` still comes exclusively from the gateway-wide system parameter in both cases.

## How It Works

#### Request Phase

1. **Content Extraction**: Extracts content from the request body using `jsonPath` (if configured) or uses the entire payload.
2. **Guardrail Evaluation**: Sends the extracted content to Amazon Bedrock Guardrails using the gateway-wide `region`, plus the guardrail ID and version resolved from this attachment's `localGuardrailID`/`localGuardrailVersion` (falling back independently to the gateway-wide `guardrailID`/`guardrailVersion` for whichever one isn't set).
3. **PII Processing**: If `redactPII` is `false`, masks PII entities with placeholders for potential restoration. If `redactPII` is `true`, replaces PII with `*****` permanently.
4. **Violation Handling**: Blocks and returns HTTP `422` when Bedrock reports a violation.
5. **Error Strategy**: Applies `passthroughOnError` behavior to decide whether to fail closed or allow traffic on Bedrock API failures.

#### Response Phase

1. **Content Extraction**: Extracts content from the response body using `jsonPath` (if configured) or uses the entire payload.
2. **Guardrail Evaluation**: Validates response content through Amazon Bedrock Guardrails.
3. **PII Restoration**: In masking mode (`redactPII: false`), restores masked PII values in response content when mappings are available from request metadata.
4. **Violation Handling**: Blocks and returns HTTP `422` when Bedrock reports a violation.
5. **Error Strategy**: Applies `passthroughOnError` behavior for Bedrock API failures.

#### PII Handling Modes

- **Masking Mode (`redactPII: false`)**: PII entities are replaced with placeholders such as `EMAIL_0001`, `PHONE_0002`, and can be restored in the response phase.
- **Redaction Mode (`redactPII: true`)**: PII entities are permanently replaced with `*****`, and original values cannot be restored.

#### Authentication Modes

- **Default Credential Chain**: Uses runtime AWS credentials from environment variables, IAM roles, or other default provider sources.
- **Static Credentials**: Uses `awsAccessKeyID`, `awsSecretAccessKey`, and optional `awsSessionToken`.
- **Role Assumption**: Uses `awsRoleARN` (and related role fields) to assume a target IAM role before calling Bedrock.

## Notes

- The guardrail must be created in Amazon Bedrock before use. Use AWS Console, CLI, or SDK to create guardrails with your policies.
- Guardrail version "DRAFT" is useful for testing. Use numbered versions (e.g., "1", "2") for production.
- PII masking with restoration (`redactPII: false`) stores mapping between original and masked values in request metadata, which is used during response processing.
- When using role assumption, ensure the IAM role has `bedrock:ApplyGuardrail` permission.
- The policy uses AWS SDK v2 for authentication and API calls.
- Content modifications (PII masking) are applied to the payload and forwarded to upstream if no blocking violation occurs.
- The policy validates both request and response phases independently when both are configured.
- Ensure your guardrail is in the specified AWS region; cross-region calls are not supported.
