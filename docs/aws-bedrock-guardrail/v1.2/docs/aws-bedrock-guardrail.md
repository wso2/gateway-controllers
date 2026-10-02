---
title: "Overview"
---
# AWS Bedrock Guardrail

## Overview

The AWS Bedrock Guardrail policy validates request or response body content against AWS Bedrock Guardrails, which provide enterprise-grade content filtering, topic detection, word filtering, and PII (Personally Identifiable Information) detection and masking. This guardrail enables you to enforce content safety policies consistently across your LLM applications using AWS Bedrock's managed guardrail service.

Every setting can be configured per policy attachment or gateway-wide. An attachment can select its own guardrail, its own region, and its own AWS identity — so a single gateway can enforce different content policies for different APIs, including guardrails that live in different AWS accounts.

## Features

- **Content filtering**: Detects and blocks prohibited content based on guardrail policies
- **Topic detection**: Validates content against configured topic restrictions
- **Word filtering**: Blocks content containing prohibited words or phrases
- **PII detection and masking**: Identifies and masks PII entities (emails, phone numbers, SSNs, etc.)
- **PII restoration**: Restores masked PII in responses when configured (masking mode)
- **PII redaction**: Permanently removes PII by replacing with "*****" (redaction mode)
- **Per-attachment guardrail selection**: Each attachment can set its own `region`, `guardrailID`, and `guardrailVersion`
- **Per-attachment AWS identity**: Each attachment can set its own `awsAuth`, letting the guardrail live in a different AWS account
- **Credential modes**: gateway-wide (`system`, the default), IRSA, STS AssumeRole, default credential chain, or static access keys
- **Gateway-level allowlists**: Operators can restrict which regions, guardrails, roles, and credential modes attachments may select
- **JSONPath support**: Extract and validate specific fields within JSON payloads
- **Separate request/response configuration**: Independent configuration for request and response phases

## Configuration

The policy uses a two-level configuration. Every parameter can be set gateway-wide in `config.toml`, and an attachment can override it in the API definition. Where both levels set the same parameter, **the attachment value wins**.

### System Parameters (from config.toml)

#### Guardrail and credential defaults

| Parameter | Type | Required | Description |
| --------- | ---- | -------- | ----------- |
| `region` | string | Yes* | AWS region where the Bedrock Guardrail is located (e.g. `us-east-1`). *Required unless every attachment sets its own. |
| `guardrailID` | string | Yes* | Default AWS Bedrock Guardrail identifier. *Required unless every attachment sets its own. |
| `guardrailVersion` | string | Yes* | Default guardrail version (e.g. `DRAFT`, `1`). *Required unless every attachment sets its own. |
| `awsAccessKeyID` | string | No | AWS access key ID for the gateway's own identity. If omitted, the default AWS credential chain is used. |
| `awsSecretAccessKey` | string | No | AWS secret access key paired with `awsAccessKeyID`. |
| `awsSessionToken` | string | No | AWS session token, for temporary credentials. |
| `awsRoleARN` | string | No | IAM role ARN to assume. If set, the gateway assumes this role instead of using static credentials. |
| `awsRoleRegion` | string | No | AWS region for role assumption. Required if `awsRoleARN` is set. |
| `awsRoleExternalID` | string | No | External ID for role assumption, for cross-account access. |

#### Allowlists

Each allowlist restricts what a policy attachment may select. An empty or unset allowlist places no restriction.

`allowedRegions` and `allowedRoleARNs` accept a single trailing `*` as a prefix match. `allowedGuardrailIDs` and `allowedAuthTypes` are exact-match only.

| Parameter | Type | Description |
| --------- | ---- | ----------- |
| `allowedRegions` | string[] | Permitted values for the effective `region`. An entry ending in `*` matches any region with that prefix, e.g. `us-east-*`. |
| `allowedGuardrailIDs` | string[] | Permitted values for the effective `guardrailID`. Exact matches only. |
| `allowedRoleARNs` | string[] | Permitted values for the effective role ARN. An entry ending in `*` matches any ARN with that prefix. Cross-account patterns need one entry per account. |
| `allowedAuthTypes` | string[] | Permitted values for the **effective** `authenticationType`. Exact matches only. An attachment that omits `awsAuth` resolves to `system`, so include `system` unless every attachment sets one explicitly. Omit `iam-user-access-key` to forbid attachment-level long-lived credentials while leaving every other parameter configurable per attachment. |

#### Sample System Configuration

Add the following configuration section under the root level in your `config.toml` file:

```toml
awsbedrock_guardrail_region  = "us-east-1"
awsbedrock_guardrail_id      = "your-guardrail-id"
awsbedrock_guardrail_version = "DRAFT"

awsbedrock_access_key_id     = ""
awsbedrock_secret_access_key = ""
awsbedrock_session_token     = ""
awsbedrock_role_arn          = ""
awsbedrock_role_region       = ""
awsbedrock_role_external_id  = ""

# Optional. Empty means unrestricted.
awsbedrock_allowed_regions       = ["us-east-1", "eu-west-1"]
awsbedrock_allowed_guardrail_ids = ["your-guardrail-id"]
awsbedrock_allowed_role_arns     = ["arn:aws:iam::444455556666:role/wso2-gw-guardrail-*"]
awsbedrock_allowed_auth_types    = ["system", "irsa", "sts-assume-role", "default-credential-chain"]
```

### User Parameters (API Definition)

| Parameter | Type | Required | Default | Description |
| --------- | ---- | -------- | ------- | ----------- |
| `region` | string | No | gateway-wide value | AWS region hosting the guardrail for this attachment. |
| `guardrailID` | string | No | gateway-wide value | Guardrail identifier for this attachment. |
| `guardrailVersion` | string | No | gateway-wide value | Guardrail version for this attachment. |
| `localGuardrailID` | string | No | – | **Deprecated** — use `guardrailID`. Retained so attachments authored against previous versions keep working unchanged; remove it when migrating. |
| `localGuardrailVersion` | string | No | – | **Deprecated** — use `guardrailVersion`. Retained so attachments authored against previous versions keep working unchanged; remove it when migrating. |
| `awsAuth` | object | No | `system` | AWS identity for this attachment. Omitting it uses the gateway-wide identity. See below. |
| `request` | object | See note | – | Request-phase validation configuration. |
| `response` | object | See note | – | Response-phase validation configuration. |

At least one of `request` or `response` must be provided.

`region`, `guardrailID`, and `guardrailVersion` resolve independently — an attachment can set only the version and inherit the rest.

> **`localGuardrailID` / `localGuardrailVersion` are deprecated.** Still work exactly as previously, therefore no existing attachment needs changing. Prefer `guardrailID` / `guardrailVersion` for new attachments. Please migrate existing attachments to the new parameter names.

#### `awsAuth` — per-attachment AWS identity

`awsAuth` is optional and defaults to `system`. If it is not set, the gateway-wide credential settings from `config.toml` are used, exactly as before.

`authenticationType: system` states that deferral explicitly. **Every other mode ignores the gateway-wide credential settings entirely** — `awsbedrock_access_key_id`, `awsbedrock_role_arn` and the rest are not consulted, so an attachment-level identity is never blended with the gateway's.

| Mode | Identity comes from | Attachment supplies |
| ---- | ------------------- | ------------------- |
| `irsa` | The gateway pod's projected service-account token (`AWS_WEB_IDENTITY_TOKEN_FILE`) | Optionally `awsRoleARN`; otherwise the injected `AWS_ROLE_ARN` is used |
| `sts-assume-role` | The role named in `awsRoleARN`, assumed from a **base** identity | The target role and its external ID. The base identity is either the static key given here, or — if none is given — the gateway's own runtime credentials, which on EKS means its IRSA identity |
| `default-credential-chain` | Whatever the AWS SDK resolves at runtime: environment, instance profile, ECS task role, or IRSA | Nothing |
| `iam-user-access-key` | The key and secret in the attachment | Everything |

Therefore "self-contained" applies strictly only to `iam-user-access-key`. The others are self-contained with respect to *gateway-wide configuration*, while still relying on the runtime identity of the gateway process.

**A field the selected mode does not use is ignored.** `awsRoleARN` alongside `iam-user-access-key`, `awsAccessKeyID` alongside `irsa`, or any credential field alongside `system` — each is accepted and has no effect. The same applies when `authenticationType` is omitted, which resolves to `system`.

Two consequences worth internalising:

- A stale field left behind by an edit will not fail a deployment, but it will not do anything either. **Read `authenticationType` to determine which identity an attachment uses — not which fields are present.**
- Fields a mode *requires* are still enforced. `sts-assume-role` without `awsRoleARN`, or `iam-user-access-key` without a key and secret, is rejected at deploy time.

| Parameter | Type | Required | Default | Description |
| --------- | ---- | -------- | ------- | ----------- |
| `authenticationType` | string | No | `system` | One of `system`, `irsa`, `sts-assume-role`, `default-credential-chain`, `iam-user-access-key`. Defaults to `system`, so an `awsAuth` block that names no mode uses the gateway-wide identity. |
| `awsRoleARN` | string | Conditional | – | Required for `sts-assume-role`. Optional for `irsa` — falls back to the `AWS_ROLE_ARN` environment variable. |
| `awsRoleRegion` | string | No | effective `region` | AWS region whose STS endpoint is used for the assumption. |
| `awsRoleExternalID` | string | No | – | External ID required by the target role's trust policy. Used only by `sts-assume-role` — `irsa` calls `AssumeRoleWithWebIdentity`, which has no external-ID parameter, so a value set there is ignored. |
| `awsRoleSessionName` | string | No | `bedrock-guardrail-session` | Session name used when assuming the role. This is what appears in the target account's CloudTrail, so prefer a value identifying this API. |
| `awsAccessKeyID` | string | Conditional | – | Required for `iam-user-access-key`. Optional base credential for `sts-assume-role`. |
| `awsSecretAccessKey` | string | Conditional | – | Required for `iam-user-access-key`. |
| `awsSessionToken` | string | No | – | Only meaningful when the key/secret pair is already temporary. |

##### Choosing a credential mode

| Mode | Credential material in the API definition | When to use |
| ---- | ----------------------------------------- | ----------- |
| `system` | **None** | The attachment has no AWS identity of its own and uses the gateway-wide configuration. Any other field in `awsAuth` is ignored. |
| `irsa` | **None** | Gateway runs on EKS with IAM Roles for Service Accounts. Preferred. |
| `sts-assume-role` | None, when the base credentials come from IRSA or the gateway's instance role | Guardrail lives in another AWS account. Preferred for cross-account. |
| `default-credential-chain` | **None** | Gateway compute already runs under the exact role needed. |
| `iam-user-access-key` | **A long-lived AWS secret key** | Only when none of the above is possible. |

> **Before using `iam-user-access-key`:** an access key placed in an API definition is stored with that definition. Unlike a role ARN and external ID, an access key is a bearer credential: it works from anywhere, against every AWS API its IAM identity permits, independently of this gateway. Scope the IAM identity behind it to `bedrock:ApplyGuardrail` on specific guardrail ARNs and nothing else, and prefer any of the other three modes. Operators can disable this mode entirely with `awsbedrock_allowed_auth_types`.

For `irsa`, the web identity token file path is never a policy parameter — it is always read from the `AWS_WEB_IDENTITY_TOKEN_FILE` environment variable injected by the EKS Pod Identity Webhook, alongside `AWS_ROLE_ARN`.

#### Request Configuration

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `enabled` | boolean | No | `true` | Enables validation for the request flow. |
| `jsonPath` | string | No | `"$.messages[-1].content"` | JSONPath expression to extract a specific value from the request JSON payload. If empty, validates the entire payload as a string. |
| `redactPII` | boolean | No | `false` | If `true`, redacts PII by replacing with `*****` (permanent). If `false`, masks PII with placeholders that can be restored in responses. |
| `passthroughOnError` | boolean | No | `false` | If `true`, allows the request to proceed when the AWS Bedrock Guardrail API call fails. If `false`, blocks on API errors. |
| `showAssessment` | boolean | No | `false` | If `true`, includes detailed assessment information from AWS Bedrock Guardrail in error responses. |

#### Response Configuration

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `enabled` | boolean | No | `false` | Enables validation for the response flow. |
| `jsonPath` | string | No | `"$.choices[0].message.content"` | JSONPath expression to extract a specific value from the response JSON payload. If empty, validates the entire payload as a string. |
| `passthroughOnError` | boolean | No | `false` | If `true`, allows the response to proceed when the AWS Bedrock Guardrail API call fails. If `false`, blocks on API errors. |
| `showAssessment` | boolean | No | `false` | If `true`, includes detailed assessment information from AWS Bedrock Guardrail in error responses. |

#### JSONPath Support

The guardrail supports JSONPath expressions to extract and validate specific fields within JSON payloads. Common examples:

- `$.messages` - Extracts the `messages` field from the root object
- `$.data.content` - Extracts nested content from `data.content`
- `$.items[0].text` - Extracts text from the first item in an array
- `$.messages[0].content` - Extracts content from the first message in a messages array
- `$.messages[-1].content` - Extracts content from the last message in a messages array

If `jsonPath` is empty or not specified, the entire payload is treated as a string and validated.

The path may also select an object or an array, or use a `*` segment to fan out over an object's values or an array's items (for example `$.questions.*.instructions`). Every string, number and boolean inside the selection is joined with newlines, with object keys in sorted order, and sent to the guardrail in one call. When the guardrail masks or redacts PII, the change is written back into each value in place, and all masked values share one set of placeholders so the response is restored correctly. A path that does not resolve, or that selects no text, fails validation.

If a masked or redacted value cannot be written back into the payload, the request is rejected rather than forwarded with the original content.

**Note:**

Inside the `gateway/build.yaml`, ensure the policy module is added under `policies:`:

```yaml
- name: aws-bedrock-guardrail
  gomodule: github.com/wso2/gateway-controllers/policies/aws-bedrock-guardrail@v1
```

## Reference Scenarios

### Example 1: Gateway defaults

Every guardrail setting comes from `config.toml`.

```yaml
apiVersion: gateway.api-platform.wso2.com/v1
kind: LlmProvider
metadata:
  name: bedrock-guardrail-provider
spec:
  displayName: AWS Bedrock Guardrail Provider
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
            awsAuth:
              authenticationType: system
            request:
              jsonPath: "$.messages[-1].content"
              showAssessment: true
            response:
              enabled: true
              jsonPath: "$.choices[0].message.content"
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

### Example 2: Per-attachment guardrail and region

Two APIs on one gateway, each with its own guardrail in its own region.

```yaml
operationPolicies:
  - name: aws-bedrock-guardrail
    version: v1
    paths:
      - path: /chat/completions
        methods: [POST]
        params:
          region: "eu-west-1"
          guardrailID: "gr-eu-strict"
          guardrailVersion: "3"
          awsAuth:
            authenticationType: system
          request:
            jsonPath: "$.messages[-1].content"
            showAssessment: true
          response:
            enabled: true
            jsonPath: "$.choices[0].message.content"
```

### Example 3: Guardrail in another AWS account, no secret in the API definition

The gateway assumes a role in the tenant's account. On EKS the base credentials come from the gateway's IRSA identity, so no credential material appears in the API definition — the external ID is an anti-confused-deputy identifier, not a secret key.

```yaml
operationPolicies:
  - name: aws-bedrock-guardrail
    version: v1
    paths:
      - path: /chat/completions
        methods: [POST]
        params:
          region: "eu-west-1"
          guardrailID: "gr-tenant-a"
          guardrailVersion: "3"
          awsAuth:
            authenticationType: sts-assume-role
            awsRoleARN: "arn:aws:iam::444455556666:role/wso2-gw-guardrail-tenant-a"
            awsRoleExternalID: "tnt-a-7f3c9e21"
            awsRoleSessionName: "wso2-gw-support-api"
          request:
            enabled: true
            jsonPath: "$.messages[-1].content"
          response:
            enabled: true
            jsonPath: "$.choices[0].message.content"
```

The target role needs a trust policy naming the gateway principal and pinning the external ID:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": { "AWS": "arn:aws:iam::111122223333:role/gateway-bedrock-guardrail" },
    "Action": "sts:AssumeRole",
    "Condition": { "StringEquals": { "sts:ExternalId": "tnt-a-7f3c9e21" } }
  }]
}
```

and a permission policy allowing only the guardrail call:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": "bedrock:ApplyGuardrail",
    "Resource": "arn:aws:bedrock:eu-west-1:444455556666:guardrail/gr-tenant-a",
    "Condition": { "StringEquals": { "aws:RequestedRegion": "eu-west-1" } }
  }]
}
```

The gateway's own identity needs only scoped assume-role permission — never `Resource: "*"`:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": "sts:AssumeRole",
    "Resource": "arn:aws:iam::*:role/wso2-gw-guardrail-*"
  }]
}
```

### Example 4: IRSA

The gateway runs on EKS under a ServiceAccount annotated with `eks.amazonaws.com/role-arn`. No credential material and no role ARN are needed in the API definition.

```yaml
        params:
          region: "us-east-1"
          guardrailID: "gr-123"
          guardrailVersion: "1"
          awsAuth:
            authenticationType: irsa
          request:
            jsonPath: "$.messages[-1].content"
```

### Example 5: PII redaction mode

```yaml
        params:
          awsAuth:
            authenticationType: system
          request:
            jsonPath: "$.messages[0].content"
            redactPII: true
            showAssessment: false
          response:
            enabled: true
            jsonPath: "$.choices[0].message.content"
```

### Example 6: Error response

When validation fails, the guardrail returns HTTP 422:

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

### Example 7: Restricting what attachments may select

An operator allows per-attachment identity but not per-attachment long-lived secrets:

```toml
awsbedrock_allowed_regions       = ["us-east-1", "eu-west-1"]
awsbedrock_allowed_guardrail_ids = ["gr-default", "gr-eu-strict", "gr-tenant-a"]
awsbedrock_allowed_role_arns     = ["arn:aws:iam::444455556666:role/wso2-gw-guardrail-*"]
awsbedrock_allowed_auth_types    = ["system", "irsa", "sts-assume-role", "default-credential-chain"]
```

An attachment selecting `iam-user-access-key`, a region outside the list, or a role ARN outside the prefix is rejected at deploy time.

## How It Works

#### Request Phase

1. **Content extraction**: Extracts content using `jsonPath`, or uses the entire payload.
2. **Guardrail evaluation**: Calls `ApplyGuardrail` with the effective region, guardrail ID, and version, using the identity resolved from `awsAuth` or the gateway-wide settings.
3. **PII processing**: With `redactPII: false`, masks PII with placeholders for later restoration. With `redactPII: true`, replaces PII with `*****` permanently.
4. **Violation handling**: Blocks and returns HTTP `422` when Bedrock reports a violation.
5. **Error Strategy**: Applies `passthroughOnError` behavior to decide whether to fail closed or allow traffic on Bedrock API failures.

#### Response Phase

1. **Content extraction**: Extracts content using `jsonPath`, or uses the entire payload.
2. **Guardrail evaluation**: Validates response content through the guardrail.
3. **PII restoration**: In masking mode, restores masked PII values when mappings are available from request metadata.
4. **Violation handling**: Blocks and returns HTTP `422` on violation.
5. **Error Strategy**: Applies `passthroughOnError` behavior for Bedrock API failures.

#### Credential resolution

The credentials provider is built **once**, when the policy attachment is created, and reused across requests. Role assumption therefore happens on first use and on refresh near expiry, not on every request. A failure to build it — an unassumable role, a missing IRSA environment — rejects the attachment at deploy time rather than failing at request time.

#### PII Handling Modes

- **Masking mode (`redactPII: false`)**: PII entities are replaced with placeholders such as `EMAIL_0001`, `PHONE_0002`, restorable in the response phase.
- **Redaction mode (`redactPII: true`)**: PII entities are permanently replaced with `*****`.

## Notes

- The guardrail must exist in AWS Bedrock before use, in the region the attachment selects. Cross-region calls are not supported: a guardrail in `eu-west-1` is not reachable from a `us-east-1` client.
- Guardrail version `DRAFT` is useful for testing. Use numbered versions for production.
- The IAM identity used must have `bedrock:ApplyGuardrail` on the target guardrail.
- PII masking with restoration stores the mapping between original and masked values in request metadata.
- Content modifications (PII masking) are forwarded upstream if no blocking violation occurs.
- Request and response phases are validated independently when both are configured.
- Credential material is never written to logs. The session name, not the credentials, is what identifies the gateway in the target account's CloudTrail.
