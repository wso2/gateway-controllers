---
title: "Overview"
---
# Amazon Bedrock Guardrails

## Overview

The Amazon Bedrock Guardrails policy validates request or response body content against Amazon Bedrock Guardrails, which provide enterprise-grade content filtering, topic detection, word filtering, and PII (Personally Identifiable Information) detection and masking. This guardrail enables you to enforce content safety policies consistently across your LLM applications using Amazon Bedrock Guardrails, the managed guardrail capability of Amazon Bedrock.

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
- **JSONPath support**: Extract and validate specific fields within JSON payloads, with wildcards and every string inside a selected object
- **MCP support**: Validates MCP tool calls and tool results, including Server-Sent Events (Streamable HTTP) responses
- **Streaming responses**: Validates streamed LLM responses (`stream: true`) a text unit at a time, so tokens still reach the client incrementally
- **Separate request/response configuration**: Independent configuration for request and response phases
- **Response status code selection**: Validate only responses with the configured upstream status codes, so provider error responses reach the client unchanged

## Configuration

The policy uses a two-level configuration. The guardrail identity and AWS credentials can be set gateway-wide in `config.toml`, and an attachment can override them in the API definition. Where both levels set the same parameter, the attachment value wins. The `request` and `response` settings are configured only on the attachment.

### System Parameters (from config.toml)

#### Guardrail and credential defaults

| Parameter | Type | Required | Description |
| --------- | ---- | -------- | ----------- |
| `region` | string | Yes* | AWS region where the Amazon Bedrock guardrail is located (e.g. `us-east-1`). *Required unless every attachment sets its own. |
| `guardrailID` | string | Yes* | Default Amazon Bedrock guardrail identifier. *Required unless every attachment sets its own. |
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

> **`localGuardrailID` / `localGuardrailVersion` are deprecated.** Still work exactly as previously, therefore no existing attachment needs changing. Prefer `guardrailID` / `guardrailVersion` for new attachments. Please migrate existing attachments to the new parameter names. If an attachment sets both a deprecated key and its replacement, the deprecated key wins, so adding `guardrailID` or `guardrailVersion` without removing `localGuardrailID` or `localGuardrailVersion` does not change the selected guardrail or version. Remove the deprecated key when you migrate.

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

- A stale field left behind by an edit does not change which identity is used, and it is not otherwise read. Its format is still checked, though: a malformed `awsRoleARN` or `awsRoleRegion` fails the deployment even under an `authenticationType` that does not use it. **Read `authenticationType` to determine which identity an attachment uses — not which fields are present.**
- Fields a mode *requires* are still enforced. `sts-assume-role` without `awsRoleARN`, or `iam-user-access-key` without a key and secret, is rejected at deploy time.

| Parameter | Type | Required | Default | Description |
| --------- | ---- | -------- | ------- | ----------- |
| `authenticationType` | string | No | `system` | One of `system`, `irsa`, `sts-assume-role`, `default-credential-chain`, `iam-user-access-key`. Defaults to `system`, so an `awsAuth` block that names no mode uses the gateway-wide identity. |
| `awsRoleARN` | string | Conditional | – | Required for `sts-assume-role`. Optional for `irsa` — falls back to the `AWS_ROLE_ARN` environment variable. |
| `awsRoleRegion` | string | No | effective `region` | AWS region whose STS endpoint is used for the assumption. |
| `awsRoleExternalID` | string | No | – | External ID required by the target role's trust policy. Used only by `sts-assume-role` — `irsa` calls `AssumeRoleWithWebIdentity`, which has no external-ID parameter, so a value set there is ignored. |
| `awsRoleSessionName` | string | No | `wso2-gw-<apiName>[-<apiVersion>]`; `bedrock-guardrail-session` when the API has neither | Session name used when assuming the role. This is what appears in the target account's CloudTrail. The default is derived from the API the policy is attached to (characters STS does not allow become `-`, truncated to 64 characters). |
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
| `jsonPath` | string | No | `"$.messages[-1].content"` | JSONPath expression selecting the request content to validate. When it selects an object or array, every string inside it is validated. If empty, validates the entire payload as a string. See [JSONPath Support](#jsonpath-support). |
| `redactPII` | boolean | No | `false` | If `true`, redacts PII by replacing with `*****` (permanent). If `false`, masks PII with placeholders that can be restored in responses. |
| `passthroughOnError` | boolean | No | `false` | If `true`, allows the request to proceed when the Amazon Bedrock Guardrails API call fails. If `false`, blocks on API errors. |
| `showAssessment` | boolean | No | `false` | If `true`, includes detailed assessment information from Amazon Bedrock Guardrails in error responses. |

#### Response Configuration

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `enabled` | boolean | No | `false` | Enables validation for the response flow. |
| `jsonPath` | string | No | `"$.choices[0].message.content"` | JSONPath expression selecting the response content to validate. When it selects an object or array, every string inside it is validated. For a Server-Sent Events response, it is applied to the JSON in each event. If empty, validates the entire payload as a string. See [JSONPath Support](#jsonpath-support). |
| `passthroughOnError` | boolean | No | `false` | If `true`, allows the response to proceed when the Amazon Bedrock Guardrails API call fails. If `false`, blocks on API errors. |
| `showAssessment` | boolean | No | `false` | If `true`, includes detailed assessment information from Amazon Bedrock Guardrails in error responses. |
| `applicableStatusCodes` | string | No | – | Comma-separated upstream response status codes and inclusive ranges to validate, such as `"200-299,422"`. Codes must be between `100` and `599`, and a range must not start after it ends. Responses with any other status code are passed through to the client unchanged. If not set, every response is validated. |
| `streamingJsonPath` | string | No | `"$.choices[0].delta.content"` | JSONPath locating the assistant text inside one streamed event of an LLM response. Separate from `jsonPath` because a streamed response carries its text under a different field than a buffered one. The default suits the OpenAI streaming format, which is also what `openai-to-bedrock-transformer` emits. See [Streaming responses](#streaming-responses). |
| `streamingTextUnitChars` | integer | No | `1000` | How many characters of streamed response text to assess at a time. Each batch is withheld until assessed. `1000` is Amazon's text unit and billing unit. Lower values give earlier first tokens but more `ApplyGuardrail` calls and a longer total time; `0` assesses the whole response when the stream ends. Minimum `100`. |

#### JSONPath Support

The guardrail supports JSONPath expressions to extract and validate specific fields within JSON payloads. Common examples:

- `$.messages` - Extracts the `messages` field from the root object
- `$.data.content` - Extracts nested content from `data.content`
- `$.items[0].text` - Extracts text from the first item in an array
- `$.messages[0].content` - Extracts content from the first message in a messages array
- `$.messages[-1].content` - Extracts content from the last message in a messages array
- `$.items[*].text` - Extracts `text` from every item in an array (`$.items.*.text` is equivalent)
- `$.params.arguments` - Selects an object, so every string inside it is validated

When the selected value is an object or an array, every string inside it is sent to the guardrail. A path that matches nothing, or that selects only `true`, `false`, or `null`, is an extraction error, handled according to `passthroughOnError`. Numbers are validated only when selected directly. Every string includes non-text values such as inline base64 image data (`data:` URLs) and type names, so a path such as `$.messages[-1].content` sends every part of a multimodal message to the guardrail, image data included.

If `jsonPath` is set to an empty string (`""`), the entire payload is treated as a string and validated. This includes a Server-Sent Events response: it is withheld whole and validated as text, rather than read event by event with `streamingJsonPath`, so it is not streamed. If `jsonPath` is omitted, the default path for that phase is used (`$.messages[-1].content` for requests, `$.choices[0].message.content` for responses).

#### MCP routes

The default paths target OpenAI-style chat completions. An MCP `tools/call` has no `messages` and a tool result has no `choices`, so set the paths for MCP traffic:

| Phase | `jsonPath` | Validates |
|-------|------------|-----------|
| Request | `$.params.arguments` | Every string argument of the tool call, whatever the argument names |
| Response | `$.result.content[*].text` | The text of every content item in the tool result |

MCP servers using Streamable HTTP may reply with a Server-Sent Events body (`Content-Type: text/event-stream`). The policy reads each event's `data:` JSON and applies the response `jsonPath` to it. Events the path does not match that carry no content, such as progress notifications, are left unchanged.

The policy runs on every message of the MCP proxy, not only `tools/call`. A JSON-RPC message that carries no content passes unchanged when the path does not match it:

- a request or notification of `initialize`, `ping`, `tools/list`, `prompts/list`, `resources/list`, `resources/templates/list`, `roots/list`, `logging/setLevel`, `resources/subscribe` or `resources/unsubscribe`, or any notification other than `notifications/message` and a `notifications/progress` that has a `message`;
- the result of one of those (an `initialize` result or a listing), or an empty result.

A JSON-RPC error response the path does not match is validated by its own text: the error's `message` and every string in its `data`. A clean error is delivered unchanged, PII in it is masked, and a violation is blocked.

Any other JSON-RPC message the path does not match, such as a `tools/call` whose arguments have another shape or a tool result without text content, is an extraction error: the response is refused with a fault, or, with `passthroughOnError: true`, delivered unassessed. The same rules apply to each event of an event stream; with `passthroughOnError: true` only the event the path misses goes unassessed, and the events it matches are still assessed. A body that is not JSON-RPC, a JSON-RPC batch, a path that selects a value that is not text (such as `null`), or an event stream with other JSON text that the path does not match, even beside events it does match, is also an extraction error.

**Note:**

Inside the `gateway/build.yaml`, ensure the policy module is added under `policies:`:

```yaml
- name: aws-bedrock-guardrail
  gomodule: github.com/wso2/gateway-controllers/policies/aws-bedrock-guardrail@v1
```

#### Streaming responses

A response flow on an LLM route can be streamed. With `stream: true`, the policy assesses the response a text unit at a time instead of holding it whole:

- Assistant text is read from each event with `streamingJsonPath` and collected into batches of `streamingTextUnitChars` characters, cut at a sentence or word boundary.
- Each batch is withheld until `ApplyGuardrail` has assessed it, so no unassessed text reaches the client. The exception is `passthroughOnError: true`: a batch whose assessment fails is released unassessed rather than stalling the stream. The first text therefore arrives after about one text unit has been generated and assessed; the rest of the response follows in batches.
- A violation found mid-stream cannot become HTTP `422`, because the `200` status and headers have already been sent. The stream ends with a final event carrying the guardrail error instead, and the termination is reported as a fault. Text delivered before the violating batch stays delivered. An API that must never deliver any text before the whole response is assessed should not stream.
- A response that is not an event stream (a JSON document or plain text) arriving over chunked transfer is withheld whole and assessed, with masked values restored, before any of it is delivered. A violation cannot become HTTP `422` here either: the `200` status and headers were sent when the response started, so the client receives `200` with the guardrail error JSON as the body, under the upstream's `Content-Type`, and the termination is reported as a fault. An event stream assessed whole (an empty `jsonPath`) gets the error as a final `data:` event instead, so an SSE client sees it. The same document sent with a `Content-Length` is buffered and answered with `422`. A body too large to withhold (over 4 MiB, or over the gateway's own 10 MB limit for an uncompressed JSON document) ends with a fault, or is delivered unassessed, with masked values restored, with `passthroughOnError: true`.
- A response with `Content-Type: text/event-stream` is read as an event stream, unless its body is a JSON document, which is read with `jsonPath`. Any other response is read event by event only if its first non-blank line is an SSE field or comment and it has a `data:` line; otherwise it is read with `jsonPath`. An SSE-looking line further into a plain-text answer does not make it an event stream.
- An event stream line whose text the policy cannot read ends the stream: text outside any event, or a `data:` payload that is neither JSON nor `[DONE]` (on a token stream, this includes an event whose JSON is split over several `data:` lines; an event stream of JSON-RPC messages joins those lines, as the SSE specification does, and reads the joined JSON). The stream ends with a fault. With `passthroughOnError: true` the line is delivered as it is, and the readable text around it is still assessed. Comments, blank lines, the `event`, `id` and `retry` fields, a leading byte order mark, and a field cut off in an unfinished last line are ignored. Any other line, including a field the SSE specification does not define, ends the stream. Comments and the values of `event` and `id` are delivered without being assessed. On a token stream, lines must end in `\n` or `\r\n`; a token stream that ends lines with a bare `\r` ends with a fault. An event stream of JSON-RPC messages accepts `\n`, `\r\n` and `\r`, in any mix.
- An event stream of JSON-RPC messages (an MCP or A2A response on a streamed route) is assessed one complete event at a time with `jsonPath`, as it is on the buffered path. An event is withheld until it is complete; one still incomplete after 256 KiB ends the stream with a fault. With `passthroughOnError: true` that event is delivered unassessed, while the complete events before it are still assessed.
- `streamingJsonPath` must describe the stream. If no event of a streamed response carries the member it starts with (for example a provider's own format under the default `$.choices[0].delta.content`), the stream ends with a fault rather than being delivered unassessed. Events before the first one that carries it are withheld until it arrives. Set `streamingJsonPath` for the provider's format, or place `openai-to-bedrock-transformer` (or another transformer that emits the OpenAI format) ahead of the guardrail.
- Model output in an event that `streamingJsonPath` does not read ends the stream with a fault rather than being delivered unassessed: a tool call's name and arguments (`delta.tool_calls`), reasoning or refusal text beside `delta.content`, a second choice in the same event, or a legacy completion's `choices[].text` under the default chat path. Events that carry no output, such as the opening role delta, the finishing delta, a usage frame or a content filter verdict, are delivered as usual. Any output in an event without the member `streamingJsonPath` starts with is refused the same way, and so is everything beneath a wildcard: `streamingJsonPath` must select a single value, such as `$.choices[0].delta.content`. On the buffered path the same stream is answered with `422`. The default paths do not read tool calls in either mode: a non-streamed tool-calling answer with `"content": null` is an extraction error under the default `jsonPath`. Set `streamingJsonPath` (token streams) or `jsonPath` (non-streamed JSON) for the field to be assessed, for example `$.choices[0].text` for the legacy completions API, or use `passthroughOnError: true` to deliver such responses unassessed.
- PII that the guardrail reports is masked even when the model emits it over several events: the replacement goes into the event where the value starts, and the rest of the value is removed from the events after it.

Only an attachment whose response flow is enabled takes part in streaming. A request-only attachment does not hold the response back, and an attachment with neither flow enabled is skipped entirely.

When another policy on the route requires the whole response body, the gateway buffers the route and a streamed response reaches this policy whole. It is still read event by event with `streamingJsonPath`, and is assessed and delivered as a whole.

Place this policy before `openai-to-bedrock-transformer` in the policy list. Response policies run in reverse order, so the transformer has already turned Bedrock's event stream into OpenAI Server-Sent Events by the time this policy reads it.

Known limitation: in masking mode, a request placeholder such as `EMAIL_0000` is restored one event at a time. When the model splits a placeholder across two events, it can reach the client as the placeholder rather than the original value. Non-streamed responses are not affected.

## Reference Scenarios

### Example 1: Gateway defaults

Every guardrail setting comes from `config.toml`.

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

### Example 8: MCP route

Validates every tool argument and every text item of tool results, including Server-Sent Events responses:

```yaml
apiVersion: gateway.api-platform.wso2.com/v1
kind: Mcp
metadata:
  name: guarded-mcp
spec:
  displayName: Guarded MCP
  version: v1.0
  context: /guarded-mcp
  specVersion: "2025-06-18"
  upstream:
    url: http://mcp-server:8080/mcp
  policies:
    - name: aws-bedrock-guardrail
      version: v1
      params:
        awsAuth:
          authenticationType: system
        request:
          jsonPath: "$.params.arguments"
        response:
          enabled: true
          jsonPath: "$.result.content[*].text"
```

A tool call or tool result that triggers a blocking guardrail policy returns HTTP `422`. PII that the guardrail anonymizes in a tool result is replaced with its type in braces, such as `{EMAIL}`.

The policy applies to every message on the route, not only `tools/call`. Messages such as `initialize`, `tools/list` and notifications have no `params.arguments` or tool result text, so they have nothing to validate and pass unchanged, without a Bedrock call. See [MCP routes](#mcp-routes).

Gateway compatibility: use gateway 1.2.0 or later on MCP routes whose server answers with Server-Sent Events. On gateway 1.1.0 such a response returns HTTP `500` with an empty body when response validation is enabled, because that gateway processes MCP responses as buffered while running the streaming handler. JSON responses are not affected.

### Example 9: Validating only successful responses

An error response from the LLM provider, such as an expired credential or an invalid model, carries the provider's error rather than generated content. Setting `applicableStatusCodes` limits response validation to the listed upstream status codes, so the provider's error reaches the client unchanged:

```yaml
        params:
          awsAuth:
            authenticationType: system
          request:
            jsonPath: "$.messages[-1].content"
          response:
            enabled: true
            jsonPath: "$.choices[0].message.content"
            applicableStatusCodes: "200-299"
```

With this configuration, an upstream `403` is returned to the client as is, while a `200` response is validated through the guardrail. Single codes and ranges can be combined, for example `"200-299,422"`.

## How It Works

#### Request Phase

1. **Content extraction**: Extracts content using `jsonPath`, or uses the entire payload.
2. **Guardrail evaluation**: Calls `ApplyGuardrail` once with every extracted string, using the effective region, guardrail ID, and version, and the identity resolved from `awsAuth` or the gateway-wide settings.
3. **Violation handling**: Blocks and returns HTTP `422` when any finding has the action `BLOCKED`, such as a prompt attack, denied topic, blocked word, or a PII type configured to block. This applies even when PII was also found.
4. **PII processing**: When every finding is `ANONYMIZED`, masks PII. With `redactPII: false`, masks PII with placeholders for later restoration. With `redactPII: true`, replaces PII with `*****` permanently.
5. **Error Strategy**: Applies `passthroughOnError` behavior to decide whether to fail closed or allow traffic on Bedrock API failures.

#### Response Phase

1. **Status check**: When `applicableStatusCodes` is set, a response whose upstream status code is not listed is passed through unchanged and the remaining steps are skipped. A response with an unknown status code is always validated.
2. **PII restoration**: In masking mode, restores the request's placeholders with the original values when mappings are available from request metadata. The restored text is what the guardrail assesses, because it is what the client receives.
3. **Content extraction**: Extracts content using `jsonPath` from a JSON body or from each event of an MCP Server-Sent Events body, using `streamingJsonPath` for a streamed LLM response, or uses the entire payload.
4. **Guardrail evaluation**: Validates the response content through the guardrail.
5. **Violation handling**: Blocks and returns HTTP `422` (or ends a stream) when any finding has the action `BLOCKED`.
6. **PII masking**: PII that the guardrail anonymizes in the response is replaced with its type in braces, such as `{EMAIL}` (or `*****` with `redactPII: true`). This covers PII that the upstream adds, such as an LLM answer or an MCP tool result. A value the request masked and this phase restored, or part of one, is not masked again.
7. **Error Strategy**: Applies `passthroughOnError` behavior for extraction errors and Bedrock API failures.

#### Credential resolution

The credentials provider is built **once**, when the policy attachment is created, and reused across requests. Role assumption therefore happens on first use and on refresh near expiry, not on every request. A configuration that cannot be used at all, such as a missing role ARN or a missing IRSA environment, rejects the attachment at deploy time. A role that cannot be assumed is only found on the first `ApplyGuardrail` call, because the role is assumed then: that request fails as a guardrail error and follows `passthroughOnError`.

#### PII Handling Modes

- **Masking mode (`redactPII: false`)**: In the request, PII entities are replaced with placeholders such as `EMAIL_0001`, `PHONE_0002`, restorable in the response phase. In the response, new PII is replaced with its type, such as `{EMAIL}`, and is not restored. A value the request masked is restored, not replaced with its type.
- **Redaction mode (`redactPII: true`)**: PII entities are permanently replaced with `*****`.

## Notes

- The guardrail must exist in Amazon Bedrock before use, in the region the attachment selects. Cross-region calls are not supported: a guardrail in `eu-west-1` is not reachable from a `us-east-1` client.
- Guardrail version `DRAFT` is useful for testing. Use numbered versions for production.
- The IAM identity used must have `bedrock:ApplyGuardrail` on the target guardrail.
- PII masking with restoration stores the mapping between original and masked values in request metadata.
- Content modifications (PII masking) are forwarded upstream if no blocking violation occurs.
- Request and response phases are validated independently when both are configured.
- A guardrail intervention is masked only when every finding is `ANONYMIZED`. Any `BLOCKED` finding blocks the content, and an intervention with no finding the policy can identify, or an `ANONYMIZED` finding with no matched text to mask, is blocked.
- Keep `showAssessment` set to `false` in production. The assessment tells the caller which filter matched, which helps an attacker tune a bypass.
- Credential material is never written to logs. The session name, not the credentials, is what identifies the gateway in the target account's CloudTrail.

## Fault reporting

From v1.4 (and in v1.5), every rejection this policy makes is also reported to the gateway as a **fault**:
a stable code and type alongside the response. A gateway that supports fault policies uses it
for the analytics event and hands it to the API's fault policies (for example `log-message`, to
log the failure). The status and body the client receives are the same as in v1.3. A gateway
without fault policy support ignores the fault, and the policy behaves exactly as v1.3.

A guardrail verdict has type `guardrail` and a code from the guardrail block (`906000`–`906399`).
It also names the intervening guardrail (`aws-bedrock-guardrail`) and records that it intervened; the
assessment is attached only when `showAssessment` is enabled, because it can hold the blocked content.
A rejection made because the policy could not run its check is not a verdict and carries no
guardrail details: a request body that cannot be read is reported as `960001` (`validation`),
because it is the caller's, and every other such failure as `960000` (`mediation`).

The response phase only rejects responses that it validates: when `applicableStatusCodes` is set,
a response whose upstream status is not listed passes through without a fault. With
`passthroughOnError` enabled, the errors in the last three rows pass the request or response through
instead of rejecting it, and no fault is reported. An intervention whose findings are all
`ANONYMIZED` is masked or redacted rather than rejected, so it produces no fault. A PII finding
with the action `BLOCKED` is rejected, and reported with the PII code.

| When | Status | Code | Type |
|------|--------|------|------|
| Request or response: Bedrock intervenes because of the hate content filter | `422` | `906001` | `guardrail` |
| Request or response: Bedrock intervenes because of the sexual content filter | `422` | `906002` | `guardrail` |
| Request or response: Bedrock intervenes because of the violence content filter | `422` | `906004` | `guardrail` |
| Request or response: Bedrock intervenes because of the insults content filter | `422` | `906005` | `guardrail` |
| Request or response: Bedrock intervenes because of the misconduct content filter | `422` | `906006` | `guardrail` |
| Request or response: Bedrock intervenes because of the prompt attack filter | `422` | `906008` | `guardrail` |
| Request or response: Bedrock intervenes because of a word filter (custom words or a managed word list) | `422` | `906007` | `guardrail` |
| Request or response: Bedrock intervenes because of a denied topic | `422` | `906301` | `guardrail` |
| Request or response: Bedrock intervenes because of a sensitive information (PII or regex) finding that is `BLOCKED` | `422` | `906101` | `guardrail` |
| Request or response: Bedrock intervenes for any other reason | `422` | `906099` | `guardrail` |
| Request: the value at `jsonPath` cannot be extracted | `422` | `960001` | `validation` |
| Response: the value at `jsonPath` cannot be extracted | `422` | `960000` | `mediation` |
| Request or response: the AWS configuration cannot be loaded, the Bedrock call fails, or Bedrock returns an invalid or unexpected response | `422` | `960000` | `mediation` |

When Bedrock reports more than one finding, a sensitive information (PII) finding decides the code
first, then a content filter, then a word filter, then a denied topic. A blocked content filter that
comes with a PII finding is therefore reported with the PII code.
For content filters, the first recognized filter in assessment order decides the code, regardless
of its action. The code can name a non-blocking filter rather than the filter that caused the rejection.

The fault's `Description` carries the internal reason, for example
`Violation of AWS Bedrock Guardrails detected` or `Error calling AWS Bedrock Guardrail`.
It is passed to fault policies and analytics only, never to the client.
