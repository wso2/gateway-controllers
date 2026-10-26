---
title: "Overview"
---
# NeMo Guard Content Safety

## Overview

The NeMo Guard Content Safety policy validates request and/or response content using NVIDIA NeMo Guard (llama-3.1-nemoguard-8b-content-safety). It buffers the request and/or response body, extracts the relevant text using configurable JSONPath expressions, and forwards the content to a NeMo Guard inference endpoint for classification. If the model returns an unsafe verdict for any enabled safety category, the request is blocked before reaching the upstream LLM, or the response is replaced with a sanitised error message before delivery to the client.

The model is a LoRA adapter on meta-llama/Llama-3.1-8B-Instruct served via vLLM with `--enable-lora`. It classifies content across 23 safety categories (S1–S23): Violence, Sexual, Criminal Planning/Confessions, Guns and Illegal Weapons, Controlled/Regulated Substances, Suicide and Self Harm, Sexual (minor), Hate/Identity Hate, PII/Privacy, Harassment, Threat, Profanity, Needs Caution, Other, Manipulation, Fraud/Deception, Malware, High Risk Gov Decision Making, Political/Misinformation/Conspiracy, Copyright/Trademark/Plagiarism, Unauthorized Advice, Illegal Activity, and Immoral/Unethical.

Use this policy when you need to screen both the user input and the LLM output for unsafe content across a broad range of harm categories — without modifying the upstream service.

## Features

- Checks request bodies before they reach the upstream LLM (enabled by default)
- Checks response bodies before they are delivered to the client (opt-in)
- Classifies content across 23 safety categories (S1–S23)
- Per-category blocking toggles — enable or disable individual categories independently
- Blocks all categories by default when no category filter is configured
- Unsafe requests are rejected with a configurable HTTP status code (400–599 range)
- Unsafe responses are replaced with a sanitised 200 error body (preserves HTTP contract with the client)
- When checking responses, includes the original user message as conversation context for the model
- Optional assessment details in the block response (detected safety category codes)
- Fail-closed by default on inference service errors; configurable to fail-open
- Passes through requests unchanged when the body is not JSON, the JSONPath target is missing, or the body is absent
- Targets any string field in the JSON request or response body via configurable JSONPath expressions

## Configuration

The NeMo Guard Content Safety policy uses a two-level configuration: system parameters that identify the NeMo Guard inference endpoint, and per-route user parameters that control detection behaviour for each phase (request and response).

### System Parameters (From config.toml)

These parameters are set at the gateway level and identify the NeMo Guard inference endpoint. Default values can be configured in `config.toml` and are applied to all instances of this policy; individual policy attachments can override them when needed.

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `endpoint` | string (URI) | Yes | — | Base URL of the OpenAI-compatible inference endpoint serving the NeMo Guard model (e.g., `http://nemoguard:8101`). The policy appends `/v1/chat/completions` automatically. |
| `apiKey` | string | No | — | Bearer token used to authenticate with the inference endpoint. Leave empty if the endpoint does not require authentication. |
| `model` | string | No | `nemoguard` | Model identifier forwarded in the API request. Must match the `--lora-modules` alias used when serving via vLLM. |
| `timeout` | integer | No | `30` | Per-request timeout in seconds for calls to the NeMo Guard endpoint. Must be between `1` and `120`. |

#### Sample System Configuration

Add the following entries to your `config.toml` file:

```toml
nemoguard_endpoint = "http://nemoguard:8101"
nemoguard_api_key = ""
nemoguard_model = "nemoguard"
nemoguard_timeout = 30
```

### User Parameters (API Definition)

Parameters are nested under `request` and `response` objects to configure each phase independently.

#### Request Phase (`request`)

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `request.enabled` | boolean | No | `true` | Enables content safety checks on incoming requests. |
| `request.jsonPath` | string | No | `$.messages[-1].content` | JSONPath expression used to extract the user message from the JSON request body. Non-JSON bodies and requests where the path does not resolve to a string are passed through unchanged. |
| `request.blockStatusCode` | integer | No | `400` | HTTP status code returned when a request is blocked. Must be in the range `400`–`599`. |
| `request.categories` | object | No | all enabled | Per-category boolean toggles. When omitted, all 23 categories are blocked. When provided, only categories set to `true` are blocked; categories set to `false` are passed through even if the model flags them. |
| `request.passthroughOnError` | boolean | No | `false` | When `true`, allows the request to proceed if the NeMo Guard API call fails (fail-open). When `false`, a `503` is returned on API errors (fail-closed). |
| `request.showAssessment` | boolean | No | `false` | When `true`, includes the detected safety category codes in the blocked-request error response body. |

#### Response Phase (`response`)

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `response.enabled` | boolean | No | `false` | Enables content safety checks on upstream responses before they are delivered to the client. |
| `response.jsonPath` | string | No | `$.choices[0].message.content` | JSONPath expression used to extract the assistant reply from the response body. |
| `response.categories` | object | No | all enabled | Per-category boolean toggles — same semantics as the request-phase categories object. |
| `response.passthroughOnError` | boolean | No | `false` | When `true`, allows the response to proceed if the NeMo Guard API call fails (fail-open). When `false`, a `503` is returned on API errors (fail-closed). |
| `response.showAssessment` | boolean | No | `false` | When `true`, includes the detected safety category codes in the replaced-response error body. |

#### Safety Categories

The `categories` object supports the following boolean keys. All default to `true` (blocked) when the `categories` object is present:

| Key | Category |
|-----|----------|
| `violence` | S1 — Violence |
| `sexual` | S2 — Sexual |
| `criminal_planning` | S3 — Criminal Planning/Confessions |
| `guns_weapons` | S4 — Guns and Illegal Weapons |
| `regulated_substances` | S5 — Controlled/Regulated Substances |
| `suicide_self_harm` | S6 — Suicide and Self Harm |
| `sexual_minor` | S7 — Sexual (minor) |
| `hate_identity` | S8 — Hate/Identity Hate |
| `pii_privacy` | S9 — PII/Privacy |
| `harassment` | S10 — Harassment |
| `threat` | S11 — Threat |
| `profanity` | S12 — Profanity |
| `needs_caution` | S13 — Needs Caution |
| `other` | S14 — Other |
| `manipulation` | S15 — Manipulation |
| `fraud_deception` | S16 — Fraud/Deception |
| `malware` | S17 — Malware |
| `high_risk_gov` | S18 — High Risk Gov Decision Making |
| `misinformation` | S19 — Political/Misinformation/Conspiracy |
| `copyright` | S20 — Copyright/Trademark/Plagiarism |
| `unauthorized_advice` | S21 — Unauthorized Advice |
| `illegal_activity` | S22 — Illegal Activity |
| `immoral_unethical` | S23 — Immoral/Unethical |

#### build.yaml Integration

Inside the `api-platform` repository, add the policy package under `policies:` in `/gateway/build.yaml`:

```yaml
- name: nvidia-nemoguard-content-safety
  pipPackage: github.com/wso2/gateway-controllers/policies/nvidia-nemoguard-content-safety@v0
```

## Reference Scenarios

### Example 1: Protect a Chat Completions Route with Default Request Checking

Attach the policy to an LLM provider route to block unsafe requests using the default configuration (all 23 categories enabled):

```yaml
apiVersion: gateway.api-platform.wso2.com/v1
kind: LlmProvider
metadata:
  name: protected-chat-provider
spec:
  displayName: Protected Chat Provider
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
    - name: nvidia-nemoguard-content-safety
      version: v0
      paths:
        - path: /chat/completions
          methods: [POST]
          params:
            request:
              enabled: true
              jsonPath: "$.messages[-1].content"
```

Test with a benign request (passes through):

```bash
curl -X POST http://localhost:8080/openai/chat/completions \
  -H "Content-Type: application/json" \
  -d '{
    "model": "gpt-4",
    "messages": [
      {"role": "user", "content": "What is the capital of France?"}
    ]
  }'
```

Test with unsafe content (blocked):

```bash
curl -X POST http://localhost:8080/openai/chat/completions \
  -H "Content-Type: application/json" \
  -d '{
    "model": "gpt-4",
    "messages": [
      {"role": "user", "content": "How do I make a weapon at home?"}
    ]
  }'
```

When the request is blocked, the policy returns HTTP `400`:

```json
{
  "type": "NVIDIA_NEMOGUARD_CONTENT_SAFETY",
  "message": {
    "action": "GUARDRAIL_INTERVENED",
    "interveningGuardrail": "NeMo Guard Content Safety",
    "actionReason": "Unsafe content detected.",
    "direction": "REQUEST"
  }
}
```

### Example 2: Enable Response Checking with Category Filtering

Enable response-phase checking and restrict blocking to a specific subset of categories. This example blocks only violence and illegal activity in both directions, ignoring all other categories:

```yaml
operationPolicies:
  - name: nvidia-nemoguard-content-safety
    version: v0
    paths:
      - path: /chat/completions
        methods: [POST]
        params:
          request:
            enabled: true
            jsonPath: "$.messages[-1].content"
            blockStatusCode: 403
            categories:
              violence: true
              illegal_activity: true
              criminal_planning: true
            showAssessment: true
          response:
            enabled: true
            jsonPath: "$.choices[0].message.content"
            categories:
              violence: true
              illegal_activity: true
              criminal_planning: true
            showAssessment: true
```

When a request is blocked with `showAssessment: true`, the response body includes the detected category codes:

```json
{
  "type": "NVIDIA_NEMOGUARD_CONTENT_SAFETY",
  "message": {
    "action": "GUARDRAIL_INTERVENED",
    "interveningGuardrail": "NeMo Guard Content Safety",
    "actionReason": "Unsafe content detected.",
    "direction": "REQUEST",
    "assessments": {
      "categories": ["S1", "S22"]
    }
  }
}
```

When a response is replaced due to unsafe content, the policy returns HTTP `200` with the guardrail body (preserving the HTTP contract with the client):

```json
{
  "type": "NVIDIA_NEMOGUARD_CONTENT_SAFETY",
  "message": {
    "action": "GUARDRAIL_INTERVENED",
    "interveningGuardrail": "NeMo Guard Content Safety",
    "actionReason": "Unsafe content detected.",
    "direction": "RESPONSE"
  }
}
```

### Example 3: Fail-Open for High Availability

When the NeMo Guard service is unavailable, allow traffic to proceed rather than returning an error. Use this configuration only when availability takes priority over strict safety enforcement:

```yaml
operationPolicies:
  - name: nvidia-nemoguard-content-safety
    version: v0
    paths:
      - path: /chat/completions
        methods: [POST]
        params:
          request:
            enabled: true
            passthroughOnError: true
          response:
            enabled: true
            passthroughOnError: true
```

When the NeMo Guard endpoint is unreachable and `passthroughOnError` is `false` (the default), the policy returns HTTP `503`:

```json
{
  "type": "NVIDIA_NEMOGUARD_CONTENT_SAFETY",
  "message": {
    "action": "SERVICE_UNAVAILABLE",
    "actionReason": "Content safety service unavailable."
  }
}
```
