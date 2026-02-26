---
title: "Overview"
---
# Azure Content Safety

## Overview

The Azure Content Safety guardrail validates request and/or response content using Azure Content Safety text moderation. It evaluates hate, sexual, self-harm, and violence categories against configurable severity thresholds.

## Features

- Request-phase and response-phase moderation (configure either or both)
- Per-category severity threshold control (`-1` to `7`)
- Optional JSONPath extraction of target content
- Optional passthrough on external API errors
- Optional detailed assessment data in blocked responses

## Configuration

This policy uses a two-level configuration model.

### System Parameters (From config.toml)

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `azureContentSafetyEndpoint` | string | Yes | Azure Content Safety endpoint URL (without trailing slash). |
| `azureContentSafetyKey` | string | Yes | Azure Content Safety API subscription key. |

#### Sample System Configuration

```toml
azurecontentsafety_endpoint = "https://your-resource.cognitiveservices.azure.com"
azurecontentsafety_key = "<your-azure-content-safety-key>"
```

### User Parameters (API Definition)

At least one of `request` or `response` is required.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `request` | `AzureContentSafetyConfig` | Conditional | Request content moderation configuration. |
| `response` | `AzureContentSafetyConfig` | Conditional | Response content moderation configuration. |

#### AzureContentSafetyConfig Configuration

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `jsonPath` | string | No | `""` | JSONPath to extract content. If empty, full payload text is analyzed. |
| `passthroughOnError` | boolean | No | `false` | If true, allows traffic when Azure API call fails. |
| `showAssessment` | boolean | No | `false` | If true, include detailed moderation assessment in blocked response. |
| `hateSeverityThreshold` | integer | No | `4` | Hate category threshold (`-1` disables category). |
| `sexualSeverityThreshold` | integer | No | `5` | Sexual category threshold (`-1` disables category). |
| `selfHarmSeverityThreshold` | integer | No | `3` | Self-harm category threshold (`-1` disables category). |
| `violenceSeverityThreshold` | integer | No | `4` | Violence category threshold (`-1` disables category). |

**Note:**

Inside `gateway/build.yaml`, ensure the policy module is added under `policies`:

```yaml
- name: azure-content-safety-content-moderation
  gomodule: github.com/wso2/gateway-controllers/policies/azure-content-safety-content-moderation@v0
```

## Reference Scenarios

### Example 1: Request and Response Moderation

```yaml
policies:
  - name: azure-content-safety-content-moderation
    version: v0
    paths:
      - path: /chat/completions
        methods: [POST]
        params:
          request:
            jsonPath: "$.messages[-1].content"
            hateSeverityThreshold: 2
            sexualSeverityThreshold: 2
            selfHarmSeverityThreshold: 2
            violenceSeverityThreshold: 2
            showAssessment: true
          response:
            jsonPath: "$.choices[0].message.content"
            hateSeverityThreshold: 2
            sexualSeverityThreshold: 2
            selfHarmSeverityThreshold: 2
            violenceSeverityThreshold: 2
            showAssessment: true
```

### Example 2: Request-Only with Selective Categories

```yaml
policies:
  - name: azure-content-safety-content-moderation
    version: v0
    paths:
      - path: /chat/completions
        methods: [POST]
        params:
          request:
            jsonPath: "$.messages[-1].content"
            hateSeverityThreshold: 3
            sexualSeverityThreshold: -1
            selfHarmSeverityThreshold: 2
            violenceSeverityThreshold: -1
            passthroughOnError: false
```

## How It Works

#### Request/Response Phase

1. Extracts text using configured `jsonPath` (or full payload when empty).
2. Builds enabled category set from thresholds where value is `0..7`.
3. Calls Azure Content Safety API and receives category severities.
4. Blocks when any category severity is greater than or equal to configured threshold.
5. Applies `passthroughOnError` for extraction/API failures.

## Notes

- Threshold `-1` disables that category for evaluation.
- If all categories are disabled, validation is skipped.
- Blocked responses use `HTTP 422` with guardrail response type.
- Keep endpoint format as base resource URL without trailing slash.
