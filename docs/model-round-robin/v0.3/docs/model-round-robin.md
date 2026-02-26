---
title: "Overview"
---
# Model Round Robin

## Overview

The Model Round Robin policy distributes requests across configured models in cyclic order. It helps spread load evenly and can temporarily suspend failed models to reduce repeated failures.

## Features

- Cyclic model selection across configured model list
- Optional failed-model suspension with configurable duration
- Support for model extraction/rewrite via provider `requestModel` configuration
- Automatic skip of currently suspended models

## Configuration

This policy requires configuration in both the API definition and LLM provider template.

### User Parameters (API Definition)

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `models` | `Model[]` | Yes | - | List of models used for round-robin distribution. |
| `suspendDuration` | integer | No | `0` | Suspension duration in seconds for failed models (`5xx`/`429`). `0` disables persisted suspension. |

#### Model Configuration

| Property | Type | Required | Description |
|----------|------|----------|-------------|
| `model` | string | Yes | Model identifier used for selection and request rewrite. |

### LLM Provider Template Requirement

This policy depends on `requestModel` configuration in the provider template.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `requestModel.location` | string | Yes | Where model is extracted from: `payload`, `header`, `queryParam`, `pathParam`. |
| `requestModel.identifier` | string | Yes | Extraction key (JSONPath/header/query key/regex pattern by location). |

**Note:**

Inside `gateway/build.yaml`, ensure the policy module is added under `policies`:

```yaml
- name: model-round-robin
  gomodule: github.com/wso2/gateway-controllers/policies/model-round-robin@v0
```

## Reference Scenarios

### Example 1: Basic Round Robin

```yaml
policies:
  - name: model-round-robin
    version: v0
    paths:
      - path: /chat/completions
        methods: [POST]
        params:
          models:
            - model: gpt-4o
            - model: gpt-4o-mini
            - model: gpt-4.1
          suspendDuration: 60
```

## How It Works

1. Selects next available model from configured list in round-robin order.
2. Rewrites request model value based on template `requestModel` location.
3. Tracks upstream failures (`429`/`5xx`) and suspends failed models when configured.
4. Returns `503` when all configured models are currently unavailable.

## Notes

- `suspendDuration` is optional; use `0` when suspension tracking is not needed.
- Model extraction and rewrite behavior depend on valid template `requestModel` configuration.
- Path-based model extraction should use a regex with a capture group for model value.
