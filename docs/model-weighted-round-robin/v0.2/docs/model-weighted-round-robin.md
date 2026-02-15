---
title: "Overview"
---
# Model Weighted Round Robin

## Overview

The Model Weighted Round Robin policy implements weighted round-robin load balancing for AI models. It distributes requests based on predefined weight values assigned to each model, enabling probabilistic control over request distribution and giving higher priority to models with greater processing power or availability. This policy is useful for distributing load proportionally across models based on their capacity, cost, or performance characteristics.

## Features

- Weighted distribution of requests across multiple models based on assigned weights
- Proportional request allocation (models with higher weights receive more requests)
- Automatic model suspension on failures (5xx or 429 responses)
- Configurable suspension duration for failed models
- Support for extracting model identifier from payload, headers, query parameters, or path parameters
- Dynamic model selection based on availability and weights

## Configuration

This policy requires configuration in both the API definition YAML and the LLM provider template.

### User Parameters (API Definition)

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `models` | `WeightedModel` array | Yes | - | List of models with weights for weighted round-robin distribution. Each model must have a `model` name and `weight`. |
| `suspendDuration` | integer | No | `0` | Suspend duration in seconds for failed models. If set to 0, failed model knowledge is not persisted. Must be >= 0. |

### WeightedModel Configuration

Each model in the `models` array is an object with the following properties:

| Property | Type | Required | Description |
|----------|------|----------|-------------|
| `model` | string | Yes | The AI model name to use for load balancing. |
| `weight` | integer | Yes | The weight assigned to this model for distribution. Higher weights mean more requests will be routed to this model. Weight is relative to total weight of all models. Must be at least 1. |

#### LLM provider template

This policy depends on the `requestModel` configuration defined in the LLM provider template to identify and extract the model from incoming requests.

> **Required:** The `requestModel` configuration must be provided; the policy will not function without it.

### `requestModel` Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `requestModel.location` | string | Yes | Location of the model identifier: `payload`, `header`, `queryParam`, or `pathParam` |
| `requestModel.identifier` | string | Yes | JSONPath (for payload), header name (for header), query param name (for queryParam), or regex pattern (for pathParam) to extract model |

**Note:**

Inside the `gateway/build.yaml`, ensure the policy module is added under `policies:`:

```yaml
- name: model-weighted-round-robin
  gomodule: github.com/wso2/gateway-controllers/policies/model-weighted-round-robin@v0
```

## Reference Scenarios

### Example 1: Basic Weighted Round Robin with Payload-based Model

Deploy an LLM provider with weighted round-robin load balancing:

```yaml
apiVersion: gateway.api-platform.wso2.com/v1alpha1
kind: LlmProvider
metadata:
  name: weighted-round-robin-provider
spec:
  displayName: Weighted Round Robin Provider
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
  policies:
    - name: model-weighted-round-robin
      version: v0
      paths:
        - path: /chat/completions
          methods: [POST]
          params:
            models:
              - model: gpt-4
                weight: 3
              - model: gpt-3.5-turbo
                weight: 2
              - model: gpt-4-turbo
                weight: 1
            suspendDuration: 60
```

**Test the weighted round-robin distribution:**

**Note**: Ensure that "openai" is mapped to the appropriate IP address (e.g., 127.0.0.1) in your `/etc/hosts` file, or remove the vhost from the LLM provider configuration and use localhost to invoke.

```bash
# Requests will be distributed: 50% gpt-4, 33.3% gpt-3.5-turbo, 16.7% gpt-4-turbo
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

## How It Works

#### Model Selection

On each request, the policy selects the next available model in a weighted cyclic sequence.
- **Weight Calculation**: During initialization, the policy computes total weight and builds a weighted sequence where each model appears proportional to its configured weight.
- **Model Extraction**: The policy extracts the original model from the request (if configured) and stores it for reference.
- **Model Modification**: The policy modifies the request to use the selected model based on the `requestModel` configuration.

#### Request Model Locations

The policy supports extracting the model identifier from different locations in the request:

**Payload (JSONPath)**: Extract model from JSON payload using JSONPath:
- **Location**: `payload`
- **Identifier**: JSONPath expression (e.g., `$.model`, `$.messages[0].model`)

**Header**: Extract model from HTTP header:
- **Location**: `header`
- **Identifier**: Header name (e.g., `X-Model-Name`, `X-LLM-Model`)

**Query Parameter**: Extract model from URL query parameter:
- **Location**: `queryParam`
- **Identifier**: Query parameter name (e.g., `model`, `llm_model`)

**Path Parameter**: Extract model from URL path using regex:
- **Location**: `pathParam`
- **Identifier**: Regex pattern to match model in path (e.g., `models/([a-zA-Z0-9.\-]+)`)

#### Model Suspension

When a model returns a 5xx or 429 response, the policy can automatically suspend that model for a configurable duration:

- **Suspension Duration**: Configured via the `suspendDuration` parameter (in seconds)
- **Automatic Recovery**: Suspended models are automatically re-enabled after the suspension period expires
- **Availability Check**: Suspended models are skipped during weighted round-robin selection until they recover
- **Weight Preservation**: When a model is suspended, the remaining models continue to be selected based on their relative weights

#### Suspension Behavior

- Suspension is tracked per model across all requests
- If all models are suspended, the policy returns HTTP 503 with error: "All models are currently unavailable"
- Suspension period starts from the time of failure
- When a model is suspended, the weighted sequence is dynamically adjusted to exclude that model

#### Weight Calculation

The policy builds a weighted sequence by repeating each model a number of times equal to its weight:

- **Total Weight**: Sum of all model weights
- **Sequence Length**: Equal to the total weight
- **Distribution**: Each model appears in the sequence `weight` times
- **Proportional Selection**: Over time, each model receives requests proportional to `model_weight / total_weight`



## Notes

- For path parameters, the regex pattern should include a capturing group to extract the model name. The policy uses the first capturing group as the model identifier.
- This capability distributes requests proportionally across multiple models to balance capacity, cost, performance tiers, and migration rollout needs.
- The weighted sequence is pre-computed once during policy initialization and reused for all requests. It is not rebuilt on each request.
- The round-robin index is maintained per policy instance and increments for each request.
- Model selection follows the weighted sequence in a deterministic cyclic pattern.
- The original model from the request is stored in metadata but is replaced with the selected model for routing.
- If `suspendDuration` is 0, failed models are not suspended and will continue to be selected in the weighted round-robin cycle.
- Higher weights result in more frequent selection but do not guarantee exact proportional distribution in small request volumes.
- The weighted sequence ensures long-term proportional distribution, but short-term distribution may vary due to suspension and availability.
- The `requestModel` configuration is required and must be provided by the LLM provider template. There is no default behavior.
