---
title: "Overview"
---
# Model Round Robin

## Overview

The Model Round Robin policy implements round-robin load balancing for AI models. It distributes requests evenly across multiple configured AI models in a cyclic manner, ensuring equal request allocation over time and preventing overloading of any single model. This policy is useful for distributing load across multiple models, improving availability, and managing resource utilization.

## Features

- Even distribution of requests across multiple models in a cyclic pattern
- Automatic model suspension on failures (5xx or 429 responses)
- Configurable suspension duration for failed models
- Support for extracting model identifier from payload, headers, query parameters, or path parameters
- Dynamic model selection based on availability

## Configuration

This policy requires configuration in both the API definition YAML and the LLM provider template.

### User Parameters (API Definition)

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `models` | ```Model``` array | Yes | - | List of models for round-robin distribution. Each model must have a `model` name. |
| `suspendDuration` | integer | No | `0` | Suspend duration in seconds for failed models. If set to 0, failed model knowledge is not persisted. Must be >= 0. |

### Model Configuration

Each model in the `models` array is an object with the following properties:

| Property | Type | Required | Description |
|----------|------|----------|-------------|
| `model` | string | Yes | The AI model name to use for load balancing. |


#### LLM provider template

This policy depends on the `requestModel` configuration defined in the LLM provider template to identify and extract the model from incoming requests.

> **Required:** The `requestModel` configuration must be provided; the policy will not function without it.

### `requestModel` Parameters

| Parameter                 | Type   | Required | Description                                                                                                                                                                                              |
| ------------------------- | ------ | -------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `requestModel.location`   | string | Yes      | Specifies where the model identifier is located in the request. Supported values: `payload`, `header`, `queryParam`, `pathParam`.                                                                        |
| `requestModel.identifier` | string | Yes      | Extraction key used to identify the model. This can be a JSONPath expression (for `payload`), header name (for `header`), query parameter name (for `queryParam`), or a regex pattern (for `pathParam`). |


**Note:**

Inside the `gateway/build.yaml`, ensure the policy module is added under `policies:`:

```yaml
- name: model-round-robin
  gomodule: github.com/wso2/gateway-controllers/policies/model-round-robin@v0
```

## Reference Scenarios

### Example 1: Basic Round Robin with Payload-based Model

Deploy an LLM provider with round-robin load balancing across multiple models:

```yaml
apiVersion: gateway.api-platform.wso2.com/v1alpha1
kind: LlmProvider
metadata:
  name: round-robin-provider
spec:
  displayName: Round Robin Provider
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
    - name: model-round-robin
      version: v0
      paths:
        - path: /chat/completions
          methods: [POST]
          params:
            models:
              - model: gpt-4
              - model: gpt-3.5-turbo
              - model: gpt-4-turbo
            suspendDuration: 60
```

**Test the round-robin distribution:**

**Note**: Ensure that "openai" is mapped to the appropriate IP address (e.g., 127.0.0.1) in your `/etc/hosts` file, or remove the vhost from the LLM provider configuration and use localhost to invoke.

```bash
# First request - will use gpt-4
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

# Second request - will use gpt-3.5-turbo
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

# Third request - will use gpt-4-turbo
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
On each request, the policy selects the next available model in the configured list using a round-robin algorithm.
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
- **Availability Check**: Suspended models are skipped during round-robin selection until they recover

#### Suspension Behavior

- Suspension is tracked per model across all requests
- If all models are suspended, the policy returns HTTP 503 with error: "All models are currently unavailable"
- Suspension period starts from the time of failure


## Notes
- For path parameters, the regex pattern should include a capturing group to extract the model name. The policy uses the first capturing group as the model identifier.
- This capability evenly distributes requests across multiple models to improve availability, balance load and cost, support A/B testing, and enable seamless traffic sharing across models from different providers.
- The round-robin index is maintained per policy instance and increments for each request.
- Model selection is deterministic and follows a strict cyclic pattern.
- The original model from the request is stored in metadata but is replaced with the selected model for routing.
- If `suspendDuration` is 0, failed models are not suspended and will continue to be selected in the round-robin cycle.
- The `requestModel` configuration is required and must be provided by the LLM provider template.
