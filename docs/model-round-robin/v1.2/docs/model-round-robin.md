---
title: "Overview"
---
# Model Round Robin

## Overview

The Model Round Robin policy implements round-robin load balancing for AI models. It distributes requests evenly across multiple configured AI models in a cyclic manner, ensuring equal request allocation over time and preventing overloading of any single model. This policy is useful for distributing load across multiple models, improving availability, and managing resource utilization.

## Features

- Even distribution of requests across multiple models in a cyclic pattern
- Optional per-target routing to additional LLM providers (multi-provider round robin)
- Automatic model suspension on failures (5xx or 429 responses), scoped to the selected provider/model pair
- Configurable suspension duration for failed models
- Support for extracting model identifier from payload, headers, query parameters, or path parameters
- Dynamic model selection based on availability

## Configuration

This policy requires configuration in both the API definition YAML and the LLM provider template.

### User Parameters (API Definition)

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `models` | `Model` array | Yes | - | List of models for round-robin distribution. Each model must have a `model` name. |
| `suspendDuration` | integer | No | `30` | Suspension time in seconds for failed models. Set to `0` to disable failed-model suspension tracking. Must be >= 0. |

### Model Configuration

Each model in the `models` array is an object with the following properties:

| Property | Type | Required | Description |
|----------|------|----------|-------------|
| `model` | string | Yes | The AI model name to use for load balancing. |
| `provider` | string | No | Optionally routes this target to an additional LLM provider. Must match an `LlmProxy` `additionalProviders[].as` value, or the provider id when `as` is absent. When omitted, the request uses the `LlmProxy` primary/default provider. |

#### Multi-provider routing

Each round-robin target can optionally name an additional provider. When a target
specifies `provider`, the policy:

- routes the request to that provider's named upstream (Envoy dynamic cluster
  selection) during the request **header** phase, so the selected upstream is
  chosen before the request is forwarded, and
- records `selected_provider` in request metadata so conditional provider
  authentication and protocol transformers can adapt to the chosen provider.

When `provider` is omitted, no upstream override is applied and `selected_provider`
is not set, so the `LlmProxy` primary-provider fallback, authentication, and
default cluster logic continue to apply unchanged.

```yaml
models:
  - model: gpt-4o
    # Omitted provider → LlmProxy primary/default provider.
  - model: claude-sonnet-4-5-20250929
    provider: anthropic-provider   # matches additionalProviders[].as (or provider id)
```


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
  gomodule: github.com/wso2/gateway-controllers/policies/model-round-robin@v1
```

## Reference Scenarios

### Example 1: Basic Round Robin with Payload-based Model

Deploy an LLM provider with round-robin load balancing across multiple models:

```yaml
apiVersion: gateway.api-platform.wso2.com/v1
kind: LlmProvider
metadata:
  name: round-robin-provider
spec:
  displayName: Round Robin Provider
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
    - name: model-round-robin
      version: v1
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

```bash
# First request - will use gpt-4
curl -X POST http://localhost:8080/openai/chat/completions \
  -H "Content-Type: application/json" \
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
curl -X POST http://localhost:8080/openai/chat/completions \
  -H "Content-Type: application/json" \
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
curl -X POST http://localhost:8080/openai/chat/completions \
  -H "Content-Type: application/json" \
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

### Example 2: Multi-Provider Round Robin

Route round-robin targets across a primary provider and two additional providers.
Deploy the three `LlmProvider` resources first. The `LlmProxy` references their
`metadata.name` values through `id`. Each `models[]` entry references an additional
provider by its proxy-local `as` alias (or by `id` when `as` is omitted). Targets
without a `provider` use the primary provider.

```yaml
apiVersion: gateway.api-platform.wso2.com/v1
kind: LlmProxy
metadata:
  name: multi-provider-round-robin
spec:
  displayName: Multi Provider Round Robin
  version: v1.0
  provider:
    id: openai-primary-provider
  additionalProviders:
    - id: anthropic-provider-resource
      as: anthropic-provider
    - id: bedrock-provider-resource
      as: bedrock-provider
      transformer:
        type: openai-to-bedrock-transformer
        version: v0
  operationPolicies:
    - name: model-round-robin
      version: v1
      paths:
        - path: /chat/completions
          methods: [POST]
          params:
            models:
              - model: gpt-4o                          # primary provider
              - model: claude-sonnet-4-5-20250929
                provider: anthropic-provider
              - model: anthropic.claude-3-5-sonnet-20240620-v1:0
                provider: bedrock-provider
            suspendDuration: 60
```

With this configuration, successive requests rotate primary → anthropic-provider
→ bedrock-provider → primary …. Requests routed to an additional provider carry
`selected_provider` metadata so the provider's conditional authentication and any
protocol transformer (for example, an OpenAI→Bedrock transformer) are applied.

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

- Suspension is tracked per **provider/model pair**, not by model name alone. The same
  model name behind two different providers is suspended independently, so a failure
  on one provider does not remove the model from rotation on another provider.
- If all targets are suspended, the policy returns HTTP 503 with error: "All models are currently unavailable"
- Suspension period starts from the time of failure


## Notes
- For path parameters, the regex pattern should include a capturing group to extract the model name. The policy uses the first capturing group as the model identifier.
- This capability evenly distributes requests across multiple models to improve availability, balance load and cost, support A/B testing, and enable seamless traffic sharing across models from different providers.
- The round-robin index is maintained per policy instance and increments for each request.
- Model selection is deterministic and follows a strict cyclic pattern.
- The original model from the request is stored in metadata but is replaced with the selected model for routing.
- If `suspendDuration` is 0, failed models are not suspended and will continue to be selected in the round-robin cycle.
- The `requestModel` configuration is required and must be provided by the LLM provider template.
- **State locality:** Round-robin index and provider/model suspension state are held in
  memory, local to each policy-engine instance. They are not shared across instances and
  are reset on process restart or configuration reload. With multiple gateway replicas,
  each replica advances its own round-robin cursor and tracks suspensions independently.
