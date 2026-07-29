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
- **Session stickiness** with gateway-generated session IDs for stateless routing
- Configurable fallbacks to Authorization header or client IP hashing

## Configuration

This policy requires configuration in both the API definition YAML and the LLM provider template.

### User Parameters (API Definition)

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `models` | `Model` array | Yes | - | List of models for round-robin distribution. Each model must have a `model` name. |
| `suspendDuration` | integer | No | `30` | Suspension time in seconds for failed models. Set to `0` to disable failed-model suspension tracking. Must be >= 0. |
| `stickyKey` | `StickyKey` object | No | - | Configuration for session stickiness. When a client sends a session key, requests are routed stickily. When no session key is found, the gateway generates a session ID and returns it to the client. |

### `stickyKey` Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `stickyKey.location` | string | Yes | - | Specifies where the session/sticky key is located in the request. Supported values: `header`, `queryParam`, `payload`, `ip`. |
| `stickyKey.identifier` | string | Yes (except for `ip`) | - | Extraction key used to identify the session. This can be a JSONPath expression (for `payload`), header name (for `header`), or query parameter name (for `queryParam`). |
| `stickyKey.fallbackToAuth` | boolean | No | `false` | Enable fallback to Authorization header hashing if the configured sticky key is missing from the request. |
| `stickyKey.fallbackToIP` | boolean | No | `false` | Enable fallback to client IP hashing if the configured sticky key and Authorization header are both missing. |

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
  gomodule: github.com/wso2/gateway-controllers/policies/model-round-robin@v1
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

### Example 2: Sticky Round Robin with Session Header

Deploy an LLM provider that routes requests stickily based on an HTTP header:

```yaml
apiVersion: gateway.api-platform.wso2.com/v1alpha1
kind: LlmProvider
metadata:
  name: sticky-round-robin-provider
spec:
  displayName: Sticky Round Robin Provider
  version: v1.0
  template: openai
  upstream:
    url: "https://api.openai.com/v1"
  policies:
    - name: model-round-robin
      version: v1
      paths:
        - path: /chat/completions
          methods: [POST]
          params:
            models:
              - model: gpt-4
              - model: gpt-3.5-turbo
            suspendDuration: 60
            stickyKey:
              location: "header"
              identifier: "x-session-id"
```

**Test the sticky session distribution:**

```bash
# Request 1 (No session ID) - routes via round-robin, response includes a generated session ID
curl -v -X POST http://localhost:8080/chat/completions \
  -H "Content-Type: application/json" \
  -d '{"model": "gpt-4", "messages": [{"role": "user", "content": "Hello"}]}'
# Response will include header: x-session-id: <generated-id>_M0

# Request 2 (With generated session ID) - routes to the SAME model (stickiness)
curl -X POST http://localhost:8080/chat/completions \
  -H "Content-Type: application/json" \
  -H "x-session-id: <generated-id>_M0" \
  -d '{"model": "gpt-4", "messages": [{"role": "user", "content": "Hello again"}]}'

# Request 3 (User-provided session ID) - routes stickily via consistent hashing
curl -X POST http://localhost:8080/chat/completions \
  -H "Content-Type: application/json" \
  -H "x-session-id: my-custom-session-123" \
  -d '{"model": "gpt-4", "messages": [{"role": "user", "content": "Hello from custom session"}]}'
```

### Example 3: Sticky Round Robin with Fallbacks Enabled

Enable fallback to Authorization header and client IP when the session key is missing:

```yaml
stickyKey:
  location: "header"
  identifier: "x-session-id"
  fallbackToAuth: true
  fallbackToIP: true
```

With this configuration, the routing priority is:
1. `x-session-id` header (if present)
2. `Authorization` header (if present and `fallbackToAuth` is `true`)
3. Client IP via `X-Forwarded-For` / `X-Real-IP` (if `fallbackToIP` is `true`)
4. Standard round-robin with gateway-generated session ID

## How It Works

#### Model Selection & Session Stickiness
On each request, the policy selects a model using either standard round-robin or session stickiness:

- **Without `stickyKey` (Standard Round-Robin)**: The policy selects the next available model in the configured list in a cyclic order, using a thread-safe incrementing index.
- **With `stickyKey` (Session Stickiness)**: The policy supports three routing paths:
  1. **Gateway-Generated Session ID**: If the session ID ends with `_M<index>` (e.g., `abc123_M1`), the gateway decodes the model index directly and routes to the corresponding model. No hashing is needed.
  2. **User-Provided Session ID**: If the session ID does not have the gateway suffix, the policy applies stateless consistent hashing (FNV-1a hash algorithm and modulo math) to map that session key deterministically to one of the configured models.
  3. **No Session ID**: The policy falls back to standard round-robin, generates a new session ID with the model index encoded (e.g., `<random>_M0`), and returns it to the client in a response header. The client can send this ID back in subsequent requests for stickiness.

- **Model Extraction**: The policy extracts the original model from the request (if configured) and stores it in context metadata for reference.
- **Model Modification**: The policy modifies the request to replace the model name at the location specified by the `requestModel` configuration with the selected model.

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
- The round-robin index is maintained per policy instance and increments for each request (when `stickyKey` is not configured or no session key is found).
- Without `stickyKey`, model selection is cyclic. With `stickyKey`, model selection is determined by either direct index lookup (gateway-generated IDs) or consistent hashing (user-provided IDs).
- The original model from the request is stored in metadata but is replaced with the selected model for routing.
- If `suspendDuration` is 0, failed models are not suspended and will continue to be selected in the round-robin cycle.
- The `requestModel` configuration is required and must be provided by the LLM provider template.
- The `fallbackToAuth` and `fallbackToIP` options are disabled by default. Enable them explicitly if you need fallback stickiness for stateless clients.
