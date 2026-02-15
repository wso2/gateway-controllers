---
title: "Overview"
---
# Token Based Rate Limiting

## Overview

The Token Based Rate Limiting policy controls LLM API usage by enforcing rate limits based on token counts rather than request counts. It enables you to set independent quotas for prompt tokens, completion tokens, and total tokens, ensuring fine-grained control over how much LLM capacity is consumed within a given time window.

Token counts are automatically extracted from LLM provider responses using provider-specific templates. This means you only need to define the token limits — the policy handles the extraction of actual token usage from each response automatically.

Use this policy when you need to:

- Limit LLM API usage based on actual token consumption.
- Apply separate quotas for prompt (input) and completion (output) tokens.
- Enforce total token budgets across time windows.
- Protect against excessive LLM costs by capping token usage per provider path.

## Features

- **Token-Level Rate Limiting**: Enforce rate limits based on actual token consumption instead of request counts.
- **Independent Token Quotas**: Configure separate limits for prompt tokens, completion tokens, and total tokens.
- **Automatic Token Extraction**: Token counts are extracted automatically from LLM provider responses using provider-specific templates — no manual cost configuration required.
- **Multiple Time Windows**: Define multiple concurrent limits per token type (for example, 1000 tokens per minute AND 50000 tokens per day).
- **Multiple Algorithms**: Supports GCRA (smooth rate limiting with burst support) and Fixed Window (simple counter per time window).
- **Dual Backends**: Choose between in-memory storage (single instance) or Redis (distributed rate limiting across multiple gateway instances).
- **Comprehensive Rate Limit Headers**: Responses include standard rate limit headers (X-RateLimit-*, IETF RateLimit, Retry-After) for client-side visibility.
- **Pre-Flight Quota Check**: Requests are blocked upfront when the token quota is already exhausted, preventing unnecessary upstream calls.

## Configuration

This policy uses a two-level configuration: system parameters configured by administrators and user parameters configured per LLM provider.

### User Parameters (LLM Provider Definition)

These parameters are configured per LLM provider path by the API developer:

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `promptTokenLimits` | `Limit` array | No | Rate limits for prompt (input) tokens. |
| `completionTokenLimits` | `Limit` array | No | Rate limits for completion (output) tokens. |
| `totalTokenLimits` | `Limit` array | No | Rate limits for total (prompt + completion) tokens. |

> **Note:** At least one of `promptTokenLimits`, `completionTokenLimits`, or `totalTokenLimits` should be configured for the policy to enforce any limits.

#### Limit Configuration

Each limit entry defines a quota for a specific time window:

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `count` | integer | Yes | Maximum number of tokens allowed in the duration. Minimum value is 1. |
| `duration` | string | Yes | Time window for the limit in Go duration format (for example, `"1m"`, `"1h"`, `"24h"`). |

### System Parameters (From config.toml)

These parameters are set by the administrator and apply globally:

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `algorithm` | string | No | `"gcra"` | Rate limiting algorithm: `"gcra"` (smooth rate limiting with burst support) or `"fixed-window"` (simple counter per time window). |
| `backend` | string | No | `"memory"` | Storage backend: `"memory"` for single-instance or `"redis"` for distributed rate limiting. |
| `redis` | `Redis` object | No | - | Redis configuration. Used when `backend=redis`. |
| `memory` | `Memory` object | No | - | In-memory storage configuration. Used when `backend=memory`. |

#### Redis Configuration

When using Redis as the backend, configure the following under `redis`:

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `host` | string | No | `"localhost"` | Redis server hostname or IP address. |
| `port` | integer | No | `6379` | Redis server port. |
| `password` | string | No | `""` | Redis authentication password (optional). |
| `username` | string | No | `""` | Redis ACL username (optional, Redis 6+). |
| `db` | integer | No | `0` | Redis database index (0-15). |
| `keyPrefix` | string | No | `"ratelimit:v1:"` | Prefix for Redis keys to avoid collisions with other applications. |
| `failureMode` | string | No | `"open"` | Behavior when Redis is unavailable: `"open"` allows traffic, `"closed"` blocks traffic. |
| `connectionTimeout` | string | No | `"5s"` | Redis connection timeout (Go duration format). |
| `readTimeout` | string | No | `"3s"` | Redis read timeout (Go duration format). |
| `writeTimeout` | string | No | `"3s"` | Redis write timeout (Go duration format). |

#### Memory Configuration

When using in-memory backend, configure the following under `memory`:

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `maxEntries` | integer | No | `10000` | Maximum number of rate limit entries stored in memory. Old entries are evicted when this limit is reached. |
| `cleanupInterval` | string | No | `"5m"` | Interval for cleaning up expired entries (Go duration format). Use `"0"` to disable periodic cleanup. |

#### Sample System Configuration

```toml
[policy_configurations.ratelimit_v0]
algorithm = "gcra"
backend = "memory"

[policy_configurations.ratelimit_v0.memory]
max_entries = 10000
cleanup_interval = "5m"
```

For distributed rate limiting across multiple gateway instances:

```toml
[policy_configurations.ratelimit_v0]
algorithm = "gcra"
backend = "redis"

[policy_configurations.ratelimit_v0.redis]
host = "redis.example.com"
port = 6379
password = "your-redis-password"
db = 0
key_prefix = "ratelimit:v1:"
failure_mode = "open"
connection_timeout = "5s"
read_timeout = "3s"
write_timeout = "3s"
```

**Note:**

Inside the `gateway/build.yaml`, ensure the policy module is added under `policies:`:

```yaml
- name: token-based-ratelimit
  gomodule: github.com/wso2/gateway-controllers/policies/token-based-ratelimit@v0
```

## Reference Scenarios

This policy is designed to be attached to an `LlmProvider`. Before attaching the policy, you must create an `LlmProviderTemplate` that defines the token extraction paths for your LLM backend.

### LLM Provider Template

The `LlmProviderTemplate` tells the policy where to find token usage information in the LLM provider's response. Here is an example template for an OpenAI-compatible provider:

```yaml
apiVersion: gateway.api-platform.wso2.com/v1alpha1
kind: LlmProviderTemplate
metadata:
  name: openai-template
spec:
  displayName: OpenAI Template
  promptTokens:
    location: payload
    identifier: $.usage.prompt_tokens
  completionTokens:
    location: payload
    identifier: $.usage.completion_tokens
  totalTokens:
    location: payload
    identifier: $.usage.total_tokens
  requestModel:
    location: payload
    identifier: $.model
  responseModel:
    location: payload
    identifier: $.model
```

The `identifier` fields use JSONPath expressions to locate token counts in the response body. Adjust these paths to match the response format of your LLM provider.

### Example 1: Limit Total Tokens Per Minute

Apply a simple total token limit to an LLM provider:

```yaml
apiVersion: gateway.api-platform.wso2.com/v1alpha1
kind: LlmProvider
metadata:
  name: openai-provider
spec:
  displayName: OpenAI Provider
  version: v1.0
  context: /openai
  template: openai-template
  upstream:
    url: https://api.openai.com
    auth:
      type: api-key
      header: Authorization
      value: Bearer ${OPENAI_API_KEY}
  accessControl:
    mode: deny_all
    exceptions:
      - path: /chat/completions
        methods: [POST]
  policies:
    - name: token-based-ratelimit
      version: v0
      paths:
        - path: /chat/completions
          methods: [POST]
          params:
            totalTokenLimits:
              - count: 10000
                duration: "1m"
```

This limits the `/chat/completions` path to 10,000 total tokens per minute. Once the quota is exhausted, subsequent requests are rejected with a 429 response until the window resets.

### Example 2: Separate Prompt and Completion Token Limits

Apply independent limits for prompt (input) and completion (output) tokens:

```yaml
apiVersion: gateway.api-platform.wso2.com/v1alpha1
kind: LlmProvider
metadata:
  name: openai-provider
spec:
  displayName: OpenAI Provider
  version: v1.0
  context: /openai
  template: openai-template
  upstream:
    url: https://api.openai.com
    auth:
      type: api-key
      header: Authorization
      value: Bearer ${OPENAI_API_KEY}
  accessControl:
    mode: deny_all
    exceptions:
      - path: /chat/completions
        methods: [POST]
  policies:
    - name: token-based-ratelimit
      version: v0
      paths:
        - path: /chat/completions
          methods: [POST]
          params:
            promptTokenLimits:
              - count: 5000
                duration: "1m"
            completionTokenLimits:
              - count: 8000
                duration: "1m"
```

This enforces 5,000 prompt tokens per minute and 8,000 completion tokens per minute independently. If either quota is exhausted, subsequent requests are rejected.

### Example 3: Multiple Time Windows

Enforce both short-term and long-term token budgets:

```yaml
apiVersion: gateway.api-platform.wso2.com/v1alpha1
kind: LlmProvider
metadata:
  name: openai-provider
spec:
  displayName: OpenAI Provider
  version: v1.0
  context: /openai
  template: openai-template
  upstream:
    url: https://api.openai.com
    auth:
      type: api-key
      header: Authorization
      value: Bearer ${OPENAI_API_KEY}
  accessControl:
    mode: deny_all
    exceptions:
      - path: /chat/completions
        methods: [POST]
  policies:
    - name: token-based-ratelimit
      version: v0
      paths:
        - path: /chat/completions
          methods: [POST]
          params:
            totalTokenLimits:
              - count: 10000
                duration: "1m"
              - count: 500000
                duration: "24h"
```

This enforces a burst limit of 10,000 total tokens per minute and a daily budget of 500,000 total tokens. Both limits are evaluated, and the most restrictive one is enforced.

### Example 4: Comprehensive Token Limits

Apply limits to all three token types with multiple time windows:

```yaml
apiVersion: gateway.api-platform.wso2.com/v1alpha1
kind: LlmProvider
metadata:
  name: openai-provider
spec:
  displayName: OpenAI Provider
  version: v1.0
  context: /openai
  template: openai-template
  upstream:
    url: https://api.openai.com
    auth:
      type: api-key
      header: Authorization
      value: Bearer ${OPENAI_API_KEY}
  accessControl:
    mode: deny_all
    exceptions:
      - path: /chat/completions
        methods: [POST]
  policies:
    - name: token-based-ratelimit
      version: v0
      paths:
        - path: /chat/completions
          methods: [POST]
          params:
            promptTokenLimits:
              - count: 5000
                duration: "1m"
              - count: 200000
                duration: "24h"
            completionTokenLimits:
              - count: 8000
                duration: "1m"
              - count: 300000
                duration: "24h"
            totalTokenLimits:
              - count: 12000
                duration: "1m"
              - count: 500000
                duration: "24h"
```

This applies per-minute and daily limits across all token types. Each token type is tracked and enforced independently. A request is rejected if any one of the configured limits is exceeded.

### Example 5: Token Limits on Multiple Paths

Apply different token limits to different paths within the same LLM provider:

```yaml
apiVersion: gateway.api-platform.wso2.com/v1alpha1
kind: LlmProvider
metadata:
  name: openai-provider
spec:
  displayName: OpenAI Provider
  version: v1.0
  context: /openai
  template: openai-template
  upstream:
    url: https://api.openai.com
    auth:
      type: api-key
      header: Authorization
      value: Bearer ${OPENAI_API_KEY}
  accessControl:
    mode: deny_all
    exceptions:
      - path: /chat/completions
        methods: [POST]
      - path: /completions
        methods: [POST]
  policies:
    - name: token-based-ratelimit
      version: v0
      paths:
        - path: /chat/completions
          methods: [POST]
          params:
            totalTokenLimits:
              - count: 50000
                duration: "1h"
        - path: /completions
          methods: [POST]
          params:
            totalTokenLimits:
              - count: 100000
                duration: "1h"
```

Each path maintains its own independent token quota. The `/chat/completions` path is limited to 50,000 total tokens per hour, while `/completions` is limited to 100,000 total tokens per hour.

## Notes

When rate limiting is applied, the following headers may be included in responses:

##### X-RateLimit Headers (Industry Standard)

| Header | Description |
|--------|-------------|
| `X-RateLimit-Limit` | Maximum tokens allowed in the current window |
| `X-RateLimit-Remaining` | Remaining tokens in the current window |
| `X-RateLimit-Reset` | Unix timestamp when the rate limit resets |

##### IETF RateLimit Headers (Draft Standard)

| Header | Description |
|--------|-------------|
| `RateLimit-Limit` | Maximum tokens allowed in the current window |
| `RateLimit-Remaining` | Remaining tokens in the current window |
| `RateLimit-Reset` | Seconds until the rate limit resets |
| `RateLimit-Policy` | Rate limit policy description |

##### Retry-After Header (RFC 7231)

| Header | Description |
|--------|-------------|
| `Retry-After` | Seconds to wait before retrying (only on 429 responses) |
