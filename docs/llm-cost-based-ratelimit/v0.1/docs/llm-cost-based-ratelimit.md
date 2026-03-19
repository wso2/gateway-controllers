---
title: "Overview"
---
# LLM Cost Based Ratelimit

## Overview

The LLM Cost Based Ratelimit policy enforces monetary spending budgets on LLM API usage. Rather than limiting by request count or token count, it limits by the actual dollar cost of each call, allowing you to cap spending within configurable time windows (for example, $10 per hour or $100 per day).

This policy reads the pre-calculated cost from `SharedContext.Metadata`, which is set by the [LLM Cost](../../llm-cost/v0.1/docs/llm-cost.md) policy. The `llm-cost` policy must be applied on the same path for this policy to function correctly.

Use this policy when you need to:

- Enforce monetary spending budgets on LLM API routes.
- Protect against runaway LLM costs caused by unexpectedly expensive models or high request volumes.
- Apply different budget limits for different time horizons (for example, per hour, per day, and per month simultaneously).

## Features

- **Monetary Budget Enforcement**: Define spending limits in dollars with per-window granularity.
- **Multiple Time Windows**: Configure multiple concurrent budget limits per route (for example, $5 per hour AND $50 per day).
- **Dollar-Denominated Headers**: Responses include `x-ratelimit-cost-limit-dollars` and `x-ratelimit-cost-remaining-dollars` headers for client-side visibility.
- **Multiple Algorithms**: Supports GCRA (smooth rate limiting with burst support) and Fixed Window (simple counter per time window).
- **Dual Backends**: Choose between in-memory storage (single instance) or Redis (distributed rate limiting across multiple gateway instances).
- **Pre-Flight Quota Check**: Requests are blocked upfront when the budget is already exhausted, preventing unnecessary upstream calls.
- **Precision Scaling**: Dollar amounts are scaled to nano-dollars internally (configurable) to preserve precision in integer counters.

## Configuration

This policy uses a two-level configuration: user parameters that define the spending budgets and system parameters configured by administrators.

### User Parameters (LLM Provider Definition)

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `budgetLimits` | `BudgetLimit` array | Yes | One or more spending limits, each defining a maximum dollar amount within a time window. Minimum 1 entry, maximum 10. |

#### BudgetLimit Configuration

Each entry in `budgetLimits` defines a spending cap for a specific time window:

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `amount` | number | Yes | Maximum dollar amount allowed in the time window. Minimum: `0.000001`, Maximum: `1000000`. |
| `duration` | string | Yes | Time window for the limit in Go duration format (for example, `"1h"`, `"24h"`, `"168h"` for 1 week, `"720h"` for 30 days). |

### System Parameters (From config.toml)

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `costScaleFactor` | integer | No | `1000000000` | Scale factor for converting dollar amounts to internal integer units. Higher values preserve more decimal precision. See [Precision Scaling](#precision-scaling) for details. |
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
[policy_configurations.llm_cost_ratelimit_v0]
cost_scale_factor = 1000000000

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

Inside the `gateway/build.yaml`, ensure both policy modules are added under `policies:`:

```yaml
- name: llm-cost
  gomodule: github.com/wso2/gateway-controllers/policies/llm-cost@v0
- name: llm-cost-based-ratelimit
  gomodule: github.com/wso2/gateway-controllers/policies/llm-cost-based-ratelimit@v0
```

## Reference Scenarios

This policy requires the `llm-cost` policy to run on the same path first, so the pre-calculated cost is available in `SharedContext.Metadata`. Both policies must be listed under the same path, with `llm-cost` placed before `llm-cost-based-ratelimit`.

### Example 1: Simple Daily Spending Budget

Limit the total spend on a route to $50 per day:

```yaml
apiVersion: gateway.api-platform.wso2.com/v1alpha1
kind: LlmProvider
metadata:
  name: openai-provider
spec:
  displayName: OpenAI Provider
  version: v1.0
  context: /openai
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
    - name: llm-cost
      version: v0
      paths:
        - path: /chat/completions
          methods: [POST]
    - name: llm-cost-based-ratelimit
      version: v0
      paths:
        - path: /chat/completions
          methods: [POST]
          params:
            budgetLimits:
              - amount: 50
                duration: "24h"
```

Once the $50 daily budget is exhausted, subsequent requests receive a `429` response until the 24-hour window resets.

### Example 2: Hourly and Daily Budget Limits

Apply both a short-term burst limit and a long-term daily budget:

```yaml
  policies:
    - name: llm-cost
      version: v0
      paths:
        - path: /chat/completions
          methods: [POST]
    - name: llm-cost-based-ratelimit
      version: v0
      paths:
        - path: /chat/completions
          methods: [POST]
          params:
            budgetLimits:
              - amount: 5
                duration: "1h"
              - amount: 50
                duration: "24h"
```

This enforces a $5 per hour burst limit alongside a $50 daily cap. Both limits are evaluated independently — a request is rejected if either limit is exceeded.

### Example 3: Weekly and Monthly Budget Limits

Apply long-horizon budget controls suitable for subscription-style APIs:

```yaml
  policies:
    - name: llm-cost
      version: v0
      paths:
        - path: /chat/completions
          methods: [POST]
    - name: llm-cost-based-ratelimit
      version: v0
      paths:
        - path: /chat/completions
          methods: [POST]
          params:
            budgetLimits:
              - amount: 25
                duration: "168h"
              - amount: 100
                duration: "720h"
```

This sets a $25 weekly budget and a $100 monthly budget. Both limits are tracked concurrently.

### Example 4: Different Budgets on Multiple Paths

Apply different spending limits to different endpoints within the same provider:

```yaml
  policies:
    - name: llm-cost
      version: v0
      paths:
        - path: /chat/completions
          methods: [POST]
        - path: /completions
          methods: [POST]
    - name: llm-cost-based-ratelimit
      version: v0
      paths:
        - path: /chat/completions
          methods: [POST]
          params:
            budgetLimits:
              - amount: 10
                duration: "24h"
        - path: /completions
          methods: [POST]
          params:
            budgetLimits:
              - amount: 5
                duration: "24h"
```

Each path tracks its own independent budget. The `/chat/completions` path is limited to $10 per day, while `/completions` is limited to $5 per day.

## Notes

### Response Headers

When rate limiting is applied, the following headers are included in responses:

##### Dollar-Denominated Headers

| Header | Description |
|--------|-------------|
| `X-RateLimit-Cost-Limit-Dollars` | Maximum dollar budget allowed in the current window |
| `X-RateLimit-Cost-Remaining-Dollars` | Remaining dollar budget in the current window |

##### X-RateLimit Headers (Industry Standard)

| Header | Description |
|--------|-------------|
| `X-RateLimit-Limit` | Maximum budget in scaled internal units |
| `X-RateLimit-Remaining` | Remaining budget in scaled internal units |
| `X-RateLimit-Reset` | Unix timestamp when the rate limit resets |

##### IETF RateLimit Headers (Draft Standard)

| Header | Description |
|--------|-------------|
| `RateLimit-Limit` | Maximum budget in scaled internal units |
| `RateLimit-Remaining` | Remaining budget in scaled internal units |
| `RateLimit-Reset` | Seconds until the rate limit resets |
| `RateLimit-Policy` | Rate limit policy description |

##### Retry-After Header (RFC 7231)

| Header | Description |
|--------|-------------|
| `Retry-After` | Seconds to wait before retrying (only on 429 responses) |

### Precision Scaling

The underlying rate limiter uses `int64` counters internally. Since LLM call costs are small decimal values (for example, `$0.000042`), they must be scaled to integers to avoid truncation. The `costScaleFactor` controls this scaling:

| Scale Factor | Unit | Precision | Example: $1.00 |
|---|---|---|---|
| `1000000000` (default) | Nano-dollars | 9 decimal places | 1,000,000,000 |
| `1000000` | Micro-dollars | 6 decimal places | 1,000,000 |
| `1000` | Milli-dollars | 3 decimal places | 1,000 |
| `100` | Cents | 2 decimal places | 100 |

The default of `1000000000` (nano-dollars) is recommended for production use with LLM APIs where per-token costs can be very small. The dollar-denominated headers (`x-ratelimit-cost-limit-dollars`, `x-ratelimit-cost-remaining-dollars`) are always formatted in human-readable dollars regardless of the scale factor.

### Dependency on llm-cost

This policy reads `x-llm-cost` from `SharedContext.Metadata`. If the `llm-cost` policy is not attached to the same path, or if the model is not found in the pricing database (causing `x-llm-cost-status` to be `not_calculated`), the deducted cost defaults to `0`. In this case, budget limits are not consumed and requests pass through without restriction.
