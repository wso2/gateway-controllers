---
title: "Overview"
---
# Token Based Rate Limiting

## Overview

The Token Based Rate Limiting policy enforces quotas using LLM token usage instead of request count. It supports independent limits for prompt, completion, and total tokens, with one or more time windows for each.

## Features

- Rate limits based on token usage
- Independent limit sets for prompt/completion/total tokens
- Multiple limit windows per token type
- Uses shared advanced-ratelimit backend/algorithm configuration
- Supports memory and Redis backends

## Configuration

This policy uses a two-level configuration model.

### User Parameters (LLM Provider Definition)

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `promptTokenLimits` | `Limit[]` | No | Limits for prompt (input) token usage. |
| `completionTokenLimits` | `Limit[]` | No | Limits for completion (output) token usage. |
| `totalTokenLimits` | `Limit[]` | No | Limits for total token usage. |

At least one of the above limit groups should be configured to enforce throttling.

#### Limit Configuration

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `count` | integer | Yes | Maximum tokens allowed in the time window. |
| `duration` | string | Yes | Time window in Go duration format (for example, `1m`, `1h`, `24h`). |

### System Parameters (From config.toml)

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `algorithm` | string | No | `gcra` | Rate-limit algorithm: `gcra` or `fixed-window`. |
| `backend` | string | No | `memory` | Backend: `memory` or `redis`. |
| `redis` | object | No | - | Redis backend settings (used when `backend=redis`). |
| `memory` | object | No | - | Memory backend settings (used when `backend=memory`). |

#### Sample System Configuration

```toml
[policy_configurations.ratelimit_v0]
algorithm = "gcra"
backend = "memory"

[policy_configurations.ratelimit_v0.memory]
max_entries = 10000
cleanup_interval = "5m"
```

**Note:**

Inside `gateway/build.yaml`, ensure the policy module is added under `policies`:

```yaml
- name: token-based-ratelimit
  gomodule: github.com/wso2/gateway-controllers/policies/token-based-ratelimit@v0
```

## Reference Scenarios

### Example 1: Total Token Limit

```yaml
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

### Example 2: Prompt and Completion Limits

```yaml
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

### Example 3: Multiple Windows

```yaml
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

## How It Works

1. Builds token-based limits from configured user parameters.
2. Uses provider template token extraction paths to read token counts.
3. Evaluates configured windows via selected backend/algorithm.
4. Rejects requests with `429` when any configured token quota is exceeded.

## Notes

- Token extraction depends on template mappings for prompt/completion/total usage fields.
- Configure Redis backend for distributed rate-limit state across multiple gateway replicas.
- Keep duration values in valid Go duration format.
