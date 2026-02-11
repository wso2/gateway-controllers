---
title: "Overview"
---
# Token-Based Rate Limiting

## Overview

The Token-Based Rate Limiting policy limits LLM traffic using token usage (prompt, completion, total).
It resolves token extraction paths from provider templates and delegates enforcement to the advanced rate limiting engine.

## Features

- Limits by `prompt`, `completion`, and/or `total` token buckets
- Uses provider template token paths dynamically
- Supports advanced rate limit backends and algorithms through delegation
- Per-route key extraction (delegated quota key uses route name)
- Request pre-check + post-response token consumption

## Configuration

At least one of `promptTokenLimits`, `completionTokenLimits`, or `totalTokenLimits` is required.

### User Parameters (API Definition)

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `promptTokenLimits` | array | No | Limits for prompt/input tokens. |
| `completionTokenLimits` | array | No | Limits for completion/output tokens. |
| `totalTokenLimits` | array | No | Limits for total tokens. |

Each limit item:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `count` | integer | Yes | Max tokens allowed in the duration. |
| `duration` | string | Yes | Time window (`1m`, `1h`, `24h`, etc.). |

### System Parameters (Optional Override)

These map to advanced rate-limit engine settings:
- `algorithm` (`gcra` or `fixed-window`)
- `backend` (`memory` or `redis`)
- `redis` object
- `memory` object

If omitted, defaults are read from configured system defaults.

## Behavior Notes

- Policy depends on `provider_name` in shared metadata.
- If provider metadata/mapping/template is missing, policy skips enforcement (no immediate failure).
- Request phase performs quota pre-check.
- Response phase extracts token usage and consumes quota.
- Enforcement uses provider-specific delegated policy instances with template-change-aware caching.

## API Definition Examples

### Example 1: Limit Total Tokens

```yaml
policies:
  - name: token-based-ratelimit
    version: v0
    params:
      totalTokenLimits:
        - count: 100000
          duration: "1h"
```

### Example 2: Separate Prompt and Completion Limits

```yaml
policies:
  - name: token-based-ratelimit
    version: v0
    params:
      promptTokenLimits:
        - count: 50000
          duration: "1h"
      completionTokenLimits:
        - count: 20000
          duration: "1h"
      algorithm: gcra
      backend: memory
```

### Example 3: Redis-Backed Token Rate Limiting

```yaml
policies:
  - name: token-based-ratelimit
    version: v0
    params:
      totalTokenLimits:
        - count: 1000000
          duration: "24h"
      backend: redis
      redis:
        host: redis.example.com
        port: 6379
        keyPrefix: ratelimit:v1:
```
