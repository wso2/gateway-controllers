---
title: "Overview"
---
# Subscription Token Rate Limit

## Overview

The Subscription Token Rate Limit policy enforces the `token-count` condition (id `tokens`) of the caller's subscription plan on an LLM API: the tokens each response reports count against the plan's limits, with a counter per subscription. The condition's `tokenType` selects which tokens count.

It reads the subscription and the plan's conditions that [`subscription-validation` v2](../../../subscription-validation/v2.0/docs/subscription-validation.md) records, so it must come **after** `subscription-validation` v2 in the policy chain. When no subscription was recorded the policy lets the request through without limiting and logs at debug level.

## Features

- Counts LLM tokens per subscription against the plan's token limits: total, prompt or completion tokens.
- Reads token counts from buffered and streamed (SSE) responses using the LLM provider template.
- Several windows per condition (minute, hour, day, month); the strictest wins.
- `onExceed: reject` returns `429` once the quota is used up; `onExceed: allow` logs and lets requests through.
- New plan limits apply as soon as the plan changes.
- In-memory or Redis counting, shared with the other rate-limit policies' configuration.

## How It Works

1. On the request, the policy finds the plan's `token-count` condition and checks the subscription's remaining tokens in every window. If any window has none left, the request is rejected (or, with `onExceed: allow`, logged and let through).
2. On the response, the token count is read from the response body (or header, or metadata) where the provider's `LlmProviderTemplate` says it is, and charged to every window.

Because tokens are only known once the response arrives, the request that uses up the quota is let through and can go over it; the next request is the one rejected. This is how `token-based-ratelimit` behaves as well.

The provider is the one the gateway records for the request (`provider_name` metadata). When the provider has no template, or the template does not say where the selected tokens are, the policy logs a warning and does not limit.

## Plan Conditions

A subscription plan holds a list of conditions. The limit conditions share one params format:

```json
{
  "id": "tokens",
  "type": "token-count",
  "params": {
    "limits": [
      {"count": 10000, "timeAmount": 1, "timeUnit": "MINUTE"},
      {"count": 500000, "timeAmount": 1, "timeUnit": "DAY"}
    ],
    "onExceed": "reject",
    "tokenType": "total"
  }
}
```

| Field | Description |
|-------|-------------|
| `limits` | One to ten windows. Every window is enforced, so the strictest one decides. |
| `limits[].count` | Allowed count in the window. A window with a count of 0 or less is ignored. |
| `limits[].timeAmount` | Number of time units in the window. Absent or `0` means `1`. |
| `limits[].timeUnit` | `MINUTE`, `HOUR`, `DAY` or `MONTH`. **A month is 30 days.** |
| `onExceed` | `reject` (default) returns `429` once a window is used up. `allow` lets the request through and logs a warning, so the limit is observed but not enforced. |

Counters are kept per subscription (`x-wso2-subscription-id`) and per condition, and are shared by all the routes of the API. When the plan's limits change, the new limits apply at once with fresh counters; a change to `onExceed` alone keeps the counters.

A plan with no condition of this policy's type, an unlimited plan (no conditions) and `custom` conditions are not limited by this policy.

The token condition also takes `tokenType`:

| `tokenType` | Counts | Template field |
|-------------|--------|----------------|
| `total` (default) | All tokens | `totalTokens`; when the template has none, `promptTokens` plus `completionTokens` |
| `prompt` | Input tokens | `promptTokens` |
| `completion` | Output tokens | `completionTokens` |

A change of `tokenType` is a change of limits: the counters start afresh.

## Configuration

### User Parameters (API Definition)

This policy has no user parameters.

### System Parameters (From config.toml)

The policy delegates counting to the `advanced-ratelimit` engine and takes the same system parameters as the other rate-limit policies, from the same `policy_configurations.ratelimit_v1` section, so they share one Redis:

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `algorithm` | string | No | `"fixed-window"` | `"fixed-window"` (a counter per window) or `"gcra"` (smooth limiting). |
| `backend` | string | No | `"memory"` | `"memory"` counts per gateway replica; `"redis"` counts across replicas exactly; `"redis-local-async"` counts locally and reconciles with Redis asynchronously (bounded overshoot). |
| `redis` | object | No | - | Redis connection (`host`, `port`, `username`, `password`, `db`, `keyPrefix`, `failureMode`, `connectionTimeout`, `readTimeout`, `writeTimeout`, `poolSize`, `tls.*`), as for `advanced-ratelimit`. With `failureMode` `open` (default) requests pass when Redis is unavailable; with `closed` they are rejected. |
| `memory` | object | No | - | In-memory storage (`maxEntries`, `cleanupInterval`). |
| `local` | object | No | - | `redis-local-async` tuning (`syncInterval`, `flushWorkers`, `maxPipelineCommands`, `maxLocalEntries`). |

```toml
[policy_configurations.ratelimit_v1]
algorithm = "fixed-window"
backend = "redis"

[policy_configurations.ratelimit_v1.redis]
host = "redis.example.com"
port = 6379
key_prefix = "ratelimit:v1:"
failure_mode = "open"
```

**Note:**

Inside the `gateway/build.yaml`, ensure the policy modules are added under `policies:`:

```yaml
- name: subscription-validation
  gomodule: github.com/wso2/gateway-controllers/policies/subscription-validation/v2@v2
- name: subscription-token-ratelimit
  gomodule: github.com/wso2/gateway-controllers/policies/subscription-token-ratelimit@v1
```

## Rate Limit Exceeded Response

When a window with `onExceed: reject` is used up, the request is rejected with the same response shape `subscription-validation` v1 used for a plan limit:

- **Status code:** `429`
- **Body (example):**
  ```json
  {
    "error": "rate_limit_exceeded",
    "message": "Subscription quota exceeded: 10000 tokens per 1 minute"
  }
  ```
- **Headers:** the violated window's `X-RateLimit-Limit`, `X-RateLimit-Remaining`, `X-RateLimit-Reset` (Unix time), `X-RateLimit-Full-Quota-Reset`, `RateLimit-Limit`, `RateLimit-Remaining`, `RateLimit-Reset` (seconds), `RateLimit-Full-Quota-Reset`, `RateLimit-Policy` (`<limit>;w=<window seconds>`) and `Retry-After`.

Successful responses carry the advanced-ratelimit engine's rate-limit headers for the token windows.

## Analytics

So that overage can be charged apart from the plan's quota, the policy adds these keys to the request's analytics metadata, per condition. The condition id is part of each key, so several subscription policies on one request don't overwrite each other.

| Key | Value | When |
|---|---|---|
| `x-wso2-subscription-quota-status-tokens` | `within` or `over` | Every counted request |
| `x-wso2-subscription-quota-action-tokens` | `allowed` (`onExceed: allow`, the request went through) or `rejected` (`onExceed: reject`, the request got 429) | Only when `over` |
| `x-wso2-subscription-quota-limit-tokens` | The window that was exceeded, e.g. "50000 tokens per 1 day" | Only when `over` and the window is known |

It is decided when the request comes in, before the response's tokens are counted: a request is `within` while the token quota is not used up yet, and `over` once it is. The response that crosses the limit is the last one marked `within`. A request without a subscription (subscription-validation v2 did not run), or whose plan has no token-count condition, carries none of these keys.

## Reference Scenarios

### Example 1: LLM Provider

The provider needs an `LlmProviderTemplate` that says where the token counts are (see `token-based-ratelimit`):

```yaml
apiVersion: gateway.api-platform.wso2.com/v1
kind: LlmProvider
metadata:
  name: openai-provider
spec:
  displayName: OpenAI Provider
  version: v1.0
  context: /openai
  template: openai-template
  upstream:
    url: https://api.openai.com/v1
    auth:
      type: api-key
      header: Authorization
      value: Bearer ${OPENAI_API_KEY}
  accessControl:
    mode: deny_all
    exceptions:
      - path: /chat/completions
        methods: [POST]
  globalPolicies:
    - name: subscription-validation
      version: v2
    - name: subscription-token-ratelimit
      version: v1
```

With a plan of 10,000 total tokens a minute, a subscription's requests are rejected with `429` once its responses have used 10,000 tokens in the minute.

## Limitations

- **The request that crosses the quota goes through.** Tokens are known only when the response arrives, so a request is checked against what is left before it runs and charged after. The request that uses up the quota can go over it; the next one is rejected. `token-based-ratelimit` behaves the same way.
- When the provider has no `LlmProviderTemplate`, or the template does not say where the selected token type is, the policy does not limit (and logs a warning).

## Fault reporting

| When | Status | Code | Type |
|------|--------|------|------|
| A plan token limit is exceeded | `429` | `900804` | `throttling` |

The fault's `Message` is `Subscription plan token limit exceeded`.
