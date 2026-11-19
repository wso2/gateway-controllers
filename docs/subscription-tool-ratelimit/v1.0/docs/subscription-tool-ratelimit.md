---
title: "Overview"
---
# Subscription Tool Rate Limit

## Overview

The Subscription Tool Rate Limit policy enforces the `tool-call-count` condition (id `tool-calls`) of the caller's subscription plan on an MCP API: each `tools/call` request counts one against the plan's limits, with a counter per subscription. Other MCP methods (`initialize`, `tools/list`, `resources/read` and so on) are not counted; use `subscription-request-ratelimit` to limit all requests.

It reads the subscription and the plan's conditions that [`subscription-validation` v2](../../../subscription-validation/v2.0/docs/subscription-validation.md) records, so it must come **after** `subscription-validation` v2 in the policy chain. When no subscription was recorded the policy lets the request through without limiting and logs at debug level.

## Features

- Counts MCP `tools/call` requests against the plan's tool call limits, per subscription.
- Several windows per condition (minute, hour, day, month); the strictest wins.
- `onExceed: reject` returns `429` with a JSON-RPC error; `onExceed: allow` logs and lets the call through.
- New plan limits apply as soon as the plan changes.
- In-memory or Redis counting, shared with the other rate-limit policies' configuration.

## Identifying Tool Calls

The policy identifies a tool call the same way `mcp-ratelimit` does. Only `POST` requests to the MCP endpoint (`/mcp` or a path under `/mcp/`) are considered.

- On a gateway with an MCP operation resolver, the method comes from the mirrored `Mcp-Method` header on MCP 2026-07-28 requests, and from the resolver's reading of the body on earlier revisions. The decision is made in the request header phase.
- On a gateway without one, the policy reads the JSON-RPC request body itself. A body that names `tools/call` in any `method` member counts.

A request whose method cannot be identified is not counted. Rejecting malformed MCP requests is left to `mcp-spec-validation` and `mcp-ratelimit`.

## Plan Conditions

A subscription plan holds a list of conditions. The limit conditions share one params format:

```json
{
  "id": "tool-calls",
  "type": "tool-call-count",
  "params": {
    "limits": [
      {"count": 100, "timeAmount": 1, "timeUnit": "MINUTE"},
      {"count": 5000, "timeAmount": 1, "timeUnit": "DAY"}
    ],
    "onExceed": "reject"
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
- name: subscription-tool-ratelimit
  gomodule: github.com/wso2/gateway-controllers/policies/subscription-tool-ratelimit@v1
```

## Rate Limit Exceeded Response

When a window with `onExceed: reject` is used up, the call is rejected with `429` and a JSON-RPC error envelope carrying the request's id (`null` when the request's id is not known, as on an MCP 2026-07-28 request decided from its headers):

```json
{
  "jsonrpc": "2.0",
  "id": 7,
  "error": {
    "code": -32000,
    "message": "Subscription quota exceeded: 20 tool calls per 1 hour"
  }
}
```

The response carries the violated window's `X-RateLimit-Limit`, `X-RateLimit-Remaining`, `X-RateLimit-Reset`, `X-RateLimit-Full-Quota-Reset`, `RateLimit-Limit`, `RateLimit-Remaining`, `RateLimit-Reset`, `RateLimit-Full-Quota-Reset`, `RateLimit-Policy` and `Retry-After` headers, as `subscription-validation` v1 did, and echoes the `mcp-session-id` header.

## Analytics

So that overage can be charged apart from the plan's quota, the policy adds these keys to the request's analytics metadata, per condition. The condition id is part of each key, so several subscription policies on one request don't overwrite each other.

| Key | Value | When |
|---|---|---|
| `x-wso2-subscription-quota-status-tool-calls` | `within` or `over` | Every counted request |
| `x-wso2-subscription-quota-action-tool-calls` | `allowed` (`onExceed: allow`, the request went through) or `rejected` (`onExceed: reject`, the request got 429) | Only when `over` |
| `x-wso2-subscription-quota-limit-tool-calls` | The window that was exceeded, e.g. "200 tool calls per 1 hour" | Only when `over` and the window is known |

Only `tools/call` requests carry it; `initialize`, `tools/list` and other methods are not counted and carry nothing from this policy. A request without a subscription (subscription-validation v2 did not run), or whose plan has no tool-call-count condition, carries none of these keys.

## Reference Scenarios

### Example 1: MCP API

```yaml
apiVersion: gateway.api-platform.wso2.com/v1
kind: Mcp
metadata:
  name: weather-mcp-v1.0
spec:
  displayName: Weather-MCP
  version: v1.0
  context: /weather-mcp/$version
  upstream:
    url: http://mcp-backend:8080
  policies:
    - name: subscription-validation
      version: v2
    - name: subscription-request-ratelimit
      version: v1
    - name: subscription-tool-ratelimit
      version: v1
```

With a plan of 1000 requests a day and 20 tool calls an hour, a subscription can call tools 20 times an hour, and all its MCP requests together are limited to 1000 a day.

## Fault reporting

| When | Status | Code | Type |
|------|--------|------|------|
| A plan tool call limit is exceeded | `429` | `900804` | `throttling` |

The fault's `Message` is `Subscription plan tool call limit exceeded`, and it carries the JSON-RPC error code `-32000` and the request id.
