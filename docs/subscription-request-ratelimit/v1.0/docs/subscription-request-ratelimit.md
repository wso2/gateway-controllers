---
title: "Overview"
---
# Subscription Request Rate Limit

## Overview

The Subscription Request Rate Limit policy enforces the `request-count` condition of the caller's subscription plan: each request counts one against the plan's limits, with a counter per subscription. On an event API it enforces the plan's `event-count` condition instead, counting one per event.

It reads the subscription and the plan's conditions that [`subscription-validation` v2](../../../subscription-validation/v2.0/docs/subscription-validation.md) records, so it must come **after** `subscription-validation` v2 in the policy chain. When no subscription was recorded (v2 is not in the chain, or comes later) the policy lets the request through without limiting and logs at debug level.

## Features

- Enforces the plan's request limits per subscription, a legacy plan throttle limit included.
- Enforces the plan's event limits on WebSub and WebSocket APIs in the event gateway, one count per event.
- Several windows per condition (minute, hour, day, month); the strictest wins.
- `onExceed: reject` returns `429`; `onExceed: allow` logs and lets the request through.
- New plan limits apply as soon as the plan changes.
- In-memory or Redis counting, shared with the other rate-limit policies' configuration.

## Plan Conditions

A subscription plan holds a list of conditions. The limit conditions share one params format:

```json
{
  "id": "requests",
  "type": "request-count",
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

## Requests and Events

In the event gateway the policy engine runs the policy chain once per message: once per subscribe request, inbound webhook event and delivery for a WebSub API, and once per connection upgrade and produced or consumed message for a WebSocket API. There each run is an event, and the policy enforces the plan's `event-count` condition (id `events`). Everywhere else each run is a request, and it enforces `request-count` (id `requests`).

The policy tells them apart by the request context: the event gateway runs the chain with the `event` scheme and the `WebSubApi` API kind. The `countAs` parameter overrides this.

Each message is a separate run with its own metadata, so on an event API put `subscription-validation` v2 in the same chain (the same enforcement point) as this policy, before it. Attach the pair at the enforcement points whose messages should count; attached to the subscribe point too, the subscribe request counts as one event.

## Configuration

### User Parameters (API Definition)

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `countAs` | string | No | `auto` | `auto` counts events in the event gateway and requests elsewhere. `request` always enforces `request-count`; `event` always enforces `event-count`. |

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
- name: subscription-request-ratelimit
  gomodule: github.com/wso2/gateway-controllers/policies/subscription-request-ratelimit@v1
```

## Rate Limit Exceeded Response

When a window with `onExceed: reject` is used up, the request is rejected with the same response shape `subscription-validation` v1 used for a plan limit:

- **Status code:** `429`
- **Body (example):**
  ```json
  {
    "error": "rate_limit_exceeded",
    "message": "Subscription quota exceeded: 100 requests per 1 minute"
  }
  ```
- **Headers:** the violated window's `X-RateLimit-Limit`, `X-RateLimit-Remaining`, `X-RateLimit-Reset` (Unix time), `X-RateLimit-Full-Quota-Reset`, `RateLimit-Limit`, `RateLimit-Remaining`, `RateLimit-Reset` (seconds), `RateLimit-Full-Quota-Reset`, `RateLimit-Policy` (`<limit>;w=<window seconds>`) and `Retry-After`.

On an event API the message reads `events` instead of `requests`.

## Reference Scenarios

### Example 1: REST API

```yaml
apiVersion: gateway.api-platform.wso2.com/v1
kind: RestApi
metadata:
  name: weather-api-v1.0
spec:
  displayName: Weather-API
  version: v1.0
  context: /weather/$version
  upstream:
    main:
      url: http://sample-backend:5000/api/v2
  policies:
    - name: subscription-validation
      version: v2
    - name: subscription-request-ratelimit
      version: v1
  operations:
    - method: GET
      path: /{country_code}/{city}
```

With a plan of 100 requests a minute and 5000 a day, each subscription can make 100 requests in a minute and 5000 in a day across all the API's operations; the 101st request in a minute gets `429`.

### Example 2: WebSocket API in the Event Gateway

```yaml
spec:
  policies:
    on_produce:
      - name: subscription-validation
        version: v2
      - name: subscription-request-ratelimit
        version: v1
```

Each message a client produces counts one event against the plan's `event-count` condition.

## Limitations

- **A WebSub subscribe request counts as one event** when this policy (with `subscription-validation` v2) is attached at the subscribe enforcement point, because the event gateway runs the chain once for it as well. Attach the pair only where the messages that should count pass.
- `MONTH` windows are 30 days.

## Fault reporting

Every rejection this policy makes is also reported to the gateway as a **fault**.

| When | Status | Code | Type |
|------|--------|------|------|
| A plan request or event limit is exceeded | `429` | `900804` | `throttling` |

The fault's `Message` is `Subscription plan request limit exceeded`, or `Subscription plan event limit exceeded` on an event API.
