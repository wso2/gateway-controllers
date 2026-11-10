---
title: "Overview"
---
# Subscription Validation

## Overview

The Subscription Validation policy ensures that incoming requests are associated with an active subscription for the target API. It validates a subscription token provided in the request, from a header or a cookie, or falls back to the application identity set by an earlier policy.

v2.0 only validates the subscription. It does not enforce the subscription plan's limits: it records the subscription, its plan and the plan's conditions in the request metadata, and the subscription rate-limit policies enforce them. See [Migrating from v1](#migrating-from-v1).

## Features

- Validates subscriptions per API using subscription tokens.
- Supports subscription tokens from a configurable HTTP header.
- Optional lookup of subscription tokens from a configurable cookie.
- Falls back to the application id (`x-wso2-application-id` metadata) when no token is sent.
- Records the subscription id, plan id and the plan's conditions for the limit policies that follow it.

## Configuration

This policy uses a single-level configuration model where all parameters are configured per API or route in the API definition YAML.

### User Parameters (API Definition)

| Parameter               | Type    | Required | Default            | Description |
|-------------------------|---------|----------|--------------------|-------------|
| `subscriptionKeyHeader` | string  | No       | `Subscription-Key` | Name of the HTTP request header that carries the subscription token. This is the primary source and is checked before cookie fallback. |
| `subscriptionKeyCookie` | string  | No       | `""`               | Optional cookie name that can carry the subscription token. When non-empty, the cookie value is checked only if the header does not contain a token. |

At runtime the policy behaves as follows:

1. It first attempts to read the subscription token from `subscriptionKeyHeader`.
2. If no header token is present and `subscriptionKeyCookie` is non-empty, it attempts to read the token from the named cookie.
3. If no token is present, it uses the application id that an earlier policy recorded in the `x-wso2-application-id` metadata.
4. The token or application is validated against the subscription store for the target API. If no active subscription is found, the request is rejected with `403`.
5. On success the token header (or cookie) is removed from the upstream request and the subscription is recorded in the request metadata.

### System Parameters

This policy does not require explicit system-level configuration; it relies on the gateway's subscription store, which is managed by the platform.

## Request Metadata

On a validated request the policy writes these `SharedContext.Metadata` keys for later policies:

| Key | Value |
|-----|-------|
| `x-wso2-subscription-id` | The subscription id. When the gateway synced the subscription without an id, a stable stand-in: `token:<hash of the token>` or `app:<application id>`. Limit policies key their counters by it. |
| `x-wso2-subscription-plan-id` | The plan id. Absent when the gateway synced none. |
| `x-wso2-subscription-plan-conditions` | The plan's conditions as a JSON array string, `[{"id":"…","type":"…","params":{…}}]`. `[]` when the plan has no conditions (unlimited). |
| `x-wso2-subscription-plan-name` | The plan name, when known (as in v1). |
| `x-wso2-subscription-status` | The subscription status (as in v1). |
| `x-wso2-billing-customer-id` | The billing customer id, when set (as in v1). |
| `x-wso2-billing-subscription-id` | The billing subscription id, when set (as in v1). |

A plan synced before plans had conditions carries only a throttle limit (`ThrottleLimitCount` per `Min`, `Hour`, `Day` or `Month`). The policy records it as a single request-count condition, so the limit policies enforce it like any other plan:

```json
[{"id":"requests","type":"request-count","params":{"limits":[{"count":100,"timeAmount":1,"timeUnit":"MINUTE"}],"onExceed":"reject"}}]
```

`onExceed` is `reject` when the plan stops on quota reach and `allow` otherwise. When the plan has conditions, the throttle limit is ignored.

## Enforcing Plan Limits

Place the limit policies after `subscription-validation` v2 in the same chain. Each enforces one kind of plan condition and does nothing when the plan has none of that kind:

| Policy | Plan condition |
|--------|----------------|
| [`subscription-request-ratelimit`](../../../subscription-request-ratelimit/v1.0/docs/subscription-request-ratelimit.md) | `request-count` (one per request); `event-count` on an event API (one per event) |
| [`subscription-tool-ratelimit`](../../../subscription-tool-ratelimit/v1.0/docs/subscription-tool-ratelimit.md) | `tool-call-count` (one per MCP `tools/call`) |
| [`subscription-token-ratelimit`](../../../subscription-token-ratelimit/v1.0/docs/subscription-token-ratelimit.md) | `token-count` (LLM tokens of each response) |

### Migrating from v1

v2.0 is a major version because it no longer enforces the plan's limits. v1.x rate-limited each subscription by the plan's throttle limit itself; v2 lets every request with an active subscription through. To keep enforcing the plan, add `subscription-request-ratelimit` v1 after `subscription-validation` v2. It enforces the plan's request limits, a legacy throttle limit included, and on an event API (WebSub or WebSocket) the plan's event limits. Add `subscription-tool-ratelimit` (MCP APIs) and `subscription-token-ratelimit` (LLM APIs) when plans carry tool-call or token conditions.

Other behavior is unchanged: the parameters, the token sources, the `403` responses and their fault codes are the same as v1.1, and the `429` that `subscription-request-ratelimit` returns has the same body shape, rate-limit headers and fault code (`900804`) that v1 returned. Two differences remain: the limit policies count per subscription id rather than per token, and they count across all gateway replicas when configured with a Redis backend. v1.x is unchanged.

Before (v1):

```yaml
policies:
  - name: subscription-validation
    version: v1
    params:
      subscriptionKeyHeader: Subscription-Key
```

After (v2):

```yaml
policies:
  - name: subscription-validation
    version: v2
    params:
      subscriptionKeyHeader: Subscription-Key
  - name: subscription-request-ratelimit
    version: v1
  # MCP APIs with tool-call limits in their plans:
  - name: subscription-tool-ratelimit
    version: v1
  # LLM APIs with token limits in their plans:
  - name: subscription-token-ratelimit
    version: v1
```

The limit policies must come after `subscription-validation` v2: without the metadata it records they let every request through. Add the new modules to the gateway build as well (see below).

## Error Responses

When validation fails, the policy returns an immediate JSON error response and stops further processing.

- **Forbidden / No Active Subscription**
  - **Status code:** `403`
  - **Body (example):**
    ```json
    {
      "error": "forbidden",
      "message": "Subscription required for this API"
    }
    ```

## Adding the Policy Module

Inside `gateway/build.yaml`, ensure the policy modules are added under `policies`:

```yaml
- name: subscription-validation
  gomodule: github.com/wso2/gateway-controllers/policies/subscription-validation/v2@v2
- name: subscription-request-ratelimit
  gomodule: github.com/wso2/gateway-controllers/policies/subscription-request-ratelimit@v1
```

## Reference Scenarios

### Example 1: Subscription Validation with Plan Request Limits

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

Requests must include a valid subscription token:

```http
GET /weather/v1.0/US/NewYork HTTP/1.1
Host: api-gateway.company.com
Subscription-Key: tok-1
```

### Example 2: Cookie-Based Subscription Token

```yaml
  policies:
    - name: subscription-validation
      version: v2
      params:
        subscriptionKeyHeader: Subscription-Key
        subscriptionKeyCookie: sub-key
```

If the `Subscription-Key` header is missing, the policy reads the token from the `sub-key` cookie and removes that cookie from the upstream request:

```http
GET /weather/v1.0/US/NewYork HTTP/1.1
Host: api-gateway.company.com
Cookie: sub-key=tok-1
```

## Fault reporting

Every rejection this policy makes is also reported to the gateway as a **fault**: a stable code and type alongside the response, as in v1.1.

| When | Status | Code | Type |
|------|--------|------|------|
| The request context, the API id or the subscription store is missing | `403` | `960000` | `mediation` |
| No subscription token or application identity is presented | `403` | `900902` | `authentication` |
| No active subscription is found for the token or the application | `403` | `900909` | `authentication` |

The fault carries no `Description`: its `Message` is the message the client already receives, for example `Subscription required for this API: API id is missing`.
