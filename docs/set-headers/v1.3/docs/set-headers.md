---
title: "Overview"
---
# Set Headers

## Overview

The Set Headers policy sets or appends HTTP headers on upstream requests and/or downstream responses. The behavior is controlled by the `mode` parameter:

- **`set` mode (default):** Headers are set/replaced. Existing headers with the same name are overwritten with the new value.
- **`append` mode:** Configured values are appended to the header, preserving any existing values for that header.

Starting with v1.3, header values can embed context-variable expressions that are resolved at request time. This enables header forwarding, credential relay, subscription plan propagation, and value composition across the gateway call chain.

## Expression syntax

| Expression | Available in | Replaced with |
|---|---|---|
| `${req.header.<name>}` | Request phase, Response phase | Value of request header `<name>` |
| `${resp.header.<name>}` | Response phase only | Value of upstream response header `<name>` |
| `${meta.<key>}` | Request phase, Response phase | Value of `SharedContext.Metadata["key"]` written by an upstream policy |

Expressions may appear anywhere in the value string — surrounded by literal text, or as the entire value:

```
"Bearer ${req.header.x-provider-token}"
"${meta.x-wso2-subscription-plan-name}"
"plan=${meta.x-wso2-subscription-plan-name}/region=${req.header.x-region}"
```

**When a referenced header or metadata key is absent**, or when the template contains a `${...}` expression with an unrecognised scope or unclosed delimiter, the target header is **removed** from the upstream request or downstream response. This prevents a client-supplied value from reaching the backend unchallenged.

**Static values (no expressions) are never removed** — they behave exactly as in v1.2.

## Configuration

### User Parameters (API Definition)

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `mode` | string | No | `set` | Controls how headers are applied. `set` overwrites existing headers; `append` adds values while preserving existing ones. Applies to both request and response phases. |
| `request` | object | No* | — | Headers to set on the upstream request. Must contain a `headers` array. |
| `request.phase` | string | No | `header` | Controls when request headers are applied. `body` applies them after body-derived metadata is available. |
| `response` | object | No* | — | Headers to set on the downstream response. Must contain a `headers` array. |

*At least one of `request` or `response` must be specified.

### Header entry fields

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `name` | string | Yes | — | Header name. Normalized to lowercase. Pattern: `^[a-zA-Z0-9\-_]+$`, max 256 chars. |
| `value` | string | Yes | — | Static value or value template. Max 8192 chars. |
| `removeSource` | boolean | No | `false` | When `true`, removes source headers referenced by `${req.header.*}` (request phase) or `${resp.header.*}` (response phase) expressions after reading their values. Has no effect on `${meta.<key>}` sources. |

## Configuration notes

Inside `gateway/build.yaml`, ensure the policy module is added under `policies:`:

```yaml
- name: set-headers
  gomodule: github.com/wso2/gateway-controllers/policies/set-headers@v1
```

## Reference scenarios

### Example 1: Static — setting request headers

Set static headers on upstream requests (unchanged from v1.2):

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
    - name: set-headers
      version: v1
      params:
        request:
          headers:
            - name: X-API-Key
              value: "12345-abcde-67890-fghij"
            - name: X-Client-Version
              value: "1.2.3"
  operations:
    - method: GET
      path: /{country_code}/{city}
```

### Example 2: Static — setting response headers for security

```yaml
policies:
  - name: set-headers
    version: v1
    params:
      response:
        headers:
          - name: X-Content-Type-Options
            value: "nosniff"
          - name: X-Frame-Options
            value: "DENY"
          - name: X-XSS-Protection
            value: "1; mode=block"
```

### Example 3: Append mode

Set `mode: append` to add values without removing values already present. Useful for multi-valued headers such as `Vary`, `Via`, or custom headers that accumulate context:

```yaml
policies:
  - name: set-headers
    version: v1
    params:
      mode: append
      request:
        headers:
          - name: Via
            value: "1.1 api-gateway"
      response:
        headers:
          - name: Vary
            value: "Accept-Encoding"
```

### Example 4: Forward subscription plan name to upstream

After `subscription-validation` runs, the resolved plan name is available as `${meta.x-wso2-subscription-plan-name}`. Forward it to the upstream service:

```yaml
policies:
  - name: jwt-auth
    version: v1
  - name: subscription-validation
    version: v1
  - name: set-headers
    version: v1
    params:
      request:
        headers:
          - name: x-subscription-plan
            value: "${meta.x-wso2-subscription-plan-name}"
          - name: x-billing-customer-id
            value: "${meta.x-wso2-billing-customer-id}"
```

`subscription-validation` must run before `set-headers` so that `x-wso2-subscription-plan-name` and related metadata keys are populated.

**Result (upstream request receives):**
```
x-subscription-plan: gold
x-billing-customer-id: cust-4821
```

### Example 5: Provider credential relay

Forward a caller-supplied credential header as the upstream `Authorization` and remove the original so it is not visible to the upstream service:

```yaml
policies:
  - name: jwt-auth
    version: v1
  - name: set-headers
    version: v1
    params:
      request:
        headers:
          - name: authorization
            value: "${req.header.x-provider-authorization}"
            removeSource: true
```

### Example 6: Promote upstream response header to client

Forward an internal trace ID from the upstream response as a standard correlation header, then strip the internal header:

```yaml
policies:
  - name: set-headers
    version: v1
    params:
      response:
        headers:
          - name: X-Correlation-ID
            value: "${resp.header.x-internal-trace-id}"
            removeSource: true
```

### Example 7: Mixed literal and expression

```yaml
policies:
  - name: set-headers
    version: v1
    params:
      request:
        headers:
          - name: Authorization
            value: "Bearer ${req.header.x-provider-token}"
            removeSource: true
```

### Example 8: Both phases simultaneously

```yaml
policies:
  - name: set-headers
    version: v1
    params:
      request:
        headers:
          - name: Authorization
            value: "${req.header.x-provider-authorization}"
            removeSource: true
          - name: x-subscription-plan
            value: "${meta.x-wso2-subscription-plan-name}"
      response:
        headers:
          - name: X-Served-By
            value: "internal-gateway"
```

### Example 9: Route-specific headers

Apply different headers to different routes:

```yaml
operations:
  - method: GET
    path: /{country_code}/{city}
    policies:
      - name: set-headers
        version: v1
        params:
          request:
            headers:
              - name: X-Operation-Type
                value: "weather-query"
  - method: POST
    path: /alerts/active
    policies:
      - name: set-headers
        version: v1
        params:
          request:
            headers:
              - name: X-Operation-Type
                value: "alert-create"
```

## Metadata keys written by platform policies

These keys are written to `SharedContext.Metadata` by their respective policies and are readable via `${meta.<key>}`:

| Key | Written by | Value |
|---|---|---|
| `x-wso2-subscription-plan-name` | `subscription-validation` | Subscription plan name (e.g. `gold`, `silver`). Requires subscription-validation v1.0.2 or later. |
| `x-wso2-application-id` | `jwt-auth` / `api-key-auth` | API consumer application ID |
| `x-wso2-billing-customer-id` | `subscription-validation` | Billing customer ID (if set on the subscription). |
| `x-wso2-billing-subscription-id` | `subscription-validation` | Billing subscription ID (if set on the subscription). |
| `x-wso2-subscription-status` | `subscription-validation` | Subscription status (e.g. `ACTIVE`). |

## How it works

1. The policy reads the `mode` parameter (defaulting to `set`) to decide whether configured values overwrite or append.
2. It processes `request.headers` and `response.headers` arrays independently.
3. For each header entry:
   - **Static value** (no `${...}`): applied using the configured `mode` (set or append). Never removed.
   - **Dynamic value** (contains `${...}`): each expression is resolved from the matching source (request headers, response headers, or metadata). If any expression fails to resolve — source absent, unrecognised scope, or unclosed delimiter — the target header is **removed** from the upstream request or downstream response to prevent a client-supplied value from reaching the backend.
4. When `removeSource: true`:
   - **Request phase:** `${req.header.<name>}` source headers are removed from the upstream request.
   - **Response phase:** `${resp.header.<name>}` source headers are removed from the downstream response. `${req.header}` and `${meta}` sources are never removed in this phase.
5. A header that is being set by this policy is never simultaneously removed (self-remove protection).
6. Header names are normalized (trimmed, lowercased) before being set or removed.

## Policy ordering

Place `set-headers` **after** any policy that writes to `SharedContext.Metadata` it needs to read. The typical order for subscription-aware APIs:

```
jwt-auth → subscription-validation → set-headers → dynamic-endpoint
```

## Limitations

1. **Policy-wide mode**: `mode` applies to the entire policy instance. Mixing set and append within one instance is not supported — attach the policy multiple times if needed.
2. **No conditional logic**: Value resolution is unconditional — entries either set or remove based on source presence.
3. **`${resp.header.*}` not allowed in request phase**: Entries using this scope in `request.headers` are rejected at configuration time.
4. **Response phase `removeSource` limited to `${resp.header.*}`**: Request headers and metadata keys cannot be removed in the response phase.
5. **At least one phase required**: Specifying neither `request` nor `response` fails validation.

## Security notes

- Use `removeSource: true` for any header carrying a credential or routing token that should not be visible to the upstream service.
- When a dynamic expression fails to resolve, the target header is actively **removed** — not merely skipped — to prevent a caller from pre-setting the target with a spoofed value.
- `${meta.<key>}` values are written by the gateway; they originate from validated JWT claims or the subscription store and are authoritative. Do not confuse them with request headers that a client could supply.
- Avoid placing long-lived secrets in API definition YAML; prefer per-request relay patterns over static credential injection.
