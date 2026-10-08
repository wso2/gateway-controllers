---
title: "Overview"
---
# Rate Limiting (Advanced)

## Overview

The Rate Limiting policy controls the rate of requests to your APIs by enforcing configurable limits based on various criteria. This policy is essential for protecting backend services from overload, ensuring fair usage, and maintaining service availability.

## Features

- Multiple rate limiting algorithms (GCRA, Fixed Window)
- Weighted rate limiting via cost parameter
- Post-response cost extraction for dynamic rate limiting (e.g., LLM token usage)
- Multiple concurrent limits (e.g., 10/second AND 1000/hour)
- Flexible key extraction (headers, metadata, auth-context/JWT properties, IP, API name, route name)
- Conditional key matching — restrict a quota to requests whose key component matches a pattern; non-matching requests bypass the quota entirely, with no counting or enforcement
- Three storage backends: in-memory (single instance), Redis (distributed, exact), or Redis-local-async (distributed, local-first counting with asynchronous Redis reconcile — lower per-request latency and Redis load, with a small bounded overshoot)
- Shared Redis client across all rate-limit policy instances (one connection pool per Redis endpoint per replica)
- Graceful degradation with fail-open/fail-closed modes for Redis failures
- Comprehensive rate limit headers (X-RateLimit-*, IETF RateLimit, Retry-After)
- Customizable error responses

## Configuration

The Rate Limiting policy uses a two-level configuration

### System Parameters (From config.toml)

These parameters are set by the administrator and apply globally to all rate limiting policies:

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `algorithm` | string | No | `"fixed-window"` | Rate limiting algorithm: `"gcra"` (smooth rate limiting with burst support) or `"fixed-window"` (simple counter per time window). |
| `backend` | string | No | `"memory"` | Storage backend: `"memory"` (single-instance), `"redis"` (distributed, exact — one Redis call per request), or `"redis-local-async"` (distributed, local-first hot path that reconciles to Redis asynchronously every `local.syncInterval`; lower per-request latency and Redis load, at the cost of a small bounded overshoot). |
| `redis` | ```Redis``` object | No | - | Redis configuration (used when `backend=redis` or `backend=redis-local-async`). |
| `memory` | ```Memory``` object | No | - | In-memory storage configuration (only used when `backend=memory`). |
| `local` | ```Local``` object | No | - | Local-first hot-path configuration (only used when `backend=redis-local-async`). |
| `headers` | ```Headers``` object | No | - | Control which rate limit headers are included in responses. |

#### Redis Configuration

When using the `redis` or `redis-local-async` backend, the following parameters can be configured under `redis`:

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `host` | string | No | `"localhost"` | Redis server hostname or IP address. |
| `port` | integer | No | `6379` | Redis server port. |
| `password` | string | No | `""` | Redis authentication password (optional). |
| `username` | string | No | `""` | Redis ACL username (optional, Redis 6+). |
| `db` | integer | No | `0` | Redis database number (0-15). |
| `keyPrefix` | string | No | `"ratelimit:v1:"` | Prefix for all Redis keys to avoid conflicts. |
| `failureMode` | string | No | `"open"` | Behavior when Redis is unavailable: `"open"` allows requests through, `"closed"` denies requests. |
| `connectionTimeout` | string | No | `"5s"` | Redis connection timeout (Go duration string). |
| `readTimeout` | string | No | `"3s"` | Redis read timeout (Go duration string). |
| `writeTimeout` | string | No | `"3s"` | Redis write timeout (Go duration string). |
| `poolSize` | integer | No | `0` | Connection pool size for the shared Redis client (`0` = go-redis default, 10 × GOMAXPROCS). One pool is shared per distinct Redis endpoint across all rate-limit policy instances and reloads, so size it for the gateway, not per route. |


#### Redis TLS Configuration

To connect to Redis over TLS (TLS 1.2 or later), configure the following under `redis.tls`. TLS is disabled by default.

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `enabled` | boolean | No | `false` | Connects to Redis over TLS when `true`. The other `tls` parameters are ignored when `false`. |
| `caFile` | string | No | `""` | Path to a PEM CA bundle used to verify the Redis server certificate. Empty uses the system trust store (suitable for public CAs, such as managed cloud Redis); set it for a private CA. |
| `serverName` | string | No | `""` | Server name to verify against the Redis certificate. Empty uses `host`. Set it when connecting by IP or by an alias that is not on the certificate. |
| `insecureSkipVerify` | boolean | No | `false` | Disables verification of the Redis server certificate. For testing only; a warning is logged when enabled. |
| `certFile` | string | No | `""` | Path to a PEM client certificate for mutual TLS. Must be set together with `keyFile`. |
| `keyFile` | string | No | `""` | Path to the PEM private key for `certFile`. Must be set together with `certFile`. |

All files are read and validated when the policy is created: a missing file, a CA file without valid PEM certificates, or a mismatched certificate and key fails policy creation regardless of `failureMode`. File paths are resolved inside the gateway runtime container, so the files must be mounted there. Rotated certificates take effect on the next configuration reload or restart.

#### Memory Configuration

When using in-memory backend, the following parameters can be configured under `memory`:

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `maxEntries` | integer | No | `10000` | Maximum number of rate limit entries to store. Oldest entries are evicted when limit is reached. |
| `cleanupInterval` | string | No | `"5m"` | Interval for cleaning up expired entries. Use `"0"` to disable periodic cleanup. |

#### Local Configuration

When using the `redis-local-async` backend, the following parameters tune the local-first hot path under `local`. Each gateway replica counts requests in memory (no Redis call on the request path) and flushes accumulated deltas to the same Redis key the `redis` backend uses every `syncInterval`, then reads back the authoritative count — so all replicas converge on one shared quota with a bounded overshoot of approximately `(replicas - 1) × rate × syncInterval`:

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `syncInterval` | string | No | `"50ms"` | How often locally counted requests are flushed to Redis and the authoritative count is read back (Go duration string). Lower values tighten accuracy (less overshoot) at the cost of more frequent flushes. |
| `flushWorkers` | integer | No | `0` | Number of background flush workers shared by all redis-local-async limiters in the process. `0` = auto (GOMAXPROCS/2, capped at 8). Only the first registrant's value takes effect; a restart is required to change it. |
| `maxPipelineCommands` | integer | No | `5000` | Maximum `INCRBY`s issued in a single Redis pipeline per flush; excess dirty keys spill to the next flush tick. |
| `maxLocalEntries` | integer | No | `100000` | Maximum local key-state entries per limiter before eviction (carrying any unflushed delta to Redis). Bounds memory under high or adversarial key cardinality. |

The `failureMode` from the `redis` block applies: on a Redis outage, `open` degrades to per-replica enforcement (not unlimited) and `closed` denies after a short streak of failed flushes. Cost-extraction quotas (token / LLM-cost) delegate to the synchronous Redis path even under `redis-local-async`.

#### Headers Configuration

Control which rate limit headers are included in responses under `headers`:

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `includeXRateLimit` | boolean | No | `true` | Include X-RateLimit-* headers (X-RateLimit-Limit, X-RateLimit-Remaining, X-RateLimit-Reset). |
| `includeIETF` | boolean | No | `true` | Include IETF RateLimit headers (RateLimit-Limit, RateLimit-Remaining, RateLimit-Reset, RateLimit-Policy). |
| `includeRetryAfter` | boolean | No | `true` | Include Retry-After header when rate limited (RFC 7231). Only set on 429 responses. |

### User Parameters (API Definition)

These parameters are configured per-API/route by the API developer:

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `quotas` | `Quota` array | Yes | - | Defines quota entries (1-10). Each quota applies independent limits with its own `keyExtraction` and `costExtraction` settings. |
| `keyExtraction` | `KeyExtraction` array | No | `[{type: "routename"}]` | Global key extraction applied to quotas that do not define their own `keyExtraction`. Defaults to `routename` if omitted. |
| `onRateLimitExceeded` | `onRateLimitExceeded` object | No | - | Customizes the response returned when a request exceeds rate limits. |

#### Quota Configuration

Each entry in the `quotas` array defines an independent rate limit bucket:

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `name` | string | No | - | Quota name used in logs and `X-RateLimit-Quota` response headers (1-128 chars). |
| `limits` | `Limit` array | Yes | - | One or more limit windows for the quota (1-10). The strictest limit is enforced. |
| `keyExtraction` | `KeyExtraction` array | No | - | Per-quota key extraction. Overrides the global `keyExtraction` when set. |
| `costExtraction` | `CostExtraction` object | No | - | Per-quota dynamic cost extraction from request or response data. |

#### Limit Configuration

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `limit` | integer | Yes | - | Maximum number of requests or tokens allowed in the duration (1-1,000,000,000). |
| `duration` | string | Yes | - | Time window for the limit (Go duration format: `"1s"`, `"1m"`, `"1h"`, `"24h"`). |
| `burst` | integer | No | Same as `limit` | Maximum burst capacity (GCRA only). Number of requests that can accumulate (1-1,000,000,000). |

#### KeyExtraction Configuration

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `type` | string | Yes | Type of component: `"header"`, `"metadata"`, `"authproperty"`, `"ip"`, `"apiname"`, `"apiversion"`, `"routename"`, `"cel"`, `"constant"`. |
| `key` | string | Conditional | Header name, metadata key, auth property (claim) name, or fixed value. Required for `header`, `metadata`, `authproperty`, and `constant` types (1-256 chars); for `constant`, `key` is the fixed value itself. |
| `expression` | string | Conditional | CEL expression returning a string. Required for `cel` type (1-1024 chars). |
| `match` | `Match` object | No | Optional match condition gating this component. See **Match Configuration** below. |

**Key extraction types:**
- `header`: Extract from HTTP header (requires `key` field)
- `metadata`: Extract from SharedContext.Metadata (requires `key` field)
- `authproperty`: Extract from SharedContext.AuthContext.Properties — a claim resolved by an earlier auth policy such as `jwt-auth` (requires `key` field, the claim name)
- `ip`: Extract client IP from X-Forwarded-For/X-Real-IP headers
- `apiname`: Use API name from context
- `apiversion`: Use API version from context
- `routename`: Use route name from metadata (default)
- `cel`: Evaluate a CEL expression returning a string (requires `expression` field)
- `constant`: Use a fixed constant string value (requires `key` field)

> **Important: Component Order Matters**
>
> The order of components in the `keyExtraction` array affects the generated rate limit key. Components are joined with `:` separator in the exact order specified:
>
> ```yaml
> # Example 1: User ID then IP
> keyExtraction:
>   - type: header
>     key: X-User-ID
>   - type: ip
> # Generates key: "user123:192.168.1.1"
> ```
>
> ```yaml
> # Example 2: IP then User ID (different from Example 1!)
> keyExtraction:
>   - type: ip
>   - type: header
>     key: X-User-ID
> # Generates key: "192.168.1.1:user123"
> ```
>
> These are treated as **different rate limit buckets** with separate counters. If you change the component order in your configuration, it will effectively reset all rate limit counters for that policy.
>
> **Best Practice:** Maintain consistent component ordering across all environments and configuration updates to avoid unexpected rate limit resets.

> **Important: authproperty vs. header/metadata**
>
> `authproperty` reads a value already resolved by an earlier authentication policy — for example, `jwt-auth` extracts every non-standard JWT claim into `AuthContext.Properties[claimName]` automatically, for every successfully authenticated request, regardless of any optional auth-policy configuration. This is the only `keyExtraction` type that can reach a JWT claim that isn't also forwarded as a header or written to `SharedContext.Metadata` — `header` and `metadata` cannot see it. Use `authproperty` when the value you want to key or filter by only exists inside a verified token, not on the wire as a plain header.

#### Match Configuration

Restricts a quota to requests whose key component matches a pattern. This is different from key extraction itself: key extraction decides *which bucket* a request counts against; `match` decides *whether the quota applies to the request at all*.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `type` | string | Yes | Match type. Currently only `"regex"` is supported. |
| `value` | string | Yes | Regex pattern matched against the component's extracted value (1-1024 chars). |

> **Important: A Non-Matching Request Bypasses the Quota Entirely**
>
> If a `keyExtraction` component's `match` does not match the extracted value, the **entire quota** is skipped for that request — it is not counted and cannot be throttled by that quota, as if the quota were not configured at all. If multiple components in the same quota declare a `match`, all of them must match (logical AND) for the quota to apply.
>
> This is intentionally different from the missing-value placeholder behavior of plain key extraction (e.g. `_missing_header_X_`) — a non-matching value does not become its own counted bucket; it opts the request out of the quota entirely.
>
> Changing a `match` pattern changes the underlying cache key for the quota, so existing counters are reset when the pattern is edited — the same behavior as changing `keyExtraction` component order or type.

#### CostExtraction Configuration

Configures per-quota dynamic cost extraction from request or response data. Values from all successful sources are summed (after applying multipliers). If all sources fail, the `default` cost is used.

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `enabled` | boolean | No | `false` | Enables dynamic cost extraction for the quota. |
| `sources` | `Source` array | Yes (if enabled) | - | Cost extraction sources (1-10). Successful values are summed with multipliers applied. |
| `default` | number | No | `1` | Fallback cost when all source extractions fail (0 to 1,000,000,000). |

**Source Configuration:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `type` | string | Yes | Source type. See **Source Types** below. |
| `key` | string | Conditional | Header name or metadata key. Required for `request_header`, `request_metadata`, `response_header`, `response_metadata` types (1-256 chars). |
| `jsonPath` | string | Conditional | JSONPath expression. Required for `request_body` and `response_body` types (1-512 chars). |
| `expression` | string | Conditional | CEL expression returning a numeric result. Required for `request_cel` and `response_cel` types (1-1024 chars). |
| `multiplier` | number | No | Multiplier applied to the extracted value (default: `1.0`, minimum 0). |

**Source Types:**

- `request_header`: Extract cost from a request header
- `request_metadata`: Extract cost from request shared metadata
- `request_body`: Extract cost from request JSON body using JSONPath
- `response_header`: Extract cost from a response header
- `response_metadata`: Extract cost from response shared metadata
- `response_body`: Extract cost from response JSON body using JSONPath
- `request_cel`: Evaluate a CEL expression on request data (numeric result)
- `response_cel`: Evaluate a CEL expression on response data (numeric result)

> **Important: Post-Response Rate Limiting Behavior**
>
> When `costExtraction.enabled: true`:
> - A **pre-flight quota check** is performed: if the key's remaining quota is already exhausted (≤ 0), the request is blocked with a 429 response
> - If quota is available, the request proceeds to upstream without consuming tokens
> - Cost is extracted from the response and consumed **after** the response is received
> - If the rate limit is exceeded post-response, the **current request has already succeeded**, but headers indicate quota exhaustion
> - **Subsequent requests** using the same key will be impacted by the consumed quota
>
> This model is appropriate for:
> - Use cases where cost is only known after the operation completes (e.g., LLM token usage)
> - Usage tracking with pre-flight protection against fully exhausted quotas

#### RateLimitExceeded Configuration

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `statusCode` | integer | No | `429` | HTTP status code for rate limit response (400-599). |
| `body` | string | No | `{"error": "Too Many Requests", "message": "Rate limit exceeded. Please try again later."}` | Custom error message body. |
| `bodyFormat` | string | No | `"json"` | Response body content type: `"json"` or `"plain"`. |

#### Sample System Configuration

##### Memory Backend Configuration

```toml
[policy_configurations.ratelimit_v1]
algorithm = "fixed-window"
backend = "memory"

[policy_configurations.ratelimit_v1.memory]
max_entries = 10000
cleanup_interval = "5m"

[policy_configurations.ratelimit_v1.headers]
include_x_rate_limit = true
include_ietf = true
include_retry_after = true
```

##### Redis Backend Configuration

For distributed rate limiting across multiple gateway instances:

```toml
[policy_configurations.ratelimit_v1]
algorithm = "fixed-window"
backend = "redis"

[policy_configurations.ratelimit_v1.redis]
host = "redis.example.com"
port = 6379
password = "your-redis-password"
db = 0
key_prefix = "ratelimit:v1:"
failure_mode = "open"
connection_timeout = "5s"
read_timeout = "3s"
write_timeout = "3s"

[policy_configurations.ratelimit_v1.headers]
include_x_rate_limit = true
include_ietf = true
include_retry_after = true
```

##### Redis Backend over TLS

For a Redis server that only accepts TLS connections, add a `tls` block under the Redis configuration. Omit `ca_file` when the server certificate is issued by a public CA:

```toml
[policy_configurations.ratelimit_v1]
algorithm = "fixed-window"
backend = "redis"

[policy_configurations.ratelimit_v1.redis]
host = "redis.example.com"
port = 6379
password = "your-redis-password"

[policy_configurations.ratelimit_v1.redis.tls]
enabled = true
ca_file = "/etc/policy-engine/certs/redis-ca.pem"
server_name = ""
insecure_skip_verify = false
# For mutual TLS, set both:
cert_file = ""
key_file = ""
```

##### Redis-local-async Backend Configuration

For distributed rate limiting with a local-first hot path — no Redis call per request, asynchronous reconcile, lower latency and Redis load, with a small bounded overshoot:

```toml
[policy_configurations.ratelimit_v1]
algorithm = "fixed-window"
backend = "redis-local-async"

[policy_configurations.ratelimit_v1.redis]
host = "redis.example.com"
port = 6379
failure_mode = "open"

[policy_configurations.ratelimit_v1.local]
sync_interval = "50ms"

[policy_configurations.ratelimit_v1.headers]
include_x_rate_limit = true
include_ietf = true
include_retry_after = true
```

**Note:**

Inside the `gateway/build.yaml`, ensure the policy module is added under `policies:`:

```yaml
- name: advanced-ratelimit
  gomodule: github.com/wso2/gateway-controllers/policies/advanced-ratelimit@v1
```

## Reference Scenarios

### Example 1: Basic Rate Limiting

Apply a simple rate limit to an API:

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
  operations:
    - method: GET
      path: /{country_code}/{city}
      policies:
        - name: advanced-ratelimit
          version: v1
          params:
            quotas:
              - limits:
                  - limit: 10
                    duration: "1m"
    - method: GET
      path: /alerts/active
```

### Example 2: Multiple Time Windows

Enforce multiple rate limits simultaneously (e.g., per-second and per-hour):

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
  operations:
    - method: GET
      path: /{country_code}/{city}
      policies:
        - name: advanced-ratelimit
          version: v1
          params:
            quotas:
              - limits:
                  - limit: 10
                    duration: "1m"
                  - limit: 20
                    duration: "1h"
    - method: GET
      path: /alerts/active
```

### Example 3: Per-User Rate Limiting

Rate limit based on user identity from a header:

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
  operations:
    - method: GET
      path: /{country_code}/{city}
      policies:
        - name: advanced-ratelimit
          version: v1
          params:
            quotas:
              - limits:
                  - limit: 10
                    duration: "1m"
                keyExtraction:
                  - type: header
                    key: X-User-ID
    - method: GET
      path: /alerts/active
```

### Example 4: Per-IP Rate Limiting

Rate limit based on client IP address:

```yaml
apiVersion: gateway.api-platform.wso2.com/v1
kind: RestApi
metadata:
  name: public-api-v1.0
spec:
  displayName: Public-API
  version: v1.0
  context: /public
  upstream:
    main:
      url: https://public-service:8080
  policies:
    - name: advanced-ratelimit
      version: v1
      params:
        quotas:
          - limits:
              - limit: 60
                duration: "1m"
            keyExtraction:
              - type: ip
  operations:
    - method: GET
      path: /data
    - method: POST
      path: /submit
```

### Example 5: Composite Key Rate Limiting

Rate limit based on multiple factors (API name + user ID):

```yaml
apiVersion: gateway.api-platform.wso2.com/v1
kind: RestApi
metadata:
  name: multi-tenant-api-v1.0
spec:
  displayName: Multi-Tenant-API
  version: v1.0
  context: /tenant
  upstream:
    main:
      url: https://tenant-service:8080
  policies:
    - name: advanced-ratelimit
      version: v1
      params:
        quotas:
          - limits:
              - limit: 500
                duration: "1h"
            keyExtraction:
              - type: apiname
              - type: header
                key: X-Tenant-ID
  operations:
    - method: GET
      path: /resources
    - method: POST
      path: /resources
```

### Example 6: Multi-Quota Rate Limiting

Apply multiple independent quotas with separate limits and key extraction:

```yaml
apiVersion: gateway.api-platform.wso2.com/v1
kind: RestApi
metadata:
  name: analytics-api-v1.0
spec:
  displayName: Analytics-API
  version: v1.0
  context: /analytics
  upstream:
    main:
      url: https://analytics-service:8080
  policies:
    - name: advanced-ratelimit
      version: v1
      params:
        quotas:
          - name: per-user
            limits:
              - limit: 1000
                duration: "1h"
            keyExtraction:
              - type: header
                key: X-User-ID
          - name: global
            limits:
              - limit: 10000
                duration: "1h"
            keyExtraction:
              - type: routename
  operations:
    - method: GET
      path: /query
    - method: POST
      path: /report
```

### Example 7: Burst Rate Limiting with GCRA

Allow burst traffic with GCRA algorithm:

```yaml
apiVersion: gateway.api-platform.wso2.com/v1
kind: RestApi
metadata:
  name: burst-api-v1.0
spec:
  displayName: Burst-API
  version: v1.0
  context: /burst
  upstream:
    main:
      url: https://burst-service:8080
  policies:
    - name: advanced-ratelimit
      version: v1
      params:
        quotas:
          - limits:
              - limit: 10
                duration: "1s"
                burst: 20
  operations:
    - method: GET
      path: /data
    - method: POST
      path: /data
```

### Example 8: Custom Error Response

Customize the rate limit exceeded response:

```yaml
apiVersion: gateway.api-platform.wso2.com/v1
kind: RestApi
metadata:
  name: custom-error-api-v1.0
spec:
  displayName: Custom-Error-API
  version: v1.0
  context: /custom
  upstream:
    main:
      url: https://backend-service:8080
  policies:
    - name: advanced-ratelimit
      version: v1
      params:
        quotas:
          - limits:
              - limit: 100
                duration: "1m"
        onRateLimitExceeded:
          statusCode: 429
          body: '{"code": "RATE_LIMIT_EXCEEDED", "message": "You have exceeded the rate limit. Please wait before making more requests.", "retryAfter": "60s"}'
          bodyFormat: json
  operations:
    - method: GET
      path: /resource
```

### Example 9: LLM Token-Based Rate Limiting (Post-Response Cost Extraction)

Rate limit based on actual token usage from an LLM API response:

```yaml
apiVersion: gateway.api-platform.wso2.com/v1
kind: RestApi
metadata:
  name: llm-api-v1.0
spec:
  displayName: LLM-API
  version: v1.0
  context: /llm
  upstream:
    main:
      url: https://llm-service:8080
  policies:
    - name: advanced-ratelimit
      version: v1
      params:
        quotas:
          - limits:
              - limit: 100000
                duration: "24h"
            keyExtraction:
              - type: header
                key: X-User-ID
            costExtraction:
              enabled: true
              sources:
                - type: response_header
                  key: X-Token-Usage
                - type: response_body
                  jsonPath: "$.usage.total_tokens"
              default: 100
  operations:
    - method: POST
      path: /chat/completions
    - method: POST
      path: /completions
```

### Example 10: Compute Unit Rate Limiting with Fallback Sources

Rate limit based on compute units with multiple extraction sources:

```yaml
apiVersion: gateway.api-platform.wso2.com/v1
kind: RestApi
metadata:
  name: compute-api-v1.0
spec:
  displayName: Compute-API
  version: v1.0
  context: /compute
  upstream:
    main:
      url: https://compute-service:8080
  policies:
    - name: advanced-ratelimit
      version: v1
      params:
        quotas:
          - limits:
              - limit: 1000
                duration: "1h"
            costExtraction:
              enabled: true
              sources:
                - type: response_header
                  key: X-Compute-Units
                - type: response_metadata
                  key: compute_units
                - type: response_body
                  jsonPath: "$.metrics.compute_units"
              default: 1
  operations:
    - method: POST
      path: /process
    - method: POST
      path: /analyze
```

### Example 11: Conditional Rate Limiting by Client ID Pattern

Apply a quota only to requests whose client ID matches a pattern (e.g. only throttle guest and channel-partner applications on a specific operation; other client IDs bypass this quota entirely):

```yaml
apiVersion: gateway.api-platform.wso2.com/v1
kind: RestApi
metadata:
  name: hotel-booking-api-v1.0
spec:
  displayName: Hotel-Booking-API
  version: v1.0
  context: /booking
  upstream:
    main:
      url: https://booking-service:8080
  operations:
    - method: POST
      path: /checkout
      policies:
        - name: advanced-ratelimit
          version: v1
          params:
            quotas:
              - name: guest-and-partner-checkout
                limits:
                  - limit: 100
                    duration: "1m"
                keyExtraction:
                  - type: header
                    key: X-App-ID
                    match:
                      type: regex
                      value: "^(guest-.*|channel-partner)$"
    - method: GET
      path: /availability
```

With this configuration, a request with `X-App-ID: guest-42` or `X-App-ID: channel-partner` is counted against the 100/minute quota. A request with any other `X-App-ID` (e.g. an internal application) is not counted or throttled by this quota at all — it is treated as if the quota were not configured.

### Example 12: Conditional Rate Limiting by a JWT Claim (authproperty + match)

The same conditional-throttling need as Example 11, but for an application ID that is only available as a custom claim inside a JWT — not sent as a header. Combines `authproperty` (to reach the claim) with `match` (to apply the quota only to matching applications). Requires `jwt-auth` (or another auth policy that populates `AuthContext.Properties`) to run before `advanced-ratelimit` in the policy chain:

```yaml
apiVersion: gateway.api-platform.wso2.com/v1
kind: RestApi
metadata:
  name: hotel-booking-api-v1.0
spec:
  displayName: Hotel-Booking-API
  version: v1.0
  context: /booking
  upstream:
    main:
      url: https://booking-service:8080
  operations:
    - method: POST
      path: /checkout
      policies:
        - name: jwt-auth
          version: v1
        - name: advanced-ratelimit
          version: v1
          params:
            quotas:
              - name: guest-and-partner-checkout
                limits:
                  - limit: 100
                    duration: "1m"
                keyExtraction:
                  - type: authproperty
                    key: app_id
                    match:
                      type: regex
                      value: "^(guest-.*|channel-partner)$"
    - method: GET
      path: /availability
```

`jwt-auth` validates the token and automatically extracts the `app_id` claim into `AuthContext.Properties` (no extra auth-policy configuration needed). `advanced-ratelimit` then reads `app_id` from there: a request whose claim matches `guest-*` or `channel-partner` is counted against the 100/minute quota and bucketed per application; a request with any other `app_id` is not counted or throttled by this quota at all — the claim never needs to be forwarded as a header for this to work.

## How it Works

### GCRA (Generic Cell Rate Algorithm)

- Token bucket semantics with smooth rate limiting
- **Best for**: Smooth traffic shaping, burst handling, consistent rate enforcement
- **Advantages**: Prevents traffic bursts at window boundaries, supports burst capacity
- **Use when**: You need consistent rate enforcement and burst tolerance

### Fixed Window

- Divides time into fixed intervals and counts requests per window
- **Best for**: Simple counting, lower computational overhead
- **Advantages**: Simple to understand, lower memory overhead
- **Limitation**: Can allow up to 2x burst at window boundaries
- **Use when**: Simplicity is preferred and boundary bursts are acceptable


## Notes:

When rate limiting is applied, the following headers may be included in responses:

### X-RateLimit Headers (Industry Standard)

| Header | Description |
|--------|-------------|
| `X-RateLimit-Limit` | Maximum requests allowed in the current window |
| `X-RateLimit-Remaining` | Remaining requests in the current window |
| `X-RateLimit-Reset` | Unix timestamp when the rate limit resets |

### IETF RateLimit Headers (Draft Standard)

| Header | Description |
|--------|-------------|
| `RateLimit-Limit` | Maximum requests allowed in the current window |
| `RateLimit-Remaining` | Remaining requests in the current window |
| `RateLimit-Reset` | Seconds until the rate limit resets |
| `RateLimit-Policy` | Rate limit policy description |

### Retry-After Header (RFC 7231)

| Header | Description |
|--------|-------------|
| `Retry-After` | Seconds to wait before retrying (only on 429 responses) |
