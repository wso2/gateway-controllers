---
title: "Overview"
---
# Basic Rate Limiting

## Overview

The Basic Rate Limiting policy provides a simplified way to control request volume and protect APIs from excessive traffic. It enforces one or more request quotas using a fixed key strategy, making it suitable for common per-route throttling scenarios without advanced key configuration.

For advanced use cases (for example, custom key extraction, weighted costs, and post-response cost extraction), use the **Advanced Rate Limiting** policy.

## Features

- **Simple Configuration**: Define only `limits` in API definitions to enable rate limiting.
- **Multiple Concurrent Limits**: Enforce multiple windows simultaneously (for example, per-second and per-hour).
- **Deterministic Keying**: Uses route-level identity by default for predictable quota behavior. When attached at the API level, uses the API name as the rate limit key.
- **Shared Engine**: Uses the same backend and algorithm capabilities as the advanced policy (`memory`/`redis`, `gcra`/`fixed-window`).
- **Distributed or Local Operation**: Supports in-memory single-instance mode and Redis-based distributed mode.
- **Operational Compatibility**: Reuses the global rate-limit system configuration in `config.toml`.

## Configuration

This policy requires two-level configuration which includes both system parameters (configured by administrators) and user parameters (configured in API definitions).

### System Parameters (From config.toml)

These parameters are configured globally and shared with the advanced rate limiting policy.

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `algorithm` | string | No | `"fixed-window"` | Rate limiting algorithm: `"gcra"` for smooth token-bucket-style throttling, or `"fixed-window"` for window-based counters. |
| `backend` | string | No | `"memory"` | Storage backend: `"memory"` for single-instance operation, or `"redis"` for distributed quotas across gateway instances. |
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

When `enabled` is `true`, all files are read and validated when the policy is created: a missing file, a CA file without valid PEM certificates, or a mismatched certificate and key fails policy creation regardless of `failureMode`. File paths are resolved inside the gateway runtime container, so the files must be mounted there. Rotated certificates take effect on the next configuration reload or restart.

#### Memory Configuration

When using in-memory backend, configure the following under `memory`:

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `maxEntries` | integer | No | `10000` | Maximum number of rate limit entries stored in memory. Old entries are evicted when this limit is reached. |
| `cleanupInterval` | string | No | `"5m"` | Interval for cleaning up expired entries (Go duration format). Use `"0"` to disable periodic cleanup. |

### User Parameters (API Definition)

This policy requires only the list of limits in the API definition.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `limits` | `Limit` array | Yes | Array of limits to enforce (1 to 10 entries). Multiple limits can be defined and all are evaluated. |

#### Limit Object

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `requests` | integer | Yes | Maximum requests allowed in the specified duration (1 to 1,000,000,000). |
| `duration` | string | Yes | Time window in Go duration format (for example, `"1s"`, `"1m"`, `"1h"`, `"24h"`). |

**Note:**

Inside the `gateway/build.yaml`, ensure the policy module is added under `policies:`:

```yaml
- name: basic-ratelimit
  gomodule: github.com/wso2/gateway-controllers/policies/basic-ratelimit@v1
```

## Reference Scenarios

### Example 1: Simple Per-Route Request Limit

Allow 1000 requests per minute for a route:

```yaml
apiVersion: gateway.api-platform.wso2.com/v1
kind: RestApi
metadata:
  name: weather-api-v1.0
spec:
  displayName: Weather API
  version: v1.0
  context: /weather/$version
  upstream:
    main:
      url: http://sample-backend:5000/api/v2
  operations:
    - method: GET
      path: /{country_code}/{city}
      policies:
        - name: basic-ratelimit
          version: v1
          params:
            limits:
              - requests: 1000
                duration: "1m"
```

### Example 2: Multiple Time Windows

Enforce a short-term burst limit and a long-term quota.
- 10 requests per second
- 500 requests per hour

```yaml
apiVersion: gateway.api-platform.wso2.com/v1
kind: RestApi
metadata:
  name: alerts-api-v1.0
spec:
  displayName: Alerts API
  version: v1.0
  context: /alerts/$version
  upstream:
    main:
      url: http://alerts-service:8080
  operations:
    - method: GET
      path: /active
      policies:
        - name: basic-ratelimit
          version: v1
          params:
            limits:
              - requests: 10
                duration: "1s"
              - requests: 500
                duration: "1h"
```

## Fault reporting

From v1.2, every rejection this policy makes is also reported to the gateway as a **fault**:
a stable code and type alongside the response. A gateway that supports fault policies uses it
for the analytics event and hands it to the API's fault policies (for example `log-message`, to
log the failure). The status and body the client receives are the same as in v1.0. A gateway
without fault policy support ignores the fault, and the policy behaves exactly as v1.0.

The limits are enforced by an `advanced-ratelimit` delegate, and the fault that delegate reports
is passed through unchanged, with its code and type.

| When | Status | Code | Type |
|------|--------|------|------|
| A limit is exceeded | `429` | the delegate's code, passed through (`900800` at the API level, `900802` at an operation) | `throttling` |

The fault's `Description` is the delegate's, for example `quota exceeded: <quota name>`. It is
passed to fault policies and analytics only, never to the client.
