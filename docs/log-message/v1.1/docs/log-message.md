---
title: "Overview"
---
# Log Message

## Overview

The Log Message policy logs the payload and headers of request/response messages for
observability and debugging, without modifying the actual traffic. It supports separate
configuration for the request and response flows.

As of v1.1 the policy has a **`destination`** parameter that selects *where* the log is
produced:

- **`inline`** (default) — logs in real time during mediation via the gateway's structured
  logs (`slog`), including per-chunk streaming (SSE). This is the original v1.0 behavior and
  has **no dependency** on the gateway collector or analytics pipeline.
- **`access-log`** — opts the API into **stdout traffic logging**. The policy stops logging
  inline and instead marks the API; the gateway's traffic-logging publisher then emits a
  single JSON line per request/response on the Envoy access-log side, **enriched with
  access-log-derived latencies** (`requestMediationLatency`, `backendLatency`,
  `responseLatency`, `responseMediationLatency`) that are not available to inline policies.

## Features

- **Two destinations**: real-time `inline` logging, or `access-log` enrichment with latencies.
- **Configurable logging**: control payload and header logging independently per flow.
- **Header handling**: exclude sensitive headers per flow; `Authorization` is masked by
  default in inline mode.
- **Streaming support (inline)**: logs streaming (SSE) chunks independently as they arrive.
- **Access-log enrichment**: in `access-log` mode the emitted line includes latencies,
  response code, timestamp, IP, and sizes — fields inline logging cannot see.
- **Non-intrusive**: never modifies or blocks request/response data.

## Configuration

### User Parameters (API Definition)

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `destination` | string | No | `inline` | Where the log is produced: `inline` (real-time, during mediation) or `access-log` (single enriched line via the traffic-logging publisher after the response). |
| `request` | object | No* | - | Configuration for request logging. |
| `request.payload` | boolean | No | `false` | Log the request payload. In `access-log` mode this includes the payload only if the collector captured it. |
| `request.headers` | boolean | No | `false` | Log the request headers. In `access-log` mode this includes headers only if the collector captured them. |
| `request.excludeHeaders` | array | No | `[]` | Header names to exclude from request logging when `request.headers` is enabled. Case-insensitive. |
| `response` | object | No* | - | Configuration for response logging. |
| `response.payload` | boolean | No | `false` | Log the response payload (see `request.payload` for `access-log` semantics). |
| `response.headers` | boolean | No | `false` | Log the response headers (see `request.headers` for `access-log` semantics). |
| `response.excludeHeaders` | array | No | `[]` | Header names to exclude from response logging when `response.headers` is enabled. Case-insensitive. |
| `fields` | object | No | - | **(access-log only)** Explicit selection of which fields appear in the emitted line. When set, it is **authoritative** over field presence (see [Field selection](#field-selection-access-log-only)). |
| `fields.mode` | string | No | `include` | `include` keeps only the listed `names`; `exclude` drops the listed `names` and keeps the rest. |
| `fields.names` | array | No | `[]` | Field names: top-level keys (e.g. `latencies`, `target`, `application`) or dotted property paths (e.g. `properties.requestHeaders`). |

*At least one of `request` or `response` must be provided.

### Prerequisites for `access-log` mode

`destination: access-log` takes effect only when **all three** hold — attaching the policy
alone is not enough:

1. `[collector].enabled = true` (the shared capture + access-log transport pipeline).
2. `[traffic_logging].enabled = true` (arms the stdout publisher).
3. The policy is attached to the API/operation with `destination: access-log`.

> **Capture is global; presentation is per-API.** The collector captures headers/bodies
> globally, *before* any user policy runs. In `access-log` mode the policy's parameters
> **filter/mask** what was captured — they cannot turn on capture (`send_request_body`,
> `send_response_headers`, …) that the collector was not configured to perform. Enable the
> matching capture flags under `[collector]` for any payloads/headers you want logged.

**Note:** Inside `gateway/build.yaml`, ensure the policy module is added under `policies:`:

```yaml
- name: log-message
  gomodule: github.com/wso2/gateway-controllers/policies/log-message@v1
```

## Reference Scenarios

### Example 1: Inline logging (default)

Log request/response payloads and headers in real time during mediation:

```yaml
apiVersion: gateway.api-platform.wso2.com/v1alpha1
kind: RestApi
metadata:
  name: user-api-v1.0
spec:
  displayName: User API
  version: v1.0
  context: /users/$version
  upstream:
    main:
      url: http://user-service:8080
  policies:
    - name: log-message
      version: v1
      params:
        request:
          payload: true
          headers: true
        response:
          payload: true
          headers: true
  operations:
    - method: POST
      path: /profile
```

### Example 2: Access-log mode (enriched with latencies)

Emit one JSON line per request via the traffic-logging publisher, including latencies.
Requires `[collector]` and `[traffic_logging]` enabled (see Prerequisites):

```yaml
apiVersion: gateway.api-platform.wso2.com/v1alpha1
kind: RestApi
metadata:
  name: orders-api-v1.0
spec:
  displayName: Orders API
  version: v1.0
  context: /orders/$version
  upstream:
    main:
      url: http://orders-service:8080
  policies:
    - name: log-message
      version: v1
      params:
        destination: access-log
        request:
          payload: true
          headers: true
          excludeHeaders:
            - X-API-Key
        response:
          headers: true
  operations:
    - method: GET
      path: /items
    - method: POST
      path: /items
```

### Example 3: Streaming (inline only)

Inline mode logs each SSE chunk independently as it arrives (access-log mode does not, as it
emits once after the response):

```yaml
apiVersion: gateway.api-platform.wso2.com/v1alpha1
kind: LlmProvider
metadata:
  name: streaming-log-provider
spec:
  displayName: Streaming Log Provider
  version: v1.0
  template: openai
  vhost: openai
  upstream:
    url: "https://api.openai.com/v1"
    auth:
      type: api-key
      header: Authorization
      value: Bearer <openai-apikey>
  policies:
    - name: log-message
      version: v1
      params:
        request:
          payload: true
        response:
          payload: true
```

## How it Works

### Inline destination (default)

- Request/response payloads and headers are logged as structured JSON via `slog` at INFO
  level during mediation, tagged with the mediation flow (REQUEST/RESPONSE) and correlated by
  `x-request-id`.
- The `Authorization` header is masked with `***` by default; `excludeHeaders` omit
  additional headers entirely.
- Streaming (SSE) chunks are logged independently as they arrive, with no buffering.

### Access-log destination

1. **Marker (request-header phase).** The policy runs only in the request-header phase. It
   stamps a marker (`traffic_log`) into the analytics dynamic metadata carrying its per-flow
   configuration. It buffers no body and modifies no traffic.
2. **Carried to the access log.** Envoy carries that metadata — alongside the headers/bodies
   captured by the collector — onto the HTTP access-log entry streamed to the policy engine
   after the response completes.
3. **Emitted with latencies.** The traffic-logging publisher reads the marker back: its
   presence gates emission (APIs without it are skipped) and its value shapes the line.
   Because emission is at access-log time, the line includes the Envoy-derived latencies.
4. **Shaping.** Headers/payloads not requested are omitted, per-flow `excludeHeaders` are
   dropped, and the gateway-wide `[traffic_logging].masked_headers` are redacted to `****`.

#### Latency fields (access-log mode)

| Field | Meaning |
|-------|---------|
| `requestMediationLatency` | Gateway processing time before sending the request upstream. |
| `backendLatency` | First request byte sent upstream → last response byte received. |
| `responseLatency` | First upstream response byte → finishing the client response. |
| `responseMediationLatency` | Gateway response processing before finishing the client send. |

#### Field selection (access-log only)

By default the emitted line contains the full analytics event (API/application/subscription
metadata, latencies, timing, client info, and the requested headers/payloads). Use `fields`
to control exactly which fields are printed:

- `fields.names` lists **top-level keys** (`api`, `operation`, `target`, `application`,
  `subscription`, `latencies`, `metaInfo`, `proxyResponseCode`, `requestTimestamp`,
  `userAgentHeader`, `userIp`, `properties`) or **dotted property paths**
  (`properties.requestHeaders`, `properties.responseHeaders`, `properties.request_payload`,
  `properties.response_payload`, `properties.responseSize`, …). Naming the whole
  `properties` key keeps all of its subkeys.
- `fields.mode = include` keeps only the listed names; `exclude` drops them and keeps the rest.
- **`fields` is authoritative over presence.** When set, the `request`/`response`
  `payload`/`headers` toggles are ignored — `fields` alone decides what appears. The
  `request`/`response` `excludeHeaders` and the global `masked_headers` still apply to header
  *values* that survive the selection.

```yaml
policies:
  - name: log-message
    version: v1
    params:
      destination: access-log
      fields:
        mode: include
        names:
          - latencies
          - target
          - properties.requestHeaders
      request:
        excludeHeaders: [x-api-key]   # still dropped from requestHeaders
```

The line above contains only `latencies`, `target`, and `properties.requestHeaders` (with
`x-api-key` removed and `authorization` masked).

## Limitations

1. **Access-log mode requires the collector and publisher** — otherwise it is a no-op.
2. **Filter/mask only (access-log)** — parameters cannot enable capture the collector did not
   perform.
3. **No real-time/streaming in access-log mode** — the line is emitted once after the
   response. Use `inline` for real-time and per-chunk streaming logs.
4. **Inline memory buffering** — inline payload logging buffers bodies in memory.
5. **Fixed field shape** — which fields appear is selectable via `fields` (access-log mode),
   but the JSON structure/nesting of each field is not customizable.

## Notes

**Sensitive data**

Exclude authentication/confidential headers and evaluate payload sensitivity before logging.
In inline mode `Authorization` is masked by default; in access-log mode redaction is driven
by `[traffic_logging].masked_headers` plus per-flow `excludeHeaders`. Control log access,
transmission, and retention in line with data-privacy regulations (e.g. GDPR, CCPA).

**Performance**

Payload logging adds memory/CPU per request and increases log volume. Enable it selectively,
avoid large uploads/downloads, and enforce sensible retention. Access-log mode adds no inline
latency (it only stamps a marker) but still relies on the collector capturing data globally.

## Related Policies

- **Analytics Header Filter**: Controls which headers are included in analytics/traffic-log output per API.
- **Authentication Policies**: Combine while excluding auth headers from logging.
