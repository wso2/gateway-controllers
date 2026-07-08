---
title: "Overview"
---
# Log Message

## Overview

The Log Message policy logs the payload and headers of request/response messages for
observability and debugging, without modifying the actual traffic. It supports separate
configuration for the request and response flows.

As of v1.1 the policy has an **`enableTrafficLogging`** parameter that selects *where* the log
is produced:

- **`false`** (default) — inline logging in real time during mediation via the gateway's
  structured logs (`slog`), including per-chunk streaming (SSE). This is the original v1.0
  behavior and has **no dependency** on the gateway collector or analytics pipeline.
- **`true`** — opts the API into **stdout traffic logging**. The policy stops logging inline
  and instead marks the API; the gateway's traffic-logging publisher then emits a single JSON
  line per request/response on the Envoy access-log side, **enriched with access-log-derived
  latencies** (`requestMediationLatency`, `backendLatency`, `responseLatency`,
  `responseMediationLatency`) that are not available to inline policies.

## Features

- **Two modes**: real-time inline logging (default), or traffic-logging enrichment with
  latencies (`enableTrafficLogging: true`).
- **Configurable logging**: control payload and header logging independently per flow.
- **Header handling**: `Authorization` is masked by default; in inline mode `excludeHeaders`
  omits additional headers per flow; in traffic-logging mode header exclusion is done via
  `fields`.
- **Streaming support (inline)**: logs streaming (SSE) chunks independently as they arrive.
- **Traffic-logging enrichment**: in `enableTrafficLogging` mode the emitted line includes
  latencies, response code, timestamp, IP, and sizes — fields inline logging cannot see.
- **Non-intrusive**: never modifies or blocks request/response data.

## Configuration

### User Parameters (API Definition)

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `enableTrafficLogging` | boolean | No | `false` | Where the log is produced: `false` (inline, real-time, during mediation) or `true` (single enriched line via the traffic-logging publisher after the response). |
| `request` | object | No* | - | Configuration for request logging. |
| `request.payload` | boolean | No | `false` | Log the request payload. In traffic-logging mode this includes the payload only if the collector captured it. |
| `request.headers` | boolean | No | `false` | Log the request headers. In traffic-logging mode this includes headers only if the collector captured them. |
| `request.excludeHeaders` | array | No | `[]` | **(inline only)** Header names to exclude from request logging when `request.headers` is enabled. Case-insensitive; matched headers are omitted entirely. In traffic-logging mode, exclude headers via `fields` instead. |
| `response` | object | No* | - | Configuration for response logging. |
| `response.payload` | boolean | No | `false` | Log the response payload (see `request.payload` for traffic-logging semantics). |
| `response.headers` | boolean | No | `false` | Log the response headers (see `request.headers` for traffic-logging semantics). |
| `response.excludeHeaders` | array | No | `[]` | **(inline only)** Header names to exclude from response logging when `response.headers` is enabled. Case-insensitive; matched headers are omitted entirely. In traffic-logging mode, exclude headers via `fields` instead. |
| `fields` | object | No | - | **(traffic-logging only)** Explicit selection of which fields appear in the emitted line. When set, it is **authoritative** over field presence (see [Field selection](#field-selection-traffic-logging-only)). |
| `fields.only` | array | No | `[]` | Keep exactly these field names and drop everything else. Set either `only` or `exclude`, not both. |
| `fields.exclude` | array | No | `[]` | Drop these field names and keep the rest. Set either `only` or `exclude`, not both. |
| `properties` | object | No | `{}` | **(traffic-logging only)** Extra key→value pairs attached under `properties` in the emitted line. String values prefixed with `$ctx:` are resolved from the request context (see [Properties](#properties-traffic-logging-only)); other values pass through. |
| `maskedHeaders` | array | No | `[]` | **(traffic-logging only)** Header names (case-insensitive) whose values are redacted with `****` in the emitted line. Merged with the global `[traffic_logging].masked_headers`. |

Field names for `fields.only`/`fields.exclude` are top-level keys (e.g. `latencies`, `target`,
`application`) or dotted paths (e.g. `properties.requestHeaders`, `request.header.<name>`).

*At least one of `request` or `response` must be provided.

### Prerequisites for traffic-logging mode

`enableTrafficLogging: true` takes effect only when **all three** hold — attaching the policy
alone is not enough:

1. `[collector].enabled = true` (the shared capture + access-log transport pipeline).
2. `[traffic_logging].enabled = true` (arms the stdout publisher).
3. The policy is attached to the API/operation with `enableTrafficLogging: true`.

> **Capture is global; presentation is per-API.** The collector captures headers/bodies
> globally, *before* any user policy runs. In traffic-logging mode the policy's parameters
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

### Example 2: Traffic-logging mode (enriched with latencies)

Emit one JSON line per request via the traffic-logging publisher, including latencies.
Requires `[collector]` and `[traffic_logging]` enabled (see Prerequisites). Header exclusion
in this mode is done via `fields` (not `excludeHeaders`):

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
        enableTrafficLogging: true
        request:
          payload: true
          headers: true
        response:
          headers: true
        fields:
          exclude:
            - request.header.x-api-key
  operations:
    - method: GET
      path: /items
    - method: POST
      path: /items
```

### Example 3: Streaming (inline only)

Inline mode logs each SSE chunk independently as it arrives (traffic-logging mode does not, as
it emits once after the response):

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

### Inline mode (default)

- Request/response payloads and headers are logged as structured JSON via `slog` at INFO
  level during mediation, tagged with the mediation flow (REQUEST/RESPONSE) and correlated by
  `x-request-id`.
- The `Authorization` header is masked with `***` by default; `excludeHeaders` omit
  additional headers entirely.
- Streaming (SSE) chunks are logged independently as they arrive, with no buffering.

### Traffic-logging mode

1. **Marker (request-header phase).** The policy runs only in the request-header phase. It
   stamps a marker (`traffic_log`) into the analytics dynamic metadata carrying its per-flow
   configuration. It buffers no body and modifies no traffic.
2. **Carried to the access log.** Envoy carries that metadata — alongside the headers/bodies
   captured by the collector — onto the HTTP access-log entry streamed to the policy engine
   after the response completes.
3. **Emitted with latencies.** The traffic-logging publisher reads the marker back: its
   presence gates emission (APIs without it are skipped) and its value shapes the line.
   Because emission is at access-log time, the line includes the Envoy-derived latencies.
4. **Shaping.** Headers/payloads not requested are omitted, the `fields` selection is applied
   (including any dotted header paths in `fields.exclude`), and the `maskedHeaders` param plus
   the gateway-wide `[traffic_logging].masked_headers` are redacted to `****`.

#### Latency fields (traffic-logging mode)

| Field | Meaning |
|-------|---------|
| `requestMediationLatency` | Gateway processing time before sending the request upstream. |
| `backendLatency` | First request byte sent upstream → last response byte received. |
| `responseLatency` | First upstream response byte → finishing the client response. |
| `responseMediationLatency` | Gateway response processing before finishing the client send. |

#### Field selection (traffic-logging only)

By default the emitted line contains the full analytics event (API/application/subscription
metadata, latencies, timing, client info, and the requested headers/payloads). Use `fields`
to control exactly which fields are printed. Set **either** `fields.only` **or**
`fields.exclude`, not both:

- `fields.only` keeps exactly the listed names and drops everything else.
- `fields.exclude` drops the listed names and keeps the rest.
- Names are **top-level keys** (`api`, `operation`, `target`, `application`, `subscription`,
  `latencies`, `metaInfo`, `proxyResponseCode`, `requestTimestamp`, `userAgentHeader`,
  `userIp`, `properties`) or **dotted paths** (`properties.requestHeaders`,
  `properties.responseHeaders`, `properties.request_payload`, `properties.response_payload`,
  `request.header.<name>`, …). Naming the whole `properties` key keeps all of its subkeys;
  a dotted header path removes/keeps just that header.
- **`fields` is authoritative over presence.** When set, the `request`/`response`
  `payload`/`headers` toggles are ignored — `fields` alone decides what appears. The
  `maskedHeaders` param and the global `masked_headers` still apply to header *values* that
  survive the selection.

```yaml
policies:
  - name: log-message
    version: v1
    params:
      enableTrafficLogging: true
      fields:
        only:
          - latencies
          - target
          - properties.requestHeaders
```

The line above contains only `latencies`, `target`, and `properties.requestHeaders` (with
`authorization` masked). To drop a single header instead, use
`fields.exclude: [request.header.x-api-key]`.

#### Properties (traffic-logging only)

`properties` adds extra key→value pairs under `properties` in the emitted line — useful for
filtering/querying logs by environment, tenant, or any request attribute. String values
prefixed with `$ctx:` are resolved from the request context at request time; other values
(including non-strings) pass through as-is. Non-resolvable references are skipped.

```yaml
params:
  enableTrafficLogging: true
  properties:
    env: production                 # literal
    request_id: "$ctx:request.id"   # resolved from context
    subject: "$ctx:auth.subject"    # requires an earlier auth policy
```

Available `$ctx:` references: `request.path`, `request.method`, `request.authority`,
`request.scheme`, `request.vhost`, `request.id`, `request.header.<name>`; `api.id`, `api.name`,
`api.version`, `api.context`, `api.kind`, `api.operation_path`; `project.id`; and (require an
earlier auth policy) `auth.subject`, `auth.type`, `auth.issuer`, `auth.credential_id`,
`auth.token_id`, `auth.authenticated`, `auth.authorized`, `auth.audience`, `auth.scopes`,
`auth.property.<claim>`.

## Limitations

1. **Traffic-logging mode requires the collector and publisher** — otherwise it is a no-op.
2. **Filter/mask only (traffic-logging)** — parameters cannot enable capture the collector did
   not perform.
3. **No real-time/streaming in traffic-logging mode** — the line is emitted once after the
   response. Use inline mode for real-time and per-chunk streaming logs.
4. **Inline memory buffering** — inline payload logging buffers bodies in memory.
5. **`excludeHeaders` is inline-only** — in traffic-logging mode use `fields` (dotted header
   paths) and `maskedHeaders` for per-header handling.
6. **Fixed field shape** — which fields appear is selectable via `fields` (traffic-logging
   mode), but the JSON structure/nesting of each field is not customizable.

## Notes

**Sensitive data**

Exclude authentication/confidential headers and evaluate payload sensitivity before logging.
In inline mode `Authorization` is masked by default and `excludeHeaders` omits additional
headers per flow; in traffic-logging mode redaction is driven by the `maskedHeaders` param
plus `[traffic_logging].masked_headers`, and headers can be dropped via `fields`. Control log
access, transmission, and retention in line with data-privacy regulations (e.g. GDPR, CCPA).

**Performance**

Payload logging adds memory/CPU per request and increases log volume. Enable it selectively,
avoid large uploads/downloads, and enforce sensible retention. Traffic-logging mode adds no
inline latency (it only stamps a marker) but still relies on the collector capturing data
globally.

## Related Policies

- **Analytics Header Filter**: Controls which headers are included in analytics/traffic-log output per API.
- **Authentication Policies**: Combine while excluding auth headers from logging.
