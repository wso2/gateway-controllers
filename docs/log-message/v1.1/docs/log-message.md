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
- **Header handling**: `Authorization` is masked by default; `excludeHeaders` omits additional
  headers per flow (works in both modes); in traffic-logging mode `maskedHeaders` redacts
  header values and `fields` further shapes the line.
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
| `request.excludeHeaders` | array | No | `[]` | Header names to exclude from request logging when `request.headers` is enabled (works in both modes). Case-insensitive; matched headers are omitted entirely (use `maskedHeaders` to redact the value instead). |
| `response` | object | No* | - | Configuration for response logging. |
| `response.payload` | boolean | No | `false` | Log the response payload (see `request.payload` for traffic-logging semantics). |
| `response.headers` | boolean | No | `false` | Log the response headers (see `request.headers` for traffic-logging semantics). |
| `response.excludeHeaders` | array | No | `[]` | Header names to exclude from response logging when `response.headers` is enabled (works in both modes). Case-insensitive; matched headers are omitted entirely (use `maskedHeaders` to redact the value instead). |
| `fields` | object | No | - | **(traffic-logging only)** Explicit selection of which fields appear in the emitted line. When set, it is **authoritative** over field presence (see [Field selection](#field-selection-traffic-logging-only)). |
| `fields.only` | array | No | `[]` | Keep exactly these field names and drop everything else. Set either `only` or `exclude`, not both. |
| `fields.exclude` | array | No | `[]` | Drop these field names and keep the rest. Set either `only` or `exclude`, not both. |
| `properties` | object | No | `{}` | **(traffic-logging only)** Extra key→value pairs attached under `properties` in the emitted line. String values prefixed with `$ctx:` are evaluated as a CEL expression against the request context (see [Properties](#properties-traffic-logging-only)); other values pass through. |
| `maskedHeaders` | array | No | `[]` | **(traffic-logging only)** Header names (case-insensitive) whose values are redacted with `****` in the emitted line. Merged with the global `[traffic_logging].masked_headers`. |

Field names for `fields.only`/`fields.exclude` are top-level keys (e.g. `latencies`, `target`,
`application`) or dotted sub-key paths (e.g. `requestHeaders.authorization`, `properties.env`).

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

### Policy ordering

List `log-message` first in the API/operation's `policies:` array, ahead of authentication,
rate-limiting, or any other policy that can reject the request with an immediate response
(e.g. 401, 403, 429).

Policies execute in declared order, phase by phase. If a policy short-circuits the request with
an immediate response, no later-listed policy runs — including `log-message`, whose logging
(inline mode) and traffic-log marker (traffic-logging mode) are both produced in the
request-header phase. Ordering `log-message` after a rejecting policy means rejected requests
produce no log entry at all, which is typically the opposite of what's wanted for failed
logins, rate-limit rejections, and similar signals.

The engine preserves request-header-phase analytics metadata (including the traffic-log marker)
from policies that ran *before* a short-circuit, so a preceding `log-message` still produces a
line for the rejected request, carrying the final status code. This only covers policies that
already ran, which is why `log-message` must be listed first to benefit from it.

**Exception:** `auth.*` properties (see [Properties](#properties-traffic-logging-only)) require
an auth policy to run first — the opposite ordering. There is no arrangement that satisfies
both; choose based on whether complete rejection coverage or `auth.*` enrichment matters more
for a given API.

```yaml
policies:
  - name: log-message
    version: v1
    params:
      enableTrafficLogging: true
      request:
        headers: true
  - name: jwt-auth
    version: v1
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
        enableTrafficLogging: true
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
4. **Shaping.** Headers/payloads not requested are omitted, per-flow `excludeHeaders` are
   dropped, the `maskedHeaders` param plus the gateway-wide `[traffic_logging].masked_headers`
   are redacted to `****`, and any `fields` selection is applied last.

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

- `fields.only` keeps exactly the listed names and drops everything else. (If both `only` and
  `exclude` are somehow set, `only` takes precedence.)
- `fields.exclude` drops the listed names and keeps the rest.
- Names are **top-level keys** of the emitted line (`timestamp`, `correlationId`, `status`,
  `api`, `operation`, `target`, `application`, `client`, `latencies`, `requestHeaders`,
  `responseHeaders`, `requestBody`, `responseBody`, `properties`) or **dotted sub-key paths**
  within the map fields (`requestHeaders.<name>`, `responseHeaders.<name>`,
  `properties.<key>`). Naming the whole `requestHeaders` key keeps all of its subkeys; a
  dotted header path removes/keeps just that header.
- **`fields` is authoritative over presence.** When set, the `request`/`response`
  `payload`/`headers` toggles are ignored — `fields` alone decides what appears. Per-flow
  `excludeHeaders`, the `maskedHeaders` param, and the global `masked_headers` still apply to
  headers that survive the selection.

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
          - requestHeaders
```

The line above contains only `latencies`, `target`, and `requestHeaders` (with `authorization`
masked). To drop a single header from the line, use `fields.exclude: [requestHeaders.x-api-key]`
or, more simply, `request.excludeHeaders: [x-api-key]`.

#### Properties (traffic-logging only)

`properties` attaches key→value pairs to the emitted line, for filtering or querying logs by
environment, tenant, or request attribute. Non-string values, and strings without a `$ctx:`
prefix, pass through as literals. A `$ctx:`-prefixed string is evaluated as a CEL (Common
Expression Language) expression against the request context, and the result keeps its native
type (string, bool, number, list, map) in the emitted line. A failed compile or evaluation —
an undeclared variable, a missing map/list key, or an `auth.*` reference before any auth
policy ran — omits that property; it does not fail the request.

```yaml
properties:
  env: production
  request_id: "$ctx:request.id"
  subject: "$ctx:auth.authenticated ? auth.subject : \"anonymous\""
  tenant: "$ctx:request.header['x-tenant-id'][0]"
  is_admin: "$ctx:\"admin\" in auth.scopes"
```

Available variables:

| Variable | Type | Notes |
|----------|------|-------|
| `request.path`, `request.method`, `request.authority`, `request.scheme`, `request.vhost`, `request.id` | string | |
| `request.header` | map(string, list(string)) | Lower-case keys, bracket-indexed, e.g. `request.header['x-request-id'][0]`. |
| `request.metadata` | map(string, dyn) | Arbitrary keys set by earlier policies (`SharedContext.Metadata`) — the only variable here without a fixed key set. |
| `api.id`, `api.name`, `api.version`, `api.context`, `api.kind`, `api.operation_path` | string | |
| `project.id` | string | |
| `auth.subject`, `auth.type`, `auth.issuer`, `auth.credential_id`, `auth.token_id` | string | Bound only if an earlier auth policy ran. |
| `auth.authenticated`, `auth.authorized` | bool | Bound only if an earlier auth policy ran. |
| `auth.audience` | list(string) | Bound only if an earlier auth policy ran. |
| `auth.scopes` | list(string), sorted | Bound only if an earlier auth policy ran. |
| `auth.property` | map(string, string) | Case-sensitive keys, bracket-indexed, e.g. `auth.property['tenant']`. Bound only if an earlier auth policy ran. |

The [`ext.Strings()`](https://pkg.go.dev/github.com/google/cel-go/ext#Strings) library
(`join`, `split`, `replace`, `trim`, `quote`, …) and standard CEL macros (`in`, `.exists()`,
`.all()`, `.map()`, `.filter()`) are available for the map/list variables above. Prefer `in`
over `has()` for presence checks: `has()` only accepts dot-select syntax, so it rejects bracket
indexing and any key containing a hyphen — which rules it out for header names in practice.

> `auth.*` variables require an earlier auth policy in the chain, which conflicts with
> [Policy ordering](#policy-ordering)'s recommendation to list `log-message` first. See that
> section for the tradeoff.

## Limitations

1. **Traffic-logging mode requires the collector and publisher** — otherwise it is a no-op.
2. **Filter/mask only (traffic-logging)** — parameters cannot enable capture the collector did
   not perform.
3. **No real-time/streaming in traffic-logging mode** — the line is emitted once after the
   response. Use inline mode for real-time and per-chunk streaming logs.
4. **Inline memory buffering** — inline payload logging buffers bodies in memory.
5. **Fixed field shape** — which fields appear is selectable via `fields` (traffic-logging
   mode), but the JSON structure/nesting of each field is not customizable.
6. **Order-sensitive within the policy chain** — a rejecting policy listed before `log-message`
   prevents it from running for that request. See [Policy ordering](#policy-ordering).

## Notes

**Sensitive data**

Exclude authentication/confidential headers and evaluate payload sensitivity before logging.
`Authorization` is masked by default, and `excludeHeaders` omits additional headers per flow
in both modes. In traffic-logging mode, `maskedHeaders` (plus the global
`[traffic_logging].masked_headers`) redacts header values, and `fields` further shapes the
line. Control log access, transmission, and retention in line with data-privacy regulations
(e.g. GDPR, CCPA).

**Performance**

Payload logging adds memory/CPU per request and increases log volume. Enable it selectively,
avoid large uploads/downloads, and enforce sensible retention. Traffic-logging mode adds no
inline latency (it only stamps a marker) but still relies on the collector capturing data
globally.

## Related Policies

- **Analytics Header Filter**: Controls which headers are included in analytics/traffic-log output per API.
- **Authentication Policies**: Combine while excluding auth headers from logging.
