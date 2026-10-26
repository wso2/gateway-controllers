---
title: "Overview"
---
# MCP Rate Limit

## Overview

The MCP Rate Limit policy applies rate limits to Model Context Protocol (***MCP***) traffic on a per-capability basis. Instead of throttling an MCP proxy as a single endpoint, it inspects the JSON-RPC request envelope and enforces independent limits per **tool**, **resource**, **prompt**, or raw **JSON-RPC method**.

Each configuration entry targets a capability by name (or `"*"` for all capabilities of that type) and declares one or more `(limit, duration)` limits. Multiple entries may be configured in the same policy, mixing exact-name rules with wildcards. Every matched capability is given its own counter — even under a wildcard rule — so one noisy tool cannot exhaust the quota of another.

Enforcement is delegated to the [Advanced Rate Limit policy](../../../advanced-ratelimit/v1.2/docs/advanced-ratelimit.md) engine, so this policy inherits the same algorithms (GCRA, Fixed Window), in-memory/Redis backends, key extraction options, and rate-limit response headers. When a request is throttled, the policy returns a JSON-RPC 2.0 error envelope (code `-32000`) so MCP clients can parse the failure.

## Features

- **Per-Capability Rate Limiting**: Throttle individual MCP tools, resources, prompts, or JSON-RPC methods independently.
- **Per-Capability Buckets**: Each matched tool/resource/prompt keeps its own counter — including matches under a `"*"` wildcard rule.
- **Exact and Wildcard Matching**: Target a single capability by name or apply a blanket rule with `"*"`. When both match, all matching entries are enforced and the strictest limit wins.
- **Multiple Concurrent Limits**: Each entry can enforce several limit windows at once (e.g. 10/minute *and* 1000/hour).
- **Flexible Key Extraction**: Build the rate-limit key from headers, metadata, client IP, API name/version, route name, a CEL expression, or a constant — globally or per entry.
- **SSE Support**: On a gateway without an MCP operation resolver, handles both plain JSON and `text/event-stream`-wrapped MCP request envelopes. On a gateway with one the body is parsed by the gateway, which accepts JSON only — note that no MCP revision permits a client to send an event-stream request body, so this affects non-conforming clients alone.
- **MCP-Aware Error Responses**: Throttled requests receive a JSON-RPC 2.0 error envelope by default (overridable), preserving the `mcp-session-id` header.
- **Dual Backends**: In-memory for single-instance deployments or Redis for distributed rate limiting across gateway replicas.

## Request identification

Before this policy can limit anything it has to know **which capability the request invokes** — the
tool, resource, prompt or JSON-RPC method its rules are matched against. Where that comes from
depends on the request and on the gateway:

| Request | Source | Needs a resolver? |
|---|---|---|
| Declares `MCP-Protocol-Version: 2026-07-28` or later, on a gateway with an MCP operation resolver | the mirrored `Mcp-Method` and `Mcp-Name` headers | yes |
| Declares an earlier version, or none, on a gateway with an MCP operation resolver | facts the resolver published, having parsed the body once for the whole policy chain | yes |
| Any version, on a gateway without one | the policy reads the request body itself | no |

You do not configure this. The gateway states which routes carry a resolver, and the policy asks for
the request body only where nothing else has already read it. A proxy deployed on an older gateway
behaves exactly as it did before this version, and the same request lands in the same bucket
whichever source identified it.

### Three outcomes, not two

| | |
|---|---|
| The capability is identified | limited normally — every matching rule is enforced, `429` on breach |
| The request body could not be read | **rejected, `400`** |
| The body was read and named no capability | **not limited — the request passes through** |
| A modern request omitted `Mcp-Method`, or a required `Mcp-Name` | **rejected, `400`** |

**A body the gateway could not read is rejected.** Invalid JSON, a JSON-RPC batch, a wrongly-typed
`method`, or a member spelled two different ways: in each case the gateway and the MCP server may
read the same bytes differently, so limiting the request on the gateway's reading would be limiting
a guess. This is the behaviour earlier versions had, and it is unchanged.

**A modern request without a required mirrored header is rejected, `400`,** on a gateway with an MCP
operation resolver. MCP 2026-07-28 requires `Mcp-Method` on every request, and `Mcp-Name` on
`tools/call`, `resources/read` and `prompts/get`; a missing required header is a validation failure.
An `Mcp-Name` that will not decode counts as missing. Forwarding it would let a caller send
unlimited requests by withholding one header. The legacy allowance for a method-less POST does not
carry over: the one such request, a JSON-RPC response answering a server-initiated call, does not
exist in 2026-07-28, which carries that answer in an ordinary request instead.

**A body that was read and simply named no capability is not limited.** This policy restricts
capabilities it can identify, and counting an unidentified request would charge it to a bucket that
is not its own. The cases are all legitimate:

- a request whose method addresses no capability family — `initialize`, `ping`, `server/discover`;
- on a legacy request, a JSON-RPC **response**, which a client POSTs to answer a server-initiated
  sampling or elicitation call and which carries an id and a result but no method.

⚠️ **On a modern request the headers are taken at face value.** This policy does not check that
`Mcp-Method` and `Mcp-Name` agree with the request body. Attach the [MCP Spec Validation
policy](../../../mcp-spec-validation/v0.9/docs/mcp-spec-validation.md) ahead of this one to close
that: it requires the mirrored headers and checks them against the body, rejecting a mismatch with
JSON-RPC `-32020`. Without it, the MCP server is responsible for that check.

### Which methods carry a capability name

A rule under `tools`, `resources` or `prompts` matches on the capability name, and only three
methods name one: `tools/call`, `resources/read` and `prompts/get`. Every other method — including
`resources/subscribe`, which carries a URI of its own — is matched by a `methods` rule instead. This
is unchanged from earlier versions and is the same on every gateway.

## Configuration

The MCP Rate Limit policy uses a two-level configuration model: **user parameters** set per MCP proxy in the API definition, and **system parameters** set by the administrator (shared with the Advanced Rate Limit engine).

### User Parameters (API Definition)

These parameters are configured per MCP proxy by the API developer:

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `tools` | `Entry` array | Conditional | - | Rate-limit rules for MCP tools. Each entry targets a tool by name (or `"*"`). 1-50 entries. |
| `resources` | `Entry` array | Conditional | - | Rate-limit rules for MCP resources. Each entry targets a resource URI (or `"*"`). 1-50 entries. |
| `prompts` | `Entry` array | Conditional | - | Rate-limit rules for MCP prompts. Each entry targets a prompt by name (or `"*"`). 1-50 entries. |
| `methods` | `Entry` array | Conditional | - | Rate-limit rules for raw JSON-RPC methods (e.g. `tools/list`, `tools/call`). Each entry targets a method (or `"*"`). 1-50 entries. |
| `keyExtraction` | `KeyExtraction` array | No | `[{type: "routename"}]` | Global key extraction applied to entries that do not define their own. The matched capability identifier is always appended automatically. 0-5 components. |
| `onRateLimitExceeded` | `onRateLimitExceeded` object | No | - | Customizes the response returned when a request exceeds rate limits. Defaults to a JSON-RPC error envelope. |

> **Note**: At least one of `tools`, `resources`, `prompts`, or `methods` must be specified.

#### Entry Configuration

Each entry in a `tools`, `resources`, `prompts`, or `methods` array defines a rate-limit rule for a capability:

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `name` | string | No | `"*"` | The capability to rate-limit (tool name, resource URI, prompt name, or JSON-RPC method), or `"*"` for all of that type. Exact and wildcard entries are both enforced when they match, and the strictest limit wins. |
| `limits` | `Limit` array | Yes | - | One or more limit windows enforced on this entry (1-10). The strictest limit wins. |
| `keyExtraction` | `KeyExtraction` array | No | - | Per-entry key extraction. Overrides the global `keyExtraction`. If neither is set, defaults to `[{type: "routename"}]`. |

> The matched capability identifier (tool name / resource URI / prompt name / method) is **always appended** to the rate-limit key automatically, so each distinct capability gets its own counter even when the rule `name` is `"*"`.

#### Limit Configuration

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `limit` | integer | Yes | - | Maximum number of requests allowed in the configured duration (1-1,000,000,000). |
| `duration` | string | Yes | - | Limit window as a Go duration string. Supports units `ns`, `us`, `µs`, `ms`, `s`, `m`, `h`, including composite and fractional values (e.g. `"500ms"`, `"1.5s"`, `"1m30s"`, `"24h"`). |

#### KeyExtraction Configuration

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `type` | string | Yes | Component type: `"header"`, `"metadata"`, `"ip"`, `"apiname"`, `"apiversion"`, `"routename"`, `"cel"`, `"constant"`. |
| `key` | string | Conditional | Header name or metadata key. Required for `header`, `metadata`, and `constant` types (1-256 chars). |
| `expression` | string | Conditional | CEL expression returning a string. Required for `cel` type (1-1024 chars). |

**Key extraction types:**
- `header`: Extract from an HTTP header (requires `key`)
- `metadata`: Extract from `SharedContext.Metadata` (requires `key`)
- `ip`: Extract client IP from `X-Forwarded-For`/`X-Real-IP` headers
- `apiname`: Use API name from context
- `apiversion`: Use API version from context
- `routename`: Use route name from metadata (default)
- `cel`: Evaluate a CEL expression returning a string (requires `expression`)
- `constant`: Use a fixed constant string value (requires `key`)

#### onRateLimitExceeded Configuration

Customizes the response returned when a request exceeds its rate limits. When omitted, the policy emits a JSON-RPC 2.0 error object with code `-32000`.

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `statusCode` | integer | No | `429` | HTTP status code returned for rate-limited requests (400-599). |
| `body` | string | No | JSON-RPC `-32000` error envelope | Response body returned for rate-limited requests (max 8192 chars). When set, it is returned verbatim instead of the JSON-RPC envelope. |
| `bodyFormat` | string | No | `"json"` | Response body format: `"json"` or `"plain"`. |

### System Parameters (From config.toml)

These parameters are set by the administrator and shared with the Advanced Rate Limit engine. They apply to all rate-limiting policies built on it.

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `algorithm` | string | No | `"fixed-window"` | Rate-limiting algorithm: `"gcra"` (smoother burst handling) or `"fixed-window"` (simple interval counting). |
| `backend` | string | No | `"memory"` | Storage backend: `"memory"` for single-instance limits or `"redis"` for distributed limits. |
| `redis` | `Redis` object | No | - | Redis configuration (only used when `backend=redis`). |
| `memory` | `Memory` object | No | - | In-memory storage configuration (only used when `backend=memory`). |
| `headers` | `Headers` object | No | - | Controls which rate-limit headers are added to responses. |

See the [Advanced Rate Limit policy](../../../advanced-ratelimit/v1.2/docs/advanced-ratelimit.md) documentation for the full `redis`, `memory`, and `headers` sub-fields and a sample `config.toml`.

**Note:**

Inside the `gateway/build.yaml`, ensure the policy module is added under `policies:`:

```yaml
- name: mcp-ratelimit
  gomodule: github.com/wso2/gateway-controllers/policies/mcp-ratelimit@v1
```

## Reference Scenarios

### Example 1: Rate Limit a Specific Tool

Limit calls to a single, expensive tool while leaving everything else untouched:

```yaml
apiVersion: gateway.api-platform.wso2.com/v1
kind: Mcp
metadata:
  name: mcp-server-api-v1.0
spec:
  displayName: mcp-server-api
  version: v1.0
  context: /mcpserver
  upstream:
    url: https://mcp-backend:8080
  policies:
    - name: mcp-ratelimit
      version: v1
      params:
        tools:
          - name: generate-report
            limits:
              - limit: 5
                duration: "1m"
  tools:
    ...
```

### Example 2: Wildcard Rule for All Tools

Apply a blanket limit to every tool. Each tool still gets its own counter, so the limit is per-tool, not shared:

```yaml
apiVersion: gateway.api-platform.wso2.com/v1
kind: Mcp
metadata:
  name: mcp-server-api-v1.0
spec:
  displayName: mcp-server-api
  version: v1.0
  context: /mcpserver
  upstream:
    url: https://mcp-backend:8080
  policies:
    - name: mcp-ratelimit
      version: v1
      params:
        tools:
          - name: "*"
            limits:
              - limit: 100
                duration: "1h"
  tools:
    ...
```

### Example 3: Multiple Time Windows

Enforce several limit windows simultaneously on the same tool (strictest wins):

```yaml
apiVersion: gateway.api-platform.wso2.com/v1
kind: Mcp
metadata:
  name: mcp-server-api-v1.0
spec:
  displayName: mcp-server-api
  version: v1.0
  context: /mcpserver
  upstream:
    url: https://mcp-backend:8080
  policies:
    - name: mcp-ratelimit
      version: v1
      params:
        tools:
          - name: search
            limits:
              - limit: 10
                duration: "1m"
              - limit: 500
                duration: "24h"
  tools:
    ...
```

### Example 4: Rate Limit Resources and Prompts

Apply different limits to resources and prompts in a single policy:

```yaml
apiVersion: gateway.api-platform.wso2.com/v1
kind: Mcp
metadata:
  name: mcp-server-api-v1.0
spec:
  displayName: mcp-server-api
  version: v1.0
  context: /mcpserver
  upstream:
    url: https://mcp-backend:8080
  policies:
    - name: mcp-ratelimit
      version: v1
      params:
        resources:
          - name: "file:///reports/quarterly.pdf"
            limits:
              - limit: 20
                duration: "1h"
          - name: "*"
            limits:
              - limit: 200
                duration: "1h"
        prompts:
          - name: summarize
            limits:
              - limit: 30
                duration: "1m"
  resources:
    ...
  prompts:
    ...
```

### Example 5: Rate Limit JSON-RPC Methods

Throttle raw JSON-RPC methods directly — useful for limiting discovery calls such as `tools/list`:

```yaml
apiVersion: gateway.api-platform.wso2.com/v1
kind: Mcp
metadata:
  name: mcp-server-api-v1.0
spec:
  displayName: mcp-server-api
  version: v1.0
  context: /mcpserver
  upstream:
    url: https://mcp-backend:8080
  policies:
    - name: mcp-ratelimit
      version: v1
      params:
        methods:
          - name: tools/list
            limits:
              - limit: 10
                duration: "1m"
          - name: tools/call
            limits:
              - limit: 100
                duration: "1m"
  tools:
    ...
```

### Example 6: Custom Rate-Limited Response

Override the default JSON-RPC error envelope with a custom body:

```yaml
apiVersion: gateway.api-platform.wso2.com/v1
kind: Mcp
metadata:
  name: mcp-server-api-v1.0
spec:
  displayName: mcp-server-api
  version: v1.0
  context: /mcpserver
  upstream:
    url: https://mcp-backend:8080
  policies:
    - name: mcp-ratelimit
      version: v1
      params:
        tools:
          - name: "*"
            limits:
              - limit: 100
                duration: "1m"
        onRateLimitExceeded:
          statusCode: 429
          body: '{"jsonrpc":"2.0","id":null,"error":{"code":-32000,"message":"Too many tool calls. Please slow down."}}'
          bodyFormat: json
  tools:
    ...
```

### Example 7: Per-User Rate Limiting

Throttle each user independently by extracting the identity from a header. The user ID is combined with the matched capability so each user has a separate bucket per tool:

```yaml
apiVersion: gateway.api-platform.wso2.com/v1
kind: Mcp
metadata:
  name: mcp-server-api-v1.0
spec:
  displayName: mcp-server-api
  version: v1.0
  context: /mcpserver
  upstream:
    url: https://mcp-backend:8080
  policies:
    - name: mcp-ratelimit
      version: v1
      params:
        keyExtraction:
          - type: header
            key: X-User-ID
        tools:
          - name: "*"
            limits:
              - limit: 50
                duration: "1h"
  tools:
    ...
```

## How it Works

1. The policy identifies the operation. On a route carrying the MCP operation resolver it reads the mirrored headers or the resolver's facts at the request-header phase; without one it parses the JSON-RPC envelope from the buffered request body itself (handling both plain JSON and `text/event-stream` payloads).
2. From that it takes the JSON-RPC `method` and, where applicable, the capability name (`params.name` for `tools/call` and `prompts/get`, `params.uri` for `resources/read`). It also publishes `mcp.method`, `mcp.type`, and `mcp.name` metadata for downstream policies.
3. It finds every configured entry that matches — exact-name matches first, then `"*"` wildcards. All matching entries are enforced.
4. For each match it resolves (and caches) an Advanced Rate Limit delegate keyed by `(entry, capability)`. The key extraction is `entry || global || [routename]` plus a trailing constant carrying the capability identifier, guaranteeing each capability its own bucket.
5. If any delegate reports the limit exceeded, the request is rejected with the configured response (a JSON-RPC `-32000` error envelope by default). Otherwise the request proceeds upstream.
6. On the response, the policy forwards to each invoked delegate so it can write its rate-limit headers (`RateLimit-*`, `X-RateLimit-*`, `Retry-After`).

## Notes

**Relationship with the Advanced Rate Limit policy**

This policy is a thin, MCP-aware front end over the [Advanced Rate Limit](../../../advanced-ratelimit/v1.2/docs/advanced-ratelimit.md) engine. The `algorithm`, `backend`, Redis/memory storage, key-extraction semantics, and response headers all behave identically — refer to that policy's documentation for the full system-parameter reference and header descriptions.

**Per-capability counters**

The matched capability identifier is always appended to the rate-limit key. This means a `"*"` rule does not create one shared bucket for all tools; instead, each distinct tool, resource, prompt, or method gets its own counter under the rule.

**Matching precedence**

When a request matches both an exact-name entry and a wildcard entry, *both* are enforced. Because the strictest applicable limit blocks the request, you can layer a tight per-tool limit on top of a looser catch-all wildcard.

**Use with other MCP policies**

Combine with [MCP Authentication](../../../mcp-auth/v1.4/docs/mcp-authentication.md) and [MCP Authorization](../../../mcp-authz/v1.3/docs/mcp-authorization.md) for identity-aware throttling (e.g. per-user limits via `keyExtraction`), or with [MCP Access Control](../../../mcp-acl-list/v1.1/docs/mcp-acl-list.md) to deny capabilities outright while rate-limiting the rest.
