---
title: "Overview"
---

# MCP Spec Validation

## Overview

The **MCP Spec Validation** policy rejects malformed and self-contradictory MCP requests at the
gateway, before any other policy acts on them. It applies to POST requests.

On every MCP request, whichever version it declares, it checks the request body: that it parses
as JSON, that it is a single JSON-RPC request object rather than a batch or a bare scalar, and
that no member the gateway reads is named twice or carries the wrong type.

MCP specification version `2026-07-28` additionally mirrors the JSON-RPC method and capability
name of every request into the `Mcp-Method` and `Mcp-Name` headers, so that gateways and other
intermediaries can apply policy without reading the request payload. On a request declaring
that revision or later, the policy also checks those headers: that they are present where the
method requires them, that they use only characters permitted in an HTTP field value, and that
the protocol version, the method and the capability name each match the corresponding value in
the body.

That last check is what makes the mirrored headers usable. A client can otherwise present one
method in a header, which the gateway's other MCP policies act on, and a different method in
the body, which is what the MCP server actually executes. The specification requires the server
to verify the two match and to reject a mismatch with JSON-RPC error `-32020`; this policy
performs that verification at the edge rather than leaving it to the upstream MCP server.

Attach it to any MCP proxy that other MCP policies govern — authentication, authorization, rate
limiting or tool access control. If it is not attached ahead of them, those policies act on the
mirrored headers alone, with nothing having checked that the headers describe the body the MCP
server will actually execute.

Requests on legacy MCP versions (`2025-06-18`, `2025-11-25`) mirror nothing into headers, so on
those only the body is validated.

On a gateway that reads MCP request bodies itself (its MCP operation resolver), the policy runs
during the request-header phase and works from what the gateway parsed, without reading the body
again.

On an older gateway without the resolver, the policy reads the body during the request-body phase
and applies only the body checks; header validation is unavailable on that route, whatever version
a request declares. Declare the policy ahead of the other MCP policies so it rejects an unreadable
body before they read it.

The policy does **not** restrict which MCP protocol versions a proxy accepts.

## Features

- Rejects a request whose body is not readable as a single JSON-RPC request object — broken JSON as
  `-32700`, and a batch, a bare scalar, a member of the wrong type or a member named twice as
  `-32600`. This applies to every MCP version.
- Rejects a request whose `MCP-Protocol-Version`, `Mcp-Method` or `Mcp-Name` disagrees with the
  JSON-RPC request body.
- Requires `Mcp-Method` on every modern request, and `Mcp-Name` on `tools/call`, `resources/read`
  and `prompts/get`, and on the Tasks extension's `tasks/get`, `tasks/update` and `tasks/cancel`.
  On a task method `Mcp-Name` carries `params.taskId`, so it is compared against the task the body
  addresses rather than against a capability name.
- Rejects header values containing characters not permitted in an HTTP field value, including the
  carriage return and line feed used in header-injection attempts.
- Rejects an `MCP-Protocol-Version` that is not a dated revision, such as `draft`, `latest` or
  `v2026-07-28`. Every well-formed date passes, including revisions newer than this policy, since
  restricting which versions a proxy accepts is a separate concern. Without this check such a
  value compares above `2026-07-28` as a string and is judged as modern.
- Decodes Base64 sentinel values (`=?base64?…?=`) before comparing, so names that cannot be written
  in plain ASCII are compared correctly.
- Returns errors as JSON-RPC, framed as a Server-Sent Event when the client requested an event
  stream, and records the error code for analytics.
- Leaves `Mcp-Param-*` headers untouched, as the specification requires of intermediaries.

## Why the other MCP policies need this

The MCP Authorization, Rate Limiting and Access Control policies all act on **which capability a
request invokes**. Each identifies it the same way this policy does — from the mirrored headers on a
modern request, and from the request body otherwise.

They already reject a request whose body the gateway could not read. What they do **not** do is check
that a modern request's mirrored headers agree with its body, because on a route where the gateway
does not read the body they have nothing to compare against.

That leaves one gap, and attaching this policy closes it:

```http
Mcp-Method: tools/list          ← what the restricting policies act on
Mcp-Name:   (omitted)

{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"delete_everything"}}
                                ← what the MCP server executes
```

Nothing here is malformed. The headers name a harmless listing that no rule targets, so the request
passes through ungoverned, while the server runs a tool that a rule would have protected. This policy
rejects that with JSON-RPC `-32020` before any other MCP policy runs.

**Attach this policy if your MCP proxy enforces authorization, rate limits or an allow/deny list on
specific tools, resources or prompts, and you want that enforcement guaranteed at the gateway rather
than left to the MCP server.**

## Configuration

Attach the policy to an MCP proxy. It takes no parameters: everything it needs arrives with the
request.

```yaml
apiVersion: gateway.api-platform.wso2.com/v1
kind: Mcp
metadata:
  name: weather-mcp
spec:
  displayName: Weather
  version: v1.0
  context: /weather
  specVersion: "2026-07-28"
  upstream:
    url: http://weather-server:3001
  policies:
    - name: mcp-spec-validation
      version: v0
```

### User Parameters (API Definition)

None. The policy is attached and takes no configuration.

The policy works on any gateway. The header checks run only where the gateway has an MCP operation
resolver, which it adds to an MCP proxy's request endpoint automatically; elsewhere only the body
is checked.

### build.yaml Integration

Add the policy to `/gateway/build.yaml` in the [api-platform](https://github.com/wso2/api-platform/blob/main/gateway/build.yaml)
repository so it is compiled into the gateway image:

```yaml
- name: mcp-spec-validation
  gomodule: github.com/wso2/gateway-controllers/policies/mcp-spec-validation@v0
```

## Reference Scenarios

### A valid request is forwarded

The header and the body name the same tool, so the request proceeds to the MCP server.

```http
POST /weather/mcp HTTP/1.1
MCP-Protocol-Version: 2026-07-28
Mcp-Method: tools/call
Mcp-Name: get_forecast
Content-Type: application/json

{"jsonrpc":"2.0","id":7,"method":"tools/call",
 "params":{"name":"get_forecast","arguments":{"city":"Colombo"}}}
```

### The header and body name different tools

The header claims a read-only listing while the body invokes a tool. The request is rejected and
never reaches the MCP server.

```http
POST /weather/mcp HTTP/1.1
MCP-Protocol-Version: 2026-07-28
Mcp-Method: tools/list
Content-Type: application/json

{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"delete_everything"}}
```

```http
HTTP/1.1 400 Bad Request
Content-Type: application/json

{"jsonrpc":"2.0","id":7,
 "error":{"code":-32020,
          "message":"Mcp-Method does not match the method in the request body"}}
```

### A body naming a member twice

The body is valid JSON, but names `method` twice. Parsers disagree about which one wins, so the
gateway and the MCP server could act on different methods. The request is rejected rather than
governed on a reading the server may not share.

```http
POST /weather/mcp HTTP/1.1
MCP-Protocol-Version: 2026-07-28
Mcp-Method: tools/list
Content-Type: application/json

{"jsonrpc":"2.0","id":7,"method":"tools/list","method":"tools/call"}
```

```http
HTTP/1.1 400 Bad Request
Content-Type: application/json

{"jsonrpc":"2.0","id":null,
 "error":{"code":-32600,
          "message":"Request body names a member more than once"}}
```

### A required header is missing

`Mcp-Name` identifies the tool being invoked, so `tools/call` cannot be validated without it.

```http
POST /weather/mcp HTTP/1.1
MCP-Protocol-Version: 2026-07-28
Mcp-Method: tools/call
```

```http
HTTP/1.1 400 Bad Request
Content-Type: application/json

{"jsonrpc":"2.0","id":null,
 "error":{"code":-32020,
          "message":"Mcp-Name header is required for tools/call"}}
```

### A name that cannot be written in plain ASCII

`Mcp-Name` carries the Base64 sentinel form. The policy decodes it before comparing, so it matches
the body value and the request is forwarded.

```http
POST /weather/mcp HTTP/1.1
MCP-Protocol-Version: 2026-07-28
Mcp-Method: tools/call
Mcp-Name: =?base64?dG9vbF/DvG1sYXV0?=
Content-Type: application/json

{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"tool_ümlaut"}}
```

### A legacy request

Legacy MCP versions mirror nothing into headers, so no header check applies — but the body is still
validated. This request is well formed, so it is forwarded and the MCP server applies its own rules.

```http
POST /weather/mcp HTTP/1.1
MCP-Protocol-Version: 2025-06-18
Content-Type: application/json

{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"get_forecast"}}
```

### An error returned to a streaming client

When the client requests an event stream, the same JSON-RPC error is delivered as an SSE frame so the
client's stream reader can consume it.

```http
POST /weather/mcp HTTP/1.1
MCP-Protocol-Version: 2026-07-28
Accept: text/event-stream
Mcp-Method: tools/list

{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"delete_everything"}}
```

```http
HTTP/1.1 400 Bad Request
Content-Type: text/event-stream

event: message
data: {"jsonrpc":"2.0","id":7,"error":{"code":-32020,"message":"Mcp-Method does not match the method in the request body"}}
```
