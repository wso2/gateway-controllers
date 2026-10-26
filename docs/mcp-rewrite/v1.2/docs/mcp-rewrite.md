---
title: "Overview"
---
# MCP Rewrite

## Overview

The MCP Rewrite policy enables API administrators to expose user-facing names for Model Context Protocol (MCP) tools, resources, and prompts while mapping them to different backend capability names. This policy supports three types of MCP capabilities: tools, resources, and prompts. For each capability type, you can define a list of user-facing capabilities with optional mappings to backend names, and optionally specify additional metadata fields to be returned in list responses.

When a list is provided for a capability type, only the configured capabilities are included in list responses. Requests for unlisted capabilities are rejected with an appropriate error. The policy rewrites request payloads to use backend capability names when configured, and rewrites list responses to return user-facing values.

## Features

- **Tool Rewriting**: Define user-facing tool names and map them to backend tool names with custom schemas and descriptions.
- **Resource Rewriting**: Define user-facing resource identifiers and map them to backend resource identifiers with custom descriptions.
- **Prompt Rewriting**: Define user-facing prompt names and map them to backend prompt names with custom metadata.
- **Flexible Metadata**: Include additional fields (beyond `name`, `description`, `target`, etc.) in capability definitions for custom metadata in list responses.
- **Optional Mapping**: Omit the `target` field to expose capabilities as-is without mapping to a different backend name.
- **Mirrored Header Consistency**: On MCP `2026-07-28`, restates the `Mcp-Name` header after a rewrite so it still describes the request body, and rejects a request whose mirrored headers disagree with its body rather than rewriting it.
- **Unreadable Body Rejection**: On a gateway with the MCP operation resolver, rejects a request body the gateway could not read rather than rewriting bytes it may be reading differently from the MCP server.

## Configuration

The MCP Rewrite policy uses a single-level configuration model where all parameters are configured per-MCP-API/route in the API definition YAML.

### User Parameters (API Definition)

These parameters are configured per MCP Proxy by the API developer:

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `tools` | `ToolRewriteConfig` array | Conditional | - | List of tools to expose and optionally rewrite. Omit to allow all tools. Set `[]` to deny all tools. When provided with entries, only these tools are included in `tools/list` responses and unlisted `tools/call` requests are rejected. |
| `resources` | `ResourceRewriteConfig` array | Conditional | - | List of resources to expose and optionally rewrite. Omit to allow all resources. Set `[]` to deny all resources. When provided with entries, only these resources are included in `resources/list` responses and unlisted `resources/read` requests are rejected. |
| `prompts` | `PromptRewriteConfig` array | Conditional | - | List of prompts to expose and optionally rewrite. Omit to allow all prompts. Set `[]` to deny all prompts. When provided with entries, only these prompts are included in `prompts/list` responses and unlisted `prompts/get` requests are rejected. |

> **Note**: At least one of `tools`, `resources`, or `prompts` must be specified.

### ToolRewriteConfig Configuration

Each `ToolRewriteConfig` object supports the following fields:

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `name` | string | Yes | - | User-facing tool name exposed to clients (1-256 characters). |
| `description` | string | Yes | - | User-facing tool description returned in `tools/list`. |
| `inputSchema` | string | Yes | - | Tool input schema returned in `tools/list`. |
| `outputSchema` | string | No | - | Tool output schema returned in `tools/list`. |
| `target` | string | No | - | Backend tool name to use when forwarding requests. If omitted, `name` is used. |

### ResourceRewriteConfig Configuration

Each `ResourceRewriteConfig` object supports the following fields:

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `name` | string | Yes | - | User-facing resource identifier exposed to clients (1-1024 characters). |
| `uri` | string | Yes | - | User-facing resource URI returned in `resources/list` (1-2048 characters). |
| `description` | string | No | - | User-facing resource description returned in `resources/list`. |
| `target` | string | No | - | Backend resource identifier (URI) to use when forwarding requests. If omitted, `uri` is used. |

### PromptRewriteConfig Configuration

Each `PromptRewriteConfig` object supports the following fields:

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `name` | string | Yes | - | User-facing prompt name exposed to clients (1-256 characters). |
| `description` | string | No | - | User-facing prompt description returned in `prompts/list`. |
| `target` | string | No | - | Backend prompt name to use when forwarding requests. If omitted, `name` is used. |

> **Note**: Additional custom fields can be included in `tools`, `resources`, and `prompts` definitions and will be returned in the corresponding list responses.

**Note:**

Inside the `gateway/build.yaml`, ensure the policy module is added under `policies:`:

```yaml
- name: mcp-rewrite
  gomodule: github.com/wso2/gateway-controllers/policies/mcp-rewrite@v1
```

## MCP 2026-07-28 and the mirrored headers

MCP specification version `2026-07-28` mirrors the JSON-RPC method and capability name of every
request into the `Mcp-Method` and `Mcp-Name` headers, so that gateways and other intermediaries
can apply policy without reading the request payload.

That creates an obligation for this policy specifically. When it rewrites `params.name` in the
body, the name the client mirrored into `Mcp-Name` no longer describes the request. A conformant
MCP server is required to detect that disagreement and reject the request with JSON-RPC error
`-32020`, so on those revisions the policy restates the header alongside the body.

Restating the header is only safe once the header has been checked. Before rewriting, the policy
verifies that the mirrored headers agree with the request body, and rejects the request with
`-32020` when they do not:

```http
POST /weather/mcp HTTP/1.1
MCP-Protocol-Version: 2026-07-28
Mcp-Name: query_database
Content-Type: application/json

{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"admin_tool"}}
```

```http
HTTP/1.1 400 Bad Request
Content-Type: application/json

{"jsonrpc":"2.0","id":7,
 "error":{"code":-32020,
          "message":"Mcp-Name does not match the capability in the request body"}}
```

Without that check, rewriting `Mcp-Name` to match the body would make the request internally
consistent and remove the MCP server's own opportunity to reject it. Other MCP policies such as
MCP Authorization and MCP Rate Limiting act on `Mcp-Name`, so a request governed under one
capability could reach the server invoking another.

The rule is applied to each header independently, and only against what the body actually
contains. On a request declaring `2026-07-28` or later:

| Header | Request body | Result |
|---|---|---|
| absent | names no corresponding value | forwarded — there is nothing to mirror |
| absent | names one | rejected with `-32020` |
| present | disagrees | rejected with `-32020` |
| present | agrees | rewritten, and `Mcp-Name` restated to match |

`Mcp-Method` is checked before the capability is resolved, `Mcp-Name` as soon as the body names one.
Neither is corrected when it is missing or wrong: a rewrite changes only the capability name, so a
request whose mirror cannot be trusted is refused rather than repaired. Deciding whether a modern
request was *obliged* to send a header in the first place is the MCP Spec Validation policy's
responsibility, not this one's.

A capability name that cannot be written as visible ASCII is wrapped in the Base64 sentinel form
(`=?base64?...?=`) the specification defines, so a `target` containing non-ASCII characters is
transmitted correctly.

Requests on earlier MCP versions (`2025-06-18`, `2025-11-25`) mirror nothing into headers. On
those, no header is verified and none is written, and rewriting behaves exactly as in v1.0.

## Ordering with other MCP policies

This policy changes which capability a request targets, so its position in the policy chain
decides what the other MCP policies see. Policies run in the order they are declared on the API.

Declare MCP Rewrite **after** the policies that govern access — MCP Authorization, MCP Rate
Limiting and MCP Access Control — so that they evaluate the user-facing name the client actually
sent. Declaring it first means those policies see the backend name instead, and rules written
against the user-facing names in this policy's configuration will not match.

If MCP Spec Validation is attached, declare it first of all.

## Reference Scenarios

### Example 1: Basic Tool Rewriting

Expose tools with different names than the backend:

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
    - name: mcp-rewrite
      version: v1
      params:
        tools:
          - name: list-files
            description: List files in a directory
            inputSchema: '{"type": "object", "properties": {"path": {"type": "string"}}}'
            target: backend_list_files
          - name: read-file
            description: Read file contents
            inputSchema: '{"type": "object", "properties": {"path": {"type": "string"}}}'
            target: backend_read_file
  tools:
    ...
```

### Example 2: Resource Rewriting with URI Mapping

Expose resources with user-friendly URIs mapped to backend resources:

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
    - name: mcp-rewrite
      version: v1
      params:
        resources:
          - name: user-docs
            uri: file:///user-documentation
            description: User documentation files
            target: file:///internal/docs/users
          - name: api-specs
            uri: file:///api-specifications
            description: API specification files
            target: file:///internal/specs/api
  resources:
    ...
```

### Example 3: Prompt and Tool Rewriting Combined

Rewrite prompts and tools with metadata:

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
    - name: mcp-rewrite
      version: v1
      params:
        tools:
          - name: create-document
            description: Create a new document
            inputSchema: '{"type": "object", "properties": {"title": {"type": "string"}}}'
            target: create_doc
        prompts:
          - name: summarize
            description: Summarize content
            target: summarize_content
            category: text-processing
  tools:
    ...
```
