---
title: "Overview"
---

# MCP Tool Schema Validator

## Overview

The **MCP Tool Schema Validator** policy checks MCP `tools/call` traffic against JSON Schemas that
you configure for each tool.

- **Input validation** checks `params.arguments` before the call reaches the MCP server. Invalid
  arguments are rejected with HTTP 400 and JSON-RPC error `-32602`, and the server is never called.
- **Output validation** checks `result.structuredContent` before the result reaches the client.
  An invalid result is replaced with JSON-RPC error `-32021`.

Each tool can enable input validation, output validation, or both. Both are off until you set `enabled: true`.

Unlike the JSON Schema Guardrail, which applies one schema to a whole API through a JSONPath, this
policy selects a schema by the tool being called. It answers in JSON-RPC with the caller's
original `id` and compiles every schema once, at deployment.

Attach it after [MCP Spec Validation](../../../mcp-spec-validation/v0.9/docs/mcp-spec-validation.md).
That policy rejects bodies that are not readable JSON-RPC, and this one leaves those to it.

## Features

- Per-tool schemas for arguments, structured results, or both, matched by exact tool name.
- JSON Schema 2020-12 by default, including `$defs`, `prefixItems`, `unevaluatedProperties` and
  `dependentRequired`. Draft-07 is supported when selected with `$schema`. See
  [Schema support](#schema-support).
- The `email`, `ipv4` and `ipv6` formats are enforced, so `"format": "email"` rejects a value that
  is not an email address. Other formats are annotations only.
- Only references within a schema are allowed. Remote, file and relative `$ref`s fail at
  deployment, and nothing is fetched, at deployment or at runtime.
- A valid result is forwarded byte for byte. An invalid one is replaced in the framing the server
  used. For a Server-Sent Events stream, only the event carrying the response is replaced.
- Rejects `tools/call` bodies that name `method`, `id`, `params`, `name` or `arguments` more than
  once, so the MCP server cannot execute arguments that the gateway never validated.
- Optional detailed errors (`showAssessment`) list JSON Pointer paths and rules, never values.
  See [Detailed errors](#detailed-errors).
- Records the tool, phase, result, reason and error count for analytics, never payload values.
- Bounds the work per request: 4 MB bodies, 64 levels of nesting and 20 listed errors.

## Configuration

### User Parameters (API Definition)

| Parameter | Type | Required | Default | Description |
|----------|------|----------|---------|-------------|
| `tools` | array | Yes | - | Tools to validate. Must not be empty. |
| `tools[].name` | string | Yes | - | Tool name, exact and case-sensitive. Must be unique. |
| `tools[].input` | object | No | - | Validation of `params.arguments`. |
| `tools[].output` | object | No | - | Validation of `result.structuredContent`. |
| `<section>.enabled` | boolean | No | `false` | Turns the check on. Both sections are off until enabled. |
| `<section>.schema` | string | When enabled | - | JSON Schema as a JSON string (an object or a boolean). At most 256 KB. |
| `<section>.showAssessment` | boolean | No | `false` | Lists each failure's path and rule in the error response. |

Each tool must enable at least one section. A disabled section's schema, if given, is still
checked, so a broken schema fails at deployment rather than when the section is enabled.

### Schema support

Validation uses [google/jsonschema-go](https://github.com/google/jsonschema-go).

| Topic | Behavior |
|---|---|
| Drafts | Draft 2020-12 applies when `$schema` is absent. Draft-07 is selected with `"$schema": "http://json-schema.org/draft-07/schema#"`. Any other `$schema`, including drafts 2019-09, 6 and 4, fails at deployment. |
| References | `$ref` may point anywhere in the same schema: `$defs`, `definitions`, JSON Pointers, `$anchor`, `$id` and recursive references. Any `$ref` outside the schema fails at deployment. This includes remote, file and relative references, and references to the draft meta-schemas. |
| Formats | `email`, `ipv4` and `ipv6` are enforced, as described below. Every other format, including `date-time`, `uri`, `uuid` and `hostname`, is an annotation and never rejects a value. |
| Schema checks | Invalid JSON, keywords of the wrong JSON type, unknown `type` names, negative length or count limits, a `multipleOf` that is not positive, invalid `pattern` regular expressions, and an array-form `items` in draft 2020-12 fail at deployment. Schemas are not otherwise checked against the draft meta-schema. |
| Numbers | Integers are compared exactly across the full 64-bit signed and unsigned range. Other numbers are compared as IEEE 754 doubles. A number is rejected with `number cannot be validated precisely` if it is outside the double range, or if it has a fraction that the double would round away. Numeric keyword bounds such as `minimum` and `multipleOf` are doubles. |

The enforced formats accept:

- **`email`:** an RFC 5321 mailbox of at most 254 characters. The local part is either a dot-atom
  of at most 64 characters or a quoted string of printable ASCII without `"` or `\`. The domain is
  a hostname, `[IPv4]` or `[IPv6:address]`. Internationalized addresses are rejected.
- **`ipv4`:** a dotted-quad address without leading zeros.
- **`ipv6`:** an RFC 4291 address, including the embedded IPv4 form, without a zone.

### build.yaml Entry

Add the following under `policies:` in `/gateway/build.yaml` of the
[api-platform](https://github.com/wso2/api-platform/blob/main/gateway/build.yaml) repository:

```yaml
- name: mcp-tool-schema-validator
  gomodule: github.com/wso2/gateway-controllers/policies/mcp-tool-schema-validator@v0
```

## Reference Scenarios

### Validate arguments and results

```yaml
apiVersion: gateway.api-platform.wso2.com/v1
kind: Mcp
metadata:
  name: weather-mcp
spec:
  displayName: Weather
  version: v1.0
  context: /weather
  upstream:
    url: http://weather-server:3001
  policies:
    - name: mcp-spec-validation
      version: v0
    - name: mcp-tool-schema-validator
      version: v0
      params:
        tools:
          - name: get_weather
            input:
              enabled: true
              schema: |
                {
                  "type": "object",
                  "properties": {
                    "city":  { "type": "string", "minLength": 1 },
                    "units": { "type": "string", "enum": ["celsius", "fahrenheit"] }
                  },
                  "required": ["city"],
                  "additionalProperties": false
                }
            output:
              enabled: true
              schema: |
                {
                  "type": "object",
                  "properties": {
                    "temperature": { "type": "number" },
                    "condition":   { "type": "string" }
                  },
                  "required": ["temperature", "condition"]
                }
```

### Input validation only

```yaml
        tools:
          - name: send_email
            input:
              enabled: true
              schema: '{"type":"object","required":["to","subject","body"],"properties":{"to":{"type":"string","format":"email"}}}'
```

### Output validation only

```yaml
        tools:
          - name: health_report
            output:
              enabled: true
              schema: '{"type":"object","required":["status"]}'
```

### Rejected arguments

Request:

```json
{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_weather","arguments":{"city":42}}}
```

Response (HTTP 400):

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "error": {
    "code": -32602,
    "message": "Tool arguments failed schema validation",
    "data": { "tool": "get_weather", "direction": "REQUEST" }
  }
}
```

With `showAssessment: true`, `data` also carries
`"errors": [{"path": "/city", "message": "got number, want string"}]`.

### Detailed errors

The validator decides whether a value is valid. When it rejects a value, the policy lists every
failure it can locate. Each entry is a JSON Pointer to the failing value and a message that
describes the rule, such as `length must be at least 1` or `value is not a valid email`.

- The response lists at most 20 errors. Analytics records the full count.
- An `anyOf` or `oneOf` failure is one error at the value's path. It does not list an error for each
  branch.
- Some failures cannot be located. These include `unevaluatedProperties` or `unevaluatedItems` next
  to `anyOf`, `oneOf`, `if` or `$ref`, and references resolved through a nested `$id` or
  `$dynamicRef`. If no failure can be located, a single error at the root path (`""`) says
  `value does not match the schema`.

When the client's `Accept` header permits only `text/event-stream`, the same error is sent as a
single `event: message` event.

### Replaced result

A result whose `structuredContent` fails the schema, or is missing, is replaced (HTTP 200):

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "error": {
    "code": -32021,
    "message": "Tool result failed schema validation",
    "data": { "tool": "get_weather", "direction": "RESPONSE", "reason": "missing_structured_content" }
  }
}
```

`data.reason` appears when the failure is not a plain schema mismatch: `arguments_not_object`,
`missing_structured_content`, `payload_too_large`, `too_deep` or `ambiguous_payload`.

### What is not validated

| Traffic | Outcome |
|---|---|
| Tools that are not configured, other methods, non-POST requests | Forwarded |
| Batches, malformed JSON, members of the wrong type | Forwarded, left to MCP Spec Validation |
| Results with `isError: true` and JSON-RPC error responses | Forwarded |
| Responses whose `id` differs from the request's, and non-2xx responses | Forwarded |
| Notifications (`tools/call` without `id`) | Arguments validated; there is no response to validate |

## Limitations

- Tool names match exactly. Wildcards and patterns are not supported.
- Schemas are not discovered from `tools/list`. They must be configured.
- There is no monitor-only mode. A failure always blocks.
- Remote schemas cannot be loaded.
- Only JSON Schema draft 2020-12 and draft-07 are supported.
- Only the `email`, `ipv4` and `ipv6` formats are enforced.

## Notes

- `-32021` is a server-defined JSON-RPC code. `-32020` is the MCP header-mismatch error that MCP
  Spec Validation returns.
- The `id` in an error is echoed exactly as sent: a string stays a string, and a large number keeps
  every digit.
- Error details never include argument or result values. The policy writes its own messages
  because the validator's messages quote the value it rejected.
