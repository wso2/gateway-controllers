---
title: "Overview"
---
# Modify Headers

## Overview

The Modify Headers policy updates request and/or response headers.
It supports two actions:
- `SET`: set/replace a header value
- `DELETE`: remove a header

Modifications can be applied in the request phase, response phase, or both.

## Features

- Modifies request headers before forwarding upstream
- Modifies response headers before returning to client
- Supports `SET` and `DELETE` actions
- Case-insensitive header handling (internally normalized)
- Independent request/response configuration

## Configuration

At least one of `requestHeaders` or `responseHeaders` should be provided.

### User Parameters (API Definition)

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `requestHeaders` | array | No | Header modifications applied to request headers. |
| `responseHeaders` | array | No | Header modifications applied to response headers. |

### Header Modification Object

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `action` | string | Yes | `SET` or `DELETE`. |
| `name` | string | Yes | Header name. |
| `value` | string | Conditional | Required when `action` is `SET`. Ignored for `DELETE`. |

### System Parameters

This policy does not require system-level configuration.

## Behavior Notes

- Invalid `requestHeaders` configuration returns immediate `500` response.
- Invalid `responseHeaders` configuration rewrites the upstream response to `500` with JSON error.
- Unknown actions are ignored at execution time (no set/remove operation produced).

## API Definition Examples

### Example 1: Set Request Headers

```yaml
policies:
  - name: modify-headers
    version: v0
    params:
      requestHeaders:
        - action: SET
          name: X-Env
          value: production
        - action: SET
          name: X-Gateway
          value: apiplatform
```

### Example 2: Delete Response Headers

```yaml
policies:
  - name: modify-headers
    version: v0
    params:
      responseHeaders:
        - action: DELETE
          name: Server
        - action: DELETE
          name: X-Powered-By
```

### Example 3: Modify Both Request and Response

```yaml
policies:
  - name: modify-headers
    version: v0
    params:
      requestHeaders:
        - action: SET
          name: X-Trace-Source
          value: gateway
      responseHeaders:
        - action: SET
          name: Cache-Control
          value: no-store
        - action: DELETE
          name: X-Internal-Debug
```
