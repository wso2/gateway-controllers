---
title: "Overview"
---
# Respond

## Overview

The Respond policy returns an immediate response from the gateway without forwarding the request to upstream.
It is useful for short-circuiting flows, mocking APIs, and returning fixed responses.

## Features

- Immediate response in request phase
- Configurable status code, body, and headers
- No upstream call when policy is executed
- Useful for mock endpoints and controlled error responses

## Configuration

### User Parameters (API Definition)

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `statusCode` | integer | No | `200` | HTTP status code returned to client. |
| `body` | string | No | `""` | Response body content. |
| `headers` | array | No | `[]` | Headers to include in immediate response. |

### Header Object

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | Yes | Header name. |
| `value` | string | Yes | Header value. |

### System Parameters

This policy does not require system-level configuration.

## Behavior Notes

- If `headers` is not an array/object list with valid `name`/`value`, policy returns `500` configuration error.
- Policy executes only in request flow; `OnResponse` is a no-op.
- If no `body` is provided, an empty body is returned.

## API Definition Examples

### Example 1: Simple Mock Response

```yaml
policies:
  - name: respond
    version: v0
    params:
      statusCode: 200
      body: '{"status":"ok"}'
      headers:
        - name: content-type
          value: application/json
```

### Example 2: Controlled Error Response

```yaml
policies:
  - name: respond
    version: v0
    params:
      statusCode: 503
      body: '{"error":"service unavailable"}'
      headers:
        - name: content-type
          value: application/json
        - name: retry-after
          value: "30"
```

### Example 3: Plain Text Short-Circuit

```yaml
policies:
  - name: respond
    version: v0
    params:
      statusCode: 200
      body: "pong"
      headers:
        - name: content-type
          value: text/plain
```
