---
title: "Overview"
---
# Basic Authentication

## Overview

The Basic Authentication policy protects APIs using HTTP Basic Authentication. It validates the `Authorization` header against configured credentials and either allows the request to continue or returns `401 Unauthorized`.

The policy also writes authentication metadata to the request context for downstream policies:
- `auth.success`
- `auth.username` (on success)
- `auth.method` (`"basic"`)

## Features

- Validates HTTP Basic credentials from `Authorization` header
- Uses constant-time credential comparison
- Optional `allowUnauthenticated` mode for soft-auth scenarios
- Configurable `realm` for `WWW-Authenticate`
- Request-phase only (no response-phase processing)

## Configuration

### User Parameters (API Definition)

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `username` | string | Yes | - | Expected username in Basic credentials. |
| `password` | string | Yes | - | Expected password in Basic credentials. |
| `allowUnauthenticated` | boolean | No | `false` | If `true`, failed authentication is recorded in metadata but request is still forwarded. |
| `realm` | string | No | `Restricted` | Realm value used in `WWW-Authenticate` challenge. |

### System Parameters

This policy does not require system-level configuration.

## Behavior Notes

- Missing/invalid policy config (`username`/`password`) returns `500` with JSON error.
- Missing/invalid credentials returns `401` with:
  - `WWW-Authenticate: Basic realm="..."`
  - JSON body: `{"error":"Unauthorized","message":"Authentication required"}`
- If `allowUnauthenticated: true`, auth failures do not block the request.

## API Definition Examples

### Example 1: Enforce Basic Authentication

```yaml
policies:
  - name: basic-auth
    version: v0
    params:
      username: admin
      password: s3cret
```

### Example 2: Custom Realm

```yaml
policies:
  - name: basic-auth
    version: v0
    params:
      username: gateway-user
      password: strong-password
      realm: Internal APIs
```

### Example 3: Soft Authentication (Allow Unauthenticated)

```yaml
policies:
  - name: basic-auth
    version: v0
    params:
      username: analytics-user
      password: analytics-pass
      allowUnauthenticated: true
```
