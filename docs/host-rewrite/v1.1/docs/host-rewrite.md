---
title: "Overview"
---
# Host Rewrite

## Overview

The Host Rewrite policy sets (rewrites) the Host/:authority header on requests before
they are forwarded to the upstream. This is useful when the upstream expects a
specific Host header that differs from the incoming request's Host.

Important: for the kernel to forward the request using the rewritten Host, the
upstream definition must set hostRewrite: manual on the named upstream.

Example upstream configuration:

```yaml
upstream:
  main:
    url: "http://example.com"
    hostRewrite: manual
```

## Features

- Rewrite the Host/:authority header sent to the upstream
- Simple single-parameter configuration (host)
- Validates that a non-empty host string is provided

## Configuration

This policy expects a single parameter `host` (string) that contains the Host
value to send to the upstream. The parameter is configured in the API/operation
policies list in the API definition YAML.

### User Parameters (API Definition)

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `host` | string | Yes | The Host header value to set on the upstream request. Allowed characters: letters, digits, `-` and `.`. Length: 1-255. |

### Sample policy params

```yaml
- name: host-rewrite
  version: v1
  params:
    host: example-updated.com
```

## Example API snippet

Apply the policy to the API (or an operation). The upstream must use `hostRewrite: manual`.

```yaml
apiVersion: gateway.api-platform.wso2.com/v1
kind: RestApi
metadata:
  name: example-api
spec:
  displayName: Example API
  version: v1.0
  context: /example/$version
  upstream:
    main:
      url: http://example-backend:8080
      hostRewrite: manual
  policies:
    - name: host-rewrite
      version: v1
      params:
        host: example-updated.com
  operations:
    - method: GET
      path: /resource
```

## How it works

- At request header processing, the policy validates the `host` parameter.
- If valid, it returns an UpstreamRequestHeaderModifications action with the
  Host field set to the configured value. The kernel applies this before
  forwarding the request to the upstream.
- If configuration is invalid (missing/empty/incorrect type), the policy
  returns an immediate 500 configuration error response.

## Notes

- The policy only rewrites the Host sent to upstream; it does not change the
  request URL or routing unless the upstream uses the Host for virtual hosting.
- Ensure `host` is a hostname optionally including ports if required by your
  upstream (e.g. `backend.example.com:8080`).
- The upstream `hostRewrite: manual` setting is required for the rewritten Host
  to be used when forwarding to the upstream.

## Fault reporting

From v1.1, every rejection this policy makes is also reported to the gateway as a **fault**:
a stable code and type alongside the response. A gateway that supports fault policies uses it
for the analytics event and hands it to the API's fault policies (for example `log-message`, to
log the failure). The status and body the client receives are the same as in v1.0. A gateway
without fault policy support ignores the fault, and the policy behaves exactly as v1.0.

| When | Status | Code | Type |
|------|--------|------|------|
| The `host` parameter is missing, not a string, or empty | `500` | `960000` | `configuration` |

The fault's `Description` carries the internal reason, for example `host parameter cannot be empty`.
The response body's `message` field carries the same reason, as it did in v1.0, so the client
receives it; the fault's `Message` is the generic `Configuration Error`.
