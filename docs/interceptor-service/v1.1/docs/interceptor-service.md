---
title: "Overview"
---

# Interceptor Service Policy

## Overview

The Interceptor Service policy lets API authors plug a user-written HTTP service into the gateway's request and/or response phases. The gateway acts as the client of the user's service: it POSTs structured request/response data to two well-known endpoints (`/handle-request` and `/handle-response`), and translates the JSON reply back into gateway actions such as header, body, and path mutations, dynamic-endpoint routing, or short-circuit responses.

The interceptor service can be implemented in any language. Before attaching this policy, you must implement an HTTP service that conforms to the OpenAPI contract shipped alongside this documentation: [`interceptor-service-open-api-v1.yaml`](https://raw.githubusercontent.com/wso2/gateway-controllers/main/docs/interceptor-service/v0.9/docs/interceptor-service-open-api-v1.yaml). Use this spec to generate server stubs (for example, with `openapi-generator`) or as a reference when implementing the two endpoints by hand. The service must expose `POST /handle-request` and `POST /handle-response` with the request and response bodies described in the spec.

Use this policy when built-in policies cannot express the required mediation logic — for example, when calling out to a custom PII redaction service, applying business rules implemented in another team's service, or routing to dynamic upstreams based on request body inspection.

## Features

- Request-phase interception that can mutate or short-circuit the request before it reaches upstream.
- Response-phase interception that can mutate the response before it reaches the client.
- Header, body, and path mutation driven by the interceptor reply.
- Dynamic endpoint routing via the gateway's named-upstream mechanism.
- Direct response — interceptor can short-circuit the chain with its own status, headers, and body.
- Cross-phase `interceptorContext` round-trip from the request phase to the response phase via shared metadata.
- Per-phase passthrough-on-error for graceful degradation when the interceptor service is unavailable.
- Configurable per-call timeout and TLS verification posture.
- Fine-grained control over which fields (request/response headers and bodies) are sent to the interceptor.

## Configuration

The Interceptor Service policy uses a single-level configuration model where all parameters are configured per-API in the API definition YAML. This policy does not require system-level configuration.

### User Parameters (API Definition)

These parameters are configured per-API/route by the API developer:

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `endpoint` | string | Yes | — | Base URL of the interceptor service (for example, `https://my-svc:8443/api/v1`). The policy posts to `{endpoint}/handle-request` and `{endpoint}/handle-response`. |
| `request` | object | Conditional | — | Enables request-phase interception. At least one of `request` or `response` must be provided. |
| `request.includeRequestHeaders` | boolean | No | `true` | If true, the request headers are sent to the interceptor. |
| `request.includeRequestBody` | boolean | No | `true` | If true, the request body is base64-encoded and sent to the interceptor. |
| `request.passthroughOnError` | boolean | No | `false` | If true, the request continues to upstream when the interceptor call fails or times out. If false, the gateway returns a `500` response. |
| `response` | object | Conditional | — | Enables response-phase interception. At least one of `request` or `response` must be provided. |
| `response.includeRequestHeaders` | boolean | No | `false` | If true, the original request headers are echoed to the interceptor in the response phase. |
| `response.includeRequestBody` | boolean | No | `false` | If true, the original request body is echoed to the interceptor (base64). |
| `response.includeResponseHeaders` | boolean | No | `true` | If true, the upstream response headers are sent to the interceptor. |
| `response.includeResponseBody` | boolean | No | `true` | If true, the upstream response body is base64-encoded and sent to the interceptor. |
| `response.passthroughOnError` | boolean | No | `false` | If true, the upstream response is forwarded unchanged when the interceptor call fails or times out. If false, the gateway returns a `500` response. |
| `timeoutMillis` | integer | No | `5000` | Per-call HTTP timeout in milliseconds. Valid range: `100`–`60000`. |
| `tlsSkipVerify` | boolean | No | `false` | If true, TLS certificate verification is skipped when calling the interceptor. Intended for development and test environments only. |

### System Parameters (From config.toml)

These parameters are configured at the gateway level by the platform operator:

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `maxResponseSize` | integer | No | `1048576` | Maximum size in bytes of the JSON response body the gateway will read from the interceptor service. Responses exceeding this limit are treated as an interceptor failure. Default is 1 MiB. |

Example `config.toml` entry:

```toml
[policy_configurations.interceptor_service_v0]
maxresponsesize = 1048576
```

**Note:**

Inside the `gateway/build.yaml`, ensure the policy module is added under `policies:`:

```yaml
- name: interceptor-service
  gomodule: github.com/wso2/gateway-controllers/policies/interceptor-service@v1
```

## Reference Scenarios

### Example 1: Request-Only Interceptor (PII Redaction)

Send the request body to a PII redaction service before it reaches upstream. If the interceptor is unreachable, the request is rejected.

```yaml
apiVersion: gateway.api-platform.wso2.com/v1
kind: RestApi
metadata:
  name: chat-api-v1.0
spec:
  displayName: Chat-API
  version: v1.0
  context: /chat/$version
  upstream:
    main:
      url: http://chat-backend:8080
  policies:
    - name: interceptor-service
      version: v1
      params:
        endpoint: https://pii-redactor:8443/api/v1
        request:
          includeRequestHeaders: true
          includeRequestBody: true
          passthroughOnError: false
        timeoutMillis: 3000
  operations:
    - method: POST
      path: /completions
```

The interceptor receives a payload like the following on `POST /handle-request`:

```json
{
  "requestHeaders": {"content-type": "application/json"},
  "requestBody": "eyJtZXNzYWdlcyI6W3sicm9sZSI6InVzZXIiLCJjb250ZW50IjoiSGVsbG8ifV19",
  "invocationContext": {
    "requestId": "75269e44-f797-4432-9906-cf39e68d6ab8",
    "apiName": "Chat-API",
    "apiVersion": "v1.0",
    "method": "POST",
    "path": "/chat/v1.0/completions",
    "scheme": "https"
  }
}
```

A reply that rewrites the request body:

```json
{
  "body": "eyJtZXNzYWdlcyI6W3sicm9sZSI6InVzZXIiLCJjb250ZW50IjoiSGVsbG8gW1JFREFDVEVEXSJ9XX0=",
  "headersToAdd": {"x-redacted": "true"}
}
```

### Example 2: Direct Respond (Short-Circuit With 403)

Use the interceptor to authorize the request based on custom business rules. When the interceptor denies the request, the gateway returns the interceptor's response directly to the client without contacting upstream.

```yaml
apiVersion: gateway.api-platform.wso2.com/v1
kind: RestApi
metadata:
  name: orders-api-v1.0
spec:
  displayName: Orders-API
  version: v1.0
  context: /orders/$version
  upstream:
    main:
      url: http://orders-backend:8080
  policies:
    - name: interceptor-service
      version: v1
      params:
        endpoint: https://authz-svc:8443/api/v1
        request:
          includeRequestHeaders: true
          includeRequestBody: false
  operations:
    - method: POST
      path: /place
```

Interceptor reply that short-circuits with `403`:

```json
{
  "directRespond": true,
  "responseCode": 403,
  "headersToAdd": {"content-type": "application/json", "x-deny-reason": "policy"},
  "body": "eyJlcnJvciI6ImZvcmJpZGRlbiJ9"
}
```

### Example 3: Path And Dynamic Endpoint Routing

Inspect the incoming request and route it to a different upstream by name, optionally rewriting the path and query string.

```yaml
apiVersion: gateway.api-platform.wso2.com/v1
kind: RestApi
metadata:
  name: pets-api-v1.0
spec:
  displayName: Pets-API
  version: v1.0
  context: /petstore/$version
  upstream:
    main:
      url: http://pets-v1:8080
    pets-v2:
      url: http://pets-v2:8080
  policies:
    - name: interceptor-service
      version: v1
      params:
        endpoint: https://router-svc:8443/api/v1
        request:
          includeRequestHeaders: true
          includeRequestBody: false
  operations:
    - method: GET
      path: /pets/{id}
```

Interceptor reply that routes the request to the `pets-v2` upstream and rewrites the path:

```json
{
  "pathToRewrite": "/v2/pets/42?expand=tags",
  "dynamicEndpoint": {"endpointName": "pets-v2"}
}
```

### Example 4: Response-Only Interceptor (Sanitisation)

Sanitise the upstream response before it reaches the client. If the interceptor is unavailable, the upstream response is forwarded unchanged.

```yaml
apiVersion: gateway.api-platform.wso2.com/v1
kind: RestApi
metadata:
  name: docs-api-v1.0
spec:
  displayName: Docs-API
  version: v1.0
  context: /docs/$version
  upstream:
    main:
      url: http://docs-backend:8080
  policies:
    - name: interceptor-service
      version: v1
      params:
        endpoint: https://sanitizer-svc:8443/api/v1
        response:
          includeResponseHeaders: true
          includeResponseBody: true
          passthroughOnError: true
        timeoutMillis: 5000
  operations:
    - method: GET
      path: /articles/{id}
```

A response-phase reply that overrides the status code and rewrites the body:

```json
{
  "responseCode": 200,
  "headersToAdd": {"x-sanitized": "true"},
  "body": "eyJ0aXRsZSI6IkhlbGxvIiwiY29udGVudCI6IltSRURBQ1RFRF0ifQ=="
}
```

### Example 5: Request And Response Round-Trip With Shared Context

Attach the policy in both the request and response phases so the interceptor can correlate the two calls via `interceptorContext`. Anything the request-phase reply puts into `interceptorContext` is automatically echoed in the response-phase request body.

```yaml
apiVersion: gateway.api-platform.wso2.com/v1
kind: RestApi
metadata:
  name: audit-api-v1.0
spec:
  displayName: Audit-API
  version: v1.0
  context: /audit/$version
  upstream:
    main:
      url: http://audit-backend:8080
  policies:
    - name: interceptor-service
      version: v1
      params:
        endpoint: https://audit-svc:8443/api/v1
        request:
          includeRequestHeaders: true
          includeRequestBody: true
          passthroughOnError: false
        response:
          includeResponseHeaders: true
          includeResponseBody: true
          passthroughOnError: false
        timeoutMillis: 4000
  operations:
    - method: POST
      path: /events
```

Request-phase reply seeds the context:

```json
{
  "interceptorContext": {"trace": "abc-123", "actor": "user-7"}
}
```

Response-phase request body received by the interceptor:

```json
{
  "responseCode": 200,
  "responseHeaders": {"content-type": "application/json"},
  "responseBody": "eyJzdGF0dXMiOiJvayJ9",
  "invocationContext": {"requestId": "75269e44-...", "apiName": "Audit-API"},
  "interceptorContext": {"trace": "abc-123", "actor": "user-7"}
}
```
