---
title: "Overview"
---
# Set Headers

## Overview

The Set Headers policy dynamically sets or appends HTTP headers on incoming requests before they are forwarded to upstream services, and/or on outgoing responses before they are returned to clients. The behavior is controlled by the `mode` parameter:

- **`set` mode (default):** Headers are set/replaced. Existing headers with the same name are overwritten with the new value.
- **`append` mode:** Configured values are appended to the header, preserving any existing values for that header.

The `mode` parameter applies to the whole policy instance — it governs both the request and response phases together. Per-header or per-phase mode selection is not supported; attach the policy more than once (for example, at different levels) if you need different modes.

## Features

- Sets or appends custom headers on requests before forwarding to upstream services
- Sets or appends custom headers on responses before returning to clients
- Supports both request and response phases independently or simultaneously
- **Selectable behavior via `mode`**: overwrite existing headers (`set`) or add to them (`append`)
- Proper header name normalization (lowercase conversion for HTTP/2 compatibility)
- Static value assignment with support for special characters and complex values
- Works with any HTTP method and request type
- Last-value-wins behavior for duplicate header names in `set` mode; all values preserved in order in `append` mode
- Comprehensive validation of header configurations

## Configuration

The Set Headers policy can be configured for request phase, response phase, or both.
This policy does not require system-level configuration and operates entirely based on the configured header arrays.


### User Parameters (API Definition)

These parameters are configured per-API/route by the API developer:

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `mode` | string | No | `set` | Controls how configured headers are applied. `set` overwrites any existing header with the same name; `append` adds the configured value while preserving existing values. Applies to both the request and response phases. Allowed values: `set`, `append`. |
| `request` | object | No | - | Specifies request-phase header settings. Must contain a `headers` array. At least one of `request` or `response` must be specified. |
| `request.phase` | string | No | `header` | Controls when request headers are applied. Use `body` when header values depend on metadata produced while processing the request body. Allowed values: `header`, `body`. |
| `response` | object | No | - | Specifies response-phase header settings. Must contain a `headers` array. At least one of `request` or `response` must be specified. |

### Request / Response Header Configuration

Each header entry in the `request.headers` or `response.headers` array must contain:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | Yes | The name of the HTTP header to set. Header names are automatically normalized to lowercase for consistency. Must match pattern `^[a-zA-Z0-9-_]+$` and be between 1 and 256 characters. |
| `value` | string | Yes | The value of the HTTP header to set. Can be static text, empty string, or contain special characters and complex values. Maximum length is 8192 characters. |

**Note:**
At least one of `request` or `response` must be specified in the policy configuration. The policy will fail validation if both are omitted. If `mode` is specified, it must be either `set` or `append`.

Request headers use the `header` phase by default. Set `request.phase` to `body`
when a body-processing policy must run first, for example when model routing
selects a provider and the provider-specific credentials are resolved from the
resulting metadata. In body phase, the policy applies the configured request
headers after the request body has been processed.

Inside the `gateway/build.yaml`, ensure the policy module is added under `policies:`:

```yaml
- name: set-headers
  gomodule: github.com/wso2/gateway-controllers/policies/set-headers@v1
```

## Reference Scenarios:

### Example 1: Setting Request Headers for Authentication

Set authentication headers on all requests sent to upstream:

```yaml
apiVersion: gateway.api-platform.wso2.com/v1
kind: RestApi
metadata:
  name: weather-api-v1.0
spec:
  displayName: Weather-API
  version: v1.0
  context: /weather/$version
  upstream:
    main:
      url: http://sample-backend:5000/api/v2
  policies:
    - name: set-headers
      version: v1
      params:
        request:
          headers:
            - name: X-API-Key
              value: "12345-abcde-67890-fghij"
            - name: X-Client-Version
              value: "1.2.3"
  operations:
    - method: GET
      path: /{country_code}/{city}
    - method: GET
      path: /alerts/active
    - method: POST
      path: /alerts/active
```

**Request transformation (header set):**

Original client request
```http
GET /weather/v1.0/US/NewYork HTTP/1.1
Host: api-gateway.company.com
Accept: application/json
User-Agent: WeatherApp/1.0
```

Resulting upstream request
```http
GET /api/v2/US/NewYork HTTP/1.1
Host: sample-backend:5000
Accept: application/json
User-Agent: WeatherApp/1.0
x-api-key: 12345-abcde-67890-fghij
x-client-version: 1.2.3
```

### Example 2: Setting Response Headers for Security

Set security headers on all responses returned to clients:

```yaml
apiVersion: gateway.api-platform.wso2.com/v1
kind: RestApi
metadata:
  name: weather-api-v1.0
spec:
  displayName: Weather-API
  version: v1.0
  context: /weather/$version
  upstream:
    main:
      url: http://sample-backend:5000/api/v2
  policies:
    - name: set-headers
      version: v1
      params:
        response:
          headers:
            - name: X-Content-Type-Options
              value: "nosniff"
            - name: X-Frame-Options
              value: "DENY"
            - name: X-XSS-Protection
              value: "1; mode=block"
  operations:
    - method: GET
      path: /{country_code}/{city}
    - method: GET
      path: /alerts/active
    - method: POST
      path: /alerts/active
```

**Response transformation (header set):**

Original upstream response
```http
HTTP/1.1 200 OK
Content-Type: application/json
Content-Length: 256

{"temperature": 22, "humidity": 65}
```

Resulting client response
```http
HTTP/1.1 200 OK
Content-Type: application/json
Content-Length: 256
x-content-type-options: nosniff
x-frame-options: DENY
x-xss-protection: 1; mode=block

{"temperature": 22, "humidity": 65}
```

### Example 3: Setting Headers on Both Request and Response

Set headers on both requests (for upstream) and responses (for clients):

```yaml
apiVersion: gateway.api-platform.wso2.com/v1
kind: RestApi
metadata:
  name: weather-api-v1.0
spec:
  displayName: Weather-API
  version: v1.0
  context: /weather/$version
  upstream:
    main:
      url: http://sample-backend:5000/api/v2
  policies:
    - name: set-headers
      version: v1
      params:
        request:
          headers:
            - name: X-Source
              value: "api-gateway"
            - name: X-Request-ID
              value: "req-12345"
        response:
          headers:
            - name: X-Cache-Status
              value: "HIT"
            - name: X-Server-Version
              value: "2.1.0"
  operations:
    - method: GET
      path: /{country_code}/{city}
    - method: GET
      path: /alerts/active
    - method: POST
      path: /alerts/active
```

**Bidirectional transformation sample:**

Incoming client request headers
```http
GET /weather/v1.0/US/NewYork HTTP/1.1
Host: api-gateway.company.com
Accept: application/json
```

Forwarded upstream request headers
```http
GET /api/v2/US/NewYork HTTP/1.1
Host: sample-backend:5000
Accept: application/json
x-source: api-gateway
x-request-id: req-12345
```

Returned upstream response headers
```http
HTTP/1.1 200 OK
Content-Type: application/json
```

Final client response headers
```http
HTTP/1.1 200 OK
Content-Type: application/json
x-cache-status: HIT
x-server-version: 2.1.0
```

### Example 4: Route-Specific Headers

Apply different headers to different routes:

```yaml
apiVersion: gateway.api-platform.wso2.com/v1
kind: RestApi
metadata:
  name: weather-api-v1.0
spec:
  displayName: Weather-API
  version: v1.0
  context: /weather/$version
  upstream:
    main:
      url: http://sample-backend:5000/api/v2
  operations:
    - method: GET
      path: /{country_code}/{city}
      policies:
        - name: set-headers
          version: v1
          params:
            request:
              headers:
                - name: X-Operation-Type
                  value: "weather-query"
            response:
              headers:
                - name: X-Data-Source
                  value: "weather-service"
    - method: GET
      path: /alerts/active
      policies:
        - name: set-headers
          version: v1
          params:
            request:
              headers:
                - name: X-Operation-Type
                  value: "alert-query"
            response:
              headers:
                - name: X-Real-Time
                  value: "true"
    - method: POST
      path: /alerts/active
      policies:
        - name: set-headers
          version: v1
          params:
            request:
              headers:
                - name: X-Operation-Type
                  value: "alert-create"
            response:
              headers:
                - name: X-Processing-Mode
                  value: "sync"
```

**Route-level transformation sample:**

For `GET /{country_code}/{city}`
```http
Request to upstream includes: x-operation-type: weather-query
Response to client includes: x-data-source: weather-service
```

For `GET /alerts/active`
```http
Request to upstream includes: x-operation-type: alert-query
Response to client includes: x-real-time: true
```

For `POST /alerts/active`
```http
Request to upstream includes: x-operation-type: alert-create
Response to client includes: x-processing-mode: sync
```

### Example 5: Overwriting Existing Headers (Set Behavior)

Demonstrate the default `set` behavior where existing headers with the same name are replaced. The `mode` parameter is omitted here, so it defaults to `set`:

```yaml
apiVersion: gateway.api-platform.wso2.com/v1
kind: RestApi
metadata:
  name: weather-api-v1.0
spec:
  displayName: Weather-API
  version: v1.0
  context: /weather/$version
  upstream:
    main:
      url: http://sample-backend:5000/api/v2
  policies:
    - name: set-headers
      version: v1
      params:
        mode: set
        response:
          headers:
            - name: Cache-Control
              value: "public, max-age=3600"
            - name: Server
              value: "API-Gateway/2.1.0"
            - name: Content-Type
              value: "application/json; charset=utf-8"
  operations:
    - method: GET
      path: /{country_code}/{city}
    - method: GET
      path: /alerts/active
    - method: POST
      path: /alerts/active
```

**Response transformation (header overwrite):**

Original upstream response
```http
HTTP/1.1 200 OK
Content-Type: text/plain
Server: Apache/2.4.41
Cache-Control: no-cache
Content-Length: 256

{"temperature": 22, "humidity": 65}
```

Resulting client response (headers overwritten)
```http
HTTP/1.1 200 OK
Content-Type: application/json; charset=utf-8
Server: API-Gateway/2.1.0
Cache-Control: public, max-age=3600
Content-Length: 256

{"temperature": 22, "humidity": 65}
```

### Example 6: Appending Headers (Append Behavior)

Set `mode: append` to add header values without removing values already present on the request or response. This is useful for multi-valued headers such as `Vary`, `Via`, or custom headers that accumulate context as a request passes through intermediaries.

```yaml
apiVersion: gateway.api-platform.wso2.com/v1
kind: RestApi
metadata:
  name: weather-api-v1.0
spec:
  displayName: Weather-API
  version: v1.0
  context: /weather/$version
  upstream:
    main:
      url: http://sample-backend:5000/api/v2
  policies:
    - name: set-headers
      version: v1
      params:
        mode: append
        request:
          headers:
            - name: Via
              value: "1.1 api-gateway"
        response:
          headers:
            - name: Vary
              value: "Accept-Encoding"
  operations:
    - method: GET
      path: /{country_code}/{city}
    - method: GET
      path: /alerts/active
    - method: POST
      path: /alerts/active
```

**Request transformation (header append):**

Original client request
```http
GET /weather/v1.0/US/NewYork HTTP/1.1
Host: api-gateway.company.com
Accept: application/json
Via: 1.0 client-proxy
```

Resulting upstream request (value appended, existing value preserved)
```http
GET /api/v2/US/NewYork HTTP/1.1
Host: sample-backend:5000
Accept: application/json
via: 1.0 client-proxy, 1.1 api-gateway
```

**Response transformation (header append):**

Original upstream response
```http
HTTP/1.1 200 OK
Content-Type: application/json
Vary: Accept
Content-Length: 256

{"temperature": 22, "humidity": 65}
```

Resulting client response (value appended, existing value preserved)
```http
HTTP/1.1 200 OK
Content-Type: application/json
vary: Accept, Accept-Encoding
Content-Length: 256

{"temperature": 22, "humidity": 65}
```

When the same header name is configured multiple times in `append` mode, all configured values are appended in the order they appear in the array. For example, configuring `X-Roles: editor` and `X-Roles: viewer` on a request that already carries `X-Roles: admin` results in `x-roles: admin, editor, viewer`.


## How it Works

* The policy reads the `mode` parameter (defaulting to `set`) to decide whether configured headers overwrite or append.
* It reads `request.headers` and `response.headers` arrays and applies them independently on the request and response flows, using the selected mode for both.
* Header names are normalized (trimmed and lowercased) before application to ensure consistent behavior across HTTP versions.
* In `set` mode, headers are applied using set semantics: if a header already exists, its value is replaced rather than appended. If the same header is configured multiple times in the same array, the last configured value wins.
* In `append` mode, configured values are appended to existing headers, preserving any values already present. If the same header is configured multiple times in the same array, all configured values are appended in order.
* Request flow modifies outbound headers to upstream; response flow modifies outbound headers to clients.
* If no headers are configured for a flow, that flow passes through without header modification.


## Limitations

1. **Policy-Wide Mode**: The `mode` parameter applies to the entire policy instance (both request and response phases). Mixing set and append behavior within a single policy instance is not supported — attach the policy multiple times if different modes are required.
2. **No Conditional Logic**: Header setting/appending is static per policy configuration and cannot be conditional on runtime content.
3. **Configuration Dependency**: At least one of `request` or `response` must be configured; omitting both fails validation.
4. **Ordering Sensitivity**: Policy order affects final header values when combined with other header manipulation policies.
5. **Header Constraints Apply**: Header names and values must satisfy schema constraints (name pattern `^[a-zA-Z0-9-_]+$`, name max length 256, value max length 8192).


## Notes

**Security and Data Handling**

Avoid placing secrets, credentials, or personally identifiable data in headers unless strictly necessary, since headers can be logged or forwarded across multiple intermediaries. Validate and sanitize dynamic header values before injecting them to reduce header injection risks. For response headers exposed to clients, ensure values do not reveal sensitive internal topology or implementation details. When using `append` mode, be aware that values accumulate alongside any existing values, which may include client-supplied data.

**Performance and Operational Impact**

Header setting is lightweight and local, but excessive or oversized headers increase request/response size and can impact proxy or load balancer limits. Keep header sets minimal and purposeful, especially on high-throughput APIs. Monitor for rejected requests caused by upstream or intermediary header-size constraints. Note that `append` mode can grow a header's overall size, particularly when it already carries values.

**Operational Best Practices**

Use clear naming conventions and document which headers are enforced at API level versus operation level to avoid conflicts. Apply route-specific policies when different operations require different header contracts. Choose `append` mode only for headers whose semantics permit multiple values (for example, `Vary`, `Via`, `Accept`); use the default `set` mode for single-valued headers like `content-type`, `cache-control`, and `server`. Test the selected behavior explicitly to ensure downstream systems and clients behave as expected.
