---
title: "Overview"
---
# Modify Headers

## Overview

The Modify Headers policy provides comprehensive HTTP header manipulation for both request and response flows. It can set (replace) header values or delete headers on incoming requests before forwarding to upstream services, and on outgoing responses before returning to clients.

Unlike policies that only add or only set headers, this policy combines both update and removal operations in a single configuration. Header names are normalized for consistent behavior, and modifications are applied independently for request and response phases.

## Features

- Modifies request headers before forwarding to upstream services
- Modifies response headers before returning to clients
- Supports both request and response phases independently or simultaneously
- Supports `SET` action to set/replace header values
- Supports `DELETE` action to remove headers
- Proper header name normalization (lowercase handling for consistent behavior)
- Last-value-wins behavior for duplicate `SET` operations on the same header name
- Comprehensive validation for malformed action/name/value entries

## Configuration

The Modify Headers policy can be configured for request phase, response phase, or both. This policy requires only a single-level configuration where all parameters are configured in the API definition YAML.

### User Parameters (API Definition)

These parameters are configured per-API/route by the API developer:

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `requestHeaders` | `HeaderModification` array | No | - | Array of header modifications to apply to requests before forwarding to upstream. |
| `responseHeaders` | `HeaderModification` array | No | - | Array of header modifications to apply to responses before returning to clients. |

### HeaderModification Configuration

Each `HeaderModification` object in `requestHeaders` and `responseHeaders` supports:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `action` | string | Yes | Action to perform on the header. Supported values: `SET`, `DELETE`. |
| `name` | string | Yes | Header name (case-insensitive). Must match `^[a-zA-Z0-9-_]+$` and cannot be empty. |
| `value` | string | Conditional | Header value. Required for `SET`; ignored for `DELETE`. Maximum length: 8192. |

**Note:**
At least one of `requestHeaders` or `responseHeaders` must be specified in the policy configuration.

Inside the `gateway/build.yaml`, ensure the policy module is added under `policies:`:

```yaml
- name: modify-headers
  gomodule: github.com/wso2/gateway-controllers/policies/modify-headers@v0
```

## Reference Scenarios:

### Example 1: SET Request Headers for Upstream Integration

Set request headers before forwarding to upstream:

```yaml
apiVersion: gateway.api-platform.wso2.com/v1alpha1
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
    - name: modify-headers
      version: v0
      params:
        requestHeaders:
          - action: SET
            name: X-API-Key
            value: "12345-abcde-67890-fghij"
          - action: SET
            name: X-Client-Version
            value: "1.2.3"
  operations:
    - method: GET
      path: /{country_code}/{city}
```

**Request transformation (SET):**

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

### Example 2: DELETE Sensitive Request Headers

Remove sensitive request headers before forwarding to upstream:

```yaml
apiVersion: gateway.api-platform.wso2.com/v1alpha1
kind: RestApi
metadata:
  name: sanitize-api-v1.0
spec:
  displayName: Sanitize-API
  version: v1.0
  context: /sanitize/$version
  upstream:
    main:
      url: http://sample-backend:5000/api/v2
  policies:
    - name: modify-headers
      version: v0
      params:
        requestHeaders:
          - action: DELETE
            name: Authorization
          - action: DELETE
            name: X-Internal-Token
  operations:
    - method: POST
      path: /submit
```

**Request transformation (DELETE):**

Original client request
```http
POST /sanitize/v1.0/submit HTTP/1.1
Host: api-gateway.company.com
Content-Type: application/json
Authorization: Bearer eyJ...
X-Internal-Token: secret-token
X-Request-ID: req-001

{"payload":"value"}
```

Resulting upstream request
```http
POST /api/v2/submit HTTP/1.1
Host: sample-backend:5000
Content-Type: application/json
X-Request-ID: req-001

{"payload":"value"}
```

### Example 3: Modify Response Headers (SET + DELETE)

Set security headers and remove response headers in one policy:

```yaml
apiVersion: gateway.api-platform.wso2.com/v1alpha1
kind: RestApi
metadata:
  name: secure-api-v1.0
spec:
  displayName: Secure-API
  version: v1.0
  context: /secure/$version
  upstream:
    main:
      url: http://sample-backend:5000/api/v2
  policies:
    - name: modify-headers
      version: v0
      params:
        responseHeaders:
          - action: SET
            name: X-Content-Type-Options
            value: "nosniff"
          - action: SET
            name: Cache-Control
            value: "no-store"
          - action: DELETE
            name: Server
  operations:
    - method: GET
      path: /profile
```

**Response transformation (SET + DELETE):**

Original upstream response
```http
HTTP/1.1 200 OK
Content-Type: application/json
Server: Apache/2.4.41
Cache-Control: public, max-age=3600
Content-Length: 42

{"name":"Alex","role":"developer"}
```

Resulting client response
```http
HTTP/1.1 200 OK
Content-Type: application/json
Cache-Control: no-store
x-content-type-options: nosniff
Content-Length: 42

{"name":"Alex","role":"developer"}
```

### Example 4: Combined Request and Response Modifications

Apply request and response header modifications in a single policy:

```yaml
apiVersion: gateway.api-platform.wso2.com/v1alpha1
kind: RestApi
metadata:
  name: full-modify-api-v1.0
spec:
  displayName: Full-Modify-API
  version: v1.0
  context: /full-modify/$version
  upstream:
    main:
      url: http://sample-backend:5000/api/v2
  policies:
    - name: modify-headers
      version: v0
      params:
        requestHeaders:
          - action: SET
            name: X-Source
            value: "api-gateway"
          - action: DELETE
            name: X-Debug
        responseHeaders:
          - action: SET
            name: X-Processed-By
            value: "gateway"
          - action: DELETE
            name: X-Powered-By
  operations:
    - method: GET
      path: /data
```

**Bidirectional transformation sample:**

Incoming client request headers
```http
GET /full-modify/v1.0/data HTTP/1.1
Host: api-gateway.company.com
X-Debug: true
```

Forwarded upstream request headers
```http
GET /api/v2/data HTTP/1.1
Host: sample-backend:5000
x-source: api-gateway
```

Returned upstream response headers
```http
HTTP/1.1 200 OK
Content-Type: application/json
X-Powered-By: backend-engine
```

Final client response headers
```http
HTTP/1.1 200 OK
Content-Type: application/json
x-processed-by: gateway
```

### Example 5: Route-Specific Header Modifications

Apply different header modifications to different routes:

```yaml
apiVersion: gateway.api-platform.wso2.com/v1alpha1
kind: RestApi
metadata:
  name: route-specific-api-v1.0
spec:
  displayName: Route-Specific-API
  version: v1.0
  context: /route-specific/$version
  upstream:
    main:
      url: http://sample-backend:5000/api/v2
  operations:
    - method: GET
      path: /public
      policies:
        - name: modify-headers
          version: v0
          params:
            responseHeaders:
              - action: SET
                name: X-Visibility
                value: "public"
    - method: GET
      path: /internal
      policies:
        - name: modify-headers
          version: v0
          params:
            requestHeaders:
              - action: SET
                name: X-Access-Level
                value: "internal"
            responseHeaders:
              - action: DELETE
                name: X-Debug-Info
```

**Route-level transformation sample:**

For `GET /public`
```http
Response to client includes: x-visibility: public
```

For `GET /internal`
```http
Request to upstream includes: x-access-level: internal
Response to client removes: x-debug-info
```

### Example 6: Default Behavior

When no parameters are specified for a flow, no modifications are applied for that flow:

```yaml
apiVersion: gateway.api-platform.wso2.com/v1alpha1
kind: RestApi
metadata:
  name: default-modify-api-v1.0
spec:
  displayName: Default-Modify-API
  version: v1.0
  context: /default-modify/$version
  upstream:
    main:
      url: http://backend-service:8080
  policies:
    - name: modify-headers
      version: v0
      params:
        requestHeaders:
          - action: SET
            name: X-App
            value: "gateway"
      # responseHeaders is omitted, so response flow is unchanged
  operations:
    - method: GET
      path: /data
```

**Behavior sample (response unchanged):**

Input upstream response headers
```http
HTTP/1.1 200 OK
Content-Type: application/json
X-Upstream: backend
```

Output client response headers (unchanged by this policy)
```http
HTTP/1.1 200 OK
Content-Type: application/json
X-Upstream: backend
```

## How it Works

* The policy parses `requestHeaders` and `responseHeaders` arrays independently and applies configured operations per flow.
* Header names are normalized to lowercase before processing, ensuring case-insensitive matching behavior.
* `SET` operations are applied via set semantics (replace existing value if the header already exists).
* `DELETE` operations remove matching headers from the message.
* If the same header appears in multiple `SET` operations in the same flow, the last configured value wins.
* Invalid runtime modification entries result in a `500` configuration error response for the relevant flow.

## Limitations

1. **Action Scope**: Only `SET` and `DELETE` actions are supported.
2. **No Conditional Rules**: Header modifications are static and cannot be dynamically conditioned on request/response content.
3. **Ordering Sensitivity**: Final header output depends on policy order when used with other header manipulation policies.
4. **Configuration Strictness**: Invalid modification entries (missing/invalid action/name/value types) fail with configuration errors.
5. **Schema Constraints Apply**: Header names and values must conform to schema constraints (pattern and length limits).

## Notes

**Security and Data Handling**

Use `DELETE` to strip sensitive headers (for example, credentials or internal tracing data) before forwarding to upstream systems. Avoid setting secrets in client-facing response headers, and ensure any dynamically resolved values are sanitized. Restrict who can configure header modification policies because they can alter trust boundaries between clients, gateway, and upstream services.

**Performance and Operational Impact**

Header modification is lightweight and local, but excessive header operations can increase response size and impact intermediaries with strict header limits. Keep configurations minimal and purpose-driven, especially for high-throughput APIs. Monitor downstream rejections caused by oversized or unexpected header sets.

**Operational Best Practices**

Use route-level policies when different endpoints require different header contracts. Document which headers are set and removed per route so client and backend teams have a consistent contract. Test policy interactions with `add-headers`, `set-headers`, and authentication policies to validate final header precedence and expected behavior.
