---
title: "Overview"
---
# Remove Headers

## Overview

The Remove Headers policy dynamically removes HTTP headers from incoming requests before they are forwarded to upstream services, and/or removes headers from outgoing responses before they are returned to clients. This policy provides comprehensive header removal functionality for both request and response flows.

## Features

- Removes specified headers from requests before forwarding to upstream services
- Removes specified headers from responses before returning to clients
- Supports both request and response phases independently or simultaneously
- Case-insensitive header name matching for reliable removal
- Header name normalization (lowercase conversion for consistency)
- Works with any HTTP method and request type
- Graceful handling of non-existent headers (no error if header doesn't exist)
- Comprehensive validation of header configurations

## Configuration

The Remove Headers policy can be configured for removal in request phase, response phase, or both.
This policy does not require system-level configuration and operates entirely based on the configured header name arrays.
At least one of `request.headers` or `response.headers` must be specified in the policy configuration. The policy will fail validation if both arrays are empty or omitted.

### User Parameters (API Definition)

These parameters are configured per-API/route by the API developer:

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `request` | `HeadersConfig` object | No | - | Request-phase header removal configuration. |
| `response` | `HeadersConfig` object | No | - | Response-phase header removal configuration. |

### HeadersConfig Configuration

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `headers` | `HeaderName` array | Yes (when the phase object is present) | Array of header names to remove in that phase. |

### HeaderName Configuration

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | Yes | Header name to remove. Matching is case-insensitive. |

**Note:**

Inside the `gateway/build.yaml`, ensure the policy module is added under `policies:`:

```yaml
- name: remove-headers
  gomodule: github.com/wso2/gateway-controllers/policies/remove-headers@v0
```

## Reference Scenarios:

### Example 1: Removing Sensitive Request Headers

Remove authentication headers before forwarding to upstream:

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
    - name: remove-headers
      version: v0
      params:
        request:
          headers:
          - name: Authorization
          - name: X-API-Key
          - name: Cookie
  operations:
    - method: GET
      path: /{country_code}/{city}
    - method: GET
      path: /alerts/active
    - method: POST
      path: /alerts/active
```

**Request transformation:**

Original client request:
```
GET /weather/v1.0/US/NewYork HTTP/1.1
Host: api-gateway.company.com
Accept: application/json
Authorization: Bearer secret-token
X-API-Key: client-secret-key
User-Agent: WeatherApp/1.0
```

Resulting upstream request:
```
GET /api/v2/US/NewYork HTTP/1.1
Host: sample-backend:5000
Accept: application/json
User-Agent: WeatherApp/1.0
```

### Example 2: Removing Server Information from Responses

Remove server identification headers from responses:

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
    - name: remove-headers
      version: v0
      params:
        response:
          headers:
          - name: Server
          - name: X-Powered-By
          - name: X-AspNet-Version
  operations:
    - method: GET
      path: /{country_code}/{city}
    - method: GET
      path: /alerts/active
    - method: POST
      path: /alerts/active
```

**Response transformation:**

Original upstream response:
```
HTTP/1.1 200 OK
Content-Type: application/json
Server: Apache/2.4.41
X-Powered-By: PHP/7.4.0
X-AspNet-Version: 4.0.30319
Content-Length: 256

{"temperature": 22, "humidity": 65}
```

Resulting client response:
```
HTTP/1.1 200 OK
Content-Type: application/json
Content-Length: 256

{"temperature": 22, "humidity": 65}
```

### Example 3: Removing Headers from Both Request and Response

Remove sensitive headers from both directions:

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
    - name: remove-headers
      version: v0
      params:
        request:
          headers:
          - name: X-Internal-Token
          - name: X-Debug-Mode
        response:
          headers:
          - name: X-Internal-Server-ID
          - name: X-Debug-Info
  operations:
    - method: GET
      path: /{country_code}/{city}
    - method: GET
      path: /alerts/active
    - method: POST
      path: /alerts/active
```

**Request and response transformation:**

Original client request:
```
GET /weather/v1.0/US/NewYork HTTP/1.1
Host: api-gateway.company.com
Accept: application/json
X-Internal-Token: internal-secret
X-Debug-Mode: enabled
```

Resulting upstream request:
```
GET /api/v2/US/NewYork HTTP/1.1
Host: sample-backend:5000
Accept: application/json
```

Original upstream response:
```
HTTP/1.1 200 OK
Content-Type: application/json
X-Internal-Server-ID: server-123
X-Debug-Info: processed-in-45ms
Content-Length: 256

{"temperature": 22, "humidity": 65}
```

Resulting client response:
```
HTTP/1.1 200 OK
Content-Type: application/json
Content-Length: 256

{"temperature": 22, "humidity": 65}
```

### Example 4: Route-Specific Header Removal

Apply different header removal rules to different routes:

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
  operations:
    - method: GET
      path: /{country_code}/{city}
      policies:
        - name: remove-headers
          version: v0
          params:
            request:
              headers:
              - name: X-Cache-Control  # Remove caching hints for weather data
            response:
              headers:
              - name: Last-Modified    # Remove caching headers
    - method: GET
      path: /alerts/active
      policies:
        - name: remove-headers
          version: v0
          params:
            request:
              headers:
              - name: If-Modified-Since  # Remove conditional headers for alerts
            response:
              headers:
              - name: ETag               # Remove caching headers for real-time alerts
    - method: POST
      path: /alerts/active
      policies:
        - name: remove-headers
          version: v0
          params:
            request:
              headers:
              - name: X-Requested-With  # Remove AJAX headers
            response:
              headers:
              - name: Location          # Remove redirect headers for API responses
```

### Example 5: Multiple Remove Headers Policies

Use multiple remove-headers policies for different purposes:

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
    # Remove authentication headers
    - name: remove-headers
      version: v0
      params:
        request:
          headers:
          - name: Authorization
          - name: X-API-Key
          - name: Cookie
    # Remove server identification
    - name: remove-headers
      version: v0
      params:
        response:
          headers:
          - name: Server
          - name: X-Powered-By
    # Remove debugging headers
    - name: remove-headers
      version: v0
      params:
        request:
          headers:
          - name: X-Debug-Mode
        response:
          headers:
          - name: X-Debug-Info
          - name: X-Trace-ID
  operations:
    - method: GET
      path: /{country_code}/{city}
    - method: GET
      path: /alerts/active
    - method: POST
      path: /alerts/active
```

## How it Works

* The policy reads `request.headers` and `response.headers` independently and removes matching headers in request and response flows.
* Header name matching is case-insensitive, and configured names are normalized for consistent processing.
* Removing a header that is not present is a no-op and does not produce runtime errors.
* For multi-value headers, removal deletes all values for the matched header name.
* Request flow removes headers before forwarding to upstream; response flow removes headers before returning to clients.
* If a flow has no configured header list, that flow passes through unchanged.


## Limitations

1. **Remove-Only Behavior**: This policy removes headers only and does not set or append new values.
2. **No Conditional Logic**: Header removal is static per policy configuration and cannot be conditional on payload or context.
3. **Configuration Dependency**: At least one of `request.headers` or `response.headers` must be configured.
4. **Ordering Sensitivity**: Policy order can affect final header output when used with other header manipulation policies.
5. **Header Constraints Apply**: Header names must comply with configured schema constraints.


## Notes

**Security and Data Handling**

Use header removal to strip sensitive or internal headers before requests leave trust boundaries and before responses reach clients. Prioritize removal of server-identification, debug, and internal tracing headers where they are not required. Ensure removed headers are not needed by downstream security controls or application behavior.

**Performance and Operational Impact**

Header removal is lightweight and local, with minimal processing overhead. Even so, validate changes in environments with strict intermediary rules to ensure removed headers do not affect caching, routing, or observability unexpectedly. Monitor for client or backend dependency on headers that are being removed.

**Operational Best Practices**

Apply route-specific rules when only selected operations require header removal, rather than enforcing broad removal globally. Document removed headers for client and backend teams to keep integration contracts clear. Test policy interactions with `add-headers`, `set-headers`, and `modify-headers` to confirm final header outcomes.
