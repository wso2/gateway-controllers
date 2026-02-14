---
title: "Overview"
---
# Add Headers

## Overview

The Add Headers policy dynamically adds HTTP headers to incoming requests before they are forwarded to upstream services, and/or adds headers to outgoing responses before they are returned to clients. **Headers are appended to existing headers rather than replacing them**, which means multiple values for the same header name will coexist.

## Features

- Adds custom headers to requests before forwarding to upstream services
- Adds custom headers to responses before returning to clients
- Supports both request and response phases independently or simultaneously
- Appends headers instead of replacing them, preserving multiple values for the same header name.
- Proper header name normalization (lowercase conversion for HTTP/2 compatibility)
- Static value assignment with support for special characters and complex values
- Works with any HTTP method and request type
- Preserves existing headers without conflicts
- Comprehensive validation of header configurations

## Configuration

This policy uses a single-level configuration where all parameters are configured in the API definition YAML.

At least one of `requestHeaders` or `responseHeaders` must be specified in the policy configuration. The policy will fail validation if both arrays are empty or omitted.

### User Parameters (API Definition)

These parameters are configured per-API/route by the API developer:

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `requestHeaders` | ```HeaderObject``` array | No | - | Array of header objects to add to requests before forwarding to upstream. Each object must contain `name` and `value` fields. |
| `responseHeaders` | ```HeaderObject``` array | No | - | Array of header objects to add to responses before returning to clients. |

### HeaderObject 

Each header object in the `requestHeaders` and `responseHeaders` arrays must contain:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | Yes | The name of the HTTP header to add. Header names are automatically normalized to lowercase for consistency. Cannot be empty or whitespace-only. |
| `value` | string | Yes | The value of the HTTP header to add. Can be static text, empty string, or contain special characters and complex values. |

**Note:**

Inside the `gateway/build.yaml`, ensure the policy module is added under `policies:`:

```yaml
- name: add-headers
  gomodule: github.com/wso2/gateway-controllers/policies/add-headers@v0
```

## Reference Scenarios

### Example 1: Adding Request Headers for Authentication

Add authentication headers to all requests sent to upstream:

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
    - name: add-headers
      version: v0
      params:
        requestHeaders:
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

**Request transformation:**

Original client request:
```
GET /weather/v1.0/US/NewYork HTTP/1.1
Host: api-gateway.company.com
Accept: application/json
User-Agent: WeatherApp/1.0
```

Resulting upstream request:
```
GET /api/v2/US/NewYork HTTP/1.1
Host: sample-backend:5000
Accept: application/json
User-Agent: WeatherApp/1.0
x-api-key: 12345-abcde-67890-fghij
x-client-version: 1.2.3
```

### Example 2: Adding Headers to Both Request and Response

Add headers to both requests (for upstream) and responses (for clients):

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
    - name: add-headers
      version: v0
      params:
        requestHeaders:
          - name: X-Source
            value: "api-gateway"
          - name: X-Request-ID
            value: "req-12345"
        responseHeaders:
          - name: X-Cache-Status
            value: "MISS"
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

**Request transformation:**

Original client request:
```
GET /weather/v1.0/US/NewYork HTTP/1.1
Host: api-gateway.company.com
Accept: application/json
```

Resulting upstream request:
```
GET /api/v2/US/NewYork HTTP/1.1
Host: sample-backend:5000
Accept: application/json
x-source: api-gateway
x-request-id: req-12345
```

**Response transformation:**

Original upstream response:
```
HTTP/1.1 200 OK
Content-Type: application/json
Content-Length: 256

{"temperature": 22, "humidity": 65}
```

Resulting client response:
```
HTTP/1.1 200 OK
Content-Type: application/json
Content-Length: 256
x-cache-status: MISS
x-server-version: 2.1.0

{"temperature": 22, "humidity": 65}
```

### Example 3: Multiple Header Policies

Use multiple add-headers policies for different purposes:

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
    # Authentication headers
    - name: add-headers
      version: v0
      params:
        requestHeaders:
          - name: X-API-Key
            value: "12345-abcde-67890-fghij"
          - name: X-Client-ID
            value: "weather-gateway"
    # Security headers
    - name: add-headers
      version: v0
      params:
        responseHeaders:
          - name: X-Content-Type-Options
            value: "nosniff"
          - name: X-Frame-Options
            value: "DENY"
    # Tracking headers
    - name: add-headers
      version: v0
      params:
        requestHeaders:
          - name: X-Source
            value: "gateway"
        responseHeaders:
          - name: X-Gateway-Version
            value: "v2.1.0"
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
Set-Cookie: existing=value123
Content-Length: 256

{"temperature": 22, "humidity": 65}
```

Resulting client response:
```
HTTP/1.1 200 OK
Content-Type: application/json
Set-Cookie: existing=value123
Set-Cookie: sessionid=abc123; Path=/; HttpOnly
Set-Cookie: userid=xyz789; Path=/; Secure
Set-Cookie: theme=dark; Path=/; SameSite=Strict
Content-Length: 256

{"temperature": 22, "humidity": 65}
```

### Example 4: Route-Specific Headers

Apply different headers to different routes:

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
        - name: add-headers
          version: v0
          params:
            requestHeaders:
              - name: X-Operation-Type
                value: "weather-query"
            responseHeaders:
              - name: X-Data-Source
                value: "weather-service"
    - method: GET
      path: /alerts/active
      policies:
        - name: add-headers
          version: v0
          params:
            requestHeaders:
              - name: X-Operation-Type
                value: "alert-query"
            responseHeaders:
              - name: X-Real-Time
                value: "true"
    - method: POST
      path: /alerts/active
      policies:
        - name: add-headers
          version: v0
          params:
            requestHeaders:
              - name: X-Operation-Type
                value: "alert-create"
            responseHeaders:
              - name: X-Processing-Mode
                value: "async"
```

### Example 5: Multiple Headers with Same Name (Append Behavior)

Demonstrate header appending behavior with multiple Set-Cookie headers:

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
    - name: add-headers
      version: v0
      params:
        responseHeaders:
          - name: Set-Cookie
            value: "sessionid=abc123; Path=/; HttpOnly"
          - name: Set-Cookie  # Same header name - will be appended
            value: "userid=xyz789; Path=/; Secure"
          - name: Set-Cookie  # Another Set-Cookie - will also be appended
            value: "theme=dark; Path=/; SameSite=Strict"
  operations:
    - method: GET
      path: /{country_code}/{city}
    - method: GET
      path: /alerts/active
    - method: POST
      path: /alerts/active
```

## How it Works

### Header Append Behavior

The policy uses **append semantics** instead of replace semantics:

- **Existing Headers**: Headers added by the policy are appended to any existing headers with the same name
- **Multiple Configuration**: If the same header name is configured multiple times in the policy, all values are added
- **Preservation**: Existing headers from the original request/response are never overwritten
- **Order**: New header values are appended after existing values
- **Common Use Case**: Particularly useful for headers like `Set-Cookie`, `Cache-Control`, `Vary`, etc.

### Header Name Normalization

The policy automatically normalizes header names for consistency:

- **Case Conversion**: All header names are converted to lowercase (e.g., "X-API-Key" becomes "x-api-key")
- **Whitespace Trimming**: Leading and trailing whitespace is removed from header names
- **HTTP/2 Compatibility**: Lowercase headers ensure compatibility with HTTP/2 protocol requirements
- **Existing Headers**: Normalization applies only to added headers, existing headers remain unchanged

### Header Value Handling

Header values are preserved exactly as configured:

- **Special Characters**: All special characters in values are preserved without encoding
- **Whitespace**: Leading and trailing whitespace in values is preserved
- **Empty Values**: Empty string values are supported and valid
- **Unicode**: Unicode characters are supported and preserved
- **Case Sensitivity**: Header values are case-sensitive and preserved as-is

### Error Handling

The policy includes robust error handling and validation:

1. **Missing Configuration**: If neither `requestHeaders` nor `responseHeaders` is specified, validation fails at configuration time
2. **Invalid Arrays**: If header arrays are not properly formatted, validation fails at configuration time
3. **Missing Fields**: If header objects are missing `name` or `value` fields, validation fails at configuration time
4. **Empty Names**: If header names are empty or whitespace-only, validation fails at configuration time
5. **Runtime Errors**: Policy execution errors do not affect request processing (graceful degradation)


## Notes:

- Provides lightweight, efficient local header processing with minimal memory overhead, no external network calls, and separate request and response phases for optimal performance.

- Follow best practices by using clear and non-conflicting header names, securing sensitive values, accounting for header normalization, validating configurations, documenting changes, separating policies by purpose, and minimizing unnecessary headers to maintain performance.

- Ensure headers do not expose sensitive data, prevent injection by trusting and validating sources, sanitize logs, enforce proper access control, respect header size limits, align CORS settings with security policies, and only add headers that upstream services and clients can securely handle.
