---
title: "Overview"
---
# API Key Authentication

## Overview

The API Key Authentication policy validates API keys to secure APIs by verifying pre-generated keys before allowing access to protected resources. This policy is essential for API security, supporting both header-based and query parameter-based key validation.

## Features

- Validates API keys from request headers or query parameters
- Configurable key extraction with optional prefix stripping
- Flexible authentication source configuration (header/query)
- Pre-generated key validation against gateway-managed key lists
- Request context enrichment with authentication metadata
- Case-insensitive header matching

## Configuration

The API Key Authentication policy uses a single-level configuration model where all parameters are configured per-API/route in the API definition YAML. 

### User Parameters (API Definition)

These parameters are configured per-API/route by the API developer:

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `key` | string | Yes | - | The name of the header or query parameter that contains the API key. For headers: case-insensitive matching is used (e.g., "X-API-Key", "Authorization"). For query parameters: exact name matching is used (e.g., "api_key", "token"). |
| `in` | string | Yes | - | Specifies where to look for the API key. Must be either "header" or "query". |
| `value-prefix` | string | No | - | Optional prefix that should be stripped from the API key value before validation. Case-insensitive matching and removal. Common use case is "Bearer " for Authorization headers. |

**Note:**

Inside the `gateway/build.yaml`, ensure the policy module is added under `policies:`:

```yaml
- name: api-key-auth
  gomodule: github.com/wso2/gateway-controllers/policies/api-key-auth@v0
```

## Reference Scenarios

### Example 1: Basic API Key Authentication (Header)

Apply API key authentication using a custom header

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
    - name: api-key-auth
      version: v0
      params:
        key: X-API-Key
        in: header
  operations:
    - method: GET
      path: /{country_code}/{city}
    - method: GET
      path: /alerts/active
    - method: POST
      path: /alerts/active
```

### Example 2: Authorization Header with Bearer Prefix

Use API key in Authorization header with Bearer prefix

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
    - name: api-key-auth
      version: v0
      params:
        key: Authorization
        in: header
        value-prefix: "Bearer "
  operations:
    - method: GET
      path: /{country_code}/{city}
    - method: GET
      path: /alerts/active
    - method: POST
      path: /alerts/active
```

### Example 3: Query Parameter Authentication

Extract API key from query parameter

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
    - name: api-key-auth
      version: v0
      params:
        key: api_key
        in: query
  operations:
    - method: GET
      path: /{country_code}/{city}
    - method: GET
      path: /alerts/active
    - method: POST
      path: /alerts/active
```

### Example 4: Custom Header with Custom Prefix

Use a custom header with a custom prefix

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
    - name: api-key-auth
      version: v0
      params:
        key: X-Custom-Auth
        in: header
        value-prefix: "ApiKey "
  operations:
    - method: GET
      path: /{country_code}/{city}
    - method: GET
      path: /alerts/active
    - method: POST
      path: /alerts/active
```

### Example 5: Route-Specific Authentication

Apply different API key configurations to different routes

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
    - name: api-key-auth
      version: v0
      params:
        key: X-Custom-Auth
        in: header
        value-prefix: "ApiKey "
  operations:
    - method: GET
      path: /{country_code}/{city}
      policies:
        - name: api-key-auth
          version: v0
          params:
            key: X-API-Key
            in: header
    - method: GET
      path: /alerts/active
      policies:
        - name: api-key-auth
          version: v0
          params:
            key: Authorization
            in: header
            value-prefix: "Bearer "
    - method: POST
      path: /alerts/active
```

## How it Works

- On each request, the gateway policy reads `key`, `in`, and optional `value-prefix` from the policy configuration and validates that required parameters are present.

- Based on `in`, it extracts the API key either from a request header (case-insensitive header lookup) or from a query parameter in the request URL.

- If `value-prefix` is configured (for example, `Bearer `), the policy strips that prefix from the extracted value before validation.

- If the key is missing, empty, or the required API context values are unavailable, the policy short-circuits the request and returns `401 Unauthorized` with a JSON error response.

- For valid inputs, the policy calls the API key store validator using API and operation context (`apiId`, operation path, HTTP method) to determine whether the key is allowed for the target operation.

- On successful validation, the request continues upstream and authentication metadata is added to request context (`auth.success=true`, `auth.method=api-key`). The policy does not modify response traffic (`OnResponse` is a no-op).

- Key lifecycle and control-plane capabilities still apply, but are handled outside this gateway runtime policy: quota enforcement (including `remaining_api_key_quota` in key management APIs), key generation/regeneration, key format, secure hashing/storage, masking, access control, and audit logging.


## Notes:

- API keys offer a lightweight, secure authentication mechanism for internal services, partner and third-party integrations, legacy systems, development and testing environments, and service-to-service communication, providing a practical alternative to complex OAuth flows while ensuring controlled access through HTTPS-only transmission, secure hashing, masking, and constant-time validation.

- Store API keys securely, never exposing them in client-side code, logs, or version control systems.

- The platform enforces access control, audit logging, and quota limits to prevent abuse and support traceability. To maintain security over time, keys should be regenerated regularly, handled carefully in logs and query parameters, and revoked immediately if compromised.

- Use clear, descriptive naming and maintain separate keys per environment (development, staging, production) to simplify management.

- Always transmit API keys over HTTPS only and ensure logging practices do not inadvertently expose sensitive key material.

