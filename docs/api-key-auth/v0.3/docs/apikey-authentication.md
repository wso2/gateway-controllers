---
title: "Overview"
---
# API Key Authentication

## Overview

The API Key Authentication policy validates API keys to secure APIs by verifying pre-generated keys before allowing access to protected resources. This policy supports both header-based and query parameter-based key validation.

## Features

- Validates API keys from request headers or query parameters
- Flexible authentication source configuration (`header` or `query`)
- Pre-generated key validation against gateway-managed key lists
- Request context enrichment with authentication metadata
- Case-insensitive header matching

## Configuration

The API Key Authentication policy uses a single-level configuration model where all parameters are configured per API or route in the API definition YAML.

### User Parameters (API Definition)

These parameters are configured per API or route by the API developer:

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `key` | string | Yes | `API-Key` | The name of the header or query parameter that contains the API key. For headers, case-insensitive matching is used (for example, `X-API-Key`, `Authorization`). For query parameters, exact name matching is used (for example, `api_key`, `token`). |
| `in` | string | Yes | `header` | Specifies where to look for the API key. Must be either `header` or `query`. |

**Note:**

Inside `gateway/build.yaml`, ensure the policy module is added under `policies`:

```yaml
- name: api-key-auth
  gomodule: github.com/wso2/gateway-controllers/policies/api-key-auth@v0
```

## Reference Scenarios

### Example 1: Basic API Key Authentication (Header)

Apply API key authentication using a custom header.

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

### Example 2: Authorization Header Key

Use the `Authorization` header as the API key source.

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
  operations:
    - method: GET
      path: /{country_code}/{city}
    - method: GET
      path: /alerts/active
    - method: POST
      path: /alerts/active
```

### Example 3: Query Parameter Authentication

Extract API key from a query parameter.

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

### Example 4: Custom Header Authentication

Use a custom request header as the API key source.

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
  operations:
    - method: GET
      path: /{country_code}/{city}
    - method: GET
      path: /alerts/active
    - method: POST
      path: /alerts/active
```

### Example 5: Route-Specific Authentication

Apply different API key configurations to different routes.

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
    - method: POST
      path: /alerts/active
```

## How it Works

- On each request, the gateway policy reads `key` and `in` from the policy configuration (or uses defaults) and validates the resolved values.
- Based on `in`, it extracts the API key either from a request header (case-insensitive lookup) or from a query parameter in the request URL.
- If the key is missing, empty, or the required API context values are unavailable, the policy short-circuits the request and returns `401 Unauthorized` with a JSON error response.
- For valid inputs, the policy calls the API key store validator using API and operation context (`apiId`, operation path, HTTP method) to determine whether the key is allowed for the target operation.
- On successful validation, the request continues upstream and authentication metadata is added to request context (`auth.success=true`, `auth.method=api-key`). The policy does not modify response traffic (`OnResponse` is a no-op).

## Notes:

- API keys offer a lightweight authentication mechanism for internal services, partner integrations, and service-to-service communication where full OAuth flows are not required.
- Store API keys securely and avoid exposing them in client-side code, logs, or version control systems.
- Always transmit API keys over HTTPS and follow secure key rotation and revocation practices.
