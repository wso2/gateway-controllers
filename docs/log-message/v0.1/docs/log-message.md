---
title: "Overview"
---
# Log Message

## Overview

The Log Message policy provides the capability to log the payload and headers of request/response messages.
This policy operates on both the request flow (logging client requests) and the response flow (logging responses from upstream services before returning to clients).
It is designed for observability and debugging purposes without modifying the actual request/response data.

## Features

- **Configurable Logging**: Control logging of payloads and headers independently
- **Header Filtering**: Exclude sensitive headers from logging using a comma-separated list
- **Security**: Authorization headers are automatically masked with "***"
- **Request ID Tracking**: Tracks request IDs for correlation across request/response flows
- **Structured Logging**: JSON-formatted log output using Go's `slog` package at INFO level for easy parsing and analysis
- **Flow Identification**: Logs are tagged with mediation flow (REQUEST/RESPONSE)
- **Non-intrusive**: Does not modify request/response data, only logs for observability
- **Case-insensitive Header Handling**: Header exclusion works regardless of header name casing

## Configuration

Log Message policy uses a single-level configuration where all parameters are configured in the API definition YAML. 

### User Parameters (API Definition)

These parameters are configured per-API/route by the API developer:

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `logRequestPayload` | boolean | No | `false` | Enables logging of request payloads. When set to `true`, the request bodies will be logged. When set to `false`, request payloads will not be logged. |
| `logRequestHeaders` | boolean | No | `false` | Enables logging of request headers. When set to `true`, the request headers will be logged. When set to `false`, request headers will not be logged. |
| `excludedRequestHeaders` | string | No | `""` | A comma-separated list of header names to exclude from request logging when `logRequestHeaders` is enabled. Example: `"Authorization,X-API-Key"` will exclude these headers from being logged. This parameter is optional and only applies when `logRequestHeaders` is true. Header names are case-insensitive. |
| `logResponsePayload` | boolean | No | `false` | Enables logging of response payloads. When set to `true`, the response bodies will be logged. When set to `false`, response payloads will not be logged. |
| `logResponseHeaders` | boolean | No | `false` | Enables logging of response headers. When set to `true`, the response headers will be logged. When set to `false`, response headers will not be logged. |
| `excludedResponseHeaders` | string | No | `""` | A comma-separated list of header names to exclude from response logging when `logResponseHeaders` is enabled. Example: `"Authorization,X-API-Key"` will exclude these headers from being logged. This parameter is optional and only applies when `logResponseHeaders` is true. Header names are case-insensitive. |

**Note:**

Inside the `gateway/build.yaml`, ensure the policy module is added under `policies:`:

```yaml
- name: log-message
  gomodule: github.com/wso2/gateway-controllers/policies/log-message@v0
```

## Reference Scenarios

### Example 1: Default Behavior (No Logging)

When no parameters are specified, no logging is performed (all parameters default to false):

```yaml
apiVersion: gateway.api-platform.wso2.com/v1alpha1
kind: RestApi
metadata:
  name: no-logging-api-v1.0
spec:
  displayName: No Logging API
  version: v1.0
  context: /no-logging/$version
  upstream:
    main:
      url: http://backend-service:8080
  policies:
    - name: log-message
      version: v0.1.0
      # No params specified - defaults to all false (no logging)
  operations:
    - method: GET
      path: /data
    - method: POST
      path: /submit
```

### Example 2: Basic Log Message Configuration

Log both payloads and headers for all requests and responses:

```yaml
apiVersion: gateway.api-platform.wso2.com/v1alpha1
kind: RestApi
metadata:
  name: user-api-v1.0
spec:
  displayName: User API with Logging
  version: v1.0
  context: /users/$version
  upstream:
    main:
      url: http://user-service:8080
  policies:
    - name: log-message
      version: v0.1.0
      params:
        logRequestPayload: true
        logRequestHeaders: true
        logResponsePayload: true
        logResponseHeaders: true
  operations:
    - method: GET
      path: /profile
    - method: POST
      path: /profile
    - method: PUT
      path: /settings
```

### Example 3: Request-Only Logging

Log only request payloads and headers, skip response logging:

```yaml
apiVersion: gateway.api-platform.wso2.com/v1alpha1
kind: RestApi
metadata:
  name: request-only-api-v1.0
spec:
  displayName: Request Only API
  version: v1.0
  context: /request-only/$version
  upstream:
    main:
      url: http://backend-service:8080
  policies:
    - name: log-message
      version: v0.1.0
      params:
        logRequestPayload: true
        logRequestHeaders: true
        logResponsePayload: false
        logResponseHeaders: false
  operations:
    - method: POST
      path: /sensitive-data
```

### Example 3: Response-Only Logging

Log only response payloads and headers, skip request logging:

```yaml
apiVersion: gateway.api-platform.wso2.com/v1alpha1
kind: RestApi
metadata:
  name: response-only-api-v1.0
spec:
  displayName: Response Only API
  version: v1.0
  context: /response-only/$version
  upstream:
    main:
      url: http://backend-service:8080
  policies:
    - name: log-message
      version: v0.1.0
      params:
        # Request parameters default to false (omitted)
        logResponsePayload: true
        logResponseHeaders: true
  operations:
    - method: GET
      path: /public-data
```

### Example 4: Headers with Different Exclusions

Log headers but exclude different sensitive headers for requests vs responses:

```yaml
apiVersion: gateway.api-platform.wso2.com/v1alpha1
kind: RestApi
metadata:
  name: payment-api-v1.0
spec:
  displayName: Payment API
  version: v1.0
  context: /payments/$version
  upstream:
    main:
      url: http://payment-service:8080
  policies:
    - name: log-message
      version: v0.1.0
      params:
        logRequestPayload: true
        logRequestHeaders: true
        excludedRequestHeaders: "Authorization,X-API-Key,X-Payment-Token"
        logResponsePayload: true
        logResponseHeaders: true
        excludedResponseHeaders: "Set-Cookie,X-Internal-Token"
  operations:
    - method: GET
      path: /transactions
    - method: POST
      path: /charge
```

### Example 5: Selective Logging

Log only request payloads and response headers:

```yaml
apiVersion: gateway.api-platform.wso2.com/v1alpha1
kind: RestApi
metadata:
  name: selective-api-v1.0
spec:
  displayName: Selective API
  version: v1.0
  context: /selective/$version
  upstream:
    main:
      url: http://backend-service:8080
  policies:
    - name: log-message
      version: v0.1.0
      params:
        logRequestPayload: true
        logRequestHeaders: false
        logResponsePayload: false
        logResponseHeaders: true
  operations:
    - method: POST
      path: /analyze
```

### Example 6: Operation-Specific Logging

Apply different logging configurations to different operations:

```yaml
apiVersion: gateway.api-platform.wso2.com/v1alpha1
kind: RestApi
metadata:
  name: mixed-api-v1.0
spec:
  displayName: Mixed API
  version: v1.0
  context: /mixed/$version
  upstream:
    main:
      url: http://backend-service:8080
  operations:
    - method: GET
      path: /public-data
      policies:
        - name: log-message
          version: v0.1.0
          params:
            logRequestPayload: false
            logRequestHeaders: true
            excludedRequestHeaders: "Authorization"
            logResponsePayload: true
            logResponseHeaders: false
    - method: POST
      path: /sensitive-operation
      policies:
        - name: log-message
          version: v0.1.0
          params:
            logRequestPayload: true
            logRequestHeaders: false
            logResponsePayload: false
            logResponseHeaders: false
    - method: PUT
      path: /debug-endpoint
      policies:
        - name: log-message
          version: v0.1.0
          params:
            logRequestPayload: true
            logRequestHeaders: true
            excludedRequestHeaders: "Authorization,X-Debug-Token"
            logResponsePayload: true
            logResponseHeaders: true
            excludedResponseHeaders: "X-Internal-Key,Set-Cookie"
```

## How it Works

* The log-message policy ensures **security by default**, automatically masking `Authorization` headers with `"***"` to prevent accidental exposure of bearer tokens, basic auth credentials, and API keys, applying this rule case-insensitively.
* Administrators can configure **header exclusions** separately for requests and responses using `excludedRequestHeaders` and `excludedResponseHeaders`; multiple headers can be excluded with comma separation, and excluded headers are completely omitted from log output.
* The policy supports **request ID correlation** by extracting the `x-request-id` header, using the same ID in both request and response logs, or `<request-id-unavailable>` if absent, enabling end-to-end tracing.
* **Content processing** is non-intrusive: request and response bodies are buffered in memory, headers are filtered for security, and flows are automatically identified and tagged as REQUEST or RESPONSE.
* When content is missing or empty, the policy still creates log entries with placeholders—omitting payloads or headers fields as needed, and providing fallback values for missing request IDs.



## Limitations

1. **Memory Buffering**: Large payloads require significant memory for buffering during logging
2. **No Partial Logging**: Cannot log only specific parts of payloads (logs entire content)
3. **Binary Content**: Binary payloads may not log readably (will be logged as raw bytes)
4. **Real-time Constraints**: Logging overhead may not be suitable for ultra-low-latency requirements
5. **Log Format**: Output format is fixed JSON structure and cannot be customized


## Notes

**Sensitive Data Protection and Security**

Protect sensitive data by excluding authentication and confidential headers, masking authorization headers, and carefully evaluating the sensitivity of logged payload content. Regularly review the excluded headers list to ensure headers with credentials or personal data are not logged, and apply selective logging per operation. Beyond technical controls, control log access and handling by restricting log visibility to authorized personnel and ensuring secure transmission and storage of logs. Maintain compliance with data privacy regulations such as GDPR and CCPA by aligning your logging practices accordingly.

**Performance and Resource Management**

Payload buffering, JSON marshaling, and logging introduce additional memory and CPU usage per request. In high-traffic environments, high log volume and large payloads can significantly increase storage and I/O pressure. To mitigate performance impact, avoid large payload logging in high-traffic scenarios, manage log storage proactively, and enforce appropriate log retention policies. Enable detailed logging selectively to minimize performance degradation rather than logging everything by default.

**Operational Best Practices**

Improve traceability by including `x-request-id` headers in client requests to correlate logs across systems and monitor log volume and disk usage continuously. Be aware that logging is disabled by default; ensure the relevant request/response logging parameters are explicitly set to `true`. Verify that sensitive headers are excluded and disable payload logging for large uploads and downloads to avoid both security exposure and performance slowdown. All logging parameters are optional, must be boolean, and default to `false`. Ensure excluded header names are correctly spelled, case-insensitive, and properly comma-separated in your configuration.



## Related Policies

- **Request/Response Transformation**: Use alongside transformation policies for complete request/response visibility
- **Authentication Policies**: Combine with authentication policies while excluding auth headers from logging
- **Rate Limiting**: Log rate-limited requests for analysis and monitoring
- **Error Handling**: Capture request details when custom error responses are generated