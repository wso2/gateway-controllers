---
title: "Overview"
---
# JSON to XML

## Overview

The JSON to XML policy provides the capability to transform request and response payloads from JSON format to XML format.
This policy operates on both the request flow (transforming client JSON requests before forwarding to upstream services) and the response flow (transforming JSON responses from upstream services before returning to clients).

## Features

- Transforms JSON request bodies to XML format before forwarding to upstream services
- Transforms JSON response bodies to XML format before returning to clients
- Automatically handles all JSON data types (objects, arrays, strings, numbers, booleans, null)
- Intelligent XML element naming with array singularization
- Proper XML declaration and formatting
- Content-Type header management (updates to `application/xml`)
- Content-Length header updates for transformed payloads
- Robust error handling with appropriate HTTP status codes

## Configuration

The JSON-to-XML policy requires only per-API/route configuration

### User Parameters (API Definition)

These parameters are configured per-API/route by the API developer:

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `onRequestFlow` | boolean | No | `false` | Enables JSON to XML transformation for incoming request payloads (client to upstream). When set to `true`, JSON request bodies will be converted to XML format before forwarding to upstream services. When set to `false`, request bodies will be passed through unchanged. |
| `onResponseFlow` | boolean | No | `false` | Enables JSON to XML transformation for outgoing response payloads (upstream to client). When set to `true`, JSON response bodies will be converted to XML format before returning to clients. When set to `false`, response bodies will be passed through unchanged. |

**Note:**

Inside the `gateway/build.yaml`, ensure the policy module is added under `policies:`:

```yaml
- name: json-to-xml
  gomodule: github.com/wso2/gateway-controllers/policies/json-to-xml@v0
```

## Reference Scenarios:

### Example 1: Request-Only Transformation

Apply JSON to XML transformation only to incoming requests (client to upstream):

```yaml
apiVersion: gateway.api-platform.wso2.com/v1alpha1
kind: RestApi
metadata:
  name: integration-api-v1.0
spec:
  displayName: Integration-API
  version: v1.0
  context: /integration/$version
  upstream:
    main:
      url: http://xml-service:9000
  policies:
    - name: json-to-xml
      version: v0
      params:
        onRequestFlow: true
        onResponseFlow: false
  operations:
    - method: POST
      path: /legacy-endpoint
    - method: PUT
      path: /xml-data
```

**Request transformation(Simple Request Object):**

Original client request
```http
POST /users/v1.0/profile HTTP/1.1
Host: api-gateway.company.com
Content-Type: application/json

{
  "name": "John Doe",
  "age": 30,
  "email": "john@example.com"
}
```

Resulting upstream request
```
POST /profile HTTP/1.1
Host: legacy-backend:8080
Content-Type: application/xml
Content-Length: 135

<root>
  <name>John Doe</name>
  <age>30</age>
  <email>john@example.com</email>
</root>
```

**Request transformation(Complex JSON with Arrays):**

Original client request
```http
POST /users/v1.0/profile HTTP/1.1
Host: api-gateway.company.com
Content-Type: application/json

{
  "user": {
    "name": "Jane Smith",
    "skills": ["Java", "Python", "Go"],
    "address": {
      "city": "New York",
      "zipcode": "10001"
    }
  },
  "active": true
}
```

Resulting upstream request
```http
POST /profile HTTP/1.1
Host: legacy-backend:8080
Content-Type: application/xml
Content-Length: 298

<root>
  <user>
    <name>Jane Smith</name>
    <skills>Java</skills>
    <skills>Python</skills>
    <skills>Go</skills>
    <address>
      <city>New York</city>
      <zipcode>10001</zipcode>
    </address>
  </user>
  <active>true</active>
</root>
```

### Example 2: Response-Only Transformation

Apply JSON to XML transformation only to outgoing responses (upstream to client):

```yaml
apiVersion: gateway.api-platform.wso2.com/v1alpha1
kind: RestApi
metadata:
  name: json-backend-api-v1.0
spec:
  displayName: JSON-Backend-API
  version: v1.0
  context: /json-backend/$version
  upstream:
    main:
      url: http://json-service:8080
  policies:
    - name: json-to-xml
      version: v0
      params:
        onRequestFlow: false
        onResponseFlow: true
  operations:
    - method: GET
      path: /data
    - method: GET
      path: /reports
```
**Response Transformation:**

Original upstream response
```http
HTTP/1.1 200 OK
Content-Type: application/json
Content-Length: 78

{
  "status": "success",
  "data": {
    "id": 12345,
    "created": true
  }
}
```

Resulting client response
```http
HTTP/1.1 200 OK
Content-Type: application/xml
Content-Length: 156

<root>
  <status>success</status>
  <data>
    <id>12345</id>
    <created>true</created>
  </data>
</root>
```

### Example 3: Basic JSON to XML Transformation

Apply JSON to XML transformation to both requests and responses (requires explicit configuration):

```yaml
apiVersion: gateway.api-platform.wso2.com/v1alpha1
kind: RestApi
metadata:
  name: user-api-v1.0
spec:
  displayName: User-API
  version: v1.0
  context: /users/$version
  upstream:
    main:
      url: http://legacy-backend:8080
  policies:
    - name: json-to-xml
      version: v0
      params:
        onRequestFlow: true
        onResponseFlow: true
  operations:
    - method: GET
      path: /profile
    - method: POST
      path: /profile
    - method: PUT
      path: /settings
```

### Example 4: Operation-Specific Direction Control

Apply different transformation directions to different operations:

```yaml
apiVersion: gateway.api-platform.wso2.com/v1alpha1
kind: RestApi
metadata:
  name: mixed-api-v1.0
spec:
  displayName: Mixed-API
  version: v1.0
  context: /mixed/$version
  upstream:
    main:
      url: http://backend-service:8080
  operations:
    - method: POST
      path: /xml-required
      policies:
        - name: json-to-xml
          version: v0
          params:
            onRequestFlow: true
            onResponseFlow: false
    - method: GET
      path: /xml-response
      policies:
        - name: json-to-xml
          version: v0
          params:
            onRequestFlow: false
            onResponseFlow: true
    - method: PUT
      path: /full-transform
      policies:
        - name: json-to-xml
          version: v0
          params:
            onRequestFlow: true
            onResponseFlow: true
```

### Example 6: Default Behavior

When no parameters are specified, no transformations are performed by default:

```yaml
apiVersion: gateway.api-platform.wso2.com/v1alpha1
kind: RestApi
metadata:
  name: default-transform-api-v1.0
spec:
  displayName: Default-Transform-API
  version: v1.0
  context: /default-transform/$version
  upstream:
    main:
      url: http://backend-service:8080
  policies:
    - name: json-to-xml
      version: v0
      # No params specified - defaults to onRequestFlow: false, onResponseFlow: false
      # This policy will be effectively disabled unless explicitly configured
  operations:
    - method: GET
      path: /data
    - method: POST
      path: /submit
```

## How it Works

* The policy uses two booleans, `onRequestFlow` and `onResponseFlow`, to control whether JSON-to-XML conversion is applied on request flow, response flow, or both; when both are `false`, the policy is effectively disabled.
* Transformation is applied only when the corresponding payload has `Content-Type: application/json` (case-insensitive); non-JSON content types are passed through unchanged.
* JSON values are converted into XML using a fixed structure: output is wrapped in a `<root>` element, object keys become child elements, array items are emitted as repeated elements of the same key name, and primitive values are serialized as element text.
* After successful conversion, the policy updates `Content-Type` to `application/xml` and recalculates `Content-Length` to match the transformed payload size.
* In request flow, invalid JSON or conversion failures return `400 Bad Request`; in response flow, conversion errors are handled gracefully by passing the original response through unchanged to avoid breaking downstream behavior.
* Empty or missing request/response bodies are not transformed and continue without modification.


## Limitations

1. **JSON-Only Processing**: Transformation runs only for payloads marked as `application/json`; other content types are ignored.
2. **Non-Customizable XML Shape**: XML output format is fixed (for example, `<root>` wrapper and key-based element naming) and cannot be customized.
3. **Single-Pass Semantics**: Reapplying the policy on the same message has no practical value once payload format has already changed to XML.
4. **Memory Buffering Requirement**: Request and response bodies are buffered for parsing and transformation, which can increase memory use for large payloads.
5. **Ordering Sensitivity**: Policy order matters and it should execute before policies that require JSON payloads.


## Notes

**Security and Data Validation**

Validate incoming JSON payloads at the client and service boundaries, and ensure upstream XML consumers perform schema/content validation before processing transformed data. Because transformation changes message format but not business intent, treat converted payloads with the same security controls as original JSON, including input sanitization and payload size enforcement. When exposing transformation failures to clients, keep error responses informative but avoid leaking internal processing details.

**Performance and Resource Management**

JSON parsing and XML generation introduce CPU overhead, and buffering can increase memory pressure—especially with large nested payloads or high request rates. XML output is often larger than equivalent JSON, so account for increased bandwidth and downstream parsing costs. For high-traffic routes, apply transformation only where required and monitor latency, payload sizes, and conversion failure trends.

**Operational Best Practices**

Use direction control (`onRequestFlow`/`onResponseFlow`) deliberately per operation rather than enabling both flows globally by default. Keep API documentation explicit about which endpoints exchange XML versus JSON to avoid client/server contract confusion. During rollout, test representative payload shapes (nested objects, arrays, nulls, edge-case values), verify transformed headers, and include observability around transformation errors and bypass behavior.
