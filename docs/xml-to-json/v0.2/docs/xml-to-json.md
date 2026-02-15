---
title: "Overview"
---
# XML to JSON

## Overview

The XML to JSON policy enables transformation of request and response payloads from XML to JSON, operating on the request flow to convert client XML requests before forwarding them to upstream services and on the response flow to convert XML responses from upstream services before returning them to clients, with transformation behavior controlled through two boolean parameters that allow enabling the conversion for requests, responses, or both

## Features

- Transforms XML request bodies to JSON format before forwarding to upstream services
- Transforms XML response bodies to JSON format before returning to clients
- Automatically handles all XML structures (elements, attributes, arrays, text content)
- Preserves XML attributes with @ prefix notation in JSON
- Intelligent type conversion for element content (strings, numbers, booleans)
- Proper Content-Type header management (updates to `application/json`)
- Content-Length header updates for transformed payloads
- Robust error handling with 500 Internal Server Error status codes

## Configuration

The XML-to-JSON policy requires only per-API/route configuration

### User Parameters (API Definition)

These parameters are configured per-API/route by the API developer:

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `onRequestFlow` | boolean | No | `false` | Enables XML to JSON transformation for incoming request payloads (client to upstream). When set to `true`, XML request bodies will be converted to JSON format before forwarding to upstream services. When set to `false`, request bodies will be passed through unchanged. |
| `onResponseFlow` | boolean | No | `false` | Enables XML to JSON transformation for outgoing response payloads (upstream to client). When set to `true`, XML response bodies will be converted to JSON format before returning to clients. When set to `false`, response bodies will be passed through unchanged. |

**Note:**

Inside the `gateway/build.yaml`, ensure the policy module is added under `policies:`:

```yaml
- name: xml-to-json
  gomodule: github.com/wso2/gateway-controllers/policies/xml-to-json@v0
```

## Reference Scenarios:

### Example 1: Request-Only Transformation

Apply XML to JSON transformation only to incoming requests (client to upstream):

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
      url: http://json-service:9000
  policies:
    - name: xml-to-json
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

**Request transformation (Simple XML Object):**

Original client request
```http
POST /integration/v1.0/legacy-endpoint HTTP/1.1
Host: api-gateway.company.com
Content-Type: application/xml

<root>
  <name>John Doe</name>
  <age>30</age>
  <email>john@example.com</email>
</root>
```

Resulting upstream request
```http
POST /legacy-endpoint HTTP/1.1
Host: json-service:9000
Content-Type: application/json
Content-Length: 73

{
  "root": {
    "name": "John Doe",
    "age": 30,
    "email": "john@example.com"
  }
}
```

**Request transformation (Attributes and Repeated Elements):**

Original client request
```http
POST /integration/v1.0/xml-data HTTP/1.1
Host: api-gateway.company.com
Content-Type: text/xml

<user id="42" active="true">
  <name>Jane Smith</name>
  <skills>Java</skills>
  <skills>Python</skills>
  <skills>Go</skills>
</user>
```

Resulting upstream request
```http
POST /xml-data HTTP/1.1
Host: json-service:9000
Content-Type: application/json
Content-Length: 134

{
  "user": {
    "@id": "42",
    "@active": true,
    "name": "Jane Smith",
    "skills": [
      "Java",
      "Python",
      "Go"
    ]
  }
}
```

### Example 2: Response-Only Transformation

Apply XML to JSON transformation only to outgoing responses (upstream to client):

```yaml
apiVersion: gateway.api-platform.wso2.com/v1alpha1
kind: RestApi
metadata:
  name: legacy-api-v1.0
spec:
  displayName: Legacy-API
  version: v1.0
  context: /legacy/$version
  upstream:
    main:
      url: http://legacy-xml-service:8080
  policies:
    - name: xml-to-json
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

**Response transformation:**

Original upstream response
```http
HTTP/1.1 200 OK
Content-Type: application/xml
Content-Length: 126

<response>
  <status>success</status>
  <data>
    <id>12345</id>
    <created>true</created>
  </data>
</response>
```

Resulting client response
```http
HTTP/1.1 200 OK
Content-Type: application/json
Content-Length: 89

{
  "response": {
    "status": "success",
    "data": {
      "id": 12345,
      "created": true
    }
  }
}
```

### Example 3: Basic XML to JSON Transformation

Apply XML to JSON transformation to both requests and responses (requires explicit configuration):

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
      url: http://json-backend:8080
  policies:
    - name: xml-to-json
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

**End-to-end transformation sample:**

Incoming client request body
```xml
<profile>
  <name>Alex</name>
  <age>28</age>
</profile>
```

Forwarded upstream request body
```json
{
  "profile": {
    "name": "Alex",
    "age": 28
  }
}
```

Upstream response body
```xml
<result>
  <updated>true</updated>
  <id>9001</id>
</result>
```

Returned client response body
```json
{
  "result": {
    "updated": true,
    "id": 9001
  }
}
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
      path: /json-required
      policies:
        - name: xml-to-json
          version: v0
          params:
            onRequestFlow: true
            onResponseFlow: false
    - method: GET
      path: /json-response
      policies:
        - name: xml-to-json
          version: v0
          params:
            onRequestFlow: false
            onResponseFlow: true
    - method: PUT
      path: /full-transform
      policies:
        - name: xml-to-json
          version: v0
          params:
            onRequestFlow: true
            onResponseFlow: true
```

**Route-level transformation sample:**

For `/json-required` (request only)
```xml
<job><name>daily-sync</name><enabled>true</enabled></job>
```
becomes
```json
{
  "job": {
    "name": "daily-sync",
    "enabled": true
  }
}
```

For `/json-response` (response only)
```xml
<health><status>ok</status><uptime>1024</uptime></health>
```
becomes
```json
{
  "health": {
    "status": "ok",
    "uptime": 1024
  }
}
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
    - name: xml-to-json
      version: v0
      # No params specified - defaults to onRequestFlow: false, onResponseFlow: false
      # This policy will be effectively disabled unless explicitly configured
  operations:
    - method: GET
      path: /data
    - method: POST
      path: /submit
```

**Behavior sample (no transformation):**

Input XML payload
```xml
<event><type>ping</type></event>
```

Output payload (unchanged)
```xml
<event><type>ping</type></event>
```

## How it Works

* The policy uses two booleans, `onRequestFlow` and `onResponseFlow`, to control whether XML-to-JSON conversion is applied on request flow, response flow, or both; when both are `false`, the policy is effectively disabled.
* Transformation is applied only when the corresponding payload has `Content-Type: application/xml` or `text/xml` (case-insensitive); unsupported content types cause an immediate error response.
* XML is converted into JSON by preserving hierarchy, mapping attributes with `@` prefixes, converting repeated elements into arrays, and applying value parsing for booleans and numbers where applicable.
* After successful conversion, the policy updates `Content-Type` to `application/json` and recalculates `Content-Length` to match the transformed payload size.
* In both request and response flow, invalid content-type for transformation, malformed XML, or conversion failures return `500 Internal Server Error` with a JSON error body.
* Empty or missing request/response bodies are not transformed and continue without modification.


## Limitations

1. **XML-Only Processing**: Transformation runs only for payloads marked as `application/xml` or `text/xml`; other content types produce errors when transformation is enabled.
2. **Non-Customizable JSON Shape**: Output conventions (for example, attribute prefix `@`) are fixed and cannot be customized per API.
3. **Single-Pass Semantics**: Reapplying the policy on the same message has no practical value once payload format has already changed to JSON.
4. **Memory Buffering Requirement**: Request and response bodies are buffered for parsing and transformation, which can increase memory use for large payloads.
5. **Ordering Sensitivity**: Policy order matters and it should execute before policies that require XML payloads.


## Notes

**Security and Data Validation**

Validate XML inputs before transformation and ensure downstream services validate resulting JSON content according to expected schemas. Since the policy can return detailed conversion errors, keep client-facing error handling controlled to avoid exposing unnecessary internals. Apply payload size limits and XML parsing protections in your deployment to reduce risk from malformed or oversized XML inputs.

**Performance and Resource Management**

XML parsing and JSON generation add CPU overhead, and buffering increases memory pressure for large or deeply nested payloads. For high-throughput routes, enable transformation only where strictly needed and monitor transformation latency and payload sizes. Although JSON payloads are often smaller than XML, conversion still adds processing cost that should be included in capacity planning.

**Operational Best Practices**

Use direction control (`onRequestFlow`/`onResponseFlow`) deliberately per operation rather than enabling both flows globally by default. Keep API contracts explicit about where XML is accepted and where JSON is returned to avoid client integration issues. During rollout, test realistic XML structures (attributes, repeated elements, empty nodes, mixed content), verify transformed headers, and monitor transformation failures with clear operational alerts.
