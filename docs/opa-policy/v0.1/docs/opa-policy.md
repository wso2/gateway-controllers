---
title: "Overview"
---
# Validate Request with OPA

## Overview

The Validate Request with OPA policy delegates the allow/deny decision for an API request to an [Open Policy Agent](https://www.openpolicyagent.org/) (OPA) policy engine. OPA is an open-source, general-purpose policy engine that lets you keep authorization logic, written in the Rego language, outside the gateway and manage it independently of your APIs.

When the gateway receives a request, the policy extracts a predefined set of request metadata (HTTP method, path, headers, client IP, the matched operation and authentication details), sends it to OPA over HTTP or HTTPS as the `input` document, and evaluates the boolean rule you configured. A decision of `true` lets the request continue to the upstream service; anything else blocks it. The policy fails closed: if OPA cannot be reached or does not return a usable decision, the request is rejected.

> **Before you apply the policy:** make sure the OPA server is running, reachable from the gateway runtime, and has the Rego policy you reference loaded. If you use HTTPS, the OPA server certificate must be trusted by the gateway runtime.

## Features

- **Externalized authorization**: Delegate allow/deny decisions to any Rego policy hosted in OPA, so authorization rules change without redeploying APIs
- **Rich request input**: HTTP method, request path, headers, client IP, matched operation template and API/authentication context sent as the OPA `input`
- **Authentication-aware decisions**: Identity, scopes, issuer, audience and credential details set by a preceding authentication policy are included, enabling role- and scope-based rules
- **Rule-level control**: Evaluate a specific rule of a policy package (`{serverUrl}/{policy}/{rule}`)
- **Secured OPA access**: Optional access key sent as a `Bearer` token to OPA; HTTP and HTTPS OPA endpoints supported
- **Opt-in access token forwarding**: Pass the caller's bearer token to OPA as `apiContext.accessToken` only when you enable it
- **Custom context**: Add values that earlier policies stored in the request context to the OPA input
- **Connection controls**: Configurable connection limit and request timeout for the gateway-to-OPA connection
- **Fail-closed behavior**: `403 Forbidden` when OPA denies the request; `500 Internal Server Error` when OPA is unreachable, slow, or returns an invalid or undefined result


## How It Works

1. The client sends a request to an API or operation that has the policy attached.
2. The policy builds the OPA input document from the request (see [OPA Input](#opa-input)).
3. The policy sends `POST {serverUrl}/{policy}/{rule}` to OPA with the body `{"input": { ... }}`.
4. OPA evaluates the rule and responds with `{"result": true}` or `{"result": false}`.
5. The policy acts on the decision:
   - `true`: the request continues along the policy chain to the upstream service.
   - `false`: the gateway returns `403 Forbidden` and the request does not reach the upstream.
   - No usable decision (see [Response Handling](#response-handling)): the gateway returns `500 Internal Server Error`.

The call to OPA is synchronous and happens on every request that reaches the policy; decisions are not cached by the gateway. Keep the OPA server close to the gateway and its policies fast to evaluate, since OPA latency is added to every request.

## Configuration

The OPA policy uses a single-level configuration: all parameters are set per API or per operation in the API definition. It has no system parameters.

### User Parameters (API Definition)

| Parameter | Type | Required | Default | Constraints | Description |
|-----------|------|----------|---------|-------------|-------------|
| `serverUrl` | string | Yes | - | Must start with `http://` or `https://` | Base URL of OPA's data API, for example `https://opa-server-host:8181/v1/data`. A trailing `/` is ignored. For HTTPS endpoints, the OPA certificate must be trusted by the gateway runtime. |
| `policy` | string | Yes | - | Non-empty | Policy (Rego package path) to evaluate, appended to `serverUrl`. Use `/` to separate package segments, for example `authz/policy` for `package authz.policy`. |
| `rule` | string | Yes | `allow` | Non-empty | Name of the rule that yields the boolean decision. The gateway queries `{serverUrl}/{policy}/{rule}`. |
| `accessKey` | string | No | - | - | Access key for the OPA server. Required only when token authentication is enabled on OPA. Sent as `Authorization: Bearer <accessKey>` on the request to OPA. |
| `sendAccessToken` | boolean | No | `false` | - | If `true`, the bearer token from the caller's `Authorization` header is included in the OPA input as `apiContext.accessToken`. |
| `additionalProperties` | array of string | No | `[]` | Each item matches `^[a-zA-Z0-9_][a-zA-Z0-9_\-.:]*$` | Keys of values in the request context (shared metadata set by earlier policies) to add to the OPA input. Each key becomes a top-level key of `input`. Keys with no value at runtime are skipped. |
| `maxOpenConnections` | integer | No | `500` | 1 to 999 | Maximum number of open HTTP connections between the gateway and the OPA server. When the limit is reached, requests wait for a free connection (and are subject to `connectionTimeout`). |
| `connectionTimeout` | integer | No | `30` | 1 to 999 | Timeout, in seconds, for a request to OPA, covering connecting, sending the input and receiving the decision. When exceeded, the request is rejected with `500`. |

Parameters are validated when the API is deployed: a missing `serverUrl`, `policy` or `rule`, a `serverUrl` that is not an HTTP(S) URL, or a value outside the ranges above causes the deployment to be rejected.

**Note:**

Inside the `gateway/build.yaml`, ensure the policy module is added under `policies:`:

```yaml
- name: opa-policy
  gomodule: github.com/wso2/gateway-controllers/policies/opa-policy@v0
```

### How the OPA URL is built

The URL queried is `serverUrl` + `/` + `policy` + `/` + `rule`, with duplicate slashes at the joins removed.

| `serverUrl` | `policy` | `rule` | URL queried |
|-------------|----------|--------|-------------|
| `https://opa:8181/v1/data` | `authz/policy` | `allow` | `https://opa:8181/v1/data/authz/policy/allow` |
| `https://opa:8181/v1/data/` | `orders/authz` | `permit` | `https://opa:8181/v1/data/orders/authz/permit` |

## OPA Request

The gateway sends the following HTTP request to OPA:

| Element | Value |
|---------|-------|
| Method | `POST` |
| URL | `{serverUrl}/{policy}/{rule}` |
| `Content-Type` | `application/json` |
| `Accept` | `application/json` |
| `Authorization` | `Bearer <accessKey>`, only when `accessKey` is configured |
| Body | `{"input": { ... }}`: the [OPA input](#opa-input) |

### OPA Input

Rego policies read these values from `input`. Example document:

```json
{
  "input": {
    "requestOrigin": "10.1.2.3",
    "requestMethod": "GET",
    "requestPath": "/petstore/v1.0/pets/42",
    "transportHeaders": {
      "authorization": "Bearer eyJhbGciOi...",
      "x-forwarded-for": "10.1.2.3, 10.9.9.9",
      "user-agent": "curl/8.5.0"
    },
    "electedResource": "/pets/{id}",
    "apiContext": {
      "apiId": "7f2b0c7e-1f4a-4d1a-9c53-2d6b1f1b0a11",
      "apiName": "PetStore",
      "apiVersion": "v1.0",
      "context": "/petstore/v1.0",
      "isAuthenticated": true,
      "isAuthorized": false,
      "authType": "jwt",
      "username": "alice",
      "issuer": "https://idp.example.com",
      "consumerKey": "client-1",
      "audience": ["petstore"],
      "scopes": ["pets:read", "pets:write"]
    }
  }
}
```

| Input key | Type | Description |
|-----------|------|-------------|
| `requestOrigin` | string | Client IP address. The first address of the `X-Forwarded-For` header; if that header is absent, the value of `X-Envoy-External-Address`; empty if neither is present. |
| `requestMethod` | string | HTTP method of the request, for example `GET`. |
| `requestPath` | string | Path of the request as received by the gateway, including the API context and version. |
| `transportHeaders` | object | All request headers as received by the gateway. Header names are lower-cased; multiple values of a header are joined with a comma; HTTP/2 pseudo-headers (those starting with `:`) are excluded. See [Sensitive data sent to OPA](#sensitive-data-sent-to-opa). |
| `electedResource` | string | Path template of the matched API operation, for example `/pets/{id}`. Use it to write rules per operation without parsing `requestPath`. |
| `apiContext` | object | Details of the API and the caller. See the table below. |
| *additional keys* | any | One top-level key per entry of `additionalProperties` that has a value in the request context. |

#### `apiContext` fields

| Field | Type | Present | Description |
|-------|------|---------|-------------|
| `apiId` | string | Always | Unique identifier of the API. |
| `apiName` | string | Always | Name of the API. |
| `apiVersion` | string | Always | Version of the API. |
| `context` | string | Always | Base context path of the API. |
| `isAuthenticated` | boolean | Always | `true` when a preceding authentication policy authenticated the request; `false` when no authentication policy has run or authentication did not succeed. |
| `isAuthorized` | boolean | With an authentication context | Whether a preceding authorization policy approved the request. |
| `authType` | string | With an authentication context | Authentication mechanism, for example `jwt`, `basic` or `apikey`. |
| `username` | string | With an authentication context | Authenticated principal (JWT `sub` claim, Basic Auth username, or API key owner). |
| `issuer` | string | With an authentication context | Token issuer (JWT `iss` claim). Empty string for Basic Auth and API key authentication. |
| `consumerKey` | string | With an authentication context | Identifier of the credential used, such as the OAuth2 client ID. |
| `audience` | array of string | When not empty | Token audiences. |
| `scopes` | array of string | When not empty | Granted scopes, sorted alphabetically. |
| `properties` | object | When not empty | Additional claims or data stored by the authentication policy as string values. |
| `accessToken` | string | Conditionally | The caller's bearer token. Present only when `sendAccessToken` is `true` and the request has an `Authorization: Bearer` header. |

"With an authentication context" fields are sent whenever a preceding authentication policy has set one, as empty strings if the policy does not provide a value. "When not empty" fields are omitted otherwise, never sent as `null`. When no authentication policy has run, `apiContext` contains only the four identification fields and `isAuthenticated: false`.

> **Order matters.** The authentication fields reflect what policies earlier in the chain have set. Place an authentication policy such as [JWT Authentication](../../../jwt-auth/v1.3/docs/jwt-authentication.md) before the OPA policy if your Rego rules depend on the caller's identity or scopes.

### Sensitive data sent to OPA

- `transportHeaders` contains **every** request header, including `Authorization` and cookies. Treat the OPA server and the network path to it as trusted, and use HTTPS when OPA is not on the same host or private network as the gateway. The `sendAccessToken` setting controls only whether the token is *additionally* sent as `apiContext.accessToken`; it does not remove it from `transportHeaders`.
- `accessKey` is part of the API definition. Restrict who can read API definitions and rotate the key if it is exposed.
- If OPA decision logging is enabled, the input, including these headers, may be written to OPA's logs. Configure OPA's [mask decision](https://www.openpolicyagent.org/docs/latest/management-decision-logs/#masking-sensitive-data) policy to drop sensitive fields.

## Response Handling

The policy reads the `result` field of the OPA response and acts as follows:

| OPA response | Meaning | Gateway response |
|--------------|---------|------------------|
| `200` with `{"result": true}` | Allowed | Request continues to the upstream |
| `200` with `{"result": false}` | Denied | `403 Forbidden` |
| `200` with `{}` | Rule or document is undefined (for example, the policy or rule is not loaded, or no rule body matched and there is no `default`) | `500 Internal Server Error` |
| `200` with a non-boolean `result` (for example, an object or a string) | Rule does not yield a boolean | `500 Internal Server Error` |
| `200` with a body that is not valid JSON | Invalid response | `500 Internal Server Error` |
| Any non-`200` status (for example `400`, `401`, `404`, `500`) | OPA rejected or failed the query | `500 Internal Server Error` |
| No response before `connectionTimeout`, connection refused, DNS or TLS failure | OPA unreachable | `500 Internal Server Error` |
| Response larger than 1 MiB | Response not accepted | `500 Internal Server Error` |

Only the boolean `true` allows a request. The rule must evaluate to a boolean, so define a `default allow := false` in your Rego policy: without it, a request that matches no rule body gets an undefined result and a `500`, not a `403`.

### Error responses

Both responses have the content type `application/json`.

`403 Forbidden`, returned when OPA denies the request:

```json
{
  "error": "Forbidden",
  "message": "The request was rejected by the OPA policy validation"
}
```

`500 Internal Server Error`, returned when no valid decision could be obtained:

```json
{
  "error": "Internal Server Error",
  "message": "Unable to validate the request with the OPA policy engine"
}
```

The response does not reveal why the decision failed. The cause is written to the gateway runtime log (see [Troubleshooting](#troubleshooting)).

## Writing the Rego Policy

The Rego policy is deployed to OPA, not to the gateway. The package path maps to the `policy` parameter and the rule name to `rule`. A policy with `package authz.policy` and a rule named `allow` is configured with `policy: authz/policy` and `rule: allow`.

Always declare a default so that an unmatched request is denied with `403` rather than failing with `500`:

```rego
package authz.policy

import rego.v1

default allow := false
```

The examples below build on this header.

**Allow only authenticated callers with a scope for the HTTP method:**

```rego
allow if {
    input.apiContext.isAuthenticated
    input.requestMethod == "GET"
    "pets:read" in input.apiContext.scopes
}

allow if {
    input.apiContext.isAuthenticated
    input.requestMethod in {"POST", "PUT", "DELETE"}
    "pets:write" in input.apiContext.scopes
}
```

**Restrict an operation by its template instead of parsing the path:**

```rego
allow if {
    input.electedResource == "/pets/{id}"
    input.requestMethod == "DELETE"
    "admin" in input.apiContext.scopes
}
```

**Allow by client IP range and a request header:**

```rego
allow if {
    net.cidr_contains("10.0.0.0/8", input.requestOrigin)
    input.transportHeaders["x-tenant-id"] == "acme"
}
```

**Use a value added through `additionalProperties`** (here `tenantId`, set by an earlier policy):

```rego
allow if {
    input.tenantId == "acme"
}
```

### Test the policy against OPA first

Before attaching the policy to an API, verify the Rego policy directly against OPA with a sample input:

```bash
curl -s -X POST http://opa-server-host:8181/v1/data/authz/policy/allow \
  -H "Content-Type: application/json" \
  -d '{"input":{"requestMethod":"GET","apiContext":{"isAuthenticated":true,"scopes":["pets:read"]}}}'
# {"result":true}
```

If the response is `{}`, the policy or rule is not loaded or the path does not match: check `policy`/`rule` against the Rego package and rule name.

## Reference Scenarios

### Example 1: Basic Request Validation

Validate every call to an operation against an OPA rule:

```yaml
apiVersion: gateway.api-platform.wso2.com/v1
kind: RestApi
metadata:
  name: petstore-v1.0
spec:
  displayName: PetStore
  version: v1.0
  context: /petstore/$version
  upstream:
    main:
      url: http://backend-service:8080
  operations:
    - method: GET
      path: /pets/{id}
      policies:
        - name: opa-policy
          version: v1
          params:
            serverUrl: https://opa-server-host:8181/v1/data
            policy: authz/policy
            rule: allow
    - method: GET
      path: /health
```

Only `GET /pets/{id}` is validated by OPA; `GET /health` is not.

### Example 2: Scope-Based Authorization After JWT Authentication

Authenticate first, then let OPA decide using the scopes in the token:

```yaml
apiVersion: gateway.api-platform.wso2.com/v1
kind: RestApi
metadata:
  name: orders-api-v1.0
spec:
  displayName: Orders API
  version: v1.0
  context: /orders/$version
  upstream:
    main:
      url: http://backend-service:8080
  operations:
    - method: GET
      path: /orders
      policies:
        - name: jwt-auth
          version: v1
          params:
            issuers:
              - PrimaryIDP
        - name: opa-policy
          version: v1
          params:
            serverUrl: https://opa-server-host:8181/v1/data
            policy: orders/authz
            rule: allow
```

With a Rego policy such as:

```rego
package orders.authz

import rego.v1

default allow := false

allow if {
    input.apiContext.isAuthenticated
    "orders:read" in input.apiContext.scopes
}
```

A missing or invalid token is rejected by `jwt-auth`. A valid token without the `orders:read` scope reaches OPA and receives `403`.

### Example 3: OPA Secured with an Access Key

When OPA runs with token authentication enabled, provide the access key. The gateway sends it as `Authorization: Bearer my-opa-token`:

```yaml
  policies:
    - name: opa-policy
      version: v1
      params:
        serverUrl: https://opa-server-host:8181/v1/data
        policy: authz/policy
        rule: allow
        accessKey: my-opa-token
```

If the key is missing or wrong, OPA answers `401`, and the gateway responds to the client with `500`.

### Example 4: Forwarding the Access Token and Extra Context

Send the caller's bearer token and a value set by an earlier policy to OPA, for rules that inspect the token or use that value:

```yaml
  policies:
    - name: opa-policy
      version: v1
      params:
        serverUrl: https://opa-server-host:8181/v1/data
        policy: authz/policy
        rule: allow
        sendAccessToken: true
        additionalProperties:
          - tenantId
```

The OPA input then contains `input.apiContext.accessToken` (when the request has a bearer token) and `input.tenantId` (when an earlier policy stored a `tenantId` value in the request context).

### Example 5: Tuning the Connection to OPA

For a busy API, bound the connections to OPA and fail fast when OPA is slow:

```yaml
  policies:
    - name: opa-policy
      version: v1
      params:
        serverUrl: http://opa.internal:8181/v1/data
        policy: authz/policy
        rule: allow
        maxOpenConnections: 200
        connectionTimeout: 2
```

A request that waits longer than 2 seconds for OPA, whether queuing for a connection or waiting for the decision, is rejected with `500`.

### Example 6: Applying the Policy to the Whole API

Attach the policy at the API level so it applies to every operation:

```yaml
apiVersion: gateway.api-platform.wso2.com/v1
kind: RestApi
metadata:
  name: inventory-api-v1.0
spec:
  displayName: Inventory API
  version: v1.0
  context: /inventory/$version
  upstream:
    main:
      url: http://backend-service:8080
  policies:
    - name: opa-policy
      version: v1
      params:
        serverUrl: https://opa-server-host:8181/v1/data
        policy: inventory/authz
        rule: allow
  operations:
    - method: GET
      path: /items
    - method: POST
      path: /items
    - method: DELETE
      path: /items/{id}
```

Use `input.electedResource` and `input.requestMethod` in the Rego policy to apply different rules per operation.



## Troubleshooting

When a request is rejected with `500`, the gateway runtime logs the cause at `ERROR` level with the policy name, rule and reason.

| Symptom | Likely cause | What to check |
|---------|--------------|---------------|
| `500`; log says `calling OPA server` with `connection refused` or `no such host` | OPA is down, or `serverUrl` is wrong or unreachable from the gateway runtime | Verify the URL and network access from the gateway runtime container or pod |
| `500`; log mentions `Client.Timeout exceeded` or `context deadline exceeded` | OPA is slow or overloaded, or `connectionTimeout` is too low | Increase `connectionTimeout`; check OPA load and policy evaluation time |
| `500`; log says `x509` or `certificate` | The gateway runtime does not trust the OPA HTTPS certificate | Add the issuing CA to the runtime's trust store |
| `500`; log says `OPA server returned status 401` or `403` | `accessKey` missing or wrong while OPA token authentication is on | Set `accessKey` to a valid token |
| `500`; log says `OPA server returned status 404` or `400` | Wrong `serverUrl` base path, or malformed query | Confirm the URL ends with `/v1/data` and that OPA's data API is enabled |
| `500`; log says `empty result received` | OPA returned `{}`: the policy or rule is not loaded or has no result | Check `policy` and `rule` against the Rego package and rule name; add `default allow := false`; query OPA directly with `curl` |
| `500`; log says `the field "result" is not a boolean` | The rule returns an object, string or set | Make `rule` point to a boolean rule |
| `403` for requests you expect to pass | The rule evaluates to `false` | Reproduce with the OPA input shown in [OPA Input](#opa-input); enable OPA decision logs to see the exact input received |
| Rule sees `isAuthenticated: false` or no `scopes` | The authentication policy runs after the OPA policy, or does not set scopes | Place the authentication policy before `opa-policy` |
| Deployment rejected | A required parameter is missing or a value is out of range | Check `serverUrl`, `policy` and `rule` are set and the numeric limits are within 1 to 999 |

## Limitations

- The policy applies to the request flow only; it cannot inspect or filter responses.
- The request body is not sent to OPA.
- Each request makes one synchronous call to OPA; decisions are not cached and failed calls are not retried.
- The OPA response must be at most 1 MiB.
- The decision must come from a boolean rule; the query is always for a single rule, not a whole policy document.

## Related Policies

- [JWT Authentication Policy](../../../jwt-auth/v1.3/docs/jwt-authentication.md) - Validates JWTs and provides the identity, issuer, audience and scopes used in OPA rules
- [Basic Authentication Policy](../../../basic-auth/v1.0/docs/basic-auth.md) - Authenticates callers with a username and password before authorization
