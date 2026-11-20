---
title: "Overview"
---
# Dynamic Endpoint

## Overview

The Dynamic Endpoint policy routes requests to an upstream chosen at request time. It can route to:

- a fixed target named by `targetUpstream`: one of the API's own upstream definitions, as in v1.0, or, when the API has no upstream definition of that name, the gateway-wide Backend of that name, or
- the gateway-wide Backend that a CEL expression names from each request (`backendExpression`).

A Backend (`kind: Backend`) is a backend defined once for the whole gateway through the management API (`/backends`). The gateway turns each Backend into its own cluster, so adding or changing a Backend never requires an API to be edited or redeployed. An API that uses `backendExpression` reaches a Backend created after the API was deployed as soon as the Backend exists, and stops reaching one that is removed. A Backend that a deployed API names in `targetUpstream` can only be removed after that API is changed to stop naming it: until then the gateway refuses the delete with `409`. This doesn't apply when the API has its own upstream definition of that name, because the API then never uses the Backend.

APIs keep `version: v1`; v1.1 only adds parameters. A v1.0 configuration whose `targetUpstream` names one of the API's upstream definitions behaves exactly as before. One case changes: on an API with no upstream definitions or sandbox upstream, a `targetUpstream` that names nothing the API defines now fails with `503` instead of being ignored. See the upgrade note under [Notes](#notes).

## Features

- Routes to a named upstream definition or Backend, or to a Backend chosen per request
- Reads the Backend name from any part of the request context with a CEL expression: a header, the path or query string, shared metadata written by an earlier policy, the API and route, or a claim of the authenticated caller
- Limits which Backends an API can reach with a label selector
- Answers every value it cannot route with the same `400`, so callers cannot probe which Backends exist
- Falls back to a fixed target, or rejects, when a request carries no value
- Fails closed with `503` when `targetUpstream` names neither an upstream definition of the API nor an existing Backend

## Configuration

The Dynamic Endpoint policy uses a single-level configuration model where parameters are configured per API or route in the API definition YAML.

### User Parameters (API Definition)

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `targetUpstream` | string | This, `backendExpression`, or both | - | The fixed target. An entry of the API's `upstreamDefinitions` with this name takes precedence; otherwise it names a gateway-wide Backend, and requests get `503` while that Backend does not exist. With `backendExpression`, used when the expression yields no value. |
| `backendExpression` | string | This, `targetUpstream`, or both | - | A CEL expression, at most 1024 characters, evaluated for each request. It must return a string that names the Backend to route the request to. Requires `backendSelector`. |
| `backendSelector` | object | With `backendExpression` | - | `matchLabels` limiting which Backends `backendExpression` can select. `{}` allows every Backend on the gateway. |
| `onMissingValue` | string | No | `fallback` | What to do when `backendExpression` yields no value: `fallback` routes to `targetUpstream`, else the API's own upstream; `reject` returns `400`. Only valid with `backendExpression`. |

### Expression variables

`backendExpression` uses the same variable names as the `cel` key extraction of the `advanced-ratelimit` policy, plus the authentication context:

| Variable | Type | Value |
|----------|------|-------|
| `request.Headers` | map of string to list of strings | Request headers as they reach this policy, by lower-case name. A header set by an earlier policy in the chain is visible. |
| `request.Path` | string | The request path, including the query string. |
| `request.Method` | string | The HTTP method. |
| `request.Metadata` | map of string to any | Shared metadata written by earlier policies. |
| `api.Name`, `api.Version`, `api.Context`, `api.Id` | string | The API the request matched. |
| `route.Name` | string | The route the policy is attached to. |
| `auth.Subject` | string | The authenticated principal, empty when no authentication policy ran before this one. |
| `auth.Properties` | map of string to string | Claims and properties set by the authentication policy, such as custom JWT claims. |

The CEL standard library and the string extensions (`split`, `lowerAscii`, `upperAscii`, `substring`, `replace`, `trim`, `indexOf` and others) are available. Examples:

| Expression | Routes by |
|------------|-----------|
| `request.Headers["x-tenant"][0]` | the first `x-tenant` header |
| `auth.Properties["tenant_id"]` | a JWT claim, after `jwt-auth` |
| `request.Metadata["tenant"]` | a value an earlier policy stored |
| `"orders-" + request.Headers["x-region"][0].lowerAscii()` | a header, mapped to a naming convention |
| `("&" + request.Path.substring(request.Path.indexOf("?") + 1)).split("&tenant=")[1].split("&")[0]` | the `tenant` query parameter, matched by its whole name (`previous_tenant` doesn't match) anywhere in the query string, even after another `?` |

### How a value is handled

- **No value.** An expression that reads something the request does not have (an absent header, metadata key or claim, or an index past the end of a list, such as an absent query parameter), and an expression that returns an empty string, yield no value. `onMissingValue` decides what happens.
- **A value that cannot be routed.** A result that is not a string, is not a valid Backend name, names no Backend, or names a Backend outside `backendSelector` is rejected with `400` and the message `The requested backend is not available for this API.` So is any other evaluation error, such as converting a header that is present but not a number. The request never reaches an upstream.
- **Reading inside a value of the wrong type.** CEL reports a field or key read on a value that isn't a map the same way as an absent key, so an expression such as `request.Metadata["tenant"].id`, where an earlier policy stored `tenant` as a string, also yields no value. Check the type in the expression, for example `type(request.Metadata["tenant"]) == map ? request.Metadata["tenant"].id : ""`, if that case needs to be told apart.
- **A Backend removed while requests are in flight** fails closed with `503` (engine fault `905008`), never falling back to another upstream.

### How targetUpstream is resolved

`targetUpstream` keeps its v1.0 meaning whenever the API has an upstream definition of that name. Only a name the API does not define refers to a gateway-wide Backend. Creating a Backend therefore never changes where an API that names one of its own upstream definitions sends requests, and the gateway allows that Backend to be deleted. A name that is neither fails closed with `503` (engine fault `905008`).

The expression is compiled when the policy is created. An expression that does not compile, or that cannot return a string, makes the policy fail to load: the gateway logs the CEL error and requests on that route fail with `500` until the expression is fixed. Test expressions on a non-production gateway first.

The policy removes no headers. To keep a routing header from reaching the backend, add the `remove-headers` policy after `dynamic-endpoint`, as in Example 3.

**Note:**

Inside the `gateway/build.yaml`, ensure the policy module is added under `policies:`:

```yaml
- name: dynamic-endpoint
  gomodule: github.com/wso2/gateway-controllers/policies/dynamic-endpoint@v1
```

## Reference Scenarios

### Example 1: Route an Operation to a Named Upstream Definition

Unchanged from v1.0: route requests for one operation to the `orders-v2` upstream definition.

```yaml
apiVersion: gateway.api-platform.wso2.com/v1
kind: RestApi
metadata:
  name: orders-api-v1.0
spec:
  displayName: Orders API
  version: v1.0
  context: /orders/$version
  upstreamDefinitions:
    - name: orders-v2
      basePath: /api/v2
      upstreams:
        - url: http://sample-backend:5000
  upstream:
    main:
      url: http://sample-backend-1:5000/api/v2
  operations:
    - method: GET
      path: /orders/*
      policies:
        - name: dynamic-endpoint
          version: v1
          params:
            targetUpstream: orders-v2
```

### Example 2: Route an API to a Fixed Backend

Create the Backend once on the gateway:

```yaml
apiVersion: gateway.choreolabs.com/v1
kind: Backend
metadata:
  name: orders-shared
  labels:
    team: orders
spec:
  basePath: /v1
  endpoints:
    - url: http://orders-1.internal:9080
      weight: 80
    - url: http://orders-2.internal:9080
      weight: 20
```

```bash
curl -X POST http://localhost:9090/api/management/v1/backends \
  -u "admin:<password>" \
  -H "Content-Type: application/yaml" \
  --data-binary "@orders-shared.yaml"
```

Then name it from an API that has no upstream definition called `orders-shared`:

```yaml
policies:
  - name: dynamic-endpoint
    version: v1
    params:
      targetUpstream: orders-shared
```

The gateway refuses to delete `orders-shared` with `409` while a deployed API names it in `targetUpstream` and has no upstream definition of that name. To remove it, first change or remove that `targetUpstream` and deploy the API, then delete the Backend.

### Example 3: Route Each Request to a Tenant's Backend by Header

One Backend per tenant, each labelled `team: orders`:

```yaml
apiVersion: gateway.choreolabs.com/v1
kind: Backend
metadata:
  name: tenant-b
  labels:
    team: orders
spec:
  basePath: /v1
  endpoints:
    - url: http://orders-tenant-b:9080
    - url: http://orders-tenant-1-b:9080
```

Create a `tenant-default` Backend in the same way for requests that carry no `x-tenant` header.

The API routes each request by its `x-tenant` header, only to Backends labelled `team: orders`, and falls back to the `tenant-default` Backend when the header is absent. `remove-headers` keeps the header from the backend:

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
      url: http://orders-default:9080
  policies:
    - name: dynamic-endpoint
      version: v1
      params:
        backendExpression: request.Headers["x-tenant"][0]
        backendSelector:
          matchLabels:
            team: orders
        targetUpstream: tenant-default
    - name: remove-headers
      version: v1
      params:
        request:
          headers:
            - name: x-tenant
  operations:
    - method: GET
      path: /orders
```

A request with `x-tenant: tenant-b` goes to `http://orders-tenant-b:9080/v1/orders` or `http://orders-tenant-1-b:9080/v1/orders`. Onboarding a new tenant is one `POST /backends`; the API is not touched.

### Example 4: Route by a JWT Claim

After `jwt-auth`, route by the caller's `tenant_id` claim and reject callers whose token has none:

```yaml
policies:
  - name: jwt-auth
    version: v1
    params:
      issuers: [corporate-idp]
  - name: dynamic-endpoint
    version: v1
    params:
      backendExpression: auth.Properties["tenant_id"]
      backendSelector: {}
      onMissingValue: reject
```

## How It Works

1. When the policy is created, it validates the parameters and compiles `backendExpression`.
2. With only `targetUpstream`, every request is routed to that target: the API's upstream definition of that name if there is one, otherwise the Backend of that name.
3. With `backendExpression`, each request's headers, path, method, metadata, API, route and authentication context are bound to the expression's variables and the expression is evaluated.
4. A string result is trimmed and checked: it must be a valid Backend name, the Backend must exist, and its labels must match `backendSelector`. The request is then routed to that Backend's cluster, with the Backend's `basePath` in front of the request path.
5. No value applies `onMissingValue`; any other result is rejected with `400`.

## Notes

- Selection happens in the request-header phase. The request body is not available to the expression.
- `backendSelector` and `onMissingValue` are only valid together with `backendExpression`, and `backendExpression` requires `backendSelector`.
- A Backend's own `tls` settings apply to every request routed to it, whatever the API's upstream definitions say.
- Requires a gateway that supports the `Backend` kind (later than 1.2.0).
- Upgrading from v1.0: with v1.0, a `targetUpstream` that names none of the API's upstream definitions was ignored when the API had no upstream definitions or sandbox upstream, and the request silently went to the API's own upstream. In v1.1 such a name refers to a Backend, so those requests fail closed with `503` until a Backend of that name exists, the same as on an API that has upstream definitions. Configurations whose `targetUpstream` names one of the API's upstream definitions are unaffected.
- `targetUpstream` is matched exactly as written, including case. A `targetUpstream` set to an empty string leaves the route's own upstream in place, as in v1.0.
