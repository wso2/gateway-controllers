# Client Secret Basic

**Version:** v1.0.0 · **Category:** Security

Validates client credentials presented in the standard `Authorization: Basic` header. The header value must be `Basic <base64(clientId:clientSecret)>`. Two validation modes are available: **static** (credentials configured directly in the API definition) and **dynamic** (credentials verified against an OAuth2 token endpoint at request time, with in-process caching to prevent a token call on every request).

After successful validation in either mode:
- The authentication context is populated (`AuthType: ClientCredentials`, `Subject` and `CredentialID` set to the validated `clientId`).
- The `Authorization` and `Subscription-Key` headers are stripped before forwarding to the upstream.
- `SharedContext.Metadata["x-wso2-application-id"]` is set to the validated `clientId`, enabling `subscription-validation` to match the subscription without requiring a separate `Subscription-Key` header from the caller.
- All `401` responses include `WWW-Authenticate: Basic realm="API Gateway"` per RFC 7235.
- Client IDs and secrets decoded from the `Authorization: Basic` header are URL-decoded per RFC 6749 §2.3.1.

---

## Configuration parameters

### Static mode

Provide either `credentials` (multi-client) or `clientId` + `clientSecret` (single-client). Mutually exclusive with `tokenEndpoint`.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `credentials` | array | See note | — | Array of `{clientId, clientSecret}` objects. Allows multiple callers with independent credentials. |
| `clientId` | string | See note | — | Single client ID (backward-compatible alternative to `credentials`). |
| `clientSecret` | string | See note | — | Single client secret matching `clientId`. |

### Dynamic mode

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `tokenEndpoint` | string | Yes (dynamic) | — | OAuth2 token endpoint URL. When set, validates credentials by attempting a `client_credentials` token request using HTTP Basic auth. |
| `tokenRequestTimeout` | string | No | `10s` | HTTP timeout for token endpoint requests. Go duration string, e.g. `"30s"`. |
| `expiryBuffer` | string | No | `30s` | How far ahead of token expiry the cached result is treated as stale. Set `"0s"` to cache until exact expiry. |
| `maxCacheTTL` | string | No | `5m` | Maximum time a successful validation is cached, regardless of `expires_in`. This is the effective revocation window — a revoked credential stays cached at most this long. |
| `failureRateLimit` | integer | No | `3` | Maximum distinct failed credential attempts per clientId per `failureWindow` before the policy returns `429`. Prevents one wrong secret from blocking all requests for that clientId. |
| `failureWindow` | string | No | `30s` | Tumbling window over which the per-clientId failure counter resets. Accepts a Go duration string, e.g. `"30s"`. |
| `tokenMetadataKey` | string | No | `upstream-access-token` | Metadata key under which the IdP access token is stored after a successful dynamic validation. Downstream policies can read it with `${meta.<key>}` (e.g. in `header-transform`: `value: Bearer ${meta.upstream-access-token}`). Has no effect in static mode. |

---

## Examples

### Example 1: Static — multi-client (recommended)

Register multiple credential pairs. The policy matches the `clientId` decoded from the `Authorization: Basic` header and validates the corresponding secret.

```yaml
apiVersion: gateway.api-platform.wso2.com/v1
kind: RestApi
metadata:
  name: orders-api-v1
spec:
  displayName: Orders API
  version: v1.0.0
  context: /orders/v1
  upstream:
    main:
      url: http://orders-backend.internal/api
  policies:
    - name: client-secret-basic
      version: v1
      params:
        credentials:
          - clientId: app-one
            clientSecret: '{{ secret "app-one-secret" }}'
          - clientId: app-two
            clientSecret: '{{ secret "app-two-secret" }}'
  operations:
    - method: GET
      path: /items
    - method: POST
      path: /items
```

**app-one request (accepted):**
```bash
CREDS=$(echo -n "app-one:secret1" | base64)
curl -H "Authorization: Basic $CREDS" https://gateway.example.com/orders/v1/items
```

Rotate one client's secret by updating its gateway secret and redeploying — the other client is unaffected.

---

### Example 2: Static — single-client

```yaml
apiVersion: gateway.api-platform.wso2.com/v1
kind: RestApi
metadata:
  name: orders-api-v1
spec:
  displayName: Orders API
  version: v1.0.0
  context: /orders/v1
  upstream:
    main:
      url: http://orders-backend.internal/api
  policies:
    - name: client-secret-basic
      version: v1
      params:
        clientId: my-service-account
        clientSecret: '{{ secret "my-service-secret" }}'
  operations:
    - method: GET
      path: /items
```

---

### Example 3: Dynamic — validate via OAuth2 token endpoint

The policy forwards the `Authorization: Basic` header unchanged to the configured token endpoint as an OAuth2 `client_credentials` grant. If the endpoint issues a token, the credentials are valid. The result is cached in-process for `expires_in − expiryBuffer` seconds to avoid a token call on every request.

```yaml
apiVersion: gateway.api-platform.wso2.com/v1
kind: RestApi
metadata:
  name: orders-api-v1
spec:
  displayName: Orders API
  version: v1.0.0
  context: /orders/v1
  upstream:
    main:
      url: http://orders-backend.internal/api
  policies:
    - name: client-secret-basic
      version: v1
      params:
        tokenEndpoint: https://idp.example.com/realms/wso2/protocol/openid-connect/token
        tokenRequestTimeout: 10s
        expiryBuffer: 30s
  operations:
    - method: GET
      path: /items
```

**Request (accepted — token endpoint returns 200):**
```
Authorization: Basic bXktY2xpZW50Om15LXNlY3JldA==
```

**Request (rejected — token endpoint returns 401):**
```json
HTTP/1.1 401 Unauthorized
{"error":"unauthorized","message":"Unauthorized: invalid credentials"}
```

The dynamic mode is useful when client credentials are managed in an external identity provider (Keycloak, Okta, Azure AD) and you want the gateway to verify them without maintaining a local copy.

---

### Example 4: Dynamic — custom timeout

```yaml
policies:
  - name: client-secret-basic
    version: v1
    params:
      tokenEndpoint: https://idp.example.com/realms/wso2/protocol/openid-connect/token
      tokenRequestTimeout: 5s
      expiryBuffer: 2m
```

---

### Example 5: Dynamic — forward the access token to the backend

After a successful dynamic validation, the IdP-issued access token is stored in `SharedContext.Metadata` under the key `upstream-access-token` by default (configurable via `tokenMetadataKey`). A downstream `header-transform` policy can read it with `${meta.upstream-access-token}` and add it as an `Authorization` header on the upstream request.

```yaml
policies:
  - name: client-secret-basic
    version: v1
    params:
      tokenEndpoint: https://idp.example.com/realms/wso2/protocol/openid-connect/token
  - name: header-transform
    version: v1
    params:
      request:
        add:
          - name: Authorization
            value: Bearer ${meta.upstream-access-token}
```

The original `Authorization: Basic` header is stripped by `client-secret-basic` before `header-transform` runs. The `header-transform` policy then sets a new `Authorization` header on the upstream request using the token from metadata.

**Note:** the token is cached in-process alongside the validation result. On a cache hit, the previously issued token is reused until the cache entry expires — the backend receives the same token for the duration of `maxCacheTTL`.

---

### Example 6: Full API definition with per-plan routing

Combines `client-secret-basic`, `subscription-validation`, and `dynamic-endpoint` to authenticate callers and route each request to the backend tier that matches the caller's subscription plan.

```yaml
apiVersion: gateway.api-platform.wso2.com/v1
kind: RestApi
metadata:
  name: orders-api-v1
spec:
  displayName: Orders API
  context: /orders/v1
  version: v1.0.0
  subscriptionPlans:
    - gold
    - silver
  upstream:
    main:
      url: http://silver-backend.internal/orders
  upstreamDefinitions:
    - name: gold
      upstreams:
        - url: http://gold-backend.internal/orders
    - name: silver
      upstreams:
        - url: http://silver-backend.internal/orders
  policies:
    - name: client-secret-basic
      version: v1
      params:
        clientId: my-client
        clientSecret: '{{ secret "my-api-secret" }}'
    - name: subscription-validation
      version: v1
    - name: dynamic-endpoint
      version: v1
      executionCondition: >-
        "x-wso2-subscription-plan-name" in request.Metadata &&
        request.Metadata["x-wso2-subscription-plan-name"] == "gold"
      params:
        targetUpstream: gold
    - name: dynamic-endpoint
      version: v1
      executionCondition: >-
        "x-wso2-subscription-plan-name" in request.Metadata &&
        request.Metadata["x-wso2-subscription-plan-name"] == "silver"
      params:
        targetUpstream: silver
  operations:
    - method: GET
      path: /items
    - method: POST
      path: /items
```

**Caller request:**
```bash
CREDS=$(echo -n "my-client:my-secret" | base64)
curl -H "Authorization: Basic $CREDS" https://gateway.example.com/orders/v1/items
```

---

## How it works

### Credential extraction

On every inbound request, the policy reads the `Authorization` header. The header must be present and use the `Basic` scheme:

```
Authorization: Basic <base64(clientId:clientSecret)>
```

- If the header is absent → 401.
- If the scheme is not `Basic` (e.g. `Bearer`) → 401.
- If the base64 value cannot be decoded → 401.
- If the decoded value does not contain a `:` separator → 401.
- The part before the first `:` becomes `clientId`; everything after becomes `clientSecret` (secrets may contain `:` characters).

### Static mode

1. At policy-load time, `GetPolicy` resolves the credential set from params into an in-memory map (`clientId → clientSecret`). Duplicate `clientId` values are rejected.
2. The extracted `clientId` is looked up in the credential map. If not found, or if the secret does not match → 401.
3. On success: auth context is populated, application ID is injected into `SharedContext.Metadata`, and the `Authorization` header is added to `HeadersToRemove`.

### Dynamic mode

1. At policy-load time, `GetPolicy` validates the `tokenEndpoint` URL and initialises an `http.Client` with the configured timeout.
2. The policy computes a cache key from `sha256(clientId + ":" + clientSecret)` and checks the in-process cache.
   - **Cache hit (not expired):** treat as valid — skip token request.
   - **Cache miss or expired:** proceed to the token request.
3. The policy POSTs a `grant_type=client_credentials` request to `tokenEndpoint`, forwarding the original `Authorization: Basic` header unchanged so percent-encoded characters are not double-decoded (RFC 6749 §2.3.1).
4. If the endpoint returns HTTP 200 with an `access_token`: the result is cached for `min(expires_in − expiryBuffer, maxCacheTTL)`. The access token value is stored in the cache entry alongside the expiry time. If `expires_in` is absent, the fallback TTL is 1 hour minus the expiry buffer, still capped by `maxCacheTTL`. Concurrent first requests for the same credential pair are deduplicated via singleflight — only one IdP call is made regardless of concurrency. Known-bad credential pairs are cached so repeats never reach the IdP. Per-clientId failure rate limiting (`failureRateLimit` attempts per `failureWindow`) returns 429 when exhausted — a single wrong secret cannot block requests for the same clientId with the correct secret. Only HTTP 400/401 responses are cached as rejections; 429 and other 4xx/5xx are treated as transient and return 503 without caching.
5. On success: same outcome as static mode (auth context, application ID, `Authorization` header removal). Additionally, when `tokenMetadataKey` is configured, the access token (from either a fresh IdP call or the cache) is stored in `SharedContext.Metadata[tokenMetadataKey]` for use by downstream policies.

---

## Subscription validation integration

Both modes set `SharedContext.Metadata["x-wso2-application-id"]` to the validated `clientId`. When `subscription-validation` follows this policy in the chain, it reads that metadata key to find the subscription — no `Subscription-Key` header is needed from the caller.

```
client-secret-basic → subscription-validation → dynamic-endpoint
```

The `x-wso2-application-id` metadata key is **always overwritten** with the validated `clientId`, so `subscription-validation` sees the credential that was actually authenticated. The `Subscription-Key` header is stripped alongside `Authorization` so upstream services never receive it, regardless of whether a subscription check follows.

---

## Error responses

The `error` field in the response body varies by condition:

**401 Unauthorized:**
```json
{"error":"unauthorized","message":"<detail>"}
```

**429 Too Many Requests** (dynamic mode; includes `Retry-After: <seconds>` header):
```json
{"error":"too_many_requests","message":"too many failed attempts — retry after the rate-limit window resets"}
```

**503 Service Unavailable** (dynamic mode):
```json
{"error":"service_unavailable","message":"service temporarily unavailable"}
```

| Condition | HTTP status | `message` |
|---|---|---|
| `Authorization` header absent | 401 | `Unauthorized: missing Authorization header` |
| `Authorization` header is not `Basic` scheme | 401 | `Unauthorized: Authorization header must use Basic scheme` |
| Base64 decode failure | 401 | `Unauthorized: malformed Basic credentials` |
| Decoded value has no `:` separator | 401 | `Unauthorized: Basic credential format must be clientId:clientSecret` |
| Static: credentials do not match | 401 | `Unauthorized: invalid credentials` |
| Dynamic: token endpoint rejects | 401 | `Unauthorized: invalid credentials` |
| Dynamic: failure rate limit exceeded (per clientId) | 429 | `too many failed attempts — retry after the rate-limit window resets` |
| Dynamic: token endpoint unreachable, returns 5xx, or returns 429 | 503 | `service temporarily unavailable` |
| Request context is nil | 401 | `Unauthorized: request context is missing` |

---

## Limitations

- **Dynamic mode — credential changes need cache expiry.** If an external credential is revoked at the IdP, cached validations for that credential remain valid until the entry expires. The effective maximum hold time is `min(expires_in - expiryBuffer, maxCacheTTL)`. Use a short `maxCacheTTL` when low revocation latency is required.
- **Static mode — no runtime rotation.** Changing the credential set requires updating the API definition and redeploying.
- **Authorization: Basic only.** Bearer tokens, API keys in query parameters, and other credential formats are not supported by this policy.
- **Dynamic mode — no Redis.** The validation cache is in-process only. Each gateway replica maintains its own cache independently.
- **Dynamic mode — 256-character client ID limit.** Client IDs longer than 256 characters are rejected with `401 Unauthorized` and the message `Unauthorized: invalid credentials`. This is the same response as a wrong secret — the limit is not disclosed to callers.
- **Dynamic mode — throttle DoS.** Anyone who knows a `clientId` can exhaust its per-window failure budget by sending `failureRateLimit` distinct wrong secrets, temporarily blocking further unauthenticated attempts for that client. Clients with a still-valid entry in the success cache are unaffected.

---

## Security notes

- Store `clientSecret` values in gateway-managed secrets and reference them with `{{ secret "<handle>" }}` — never commit literal values to YAML.
- The `Authorization` header is stripped from every upstream request after validation.
- Dynamic mode sends the raw `clientSecret` to the token endpoint over HTTPS. Always ensure `tokenEndpoint` uses TLS.
- `AuthContext` is populated with `Subject` and `CredentialID` both set to the validated `clientId`. `TokenId` is not set: deriving a stable identifier from the secret value would create an analytics-visible fingerprint of the credential.
- The dynamic-mode cache key is also a SHA-256 hash of the credential pair — the raw secret never appears in memory structures visible in diagnostics or traces.
