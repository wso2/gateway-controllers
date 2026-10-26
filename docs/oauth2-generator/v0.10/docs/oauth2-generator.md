---
title: "Overview"
---
# OAuth2 Generator

## Overview

The **OAuth2 Generator** policy generates an upstream credential and injects
it into a configurable request header before the request is forwarded to the
backend. It can be attached (via `policies:`/`operationPolicies:`) to any
API kind.

Configure exactly one of two mutually exclusive auth paths:

1. **Token endpoint + client credentials** (`tokenEndpoint`/`clientId`/
   `clientSecret`) — exchanges credentials for an access token via an OAuth2
   grant (`client_credentials` or `password`), then caches and automatically
   refreshes it ahead of expiry.
2. **A directly supplied token** (`bearerToken`) — for backends behind a
   long-lived or static credential. Injected as-is on every request; no
   token endpoint call, caching, or refresh involved.

The credential is injected into `headerName` (default `Authorization`) with
`valuePrefix` (default `Bearer`) prepended. Token-endpoint tokens are cached
in-process, and optionally shared across gateway-runtime replicas via Redis
(`cacheStrategy: redis`). A token rejected by the upstream backend
(`tokenPurgeStatusCodes`, default `[401]`) is purged from the cache so the
next request fetches a fresh one. The token-endpoint call itself also
supports proxying and custom TLS trust (`proxyURL`/`tlsCaCert`/
`tlsInsecureSkipVerify`).

## Features

- Two mutually exclusive auth paths: OAuth2 grant (`client_credentials` /
  `password`) against a token endpoint, or a directly supplied static token
- Two-tier token cache: in-process (always on) and an optional shared Redis
  tier (`cacheStrategy: redis`) so every gateway-runtime replica reuses the
  same token and survives an individual replica restart
- Automatic refresh ahead of token expiry (`expiryBuffer`, default `5m`
  before actual expiry), and automatic cache purge on a configurable set of
  upstream rejection status codes (default `401`)
- Bounded retry of transient token-endpoint failures (network errors,
  `429`, `5xx`), with exponential backoff and jitter
- Configurable credential injection: any header name, any (or no) scheme
  prefix
- Proxy (`proxyURL`) and custom TLS trust (`tlsCaCert` /
  `tlsInsecureSkipVerify`) for the token-endpoint call, independent of the
  proxied request's own upstream connection
- Extra headers (`tokenRequestHeaders`) and extra grant/body parameters
  (`tokenRequestParams`, e.g. `scope`) on the token request itself

## Configuration

This policy has two levels of configuration: **user parameters**, set per-API,
and **system parameters**, set by the gateway operator in `config.toml` and
shared across every policy instance.

### User Parameters (API Definition)

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `tokenEndpoint` | string | Conditional | - | OAuth2 token endpoint URL. Required (together with `clientId`/`clientSecret`) when `bearerToken` is not set. |
| `clientId` | string | Conditional | - | OAuth2 client ID. Required with `tokenEndpoint`. |
| `clientSecret` | string | Conditional | - | OAuth2 client secret. Required with `tokenEndpoint`. Supply either a literal value or a secret reference (e.g. a `secret` template expression) — see the redaction caveat under [Security Considerations](#security-considerations). |
| `grantType` | string | No | `"client_credentials"` | OAuth2 grant: `"client_credentials"` (RFC 6749 §4.4, the standard machine-to-machine grant — prefer this whenever the identity provider supports it) or `"password"` (RFC 6749 §4.3, Resource Owner Password Credentials — for bridging to legacy identity providers that only expose this grant; discouraged for new integrations, since it requires handling the resource owner's raw credentials directly). |
| `clientAuthMethod` | string | No | `"client_secret_basic"` | How the client ID/secret are presented to the token endpoint: `"client_secret_basic"` (HTTP Basic `Authorization` header — RFC 6749's preferred convention) or `"client_secret_post"` (as `client_id`/`client_secret` form fields in the request body). |
| `tokenRequestParams` | object (string map) | No | - | Extra form fields sent with the token request. The whole map is forwarded verbatim as additional form fields for both `client_credentials` (e.g. `scope`, `audience`, `resource`) and `password` |
| `bearerToken` | string | Conditional | - | Directly supplied credential. Mutually exclusive with `tokenEndpoint`/`clientId`/`clientSecret` — configure exactly one of the two auth paths. When set, every token-endpoint-only parameter below is unused. |
| `username` | string | Conditional | - | Resource owner username. Required when `grantType` is `"password"`. |
| `password` | string | Conditional | - | Resource owner password. Required when `grantType` is `"password"` — see the redaction caveat under [Security Considerations](#security-considerations). |
| `tokenRequestHeaders` | object (string map) | No | - | Extra HTTP headers sent with the token-endpoint request, on top of whatever `clientAuthMethod`/the grant itself already set. `Authorization` and `Content-Type` are dropped if present — both are already managed by `clientAuthMethod` and the grant's own request encoding. |
| `headerName` | string | No | `"Authorization"` | Header the generated (or directly supplied) credential is injected into. |
| `valuePrefix` | string | No | `"Bearer"` | Prepended (with a single space) to the credential value. Set to `""` explicitly for no prefix at all. |
| `tokenRequestTimeout` | string | No | `"10s"` | Bounds a single token-endpoint HTTP call (Go duration format). Without this, a hung identity provider would otherwise block a token fetch indefinitely. A zero or negative value falls back to the default rather than being honored as-is (it would otherwise disable the timeout entirely). |
| `tokenRequestMaxRetries` | integer | No | `2` | Additional attempts after the initial token-endpoint call fails with a transient error (network error, `429`, `5xx`) — a rejected/malformed credential (other `4xx`) is never retried. Backoff is exponential with jitter, capped at 2s. |
| `defaultTokenTTL` | string | No | `"1h"` | Applied when the token endpoint's response omits `expires_in` (Go duration format). Without this fallback, such a token would never be cached — every request would re-fetch it. A zero or negative value falls back to the default rather than being honored as-is (it would otherwise make the fetched token expire before it's even cached). |
| `expiryBuffer` | string | No | `"5m"` | How long before a token's actual expiry it's treated as stale and refreshed early (Go duration format) — so a request is never forwarded upstream with a credential that expires mid-flight. Applies to both the cache tiers and the token endpoint's own refresh timing, replacing the hardcoded 10s margin `golang.org/x/oauth2` uses internally. Keep this comfortably below `defaultTokenTTL` and any `expires_in` the token endpoint actually returns — a value at or above the token's real lifetime forces a fresh fetch on every request (in particular, a token endpoint issuing ~5-minute-or-shorter tokens needs an explicitly smaller `expiryBuffer`, or caching is effectively disabled). Unlike every other duration parameter on this page, `0` is honored as-is here (no early-refresh margin — a token only refreshes once actually expired); only a *negative* value falls back to the `5m` default. |
| `tokenPurgeStatusCodes` | integer array | No | `[401]` | Upstream response status codes that purge the cached token — a signal that the token this policy just injected was rejected (e.g. revoked out-of-band at the identity provider). Set to `[]` to disable purge-on-rejection entirely. |
| `cacheStrategy` | string | No | `"memory"` | Token cache tier(s): `"memory"` (per-replica, in-process only) or `"redis"` (adds a shared Redis tier in front of the token endpoint — see [System Parameters](#system-parameters-from-configtoml) below). |
| `proxyURL` | string | No | `""` | Explicit HTTP/HTTPS proxy URL for the token-endpoint call only (e.g. `"http://user:pass@proxy.internal:8080"`) — independent of the proxied request's own upstream connection. Defaults to the standard `HTTP_PROXY`/`HTTPS_PROXY`/`NO_PROXY` environment variables when omitted. |
| `tlsCaCert` | string | No | `""` | PEM-encoded CA certificate **content** to trust for the token endpoint's TLS connection — for a private/internal CA (on-prem IdPs, TLS-inspecting corporate proxies). This is the certificate content itself, not a filesystem path; supply it via a secret reference (e.g. `{{ secret "handle" }}`) rather than a literal value. Once set, the token endpoint's TLS connection trusts *only* the CA(s) given here, not the system's default public CAs as well — if the endpoint's certificate chain also needs a public root/intermediate to validate, concatenate that certificate into this same value too (multiple PEM certificates in one value are supported, to trust more than one CA). |
| `tlsInsecureSkipVerify` | boolean | No | `false` | Skips TLS certificate verification for the token-endpoint call. Only ever use this in local/throwaway test setups, never against a real identity provider. |

### System Parameters (From config.toml)

Redis connection settings for the shared cache tier are operator/gateway-level,
not something an individual API publisher sets — they resolve from the
gateway's own `config.toml`, entirely under this policy's own
`policy_configurations.oauth2_generator_v1.redis` section. This section is
*not* shared with any other Redis-using policy (e.g. `advanced-ratelimit`
resolves its own settings from its own `policy_configurations.ratelimit_v1.redis`
section instead) — every field below, including `host`/`port`, is namespaced
to this policy, not just `keyPrefix`. Only read at all when a policy instance
sets `cacheStrategy: redis`.

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `host` | string | No | `"localhost"` | Redis server hostname or IP address. |
| `port` | integer | No | `6379` | Redis server port. |
| `username` | string | No | `""` | Redis ACL username (optional, Redis 6+). |
| `password` | string | No | `""` | Redis authentication password (optional). |
| `db` | integer | No | `0` | Redis database index (0-15). |
| `keyPrefix` | string | No | `"oauth2-generator:token:v1:"` | Prefix for this policy's Redis keys, so that sharing a Redis *server* with another policy never collides in the keyspace. |
| `failureMode` | string | No | `"open"` | Behavior when Redis is unavailable: `"open"` falls back to fetching a fresh token directly from the token endpoint; `"closed"` treats a Redis error as a token-acquisition failure (`502`). |
| `connectionTimeout` | string | No | `"5s"` | Redis connection timeout (Go duration format). |
| `readTimeout` | string | No | `"3s"` | Redis read timeout (Go duration format). |
| `writeTimeout` | string | No | `"3s"` | Redis write timeout (Go duration format). |
| `poolSize` | integer | No | `0` | Connection pool size for the shared Redis client (`0` = go-redis default, 10 × GOMAXPROCS). One pool is shared per distinct Redis endpoint across every *oauth2-generator* policy instance on this gateway with identical connection settings — not across other policy types (each maintains its own separate pool), and not one pool per policy instance. |

#### Sample System Configuration

```toml
[policy_configurations.oauth2_generator_v1.redis]
host = "redis.example.com"
port = 6379
failure_mode = "open"
key_prefix = "my-gateway:oauth2:"
```

## How It Works

1. **Request header phase** – On each request, the policy asks its token
   source for the current credential:
   - **Static path** (`bearerToken` set): the configured token is returned
     as-is. No network call, caching, or refresh.
   - **Token-endpoint path**: a token still fresh outside `expiryBuffer` of
     its expiry is served from the in-process cache (and, if
     `cacheStrategy: redis`, the shared Redis tier) if one exists. Otherwise
     the token endpoint is called using the configured grant, with bounded
     retry on transient failures (`tokenRequestMaxRetries`), and the
     resulting token is cached (using `defaultTokenTTL` as a fallback expiry
     if the response omitted `expires_in`). `expiryBuffer` governs this
     refresh-ahead decision at every layer — the cache tiers and the token
     endpoint's own internal reuse both refresh once a cached token enters
     that window, rather than only once it's actually expired.
2. The credential is injected into `headerName`, prefixed with `valuePrefix`
   (a single space separator), and the request is forwarded upstream.
3. **Response header phase** – if the upstream backend responds with one of
   `tokenPurgeStatusCodes` (default `401`), the cached token is purged from
   both cache tiers so the *next* request fetches a genuinely fresh one. The
   current response still passes through unchanged — this policy never
   retries the proxied request itself, only the token fetch.
4. If a credential cannot be obtained (token endpoint unreachable, retries
   exhausted, malformed response, or rejected client credentials), the
   request is short-circuited with `502 Bad Gateway` — a gateway-to-backend
   authentication failure, not an inbound-client authentication rejection.

## Reference Scenarios

### Example 1: `client_credentials` Grant Against a Standard OAuth2 IdP

```yaml
apiVersion: gateway.api-platform.wso2.com/v1alpha1
kind: RestApi
metadata:
  name: partner-api-v1.0
spec:
  displayName: Partner-API
  version: v1.0
  context: /partner/$version
  upstream:
    main:
      url: https://partner-backend.example.com
  policies:
    - name: oauth2-generator
      version: v0
      params:
        tokenEndpoint: https://idp.example.com/oauth2/token
        clientId: gateway-client
        clientSecret: '{{ secret "partner-api-client-secret" }}'
        tokenRequestParams:
          scope: partner-api.read
  operations:
    - method: GET
      path: /orders
```

### Example 2: Directly Supplied Static Token, Custom Header

```yaml
  policies:
    - name: oauth2-generator
      version: v0
      params:
        bearerToken: '{{ secret "static-api-token" }}'
        headerName: X-Api-Token
        valuePrefix: ""
```

### Example 3: Password Grant with Custom Retry/Timeout Tuning

```yaml
  policies:
    - name: oauth2-generator
      version: v0
      params:
        grantType: password
        tokenEndpoint: https://legacy-idp.example.com/oauth2/token
        clientId: gateway-client
        clientSecret: '{{ secret "legacy-idp-client-secret" }}'
        username: resource-owner
        password: '{{ secret "legacy-idp-password" }}'
        tokenRequestTimeout: "5s"
        tokenRequestMaxRetries: 3
```

### Example 4: Trusting a Private CA for the Token Endpoint

```yaml
  policies:
    - name: oauth2-generator
      version: v0
      params:
        tokenEndpoint: https://idp.internal.example.com/oauth2/token
        clientId: gateway-client
        clientSecret: '{{ secret "internal-idp-client-secret" }}'
        tlsCaCert: '{{ secret "internal-idp-ca-bundle" }}'
```

## Error Responses

All error responses are returned as JSON with `Content-Type: application/json`.

| Scenario | Status | Message |
|----------|--------|---------|
| Token endpoint unreachable, or retries exhausted against a transient failure | 502 | `failed to authenticate request to upstream service` |
| Client credentials rejected by the identity provider | 502 | `failed to authenticate request to upstream service` |
| Malformed token-endpoint response (missing `access_token`) | 502 | `failed to authenticate request to upstream service` |
| Redis cache unavailable and `failureMode: closed` | 502 | `failed to authenticate request to upstream service` |

**Example error body:**
```json
{
  "error": "Bad Gateway",
  "message": "failed to authenticate request to upstream service"
}
```

Every gateway-side credential-acquisition failure returns the identical
generic `502` shape regardless of the underlying cause — the specific reason
is logged internally only, never disclosed to the caller.

## Security Considerations

- **Prefer `client_credentials` over `password`** – the Resource Owner
  Password grant requires the gateway to handle the resource owner's raw
  username/password directly; use it only to bridge legacy identity
  providers that offer no alternative.
- **`tlsInsecureSkipVerify`** – only ever appropriate for local/throwaway
  test setups against a self-signed certificate. Never use it against a
  real identity provider; prefer `tlsCaCert` to trust a specific private
  CA instead.
- **Redis cache is namespaced per policy, not a shared resource across policy types** –
  the connection pool and keyspace are shared only across oauth2-generator
  policy instances with identical connection settings, not with other
  Redis-using policies (each has its own separate `policy_configurations.<policy>_v1.redis`
  section and pool). `keyPrefix` prevents key collisions between multiple
  oauth2-generator instances pointed at the same Redis server; the Redis
  instance itself should still be access-controlled like any other
  credential store, since cached entries are access tokens.
- **`failureMode: closed`** – if you cannot tolerate a cache-tier outage
  silently falling back to direct token-endpoint calls (e.g. for load
  reasons), set this explicitly; the default (`open`) prioritizes
  availability over strict cache enforcement.

## Gateway Module Reference

```yaml
- name: oauth2-generator
  gomodule: github.com/wso2/gateway-controllers/policies/oauth2-generator@v0
```
