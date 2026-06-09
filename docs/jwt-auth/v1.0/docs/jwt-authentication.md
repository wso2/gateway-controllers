---
title: "Overview"
---
# JWT Authentication

## Overview

The JWT Authentication policy validates JWT access tokens using one or more JWKS (JSON Web Key Set) providers. It is typically applied to operations that require bearer token authentication before requests are forwarded upstream.

## Features

- Validates JWTs using multiple key managers (JWKS providers)
- Supports remote JWKS endpoints and local certificates
- Configurable issuer, audience, scope, and claim validation
- Claim-to-header mappings for downstream services
- Token validation cache to skip repeated signature verification for the same token
- Configurable JWKS cache and retry settings
- Allowed signing algorithm allowlist
- Authorization header scheme enforcement and clock skew tolerance
- Customizable error responses
- Optional `userIdClaim` mapping for analytics
- Optional forwarding of the JWT to the upstream under a configurable header name

## Configuration

JWT Authentication requires two levels of configuration.

### System Parameters (config.toml)

| Parameter | Type | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `keymanagers` | ```KeyManager``` array | Yes | - | List of key manager definitions with JWKS configuration. |
| `jwkscachettl` | string | No | `"5m"` | JWKS cache TTL. |
| `jwksfetchtimeout` | string | No | `"5s"` | JWKS fetch timeout. |
| `jwksfetchretrycount` | integer | No | `3` | JWKS fetch retry count. |
| `jwksfetchretryinterval` | string | No | `"2s"` | JWKS fetch retry interval. |
| `tokencacheenabled` | boolean | No | `true` | Cache validated token claims to skip repeated signature verification. Algorithm check and expiry re-validation still run on every cache hit. |
| `tokencachettl` | string | No | `"5m"` | Maximum cache lifetime per token. The effective TTL is capped to the token's own `exp` claim so entries never outlive the token. |
| `tokencachemaxsize` | integer | No | `15000` | Maximum number of cached tokens. When full, expired entries are swept first; if still full, the new entry is dropped. Set to `0` for unlimited. |
| `allowedalgorithms` | array | No | `["RS256", "ES256"]` | Allowed JWT signing algorithms. |
| `leeway` | string | No | `"30s"` | Clock skew allowance for exp/nbf. |
| `authheaderscheme` | string | No | `"Bearer"` | Expected authorization scheme prefix. |
| `headername` | string | No | `"Authorization"` | Header name to extract the token from. |
| `onfailurestatuscode` | integer | No | `401` | HTTP status code on authentication failure. |
| `errormessageformat` | string | No | `"json"` | Error format: `"json"`, `"plain"`, or `"minimal"`. |
| `errormessage` | string | No | `"Authentication failed"` | Error message body for failures. |
| `validateissuer` | boolean | No | `true` | Validate the token `iss` claim against key managers. |

#### KeyManager Configuration

Each entry in `keymanagers` must include a unique `name` and either `jwks.remote` or `jwks.local`.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `name` | string | Yes | Unique key manager name. |
| `issuer` | string | No | Optional issuer (`iss`) value for this key manager. |
| `jwks.remote.uri` | string | Conditional | JWKS endpoint URL. Required if using remote JWKS. |
| `jwks.remote.certificatePath` | string | No | CA cert path for self-signed JWKS endpoints. |
| `jwks.remote.skipTlsVerify` | boolean | No | Skip TLS verification (use with caution). |
| `jwks.local.inline` | string | Conditional | Inline PEM certificate or public key. |
| `jwks.local.certificatePath` | string | Conditional | Path to certificate or public key file. |

#### Sample System Configuration

```toml
[policy_configurations.jwtauth_v1]
jwkscachettl = "5m"
jwksfetchtimeout = "5s"
jwksfetchretrycount = 3
jwksfetchretryinterval = "2s"
tokencacheenabled = true
tokencachettl = "5m"
tokencachemaxsize = 15000
allowedalgorithms = ["RS256", "ES256"]
leeway = "30s"
authheaderscheme = "Bearer"
headername = "Authorization"
onfailurestatuscode = 401
errormessageformat = "json"
errormessage = "Authentication failed"
validateissuer = true

[[policy_configurations.jwtauth_v1.keymanagers]]
name = "PrimaryIDP"
issuer = "https://idp.example.com/oauth2/token"

[policy_configurations.jwtauth_v1.keymanagers.jwks.remote]
uri = "https://idp.example.com/oauth2/jwks"
skipTlsVerify = false

[[policy_configurations.jwtauth_v1.keymanagers]]
name = "SecondaryIDP"
issuer = "https://auth.example.org/oauth2/token"

[policy_configurations.jwtauth_v1.keymanagers.jwks.remote]
uri = "https://auth.example.org/oauth2/jwks"
skipTlsVerify = false
```


### User Parameters (API Definition)

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `issuers` | array | No | List of key manager names (or issuer values) to use. If omitted, runtime matches token `iss` or tries all key managers. |
| `audiences` | array | No | Acceptable audience values. Token must contain at least one. |
| `requiredScopes` | array | No | Required scopes. Uses space-delimited `scope` claim or array `scp` claim. |
| `requiredClaims` | object | No | Map of claim name to expected value. |
| `claimMappings` | object | No | Map of claim name to downstream header name. |
| `authHeaderPrefix` | string | No | Overrides the configured authorization header scheme for this route. |
| `headerName` | string | No | Header name to extract the token from (e.g., `"Authorization"`). Overrides `system.headerName`. Must be a valid HTTP header field name (non-empty, no spaces or control characters). |
| `userIdClaim` | string | No | Claim name to extract user ID for analytics. Defaults to `sub`. |
| `forwardToken` | boolean | No | If `true` (default), the JWT is forwarded to the upstream after successful validation. Set to `false` to strip the token header before proxying. |
| `forwardedTokenHeader` | string | No | Header name used to forward the JWT to the upstream when `forwardToken` is `true`. Defaults to `x-forwarded-authorization`. If this differs from `headerName`, the original header is removed and the token is forwarded under this name instead. Has no effect when `forwardToken` is `false`. |


#### Token Validation Cache

When `tokencacheenabled` is `true` (the default), the gateway caches the validated claims of each unique token after its first successful verification. Subsequent requests carrying the same token return the cached claims directly, skipping the computationally expensive RSA signature verification and any remote JWKS network round-trip.

**Security invariants preserved on every cache hit:**

- **Algorithm check** — the token's signing algorithm is re-validated against `allowedalgorithms` on every request before the cache is consulted. Removing an algorithm from the allowlist takes effect immediately, even for tokens already in the cache.
- **Expiry re-check** — the `exp` claim is re-evaluated on every cache hit as a defense-in-depth guard. A stale entry (e.g. caused by a clock adjustment) is evicted and the request falls back to full validation.
- **Audience, scope, and required-claim checks** — these always run after the cache hit, so per-route policy constraints are always enforced.

**Cache TTL:** Entries expire at `min(tokencachettl, token exp + leeway)`, so a cached entry is never valid longer than the token itself regardless of how large `tokencachettl` is set.

**Cache eviction:** When the cache reaches `tokencachemaxsize`, expired entries are swept first. If the cache is still full after the sweep, the incoming entry is dropped silently (the request still succeeds via full validation; only future identical tokens lose the cache benefit).

To disable the cache entirely — for example when tokens are short-lived and unique per-request, or when the deployment requires strict real-time revocation detection — set `tokencacheenabled = false`.

**Note:**

Inside the `gateway/build.yaml`, ensure the policy module is added under `policies:`:

```yaml
- name: jwt-auth
  gomodule: github.com/wso2/gateway-controllers/policies/jwt-auth@v1
```

## Reference Scenarios

### Example 1: Basic JWT Authentication

```yaml
apiVersion: gateway.api-platform.wso2.com/v1alpha1
kind: RestApi
metadata:
  name: jwt-auth-basic-api
spec:
  displayName: JWT Auth Basic API
  version: v1.0
  context: /jwt-auth-basic/$version
  upstream:
    main:
      url: http://sample-backend:9080/api/v1
  operations:
    - method: GET
      path: /health
    - method: GET
      path: /protected
      policies:
        - name: jwt-auth
          version: v1
          params:
            issuers:
              - PrimaryIDP
```

### Example 2: Audience and Scope Validation

```yaml
apiVersion: gateway.api-platform.wso2.com/v1alpha1
kind: RestApi
metadata:
  name: jwt-auth-audience-api
spec:
  displayName: JWT Auth Audience API
  version: v1.0
  context: /jwt-auth-audience/$version
  upstream:
    main:
      url: http://sample-backend:9080/api/v1
  operations:
    - method: GET
      path: /protected
      policies:
        - name: jwt-auth
          version: v1
          params:
            issuers:
              - PrimaryIDP
            audiences:
              - "test-audience"
            requiredScopes:
              - read:data
```

### Example 3: Claim Mapping to Downstream Headers

```yaml
apiVersion: gateway.api-platform.wso2.com/v1alpha1
kind: RestApi
metadata:
  name: jwt-auth-claims-api
spec:
  displayName: JWT Auth Claims API
  version: v1.0
  context: /jwt-auth-claims/$version
  upstream:
    main:
      url: http://sample-backend:9080/api/v1
  operations:
    - method: GET
      path: /profile
      policies:
        - name: jwt-auth
          version: v1
          params:
            issuers:
              - PrimaryIDP
            claimMappings:
              sub: X-User-ID
              email: X-User-Email
              role: X-User-Role
```

### Example 4: Custom Token Header

```yaml
apiVersion: gateway.api-platform.wso2.com/v1alpha1
kind: RestApi
metadata:
  name: jwt-auth-custom-header-api
spec:
  displayName: JWT Auth Custom Header API
  version: v1.0
  context: /jwt-auth-custom/$version
  upstream:
    main:
      url: http://sample-backend:9080/api/v1
  operations:
    - method: GET
      path: /protected
      policies:
        - name: jwt-auth
          version: v1
          params:
            issuers:
              - PrimaryIDP
            headerName: X-API-Token
```

### Example 5: Custom User ID Claim for Analytics

```yaml
apiVersion: gateway.api-platform.wso2.com/v1alpha1
kind: RestApi
metadata:
  name: jwt-auth-claims-api
spec:
  displayName: JWT Auth Claims API
  version: v1.0
  context: /jwt-auth-claims/$version
  upstream:
    main:
      url: http://sample-backend:9080/api/v1
  operations:
    - method: GET
      path: /profile
      policies:
        - name: jwt-auth
          version: v1
          params:
            issuers:
              - PrimaryIDP
            claimMappings:
              sub: X-User-ID
              email: X-User-Email
              role: X-User-Role
            userIdClaim: username
```

### Example 6: Strip JWT Before Forwarding to Upstream

By default, the JWT is forwarded to the upstream after successful validation under the `x-forwarded-authorization` header. Set `forwardToken: false` to strip it before proxying.

```yaml
apiVersion: gateway.api-platform.wso2.com/v1alpha1
kind: RestApi
metadata:
  name: jwt-auth-strip-token-api
spec:
  displayName: JWT Auth Strip Token API
  version: v1.0
  context: /jwt-auth-strip/$version
  upstream:
    main:
      url: http://sample-backend:9080/api/v1
  operations:
    - method: GET
      path: /protected
      policies:
        - name: jwt-auth
          version: v1
          params:
            issuers:
              - PrimaryIDP
            forwardToken: false
```

### Example 7: Forward JWT Under a Custom Header

When `forwardToken` is `true` (the default), the validated JWT is forwarded to the upstream under the header named by `forwardedTokenHeader` (default `x-forwarded-authorization`). Use this to preserve the incoming `Authorization` header for other purposes, or to hand the token to a backend that expects a specific header name.

```yaml
apiVersion: gateway.api-platform.wso2.com/v1alpha1
kind: RestApi
metadata:
  name: jwt-auth-forwarded-header-api
spec:
  displayName: JWT Auth Forwarded Header API
  version: v1.0
  context: /jwt-auth-forwarded/$version
  upstream:
    main:
      url: http://sample-backend:9080/api/v1
  operations:
    - method: GET
      path: /protected
      policies:
        - name: jwt-auth
          version: v1
          params:
            issuers:
              - PrimaryIDP
            forwardToken: true
            forwardedTokenHeader: X-Backend-Authorization
```

### Example 8: Token Cache Tuning

The token validation cache is enabled by default and sized for up to 15 000 concurrent unique tokens. The example below shows how to tune the cache in `config.toml` for a deployment with a large number of active sessions or very short-lived tokens.

**High-throughput deployment (many concurrent sessions):**

```toml
[policy_configurations.jwtauth_v1]
# Keep the cache enabled but raise the cap to match the expected active session count.
tokencacheenabled = true
tokencachettl     = "10m"
tokencachemaxsize = 50000
```

**Strict revocation semantics (disable cache):**

When tokens can be revoked server-side and the deployment requires that revocations take effect within the next request, disable the token cache so every request performs a full signature verification.

```toml
[policy_configurations.jwtauth_v1]
tokencacheenabled = false
```

> **Note:** Disabling the token cache increases CPU load proportionally to request throughput because RSA signature verification runs on every request. Consider adjusting `jwkscachettl` to ensure the JWKS keys are still cached to avoid a network round-trip on every request.
