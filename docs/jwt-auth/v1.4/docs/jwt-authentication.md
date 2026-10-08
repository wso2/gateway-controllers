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
- Boolean scope and claim requirements via `allOf` / `anyOf` composition (the `scopes` and `claims` parameters)
- Per-key-manager scope claim selection (`scopeClaim` / `scopeClaimSeparator`)
- Claim-to-header mappings for downstream services
- Configurable JWKS cache and retry settings
- Token verification result caching: successfully verified tokens skip re-verification on repeat presentation, and deterministically invalid tokens (expired or malformed) are also cached to absorb repeated bad requests without re-verifying them
- Fixed signing algorithm set: RS256, PS256, and ES256 (HMAC and `none` are rejected unconditionally)
- Authorization header scheme enforcement and clock skew tolerance
- Customizable error responses
- Optional `userIdClaim` mapping for analytics
- Optional forwarding of the JWT to the upstream under a configurable header name, as either the full header value or the bare token value (scheme prefix stripped)

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
| `leeway` | string | No | `"30s"` | Clock skew allowance for exp/nbf. |
| `authheaderscheme` | string | No | `"Bearer"` | Expected authorization scheme prefix. |
| `headername` | string | No | `"Authorization"` | Header name to extract the token from. |
| `onfailurestatuscode` | integer | No | `401` | HTTP status code on authentication failure. |
| `errormessageformat` | string | No | `"json"` | Error format: `"json"`, `"plain"`, or `"minimal"`. |
| `errormessage` | string | No | `"Authentication failed"` | Error message body for failures. |
| `validateissuer` | boolean | No | `true` | Validate the token `iss` claim against key managers. |
| `tokencaching` | boolean | No | `true` | Whether to cache token verification verdicts (see [Token Verification Caching](#token-verification-caching) below). Set to `false` to force full re-verification on every request. |
| `tokencachettl` | string | No | `"5m"` | Maximum duration a successfully verified token is trusted from cache. The actual cache expiry is the sooner of this value and the token's own `exp` claim (minus leeway). |
| `negativecachettl` | string | No | `"30s"` | Duration a deterministically invalid verdict (expired or malformed token) is cached before re-verification is attempted again. |
| `cachemaxsize` | integer | No | `100000` | Maximum total number of cached verdicts (successful and failed, combined) held across all APIs. Least-recently-used entries are evicted once the limit is reached. |

#### KeyManager Configuration

Each entry in `keymanagers` must include a unique `name` and either `jwks.remote` or `jwks.local`.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `name` | string | Yes | Unique key manager name. |
| `issuer` | string | No | Optional issuer (`iss`) value for this key manager. |
| `scopeClaim` | string | No | Token claim to read scopes from for tokens verified by this key manager. When omitted, scopes are read from both the space-delimited `scope` claim and the `scp` array claim (the default behavior). |
| `scopeClaimSeparator` | string | No | Separator used to split a string-valued `scopeClaim` into individual scopes. Defaults to a single space (`" "`). Ignored when `scopeClaim` resolves to an array claim, and has no effect unless `scopeClaim` is set. |
| `jwks.remote.uri` | string | Conditional | JWKS endpoint URL. Required if using remote JWKS. |
| `jwks.remote.certificatePath` | string | No | CA cert path for self-signed JWKS endpoints. |
| `jwks.remote.skipTlsVerify` | boolean | No | Skip TLS verification (use with caution). |
| `jwks.local.inline` | string | Conditional | Inline PEM certificate or public key. |
| `jwks.local.certificatePath` | string | Conditional | Path to certificate or public key file. |

#### Token Verification Caching

When `tokencaching` is enabled (the default), the policy caches the outcome of signature verification so that repeat presentations of the same token — under the same key manager and validation configuration — skip re-verification entirely (unverified parsing, key manager/certificate parsing, and signature checking).

- **Successful verifications** are cached for up to `tokencachettl`, but never longer than the token's own `exp` claim (minus `leeway`) — so a live cache entry is always still within the token's validity window. This bounds how long a revoked token may still be accepted after it was last verified.
- **Deterministically invalid tokens** — expired or structurally malformed only — are also cached, for the shorter `negativecachettl`, so repeated bad tokens are rejected without re-verifying them each time. Transient failures (e.g. a JWKS endpoint outage, an unrecognized `kid` during key rotation) and not-yet-valid (`nbf`) tokens are never cached, since those may resolve on a later attempt.
- The cache is a single pool shared across all APIs on the gateway, bounded by `cachemaxsize`; entries are keyed by the token together with the key manager configuration, issuer validation settings, the configured `issuers` list, `leeway`, and the API identity, so a configuration change or redeploy is never served a stale verdict.
- Set `tokencaching` to `false` to force full verification on every request — useful when debugging or when token validity must be checked against live state on every call.

#### Sample System Configuration

```toml
[policy_configurations.jwtauth_v1]
jwkscachettl = "5m"
jwksfetchtimeout = "5s"
jwksfetchretrycount = 3
jwksfetchretryinterval = "2s"
leeway = "30s"
authheaderscheme = "Bearer"
headername = "Authorization"
onfailurestatuscode = 401
errormessageformat = "json"
errormessage = "Authentication failed"
validateissuer = true
tokencaching = true
tokencachettl = "5m"
negativecachettl = "30s"
cachemaxsize = 100000

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
| `scopes` | object | No | Scope requirements as `allOf` (every listed scope must be present) and/or `anyOf` (at least one must be present). When both are given they are AND-ed: `(all of allOf) AND (any of anyOf)`. Takes precedence over `requiredScopes`. See [Example 3](#example-3-scopes-and-claims-each-with-allof--anyof). |
| `claims` | object | No | Claim requirements as `allOf` and/or `anyOf` lists of matchers, each `{ claim, values }`. A matcher is satisfied when the token's claim value is one of `values` (for a multi-valued claim, any overlap). `allOf` requires every matcher; `anyOf` requires at least one; both are AND-ed. Takes precedence over `requiredClaims`. See [Example 3](#example-3-scopes-and-claims-each-with-allof--anyof). |
| `requiredScopes` | array | No | **Deprecated — use `scopes` (`anyOf`) instead.** Required scopes; at least one must be present (uses the space-delimited `scope` claim or the array `scp` claim). Ignored when `scopes` is configured. |
| `requiredClaims` | object | No | **Deprecated — use `claims` instead.** Map of claim name to expected value; every pair must match (exact string). Ignored when `claims` is configured. |
| `claimMappings` | object | No | Map of claim name to downstream header name. |
| `authHeaderPrefix` | string | No | Overrides the configured authorization header scheme for this route. |
| `headerName` | string | No | Header name to extract the token from (e.g., `"Authorization"`). Overrides `system.headerName`. Must be a valid HTTP header field name (non-empty, no spaces or control characters). |
| `userIdClaim` | string | No | Claim name to extract user ID for analytics. Defaults to `sub`. |
| `forwardToken` | boolean | No | If `true` (default), the JWT is forwarded to the upstream after successful validation. Set to `false` to strip the token header before proxying. |
| `forwardedTokenHeader` | string | No | Header name used to forward the JWT to the upstream when `forwardToken` is `true`. Defaults to `x-forwarded-authorization`. If this differs from `headerName`, the original header is removed and the token is forwarded under this name instead. By default the full header value (including the scheme prefix) is forwarded; set `forwardTokenStripScheme` to `true` to forward only the bare token value. Has no effect when `forwardToken` is `false`. |
| `forwardTokenStripScheme` | boolean | No | Controls what is forwarded under `forwardedTokenHeader` when `forwardToken` is `true`. If `true`, only the bare token value (with the scheme prefix such as `Bearer` stripped) is forwarded. If `false` (default), the full header value including the prefix is forwarded. Has no effect when `forwardToken` is `false`. |


**Note:**

Inside the `gateway/build.yaml`, ensure the policy module is added under `policies:`:

```yaml
- name: jwt-auth
  gomodule: github.com/wso2/gateway-controllers/policies/jwt-auth@v1
```


## Reference Scenarios

### Example 1: Basic JWT Authentication

```yaml
apiVersion: gateway.api-platform.wso2.com/v1
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

Requires the `test-audience` audience, all of `read:data` / `list:data`, and at least one of
`write:data` / `update:data`. (For the legacy any-one-of behavior, use `scopes.anyOf` alone, which
replaces the deprecated `requiredScopes`.)

```yaml
apiVersion: gateway.api-platform.wso2.com/v1
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
            scopes:
              allOf:
                - read:data
                - list:data
              anyOf:
                - write:data
                - update:data
```


### Example 3: Scopes and Claims, each with `allOf` + `anyOf`


```yaml
apiVersion: gateway.api-platform.wso2.com/v1
kind: RestApi
metadata:
  name: jwt-auth-scopes-claims-api
spec:
  displayName: JWT Auth Scopes And Claims API
  version: v1.0
  context: /jwt-auth-scopes-claims/$version
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
            scopes:
              allOf:
                - "api:read"
                - "api:deploy"
              anyOf:
                - "api:write"
                - "api:update"
            claims:
              allOf:
                - claim: status
                  values: ["active"]
              anyOf:
                - claim: department
                  values: ["platform", "engineering"]
```

The request is authorized only when **all** of the following hold:

```text
SCOPES = (api:read AND api:deploy)  AND  (api:write OR api:update)
CLAIMS = (status = active)          AND  (department ∈ {platform, engineering})

```



| Token scopes | `status` | `department` | Result | Reason |
| --- | --- | --- | --- | --- |
| `api:read api:deploy api:write` | `active` | `platform` | 200 | scope `allOf` + `anyOf` and claim `allOf` + `anyOf` all satisfied |
| `api:read api:deploy` | `active` | `engineering` | 401 | scope `anyOf` unmet — neither `api:write` nor `api:update` present |
| `api:read api:write` | `active` | `platform` | 401 | scope `allOf` incomplete — `api:deploy` missing |
| `api:read api:deploy api:update` | `active` | `sales` | 401 | claim `anyOf` unmet — `department` not in `{platform, engineering}` |
| `api:read api:deploy api:update` | `suspended` | `platform` | 401 | claim `allOf` unmet — `status` is not `active` |



**Precedence and deprecation:** New `scopes`/`claims` parameters take precedence over deprecated counterparts; legacy params remain supported with deprecation warnings. Also any malformed `scopes` or `claims` value will be rejected.

### Example 4: Claim Mapping to Downstream Headers

```yaml
apiVersion: gateway.api-platform.wso2.com/v1
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

### Example 5: Custom Token Header

```yaml
apiVersion: gateway.api-platform.wso2.com/v1
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

### Example 6: Custom User ID Claim for Analytics

```yaml
apiVersion: gateway.api-platform.wso2.com/v1
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

### Example 7: Strip JWT Before Forwarding to Upstream

By default, the JWT is forwarded to the upstream after successful validation under the `x-forwarded-authorization` header. Set `forwardToken: false` to strip it before proxying.

```yaml
apiVersion: gateway.api-platform.wso2.com/v1
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

### Example 8: Forward JWT Under a Custom Header

When `forwardToken` is `true` (the default), the validated JWT is forwarded to the upstream under the header named by `forwardedTokenHeader` (default `x-forwarded-authorization`). Use this to preserve the incoming `Authorization` header for other purposes, or to hand the token to a backend that expects a specific header name.

```yaml
apiVersion: gateway.api-platform.wso2.com/v1
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

### Example 9: Forward the Token Value Without the Scheme Prefix

Some upstreams expect the raw token value without the `Bearer` (or other) scheme prefix. Set `forwardTokenStripScheme: true` to forward the bare token under `forwardedTokenHeader` instead of the full header value. For example, an incoming `Authorization: Bearer eyJ...` results in the upstream receiving `X-JWT-Token: eyJ...`.

```yaml
apiVersion: gateway.api-platform.wso2.com/v1
kind: RestApi
metadata:
  name: jwt-auth-token-value-api
spec:
  displayName: JWT Auth Token Value API
  version: v1.0
  context: /jwt-auth-token-value/$version
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
            forwardTokenStripScheme: true
            forwardedTokenHeader: X-JWT-Token
```

### Example 10: Disable Token Verification Caching

Token verification caching is enabled by default. To force full re-verification on every request — for example while debugging, or when tokens must be checked against live revocation state on every call — disable it at the system level.

```toml
[policy_configurations.jwtauth_v1]
tokencaching = false
```
