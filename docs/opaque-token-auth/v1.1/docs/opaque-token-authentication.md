---
title: "Overview"
---
# Opaque Token Authentication

## Overview

The Opaque Token Authentication policy validates opaque OAuth 2.0 access tokens — reference tokens that carry no inline claims — by calling an authorization server's [RFC 7662](https://www.rfc-editor.org/rfc/rfc7662.html) token introspection endpoint. The gateway forwards the bearer token to the introspection endpoint, authenticates itself, and admits the request only when the response reports `active: true`. It is typically applied to operations that require bearer token authentication before requests are forwarded upstream.

Use this policy when your authorization server issues opaque (reference) tokens. For self-contained JWT access tokens validated locally against JWKS, use the JWT Authentication policy instead.

## Features

- Validates opaque access tokens via RFC 7662 token introspection
- Supports multiple introspection providers with ordered fallback and optional token-pattern routing
- Gateway client authentication via `client_secret_basic`, `client_secret_post`, or a static bearer token
- Custom CA / skip-TLS-verify options for the introspection endpoint
- Short-lived caching of active and inactive responses, never beyond the token's `exp`
- Configurable audience, scope (OR semantics), and required-claim validation
- Authorization header scheme enforcement and clock skew tolerance
- Customizable error responses
- Optional `userIdClaim` mapping for analytics
- Optional forwarding of the token to the upstream under a configurable header name

## How it Works

1. The policy extracts the token from the configured authorization header.
2. It selects introspection providers (by the user-level `issuers` list, or all providers in order).
3. For each selected provider, it POSTs `token` (and `token_type_hint`) to the introspection endpoint as `application/x-www-form-urlencoded`, authenticating itself with the configured client credentials or bearer token, until a provider reports the token `active`.
4. Active responses are cached per-provider, keyed by a SHA-256 of the provider name and token, expiring at `min(introspectionCacheTtl, token exp)`. Inactive (`active: false`) responses are cached separately for `introspectionNegativeCacheTtl`. Transport errors and non-200 responses are never cached.
5. The policy then enforces audiences, scopes, and required claims, and populates the authentication context before forwarding upstream.

## Configuration

Opaque Token Authentication requires two levels of configuration.

### System Parameters (config.toml)

| Parameter | Type | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `introspectionproviders` | ```IntrospectionProvider``` array | Yes | - | List of introspection endpoint definitions. |
| `introspectioncachettl` | string | No | `"60s"` | Cache TTL for active introspection responses (never exceeds token `exp`). |
| `introspectionnegativecachettl` | string | No | `"30s"` | Cache TTL for inactive (`active: false`) responses. Set to `"0s"` to disable. Transport errors are never cached regardless of this setting. |
| `introspectiontimeout` | string | No | `"5s"` | Timeout for each introspection request. |
| `introspectionretrycount` | integer | No | `2` | Introspection retry count on transient failures. |
| `introspectionretryinterval` | string | No | `"1s"` | Interval between introspection retries. |
| `leeway` | string | No | `"30s"` | Clock skew allowance for local exp/nbf re-checks. |
| `authheaderscheme` | string | No | `"Bearer"` | Expected authorization scheme prefix. |
| `headername` | string | No | `"Authorization"` | Header name to extract the token from. |
| `onfailurestatuscode` | integer | No | `401` | HTTP status code on authentication failure. Must be `401` or `403`. |
| `errormessageformat` | string | No | `"json"` | Error format: `"json"`, `"plain"`, or `"minimal"`. |
| `errormessage` | string | No | `"Authentication failed"` | Error message body for failures. |

#### IntrospectionProvider Configuration

Each entry in `introspectionproviders` must include a unique `name` and an `introspection` configuration whose `uri` is required.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `name` | string | Yes | Unique provider name (referenced by `user.issuers`). |
| `issuer` | string | No | Optional issuer value for this provider (also matchable via `user.issuers`). |
| `tokenPattern` | string | No | Regex matched against the raw token. When set, only tokens matching the pattern are sent to this provider. See [Token Pattern Routing](#token-pattern-routing). |
| `introspection.uri` | string | Yes | RFC 7662 introspection endpoint URL. |
| `introspection.clientId` | string | No | OAuth2 client id for gateway client authentication. Mutually exclusive with `bearerToken`. |
| `introspection.clientSecret` | string | No | OAuth2 client secret paired with `clientId`. |
| `introspection.authStyle` | string | No | `"basic"` (client_secret_basic, default) or `"post"` (client_secret_post). |
| `introspection.bearerToken` | string | No | Static bearer token used instead of client credentials. Mutually exclusive with `clientId`. |
| `introspection.tokenTypeHint` | string | No | `token_type_hint` sent with the request (default `access_token`). |
| `introspection.certificatePath` | string | No | CA cert path for a self-signed introspection endpoint. |
| `introspection.skipTlsVerify` | boolean | No | Skip TLS verification (use with caution). |

#### Sample System Configuration

```toml
[policy_configurations.opaquetokenauth_v1]
introspectioncachettl = "60s"
introspectiontimeout = "5s"
introspectionretrycount = 2
introspectionretryinterval = "1s"
leeway = "30s"
authheaderscheme = "Bearer"
headername = "Authorization"
onfailurestatuscode = 401
errormessageformat = "json"
errormessage = "Authentication failed"

[[policy_configurations.opaquetokenauth_v1.introspectionproviders]]
name = "PrimaryIDP"
issuer = "https://idp.example.com/oauth2/token"

[policy_configurations.opaquetokenauth_v1.introspectionproviders.introspection]
uri = "https://idp.example.com/oauth2/introspect"
clientId = "gateway-client"
clientSecret = "gateway-secret"
authStyle = "basic"
tokenTypeHint = "access_token"
skipTlsVerify = false
```

### User Parameters (API Definition)

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `issuers` | array | No | List of provider names (or issuer values) to use. If omitted, providers are tried in order until one reports the token active. |
| `audiences` | array | No | Acceptable audience values. The token must contain at least one of the listed values in its `aud` claim. |
| `requiredScopes` | array | No | Required scopes (OR semantics — the token must contain at least one). Checked against the space-delimited `scope` member or array `scp` member. |
| `requiredClaims` | object | No | Map of claim name to expected value. All entries must match (AND semantics). |
| `authHeaderPrefix` | string | No | Overrides `system.authHeaderScheme` for this route only. |
| `headerName` | string | No | Header name to extract the token from. Overrides `system.headerName`. Must be a valid HTTP header field name. |
| `userIdClaim` | string | No | Introspection response member to use as the user ID for analytics. Defaults to `sub`. |
| `forwardToken` | boolean | No | If `true` (default), the token is forwarded to the upstream. If `false`, the authorization header is stripped before proxying. |
| `forwardedTokenHeader` | string | No | Header name under which the token is forwarded when `forwardToken` is `true`. Defaults to `x-forwarded-authorization`. By default, the original `Authorization` header is removed and the full header value (e.g. `Bearer <token>`) is re-sent under `x-forwarded-authorization`. Has no effect when `forwardToken` is `false`. |

**Note:**

Inside the `gateway/build.yaml`, ensure the policy module is added under `policies:`:

```yaml
- name: opaque-token-auth
  gomodule: github.com/wso2/gateway-controllers/policies/opaque-token-auth@v1
```

## Reference Scenarios

### Example 1: Basic Opaque Token Authentication

```yaml
apiVersion: gateway.api-platform.wso2.com/v1
kind: RestApi
metadata:
  name: opaque-token-basic-api
spec:
  displayName: Opaque Token Basic API
  version: v1.0
  context: /opaque-basic/$version
  upstream:
    main:
      url: http://sample-backend:9080/api/v1
  operations:
    - method: GET
      path: /health
    - method: GET
      path: /protected
      policies:
        - name: opaque-token-auth
          version: v1
          params:
            issuers:
              - PrimaryIDP
```

### Example 2: Audience and Scope Validation

```yaml
apiVersion: gateway.api-platform.wso2.com/v1
kind: RestApi
metadata:
  name: opaque-token-audience-api
spec:
  displayName: Opaque Token Audience API
  version: v1.0
  context: /opaque-audience/$version
  upstream:
    main:
      url: http://sample-backend:9080/api/v1
  operations:
    - method: GET
      path: /protected
      policies:
        - name: opaque-token-auth
          version: v1
          params:
            issuers:
              - PrimaryIDP
            audiences:
              - "test-audience"
            requiredScopes:
              - read:data
```

### Example 3: Required Claim Validation

```yaml
apiVersion: gateway.api-platform.wso2.com/v1
kind: RestApi
metadata:
  name: opaque-token-claims-api
spec:
  displayName: Opaque Token Claims API
  version: v1.0
  context: /opaque-claims/$version
  upstream:
    main:
      url: http://sample-backend:9080/api/v1
  operations:
    - method: GET
      path: /profile
      policies:
        - name: opaque-token-auth
          version: v1
          params:
            issuers:
              - PrimaryIDP
            requiredClaims:
              tenant: acme-corp
```

### Example 4: Strip Token Before Forwarding to Upstream

By default, the token is forwarded to the upstream after successful validation under the `x-forwarded-authorization` header. Set `forwardToken: false` to strip it before proxying.

```yaml
apiVersion: gateway.api-platform.wso2.com/v1
kind: RestApi
metadata:
  name: opaque-token-strip-api
spec:
  displayName: Opaque Token Strip API
  version: v1.0
  context: /opaque-strip/$version
  upstream:
    main:
      url: http://sample-backend:9080/api/v1
  operations:
    - method: GET
      path: /protected
      policies:
        - name: opaque-token-auth
          version: v1
          params:
            issuers:
              - PrimaryIDP
            forwardToken: false
```

## Token Pattern Routing

When multiple introspection providers are configured, the gateway tries them in order by default. Setting `tokenPattern` on a provider restricts it to tokens whose raw value matches the regex, so each provider only receives the tokens it can validate.

This is recommended whenever providers issue tokens with distinguishable formats (for example, a UUID-prefixed token for one IdP and an `opaque_` prefixed token for another). It improves performance by avoiding unnecessary introspection calls and improves cache efficiency by ensuring tokens are always routed to the same provider, producing stable per-provider cache keys.

```toml
[[policy_configurations.opaquetokenauth_v1.introspectionproviders]]
name = "AsgardeoIDP"
tokenPattern = "^[0-9a-f]{8}-"   # UUID-like prefix

[policy_configurations.opaquetokenauth_v1.introspectionproviders.introspection]
uri = "https://asgardeo.example.com/oauth2/introspect"
clientId = "gateway-client"
clientSecret = "gateway-secret"

[[policy_configurations.opaquetokenauth_v1.introspectionproviders]]
name = "LocalIDP"
tokenPattern = "^opaque_"         # local token format

[policy_configurations.opaquetokenauth_v1.introspectionproviders.introspection]
uri = "https://idp.internal/oauth2/introspect"
bearerToken = "introspect-secret"
```

Providers without a `tokenPattern` match all tokens and act as a fallback for any token that does not match a pattern-restricted provider.

## Notes

- **Transport security:** Always use HTTPS introspection endpoints. RFC 7662 mandates TLS for the introspection request; `skipTlsVerify` should only be used for testing or trusted internal endpoints.
- **Caching vs. revocation latency:** A longer `introspectionCacheTtl` reduces load on the authorization server but increases the window during which a revoked token is still accepted. Cached entries never outlive the token's `exp`. Tune the TTL to your revocation requirements.
- **Negative caching:** By default, inactive (`active: false`) responses are cached for `introspectionNegativeCacheTtl` (`"30s"`). This reduces load for repeated requests with invalid tokens. Set to `"0s"` to disable if your use case requires re-checking every request.
- **Provider fallback:** When no `issuers` are configured, every provider is tried in order until one reports the token active. Constrain this with `issuers` (or per-provider `issuer` values) to avoid presenting tokens to unintended authorization servers.

## Related Policies

- **JWT Authentication** — validates self-contained JWT access tokens locally via JWKS providers.
