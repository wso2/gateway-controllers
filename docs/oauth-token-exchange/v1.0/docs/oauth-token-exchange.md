# OAuth Token Exchange

Exchanges the caller's inbound credential for a backend-specific token issued by an external OAuth2 authorization server, then attaches the exchanged token to the upstream request. Implements [RFC 8693 Token Exchange](https://www.rfc-editor.org/rfc/rfc8693) (default) and [RFC 7523 JWT Bearer](https://www.rfc-editor.org/rfc/rfc7523).

Unlike [`backend-jwt`](../../backend-jwt/v1.0/docs/backend-jwt.md), which mints a new token signed by the gateway's own key, the token this policy attaches is issued by the backend's own authorization server — the backend's IdP vouches for it, not the gateway. Backend credentials are never exposed to the client, and the client's original credential never reaches the backend.

## How It Works

The exchange is attempted in the request-header phase first, so that it works correctly whether the caller's credential is present at the start of the request or only added partway through policy processing — but only a missing credential is ever worth a second attempt:

1. **Request-header phase (optimistic).** The policy reads the caller's credential from the live request state (by default, the `Authorization: Bearer <token>` header) — honoring any rewrite already made by an earlier policy in the same chain.
   - If the credential is **not yet present**, this phase defers to the request-body phase without rejecting the request, since the credential may simply not have arrived yet (e.g. an earlier body-phase auth policy hasn't forwarded it under this header yet).
   - If the credential **is present**, it calls the configured token endpoint right away. On success, the exchanged token is attached to the upstream request immediately. If that call fails, or the policy configuration itself is invalid, the request is **rejected immediately, right here** — `500` for a configuration error, a generic `502` for an exchange failure — rather than deferred: repeating the identical call or re-parsing the same configuration would not produce a different result. This rejection short-circuits the entire policy chain, so the request-body phase never runs for that request.
2. **Request-body phase (fallback for a missing credential only).** This phase only ever runs when the header phase deferred — every other outcome was already resolved or rejected there. It repeats the credential read and exchange: by now, any earlier body-phase policy in the chain has had its chance to run, so the credential may be present even though it wasn't before.
   - If still no credential is present, the request is rejected with a generic `401` — the same unified authentication-failure response used across this gateway, regardless of the reason.
   - If the token endpoint is unreachable, returns a non-2xx status, or returns a malformed response, the request is rejected with a generic `502`. **The original client credential is never forwarded upstream as a fallback.**

Both phases exchange the credential for a new token the same way:
- **TokenExchange** (default): sends the credential as `subject_token` per RFC 8693.
- **JwtBearer**: sends the credential as-is as the `assertion` per RFC 7523.

On success, the exchanged token is cached in memory for part of its reported lifetime and set on the configured upstream header (default: `Authorization: Bearer <token>`).

The outbound call to the token endpoint goes through the gateway's shared, SSRF-guarded HTTP client — the same dial-time private/loopback/link-local/metadata-address blocking, bounded redirects, and timeouts used for every other policy-initiated outbound call, not a policy-specific client.

## Configuration

### User Parameters

| Parameter | Type | Default | Description |
|---|---|---|---|
| `tokenEndpoint` | string | — | Absolute URL of the OAuth2 token endpoint. Must be `https://` unless the system `allowInsecureTokenEndpoint` override is enabled. |
| `grantType` | string | `TokenExchange` | `TokenExchange` (RFC 8693) or `JwtBearer` (RFC 7523). |
| `clientId` | string | — | OAuth2 client identifier used to authenticate to the token endpoint. |
| `clientSecret` | string | — | OAuth2 client secret paired with `clientId`. |
| `clientAuthMethod` | string | `ClientSecretBasic` | `ClientSecretBasic` (HTTP Basic auth) or `ClientSecretPost` (form fields). |
| `subjectTokenSource` | object | `{type: header, name: Authorization, prefix: "Bearer "}` | Where to read the caller's credential from — `header`, `cookie`, or `queryParameter`. |
| `subjectTokenType` | string | `AccessToken` | Type of the inbound credential: `AccessToken`, `Jwt`, or `IdToken`. |
| `requestedTokenType` | string | _(unset)_ | Requested type of the issued token. `TokenExchange` only. |
| `audiences` | string[] | `[]` | Sent as repeated `audience` parameters. |
| `scopes` | string[] | `[]` | Space-joined into the `scope` parameter. |
| `resources` | string[] | `[]` | RFC 8707 resource indicators, sent as repeated `resource` parameters. |
| `header` | string | `Authorization` | Upstream header to set the exchanged token on. |
| `headerPrefix` | string | `Bearer ` | Prefix prepended to the exchanged token. Set to `""` for none. |
| `tokenCaching` | boolean | `true` | Cache exchanged tokens in memory to avoid a token-endpoint call on every request. |

### System Parameters

| Parameter | Type | Default | Description |
|---|---|---|---|
| `cacheMaxSize` | integer | `100000` | Maximum total exchanged tokens cached across all APIs (a single global bound). |
| `requestTimeout` | string | `5s` | Timeout for the outbound call to the token endpoint. |
| `maxResponseBytes` | integer | `65536` | Maximum bytes read from the token endpoint's response before rejection. |
| `allowInsecureTokenEndpoint` | boolean | `false` | Off-by-default opt-in allowing `tokenEndpoint` to use `http://`. Intended for local/dev testing only. |

## Token Caching

Exchanged tokens are cached for half their reported `expires_in` lifetime (minimum 30 seconds, never reaching or exceeding the token's real expiry). The cache key is a digest of the API, token endpoint, client ID, grant type, audiences, scopes, resources, and the caller's own credential — so requests from the same caller against the same configuration reuse the cached token, while a change to any of those inputs (including the caller's credential changing) produces a fresh exchange.

## Example

```yaml
policies:
  - name: oauth-token-exchange
    parameters:
      tokenEndpoint: https://auth.backend.example.com/oauth2/token
      grantType: TokenExchange
      clientId: gateway-exchange-client
      clientSecret: "***"
      audiences:
        - backend-api
      scopes:
        - read:orders
      header: Authorization
```

The upstream service then receives `Authorization: Bearer <token issued by auth.backend.example.com>` — never the client's original credential.

## Related Policies

- [`jwt-auth`](../../jwt-auth/v1.3/docs/jwt-authentication.md), [`basic-auth`](../../basic-auth/v1.0/docs/basic-auth.md), [`api-key-auth`](../../api-key-auth/v1.2/docs/apikey-authentication.md) — authenticate the inbound client request; this policy reads the resulting credential directly from the request, not from their `AuthContext` output.
- [`backend-jwt`](../../backend-jwt/v1.0/docs/backend-jwt.md) — mints a new, gateway-signed JWT from `AuthContext` instead of exchanging with an external authorization server. Use `backend-jwt` when the backend should trust the gateway's own key; use `oauth-token-exchange` when the backend should trust its own authorization server.
