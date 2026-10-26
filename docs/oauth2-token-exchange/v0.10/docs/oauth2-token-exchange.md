# OAuth2 Token Exchange

Exchanges your API caller's inbound credential (e.g. an access token or JWT) for a different token issued by your backend's own OAuth2 authorization server, then attaches the exchanged token to the request before it reaches your backend. Implements [RFC 8693 Token Exchange](https://www.rfc-editor.org/rfc/rfc8693) (default) and [RFC 7523 JWT Bearer](https://www.rfc-editor.org/rfc/rfc7523).

Use this policy when your backend expects a token issued by its own identity provider, rather than the token your API clients authenticate with. Unlike [`backend-jwt`](../../backend-jwt/v1.0/docs/backend-jwt.md), which mints a gateway-signed token, the token this policy attaches is issued by your backend's authorization server itself — your backend's IdP vouches for it, not the gateway. Your backend's own client credentials stay in the gateway configuration and are never exposed to the API caller, and the caller's original credential never reaches your backend — unless `subjectTokenSource.forwardToken` is enabled.

## How It Works

1. The policy reads the caller's credential from the incoming request (by default, the `Authorization: Bearer <token>` header — configurable via `subjectTokenSource`).
2. It exchanges that credential for a new token by calling the `tokenEndpoint` you configure:
   - **TokenExchange** (default): sends the credential as `subject_token`, per RFC 8693.
   - **JwtBearer**: sends the credential as-is as the `assertion`, per RFC 7523.
3. On success, the exchanged token is attached to the request on the configured upstream `header` (default: `Authorization: Bearer <token>`) and cached in memory so the same caller doesn't trigger a new exchange on every request (see [Token Caching](#token-caching)). By default, the caller's original credential is also stripped from wherever it was read — the header, cookie, or query parameter named by `subjectTokenSource` — before the request goes upstream. Set `subjectTokenSource.forwardToken: true` to leave it in place instead.

If the caller doesn't present a credential, the request is rejected with a generic `401 Unauthorized`. If the token endpoint is unreachable, returns an error, or returns a malformed response, the request is rejected with a generic `502 Bad Gateway`. In both cases, the caller's original credential is never forwarded to your backend as a fallback — a failed exchange always fails the request rather than silently degrading security.

## Configuration

### User Parameters

| Parameter | Type | Default | Description |
|---|---|---|---|
| `tokenEndpoint` | string | — | Absolute URL of the OAuth2 token endpoint. Must be `https://` unless the system `allowInsecureTokenEndpoint` override is enabled. |
| `grantType` | string | `TokenExchange` | `TokenExchange` (RFC 8693) or `JwtBearer` (RFC 7523). |
| `clientId` | string | — | OAuth2 client identifier used to authenticate to the token endpoint. |
| `clientSecret` | string | — | OAuth2 client secret paired with `clientId`. |
| `clientAuthMethod` | string | `ClientSecretBasic` | `ClientSecretBasic` (HTTP Basic auth) or `ClientSecretPost` (form fields). |
| `subjectTokenSource` | object | `{type: header, name: Authorization, prefix: "Bearer ", forwardToken: false}` | Where to read the caller's credential from — `header`, `cookie`, or `queryParameter`. `forwardToken: false` (default) strips it from the request after it's read; set to `true` to also leave it in place. |
| `subjectTokenType` | string | `AccessToken` | Type of the inbound credential: `AccessToken`, `Jwt`, or `IdToken`. |
| `requestedTokenType` | string | _(unset)_ | Requested type of the issued token. `TokenExchange` only. |
| `audiences` | string[] | `[]` | Sent as repeated `audience` parameters. |
| `scopes` | string[] | `[]` | Space-joined into the `scope` parameter. |
| `resources` | string[] | `[]` | RFC 8707 resource indicators, sent as repeated `resource` parameters. |
| `header` | string | `Authorization` | Upstream header to set the exchanged token on. |
| `headerPrefix` | string | `"Bearer "` | Prefix prepended to the exchanged token. Set to `""` for none. |
| `tokenCaching` | boolean | `true` | Cache exchanged tokens in memory to avoid a token-endpoint call on every request. |

### System Parameters

| Parameter | Type | Default | Description |
|---|---|---|---|
| `cacheMaxSize` | integer | `100000` | Maximum total exchanged tokens cached across all APIs (a single global bound). |
| `requestTimeout` | string | `5s` | Timeout for the outbound call to the token endpoint. |
| `maxResponseBytes` | integer | `65536` | Maximum bytes read from the token endpoint's response before rejection. |
| `allowInsecureTokenEndpoint` | boolean | `false` | Off-by-default opt-in allowing `tokenEndpoint` to use `http://`. Intended for local/dev testing only. |

## Token Caching

When `tokenCaching` is enabled (the default), exchanged tokens are cached in memory for part of their reported lifetime (minimum 30 seconds, never reaching or exceeding the token's real expiry). Repeated requests from the same caller, against the same policy configuration, reuse the cached token instead of calling the token endpoint again — this is what makes token exchange practical under real traffic. If the caller's credential or any of your configured parameters (audiences, scopes, resources, etc.) changes, a fresh token is exchanged automatically.

## Example

```yaml
policies:
  - name: oauth2-token-exchange
    version: v0
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

The upstream service then receives `Authorization: Bearer <token issued by auth.backend.example.com>` — never the client's original credential, unless `subjectTokenSource.forwardToken` is enabled.

## Fault reporting

From v0.10, every rejection this policy makes is also reported to the gateway as a **fault**: a
stable code and type alongside the response. A gateway that supports fault policies uses it for
the analytics event and hands it to the API's fault policies (for example `log-message`, to log
the failure). On a REST, MCP or LLM API the status and body the client receives are the same as in
v0.9; on an Agent (A2A) API, a JSON-RPC caller receives the failure as a JSON-RPC error envelope.
A gateway without fault policy support ignores the fault, and the policy behaves exactly as v0.9.

| When | Status | Code | Type |
|------|--------|------|------|
| The policy configuration cannot be parsed | `500` | `960000` | `configuration` |
| The subject token is missing when the request body phase runs | `401` | `900902` | `authentication` |
| The token exchange fails: the token endpoint is unreachable, returns a non-2xx status, or returns no usable token | `502` | `960000` | `mediation` |

The fault's `Description` carries the internal reason, for example
`invalid policy configuration: <error>`. For a failed exchange it carries only the tracking ID,
`token exchange failed, tracking_id <id>`, which matches the body and the gateway log line holding
the token endpoint's error. It is passed to fault policies and analytics only, never to the
client.
