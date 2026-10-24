# Backend JWT

Generates a signed JWT containing authenticated user information and injects it into the upstream request header. Run this policy **after** an authentication policy (e.g. `jwt-auth`, `basic-auth`, `api-key-auth`) to forward a gateway-signed assertion to backend services.

Backend services can verify the generated JWT using the gateway's corresponding public key — they do not need access to the original client credential (API key, OAuth token, etc.). When the gateway has its own signing keys, backends fetch that public key from the gateway JWKS by `kid` (see [Signing Key](#signing-key)).

## How It Works

1. After an auth policy authenticates the request, the gateway's `AuthContext` is populated with the subject, auth type, issuer, audience, scopes, and any custom properties from the incoming credential.
2. The Backend JWT policy reads this context, builds a JWT with the configured claims, and signs it with the gateway's active signing key or, when the gateway has none, the policy-level RSA or ECDSA private key.
3. The signed JWT is set as the value of the configured upstream header (default: `x-jwt-assertion`).
4. The upstream service verifies the JWT using the matching public key, from the gateway JWKS or distributed out of band.

When the incoming credential is a JWT (authenticated by `jwt-auth`), all non-standard claims from the original token are automatically forwarded to the backend JWT under their original names. Standard claims (`iss`, `aud`, `sub`, etc.) are handled via their dedicated typed fields (see table below). Scopes are forwarded as a space-delimited `scope` claim. `claimMappings` and `customClaims` can add aliases or override any auto-forwarded claim.

Generated tokens are cached in memory for half their configured `tokenExpiry` (minimum 30 seconds). The cache key is derived from the authenticated client identity, the operation path and method, and the signing key, so a token signed by one key is never served after the gateway's active key changes. Only `customClaims` values resolved from `$ctx:` references are included in the key, because static claims and `claimMappings` values are constant per-operation or already captured in the identity hash. Requests from the same client hitting the same operation within the cache window receive the previously signed token, avoiding repeated cryptographic operations. Dynamic custom claims that differ between requests (e.g. `$ctx:request.header.*`) produce separate cache entries, preserving correctness.

If no authentication context is present (no auth policy in the chain), a backend JWT is still generated using the available system claims (`iss`, `iat`, `exp`). Auth-derived claims (`sub`, `auth_type`, `aud`, `credential_id`) are omitted. Static `customClaims` and request-context variables (`$ctx:request.*`, `$ctx:api.*`) still resolve normally. To enforce that authentication must have occurred before this policy runs, add an auth policy earlier in the chain.

## Claims in the Generated Token

| Claim | Source |
|---|---|
| `sub` | `AuthContext.Subject` (JWT sub, basic-auth username, API key owner) |
| `iss` | `system.issuer` parameter |
| `iat` | Current time |
| `exp` | Current time + `system.tokenExpiry` |
| `auth_type` | `AuthContext.AuthType` (e.g. `jwt`, `basic`, `apikey`) |
| `aud` | `AuthContext.Audience` (JWT auth only) |
| `credential_id` | `AuthContext.CredentialID` (OAuth client_id, API key credential) |
| `scope` | `AuthContext.Scopes` as space-delimited string (JWT auth only) |
| _all other claims_ | All non-standard claims from the incoming JWT, forwarded under their original names (JWT auth only — see below) |
| _custom_ | `customClaims` — add new claims or override any of the above |

## Signing Key

The token is signed with one of two keys:

| Gateway signing keys (`[signing]`) | Key used | JWT header |
|---|---|---|
| Configured, with an active key | The gateway's active signing key | `alg` and `kid` of that key, and `typ: JWT` |
| Not configured | The policy-level `signingKey` and `algorithm` | `alg` from `algorithm`, no `kid` |

With gateway signing keys:

- Backends verify the token from the gateway JWKS at `/.well-known/jwks`, selecting the key by the token's `kid`. Key rotation needs no backend change.
- The algorithm follows the gateway key: `RS256`, `PS256`, `ES256` or `ES384`.
- `signingKey` and `algorithm` are not required, and are ignored if set. The gateway logs a warning once per deployment when they are set, so an operator migrating to `[signing]` can remove them.
- The policy never receives the private key; it asks the gateway signing service for a signature.

Without gateway signing keys, the policy behaves exactly as in v1.0. Gateway signing keys require a gateway release newer than 1.2.0; on 1.2.0 the policy always uses the policy-level key.

```toml
# Gateway configuration: one signing key shared by every signing policy.
[signing]
jwks_cache_max_age = "5m"

[[signing.keys]]
path = "/secrets/gateway-runtime/signing/current.key"
active = true
```

## Configuration

### System Parameters

| Parameter | Type | Default | Description |
|---|---|---|---|
| `signingKey.inline` | string | — | PEM-encoded RSA or ECDSA private key (mutually exclusive with `path`). Not required when `algorithm` is `NONE` or gateway signing keys are configured. |
| `signingKey.path` | string | — | Path to a PEM private key file (mutually exclusive with `inline`). Not required when `algorithm` is `NONE` or gateway signing keys are configured. |
| `algorithm` | string | `SHA256withRSA` | Signing algorithm for the policy-level key: `SHA256withRSA` (RSA) or `ES256` (ECDSA) or `NONE` (unsigned, no key required). Ignored when gateway signing keys are configured. |
| `issuer` | string | `""` | Value of the `iss` claim in generated tokens |
| `tokenExpiry` | string | `15m` | Default token validity as a Go duration string (e.g. `"15m"`, `"1h"`). Can be overridden per-API via the user parameter of the same name. |
| `tokenCaching` | boolean | `true` | When `false`, disables token caching — every request signs a new token. Useful for debugging or when dynamic claims must reflect per-request state without a cache window. |

### User Parameters

| Parameter | Type | Default | Description |
|---|---|---|---|
| `header` | string | `x-jwt-assertion` | Upstream request header to set the generated JWT on |
| `claimMappings` | object | `{}` | Maps upstream JWT claim names to backend JWT claim names (see below) |
| `customClaims` | object | `{}` | Static or dynamic claim name→value pairs added to every generated token (see below) |
| `tokenExpiry` | string | _(system default)_ | Override the system `tokenExpiry` for this API (e.g. `"5m"`, `"1h"`). When set, takes precedence over the system-level value. |
| `dialect` | string | `""` | Namespace prefix applied to all user-configured and auto-forwarded claims. When set, auto-forwarded original-JWT claims, `claimMappings` destinations, and `customClaims` keys are all emitted as `<dialect><claimName>` (e.g. `"http://wso2.org/claims/"` turns `email` into `http://wso2.org/claims/email`). Does not affect standard claims set by the policy itself (`sub`, `iss`, `aud`, `scope`, etc.). |
| `excludedClaims` | string[] | `[]` | List of original-JWT claim names to exclude from auto-forwarding. Matched by original name before any `dialect` prefix is applied. Does not affect standard claims or explicitly configured `claimMappings`/`customClaims`. |

## Claim Mappings

`claimMappings` provides a structured way to forward upstream JWT claims into the backend JWT under a different name. The key is the backend JWT claim name to set; the value is the property key from the authenticated context (populated by `jwt-auth` from the upstream JWT's custom claims).

| `claimMappings` key | Source | Notes |
|---|---|---|
| any non-reserved name | `AuthContext.Properties[value]` | String values only |

Claims mapped to reserved names (`iss`, `sub`, `aud`, `exp`, `iat`) are skipped with a warning. Missing source properties are silently skipped. `customClaims` entries take precedence over `claimMappings` — if the same destination claim appears in both, `customClaims` wins.

```yaml
claimMappings:
  email: email           # forward AuthContext.Properties["email"] as "email"
  clientRole: role       # forward AuthContext.Properties["role"] as "clientRole"
  orgId: organization    # forward AuthContext.Properties["organization"] as "orgId"
```

## Dynamic Context Claims

`customClaims` values that start with `$ctx:` are resolved from the request context at runtime instead of being treated as static strings.

| Variable | Resolves to |
|---|---|
| `$ctx:request.path` | Request path (e.g. `/petstore/v1/pets/42`) |
| `$ctx:request.method` | HTTP method (`GET`, `POST`, …) |
| `$ctx:request.authority` | Host authority |
| `$ctx:request.scheme` | `http` or `https` |
| `$ctx:request.header.<name>` | First value of request header `<name>` (case-insensitive) |
| `$ctx:api.id` | API UUID |
| `$ctx:api.name` | API name |
| `$ctx:api.version` | API version |
| `$ctx:api.context` | API base context path |
| `$ctx:auth.subject` | Authenticated subject (same value as the `sub` claim) |
| `$ctx:auth.type` | Auth type (`jwt`, `basic`, `apikey`) |
| `$ctx:auth.credential_id` | Credential ID (OAuth client_id or API key) |
| `$ctx:auth.property.<key>` | Custom property from `AuthContext.Properties` |

Context variables that cannot be resolved (missing header, nil auth context, unknown variable name) are **silently skipped** — the claim is omitted from the token rather than causing an error or rejecting the request.

Use this to put an auth context value under a different claim name. For example, to expose the credential ID as `clientId` rather than `credential_id`:

```yaml
customClaims:
  clientId: $ctx:auth.credential_id
```

## Example

```yaml
# System-level (gateway config). signingKey and algorithm apply only when the
# gateway has no signing keys ([signing]).
system:
  signingKey:
    path: /etc/certs/backend-jwt.key
  algorithm: SHA256withRSA
  issuer: https://gateway.example.com
  tokenExpiry: 15m

# Per-route policy attachment
policies:
  - name: backend-jwt
    parameters:
      header: x-jwt-assertion
      tokenExpiry: 5m                               # override system default for this API
      claimMappings:
        email: email                                 # AuthContext.Properties["email"] → "email"
        clientRole: role                             # AuthContext.Properties["role"] → "clientRole"
      customClaims:
        env: production                              # static
        clientId: $ctx:auth.credential_id            # dynamic — credential ID
        clientName: $ctx:auth.property.client_name  # dynamic — from auth context property
        tenantId: $ctx:request.header.x-tenant-id   # dynamic — from request header
```

The upstream service then validates the `x-jwt-assertion` header using the public key matching the signing key: from the gateway JWKS (`/.well-known/jwks`) by `kid` when gateway signing keys are configured, otherwise the public key of the policy-level `signingKey`.

## Related Policies

- [`jwt-auth`](../../jwt-auth/v1.0/docs/jwt-authentication.md) — validates incoming JWTs from clients
- [`basic-auth`](../../basic-auth/) — authenticates clients with username/password; pairs well with Backend JWT to forward user identity
- [`api-key-auth`](../../api-key-auth/) — authenticates clients with API keys; pairs well with Backend JWT to forward client identity
