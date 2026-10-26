---
title: "Overview"
---
# MCP Authentication

## Overview

The MCP Authentication policy is designed to secure traffic to Model Context Protocol (MCP) servers. The Gateway acts as a resource server, protecting MCP resources by validating access tokens presented in requests. This policy leverages the underlying JWT Authentication mechanism for token validation and additionally handles MCP-specific requirements such as serving protected resource metadata. This policy supports the auth requirements mentioned in the [MCP Specification](https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization#introduction).

## Features

- Identifies the MCP operation from the mirrored headers on MCP 2026-07-28 and from the request
  body on earlier revisions, so one proxy serves both eras.

- **Access Token Validation**: Validates JWT access tokens using configured key managers. Please refer to the [JWT Authentication Policy](../../../jwt-auth/v1.3/docs/jwt-authentication.md) for more information on how the key validation works.
- **Resource-Specific Security**: Configure authentication independently for tools, resources, prompts, and JSON-RPC methods.
- **Exception Lists**: Exclude specific resources from authentication using exception lists.
- **Protected Resource Metadata**: Intercepts `GET /.well-known/oauth-protected-resource` requests to return resource metadata, including authorization servers and supported scopes.
- **Standardized Error Handling**: Returns `WWW-Authenticate` headers with `resource_metadata` on authentication failures.
- **Claim Mapping**: Maps token claims to downstream headers for use by backend services.
- **Configurable User ID Claim**: Choose which claim identifies the user in analytics.
- **Controlled Token Forwarding**: The client credential is withheld from the MCP server by default, and can optionally be forwarded under a dedicated header.
- **Header Ownership Awareness**: Reads the token from the original client request and yields the inbound token header to a peer policy (such as `set-headers`) that has set it.
- **Configurable Issuers**: Specify which key managers to use for token validation and metadata publication.


## How a request is identified

Every authentication decision starts from two facts: the JSON-RPC **method**, and the **capability
name** it targets (`params.name`, or `params.uri` for `resources/read`). Those are what the
`tools` / `resources` / `prompts` / `methods` exception lists are matched against.

Where they come from depends on the request and on the gateway:

| Request | Source | Needs a resolver? |
|---|---|---|
| Declares `MCP-Protocol-Version: 2026-07-28` or later, on a gateway with an MCP operation resolver | the mirrored `Mcp-Method` and `Mcp-Name` headers | yes |
| Declares an earlier version, or none, on a gateway with an MCP operation resolver | facts the resolver published after parsing the body once for the whole policy chain | yes |
| Any version, on a gateway without one | the policy parses the request body itself | no |

You do not configure this. The gateway states which routes carry a resolver, and the policy asks for
the request body only where nothing else has already read it. A proxy deployed on an older gateway
behaves exactly as it did before this version.

**Dual-era proxies.** Because the era is a property of each request rather than of the proxy, one
proxy serves both. If you exempt the legacy handshake from authentication, exempt the modern entry
point alongside it:

```yaml
policies:
  - name: mcp-auth
    version: v1
    params:
      methods:
        enabled: true
        exceptions: ["initialize", "ping", "server/discover"]
```

**A modern request without a required mirrored header is rejected, `400`,** on a gateway with an MCP
operation resolver. MCP 2026-07-28 requires `Mcp-Method` on every request, and `Mcp-Name` on
`tools/call`, `resources/read` and `prompts/get`; a missing required header is a validation failure.
An `Mcp-Name` that will not decode counts as missing. The legacy allowance for a method-less POST
does not carry over: the one such request, a JSON-RPC response answering a server-initiated call,
does not exist in 2026-07-28, which carries that answer in an ordinary request instead.

Rejecting matters here: the exception lists say which operations skip authentication, so an empty
name would match no exception and, under `enabled: false`, exempt the call.

**A legacy request with no body is authenticated, never exempted,** because nothing named the
operation. A request whose body the gateway could not read at all is rejected outright.

⚠️ This is stricter than releases before v1.3 on one point. Previously a request whose body named no
method was matched against the `methods` list as an empty name, so on a proxy configured
`methods.enabled: false` it was forwarded without a token. Such a request is not executable by the
MCP server anyway, so nothing that worked before stops working — but the gateway now answers it
itself rather than passing it upstream.

⚠️ **On a modern request the headers are taken at face value.** This policy does not check that
`Mcp-Method` and `Mcp-Name` agree with the request body. If you need that guarantee at the gateway,
attach the **mcp-spec-validation** policy ahead of this one; without it, the MCP server is
responsible for rejecting a request whose headers and body disagree.

## Configuration

The MCP Authentication policy uses a two-level configuration model:

### System Parameters (config.toml)

Configured by the administrator in `config.toml` under `policy_configurations.mcpauth_v1` or `policy_configurations.jwtauth_v1` depending on the parameter.

| Parameter | Type | Required | Default | Path | Description |
|-----------|------|----------|---------|------|-------------|
| `keymanagers` | `KeyManager` array | Yes | - | jwtauth_v1 | List of key manager definitions. Each entry must include a unique `name` and `issuer`, and either `jwks.remote` or `jwks.local` configuration. |
| `jwkscachettl` | string | No | - | jwtauth_v1 | Duration string for JWKS caching (e.g., `"5m"`). If omitted a default is used. |
| `jwksfetchtimeout` | string | No | - | jwtauth_v1 | Timeout for HTTP fetch of JWKS (e.g., `"5s"`). |
| `jwksfetchretrycount` | integer | No | - | jwtauth_v1 | Number of retries for JWKS fetch on transient failures. |
| `jwksfetchretryinterval` | string | No | - | jwtauth_v1 | Interval between JWKS fetch retries (e.g., `"2s"`). |
| `leeway` | string | No | - | jwtauth_v1 | Clock skew allowance for `exp`/`nbf` checks (e.g., `"30s"`). |
| `authheaderscheme` | string | No | `"Bearer"` | jwtauth_v1 | Expected scheme prefix in the authorization header. |
| `headername` | string | No | `"Authorization"` | jwtauth_v1 | Header name to extract the token from. |
| `onfailurestatuscode` | integer | No | `401` | jwtauth_v1 | HTTP status code returned on authentication failure. Allowed values: `401`, `403`. |
| `errormessageformat` | string | No | `"json"` | jwtauth_v1 | Format of the error response. Allowed values: `"json"`, `"plain"`, `"minimal"`. |
| `errormessage` | string | No | - | jwtauth_v1 | Custom error message to include in the response body on authentication failure. |
| `validateissuer` | boolean | No | - | jwtauth_v1 | Whether to validate the token's issuer claim against configured key managers. |
| `gatewayhost` | string | No | `"localhost"` | mcpauth_v1 | **Deprecated — use `gatewayurl` instead.** The outward-facing gateway host name used when deriving the protected resource metadata URL and response. Ignored when `gatewayurl` is configured. |
| `gatewayurl` | string | No | - | mcpauth_v1 | Full externally-reachable base URL of the gateway (scheme + host + optional port), used verbatim for the protected resource metadata URL and response. Takes precedence over `gatewayhost`. |

#### KeyManager Configuration

Each key manager in the `keymanagers` array supports the following structure:

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `name` | string | Yes | Unique name for this key manager (used in user-level `issuers` configuration). |
| `issuer` | string | Yes | Issuer (`iss`) value associated with keys from this provider. |
| `jwks.remote.uri` | string | Conditional | JWKS endpoint URL. Required if using remote JWKS. |
| `jwks.remote.certificatePath` | string | No | Path to CA certificate file for validating self-signed JWKS endpoints. |
| `jwks.remote.skipTlsVerify` | boolean | No | If true, skip TLS certificate verification. Use with caution. |
| `jwks.local.inline` | string | Conditional | Inline PEM-encoded certificate or public key. |
| `jwks.local.certificatePath` | string | Conditional | Path to certificate or public key file. |

> **Note**: Either `jwks.remote` or `jwks.local` must be specified, but not both.

#### System Configuration Example

```toml
[policy_configurations.mcpauth_v1]
gatewayurl = "https://gw.example.com"
# gatewayhost = "gw.example.com"  # deprecated form — still works, but gatewayurl is recommended

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
errormessage = "Authentication failed."
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

These parameters are configured per-API/route by the API developer:

#### Resource Type Configuration

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `tools` | `SecurityConfig` object | No | `{"enabled": true}` | Security configuration for MCP tools. |
| `resources` | `SecurityConfig` object | No | `{"enabled": true}` | Security configuration for MCP resources. |
| `prompts` | `SecurityConfig` object | No | `{"enabled": true}` | Security configuration for MCP prompts. |
| `methods` | `SecurityConfig` object | No | `{"enabled": true}` | Security configuration for MCP (JSON-RPC) methods. |
| `issuers` | string array | No | `[]` | List of issuer names from `system.keymanagers` to publish in protected resource metadata and use for token validation. If empty, runtime uses all configured key managers. |
| `requiredScopes` | string array | No | `[]` | Scopes to advertise in protected-resource metadata for the MCP authorization flow. They are **not enforced** by this policy; use the MCP Authorization policy to enforce scopes. |
| `claimMappings` | object | No | `{}` | Map of claimName → downstream header or context key to expose claims for downstream services. |
| `userIdClaim` | string | No | `"sub"` | Claim name used to extract the user ID for analytics. |
| `forwardToken` | boolean | No | `false` | If `true`, the validated token is forwarded to the upstream under `forwardedTokenHeader`. If `false` (default), the token is not forwarded at all and the MCP server never sees the client credential. See [Token Forwarding](#token-forwarding). |
| `forwardedTokenHeader` | string | No | `"x-forwarded-authorization"` | Header name used to forward the token to the upstream when `forwardToken` is `true`. Has no effect when `forwardToken` is `false`. |
| `forwardTokenStripScheme` | boolean | No | `false` | If `true`, only the bare token value is forwarded under `forwardedTokenHeader` (the `Bearer` prefix is stripped). If `false` (default), the full header value is forwarded. Has no effect when `forwardToken` is `false`. |

#### SecurityConfig Object

Each resource type configuration supports the following structure:

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `enabled` | boolean | No | `true` | Whether security is enabled for this resource type. |
| `exceptions` | string array | No | `[]` | List of resource names to exclude from security checks. |

> **Note on `exceptions`**: The list inverts the `enabled` decision for the named items. When `enabled: true`, the listed items skip authentication. When `enabled: false`, only the listed items require authentication.

**Note:**

Inside the `gateway/build.yaml`, ensure the policy module is added under `policies:`:

```yaml
- name: mcp-auth
  gomodule: github.com/wso2/gateway-controllers/policies/mcp-auth@v1
```

#### Token Forwarding

MCP servers are frequently third-party processes, so this policy does **not** release the client credential upstream unless you ask it to. This is the one behavioural difference from the [JWT Authentication Policy](../../../jwt-auth/v1.3/docs/jwt-authentication.md), where `forwardToken` defaults to `true`.

| `forwardToken` | What the upstream receives |
|----------------|----------------------------|
| `false` (default) | Nothing. The inbound token header (`system.headername`, default `Authorization`) is removed before the request is proxied. |
| `true` | The token under `forwardedTokenHeader` (default `x-forwarded-authorization`). The inbound token header is still removed unless `forwardedTokenHeader` names that same header. |

`forwardTokenStripScheme` controls the shape of the forwarded value: `false` (default) forwards `Bearer eyJ...`, `true` forwards `eyJ...`.

If a peer policy such as [Set Headers](../../../set-headers/v1.1/docs/set-headers.md) sets the inbound token header to a value other than the one the client sent, that policy is treated as the **owner** of the header, and this policy preserves its value instead of removing it. A warn log will appear in such scenarios hence using a dedicated header such as the default `x-forwarded-authorization` would be preferred.

## Reference Scenarios

### Example 1: Basic MCP Authentication

Apply MCP authentication to an API using a specific key manager:

```yaml
apiVersion: gateway.api-platform.wso2.com/v1
kind: Mcp
metadata:
    name: mcp-server-api-v1.0
spec:
  displayName: mcp-server-api
  version: v1.0
  context: /mcpserver
  vhost: mcp1.gw.example.com
  upstream:
    url: https://mcp-backend:8080
  policies:
    - name: mcp-auth
      version: v1
      params:
        issuers:
          - PrimaryIDP
  tools:
    ...
```

### Example 2: Disable Security for Specific Tools

Disable authentication for specific tools while keeping it enabled for others:

```yaml
apiVersion: gateway.api-platform.wso2.com/v1
kind: Mcp
metadata:
    name: mcp-server-api-v1.0
spec:
  displayName: mcp-server-api
  version: v1.0
  context: /mcpserver
  vhost: mcp1.gw.example.com
  upstream:
    url: https://mcp-backend:8080
  policies:
    - name: mcp-auth
      version: v1
      params:
        issuers:
          - PrimaryIDP
        tools:
          enabled: true
          exceptions:
            - health_check
            - list_public_resources
        resources:
          enabled: true
        prompts:
          enabled: true
        methods:
          enabled: true
  tools:
    ...
```

### Example 3: Scope Advertisement in Protected Resource Metadata

Advertise required scopes in the protected resource metadata (scopes are not enforced by this policy):

```yaml
apiVersion: gateway.api-platform.wso2.com/v1
kind: Mcp
metadata:
    name: mcp-server-api-v1.0
spec:
  displayName: mcp-server-api
  version: v1.0
  context: /mcpserver
  vhost: mcp1.gw.example.com
  upstream:
    url: https://mcp-backend:8080
  policies:
    - name: mcp-auth
      version: v1
      params:
        issuers:
          - PrimaryIDP
        requiredScopes:
          - mcp:read
          - mcp:write
  tools:
    ...
```

### Example 4: Claim Mapping for Downstream Services

Map JWT claims to downstream headers for use by backend services:

```yaml
apiVersion: gateway.api-platform.wso2.com/v1
kind: Mcp
metadata:
    name: mcp-server-api-v1.0
spec:
  displayName: mcp-server-api
  version: v1.0
  context: /mcpserver
  vhost: mcp1.gw.example.com
  upstream:
    url: https://mcp-backend:8080
  policies:
    - name: mcp-auth
      version: v1
      params:
        issuers:
          - PrimaryIDP
        claimMappings:
          sub: x-user-id
          email: x-user-email
          department: x-user-department
  tools:
    ...
```

### Example 5: Disable Authentication for Resources

Completely disable authentication for MCP resources while keeping it for tools:

```yaml
apiVersion: gateway.api-platform.wso2.com/v1
kind: Mcp
metadata:
    name: mcp-server-api-v1.0
spec:
  displayName: mcp-server-api
  version: v1.0
  context: /mcpserver
  vhost: mcp1.gw.example.com
  upstream:
    url: https://mcp-backend:8080
  policies:
    - name: mcp-auth
      version: v1
      params:
        issuers:
          - PrimaryIDP
        tools:
          enabled: true
        resources:
          enabled: false
        prompts:
          enabled: true
        methods:
          enabled: true
  tools:
    ...
```

### Example 6: Selecting the Analytics User ID Claim

By default the user ID published to analytics is taken from the `sub` claim. Point `userIdClaim` at a different claim when your identity provider carries the meaningful identifier elsewhere:

```yaml
apiVersion: gateway.api-platform.wso2.com/v1
kind: Mcp
metadata:
    name: mcp-server-api-v1.0
spec:
  displayName: mcp-server-api
  version: v1.0
  context: /mcpserver
  vhost: mcp1.gw.example.com
  upstream:
    url: https://mcp-backend:8080
  policies:
    - name: mcp-auth
      version: v1
      params:
        issuers:
          - PrimaryIDP
        userIdClaim: username
  tools:
    ...
```

### Example 7: Forwarding the Validated Token to the MCP Server

Forward the token under a dedicated header so the MCP server can identify the caller, while the inbound `Authorization` header is still stripped:

```yaml
apiVersion: gateway.api-platform.wso2.com/v1
kind: Mcp
metadata:
    name: mcp-server-api-v1.0
spec:
  displayName: mcp-server-api
  version: v1.0
  context: /mcpserver
  vhost: mcp1.gw.example.com
  upstream:
    url: https://mcp-backend:8080
  policies:
    - name: mcp-auth
      version: v1
      params:
        issuers:
          - PrimaryIDP
        forwardToken: true
        forwardedTokenHeader: X-Backend-Authorization
  tools:
    ...
```

The MCP server receives `X-Backend-Authorization: Bearer eyJ...`.

### Example 8: Forwarding the Bare Token Value

Some MCP servers expect the raw token without the `Bearer` prefix:

```yaml
apiVersion: gateway.api-platform.wso2.com/v1
kind: Mcp
metadata:
    name: mcp-server-api-v1.0
spec:
  displayName: mcp-server-api
  version: v1.0
  context: /mcpserver
  vhost: mcp1.gw.example.com
  upstream:
    url: https://mcp-backend:8080
  policies:
    - name: mcp-auth
      version: v1
      params:
        issuers:
          - PrimaryIDP
        forwardToken: true
        forwardTokenStripScheme: true
        forwardedTokenHeader: X-MCP-Token
  tools:
    ...
```

The MCP server receives `X-MCP-Token: eyJ...`.

### Example 9: Replacing the Upstream Credential with `set-headers`

A common pattern is to authenticate the client with its own token and hand the MCP server a completely different credential. Because `set-headers` owns `Authorization` once it writes to it, this policy leaves that value alone:

```yaml
apiVersion: gateway.api-platform.wso2.com/v1
kind: Mcp
metadata:
    name: mcp-server-api-v1.0
spec:
  displayName: mcp-server-api
  version: v1.0
  context: /mcpserver
  vhost: mcp1.gw.example.com
  upstream:
    url: https://mcp-backend:8080
  policies:
    - name: mcp-auth
      version: v1
      params:
        issuers:
          - PrimaryIDP
    - name: set-headers
      version: v1
      params:
        request:
          headers:
            - name: Authorization
              value: Bearer <mcp-server-service-token>
  tools:
    ...
```

The client's token is validated by `mcp-auth`, and the MCP server receives the service token set by `set-headers`. This works regardless of the order the two policies appear in, because `mcp-auth` validates the token the client sent rather than the header value that reaches the upstream.

#### Error Responses

| Situation | Status | Body |
|-----------|--------|------|
| Token missing, expired, or otherwise invalid | `onfailurestatuscode` (default `401`) | Shaped by `errormessageformat`; accompanied by a `WWW-Authenticate: Bearer resource_metadata="…"` header. |
| Request body is not valid JSON, or not a valid JSON-RPC request object | `400` | A JSON-RPC 2.0 error object — code `-32700` (Parse error) for invalid JSON syntax, `-32600` (Invalid Request) otherwise. Not affected by `errormessageformat`. |
| Policy configuration is invalid (e.g. a malformed `keymanagers` entry) | `500` | JSON error object. |

## Related Policies

- [MCP Authorization Policy](../../../mcp-authz/v1.3/docs/mcp-authorization.md) - Enforces claim and scope rules on MCP tools, resources, prompts, and methods after this policy authenticates the caller
- [JWT Authentication Policy](../../../jwt-auth/v1.3/docs/jwt-authentication.md) - Base JWT token validation mechanism
