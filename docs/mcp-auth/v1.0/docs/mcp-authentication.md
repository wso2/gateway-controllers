---
title: "Overview"
---
# MCP Authentication

## Overview

The MCP Authentication policy is designed to secure traffic to Model Context Protocol (MCP) servers. The Gateway acts as a resource server, protecting MCP resources by validating access tokens presented in requests. This policy leverages the underlying JWT Authentication mechanism for token validation and additionally handles MCP-specific requirements such as serving protected resource metadata. This policy supports the auth requirements mentioned in the [MCP Specification](https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization#introduction).

## Features

- **Access Token Validation**: Validates JWT access tokens using configured key managers. Please refer to the [JWT Authentication Policy](../../../jwt-auth/v1.0/docs/jwt-authentication.md) for more information on how the key validation works.
- **Resource-Specific Security**: Configure authentication independently for tools, resources, prompts, and JSON-RPC methods.
- **Exception Lists**: Exclude specific resources from authentication using exception lists.
- **Full Endpoint Coverage**: Validates tokens on every generated MCP endpoint — `POST /mcp` (JSON-RPC), `GET /mcp` (server-to-client SSE stream) and `DELETE /mcp` (session termination).
- **Protected Resource Metadata**: Intercepts `GET /.well-known/oauth-protected-resource` requests to return resource metadata, including authorization servers and supported scopes.
- **Standardized Error Handling**: Returns `WWW-Authenticate` headers with `resource_metadata` on authentication failures.
- **Claim Mapping**: Maps token claims to downstream headers for use by backend services.
- **Configurable Issuers**: Specify which key managers to use for token validation and metadata publication.

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
| `gatewayhost` | string | No | `"localhost"` | mcpauth_v1 | The outward-facing gateway host name used when deriving the protected resource metadata URL and response. |

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
gatewayhost = "gw.example.com"

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
| `requiredScopes` | string array | No | `[]` | List of scopes that should be included in the token generated through MCP auth flow. These are advertised in the protected resource metadata but **not enforced** by this policy. Use the MCP Authorization policy to enforce scopes. If empty, `scopes_supported` is omitted from the metadata document (it is OPTIONAL per RFC 9728). |
| `claimMappings` | object | No | `{}` | Map of claimName → downstream header or context key to expose claims for downstream services. |

#### SecurityConfig Object

Each resource type configuration supports the following structure:

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `enabled` | boolean | No | `true` | Whether security is enabled for this resource type. |
| `exceptions` | string array | No | `[]` | List of resource names to exclude from security checks. |

#### Endpoint Coverage

An MCP API exposes three endpoints on `/mcp`. Only `POST /mcp` carries a JSON-RPC payload, so only that request can be matched against the `tools`, `resources`, `prompts` and `methods` configuration above.

`GET /mcp` (server-to-client SSE stream) and `DELETE /mcp` (session termination) act on live session state without naming a tool, resource, prompt or method, so they cannot be matched against an exception list. The policy therefore requires a valid access token on both, unless `tools`, `resources`, `prompts` and `methods` are all disabled with no exceptions — an MCP server that is public by configuration, where no request is authenticated.

CORS preflights (`OPTIONS /mcp`) and the protected resource metadata endpoint (`GET /.well-known/oauth-protected-resource`) are never authenticated: browsers send preflights without credentials, and the metadata endpoint must be publicly readable for MCP clients to discover the authorization server.

**Note:**

Inside the `gateway/build.yaml`, ensure the policy module is added under `policies:`:

```yaml
- name: mcp-auth
  gomodule: github.com/wso2/gateway-controllers/policies/mcp-auth@v1
```

## Reference Scenarios

### Example 1: Basic MCP Authentication

Apply MCP authentication to an API using a specific key manager:

```yaml
apiVersion: gateway.api-platform.wso2.com/v1alpha1
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
apiVersion: gateway.api-platform.wso2.com/v1alpha1
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
apiVersion: gateway.api-platform.wso2.com/v1alpha1
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
apiVersion: gateway.api-platform.wso2.com/v1alpha1
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
apiVersion: gateway.api-platform.wso2.com/v1alpha1
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
