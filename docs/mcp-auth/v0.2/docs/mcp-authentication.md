---
title: "Overview"
---
# MCP Authentication

## Overview

The MCP Authentication policy is designed to secure traffic to Model Context Protocol (MCP) servers. The Gateway acts as a resource server, protecting MCP resources by validating access tokens presented in requests. This policy leverages the underlying JWT Authentication mechanism for token validation and additionally handles MCP-specific requirements such as serving protected resource metadata. This policy supports the auth requirements mentioned in the [MCP Specification](https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization#introduction).

## Features

- **Access Token Validation**: Validates JWT access tokens using configured key managers. Please refer the [JWT Authentication Policy](../../../gateway/policies/jwt-authentication.md) for more information on how the key validation works.
- **Protected Resource Metadata**: Intercepts `GET /.well-known/oauth-protected-resource` requests to return resource metadata, including authorization servers and supported scopes.
- **Standardized Error Handling**: Returns `WWW-Authenticate` headers with `resource_metadata` on authentication failures.
- **Configurable Validation**: Supports issuer, audience, scope, and custom claim validation.
- **Claim Mapping**: Maps token claims to downstream headers.

## Configuration

The MCP Authentication policy uses a two-level configuration model:

### System Parameters (config.toml)

Configured by the administrator in `config.toml` under `policy_configurations.mcpauth_v0` or `policy_configurations.jwtauth_v0` depending on the parameter.

| Parameter | Type | Required | Default | Path | Description |
|-----------|------|----------|---------|----------|-------------|
| `keyManagers` | `KeyManager` array | Yes | - | jwtauth_v0 | List of key manager definitions. Each entry must include a unique `name` and `issuer`, and either `jwks.remote` or `jwks.local` configuration. |
| `jwksCacheTtl` | string | No | - | jwtauth_v0 | Duration string for JWKS caching (e.g., `"5m"`). If omitted a default is used. |
| `jwksFetchTimeout` | string | No | - | jwtauth_v0 | Timeout for HTTP fetch of JWKS (e.g., `"5s"`). |
| `jwksFetchRetryCount` | integer | No | - | jwtauth_v0 | Number of retries for JWKS fetch on transient failures. |
| `jwksFetchRetryInterval` | string | No | - | jwtauth_v0 | Interval between JWKS fetch retries (e.g., `"2s"`). |
| `allowedAlgorithms` | string array | No | - | jwtauth_v0 | Allowed JWT signing algorithms (e.g., `["RS256", "ES256"]`). |
| `leeway` | string | No | - | jwtauth_v0 | Clock skew allowance for `exp`/`nbf` checks (e.g., `"30s"`). |
| `authHeaderScheme` | string | No | `"Bearer"` | jwtauth_v0 | Expected scheme prefix in the authorization header. |
| `headerName` | string | No | `"Authorization"` | jwtauth_v0 | Header name to extract the token from. |
| `onFailureStatusCode` | integer | No | `401` | jwtauth_v0 | HTTP status code returned on authentication failure. Allowed values: `401`, `403`. |
| `errorMessageFormat` | string | No | `"json"` | jwtauth_v0 | Format of the error response. Allowed values: `"json"`, `"plain"`, `"minimal"`. |
| `errorMessage` | string | No | - | jwtauth_v0 | Custom error message to include in the response body on authentication failure. |
| `validateIssuer` | boolean | No | - | jwtauth_v0 | Whether to validate the token's issuer claim against configured key managers. |
| `gatewayHost` | string | No | `"localhost"` | mcpauth_v0 | The outward facing gateway host name used when deriving the protected resource metadata URL and response. Falls back to this if no vhosts are defined in the MCP proxy configuration. |

#### KeyManager Configuration

Each key manager in the `keyManagers` array supports the following structure:

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
[policy_configurations.mcpauth_v0]
gatewayHost = "gw.example.com"

[policy_configurations.jwtauth_v0]
jwksCacheTtl = "5m"
jwksFetchTimeout = "5s"
jwksFetchRetryCount = 3
jwksFetchRetryInterval = "2s"
allowedAlgorithms = ["RS256", "ES256"]
leeway = "30s"
authHeaderScheme = "Bearer"
headerName = "Authorization"
onFailureStatusCode = 401
errorMessageFormat = "json"
errorMessage = "Authentication failed."
validateIssuer = true

[[policy_configurations.jwtauth_v0.keyManagers]]
name = "PrimaryIDP"
issuer = "https://idp.example.com/oauth2/token"

[policy_configurations.jwtauth_v0.keyManagers.jwks.remote]
uri = "https://idp.example.com/oauth2/jwks"
skipTlsVerify = false

[[policy_configurations.jwtauth_v0.keyManagers]]
name = "SecondaryIDP"
issuer = "https://auth.example.org/oauth2/token"

[policy_configurations.jwtauth_v0.keyManagers.jwks.remote]
uri = "https://auth.example.org/oauth2/jwks"
skipTlsVerify = false
```

### User Parameters (API Definition)

These parameters are configured per-API/route by the API developer:

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `issuers` | string array | No | `[]` | List of issuer names (referencing entries in `system.keyManagers`). This list is sent as `authorization_servers` in the protected resource metadata response. If omitted, all configured key managers are used. |
| `requiredScopes` | string array | No | `[]` | List of scopes that must be present in the token (space-delimited `scope` claim or array `scp`). These are also advertised in the protected resource metadata. |
| `audiences` | string array | No | `[]` | List of acceptable audience values; token must contain at least one. |
| `requiredClaims` | object | No | `{}` | Map of claimName → expectedValue for custom claim validation. |
| `claimMappings` | object | No | `{}` | Map of claimName → downstream header name to expose claims for downstream services. |

**Note:**

Inside the `gateway/build.yaml`, ensure the policy module is added under `policies:`:

```yaml
- name: mcp-auth
  gomodule: github.com/wso2/gateway-controllers/policies/mcp-auth@v0
```

## Reference Scenarios:

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
      version: v0
      params:
        issuers:
          - PrimaryIDP
  tools:
    ...
```

### Example 2: Scope and Audience Validation

Require specific scopes and audiences:

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
      version: v0
      params:
        issuers:
          - PrimaryIDP
        audiences:
          - https://mcp-api.example.com
        requiredScopes:
          - mcp:read
          - mcp:write
  tools:
    ...
```
