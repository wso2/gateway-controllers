---
title: "Overview"
---
# MCP Authorization

## Overview

The MCP Authorization policy provides fine-grained access control for Model Context Protocol (MCP) server resources. It enables API administrators to define authorization rules based on user claims and scopes extracted from validated JWT tokens, controlling access to specific MCP tools, resources, prompts, and JSON-RPC methods.

The policy governs only the capabilities that at least one rule targets. An invocation that no rule matches is not governed and passes through untouched, without requiring authentication. An invocation that *is* matched requires an authenticated caller and must satisfy every rule that matched it.

> **Prerequisite**: The MCP Authorization policy requires the [MCP Authentication policy](../../../mcp-auth/v1.4/docs/mcp-authentication.md) to be applied first. The MCP Authentication policy validates and extracts JWT claims that are used by the authorization policy for access control decisions.

## Features

- **Tool-Level Access Control**: Restrict access to specific MCP tools based on user claims and scopes
- **Resource-Level Access Control**: Control access to specific MCP resources based on authorization rules
- **Prompt-Level Access Control**: Manage access to specific MCP prompts
- **JSON-RPC Method-Level Access Control**: Apply authorization rules at the JSON-RPC method level (e.g., `tools/call`, `resources/read`, `prompts/get`) for fine-grained control
- **Flexible Rule-Based Authorization**: Define multiple authorization rules with name matching (exact or wildcard `*`)
- **Claim-Based Validation**: Validate custom claims (e.g., department, role, team) in user tokens
- **Scope-Based Validation**: Require specific OAuth scopes for accessing protected resources
- **Boolean Composition (`allOf` / `anyOf`)**: Express scope and claim requirements with `allOf` (all) and/or `anyOf` (at least one) via the `scopes` and `claims` fields
- **Wildcard Matching**: Use wildcard patterns (`*`) to create default rules for all resources of a type
- **Rule Specificity**: Exact-name rules are evaluated before wildcards, and all matching rules must pass
- **Pass-Through for Ungoverned Capabilities**: Capabilities that no rule targets — including those excluded from authentication by the MCP Authentication policy, and auth-exempt methods such as `initialize` and `ping` — are left untouched

## Request identification

Before this policy can decide anything it has to know **which capability the request invokes** — the
tool, resource, prompt or JSON-RPC method its rules are matched against. Where that comes from
depends on the request and on the gateway:

| Request | Source | Needs a resolver? |
|---|---|---|
| Declares `MCP-Protocol-Version: 2026-07-28` or later, on a gateway with an MCP operation resolver | the mirrored `Mcp-Method` and `Mcp-Name` headers | yes |
| Declares an earlier version, or none, on a gateway with an MCP operation resolver | facts the resolver published, having parsed the body once for the whole policy chain | yes |
| Any version, on a gateway without one | the policy reads the request body itself | no |

You do not configure this. The gateway states which routes carry a resolver, and the policy asks for
the request body only where nothing else has already read it. A proxy deployed on an older gateway
behaves exactly as it did before this version.

### Three outcomes, not two

| | |
|---|---|
| The capability is identified | governed normally — rules matched, `401` without an authenticated identity, `403` on insufficient scopes |
| The request body could not be read | **rejected, `400`** |
| The body was read and named no capability | **not governed — the request passes through** |
| A modern request omitted `Mcp-Method`, or a required `Mcp-Name` | **rejected, `400`** |

**A body the gateway could not read is rejected.** Invalid JSON, a JSON-RPC batch, a wrongly-typed
`method`, or a member spelled two different ways: in each case the gateway and the MCP server may
read the same bytes differently, so governing the request on the gateway's reading would be
governing a guess. This is the behaviour earlier versions had, and it is unchanged.

**A modern request without a required mirrored header is rejected, `400`,** on a gateway with an MCP
operation resolver. MCP 2026-07-28 requires `Mcp-Method` on every request, and `Mcp-Name` on
`tools/call`, `resources/read` and `prompts/get`; a missing required header is a validation failure.
An `Mcp-Name` that will not decode counts as missing. The legacy allowance for a method-less POST
does not carry over: the one such request, a JSON-RPC response answering a server-initiated call,
does not exist in 2026-07-28, which carries that answer in an ordinary request instead.

**A body that was read and simply named no capability is not governed.** This policy restricts
capabilities it can identify, and it never rejects a request on a guess. The cases are all
legitimate:

- a request whose method addresses no capability family — `initialize`, `ping`, `server/discover`;
- on a legacy request, a JSON-RPC **response**, which a client POSTs to answer a server-initiated
  sampling or elicitation call and which carries an id and a result but no method.

⚠️ **On a modern request the headers are taken at face value.** This policy does not check that
`Mcp-Method` and `Mcp-Name` agree with the request body. Attach the [MCP Spec Validation
policy](../../../mcp-spec-validation/v0.9/docs/mcp-spec-validation.md) ahead of this one to close
that: it requires the mirrored headers and checks them against the body, rejecting a mismatch with
JSON-RPC `-32020`. Without it, the MCP server is responsible for that check.

## Configuration

The MCP Authorization policy uses a single-level configuration model where all parameters are configured per-MCP-API/route in the API definition YAML.

### User Parameters (API Definition)

These parameters are configured per MCP Proxy by the API developer:

> At least one of `tools`, `resources`, `prompts`, or `methods` must be provided, and any array that is provided must contain at least one rule. A policy attached with none of them configured is rejected — applying the policy with no rules would govern nothing and silently do nothing.

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `tools` | `AuthzRule` array | Conditional | - | Authorization rules for MCP tools. Minimum 1 item when present. |
| `resources` | `AuthzRule` array | Conditional | - | Authorization rules for MCP resources. Minimum 1 item when present. |
| `prompts` | `AuthzRule` array | Conditional | - | Authorization rules for MCP prompts. Minimum 1 item when present. |
| `methods` | `AuthzRule` array | Conditional | - | Authorization rules for MCP (JSON-RPC) methods. Minimum 1 item when present. |

### AuthzRule Configuration

Each authorization rule object supports the following fields:

> Each rule must specify at least one authorization condition: `scopes`, `claims`, or the deprecated `requiredScopes` / `requiredClaims`. When several are present, all of them must pass.

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `name` | string | Yes | `"*"` | Name of the resource to authorize, or `*` to match all resources of this type (1–256 characters). |
| `scopes` | object | Conditional | `{}` | Scope requirement as `allOf` (every listed scope must be present) and/or `anyOf` (at least one must be present); AND-ed when both are given. Takes precedence over `requiredScopes`. See [Example 6](#example-6-scopes-and-claims-each-with-allof--anyof). |
| `claims` | object | Conditional | `{}` | Claim requirement as `allOf` and/or `anyOf` lists of matchers, each `{ claim, values }`. A matcher is satisfied when the claim's value is one of `values`; `allOf` requires every matcher, `anyOf` at least one, AND-ed when both are given. Takes precedence over `requiredClaims`. See [Example 6](#example-6-scopes-and-claims-each-with-allof--anyof). |
| `requiredScopes` | string array | Conditional | `[]` | **Deprecated — use `scopes` (`anyOf`) instead.** At least one of the listed scopes must be present. Ignored when `scopes` is set. |
| `requiredClaims` | object | Conditional | `{}` | **Deprecated — use `claims` instead.** Map of claim names to expected values; all must be present and match exactly. Ignored when `claims` is set. |

**Note:**

Inside the `gateway/build.yaml`, ensure the policy module is added under `policies:`:

```yaml
- name: mcp-authz
  gomodule: github.com/wso2/gateway-controllers/policies/mcp-authz@v1
```

## Reference Scenarios

### Example 1: Basic Tool Access Control

Restrict access to specific tools based on scopes:

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
    - name: mcp-authz
      version: v1
      params:
        tools:
          - name: list_files
            scopes:
              anyOf:
                - mcp:tool:read
          - name: create_file
            scopes:
              anyOf:
                - mcp:tool:write
          - name: "*"
            scopes:
              anyOf:
                - mcp:tool:execute
  tools:
    ...
```

**Authorization decision examples:**

**Scenario 1**: User with scopes `mcp:tool:read` and `mcp:tool:execute` attempts to call `list_files` tool
- Matching rules:
  - `name="list_files", scopes.anyOf=["mcp:tool:read"]`
  - `name="*", scopes.anyOf=["mcp:tool:execute"]`
- Result: ✅ Access Granted (both matching rules pass)

**Scenario 2**: User with scope `mcp:tool:execute` (no write scope) attempts to call `create_file` tool
- Rule: `name="create_file", scopes.anyOf=["mcp:tool:write"]`
- Result: ❌ `403` (insufficient scopes)

**Scenario 3**: User with scope `mcp:tool:read` only attempts to call `list_files` tool
- The exact rule passes, but the `*` rule requiring `mcp:tool:execute` also matches and fails
- Result: ❌ `403` — remember that a wildcard rule applies *in addition to* the exact rule, not instead of it

**Scenario 4**: An unauthenticated caller attempts to call `list_files`
- Result: ❌ `401` — the tool is governed by a rule, so an authenticated identity is required

### Example 2: Claim-Based Resource Access

Control resource access based on user claims:

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
    - name: mcp-authz
      version: v1
      params:
        resources:
          - name: "file:///private/main"
            claims:
              allOf:
                - claim: department
                  values: ["engineering"]
            scopes:
              anyOf:
                - mcp:resource:read
          - name: "file:///public/main"
            scopes:
              anyOf:
                - mcp:resource:read
  tools:
    ...
```

Note that the resource rule name is matched against the `params.uri` of the `resources/read` request.

**Authorization decision examples:**

**Scenario 5**: User with claim `department="engineering"` and scope `mcp:resource:read` attempts to read resource `file:///private/main`
- Rule: `name="file:///private/main", claims.allOf=[department ∈ {engineering}], scopes.anyOf=["mcp:resource:read"]`
- Result: ✅ Access Granted

**Scenario 6**: User with claim `department="finance"` and scope `mcp:resource:read` attempts to read resource `file:///private/main`
- Result: ❌ `403` (claim mismatch)

**Scenario 7**: User with claim `department="engineering"` but no `mcp:resource:read` scope attempts to read resource `file:///private/main`
- Result: ❌ `403` (scope mismatch)

**Scenario 8**: Any caller attempts to read `file:///other/doc`
- Result: ✅ Access Granted — no rule names it and there is no `*` resource rule, so it is ungoverned

### Example 3: Role-Based Prompt Access

Restrict prompt access based on user roles:

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
    - name: mcp-authz
      version: v1
      params:
        prompts:
          - name: "admin_summary"
            claims:
              allOf:
                - claim: role
                  values: ["admin"]
            scopes:
              anyOf:
                - mcp:prompt:admin
          - name: "*"
            scopes:
              anyOf:
                - mcp:prompt:read
  tools:
    ...
```

Because `role` is matched through the typed claim value, this rule also works when the token carries `role` as an array (for example `["admin", "auditor"]`). The deprecated `requiredClaims` form would not match such a token.

### Example 4: Method-Level Authorization

Apply authorization at the JSON-RPC method level. Method rules are the way to govern the listing methods (`tools/list`, `resources/list`, `prompts/list`), which carry no capability name and therefore never match a tool, resource, or prompt rule:

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
    - name: mcp-authz
      version: v1
      params:
        methods:
          - name: "tools/list"
            scopes:
              anyOf:
                - mcp:method:tools:list
          - name: "tools/call"
            scopes:
              anyOf:
                - mcp:method:tools:call
          - name: "resources/write"
            claims:
              allOf:
                - claim: role
                  values: ["admin"]
            scopes:
              anyOf:
                - mcp:method:resources:write
  tools:
    ...
```

> **Limitation**: A `methods` rule only takes effect for method names of the form `tools/…`, `resources/…`, or `prompts/…`. Bare methods such as `initialize` and `ping`, and other namespaces such as `notifications/initialized`, `completion/complete`, `subscriptions/listen` and MCP 2026-07-28's `server/discover`, are skipped before rule matching runs — a rule naming one of them is dead configuration. Use the MCP Authentication policy's `methods` configuration to control authentication for those; unlike this policy's, it matches any method name.
>
> A `methods` rule with `name: "*"` matches every `tools/…`, `resources/…`, and `prompts/…` invocation, which makes the whole MCP surface (except the bare methods above) require authentication. Use it deliberately.

### Example 5: Multi-Level Authorization

Combine different resource types with varying access requirements:

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
          - mcp:access
    - name: mcp-authz
      version: v1
      params:
        # Restrictive tool access
        tools:
          - name: "execute_command"
            claims:
              allOf:
                - claim: department
                  values: ["platform"]
                - claim: role
                  values: ["admin"]
            scopes:
              anyOf:
                - mcp:tool:execute:admin
          - name: "*"
            scopes:
              anyOf:
                - mcp:tool:execute
        # Resource access for a finance document (rule names are matched exactly, or a standalone "*")
        resources:
          - name: "file:///finance/report.pdf"
            claims:
              allOf:
                - claim: department
                  values: ["finance"]
            scopes:
              anyOf:
                - mcp:resource:read:finance
          - name: "*"
            scopes:
              anyOf:
                - mcp:resource:read
        # Prompt access
        prompts:
          - name: "admin_dashboard"
            claims:
              allOf:
                - claim: role
                  values: ["admin"]
            scopes:
              anyOf:
                - mcp:prompt:admin
  tools:
    ...
```

Calling `execute_command` here requires **both** matching rules to pass: the exact rule (`department=platform` and `role=admin`, plus `mcp:tool:execute:admin`) and the `*` rule (`mcp:tool:execute`).

### Example 6: Scopes and Claims, each with `allOf` + `anyOf`


```yaml
apiVersion: gateway.api-platform.wso2.com/v1
kind: Mcp
metadata:
  name: mcp-authz-scopes-claims
spec:
  displayName: MCP AuthZ Scopes And Claims
  version: v1.0
  context: /mcpauthzscopesclaims
  specVersion: "2025-06-18"
  upstream:
    url: http://mcp-server-backend:3001/mcp
  policies:
    - name: mcp-auth
      version: v1
      params:
        issuers:
          - PrimaryIDP
    - name: mcp-authz
      version: v1
      params:
        tools:
          - name: deploy
            scopes:
              allOf:
                - "mcp:tool:read"
                - "mcp:tool:list"
              anyOf:
                - "mcp:tool:write"
                - "mcp:tool:admin"
            claims:
              allOf:
                - claim: department
                  values: ["engineering"]
              anyOf:
                - claim: role
                  values: ["lead", "staff"]
```

A `tools/call` for the `deploy` tool is authorized only when **all** of the following hold:

```text
SCOPES = (mcp:tool:read AND mcp:tool:list)  AND  (mcp:tool:write OR mcp:tool:admin)
CLAIMS = (department = engineering)         AND  (role ∈ {lead, staff})
```

| Token scopes | `department` | `role` | Result | Reason |
| --- | --- | --- | --- | --- |
| `mcp:tool:read mcp:tool:list mcp:tool:write` | `engineering` | `lead` | Authorized | scope `allOf` + `anyOf` and claim `allOf` + `anyOf` all satisfied |
| `mcp:tool:read mcp:tool:list` | `engineering` | `lead` | 403 | scope `anyOf` unmet — neither `mcp:tool:write` nor `mcp:tool:admin` present |
| `mcp:tool:read mcp:tool:write` | `engineering` | `lead` | 403 | scope `allOf` incomplete — `mcp:tool:list` missing |
| `mcp:tool:read mcp:tool:list mcp:tool:admin` | `sales` | `lead` | 403 | claim `allOf` unmet — `department` is not `engineering` |
| `mcp:tool:read mcp:tool:list mcp:tool:admin` | `engineering` | `intern` | 403 | claim `anyOf` unmet — `role` not in `{lead, staff}` |

### Example 7: Migrating from `requiredScopes` / `requiredClaims`

`requiredScopes` and `requiredClaims` remain supported for backward compatibility and are flagged as deprecated in the policy definition. Each is superseded by its structured counterpart:

| Deprecated | Equivalent |
|------------|------------|
| `requiredScopes: [a, b]` | `scopes: { anyOf: [a, b] }` |
| `requiredClaims: { department: engineering, role: admin }` | `claims: { allOf: [{ claim: department, values: [engineering] }, { claim: role, values: [admin] }] }` |

```yaml
# Before
tools:
  - name: deploy
    requiredClaims:
      department: engineering
    requiredScopes:
      - mcp:tool:write
      - mcp:tool:admin

# After
tools:
  - name: deploy
    claims:
      allOf:
        - claim: department
          values: ["engineering"]
    scopes:
      anyOf:
        - mcp:tool:write
        - mcp:tool:admin
```

**Precedence:** the new fields take precedence over the deprecated ones **per dimension**. A rule that sets both `scopes` and `requiredScopes` ignores `requiredScopes` entirely; a rule that sets `scopes` and `requiredClaims` uses `scopes` for the scope check and still honours `requiredClaims` for the claim check. Deprecation warnings are logged once at policy load when a deprecated field is actually in use. Any malformed `scopes` or `claims` value fails the policy at load.

The migration is not purely cosmetic: `requiredClaims` compares the flattened string value exactly, so it never matches an array-valued claim, while `claims` matches array-valued claims as a set.

### Authorization Logic

The MCP Authorization policy processes each POST to the MCP path as follows:

1. **The JSON-RPC method determines the type**: — `tools/*` → `tool`, `resources/*` → `resource`, `prompts/*` → `prompt`. Methods that do not carry one of those three prefixes (Ex: initialize) are skipped entirely.

2. **Match applicable rules**: Match rules by the full method or capability name (including wildcard `*`) before checking user identity.

3. **Allow ungoverned requests**: If no rule matches, forward the request without requiring authentication.

4. **Require authentication**: If any rule matches, the request must be authenticated; otherwise, return `401 Unauthorized`.

5. **Apply rule precedence**: Evaluate exact capability rules before wildcard (`*`) rules.

6. **Enforce all matching rules**: Every matched rule must pass. If any fail, deny access and include the missing scopes in the `WWW-Authenticate` challenge.


#### Examples

Given the tool rule set `A` = `[{name:"list_files", scopes:{anyOf:["read"]}}, {name:"*", scopes:{anyOf:["execute"]}}]`
and `B` = `[{name:"admin_tool", claims:{allOf:[{claim:"role", values:["admin"]}]}, scopes:{anyOf:["write"]}}]`:

The Result column reflects only the authorization decision. Authentication is checked first, so a ✅ for "No token" does not guarantee access. It is allowed only if the authentication policy permits unauthenticated requests.

| Capability | Rule set | User Token | Result (MCP Authorization only) |
|----------|--------------|------------|--------|
| `list_files` | `A` | Scopes: `["read", "execute"]` | ✅ Allowed |
| `list_files` | `A` | Scopes: `["execute"]` | ❌ `403` (exact rule fails) |
| `list_files` | `A` | Scopes: `["read"]` | ❌ `403` (wildcard rule fails) |
| `delete_file` | `A` | Scopes: `["execute"]` | ✅ Allowed (only the wildcard matches) |
| `list_files` | `A` | No token | ❌ `401` (governed but unauthenticated) |
| `admin_tool` | `B` | Claims: `{role:"admin"}`, Scopes: `["write"]` | ✅ Allowed |
| `admin_tool` | `B` | Claims: `{role:"user"}`, Scopes: `["write"]` | ❌ `403` (claim mismatch) |
| `public_tool` | `B` | No token | ✅ Ungoverned — no rule matches. Reaches the upstream only if `public_tool` is in the MCP Authentication policy's `tools.exceptions`; otherwise that policy returns `401` first. |
| `tools/list` | `A` or `B` | No token | ✅ Ungoverned — no capability name, so no tool rule matches. Reaches the upstream only if the MCP Authentication policy sets `methods.enabled: false` or lists `tools/list` in `methods.exceptions`; otherwise that policy returns `401` first. |


## Related Policies

- [MCP Authentication Policy](../../../mcp-auth/v1.4/docs/mcp-authentication.md) - Validates JWT tokens and is a prerequisite for MCP Authorization
- [JWT Authentication Policy](../../../jwt-auth/v1.3/docs/jwt-authentication.md) - Base JWT token validation mechanism
