---
title: "Overview"
---
# GraphQL Authorization

## Overview

The GraphQL Authorization policy provides fine-grained access control for GraphQL APIs. It authorizes each root Query and Mutation field selected by a request using JWT claims and/or OAuth scopes carried on the request's `AuthContext`, which an upstream authentication policy (e.g. [jwt-auth](../../../jwt-auth/v1.3/docs/jwt-authentication.md)) must have already populated.

Unlike a REST API, a GraphQL API exposes a single HTTP endpoint for every query and mutation, so there is no per-operation route to attach a policy to at the transport level. This policy re-creates that per-operation control inside a single policy instance: rules are configured **per field name** under `queries` / `mutations` ("op-level" rules), plus a type-wide `*` wildcard and a cross-type `global` fallback. **Every rule that matches a field applies — they stack, they don't override.** This mirrors the [mcp-authz](../../../mcp-authz/v1.2/docs/mcp-authorization.md) policy's rule-matching model: a `*` or `global` rule is not skipped just because the field also has its own exact-name rule; if both match, both must grant access. A field matched by **no** rule at all — no exact rule, no `*`, no `global` — is **not governed by this policy instance**: it passes through untouched, leaving that field to whatever else is attached to the API (another policy, or nothing). This lets the policy govern exactly the fields it's configured for and defer everything else to the rest of the API's policy chain, rather than requiring every field the schema will ever have to be listed here up front.

A single GraphQL request can select more than one root field in its executed operation (e.g. `query { books authors }`), and a single field can be matched by more than one rule (its own exact rule, `*`, and `global` can all apply at once); every rule for every governed field in the request must be satisfied for the request to be authorized.

> **Prerequisite**: An authentication policy (e.g. `jwt-auth`) must run before this policy and populate `AuthContext.Scopes` / claim properties for scope- and claim-based rules to have anything to check. Authentication is only required when at least one selected field is governed by a rule — a request touching only ungoverned fields is not required to be authenticated by this policy.

## Features

- **Field-Level Access Control**: Restrict access to specific Query/Mutation fields based on scopes and/or claims
- **Op-Level, Wildcard, and Global Rules**: Configure rules per field (`queries` / `mutations`), a type-wide `*` wildcard, and a cross-type `global` fallback
- **Rule Stacking (mcp-authz-style)**: Every rule that matches a field applies — a `*` or `global` rule is enforced *in addition to* a field's own exact rule, not instead of it; all matching rules must grant access
- **Multi-Field Requests**: Every root field selected by the executed operation is authorized independently; all governed fields must pass
- **Boolean Composition (`allOf` / `anyOf`)**: Express scope and claim requirements with `allOf` (all) and/or `anyOf` (at least one)
- **Fragment-Aware**: Root fields selected through a fragment spread or inline fragment are resolved and governed the same as fields selected directly
- **`__typename` Exempt**: The meta-field `__typename` carries no data and is never subject to authorization
- **Pass-Through for Ungoverned Fields**: A field matched by no rule at all — no exact rule, no `*`, no `global` — is left to the rest of the API's policy chain, without requiring authentication on its own account

## Configuration

> At least one of `queries`, `mutations`, or `global` must be provided.

### User Parameters (API Definition)

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `queries` | rule array | Conditional | - | Authorization rules for top-level Query fields, by field name. Minimum 1 item when present. |
| `mutations` | rule array | Conditional | - | Authorization rules for top-level Mutation fields, by field name. Minimum 1 item when present. |
| `global` | object | Conditional | - | `scopes` / `claims` requirement applied to **every** query and mutation root field, in addition to any matching rule in `queries` / `mutations` — not instead of it. |

### Rule Configuration (`queries[]` / `mutations[]`)

> Each rule must specify at least one of `scopes` or `claims`.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | Yes | The field name to authorize (e.g. `books`, `createUser`), or `*` to match every field of this type. A `*` rule applies *in addition to* a field's own exact-name rule when both match — not instead of it. |
| `scopes` | object | Conditional | Scope requirement as `allOf` (every listed scope must be present) and/or `anyOf` (at least one must be present); AND-ed when both are given. |
| `claims` | object | Conditional | Claim requirement as `allOf` and/or `anyOf` lists of matchers, each `{ claim, values }`; a matcher is satisfied when the claim's value is one of `values`. |

### Global Fallback (`global`)

`global` uses the same `scopes` / `claims` shape as a rule (without `name`), and requires at least one of them. Despite the name "fallback," it is not skipped when an op-level or `*` rule also matches — it stacks with them, the same way `*` stacks with an exact rule.

## Reference Scenarios

### Example 1: Basic Field Access Control

```yaml
apiVersion: gateway.api-platform.wso2.com/v1
kind: GraphQLApi
metadata:
  name: bookstore-api-v1.0
spec:
  displayName: bookstore-api
  version: v1.0
  context: /bookstore
  vhost: graphql1.gw.example.com
  upstream:
    url: https://bookstore-backend:8080/graphql
  policies:
    - name: jwt-auth
      version: v1
      params:
        issuers:
          - PrimaryIDP
    - name: graphql-authz
      version: v0
      params:
        queries:
          - name: books
            scopes:
              anyOf:
                - "books:read"
        mutations:
          - name: addBook
            scopes:
              anyOf:
                - "books:write"
```

**Scenario 1**: Caller with scope `books:read` runs `query { books { id } }`
- Result: ✅ Authorized.

**Scenario 2**: Caller with scope `books:read` (no write scope) runs `mutation { addBook(title: "Dune") { id } }`
- Result: ❌ `403` — `addBook` requires `books:write`.

**Scenario 3**: Unauthenticated caller runs `query { books { id } }`
- Result: ❌ `401` — `books` is governed by a rule, so authentication is required.

**Scenario 4**: Any caller (including unauthenticated) runs `query { authors { id } }`
- `authors` is named by no rule and there is no `*` query rule or `global` fallback.
- Result: ✅ Not governed by this policy — forwarded, without this policy requiring authentication. (Whether it actually reaches the upstream still depends on the rest of the API's policy chain.)

### Example 2: Type-Wide Wildcard

```yaml
apiVersion: gateway.api-platform.wso2.com/v1
kind: GraphQLApi
metadata:
  name: bookstore-api-v1.0
spec:
  displayName: bookstore-api
  version: v1.0
  context: /bookstore
  vhost: graphql1.gw.example.com
  upstream:
    url: https://bookstore-backend:8080/graphql
  policies:
    - name: jwt-auth
      version: v1
      params:
        issuers:
          - PrimaryIDP
    - name: graphql-authz
      version: v0
      params:
        queries:
          - name: books
            scopes:
              anyOf:
                - "books:read"
          - name: "*"
            scopes:
              anyOf:
                - "api:read"
```

**Scenario 5**: Caller with scope `api:read` (no `books:read`) runs `query { authors { id } }`
- `authors` has no exact rule, so only the `*` query rule governs it.
- Result: ✅ Authorized.

**Scenario 6**: Caller with scope `api:read` only (no `books:read`) runs `query { books { id } }`
- `books` matches **both** its own exact rule and `*` — both apply, mirroring mcp-authz's "a wildcard rule applies in addition to the exact rule, not instead of it." Having only the `*` rule's scope isn't enough.
- Result: ❌ `403` — the exact rule's `books:read` is still required.

**Scenario 7**: Caller with both `books:read` and `api:read` runs `query { books { id } }`
- Both matching rules are satisfied.
- Result: ✅ Authorized.

### Example 3: Global Baseline Stacked With Op-Level Rules

```yaml
apiVersion: gateway.api-platform.wso2.com/v1
kind: GraphQLApi
metadata:
  name: bookstore-api-v1.0
spec:
  displayName: bookstore-api
  version: v1.0
  context: /bookstore
  vhost: graphql1.gw.example.com
  upstream:
    url: https://bookstore-backend:8080/graphql
  policies:
    - name: jwt-auth
      version: v1
      params:
        issuers:
          - PrimaryIDP
    - name: graphql-authz
      version: v0
      params:
        queries:
          - name: books
            scopes:
              anyOf:
                - "books:read"
        mutations:
          - name: addBook
            scopes:
              anyOf:
                - "books:write"
        global:
          scopes:
            anyOf:
              - "api:access"
```

`global` applies to *every* query and mutation field, so `books` and `addBook` are each governed by **two** rules at once: their own op-level rule, and `global`. Every *other* query or mutation field — for example `authors`, or a `deleteBook` mutation the API adds later without an explicit rule — is governed by `global` alone, requiring `api:access`, instead of passing through ungoverned as it did in Example 1 (Scenario 4), where no `global` was configured at all. Adding `global` is how you turn "everything not explicitly listed is someone else's problem" into "everything not explicitly listed needs at least this baseline scope" — and it raises the bar on the explicitly-listed fields too.

**Scenario 8**: Caller with only `api:access` runs `query { authors { id } }`
- No op-level rule names `authors`, so `global` alone governs it.
- Result: ✅ Authorized.

**Scenario 9**: Caller with only `api:access` (no `books:read`) runs `query { books { id } }`
- `books` matches both its own op-level rule and `global`; both must pass, and `books:read` is missing.
- Result: ❌ `403`.

**Scenario 10**: Caller with only `books:read` (no `api:access`) runs `query { books { id } }`
- The op-level rule alone is satisfied, but `global` also governs `books` and its `api:access` requirement is unmet.
- Result: ❌ `403` — this is the behavior change from having no `global` at all: an op-level rule no longer guarantees access by itself once `global` is configured.

**Scenario 11**: Caller with both `books:read` and `api:access` runs `query { books { id } }`
- Both rules governing `books` are satisfied.
- Result: ✅ Authorized.

### Example 4: Claim-Based Rule and Multi-Field Requests

```yaml
apiVersion: gateway.api-platform.wso2.com/v1
kind: GraphQLApi
metadata:
  name: bookstore-api-v1.0
spec:
  displayName: bookstore-api
  version: v1.0
  context: /bookstore
  vhost: graphql1.gw.example.com
  upstream:
    url: https://bookstore-backend:8080/graphql
  policies:
    - name: jwt-auth
      version: v1
      params:
        issuers:
          - PrimaryIDP
    - name: graphql-authz
      version: v0
      params:
        mutations:
          - name: deleteBook
            claims:
              allOf:
                - claim: role
                  values: ["admin"]
        queries:
          - name: books
            scopes:
              anyOf:
                - "books:read"
          - name: authors
            scopes:
              anyOf:
                - "authors:read"
```

**Scenario 12**: Caller with claim `role=admin` runs `mutation { deleteBook(id: "1") }`
- Result: ✅ Authorized.

**Scenario 13**: Caller with claim `role=user` runs the same mutation
- Result: ❌ `403` — claim mismatch.

**Scenario 14**: Caller with only `books:read` runs `query { books { id } authors { id } }`
- The request selects two root fields; `authors` also requires `authors:read`, which this caller lacks.
- Result: ❌ `403` — every governed field in the request must pass, not just one.

### Example 5: Claims-Only Configuration

> Every rule here uses `claims` — no `scopes` appear anywhere in this configuration — showing that scopes are entirely optional as long as at least one of `scopes` / `claims` is present per rule.

```yaml
apiVersion: gateway.api-platform.wso2.com/v1
kind: GraphQLApi
metadata:
  name: bookstore-api-v1.0
spec:
  displayName: bookstore-api
  version: v1.0
  context: /bookstore
  vhost: graphql1.gw.example.com
  upstream:
    url: https://bookstore-backend:8080/graphql
  policies:
    - name: jwt-auth
      version: v1
      params:
        issuers:
          - PrimaryIDP
    - name: graphql-authz
      version: v0
      params:
        queries:
          - name: books
            claims:
              anyOf:
                - claim: department
                  values: ["sales", "marketing"]
        mutations:
          - name: deleteBook
            claims:
              allOf:
                - claim: role
                  values: ["admin"]
        global:
          claims:
            allOf:
              - claim: tenant
                values: ["acme-corp"]
```

**Scenario 15**: Caller with claims `department=sales` and `tenant=acme-corp` runs `query { books { id } }`
- `books`'s own rule (`department` in `["sales", "marketing"]`) and `global` (`tenant=acme-corp`) both pass.
- Result: ✅ Authorized.

**Scenario 16**: Caller with claims `department=engineering` and `tenant=acme-corp` runs `query { books { id } }`
- `global`'s `tenant` requirement is met, but `books`'s own rule fails — `engineering` is not in `["sales", "marketing"]`.
- Result: ❌ `403`.

**Scenario 17**: Caller with claims `role=admin` and `tenant=other-corp` runs `mutation { deleteBook(id: "1") }`
- `deleteBook`'s own rule (`role=admin`) passes, but `global` also governs it and `tenant` doesn't match `acme-corp`.
- Result: ❌ `403` — same stacking behavior as Example 3, now with claims instead of scopes on both sides.

**Scenario 18**: Caller with claims `role=admin` and `tenant=acme-corp` runs `mutation { deleteBook(id: "1") }`
- Both rules governing `deleteBook` are satisfied.
- Result: ✅ Authorized.

## Authorization Logic

The GraphQL Authorization policy processes each POST request as follows:

1. **Parse the request body** as a standard GraphQL-over-HTTP request (`query`, `operationName`, `variables`).
2. **Parse the query document** and resolve the operation to execute via `operationName` (required when the document defines more than one operation).
3. **Skip subscriptions** — this policy does not govern `subscription` operations (a transport limitation, not a security decision; see Limitations below).
4. **Collect the operation's root field names**, expanding fragment spreads and inline fragments, excluding `__typename`.
5. **Collect every rule that matches each field**: its own exact-name rule in `queries`/`mutations` (matching the operation type) if present, the type-wide `*` rule in the same array if present, and `global` if configured — all of these can apply to the same field at once. A field matched by none of them is **not governed**.
6. **Pass through untouched** if no selected field matched any rule — this policy has nothing to say about the request, and does not require authentication for it.
7. **Require authentication** if at least one field is governed; deny with `401` if `AuthContext` is missing or unauthenticated.
8. **Evaluate every rule for every governed field** against the `AuthContext`; every rule that matched must independently grant access, or deny with `403`.
9. **Forward unchanged** once every rule for every governed field has passed.

## Limitations

- **Subscriptions are not governed.** GraphQL subscriptions are typically served over a different transport (e.g. WebSocket) than the request/response body this policy inspects, so `subscription` operations pass through unauthorized by this policy. Use a transport-level policy or the subscription server's own authorization if you expose subscriptions.
- **Ungoverned fields are this policy's blind spot by design.** A field matched by no rule at all — no exact rule, no `*`, no `global` — is not authorized by this policy at all — not "authorized because it's safe," just not evaluated. If you want every field to require at least a baseline scope, configure `global`; if you want to guarantee nothing slips through unauthorized anywhere in the chain, pair this policy with whatever other policy is meant to catch the rest (or review the API's full policy chain, since this policy alone does not guarantee default-deny coverage).
- **Rule stacking can surprise you when adding `global` or a `*` rule later.** Because `global` and `*` apply to fields that already have their own exact rule, introducing either one after the fact raises the bar for every field that previously only needed its own rule — see Example 3, Scenario 10.

## Related Policies

- [JWT Authentication Policy](../../../jwt-auth/v1.3/docs/jwt-authentication.md) - Base JWT token validation mechanism, and prerequisite for scope/claim-based decisions
