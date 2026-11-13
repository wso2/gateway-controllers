---
title: "Overview"
---
# Azure Authentication

## Overview

The **Azure Authentication** policy authenticates requests to Azure-hosted backends with a
short-lived [Microsoft Entra ID](https://learn.microsoft.com/entra/identity-platform/) access
token instead of a static API key. Before a request is forwarded upstream, the policy obtains a
token for the gateway's own Azure identity and sets it in a request header, by default
`Authorization: Bearer <token>`.

With `authenticationType: workload-identity`, the gateway uses
[AKS Workload Identity](https://learn.microsoft.com/azure/aks/workload-identity-overview): the
Kubernetes service account token projected into the gateway pod is exchanged for an access token
of the user-assigned managed identity federated with that service account. No key, secret or
certificate is configured on the API, and nothing needs rotating by hand.

With `authenticationType: managed-identity`, the gateway gets the token for a
[managed identity](https://learn.microsoft.com/entra/identity/managed-identities-azure-resources/overview)
assigned to the host it runs on: from the
[Azure Instance Metadata Service](https://learn.microsoft.com/azure/virtual-machines/instance-metadata-service)
(IMDS) of a VM, VM scale set or AKS node, or from the host's own managed identity endpoint on
App Service, Container Apps or Azure Arc. Use it when the gateway runs on Azure compute without
Workload Identity, for example on Azure VMs.

Tokens are obtained and cached by the
[Azure Identity SDK for Go](https://learn.microsoft.com/azure/developer/go/sdk/authentication/authentication-overview)
(`azidentity`). Use the policy for Azure AI Foundry, Azure OpenAI and other Azure services that
accept Entra ID tokens, typically as the upstream authentication of an LLM provider.

## Features

- Secretless upstream authentication with AKS Workload Identity (user-assigned managed identity),
  or with the host's managed identity: IMDS on VMs, VM scale sets and AKS nodes, or the endpoint
  of App Service, Container Apps or Azure Arc
- Works with any Entra ID–protected resource through a configurable `scope`
- One credential per identity, shared by every route and API that uses it, with its tokens
  cached by the Azure Identity SDK
- Retries network errors, throttling and server errors (and IMDS's 404 and 410), honouring
  `Retry-After`
- Picks up the rotated service account token automatically
- Sovereign clouds through the `AZURE_AUTHORITY_HOST` environment variable
- Keeps any authentication context set by an earlier inbound auth policy

## Configuration

### User Parameters (API Definition)

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `authenticationType` | string | Yes | | How the token is obtained: `workload-identity` (AKS Workload Identity) or `managed-identity` (the host's managed identity). |
| `scope` | string | No | `https://ai.azure.com/.default` | Scope of the access token: the target resource followed by `/.default`. See [Choosing the scope](#choosing-the-scope). |
| `clientId` | string | No | `AZURE_CLIENT_ID` (`workload-identity`) | Application (client) ID of the managed identity, as a GUID. With `workload-identity`, overrides the environment variable. With `managed-identity`, selects a user-assigned identity of the host; leave it unset for the host's default identity (its system-assigned identity, or its only user-assigned identity if it has none). |
| `tenantId` | string | No | `AZURE_TENANT_ID` | Microsoft Entra tenant ID (GUID) or domain name. Overrides the environment variable. `workload-identity` only: setting it with `managed-identity` makes the policy fail to initialize. |
| `headerName` | string | No | `Authorization` | Request header the token is set in. |
| `valuePrefix` | string | No | `Bearer` | Prefix placed before the token, separated by a space. An empty string sends the token alone. Control characters are not allowed. |
| `tokenRequestTimeout` | string | No | `10s` | Maximum time to obtain a token, including retries: whole seconds from `1s` to `30s`, or milliseconds from `1ms` to `30000ms`. |

There are no system (`config.toml`) parameters.

### Environment Variables (Gateway Runtime)

With `workload-identity`, the identity is read from the environment the AKS Workload Identity
webhook injects into the gateway runtime pod. `managed-identity` reads none of these variables; on
App Service, Container Apps and Azure Arc, the SDK finds the managed identity endpoint through the
variables those platforms set.

| Variable | Required | Description |
|----------|----------|-------------|
| `AZURE_TENANT_ID` | Unless `tenantId` is set | Tenant of the managed identity. |
| `AZURE_CLIENT_ID` | Unless `clientId` is set | Client ID of the managed identity. |
| `AZURE_FEDERATED_TOKEN_FILE` | Yes | Path of the projected service account token. Read again at least every 10 minutes, so rotation is picked up. |
| `AZURE_AUTHORITY_HOST` | No | Entra ID host, `https://login.microsoftonline.com/` by default. Set by the webhook for sovereign clouds. Must use `https`. |

The token file path and the authority host are deliberately never policy parameters. If both
could be set on an API, whoever writes that API could make the gateway send any file it can read
to a host of their choosing.

If `AZURE_FEDERATED_TOKEN_FILE` is missing, or neither the parameter nor the environment variable
supplies a client or tenant ID, the policy fails to initialize: the routes using it return
`500` and the gateway runtime logs the reason. Other routes are not affected. With
`managed-identity`, the policy also fails to initialize when `tenantId` is set.

Parameters are checked against the policy definition when an API is created, and an invalid
value is rejected with `400`. Parameters given in an LLM provider's `upstream.auth.policyParams`
are not checked when the provider is created; an invalid value or an unknown parameter name there
(such as `clientID` for `clientId`) also makes the provider's routes return `500`, with the reason
in the gateway runtime log.

**Note:**

Inside the `gateway/build.yaml`, ensure the policy module is added under `policies:`:

```yaml
- name: azure-authentication
  gomodule: github.com/wso2/gateway-controllers/policies/azure-authentication@v0
```

## Workload Identity Prerequisites

The gateway must run on AKS with Workload Identity set up for the gateway runtime's service
account. This is Azure and Kubernetes configuration, not something the policy creates.

1. Enable the OIDC issuer and Workload Identity on the cluster, and note the issuer URL:

   ```bash
   az aks update -g <resource-group> -n <cluster> --enable-oidc-issuer --enable-workload-identity
   export AKS_OIDC_ISSUER="$(az aks show -g <resource-group> -n <cluster> \
     --query oidcIssuerProfile.issuerUrl -o tsv)"
   ```

2. Create a user-assigned managed identity:

   ```bash
   az identity create -g <resource-group> -n gateway-identity
   export CLIENT_ID="$(az identity show -g <resource-group> -n gateway-identity --query clientId -o tsv)"
   ```

3. Federate the identity with the gateway's service account. The subject is
   `system:serviceaccount:<namespace>:<service-account>`:

   ```bash
   az identity federated-credential create --name gateway-runtime \
     --identity-name gateway-identity -g <resource-group> \
     --issuer "$AKS_OIDC_ISSUER" \
     --subject system:serviceaccount:<namespace>:<service-account> \
     --audience api://AzureADTokenExchange
   ```

4. Grant the identity a data-plane role on the target resource, for example
   `Cognitive Services OpenAI User` on an Azure OpenAI resource, or the role your Azure AI Foundry
   resource or project requires:

   ```bash
   az role assignment create --role "<role>" --scope <resource-id> \
     --assignee-object-id "$(az identity show -g <resource-group> -n gateway-identity --query principalId -o tsv)" \
     --assignee-principal-type ServicePrincipal
   ```

5. Annotate the service account with the client ID and label the gateway runtime pods. With the
   gateway Helm chart:

   ```yaml
   serviceAccount:
     annotations:
       azure.workload.identity/client-id: <CLIENT_ID>
   gateway:
     gatewayRuntime:
       deployment:
         podLabels:
           azure.workload.identity/use: "true"
   ```

   The chart's service account is named after the release unless `serviceAccount.name` is set;
   the federated credential's subject must match it.

The gateway also needs outbound HTTPS access to `login.microsoftonline.com` (or your cloud's
authority host).

### Choosing the scope

The scope names the resource the token is for, followed by `/.default`.

| Backend | Scope |
|---------|-------|
| Azure AI Foundry (`*.services.ai.azure.com`) | `https://ai.azure.com/.default` (default) |
| Azure OpenAI (`*.openai.azure.com`) | `https://cognitiveservices.azure.com/.default` |
| Azure AI Content Safety and other Azure AI services | `https://cognitiveservices.azure.com/.default` |

A token issued for the wrong scope is rejected by the backend with `401`, which the gateway passes
through to the client unchanged.

## Managed Identity Prerequisites

With `managed-identity`, the gateway must run on Azure compute that has the managed identity
assigned. This is Azure configuration, not something the policy creates. The steps below are for
a VM, VM scale set or AKS node, which serve tokens through IMDS. On App Service, Container Apps or
Azure Arc, assign the identity to the app or server instead.

1. Assign a user-assigned identity to the host, or leave out `--identities` to enable its
   system-assigned identity:

   ```bash
   # A VM
   az vm identity assign -g <resource-group> -n <vm> --identities <identity-resource-id>

   # A VM scale set; then apply the change to the existing instances
   az vmss identity assign -g <resource-group> -n <vmss> --identities <identity-resource-id>
   az vmss update-instances -g <resource-group> -n <vmss> --instance-ids '*'
   ```

2. Grant the identity a data-plane role on the target resource, as in step 4 of the Workload
   Identity prerequisites.

3. Set `clientId` to the identity's client ID to use a user-assigned identity. Without
   `clientId`, IMDS uses the host's system-assigned identity; a host without one uses its only
   user-assigned identity, and IMDS rejects the request if the host has several.

The gateway must reach `169.254.169.254` directly, and host firewalls and Kubernetes network
policies must allow it. If the gateway runtime has `HTTP_PROXY` or `HTTPS_PROXY` set, add
`169.254.169.254` to `NO_PROXY`; otherwise requests to IMDS, and the tokens in their answers, go
through the proxy.

On AKS, prefer Workload Identity. Any pod that can reach IMDS can get tokens for the node's
identities, so an identity assigned to a node pool is shared by every workload on it. Clusters
with IMDS restriction enabled block pods from reaching IMDS, so `managed-identity` doesn't work
there.

## How It Works

1. **Request header phase**: the policy only sets a header, so it never buffers the request body.
2. The policy asks its identity's credential for a token, waiting at most `tokenRequestTimeout`.
   Every route and API with the same authentication type, client ID and tenant shares one
   credential, and the Azure Identity SDK caches its tokens by scope.
   - A cached token is returned straight away until it is due for refresh: once Entra ID's
     `refresh_in` hint passes (half its lifetime for a managed identity token valid for more than
     2 hours), or 5 minutes before it expires.
   - The first request that needs a token that is due fetches a new one, and other requests for
     the same identity wait for it. If a refresh after the hint fails, the cached token stays in
     use; in a token's last 5 minutes, a failed refresh fails the request.
3. With `workload-identity`, the SDK sends an OAuth 2.0 client credentials request with the token
   in `AZURE_FEDERATED_TOKEN_FILE` as a client assertion. On a credential's first token request it
   reads the tenant's OpenID configuration,
   `{authority}/{tenant}/v2.0/.well-known/openid-configuration`, to find the token endpoint.
   Network errors, `408`, `429`, `500`, `502`, `503` and `504` are retried up to twice, waiting from
   200 ms up to 2 seconds.

   With `managed-identity`, on a VM, VM scale set or AKS node, a token request is one `GET` to
   IMDS, `http://169.254.169.254/metadata/identity/oauth2/token`, with `api-version=2018-02-01`,
   the scope's resource (the scope without `/.default`), `client_id` when `clientId` is set, and
   the `Metadata: true` header. Network errors, `404`, `410`, `429` and `5xx` are retried up to
   four times, waiting about 1, 2, 4 and 4 seconds.

   Retries honour `Retry-After`, but one longer than the longest wait (2 seconds for Entra ID,
   4 seconds for managed identity) isn't retried. When the next wait doesn't fit in what is left of
   `tokenRequestTimeout`, the request waits until the timeout and fails.
4. The token is set in `headerName` (`Authorization: Bearer <token>` by default) and the request
   is forwarded upstream.
5. If no token can be obtained, the request is short-circuited with `502 Bad Gateway`: it is the
   gateway's own upstream credential that failed, not the client's. When Entra ID or the managed
   identity endpoint rejects the token request itself (a `4xx` answer other than `429`, and for
   managed identity other than `404` and `410`, such as `invalid_client` or "Identity not found"),
   requests in the next 2 seconds or so get the same `502` without a new token request, so a
   misconfigured identity doesn't send one for every API request. Other failures aren't
   remembered.

## Reference Scenarios

### Example 1: Azure AI Foundry LLM Provider

Requires a gateway release newer than 1.2.0, which supports `upstream.auth.type: other`.

```yaml
apiVersion: gateway.api-platform.wso2.com/v1
kind: LlmProvider
metadata:
  name: foundry-provider
spec:
  displayName: Azure AI Foundry Provider
  version: v1.0
  template: azureai-foundry
  upstream:
    url: https://<resource>.services.ai.azure.com
    auth:
      type: other
      policyName: azure-authentication
      policyVersion: v0
      policyParams:
        authenticationType: workload-identity
```

### Example 2: Azure OpenAI as a REST API

```yaml
apiVersion: gateway.api-platform.wso2.com/v1
kind: RestApi
metadata:
  name: azure-openai-chat-v1.0
spec:
  displayName: Azure-OpenAI-Chat
  version: v1.0
  context: /aoai/$version
  upstream:
    main:
      url: https://<resource>.openai.azure.com
  policies:
    - name: azure-authentication
      version: v0
      params:
        authenticationType: workload-identity
        scope: https://cognitiveservices.azure.com/.default
  operations:
    - method: POST
      path: /openai/deployments/{deployment}/chat/completions
```

### Example 3: A Second Identity for One API

A gateway can use more than one managed identity, as long as each identity has a federated
credential that trusts the gateway's service account.

```yaml
  policies:
    - name: azure-authentication
      version: v0
      params:
        authenticationType: workload-identity
        clientId: 99999999-8888-7777-6666-555555555555
```

### Example 4: Inbound API Key, Outbound Entra ID Token

Clients authenticate to the gateway with its own API key; `api-key-auth` removes that key before
the request is forwarded, and `azure-authentication` adds the Entra ID token.

```yaml
  policies:
    - name: api-key-auth
      version: v1
      params:
        key: X-API-Key
        in: header
    - name: azure-authentication
      version: v0
      params:
        authenticationType: workload-identity
```

### Example 5: Managed Identity on an Azure VM

The gateway runs on an Azure VM with a user-assigned identity that has access to the Azure OpenAI
resource.

```yaml
  policies:
    - name: azure-authentication
      version: v0
      params:
        authenticationType: managed-identity
        clientId: 99999999-8888-7777-6666-555555555555
        scope: https://cognitiveservices.azure.com/.default
```

## Error Responses

All error responses are returned as JSON with `Content-Type: application/json`.

| Scenario | Status | Message |
|----------|--------|---------|
| A token could not be obtained from Microsoft Entra ID or the managed identity endpoint (token file unreadable, endpoint unreachable, request rejected, invalid response or timeout) | 502 | `failed to authenticate request to upstream Azure service` |

**Example error body:**

```json
{
  "error": "Bad Gateway",
  "message": "failed to authenticate request to upstream Azure service"
}
```

The gateway runtime logs the reason with the Azure Identity SDK's error, which includes the
response from Entra ID (its error code, `AADSTS` codes and correlation ID, which Microsoft support
asks for) or from the managed identity endpoint. The access token and the service account token
are never logged.

## Fault reporting

Every rejection this policy makes is reported to the gateway as a **fault**: a stable code and
type alongside the response. A gateway that supports fault policies uses it for the analytics
event and hands it to the API's fault policies (for example `log-message`). A gateway without
fault policy support ignores it.

| When | Status | Code | Type |
|------|--------|------|------|
| No access token could be obtained from Microsoft Entra ID or the managed identity endpoint | `502` | `960000` | `mediation` |

The fault's `Description` carries a short internal reason, for example
`Microsoft Entra ID rejected the token request (HTTP 401, invalid_client)`, or with
`managed-identity`
`the managed identity endpoint rejected the token request (HTTP 400, invalid_request)`. It is
passed to fault policies and analytics only, never to the client.

## Security Considerations

- **Least privilege**: grant the managed identity only the data-plane role the backend needs, on
  the specific resource rather than the subscription.
- **Federate narrowly**: the federated credential's subject should name the gateway runtime's own
  namespace and service account, so no other workload can use the identity.
- **Identity overrides**: `clientId` lets an API choose any identity federated with the gateway's
  service account. Federate only identities that every API on the gateway may use.
- **Who configures the policy controls the token**: whoever creates an API or LLM provider with
  this policy chooses the identity (`clientId`), the scope (any resource's `/.default`, such as
  `https://management.azure.com/.default`) and the upstream URL the token is sent to. They can
  therefore obtain a token for any identity the gateway can use, for any resource that identity
  can access, and send it to a server of their choosing; with `managed-identity` on AKS, that
  includes the node's identities. Give the gateway's identities only the roles its APIs need, and
  allow only trusted users to create APIs and LLM providers on a gateway that uses this policy.
- **No stored secret**: nothing is stored in the API definition, and the projected token is short
  lived and rotated by Kubernetes.
- **HTTPS only**: the authority host must use `https`. With `managed-identity`, plain HTTP goes
  only to the link-local IMDS address, or to the platform's local endpoint on App Service,
  Container Apps or Azure Arc.
- **Proxies**: token requests honour `HTTP_PROXY` and `HTTPS_PROXY`. With `managed-identity` on a
  VM, VM scale set or AKS node, add `169.254.169.254` to `NO_PROXY` so a proxy never sees IMDS
  tokens.
- **Managed identity on shared hosts**: with `managed-identity`, every process that can reach the
  host's IMDS can get tokens for the same identity, including every pod on an AKS node. Use it on
  hosts dedicated to the gateway, and prefer Workload Identity on AKS.

## Limitations

- Client secrets and certificates are not supported.
- Tokens are refreshed when a request needs one, not in the background. The first request after a
  token is due waits for the new one, and if Entra ID can't be reached in a token's last 5
  minutes, requests fail with `502` until it can.
- IMDS answers `410` while it updates, which can take about 70 seconds. A request that needs a
  new token during that time fails with `502` once `tokenRequestTimeout` passes; the next request
  tries again.
- The AKS identity bindings proxy and Entra ID regional endpoints are not used.
- A token rejected by the backend is not discarded early; it is replaced on the normal refresh
  schedule.

## Gateway Module Reference

```yaml
- name: azure-authentication
  gomodule: github.com/wso2/gateway-controllers/policies/azure-authentication@v0
```
