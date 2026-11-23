# Intelligent Model Routing

Routes AI/LLM requests to different models using LLM-powered classification. An LLM analyzes each incoming request against user-defined routing rules and selects the best-matching model. When no rule matches, the request falls back to a configurable default model.

## How It Works

1. The incoming request payload is read and the user prompt is extracted using the configured `contentPath` (a JSONPath expression, defaulting to `$.messages[-1].content`).
2. A classification prompt is dynamically built listing all configured routing rules with their names and context descriptions.
3. The classification LLM is called and asked to respond with exactly one rule name or `NONE`.
4. If a rule name is returned, the target model for that rule replaces the model in the outgoing request. If `NONE` is returned, the `defaultModel` is used.

## When to Use This Policy

Use **Intelligent Model Routing** when:
- You want to route requests based on **topic or intent** (e.g., coding questions → a code-specialist model, creative writing → a creative model).
- Your users ask varied, conversational questions that don't map cleanly to fixed example phrases.
- The routing categories are best described as natural-language context descriptions rather than exact utterances.

> **Tip:** If your users tend to send short keyword-style queries, consider **Semantic Model Routing** instead, which uses embedding similarity rather than LLM classification.

## Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `contentPath` | string | No | JSONPath to extract the prompt from the request body. Default: `$.messages[-1].content` |
| `routingRules` | array | Yes | List of routing rules. Each rule has a `name`, a `context` description, and a target `model`. |
| `defaultModel` | string | Yes | Model to use when no rule matches or the classifier returns `NONE`. |
| `defaultProvider` | string | No | Destination provider alias to use with `defaultModel` on fallback. |
| `azureAuth` | object | No | How the classifier call authenticates to Azure OpenAI: the API key (the default) or the gateway's Azure identity. See [Azure Identity Authentication](#azure-identity-authentication). |

### Routing Rule Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | Yes | A short label for the rule (e.g. `"Coding"`, `"Customer Support"`). The LLM uses this name to identify the match. |
| `context` | string | Yes | Plain-language description of request types this rule handles. The LLM reads this when classifying. |
| `model` | string | Yes | The target AI model name to route matching requests to. |
| `provider` | string | No | Additional-provider alias for this route. Empty or omitted preserves the current upstream. |

## Example Configuration

```yaml
- name: intelligent-model-routing
  version: v0.10
  paths:
    - path: /chat/completions
      methods: [POST]
      params:
        contentPath: "$.messages[-1].content"
        routingRules:
          - name: Coding
            context: "Code-related questions, programming, debugging, algorithms, software development"
            model: "gpt-4o-mini"
            provider: "coding-provider"
          - name: Creative Writing
            context: "Stories, poems, creative content, fiction, song lyrics, screenplays"
            model: "gpt-4o"
        defaultModel: "gpt-4o-mini"
        defaultProvider: "fallback-provider"
```

## System Requirements

This policy requires a classifier LLM. It reads the LLM from its own section of the gateway's
`config.toml`, `[policy_configurations.intelligent_model_routing_v1]`:

| Config Key | Description |
|------------|-------------|
| `llm_provider` | Provider type: `OPENAI` or `AZURE_OPENAI` |
| `llm_provider_endpoint` | Chat completions endpoint URL |
| `llm_provider_model` | Model name used for classification (e.g. `gpt-4o-mini`). Not needed for `AZURE_OPENAI`, where the deployment is in the endpoint |
| `llm_provider_api_key` | API key for the LLM service. Needed only by APIs that send a key (`api-key` mode, the default) |
| `llm_provider_allowed_auth_types` | Optional. The authentication types the gateway's APIs may choose in `azureAuth`. Empty (the default) places no limit |
| `llm_provider_allowed_endpoints` | Optional. The LLM resources the gateway's APIs may call. Empty (the default) places no limit |

```toml
[policy_configurations.intelligent_model_routing_v1]
llm_provider = "OPENAI"
llm_provider_endpoint = "https://api.openai.com/v1/chat/completions"
llm_provider_model = "gpt-4o-mini"
llm_provider_api_key = "<api-key>"

# Optional: limit what the gateway's APIs may use. Empty (the default) means no limit.
# llm_provider_allowed_auth_types = ["api-key"]
# llm_provider_allowed_endpoints = ["https://api.openai.com"]
```

An API can override `llmProvider`, `llmEndpoint`, `llmModel` and `llmApiKey` in its params, for example
to use an Azure OpenAI resource of its own. The two allowlists apply to it all the same.

## Azure Identity Authentication

An API whose `azureAuth.authenticationType` is an Azure identity sends `Authorization: Bearer <token>`,
a Microsoft Entra ID access token for the gateway's own identity, to Azure OpenAI, and never sends an API
key. There is no key to store or rotate, and once every API uses an identity the Azure OpenAI resource can
turn key access off. An API without `azureAuth` sends the API key, as v0.9 does.

The identity types need `llmProvider` set to `AZURE_OPENAI`: the gateway's `llm_provider = "AZURE_OPENAI"`,
or the same value in the API's params.

```yaml
- name: intelligent-model-routing
  version: v0.10
  paths:
    - path: /chat/completions
      methods: [POST]
      params:
        routingRules:
          - name: Coding
            context: "Code-related questions, programming, debugging, algorithms, software development"
            model: "gpt-4o-mini"
        defaultModel: "gpt-4o"
        azureAuth:
          authenticationType: container-apps
          # Optional: a user-assigned identity. Without it, the app's system-assigned identity is used.
          clientId: "<identity-client-id>"
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `azureAuth.authenticationType` | string | No | `api-key` (the default) sends the API key. `workload-identity`, `managed-identity` and `container-apps` send a Microsoft Entra ID access token for the gateway's Azure identity instead. |
| `azureAuth.clientId` | string | No | Client ID (a GUID) of the identity to use. With `workload-identity`, defaults to `AZURE_CLIENT_ID`. With `managed-identity` or `container-apps`, selects a user-assigned identity; leave it unset for the system-assigned one. Ignored with `api-key`. |
| `azureAuth.scope` | string | No | Scope of the access token. Default: `https://cognitiveservices.azure.com/.default`. Must end in `/.default`. Ignored with `api-key`. |

| Authentication type | Where the gateway runs | Where the token comes from |
|---------------------|------------------------|----------------------------|
| `workload-identity` | AKS, with Workload Identity set up for the gateway runtime's service account | Microsoft Entra ID, in exchange for the pod's federated token |
| `managed-identity` | An Azure VM, VM scale set or AKS node with a managed identity | The Azure Instance Metadata Service (IMDS) |
| `container-apps` | An Azure Container Apps app with a managed identity | The identity endpoint Container Apps runs beside the app |

### Azure setup

1. Give the gateway an identity: Workload Identity for the gateway runtime's service account on AKS, a
   managed identity assigned to the VM or node pool, or a system-assigned or user-assigned identity on the
   container app.
2. Grant that identity the **Cognitive Services OpenAI User** role on the Azure OpenAI resource:

   ```bash
   az role assignment create --assignee <identity-principal-id> --role "Cognitive Services OpenAI User" \
     --scope <azure-openai-resource-id>
   ```

3. Use the resource's custom subdomain, `https://<resource>.openai.azure.com`. The chat completions
   endpoint is the deployment URL on it, with the deployment name in the path:
   `https://<resource>.openai.azure.com/openai/deployments/<deployment>/chat/completions?api-version=<version>`.
   Regional endpoints such as `https://eastus.api.cognitive.microsoft.com` don't accept Entra ID tokens.
4. Once the identity works, you can turn key access off on the resource
   (`az resource update --ids <azure-openai-resource-id> --set properties.disableLocalAuth=true`), so that
   only Entra ID tokens are accepted. An API still in `api-key` mode then sends every request to
   `defaultModel`.

### Choosing the identity

- `workload-identity` uses `AZURE_CLIENT_ID`, `AZURE_TENANT_ID` and `AZURE_FEDERATED_TOKEN_FILE`, which the
  AKS Workload Identity webhook sets. `azureAuth.clientId` overrides the client ID; the tenant always comes
  from `AZURE_TENANT_ID`.
- `managed-identity` without a client ID uses the host's system-assigned identity, or its only user-assigned
  identity if it has none; IMDS rejects the request if the host has several. The gateway must reach
  `169.254.169.254` directly: if the gateway runtime has `HTTP_PROXY` or `HTTPS_PROXY` set, add
  `169.254.169.254` to `NO_PROXY`. On AKS, prefer Workload Identity, because every pod that can reach IMDS
  can get tokens for the node's identities.
- `container-apps` without a client ID uses the app's system-assigned identity, which the app must then
  have: unlike IMDS, Container Apps doesn't fall back to an app's only user-assigned identity, and answers
  `400`. Container Apps sets `IDENTITY_ENDPOINT` and `IDENTITY_HEADER` only while the app has a managed
  identity, and a container sees the values it started with: when a running app gets its first identity,
  Container Apps can replace its containers, which restarts the gateway; if the API still fails to deploy
  because the variables are not set, restart the revision with `az containerapp revision restart`.

### How the token is used

- Nothing calls Azure when the gateway builds the API's route. The policy gets a token when it classifies a
  request, with that request, and sends it to the classifier. The Azure Identity SDK caches the token and
  refreshes it before it expires, so most requests don't make a token request. Every policy on the gateway
  that uses the same identity shares the cache.
- On gateways newer than 1.2.0, an API's route answers `500` when its policy can't be built: when its
  settings are invalid, when the gateway doesn't allow its authentication type or endpoint, when it chooses
  an identity with the `OPENAI` provider, or when the gateway's host can't provide the identity, for example
  `container-apps` without `IDENTITY_ENDPOINT`. The gateway logs
  `Failed to build policy chain for route, skipping` at `ERROR`, with the reason.
- When no access token can be obtained for a request, the request goes to `defaultModel` (with
  `defaultProvider`), as it does for any other classifier failure, and the policy logs
  `IntelligentModelRouting: could not obtain an access token for the LLM provider` at `ERROR`, with the
  reason and the identity's client ID. A token request the identity service refused is answered again from
  a short cache for about two seconds, and logged at `DEBUG` while it is. A request that ends before its
  token arrives is logged at `DEBUG` too.
- A token Azure OpenAI refuses with `401` or `403` sends the request to `defaultModel` the same way, and is
  logged at `ERROR` as `IntelligentModelRouting: the LLM provider refused the access token`, with the
  status, the authentication type, the identity's client ID and the scope. Azure OpenAI's answer, which can
  name the identity, is logged only at `DEBUG`, where it tells a missing role from a wrong scope or endpoint.
- APIs on the same gateway can authenticate differently: a key, the API's own or the gateway's, is sent only
  by the APIs that use `api-key`. With `api-key`, `clientId` and `scope` are ignored.
- The token goes to the endpoint in effect: the API's `llmEndpoint` if it sets one, otherwise the gateway's.
  An API can use its own Azure OpenAI resource this way, with an identity that has the role on it, or with
  its own `llmApiKey` in `api-key` mode, and the allowlists below apply to the endpoint it uses.

### Limiting what APIs can use

`llm_provider_allowed_auth_types` lists the authentication types the gateway's APIs may use, from `api-key`,
`workload-identity`, `managed-identity` and `container-apps`. An API whose type isn't listed is refused, and
an API without `azureAuth` counts as `api-key`.

- To stop APIs from sending the key, leave `api-key` out, for example `["workload-identity"]`. APIs that
  don't choose an identity are then refused instead of sending the key.
- To keep APIs off the gateway's identities, list only `api-key`.

`llm_provider_allowed_endpoints` lists the LLM resources the gateway's APIs may call. An API can set its own
`llmEndpoint`, so without this list an API could have the gateway's key, or a token for the gateway's
identity, sent to a server of its choosing. The list is checked against the endpoint in effect, the API's or
the gateway's, so include the gateway's own `llm_provider_endpoint`. Set it on every gateway whose APIs use
an Azure identity.

- Entries are resource URLs: a scheme, a host and optionally a port, such as
  `https://<resource>.openai.azure.com`. They match on scheme, host and port, ignoring case, so any
  deployment and `api-version` on a listed resource is allowed.
- An entry with a path other than `/`, a query or a fragment, or that isn't an `http` or `https` URL, is
  invalid. So is a host with non-ASCII characters. An invalid entry in either list refuses every API that
  uses the policy, so a typo is found at the first deployment.
- Both lists are empty by default, which places no limit. They are this policy's own settings, in
  `[policy_configurations.intelligent_model_routing_v1]` beside its other `llm_provider_*` keys. An API
  cannot set them in its params: the gateway rejects such an API.
- Both are checked when the route is built, so a refused endpoint never receives the key or a token.

On gateways newer than 1.2.0, a refused authentication type or endpoint makes the API's route answer `500`,
with the reason in the gateway log.

```toml
[policy_configurations.intelligent_model_routing_v1]
llm_provider = "AZURE_OPENAI"
llm_provider_endpoint = "https://<resource>.openai.azure.com/openai/deployments/<deployment>/chat/completions?api-version=<version>"
# No llm_provider_api_key is needed when every API uses an identity.

llm_provider_allowed_auth_types = ["workload-identity"]
llm_provider_allowed_endpoints = ["https://<resource>.openai.azure.com"]
```

### Troubleshooting

- The API's route answers `500`: look for `Failed to build policy chain for route, skipping` in the gateway
  log. Its reason names the refused setting or the missing environment variable. The gateway doesn't retry
  that build on a timer. It builds the route again when an API on the gateway, this one or any other, is
  created or updated, so after fixing the cause, redeploy or update the API.
- Every request goes to `defaultModel`: look for the `ERROR` lines above. A classifier call that fails for
  any other reason is logged only at `DEBUG`, as
  `IntelligentModelRouting: LLM call failed, using default model`.
- Azure OpenAI answers `401`: the identity lacks the Cognitive Services OpenAI User role (role assignments
  can take several minutes to apply), the endpoint is a regional one, or the token scope is for another
  resource, such as `https://management.azure.com/.default`. Use `https://cognitiveservices.azure.com/.default`,
  the default.
- A `403` is reported as a refused token even when Azure OpenAI refused the call for another reason, such as
  the resource's network rules (public network access disabled, or the gateway's address not allowed). The
  `DEBUG` line `LLM call failed, using default model` has Azure OpenAI's answer, which says which.

### Security considerations

- **Least privilege**: grant the identity the Cognitive Services OpenAI User role on the Azure OpenAI
  resource only, rather than on a resource group or subscription.
- **Who configures an API chooses its identity and endpoint**: whoever creates an API with this policy
  chooses which of the gateway's identities its classifier call uses, the token scope, and the endpoint the
  token is sent to. Without `llm_provider_allowed_endpoints`, they can have a token for any identity the
  gateway can use sent to a server of their choosing, just as they can have the gateway's key sent there in
  `api-key` mode. In `[policy_configurations.intelligent_model_routing_v1]`, list the gateway's Azure OpenAI
  resources in `llm_provider_allowed_endpoints` and use `llm_provider_allowed_auth_types` to keep APIs to the
  types you intend. Give the gateway's identities only the roles its APIs need.
- **No stored secret**: with an Azure identity, no key is stored in the gateway's configuration or sent to
  Azure OpenAI, and the tokens are short lived.
- **No redirects**: the policy doesn't follow a redirect from the classifier endpoint, so neither the key nor
  a token reaches a host the endpoint redirects to.
- **Removing a role doesn't cut an identity off at once**: Azure OpenAI can keep accepting an identity's
  token for an hour or more after its role is removed, and the gateway keeps using a cached token until it
  is close to expiry. To stop an API using an identity at once, update its `azureAuth` or remove the API.

### Upgrading from v0.9

- An API that sets nothing keeps sending the gateway's key, as v0.9 does. An API that sets its own endpoint
  or key, or overrides any other setting, keeps doing so.
- The gateway settings are unchanged: v0.10 reads `[policy_configurations.intelligent_model_routing_v1]`, as
  v0.9 does.
- The only parameters v0.10 refuses in an API definition are `llmAllowedAuthTypes` and
  `llmAllowedEndpoints`, which only the gateway can set.
- v0.10 doesn't follow redirects from the classifier endpoint, in any mode. An endpoint that answers with a
  redirect now sends every request to `defaultModel`; configure the endpoint the redirect points to instead.

### Gateway versions

v0.10 needs Go 1.26.10 or later to build. The latest gateway's builder has it. A 1.2.0 gateway's builder
downloads a newer Go during the build, so the build machine needs internet access. A 1.1.0 gateway's builder
can't build v0.10: pin the policy to `@v0.9.0` in `build.yaml` before rebuilding, because `@v0` would pick
v0.10.

## Destination Provider Routing

Configure the example aliases `coding-provider` and `fallback-provider` in the
LlmProxy's `additionalProviders`. The `provider` and `defaultProvider` values
must match `additionalProviders[].as`, or the provider id when `as` is absent.
These fields select the destination of the user request; they do not change the
classification LLM or embedding service configured through system parameters.

A matched route uses its own model and provider. `defaultProvider` is used only
with `defaultModel` when classification or matching falls back, including an
empty prompt in a non-empty JSON payload or a classification/embedding request failure. Omitting a provider
leaves the upstream and routing metadata unchanged, so a request with no earlier
routing override uses the primary provider. Matched routes do not inherit
`defaultProvider`. An absent or zero-length request body leaves the request and
routing metadata unchanged, even when `defaultProvider` is configured. No
classification or embedding call is made for such requests. Malformed JSON or a
failed model rewrite also retains the no-op behavior and does not apply a provider
override.

The policy selects the destination during buffered request-body processing and
sets `UpstreamName` together with `request.Metadata["selected_provider"]`.
Use a gateway runtime that supports named additional-provider upstreams and
conditional provider authentication/transformers. Place this routing policy
before provider-specific body transformers and authentication/signing policies;
they must use the selected provider after body routing. Header-only provider
authentication that has already executed cannot react to this selection.
Only payload-based model rewriting is supported.

The existing system configuration namespaces (`intelligent_model_routing_v1`
and `semantic_model_routing_v1`, respectively) remain unchanged; the policy
version in configuration is `v0.10`.
