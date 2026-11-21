---
title: "Overview"
---

# Semantic Tool Filtering policy

## Overview
The **Semantic Tool Filtering** policy dynamically filters the tools provided within an API request based on their semantic relevance to the user query. This policy extracts both the query and the tool definitions from the incoming payload, generates embeddings for the query, and performs a similarity search against the provided tools. It then replaces the original tools array with a filtered subset, optimizing the request before it reaches the LLM.

This policy helps reduce token consumption and improve LLM response quality by sending only the most relevant tools for each request.

## Features
- **Semantic similarity-based filtering** of tools using embedding vectors.
- **Two selection modes**: "By Rank" (top-K) and "By Threshold".
- **Flexible Format Support**: Supports both JSON and text-based tool/query extraction.
- **Embedding cache** with LRU eviction to minimize redundant API calls.
- **Configurable JSONPath expressions** for payload extraction.
- **Mixed mode support** (extract query from JSON and tools from text, or vice versa).
- **Azure identity authentication**: with Azure OpenAI, an API's embedding calls can use a Microsoft Entra ID token for the gateway's own Azure identity instead of an API key.

## Configuration

### User Parameters (API Definition)

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| selectionMode | string | Yes | `By Rank` | Method used to filter tools: `By Rank` (selects top-K) or `By Threshold` (selects based on score). |
| limit | integer | No | `5` | The number of most relevant tools to include (used if selectionMode is `By Rank`). |
| threshold | number | No | `0.7` | Similarity threshold for filtering (0.0 to 1.0). Only tools with a score above this value are included (used if selectionMode is `By Threshold`). |
| queryJSONPath | string | Yes | `$.messages[-1].content` | JSONPath expression to extract the user's query from the request body. |
| toolsJSONPath | string | Yes | `$.tools` | JSONPath expression to extract the tools definition from the request body. It can point to the array itself, such as `$.tools`, or to the iterated object inside each array item, such as `$.tools[*].function`. |
| userQueryIsJson | boolean | Yes | `true` | Specifies format of user query. `true`: use `queryJSONPath`. `false`: extract from text using `<userq>` tags. |
| toolsIsJson | boolean | Yes | `true` | Specifies format of tools definition. `true`: use `toolsJSONPath`. `false`: extract from text using `<toolname>`/`<tooldescription>` tags. |
| azureAuth | object | No | - | How this API's embedding calls authenticate to Azure OpenAI: `authenticationType` (`api-key`, the default, `workload-identity`, `managed-identity` or `container-apps`), `clientId` (a GUID selecting the identity) and `scope` (default `https://cognitiveservices.azure.com/.default`). See [Azure Identity Authentication](#azure-identity-authentication). |

### System Parameters (From config.toml)

These parameters are configured in the gateway's `config.toml` to set up the embedding provider.

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| embeddingProvider | string | Yes | - | Embedding provider: `OPENAI`, `MISTRAL`, or `AZURE_OPENAI`. |
| embeddingEndpoint | string | Yes | - | Endpoint URL for the embedding service. |
| embeddingModel | string | Conditional | - | Model name (e.g., `text-embedding-3-small` or `mistral-embed`). Required for `OPENAI` and `MISTRAL`; optional for `AZURE_OPENAI` (deployment name is derived from the endpoint). |
| apiKey | string | Conditional | - | API key for the embedding service, sent by every API whose `azureAuth.authenticationType` is `api-key` (the default), unless the API has its own. The authentication header is set to `api-key` for Azure OpenAI and `Authorization` for other providers. Not needed when every API uses an Azure identity. |
| embeddingAllowedAuthTypes | array of strings | No | `[]` | If non-empty, the authentication types this gateway's APIs may choose in `azureAuth.authenticationType`: `api-key`, `workload-identity`, `managed-identity`, `container-apps`. An API without `azureAuth` counts as `api-key`. Empty places no limit. Set from the gateway's `embedding_provider_allowed_auth_types`; an API cannot set it. See [Limiting what APIs can use](#limiting-what-apis-can-use). |
| embeddingAllowedEndpoints | array of strings | No | `[]` | If non-empty, the embedding resources this gateway's APIs may call, including the gateway's own `embedding_provider_endpoint`. Entries are resource URLs such as `https://<resource>.openai.azure.com`, with no path, query or fragment. Empty places no limit. Set from the gateway's `embedding_provider_allowed_endpoints`; an API cannot set it. See [Limiting what APIs can use](#limiting-what-apis-can-use). |

#### Sample System Configuration

Add the following configuration section under the root level in your `config.toml` file:

```toml
embedding_provider = "MISTRAL" # Supported: MISTRAL, OPENAI, AZURE_OPENAI
embedding_provider_endpoint = "https://api.mistral.ai/v1/embeddings"
embedding_provider_model = "mistral-embed"
embedding_provider_dimension = 1024
embedding_provider_api_key = "" # Optional when every API uses an Azure identity

# Optional: limit what the gateway's APIs may use. Empty (the default) means no limit.
# Shared with semantic-cache (v1.4 and later) and semantic-prompt-guard (v1.2 and later).
embedding_provider_allowed_auth_types = []
embedding_provider_allowed_endpoints = []
```

### Azure Identity Authentication

An API whose `azureAuth.authenticationType` is an Azure identity sends `Authorization: Bearer <token>`,
a Microsoft Entra ID access token for the gateway's own identity, to Azure OpenAI, and never sends an API
key. There is no key to store or rotate, and once every API uses an identity the Azure OpenAI resource can
turn key access off. An API without `azureAuth` sends the API key, exactly as v1.0 does.

The identity types need `embeddingProvider` set to `AZURE_OPENAI`: the gateway's
`embedding_provider = "AZURE_OPENAI"`, or the same value in the API's params.

```yaml
operationPolicies:
  - name: semantic-tool-filtering
    version: v1
    paths:
      - path: /chat/completions
        methods: [POST]
        params:
          selectionMode: "By Rank"
          limit: 5
          azureAuth:
            authenticationType: container-apps
            # Optional: a user-assigned identity. Without it, the app's system-assigned identity is used.
            clientId: "<identity-client-id>"
```

| Authentication type | Where the gateway runs | Where the token comes from |
|---------------------|------------------------|----------------------------|
| `workload-identity` | AKS, with Workload Identity set up for the gateway runtime's service account | Microsoft Entra ID, in exchange for the pod's federated token |
| `managed-identity` | An Azure VM, VM scale set or AKS node with a managed identity | The Azure Instance Metadata Service (IMDS) |
| `container-apps` | An Azure Container Apps app with a managed identity | The identity endpoint Container Apps runs beside the app |

**Azure setup**

1. Give the gateway an identity: Workload Identity for the gateway runtime's service account on AKS, a
   managed identity assigned to the VM or node pool, or a system-assigned or user-assigned identity on the
   container app.
2. Grant that identity the **Cognitive Services OpenAI User** role on the Azure OpenAI resource:

   ```bash
   az role assignment create --assignee <identity-principal-id> --role "Cognitive Services OpenAI User" \
     --scope <azure-openai-resource-id>
   ```

3. Use the resource's custom subdomain, `https://<resource>.openai.azure.com`. The embeddings endpoint is
   the deployment URL on it, with the deployment name in the path:
   `https://<resource>.openai.azure.com/openai/deployments/<deployment>/embeddings?api-version=<version>`.
   Regional endpoints such as `https://eastus.api.cognitive.microsoft.com` don't accept Entra ID tokens.
4. Once the identity works, you can turn key access off on the resource
   (`az resource update --ids <azure-openai-resource-id> --set properties.disableLocalAuth=true`), so that
   only Entra ID tokens are accepted.

**Choosing the identity**

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

**How the token is used**

- The policy embeds nothing when the gateway builds the API's route: it embeds each request's query, and each
  tool it hasn't cached for the API yet, when the request arrives, so the first token is fetched with the
  first request. Both use the API's authentication. The Azure Identity SDK caches the token and refreshes
  it before it expires, so most requests don't make a token request. Every policy on the gateway that uses
  the same identity shares the cache.
- On gateways newer than 1.2.0, an API's route answers `500` when its policy can't be built: when its
  settings are invalid, when the gateway doesn't allow its authentication type or endpoint, when the
  gateway's host can't provide the identity, for example `container-apps` without `IDENTITY_ENDPOINT`. The
  gateway logs `Failed to build policy chain for route, skipping` at `ERROR`, with the reason.
- When no token can be obtained, the request goes on with every tool, unfiltered, like any other embedding
  failure: the policy never blocks a request, and the client sees no error. The policy logs it at `ERROR`,
  with the reason, which can describe the gateway's identity. A token request the identity service refused
  is answered again from a short cache for about two seconds, and logged at `DEBUG` while it is.
- A token Azure OpenAI refuses with `401` or `403` is handled the same way: the request keeps every tool,
  and the policy logs the status at `ERROR`. Azure OpenAI's answer, which can name the identity, is logged
  only at `DEBUG`, where it tells a missing role from a wrong scope or endpoint.
- APIs on the same gateway can authenticate differently: a key, the API's own or the gateway's, is sent only
  by the APIs that use `api-key`. With `api-key`, `clientId` and `scope` are ignored.
- The token goes to the endpoint in effect: the API's `embeddingEndpoint` if it sets one, otherwise the
  gateway's. An API can use its own Azure OpenAI resource this way, with an identity that has the role on
  it, or with its own `apiKey` in `api-key` mode, and the allowlists below apply to the endpoint it uses.

#### Limiting what APIs can use

`embedding_provider_allowed_auth_types` lists the authentication types the gateway's APIs may use, from
`api-key`, `workload-identity`, `managed-identity` and `container-apps`. An API whose type isn't listed is
refused, and an API without `azureAuth` counts as `api-key`.

- To stop APIs from sending the key, leave `api-key` out, for example `["workload-identity"]`. APIs that
  don't choose an identity are then refused instead of sending the key.
- To keep APIs off the gateway's identities, list only `api-key`.

`embedding_provider_allowed_endpoints` lists the embedding resources the gateway's APIs may call. An API can
set its own `embeddingEndpoint`, so without this list an API could have the gateway's key, or a token for the
gateway's identity, sent to a server of its choosing. The list is checked against the endpoint in effect, the
API's or the gateway's, so include the gateway's own `embedding_provider_endpoint`. Set it on every gateway
whose APIs use an Azure identity.

- Entries are resource URLs: a scheme, a host and optionally a port, such as
  `https://<resource>.openai.azure.com`. They match on scheme, host and port, ignoring case, so any
  deployment and `api-version` on a listed resource is allowed.
- An entry with a path other than `/`, a query or a fragment, or that isn't an `http` or `https` URL, is
  invalid. So is a host with non-ASCII characters. An invalid entry in either list refuses every API that
  uses the policy, so a typo is found at the first deployment.
- Both lists are empty by default, which places no limit. They are gateway settings, at the root like the
  other `embedding_provider_*` keys, and are shared with the semantic-cache (v1.4 and later) and
  semantic-prompt-guard (v1.2 and later) policies, so one setting limits all three. An API cannot set them in its params: the gateway rejects such an API.
- Both are checked when the route is built, before any embedding call, so a refused endpoint never receives
  the key or a token.

On gateways newer than 1.2.0, a refused authentication type or endpoint makes the API's route answer
`500`, with the reason in the gateway log.

```toml
embedding_provider = "AZURE_OPENAI"
embedding_provider_endpoint = "https://<resource>.openai.azure.com/openai/deployments/<deployment>/embeddings?api-version=<version>"
# No embedding_provider_api_key is needed when every API uses an identity.

embedding_provider_allowed_auth_types = ["workload-identity"]
embedding_provider_allowed_endpoints = ["https://<resource>.openai.azure.com"]
```

**Troubleshooting**

- The API's route answers `500`: look for `Failed to build policy chain for route, skipping` in the gateway
  log. Its reason names the refused setting or the missing environment variable. The gateway doesn't retry
  that build on its own: after fixing the cause (the allowlists, the environment variables or the key),
  redeploy or update the API so its route is built again.
- The tools reach the LLM unfiltered: the embedding failed and the request went on with every tool. Look
  for the `ERROR` lines below.
- Azure OpenAI answers `401`: the identity lacks the Cognitive Services OpenAI User role (role assignments
  can take several minutes to apply), the endpoint is a regional one, or the token scope is for another
  resource, such as `https://management.azure.com/.default`. Use `https://cognitiveservices.azure.com/.default`,
  the default. For an API that uses an Azure identity, a `401` or `403` at request time is logged at `ERROR`
  as `SemanticToolFiltering: the embedding provider refused the access token`, with the status, the
  authentication type, the identity's client ID and the scope.
- The `ERROR` log line `SemanticToolFiltering: could not obtain an access token for the embedding provider`
  carries the reason, such as the Microsoft Entra ID response, and the identity's client ID.

**Security considerations**

- **Least privilege**: grant the identity the Cognitive Services OpenAI User role on the Azure OpenAI
  resource only, rather than on a resource group or subscription.
- **Who configures an API chooses its identity and endpoint**: whoever creates an API with this policy
  chooses which of the gateway's identities its embedding calls use, the token scope, and the endpoint the
  token is sent to. Without `embedding_provider_allowed_endpoints`, they can have a token for any identity
  the gateway can use sent to a server of their choosing, just as they can have the gateway's key sent there
  in `api-key` mode. List the gateway's Azure OpenAI resources in `embedding_provider_allowed_endpoints`, use
  `embedding_provider_allowed_auth_types` to keep APIs to the types you intend, and give the gateway's
  identities only the roles its APIs need.
- **No stored secret**: with an Azure identity, no key is stored in the gateway's configuration or sent to
  Azure OpenAI, and the tokens are short lived.

**Upgrading from v1.0**

- An API that sets nothing keeps sending the gateway's key, exactly as v1.0 does. An API that sets its own
  endpoint or key, or overrides any other setting, keeps doing so.
- The only parameters v1.1 refuses in an API definition are `embeddingAllowedAuthTypes` and
  `embeddingAllowedEndpoints`, which only the gateway can set.

**Gateway versions**

v1.1 needs Go 1.26.10 or later to build. The latest gateway's builder has it. A 1.2.0 gateway's builder
downloads a newer Go during the build, so the build machine needs internet access. A 1.1.0 gateway's builder
can't build v1.1: pin the policy to `@v1.0.2` in `build.yaml` before rebuilding, because `@v1` would pick
v1.1.


### build.yaml

Add the following entry to the `policies` section in `/gateway/build.yaml`:

```yaml
- name: semantic-tool-filtering
  gomodule: github.com/wso2/gateway-controllers/policies/semantic-tool-filtering@v1
```

## Reference Scenarios

### Scenario 1: Filtering Tools by Rank (JSON Format)

This scenario demonstrates filtering tools to select the top 3 most relevant ones based on a user query in a JSON payload.

**Configuration:**

```yaml
type: http
policies:
  - policy:
      name: semantic-tool-filtering
      parameters:
        selectionMode: "By Rank"
        limit: 3
        queryJSONPath: "$.contents[0].parts[0].text"
        toolsJSONPath: "$.tools[0].function_declarations"
        userQueryIsJson: true
        toolsIsJson: true
```

**Request:**

```json
{
  "contents": [
    {
      "role": "user",
      "parts": [
        {
          "text": "Get weather forecast. what are the tools you have?"
        }
      ]
    }
  ],
  "tools": [
    {
      "function_declarations": [
        {
          "name": "get_weather",
          "description": "Get current weather and 7-day forecast for a location.",
          "parameters": { "type": "OBJECT", "properties": { "location": { "type": "string" } }, "required": ["location"] }
        },
        {
          "name": "book_venue",
          "description": "Reserve a conference room or meeting space.",
          "parameters": { "type": "OBJECT", "properties": { "location": { "type": "string" } }, "required": ["location"] }
        },
        {
           "name": "send_email",
           "description": "Send an email to a specific recipient.",
           "parameters": { "type": "OBJECT", "properties": { "recipient": { "type": "string" } }, "required": ["recipient"] }
        }
      ]
    }
  ]
}
```

The policy will interpret the request, calculate embeddings, and filter the `tools` array to include only the top 3 matches (e.g., `get_weather`, `book_venue`, `send_email`).

### Scenario 1b: OpenAI/Mistral-style Function Wrappers

If the request wraps each tool as an object with a nested `function`, configure the iterator path so the policy reads `name` and `description` from the nested object while still filtering the parent `tools` array.

**Configuration:**

```yaml
type: http
policies:
  - policy:
      name: semantic-tool-filtering
      parameters:
        selectionMode: "By Rank"
        limit: 3
        queryJSONPath: "$.messages[-1].content"
        toolsJSONPath: "$.tools[*].function"
        userQueryIsJson: true
        toolsIsJson: true
```

**Request:**

```json
{
  "messages": [
    {
      "role": "user",
      "content": "What tools can help me check the weather?"
    }
  ],
  "tools": [
    {
      "type": "function",
      "function": {
        "name": "get_weather",
        "description": "Get current weather"
      }
    },
    {
      "type": "function",
      "function": {
        "name": "send_email",
        "description": "Send an email notification"
      }
    }
  ]
}
```

### Scenario 2: Filtering Tools by Threshold

In this scenario, only tools with a semantic similarity score of 0.7 or higher are included.

**Configuration:**

```yaml
policies:
  - policy:
      name: semantic-tool-filtering
      parameters:
        selectionMode: "By Threshold"
        threshold: 0.7
        # Rest of the parameters
```

### Scenario 3: Text Format (XML-like Tags)

This scenario handles cases where the user query and tool definitions are embedded in a text payload using custom tags.

**Configuration:**

```yaml
policies:
  - policy:
      name: semantic-tool-filtering
      parameters:
        selectionMode: "By Rank"
        limit: 3
        userQueryIsJson: false
        toolsIsJson: false
        queryJSONPath: "$.messages[-1].content.text"
        toolsJSONPath: "$.messages[-1].content.text"

```

**Request Body:**

```json
{
  "contents": [
    {
      "parts": [
        {
          "text": "You are a logistics assistant with access to the following tools:\n\n<toolname>get_weather</toolname><tooldescription>Get current weather and 7-day forecast for a location</tooldescription>\n<toolname>book_venue</toolname><tooldescription>Reserve meeting spaces</tooldescription>\n\n<userq>I'm planning a corporate retreat in Denver next weekend. Check the weather.</userq>"
        }
      ]
    }
  ]
}
```

The policy extracts `<userq>` as the query and `<toolname>`/`<tooldescription>` as tools, then performs filtering. After the filtering process, the tags are removed.
