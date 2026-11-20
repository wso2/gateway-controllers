---
title: "Overview"
---
# Semantic Prompt Guardrail

## Overview

The Semantic Prompt Guardrail validates prompts using semantic similarity matching against configured allow and deny phrase lists. Unlike keyword-based filtering, this guardrail understands the meaning of prompts by converting them to vector embeddings and comparing them using cosine similarity. This enables more intelligent content filtering that can catch semantically similar content even when exact keywords differ.

The policy uses embedding models (OpenAI, Mistral, or Azure OpenAI) to convert prompts and configured phrases into high-dimensional vectors, then performs similarity comparisons. Prompts are blocked if they are too similar to denied phrases or not similar enough to allowed phrases, based on configurable similarity thresholds.

## Features

- **Semantic similarity matching**: Uses embeddings to understand meaning, not just keywords
- **Allow/Deny phrase lists**: Configure lists of allowed and denied phrases for flexible filtering
- **Configurable similarity thresholds**: Control matching sensitivity separately for allow and deny lists (0.0 to 1.0)
- **Multiple embedding provider support**: Works with OpenAI, Mistral, and Azure OpenAI embedding services
- **JSONPath extraction**: Extract specific fields from request body for validation
- **Detailed assessment information**: Optional detailed violation information in error responses
- **Azure identity authentication**: From v1.2, an API can get embeddings from Azure OpenAI with a Microsoft Entra ID access token for the gateway's own Azure identity (AKS Workload Identity, a managed identity of the VM or AKS node, or of the Azure Container Apps app) instead of an API key, and the gateway can limit which authentication types and embedding endpoints its APIs use

## Configuration

The Semantic Prompt Guardrail policy uses a two-level configuration.

### System Parameters (From config.toml)

These parameters are usually set at the gateway level and automatically applied, but they can also be overridden in the params section of an API artifact definition. System-wide defaults can be configured in the gateway's `config.toml` file, and while these defaults apply to all Semantic Prompt Guardrail policy instances, they can be customized for individual policies within the API configuration when necessary.

##### Embedding Provider Configuration

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `embeddingProvider` | string | Yes | Embedding provider type. Must be one of: `OPENAI`, `MISTRAL`, `AZURE_OPENAI` |
| `embeddingEndpoint` | string | Yes | Endpoint URL for the embedding service. Examples: OpenAI: `https://api.openai.com/v1/embeddings`, Mistral: `https://api.mistral.ai/v1/embeddings`, Azure OpenAI: Your Azure OpenAI endpoint URL |
| `embeddingModel` | string | Conditional | - | Embedding model name. **Required for OPENAI and MISTRAL**, not required for AZURE_OPENAI (deployment name is in endpoint URL). Examples: OpenAI: `text-embedding-ada-002` or `text-embedding-3-small`, Mistral: `mistral-embed` |
| `apiKey` | string | Conditional | API key for the embedding service authentication, sent by every API whose `azureAuth.authenticationType` is `api-key` (the default), unless the API has its own. The authentication header is automatically set to `api-key` for Azure OpenAI and `Authorization` for other providers. Not needed when every API uses an Azure identity. |
| `embeddingAllowedAuthTypes` | array of strings | No | If non-empty, the authentication types this gateway's APIs may choose in `azureAuth.authenticationType`: `api-key`, `workload-identity`, `managed-identity`, `container-apps`. An API without `azureAuth` counts as `api-key`. Empty (the default) places no limit. Set from the gateway's `embedding_provider_allowed_auth_types`; an API cannot set it. See [Limiting what APIs can use](#limiting-what-apis-can-use). |
| `embeddingAllowedEndpoints` | array of strings | No | If non-empty, the embedding resources this gateway's APIs may call, including the gateway's own `embedding_provider_endpoint`. Entries are resource URLs such as `https://<resource>.openai.azure.com`, with no path, query or fragment. Empty (the default) places no limit. Set from the gateway's `embedding_provider_allowed_endpoints`; an API cannot set it. See [Limiting what APIs can use](#limiting-what-apis-can-use). |

#### Sample System Configuration

Add the following configuration section under the root level in your `config.toml` file:

```toml
embedding_provider = "MISTRAL" # Supported: MISTRAL, OPENAI, AZURE_OPENAI
embedding_provider_endpoint = "https://api.mistral.ai/v1/embeddings"
embedding_provider_model = "mistral-embed"
embedding_provider_dimension = 1024
embedding_provider_api_key = "" # Optional when every API uses an Azure identity

# Optional: limit what the gateway's APIs may use. Empty (the default) means no limit.
# Shared with the semantic-cache policy (v1.4 and later).
embedding_provider_allowed_auth_types = []
embedding_provider_allowed_endpoints = []
```

### User Parameters (API Definition)

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `jsonPath` | string | No | `"$.messages[-1].content"` | JSONPath expression to extract the prompt from JSON payload. If empty, validates the entire payload as a string. Examples: `"$.messages[-1].content"`, `"$.prompt"` |
| `azureAuth` | `azureAuth` object | No | `api-key` | How this API's embedding calls authenticate to Azure OpenAI. Without it, they send the API key. The identity types need `embeddingProvider` set to `AZURE_OPENAI`. See [Azure Identity Authentication](#azure-identity-authentication). |
| `allowSimilarityThreshold` | number | No | `0.65` | Minimum similarity threshold (0.0 to 1.0) for a prompt to be considered similar to an allowed phrase. Higher values mean stricter matching. |
| `denySimilarityThreshold` | number | No | `0.65` | Similarity threshold (0.0 to 1.0) for blocking against denied phrases. If any denied phrase has similarity >= this threshold, the request is blocked. |
| `allowedPhrases` | array | No* | `[]` | List of phrases that are considered safe. The prompt must match one of these within `allowSimilarityThreshold` when allow-list validation is configured. |
| `deniedPhrases` | array | No* | `[]` | List of phrases that should block the prompt when similar within `denySimilarityThreshold`. |
| `showAssessment` | boolean | No | `false` | If `true`, includes detailed assessment information in error responses. If `false`, returns minimal error information. |

\* At least one of `allowedPhrases` or `deniedPhrases` must be provided.

| `azureAuth` field | Type | Required | Default | Description |
|-------------------|------|----------|---------|-------------|
| `authenticationType` | string | No | `api-key` | `api-key` sends the API key, the API's own `apiKey` or the gateway's `embedding_provider_api_key`. `workload-identity`, `managed-identity` and `container-apps` send an access token for the gateway's Azure identity and need the `AZURE_OPENAI` embedding provider. |
| `clientId` | string | No | - | With an Azure identity, the client ID of the identity, as a GUID. Defaults to `AZURE_CLIENT_ID` for `workload-identity`; with `managed-identity` or `container-apps`, selects a user-assigned identity, and is left unset for the system-assigned one. Ignored with `api-key`. |
| `scope` | string | No | `https://cognitiveservices.azure.com/.default` | With an Azure identity, the scope of the access token. Ignored with `api-key`. |

An API can also set its own `embeddingEndpoint`, and `apiKey` in `api-key` mode, instead of the gateway's. It cannot set `embeddingAllowedAuthTypes` or `embeddingAllowedEndpoints`: the gateway rejects an API that does.

#### JSONPath Support

The guardrail supports JSONPath expressions to extract specific text from request bodies before validation. This is useful for:
- Extracting message content from chat completion requests
- Focusing on specific prompt fields while ignoring metadata
- Handling structured JSON payloads

**Common JSONPath Examples**

- `$.messages[0].content` - First message's content in chat completions
- `$.messages[-1].content` - Last message's content
- `$.prompt` - Extract prompt field from completions API
- `$.input` - Extract input field from embeddings API
- `$` - Entire request body (default if jsonPath is not specified)

**Note:**

Inside the `gateway/build.yaml`, ensure the policy module is added under `policies:`:

```yaml
- name: semantic-prompt-guard
  gomodule: github.com/wso2/gateway-controllers/policies/semantic-prompt-guard@v1
```

### Azure Identity Authentication

An API whose `azureAuth.authenticationType` is an Azure identity sends `Authorization: Bearer <token>`,
a Microsoft Entra ID access token for the gateway's own identity, to Azure OpenAI, and never sends an API
key. There is no key to store or rotate, and once every API uses an identity the Azure OpenAI resource can
turn key access off. An API without `azureAuth` sends the API key, exactly as v1.1 does.

The identity types need `embeddingProvider` set to `AZURE_OPENAI`: the gateway's
`embedding_provider = "AZURE_OPENAI"`, or the same value in the API's params.

```yaml
operationPolicies:
  - name: semantic-prompt-guard
    version: v1
    paths:
      - path: /chat/completions
        methods: [POST]
        params:
          deniedPhrases:
            - "hack the system"
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

- The policy embeds its allowed and denied phrases when the gateway builds the API's route, and each prompt
  when it arrives. Both use the API's authentication. The Azure Identity SDK caches the token and refreshes
  it before it expires, so most requests don't make a token request. Every policy on the gateway that uses
  the same identity shares the cache.
- On gateways newer than 1.2.0, an API's route answers `500` when its policy can't be built: when its
  settings are invalid, when the gateway doesn't allow its authentication type or endpoint, when the
  gateway's host can't provide the identity, for example `container-apps` without `IDENTITY_ENDPOINT`, or
  when the phrases can't be embedded, for example because no access token could be obtained or Azure OpenAI
  refused it. The gateway logs `Failed to build policy chain for route, skipping` at `ERROR`, with the reason.
- A prompt whose token can't be obtained is rejected with `422` and fault `960000`, like any other embedding
  failure, so a broken identity never lets prompts through unchecked. The policy logs it at `ERROR`. With
  `showAssessment`, the response says only `Could not obtain an access token for the embedding provider`:
  the reason, which can describe the gateway's identity, is in the log and in the fault's description. A
  token request the identity service refused is answered again from a short cache for about two seconds,
  and logged at `DEBUG` while it is.
- A token Azure OpenAI refuses with `401` or `403` is rejected the same way. With `showAssessment`, the
  response says only `The embedding provider refused the access token`, and the fault's description carries
  the status. Azure OpenAI's answer, which can name the identity, is not passed on; it is logged only at
  `DEBUG`, where it tells a missing role from a wrong scope or endpoint.
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
  other `embedding_provider_*` keys, and are shared with the semantic-cache policy (v1.4 and later), so one
  setting limits both. An API cannot set them in its params: the gateway rejects such an API.
- Both are checked before the phrases are embedded, so a refused endpoint never receives the key or a token.

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
  log. Its reason names the refused setting, the missing environment variable, or the failed phrase
  embeddings.
- Azure OpenAI answers `401`: the identity lacks the Cognitive Services OpenAI User role (role assignments
  can take several minutes to apply), the endpoint is a regional one, or the token scope is for another
  resource, such as `https://management.azure.com/.default`. Use `https://cognitiveservices.azure.com/.default`,
  the default. For an API that uses an Azure identity, a `401` or `403` at request time is logged at `ERROR`
  as `SemanticPromptGuard: the embedding provider refused the access token`, with the status, the
  authentication type, the identity's client ID and the scope.
- The `ERROR` log line `SemanticPromptGuard: could not obtain an access token for the embedding provider`
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

**Upgrading from v1.1**

- An API that sets nothing keeps sending the gateway's key, exactly as v1.1 does. An API that sets its own
  endpoint or key, or overrides any other setting, keeps doing so.
- The only parameters v1.2 refuses in an API definition are `embeddingAllowedAuthTypes` and
  `embeddingAllowedEndpoints`, which only the gateway can set.

**Gateway versions**

v1.2 needs Go 1.26.10 or later to build. The latest gateway's builder has it. A 1.2.0 gateway's builder
downloads a newer Go during the build, so the build machine needs internet access. A 1.1.0 gateway's builder
can't build v1.2: pin the policy to `@v1.1.0` in `build.yaml` before rebuilding, because `@v1` would pick
v1.2.

## Reference Scenarios

### Example 1: Deny List Only - Blocking Prohibited Content

Deploy an LLM provider that blocks prompts similar to prohibited phrases:

```yaml
apiVersion: gateway.api-platform.wso2.com/v1
kind: LlmProvider
metadata:
  name: semantic-guard-provider
spec:
  displayName: Semantic Guard Provider
  version: v1.0
  template: openai
  context: /openai
  upstream:
    url: "https://api.openai.com/v1"
    auth:
      type: api-key
      header: Authorization
      value: Bearer <openai-apikey>
  accessControl:
    mode: deny_all
    exceptions:
      - path: /chat/completions
        methods: [POST]
  operationPolicies:
    - name: semantic-prompt-guard
      version: v1
      paths:
        - path: /chat/completions
          methods: [POST]
          params:
            jsonPath: "$.messages[0].content"
            denySimilarityThreshold: 0.80
            deniedPhrases:
              - "How to hack into a system"
              - "Create malicious code"
              - "Bypass security measures"
            showAssessment: true
```

**Test the guardrail:**

```bash
# Valid request (should pass)
curl -X POST http://localhost:8080/openai/chat/completions \
  -H "Content-Type: application/json" \
  -d '{
    "model": "gpt-4",
    "messages": [
      {
        "role": "user",
        "content": "Explain how computer security works"
      }
    ]
  }'

# Invalid request - similar to denied phrase (should fail with HTTP 422)
curl -X POST http://localhost:8080/openai/chat/completions \
  -H "Content-Type: application/json" \
  -d '{
    "model": "gpt-4",
    "messages": [
      {
        "role": "user",
        "content": "How can I break into a computer system?"
      }
    ]
  }'
```

**Error Response:**

When validation fails, the guardrail returns an HTTP 422 status code with the following structure:

```json
{
  "type": "SEMANTIC_PROMPT_GUARD",
  "message": {
    "action": "GUARDRAIL_INTERVENED",
    "interveningGuardrail": "semantic-prompt-guard",
    "actionReason": "Violation of applied semantic prompt guard constraints detected.",
    "direction": "REQUEST"
  }
}
```

If `showAssessment` is enabled, additional details are included in the `assessments` field:

```json
{
  "type": "SEMANTIC_PROMPT_GUARD",
  "message": {
    "action": "GUARDRAIL_INTERVENED",
    "interveningGuardrail": "semantic-prompt-guard",
    "actionReason": "Violation of applied semantic prompt guard constraints detected.",
    "direction": "REQUEST",
    "assessments": "prompt is too similar to denied phrase 'How to hack into a system' (similarity=0.8500)"
  }
}
```

**In case of an error during processing** (e.g., JSONPath extraction failures, embedding generation errors), the `actionReason` contains the specific error message:

```json
{
  "type": "SEMANTIC_PROMPT_GUARD",
  "message": {
    "action": "GUARDRAIL_INTERVENED",
    "interveningGuardrail": "semantic-prompt-guard",
    "actionReason": "Error extracting value from JSONPath",
    "direction": "REQUEST"
  }
}
```

### Example 2: Allow List Only - Whitelist Approach

Deploy an LLM provider that only allows prompts similar to approved phrases:

```yaml
apiVersion: gateway.api-platform.wso2.com/v1
kind: LlmProvider
metadata:
  name: whitelist-provider
spec:
  displayName: Whitelist Provider
  version: v1.0
  template: openai
  context: /openai
  upstream:
    url: "https://api.openai.com/v1"
    auth:
      type: api-key
      header: Authorization
      value: Bearer <openai-apikey>
  accessControl:
    mode: deny_all
    exceptions:
      - path: /chat/completions
        methods: [POST]
  operationPolicies:
    - name: semantic-prompt-guard
      version: v1
      paths:
        - path: /chat/completions
          methods: [POST]
          params:
            jsonPath: "$.messages[0].content"
            allowSimilarityThreshold: 0.75
            allowedPhrases:
              - "How can I help you with customer service?"
              - "What product information do you need?"
              - "Tell me about your order status"
              - "I need help with my account"
```

**Allow list Violations:**
For an allow list violations, the assessment message format is:

```json
{
  "type": "SEMANTIC_PROMPT_GUARD",
  "message": {
    "action": "GUARDRAIL_INTERVENED",
    "interveningGuardrail": "semantic-prompt-guard",
    "actionReason": "Violation of applied semantic prompt guard constraints detected.",
    "direction": "REQUEST",
    "assessments": "prompt is not similar enough to allowed phrases (similarity=0.6000 < threshold=0.6500)"
  }
}
```

### Example 3: Combined Allow and Deny Lists

Use both allow and deny lists for comprehensive filtering:

```yaml
operationPolicies:
  - name: semantic-prompt-guard
    version: v1
    paths:
      - path: /chat/completions
        methods: [POST]
        params:
          jsonPath: "$.messages[0].content"
          allowSimilarityThreshold: 0.70
          denySimilarityThreshold: 0.75
          allowedPhrases:
            - "Customer service inquiry"
            - "Product information request"
            - "Technical support question"
          deniedPhrases:
            - "How to hack"
            - "Create malware"
            - "Bypass authentication"
          showAssessment: true
```

### Example 4: Azure OpenAI with Custom Timeout

Configure semantic prompt guardrail with Azure OpenAI and extended timeout:

```yaml
operationPolicies:
  - name: semantic-prompt-guard
    version: v1
    paths:
      - path: /chat/completions
        methods: [POST]
        params:
          jsonPath: "$.messages[-1].content"
          denySimilarityThreshold: 0.80
          deniedPhrases:
            - "Prohibited content example"
            - "Another prohibited phrase"
```

## How It Works

#### Request Phase

1. **Text Extraction**: Extracts prompt text from the request body using JSONPath (if configured) or uses the entire request body.
2. **Embedding Generation**: Generates a vector embedding from the extracted prompt using the configured embedding provider.
3. **Validation Strategy**: Applies deny-list checks, allow-list checks, or both, depending on configured phrase lists and thresholds.
4. **Decision Enforcement**: Blocks with HTTP `422` when validation fails; otherwise, request proceeds upstream.

#### Validation Strategy

- **Deny list only**: Compares prompt embedding against all denied phrases. If any denied phrase has similarity >= `denySimilarityThreshold`, the request is blocked.
- **Allow list only**: Compares prompt embedding against all allowed phrases. If no allowed phrase has similarity >= `allowSimilarityThreshold`, the request is blocked.
- **Both lists**: Checks deny list first (blocks on deny match), then checks allow list (blocks on allow miss). Request proceeds only if both checks pass.

#### Similarity Thresholds

- **Allow threshold (`allowSimilarityThreshold`)**: Controls minimum similarity required for allow-list matching.
- **Deny threshold (`denySimilarityThreshold`)**: Controls similarity level that triggers deny-list blocking.
- **Strict matching (`0.85-1.0`)**: Captures near-identical semantics with fewer broad matches.
- **Balanced matching (`0.70-0.84`)**: Recommended for most production use cases.
- **Flexible matching (`0.60-0.69`)**: Broad matching with higher false positive/negative risk depending on list quality.

#### Performance

- **Embedding Generation Latency**: Embedding generation adds approximately `100-500ms` per request.
- **Batch Initialization**: Allow/deny phrase embeddings are generated in batch during policy initialization.
- **Similarity Computation**: Cosine similarity calculations are typically fast (< `10ms`) even with moderate phrase lists.
- **Provider Trade-offs**: OpenAI, Mistral, and Azure OpenAI each have different latency and deployment characteristics.

## Notes

- The policy validates prompts in the request phase only (before sending to LLM). Response validation is not supported.

- Embeddings for allow/deny phrases are generated automatically during policy initialization. Ensure the embedding provider is accessible at initialization time.

- The policy uses cosine similarity to compare embeddings. This is optimal for semantic similarity matching.

- At least one of `allowedPhrases` or `deniedPhrases` must be provided. An empty list for both will cause policy initialization to fail.

- Similarity thresholds are independent for allow and deny lists. You can use different thresholds for each list based on your requirements.

- JSONPath extraction is optional. If not specified, the entire request body (as string) is used for embedding generation.

- The `embeddingModel` parameter is required for `OPENAI` and `MISTRAL` providers, but not for `AZURE_OPENAI` (the deployment name is included in the endpoint URL).

- For Azure OpenAI, the authentication header is automatically set to `api-key`. For other providers, it's set to `Authorization`.

- The policy processes all phrases in batch during initialization for efficiency. Large phrase lists (100+ phrases) may take a few seconds to initialize.

- Similarity scores range from 0.0 (no similarity) to 1.0 (identical meaning). Higher thresholds mean stricter matching.

- For production deployments, monitor false positive/negative rates and adjust similarity thresholds accordingly.

## Fault reporting

From v1.1, every rejection this policy makes is also reported to the gateway as a **fault**:
a stable code and type alongside the response. A gateway that supports fault policies uses it
for the analytics event and hands it to the API's fault policies (for example `log-message`, to
log the failure). The status and body the client receives are the same as in v1.0. A gateway
without fault policy support ignores the fault, and the policy behaves exactly as v1.0.

A guardrail verdict has type `guardrail` and a code from the guardrail block (`906000`–`906399`).
It also names the intervening guardrail (`SemanticPromptGuard`) and records that it intervened; the
assessment is attached only when `showAssessment` is enabled, because it can hold the blocked content.
A rejection made without a similarity verdict carries no guardrail details: a prompt that cannot
be read is reported as `960001` (`validation`), because it is the caller's, and a comparison the
policy cannot compute as `960000` (`mediation`).

The policy checks the request only.

| When | Status | Code | Type |
|------|--------|------|------|
| The prompt's similarity to a denied phrase reaches `denySimilarityThreshold` | `422` | `906301` | `guardrail` |
| The prompt's similarity to every allowed phrase is below `allowSimilarityThreshold` | `422` | `906301` | `guardrail` |
| The value at `jsonPath` cannot be extracted, or the extracted prompt is empty | `422` | `960001` | `validation` |
| The prompt's embedding cannot be generated, or its similarity cannot be calculated | `422` | `960000` | `mediation` |
| An API that uses an Azure identity has no access token for the prompt's embedding, or Azure OpenAI refuses it with `401` or `403` | `422` | `960000` | `mediation` |

The fault's `Description` carries the internal reason, for example
`prompt is too similar to denied phrase '<phrase>' (similarity=0.9123)`.
It is passed to fault policies and analytics only, never to the client. For an Azure identity's missing
or refused token, it carries the reason or the status, which the response body never does.
