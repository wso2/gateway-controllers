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

## Configuration

The Semantic Prompt Guardrail policy uses a two-level configuration

### System Parameters (From config.toml)

These parameters are usually set at the gateway level and automatically applied, but they can also be overridden in the params section of an API artifact definition. System-wide defaults can be configured in the gateway’s `config.toml` file, and while these defaults apply to all Semantic Prompt Guardrail policy instances, they can be customized for individual policies within the API configuration when necessary.

##### Embedding Provider Configuration

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `embeddingProvider` | string | Yes | Embedding provider type. Must be one of: `OPENAI`, `MISTRAL`, `AZURE_OPENAI` |
| `embeddingEndpoint` | string | Yes | Endpoint URL for the embedding service. Examples: OpenAI: `https://api.openai.com/v1/embeddings`, Mistral: `https://api.mistral.ai/v1/embeddings`, Azure OpenAI: Your Azure OpenAI endpoint URL |
| `embeddingModel` | string | Conditional | - | Embedding model name. **Required for OPENAI and MISTRAL**, not required for AZURE_OPENAI (deployment name is in endpoint URL). Examples: OpenAI: `text-embedding-ada-002` or `text-embedding-3-small`, Mistral: `mistral-embed` |
| `apiKey` | string | Yes | API key for the embedding service authentication |

#### Sample System Configuration

Add the following configuration section under the root level in your `config.toml` file:

```toml
embedding_provider = "MISTRAL" # Supported: MISTRAL, OPENAI, AZURE_OPENAI
embedding_provider_endpoint = "https://api.mistral.ai/v1/embeddings"
embedding_provider_model = "mistral-embed"
embedding_provider_dimension = 1024
embedding_provider_api_key = ""
```

### User Parameters (API Definition)

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `jsonPath` | string | No | `""` | JSONPath expression to extract the prompt from JSON payload. If empty, validates the entire payload as a string. Examples: `"$.messages[0].content"`, `"$.prompt"` |
| `allowSimilarityThreshold` | number | No | `0.65` | Minimum similarity threshold (0.0 to 1.0) for a prompt to be considered similar to an allowed phrase. Higher values mean stricter matching. |
| `denySimilarityThreshold` | number | No | `0.65` | Similarity threshold (0.0 to 1.0) for blocking against denied phrases. If any denied phrase has similarity >= this threshold, the request is blocked. |
| `allowedPhrases` | array | No* | `[]` | List of phrases that are considered safe. The prompt must match one of these within `allowSimilarityThreshold` when allow-list validation is configured. |
| `deniedPhrases` | array | No* | `[]` | List of phrases that should block the prompt when similar within `denySimilarityThreshold`. |
| `showAssessment` | boolean | No | `false` | If `true`, includes detailed assessment information in error responses. If `false`, returns minimal error information. |

\* At least one of `allowedPhrases` or `deniedPhrases` must be provided.

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
  gomodule: github.com/wso2/gateway-controllers/policies/semantic-prompt-guard@v0
```

## Reference Scenarios

### Example 1: Deny List Only - Blocking Prohibited Content

Deploy an LLM provider that blocks prompts similar to prohibited phrases:

```yaml
apiVersion: gateway.api-platform.wso2.com/v1alpha1
kind: LlmProvider
metadata:
  name: semantic-guard-provider
spec:
  displayName: Semantic Guard Provider
  version: v1.0
  template: openai
  vhost: openai
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
  policies:
    - name: semantic-prompt-guard
      version: v0
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

**Note**: Ensure that "openai" is mapped to the appropriate IP address (e.g., 127.0.0.1) in your `/etc/hosts` file, or remove the vhost from the LLM provider configuration and use localhost to invoke.

```bash
# Valid request (should pass)
curl -X POST http://openai:8080/chat/completions \
  -H "Content-Type: application/json" \
  -H "Host: openai" \
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
curl -X POST http://openai:8080/chat/completions \
  -H "Content-Type: application/json" \
  -H "Host: openai" \
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
apiVersion: gateway.api-platform.wso2.com/v1alpha1
kind: LlmProvider
metadata:
  name: whitelist-provider
spec:
  displayName: Whitelist Provider
  version: v1.0
  template: openai
  vhost: openai
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
  policies:
    - name: semantic-prompt-guard
      version: v0
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
policies:
  - name: semantic-prompt-guard
    version: v0
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
policies:
  - name: semantic-prompt-guard
    version: v0
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
