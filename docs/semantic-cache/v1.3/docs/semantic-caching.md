---
title: "Overview"
---
# Semantic Caching

## Overview

The Semantic Cache policy enables intelligent response caching for LLM (Large Language Model) APIs using vector similarity search. Unlike traditional key-based caching, semantic caching understands the meaning of requests and can serve cached responses for semantically similar queries, even when the exact wording differs. This dramatically improves performance and reduces costs by avoiding redundant API calls to upstream LLM services.

The policy uses embedding models to convert request text into high-dimensional vectors, then performs similarity searches in a vector database to find previously cached responses. If a similar request is found within the configured similarity threshold, the cached response is returned immediately without calling the upstream service.

Cache entries are scoped to the authenticated caller (application/subscriber identity) in addition to the API/route, so a response produced for one caller is never served to a different caller.

## Features

- **Vector-based similarity matching**: Uses embeddings to find semantically similar requests, not just exact matches
- **Multiple embedding provider support**: Works with OpenAI, Mistral, and Azure OpenAI embedding services
- **Multiple vector database support**: Supports Redis and Milvus as vector storage backends
- **Configurable similarity threshold**: Control cache hit sensitivity (0.0 to 1.0)
- **JSONPath extraction**: Extract specific fields from request body for embedding generation
- **Per-caller cache isolation**: Cache entries are bound to the authenticated caller identity; no cross-caller sharing by default
- **Cacheability gate**: Responses marked `Cache-Control: no-store`, `private`, or `no-cache` are never cached
- **Optional Jev cache admission**: Ask TypeSafe Jev whether a response is suitable to reuse before writing it
- **Automatic cache management**: Stores eligible successful responses (200) automatically after upstream calls
- **Immediate response on cache hit**: Returns cached response with `X-Cache-Status: HIT` header without upstream call
- **TTL support**: Configurable time-to-live for cache entries


## Configuration

The Semantic Cache policy uses a two-level configuration

### System Parameters (From config.toml)

These parameters are usually set at the gateway level and automatically applied, but they can also be overridden in the params section of an API artifact definition. System-wide defaults can be configured in the gateway's `config.toml` file, and while these defaults apply to all Semantic Cache policy instances, they can be customized for individual policies within the API configuration when necessary.

#### Embedding Provider Configuration

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `embeddingProvider` | string | Yes | Embedding provider type. Must be one of: `OPENAI`, `MISTRAL`, `AZURE_OPENAI` |
| `embeddingEndpoint` | string | Yes | Endpoint URL for the embedding service. Examples: OpenAI: `https://api.openai.com/v1/embeddings`, Mistral: `https://api.mistral.ai/v1/embeddings`, Azure OpenAI: Your Azure OpenAI endpoint URL |
| `embeddingModel` | string | Conditional | Embedding model name. **Required for OPENAI and MISTRAL**, not required for AZURE_OPENAI (deployment name is in endpoint URL). Examples: OpenAI: `text-embedding-ada-002` or `text-embedding-3-small`, Mistral: `mistral-embed` |
| `embeddingDimension` | integer | Yes | Dimension of embedding vectors. Common values: 1536 (OpenAI ada-002), 1024 (Mistral). Must match the model's output dimension. |
| `apiKey` | string | Yes | API key for the embedding service authentication. The authentication header is automatically set to `api-key` for Azure OpenAI and `Authorization` for other providers. |

#### Vector Database Configuration

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `vectorStoreProvider` | string | Yes | Vector database provider. Must be one of: `REDIS`, `MILVUS` |
| `dbHost` | string | Yes | Vector database host address |
| `dbPort` | integer | Yes | Vector database port number |
| `username` | string | No | Database username for authentication (if required) |
| `password` | string | No | Database password for authentication (if required) |
| `database` | string | No | Database name or index number (for Redis) |
| `ttl` | integer | No | Time-to-live for cache entries in seconds. Default is 3600 (1 hour). Set to 0 for no expiration. |

#### Optional TypeSafe Jev Configuration

These keys are read only when `jevCacheCheck.enabled` is `true`. They are not required system parameters, so existing gateways without Jev configuration keep the v1.1 behavior.

| `config.toml` key | Policy system parameter | Type | Required | Description |
|-------------------|-------------------------|------|----------|-------------|
| `policy_configurations.typesafe_jev_v0.api_key` | `jevApiKey` | string | When enabled | TypeSafe AI API key. Policy initialization fails with a clear error if the check is enabled without this value. |
| `policy_configurations.typesafe_jev_v0.base_url` | `jevBaseURL` | string | No | Jev API base URL. Defaults to `https://api.typesafe.ai`. |
| `policy_configurations.typesafe_jev_v0.model` | `jevModel` | string | No | Jev model identifier. Defaults to `jev-latest`. |


#### Sample System Configuration

Add the following configuration section under the root level in your `config.toml` file:

```toml
embedding_provider = "MISTRAL" # Supported: MISTRAL, OPENAI, AZURE_OPENAI
embedding_provider_endpoint = "https://api.mistral.ai/v1/embeddings"
embedding_provider_model = "mistral-embed"
embedding_provider_dimension = 1024
embedding_provider_api_key = ""

vector_db_provider = "REDIS" # Supported: REDIS, MILVUS
vector_db_provider_host = "redis"
vector_db_provider_port = 6379
vector_db_provider_database = "0"
vector_db_provider_username = "default"
vector_db_provider_password = "default"
vector_db_provider_ttl = 3600

# Only needed when jevCacheCheck.enabled is true
[policy_configurations.typesafe_jev_v0]
api_key = ""
base_url = "https://api.typesafe.ai"
model = "jev-latest"
```

### User Parameters (API Definition)

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `similarityThreshold` | number | Yes | `0.5` | Similarity threshold for cache hits (0.0 to 1.0). Higher values require more similarity. For example, 0.9 means 90% similarity required. Recommended: 0.85-0.95 for strict matching, 0.70-0.85 for more flexible matching. |
| `jsonPath` | string | No | `"$.messages[-1].content"` | JSONPath expression to extract text from request body for embedding generation. If empty, uses the entire request body. Example: `"$.messages[-1].content"` to extract the last message's content. |
| `streamingJsonPath` | string | No | `"$.choices[0].delta.content"` | JSONPath expression used to extract and concatenate content from buffered SSE events before caching or performing the Jev check. |
| `cacheUnauthenticated` | boolean | No | `false` | Controls caching for requests with no resolvable caller identity (a fully public, unauthenticated API). See [Cache Scoping and Provenance](#cache-scoping-and-provenance) below before enabling. |
| `jevCacheCheck` | object | No | `{enabled: false}` | Optional Jev admission check for new cache writes. See [Jev Cache Admission](#jev-cache-admission). |

| `jevCacheCheck` field | Type | Required | Default | Description |
|-----------------------|------|----------|---------|-------------|
| `enabled` | boolean | Yes when the object is present | `false` | Enables the Jev check. When `false`, the other fields are ignored and behavior remains compatible with v1.1. |
| `timeout` | string | No | `"5s"` | Go duration greater than zero and no more than `30s`. Covers the initial call, retry delay, and one retry after HTTP 429 or 529. |
| `questions` | array | No | Built-in questions | Questions used to reject cache writes. The UI starts with the four built-in questions. A non-empty array is evaluated exactly as configured; adding questions keeps the built-ins that remain in the array, while removing a built-in disables that check. An omitted or empty array restores all four built-ins. |

### Jev Cache Admission

When enabled, the policy sends a JSON state containing the extracted request and response text to TypeSafe Jev immediately before an otherwise eligible cache write. It stores the response only when every configured answer stays below its threshold. The check runs inline during response processing, so delivery to the client waits until Jev completes or reaches the configured timeout. A timeout, provider error, malformed answer, or missing response text skips the cache write, but the policy does not change the upstream response returned to the client. Existing cache lookups and entries are unaffected.

Jev receives the state `{"request":"<text at jsonPath>","response":"<choices[0].message.content>"}`. For streamed responses, the policy first reassembles the configured SSE content fragments into the same response shape.

An omitted or empty `questions` array uses these `noul` questions:

| Key | Threshold | Question |
|-----|-----------|----------|
| `time_sensitive` | `0.7` | Does the answer in `response` depend on the current date or time, or on live information such as news, prices, weather, or stock levels? |
| `needs_context` | `0.7` | Does `request` only make sense together with earlier messages in the conversation, for example a follow-up like “tell me more” or “what about the second one”? |
| `unhelpful_response` | `0.7` | Is `response` a refusal, an error, or a reply saying the request couldn't be completed? |
| `sensitive_data` | `0.7` | Do `request` or `response` contain secrets, credentials, or personal data such as passwords, card numbers, or ID numbers? |

#### Configured Question List Behavior

The UI pre-populates `questions` with the four built-in questions above. The
policy evaluates exactly the questions present in a non-empty array:

- Adding two custom questions without removing any built-ins evaluates all six
  questions.
- Removing a built-in question from the array disables that check; the policy
  does not add it back automatically.
- Omitting `questions`, or submitting an empty array, restores and evaluates all
  four built-in questions.
- If any evaluated question reaches its threshold, the cache write is skipped.
  The response is cached only when every evaluated question stays below its
  threshold.

For example, if the four pre-populated questions remain and the user adds
`creative_output` and `personalized_advice`, the decision is:

```text
Any of the 6 questions reaches its threshold → SKIP the cache write
All 6 questions stay below their thresholds → CACHE the response
```

Custom questions support the following fields:

| Field | Applies to | Description |
|-------|------------|-------------|
| `key` | All | Unique, non-empty answer identifier. |
| `type` | All | `noul` or `score`. Choice questions are intentionally unsupported because Semantic Cache admission needs an ordered value that can be compared directly with a cache-write threshold. |
| `instructions` | All | Plain-English question Jev evaluates. |
| `threshold` | All | Inclusive cache-write rejection threshold. `noul` uses `(0,1]`; `score` uses `(0,last scale position]`. |
| `criteria` | `score` | An array of 2–10 scale descriptions ordered from cacheable to non-cacheable. Not used for `noul`. |

Enabling this option sends request and response text to TypeSafe AI's hosted service; confirm that this is compatible with your privacy, residency, and compliance requirements.

#### JSONPath Support

The policy supports JSONPath expressions to extract specific text from request bodies before generating embeddings. This is useful for:
- Extracting message content from chat completion requests
- Focusing on specific prompt fields while ignoring metadata
- Handling structured JSON payloads

**Common JSONPath Examples**

- `$.messages[0].content` - First message's content in chat completions
- `$.messages[-1].content` - Last message's content
- `$.prompt` - Extract prompt field from completions API
- `$.input` - Extract input field from embeddings API
- `$` - Entire request body (default if jsonPath is not specified)

#### build.yaml Integration

Inside the `gateway/build.yaml`, ensure the policy module is added under `policies:`:

```yaml
- name: semantic-cache
  gomodule: github.com/wso2/gateway-controllers/policies/semantic-cache@v1
```

## Reference Scenarios

### Example 1: OpenAI Embeddings with Redis

Deploy an LLM provider with semantic caching using OpenAI embeddings and Redis vector store:

```yaml
apiVersion: gateway.api-platform.wso2.com/v1
kind: LlmProvider
metadata:
  name: cached-chat-provider
spec:
  displayName: OpenAI Cached Provider
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
    - name: semantic-cache
      version: v1
      paths:
        - path: /chat/completions
          methods: [POST]
          params:
            similarityThreshold: 0.85
            jsonPath: "$.messages[0].content"

```

**Test the semantic cache:**

```bash
# First request - cache miss, will call upstream
curl -X POST http://localhost:8080/openai/chat/completions \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <consumer-token>" \
  -d '{
    "model": "gpt-4",
    "messages": [
      {
        "role": "user",
        "content": "Explain quantum computing in simple terms"
      }
    ]
  }'

# Second request with similar but different wording, from the SAME caller - cache hit!
curl -X POST http://localhost:8080/openai/chat/completions \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <consumer-token>" \
  -d '{
    "model": "gpt-4",
    "messages": [
      {
        "role": "user",
        "content": "Can you describe quantum computing using simple language?"
      }
    ]
  }'
# Response will include: X-Cache-Status: HIT
```

### Example 2: Enable the Default Jev Cache Check

This configuration skips cache writes for time-sensitive requests, context-dependent follow-ups, unhelpful responses, and content containing the sensitive data covered by the built-in questions:

```yaml
operationPolicies:
  - name: semantic-cache
    version: v1
    paths:
      - path: /chat/completions
        methods: [POST]
        params:
          similarityThreshold: 0.85
          jsonPath: "$.messages[-1].content"
          jevCacheCheck:
            enabled: true
            timeout: "5s"
```

For example, a current-weather response that triggers `time_sensitive` is still returned to the client unchanged but is not written to the vector database. A stable response such as “The capital of France is Paris” is stored when every answer remains below `0.7`.

### Example 3: Add a Custom Creative-Output Question

Providing a non-empty `questions` array makes that array the complete question
battery. This example intentionally evaluates only `creative_output`. To keep
the built-in checks as well, leave the four pre-populated questions in the
array and append this custom question:

```yaml
operationPolicies:
  - name: semantic-cache
    version: v1
    paths:
      - path: /chat/completions
        methods: [POST]
        params:
          similarityThreshold: 0.85
          jsonPath: "$.messages[-1].content"
          jevCacheCheck:
            enabled: true
            questions:
              - key: creative_output
                type: noul
                instructions: "Does `request` ask for creative or varied output where a different answer each time is expected?"
                threshold: 0.7
```

## How it Works

### Request Phase

1. **Text Extraction**: Extracts text from the request body using JSONPath (if configured) or uses the entire request body
2. **Caller Identity Resolution**: Resolves the caller's identity (application/subscriber ID from authentication, or a JWT subject/client ID). If no identity can be resolved and `cacheUnauthenticated` is not enabled, the cache is bypassed entirely and the request proceeds to the upstream service (see [Cache Scoping and Provenance](#cache-scoping-and-provenance))
3. **Embedding Generation**: Generates a vector embedding from the extracted text using the configured embedding provider
4. **Cache Lookup**: Searches the vector database for semantically similar cached responses previously stored by the SAME caller, using cosine similarity
5. **Threshold Check**: If a similar embedding is found with similarity >= similarityThreshold, returns the cached response immediately
6. **Cache Miss**: If no similar response is found, the request proceeds to the upstream service

### Response Phase

1. **Success Check**: Only processes responses with 200 status codes
2. **Cacheability Check**: Responses marked `Cache-Control: no-store`, `private`, or `no-cache` are skipped and never stored
3. **Embedding Retrieval**: Retrieves the embedding generated during the request phase from metadata
4. **Optional Jev Check**: When enabled, asks the configured Jev questions and skips storage if any answer reaches its threshold or the check fails
5. **Response Storage**: Stores the response payload along with its embedding in the vector database, scoped to the resolved caller identity
6. **TTL Application**: Applies the configured TTL to the cache entry


### Similarity Thresholds

The `similarityThreshold` parameter controls how similar requests must be to trigger a cache hit:

- **0.95-1.0**: Very strict matching. Only near-identical requests will hit cache. Use for exact-match scenarios.
- **0.85-0.94**: Recommended for most use cases. Catches semantically equivalent requests with some wording variation.
- **0.75-0.84**: More flexible matching. Useful for broader conceptual similarity.
- **0.60-0.74**: Very flexible. May return cached responses for loosely related queries.
- **Below 0.60**: Not recommended. Risk of returning irrelevant cached responses.

**Recommendation**: Start with 0.85 and adjust based on your use case. Monitor cache hit rates and response relevance to fine-tune.

### Cache Scoping and Provenance

- **Per-caller isolation**: Every cache entry is bound to the caller who produced it (resolved from the application/subscriber identity established by an auth policy, or falling back to the JWT subject/client ID). Lookups only ever match entries written by the same caller — one caller can never receive another caller's cached response, and a caller cannot seed an entry another caller will be served.
- **`cacheUnauthenticated` (default `false`)**: For a fully public, unauthenticated API where no caller identity is ever available, the cache is bypassed by default — nothing is stored or served. Setting `cacheUnauthenticated: true` restores a single shared, api-wide cache bucket for all identity-less callers.

  > **Security warning**: enabling `cacheUnauthenticated` means any identity-less caller who can influence the upstream's response for a given prompt can seed an entry that is later served to a *different* identity-less caller as a trusted cache hit (cache poisoning), and a personalized or sensitive response produced for one identity-less caller can be replayed to another. Only enable this when every possible response the upstream can produce is safe to share across all unauthenticated callers of the API.
- **`no-store` responses are never cached**: a response whose `Cache-Control` header contains `no-store`, `private`, or `no-cache` is skipped by the storage step regardless of caller identity.

### Cache Behavior

- **Cache Hit**: When a similar request from the same caller (or the same shared bucket, if `cacheUnauthenticated` is enabled) is found, the policy immediately returns the cached response with a `200` status, adds the `X-Cache-Status: HIT` header, and avoids any upstream call, typically responding in under 50 ms.

- **Cache Miss**: When no similar request exists for that caller, the request is forwarded to the upstream service, and upon a successful `200` response that is not marked non-shareable, the result is stored so that subsequent similar requests from the same caller can be served from the cache.

- **Cache Storage**: Only eligible successful responses are cached along with their embeddings in the vector database, with a TTL applied to each entry and isolated cache namespaces maintained per route/API **and per caller** to prevent cross-contamination.

## Limitations

- The Jev check affects only new writes. Entries cached before it was enabled remain available until they expire or are removed from the vector database.
- Cache lookups are not checked by Jev. A request can still receive an earlier cached response that passed the admission check.
- Jev sees only the extracted request text and response text, not the full conversation or caller context.
- The response text sent to Jev is read from `choices[0].message.content` (OpenAI-compatible shape, or the reassembled SSE stream). If an upstream returns a different shape, the text cannot be read and every write is skipped, so enable the check only on OpenAI-compatible APIs.
- Jev answers are probabilistic. Operators should validate question wording and thresholds against representative traffic.
- Creative requests are not rejected by the default battery; add a custom question when varied output should not be cached.
- The check runs inline before storage and adds one Jev request—and up to the configured timeout—to each response that passes the existing storage checks. Cache hits do not call Jev.
- Sending request and response text to TypeSafe AI may have privacy, data-residency, and compliance implications.

## Notes

### Operational Resilience
- **Graceful degradation**: If embedding generation, vector database access, or cache storage fails, the request proceeds directly to the upstream service without blocking the client response. A JSONPath extraction failure is the exception: the policy returns a `400` error response instead of proceeding to the upstream service.

- **Non-blocking resilience**: Caching operations are best-effort and never interfere with normal request handling, ensuring uninterrupted service even when caching components are unavailable.


- **Latency and efficiency trade-offs**: Embedding generation adds processing overhead, and vector database performance, embedding dimensions, and index creation time directly affect latency, storage, and search efficiency.

- **Cache effectiveness**: Overall performance gains depend on achieving a healthy cache hit rate, with moderate hit ratios delivering meaningful cost and latency benefits that justify the added processing overhead.
- This capability reduces cost and latency by serving cached responses, helps manage rate limits and high traffic, ensures consistent results, improves resilience during upstream outages, and supports faster development, testing, and experimentation such as A/B testing.

- The policy requires both request and response phases to function properly (generates embeddings in request phase, stores responses in response phase).

- Embedding generation adds latency to each request (~100-500ms). This overhead is typically offset by the performance gains from cache hits.

- Cache entries are scoped per route/API **and per authenticated caller** to prevent cross-contamination between different APIs, routes, or callers. Identity-less (unauthenticated) requests are not cached unless `cacheUnauthenticated` is explicitly enabled — see [Cache Scoping and Provenance](#cache-scoping-and-provenance).

- Only responses with 200 status code are cached. Errors and non-200 responses are never cached. Responses marked `Cache-Control: no-store`, `private`, or `no-cache` are also never cached.

- Jev failures, timeouts, malformed answers, or unreadable response content fail closed for the cache write only. The upstream response is returned unchanged.

- Jev decisions are recorded in request metadata under `semantic-cache:jev-check`, including fired questions for a skip decision. Token usage is recorded under `semantic-cache:jev-usage` when the provider returns it.

- The similarity search uses cosine similarity to compare embeddings. This is optimal for semantic similarity matching.

- Vector database indexes are created automatically when the policy is first used. Ensure your vector database has sufficient resources.

- The policy maintains provider instances per route for efficiency. Configuration changes require policy reinitialization.

- TTL of 0 means no expiration. Use with caution as it may lead to unbounded cache growth.

- JSONPath extraction is optional. If not specified, the entire request body (as string) is used for embedding generation.

- The policy stores embeddings in metadata between request and response phases. Ensure metadata persistence is enabled in your gateway configuration.

- For production deployments, monitor cache hit rates, embedding generation latency, and vector database performance metrics to optimize configuration.
