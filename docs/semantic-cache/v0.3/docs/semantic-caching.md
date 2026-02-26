---
title: "Overview"
---
# Semantic Caching

## Overview

The Semantic Cache policy caches LLM responses by comparing semantic similarity of request embeddings instead of relying on exact request text matches. On a cache hit, the gateway returns the cached response immediately. On a cache miss, the request is forwarded upstream and successful responses are stored for future reuse.

## Features

- Embedding-based semantic cache lookup
- Supports `OPENAI`, `MISTRAL`, and `AZURE_OPENAI` embedding providers
- Supports `REDIS` and `MILVUS` vector stores
- Configurable similarity threshold (`0.0` to `1.0`)
- Optional JSONPath extraction for embedding input
- Automatic cache write for successful (`200`) responses
- Returns cache-hit responses with `X-Cache-Status: HIT`

## Configuration

The Semantic Cache policy uses a two-level configuration model.

### System Parameters (From config.toml)

These parameters are typically configured globally and can be overridden per policy when needed.

##### Embedding Provider Configuration

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `embeddingProvider` | string | Yes | Embedding provider. One of `OPENAI`, `MISTRAL`, `AZURE_OPENAI`. |
| `embeddingEndpoint` | string | Yes | Embedding endpoint URL. |
| `embeddingModel` | string | Conditional | Required for `OPENAI` and `MISTRAL`; optional for `AZURE_OPENAI`. |
| `embeddingDimension` | integer | Yes | Embedding vector dimension expected by the vector store. |
| `apiKey` | string | Yes | API key for embedding provider authentication. |

##### Vector Database Configuration

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `vectorStoreProvider` | string | Yes | Vector store provider. One of `REDIS`, `MILVUS`. |
| `dbHost` | string | Yes | Vector database host. |
| `dbPort` | integer | Yes | Vector database port. |
| `username` | string | No | Database username. |
| `password` | string | No | Database password. |
| `database` | string | No | Database name/index. |
| `ttl` | integer | No | TTL in seconds for cache entries. |

#### Sample System Configuration

```toml
embedding_provider = "MISTRAL"
embedding_provider_endpoint = "https://api.mistral.ai/v1/embeddings"
embedding_provider_model = "mistral-embed"
embedding_provider_dimension = 1024
embedding_provider_api_key = ""

vector_db_provider = "REDIS"
vector_db_provider_host = "redis"
vector_db_provider_port = 6379
vector_db_provider_database = "0"
vector_db_provider_username = "default"
vector_db_provider_password = "default"
vector_db_provider_ttl = 3600
```

### User Parameters (API Definition)

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `similarityThreshold` | number | Yes | `0.5` | Minimum similarity (`0.0` to `1.0`) required to return a cached response. |
| `jsonPath` | string | No | `""` | JSONPath used to extract text for embedding. If empty, the full request body is used. |

#### JSONPath Support

Examples:

- `$.messages[0].content`
- `$.messages[-1].content`
- `$.prompt`
- `$.input`
- `$` (entire payload)

**Note:**

Inside `gateway/build.yaml`, ensure the policy module is added under `policies`:

```yaml
- name: semantic-cache
  gomodule: github.com/wso2/gateway-controllers/policies/semantic-cache@v0
```

## Reference Scenarios

### Example 1: Semantic Cache for Chat Completions

```yaml
apiVersion: gateway.api-platform.wso2.com/v1alpha1
kind: LlmProvider
metadata:
  name: cached-chat-provider
spec:
  displayName: Cached Chat Provider
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
    - name: semantic-cache
      version: v0
      paths:
        - path: /chat/completions
          methods: [POST]
          params:
            similarityThreshold: 0.85
            jsonPath: "$.messages[-1].content"
```

## How It Works

#### Request Phase

1. Extracts text using `jsonPath` (or full payload if empty).
2. Generates embedding for extracted text.
3. Looks up semantically similar cached entries using configured threshold.
4. Returns immediate cached response on hit.
5. Forwards request upstream on miss.

#### Response Phase

1. Processes only successful (`200`) responses.
2. Reads request embedding stored in request metadata.
3. Stores response payload with embedding in vector store.

## Notes

- Cache behavior is best-effort. If embedding generation or vector operations fail, requests continue upstream.
- Very high thresholds reduce false hits but lower hit rate; very low thresholds increase hit rate but risk irrelevant responses.
- Only successful upstream responses are cached.
