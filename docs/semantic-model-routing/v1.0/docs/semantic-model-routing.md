# Semantic Model Routing

Routes AI/LLM requests to different models based on the semantic similarity between the user's prompt and predefined example utterances (reference phrases). At startup, embeddings are precomputed for all utterances. At request time, the incoming prompt is compared against them using cosine similarity, and the best-matching model is selected.

## How It Works

1. **At startup (precomputation):** Embeddings are generated for all configured utterances across all routes and stored in memory.
2. **At request time:**
   - The user prompt is extracted from the request payload using the configured `contentPath`.
   - An embedding vector is generated for the incoming prompt.
   - Cosine similarity is computed between the prompt embedding and every precomputed utterance embedding.
   - The route with the highest similarity score is selected.
   - If that score meets or exceeds the route's `scorethreshold`, the request is routed to that route's model.
   - Otherwise, the `defaultModel` is used.

## When to Use This Policy

Use **Semantic Model Routing** when:
- Your users send **short, keyword-style queries** that closely match expected phrases (e.g., "what's the weather today", "write me a poem").
- You have a small, well-defined set of request categories with clear example utterances.
- You want **low-latency routing** — no LLM call is needed at request time, only an embedding lookup.

> **Tip:** If your routing categories are complex or hard to express as example phrases, consider **Intelligent Model Routing** instead, which uses an LLM classifier with natural-language context descriptions.

## Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `contentPath` | string | No | JSONPath to extract the prompt from the request body. Default: `$.messages[-1].content` |
| `routes` | array | Yes | List of routing routes. Each route defines utterances, a similarity threshold, and a target model. |
| `defaultModel` | string | Yes | Model to use when no route's similarity score meets its threshold. |

### Route Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `model` | string | Yes | The target AI model name to route matching requests to. |
| `utterances` | array of strings | Yes | Example phrases representing the types of requests this route should handle. |
| `scorethreshold` | number | No | Minimum cosine similarity score (0.0–1.0) required to match this route. Default: `0.7` |

## Example Configuration

```yaml
- name: semantic-model-routing
  version: v1
  paths:
    - path: /chat/completions
      methods: [POST]
      params:
        contentPath: "$.messages[-1].content"
        routes:
          - model: "gpt-4o-mini"
            utterances:
              - "write a python function"
              - "fix this bug in my code"
              - "explain this algorithm"
              - "create a REST API"
            scorethreshold: 0.85
          - model: "gpt-4o"
            utterances:
              - "what is the weather forecast"
              - "will it rain tomorrow"
              - "how is the temperature today"
            scorethreshold: 0.85
        defaultModel: "gpt-4o-mini"
```

## System Requirements

This policy requires an embedding provider to be configured in the gateway:

| Config Key | Description |
|------------|-------------|
| `embedding_provider` | Provider type: `OPENAI`, `MISTRAL`, or `AZURE_OPENAI` |
| `embedding_provider_endpoint` | Embeddings API endpoint URL |
| `embedding_provider_model` | Embedding model name (e.g. `text-embedding-3-small`) |
| `embedding_provider_api_key` | API key for the embedding service |
| `embedding_vector_dimension` | Dimension of the embedding vectors produced by the model |
