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
| `defaultProvider` | string | No | Destination provider alias to use with `defaultModel` on fallback. |

### Route Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `model` | string | Yes | The target AI model name to route matching requests to. |
| `provider` | string | No | Additional-provider alias for this route. Empty or omitted preserves the current upstream. |
| `utterances` | array of strings | Yes | Example phrases representing the types of requests this route should handle. |
| `scorethreshold` | number | No | Minimum cosine similarity score (0.0–1.0) required to match this route. Default: `0.90` |

## Example Configuration

```yaml
- name: semantic-model-routing
  version: v0.9
  paths:
    - path: /chat/completions
      methods: [POST]
      params:
        contentPath: "$.messages[-1].content"
        routes:
          - model: "gpt-4o-mini"
            provider: "coding-provider"
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
        defaultProvider: "fallback-provider"
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
version in configuration is `v0.9`.

### Gateway Controller Integration

In the API Platform gateway controller, register both `intelligent-model-routing`
and `semantic-model-routing` in `routingPolicyUsesRequestModel` and
`llmProxyUsesBodyBasedRoutingPolicy` in
`gateway/gateway-controller/pkg/utils/llm_transformer.go`. This supplies template
model extraction settings for global policies and moves conditional provider
credentials to the body phase. Without that registration, a header-phase auth
policy may apply primary-provider credentials before the router has selected an
additional provider. The gateway's `set-headers` policy must also support the
`request.phase: body` setting generated by the controller.
