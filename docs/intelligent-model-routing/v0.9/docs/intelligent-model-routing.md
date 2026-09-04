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
  version: v0.9
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

This policy requires an LLM provider to be configured in the gateway:

| Config Key | Description |
|------------|-------------|
| `llm_provider` | Provider type: `OPENAI` or `AZURE_OPENAI` |
| `llm_provider_endpoint` | Chat completions endpoint URL |
| `llm_provider_model` | Model name used for classification (e.g. `gpt-4o-mini`) |
| `llm_provider_api_key` | API key for the LLM service |

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
