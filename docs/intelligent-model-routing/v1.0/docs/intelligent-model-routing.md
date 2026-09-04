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

### Routing Rule Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | Yes | A short label for the rule (e.g. `"Coding"`, `"Customer Support"`). The LLM uses this name to identify the match. |
| `context` | string | Yes | Plain-language description of request types this rule handles. The LLM reads this when classifying. |
| `model` | string | Yes | The target AI model name to route matching requests to. |

## Example Configuration

```yaml
- name: intelligent-model-routing
  version: v1
  paths:
    - path: /chat/completions
      methods: [POST]
      params:
        contentPath: "$.messages[-1].content"
        routingRules:
          - name: Coding
            context: "Code-related questions, programming, debugging, algorithms, software development"
            model: "gpt-4o-mini"
          - name: Creative Writing
            context: "Stories, poems, creative content, fiction, song lyrics, screenplays"
            model: "gpt-4o"
        defaultModel: "gpt-4o-mini"
```

## System Requirements

This policy requires an LLM provider to be configured in the gateway:

| Config Key | Description |
|------------|-------------|
| `llm_provider` | Provider type: `OPENAI` or `AZURE_OPENAI` |
| `llm_provider_endpoint` | Chat completions endpoint URL |
| `llm_provider_model` | Model name used for classification (e.g. `gpt-4o-mini`) |
| `llm_provider_api_key` | API key for the LLM service |
