---
title: "Overview"
---
# Context-Based Routing

## Overview

The Context-Based Routing policy estimates the input tokens in an LLM request
and selects a configured model and optional provider using token ranges. It does
not add an output-token allowance to the estimate.

Ranges use an optional inclusive `minTokens` and a required exclusive
`maxTokens` boundary. When `minTokens` is omitted, the range starts at zero.
Ranges must not overlap. Omitting `providerName` keeps routing on the LLM proxy's
primary provider; specifying it selects an `additionalProviders[].as` alias.

## Configuration

| Field | Required | Default | Use |
|---|---:|---:|---|
| `modelMappings` | Yes | - | Input-token ranges and their targets. |
| `modelMappings[].name` | No | generated | Human-readable route name. |
| `modelMappings[].minTokens` | No | `0` | Inclusive lower boundary. |
| `modelMappings[].maxTokens` | Yes | - | Exclusive upper boundary. |
| `modelMappings[].model.modelName` | Yes | - | Model selected for the range. |
| `modelMappings[].model.providerName` | No | primary | Additional-provider alias selected for the range. |
| `fallback.modelName` | No | original model | Model used when estimation fails or no range matches. |
| `fallback.providerName` | No | primary | Optional additional-provider alias for the fallback. |
| `charsPerToken` | No | `4` | Characters-per-token approximation. |
| `inputJSONPaths` | No | built-in paths | JSON values whose text contributes to the estimate. |

```yaml
modelMappings:
  - name: small-context
    maxTokens: 200000
    model:
      modelName: gpt-4o-mini

  - name: medium-context
    minTokens: 200000
    maxTokens: 500000
    model:
      providerName: anthropic-provider
      modelName: claude-sonnet

  - name: large-context
    minTokens: 500000
    maxTokens: 1000000
    model:
      providerName: bedrock-provider
      modelName: claude-long-context

fallback:
  modelName: gpt-4o
charsPerToken: 4
inputJSONPaths:
  - $.messages.*.content
  - $.tools
```

## Request Behavior

- Malformed JSON or a non-object JSON body returns `400 Bad Request`.
- By default, a supported body is estimated from fields such as `messages`,
  `prompt`, `input`, `contents`, `system`, `tools`, and `functions`.
- `inputJSONPaths` replaces those defaults when configured. It controls exactly
  which JSON values contribute characters, but token counts remain approximate
  because the policy does not run the selected provider's tokenizer.
- Estimation failure or no matching range uses `fallback` when configured.
- Without a fallback, the request body, original model, and provider remain
  unchanged.
- A matched or fallback target rewrites the model using the provider template's
  `requestModel` definition.
- A target with `providerName` also publishes `selected_provider`, allowing the
  matching provider authentication and protocol transformer to run afterward.
- Provider responses keep the actual upstream model so clients can see which
  routed model served the request.

For local development, add the policy module to the gateway build configuration:

```yaml
- name: context-based-routing
  filePath: ./dev-policies/context-based-routing
```

Existing configurations using `routes`, `target` (or `models`), inner `model`, and `provider` remain
accepted by the runtime as legacy aliases. New configurations use the fields
shown above; canonical fields take precedence when both names are supplied.
