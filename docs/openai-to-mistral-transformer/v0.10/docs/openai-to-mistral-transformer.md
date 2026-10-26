---
title: "Overview"
---
# OpenAI to Mistral Transformer

## Overview

The OpenAI to Mistral policy adapts an OpenAI Chat Completions request so it can be served by a Mistral-compatible upstream. Mistral's API is close to OpenAI's, so the work is small: the policy resolves the target model, strips a handful of OpenAI-only fields that Mistral rejects, and rewrites the request path to Mistral's `/v1/chat/completions`. Mistral already returns OpenAI-shaped responses, so the response side only normalises the error envelope and ensures the response `model` is populated.

It is designed to run on an LLM proxy that fans one OpenAI-shaped `/chat/completions` endpoint out to several providers. It supports two modes:

- **Single-provider mode** — attach the policy with no router in front of it. With no provider selected in the request metadata, the policy always runs.
- **Multi-provider mode** — put a router (for example `llm-header-router`) first. The router writes the chosen provider into `SharedContext.Metadata["selected_provider"]`, and this policy runs only when that selection matches its own `providerId`.

Use this policy when you need to:

- Expose a single OpenAI-compatible endpoint that is actually backed by Mistral models.
- Route a subset of traffic to Mistral within a multi-provider LLM proxy without changing client code.

## Features

- **Model resolution**: Uses the model named in the request payload. The configured `model` is a fallback, applied only when the payload names none.
- **Field stripping**: Removes OpenAI request fields Mistral rejects — `logprobs`, `top_logprobs`, `logit_bias`, `n`, `service_tier`, `store`, `metadata`, and `user`.
- **Path rewriting**: Rewrites the request path to `/v1/chat/completions`.
- **Response normalisation**: Passes Mistral's OpenAI-shaped success bodies through, translating error envelopes and ensuring the response `model` is non-empty.

## Parameters

| Name | Required | Default | Description |
|------|----------|---------|-------------|
| `model` | No | Request `model` | Fallback Mistral model name (for example `mistral-large-latest`), used when the request payload names none. It does **not** override a model the client named. |
| `providerId` | No | — | Provider this translator targets. Used as the upstream cluster name and, in multi-provider mode, matched case-insensitively against `SharedContext.Metadata["selected_provider"]`. When omitted, routing is left to the route's default upstream. |

## Model resolution

`model` is optional, and it is a **fallback**. It does not override what the client asks for. The model that serves a request is resolved in one order, the same order every WSO2 LLM transformer uses:

1. the `model` field of the request payload, whenever it names one, this takes priority;
2. otherwise the `model` parameter configured on this policy;
3. if neither supplies one, the request is rejected with a 400 naming both sources.

An absent, `null` or empty (`""`) request `model` counts as naming none, so the configured value applies. A **whitespace-only** `model` is rejected as malformed even when a model is configured, it is bad input rather than a missing value. A non-string `model` is rejected as a bad request.

Set `model` to give clients that name no model a sensible default. There is no way to force every request onto one model: a client that names a model is always served the model it named.

Responses report the model that actually served the request, in buffered and streamed
responses alike, not the configured value, which may be unset. A response therefore never misattributes its own output.

## Example

For a multi-provider LLM proxy, attach this translator as the provider's `transformer` under `additionalProviders`. The provider `id` (or its `as` alias) is supplied by the gateway as `providerId`, so it is not repeated in `params`:

```yaml
additionalProviders:
  - id: mistral-provider
    auth:
      type: api-key
      header: X-API-Key
      value: REPLACE_WITH_MISTRAL_PROVIDER_LOOPBACK_KEY
    transformer:
      type: openai-to-mistral-transformer
      version: v1
      params:
        model: mistral-large-latest
```

For a single-provider proxy (no router in front), attach it directly under `spec.operationPolicies` so it runs on every request:

```yaml
operationPolicies:
  - name: openai-to-mistral-transformer
    version: v1
    paths:
      - path: /chat/completions
        methods: [POST]
        params:
          model: mistral-large-latest
```

## Notes

- The upstream must be configured with Mistral authentication (the `Authorization: Bearer` header) at the provider level; this policy handles only the request/response body and path adaptation.
- Text-only models such as `mistral-large-latest` cannot accept image input. If you need it, name a vision-capable model such as `pixtral-12b-2409` in the request, or configure one as the fallback.
