---
title: "Overview"
---
# OpenAI to Anthropic Transformer

## Overview

The OpenAI to Anthropic policy lets a client speak the OpenAI Chat Completions API while the request is served by Anthropic's Messages API. It rewrites the request body and path on the way upstream, and rewrites the response back into the OpenAI shape on the way down — buffered responses as OpenAI ChatCompletion JSON and streaming responses as OpenAI Chat Completions Server-Sent Events — so the client never has to know which provider answered.

It is designed to run on an LLM proxy that fans one OpenAI-shaped `/chat/completions` endpoint out to several providers. It supports two modes:

- **Single-provider mode** — attach the translator with no router in front of it. With no provider selected in the request metadata, the translator always runs.
- **Multi-provider mode** — put a router (for example `llm-header-router`) first. The router writes the chosen provider into `SharedContext.Metadata["selected_provider"]`, and this translator runs only when that selection matches its own `providerId`.

Use this policy when you need to:

- Expose a single OpenAI-compatible endpoint that is actually backed by Anthropic models.
- Route a subset of traffic to Anthropic within a multi-provider LLM proxy without changing client code.
- Migrate an existing OpenAI integration to Anthropic without rewriting request/response handling.

## Features

- **Request translation**: Rewrites the OpenAI request body to the Anthropic Messages format and the path to `/v1/messages`.
- **System prompt handling**: Extracts `system`/`developer` messages into Anthropic's top-level `system` field.
- **Tool / function calling**: Maps OpenAI `tools`, `tool_choice`, `tool_calls`, and `tool` result messages to their Anthropic equivalents (`tools` with `input_schema`, `tool_use`, `tool_result`). `tool_choice: "none"` drops tools entirely, since Anthropic has no negative form.
- **Multi-modal input**: Converts OpenAI `image_url` content blocks (both base64 data URIs and remote URLs) into Anthropic image source blocks.
- **max_tokens handling**: Anthropic requires `max_tokens`; the policy honours OpenAI's `max_completion_tokens` (preferred) or `max_tokens`, falling back to a default when neither is present.
- **Response translation**: Rewrites non-streaming Anthropic responses into the OpenAI ChatCompletion shape, including `finish_reason` and tool-call mapping.
- **Streaming translation**: Converts Anthropic's Server-Sent Events into OpenAI `chat.completion.chunk` events (`data: {chunk}\n\n` … `data: [DONE]\n\n`), including the initial `delta.role`, text and tool-call argument deltas, finish reasons, and final usage. Events are parsed incrementally, so provider events split across transport chunks are handled without buffering the whole response.

## Parameters

| Name | Required | Default | Description |
|------|----------|---------|-------------|
| `model` | No | Request `model` | Fallback Anthropic model name (for example `claude-sonnet-4-20250514`), used when the request payload names none. It does **not** override a model the client named. |
| `providerId` | No | — | Provider this translator targets. Used as the upstream cluster name and, in multi-provider mode, matched case-insensitively against `SharedContext.Metadata["selected_provider"]`. When omitted, routing is left to the route's default upstream. |
| `anthropicVersion` | No | `2023-06-01` | Value of the `anthropic-version` request header sent upstream. |

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
  - id: anthropic-provider
    auth:
      type: api-key
      header: X-API-Key
      value: REPLACE_WITH_ANTHROPIC_PROVIDER_LOOPBACK_KEY
    transformer:
      type: openai-to-anthropic-transformer
      version: v1
      params:
        model: claude-sonnet-4-5-20250929
```

For a single-provider proxy (no router in front), attach it directly under `spec.operationPolicies` so it runs on every request:

```yaml
operationPolicies:
  - name: openai-to-anthropic-transformer
    version: v1
    paths:
      - path: /chat/completions
        methods: [POST]
        params:
          model: claude-sonnet-4-5-20250929
```

## Notes

- Streaming (`stream: true`) responses are translated to OpenAI Chat Completions SSE. The downstream `content-type` is set to `text/event-stream` and the stale `content-length` is removed.
- Stop reasons map to OpenAI finish reasons as `end_turn`/`stop_sequence` → `stop`, `max_tokens` → `length`, `tool_use` → `tool_calls`.
- Anthropic numbers every content block, including text; the policy renumbers tool-use blocks into the contiguous, zero-based `tool_calls` index OpenAI expects.
- Final usage is emitted as a terminal chunk with an empty `choices` array, carrying `prompt_tokens_details.cached_tokens` and `cache_creation_tokens` when Anthropic reports cache usage.
- **Unmapped stream events.** `ping` and `content_block_stop` carry nothing OpenAI represents and are dropped. `thinking_delta` and `signature_delta` (extended thinking) have no OpenAI Chat Completions streaming equivalent and are excluded from visible assistant content.
- A mid-stream Anthropic `error` event, or an event that cannot be parsed, is emitted as an OpenAI-style error object and the stream is then closed. Provider bytes are never forwarded as if they were OpenAI chunks, and such a stream is not terminated with `[DONE]`. Because response headers are already committed once streaming has begun, a mid-stream failure cannot be surfaced as an HTTP error status.
- The upstream must be configured with Anthropic authentication (the `x-api-key` header) at the provider level; this policy handles only the request/response body and path translation.
