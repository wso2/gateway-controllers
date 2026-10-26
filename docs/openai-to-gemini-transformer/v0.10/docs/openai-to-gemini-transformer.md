---
title: "Overview"
---
# OpenAI to Gemini Transformer

## Overview

The OpenAI to Gemini policy lets a client speak the OpenAI Chat Completions API while the request is served by Google's Gemini `generateContent` API. Gemini has one of the most divergent request/response shapes of the major providers, so this policy performs a full body and path rewrite in both directions: OpenAI `messages` become Gemini `contents`, system prompts become `systemInstruction`, tools become `functionDeclarations`, and the response is rewritten back into the OpenAI shape — buffered responses as ChatCompletion JSON and streaming responses as OpenAI Chat Completions Server-Sent Events.

It is designed to run on an LLM proxy that fans one OpenAI-shaped `/chat/completions` endpoint out to several providers. It supports two modes:

- **Single-provider mode** — attach the translator with no router in front of it. With no provider selected in the request metadata, the translator always runs.
- **Multi-provider mode** — put a router (for example `llm-header-router`) first. The router writes the chosen provider into `SharedContext.Metadata["selected_provider"]`, and this translator runs only when that selection matches its own `providerId`.

Use this policy when you need to:

- Expose a single OpenAI-compatible endpoint that is actually backed by Gemini models.
- Route a subset of traffic to Gemini within a multi-provider LLM proxy without changing client code.

## Features

- **Request translation**: Rewrites the OpenAI request body to Gemini's `generateContent` format and the path to `/{apiVersion}/models/{model}:generateContent`.
- **System prompt handling**: Maps `system`/`developer` messages into Gemini's `systemInstruction`.
- **Message mapping**: Converts OpenAI `messages` into Gemini `contents`, flushing consecutive user/tool turns into `user` content and assistant turns into `model` content.
- **Tool / function calling**: Maps OpenAI `tools` and `tool_choice` to Gemini `functionDeclarations` and `toolConfig` (with `tool_choice: "none"` mapped to `functionCallingConfig.mode=NONE`), and rewrites function-call responses back into OpenAI `tool_calls`.
- **Multi-modal input**: Converts OpenAI `image_url` content blocks — base64 data URIs become `inlineData`, remote URLs become `fileData`.
- **Response translation**: Rewrites non-streaming Gemini responses into the OpenAI ChatCompletion shape, including finish-reason and usage mapping.
- **Streaming path**: When `stream: true`, the path is rewritten to `streamGenerateContent?alt=sse`.
- **Streaming translation**: Converts Gemini's Server-Sent Events into OpenAI `chat.completion.chunk` events (`data: {chunk}\n\n` … `data: [DONE]\n\n`), including the initial `delta.role`, candidate text, function calls as `delta.tool_calls`, finish reasons, and final usage. Events are parsed incrementally, so provider events split across transport chunks are handled without buffering the whole response.

## Parameters

| Name | Required | Default | Description |
|------|----------|---------|-------------|
| `model` | No | Request `model` | Fallback Gemini model name (for example `gemini-2.5-pro`), used in the translated request and the rewritten path when the request payload names none. It does **not** override a model the client named. |
| `providerId` | No | — | Provider this translator targets. Used as the upstream cluster name and, in multi-provider mode, matched case-insensitively against `SharedContext.Metadata["selected_provider"]`. When omitted, routing is left to the route's default upstream. |
| `apiVersion` | No | `v1beta` | Gemini API version segment used in the rewritten path (`/{apiVersion}/models/{model}:generateContent`). |

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
  - id: gemini-provider
    auth:
      type: api-key
      header: X-API-Key
      value: REPLACE_WITH_GEMINI_PROVIDER_LOOPBACK_KEY
    transformer:
      type: openai-to-gemini-transformer
      version: v1
      params:
        model: gemini-2.5-flash
        apiVersion: v1beta
```

For a single-provider proxy (no router in front), attach it directly under `spec.operationPolicies` so it runs on every request:

```yaml
operationPolicies:
  - name: openai-to-gemini-transformer
    version: v1
    paths:
      - path: /chat/completions
        methods: [POST]
        params:
          model: gemini-2.5-flash
          apiVersion: v1beta
```

## Notes

- Streaming (`stream: true`) responses are translated to OpenAI Chat Completions SSE. The downstream `content-type` is set to `text/event-stream` and the stale `content-length` is removed.
- Finish reasons map exactly as they do for non-streaming responses: `MAX_TOKENS` → `length`; a candidate that produced function calls → `tool_calls`; `SAFETY`, `RECITATION`, `BLOCKLIST`, `PROHIBITED_CONTENT`, `SPII`, `IMAGE_SAFETY`, and `LANGUAGE` → `content_filter`; everything else → `stop`. A prompt rejected via `promptFeedback.blockReason` is reported as `content_filter` on choice 0.
- Gemini candidate indices are preserved as OpenAI choice indices, so multi-candidate (`n > 1`) streams keep their per-choice content, tool-call indices, and finish reasons separate.
- Function calls arrive whole rather than as incremental argument deltas, so each becomes a single `tool_calls` chunk with `function.arguments` serialized as a JSON string.
- Final usage is emitted as a terminal chunk with an empty `choices` array. `completion_tokens` includes thought tokens, with `prompt_tokens_details.cached_tokens` and `completion_tokens_details.reasoning_tokens` populated when Gemini reports them. No usage chunk is emitted when the provider reports no `usageMetadata`.
- **Unmapped stream events.** Parts flagged `thought: true` are the model's reasoning and have no OpenAI Chat Completions streaming equivalent, so they are excluded from visible assistant content (their token count is still reported as `reasoning_tokens`).
- A mid-stream Gemini `error` object, or an event that cannot be parsed, is emitted as an OpenAI-style error object and the stream is then closed. Provider bytes are never forwarded as if they were OpenAI chunks, and such a stream is not terminated with `[DONE]`. Because response headers are already committed once streaming has begun, a mid-stream failure cannot be surfaced as an HTTP error status.
- The upstream must be configured with Gemini authentication (the `x-goog-api-key` header) at the provider level; this policy handles only the request/response body and path translation.
