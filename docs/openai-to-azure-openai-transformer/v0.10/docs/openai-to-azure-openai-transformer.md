---
title: "Overview"
---
# OpenAI to Azure OpenAI Transformer

## Overview

The OpenAI to Azure OpenAI policy lets a client use the standard OpenAI Chat Completions API while the request is served by an Azure OpenAI deployment. Azure OpenAI is wire-compatible with the OpenAI Chat Completions body, so this policy only rewrites the request **path** — it inserts the Azure deployment id and the required `api-version` query parameter — and leaves the request and response bodies unchanged.

It is designed to run on an LLM proxy that fans one OpenAI-shaped `/chat/completions` endpoint out to several providers. It supports two modes:

- **Single-provider mode** — attach the policy with no router in front of it. With no provider selected in the request metadata, the policy always runs.
- **Multi-provider mode** — put a router (for example `llm-header-router`) first. The router writes the chosen provider into `SharedContext.Metadata["selected_provider"]`, and this policy runs only when that selection matches its own `providerId`.

Use this policy when you need to:

- Expose a single OpenAI-compatible endpoint that is actually backed by an Azure OpenAI deployment.
- Route a subset of traffic to Azure OpenAI within a multi-provider LLM proxy without changing client code.

## Features

- **Path rewriting**: Rewrites the request path to `/openai/deployments/{deployment}{pathSuffix}?api-version={apiVersion}`.
- **Deployment resolution**: Uses the request body's `model` field as the deployment id. The configured `model` parameter is a fallback, applied only when the request body names none.
- **api-version injection**: Adds the required Azure `api-version` query parameter.
- **Body passthrough**: The request and response bodies are not modified, since Azure OpenAI matches the OpenAI wire format.

## Parameters

| Name | Required | Default | Description |
|------|----------|---------|-------------|
| `apiVersion` | Yes | — | Azure OpenAI `api-version` query-string value (for example `2024-02-15-preview`). Required because Azure rejects requests without it. |
| `model` | No | Request `model` | Fallback Azure deployment id for the rewritten path, used when the request body names no `model`. It does **not** override a model the client named. |
| `providerId` | No | — | Provider this translator targets. Used as the upstream cluster name and, in multi-provider mode, matched case-insensitively against `SharedContext.Metadata["selected_provider"]`. When omitted, routing is left to the route's default upstream. |
| `pathSuffix` | No | `/chat/completions` | Endpoint suffix appended after the deployment segment in the rewritten path. |

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
  - id: azure-openai-provider
    auth:
      type: api-key
      header: X-API-Key
      value: REPLACE_WITH_AZURE_OPENAI_PROVIDER_LOOPBACK_KEY
    transformer:
      type: openai-to-azure-openai-transformer
      version: v1
      params:
        model: gpt-4o
        apiVersion: "2024-02-15-preview"
```

For a single-provider proxy (no router in front), attach it directly under `spec.operationPolicies` so it runs on every request:

```yaml
operationPolicies:
  - name: openai-to-azure-openai-transformer
    version: v1
    paths:
      - path: /chat/completions
        methods: [POST]
        params:
          model: gpt-4o
          apiVersion: "2024-02-15-preview"
```

## Notes

- The upstream must be configured with Azure OpenAI authentication (the `api-key` header) and the correct resource URL at the provider level; this policy handles only the path rewrite.
- Because the body is passed through unchanged, features like tool calling and vision work natively as long as the target deployment supports them.
