---
title: "Overview"
---
# OpenAI to Bedrock Transformer

## Overview

The OpenAI to Bedrock Transformer policy lets OpenAI Chat Completions clients use the AWS Bedrock Converse API without changing their request or response handling. It rewrites requests to Bedrock's `/model/{modelId}/converse` or `/model/{modelId}/converse-stream` endpoint and translates Bedrock responses back to the OpenAI format.

The policy supports two modes:

- **Single-provider mode** — attach the transformer directly to a proxy that uses Bedrock as its upstream provider.
- **Multi-provider mode** — attach the transformer to a Bedrock provider in a proxy with multiple providers. The transformer applies to requests routed to that provider.

## Features

- Converts OpenAI messages, system/developer prompts, inference settings, stop sequences, and tools to Bedrock Converse format.
- Maps OpenAI assistant tool calls and tool results to Bedrock `toolUse` and `toolResult` content blocks.
- Supports base64 data-URI images in OpenAI `image_url` blocks.
- Maps OpenAI `file` content parts to Bedrock `document` blocks (PDF, CSV, Word, Excel, HTML, plain text and Markdown).
- Rewrites non-streaming Converse responses, usage, tool calls, finish reasons, and errors to OpenAI ChatCompletion JSON.
- Decodes Bedrock's binary Amazon event-stream responses and emits OpenAI-compatible Server-Sent Events, including usage and the final `[DONE]` marker.
- Supports Bedrock model IDs and inference-profile IDs in the upstream path.

## Parameters

| Name | Required | Default | Description |
|------|----------|---------|-------------|
| `model` | No | Request `model` | Fallback Bedrock model or inference-profile ID for the Converse request path, used when the request payload names none. It does **not** override a model the client named. |
| `providerId` | No | — | Bedrock provider ID used in multi-provider configurations. |

## Model resolution

`model` is optional, and it is a **fallback**. It does not override what the client asks for. The model that serves a request is resolved in one order, the same order every WSO2 LLM transformer uses:

1. the `model` field of the request payload, whenever it names one, this takes priority;
2. otherwise the `model` parameter configured on this policy;
3. if neither supplies one, the request is rejected with a 400 naming both sources.

An absent, `null` or empty (`""`) request `model` counts as naming none, so the configured value applies. A **whitespace-only** `model` is rejected as malformed even when a model is configured, it is bad input rather than a missing value. A non-string `model` is rejected as a bad request.

Set `model` to give clients that name no model a sensible default. There is no way to force every request onto one model: a client that names a model is always served the model it named.

Responses report the model that actually served the request, in buffered and streamed
responses alike, not the configured value, which may be unset. A response therefore never misattributes its own output.

## File input

OpenAI `file` content parts in user messages are converted to Bedrock Converse `document` blocks. Send the file inline as a base64 data URI in `file_data`. Bedrock requires text alongside a document, so every user message that contains a file must also contain a non-empty `text` part:

```json
{
  "model": "us.anthropic.claude-sonnet-4-5-20250929-v1:0",
  "messages": [
    {
      "role": "user",
      "content": [
        { "type": "text", "text": "Summarise this report." },
        {
          "type": "file",
          "file": {
            "filename": "q3-report.pdf",
            "file_data": "data:application/pdf;base64,JVBERi0xLjQK..."
          }
        }
      ]
    }
  ]
}
```

The policy forwards it to Bedrock as:

```json
{ "document": { "format": "pdf", "name": "q3-report", "source": { "bytes": "JVBERi0xLjQK..." } } }
```

- **Format** comes from the data URI's media type. If the media type is not recognised (for example `application/octet-stream`), the `filename` extension is used instead.

  | Media type | Extension | Bedrock format |
  |------------|-----------|----------------|
  | `application/pdf` | `.pdf` | `pdf` |
  | `text/csv` | `.csv` | `csv` |
  | `application/msword` | `.doc` | `doc` |
  | `application/vnd.openxmlformats-officedocument.wordprocessingml.document` | `.docx` | `docx` |
  | `application/vnd.ms-excel` | `.xls` | `xls` |
  | `application/vnd.openxmlformats-officedocument.spreadsheetml.sheet` | `.xlsx` | `xlsx` |
  | `text/html` | `.html`, `.htm` | `html` |
  | `text/plain` | `.txt` | `txt` |
  | `text/markdown`, `text/x-markdown` | `.md`, `.markdown` | `md` |

- **Name** is the filename without its extension. Characters Bedrock does not allow in a document name (anything other than letters, digits, single spaces, hyphens, parentheses and square brackets) are replaced with spaces. Without a filename the name is `document`. Bedrock requires document names to be unique, so a repeated name gets a suffix (`q3-report-2`). Names are cut to Bedrock's 200-character limit, and a repeated long name is shortened to make room for its suffix, so it stays unique.
- **Bytes** are forwarded exactly as sent, once checked to be valid standard base64.

The request is rejected with a `400` when a `file` part:

- references a `file_id`. Bedrock cannot read files uploaded to OpenAI, so send the content in `file_data`.
- has no `file_data`, or `file_data` is not a base64 data URI (`data:<media type>;base64,<data>`). Remote URLs are not fetched.
- has empty or malformed base64 data: invalid characters, missing padding, URL-safe base64 (`-`, `_`), or whitespace and line breaks.
- has a type that is not in the table above.
- is in a user message with no non-empty `text` part. Text in another message does not count.

Bedrock's own limits on the number and size of documents per request apply, and models that do not accept document input return an error from Bedrock. See the [Bedrock Converse `DocumentBlock` reference](https://docs.aws.amazon.com/bedrock/latest/APIReference/API_runtime_DocumentBlock.html).

## Example

For a multi-provider LLM proxy, attach the transformer to the Bedrock provider. The provider `id` (or its `as` alias) is supplied by the gateway as `providerId`, so it is not repeated in `params`:

```yaml
additionalProviders:
  - id: bedrock-provider
    auth:
      type: api-key
      header: Authorization
      value: Bearer REPLACE_WITH_BEDROCK_API_KEY
    transformer:
      type: openai-to-bedrock-transformer
      version: v1
      params:
        model: us.anthropic.claude-sonnet-4-5-20250929-v1:0
```

For a single-provider proxy, attach the policy directly:

```yaml
operationPolicies:
  - name: openai-to-bedrock-transformer
    version: v1
    paths:
      - path: /chat/completions
        methods: [POST]
        params:
          model: us.amazon.nova-lite-v1:0
```

## Notes

- The policy translates payloads and paths only. Configure Bedrock authentication on the upstream provider.
- When `model` is omitted from the policy configuration, the OpenAI request's `model` field must contain a valid Bedrock model or inference-profile ID.
- Remote image URLs are not fetched; use base64 data URIs for image input.
- File input supports inline `file_data` only; `file_id` references are rejected with a `400`.
- Streaming translation expects Bedrock's `application/vnd.amazon.eventstream` framing.
