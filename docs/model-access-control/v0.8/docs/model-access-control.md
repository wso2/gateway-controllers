---
title: "Overview"
---
# Model Access Control

## Overview

The Model Access Control policy checks the model a client requests against an
allow or deny list before the request reaches the LLM provider. A permitted
model is forwarded unchanged. A denied model is sent to a fallback model, and
optionally to another provider of the LLM proxy, when a fallback mapping
matches it. Otherwise it is rejected with `404 model_not_found`, and the
provider is never called.

The policy changes requests only. Responses pass through untouched, so after a
fallback the client sees the model name the provider returns, not the name it
requested.

## How a request is decided

```text
read the client-requested model
  → the request names no model      → apply onMissingModel
  → the access rule permits it      → forward the request unchanged
  → the access rule denies it       → look for a fallback mapping
      → a mapping matches           → rewrite the model, select the mapping's provider, forward
      → no mapping matches          → reject with 404 before the upstream call
```

| `access.mode` | Requested model is listed in `models` or `modelPatterns` | Action |
|---|---|---|
| `allow` | Yes | Forward unchanged |
| `allow` | No | Use a fallback mapping, otherwise reject |
| `deny` | Yes | Use a fallback mapping, otherwise reject |
| `deny` | No | Forward unchanged |

The access rule applies to the **requested** model only:

- A permitted model is never redirected, even when a fallback mapping matches
  it. With `mode: allow`, leave a model out of `models` if you want its
  fallback mapping to apply.
- A fixed fallback target is a destination the administrator chose, so it is
  not checked against the access rule. A target built from a capture group is
  checked (see [Fallback mappings](#fallback-mappings)).

## Configuration

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `access` | object | Yes | - | Access rule applied to the requested model. |
| `access.mode` | string | Yes | - | `allow` (only the listed models are permitted) or `deny` (the listed models are rejected, every other model is permitted). |
| `access.models` | array of string | Yes | - | Model names the mode applies to. At least one entry. |
| `access.modelPatterns` | array of string | No | - | RE2 expressions for more models the mode applies to. At most 50, each up to 512 characters. |
| `access.onMissingModel` | string | No | `deny` | `deny` or `skip`. See [Requests without a model](#requests-without-a-model). |
| `fallback.mappingPatterns` | array | No | - | Fallback mappings for denied models, tried in order. At most 50. A `fallback` without `mappingPatterns` redirects nothing. |
| `fallback.mappingPatterns[].fromPattern` | string | Yes | - | RE2 expression that must match the whole requested model. Up to 512 characters. |
| `fallback.mappingPatterns[].to` | string | Yes | - | Fallback model sent to the provider, as plain text. At most 1024 bytes of valid UTF-8, without control characters. |
| `fallback.mappingPatterns[].provider` | string | No | primary provider | Primary provider name or additional-provider alias of the LLM proxy, matched exactly. The name is not checked when the policy is deployed. |

### Matching models

- A name in `models` matches the requested model exactly, ignoring case and
  surrounding whitespace. `gpt-4o` never matches `gpt-4o-mini`.
- `modelPatterns` and `fromPattern` are RE2 expressions that must match the
  whole name: `gpt-4o|gpt-4o-mini` is applied as `^(?:gpt-4o|gpt-4o-mini)$`.
- `modelPatterns` ignore case, like `models`; start one with `(?-i)` to make it
  case-sensitive. `fromPattern` is case-sensitive unless it starts with `(?i)`.
- A dot matches any character, so escape it: `gpt-4\.1` matches only
  `gpt-4.1`, while `gpt-4.1` also matches `gpt-401`.
- A requested model longer than 1024 bytes, or one that contains a control
  character or invalid UTF-8, is rejected with `400`. An upstream that strips
  such characters could read a different model from the one the policy checked.

### Fallback mappings

- Fallback mappings are tried in the order they are declared, and the first
  match wins. Put specific patterns before general ones.
- To redirect a single model, write its name as `fromPattern`, for example
  `(?i)gpt-4o`. Because the pattern must match the whole name, it does not
  match `gpt-4o-mini`.
- `to` is plain text, not a regular expression: write a target such as
  `us.amazon.nova-lite-v1:0` as is. `$1`, `${1}` and `${name}` insert capture
  groups of `fromPattern`; `$$` is a literal `$`.
- A target that inserts a capture group is partly chosen by the client, so it
  must also pass the access rule, otherwise the request is rejected with `404`.
  With `mode: allow`, list such targets in `models` or `modelPatterns`;
  otherwise `legacy-(.*)` → `$1` would forward any model a client names.
- A fallback mapping without `provider` sends the request to the proxy's
  primary provider.

| `fromPattern` | `to` | Redirects |
|---|---|---|
| `gpt-4o` | `my-gpt4o` | `gpt-4o` only |
| `(?i)gpt-4o` | `my-gpt4o` | `gpt-4o`, `GPT-4o`, `Gpt-4O` |
| `gpt-4\.1` | `gpt-4.1-mini` | `gpt-4.1` only |
| `(?i)claude-.*` | `us.anthropic.claude-haiku-4-5-20251001-v1:0` | every name starting with `claude-` |
| `gpt-(.+)` | `my-gpt$1` | `gpt-4o` → `my-gpt4o`, if the access rule permits `my-gpt4o` |

### LLM provider template configuration

The policy also needs the `requestModel` system parameter, which the gateway
controller injects from the LLM provider template, including a resource-specific
override when the template has one. It is not a user-configurable parameter.

| System parameter | Type | Required | Description |
|---|---|---|---|
| `requestModel.location` | string | Yes | `payload`, `header`, `queryParam` or `pathParam`. |
| `requestModel.identifier` | string | Yes | A dotted JSONPath such as `$.model` for `payload`, a header name for `header`, a query parameter name for `queryParam`, or an RE2 expression for `pathParam`. When `mappingPatterns` is configured, a `pathParam` expression must have a capture group around the model, for example `/models/([^/]+)/chat`. |

For `payload`, the policy buffers the request body. For the other locations it
reads only the request headers and the path, and never buffers the body.

On an LLM proxy, the template is the one named by the proxy's
`inboundTemplate`, which describes the format clients send. Without it, the
primary provider's template is used. Set `inboundTemplate` when clients send a
different format from the primary provider's. For example, clients send
OpenAI-format requests to a proxy whose only provider is AWS Bedrock with an
`openai-to-bedrock-transformer`. With `inboundTemplate: openai`, the model is
read from `$.model` in the body. Without it, the policy looks for the model in a
Bedrock `/model/<id>/...` path, finds none in `/chat/completions`, and rejects
every request with `400`.

## Examples

### Allow list with fallback mappings

```yaml
params:
  access:
    mode: allow
    models:
      - gpt-4o
      - claude-sonnet
    onMissingModel: deny
  fallback:
    mappingPatterns:
      - fromPattern: "(?i)old-model"
        to: gpt-4o
      - fromPattern: "(?i)claude-friendly"
        to: claude-sonnet
        provider: anthropic
```

- `gpt-4o` and `claude-sonnet` are forwarded unchanged.
- `old-model` is forwarded to the primary provider as `gpt-4o`.
- `claude-friendly` is forwarded to the `anthropic` additional provider as
  `claude-sonnet`.
- Any other model is rejected with `404 model_not_found`.

### Deny list with pattern fallback mappings

```yaml
params:
  access:
    mode: deny
    models:
      - gpt-4-32k
    modelPatterns:
      - "(?i).*-preview"
  fallback:
    mappingPatterns:
      - fromPattern: "gpt-4-32k"
        to: gpt-4o
      - fromPattern: "claude-(\\w+)-preview"
        to: "claude-$1"
        provider: anthropic
```

Every model is permitted except `gpt-4-32k` and names ending in `-preview`.
`gpt-4-32k` falls back to `gpt-4o`; `claude-opus-preview` falls back to
`claude-opus` on `anthropic`; `gpt-5-preview` is rejected.

### Attach to an LLM proxy operation

```yaml
apiVersion: gateway.api-platform.wso2.com/v1
kind: LlmProxy
metadata:
  name: governed-proxy
spec:
  displayName: Governed Proxy
  version: v1.0
  context: /governed
  provider:
    id: openai-provider
  additionalProviders:
    - id: anthropic-provider
      as: anthropic
  policies:
    - name: model-access-control
      version: v0
      paths:
        - path: /chat/completions
          methods: [POST]
          params:
            access:
              mode: allow
              models: [gpt-4o]
            fallback:
              mappingPatterns:
                - fromPattern: "(?i)claude-friendly"
                  to: claude-sonnet
                  provider: anthropic
```

The policy can also be attached to an `LlmProvider`.

### Attach proxy-wide

```yaml
apiVersion: gateway.api-platform.wso2.com/v1
kind: LlmProxy
metadata:
  name: proxy-a
spec:
  displayName: Proxy A
  version: v1.0
  context: /proxy-a
  inboundTemplate: openai
  provider:
    id: bedrock-shared
    transformer:
      type: openai-to-bedrock-transformer
      version: v0
  globalPolicies:
    - name: model-access-control
      version: v0
      params:
        access:
          mode: allow
          models:
            - us.anthropic.claude-haiku-4-5-20251001-v1:0
            - us.amazon.nova-lite-v1:0
          onMissingModel: skip
```

A proxy-wide attachment runs on every route of the proxy, including routes
that never carry a model. Set `onMissingModel: skip` so those keep working:

| Request | `deny` (default) | `skip` |
|---|---|---|
| `POST /chat/completions` with a listed model | Forwarded | Forwarded |
| `POST /chat/completions` with an unlisted model | `404` | `404` |
| `POST /chat/completions` without a model | `400` | `400` |
| `GET /models`, `GET` or `DELETE /files/{id}` | `400` | Forwarded unchanged |
| `POST /files` (multipart, no `model` field) | `400` | Forwarded unchanged |
| `POST /audio/transcriptions` (multipart) with an unlisted `model` field | `404` | `404` |

On a single inference route such as `/chat/completions`, `onMissingModel` makes
no difference.

## Provider routing

When a fallback mapping names a provider, the policy routes the request to that
provider and publishes `selected_provider` in the same step, so the provider's
credentials and protocol transformer apply to the same target. This works for
every model location, including `payload`. A fallback mapping without a
provider, and a permitted model, keep the proxy's primary provider and do not
set `selected_provider`.

If an earlier policy has already selected a provider, the policy rejects a
mapped request whose provider differs (or whose fallback mapping names no
provider) with `500 routing_error`, instead of sending the fallback model to the
wrong provider. A permitted model ignores an earlier selection. Do not combine
this policy with another policy that rewrites the model or selects a provider
on the same operation.

## Requests without a model

A request that does not carry exactly one usable model is rejected with
`400 invalid_model`: the model is missing, empty, not a string, unreadable (for
example malformed JSON or an invalid percent-encoding), too long, or given more
than once. See [Edge cases](#edge-cases) for what counts as "more than once".

With `onMissingModel: skip`, a request without a model is forwarded unchanged
only when it cannot carry an inference model:

- a `GET`, `HEAD`, `DELETE` or `OPTIONS` request;
- a multipart or URL-encoded body without the model field, such as a file upload;
- a body that is neither JSON nor text, such as `application/octet-stream`.

Every other request without a usable model is still rejected with `400`,
including a JSON body without a model. Use `skip` for a proxy-wide attachment
that also covers model-less routes. A model that is present is always checked,
including the `model` field of a multipart or URL-encoded body.

## How the request is rewritten

- A rejected request is never partly modified: every check runs before the
  model is rewritten or a provider is selected.
- A request whose model is not changed is forwarded byte for byte.
- A fallback on a JSON body re-encodes the body: object keys are sorted, while
  numbers and text keep their exact values. On a multipart or URL-encoded body,
  the model field is rewritten.
- A header, query or path rewrite replaces only the model's bytes.
- A fallback target of `.` or `..` is never written into a path, and a target
  that contains the multipart boundary is never written into a multipart body.
  Either is rejected with `500 routing_error`.

## Responses and errors

Rejections use the status codes and error shape that OpenAI and Anthropic use
themselves, so existing client error handling keeps working. The bodies never
name the requested model, a configured model or a provider.

A model the access rule denies, with no fallback mapping, returns `404`. As with
OpenAI, a restricted model and a model that does not exist get the same
response, so the response does not reveal which models exist behind the API:

```json
{"error":{"message":"The model does not exist or you do not have access to it.","type":"invalid_request_error","param":"model","code":"model_not_found"}}
```

A request whose model is missing, unreadable or given more than once returns
`400`:

```json
{"error":{"message":"The request must specify exactly one valid model.","type":"invalid_request_error","param":"model","code":"invalid_model"}}
```

A configuration fault at request time, such as a provider conflict or a pattern
that expands to an empty model, returns `500`:

```json
{"error":{"message":"The request could not be routed.","type":"server_error","code":"routing_error"}}
```

The policy does not filter model lists. A `GET /models` request that `skip`
forwards returns every model the provider lists, including models the access
rule denies. Requests for those models are still rejected. To hide the list,
do not expose the `/models` route on the proxy.

## Fault reporting

Every rejection is reported to the gateway as a fault. The gateway uses it for
the analytics event and passes it to the API's fault policies. The fault's
`Description` holds the internal reason (for example the denied model name) and
never reaches the client.

| When | Status | Code | Type |
|---|---|---|---|
| The access rule denies the model and no fallback mapping matches | `404` | `900908` | `authorization` |
| The model in the request body is missing, unreadable or repeated | `400` | `960001` | `validation` |
| The model header is missing or repeated | `400` | `960004` | `validation` |
| The model query parameter or path segment is missing, unreadable or repeated | `400` | `960005` | `validation` |
| A provider conflict, an unusable pattern expansion or a failed rewrite | `500` | `960000` | `mediation` |

## Metadata

The policy publishes the following values to `SharedContext.Metadata`:

| Key | Description |
|---|---|
| `model_access_control.requested_model` | Requested model, trimmed. |
| `model_access_control.effective_model` | Model forwarded to the provider. |
| `model_access_control.decision` | `permitted`, `mapped`, `denied`, `skipped` or `error`. |
| `model_access_control.mapping_matched` | Whether a fallback mapping supplied the effective model. |
| `selected_provider` | Set only when a fallback mapping names a provider. |

The analytics event carries `model_access_decision`, `requested_model`,
`effective_model` and `mapping_matched`, with model names truncated to 128
bytes.

## Edge cases

These rules close gaps where the policy and the upstream could read a request
differently. Each case below is rejected with `400`.

### A model given more than once

Anything an upstream parser could read as a second model counts:

- two headers, or one header holding two values joined with a comma;
- two query values or form fields, or a key that some parser reads as the model:
  one that differs only in case or surrounding spaces (`MODEL`, `Model`), one
  with an array suffix (`model[]`), or one behind a `;` separator
  (`x=1;model=...`);
- two multipart parts named `model` in any case;
- a repeated JSON key on the model's path, including keys that differ only in
  case (`model` and `MODEL`);
- two matches of the `pathParam` expression in one path, also after encoded
  slashes are decoded. A path that matches the expression only after they are
  decoded is rejected too, because its model is hidden from the policy.

### Model in the path (`pathParam`)

- An encoded slash (`%2F`) inside the model stays part of it, so a Bedrock
  inference-profile ARN is read and rewritten whole.
- If the template's expression cannot read past an encoded character, the
  request is rejected instead of checking only part of the model.
- A path with a `.` or `..` segment, written plainly or encoded (`%2e%2e`, or
  behind an encoded slash), is rejected, because an upstream that resolves it
  would read a different model from the one the policy checked.

### Model in the body (`payload`)

- The body's content decides how it is read, not its `Content-Type`. A body
  that starts with `{` or `[` (after whitespace and an optional byte order mark)
  is always read as JSON.
- A body in UTF-16 or UTF-32, recognised by its byte order mark or NUL bytes as
  Python's `json` module does, also counts as JSON and is rejected, because the
  policy reads only UTF-8.
- Otherwise, a multipart or URL-encoded body is read from the form field named
  by the template's JSONPath (`model` for `$.model`), so endpoints such as
  `/audio/transcriptions` and `/images/edits` are checked like JSON requests.

### Rejected even with `onMissingModel: skip`

- a body that looks like JSON but has no model, or does not parse strictly (for
  example a byte order mark or a trailing comma), whatever its `Content-Type`;
- a `text/*` body that cannot be read, because a lenient upstream could still
  read it as JSON;
- a request whose query string or path cannot be decoded;
- a multipart body with no part at all;
- a form that cannot be parsed, or a multipart part whose field name parsers
  could read differently: more than one `Content-Disposition` header, a
  repeated or malformed parameter, or an RFC 2231 encoded name (`name*=`);
- a `model` part with a `Content-Transfer-Encoding`;
- a model given more than once.
