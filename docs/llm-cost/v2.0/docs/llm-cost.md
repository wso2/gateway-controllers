---
title: "Overview"
---
# LLM Cost

## Overview

The LLM Cost policy works out what each LLM call cost, in US dollars, and makes that figure available to the rest of the request pipeline. It runs in the response phase, once the provider has replied and reported how many tokens the call used.

The cost is never returned to the client. It is written to `SharedContext.Metadata`, which is how policies on the same route share data. The most common consumer is the [LLM Cost Based Ratelimit](../../../llm-cost-based-ratelimit/v1.0/docs/llm-cost-based-ratelimit.md) policy, which uses it to enforce a spending budget.

**Providers supported out of the box:** OpenAI, Anthropic, Google Gemini (AI Studio and Vertex AI), Mistral, and AWS Bedrock. Each ships with an `LlmProviderTemplate`, so for these providers you only need to attach the policy.

The template says where the token counts, the model name, and the billing tier sit in a given provider's request and response, and the policy follows those directions. A new API surface on a provider already listed is therefore a template change on its own, as is a new provider that bills purely per token. A provider that also charges for something other than tokens, such as a web search call, or that applies a multiplier to the total, needs a matching calculator added to the policy as well.

Use this policy when you need to:

- Track spend per API call for billing or observability.
- Give a budget-enforcing policy accurate per-call costs.
- Attribute cost across several providers from a single gateway.

## Features

- **Template-driven**: Token counts, the model name, and the billing tier are read from the route's `LlmProviderTemplate`, so those provider differences live in configuration rather than in code.
- **Streaming and non-streaming**: Both are handled the same way. Chunks are passed on to the client as they arrive while a copy is kept, so usage reported only in the closing chunk is still picked up without holding up the stream.
- **Finds the model wherever it is**: The response body, the request body, or the request URL, whichever the template points at. A provider that does not echo the model back is still priced, from what the caller asked for.
- **One template, several API surfaces**: A provider that reports the same counts under different names on different paths, such as a chat endpoint and a newer responses endpoint, is covered by a single template.
- **Prices more than plain tokens**: Prompt caching, reasoning tokens, and audio and image tokens are billed at their own rates. Charges that are not token counts at all, such as web search or grounding calls, are added by a per-provider calculator where the pricing file defines a rate.
- **Follows the pricing file**: Large-context tiers and cheaper or premium service tiers are applied when the model's pricing entry defines them, and the standard rate is used when it does not.
- **Never blocks a request**: If the cost cannot be worked out, it is reported as zero with a status saying so, and the response is passed through untouched.
- **Publishes analytics**: The cost is sent to analytics for every call. The model and token counts are also sent when pricing succeeded; analytics collects those independently in any case.

## Configuration

This policy has no user parameters. Everything is configured by the gateway administrator.

### System Parameters (From config.toml)

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `pricing_file` | string | Yes | - | Path to the model pricing JSON file shipped with the gateway image. Gateway administrators can override this path in `config.toml`. |

#### Sample System Configuration

```toml
[policy_configurations.llm_cost_v2]
pricing_file = "/etc/policy-engine/llm-pricing/model_prices.json"
```

**Note:**

Inside the `gateway/build.yaml`, ensure the policy module is added under `policies:`:

```yaml
- name: llm-cost
  gomodule: github.com/wso2/gateway-controllers/policies/llm-cost/v2@v2
```

### Template Fields Used

The shipped templates already declare everything below. This section matters when you are writing a template for a provider of your own. A template covers extraction and per-token pricing on its own; a charge that is not a token count, or a multiplier applied to the total, additionally needs a calculator in the policy.

Each field names where its value lives. `location: payload` is a JSONPath into a JSON body, and `location: pathParam` is a regular expression over the request URL whose first capture group is the value. Any other location yields nothing. A field may also list `fallbackIdentifiers`, further places to look when the first one is empty:

```yaml
promptTokens:
  location: payload
  identifier: $.usage.prompt_tokens
  fallbackIdentifiers:
    - $.usage.input_tokens
```

Which body a payload identifier reads is decided by the field, not by the template. The token counts, the billing tier and `responseModel` are read from the response. `requestModel` is read from the request, which is why the policy buffers the request body.

Every field is optional. One that is absent is treated as zero or empty, and only the model name is required for a cost to be calculated.

| Field | Purpose |
|-------|---------|
| `promptTokens` | Input token count. |
| `completionTokens` | Output token count. |
| `totalTokens` | Provider-reported total. Derived from input plus output when absent. |
| `cachedTokens` | Input tokens served from the prompt cache, billed at the cache-read rate. |
| `cacheWriteTokens` | Tokens written to the prompt cache with the default (5-minute) TTL. |
| `cacheWrite1hTokens` | Tokens written with the extended 1-hour TTL, billed at the extended-TTL rate when the pricing entry defines one and at the standard cache-write rate otherwise. |
| `reasoningTokens` | Reasoning or thinking tokens, where the provider rates them apart from output. |
| `audioInputTokens` | Audio input tokens, re-billed at the audio rate. |
| `audioOutputTokens` | Audio output tokens, re-billed at the audio rate. |
| `serviceTier` | Billing tier served. A `valueMap` normalises it to `priority`, `flex`, or `batch`; anything else, including an absent field, prices at the standard rates. |
| `requestModel` | Model name as sent, read from the request body or the request path. |
| `responseModel` | Model name as reported in the response, preferred over `requestModel` when present. |
| `providerFields` | Named payload locations the per-provider fee calculators read, from the response or the request depending on the charge. |
| `cacheAccounting` | `additive` when the cached and cache-write counts sit outside the reported input total. Any other value means they are already inside it. |
| `resourceMappings` | Per-resource overrides of any of the above, so one template can cover a provider's several API surfaces. |

## Reference Scenarios

This policy runs in the response phase. Place it after any policy that consumes the cost, because response-phase policies execute in reverse order.

### Example 1: Attach to a Provider

The `template` field selects the `LlmProviderTemplate` used to read usage. Nothing else is needed on the provider itself, given the `pricing_file` the gateway administrator has set:

```yaml
apiVersion: gateway.api-platform.wso2.com/v1
kind: LlmProvider
metadata:
  name: openai-provider
spec:
  displayName: OpenAI Provider
  version: v1.0
  context: /openai
  template: openai
  upstream:
    url: https://api.openai.com/v1
    auth:
      type: api-key
      header: Authorization
      value: Bearer ${OPENAI_API_KEY}
  accessControl:
    mode: deny_all
    exceptions:
      - path: /chat/completions
        methods: [POST]
  operationPolicies:
    - name: llm-cost
      version: v2
      paths:
        - path: /chat/completions
          methods: [POST]
```

After each response the policy writes two entries to `SharedContext.Metadata`:

- `x-llm-cost`: the amount in USD as a string, to 10 decimal places, for example `"0.0000423100"`.
- `x-llm-cost-status`: `"calculated"` when the figure is real, or `"not_calculated"` when it could not be worked out.

The status matters because both cases report a number. A genuine zero-cost call and a failed lookup would otherwise look identical.

Usage is read through the shared LLM usage library, so that library publishes what it extracted at the same time:

- `llm:usage:v1`: the token breakdown, covering input and uncached input, cached and cache-write tokens, output, reasoning and audio tokens, the total, the billing tier, and the resolved model name.
- `llm:usage:status`: `"extracted"`, `"no_usage"`, or `"template_missing"`, describing the extraction rather than the pricing.

A policy that needs token counts rather than a cost can read those two. They are written even when the model has no pricing entry, so they are still available on a call this policy reports as `not_calculated`.

### Example 2: Enforce a Spending Budget

Pairing this policy with `llm-cost-based-ratelimit` is the main use case. List the rate limit policy first: response-phase policies run in reverse order, so `llm-cost` calculates the cost and `llm-cost-based-ratelimit` then deducts it from the budget.

```yaml
  operationPolicies:
    - name: llm-cost-based-ratelimit
      version: v1
      paths:
        - path: /chat/completions
          methods: [POST]
          params:
            budgetLimits:
              - amount: 10
                duration: "24h"
    - name: llm-cost
      version: v2
      paths:
        - path: /chat/completions
          methods: [POST]
```

### Example 3: Cover Every Path on a Provider

A provider often exposes more than one endpoint, and some carry the model name in the URL rather than the response body. A single catch-all attachment covers all of them, because the policy works out which endpoint was called from the request URL and applies the matching part of the template:

```yaml
  accessControl:
    mode: allow_all
  operationPolicies:
    - name: llm-cost
      version: v2
      paths:
        - path: /*
          methods: [POST]
```

Narrower patterns work the same way, so a Bedrock provider can be attached at `/model/*` instead if you prefer to be explicit.

## How It Works

The clearest way to see what the policy does is to follow one call through it. The example below is an ordinary chat completion against the OpenAI provider from Example 1, published at context `/openai`.

The client sends:

```
POST /openai/chat/completions
```
```json
{ "model": "gpt-4o-mini-2024-07-18", "messages": [ ... ] }
```

The provider replies:

```json
{
  "model": "gpt-4o-mini-2024-07-18",
  "usage": {
    "prompt_tokens": 1000,
    "completion_tokens": 200,
    "total_tokens": 1200,
    "prompt_tokens_details": { "cached_tokens": 400 }
  }
}
```

### 1. Collect the response

The policy sees the response one chunk at a time. Every chunk is copied into a buffer and then forwarded on straight away, so nothing is held back and the client reads the stream at the speed the provider produced it. For a buffered reply like this one there is a single chunk carrying the whole body.

Pricing happens only once the chunk marked as the end of the stream arrives, and it runs against the buffered copy. At that point, if the provider streamed server-sent events, those events are merged into one document, so a model name announced in the opening event and usage reported only in the closing event are read together.

### 2. Work out which endpoint was called

The called path is `/openai/chat/completions`. The API's context, `/openai`, is stripped from the front, leaving `/chat/completions`. That is what gets matched against the template's `resourceMappings`.

Nothing in the OpenAI template matches `/chat/completions`, so the template root applies as written. Had the call gone to `/responses` instead, the `/responses` mapping would have replaced four of the fields, because that API reports its counts as `usage.input_tokens` and `usage.output_tokens`.

### 3. Read the values the template points at

Each of these is a JSONPath into the response body:

| Template field | Identifier | Value found |
|---|---|---|
| `promptTokens` | `$.usage.prompt_tokens` | 1000 |
| `completionTokens` | `$.usage.completion_tokens` | 200 |
| `totalTokens` | `$.usage.total_tokens` | 1200 |
| `cachedTokens` | `$.usage.prompt_tokens_details.cached_tokens` | 400 |
| `responseModel` | `$.model` | `gpt-4o-mini-2024-07-18` |

`responseModel` produced a name, so `requestModel` is not needed. Had the response omitted the model, that same read would have run against the request body and found it in the `model` the client sent.

### 4. Settle the cache accounting

The template sets `cacheAccounting: inclusive`, which says the 400 cached tokens are counted inside the 1000 rather than on top of them. The input therefore splits into 600 tokens charged at the standard rate and 400 charged at the cheaper cache rate.

Under `additive` the same response would have meant 1400 input tokens, 400 of them cached.

### 5. Look up the model

`gpt-4o-mini-2024-07-18` matches a pricing key exactly:

| Rate | Value per token |
|---|---|
| input | 0.00000015 |
| output | 0.00000060 |
| cache read | 0.000000075 |

Only a complete key match counts. A name the file does not carry is reported as unpriced rather than being trimmed until it happens to match something else. The 1000 input tokens sit below every large-context threshold and the response named no billing tier, so these standard rates stand.

### 6. Price each category and add up

```
uncached input    600 x 0.00000015   = 0.00009
output            200 x 0.00000060   = 0.00012
cache read        400 x 0.000000075  = 0.00003
                                       0.00024
```

### 7. Publish the result

```
x-llm-cost         "0.0002400000"
x-llm-cost-status  "calculated"
llm:usage:v1       input 1000, uncached 600, cached 400, output 200, total 1200
llm:usage:status   "extracted"
```

Analytics separately receives the same cost together with the model and the three token counts. The response body itself is forwarded to the client untouched.

## Notes

- A route with no `LlmProviderTemplate` cannot be priced. The cost is reported as `0.0000000000` with status `not_calculated`, and a warning is logged.
- The same applies when the model is missing from the pricing file. The warning names what was looked for, and the request still goes through.
- The pricing file is read once and kept for the life of the process, so a restart is needed after editing it.
- A billing tier the policy does not recognise, or one the model has no special rate for, is charged at the standard rate. This is normal and is not treated as a failure.
