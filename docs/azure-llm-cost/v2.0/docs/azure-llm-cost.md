---
title: "Overview"
---
# Azure LLM Cost

## Overview

The Azure LLM Cost policy works out what each LLM call made through **Azure OpenAI** or **Azure AI Foundry** cost, in US dollars, and makes that figure available to the rest of the request pipeline. It runs in the response phase, once Azure has replied and reported how many tokens the call used.

The cost is never returned to the client. It is written to `SharedContext.Metadata`, which is how policies on the same route share data. The most common consumer is the [LLM Cost Based Ratelimit](../../../llm-cost-based-ratelimit/v1.0/docs/llm-cost-based-ratelimit.md) policy, which uses it to enforce a spending budget.

Azure differs from other providers in one way that matters here. You never call a model by name, you call a *deployment*, which is your own alias for a model instance. The pricing database is keyed by model name, so the policy needs to know which model sits behind each deployment. That mapping, and the tier each deployment runs on, are the only things you configure.

Usage itself is read from the `LlmProviderTemplate` on the route. The template says where the token counts, the model name and the billing tier sit in the response, and the policy follows those directions, so both Azure surfaces are handled the same way.

Use this policy for routes that reach an LLM through Azure. For a vendor's own endpoint use the [LLM Cost](../../../llm-cost/v1.1/docs/llm-cost.md) policy instead. The endpoint decides which applies, not the model: Mistral served by Azure AI Foundry belongs to this policy, Mistral served by Mistral directly belongs to the other.

## Features

- **Deployment-aware pricing**: Resolves the deployment name Azure reports back to the model that actually ran, so the right rate is charged.
- **Two product catalogues**: Prices Azure OpenAI models from the `azure/` catalogue and Azure AI Foundry models from `azure_ai/`, choosing between them from the provider template on the route.
- **Multi-vendor Foundry support**: One attachment covers the vendors Foundry serves over the OpenAI-compatible API, currently OpenAI, Mistral and DeepSeek, because each model is priced from whichever catalogue holds it.
- **Template-driven extraction**: Token counts, the model name and the billing tier come from the route's `LlmProviderTemplate`, so response-shape differences between the Azure surfaces live in configuration rather than in code.
- **Deployment tier pricing**: Applies Global Standard, Data Zone, or single-region rates per deployment, since the tier is chosen per deployment rather than per resource.
- **Streaming and non-streaming**: Chunks are passed on to the client as they arrive while a copy is kept, so usage reported only in the closing chunk is still picked up without holding up the stream.
- **Category and tier rates**: Charges cached input, cache writes, audio tokens and reasoning tokens at their own rates where the pricing entry defines them, along with priority and above-272k rates.
- **Never blocks a request**: If the cost cannot be worked out, it is reported as zero with a status saying so, and the response is passed through untouched.

## Configuration

### User Parameters (API Definition)

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `modelMappings` | array | Yes | - | The deployments this route can reach, and the model each one runs. |

Each entry describes one deployment:

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `deployment` | string | Yes | - | The Azure deployment name, for example `apip-4o-mini`. |
| `model` | string | Yes | - | The model it runs, for example `gpt-4o-mini`. This is the name looked up in the pricing database. |
| `region` | string | No | `global-standard` | The deployment type, which selects the pricing tier. |

List every deployment the route can reach. `region` sits on each entry rather than on the policy because two deployments in the same Azure resource can be on different tiers. Valid values are `global-standard` (Azure's default), `us`, `eu` or `apac` for a Data Zone deployment, and `regional` for a single-region one. Provisioned Throughput deployments are not covered, as they bill reserved capacity by the hour rather than by token.

### System Parameters (From config.toml)

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `pricing_file` | string | Yes | - | Path to the model pricing JSON file shipped with the gateway image, the same file the `llm-cost` policy uses. |

#### Sample System Configuration

```toml
[policy_configurations.azure_llm_cost_v2]
pricing_file = "/etc/policy-engine/llm-pricing/model_prices.json"
```

**Note:**

Inside the `gateway/build.yaml`, ensure the policy module is added under `policies:`:

```yaml
- name: azure-llm-cost
  gomodule: github.com/wso2/gateway-controllers/policies/azure-llm-cost/v2@v2
```

## Reference Scenarios

This policy runs in the response phase and should be placed after any policy that consumes the cost, because response-phase policies execute in reverse order. Every scenario below depends on the provider using one of the two Azure templates, `azure-openai` or `azureai-foundry`, since the policy reads that template to decide which catalogue applies.

### Example 1: Attach to an Azure OpenAI provider

```yaml
apiVersion: gateway.api-platform.wso2.com/v1
kind: LlmProvider
metadata:
  name: azure-openai-provider
spec:
  displayName: Azure OpenAI Provider
  version: v1.0
  context: /azure-openai
  template: azure-openai
  upstream:
    url: https://my-resource.openai.azure.com/openai/v1
    auth:
      type: api-key
      header: api-key
      value: ${AZURE_OPENAI_API_KEY}
  accessControl:
    mode: deny_all
    exceptions:
      - path: /chat/completions
        methods: [POST]
  operationPolicies:
    - name: azure-llm-cost
      version: v2
      paths:
        - path: /chat/completions
          methods: [POST]
          params:
            modelMappings:
              - deployment: apip-4o-mini
                model: gpt-4o-mini
                region: eu
              - deployment: prod-gpt5
                model: gpt-5.1
```

After each response the policy writes two entries to `SharedContext.Metadata`:

- `x-llm-cost`: the amount in USD as a string, to 10 decimal places, for example `"0.0000423100"`.
- `x-llm-cost-status`: `"calculated"` when the figure is real, or `"not_calculated"` when it could not be worked out.

The status matters because both cases report a number. A genuine zero-cost call and a failed lookup would otherwise look identical.

Usage is read through the shared LLM usage library, so that library publishes what it extracted at the same time, under `llm:usage:v1` and `llm:usage:status`. A policy that needs token counts rather than a cost can read those, and they are written even when the model has no pricing entry.

Here `apip-4o-mini` is priced from `azure/eu/gpt-4o-mini` when that key exists and from `azure/gpt-4o-mini` otherwise, while `prod-gpt5` omits `region` and is priced as Global Standard.

### Example 2: Several vendors on one Azure AI Foundry provider

A Foundry resource can serve models from several vendors as well as the OpenAI models it hosts. One attachment covers all of them, because each model is priced from whichever catalogue holds it. Set `template: azureai-foundry` on the provider, then:

```yaml
params:
  modelMappings:
    - deployment: my-deepseek
      model: deepseek-v3.1
    - deployment: my-mistral
      model: mistral-large
    - deployment: apip-gpt-5-6
      model: gpt-5.6-terra
```

The first two are Foundry's own models, priced from `azure_ai/`. The last is an OpenAI model hosted on Foundry, which appears only in `azure/`, and the policy finds it there.

### Example 3: Enforce a spending budget

List `llm-cost-based-ratelimit` first. Response-phase policies run in reverse order, so `azure-llm-cost` calculates the cost and `llm-cost-based-ratelimit` then deducts it from the budget.

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
  - name: azure-llm-cost
    version: v2
    paths:
      - path: /chat/completions
        methods: [POST]
        params:
          modelMappings:
            - deployment: apip-4o-mini
              model: gpt-4o-mini
```

## How It Works

The clearest way to see what the policy does is to follow one call through it. The example below reaches an Azure OpenAI provider published at context `/az-01`, on the legacy surface where the deployment sits in the URL. The route maps that deployment to a Data Zone deployment in the EU:

```yaml
modelMappings:
  - deployment: apip-gpt-4.1
    model: gpt-4.1-2025-04-14
    region: eu
```

The client sends:

```
POST /az-01/openai/deployments/apip-gpt-4.1/chat/completions?api-version=2024-02-01
```
```json
{ "messages": [ { "role": "user", "content": "Say hello!" } ] }
```

Azure replies:

```json
{
  "object": "chat.completion",
  "model": "gpt-4.1-2025-04-14",
  "service_tier": "default",
  "usage": { "prompt_tokens": 10, "completion_tokens": 11, "total_tokens": 21 }
}
```

### 1. Collect the response

Every chunk is copied into a buffer and forwarded on straight away, so nothing is held back. Pricing runs once the closing chunk arrives, against the buffered copy.

### 2. Decide which catalogue applies

The product comes from the provider template recorded on the route, not from the path. `azure-openai` selects the `azure/` catalogue and `azureai-foundry` selects `azure_ai/` with `azure/` behind it. The path cannot be used, because Foundry serves the OpenAI-compatible API on the same path Azure OpenAI does. A route using neither template is left unpriced and a warning is logged once, rather than being billed against a catalogue that may not apply.

### 3. Work out which endpoint was called

The query string is dropped and the API's context, `/az-01`, is stripped from the front, leaving `/openai/deployments/apip-gpt-4.1/chat/completions`. That is what the template's `resourceMappings` are matched against, and it still carries the deployment segment for the next step.

### 4. Read the values the template points at

| Template field | Identifier | Value found |
|---|---|---|
| `promptTokens` | `$.usage.prompt_tokens` | 10 |
| `completionTokens` | `$.usage.completion_tokens` | 11 |
| `responseModel` | `$.model` | `gpt-4.1-2025-04-14` |
| `serviceTier` | `$.service_tier` | `default` |

`default` is not one of the tiers that carries its own rates, so this call is billed at the standard rate.

### 5. Work out the deployment tier, then the model

These are two separate lookups against `modelMappings`, and the tier comes first because it decides which pricing namespaces the model is then searched for.

The tier is looked up by deployment name, taken from what the caller addressed: the request-side candidates, plus the deployment in `/deployments/{name}/` when the URL carries one. The name the response returned is not consulted for the tier.

The model is resolved from the full candidate list: response first, then request, then the URL deployment. Each is looked up in `modelMappings` first and used directly second, so a mapping always wins over the name Azure reported.

Here the URL supplies `apip-gpt-4.1`, which the route maps, so the tier is `eu`. Had that deployment been absent from `modelMappings`, the tier would have fallen back to Global Standard and that would be logged once for the deployment. This response carried a model name, so `gpt-4.1-2025-04-14` is what gets priced.

### 6. Find the pricing entry

The namespaces are tried in order until one matches a whole key. The tier comes first, the base entry second:

```
azure/eu/gpt-4.1-2025-04-14                 miss
azure/gpt-4.1-2025-04-14                    hit
```

The catalogue carries no EU entry for this model, so the base entry is used and the call is billed at Global Standard rates despite the deployment being in an EU Data Zone. That is logged once per model and tier, so it is visible rather than silent:

```
azure-llm-cost: no pricing entry for the configured tier, billing at the base rate
  model=gpt-4.1-2025-04-14
  missing_key=azure/eu/gpt-4.1-2025-04-14
  used_key=azure/gpt-4.1-2025-04-14
```

A Global Standard deployment takes the same path without the warning, since the base entry already holds its rates.

Only complete matches count. A name the catalogue does not carry is reported as unpriced rather than trimmed until it happens to match something else.

### 7. Price each category and add up

Cached, cache-write, audio and reasoning tokens are subtracted from the two totals before being charged at their own rates, so nothing is counted twice. This call has none of them, so it reduces to text input and text output:

```
input     10 x 0.000002   = 0.00002
output    11 x 0.000008   = 0.00008
                            0.00010800
```

### 8. Publish the result

```
x-llm-cost         "0.0001080000"
x-llm-cost-status  "calculated"
```

Analytics separately receives the cost together with the model and the token counts. The response body itself is forwarded to the client untouched.

## Limitations

- Model names must match a pricing key exactly. There is no partial matching, because `gpt-4o` and `gpt-4o-mini` are priced very differently and matching loosely would quietly bill the wrong rate. A model absent from the database is reported unpriced instead.
- Azure reports dated snapshots such as `gpt-4.1-2025-04-14`, and each needs its own key. A newly released snapshot is unpriced until the database is updated, or until a mapping points the deployment at a model it already carries.
- A streamed chat completions call reports no token usage unless the request asks for it with `"stream_options": {"include_usage": true}`. Without it Azure sends no `usage` object at all, on Azure OpenAI and Azure AI Foundry alike, so the call is recorded as unpriced. The Responses API always reports usage and needs no extra parameter.
- The `azureai-foundry` template reads the OpenAI-compatible response shape, which covers the vendors Foundry currently serves that way, namely OpenAI, Mistral and DeepSeek. A vendor that answers in its own shape is not read by it. Anthropic is the case today, so a Foundry route serving Anthropic models should use version 1 of this policy for now. Templates for the remaining vendors are planned, and this policy will price them once those exist, with no change to the policy itself.
- Web search, image, character, per-second and code interpreter charges are not applied. A model priced only in those units is reported unpriced.
- `region` prefixes keys in the `azure/` catalogue only. The `azure_ai/` keys shipped today are not tier-scoped, so it has no effect on a Foundry-native model, though it still applies to an OpenAI model hosted on Foundry.

## Related Policies

- [LLM Cost](../../../llm-cost/v1.1/docs/llm-cost.md) prices calls to a vendor's own endpoint. Use it instead of this policy for non-Azure routes, never alongside it.
- [LLM Cost Based Ratelimit](../../../llm-cost-based-ratelimit/v1.0/docs/llm-cost-based-ratelimit.md) reads `x-llm-cost` and enforces a spending budget.

## Notes

- Do not attach this policy and version 1 of `azure-llm-cost` to the same route. They write the same metadata entries and would overwrite each other.
- A route whose template is neither `azure-openai` nor `azureai-foundry` cannot be priced. The cost is reported as `0.0000000000` with status `not_calculated`, and a warning is logged once for that template.
- The same applies when the model is missing from the pricing file. The warning names what was looked for, and the request still goes through.
- Leaving a deployment out of `modelMappings` costs you the tier, which falls back to Global Standard and is logged once, and on the endpoints that report the deployment name rather than the model, it also means that name is priced as though it were a model. Mapping every deployment covers both cases.
- The pricing file is read once and kept for the life of the process, so a restart is needed after editing it.
- Adding a rate for a new model, tier or token category is a data change to the pricing database and needs no new gateway build.
- When a cost of `0` appears, read `x-llm-cost-status` rather than the amount. The gateway log always records why a request went unpriced, naming the model or deployment involved.
