---
title: "Overview"
---
# Azure LLM Cost

## Overview

The Azure LLM Cost policy calculates the monetary cost of an LLM API call made through **Azure OpenAI** or **Azure AI Foundry** at response time and stores the result in `SharedContext.Metadata`. The cost is not exposed as a response header, so it is only available to other policies in the same pipeline, such as the [LLM Cost Based Ratelimit](../../../llm-cost-based-ratelimit/v1.0/docs/llm-cost-based-ratelimit.md) policy.

Azure differs from other providers in one way that matters here: you never call a model by name, you call a *deployment*, which is your own alias for a model instance. Because the pricing database is keyed by model name, the policy needs to know which model sits behind each deployment. That model-deployment mapping and the deployed region are the only configurations it requires.

Use this policy for routes that reach an LLM through Azure. For a vendor's own endpoint, use the [LLM Cost](../../../llm-cost/v1.1/docs/llm-cost.md) policy instead. The endpoint decides which applies, not the model: Claude served by Azure AI Foundry belongs to this policy, Claude served by Anthropic directly belongs to the other. Never attach both to the same route, as they write to the same metadata keys.

## Features

- **Deployment-Aware Pricing**: Resolves the deployment name Azure reports back to the model that actually ran.
- **Two Product Catalogs**: Prices Azure OpenAI models from the `azure/` catalog and Azure AI Foundry models from `azure_ai/`, choosing between them from the provider template on the route.
- **Multi-Vendor Foundry Support**: Prices the vendors currently served through Azure AI Foundry, namely **OpenAI**, **DeepSeek**, **Mistral**, and **Anthropic**, from one attachment.
- **Deployment Tier Pricing**: Applies Global Standard, Data Zone Standard, or Standard rates per deployment, since the deployment type is chosen per deployment.
- **Response Format Independence**: Reads token counts written in either the OpenAI style (`prompt_tokens`) or the Anthropic style (`input_tokens`), so every vendor Azure fronts is handled the same way.
- **Cache, Category, and Tier Rates**: Charges cached input, cache writes, audio tokens, reasoning tokens, and web search queries at their own rates where the pricing database defines them, along with priority and above-272k rates.
- **Streaming Support**: Accumulates streamed responses and prices them once, at the end of the stream. Chat completions additionally require `stream_options.include_usage` on the request, since the provider otherwise omits usage from the stream.
- **Non-Blocking on Failure**: When no price can be determined the cost is set to `0.0000000000`, `x-llm-cost-status` is set to `not_calculated`, and the request proceeds untouched.

## Configuration

### User Parameters (API Definition)

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `modelMappings` | array | Yes | - | The deployments this route can reach, and the model each one runs. |

Each entry describes one deployment:

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `deployment` | string | Yes | - | The Azure deployment name, for example `apim-4o-mini`. |
| `model` | string | Yes | - | The model it runs, for example `gpt-4o-mini`. This is the name looked up in the pricing database. |
| `region` | string | No | `global-standard` | The deployment type, which selects the pricing tier. |

List every deployment the route can reach. `region` sits on each entry rather than on the policy because two deployments in the same Azure resource can be on different tiers. Valid values are `global-standard` (Azure's default), `us`, `eu` or `apac` for a Data Zone deployment, and `regional` for a single-region one. Provisioned Throughput deployments are not covered, as they bill reserved capacity by the hour rather than by token.

### System Parameters (From config.toml)

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `pricing_file` | string | Yes | - | Path to the model pricing JSON file shipped with the gateway image, the same file the `llm-cost` policy uses. |

#### Sample System Configuration

```toml
[policy_configurations.azure_llm_cost_v1]
pricing_file = "/etc/policy-engine/llm-pricing/model_prices.json"
```

**Note:**

Inside the `gateway/build.yaml`, ensure the policy module is added under `policies:`:

```yaml
- name: azure-llm-cost
  gomodule: github.com/wso2/gateway-controllers/policies/azure-llm-cost@v1
```

## Reference Scenarios

This policy runs in the response phase and should be placed before any cost-consuming policy in the chain. Every scenario below depends on the provider using one of the two Azure templates, `azure-openai` or `azureai-foundry`, since the policy reads that template to decide which catalog applies.

### Example 1: Attach the policy to an Azure OpenAI provider

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
      version: v1
      paths:
        - path: /chat/completions
          methods: [POST]
          params:
            modelMappings:
              - deployment: apim-4o-mini
                model: gpt-4o-mini
                region: eu
              - deployment: prod-gpt5
                model: gpt-5.1
```

After each successful response the policy sets `x-llm-cost`, a USD amount to 10 decimal places such as `"0.0000423100"`, and `x-llm-cost-status`, either `calculated` or `not_calculated`. The cost is also published as analytics metadata, where it appears as `llmCost`. Here `apim-4o-mini` is priced from `azure/eu/gpt-4o-mini` when that key exists and from `azure/gpt-4o-mini` otherwise, while `prod-gpt5` omits `region` and is priced as Global Standard.

### Example 2: Several vendors on one Azure AI Foundry provider

A Foundry resource can serve models from several vendors as well as the OpenAI models it hosts. One attachment covers all of them, because each model is priced from whichever catalog holds it. Set `template: azureai-foundry` on the provider, then:

```yaml
params:
  modelMappings:
    - deployment: my-claude
      model: claude-opus-4-5
    - deployment: my-deepseek
      model: deepseek-v3.1
    - deployment: my-mistral
      model: mistral-large
    - deployment: apim-gpt-5-6
      model: gpt-5.6-terra
```

The first three are Foundry's own models, priced from `azure_ai/`. The last is an OpenAI model hosted on Foundry, which appears only in `azure/`, and the policy finds it there.

### Example 3: Use with LLM Cost Based Ratelimit

List `llm-cost-based-ratelimit` before `azure-llm-cost`. Response-phase policies execute in reverse order, so `azure-llm-cost` runs first and calculates the cost, and `llm-cost-based-ratelimit` deducts it afterwards.

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
    version: v1
    paths:
      - path: /chat/completions
        methods: [POST]
        params:
          modelMappings:
            - deployment: apim-4o-mini
              model: gpt-4o-mini
```

## How It Works

1. **Response phase**: The response body is accumulated, so streamed and buffered responses are treated alike.
2. **The product is identified** from the provider template on the route. `azure-openai` selects the `azure/` catalog and `azureai-foundry` selects `azure_ai/`. The request path cannot be used, because Azure AI Foundry serves the OpenAI-compatible API on the same path Azure OpenAI does. A route using neither template is left unpriced and a warning is logged, rather than being billed against a catalog that may not apply.
3. **The model name is resolved** from the response body, then the request body, then the deployment segment of the URL. Each candidate is looked up in `modelMappings` first and used directly second, so a mapping always wins over the name Azure reported.
4. **The pricing entry is located** by exact key match. An Azure OpenAI route tries `azure/<region>/` then `azure/`. A Foundry route tries `azure_ai/` first and then falls back to `azure/`, which is how the OpenAI models hosted on Foundry are priced. The fallback runs one way only: a Foundry-native model on an Azure OpenAI route is reported unpriced, since Azure OpenAI cannot serve one and the route is therefore misconfigured.
5. **Tokens are charged** by category. Audio tokens, reasoning tokens, and web search queries are subtracted from the totals before being charged separately, so nothing is counted twice, and any category the entry gives no rate for is charged at the ordinary text rate. Priority and above-272k rates apply where the entry defines them, each falling back to the ordinary rate.
6. **The result is written** to `SharedContext`, published as analytics metadata, and the response continues unmodified.

How much the mapping has to do depends on what the response reports in step 3. When it reports the real model, as the chat completions endpoints do on both products, the mapping is only needed for the pricing tier. When it reports the deployment name, as the Responses endpoints do, the mapping supplies the model as well.

Leaving a deployment out of `modelMappings` therefore costs you two things:

- **The tier falls back to Global Standard**, because only the mapping carries it. This is logged once per deployment.
- **On the endpoints that report the deployment name**, that name is priced as though it were a model. This is not logged.

The second only bites where the response reports the deployment name. There, a deployment called `gpt-4o` that actually runs `gpt-4o-mini` is charged at `gpt-4o` rates, and nothing in the response contradicts it. A mapping fixes that. On chat completions the same deployment prices correctly on its own, because the response names the model that really ran, but the mapping is still what supplies its tier. Mapping every deployment covers both cases.

## Limitations

- Model names must match a pricing key exactly. There is no partial matching, because `gpt-4o` and `gpt-4o-mini` are priced very differently and matching loosely would quietly bill the wrong rate. A model absent from the database is reported unpriced instead.
- Azure reports dated snapshots such as `gpt-4.1-2025-04-14`, and each needs its own key. A newly released snapshot is unpriced until the database is updated or a mapping points the deployment at a model it already carries.
- A streamed chat completions call reports no token usage unless the request asks for it with `"stream_options": {"include_usage": true}`. Without it the provider sends no `usage` object at all, on Azure OpenAI and on Azure AI Foundry alike, so the call is recorded as unpriced. The Responses API and the Anthropic Messages API always report usage and need no extra parameter.
- Image, character, per-second, and code interpreter charges are not applied. A model priced only in those units is reported unpriced.
- `region` prefixes keys in the `azure/` catalog only. The `azure_ai/` keys shipped today are not tier-scoped, so it has no effect on a Foundry-native model, though it still applies to an OpenAI model hosted on Foundry.

## Related Policies

- [LLM Cost](../../../llm-cost/v1.1/docs/llm-cost.md) prices calls to a vendor's own endpoint. Use it instead of this policy for non-Azure routes, never alongside it.
- [LLM Cost Based Ratelimit](../../../llm-cost-based-ratelimit/v1.0/docs/llm-cost-based-ratelimit.md) reads `x-llm-cost` and enforces a spending budget.

## Notes

- The pricing file is loaded once at process startup. Restart the gateway to pick up changes to it.
- `modelMappings` is set per attachment, so different routes can describe different deployments.
- Adding a rate for a new model, tier, or token category is a data change to the pricing database and needs no new gateway build.
- When a cost of `0` appears, read `x-llm-cost-status` rather than the amount. The gateway log always records why a request went unpriced, naming the model or deployment involved.
