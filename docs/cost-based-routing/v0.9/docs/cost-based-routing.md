---
title: "Overview"
---
# Cost-Based Routing

## Overview

Cost-Based Routing matches the requested model to an independent, shared model
budget. Model matching is always enabled and list order does not affect routing.

1. Read the requested model and look for an exact, case-sensitive model name.
2. If the model has an exact budget, check it. Otherwise, use the wildcard budget
   (`*` or `other`) if configured, preserving the unlisted requested model name.
3. If the applicable budget has capacity, call the requested model. Exact matches
   use their configured provider; wildcard matches use the proxy's primary provider.
4. If the applicable budget is missing or exhausted, follow `onExhausted`: use the
   configured `fallback` (the default behavior), or return HTTP 429 for `reject`.
5. Fallback must have its own exact model budget. Check it once and charge it if
   available. Direct and fallback requests share this model budget. If missing or
   exhausted, return HTTP 429 without retrying wildcard or another model.

A configured model with an exhausted budget cannot use the wildcard to bypass
its limit. Wildcard applies only to unlisted concrete model names; an empty model
or a request literally naming `*` or `other` does not select the wildcard.

All callers share each model budget within the policy attachment, regardless of
application identity. When a budget window resets, that model becomes eligible
again. Budget checks use previously recorded spending; the response's actual
cost is charged once after completion.

## Configuration

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `modelBudgets` | array | Yes | - | Model-budgets, matched by requested model name. Maximum 10. |
| `modelBudgets[].name` | string | No | `route-N` | Unique name for the model budget in diagnostics. |
| `modelBudgets[].model` | object | Yes | - | Models configuration for this budget. |
| `modelBudgets[].model.modelName` | string | Yes | - | Exact model name, or `*` / `other` for the unlisted-model budget. Model names must be unique, with at most one wildcard entry. |
| `modelBudgets[].model.providerName` | string | No | primary provider | Additional-provider alias matching `additionalProviders[].as`, or provider ID when `as` is absent. Omit for wildcard entries; unlisted models use the proxy primary provider. |
| `modelBudgets[].budgetLimits` | array | Yes | - | Spending windows for this model. Maximum 10. Any exhausted window makes the budget unavailable. |
| `modelBudgets[].budgetLimits[].amount` | number | Yes | - | Positive maximum spend in US dollars within the window. |
| `modelBudgets[].budgetLimits[].duration` | string | Yes | - | Positive Go duration such as `1h`, `24h`, `168h`, or `720h`. |
| `onExhausted` | string | No | `fallback` | Action when the applicable model or wildcard budget is missing or exhausted: `fallback` or `reject`. |
| `fallback` | object | When `onExhausted: fallback` | - | Concrete model and provider used for fallback requests. |
| `fallback.modelName` | string | Yes when fallback is supplied | - | Concrete upstream model name; cannot be `*` or `other`. |
| `fallback.providerName` | string | No | primary provider | Additional-provider alias for fallback. |

### Unlisted models with a budgeted fallback

```yaml
parameters:
  modelBudgets:
    - name: gpt-4o-budget
      model:
        modelName: gpt-4o
        providerName: openai
      budgetLimits:
        - amount: 2
          duration: 1h
        - amount: 20
          duration: 24h
    - name: economy-budget
      model:
        modelName: gpt-4o-mini
        providerName: openai
      budgetLimits:
        - amount: 50
          duration: 24h
    - name: unlisted-model-budget
      model:
        modelName: "*" # "other" is an equivalent alias
      budgetLimits:
        - amount: 5
          duration: 24h
  onExhausted: fallback
  fallback:
    modelName: gpt-4o-mini
    providerName: openai
```

A request for `gpt-4o` uses `gpt-4o-budget` while both its hourly and daily
windows have capacity. A request for `gpt-4o-mini` uses `economy-budget`
directly, regardless of its position in the list.

A request for an unlisted model such as `gpt-5.5` calls that requested model
through the primary provider and charges the $5 `unlisted-model-budget`. Other
unlisted model names share the same $5 allowance.

When that wildcard budget is exhausted, `onExhausted: fallback` sends subsequent
unlisted-model requests to `gpt-4o-mini`, charging its $50 `economy-budget`.
Direct requests for `gpt-4o-mini` also charge that same budget. Once it is
exhausted, fallback requests return HTTP 429. The policy does not restart at the
wildcard or look for another model with money remaining.

A configured `gpt-4o` request uses its own budget. If that budget is exhausted,
it goes directly to the fallback model's budget; it does not consume wildcard.
A wildcard is a budget selector and is never sent upstream as a model name.

| Request | Applicable budget | After exhaustion with `onExhausted: fallback` |
|---|---|---|
| `gpt-4o` | `gpt-4o-budget` | Use `gpt-4o-mini` and charge `economy-budget`. |
| Unlisted `gpt-5.5` | `unlisted-model-budget` | Use `gpt-4o-mini` and charge `economy-budget`. |
| Direct `gpt-4o-mini` | `economy-budget` | Reject: fallback is the same exhausted model. |
| Request needs fallback but its model budget is missing/exhausted | None available | HTTP 429; no loop. |

### Reject missing or exhausted models

```yaml
parameters:
  onExhausted: reject
  modelBudgets:
    - name: gpt-4o-budget
      model:
        modelName: gpt-4o
      budgetLimits:
        - amount: 10
          duration: 24h
```

An unknown model or an exhausted `gpt-4o` budget returns:

```http
HTTP/1.1 429 Too Many Requests
Content-Type: application/json

{"code":"cost_based_routing_budget_exhausted","error":"requested model has no available budget or the fallback budget is missing or exhausted"}
```

### Migrating existing configuration

Rename `routes` to `modelBudgets`, `target` to `model`, `model` to `modelName`,
`provider` to `providerName`, and `default` to `fallback`. Change
`onExhausted: default` to `onExhausted: fallback`. Remove `respectRequestedModel`
and `consumerBased`; these options are no longer supported. Model matching is
always enabled and budgets are always shared.

The runtime parser accepts the earlier routing names and the original
`primary`/`fallback`/`budgetLimits` shape for migration, but all configurations
use the new model-matching behavior. The published schema exposes the new names.

## Model and provider rewriting

The system-provided `requestModel` setting identifies where the model appears
in the upstream request. Supported locations are `payload` (with `body` as a
backward-compatible alias), `header`, `queryParam`, and `pathParam`. Requested-
model matching and rewriting use that location. Payload identifiers are
JSONPaths; path identifiers are regular expressions containing a capture group
for the model segment.

When a target specifies `providerName`, the policy selects that named upstream and
sets `SharedContext.Metadata["selected_provider"]` for conditional provider
authentication and protocol transformation. When a target omits `providerName`,
the LLM proxy's primary provider is used and any stale `selected_provider`
metadata from an earlier routing policy is removed.

## Cost accounting

The exact LLM cost is known only after the upstream response completes. The
selected route is therefore checked using previously recorded spending and is
charged once afterward using `x-llm-cost` and `x-llm-cost-status` metadata
published by the `llm-cost` policy.

Place `cost-based-routing` before `llm-cost` in the policy list. Response-phase
policies run in reverse order, allowing `llm-cost` to publish the final cost
before Cost-Based Routing charges the selected route.

- A request can slightly overshoot a limit because its cost is not known during
  selection. Its response is still returned; the next request observes the
  exhausted budget.
- A cost is charged only when `x-llm-cost-status` is `calculated` and the cost
  is a usable, positive number. Missing, invalid, zero, or uncalculated costs do
  not consume budget.
- Unlisted-model responses charge only the wildcard budget. Fallback responses
  charge only the fallback model's own exact budget. They never charge both.
- Streaming responses are charged exactly once at end of stream. If a stream is
  aborted before end of stream, the gateway policy SDK provides no completion
  callback and the cost cannot be charged.
- No remaining-budget response headers are emitted because the final remaining
  amount is unknown until the response body completes.

## Storage and accounting settings

These values are supplied as system parameters by the gateway configuration:

| Setting | Default | Behavior |
|---|---|---|
| `costScaleFactor` | `1000000000` | Converts dollar values to integer nano-dollar units. Lower values reduce precision. |
| `algorithm` | `fixed-window` | `fixed-window` resets the full budget at the window boundary. `gcra` replenishes capacity gradually. |
| `backend` | `memory` | `memory` is per gateway instance. `redis` shares budgets across replicas. `redis-local-async` is accepted but uses the same synchronous query and charge behavior as `redis`. |
| `redis.failureMode` | `open` | `open` continues on the route when budget state cannot be read. `closed` returns HTTP 503. Storage failure is never treated as budget exhaustion. |

## Routing metadata

The policy records its selection and accounting state in
`SharedContext.Metadata`:

| Key | Description |
|---|---|
| `cost_based_routing.selected_model` | Model selected for the upstream request. |
| `cost_based_routing.selected_provider` | Selected provider alias, or an empty string for the primary provider. |
| `cost_based_routing.selected_route` | Configured model budget name or generated `route-N` name. |
| `cost_based_routing.selected_tier` | The selected model budget name for direct matches, `wildcard` for unlisted models, or `fallback` for fallback selections. |
| `cost_based_routing.track_primary_cost` | Whether this response should be charged to a configured route. |
| `cost_based_routing.budget_key` | Internal shared budget key for the selected model budget. |
| `cost_based_routing.budget_index` | Internal index of the selected budgeted route. |
| `cost_based_routing.cost_charged` | Marks that response accounting has already run, preventing duplicate charges. |
| `selected_provider` | Engine routing key, present only when the selected target specifies a provider. |

## Selection traces

At debug log level, the policy emits `CostBasedRouting: selected model` with
`requestedModel`, `modelName`, `providerName`, `modelBudget`, `selectionTier`,
`policyLevel`, `route`, `budgetState`, and `availableScaledUnits`. These fields
identify the model and provider actually selected, including unlisted models using wildcard
and fallback models using their own budgets. An empty `providerName` means the proxy's primary provider.

## Error behavior

| Status | Condition |
|---|---|
| `400 Bad Request` | The configured model location cannot be read or rewritten, or a required JSON request body is empty, malformed, or not an object. |
| `429 Too Many Requests` | Applicable model/wildcard budget is missing/exhausted with `onExhausted: reject`, or the fallback budget is missing or exhausted. |
| `503 Service Unavailable` | The budget backend cannot be queried and Redis failure mode is `closed`. |

The previous `models` wrapper is also accepted by the runtime as an alias for `model`.

### Model name patterns

`modelBudgets[].model.modelName` supports `*` as zero or more characters,
for example `gpt-*`, `claude-*`, or `*-mini`. Matching is case-sensitive and
covers the whole model name. All other characters are literal, not regex syntax.
Exact names win; otherwise the matching pattern with the most non-`*`
characters wins. Ties use configuration order. `*` and `other` remain catch-all
aliases. Every request matching a pattern shares that entry's budget and keeps
its requested model on the primary provider; omit `providerName` for patterns.
An exhausted match follows `onExhausted` without trying broader patterns.
Fallback still requires its own exact model budget; missing or exhausted means
HTTP 429, with no recursive fallback.
