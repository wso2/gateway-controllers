---
title: "Overview"
---
# Cost-Based Routing

## Overview

The Cost-Based Routing policy sends LLM requests through an ordered set of
independently budgeted model targets. By default, it respects a client's
requested model when that model has a configured route and remaining budget.
Otherwise, it falls back through the configured routes in priority order:

1. If the requested model matches a configured route, try that route first.
2. If that route is exhausted, try the first available route from the beginning
   of the configured list.
3. If the requested model is not configured, start from the top immediately.
4. If all configured route budgets are exhausted, follow `onExhausted`.

Set `onExhausted` to `default` to call a configured fallback target, or set it
to `reject` to return HTTP 429 without calling an upstream model. The default
target is not budgeted and its cost is not charged against any configured route.

Set `respectRequestedModel: false` when clients must not influence route
selection. In that mode, routes are always checked from top to bottom and the
first route with remaining budget is selected.

## Configuration

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `routes` | array | Yes | - | Ordered budgeted routes. A matching requested model is tried first when `respectRequestedModel` is enabled; fallback uses this order. Maximum 10. |
| `routes[].name` | string | No | `route-N` | Human-readable unique route name. |
| `routes[].target.model` | string | Yes | - | Model matched against the client request and written upstream. |
| `routes[].target.provider` | string | No | primary provider | Additional-provider alias. It must match `additionalProviders[].as`, or the provider ID when `as` is absent. |
| `routes[].budgetLimits` | array | Yes | - | One or more independent spending caps for this route. Maximum 10. A route is exhausted when any limit is exhausted. |
| `routes[].budgetLimits[].amount` | number | Yes | - | Maximum spend in US dollars within the window; must be greater than zero. |
| `routes[].budgetLimits[].duration` | string | Yes | - | Positive Go duration such as `1h`, `24h`, `168h`, or `720h`. |
| `onExhausted` | string | No | `default` | `default` uses the fallback target; `reject` returns HTTP 429. |
| `default` | object | When `onExhausted: default` | - | Unbudgeted target used after every route budget is exhausted. |
| `default.model` | string | Yes when `default` is used | - | Default model written upstream. |
| `default.provider` | string | No | primary provider | Additional-provider alias for the default target. |
| `consumerBased` | boolean | No | `false` | Gives each application independent route budgets using `x-wso2-application-id`. Requests without an ID share the `default` consumer budget. |
| `respectRequestedModel` | boolean | No | `true` | Tries an exact, case-sensitive configured client model match first. When false, always checks routes from top to bottom. |

## Selection examples

### Respect the requested model

```yaml
parameters:
  respectRequestedModel: true
  onExhausted: default
  routes:
    - name: premium
      target:
        model: gpt-5
      budgetLimits:
        - amount: 10
          duration: 24h
    - name: economy
      target:
        model: gpt-5-mini
      budgetLimits:
        - amount: 50
          duration: 24h
  default:
    model: emergency-model
```

If the client requests `gpt-5-mini`, the `economy` route is tried first even
though it is second in the list. If its budget is exhausted, the policy falls
back to the first available route from the top. A client model that does not
exactly match a configured route starts normal top-to-bottom selection.

### Ignore the requested model

```yaml
parameters:
  respectRequestedModel: false
  onExhausted: default
  routes:
    - name: preferred
      target:
        model: gpt-5
      budgetLimits:
        - amount: 10
          duration: 24h
    - name: economy
      target:
        model: gpt-5-mini
      budgetLimits:
        - amount: 50
          duration: 24h
  default:
    model: emergency-model
```

Every request tries `preferred` first, regardless of the model sent by the
client. The selected target replaces the client model before the request is
sent upstream.

### Apply multiple budget windows

```yaml
parameters:
  routes:
    - name: premium
      target:
        model: gpt-5
      budgetLimits:
        - amount: 2
          duration: 1h
        - amount: 20
          duration: 24h
  onExhausted: default
  default:
    model: gpt-5-mini
```

Each limit is tracked independently. The route becomes unavailable as soon as
either its hourly or daily budget is exhausted and becomes eligible again when
the exhausted window resets.

### Return an error after exhaustion

```yaml
parameters:
  onExhausted: reject
  routes:
    - name: premium
      target:
        model: gpt-5
      budgetLimits:
        - amount: 10
          duration: 24h
```

After the last route is exhausted, this configuration returns:

```http
HTTP/1.1 429 Too Many Requests
Content-Type: application/json

{"code":"cost_based_routing_budget_exhausted","error":"all configured route budgets are exhausted"}
```

## Consumer-based budgets

With `consumerBased: false`, each configured route has one budget shared by all
requests to the API route. With `consumerBased: true`, every application gets
an independent budget for each configured route. The application identity is
read from `SharedContext.Metadata["x-wso2-application-id"]`, which is normally
published by an authentication policy.

Requests with a missing, empty, or non-string application ID share a consumer
scope named `default`; they do not bypass budget enforcement.

## Model and provider rewriting

The system-provided `requestModel` setting identifies where the model appears
in the upstream request. Supported locations are `payload` (with `body` as a
backward-compatible alias), `header`, `queryParam`, and `pathParam`. Requested-
model matching and rewriting use that location. Payload identifiers are
JSONPaths; path identifiers are regular expressions containing a capture group
for the model segment.

When a target specifies `provider`, the policy selects that named upstream and
sets `SharedContext.Metadata["selected_provider"]` for conditional provider
authentication and protocol transformation. When a target omits `provider`,
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
- The default target is not charged against a route budget.
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
| `cost_based_routing.selected_route` | Configured route name, generated `route-N` name, or `default`. |
| `cost_based_routing.selected_tier` | Selection tier; retained for compatibility and normally matches the selected route name. |
| `cost_based_routing.track_primary_cost` | Whether this response should be charged to a configured route. |
| `cost_based_routing.budget_key` | Internal consumer/shared budget key for the selected budgeted route. |
| `cost_based_routing.budget_index` | Internal index of the selected budgeted route. |
| `cost_based_routing.cost_charged` | Marks that response accounting has already run, preventing duplicate charges. |
| `selected_provider` | Engine routing key, present only when the selected target specifies a provider. |

## Error behavior

| Status | Condition |
|---|---|
| `400 Bad Request` | The configured model location cannot be read or rewritten, or a required JSON request body is empty, malformed, or not an object. |
| `429 Too Many Requests` | All route budgets are exhausted and `onExhausted` is `reject`. |
| `503 Service Unavailable` | The budget backend cannot be queried and Redis failure mode is `closed`. |
