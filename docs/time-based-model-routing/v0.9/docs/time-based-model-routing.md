---
title: "Overview"
---
# Time-Based Model Routing

## Overview

The Time-Based Model Routing policy routes an LLM request to a configured model and
optional provider according to the gateway's current time in a configured
timezone. Schedules are evaluated in order. Their start time is inclusive and
their end time is exclusive.

Schedules can cover a same-day window, such as `06:00` to `12:00`, or cross
midnight, such as `22:00` to `06:00`. An overnight schedule associated with a
weekday starts on that weekday and continues into the following day.

When no schedule matches, the policy uses the optional `fallback` target. If no
fallback is configured, the original model and provider remain unchanged.

## Configuration

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `timezone` | string | No | `UTC` | IANA timezone used to evaluate schedules, for example `America/New_York` or `Asia/Colombo`. |
| `schedules` | array | Yes | - | Ordered, non-overlapping routing windows. |
| `schedules[].name` | string | No | `schedule-N` | Human-readable name recorded in request metadata. |
| `schedules[].days` | array | No | every day | Weekdays on which the window starts, using short or long English names such as `Mon` or `Monday`. |
| `schedules[].from` | string | Yes | - | Inclusive start time in 24-hour `HH:MM` format. |
| `schedules[].to` | string | Yes | - | Exclusive end time in 24-hour `HH:MM` format. |
| `schedules[].model.modelName` | string | Yes | - | Model written to the upstream request. |
| `schedules[].model.providerName` | string | No | primary provider | Additional-provider alias selected for this window. |
| `fallback.modelName` | string | No | original model | Model selected when no schedule matches. |
| `fallback.providerName` | string | No | primary provider | Additional-provider alias for the fallback model. |

## Examples

### Route by weekday and time

```yaml
parameters:
  timezone: America/New_York
  schedules:
    - name: business-hours
      days: [Mon, Tue, Wed, Thu, Fri]
      from: "09:00"
      to: "17:00"
      model:
        modelName: gpt-5
        providerName: openai-primary
    - name: overnight
      from: "22:00"
      to: "06:00"
      model:
        modelName: gpt-5-mini
  fallback:
    modelName: gpt-5-mini
```

In this example, the `business-hours` target is active from 09:00 inclusive to
17:00 exclusive on weekdays in New York. The `overnight` target applies every
day and spans midnight. At all other times, the fallback model is used.

### Preserve the client target when no schedule matches

```yaml
parameters:
  timezone: UTC
  schedules:
    - name: nightly-batch
      from: "00:00"
      to: "05:00"
      model:
        modelName: batch-model
```

Because this configuration has no `fallback`, requests outside the configured
window retain their original model and provider.

## Routing metadata

When a schedule or the fallback model is selected, the policy publishes the
following values to `SharedContext.Metadata` for downstream policies:

| Key | Description |
|---|---|
| `time_based_model_routing.selected_model` | Selected upstream model. |
| `time_based_model_routing.selected_provider` | Selected provider alias, or an empty string when the primary provider is used. |
| `time_based_model_routing.selected_route` | Configured schedule name, generated `schedule-N` name, or `default` when the fallback is selected. |
| `time_based_model_routing.selected_time` | Local selection time in `HH:MM` format. |
| `selected_provider` | Provider routing key, set only when the selected target specifies a provider. |

If no schedule matches and no default is configured, the policy does not add
time-based model routing metadata.

## Validation and matching rules

- Times must use 24-hour `HH:MM` format and `from` must differ from `to`.
- Schedule windows must not overlap on the same active day.
- Schedule matching uses the gateway clock converted to `timezone`.
- The first matching schedule is selected.
- A provider value must match an additional-provider alias configured for the
  LLM proxy. Omitting it uses the proxy's primary provider.

The runtime also accepts `target` and `models` as legacy aliases for the schedule’s `model` object.

The runtime accepts `default`, inner `model`, and `provider` as legacy aliases for
`fallback`, `modelName`, and `providerName`. Canonical fields take precedence.
