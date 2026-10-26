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
| `schedules[].days` | object | No | every day | Day switches named `Monday` through `Sunday`. Enabled days determine when the window starts. Omitted switches default to `true`; at least one day must be enabled. |
| `schedules[].from` | string | Yes | - | Inclusive start time in 24-hour `HH:MM` format. |
| `schedules[].to` | string | Yes | - | Exclusive end time in 24-hour `HH:MM` format. |
| `schedules[].model.modelName` | string | Yes | - | Model written to the upstream request. |
| `schedules[].model.providerName` | string | No | primary provider | Additional-provider alias selected for this window. |
| `fallback.modelName` | string | No | original model | Model selected when no schedule matches. |
| `fallback.providerName` | string | No | primary provider | Additional-provider alias for the fallback model. |

### LLM provider template configuration

The policy also requires the `requestModel` system parameter from the LLM
provider template. The gateway controller injects this setting; it is not a
user-configurable policy parameter. It tells the policy where the request stores
the model so that the model selected by a schedule or fallback can be written
back to the request.

| System parameter | Type | Required | Description |
|---|---|---|---|
| `requestModel.location` | string | Yes | Model location. Supported values are `payload` (or its `body` alias), `header`, `queryParam`, and `pathParam`. |
| `requestModel.identifier` | string | Yes | Model identifier for the configured location: a JSONPath expression for `payload`/`body`, a header name for `header`, a query parameter name for `queryParam`, or a regular expression for `pathParam`. A path expression may match the model directly, use its first capture group for the model, or use a leading positive lookbehind expression such as `(?<=models/)[a-zA-Z0-9.\\-]+`. |

The provider template must supply both fields. Without them, policy
configuration fails and the selected model cannot be written to the upstream
request.

## Examples

### Route by weekday and time

```yaml
parameters:
  timezone: America/New_York
  schedules:
    - name: business-hours
      days:
        Monday: true
        Tuesday: true
        Wednesday: true
        Thursday: true
        Friday: true
        Saturday: false
        Sunday: false
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

### Select Monday and Wednesday

In the policy form, expand `days`, leave Monday and Wednesday enabled, and turn
all other days off. For example, use the following day settings with a schedule's
`from`, `to`, and `model`:

```yaml
days:
  Monday: true
  Tuesday: false
  Wednesday: true
  Thursday: false
  Friday: false
  Saturday: false
  Sunday: false
```

All seven switches start enabled. Omitting `days` applies the schedule every day;
omitting an individual switch leaves that day enabled. Turning every switch off
is invalid. For an overnight window, the selected day is the day the window starts.

The runtime continues to accept existing lists such as `days: [Mon, Wed]`,
including short and long English day names. The policy form uses the boolean
object; convert legacy lists to this object when editing through the form.

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
