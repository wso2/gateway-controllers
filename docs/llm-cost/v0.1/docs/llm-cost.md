---
title: "Overview"
---
# LLM Cost

## Overview

The LLM Cost policy calculates the monetary cost of an LLM API call at response time and stores the result in `SharedContext.Metadata`. The cost is not exposed as a response header — it is only available to other policies in the same request pipeline, such as the [LLM Cost Based Ratelimit](../../llm-cost-based-ratelimit/v0.1/docs/llm-cost-based-ratelimit.md) policy.

The policy reads the model name from the response body, looks it up in a pricing database, and computes the cost using provider-specific calculators that normalise token usage fields across different response formats.

Use this policy when you need to:

- Track the monetary cost of each LLM API call for billing or observability.
- Feed downstream policies (such as budget-based rate limiting) with accurate per-call cost data.
- Support cost attribution across multiple LLM providers from a single gateway.

## Features

- **Automatic Cost Calculation**: Computes cost from token usage fields in the LLM response — no manual configuration per model.
- **Multi-Provider Support**: Built-in calculators for OpenAI, Anthropic, Gemini (Google AI Studio and Vertex AI), and Mistral.
- **Pricing Database**: Model pricing is loaded once at startup from a JSON file shipped with the gateway image.
- **SharedContext Integration**: Stores the calculated cost in `SharedContext.Metadata` under `x-llm-cost` for use by downstream policies.
- **Non-Blocking on Failure**: If the model is not found in the pricing database or usage cannot be parsed, the cost is set to `0.0000000000` and the request is not blocked.
- **Status Metadata**: Sets `x-llm-cost-status` to `calculated` or `not_calculated` to disambiguate a zero cost from a failed calculation.

## Configuration

This policy has no user parameters. All configuration is handled by the gateway administrator via system parameters.

### System Parameters (From config.toml)

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `pricing_file` | string | Yes | - | Path to the model pricing JSON file shipped with the gateway image. Can be overridden by the gateway administrator via `config.toml`. |

#### Sample System Configuration

```toml
[policy_configurations.llm_cost_v0]
pricing_file = "/etc/gateway/pricing.json"
```

**Note:**

Inside the `gateway/build.yaml`, ensure the policy module is added under `policies:`:

```yaml
- name: llm-cost
  gomodule: github.com/wso2/gateway-controllers/policies/llm-cost@v0
```

## Reference Scenarios

This policy runs in the response phase and is designed to be placed before cost-consuming policies in the policy chain (such as `llm-cost-based-ratelimit`).

### Example 1: Attach LLM Cost Policy to an OpenAI Provider

```yaml
apiVersion: gateway.api-platform.wso2.com/v1alpha1
kind: LlmProvider
metadata:
  name: openai-provider
spec:
  displayName: OpenAI Provider
  version: v1.0
  context: /openai
  upstream:
    url: https://api.openai.com
    auth:
      type: api-key
      header: Authorization
      value: Bearer ${OPENAI_API_KEY}
  accessControl:
    mode: deny_all
    exceptions:
      - path: /chat/completions
        methods: [POST]
  policies:
    - name: llm-cost
      version: v0
      paths:
        - path: /chat/completions
          methods: [POST]
```

After each successful response, the policy stores the calculated cost in `SharedContext.Metadata`:

- `x-llm-cost`: USD dollar amount formatted to 10 decimal places (for example, `"0.0000423100"`).
- `x-llm-cost-status`: `"calculated"` if the cost was computed successfully, or `"not_calculated"` if the model was not found in the pricing database or parsing failed.

### Example 2: Use with LLM Cost Based Ratelimit

The primary use case is pairing this policy with `llm-cost-based-ratelimit` to enforce monetary budget limits. Place `llm-cost` before `llm-cost-based-ratelimit` in the policy list so the cost is available when the rate limit check runs:

```yaml
apiVersion: gateway.api-platform.wso2.com/v1alpha1
kind: LlmProvider
metadata:
  name: openai-provider
spec:
  displayName: OpenAI Provider
  version: v1.0
  context: /openai
  upstream:
    url: https://api.openai.com
    auth:
      type: api-key
      header: Authorization
      value: Bearer ${OPENAI_API_KEY}
  accessControl:
    mode: deny_all
    exceptions:
      - path: /chat/completions
        methods: [POST]
  policies:
    - name: llm-cost
      version: v0
      paths:
        - path: /chat/completions
          methods: [POST]
    - name: llm-cost-based-ratelimit
      version: v0
      paths:
        - path: /chat/completions
          methods: [POST]
          params:
            budgetLimits:
              - amount: 10
                duration: "24h"
```

## How It Works

1. **Request phase**: The request body is buffered (required by some providers such as Anthropic to determine speed tier).
2. **Response phase**: The response body is buffered and parsed.
3. The model name is extracted from `$.model` in the response body. For Gemini native format, `$.modelVersion` is used as a fallback.
4. The model name is looked up in the pricing database loaded at startup.
5. A provider-specific calculator normalises the usage fields (prompt tokens, completion tokens, and any provider-specific fields such as cache read tokens or reasoning tokens) into a common `Usage` struct.
6. The cost is calculated using the normalised usage and the pricing entry, then adjusted for any provider-specific multipliers (such as geographic pricing tiers or speed multipliers for Anthropic).
7. The final cost and status are written to `SharedContext.Metadata` and the response continues unmodified.

## Notes

- The pricing file is loaded once at process startup using a singleton pattern. All APIs and routes that attach this policy share the same pricing data.
- If the model name is not found in the pricing database, `x-llm-cost` is set to `0.0000000000`, `x-llm-cost-status` is set to `not_calculated`, and a warning is logged. The request is **not** blocked.
- The cost is stored internally only and is never sent to the client as a response header.
- Supported providers: **OpenAI**, **Anthropic**, **Gemini** (Google AI Studio and Vertex AI), **Mistral**.
