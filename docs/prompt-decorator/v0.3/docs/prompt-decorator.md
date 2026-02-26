---
title: "Overview"
---
# Prompt Decorator

## Overview

The Prompt Decorator policy modifies request prompts by prepending or appending configured decoration content. It supports two explicit decoration styles through `promptDecoratorConfig`: `text` for string targets and `messages` for chat-message array targets.

## Features

- Two decoration styles: `text` or `messages`
- Exactly one style is required per policy instance
- Optional JSONPath targeting
- Auto-default JSONPath based on selected style
- Prepend (`append: false`) or append (`append: true`) behavior

## Configuration

This policy uses single-level configuration in the API definition YAML.

### User Parameters (API Definition)

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `promptDecoratorConfig` | object | Yes | - | Decoration configuration. Must include exactly one of `text` or `messages`. |
| `jsonPath` | string | No | `""` | Target JSONPath. If empty, defaults to `$.messages[-1].content` for `text` and `$.messages` for `messages`. |
| `append` | boolean | No | `false` | If `true`, append decoration. If `false`, prepend decoration. |

#### PromptDecoratorConfig Configuration

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `text` | string | Conditional | Non-empty text decoration for string targets. |
| `messages` | `PromptMessage[]` | Conditional | Message decorations for array targets. |

Exactly one of `text` or `messages` must be provided.

#### PromptMessage Configuration

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `role` | string | Yes | Message role. Allowed: `system`, `user`, `assistant`, `tool`. |
| `content` | string | Yes | Non-empty message content. |

#### JSONPath Support

Common examples:

- `$.messages[-1].content` for text decoration
- `$.messages` for message-array decoration
- `$.data.prompt` for nested string prompt fields

**Note:**

Inside `gateway/build.yaml`, ensure the policy module is added under `policies`:

```yaml
- name: prompt-decorator
  gomodule: github.com/wso2/gateway-controllers/policies/prompt-decorator@v0
```

## Reference Scenarios

### Example 1: Text Decoration

```yaml
policies:
  - name: prompt-decorator
    version: v0
    paths:
      - path: /chat/completions
        methods: [POST]
        params:
          promptDecoratorConfig:
            text: "Summarize the following in bullet points:"
          jsonPath: "$.messages[-1].content"
          append: false
```

### Example 2: Message Decoration

```yaml
policies:
  - name: prompt-decorator
    version: v0
    paths:
      - path: /chat/completions
        methods: [POST]
        params:
          promptDecoratorConfig:
            messages:
              - role: system
                content: "You are a concise assistant."
          jsonPath: "$.messages"
          append: false
```

### Example 3: Inferred JSONPath Defaults

```yaml
# jsonPath omitted intentionally
params:
  promptDecoratorConfig:
    text: "Answer briefly"
```

When omitted:

- `text` uses `$.messages[-1].content`
- `messages` uses `$.messages`

## How It Works

#### Request Phase

1. Validates `promptDecoratorConfig` and `jsonPath`.
2. Resolves target value from JSON payload.
3. Applies text or messages decoration according to target type.
4. Writes updated value back into payload.

#### Response Phase

No response-phase processing is applied.

## Notes

- Empty request bodies are rejected by this policy.
- If `jsonPath` points to a string, use `promptDecoratorConfig.text`.
- If `jsonPath` points to an array, use `promptDecoratorConfig.messages`.
- Invalid role values in `messages` are rejected during policy initialization.
