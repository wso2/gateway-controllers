---
title: "Overview"
---
# Prompt Decorator

## Overview

The Prompt Decorator policy dynamically modifies prompts by prepending or appending custom content to specific fields in JSON payloads. This policy supports two decoration modes: **text prompt decoration** (for string content fields) and **chat prompt decoration** (for message arrays). It's useful for adding consistent instructions, system messages, or standardized prefixes/suffixes to prompts before they're sent to AI services.

## Features

- Two decoration modes: text decoration (string fields) and chat decoration (message arrays)
- Configurable prepend or append behavior
- JSONPath support for targeting specific fields in JSON payloads
- Flexible decoration format: simple strings or structured message objects
- Processes request body only (response phase not supported)

## Configuration

This policy requires only a single-level configuration where all parameters are configured in the API definition YAML.

### User Parameters (API Definition)

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `promptDecoratorConfig` | object | Yes | - | Specifies prompt decoration configuration. Provide exactly one of `text` or `messages`. |
| `promptDecoratorConfig.text` | string | Conditional | - | Specifies text decoration applied when targeting a string prompt. Required if `messages` is not provided. |
| `promptDecoratorConfig.messages` | array | Conditional | - | Specifies chat message decorations applied when targeting a messages array. Required if `text` is not provided. |
| `jsonPath` | string | No | `""` | JSONPath expression used to locate the prompt segment to decorate. If omitted, defaults to `"$.messages[-1].content"` for `text` decorations and `"$.messages"` for `messages` decorations. |
| `append` | boolean | No | `false` | If `true`, decoration is appended to the content. If `false`, decoration is prepended (default). |

### PromptDecoratorConfig.messages Array Item

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `role` | string | Yes | Role for the chat message. Valid values: `system`, `user`, `assistant`, `tool`. |
| `content` | string | Yes | Message content to prepend or append in chat decoration mode. |

#### JSONPath Support

The decorator supports JSONPath expressions to target specific fields. Common examples:

- `$.messages[0].content` - First message's content field (text decoration)
- `$.messages[-1].content` - Last message's content field (text decoration)
- `$.messages` - Entire messages array (chat decoration)
- `$.data.text` - Nested text field (text decoration)

**Array Index Syntax:**
- Use `[0]` for first element, `[1]` for second, etc.
- Use `[-1]` for last element, `[-2]` for second-to-last, etc.

**Note:**

Inside the `gateway/build.yaml`, ensure the policy module is added under `policies:`:

```yaml
- name: prompt-decorator
  gomodule: github.com/wso2/gateway-controllers/policies/prompt-decorator@v0
```

## Reference Scenarios

### Example 1: Text Prompt Decoration - Summarization Directive

Add a summarization instruction to user prompts:

```yaml
apiVersion: gateway.api-platform.wso2.com/v1alpha1
kind: LlmProvider
metadata:
  name: summarization-provider
spec:
  displayName: Summarization Provider
  version: v1.0
  template: openai
  vhost: openai
  upstream:
    url: "https://api.openai.com/v1"
    auth:
      type: api-key
      header: Authorization
      value: Bearer <openai-apikey>
  accessControl:
    mode: deny_all
    exceptions:
      - path: /chat/completions
        methods: [POST]
  policies:
    - name: prompt-decorator
      version: v0
      paths:
        - path: /chat/completions
          methods: [POST]
          params:
            promptDecoratorConfig:
              text: "Summarize the following content in a concise, neutral, and professional tone. Structure the summary using bullet points if appropriate.\n\n"
            jsonPath: "$.messages[0].content"
            append: false
```

**Test the decorator:**

**Note**: Ensure that "openai" is mapped to the appropriate IP address (e.g., 127.0.0.1) in your `/etc/hosts` file, or remove the vhost from the LLM provider configuration and use localhost to invoke.

```bash
# Original request
curl -X POST http://openai:8080/chat/completions \
  -H "Content-Type: application/json" \
  -H "Host: openai" \
  -d '{
    "model": "gpt-4",
    "messages": [
      {
        "role": "user",
        "content": "Large text block to summarize here..."
      }
    ]
  }'

# After decoration, the request sent to OpenAI will be:
# {
#   "model": "gpt-4",
#   "messages": [
#     {
#       "role": "user",
#       "content": "Summarize the following content in a concise, neutral, and professional tone. Structure the summary using bullet points if appropriate.

 Large text block to summarize here..."
#     }
#   ]
# }
```

**Error Response:**

When the policy encounters an error (e.g., invalid JSONPath, invalid decoration config, or missing required fields), it returns an HTTP 500 status code with the following structure:

```json
{
  "type": "PROMPT_DECORATOR_ERROR",
  "message": "Error description here"
}
```

### Example 2: Chat Prompt Decoration - System Persona

Add a system message to define AI behavior:

```yaml
apiVersion: gateway.api-platform.wso2.com/v1alpha1
kind: LlmProvider
metadata:
  name: hotel-booking-provider
spec:
  displayName: Hotel Booking Provider
  version: v1.0
  template: openai
  vhost: openai
  upstream:
    url: "https://api.openai.com/v1"
    auth:
      type: api-key
      header: Authorization
      value: Bearer <openai-apikey>
  accessControl:
    mode: deny_all
    exceptions:
      - path: /chat/completions
        methods: [POST]
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
                  content: "You are a helpful hotel booking receptionist for Azure Horizon Resort. Collect booking details: name, NIC, check-in time, staying duration (nights), and room type (single, double, suite). Ask one detail at a time in a friendly tone."
            jsonPath: "$.messages"
            append: false
```

**Test the decorator:**

```bash
# Original request
curl -X POST http://openai:8080/chat/completions \
  -H "Content-Type: application/json" \
  -H "Host: openai" \
  -d '{
    "model": "gpt-4",
    "messages": [
      {
        "role": "user",
        "content": "Hi, I would like to book a room."
      }
    ]
  }'

# After decoration, the request sent to OpenAI will be:
# {
#   "model": "gpt-4",
#   "messages": [
#     {
#       "role": "system",
#       "content": "You are a helpful hotel booking receptionist for Azure Horizon Resort. Collect booking details: name, NIC, check-in time, staying duration (nights), and room type (single, double, suite). Ask one detail at a time in a friendly tone."
#     },
#     {
#       "role": "user",
#       "content": "Hi, I would like to book a room."
#     }
#   ]
# }
```

### Example 3: Append Mode - Adding Suffix Instructions

Append instructions to the end of user messages:

```yaml
policies:
  - name: prompt-decorator
    version: v0
    paths:
      - path: /chat/completions
        methods: [POST]
        params:
          promptDecoratorConfig:
            text: "\n\nPlease respond in JSON format."
          jsonPath: "$.messages[-1].content"
          append: true
```

## How It Works

#### Request Phase

1. **Target Extraction**: Resolves the target field using `jsonPath` from the request payload.
2. **Mode Detection**: Determines decoration mode based on target type and `promptDecoratorConfig.decoration` shape (string vs message array).
3. **Decoration Application**: Prepends or appends decoration based on `append` configuration.
4. **Payload Update**: Writes the decorated value back to the request payload and forwards it upstream.

#### Decoration Modes


**Mode 1: Text Prompt Decoration**

Text decoration is used when the JSONPath targets a string field (e.g., `$.messages[0].content`). Use the `text` field in `promptDecoratorConfig`:

*Configuration Example:*
```yaml
promptDecoratorConfig:
  text: "Summarize the following content in a concise, neutral, and professional tone.\n\n"
```

*Behavior:*
- Decoration string is prepended or appended to the target content field
- A space is automatically added between the decoration and original content


**Mode 2: Chat Prompt Decoration**

Chat decoration is used when the JSONPath targets an array field (e.g., `$.messages`). Use the `messages` field in `promptDecoratorConfig`:

*Configuration Example:*
```yaml
promptDecoratorConfig:
  messages:
    - role: system
      content: "You are a helpful hotel booking receptionist for the imaginary hotel 'Azure Horizon Resort'. Your job is to collect all the necessary booking details from guests."
```

*Behavior:*
- Decoration messages are prepended or appended to the messages array
- Each decoration object must have `role` and `content` fields
- Multiple decoration messages can be added

## Notes

- Common use cases include prompt standardization, persona injection, output-format enforcement, and contextual prompt enrichment.
- The policy only processes request bodies.
- For text decoration, a space is automatically added between the decoration and original content.
- JSONPath expressions must correctly identify the target field. Invalid paths will result in errors.
- When decorating message arrays, ensure the target field is actually an array of message objects.
- The `append: false` (default) means decoration is prepended. Set `append: true` to append decoration.
- Messages in chat mode must have both `role` and `content` fields; both are required.
- Valid role values are: `system`, `user`, `assistant`, `tool`.
- Negative array indices (e.g., `[-1]` for last element) are supported in JSONPath expressions.
- If `jsonPath` is omitted, it defaults to `"$.messages[-1].content"` for `text` decorations and `"$.messages"` for `messages` decorations.
