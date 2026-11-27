---
title: "Overview"
---
# Mistral Moderation

## Overview

The Mistral Moderation guardrail checks request or response body content with the [Mistral moderation API](https://docs.mistral.ai/studio/safety-moderation/) (model `mistral-moderation-2603`). Each phase uses one of Mistral's two endpoints:

- **Text mode** sends a piece of text to the raw-text endpoint, `POST /v1/moderations`.
- **Conversation mode** sends the chat messages to the conversational endpoint, `POST /v1/chat/moderations`. That endpoint classifies the last message in the context of the earlier ones. On the response, the reply is appended to the request's messages, so it is judged against the prompt that produced it, as in Mistral's [system-level guardrails cookbook](https://docs.mistral.ai/resources/cookbooks/mistral-moderation-system-level-guardrails).

Mistral recommends the conversational endpoint for chat APIs. Mistral returns a score from 0 to 1 for each of eleven categories. The policy compares each enabled category's score with a threshold the API developer configures, and blocks the request or response when any score reaches its threshold.

Request and response moderation are configured independently. A route can moderate only prompts, only model output, or both with different thresholds. The Mistral API key is configured once by the gateway administrator. It never appears in an API definition.

Use this policy to screen LLM prompts and completions for harmful content, jailbreak attempts, personal data or unqualified advice before they reach the model or the API consumer.

## Features

- **Text and conversation moderation**: per phase, moderate raw text (`/v1/moderations`) or a conversation (`/v1/chat/moderations`), where the last message is judged in context
- **Eleven moderation categories**: sexual, hate and discrimination, violence and threats, dangerous, criminal, self-harm, health, financial, law, PII and jailbreaking, exactly as `mistral-moderation-2603` returns them
- **Per-category score thresholds**: a threshold from 0 to 1 for each category, or `-1` to disable it
- **Separate request/response configuration**: independent JSONPath, thresholds, error handling and timeout for each phase
- **Streamed and non-streamed responses**: a `"stream": true` reply is buffered, reassembled from its events and moderated whole before any of it reaches the client
- **JSONPath support**: moderate one field, the last message, or a whole conversation with the `[*]` wildcard; OpenAI-style content parts are supported
- **Gateway-level credentials**: the Mistral API key comes from `config.toml` or the policy engine's environment, never from the API definition
- **Fail-closed by default**: `passthroughOnError` decides what happens when Mistral cannot give a verdict; a detected violation is always blocked
- **Optional assessment details**: violating categories with their scores and thresholds, without the moderated content
- **Fault reporting**: every rejection is reported to the gateway with a guardrail or mediation fault code

## Configuration

This policy uses a two-level configuration. The gateway administrator configures the Mistral credentials. The API developer configures moderation behaviour in the API definition.

### System Parameters (From config.toml)

Configured by the **gateway administrator**.

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `apiKey` | string | Yes | `""` | Mistral API key. When empty, the policy reads the `MISTRAL_API_KEY` environment variable of the policy engine. |
| `model` | string | No | `"mistral-moderation-2603"` | Mistral moderation model. The category names below are those of `mistral-moderation-2603`. |

The Mistral endpoint defaults to `https://api.mistral.ai`. It is deliberately not a policy parameter, because the gateway lets an API definition override any system parameter. An API developer who could set the endpoint could have the administrator's key sent to a server of their own. To route moderation calls through an egress proxy or a private deployment, set the `MISTRAL_MODERATION_ENDPOINT` environment variable on the policy engine (gateway runtime) container. The value is a base URL without the `/v1/moderations` path.

#### Sample System Configuration

Add the key to the gateway's `config.toml`:

```toml
[policy_configurations.mistral_moderation_v1]
api_key = "<your-mistral-api-key>"
# model = "mistral-moderation-2603"
```

To keep the key out of `config.toml`, leave `api_key` unset and set the environment variable on the gateway runtime container instead, for example in Docker Compose:

```yaml
services:
  gateway-runtime:
    environment:
      - MISTRAL_API_KEY=${MISTRAL_API_KEY}
```

Restart the gateway runtime after changing the key, the model or the environment. The policy reads them when an API's policy chain is built.

### User Parameters (API Definition)

Configured by the **API developer**. At least one of `request` or `response` is required. Each side has its own `enabled` switch, so a side can be turned off without removing its settings. A side that is left out, or present with `enabled: false`, is not buffered and never calls Mistral.

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `request` | `MistralModerationConfig` object | Conditional | - | Moderation settings for request payloads. |
| `response` | `MistralModerationConfig` object | Conditional | - | Moderation settings for response payloads. |

#### MistralModerationConfig

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `enabled` | boolean | No | `true` | Turns moderation of this side on or off. A disabled side is still validated when the API is deployed, so it can be turned back on safely. |
| `moderationMode` | string | No | `"text"` | `"text"` or `"conversation"`. See [Moderation modes](#moderation-modes). |
| `messagesPath` | string | No | `"$.messages"` | Conversation mode only. JSONPath of the chat messages array in the request body. On the response, these messages are the context for the reply. |
| `jsonPath` | string | No | `"$.messages[-1].content"` (request), `"$.choices[0].message.content"` (response) | JSONPath of the text to moderate in text mode, and of the reply in response-side conversation mode. It is not used on the request in conversation mode. Leave empty to moderate the whole body as text. |
| `streamingJsonPath` | string | No | `"$.choices[0].delta.content"` | Response only. JSONPath of the reply text in each event of a streamed (`"stream": true`) response. See [Streaming](#streaming). |
| `passthroughOnError` | boolean | No | `false` | If `true`, traffic continues when the check cannot be completed: a Mistral API error, timeout or invalid response, or a JSONPath that cannot be read. If `false`, it is blocked. A detected violation is always blocked. |
| `showAssessment` | boolean | No | `false` | If `true`, blocked responses list the violating categories with their scores and thresholds. The moderated content is never included. |
| `timeout` | string | No | `"5s"` | Maximum time to wait for Mistral, as a Go duration (for example `"1500ms"`), up to `"30s"`. |
| `categoryThresholds` | object | No | see below | Per-category score thresholds. |

#### Moderation modes

| Mode | Request phase | Response phase |
|------|---------------|----------------|
| `text` | Sends the text at `jsonPath` to `POST /v1/moderations`. | Sends the reply at `jsonPath` to `POST /v1/moderations`. |
| `conversation` | Sends the messages at `messagesPath` to `POST /v1/chat/moderations`. Mistral classifies the last message, normally the new user turn, in the context of the earlier ones. This catches a harmful request spread over several turns. | Appends the reply at `jsonPath` as an assistant message to the request's messages at `messagesPath`, and sends them to `POST /v1/chat/moderations`. The reply is judged against the prompt that produced it. |

In conversation mode, messages are converted to the form Mistral accepts:

- **Roles**: `system`, `user`, `assistant` and `tool` are sent as is. `developer` is sent as `system`, and `function` as `tool`. A message with any other role is left out.
- **Content**: string content is sent as is. Content parts become their joined text, and image or audio parts are skipped. A message with no text, such as an assistant turn with only tool calls, is left out.
- **Nothing to classify**: when the last message has no text or an unsupported role, or the conversation has only system messages, the request passes without a Mistral call.
- **Unreadable messages**: if the request's messages can't be read, a request-phase check fails, and `passthroughOnError` decides. On the response phase they are only context, so the reply is classified on its own.
- **Request buffering**: response-side conversation mode buffers the request body so the policy can read the messages. This does not affect response streaming.

#### Streaming

Requests and responses are moderated the same way whether or not the client asked for a stream:

- **Request**: a `"stream": true` request is an ordinary JSON body, so it is moderated like any other request, in either mode.
- **Response, not streamed**: the reply is read at `jsonPath`.
- **Response, streamed**: configuring `response` buffers the response body. The policy receives the complete event stream, joins the `streamingJsonPath` fragment of every `data:` event into the full reply, and moderates it with the same mode, thresholds and error handling as a non-streamed reply. In conversation mode, the full reply is the assistant message after the request's messages.
  - If the reply passes, the original event stream is delivered to the client unchanged, all at once rather than token by token.
  - If it's blocked, the client receives HTTP `422` with the JSON error body instead of the stream. The status can still change because nothing has been sent yet.
- **Events with no text**: the opening role delta, the finishing delta, usage frames, `[DONE]`, comments and `event:` lines add no text. A reply with only tool calls has no text and passes without a Mistral call.
- **Unreadable stream**: if `streamingJsonPath` matches none of the stream's events (for example another provider's format), the reply can't be read, and `passthroughOnError` decides. Set `streamingJsonPath` for that format, for example `$.delta.text` for Anthropic-style streams.
- **Empty `jsonPath`**: the whole body, an event stream included, is moderated as raw text.
- **Request-only attachments**: the response is not buffered, so streamed replies keep streaming token by token.

#### Model Providers

The policy reads content only through `jsonPath`, `messagesPath` and `streamingJsonPath`, so it works in front of any model provider. There are two ways to deploy it.

**Behind an OpenAI-to-provider transformer (recommended).** The client speaks the OpenAI Chat Completions API, and a transformer such as `openai-to-anthropic-transformer`, `openai-to-gemini-transformer`, `openai-to-bedrock-transformer`, `openai-to-mistral-transformer` or `openai-to-azure-openai-transformer` converts it for the provider. The transformers convert streamed and non-streamed responses back to the OpenAI shape, so the default paths work for every provider.

List `mistral-moderation` **before** the transformer:

- Request policies run in list order, so the request is moderated in the OpenAI shape, before it is converted.
- Response policies run in reverse order, so the transformer converts the provider's response first and the policy then reads the OpenAI shape.

```yaml
operationPolicies:
  - name: mistral-moderation
    version: v0
    paths: [{path: /chat/completions, methods: [POST]}]
    params:
      request:  {moderationMode: conversation}
      response: {moderationMode: conversation}
  - name: openai-to-anthropic-transformer
    version: v0
    paths: [{path: /chat/completions, methods: [POST]}]
```

**Directly in front of a provider's native API.** Set the paths for that provider's format:

| Provider format | Request `jsonPath` (text) | `messagesPath` (conversation) | Response `jsonPath` | `streamingJsonPath` |
|-----------------|---------------------------|-------------------------------|---------------------|---------------------|
| OpenAI and compatible (Azure OpenAI, Mistral, vLLM, Ollama) | `$.messages[-1].content` (default) | `$.messages` (default) | `$.choices[0].message.content` (default) | `$.choices[0].delta.content` (default) |
| Anthropic Messages | `$.messages[-1].content` | `$.messages` | `$.content` | `$.delta.text` |
| Google Gemini | `$.contents[-1].parts` | `$.contents` | `$.candidates[0].content.parts` | `$.candidates[0].content.parts[0].text` |
| AWS Bedrock Converse | `$.messages[-1].content` | `$.messages` | `$.output.message.content` | not supported natively; use `openai-to-bedrock-transformer` |

Content blocks and parts are read the same way for every provider: the text of each block is joined, and blocks without text, such as images, tool calls (`tool_use`, `toolUse`, `functionCall`) and audio, are skipped. Gemini's `model` role is sent as `assistant`.

Native-format limits:

- A system prompt kept outside the messages array, such as Anthropic's top-level `system` or Bedrock's `system` blocks, is not part of the conversation sent in conversation mode. The messages are still classified.
- Bedrock's native streaming uses binary Amazon event-stream framing rather than server-sent events. It can't be read without `openai-to-bedrock-transformer`, and is handled as an extraction error.
- If `messagesPath` points at an array where no message has `content` or `parts`, the content can't be read, and `passthroughOnError` decides. Content that can't be read is never passed as clean.

#### categoryThresholds

Each key is a category name exactly as Mistral returns it. The value is a threshold from `0` to `1`, or `-1` to disable the category. Content is blocked when a category's score is **greater than or equal to** its threshold. Unknown category names are rejected when the API is created.

| Category | Default | Description |
|----------|---------|-------------|
| `sexual` | `0.5` | Sexual content |
| `hate_and_discrimination` | `0.5` | Hate and discrimination |
| `violence_and_threats` | `0.5` | Violence and threats |
| `selfharm` | `0.5` | Self-harm |
| `dangerous` | not evaluated | Dangerous content |
| `criminal` | not evaluated | Criminal content |
| `health` | not evaluated | Unqualified health advice |
| `financial` | not evaluated | Unqualified financial advice |
| `law` | not evaluated | Unqualified legal advice |
| `pii` | not evaluated | Personally identifiable information |
| `jailbreaking` | not evaluated | Attempts to override the model's instructions |

The four categories that correspond to Azure Content Safety's categories are on by default at `0.5`. Every other category is evaluated only when given a threshold. Configured values are applied on top of the defaults, so `{"pii": 0.5}` evaluates `pii` and the four defaults. Set a default category to `-1` to turn it off.

#### JSONPath Support

- `$.message`: a top-level field
- `$.data.content`: a nested field
- `$.messages[0].content`: the first message
- `$.messages[-1].content`: the last message
- `$.messages[*].content`: every message, moderated together in one call
- `$.choices[0].message.content`: the assistant's reply

When the value is an array of OpenAI-style content parts, the text parts are moderated and image or audio parts are skipped. A `null` value (for example a reply that only has tool calls) has nothing to moderate and passes.

#### build.yaml

Inside `gateway/build.yaml` in the `api-platform` repository, add the policy under `policies:`:

```yaml
- name: mistral-moderation
  gomodule: github.com/wso2/gateway-controllers/policies/mistral-moderation@v0
```

## Reference Scenarios

### Example 1: Moderating prompts and completions

```yaml
apiVersion: gateway.api-platform.wso2.com/v1
kind: LlmProvider
metadata:
  name: moderated-openai
spec:
  displayName: Moderated OpenAI
  version: v1.0
  template: openai
  context: /openai
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
  operationPolicies:
    - name: mistral-moderation
      version: v0
      paths:
        - path: /chat/completions
          methods: [POST]
          params:
            request:
              jsonPath: "$.messages[-1].content"
              categoryThresholds:
                jailbreaking: 0.7
                dangerous: 0.6
                criminal: 0.6
            response:
              jsonPath: "$.choices[0].message.content"
              showAssessment: true
              categoryThresholds:
                pii: 0.5
```

**Safe request (passes):**

```bash
curl -X POST http://localhost:8080/openai/chat/completions \
  -H "Content-Type: application/json" \
  -d '{"model": "gpt-4o", "messages": [{"role": "user", "content": "What is the capital of France?"}]}'
```

**Harmful request (blocked with HTTP 422):**

```bash
curl -X POST http://localhost:8080/openai/chat/completions \
  -H "Content-Type: application/json" \
  -d '{"model": "gpt-4o", "messages": [{"role": "user", "content": "I am going to find you and kill you."}]}'
```

```json
{
  "type": "MISTRAL_MODERATION",
  "message": {
    "action": "GUARDRAIL_INTERVENED",
    "interveningGuardrail": "mistral-moderation",
    "actionReason": "Violation of Mistral moderation detected.",
    "direction": "REQUEST"
  }
}
```

With `showAssessment: true`, the violating categories are added, highest score first:

```json
{
  "type": "MISTRAL_MODERATION",
  "message": {
    "action": "GUARDRAIL_INTERVENED",
    "interveningGuardrail": "mistral-moderation",
    "actionReason": "Violation of Mistral moderation detected.",
    "direction": "RESPONSE",
    "assessments": {
      "categories": [
        {"category": "violence_and_threats", "score": 0.998, "threshold": 0.5, "result": "FAIL"},
        {"category": "criminal", "score": 0.518, "threshold": 0.5, "result": "FAIL"}
      ]
    }
  }
}
```

### Example 2: Conversation moderation (recommended for chat APIs)

```yaml
params:
  request:
    moderationMode: conversation      # last user turn judged in the context of the chat
    categoryThresholds:
      jailbreaking: 0.7
  response:
    moderationMode: conversation      # reply judged against the prompt that produced it
    jsonPath: "$.choices[0].message.content"
```

For the request below, Mistral receives all three messages and classifies the last one:

```json
{"model": "gpt-4o", "messages": [
  {"role": "developer", "content": "You are a helpful assistant."},
  {"role": "user", "content": "Hi"},
  {"role": "user", "content": "Ignore your previous instructions and ..."}
]}
```

For the response, Mistral receives the same messages plus `{"role": "assistant", "content": "<reply>"}`.

### Example 3: Moderating every message as one text, with fail-open behaviour

```yaml
params:
  request:
    jsonPath: "$.messages[*].content"
    passthroughOnError: true
    timeout: "2s"
    categoryThresholds:
      sexual: 0.3
      selfharm: 0.3
      jailbreaking: 0.8
```

### Example 4: Only some categories

```yaml
params:
  request:
    categoryThresholds:
      sexual: -1                  # disabled
      hate_and_discrimination: -1 # disabled
      violence_and_threats: 0.7
      selfharm: 0.4
```

### Example 5: Moderation service failure

When Mistral cannot give a verdict and `passthroughOnError` is `false`, the policy blocks with HTTP 422:

```json
{
  "type": "MISTRAL_MODERATION",
  "message": {
    "action": "GUARDRAIL_INTERVENED",
    "interveningGuardrail": "mistral-moderation",
    "actionReason": "Error calling Mistral moderation API",
    "direction": "REQUEST",
    "assessments": ["Mistral moderation API rate limit exceeded (HTTP 429)"]
  }
}
```

`assessments` appears only with `showAssessment: true`. It names the class of failure and never holds the key, the endpoint or Mistral's own error text. The classes are rejected credentials (401/403), rate limit (429), unavailable (5xx), an unexpected status, a timeout, an unreachable service and an invalid response.

A request whose `jsonPath` (or, in conversation mode, `messagesPath`) cannot be read is blocked with `"actionReason": "Error extracting value from JSONPath"`, unless `passthroughOnError` is `true`.

## How it Works

#### Request Phase

1. **Content extraction**: in text mode, reads the text at `jsonPath`, or the whole body. In conversation mode, reads and converts the messages at `messagesPath`. If the content can't be read, `passthroughOnError` decides.
2. **Nothing to moderate**: if the text is empty, or the conversation has nothing to classify, the request passes without a Mistral call.
3. **Moderation**: sends the content to Mistral with `Authorization: Bearer <key>`, bounded by `timeout`. The call is not retried.
   - Text mode: `{"model": "mistral-moderation-2603", "input": "<text>"}` to `POST /v1/moderations`.
   - Conversation mode: `{"model": "mistral-moderation-2603", "input": [{"role": "...", "content": "..."}, ...]}` to `POST /v1/chat/moderations`.
4. **Threshold evaluation**: compares each enabled category's score with its threshold. The request is blocked with HTTP 422 if any score is greater than or equal to its threshold. Otherwise it continues to the upstream unchanged.
5. **Error strategy**: if Mistral returns an error, times out, cannot be reached or returns an invalid response, `passthroughOnError` decides.

#### Response Phase

The response phase follows the same steps on the upstream's response, using the `response` configuration. A streamed response is first reassembled into the complete reply from its events (see [Streaming](#streaming)). In conversation mode, the reply at `jsonPath` is appended as an assistant message to the original request's messages. An upstream response with a non-2xx status carries no model output, so it is passed through without moderation. A blocked response is replaced with HTTP 422 and the error body.

#### Threshold Evaluation

The policy decides on `category_scores` only. Mistral also returns a boolean `categories` map. Those booleans reflect Mistral's own fixed thresholds, which can be neither seen nor tuned, so they are not used to decide.

If an enabled category is missing from Mistral's scores (for example after the administrator switches to a model with different categories), the check counts as failed and `passthroughOnError` decides. The policy does not treat a missing score as safe.

When more than one category reaches its threshold, the highest-scoring category decides the fault code.

#### Fault Reporting

Every rejection is also reported to the gateway as a fault, which the gateway uses for analytics and hands to the API's fault policies. The status and body the client receives are as described above. A guardrail verdict names the intervening guardrail (`mistral-moderation`). Its assessment is attached only when `showAssessment` is enabled.

| When | Status | Code | Type |
|------|--------|------|------|
| `sexual` decides | `422` | `906002` | `guardrail` |
| `hate_and_discrimination` decides | `422` | `906001` | `guardrail` |
| `violence_and_threats` decides | `422` | `906004` | `guardrail` |
| `selfharm` decides | `422` | `906003` | `guardrail` |
| `dangerous` or `criminal` decides | `422` | `906006` | `guardrail` |
| `jailbreaking` decides | `422` | `906008` | `guardrail` |
| `pii` decides | `422` | `906101` | `guardrail` |
| `health`, `financial` or `law` decides | `422` | `906099` | `guardrail` |
| Request: the value at `jsonPath` or `messagesPath` cannot be read | `422` | `960001` | `validation` |
| Response: the value at `jsonPath` cannot be read | `422` | `960000` | `mediation` |
| Request or response: Mistral gives no verdict | `422` | `960000` | `mediation` |

With `passthroughOnError` enabled, the last three rows pass the traffic through instead, and no fault is reported.

## Testing

Curl scenarios for text and conversation mode, with streamed and non-streamed replies, are in [Testing with curl](./mistral-moderation-testing.md). Each scenario lists the configuration change to make before the curl, and what HTTP status and body to expect.

## Limitations

- **No token-by-token delivery with response moderation**: a streamed reply is held until the whole reply has been generated and moderated, then delivered at once. The client receives a valid event stream, but its time to first token becomes the time to the full reply plus one Mistral call. Request-only attachments keep token-by-token streaming.
- **One choice per stream**: `streamingJsonPath` reads one path, so with `n` greater than 1 only the choice it selects is moderated. Tool-call arguments and reasoning text in stream events are not moderated.
- **Input size**: the text or conversation is sent whole and is not truncated. Long conversations count against the limit in conversation mode. Mistral documents a 128k-token context for `mistral-moderation-2603`. A larger input is rejected by Mistral and handled by `passthroughOnError`.
- **Model and categories**: the category names are those of `mistral-moderation-2603`. Mistral notes that policies built on `category_scores` can need recalibration when the model changes.
- **Text only**: image and audio content parts are not moderated.

## Notes

- Each moderated phase adds one Mistral call to the request's latency, typically a few hundred milliseconds, with occasional spikes. Set `timeout` to bound the worst case. When it is reached, `passthroughOnError` decides.
- Mistral's cookbook blocks when the highest score across all categories reaches 0.2. To get that behaviour, give every category a threshold of `0.2`.
- Mistral applies rate limits per API key. A 429 is handled by `passthroughOnError`, and the policy does not retry, so a rate-limited key does not multiply traffic. Size your Mistral plan for the combined request and response volume of every route that uses the policy.
- Moderated text is sent to Mistral, so check your data residency and privacy requirements.
- The policy uses the gateway's shared outbound HTTP client, with its pooling, timeouts and optional SSRF guard. It never logs the API key or the moderated text.
- Start with `showAssessment: true` in a test environment to calibrate thresholds against real traffic, then turn it off in production.
- A threshold of `0` blocks every request for that category, because every score is at least `0`.
