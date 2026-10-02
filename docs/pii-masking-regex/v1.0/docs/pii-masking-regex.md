---
title: "Overview"
---
# PII Masking Regex Guardrail

## Overview

The PII Masking Regex Guardrail masks or redacts Personally Identifiable Information (PII) from request and response bodies using configurable regular expression patterns. This guardrail helps protect sensitive user data by replacing PII with placeholders or redaction markers before content is processed or returned.

This policy supports SSE streaming responses. When the upstream returns a streaming response (`stream: true`), the guardrail detects PII placeholders in the streamed assistant text and restores masked values across event and chunk boundaries. It is not tied to one vendor's wire format: the OpenAI chat/legacy completions shape (and every provider that speaks it), Anthropic Messages, Google Gemini, and Amazon Bedrock are handled out of the box, with no configuration required.

## Features

- Configurable PII entity detection using regular expressions
- Two modes: masking (reversible) and redaction (permanent)
- Automatic PII restoration in responses when using masking mode
- Supports JSONPath extraction to process specific fields within JSON payloads
- Streaming response support for both SSE and plain chunked bodies -- the gateway accumulates only until a PII placeholder (e.g., `[EMAIL_0000]`) is complete, then restores and forwards

## Configuration

This policy requires only a single-level configuration where all parameters are configured in the API definition YAML.

### User Parameters (API Definition)

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `email` | boolean | No | `false` | Enables built-in EMAIL detection. At least one of `email`, `phone`, `ssn`, or `customPIIEntities` must be enabled. |
| `phone` | boolean | No | `false` | Enables built-in PHONE detection. At least one of `email`, `phone`, `ssn`, or `customPIIEntities` must be enabled. |
| `ssn` | boolean | No | `false` | Enables built-in SSN detection. At least one of `email`, `phone`, `ssn`, or `customPIIEntities` must be enabled. |
| `customPIIEntities` | `CustomPIIEntity` array | No | - | Custom PII entity definitions for detection. Each item defines a `piiEntity` name and `piiRegex` pattern. At least one item required if provided. |
| `jsonPath` | string | No | `"$.messages[-1].content"` | JSONPath expression to extract a specific value from JSON payload. If empty, processes the entire payload as a string. |
| `redactPII` | boolean | No | `false` | If `true`, redacts PII by replacing with "*****" (permanent, cannot be restored). If `false`, masks PII with placeholders that can be restored in responses. |

### CustomPIIEntity Configuration

Each item in the `customPIIEntities` array must contain:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `piiEntity` | string | Yes | Name/type of the PII entity (e.g., "CREDIT_CARD", "PASSPORT"). Must contain only uppercase letters and underscores. |
| `piiRegex` | string | Yes | Regular expression pattern to match the PII entity. Must be a valid Go regexp pattern. |

#### JSONPath Support

The guardrail supports JSONPath expressions to extract and process specific fields within JSON payloads. Common examples:

- `$.messages` - Extracts the `messages` field from the root object
- `$.data.content` - Extracts nested content from `data.content`
- `$.items[0].text` - Extracts text from the first item in an array
- `$.messages[0].content` - Extracts content from the first message in a messages array

If `jsonPath` is empty or not specified, the entire payload is processed as a string.

The path may also select an object or an array, or use a `*` segment to fan out over an object's values or an array's items (for example `$.questions.*.instructions`). Every string and number inside the selection is masked in place, the rest of the payload is left unchanged, and all masked values share one set of placeholders so the response is restored correctly. This includes chat multimodal `content` arrays, whose `text` parts are masked.

If the masked value cannot be written back, the request is rejected with a `500` rather than forwarded unmasked.

**Note:**

Inside the `gateway/build.yaml`, ensure the policy module is added under `policies:`:

```yaml
- name: pii-masking-regex
  gomodule: github.com/wso2/gateway-controllers/policies/pii-masking-regex@v1
```

## Reference Scenarios

### Example 1: Basic PII Masking

Deploy an LLM provider that masks email addresses and phone numbers in requests and restores them in responses:

```yaml
apiVersion: gateway.api-platform.wso2.com/v1
kind: LlmProvider
metadata:
  name: pii-masking-provider
spec:
  displayName: PII Masking Provider
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
      - path: /models
        methods: [GET]
      - path: /models/{modelId}
        methods: [GET]
  operationPolicies:
    - name: pii-masking-regex
      version: v1
      paths:
        - path: /chat/completions
          methods: [POST]
          params:
            email: true
            phone: true
            jsonPath: "$.messages[-1].content"
            redactPII: true
```

**Test the guardrail:**

```bash
# Request with PII (should be masked)
curl -X POST http://localhost:8080/openai/chat/completions \
  -H "Content-Type: application/json" \
  -d '{
    "model": "gpt-4",
    "messages": [
      {
        "role": "user",
        "content": "Contact me at john.doe@example.com or call +1234567890"
      }
    ]
  }'
```

 **Sample Payload after intervention from Regex PII Masking with redactPII=true**

```json
{
  "messages": [
    {
      "role": "user",
      "content": "Prepare an email with my contact information, email: *****, and website: https://example.com."
    }
  ]
}
```

### Example 2: Streaming Response PII Restoration

When using masking mode with a streaming LLM endpoint, PII placeholders sent to the upstream are automatically restored in the SSE response stream:

```yaml
  operationPolicies:
    - name: pii-masking-regex
      version: v1
      paths:
        - path: /chat/completions
          methods: [POST]
          params:
            email: true
            phone: true
            jsonPath: "$.messages[-1].content"
            redactPII: false
```

When the upstream returns an SSE streaming response, the policy detects placeholders such as `[EMAIL_0000]` in the delta content across chunk boundaries and restores them to the original PII values. The smart boundary detection ensures placeholders split across multiple SSE events (e.g., `[`, `EMAIL`, `_`, `0000`, `]` arriving in separate tokens) are correctly reassembled before restoration.

## How It Works

#### Request Phase

1. **Content Extraction**: Extracts content using `jsonPath` (if configured) or uses the entire payload as a string.
2. **PII Detection**: Applies each configured `piiRegex` pattern to detect matching PII entities.
3. **Intervention**: Replaces matches with placeholders (`[ENTITY_TYPE_XXXX]`) in masking mode or with `*****` in redaction mode.
4. **Metadata Storage**: Stores placeholder-to-original mappings in request metadata when masking mode is used.
5. **Forwarding**: Sends the transformed payload to the upstream service.

#### Response Phase

1. **Mapping Check**: Checks whether masking metadata is available from request processing.
2. **Restoration**: If `redactPII: false`, replaces placeholders with original values in the response.
3. **Redaction Preservation**: If `redactPII: true`, no restoration is performed.
4. **Response Return**: Returns restored or redacted content to the client.

#### PII Modes

- **Masking Mode (`redactPII: false`)**: Uses placeholders such as `[EMAIL_0000]` and original PII values are stored temporarily in request metadata for restoration. Recommended when you need to preserve data for downstream processing or response generation
- **Redaction Mode (`redactPII: true`)**: Permanently replaces detected PII with `*****` and does not restore original values. Recommended for maximum privacy protection when original values are not needed

### Streaming (SSE) Processing

When the upstream returns an SSE streaming response, each SSE event arrives as a `data:` line containing a JSON payload, for example:

```
data: {"choices":[{"delta":{"content":"token"}}]}
```

Restoration needs a *complete* placeholder: an LLM emits `[EMAIL_0000]` as several tokens (`[`, `EMAIL`, `_0000`, `]`), each in its own SSE event, so a chunk cut in the middle would match nothing and deliver the masked text to the client. The gateway therefore buffers response chunks on the policy's behalf and hands them over only once a placeholder cannot still be half-emitted:

1. **Response Mode Detection**: Each buffer handed to the policy is routed as SSE or plain-body by its own shape — SSE if it carries a `data:` or `event:` line. Because the gateway only releases a buffer on an SSE event boundary, a frame that is legitimately not data-shaped (a `: keep-alive` comment, for example) always travels with the events around it rather than being judged on its own.
2. **Delta Content Extraction**: The assistant text is extracted from each SSE `data:` line using an ordered list of JSONPath expressions — `choices[0].delta.content` for OpenAI-compatible providers, `delta.text` for Anthropic, `candidates[0].content.parts[0].text` for Gemini, `contentBlockDelta.delta.text` for Bedrock Converse, and so on. The paths are tried in order and the first match wins, so no provider is special-cased.
3. **Placeholder Boundary Detection**: The policy asks the gateway to keep buffering while the assembled assistant text ends in an unclosed `[` whose trailing characters could still complete a placeholder. Because a placeholder is always an uppercase entity name followed by a four-digit counter (`[EMAIL_0000]`), any other character after the bracket — a space, lowercase prose, punctuation — proves nothing restorable is arriving, and the stream is released on the spot. Buffering stops as soon as the bracket closes, as soon as the text stops looking like a placeholder, at end of stream, or once 64 bytes have accumulated after the bracket, whichever comes first. This test is on the assembled text rather than on how many events it spans: there is no limit on the number of SSE events buffering may continue across, so a placeholder emitted one character per event is held exactly as long as one emitted whole. Buffering also continues across a partially received event, since a truncated JSON payload has no readable content.
4. **Placeholder Restoration**: When a buffer is released, the extracted text of every event in it is concatenated, placeholders are restored to their original PII values, and the restored text is written back through the same JSONPath it was extracted from, into the first content-bearing SSE event. Each subsequent merged event is dropped as a complete block — its `event:` field line and trailing blank separator go with its `data:` line — so the stream stays well-formed for providers that label every event. Comments, `[DONE]`, and usage frames keep their original position.
5. **Redaction Mode**: When `redactPII: true`, no restoration is performed in the response phase, so the policy never asks for buffering and chunks pass straight through.
6. **Error Handling**: Since HTTP response headers are already committed when streaming begins, errors cannot be reported via HTTP status codes. If an error occurs during restoration, the chunk passes through unmodified.

**Non-SSE chunked responses**: For plain JSON responses delivered via chunked transfer encoding (e.g., `stream: false` with `Transfer-Encoding: chunked`), the body is accumulated until it parses as complete JSON, then restored and forwarded in one piece. Such a response is not incrementally consumable anyway, so buffering it costs no perceived latency, and it guarantees no placeholder is split across two flushes.

**Compressed responses**: `gzip`, `br`, `zstd` and `deflate` responses are decompressed by the gateway before this policy runs and re-compressed afterwards, so restoration works normally and the policy itself is encoding-agnostic. If an upstream answers in an encoding the gateway cannot round-trip, the response is rejected rather than forwarded uninspected, so a masked placeholder is never silently delivered because restoration did not run.

#### Processing Behavior

- Supports multiple entity patterns in one policy and processes each detected match by entity type.
- Placeholder format is `[ENTITY_TYPE_XXXX]`, where `XXXX` is a 4-digit hexadecimal sequence.
- Full payload processing is used when `jsonPath` is not configured.

## Notes

- Common use cases include privacy protection, compliance (GDPR/CCPA/HIPAA), data minimization, secure AI processing, and audit-friendly masking workflows.
- Regular expressions use Go's regexp package (RE2 syntax).
- PII detection is case-sensitive by default. Use `(?i)` flag for case-insensitive matching.
- The `piiEntity` name must contain only uppercase letters and underscores (e.g., "EMAIL", "PHONE_NUMBER", "SSN").
- When using masking mode, the placeholder-to-original mapping is stored in request metadata and automatically used for response restoration.
- Multiple PII entities can match the same content; each match is processed according to its entity type.
- Placeholder format is `[ENTITY_TYPE_XXXX]` where XXXX is a 4-digit hexadecimal number (e.g., `[EMAIL_0000]`, `[EMAIL_0001]`, `[PHONE_000a]`).
- When using JSONPath, if the path does not exist or the extracted value is not a string, an error response (HTTP 500) is returned.
- Redaction mode is irreversible; use masking mode if you need to restore PII in responses.
- In streaming mode, `redactPII: true` disables response-phase processing entirely since there is nothing to restore. Chunks pass through without buffering overhead.
- In streaming mode, buffering continues only while the text after an unclosed `[` could still complete a placeholder, and never holds back more than 64 bytes of assistant text. Restoration does not depend on how finely the upstream tokenises a placeholder or on where chunk boundaries fall.
- Complex regex patterns may impact performance; test thoroughly with expected content volumes.
