---
title: "Overview"
---
# Bring Your Own Guardrail

## Overview

The Bring Your Own Guardrail policy connects a guardrail service you already run to the gateway, through configuration alone. The policy extracts text from the request or response body using JSONPath, POSTs it to your service, and applies the decision the service returns: **allow** the traffic, **block** it, or **modify** it by replacing the checked text.

Your service must implement the [guardrail service contract](#guardrail-service-contract) below. The policy does not adapt itself to arbitrary guardrail APIs: if an existing service speaks a different API, put a small adapter in front of it that translates to and from this contract.

Use this policy when your organisation already has its own content checks (an in-house classifier, a DLP service, a vendor not covered by a dedicated policy) and you want the gateway to enforce them without writing, compiling, or maintaining gateway policy code.

### What it does not do

- It inspects **text only**. Images, audio, and tool calls are not sent to the service; in a multimodal message, only the text parts are checked.
- It does not forward request headers, credentials, or other payload fields to your service. Only the extracted text and a little context are sent.
- It does not template the request to, or map the response from, your service. The contract is fixed.

## Features

- One HTTP endpoint of your own, called with a fixed, versioned JSON contract
- Three decisions: `allow`, `block`, and `modify` (replace the checked text, keeping every other field of the payload)
- Request and response checks, configured independently
- JSONPath extraction of a string or of the text parts of a content-part array
- Bearer or raw token authentication, with the token supplied as a secret reference
- Configurable timeout (default `5s`, maximum `30s`)
- `enforce` and `monitor` modes
- Explicit `onError` behaviour: fail closed (default) or fail open when no valid decision is obtained
- Strict response validation: a malformed or ambiguous decision is an error, never an allow
- Records each check's outcome in request metadata, and guardrail hits in analytics
- Logs never include the checked text, the token, or the service's response body

## Configuration

All parameters are set on the policy attachment. This policy has no system parameters in `config.toml`.

### User Parameters (API Definition)

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `endpoint` | string | Yes | — | Full URL the policy POSTs each check to, for example `https://guardrail.example.com/evaluate`. No path is appended. Must use `http` or `https` and must not contain credentials (`user:pass@`). |
| `auth` | object | No | — | Credentials for the service. Omit when the service needs no authentication. See [Authentication](#authentication). |
| `auth.type` | string | No | `bearer` | Authentication scheme: `bearer` sends `Authorization: Bearer <token>`; `raw` sends `Authorization: <token>` with no prefix. |
| `auth.token` | string | Yes, when `auth` is set | — | Token for the service. Supply it as a secret reference, `'{{ secret "handle" }}'`, not a literal value. |
| `timeout` | string | No | `"5s"` | Maximum time to wait for the service, as a Go duration (for example `"1500ms"`). Must be greater than `0` and at most `"30s"`. |
| `mode` | string | No | `enforce` | `enforce` applies decisions. `monitor` never blocks or modifies; see [Enforce and monitor modes](#enforce-and-monitor-modes). |
| `onError` | string | No | `block` | `block` rejects traffic when no valid decision is obtained; `allow` passes it through unchecked. See [Service errors](#service-errors-fail-closed-and-fail-open). |
| `request` | object | One of `request`/`response` | — | Request phase configuration. |
| `response` | object | One of `request`/`response` | — | Response phase configuration. |

#### Request configuration

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `enabled` | boolean | No | `true` | Enables request checks. |
| `jsonPath` | string | No | `"$.messages[-1].content"` | JSONPath of the text to check. See [JSONPath](#jsonpath). |
| `showAssessment` | boolean | No | `false` | Include the service's `reason` (for a block) or the kind of error (for a failed check) in the `422` response. |

#### Response configuration

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `enabled` | boolean | No | `true` | Enables response checks. |
| `jsonPath` | string | No | `"$.choices[0].message.content"` | JSONPath of the text to check. |
| `streamingJsonPath` | string | No | `"$.choices[0].delta.content"` | JSONPath of the text in each event of a streamed response. See [Streaming](#streaming). |
| `showAssessment` | boolean | No | `false` | As for requests. |

> Unlike the AWS Bedrock Guardrail policy, `response.enabled` defaults to `true`: adding a `response` block turns response checks on. Set `enabled: false` to keep the block but switch checks off.

#### Validation

The policy rejects the attachment at deploy time, rather than failing on live traffic, when:

- `endpoint` is missing, is not an absolute `http`/`https` URL with a host, contains credentials, or contains a fragment;
- `auth` is not an object, `auth.type` is not `bearer` or `raw`, or `auth.token` is missing, blank, or contains line breaks;
- `timeout` is not a Go duration, is `0` or negative, or exceeds `30s`;
- `mode` or `onError` is not one of its listed values;
- neither `request` nor `response` is present;
- a `jsonPath` or `streamingJsonPath` is not in the [supported form](#jsonpath).

Error messages never include the token.

### Authentication

Store the token as a gateway secret and reference it from the attachment:

```yaml
params:
  endpoint: https://guardrail.example.com/evaluate
  auth:
    type: bearer
    token: '{{ secret "guardrail-token" }}'
```

The gateway substitutes the secret's value before the policy receives its parameters, and the policy sends `Authorization: Bearer <token>` on every check. The token is never logged. Redirects from the service are not followed, so the token is only ever sent to the configured `endpoint`; a `3xx` reply is treated as an unexpected status.

For a service that expects the token with no `Bearer ` prefix, set `auth.type: raw` instead; the policy then sends `Authorization: <token>` verbatim.

Do not put credentials in the endpoint URL. User info (`https://user:pass@host`) is rejected. A query-string key is accepted but discouraged: prefer `auth`.

### JSONPath

`jsonPath` selects a single value. The policy supports the dotted form the gateway's other guardrails use: `$.` followed by keys separated by `.`, where a key may carry an array index, including negative indexes counted from the end.

| `jsonPath` | Selects |
|------------|---------|
| `$.messages[-1].content` | Content of the last message (OpenAI Chat Completions request) |
| `$.messages[0].content` | Content of the first message |
| `$.choices[0].message.content` | Assistant reply (OpenAI Chat Completions response) |
| `$.input` | A top-level `input` string |
| `$.data.prompt.text` | A nested field |
| *(empty string)* | The whole body, as text |

The selected value determines what is sent:

- **A string** is sent as one text.
- **An array of content parts** (OpenAI multimodal format) sends one text per text part, in order. Image, audio, and other non-text parts are skipped and not inspected. A `modify` decision replaces each text part in place.
- **`null`**, such as the content of a tool-call-only reply, has nothing to check and passes without calling the service. So does text that is empty or only whitespace.
- **Anything else**, or a path that does not resolve, is an extraction error, handled per `onError`.

Wildcards (`*`, `[*]`) are rejected, because a `modify` decision needs a single location to write to.

## Guardrail Service Contract

Contract version: **`v1`**.

### Request

For every check, the policy sends:

```http
POST <endpoint>
Content-Type: application/json
Accept: application/json
Authorization: Bearer <token>        (only when auth is configured; "<token>" alone when auth.type is "raw")
```

```json
{
  "contractVersion": "v1",
  "inputType": "request",
  "texts": ["Text extracted from the API payload"],
  "metadata": {
    "apiName": "example-api",
    "apiVersion": "v1.0",
    "requestId": "8a0c1f3e-0b8a-4c4f-9d1e-2f6f7f0c9d11"
  }
}
```

| Field | Description |
|-------|-------------|
| `contractVersion` | Always `"v1"` for this contract. It changes only if the contract changes incompatibly. |
| `inputType` | `"request"` or `"response"`: the phase being checked. |
| `texts` | The extracted texts, at least one. Usually one; one per text part when `jsonPath` selects a content-part array. |
| `metadata` | Context for correlation. Each field is present only when the gateway knows it. |

Nothing else is sent: no request headers, no client credentials, and no other payload fields.

### Response

The service must reply with HTTP `200` and a JSON object containing one of three decisions.

**Allow** the traffic unchanged:

```json
{ "action": "allow" }
```

**Block** the traffic. `reason` is optional; it is shown to the client only when `showAssessment` is `true`:

```json
{ "action": "block", "reason": "Restricted content" }
```

**Modify** the traffic by replacing the checked text. `texts` must have exactly as many entries as the request's `texts`, in the same order; each entry replaces the text at that position:

```json
{ "action": "modify", "texts": ["My card number is [REDACTED]"] }
```

### Validation rules

The policy treats any of the following as a **guardrail error**, handled per `onError`. None of them is ever treated as `allow`.

- An HTTP status other than `200`, including other `2xx` codes and redirects.
- A body that is not a JSON object, is empty, or is larger than 1 MiB.
- A missing `action`, or one that is not exactly `allow`, `block`, or `modify` (case-sensitive).
- `modify` without `texts`, with `texts` that is not an array of strings (a `null` entry is rejected), or with a different number of entries than were sent.
- `texts` present alongside `allow` or `block`, since it is unclear whether the service meant to modify.
- A connection failure or a timeout.

Fields the contract doesn't define are ignored, so a service can return its own diagnostics alongside the decision.

### Implementing the contract

A minimal service using only the Python standard library, for local testing. It blocks texts containing `forbidden`, masks `secret`, and allows everything else:

```python
# guardrail.py: run with `python3 guardrail.py`, listens on :9000
import json
from http.server import BaseHTTPRequestHandler, HTTPServer

TOKEN = "dev-token"

class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path != "/evaluate":
            return self.send_error(404)
        if self.headers.get("Authorization") != f"Bearer {TOKEN}":
            return self.send_error(401)
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        texts = body["texts"]
        if any("forbidden" in t.lower() for t in texts):
            decision = {"action": "block", "reason": "Forbidden topic"}
        elif any("secret" in t.lower() for t in texts):
            decision = {"action": "modify", "texts": [t.replace("secret", "******") for t in texts]}
        else:
            decision = {"action": "allow"}
        out = json.dumps(decision).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)

HTTPServer(("0.0.0.0", 9000), Handler).serve_forever()
```

Verify it with `curl` before pointing the gateway at it:

```bash
# allow
curl -s localhost:9000/evaluate -H 'Authorization: Bearer dev-token' \
  -d '{"contractVersion":"v1","inputType":"request","texts":["Hello"],"metadata":{}}'
# {"action": "allow"}

# block
curl -s localhost:9000/evaluate -H 'Authorization: Bearer dev-token' \
  -d '{"contractVersion":"v1","inputType":"request","texts":["a forbidden topic"],"metadata":{}}'
# {"action": "block", "reason": "Forbidden topic"}

# modify
curl -s localhost:9000/evaluate -H 'Authorization: Bearer dev-token' \
  -d '{"contractVersion":"v1","inputType":"request","texts":["my secret plan"],"metadata":{}}'
# {"action": "modify", "texts": ["my ****** plan"]}
```

Check that each reply has status `200`, a JSON body, and, for `modify`, one entry in `texts` for every text sent.

## Behaviour

### Decisions

| Decision | `enforce` mode | `monitor` mode |
|----------|----------------|----------------|
| `allow` | Traffic continues unchanged. | Same. |
| `block` | Request: `422` returned to the client, upstream not called. Response: replaced with a `422`. | Traffic continues unchanged; hit recorded. |
| `modify` | The text at `jsonPath` is replaced; every other field of the payload is kept. | Traffic continues unchanged; would-be modification recorded. |

When a body is modified it is re-encoded as JSON, so its key order and whitespace may change, while its fields and values, including large integers, are kept exactly.

A blocked request or response receives:

```json
{
  "type": "BYO_GUARDRAIL",
  "message": {
    "action": "GUARDRAIL_INTERVENED",
    "interveningGuardrail": "BYO Guardrail",
    "direction": "REQUEST",
    "actionReason": "Violation of guardrail detected.",
    "assessments": "Restricted content"
  }
}
```

`assessments` appears only with `showAssessment: true` and a `reason` from the service. `direction` is `RESPONSE` in the response phase.

### Enforce and monitor modes

With `mode: monitor`, the policy calls the service exactly as in `enforce` mode, but never blocks or modifies traffic, not even on a service error, regardless of `onError`. For a `block` decision it:

- sets `isGuardrailHit: true` and `guardrailName: BYO Guardrail` in analytics, the same fields a block sets; a monitored hit is told apart from a real block by its status code (the upstream's status rather than `422`);
- records the decision in request metadata (see below);
- logs the would-be block at `INFO` level, without the checked text.

A `modify` decision in monitor mode is recorded in request metadata and logged at `INFO`, but not counted as an analytics hit, consistent with modifications in enforce mode.

Use monitor mode to see how your service behaves on real traffic before switching to `enforce`.

### Service errors: fail-closed and fail-open

A check fails when the policy cannot obtain a valid decision: the service is unreachable or times out, returns an unexpected status, returns a response that breaks the [validation rules](#validation-rules), or the text cannot be extracted from the payload.

| `onError` | In `enforce` mode |
|-----------|-------------------|
| `block` (default) | The traffic is rejected with `422` and `actionReason: "Guardrail check could not be completed."`. With `showAssessment`, `assessments` names the kind of failure (for example `"Guardrail service timed out"`), never the raw error or the service's response body. |
| `allow` | The traffic passes through unchanged and unchecked. |

Either way, the failure is logged at `WARN` with the phase, the kind of error, the HTTP status (when there was one), the configured timeout, and the request ID, and it is recorded in request metadata as `decision: error`. A fail-open pass-through is never recorded as an `allow`.

**Choosing between them.** Fail-closed is the safe default: if the guardrail cannot vouch for the traffic, the traffic does not flow, so an outage of your service becomes an outage of the API. Fail-open keeps the API available during a guardrail outage, but lets unchecked content through for as long as the outage lasts; choose it only when availability matters more than the check, and alert on the `WARN` logs.

`timeout` bounds each call. Set it below the client's own timeout, leaving room for the upstream call as well.

### Request metadata

Each check records its result in `SharedContext.Metadata` under `byo-guardrail:request` or `byo-guardrail:response`, where later policies and the traffic-logging analytics publisher can read it:

| Field | Values |
|-------|--------|
| `decision` | `allow`, `block`, `modify`, or `error` |
| `outcome` | What the gateway did: `passed`, `blocked`, or `modified` |
| `errorType` | For `error` only: `extraction`, `timeout`, `connection`, `http_status`, `invalid_response`, or `modification` |
| `statusCode` | For `error` only, when the service replied: its HTTP status |

The service's `reason` and the checked text are not recorded.

### Streaming

Your service checks complete text, not a stream of fragments: checking each chunk on its own would let content split across chunks through. So:

- **Request checks only:** streaming works normally. The policy does not touch the response.
- **Response checks enabled:** streaming is disabled on the route. A streamed (`stream: true`) reply is buffered in full, its text is reassembled from each SSE event using `streamingJsonPath`, checked once, and delivered to the client in one piece, or replaced by a `422`.

A `modify` decision cannot be applied to a streamed reply, which has no single location to write the replacement to. Rather than deliver text the service asked to change, the policy blocks the reply (or, in monitor mode, records it). If your service modifies responses, have clients send non-streaming requests.

For providers whose SSE events don't use the OpenAI delta shape, set `streamingJsonPath` accordingly (for example `$.delta.text` for Anthropic `content_block_delta` events). If it matches none of the stream's events, the reply is an extraction error, handled per `onError`.

### Upstream errors

A response with a non-`2xx` status from the upstream is passed through without being checked, so clients see the provider's own error instead of a guardrail block.

### build.yaml Integration

Inside the `api-platform` repository, add the policy package under `policies:` in `/gateway/build.yaml`:

```yaml
- name: byo-guardrail
  gomodule: github.com/wso2/gateway-controllers/policies/byo-guardrail@v0
```

## Reference Scenarios

### Example 1: Check prompts, fail closed

```yaml
apiVersion: gateway.api-platform.wso2.com/v1
kind: LlmProvider
metadata:
  name: byo-guardrail-provider
spec:
  displayName: BYO Guardrail Provider
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
    - name: byo-guardrail
      version: v0
      paths:
        - path: /chat/completions
          methods: [POST]
          params:
            endpoint: https://guardrail.internal.example.com/evaluate
            auth:
              type: bearer
              token: '{{ secret "guardrail-token" }}'
            request:
              jsonPath: "$.messages[-1].content"
              showAssessment: true
```

**Test the guardrail** (with the [sample service](#implementing-the-contract)):

```bash
# Blocked: HTTP 422
curl -X POST http://localhost:8080/openai/chat/completions \
  -H "Content-Type: application/json" \
  -d '{"model":"gpt-4o","messages":[{"role":"user","content":"Tell me about the forbidden topic"}]}'

# Modified: the upstream receives "My ****** plan"
curl -X POST http://localhost:8080/openai/chat/completions \
  -H "Content-Type: application/json" \
  -d '{"model":"gpt-4o","messages":[{"role":"user","content":"My secret plan"}]}'
```

### Example 2: Check requests and responses, fail open

```yaml
params:
  endpoint: https://guardrail.internal.example.com/evaluate
  auth:
    token: '{{ secret "guardrail-token" }}'
  timeout: "2s"
  onError: allow
  request:
    jsonPath: "$.messages[-1].content"
  response:
    jsonPath: "$.choices[0].message.content"
```

If the service is down or slow, traffic flows unchecked and each failure is logged at `WARN` and recorded as `decision: error` in request metadata.

### Example 3: Monitor before enforcing

```yaml
params:
  endpoint: https://guardrail.internal.example.com/evaluate
  auth:
    token: '{{ secret "guardrail-token" }}'
  mode: monitor
  request: {}
```

Nothing is blocked or modified. Would-be blocks appear in analytics as guardrail hits, and every decision is recorded under `byo-guardrail:request`. Switch `mode` to `enforce` once the service's decisions look right.

### Example 4: Check a non-chat payload

For an API whose body is `{"query": {"text": "..."}}`:

```yaml
params:
  endpoint: https://guardrail.internal.example.com/evaluate
  auth:
    token: '{{ secret "guardrail-token" }}'
  request:
    jsonPath: "$.query.text"
```

## Notes

- The service is called once per enabled phase per request, so it adds its latency to every call; keep it close to the gateway.
- TLS uses the gateway's system trust store. A service with a certificate from a private CA must present a chain the gateway already trusts.
- The policy does not retry. Make the service highly available, or use `onError: allow` if availability matters more than the check.
- An existing guardrail API that does not implement this contract needs an adapter: a small service that accepts this contract's request, calls your API, and maps its result to `allow`, `block`, or `modify`.
