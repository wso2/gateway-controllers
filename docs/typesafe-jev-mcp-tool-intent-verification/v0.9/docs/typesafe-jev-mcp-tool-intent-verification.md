---
title: "Overview"
---
# TypeSafe Jev MCP Tool Intent Verification

## Overview

The TypeSafe Jev MCP Tool Intent Verification policy screens MCP `tools/call` requests using [TypeSafe AI's Jev](https://typesafe.ai/) "System One" model before they reach the MCP server. Jev doesn't generate text: it takes a state and a battery of typed questions, and returns calibrated structured answers. A `noul` question returns a yes/no probability, a `score` question returns a position on a scale you define, and a `choice` question returns a probability for each option you define.

For each screened tool call, the policy sends Jev a JSON state holding the tool name, its arguments and the scope from the matching [tool rule](#tool-rules), a plain description of what the agent is for:

```json
{
  "tool": { "name": "run_sql", "arguments": { "query": "DROP TABLE users;" } },
  "scope": "A customer support assistant that looks up orders and answers product questions."
}
```

If any question's answer reaches its threshold, the call is blocked with a JSON-RPC error. A `score` question with a `confidenceThreshold` blocks only when Jev's confidence also reaches it; a less confident answer is only recorded. In monitor mode, the policy only records that it would have blocked.

Use this policy alongside `mcp-acl-list` and `mcp-authz`. Those decide which tools a client may call by name and scope; this policy judges what a particular call would do. For example, `run_sql` may be allowed, but `run_sql` with `DROP TABLE users;` can still be blocked.

## Features

- Screens `tools/call` requests only; every other MCP method, notification and response passes through without calling Jev
- Tool rules set everything per tool: which tools are screened, the scope, the questions, the mode and fail-open; name one tool, or use `*` for every tool without its own rule
- Default questions covering destructive, irreversible, data-exfiltrating, secret-reading, privilege-raising, disruptive, security-weakening and out-of-scope calls; the destructive, irreversible, privilege and disruption questions don't flag effects the scope calls for
- The default questions are pre-filled in each new rule, so they can be seen and edited
- Configurable battery of typed questions (`noul`, `score`, `choice`) that can refer to `tool.name`, `tool.arguments` and `scope`
- Blocks with a JSON-RPC error that echoes the request `id` and `Mcp-Session-Id`, framed as a server-sent event when the request was sent with `Content-Type: text/event-stream`
- Rejects request bodies that can't be read unambiguously (invalid JSON, batches, duplicate or case-variant members), so a body can't be crafted to screen different arguments from the ones the MCP server runs
- `enforce` mode (blocks) or `monitor` mode (records hits without blocking, for tuning thresholds on real traffic), per rule
- Configurable Jev timeout (default `5s`) with one automatic retry when Jev is rate limited or overloaded
- Fail-closed by default on Jev API errors and timeouts; configurable to fail-open per rule
- Records Jev token usage and flagged questions in request metadata

## Configuration

The policy uses a two-level configuration: system parameters that hold your TypeSafe API credential, and per-proxy user parameters that control screening behaviour.

### System Parameters (From config.toml)

These parameters are set at the gateway level and are shared with the other TypeSafe Jev policies. Individual policy attachments can override them when needed.

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `apiKey` | string | Yes | — | TypeSafe AI API key (https://typesafe.ai). |
| `baseURL` | string (URI) | No | `https://api.typesafe.ai` | Override the Jev API base URL. For testing only. |
| `model` | string | No | `jev-latest` | Jev model identifier. |

#### Sample System Configuration

Add the following block to your `config.toml` file:

```toml
[policy_configurations.typesafe_jev_v0]
api_key = ""
base_url = "https://api.typesafe.ai"
model = "jev-latest"
```

Every TypeSafe Jev policy reads the same `[policy_configurations.typesafe_jev_v0]` block, so the key is set once for all of them.

### User Parameters (API Definition)

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `tools` | array of objects | Yes | — | Which tools to screen, and how; see [Tool rules](#tool-rules). At least one rule. |
| `timeout` | string (Go duration) | No | `5s` | Maximum time to wait for Jev, for example `"5s"` or `"1500ms"`, up to `"30s"`. Includes one retry when Jev returns `429` (rate limited) or `529` (overloaded). A timeout is handled per the matching rule's `passthroughOnError`. |
| `showAssessment` | boolean | No | `false` | When `true`, the JSON-RPC error for a blocked call includes, in `error.data`, which questions were flagged, their values, and thresholds. |

`scope`, `questions`, `mode` and `passthroughOnError` are set in each rule. At the top level they are rejected, so a setting can't be silently ignored.

#### Question object shape

| Field | Type | Required | Description |
|-------|------|----------|--------------|
| `key` | string | Yes | Unique identifier for this question, echoed in the assessment. |
| `type` | `noul` \| `score` \| `choice` | Yes | `noul` returns a calibrated 0–1 probability. `score` returns a position on `criteria`. `choice` returns a probability for each option in `criteria`. |
| `instructions` | string | Yes | The question to ask Jev. Refer to parts of the state in backticks, for example `` `tool.arguments` `` or `` `scope` ``. |
| `criteria` | array of strings | Required for `score` and `choice` | For `score`: 2–10 ordered scale descriptions, lowest first. For `choice`: 2–255 options; add an `other` option when the list might not cover every call. |
| `blockOn` | array of strings | Required for `choice` | The `criteria` options that count towards blocking. |
| `threshold` | number | Yes | For `noul`: minimum probability (0–1) to block. For `score`: minimum scale position to block. For `choice`: minimum combined probability (0–1) of the `blockOn` options to block. |
| `confidenceThreshold` | number | No (`score` only) | Minimum confidence (0–1) Jev must report for a `score` at or above `threshold` to block. A less confident answer doesn't block; it is recorded in request metadata under `typesafe-jev-mcp-tool-intent-verification:low-confidence`. |

#### Default questions

Each rule's `questions` is pre-filled with these `noul` questions, each blocking at `0.7`, so they can be seen and edited in the policy configuration. If a rule's `questions` is omitted or empty, the same questions are used.

| Key | Instructions |
|-----|--------------|
| `destructive` | Would running the tool call in `tool` destroy, overwrite, or damage data, files, or systems that cannot easily be recreated, in a way that `scope` does not call for? |
| `irreversible` | Would running the tool call in `tool` have an effect that cannot be undone, such as sending a message, moving money, or publishing something, that `scope` does not call for? |
| `exfiltration` | Would running the tool call in `tool` send secrets, credentials, or private data outside the organisation? |
| `sensitive_data` | Would running the tool call in `tool` read or reveal secrets, credentials, or payment card data? |
| `privilege` | Would running the tool call in `tool` grant or raise access rights or permissions in a way that `scope` does not call for? |
| `disruption` | Would running the tool call in `tool` stop, shut down, or take offline a running service or system in a way that `scope` does not call for? |
| `security_control` | Would running the tool call in `tool` turn off or weaken a security control, such as multi-factor authentication, a firewall, encryption, or audit logging? |
| `out_of_scope` | Is the tool call in `tool` unrelated to the purpose described in `scope`? |

The questions that mention `scope` keep the guardrail from blocking the work the agent exists to do, such as a support assistant replying to a customer or issuing a refund within its limit, while still flagging calls outside that job. This is why every tool rule needs a `scope`: without one, these questions have nothing to compare against.

#### Tool rules

The `tools` parameter chooses which tools are screened and how. Each rule names one tool, exactly as it appears in `tools/call` (`params.name`), or `*` for every tool without its own rule. MCP proxies take policies for the whole proxy, so this list is how the policy is set up per tool, as in `mcp-authz`.

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `name` | string | Yes | `*`, pre-filled | The tool name, or `*`. Each name, `*` included, can have one rule. |
| `scope` | string | Yes | — | What the agent is meant to do, in plain words; see [Writing a scope](#writing-a-scope). |
| `questions` | array of objects | No | The [default questions](#default-questions), pre-filled | The typed questions to ask Jev about this rule's tool calls; see [Question object shape](#question-object-shape). The call is blocked if any question's answer is at or above its threshold; a `score` question with a `confidenceThreshold` also needs Jev's confidence to reach it, and is otherwise only recorded. |
| `mode` | `enforce` \| `monitor` | No | `enforce`, pre-filled | `enforce` blocks when a question crosses its threshold. `monitor` never blocks; see [Monitor mode](#monitor-mode). |
| `passthroughOnError` | boolean | No | `false` | When `true`, lets this rule's calls through if the Jev API call fails or times out (fail-open). When `false`, the call is rejected with a JSON-RPC internal error (fail-closed). |

How a call is matched:

- A rule for the exact tool name wins over `*`. Only one rule applies to a call, so each screened call is one Jev request, with that rule's scope, questions, mode and `passthroughOnError`.
- A tool that no rule matches isn't screened and passes through without calling Jev. Without a `*` rule, only the listed tools are checked, and tools added to the MCP server later aren't checked until they get a rule.
- A rule doesn't inherit anything from the `*` rule. For example, a custom question added to `*` doesn't apply to a tool with its own rule; add it there too.

To screen every tool, use one `*` rule:

```yaml
params:
  tools:
    - name: "*"
      scope: "A calculator assistant that adds numbers and echoes short messages back to the user."
```

To screen every tool, but judge one of them against a different scope, or monitor it instead of blocking, add a rule for it:

```yaml
params:
  tools:
    - name: "*"
      scope: "A calculator assistant that adds numbers and echoes short messages back to the user."
    - name: orderPizza
      scope: "A pizza ordering assistant that places pizza orders for the customer."
      mode: monitor
```

To screen only some tools, leave out the `*` rule:

```yaml
params:
  tools:
    - name: orderPizza
      scope: "A pizza ordering assistant that places pizza orders for the customer."
```

Here only `orderPizza` calls are sent to Jev; every other tool call goes straight to the MCP server.

##### Writing a scope

The scope is sent to Jev as `scope`. The default `destructive`, `irreversible`, `privilege` and `disruption` questions ignore effects the scope calls for, and `out_of_scope` flags calls outside it. `exfiltration`, `sensitive_data` and `security_control` don't mention the scope, but Jev still sees it, so a job that clearly involves that data can lower their answers too: a raw card number passed to `orderPizza` was flagged under "A calculator and pizza ordering assistant…", but not under "A pizza ordering assistant that places pizza orders for the customer.".

Describe the job rather than giving instructions: "A calculator and pizza ordering assistant that adds numbers and places pizza orders" works, while "A calculator assistant; allow pizza ordering" doesn't, because Jev judges whether each call fits the job described.

#### What is screened

- **Screened:** a `POST` to the proxy's `/mcp` endpoint whose JSON-RPC `method` is `tools/call`. The policy reads `params.name` and `params.arguments` from the request body, on every MCP protocol version.
- **Passed through without calling Jev:** a `tools/call` for a tool no [tool rule](#tool-rules) matches, every other method (`initialize`, `tools/list`, `resources/read`, and so on), notifications, JSON-RPC responses sent by the client, and requests to other paths.
- **Rejected before calling Jev:** request bodies the policy can't read unambiguously, since the MCP server might read them differently. This happens before the tool rules are matched, so a body can't name one tool to the policy and another to the MCP server:

| Case | HTTP status | JSON-RPC code |
|------|-------------|---------------|
| Invalid JSON | `400` | `-32700` |
| Not a single JSON-RPC object (for example a batch array, or an event-stream body with more than one event) | `400` | `-32600` |
| Duplicate or case-variant `id`, `method`, `params`, `name` or `arguments` member | `400` | `-32600` |
| `params` missing or not an object, tool name missing, or `arguments` not an object | `400` | `-32602` |

#### Block response

A blocked call gets HTTP `400` with a JSON-RPC error, the same status and code `mcp-acl-list` uses for a denied tool:

```json
{
  "jsonrpc": "2.0",
  "id": 7,
  "error": {
    "code": -32000,
    "message": "MCP tool call blocked by guardrail"
  }
}
```

With `showAssessment: true`, `error.data` carries the details:

```json
"data": {
  "interveningGuardrail": "TypesafeJevMcpToolIntentVerification",
  "assessments": [
    { "question": "destructive", "type": "noul", "threshold": 0.7, "value": 0.98 }
  ]
}
```

When the check itself fails (a Jev error, timeout, or incomplete answer) and the policy fails closed, the call gets HTTP `503` with JSON-RPC code `-32603` and the message `MCP tool call could not be checked by guardrail`.

Every error response echoes the `Mcp-Session-Id` header, and the request `id` when the policy could read it; a body rejected as invalid JSON, not a single object, or with an ambiguous `id` gets `"id": null`. If the request was sent with `Content-Type: text/event-stream`, the error is framed as a single server-sent event.

#### Monitor mode

With `mode: monitor` on a rule, the policy never blocks that rule's calls. A call that would have been blocked is let through, the hit is recorded in analytics (`isGuardrailHit`, `guardrailName`), and the flagged questions are written to request metadata under `typesafe-jev-mcp-tool-intent-verification:assessments`. Use it to tune thresholds and wording on real traffic before enforcing.

#### Request metadata

In both modes the policy writes Jev's token usage to `typesafe-jev-mcp-tool-intent-verification:usage` as `{"input_tokens": ..., "output_tokens": ...}`, alongside any flagged questions as described above.

#### Limitations

- **The MCP proxy doesn't see the agent's conversation.** Scope is judged against the configured `scope` text, not against what the user asked for.
- **Tools without a rule aren't screened.** Without a `*` rule, a tool added to the MCP server later isn't checked until it gets a rule.
- **Jev judges what the arguments say.** Tool descriptions aren't part of a `tools/call` request, so Jev sees only the name and arguments. For example, an `echo` tool asked to repeat the text "rm -rf /" can be flagged as destructive.
- **Arguments are untrusted input.** Adversarial text inside arguments can influence Jev's answers ([jev-1.13 known weaknesses](https://docs.typesafe.ai/model-jaggedness/jev-1.13)). Keep `mcp-acl-list` and `mcp-authz` in place for rules that must always hold.
- **Latency.** Each tool call waits for one Jev request, bounded by `timeout`.
- **Size.** Jev accepts up to 32k tokens of state within 64k tokens per request ([models](https://docs.typesafe.ai/models)). A larger call fails the check and is handled per the matching rule's `passthroughOnError`.

#### Policy order

Place this policy after `mcp-spec-validation`, `mcp-auth` and `mcp-authz` in the proxy's policy list, so malformed and unauthorised requests are rejected before a Jev request is made.

#### build.yaml Integration

Inside the `api-platform` repository, add the policy package under `policies:` in `/gateway/build.yaml`:

```yaml
- name: typesafe-jev-mcp-tool-intent-verification
  gomodule: github.com/wso2/gateway-controllers/policies/typesafe-jev-mcp-tool-intent-verification@v0
```

## Reference Scenarios

### Example 1: Screen Tool Calls with the Default Questions

Attach the policy to an MCP proxy with one `*` rule, to screen every tool with the default questions:

```yaml
apiVersion: gateway.api-platform.wso2.com/v1
kind: Mcp
metadata:
  name: support-tools-v1.0
spec:
  displayName: support-tools
  version: v1.0
  context: /support-tools
  upstream:
    url: https://mcp-backend:8080/mcp
  policies:
    - name: typesafe-jev-mcp-tool-intent-verification
      version: v0
      params:
        tools:
          - name: "*"
            scope: "A customer support assistant that looks up orders and answers product questions."
```

A read-only call passes through to the MCP server:

```bash
curl -X POST http://localhost:8080/support-tools/mcp \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_order","arguments":{"order_id":"A-1042"}}}'
```

A destructive call is blocked:

```bash
curl -X POST http://localhost:8080/support-tools/mcp \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"run_sql","arguments":{"query":"DROP TABLE users;"}}}'
```

```json
{"jsonrpc":"2.0","id":2,"error":{"code":-32000,"message":"MCP tool call blocked by guardrail"}}
```

### Example 2: Custom Questions with Assessment Details

Replace the default questions with a risk scale and a destination check, and include the assessment in blocked responses:

```yaml
policies:
  - name: typesafe-jev-mcp-tool-intent-verification
    version: v0
    params:
      showAssessment: true
      tools:
        - name: "*"
          scope: "A support assistant that looks up orders and replies to customers by email."
          questions:
            - key: risk
              type: score
              instructions: "What is the worst effect running the tool call in `tool` could have?"
              criteria:
                - "Reads data only."
                - "Changes data in a way that is easy to undo."
                - "Deletes or overwrites data."
                - "Has an effect outside the system that cannot be undone."
              threshold: 2
              confidenceThreshold: 0.6
            - key: external_destination
              type: noul
              instructions: "Does `tool.arguments` send data to a URL or email address outside example.com?"
              threshold: 0.7
```

### Example 3: Monitor Before Enforcing, Fail-Open on Outage

Run the default questions in monitor mode first, and let calls through if Jev is unavailable:

```yaml
policies:
  - name: typesafe-jev-mcp-tool-intent-verification
    version: v0
    params:
      timeout: "2s"
      tools:
        - name: "*"
          scope: "A support assistant that looks up orders and replies to customers by email."
          mode: monitor
          passthroughOnError: true
```

Flagged calls are recorded in analytics and request metadata without being blocked. Once the thresholds look right on real traffic, set the rule's `mode` to `enforce`.
