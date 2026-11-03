# NVIDIA Switchyard Router

## Overview

The NVIDIA Switchyard Router policy picks the model for each request by asking NVIDIA's [Switchyard](https://github.com/NVIDIA-NeMo/Switchyard) server, and keeps the routing itself in the gateway. The server runs a **routing profile**, such as the Stage router, and places every request in one of two tiers:

- **efficient**: cheaper models for routine work, such as writing and editing with no recent errors
- **capable**: stronger models for exploration, planning, and recovering from errors

The policy owns the model pool. It maps the tier to a pooled model of that tier, chosen by `tierBalancing`, rewrites the model in the request, and selects that model's provider as the upstream. Switchyard only returns the tier. It never calls the selected model and never holds the credentials of the providers that serve requests; it runs in your own network, and no request is sent to NVIDIA. A profile with a judge is the exception to keeping content local: the judge is an LLM that the server calls with its own credentials (for example `JUDGE_API_KEY`), so the conversation content that `promptDisclosure` lets through goes to the judge's provider.

## Features

- Routes each request of an agent run on the run's recent tool results
- Keeps models in the proxy's policy configuration; the server holds only routing profiles
- Mixes providers across tiers, and spreads a tier's requests over several models by weight
- Redacts the conversation to what the profile needs before sending it to the server
- Passes session IDs, including coding agents' own session headers, so the server can keep holds per agent run, optionally derived from the conversation when clients send none
- Observe-only mode to measure a profile on real traffic before it routes anything
- Falls back to a configured model, or rejects the request, when the server fails
- Records the tier, profile, and outcome in analytics and in response headers

## How It Works

1. The policy buffers the request body and works out the request's API format from the path: `/chat/completions`, `/responses`, or `/messages`. A request on any other path goes to the fallback.
2. It redacts a copy of the conversation to the `promptDisclosure` level and POSTs it to the server's `/v1/decision` endpoint, with the request's `model` set to the configured profile. The session headers go with it (see [Sessions](#sessions)).
3. The server runs the profile and returns the selected target, `efficient` or `capable`.
4. The policy picks a model of that tier (see [Tier balancing](#tier-balancing)), writes it into the request, and selects its provider as the upstream. The gateway sends the request, unredacted, and the response carries the routing headers.

An empty body or a body that is not a JSON object passes through unchanged, and the server is not called.

### Observe-only mode

With `mode: observe_only`, the policy still asks the server, but leaves every request unchanged and never rejects one, even when the server fails. It records the tier and the model it would have chosen in analytics. Use it to see a profile's efficient/capable split on real traffic, then switch to `enforce`.

### Tier balancing

When a tier has several models, `tierBalancing` chooses which one serves each request:

| `tierBalancing` | Behavior |
|-----------------|----------|
| `first` (default) | Always the tier's first model. The others are spares. |
| `round_robin` | Rotates through the tier's models in proportion to their `weight`. |
| `session_affinity` | Keeps each session on one model of the tier, chosen in proportion to `weight`, so the provider's prompt cache stays warm across the run. Requests without a session ID rotate as with `round_robin`. |

The session is the one the server sees (see [Sessions](#sessions)). Rotation is counted per gateway instance, so across several replicas the split matches the weights on average rather than exactly. Balancing applies only to decided tiers; the fallback always uses `fallback.model`.

### Prompt disclosure

The server reads the conversation to decide, so the policy sends it only what the profile needs. Redacted turns keep their role and position, and their text is replaced by its length, such as `[redacted 240 chars]`. System prompts, instructions, tool definitions, and generation settings are never sent, except at `full`. The request sent to the provider is never redacted.

| `promptDisclosure` | Sent to the server | Use with |
|--------------------|--------------------|----------|
| `none` | Roles and sizes only. Tool results become user turns. | Profiles that read nothing, such as `random` |
| `tool_activity` | Tool calls and tool results, including their arguments and output | `stage_router` without a judge |
| `task_and_tool_activity` (default) | Tool activity, plus the opening user request and the latest user message | `stage_router` with a judge |
| `full` | The whole request | Profiles that read more, such as a classifier with `recent_turn_window` |

With `tool_activity` the judge sees only redaction markers, so judged turns go to the capable tier. With `none`, Stage sees no tool signals and every turn takes the picker default.

### Sessions

The server keeps holds per session, so it needs the same session ID on every request of an agent run. The policy forwards the headers the server recognizes, as the client sent them:

- `x-switchyard-session-id` and the other `x-switchyard-*` agent headers
- Claude Code's `x-claude-code-session-id`, `x-claude-code-agent-id`, and `x-claude-code-parent-agent-id`
- Codex's `x-codex-turn-metadata` and `x-codex-parent-thread-id`, and `x-openai-subagent`
- `x-session-id`, `session-id`, `thread-id`, `x-task-id`, the NeMo Relay and Dynamo session headers, and `user-agent`

Coding agents that send their own session headers therefore get holds without any setup, and their sub-agents keep their own history instead of sharing the parent's. A value in `sessionHeader` is sent as `x-switchyard-session-id`, which takes precedence over the others. With `sessionFromPrompt`, a request with no session ID in any of these headers gets one derived from its first user message. A request with no session ID keeps no routing history on the server.

### Response headers

Unless `responseHeaders` is `false`, the response carries:

| Header | Value |
|--------|-------|
| `x-switchyard-tier` | `efficient` or `capable`: the tier that served the request, or in observe-only mode, the tier that would have |
| `x-switchyard-outcome` | `routed`, `observed`, `fallback`, `rejected`, or `decision_failed` |
| `x-switchyard-error` | On a failure, why no decision was made, as in `switchyard_error` |

## Configuration

### User Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `modelPool` | array | Yes | - | The models the router may choose between. Each tier needs at least one model. |
| `modelPool[].provider` | string | No | - | `additionalProviders[].as` alias, or provider id when `as` is absent. Empty keeps the current upstream (normally the primary provider). |
| `modelPool[].model` | string | Yes | - | Model ID written into the routed request. |
| `modelPool[].tier` | string | Yes | - | `efficient` or `capable`. |
| `modelPool[].weight` | integer | No | `1` | Share of the tier's requests with `round_robin` or `session_affinity`, from 1 to 100. |
| `tierBalancing` | string | No | `first` | How a tier with several models chooses one: `first`, `round_robin`, or `session_affinity`. See [Tier balancing](#tier-balancing). |
| `profile` | string | Yes | - | Route id of a routing profile in the server's configuration, such as `coding-agents`. |
| `mode` | string | No | `enforce` | `enforce` routes each request. `observe_only` records the decision in analytics and leaves requests unchanged. |
| `fallback.mode` | string | No | `error` | `error` rejects the request when no decision is available. `model` routes to the fallback model. |
| `fallback.provider` | string | No | - | Provider of the fallback model. |
| `fallback.model` | string | When mode is `model` | - | The fallback model ID. Must be in `modelPool`. |
| `promptDisclosure` | string | No | `task_and_tool_activity` | How much of the conversation the server sees: `none`, `tool_activity`, `task_and_tool_activity`, or `full`. See [Prompt disclosure](#prompt-disclosure). |
| `sessionHeader` | string | No | `x-switchyard-session-id` | Request header carrying a stable session ID for the agent run. Its value is sent to the server as `x-switchyard-session-id`. Coding agents' own session headers are forwarded as well. |
| `sessionFromPrompt` | boolean | No | `false` | When a request carries no session ID in any recognized header, use a hash of the conversation's first user message as its session ID, so holds still work. Conversations that open with the same message share a session, so leave it off for agents that start sub-agents with a fixed prompt. |
| `responseHeaders` | boolean | No | `true` | Add the `x-switchyard-tier`, `x-switchyard-outcome`, and `x-switchyard-error` response headers. |

### System Parameters (From config.toml)

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `switchyardEndpoint` | string | Yes | - | Full URL of the server's decision endpoint, such as `http://switchyard-server:4000/v1/decision`. |
| `switchyardApiKey` | string | No | - | Bearer credential for a proxy in front of the server. The server itself does not authenticate callers. |
| `switchyardTimeout` | string | No | `1s` | Maximum time to wait for the server. Greater than zero and at most `10s`. For a profile with a judge, set it above the judge's timeout, for example `4s`. |

```toml
[policy_configurations.nvidia_switchyard_router_v0]
switchyard_endpoint = "http://switchyard-server:4000/v1/decision"
switchyard_api_key = ""
switchyard_timeout = "1s"
```

## Server Profiles

Profiles live in the server's TOML file and contain no real models. Each profile is a route whose targets are named `efficient` and `capable`; the policy maps those names to its own model pool. Targets use a placeholder client because the decision endpoint never calls them.

This differs from Switchyard's own examples, where targets are real models that the server calls. Here the server only decides, and the real models go in the policy's `modelPool`. Name each route's two targets `efficient` and `capable`, and give them those same ids, as in `[targets.efficient]` with `id = "efficient"`. A target with any other name, such as a model id, is reported as `invalid_decision`, and every request takes the fallback.

Two profiles cover most traffic: one for tool-using agents, decided by tool signals alone, and one for chat, where a judge decides the turns the signals cannot.

```toml
schema_version = 1

[llm_clients.unused]
format = "openai_chat"
base_url = "http://127.0.0.1:9"
max_retries = 0

[llm_clients.judge]
format = "openai_chat"
base_url = "https://api.openai.com/v1"
api_key_env = "JUDGE_API_KEY"
timeout_ms = 3000
max_retries = 0

[targets.efficient]
id = "efficient"
llm_client = "unused"

[targets.capable]
id = "capable"
llm_client = "unused"

[targets.judge]
id = "gpt-4o-mini"
llm_client = "judge"

# Tool-using agents: tool signals only, no judge.
[routes.coding-agents]
id = "coding-agents"
type = "stage_router"
efficient_target = "efficient"
capable_target = "capable"
picker = "efficient_first"
confidence_threshold = 0.3

# Chat and mixed traffic: tool signals first, then a judge for turns they
# cannot decide, including plain chat.
[routes.chat-with-judge]
id = "chat-with-judge"
type = "stage_router"
efficient_target = "efficient"
capable_target = "capable"
picker = "efficient_first"
confidence_threshold = 0.3

[routes.chat-with-judge.classifier]
target = "judge"
base_threshold = 0.5
threshold_step = 0.1
response_format_type = "json_object"
prompt = """
You forecast whether a small, fast, inexpensive language model (the efficient
model) will answer a user's request as well as a frontier model would. You see
the conversation's opening request and, when present, the latest user
follow-up.

SUCCESS means the efficient model's answer would be correct, complete, and as
useful to this user as a frontier model's answer. FAILURE means a frontier
model would give a noticeably better answer. Judge the request itself; do not
assume extra context, tools, or files that are not shown.

Steps:
1. State the crux: the single hardest thing the request needs done well.
2. Pick the one rule below that best describes that crux. Use primary_rule
   "none" and capability_boundary "unmatched" when no rule fits. The rule ids
   are labels only.
3. Estimate p_solve last: the probability, from 0.00 to 1.00, that the
   efficient model succeeds. Use the full range; reserve 0.00 and 1.00 for
   certain outcomes.

Rules:
- SUP-1 [supported]: Greetings, small talk, and short factual or definitional
  questions answerable from common knowledge.
- SUP-2 [supported]: Rewriting, summarizing, translating, extracting, or
  reformatting text that the user provides.
- SUP-3 [supported]: A small, well-specified piece of code: one function or a
  short script with clear inputs and outputs, or an explanation of short code.
- SUP-4 [supported]: Arithmetic or reasoning that takes only a few clear steps.
- SUP-5 [supported]: Everyday how-to, advice, or recommendations that do not
  need specialist judgment.
- UNC-1 [uncertain]: Open-ended writing or analysis of moderate length where
  quality depends on judgment and the request leaves important choices open.
- UNC-2 [uncertain]: A request with several moderate parts that all have to be
  done correctly.
- LIM-1 [unsupported]: Deep multi-step reasoning: proofs, hard mathematics,
  algorithm design, system architecture with trade-offs, or diagnosing a
  non-trivial failure.
- LIM-2 [unsupported]: Large or interdependent code, or expert analysis in law,
  medicine, finance, or security where subtle errors matter.

Return exactly one JSON object with the fields crux, primary_rule,
capability_boundary, and p_solve, and nothing else.
"""
```

### Choosing settings

- **Threshold.** In Switchyard 0.3.0, clean writes alone score about 0.46 and repeated failures override to the capable tier. A `confidence_threshold` of `0.3` lets clean production move a turn to the efficient tier on its own; at `0.5` it needs a second signal, and with a judge configured the undecided turn goes to the judge.
- **Tool names.** The built-in vocabulary covers common coding-agent tools such as `read_file`, `write_file`, and `bash`. Map other tools with `tool_semantics`; tools that are neither built in nor mapped give Stage no signal, and the turn takes the picker default or the judge.
- **Judge prompt.** Switchyard's packaged judge prompt forecasts coding-agent task success against a verifier, which fits chat poorly. For chat traffic, replace it with `classifier.prompt`. The verdict schema is fixed: the prompt must return `crux`, `primary_rule` (one of `SUP-1`…`SUP-5`, `UNC-1`, `UNC-2`, `LIM-1`, `LIM-2`, or `none`), `capability_boundary` (`supported`, `uncertain`, `unsupported`, or `unmatched`), and `p_solve`. The rule ids are labels; the prompt defines what each means. The turn goes to the efficient tier when `p_solve` reaches `base_threshold`, raised by `threshold_step` once for uncertain or unmatched verdicts and twice for unsupported ones.
- **Judge model.** Use a small, fast model that supports JSON output, on its own key or quota. Prefer a judge profile built on `stage_router` with a classifier over `llm_classifier`, which consults the judge on every request and gave less consistent verdicts in testing.
- **Prompt disclosure.** Pair `coding-agents` with `promptDisclosure: tool_activity`, and `chat-with-judge` with the default `task_and_tool_activity`. In testing on switchyard-server 0.3.0, both gave the same decisions as `full` in all three API formats.
- **Timeout without a judge.** A signal-only decision takes a few milliseconds, but the first call on a new connection includes a DNS lookup, which can take over 100 ms inside a container. Keep the timeout at `1s` or more; a shorter one sends those requests to the fallback, recorded as `switchyard_error: timeout`.
- **Timeout.** A judged decision takes one to three seconds. Set the judge client's `timeout_ms` to about `3000` and the policy's `switchyardTimeout` above it, for example `4s`. With the 1 s default, judged requests can time out and take the fallback, recorded as `switchyard_error: timeout`.
- **Azure OpenAI as the judge.** Use the resource's OpenAI-compatible v1 endpoint, `https://<resource>.openai.azure.com/openai/v1`, with the deployment name as the target `id`. The classic `/openai/deployments/...?api-version=` URLs are not supported by Switchyard's client.

In 0.3.0, built-in tool names cannot be remapped in `tool_semantics`, `capable_hold_turns` cannot be negative, and a failed judge call fails the decision, so the policy uses its fallback.

## Setting Up the Server

The policy needs `switchyard-server` 0.3.0, which you run yourself, next to the gateway. NVIDIA publishes it as source only: there is no prebuilt binary or container image. Use 0.3.0 exactly; the policy is tested against that release, and later versions, including the 0.4.0 pre-releases, change the server's configuration.

NVIDIA describes the standalone `switchyard-server` 0.3.0 as a demo and evaluation component, not for production use, validated on Ubuntu 24.04 on x86_64. Evaluate it with `mode: observe_only` and review the decisions before routing traffic with it.

### 1. Install the server

**As a container image** (for Docker Compose or Kubernetes). Build it from the release tag with the Dockerfile in NVIDIA's repository. The image installs CA certificates, runs as user 1000, and listens on port 4000:

```bash
git clone --depth 1 --branch v0.3.0 https://github.com/NVIDIA-NeMo/Switchyard.git
docker build -t switchyard-server:0.3.0 Switchyard
```

The build takes a few minutes and needs no local Rust toolchain. Push the image to your own registry if the gateway runs elsewhere. x86_64 builds need a CPU with AVX2 (`x86-64-v3`, 2013 or later); ARM builds target Graviton 2 or Ampere Altra and later.

**As a binary** (for a VM). With Rust 1.96 or later installed:

```bash
cargo install --locked switchyard-server --version 0.3.0
```

### 2. Write the configuration

Save the [Server Profiles](#server-profiles) TOML as `switchyard.toml`, keeping the profiles you use. Each proxy's `profile` parameter must name one of its routes.

The server checks every LLM client at startup. If the file keeps the judge client, `JUDGE_API_KEY` must be set, or the server exits with `could not read api_key_env JUDGE_API_KEY`. Without a judge, remove `[llm_clients.judge]`, `[targets.judge]`, and the `chat-with-judge` route.

### 3. Run it next to the gateway

Keep the server on an internal network. It does not authenticate callers, and it also serves Switchyard's proxy endpoints, which fail against the placeholder targets. Publish no ports.

**Docker Compose.** Next to the gateway's `docker-compose.yaml`, create a `switchyard` folder holding `switchyard.toml` and a `switchyard.env` file with the judge key:

```bash
JUDGE_API_KEY=<judge key>
```

Then save this as `docker-compose.switchyard.yaml`. Without a judge, leave out `env_file` and `switchyard.env`.

```yaml
services:
  switchyard-server:
    image: switchyard-server:0.3.0
    command: ["--config", "/etc/switchyard/switchyard.toml"]
    env_file:
      - ./switchyard/switchyard.env
    volumes:
      - ./switchyard/switchyard.toml:/etc/switchyard/switchyard.toml:ro
    networks:
      - gateway-network
    restart: unless-stopped
```

Start the gateway with both files, and pass both to later commands such as `down`:

```bash
docker compose -f docker-compose.yaml -f docker-compose.switchyard.yaml up -d
```

**Kubernetes.** Run a single replica, since session holds live in the server's memory, and expose it through a ClusterIP Service in the gateway's namespace:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: switchyard-config
data:
  switchyard.toml: |
    # contents of switchyard.toml
---
apiVersion: v1
kind: Secret
metadata:
  name: switchyard-judge
stringData:
  JUDGE_API_KEY: <judge key>
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: switchyard-server
spec:
  replicas: 1
  selector:
    matchLabels:
      app: switchyard-server
  template:
    metadata:
      labels:
        app: switchyard-server
    spec:
      containers:
        - name: switchyard-server
          image: <your-registry>/switchyard-server:0.3.0
          args: ["--config", "/etc/switchyard/switchyard.toml"]
          ports:
            - containerPort: 4000
          envFrom:
            - secretRef:
                name: switchyard-judge
          volumeMounts:
            - name: config
              mountPath: /etc/switchyard
              readOnly: true
          readinessProbe:
            httpGet:
              path: /health
              port: 4000
          livenessProbe:
            httpGet:
              path: /health
              port: 4000
      volumes:
        - name: config
          configMap:
            name: switchyard-config
---
apiVersion: v1
kind: Service
metadata:
  name: switchyard-server
spec:
  type: ClusterIP
  selector:
    app: switchyard-server
  ports:
    - port: 4000
      targetPort: 4000
```

Restrict access to the gateway's pods with a NetworkPolicy where the cluster enforces them. Without a judge, drop the Secret and `envFrom`.

### 4. Point the gateway at the server

Set the decision endpoint in the gateway's `config.toml` and restart the gateway:

```toml
[policy_configurations.nvidia_switchyard_router_v0]
switchyard_endpoint = "http://switchyard-server:4000/v1/decision"
switchyard_timeout = "4s"   # with a judge; the 1s default suits signal-only profiles
```

### 5. Check the server

Send a decision request from a container on the gateway's network. Find the network's full name with `docker network ls`; Compose prefixes it with the project name:

```bash
docker run --rm --network <project>_gateway-network curlimages/curl:8.11.1 -s \
  http://switchyard-server:4000/v1/decision \
  -H 'Content-Type: application/json' \
  -d '{"input_format":"openai_chat","request":{"model":"coding-agents","messages":[{"role":"user","content":"Read the README."},{"role":"assistant","content":null,"tool_calls":[{"id":"c1","type":"function","function":{"name":"read_file","arguments":"{\"path\":\"README.md\"}"}}]},{"role":"tool","tool_call_id":"c1","content":"# Project"}]}}'
```

A working server returns `200` with `"selected":{"target":"efficient", ...}`. A `404` with `model_not_found` means the profile is not in `switchyard.toml`. A `401` from a judge profile means the judge key is wrong. `GET /health` returns `{"status":"ok"}`, and `GET /metrics` serves Prometheus metrics, including decisions per tier.

Stage escalates on evidence: an agent that is reading or writing cleanly stays on the efficient tier, and repeated failures without progress move it to the capable tier. A single failed command, or failures mixed with steady file writes, usually does not.

### Operating the server

- The server reads its TOML only at startup. Adding or changing a profile needs a restart, which clears all session holds. Changing models in a proxy's policy needs no server change.
- Holds are kept in server memory per session. Run one server, or route by session ID when you run several.
- If you build your own image instead of NVIDIA's Dockerfile, install CA certificates in it, or calls to an HTTPS judge fail.

## Examples

```yaml
operationPolicies:
  - name: nvidia-switchyard-router
    version: v0
    paths:
      - path: /chat/completions
        methods: [POST]
        params:
          profile: coding-agents
          promptDisclosure: tool_activity
          modelPool:
            - { provider: openai-provider, model: gpt-4o-mini, tier: efficient }
            - { provider: openai-provider, model: gpt-4o, tier: capable }
          fallback:
            mode: model
            provider: openai-provider
            model: gpt-4o-mini
```

The policy changes only the model and the upstream provider; it does not translate the request or the response. A pooled model on a provider with a different API format, such as an Anthropic provider behind an OpenAI chat proxy, needs that provider's transformer, for example [`openai-to-anthropic-transformer`](../../../openai-to-anthropic-transformer/v0.9/docs/openai-to-anthropic-transformer.md).

## Errors

Errors use the gateway's JSON error shape `{"error": "...", "code": "..."}`.

| Status | `code` | When |
|--------|--------|------|
| 503 | `nvidia_switchyard_router_decision_failed` | The server failed, timed out, has no route for the profile, or selected a target other than `efficient` or `capable`, and fallback is `error`. |
| 500 | `nvidia_switchyard_router_routing_failed` | The routed request could not be written. |

A profile the server does not know, and a decision that times out, are logged as warnings. Invalid configuration, such as a tier with no models, a duplicate pool entry, or a fallback outside the pool, fails the deployment instead of failing requests.

## Analytics

| Key | Value |
|-----|-------|
| `switchyard_tier` | `efficient` or `capable` |
| `switchyard_profile` | The configured profile |
| `switchyard_outcome` | `routed` when the decided model served the request, `observed` when an observe-only request had a decision, `fallback` when the fallback model was used, `rejected` when the request was rejected, `decision_failed` in observe-only mode when no decision was made |
| `switchyard_error` | Why no decision was made: `timeout`, `unavailable`, `profile_not_found`, `invalid_decision`, `unknown_format`, or `invalid_request` |
| `switchyard_mode` | `observe_only` when the request was only observed |
| `switchyard_observed_model` / `switchyard_observed_provider` | Observe-only mode: the model and provider the request would have been routed to |
