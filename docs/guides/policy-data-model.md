# Gateway Policy Data Model: Immutable Context, Mutable Actions, and Existing Conventions

## Purpose and audience

This guide is for anyone writing a gateway policy — a WSO2 engineer adding a policy to this repository, or a partner/customer building a custom policy via the `ap` CLI custom-policy flow. It answers two questions a policy author needs before writing a single line:

1. **What data can my policy read, and which parts of it can I actually change?** The SDK draws a real, enforced line between data that is fixed for the life of a request (kernel-owned facts, pre-mutation snapshots) and data a policy changes by returning an `Action` value. Confusing the two is the most common source of a new policy silently doing nothing.
2. **What does the gateway, or a sibling policy, already put there?** Roughly 55 policies already ship in this repository. Many of them read or write the same handful of header names and `SharedContext.Metadata` keys to coordinate with each other. A new policy should reuse those conventions, not invent a parallel one.

This is a companion to the per-policy documentation under `docs/<policy-name>/`, not a replacement for it — it explains the shared mechanism those policies are all built on.

**Source of truth:** every type discussed here is defined in the policy SDK, `github.com/wso2/api-platform/sdk/core/policy/v1alpha2` (Go package `policyv1alpha2`), which lives in the separate `api-platform` repository at `sdk/core/policy/v1alpha2/`. This repository (`gateway-controllers`) only consumes that SDK. If something here looks stale, the SDK source is the tiebreaker — this document was last verified against SDK `v0.4.12` (the version pinned by several policies' `go.mod` files at the time of writing; check `go.mod` in `policies/<any-policy>/go.mod` for the current pin, since versions drift between the two repos independently).

---

## 1. The six processing phases

A policy chain runs in up to six phases per request. A policy declares which phases it participates in by implementing the corresponding sub-interface (see `interface.go`) and by returning a `ProcessingMode` from `Mode()`.

| Phase | Context type | Body available? | Buffering | Declared via |
|---|---|---|---|---|
| Request headers | `RequestHeaderContext` | No — body not yet read | n/a | `RequestHeaderPolicy.OnRequestHeaders` |
| Request body (buffered) | `RequestContext` | Yes, fully buffered | `BodyModeBuffer` | `RequestPolicy.OnRequestBody` |
| Request body (streaming) | `RequestStreamContext` + `StreamBody` per chunk | One chunk at a time | `BodyModeStream` | `StreamingRequestPolicy.OnRequestBodyChunk` |
| Response headers | `ResponseHeaderContext` | No — body not yet read | n/a | `ResponseHeaderPolicy.OnResponseHeaders` |
| Response body (buffered) | `ResponseContext` | Yes, fully buffered | `BodyModeBuffer` | `ResponsePolicy.OnResponseBody` |
| Response body (streaming) | `ResponseStreamContext` + `StreamBody` per chunk | One chunk at a time | `BodyModeStream` | `StreamingResponsePolicy.OnResponseBodyChunk` |

A few mechanics worth knowing up front:

- The kernel runs **every** policy's header phase in the chain before **any** policy's body phase runs, for both request and response. This matters for what "immutable" means below.
- If any policy in the chain implements `RequestPolicy`/`ResponsePolicy` (buffered), the whole chain buffers that body — a streaming policy embeds the buffered interface as its fallback for exactly this reason.
- `ImmediateResponse` is available to short-circuit at the header or buffered-body phase, but **not** in the streaming chunk phases, because by the time chunks flow, headers and status are already committed to the wire (see §4.3).

## 2. Context types per phase

Every phase context embeds `*SharedContext`, so `ctx.RequestID`, `ctx.Metadata`, `ctx.AuthContext`, etc. are reachable directly off any of the six context types shown above (Go's embedded-struct field promotion). The non-shared fields differ per phase:

| Context type | Own fields (beyond `*SharedContext`) |
|---|---|
| `RequestHeaderContext` | `Headers, Path, Method, Authority, Scheme, Vhost, Downstream, Upstream *UpstreamRequestContext` |
| `RequestContext` | same as above + `Body *Body` (+ deprecated `UpstreamInfo`) |
| `RequestStreamContext` | same shape as `RequestHeaderContext` (chunks arrive via the `StreamBody` argument, not on the context) |
| `ResponseHeaderContext` | `RequestHeaders, RequestBody, RequestPath, RequestMethod` (echoes of the request), `ResponseHeaders, ResponseStatus, Downstream, Upstream *UpstreamResponseContext` |
| `ResponseContext` | same as above + `ResponseBody *Body` |
| `ResponseStreamContext` | same shape as `ResponseHeaderContext` (chunks arrive via `StreamBody`) |

## 3. Immutable / kernel-owned data

Nothing in this section has a policy-facing setter. A policy can only read it.

### 3.1 Identity and routing facts, fixed before the chain runs

On `SharedContext`: `ProjectID`, `RequestID` (kernel-generated, for correlation), `APIId`, `APIName`, `APIVersion`, `APIKind`, `APIContext`, `OperationPath`.

`ResolvedOperation` is the canonical protocol operation a request resolved to, for API kinds where the operation can't be read off the route itself — an A2A JSON-RPC endpoint serves eleven different operations at one path, so `OperationPath` alone can't tell them apart. It's written once, before any policy in the chain runs. **Empty string means "not applicable," not "failed to resolve"** — every API kind that shipped before Agent support leaves it empty, so treat `""` accordingly rather than erroring on it.

### 3.2 `ResolutionAttributes`

Protocol-derived facts the route's resolver captured in the same pass that identified the operation (e.g. an A2A message's `a2a.context.id`, `a2a.task.id`). They exist so a multiplexed-transport body is parsed once instead of every consumer re-parsing the same bytes, and they're the only way a body-sourced value reaches a *request-header-phase* policy, since `RequestHeaderContext` has no body of its own.

Read-only access only: `Get(name) string`, `Lookup(name) (string, bool)`, `Len() int`, `Iterate(fn)`. There is deliberately no setter — the type's own doc comment explains why: a route whose resolution is fixed at deploy time builds its attributes once and shares them across every request on that route, so a policy writing into them would leak one request's data into the next request, silently, with no error and no way to distinguish it from a correlation bug downstream.

**Trust boundary:** these values come out of the request body and are attacker-controlled in the general case (bounded in count/length by the engine before they reach a policy, but not otherwise validated). Don't use one as a cache key or a rate-limit key without validating it first — a bounded protocol fact and an unbounded caller-supplied identifier can sit side by side here.

### 3.3 Downstream / Upstream snapshots

`Downstream.Request` (`*DownstreamRequest{Headers, Path, Method, Authority, Scheme}`) and `Upstream.Response` (`*UpstreamResponse{Headers, StatusCode}`, response phase only) capture the request **as the client actually sent it** and the response **as the upstream actually returned it**, frozen before any policy's mutation is applied.

Why this exists: because every policy's header phase runs before any policy's body phase, the *live* `ctx.Headers`/`ctx.ResponseHeaders` are one shared, kernel-mutated set — a later policy reading them can observe an earlier policy's rewrite, regardless of the declared chain order. For anything security-sensitive (an authentication decision, an authorization gate), that's the wrong thing to read: it can be fooled by an earlier policy that legitimately rewrote a header for its own purposes. The snapshot is immune to that, by construction.

Use the accessor methods, not the raw fields, on every context type: `DownstreamRequest()`/`DownstreamHeaders()` (all six context types) and `UpstreamResponse()`/`UpstreamHeaders()` (response-phase types only). Each returns the snapshot when the gateway provides one, falling back to the live working values only on a gateway build that predates the snapshot feature — see `context_accessors.go`. **Prefer the snapshot accessor over the live field for any authentication, authorization, or gating decision.**

There is a **chain-internal-only** way to mutate this snapshot object — `SetDownstreamHeader`/`AddDownstreamHeader`/`RemoveDownstreamHeader` and their `Upstream` counterparts, from `context_header_writers.go`. Don't confuse this with changing what goes out on the wire: see the callout in §4.2, because getting this backwards is the single easiest mistake to make with this SDK.

### 3.4 `Headers` — read-only surface

`ctx.Headers`, `ctx.ResponseHeaders`, `Downstream.Request.Headers`, `Upstream.Response.Headers` are all `*Headers`, a type that exposes only `Get(name) []string`, `Has(name) bool`, `GetAll() map[string][]string`, and `Iterate(fn)` — every one of these returns a **defensive copy**. There is no public mutator. `UnsafeInternalValues()` exists on the type, but its doc comment is explicit: "Policies MUST NEVER call this method" — it's reserved for the kernel's own executor/translator code. A policy that wants to change a header returns an `Action` (§4); it never reaches into `Headers` directly.

### 3.5 A policy's own configuration

Every `On*` method also receives `params map[string]interface{}` — the policy's own user parameters (from the API definition) merged with system parameters (from the gateway's `config.toml`), already validated against the policy's parameter schema at configuration time. This is fixed for the life of the request and is a completely separate concept from the per-request context above — don't confuse "my policy's own config" with "data about this request."

---

## 4. Mutable data, and how mutation actually reaches the wire

### 4.1 Action return types are the *only* channel to Envoy, upstream, or the client

A policy cannot mutate its context struct to change what goes out — instead, each phase method returns a value implementing a sealed "action" interface, and the kernel applies it. Only these four shapes exist per non-streaming phase:

| Phase | Continue-normally type | Short-circuit type |
|---|---|---|
| `OnRequestHeaders` | `UpstreamRequestHeaderModifications` | `ImmediateResponse` |
| `OnRequestBody` | `UpstreamRequestModifications` | `ImmediateResponse` |
| `OnResponseHeaders` | `DownstreamResponseHeaderModifications` | `ImmediateResponse` |
| `OnResponseBody` | `DownstreamResponseModifications` | `ImmediateResponse` (replaces the *entire* response) |

Each "continue" type carries `HeadersToSet` (overwrite, last write wins), `HeadersToAppend` (preserve existing values, add more), and `HeadersToRemove` (case-insensitive, by name). The two request-phase types additionally carry routing mutations, valid because routing doesn't need the body: `UpstreamName` (route to a named upstream), `UpstreamSlot` (`main`/`sandbox`), `Path`, `Host` (rewrites `:authority`), `Method`, `QueryParametersToAdd`/`QueryParametersToRemove`. The body-phase types (`UpstreamRequestModifications`, `DownstreamResponseModifications`) additionally carry `Body []byte`, and `DownstreamResponseModifications` also carries `StatusCode *int`.

### 4.2 The easiest mistake: snapshot writers are not wire mutations

`context_header_writers.go`'s `SetDownstreamHeader`/`AddDownstreamHeader`/`RemoveDownstreamHeader` (and the `Upstream` equivalents) mutate the in-memory snapshot object described in §3.3 — nothing more. They exist so an **earlier policy in the same chain** can leave a value for a **later policy in the same chain** to read via `DownstreamHeaders()`/`UpstreamHeaders()` — for example, an earlier policy deriving a value that a later JWT/auth policy should validate against the client-request snapshot.

> **They never translate into an Envoy header mutation.** Calling `SetDownstreamHeader("x-foo", "bar")` does **not** add `x-foo` to what the client receives, and `SetUpstreamHeader` does **not** add anything to what the backend receives. To actually change what the client or upstream sees, return the corresponding field on an `Action` value from §4.1. If the gateway build doesn't populate a snapshot at all (a pre-snapshot-feature gateway), these setters are silent no-ops — don't rely on the write actually landing anywhere without a snapshot-capable gateway.

### 4.3 Streaming actions

`ForwardRequestChunk{Body}`, `ForwardResponseChunk{Body}`, and `TerminateResponseChunk{Body}` operate on one `StreamBody` chunk at a time; `Body: nil` passes the chunk through unchanged, a non-nil `[]byte` replaces it. `ImmediateResponse` is not available here — by the time chunks are flowing, request headers are already committed upstream and response headers/status are already committed to the client, so there's nothing left to intercept with a fresh HTTP response. `TerminateResponseChunk` is the correct way to end a response stream early (e.g. a guardrail intervening mid-SSE-stream): set `Body` to a final SSE event (an error frame, or `[DONE]`) and return it — the stream then closes cleanly after that chunk, since no HTTP-level error status can be layered on top of an already-committed response.

### 4.4 Body mutation semantics

Consistent across every action that carries a `Body []byte` field: `nil` means passthrough (don't touch the body), an empty-but-non-nil `[]byte{}` means explicitly clear it. This distinction matters — a policy that wants to strip a body must return `[]byte{}`, not `nil`.

---

## 5. `SharedContext.Metadata` — the inter-policy scratch space

`SharedContext.Metadata map[string]interface{}` is the one piece of per-request state that's genuinely, freely mutable by any policy: read and write it directly, no accessor, no Action needed. It persists from the request phase through the response phase of the *same* request (not across requests), which makes it the standard way for one policy to compute something and hand it to a later policy in the chain without a header round-trip.

### 5.1 Conventions observed in shipped policies

- **Plain exported constants** for a value any sibling policy might read: e.g. `MetadataKeySelectedModel = "model_roundrobin.selected_model"`.
- **Per-instance-namespaced keys**, via a small helper, when more than one instance of the *same* policy can run in one chain and each instance's data must not collide — e.g. `advanced-ratelimit`'s `func (p *RateLimitPolicy) metaKey(base string) string { return base + ":" + p.instanceID }` (falls back to the bare `base` if no instance ID is configured), and `llm-cost-based-ratelimit`'s `delegateMetadataKey`/`costScaleFactorMetadataKey`, which pick between two constants depending on a `consumerBased` config flag so a "backend" instance and a "consumer" instance in the same chain don't overwrite each other.
- Values are read back with a type assertion (`v, ok := reqCtx.Metadata[key].(string)`), since the map is `map[string]interface{}` with no enforced schema — always check `ok` rather than assuming the type.
- A handful of policies reuse the same literal string as both a `Metadata` key and a header name they also happen to be associated with (see the gotcha in §5.2's application-identity row and §7's note). That's a coincidence of naming, not a mechanism — a `Metadata` key and an HTTP header are unrelated maps; nothing about matching the strings makes one become the other.

### 5.2 Catalog of keys already in use

Exact literal key/constant values, so this is copy-pasteable — grep the listed file to confirm before reusing.

**Auth → billing / cache**

| Key (literal) | Constant | Written by (phase) | Read by |
|---|---|---|---|
| `x-wso2-application-id` | `applicationIDMetadataKey` (`api-key-auth/apikey.go`) | api-key-auth, request header phase | `semantic-cache`, `subscription-validation`, `token-based-ratelimit`, `llm-cost-based-ratelimit` (own local constants of the same name/value in each file) |

> **Gotcha:** despite the header-shaped name, `x-wso2-application-id`/`x-wso2-application-name` are **not** set as actual outbound HTTP headers by any shipped policy today — they exist purely as `Metadata` keys. If you need the application identity as a real header on the upstream request, you have to set it yourself via `HeadersToSet`; don't assume it's already on the wire because the key looks like a header name.

**Subscription/billing decision** (`subscription-validation/subscriptionvalidation.go`, written in `writeSubscriptionMetadata`, request header phase — no known reader among shipped policies yet, available for a custom policy, e.g. a header-forwarding or `backend-jwt` claim-mapping policy, to pick up):

| Key (literal) | Constant |
|---|---|
| `x-wso2-billing-customer-id` | `billingCustomerIDMetadataKey` |
| `x-wso2-billing-subscription-id` | `billingSubscriptionIDMetadataKey` |
| `x-wso2-subscription-status` | `subscriptionStatusMetadataKey` |
| `x-wso2-subscription-plan-name` | `subscriptionPlanNameMetadataKey` |

Same gotcha as above applies — these are `Metadata`-only, not headers, in the current codebase.

**Model routing → transformers**

| Key (literal) | Constant | Written by | Read by |
|---|---|---|---|
| `model_roundrobin.selected_model` | `MetadataKeySelectedModel` | `model-round-robin` / `model-weighted-round-robin` (own local constant per file) | same policy, own response phase (to record the choice for analytics) |
| `model_roundrobin.original_model` | `MetadataKeyOriginalModel` | same | same |
| `model_roundrobin.headers_processed` | `MetadataKeyHeadersProcessed` | same | same |
| `selected_provider` | `MetadataKeyProviderRouting` (writer, `model-round-robin`/`model-weighted-round-robin`) / `MetadataKeySelectedProvider` (reader, `openai-to-bedrock-transformer`, `openai-to-azure-openai-transformer`) | model-round-robin / model-weighted-round-robin, request header phase | `openai-to-*-transformer` family — this is the actual cross-policy bridge key; the two sides use *different* constant names for the same literal string, so match on the string `"selected_provider"`, not the constant name, when wiring a new consumer |
| `openai_to_bedrock_effective_model` | `MetadataKeyEffectiveModel` | `openai-to-bedrock-transformer` | same policy (own response phase) |

**MCP method/capability, resolved once and shared across the family** (parsed from the JSON-RPC body once, since MCP multiplexes every operation through one path — the same rationale as `ResolutionAttributes` in §3.2, but expressed as ordinary `Metadata` here rather than the engine-level mechanism):

| Key (literal) | Constant(s) used | Policies |
|---|---|---|
| `mcp.method` | `MetadataMcpMethod` (`mcp-authz`), `metadataMcpMethod` (`mcp-ratelimit`) | written request phase, read by the same policy's response phase |
| `mcp.type` | `MetadataMcpCapabilityType` (`mcp-authz`), `metadataMcpCapabilityType` (`mcp-ratelimit`) | " |
| `mcp.name` | `MetadataMcpCapabilityName` (`mcp-authz`), `metadataMcpCapabilityName` (`mcp-ratelimit`) | " |
| `mcp.capabilityType` | `metadataMcpCapabilityType` (`mcp-acl-list`, `mcp-rewrite`) | note this is a **different literal string** (`mcp.capabilityType` vs `mcp.type`) from the `mcp-authz`/`mcp-ratelimit` pair above despite the similar constant name — the MCP-family keys are not fully unified today; check the literal string, not just the constant name, before assuming two policies share a key |
| `mcp.action` | `metadataMcpAction` (`mcp-acl-list`, `mcp-rewrite`) | " |
| `auth.success` | `MetadataKeyAuthSuccess` (`mcp-auth`) | mcp-auth, request phase |
| `auth.method` | `MetadataKeyAuthMethod` (`mcp-auth`) | mcp-auth, request phase |

**Streamed-body accumulation** (identical idiom repeated in every content guardrail, because `StreamBody` only ever delivers one chunk at a time — each policy accumulates into its own namespaced key rather than sharing one):

| Policy | Keys (literal) |
|---|---|
| `content-length-guardrail` | `contentlengthguardrail:json_body` |
| `regex-guardrail` | `regexguardrail:accumulated_response_content`, `regexguardrail:json_body` |
| `sentence-count-guardrail` | `sentencecountguardrail:accumulated_content`, `sentencecountguardrail:json_body` |
| `word-count-guardrail` | `wordcountguardrail:accumulated_content`, `wordcountguardrail:json_body` |
| `url-guardrail` | `urlguardrail:json_body` |

**Cost/usage handoff**

| Key (literal) | Constant | Written by | Read by |
|---|---|---|---|
| `x-llm-cost` | `MetadataLLMCost` (`llm-cost`) | `llm-cost`, response phase (also has a `llm-cost:stream-accum` internal accumulation key for streaming) | `llm-cost-based-ratelimit`, `token-based-ratelimit` (via their own `MetadataKeyProviderName` lookup logic, not a direct read of this exact key today — see note below) |
| `x-llm-cost-status` | `MetadataLLMCostStatus` (`llm-cost`) | same | disambiguates a `0` cost value (failed calculation) from a genuine zero-cost response |
| `provider_name` | `MetadataKeyProviderName` (own local constant in both `llm-cost-based-ratelimit` and `token-based-ratelimit`) | set earlier in the chain (by a model-selection or provider-detection policy) | both ratelimit policies, to scope their quota bucket per provider |

> **Gotcha, mirroring the one in the billing table:** `x-llm-cost`/`x-llm-cost-status` are **not** emitted as response headers by `llm-cost` — confirmed by reading its `OnResponseBody`, which returns `DownstreamResponseModifications{}` with no `HeadersToSet`. They're `Metadata`-only. If you need the cost as a client-visible header, you have to add that yourself.

**Embedding handoff:** `semantic-cache`'s `semantic_cache_embedding` (`MetadataKeyEmbedding`) — request-phase computed embedding, read back at response phase to populate the cache entry.

**PII handoff:** `pii-masking-regex`'s `piimaskingregex:pii_entities` (`MetadataKeyPIIEntities`) — request phase → response phase.

**CORS decision handoff:** `cors`'s `cors_headers` (`map[string]string`, plain string key, no exported constant) and `cors_strip` (`bool`) — computed at request-header phase, read at response-header phase to emit the right `Access-Control-*` headers on the actual response.

**Interceptor context:** `interceptor-service`'s configurable key `interceptor-service:context` (`sharedContextKey`) — carries the external interceptor call's returned context map from request phase into response phase.

**Rate-limit internals:** `advanced-ratelimit`'s namespaced (via `metaKey`) `ratelimit:result`, `ratelimit:keys`, `ratelimit:header_handled`, `ratelimit:stream_state` — request-phase computation consumed by the same policy's own response phase; not intended for cross-policy use.

### 5.3 Before adding a new key

Check the tables above for something that already does what you need — an accidental near-duplicate key (like the `mcp.type` vs `mcp.capabilityType` split above) is exactly the kind of drift this document exists to prevent. If you're adding a new key: use a plain exported constant if any sibling policy might read it; namespace it (like `advanced-ratelimit`'s `metaKey` pattern) if more than one instance of *your* policy can run in the same chain.

---

## 6. `AuthContext` — progressive replacement, not in-place mutation

### 6.1 The pattern

`SharedContext.AuthContext *AuthContext` is `nil` until the first authentication policy in the chain runs. Every auth policy that succeeds **replaces the pointer** with a brand-new value, chaining the old one via `Previous`:

```go
shared.AuthContext = &policy.AuthContext{
    Authenticated: true,
    AuthType:      "jwt",
    Subject:       subject,
    // ...
    Previous: shared.AuthContext, // nil, or the prior layer's AuthContext
}
```

Confirmed in `jwt-auth/jwtauth.go` (`shared.AuthContext = &policy.AuthContext{...}`), `api-key-auth/apikey.go`, and `basic-auth/basicauth.go` — all three follow this exact shape. A policy that only cares about "the current, most-recently-established identity" reads `shared.AuthContext` directly; one that needs to see every layer of a multi-layer auth chain (e.g. an API-key layer stacked on a JWT layer) walks `Previous`.

### 6.2 Field reference

`Authenticated bool`, `Authorized bool` (set by authorization policies like `mcp-authz`; always false for authentication-only policies), `AuthType string` (`"jwt"`, `"basic"`, `"apikey"`, or MCP's `"mcp/oauth"`/`"mcp/oauth+authz"`), `Subject string`, `Issuer string`, `Audience []string`, `Scopes map[string]bool`, `CredentialID string` (opaque — an API key application ID, an OAuth `client_id`), `Properties map[string]string` (flattened custom claims), `TypedProperties map[string]interface{}` (same, but structure-preserving for array/object claims), `TokenId string` (e.g. JWT `jti`), `Previous *AuthContext`.

### 6.3 Canonical consumer: `backend-jwt`

`backend-jwt` (`policies/backend-jwt/backendjwt.go`) is designed to run *after* an authentication policy. It reads `reqCtx.SharedContext.AuthContext` — immutable, from its point of view; it was produced by an earlier policy — builds a brand-new signed JWT from those claims, and injects it as a genuinely new outbound header via `HeadersToSet` (default header name `x-jwt-assertion`, configurable via the `header` parameter). This is the clearest example in the codebase of the general pattern: **read immutable identity data, produce a new mutable header via an Action.**

---

## 7. Catalog: headers already inserted (or verified) by shipped policies

Check this before inventing a new header. Columns: header, direction, producing/consuming policy, source file. Only headers confirmed by reading the actual `Action`-returning code are listed as "set" — a header name appearing as a string literal elsewhere (a strip-list, a comment, a `Metadata` key) is called out separately and is **not** implied to be set on the wire.

### 7.1 Set on the outbound request to upstream

| Header | Producing policy | Notes | Source |
|---|---|---|---|
| `x-jwt-assertion` (configurable name, default shown) | `backend-jwt` | Signed JWT built from `AuthContext` — see §6.3 | `backend-jwt/backendjwt.go` |
| `x-forwarded-authorization` (configurable name, default shown) | `jwt-auth`, `opaque-token-auth`, `mcp-auth` | Forwards/relabels the original credential toward upstream, honoring a `forwardTokenStripScheme` option | `jwt-auth/jwtauth.go`, `opaque-token-auth/opaquetokenauth.go`, `mcp-auth/mcp-auth.go` |
| `X-Amz-Date`, `X-Amz-Content-Sha256`, `X-Amz-Security-Token` | `aws-authentication` | AWS SigV4 request signing — upstream-only, never forwarded to the client | `aws-authentication/aws_authentication.go` |

### 7.2 Set on the response returned to the client

| Header(s) | Producing policy | Notes | Source |
|---|---|---|---|
| `X-RateLimit-Limit`, `X-RateLimit-Remaining`, `X-RateLimit-Reset`, `X-RateLimit-Full-Quota-Reset`, plus IETF `RateLimit-*` equivalents | `subscription-validation`, `advanced-ratelimit` | `subscription-validation` sets these only inside the 429 `ImmediateResponse` when quota is exceeded, not on a normal pass-through response; `advanced-ratelimit` sets them on ordinary responses too | `subscription-validation/subscriptionvalidation.go`, `advanced-ratelimit/ratelimit.go`, `advanced-ratelimit/limiter/result.go` |
| `x-ratelimit-limit`, `x-ratelimit-remaining`, `x-ratelimit-reset`, `x-ratelimit-limit-requests`/`-tokens`, `x-ratelimit-remaining-requests`/`-tokens`, `x-ratelimit-reset-requests`/`-tokens`, `x-ratelimit-quota` | `advanced-ratelimit` | Legacy/lowercase variants alongside the IETF-style set above | `advanced-ratelimit/ratelimit.go` |
| `x-ratelimit-cost-limit-dollars`, `x-ratelimit-cost-remaining-dollars` | `llm-cost-based-ratelimit` | Dollar-denominated overlay added on top of a delegate rate-limit policy's own headers (reads `ratelimit-limit`/`x-ratelimit-limit` style headers already on the response, adds a dollar-scaled sibling) | `llm-cost-based-ratelimit/llm_cost_based_ratelimit.go` |
| `X-Cache-Status: HIT` | `semantic-cache` | Set only on a cache-hit `ImmediateResponse` (200, short-circuits the chain) | `semantic-cache/semanticcache.go` |

### 7.3 Read-only inputs — consumed, not set, by shipped policies

| Header | Consuming policy | Notes | Source |
|---|---|---|---|
| `x-request-id` | `log-message` | Read from existing request headers for log correlation; **not generated** by any shipped policy — something upstream of the policy chain (an ingress/edge layer, or the client) is expected to have already set it | `log-message/logmessage.go` |
| `x-forwarded-for`, `x-real-ip` | `advanced-ratelimit` | Read to key a rate limit by client IP | `advanced-ratelimit/ratelimit.go` |
| `x-provider` (configurable name, default shown) | `llm-header-router` | Client-supplied; read to pick an LLM provider | `llm-header-router/llmheaderrouter.go` |
| `X-Hub-Signature-256` / `X-Hub-Signature` | `websub-hmac-auth` | **Verified against a computed HMAC, not generated** — this policy authenticates an *inbound* WebSub hub notification; despite the "signature" name it is a request-authentication check, not an outbound-signing policy like `aws-authentication` in §7.1 | `websub-hmac-auth/websub_hmac_auth.go` |

### 7.4 Named like a header, but `Metadata`-only today

Covered in full in §5.2 — repeated here because the naming makes it easy to assume otherwise: `x-wso2-application-id`, `x-wso2-application-name`, `x-wso2-billing-customer-id`, `x-wso2-billing-subscription-id`, `x-wso2-subscription-status`, `x-wso2-subscription-plan-name`, `x-llm-cost`, `x-llm-cost-status`. None of these are set as outbound headers by any shipped policy as of this writing.

---

## 8. Worked example: one request through a realistic chain

Trace of `jwt-auth` → `subscription-validation` → `backend-jwt` on the request path, with `subscription-validation`'s own quota check surfacing on a rejected request:

1. **`jwt-auth`, request-header phase.** Validates the bearer token from `Authorization` (read via `DownstreamHeaders()` — the pre-mutation client snapshot, per §3.3, not the live header, so an earlier policy rewriting `Authorization` for its own purposes can't fool this check). On success, it **replaces** `shared.AuthContext` with a new `*AuthContext{Authenticated: true, AuthType: "jwt", Subject: ..., Scopes: ..., Previous: shared.AuthContext}` (§6.1) and returns `UpstreamRequestHeaderModifications{HeadersToSet: {"x-forwarded-authorization": ...}}` to forward the credential, per its `forwardedTokenHeader` config.

2. **`subscription-validation`, request-header phase (its only phase).** Reads the API ID from the immutable `SharedContext.APIId` (§3.1) and the caller's application identity from `SharedContext.Metadata["x-wso2-application-id"]` — a `Metadata` key set earlier in the chain by `api-key-auth`, if that policy also runs; independently, it can validate by a subscription-key header or cookie read via the downstream snapshot. On success it calls `writeSubscriptionMetadata`, writing `x-wso2-billing-customer-id`/`x-wso2-billing-subscription-id`/`x-wso2-subscription-status`/`x-wso2-subscription-plan-name` into `SharedContext.Metadata` (§5.2 — **Metadata only, not headers**), then returns an essentially pass-through `UpstreamRequestHeaderModifications{}` (or one that strips the now-consumed subscription-key header). **On a quota violation**, it instead returns `ImmediateResponse{StatusCode: 429, Headers: {"X-RateLimit-Limit": ..., "X-RateLimit-Remaining": ..., ...}}` (§7.2) — this short-circuits the chain entirely; `backend-jwt` below never runs for this request.

3. **`backend-jwt`, request-header phase** (only reached if step 2 didn't short-circuit). Reads `reqCtx.SharedContext.AuthContext` — the value `jwt-auth` set in step 1, immutable from `backend-jwt`'s point of view — builds a new signed JWT from its claims, and returns `UpstreamRequestHeaderModifications{HeadersToSet: {"x-jwt-assertion": <signed JWT>}}` (§6.3, §7.1). This is what the backend actually receives as its identity assertion; nothing about `AuthContext` itself changed, a brand-new header was derived from it.

What this trace shows concretely: step 1 wrote `Metadata` en route to step 2's read (via `api-key-auth`, not shown, but the same shape as step 2 reading `AuthContext`); step 2's `Metadata` writes have no reader among shipped policies yet (the §5.2 gotcha); every header that reaches the backend was produced by an explicit `Action`, never by directly poking a context field.

---

## 9. Quick-reference checklist for new policy authors

Before adding a new header or `Metadata` key:

- [ ] Checked §5.2 and §7 for an existing key/header that already carries this data?
- [ ] Using an `Action` return (`HeadersToSet`/`HeadersToAppend`/`HeadersToRemove`, or `ImmediateResponse`) for anything that must actually reach upstream or the client — not one of the `Set*Header` snapshot writers from §4.2, which never leave the chain?
- [ ] If more than one instance of your policy can run in the same chain, namespaced the `Metadata` key (§5.1) so instances don't clobber each other?
- [ ] Treated any `ResolutionAttributes` value as untrusted, request-derived input (§3.2) rather than a trusted key?
- [ ] For an authentication/authorization/gating decision, read the `Downstream`/`Upstream` snapshot accessor (§3.3), not the live header field, so an earlier policy's rewrite can't be mistaken for what the client/upstream actually sent?

---

## Appendix: SDK source map

All paths relative to `sdk/core/policy/v1alpha2/` in the `api-platform` repository.

| File | Contents |
|---|---|
| `context.go` | The six per-phase context structs, `SharedContext`, `Body`, `Downstream`/`Upstream` snapshot types |
| `headers.go` | The `Headers` type — read-only public surface, kernel-only `UnsafeInternalValues` |
| `context_accessors.go` | Snapshot-preferring, live-falling-back read accessors (`DownstreamRequest()`, `UpstreamResponse()`, etc.) |
| `context_header_writers.go` | Chain-internal-only snapshot writers (`SetDownstreamHeader`, etc.) — never a wire mutation |
| `action.go` | All `Action` return types: header/body, request/response, buffered/streaming, `ImmediateResponse` |
| `auth_context.go` | `AuthContext` struct definition |
| `resolution_attributes.go` | `ResolutionAttributes` — read-only protocol-derived facts |
| `interface.go` | `Policy`, per-phase sub-interfaces, `ProcessingMode`, `PolicyMetadata` |
| `definition.go` | `PolicyParameters`, `PolicyDefinition`, `PolicySpec` — a policy's own configuration shape |
| `types.go` | `APIKind`, `UpstreamSlot`, parameter type system |

_Verified against SDK `v0.4.12` (per `policies/*/go.mod` at the time of writing). Re-check the pinned version in any given policy's `go.mod` before relying on exact field names — the two repositories version independently._
