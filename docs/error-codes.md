# Writing a policy that rejects a request

A policy that refuses a request — or refuses a response on the way back — has to say three
things: what the client sees, what the gateway records, and which of the API's fault policies
should run over it. This is the reference for all three.

```go
return policy.ImmediateResponse{
    StatusCode: 401,
    Headers:    map[string]string{"content-type": "application/json"},
    Body:       body,                       // what the client parses
    IsFault:    true,                       // opts into the fault flow
    Fault: &policy.FaultDetails{            // what the gateway records
        Code:      policy.FaultCodeAuthMissingCredentials,
        Type:      policy.FaultTypeAuthentication,
        Direction: policy.DirectionRequest,
        Message:   "Valid credentials required",
    },
}
```

## 1. Describe the failure, always

`Fault` is not optional decoration. Without it the gateway knows only a status code, so the
analytics event says "401" and nothing about which condition produced it, and the API's fault
policies never run.

| Field | What it is for |
|---|---|
| `Code` | The condition. Drives the analytics category — see below. **Always an SDK constant.** |
| `Type` | The class of failure: `policy.FaultTypeAuthentication`, `…Authorization`, `…Validation`, `…Throttling`, `…Guardrail`, `…Mediation`. |
| `Direction` | `policy.DirectionRequest` or `policy.DirectionResponse` — which side of the call failed. |
| `Message` | One short, client-safe sentence. See §4. |
| `Description` | Optional, and **never reaches the client**. For detail too sensitive or too verbose to return — a guardrail's matched content belongs here, not in `Message`. |

Setting `Fault` opts the rejection into the fault flow. A policy that sets neither `Fault` nor
`IsFault` is treated as *not a failure*, and its rejection reaches the client without the API's
fault policies ever seeing it. That default is deliberate — a cache hit and a CORS preflight are
`ImmediateResponse`s too, and neither is a fault.

## 2. Use an SDK constant for the code, never a literal

Every code lives in `policy` (`sdk/core/policy/v1alpha2`). Import it and use the constant:

```go
Code: policy.FaultCodeAuthMissingCredentials,   // yes
Code: "900902",                                 // no
```

A literal is unverifiable at review time and drifts silently when the vocabulary moves. The
constants are the single source; if the one you need is missing, add it there rather than
inventing a number locally.

### The shared policy codes

Many policies can hit these, so they are shared rather than allocated per policy:

| Code | Constant | Use when |
|---|---|---|
| `960000` | `policy.FaultCodeMediationFailed` | **The policy could not do its job.** A transformation that failed, a credential it could not mint, a rewrite it could not apply. The failure is the gateway's. Type `Mediation`. |
| `960001` | `policy.FaultCodeInvalidRequestBody` | **The caller's payload could not be read.** Malformed JSON, an envelope that is not one, a body whose shape the configuration does not fit. The failure is the caller's. Type `Validation`. |
| `960002` | `policy.FaultCodeProviderStreamFailed` | **A provider ended a streamed response with a failure** after the response began: an error event, an exception frame. Type `Mediation`, direction `Response`. |
| `960003` | `policy.FaultCodeNoModelAvailable` | **A model-routing policy has no model left to route to** — every configured model suspended or excluded, so the request never reached a provider. Type `Mediation`, direction `Request`. |
| `960004` | `policy.FaultCodeInvalidRequestHeader` | **A request header the policy needed is missing, malformed, or contradicts the body.** The failure is the caller's. Type `Validation`, direction `Request`. |
| `960005` | `policy.FaultCodeInvalidRequestURI` | **The request path or query string could not be used** — a query string that does not parse, a path that does not match the shape the policy rewrites. The failure is the caller's. Type `Validation`, direction `Request`. |

Do not allocate a per-policy code for any of these. `FaultDetails.Policy` already carries *which*
policy failed — the gateway fills it in and it reaches the analytics event — so a code that
encodes the policy name a second time tells a reader nothing new and costs a registry entry to
keep straight.

### Codes for a specific condition

Where the condition is genuinely the policy's own and the policy name does not already say it,
use the constant for that condition if one exists (the shared codes above, the auth and
throttling codes, the guardrail block), and add one to the SDK if it does not. The
`policy.FaultCodeUpstream*` codes are the gateway's own, for the router failing to proxy a
request; a policy does not use them — no model left to route to is `FaultCodeNoModelAvailable`,
and a provider's stream breaking mid-response is `FaultCodeProviderStreamFailed`.

## 3. Code ranges, and why the number matters

The code decides the analytics **category** by which range it falls in. Picking a number from
the wrong range files the rejection as the wrong kind of failure.

| Range | Category | Constants |
|---|---|---|
| `900900`–`900999` | authentication / authorization | `policy.FaultCodeAuth*`, `FaultCodeInvalidScope`, `FaultCodeSubscriptionInactive` |
| `900800`–`900899` | throttling | `policy.FaultCodeThrottled*` |
| `101500`–`101599`, `303001` | upstream / target | `policy.FaultCodeUpstream*` |
| `906000`–`906399` | guardrail | `policy.GuardrailCode*` — one block, one range test |
| `960000`–`964999` | **shipped policies** — `other` | `FaultCodeMediationFailed`, `FaultCodeInvalidRequestBody`, `FaultCodeProviderStreamFailed`, `FaultCodeNoModelAvailable`, `FaultCodeInvalidRequestHeader`, `FaultCodeInvalidRequestURI` (`960000`–`960005`), plus any specific ones |
| `965000`–`969999` | **reserved for your own policies** — `other` | yours to allocate; nothing shipped will ever take a number here |

Classifying as `other` is the honest answer for a condition the taxonomy has no category for —
it is not a shortcoming to route around. Reaching into the auth range for a mediation failure
would report a gateway bug as a client authentication failure.

Writing a policy for your own deployment? Allocate in `965000`–`969999`, a sub-block per policy,
and keep the allocation somewhere a reviewer can check it.

## 4. Keep the client-facing body safe and unchanged

**`Message` and `Body` reach the client.** Never put an internal error string, a stack trace, a
file path, an upstream hostname, a credential, or the content a guardrail matched into either.
Detail that is useful to an operator goes in `Description`, which the gateway records and never
returns, or in a log line.

**Migrating an existing policy? The bytes it returns must not change.** Clients have been parsing
that body since before the fault contract existed, so adding a description is additive: set
`IsFault` and `Fault`, leave `StatusCode`, `Headers` and `Body` exactly as they were. A gateway
that renders error bodies will use the description; one that does not sends what you wrote,
unchanged.

## 5. Format

Six-digit numeric strings — not integers, not names. That is what clients already parse.
