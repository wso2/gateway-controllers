# Rule: Declaring Faults in Policy Error Responses (IsFault, FaultDetails, SDK Error Codes)

## Context & Scope

Apply this rule whenever writing, refactoring, or reviewing a policy under `policies/` that rejects a request or a response: any return of `policy.ImmediateResponse`, a `policy.DownstreamResponseModifications` or `policy.UpstreamResponseModifications` that sets an error status, or a `policy.TerminateResponseChunk` that ends a stream because something failed. The Python equivalent is any `ImmediateResponse` a Python policy returns for a failure. The full reference is [`docs/error-codes.md`](../../docs/error-codes.md); this rule is the checklist a change must pass.

The gateway only knows *why* a request failed if the policy says so. Without a declared fault, the analytics event carries a bare status code, and the API's fault policies (for example `log-message` or `error-response-formatter` under `faultPolicies`) never run for the rejection.

## Directives

1. **Declare every rejection.** Set `IsFault: true` and a `Fault: &policy.FaultDetails{...}` on every response the policy returns because something failed. Do not set either on a response that is not a failure — a cache hit, a CORS preflight answer, a redirect, a mock response — because the gateway would then report a successful call as a failure.

2. **Fill `FaultDetails` completely.**
   - `Code` — an SDK constant (directive 3).
   - `Type` — `policy.FaultTypeAuthentication`, `FaultTypeAuthorization`, `FaultTypeValidation`, `FaultTypeThrottling`, `FaultTypeGuardrail` or `FaultTypeMediation`.
   - `Direction` — `policy.DirectionRequest` or `policy.DirectionResponse`, for the side of the call that failed.
   - `Message` — one short, client-safe sentence.
   - `Description` — optional internal detail. It reaches fault policies and analytics, never the client.
   - Never set `Policy`: the gateway fills it in and overwrites whatever a policy puts there.

3. **Use an SDK constant for the code, never a literal.** Codes come from `github.com/wso2/api-platform/sdk/core/policy/v1alpha2` (`policy.FaultCode*`, `policy.GuardrailCode*`). Write `policy.FaultCodeAuthMissingCredentials`, not `"900902"`. If the constant you need does not exist, add it to the SDK; do not invent a number in the policy. The number decides the analytics category by its range, so pick by meaning:
   - authentication / authorization: `FaultCodeAuth*`, `FaultCodeInvalidScope`, `FaultCodeSubscriptionInactive` (900900–900999)
   - throttling: `FaultCodeThrottled*` (900800–900899)
   - upstream: `FaultCodeUpstream*`
   - guardrail: `GuardrailCode*` (906000–906399)
   - the policy could not do its job: `FaultCodeMediationFailed`; the caller's payload could not be read: `FaultCodeInvalidRequestBody`. Do not allocate a per-policy code for either — `Policy` already says which policy failed.

4. **Keep the client response unchanged when migrating a policy.** Adding `IsFault` and `Fault` must not change `StatusCode`, `Headers` or `Body`. Clients already parse those bytes; the fault description is additive.

5. **Keep secrets and blocked content out of `Message`.** `Message` and `Body` reach the client. An internal error string, a stack trace, a file path, an upstream hostname, a credential, or the content a guardrail matched belongs in `Description` or a log line, never in `Message`.

6. **Use the protocol-specific detail where it applies.**
   - A guardrail sets `Type: policy.FaultTypeGuardrail` and `Guardrail: &policy.GuardrailDetails{InterveningGuardrail, Action: policy.GuardrailActionIntervened, ActionReason}`. Put `Assessments` there only when the operator opted in (for example `showAssessment`) — it can hold the blocked content.
   - A policy that has parsed a JSON-RPC request (MCP, A2A) sets `JSONRPC: &policy.JSONRPCError{Code, ID}` when it knows a more specific code than the status implies, such as `-32602`.

7. **Declare on every path that can fail, not only the request header phase.**
   - A response-side rejection returns `DownstreamResponseModifications` with `StatusCode`, `IsFault: true` and `Fault`.
   - A rejection that keeps a success status (for example a guardrail intervening with a 200) must set `IsFault: true`; the status alone does not mark it as a failure.
   - A stream ended because of a failure returns `TerminateResponseChunk` with `IsFault: true` and `Fault`. A clean end of stream sets neither.
   - A policy that delegates to another and returns its action passes the delegate's `IsFault` and `Fault` through unchanged.

8. **Python policies feature-detect the fault types.** The Python SDK is the one the gateway runtime ships, so a gateway older than the fault contract does not have it. Import the fault names in a `try`/`except ImportError` block, and add `is_fault=True, fault=FaultDetails(...)` only when the import succeeded, so the policy still loads and behaves as before on an older gateway.

9. **Require an SDK that has the contract, and test the declaration.** A Go policy that uses `IsFault`, `FaultDetails` or the code constants requires `sdk/core` v0.4.2 or later in its `go.mod`. Add a unit test that asserts each rejection's `IsFault`, `Code` and `Type`, and that the body is unchanged.

10. **No deferring behind a comment.** Do not ship a rejection without its fault declaration and a `// TODO: declare fault` next to it. Declare it, or raise the gap in the PR.

## Example

```go
// BAD: no fault — the gateway records only "401", and the API's fault policies never run.
return policy.ImmediateResponse{
    StatusCode: 401,
    Headers:    map[string]string{"content-type": "application/json"},
    Body:       body,
}

// BAD: a literal code, the matched secret in Message, and Policy set by hand.
Fault: &policy.FaultDetails{
    Code:    "900902",
    Message: "token " + rawToken + " rejected",
    Policy:  "my-auth",
}

// GOOD: same status, headers and body as before; the fault is described with SDK constants,
// and the internal reason goes to Description, which the client never sees.
return policy.ImmediateResponse{
    StatusCode: 401,
    Headers:    map[string]string{"content-type": "application/json"},
    Body:       body,
    IsFault:    true,
    Fault: &policy.FaultDetails{
        Code:        policy.FaultCodeAuthMissingCredentials,
        Type:        policy.FaultTypeAuthentication,
        Direction:   policy.DirectionRequest,
        Message:     "Valid credentials required",
        Description: "no authorization header presented",
    },
}
```

```python
# Python: feature-detect, so the policy still loads on a gateway without the fault contract.
try:
    from apip_sdk_core import FaultCode, FaultDetails, FaultType
except ImportError:
    FaultDetails = None

def _fault(message: str) -> dict:
    if FaultDetails is None:
        return {}
    return {"is_fault": True, "fault": FaultDetails(
        code=FaultCode.MEDIATION_FAILED, type=FaultType.MEDIATION,
        direction="Request", message=message)}

return ImmediateResponse(status_code=502, headers=headers, body=body, **_fault("Upstream call failed."))
```

> **Verification Checklist before outputting code:**
> * Does every response returned because something failed set `IsFault: true` and `Fault`, and does no non-failure response (cache hit, preflight, redirect) set them?
> * Is `Fault.Code` an SDK constant (`policy.FaultCode*` / `policy.GuardrailCode*`) from the range that matches the failure's meaning, never a string literal or a locally allocated number?
> * Are `Type`, `Direction` and `Message` set, and is `Policy` left for the gateway to fill?
> * For a migrated policy, are `StatusCode`, `Headers` and `Body` byte-for-byte what they were before?
> * Is anything sensitive — a credential, an internal error, a hostname, matched content — kept out of `Message` and `Body`, and in `Description` or a log instead?
> * Are response-side rejections, success-status interventions, failed stream terminations and delegated actions declared too?
> * Does a Python policy import the fault types inside `try`/`except ImportError` and add them only when present?
> * Does the policy's `go.mod` require `sdk/core` v0.4.2 or later, and is there a test asserting each rejection's fault?
