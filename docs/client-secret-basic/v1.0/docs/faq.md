# Client Secret Basic — FAQ

---

## What is the difference between static and dynamic mode?

In **static mode** the policy holds the expected credentials in memory at deploy time and validates each request against that in-memory map. No external call is made. Best for closed systems where you control both the caller and the gateway configuration.

In **dynamic mode** the policy forwards the original `Authorization: Basic` header unchanged to a configured OAuth2 token endpoint as a `client_credentials` grant. If the endpoint issues a token, the credentials are valid. The result is cached in-process so the token endpoint is not called on every request. Best when credentials are managed in an external identity provider (Keycloak, Okta, Azure AD) and you need the gateway to honour that source of truth without maintaining a local copy.

---

## How do I choose a mode?

Use **static mode** when:
- You own the credential store and it does not change frequently.
- You want zero external dependencies in the policy chain.
- You need to register multiple callers with independent credentials in a single policy instance.

Use **dynamic mode** when:
- Credentials are managed in a centralised IdP.
- You want client registration and revocation to take effect at the IdP without redeploying the API.
- The token endpoint is on the same network as the gateway (latency is not a concern for cache misses).

---

## How do callers encode their credentials?

Concatenate `clientId`, a literal colon, and `clientSecret`, then base64-encode the result and pass it in the `Authorization` header:

```bash
CREDS=$(echo -n "my-client:my-secret" | base64)
curl -H "Authorization: Basic $CREDS" https://gateway.example.com/api/path
```

In most HTTP client libraries this is the standard Basic auth mechanism — set `auth=("my-client", "my-secret")` or equivalent and the library handles base64 encoding automatically. **Note:** per RFC 6749 §2.3.1, any `+`, `%`, `&`, or `=` characters in the client ID or secret must be percent-encoded *before* base64 encoding. Not all HTTP libraries do this automatically — if your credentials contain special characters, verify that your library percent-encodes them or encode manually with `urllib.parse.quote_plus` (Python), `URLEncoder.encode` (Java), or `encodeURIComponent` (JavaScript).

---

## Can my client secret contain a colon?

Yes. The policy splits the decoded value on the **first** colon only (`strings.SplitN(..., ":", 2)`), so everything after the first `:` is the secret, including any subsequent `:` characters.

---

## What happens if the Authorization header is absent?

The request is rejected immediately with `401 Unauthorized` and the message `Unauthorized: missing Authorization header`.

---

## What happens if the Authorization header uses Bearer or another scheme?

The request is rejected with `401 Unauthorized` and the message `Unauthorized: Authorization header must use Basic scheme`. The policy does not inspect `Bearer` tokens — use `jwt-auth` for JWT validation.

---

## What happens if the base64 value is malformed?

The request is rejected with `401 Unauthorized` and the message `Unauthorized: malformed Basic credentials`. The decoding error is logged at `debug` level on the gateway.

---

## What happens if both clientId and clientSecret are present but the credentials are wrong?

The request is rejected with `401 Unauthorized` and the message `Unauthorized: invalid credentials`. The error does not distinguish which value was wrong — this is intentional to avoid leaking information.

---

## Is the Authorization header forwarded to the upstream?

No. Both the `Authorization` and `Subscription-Key` headers are added to `HeadersToRemove` on every successful request and stripped before the request reaches the upstream backend.

---

## How does the dynamic-mode cache work?

On a successful token request the policy stores a SHA-256 hash of `clientId:clientSecret` to `expiresAt` in an in-process cache. `expiresAt` is `now + min(expires_in - expiryBuffer, maxCacheTTL)`. On subsequent requests for the same credential pair, the cache entry is checked first; if it is present and not yet expired, the token endpoint is skipped entirely.

When the cache entry expires, the next request triggers a fresh token call and refreshes the entry if the credentials are still valid. Concurrent first requests for the same credential pair are deduplicated (singleflight) so that only one IdP call is made regardless of burst concurrency.

Failed credential attempts are tracked in two layers to prevent IdP hammering without blocking legitimate traffic:

1. **Wrong-credential pair cache**: A confirmed bad `(clientId, secret)` pair is stored so repeats of the exact same wrong secret never reach the IdP — they return `401` immediately from the cache.
2. **Per-clientId throttle counter**: Each distinct new wrong secret for a clientId increments a counter. When the counter reaches `failureRateLimit` (default 3) within `failureWindow` (default 30s), further requests for that clientId return `429 Too Many Requests` until the window resets.

The key difference from a pure clientId-level block: the first few requests with the **correct** secret still reach the IdP as long as the per-clientId counter has not been exhausted. Only HTTP 400/401 responses from the IdP are cached as rejections; 429 and other 4xx/5xx return `503` and are not cached.

---

## What is the 429 response in dynamic mode?

When a clientId has exceeded `failureRateLimit` distinct failed credential attempts within `failureWindow`, the policy returns `429 Too Many Requests`:

```json
HTTP/1.1 429 Too Many Requests
{"error":"too_many_requests","message":"too many failed attempts — retry after the rate-limit window resets"}
```

A `429` means the per-clientId failure rate limit was reached — not that the credentials are wrong. The window resets automatically after `failureWindow`. This is distinct from a `401` (confirmed bad credentials) and `503` (IdP unreachable).

---

## What happens if the token endpoint is unreachable?

The policy returns `503 Service Unavailable`. Returning 401 would be incorrect here — the credentials may be valid; the IdP simply cannot be reached. Requests that hit a still-fresh success cache entry continue to succeed; the token endpoint is only consulted on a cache miss.

---


## What is the difference between a 401 and a 503 response in dynamic mode?

A `401 Unauthorized` means the credentials were checked and found invalid (the token endpoint rejected them). A `503 Service Unavailable` means the credentials could not be checked at all — the token endpoint was unreachable, timed out, or returned a 5xx server error. Distinguish these in your client: a 401 suggests rotating credentials; a 503 suggests retrying after a brief delay.

## If I revoke a credential at the IdP, how quickly does the gateway reject it?

The gateway continues to accept requests for that credential until the cache entry expires. The effective hold time is `min(expires_in - expiryBuffer, maxCacheTTL)`. To reduce the revocation window, set a short `maxCacheTTL` (e.g. `"1m"`). There is no purge API — for immediate revocation after a cache entry is written, restart the gateway pod.

**Secret rotation note:** when using `{{ secret "handle" }}` references, updating the secret store value does not take effect until the API is redeployed or the controller is restarted. Static mode has no in-process cache — the old value stays in the deployed API definition until it is redeployed with the new value; the new value is not picked up at rotation time alone.

---

## How do I forward the IdP access token to the backend?

In dynamic mode, the IdP-issued access token is automatically stored in `SharedContext.Metadata["upstream-access-token"]` after every successful validation (the key is `upstream-access-token` by default; override with `tokenMetadataKey` if needed). A downstream `header-transform` policy can read it with `${meta.upstream-access-token}`:

```yaml
policies:
  - name: client-secret-basic
    version: v1
    params:
      tokenEndpoint: https://idp.example.com/token
  - name: header-transform
    version: v1
    params:
      request:
        add:
          - name: Authorization
            value: Bearer ${meta.upstream-access-token}
```

The `Authorization: Basic` header is already stripped by `client-secret-basic` before `header-transform` runs, so there is no conflict.

**On cache hits:** the same access token that was returned on the first IdP call is reused until the cache entry expires. The backend receives the same token for the full cache TTL (`min(expires_in - expiryBuffer, maxCacheTTL)`). This is intentional — the token is valid for that duration, and issuing a new one on every request would defeat the caching.

**Static mode:** `tokenMetadataKey` has no effect in static mode because no token is issued — static validation is a pure in-memory credential check.

---

## How does subscription validation work with this policy?

After a successful validation (either mode), the policy sets `SharedContext.Metadata["x-wso2-application-id"]` to the validated `clientId`. When `subscription-validation` follows in the chain, it reads that metadata key to look up the subscription — no `Subscription-Key` header is required from the caller.

```
client-secret-basic → subscription-validation → dynamic-endpoint
```

This requires a subscription to exist with `applicationId` matching the `clientId` value. Create subscriptions via the management API:

```bash
curl -s -X POST "http://localhost:9090/api/management/v1/subscriptions" -u admin:admin \
  -H "Content-Type: application/json" \
  -d '{
    "apiId": "TC5API",
    "subscriptionPlanId": "<plan-uuid>",
    "subscriptionToken": "any-unique-value",
    "applicationId": "my-client-id"
  }'
```

---

## Can two different client identities use the same API?

Yes — in static mode using the `credentials` array. Each entry has a unique `clientId`. In dynamic mode any credential pair that the token endpoint accepts is treated as a valid client, so all registered IdP clients are implicitly allowed.

---

## How do I rotate a `clientSecret` in static mode?

Update the `clientSecret` param (or the gateway secret it references) in the API definition YAML and redeploy:

```bash
curl -s -X PUT http://localhost:9090/api/management/v1/rest-apis/TC5API \
  -u admin:admin \
  -H "Content-Type: application/yaml" \
  --data-binary @tc5-api.yaml
```

There is no zero-downtime rotation path — the old secret becomes invalid as soon as the new definition is applied. Use `{{ secret }}` references to decouple the value from the YAML so only the secret store needs updating.

---

## Can I use this policy without subscription validation?

Yes. `client-secret-basic` is a standalone authentication policy. It can be the only policy on an API, or it can be followed by any other policy in the chain. The `x-wso2-application-id` injection is a no-op if `subscription-validation` is not present.

---

## What fields does the policy set in `AuthContext`?

After successful validation, `AuthContext` has:
- `Authenticated: true`
- `AuthType: "ClientCredentials"`
- `Subject: <clientId>` — the principal identity
- `CredentialID: <clientId>` — the credential identifier (OAuth2 client_id equivalent)
- `Properties["ClientId"]: <clientId>` — for backward compatibility with policies that read this map

`TokenId` is **not** set. Deriving a stable identifier from the raw secret would create an analytics-visible fingerprint of the credential once `Subject` is populated.

---

## How do I release a new version of the policy?

1. Make changes to the policy source under `policies/client-secret-basic/`.
2. Update the `version` field in `policies/client-secret-basic/policy-definition.yaml` to the new version (e.g. `v1.1.0`).
3. Create `docs/client-secret-basic/v1.1/` following the same `docs/`, `assets/`, `metadata.json` structure as `v1.0/`.
4. Rebuild the gateway image: `ap gateway image build --path policies` from the directory containing the `policies/` folder.
5. Push and deploy the new image using your environment's deployment pipeline (ConfigMap update, Helm upgrade, or equivalent rollout restart).
