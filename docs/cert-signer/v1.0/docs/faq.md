# cert-signer — FAQ

## Why does the backend return 401?

**Most likely causes, in order:**

1. **Auth policy did not run before cert-signer** — cert-signer reads the authorized
   application ID from `SharedContext.Metadata["x-wso2-application-id"]`, which is set by
   `jwt-auth` or `client-secret-basic`. If neither policy ran before cert-signer (or the policy
   chain is misconfigured), the metadata key is absent and cert-signer returns 401 with
   `{"error":"unauthorized","message":"application identity not established"}`. Check the API
   definition policy order — the auth policy must appear before cert-signer.

2. **Wrong identity** — the cert/key referenced by `certPem`/`keyPem` does not match the
   certificate the backend has pre-shared. Confirm the CN in the JWT `iss` claim matches
   what the backend expects.

3. **JWT expired** — default TTL is 300 s. If there is clock skew between the gateway and the
   backend, reduce `ttlSeconds` or align NTP. Check `exp` in the decoded token.

4. **Wrong header or scheme** — the backend expects the JWT on a different header or with a
   different prefix. Set `signatureHeader` and `scheme` accordingly.

5. **Secret not resolved** — if `{{ secret "..." }}` is not being resolved, the policy receives
   the literal string and cert parsing fails at deploy time. Check the gateway deploy log for a
   `cert-signer: parsing cert` error.

6. **Base64 mismatch** — the token uses standard base64 with padding. If a custom backend is
   decoding with base64url (no padding), it will fail to parse the token.

## How do I decode the token manually?

The token format is `base64(header).base64(payload).base64(signature)` using **standard base64
with padding**. To inspect:

```bash
TOKEN="eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOi..."
# Decode header (part 0):
echo $TOKEN | cut -d. -f1 | base64 -d | python3 -m json.tool
# Decode payload (part 1):
echo $TOKEN | cut -d. -f2 | base64 -d | python3 -m json.tool
```

Expected header: `{"alg":"RS256"}` (no `typ` field).  
Expected payload: includes `typ:"JWT"`, `iss`, `sub`, `iat`, `exp`, `jti`.

## How do I rotate a certificate?

1. Upload the new cert and key as gateway secrets:
   ```bash
   ap gateway secret create apip-identity-medium-cert --from-file new-gateway-medium.crt
   ap gateway secret create apip-identity-medium-key  --from-file new-gateway-medium.key
   ```
2. Redeploy the API definition — triggers `GetPolicy`, which reloads cert + key.
3. Confirm the backend has the new cert in its trust store before cutting over.

## Can I use the same identity across multiple APIs?

Yes. The same `{{ secret "..." }}` references can appear in any number of API definitions.
Each API gets its own in-memory `PolicyConfig` at deploy time but all share the same cert + key.

## What is the JWT lifetime, and when should I change it?

Default is **300 seconds (5 minutes)**. Maximum is **3600 s (1 hour)**.

## What is the jtiHeader and when is a UUID used instead?

`jtiHeader` (default `x-global-transaction-id`) is the incoming request header whose value
becomes the JWT `jti` claim. When the header is absent, a random UUID is generated per-request as a fallback.

## How is the sub claim set?

`sub` is set **per-request** from `SharedContext.Metadata["x-wso2-application-id"]`, which an
upstream auth policy (`jwt-auth` or `client-secret-basic`) sets to the authorized application's
client ID.

There is no static `subject` configuration parameter — the value is always read from request
metadata at runtime. If the metadata key is absent or empty when cert-signer runs, the policy
returns 401 immediately (the JWT is never generated).

**Required policy chain order:**

```yaml
policies:
  - name: jwt-auth        # (or client-secret-basic) sets x-wso2-application-id in metadata
    version: v1
    params:
      scopes:
        allOf: [MY_SCOPE]
  - name: cert-signer     # reads x-wso2-application-id → JWT sub claim
    version: v1
    params:
      certPem: '{{ secret "apip-identity-medium-cert" }}'
      keyPem:  '{{ secret "apip-identity-medium-key" }}'
```

## Does the policy send the certificate to the backend?

No. The certificate is used only to sign the JWT. The backend holds the certificate pre-shared
and uses its public key to verify the RS256 signature.

## How is this different from mutual TLS?

mTLS authenticates at the **TLS handshake** layer — both sides present certificates before any
HTTP traffic flows. `cert-signer` authenticates at the **HTTP layer** via a signed JWT. It works
over both mTLS and plain TLS transports.

## Can I place the JWT on a header other than Authorization?

Yes. Set `signatureHeader` to the target header name:

```yaml
params:
  certPem: '{{ secret "apip-identity-medium-cert" }}'
  keyPem:  '{{ secret "apip-identity-medium-key" }}'
  signatureHeader: x-client-signature
```

## Can I use EC (elliptic curve) keys?

Not in v1.0. Only RSA private keys (PKCS1 `RSA PRIVATE KEY` and PKCS8 `PRIVATE KEY` PEM blocks)
are supported. RSA-2048 or RSA-4096 is recommended.

## What happens if neither certPem nor certFile is configured?

The policy falls back to `/etc/gateway/mtls/tls.crt` and `/etc/gateway/mtls/tls.key` inside the
gateway-runtime container. If those files are absent, `GetPolicy` returns an error and the API
definition is rejected at deploy time.
