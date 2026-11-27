# Certificate Signer — v1.0

## Overview

`cert-signer` authenticates the gateway to backend services using a TLS certificate identity.
It generates a short-lived RS256-signed JWT from a configured certificate and private key,
and injects it as the `Authorization` header on every upstream request.

```
Authorization: Cert <base64(header)>.<base64(payload)>.<base64(signature)>
```

The backend holds the configured certificate **pre-shared** and verifies the JWT signature using the
certificate's public key. The certificate is never sent per-request.

## Token Format

| Aspect | cert-signer |
|---|---|
| Signing | RSA-SHA256 (PKCS1v15) |
| Encoding | Standard base64 with padding |
| JWT header | `{"alg":"RS256"}` — no `typ` field |
| `typ` field | `"typ":"JWT"` in the payload |
| `jti` source | Configurable header (default: `x-global-transaction-id`); random UUID fallback |
| `sub` claim | Application ID from `SharedContext.Metadata["x-wso2-application-id"]`; set by upstream auth policy (jwt-auth / client-secret-basic); requests lacking this value are rejected with 401 |
| `iss` claim | Gateway cert CN |
| Timestamps | Unix seconds (`time.Now().Unix()`) |
| Authorization scheme | `Cert` |

> **Note on scheme:** The scheme is `Cert`. The backend accepts `Cert` and `tls-client`.
> Timestamps (`iat`, `exp`) use Unix seconds.

## How It Works

```
API deploy
  [cert-signer GetPolicy]
    1. Receives certPem + keyPem (gateway resolves {{ secret "..." }} before the policy sees them)
    2. Parses cert → extracts CN as JWT issuer
    3. Parses RSA private key
    4. Stores PrivateKey + config in PolicyConfig (in-memory, per-deployment)

Per upstream request
  [cert-signer OnRequestHeaders]
    1. Reads application ID from SharedContext.Metadata["x-wso2-application-id"]
       (set by an upstream auth policy — jwt-auth or client-secret-basic)
       Returns 401 immediately when the value is absent or empty
    2. Reads jti from configured request header (default: x-global-transaction-id)
       Falls back to random UUID when header is absent
    3. Builds JWT: iss, sub (application ID), typ, iat, exp (iat + ttlSeconds), jti
    4. Signs with RS256 using stored RSA private key
    5. Sets Authorization: Cert <token> on upstream request

Backend (LBP service)
    1. Strips "Cert " prefix → extracts compact token
    2. Splits token into header.payload.signature (3 parts)
    3. Base64-decodes all three parts (standard base64 with padding)
    4. Verifies RS256 signature using the pre-shared certificate public key
    5. Checks iss matches configured cert CN
    6. Checks exp is in the future
    Returns: 200 OK / 401 Unauthorized
```

## JWT Structure

**Header** (base64-encoded):
```json
{"alg":"RS256"}
```

**Payload** (base64-encoded):
```json
{
  "iss": "<configured cert CN>",
  "sub": "<application ID from SharedContext.Metadata[\"x-wso2-application-id\"]>,"
  "typ": "JWT",
  "iat": 1731006941,
  "exp": 1731007241,
  "jti": "<x-global-transaction-id header value, or random UUID>"
}
```

**Resulting header:**
```
Authorization: Cert eyJhbGciOiJSUzI1NiJ9.<payload_base64>.<signature_base64>
```

## Configuration Parameters

| Parameter | Type | Default | Description |
|---|---|---|---|
| `certPem` | string | — | PEM-encoded X.509 certificate. Accepts `{{ secret "handle" }}`. Mutually exclusive with `certFile`. |
| `certFile` | string | `/etc/gateway/mtls/tls.crt` | Fallback path when `certPem` is not set. |
| `keyPem` | string | — | PEM-encoded RSA private key. Accepts `{{ secret "handle" }}`. Mutually exclusive with `keyFile`. |
| `keyFile` | string | `/etc/gateway/mtls/tls.key` | Fallback path when `keyPem` is not set. |
| `signatureHeader` | string | `Authorization` | HTTP request header to set with the JWT value. |
| `scheme` | string | `Cert` | Token prefix written before the JWT (`<scheme> <token>`). |
| `jtiHeader` | string | `x-global-transaction-id` | Incoming request header used as the JWT `jti` claim. Falls back to a random UUID when absent. |
| `issuer` | string | cert CN | JWT `iss` claim. Defaults to the certificate's Common Name. |
| `audience` | string | — | JWT `aud` claim. Omitted from the token when not set. |
| `ttlSeconds` | integer | `300` | JWT lifetime in seconds (`exp = iat + ttlSeconds`). Min 10, max 3600. |

**Parameter resolution order:** `certPem`/`keyPem` → `certFile`/`keyFile`. Misconfiguration
fails hard at **deploy time**, not per-request.

## Identity Model

LBP operates multiple TLS identities, each corresponding to a backend security domain:

| Gateway secret handle | Subject CN | Used by |
|---|---|---|
| `apip-identity-small-cert` / `apip-identity-small-key` | `apip-gateway-small` | Small plan APIs |
| `apip-identity-medium-cert` / `apip-identity-medium-key` | `apip-gateway-medium` | Medium plan APIs |
| `apip-identity-large-cert` / `apip-identity-large-key` | `apip-gateway-large` | Large plan APIs |

## API Definition Example

Example configuration:

```yaml
policies:
  - name: jwt-auth               # or client-secret-basic
    version: v1
    # jwt-auth/client-secret-basic set SharedContext.Metadata["x-wso2-application-id"]
    # cert-signer reads this value as the JWT sub claim
  - name: cert-signer
    version: v1
    params:
      certPem: '{{ secret "apip-identity-medium-cert" }}'
      keyPem:  '{{ secret "apip-identity-medium-key" }}'
      jtiHeader: x-global-transaction-id
      ttlSeconds: 300
```

> **cert-signer must run after an auth policy.** The auth policy sets
> `SharedContext.Metadata["x-wso2-application-id"]`; cert-signer reads this as the JWT `sub`
> claim. If the metadata key is absent or empty,
> cert-signer returns 401 immediately.

## Uploading Identities as Gateway Secrets

```bash
ap gateway secret create apip-identity-medium-cert --from-file gateway-medium.crt
ap gateway secret create apip-identity-medium-key  --from-file gateway-medium.key
```

## Backend Verification

The backend (`cert-signer-validation-backend`) verifies:

1. `Authorization` header present; scheme is `Cert`.
2. Token splits into exactly 3 parts separated by `.`.
3. All parts decoded with **standard base64** (with padding).
4. JWT header declares `alg: RS256`.
5. RS256 signature valid against the pre-shared certificate public key.
6. `iss` matches the configured certificate's Common Name.
7. `exp` is in the future.
