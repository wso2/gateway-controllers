---
title: "Overview"
---
# WebSub HMAC Auth

## Overview

The **WebSub HMAC Auth** policy validates the HMAC signature included in incoming
[WebSub](https://www.w3.org/TR/websub/) hub event notification requests. When a
Webhook publisher delivers content to a WebSub API, it signs the raw request body
with the shared secret that was agreed upon at subscription time and places the
signature in the `X-Hub-Signature-256` (or `X-Hub-Signature`) header.

This policy recomputes the HMAC over the buffered request body using all active
webhook secrets registered for the API and compares each result to the provided
signature using a constant-time comparison. The request is accepted if any secret
produces a matching signature. Requests with missing, malformed, or invalid
signatures are rejected with `401 Unauthorized` before they reach the upstream
service.

## Features

- HMAC-SHA256 verification (default), with SHA-512 and SHA-1 (legacy) support
- Early rejection in the **header phase** when the signature header is absent
- Full body-phase HMAC verification using constant-time comparison to prevent timing attacks
- Configurable signature header name for non-standard hub implementations
- Algorithm prefix validation (`sha256=...`, `sha1=...`, `sha512=...`)

## Configuration

### User Parameters (API Definition)

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `algorithm` | string | No | `sha256` | HMAC algorithm. One of `sha256`, `sha512`, or `sha1` (legacy). |
| `signatureHeader` | string | No | `X-Hub-Signature-256` (sha256/sha512) or `X-Hub-Signature` (sha1) | HTTP header name that carries the hub's signature. |

> **Note:** The shared secrets are **not** configured as policy parameters. Secret lifecycle (registration, rotation, and revocation) is handled outside this gateway runtime policy through the platform's secret management capabilities.

## How It Works

1. **Header phase** – The policy checks whether the configured `signatureHeader` is
   present. If absent, the request is rejected immediately with `401 Unauthorized`
   before the body is buffered.

2. **Body phase** – Once the kernel has buffered the full request body:
   - The signature header value is parsed to extract the algorithm prefix and hex digest
     (format: `<algorithm>=<hexdigest>`).
   - The algorithm prefix is verified against the configured `algorithm`.
   - The HMAC is recomputed over the raw body bytes using each active secret registered for the API.
   - The computed hex digest is compared to the provided one using `hmac.Equal`
     (constant-time) to prevent timing attacks.
   - If the signatures match, the request proceeds to the upstream service.
   - If they do not match, a `401 Unauthorized` response is returned.

## Reference Scenarios

### Example 1: Basic WebSub Subscriber Endpoint (SHA-256)

```yaml
apiVersion: gateway.api-platform.wso2.com/v1
kind: WebSubApi
metadata:
  name: repo-watcher-v1-0
spec:
  displayName: repo-watcher
  version: v1.0
  context: /repos
  allChannels:
    on_message_received:
      policies:
        - name: websub-hmac-auth
          version: v1
  channels:
    issues: {}
  deploymentState: deployed
```

### Example 2: Legacy Hub Using SHA-1

Some older WebSub hubs still use `X-Hub-Signature` with SHA-1. Configure the policy
to match:

```yaml
  policies:
    - name: websub-hmac-auth
      version: v1
      params:
        algorithm: sha1
        # signatureHeader defaults to X-Hub-Signature for sha1
```

### Example 3: Custom Signature Header

If your hub uses a non-standard header name:

```yaml
  policies:
    - name: websub-hmac-auth
      version: v1
      params:
        algorithm: sha256
        signatureHeader: X-WebSub-Signature
```

## Error Responses

All error responses are returned as JSON with `Content-Type: application/json`.

| Scenario | Status | Message |
|----------|--------|---------|
| Signature header absent | 401 | `missing signature header: <header-name>` |
| Malformed signature header value | 401 | `malformed signature header` |
| Algorithm prefix mismatch | 401 | `algorithm mismatch: expected <x>, got <y>` |
| HMAC digest does not match | 401 | `invalid HMAC signature` |

**Example error body:**
```json
{
  "error": "Unauthorized",
  "message": "invalid HMAC signature"
}
```

## Security Considerations

- **Secret length** – Use at least 16 characters of high entropy (NIST SP 800-107 recommends ≥ 128-bit secrets for HMAC).
- **HTTPS only** – Ensure the subscriber callback URL uses HTTPS to prevent the secret from being exposed to network eavesdroppers.
- **Algorithm choice** – Prefer `sha256` (default) or `sha512`. Avoid `sha1` unless required for compatibility with legacy hubs that do not support SHA-256.
- **Secret rotation** – When rotating the shared secret, coordinate with the hub to resubscribe with the new secret before invalidating the old one.

## Gateway Module Reference

```yaml
- name: websub-hmac-auth
  gomodule: github.com/wso2/gateway-controllers/policies/websub-hmac-auth@v1
```
