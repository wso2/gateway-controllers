---
title: "Overview"
---
# DPoP

## Overview

The DPoP policy enforces OAuth 2.0 Demonstrating Proof of Possession ([RFC 9449](https://www.rfc-editor.org/rfc/rfc9449)) on an API. A DPoP-bound access token is tied to a key pair the client holds. With every request, the client signs a short-lived JWT, the DPoP proof, and sends it in the `DPoP` header. The gateway accepts the request only when the proof was made for this exact request, by the key the access token is bound to. A leaked or stolen access token is useless without the client's private key.

The policy checks the proof and the binding. The access token itself is validated by [JWT Auth](../../../jwt-auth/v1.3/docs/jwt-authentication.md) or Opaque Token Auth, attached before this policy. The DPoP policy reads the token's confirmation claim, `cnf.jkt`, from what that policy recorded.

## Features

- Every check of RFC 9449 section 4.3: one `DPoP` header holding a `dpop+jwt` JWT, signed with an accepted asymmetric algorithm by the public key in its `jwk` header, with `htm`, `htu` and `iat` matching the request
- Binds the proof to the token: `ath` must be the hash of the access token, and the proof key's thumbprint (RFC 7638) must equal the token's `cnf.jkt`
- Works with JWT access tokens (JWT Auth) and introspected opaque tokens (Opaque Token Auth), from any authorization server that issues DPoP-bound tokens; tested with WSO2 Identity Server and Keycloak
- Refuses a DPoP-bound token sent as a bearer token, in every mode (RFC 9449 section 7.2)
- `required` mode for DPoP-only APIs, `optional` mode for APIs migrating from bearer tokens
- Single-use proofs, per replica or across every replica through Redis; flooding the replay cache never makes a captured proof replayable
- Optional server-issued nonces (RFC 9449 section 9), verifiable by every replica that shares the secret
- Self-explanatory refusals: the `WWW-Authenticate` challenge and the JSON body name the check that failed
- ES256/384/512, PS256/384/512, RS256/384/512 and Ed25519 (as `EdDSA` or the RFC 9864 `Ed25519`); HMAC and `none` are never accepted

## Quick Start

1. **Issue DPoP-bound tokens.** Configure the authorization server to bind access tokens to DPoP. For example, in WSO2 Identity Server select **DPoP** as the application's token binding type; in Keycloak turn on **Require DPoP bound tokens** for the client. The tokens then carry `cnf.jkt`.

2. **Attach the policies.** JWT Auth validates the token, then DPoP checks the proof. A DPoP client sends `Authorization: DPoP <token>`, so set JWT Auth's `authHeaderPrefix` to `DPoP`, and leave its `headerName` at the default, `Authorization`. The DPoP policy needs no parameters.

   ```yaml
   apiVersion: gateway.api-platform.wso2.com/v1
   kind: RestApi
   metadata:
     name: orders-api
   spec:
     displayName: Orders API
     version: v1.0
     context: /orders/$version
     upstream:
       main:
         url: http://orders-backend:9080/api/v1
     operations:
       - method: GET
         path: /orders
         policies:
           - name: jwt-auth
             version: v1
             params:
               issuers: [PrimaryIDP]
               authHeaderPrefix: DPoP
           - name: dpop
             version: v0
   ```

3. **Call it.** For every request the client makes a new proof with `htm` set to the method, `htu` to the URL without query, `iat` to now, a unique `jti`, and `ath` to the base64url SHA-256 hash of the access token:

   ```http
   GET /orders/v1.0/orders HTTP/1.1
   Host: api.example.com
   Authorization: DPoP eyJhbGciOiJSUzI1NiIsInR5cCI6ImF0K2p3dCJ9...
   DPoP: eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7...
   ```

   A refusal tells the client what to fix, for example:

   ```http
   HTTP/1.1 401 Unauthorized
   WWW-Authenticate: DPoP error="invalid_dpop_proof", error_description="htu does not match the request URI", algs="ES256 ES384 ES512 PS256 PS384 PS512 RS256 RS384 RS512 EdDSA Ed25519"
   Content-Type: application/json

   {"error":"invalid_dpop_proof","error_description":"htu does not match the request URI"}
   ```

Running more than one gateway runtime replica, or behind a load balancer that terminates TLS? Read [Production Deployment](#production-deployment).

## Configuration

User parameters are set per API in the API definition. System parameters are set by the administrator under `[policy_configurations.dpop_v0]` in the gateway's `config.toml`.

### User Parameters (API Definition)

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `mode` | enum | `required` | `required` accepts only DPoP-bound tokens with a valid proof. `optional` also lets unbound tokens through as bearer tokens (see [Example 3](#example-3-migrate-an-api-to-dpop)). A DPoP-bound token sent as a bearer token is refused in both modes. |
| `allowedAlgorithms` | array | all supported | Proof signature algorithms accepted, from `ES256`, `ES384`, `ES512`, `PS256`, `PS384`, `PS512`, `RS256`, `RS384`, `RS512`, `EdDSA`, `Ed25519`. Sent to clients in the challenge's `algs`. For FAPI 2.0, use `[PS256, ES256, Ed25519, EdDSA]`. |
| `proofMaxAge` | string | `1m` | How long after its `iat` a proof is accepted. A proof is made for one request, so keep it short. |
| `requireNonce` | boolean | `false` | Require gateway-issued nonces in proofs (see [Nonces](#nonces)). |
| `htuOrigins` | array | `[]` | Public origins (`scheme://host[:port]`) a proof's `htu` may use. Set it when clients reach the gateway through a different scheme or host, such as a load balancer that terminates TLS. Empty: the `htu` must match the scheme and host the gateway receives. |
| `forwardProof` | boolean | `false` | Forward the `DPoP` header to the backend. By default it is removed. |

A value the policy cannot use, such as an unknown algorithm or an `htuOrigins` entry with a path, is refused when the API is deployed.

### System Parameters (config.toml)

| Key under `[policy_configurations.dpop_v0]` | Default | Description |
|-----|---------|-------------|
| `clockskew` | `"30s"` | Clock difference tolerated with clients (proof `iat`) and between replicas (nonce age). |
| `noncelifetime` | `"5m"` | How long a gateway-issued nonce is valid. |
| `noncesecret` | `""` | Secret, at least 32 bytes, that signs nonces. Set the same value on every replica (see [Secrets](#secrets-and-configuration)). Empty: each process uses its own random key, which works only with one replica. |
| `replaycachemaxsize` | `100000` | Proof identifiers each replica's in-memory cache can hold, across all APIs. Entries are never dropped before they expire; while the cache is full, DPoP requests are refused with `503`. About 150 bytes each, so the default uses about 15 MB. |
| `replay_store` | `"memory"` | `memory`: each replica remembers the proofs it accepted. `redis`: every replica shares one record, so a proof is accepted once across the deployment. |
| `[…dpop_v0.redis]` | | Used when `replay_store = "redis"`. Same keys as the rate-limit policies' Redis block: `host` (`localhost`), `port` (`6379`), `username`, `password`, `db` (`0`), `key_prefix` (`"dpop:v0:"`), `failure_mode` (`"closed"`), `connection_timeout` (`"5s"`), `read_timeout` (`"1s"`), `write_timeout` (`"1s"`), `pool_size` (`0` = go-redis default), and `[…dpop_v0.redis.tls]` with `enabled`, `ca_file`, `server_name`, `insecure_skip_verify`, `cert_file`, `key_file`. |
| `redis.failure_mode` | `"closed"` | While Redis is unreachable: `closed` refuses DPoP requests with `503`, so no proof is accepted unrecorded; `local` keeps serving: each replica also records every proof it accepts in its own memory, and relies on that record alone while Redis is down, so replays to the same replica are still refused, before, during and after an outage. |

#### Sample System Configuration

```toml
[policy_configurations.dpop_v0]
noncesecret = '{{ env "APIP_GW_DPOP_NONCE_SECRET" }}'
replay_store = "redis"

[policy_configurations.dpop_v0.redis]
host = "redis.gateway.svc.cluster.local"
port = 6379
password = '{{ env "APIP_GW_DPOP_REDIS_PASSWORD" }}'
failure_mode = "closed"

[policy_configurations.dpop_v0.redis.tls]
enabled = true
ca_file = "/etc/policy-engine/certs/redis-ca.pem"
```

**Note:** Include the policy in the gateway build (`build.yaml`):

```yaml
- name: dpop
  gomodule: github.com/wso2/gateway-controllers/policies/dpop@v0
```

## Reference Scenarios

### Example 1: DPoP With Introspected Opaque Tokens

The introspection response carries `cnf.jkt` for a DPoP-bound token.

```yaml
      policies:
        - name: opaque-token-auth
          version: v1
          params:
            issuers: [PrimaryIntrospection]
            authHeaderPrefix: DPoP
        - name: dpop
          version: v0
```

### Example 2: Behind a Load Balancer That Terminates TLS

Clients call `https://api.example.com`; the load balancer forwards to the gateway over HTTP on an internal host. The proofs name the public origin, so list it:

```yaml
        - name: dpop
          version: v0
          params:
            htuOrigins: [https://api.example.com]
```

### Example 3: Migrate an API to DPoP

In `optional` mode, existing clients keep sending bearer tokens while new clients use DPoP. A DPoP-bound token still needs a valid proof, and is refused as a bearer token. The access-token policy must accept both schemes: JWT Auth does when `authHeaderPrefix` is empty and the gateway-wide `authheaderscheme` is empty.

```toml
[policy_configurations.jwtauth_v1]
authheaderscheme = ""
```

```yaml
        - name: jwt-auth
          version: v1
          params:
            issuers: [PrimaryIDP]
            authHeaderPrefix: ""
        - name: dpop
          version: v0
          params:
            mode: optional
```

With `authheaderscheme` empty, every JWT Auth instance that does not set `authHeaderPrefix` accepts any scheme. Set `authHeaderPrefix: Bearer` on APIs that must keep requiring `Bearer`. Wherever the DPoP policy is attached, a DPoP-bound token sent as a bearer token is still refused.

### Example 4: FAPI 2.0 Profile

```yaml
        - name: dpop
          version: v0
          params:
            allowedAlgorithms: [PS256, ES256, Ed25519, EdDSA]
            proofMaxAge: 30s
            requireNonce: true
```

## How It Works

The policy runs in the request-header phase, after the access-token policy.

1. **Find the binding.** It reads the newest authenticated layer of the authentication context that carries `cnf`. A `cnf` without `jkt` (for example an mTLS-bound token's `x5t#S256`) is not a DPoP binding. A binding it cannot read reliably is refused, not treated as unbound: a `cnf` that is not an object, a `jkt` that is not a non-empty string, or an introspected `token_type` of `DPoP` without `cnf.jkt`. With no authenticated layer, it refuses the request: the policy was attached without an access-token policy before it.
2. **Check the scheme.** More than one `Authorization` header is refused with `400`. A bound token must use the `DPoP` scheme. An unbound `Bearer` token is refused in `required` mode and passes in `optional` mode, where a stray `DPoP` header is removed. An unbound token with the `DPoP` scheme is refused.
3. **Verify the proof.** One `DPoP` header of at most 8 KB; `typ` is `dpop+jwt`; `alg` is accepted; no `crit` header; `jwk` is a public key matching `alg` (EC P-256/P-384/P-521 on the curve, RSA 2048 to 8192 bits, or Ed25519) with no private members, and the signature verifies with it. The key comes only from `jwk`; `kid`, `jku`, `x5u` and `x5c` are never used. Then `jti`, `htm`, `htu`, `iat` and `ath` are present; `htm` equals the method; `htu` matches the request URI ([Matching htu](#matching-htu)); `iat` is at most `clockskew` in the future and `proofMaxAge` plus `clockskew` in the past; the nonce is valid (with `requireNonce`); `ath` is the access token's hash; and the `jwk` thumbprint equals `cnf.jkt`.
4. **Record it.** The proof's `jti` is recorded for this key until the proof would expire anyway. A `jti` seen before is a replay. Recording happens only after every other check passes, so a refused proof never uses one up.
5. **Continue.** The `DPoP` header is removed (unless `forwardProof`), and the key thumbprint is stored in the shared metadata as `dpop.jkt` for later policies. `Authorization` and the access-token policy's authentication context are left as they are.

### Matching `htu`

The `htu` claim and the request URI are compared after RFC 3986 normalization: scheme and host are lowercased, a default port is dropped, percent-encoded unreserved characters are decoded, other percent-encodings are uppercased, `.` and `..` segments are removed, and an empty path becomes `/`. Query and fragment are ignored. The path is otherwise case-sensitive, and a trailing slash matters. A host must be ASCII; clients send internationalized names in punycode.

### Nonces

With `requireNonce: true`, a proof without a valid nonce is refused with `error="use_dpop_nonce"`, and the response carries a fresh nonce in `DPoP-Nonce`. The client repeats the request with a new proof containing it. Every other refusal also carries a fresh nonce, and once a client's nonce is past half its lifetime the successful response hands over the next one, so a busy client never has to retry. Responses carrying a nonce are sent with `Cache-Control: no-store` (RFC 9449 section 8.2). With `requireNonce` off, the policy never sends a nonce.

A nonce is its issue time signed with HMAC-SHA256 under `noncesecret`; nothing is stored, and any replica with the same secret accepts it.

## Production Deployment

The policy runs in the policy engine, inside every gateway runtime pod. Gateway runtimes in production run as two or more replicas, often autoscaled, behind a load balancer. Four things then need attention.

| | Single replica | Several replicas |
|---|---|---|
| Replay protection | `memory` (default) | `replay_store = "redis"`, or accept that a captured proof can be used once per replica within `proofMaxAge` |
| `noncesecret` (only with `requireNonce`) | optional | required, the same on every replica |
| `htu` behind a load balancer | `htuOrigins` when the load balancer terminates TLS or changes the host | same |
| Clocks | NTP on the gateway nodes | NTP on every node |

The policy keeps no state in the gateway database. Its configuration reaches every runtime the same way as any other policy's, so controller replicas and the database need nothing DPoP-specific.

### Replay Protection Across Replicas

With the default `memory` store, each replica remembers only the proofs it accepted. A proof captured in transit could be replayed once to each other replica while it is fresh. For strict single use across the deployment, share the record in Redis:

```toml
[policy_configurations.dpop_v0]
replay_store = "redis"

[policy_configurations.dpop_v0.redis]
host = "my-redis.example.internal"
password = '{{ env "APIP_GW_DPOP_REDIS_PASSWORD" }}'
```

- **One command per verified proof.** `SET key NX PX <ttl>` is atomic, so of two copies of a proof sent to different replicas at the same moment, exactly one is accepted. Keys expire on their own, after `proofMaxAge` plus `clockskew` (90 seconds by default). Memory used is about 200 bytes × DPoP requests per second × 90 seconds.
- **Use an HA Redis endpoint.** The policy connects to one endpoint: a managed service's primary endpoint (Amazon ElastiCache or MemoryDB, Azure Cache for Redis, Google Memorystore) or a Redis behind a proxy. Redis Sentinel and Cluster protocols are not supported. You can share the Redis the rate-limit policies use; give each gateway deployment its own `key_prefix`.
- **Set `maxmemory-policy noeviction`** (or use a dedicated instance). A Redis that evicts keys to free memory could forget a live proof, which would make it replayable. With `noeviction`, a full Redis refuses writes and the policy follows `failure_mode`.
- **Choose `failure_mode`.** `closed` (default) refuses DPoP requests with `503` while Redis is unreachable. `local` keeps serving, falling back to per-replica protection, and is the choice when availability matters more than cross-replica replay protection. In `local` mode each replica also records every proof it accepts in its own memory (bounded by `replaycachemaxsize`), so its history survives the switch to and from Redis. Either way the gateway logs `dpop: cannot record proof identifiers in Redis` (at most once a minute per replica); alert on it.
- **Failover.** Redis replicates asynchronously; a proof recorded just before a failover may be lost, and could be accepted once more within its lifetime.
- **TLS.** Set `[…dpop_v0.redis.tls] enabled = true`; leave `ca_file` empty for managed services with public CAs. Certificate files must be mounted in the runtime container.

### Secrets and Configuration

Put `noncesecret` and the Redis password in the gateway's secret store and reference them from `config.toml` with an environment token that has **no default**, such as `'{{ env "APIP_GW_DPOP_NONCE_SECRET" }}'`. Without a default, a missing variable stops the gateway at startup instead of silently running with a per-process nonce key. The policy also refuses a nonce secret shorter than 32 bytes. Generate one with `openssl rand -base64 48`.

- **Docker Compose:** add the variables to `api-platform.env`, which both containers load.
- **Kubernetes (Helm):** the chart renders `gateway.config.policy_configurations` into `config.toml`, mounted by both the gateway controller and the runtime. Both resolve every token at startup, so inject the variables into **both** deployments, or the controller fails to start:

  ```yaml
  gateway:
    config:
      policy_configurations:
        dpop_v0:
          noncesecret: '{{ env "APIP_GW_DPOP_NONCE_SECRET" }}'
          replay_store: redis
          redis:
            host: redis.gateway.svc.cluster.local
            password: '{{ env "APIP_GW_DPOP_REDIS_PASSWORD" }}'
    controller:
      deployment:
        extraEnv: &dpopSecrets
          - name: APIP_GW_DPOP_NONCE_SECRET
            valueFrom: {secretKeyRef: {name: gateway-dpop, key: nonce-secret}}
          - name: APIP_GW_DPOP_REDIS_PASSWORD
            valueFrom: {secretKeyRef: {name: gateway-dpop, key: redis-password}}
    gatewayRuntime:
      deployment:
        extraEnv: *dpopSecrets
  ```

- **Gateway Operator:** put the same values in the ConfigMap the `APIGateway` references with `spec.configRef` (or the `Gateway` with the `gateway.api-platform.wso2.com/helm-values-configmap` annotation).
- **Immutable gateway:** bake or mount `config.toml` with the same tokens, and provide the variables to the containers.

Rotating `noncesecret` invalidates outstanding nonces; clients get one `use_dpop_nonce` challenge each and continue.

### Load Balancers, Ingress and `htu`

A proof names the URL the client called. The gateway compares it with the scheme, host and path it receives. Wherever something in front of the gateway changes one of these, tell the policy the public origin with `htuOrigins`, and never rewrite the path.

| In front of the gateway | What to do |
|---|---|
| Nothing, or a TCP / TLS-passthrough load balancer (AWS NLB, Azure Load Balancer, OpenShift passthrough Route) | Nothing; the gateway sees what the client sent. |
| TLS terminated before the gateway: Kubernetes Ingress, Gateway API, AWS ALB, Azure Application Gateway, GCP HTTPS load balancer, OpenShift edge Route | Set `htuOrigins: [https://<public host>]`. The gateway receives `http`, and possibly an internal host. |
| TLS re-encrypted to the gateway (OpenShift reencrypt Route, ALB with HTTPS targets) | Set `htuOrigins` unless the host header is preserved and the scheme stays `https`. |
| Path rewritten (for example an Ingress `rewrite-target`, or a prefix stripped) | Not supported: the proof's path no longer matches. Route on the full path instead. |

Proofs are 0.5 to 3 KB; the default header limits of common load balancers and ingress controllers (8 KB or more) are enough. Forwarded headers (`X-Forwarded-Proto`, `X-Forwarded-Host`) are not trusted for this check, so a client cannot spoof the origin it signed.

### Clocks

Proof age is judged by comparing the client's `iat` with the gateway's clock, with `clockskew` (30 seconds) tolerance, so both clocks must be right. Run NTP on every gateway node; managed Kubernetes services (EKS, AKS, GKE) and OpenShift do so by default. Clients must keep their clocks synchronized too: a client whose clock is off by more than `clockskew` is refused with `iat is in the future` or `proof has expired (iat is too old)`. `requireNonce` adds a second freshness check by the gateway's clock; it does not replace the `iat` check, so it does not help a client with a wrong clock.

### Sizing

The in-memory replay cache holds at most `replaycachemaxsize` entries per runtime replica, about 15 MB at the default, well within the recommended runtime memory (512 Mi request, 2 Gi limit). It holds a little over 1,100 DPoP requests per second per replica with the default one-minute window; raise it in proportion for more, or shorten `proofMaxAge`. When it fills, DPoP requests get `503` and the gateway logs `dpop: replay cache is full`; alert on it. Verifying a proof, including its signature, takes about 40 to 70 microseconds of CPU for every supported algorithm.

### Browser Clients

A browser app reads `WWW-Authenticate` and `DPoP-Nonce` only when the CORS policy lists them in `exposeHeaders`, and sends `DPoP` only when it is in `allowHeaders`.

## Troubleshooting

Each refusal names the check that failed in `error_description`, in both the `WWW-Authenticate` header and the JSON body. Descriptions are fixed texts; nothing from the request is echoed back.

| Status, `error` | `error_description` | Fix |
|---|---|---|
| 401 `invalid_dpop_proof` | `missing DPoP header`, `more than one DPoP header` | Send exactly one `DPoP` header. |
| 401 `invalid_dpop_proof` | `proof is not a well-formed JWT`, `typ must be dpop+jwt`, `crit header is not supported`, `jwk header is missing` | Build the proof as RFC 9449 section 4.2 describes: header `{"typ":"dpop+jwt","alg":...,"jwk":<public key>}`. |
| 401 `invalid_dpop_proof` | `alg is not one of the accepted algs` | Sign with an algorithm from the challenge's `algs`. |
| 401 `invalid_dpop_proof` | `jwk is not a public key usable with alg` | Put the public key (no private members) in `jwk`, of the type and curve `alg` needs. RSA keys must be 2048 bits or more. |
| 401 `invalid_dpop_proof` | `signature does not verify with the jwk` | Sign the proof with the private key of the `jwk` it carries. |
| 401 `invalid_dpop_proof` | `jti is missing or longer than 512 characters`, `htm or htu is missing`, `iat is missing or not a number`, `ath is missing` | Include every required claim. |
| 401 `invalid_dpop_proof` | `htm does not match the request method` | Set `htm` to the request's method, in upper case. |
| 401 `invalid_dpop_proof` | `htu does not match the request URI` | Set `htu` to the URL called, without query. Behind a load balancer that terminates TLS, set `htuOrigins` (see [Load Balancers](#load-balancers-ingress-and-htu)). |
| 401 `invalid_dpop_proof` | `iat is in the future`, `proof has expired (iat is too old)` | Create a new proof for every request, with `iat` set to now. Synchronize the client's clock (NTP); the gateway allows `clockskew` (30 seconds) of difference. |
| 401 `invalid_dpop_proof` | `ath does not match the access token` | Hash the exact access token sent in `Authorization`. |
| 401 `invalid_dpop_proof` | `proof has already been used` | Create a new proof, with a new `jti`, for every request, including retries. |
| 401 `use_dpop_nonce` | `resource server requires nonce in DPoP proof` | Retry with a new proof whose `nonce` is the `DPoP-Nonce` from the response. |
| 401 `invalid_token` | `invalid DPoP key binding` | Sign the proof with the key the token was issued for; if it persists, check the token's `cnf` claim. |
| 401 `invalid_token` | `access token is not DPoP-bound` | Request a DPoP-bound token (send a proof to the token endpoint), or use the `Bearer` scheme on an `optional` API. |
| 401 `invalid_token` (in a `Bearer` challenge) | `DPoP-bound access token requires the DPoP authorization scheme`, `DPoP-bound access token required` | Send `Authorization: DPoP <token>` with a proof. |
| 401 `invalid_token` | `access token required` | Attach JWT Auth or Opaque Token Auth before the DPoP policy. |
| 400 `invalid_request` | `multiple methods used to include access token` | Send one `Authorization` header. |
| 503 `temporarily_unavailable` | `DPoP replay protection is unavailable; retry later` | The replay cache is full or Redis is unreachable. See [Sizing](#sizing) and [Replay Protection Across Replicas](#replay-protection-across-replicas). |

A refusal from the access-token policy before the DPoP policy, such as an expired token or a `Bearer` scheme where JWT Auth expects `DPoP`, comes from that policy and carries no DPoP challenge. The gateway's debug log (`level = "debug"` under `[policy_engine.logging]`) shows the detail behind each refusal.

## Notes

- **Per-replica replay detection** (the `memory` store) allows a captured proof to be used once per replica within `proofMaxAge`; use Redis to close that, or keep `proofMaxAge` short.
- **Use HTTPS.** A proof does not protect the request body or the response (RFC 9449 section 11.7).
- **Keep access tokens short-lived.** Without nonces, a client whose key is stolen can pre-generate proofs (RFC 9449 section 11.2).
- **The token must arrive in `Authorization`.** RFC 9449 carries a DPoP-bound token there, and the policy checks `ath` against that header. Keep the access-token policy's `headerName` at its default, `Authorization`, so both policies judge the same token.
- **What the backend receives.** The DPoP policy removes the `DPoP` header and leaves `Authorization` to the access-token policy's forwarding options; for example, JWT Auth's `forwardTokenStripScheme: true` forwards the bare token.
- **Long-lived connections.** The proof is checked when a request starts; a streamed response or a WebSocket stays open past the proof's lifetime.
- **Analytics.** The access-token policy's authentication context is kept; the DPoP policy adds a layer of type `dpop` only when it refuses a request.

## Related Policies

- **JWT Auth** and **Opaque Token Auth**: validate the access token; attach one before this policy
- **Mutual TLS Auth**: binds tokens to a client certificate instead (RFC 8705); a token bound with `cnf` `x5t#S256` is not DPoP-bound and must be enforced with mTLS
- **CORS**: expose `WWW-Authenticate` and `DPoP-Nonce`, and allow the `DPoP` header, for browser clients
