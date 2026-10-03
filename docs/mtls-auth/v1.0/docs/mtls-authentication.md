---
title: "Overview"
---
# Mutual TLS Authentication

## Overview

The Mutual TLS Authentication policy authenticates API callers by the client certificate they present. The gateway's HTTPS listener requests a client certificate, and the policy decides whether the caller is one the API accepts. To be accepted, the certificate must chain to a client certificate authority that the API names from the gateway's client-CA pool. The API can further require the certificate to carry a given subject alternative name (SAN) or to have a given thumbprint.

When the gateway sits behind a load balancer that terminates TLS, the load balancer can relay the client certificate in a request header. The policy trusts that header only when the connection it arrived on is authenticated as a known load balancer, called a relay entry in the pool.

## Features

- Authenticates callers by the client certificate presented on the TLS connection
- Accepts certificates from the client certificate authorities an API names in `accept`, chosen from the gateway's client-CA pool. When `accept` is omitted, every client authority in the pool is accepted
- Narrows an accepted authority to certificates with specific URI or DNS SANs, or to specific SHA-256 thumbprints
- Accepts a client certificate relayed in a header by a load balancer, but only on a connection the gateway has authenticated as that load balancer
- Denies a connection whose own certificate is untrusted, expired, not yet valid or unreadable, whatever a header carries
- Controls whether `X-Forwarded-Client-Cert` reaches the backend (`forwardCertificate`)
- Returns one uniform failure response for every denial; the reason appears only in logs and traces
- Sets an authentication context (subject, issuing authority, thumbprint and certificate details) for later policies
- Re-reads the client-CA pool on every request, so pool changes take effect without redeploying the API

## Prerequisites

The policy holds no certificates. It refers to entries of the gateway's client-CA pool by name, so add those entries through the gateway controller's certificate API before deploying an API that uses the policy.

Upload a client certificate authority with `usage: downstream`. The `role` defaults to `client`.

```bash
curl -X POST http://localhost:9090/api/management/v1/certificates \
  -u admin:<password> \
  -H "Content-Type: application/json" \
  -d '{
    "name": "partner-a",
    "usage": "downstream",
    "role": "client",
    "certificate": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"
  }'
```

When a load balancer relays client certificates in a header, upload the authority that issues the load balancer's own certificate with `role: relay`. An optional `match` narrows the relay entry to connections whose certificate carries one of the listed SANs.

```bash
curl -X POST http://localhost:9090/api/management/v1/certificates \
  -u admin:<password> \
  -H "Content-Type: application/json" \
  -d '{
    "name": "edge-lb",
    "usage": "downstream",
    "role": "relay",
    "match": { "dnsSANs": ["lb.example.com"] },
    "certificate": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"
  }'
```

A relay entry identifies a load balancer that may forward client certificates; it is not itself an accepted caller. An `accept` entry may name only a `role: client` entry; naming a relay entry is refused at deployment.

## Configuration

The Mutual TLS Authentication policy uses a two-level configuration model. User parameters are configured per API in the API definition YAML, and system parameters are resolved from the gateway configuration.

### User Parameters (API Definition)

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `accept` | array | No | - | Client certificate authorities this policy accepts, evaluated in order; the first matching entry authenticates the request. Omit to accept a certificate issued by any client authority in the pool. An empty list is refused at deployment. |
| `accept[].ca` | string | Yes | - | Name of a `role: client` entry in the gateway's client-CA pool. |
| `accept[].match.uriSANs` | array | No | - | Accepted URI SANs. The certificate must carry at least one of them. |
| `accept[].match.dnsSANs` | array | No | - | Accepted DNS SANs. The certificate must carry at least one of them. When both lists are set, the certificate must satisfy both. A `match` must list at least one SAN. |
| `accept[].thumbprints` | array | No | - | Accepted SHA-256 certificate thumbprints: 64 hex characters, with or without colon separators and a `sha256:` prefix. The policy compares thumbprints as 64 lowercase hex characters. One given in another form still works; the deploy response shows the converted form with an `MTLS_THUMBPRINT_NORMALISED` warning, and the stored definition keeps the form you sent. When set, the list must not be empty. |
| `forwardCertificate` | boolean | No | `true` | If `true`, the backend receives `X-Forwarded-Client-Cert` describing the certificate the caller authenticated with. Set to `false` to remove it. The relayed certificate header never reaches the backend. |
| `onFailureStatusCode` | integer | No | `401` | HTTP status code returned on authentication failure (400-599). |
| `errorMessageFormat` | enum | No | `"json"` | Format of the failure response. One of `json` (structured error), `plain` (plain text) or `minimal` (the body `Unauthorized` only). Any other value is refused at deployment. |
| `errorMessage` | string | No | `"Authentication failed"` | Message included in the failure response body. |

SAN values are compared exactly; there is no wildcard or pattern matching. A malformed `accept` list or `forwardCertificate` value is refused at deployment; nothing is silently ignored.

### System Parameters (config.toml)

These parameters are set by the administrator in the gateway configuration and apply to every API on the gateway. They cannot be set in an API definition. When the section isn't in your `config.toml`, add it; a key you leave out keeps its default.

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `headerName` | string | No | `"X-WSO2-CLIENT-CERTIFICATE"` | HTTP header in which a trusted front proxy relays the client certificate. Read from the `name` key of the `[router.downstream_tls.client_certificate_header]` section in `config.toml`. |
| `trustAny` | boolean | No | `false` | If `true`, the certificate header is trusted on any connection whose own certificate was not rejected, not only on a connection from a `role: relay` entry. **Enable it only when nothing but a trusted front proxy can reach the gateway.** Read from the `trust_any` key of the same section. |

> **Warning:** With `trust_any` enabled, any client that can open a connection to the gateway can send a certificate in the header without being a relay. The certificate must still be valid and satisfy the API's `accept`, but a certificate is public: a client that has an accepted caller's certificate, even without its private key, is authenticated as that caller. Enable it only when the gateway is reachable from nothing but a trusted front proxy. While it is on, the gateway logs a warning at startup and every `mtls-auth` deployment carries a `HEADER_CERT_BYPASS_ACTIVE` warning.

#### Sample System Configuration

```toml
[router.downstream_tls.client_certificate_header]
name = "X-WSO2-CLIENT-CERTIFICATE"
trust_any = false
```

**Note:**

Inside the `gateway/build.yaml`, ensure the policy module is added under `policies:`:

```yaml
- name: mtls-auth
  gomodule: github.com/wso2/gateway-controllers/policies/mtls-auth@v1
```

## Reference Scenarios

Each example is a REST API definition. Deploy it with `POST http://localhost:9090/api/management/v1/rest-apis`, the admin credentials (`-u admin:<password>`) and `Content-Type: application/yaml`, as shown in [Gateway at the edge](#gateway-at-the-edge). `sample-backend:9080` stands for your own backend.

### Example 1: Accept Any Pooled Client Authority

With no parameters, the policy accepts a certificate issued by any `role: client` entry in the pool.

```yaml
apiVersion: gateway.api-platform.wso2.com/v1
kind: RestApi
metadata:
  name: mtls-auth-basic-api
spec:
  displayName: mTLS Auth Basic API
  version: v1.0
  context: /mtls-basic/$version
  vhosts:
    main: mtls-basic.example.com
  upstream:
    main:
      url: http://sample-backend:9080/api/v1
  policies:
    - name: mtls-auth
      version: v1
  operations:
    - method: GET
      path: /orders
```

### Example 2: One Authority Narrowed by URI SAN

Accept only certificates issued by `partner-a` that carry the URI SAN `urn:partner-a:payments`.

```yaml
apiVersion: gateway.api-platform.wso2.com/v1
kind: RestApi
metadata:
  name: mtls-auth-san-api
spec:
  displayName: mTLS Auth SAN API
  version: v1.0
  context: /mtls-san/$version
  vhosts:
    main: mtls-san.example.com
  upstream:
    main:
      url: http://sample-backend:9080/api/v1
  policies:
    - name: mtls-auth
      version: v1
      params:
        accept:
          - ca: partner-a
            match:
              uriSANs:
                - "urn:partner-a:payments"
  operations:
    - method: POST
      path: /payments
```

### Example 3: Several Partners on One API

Entries are tried in order and the first one the certificate satisfies authenticates the request. Here `partner-a` is narrowed to certificates carrying the DNS SAN `orders.partner-a.example`, and any certificate issued by `partner-b` is accepted. The deploy response carries an `MTLS_ACCEPT_UNNARROWED` warning for the `partner-b` entry, because it accepts every certificate that authority issues.

```yaml
apiVersion: gateway.api-platform.wso2.com/v1
kind: RestApi
metadata:
  name: mtls-auth-partners-api
spec:
  displayName: mTLS Auth Partners API
  version: v1.0
  context: /mtls-partners/$version
  vhosts:
    main: mtls-partners.example.com
  upstream:
    main:
      url: http://sample-backend:9080/api/v1
  policies:
    - name: mtls-auth
      version: v1
      params:
        accept:
          - ca: partner-a
            match:
              dnsSANs:
                - "orders.partner-a.example"
          - ca: partner-b
  operations:
    - method: GET
      path: /orders
```

### Example 4: Thumbprint Pinning

Accept only the listed certificates from `partner-b`. When a pinned caller renews its certificate, list the new thumbprint alongside the old one, let the caller switch, then remove the old one.

To print a certificate's thumbprint as 64 lowercase hex characters:

```bash
openssl x509 -in client.pem -noout -fingerprint -sha256 | cut -d= -f2 | tr -d : | tr A-F a-f
```

```yaml
apiVersion: gateway.api-platform.wso2.com/v1
kind: RestApi
metadata:
  name: mtls-auth-pinned-api
spec:
  displayName: mTLS Auth Pinned API
  version: v1.0
  context: /mtls-pinned/$version
  vhosts:
    main: mtls-pinned.example.com
  upstream:
    main:
      url: http://sample-backend:9080/api/v1
  policies:
    - name: mtls-auth
      version: v1
      params:
        accept:
          - ca: partner-b
            thumbprints:
              - "5b0d9c2f7e4a1b8c3d6e9f0a2b4c6d8e0f1a3b5c7d9e1f2a4b6c8d0e2f4a6b8c"
  operations:
    - method: GET
      path: /reports
```

### Example 5: Keep the Certificate Away From the Backend

By default the backend receives an `X-Forwarded-Client-Cert` header describing the certificate the caller authenticated with. It also carries `DNS` for each DNS SAN, and `Chain` with the certificate chain when the caller authenticated in the TLS handshake. For example (abbreviated):

```http
X-Forwarded-Client-Cert: Hash=5b0d9c2f...;Cert="-----BEGIN%20CERTIFICATE-----...";Subject="CN=payments,O=Partner A";URI=urn:partner-a:payments
```

Set `forwardCertificate: false` when the backend must not see it. The policy then removes `X-Forwarded-Client-Cert`; the relayed certificate header never reaches the backend in either case. The backend learns the caller's certificate only from `X-Forwarded-Client-Cert`, which the gateway sets for the authenticated caller. Any other header, including `X-WSO2-CLIENT-CERTIFICATE` when another header name is configured, comes from the caller.

```yaml
apiVersion: gateway.api-platform.wso2.com/v1
kind: RestApi
metadata:
  name: mtls-auth-private-api
spec:
  displayName: mTLS Auth Private API
  version: v1.0
  context: /mtls-private/$version
  vhosts:
    main: mtls-private.example.com
  upstream:
    main:
      url: http://sample-backend:9080/api/v1
  policies:
    - name: mtls-auth
      version: v1
      params:
        accept:
          - ca: partner-a
        forwardCertificate: false
  operations:
    - method: GET
      path: /reports
```

### Example 6: Behind a Load Balancer

The load balancer connects with its own certificate, issued by the authority pooled as the `edge-lb` relay entry in Prerequisites, and relays the caller's certificate in the certificate header (`X-WSO2-CLIENT-CERTIFICATE` by default). The API definition is the same as without a load balancer; the relay entry in the pool is what allows the header to be trusted. For the load balancer and gateway setup, see [Load balancer with its own certificate](#load-balancer-with-its-own-certificate).

```yaml
apiVersion: gateway.api-platform.wso2.com/v1
kind: RestApi
metadata:
  name: mtls-auth-relay-api
spec:
  displayName: mTLS Auth Relay API
  version: v1.0
  context: /mtls-relay/$version
  vhosts:
    main: mtls-relay.example.com
  upstream:
    main:
      url: http://sample-backend:9080/api/v1
  policies:
    - name: mtls-auth
      version: v1
      params:
        accept:
          - ca: partner-a
  operations:
    - method: GET
      path: /orders
```

The relayed header carries the caller's certificate in one header value, in any of the forms listed in [The header](#the-header).

### Example 7: Protect One Operation Only

Attach the policy to an operation instead of the API to require a certificate for that operation alone. Attach it at one level only; the same policy at both the API and an operation is refused at deployment.

```yaml
apiVersion: gateway.api-platform.wso2.com/v1
kind: RestApi
metadata:
  name: mtls-auth-operation-api
spec:
  displayName: mTLS Auth Operation API
  version: v1.0
  context: /mtls-operation/$version
  vhosts:
    main: mtls-operation.example.com
  upstream:
    main:
      url: http://sample-backend:9080/api/v1
  operations:
    - method: GET
      path: /catalog
    - method: POST
      path: /orders
      policies:
        - name: mtls-auth
          version: v1
          params:
            accept:
              - ca: partner-a
```

### Example 8: Certificate and Token Together

Mutual TLS authenticates the caller; it does not authorize or identify an application. To require a token as well, attach `jwt-auth` after `mtls-auth`. Both must pass. Placing another authentication policy before `mtls-auth` is allowed, but the deploy response carries an `MTLS_AUTH_NOT_FIRST` warning.

`PrimaryIDP` is a key manager the administrator configures for `jwt-auth` in the gateway's `config.toml`, as described in the JWT Authentication policy documentation:

```toml
[[policy_configurations.jwtauth_v1.keymanagers]]
name = "PrimaryIDP"
issuer = "https://idp.example.com/oauth2/token"

[policy_configurations.jwtauth_v1.keymanagers.jwks.remote]
uri = "https://idp.example.com/oauth2/jwks"
```

```yaml
apiVersion: gateway.api-platform.wso2.com/v1
kind: RestApi
metadata:
  name: mtls-auth-token-api
spec:
  displayName: mTLS Auth Token API
  version: v1.0
  context: /mtls-token/$version
  vhosts:
    main: mtls-token.example.com
  upstream:
    main:
      url: http://sample-backend:9080/api/v1
  policies:
    - name: mtls-auth
      version: v1
      params:
        accept:
          - ca: partner-a
    - name: jwt-auth
      version: v1
      params:
        issuers:
          - PrimaryIDP
  operations:
    - method: GET
      path: /orders
```

### Example 9: Custom Failure Response

Change the status code, the body format and the message the caller receives on a denial. The response is still identical for every cause; the cause is recorded in telemetry only.

```yaml
apiVersion: gateway.api-platform.wso2.com/v1
kind: RestApi
metadata:
  name: mtls-auth-custom-error-api
spec:
  displayName: mTLS Auth Custom Error API
  version: v1.0
  context: /mtls-custom-error/$version
  vhosts:
    main: mtls-custom-error.example.com
  upstream:
    main:
      url: http://sample-backend:9080/api/v1
  policies:
    - name: mtls-auth
      version: v1
      params:
        accept:
          - ca: partner-a
        onFailureStatusCode: 403
        errorMessageFormat: plain
        errorMessage: "A client certificate issued by Partner A is required"
  operations:
    - method: GET
      path: /orders
```

The caller receives:

```http
HTTP/1.1 403 Forbidden
Content-Type: text/plain

A client certificate issued by Partner A is required
```

## Deployment Scenarios

What the gateway needs depends on what sits between the caller and the gateway. Find your deployment below, set up the gateway with its steps, and configure your load balancer as described. The `accept` list in the API definition is the same in every scenario.

| Scenario | Who ends the caller's TLS | How the caller's certificate reaches the gateway | Gateway setup |
|---|---|---|---|
| [Gateway at the edge](#gateway-at-the-edge) | The gateway | In the TLS handshake | Client authorities only |
| [Layer-4 load balancer](#layer-4-load-balancer) | The gateway, through the load balancer | In the TLS handshake | Client authorities only |
| [Load balancer with its own certificate](#load-balancer-with-its-own-certificate) | The load balancer, which re-encrypts to the gateway | In a header, believed only from the load balancer | A `role: relay` entry |
| [Load balancer without a certificate](#load-balancer-without-a-certificate) | The load balancer, which re-encrypts to the gateway | In a header, believed from any connection | `trust_any` |
| [Load balancer over plain HTTP](#load-balancer-over-plain-http) | The load balancer, which sends HTTP to port 8080 | In a header, believed from any connection | `trust_any` |

Changes to the gateway's `config.toml` take effect after a restart. With the distribution's Docker Compose setup, run `docker compose restart` in the distribution directory, and allow about a minute before the gateway serves API traffic again.

### Gateway at the edge

Callers connect straight to the gateway's HTTPS listener and present their certificate in the TLS handshake.

1. Upload the authority that issues your callers' certificates with `usage: downstream`, as in [Prerequisites](#prerequisites). If your callers' certificates are issued by an intermediate authority, upload the intermediate.
2. Deploy the API with the policy and its own hostname in `vhosts.main`, as in [Example 1](#example-1-accept-any-pooled-client-authority):

   ```bash
   curl -X POST http://localhost:9090/api/management/v1/rest-apis \
     -u admin:<password> \
     -H "Content-Type: application/yaml" \
     --data-binary @mtls-basic-api.yaml
   ```

   Only connections to that hostname are asked for a certificate, unless the pool holds a relay entry (see [More than one path](#more-than-one-path)).
3. Call the API with a client certificate, sending its hostname:

   ```bash
   curl https://mtls-basic.example.com:8443/mtls-basic/v1.0/orders \
     --resolve mtls-basic.example.com:8443:<gateway-address> \
     --cert client.pem --key client.key --cacert listener-ca.pem
   ```

   `listener-ca.pem` is the authority of the gateway's HTTPS listener certificate. The listener certificate the distribution ships covers only `localhost`. Replace `resources/listener-certs/default-listener.crt` and `default-listener.key` with a certificate and key that cover your API hostnames, then restart the gateway, or add `-k` for a local test.

### Layer-4 load balancer

A load balancer that forwards TCP to the gateway's port 8443 without ending TLS, such as HAProxy in `mode tcp` or nginx `stream` with `ssl_preread on`, needs no special configuration. The server name and the client certificate pass through it unchanged.

Set up the gateway exactly as at the edge. The gateway receives the connection from the load balancer's address, not the caller's.

### Load balancer with its own certificate

The recommended setup when a load balancer ends TLS.

The load balancer:
- verifies the caller's certificate against your callers' authority, and still forwards a request without one, so the gateway answers it;
- connects to the gateway's port 8443 over TLS using HTTP/1.1, and sends the API's hostname as the `Host` header, so the gateway routes the request to the API;
- presents a client certificate of its own on that connection;
- sends the caller's certificate in the `X-WSO2-CLIENT-CERTIFICATE` header, **replacing any value the caller sent**.

If the load balancer verifies the gateway's certificate, its server name for the gateway must be a name that certificate covers. If your callers' certificates are issued by an intermediate authority, put the intermediate in the load balancer's file of callers' authorities.

**nginx**

- `listen 443 ssl;`, `ssl_certificate` and `ssl_certificate_key` for the load balancer's own front certificate.
- `ssl_client_certificate <callers' authority>;` and `ssl_verify_client optional;` verify the caller. With `on` instead of `optional`, a caller without a certificate gets nginx's 400 instead of the gateway's 401. A caller whose certificate fails nginx's check gets nginx's 400 "The SSL certificate error" either way, and never reaches the gateway.
- `proxy_pass https://<gateway>:8443;`
- `proxy_set_header X-WSO2-CLIENT-CERTIFICATE $ssl_client_escaped_cert;` sets the header to the caller's certificate, and sends none when the caller presented no certificate.
- `proxy_set_header Host <API hostname>;`
- `proxy_http_version 1.1;`. Without it nginx sends HTTP/1.0, which the gateway refuses, and nginx answers 502 "upstream prematurely closed connection".
- `proxy_ssl_certificate` and `proxy_ssl_certificate_key` for the load balancer's own certificate.
- To verify the gateway: `proxy_ssl_verify on;`, `proxy_ssl_trusted_certificate <listener authority>;`, `proxy_ssl_server_name on;` and `proxy_ssl_name <a name the listener certificate covers>;`.

**HAProxy**

- `mode http`, in the frontend and backend.
- `bind :443 ssl crt <front certificate> ca-file <callers' authority> verify optional` verifies the caller.
  A caller whose certificate fails HAProxy's check has its handshake aborted, and never reaches the gateway.
- `http-request del-header X-WSO2-CLIENT-CERTIFICATE` removes any value the caller sent.
- `http-request set-header X-WSO2-CLIENT-CERTIFICATE %[ssl_c_der,base64] if { ssl_c_used } { ssl_c_verify 0 }` adds the caller's verified certificate.
- `http-request set-header Host <API hostname>`
- `server gw <gateway>:8443 ssl crt <file> ca-file <listener authority> sni str(<a name the listener certificate covers>)` connects over TLS and presents the load balancer's own certificate. The `crt` file holds the certificate followed by its key. `ssl` is required: without it HAProxy sends plain HTTP to port 8443 and answers 502. `verify none` in place of `ca-file` skips checking the gateway's certificate, for a local test only.

Set up the gateway:

1. Upload the authority that issued the load balancer's certificate as a relay entry, narrowed to that certificate's SAN:

   ```bash
   curl -X POST http://localhost:9090/api/management/v1/certificates \
     -u admin:<password> \
     -H "Content-Type: application/json" \
     -d '{
       "name": "edge-lb",
       "usage": "downstream",
       "role": "relay",
       "match": { "dnsSANs": ["lb.example.com"] },
       "certificate": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"
     }'
   ```

2. Upload the authority that issues your callers' certificates with `usage: downstream`, as in [Prerequisites](#prerequisites). Load balancers relay only the caller's own certificate, so if it's issued by an intermediate authority, upload the intermediate.
3. If your load balancer uses another header name, set it in the gateway's `config.toml`, restart the gateway, and use the same name in the load balancer:

   ```toml
   [router.downstream_tls.client_certificate_header]
   name = "X-Client-Cert"
   ```

   The configured header never reaches the backend. With another name configured, `X-WSO2-CLIENT-CERTIFICATE` is an ordinary header that only a caller would send.
4. Deploy the API with the policy and its own hostname, as in [Example 6](#example-6-behind-a-load-balancer). The API definition is the same as at the edge.

The policy believes the header only on a connection whose certificate matches the relay entry. The backend receives `X-Forwarded-Client-Cert` describing the caller, not the load balancer.

### Load balancer without a certificate

The load balancer verifies the caller and re-encrypts to the gateway as above, but can't present a client certificate of its own, so the gateway can't tell it apart from any other client. Configure it as above without its own certificate: leave out `proxy_ssl_certificate` and `proxy_ssl_certificate_key` in nginx, or `crt` on HAProxy's `server` line.

Set up the gateway:

1. Make sure nothing but the load balancer can reach the gateway's ports 8443 and 8080.
2. Set `trust_any` in the gateway's `config.toml` (see [System Parameters](#system-parameters-configtoml)) and restart the gateway:

   ```toml
   [router.downstream_tls.client_certificate_header]
   trust_any = true
   ```

3. Upload the authority that issues your callers' certificates, and deploy the API, as at the edge.

The header is then believed on every connection whose own certificate wasn't rejected.

### Load balancer over plain HTTP

The load balancer verifies the caller as above, ends TLS, and forwards plain HTTP to the gateway's port 8080, with the API's hostname as the `Host` header and the caller's certificate in the header, replacing any value the caller sent. With nginx, use the caller-side directives above with `proxy_pass http://<gateway>:8080;` and `proxy_http_version 1.1;`. With HAProxy, use the frontend lines above with `server gw <gateway>:8080`, without `ssl`.

There is no TLS connection to identify the load balancer by, so set up the gateway as for a load balancer without a certificate: restrict who can reach ports 8080 and 8443, set `trust_any = true`, restart, then upload the authority and deploy the API.

### More than one path

Direct and relayed callers can use one gateway at the same time. A caller's own certificate on the connection is used; the header is used only on a relay connection. While the pool holds a relay entry, the gateway asks every connection for a certificate, whatever its hostname, and the handshake lists every pooled authority, relay authorities included.

With two proxies in a row, the proxy that faces callers verifies the caller, sets the header and the `Host` header as above, and forwards to the inner proxy, for example over plain HTTP on the internal network. The inner proxy passes both headers through unchanged, so it must not remove or set them, and connects to the gateway over TLS presenting the relay certificate. The inner proxy must be reachable only from the outer one.

### The header

- The header carries the caller's own certificate, as base64-encoded DER, or as PEM: URL-encoded, with its line breaks replaced by spaces, or with the line breaks removed. A chain must be PEM.
- The first certificate in the value is the caller's, and only it authenticates. Certificates after it may link it to a pooled authority, as a handshake's chain does. Most load balancers relay only the caller's own certificate, so pool any intermediate authority that issues your callers' certificates.
- A certificate authority is never accepted as a caller, and the certificate must allow client authentication.
- An empty value means no certificate. Two header lines are refused.

> **Warning:** The gateway believes the header because it trusts the load balancer, so the load balancer must remove any `X-WSO2-CLIENT-CERTIFICATE` header a caller sends. A certificate is public: a caller without a certificate could otherwise copy an accepted caller's certificate into the header and be authenticated as that caller. With `trust_any`, the same applies to anything that can reach the gateway.

## How it Works

Two certificates can take part in a request: the **connection certificate**, presented on the TLS handshake to the gateway, and the **header certificate**, carried in the relay header by a front proxy. The policy runs in the request-header phase and decides in this order.

1. **Envoy checks the connection certificate.** The HTTPS listener asks the client for a certificate and verifies it against the whole client-CA pool. If the certificate is untrusted, expired, not yet valid or unreadable, Envoy still lets the request through to the policy, and the policy denies it. A header cannot save a request whose connection certificate failed this check.

2. **The policy checks the connection certificate against `accept`.** For each `accept` entry, in order, it asks two questions: was this certificate issued by that entry's authority, and does it satisfy the entry's SAN or thumbprint narrowing? The first entry that answers yes to both wins. The request is allowed, the caller's identity is taken from the certificate, and any header certificate is ignored.

3. **If no entry matched, the header certificate may be checked.** This happens only when the connection can be trusted to relay: its certificate matches a `role: relay` pool entry (including that entry's `match`) and is within its validity period, or the `trustAny` system parameter is on. The first certificate in the header is the caller's; any after it only link it to a pooled authority. That certificate is then checked against `accept` in the same way as in step 2. If the connection cannot be trusted to relay, the header is ignored. On a relay connection that carries no header, the load balancer's own certificate is evaluated like any other connection certificate, so the request is refused unless the API accepts the load balancer's authority.

4. **Everything else is denied.** No certificate, a certificate the API does not accept with no trusted header, or a header certificate that fails `accept`: each gets the same failure response, described under Error Responses.

### After a request is allowed

The request continues through the rest of the policy chain to the backend, and the policy leaves three things behind it.

* **For later policies in the chain:** an authentication context of type `mtls`:

  | Field | Value |
  |-------|-------|
  | Subject | The matched SAN when the entry narrows by SAN; otherwise the first URI SAN, then the first DNS SAN, then the subject DN |
  | Issuer | Name of the pool entry that accepted the certificate |
  | Credential ID | SHA-256 thumbprint of the certificate |
  | Properties | `subjectDN`, `issuerDN`, `serialNumber`, `notAfter`, `matchedEntry` (index into `accept`), `source` (`handshake`, `header` or `bypass`), and `relayedBy` and `relaySubject` when a relay delivered the certificate |

* **For analytics:** the authentication context's subject is recorded as the user id of the request.

* **For the backend:** at most one certificate header, `X-Forwarded-Client-Cert`, and it always describes the certificate the caller authenticated with. When the caller authenticated through the header certificate, the policy rewrites `X-Forwarded-Client-Cert` to describe that certificate, in the format Envoy uses. The relay header itself never reaches the backend. With `forwardCertificate: false`, `X-Forwarded-Client-Cert` is removed as well.

## Error Responses

Every denial returns the same response, whatever the cause. The response has no `WWW-Authenticate` header.

```http
HTTP/1.1 401 Unauthorized
Content-Type: application/json

{"error":"Unauthorized","message":"Authentication failed"}
```

With `errorMessageFormat: plain` the body is `errorMessage` as `text/plain`; with `minimal` it is `Unauthorized`. The cause (for example `no_certificate`, `expired`, `not_yet_valid`, `untrusted_chain`, `invalid_certificate`, `authority_not_accepted`, `san_mismatch` or `thumbprint_mismatch`) is recorded as the `mtls_auth.reason` span attribute and in the policy engine's debug log, never in the response. To see it in the log, set `level = "debug"` under `[policy_engine.logging]` in the gateway's `config.toml`.

## Notes

* **Deploy warnings.** An API that omits `accept` gets `MTLS_ACCEPT_INHERITS_POOL`: it accepts certificates from every client authority in the pool. An `accept` entry with neither `match` nor `thumbprints` gets `MTLS_ACCEPT_UNNARROWED`: it accepts any certificate from that authority. Both deploy; narrow the entry, or name the authorities, to clear them.
* **Give each API its own hostname.** Every example sets `vhosts.main`, so the gateway asks for a client certificate only on connections to that hostname, and callers of other APIs, browsers included, aren't asked. An API without `vhosts` is served on the gateway's default hostname. It still works, but the deploy response carries an `MTLS_HOSTNAME_NOT_SCOPED` warning and every connection to the gateway is asked for a certificate. With the gateway setting below, such an API is refused at deployment:

  ```toml
  [router.downstream_tls]
  mtls_requires_dedicated_hostname = true
  ```
* **Pool changes apply on the next request.** The accept list is evaluated against the current pool on every request, so adding, replacing or narrowing a pool entry takes effect without redeploying the API.
* **A missing authority never authenticates anyone.** If an `accept` entry names an authority that is not in the pool, the policy skips that entry and tries the rest. If none of the entries is in the pool, the API denies every request with its usual response, and the gateway writes one warning to its log rather than one per request. The gateway refuses to deploy an API that names a missing authority and refuses to delete an authority an API still names, so this happens only when a pool entry cannot be read or in the moment before a pool change has reached the gateway.
* **Load balancer as a caller.** If the load balancer's authority is also pooled as a `role: client` entry that the API accepts, the load balancer's own certificate authenticates every request and the relayed header is ignored, so callers behind it are no longer authenticated individually. The deploy response warns when an accepted authority is also pooled as a relay.
* **Unreadable pool entries.** A pool entry that cannot be read is skipped and logged; the rest of the pool keeps working.

## Related Policies

- **JWT Auth**: Combine with mutual TLS when callers must present both a certificate and a token
- **API Key Auth**: Use for callers that cannot present a client certificate
