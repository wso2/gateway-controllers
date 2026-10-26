---
title: "Overview"
---
# AWS Authentication

## Overview

The **AWS Authentication** policy signs outbound requests to AWS-hosted backends
using [AWS Signature Version 4 (SigV4)](https://docs.aws.amazon.com/general/latest/gr/signature-version-4.html)
before they are forwarded upstream. Many AWS services — API Gateway endpoints
protected with IAM authorization, Lambda Function URLs, OpenSearch domains, S3,
and others — reject requests that are not correctly SigV4-signed. This policy
lets the gateway act as a trusted caller to such backends by signing every
proxied request with credentials configured directly on the API.

Four credential-acquisition modes are supported:

- **`sts-assume-role`** — the gateway calls AWS STS `AssumeRole` to obtain
  short-lived temporary credentials, then signs with those. Temporary
  credentials are cached and automatically refreshed before they expire.
- **`iam-user-access-key`** — the gateway signs directly with a static,
  long-lived IAM user access key/secret pair (optionally paired with a
  session token if the configured key is already temporary).
- **`irsa`** — the gateway calls AWS STS `AssumeRoleWithWebIdentity` using a
  Kubernetes projected service account token, the mechanism behind **IAM
  Roles for Service Accounts (IRSA)**. This mode only works when the gateway
  runs on a Kubernetes cluster federated with AWS IAM via OIDC (most commonly
  EKS) — see [IRSA Prerequisites](#irsa-prerequisites) below.
- **`default-credential-chain`** — the gateway signs directly with whatever
  credentials the AWS SDK's default credential provider chain resolves (an
  EC2 instance profile, ECS task role, Lambda execution role, or an EKS Pod
  Identity association, among others) — no `AssumeRole` call and no static
  keys configured on the API at all. Use this when the gateway's own compute
  environment already runs under the exact IAM role needed to call the target
  backend — see [Default Credential Chain Notes](#default-credential-chain-notes)
  below.

## Features

- AWS SigV4 request signing for any AWS service (`execute-api`, `lambda`, `s3`, `es`, ...)
- Four credential modes: STS AssumeRole, static IAM user access keys, IRSA, and the AWS SDK default credential chain
- Automatic caching and refresh of temporary credentials obtained via AssumeRole/AssumeRoleWithWebIdentity
- Cross-account role assumption support via an optional External ID (`sts-assume-role` only)
- Preserves any existing authentication context set by an earlier (inbound) auth policy

## Configuration

### User Parameters (API Definition)

All configuration for this policy — including credential material — is set
per-API in the API definition. There are no system/config.toml-level
parameters.

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `service` | string | Yes | | AWS SigV4 signing name of the target backend service (e.g. `execute-api`, `lambda`, `es`, `s3`). |
| `region` | string | Yes | | AWS region of the target backend (e.g. `us-east-1`). |
| `authenticationType` | string | Yes | | Selects the credential-acquisition mode: `sts-assume-role`, `iam-user-access-key`, `irsa`, or `default-credential-chain`. |
| `awsAccessKeyID` | string | Conditional | | Required when `authenticationType` is `iam-user-access-key`. Optional base credential for `sts-assume-role` (if omitted, the default AWS SDK credential chain is used to call `sts:AssumeRole`). Not applicable to `irsa` or `default-credential-chain`. |
| `awsSecretAccessKey` | string | Conditional | | Required when `authenticationType` is `iam-user-access-key`. Must be set together with `awsAccessKeyID`. Not applicable to `irsa` or `default-credential-chain`. |
| `awsSessionToken` | string | No | | Optional session token, only meaningful when `awsAccessKeyID`/`awsSecretAccessKey` already represent temporary credentials. |
| `awsRoleARN` | string | Conditional | | Required when `authenticationType` is `sts-assume-role`. ARN of the IAM role to assume. Optional for `irsa`: if omitted, falls back to the `AWS_ROLE_ARN` environment variable injected by the EKS Pod Identity Webhook. Not applicable to `default-credential-chain`, which never assumes a role. |
| `awsRoleExternalID` | string | No | | Optional External ID passed to `sts:AssumeRole`, for cross-account role assumption hardening. Only applicable for `sts-assume-role` (`AssumeRoleWithWebIdentity`, used by `irsa`, does not support an External ID). |
| `awsRoleSessionName` | string | No | `aws-authentication-session` | Session name used when assuming the role. Applicable for `sts-assume-role` and `irsa`. Not applicable to `default-credential-chain`. |

For `irsa`, the web identity token file path is never a policy param — it is
always read from the `AWS_WEB_IDENTITY_TOKEN_FILE` environment variable
injected by the EKS Pod Identity Webhook (typically
`/var/run/secrets/eks.amazonaws.com/serviceaccount/token`), since this mode
is only meaningful when the gateway is itself running as a Kubernetes
workload with that webhook in place.

> **Security note:** Because credential material is set directly on the API's
> own policy configuration (rather than resolved from operator-controlled
> gateway configuration), access to API definitions containing this policy
> should be restricted accordingly. Scope the IAM user or role used to the
> minimum permissions required by the target backend (least privilege), and
> prefer `default-credential-chain`, `irsa`, or `sts-assume-role` with
> short-lived credentials over long-lived IAM user access keys wherever
> possible.

**Note:**

Inside the `gateway/build.yaml`, ensure the policy module is added under `policies:`:

```yaml
- name: aws-authentication
  gomodule: github.com/wso2/gateway-controllers/policies/aws-authentication@v0
```

## IRSA Prerequisites

`authenticationType: irsa` implements **IAM Roles for Service Accounts**: it
lets the gateway assume an IAM role using its Kubernetes pod identity,
without any AWS access keys ever being configured on the API. This requires
the following to already be in place — it is *not* something this policy
sets up on its own:

1. The Kubernetes cluster's OIDC issuer is registered as an IAM OIDC identity
   provider in the target AWS account (on EKS, this is a one-time cluster
   setup step).
2. The target IAM role's trust policy allows that OIDC provider and is scoped
   (via a `StringEquals` condition on the `sub` claim) to the specific
   Kubernetes namespace/ServiceAccount the gateway pod runs as.
3. The gateway pod's ServiceAccount is annotated with
   `eks.amazonaws.com/role-arn: <role-arn>` (on EKS). The EKS Pod Identity
   Webhook then automatically injects `AWS_ROLE_ARN` and
   `AWS_WEB_IDENTITY_TOKEN_FILE` into the pod, and projects the OIDC token
   file into the pod filesystem.

If the gateway is not running in an environment where the above is
configured, `irsa` fails rather than falling back to some other credential
source. A missing role ARN (neither `awsRoleARN` nor the injected
`AWS_ROLE_ARN` is set) or a missing `AWS_WEB_IDENTITY_TOKEN_FILE` environment
variable is caught during policy-provider initialization — `GetPolicy`
returns an error and the policy never starts serving requests. Once
initialization succeeds, an unreadable/invalid token file or a failing
`AssumeRoleWithWebIdentity` call surfaces at request time as a `502 Bad
Gateway` (per [Error Responses](#error-responses)) — the same failure shape
as `sts-assume-role` when no credentials are resolvable from the default AWS
SDK chain.

Given this, `irsa` is a recommended mode for gateways deployed on EKS (or
another Kubernetes distribution with equivalent OIDC-to-IAM federation): it
avoids storing any long-lived or explicitly-configured AWS credentials on the
API at all, and credentials rotate automatically as the projected token is
refreshed by the kubelet.

## Default Credential Chain Notes

`authenticationType: default-credential-chain` signs requests directly with
whatever the AWS SDK's [default credential provider
chain](https://docs.aws.amazon.com/sdkref/latest/guide/standardized-credentials.html)
resolves at request time — no `AssumeRole`/`AssumeRoleWithWebIdentity` call is
made, and no `awsRoleARN`, key, or secret is ever read from policy params.
Depending on the environment the gateway runs in, this may resolve to:

- An EC2 instance profile's role credentials (from the instance metadata
  service).
- An ECS task role (from the ECS container credentials endpoint).
- A Lambda execution role (if the gateway itself runs inside Lambda).
- An EKS Pod Identity association (via the EKS Pod Identity Agent), which is
  distinct from `irsa`: Pod Identity does not use a projected OIDC token or an
  OIDC identity provider — the agent resolves credentials for the pod
  directly.
- Environment variables (`AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY`) or a
  shared credentials/config file, if present.

This mode is the simplest option whenever the compute the gateway already
runs on carries the exact IAM role/permissions the target backend needs —
there is no separate role to assume and no credential material to configure
on the API at all. If nothing in the chain resolves usable credentials, it
fails at credential-retrieval time with the same `502 Bad Gateway` shape
described in [Error Responses](#error-responses).

## How It Works

1. **Body phase** – Because SigV4 requires a hash of the full request body,
   this policy buffers the complete request before processing.
2. The policy retrieves current AWS credentials from the provider configured
   at policy-instance creation time:
   - `iam-user-access-key` mode uses the static access key/secret directly.
   - `sts-assume-role` mode calls AWS STS `AssumeRole` (caching and
     automatically refreshing the resulting temporary credentials across
     requests until they are close to expiry).
   - `irsa` mode calls AWS STS `AssumeRoleWithWebIdentity` using the
     Kubernetes projected service account token as the web identity token
     (also caching and automatically refreshing the resulting temporary
     credentials).
   - `default-credential-chain` mode resolves credentials directly from the
     AWS SDK's default credential provider chain, with no role assumption.
3. A synthetic HTTP request mirroring the proxied request (method, path,
   query string, host, and body) is built and signed with SigV4 using the
   configured `service` and `region`.
4. The resulting `Authorization`, `X-Amz-Date`, `X-Amz-Content-Sha256`, and
   (when using temporary credentials) `X-Amz-Security-Token` headers are set
   on the request before it is forwarded upstream. The request body is never
   modified.
5. If credentials cannot be retrieved or signing fails, the request is
   short-circuited with `502 Bad Gateway` — this reflects a gateway-to-backend
   authentication failure, not an inbound-client authentication rejection.

## Reference Scenarios

### Example 1: IAM User Access Keys Against an API Gateway (IAM Auth) Backend

```yaml
apiVersion: gateway.api-platform.wso2.com/v1
kind: RestApi
metadata:
  name: inventory-api-v1.0
spec:
  displayName: Inventory-API
  version: v1.0
  context: /inventory/$version
  upstream:
    main:
      url: https://abc123xyz.execute-api.us-east-1.amazonaws.com/prod
  policies:
    - name: aws-authentication
      version: v0
      params:
        service: execute-api
        region: us-east-1
        authenticationType: iam-user-access-key
        awsAccessKeyID: AKIAEXAMPLE1234567
        awsSecretAccessKey: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
  operations:
    - method: GET
      path: /items
    - method: POST
      path: /items
```

### Example 2: STS AssumeRole Against a Lambda Function URL

```yaml
apiVersion: gateway.api-platform.wso2.com/v1
kind: RestApi
metadata:
  name: orders-api-v1.0
spec:
  displayName: Orders-API
  version: v1.0
  context: /orders/$version
  upstream:
    main:
      url: https://abcdefghij.lambda-url.us-east-1.on.aws
  policies:
    - name: aws-authentication
      version: v0
      params:
        service: lambda
        region: us-east-1
        authenticationType: sts-assume-role
        awsRoleARN: arn:aws:iam::123456789012:role/gateway-orders-invoker
        awsRoleExternalID: gateway-prod-01
  operations:
    - method: GET
      path: /{orderId}
    - method: POST
      path: /
```

### Example 3: Cross-Account Role Assumption with Base Credentials

```yaml
  policies:
    - name: aws-authentication
      version: v0
      params:
        service: es
        region: eu-west-1
        authenticationType: sts-assume-role
        awsAccessKeyID: AKIAEXAMPLE1234567
        awsSecretAccessKey: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
        awsRoleARN: arn:aws:iam::987654321098:role/cross-account-opensearch-access
        awsRoleExternalID: partner-gateway-search
        awsRoleSessionName: gateway-search-session
```

### Example 4: IRSA Against an OpenSearch Domain (EKS)

Relies entirely on the `eks.amazonaws.com/role-arn` annotation on the
gateway's ServiceAccount for both the role ARN and the web identity token
file — no credential material is set on the API at all:

```yaml
  policies:
    - name: aws-authentication
      version: v0
      params:
        service: es
        region: us-east-1
        authenticationType: irsa
  operations:
    - method: GET
      path: /{index}/_search
```

### Example 5: IRSA with an Explicit Role ARN

Overrides the role to assume without touching the ServiceAccount annotation
(the web identity token file still comes from `AWS_WEB_IDENTITY_TOKEN_FILE`):

```yaml
  policies:
    - name: aws-authentication
      version: v0
      params:
        service: execute-api
        region: us-east-1
        authenticationType: irsa
        awsRoleARN: arn:aws:iam::123456789012:role/gateway-orders-invoker
        awsRoleSessionName: orders-api-session
```

### Example 6: Default Credential Chain on a Gateway with an Attached IAM Role

For a gateway running on an EC2 instance, ECS task, or EKS pod that already
carries the IAM role/permissions needed to call the target backend directly
— no role to assume, no credential material set on the API at all:

```yaml
  policies:
    - name: aws-authentication
      version: v0
      params:
        service: s3
        region: us-east-1
        authenticationType: default-credential-chain
  operations:
    - method: GET
      path: /{bucket}/{key}
```

## Error Responses

All error responses are returned as JSON with `Content-Type: application/json`.

| Scenario | Status | Message |
|----------|--------|---------|
| AWS credentials could not be retrieved (e.g. AssumeRole/AssumeRoleWithWebIdentity call failed) | 502 | `failed to authenticate request to upstream AWS service` |
| SigV4 signing failed | 502 | `failed to authenticate request to upstream AWS service` |

**Example error body:**
```json
{
  "error": "Bad Gateway",
  "message": "failed to authenticate request to upstream AWS service"
}
```

> `default-credential-chain` also returns this 502 shape if no source in the
> default credential chain resolves anything at request time — since this is,
> from the gateway's perspective, still a failure to obtain valid AWS
> credentials before signing.
>
> For `irsa`, a missing role ARN (neither `awsRoleARN` nor `AWS_ROLE_ARN` is
> set) or a missing `AWS_WEB_IDENTITY_TOKEN_FILE` environment variable is
> instead a policy-provider initialization failure: `GetPolicy` returns an
> error and the policy never starts serving requests, so no request ever
> reaches this 502 path. Once initialization succeeds, a token file that is
> unreadable/invalid or an `AssumeRoleWithWebIdentity` call that fails at
> request time still surfaces as this same 502.

## Security Considerations

- **Least privilege** – Scope the IAM user or role used by this policy to only
  the permissions required by the target AWS backend.
- **Prefer temporary/ambient credentials** – Where possible, use
  `default-credential-chain`, `irsa`, or `sts-assume-role` instead of
  long-lived `iam-user-access-key` credentials. `default-credential-chain`
  and `irsa` additionally avoid storing any AWS credential material on the
  API at all.
- **Scope the IRSA trust policy narrowly** – When using `irsa`, scope the
  target role's trust policy to the specific namespace/ServiceAccount the
  gateway runs as (via a `StringEquals` condition on the OIDC provider's
  `sub` claim), not to the whole OIDC provider — otherwise any workload in the
  cluster with a token could potentially assume the role.
- **Scope the ambient compute role narrowly** – When using
  `default-credential-chain`, the IAM role attached to the gateway's compute
  (instance profile, task role, Pod Identity association) is used as-is with
  no further scoping by this policy — keep that role's permissions limited to
  exactly what the target backend(s) this gateway signs for require.
- **Cross-account hardening** – When assuming a role in another AWS account
  with `sts-assume-role`, always set `awsRoleExternalID` to guard against the
  confused deputy problem.
- **Credential storage** – Credential material configured on this policy
  (when using `sts-assume-role` or `iam-user-access-key`) is stored as part of
  the API's own configuration. Restrict access to API definitions and
  control-plane storage accordingly.
- **HTTPS only** – Ensure the upstream AWS backend URL uses HTTPS so that
  signed requests (and any response data) are not exposed to network
  eavesdroppers.

## Gateway Module Reference

```yaml
- name: aws-authentication
  gomodule: github.com/wso2/gateway-controllers/policies/aws-authentication@v0
```
