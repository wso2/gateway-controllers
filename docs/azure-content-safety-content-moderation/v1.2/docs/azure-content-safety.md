---
title: "Overview"
---
# Azure Content Safety

## Overview

The Azure Content Safety guardrail validates request or response body content against Microsoft Azure Content Safety API for content moderation. It detects and blocks harmful content across four categories: hate speech, sexual content, self-harm, and violence. Each category can be configured with a severity threshold (0-7) or disabled entirely, providing flexible content moderation policies tailored to your application's requirements.

The policy uses Azure Content Safety's text analysis API to evaluate content and blocks requests or responses that exceed configured severity thresholds. This enables enterprise-grade content filtering for LLM applications integrated with Azure services.

## Features

- **Multi-category detection**: Detects hate speech, sexual content, self-harm, and violence
- **Configurable severity thresholds**: Set per-category thresholds (0-7) or disable categories
- **Eight severity levels**: Uses Azure's 8-level severity scale (0=Safe, 7=Most severe)
- **JSONPath support**: Extract and validate specific fields within JSON payloads
- **Separate request/response configuration**: Independent configuration for request and response phases
- **Detailed assessment information**: Optional detailed violation information in error responses
- **Error handling**: Configurable passthrough behavior on API errors
- **Retry logic**: Automatic retry with exponential backoff for transient API failures
- **Azure identity authentication**: From v1.2, an API can authenticate with a Microsoft Entra ID access token for the gateway's own Azure identity (AKS Workload Identity, a managed identity of the VM or AKS node, or of the Azure Container Apps app) instead of the subscription key, and the gateway can limit which authentication types its APIs use

## Configuration

The Azure Content Safety policy uses a two-level configuration: the gateway sets the Content Safety resource, its key and what APIs may use, and each API sets how its checks authenticate and what they check, and can use its own resource and key.

### System Parameters (From config.toml)

These parameters are set in the gateway's `config.toml` and apply to every API that uses the policy. An API can use its own endpoint and key instead, through the `azureContentSafetyEndpoint` and `azureContentSafetyKey` user parameters below; it can't change the allowed lists. From v1.2 the API definition accepts only the user parameters.

##### Azure Content Safety Configuration

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `azureContentSafetyEndpoint` | string | Yes | Azure Content Safety API endpoint URL (without trailing slash). Example: `https://your-resource.cognitiveservices.azure.com` |
| `azureContentSafetyKey` | string | When an API uses `api-key`, the default | Azure Content Safety API subscription key, sent by every API that uses `api-key`. Found in Azure Portal under your Content Safety resource's "Keys and Endpoint" section. Not needed when every API uses an Azure identity. |
| `azureContentSafetyAllowedAuthTypes` | array of strings | No | The authentication types the gateway's APIs may choose in `azureAuth.authenticationType`: any of `api-key`, `workload-identity`, `managed-identity` and `container-apps`. An API without `azureAuth` uses `api-key` and is checked as such. Empty, the default, places no limit. See [Limiting what APIs can use](#limiting-what-apis-can-use). |
| `azureContentSafetyAllowedEndpoints` | array of strings | No | The endpoints the gateway's APIs may call, including the gateway's own. Checked against the endpoint an API uses, its own or the gateway's, so the gateway's key and tokens for its identity go only to listed resources. Empty, the default, places no limit. See [Limiting what APIs can use](#limiting-what-apis-can-use). |

#### Sample System Configuration

Add the following configuration section under the root level in your `config.toml` file:

```toml
azurecontentsafety_endpoint = "https://your-resource.cognitiveservices.azure.com"
azurecontentsafety_key = "<your-azure-content-safety-key>"
```

A gateway whose APIs all authenticate with its workload identity needs no key, and can require the identity and keep its tokens to its own resource:

```toml
azurecontentsafety_endpoint = "https://your-resource.cognitiveservices.azure.com"
azurecontentsafety_allowed_auth_types = ["workload-identity"]
azurecontentsafety_allowed_endpoints = ["https://your-resource.cognitiveservices.azure.com"]
```

#### Authenticating with an Azure Identity

An API whose `azureAuth.authenticationType` is an Azure identity sends `Authorization: Bearer <token>`,
a Microsoft Entra ID access token for the gateway's own identity, and never sends the subscription
key. There is no key to store or rotate, and once every API uses an identity the Content Safety
resource can turn key access off. An API without `azureAuth` sends the gateway's key, exactly as
v1.1 does.

```yaml
params:
  azureAuth:
    authenticationType: container-apps
    # Optional: a user-assigned identity. Without it, the app's system-assigned identity is used.
    clientId: "<identity-client-id>"
  request:
    jsonPath: "$.messages[-1].content"
```

| Authentication type | Where the gateway runs | Where the token comes from |
|---------------------|------------------------|----------------------------|
| `workload-identity` | AKS, with Workload Identity set up for the gateway runtime's service account | Microsoft Entra ID, in exchange for the pod's federated token |
| `managed-identity` | An Azure VM, VM scale set or AKS node with a managed identity | The Azure Instance Metadata Service (IMDS) |
| `container-apps` | An Azure Container Apps app with a managed identity | The identity endpoint Container Apps runs beside the app |

**Azure setup**

1. Give the gateway an identity, as for the `azure-authentication` policy: Workload Identity for
   the gateway runtime's service account on AKS, a managed identity assigned to the VM or node
   pool, or a system-assigned or user-assigned identity on the container app.
2. Grant that identity the **Cognitive Services User** role on the Content Safety resource:

   ```bash
   az role assignment create --assignee <identity-principal-id> --role "Cognitive Services User" \
     --scope <content-safety-resource-id>
   ```

3. Use the resource's custom subdomain endpoint, `https://<resource-name>.cognitiveservices.azure.com`.
   Regional endpoints such as `https://eastus.api.cognitive.microsoft.com` don't accept Entra ID
   tokens.
4. Once the identity works, you can turn key access off on the resource
   (`az resource update --ids <content-safety-resource-id> --set properties.disableLocalAuth=true`),
   so that only Entra ID tokens are accepted.

**Choosing the identity**

- `workload-identity` uses `AZURE_CLIENT_ID`, `AZURE_TENANT_ID` and `AZURE_FEDERATED_TOKEN_FILE`,
  which the AKS Workload Identity webhook sets. `azureAuth.clientId` overrides the client ID; the
  tenant always comes from `AZURE_TENANT_ID`.
- `managed-identity` without a client ID uses the host's system-assigned identity, or its only
  user-assigned identity if it has none; IMDS rejects the request if the host has several. The
  gateway must reach `169.254.169.254` directly: if the gateway runtime has `HTTP_PROXY` or
  `HTTPS_PROXY` set, add `169.254.169.254` to `NO_PROXY`. On AKS, prefer Workload Identity, because
  every pod that can reach IMDS can get tokens for the node's identities.
- `container-apps` without a client ID uses the app's system-assigned identity, which the app must
  then have: unlike IMDS, Container Apps doesn't fall back to an app's only user-assigned identity,
  and answers `400`. Container Apps sets `IDENTITY_ENDPOINT` and `IDENTITY_HEADER` only while the
  app has a managed identity, and a container sees the values it started with: when a running app
  gets its first identity, Container Apps can replace its containers, which restarts the gateway;
  if the API still fails to deploy because the variables are not set, restart the revision with
  `az containerapp revision restart`.

**How the token is used**

- The token is fetched once per check, before the call to Content Safety and its retries, within
  10 seconds. The Azure Identity SDK caches it and refreshes it before it expires, so most checks
  don't make a token request. Every policy on the gateway that uses the same identity shares the
  cache.
- An API fails to deploy when its settings are invalid, when the gateway doesn't allow its
  authentication type, or when the gateway's host can't provide the identity, for example
  `container-apps` without `IDENTITY_ENDPOINT`. The error names the setting or the missing
  environment variable.
- A check that can't get a token fails the way a failed Content Safety call does:
  `passthroughOnError` lets the content through, and otherwise the policy answers `422`. With
  `showAssessment`, the client sees only `Could not obtain an access token for Azure Content Safety`;
  the reason goes to the fault's `Description` and the log.
- A token failure is logged at `ERROR`, even with `passthroughOnError`, so a broken identity can't
  quietly turn moderation off. A token request the identity service refused is answered again
  from a short cache for about two seconds, and logged at `DEBUG` while it is.
- APIs on the same gateway can authenticate differently: a key, the API's own or the gateway's, is
  sent only by the APIs that use `api-key`. With `api-key`, `clientId` and `scope` are ignored, so a
  form that keeps them when the type changes does no harm.
- The token goes to the endpoint in effect: the API's `azureContentSafetyEndpoint` if it sets one,
  otherwise the gateway's.
- APIs that use the same identity share one credential, and its token cache, across the gateway.

**Limiting what APIs can use**

`azurecontentsafety_allowed_auth_types` lists the types the gateway's APIs may use. An API whose
type isn't listed fails to deploy, with an error that names the allowed types; an API without
`azureAuth` counts as `api-key`.

- To stop APIs from sending the key, leave `api-key` out, for example `["workload-identity"]`. APIs
  that don't choose an identity then fail to deploy instead of sending the key.
- To keep APIs off the gateway's identities, list only `api-key`.

`azurecontentsafety_allowed_endpoints` lists the endpoints the gateway's APIs may call. An API can
set its own endpoint, so without this list an API could have the gateway's key, or a token for the
gateway's identity, sent to a server of its choosing. The list is checked against the endpoint in
effect, the API's or the gateway's, so include the gateway's own endpoint. Entries match regardless
of case and of a trailing slash. Set it on every gateway whose APIs use an Azure identity.

An entry in either list that isn't a type or an `http` or `https` URL fails every API that uses the
policy, so a typo is found at the first deployment.

**Troubleshooting**

- Content Safety answers `401`: the identity lacks the Cognitive Services User role (role
  assignments can take several minutes to apply), the endpoint is a regional one, or the token
  scope is for another resource, such as `https://management.azure.com/.default`. Content Safety
  accepts tokens for `https://cognitiveservices.azure.com/.default`, the default, and for
  `https://ai.azure.com/.default`.
- The `ERROR` log line `AzureContentSafety: could not obtain an access token for Azure Content Safety`
  carries the reason, such as `Microsoft Entra ID rejected the token request (HTTP 401,
  invalid_client)`, and the identity's client ID.

**Security considerations**

- **Least privilege**: grant the identity the Cognitive Services User role on the Content Safety
  resource only, rather than on a resource group or subscription.
- **Who configures an API chooses its identity and endpoint**: whoever creates an API with this
  policy chooses which of the gateway's identities its checks use, the token scope, and the
  endpoint the token is sent to. Without `azurecontentsafety_allowed_endpoints`, they can have a
  token for any identity the gateway can use, for any resource that identity can access, sent to a
  server of their choosing, just as they can have the gateway's key sent there in `api-key` mode.
  List the gateway's Content Safety resources in `azurecontentsafety_allowed_endpoints`, use
  `azurecontentsafety_allowed_auth_types` to keep APIs to the types you intend, and give the
  gateway's identities only the roles its APIs need.
- **No stored secret**: with an Azure identity, no key is stored in the gateway's configuration or
  sent to Content Safety, and the tokens are short lived.

**Upgrading from v1.1**

- An API that sets nothing keeps sending the gateway's key, and an API that sets its own endpoint
  or key keeps using them.
- v1.2 accepts only the parameters listed under User Parameters, so an API definition that carries
  any other parameter fails to deploy.

**Gateway versions**

v1.2 needs Go 1.26.10 or later to build. The latest gateway's builder has it. A 1.2.0 gateway's
builder downloads a newer Go during the build, so the build machine needs internet access. A 1.1.0 gateway's
builder can't build v1.2: pin the policy to `@v1.1.0` in `build.yaml` before rebuilding, because
`@v1` would pick v1.2.

### User Parameters (API Definition)

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `azureContentSafetyEndpoint` | string | No | the gateway's | This API's Content Safety endpoint, instead of the gateway's `azurecontentsafety_endpoint`. Must be one the gateway's `azurecontentsafety_allowed_endpoints` lists, if it lists any. |
| `azureContentSafetyKey` | string | No | the gateway's | This API's subscription key, sent with `api-key`, instead of the gateway's `azurecontentsafety_key`. Stored as a literal value in the API definition. |
| `azureAuth` | `AzureAuth` object | No | `api-key` | How the API's checks authenticate. Without it, they send the subscription key. |
| `request` | `AzureContentSafetyConfig` object | No | - | Configuration for request-phase moderation. Supports `jsonPath`, `passthroughOnError`, `showAssessment`, and per-category severity thresholds. |
| `response` | `AzureContentSafetyConfig` object | No | - | Configuration for response-phase moderation. Supports `jsonPath`, `passthroughOnError`, `showAssessment`, and per-category severity thresholds. |

#### Azure Authentication Configuration

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `authenticationType` | string | No | `api-key` | `api-key` sends the subscription key, the API's or the gateway's. `workload-identity`, `managed-identity` and `container-apps` send an access token for the gateway's Azure identity. See [Authenticating with an Azure Identity](#authenticating-with-an-azure-identity). |
| `clientId` | string | No | - | With an Azure identity, the client ID of the identity, as a GUID. Defaults to `AZURE_CLIENT_ID` for `workload-identity` and to the host's default identity otherwise. |
| `scope` | string | No | `https://cognitiveservices.azure.com/.default` | With an Azure identity, the scope of the access token. |

#### Request Configuration

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `jsonPath` | string | No | `"$.messages[-1].content"` | JSONPath expression to extract a specific value from the request JSON payload. If empty, validates the entire payload as a string. |
| `passthroughOnError` | boolean | No | `false` | If `true`, allows traffic to proceed if Azure Content Safety API call fails. If `false`, blocks on API errors. |
| `showAssessment` | boolean | No | `false` | If `true`, includes detailed assessment information in error responses. |
| `hateSeverityThreshold` | integer | No | `4` | Severity threshold for hate content (-1 to 7). `-1` disables this category. Content with severity >= threshold will be blocked. |
| `sexualSeverityThreshold` | integer | No | `5` | Severity threshold for sexual content (-1 to 7). `-1` disables this category. Content with severity >= threshold will be blocked. |
| `selfHarmSeverityThreshold` | integer | No | `3` | Severity threshold for self-harm content (-1 to 7). `-1` disables this category. Content with severity >= threshold will be blocked. |
| `violenceSeverityThreshold` | integer | No | `4` | Severity threshold for violence content (-1 to 7). `-1` disables this category. Content with severity >= threshold will be blocked. |

#### Response Configuration

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `jsonPath` | string | No | `"$.choices[0].message.content"` | JSONPath expression to extract a specific value from the response JSON payload. If empty, validates the entire payload as a string. |
| `passthroughOnError` | boolean | No | `false` | If `true`, allows traffic to proceed if Azure Content Safety API call fails. If `false`, blocks on API errors. |
| `showAssessment` | boolean | No | `false` | If `true`, includes detailed assessment information in error responses. |
| `hateSeverityThreshold` | integer | No | `4` | Severity threshold for hate content (-1 to 7). `-1` disables this category. Content with severity >= threshold will be blocked. |
| `sexualSeverityThreshold` | integer | No | `5` | Severity threshold for sexual content (-1 to 7). `-1` disables this category. Content with severity >= threshold will be blocked. |
| `selfHarmSeverityThreshold` | integer | No | `3` | Severity threshold for self-harm content (-1 to 7). `-1` disables this category. Content with severity >= threshold will be blocked. |
| `violenceSeverityThreshold` | integer | No | `4` | Severity threshold for violence content (-1 to 7). `-1` disables this category. Content with severity >= threshold will be blocked. |

#### JSONPath Support

The guardrail supports JSONPath expressions to extract and validate specific fields within JSON payloads. Common examples:

- `$.messages` - Extracts the `messages` field from the root object
- `$.data.content` - Extracts nested content from `data.content`
- `$.items[0].text` - Extracts text from the first item in an array
- `$.messages[0].content` - Extracts content from the first message in a messages array
- `$.messages[-1].content` - Extracts content from the last message in a messages array
- `$.choices[0].message.content` - Extracts assistant response content

If `jsonPath` is empty or not specified, the entire payload is treated as a string and validated.

**Note:**

Inside the `gateway/build.yaml`, ensure the policy module is added under `policies:`:

```yaml
- name: azure-content-safety-content-moderation
  gomodule: github.com/wso2/gateway-controllers/policies/azure-content-safety-content-moderation@v1
```

## Reference Scenarios

### Example 1: Basic Content Moderation

Deploy an LLM provider with Azure Content Safety validation:

```yaml
apiVersion: gateway.api-platform.wso2.com/v1
kind: LlmProvider
metadata:
  name: azure-safety-provider
spec:
  displayName: Azure Content Safety Provider
  version: v1.0
  template: openai
  context: /openai
  upstream:
    url: "https://api.openai.com/v1"
    auth:
      type: api-key
      header: Authorization
      value: Bearer <openai-apikey>
  accessControl:
    mode: deny_all
    exceptions:
      - path: /chat/completions
        methods: [POST]
  operationPolicies:
    - name: azure-content-safety-content-moderation
      version: v1
      paths:
        - path: /chat/completions
          methods: [POST]
          params:
            request:
              jsonPath: "$.messages[0].content"
              hateSeverityThreshold: 2
              sexualSeverityThreshold: 2
              selfHarmSeverityThreshold: 2
              violenceSeverityThreshold: 2
              showAssessment: true
            response:
              jsonPath: "$.choices[0].message.content"
              hateSeverityThreshold: 2
              sexualSeverityThreshold: 2
              selfHarmSeverityThreshold: 2
              violenceSeverityThreshold: 2
              showAssessment: true
```

**Test the guardrail:**

**Case 1: Valid request (should pass)**
```bash
curl -X POST http://localhost:8080/openai/chat/completions \
  -H "Content-Type: application/json" \
  -d '{
    "model": "gpt-4",
    "messages": [
      {
        "role": "user",
        "content": "Explain quantum computing in simple terms"
      }
    ]
  }'
```

**Case 2: Request with harmful content**

```bash
# (should fail with HTTP 422)
curl -X POST http://localhost:8080/openai/chat/completions \
  -H "Content-Type: application/json" \
  -d '{
    "model": "gpt-4",
    "messages": [
      {
        "role": "user",
        "content": "Summarize this article and suggest ways someone could take revenge on Mr. Anonymous Senator violently."
      }
    ]
  }'
```

**Error Response:**

When validation fails, the guardrail returns an `HTTP 422` status code with the following structure:

```json
{
  "type": "AZURE_CONTENT_SAFETY_CONTENT_MODERATION",
  "message": {
    "action": "GUARDRAIL_INTERVENED",
    "interveningGuardrail": "azure-content-safety-content-moderation",
    "actionReason": "Violation of Azure content safety content moderation detected.",
    "direction": "REQUEST"
  }
}
```

If `showAssessment` is enabled, additional details are included:

```json
{
  "type": "AZURE_CONTENT_SAFETY_CONTENT_MODERATION",
  "message": {
    "action": "GUARDRAIL_INTERVENED",
    "interveningGuardrail": "azure-content-safety-content-moderation",
    "actionReason": "Violation of Azure content safety content moderation detected.",
    "direction": "REQUEST",
    "assessments": {
      "inspectedContent": "The content that was analyzed",
      "categories": [
        {
          "category": "Hate",
          "severity": 4,
          "result": "FAIL"
        },
        {
          "category": "Violence",
          "severity": 2,
          "result": "FAIL"
        }
      ]
    }
  }
}
```


### Example 2: Strict Moderation with All Categories

Configure strict moderation thresholds:

```yaml
operationPolicies:
  - name: azure-content-safety-content-moderation
    version: v1
    paths:
      - path: /chat/completions
        methods: [POST]
        params:
          request:
            jsonPath: "$.messages[-1].content"
            hateSeverityThreshold: 1
            sexualSeverityThreshold: 1
            selfHarmSeverityThreshold: 1
            violenceSeverityThreshold: 1
            showAssessment: true
            passthroughOnError: false
          response:
            jsonPath: "$.choices[0].message.content"
            hateSeverityThreshold: 1
            sexualSeverityThreshold: 1
            selfHarmSeverityThreshold: 1
            violenceSeverityThreshold: 1
            showAssessment: true
```

### Example 3: Selective Category Monitoring

Monitor only specific categories:

```yaml
operationPolicies:
  - name: azure-content-safety-content-moderation
    version: v1
    paths:
      - path: /chat/completions
        methods: [POST]
        params:
          request:
            jsonPath: "$.messages[0].content"
            hateSeverityThreshold: 3
            sexualSeverityThreshold: -1  # Disabled
            selfHarmSeverityThreshold: 2
            violenceSeverityThreshold: -1  # Disabled
```

### Example 4: Lenient Moderation

Allow more content with higher thresholds:

```yaml
operationPolicies:
  - name: azure-content-safety-content-moderation
    version: v1
    paths:
      - path: /chat/completions
        methods: [POST]
        params:
          request:
            jsonPath: "$.messages[0].content"
            hateSeverityThreshold: 5
            sexualSeverityThreshold: 5
            selfHarmSeverityThreshold: 4
            violenceSeverityThreshold: 5
            passthroughOnError: true
```

## How It Works

#### Request Phase

1. **Content Extraction**: Extracts content from the request body using `jsonPath` (if configured) or uses the entire payload.
2. **Category Selection**: Includes only categories with thresholds >= `0` for moderation checks.
3. **Authentication**: With an Azure identity, gets an access token for the gateway's identity, usually from the SDK's cache.
4. **Moderation Analysis**: Sends content to Azure Content Safety text analysis API and receives per-category severity scores.
5. **Threshold Evaluation**: Compares each configured category score against its threshold and blocks when severity >= threshold.
6. **Error Strategy**: Applies `passthroughOnError` behavior to determine fail-open or fail-closed behavior on API failures.

#### Response Phase

1. **Content Extraction**: Extracts content from the response body using `jsonPath` (if configured) or uses the entire payload.
2. **Category Selection**: Includes only categories with thresholds >= `0` for moderation checks.
3. **Authentication**: With an Azure identity, gets an access token for the gateway's identity, usually from the SDK's cache.
4. **Moderation Analysis**: Sends response content to Azure Content Safety and receives per-category severities.
5. **Threshold Evaluation**: Blocks and returns HTTP `422` if any configured threshold is violated.
6. **Error Strategy**: Applies `passthroughOnError` behavior for API errors.

#### Severity Levels

Azure Content Safety uses an 8-level severity scale (`0-7`):

- **0**: Safe - No harmful content detected
- **1-2**: Low severity - Mildly concerning content
- **3-4**: Medium severity - Moderately concerning content
- **5-6**: High severity - Highly concerning content
- **7**: Maximum severity - Most severe harmful content

#### Severity Threshold Guidelines

- **Threshold behavior**: Set a threshold value (`0-7`) to block content at or above that severity; set `-1` to disable a category.
- **Strict** (family-friendly applications): `1-2` across all categories.
- **Moderate** (general business applications): `3-4` across all categories.
- **Lenient** (technical/professional contexts): `5-6` for most categories, disable non-applicable ones.
- **Category tuning**: Hate (`2-3`), Sexual (`1-4` depending on context), Self-harm (`1-2`), Violence (`1-2` general use, higher for educational/historical content).

## Notes

- Azure Content Safety API requires an active Azure subscription and Content Safety resource.
- The API endpoint URL must not include a trailing slash (e.g., `https://resource.cognitiveservices.azure.com`).
- In `api-key` mode, API keys are found in Azure Portal under your Content Safety resource's "Keys and Endpoint" section.
- Category thresholds are independent - you can disable any category by setting it to `-1`.
- Only categories with thresholds >= 0 are sent to the Azure API for analysis (performance optimization).
- The policy validates both request and response phases independently when both are configured.
- Content is sent to Azure Content Safety API for analysis, so ensure compliance with data residency requirements.
- Rate limits may apply based on your Azure Content Safety subscription tier.
- The API uses Azure's 8-severity-level analysis, providing fine-grained control over content moderation.
- For production deployments, monitor API response times and adjust retry/timeout settings if needed.

## Fault reporting

From v1.1, every rejection this policy makes is also reported to the gateway as a **fault**:
a stable code and type alongside the response. A gateway that supports fault policies uses it
for the analytics event and hands it to the API's fault policies (for example `log-message`, to
log the failure). The status and body the client receives are the same as in v1.0. A gateway
without fault policy support ignores the fault, and the policy behaves exactly as v1.0.

A guardrail verdict has type `guardrail` and a code from the guardrail block (`906000`–`906399`).
It also names the intervening guardrail (`azure-content-safety-content-moderation`) and records that it intervened; the
assessment is attached only when `showAssessment` is enabled, because it can hold the blocked content.
A rejection made because the policy could not run its check is not a verdict and carries no
guardrail details: a request body that cannot be read is reported as `960001` (`validation`),
because it is the caller's, and every other such failure as `960000` (`mediation`).

With `passthroughOnError` enabled, the errors in the last four rows pass the request or response through
instead of rejecting it, and no fault is reported.

| When | Status | Code | Type |
|------|--------|------|------|
| Request or response: the `Hate` severity reaches its threshold | `422` | `906001` | `guardrail` |
| Request or response: the `Sexual` severity reaches its threshold | `422` | `906002` | `guardrail` |
| Request or response: the `SelfHarm` severity reaches its threshold | `422` | `906003` | `guardrail` |
| Request or response: the `Violence` severity reaches its threshold | `422` | `906004` | `guardrail` |
| Request: the value at `jsonPath` cannot be extracted | `422` | `960001` | `validation` |
| Response: the value at `jsonPath` cannot be extracted | `422` | `960000` | `mediation` |
| Request or response: the Azure Content Safety call fails | `422` | `960000` | `mediation` |
| Request or response: with an Azure identity, no access token can be obtained | `422` | `960000` | `mediation` |

When more than one category reaches its threshold, the first one in Azure's response decides the code.

The fault's `Description` carries the internal reason, for example
`Violation of Azure content safety content moderation detected`, or, when no access token could be
obtained, `Could not obtain an access token for Azure Content Safety:` followed by the reason.
It is passed to fault policies and analytics only, never to the client.
