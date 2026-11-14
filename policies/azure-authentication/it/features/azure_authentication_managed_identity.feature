# --------------------------------------------------------------------
# Copyright (c) 2026, WSO2 LLC. (https://www.wso2.com).
#
# WSO2 LLC. licenses this file to you under the Apache License,
# Version 2.0 (the "License"); you may not use this file except
# in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.
# --------------------------------------------------------------------

@azure-authentication
Feature: Azure Authentication policy with a managed identity
  As an API developer
  I want the gateway to call Entra ID-protected Azure services with a token for its managed identity
  So that no Azure key needs to be stored on the API or LLM provider when the gateway runs on Azure compute

  # authenticationType managed-identity gets the token for the host's managed identity, and
  # container-apps for a managed identity of the Azure Container Apps app the gateway runs in. The
  # gateway runtime has the IDENTITY_ENDPOINT and IDENTITY_HEADER Container Apps gives an app with a
  # managed identity: the testbench entra service's managed identity endpoint under this block's
  # partition, https://testbench:3028/${CTX:testbenchPartition}/msi/token, and the header value it
  # requires, "testbench-identity-header". With them set, the policy's Azure Identity SDK sends the
  # token requests of both types there. IMDS's own request format, which managed-identity uses on a
  # VM or AKS node, can't be reached from a container; the unit tests and real Azure runs cover it,
  # as they cover container-apps refusing to start without the two variables.
  #
  # The endpoint checks a request as Container Apps does and records it for the block and the
  # identity, read back at /${CTX:testbenchPartition}/test/managed-identity/<client_id> (or
  # system-assigned for a request without client_id). Its tokens carry the resource as their
  # audience, "managed-identity" as their tenant and the client_id (or "system-assigned") as their
  # appid, which the protected resources report in the X-Testbench-Entra-Aud, -Tid and -Appid
  # headers.
  #
  # Every scenario except the system-assigned one names its own identity, a fresh UUID per row,
  # through the clientId parameter; the identity is also its request log. The SDK caches managed
  # identity tokens for the whole runtime by identity and resource, whichever type asked, so no two
  # rows share an identity and resource. A resource picks the failure: api://not-found-once (404),
  # api://throttle-once (429) and api://error-once (500) fail the identity's first request only;
  # api://identity-not-found answers Container Apps' 400 for an identity the app doesn't have, and
  # api://unknown-resource Entra ID's 400 invalid_resource, every time.
  #
  # Every issued token starts with "testbench-entra.", so a response or log without it discloses no
  # credential.

  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"

  # The identity named by clientId gets a token for the default scope's resource from the endpoint,
  # with the identity header and the api-version Container Apps expects, and one cached token serves
  # every API that uses the same identity and scope.
  Scenario Outline: The upstream receives a managed identity token, and one token serves every API (<authenticationType>)
    Given I generate a UUID and store it as "clientId"
    And I generate a unique value from "az-mi" and store it as "apiName"
    And I generate a unique API version from "az-mi" and store it as "apiVersion"
    And I generate a unique API context from "/az-mi" and store it as "apiContext"
    And I generate a unique value from "az-mi-second" and store it as "secondApiName"
    And I generate a unique API version from "az-mi-second" and store it as "secondApiVersion"
    And I generate a unique API context from "/az-mi-second" and store it as "secondApiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3027/${CTX:testbenchPartition}/foundry |
      | spec.policies          | [{"name":"azure-authentication","version":"v0","params":{"authenticationType":"<authenticationType>","clientId":"${CTX:clientId}"}}] |
      | spec.operations        | [{"method":"POST","path":"/chat/completions"}] |
    Then the response should be successful
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:secondApiName} |
      | spec.displayName       | ${CTX:secondApiName} |
      | spec.version           | ${CTX:secondApiVersion} |
      | spec.context           | ${CTX:secondApiContext}/$version |
      | spec.upstream.main.url | http://testbench:3027/${CTX:testbenchPartition}/foundry |
      | spec.policies          | [{"name":"azure-authentication","version":"v0","params":{"authenticationType":"<authenticationType>","clientId":"${CTX:clientId}"}}] |
      | spec.operations        | [{"method":"POST","path":"/chat/completions"}] |
    Then the response should be successful

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat/completions" until status 200
    Then the response header "X-Testbench-Entra-Aud" should be "https://ai.azure.com"
    And the response header "X-Testbench-Entra-Tid" should be "managed-identity"
    And the response header "X-Testbench-Entra-Appid" should be "${CTX:clientId}"
    And the response should contain echoed header "Authorization" containing "Bearer testbench-entra."
    When I send a "POST" request to "${CTX:secondApiContext}/${CTX:secondApiVersion}/chat/completions" until status 200
    Then the response header "X-Testbench-Entra-Appid" should be "${CTX:clientId}"
    When I send a "GET" request to the "entra" service at "/${CTX:testbenchPartition}/test/managed-identity/${CTX:clientId}"
    Then the response status code should be 200
    And the JSON response field "count" should be 1
    And the JSON response field "requests[0].clientId" should be "${CTX:clientId}"
    And the JSON response field "requests[0].resource" should be "https://ai.azure.com"
    And the JSON response field "requests[0].apiVersion" should be "2019-08-01"
    And the JSON response field "requests[0].identityHeader" should be "testbench-identity-header"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat/completions" until status 404
    When I delete the API "${CTX:secondApiName}"
    Then the response should be successful
    And I send a "POST" request to "${CTX:secondApiContext}/${CTX:secondApiVersion}/chat/completions" until status 404

    Examples:
      | authenticationType |
      | managed-identity   |
      | container-apps     |

  # Without clientId the request names no identity, so the endpoint uses the system-assigned
  # identity. This outline is the block's only user of it, so the block's system-assigned log is its
  # own: the managed-identity row's request is the log's first, the container-apps row's its
  # second. The SDK would serve the second row the first row's cached token for the same resource,
  # so the rows ask for different resources.
  Scenario Outline: Without clientId the system-assigned identity is used (<authenticationType>)
    Given I generate a unique value from "az-mi-system" and store it as "apiName"
    And I generate a unique API version from "az-mi-system" and store it as "apiVersion"
    And I generate a unique API context from "/az-mi-system" and store it as "apiContext"
    And I generate a unique resource name from "az-res" and store it as "resourcePartition"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3027/${CTX:resourcePartition}/<upstream> |
      | spec.policies          | [{"name":"azure-authentication","version":"v0","params":{"authenticationType":"<authenticationType>","scope":"<resource>/.default"}}] |
      | spec.operations        | [{"method":"POST","path":"/chat/completions"}] |
    Then the response should be successful

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat/completions" until status 200
    Then the response header "X-Testbench-Entra-Appid" should be "system-assigned"
    And the response header "X-Testbench-Entra-Tid" should be "managed-identity"
    And the response header "X-Testbench-Entra-Aud" should be "<resource>"
    When I send a "GET" request to the "entra" service at "/${CTX:testbenchPartition}/test/managed-identity/system-assigned"
    Then the response status code should be 200
    And the JSON response field "count" should be <count>
    And the JSON response field "requests[<entry>].clientId" should be ""
    And the JSON response field "requests[<entry>].resource" should be "<resource>"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat/completions" until status 404

    Examples:
      | authenticationType | resource                             | upstream  | entry | count |
      | managed-identity   | https://ai.azure.com                 | foundry   | 0     | 1     |
      | container-apps     | https://cognitiveservices.azure.com  | cognitive | 1     | 2     |

  # The endpoint answering 429 or 500 is retried within the same client request, which then
  # succeeds: one client request, two token requests. The tokens are for an api:// resource no
  # Entra-protected testbench resource accepts, so the upstream is the echo backend, whose
  # policy-free /health operation shows the route is live before the one request that needs a token.
  Scenario Outline: The identity endpoint asks the gateway to retry (<authenticationType>, <case>)
    Given I generate a UUID and store it as "clientId"
    And I generate a unique value from "az-mi-retry" and store it as "apiName"
    And I generate a unique API version from "az-mi-retry" and store it as "apiVersion"
    And I generate a unique API context from "/az-mi-retry" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3000 |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"GET","path":"/get","policies":[{"name":"azure-authentication","version":"v0","params":{"authenticationType":"<authenticationType>","clientId":"${CTX:clientId}","scope":"<resource>/.default"}}]}] |
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get"
    Then the response status code should be 200
    And the response should contain echoed header "Authorization" containing "Bearer testbench-entra."
    When I send a "GET" request to the "entra" service at "/${CTX:testbenchPartition}/test/managed-identity/${CTX:clientId}"
    Then the response status code should be 200
    And the JSON response field "count" should be 2

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 404

    Examples:
      | authenticationType | case                     | resource            |
      | managed-identity   | throttled                | api://throttle-once |
      | managed-identity   | transient server failure | api://error-once    |
      | container-apps     | throttled                | api://throttle-once |
      | container-apps     | transient server failure | api://error-once    |

  # A 404 is not retried. container-apps takes it as a refusal and answers again from the rejection
  # cache for about 2 seconds, so the second request gets the same 502 without a new token request.
  # managed-identity, which on a VM may be talking to IMDS while it starts, doesn't, so the second
  # request asks again and gets a token. Either way the endpoint's next answer is a token.
  Scenario Outline: A 404 from the identity endpoint is a refusal only for container-apps (<authenticationType>)
    Given I generate a UUID and store it as "clientId"
    And I generate a unique value from "az-mi-404" and store it as "apiName"
    And I generate a unique API version from "az-mi-404" and store it as "apiVersion"
    And I generate a unique API context from "/az-mi-404" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3000 |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"GET","path":"/get","policies":[{"name":"azure-authentication","version":"v0","params":{"authenticationType":"<authenticationType>","clientId":"${CTX:clientId}","scope":"api://not-found-once/.default"}}]}] |
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get"
    Then the response status code should be 502
    And the response should match the expected error response "azure-authentication-upstream-auth-failed"
    And the "gateway-runtime" service logs should have exactly 1 line containing:
      | ${CTX:clientId} |
      | <reason>        |
    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get"
    Then the response status code should be <second>
    When I send a "GET" request to the "entra" service at "/${CTX:testbenchPartition}/test/managed-identity/${CTX:clientId}"
    Then the response status code should be 200
    And the JSON response field "count" should be <requests>
    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 200
    Then the response should contain echoed header "Authorization" containing "Bearer testbench-entra."
    When I send a "GET" request to the "entra" service at "/${CTX:testbenchPartition}/test/managed-identity/${CTX:clientId}"
    Then the response status code should be 200
    And the JSON response field "count" should be 2

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 404

    Examples:
      | authenticationType | reason                                                                      | second | requests |
      | managed-identity   | the managed identity endpoint returned HTTP 404                             | 200    | 2        |
      | container-apps     | the Container Apps identity endpoint rejected the token request (HTTP 404)  | 502    | 1        |

  # The endpoint refusing the request fails it with the policy's 502, which says nothing about the
  # cause. The refusal is not retried, and the gateway runtime log names the endpoint, the status
  # and any error code for this scenario's identity, but no access token. Container Apps passes
  # Entra ID's own refusals on with the code in errorCode.
  Scenario Outline: The identity endpoint refusing the request fails it with 502 (<authenticationType>, <case>)
    Given I generate a UUID and store it as "clientId"
    And I generate a unique value from "az-mi-refused" and store it as "apiName"
    And I generate a unique API version from "az-mi-refused" and store it as "apiVersion"
    And I generate a unique API context from "/az-mi-refused" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3027/${CTX:testbenchPartition}/foundry |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"POST","path":"/chat/completions","policies":[{"name":"azure-authentication","version":"v0","params":{"authenticationType":"<authenticationType>","clientId":"${CTX:clientId}","scope":"<resource>/.default"}}]}] |
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 401

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat/completions"
    Then the response status code should be 502
    And the response should match the expected error response "azure-authentication-upstream-auth-failed"
    And the response body should not contain "testbench-entra."
    When I send a "GET" request to the "entra" service at "/${CTX:testbenchPartition}/test/managed-identity/${CTX:clientId}"
    Then the response status code should be 200
    And the JSON response field "count" should be 1
    And the "gateway-runtime" service logs should have exactly 1 line containing:
      | ${CTX:clientId} |
      | <reason>        |
    And the "gateway-runtime" service logs should not contain "testbench-entra."

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 404

    Examples:
      | authenticationType | case               | resource                 | reason                                                                                         |
      | managed-identity   | identity not found | api://identity-not-found | the managed identity endpoint rejected the token request (HTTP 400)                            |
      | managed-identity   | unknown resource   | api://unknown-resource   | the managed identity endpoint rejected the token request (HTTP 400, invalid_resource)          |
      | container-apps     | identity not found | api://identity-not-found | the Container Apps identity endpoint rejected the token request (HTTP 400)                     |
      | container-apps     | unknown resource   | api://unknown-resource   | the Container Apps identity endpoint rejected the token request (HTTP 400, invalid_resource)   |

  # A host identity's tenant comes from the identity, so tenantId is a mistake in both types. The
  # gateway accepts the API, but the policy cannot be built: the operation fails closed with 500,
  # the runtime log says why, and the API's other operation keeps working.
  Scenario Outline: tenantId fails the API's requests closed (<authenticationType>)
    Given I generate a UUID and store it as "clientId"
    And I generate a unique value from "az-mi-tenant" and store it as "apiName"
    And I generate a unique API version from "az-mi-tenant" and store it as "apiVersion"
    And I generate a unique API context from "/az-mi-tenant" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3027/${CTX:testbenchPartition}/foundry |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"POST","path":"/chat/completions","policies":[{"name":"azure-authentication","version":"v0","params":{"authenticationType":"<authenticationType>","clientId":"${CTX:clientId}","tenantId":"contoso.onmicrosoft.com"}}]}] |
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 401

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat/completions"
    Then the response status code should be 500
    And the JSON response field "error" should be "Internal Server Error"
    And the "gateway-runtime" service logs should contain "'tenantId' is not used with authenticationType"
    When I send a "GET" request to the "entra" service at "/${CTX:testbenchPartition}/test/managed-identity/${CTX:clientId}"
    Then the response status code should be 200
    And the JSON response field "count" should be 0

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 404

    Examples:
      | authenticationType |
      | managed-identity   |
      | container-apps     |

  # An LLM provider names the policy in its upstream auth (type other, gateways after 1.2.0), and
  # gets the same managed identity token as an API.
  Scenario Outline: An LLM provider with upstream auth type other uses the managed identity (<authenticationType>)
    Given the gateway version satisfies ">1.2.0"
    And I generate a UUID and store it as "clientId"
    And I generate a unique resource name from "az-llm-mi" and store it as "providerName"
    And I generate a unique value from "az-llm-mi" and store it as "providerDisplayName"
    And I generate a unique API version from "az-llm-mi" and store it as "providerVersion"
    And I generate a unique API context from "/az-llm-mi" and store it as "providerContext"
    When I create LLM provider from "resources/templates/llm-provider.yaml" with values:
      | apiVersion         | ${CTX:gatewaySpecVersion} |
      | name               | ${CTX:providerName} |
      | displayName        | ${CTX:providerDisplayName} |
      | version            | ${CTX:providerVersion} |
      | template           | azureai-foundry |
      | spec.context       | ${CTX:providerContext} |
      | spec.upstream.url  | http://testbench:3027/${CTX:testbenchPartition}/foundry |
      | spec.upstream.auth | {"type":"other","policyName":"azure-authentication","policyVersion":"v0","policyParams":{"authenticationType":"<authenticationType>","clientId":"${CTX:clientId}"}} |
      | accessControl.mode | allow_all |
    Then the response status code should be 201
    When I send a "POST" request to "${CTX:providerContext}/chat/completions" until status 200 with body:
      """
      {"model":"chat","messages":[{"role":"user","content":"hello"}]}
      """
    Then the JSON response field "object" should be "chat.completion"
    And the response header "X-Testbench-Entra-Appid" should be "${CTX:clientId}"
    And the response header "X-Testbench-Entra-Tid" should be "managed-identity"

    When I delete the LLM provider "${CTX:providerName}"
    Then the response should be successful
    And I send a "POST" request to "${CTX:providerContext}/chat/completions" until status 404

    Examples:
      | authenticationType |
      | managed-identity   |
      | container-apps     |
