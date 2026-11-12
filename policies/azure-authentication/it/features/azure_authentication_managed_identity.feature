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
  I want the gateway to call Entra ID-protected Azure services with a token for the managed identity of its host
  So that no Azure key needs to be stored on the API or LLM provider when the gateway runs on an Azure VM

  # authenticationType managed-identity gets the token from the Azure Instance Metadata Service
  # (IMDS) of the host. The gateway runtime's AZURE_IMDS_TOKEN_ENDPOINT points at the testbench
  # entra service's IMDS endpoint under this block's partition,
  # https://testbench:3028/${CTX:testbenchPartition}/metadata/identity/oauth2/token, which checks the
  # request as IMDS does and records it for the block and the identity, read back at
  # /${CTX:testbenchPartition}/test/managed-identity/<client_id> (or system-assigned for a request
  # without client_id). Its tokens carry the resource as
  # their audience, "managed-identity" as their tenant and the client_id (or "system-assigned") as
  # their appid, which the protected resources report in the X-Testbench-Entra-Aud, -Tid and -Appid
  # headers.
  #
  # Every scenario except the system-assigned one names its own identity, a fresh UUID, through the
  # clientId parameter; the identity is also its request log and its key in the policy's token
  # cache. A resource picks the failure: api://not-found-once (404), api://gone-once (410),
  # api://throttle-once (429) and api://error-once (500) fail the identity's first request only;
  # api://identity-not-found answers 400 "Identity not found" every time.
  #
  # Every issued token starts with "testbench-entra.", so a response or log without it discloses no
  # credential.

  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"

  # The identity named by clientId gets a token for the default scope's resource, and one cached
  # token serves every API that uses the same identity and scope.
  Scenario: The upstream receives a managed identity token from IMDS, and one token serves every API
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
      | spec.policies          | [{"name":"azure-authentication","version":"v0","params":{"authenticationType":"managed-identity","clientId":"${CTX:clientId}"}}] |
      | spec.operations        | [{"method":"POST","path":"/chat/completions"}] |
    Then the response should be successful
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:secondApiName} |
      | spec.displayName       | ${CTX:secondApiName} |
      | spec.version           | ${CTX:secondApiVersion} |
      | spec.context           | ${CTX:secondApiContext}/$version |
      | spec.upstream.main.url | http://testbench:3027/${CTX:testbenchPartition}/foundry |
      | spec.policies          | [{"name":"azure-authentication","version":"v0","params":{"authenticationType":"managed-identity","clientId":"${CTX:clientId}"}}] |
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
    And the JSON response field "requests[0].apiVersion" should be "2018-02-01"
    And the JSON response field "requests[0].metadata" should be "true"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat/completions" until status 404
    When I delete the API "${CTX:secondApiName}"
    Then the response should be successful
    And I send a "POST" request to "${CTX:secondApiContext}/${CTX:secondApiVersion}/chat/completions" until status 404

  # Without clientId the request names no identity, so IMDS uses the host's system-assigned
  # identity. This is the block's only scenario that uses it, so the block's system-assigned log is
  # its own.
  Scenario: Without clientId the system-assigned identity is used
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
      | spec.upstream.main.url | http://testbench:3027/${CTX:resourcePartition}/foundry |
      | spec.policies          | [{"name":"azure-authentication","version":"v0","params":{"authenticationType":"managed-identity"}}] |
      | spec.operations        | [{"method":"POST","path":"/chat/completions"}] |
    Then the response should be successful

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat/completions" until status 200
    Then the response header "X-Testbench-Entra-Appid" should be "system-assigned"
    And the response header "X-Testbench-Entra-Tid" should be "managed-identity"
    When I send a "GET" request to the "entra" service at "/${CTX:testbenchPartition}/test/managed-identity/system-assigned"
    Then the response status code should be 200
    And the JSON response field "requests[0].clientId" should be ""
    And the JSON response field "requests[0].resource" should be "https://ai.azure.com"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat/completions" until status 404

  # IMDS answers 404 while it starts, 410 while it updates, and 429 or 5xx when it can't serve the
  # request now; the policy retries all of them, so the request still gets its token. The tokens are
  # for an api:// resource no Entra-protected testbench resource accepts, so the upstream is the
  # echo backend.
  Scenario Outline: IMDS asks the gateway to retry (<case>)
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
      | spec.policies          | [{"name":"azure-authentication","version":"v0","params":{"authenticationType":"managed-identity","clientId":"${CTX:clientId}","scope":"<resource>/.default"}}] |
      | spec.operations        | [{"method":"GET","path":"/get"}] |
    Then the response should be successful

    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 200
    Then the response should contain echoed header "Authorization" containing "Bearer testbench-entra."
    When I send a "GET" request to the "entra" service at "/${CTX:testbenchPartition}/test/managed-identity/${CTX:clientId}"
    Then the response status code should be 200
    And the JSON response field "count" should be 2

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 404

    Examples:
      | case                      | resource             |
      | identity not yet ready    | api://not-found-once |
      | IMDS updating             | api://gone-once      |
      | throttled                 | api://throttle-once  |
      | transient server failure  | api://error-once     |

  # IMDS refusing the identity fails the request with the policy's 502, which says nothing about the
  # cause. The refusal is not retried, and the gateway runtime log names IMDS and its error code for
  # this scenario's identity but no access token.
  Scenario: IMDS not finding the identity fails the request with 502
    Given I generate a UUID and store it as "clientId"
    And I generate a unique value from "az-mi-unknown" and store it as "apiName"
    And I generate a unique API version from "az-mi-unknown" and store it as "apiVersion"
    And I generate a unique API context from "/az-mi-unknown" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3027/${CTX:testbenchPartition}/foundry |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"POST","path":"/chat/completions","policies":[{"name":"azure-authentication","version":"v0","params":{"authenticationType":"managed-identity","clientId":"${CTX:clientId}","scope":"api://identity-not-found/.default"}}]}] |
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
      | ${CTX:clientId}                                                                  |
      | the Azure Instance Metadata Service rejected the token request (invalid_request) |
    And the "gateway-runtime" service logs should not contain "testbench-entra."

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 404

  # A managed identity's tenant comes from the identity, so tenantId is a mistake in this mode. The
  # gateway accepts the API, but the policy cannot be built: the operation fails closed with 500,
  # the runtime log says why, and the API's other operation keeps working.
  Scenario: tenantId with managed-identity fails the API's requests closed
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
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"POST","path":"/chat/completions","policies":[{"name":"azure-authentication","version":"v0","params":{"authenticationType":"managed-identity","clientId":"${CTX:clientId}","tenantId":"contoso.onmicrosoft.com"}}]}] |
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

  # An LLM provider names the policy in its upstream auth (type other, gateways after 1.2.0), and
  # gets the same managed identity token as an API.
  Scenario: An LLM provider with upstream auth type other uses the managed identity
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
      | spec.upstream.auth | {"type":"other","policyName":"azure-authentication","policyVersion":"v0","policyParams":{"authenticationType":"managed-identity","clientId":"${CTX:clientId}"}} |
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
