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
Feature: Azure Authentication policy
  As an API developer
  I want the gateway to call Entra ID-protected Azure services with a token for its workload identity
  So that no Azure key needs to be stored on the API or LLM provider

  # Obtaining a Microsoft Entra ID token for the gateway's Azure Workload Identity and sending it
  # upstream: token delivery and sharing, parameters, failures and recovery, policy changes on a
  # deployed API, and LLM providers. Rejected configurations, gateway restarts and an unreadable
  # federated token are in the other azure_authentication_*.feature files.
  #
  # The gateway runtime's identity is tenant 7f3c2a10-4b5e-4c6d-8e9f-0a1b2c3d4e5f and client
  # 5d6e7f80-91a2-4b3c-8d4e-5f6a7b8c9d0e, its authority is the testbench entra service at
  # https://testbench:3028/ and its federated token is "testbench-federated-identity-token".
  # The entra service issues tokens at /<tenant>/oauth2/v2.0/token and records every token request
  # at /<tenant>/test/requests. Its Entra-protected resources, http://testbench:3027/<tenant>/foundry
  # (audience https://ai.azure.com) and .../cognitive (audience https://cognitiveservices.azure.com),
  # answer a valid token with a chat completion echoing the request headers, anything else with
  # 401, and report the token they received in the X-Testbench-Entra-Token, -Tid and -Aud response
  # headers.
  #
  # Every scenario that counts token requests or picks a failure mode names its own tenant through
  # the tenantId parameter; the tenant is also its partition and its key in the policy's token cache.
  # A tenant prefix picks the failure: invalid-client- (401, AADSTS700213), reject-once-,
  # throttle-once- (429 with Retry-After), error-once- (500), unavailable- (503), slow- (3 seconds)
  # and refresh-soon- (a first token due for refresh after 2 seconds).
  #
  # The federated token is "testbench-federated-identity-token" and every issued token starts with
  # "testbench-entra.", so a response or log without either discloses no credential.

  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"

  # The gateway's own identity and the default scope: the upstream receives a token for
  # https://ai.azure.com issued to the runtime's tenant and client. The scenario counts nothing,
  # because every scenario that omits tenantId shares the runtime's tenant.
  Scenario: The upstream receives an Entra token for the gateway's identity and the default scope
    Given I generate a unique value from "az-default" and store it as "apiName"
    And I generate a unique API version from "az-default" and store it as "apiVersion"
    And I generate a unique API context from "/az-default" and store it as "apiContext"
    And I generate a unique resource name from "az-res" and store it as "resourcePartition"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}                                                                            |
      | name                   | ${CTX:apiName}                                                                                       |
      | spec.displayName       | ${CTX:apiName}                                                                                       |
      | spec.version           | ${CTX:apiVersion}                                                                                    |
      | spec.context           | ${CTX:apiContext}/$version                                                                           |
      | spec.upstream.main.url | http://testbench:3027/${CTX:resourcePartition}/foundry                                               |
      | spec.policies          | [{"name":"azure-authentication","version":"v0","params":{"authenticationType":"workload-identity"}}] |
      | spec.operations        | [{"method":"POST","path":"/chat/completions"}]                                                       |
    Then the response should be successful

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat/completions" until status 200
    Then the response header "X-Testbench-Entra-Aud" should be "https://ai.azure.com"
    And the response header "X-Testbench-Entra-Tid" should be "7f3c2a10-4b5e-4c6d-8e9f-0a1b2c3d4e5f"
    And the JSON response field "token.appid" should be "5d6e7f80-91a2-4b3c-8d4e-5f6a7b8c9d0e"
    And the response should contain echoed header "Authorization" containing "Bearer testbench-entra."

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat/completions" until status 404

  # The policy sends the projected service account token as the client assertion and caches the
  # token it gets per identity and scope, so two APIs and five requests make one token request.
  Scenario: The federated token is the client assertion, and one cached token serves every API
    Given I generate a unique resource name from "az" and store it as "tenant"
    And I generate a unique value from "az-shared-a" and store it as "apiName"
    And I generate a unique API version from "az-shared-a" and store it as "apiVersion"
    And I generate a unique API context from "/az-shared-a" and store it as "apiContext"
    And I generate a unique value from "az-shared-b" and store it as "secondApiName"
    And I generate a unique API version from "az-shared-b" and store it as "secondApiVersion"
    And I generate a unique API context from "/az-shared-b" and store it as "secondApiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3027/${CTX:tenant}/foundry |
      | spec.policies          | [{"name":"azure-authentication","version":"v0","params":{"authenticationType":"workload-identity","tenantId":"${CTX:tenant}"}}] |
      | spec.operations        | [{"method":"POST","path":"/chat/completions"}] |
    Then the response should be successful
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:secondApiName} |
      | spec.displayName       | ${CTX:secondApiName} |
      | spec.version           | ${CTX:secondApiVersion} |
      | spec.context           | ${CTX:secondApiContext}/$version |
      | spec.upstream.main.url | http://testbench:3027/${CTX:tenant}/foundry |
      | spec.policies          | [{"name":"azure-authentication","version":"v0","params":{"authenticationType":"workload-identity","tenantId":"${CTX:tenant}"}}] |
      | spec.operations        | [{"method":"POST","path":"/chat/completions"}] |
    Then the response should be successful

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat/completions" until status 200
    And I send a "POST" request to "${CTX:secondApiContext}/${CTX:secondApiVersion}/chat/completions" until status 200
    And I send 3 "POST" requests to "${CTX:apiContext}/${CTX:apiVersion}/chat/completions"
    Then the response status code should be 200
    When I send a "GET" request to the "entra" service at "/${CTX:tenant}/test/requests"
    Then the response status code should be 200
    And the JSON response field "count" should be 1
    And the JSON response field "requests[0].clientAssertion" should be "testbench-federated-identity-token"
    And the JSON response field "requests[0].grantType" should be "client_credentials"
    And the JSON response field "requests[0].clientAssertionType" should be "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
    And the JSON response field "requests[0].clientId" should be "5d6e7f80-91a2-4b3c-8d4e-5f6a7b8c9d0e"
    And the JSON response field "requests[0].scope" should be "https://ai.azure.com/.default"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat/completions" until status 404
    When I delete the API "${CTX:secondApiName}"
    Then the response should be successful
    And I send a "POST" request to "${CTX:secondApiContext}/${CTX:secondApiVersion}/chat/completions" until status 404

  # Concurrent first requests on a cold cache wait for one token request instead of each making
  # their own. The policy-free /health operation shows the route is live without requesting a token.
  Scenario: Concurrent first requests share a single token request
    Given I generate a unique resource name from "az" and store it as "tenant"
    And I generate a unique value from "az-concurrent" and store it as "apiName"
    And I generate a unique API version from "az-concurrent" and store it as "apiVersion"
    And I generate a unique API context from "/az-concurrent" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3027/${CTX:tenant}/foundry |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"POST","path":"/chat/{id}","policies":[{"name":"azure-authentication","version":"v0","params":{"authenticationType":"workload-identity","tenantId":"${CTX:tenant}"}}]}] |
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until the route answers 401

    # Fails unless every request is answered 2xx.
    When I send 20 concurrent "POST" requests to "${CTX:apiContext}/${CTX:apiVersion}/chat/{i}" with per-request body:
      """
      {"model":"chat","messages":[{"role":"user","content":"request {i}"}]}
      """
    When I send a "GET" request to the "entra" service at "/${CTX:tenant}/test/requests"
    Then the response status code should be 200
    And the JSON response field "count" should be 1

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 404

  # The policy refreshes a token in the background once it is due (Entra ID's refresh_in), while
  # requests keep using the cached one: the first token is due after 2 seconds, and a later request
  # carries a new token without any request failing.
  Scenario: A token due for refresh is replaced in the background
    Given I generate a unique resource name from "az" and store it as "tenant"
    And I generate a unique value from "az-refresh" and store it as "apiName"
    And I generate a unique API version from "az-refresh" and store it as "apiVersion"
    And I generate a unique API context from "/az-refresh" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3027/refresh-soon-${CTX:tenant}/foundry |
      | spec.policies          | [{"name":"azure-authentication","version":"v0","params":{"authenticationType":"workload-identity","tenantId":"refresh-soon-${CTX:tenant}"}}] |
      | spec.operations        | [{"method":"POST","path":"/chat/completions"}] |
    Then the response should be successful

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat/completions" until status 200
    And I store the response header "X-Testbench-Entra-Token" as "firstToken"
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat/completions" until header "X-Testbench-Entra-Token" is not "${CTX:firstToken}"
    Then the response status code should be 200
    And the response header "X-Testbench-Entra-Token" should contain "testbench-entra."
    When I send a "GET" request to the "entra" service at "/refresh-soon-${CTX:tenant}/test/requests"
    Then the response status code should be 200
    And the JSON response field "count" should be 2

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat/completions" until status 404

  # Attached at API level, the policy authenticates every operation of the API.
  Scenario: Apply Azure Authentication at API level and operation level (API level)
    Given I generate a unique resource name from "az" and store it as "tenant"
    And I generate a unique value from "az-api-level" and store it as "apiName"
    And I generate a unique API version from "az-api-level" and store it as "apiVersion"
    And I generate a unique API context from "/az-api-level" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3027/${CTX:tenant}/foundry |
      | spec.policies          | [{"name":"azure-authentication","version":"v0","params":{"authenticationType":"workload-identity","tenantId":"${CTX:tenant}"}}] |
      | spec.operations        | [{"method":"POST","path":"/chat/completions"},{"method":"GET","path":"/models"}] |
    Then the response should be successful

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat/completions" until status 200
    Then the response header "X-Testbench-Entra-Tid" should be "${CTX:tenant}"
    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/models"
    Then the response status code should be 200
    And the response header "X-Testbench-Entra-Tid" should be "${CTX:tenant}"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat/completions" until status 404

  # Attached to one operation, the policy authenticates that operation only; the other reaches the
  # upstream without a token, which the Entra-protected upstream refuses.
  Scenario: Apply Azure Authentication at API level and operation level (operation level)
    Given I generate a unique resource name from "az" and store it as "tenant"
    And I generate a unique value from "az-op-level" and store it as "apiName"
    And I generate a unique API version from "az-op-level" and store it as "apiVersion"
    And I generate a unique API context from "/az-op-level" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3027/${CTX:tenant}/foundry |
      | spec.operations        | [{"method":"POST","path":"/chat/completions","policies":[{"name":"azure-authentication","version":"v0","params":{"authenticationType":"workload-identity","tenantId":"${CTX:tenant}"}}]},{"method":"GET","path":"/models"}] |
    Then the response should be successful

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat/completions" until status 200
    Then the response header "X-Testbench-Entra-Tid" should be "${CTX:tenant}"
    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/models" until the route answers 401
    Then the response header "X-Testbench-Entra-Token" should not exist

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat/completions" until status 404

  # clientId, tenantId and scope from the policy parameters replace the runtime's identity and the
  # default scope: the token is issued to that client in that tenant, for Azure OpenAI.
  Scenario: The identity and scope come from the policy parameters
    Given I generate a unique resource name from "az" and store it as "tenant"
    And I generate a unique value from "az-override" and store it as "apiName"
    And I generate a unique API version from "az-override" and store it as "apiVersion"
    And I generate a unique API context from "/az-override" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3027/${CTX:tenant}/cognitive |
      | spec.policies          | [{"name":"azure-authentication","version":"v0","params":{"authenticationType":"workload-identity","tenantId":"${CTX:tenant}","clientId":"11111111-2222-4333-8444-555555555555","scope":"https://cognitiveservices.azure.com/.default"}}] |
      | spec.operations        | [{"method":"POST","path":"/chat/completions"}] |
    Then the response should be successful

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat/completions" until status 200
    Then the response header "X-Testbench-Entra-Aud" should be "https://cognitiveservices.azure.com"
    And the response header "X-Testbench-Entra-Tid" should be "${CTX:tenant}"
    And the JSON response field "token.appid" should be "11111111-2222-4333-8444-555555555555"
    When I send a "GET" request to the "entra" service at "/${CTX:tenant}/test/requests"
    Then the response status code should be 200
    And the JSON response field "requests[0].clientId" should be "11111111-2222-4333-8444-555555555555"
    And the JSON response field "requests[0].scope" should be "https://cognitiveservices.azure.com/.default"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat/completions" until status 404

  # headerName and valuePrefix put the token in another header with another prefix, for upstreams
  # that do not read the Authorization header. The upstream here echoes what it receives.
  Scenario: The token is sent in a custom header with a custom prefix
    Given I generate a unique resource name from "az" and store it as "tenant"
    And I generate a unique value from "az-header" and store it as "apiName"
    And I generate a unique API version from "az-header" and store it as "apiVersion"
    And I generate a unique API context from "/az-header" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3000 |
      | spec.policies          | [{"name":"azure-authentication","version":"v0","params":{"authenticationType":"workload-identity","tenantId":"${CTX:tenant}","headerName":"X-Upstream-Token","valuePrefix":"Token"}}] |
      | spec.operations        | [{"method":"GET","path":"/get"}] |
    Then the response should be successful

    # The data-plane request carries no Authorization header of its own, so one reaching the
    # upstream could only have come from the policy.
    When I clear all headers
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 200
    Then the response should contain echoed header "X-Upstream-Token" containing "Token testbench-entra."
    And the response should not contain echoed header "Authorization"

    When I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 404

  # The policy sets the header rather than adding to it, so a token the client sends never reaches
  # the upstream: the Entra-protected upstream would refuse it.
  Scenario: An Authorization header from the client is replaced by the Entra token
    Given I generate a unique resource name from "az" and store it as "tenant"
    And I generate a unique value from "az-replace" and store it as "apiName"
    And I generate a unique API version from "az-replace" and store it as "apiVersion"
    And I generate a unique API context from "/az-replace" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3027/${CTX:tenant}/foundry |
      | spec.policies          | [{"name":"azure-authentication","version":"v0","params":{"authenticationType":"workload-identity","tenantId":"${CTX:tenant}"}}] |
      | spec.operations        | [{"method":"POST","path":"/chat/completions"}] |
    Then the response should be successful

    When I set header "Authorization" to "Bearer client-supplied-token"
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat/completions" until status 200
    Then the response header "X-Testbench-Entra-Token" should contain "testbench-entra."
    And the response should contain echoed header "Authorization" containing "Bearer testbench-entra."
    And the response body should not contain "client-supplied-token"

    When I clear all headers
    And I authenticate using basic auth as "admin"
    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat/completions" until status 404

  # api-key-auth authenticates the client with a gateway API key, then azure-authentication
  # authenticates the gateway to Azure: the client's key stays at the gateway and the upstream gets
  # the Entra token.
  Scenario: Configure Azure Authentication with api-key-auth for inbound authentication
    Given I generate a unique resource name from "az" and store it as "tenant"
    And I generate a unique value from "az-apikey" and store it as "apiName"
    And I generate a unique API version from "az-apikey" and store it as "apiVersion"
    And I generate a unique API context from "/az-apikey" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3027/${CTX:tenant}/foundry |
      | spec.policies          | [{"name":"api-key-auth","version":"v1","params":{"key":"API-Key","in":"header"}},{"name":"azure-authentication","version":"v0","params":{"authenticationType":"workload-identity","tenantId":"${CTX:tenant}"}}] |
      | spec.operations        | [{"method":"POST","path":"/chat/completions"}] |
    Then the response should be successful
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat/completions" until status 401
    And the JSON response field "message" should be "Valid API key required"

    When I send a "POST" request to the "gateway-controller" service at "/rest-apis/${CTX:apiName}/api-keys" with body:
      """
      {"name":"az-key"}
      """
    Then the response status code should be 201
    And I store the JSON response field "apiKey.apiKey" as "apiKey"
    When I set header "API-Key" to "${CTX:apiKey}"
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat/completions" until status 200
    Then the response header "X-Testbench-Entra-Tid" should be "${CTX:tenant}"
    And the response should contain echoed header "Authorization" containing "Bearer testbench-entra."
    And the response should not contain echoed header "API-Key"

    When I clear all headers
    And I authenticate using basic auth as "admin"
    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat/completions" until status 404

  # A throttled (429, honouring Retry-After) or failing (500) token request is retried within the
  # same client request, which then succeeds: one client request, two token requests.
  Scenario Outline: Retry a throttled or failing token request (<case>)
    Given I generate a unique resource name from "az" and store it as "tenant"
    And I generate a unique value from "az-retry" and store it as "apiName"
    And I generate a unique API version from "az-retry" and store it as "apiVersion"
    And I generate a unique API context from "/az-retry" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3027/<prefix>${CTX:tenant}/foundry |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"POST","path":"/chat/completions","policies":[{"name":"azure-authentication","version":"v0","params":{"authenticationType":"workload-identity","tenantId":"<prefix>${CTX:tenant}"}}]}] |
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until the route answers 401

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat/completions"
    Then the response status code should be 200
    And the response header "X-Testbench-Entra-Tid" should be "<prefix>${CTX:tenant}"
    When I send a "GET" request to the "entra" service at "/<prefix>${CTX:tenant}/test/requests"
    Then the response status code should be 200
    And the JSON response field "count" should be 2

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 404

    Examples:
      | case                     | prefix         |
      | throttled with 429       | throttle-once- |
      | transient server failure | error-once-    |

  # Entra ID rejecting the identity fails the request with the policy's 502, which says nothing about
  # the cause. The rejection is not retried, and the gateway runtime log has Entra ID's error code
  # for this scenario's tenant but neither the federated token nor any access token.
  Scenario: Entra ID rejecting the identity fails the request with 502
    Given I generate a unique resource name from "az" and store it as "tenant"
    And I generate a unique value from "az-rejected" and store it as "apiName"
    And I generate a unique API version from "az-rejected" and store it as "apiVersion"
    And I generate a unique API context from "/az-rejected" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3027/invalid-client-${CTX:tenant}/foundry |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"POST","path":"/chat/completions","policies":[{"name":"azure-authentication","version":"v0","params":{"authenticationType":"workload-identity","tenantId":"invalid-client-${CTX:tenant}"}}]}] |
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until the route answers 401

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat/completions"
    Then the response status code should be 502
    And the response should match the expected error response "azure-authentication-upstream-auth-failed"
    And the response body should not contain "testbench-federated-identity-token"
    And the response body should not contain "testbench-entra."
    When I send a "GET" request to the "entra" service at "/invalid-client-${CTX:tenant}/test/requests"
    Then the response status code should be 200
    And the JSON response field "count" should be 1
    And the "gateway-runtime" service logs should contain "invalid-client-${CTX:tenant}"
    And the "gateway-runtime" service logs should contain "700213"
    And the "gateway-runtime" service logs should not contain "testbench-federated-identity-token"
    And the "gateway-runtime" service logs should not contain "testbench-entra."

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 404

  # A token endpoint that keeps failing is tried three times (the request and two retries), then
  # the request fails with the policy's 502.
  Scenario: A token endpoint that keeps failing is retried twice, then the request fails with 502
    Given I generate a unique resource name from "az" and store it as "tenant"
    And I generate a unique value from "az-unavailable" and store it as "apiName"
    And I generate a unique API version from "az-unavailable" and store it as "apiVersion"
    And I generate a unique API context from "/az-unavailable" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3027/unavailable-${CTX:tenant}/foundry |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"POST","path":"/chat/completions","policies":[{"name":"azure-authentication","version":"v0","params":{"authenticationType":"workload-identity","tenantId":"unavailable-${CTX:tenant}"}}]}] |
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until the route answers 401

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat/completions"
    Then the response status code should be 502
    And the response should match the expected error response "azure-authentication-upstream-auth-failed"
    When I send a "GET" request to the "entra" service at "/unavailable-${CTX:tenant}/test/requests"
    Then the response status code should be 200
    And the JSON response field "count" should be 3

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 404

  # tokenRequestTimeout bounds the whole token request, retries included: Entra ID answering after
  # 3 seconds fails a request whose policy allows 1 second, with the policy's 502.
  Scenario: A token request that outlives tokenRequestTimeout fails the request with 502
    Given I generate a unique resource name from "az" and store it as "tenant"
    And I generate a unique value from "az-slow" and store it as "apiName"
    And I generate a unique API version from "az-slow" and store it as "apiVersion"
    And I generate a unique API context from "/az-slow" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3027/slow-${CTX:tenant}/foundry |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"POST","path":"/chat/completions","policies":[{"name":"azure-authentication","version":"v0","params":{"authenticationType":"workload-identity","tenantId":"slow-${CTX:tenant}","tokenRequestTimeout":"1s"}}]}] |
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until the route answers 401

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat/completions"
    Then the response status code should be 502
    And the response should match the expected error response "azure-authentication-upstream-auth-failed"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 404

  # A failed token request is not cached: once Entra ID accepts the identity again, the next request
  # gets a token and succeeds, with no restart and no change to the API.
  Scenario: Restore authentication after Entra ID rejected the identity
    Given I generate a unique resource name from "az" and store it as "tenant"
    And I generate a unique value from "az-recover" and store it as "apiName"
    And I generate a unique API version from "az-recover" and store it as "apiVersion"
    And I generate a unique API context from "/az-recover" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3027/reject-once-${CTX:tenant}/foundry |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"POST","path":"/chat/completions","policies":[{"name":"azure-authentication","version":"v0","params":{"authenticationType":"workload-identity","tenantId":"reject-once-${CTX:tenant}"}}]}] |
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until the route answers 401

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat/completions"
    Then the response status code should be 502
    And the response should match the expected error response "azure-authentication-upstream-auth-failed"
    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat/completions"
    Then the response status code should be 200
    And the response header "X-Testbench-Entra-Tid" should be "reject-once-${CTX:tenant}"
    When I send a "GET" request to the "entra" service at "/reject-once-${CTX:tenant}/test/requests"
    Then the response status code should be 200
    And the JSON response field "count" should be 2

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 404

  # A token for another resource is the upstream's to refuse: the gateway passes the upstream's 401
  # through unchanged instead of failing the request itself.
  Scenario: The upstream's 401 for a token issued for another resource reaches the client
    Given I generate a unique resource name from "az" and store it as "tenant"
    And I generate a unique value from "az-audience" and store it as "apiName"
    And I generate a unique API version from "az-audience" and store it as "apiVersion"
    And I generate a unique API context from "/az-audience" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3027/${CTX:tenant}/foundry |
      | spec.policies          | [{"name":"azure-authentication","version":"v0","params":{"authenticationType":"workload-identity","tenantId":"${CTX:tenant}","scope":"https://cognitiveservices.azure.com/.default"}}] |
      | spec.operations        | [{"method":"POST","path":"/chat/completions"}] |
    Then the response should be successful

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat/completions" until the route answers 401
    Then the response body should contain "audience"
    And the response header "X-Testbench-Entra-Aud" should be "https://cognitiveservices.azure.com"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat/completions" until status 404
