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

# Runs in the identity block, whose gateway has the testbench Azure OpenAI embedding deployment and
# no API key. A request is only cached, and its repeat only a cache hit, when its embedding call
# succeeded, so a hit shows the API's Azure identity authenticated that call. Each API chooses its
# identity in azureAuth. The gateway gets its workload identity from the testbench Entra ID mock and
# its container app's identity from the testbench Container Apps identity endpoint.
#
# This policy doesn't cache on gateway 1.1.0, which is why the suite's semantic-cache-policy runner
# needs 1.2.0. So the scenarios that expect a cache hit run on 1.2.0 and later, and so do the two
# that expect none, which mean something only beside a hit on the same gateway. The controller's
# checks, the two outlines, run on every gateway.
@semantic-cache-identity
Feature: Semantic cache with the gateway's Azure identity
  As an API developer
  I want my API's embedding calls to authenticate with the gateway's Azure identity
  So that no Azure OpenAI key has to be stored or rotated

  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"

  Scenario: A repeated request is a cache hit with the gateway's workload identity
    Given the gateway version satisfies ">=1.2.0"
    And I generate a unique value from "sc-wi-hit" and store it as "apiName"
    And I generate a unique API version from "sc-wi-hit" and store it as "apiVersion"
    And I generate a unique API context from "/sc-wi-hit" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}  |
      | name                   | ${CTX:apiName}             |
      | spec.displayName       | ${CTX:apiName}             |
      | spec.version           | ${CTX:apiVersion}          |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3002      |
      | spec.operations        | [{"method":"POST","path":"/chat","policies":[{"name":"semantic-cache","version":"v1","params":{"azureAuth":{"authenticationType":"workload-identity"},"similarityThreshold":0.9,"cacheUnauthenticated":true}}]},{"method":"GET","path":"/health"}] |
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 200 with body:
      """
      {"prompt":"What is the capital of Germany?"}
      """

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until header "X-Cache-Status" is "HIT" with body:
      """
      {"prompt":"What is the capital of Germany?"}
      """

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 404

  # A managed identity of the container app the gateway runs in: its system-assigned identity.
  Scenario: A repeated request is a cache hit with the container app's identity
    Given the gateway version satisfies ">=1.2.0"
    And I generate a unique value from "sc-ca-hit" and store it as "apiName"
    And I generate a unique API version from "sc-ca-hit" and store it as "apiVersion"
    And I generate a unique API context from "/sc-ca-hit" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}  |
      | name                   | ${CTX:apiName}             |
      | spec.displayName       | ${CTX:apiName}             |
      | spec.version           | ${CTX:apiVersion}          |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3002      |
      | spec.operations        | [{"method":"POST","path":"/chat","policies":[{"name":"semantic-cache","version":"v1","params":{"azureAuth":{"authenticationType":"container-apps"},"similarityThreshold":0.9,"cacheUnauthenticated":true}}]},{"method":"GET","path":"/health"}] |
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 200 with body:
      """
      {"prompt":"What is the capital of Germany?"}
      """

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until header "X-Cache-Status" is "HIT" with body:
      """
      {"prompt":"What is the capital of Germany?"}
      """

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 404

  # A token scope the testbench Container Apps identity endpoint always refuses, so the API gets no
  # access token and no embedding. The cache fails open: requests still reach the upstream, uncached.
  Scenario: Without an access token, requests go through uncached
    Given the gateway version satisfies ">=1.2.0"
    And I generate a unique value from "sc-noid" and store it as "apiName"
    And I generate a unique API version from "sc-noid" and store it as "apiVersion"
    And I generate a unique API context from "/sc-noid" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}  |
      | name                   | ${CTX:apiName}             |
      | spec.displayName       | ${CTX:apiName}             |
      | spec.version           | ${CTX:apiVersion}          |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3002      |
      | spec.operations        | [{"method":"POST","path":"/chat","policies":[{"name":"semantic-cache","version":"v1","params":{"azureAuth":{"authenticationType":"container-apps","scope":"api://identity-not-found/.default"},"similarityThreshold":0.9,"cacheUnauthenticated":true}}]},{"method":"GET","path":"/health"}] |
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 200 with body:
      """
      {"prompt":"What is the capital of Germany?"}
      """

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" with body:
      """
      {"prompt":"What is the capital of Germany?"}
      """
    Then the response status code should be 200
    And the response header "X-Cache-Status" should not exist

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 404

  # An API without azureAuth sends an API key. On a gateway with no key it brings its own, and it can
  # point at a deployment of its own too.
  Scenario: An API can still use its own endpoint and key
    Given the gateway version satisfies ">=1.2.0"
    And I generate a unique value from "sc-own-key" and store it as "apiName"
    And I generate a unique API version from "sc-own-key" and store it as "apiVersion"
    And I generate a unique API context from "/sc-own-key" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}  |
      | name                   | ${CTX:apiName}             |
      | spec.displayName       | ${CTX:apiName}             |
      | spec.version           | ${CTX:apiVersion}          |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3002      |
      | spec.operations        | [{"method":"POST","path":"/chat","policies":[{"name":"semantic-cache","version":"v1","params":{"embeddingEndpoint":"http://testbench:3004/openai/deployments/other/embeddings?api-version=2024-10-21","apiKey":"test-api-key","similarityThreshold":0.9,"cacheUnauthenticated":true}}]},{"method":"GET","path":"/health"}] |
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 200 with body:
      """
      {"prompt":"What is the capital of Germany?"}
      """

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until header "X-Cache-Status" is "HIT" with body:
      """
      {"prompt":"What is the capital of Germany?"}
      """

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 404

  # The testbench deployment refuses a key it didn't issue, so the API gets no embedding.
  Scenario: A wrong key leaves requests uncached
    Given the gateway version satisfies ">=1.2.0"
    And I generate a unique value from "sc-wrong-key" and store it as "apiName"
    And I generate a unique API version from "sc-wrong-key" and store it as "apiVersion"
    And I generate a unique API context from "/sc-wrong-key" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}  |
      | name                   | ${CTX:apiName}             |
      | spec.displayName       | ${CTX:apiName}             |
      | spec.version           | ${CTX:apiVersion}          |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3002      |
      | spec.operations        | [{"method":"POST","path":"/chat","policies":[{"name":"semantic-cache","version":"v1","params":{"embeddingEndpoint":"http://testbench:3004/openai/deployments/other/embeddings?api-version=2024-10-21","apiKey":"wrong-key","similarityThreshold":0.9,"cacheUnauthenticated":true}}]},{"method":"GET","path":"/health"}] |
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 200 with body:
      """
      {"prompt":"What is the capital of Germany?"}
      """

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" with body:
      """
      {"prompt":"What is the capital of Germany?"}
      """
    Then the response status code should be 200
    And the response header "X-Cache-Status" should not exist

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 404

  # The controller checks an API's params against the policy definition before deploying it.
  # azureAuth is an object that takes a known type, a GUID client ID and a /.default scope, and
  # nothing else. A rejected API is never deployed, so its route answers 404.
  Scenario Outline: The controller rejects azureAuth settings that don't fit the policy (<case>)
    Given I generate a unique value from "sc-invalid-auth" and store it as "apiName"
    And I generate a unique API version from "sc-invalid-auth" and store it as "apiVersion"
    And I generate a unique API context from "/sc-invalid-auth" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}  |
      | name                   | ${CTX:apiName}             |
      | spec.displayName       | ${CTX:apiName}             |
      | spec.version           | ${CTX:apiVersion}          |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3002      |
      | spec.operations        | [{"method":"POST","path":"/chat","policies":[{"name":"semantic-cache","version":"v1","params":{<params>,"similarityThreshold":0.9,"cacheUnauthenticated":true}}]}] |
    Then the response status code should be 400
    And the response should be valid JSON
    And the JSON response field "status" should be "error"
    And the response body should contain "Configuration validation failed"
    And the response body should contain "<error>"
    And the response body should contain "<field>"

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat"
    Then the response status code should be 404

    Examples:
      | case                           | params                                                                                                 | error                                       | field              |
      | an unknown authentication type | "azureAuth":{"authenticationType":"client-secret"}                                                     | must be one of the following                | authenticationType |
      | a client ID that is not a GUID | "azureAuth":{"authenticationType":"managed-identity","clientId":"not-a-guid"}                          | Does not match pattern                      | clientId           |
      | a scope without /.default      | "azureAuth":{"authenticationType":"workload-identity","scope":"https://cognitiveservices.azure.com"}   | Does not match pattern                      | scope              |
      | a field azureAuth doesn't have | "azureAuth":{"authenticationType":"workload-identity","tenantId":"contoso.onmicrosoft.com"}            | Additional property tenantId is not allowed | tenantId           |
      | azureAuth that isn't an object | "azureAuth":"workload-identity"                                                                        | Expected: object, given: string             | azureAuth          |

  # The gateway's allowlists limit what its APIs may choose, so an API can't set them: the policy
  # definition forbids their names in an API's params.
  Scenario Outline: The controller rejects an API that sets the gateway's allowlists (<param>)
    Given I generate a unique value from "sc-allowlist-param" and store it as "apiName"
    And I generate a unique API version from "sc-allowlist-param" and store it as "apiVersion"
    And I generate a unique API context from "/sc-allowlist-param" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}  |
      | name                   | ${CTX:apiName}             |
      | spec.displayName       | ${CTX:apiName}             |
      | spec.version           | ${CTX:apiVersion}          |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3002      |
      | spec.operations        | [{"method":"POST","path":"/chat","policies":[{"name":"semantic-cache","version":"v1","params":{<params>,"similarityThreshold":0.9,"cacheUnauthenticated":true}}]}] |
    Then the response status code should be 400
    And the response should be valid JSON
    And the JSON response field "status" should be "error"
    And the response body should contain "Configuration validation failed"
    And the response body should contain "<param>"

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat"
    Then the response status code should be 404

    Examples:
      | param                     | params                                                   |
      | embeddingAllowedAuthTypes | "embeddingAllowedAuthTypes":["workload-identity"]        |
      | embeddingAllowedEndpoints | "embeddingAllowedEndpoints":["http://testbench:3004"]    |
