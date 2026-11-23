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

# Runs on a gateway with the testbench Azure OpenAI classifier and no API key. A request routed to
# the rule's model shows the identity's token was accepted: any classifier failure falls back.
@intelligent-model-routing-identity
Feature: Intelligent model routing with the gateway's Azure identity
  As an API developer
  I want my API's classifier call to authenticate with the gateway's Azure identity
  So that no Azure OpenAI key has to be stored or rotated

  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"

  Scenario: Requests are routed with the gateway's workload identity
    Given I generate a unique value from "imr-wi" and store it as "apiName"
    And I generate a unique API version from "imr-wi" and store it as "apiVersion"
    And I generate a unique API context from "/imr-wi" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}  |
      | name                   | ${CTX:apiName}             |
      | spec.displayName       | ${CTX:apiName}             |
      | spec.version           | ${CTX:apiVersion}          |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3002      |
      | spec.operations        | [{"method":"POST","path":"/chat","policies":[{"name":"intelligent-model-routing","version":"v0","params":{"azureAuth":{"authenticationType":"workload-identity"},"routingRules":[{"name":"coding","context":"Programming questions","model":"coding-model"}],"defaultModel":"default-model","requestModel":{"location":"payload","identifier":"$.model"}}}]},{"method":"GET","path":"/health"}] |
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 200 with body:
      """
      {"model":"original-model","messages":[{"role":"user","content":"write a python function"}]}
      """
    Then the response body should contain "coding-model"
    And the response body should not contain "default-model"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 404

  # A managed identity of the container app the gateway runs in: its system-assigned identity.
  Scenario: Requests are routed with the container app's identity
    Given I generate a unique value from "imr-aca" and store it as "apiName"
    And I generate a unique API version from "imr-aca" and store it as "apiVersion"
    And I generate a unique API context from "/imr-aca" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}  |
      | name                   | ${CTX:apiName}             |
      | spec.displayName       | ${CTX:apiName}             |
      | spec.version           | ${CTX:apiVersion}          |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3002      |
      | spec.operations        | [{"method":"POST","path":"/chat","policies":[{"name":"intelligent-model-routing","version":"v0","params":{"azureAuth":{"authenticationType":"container-apps"},"routingRules":[{"name":"coding","context":"Programming questions","model":"coding-model"}],"defaultModel":"default-model","requestModel":{"location":"payload","identifier":"$.model"}}}]},{"method":"GET","path":"/health"}] |
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 200 with body:
      """
      {"model":"original-model","messages":[{"role":"user","content":"write a python function"}]}
      """
    Then the response body should contain "coding-model"
    And the response body should not contain "default-model"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 404

  # The testbench identity endpoint refuses this scope, so the classifier is never called and the
  # request goes to the default model, as for any classifier failure.
  Scenario: An identity that gets no access token sends requests to the default model
    Given I generate a unique value from "imr-no-token" and store it as "apiName"
    And I generate a unique API version from "imr-no-token" and store it as "apiVersion"
    And I generate a unique API context from "/imr-no-token" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}  |
      | name                   | ${CTX:apiName}             |
      | spec.displayName       | ${CTX:apiName}             |
      | spec.version           | ${CTX:apiVersion}          |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3002      |
      | spec.operations        | [{"method":"POST","path":"/chat","policies":[{"name":"intelligent-model-routing","version":"v0","params":{"azureAuth":{"authenticationType":"container-apps","scope":"api://identity-not-found/.default"},"routingRules":[{"name":"coding","context":"Programming questions","model":"coding-model"}],"defaultModel":"default-model","requestModel":{"location":"payload","identifier":"$.model"}}}]},{"method":"GET","path":"/health"}] |
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 200 with body:
      """
      {"model":"original-model","messages":[{"role":"user","content":"write a python function"}]}
      """
    Then the response body should contain "default-model"
    And the response body should not contain "coding-model"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 404

  # The token is for another resource, so the classifier deployment answers 401.
  Scenario: A token the classifier refuses sends requests to the default model
    Given I generate a unique value from "imr-refused" and store it as "apiName"
    And I generate a unique API version from "imr-refused" and store it as "apiVersion"
    And I generate a unique API context from "/imr-refused" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}  |
      | name                   | ${CTX:apiName}             |
      | spec.displayName       | ${CTX:apiName}             |
      | spec.version           | ${CTX:apiVersion}          |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3002      |
      | spec.operations        | [{"method":"POST","path":"/chat","policies":[{"name":"intelligent-model-routing","version":"v0","params":{"azureAuth":{"authenticationType":"workload-identity","scope":"api://other-resource/.default"},"routingRules":[{"name":"coding","context":"Programming questions","model":"coding-model"}],"defaultModel":"default-model","requestModel":{"location":"payload","identifier":"$.model"}}}]},{"method":"GET","path":"/health"}] |
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 200 with body:
      """
      {"model":"original-model","messages":[{"role":"user","content":"write a python function"}]}
      """
    Then the response body should contain "default-model"
    And the response body should not contain "coding-model"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 404

  # An API without azureAuth sends an API key. On a gateway with no key it brings its own, and its
  # own deployment answers "own", the name of its rule.
  Scenario: An API can still use its own endpoint and key
    Given I generate a unique value from "imr-own-key" and store it as "apiName"
    And I generate a unique API version from "imr-own-key" and store it as "apiVersion"
    And I generate a unique API context from "/imr-own-key" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}  |
      | name                   | ${CTX:apiName}             |
      | spec.displayName       | ${CTX:apiName}             |
      | spec.version           | ${CTX:apiVersion}          |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3002      |
      | spec.operations        | [{"method":"POST","path":"/chat","policies":[{"name":"intelligent-model-routing","version":"v0","params":{"llmEndpoint":"http://testbench:3008/openai-azure/openai/deployments/own/chat/completions?api-version=2024-10-21","llmApiKey":"sk-testbench-valid-key","routingRules":[{"name":"own","context":"Programming questions","model":"coding-model"}],"defaultModel":"default-model","requestModel":{"location":"payload","identifier":"$.model"}}}]},{"method":"GET","path":"/health"}] |
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 200 with body:
      """
      {"model":"original-model","messages":[{"role":"user","content":"write a python function"}]}
      """
    Then the response body should contain "coding-model"
    And the response body should not contain "default-model"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 404

  # Without azureAuth the policy sends a key, and neither the API nor this gateway has one, so the
  # policy can't be built. Gateways up to 1.2.0 handle that differently.
  Scenario: An API that sends a key fails to build when neither it nor the gateway has one
    Given the gateway version satisfies ">1.2.0"
    And I generate a unique value from "imr-no-key" and store it as "apiName"
    And I generate a unique API version from "imr-no-key" and store it as "apiVersion"
    And I generate a unique API context from "/imr-no-key" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}  |
      | name                   | ${CTX:apiName}             |
      | spec.displayName       | ${CTX:apiName}             |
      | spec.version           | ${CTX:apiVersion}          |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3002      |
      | spec.operations        | [{"method":"POST","path":"/chat","policies":[{"name":"intelligent-model-routing","version":"v0","params":{"routingRules":[{"name":"coding","context":"Programming questions","model":"coding-model"}],"defaultModel":"default-model","requestModel":{"location":"payload","identifier":"$.model"}}}]},{"method":"GET","path":"/health"}] |
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 500 with body:
      """
      {"model":"original-model","messages":[{"role":"user","content":"write a python function"}]}
      """
    Then the JSON response field "error" should be "Internal Server Error"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 404

  # The identity types work only with Azure OpenAI.
  Scenario: An identity type with the OPENAI provider fails the route's build
    Given the gateway version satisfies ">1.2.0"
    And I generate a unique value from "imr-openai-identity" and store it as "apiName"
    And I generate a unique API version from "imr-openai-identity" and store it as "apiVersion"
    And I generate a unique API context from "/imr-openai-identity" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}  |
      | name                   | ${CTX:apiName}             |
      | spec.displayName       | ${CTX:apiName}             |
      | spec.version           | ${CTX:apiVersion}          |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3002      |
      | spec.operations        | [{"method":"POST","path":"/chat","policies":[{"name":"intelligent-model-routing","version":"v0","params":{"llmProvider":"OPENAI","llmModel":"gpt-4o-mini","azureAuth":{"authenticationType":"workload-identity"},"routingRules":[{"name":"coding","context":"Programming questions","model":"coding-model"}],"defaultModel":"default-model","requestModel":{"location":"payload","identifier":"$.model"}}}]},{"method":"GET","path":"/health"}] |
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 500 with body:
      """
      {"model":"original-model","messages":[{"role":"user","content":"write a python function"}]}
      """
    Then the JSON response field "error" should be "Internal Server Error"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 404

  # The controller checks azureAuth (a known type, a GUID client ID, a /.default scope, nothing
  # else) before deploying an API, so a rejected API's route answers 404.
  Scenario Outline: The controller rejects azureAuth settings that don't fit the policy (<case>)
    Given I generate a unique value from "imr-invalid-auth" and store it as "apiName"
    And I generate a unique API version from "imr-invalid-auth" and store it as "apiVersion"
    And I generate a unique API context from "/imr-invalid-auth" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}  |
      | name                   | ${CTX:apiName}             |
      | spec.displayName       | ${CTX:apiName}             |
      | spec.version           | ${CTX:apiVersion}          |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3002      |
      | spec.operations        | [{"method":"POST","path":"/chat","policies":[{"name":"intelligent-model-routing","version":"v0","params":{<params>,"routingRules":[{"name":"coding","context":"Programming questions","model":"coding-model"}],"defaultModel":"default-model","requestModel":{"location":"payload","identifier":"$.model"}}}]},{"method":"GET","path":"/health"}] |
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
    Given I generate a unique value from "imr-allowlist-param" and store it as "apiName"
    And I generate a unique API version from "imr-allowlist-param" and store it as "apiVersion"
    And I generate a unique API context from "/imr-allowlist-param" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}  |
      | name                   | ${CTX:apiName}             |
      | spec.displayName       | ${CTX:apiName}             |
      | spec.version           | ${CTX:apiVersion}          |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3002      |
      | spec.operations        | [{"method":"POST","path":"/chat","policies":[{"name":"intelligent-model-routing","version":"v0","params":{<params>,"routingRules":[{"name":"coding","context":"Programming questions","model":"coding-model"}],"defaultModel":"default-model","requestModel":{"location":"payload","identifier":"$.model"}}}]},{"method":"GET","path":"/health"}] |
    Then the response status code should be 400
    And the response should be valid JSON
    And the JSON response field "status" should be "error"
    And the response body should contain "Configuration validation failed"
    And the response body should contain "<param>"

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat"
    Then the response status code should be 404

    Examples:
      | param               | params                                          |
      | llmAllowedAuthTypes | "llmAllowedAuthTypes":["workload-identity"]     |
      | llmAllowedEndpoints | "llmAllowedEndpoints":["http://testbench:3008"] |
