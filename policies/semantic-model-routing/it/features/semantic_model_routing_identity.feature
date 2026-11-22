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

# Runs on a gateway with the testbench Azure OpenAI deployment and no API key. A routed prompt shows
# both the utterance and the prompt embeddings authenticated: a failed one falls back.
@semantic-model-routing-identity
Feature: Semantic model routing with the gateway's Azure identity
  As an API developer
  I want my API's embedding calls to authenticate with the gateway's Azure identity
  So that no Azure OpenAI key has to be stored or rotated

  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"

  Scenario: Prompts are routed with the gateway's workload identity
    Given I generate a unique value from "smr-wi" and store it as "apiName"
    And I generate a unique API version from "smr-wi" and store it as "apiVersion"
    And I generate a unique API context from "/smr-wi" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}  |
      | name                   | ${CTX:apiName}             |
      | spec.displayName       | ${CTX:apiName}             |
      | spec.version           | ${CTX:apiVersion}          |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3002      |
      | spec.operations        | [{"method":"POST","path":"/chat","policies":[{"name":"semantic-model-routing","version":"v0","params":{"azureAuth":{"authenticationType":"workload-identity"},"routes":[{"model":"coding-model","utterances":["write a python function"],"scorethreshold":0.9}],"defaultModel":"default-model","requestModel":{"location":"payload","identifier":"$.model"}}}]},{"method":"GET","path":"/health"}] |
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
  Scenario: Prompts are routed with the container app's identity
    Given I generate a unique value from "smr-ca" and store it as "apiName"
    And I generate a unique API version from "smr-ca" and store it as "apiVersion"
    And I generate a unique API context from "/smr-ca" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}  |
      | name                   | ${CTX:apiName}             |
      | spec.displayName       | ${CTX:apiName}             |
      | spec.version           | ${CTX:apiVersion}          |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3002      |
      | spec.operations        | [{"method":"POST","path":"/chat","policies":[{"name":"semantic-model-routing","version":"v0","params":{"azureAuth":{"authenticationType":"container-apps"},"routes":[{"model":"coding-model","utterances":["write a python function"],"scorethreshold":0.9}],"defaultModel":"default-model","requestModel":{"location":"payload","identifier":"$.model"}}}]},{"method":"GET","path":"/health"}] |
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

  # The testbench identity endpoint refuses this scope, so the utterances can't be embedded and the
  # policy can't be built. Gateways up to 1.2.0 handle that differently.
  Scenario: An identity that gets no access token fails the route's build
    Given the gateway version satisfies ">1.2.0"
    And I generate a unique value from "smr-no-token" and store it as "apiName"
    And I generate a unique API version from "smr-no-token" and store it as "apiVersion"
    And I generate a unique API context from "/smr-no-token" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}  |
      | name                   | ${CTX:apiName}             |
      | spec.displayName       | ${CTX:apiName}             |
      | spec.version           | ${CTX:apiVersion}          |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3002      |
      | spec.operations        | [{"method":"POST","path":"/chat","policies":[{"name":"semantic-model-routing","version":"v0","params":{"azureAuth":{"authenticationType":"container-apps","scope":"api://identity-not-found/.default"},"routes":[{"model":"coding-model","utterances":["write a python function"],"scorethreshold":0.9}],"defaultModel":"default-model","requestModel":{"location":"payload","identifier":"$.model"}}}]},{"method":"GET","path":"/health"}] |
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 500 with body:
      """
      {"model":"original-model","messages":[{"role":"user","content":"write a python function"}]}
      """
    Then the JSON response field "error" should be "Internal Server Error"
    And the response body should not contain "identity-not-found"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 404

  # An API without azureAuth sends an API key. On a gateway with no key it brings its own, and it can
  # point at a deployment of its own too.
  Scenario: An API can still use its own endpoint and key
    Given I generate a unique value from "smr-own-key" and store it as "apiName"
    And I generate a unique API version from "smr-own-key" and store it as "apiVersion"
    And I generate a unique API context from "/smr-own-key" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}  |
      | name                   | ${CTX:apiName}             |
      | spec.displayName       | ${CTX:apiName}             |
      | spec.version           | ${CTX:apiVersion}          |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3002      |
      | spec.operations        | [{"method":"POST","path":"/chat","policies":[{"name":"semantic-model-routing","version":"v0","params":{"embeddingEndpoint":"http://testbench:3004/openai/deployments/own/embeddings?api-version=2024-10-21","apiKey":"test-api-key","routes":[{"model":"coding-model","utterances":["write a python function"],"scorethreshold":0.9}],"defaultModel":"default-model","requestModel":{"location":"payload","identifier":"$.model"}}}]},{"method":"GET","path":"/health"}] |
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

  # The testbench deployment refuses a key it didn't issue, so the utterances can't be embedded.
  Scenario: A wrong key fails the route's build
    Given the gateway version satisfies ">1.2.0"
    And I generate a unique value from "smr-wrong-key" and store it as "apiName"
    And I generate a unique API version from "smr-wrong-key" and store it as "apiVersion"
    And I generate a unique API context from "/smr-wrong-key" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}  |
      | name                   | ${CTX:apiName}             |
      | spec.displayName       | ${CTX:apiName}             |
      | spec.version           | ${CTX:apiVersion}          |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3002      |
      | spec.operations        | [{"method":"POST","path":"/chat","policies":[{"name":"semantic-model-routing","version":"v0","params":{"apiKey":"wrong-key","routes":[{"model":"coding-model","utterances":["write a python function"],"scorethreshold":0.9}],"defaultModel":"default-model","requestModel":{"location":"payload","identifier":"$.model"}}}]},{"method":"GET","path":"/health"}] |
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 500 with body:
      """
      {"model":"original-model","messages":[{"role":"user","content":"write a python function"}]}
      """
    Then the JSON response field "error" should be "Internal Server Error"
    And the response body should not contain "wrong-key"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 404

  # Without azureAuth the policy sends a key, and neither the API nor this gateway has one, so the
  # policy can't be built.
  Scenario: An API that sends a key fails to build when neither it nor the gateway has one
    Given the gateway version satisfies ">1.2.0"
    And I generate a unique value from "smr-nokey" and store it as "apiName"
    And I generate a unique API version from "smr-nokey" and store it as "apiVersion"
    And I generate a unique API context from "/smr-nokey" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}  |
      | name                   | ${CTX:apiName}             |
      | spec.displayName       | ${CTX:apiName}             |
      | spec.version           | ${CTX:apiVersion}          |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3002      |
      | spec.operations        | [{"method":"POST","path":"/chat","policies":[{"name":"semantic-model-routing","version":"v0","params":{"routes":[{"model":"coding-model","utterances":["write a python function"],"scorethreshold":0.9}],"defaultModel":"default-model","requestModel":{"location":"payload","identifier":"$.model"}}}]},{"method":"GET","path":"/health"}] |
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
    Given I generate a unique value from "smr-invalid-auth" and store it as "apiName"
    And I generate a unique API version from "smr-invalid-auth" and store it as "apiVersion"
    And I generate a unique API context from "/smr-invalid-auth" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}  |
      | name                   | ${CTX:apiName}             |
      | spec.displayName       | ${CTX:apiName}             |
      | spec.version           | ${CTX:apiVersion}          |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3002      |
      | spec.operations        | [{"method":"POST","path":"/chat","policies":[{"name":"semantic-model-routing","version":"v0","params":{<params>,"routes":[{"model":"coding-model","utterances":["write a python function"],"scorethreshold":0.9}],"defaultModel":"default-model","requestModel":{"location":"payload","identifier":"$.model"}}}]}] |
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
    Given I generate a unique value from "smr-allowlist-param" and store it as "apiName"
    And I generate a unique API version from "smr-allowlist-param" and store it as "apiVersion"
    And I generate a unique API context from "/smr-allowlist-param" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}  |
      | name                   | ${CTX:apiName}             |
      | spec.displayName       | ${CTX:apiName}             |
      | spec.version           | ${CTX:apiVersion}          |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3002      |
      | spec.operations        | [{"method":"POST","path":"/chat","policies":[{"name":"semantic-model-routing","version":"v0","params":{<params>,"routes":[{"model":"coding-model","utterances":["write a python function"],"scorethreshold":0.9}],"defaultModel":"default-model","requestModel":{"location":"payload","identifier":"$.model"}}}]}] |
    Then the response status code should be 400
    And the response should be valid JSON
    And the JSON response field "status" should be "error"
    And the response body should contain "Configuration validation failed"
    And the response body should contain "<param>"

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat"
    Then the response status code should be 404

    Examples:
      | param                     | params                                                |
      | embeddingAllowedAuthTypes | "embeddingAllowedAuthTypes":["workload-identity"]     |
      | embeddingAllowedEndpoints | "embeddingAllowedEndpoints":["http://testbench:3004"] |
