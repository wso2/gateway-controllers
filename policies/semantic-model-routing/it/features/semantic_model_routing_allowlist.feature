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

# Runs on a gateway that has a key but allows only workload identity, and only the testbench Azure
# OpenAI resource. An API the lists refuse can't build its policy, so its route answers 500.
@semantic-model-routing-allowlist
Feature: The gateway's lists of allowed authentication types and endpoints for embeddings
  As a gateway operator
  I want to limit how APIs authenticate to the embedding provider
  So that no API sends the API key, uses an identity I haven't allowed, or sends either elsewhere

  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"

  Scenario: An API that chooses an allowed authentication type routes prompts
    Given I generate a unique value from "smr-allow-wi" and store it as "apiName"
    And I generate a unique API version from "smr-allow-wi" and store it as "apiVersion"
    And I generate a unique API context from "/smr-allow-wi" and store it as "apiContext"
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

  # The endpoint list names resources, so another deployment or API version on a listed resource is
  # allowed.
  Scenario: An API's own deployment on a listed resource is allowed
    Given I generate a unique value from "smr-allow-own" and store it as "apiName"
    And I generate a unique API version from "smr-allow-own" and store it as "apiVersion"
    And I generate a unique API context from "/smr-allow-own" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}  |
      | name                   | ${CTX:apiName}             |
      | spec.displayName       | ${CTX:apiName}             |
      | spec.version           | ${CTX:apiVersion}          |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3002      |
      | spec.operations        | [{"method":"POST","path":"/chat","policies":[{"name":"semantic-model-routing","version":"v0","params":{"embeddingEndpoint":"http://testbench:3004/openai/deployments/own/embeddings?api-version=2024-10-21","azureAuth":{"authenticationType":"workload-identity"},"routes":[{"model":"coding-model","utterances":["write a python function"],"scorethreshold":0.9}],"defaultModel":"default-model","requestModel":{"location":"payload","identifier":"$.model"}}}]},{"method":"GET","path":"/health"}] |
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

  # Gateways up to 1.2.0 handle a policy that can't be built differently, so these run on newer ones.
  # A trailing dot makes the testbench another resource: off the list, yet it would serve embeddings.
  Scenario Outline: An API whose authentication type or endpoint the gateway doesn't allow fails closed (<case>)
    Given the gateway version satisfies ">1.2.0"
    And I generate a unique value from "smr-refused" and store it as "apiName"
    And I generate a unique API version from "smr-refused" and store it as "apiVersion"
    And I generate a unique API context from "/smr-refused" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}  |
      | name                   | ${CTX:apiName}             |
      | spec.displayName       | ${CTX:apiName}             |
      | spec.version           | ${CTX:apiVersion}          |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3002      |
      | spec.operations        | [{"method":"POST","path":"/chat","policies":[{"name":"semantic-model-routing","version":"v0","params":{<params>"routes":[{"model":"coding-model","utterances":["write a python function"],"scorethreshold":0.9}],"defaultModel":"default-model","requestModel":{"location":"payload","identifier":"$.model"}}}]},{"method":"GET","path":"/health"}] |
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 500 with body:
      """
      {"model":"original-model","messages":[{"role":"user","content":"write a python function"}]}
      """
    Then the JSON response field "error" should be "Internal Server Error"
    And the response body should not contain "test-api-key"
    And the response body should not contain "embeddingAllowedAuthTypes"
    And the response body should not contain "embeddingAllowedEndpoints"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 404

    Examples:
      | case                                                          | params                                                                                                                                                       |
      | no azureAuth, so api-key                                      |                                                                                                                                                              |
      | an identity that isn't on the list                            | "azureAuth":{"authenticationType":"container-apps"},                                                                                                         |
      | an allowed identity sent to a resource that isn't on the list | "embeddingEndpoint":"http://testbench.:3004/openai/deployments/d/embeddings?api-version=2024-10-21","azureAuth":{"authenticationType":"workload-identity"}, |
