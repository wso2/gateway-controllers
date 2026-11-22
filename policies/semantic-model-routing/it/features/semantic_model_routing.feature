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

@semantic-model-routing
Feature: Semantic model routing policy
  As an API developer
  I want prompts sent to the model whose example utterances they resemble
  So that each kind of request reaches the model best suited to it

  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"

  # The testbench embeddings service gives the same text the same vector, so a prompt equal to an
  # utterance scores 1.0, and the echo upstream shows the model the policy chose.
  Scenario: A prompt like a route's utterance goes to that route's model
    Given I generate a unique value from "smr-match" and store it as "apiName"
    And I generate a unique API version from "smr-match" and store it as "apiVersion"
    And I generate a unique API context from "/smr-match" and store it as "apiContext"
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

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 200 with body:
      """
      {"model":"original-model","messages":[{"role":"user","content":"write a python function"}]}
      """
    Then the response body should contain "coding-model"
    And the response body should not contain "default-model"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 404

  Scenario: A prompt like no utterance goes to the default model
    Given I generate a unique value from "smr-default" and store it as "apiName"
    And I generate a unique API version from "smr-default" and store it as "apiVersion"
    And I generate a unique API context from "/smr-default" and store it as "apiContext"
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

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 200 with body:
      """
      {"model":"original-model","messages":[{"role":"user","content":"what is the capital of France"}]}
      """
    Then the response body should contain "default-model"
    And the response body should not contain "coding-model"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 404

  # The testbench embeddings service answers 500 to a text asking it to simulate an error.
  Scenario: When the embedding provider fails, the request goes to the default model
    Given I generate a unique value from "smr-embed-error" and store it as "apiName"
    And I generate a unique API version from "smr-embed-error" and store it as "apiVersion"
    And I generate a unique API context from "/smr-embed-error" and store it as "apiContext"
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

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 200 with body:
      """
      {"model":"original-model","messages":[{"role":"user","content":"please simulate error"}]}
      """
    Then the response body should contain "default-model"
    And the response body should not contain "coding-model"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 404
