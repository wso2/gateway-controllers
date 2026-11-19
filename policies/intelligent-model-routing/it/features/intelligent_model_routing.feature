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

@intelligent-model-routing
Feature: Intelligent model routing policy
  As an API developer
  I want the intelligent-model-routing policy to ask a classifier LLM which routing rule a request
  matches and to rewrite the request's model to that rule's model
  So that each request reaches the model suited to it, and the default model when no rule applies

  The testbench openai service plays the classifier. Each of its chat paths answers with a fixed
  reply ("Flex tier response." on /openai/v1/chat-flex, "Batch tier response." on
  /openai/v1/chat-batch, an empty reply on /__readiness), so the routing rules are named after
  those replies and a scenario picks the classifier's answer through llmEndpoint. The overlay's
  classifier answers "Hello! How can I assist you today?", which names no rule. The capture service
  records the classification request when a scenario needs to see it. The echo backend reflects
  the routed request, so its "json.model" is the model the upstream received.

  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"
    And I resolve the "capture" service URL at "" and store it as "captureUpstream"

  Scenario Outline: The classifier's answer selects the model of the rule it names
    Given I generate a unique value from "imr-match" and store it as "apiName"
    And I generate a unique API version from "imr-match" and store it as "apiVersion"
    And I generate a unique API context from "/imr-match" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}  |
      | name                   | ${CTX:apiName}             |
      | spec.displayName       | ${CTX:apiName}             |
      | spec.version           | ${CTX:apiVersion}          |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3002      |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"POST","path":"/chat","policies":[{"name":"intelligent-model-routing","version":"v0","params":{"routingRules":[{"name":"Flex tier response.","context":"Requests the classifier labels as flex tier","model":"imr-flex-model"},{"name":"Batch tier response.","context":"Requests the classifier labels as batch tier","model":"imr-batch-model"}],"defaultModel":"imr-default-model","requestModel":{"location":"payload","identifier":"$.model"},"llmEndpoint":"http://testbench:3008<classifierPath>"}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" with body:
      """
      {"model":"imr-original-model","messages":[{"role":"user","content":"Route this request"}]}
      """
    Then the response status code should be 200
    And the JSON response field "json.model" should be "<routedModel>"
    And the JSON response field "json.messages[0].content" should be "Route this request"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 404

    Examples:
      | classifierPath           | routedModel     |
      | /openai/v1/chat-flex     | imr-flex-model  |
      | /openai/v1/chat-batch    | imr-batch-model |

  Scenario: Rule names match the classifier's answer regardless of case
    Given I generate a unique value from "imr-case" and store it as "apiName"
    And I generate a unique API version from "imr-case" and store it as "apiVersion"
    And I generate a unique API context from "/imr-case" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}  |
      | name                   | ${CTX:apiName}             |
      | spec.displayName       | ${CTX:apiName}             |
      | spec.version           | ${CTX:apiVersion}          |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3002      |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"POST","path":"/chat","policies":[{"name":"intelligent-model-routing","version":"v0","params":{"routingRules":[{"name":"FLEX TIER RESPONSE.","context":"Requests the classifier labels as flex tier","model":"imr-flex-model"}],"defaultModel":"imr-default-model","requestModel":{"location":"payload","identifier":"$.model"},"llmEndpoint":"http://testbench:3008/openai/v1/chat-flex"}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" with body:
      """
      {"model":"imr-original-model","messages":[{"role":"user","content":"Route this request"}]}
      """
    Then the response status code should be 200
    And the JSON response field "json.model" should be "imr-flex-model"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 404

  # No llmEndpoint in params: the policy uses the classifier the gateway configuration names.
  Scenario: An answer that names no rule routes to the default model
    Given I generate a unique value from "imr-no-rule" and store it as "apiName"
    And I generate a unique API version from "imr-no-rule" and store it as "apiVersion"
    And I generate a unique API context from "/imr-no-rule" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}  |
      | name                   | ${CTX:apiName}             |
      | spec.displayName       | ${CTX:apiName}             |
      | spec.version           | ${CTX:apiVersion}          |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3002      |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"POST","path":"/chat","policies":[{"name":"intelligent-model-routing","version":"v0","params":{"routingRules":[{"name":"Flex tier response.","context":"Requests the classifier labels as flex tier","model":"imr-flex-model"},{"name":"Batch tier response.","context":"Requests the classifier labels as batch tier","model":"imr-batch-model"}],"defaultModel":"imr-default-model","requestModel":{"location":"payload","identifier":"$.model"}}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" with body:
      """
      {"model":"imr-original-model","messages":[{"role":"user","content":"Route this request"}]}
      """
    Then the response status code should be 200
    And the JSON response field "json.model" should be "imr-default-model"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 404

  Scenario: An empty answer routes to the default model
    Given I generate a unique value from "imr-empty-answer" and store it as "apiName"
    And I generate a unique API version from "imr-empty-answer" and store it as "apiVersion"
    And I generate a unique API context from "/imr-empty-answer" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}  |
      | name                   | ${CTX:apiName}             |
      | spec.displayName       | ${CTX:apiName}             |
      | spec.version           | ${CTX:apiVersion}          |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3002      |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"POST","path":"/chat","policies":[{"name":"intelligent-model-routing","version":"v0","params":{"routingRules":[{"name":"Flex tier response.","context":"Requests the classifier labels as flex tier","model":"imr-flex-model"},{"name":"Batch tier response.","context":"Requests the classifier labels as batch tier","model":"imr-batch-model"}],"defaultModel":"imr-default-model","requestModel":{"location":"payload","identifier":"$.model"},"llmEndpoint":"http://testbench:3008/__readiness"}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" with body:
      """
      {"model":"imr-original-model","messages":[{"role":"user","content":"Route this request"}]}
      """
    Then the response status code should be 200
    And the JSON response field "json.model" should be "imr-default-model"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 404

  Scenario: A classifier that fails lets the request through on the default model
    Given I generate a unique value from "imr-classifier-error" and store it as "apiName"
    And I generate a unique API version from "imr-classifier-error" and store it as "apiVersion"
    And I generate a unique API context from "/imr-classifier-error" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}  |
      | name                   | ${CTX:apiName}             |
      | spec.displayName       | ${CTX:apiName}             |
      | spec.version           | ${CTX:apiVersion}          |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3002      |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"POST","path":"/chat","policies":[{"name":"intelligent-model-routing","version":"v0","params":{"routingRules":[{"name":"Flex tier response.","context":"Requests the classifier labels as flex tier","model":"imr-flex-model"},{"name":"Batch tier response.","context":"Requests the classifier labels as batch tier","model":"imr-batch-model"}],"defaultModel":"imr-default-model","requestModel":{"location":"payload","identifier":"$.model"},"llmEndpoint":"http://testbench:3002/status/500"}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" with body:
      """
      {"model":"imr-original-model","messages":[{"role":"user","content":"Route this request"}]}
      """
    Then the response status code should be 200
    And the JSON response field "json.model" should be "imr-default-model"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 404

  # The capture service answers with the request it recorded, which carries no "choices", so the
  # policy treats the answer as unusable and routes to the default model.
  Scenario: The classifier receives the routing rules and the last message of the request
    Given I generate a unique value from "imr-classifier-request" and store it as "apiName"
    And I generate a unique API version from "imr-classifier-request" and store it as "apiVersion"
    And I generate a unique API context from "/imr-classifier-request" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}  |
      | name                   | ${CTX:apiName}             |
      | spec.displayName       | ${CTX:apiName}             |
      | spec.version           | ${CTX:apiVersion}          |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3002      |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"POST","path":"/chat","policies":[{"name":"intelligent-model-routing","version":"v0","params":{"routingRules":[{"name":"Weather Information","context":"Questions about weather forecasts","model":"imr-weather-model"},{"name":"Coding Questions","context":"Questions about writing software","model":"imr-coding-model"}],"defaultModel":"imr-default-model","requestModel":{"location":"payload","identifier":"$.model"},"llmEndpoint":"${CTX:captureUpstream}/${CTX:apiName}/chat/completions"}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" with body:
      """
      {"model":"imr-original-model","messages":[{"role":"user","content":"An earlier message about databases"},{"role":"assistant","content":"Noted."},{"role":"user","content":"Will it rain in Colombo tomorrow?"}]}
      """
    Then the response status code should be 200
    And the JSON response field "json.model" should be "imr-default-model"

    When I send a "GET" request to the "capture" service at "/test/captured?path=/${CTX:apiName}/chat/completions"
    Then the response status code should be 200
    And the JSON response field "method" should be "POST"
    And the JSON response field "headers.Authorization[0]" should be "Bearer imr-classifier-key"
    And the JSON response field "headers.Content-Type[0]" should be "application/json"
    And the JSON response field "body" should contain "imr-classifier-model"
    And the JSON response field "body" should contain "You are an API routing assistant."
    And the JSON response field "body" should contain "- Weather Information: Questions about weather forecasts"
    And the JSON response field "body" should contain "- Coding Questions: Questions about writing software"
    And the JSON response field "body" should contain "You MUST respond with ONLY one of: Weather Information, Coding Questions, NONE"
    And the JSON response field "body" should contain "Will it rain in Colombo tomorrow?"
    And the response body should not contain "An earlier message about databases"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 404

  Scenario: contentPath selects the request text the classifier sees
    Given I generate a unique value from "imr-content-path" and store it as "apiName"
    And I generate a unique API version from "imr-content-path" and store it as "apiVersion"
    And I generate a unique API context from "/imr-content-path" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}  |
      | name                   | ${CTX:apiName}             |
      | spec.displayName       | ${CTX:apiName}             |
      | spec.version           | ${CTX:apiVersion}          |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3002      |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"POST","path":"/chat","policies":[{"name":"intelligent-model-routing","version":"v0","params":{"routingRules":[{"name":"Flex tier response.","context":"Requests the classifier labels as flex tier","model":"imr-flex-model"},{"name":"Batch tier response.","context":"Requests the classifier labels as batch tier","model":"imr-batch-model"}],"defaultModel":"imr-default-model","requestModel":{"location":"payload","identifier":"$.model"},"contentPath":"$.input.query","llmEndpoint":"${CTX:captureUpstream}/${CTX:apiName}/chat/completions"}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" with body:
      """
      {"model":"imr-original-model","input":{"query":"Text from the custom content path"},"messages":[{"role":"user","content":"Text from the last message"}]}
      """
    Then the response status code should be 200
    And the JSON response field "json.model" should be "imr-default-model"

    When I send a "GET" request to the "capture" service at "/test/captured?path=/${CTX:apiName}/chat/completions"
    Then the response status code should be 200
    And the JSON response field "body" should contain "Text from the custom content path"
    And the response body should not contain "Text from the last message"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 404

  Scenario: An AZURE_OPENAI classifier is called with the api-key header
    Given I generate a unique value from "imr-azure" and store it as "apiName"
    And I generate a unique API version from "imr-azure" and store it as "apiVersion"
    And I generate a unique API context from "/imr-azure" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}  |
      | name                   | ${CTX:apiName}             |
      | spec.displayName       | ${CTX:apiName}             |
      | spec.version           | ${CTX:apiVersion}          |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3002      |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"POST","path":"/chat","policies":[{"name":"intelligent-model-routing","version":"v0","params":{"routingRules":[{"name":"Flex tier response.","context":"Requests the classifier labels as flex tier","model":"imr-flex-model"},{"name":"Batch tier response.","context":"Requests the classifier labels as batch tier","model":"imr-batch-model"}],"defaultModel":"imr-default-model","requestModel":{"location":"payload","identifier":"$.model"},"llmProvider":"AZURE_OPENAI","llmEndpoint":"${CTX:captureUpstream}/${CTX:apiName}/chat/completions"}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" with body:
      """
      {"model":"imr-original-model","messages":[{"role":"user","content":"Route this request"}]}
      """
    Then the response status code should be 200
    And the JSON response field "json.model" should be "imr-default-model"

    When I send a "GET" request to the "capture" service at "/test/captured?path=/${CTX:apiName}/chat/completions"
    Then the response status code should be 200
    And the JSON response field "headers.Api-Key[0]" should be "imr-classifier-key"
    And the JSON response field "headers.Authorization" should not exist

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 404

  Scenario: A request without text at the content path routes to the default model without a classifier call
    Given I generate a unique value from "imr-no-content" and store it as "apiName"
    And I generate a unique API version from "imr-no-content" and store it as "apiVersion"
    And I generate a unique API context from "/imr-no-content" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}  |
      | name                   | ${CTX:apiName}             |
      | spec.displayName       | ${CTX:apiName}             |
      | spec.version           | ${CTX:apiVersion}          |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3002      |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"POST","path":"/chat","policies":[{"name":"intelligent-model-routing","version":"v0","params":{"routingRules":[{"name":"Flex tier response.","context":"Requests the classifier labels as flex tier","model":"imr-flex-model"},{"name":"Batch tier response.","context":"Requests the classifier labels as batch tier","model":"imr-batch-model"}],"defaultModel":"imr-default-model","requestModel":{"location":"payload","identifier":"$.model"},"llmEndpoint":"${CTX:captureUpstream}/${CTX:apiName}/chat/completions"}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" with body:
      """
      {"model":"imr-original-model","prompt":"There are no messages in this request"}
      """
    Then the response status code should be 200
    And the JSON response field "json.model" should be "imr-default-model"

    When I send a "GET" request to the "capture" service at "/test/captured?path=/${CTX:apiName}/chat/completions"
    Then the response status code should be 204

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 404
