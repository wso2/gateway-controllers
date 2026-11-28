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
@semantic-tool-filtering-allowlist
Feature: The gateway's lists of allowed authentication types and endpoints for embeddings
  As a gateway operator
  I want to limit how APIs authenticate to the embedding provider
  So that no API sends the API key, uses an identity I haven't allowed, or sends either elsewhere

  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"

  Scenario: An API that chooses an allowed authentication type filters tools
    Given I generate a unique resource name from "stf-allow-wi" and store it as "providerName"
    And I generate a unique value from "stf-allow-wi" and store it as "providerDisplayName"
    And I generate a unique API version from "stf-allow-wi" and store it as "providerVersion"
    And I generate a unique API context from "/stf-allow-wi" and store it as "providerContext"
    When I create LLM provider from "resources/templates/llm-provider.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:providerName}        |
      | displayName            | ${CTX:providerDisplayName} |
      | version                | ${CTX:providerVersion}     |
      | template               | gemini                     |
      | spec.context           | ${CTX:providerContext}     |
      | spec.upstream.url      | http://testbench:3002/anything |
      | spec.upstream.auth     | {"type":"api-key","header":"Authorization","value":"test-key"} |
      | accessControl.mode     | allow_all                  |
      | spec.operationPolicies | [{"name":"semantic-tool-filtering","version":"v1","paths":[{"path":"/gemini/v1/models/gemini-1.5-flash-002:generateContent","methods":["POST"],"params":{"selectionMode":"By Rank","limit":1,"queryJSONPath":"$.contents[0].parts[0].text","toolsJSONPath":"$.tools[0].function_declarations","userQueryIsJson":true,"toolsIsJson":true,"azureAuth":{"authenticationType":"workload-identity"}}}]}] |
    Then the response should be successful

    When I send a "POST" request to "${CTX:providerContext}/gemini/v1/models/gemini-1.5-flash-002:generateContent" until status 200 with body:
      """
      {"contents":[{"role":"user","parts":[{"text":"warmup"}]}],"tools":[{"function_declarations":[{"name":"warmup_tool","description":"Warmup tool"}]}]}
      """

    When I set header "Content-Type" to "application/json"
    And I send a "POST" request to "${CTX:providerContext}/gemini/v1/models/gemini-1.5-flash-002:generateContent" with body:
      """
      {
        "contents": [{"role":"user","parts":[{"text":"Please check weather forecast for London"}]}],
        "tools": [{"function_declarations":[
          {"name":"send_email","description":"Send email notifications to recipients"},
          {"name":"get_weather","description":"Get current weather and short-term forecast for a city"},
          {"name":"book_venue","description":"Reserve a conference room for meetings"}
        ]}]
      }
      """
    Then the response status code should be 200
    And the response should be valid JSON
    And the JSON response array field "json.tools[0].function_declarations" should have 1 items

    When I delete the LLM provider "${CTX:providerName}"
    Then the response should be successful

  # The endpoint list names resources, so another deployment or API version on a listed resource is
  # allowed.
  Scenario: An API's own deployment on a listed resource is allowed
    Given I generate a unique resource name from "stf-allow-own" and store it as "providerName"
    And I generate a unique value from "stf-allow-own" and store it as "providerDisplayName"
    And I generate a unique API version from "stf-allow-own" and store it as "providerVersion"
    And I generate a unique API context from "/stf-allow-own" and store it as "providerContext"
    When I create LLM provider from "resources/templates/llm-provider.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:providerName}        |
      | displayName            | ${CTX:providerDisplayName} |
      | version                | ${CTX:providerVersion}     |
      | template               | gemini                     |
      | spec.context           | ${CTX:providerContext}     |
      | spec.upstream.url      | http://testbench:3002/anything |
      | spec.upstream.auth     | {"type":"api-key","header":"Authorization","value":"test-key"} |
      | accessControl.mode     | allow_all                  |
      | spec.operationPolicies | [{"name":"semantic-tool-filtering","version":"v1","paths":[{"path":"/gemini/v1/models/gemini-1.5-flash-002:generateContent","methods":["POST"],"params":{"selectionMode":"By Rank","limit":1,"queryJSONPath":"$.contents[0].parts[0].text","toolsJSONPath":"$.tools[0].function_declarations","userQueryIsJson":true,"toolsIsJson":true,"embeddingEndpoint":"http://testbench:3004/openai/deployments/other/embeddings?api-version=2025-01-01","azureAuth":{"authenticationType":"workload-identity"}}}]}] |
    Then the response should be successful

    When I send a "POST" request to "${CTX:providerContext}/gemini/v1/models/gemini-1.5-flash-002:generateContent" until status 200 with body:
      """
      {"contents":[{"role":"user","parts":[{"text":"warmup"}]}],"tools":[{"function_declarations":[{"name":"warmup_tool","description":"Warmup tool"}]}]}
      """

    When I set header "Content-Type" to "application/json"
    And I send a "POST" request to "${CTX:providerContext}/gemini/v1/models/gemini-1.5-flash-002:generateContent" with body:
      """
      {
        "contents": [{"role":"user","parts":[{"text":"Please check weather forecast for London"}]}],
        "tools": [{"function_declarations":[
          {"name":"send_email","description":"Send email notifications to recipients"},
          {"name":"get_weather","description":"Get current weather and short-term forecast for a city"},
          {"name":"book_venue","description":"Reserve a conference room for meetings"}
        ]}]
      }
      """
    Then the response status code should be 200
    And the response should be valid JSON
    And the JSON response array field "json.tools[0].function_declarations" should have 1 items

    When I delete the LLM provider "${CTX:providerName}"
    Then the response should be successful

  # Gateways up to 1.2.0 handle a policy that can't be built differently, so these run on newer ones.
  # The same host on another port is another resource, so it isn't on the list.
  Scenario Outline: An API whose authentication type or endpoint the gateway doesn't allow fails closed (<case>)
    Given the gateway version satisfies ">1.2.0"
    And I generate a unique value from "stf-refused" and store it as "apiName"
    And I generate a unique API version from "stf-refused" and store it as "apiVersion"
    And I generate a unique API context from "/stf-refused" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}  |
      | name                   | ${CTX:apiName}             |
      | spec.displayName       | ${CTX:apiName}             |
      | spec.version           | ${CTX:apiVersion}          |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3002      |
      | spec.operations        | [{"method":"POST","path":"/chat","policies":[{"name":"semantic-tool-filtering","version":"v1","params":{<params>"selectionMode":"By Rank"}}]},{"method":"GET","path":"/health"}] |
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 500 with body:
      """
      {"messages":[{"role":"user","content":"what is the weather today"}],"tools":[]}
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
      | an allowed identity sent to a resource that isn't on the list | "embeddingEndpoint":"http://testbench:3002/openai/deployments/d/embeddings?api-version=2024-10-21","azureAuth":{"authenticationType":"workload-identity"}, |
