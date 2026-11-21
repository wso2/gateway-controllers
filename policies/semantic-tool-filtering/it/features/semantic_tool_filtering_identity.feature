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
# no API key. The policy embeds the query and the tools when a request arrives and fails open, so a
# request that reaches the upstream with one tool left shows the API's Azure identity authenticated,
# and one that keeps all three shows the embedding failed. Each API chooses its identity in azureAuth.
# The gateway gets its workload identity from the testbench Entra ID mock and its container app's
# identity from the testbench Container Apps identity endpoint.
@semantic-tool-filtering-identity
Feature: Semantic tool filtering with the gateway's Azure identity
  As an API developer
  I want my API's embedding calls to authenticate with the gateway's Azure identity
  So that no Azure OpenAI key has to be stored or rotated

  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"

  Scenario: Tools are filtered with the gateway's workload identity
    Given I generate a unique resource name from "stf-wi" and store it as "providerName"
    And I generate a unique value from "stf-wi" and store it as "providerDisplayName"
    And I generate a unique API version from "stf-wi" and store it as "providerVersion"
    And I generate a unique API context from "/stf-wi" and store it as "providerContext"
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

  # A managed identity of the container app the gateway runs in: its system-assigned identity.
  Scenario: Tools are filtered with the container app's identity
    Given I generate a unique resource name from "stf-ca" and store it as "providerName"
    And I generate a unique value from "stf-ca" and store it as "providerDisplayName"
    And I generate a unique API version from "stf-ca" and store it as "providerVersion"
    And I generate a unique API context from "/stf-ca" and store it as "providerContext"
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
      | spec.operationPolicies | [{"name":"semantic-tool-filtering","version":"v1","paths":[{"path":"/gemini/v1/models/gemini-1.5-flash-002:generateContent","methods":["POST"],"params":{"selectionMode":"By Rank","limit":1,"queryJSONPath":"$.contents[0].parts[0].text","toolsJSONPath":"$.tools[0].function_declarations","userQueryIsJson":true,"toolsIsJson":true,"azureAuth":{"authenticationType":"container-apps"}}}]}] |
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

  # A token scope the testbench Container Apps identity endpoint always refuses, so the API gets no
  # access token and no embedding. The policy fails open: the upstream receives every tool.
  Scenario: Without an access token, the request keeps every tool
    Given I generate a unique resource name from "stf-noid" and store it as "providerName"
    And I generate a unique value from "stf-noid" and store it as "providerDisplayName"
    And I generate a unique API version from "stf-noid" and store it as "providerVersion"
    And I generate a unique API context from "/stf-noid" and store it as "providerContext"
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
      | spec.operationPolicies | [{"name":"semantic-tool-filtering","version":"v1","paths":[{"path":"/gemini/v1/models/gemini-1.5-flash-002:generateContent","methods":["POST"],"params":{"selectionMode":"By Rank","limit":1,"queryJSONPath":"$.contents[0].parts[0].text","toolsJSONPath":"$.tools[0].function_declarations","userQueryIsJson":true,"toolsIsJson":true,"azureAuth":{"authenticationType":"container-apps","scope":"api://identity-not-found/.default"}}}]}] |
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
    And the JSON response array field "json.tools[0].function_declarations" should have 3 items

    When I delete the LLM provider "${CTX:providerName}"
    Then the response should be successful

  # An API without azureAuth sends an API key. On a gateway with no key it brings its own, and it can
  # point at a deployment of its own too.
  Scenario: An API can still use its own endpoint and key
    Given I generate a unique resource name from "stf-ownkey" and store it as "providerName"
    And I generate a unique value from "stf-ownkey" and store it as "providerDisplayName"
    And I generate a unique API version from "stf-ownkey" and store it as "providerVersion"
    And I generate a unique API context from "/stf-ownkey" and store it as "providerContext"
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
      | spec.operationPolicies | [{"name":"semantic-tool-filtering","version":"v1","paths":[{"path":"/gemini/v1/models/gemini-1.5-flash-002:generateContent","methods":["POST"],"params":{"selectionMode":"By Rank","limit":1,"queryJSONPath":"$.contents[0].parts[0].text","toolsJSONPath":"$.tools[0].function_declarations","userQueryIsJson":true,"toolsIsJson":true,"embeddingEndpoint":"http://testbench:3004/openai/deployments/other/embeddings?api-version=2024-10-21","apiKey":"test-api-key"}}]}] |
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

  # The testbench refuses the key, so the embedding fails and the request keeps every tool.
  Scenario: A wrong key leaves the tools unfiltered
    Given I generate a unique resource name from "stf-wrongkey" and store it as "providerName"
    And I generate a unique value from "stf-wrongkey" and store it as "providerDisplayName"
    And I generate a unique API version from "stf-wrongkey" and store it as "providerVersion"
    And I generate a unique API context from "/stf-wrongkey" and store it as "providerContext"
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
      | spec.operationPolicies | [{"name":"semantic-tool-filtering","version":"v1","paths":[{"path":"/gemini/v1/models/gemini-1.5-flash-002:generateContent","methods":["POST"],"params":{"selectionMode":"By Rank","limit":1,"queryJSONPath":"$.contents[0].parts[0].text","toolsJSONPath":"$.tools[0].function_declarations","userQueryIsJson":true,"toolsIsJson":true,"embeddingEndpoint":"http://testbench:3004/openai/deployments/other/embeddings?api-version=2024-10-21","apiKey":"wrong-key"}}]}] |
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
    And the JSON response array field "json.tools[0].function_declarations" should have 3 items

    When I delete the LLM provider "${CTX:providerName}"
    Then the response should be successful

  # Without azureAuth the policy sends a key, and neither the API nor this gateway has one, so the
  # policy can't be built. Gateways up to 1.2.0 handle a policy that can't be built differently.
  Scenario: An API that sends a key fails to build when neither it nor the gateway has one
    Given the gateway version satisfies ">1.2.0"
    And I generate a unique value from "stf-nokey" and store it as "apiName"
    And I generate a unique API version from "stf-nokey" and store it as "apiVersion"
    And I generate a unique API context from "/stf-nokey" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}  |
      | name                   | ${CTX:apiName}             |
      | spec.displayName       | ${CTX:apiName}             |
      | spec.version           | ${CTX:apiVersion}          |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3002      |
      | spec.operations        | [{"method":"POST","path":"/chat","policies":[{"name":"semantic-tool-filtering","version":"v1","params":{"selectionMode":"By Rank"}}]},{"method":"GET","path":"/health"}] |
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 500 with body:
      """
      {"messages":[{"role":"user","content":"what is the weather today"}],"tools":[]}
      """
    Then the JSON response field "error" should be "Internal Server Error"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 404

  # The controller checks an API's params against the policy definition before deploying it.
  # azureAuth is an object that takes a known type, a GUID client ID and a /.default scope, and
  # nothing else. A rejected API is never deployed, so its route answers 404.
  Scenario Outline: The controller rejects azureAuth settings that don't fit the policy (<case>)
    Given I generate a unique value from "stf-invalid-auth" and store it as "apiName"
    And I generate a unique API version from "stf-invalid-auth" and store it as "apiVersion"
    And I generate a unique API context from "/stf-invalid-auth" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}  |
      | name                   | ${CTX:apiName}             |
      | spec.displayName       | ${CTX:apiName}             |
      | spec.version           | ${CTX:apiVersion}          |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3002      |
      | spec.operations        | [{"method":"POST","path":"/chat","policies":[{"name":"semantic-tool-filtering","version":"v1","params":{<params>,"selectionMode":"By Rank"}}]}] |
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
    Given I generate a unique value from "stf-allowlist-param" and store it as "apiName"
    And I generate a unique API version from "stf-allowlist-param" and store it as "apiVersion"
    And I generate a unique API context from "/stf-allowlist-param" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}  |
      | name                   | ${CTX:apiName}             |
      | spec.displayName       | ${CTX:apiName}             |
      | spec.version           | ${CTX:apiVersion}          |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3002      |
      | spec.operations        | [{"method":"POST","path":"/chat","policies":[{"name":"semantic-tool-filtering","version":"v1","params":{<params>,"selectionMode":"By Rank"}}]}] |
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
