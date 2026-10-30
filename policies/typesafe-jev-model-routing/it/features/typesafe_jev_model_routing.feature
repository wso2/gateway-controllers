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

@typesafe-jev-model-routing
Feature: TypeSafe Jev model routing policy
  As an AI platform operator
  I want TypeSafe Jev to pick the model for each LLM request from plain-language routing rules
  So that each request reaches the model, and provider, that suits it

  # The testbench jev service stands in for TypeSafe's API. Each scenario points the policy's
  # baseURL at its own partition of it, http://testbench:3019/<partition>/<mode>, so the requests
  # the policy makes can be read back for that scenario alone. A "jev:route=<rule>@<probability>"
  # marker in the prompt sets Jev's choice. Providers forward to the echo backend, which reflects
  # the upstream path and body, so the echoed model and path show what the policy decided.

  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"

  Scenario: A confident rule match rewrites the request's model
    Given I generate a unique resource name from "jev-mr-match" and store it as "providerName"
    And I generate a unique value from "jev-mr-match" and store it as "providerDisplayName"
    And I generate a unique API version from "jev-mr-match" and store it as "providerVersion"
    And I generate a unique API context from "/jev-mr-match" and store it as "providerContext"
    And I generate a unique resource name from "jev-mr-match-jev" and store it as "jevPartition"
    And I resolve the "jev" service URL at "/${CTX:jevPartition}/ok" and store it as "jevBaseURL"
    When I create LLM provider from "resources/templates/llm-provider.yaml" with values:
      | apiVersion         | ${CTX:gatewaySpecVersion} |
      | name               | ${CTX:providerName} |
      | displayName        | ${CTX:providerDisplayName} |
      | version            | ${CTX:providerVersion} |
      | template           | openai |
      | spec.context       | ${CTX:providerContext} |
      | spec.upstream.url  | http://testbench:3002/primary-upstream |
      | accessControl.mode | allow_all |
      | spec.operationPolicies | [{"name":"typesafe-jev-model-routing","version":"v0","paths":[{"path":"/chat/completions","methods":["POST"],"params":{"baseURL":"${CTX:jevBaseURL}","routingRules":[{"name":"code","context":"Requests to write, debug or review code","model":"code-model"},{"name":"chat","context":"Small talk and greetings","model":"chat-model"},{"name":"analysis","context":"Multi-step reasoning over long documents","model":"analysis-model"}],"defaultModel":"default-model"}}]}] |
    Then the response status code should be 201
    And I send a "GET" request to "${CTX:providerContext}/models" until status 200

    When I send a "POST" request to "${CTX:providerContext}/chat/completions" with body:
      """
      {"model":"client-model","messages":[{"role":"user","content":"jev:route=code@0.9 Why does this function return null?"}]}
      """
    Then the response status code should be 200
    And the JSON response field "json.model" should be "code-model"
    And the JSON response field "json.messages[0].content" should be "jev:route=code@0.9 Why does this function return null?"
    When I send a "GET" request to the "jev" service at "/${CTX:jevPartition}/test/requests"
    Then the JSON response field "count" should be 1
    And the JSON response field "requests[0].state" should be "jev:route=code@0.9 Why does this function return null?"
    And the JSON response array field "requests[0].questionKeys" should have 1 item
    And the JSON response field "requests[0].questionKeys[0]" should be "route"
    And the JSON response field "requests[0].questions.route.type" should be "choice"
    And the JSON response field "requests[0].questions.route.criteria.code" should be "Requests to write, debug or review code"
    And the JSON response field "requests[0].questions.route.criteria.chat" should be "Small talk and greetings"
    And the JSON response field "requests[0].questions.route.criteria.analysis" should be "Multi-step reasoning over long documents"

    When I delete the LLM provider "${CTX:providerName}"
    Then the response should be successful

  Scenario: A rule below the default confidence threshold falls back to the default model
    Given I generate a unique resource name from "jev-mr-low" and store it as "providerName"
    And I generate a unique value from "jev-mr-low" and store it as "providerDisplayName"
    And I generate a unique API version from "jev-mr-low" and store it as "providerVersion"
    And I generate a unique API context from "/jev-mr-low" and store it as "providerContext"
    And I generate a unique resource name from "jev-mr-low-jev" and store it as "jevPartition"
    And I resolve the "jev" service URL at "/${CTX:jevPartition}/ok" and store it as "jevBaseURL"
    When I create LLM provider from "resources/templates/llm-provider.yaml" with values:
      | apiVersion         | ${CTX:gatewaySpecVersion} |
      | name               | ${CTX:providerName} |
      | displayName        | ${CTX:providerDisplayName} |
      | version            | ${CTX:providerVersion} |
      | template           | openai |
      | spec.context       | ${CTX:providerContext} |
      | spec.upstream.url  | http://testbench:3002/primary-upstream |
      | accessControl.mode | allow_all |
      | spec.operationPolicies | [{"name":"typesafe-jev-model-routing","version":"v0","paths":[{"path":"/chat/completions","methods":["POST"],"params":{"baseURL":"${CTX:jevBaseURL}","routingRules":[{"name":"code","context":"Requests to write, debug or review code","model":"code-model"},{"name":"chat","context":"Small talk and greetings","model":"chat-model"},{"name":"analysis","context":"Multi-step reasoning over long documents","model":"analysis-model"}],"defaultModel":"default-model"}}]}] |
    Then the response status code should be 201
    And I send a "GET" request to "${CTX:providerContext}/models" until status 200

    When I send a "POST" request to "${CTX:providerContext}/chat/completions" with body:
      """
      {"model":"client-model","messages":[{"role":"user","content":"jev:route=code:0.4,chat:0.3,analysis:0.3 Maybe a coding question?"}]}
      """
    Then the response status code should be 200
    And the JSON response field "json.model" should be "default-model"

    When I delete the LLM provider "${CTX:providerName}"
    Then the response should be successful

  Scenario: A custom confidence threshold decides whether a rule is followed
    Given I generate a unique resource name from "jev-mr-threshold" and store it as "providerName"
    And I generate a unique value from "jev-mr-threshold" and store it as "providerDisplayName"
    And I generate a unique API version from "jev-mr-threshold" and store it as "providerVersion"
    And I generate a unique API context from "/jev-mr-threshold" and store it as "providerContext"
    And I generate a unique resource name from "jev-mr-threshold-jev" and store it as "jevPartition"
    And I resolve the "jev" service URL at "/${CTX:jevPartition}/ok" and store it as "jevBaseURL"
    When I create LLM provider from "resources/templates/llm-provider.yaml" with values:
      | apiVersion         | ${CTX:gatewaySpecVersion} |
      | name               | ${CTX:providerName} |
      | displayName        | ${CTX:providerDisplayName} |
      | version            | ${CTX:providerVersion} |
      | template           | openai |
      | spec.context       | ${CTX:providerContext} |
      | spec.upstream.url  | http://testbench:3002/primary-upstream |
      | accessControl.mode | allow_all |
      | spec.operationPolicies | [{"name":"typesafe-jev-model-routing","version":"v0","paths":[{"path":"/chat/completions","methods":["POST"],"params":{"baseURL":"${CTX:jevBaseURL}","routingRules":[{"name":"code","context":"Requests to write, debug or review code","model":"code-model"},{"name":"chat","context":"Small talk and greetings","model":"chat-model"},{"name":"analysis","context":"Multi-step reasoning over long documents","model":"analysis-model"}],"defaultModel":"default-model","confidenceThreshold":0.8}}]}] |
    Then the response status code should be 201
    And I send a "GET" request to "${CTX:providerContext}/models" until status 200

    When I send a "POST" request to "${CTX:providerContext}/chat/completions" with body:
      """
      {"model":"client-model","messages":[{"role":"user","content":"jev:route=code@0.75 Review this function"}]}
      """
    Then the response status code should be 200
    And the JSON response field "json.model" should be "default-model"
    When I send a "POST" request to "${CTX:providerContext}/chat/completions" with body:
      """
      {"model":"client-model","messages":[{"role":"user","content":"jev:route=code@0.85 Review this function"}]}
      """
    Then the response status code should be 200
    And the JSON response field "json.model" should be "code-model"

    When I delete the LLM provider "${CTX:providerName}"
    Then the response should be successful

  Scenario: A rule that is not configured falls back to the default model
    Given I generate a unique resource name from "jev-mr-unknown" and store it as "providerName"
    And I generate a unique value from "jev-mr-unknown" and store it as "providerDisplayName"
    And I generate a unique API version from "jev-mr-unknown" and store it as "providerVersion"
    And I generate a unique API context from "/jev-mr-unknown" and store it as "providerContext"
    And I generate a unique resource name from "jev-mr-unknown-jev" and store it as "jevPartition"
    And I resolve the "jev" service URL at "/${CTX:jevPartition}/ok" and store it as "jevBaseURL"
    When I create LLM provider from "resources/templates/llm-provider.yaml" with values:
      | apiVersion         | ${CTX:gatewaySpecVersion} |
      | name               | ${CTX:providerName} |
      | displayName        | ${CTX:providerDisplayName} |
      | version            | ${CTX:providerVersion} |
      | template           | openai |
      | spec.context       | ${CTX:providerContext} |
      | spec.upstream.url  | http://testbench:3002/primary-upstream |
      | accessControl.mode | allow_all |
      | spec.operationPolicies | [{"name":"typesafe-jev-model-routing","version":"v0","paths":[{"path":"/chat/completions","methods":["POST"],"params":{"baseURL":"${CTX:jevBaseURL}","routingRules":[{"name":"code","context":"Requests to write, debug or review code","model":"code-model"},{"name":"chat","context":"Small talk and greetings","model":"chat-model"},{"name":"analysis","context":"Multi-step reasoning over long documents","model":"analysis-model"}],"defaultModel":"default-model"}}]}] |
    Then the response status code should be 201
    And I send a "GET" request to "${CTX:providerContext}/models" until status 200

    When I send a "POST" request to "${CTX:providerContext}/chat/completions" with body:
      """
      {"model":"client-model","messages":[{"role":"user","content":"jev:route=unknown@0.99 Something else entirely"}]}
      """
    Then the response status code should be 200
    And the JSON response field "json.model" should be "default-model"

    When I delete the LLM provider "${CTX:providerName}"
    Then the response should be successful

  # LLM proxies take additionalProviders from gateway 1.2.0.
  Scenario: A rule that names an additional provider routes the request to it
    Given the gateway version satisfies ">=1.2.0"
    And I generate a unique resource name from "jev-mr-provider-p" and store it as "primaryProviderName"
    And I generate a unique value from "jev-mr-provider-p" and store it as "primaryProviderDisplayName"
    And I generate a unique API version from "jev-mr-provider-p" and store it as "primaryProviderVersion"
    And I generate a unique API context from "/jev-mr-provider-p" and store it as "primaryProviderContext"
    And I generate a unique resource name from "jev-mr-provider-l" and store it as "largeProviderName"
    And I generate a unique value from "jev-mr-provider-l" and store it as "largeProviderDisplayName"
    And I generate a unique API version from "jev-mr-provider-l" and store it as "largeProviderVersion"
    And I generate a unique API context from "/jev-mr-provider-l" and store it as "largeProviderContext"
    And I generate a unique resource name from "jev-mr-provider-x" and store it as "proxyName"
    And I generate a unique value from "jev-mr-provider-x" and store it as "proxyDisplayName"
    And I generate a unique API version from "jev-mr-provider-x" and store it as "proxyVersion"
    And I generate a unique API context from "/jev-mr-provider-x" and store it as "proxyContext"
    And I generate a unique resource name from "jev-mr-provider-jev" and store it as "jevPartition"
    And I resolve the "jev" service URL at "/${CTX:jevPartition}/ok" and store it as "jevBaseURL"
    When I create LLM provider from "resources/templates/llm-provider.yaml" with values:
      | apiVersion         | ${CTX:gatewaySpecVersion} |
      | name               | ${CTX:primaryProviderName} |
      | displayName        | ${CTX:primaryProviderDisplayName} |
      | version            | ${CTX:primaryProviderVersion} |
      | template           | openai |
      | spec.context       | ${CTX:primaryProviderContext} |
      | spec.upstream.url  | http://testbench:3002/primary-upstream |
      | accessControl.mode | allow_all |
    Then the response status code should be 201
    And I send a "GET" request to "${CTX:primaryProviderContext}/models" until status 200
    When I create LLM provider from "resources/templates/llm-provider.yaml" with values:
      | apiVersion         | ${CTX:gatewaySpecVersion} |
      | name               | ${CTX:largeProviderName} |
      | displayName        | ${CTX:largeProviderDisplayName} |
      | version            | ${CTX:largeProviderVersion} |
      | template           | openai |
      | spec.context       | ${CTX:largeProviderContext} |
      | spec.upstream.url  | http://testbench:3002/large-upstream |
      | accessControl.mode | allow_all |
    Then the response status code should be 201
    And I send a "GET" request to "${CTX:largeProviderContext}/models" until status 200
    When I create LLM proxy from "resources/templates/llm-proxy.yaml" with values:
      | apiVersion               | ${CTX:gatewaySpecVersion} |
      | name                     | ${CTX:proxyName} |
      | displayName              | ${CTX:proxyDisplayName} |
      | version                  | ${CTX:proxyVersion} |
      | context                  | ${CTX:proxyContext} |
      | provider.id              | ${CTX:primaryProviderName} |
      | spec.additionalProviders | [{"id":"${CTX:largeProviderName}","as":"large"}] |
      | spec.operationPolicies   | [{"name":"typesafe-jev-model-routing","version":"v0","paths":[{"path":"/chat/completions","methods":["POST"],"params":{"baseURL":"${CTX:jevBaseURL}","routingRules":[{"name":"analysis","context":"Multi-step reasoning over long documents","model":"big-model","provider":"large"},{"name":"chat","context":"Small talk and greetings","model":"chat-model"},{"name":"code","context":"Requests to write, debug or review code","model":"code-model"}],"defaultModel":"default-model"}}]}] |
    Then the response status code should be 201
    And I send a "GET" request to "${CTX:proxyContext}/models" until status 200

    When I send a "POST" request to "${CTX:proxyContext}/chat/completions" with body:
      """
      {"model":"client-model","messages":[{"role":"user","content":"jev:route=analysis@0.9 Summarise the attached report"}]}
      """
    Then the response status code should be 200
    And the JSON response field "json.model" should be "big-model"
    And the JSON response field "path" should contain "/large-upstream"

    When I delete the LLM proxy "${CTX:proxyName}"
    Then the response should be successful
    When I delete the LLM provider "${CTX:largeProviderName}"
    Then the response should be successful
    When I delete the LLM provider "${CTX:primaryProviderName}"
    Then the response should be successful

  # LLM proxies take additionalProviders from gateway 1.2.0.
  Scenario: The fallback uses the default provider, but a rule without a provider stays on the primary
    Given the gateway version satisfies ">=1.2.0"
    And I generate a unique resource name from "jev-mr-default-provider-p" and store it as "primaryProviderName"
    And I generate a unique value from "jev-mr-default-provider-p" and store it as "primaryProviderDisplayName"
    And I generate a unique API version from "jev-mr-default-provider-p" and store it as "primaryProviderVersion"
    And I generate a unique API context from "/jev-mr-default-provider-p" and store it as "primaryProviderContext"
    And I generate a unique resource name from "jev-mr-default-provider-l" and store it as "largeProviderName"
    And I generate a unique value from "jev-mr-default-provider-l" and store it as "largeProviderDisplayName"
    And I generate a unique API version from "jev-mr-default-provider-l" and store it as "largeProviderVersion"
    And I generate a unique API context from "/jev-mr-default-provider-l" and store it as "largeProviderContext"
    And I generate a unique resource name from "jev-mr-default-provider-x" and store it as "proxyName"
    And I generate a unique value from "jev-mr-default-provider-x" and store it as "proxyDisplayName"
    And I generate a unique API version from "jev-mr-default-provider-x" and store it as "proxyVersion"
    And I generate a unique API context from "/jev-mr-default-provider-x" and store it as "proxyContext"
    And I generate a unique resource name from "jev-mr-default-provider-jev" and store it as "jevPartition"
    And I resolve the "jev" service URL at "/${CTX:jevPartition}/ok" and store it as "jevBaseURL"
    When I create LLM provider from "resources/templates/llm-provider.yaml" with values:
      | apiVersion         | ${CTX:gatewaySpecVersion} |
      | name               | ${CTX:primaryProviderName} |
      | displayName        | ${CTX:primaryProviderDisplayName} |
      | version            | ${CTX:primaryProviderVersion} |
      | template           | openai |
      | spec.context       | ${CTX:primaryProviderContext} |
      | spec.upstream.url  | http://testbench:3002/primary-upstream |
      | accessControl.mode | allow_all |
    Then the response status code should be 201
    And I send a "GET" request to "${CTX:primaryProviderContext}/models" until status 200
    When I create LLM provider from "resources/templates/llm-provider.yaml" with values:
      | apiVersion         | ${CTX:gatewaySpecVersion} |
      | name               | ${CTX:largeProviderName} |
      | displayName        | ${CTX:largeProviderDisplayName} |
      | version            | ${CTX:largeProviderVersion} |
      | template           | openai |
      | spec.context       | ${CTX:largeProviderContext} |
      | spec.upstream.url  | http://testbench:3002/large-upstream |
      | accessControl.mode | allow_all |
    Then the response status code should be 201
    And I send a "GET" request to "${CTX:largeProviderContext}/models" until status 200
    When I create LLM proxy from "resources/templates/llm-proxy.yaml" with values:
      | apiVersion               | ${CTX:gatewaySpecVersion} |
      | name                     | ${CTX:proxyName} |
      | displayName              | ${CTX:proxyDisplayName} |
      | version                  | ${CTX:proxyVersion} |
      | context                  | ${CTX:proxyContext} |
      | provider.id              | ${CTX:primaryProviderName} |
      | spec.additionalProviders | [{"id":"${CTX:largeProviderName}","as":"large"}] |
      | spec.operationPolicies   | [{"name":"typesafe-jev-model-routing","version":"v0","paths":[{"path":"/chat/completions","methods":["POST"],"params":{"baseURL":"${CTX:jevBaseURL}","routingRules":[{"name":"analysis","context":"Multi-step reasoning over long documents","model":"big-model","provider":"large"},{"name":"chat","context":"Small talk and greetings","model":"chat-model"},{"name":"code","context":"Requests to write, debug or review code","model":"code-model"}],"defaultModel":"default-model","defaultProvider":"large"}}]}] |
    Then the response status code should be 201
    And I send a "GET" request to "${CTX:proxyContext}/models" until status 200

    When I send a "POST" request to "${CTX:proxyContext}/chat/completions" with body:
      """
      {"model":"client-model","messages":[{"role":"user","content":"jev:route=analysis:0.3,chat:0.35,code:0.35 Not sure what this is"}]}
      """
    Then the response status code should be 200
    And the JSON response field "json.model" should be "default-model"
    And the JSON response field "path" should contain "/large-upstream"
    When I send a "POST" request to "${CTX:proxyContext}/chat/completions" with body:
      """
      {"model":"client-model","messages":[{"role":"user","content":"jev:route=chat@0.9 Hi, how are you?"}]}
      """
    Then the response status code should be 200
    And the JSON response field "json.model" should be "chat-model"
    And the JSON response field "path" should contain "/primary-upstream"

    When I delete the LLM proxy "${CTX:proxyName}"
    Then the response should be successful
    When I delete the LLM provider "${CTX:largeProviderName}"
    Then the response should be successful
    When I delete the LLM provider "${CTX:primaryProviderName}"
    Then the response should be successful

  Scenario: Only the text parts of a content-part array, or the value at contentPath, are classified
    Given I generate a unique resource name from "jev-mr-content" and store it as "providerName"
    And I generate a unique value from "jev-mr-content" and store it as "providerDisplayName"
    And I generate a unique API version from "jev-mr-content" and store it as "providerVersion"
    And I generate a unique API context from "/jev-mr-content" and store it as "providerContext"
    And I generate a unique resource name from "jev-mr-content-jev" and store it as "jevPartition"
    And I resolve the "jev" service URL at "/${CTX:jevPartition}/ok" and store it as "jevBaseURL"
    When I create LLM provider from "resources/templates/llm-provider.yaml" with values:
      | apiVersion         | ${CTX:gatewaySpecVersion} |
      | name               | ${CTX:providerName} |
      | displayName        | ${CTX:providerDisplayName} |
      | version            | ${CTX:providerVersion} |
      | template           | openai |
      | spec.context       | ${CTX:providerContext} |
      | spec.upstream.url  | http://testbench:3002/primary-upstream |
      | accessControl.mode | allow_all |
      | spec.operationPolicies | [{"name":"typesafe-jev-model-routing","version":"v0","paths":[{"path":"/chat/completions","methods":["POST"],"params":{"baseURL":"${CTX:jevBaseURL}","routingRules":[{"name":"code","context":"Requests to write, debug or review code","model":"code-model"},{"name":"chat","context":"Small talk and greetings","model":"chat-model"},{"name":"analysis","context":"Multi-step reasoning over long documents","model":"analysis-model"}],"defaultModel":"default-model"}}]},{"name":"typesafe-jev-model-routing","version":"v0","paths":[{"path":"/completions","methods":["POST"],"params":{"baseURL":"${CTX:jevBaseURL}","routingRules":[{"name":"code","context":"Requests to write, debug or review code","model":"code-model"},{"name":"chat","context":"Small talk and greetings","model":"chat-model"},{"name":"analysis","context":"Multi-step reasoning over long documents","model":"analysis-model"}],"defaultModel":"default-model","contentPath":"$.prompt"}}]}] |
    Then the response status code should be 201
    And I send a "GET" request to "${CTX:providerContext}/models" until status 200

    When I send a "POST" request to "${CTX:providerContext}/chat/completions" with body:
      """
      {"model":"client-model","messages":[{"role":"user","content":[{"type":"text","text":"part one"},{"type":"image_url","image_url":{"url":"https://example.com/a.png"}},{"type":"text","text":"part two"}]}]}
      """
    Then the response status code should be 200
    When I send a "POST" request to "${CTX:providerContext}/completions" with body:
      """
      {"model":"client-model","prompt":"jev:route=code@0.9 Fix this loop","suffix":"ignored"}
      """
    Then the response status code should be 200
    And the JSON response field "json.model" should be "code-model"
    When I send a "GET" request to the "jev" service at "/${CTX:jevPartition}/test/requests"
    Then the JSON response field "count" should be 2
    And the JSON response field "requests[0].state" should be:
      """
      part one
      part two
      """
    And the JSON response field "requests[1].state" should be "jev:route=code@0.9 Fix this loop"

    When I delete the LLM provider "${CTX:providerName}"
    Then the response should be successful

  Scenario: A streamed request is routed and still streams
    Given I generate a unique resource name from "jev-mr-stream" and store it as "providerName"
    And I generate a unique value from "jev-mr-stream" and store it as "providerDisplayName"
    And I generate a unique API version from "jev-mr-stream" and store it as "providerVersion"
    And I generate a unique API context from "/jev-mr-stream" and store it as "providerContext"
    And I generate a unique resource name from "jev-mr-stream-jev" and store it as "jevPartition"
    And I resolve the "jev" service URL at "/${CTX:jevPartition}/ok" and store it as "jevBaseURL"
    When I create LLM provider from "resources/templates/llm-provider.yaml" with values:
      | apiVersion         | ${CTX:gatewaySpecVersion} |
      | name               | ${CTX:providerName} |
      | displayName        | ${CTX:providerDisplayName} |
      | version            | ${CTX:providerVersion} |
      | template           | openai |
      | spec.context       | ${CTX:providerContext} |
      | spec.upstream.url  | http://testbench:3008/openai-echo/v1 |
      | accessControl.mode | allow_all |
      | spec.operationPolicies | [{"name":"typesafe-jev-model-routing","version":"v0","paths":[{"path":"/chat/completions","methods":["POST"],"params":{"baseURL":"${CTX:jevBaseURL}","routingRules":[{"name":"code","context":"Requests to write, debug or review code","model":"code-model"},{"name":"chat","context":"Small talk and greetings","model":"chat-model"},{"name":"analysis","context":"Multi-step reasoning over long documents","model":"analysis-model"}],"defaultModel":"default-model"}}]}] |
    Then the response status code should be 201
    And I send a "GET" request to "${CTX:providerContext}/models" until status 200

    When I send a "POST" request to "${CTX:providerContext}/chat/completions" with body:
      """
      {"model":"client-model","messages":[{"role":"user","content":"jev:route=code@0.9 Write a sort function"}],"stream":true}
      """
    Then the response status code should be 200
    And the response header "Content-Type" should contain "text/event-stream"
    And the response body should contain "code-model"
    And the response body should contain "data: [DONE]"

    When I delete the LLM provider "${CTX:providerName}"
    Then the response should be successful

  Scenario Outline: A Jev failure never rejects the request
    Given I generate a unique resource name from "jev-mr-failure" and store it as "providerName"
    And I generate a unique value from "jev-mr-failure" and store it as "providerDisplayName"
    And I generate a unique API version from "jev-mr-failure" and store it as "providerVersion"
    And I generate a unique API context from "/jev-mr-failure" and store it as "providerContext"
    And I generate a unique resource name from "jev-mr-failure-jev" and store it as "jevPartition"
    And I resolve the "jev" service URL at "/${CTX:jevPartition}/<mode>" and store it as "jevBaseURL"
    When I create LLM provider from "resources/templates/llm-provider.yaml" with values:
      | apiVersion         | ${CTX:gatewaySpecVersion} |
      | name               | ${CTX:providerName} |
      | displayName        | ${CTX:providerDisplayName} |
      | version            | ${CTX:providerVersion} |
      | template           | openai |
      | spec.context       | ${CTX:providerContext} |
      | spec.upstream.url  | http://testbench:3002/primary-upstream |
      | accessControl.mode | allow_all |
      | spec.operationPolicies | [{"name":"typesafe-jev-model-routing","version":"v0","paths":[{"path":"/chat/completions","methods":["POST"],"params":{"baseURL":"${CTX:jevBaseURL}","routingRules":[{"name":"code","context":"Requests to write, debug or review code","model":"code-model"},{"name":"chat","context":"Small talk and greetings","model":"chat-model"},{"name":"analysis","context":"Multi-step reasoning over long documents","model":"analysis-model"}],"defaultModel":"default-model","apiKey":"<key>"}}]}] |
    Then the response status code should be 201
    And I send a "GET" request to "${CTX:providerContext}/models" until status 200

    When I send a "POST" request to "${CTX:providerContext}/chat/completions" with body:
      """
      {"model":"client-model","messages":[{"role":"user","content":"jev:route=code@0.9 Debug this"}]}
      """
    Then the response status code should be 200
    And the JSON response field "json.model" should be "default-model"
    When I send a "GET" request to the "jev" service at "/${CTX:jevPartition}/test/requests"
    Then the JSON response field "count" should be 1

    When I delete the LLM provider "${CTX:providerName}"
    Then the response should be successful

    Examples:
      | mode         | key          |
      | error        | test-jev-key |
      | invalid-json | test-jev-key |
      | ok           | wrong-key    |

  Scenario: A Jev call that outlasts the timeout falls back within the timeout
    Given I generate a unique resource name from "jev-mr-timeout" and store it as "providerName"
    And I generate a unique value from "jev-mr-timeout" and store it as "providerDisplayName"
    And I generate a unique API version from "jev-mr-timeout" and store it as "providerVersion"
    And I generate a unique API context from "/jev-mr-timeout" and store it as "providerContext"
    And I generate a unique resource name from "jev-mr-timeout-jev" and store it as "jevPartition"
    And I resolve the "jev" service URL at "/${CTX:jevPartition}/slow" and store it as "jevBaseURL"
    When I create LLM provider from "resources/templates/llm-provider.yaml" with values:
      | apiVersion         | ${CTX:gatewaySpecVersion} |
      | name               | ${CTX:providerName} |
      | displayName        | ${CTX:providerDisplayName} |
      | version            | ${CTX:providerVersion} |
      | template           | openai |
      | spec.context       | ${CTX:providerContext} |
      | spec.upstream.url  | http://testbench:3002/primary-upstream |
      | accessControl.mode | allow_all |
      | spec.operationPolicies | [{"name":"typesafe-jev-model-routing","version":"v0","paths":[{"path":"/chat/completions","methods":["POST"],"params":{"baseURL":"${CTX:jevBaseURL}","routingRules":[{"name":"code","context":"Requests to write, debug or review code","model":"code-model"},{"name":"chat","context":"Small talk and greetings","model":"chat-model"},{"name":"analysis","context":"Multi-step reasoning over long documents","model":"analysis-model"}],"defaultModel":"default-model","timeout":"1s"}}]}] |
    Then the response status code should be 201
    And I send a "GET" request to "${CTX:providerContext}/models" until status 200

    When I send a "POST" request to "${CTX:providerContext}/chat/completions" with body:
      """
      {"model":"client-model","messages":[{"role":"user","content":"jev:route=code@0.9 Debug this"}]}
      """
    Then the response status code should be 200
    And the JSON response field "json.model" should be "default-model"
    And the gateway should have responded within "3" seconds

    When I delete the LLM provider "${CTX:providerName}"
    Then the response should be successful

  Scenario: A rate-limited Jev call is retried once
    Given I generate a unique resource name from "jev-mr-retry" and store it as "providerName"
    And I generate a unique value from "jev-mr-retry" and store it as "providerDisplayName"
    And I generate a unique API version from "jev-mr-retry" and store it as "providerVersion"
    And I generate a unique API context from "/jev-mr-retry" and store it as "providerContext"
    And I generate a unique resource name from "jev-mr-retry-jev" and store it as "jevPartition"
    And I resolve the "jev" service URL at "/${CTX:jevPartition}/ratelimit-once" and store it as "jevBaseURL"
    When I create LLM provider from "resources/templates/llm-provider.yaml" with values:
      | apiVersion         | ${CTX:gatewaySpecVersion} |
      | name               | ${CTX:providerName} |
      | displayName        | ${CTX:providerDisplayName} |
      | version            | ${CTX:providerVersion} |
      | template           | openai |
      | spec.context       | ${CTX:providerContext} |
      | spec.upstream.url  | http://testbench:3002/primary-upstream |
      | accessControl.mode | allow_all |
      | spec.operationPolicies | [{"name":"typesafe-jev-model-routing","version":"v0","paths":[{"path":"/chat/completions","methods":["POST"],"params":{"baseURL":"${CTX:jevBaseURL}","routingRules":[{"name":"code","context":"Requests to write, debug or review code","model":"code-model"},{"name":"chat","context":"Small talk and greetings","model":"chat-model"},{"name":"analysis","context":"Multi-step reasoning over long documents","model":"analysis-model"}],"defaultModel":"default-model"}}]}] |
    Then the response status code should be 201
    And I send a "GET" request to "${CTX:providerContext}/models" until status 200

    When I send a "POST" request to "${CTX:providerContext}/chat/completions" with body:
      """
      {"model":"client-model","messages":[{"role":"user","content":"jev:route=code@0.9 Debug this"}]}
      """
    Then the response status code should be 200
    And the JSON response field "json.model" should be "code-model"
    When I send a "GET" request to the "jev" service at "/${CTX:jevPartition}/test/requests"
    Then the JSON response field "count" should be 2

    When I delete the LLM provider "${CTX:providerName}"
    Then the response should be successful

  # Gateway 1.2.0 deploys an LLM provider without validating its operation policies' params.
  Scenario Outline: A routing configuration the schema rejects is refused at deployment
    Given the gateway version satisfies ">1.2.0"
    And I generate a unique resource name from "jev-mr-schema" and store it as "providerName"
    And I generate a unique value from "jev-mr-schema" and store it as "providerDisplayName"
    And I generate a unique API version from "jev-mr-schema" and store it as "providerVersion"
    And I generate a unique API context from "/jev-mr-schema" and store it as "providerContext"
    When I create LLM provider from "resources/templates/llm-provider.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:providerName} |
      | displayName            | ${CTX:providerDisplayName} |
      | version                | ${CTX:providerVersion} |
      | template               | openai |
      | spec.context           | ${CTX:providerContext} |
      | spec.upstream.url      | http://testbench:3002/primary-upstream |
      | accessControl.mode     | allow_all |
      | spec.operationPolicies | [{"name":"typesafe-jev-model-routing","version":"v0","paths":[{"path":"/chat/completions","methods":["POST"],"params":<params>}]}] |
    Then the response status code should be 400
    And the response should be valid JSON

    Examples:
      | case                     | params |
      | no routing rules         | {"defaultModel":"default-model"} |
      | no default model         | {"routingRules":[{"name":"code","context":"Code","model":"code-model"}]} |
      | rule without context     | {"routingRules":[{"name":"code","model":"code-model"}],"defaultModel":"default-model"} |
      | rule without model       | {"routingRules":[{"name":"code","context":"Code"}],"defaultModel":"default-model"} |
      | threshold above 1        | {"routingRules":[{"name":"code","context":"Code","model":"code-model"}],"defaultModel":"default-model","confidenceThreshold":1.5} |

  Scenario: Two rules with the same name stop the route
    Given I generate a unique resource name from "jev-mr-duplicate" and store it as "providerName"
    And I generate a unique value from "jev-mr-duplicate" and store it as "providerDisplayName"
    And I generate a unique API version from "jev-mr-duplicate" and store it as "providerVersion"
    And I generate a unique API context from "/jev-mr-duplicate" and store it as "providerContext"
    And I generate a unique resource name from "jev-mr-duplicate-jev" and store it as "jevPartition"
    And I resolve the "jev" service URL at "/${CTX:jevPartition}/ok" and store it as "jevBaseURL"
    When I create LLM provider from "resources/templates/llm-provider.yaml" with values:
      | apiVersion         | ${CTX:gatewaySpecVersion} |
      | name               | ${CTX:providerName} |
      | displayName        | ${CTX:providerDisplayName} |
      | version            | ${CTX:providerVersion} |
      | template           | openai |
      | spec.context       | ${CTX:providerContext} |
      | spec.upstream.url  | http://testbench:3002/primary-upstream |
      | accessControl.mode | allow_all |
      | spec.operationPolicies | [{"name":"typesafe-jev-model-routing","version":"v0","paths":[{"path":"/chat/completions","methods":["POST"],"params":{"baseURL":"${CTX:jevBaseURL}","routingRules":[{"name":"code","context":"Requests to write, debug or review code","model":"code-model"},{"name":"code","context":"Another description","model":"code-model"}],"defaultModel":"default-model"}}]}] |
    Then the response status code should be 201
    And I send a "GET" request to "${CTX:providerContext}/models" until status 200

    When I send a "POST" request to "${CTX:providerContext}/chat/completions" until status 500 with body:
      """
      {"model":"client-model","messages":[{"role":"user","content":"Any request"}]}
      """
    Then the "gateway-runtime" service logs should contain "is a duplicate; rule names must be unique"

    When I delete the LLM provider "${CTX:providerName}"
    Then the response should be successful

  Scenario: Every Jev call carries the key and model from the shared Jev configuration
    Given I generate a unique resource name from "jev-mr-shared" and store it as "providerName"
    And I generate a unique value from "jev-mr-shared" and store it as "providerDisplayName"
    And I generate a unique API version from "jev-mr-shared" and store it as "providerVersion"
    And I generate a unique API context from "/jev-mr-shared" and store it as "providerContext"
    And I generate a unique value from "jev-mr-shared-prompt" and store it as "prompt"
    When I create LLM provider from "resources/templates/llm-provider.yaml" with values:
      | apiVersion         | ${CTX:gatewaySpecVersion} |
      | name               | ${CTX:providerName} |
      | displayName        | ${CTX:providerDisplayName} |
      | version            | ${CTX:providerVersion} |
      | template           | openai |
      | spec.context       | ${CTX:providerContext} |
      | spec.upstream.url  | http://testbench:3002/primary-upstream |
      | accessControl.mode | allow_all |
      | spec.operationPolicies | [{"name":"typesafe-jev-model-routing","version":"v0","paths":[{"path":"/chat/completions","methods":["POST"],"params":{"routingRules":[{"name":"code","context":"Requests to write, debug or review code","model":"code-model"},{"name":"chat","context":"Small talk and greetings","model":"chat-model"},{"name":"analysis","context":"Multi-step reasoning over long documents","model":"analysis-model"}],"defaultModel":"default-model"}}]}] |
    Then the response status code should be 201
    And I send a "GET" request to "${CTX:providerContext}/models" until status 200

    When I send a "POST" request to "${CTX:providerContext}/chat/completions" with body:
      """
      {"model":"client-model","messages":[{"role":"user","content":"${CTX:prompt}"}]}
      """
    Then the response status code should be 200

    # Without a baseURL of its own, the policy uses the block's partition from the overlay.
    When I send a "GET" request to the "jev" service at "/${CTX:testbenchPartition}/test/requests"
    Then the JSON response array "requests" should contain an item with "state" equal to "${CTX:prompt}"
    And the JSON response array "requests" item with "state" equal to "${CTX:prompt}" should have "authorization" equal to "Bearer test-jev-key"
    And the JSON response array "requests" item with "state" equal to "${CTX:prompt}" should have "model" equal to "jev-it-model"

    When I delete the LLM provider "${CTX:providerName}"
    Then the response should be successful
