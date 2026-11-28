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

@llm-cost
Feature: LLM cost on different route shapes
  As an API developer
  I want to know what the policy does when the route is not a plain provider route
  So that a mis-attached or mis-ordered policy never breaks traffic and a custom template is priced like any other

  # The block stages a pricing file whose rates this suite controls (overlays/pricing/).
  # gpt-4o-mini costs 0.003 and my-org-llm 0.006 for 1000 prompt and 500 completion tokens.

  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"

  # A REST API route carries no LlmProviderTemplate, so there is nowhere to read usage from. The policy
  # leaves the call unpriced, still reports a cost of zero to analytics and never touches the response.
  Scenario: Attach llm-cost to a REST API route that has no LlmProviderTemplate
    Given I generate a unique value from "lc-rest" and store it as "apiName"
    And I generate a unique API version from "lc-rest" and store it as "apiVersion"
    And I generate a unique API context from "/lc-rest" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}     |
      | name                   | ${CTX:apiName}                |
      | spec.displayName       | ${CTX:apiName}                |
      | spec.version           | ${CTX:apiVersion}             |
      | spec.context           | ${CTX:apiContext}/$version    |
      | spec.upstream.main.url | http://testbench:3008          |
      | spec.operations        | [{"method":"POST","path":"/scripted/chat","policies":[{"name":"llm-cost","version":"v1"}]}] |
    Then the response should be successful

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/scripted/chat" until status 200 with body:
      """
      {"model":"gpt-4o-mini","messages":[{"role":"user","content":"Hello"}],"x_testbench_reply":{"body":{"id":"chatcmpl-lc","object":"chat.completion","model":"gpt-4o-mini","choices":[{"index":0,"message":{"role":"assistant","content":"Hi there"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1000,"completion_tokens":500,"total_tokens":1500}}}}
      """
    And the response body should be:
      """
      {"id":"chatcmpl-lc","object":"chat.completion","model":"gpt-4o-mini","choices":[{"index":0,"message":{"role":"assistant","content":"Hi there"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1000,"completion_tokens":500,"total_tokens":1500}}
      """
    And the response header "X-Testbench-Scripted" should be "true"
    And the response header "x-llm-cost" should not exist
    # The body is priceable, so nothing being reported here comes from the missing template alone: the
    # policy has no template to read usage from, and a REST API route carries no AI metadata of its own.
    And the latest analytics event for path "${CTX:apiContext}/${CTX:apiVersion}/scripted/chat" should not have metadata field "aiMetadata"
    And the latest analytics event for path "${CTX:apiContext}/${CTX:apiVersion}/scripted/chat" should not have metadata field "aiTokenUsage"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/scripted/chat" until status 404
    And I wait for the config dump to stop containing a route with base path "${CTX:apiContext}"

  # docs Example 1: the provider denies everything but two paths, and llm-cost is attached to one of
  # them. Only the attached path is priced.
  # The upstream URL carries /scripted because gateways rewrite the upstream path differently for a route
  # attached below the context (1.1.0 drops the route's own prefix, later releases keep it). Either way the
  # call still lands under /scripted/ on the testbench.
  Scenario: Attach llm-cost to one path of a provider that allows two
    Given I generate a unique resource name from "lc-narrow" and store it as "providerName"
    And I generate a unique value from "lc-narrow" and store it as "providerDisplayName"
    And I generate a unique API version from "lc-narrow" and store it as "providerVersion"
    And I generate a unique API context from "/lc-narrow" and store it as "providerContext"
    When I create LLM provider from "resources/templates/llm-provider.yaml" with values:
      | apiVersion                    | ${CTX:gatewaySpecVersion}  |
      | name                          | ${CTX:providerName}        |
      | displayName                   | ${CTX:providerDisplayName} |
      | version                       | ${CTX:providerVersion}     |
      | template                      | openai |
      | spec.context                  | ${CTX:providerContext}     |
      | spec.upstream.url             | http://testbench:3008/scripted |
      | accessControl.mode            | deny_all                   |
      | spec.accessControl.exceptions | [{"path":"/scripted/priced/*","methods":["POST"]},{"path":"/scripted/other/*","methods":["POST"]}] |
      | spec.policies                 | [{"name":"llm-cost","version":"v1","paths":[{"path":"/scripted/priced/*","methods":["POST"]}]}] |
    Then the response status code should be 201

    When I send a "POST" request to "${CTX:providerContext}/scripted/priced/chat/completions" until status 200 with body:
      """
      {"model":"gpt-4o-mini","messages":[{"role":"user","content":"Hello"}],"x_testbench_reply":{"body":{"id":"chatcmpl-lc","object":"chat.completion","model":"gpt-4o-mini","choices":[{"index":0,"message":{"role":"assistant","content":"Hi there"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1000,"completion_tokens":500,"total_tokens":1500}}}}
      """
    Then the response header "X-Testbench-Scripted" should be "true"
    And the latest analytics event for path "${CTX:providerContext}/scripted/priced/chat/completions" should have numeric metadata field "aiMetadata.llmCost" equal to "0.003"

    When I send a "POST" request to "${CTX:providerContext}/scripted/other/chat/completions" until status 200 with body:
      """
      {"model":"gpt-4o-mini","messages":[{"role":"user","content":"Hello"}],"x_testbench_reply":{"body":{"id":"chatcmpl-lc","object":"chat.completion","model":"gpt-4o-mini","choices":[{"index":0,"message":{"role":"assistant","content":"Hi there"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1000,"completion_tokens":500,"total_tokens":1500}}}}
      """
    Then the response header "X-Testbench-Scripted" should be "true"
    And the response header "x-llm-cost" should not exist
    # The gateway reports the provider's own AI metadata (model and vendor) and token usage for any call, so
    # the event is still there. Only llm-cost adds a cost, so its absence shows nothing priced this call.
    And the latest analytics event for path "${CTX:providerContext}/scripted/other/chat/completions" should have metadata field "aiMetadata.vendorName" with value "openai"
    And the latest analytics event for path "${CTX:providerContext}/scripted/other/chat/completions" should not have metadata field "aiMetadata.llmCost"

    When I delete the LLM provider "${CTX:providerName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:providerContext}/scripted/priced/chat/completions" until status 404

  # The template names where usage and model sit, so a provider whose JSON is shaped differently is
  # priced with no change to the policy. Here usage lives under stats and the model under meta.
  # my-org-llm: 1000 x 0.000002 + 500 x 0.000008 = 0.006
  Scenario: Price a call from a custom LlmProviderTemplate with its own token and model locations
    Given I generate a unique resource name from "lc-custom-template" and store it as "templateName"
    And I generate a unique value from "lc-custom-template" and store it as "templateDisplayName"
    And I generate a unique resource name from "lc-custom-template" and store it as "providerName"
    And I generate a unique value from "lc-custom-template" and store it as "providerDisplayName"
    And I generate a unique API version from "lc-custom-template" and store it as "providerVersion"
    And I generate a unique API context from "/lc-custom-template" and store it as "providerContext"
    When I create LLM provider template from "resources/templates/llm-provider-template.yaml" with values:
      | apiVersion            | ${CTX:gatewaySpecVersion}                                    |
      | name                  | ${CTX:templateName}                                          |
      | displayName           | ${CTX:templateDisplayName}                                   |
      | spec.promptTokens     | {"location":"payload","identifier":"$.stats.tokens_in"}      |
      | spec.completionTokens | {"location":"payload","identifier":"$.stats.tokens_out"}     |
      | spec.responseModel    | {"location":"payload","identifier":"$.meta.engine"}          |
    Then the response status code should be 201

    When I create LLM provider from "resources/templates/llm-provider.yaml" with values:
      | apiVersion         | ${CTX:gatewaySpecVersion}  |
      | name               | ${CTX:providerName}        |
      | displayName        | ${CTX:providerDisplayName} |
      | version            | ${CTX:providerVersion}     |
      | template           | ${CTX:templateName}        |
      | spec.context       | ${CTX:providerContext}     |
      | spec.upstream.url  | http://testbench:3008      |
      | accessControl.mode | allow_all                  |
      | spec.policies      | [{"name":"llm-cost","version":"v1","paths":[{"path":"/*","methods":["*"]}]}] |
    Then the response status code should be 201

    When I send a "POST" request to "${CTX:providerContext}/scripted/custom" until status 200 with body:
      """
      {"x_testbench_reply":{"body":{"stats":{"tokens_in":1000,"tokens_out":500},"meta":{"engine":"my-org-llm"},"text":"Hi there"}}}
      """
    Then the response body should be:
      """
      {"stats":{"tokens_in":1000,"tokens_out":500},"meta":{"engine":"my-org-llm"},"text":"Hi there"}
      """
    And the response header "x-llm-cost" should not exist
    And the latest analytics event for path "${CTX:providerContext}/scripted/custom" should have numeric metadata field "aiMetadata.llmCost" equal to "0.006"

    When I delete the LLM provider "${CTX:providerName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:providerContext}/scripted/custom" until status 404
    When I delete the LLM provider template "${CTX:templateName}"
    Then the response should be successful

  # Response-phase policies run in reverse order, so the policy listed last runs first on the way
  # back. With llm-cost first, the rate limiter looks for a cost before llm-cost has published one and
  # never consumes the budget. Each call costs 0.003, so a 0.0001 budget would be spent by the first
  # call if the order were right, and the second would be refused.
  Scenario: List llm-cost before llm-cost-based-ratelimit so the budget is never consumed
    Given I generate a unique resource name from "lc-wrong-order" and store it as "providerName"
    And I generate a unique value from "lc-wrong-order" and store it as "providerDisplayName"
    And I generate a unique API version from "lc-wrong-order" and store it as "providerVersion"
    And I generate a unique API context from "/lc-wrong-order" and store it as "providerContext"
    When I create LLM provider from "resources/templates/llm-provider.yaml" with values:
      | apiVersion         | ${CTX:gatewaySpecVersion}  |
      | name               | ${CTX:providerName}        |
      | displayName        | ${CTX:providerDisplayName} |
      | version            | ${CTX:providerVersion}     |
      | template           | openai |
      | spec.context       | ${CTX:providerContext}     |
      | spec.upstream.url  | http://testbench:3008      |
      | accessControl.mode | allow_all                  |
      | spec.policies      | [{"name":"llm-cost","version":"v1","paths":[{"path":"/*","methods":["*"]}]},{"name":"llm-cost-based-ratelimit","version":"v1","paths":[{"path":"/*","methods":["*"],"params":{"budgetLimits":[{"amount":0.0001,"duration":"1h"}]}}]}] |
    Then the response status code should be 201

    # An unpriced reply costs nothing in either order, so it is safe to poll until the route is live.
    When I send a "POST" request to "${CTX:providerContext}/scripted/ready" until status 200 with body:
      """
      {"x_testbench_reply":{"body":{}}}
      """

    When I send a "POST" request to "${CTX:providerContext}/scripted/order/1" with body:
      """
      {"model":"gpt-4o-mini","messages":[{"role":"user","content":"Hello"}],"x_testbench_reply":{"body":{"id":"chatcmpl-lc","object":"chat.completion","model":"gpt-4o-mini","choices":[{"index":0,"message":{"role":"assistant","content":"Hi there"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1000,"completion_tokens":500,"total_tokens":1500}}}}
      """
    Then the response status code should be 200
    And the latest analytics event for path "${CTX:providerContext}/scripted/order/1" should have numeric metadata field "aiMetadata.llmCost" equal to "0.003"

    When I send a "POST" request to "${CTX:providerContext}/scripted/order/2" with body:
      """
      {"model":"gpt-4o-mini","messages":[{"role":"user","content":"Hello"}],"x_testbench_reply":{"body":{"id":"chatcmpl-lc","object":"chat.completion","model":"gpt-4o-mini","choices":[{"index":0,"message":{"role":"assistant","content":"Hi there"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1000,"completion_tokens":500,"total_tokens":1500}}}}
      """
    Then the response status code should be 200

    When I send a "POST" request to "${CTX:providerContext}/scripted/order/3" with body:
      """
      {"model":"gpt-4o-mini","messages":[{"role":"user","content":"Hello"}],"x_testbench_reply":{"body":{"id":"chatcmpl-lc","object":"chat.completion","model":"gpt-4o-mini","choices":[{"index":0,"message":{"role":"assistant","content":"Hi there"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1000,"completion_tokens":500,"total_tokens":1500}}}}
      """
    Then the response status code should be 200

    When I delete the LLM provider "${CTX:providerName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:providerContext}/scripted/ready" until status 404
