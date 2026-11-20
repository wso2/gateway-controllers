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
Feature: LLM cost on upstream error responses
  As an API developer
  I want an upstream error to reach the client untouched and cost nothing
  So that a failing provider never spends a cost budget

  # The provider's upstream is the testbench fault-injection service, which answers each scripted
  # status in turn and then forwards to the scripted-reply mock on port 3008. gpt-4o-mini costs 0.003
  # for 1000 prompt and 500 completion tokens, against a budget of 0.0001: a single charged call
  # would leave no budget for the next one.

  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"

  Scenario: The provider answers 429 and 500 and then recovers, with llm-cost ahead of llm-cost-based-ratelimit
    Given I generate a unique resource name from "lc-upstream-error" and store it as "providerName"
    And I generate a unique value from "lc-upstream-error" and store it as "providerDisplayName"
    And I generate a unique API version from "lc-upstream-error" and store it as "providerVersion"
    And I generate a unique API context from "/lc-upstream-error" and store it as "providerContext"
    And I resolve the "fault-injection" service URL at "/${CTX:providerName}" and store it as "faultUpstream"
    # The service answers 404 until a script exists, so store an empty one: it forwards every call.
    When I send a "PUT" request to the "fault-injection" service at "/test/scripts/${CTX:providerName}" with body:
      """
      {"forwardPort":3008,"steps":[]}
      """
    Then the response status code should be 200

    When I create LLM provider from "resources/templates/llm-provider.yaml" with values:
      | apiVersion         | ${CTX:gatewaySpecVersion}  |
      | name               | ${CTX:providerName}        |
      | displayName        | ${CTX:providerDisplayName} |
      | version            | ${CTX:providerVersion}     |
      | template           | openai |
      | spec.context       | ${CTX:providerContext}     |
      | spec.upstream.url  | ${CTX:faultUpstream}       |
      | accessControl.mode | allow_all                  |
      | spec.policies      | [{"name":"llm-cost-based-ratelimit","version":"v1","paths":[{"path":"/*","methods":["*"],"params":{"budgetLimits":[{"amount":0.0001,"duration":"1h"}]}}]},{"name":"llm-cost","version":"v1","paths":[{"path":"/*","methods":["*"]}]}] |
    Then the response status code should be 201

    # An unpriced reply costs nothing, so it is safe to poll until the route is live.
    When I send a "POST" request to "${CTX:providerContext}/scripted/ready" until status 200 with body:
      """
      {"x_testbench_reply":{"body":{}}}
      """

    # Storing the script again replaces the first and resets its call count.
    When I send a "PUT" request to the "fault-injection" service at "/test/scripts/${CTX:providerName}" with body:
      """
      {"forwardPort":3008,"steps":[{"status":429},{"status":500}]}
      """
    Then the response status code should be 200

    When I send a "POST" request to "${CTX:providerContext}/scripted/err/1" with body:
      """
      {"model":"gpt-4o-mini","messages":[{"role":"user","content":"Hello"}]}
      """
    Then the response status code should be 429
    And the response body should contain "scripted status 429"
    And the response header "x-llm-cost" should not exist
    And the latest analytics event for path "${CTX:providerContext}/scripted/err/1" should have response status 429

    When I send a "POST" request to "${CTX:providerContext}/scripted/err/2" with body:
      """
      {"model":"gpt-4o-mini","messages":[{"role":"user","content":"Hello"}]}
      """
    Then the response status code should be 500
    And the response body should contain "scripted status 500"
    And the response header "x-llm-cost" should not exist
    And the latest analytics event for path "${CTX:providerContext}/scripted/err/2" should have response status 500

    # The script is spent, so this call reaches the scripted mock. It is priced and allowed, which
    # shows the two errors did not use the budget.
    When I send a "POST" request to "${CTX:providerContext}/scripted/err/3" with body:
      """
      {"model":"gpt-4o-mini","messages":[{"role":"user","content":"Hello"}],"x_testbench_reply":{"body":{"id":"chatcmpl-lc","object":"chat.completion","model":"gpt-4o-mini","choices":[{"index":0,"message":{"role":"assistant","content":"Hi there"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1000,"completion_tokens":500,"total_tokens":1500}}}}
      """
    Then the response status code should be 200
    And the response header "X-Testbench-Scripted" should be "true"
    And the latest analytics event for path "${CTX:providerContext}/scripted/err/3" should have numeric metadata field "aiMetadata.llmCost" equal to "0.003"

    When I send a "GET" request to the "fault-injection" service at "/test/scripts/${CTX:providerName}"
    Then the response status code should be 200
    And the JSON response field "received" should be 3

    When I delete the LLM provider "${CTX:providerName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:providerContext}/scripted/ready" until status 404
