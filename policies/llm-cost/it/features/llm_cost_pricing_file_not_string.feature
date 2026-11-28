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
Feature: LLM cost with a bad pricing file (not-string)
  As an API developer
  I want an LLM route to fail closed when the policy has no usable pricing table
  So that a misconfigured gateway never forwards traffic it cannot price, and never tells a caller why

  # The gateway here sets the policy's pricing file to a number.

  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"

  Scenario: Set the pricing_file system parameter to a non-string value
    Given I generate a unique resource name from "lc-pf-not-string" and store it as "providerName"
    And I generate a unique value from "lc-pf-not-string" and store it as "providerDisplayName"
    And I generate a unique API version from "lc-pf-not-string" and store it as "providerVersion"
    And I generate a unique API context from "/lc-pf-not-string" and store it as "providerContext"
    When I create LLM provider from "resources/templates/llm-provider.yaml" with values:
      | apiVersion         | ${CTX:gatewaySpecVersion}  |
      | name               | ${CTX:providerName}        |
      | displayName        | ${CTX:providerDisplayName} |
      | version            | ${CTX:providerVersion}     |
      | template           | openai |
      | spec.context       | ${CTX:providerContext}     |
      | spec.upstream.url  | http://testbench:3008      |
      | accessControl.mode | allow_all                  |
      | spec.policies      | [{"name":"llm-cost","version":"v1","paths":[{"path":"/*","methods":["*"]}]}] |
    Then the response status code should be 201


    # The gateway accepts the provider: only the policy engine reads the pricing file, when it
    # builds the route's policy chain.
    When I send a "POST" request to "${CTX:providerContext}/scripted/openai/v1/chat/completions" until status 500 with body:
      """
      {"model":"gpt-4o-mini","messages":[{"role":"user","content":"Hello"}],"x_testbench_reply":{"body":{"id":"chatcmpl-lc","object":"chat.completion","model":"gpt-4o-mini","choices":[{"index":0,"message":{"role":"assistant","content":"Hi there"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1000,"completion_tokens":500,"total_tokens":1500}}}}
      """
    Then the response body should be:
      """
      {"error":"Internal Server Error"}
      """
    And the response header "X-Testbench-Scripted" should not exist
    And the "gateway-runtime" service logs should contain "pricing_file"

    When I delete the LLM provider "${CTX:providerName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:providerContext}/scripted/openai/v1/chat/completions" until status 404
