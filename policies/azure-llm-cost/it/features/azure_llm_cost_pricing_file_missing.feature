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

@azure-llm-cost
Feature: Azure LLM Cost policy with a missing pricing file
  As an API developer
  I want an Azure OpenAI route to fail closed when the policy has no usable pricing table
  So that a misconfigured gateway never forwards traffic it cannot price, and never tells a caller why

  # The gateway here points the policy's pricing file at a path that does not exist.

  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"

  Scenario: Point pricing_file at a file that does not exist, or at a file containing malformed JSON (missing file)
    Given I generate a unique resource name from "alc-missing" and store it as "providerName"
    And I generate a unique value from "alc-missing" and store it as "providerDisplayName"
    And I generate a unique API version from "alc-missing" and store it as "providerVersion"
    And I generate a unique API context from "/alc-missing" and store it as "providerContext"
    When I create LLM provider from "resources/templates/llm-provider.yaml" with values:
      | apiVersion         | ${CTX:gatewaySpecVersion}  |
      | name               | ${CTX:providerName}        |
      | displayName        | ${CTX:providerDisplayName} |
      | version            | ${CTX:providerVersion}     |
      | template           | azure-openai               |
      | spec.context       | ${CTX:providerContext}     |
      | spec.upstream.url  | http://testbench:3008      |
      | accessControl.mode | allow_all                  |
      | spec.policies      | [{"name":"azure-llm-cost","version":"v1","paths":[{"path":"/*","methods":["*"],"params":{"modelMappings":[{"deployment":"chat-mini","model":"gpt-4o-mini"}]}}]}] |
    # The gateway accepts the provider: only the policy engine reads the pricing file, when it
    # builds the route's policy chain.
    Then the response status code should be 201

    When I send a "POST" request to "${CTX:providerContext}/scripted/openai/v1/chat/completions" until status 500 with body:
      """
      {"model":"chat-mini","messages":[{"role":"user","content":"Hello"}],"x_testbench_reply":{"body":{"model":"gpt-4o-mini","usage":{"prompt_tokens":1000,"completion_tokens":500,"total_tokens":1500}}}}
      """
    Then the response body should be:
      """
      {"error":"Internal Server Error"}
      """
    And the response header "X-Testbench-Scripted" should not exist
    # The gateway log carries the cause the policy wraps; the caller never sees it.
    And the "gateway-runtime" service logs should contain "failed to load pricing file"
    And the "gateway-runtime" service logs should contain "no such file or directory"

    When I delete the LLM provider "${CTX:providerName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:providerContext}/scripted/openai/v1/chat/completions" until status 404
