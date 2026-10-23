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

@cost-based-model-routing
Feature: Cost based model routing policy
  As an API developer
  I want the cost-based-model-routing policy to behave as documented
  So that a change to it is caught before it reaches a release

  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"

  # The response must match the expected error response recorded from the policy before a
  # change (resources/expected-error-responses), so a change a client could observe fails.
  Scenario: cost-based-model-routing rejects a request for a model that has no budget
    Given I generate a unique resource name from "compat-cbr-unlisted-provider" and store it as "providerName"
    And I generate a unique value from "compat-cbr-unlisted-provider" and store it as "providerDisplayName"
    And I generate a unique API version from "compat-cbr-unlisted-provider" and store it as "providerVersion"
    And I generate a unique API context from "/compat-cbr-unlisted-provider" and store it as "providerContext"
    And I generate a unique resource name from "compat-cbr-unlisted-proxy" and store it as "proxyName"
    And I generate a unique value from "compat-cbr-unlisted-proxy" and store it as "proxyDisplayName"
    And I generate a unique API version from "compat-cbr-unlisted-proxy" and store it as "proxyVersion"
    And I generate a unique API context from "/compat-cbr-unlisted-proxy" and store it as "proxyContext"
    When I create LLM provider from "resources/templates/llm-provider.yaml" with values:
      | apiVersion         | ${CTX:gatewaySpecVersion} |
      | name               | ${CTX:providerName} |
      | displayName        | ${CTX:providerDisplayName} |
      | version            | ${CTX:providerVersion} |
      | template           | openai |
      | spec.context       | ${CTX:providerContext} |
      | spec.upstream.url  | http://testbench:3008/openai/v1 |
      | accessControl.mode | allow_all |
    Then the response status code should be 201
    When I create LLM proxy from "resources/templates/llm-proxy.yaml" with values:
      | apiVersion    | ${CTX:gatewaySpecVersion} |
      | name          | ${CTX:proxyName} |
      | displayName   | ${CTX:proxyDisplayName} |
      | version       | ${CTX:proxyVersion} |
      | context       | ${CTX:proxyContext} |
      | provider.id   | ${CTX:providerName} |
      | spec.policies | [{"name":"cost-based-model-routing","version":"v0","paths":[{"path":"/chat/completions","methods":["POST"],"params":{"modelBudgets":[{"model":{"modelName":"gpt-4o"},"budgetLimits":[{"amount":100,"duration":"1h"}]}],"onExhausted":"reject"}}]}] |
    Then the response status code should be 201
    And I send a "POST" request to "${CTX:proxyContext}/chat/completions" until status 200 with body:
      """
      {"model":"gpt-4o","messages":[{"role":"user","content":"Hello"}]}
      """

    When I send a "POST" request to "${CTX:proxyContext}/chat/completions" with body:
      """
      {"model":"gpt-unlisted","messages":[{"role":"user","content":"Hello"}]}
      """
    Then the response status code should be 429
    And the response should match the expected error response "cost-based-model-routing-no-budget-for-model"
