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

@llm-cost-based-ratelimit
Feature: LLM cost-based rate limit with budgets the gateway does not validate
  As an API developer
  I want a provider with an unusable budget to keep serving requests
  So that a misconfigured budget degrades to no rate limiting instead of breaking the route

  # Gateways 1.1.0 and 1.2.0 do not validate an LLM provider's policy parameters, so they accept
  # these budgets and the policy meets them at request time. Later gateways reject them when the
  # provider is created (see the validation feature).

  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"

  Scenario Outline: A budget the policy cannot use applies no rate limit (<case>)
    # The policy builds no limiter, so the route serves every request and carries none of the
    # cost headers.
    Given I generate a unique resource name from "cblr-u-<slug>-template" and store it as "templateName"
    And I generate a unique value from "cblr-u-<slug>-template" and store it as "templateDisplayName"
    And I generate a unique resource name from "cblr-u-<slug>-provider" and store it as "providerName"
    And I generate a unique value from "cblr-u-<slug>-provider" and store it as "providerDisplayName"
    And I generate a unique API version from "cblr-u-<slug>" and store it as "providerVersion"
    And I generate a unique API context from "/cblr-u-<slug>" and store it as "providerContext"
    When I create LLM provider template from "resources/templates/llm-provider-template.yaml" with values:
      | apiVersion            | ${CTX:gatewaySpecVersion} |
      | name                  | ${CTX:templateName} |
      | displayName           | ${CTX:templateDisplayName} |
      | spec.promptTokens     | {"location":"payload","identifier":"$.usage.prompt_tokens"} |
      | spec.completionTokens | {"location":"payload","identifier":"$.usage.completion_tokens"} |
      | spec.responseModel    | {"location":"payload","identifier":"$.model"} |
    Then the response status code should be 201

    When I create LLM provider from "resources/templates/llm-provider.yaml" with values:
      | apiVersion         | ${CTX:gatewaySpecVersion} |
      | name               | ${CTX:providerName} |
      | displayName        | ${CTX:providerDisplayName} |
      | version            | ${CTX:providerVersion} |
      | template           | ${CTX:templateName} |
      | spec.context       | ${CTX:providerContext} |
      | spec.upstream.url  | http://testbench:3008 |
      | accessControl.mode | allow_all |
      | spec.policies      | [{"name":"llm-cost-based-ratelimit","version":"v1","paths":[{"path":"/*","methods":["*"],"params":<params>}]},{"name":"llm-cost","version":"v1","paths":[{"path":"/*","methods":["*"]}]}] |
    Then the response status code should be 201

    And I send a "POST" request to "${CTX:providerContext}/openai/v1/chat/completions" until status 200 with body:
      """
      {"model":"gpt-4.1-2025-04-14","messages":[{"role":"user","content":"Hello"}]}
      """
    Then the response header "x-ratelimit-cost-limit-dollars" should not exist
    And the response header "x-ratelimit-limit" should not exist

    When I send a "POST" request to "${CTX:providerContext}/openai/v1/chat/completions" with body:
      """
      {"model":"gpt-4.1-2025-04-14","messages":[{"role":"user","content":"Hello"}]}
      """
    Then the response status code should be 200
    And the response header "x-ratelimit-cost-limit-dollars" should not exist

    When I delete the LLM provider "${CTX:providerName}"
    Then the response should be successful

    Examples:
      | case | slug | params |
      | absent | absent | {} |
      | not an array | not-array | {"budgetLimits":{"amount":1,"duration":"1h"}} |
      | non-object entries | not-object | {"budgetLimits":["one-dollar",7]} |
      | amount that is not a number | amount-text | {"budgetLimits":[{"amount":"abc","duration":"1h"}]} |

  Scenario: A usable budget on the same gateway is applied
    # The positive control for the scenarios above: the same provider shape with a valid budget does
    # carry the cost headers.
    Given I generate a unique resource name from "cblr-u-valid-template" and store it as "templateName"
    And I generate a unique value from "cblr-u-valid-template" and store it as "templateDisplayName"
    And I generate a unique resource name from "cblr-u-valid-provider" and store it as "providerName"
    And I generate a unique value from "cblr-u-valid-provider" and store it as "providerDisplayName"
    And I generate a unique API version from "cblr-u-valid" and store it as "providerVersion"
    And I generate a unique API context from "/cblr-u-valid" and store it as "providerContext"
    When I create LLM provider template from "resources/templates/llm-provider-template.yaml" with values:
      | apiVersion            | ${CTX:gatewaySpecVersion} |
      | name                  | ${CTX:templateName} |
      | displayName           | ${CTX:templateDisplayName} |
      | spec.promptTokens     | {"location":"payload","identifier":"$.usage.prompt_tokens"} |
      | spec.completionTokens | {"location":"payload","identifier":"$.usage.completion_tokens"} |
      | spec.responseModel    | {"location":"payload","identifier":"$.model"} |
    Then the response status code should be 201

    When I create LLM provider from "resources/templates/llm-provider.yaml" with values:
      | apiVersion         | ${CTX:gatewaySpecVersion} |
      | name               | ${CTX:providerName} |
      | displayName        | ${CTX:providerDisplayName} |
      | version            | ${CTX:providerVersion} |
      | template           | ${CTX:templateName} |
      | spec.context       | ${CTX:providerContext} |
      | spec.upstream.url  | http://testbench:3008 |
      | accessControl.mode | allow_all |
      | spec.policies      | [{"name":"llm-cost-based-ratelimit","version":"v1","paths":[{"path":"/*","methods":["*"],"params":{"budgetLimits":[{"amount":1,"duration":"1h"}]}}]},{"name":"llm-cost","version":"v1","paths":[{"path":"/*","methods":["*"]}]}] |
    Then the response status code should be 201

    And I send a "POST" request to "${CTX:providerContext}/__readiness" until header "x-ratelimit-cost-limit-dollars" is "1.000000" with body:
      """
      {"model":"gpt-4.1-2025-04-14","messages":[{"role":"user","content":"readiness"}]}
      """

    When I delete the LLM provider "${CTX:providerName}"
    Then the response should be successful
