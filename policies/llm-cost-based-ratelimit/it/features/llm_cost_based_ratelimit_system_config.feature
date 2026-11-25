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
Feature: LLM cost-based rate limit system configuration
  As a gateway operator
  I want the cost scale factor I configure to apply to every budget
  So that budgets stay exact at a different precision

  # The gateway of this feature sets costScaleFactor to 9,000,000,000,000 (overlays/system-config.toml),
  # which keeps the largest budget the policy accepts, $1,000,000, inside the int64 range of the
  # limiter: 1,000,000 x 9,000,000,000,000 = 9,000,000,000,000,000,000.

  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"

  Scenario: The configured cost scale factor scales the budget and the dollar headers stay in dollars
    # A $0.50 budget is 4,500,000,000,000 raw units at the configured factor, and the dollar headers
    # still read 0.500000.
    Given I generate a unique resource name from "cblr-scale-template" and store it as "templateName"
    And I generate a unique value from "cblr-scale-template" and store it as "templateDisplayName"
    And I generate a unique resource name from "cblr-scale-provider" and store it as "providerName"
    And I generate a unique value from "cblr-scale-provider" and store it as "providerDisplayName"
    And I generate a unique API version from "cblr-scale" and store it as "providerVersion"
    And I generate a unique API context from "/cblr-scale" and store it as "providerContext"
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
      | spec.policies      | [{"name":"llm-cost-based-ratelimit","version":"v1","paths":[{"path":"/*","methods":["*"],"params":{"budgetLimits":[{"amount":0.5,"duration":"1h"}]}}]},{"name":"llm-cost","version":"v1","paths":[{"path":"/*","methods":["*"]}]}] |
    Then the response status code should be 201

    And I send a "POST" request to "${CTX:providerContext}/__readiness" until header "x-ratelimit-cost-limit-dollars" is "0.500000" with body:
      """
      {"model":"gpt-4.1-2025-04-14","messages":[{"role":"user","content":"readiness"}]}
      """
    Then the response header "x-ratelimit-cost-remaining-dollars" should be "0.500000"
    And the response header "x-ratelimit-limit" should be "4500000000000"
    And the response header "x-ratelimit-remaining" should be "4500000000000"

    When I delete the LLM provider "${CTX:providerName}"
    Then the response should be successful

  @known-issue
  Scenario: The configured cost scale factor also scales the charged cost
    # gpt-4.1-2025-04-14 costs $0.000118 for this request and the $0.000236 budget holds exactly two. The
    # limit and the charge use the same factor, so the third request is rejected.
    Given I generate a unique resource name from "cblr-scale-charge-template" and store it as "templateName"
    And I generate a unique value from "cblr-scale-charge-template" and store it as "templateDisplayName"
    And I generate a unique resource name from "cblr-scale-charge-provider" and store it as "providerName"
    And I generate a unique value from "cblr-scale-charge-provider" and store it as "providerDisplayName"
    And I generate a unique API version from "cblr-scale-charge" and store it as "providerVersion"
    And I generate a unique API context from "/cblr-scale-charge" and store it as "providerContext"
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
      | spec.policies      | [{"name":"llm-cost-based-ratelimit","version":"v1","paths":[{"path":"/*","methods":["*"],"params":{"budgetLimits":[{"amount":0.000236,"duration":"1h"}]}}]},{"name":"llm-cost","version":"v1","paths":[{"path":"/*","methods":["*"]}]}] |
    Then the response status code should be 201

    And I send a "POST" request to "${CTX:providerContext}/__readiness" until header "x-ratelimit-cost-limit-dollars" is "0.000236" with body:
      """
      {"model":"gpt-4.1-2025-04-14","messages":[{"role":"user","content":"readiness"}]}
      """
    And I send a "POST" request to "${CTX:providerContext}/openai/v1/chat/completions" with body:
      """
      {"model":"gpt-4.1-2025-04-14","messages":[{"role":"user","content":"Hello"}]}
      """
    Then the response status code should be 200
    And I send a "POST" request to "${CTX:providerContext}/openai/v1/chat/completions" with body:
      """
      {"model":"gpt-4.1-2025-04-14","messages":[{"role":"user","content":"Hello"}]}
      """
    Then the response status code should be 200
    And I send a "POST" request to "${CTX:providerContext}/__readiness" until header "x-ratelimit-cost-remaining-dollars" is "0.000000" with body:
      """
      {"model":"gpt-4.1-2025-04-14","messages":[{"role":"user","content":"readiness"}]}
      """
    When I send a "POST" request to "${CTX:providerContext}/openai/v1/chat/completions" with body:
      """
      {"model":"gpt-4.1-2025-04-14","messages":[{"role":"user","content":"Hello"}]}
      """
    Then the response status code should be 429

    When I delete the LLM provider "${CTX:providerName}"
    Then the response should be successful

  Scenario: The largest budget stays exact under a large cost scale factor
    # The schema allows $1,000,000 and puts no upper bound on the factor. At this factor the scaled
    # limit, 9,000,000,000,000,000,000, is just inside int64, so the budget enforced is the one
    # configured. A limit that overflowed would saturate and enforce a far smaller cap.
    Given I generate a unique resource name from "cblr-scale-max-template" and store it as "templateName"
    And I generate a unique value from "cblr-scale-max-template" and store it as "templateDisplayName"
    And I generate a unique resource name from "cblr-scale-max-provider" and store it as "providerName"
    And I generate a unique value from "cblr-scale-max-provider" and store it as "providerDisplayName"
    And I generate a unique API version from "cblr-scale-max" and store it as "providerVersion"
    And I generate a unique API context from "/cblr-scale-max" and store it as "providerContext"
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
      | spec.policies      | [{"name":"llm-cost-based-ratelimit","version":"v1","paths":[{"path":"/*","methods":["*"],"params":{"budgetLimits":[{"amount":1000000,"duration":"1h"}]}}]},{"name":"llm-cost","version":"v1","paths":[{"path":"/*","methods":["*"]}]}] |
    Then the response status code should be 201

    And I send a "POST" request to "${CTX:providerContext}/__readiness" until header "x-ratelimit-cost-limit-dollars" is "1000000.000000" with body:
      """
      {"model":"gpt-4.1-2025-04-14","messages":[{"role":"user","content":"readiness"}]}
      """
    Then the response header "x-ratelimit-cost-remaining-dollars" should be "1000000.000000"
    And the response header "x-ratelimit-limit" should be "9000000000000000000"
    And the response header "x-ratelimit-remaining" should be "9000000000000000000"

    When I delete the LLM provider "${CTX:providerName}"
    Then the response should be successful
