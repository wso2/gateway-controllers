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
Feature: LLM cost-based rate limit budget validation
  As an API developer
  I want the gateway to reject an LLM provider whose budget is misconfigured
  So that a mistake in the budget limits is reported when the provider is created

  # Configurations rejected when the provider is created, from the policy's parameter schema.
  # Gateways 1.1.0 and 1.2.0 do not validate them, so these run on later releases only; the same
  # configurations on those releases are covered by the unvalidated-params feature.

  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"

  Scenario Outline: Reject a budgetLimits parameter the schema does not allow (<case>)
    Given I generate a unique resource name from "cblr-v-<slug>-provider" and store it as "providerName"
    And I generate a unique value from "cblr-v-<slug>-provider" and store it as "providerDisplayName"
    And I generate a unique API version from "cblr-v-<slug>" and store it as "providerVersion"
    And I generate a unique API context from "/cblr-v-<slug>" and store it as "providerContext"

    When I create LLM provider from "resources/templates/llm-provider.yaml" with values:
      | apiVersion         | ${CTX:gatewaySpecVersion} |
      | name               | ${CTX:providerName} |
      | displayName        | ${CTX:providerDisplayName} |
      | version            | ${CTX:providerVersion} |
      | template           | openai |
      | spec.context       | ${CTX:providerContext} |
      | spec.upstream.url  | http://testbench:3008 |
      | accessControl.mode | allow_all |
      | spec.policies      | [{"name":"llm-cost-based-ratelimit","version":"v1","paths":[{"path":"/*","methods":["*"],"params":<params>}]},{"name":"llm-cost","version":"v1","paths":[{"path":"/*","methods":["*"]}]}] |
    Then the response status code should be 400
    And the response body should contain "<field>"

    Examples:
      | case | slug | params | field |
      | absent | absent | {} | params: budgetLimits is required |
      | not an array | not-array | {"budgetLimits":{"amount":1,"duration":"1h"}} | params.budgetLimits |
      | empty array | empty | {"budgetLimits":[]} | params.budgetLimits |
      | eleven entries | eleven | {"budgetLimits":[{"amount":1,"duration":"1h"},{"amount":1,"duration":"1h"},{"amount":1,"duration":"1h"},{"amount":1,"duration":"1h"},{"amount":1,"duration":"1h"},{"amount":1,"duration":"1h"},{"amount":1,"duration":"1h"},{"amount":1,"duration":"1h"},{"amount":1,"duration":"1h"},{"amount":1,"duration":"1h"},{"amount":1,"duration":"1h"}]} | params.budgetLimits |
      | non-object entry | not-object | {"budgetLimits":[{"amount":1,"duration":"1h"},"one-dollar"]} | params.budgetLimits.1 |
      | missing amount | no-amount | {"budgetLimits":[{"duration":"1h"}]} | params.budgetLimits.0: amount is required |
      | missing duration | no-duration | {"budgetLimits":[{"amount":1}]} | params.budgetLimits.0: duration is required |
      | non-numeric amount | amount-text | {"budgetLimits":[{"amount":"abc","duration":"1h"}]} | params.budgetLimits.0.amount |
      | amount below the minimum | amount-min | {"budgetLimits":[{"amount":0.0000001,"duration":"1h"}]} | params.budgetLimits.0.amount |
      | amount above the maximum | amount-max | {"budgetLimits":[{"amount":1000001,"duration":"1h"}]} | params.budgetLimits.0.amount |
      | duration with a space | duration-text | {"budgetLimits":[{"amount":1,"duration":"1 hour"}]} | params.budgetLimits.0.duration |
      | duration in days | duration-days | {"budgetLimits":[{"amount":1,"duration":"1d"}]} | params.budgetLimits.0.duration |
      | duration without a unit | duration-bare | {"budgetLimits":[{"amount":1,"duration":"60"}]} | params.budgetLimits.0.duration |

  Scenario: A quoted number is coerced to the budget amount
    # The control plane coerces a numeric string to a number before the policy is created, so a budget
    # written as "1" behaves as 1. This is also the positive control for the rejections above: the
    # same shape with a valid amount is accepted and enforced.
    Given I generate a unique resource name from "cblr-v-quoted-provider" and store it as "providerName"
    And I generate a unique value from "cblr-v-quoted-provider" and store it as "providerDisplayName"
    And I generate a unique API version from "cblr-v-quoted" and store it as "providerVersion"
    And I generate a unique API context from "/cblr-v-quoted" and store it as "providerContext"

    When I create LLM provider from "resources/templates/llm-provider.yaml" with values:
      | apiVersion         | ${CTX:gatewaySpecVersion} |
      | name               | ${CTX:providerName} |
      | displayName        | ${CTX:providerDisplayName} |
      | version            | ${CTX:providerVersion} |
      | template           | openai |
      | spec.context       | ${CTX:providerContext} |
      | spec.upstream.url  | http://testbench:3008 |
      | accessControl.mode | allow_all |
      | spec.policies      | [{"name":"llm-cost-based-ratelimit","version":"v1","paths":[{"path":"/*","methods":["*"],"params":{"budgetLimits":[{"amount":"1","duration":"1h"}]}}]},{"name":"llm-cost","version":"v1","paths":[{"path":"/*","methods":["*"]}]}] |
    Then the response status code should be 201

    And I send a "POST" request to "${CTX:providerContext}/__readiness" until header "x-ratelimit-cost-limit-dollars" is "1.000000" with body:
      """
      {"model":"gpt-4.1-2025-04-14","messages":[{"role":"user","content":"readiness"}]}
      """
    And the response header "x-ratelimit-limit" should be "1000000000"

    When I delete the LLM provider "${CTX:providerName}"
    Then the response should be successful
