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
Feature: LLM cost-based rate limiting
  As an API developer
  I want to rate limit LLM APIs based on monetary budgets
  So that I can control costs by setting spending limits

  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"

  @known-issue
  Scenario: Enforce cost-based rate limit on LLM API
    # gpt-4.1-2025-04-14: 19 prompt x $2/1M + 10 completion x $8/1M = $0.000118 per request
    # Budget $0.000236 = exactly 2 requests worth
    Given I generate a unique resource name from "cblr-enforce-template" and store it as "templateName"
    And I generate a unique value from "cblr-enforce-template" and store it as "templateDisplayName"
    And I generate a unique resource name from "cblr-enforce-provider" and store it as "providerName"
    And I generate a unique value from "cblr-enforce-provider" and store it as "providerDisplayName"
    And I generate a unique API version from "cblr-enforce" and store it as "providerVersion"
    And I generate a unique API context from "/cblr-enforce" and store it as "providerContext"
    When I create LLM provider template from "resources/templates/llm-provider-template.yaml" with values:
      | apiVersion  | ${CTX:gatewaySpecVersion} |
      | name        | ${CTX:templateName}              |
      | displayName | ${CTX:templateDisplayName}       |
      | spec.promptTokens     | {"location":"payload","identifier":"$.usage.prompt_tokens"} |
      | spec.completionTokens | {"location":"payload","identifier":"$.usage.completion_tokens"} |
      | spec.responseModel    | {"location":"payload","identifier":"$.model"} |
    Then the response status code should be 201

    When I create LLM provider from "resources/templates/llm-provider.yaml" with values:
      | apiVersion         | ${CTX:gatewaySpecVersion} |
      | name               | ${CTX:providerName}               |
      | displayName        | ${CTX:providerDisplayName}        |
      | version            | ${CTX:providerVersion}            |
      | template           | ${CTX:templateName}               |
      | spec.context       | ${CTX:providerContext}            |
      | spec.upstream.url  | http://testbench:3008             |
      | accessControl.mode | allow_all                          |
      | spec.policies      | [{"name":"llm-cost-based-ratelimit","version":"v1","paths":[{"path":"/*","methods":["*"],"params":{"budgetLimits":[{"amount":0.000236,"duration":"1h"}]}}]},{"name":"llm-cost","version":"v1","paths":[{"path":"/*","methods":["*"]}]}] |
    Then the response status code should be 201

    # An unrecognized model returns cost=0 and is never billed (see "Zero cost requests do not
    # consume budget"), so it doubles as a free readiness canary: retry until the route and its
    # policy chain are live without touching the budget the real requests below rely on.
    And I send a "POST" request to "${CTX:providerContext}/unknown-llm/v1/chat" until status 200 with body:
      """
      {"model":"my-unknown-model-xyz","messages":[{"role":"user","content":"Hello"}]}
      """

    When I send a "POST" request to "${CTX:providerContext}/openai/v1/chat/completions" with body:
      """
      {"model":"gpt-4.1-2025-04-14","messages":[{"role":"user","content":"Hello"}]}
      """
    Then the response status code should be 200
    And the response header "x-ratelimit-cost-limit-dollars" should exist
    And the response header "x-ratelimit-cost-remaining-dollars" should exist

    When I send a "POST" request to "${CTX:providerContext}/openai/v1/chat/completions" with body:
      """
      {"model":"gpt-4.1-2025-04-14","messages":[{"role":"user","content":"Hello"}]}
      """
    Then the response status code should be 200

    # Wait for the prior charge without consuming more budget, then make exactly one
    # billable request for the exhaustion assertion.
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

  @known-issue @llm-cost-multi-window
  Scenario: Cost-based rate limit with multiple budget time windows
    # Budget: $0.000236/1m (minute) AND $0.001180/1h (hourly - 10x per-request cost)
    # 2 requests exhaust the minute window even though the hourly budget still has room
    Given I generate a unique resource name from "cblr-multiwin-template" and store it as "templateName"
    And I generate a unique value from "cblr-multiwin-template" and store it as "templateDisplayName"
    And I generate a unique resource name from "cblr-multiwin-provider" and store it as "providerName"
    And I generate a unique value from "cblr-multiwin-provider" and store it as "providerDisplayName"
    And I generate a unique API version from "cblr-multiwin" and store it as "providerVersion"
    And I generate a unique API context from "/cblr-multiwin" and store it as "providerContext"
    When I create LLM provider template from "resources/templates/llm-provider-template.yaml" with values:
      | apiVersion  | ${CTX:gatewaySpecVersion} |
      | name        | ${CTX:templateName}              |
      | displayName | ${CTX:templateDisplayName}       |
      | spec.promptTokens     | {"location":"payload","identifier":"$.usage.prompt_tokens"} |
      | spec.completionTokens | {"location":"payload","identifier":"$.usage.completion_tokens"} |
      | spec.responseModel    | {"location":"payload","identifier":"$.model"} |
    Then the response status code should be 201

    When I create LLM provider from "resources/templates/llm-provider.yaml" with values:
      | apiVersion         | ${CTX:gatewaySpecVersion} |
      | name               | ${CTX:providerName}               |
      | displayName        | ${CTX:providerDisplayName}        |
      | version            | ${CTX:providerVersion}            |
      | template           | ${CTX:templateName}               |
      | spec.context       | ${CTX:providerContext}            |
      | spec.upstream.url  | http://testbench:3008             |
      | accessControl.mode | allow_all                          |
      | spec.policies      | [{"name":"llm-cost-based-ratelimit","version":"v1","paths":[{"path":"/*","methods":["*"],"params":{"budgetLimits":[{"amount":0.000236,"duration":"1m"},{"amount":0.001180,"duration":"1h"}]}}]},{"name":"llm-cost","version":"v1","paths":[{"path":"/*","methods":["*"]}]}] |
    Then the response status code should be 201

    # The dedicated readiness response reports zero usage, so this retries route
    # and policy readiness without consuming either budget window.
    And I send a "POST" request to "${CTX:providerContext}/__readiness" until header "x-ratelimit-cost-limit-dollars" is "0.000236" with body:
      """
      {"model":"gpt-4.1-2025-04-14","messages":[{"role":"user","content":"readiness"}]}
      """

    When I send a "POST" request to "${CTX:providerContext}/openai/v1/chat/completions" with body:
      """
      {"model":"gpt-4.1-2025-04-14","messages":[{"role":"user","content":"Hello"}]}
      """
    Then the response status code should be 200
    And the response header "x-ratelimit-cost-limit-dollars" should exist
    And the response header "x-ratelimit-cost-remaining-dollars" should exist

    When I send a "POST" request to "${CTX:providerContext}/openai/v1/chat/completions" with body:
      """
      {"model":"gpt-4.1-2025-04-14","messages":[{"role":"user","content":"Hello"}]}
      """
    Then the response status code should be 200
    And the response header "x-ratelimit-cost-remaining-dollars" should be "0.000000"

    # The tighter per-minute window blocks this request even though the hourly budget still
    # has $0.000944 remaining
    When I send a "POST" request to "${CTX:providerContext}/openai/v1/chat/completions" with body:
      """
      {"model":"gpt-4.1-2025-04-14","messages":[{"role":"user","content":"Hello"}]}
      """
    Then the response status code should be 429

    When I delete the LLM provider "${CTX:providerName}"
    Then the response should be successful

  @known-issue
  Scenario: Cost accumulates correctly across real LLM responses
    # The Anthropic reply reports input_tokens and output_tokens, which the template maps.
    # claude-3-5-haiku-20241022: 50 input x $0.80/1M + 25 output x $4.00/1M = $0.000140 per request
    # Budget $0.000280 = exactly 2 requests worth
    Given I generate a unique resource name from "cblr-anthropic-template" and store it as "templateName"
    And I generate a unique value from "cblr-anthropic-template" and store it as "templateDisplayName"
    And I generate a unique resource name from "cblr-anthropic-provider" and store it as "providerName"
    And I generate a unique value from "cblr-anthropic-provider" and store it as "providerDisplayName"
    And I generate a unique API version from "cblr-anthropic" and store it as "providerVersion"
    And I generate a unique API context from "/cblr-anthropic" and store it as "providerContext"
    When I create LLM provider template from "resources/templates/llm-provider-template.yaml" with values:
      | apiVersion  | ${CTX:gatewaySpecVersion} |
      | name        | ${CTX:templateName}              |
      | displayName | ${CTX:templateDisplayName}       |
      | spec.promptTokens     | {"location":"payload","identifier":"$.usage.input_tokens"} |
      | spec.completionTokens | {"location":"payload","identifier":"$.usage.output_tokens"} |
      | spec.responseModel    | {"location":"payload","identifier":"$.model"} |
    Then the response status code should be 201

    When I create LLM provider from "resources/templates/llm-provider.yaml" with values:
      | apiVersion         | ${CTX:gatewaySpecVersion} |
      | name               | ${CTX:providerName}               |
      | displayName        | ${CTX:providerDisplayName}        |
      | version            | ${CTX:providerVersion}            |
      | template           | ${CTX:templateName}               |
      | spec.context       | ${CTX:providerContext}            |
      | spec.upstream.url  | http://testbench:3008             |
      | accessControl.mode | allow_all                          |
      | spec.policies      | [{"name":"llm-cost-based-ratelimit","version":"v1","paths":[{"path":"/*","methods":["*"],"params":{"budgetLimits":[{"amount":0.000280,"duration":"1h"}]}}]},{"name":"llm-cost","version":"v1","paths":[{"path":"/*","methods":["*"]}]}] |
    Then the response status code should be 201

    # An unrecognized model returns cost=0 and is never billed (see "Zero cost requests do not
    # consume budget"), so it doubles as a free readiness canary: retry until the route and its
    # policy chain are live without touching the budget the real requests below rely on.
    And I send a "POST" request to "${CTX:providerContext}/unknown-llm/v1/chat" until status 200 with body:
      """
      {"model":"my-unknown-model-xyz","messages":[{"role":"user","content":"Hello"}]}
      """

    When I send a "POST" request to "${CTX:providerContext}/anthropic/v1/messages" with body:
      """
      {"model":"claude-3-5-haiku-20241022","messages":[{"role":"user","content":"Hello"}],"max_tokens":100}
      """
    Then the response status code should be 200

    When I send a "POST" request to "${CTX:providerContext}/anthropic/v1/messages" with body:
      """
      {"model":"claude-3-5-haiku-20241022","messages":[{"role":"user","content":"Hello"}],"max_tokens":100}
      """
    Then the response status code should be 200

    # Wait for the prior charge without consuming more budget, then make exactly one
    # billable request for the exhaustion assertion.
    And I send a "POST" request to "${CTX:providerContext}/__readiness" until header "x-ratelimit-cost-remaining-dollars" is "0.000000" with body:
      """
      {"model":"claude-3-5-haiku-20241022","messages":[{"role":"user","content":"readiness"}],"max_tokens":100}
      """

    When I send a "POST" request to "${CTX:providerContext}/anthropic/v1/messages" with body:
      """
      {"model":"claude-3-5-haiku-20241022","messages":[{"role":"user","content":"Hello"}],"max_tokens":100}
      """
    Then the response status code should be 429

    When I delete the LLM provider "${CTX:providerName}"
    Then the response should be successful

  Scenario: Cost-based rate limit returns proper rate limit headers
    # The readiness path reports zero usage, so its response shows the budget untouched without spending
    # any of it. With no costScaleFactor configured the default of 1,000,000,000 applies: a $0.50 budget
    # is 500,000,000 in the raw headers and 0.500000 in the dollar headers.
    Given I generate a unique resource name from "cblr-headers-template" and store it as "templateName"
    And I generate a unique value from "cblr-headers-template" and store it as "templateDisplayName"
    And I generate a unique resource name from "cblr-headers-provider" and store it as "providerName"
    And I generate a unique value from "cblr-headers-provider" and store it as "providerDisplayName"
    And I generate a unique API version from "cblr-headers" and store it as "providerVersion"
    And I generate a unique API context from "/cblr-headers" and store it as "providerContext"
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
    And the response header "x-ratelimit-limit" should be "500000000"
    And the response header "x-ratelimit-remaining" should be "500000000"
    And the response header "RateLimit-Policy" should contain "llm_cost_quota"
    And the response header "RateLimit" should contain "llm_cost_quota"

    And I send a "POST" request to "${CTX:providerContext}/openai/v1/chat/completions" until status 200 with body:
      """
      {"model":"gpt-4.1-2025-04-14","messages":[{"role":"user","content":"Hello"}]}
      """
    Then the response header "x-ratelimit-cost-limit-dollars" should be "0.500000"
    And the response header "x-ratelimit-cost-remaining-dollars" should exist

    When I delete the LLM provider "${CTX:providerName}"
    Then the response should be successful

  @known-issue
  Scenario: Per-provider cost rate limiting is isolated
    # Two separate providers each budgeted for exactly 2 requests. Exhausting provider A's
    # budget must not affect provider B's budget.
    Given I generate a unique resource name from "cblr-prov-a-template" and store it as "templateNameA"
    And I generate a unique value from "cblr-prov-a-template" and store it as "templateDisplayNameA"
    And I generate a unique resource name from "cblr-prov-a-provider" and store it as "providerNameA"
    And I generate a unique value from "cblr-prov-a-provider" and store it as "providerDisplayNameA"
    And I generate a unique API version from "cblr-prov-a" and store it as "providerVersionA"
    And I generate a unique API context from "/cblr-prov-a" and store it as "providerContextA"
    And I generate a unique resource name from "cblr-prov-b-template" and store it as "templateNameB"
    And I generate a unique value from "cblr-prov-b-template" and store it as "templateDisplayNameB"
    And I generate a unique resource name from "cblr-prov-b-provider" and store it as "providerNameB"
    And I generate a unique value from "cblr-prov-b-provider" and store it as "providerDisplayNameB"
    And I generate a unique API version from "cblr-prov-b" and store it as "providerVersionB"
    And I generate a unique API context from "/cblr-prov-b" and store it as "providerContextB"
    When I create LLM provider template from "resources/templates/llm-provider-template.yaml" with values:
      | apiVersion  | ${CTX:gatewaySpecVersion} |
      | name        | ${CTX:templateNameA}             |
      | displayName | ${CTX:templateDisplayNameA}      |
      | spec.promptTokens     | {"location":"payload","identifier":"$.usage.prompt_tokens"} |
      | spec.completionTokens | {"location":"payload","identifier":"$.usage.completion_tokens"} |
      | spec.responseModel    | {"location":"payload","identifier":"$.model"} |
    Then the response status code should be 201

    When I create LLM provider template from "resources/templates/llm-provider-template.yaml" with values:
      | apiVersion  | ${CTX:gatewaySpecVersion} |
      | name        | ${CTX:templateNameB}             |
      | displayName | ${CTX:templateDisplayNameB}      |
      | spec.promptTokens     | {"location":"payload","identifier":"$.usage.prompt_tokens"} |
      | spec.completionTokens | {"location":"payload","identifier":"$.usage.completion_tokens"} |
      | spec.responseModel    | {"location":"payload","identifier":"$.model"} |
    Then the response status code should be 201

    When I create LLM provider from "resources/templates/llm-provider.yaml" with values:
      | apiVersion         | ${CTX:gatewaySpecVersion} |
      | name               | ${CTX:providerNameA}              |
      | displayName        | ${CTX:providerDisplayNameA}       |
      | version            | ${CTX:providerVersionA}           |
      | template           | ${CTX:templateNameA}              |
      | spec.context       | ${CTX:providerContextA}           |
      | spec.upstream.url  | http://testbench:3008             |
      | accessControl.mode | allow_all                          |
      | spec.policies      | [{"name":"llm-cost-based-ratelimit","version":"v1","paths":[{"path":"/*","methods":["*"],"params":{"budgetLimits":[{"amount":0.000236,"duration":"1h"}]}}]},{"name":"llm-cost","version":"v1","paths":[{"path":"/*","methods":["*"]}]}] |
    Then the response status code should be 201

    When I create LLM provider from "resources/templates/llm-provider.yaml" with values:
      | apiVersion         | ${CTX:gatewaySpecVersion} |
      | name               | ${CTX:providerNameB}              |
      | displayName        | ${CTX:providerDisplayNameB}       |
      | version            | ${CTX:providerVersionB}           |
      | template           | ${CTX:templateNameB}              |
      | spec.context       | ${CTX:providerContextB}           |
      | spec.upstream.url  | http://testbench:3008             |
      | accessControl.mode | allow_all                          |
      | spec.policies      | [{"name":"llm-cost-based-ratelimit","version":"v1","paths":[{"path":"/*","methods":["*"],"params":{"budgetLimits":[{"amount":0.000236,"duration":"1h"}]}}]},{"name":"llm-cost","version":"v1","paths":[{"path":"/*","methods":["*"]}]}] |
    Then the response status code should be 201

    And I send a "POST" request to "${CTX:providerContextA}/openai/v1/chat/completions" until status 200 with body:
      """
      {"model":"gpt-4.1-2025-04-14","messages":[{"role":"user","content":"Hello"}]}
      """
    And I send a "POST" request to "${CTX:providerContextB}/openai/v1/chat/completions" until status 200 with body:
      """
      {"model":"gpt-4.1-2025-04-14","messages":[{"role":"user","content":"Hello"}]}
      """

    When I send a "POST" request to "${CTX:providerContextA}/openai/v1/chat/completions" with body:
      """
      {"model":"gpt-4.1-2025-04-14","messages":[{"role":"user","content":"Hello"}]}
      """
    Then the response status code should be 200

    # Wait for the prior charge without consuming more budget, then make exactly one
    # billable request for the exhaustion assertion.
    And I send a "POST" request to "${CTX:providerContextA}/__readiness" until header "x-ratelimit-cost-remaining-dollars" is "0.000000" with body:
      """
      {"model":"gpt-4.1-2025-04-14","messages":[{"role":"user","content":"readiness"}]}
      """

    When I send a "POST" request to "${CTX:providerContextA}/openai/v1/chat/completions" with body:
      """
      {"model":"gpt-4.1-2025-04-14","messages":[{"role":"user","content":"Hello"}]}
      """
    Then the response status code should be 429

    When I send a "POST" request to "${CTX:providerContextB}/openai/v1/chat/completions" with body:
      """
      {"model":"gpt-4.1-2025-04-14","messages":[{"role":"user","content":"Hello"}]}
      """
    Then the response status code should be 200

    When I delete the LLM provider "${CTX:providerNameA}"
    Then the response should be successful

    When I delete the LLM provider "${CTX:providerNameB}"
    Then the response should be successful

  @known-issue
  Scenario: Zero cost requests do not consume budget
    # An unrecognized model returns cost=0 (not_calculated) and must not consume budget, leaving
    # it intact for the known-model requests that follow.
    Given I generate a unique resource name from "cblr-zero-template" and store it as "templateName"
    And I generate a unique value from "cblr-zero-template" and store it as "templateDisplayName"
    And I generate a unique resource name from "cblr-zero-provider" and store it as "providerName"
    And I generate a unique value from "cblr-zero-provider" and store it as "providerDisplayName"
    And I generate a unique API version from "cblr-zero" and store it as "providerVersion"
    And I generate a unique API context from "/cblr-zero" and store it as "providerContext"
    When I create LLM provider template from "resources/templates/llm-provider-template.yaml" with values:
      | apiVersion  | ${CTX:gatewaySpecVersion} |
      | name        | ${CTX:templateName}              |
      | displayName | ${CTX:templateDisplayName}       |
      | spec.promptTokens     | {"location":"payload","identifier":"$.usage.prompt_tokens"} |
      | spec.completionTokens | {"location":"payload","identifier":"$.usage.completion_tokens"} |
      | spec.responseModel    | {"location":"payload","identifier":"$.model"} |
    Then the response status code should be 201

    When I create LLM provider from "resources/templates/llm-provider.yaml" with values:
      | apiVersion         | ${CTX:gatewaySpecVersion} |
      | name               | ${CTX:providerName}               |
      | displayName        | ${CTX:providerDisplayName}        |
      | version            | ${CTX:providerVersion}            |
      | template           | ${CTX:templateName}               |
      | spec.context       | ${CTX:providerContext}            |
      | spec.upstream.url  | http://testbench:3008             |
      | accessControl.mode | allow_all                          |
      | spec.policies      | [{"name":"llm-cost-based-ratelimit","version":"v1","paths":[{"path":"/*","methods":["*"],"params":{"budgetLimits":[{"amount":0.000236,"duration":"1h"}]}}]},{"name":"llm-cost","version":"v1","paths":[{"path":"/*","methods":["*"]}]}] |
    Then the response status code should be 201

    And I send a "POST" request to "${CTX:providerContext}/unknown-llm/v1/chat" until status 200 with body:
      """
      {"model":"my-unknown-model-xyz","messages":[{"role":"user","content":"Hello"}]}
      """

    When I send a "POST" request to "${CTX:providerContext}/unknown-llm/v1/chat" with body:
      """
      {"model":"my-unknown-model-xyz","messages":[{"role":"user","content":"Hello"}]}
      """
    Then the response status code should be 200

    # Known model - the full budget is still available since the unknown-model requests above
    # never consumed any of it
    When I send a "POST" request to "${CTX:providerContext}/openai/v1/chat/completions" with body:
      """
      {"model":"gpt-4.1-2025-04-14","messages":[{"role":"user","content":"Hello"}]}
      """
    Then the response status code should be 200

    When I send a "POST" request to "${CTX:providerContext}/openai/v1/chat/completions" with body:
      """
      {"model":"gpt-4.1-2025-04-14","messages":[{"role":"user","content":"Hello"}]}
      """
    Then the response status code should be 200

    # Wait for the prior charge without consuming more budget, then make exactly one
    # billable request for the exhaustion assertion.
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

  @known-issue @llm-cost-window-reset
  Scenario: Rate limit window resets after time window expires
    Given I generate a unique resource name from "cblr-reset-template" and store it as "templateName"
    And I generate a unique value from "cblr-reset-template" and store it as "templateDisplayName"
    And I generate a unique resource name from "cblr-reset-provider" and store it as "providerName"
    And I generate a unique value from "cblr-reset-provider" and store it as "providerDisplayName"
    And I generate a unique API version from "cblr-reset" and store it as "providerVersion"
    And I generate a unique API context from "/cblr-reset" and store it as "providerContext"
    When I create LLM provider template from "resources/templates/llm-provider-template.yaml" with values:
      | apiVersion  | ${CTX:gatewaySpecVersion} |
      | name        | ${CTX:templateName}              |
      | displayName | ${CTX:templateDisplayName}       |
      | spec.promptTokens     | {"location":"payload","identifier":"$.usage.prompt_tokens"} |
      | spec.completionTokens | {"location":"payload","identifier":"$.usage.completion_tokens"} |
      | spec.responseModel    | {"location":"payload","identifier":"$.model"} |
    Then the response status code should be 201

    When I create LLM provider from "resources/templates/llm-provider.yaml" with values:
      | apiVersion         | ${CTX:gatewaySpecVersion} |
      | name               | ${CTX:providerName}               |
      | displayName        | ${CTX:providerDisplayName}        |
      | version            | ${CTX:providerVersion}            |
      | template           | ${CTX:templateName}               |
      | spec.context       | ${CTX:providerContext}            |
      | spec.upstream.url  | http://testbench:3008             |
      | accessControl.mode | allow_all                          |
      | spec.policies      | [{"name":"llm-cost-based-ratelimit","version":"v1","paths":[{"path":"/*","methods":["*"],"params":{"budgetLimits":[{"amount":0.000236,"duration":"10s"}]}}]},{"name":"llm-cost","version":"v1","paths":[{"path":"/*","methods":["*"]}]}] |
    Then the response status code should be 201

    # The dedicated readiness response reports zero usage, so this retries route
    # and policy readiness without consuming the short budget window.
    And I send a "POST" request to "${CTX:providerContext}/__readiness" until header "x-ratelimit-cost-limit-dollars" is "0.000236" with body:
      """
      {"model":"gpt-4.1-2025-04-14","messages":[{"role":"user","content":"readiness"}]}
      """

    When I send a "POST" request to "${CTX:providerContext}/openai/v1/chat/completions" with body:
      """
      {"model":"gpt-4.1-2025-04-14","messages":[{"role":"user","content":"Hello"}]}
      """
    Then the response status code should be 200

    When I send a "POST" request to "${CTX:providerContext}/openai/v1/chat/completions" with body:
      """
      {"model":"gpt-4.1-2025-04-14","messages":[{"role":"user","content":"Hello"}]}
      """
    Then the response status code should be 200
    And the response header "x-ratelimit-cost-remaining-dollars" should be "0.000000"

    When I send a "POST" request to "${CTX:providerContext}/openai/v1/chat/completions" with body:
      """
      {"model":"gpt-4.1-2025-04-14","messages":[{"role":"user","content":"Hello"}]}
      """
    Then the response status code should be 429

    # Instead of a blind sleep past the 10s window, retry the same real request until the
    # window has actually reset and it is accepted - this can never over-wait and never
    # under-wait relative to the policy engine's own clock.
    When I send a "POST" request to "${CTX:providerContext}/openai/v1/chat/completions" until status 200 with body:
      """
      {"model":"gpt-4.1-2025-04-14","messages":[{"role":"user","content":"Hello"}]}
      """

    When I delete the LLM provider "${CTX:providerName}"
    Then the response should be successful

  Scenario Outline: Budget amounts of any magnitude scale to the same unit (<amount>)
    # Integer, fractional, the schema minimum and the schema maximum all scale by the default
    # factor, so the raw headers and the dollar headers agree for each.
    Given I generate a unique resource name from "cblr-amount-template" and store it as "templateName"
    And I generate a unique value from "cblr-amount-template" and store it as "templateDisplayName"
    And I generate a unique resource name from "cblr-amount-provider" and store it as "providerName"
    And I generate a unique value from "cblr-amount-provider" and store it as "providerDisplayName"
    And I generate a unique API version from "cblr-amount" and store it as "providerVersion"
    And I generate a unique API context from "/cblr-amount" and store it as "providerContext"
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
      | spec.policies      | [{"name":"llm-cost-based-ratelimit","version":"v1","paths":[{"path":"/*","methods":["*"],"params":{"budgetLimits":[{"amount":<amount>,"duration":"1h"}]}}]},{"name":"llm-cost","version":"v1","paths":[{"path":"/*","methods":["*"]}]}] |
    Then the response status code should be 201

    And I send a "POST" request to "${CTX:providerContext}/__readiness" until header "x-ratelimit-cost-limit-dollars" is "<dollars>" with body:
      """
      {"model":"gpt-4.1-2025-04-14","messages":[{"role":"user","content":"readiness"}]}
      """
    Then the response header "x-ratelimit-cost-remaining-dollars" should be "<dollars>"
    And the response header "x-ratelimit-limit" should be "<raw>"

    When I delete the LLM provider "${CTX:providerName}"
    Then the response should be successful

    Examples:
      | amount   | raw              | dollars      |
      | 1        | 1000000000       | 1.000000     |
      | 2.5      | 2500000000       | 2.500000     |
      | 0.000001 | 1000             | 0.000001     |
      | 1000000  | 1000000000000000 | 1000000.000000 |

  Scenario: Hourly, daily and monthly budgets are enforced together
    # Three windows of different granularity become three limits of one quota. The headers report the
    # tightest one, the hourly $1.00, even though the daily and monthly budgets are larger.
    Given I generate a unique resource name from "cblr-three-windows-template" and store it as "templateName"
    And I generate a unique value from "cblr-three-windows-template" and store it as "templateDisplayName"
    And I generate a unique resource name from "cblr-three-windows-provider" and store it as "providerName"
    And I generate a unique value from "cblr-three-windows-provider" and store it as "providerDisplayName"
    And I generate a unique API version from "cblr-three-windows" and store it as "providerVersion"
    And I generate a unique API context from "/cblr-three-windows" and store it as "providerContext"
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
      | spec.policies      | [{"name":"llm-cost-based-ratelimit","version":"v1","paths":[{"path":"/*","methods":["*"],"params":{"budgetLimits":[{"amount":1,"duration":"1h"},{"amount":5,"duration":"24h"},{"amount":20,"duration":"720h"}]}}]},{"name":"llm-cost","version":"v1","paths":[{"path":"/*","methods":["*"]}]}] |
    Then the response status code should be 201

    And I send a "POST" request to "${CTX:providerContext}/__readiness" until header "x-ratelimit-cost-limit-dollars" is "1.000000" with body:
      """
      {"model":"gpt-4.1-2025-04-14","messages":[{"role":"user","content":"readiness"}]}
      """
    Then the response header "x-ratelimit-cost-remaining-dollars" should be "1.000000"
    And the response header "x-ratelimit-limit" should be "1000000000"

    When I delete the LLM provider "${CTX:providerName}"
    Then the response should be successful

  Scenario: A composite Go duration is accepted as a budget window
    # The duration is handed to the rate-limit engine as written, and 1h30m is a valid Go duration.
    Given I generate a unique resource name from "cblr-composite-template" and store it as "templateName"
    And I generate a unique value from "cblr-composite-template" and store it as "templateDisplayName"
    And I generate a unique resource name from "cblr-composite-provider" and store it as "providerName"
    And I generate a unique value from "cblr-composite-provider" and store it as "providerDisplayName"
    And I generate a unique API version from "cblr-composite" and store it as "providerVersion"
    And I generate a unique API context from "/cblr-composite" and store it as "providerContext"
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
      | spec.policies      | [{"name":"llm-cost-based-ratelimit","version":"v1","paths":[{"path":"/*","methods":["*"],"params":{"budgetLimits":[{"amount":1,"duration":"1h30m"}]}}]},{"name":"llm-cost","version":"v1","paths":[{"path":"/*","methods":["*"]}]}] |
    Then the response status code should be 201

    And I send a "POST" request to "${CTX:providerContext}/__readiness" until header "x-ratelimit-cost-limit-dollars" is "1.000000" with body:
      """
      {"model":"gpt-4.1-2025-04-14","messages":[{"role":"user","content":"readiness"}]}
      """

    When I delete the LLM provider "${CTX:providerName}"
    Then the response should be successful

  Scenario: A route that is not an LLM provider is not rate limited
    # A REST API route has no provider_name, so the policy skips every phase and the request goes
    # through with no cost-based rate limit and none of its headers. The provider scenarios above, which
    # send the same policy on an LLM provider and read its headers, are the positive control.
    Given I generate a unique value from "cblr-no-provider" and store it as "apiName"
    And I generate a unique API version from "cblr-no-provider" and store it as "apiVersion"
    And I generate a unique API context from "/cblr-no-provider" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3008 |
      | spec.operations        | [{"method":"POST","path":"/openai/v1/chat/completions","policies":[{"name":"llm-cost-based-ratelimit","version":"v1","params":{"budgetLimits":[{"amount":0.000001,"duration":"1h"}]}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/openai/v1/chat/completions" until status 200 with body:
      """
      {"model":"gpt-4.1-2025-04-14","messages":[{"role":"user","content":"Hello"}]}
      """
    Then the response body should contain "chat.completion"
    And the response header "x-ratelimit-cost-limit-dollars" should not exist
    And the response header "x-ratelimit-cost-remaining-dollars" should not exist
    And the response header "x-ratelimit-limit" should not exist

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/openai/v1/chat/completions" with body:
      """
      {"model":"gpt-4.1-2025-04-14","messages":[{"role":"user","content":"Hello"}]}
      """
    Then the response status code should be 200
    And the response header "x-ratelimit-cost-limit-dollars" should not exist

    When I delete the API "${CTX:apiName}"
    Then the response should be successful

  Scenario: Concurrent requests on one provider all succeed and leave an unspent budget untouched
    # The readiness path reports zero usage, so a burst of them must neither be rejected nor consume any
    # of the $1000 budget, however the requests interleave on the provider's single limiter.
    Given I generate a unique resource name from "cblr-concurrent-template" and store it as "templateName"
    And I generate a unique value from "cblr-concurrent-template" and store it as "templateDisplayName"
    And I generate a unique resource name from "cblr-concurrent-provider" and store it as "providerName"
    And I generate a unique value from "cblr-concurrent-provider" and store it as "providerDisplayName"
    And I generate a unique API version from "cblr-concurrent" and store it as "providerVersion"
    And I generate a unique API context from "/cblr-concurrent" and store it as "providerContext"
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
      | spec.policies      | [{"name":"llm-cost-based-ratelimit","version":"v1","paths":[{"path":"/*","methods":["*"],"params":{"budgetLimits":[{"amount":1000,"duration":"1h"}]}}]},{"name":"llm-cost","version":"v1","paths":[{"path":"/*","methods":["*"]}]}] |
    Then the response status code should be 201

    And I send a "POST" request to "${CTX:providerContext}/__readiness" until header "x-ratelimit-cost-limit-dollars" is "1000.000000" with body:
      """
      {"model":"gpt-4.1-2025-04-14","messages":[{"role":"user","content":"readiness"}]}
      """
    When I send 20 concurrent "POST" requests to "${CTX:providerContext}/__readiness" with per-request body:
      """
      {"model":"gpt-4.1-2025-04-14","messages":[{"role":"user","content":"readiness {i}"}]}
      """

    And I send a "POST" request to "${CTX:providerContext}/__readiness" until header "x-ratelimit-cost-remaining-dollars" is "1000.000000" with body:
      """
      {"model":"gpt-4.1-2025-04-14","messages":[{"role":"user","content":"readiness"}]}
      """
    Then the response header "x-ratelimit-cost-limit-dollars" should be "1000.000000"

    When I delete the LLM provider "${CTX:providerName}"
    Then the response should be successful

  @known-issue
  Scenario: A caller cannot dodge the budget by naming another provider
    # The provider name is recorded by the gateway for the route, never read from the request. Every
    # request below claims a different provider, yet all of them draw on the one budget, which holds
    # exactly two requests.
    Given I generate a unique resource name from "cblr-spoof-template" and store it as "templateName"
    And I generate a unique value from "cblr-spoof-template" and store it as "templateDisplayName"
    And I generate a unique resource name from "cblr-spoof-provider" and store it as "providerName"
    And I generate a unique value from "cblr-spoof-provider" and store it as "providerDisplayName"
    And I generate a unique API version from "cblr-spoof" and store it as "providerVersion"
    And I generate a unique API context from "/cblr-spoof" and store it as "providerContext"
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
    When I set header "provider_name" to "spoofed-one"
    And I set header "x-llm-provider" to "spoofed-one"
    And I send a "POST" request to "${CTX:providerContext}/openai/v1/chat/completions" with body:
      """
      {"model":"gpt-4.1-2025-04-14","messages":[{"role":"user","content":"Hello"}]}
      """
    Then the response status code should be 200
    When I set header "provider_name" to "spoofed-two"
    And I set header "x-llm-provider" to "spoofed-two"
    And I send a "POST" request to "${CTX:providerContext}/openai/v1/chat/completions" with body:
      """
      {"model":"gpt-4.1-2025-04-14","messages":[{"role":"user","content":"Hello"}]}
      """
    Then the response status code should be 200

    # Wait for the prior charges without spending more, then make one billable request.
    When I set header "provider_name" to "spoofed-three"
    And I set header "x-llm-provider" to "spoofed-three"
    And I send a "POST" request to "${CTX:providerContext}/__readiness" until header "x-ratelimit-cost-remaining-dollars" is "0.000000" with body:
      """
      {"model":"gpt-4.1-2025-04-14","messages":[{"role":"user","content":"readiness"}]}
      """
    When I send a "POST" request to "${CTX:providerContext}/openai/v1/chat/completions" with body:
      """
      {"model":"gpt-4.1-2025-04-14","messages":[{"role":"user","content":"Hello"}]}
      """
    Then the response status code should be 429

    When I clear all headers
    And I authenticate using basic auth as "admin"
    When I delete the LLM provider "${CTX:providerName}"
    Then the response should be successful

  @known-issue
  Scenario: Changing the budget replaces the limiter and discards the spend recorded against the old one
    # Spend lives inside the limiter instance. A new budget builds a new limiter, so a provider that was
    # exhausted accepts requests again, with a full balance under the new limit.
    Given I generate a unique resource name from "cblr-update-template" and store it as "templateName"
    And I generate a unique value from "cblr-update-template" and store it as "templateDisplayName"
    And I generate a unique resource name from "cblr-update-provider" and store it as "providerName"
    And I generate a unique value from "cblr-update-provider" and store it as "providerDisplayName"
    And I generate a unique API version from "cblr-update" and store it as "providerVersion"
    And I generate a unique API context from "/cblr-update" and store it as "providerContext"
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

    When I update LLM provider "${CTX:providerName}" from "resources/templates/llm-provider.yaml" with values:
      | apiVersion         | ${CTX:gatewaySpecVersion} |
      | name               | ${CTX:providerName} |
      | displayName        | ${CTX:providerDisplayName} |
      | version            | ${CTX:providerVersion} |
      | template           | ${CTX:templateName} |
      | spec.context       | ${CTX:providerContext} |
      | spec.upstream.url  | http://testbench:3008 |
      | accessControl.mode | allow_all |
      | spec.policies      | [{"name":"llm-cost-based-ratelimit","version":"v1","paths":[{"path":"/*","methods":["*"],"params":{"budgetLimits":[{"amount":0.001,"duration":"1h"}]}}]},{"name":"llm-cost","version":"v1","paths":[{"path":"/*","methods":["*"]}]}] |
    Then the response should be successful
    And I send a "POST" request to "${CTX:providerContext}/__readiness" until header "x-ratelimit-cost-limit-dollars" is "0.001000" with body:
      """
      {"model":"gpt-4.1-2025-04-14","messages":[{"role":"user","content":"readiness"}]}
      """
    Then the response header "x-ratelimit-cost-remaining-dollars" should be "0.001000"
    When I send a "POST" request to "${CTX:providerContext}/openai/v1/chat/completions" with body:
      """
      {"model":"gpt-4.1-2025-04-14","messages":[{"role":"user","content":"Hello"}]}
      """
    Then the response status code should be 200

    When I delete the LLM provider "${CTX:providerName}"
    Then the response should be successful
