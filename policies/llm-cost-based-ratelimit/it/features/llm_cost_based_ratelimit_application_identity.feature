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
Feature: LLM cost-based rate limit and the application identity
  As an API developer
  I want a budget shared by every caller or kept per application
  So that one application cannot spend another's budget, and a shared budget is spent by all

  # The key manager of overlays/application-identity.toml reads the application from the client_id
  # claim of the JWT, which jwt-auth records as x-wso2-application-id. alice and bob belong to the
  # alpha application, carol to beta. gpt-4.1-2025-04-14 costs $0.000118 a request, so a budget of
  # $0.000236 holds two.

  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"

  Scenario: With consumerBased the spend of one application leaves another application's budget untouched
    # alice spends one request of the alpha budget, which leaves alpha with half of it. carol belongs
    # to beta and still has all of hers. Nothing is exhausted, so no request is rejected.
    Given I generate a unique resource name from "cblr-consumer-template" and store it as "templateName"
    And I generate a unique value from "cblr-consumer-template" and store it as "templateDisplayName"
    And I generate a unique resource name from "cblr-consumer-provider" and store it as "providerName"
    And I generate a unique value from "cblr-consumer-provider" and store it as "providerDisplayName"
    And I generate a unique API version from "cblr-consumer" and store it as "providerVersion"
    And I generate a unique API context from "/cblr-consumer" and store it as "providerContext"
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
      | spec.policies      | [{"name":"jwt-auth","version":"v1","paths":[{"path":"/*","methods":["*"],"params":{"issuers":["mock-jwks-appid"]}}]},{"name":"llm-cost-based-ratelimit","version":"v1","paths":[{"path":"/*","methods":["*"],"params":{"budgetLimits":[{"amount":0.000236,"duration":"1h"}],"consumerBased":true}}]},{"name":"llm-cost","version":"v1","paths":[{"path":"/*","methods":["*"]}]}] |
    Then the response status code should be 201
    And I generate a unique value from "cblr-consumer-alpha" and store it as "alphaClient"
    And I generate a unique value from "cblr-consumer-beta" and store it as "betaClient"

    When I clear all headers
    And I set header "Content-Type" to "application/json"
    And I get a JWT token from the mock JWKS server with issuer "http://testbench:3001/token" and claims "sub=alice,client_id=${CTX:alphaClient}" and store it as "aliceToken"
    And I get a JWT token from the mock JWKS server with issuer "http://testbench:3001/token" and claims "sub=bob,client_id=${CTX:alphaClient}" and store it as "bobToken"
    And I get a JWT token from the mock JWKS server with issuer "http://testbench:3001/token" and claims "sub=carol,client_id=${CTX:betaClient}" and store it as "carolToken"
    When I set header "Authorization" to "Bearer ${CTX:aliceToken}"
    And I send a "POST" request to "${CTX:providerContext}/__readiness" until header "x-ratelimit-cost-limit-dollars" is "0.000236" with body:
      """
      {"model":"gpt-4.1-2025-04-14","messages":[{"role":"user","content":"readiness"}]}
      """
    And I send a "POST" request to "${CTX:providerContext}/openai/v1/chat/completions" with body:
      """
      {"model":"gpt-4.1-2025-04-14","messages":[{"role":"user","content":"Hello"}]}
      """
    Then the response status code should be 200
    When I send a "POST" request to "${CTX:providerContext}/__readiness" with body:
      """
      {"model":"gpt-4.1-2025-04-14","messages":[{"role":"user","content":"readiness"}]}
      """
    Then the response header "x-ratelimit-cost-limit-dollars" should be "0.000236"
    And the response header "x-ratelimit-cost-remaining-dollars" should match pattern "^0\.0001[0-9]{2}$"
    When I set header "Authorization" to "Bearer ${CTX:carolToken}"
    And I send a "POST" request to "${CTX:providerContext}/__readiness" with body:
      """
      {"model":"gpt-4.1-2025-04-14","messages":[{"role":"user","content":"readiness"}]}
      """
    Then the response header "x-ratelimit-cost-remaining-dollars" should be "0.000236"

    When I clear all headers
    And I authenticate using basic auth as "admin"
    When I delete the LLM provider "${CTX:providerName}"
    Then the response should be successful

  # Known issue: https://github.com/wso2/api-platform/issues/2936 (an exactly spent budget still admits one more request under GCRA)
  @known-issue
  Scenario: With consumerBased every application has a budget of its own
    # alice spends the alpha budget, so bob, in the same application, is rejected. carol belongs to
    # another application and still has all of hers.
    Given I generate a unique resource name from "cblr-consumer-template" and store it as "templateName"
    And I generate a unique value from "cblr-consumer-template" and store it as "templateDisplayName"
    And I generate a unique resource name from "cblr-consumer-provider" and store it as "providerName"
    And I generate a unique value from "cblr-consumer-provider" and store it as "providerDisplayName"
    And I generate a unique API version from "cblr-consumer" and store it as "providerVersion"
    And I generate a unique API context from "/cblr-consumer" and store it as "providerContext"
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
      | spec.policies      | [{"name":"jwt-auth","version":"v1","paths":[{"path":"/*","methods":["*"],"params":{"issuers":["mock-jwks-appid"]}}]},{"name":"llm-cost-based-ratelimit","version":"v1","paths":[{"path":"/*","methods":["*"],"params":{"budgetLimits":[{"amount":0.000236,"duration":"1h"}],"consumerBased":true}}]},{"name":"llm-cost","version":"v1","paths":[{"path":"/*","methods":["*"]}]}] |
    Then the response status code should be 201
    And I generate a unique value from "cblr-consumer-alpha" and store it as "alphaClient"
    And I generate a unique value from "cblr-consumer-beta" and store it as "betaClient"

    When I clear all headers
    And I set header "Content-Type" to "application/json"
    And I get a JWT token from the mock JWKS server with issuer "http://testbench:3001/token" and claims "sub=alice,client_id=${CTX:alphaClient}" and store it as "aliceToken"
    And I get a JWT token from the mock JWKS server with issuer "http://testbench:3001/token" and claims "sub=bob,client_id=${CTX:alphaClient}" and store it as "bobToken"
    And I get a JWT token from the mock JWKS server with issuer "http://testbench:3001/token" and claims "sub=carol,client_id=${CTX:betaClient}" and store it as "carolToken"
    When I set header "Authorization" to "Bearer ${CTX:aliceToken}"
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
    When I set header "Authorization" to "Bearer ${CTX:bobToken}"
    When I send a "POST" request to "${CTX:providerContext}/openai/v1/chat/completions" with body:
      """
      {"model":"gpt-4.1-2025-04-14","messages":[{"role":"user","content":"Hello"}]}
      """
    Then the response status code should be 429
    When I set header "Authorization" to "Bearer ${CTX:carolToken}"
    When I send a "POST" request to "${CTX:providerContext}/openai/v1/chat/completions" with body:
      """
      {"model":"gpt-4.1-2025-04-14","messages":[{"role":"user","content":"Hello"}]}
      """
    Then the response status code should be 200

    When I clear all headers
    And I authenticate using basic auth as "admin"
    When I delete the LLM provider "${CTX:providerName}"
    Then the response should be successful

  # Known issue: https://github.com/wso2/api-platform/issues/2936 (an exactly spent budget still admits one more request under GCRA)
  @known-issue
  Scenario: Without consumerBased every caller draws on one budget
    # alice and carol, in different applications, each spend one request of the two the route holds.
    # bob is then rejected, and so is alice again: no application has a budget of its own.
    Given I generate a unique resource name from "cblr-shared-template" and store it as "templateName"
    And I generate a unique value from "cblr-shared-template" and store it as "templateDisplayName"
    And I generate a unique resource name from "cblr-shared-provider" and store it as "providerName"
    And I generate a unique value from "cblr-shared-provider" and store it as "providerDisplayName"
    And I generate a unique API version from "cblr-shared" and store it as "providerVersion"
    And I generate a unique API context from "/cblr-shared" and store it as "providerContext"
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
      | spec.policies      | [{"name":"jwt-auth","version":"v1","paths":[{"path":"/*","methods":["*"],"params":{"issuers":["mock-jwks-appid"]}}]},{"name":"llm-cost-based-ratelimit","version":"v1","paths":[{"path":"/*","methods":["*"],"params":{"budgetLimits":[{"amount":0.000236,"duration":"1h"}]}}]},{"name":"llm-cost","version":"v1","paths":[{"path":"/*","methods":["*"]}]}] |
    Then the response status code should be 201
    And I generate a unique value from "cblr-shared-alpha" and store it as "alphaClient"
    And I generate a unique value from "cblr-shared-beta" and store it as "betaClient"

    When I clear all headers
    And I set header "Content-Type" to "application/json"
    And I get a JWT token from the mock JWKS server with issuer "http://testbench:3001/token" and claims "sub=alice,client_id=${CTX:alphaClient}" and store it as "aliceToken"
    And I get a JWT token from the mock JWKS server with issuer "http://testbench:3001/token" and claims "sub=bob,client_id=${CTX:alphaClient}" and store it as "bobToken"
    And I get a JWT token from the mock JWKS server with issuer "http://testbench:3001/token" and claims "sub=carol,client_id=${CTX:betaClient}" and store it as "carolToken"
    When I set header "Authorization" to "Bearer ${CTX:aliceToken}"
    And I send a "POST" request to "${CTX:providerContext}/__readiness" until header "x-ratelimit-cost-limit-dollars" is "0.000236" with body:
      """
      {"model":"gpt-4.1-2025-04-14","messages":[{"role":"user","content":"readiness"}]}
      """
    And I send a "POST" request to "${CTX:providerContext}/openai/v1/chat/completions" with body:
      """
      {"model":"gpt-4.1-2025-04-14","messages":[{"role":"user","content":"Hello"}]}
      """
    Then the response status code should be 200
    When I set header "Authorization" to "Bearer ${CTX:carolToken}"
    When I send a "POST" request to "${CTX:providerContext}/openai/v1/chat/completions" with body:
      """
      {"model":"gpt-4.1-2025-04-14","messages":[{"role":"user","content":"Hello"}]}
      """
    Then the response status code should be 200
    And I send a "POST" request to "${CTX:providerContext}/__readiness" until header "x-ratelimit-cost-remaining-dollars" is "0.000000" with body:
      """
      {"model":"gpt-4.1-2025-04-14","messages":[{"role":"user","content":"readiness"}]}
      """
    When I set header "Authorization" to "Bearer ${CTX:bobToken}"
    When I send a "POST" request to "${CTX:providerContext}/openai/v1/chat/completions" with body:
      """
      {"model":"gpt-4.1-2025-04-14","messages":[{"role":"user","content":"Hello"}]}
      """
    Then the response status code should be 429
    When I set header "Authorization" to "Bearer ${CTX:aliceToken}"
    When I send a "POST" request to "${CTX:providerContext}/openai/v1/chat/completions" with body:
      """
      {"model":"gpt-4.1-2025-04-14","messages":[{"role":"user","content":"Hello"}]}
      """
    Then the response status code should be 429

    When I clear all headers
    And I authenticate using basic auth as "admin"
    When I delete the LLM provider "${CTX:providerName}"
    Then the response should be successful

  # Known issue: https://github.com/wso2/api-platform/issues/2936 (an exactly spent budget still admits one more request under GCRA)
  @known-issue
  Scenario: A shared budget and a consumer budget on one route are enforced independently
    # Two instances of the policy are attached to the same route. Each keeps its own pinned delegate
    # and scale factor, so neither overwrites the other. The consumer budget, $0.000236 per
    # application, is listed first so its headers are the ones reported. The shared budget, $0.000354,
    # holds three requests in all. alice spends her two and is stopped by her own budget. carol then
    # spends one, which takes the route to three, and is stopped by the shared budget although her
    # own still holds one more.
    Given I generate a unique resource name from "cblr-both-template" and store it as "templateName"
    And I generate a unique value from "cblr-both-template" and store it as "templateDisplayName"
    And I generate a unique resource name from "cblr-both-provider" and store it as "providerName"
    And I generate a unique value from "cblr-both-provider" and store it as "providerDisplayName"
    And I generate a unique API version from "cblr-both" and store it as "providerVersion"
    And I generate a unique API context from "/cblr-both" and store it as "providerContext"
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
      | spec.policies      | [{"name":"jwt-auth","version":"v1","paths":[{"path":"/*","methods":["*"],"params":{"issuers":["mock-jwks-appid"]}}]},{"name":"llm-cost-based-ratelimit","version":"v1","paths":[{"path":"/*","methods":["*"],"params":{"budgetLimits":[{"amount":0.000236,"duration":"1h"}],"consumerBased":true}}]},{"name":"llm-cost-based-ratelimit","version":"v1","paths":[{"path":"/*","methods":["*"],"params":{"budgetLimits":[{"amount":0.000354,"duration":"1h"}]}}]},{"name":"llm-cost","version":"v1","paths":[{"path":"/*","methods":["*"]}]}] |
    Then the response status code should be 201
    And I generate a unique value from "cblr-both-alpha" and store it as "alphaClient"
    And I generate a unique value from "cblr-both-beta" and store it as "betaClient"

    When I clear all headers
    And I set header "Content-Type" to "application/json"
    And I get a JWT token from the mock JWKS server with issuer "http://testbench:3001/token" and claims "sub=alice,client_id=${CTX:alphaClient}" and store it as "aliceToken"
    And I get a JWT token from the mock JWKS server with issuer "http://testbench:3001/token" and claims "sub=bob,client_id=${CTX:alphaClient}" and store it as "bobToken"
    And I get a JWT token from the mock JWKS server with issuer "http://testbench:3001/token" and claims "sub=carol,client_id=${CTX:betaClient}" and store it as "carolToken"
    When I set header "Authorization" to "Bearer ${CTX:aliceToken}"
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
    When I set header "Authorization" to "Bearer ${CTX:carolToken}"
    When I send a "POST" request to "${CTX:providerContext}/openai/v1/chat/completions" with body:
      """
      {"model":"gpt-4.1-2025-04-14","messages":[{"role":"user","content":"Hello"}]}
      """
    Then the response status code should be 200
    And I send a "POST" request to "${CTX:providerContext}/__readiness" until header "x-ratelimit-cost-remaining-dollars" is "0.000118" with body:
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
