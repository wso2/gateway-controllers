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

@word-count-guardrail
Feature: Word count guardrail policy
  As an API developer
  I want the word-count-guardrail policy to behave as documented
  So that a change to it is caught before it reaches a release

  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"

  # The response must match the expected error response recorded from the policy before a
  # change (resources/expected-error-responses), so a change a client could observe fails.
  Scenario: word-count-guardrail rejects a request over the maximum
    Given I generate a unique value from "compat-wcg" and store it as "apiName"
    And I generate a unique API version from "compat-wcg" and store it as "apiVersion"
    And I generate a unique API context from "/compat-wcg" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}        |
      | name                   | ${CTX:apiName}                   |
      | spec.displayName       | ${CTX:apiName}                   |
      | spec.version           | ${CTX:apiVersion}                |
      | spec.context           | ${CTX:apiContext}/$version       |
      | spec.upstream.main.url | http://testbench:3000            |
      | spec.operations        | [{"method":"GET","path":"/get"},{"method":"POST","path":"/validate","policies":[{"name":"word-count-guardrail","version":"v1","params":{"request":{"min":1,"max":3,"jsonPath":""}}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 200

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/validate" with body:
      """
      this request has far too many words
      """
    Then the response status code should be 422
    And the response should match the expected error response "word-count-guardrail-request-max"

  Scenario: word-count-guardrail ends a streamed reply over the maximum
    Given the gateway version satisfies ">=1.2.0"
    And I generate a unique resource name from "compat-stream-wcg" and store it as "providerName"
    And I generate a unique value from "compat-stream-wcg" and store it as "providerDisplayName"
    And I generate a unique API version from "compat-stream-wcg" and store it as "providerVersion"
    And I generate a unique API context from "/compat-stream-wcg" and store it as "providerContext"
    When I create LLM provider from "resources/templates/llm-provider.yaml" with values:
      | apiVersion         | ${CTX:gatewaySpecVersion}  |
      | name               | ${CTX:providerName}        |
      | displayName        | ${CTX:providerDisplayName} |
      | version            | ${CTX:providerVersion}     |
      | template           | openai                     |
      | spec.context       | ${CTX:providerContext}     |
      | spec.upstream.url  | http://testbench:3008      |
      | accessControl.mode | allow_all                  |
      | spec.policies      | [{"name":"word-count-guardrail","version":"v1","paths":[{"path":"/*","methods":["*"],"params":{"response":{"enabled":true,"min":1,"max":3}}}]}] |
    Then the response status code should be 201

    # The streamed reply has 9 words; the guardrail allows at most 3.
    When I set header "Content-Type" to "application/json"
    And I send a "POST" request to "${CTX:providerContext}/openai/v1/chat/completions" until status 200 with body:
      """
      {"model":"gpt-4.1-2025-04-14","stream":true,"messages":[{"role":"user","content":"Hello"}]}
      """
    Then the response status code should be 200
    And the response should match the expected error response "word-count-guardrail-stream-max"
