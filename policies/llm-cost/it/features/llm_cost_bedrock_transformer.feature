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
Feature: LLM cost behind the openai-to-bedrock-transformer policy
  As an API developer
  I want a Bedrock call translated to the OpenAI shape to be priced
  So that its cost is charged like any other call

  # The testbench answers a Converse request with "Hello from Bedrock" and 10 prompt and 3 completion
  # tokens, and the transformer reports the model the request named. amazon.nova-lite-v1 is priced at
  # 10 x 0.000001 + 3 x 0.000004 = 0.000022. llm-cost is listed first so that, with response-phase
  # policies running in reverse order, it sees the response after the transformer has translated it.

  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"

  Scenario: Price a Bedrock Converse call through the openai-to-bedrock-transformer policy
    Given I generate a unique resource name from "lc-o2b-provider" and store it as "providerName"
    And I generate a unique API context from "/lc-o2b-provider" and store it as "providerContext"
    And I generate a unique resource name from "lc-o2b-proxy" and store it as "proxyName"
    And I generate a unique API context from "/lc-o2b-proxy" and store it as "proxyContext"
    When I create LLM provider from "resources/templates/llm-provider.yaml" with values:
      | apiVersion         | ${CTX:gatewaySpecVersion} |
      | name               | ${CTX:providerName}       |
      | displayName        | LC-O2B-Provider           |
      | version            | v1.0                      |
      | template           | openai                    |
      | spec.context       | ${CTX:providerContext}    |
      | spec.upstream.url  | http://testbench:3008     |
      | accessControl.mode | allow_all                 |
    Then the response status code should be 201
    When I create LLM proxy from "resources/templates/llm-proxy.yaml" with values:
      | apiVersion    | ${CTX:gatewaySpecVersion} |
      | name          | ${CTX:proxyName}          |
      | displayName   | LC-O2B-Proxy              |
      | version       | v1.0                      |
      | context       | ${CTX:proxyContext}       |
      | provider.id   | ${CTX:providerName}       |
      | spec.policies | [{"name":"llm-cost","version":"v1","paths":[{"path":"/chat/completions","methods":["POST"]}]},{"name":"openai-to-bedrock-transformer","version":"v0","paths":[{"path":"/chat/completions","methods":["POST"],"params":{"model":"amazon.fallback-model"}}]}] |
    Then the response status code should be 201

    When I send a "POST" request to "${CTX:proxyContext}/chat/completions" until status 200 with body:
      """
      {"model":"amazon.nova-lite-v1","messages":[{"role":"user","content":"Hello"}]}
      """
    Then the JSON response field "object" should be "chat.completion"
    And the JSON response field "model" should be "amazon.nova-lite-v1"
    And the JSON response field "usage.total_tokens" should be 13
    And the response header "x-llm-cost" should not exist
    # The proxy forwards to its provider's route, so the analytics event carries the provider's path as
    # the transformer rewrote it for Bedrock.
    And the latest analytics event for path "${CTX:providerContext}/model/amazon.nova-lite-v1/converse" should have numeric metadata field "aiMetadata.llmCost" equal to "0.000022"
    And the latest analytics event for path "${CTX:providerContext}/model/amazon.nova-lite-v1/converse" should have numeric metadata field "aiTokenUsage.promptTokens" equal to "10"
    And the latest analytics event for path "${CTX:providerContext}/model/amazon.nova-lite-v1/converse" should have numeric metadata field "aiTokenUsage.completionTokens" equal to "3"

    When I delete the LLM proxy "${CTX:proxyName}"
    Then the response should be successful
    When I delete the LLM provider "${CTX:providerName}"
    Then the response should be successful
