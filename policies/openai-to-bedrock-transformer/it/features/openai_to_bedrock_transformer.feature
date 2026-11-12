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

@openai-to-bedrock-transformer
Feature: OpenAI to Bedrock transformer
  As an API consumer
  I want to call an AWS Bedrock upstream with OpenAI Chat Completions requests
  So that clients written for OpenAI work unchanged against the Bedrock Converse API

  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"
    And I resolve the "capture" service URL at "" and store it as "captureUpstream"

  Scenario: A Bedrock Converse response is returned in the OpenAI chat completion shape
    Given I generate a unique resource name from "o2b-response-provider" and store it as "providerName"
    And I generate a unique API context from "/o2b-response-provider" and store it as "providerContext"
    And I generate a unique resource name from "o2b-response-proxy" and store it as "proxyName"
    And I generate a unique API context from "/o2b-response-proxy" and store it as "proxyContext"
    When I create LLM provider from "resources/templates/llm-provider.yaml" with values:
      | apiVersion         | ${CTX:gatewaySpecVersion} |
      | name               | ${CTX:providerName}       |
      | displayName        | O2B-Response-Provider     |
      | version            | v1.0                      |
      | template           | openai                    |
      | spec.context       | ${CTX:providerContext}    |
      | spec.upstream.url  | http://testbench:3008     |
      | accessControl.mode | allow_all                 |
    Then the response status code should be 201
    When I create LLM proxy from "resources/templates/llm-proxy.yaml" with values:
      | apiVersion    | ${CTX:gatewaySpecVersion}                                                                                                                                |
      | name          | ${CTX:proxyName}                                                                                                                                         |
      | displayName   | O2B-Response-Proxy                                                                                                                                       |
      | version       | v1.0                                                                                                                                                     |
      | context       | ${CTX:proxyContext}                                                                                                                                      |
      | provider.id   | ${CTX:providerName}                                                                                                                                      |
      | spec.policies | [{"name":"openai-to-bedrock-transformer","version":"v0","paths":[{"path":"/chat/completions","methods":["POST"],"params":{"model":"amazon.fallback-model"}}]}] |
    Then the response status code should be 201
    # Converse responses carry no model, so the response reports the model the request named.
    And I send a "POST" request to "${CTX:proxyContext}/chat/completions" until status 200 with body:
      """
      {"model":"amazon.nova-lite-v1","messages":[{"role":"user","content":"Hello"}]}
      """
    Then the response should be valid JSON
    And the JSON response field "object" should be "chat.completion"
    And the JSON response field "model" should be "amazon.nova-lite-v1"
    And the JSON response field "choices[0].message.role" should be "assistant"
    And the JSON response field "choices[0].message.content" should be "Hello from Bedrock"
    And the JSON response field "choices[0].finish_reason" should be "stop"
    And the JSON response field "usage.prompt_tokens" should be 10
    And the JSON response field "usage.completion_tokens" should be 3
    And the JSON response field "usage.total_tokens" should be 13
    When I delete the LLM proxy "${CTX:proxyName}"
    Then the response should be successful
    When I delete the LLM provider "${CTX:providerName}"
    Then the response should be successful

  Scenario: The upstream receives Converse and ConverseStream requests for the resolved model
    Given I generate a unique resource name from "o2b-request-provider" and store it as "providerName"
    And I generate a unique API context from "/o2b-request-provider" and store it as "providerContext"
    And I generate a unique resource name from "o2b-request-proxy" and store it as "proxyName"
    And I generate a unique API context from "/o2b-request-proxy" and store it as "proxyContext"
    When I create LLM provider from "resources/templates/llm-provider.yaml" with values:
      | apiVersion         | ${CTX:gatewaySpecVersion} |
      | name               | ${CTX:providerName}       |
      | displayName        | O2B-Request-Provider      |
      | version            | v1.0                      |
      | template           | openai                    |
      | spec.context       | ${CTX:providerContext}    |
      | spec.upstream.url  | ${CTX:captureUpstream}    |
      | accessControl.mode | allow_all                 |
    Then the response status code should be 201
    When I create LLM proxy from "resources/templates/llm-proxy.yaml" with values:
      | apiVersion    | ${CTX:gatewaySpecVersion}                                                                                                                              |
      | name          | ${CTX:proxyName}                                                                                                                                       |
      | displayName   | O2B-Request-Proxy                                                                                                                                      |
      | version       | v1.0                                                                                                                                                   |
      | context       | ${CTX:proxyContext}                                                                                                                                    |
      | provider.id   | ${CTX:providerName}                                                                                                                                    |
      | spec.policies | [{"name":"openai-to-bedrock-transformer","version":"v0","paths":[{"path":"/chat/completions","methods":["POST"],"params":{"model":"amazon.nova-lite-v1"}}]}] |
    Then the response status code should be 201
    # The request names no model, so the fallback model goes into the Converse path.
    And I send a "POST" request to "${CTX:proxyContext}/chat/completions" until status 200 with body:
      """
      {"messages":[{"role":"system","content":"Answer briefly."},{"role":"user","content":"Hello"}],"max_tokens":64,"temperature":0.2}
      """
    When I send a "GET" request to the "capture" service at "/test/captured?path=/model/amazon.nova-lite-v1/converse"
    Then the response status code should be 200
    And the JSON response field "method" should be "POST"
    And the JSON response field "path" should be "/model/amazon.nova-lite-v1/converse"
    And the JSON response field "body" should contain "Answer briefly."
    And the JSON response field "body" should contain "inferenceConfig"
    And the JSON response field "body" should contain "maxTokens"
    And the response body should not contain "max_tokens"
    # A streaming request is sent to the ConverseStream endpoint instead.
    When I send a "POST" request to "${CTX:proxyContext}/chat/completions" with body:
      """
      {"stream":true,"messages":[{"role":"user","content":"Hello"}]}
      """
    And I send a "GET" request to the "capture" service at "/test/captured?path=/model/amazon.nova-lite-v1/converse-stream"
    Then the response status code should be 200
    And the JSON response field "path" should be "/model/amazon.nova-lite-v1/converse-stream"
    When I delete the LLM proxy "${CTX:proxyName}"
    Then the response should be successful
    When I delete the LLM provider "${CTX:providerName}"
    Then the response should be successful

  # The response must match the expected error response recorded from the policy before a
  # change (resources/expected-error-responses), so a change a client could observe fails.
  Scenario: openai-to-bedrock-transformer rejects an empty request body
    Given I generate a unique value from "compat-ob-empty" and store it as "apiName"
    And I generate a unique API version from "compat-ob-empty" and store it as "apiVersion"
    And I generate a unique API context from "/compat-ob-empty" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3002 |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"POST","path":"/chat/completions","policies":[{"name":"openai-to-bedrock-transformer","version":"v0","params":{"model":"anthropic.claude-3-5-sonnet-20240620-v1:0"}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat/completions" with body:
      """
      """
    Then the response status code should be 400
    And the response should match the expected error response "openai-to-bedrock-transformer-empty-body"
