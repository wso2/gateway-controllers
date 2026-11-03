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

@openai-to-mistral-transformer
Feature: OpenAI to Mistral transformer
  As an API consumer
  I want to call a Mistral upstream with OpenAI Chat Completions requests
  So that clients written for OpenAI work unchanged against Mistral

  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"
    And I resolve the "capture" service URL at "" and store it as "captureUpstream"

  Scenario: A Mistral chat completion is returned in the OpenAI chat completion shape
    Given I generate a unique resource name from "o2m-response-provider" and store it as "providerName"
    And I generate a unique API context from "/o2m-response-provider" and store it as "providerContext"
    And I generate a unique resource name from "o2m-response-proxy" and store it as "proxyName"
    And I generate a unique API context from "/o2m-response-proxy" and store it as "proxyContext"
    When I create LLM provider from "resources/templates/llm-provider.yaml" with values:
      | apiVersion         | ${CTX:gatewaySpecVersion}     |
      | name               | ${CTX:providerName}           |
      | displayName        | O2M-Response-Provider         |
      | version            | v1.0                          |
      | template           | openai                        |
      | spec.context       | ${CTX:providerContext}        |
      | spec.upstream.url  | http://testbench:3008/mistral |
      | accessControl.mode | allow_all                     |
    Then the response status code should be 201
    When I create LLM proxy from "resources/templates/llm-proxy.yaml" with values:
      | apiVersion    | ${CTX:gatewaySpecVersion}                                                                                                                                 |
      | name          | ${CTX:proxyName}                                                                                                                                          |
      | displayName   | O2M-Response-Proxy                                                                                                                                        |
      | version       | v1.0                                                                                                                                                      |
      | context       | ${CTX:proxyContext}                                                                                                                                       |
      | provider.id   | ${CTX:providerName}                                                                                                                                       |
      | spec.policies | [{"name":"openai-to-mistral-transformer","version":"v0","paths":[{"path":"/chat/completions","methods":["POST"],"params":{"model":"mistral-large-latest"}}]}] |
    Then the response status code should be 201
    And I send a "POST" request to "${CTX:proxyContext}/chat/completions" until status 200 with body:
      """
      {"model":"mistral-small-latest","messages":[{"role":"user","content":"Hello"}]}
      """
    Then the response should be valid JSON
    And the JSON response field "object" should be "chat.completion"
    And the JSON response field "model" should be "mistral-small-latest"
    And the JSON response field "choices[0].message.role" should be "assistant"
    And the JSON response field "choices[0].message.content" should be "Hello! How can I assist you today?"
    And the JSON response field "choices[0].finish_reason" should be "stop"
    And the JSON response field "usage.prompt_tokens" should be 100
    And the JSON response field "usage.completion_tokens" should be 50
    And the JSON response field "usage.total_tokens" should be 150
    When I delete the LLM proxy "${CTX:proxyName}"
    Then the response should be successful
    When I delete the LLM provider "${CTX:providerName}"
    Then the response should be successful

  Scenario: The upstream receives a Mistral request without the fields Mistral rejects
    Given I generate a unique resource name from "o2m-request-provider" and store it as "providerName"
    And I generate a unique API context from "/o2m-request-provider" and store it as "providerContext"
    And I generate a unique resource name from "o2m-request-proxy" and store it as "proxyName"
    And I generate a unique API context from "/o2m-request-proxy" and store it as "proxyContext"
    When I create LLM provider from "resources/templates/llm-provider.yaml" with values:
      | apiVersion         | ${CTX:gatewaySpecVersion} |
      | name               | ${CTX:providerName}       |
      | displayName        | O2M-Request-Provider      |
      | version            | v1.0                      |
      | template           | openai                    |
      | spec.context       | ${CTX:providerContext}    |
      | spec.upstream.url  | ${CTX:captureUpstream}    |
      | accessControl.mode | allow_all                 |
    Then the response status code should be 201
    When I create LLM proxy from "resources/templates/llm-proxy.yaml" with values:
      | apiVersion    | ${CTX:gatewaySpecVersion}                                                                                                                                 |
      | name          | ${CTX:proxyName}                                                                                                                                          |
      | displayName   | O2M-Request-Proxy                                                                                                                                         |
      | version       | v1.0                                                                                                                                                      |
      | context       | ${CTX:proxyContext}                                                                                                                                       |
      | provider.id   | ${CTX:providerName}                                                                                                                                       |
      | spec.policies | [{"name":"openai-to-mistral-transformer","version":"v0","paths":[{"path":"/chat/completions","methods":["POST"],"params":{"model":"mistral-large-latest"}}]}] |
    Then the response status code should be 201
    # The request names no model, so the fallback model is sent upstream.
    And I send a "POST" request to "${CTX:proxyContext}/chat/completions" until status 200 with body:
      """
      {"messages":[{"role":"user","content":"Hello"}],"temperature":0.2,"user":"o2m-end-user","n":1,"logit_bias":{"50256":-100},"service_tier":"auto","store":false}
      """
    When I send a "GET" request to the "capture" service at "/test/captured?path=/v1/chat/completions"
    Then the response status code should be 200
    And the JSON response field "method" should be "POST"
    And the JSON response field "path" should be "/v1/chat/completions"
    And the JSON response field "body" should contain "mistral-large-latest"
    And the JSON response field "body" should contain "temperature"
    And the response body should not contain "o2m-end-user"
    And the response body should not contain "logit_bias"
    And the response body should not contain "service_tier"
    When I delete the LLM proxy "${CTX:proxyName}"
    Then the response should be successful
    When I delete the LLM provider "${CTX:providerName}"
    Then the response should be successful

  # The response must match the expected error response recorded from the policy before a
  # change (resources/expected-error-responses), so a change a client could observe fails.
  Scenario: openai-to-mistral-transformer rejects an empty request body
    Given I generate a unique value from "compat-om-empty" and store it as "apiName"
    And I generate a unique API version from "compat-om-empty" and store it as "apiVersion"
    And I generate a unique API context from "/compat-om-empty" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3002 |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"POST","path":"/chat/completions","policies":[{"name":"openai-to-mistral-transformer","version":"v0","params":{"model":"mistral-small-latest"}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat/completions" with body:
      """
      """
    Then the response status code should be 400
    And the response should match the expected error response "openai-to-mistral-transformer-empty-body"
