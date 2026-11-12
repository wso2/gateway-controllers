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

@openai-to-azure-openai-transformer
Feature: OpenAI to Azure OpenAI transformer
  As an API consumer
  I want to call an Azure OpenAI upstream with OpenAI Chat Completions requests
  So that clients written for OpenAI reach the right Azure deployment unchanged

  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"
    And I resolve the "capture" service URL at "" and store it as "captureUpstream"

  Scenario: A chat completion is served through the Azure deployment path
    Given I generate a unique resource name from "o2az-response-provider" and store it as "providerName"
    And I generate a unique API context from "/o2az-response-provider" and store it as "providerContext"
    And I generate a unique resource name from "o2az-response-proxy" and store it as "proxyName"
    And I generate a unique API context from "/o2az-response-proxy" and store it as "proxyContext"
    When I create LLM provider from "resources/templates/llm-provider.yaml" with values:
      | apiVersion         | ${CTX:gatewaySpecVersion} |
      | name               | ${CTX:providerName}       |
      | displayName        | O2AZ-Response-Provider    |
      | version            | v1.0                      |
      | template           | openai                    |
      | spec.context       | ${CTX:providerContext}    |
      | spec.upstream.url  | http://testbench:3008     |
      | accessControl.mode | allow_all                 |
    Then the response status code should be 201
    When I create LLM proxy from "resources/templates/llm-proxy.yaml" with values:
      | apiVersion    | ${CTX:gatewaySpecVersion}                                                                                                                                         |
      | name          | ${CTX:proxyName}                                                                                                                                                  |
      | displayName   | O2AZ-Response-Proxy                                                                                                                                               |
      | version       | v1.0                                                                                                                                                              |
      | context       | ${CTX:proxyContext}                                                                                                                                               |
      | provider.id   | ${CTX:providerName}                                                                                                                                               |
      | spec.policies | [{"name":"openai-to-azure-openai-transformer","version":"v0","paths":[{"path":"/chat/completions","methods":["POST"],"params":{"apiVersion":"2024-10-21"}}]}] |
    Then the response status code should be 201
    And I send a "POST" request to "${CTX:proxyContext}/chat/completions" until status 200 with body:
      """
      {"model":"gpt-4o","messages":[{"role":"user","content":"Hello"}]}
      """
    Then the response should be valid JSON
    And the JSON response field "object" should be "chat.completion"
    And the JSON response field "model" should be "gpt-4o"
    And the JSON response field "choices[0].message.content" should be "Hello from the testbench."
    When I delete the LLM proxy "${CTX:proxyName}"
    Then the response should be successful
    When I delete the LLM provider "${CTX:providerName}"
    Then the response should be successful

  Scenario: The request model is used as the Azure deployment and the body passes through
    Given I generate a unique resource name from "o2az-model-provider" and store it as "providerName"
    And I generate a unique API context from "/o2az-model-provider" and store it as "providerContext"
    And I generate a unique resource name from "o2az-model-proxy" and store it as "proxyName"
    And I generate a unique API context from "/o2az-model-proxy" and store it as "proxyContext"
    When I create LLM provider from "resources/templates/llm-provider.yaml" with values:
      | apiVersion         | ${CTX:gatewaySpecVersion} |
      | name               | ${CTX:providerName}       |
      | displayName        | O2AZ-Model-Provider       |
      | version            | v1.0                      |
      | template           | openai                    |
      | spec.context       | ${CTX:providerContext}    |
      | spec.upstream.url  | ${CTX:captureUpstream}    |
      | accessControl.mode | allow_all                 |
    Then the response status code should be 201
    When I create LLM proxy from "resources/templates/llm-proxy.yaml" with values:
      | apiVersion    | ${CTX:gatewaySpecVersion}                                                                                                                                                                    |
      | name          | ${CTX:proxyName}                                                                                                                                                                             |
      | displayName   | O2AZ-Model-Proxy                                                                                                                                                                             |
      | version       | v1.0                                                                                                                                                                                         |
      | context       | ${CTX:proxyContext}                                                                                                                                                                          |
      | provider.id   | ${CTX:providerName}                                                                                                                                                                          |
      | spec.policies | [{"name":"openai-to-azure-openai-transformer","version":"v0","paths":[{"path":"/chat/completions","methods":["POST"],"params":{"apiVersion":"2024-10-21","model":"fallback-deployment"}}]}] |
    Then the response status code should be 201
    And I send a "POST" request to "${CTX:proxyContext}/chat/completions" until status 200 with body:
      """
      {"model":"gpt-4o-mini","messages":[{"role":"user","content":"o2az passthrough body"}]}
      """
    When I send a "GET" request to the "capture" service at "/test/captured?path=/openai/deployments/gpt-4o-mini/chat/completions"
    Then the response status code should be 200
    And the JSON response field "method" should be "POST"
    And the JSON response field "path" should be "/openai/deployments/gpt-4o-mini/chat/completions"
    And the JSON response field "query" should be "api-version=2024-10-21"
    And the JSON response field "body" should contain "o2az passthrough body"
    And the JSON response field "body" should contain "gpt-4o-mini"
    When I delete the LLM proxy "${CTX:proxyName}"
    Then the response should be successful
    When I delete the LLM provider "${CTX:providerName}"
    Then the response should be successful

  Scenario: The fallback deployment and a custom path suffix are used when the request names no model
    Given I generate a unique resource name from "o2az-fallback-provider" and store it as "providerName"
    And I generate a unique API context from "/o2az-fallback-provider" and store it as "providerContext"
    And I generate a unique resource name from "o2az-fallback-proxy" and store it as "proxyName"
    And I generate a unique API context from "/o2az-fallback-proxy" and store it as "proxyContext"
    When I create LLM provider from "resources/templates/llm-provider.yaml" with values:
      | apiVersion         | ${CTX:gatewaySpecVersion} |
      | name               | ${CTX:providerName}       |
      | displayName        | O2AZ-Fallback-Provider    |
      | version            | v1.0                      |
      | template           | openai                    |
      | spec.context       | ${CTX:providerContext}    |
      | spec.upstream.url  | ${CTX:captureUpstream}    |
      | accessControl.mode | allow_all                 |
    Then the response status code should be 201
    When I create LLM proxy from "resources/templates/llm-proxy.yaml" with values:
      | apiVersion    | ${CTX:gatewaySpecVersion}                                                                                                                                                                                                     |
      | name          | ${CTX:proxyName}                                                                                                                                                                                                              |
      | displayName   | O2AZ-Fallback-Proxy                                                                                                                                                                                                           |
      | version       | v1.0                                                                                                                                                                                                                          |
      | context       | ${CTX:proxyContext}                                                                                                                                                                                                           |
      | provider.id   | ${CTX:providerName}                                                                                                                                                                                                           |
      | spec.policies | [{"name":"openai-to-azure-openai-transformer","version":"v0","paths":[{"path":"/chat/completions","methods":["POST"],"params":{"apiVersion":"2024-02-15-preview","model":"fallback-deployment","pathSuffix":"/completions"}}]}] |
    Then the response status code should be 201
    And I send a "POST" request to "${CTX:proxyContext}/chat/completions" until status 200 with body:
      """
      {"messages":[{"role":"user","content":"Hello"}]}
      """
    When I send a "GET" request to the "capture" service at "/test/captured?path=/openai/deployments/fallback-deployment/completions"
    Then the response status code should be 200
    And the JSON response field "path" should be "/openai/deployments/fallback-deployment/completions"
    And the JSON response field "query" should be "api-version=2024-02-15-preview"
    When I delete the LLM proxy "${CTX:proxyName}"
    Then the response should be successful
    When I delete the LLM provider "${CTX:providerName}"
    Then the response should be successful

  # The response must match the expected error response recorded from the policy before a
  # change (resources/expected-error-responses), so a change a client could observe fails.
  Scenario: openai-to-azure-openai-transformer rejects a request that names no deployment anywhere
    Given I generate a unique value from "compat-oz-nomodel" and store it as "apiName"
    And I generate a unique API version from "compat-oz-nomodel" and store it as "apiVersion"
    And I generate a unique API context from "/compat-oz-nomodel" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3002 |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"POST","path":"/chat/completions","policies":[{"name":"openai-to-azure-openai-transformer","version":"v0","params":{"apiVersion":"2024-10-21"}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat/completions" with body:
      """
      {"messages":[{"role":"user","content":"Hello"}]}
      """
    Then the response status code should be 400
    And the response should match the expected error response "openai-to-azure-openai-transformer-model-missing"
