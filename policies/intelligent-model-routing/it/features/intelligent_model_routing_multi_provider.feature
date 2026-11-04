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

@intelligent-model-routing-multi-provider
Feature: Intelligent model routing across LLM providers
  As an API developer
  I want a routing rule to name the LLM provider its model lives on
  So that the policy routes a request to that provider's upstream as well as rewriting its model

  The LLM proxy has a primary provider and one additional provider, "secondary-provider". Each
  provider forwards to its own path on the echo backend, so the echoed "path" shows which provider
  was selected and the echoed "json.model" shows the rewritten model. The testbench openai service
  plays the classifier, as in intelligent_model_routing.feature.

  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"

  Scenario Outline: A matched rule routes to the provider it names, or stays on the primary provider
    Given I generate a unique resource name from "imr-mp-match-primary" and store it as "primaryProviderName"
    And I generate a unique value from "imr-mp-match-primary" and store it as "primaryProviderDisplayName"
    And I generate a unique API version from "imr-mp-match-primary" and store it as "primaryProviderVersion"
    And I generate a unique API context from "/imr-mp-match-primary" and store it as "primaryProviderContext"
    And I generate a unique resource name from "imr-mp-match-secondary" and store it as "secondaryProviderName"
    And I generate a unique value from "imr-mp-match-secondary" and store it as "secondaryProviderDisplayName"
    And I generate a unique API version from "imr-mp-match-secondary" and store it as "secondaryProviderVersion"
    And I generate a unique API context from "/imr-mp-match-secondary" and store it as "secondaryProviderContext"
    And I generate a unique resource name from "imr-mp-match-proxy" and store it as "proxyName"
    And I generate a unique value from "imr-mp-match-proxy" and store it as "proxyDisplayName"
    And I generate a unique API version from "imr-mp-match-proxy" and store it as "proxyVersion"
    And I generate a unique API context from "/imr-mp-match-proxy" and store it as "proxyContext"
    When I create LLM provider from "resources/templates/llm-provider.yaml" with values:
      | apiVersion         | ${CTX:gatewaySpecVersion}            |
      | name               | ${CTX:primaryProviderName}              |
      | displayName        | ${CTX:primaryProviderDisplayName}       |
      | version            | ${CTX:primaryProviderVersion}           |
      | template           | openai                               |
      | spec.context       | ${CTX:primaryProviderContext}           |
      | spec.upstream.url  | http://testbench:3002/primary-upstream  |
      | accessControl.mode | allow_all                            |
    Then the response status code should be 201

    When I create LLM provider from "resources/templates/llm-provider.yaml" with values:
      | apiVersion         | ${CTX:gatewaySpecVersion}            |
      | name               | ${CTX:secondaryProviderName}              |
      | displayName        | ${CTX:secondaryProviderDisplayName}       |
      | version            | ${CTX:secondaryProviderVersion}           |
      | template           | openai                               |
      | spec.context       | ${CTX:secondaryProviderContext}           |
      | spec.upstream.url  | http://testbench:3002/secondary-upstream  |
      | accessControl.mode | allow_all                            |
    Then the response status code should be 201

    When I create LLM proxy from "resources/templates/llm-proxy.yaml" with values:
      | apiVersion               | ${CTX:gatewaySpecVersion}       |
      | name                     | ${CTX:proxyName}                |
      | displayName              | ${CTX:proxyDisplayName}         |
      | version                  | ${CTX:proxyVersion}             |
      | context                  | ${CTX:proxyContext}             |
      | provider.id              | ${CTX:primaryProviderName}      |
      | spec.additionalProviders | [{"id":"${CTX:secondaryProviderName}","as":"secondary-provider"}] |
      | spec.operationPolicies   | [{"name":"intelligent-model-routing","version":"v0","paths":[{"path":"/chat/completions","methods":["POST"],"params":{"routingRules":[{"name":"Flex tier response.","context":"Requests the classifier labels as flex tier","provider":"secondary-provider","model":"imr-secondary-model"},{"name":"Batch tier response.","context":"Requests the classifier labels as batch tier","model":"imr-primary-model"}],"defaultModel":"imr-fallback-model","requestModel":{"location":"payload","identifier":"$.model"},"llmEndpoint":"http://testbench:3008<classifierPath>"}}]}] |
    Then the response status code should be 201
    And I send a "POST" request to "${CTX:proxyContext}/chat/completions" until status 200 with body:
      """
      {"model":"imr-original-model","messages":[{"role":"user","content":"Route this request"}]}
      """
    Then the JSON response field "path" should contain "/<upstream>/"
    And the JSON response field "json.model" should be "<routedModel>"

    When I delete the LLM proxy "${CTX:proxyName}"
    Then the response should be successful
    When I delete the LLM provider "${CTX:secondaryProviderName}"
    Then the response should be successful
    When I delete the LLM provider "${CTX:primaryProviderName}"
    Then the response should be successful

    Examples:
      | classifierPath        | upstream           | routedModel         |
      | /openai/v1/chat-flex  | secondary-upstream | imr-secondary-model |
      | /openai/v1/chat-batch | primary-upstream   | imr-primary-model   |

  Scenario: The fallback routes to defaultProvider with the default model
    Given I generate a unique resource name from "imr-mp-fallback-primary" and store it as "primaryProviderName"
    And I generate a unique value from "imr-mp-fallback-primary" and store it as "primaryProviderDisplayName"
    And I generate a unique API version from "imr-mp-fallback-primary" and store it as "primaryProviderVersion"
    And I generate a unique API context from "/imr-mp-fallback-primary" and store it as "primaryProviderContext"
    And I generate a unique resource name from "imr-mp-fallback-secondary" and store it as "secondaryProviderName"
    And I generate a unique value from "imr-mp-fallback-secondary" and store it as "secondaryProviderDisplayName"
    And I generate a unique API version from "imr-mp-fallback-secondary" and store it as "secondaryProviderVersion"
    And I generate a unique API context from "/imr-mp-fallback-secondary" and store it as "secondaryProviderContext"
    And I generate a unique resource name from "imr-mp-fallback-proxy" and store it as "proxyName"
    And I generate a unique value from "imr-mp-fallback-proxy" and store it as "proxyDisplayName"
    And I generate a unique API version from "imr-mp-fallback-proxy" and store it as "proxyVersion"
    And I generate a unique API context from "/imr-mp-fallback-proxy" and store it as "proxyContext"
    When I create LLM provider from "resources/templates/llm-provider.yaml" with values:
      | apiVersion         | ${CTX:gatewaySpecVersion}            |
      | name               | ${CTX:primaryProviderName}              |
      | displayName        | ${CTX:primaryProviderDisplayName}       |
      | version            | ${CTX:primaryProviderVersion}           |
      | template           | openai                               |
      | spec.context       | ${CTX:primaryProviderContext}           |
      | spec.upstream.url  | http://testbench:3002/primary-upstream  |
      | accessControl.mode | allow_all                            |
    Then the response status code should be 201

    When I create LLM provider from "resources/templates/llm-provider.yaml" with values:
      | apiVersion         | ${CTX:gatewaySpecVersion}            |
      | name               | ${CTX:secondaryProviderName}              |
      | displayName        | ${CTX:secondaryProviderDisplayName}       |
      | version            | ${CTX:secondaryProviderVersion}           |
      | template           | openai                               |
      | spec.context       | ${CTX:secondaryProviderContext}           |
      | spec.upstream.url  | http://testbench:3002/secondary-upstream  |
      | accessControl.mode | allow_all                            |
    Then the response status code should be 201

    When I create LLM proxy from "resources/templates/llm-proxy.yaml" with values:
      | apiVersion               | ${CTX:gatewaySpecVersion}       |
      | name                     | ${CTX:proxyName}                |
      | displayName              | ${CTX:proxyDisplayName}         |
      | version                  | ${CTX:proxyVersion}             |
      | context                  | ${CTX:proxyContext}             |
      | provider.id              | ${CTX:primaryProviderName}      |
      | spec.additionalProviders | [{"id":"${CTX:secondaryProviderName}","as":"secondary-provider"}] |
      | spec.operationPolicies   | [{"name":"intelligent-model-routing","version":"v0","paths":[{"path":"/chat/completions","methods":["POST"],"params":{"routingRules":[{"name":"Flex tier response.","context":"Requests the classifier labels as flex tier","provider":"secondary-provider","model":"imr-secondary-model"},{"name":"Batch tier response.","context":"Requests the classifier labels as batch tier","model":"imr-primary-model"}],"defaultModel":"imr-fallback-model","requestModel":{"location":"payload","identifier":"$.model"},"defaultProvider":"secondary-provider","llmEndpoint":"http://testbench:3002/status/500"}}]}] |
    Then the response status code should be 201
    And I send a "POST" request to "${CTX:proxyContext}/chat/completions" until status 200 with body:
      """
      {"model":"imr-original-model","messages":[{"role":"user","content":"Route this request"}]}
      """
    Then the JSON response field "path" should contain "/secondary-upstream/"
    And the JSON response field "json.model" should be "imr-fallback-model"

    When I delete the LLM proxy "${CTX:proxyName}"
    Then the response should be successful
    When I delete the LLM provider "${CTX:secondaryProviderName}"
    Then the response should be successful
    When I delete the LLM provider "${CTX:primaryProviderName}"
    Then the response should be successful

  Scenario: The fallback without defaultProvider stays on the primary provider
    Given I generate a unique resource name from "imr-mp-primary-primary" and store it as "primaryProviderName"
    And I generate a unique value from "imr-mp-primary-primary" and store it as "primaryProviderDisplayName"
    And I generate a unique API version from "imr-mp-primary-primary" and store it as "primaryProviderVersion"
    And I generate a unique API context from "/imr-mp-primary-primary" and store it as "primaryProviderContext"
    And I generate a unique resource name from "imr-mp-primary-secondary" and store it as "secondaryProviderName"
    And I generate a unique value from "imr-mp-primary-secondary" and store it as "secondaryProviderDisplayName"
    And I generate a unique API version from "imr-mp-primary-secondary" and store it as "secondaryProviderVersion"
    And I generate a unique API context from "/imr-mp-primary-secondary" and store it as "secondaryProviderContext"
    And I generate a unique resource name from "imr-mp-primary-proxy" and store it as "proxyName"
    And I generate a unique value from "imr-mp-primary-proxy" and store it as "proxyDisplayName"
    And I generate a unique API version from "imr-mp-primary-proxy" and store it as "proxyVersion"
    And I generate a unique API context from "/imr-mp-primary-proxy" and store it as "proxyContext"
    When I create LLM provider from "resources/templates/llm-provider.yaml" with values:
      | apiVersion         | ${CTX:gatewaySpecVersion}            |
      | name               | ${CTX:primaryProviderName}              |
      | displayName        | ${CTX:primaryProviderDisplayName}       |
      | version            | ${CTX:primaryProviderVersion}           |
      | template           | openai                               |
      | spec.context       | ${CTX:primaryProviderContext}           |
      | spec.upstream.url  | http://testbench:3002/primary-upstream  |
      | accessControl.mode | allow_all                            |
    Then the response status code should be 201

    When I create LLM provider from "resources/templates/llm-provider.yaml" with values:
      | apiVersion         | ${CTX:gatewaySpecVersion}            |
      | name               | ${CTX:secondaryProviderName}              |
      | displayName        | ${CTX:secondaryProviderDisplayName}       |
      | version            | ${CTX:secondaryProviderVersion}           |
      | template           | openai                               |
      | spec.context       | ${CTX:secondaryProviderContext}           |
      | spec.upstream.url  | http://testbench:3002/secondary-upstream  |
      | accessControl.mode | allow_all                            |
    Then the response status code should be 201

    When I create LLM proxy from "resources/templates/llm-proxy.yaml" with values:
      | apiVersion               | ${CTX:gatewaySpecVersion}       |
      | name                     | ${CTX:proxyName}                |
      | displayName              | ${CTX:proxyDisplayName}         |
      | version                  | ${CTX:proxyVersion}             |
      | context                  | ${CTX:proxyContext}             |
      | provider.id              | ${CTX:primaryProviderName}      |
      | spec.additionalProviders | [{"id":"${CTX:secondaryProviderName}","as":"secondary-provider"}] |
      | spec.operationPolicies   | [{"name":"intelligent-model-routing","version":"v0","paths":[{"path":"/chat/completions","methods":["POST"],"params":{"routingRules":[{"name":"Flex tier response.","context":"Requests the classifier labels as flex tier","provider":"secondary-provider","model":"imr-secondary-model"},{"name":"Batch tier response.","context":"Requests the classifier labels as batch tier","model":"imr-primary-model"}],"defaultModel":"imr-fallback-model","requestModel":{"location":"payload","identifier":"$.model"},"llmEndpoint":"http://testbench:3002/status/500"}}]}] |
    Then the response status code should be 201
    And I send a "POST" request to "${CTX:proxyContext}/chat/completions" until status 200 with body:
      """
      {"model":"imr-original-model","messages":[{"role":"user","content":"Route this request"}]}
      """
    Then the JSON response field "path" should contain "/primary-upstream/"
    And the JSON response field "json.model" should be "imr-fallback-model"

    When I delete the LLM proxy "${CTX:proxyName}"
    Then the response should be successful
    When I delete the LLM provider "${CTX:secondaryProviderName}"
    Then the response should be successful
    When I delete the LLM provider "${CTX:primaryProviderName}"
    Then the response should be successful
