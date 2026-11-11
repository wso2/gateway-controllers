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

@azure-llm-cost
Feature: Azure LLM Cost policy configuration validation
  As an API developer
  I want the gateway to reject an Azure LLM provider whose cost policy is misconfigured
  So that a mistake in the deployment mappings is reported when the provider is created

  # Configurations rejected when the provider is created, from the policy's parameter schema.
  # Gateways 1.1.0 and 1.2.0 do not validate them, so these run on later releases only.

  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"

  # The rejection names the parameter path of the offending entry, index included.
  Scenario Outline: Configure modelMappings as a non-array, with a non-object entry, or with a blank/missing deployment or model (<case>)
    Given I generate a unique resource name from "alc-v-<slug>" and store it as "providerName"
    And I generate a unique value from "alc-v-<slug>" and store it as "providerDisplayName"
    And I generate a unique API version from "alc-v-<slug>" and store it as "providerVersion"
    And I generate a unique API context from "/alc-v-<slug>" and store it as "providerContext"
    When I create LLM provider from "resources/templates/llm-provider.yaml" with values:
      | apiVersion         | ${CTX:gatewaySpecVersion}  |
      | name               | ${CTX:providerName}        |
      | displayName        | ${CTX:providerDisplayName} |
      | version            | ${CTX:providerVersion}     |
      | template           | azure-openai               |
      | spec.context       | ${CTX:providerContext}     |
      | spec.upstream.url  | http://testbench:3008      |
      | accessControl.mode | allow_all                  |
      | spec.policies      | [{"name":"azure-llm-cost","version":"v1","paths":[{"path":"/*","methods":["*"],"params":{"modelMappings":<modelMappings>}}]}] |
    Then the response status code should be 400
    And the response body should contain "<field>"

    Examples:
      | case               | slug          | modelMappings                                                                                  | field                           |
      | not an array       | not-array     | {"deployment":"chat-mini","model":"gpt-4o-mini"}                                               | params.modelMappings            |
      | non-object entry   | not-object    | [{"deployment":"chat-mini","model":"gpt-4o-mini"},"chat-4o"]                                   | params.modelMappings.1          |
      | missing deployment | no-deployment | [{"deployment":"chat-mini","model":"gpt-4o-mini"},{"model":"gpt-4o"}]                          | params.modelMappings.1          |
      | missing model      | no-model      | [{"deployment":"chat-mini","model":"gpt-4o-mini"},{"deployment":"chat-4o"}]                    | params.modelMappings.1          |
      | blank deployment   | blank-deploy  | [{"deployment":"chat-mini","model":"gpt-4o-mini"},{"deployment":"","model":"gpt-4o"}]          | params.modelMappings.1.deployment |
      | blank model        | blank-model   | [{"deployment":"chat-mini","model":"gpt-4o-mini"},{"deployment":"chat-4o","model":""}]         | params.modelMappings.1.model    |
