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

@model-access-control-locations
Feature: Model access control for every model location
  As an API developer
  I want the access rule applied wherever a provider carries the model
  So that header, query, path and payload providers are all governed the same way

  The gateway controller injects requestModel from the provider template, so each scenario
  creates a template that carries the model where the scenario needs it. The providers forward
  to the capture service, and reading it back shows the request the provider received.

  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"
    And I resolve the "capture" service URL at "" and store it as "captureUpstream"

  Scenario: The model is read from and rewritten in a request header
    Given I generate a unique resource name from "mac-header-template" and store it as "templateName"
    And I generate a unique value from "mac-header-template" and store it as "templateDisplayName"
    And I generate a unique resource name from "mac-header-provider" and store it as "providerName"
    And I generate a unique value from "mac-header-provider" and store it as "providerDisplayName"
    And I generate a unique API version from "mac-header-provider" and store it as "providerVersion"
    And I generate a unique API context from "/mac-header-provider" and store it as "providerContext"
    When I create LLM provider template from "resources/templates/llm-provider-template.yaml" with values:
      | apiVersion        | ${CTX:gatewaySpecVersion}                             |
      | name              | ${CTX:templateName}                                   |
      | displayName       | ${CTX:templateDisplayName}                            |
      | spec.requestModel | {"location":"header","identifier":"x-model-name"}     |
    Then the response status code should be 201
    When I create LLM provider from "resources/templates/llm-provider.yaml" with values:
      | apiVersion         | ${CTX:gatewaySpecVersion}                  |
      | name               | ${CTX:providerName}                        |
      | displayName        | ${CTX:providerDisplayName}                 |
      | version            | ${CTX:providerVersion}                     |
      | template           | ${CTX:templateName}                        |
      | spec.context       | ${CTX:providerContext}                     |
      | spec.upstream.url  | ${CTX:captureUpstream}/${CTX:providerName} |
      | accessControl.mode | allow_all                                  |
      | spec.policies      | [{"name":"model-access-control","version":"v0","paths":[{"path":"/chat/completions","methods":["POST"],"params":{"access":{"mode":"allow","models":["gpt-4o"]},"fallback":{"mappingPatterns":[{"fromPattern":"old-model","to":"gpt-4o"}]}}}]}] |
    Then the response status code should be 201

    When I set header "x-model-name" to "unlisted-model"
    And I send a "POST" request to "${CTX:providerContext}/chat/completions" until status 404 and the response body contains "model_not_found" with body:
      """
      {"messages":[{"role":"user","content":"Hello"}]}
      """
    Then the response should match the expected error response "model-access-control-denied"
    When I send a "GET" request to the "capture" service at "/test/captured?path=/${CTX:providerName}/chat/completions"
    Then the response status code should be 204

    When I set header "x-model-name" to "old-model"
    And I send a "POST" request to "${CTX:providerContext}/chat/completions" with body:
      """
      {"messages":[{"role":"user","content":"Hello"}]}
      """
    Then the response status code should be 200
    And the response should contain echoed header "x-model-name" with value "gpt-4o"

    When I set header "x-model-name" to "gpt-4o"
    And I send a "POST" request to "${CTX:providerContext}/chat/completions" with body:
      """
      {"messages":[{"role":"user","content":"Hello"}]}
      """
    Then the response status code should be 200
    And the response should contain echoed header "x-model-name" with value "gpt-4o"

    # Without the header there is no model to check.
    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I send a "POST" request to "${CTX:providerContext}/chat/completions" with body:
      """
      {"model":"gpt-4o","messages":[{"role":"user","content":"Hello"}]}
      """
    Then the response should match the expected error response "model-access-control-invalid-model"

    When I delete the LLM provider "${CTX:providerName}"
    Then the response should be successful
    When I delete the LLM provider template "${CTX:templateName}"
    Then the response should be successful

  Scenario: The model is read from and rewritten in a query parameter
    Given I generate a unique resource name from "mac-query-template" and store it as "templateName"
    And I generate a unique value from "mac-query-template" and store it as "templateDisplayName"
    And I generate a unique resource name from "mac-query-provider" and store it as "providerName"
    And I generate a unique value from "mac-query-provider" and store it as "providerDisplayName"
    And I generate a unique API version from "mac-query-provider" and store it as "providerVersion"
    And I generate a unique API context from "/mac-query-provider" and store it as "providerContext"
    When I create LLM provider template from "resources/templates/llm-provider-template.yaml" with values:
      | apiVersion        | ${CTX:gatewaySpecVersion}                      |
      | name              | ${CTX:templateName}                            |
      | displayName       | ${CTX:templateDisplayName}                     |
      | spec.requestModel | {"location":"queryParam","identifier":"model"} |
    Then the response status code should be 201
    When I create LLM provider from "resources/templates/llm-provider.yaml" with values:
      | apiVersion         | ${CTX:gatewaySpecVersion}                  |
      | name               | ${CTX:providerName}                        |
      | displayName        | ${CTX:providerDisplayName}                 |
      | version            | ${CTX:providerVersion}                     |
      | template           | ${CTX:templateName}                        |
      | spec.context       | ${CTX:providerContext}                     |
      | spec.upstream.url  | ${CTX:captureUpstream}/${CTX:providerName} |
      | accessControl.mode | allow_all                                  |
      | spec.policies      | [{"name":"model-access-control","version":"v0","paths":[{"path":"/chat/completions","methods":["POST"],"params":{"access":{"mode":"allow","models":["gpt-4o"]},"fallback":{"mappingPatterns":[{"fromPattern":"old-model","to":"gpt-4o"}]}}}]}] |
    Then the response status code should be 201

    When I send a "POST" request to "${CTX:providerContext}/chat/completions?api-version=1&model=unlisted-model" until status 404 and the response body contains "model_not_found" with body:
      """
      {"messages":[{"role":"user","content":"Hello"}]}
      """
    Then the response should match the expected error response "model-access-control-denied"

    # Two model values: the gateway and the provider could read different ones.
    When I send a "POST" request to "${CTX:providerContext}/chat/completions?model=gpt-4o&model=unlisted-model" with body:
      """
      {"messages":[{"role":"user","content":"Hello"}]}
      """
    Then the response should match the expected error response "model-access-control-invalid-model"
    When I send a "GET" request to the "capture" service at "/test/captured?path=/${CTX:providerName}/chat/completions"
    Then the response status code should be 204

    # Only the model's value changes; the other parameters keep their order.
    When I send a "POST" request to "${CTX:providerContext}/chat/completions?api-version=1&model=old-model&tier=a" with body:
      """
      {"messages":[{"role":"user","content":"Hello"}]}
      """
    Then the response status code should be 200
    And the JSON response field "query" should be "api-version=1&model=gpt-4o&tier=a"

    When I send a "POST" request to "${CTX:providerContext}/chat/completions?model=gpt-4o" with body:
      """
      {"messages":[{"role":"user","content":"Hello"}]}
      """
    Then the response status code should be 200
    And the JSON response field "query" should be "model=gpt-4o"

    When I delete the LLM provider "${CTX:providerName}"
    Then the response should be successful
    When I delete the LLM provider template "${CTX:templateName}"
    Then the response should be successful

  Scenario: A resource-specific template override puts the model in the path, beside a payload default
    Given I generate a unique resource name from "mac-path-template" and store it as "templateName"
    And I generate a unique value from "mac-path-template" and store it as "templateDisplayName"
    And I generate a unique resource name from "mac-path-provider" and store it as "providerName"
    And I generate a unique value from "mac-path-provider" and store it as "providerDisplayName"
    And I generate a unique API version from "mac-path-provider" and store it as "providerVersion"
    And I generate a unique API context from "/mac-path-provider" and store it as "providerContext"
    When I create LLM provider template from "resources/templates/llm-provider-template.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:templateName}       |
      | displayName            | ${CTX:templateDisplayName} |
      | spec.requestModel      | {"location":"payload","identifier":"$.model"} |
      | spec.resourceMappings  | {"resources":[{"resource":"/deployments/*","requestModel":{"location":"pathParam","identifier":"/deployments/([^/]+)/chat"}}]} |
    Then the response status code should be 201
    When I create LLM provider from "resources/templates/llm-provider.yaml" with values:
      | apiVersion         | ${CTX:gatewaySpecVersion}                  |
      | name               | ${CTX:providerName}                        |
      | displayName        | ${CTX:providerDisplayName}                 |
      | version            | ${CTX:providerVersion}                     |
      | template           | ${CTX:templateName}                        |
      | spec.context       | ${CTX:providerContext}                     |
      | spec.upstream.url  | ${CTX:captureUpstream}/${CTX:providerName} |
      | accessControl.mode | allow_all                                  |
      | spec.policies      | [{"name":"model-access-control","version":"v0","paths":[{"path":"/deployments/*","methods":["POST"],"params":{"access":{"mode":"allow","models":["gpt-4o"]},"fallback":{"mappingPatterns":[{"fromPattern":"old-model","to":"gpt-4o"}]}}},{"path":"/chat/completions","methods":["POST"],"params":{"access":{"mode":"allow","models":["gpt-4o"]},"fallback":{"mappingPatterns":[{"fromPattern":"old-model","to":"gpt-4o"}]}}}]}] |
    Then the response status code should be 201

    # The resource override: the model is the path segment.
    When I send a "POST" request to "${CTX:providerContext}/deployments/unlisted-model/chat" until status 404 and the response body contains "model_not_found" with body:
      """
      {"messages":[{"role":"user","content":"Hello"}]}
      """
    Then the response should match the expected error response "model-access-control-denied"
    When I send a "GET" request to the "capture" service at "/test/captured?path=/${CTX:providerName}/deployments/unlisted-model/chat"
    Then the response status code should be 204

    When I send a "POST" request to "${CTX:providerContext}/deployments/old-model/chat" with body:
      """
      {"model":"not-read-here","messages":[{"role":"user","content":"Hello"}]}
      """
    Then the response status code should be 200
    And the JSON response field "path" should be "/${CTX:providerName}/deployments/gpt-4o/chat"
    And the response body should contain "not-read-here"

    # The base template: the model is in the payload.
    When I send a "POST" request to "${CTX:providerContext}/chat/completions" with body:
      """
      {"model":"old-model","messages":[{"role":"user","content":"Hello"}]}
      """
    Then the response status code should be 200
    And the JSON response field "path" should be "/${CTX:providerName}/chat/completions"
    And the response body should contain "gpt-4o"
    And the response body should not contain "old-model"

    When I send a "POST" request to "${CTX:providerContext}/chat/completions" with body:
      """
      {"model":"unlisted-model","messages":[{"role":"user","content":"Hello"}]}
      """
    Then the response should match the expected error response "model-access-control-denied"

    When I delete the LLM provider "${CTX:providerName}"
    Then the response should be successful
    When I delete the LLM provider template "${CTX:templateName}"
    Then the response should be successful
