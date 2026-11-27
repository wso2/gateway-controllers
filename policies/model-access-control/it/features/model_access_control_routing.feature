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

@model-access-control-routing
Feature: Model access control fallbacks to another provider and to models built from the request
  As an API developer
  I want a denied model sent to an approved model, on the provider I choose
  So that clients keep working while the access rule stays enforced

  Every provider forwards to its own path on the capture service, so the path in the
  response shows which provider received the request.

  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"
    And I resolve the "capture" service URL at "" and store it as "captureUpstream"

  Scenario: A fallback that names an additional provider sends the request to that provider
    Given I generate a unique resource name from "mac-route-primary" and store it as "primaryName"
    And I generate a unique value from "mac-route-primary" and store it as "primaryDisplayName"
    And I generate a unique API version from "mac-route-primary" and store it as "primaryVersion"
    And I generate a unique API context from "/mac-route-primary" and store it as "primaryContext"
    And I generate a unique resource name from "mac-route-backup" and store it as "backupName"
    And I generate a unique value from "mac-route-backup" and store it as "backupDisplayName"
    And I generate a unique API version from "mac-route-backup" and store it as "backupVersion"
    And I generate a unique API context from "/mac-route-backup" and store it as "backupContext"
    And I generate a unique resource name from "mac-route-proxy" and store it as "proxyName"
    And I generate a unique value from "mac-route-proxy" and store it as "proxyDisplayName"
    And I generate a unique API version from "mac-route-proxy" and store it as "proxyVersion"
    And I generate a unique API context from "/mac-route-proxy" and store it as "proxyContext"
    When I create LLM provider from "resources/templates/llm-provider.yaml" with values:
      | apiVersion         | ${CTX:gatewaySpecVersion}                 |
      | name               | ${CTX:primaryName}                        |
      | displayName        | ${CTX:primaryDisplayName}                 |
      | version            | ${CTX:primaryVersion}                     |
      | template           | openai                                    |
      | spec.context       | ${CTX:primaryContext}                     |
      | spec.upstream.url  | ${CTX:captureUpstream}/${CTX:primaryName} |
      | accessControl.mode | allow_all                                 |
    Then the response status code should be 201
    When I create LLM provider from "resources/templates/llm-provider.yaml" with values:
      | apiVersion         | ${CTX:gatewaySpecVersion}                |
      | name               | ${CTX:backupName}                        |
      | displayName        | ${CTX:backupDisplayName}                 |
      | version            | ${CTX:backupVersion}                     |
      | template           | openai                                   |
      | spec.context       | ${CTX:backupContext}                     |
      | spec.upstream.url  | ${CTX:captureUpstream}/${CTX:backupName} |
      | accessControl.mode | allow_all                                |
    Then the response status code should be 201
    When I create LLM proxy from "resources/templates/llm-proxy.yaml" with values:
      | apiVersion               | ${CTX:gatewaySpecVersion}                    |
      | name                     | ${CTX:proxyName}                             |
      | displayName              | ${CTX:proxyDisplayName}                      |
      | version                  | ${CTX:proxyVersion}                          |
      | context                  | ${CTX:proxyContext}                          |
      | provider.id              | ${CTX:primaryName}                           |
      | spec.additionalProviders | [{"id":"${CTX:backupName}","as":"backup"}]   |
      | spec.policies            | [{"name":"model-access-control","version":"v0","paths":[{"path":"/chat/completions","methods":["POST"],"params":{"access":{"mode":"allow","models":["gpt-4o"]},"fallback":{"mappingPatterns":[{"fromPattern":"claude-.*","to":"gpt-4o-mini","provider":"backup"},{"fromPattern":"old-model","to":"gpt-4o"}]}}}]}] |
    Then the response status code should be 201

    # A permitted model stays on the primary provider.
    When I send a "POST" request to "${CTX:proxyContext}/chat/completions" until status 200 with body:
      """
      {"model":"gpt-4o","messages":[{"role":"user","content":"Hello"}]}
      """
    Then the JSON response field "path" should be "/${CTX:primaryName}/chat/completions"
    And the response body should contain "gpt-4o"

    # A denied model whose fallback names the backup provider goes there, with the fallback model.
    When I send a "POST" request to "${CTX:proxyContext}/chat/completions" with body:
      """
      {"model":"claude-3-opus","messages":[{"role":"user","content":"Hello"}]}
      """
    Then the response status code should be 200
    And the JSON response field "path" should be "/${CTX:backupName}/chat/completions"
    And the response body should contain "gpt-4o-mini"
    And the response body should not contain "claude-3-opus"

    # A fallback without a provider stays on the primary provider.
    When I send a "POST" request to "${CTX:proxyContext}/chat/completions" with body:
      """
      {"model":"old-model","messages":[{"role":"user","content":"Hello"}]}
      """
    Then the response status code should be 200
    And the JSON response field "path" should be "/${CTX:primaryName}/chat/completions"
    And the response body should not contain "old-model"

    # A denied model without a fallback reaches neither provider.
    When I send a "POST" request to "${CTX:proxyContext}/chat/completions" with body:
      """
      {"model":"unlisted-model","messages":[{"role":"user","content":"Hello"}]}
      """
    Then the response should match the expected error response "model-access-control-denied"

    When I delete the LLM proxy "${CTX:proxyName}"
    Then the response should be successful
    When I delete the LLM provider "${CTX:backupName}"
    Then the response should be successful
    When I delete the LLM provider "${CTX:primaryName}"
    Then the response should be successful

  Scenario: A fallback built from the requested model must itself be permitted
    Given I generate a unique resource name from "mac-dyn-provider" and store it as "providerName"
    And I generate a unique value from "mac-dyn-provider" and store it as "providerDisplayName"
    And I generate a unique API version from "mac-dyn-provider" and store it as "providerVersion"
    And I generate a unique API context from "/mac-dyn-provider" and store it as "providerContext"
    When I create LLM provider from "resources/templates/llm-provider.yaml" with values:
      | apiVersion         | ${CTX:gatewaySpecVersion}                  |
      | name               | ${CTX:providerName}                        |
      | displayName        | ${CTX:providerDisplayName}                 |
      | version            | ${CTX:providerVersion}                     |
      | template           | openai                                     |
      | spec.context       | ${CTX:providerContext}                     |
      | spec.upstream.url  | ${CTX:captureUpstream}/${CTX:providerName} |
      | accessControl.mode | allow_all                                  |
      | spec.policies      | [{"name":"model-access-control","version":"v0","paths":[{"path":"/chat/completions","methods":["POST"],"params":{"access":{"mode":"allow","models":["gpt-4o","gpt-4o-mini"]},"fallback":{"mappingPatterns":[{"fromPattern":"legacy-(.*)","to":"$1"}]}}}]}] |
    Then the response status code should be 201

    # The target the capture group builds is permitted: redirected to it.
    When I send a "POST" request to "${CTX:providerContext}/chat/completions" until status 200 with body:
      """
      {"model":"legacy-gpt-4o-mini","messages":[{"role":"user","content":"Hello"}]}
      """
    Then the response body should contain "gpt-4o-mini"
    And the response body should not contain "legacy-"

    # The target is not permitted, so the client cannot name any model through the fallback.
    When I send a "POST" request to "${CTX:providerContext}/chat/completions" with body:
      """
      {"model":"legacy-llama-3","messages":[{"role":"user","content":"Hello"}]}
      """
    Then the response should match the expected error response "model-access-control-denied"
    And the response body should not contain "llama-3"

    # The capture group is empty, so the fallback has no model to send.
    When I send a "POST" request to "${CTX:providerContext}/chat/completions" with body:
      """
      {"model":"legacy-","messages":[{"role":"user","content":"Hello"}]}
      """
    Then the response should match the expected error response "model-access-control-routing-error"

    When I delete the LLM provider "${CTX:providerName}"
    Then the response should be successful
