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

@llm-header-router
Feature: LLM header router
  As an API consumer
  I want a request header to choose which provider of an LLM proxy serves my request
  So that one proxy can front several providers

  Each provider forwards to the capture service under its own path. The capture service echoes
  the request it received, so the "path" field of the response shows which provider served it.

  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"
    And I resolve the "capture" service URL at "" and store it as "captureUpstream"

  Scenario: The header selects a mapped provider and a missing header uses the primary provider
    Given I generate a unique resource name from "lhr-map-primary" and store it as "primaryName"
    And I generate a unique API context from "/lhr-map-primary" and store it as "primaryContext"
    And I generate a unique resource name from "lhr-map-beta" and store it as "betaName"
    And I generate a unique API context from "/lhr-map-beta" and store it as "betaContext"
    And I generate a unique resource name from "lhr-map-gamma" and store it as "gammaName"
    And I generate a unique API context from "/lhr-map-gamma" and store it as "gammaContext"
    And I generate a unique resource name from "lhr-map-proxy" and store it as "proxyName"
    And I generate a unique API context from "/lhr-map-proxy" and store it as "proxyContext"
    When I create LLM provider from "resources/templates/llm-provider.yaml" with values:
      | apiVersion         | ${CTX:gatewaySpecVersion}      |
      | name               | ${CTX:primaryName}             |
      | displayName        | LHR-Map-Primary                |
      | version            | v1.0                           |
      | template           | openai                         |
      | spec.context       | ${CTX:primaryContext}          |
      | spec.upstream.url  | ${CTX:captureUpstream}/primary |
      | accessControl.mode | allow_all                      |
    Then the response status code should be 201
    When I create LLM provider from "resources/templates/llm-provider.yaml" with values:
      | apiVersion         | ${CTX:gatewaySpecVersion}   |
      | name               | ${CTX:betaName}             |
      | displayName        | LHR-Map-Beta                |
      | version            | v1.0                        |
      | template           | openai                      |
      | spec.context       | ${CTX:betaContext}          |
      | spec.upstream.url  | ${CTX:captureUpstream}/beta |
      | accessControl.mode | allow_all                   |
    Then the response status code should be 201
    When I create LLM provider from "resources/templates/llm-provider.yaml" with values:
      | apiVersion         | ${CTX:gatewaySpecVersion}    |
      | name               | ${CTX:gammaName}             |
      | displayName        | LHR-Map-Gamma                |
      | version            | v1.0                         |
      | template           | openai                       |
      | spec.context       | ${CTX:gammaContext}          |
      | spec.upstream.url  | ${CTX:captureUpstream}/gamma |
      | accessControl.mode | allow_all                    |
    Then the response status code should be 201
    When I create LLM proxy from "resources/templates/llm-proxy.yaml" with values:
      | apiVersion               | ${CTX:gatewaySpecVersion}                                                                                                                                                                                                              |
      | name                     | ${CTX:proxyName}                                                                                                                                                                                                                       |
      | displayName              | LHR-Map-Proxy                                                                                                                                                                                                                          |
      | version                  | v1.0                                                                                                                                                                                                                                   |
      | context                  | ${CTX:proxyContext}                                                                                                                                                                                                                    |
      | provider.id              | ${CTX:primaryName}                                                                                                                                                                                                                     |
      | spec.additionalProviders | [{"id":"${CTX:betaName}","as":"beta-provider"},{"id":"${CTX:gammaName}","as":"gamma-provider"}]                                                                                                                                          |
      | spec.policies            | [{"name":"llm-header-router","version":"v0","paths":[{"path":"/chat/completions","methods":["POST"],"params":{"mappings":[{"headerValue":"beta","provider":"beta-provider"},{"headerValue":"gamma","provider":"gamma-provider"}]}}]}] |
    Then the response status code should be 201
    # No x-provider header and no defaultProvider: the primary provider serves the request.
    And I send a "POST" request to "${CTX:proxyContext}/chat/completions" until status 200 with body:
      """
      {"model":"gpt-4o","messages":[{"role":"user","content":"Hello"}]}
      """
    And the JSON response field "path" should be "/primary/chat/completions"
    When I set header "x-provider" to "beta"
    And I send a "POST" request to "${CTX:proxyContext}/chat/completions" with body:
      """
      {"model":"gpt-4o","messages":[{"role":"user","content":"Hello"}]}
      """
    Then the response status code should be 200
    And the JSON response field "path" should be "/beta/chat/completions"
    # Header values match case-insensitively, with surrounding whitespace trimmed.
    When I set header "x-provider" to " GAMMA "
    And I send a "POST" request to "${CTX:proxyContext}/chat/completions" with body:
      """
      {"model":"gpt-4o","messages":[{"role":"user","content":"Hello"}]}
      """
    Then the response status code should be 200
    And the JSON response field "path" should be "/gamma/chat/completions"
    # A value with no mapping and no defaultProvider falls back to the primary provider.
    When I set header "x-provider" to "unknown"
    And I send a "POST" request to "${CTX:proxyContext}/chat/completions" with body:
      """
      {"model":"gpt-4o","messages":[{"role":"user","content":"Hello"}]}
      """
    Then the response status code should be 200
    And the JSON response field "path" should be "/primary/chat/completions"
    When I delete the LLM proxy "${CTX:proxyName}"
    Then the response should be successful
    When I delete the LLM provider "${CTX:gammaName}"
    Then the response should be successful
    When I delete the LLM provider "${CTX:betaName}"
    Then the response should be successful
    When I delete the LLM provider "${CTX:primaryName}"
    Then the response should be successful

  Scenario: A custom header name is read and the default provider covers missing and unmapped values
    Given I generate a unique resource name from "lhr-default-primary" and store it as "primaryName"
    And I generate a unique API context from "/lhr-default-primary" and store it as "primaryContext"
    And I generate a unique resource name from "lhr-default-beta" and store it as "betaName"
    And I generate a unique API context from "/lhr-default-beta" and store it as "betaContext"
    And I generate a unique resource name from "lhr-default-gamma" and store it as "gammaName"
    And I generate a unique API context from "/lhr-default-gamma" and store it as "gammaContext"
    And I generate a unique resource name from "lhr-default-proxy" and store it as "proxyName"
    And I generate a unique API context from "/lhr-default-proxy" and store it as "proxyContext"
    When I create LLM provider from "resources/templates/llm-provider.yaml" with values:
      | apiVersion         | ${CTX:gatewaySpecVersion}      |
      | name               | ${CTX:primaryName}             |
      | displayName        | LHR-Default-Primary            |
      | version            | v1.0                           |
      | template           | openai                         |
      | spec.context       | ${CTX:primaryContext}          |
      | spec.upstream.url  | ${CTX:captureUpstream}/primary |
      | accessControl.mode | allow_all                      |
    Then the response status code should be 201
    When I create LLM provider from "resources/templates/llm-provider.yaml" with values:
      | apiVersion         | ${CTX:gatewaySpecVersion}   |
      | name               | ${CTX:betaName}             |
      | displayName        | LHR-Default-Beta            |
      | version            | v1.0                        |
      | template           | openai                      |
      | spec.context       | ${CTX:betaContext}          |
      | spec.upstream.url  | ${CTX:captureUpstream}/beta |
      | accessControl.mode | allow_all                   |
    Then the response status code should be 201
    When I create LLM provider from "resources/templates/llm-provider.yaml" with values:
      | apiVersion         | ${CTX:gatewaySpecVersion}    |
      | name               | ${CTX:gammaName}             |
      | displayName        | LHR-Default-Gamma            |
      | version            | v1.0                         |
      | template           | openai                       |
      | spec.context       | ${CTX:gammaContext}          |
      | spec.upstream.url  | ${CTX:captureUpstream}/gamma |
      | accessControl.mode | allow_all                    |
    Then the response status code should be 201
    When I create LLM proxy from "resources/templates/llm-proxy.yaml" with values:
      | apiVersion               | ${CTX:gatewaySpecVersion}                                                                                                                                                                                                                  |
      | name                     | ${CTX:proxyName}                                                                                                                                                                                                                           |
      | displayName              | LHR-Default-Proxy                                                                                                                                                                                                                          |
      | version                  | v1.0                                                                                                                                                                                                                                       |
      | context                  | ${CTX:proxyContext}                                                                                                                                                                                                                        |
      | provider.id              | ${CTX:primaryName}                                                                                                                                                                                                                         |
      | spec.additionalProviders | [{"id":"${CTX:betaName}","as":"beta-provider"},{"id":"${CTX:gammaName}","as":"gamma-provider"}]                                                                                                                                              |
      | spec.policies            | [{"name":"llm-header-router","version":"v0","paths":[{"path":"/chat/completions","methods":["POST"],"params":{"headerName":"x-llm-target","defaultProvider":"gamma-provider","mappings":[{"headerValue":"beta","provider":"beta-provider"}]}}]}] |
    Then the response status code should be 201
    # No header: the default provider serves the request instead of the primary one.
    And I send a "POST" request to "${CTX:proxyContext}/chat/completions" until status 200 with body:
      """
      {"model":"gpt-4o","messages":[{"role":"user","content":"Hello"}]}
      """
    And the JSON response field "path" should be "/gamma/chat/completions"
    # The default x-provider header is ignored when headerName names another header.
    When I set header "x-provider" to "beta"
    And I send a "POST" request to "${CTX:proxyContext}/chat/completions" with body:
      """
      {"model":"gpt-4o","messages":[{"role":"user","content":"Hello"}]}
      """
    Then the response status code should be 200
    And the JSON response field "path" should be "/gamma/chat/completions"
    When I set header "x-llm-target" to "beta"
    And I send a "POST" request to "${CTX:proxyContext}/chat/completions" with body:
      """
      {"model":"gpt-4o","messages":[{"role":"user","content":"Hello"}]}
      """
    Then the response status code should be 200
    And the JSON response field "path" should be "/beta/chat/completions"
    When I set header "x-llm-target" to "unknown"
    And I send a "POST" request to "${CTX:proxyContext}/chat/completions" with body:
      """
      {"model":"gpt-4o","messages":[{"role":"user","content":"Hello"}]}
      """
    Then the response status code should be 200
    And the JSON response field "path" should be "/gamma/chat/completions"
    When I delete the LLM proxy "${CTX:proxyName}"
    Then the response should be successful
    When I delete the LLM provider "${CTX:gammaName}"
    Then the response should be successful
    When I delete the LLM provider "${CTX:betaName}"
    Then the response should be successful
    When I delete the LLM provider "${CTX:primaryName}"
    Then the response should be successful

  Scenario: The selected provider drives which translator runs
    Given I generate a unique resource name from "lhr-tr-primary" and store it as "primaryName"
    And I generate a unique API context from "/lhr-tr-primary" and store it as "primaryContext"
    And I generate a unique resource name from "lhr-tr-openai" and store it as "openaiName"
    And I generate a unique API context from "/lhr-tr-openai" and store it as "openaiContext"
    And I generate a unique resource name from "lhr-tr-anthropic" and store it as "anthropicName"
    And I generate a unique API context from "/lhr-tr-anthropic" and store it as "anthropicContext"
    And I generate a unique resource name from "lhr-tr-proxy" and store it as "proxyName"
    And I generate a unique API context from "/lhr-tr-proxy" and store it as "proxyContext"
    When I create LLM provider from "resources/templates/llm-provider.yaml" with values:
      | apiVersion         | ${CTX:gatewaySpecVersion}      |
      | name               | ${CTX:primaryName}             |
      | displayName        | LHR-Translator-Primary         |
      | version            | v1.0                           |
      | template           | openai                         |
      | spec.context       | ${CTX:primaryContext}          |
      | spec.upstream.url  | ${CTX:captureUpstream}/primary |
      | accessControl.mode | allow_all                      |
    Then the response status code should be 201
    When I create LLM provider from "resources/templates/llm-provider.yaml" with values:
      | apiVersion         | ${CTX:gatewaySpecVersion}     |
      | name               | ${CTX:openaiName}             |
      | displayName        | LHR-Translator-OpenAI         |
      | version            | v1.0                          |
      | template           | openai                        |
      | spec.context       | ${CTX:openaiContext}          |
      | spec.upstream.url  | ${CTX:captureUpstream}/openai |
      | accessControl.mode | allow_all                     |
    Then the response status code should be 201
    When I create LLM provider from "resources/templates/llm-provider.yaml" with values:
      | apiVersion         | ${CTX:gatewaySpecVersion}        |
      | name               | ${CTX:anthropicName}             |
      | displayName        | LHR-Translator-Anthropic         |
      | version            | v1.0                             |
      | template           | openai                           |
      | spec.context       | ${CTX:anthropicContext}          |
      | spec.upstream.url  | ${CTX:captureUpstream}/anthropic |
      | accessControl.mode | allow_all                        |
    Then the response status code should be 201
    When I create LLM proxy from "resources/templates/llm-proxy.yaml" with values:
      | apiVersion               | ${CTX:gatewaySpecVersion}                                                                                                                                                                                                                                                                                                                                                                                 |
      | name                     | ${CTX:proxyName}                                                                                                                                                                                                                                                                                                                                                                                          |
      | displayName              | LHR-Translator-Proxy                                                                                                                                                                                                                                                                                                                                                                                      |
      | version                  | v1.0                                                                                                                                                                                                                                                                                                                                                                                                      |
      | context                  | ${CTX:proxyContext}                                                                                                                                                                                                                                                                                                                                                                                       |
      | provider.id              | ${CTX:primaryName}                                                                                                                                                                                                                                                                                                                                                                                        |
      | spec.additionalProviders | [{"id":"${CTX:openaiName}","as":"openai-provider"},{"id":"${CTX:anthropicName}","as":"anthropic-provider"}]                                                                                                                                                                                                                                                                                                 |
      | spec.policies            | [{"name":"llm-header-router","version":"v0","paths":[{"path":"/chat/completions","methods":["POST"],"params":{"mappings":[{"headerValue":"openai","provider":"openai-provider"},{"headerValue":"anthropic","provider":"anthropic-provider"}]}}]},{"name":"openai-to-anthropic-transformer","version":"v0","paths":[{"path":"/chat/completions","methods":["POST"],"params":{"providerId":"anthropic-provider","model":"claude-fallback-model"}}]}] |
    Then the response status code should be 201
    # The openai provider is selected, so the anthropic translator sees another provider's
    # selection and leaves the request untouched.
    When I set header "x-provider" to "openai"
    And I send a "POST" request to "${CTX:proxyContext}/chat/completions" until status 200 with body:
      """
      {"model":"gpt-4o","messages":[{"role":"user","content":"lhr passthrough"}]}
      """
    Then the JSON response field "path" should be "/openai/chat/completions"
    And the JSON response field "body" should contain "lhr passthrough"
    And the JSON response field "body" should contain "gpt-4o"
    # Selecting the anthropic provider makes its translator rewrite the request.
    When I set header "x-provider" to "anthropic"
    And I send a "POST" request to "${CTX:proxyContext}/chat/completions" with body:
      """
      {"messages":[{"role":"user","content":"lhr translated"}]}
      """
    Then the response status code should be 200
    When I send a "GET" request to the "capture" service at "/test/captured?path=/anthropic/v1/messages"
    Then the response status code should be 200
    And the JSON response field "path" should be "/anthropic/v1/messages"
    And the JSON response field "headers.Anthropic-Version[0]" should be "2023-06-01"
    And the JSON response field "body" should contain "claude-fallback-model"
    And the JSON response field "body" should contain "lhr translated"
    And the JSON response field "body" should contain "max_tokens"
    When I delete the LLM proxy "${CTX:proxyName}"
    Then the response should be successful
    When I delete the LLM provider "${CTX:anthropicName}"
    Then the response should be successful
    When I delete the LLM provider "${CTX:openaiName}"
    Then the response should be successful
    When I delete the LLM provider "${CTX:primaryName}"
    Then the response should be successful
