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

@model-access-control
Feature: Model access control
  As an API developer
  I want requests for models outside the access rule rejected or sent to an approved fallback
  So that clients reach only the models I permit, before any provider call

  Every provider here forwards to the capture service, which answers with the request it received
  and remembers it per path. Reading it back proves what the provider was sent, and a 204 from the
  read-back proves the provider was not called at all.

  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"
    And I resolve the "capture" service URL at "" and store it as "captureUpstream"

  Scenario: A permitted model passes unchanged, a mapped model is rewritten and a denied model never reaches the provider
    Given I generate a unique resource name from "mac-basic-provider" and store it as "providerName"
    And I generate a unique value from "mac-basic-provider" and store it as "providerDisplayName"
    And I generate a unique API version from "mac-basic-provider" and store it as "providerVersion"
    And I generate a unique API context from "/mac-basic-provider" and store it as "providerContext"
    And I generate a unique resource name from "mac-basic-proxy" and store it as "proxyName"
    And I generate a unique value from "mac-basic-proxy" and store it as "proxyDisplayName"
    And I generate a unique API version from "mac-basic-proxy" and store it as "proxyVersion"
    And I generate a unique API context from "/mac-basic-proxy" and store it as "proxyContext"
    When I create LLM provider from "resources/templates/llm-provider.yaml" with values:
      | apiVersion         | ${CTX:gatewaySpecVersion}                  |
      | name               | ${CTX:providerName}                        |
      | displayName        | ${CTX:providerDisplayName}                 |
      | version            | ${CTX:providerVersion}                     |
      | template           | openai                                     |
      | spec.context       | ${CTX:providerContext}                     |
      | spec.upstream.url  | ${CTX:captureUpstream}/${CTX:providerName} |
      | accessControl.mode | allow_all                                  |
    Then the response status code should be 201
    When I create LLM proxy from "resources/templates/llm-proxy.yaml" with values:
      | apiVersion    | ${CTX:gatewaySpecVersion} |
      | name          | ${CTX:proxyName}          |
      | displayName   | ${CTX:proxyDisplayName}   |
      | version       | ${CTX:proxyVersion}       |
      | context       | ${CTX:proxyContext}       |
      | provider.id   | ${CTX:providerName}       |
      | spec.policies | [{"name":"model-access-control","version":"v0","paths":[{"path":"/chat/completions","methods":["POST"],"params":{"access":{"mode":"allow","models":["gpt-4o"]},"fallback":{"mappingPatterns":[{"fromPattern":"old-model","to":"gpt-4o"}]}}}]}] |
    Then the response status code should be 201

    # Denied, no mapping: the generic error, and the provider never sees the request.
    When I send a "POST" request to "${CTX:proxyContext}/chat/completions" until status 404 and the response body contains "model_not_found" with body:
      """
      {"model":"unlisted-model","messages":[{"role":"user","content":"Hello"}]}
      """
    Then the response should match the expected error response "model-access-control-denied"
    And the response body should not contain "unlisted-model"
    And the response body should not contain "gpt-4o"
    When I send a "GET" request to the "capture" service at "/test/captured?path=/${CTX:providerName}/chat/completions"
    Then the response status code should be 204

    # Permitted: forwarded byte for byte, including the number's trailing zero.
    When I send a "POST" request to "${CTX:proxyContext}/chat/completions" with body:
      """
      {"model":"gpt-4o","messages":[{"role":"user","content":"keep  these   bytes"}],"temperature":0.70}
      """
    Then the response status code should be 200
    When I send a "GET" request to the "capture" service at "/test/captured?path=/${CTX:providerName}/chat/completions"
    Then the response status code should be 200
    And the JSON response field "body" should be:
      """
      {"model":"gpt-4o","messages":[{"role":"user","content":"keep  these   bytes"}],"temperature":0.70}
      """

    # Listed models ignore case: also forwarded unchanged.
    When I send a "POST" request to "${CTX:proxyContext}/chat/completions" with body:
      """
      {"model":"GPT-4o","messages":[{"role":"user","content":"Hello"}]}
      """
    Then the response status code should be 200
    When I send a "GET" request to the "capture" service at "/test/captured?path=/${CTX:providerName}/chat/completions"
    Then the JSON response field "body" should be:
      """
      {"model":"GPT-4o","messages":[{"role":"user","content":"Hello"}]}
      """

    # Denied, mapped: the provider receives the fallback model.
    When I send a "POST" request to "${CTX:proxyContext}/chat/completions" with body:
      """
      {"model":"old-model","messages":[{"role":"user","content":"Hello"}]}
      """
    Then the response status code should be 200
    When I send a "GET" request to the "capture" service at "/test/captured?path=/${CTX:providerName}/chat/completions"
    Then the response status code should be 200
    And the response body should contain "gpt-4o"
    And the response body should not contain "old-model"
    And the response body should contain "Hello"

    # A route without the policy is not governed by it.
    When I send a "POST" request to "${CTX:proxyContext}/embeddings" with body:
      """
      {"model":"unlisted-model","input":"Hello"}
      """
    Then the response status code should be 200
    And the response body should contain "unlisted-model"

    When I delete the LLM proxy "${CTX:proxyName}"
    Then the response should be successful
    When I delete the LLM provider "${CTX:providerName}"
    Then the response should be successful

  Scenario: Deny mode, model and mapping patterns, and a pattern-only denial
    Given I generate a unique resource name from "mac-pattern-provider" and store it as "providerName"
    And I generate a unique value from "mac-pattern-provider" and store it as "providerDisplayName"
    And I generate a unique API version from "mac-pattern-provider" and store it as "providerVersion"
    And I generate a unique API context from "/mac-pattern-provider" and store it as "providerContext"
    And I generate a unique resource name from "mac-pattern-proxy" and store it as "proxyName"
    And I generate a unique value from "mac-pattern-proxy" and store it as "proxyDisplayName"
    And I generate a unique API version from "mac-pattern-proxy" and store it as "proxyVersion"
    And I generate a unique API context from "/mac-pattern-proxy" and store it as "proxyContext"
    When I create LLM provider from "resources/templates/llm-provider.yaml" with values:
      | apiVersion         | ${CTX:gatewaySpecVersion}                  |
      | name               | ${CTX:providerName}                        |
      | displayName        | ${CTX:providerDisplayName}                 |
      | version            | ${CTX:providerVersion}                     |
      | template           | openai                                     |
      | spec.context       | ${CTX:providerContext}                     |
      | spec.upstream.url  | ${CTX:captureUpstream}/${CTX:providerName} |
      | accessControl.mode | allow_all                                  |
    Then the response status code should be 201
    # Every model is permitted except gpt-4-32k and names ending in -preview. A restricted
    # claude-*-preview falls back to the stable name; gpt-4-32k falls back to gpt-4o. Mapping
    # patterns are case-sensitive unless they start with (?i), unlike the access rule.
    When I create LLM proxy from "resources/templates/llm-proxy.yaml" with values:
      | apiVersion    | ${CTX:gatewaySpecVersion} |
      | name          | ${CTX:proxyName}          |
      | displayName   | ${CTX:proxyDisplayName}   |
      | version       | ${CTX:proxyVersion}       |
      | context       | ${CTX:proxyContext}       |
      | provider.id   | ${CTX:providerName}       |
      | spec.policies | [{"name":"model-access-control","version":"v0","paths":[{"path":"/chat/completions","methods":["POST"],"params":{"access":{"mode":"deny","models":["gpt-4-32k"],"modelPatterns":[".*-preview"]},"fallback":{"mappingPatterns":[{"fromPattern":"(?i)gpt-4-32k","to":"gpt-4o"},{"fromPattern":"claude-([a-z]+)-preview","to":"claude-$1-stable"}]}}}]}] |
    Then the response status code should be 201

    When I send a "POST" request to "${CTX:proxyContext}/chat/completions" until status 404 and the response body contains "model_not_found" with body:
      """
      {"model":"gpt-5-preview","messages":[{"role":"user","content":"Hello"}]}
      """
    Then the response should match the expected error response "model-access-control-denied"
    When I send a "GET" request to the "capture" service at "/test/captured?path=/${CTX:providerName}/chat/completions"
    Then the response status code should be 204

    When I send a "POST" request to "${CTX:proxyContext}/chat/completions" with body:
      """
      {"model":"claude-opus-preview","messages":[{"role":"user","content":"Hello"}]}
      """
    Then the response status code should be 200
    And the response body should contain "claude-opus-stable"
    And the response body should not contain "claude-opus-preview"

    When I send a "POST" request to "${CTX:proxyContext}/chat/completions" with body:
      """
      {"model":"GPT-4-32K","messages":[{"role":"user","content":"Hello"}]}
      """
    Then the response status code should be 200
    And the response body should contain "gpt-4o"

    # The pattern must match the whole name, so this one is permitted and left alone.
    When I send a "POST" request to "${CTX:proxyContext}/chat/completions" with body:
      """
      {"model":"claude-preview-tuned","messages":[{"role":"user","content":"Hello"}]}
      """
    Then the response status code should be 200
    When I send a "GET" request to the "capture" service at "/test/captured?path=/${CTX:providerName}/chat/completions"
    Then the JSON response field "body" should be:
      """
      {"model":"claude-preview-tuned","messages":[{"role":"user","content":"Hello"}]}
      """

    When I delete the LLM proxy "${CTX:proxyName}"
    Then the response should be successful
    When I delete the LLM provider "${CTX:providerName}"
    Then the response should be successful

  Scenario: A request without one usable model is rejected before the provider call
    Given I generate a unique resource name from "mac-missing-provider" and store it as "providerName"
    And I generate a unique value from "mac-missing-provider" and store it as "providerDisplayName"
    And I generate a unique API version from "mac-missing-provider" and store it as "providerVersion"
    And I generate a unique API context from "/mac-missing-provider" and store it as "providerContext"
    And I generate a unique resource name from "mac-missing-proxy" and store it as "proxyName"
    And I generate a unique value from "mac-missing-proxy" and store it as "proxyDisplayName"
    And I generate a unique API version from "mac-missing-proxy" and store it as "proxyVersion"
    And I generate a unique API context from "/mac-missing-proxy" and store it as "proxyContext"
    When I create LLM provider from "resources/templates/llm-provider.yaml" with values:
      | apiVersion         | ${CTX:gatewaySpecVersion}                  |
      | name               | ${CTX:providerName}                        |
      | displayName        | ${CTX:providerDisplayName}                 |
      | version            | ${CTX:providerVersion}                     |
      | template           | openai                                     |
      | spec.context       | ${CTX:providerContext}                     |
      | spec.upstream.url  | ${CTX:captureUpstream}/${CTX:providerName} |
      | accessControl.mode | allow_all                                  |
    Then the response status code should be 201
    When I create LLM proxy from "resources/templates/llm-proxy.yaml" with values:
      | apiVersion    | ${CTX:gatewaySpecVersion} |
      | name          | ${CTX:proxyName}          |
      | displayName   | ${CTX:proxyDisplayName}   |
      | version       | ${CTX:proxyVersion}       |
      | context       | ${CTX:proxyContext}       |
      | provider.id   | ${CTX:providerName}       |
      | spec.policies | [{"name":"model-access-control","version":"v0","paths":[{"path":"/chat/completions","methods":["POST"],"params":{"access":{"mode":"allow","models":["gpt-4o"]}}}]}] |
    Then the response status code should be 201

    When I send a "POST" request to "${CTX:proxyContext}/chat/completions" until status 400 with body:
      """
      {"messages":[{"role":"user","content":"Hello"}]}
      """
    Then the response should match the expected error response "model-access-control-invalid-model"

    When I send a "POST" request to "${CTX:proxyContext}/chat/completions" with body:
      """
      {"model":"","messages":[]}
      """
    Then the response should match the expected error response "model-access-control-invalid-model"

    When I send a "POST" request to "${CTX:proxyContext}/chat/completions" with body:
      """
      {"model":"gpt-4o","messages":[
      """
    Then the response should match the expected error response "model-access-control-invalid-model"

    # Two model keys: the gateway and the provider could read different ones.
    When I send a "POST" request to "${CTX:proxyContext}/chat/completions" with body:
      """
      {"model":"gpt-4o","model":"unlisted-model","messages":[]}
      """
    Then the response should match the expected error response "model-access-control-invalid-model"

    When I send a "GET" request to the "capture" service at "/test/captured?path=/${CTX:providerName}/chat/completions"
    Then the response status code should be 204

    When I delete the LLM proxy "${CTX:proxyName}"
    Then the response should be successful
    When I delete the LLM provider "${CTX:providerName}"
    Then the response should be successful

  Scenario: onMissingModel skip forwards a model-less route but still rejects a JSON request without a model
    Given I generate a unique resource name from "mac-skip-provider" and store it as "providerName"
    And I generate a unique value from "mac-skip-provider" and store it as "providerDisplayName"
    And I generate a unique API version from "mac-skip-provider" and store it as "providerVersion"
    And I generate a unique API context from "/mac-skip-provider" and store it as "providerContext"
    And I generate a unique resource name from "mac-skip-proxy" and store it as "proxyName"
    And I generate a unique value from "mac-skip-proxy" and store it as "proxyDisplayName"
    And I generate a unique API version from "mac-skip-proxy" and store it as "proxyVersion"
    And I generate a unique API context from "/mac-skip-proxy" and store it as "proxyContext"
    When I create LLM provider from "resources/templates/llm-provider.yaml" with values:
      | apiVersion         | ${CTX:gatewaySpecVersion}                  |
      | name               | ${CTX:providerName}                        |
      | displayName        | ${CTX:providerDisplayName}                 |
      | version            | ${CTX:providerVersion}                     |
      | template           | openai                                     |
      | spec.context       | ${CTX:providerContext}                     |
      | spec.upstream.url  | ${CTX:captureUpstream}/${CTX:providerName} |
      | accessControl.mode | allow_all                                  |
    Then the response status code should be 201
    When I create LLM proxy from "resources/templates/llm-proxy.yaml" with values:
      | apiVersion    | ${CTX:gatewaySpecVersion} |
      | name          | ${CTX:proxyName}          |
      | displayName   | ${CTX:proxyDisplayName}   |
      | version       | ${CTX:proxyVersion}       |
      | context       | ${CTX:proxyContext}       |
      | provider.id   | ${CTX:providerName}       |
      | spec.policies | [{"name":"model-access-control","version":"v0","paths":[{"path":"/models","methods":["GET"],"params":{"access":{"mode":"allow","models":["gpt-4o"],"onMissingModel":"skip"}}},{"path":"/chat/completions","methods":["POST"],"params":{"access":{"mode":"allow","models":["gpt-4o"],"onMissingModel":"skip"}}}]}] |
    Then the response status code should be 201

    When I send a "GET" request to "${CTX:proxyContext}/models" until status 200
    Then the response body should contain "/${CTX:providerName}/models"

    When I send a "POST" request to "${CTX:proxyContext}/chat/completions" until status 400 with body:
      """
      {"messages":[{"role":"user","content":"Hello"}]}
      """
    Then the response should match the expected error response "model-access-control-invalid-model"

    # skip never lets a model through that the rule denies.
    When I send a "POST" request to "${CTX:proxyContext}/chat/completions" with body:
      """
      {"model":"unlisted-model","messages":[]}
      """
    Then the response should match the expected error response "model-access-control-denied"
    When I send a "GET" request to the "capture" service at "/test/captured?path=/${CTX:providerName}/chat/completions"
    Then the response status code should be 204

    When I delete the LLM proxy "${CTX:proxyName}"
    Then the response should be successful
    When I delete the LLM provider "${CTX:providerName}"
    Then the response should be successful

  Scenario: Buffered and streamed responses keep the provider's model name after a fallback
    Given I generate a unique resource name from "mac-response-provider" and store it as "providerName"
    And I generate a unique value from "mac-response-provider" and store it as "providerDisplayName"
    And I generate a unique API version from "mac-response-provider" and store it as "providerVersion"
    And I generate a unique API context from "/mac-response-provider" and store it as "providerContext"
    And I generate a unique resource name from "mac-response-proxy" and store it as "proxyName"
    And I generate a unique value from "mac-response-proxy" and store it as "proxyDisplayName"
    And I generate a unique API version from "mac-response-proxy" and store it as "proxyVersion"
    And I generate a unique API context from "/mac-response-proxy" and store it as "proxyContext"
    # The OpenAI mock answers with the model it was sent, buffered or streamed.
    When I create LLM provider from "resources/templates/llm-provider.yaml" with values:
      | apiVersion         | ${CTX:gatewaySpecVersion}       |
      | name               | ${CTX:providerName}             |
      | displayName        | ${CTX:providerDisplayName}      |
      | version            | ${CTX:providerVersion}          |
      | template           | openai                          |
      | spec.context       | ${CTX:providerContext}          |
      | spec.upstream.url  | http://testbench:3008/openai/v1 |
      | accessControl.mode | allow_all                       |
    Then the response status code should be 201
    When I create LLM proxy from "resources/templates/llm-proxy.yaml" with values:
      | apiVersion    | ${CTX:gatewaySpecVersion} |
      | name          | ${CTX:proxyName}          |
      | displayName   | ${CTX:proxyDisplayName}   |
      | version       | ${CTX:proxyVersion}       |
      | context       | ${CTX:proxyContext}       |
      | provider.id   | ${CTX:providerName}       |
      | spec.policies | [{"name":"model-access-control","version":"v0","paths":[{"path":"/chat/completions","methods":["POST"],"params":{"access":{"mode":"allow","models":["gpt-4o"]},"fallback":{"mappingPatterns":[{"fromPattern":"friendly-model","to":"gpt-4o"}]}}}]}] |
    Then the response status code should be 201

    When I send a "POST" request to "${CTX:proxyContext}/chat/completions" until status 200 with body:
      """
      {"model":"friendly-model","messages":[{"role":"user","content":"Hello"}]}
      """
    Then the JSON response field "model" should be "gpt-4o"
    And the response body should not contain "friendly-model"

    When I send a "POST" request to "${CTX:proxyContext}/chat/completions" with body:
      """
      {"model":"friendly-model","stream":true,"messages":[{"role":"user","content":"Hello"}]}
      """
    Then the response status code should be 200
    And the response header "content-type" should contain "text/event-stream"
    And the response body should contain "gpt-4o"
    And the response body should contain "[DONE]"
    And the response body should not contain "friendly-model"

    When I delete the LLM proxy "${CTX:proxyName}"
    Then the response should be successful
    When I delete the LLM provider "${CTX:providerName}"
    Then the response should be successful
