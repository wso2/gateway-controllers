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

  # Mistral streams in the OpenAI chunk format already, so the event stream is forwarded as is.
  Scenario: A Mistral event stream is passed through unchanged
    Given I generate a unique resource name from "o2m-stream-provider" and store it as "providerName"
    And I generate a unique API context from "/o2m-stream-provider" and store it as "providerContext"
    And I generate a unique resource name from "o2m-stream-proxy" and store it as "proxyName"
    And I generate a unique API context from "/o2m-stream-proxy" and store it as "proxyContext"
    When I create LLM provider from "resources/templates/llm-provider.yaml" with values:
      | apiVersion         | ${CTX:gatewaySpecVersion}     |
      | name               | ${CTX:providerName}           |
      | displayName        | O2M-Stream-Provider           |
      | version            | v1.0                          |
      | template           | openai                        |
      | spec.context       | ${CTX:providerContext}        |
      | spec.upstream.url  | http://testbench:3008/mistral |
      | accessControl.mode | allow_all                     |
    Then the response status code should be 201
    When I create LLM proxy from "resources/templates/llm-proxy.yaml" with values:
      | apiVersion    | ${CTX:gatewaySpecVersion}                                                                                                                                 |
      | name          | ${CTX:proxyName}                                                                                                                                          |
      | displayName   | O2M-Stream-Proxy                                                                                                                                          |
      | version       | v1.0                                                                                                                                                      |
      | context       | ${CTX:proxyContext}                                                                                                                                       |
      | provider.id   | ${CTX:providerName}                                                                                                                                       |
      | spec.policies | [{"name":"openai-to-mistral-transformer","version":"v0","paths":[{"path":"/chat/completions","methods":["POST"],"params":{"model":"mistral-large-latest"}}]}] |
    Then the response status code should be 201
    And I send a "POST" request to "${CTX:proxyContext}/chat/completions" until status 200 with body:
      """
      {"model":"mistral-small-latest","messages":[{"role":"user","content":"Hello"}]}
      """
    When I send a "POST" request to "${CTX:proxyContext}/chat/completions" with body:
      """
      {"model":"mistral-small-latest","stream":true,"messages":[{"role":"user","content":"Hello"}]}
      """
    Then the response status code should be 200
    And the response header "content-type" should contain "text/event-stream"
    And the response body should contain "chat.completion.chunk"
    And the response body should contain "mistral-small-latest"
    And the response body should contain "streamed "
    And the response body should contain "data: [DONE]"
    When I delete the LLM proxy "${CTX:proxyName}"
    Then the response should be successful
    When I delete the LLM provider "${CTX:providerName}"
    Then the response should be successful

  # The testbench scripted path answers with the reply the request names in x_testbench_reply,
  # which the translator forwards untouched, so each request controls what Mistral returns.
  Scenario: Mistral replies are backfilled with the model or passed through when not JSON
    Given I generate a unique resource name from "o2m-scripted-provider" and store it as "providerName"
    And I generate a unique API context from "/o2m-scripted-provider" and store it as "providerContext"
    And I generate a unique resource name from "o2m-scripted-proxy" and store it as "proxyName"
    And I generate a unique API context from "/o2m-scripted-proxy" and store it as "proxyContext"
    When I create LLM provider from "resources/templates/llm-provider.yaml" with values:
      | apiVersion         | ${CTX:gatewaySpecVersion}              |
      | name               | ${CTX:providerName}                    |
      | displayName        | O2M-Scripted-Provider                  |
      | version            | v1.0                                   |
      | template           | openai                                 |
      | spec.context       | ${CTX:providerContext}                 |
      | spec.upstream.url  | http://testbench:3008/scripted/mistral |
      | accessControl.mode | allow_all                              |
    Then the response status code should be 201
    When I create LLM proxy from "resources/templates/llm-proxy.yaml" with values:
      | apiVersion    | ${CTX:gatewaySpecVersion}                                                                                                                                 |
      | name          | ${CTX:proxyName}                                                                                                                                          |
      | displayName   | O2M-Scripted-Proxy                                                                                                                                        |
      | version       | v1.0                                                                                                                                                      |
      | context       | ${CTX:proxyContext}                                                                                                                                       |
      | provider.id   | ${CTX:providerName}                                                                                                                                       |
      | spec.policies | [{"name":"openai-to-mistral-transformer","version":"v0","paths":[{"path":"/chat/completions","methods":["POST"],"params":{"model":"mistral-large-latest"}}]}] |
    Then the response status code should be 201
    # A reply without a model is reported with the model that served the request.
    And I send a "POST" request to "${CTX:proxyContext}/chat/completions" until status 200 with body:
      """
      {"model":"mistral-small-latest","messages":[{"role":"user","content":"Hello"}],"x_testbench_reply":{"body":{"id":"cmpl-scripted","object":"chat.completion","choices":[{"index":0,"message":{"role":"assistant","content":"Scripted hello"},"finish_reason":"stop"}]}}}
      """
    Then the JSON response field "model" should be "mistral-small-latest"
    And the JSON response field "choices[0].message.content" should be "Scripted hello"
    # With no model in the request either, the configured fallback model is reported.
    When I send a "POST" request to "${CTX:proxyContext}/chat/completions" with body:
      """
      {"messages":[{"role":"user","content":"Hello"}],"x_testbench_reply":{"body":{"id":"cmpl-scripted","object":"chat.completion","model":"","choices":[]}}}
      """
    Then the response status code should be 200
    And the JSON response field "model" should be "mistral-large-latest"
    # A 2xx body that is not JSON is forwarded unchanged rather than masked.
    When I send a "POST" request to "${CTX:proxyContext}/chat/completions" with body:
      """
      {"model":"mistral-small-latest","messages":[{"role":"user","content":"Hello"}],"x_testbench_reply":{"raw":"plain text from mistral","contentType":"text/plain"}}
      """
    Then the response status code should be 200
    And the response body should contain "plain text from mistral"
    # An event stream without an event-stream content type is recognised from its first bytes.
    When I send a "POST" request to "${CTX:proxyContext}/chat/completions" with body:
      """
      {"model":"mistral-small-latest","stream":true,"messages":[{"role":"user","content":"Hello"}],"x_testbench_reply":{"events":[{"id":"cmpl-sniffed","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"content":"sniffed"}}]},"data: [DONE]"],"contentType":"application/octet-stream"}}
      """
    Then the response status code should be 200
    And the response body should contain "cmpl-sniffed"
    And the response body should contain "data: [DONE]"
    When I delete the LLM proxy "${CTX:proxyName}"
    Then the response should be successful
    When I delete the LLM provider "${CTX:providerName}"
    Then the response should be successful

  Scenario: A request the policy cannot translate is rejected with 400
    Given I generate a unique resource name from "o2m-invalid-provider" and store it as "providerName"
    And I generate a unique API context from "/o2m-invalid-provider" and store it as "providerContext"
    And I generate a unique resource name from "o2m-invalid-proxy" and store it as "proxyName"
    And I generate a unique API context from "/o2m-invalid-proxy" and store it as "proxyContext"
    When I create LLM provider from "resources/templates/llm-provider.yaml" with values:
      | apiVersion         | ${CTX:gatewaySpecVersion}     |
      | name               | ${CTX:providerName}           |
      | displayName        | O2M-Invalid-Provider          |
      | version            | v1.0                          |
      | template           | openai                        |
      | spec.context       | ${CTX:providerContext}        |
      | spec.upstream.url  | http://testbench:3008/mistral |
      | accessControl.mode | allow_all                     |
    Then the response status code should be 201
    # No fallback model is configured, so the request has to name one.
    When I create LLM proxy from "resources/templates/llm-proxy.yaml" with values:
      | apiVersion    | ${CTX:gatewaySpecVersion}                                                                                                   |
      | name          | ${CTX:proxyName}                                                                                                            |
      | displayName   | O2M-Invalid-Proxy                                                                                                           |
      | version       | v1.0                                                                                                                        |
      | context       | ${CTX:proxyContext}                                                                                                         |
      | provider.id   | ${CTX:providerName}                                                                                                         |
      | spec.policies | [{"name":"openai-to-mistral-transformer","version":"v0","paths":[{"path":"/chat/completions","methods":["POST"],"params":{}}]}] |
    Then the response status code should be 201
    And I send a "POST" request to "${CTX:proxyContext}/chat/completions" until status 200 with body:
      """
      {"model":"mistral-small-latest","messages":[{"role":"user","content":"Hello"}]}
      """
    When I send a "POST" request to "${CTX:proxyContext}/chat/completions" with body:
      """
      {"messages":[{"role":"user","content":"Hello"}]}
      """
    Then the response status code should be 400
    And the JSON response field "error" should contain "either the policy configuration or request body"
    When I send a "POST" request to "${CTX:proxyContext}/chat/completions" with body:
      """
      {"model":42,"messages":[{"role":"user","content":"Hello"}]}
      """
    Then the response status code should be 400
    And the JSON response field "error" should contain "must be a string"
    When I send a "POST" request to "${CTX:proxyContext}/chat/completions" with body:
      """
      {"model":"   ","messages":[{"role":"user","content":"Hello"}]}
      """
    Then the response status code should be 400
    And the JSON response field "error" should contain "must not be blank"
    When I send a "POST" request to "${CTX:proxyContext}/chat/completions" with body:
      """
      {"model":
      """
    Then the response status code should be 400
    And the JSON response field "error" should contain "Invalid JSON in request body"
    When I delete the LLM proxy "${CTX:proxyName}"
    Then the response should be successful
    When I delete the LLM provider "${CTX:providerName}"
    Then the response should be successful

  # The fault-injection service answers the scripted statuses in order, each with a plain-text
  # body, before it forwards anything to the mock. Each status maps onto an OpenAI error type;
  # Mistral's 422 validation error is reported as invalid_request_error.
  Scenario: Upstream error statuses are returned as OpenAI error objects
    Given I generate a unique resource name from "o2m-errors-provider" and store it as "providerName"
    And I generate a unique API context from "/o2m-errors-provider" and store it as "providerContext"
    And I generate a unique resource name from "o2m-errors-proxy" and store it as "proxyName"
    And I generate a unique API context from "/o2m-errors-proxy" and store it as "proxyContext"
    And I resolve the "fault-injection" service URL at "/${CTX:providerName}" and store it as "faultUpstream"
    When I send a "PUT" request to the "fault-injection" service at "/test/scripts/${CTX:providerName}" with body:
      """
      {"forwardPort":3008,"steps":[]}
      """
    Then the response status code should be 200
    When I create LLM provider from "resources/templates/llm-provider.yaml" with values:
      | apiVersion         | ${CTX:gatewaySpecVersion}    |
      | name               | ${CTX:providerName}          |
      | displayName        | O2M-Errors-Provider          |
      | version            | v1.0                         |
      | template           | openai                       |
      | spec.context       | ${CTX:providerContext}       |
      | spec.upstream.url  | ${CTX:faultUpstream}/mistral |
      | accessControl.mode | allow_all                    |
    Then the response status code should be 201
    When I create LLM proxy from "resources/templates/llm-proxy.yaml" with values:
      | apiVersion    | ${CTX:gatewaySpecVersion}                                                                                                                                 |
      | name          | ${CTX:proxyName}                                                                                                                                          |
      | displayName   | O2M-Errors-Proxy                                                                                                                                          |
      | version       | v1.0                                                                                                                                                      |
      | context       | ${CTX:proxyContext}                                                                                                                                       |
      | provider.id   | ${CTX:providerName}                                                                                                                                       |
      | spec.policies | [{"name":"openai-to-mistral-transformer","version":"v0","paths":[{"path":"/chat/completions","methods":["POST"],"params":{"model":"mistral-large-latest"}}]}] |
    Then the response status code should be 201
    And I send a "POST" request to "${CTX:proxyContext}/chat/completions" until status 200 with body:
      """
      {"messages":[{"role":"user","content":"Hello"}]}
      """
    When I send a "PUT" request to the "fault-injection" service at "/test/scripts/${CTX:providerName}" with body:
      """
      {"forwardPort":3008,"steps":[{"status":400},{"status":401},{"status":403},{"status":404},{"status":413},{"status":422},{"status":429},{"status":503},{"status":409}]}
      """
    Then the response status code should be 200
    When I send a "POST" request to "${CTX:proxyContext}/chat/completions" with body:
      """
      {"messages":[{"role":"user","content":"Hello"}]}
      """
    Then the response status code should be 400
    And the JSON response field "error.type" should be "invalid_request_error"
    And the JSON response field "error.code" should be "400"
    When I send a "POST" request to "${CTX:proxyContext}/chat/completions" with body:
      """
      {"messages":[{"role":"user","content":"Hello"}]}
      """
    Then the response status code should be 401
    And the JSON response field "error.type" should be "authentication_error"
    When I send a "POST" request to "${CTX:proxyContext}/chat/completions" with body:
      """
      {"messages":[{"role":"user","content":"Hello"}]}
      """
    Then the response status code should be 403
    And the JSON response field "error.type" should be "permission_error"
    When I send a "POST" request to "${CTX:proxyContext}/chat/completions" with body:
      """
      {"messages":[{"role":"user","content":"Hello"}]}
      """
    Then the response status code should be 404
    And the JSON response field "error.type" should be "not_found_error"
    When I send a "POST" request to "${CTX:proxyContext}/chat/completions" with body:
      """
      {"messages":[{"role":"user","content":"Hello"}]}
      """
    Then the response status code should be 413
    And the JSON response field "error.type" should be "request_too_large"
    When I send a "POST" request to "${CTX:proxyContext}/chat/completions" with body:
      """
      {"messages":[{"role":"user","content":"Hello"}]}
      """
    Then the response status code should be 422
    And the JSON response field "error.type" should be "invalid_request_error"
    And the JSON response field "error.code" should be "422"
    When I send a "POST" request to "${CTX:proxyContext}/chat/completions" with body:
      """
      {"messages":[{"role":"user","content":"Hello"}]}
      """
    Then the response status code should be 429
    And the JSON response field "error.type" should be "rate_limit_error"
    When I send a "POST" request to "${CTX:proxyContext}/chat/completions" with body:
      """
      {"messages":[{"role":"user","content":"Hello"}]}
      """
    Then the response status code should be 503
    And the JSON response field "error.type" should be "server_error"
    When I send a "POST" request to "${CTX:proxyContext}/chat/completions" with body:
      """
      {"messages":[{"role":"user","content":"Hello"}]}
      """
    Then the response status code should be 409
    And the JSON response field "error.type" should be "api_error"
    # The script is used up, so the next request reaches the mock again and succeeds.
    When I send a "POST" request to "${CTX:proxyContext}/chat/completions" with body:
      """
      {"messages":[{"role":"user","content":"Hello"}]}
      """
    Then the response status code should be 200
    When I send a "GET" request to the "fault-injection" service at "/test/scripts/${CTX:providerName}"
    Then the response status code should be 200
    And the JSON response field "received" should be 10
    When I delete the LLM proxy "${CTX:proxyName}"
    Then the response should be successful
    When I delete the LLM provider "${CTX:providerName}"
    Then the response should be successful

  # ---- generated coverage scenarios: begin ----

  Scenario Outline: A scripted O2M reply is translated into the OpenAI shape (<case>)
    Given I generate a unique value from "o2m-fake-<case>" and store it as "fakeName"
    And I generate a unique API context from "/o2m-fake-<case>" and store it as "fakeContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}                                                                                                                                                                                                     |
      | name                   | ${CTX:fakeName}                                                                                                                                                                                                               |
      | spec.displayName       | ${CTX:fakeName}                                                                                                                                                                                                               |
      | spec.version           | v1.0                                                                                                                                                                                                                          |
      | spec.context           | ${CTX:fakeContext}/$version                                                                                                                                                                                                   |
      | spec.upstream.main.url | http://testbench:3002                                                                                                                                                                                                         |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"POST","path":"/*","policies":[{"name":"respond","version":"v1","params":{"statusCode":<status>,"headers":[{"name":"Content-Type","value":"<contentType>"}],"body":"<body>"}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:fakeContext}/v1.0/health" until status 200
    And I generate a unique resource name from "o2m-scripted-provider" and store it as "providerName"
    And I generate a unique API context from "/o2m-scripted-provider" and store it as "providerContext"
    And I generate a unique resource name from "o2m-scripted-proxy" and store it as "proxyName"
    And I generate a unique API context from "/o2m-scripted-proxy" and store it as "proxyContext"
    When I create LLM provider from "resources/templates/llm-provider.yaml" with values:
      | apiVersion         | ${CTX:gatewaySpecVersion}                          |
      | name               | ${CTX:providerName}                                |
      | displayName        | O2M-Scripted-Provider                              |
      | version            | v1.0                                               |
      | template           | openai                                             |
      | spec.context       | ${CTX:providerContext}                             |
      | spec.upstream.url  | http://gateway-runtime:8080${CTX:fakeContext}/v1.0 |
      | accessControl.mode | allow_all                                          |
    Then the response status code should be 201
    When I create LLM proxy from "resources/templates/llm-proxy.yaml" with values:
      | apiVersion    | ${CTX:gatewaySpecVersion}                                                                                                                                     |
      | name          | ${CTX:proxyName}                                                                                                                                              |
      | displayName   | O2M-Scripted-Proxy                                                                                                                                            |
      | version       | v1.0                                                                                                                                                          |
      | context       | ${CTX:proxyContext}                                                                                                                                           |
      | provider.id   | ${CTX:providerName}                                                                                                                                           |
      | spec.policies | [{"name":"openai-to-mistral-transformer","version":"v0","paths":[{"path":"/chat/completions","methods":["POST"],"params":{"model":"mistral-large-latest"}}]}] |
    Then the response status code should be 201
    And I send a "POST" request to "${CTX:proxyContext}/chat/completions" until status <expected> with body:
      """
      <request>
      """
    Then the response body should contain "<expect1>"
    And the response body should contain "<expect2>"
    And the response body should contain "<expect3>"
    And the response body should not contain "<absent>"
    When I delete the LLM proxy "${CTX:proxyName}"
    Then the response should be successful
    When I delete the LLM provider "${CTX:providerName}"
    Then the response should be successful
    When I delete the API "${CTX:fakeName}"
    Then the response should be successful

    Examples:
      | case               | status | contentType              | body                                                                                                                                                                                                          | request                                                                                       | expected | expect1      | expect2      | expect3 | absent |
      | comment-led-stream | 200    | application/octet-stream | : ping\\u000a\\u000adata: {\\"id\\":\\"cmpl-comment\\",\\"object\\":\\"chat.completion.chunk\\",\\"choices\\":[{\\"index\\":0,\\"delta\\":{\\"content\\":\\"hi\\"}}]}\\u000a\\u000adata: [DONE]\\u000a\\u000a | {"model":"mistral-small-latest","messages":[{"role":"user","content":"Hello"}],"stream":true} | 200      | cmpl-comment | data: [DONE] | hi      | error  |
  Scenario Outline: A scripted O2M error is rewritten as an OpenAI error object (<case>)
    Given I generate a unique value from "o2m-fake-<case>" and store it as "fakeName"
    And I generate a unique API context from "/o2m-fake-<case>" and store it as "fakeContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}                                                                                                                                                                                                     |
      | name                   | ${CTX:fakeName}                                                                                                                                                                                                               |
      | spec.displayName       | ${CTX:fakeName}                                                                                                                                                                                                               |
      | spec.version           | v1.0                                                                                                                                                                                                                          |
      | spec.context           | ${CTX:fakeContext}/$version                                                                                                                                                                                                   |
      | spec.upstream.main.url | http://testbench:3002                                                                                                                                                                                                         |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"POST","path":"/*","policies":[{"name":"respond","version":"v1","params":{"statusCode":<status>,"headers":[{"name":"Content-Type","value":"<contentType>"}],"body":"<body>"}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:fakeContext}/v1.0/health" until status 200
    And I generate a unique resource name from "o2m-scripted-provider" and store it as "providerName"
    And I generate a unique API context from "/o2m-scripted-provider" and store it as "providerContext"
    And I generate a unique resource name from "o2m-scripted-proxy" and store it as "proxyName"
    And I generate a unique API context from "/o2m-scripted-proxy" and store it as "proxyContext"
    When I create LLM provider from "resources/templates/llm-provider.yaml" with values:
      | apiVersion         | ${CTX:gatewaySpecVersion}                          |
      | name               | ${CTX:providerName}                                |
      | displayName        | O2M-Scripted-Provider                              |
      | version            | v1.0                                               |
      | template           | openai                                             |
      | spec.context       | ${CTX:providerContext}                             |
      | spec.upstream.url  | http://gateway-runtime:8080${CTX:fakeContext}/v1.0 |
      | accessControl.mode | allow_all                                          |
    Then the response status code should be 201
    When I create LLM proxy from "resources/templates/llm-proxy.yaml" with values:
      | apiVersion    | ${CTX:gatewaySpecVersion}                                                                                                                                     |
      | name          | ${CTX:proxyName}                                                                                                                                              |
      | displayName   | O2M-Scripted-Proxy                                                                                                                                            |
      | version       | v1.0                                                                                                                                                          |
      | context       | ${CTX:proxyContext}                                                                                                                                           |
      | provider.id   | ${CTX:providerName}                                                                                                                                           |
      | spec.policies | [{"name":"openai-to-mistral-transformer","version":"v0","paths":[{"path":"/chat/completions","methods":["POST"],"params":{"model":"mistral-large-latest"}}]}] |
    Then the response status code should be 201
    And I send a "POST" request to "${CTX:proxyContext}/chat/completions" until status <expected> with body:
      """
      <request>
      """
    Then the JSON response field "error.type" should be "<errType>"
    And the JSON response field "error.message" should be "<errMessage>"
    And the JSON response field "error.code" should be "<errCode>"
    And the JSON response field "<gone>" should not exist
    When I delete the LLM proxy "${CTX:proxyName}"
    Then the response should be successful
    When I delete the LLM provider "${CTX:providerName}"
    Then the response should be successful
    When I delete the API "${CTX:fakeName}"
    Then the response should be successful

    Examples:
      | case           | status | contentType      | body                                                                                                                             | request                                                                                       | expected | errType                       | errMessage        | errCode       | gone    |
      | nested-error   | 400    | application/json | {\\"error\\":{\\"message\\":\\"Nested failure\\",\\"type\\":\\"invalid_model\\",\\"code\\":\\"model_missing\\"}}                 | {"model":"mistral-small-latest","messages":[{"role":"user","content":"Hello"}]}               | 400      | invalid_model                 | Nested failure    | model_missing | detail  |
      | flat-error     | 422    | application/json | {\\"object\\":\\"error\\",\\"message\\":\\"Flat failure\\",\\"type\\":\\"invalid_request_message_order\\",\\"code\\":\\"3230\\"} | {"model":"mistral-small-latest","messages":[{"role":"user","content":"Hello"}]}               | 422      | invalid_request_message_order | Flat failure      | 3230          | message |
      | streamed-error | 429    | application/json | {\\"object\\":\\"error\\",\\"message\\":\\"Too many requests\\",\\"type\\":\\"rate_limited\\",\\"code\\":\\"1300\\"}             | {"model":"mistral-small-latest","messages":[{"role":"user","content":"Hello"}],"stream":true} | 429      | rate_limited                  | Too many requests | 1300          | message |

  Scenario: The translator runs only for the provider a header router selected for it
    Given I generate a unique resource name from "o2m-route-primary" and store it as "primaryName"
    And I generate a unique API context from "/o2m-route-primary" and store it as "primaryContext"
    And I generate a unique resource name from "o2m-route-target" and store it as "targetName"
    And I generate a unique API context from "/o2m-route-target" and store it as "targetContext"
    And I generate a unique resource name from "o2m-route-other" and store it as "otherName"
    And I generate a unique API context from "/o2m-route-other" and store it as "otherContext"
    And I generate a unique resource name from "o2m-route-proxy" and store it as "proxyName"
    And I generate a unique API context from "/o2m-route-proxy" and store it as "proxyContext"
    When I create LLM provider from "resources/templates/llm-provider.yaml" with values:
      | apiVersion         | ${CTX:gatewaySpecVersion}      |
      | name               | ${CTX:primaryName}             |
      | displayName        | O2M-Route-Primary              |
      | version            | v1.0                           |
      | template           | openai                         |
      | spec.context       | ${CTX:primaryContext}          |
      | spec.upstream.url  | ${CTX:captureUpstream}/primary |
      | accessControl.mode | allow_all                      |
    Then the response status code should be 201
    When I create LLM provider from "resources/templates/llm-provider.yaml" with values:
      | apiVersion         | ${CTX:gatewaySpecVersion}     |
      | name               | ${CTX:targetName}             |
      | displayName        | O2M-Route-Target              |
      | version            | v1.0                          |
      | template           | openai                        |
      | spec.context       | ${CTX:targetContext}          |
      | spec.upstream.url  | ${CTX:captureUpstream}/target |
      | accessControl.mode | allow_all                     |
    Then the response status code should be 201
    When I create LLM provider from "resources/templates/llm-provider.yaml" with values:
      | apiVersion         | ${CTX:gatewaySpecVersion}    |
      | name               | ${CTX:otherName}             |
      | displayName        | O2M-Route-Other              |
      | version            | v1.0                         |
      | template           | openai                       |
      | spec.context       | ${CTX:otherContext}          |
      | spec.upstream.url  | ${CTX:captureUpstream}/other |
      | accessControl.mode | allow_all                    |
    Then the response status code should be 201
    When I create LLM proxy from "resources/templates/llm-proxy.yaml" with values:
      | apiVersion               | ${CTX:gatewaySpecVersion}                                                                                                                                                                                                                                                                                                                                                                                                            |
      | name                     | ${CTX:proxyName}                                                                                                                                                                                                                                                                                                                                                                                                                     |
      | displayName              | O2M-Route-Proxy                                                                                                                                                                                                                                                                                                                                                                                                                      |
      | version                  | v1.0                                                                                                                                                                                                                                                                                                                                                                                                                                 |
      | context                  | ${CTX:proxyContext}                                                                                                                                                                                                                                                                                                                                                                                                                  |
      | provider.id              | ${CTX:primaryName}                                                                                                                                                                                                                                                                                                                                                                                                                   |
      | spec.additionalProviders | [{"id":"${CTX:targetName}","as":"target-provider"},{"id":"${CTX:otherName}","as":"other-provider"}]                                                                                                                                                                                                                                                                                                                                  |
      | spec.policies            | [{"name":"llm-header-router","version":"v0","paths":[{"path":"/chat/completions","methods":["POST"],"params":{"mappings":[{"headerValue":"target","provider":"target-provider"},{"headerValue":"other","provider":"other-provider"}]}}]},{"name":"openai-to-mistral-transformer","version":"v0","paths":[{"path":"/chat/completions","methods":["POST"],"params":{"model":"mistral-large-latest","providerId":"target-provider"}}]}] |
    Then the response status code should be 201
    When I set header "x-provider" to "target"
    And I send a "POST" request to "${CTX:proxyContext}/chat/completions" until status 200 with body:
      """
      {"model":"route-model","messages":[{"role":"user","content":"routed to the target"}]}
      """
    When I send a "GET" request to the "capture" service at "/test/captured?path=/target/v1/chat/completions"
    Then the response status code should be 200
    And the JSON response field "path" should be "/target/v1/chat/completions"
    And the JSON response field "body" should contain "routed to the target"
    When I set header "x-provider" to "other"
    And I send a "POST" request to "${CTX:proxyContext}/chat/completions" with body:
      """
      {"model":"route-model","messages":[{"role":"user","content":"left untranslated"}]}
      """
    Then the response status code should be 200
    And the JSON response field "path" should be "/other/chat/completions"
    And the JSON response field "body" should match pattern "^[{].model.:.route-model.,.messages.:[[][{].role.:.user.,.content.:.left untranslated.[}][]][}][[:space:]]*$"
    When I send a "POST" request to "${CTX:proxyContext}/chat/completions" with body:
      """
      {"model":"route-model","stream":true,"messages":[{"role":"user","content":"streamed untranslated"}]}
      """
    Then the response status code should be 200
    And the JSON response field "path" should be "/other/chat/completions"
    When I delete the LLM proxy "${CTX:proxyName}"
    Then the response should be successful
    When I delete the LLM provider "${CTX:otherName}"
    Then the response should be successful
    When I delete the LLM provider "${CTX:targetName}"
    Then the response should be successful
    When I delete the LLM provider "${CTX:primaryName}"
    Then the response should be successful

  # ---- generated coverage scenarios: end ----
