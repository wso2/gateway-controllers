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

@openai-to-anthropic-transformer
Feature: OpenAI to Anthropic transformer
  As an API consumer
  I want to call an Anthropic upstream with OpenAI Chat Completions requests
  So that clients written for OpenAI work unchanged against Anthropic

  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"
    And I resolve the "capture" service URL at "" and store it as "captureUpstream"

  Scenario: An Anthropic Messages response is returned in the OpenAI chat completion shape
    Given I generate a unique resource name from "o2a-response-provider" and store it as "providerName"
    And I generate a unique API context from "/o2a-response-provider" and store it as "providerContext"
    And I generate a unique resource name from "o2a-response-proxy" and store it as "proxyName"
    And I generate a unique API context from "/o2a-response-proxy" and store it as "proxyContext"
    When I create LLM provider from "resources/templates/llm-provider.yaml" with values:
      | apiVersion         | ${CTX:gatewaySpecVersion}       |
      | name               | ${CTX:providerName}             |
      | displayName        | O2A-Response-Provider           |
      | version            | v1.0                            |
      | template           | openai                          |
      | spec.context       | ${CTX:providerContext}          |
      | spec.upstream.url  | http://testbench:3008/anthropic |
      | accessControl.mode | allow_all                       |
    Then the response status code should be 201
    When I create LLM proxy from "resources/templates/llm-proxy.yaml" with values:
      | apiVersion    | ${CTX:gatewaySpecVersion}                                                                                                                                  |
      | name          | ${CTX:proxyName}                                                                                                                                           |
      | displayName   | O2A-Response-Proxy                                                                                                                                         |
      | version       | v1.0                                                                                                                                                       |
      | context       | ${CTX:proxyContext}                                                                                                                                        |
      | provider.id   | ${CTX:providerName}                                                                                                                                        |
      | spec.policies | [{"name":"openai-to-anthropic-transformer","version":"v0","paths":[{"path":"/chat/completions","methods":["POST"],"params":{"model":"claude-fallback-model"}}]}] |
    Then the response status code should be 201
    And I send a "POST" request to "${CTX:proxyContext}/chat/completions" until status 200 with body:
      """
      {"model":"claude-3-5-haiku-20241022","messages":[{"role":"user","content":"Hello"}]}
      """
    Then the response should be valid JSON
    And the JSON response field "object" should be "chat.completion"
    And the JSON response field "model" should be "claude-3-5-haiku-20241022"
    And the JSON response field "choices[0].message.role" should be "assistant"
    And the JSON response field "choices[0].message.content" should be "Hello! How can I help you today?"
    And the JSON response field "choices[0].finish_reason" should be "stop"
    And the JSON response field "usage.prompt_tokens" should be 50
    And the JSON response field "usage.completion_tokens" should be 25
    And the JSON response field "usage.total_tokens" should be 75
    When I delete the LLM proxy "${CTX:proxyName}"
    Then the response should be successful
    When I delete the LLM provider "${CTX:providerName}"
    Then the response should be successful

  Scenario: The upstream receives an Anthropic Messages request
    Given I generate a unique resource name from "o2a-request-provider" and store it as "providerName"
    And I generate a unique API context from "/o2a-request-provider" and store it as "providerContext"
    And I generate a unique resource name from "o2a-request-proxy" and store it as "proxyName"
    And I generate a unique API context from "/o2a-request-proxy" and store it as "proxyContext"
    When I create LLM provider from "resources/templates/llm-provider.yaml" with values:
      | apiVersion         | ${CTX:gatewaySpecVersion} |
      | name               | ${CTX:providerName}       |
      | displayName        | O2A-Request-Provider      |
      | version            | v1.0                      |
      | template           | openai                    |
      | spec.context       | ${CTX:providerContext}    |
      | spec.upstream.url  | ${CTX:captureUpstream}    |
      | accessControl.mode | allow_all                 |
    Then the response status code should be 201
    When I create LLM proxy from "resources/templates/llm-proxy.yaml" with values:
      | apiVersion    | ${CTX:gatewaySpecVersion}                                                                                                                                                                  |
      | name          | ${CTX:proxyName}                                                                                                                                                                           |
      | displayName   | O2A-Request-Proxy                                                                                                                                                                          |
      | version       | v1.0                                                                                                                                                                                       |
      | context       | ${CTX:proxyContext}                                                                                                                                                                        |
      | provider.id   | ${CTX:providerName}                                                                                                                                                                        |
      | spec.policies | [{"name":"openai-to-anthropic-transformer","version":"v0","paths":[{"path":"/chat/completions","methods":["POST"],"params":{"model":"claude-fallback-model","anthropicVersion":"2023-06-01"}}]}] |
    Then the response status code should be 201
    # The request names no model, so the policy's fallback model is sent upstream.
    And I send a "POST" request to "${CTX:proxyContext}/chat/completions" until status 200 with body:
      """
      {"messages":[{"role":"system","content":"Answer briefly."},{"role":"user","content":"Hello"}],"max_completion_tokens":64,"stop":"END"}
      """
    When I send a "GET" request to the "capture" service at "/test/captured?path=/v1/messages"
    Then the response status code should be 200
    And the JSON response field "method" should be "POST"
    And the JSON response field "path" should be "/v1/messages"
    And the JSON response field "headers.Anthropic-Version[0]" should be "2023-06-01"
    And the JSON response field "body" should contain "claude-fallback-model"
    And the JSON response field "body" should contain "Answer briefly."
    And the JSON response field "body" should contain "stop_sequences"
    And the JSON response field "body" should contain "max_tokens"
    And the response body should not contain "max_completion_tokens"
    When I delete the LLM proxy "${CTX:proxyName}"
    Then the response should be successful
    When I delete the LLM provider "${CTX:providerName}"
    Then the response should be successful

  # The response must match the expected error response recorded from the policy before a
  # change (resources/expected-error-responses), so a change a client could observe fails.
  Scenario: openai-to-anthropic-transformer rejects an empty request body
    Given I generate a unique value from "compat-oa-empty" and store it as "apiName"
    And I generate a unique API version from "compat-oa-empty" and store it as "apiVersion"
    And I generate a unique API context from "/compat-oa-empty" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3002 |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"POST","path":"/chat/completions","policies":[{"name":"openai-to-anthropic-transformer","version":"v0","params":{"model":"claude-3-5-haiku-20241022"}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat/completions" with body:
      """
      """
    Then the response status code should be 400
    And the response should match the expected error response "openai-to-anthropic-transformer-empty-body"

  Scenario: An Anthropic event stream is returned as an OpenAI chat completion chunk stream
    Given I generate a unique resource name from "o2a-stream-provider" and store it as "providerName"
    And I generate a unique API context from "/o2a-stream-provider" and store it as "providerContext"
    And I generate a unique resource name from "o2a-stream-proxy" and store it as "proxyName"
    And I generate a unique API context from "/o2a-stream-proxy" and store it as "proxyContext"
    When I create LLM provider from "resources/templates/llm-provider.yaml" with values:
      | apiVersion         | ${CTX:gatewaySpecVersion}       |
      | name               | ${CTX:providerName}             |
      | displayName        | O2A-Stream-Provider             |
      | version            | v1.0                            |
      | template           | openai                          |
      | spec.context       | ${CTX:providerContext}          |
      | spec.upstream.url  | http://testbench:3008/anthropic |
      | accessControl.mode | allow_all                       |
    Then the response status code should be 201
    When I create LLM proxy from "resources/templates/llm-proxy.yaml" with values:
      | apiVersion    | ${CTX:gatewaySpecVersion}                                                                                                                                  |
      | name          | ${CTX:proxyName}                                                                                                                                           |
      | displayName   | O2A-Stream-Proxy                                                                                                                                           |
      | version       | v1.0                                                                                                                                                       |
      | context       | ${CTX:proxyContext}                                                                                                                                        |
      | provider.id   | ${CTX:providerName}                                                                                                                                        |
      | spec.policies | [{"name":"openai-to-anthropic-transformer","version":"v0","paths":[{"path":"/chat/completions","methods":["POST"],"params":{"model":"claude-fallback-model"}}]}] |
    Then the response status code should be 201
    And I send a "POST" request to "${CTX:proxyContext}/chat/completions" until status 200 with body:
      """
      {"model":"claude-3-5-haiku-20241022","messages":[{"role":"user","content":"Hello"}]}
      """
    # The mock answers a streaming request with an Anthropic Messages event stream: message_start,
    # one text delta per word, message_delta with end_turn and usage, then message_stop.
    When I send a "POST" request to "${CTX:proxyContext}/chat/completions" with body:
      """
      {"model":"claude-3-5-haiku-20241022","stream":true,"messages":[{"role":"user","content":"Hello"}]}
      """
    Then the response status code should be 200
    And the response header "content-type" should contain "text/event-stream"
    And the response body should contain "chat.completion.chunk"
    And the response body should contain "chatcmpl-mock_stream"
    And the response body should contain "assistant"
    And the response body should contain "streamed "
    And the response body should contain "model."
    And the response body should contain "finish_reason"
    And the response body should contain "prompt_tokens"
    And the response body should contain "data: [DONE]"
    And the response body should not contain "content_block_delta"
    And the response body should not contain "message_start"
    When I delete the LLM proxy "${CTX:proxyName}"
    Then the response should be successful
    When I delete the LLM provider "${CTX:providerName}"
    Then the response should be successful

  Scenario: An Anthropic stream that fails mid-way ends with an OpenAI error event and no DONE
    Given I generate a unique resource name from "o2a-stream-error-provider" and store it as "providerName"
    And I generate a unique API context from "/o2a-stream-error-provider" and store it as "providerContext"
    And I generate a unique resource name from "o2a-stream-error-proxy" and store it as "proxyName"
    And I generate a unique API context from "/o2a-stream-error-proxy" and store it as "proxyContext"
    When I create LLM provider from "resources/templates/llm-provider.yaml" with values:
      | apiVersion         | ${CTX:gatewaySpecVersion}       |
      | name               | ${CTX:providerName}             |
      | displayName        | O2A-Stream-Error-Provider       |
      | version            | v1.0                            |
      | template           | openai                          |
      | spec.context       | ${CTX:providerContext}          |
      | spec.upstream.url  | http://testbench:3008/anthropic |
      | accessControl.mode | allow_all                       |
    Then the response status code should be 201
    When I create LLM proxy from "resources/templates/llm-proxy.yaml" with values:
      | apiVersion    | ${CTX:gatewaySpecVersion}                                                                                                                                  |
      | name          | ${CTX:proxyName}                                                                                                                                           |
      | displayName   | O2A-Stream-Error-Proxy                                                                                                                                     |
      | version       | v1.0                                                                                                                                                       |
      | context       | ${CTX:proxyContext}                                                                                                                                        |
      | provider.id   | ${CTX:providerName}                                                                                                                                        |
      | spec.policies | [{"name":"openai-to-anthropic-transformer","version":"v0","paths":[{"path":"/chat/completions","methods":["POST"],"params":{"model":"claude-fallback-model"}}]}] |
    Then the response status code should be 201
    And I send a "POST" request to "${CTX:proxyContext}/chat/completions" until status 200 with body:
      """
      {"model":"claude-3-5-haiku-20241022","messages":[{"role":"user","content":"Hello"}]}
      """
    # STREAM_ERROR in the request makes the mock end the stream with an Anthropic error event.
    When I send a "POST" request to "${CTX:proxyContext}/chat/completions" with body:
      """
      {"model":"claude-3-5-haiku-20241022","stream":true,"messages":[{"role":"user","content":"STREAM_ERROR"}]}
      """
    Then the response header "content-type" should contain "text/event-stream"
    And the response body should contain "chat.completion.chunk"
    And the response body should contain "overloaded_error"
    And the response body should contain "Overloaded"
    And the response body should not contain "[DONE]"
    When I delete the LLM proxy "${CTX:proxyName}"
    Then the response should be successful
    When I delete the LLM provider "${CTX:providerName}"
    Then the response should be successful

  Scenario: Tools, tool choice, images and tool turns are translated into Anthropic blocks
    Given I generate a unique resource name from "o2a-tools-provider" and store it as "providerName"
    And I generate a unique API context from "/o2a-tools-provider" and store it as "providerContext"
    And I generate a unique resource name from "o2a-tools-proxy" and store it as "proxyName"
    And I generate a unique API context from "/o2a-tools-proxy" and store it as "proxyContext"
    When I create LLM provider from "resources/templates/llm-provider.yaml" with values:
      | apiVersion         | ${CTX:gatewaySpecVersion} |
      | name               | ${CTX:providerName}       |
      | displayName        | O2A-Tools-Provider        |
      | version            | v1.0                      |
      | template           | openai                    |
      | spec.context       | ${CTX:providerContext}    |
      | spec.upstream.url  | ${CTX:captureUpstream}    |
      | accessControl.mode | allow_all                 |
    Then the response status code should be 201
    When I create LLM proxy from "resources/templates/llm-proxy.yaml" with values:
      | apiVersion    | ${CTX:gatewaySpecVersion}                                                                                                                                  |
      | name          | ${CTX:proxyName}                                                                                                                                           |
      | displayName   | O2A-Tools-Proxy                                                                                                                                            |
      | version       | v1.0                                                                                                                                                       |
      | context       | ${CTX:proxyContext}                                                                                                                                        |
      | provider.id   | ${CTX:providerName}                                                                                                                                        |
      | spec.policies | [{"name":"openai-to-anthropic-transformer","version":"v0","paths":[{"path":"/chat/completions","methods":["POST"],"params":{"model":"claude-fallback-model"}}]}] |
    Then the response status code should be 201
    # A developer message joins the system prompt, user content parts become text and image blocks
    # (base64 data URL and remote URL), the assistant tool call becomes a tool_use block with its
    # arguments decoded, and consecutive tool messages collapse into one user turn of tool_result
    # blocks. tool_choice "required" becomes Anthropic's "any".
    And I send a "POST" request to "${CTX:proxyContext}/chat/completions" until status 200 with body:
      """
      {"model":"claude-3-5-haiku-20241022","max_tokens":128,"temperature":0.2,"top_p":0.9,"stop":["END","STOP"],"messages":[{"role":"developer","content":[{"type":"text","text":"Use metric units."}]},{"role":"user","content":[{"type":"text","text":"What is in this picture?"},{"type":"image_url","image_url":{"url":"data:image/png;base64,iVBORw0KGgo="}},{"type":"image_url","image_url":{"url":"https://example.com/cat.png"}}]},{"role":"assistant","content":"Checking the weather.","tool_calls":[{"id":"call_weather","type":"function","function":{"name":"get_weather","arguments":"{\"city\":\"Colombo\"}"}},{"id":"call_time","type":"function","function":{"name":"get_time","arguments":""}}]},{"role":"tool","tool_call_id":"call_weather","content":"31C and sunny"},{"role":"tool","tool_call_id":"call_time","content":[{"type":"text","text":"10:00"}]},{"role":"user","content":"Summarise."}],"tools":[{"type":"function","function":{"name":"get_weather","description":"Weather for a city","parameters":{"type":"object","properties":{"city":{"type":"string"}}}}},{"type":"function","function":{"name":"get_time"}}],"tool_choice":"required"}
      """
    When I send a "GET" request to the "capture" service at "/test/captured?path=/v1/messages"
    Then the response status code should be 200
    And the JSON response field "body" should contain "Use metric units."
    And the JSON response field "body" should contain "image/png"
    And the JSON response field "body" should contain "iVBORw0KGgo="
    And the JSON response field "body" should contain "https://example.com/cat.png"
    And the JSON response field "body" should contain "tool_use"
    And the JSON response field "body" should contain "call_weather"
    And the JSON response field "body" should contain "Colombo"
    And the JSON response field "body" should contain "tool_result"
    And the JSON response field "body" should contain "tool_use_id"
    And the JSON response field "body" should contain "31C and sunny"
    And the JSON response field "body" should contain "10:00"
    And the JSON response field "body" should contain "input_schema"
    And the JSON response field "body" should contain "Weather for a city"
    And the JSON response field "body" should contain "tool_choice"
    And the JSON response field "body" should contain "stop_sequences"
    And the JSON response field "body" should contain "top_p"
    And the response body should not contain "tool_calls"
    And the response body should not contain "image_url"
    # tool_choice "none" has no Anthropic form, so the tools are dropped instead.
    When I send a "POST" request to "${CTX:proxyContext}/chat/completions" with body:
      """
      {"model":"claude-3-5-haiku-20241022","messages":[{"role":"user","content":"Hi"}],"tools":[{"type":"function","function":{"name":"get_weather"}}],"tool_choice":"none"}
      """
    Then the response status code should be 200
    When I send a "GET" request to the "capture" service at "/test/captured?path=/v1/messages"
    Then the response status code should be 200
    And the response body should not contain "get_weather"
    And the response body should not contain "tool_choice"
    # A named function choice becomes an Anthropic "tool" choice; "auto" stays "auto".
    When I send a "POST" request to "${CTX:proxyContext}/chat/completions" with body:
      """
      {"model":"claude-3-5-haiku-20241022","messages":[{"role":"user","content":"Hi"}],"tools":[{"type":"function","function":{"name":"get_weather"}}],"tool_choice":{"type":"function","function":{"name":"get_weather"}}}
      """
    Then the response status code should be 200
    When I send a "GET" request to the "capture" service at "/test/captured?path=/v1/messages"
    Then the response status code should be 200
    And the JSON response field "body" should contain "get_weather"
    And the JSON response field "body" should contain "tool_choice"
    When I send a "POST" request to "${CTX:proxyContext}/chat/completions" with body:
      """
      {"model":"claude-3-5-haiku-20241022","messages":[{"role":"user","content":"Hi"}],"tools":[{"type":"function","function":{"name":"get_weather"}}],"tool_choice":"auto"}
      """
    Then the response status code should be 200
    When I send a "GET" request to the "capture" service at "/test/captured?path=/v1/messages"
    Then the response status code should be 200
    And the JSON response field "body" should contain "auto"
    When I delete the LLM proxy "${CTX:proxyName}"
    Then the response should be successful
    When I delete the LLM provider "${CTX:providerName}"
    Then the response should be successful

  Scenario: A request the policy cannot translate is rejected with 400
    Given I generate a unique resource name from "o2a-invalid-provider" and store it as "providerName"
    And I generate a unique API context from "/o2a-invalid-provider" and store it as "providerContext"
    And I generate a unique resource name from "o2a-invalid-proxy" and store it as "proxyName"
    And I generate a unique API context from "/o2a-invalid-proxy" and store it as "proxyContext"
    When I create LLM provider from "resources/templates/llm-provider.yaml" with values:
      | apiVersion         | ${CTX:gatewaySpecVersion}       |
      | name               | ${CTX:providerName}             |
      | displayName        | O2A-Invalid-Provider            |
      | version            | v1.0                            |
      | template           | openai                          |
      | spec.context       | ${CTX:providerContext}          |
      | spec.upstream.url  | http://testbench:3008/anthropic |
      | accessControl.mode | allow_all                       |
    Then the response status code should be 201
    # No fallback model is configured, so the request has to name one.
    When I create LLM proxy from "resources/templates/llm-proxy.yaml" with values:
      | apiVersion    | ${CTX:gatewaySpecVersion}                                                                                                     |
      | name          | ${CTX:proxyName}                                                                                                              |
      | displayName   | O2A-Invalid-Proxy                                                                                                             |
      | version       | v1.0                                                                                                                          |
      | context       | ${CTX:proxyContext}                                                                                                           |
      | provider.id   | ${CTX:providerName}                                                                                                           |
      | spec.policies | [{"name":"openai-to-anthropic-transformer","version":"v0","paths":[{"path":"/chat/completions","methods":["POST"],"params":{}}]}] |
    Then the response status code should be 201
    And I send a "POST" request to "${CTX:proxyContext}/chat/completions" until status 200 with body:
      """
      {"model":"claude-3-5-haiku-20241022","messages":[{"role":"user","content":"Hello"}]}
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
  # body, before it forwards anything to the mock. Each status maps onto an OpenAI error type.
  Scenario: Upstream error statuses are returned as OpenAI error objects
    Given I generate a unique resource name from "o2a-errors-provider" and store it as "providerName"
    And I generate a unique API context from "/o2a-errors-provider" and store it as "providerContext"
    And I generate a unique resource name from "o2a-errors-proxy" and store it as "proxyName"
    And I generate a unique API context from "/o2a-errors-proxy" and store it as "proxyContext"
    And I resolve the "fault-injection" service URL at "/${CTX:providerName}" and store it as "faultUpstream"
    When I send a "PUT" request to the "fault-injection" service at "/test/scripts/${CTX:providerName}" with body:
      """
      {"forwardPort":3008,"steps":[]}
      """
    Then the response status code should be 200
    When I create LLM provider from "resources/templates/llm-provider.yaml" with values:
      | apiVersion         | ${CTX:gatewaySpecVersion}       |
      | name               | ${CTX:providerName}             |
      | displayName        | O2A-Errors-Provider             |
      | version            | v1.0                            |
      | template           | openai                          |
      | spec.context       | ${CTX:providerContext}          |
      | spec.upstream.url  | ${CTX:faultUpstream}/anthropic  |
      | accessControl.mode | allow_all                       |
    Then the response status code should be 201
    When I create LLM proxy from "resources/templates/llm-proxy.yaml" with values:
      | apiVersion    | ${CTX:gatewaySpecVersion}                                                                                                                                  |
      | name          | ${CTX:proxyName}                                                                                                                                           |
      | displayName   | O2A-Errors-Proxy                                                                                                                                           |
      | version       | v1.0                                                                                                                                                       |
      | context       | ${CTX:proxyContext}                                                                                                                                        |
      | provider.id   | ${CTX:providerName}                                                                                                                                        |
      | spec.policies | [{"name":"openai-to-anthropic-transformer","version":"v0","paths":[{"path":"/chat/completions","methods":["POST"],"params":{"model":"claude-fallback-model"}}]}] |
    Then the response status code should be 201
    And I send a "POST" request to "${CTX:proxyContext}/chat/completions" until status 200 with body:
      """
      {"messages":[{"role":"user","content":"Hello"}]}
      """
    # The fallback model is reported when the upstream reply names none, which the mock does not do,
    # so only the error mapping is checked from here on.
    When I send a "PUT" request to the "fault-injection" service at "/test/scripts/${CTX:providerName}" with body:
      """
      {"forwardPort":3008,"steps":[{"status":400},{"status":401},{"status":403},{"status":404},{"status":413},{"status":429},{"status":503},{"status":409}]}
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
    And the JSON response field "error.code" should be "409"
    # The script is used up, so the next request reaches the mock again and succeeds.
    When I send a "POST" request to "${CTX:proxyContext}/chat/completions" with body:
      """
      {"messages":[{"role":"user","content":"Hello"}]}
      """
    Then the response status code should be 200
    And the JSON response field "object" should be "chat.completion"
    When I send a "GET" request to the "fault-injection" service at "/test/scripts/${CTX:providerName}"
    Then the response status code should be 200
    And the JSON response field "received" should be 9
    When I delete the LLM proxy "${CTX:proxyName}"
    Then the response should be successful
    When I delete the LLM provider "${CTX:providerName}"
    Then the response should be successful

  # ---- generated coverage scenarios: begin ----

  Scenario Outline: A scripted O2A reply is translated into the OpenAI shape (<case>)
    Given I generate a unique value from "o2a-fake-<case>" and store it as "fakeName"
    And I generate a unique API context from "/o2a-fake-<case>" and store it as "fakeContext"
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
    And I generate a unique resource name from "o2a-scripted-provider" and store it as "providerName"
    And I generate a unique API context from "/o2a-scripted-provider" and store it as "providerContext"
    And I generate a unique resource name from "o2a-scripted-proxy" and store it as "proxyName"
    And I generate a unique API context from "/o2a-scripted-proxy" and store it as "proxyContext"
    When I create LLM provider from "resources/templates/llm-provider.yaml" with values:
      | apiVersion         | ${CTX:gatewaySpecVersion}                          |
      | name               | ${CTX:providerName}                                |
      | displayName        | O2A-Scripted-Provider                              |
      | version            | v1.0                                               |
      | template           | openai                                             |
      | spec.context       | ${CTX:providerContext}                             |
      | spec.upstream.url  | http://gateway-runtime:8080${CTX:fakeContext}/v1.0 |
      | accessControl.mode | allow_all                                          |
    Then the response status code should be 201
    When I create LLM proxy from "resources/templates/llm-proxy.yaml" with values:
      | apiVersion    | ${CTX:gatewaySpecVersion}                                                                                                                                        |
      | name          | ${CTX:proxyName}                                                                                                                                                 |
      | displayName   | O2A-Scripted-Proxy                                                                                                                                               |
      | version       | v1.0                                                                                                                                                             |
      | context       | ${CTX:proxyContext}                                                                                                                                              |
      | provider.id   | ${CTX:providerName}                                                                                                                                              |
      | spec.policies | [{"name":"openai-to-anthropic-transformer","version":"v0","paths":[{"path":"/chat/completions","methods":["POST"],"params":{"model":"claude-fallback-model"}}]}] |
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
      | case                    | status | contentType       | body                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  | request                                                                                      | expected | expect1                          | expect2          | expect3         | absent          |
      | tool-use                | 200    | application/json  | {\\"id\\":\\"msg_tool\\",\\"type\\":\\"message\\",\\"role\\":\\"assistant\\",\\"model\\":\\"claude-tool-model\\",\\"content\\":[{\\"type\\":\\"text\\",\\"text\\":\\"Let me check.\\"},{\\"type\\":\\"tool_use\\",\\"id\\":\\"toolu_one\\",\\"name\\":\\"get_weather\\",\\"input\\":{\\"city\\":\\"Colombo\\"}},{\\"type\\":\\"tool_use\\",\\"id\\":\\"toolu_two\\",\\"name\\":\\"get_time\\"}],\\"stop_reason\\":\\"tool_use\\",\\"usage\\":{\\"input_tokens\\":10,\\"output_tokens\\":5,\\"cache_read_input_tokens\\":3,\\"cache_creation_input_tokens\\":2}}                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       | {"model":"claude-tool-model","messages":[{"role":"user","content":"Hello"}]}                 | 200      | toolu_two                        | cached_tokens    | tool_calls      | tool_use        |
      | max-tokens              | 200    | application/json  | {\\"id\\":\\"msg_len\\",\\"type\\":\\"message\\",\\"role\\":\\"assistant\\",\\"content\\":[{\\"type\\":\\"text\\",\\"text\\":\\"Cut off\\"}],\\"stop_reason\\":\\"max_tokens\\",\\"usage\\":{\\"input_tokens\\":1,\\"output_tokens\\":1}}                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             | {"model":"claude-len-model","messages":[{"role":"user","content":"Hello"}]}                  | 200      | Cut off                          | length           | chat.completion | max_tokens      |
      | tool-stop-without-tools | 200    | application/json  | {\\"id\\":\\"msg_ts\\",\\"type\\":\\"message\\",\\"role\\":\\"assistant\\",\\"content\\":[{\\"type\\":\\"text\\",\\"text\\":\\"Done\\"}],\\"stop_reason\\":\\"tool_use\\",\\"usage\\":{\\"input_tokens\\":1,\\"output_tokens\\":1}}                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   | {"model":"claude-ts-model","messages":[{"role":"user","content":"Hello"}]}                   | 200      | Done                             | tool_calls       | chat.completion | end_turn        |
      | not-json                | 200    | text/plain        | plain upstream text                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   | {"model":"claude-plain-model","messages":[{"role":"user","content":"Hello"}]}                | 200      | plain                            | upstream         | text            | chat.completion |
      | error-envelope          | 429    | application/json  | {\\"type\\":\\"error\\",\\"error\\":{\\"type\\":\\"rate_limit_error\\",\\"message\\":\\"Slow down please\\"}}                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         | {"model":"claude-err-model","messages":[{"role":"user","content":"Hello"}]}                  | 429      | rate_limit_error                 | Slow down please | error           | overloaded      |
      | streamed-error-envelope | 429    | application/json  | {\\"type\\":\\"error\\",\\"error\\":{\\"type\\":\\"rate_limit_error\\",\\"message\\":\\"Slow down please\\"}}                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         | {"model":"claude-err-model","messages":[{"role":"user","content":"Hello"}],"stream":true}    | 429      | rate_limit_error                 | Slow down please | error           | overloaded      |
      | event-stream            | 200    | text/event-stream | event: message_start\\u000adata: {\\"type\\":\\"message_start\\",\\"message\\":{\\"id\\":\\"msg_s1\\",\\"model\\":\\"claude-stream-model\\",\\"usage\\":{\\"input_tokens\\":7,\\"cache_read_input_tokens\\":4,\\"cache_creation_input_tokens\\":2}}}\\u000a\\u000aevent: message_start\\u000adata: {\\"type\\":\\"message_start\\",\\"message\\":{\\"id\\":\\"msg_s1\\"}}\\u000a\\u000a: keep-alive\\u000a\\u000aevent: content_block_start\\u000adata: {\\"type\\":\\"content_block_start\\",\\"index\\":0,\\"content_block\\":{\\"type\\":\\"text\\",\\"text\\":\\"\\"}}\\u000a\\u000aevent: content_block_delta\\u000adata: {\\"type\\":\\"content_block_delta\\",\\"index\\":0,\\"delta\\":{\\"type\\":\\"text_delta\\",\\"text\\":\\"\\"}}\\u000a\\u000aevent: content_block_delta\\u000adata: {\\"type\\":\\"content_block_delta\\",\\"index\\":0,\\"delta\\":{\\"type\\":\\"text_delta\\",\\"text\\":\\"Checking\\"}}\\u000a\\u000aevent: content_block_delta\\u000adata: {\\"type\\":\\"content_block_delta\\",\\"index\\":0}\\u000a\\u000aevent: content_block_start\\u000adata: {\\"type\\":\\"content_block_start\\",\\"index\\":1,\\"content_block\\":{\\"type\\":\\"tool_use\\",\\"id\\":\\"toolu_stream\\",\\"name\\":\\"get_weather\\"}}\\u000a\\u000aevent: content_block_delta\\u000adata: {\\"type\\":\\"content_block_delta\\",\\"index\\":1,\\"delta\\":{\\"type\\":\\"input_json_delta\\",\\"partial_json\\":\\"{\\\\\\"city\\\\\\":\\"}}\\u000a\\u000aevent: content_block_delta\\u000d\\u000adata: {\\"type\\":\\"content_block_delta\\",\\"index\\":1,\\"delta\\":{\\"type\\":\\"input_json_delta\\",\\"partial_json\\":\\"\\\\\\"Colombo\\\\\\"}\\"}}\\u000d\\u000a\\u000d\\u000a\\u000aevent: content_block_delta\\u000adata: {\\"type\\":\\"content_block_delta\\",\\"index\\":0,\\"delta\\":{\\"type\\":\\"thinking_delta\\",\\"thinking\\":\\"hmm\\"}}\\u000a\\u000aevent: ping\\u000adata: {\\"type\\":\\"ping\\",\\u000adata: \\"note\\":\\"split across two data lines\\"}\\u000a\\u000aevent: message_delta\\u000adata: {\\"type\\":\\"message_delta\\",\\"usage\\":{\\"output_tokens\\":9,\\"cache_read_input_tokens\\":4,\\"cache_creation_input_tokens\\":2}}\\u000a\\u000aevent: message_delta\\u000adata: {\\"type\\":\\"message_delta\\",\\"delta\\":{\\"stop_reason\\":\\"tool_use\\"},\\"usage\\":{\\"output_tokens\\":9}}\\u000a\\u000aevent: message_delta\\u000adata: {\\"type\\":\\"message_delta\\",\\"delta\\":{\\"stop_reason\\":\\"end_turn\\"}}\\u000a\\u000aevent: message_stop\\u000adata: {\\"type\\":\\"message_stop\\"}\\u000a\\u000aevent: ping\\u000adata: {\\"type\\":\\"pi | {"model":"claude-stream-model","messages":[{"role":"user","content":"Hello"}],"stream":true} | 200      | toolu_stream                     | cached_tokens    | data: [DONE]    | content_block   |
      | malformed-event         | 200    | text/event-stream | event: message_start\\u000adata: {not json\\u000a\\u000a                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              | {"model":"claude-bad-model","messages":[{"role":"user","content":"Hello"}],"stream":true}    | 200      | malformed Anthropic stream event | error            | data:           | [DONE]          |
      | error-event             | 500    | text/event-stream | event: error\\u000adata: {\\"type\\":\\"error\\",\\"error\\":{}}\\u000a\\u000a                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        | {"model":"claude-fail-model","messages":[{"role":"user","content":"Hello"}],"stream":true}   | 500      | anthropic stream error           | 500              | error           | [DONE]          |

  Scenario: The translator runs only for the provider a header router selected for it
    Given I generate a unique resource name from "o2a-route-primary" and store it as "primaryName"
    And I generate a unique API context from "/o2a-route-primary" and store it as "primaryContext"
    And I generate a unique resource name from "o2a-route-target" and store it as "targetName"
    And I generate a unique API context from "/o2a-route-target" and store it as "targetContext"
    And I generate a unique resource name from "o2a-route-other" and store it as "otherName"
    And I generate a unique API context from "/o2a-route-other" and store it as "otherContext"
    And I generate a unique resource name from "o2a-route-proxy" and store it as "proxyName"
    And I generate a unique API context from "/o2a-route-proxy" and store it as "proxyContext"
    When I create LLM provider from "resources/templates/llm-provider.yaml" with values:
      | apiVersion         | ${CTX:gatewaySpecVersion}      |
      | name               | ${CTX:primaryName}             |
      | displayName        | O2A-Route-Primary              |
      | version            | v1.0                           |
      | template           | openai                         |
      | spec.context       | ${CTX:primaryContext}          |
      | spec.upstream.url  | ${CTX:captureUpstream}/primary |
      | accessControl.mode | allow_all                      |
    Then the response status code should be 201
    When I create LLM provider from "resources/templates/llm-provider.yaml" with values:
      | apiVersion         | ${CTX:gatewaySpecVersion}     |
      | name               | ${CTX:targetName}             |
      | displayName        | O2A-Route-Target              |
      | version            | v1.0                          |
      | template           | openai                        |
      | spec.context       | ${CTX:targetContext}          |
      | spec.upstream.url  | ${CTX:captureUpstream}/target |
      | accessControl.mode | allow_all                     |
    Then the response status code should be 201
    When I create LLM provider from "resources/templates/llm-provider.yaml" with values:
      | apiVersion         | ${CTX:gatewaySpecVersion}    |
      | name               | ${CTX:otherName}             |
      | displayName        | O2A-Route-Other              |
      | version            | v1.0                         |
      | template           | openai                       |
      | spec.context       | ${CTX:otherContext}          |
      | spec.upstream.url  | ${CTX:captureUpstream}/other |
      | accessControl.mode | allow_all                    |
    Then the response status code should be 201
    When I create LLM proxy from "resources/templates/llm-proxy.yaml" with values:
      | apiVersion               | ${CTX:gatewaySpecVersion}                                                                                                                                                                                                                                                                                                                                                                                                               |
      | name                     | ${CTX:proxyName}                                                                                                                                                                                                                                                                                                                                                                                                                        |
      | displayName              | O2A-Route-Proxy                                                                                                                                                                                                                                                                                                                                                                                                                         |
      | version                  | v1.0                                                                                                                                                                                                                                                                                                                                                                                                                                    |
      | context                  | ${CTX:proxyContext}                                                                                                                                                                                                                                                                                                                                                                                                                     |
      | provider.id              | ${CTX:primaryName}                                                                                                                                                                                                                                                                                                                                                                                                                      |
      | spec.additionalProviders | [{"id":"${CTX:targetName}","as":"target-provider"},{"id":"${CTX:otherName}","as":"other-provider"}]                                                                                                                                                                                                                                                                                                                                     |
      | spec.policies            | [{"name":"llm-header-router","version":"v0","paths":[{"path":"/chat/completions","methods":["POST"],"params":{"mappings":[{"headerValue":"target","provider":"target-provider"},{"headerValue":"other","provider":"other-provider"}]}}]},{"name":"openai-to-anthropic-transformer","version":"v0","paths":[{"path":"/chat/completions","methods":["POST"],"params":{"model":"claude-fallback-model","providerId":"target-provider"}}]}] |
    Then the response status code should be 201
    When I set header "x-provider" to "target"
    And I send a "POST" request to "${CTX:proxyContext}/chat/completions" until status 200 with body:
      """
      {"model":"route-model","messages":[{"role":"user","content":"routed to the target"}]}
      """
    When I send a "GET" request to the "capture" service at "/test/captured?path=/target/v1/messages"
    Then the response status code should be 200
    And the JSON response field "path" should be "/target/v1/messages"
    And the JSON response field "body" should contain "routed to the target"
    When I set header "x-provider" to "other"
    And I send a "POST" request to "${CTX:proxyContext}/chat/completions" with body:
      """
      {"model":"route-model","messages":[{"role":"user","content":"left untranslated"}]}
      """
    Then the response status code should be 200
    And the JSON response field "path" should be "/other/chat/completions"
    And the JSON response field "body" should contain "left untranslated"
    When I delete the LLM proxy "${CTX:proxyName}"
    Then the response should be successful
    When I delete the LLM provider "${CTX:otherName}"
    Then the response should be successful
    When I delete the LLM provider "${CTX:targetName}"
    Then the response should be successful
    When I delete the LLM provider "${CTX:primaryName}"
    Then the response should be successful

  Scenario: Malformed and unusual message parts are skipped while the rest of the request is translated
    Given I generate a unique resource name from "o2a-edge-provider" and store it as "providerName"
    And I generate a unique API context from "/o2a-edge-provider" and store it as "providerContext"
    And I generate a unique resource name from "o2a-edge-proxy" and store it as "proxyName"
    And I generate a unique API context from "/o2a-edge-proxy" and store it as "proxyContext"
    When I create LLM provider from "resources/templates/llm-provider.yaml" with values:
      | apiVersion         | ${CTX:gatewaySpecVersion} |
      | name               | ${CTX:providerName}       |
      | displayName        | O2A-Edge-Provider         |
      | version            | v1.0                      |
      | template           | openai                    |
      | spec.context       | ${CTX:providerContext}    |
      | spec.upstream.url  | ${CTX:captureUpstream}    |
      | accessControl.mode | allow_all                 |
    Then the response status code should be 201
    When I create LLM proxy from "resources/templates/llm-proxy.yaml" with values:
      | apiVersion    | ${CTX:gatewaySpecVersion}                                                                                                                                        |
      | name          | ${CTX:proxyName}                                                                                                                                                 |
      | displayName   | O2A-Edge-Proxy                                                                                                                                                   |
      | version       | v1.0                                                                                                                                                             |
      | context       | ${CTX:proxyContext}                                                                                                                                              |
      | provider.id   | ${CTX:providerName}                                                                                                                                              |
      | spec.policies | [{"name":"openai-to-anthropic-transformer","version":"v0","paths":[{"path":"/chat/completions","methods":["POST"],"params":{"model":"claude-fallback-model"}}]}] |
    Then the response status code should be 201
    And I send a "POST" request to "${CTX:proxyContext}/chat/completions" until status 200 with body:
      """
      {"model":"claude-edge-model","messages":[42,{"role":"system","content":[{"type":"image_url"},{"type":"text","text":"Edge system."}]},{"role":"developer","content":7},{"role":"user","content":[5,{"text":"no type"},{"type":"image_url","image_url":"x"},{"type":"image_url","image_url":{"url":""}},{"type":"image_url","image_url":{"url":"data:image/png;base64"}}]},{"role":"user","content":9},{"role":"assistant","content":"Sure thing."},{"role":"assistant","content":[]},{"role":"assistant","content":"Calling.","tool_calls":[7,{"id":"call_a","type":"function"},{"id":"call_b","type":"function","function":{"name":"lookup","arguments":"not json"}}]},{"role":"tool","tool_call_id":"call_b","content":"looked up"},42,{"role":"user","content":"Go on."}],"tools":[3,{"type":"function"},{"type":"function","function":{"name":"lookup"}}],"tool_choice":"something-else"}
      """
    When I send a "GET" request to the "capture" service at "/test/captured?path=/v1/messages"
    Then the response status code should be 200
    And the JSON response field "body" should contain "Edge system."
    And the JSON response field "body" should contain "Sure thing."
    And the JSON response field "body" should contain "tool_use"
    And the JSON response field "body" should contain "auto"
    When I delete the LLM proxy "${CTX:proxyName}"
    Then the response should be successful
    When I delete the LLM provider "${CTX:providerName}"
    Then the response should be successful

  # ---- generated coverage scenarios: end ----
