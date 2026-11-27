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

@openai-to-gemini-transformer
Feature: OpenAI to Gemini transformer
  As an API consumer
  I want to call a Gemini upstream with OpenAI Chat Completions requests
  So that clients written for OpenAI work unchanged against Gemini

  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"
    And I resolve the "capture" service URL at "" and store it as "captureUpstream"

  Scenario: A Gemini generateContent response is returned in the OpenAI chat completion shape
    Given I generate a unique resource name from "o2g-response-provider" and store it as "providerName"
    And I generate a unique API context from "/o2g-response-provider" and store it as "providerContext"
    And I generate a unique resource name from "o2g-response-proxy" and store it as "proxyName"
    And I generate a unique API context from "/o2g-response-proxy" and store it as "proxyContext"
    When I create LLM provider from "resources/templates/llm-provider.yaml" with values:
      | apiVersion         | ${CTX:gatewaySpecVersion}    |
      | name               | ${CTX:providerName}          |
      | displayName        | O2G-Response-Provider        |
      | version            | v1.0                         |
      | template           | openai                       |
      | spec.context       | ${CTX:providerContext}       |
      | spec.upstream.url  | http://testbench:3008/gemini |
      | accessControl.mode | allow_all                    |
    Then the response status code should be 201
    # The testbench serves generateContent under /v1, so the policy's apiVersion is set to v1.
    When I create LLM proxy from "resources/templates/llm-proxy.yaml" with values:
      | apiVersion    | ${CTX:gatewaySpecVersion}                                                                                                                                                   |
      | name          | ${CTX:proxyName}                                                                                                                                                            |
      | displayName   | O2G-Response-Proxy                                                                                                                                                          |
      | version       | v1.0                                                                                                                                                                        |
      | context       | ${CTX:proxyContext}                                                                                                                                                         |
      | provider.id   | ${CTX:providerName}                                                                                                                                                         |
      | spec.policies | [{"name":"openai-to-gemini-transformer","version":"v0","paths":[{"path":"/chat/completions","methods":["POST"],"params":{"model":"gemini-fallback-model","apiVersion":"v1"}}]}] |
    Then the response status code should be 201
    And I send a "POST" request to "${CTX:proxyContext}/chat/completions" until status 200 with body:
      """
      {"model":"gemini-2.5-flash","messages":[{"role":"user","content":"Hello"}]}
      """
    Then the response should be valid JSON
    And the JSON response field "object" should be "chat.completion"
    And the JSON response field "model" should be "gemini-2.5-flash"
    And the JSON response field "choices[0].message.role" should be "assistant"
    And the JSON response field "choices[0].message.content" should be "Hello! How can I assist you today?"
    And the JSON response field "choices[0].finish_reason" should be "stop"
    And the JSON response field "usage.prompt_tokens" should be 100
    And the JSON response field "usage.completion_tokens" should be 100
    And the JSON response field "usage.total_tokens" should be 200
    When I delete the LLM proxy "${CTX:proxyName}"
    Then the response should be successful
    When I delete the LLM provider "${CTX:providerName}"
    Then the response should be successful

  Scenario: The upstream receives a Gemini generateContent request for the resolved model
    Given I generate a unique resource name from "o2g-request-provider" and store it as "providerName"
    And I generate a unique API context from "/o2g-request-provider" and store it as "providerContext"
    And I generate a unique resource name from "o2g-request-proxy" and store it as "proxyName"
    And I generate a unique API context from "/o2g-request-proxy" and store it as "proxyContext"
    When I create LLM provider from "resources/templates/llm-provider.yaml" with values:
      | apiVersion         | ${CTX:gatewaySpecVersion} |
      | name               | ${CTX:providerName}       |
      | displayName        | O2G-Request-Provider      |
      | version            | v1.0                      |
      | template           | openai                    |
      | spec.context       | ${CTX:providerContext}    |
      | spec.upstream.url  | ${CTX:captureUpstream}    |
      | accessControl.mode | allow_all                 |
    Then the response status code should be 201
    When I create LLM proxy from "resources/templates/llm-proxy.yaml" with values:
      | apiVersion    | ${CTX:gatewaySpecVersion}                                                                                                                        |
      | name          | ${CTX:proxyName}                                                                                                                                 |
      | displayName   | O2G-Request-Proxy                                                                                                                                |
      | version       | v1.0                                                                                                                                             |
      | context       | ${CTX:proxyContext}                                                                                                                              |
      | provider.id   | ${CTX:providerName}                                                                                                                              |
      | spec.policies | [{"name":"openai-to-gemini-transformer","version":"v0","paths":[{"path":"/chat/completions","methods":["POST"],"params":{"model":"gemini-2.5-pro"}}]}] |
    Then the response status code should be 201
    # The request names no model, so the fallback model goes into the path under the default
    # v1beta API version.
    And I send a "POST" request to "${CTX:proxyContext}/chat/completions" until status 200 with body:
      """
      {"messages":[{"role":"system","content":"Answer briefly."},{"role":"user","content":"Hello"}],"max_tokens":64,"temperature":0.2}
      """
    When I send a "GET" request to the "capture" service at "/test/captured?path=/v1beta/models/gemini-2.5-pro:generateContent"
    Then the response status code should be 200
    And the JSON response field "method" should be "POST"
    And the JSON response field "path" should be "/v1beta/models/gemini-2.5-pro:generateContent"
    And the JSON response field "body" should contain "systemInstruction"
    And the JSON response field "body" should contain "Answer briefly."
    And the JSON response field "body" should contain "contents"
    And the JSON response field "body" should contain "generationConfig"
    And the JSON response field "body" should contain "maxOutputTokens"
    And the response body should not contain "max_tokens"
    When I delete the LLM proxy "${CTX:proxyName}"
    Then the response should be successful
    When I delete the LLM provider "${CTX:providerName}"
    Then the response should be successful

  # The response must match the expected error response recorded from the policy before a
  # change (resources/expected-error-responses), so a change a client could observe fails.
  Scenario: openai-to-gemini-transformer rejects an empty request body
    Given I generate a unique value from "compat-og-empty" and store it as "apiName"
    And I generate a unique API version from "compat-og-empty" and store it as "apiVersion"
    And I generate a unique API context from "/compat-og-empty" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3002 |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"POST","path":"/chat/completions","policies":[{"name":"openai-to-gemini-transformer","version":"v0","params":{"model":"gemini-1.5-flash-002"}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat/completions" with body:
      """
      """
    Then the response status code should be 400
    And the response should match the expected error response "openai-to-gemini-transformer-empty-body"

  Scenario: A Gemini event stream is returned as an OpenAI chat completion chunk stream
    Given I generate a unique resource name from "o2g-stream-provider" and store it as "providerName"
    And I generate a unique API context from "/o2g-stream-provider" and store it as "providerContext"
    And I generate a unique resource name from "o2g-stream-proxy" and store it as "proxyName"
    And I generate a unique API context from "/o2g-stream-proxy" and store it as "proxyContext"
    When I create LLM provider from "resources/templates/llm-provider.yaml" with values:
      | apiVersion         | ${CTX:gatewaySpecVersion}    |
      | name               | ${CTX:providerName}          |
      | displayName        | O2G-Stream-Provider          |
      | version            | v1.0                         |
      | template           | openai                       |
      | spec.context       | ${CTX:providerContext}       |
      | spec.upstream.url  | http://testbench:3008/gemini |
      | accessControl.mode | allow_all                    |
    Then the response status code should be 201
    When I create LLM proxy from "resources/templates/llm-proxy.yaml" with values:
      | apiVersion    | ${CTX:gatewaySpecVersion}                                                                                                                                                 |
      | name          | ${CTX:proxyName}                                                                                                                                                          |
      | displayName   | O2G-Stream-Proxy                                                                                                                                                          |
      | version       | v1.0                                                                                                                                                                      |
      | context       | ${CTX:proxyContext}                                                                                                                                                       |
      | provider.id   | ${CTX:providerName}                                                                                                                                                       |
      | spec.policies | [{"name":"openai-to-gemini-transformer","version":"v0","paths":[{"path":"/chat/completions","methods":["POST"],"params":{"model":"gemini-fallback-model","apiVersion":"v1"}}]}] |
    Then the response status code should be 201
    And I send a "POST" request to "${CTX:proxyContext}/chat/completions" until status 200 with body:
      """
      {"model":"gemini-2.5-flash","messages":[{"role":"user","content":"Hello"}]}
      """
    # "stream": true sends the request to streamGenerateContent with alt=sse; the mock answers with
    # one frame per word, the last carrying finishReason STOP and the usage metadata.
    When I send a "POST" request to "${CTX:proxyContext}/chat/completions" with body:
      """
      {"model":"gemini-2.5-flash","stream":true,"messages":[{"role":"user","content":"Hello"}]}
      """
    Then the response status code should be 200
    And the response header "content-type" should contain "text/event-stream"
    And the response body should contain "chat.completion.chunk"
    And the response body should contain "gemini-2.5-flash"
    And the response body should contain "assistant"
    And the response body should contain "streamed "
    And the response body should contain "model."
    And the response body should contain "finish_reason"
    And the response body should contain "prompt_tokens"
    And the response body should contain "data: [DONE]"
    And the response body should not contain "candidates"
    And the response body should not contain "usageMetadata"
    When I delete the LLM proxy "${CTX:proxyName}"
    Then the response should be successful
    When I delete the LLM provider "${CTX:providerName}"
    Then the response should be successful

  Scenario: A Gemini stream that fails mid-way ends with an OpenAI error event and no DONE
    Given I generate a unique resource name from "o2g-stream-error-provider" and store it as "providerName"
    And I generate a unique API context from "/o2g-stream-error-provider" and store it as "providerContext"
    And I generate a unique resource name from "o2g-stream-error-proxy" and store it as "proxyName"
    And I generate a unique API context from "/o2g-stream-error-proxy" and store it as "proxyContext"
    When I create LLM provider from "resources/templates/llm-provider.yaml" with values:
      | apiVersion         | ${CTX:gatewaySpecVersion}    |
      | name               | ${CTX:providerName}          |
      | displayName        | O2G-Stream-Error-Provider    |
      | version            | v1.0                         |
      | template           | openai                       |
      | spec.context       | ${CTX:providerContext}       |
      | spec.upstream.url  | http://testbench:3008/gemini |
      | accessControl.mode | allow_all                    |
    Then the response status code should be 201
    When I create LLM proxy from "resources/templates/llm-proxy.yaml" with values:
      | apiVersion    | ${CTX:gatewaySpecVersion}                                                                                                                                                 |
      | name          | ${CTX:proxyName}                                                                                                                                                          |
      | displayName   | O2G-Stream-Error-Proxy                                                                                                                                                    |
      | version       | v1.0                                                                                                                                                                      |
      | context       | ${CTX:proxyContext}                                                                                                                                                       |
      | provider.id   | ${CTX:providerName}                                                                                                                                                       |
      | spec.policies | [{"name":"openai-to-gemini-transformer","version":"v0","paths":[{"path":"/chat/completions","methods":["POST"],"params":{"model":"gemini-fallback-model","apiVersion":"v1"}}]}] |
    Then the response status code should be 201
    And I send a "POST" request to "${CTX:proxyContext}/chat/completions" until status 200 with body:
      """
      {"model":"gemini-2.5-flash","messages":[{"role":"user","content":"Hello"}]}
      """
    # STREAM_ERROR in the request makes the mock end the stream with a Gemini error frame.
    When I send a "POST" request to "${CTX:proxyContext}/chat/completions" with body:
      """
      {"model":"gemini-2.5-flash","stream":true,"messages":[{"role":"user","content":"STREAM_ERROR"}]}
      """
    Then the response header "content-type" should contain "text/event-stream"
    And the response body should contain "chat.completion.chunk"
    And the response body should contain "UNAVAILABLE"
    And the response body should contain "The model is overloaded."
    And the response body should contain "503"
    And the response body should not contain "[DONE]"
    When I delete the LLM proxy "${CTX:proxyName}"
    Then the response should be successful
    When I delete the LLM provider "${CTX:providerName}"
    Then the response should be successful

  Scenario: Tools, tool choice, images, tool turns and sampling fields are translated for Gemini
    Given I generate a unique resource name from "o2g-tools-provider" and store it as "providerName"
    And I generate a unique API context from "/o2g-tools-provider" and store it as "providerContext"
    And I generate a unique resource name from "o2g-tools-proxy" and store it as "proxyName"
    And I generate a unique API context from "/o2g-tools-proxy" and store it as "proxyContext"
    When I create LLM provider from "resources/templates/llm-provider.yaml" with values:
      | apiVersion         | ${CTX:gatewaySpecVersion} |
      | name               | ${CTX:providerName}       |
      | displayName        | O2G-Tools-Provider        |
      | version            | v1.0                      |
      | template           | openai                    |
      | spec.context       | ${CTX:providerContext}    |
      | spec.upstream.url  | ${CTX:captureUpstream}    |
      | accessControl.mode | allow_all                 |
    Then the response status code should be 201
    When I create LLM proxy from "resources/templates/llm-proxy.yaml" with values:
      | apiVersion    | ${CTX:gatewaySpecVersion}                                                                                                                         |
      | name          | ${CTX:proxyName}                                                                                                                                  |
      | displayName   | O2G-Tools-Proxy                                                                                                                                   |
      | version       | v1.0                                                                                                                                              |
      | context       | ${CTX:proxyContext}                                                                                                                               |
      | provider.id   | ${CTX:providerName}                                                                                                                               |
      | spec.policies | [{"name":"openai-to-gemini-transformer","version":"v0","paths":[{"path":"/chat/completions","methods":["POST"],"params":{"model":"gemini-2.5-pro"}}]}] |
    Then the response status code should be 201
    # A developer message joins the system instruction, image parts become inlineData (data URL)
    # and fileData (remote URL, MIME type from the extension), the assistant tool call becomes a
    # functionCall part, tool messages become functionResponse parts, and the sampling fields move
    # into generationConfig. tool_choice "required" becomes function calling mode ANY.
    And I send a "POST" request to "${CTX:proxyContext}/chat/completions" until status 200 with body:
      """
      {"max_completion_tokens":128,"temperature":0.2,"top_p":0.9,"n":1,"seed":7,"frequency_penalty":0.1,"presence_penalty":0.2,"stop":["END","STOP"],"messages":[{"role":"developer","content":[{"type":"text","text":"Use metric units."}]},{"role":"user","content":[{"type":"text","text":"What is in these pictures?"},{"type":"image_url","image_url":{"url":"data:image/png;base64,iVBORw0KGgo="}},{"type":"image_url","image_url":{"url":"https://example.com/cat.webp"}},{"type":"image_url","image_url":{"url":"https://example.com/dog.gif"}},{"type":"image_url","image_url":{"url":"https://example.com/bird.jpg"}}]},{"role":"assistant","content":"Checking the weather.","tool_calls":[{"id":"call_weather","type":"function","function":{"name":"get_weather","arguments":"{\"city\":\"Colombo\"}"}},{"id":"call_time","type":"function","function":{"name":"get_time","arguments":""}}]},{"role":"tool","tool_call_id":"get_weather","content":"31C and sunny"},{"role":"tool","tool_call_id":"get_time","content":[{"type":"text","text":"10:00"}]},{"role":"user","content":"Summarise."}],"tools":[{"type":"function","function":{"name":"get_weather","description":"Weather for a city","parameters":{"type":"object","properties":{"city":{"type":"string"}}}}},{"type":"function","function":{"name":"get_time"}}],"tool_choice":"required"}
      """
    When I send a "GET" request to the "capture" service at "/test/captured?path=/v1beta/models/gemini-2.5-pro:generateContent"
    Then the response status code should be 200
    And the JSON response field "body" should contain "systemInstruction"
    And the JSON response field "body" should contain "Use metric units."
    And the JSON response field "body" should contain "inlineData"
    And the JSON response field "body" should contain "iVBORw0KGgo="
    And the JSON response field "body" should contain "fileData"
    And the JSON response field "body" should contain "https://example.com/cat.webp"
    And the JSON response field "body" should contain "image/webp"
    And the JSON response field "body" should contain "image/gif"
    And the JSON response field "body" should contain "image/jpeg"
    And the JSON response field "body" should contain "functionCall"
    And the JSON response field "body" should contain "Colombo"
    And the JSON response field "body" should contain "functionResponse"
    And the JSON response field "body" should contain "31C and sunny"
    And the JSON response field "body" should contain "10:00"
    And the JSON response field "body" should contain "functionDeclarations"
    And the JSON response field "body" should contain "Weather for a city"
    And the JSON response field "body" should contain "functionCallingConfig"
    And the JSON response field "body" should contain "ANY"
    And the JSON response field "body" should contain "stopSequences"
    And the JSON response field "body" should contain "topP"
    And the JSON response field "body" should contain "candidateCount"
    And the JSON response field "body" should contain "seed"
    And the JSON response field "body" should contain "frequencyPenalty"
    And the JSON response field "body" should contain "presencePenalty"
    And the response body should not contain "tool_calls"
    And the response body should not contain "image_url"
    And the response body should not contain "max_completion_tokens"
    # tool_choice "none" drops the declarations and sets mode NONE.
    When I send a "POST" request to "${CTX:proxyContext}/chat/completions" with body:
      """
      {"messages":[{"role":"user","content":"Hi"}],"tools":[{"type":"function","function":{"name":"get_weather"}}],"tool_choice":"none"}
      """
    Then the response status code should be 200
    When I send a "GET" request to the "capture" service at "/test/captured?path=/v1beta/models/gemini-2.5-pro:generateContent"
    Then the response status code should be 200
    And the JSON response field "body" should contain "NONE"
    And the response body should not contain "functionDeclarations"
    # A named function choice restricts mode ANY to that function; "auto" becomes mode AUTO.
    When I send a "POST" request to "${CTX:proxyContext}/chat/completions" with body:
      """
      {"messages":[{"role":"user","content":"Hi"}],"tools":[{"type":"function","function":{"name":"get_weather"}}],"tool_choice":{"type":"function","function":{"name":"get_weather"}}}
      """
    Then the response status code should be 200
    When I send a "GET" request to the "capture" service at "/test/captured?path=/v1beta/models/gemini-2.5-pro:generateContent"
    Then the response status code should be 200
    And the JSON response field "body" should contain "allowedFunctionNames"
    When I send a "POST" request to "${CTX:proxyContext}/chat/completions" with body:
      """
      {"messages":[{"role":"user","content":"Hi"}],"tools":[{"type":"function","function":{"name":"get_weather"}}],"tool_choice":"auto"}
      """
    Then the response status code should be 200
    When I send a "GET" request to the "capture" service at "/test/captured?path=/v1beta/models/gemini-2.5-pro:generateContent"
    Then the response status code should be 200
    And the JSON response field "body" should contain "AUTO"
    # A streaming request goes to streamGenerateContent instead, under the requested model.
    When I send a "POST" request to "${CTX:proxyContext}/chat/completions" with body:
      """
      {"model":"gemini-2.5-flash","stream":true,"messages":[{"role":"user","content":"Hi"}]}
      """
    When I send a "GET" request to the "capture" service at "/test/captured?path=/v1beta/models/gemini-2.5-flash:streamGenerateContent"
    Then the response status code should be 200
    And the JSON response field "path" should be "/v1beta/models/gemini-2.5-flash:streamGenerateContent"
    When I delete the LLM proxy "${CTX:proxyName}"
    Then the response should be successful
    When I delete the LLM provider "${CTX:providerName}"
    Then the response should be successful

  Scenario: A request the policy cannot translate is rejected with 400
    Given I generate a unique resource name from "o2g-invalid-provider" and store it as "providerName"
    And I generate a unique API context from "/o2g-invalid-provider" and store it as "providerContext"
    And I generate a unique resource name from "o2g-invalid-proxy" and store it as "proxyName"
    And I generate a unique API context from "/o2g-invalid-proxy" and store it as "proxyContext"
    When I create LLM provider from "resources/templates/llm-provider.yaml" with values:
      | apiVersion         | ${CTX:gatewaySpecVersion}    |
      | name               | ${CTX:providerName}          |
      | displayName        | O2G-Invalid-Provider         |
      | version            | v1.0                         |
      | template           | openai                       |
      | spec.context       | ${CTX:providerContext}       |
      | spec.upstream.url  | http://testbench:3008/gemini |
      | accessControl.mode | allow_all                    |
    Then the response status code should be 201
    # No fallback model is configured, so the request has to name one.
    When I create LLM proxy from "resources/templates/llm-proxy.yaml" with values:
      | apiVersion    | ${CTX:gatewaySpecVersion}                                                                                                                   |
      | name          | ${CTX:proxyName}                                                                                                                            |
      | displayName   | O2G-Invalid-Proxy                                                                                                                           |
      | version       | v1.0                                                                                                                                        |
      | context       | ${CTX:proxyContext}                                                                                                                         |
      | provider.id   | ${CTX:providerName}                                                                                                                         |
      | spec.policies | [{"name":"openai-to-gemini-transformer","version":"v0","paths":[{"path":"/chat/completions","methods":["POST"],"params":{"apiVersion":"v1"}}]}] |
    Then the response status code should be 201
    And I send a "POST" request to "${CTX:proxyContext}/chat/completions" until status 200 with body:
      """
      {"model":"gemini-2.5-flash","messages":[{"role":"user","content":"Hello"}]}
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
    Given I generate a unique resource name from "o2g-errors-provider" and store it as "providerName"
    And I generate a unique API context from "/o2g-errors-provider" and store it as "providerContext"
    And I generate a unique resource name from "o2g-errors-proxy" and store it as "proxyName"
    And I generate a unique API context from "/o2g-errors-proxy" and store it as "proxyContext"
    And I resolve the "fault-injection" service URL at "/${CTX:providerName}" and store it as "faultUpstream"
    When I send a "PUT" request to the "fault-injection" service at "/test/scripts/${CTX:providerName}" with body:
      """
      {"forwardPort":3008,"steps":[]}
      """
    Then the response status code should be 200
    When I create LLM provider from "resources/templates/llm-provider.yaml" with values:
      | apiVersion         | ${CTX:gatewaySpecVersion}   |
      | name               | ${CTX:providerName}         |
      | displayName        | O2G-Errors-Provider         |
      | version            | v1.0                        |
      | template           | openai                      |
      | spec.context       | ${CTX:providerContext}      |
      | spec.upstream.url  | ${CTX:faultUpstream}/gemini |
      | accessControl.mode | allow_all                   |
    Then the response status code should be 201
    When I create LLM proxy from "resources/templates/llm-proxy.yaml" with values:
      | apiVersion    | ${CTX:gatewaySpecVersion}                                                                                                                                            |
      | name          | ${CTX:proxyName}                                                                                                                                                     |
      | displayName   | O2G-Errors-Proxy                                                                                                                                                     |
      | version       | v1.0                                                                                                                                                                 |
      | context       | ${CTX:proxyContext}                                                                                                                                                  |
      | provider.id   | ${CTX:providerName}                                                                                                                                                  |
      | spec.policies | [{"name":"openai-to-gemini-transformer","version":"v0","paths":[{"path":"/chat/completions","methods":["POST"],"params":{"model":"gemini-2.5-flash","apiVersion":"v1"}}]}] |
    Then the response status code should be 201
    And I send a "POST" request to "${CTX:proxyContext}/chat/completions" until status 200 with body:
      """
      {"messages":[{"role":"user","content":"Hello"}]}
      """
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

  Scenario Outline: A scripted O2G reply is translated into the OpenAI shape (<case>)
    Given I generate a unique value from "o2g-fake-<case>" and store it as "fakeName"
    And I generate a unique API context from "/o2g-fake-<case>" and store it as "fakeContext"
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
    And I generate a unique resource name from "o2g-scripted-provider" and store it as "providerName"
    And I generate a unique API context from "/o2g-scripted-provider" and store it as "providerContext"
    And I generate a unique resource name from "o2g-scripted-proxy" and store it as "proxyName"
    And I generate a unique API context from "/o2g-scripted-proxy" and store it as "proxyContext"
    When I create LLM provider from "resources/templates/llm-provider.yaml" with values:
      | apiVersion         | ${CTX:gatewaySpecVersion}                          |
      | name               | ${CTX:providerName}                                |
      | displayName        | O2G-Scripted-Provider                              |
      | version            | v1.0                                               |
      | template           | openai                                             |
      | spec.context       | ${CTX:providerContext}                             |
      | spec.upstream.url  | http://gateway-runtime:8080${CTX:fakeContext}/v1.0 |
      | accessControl.mode | allow_all                                          |
    Then the response status code should be 201
    When I create LLM proxy from "resources/templates/llm-proxy.yaml" with values:
      | apiVersion    | ${CTX:gatewaySpecVersion}                                                                                                                               |
      | name          | ${CTX:proxyName}                                                                                                                                        |
      | displayName   | O2G-Scripted-Proxy                                                                                                                                      |
      | version       | v1.0                                                                                                                                                    |
      | context       | ${CTX:proxyContext}                                                                                                                                     |
      | provider.id   | ${CTX:providerName}                                                                                                                                     |
      | spec.policies | [{"name":"openai-to-gemini-transformer","version":"v0","paths":[{"path":"/chat/completions","methods":["POST"],"params":{"model":"gemini-scripted"}}]}] |
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
      | case                   | status | contentType       | body                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       | request                                                                                  | expected | expect1                       | expect2    | expect3          | absent          |
      | tool-calls             | 200    | application/json  | {\\"responseId\\":\\"resp-tools\\",\\"candidates\\":[{\\"content\\":{\\"parts\\":[{\\"text\\":\\"Let me check.\\"},{\\"functionCall\\":{\\"name\\":\\"get_weather\\",\\"args\\":{\\"city\\":\\"Colombo\\"}}},{\\"functionCall\\":{\\"name\\":\\"get_time\\"}}]},\\"finishReason\\":\\"STOP\\"},{\\"content\\":{\\"parts\\":[{\\"text\\":\\"Alt\\"}]},\\"finishReason\\":\\"MAX_TOKENS\\"},{\\"content\\":{\\"parts\\":[{\\"text\\":\\"Blocked\\"}]},\\"finishReason\\":\\"SAFETY\\"},{\\"content\\":{\\"parts\\":[{\\"text\\":\\"Other\\"}]},\\"finishReason\\":\\"OTHER\\"}],\\"usageMetadata\\":{\\"promptTokenCount\\":10,\\"candidatesTokenCount\\":5,\\"totalTokenCount\\":15,\\"cachedContentTokenCount\\":3,\\"thoughtsTokenCount\\":2}}                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            | {"model":"gemini-scripted","messages":[{"role":"user","content":"Hello"}]}               | 200      | chatcmpl-resp-tools           | tool_calls | reasoning_tokens | candidates      |
      | not-json               | 200    | text/plain        | plain upstream text                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        | {"model":"gemini-scripted","messages":[{"role":"user","content":"Hello"}]}               | 200      | plain                         | upstream   | text             | chat.completion |
      | event-stream-truncated | 200    | text/event-stream | data: {\\"responseId\\":\\"r-stream\\",\\"modelVersion\\":\\"gemini-stream-model\\",\\"candidates\\":[{\\"content\\":{\\"parts\\":[{\\"text\\":\\"Checking\\"},{\\"text\\":\\"hidden thought\\",\\"thought\\":true},{\\"functionCall\\":{\\"name\\":\\"get_weather\\",\\"args\\":{\\"city\\":\\"Colombo\\"}}},{\\"functionCall\\":{\\"name\\":\\"get_time\\"}}]},\\"index\\":0}],\\"usageMetadata\\":{\\"promptTokenCount\\":5,\\"candidatesTokenCount\\":3,\\"totalTokenCount\\":8,\\"cachedContentTokenCount\\":2,\\"thoughtsTokenCount\\":1}}\\u000a\\u000a: keep-alive\\u000a\\u000adata: {\\"promptFeedback\\":{\\"blockReason\\":\\"SAFETY\\"}}\\u000a\\u000adata: {\\"promptFeedback\\":{\\"blockReason\\":\\"SAFETY\\"}}\\u000a\\u000aevent: message\\u000d\\u000adata: {\\"responseId\\":\\"r-other\\",\\"candidates\\":[{\\"content\\":{\\"parts\\":[{\\"text\\":\\"A\\"}]},\\"finishReason\\":\\"STOP\\"},{\\"content\\":{\\"parts\\":[{\\"text\\":\\"B\\"}]},\\"finishReason\\":\\"MAX_TOKENS\\"}]}\\u000d\\u000a\\u000d\\u000a\\u000adata: {\\"candidates\\":[{\\"content\\":{\\"parts\\":[{\\"text\\":\\"x\\"}]},\\u000adata: \\"finishReason\\":\\"RECITATION\\",\\"index\\":2}]}\\u000a\\u000adata: {\\"candidates\\":[{\\"content\\":{\\"parts\\":[{\\"te | {"model":"gemini-scripted","messages":[{"role":"user","content":"Hello"}],"stream":true} | 200      | chatcmpl-r-stream             | tool_calls | content_filter   | candidates      |
      | malformed-event        | 200    | text/event-stream | data: {not json\\u000a\\u000a                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              | {"model":"gemini-scripted","messages":[{"role":"user","content":"Hello"}],"stream":true} | 200      | malformed Gemini stream event | error      | data:            | [DONE]          |
      | error-event            | 500    | text/event-stream | data: {\\"error\\":{}}\\u000a\\u000a                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       | {"model":"gemini-scripted","messages":[{"role":"user","content":"Hello"}],"stream":true} | 500      | gemini stream error           | 500        | error            | [DONE]          |
  Scenario Outline: A scripted O2G error is rewritten as an OpenAI error object (<case>)
    Given I generate a unique value from "o2g-fake-<case>" and store it as "fakeName"
    And I generate a unique API context from "/o2g-fake-<case>" and store it as "fakeContext"
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
    And I generate a unique resource name from "o2g-scripted-provider" and store it as "providerName"
    And I generate a unique API context from "/o2g-scripted-provider" and store it as "providerContext"
    And I generate a unique resource name from "o2g-scripted-proxy" and store it as "proxyName"
    And I generate a unique API context from "/o2g-scripted-proxy" and store it as "proxyContext"
    When I create LLM provider from "resources/templates/llm-provider.yaml" with values:
      | apiVersion         | ${CTX:gatewaySpecVersion}                          |
      | name               | ${CTX:providerName}                                |
      | displayName        | O2G-Scripted-Provider                              |
      | version            | v1.0                                               |
      | template           | openai                                             |
      | spec.context       | ${CTX:providerContext}                             |
      | spec.upstream.url  | http://gateway-runtime:8080${CTX:fakeContext}/v1.0 |
      | accessControl.mode | allow_all                                          |
    Then the response status code should be 201
    When I create LLM proxy from "resources/templates/llm-proxy.yaml" with values:
      | apiVersion    | ${CTX:gatewaySpecVersion}                                                                                                                               |
      | name          | ${CTX:proxyName}                                                                                                                                        |
      | displayName   | O2G-Scripted-Proxy                                                                                                                                      |
      | version       | v1.0                                                                                                                                                    |
      | context       | ${CTX:proxyContext}                                                                                                                                     |
      | provider.id   | ${CTX:providerName}                                                                                                                                     |
      | spec.policies | [{"name":"openai-to-gemini-transformer","version":"v0","paths":[{"path":"/chat/completions","methods":["POST"],"params":{"model":"gemini-scripted"}}]}] |
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
      | case                    | status | contentType      | body                                                                                                  | request                                                                                  | expected | errType            | errMessage     | errCode | gone         |
      | error-envelope          | 400    | application/json | {\\"error\\":{\\"code\\":400,\\"message\\":\\"Bad model name\\",\\"status\\":\\"INVALID_ARGUMENT\\"}} | {"model":"gemini-scripted","messages":[{"role":"user","content":"Hello"}]}               | 400      | INVALID_ARGUMENT   | Bad model name | 400     | error.status |
      | streamed-error-envelope | 429    | application/json | {\\"error\\":{\\"code\\":429,\\"message\\":\\"Quota gone\\",\\"status\\":\\"RESOURCE_EXHAUSTED\\"}}   | {"model":"gemini-scripted","messages":[{"role":"user","content":"Hello"}],"stream":true} | 429      | RESOURCE_EXHAUSTED | Quota gone     | 429     | error.status |
  Scenario Outline: A scripted O2G stream is translated and ends as expected (<case>)
    Given I generate a unique value from "o2g-fake-<case>" and store it as "fakeName"
    And I generate a unique API context from "/o2g-fake-<case>" and store it as "fakeContext"
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
    And I generate a unique resource name from "o2g-scripted-provider" and store it as "providerName"
    And I generate a unique API context from "/o2g-scripted-provider" and store it as "providerContext"
    And I generate a unique resource name from "o2g-scripted-proxy" and store it as "proxyName"
    And I generate a unique API context from "/o2g-scripted-proxy" and store it as "proxyContext"
    When I create LLM provider from "resources/templates/llm-provider.yaml" with values:
      | apiVersion         | ${CTX:gatewaySpecVersion}                          |
      | name               | ${CTX:providerName}                                |
      | displayName        | O2G-Scripted-Provider                              |
      | version            | v1.0                                               |
      | template           | openai                                             |
      | spec.context       | ${CTX:providerContext}                             |
      | spec.upstream.url  | http://gateway-runtime:8080${CTX:fakeContext}/v1.0 |
      | accessControl.mode | allow_all                                          |
    Then the response status code should be 201
    When I create LLM proxy from "resources/templates/llm-proxy.yaml" with values:
      | apiVersion    | ${CTX:gatewaySpecVersion}                                                                                                                               |
      | name          | ${CTX:proxyName}                                                                                                                                        |
      | displayName   | O2G-Scripted-Proxy                                                                                                                                      |
      | version       | v1.0                                                                                                                                                    |
      | context       | ${CTX:proxyContext}                                                                                                                                     |
      | provider.id   | ${CTX:providerName}                                                                                                                                     |
      | spec.policies | [{"name":"openai-to-gemini-transformer","version":"v0","paths":[{"path":"/chat/completions","methods":["POST"],"params":{"model":"gemini-scripted"}}]}] |
    Then the response status code should be 201
    And I send a "POST" request to "${CTX:proxyContext}/chat/completions" until status <expected> with body:
      """
      <request>
      """
    Then the response body should contain "<expect1>"
    And the response body should contain "<expect2>"
    And the response body should contain "<expect3>"
    And the response body should not contain "<absent>"
    And the response body should match pattern "<tail>"
    When I delete the LLM proxy "${CTX:proxyName}"
    Then the response should be successful
    When I delete the LLM provider "${CTX:providerName}"
    Then the response should be successful
    When I delete the API "${CTX:fakeName}"
    Then the response should be successful

    Examples:
      | case                  | status | contentType       | body                                                                                                                                                                                                                                                                                          | request                                                                                  | expected | expect1         | expect2 | expect3 | absent     | tail                          |
      | event-stream-complete | 200    | text/event-stream | data: {\\"responseId\\":\\"r-done\\",\\"candidates\\":[{\\"content\\":{\\"parts\\":[{\\"text\\":\\"Hello\\"}]}}]}\\u000a\\u000adata: {\\"responseId\\":\\"r-done\\",\\"candidates\\":[{\\"content\\":{\\"parts\\":[{\\"text\\":\\" there\\"}]},\\"finishReason\\":\\"STOP\\"}]}\\u000a\\u000a | {"model":"gemini-scripted","messages":[{"role":"user","content":"Hello"}],"stream":true} | 200      | chatcmpl-r-done | Hello   | there   | candidates | data: [[]DONE[]][[:space:]]*$ |

  Scenario: The translator runs only for the provider a header router selected for it
    Given I generate a unique resource name from "o2g-route-primary" and store it as "primaryName"
    And I generate a unique API context from "/o2g-route-primary" and store it as "primaryContext"
    And I generate a unique resource name from "o2g-route-target" and store it as "targetName"
    And I generate a unique API context from "/o2g-route-target" and store it as "targetContext"
    And I generate a unique resource name from "o2g-route-other" and store it as "otherName"
    And I generate a unique API context from "/o2g-route-other" and store it as "otherContext"
    And I generate a unique resource name from "o2g-route-proxy" and store it as "proxyName"
    And I generate a unique API context from "/o2g-route-proxy" and store it as "proxyContext"
    When I create LLM provider from "resources/templates/llm-provider.yaml" with values:
      | apiVersion         | ${CTX:gatewaySpecVersion}      |
      | name               | ${CTX:primaryName}             |
      | displayName        | O2G-Route-Primary              |
      | version            | v1.0                           |
      | template           | openai                         |
      | spec.context       | ${CTX:primaryContext}          |
      | spec.upstream.url  | ${CTX:captureUpstream}/primary |
      | accessControl.mode | allow_all                      |
    Then the response status code should be 201
    When I create LLM provider from "resources/templates/llm-provider.yaml" with values:
      | apiVersion         | ${CTX:gatewaySpecVersion}     |
      | name               | ${CTX:targetName}             |
      | displayName        | O2G-Route-Target              |
      | version            | v1.0                          |
      | template           | openai                        |
      | spec.context       | ${CTX:targetContext}          |
      | spec.upstream.url  | ${CTX:captureUpstream}/target |
      | accessControl.mode | allow_all                     |
    Then the response status code should be 201
    When I create LLM provider from "resources/templates/llm-provider.yaml" with values:
      | apiVersion         | ${CTX:gatewaySpecVersion}    |
      | name               | ${CTX:otherName}             |
      | displayName        | O2G-Route-Other              |
      | version            | v1.0                         |
      | template           | openai                       |
      | spec.context       | ${CTX:otherContext}          |
      | spec.upstream.url  | ${CTX:captureUpstream}/other |
      | accessControl.mode | allow_all                    |
    Then the response status code should be 201
    When I create LLM proxy from "resources/templates/llm-proxy.yaml" with values:
      | apiVersion               | ${CTX:gatewaySpecVersion}                                                                                                                                                                                                                                                                                                                                                                            |
      | name                     | ${CTX:proxyName}                                                                                                                                                                                                                                                                                                                                                                                     |
      | displayName              | O2G-Route-Proxy                                                                                                                                                                                                                                                                                                                                                                                      |
      | version                  | v1.0                                                                                                                                                                                                                                                                                                                                                                                                 |
      | context                  | ${CTX:proxyContext}                                                                                                                                                                                                                                                                                                                                                                                  |
      | provider.id              | ${CTX:primaryName}                                                                                                                                                                                                                                                                                                                                                                                   |
      | spec.additionalProviders | [{"id":"${CTX:targetName}","as":"target-provider"},{"id":"${CTX:otherName}","as":"other-provider"}]                                                                                                                                                                                                                                                                                                  |
      | spec.policies            | [{"name":"llm-header-router","version":"v0","paths":[{"path":"/chat/completions","methods":["POST"],"params":{"mappings":[{"headerValue":"target","provider":"target-provider"},{"headerValue":"other","provider":"other-provider"}]}}]},{"name":"openai-to-gemini-transformer","version":"v0","paths":[{"path":"/chat/completions","methods":["POST"],"params":{"providerId":"target-provider"}}]}] |
    Then the response status code should be 201
    When I set header "x-provider" to "target"
    And I send a "POST" request to "${CTX:proxyContext}/chat/completions" until status 200 with body:
      """
      {"model":"route-model","messages":[{"role":"user","content":"routed to the target"}]}
      """
    When I send a "GET" request to the "capture" service at "/test/captured?path=/target/v1beta/models/route-model:generateContent"
    Then the response status code should be 200
    And the JSON response field "path" should be "/target/v1beta/models/route-model:generateContent"
    And the JSON response field "body" should contain "routed to the target"
    When I set header "x-provider" to "other"
    And I send a "POST" request to "${CTX:proxyContext}/chat/completions" with body:
      """
      {"model":"route-model","messages":[{"role":"user","content":"left untranslated"}]}
      """
    Then the response status code should be 200
    And the JSON response field "path" should be "/other/chat/completions"
    And the response body should match pattern "role[^a-z]+user[^a-z]+content[^a-z]+left untranslated[^a-z]+[}][]][}]"
    When I delete the LLM proxy "${CTX:proxyName}"
    Then the response should be successful
    When I delete the LLM provider "${CTX:otherName}"
    Then the response should be successful
    When I delete the LLM provider "${CTX:targetName}"
    Then the response should be successful
    When I delete the LLM provider "${CTX:primaryName}"
    Then the response should be successful

  Scenario: Malformed and unusual message parts are skipped while the rest of the request is translated
    Given I generate a unique resource name from "o2g-edge-provider" and store it as "providerName"
    And I generate a unique API context from "/o2g-edge-provider" and store it as "providerContext"
    And I generate a unique resource name from "o2g-edge-proxy" and store it as "proxyName"
    And I generate a unique API context from "/o2g-edge-proxy" and store it as "proxyContext"
    When I create LLM provider from "resources/templates/llm-provider.yaml" with values:
      | apiVersion         | ${CTX:gatewaySpecVersion} |
      | name               | ${CTX:providerName}       |
      | displayName        | O2G-Edge-Provider         |
      | version            | v1.0                      |
      | template           | openai                    |
      | spec.context       | ${CTX:providerContext}    |
      | spec.upstream.url  | ${CTX:captureUpstream}    |
      | accessControl.mode | allow_all                 |
    Then the response status code should be 201
    When I create LLM proxy from "resources/templates/llm-proxy.yaml" with values:
      | apiVersion    | ${CTX:gatewaySpecVersion}                                                                                                                                 |
      | name          | ${CTX:proxyName}                                                                                                                                          |
      | displayName   | O2G-Edge-Proxy                                                                                                                                            |
      | version       | v1.0                                                                                                                                                      |
      | context       | ${CTX:proxyContext}                                                                                                                                       |
      | provider.id   | ${CTX:providerName}                                                                                                                                       |
      | spec.policies | [{"name":"openai-to-gemini-transformer","version":"v0","paths":[{"path":"/chat/completions","methods":["POST"],"params":{"model":"gemini-edge-model"}}]}] |
    Then the response status code should be 201
    And I send a "POST" request to "${CTX:proxyContext}/chat/completions" until status 200 with body:
      """
      {"model":"gemini-edge-model","messages":[42,{"role":"assistant","content":"Starting."},{"role":"system","content":""},{"role":"system","content":[{"type":"image_url"},{"type":"text","text":"Edge system."}]},{"role":"developer","content":7},{"role":"user","content":""},{"role":"user","content":[5,{"type":"image_url","image_url":"x"},{"type":"image_url","image_url":{"url":""}},{"type":"image_url","image_url":{"url":"data:image/png;base64"}},{"type":"image_url","image_url":{"url":"https://example.com/a.PNG"}},{"type":"text","text":"Look."}]},{"role":"user","content":9},{"role":"tool","tool_call_id":"lookup","content":[{"type":"image_url"},{"type":"text","text":"looked up"}]},{"role":"tool","tool_call_id":"other","content":5},{"role":"assistant","content":"Calling.","tool_calls":[7,{"id":"call_a"},{"id":"call_b","type":"function","function":{"name":"lookup","arguments":"not json"}}]},{"role":"user","content":"Go on."}],"stop":"END","tools":[3,{"type":"function"}],"tool_choice":"something-else"}
      """
    When I send a "GET" request to the "capture" service at "/test/captured?path=/v1beta/models/gemini-edge-model:generateContent"
    Then the response status code should be 200
    And the JSON response field "body" should contain "Edge system."
    And the JSON response field "body" should contain "image/png"
    And the JSON response field "body" should contain "functionCall"
    And the JSON response field "body" should contain "AUTO"
    And the JSON response field "body" should contain "END"
    When I delete the LLM proxy "${CTX:proxyName}"
    Then the response should be successful
    When I delete the LLM provider "${CTX:providerName}"
    Then the response should be successful

  # ---- generated coverage scenarios: end ----
