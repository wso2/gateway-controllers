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

@openai-to-bedrock-transformer
Feature: OpenAI to Bedrock transformer
  As an API consumer
  I want to call an AWS Bedrock upstream with OpenAI Chat Completions requests
  So that clients written for OpenAI work unchanged against the Bedrock Converse API

  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"
    And I resolve the "capture" service URL at "" and store it as "captureUpstream"

  Scenario: A Bedrock Converse response is returned in the OpenAI chat completion shape
    Given I generate a unique resource name from "o2b-response-provider" and store it as "providerName"
    And I generate a unique API context from "/o2b-response-provider" and store it as "providerContext"
    And I generate a unique resource name from "o2b-response-proxy" and store it as "proxyName"
    And I generate a unique API context from "/o2b-response-proxy" and store it as "proxyContext"
    When I create LLM provider from "resources/templates/llm-provider.yaml" with values:
      | apiVersion         | ${CTX:gatewaySpecVersion} |
      | name               | ${CTX:providerName}       |
      | displayName        | O2B-Response-Provider     |
      | version            | v1.0                      |
      | template           | openai                    |
      | spec.context       | ${CTX:providerContext}    |
      | spec.upstream.url  | http://testbench:3008     |
      | accessControl.mode | allow_all                 |
    Then the response status code should be 201
    When I create LLM proxy from "resources/templates/llm-proxy.yaml" with values:
      | apiVersion    | ${CTX:gatewaySpecVersion}                                                                                                                                |
      | name          | ${CTX:proxyName}                                                                                                                                         |
      | displayName   | O2B-Response-Proxy                                                                                                                                       |
      | version       | v1.0                                                                                                                                                     |
      | context       | ${CTX:proxyContext}                                                                                                                                      |
      | provider.id   | ${CTX:providerName}                                                                                                                                      |
      | spec.policies | [{"name":"openai-to-bedrock-transformer","version":"v0","paths":[{"path":"/chat/completions","methods":["POST"],"params":{"model":"amazon.fallback-model"}}]}] |
    Then the response status code should be 201
    # Converse responses carry no model, so the response reports the model the request named.
    And I send a "POST" request to "${CTX:proxyContext}/chat/completions" until status 200 with body:
      """
      {"model":"amazon.nova-lite-v1","messages":[{"role":"user","content":"Hello"}]}
      """
    Then the response should be valid JSON
    And the JSON response field "object" should be "chat.completion"
    And the JSON response field "model" should be "amazon.nova-lite-v1"
    And the JSON response field "choices[0].message.role" should be "assistant"
    And the JSON response field "choices[0].message.content" should be "Hello from Bedrock"
    And the JSON response field "choices[0].finish_reason" should be "stop"
    And the JSON response field "usage.prompt_tokens" should be 10
    And the JSON response field "usage.completion_tokens" should be 3
    And the JSON response field "usage.total_tokens" should be 13
    When I delete the LLM proxy "${CTX:proxyName}"
    Then the response should be successful
    When I delete the LLM provider "${CTX:providerName}"
    Then the response should be successful

  Scenario: The upstream receives Converse and ConverseStream requests for the resolved model
    Given I generate a unique resource name from "o2b-request-provider" and store it as "providerName"
    And I generate a unique API context from "/o2b-request-provider" and store it as "providerContext"
    And I generate a unique resource name from "o2b-request-proxy" and store it as "proxyName"
    And I generate a unique API context from "/o2b-request-proxy" and store it as "proxyContext"
    When I create LLM provider from "resources/templates/llm-provider.yaml" with values:
      | apiVersion         | ${CTX:gatewaySpecVersion} |
      | name               | ${CTX:providerName}       |
      | displayName        | O2B-Request-Provider      |
      | version            | v1.0                      |
      | template           | openai                    |
      | spec.context       | ${CTX:providerContext}    |
      | spec.upstream.url  | ${CTX:captureUpstream}    |
      | accessControl.mode | allow_all                 |
    Then the response status code should be 201
    When I create LLM proxy from "resources/templates/llm-proxy.yaml" with values:
      | apiVersion    | ${CTX:gatewaySpecVersion}                                                                                                                              |
      | name          | ${CTX:proxyName}                                                                                                                                       |
      | displayName   | O2B-Request-Proxy                                                                                                                                      |
      | version       | v1.0                                                                                                                                                   |
      | context       | ${CTX:proxyContext}                                                                                                                                    |
      | provider.id   | ${CTX:providerName}                                                                                                                                    |
      | spec.policies | [{"name":"openai-to-bedrock-transformer","version":"v0","paths":[{"path":"/chat/completions","methods":["POST"],"params":{"model":"amazon.nova-lite-v1"}}]}] |
    Then the response status code should be 201
    # The request names no model, so the fallback model goes into the Converse path.
    And I send a "POST" request to "${CTX:proxyContext}/chat/completions" until status 200 with body:
      """
      {"messages":[{"role":"system","content":"Answer briefly."},{"role":"user","content":"Hello"}],"max_tokens":64,"temperature":0.2}
      """
    When I send a "GET" request to the "capture" service at "/test/captured?path=/model/amazon.nova-lite-v1/converse"
    Then the response status code should be 200
    And the JSON response field "method" should be "POST"
    And the JSON response field "path" should be "/model/amazon.nova-lite-v1/converse"
    And the JSON response field "body" should contain "Answer briefly."
    And the JSON response field "body" should contain "inferenceConfig"
    And the JSON response field "body" should contain "maxTokens"
    And the response body should not contain "max_tokens"
    # A streaming request is sent to the ConverseStream endpoint instead.
    When I send a "POST" request to "${CTX:proxyContext}/chat/completions" with body:
      """
      {"stream":true,"messages":[{"role":"user","content":"Hello"}]}
      """
    And I send a "GET" request to the "capture" service at "/test/captured?path=/model/amazon.nova-lite-v1/converse-stream"
    Then the response status code should be 200
    And the JSON response field "path" should be "/model/amazon.nova-lite-v1/converse-stream"
    When I delete the LLM proxy "${CTX:proxyName}"
    Then the response should be successful
    When I delete the LLM provider "${CTX:providerName}"
    Then the response should be successful

  # The response must match the expected error response recorded from the policy before a
  # change (resources/expected-error-responses), so a change a client could observe fails.
  Scenario: openai-to-bedrock-transformer rejects an empty request body
    Given I generate a unique value from "compat-ob-empty" and store it as "apiName"
    And I generate a unique API version from "compat-ob-empty" and store it as "apiVersion"
    And I generate a unique API context from "/compat-ob-empty" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3002 |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"POST","path":"/chat/completions","policies":[{"name":"openai-to-bedrock-transformer","version":"v0","params":{"model":"anthropic.claude-3-5-sonnet-20240620-v1:0"}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat/completions" with body:
      """
      """
    Then the response status code should be 400
    And the response should match the expected error response "openai-to-bedrock-transformer-empty-body"

  Scenario: Documents, images, tools and tool turns are translated into Converse blocks
    Given I generate a unique resource name from "o2b-rich-provider" and store it as "providerName"
    And I generate a unique API context from "/o2b-rich-provider" and store it as "providerContext"
    And I generate a unique resource name from "o2b-rich-proxy" and store it as "proxyName"
    And I generate a unique API context from "/o2b-rich-proxy" and store it as "proxyContext"
    When I create LLM provider from "resources/templates/llm-provider.yaml" with values:
      | apiVersion         | ${CTX:gatewaySpecVersion} |
      | name               | ${CTX:providerName}       |
      | displayName        | O2B-Rich-Provider         |
      | version            | v1.0                      |
      | template           | openai                    |
      | spec.context       | ${CTX:providerContext}    |
      | spec.upstream.url  | ${CTX:captureUpstream}    |
      | accessControl.mode | allow_all                 |
    Then the response status code should be 201
    When I create LLM proxy from "resources/templates/llm-proxy.yaml" with values:
      | apiVersion    | ${CTX:gatewaySpecVersion}                                                                                                                                    |
      | name          | ${CTX:proxyName}                                                                                                                                             |
      | displayName   | O2B-Rich-Proxy                                                                                                                                               |
      | version       | v1.0                                                                                                                                                         |
      | context       | ${CTX:proxyContext}                                                                                                                                          |
      | provider.id   | ${CTX:providerName}                                                                                                                                          |
      | spec.policies | [{"name":"openai-to-bedrock-transformer","version":"v0","paths":[{"path":"/chat/completions","methods":["POST"],"params":{"model":"amazon.nova-lite-v1"}}]}] |
    Then the response status code should be 201
    # Documents keep a sanitised, de-duplicated name and take their format from the media type, or
    # from the file extension when the media type is generic. Only data URL images can be sent to
    # Converse, so the remote image is dropped. tool_choice "required" becomes Converse "any".
    And I send a "POST" request to "${CTX:proxyContext}/chat/completions" until status 200 with body:
      """
      {"max_completion_tokens":128,"temperature":0.2,"top_p":0.9,"stop":"END","messages":[{"role":"developer","content":[{"type":"text","text":"Use metric units."}]},{"role":"user","content":[{"type":"text","text":"Compare these files."},{"type":"file","file":{"filename":"Q3 report!.pdf","file_data":"data:application/pdf;base64,JVBERi0xLjQ="}},{"type":"file","file":{"filename":"Q3 report!.pdf","file_data":"data:application/pdf;base64,JVBERi0xLjQ="}},{"type":"file","file":{"filename":"numbers.csv","file_data":"data:application/octet-stream;base64,YSxiCjEsMgo="}},{"type":"file","file":{"filename":"","file_data":"data:text/plain;base64,aGVsbG8="}},{"type":"image_url","image_url":{"url":"data:image/png;base64,iVBORw0KGgo="}},{"type":"image_url","image_url":{"url":"https://example.com/remote.png"}}]},{"role":"assistant","content":"Checking the weather.","tool_calls":[{"id":"call_weather","type":"function","function":{"name":"get_weather","arguments":"{\"city\":\"Colombo\"}"}},{"id":"call_time","type":"function","function":{"name":"get_time","arguments":"not json"}}]},{"role":"tool","tool_call_id":"call_weather","content":"31C and sunny"},{"role":"tool","tool_call_id":"call_time","content":[{"type":"text","text":"10:00"}]},{"role":"assistant","content":""},{"role":"user","content":"Summarise."}],"tools":[{"type":"function","function":{"name":"get_weather","description":"Weather for a city","parameters":{"type":"object","properties":{"city":{"type":"string"}}}}},{"type":"function","function":{"name":"get_time"}}],"tool_choice":"required"}
      """
    When I send a "GET" request to the "capture" service at "/test/captured?path=/model/amazon.nova-lite-v1/converse"
    Then the response status code should be 200
    And the JSON response field "body" should contain "Use metric units."
    And the JSON response field "body" should contain "document"
    And the response body should match pattern "name[^a-z]+Q3 report[^a-zA-Z0-9-]"
    And the response body should match pattern "name[^a-z]+Q3 report-2"
    And the JSON response field "body" should contain "pdf"
    And the JSON response field "body" should contain "csv"
    And the JSON response field "body" should contain "txt"
    And the JSON response field "body" should contain "JVBERi0xLjQ="
    And the JSON response field "body" should contain "image"
    And the JSON response field "body" should contain "png"
    And the JSON response field "body" should contain "iVBORw0KGgo="
    And the JSON response field "body" should contain "toolUse"
    And the JSON response field "body" should contain "call_weather"
    And the JSON response field "body" should contain "Colombo"
    And the JSON response field "body" should contain "toolResult"
    And the JSON response field "body" should contain "toolUseId"
    And the JSON response field "body" should contain "31C and sunny"
    And the JSON response field "body" should contain "10:00"
    And the JSON response field "body" should contain "toolSpec"
    And the JSON response field "body" should contain "inputSchema"
    And the JSON response field "body" should contain "Weather for a city"
    And the response body should match pattern "toolChoice[^a-z]+any"
    And the JSON response field "body" should contain "stopSequences"
    And the JSON response field "body" should contain "topP"
    And the JSON response field "body" should contain "maxTokens"
    And the response body should not contain "https://example.com/remote.png"
    And the response body should not contain "tool_calls"
    And the response body should not contain "image_url"
    And the response body should not contain "file_data"
    When I send a "POST" request to "${CTX:proxyContext}/chat/completions" with body:
      """
      {"messages":[{"role":"user","content":"Hi"}],"tools":[{"type":"function","function":{"name":"get_weather"}}],"tool_choice":"none"}
      """
    Then the response status code should be 200
    When I send a "GET" request to the "capture" service at "/test/captured?path=/model/amazon.nova-lite-v1/converse"
    Then the response status code should be 200
    And the response body should not contain "toolConfig"
    When I send a "POST" request to "${CTX:proxyContext}/chat/completions" with body:
      """
      {"messages":[{"role":"user","content":"Hi"}],"tools":[{"type":"function","function":{"name":"get_weather"}}],"tool_choice":"auto"}
      """
    Then the response status code should be 200
    When I send a "GET" request to the "capture" service at "/test/captured?path=/model/amazon.nova-lite-v1/converse"
    Then the response status code should be 200
    And the response body should match pattern "toolChoice[^a-z]+auto"
    When I send a "POST" request to "${CTX:proxyContext}/chat/completions" with body:
      """
      {"messages":[{"role":"user","content":"Hi"}],"tools":[{"type":"function","function":{"name":"get_weather"}}],"tool_choice":{"type":"function","function":{"name":"get_weather"}}}
      """
    Then the response status code should be 200
    When I send a "GET" request to the "capture" service at "/test/captured?path=/model/amazon.nova-lite-v1/converse"
    Then the response status code should be 200
    And the response body should match pattern "toolChoice[^a-z]+tool[^a-z]+name[^a-z]+get_weather"
    When I delete the LLM proxy "${CTX:proxyName}"
    Then the response should be successful
    When I delete the LLM provider "${CTX:providerName}"
    Then the response should be successful

  Scenario: A file part Converse cannot accept is rejected with 400
    Given I generate a unique resource name from "o2b-files-provider" and store it as "providerName"
    And I generate a unique API context from "/o2b-files-provider" and store it as "providerContext"
    And I generate a unique resource name from "o2b-files-proxy" and store it as "proxyName"
    And I generate a unique API context from "/o2b-files-proxy" and store it as "proxyContext"
    When I create LLM provider from "resources/templates/llm-provider.yaml" with values:
      | apiVersion         | ${CTX:gatewaySpecVersion} |
      | name               | ${CTX:providerName}       |
      | displayName        | O2B-Files-Provider        |
      | version            | v1.0                      |
      | template           | openai                    |
      | spec.context       | ${CTX:providerContext}    |
      | spec.upstream.url  | ${CTX:captureUpstream}    |
      | accessControl.mode | allow_all                 |
    Then the response status code should be 201
    When I create LLM proxy from "resources/templates/llm-proxy.yaml" with values:
      | apiVersion    | ${CTX:gatewaySpecVersion}                                                                                                                                    |
      | name          | ${CTX:proxyName}                                                                                                                                             |
      | displayName   | O2B-Files-Proxy                                                                                                                                              |
      | version       | v1.0                                                                                                                                                         |
      | context       | ${CTX:proxyContext}                                                                                                                                          |
      | provider.id   | ${CTX:providerName}                                                                                                                                          |
      | spec.policies | [{"name":"openai-to-bedrock-transformer","version":"v0","paths":[{"path":"/chat/completions","methods":["POST"],"params":{"model":"amazon.nova-lite-v1"}}]}] |
    Then the response status code should be 201
    And I send a "POST" request to "${CTX:proxyContext}/chat/completions" until status 200 with body:
      """
      {"messages":[{"role":"user","content":"Hello"}]}
      """
    When I send a "POST" request to "${CTX:proxyContext}/chat/completions" with body:
      """
      {"messages":[{"role":"user","content":[{"type":"text","text":"Read this."},{"type":"file"}]}]}
      """
    Then the response status code should be 400
    And the JSON response field "error" should contain "missing its file object"
    When I send a "POST" request to "${CTX:proxyContext}/chat/completions" with body:
      """
      {"messages":[{"role":"user","content":[{"type":"text","text":"Read this."},{"type":"file","file":{"file_id":"file-123"}}]}]}
      """
    Then the response status code should be 400
    And the JSON response field "error" should contain "file_id is not supported"
    When I send a "POST" request to "${CTX:proxyContext}/chat/completions" with body:
      """
      {"messages":[{"role":"user","content":[{"type":"text","text":"Read this."},{"type":"file","file":{"filename":"a.pdf"}}]}]}
      """
    Then the response status code should be 400
    And the JSON response field "error" should contain "requires file_data"
    When I send a "POST" request to "${CTX:proxyContext}/chat/completions" with body:
      """
      {"messages":[{"role":"user","content":[{"type":"text","text":"Read this."},{"type":"file","file":{"filename":"a.pdf","file_data":"JVBERi0xLjQ="}}]}]}
      """
    Then the response status code should be 400
    And the JSON response field "error" should contain "must be a base64 data URI"
    When I send a "POST" request to "${CTX:proxyContext}/chat/completions" with body:
      """
      {"messages":[{"role":"user","content":[{"type":"text","text":"Read this."},{"type":"file","file":{"filename":"a.pdf","file_data":"data:application/pdf;base64"}}]}]}
      """
    Then the response status code should be 400
    And the JSON response field "error" should contain "must be a base64 data URI"
    When I send a "POST" request to "${CTX:proxyContext}/chat/completions" with body:
      """
      {"messages":[{"role":"user","content":[{"type":"text","text":"Read this."},{"type":"file","file":{"filename":"a.pdf","file_data":"data:application/pdf,JVBERi0xLjQ="}}]}]}
      """
    Then the response status code should be 400
    And the JSON response field "error" should contain "must be base64 encoded"
    When I send a "POST" request to "${CTX:proxyContext}/chat/completions" with body:
      """
      {"messages":[{"role":"user","content":[{"type":"text","text":"Read this."},{"type":"file","file":{"filename":"a.pdf","file_data":"data:application/pdf;base64,"}}]}]}
      """
    Then the response status code should be 400
    And the JSON response field "error" should contain "contains no data"
    When I send a "POST" request to "${CTX:proxyContext}/chat/completions" with body:
      """
      {"messages":[{"role":"user","content":[{"type":"text","text":"Read this."},{"type":"file","file":{"filename":"a.pdf","file_data":"data:application/pdf;base64,JVBE Ri0x"}}]}]}
      """
    Then the response status code should be 400
    And the JSON response field "error" should contain "without whitespace"
    When I send a "POST" request to "${CTX:proxyContext}/chat/completions" with body:
      """
      {"messages":[{"role":"user","content":[{"type":"text","text":"Read this."},{"type":"file","file":{"filename":"a.pdf","file_data":"data:application/pdf;base64,***"}}]}]}
      """
    Then the response status code should be 400
    And the JSON response field "error" should contain "not valid base64"
    When I send a "POST" request to "${CTX:proxyContext}/chat/completions" with body:
      """
      {"messages":[{"role":"user","content":[{"type":"text","text":"Read this."},{"type":"file","file":{"filename":"picture.png","file_data":"data:image/png;base64,iVBORw0KGgo="}}]}]}
      """
    Then the response status code should be 400
    And the JSON response field "error" should contain "unsupported file type"
    When I send a "POST" request to "${CTX:proxyContext}/chat/completions" with body:
      """
      {"messages":[{"role":"user","content":[{"type":"text","text":"Read this."},{"type":"file","file":{"filename":"","file_data":"data:;base64,iVBORw0KGgo="}}]}]}
      """
    Then the response status code should be 400
    And the JSON response field "error" should contain "unsupported file type"
    # A document needs text beside it in the same message.
    When I send a "POST" request to "${CTX:proxyContext}/chat/completions" with body:
      """
      {"messages":[{"role":"user","content":[{"type":"file","file":{"filename":"a.pdf","file_data":"data:application/pdf;base64,JVBERi0xLjQ="}}]}]}
      """
    Then the response status code should be 400
    And the JSON response field "error" should contain "non-empty text part"
    When I delete the LLM proxy "${CTX:proxyName}"
    Then the response should be successful
    When I delete the LLM provider "${CTX:providerName}"
    Then the response should be successful

  Scenario: A request the policy cannot translate is rejected with 400
    Given I generate a unique resource name from "o2b-invalid-provider" and store it as "providerName"
    And I generate a unique API context from "/o2b-invalid-provider" and store it as "providerContext"
    And I generate a unique resource name from "o2b-invalid-proxy" and store it as "proxyName"
    And I generate a unique API context from "/o2b-invalid-proxy" and store it as "proxyContext"
    When I create LLM provider from "resources/templates/llm-provider.yaml" with values:
      | apiVersion         | ${CTX:gatewaySpecVersion} |
      | name               | ${CTX:providerName}       |
      | displayName        | O2B-Invalid-Provider      |
      | version            | v1.0                      |
      | template           | openai                    |
      | spec.context       | ${CTX:providerContext}    |
      | spec.upstream.url  | http://testbench:3008     |
      | accessControl.mode | allow_all                 |
    Then the response status code should be 201
    # No fallback model is configured, so the request has to name one.
    When I create LLM proxy from "resources/templates/llm-proxy.yaml" with values:
      | apiVersion    | ${CTX:gatewaySpecVersion}                                                                                                       |
      | name          | ${CTX:proxyName}                                                                                                                |
      | displayName   | O2B-Invalid-Proxy                                                                                                               |
      | version       | v1.0                                                                                                                            |
      | context       | ${CTX:proxyContext}                                                                                                             |
      | provider.id   | ${CTX:providerName}                                                                                                             |
      | spec.policies | [{"name":"openai-to-bedrock-transformer","version":"v0","paths":[{"path":"/chat/completions","methods":["POST"],"params":{}}]}] |
    Then the response status code should be 201
    And I send a "POST" request to "${CTX:proxyContext}/chat/completions" until status 200 with body:
      """
      {"model":"amazon.nova-lite-v1","messages":[{"role":"user","content":"Hello"}]}
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
    Given I generate a unique resource name from "o2b-errors-provider" and store it as "providerName"
    And I generate a unique API context from "/o2b-errors-provider" and store it as "providerContext"
    And I generate a unique resource name from "o2b-errors-proxy" and store it as "proxyName"
    And I generate a unique API context from "/o2b-errors-proxy" and store it as "proxyContext"
    And I resolve the "fault-injection" service URL at "/${CTX:providerName}" and store it as "faultUpstream"
    When I send a "PUT" request to the "fault-injection" service at "/test/scripts/${CTX:providerName}" with body:
      """
      {"forwardPort":3008,"steps":[]}
      """
    Then the response status code should be 200
    When I create LLM provider from "resources/templates/llm-provider.yaml" with values:
      | apiVersion         | ${CTX:gatewaySpecVersion} |
      | name               | ${CTX:providerName}       |
      | displayName        | O2B-Errors-Provider       |
      | version            | v1.0                      |
      | template           | openai                    |
      | spec.context       | ${CTX:providerContext}    |
      | spec.upstream.url  | ${CTX:faultUpstream}      |
      | accessControl.mode | allow_all                 |
    Then the response status code should be 201
    When I create LLM proxy from "resources/templates/llm-proxy.yaml" with values:
      | apiVersion    | ${CTX:gatewaySpecVersion}                                                                                                                                    |
      | name          | ${CTX:proxyName}                                                                                                                                             |
      | displayName   | O2B-Errors-Proxy                                                                                                                                             |
      | version       | v1.0                                                                                                                                                         |
      | context       | ${CTX:proxyContext}                                                                                                                                          |
      | provider.id   | ${CTX:providerName}                                                                                                                                          |
      | spec.policies | [{"name":"openai-to-bedrock-transformer","version":"v0","paths":[{"path":"/chat/completions","methods":["POST"],"params":{"model":"amazon.nova-lite-v1"}}]}] |
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
    And the JSON response field "error.code" should be "401"
    When I send a "POST" request to "${CTX:proxyContext}/chat/completions" with body:
      """
      {"messages":[{"role":"user","content":"Hello"}]}
      """
    Then the response status code should be 403
    And the JSON response field "error.type" should be "permission_error"
    And the JSON response field "error.code" should be "403"
    When I send a "POST" request to "${CTX:proxyContext}/chat/completions" with body:
      """
      {"messages":[{"role":"user","content":"Hello"}]}
      """
    Then the response status code should be 404
    And the JSON response field "error.type" should be "not_found_error"
    And the JSON response field "error.code" should be "404"
    When I send a "POST" request to "${CTX:proxyContext}/chat/completions" with body:
      """
      {"messages":[{"role":"user","content":"Hello"}]}
      """
    Then the response status code should be 413
    And the JSON response field "error.type" should be "request_too_large"
    And the JSON response field "error.code" should be "413"
    When I send a "POST" request to "${CTX:proxyContext}/chat/completions" with body:
      """
      {"messages":[{"role":"user","content":"Hello"}]}
      """
    Then the response status code should be 429
    And the JSON response field "error.type" should be "rate_limit_error"
    And the JSON response field "error.code" should be "429"
    When I send a "POST" request to "${CTX:proxyContext}/chat/completions" with body:
      """
      {"messages":[{"role":"user","content":"Hello"}]}
      """
    Then the response status code should be 503
    And the JSON response field "error.type" should be "server_error"
    And the JSON response field "error.code" should be "503"
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

  Scenario Outline: A scripted O2B reply is translated into the OpenAI shape (<case>)
    Given I generate a unique value from "o2b-fake-<case>" and store it as "fakeName"
    And I generate a unique API context from "/o2b-fake-<case>" and store it as "fakeContext"
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
    And I generate a unique resource name from "o2b-scripted-provider" and store it as "providerName"
    And I generate a unique API context from "/o2b-scripted-provider" and store it as "providerContext"
    And I generate a unique resource name from "o2b-scripted-proxy" and store it as "proxyName"
    And I generate a unique API context from "/o2b-scripted-proxy" and store it as "proxyContext"
    When I create LLM provider from "resources/templates/llm-provider.yaml" with values:
      | apiVersion         | ${CTX:gatewaySpecVersion}                          |
      | name               | ${CTX:providerName}                                |
      | displayName        | O2B-Scripted-Provider                              |
      | version            | v1.0                                               |
      | template           | openai                                             |
      | spec.context       | ${CTX:providerContext}                             |
      | spec.upstream.url  | http://gateway-runtime:8080${CTX:fakeContext}/v1.0 |
      | accessControl.mode | allow_all                                          |
    Then the response status code should be 201
    When I create LLM proxy from "resources/templates/llm-proxy.yaml" with values:
      | apiVersion    | ${CTX:gatewaySpecVersion}                                                                                                                                      |
      | name          | ${CTX:proxyName}                                                                                                                                               |
      | displayName   | O2B-Scripted-Proxy                                                                                                                                             |
      | version       | v1.0                                                                                                                                                           |
      | context       | ${CTX:proxyContext}                                                                                                                                            |
      | provider.id   | ${CTX:providerName}                                                                                                                                            |
      | spec.policies | [{"name":"openai-to-bedrock-transformer","version":"v0","paths":[{"path":"/chat/completions","methods":["POST"],"params":{"model":"amazon.fallback-model"}}]}] |
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
      | case                    | status | contentType              | body                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         | request                                                                                       | expected | expect1                 | expect2        | expect3         | absent              |
      | tool-use                | 200    | application/json         | {\\"output\\":{\\"message\\":{\\"role\\":\\"assistant\\",\\"content\\":[{\\"text\\":\\"Let me check.\\"},{\\"toolUse\\":{\\"toolUseId\\":\\"tu_one\\",\\"name\\":\\"get_weather\\",\\"input\\":{\\"city\\":\\"Colombo\\"}}},{\\"toolUse\\":{\\"toolUseId\\":\\"tu_two\\",\\"name\\":\\"get_time\\"}}]}},\\"stopReason\\":\\"end_turn\\",\\"usage\\":{\\"inputTokens\\":10,\\"outputTokens\\":5,\\"totalTokens\\":99,\\"cacheReadInputTokens\\":2,\\"cacheWriteInputTokens\\":7,\\"cacheDetails\\":[{\\"ttl\\":\\"5m\\",\\"inputTokens\\":2},{\\"ttl\\":\\"1h\\",\\"inputTokens\\":3}]}}                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      | {"model":"bedrock-tool-model","messages":[{"role":"user","content":"Hello"}]}                 | 200      | tu_two                  | tool_calls     | chat.completion | toolUse             |
      | max-tokens              | 200    | application/json         | {\\"output\\":{\\"message\\":{\\"role\\":\\"assistant\\",\\"content\\":[{\\"text\\":\\"Cut off\\"}]}},\\"stopReason\\":\\"max_tokens\\",\\"usage\\":{\\"inputTokens\\":1,\\"outputTokens\\":1,\\"totalTokens\\":2}}                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          | {"model":"bedrock-len-model","messages":[{"role":"user","content":"Hello"}]}                  | 200      | Cut off                 | length         | chat.completion | max_tokens          |
      | guardrail               | 200    | application/json         | {\\"output\\":{\\"message\\":{\\"role\\":\\"assistant\\",\\"content\\":[{\\"text\\":\\"Withheld\\"}]}},\\"stopReason\\":\\"guardrail_intervened\\",\\"usage\\":{\\"inputTokens\\":1,\\"outputTokens\\":1,\\"totalTokens\\":2}}                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               | {"model":"bedrock-guard-model","messages":[{"role":"user","content":"Hello"}]}                | 200      | Withheld                | content_filter | chat.completion | guardrail           |
      | not-json                | 200    | text/plain               | plain upstream text                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          | {"model":"bedrock-plain-model","messages":[{"role":"user","content":"Hello"}]}                | 200      | plain                   | upstream       | text            | chat.completion     |
      | error-envelope          | 400    | application/json         | {\\"message\\":\\"Malformed input request\\"}                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                | {"model":"bedrock-err-model","messages":[{"role":"user","content":"Hello"}]}                  | 400      | Malformed input request | error          | 400             | ValidationException |
      | streamed-error-envelope | 429    | application/json         | {\\"message\\":\\"Too many tokens\\"}                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        | {"model":"bedrock-err-model","messages":[{"role":"user","content":"Hello"}],"stream":true}    | 429      | Too many tokens         | error          | 429             | ValidationException |
      | event-stream-exceptions | 200    | application/octet-stream | \\u0000\\u0000\\u0000v\\u0000\\u0000\\u0000R\\u0000\\u0000\\u0000\\u0000\\u000b:event-type\\u0007\\u0000\\u000cmessageStart\\u000d:content-type\\u0007\\u0000\\u0010application/json\\u000d:message-type\\u0007\\u0000\\u0005event{\\"role\\":\\"assistant\\"}\\u0000\\u0000\\u0000\\u0000\\u0000\\u0000\\u0000\|\\u0000\\u0000\\u0000Q\\u0000\\u0000\\u0000\\u0000\\u000b:event-type\\u0007\\u0000\\u000bmessageStop\\u000d:content-type\\u0007\\u0000\\u0010application/json\\u000d:message-type\\u0007\\u0000\\u0005event{\\"stopReason\\":\\"max_tokens\\"}\\u0000\\u0000\\u0000\\u0000\\u0000\\u0000\\u0001\\u0000\\u0000\\u0000\\u0000Q\\u0000\\u0000\\u0000\\u0000\\u000b:event-type\\u0007\\u0000\\u000bmessageStop\\u000d:content-type\\u0007\\u0000\\u0010application/json\\u000d:message-type\\u0007\\u0000\\u0005event{\\"stopReason\\":\\"content_filtered\\"}                                                                                                                              \\u0000\\u0000\\u0000\\u0000\\u0000\\u0000\\u0000k\\u0000\\u0000\\u0000@\\u0000\\u0000\\u0000\\u0000\\u000d:message-type\\u0007\\u0000\\u0009exception\\u000f:exception-type\\u0007\\u0000\\u0013throttlingException{\\"message\\":\\"Rate exceeded\\"}\\u0000\\u0000\\u0000\\u0000\\u0000\\u0000\\u0000X\\u0000\\u0000\\u0000F\\u0000\\u0000\\u0000\\u0000\\u000d:message-type\\u0007\\u0000\\u0009exception\\u000f:exception-type\\u0007\\u0000\\u0019modelStreamErrorException{}\\u0000\\u0000\\u0000\\u0000\\u0000\\u0000\\u00002\\u0000\\u0000\\u0000\\u001a\\u0000\\u0000\\u0000\\u0000\\u000d:message-type\\u0007\\u0000\\u0009exceptionnot json\\u0000\\u0000\\u0000\\u0000 | {"model":"bedrock-stream-model","messages":[{"role":"user","content":"Hello"}],"stream":true} | 200      | Rate exceeded           | length         | data:           | messageStop         |
  Scenario Outline: A scripted O2B stream is translated and ends as expected (<case>)
    Given I generate a unique value from "o2b-fake-<case>" and store it as "fakeName"
    And I generate a unique API context from "/o2b-fake-<case>" and store it as "fakeContext"
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
    And I generate a unique resource name from "o2b-scripted-provider" and store it as "providerName"
    And I generate a unique API context from "/o2b-scripted-provider" and store it as "providerContext"
    And I generate a unique resource name from "o2b-scripted-proxy" and store it as "proxyName"
    And I generate a unique API context from "/o2b-scripted-proxy" and store it as "proxyContext"
    When I create LLM provider from "resources/templates/llm-provider.yaml" with values:
      | apiVersion         | ${CTX:gatewaySpecVersion}                          |
      | name               | ${CTX:providerName}                                |
      | displayName        | O2B-Scripted-Provider                              |
      | version            | v1.0                                               |
      | template           | openai                                             |
      | spec.context       | ${CTX:providerContext}                             |
      | spec.upstream.url  | http://gateway-runtime:8080${CTX:fakeContext}/v1.0 |
      | accessControl.mode | allow_all                                          |
    Then the response status code should be 201
    When I create LLM proxy from "resources/templates/llm-proxy.yaml" with values:
      | apiVersion    | ${CTX:gatewaySpecVersion}                                                                                                                                      |
      | name          | ${CTX:proxyName}                                                                                                                                               |
      | displayName   | O2B-Scripted-Proxy                                                                                                                                             |
      | version       | v1.0                                                                                                                                                           |
      | context       | ${CTX:proxyContext}                                                                                                                                            |
      | provider.id   | ${CTX:providerName}                                                                                                                                            |
      | spec.policies | [{"name":"openai-to-bedrock-transformer","version":"v0","paths":[{"path":"/chat/completions","methods":["POST"],"params":{"model":"amazon.fallback-model"}}]}] |
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
      | case         | status | contentType                        | body                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       | request                                                                                       | expected | expect1   | expect2    | expect3      | absent       | tail                          |
      | event-stream | 200    | application/vnd.amazon.eventstream | \\u0000\\u0000\\u0000v\\u0000\\u0000\\u0000R\\u0000\\u0000\\u0000\\u0000\\u000b:event-type\\u0007\\u0000\\u000cmessageStart\\u000d:content-type\\u0007\\u0000\\u0010application/json\\u000d:message-type\\u0007\\u0000\\u0005event{\\"role\\":\\"assistant\\"}\\u0000\\u0000\\u0000\\u0000\\u0000\\u0000\\u0001\\u0000\\u0000\\u0000\\u0000W\\u0000\\u0000\\u0000\\u0000\\u000b:event-type\\u0007\\u0000\\u0011contentBlockDelta\\u000d:content-type\\u0007\\u0000\\u0010application/json\\u000d:message-type\\u0007\\u0000\\u0005event{\\"delta\\":{\\"text\\":\\"Checking\\"},\\"contentBlockIndex\\":0}                                                                                                      \\u0000\\u0000\\u0000\\u0000\\u0000\\u0000\\u0001\\u0000\\u0000\\u0000\\u0000W\\u0000\\u0000\\u0000\\u0000\\u000b:event-type\\u0007\\u0000\\u0011contentBlockStart\\u000d:content-type\\u0007\\u0000\\u0010application/json\\u000d:message-type\\u0007\\u0000\\u0005event{\\"start\\":{},\\"contentBlockIndex\\":0}                                                                                                                       \\u0000\\u0000\\u0000\\u0000\\u0000\\u0000\\u0001\\u0000\\u0000\\u0000\\u0000W\\u0000\\u0000\\u0000\\u0000\\u000b:event-type\\u0007\\u0000\\u0011contentBlockStart\\u000d:content-type\\u0007\\u0000\\u0010application/json\\u000d:message-type\\u0007\\u0000\\u0005event{\\"start\\":{\\"toolUse\\":{\\"toolUseId\\":\\"tu_stream\\",\\"name\\":\\"get_weather\\"}},\\"contentBlockIndex\\":1}                                                               \\u0000\\u0000\\u0000\\u0000\\u0000\\u0000\\u0001\\u0000\\u0000\\u0000\\u0000W\\u0000\\u0000\\u0000\\u0000\\u000b:event-type\\u0007\\u0000\\u0011contentBlockDelta\\u000d:content-type\\u0007\\u0000\\u0010application/json\\u000d:message-type\\u0007\\u0000\\u0005event{\\"delta\\":{\\"toolUse\\":{\\"input\\":\\"{\\\\\\"city\\\\\\":\\\\\\"Colombo\\\\\\"}\\"}},\\"contentBlockIndex\\":1.0}                                                                         \\u0000\\u0000\\u0000\\u0000\\u0000\\u0000\\u0001\\u0000\\u0000\\u0000\\u0000W\\u0000\\u0000\\u0000\\u0000\\u000b:event-type\\u0007\\u0000\\u0011contentBlockDelta\\u000d:content-type\\u0007\\u0000\\u0010application/json\\u000d:message-type\\u0007\\u0000\\u0005event{\\"delta\\":{},\\"contentBlockIndex\\":1.5}                                                                                                                     \\u0000\\u0000\\u0000\\u0000\\u0000\\u0000\\u0000z\\u0000\\u0000\\u0000Q\\u0000\\u0000\\u0000\\u0000\\u000b:event-type\\u0007\\u0000\\u000bmessageStop\\u000d:content-type\\u0007\\u0000\\u0010application/json\\u000d:message-type\\u0007\\u0000\\u0005event{\\"stopReason\\":\\"tool_use\\"}\\u0000\\u0000\\u0000\\u0000\\u0000\\u0000\\u0001+\\u0000\\u0000\\u0000N\\u0000\\u0000\\u0000\\u0000\\u000b:event-type\\u0007\\u0000\\u0008metadata\\u000d:content-type\\u0007\\u0000\\u0010application/json\\u000d:message-type\\u0007\\u0000\\u0005event{\\"usage\\":{\\"inputTokens\\":5,\\"outputTokens\\":3,\\"totalTokens\\":30,\\"cacheReadInputTokens\\":1,\\"cacheWriteInputTokens\\":9,\\"cacheDetails\\":[{\\"ttl\\":\\"5m\\",\\"inputTokens\\":2},{\\"ttl\\":\\"1h\\",\\"inputTokens\\":3},{\\"inputTokens\\":1}]}}\\u0000\\u0000\\u0000\\u0000\\u0000\\u0000\\u0000y\\u0000\\u0000\\u0000N\\u0000\\u0000\\u0000\\u0000\\u000b:event-type\\u0007\\u0000\\u0008metadata\\u000d:content-type\\u0007\\u0000\\u0010application/json\\u000d:message-type\\u0007\\u0000\\u0005event{\\"metrics\\":{\\"latencyMs\\":1}}\\u0000\\u0000\\u0000\\u0000\\u0000\\u0000\\u0001\\u0000\\u0000\\u0000\\u0000z\\u0000\\u0000\\u0000\\u0000\\u000b:event-type\\u0007\\u0000\\u000csomethingNew\\u000d:message-type\\u0007\\u0000\\u0005event\\u0001t\\u0000\\u0001f\\u0001\\u0001b\\u0002\\u0001\\u0001s\\u0003\\u0000\\u0001\\u0001i\\u0004\\u0000\\u0000\\u0000\\u0001\\u0001l\\u0005\\u0000\\u0000\\u0000\\u0000\\u0000\\u0000\\u0000\\u0000\\u0001m\\u0008\\u0000\\u0000\\u0000\\u0000\\u0000\\u0000\\u0000\\u0000\\u0001u\\u0009\\u0000\\u0000\\u0000\\u0000\\u0000\\u0000\\u0000\\u0000\\u0000\\u0000\\u0000\\u0000\\u0000\\u0000\\u0000\\u0000\\u0001a\\u0006\\u0000\\u0002zz\\u0001x\\u000a{}                                                                                                                    \\u0000\\u0000\\u0000\\u0000 | {"model":"bedrock-stream-model","messages":[{"role":"user","content":"Hello"}],"stream":true} | 200      | tu_stream | tool_calls | data: [DONE] | contentBlock | data: [[]DONE[]][[:space:]]*$ |

  Scenario: The translator runs only for the provider a header router selected for it
    Given I generate a unique resource name from "o2b-route-primary" and store it as "primaryName"
    And I generate a unique API context from "/o2b-route-primary" and store it as "primaryContext"
    And I generate a unique resource name from "o2b-route-target" and store it as "targetName"
    And I generate a unique API context from "/o2b-route-target" and store it as "targetContext"
    And I generate a unique resource name from "o2b-route-other" and store it as "otherName"
    And I generate a unique API context from "/o2b-route-other" and store it as "otherContext"
    And I generate a unique resource name from "o2b-route-proxy" and store it as "proxyName"
    And I generate a unique API context from "/o2b-route-proxy" and store it as "proxyContext"
    When I create LLM provider from "resources/templates/llm-provider.yaml" with values:
      | apiVersion         | ${CTX:gatewaySpecVersion}      |
      | name               | ${CTX:primaryName}             |
      | displayName        | O2B-Route-Primary              |
      | version            | v1.0                           |
      | template           | openai                         |
      | spec.context       | ${CTX:primaryContext}          |
      | spec.upstream.url  | ${CTX:captureUpstream}/primary |
      | accessControl.mode | allow_all                      |
    Then the response status code should be 201
    When I create LLM provider from "resources/templates/llm-provider.yaml" with values:
      | apiVersion         | ${CTX:gatewaySpecVersion}     |
      | name               | ${CTX:targetName}             |
      | displayName        | O2B-Route-Target              |
      | version            | v1.0                          |
      | template           | openai                        |
      | spec.context       | ${CTX:targetContext}          |
      | spec.upstream.url  | ${CTX:captureUpstream}/target |
      | accessControl.mode | allow_all                     |
    Then the response status code should be 201
    When I create LLM provider from "resources/templates/llm-provider.yaml" with values:
      | apiVersion         | ${CTX:gatewaySpecVersion}    |
      | name               | ${CTX:otherName}             |
      | displayName        | O2B-Route-Other              |
      | version            | v1.0                         |
      | template           | openai                       |
      | spec.context       | ${CTX:otherContext}          |
      | spec.upstream.url  | ${CTX:captureUpstream}/other |
      | accessControl.mode | allow_all                    |
    Then the response status code should be 201
    When I create LLM proxy from "resources/templates/llm-proxy.yaml" with values:
      | apiVersion               | ${CTX:gatewaySpecVersion}                                                                                                                                                                                                                                                                                                                                                                             |
      | name                     | ${CTX:proxyName}                                                                                                                                                                                                                                                                                                                                                                                      |
      | displayName              | O2B-Route-Proxy                                                                                                                                                                                                                                                                                                                                                                                       |
      | version                  | v1.0                                                                                                                                                                                                                                                                                                                                                                                                  |
      | context                  | ${CTX:proxyContext}                                                                                                                                                                                                                                                                                                                                                                                   |
      | provider.id              | ${CTX:primaryName}                                                                                                                                                                                                                                                                                                                                                                                    |
      | spec.additionalProviders | [{"id":"${CTX:targetName}","as":"target-provider"},{"id":"${CTX:otherName}","as":"other-provider"}]                                                                                                                                                                                                                                                                                                   |
      | spec.policies            | [{"name":"llm-header-router","version":"v0","paths":[{"path":"/chat/completions","methods":["POST"],"params":{"mappings":[{"headerValue":"target","provider":"target-provider"},{"headerValue":"other","provider":"other-provider"}]}}]},{"name":"openai-to-bedrock-transformer","version":"v0","paths":[{"path":"/chat/completions","methods":["POST"],"params":{"providerId":"target-provider"}}]}] |
    Then the response status code should be 201
    When I set header "x-provider" to "target"
    And I send a "POST" request to "${CTX:proxyContext}/chat/completions" until status 200 with body:
      """
      {"model":"route-model","messages":[{"role":"user","content":"routed to the target"}]}
      """
    When I send a "GET" request to the "capture" service at "/test/captured?path=/target/model/route-model/converse"
    Then the response status code should be 200
    And the JSON response field "path" should be "/target/model/route-model/converse"
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
    Given I generate a unique resource name from "o2b-edge-provider" and store it as "providerName"
    And I generate a unique API context from "/o2b-edge-provider" and store it as "providerContext"
    And I generate a unique resource name from "o2b-edge-proxy" and store it as "proxyName"
    And I generate a unique API context from "/o2b-edge-proxy" and store it as "proxyContext"
    When I create LLM provider from "resources/templates/llm-provider.yaml" with values:
      | apiVersion         | ${CTX:gatewaySpecVersion} |
      | name               | ${CTX:providerName}       |
      | displayName        | O2B-Edge-Provider         |
      | version            | v1.0                      |
      | template           | openai                    |
      | spec.context       | ${CTX:providerContext}    |
      | spec.upstream.url  | ${CTX:captureUpstream}    |
      | accessControl.mode | allow_all                 |
    Then the response status code should be 201
    When I create LLM proxy from "resources/templates/llm-proxy.yaml" with values:
      | apiVersion    | ${CTX:gatewaySpecVersion}                                                                                                                                  |
      | name          | ${CTX:proxyName}                                                                                                                                           |
      | displayName   | O2B-Edge-Proxy                                                                                                                                             |
      | version       | v1.0                                                                                                                                                       |
      | context       | ${CTX:proxyContext}                                                                                                                                        |
      | provider.id   | ${CTX:providerName}                                                                                                                                        |
      | spec.policies | [{"name":"openai-to-bedrock-transformer","version":"v0","paths":[{"path":"/chat/completions","methods":["POST"],"params":{"model":"amazon.edge-model"}}]}] |
    Then the response status code should be 201
    And I send a "POST" request to "${CTX:proxyContext}/chat/completions" until status 200 with body:
      """
      {"messages":[42,{"role":"system","content":[{"type":"image_url"},{"type":"text","text":"Edge system."}]},{"role":"system","content":7},{"role":"user","content":[5,{"type":"image_url","image_url":"x"},{"type":"image_url","image_url":{"url":"data:image/png;base64"}},{"type":"image_url","image_url":{"url":"data:;base64,AAAA"}},{"type":"text","text":"Read these."},{"type":"file","file":{"filename":"rrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrr.pdf","file_data":"data:application/pdf;base64,JVBERi0xLjQ="}},{"type":"file","file":{"filename":"@@@.txt","file_data":"data:text/plain;base64,aGVsbG8="}}]},{"role":"user","content":9},{"role":"assistant","content":"Calling.","tool_calls":[7,{"id":"call_a","type":"function"},{"id":"call_b","type":"function","function":{"name":"lookup","arguments":"{}"}}]},{"role":"tool","tool_call_id":"call_b","content":"looked up"},42,{"role":"user","content":"Go on."}],"stop":["END","STOP"],"tools":[3,{"type":"function"}]}
      """
    When I send a "GET" request to the "capture" service at "/test/captured?path=/model/amazon.edge-model/converse"
    Then the response status code should be 200
    And the JSON response field "body" should contain "Edge system."
    And the JSON response field "body" should contain "Read these."
    And the JSON response field "body" should contain "document"
    And the JSON response field "body" should contain "stopSequences"
    When I send a "POST" request to "${CTX:proxyContext}/chat/completions" with body:
      """
      {"messages":[{"role":"user","content":"Hi"}],"tools":[{"type":"function","function":{"name":"lookup"}}],"tool_choice":"something-else"}
      """
    Then the response status code should be 200
    When I send a "GET" request to the "capture" service at "/test/captured?path=/model/amazon.edge-model/converse"
    Then the response status code should be 200
    And the JSON response field "body" should contain "toolSpec"
    And the response body should not contain "toolChoice"
    When I delete the LLM proxy "${CTX:proxyName}"
    Then the response should be successful
    When I delete the LLM provider "${CTX:providerName}"
    Then the response should be successful

  # ---- generated coverage scenarios: end ----
