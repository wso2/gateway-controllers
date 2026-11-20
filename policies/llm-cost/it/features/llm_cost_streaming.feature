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

@llm-cost
Feature: LLM cost streaming
  As an API developer
  I want streamed responses priced once, from the events the stream actually carried
  So that a streamed call costs the same as a buffered one and reaches the client unchanged

  # The mock flushes each event on its own; how many chunks reach the policy is up to the gateway.
  # The policy forwards every chunk unchanged and prices the stream once, when it ends.

  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"

  Scenario: Stream an OpenAI SSE chat completion with the usage event last
    Given I generate a unique resource name from "lc-stream-usage" and store it as "providerName"
    And I generate a unique value from "lc-stream-usage" and store it as "providerDisplayName"
    And I generate a unique API version from "lc-stream-usage" and store it as "providerVersion"
    And I generate a unique API context from "/lc-stream-usage" and store it as "providerContext"
    When I create LLM provider from "resources/templates/llm-provider.yaml" with values:
      | apiVersion         | ${CTX:gatewaySpecVersion}  |
      | name               | ${CTX:providerName}        |
      | displayName        | ${CTX:providerDisplayName} |
      | version            | ${CTX:providerVersion}     |
      | template           | openai |
      | spec.context       | ${CTX:providerContext}     |
      | spec.upstream.url  | http://testbench:3008      |
      | accessControl.mode | allow_all                  |
      | spec.policies      | [{"name":"llm-cost","version":"v1","paths":[{"path":"/*","methods":["*"]}]}] |
    Then the response status code should be 201

    # A scripted reply with no model goes unpriced, so polling it until the route is live leaves the
    # requests below the only priced ones on their paths.
    When I send a "POST" request to "${CTX:providerContext}/scripted/ready" until status 200 with body:
      """
      {"x_testbench_reply":{"body":{}}}
      """
    # gpt-4o-mini: 1000 x 0.000001 + 500 x 0.000004 = 0.003, the same as the buffered reply

    When I send a "POST" request to "${CTX:providerContext}/scripted/openai/v1/chat/completions" with body:
      """
      {"model":"gpt-4o-mini","messages":[{"role":"user","content":"Hello"}],"stream":true,"stream_options":{"include_usage":true},"x_testbench_reply":{"events":[{"id":"chatcmpl-lc","object":"chat.completion.chunk","model":"gpt-4o-mini","choices":[{"index":0,"delta":{"role":"assistant","content":""}}],"usage":null},{"id":"chatcmpl-lc","object":"chat.completion.chunk","model":"gpt-4o-mini","choices":[{"index":0,"delta":{"content":"Hi"}}],"usage":null},{"id":"chatcmpl-lc","object":"chat.completion.chunk","model":"gpt-4o-mini","choices":[{"index":0,"delta":{"content":" there"}}],"usage":null},{"id":"chatcmpl-lc","object":"chat.completion.chunk","model":"gpt-4o-mini","choices":[],"usage":{"prompt_tokens":1000,"completion_tokens":500,"total_tokens":1500}},"data: [DONE]"]}}
      """
    Then the response status code should be 200
    And the response header "X-Testbench-Scripted" should be "true"
    And the response header "x-llm-cost" should not exist
    And the response header "Content-Type" should contain "text/event-stream"
    And the response body should contain template literal:
      """
      {"id":"chatcmpl-lc","object":"chat.completion.chunk","model":"gpt-4o-mini","choices":[{"index":0,"delta":{"role":"assistant","content":""}}],"usage":null}
      """
    And the response body should contain template literal:
      """
      {"id":"chatcmpl-lc","object":"chat.completion.chunk","model":"gpt-4o-mini","choices":[{"index":0,"delta":{"content":"Hi"}}],"usage":null}
      """
    And the response body should contain template literal:
      """
      {"id":"chatcmpl-lc","object":"chat.completion.chunk","model":"gpt-4o-mini","choices":[{"index":0,"delta":{"content":" there"}}],"usage":null}
      """
    And the latest analytics event for path "${CTX:providerContext}/scripted/openai/v1/chat/completions" should have numeric metadata field "aiMetadata.llmCost" equal to "0.003"
    And the latest analytics event for path "${CTX:providerContext}/scripted/openai/v1/chat/completions" should have numeric metadata field "aiTokenUsage.promptTokens" equal to "1000"
    And the latest analytics event for path "${CTX:providerContext}/scripted/openai/v1/chat/completions" should have numeric metadata field "aiTokenUsage.completionTokens" equal to "500"
    And the latest analytics event for path "${CTX:providerContext}/scripted/openai/v1/chat/completions" should have numeric metadata field "aiTokenUsage.totalTokens" equal to "1500"

    When I delete the LLM provider "${CTX:providerName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:providerContext}/scripted/ready" until status 404

  Scenario: Stream an OpenAI SSE chat completion that never sends a usage event
    Given I generate a unique resource name from "lc-stream-no-usage" and store it as "providerName"
    And I generate a unique value from "lc-stream-no-usage" and store it as "providerDisplayName"
    And I generate a unique API version from "lc-stream-no-usage" and store it as "providerVersion"
    And I generate a unique API context from "/lc-stream-no-usage" and store it as "providerContext"
    When I create LLM provider from "resources/templates/llm-provider.yaml" with values:
      | apiVersion         | ${CTX:gatewaySpecVersion}  |
      | name               | ${CTX:providerName}        |
      | displayName        | ${CTX:providerDisplayName} |
      | version            | ${CTX:providerVersion}     |
      | template           | openai |
      | spec.context       | ${CTX:providerContext}     |
      | spec.upstream.url  | http://testbench:3008      |
      | accessControl.mode | allow_all                  |
      | spec.policies      | [{"name":"llm-cost","version":"v1","paths":[{"path":"/*","methods":["*"]}]}] |
    Then the response status code should be 201

    # A scripted reply with no model goes unpriced, so polling it until the route is live leaves the
    # requests below the only priced ones on their paths.
    When I send a "POST" request to "${CTX:providerContext}/scripted/ready" until status 200 with body:
      """
      {"x_testbench_reply":{"body":{}}}
      """

    When I send a "POST" request to "${CTX:providerContext}/scripted/openai/v1/chat/completions" with body:
      """
      {"model":"gpt-4o-mini","messages":[{"role":"user","content":"Hello"}],"stream":true,"x_testbench_reply":{"events":[{"id":"chatcmpl-lc","object":"chat.completion.chunk","model":"gpt-4o-mini","choices":[{"index":0,"delta":{"role":"assistant","content":"Hi"}}],"usage":null},{"id":"chatcmpl-lc","object":"chat.completion.chunk","model":"gpt-4o-mini","choices":[{"index":0,"delta":{"content":" there"}}],"usage":null},"data: [DONE]"]}}
      """
    Then the response status code should be 200
    And the response header "X-Testbench-Scripted" should be "true"
    And the response header "x-llm-cost" should not exist
    And the response header "Content-Type" should contain "text/event-stream"
    And the response body should contain template literal:
      """
      {"id":"chatcmpl-lc","object":"chat.completion.chunk","model":"gpt-4o-mini","choices":[{"index":0,"delta":{"role":"assistant","content":"Hi"}}],"usage":null}
      """
    And the latest analytics event for path "${CTX:providerContext}/scripted/openai/v1/chat/completions" should have numeric metadata field "aiMetadata.llmCost" equal to "0"

    When I delete the LLM provider "${CTX:providerName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:providerContext}/scripted/ready" until status 404

  # Fixed in newer gateways by wso2/api-platform PR #3275 (https://github.com/wso2/api-platform/pull/3275): the built-in template gains serviceTier and providerFields.
  @known-issue-gw-1.2.0
  Scenario: Stream an Anthropic SSE response with the model and input usage in the opening event
    Given I generate a unique resource name from "lc-stream-anthropic" and store it as "providerName"
    And I generate a unique value from "lc-stream-anthropic" and store it as "providerDisplayName"
    And I generate a unique API version from "lc-stream-anthropic" and store it as "providerVersion"
    And I generate a unique API context from "/lc-stream-anthropic" and store it as "providerContext"
    When I create LLM provider from "resources/templates/llm-provider.yaml" with values:
      | apiVersion         | ${CTX:gatewaySpecVersion}  |
      | name               | ${CTX:providerName}        |
      | displayName        | ${CTX:providerDisplayName} |
      | version            | ${CTX:providerVersion}     |
      | template           | anthropic |
      | spec.context       | ${CTX:providerContext}     |
      | spec.upstream.url  | http://testbench:3008      |
      | accessControl.mode | allow_all                  |
      | spec.policies      | [{"name":"llm-cost","version":"v1","paths":[{"path":"/*","methods":["*"]}]}] |
    Then the response status code should be 201

    # A scripted reply with no model goes unpriced, so polling it until the route is live leaves the
    # requests below the only priced ones on their paths.
    When I send a "POST" request to "${CTX:providerContext}/scripted/ready" until status 200 with body:
      """
      {"x_testbench_reply":{"body":{}}}
      """
    # claude-test: 1000 x 0.000003 + 500 x 0.000015 = 0.0105, the input read from message_start
    # and the output from message_delta

    When I send a "POST" request to "${CTX:providerContext}/scripted/anthropic/v1/messages" with body:
      """
      {"model":"claude-test","max_tokens":100,"stream":true,"messages":[{"role":"user","content":"Hello"}],"x_testbench_reply":{"events":["event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_lc\",\"type\":\"message\",\"role\":\"assistant\",\"model\":\"claude-test\",\"content\":[],\"usage\":{\"input_tokens\":1000,\"output_tokens\":1}}}","event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"Hi\"}}","event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":500}}","event: message_stop\ndata: {\"type\":\"message_stop\"}"]}}
      """
    Then the response status code should be 200
    And the response header "X-Testbench-Scripted" should be "true"
    And the response header "x-llm-cost" should not exist
    And the response header "Content-Type" should contain "text/event-stream"
    And the response body should contain "message_start"
    And the response body should contain "message_delta"
    And the latest analytics event for path "${CTX:providerContext}/scripted/anthropic/v1/messages" should have numeric metadata field "aiMetadata.llmCost" equal to "0.0105"
    And the latest analytics event for path "${CTX:providerContext}/scripted/anthropic/v1/messages" should have numeric metadata field "aiTokenUsage.promptTokens" equal to "1000"
    And the latest analytics event for path "${CTX:providerContext}/scripted/anthropic/v1/messages" should have numeric metadata field "aiTokenUsage.completionTokens" equal to "500"

    When I delete the LLM provider "${CTX:providerName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:providerContext}/scripted/ready" until status 404
