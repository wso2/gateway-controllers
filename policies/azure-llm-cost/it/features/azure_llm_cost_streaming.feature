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
Feature: Azure LLM Cost policy streaming
  As an API developer
  I want streamed responses priced once, from the events the stream actually carried
  So that a streamed call costs the same as a buffered one and reaches the client unchanged

  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"

  # The mock flushes each event on its own; how many chunks reach the policy is up to the gateway.
  # The policy forwards every chunk unchanged and prices the stream once, when it ends, from the
  # usage the last event carries. azure/gpt-4o-mini: 0.003
  Scenario: Deliver a streamed SSE chat completion split across many chunks, with the usage event arriving last
    Given I generate a unique resource name from "alc-stream" and store it as "providerName"
    And I generate a unique value from "alc-stream" and store it as "providerDisplayName"
    And I generate a unique API version from "alc-stream" and store it as "providerVersion"
    And I generate a unique API context from "/alc-stream" and store it as "providerContext"
    When I create LLM provider from "resources/templates/llm-provider.yaml" with values:
      | apiVersion         | ${CTX:gatewaySpecVersion}  |
      | name               | ${CTX:providerName}        |
      | displayName        | ${CTX:providerDisplayName} |
      | version            | ${CTX:providerVersion}     |
      | template           | azure-openai               |
      | spec.context       | ${CTX:providerContext}     |
      | spec.upstream.url  | http://testbench:3008      |
      | accessControl.mode | allow_all                  |
      | spec.policies      | [{"name":"azure-llm-cost","version":"v1","paths":[{"path":"/*","methods":["*"],"params":{"modelMappings":[{"deployment":"chat-mini","model":"gpt-4o-mini"}]}}]}] |
    Then the response status code should be 201

    # A scripted reply with no model goes unpriced, so polling it until the route is live leaves the
    # requests below the only priced ones on their paths.
    When I send a "POST" request to "${CTX:providerContext}/scripted/ready" until status 200 with body:
      """
      {"x_testbench_reply":{"body":{}}}
      """

    When I send a "POST" request to "${CTX:providerContext}/scripted/openai/v1/chat/completions" with body:
      """
      {"model":"chat-mini","stream":true,"stream_options":{"include_usage":true},"messages":[{"role":"user","content":"Hello"}],"x_testbench_reply":{"events":[{"id":"chatcmpl-alc","object":"chat.completion.chunk","model":"gpt-4o-mini","choices":[{"index":0,"delta":{"role":"assistant","content":""}}],"usage":null},{"id":"chatcmpl-alc","object":"chat.completion.chunk","model":"gpt-4o-mini","choices":[{"index":0,"delta":{"content":"Hi"}}],"usage":null},{"id":"chatcmpl-alc","object":"chat.completion.chunk","model":"gpt-4o-mini","choices":[{"index":0,"delta":{"content":" there"}}],"usage":null},{"id":"chatcmpl-alc","object":"chat.completion.chunk","model":"gpt-4o-mini","choices":[{"index":0,"delta":{},"finish_reason":"stop"}],"usage":null},{"id":"chatcmpl-alc","object":"chat.completion.chunk","model":"gpt-4o-mini","choices":[],"usage":{"prompt_tokens":1000,"completion_tokens":500,"total_tokens":1500}},"data: [DONE]"]}}
      """
    Then the response status code should be 200
    And the response header "Content-Type" should contain "text/event-stream"
    And the response header "X-Testbench-Scripted" should be "true"
    And the response header "x-llm-cost" should not exist
    And the response body should contain template literal:
      """
      {"id":"chatcmpl-alc","object":"chat.completion.chunk","model":"gpt-4o-mini","choices":[{"index":0,"delta":{"role":"assistant","content":""}}],"usage":null}
      """
    And the response body should contain template literal:
      """
      {"id":"chatcmpl-alc","object":"chat.completion.chunk","model":"gpt-4o-mini","choices":[{"index":0,"delta":{"content":"Hi"}}],"usage":null}
      """
    And the response body should contain template literal:
      """
      {"id":"chatcmpl-alc","object":"chat.completion.chunk","model":"gpt-4o-mini","choices":[{"index":0,"delta":{"content":" there"}}],"usage":null}
      """
    And the response body should contain template literal:
      """
      {"id":"chatcmpl-alc","object":"chat.completion.chunk","model":"gpt-4o-mini","choices":[{"index":0,"delta":{},"finish_reason":"stop"}],"usage":null}
      """
    And the response body should contain template literal:
      """
      {"id":"chatcmpl-alc","object":"chat.completion.chunk","model":"gpt-4o-mini","choices":[],"usage":{"prompt_tokens":1000,"completion_tokens":500,"total_tokens":1500}}
      """
    And the response body should contain "data: [DONE]"
    And the latest analytics event for path "${CTX:providerContext}/scripted/openai/v1/chat/completions" should have numeric metadata field "aiMetadata.llmCost" equal to "0.003"
    And the latest analytics event for path "${CTX:providerContext}/scripted/openai/v1/chat/completions" should have numeric metadata field "aiTokenUsage.promptTokens" equal to "1000"
    And the latest analytics event for path "${CTX:providerContext}/scripted/openai/v1/chat/completions" should have numeric metadata field "aiTokenUsage.completionTokens" equal to "500"
    And the latest analytics event for path "${CTX:providerContext}/scripted/openai/v1/chat/completions" should have numeric metadata field "aiTokenUsage.totalTokens" equal to "1500"

    When I delete the LLM provider "${CTX:providerName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:providerContext}/scripted/ready" until status 404

  # Azure's first chunk carries an empty model, and the request's deployment is not mapped, so only the
  # model a later chunk reports can price the call. The non-JSON line and [DONE] are skipped.
  # azure/gpt-4o-mini: 0.003
  Scenario: Merge an Azure SSE stream whose first chunk carries an empty model, alongside the [DONE] sentinel and a non-JSON event line
    Given I generate a unique resource name from "alc-merge-model" and store it as "providerName"
    And I generate a unique value from "alc-merge-model" and store it as "providerDisplayName"
    And I generate a unique API version from "alc-merge-model" and store it as "providerVersion"
    And I generate a unique API context from "/alc-merge-model" and store it as "providerContext"
    When I create LLM provider from "resources/templates/llm-provider.yaml" with values:
      | apiVersion         | ${CTX:gatewaySpecVersion}  |
      | name               | ${CTX:providerName}        |
      | displayName        | ${CTX:providerDisplayName} |
      | version            | ${CTX:providerVersion}     |
      | template           | azure-openai               |
      | spec.context       | ${CTX:providerContext}     |
      | spec.upstream.url  | http://testbench:3008      |
      | accessControl.mode | allow_all                  |
      | spec.policies      | [{"name":"azure-llm-cost","version":"v1","paths":[{"path":"/*","methods":["*"],"params":{"modelMappings":[{"deployment":"chat-mini","model":"gpt-4o-mini"}]}}]}] |
    Then the response status code should be 201

    # A scripted reply with no model goes unpriced, so polling it until the route is live leaves the
    # requests below the only priced ones on their paths.
    When I send a "POST" request to "${CTX:providerContext}/scripted/ready" until status 200 with body:
      """
      {"x_testbench_reply":{"body":{}}}
      """

    When I send a "POST" request to "${CTX:providerContext}/scripted/openai/v1/chat/completions" with body:
      """
      {"model":"stream-deployment","stream":true,"stream_options":{"include_usage":true},"messages":[{"role":"user","content":"Hello"}],"x_testbench_reply":{"events":[{"id":"chatcmpl-alc","object":"chat.completion.chunk","model":"","choices":[],"prompt_filter_results":[{"prompt_index":0,"content_filter_results":{}}]},{"id":"chatcmpl-alc","object":"chat.completion.chunk","model":"gpt-4o-mini","choices":[{"index":0,"delta":{"role":"assistant","content":"Hi"}}],"usage":null},"data: keep-alive",{"id":"chatcmpl-alc","object":"chat.completion.chunk","model":"gpt-4o-mini","choices":[],"usage":{"prompt_tokens":1000,"completion_tokens":500,"total_tokens":1500}},"data: [DONE]"]}}
      """
    Then the response status code should be 200
    And the response header "Content-Type" should contain "text/event-stream"
    And the response header "X-Testbench-Scripted" should be "true"
    And the response header "x-llm-cost" should not exist
    And the response body should contain template literal:
      """
      {"id":"chatcmpl-alc","object":"chat.completion.chunk","model":"","choices":[],"prompt_filter_results":[{"prompt_index":0,"content_filter_results":{}}]}
      """
    And the response body should contain template literal:
      """
      {"id":"chatcmpl-alc","object":"chat.completion.chunk","model":"gpt-4o-mini","choices":[{"index":0,"delta":{"role":"assistant","content":"Hi"}}],"usage":null}
      """
    And the response body should contain "data: keep-alive"
    And the response body should contain template literal:
      """
      {"id":"chatcmpl-alc","object":"chat.completion.chunk","model":"gpt-4o-mini","choices":[],"usage":{"prompt_tokens":1000,"completion_tokens":500,"total_tokens":1500}}
      """
    And the response body should contain "data: [DONE]"
    And the latest analytics event for path "${CTX:providerContext}/scripted/openai/v1/chat/completions" should have numeric metadata field "aiMetadata.llmCost" equal to "0.003"
    And the latest analytics event for path "${CTX:providerContext}/scripted/openai/v1/chat/completions" should have numeric metadata field "aiTokenUsage.promptTokens" equal to "1000"
    And the latest analytics event for path "${CTX:providerContext}/scripted/openai/v1/chat/completions" should have numeric metadata field "aiTokenUsage.completionTokens" equal to "500"
    And the latest analytics event for path "${CTX:providerContext}/scripted/openai/v1/chat/completions" should have numeric metadata field "aiTokenUsage.totalTokens" equal to "1500"

    When I delete the LLM provider "${CTX:providerName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:providerContext}/scripted/ready" until status 404

  # The first event's null model holds until a later event names it. Usage arrives in two parts and
  # is merged. The trailing content-filter event repeats model blank and usage null, which must not
  # erase either. The request's deployment is not mapped. azure/gpt-4o-mini: 0.003
  Scenario: Merge a stream whose trailing content-filter events repeat model as blank and usage as null, and whose first event carries a null before a later value
    Given I generate a unique resource name from "alc-merge-nulls" and store it as "providerName"
    And I generate a unique value from "alc-merge-nulls" and store it as "providerDisplayName"
    And I generate a unique API version from "alc-merge-nulls" and store it as "providerVersion"
    And I generate a unique API context from "/alc-merge-nulls" and store it as "providerContext"
    When I create LLM provider from "resources/templates/llm-provider.yaml" with values:
      | apiVersion         | ${CTX:gatewaySpecVersion}  |
      | name               | ${CTX:providerName}        |
      | displayName        | ${CTX:providerDisplayName} |
      | version            | ${CTX:providerVersion}     |
      | template           | azure-openai               |
      | spec.context       | ${CTX:providerContext}     |
      | spec.upstream.url  | http://testbench:3008      |
      | accessControl.mode | allow_all                  |
      | spec.policies      | [{"name":"azure-llm-cost","version":"v1","paths":[{"path":"/*","methods":["*"],"params":{"modelMappings":[{"deployment":"chat-mini","model":"gpt-4o-mini"}]}}]}] |
    Then the response status code should be 201

    # A scripted reply with no model goes unpriced, so polling it until the route is live leaves the
    # requests below the only priced ones on their paths.
    When I send a "POST" request to "${CTX:providerContext}/scripted/ready" until status 200 with body:
      """
      {"x_testbench_reply":{"body":{}}}
      """

    When I send a "POST" request to "${CTX:providerContext}/scripted/openai/v1/chat/completions" with body:
      """
      {"model":"stream-deployment","stream":true,"stream_options":{"include_usage":true},"messages":[{"role":"user","content":"Hello"}],"x_testbench_reply":{"events":[{"id":"chatcmpl-alc","model":null,"choices":[],"usage":null},{"id":"chatcmpl-alc","object":"chat.completion.chunk","model":"gpt-4o-mini","choices":[{"index":0,"delta":{"role":"assistant","content":"Hi"}}],"usage":null},{"id":"chatcmpl-alc","model":"gpt-4o-mini","choices":[],"usage":{"prompt_tokens":1000}},{"id":"chatcmpl-alc","model":"gpt-4o-mini","choices":[],"usage":{"completion_tokens":500,"total_tokens":1500}},{"id":"chatcmpl-alc","model":"","choices":[],"usage":null,"prompt_filter_results":[{"prompt_index":0,"content_filter_results":{}}]},"data: [DONE]"]}}
      """
    Then the response status code should be 200
    And the response header "Content-Type" should contain "text/event-stream"
    And the response header "X-Testbench-Scripted" should be "true"
    And the response header "x-llm-cost" should not exist
    And the response body should contain template literal:
      """
      {"id":"chatcmpl-alc","model":null,"choices":[],"usage":null}
      """
    And the response body should contain template literal:
      """
      {"id":"chatcmpl-alc","object":"chat.completion.chunk","model":"gpt-4o-mini","choices":[{"index":0,"delta":{"role":"assistant","content":"Hi"}}],"usage":null}
      """
    And the response body should contain template literal:
      """
      {"id":"chatcmpl-alc","model":"gpt-4o-mini","choices":[],"usage":{"prompt_tokens":1000}}
      """
    And the response body should contain template literal:
      """
      {"id":"chatcmpl-alc","model":"gpt-4o-mini","choices":[],"usage":{"completion_tokens":500,"total_tokens":1500}}
      """
    And the response body should contain template literal:
      """
      {"id":"chatcmpl-alc","model":"","choices":[],"usage":null,"prompt_filter_results":[{"prompt_index":0,"content_filter_results":{}}]}
      """
    And the response body should contain "data: [DONE]"
    And the latest analytics event for path "${CTX:providerContext}/scripted/openai/v1/chat/completions" should have numeric metadata field "aiMetadata.llmCost" equal to "0.003"
    And the latest analytics event for path "${CTX:providerContext}/scripted/openai/v1/chat/completions" should have numeric metadata field "aiTokenUsage.promptTokens" equal to "1000"
    And the latest analytics event for path "${CTX:providerContext}/scripted/openai/v1/chat/completions" should have numeric metadata field "aiTokenUsage.completionTokens" equal to "500"
    And the latest analytics event for path "${CTX:providerContext}/scripted/openai/v1/chat/completions" should have numeric metadata field "aiTokenUsage.totalTokens" equal to "1500"

    When I delete the LLM provider "${CTX:providerName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:providerContext}/scripted/ready" until status 404

  # No event parses, so there is nothing to merge; every line still reaches the client.
  Scenario: Stream a response whose events are all unparseable, and separately end a stream having received no chunks at all (all events unparseable)
    Given I generate a unique resource name from "alc-unparseable" and store it as "providerName"
    And I generate a unique value from "alc-unparseable" and store it as "providerDisplayName"
    And I generate a unique API version from "alc-unparseable" and store it as "providerVersion"
    And I generate a unique API context from "/alc-unparseable" and store it as "providerContext"
    When I create LLM provider from "resources/templates/llm-provider.yaml" with values:
      | apiVersion         | ${CTX:gatewaySpecVersion}  |
      | name               | ${CTX:providerName}        |
      | displayName        | ${CTX:providerDisplayName} |
      | version            | ${CTX:providerVersion}     |
      | template           | azure-openai               |
      | spec.context       | ${CTX:providerContext}     |
      | spec.upstream.url  | http://testbench:3008      |
      | accessControl.mode | allow_all                  |
      | spec.policies      | [{"name":"azure-llm-cost","version":"v1","paths":[{"path":"/*","methods":["*"],"params":{"modelMappings":[{"deployment":"chat-mini","model":"gpt-4o-mini"}]}}]}] |
    Then the response status code should be 201

    # A scripted reply with no model goes unpriced, so polling it until the route is live leaves the
    # requests below the only priced ones on their paths.
    When I send a "POST" request to "${CTX:providerContext}/scripted/ready" until status 200 with body:
      """
      {"x_testbench_reply":{"body":{}}}
      """

    When I send a "POST" request to "${CTX:providerContext}/scripted/openai/v1/chat/completions" with body:
      """
      {"model":"chat-mini","stream":true,"stream_options":{"include_usage":true},"messages":[{"role":"user","content":"Hello"}],"x_testbench_reply":{"events":["data: not json","data: {broken","data: [DONE]"]}}
      """
    Then the response status code should be 200
    And the response header "Content-Type" should contain "text/event-stream"
    And the response header "X-Testbench-Scripted" should be "true"
    And the response header "x-llm-cost" should not exist
    And the response body should contain "data: not json"
    And the response body should contain "data: {broken"
    And the response body should contain "data: [DONE]"
    And the latest analytics event for path "${CTX:providerContext}/scripted/openai/v1/chat/completions" should have numeric metadata field "aiMetadata.llmCost" equal to "0"

    When I delete the LLM provider "${CTX:providerName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:providerContext}/scripted/ready" until status 404

  # The stream ends without a single event.
  Scenario: Stream a response whose events are all unparseable, and separately end a stream having received no chunks at all (no chunks)
    Given I generate a unique resource name from "alc-no-chunks" and store it as "providerName"
    And I generate a unique value from "alc-no-chunks" and store it as "providerDisplayName"
    And I generate a unique API version from "alc-no-chunks" and store it as "providerVersion"
    And I generate a unique API context from "/alc-no-chunks" and store it as "providerContext"
    When I create LLM provider from "resources/templates/llm-provider.yaml" with values:
      | apiVersion         | ${CTX:gatewaySpecVersion}  |
      | name               | ${CTX:providerName}        |
      | displayName        | ${CTX:providerDisplayName} |
      | version            | ${CTX:providerVersion}     |
      | template           | azure-openai               |
      | spec.context       | ${CTX:providerContext}     |
      | spec.upstream.url  | http://testbench:3008      |
      | accessControl.mode | allow_all                  |
      | spec.policies      | [{"name":"azure-llm-cost","version":"v1","paths":[{"path":"/*","methods":["*"],"params":{"modelMappings":[{"deployment":"chat-mini","model":"gpt-4o-mini"}]}}]}] |
    Then the response status code should be 201

    # A scripted reply with no model goes unpriced, so polling it until the route is live leaves the
    # requests below the only priced ones on their paths.
    When I send a "POST" request to "${CTX:providerContext}/scripted/ready" until status 200 with body:
      """
      {"x_testbench_reply":{"body":{}}}
      """

    When I send a "POST" request to "${CTX:providerContext}/scripted/openai/v1/chat/completions" with body:
      """
      {"model":"chat-mini","stream":true,"stream_options":{"include_usage":true},"messages":[{"role":"user","content":"Hello"}],"x_testbench_reply":{"events":[]}}
      """
    Then the response status code should be 200
    And the response body should be empty
    And the response header "X-Testbench-Scripted" should be "true"
    And the response header "x-llm-cost" should not exist
    And the latest analytics event for path "${CTX:providerContext}/scripted/openai/v1/chat/completions" should have numeric metadata field "aiMetadata.llmCost" equal to "0"

    When I delete the LLM provider "${CTX:providerName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:providerContext}/scripted/ready" until status 404
