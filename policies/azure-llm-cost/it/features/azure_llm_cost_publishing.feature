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
Feature: Azure LLM Cost policy publishing and failures
  As an API developer
  I want to know what the policy publishes for priced and unpriced calls
  So that a call that could not be priced never blocks, rewrites or misreports the response

  # Also covers hostile and failing responses, which the policy forwards untouched.

  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"

  # azure/gpt-4o-mini: 1000 x 0.000001 + 500 x 0.000004 = 0.003
  Scenario: Deliver a complete non-streamed response through the buffered response phase
    Given I generate a unique resource name from "alc-buffered" and store it as "providerName"
    And I generate a unique value from "alc-buffered" and store it as "providerDisplayName"
    And I generate a unique API version from "alc-buffered" and store it as "providerVersion"
    And I generate a unique API context from "/alc-buffered" and store it as "providerContext"
    When I create LLM provider from "resources/templates/llm-provider.yaml" with values:
      | apiVersion         | ${CTX:gatewaySpecVersion}  |
      | name               | ${CTX:providerName}        |
      | displayName        | ${CTX:providerDisplayName} |
      | version            | ${CTX:providerVersion}     |
      | template           | azure-openai               |
      | spec.context       | ${CTX:providerContext}     |
      | spec.upstream.url  | http://testbench:3008      |
      | accessControl.mode | allow_all                  |
      | spec.policies      | [{"name":"azure-llm-cost","version":"v1","paths":[{"path":"/*","methods":["*"],"params":{"modelMappings":[{"deployment":"resp-mini","model":"gpt-4o-mini"}]}}]}] |
    Then the response status code should be 201

    # A scripted reply with no model goes unpriced, so polling it until the route is live leaves the
    # requests below the only priced ones on their paths.
    When I send a "POST" request to "${CTX:providerContext}/scripted/ready" until status 200 with body:
      """
      {"x_testbench_reply":{"body":{}}}
      """

    When I send a "POST" request to "${CTX:providerContext}/scripted/openai/v1/responses" with body:
      """
      {"model":"resp-mini","input":"Hello","x_testbench_reply":{"body":{"id":"resp_alc","object":"response","model":"resp-mini","output":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":"Hi there"}]}],"usage":{"input_tokens":1000,"output_tokens":500,"total_tokens":1500}}}}
      """
    Then the response status code should be 200
    And the response body should be:
      """
      {"id":"resp_alc","object":"response","model":"resp-mini","output":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":"Hi there"}]}],"usage":{"input_tokens":1000,"output_tokens":500,"total_tokens":1500}}
      """
    And the response header "X-Testbench-Scripted" should be "true"
    And the response header "x-llm-cost" should not exist
    And the latest analytics event for path "${CTX:providerContext}/scripted/openai/v1/responses" should have numeric metadata field "aiMetadata.llmCost" equal to "0.003"
    And the latest analytics event for path "${CTX:providerContext}/scripted/openai/v1/responses" should have numeric metadata field "aiTokenUsage.promptTokens" equal to "1000"
    And the latest analytics event for path "${CTX:providerContext}/scripted/openai/v1/responses" should have numeric metadata field "aiTokenUsage.completionTokens" equal to "500"
    And the latest analytics event for path "${CTX:providerContext}/scripted/openai/v1/responses" should have numeric metadata field "aiTokenUsage.totalTokens" equal to "1500"

    When I delete the LLM provider "${CTX:providerName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:providerContext}/scripted/ready" until status 404

  # A small call whose cost needs many decimals: 7 x 0.000001 + 3 x 0.000004 = 0.000019.
  Scenario: Price a request successfully and inspect the SharedContext metadata the policy publishes
    Given I generate a unique resource name from "alc-published-priced" and store it as "providerName"
    And I generate a unique value from "alc-published-priced" and store it as "providerDisplayName"
    And I generate a unique API version from "alc-published-priced" and store it as "providerVersion"
    And I generate a unique API context from "/alc-published-priced" and store it as "providerContext"
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
      {"model":"chat-mini","messages":[{"role":"user","content":"Hello"}],"x_testbench_reply":{"body":{"id":"chatcmpl-alc","object":"chat.completion","model":"gpt-4o-mini","choices":[{"index":0,"message":{"role":"assistant","content":"Hi there"},"finish_reason":"stop"}],"usage":{"prompt_tokens":7,"completion_tokens":3,"total_tokens":10}}}}
      """
    Then the response status code should be 200
    And the response body should be:
      """
      {"id":"chatcmpl-alc","object":"chat.completion","model":"gpt-4o-mini","choices":[{"index":0,"message":{"role":"assistant","content":"Hi there"},"finish_reason":"stop"}],"usage":{"prompt_tokens":7,"completion_tokens":3,"total_tokens":10}}
      """
    And the response header "X-Testbench-Scripted" should be "true"
    And the response header "x-llm-cost" should not exist
    And the latest analytics event for path "${CTX:providerContext}/scripted/openai/v1/chat/completions" should have numeric metadata field "aiMetadata.llmCost" equal to "0.000019"
    And the latest analytics event for path "${CTX:providerContext}/scripted/openai/v1/chat/completions" should have numeric metadata field "aiTokenUsage.promptTokens" equal to "7"
    And the latest analytics event for path "${CTX:providerContext}/scripted/openai/v1/chat/completions" should have numeric metadata field "aiTokenUsage.completionTokens" equal to "3"
    And the latest analytics event for path "${CTX:providerContext}/scripted/openai/v1/chat/completions" should have numeric metadata field "aiTokenUsage.totalTokens" equal to "10"

    When I delete the LLM provider "${CTX:providerName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:providerContext}/scripted/ready" until status 404

  # An unknown model with real token usage still publishes a zero cost, not a guessed one.
  Scenario: Fail to price a request and inspect the SharedContext metadata
    Given I generate a unique resource name from "alc-published-unpriced" and store it as "providerName"
    And I generate a unique value from "alc-published-unpriced" and store it as "providerDisplayName"
    And I generate a unique API version from "alc-published-unpriced" and store it as "providerVersion"
    And I generate a unique API context from "/alc-published-unpriced" and store it as "providerContext"
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
      {"model":"unlisted-deployment","messages":[{"role":"user","content":"Hello"}],"x_testbench_reply":{"body":{"id":"chatcmpl-alc","object":"chat.completion","model":"gpt-9-preview","choices":[{"index":0,"message":{"role":"assistant","content":"Hi there"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1000,"completion_tokens":500,"total_tokens":1500}}}}
      """
    Then the response status code should be 200
    And the response body should be:
      """
      {"id":"chatcmpl-alc","object":"chat.completion","model":"gpt-9-preview","choices":[{"index":0,"message":{"role":"assistant","content":"Hi there"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1000,"completion_tokens":500,"total_tokens":1500}}
      """
    And the response header "X-Testbench-Scripted" should be "true"
    And the response header "x-llm-cost" should not exist
    And the latest analytics event for path "${CTX:providerContext}/scripted/openai/v1/chat/completions" should have numeric metadata field "aiMetadata.llmCost" equal to "0"

    When I delete the LLM provider "${CTX:providerName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:providerContext}/scripted/ready" until status 404

  # The same call, buffered and streamed, publishes the same cost and token counts.
  Scenario: Price the same payload through the buffered phase and the streaming phase, both priced and unpriced (priced)
    Given I generate a unique resource name from "alc-phases-priced" and store it as "providerName"
    And I generate a unique value from "alc-phases-priced" and store it as "providerDisplayName"
    And I generate a unique API version from "alc-phases-priced" and store it as "providerVersion"
    And I generate a unique API context from "/alc-phases-priced" and store it as "providerContext"
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

    When I send a "POST" request to "${CTX:providerContext}/scripted/buffered/chat/completions" with body:
      """
      {"model":"chat-mini","messages":[{"role":"user","content":"Hello"}],"x_testbench_reply":{"body":{"id":"chatcmpl-alc","object":"chat.completion","model":"gpt-4o-mini","choices":[{"index":0,"message":{"role":"assistant","content":"Hi there"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1000,"completion_tokens":500,"total_tokens":1500}}}}
      """
    Then the response status code should be 200
    And the response body should be:
      """
      {"id":"chatcmpl-alc","object":"chat.completion","model":"gpt-4o-mini","choices":[{"index":0,"message":{"role":"assistant","content":"Hi there"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1000,"completion_tokens":500,"total_tokens":1500}}
      """
    And the response header "X-Testbench-Scripted" should be "true"
    And the response header "x-llm-cost" should not exist
    And the latest analytics event for path "${CTX:providerContext}/scripted/buffered/chat/completions" should have numeric metadata field "aiMetadata.llmCost" equal to "0.003"
    And the latest analytics event for path "${CTX:providerContext}/scripted/buffered/chat/completions" should have numeric metadata field "aiTokenUsage.promptTokens" equal to "1000"
    And the latest analytics event for path "${CTX:providerContext}/scripted/buffered/chat/completions" should have numeric metadata field "aiTokenUsage.completionTokens" equal to "500"
    And the latest analytics event for path "${CTX:providerContext}/scripted/buffered/chat/completions" should have numeric metadata field "aiTokenUsage.totalTokens" equal to "1500"

    When I send a "POST" request to "${CTX:providerContext}/scripted/streamed/chat/completions" with body:
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
    And the latest analytics event for path "${CTX:providerContext}/scripted/streamed/chat/completions" should have numeric metadata field "aiMetadata.llmCost" equal to "0.003"
    And the latest analytics event for path "${CTX:providerContext}/scripted/streamed/chat/completions" should have numeric metadata field "aiTokenUsage.promptTokens" equal to "1000"
    And the latest analytics event for path "${CTX:providerContext}/scripted/streamed/chat/completions" should have numeric metadata field "aiTokenUsage.completionTokens" equal to "500"
    And the latest analytics event for path "${CTX:providerContext}/scripted/streamed/chat/completions" should have numeric metadata field "aiTokenUsage.totalTokens" equal to "1500"

    When I delete the LLM provider "${CTX:providerName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:providerContext}/scripted/ready" until status 404

  # The same unpriced call, buffered and streamed, publishes the same zero cost and nothing else.
  Scenario: Price the same payload through the buffered phase and the streaming phase, both priced and unpriced (unpriced)
    Given I generate a unique resource name from "alc-phases-unpriced" and store it as "providerName"
    And I generate a unique value from "alc-phases-unpriced" and store it as "providerDisplayName"
    And I generate a unique API version from "alc-phases-unpriced" and store it as "providerVersion"
    And I generate a unique API context from "/alc-phases-unpriced" and store it as "providerContext"
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

    When I send a "POST" request to "${CTX:providerContext}/scripted/buffered/chat/completions" with body:
      """
      {"model":"unlisted-deployment","messages":[{"role":"user","content":"Hello"}],"x_testbench_reply":{"body":{"id":"chatcmpl-alc","object":"chat.completion","model":"gpt-9-preview","choices":[{"index":0,"message":{"role":"assistant","content":"Hi there"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1000,"completion_tokens":500,"total_tokens":1500}}}}
      """
    Then the response status code should be 200
    And the response body should be:
      """
      {"id":"chatcmpl-alc","object":"chat.completion","model":"gpt-9-preview","choices":[{"index":0,"message":{"role":"assistant","content":"Hi there"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1000,"completion_tokens":500,"total_tokens":1500}}
      """
    And the response header "X-Testbench-Scripted" should be "true"
    And the response header "x-llm-cost" should not exist
    And the latest analytics event for path "${CTX:providerContext}/scripted/buffered/chat/completions" should have numeric metadata field "aiMetadata.llmCost" equal to "0"

    When I send a "POST" request to "${CTX:providerContext}/scripted/streamed/chat/completions" with body:
      """
      {"model":"unlisted-deployment","stream":true,"stream_options":{"include_usage":true},"messages":[{"role":"user","content":"Hello"}],"x_testbench_reply":{"events":[{"id":"chatcmpl-alc","object":"chat.completion.chunk","model":"gpt-9-preview","choices":[{"index":0,"delta":{"role":"assistant","content":""}}],"usage":null},{"id":"chatcmpl-alc","object":"chat.completion.chunk","model":"gpt-9-preview","choices":[{"index":0,"delta":{"content":"Hi"}}],"usage":null},{"id":"chatcmpl-alc","object":"chat.completion.chunk","model":"gpt-9-preview","choices":[{"index":0,"delta":{"content":" there"}}],"usage":null},{"id":"chatcmpl-alc","object":"chat.completion.chunk","model":"gpt-9-preview","choices":[{"index":0,"delta":{},"finish_reason":"stop"}],"usage":null},{"id":"chatcmpl-alc","object":"chat.completion.chunk","model":"gpt-9-preview","choices":[],"usage":{"prompt_tokens":1000,"completion_tokens":500,"total_tokens":1500}},"data: [DONE]"]}}
      """
    Then the response status code should be 200
    And the response header "Content-Type" should contain "text/event-stream"
    And the response header "X-Testbench-Scripted" should be "true"
    And the response header "x-llm-cost" should not exist
    And the response body should contain template literal:
      """
      {"id":"chatcmpl-alc","object":"chat.completion.chunk","model":"gpt-9-preview","choices":[{"index":0,"delta":{"role":"assistant","content":""}}],"usage":null}
      """
    And the response body should contain template literal:
      """
      {"id":"chatcmpl-alc","object":"chat.completion.chunk","model":"gpt-9-preview","choices":[{"index":0,"delta":{"content":"Hi"}}],"usage":null}
      """
    And the response body should contain template literal:
      """
      {"id":"chatcmpl-alc","object":"chat.completion.chunk","model":"gpt-9-preview","choices":[{"index":0,"delta":{"content":" there"}}],"usage":null}
      """
    And the response body should contain template literal:
      """
      {"id":"chatcmpl-alc","object":"chat.completion.chunk","model":"gpt-9-preview","choices":[{"index":0,"delta":{},"finish_reason":"stop"}],"usage":null}
      """
    And the response body should contain template literal:
      """
      {"id":"chatcmpl-alc","object":"chat.completion.chunk","model":"gpt-9-preview","choices":[],"usage":{"prompt_tokens":1000,"completion_tokens":500,"total_tokens":1500}}
      """
    And the response body should contain "data: [DONE]"
    And the latest analytics event for path "${CTX:providerContext}/scripted/streamed/chat/completions" should have numeric metadata field "aiMetadata.llmCost" equal to "0"

    When I delete the LLM provider "${CTX:providerName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:providerContext}/scripted/ready" until status 404

  # The client gets the mock's status, headers and body exactly, with no cost header added.
  Scenario Outline: Inspect everything the policy returns to the kernel on both the buffered and streaming paths, for priced and unpriced requests (buffered, <case>)
    Given I generate a unique resource name from "alc-untouched-buffered-<slug>" and store it as "providerName"
    And I generate a unique value from "alc-untouched-buffered-<slug>" and store it as "providerDisplayName"
    And I generate a unique API version from "alc-untouched-buffered-<slug>" and store it as "providerVersion"
    And I generate a unique API context from "/alc-untouched-buffered-<slug>" and store it as "providerContext"
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
      {"model":"<deployment>","messages":[{"role":"user","content":"Hello"}],"x_testbench_reply":{"body":{"id":"chatcmpl-alc","object":"chat.completion","model":"<model>","choices":[{"index":0,"message":{"role":"assistant","content":"Hi there"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1000,"completion_tokens":500,"total_tokens":1500}}}}
      """
    Then the response status code should be 200
    And the response body should be:
      """
      {"id":"chatcmpl-alc","object":"chat.completion","model":"<model>","choices":[{"index":0,"message":{"role":"assistant","content":"Hi there"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1000,"completion_tokens":500,"total_tokens":1500}}
      """
    And the response header "X-Testbench-Scripted" should be "true"
    And the response header "x-llm-cost" should not exist
    And the response header "x-llm-cost-status" should not exist

    When I delete the LLM provider "${CTX:providerName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:providerContext}/scripted/ready" until status 404

    Examples:
      | case     | slug     | deployment          | model         |
      | priced   | priced   | chat-mini           | gpt-4o-mini   |
      | unpriced | unpriced | unlisted-deployment | gpt-9-preview |

  # Every event reaches the client as the mock sent it, with no cost header added.
  Scenario Outline: Inspect everything the policy returns to the kernel on both the buffered and streaming paths, for priced and unpriced requests (streamed, <case>)
    Given I generate a unique resource name from "alc-untouched-streamed-<slug>" and store it as "providerName"
    And I generate a unique value from "alc-untouched-streamed-<slug>" and store it as "providerDisplayName"
    And I generate a unique API version from "alc-untouched-streamed-<slug>" and store it as "providerVersion"
    And I generate a unique API context from "/alc-untouched-streamed-<slug>" and store it as "providerContext"
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
      {"model":"<deployment>","stream":true,"stream_options":{"include_usage":true},"messages":[{"role":"user","content":"Hello"}],"x_testbench_reply":{"events":[{"id":"chatcmpl-alc","object":"chat.completion.chunk","model":"<model>","choices":[{"index":0,"delta":{"role":"assistant","content":""}}],"usage":null},{"id":"chatcmpl-alc","object":"chat.completion.chunk","model":"<model>","choices":[{"index":0,"delta":{"content":"Hi"}}],"usage":null},{"id":"chatcmpl-alc","object":"chat.completion.chunk","model":"<model>","choices":[{"index":0,"delta":{"content":" there"}}],"usage":null},{"id":"chatcmpl-alc","object":"chat.completion.chunk","model":"<model>","choices":[{"index":0,"delta":{},"finish_reason":"stop"}],"usage":null},{"id":"chatcmpl-alc","object":"chat.completion.chunk","model":"<model>","choices":[],"usage":{"prompt_tokens":1000,"completion_tokens":500,"total_tokens":1500}},"data: [DONE]"]}}
      """
    Then the response status code should be 200
    And the response header "Content-Type" should contain "text/event-stream"
    And the response header "X-Testbench-Scripted" should be "true"
    And the response header "x-llm-cost" should not exist
    And the response body should contain template literal:
      """
      {"id":"chatcmpl-alc","object":"chat.completion.chunk","model":"<model>","choices":[{"index":0,"delta":{"role":"assistant","content":""}}],"usage":null}
      """
    And the response body should contain template literal:
      """
      {"id":"chatcmpl-alc","object":"chat.completion.chunk","model":"<model>","choices":[{"index":0,"delta":{"content":"Hi"}}],"usage":null}
      """
    And the response body should contain template literal:
      """
      {"id":"chatcmpl-alc","object":"chat.completion.chunk","model":"<model>","choices":[{"index":0,"delta":{"content":" there"}}],"usage":null}
      """
    And the response body should contain template literal:
      """
      {"id":"chatcmpl-alc","object":"chat.completion.chunk","model":"<model>","choices":[{"index":0,"delta":{},"finish_reason":"stop"}],"usage":null}
      """
    And the response body should contain template literal:
      """
      {"id":"chatcmpl-alc","object":"chat.completion.chunk","model":"<model>","choices":[],"usage":{"prompt_tokens":1000,"completion_tokens":500,"total_tokens":1500}}
      """
    And the response body should contain "data: [DONE]"
    And the response header "x-llm-cost-status" should not exist

    When I delete the LLM provider "${CTX:providerName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:providerContext}/scripted/ready" until status 404

    Examples:
      | case     | slug     | deployment          | model         |
      | priced   | priced   | chat-mini           | gpt-4o-mini   |
      | unpriced | unpriced | unlisted-deployment | gpt-9-preview |

  # Whatever the upstream sends, the client gets it unchanged and the published cost is a finite,
  # non-negative number.
  Scenario Outline: Send hostile or malformed response bodies: deeply nested JSON, duplicate keys, token counts at the int64 limit, and negative token counts (<case>)
    Given I generate a unique resource name from "alc-hostile-<slug>" and store it as "providerName"
    And I generate a unique value from "alc-hostile-<slug>" and store it as "providerDisplayName"
    And I generate a unique API version from "alc-hostile-<slug>" and store it as "providerVersion"
    And I generate a unique API context from "/alc-hostile-<slug>" and store it as "providerContext"
    When I create LLM provider from "resources/templates/llm-provider.yaml" with values:
      | apiVersion         | ${CTX:gatewaySpecVersion}  |
      | name               | ${CTX:providerName}        |
      | displayName        | ${CTX:providerDisplayName} |
      | version            | ${CTX:providerVersion}     |
      | template           | azure-openai               |
      | spec.context       | ${CTX:providerContext}     |
      | spec.upstream.url  | http://testbench:3008      |
      | accessControl.mode | allow_all                  |
      | spec.policies      | [{"name":"azure-llm-cost","version":"v1","paths":[{"path":"/*","methods":["*"],"params":{"modelMappings":[{"deployment":"chat-mini","model":"gpt-4o-mini"},{"deployment":"chat-search","model":"gpt-4o-search-preview"}]}}]}] |
    Then the response status code should be 201

    # A scripted reply with no model goes unpriced, so polling it until the route is live leaves the
    # requests below the only priced ones on their paths.
    When I send a "POST" request to "${CTX:providerContext}/scripted/ready" until status 200 with body:
      """
      {"x_testbench_reply":{"body":{}}}
      """

    When I send a "POST" request to "${CTX:providerContext}/scripted/openai/v1/chat/completions" with body:
      """
      {"model":"chat-mini","messages":[{"role":"user","content":"Hello"}],"x_testbench_reply":{"body":<reply>}}
      """
    Then the response status code should be 200
    And the response body should be:
      """
      <reply>
      """
    And the response header "X-Testbench-Scripted" should be "true"
    And the response header "x-llm-cost" should not exist
    And the latest analytics event for path "${CTX:providerContext}/scripted/openai/v1/chat/completions" should have numeric metadata field "aiMetadata.llmCost" at least "0"

    When I delete the LLM provider "${CTX:providerName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:providerContext}/scripted/ready" until status 404

    Examples:
      | case                            | slug       | reply                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
      | deeply nested JSON              | nested     | {"model":"gpt-4o-mini","usage":{"prompt_tokens":1000,"completion_tokens":500},"extra":[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]} |
      | duplicate keys                  | duplicates | {"model":"gpt-4o","model":"gpt-4o-mini","usage":{"prompt_tokens":1,"prompt_tokens":1000,"completion_tokens":500}}                                                                                                                                                                                                                                                                                                                                                                                       |
      | token counts at the int64 limit | int64      | {"model":"gpt-4o-mini","usage":{"prompt_tokens":9223372036854775807,"completion_tokens":9223372036854775807}}                                                                                                                                                                                                                                                                                                                                                                                           |

  # Negative counts must not produce a negative cost: the client still gets the body unchanged, and
  # the published cost stays at or above zero.
  @known-issue
  Scenario Outline: Send hostile or malformed response bodies: deeply nested JSON, duplicate keys, token counts at the int64 limit, and negative token counts (<case>)
    Given I generate a unique resource name from "alc-hostile-<slug>" and store it as "providerName"
    And I generate a unique value from "alc-hostile-<slug>" and store it as "providerDisplayName"
    And I generate a unique API version from "alc-hostile-<slug>" and store it as "providerVersion"
    And I generate a unique API context from "/alc-hostile-<slug>" and store it as "providerContext"
    When I create LLM provider from "resources/templates/llm-provider.yaml" with values:
      | apiVersion         | ${CTX:gatewaySpecVersion}  |
      | name               | ${CTX:providerName}        |
      | displayName        | ${CTX:providerDisplayName} |
      | version            | ${CTX:providerVersion}     |
      | template           | azure-openai               |
      | spec.context       | ${CTX:providerContext}     |
      | spec.upstream.url  | http://testbench:3008      |
      | accessControl.mode | allow_all                  |
      | spec.policies      | [{"name":"azure-llm-cost","version":"v1","paths":[{"path":"/*","methods":["*"],"params":{"modelMappings":[{"deployment":"chat-mini","model":"gpt-4o-mini"},{"deployment":"chat-search","model":"gpt-4o-search-preview"}]}}]}] |
    Then the response status code should be 201

    # A scripted reply with no model goes unpriced, so polling it until the route is live leaves the
    # requests below the only priced ones on their paths.
    When I send a "POST" request to "${CTX:providerContext}/scripted/ready" until status 200 with body:
      """
      {"x_testbench_reply":{"body":{}}}
      """

    When I send a "POST" request to "${CTX:providerContext}/scripted/openai/v1/chat/completions" with body:
      """
      {"model":"chat-mini","messages":[{"role":"user","content":"Hello"}],"x_testbench_reply":{"body":<reply>}}
      """
    Then the response status code should be 200
    And the response body should be:
      """
      <reply>
      """
    And the response header "X-Testbench-Scripted" should be "true"
    And the response header "x-llm-cost" should not exist
    # The policy floors the text tokens at zero but bills the negative cached-token or web-search
    # count at its rate, so it wrongly publishes a negative cost (-0.0002 and -0.143).
    And the latest analytics event for path "${CTX:providerContext}/scripted/openai/v1/chat/completions" should have numeric metadata field "aiMetadata.llmCost" at least "0"

    When I delete the LLM provider "${CTX:providerName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:providerContext}/scripted/ready" until status 404

    Examples:
      | case                      | slug            | reply                                                                                                                                 |
      | negative token counts     | negative        | {"model":"gpt-4o-mini","usage":{"prompt_tokens":-1000,"completion_tokens":-500,"prompt_tokens_details":{"cached_tokens":-400}}}       |
      | negative web-search count | negative-search | {"model":"gpt-4o-search-preview","usage":{"prompt_tokens":1000,"completion_tokens":500,"server_tool_use":{"web_search_requests":-5}}} |

  # A published token count must not be negative either. The policy adds the two counts with no
  # overflow check, so two int64-limit counts wrongly publish a total of -2.
  @known-issue
  Scenario: Send hostile or malformed response bodies: deeply nested JSON, duplicate keys, token counts at the int64 limit, and negative token counts (token total at the int64 limit)
    Given I generate a unique resource name from "alc-hostile-int64-total" and store it as "providerName"
    And I generate a unique value from "alc-hostile-int64-total" and store it as "providerDisplayName"
    And I generate a unique API version from "alc-hostile-int64-total" and store it as "providerVersion"
    And I generate a unique API context from "/alc-hostile-int64-total" and store it as "providerContext"
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
      {"model":"chat-mini","messages":[{"role":"user","content":"Hello"}],"x_testbench_reply":{"body":{"model":"gpt-4o-mini","usage":{"prompt_tokens":9223372036854775807,"completion_tokens":9223372036854775807}}}}
      """
    Then the response status code should be 200
    And the response body should be:
      """
      {"model":"gpt-4o-mini","usage":{"prompt_tokens":9223372036854775807,"completion_tokens":9223372036854775807}}
      """
    And the latest analytics event for path "${CTX:providerContext}/scripted/openai/v1/chat/completions" should have numeric metadata field "aiMetadata.llmCost" at least "0"
    And the latest analytics event for path "${CTX:providerContext}/scripted/openai/v1/chat/completions" should have numeric metadata field "aiTokenUsage.totalTokens" at least "0"

    When I delete the LLM provider "${CTX:providerName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:providerContext}/scripted/ready" until status 404

  # The buffered forms of these failures are covered above (rows on non-Azure templates, unknown
  # models, non-token entries and missing usage); malformed and empty streams are covered by the
  # unparseable-events and no-chunks scenarios. Here each failure arrives as a stream, and the
  # client still gets every event unchanged.
  Scenario Outline: Exercise every failure path the policy has - no template, unknown model, unpriced entry, absent usage, malformed body, empty body and a failed merge - on both response phases (streamed, <case>)
    Given I generate a unique resource name from "alc-failure-<slug>" and store it as "providerName"
    And I generate a unique value from "alc-failure-<slug>" and store it as "providerDisplayName"
    And I generate a unique API version from "alc-failure-<slug>" and store it as "providerVersion"
    And I generate a unique API context from "/alc-failure-<slug>" and store it as "providerContext"
    When I create LLM provider from "resources/templates/llm-provider.yaml" with values:
      | apiVersion         | ${CTX:gatewaySpecVersion}  |
      | name               | ${CTX:providerName}        |
      | displayName        | ${CTX:providerDisplayName} |
      | version            | ${CTX:providerVersion}     |
      | template           | <template>                 |
      | spec.context       | ${CTX:providerContext}     |
      | spec.upstream.url  | http://testbench:3008      |
      | accessControl.mode | allow_all                  |
      | spec.policies      | [{"name":"azure-llm-cost","version":"v1","paths":[{"path":"/*","methods":["*"],"params":{"modelMappings":[{"deployment":"chat-mini","model":"gpt-4o-mini"},{"deployment":"my-dalle","model":"hd/1024-x-1024/dall-e-3"}]}}]}] |
    Then the response status code should be 201

    # A scripted reply with no model goes unpriced, so polling it until the route is live leaves the
    # requests below the only priced ones on their paths.
    When I send a "POST" request to "${CTX:providerContext}/scripted/ready" until status 200 with body:
      """
      {"x_testbench_reply":{"body":{}}}
      """

    When I send a "POST" request to "${CTX:providerContext}/scripted/openai/v1/chat/completions" with body:
      """
      {"model":"<deployment>","stream":true,"messages":[{"role":"user","content":"Hello"}],"x_testbench_reply":{"events":[{"id":"chatcmpl-alc","object":"chat.completion.chunk","model":"<model>","choices":[{"index":0,"delta":{"role":"assistant","content":"Hi"}}],"usage":null},{"id":"chatcmpl-alc","object":"chat.completion.chunk","model":"<model>","choices":[],"usage":<usage>},"data: [DONE]"]}}
      """
    Then the response status code should be 200
    And the response header "Content-Type" should contain "text/event-stream"
    And the response header "X-Testbench-Scripted" should be "true"
    And the response header "x-llm-cost" should not exist
    And the response body should contain template literal:
      """
      {"id":"chatcmpl-alc","object":"chat.completion.chunk","model":"<model>","choices":[{"index":0,"delta":{"role":"assistant","content":"Hi"}}],"usage":null}
      """
    And the response body should contain template literal:
      """
      {"id":"chatcmpl-alc","object":"chat.completion.chunk","model":"<model>","choices":[],"usage":<usage>}
      """
    And the latest analytics event for path "${CTX:providerContext}/scripted/openai/v1/chat/completions" should have numeric metadata field "aiMetadata.llmCost" equal to "0"

    When I delete the LLM provider "${CTX:providerName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:providerContext}/scripted/ready" until status 404

    Examples:
      | case                    | slug        | template     | deployment          | model                   | usage                                          |
      | no Azure template       | no-template | openai       | chat-mini           | gpt-4o-mini             | {"prompt_tokens":1000,"completion_tokens":500} |
      | unknown model           | unknown     | azure-openai | unlisted-deployment | gpt-9-preview           | {"prompt_tokens":1000,"completion_tokens":500} |
      | non-token pricing entry | non-token   | azure-openai | my-dalle            | hd/1024-x-1024/dall-e-3 | {"prompt_tokens":10,"completion_tokens":0}     |
      | absent usage            | no-usage    | azure-openai | chat-mini           | gpt-4o-mini             | null                                           |

  # The gateway logs at debug level, where the policy records each cost it calculates. The prompt and
  # the completion each carry a marker no other scenario uses, and neither may reach the log.
  Scenario: Price a request whose prompt and completion carry sensitive content, capturing every log line the policy emits at debug level
    Given I generate a unique resource name from "alc-logs" and store it as "providerName"
    And I generate a unique value from "alc-logs" and store it as "providerDisplayName"
    And I generate a unique API version from "alc-logs" and store it as "providerVersion"
    And I generate a unique API context from "/alc-logs" and store it as "providerContext"
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
      {"model":"chat-mini","messages":[{"role":"user","content":"ALC-PROMPT-MARKER-7F3A"}],"x_testbench_reply":{"body":{"model":"gpt-4o-mini","choices":[{"index":0,"message":{"role":"assistant","content":"ALC-COMPLETION-MARKER-9B2C"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1000,"completion_tokens":500,"total_tokens":1500}}}}
      """
    Then the response status code should be 200
    And the response body should be:
      """
      {"model":"gpt-4o-mini","choices":[{"index":0,"message":{"role":"assistant","content":"ALC-COMPLETION-MARKER-9B2C"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1000,"completion_tokens":500,"total_tokens":1500}}
      """
    And the response header "X-Testbench-Scripted" should be "true"
    And the response header "x-llm-cost" should not exist
    And the latest analytics event for path "${CTX:providerContext}/scripted/openai/v1/chat/completions" should have numeric metadata field "aiMetadata.llmCost" equal to "0.003"
    And the "gateway-runtime" service logs should contain "azure-llm-cost: calculated cost"
    And the "gateway-runtime" service logs should not contain "ALC-PROMPT-MARKER-7F3A"
    And the "gateway-runtime" service logs should not contain "ALC-COMPLETION-MARKER-9B2C"

    When I delete the LLM provider "${CTX:providerName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:providerContext}/scripted/ready" until status 404
