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
Feature: Azure LLM Cost policy usage and rates
  As an API developer
  I want every usage shape an Azure endpoint reports priced at the right rates
  So that cached, reasoning, audio, priority and long-context tokens are neither missed nor billed twice

  # Costs follow from the test rates in overlays/pricing/model_prices.json.

  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"

  # 400 of the 1000 prompt tokens are cached and already counted in prompt_tokens:
  # 600 x 0.000001 + 400 cached x 0.0000005 + 500 x 0.000004 = 0.0028. The input total stays 1000.
  Scenario: Parse an Azure OpenAI chat completions usage object using prompt_tokens/completion_tokens with prompt_tokens_details
    Given I generate a unique resource name from "alc-chat-usage" and store it as "providerName"
    And I generate a unique value from "alc-chat-usage" and store it as "providerDisplayName"
    And I generate a unique API version from "alc-chat-usage" and store it as "providerVersion"
    And I generate a unique API context from "/alc-chat-usage" and store it as "providerContext"
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
      {"model":"chat-mini","messages":[{"role":"user","content":"Hello"}],"x_testbench_reply":{"body":{"id":"chatcmpl-alc","object":"chat.completion","model":"gpt-4o-mini","choices":[{"index":0,"message":{"role":"assistant","content":"Hi there"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1000,"completion_tokens":500,"total_tokens":1500,"prompt_tokens_details":{"cached_tokens":400}}}}}
      """
    Then the response status code should be 200
    And the response body should be:
      """
      {"id":"chatcmpl-alc","object":"chat.completion","model":"gpt-4o-mini","choices":[{"index":0,"message":{"role":"assistant","content":"Hi there"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1000,"completion_tokens":500,"total_tokens":1500,"prompt_tokens_details":{"cached_tokens":400}}}
      """
    And the response header "X-Testbench-Scripted" should be "true"
    And the response header "x-llm-cost" should not exist
    And the latest analytics event for path "${CTX:providerContext}/scripted/openai/v1/chat/completions" should have numeric metadata field "aiMetadata.llmCost" equal to "0.0028"
    And the latest analytics event for path "${CTX:providerContext}/scripted/openai/v1/chat/completions" should have numeric metadata field "aiTokenUsage.promptTokens" equal to "1000"
    And the latest analytics event for path "${CTX:providerContext}/scripted/openai/v1/chat/completions" should have numeric metadata field "aiTokenUsage.completionTokens" equal to "500"
    And the latest analytics event for path "${CTX:providerContext}/scripted/openai/v1/chat/completions" should have numeric metadata field "aiTokenUsage.totalTokens" equal to "1500"

    When I delete the LLM provider "${CTX:providerName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:providerContext}/scripted/ready" until status 404

  # The Responses API echoes the deployment, which maps to gpt-5.4. gpt-5.4 bills reasoning at its own
  # rate: 800 x 0.000001 + 200 cached x 0.0000001 + 400 x 0.00001 + 100 reasoning x 0.00002 = 0.00682
  # (0.00582 if reasoning were plain output)
  Scenario: Parse a Responses API usage object using input_tokens/output_tokens with input_tokens_details and output_tokens_details
    Given I generate a unique resource name from "alc-responses-usage" and store it as "providerName"
    And I generate a unique value from "alc-responses-usage" and store it as "providerDisplayName"
    And I generate a unique API version from "alc-responses-usage" and store it as "providerVersion"
    And I generate a unique API context from "/alc-responses-usage" and store it as "providerContext"
    When I create LLM provider from "resources/templates/llm-provider.yaml" with values:
      | apiVersion         | ${CTX:gatewaySpecVersion}  |
      | name               | ${CTX:providerName}        |
      | displayName        | ${CTX:providerDisplayName} |
      | version            | ${CTX:providerVersion}     |
      | template           | azure-openai               |
      | spec.context       | ${CTX:providerContext}     |
      | spec.upstream.url  | http://testbench:3008      |
      | accessControl.mode | allow_all                  |
      | spec.policies      | [{"name":"azure-llm-cost","version":"v1","paths":[{"path":"/*","methods":["*"],"params":{"modelMappings":[{"deployment":"resp-54","model":"gpt-5.4"}]}}]}] |
    Then the response status code should be 201

    # A scripted reply with no model goes unpriced, so polling it until the route is live leaves the
    # requests below the only priced ones on their paths.
    When I send a "POST" request to "${CTX:providerContext}/scripted/ready" until status 200 with body:
      """
      {"x_testbench_reply":{"body":{}}}
      """

    When I send a "POST" request to "${CTX:providerContext}/scripted/openai/v1/responses" with body:
      """
      {"model":"resp-54","input":"Hello","x_testbench_reply":{"body":{"id":"resp_alc","object":"response","model":"resp-54","output":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":"Hi there"}]}],"usage":{"input_tokens":1000,"input_tokens_details":{"cached_tokens":200},"output_tokens":500,"output_tokens_details":{"reasoning_tokens":100},"total_tokens":1500}}}}
      """
    Then the response status code should be 200
    And the response body should be:
      """
      {"id":"resp_alc","object":"response","model":"resp-54","output":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":"Hi there"}]}],"usage":{"input_tokens":1000,"input_tokens_details":{"cached_tokens":200},"output_tokens":500,"output_tokens_details":{"reasoning_tokens":100},"total_tokens":1500}}
      """
    And the response header "X-Testbench-Scripted" should be "true"
    And the response header "x-llm-cost" should not exist
    And the latest analytics event for path "${CTX:providerContext}/scripted/openai/v1/responses" should have numeric metadata field "aiMetadata.llmCost" equal to "0.00682"
    And the latest analytics event for path "${CTX:providerContext}/scripted/openai/v1/responses" should have numeric metadata field "aiTokenUsage.promptTokens" equal to "1000"
    And the latest analytics event for path "${CTX:providerContext}/scripted/openai/v1/responses" should have numeric metadata field "aiTokenUsage.completionTokens" equal to "500"
    And the latest analytics event for path "${CTX:providerContext}/scripted/openai/v1/responses" should have numeric metadata field "aiTokenUsage.totalTokens" equal to "1500"

    When I delete the LLM provider "${CTX:providerName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:providerContext}/scripted/ready" until status 404

  # Anthropic-style usage reports cache reads and writes beside input_tokens, so they add to the input
  # total. claude-opus-4-5 on azure_ai/: input 0.000005, output 0.000025, cache read 0.0000005, 5-minute
  # write 0.00000625, 1-hour write 0.00001, web search 0.01 per query.
  # cache read: 100 x 0.000005 + 400 x 0.0000005 + 50 x 0.000025 = 0.00195 (input total 500)
  # TTL breakdown: 100 x 0.000005 + 200 x 0.00000625 + 300 x 0.00001 + 50 x 0.000025 = 0.006 (input 600)
  # flat cache creation, no breakdown: 100 x 0.000005 + 400 x 0.00000625 + 50 x 0.000025 = 0.00425
  # server tool use: 100 x 0.000005 + 50 x 0.000025 + 2 x 0.01 = 0.02175
  Scenario Outline: Parse an Anthropic-style usage object served through Foundry, with cache_read_input_tokens, a cache_creation TTL breakdown, and server tool use (<case>)
    Given I generate a unique resource name from "alc-anthropic-<slug>" and store it as "providerName"
    And I generate a unique value from "alc-anthropic-<slug>" and store it as "providerDisplayName"
    And I generate a unique API version from "alc-anthropic-<slug>" and store it as "providerVersion"
    And I generate a unique API context from "/alc-anthropic-<slug>" and store it as "providerContext"
    When I create LLM provider from "resources/templates/llm-provider.yaml" with values:
      | apiVersion         | ${CTX:gatewaySpecVersion}  |
      | name               | ${CTX:providerName}        |
      | displayName        | ${CTX:providerDisplayName} |
      | version            | ${CTX:providerVersion}     |
      | template           | azureai-foundry            |
      | spec.context       | ${CTX:providerContext}     |
      | spec.upstream.url  | http://testbench:3008      |
      | accessControl.mode | allow_all                  |
      | spec.policies      | [{"name":"azure-llm-cost","version":"v1","paths":[{"path":"/*","methods":["*"],"params":{"modelMappings":[{"deployment":"my-claude","model":"claude-opus-4-5"}]}}]}] |
    Then the response status code should be 201

    # A scripted reply with no model goes unpriced, so polling it until the route is live leaves the
    # requests below the only priced ones on their paths.
    When I send a "POST" request to "${CTX:providerContext}/scripted/ready" until status 200 with body:
      """
      {"x_testbench_reply":{"body":{}}}
      """

    When I send a "POST" request to "${CTX:providerContext}/scripted/anthropic/v1/messages" with body:
      """
      {"model":"my-claude","max_tokens":100,"messages":[{"role":"user","content":"Hello"}],"x_testbench_reply":{"body":<usage>}}
      """
    Then the response status code should be 200
    And the response body should be:
      """
      <usage>
      """
    And the response header "X-Testbench-Scripted" should be "true"
    And the response header "x-llm-cost" should not exist
    And the latest analytics event for path "${CTX:providerContext}/scripted/anthropic/v1/messages" should have numeric metadata field "aiMetadata.llmCost" equal to "<cost>"
    And the latest analytics event for path "${CTX:providerContext}/scripted/anthropic/v1/messages" should have numeric metadata field "aiTokenUsage.promptTokens" equal to "<input>"
    And the latest analytics event for path "${CTX:providerContext}/scripted/anthropic/v1/messages" should have numeric metadata field "aiTokenUsage.completionTokens" equal to "50"

    When I delete the LLM provider "${CTX:providerName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:providerContext}/scripted/ready" until status 404

    Examples:
      | case                         | slug       | usage                                                                                                                                                                                                                                                                                             | cost    | input |
      | cache read                   | cache-read | {"id":"msg_alc","type":"message","role":"assistant","model":"claude-opus-4-5","content":[{"type":"text","text":"Hi there"}],"usage":{"input_tokens":100,"cache_read_input_tokens":400,"output_tokens":50}}                                                                                        | 0.00195 | 500   |
      | cache creation TTL breakdown | ttl        | {"id":"msg_alc","type":"message","role":"assistant","model":"claude-opus-4-5","content":[{"type":"text","text":"Hi there"}],"usage":{"input_tokens":100,"cache_creation_input_tokens":500,"cache_creation":{"ephemeral_5m_input_tokens":200,"ephemeral_1h_input_tokens":300},"output_tokens":50}} | 0.006   | 600   |
      | flat cache creation          | flat       | {"id":"msg_alc","type":"message","role":"assistant","model":"claude-opus-4-5","content":[{"type":"text","text":"Hi there"}],"usage":{"input_tokens":100,"cache_creation_input_tokens":400,"output_tokens":50}}                                                                                    | 0.00425 | 500   |
      | server tool use              | web-search | {"id":"msg_alc","type":"message","role":"assistant","model":"claude-opus-4-5","content":[{"type":"text","text":"Hi there"}],"usage":{"input_tokens":100,"output_tokens":50,"server_tool_use":{"web_search_requests":2}}}                                                                          | 0.02175 | 100   |

  # The Responses API stream carries the model and the usage inside the response object of its
  # completed event. gpt-5.4: 1000 x 0.000001 + 500 x 0.00001 = 0.006
  Scenario: Parse a Responses API stream envelope that nests usage under a response object, and a payload carrying usage in both positions (nested usage)
    Given I generate a unique resource name from "alc-responses-stream" and store it as "providerName"
    And I generate a unique value from "alc-responses-stream" and store it as "providerDisplayName"
    And I generate a unique API version from "alc-responses-stream" and store it as "providerVersion"
    And I generate a unique API context from "/alc-responses-stream" and store it as "providerContext"
    When I create LLM provider from "resources/templates/llm-provider.yaml" with values:
      | apiVersion         | ${CTX:gatewaySpecVersion}  |
      | name               | ${CTX:providerName}        |
      | displayName        | ${CTX:providerDisplayName} |
      | version            | ${CTX:providerVersion}     |
      | template           | azure-openai               |
      | spec.context       | ${CTX:providerContext}     |
      | spec.upstream.url  | http://testbench:3008      |
      | accessControl.mode | allow_all                  |
      | spec.policies      | [{"name":"azure-llm-cost","version":"v1","paths":[{"path":"/*","methods":["*"],"params":{"modelMappings":[{"deployment":"resp-54","model":"gpt-5.4"}]}}]}] |
    Then the response status code should be 201

    # A scripted reply with no model goes unpriced, so polling it until the route is live leaves the
    # requests below the only priced ones on their paths.
    When I send a "POST" request to "${CTX:providerContext}/scripted/ready" until status 200 with body:
      """
      {"x_testbench_reply":{"body":{}}}
      """

    When I send a "POST" request to "${CTX:providerContext}/scripted/openai/v1/responses" with body:
      """
      {"model":"resp-54","input":"Hello","stream":true,"x_testbench_reply":{"events":[{"type":"response.created","response":{"id":"resp_alc","model":"resp-54","status":"in_progress","usage":null}},{"type":"response.output_text.delta","delta":"Hi there"},{"type":"response.completed","response":{"id":"resp_alc","model":"resp-54","status":"completed","usage":{"input_tokens":1000,"output_tokens":500,"total_tokens":1500}}}]}}
      """
    Then the response status code should be 200
    And the response header "Content-Type" should contain "text/event-stream"
    And the response header "X-Testbench-Scripted" should be "true"
    And the response header "x-llm-cost" should not exist
    And the response body should contain template literal:
      """
      {"type":"response.created","response":{"id":"resp_alc","model":"resp-54","status":"in_progress","usage":null}}
      """
    And the response body should contain template literal:
      """
      {"type":"response.output_text.delta","delta":"Hi there"}
      """
    And the response body should contain template literal:
      """
      {"type":"response.completed","response":{"id":"resp_alc","model":"resp-54","status":"completed","usage":{"input_tokens":1000,"output_tokens":500,"total_tokens":1500}}}
      """
    And the latest analytics event for path "${CTX:providerContext}/scripted/openai/v1/responses" should have numeric metadata field "aiMetadata.llmCost" equal to "0.006"
    And the latest analytics event for path "${CTX:providerContext}/scripted/openai/v1/responses" should have numeric metadata field "aiTokenUsage.promptTokens" equal to "1000"
    And the latest analytics event for path "${CTX:providerContext}/scripted/openai/v1/responses" should have numeric metadata field "aiTokenUsage.completionTokens" equal to "500"
    And the latest analytics event for path "${CTX:providerContext}/scripted/openai/v1/responses" should have numeric metadata field "aiTokenUsage.totalTokens" equal to "1500"

    When I delete the LLM provider "${CTX:providerName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:providerContext}/scripted/ready" until status 404

  # The top-level usage wins over the nested one: 1000 x 0.000001 + 500 x 0.00001 = 0.006 (the nested
  # usage would give 0.99).
  Scenario: Parse a Responses API stream envelope that nests usage under a response object, and a payload carrying usage in both positions (usage in both positions)
    Given I generate a unique resource name from "alc-responses-both" and store it as "providerName"
    And I generate a unique value from "alc-responses-both" and store it as "providerDisplayName"
    And I generate a unique API version from "alc-responses-both" and store it as "providerVersion"
    And I generate a unique API context from "/alc-responses-both" and store it as "providerContext"
    When I create LLM provider from "resources/templates/llm-provider.yaml" with values:
      | apiVersion         | ${CTX:gatewaySpecVersion}  |
      | name               | ${CTX:providerName}        |
      | displayName        | ${CTX:providerDisplayName} |
      | version            | ${CTX:providerVersion}     |
      | template           | azure-openai               |
      | spec.context       | ${CTX:providerContext}     |
      | spec.upstream.url  | http://testbench:3008      |
      | accessControl.mode | allow_all                  |
      | spec.policies      | [{"name":"azure-llm-cost","version":"v1","paths":[{"path":"/*","methods":["*"],"params":{"modelMappings":[{"deployment":"resp-54","model":"gpt-5.4"}]}}]}] |
    Then the response status code should be 201

    # A scripted reply with no model goes unpriced, so polling it until the route is live leaves the
    # requests below the only priced ones on their paths.
    When I send a "POST" request to "${CTX:providerContext}/scripted/ready" until status 200 with body:
      """
      {"x_testbench_reply":{"body":{}}}
      """

    When I send a "POST" request to "${CTX:providerContext}/scripted/openai/v1/responses" with body:
      """
      {"model":"resp-54","input":"Hello","x_testbench_reply":{"body":{"id":"resp_alc","model":"resp-54","usage":{"input_tokens":1000,"output_tokens":500,"total_tokens":1500},"response":{"model":"resp-54","usage":{"input_tokens":90000,"output_tokens":90000,"total_tokens":180000}}}}}
      """
    Then the response status code should be 200
    And the response body should be:
      """
      {"id":"resp_alc","model":"resp-54","usage":{"input_tokens":1000,"output_tokens":500,"total_tokens":1500},"response":{"model":"resp-54","usage":{"input_tokens":90000,"output_tokens":90000,"total_tokens":180000}}}
      """
    And the response header "X-Testbench-Scripted" should be "true"
    And the response header "x-llm-cost" should not exist
    And the latest analytics event for path "${CTX:providerContext}/scripted/openai/v1/responses" should have numeric metadata field "aiMetadata.llmCost" equal to "0.006"
    And the latest analytics event for path "${CTX:providerContext}/scripted/openai/v1/responses" should have numeric metadata field "aiTokenUsage.promptTokens" equal to "1000"
    And the latest analytics event for path "${CTX:providerContext}/scripted/openai/v1/responses" should have numeric metadata field "aiTokenUsage.completionTokens" equal to "500"
    And the latest analytics event for path "${CTX:providerContext}/scripted/openai/v1/responses" should have numeric metadata field "aiTokenUsage.totalTokens" equal to "1500"

    When I delete the LLM provider "${CTX:providerName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:providerContext}/scripted/ready" until status 404

  # The model resolves, but there is nothing to price, so the request is unpriced rather than free.
  # The analytics event shows cost 0 either way, so the policy's warning tells the two apart. Each
  # example maps to its own test pricing entry, so its warning is the only one naming that model.
  Scenario Outline: Send a response with no usage object, with a malformed body, and with a usage object reporting zero input and zero output tokens (<case>)
    Given I generate a unique resource name from "alc-no-usage-<slug>" and store it as "providerName"
    And I generate a unique value from "alc-no-usage-<slug>" and store it as "providerDisplayName"
    And I generate a unique API version from "alc-no-usage-<slug>" and store it as "providerVersion"
    And I generate a unique API context from "/alc-no-usage-<slug>" and store it as "providerContext"
    When I create LLM provider from "resources/templates/llm-provider.yaml" with values:
      | apiVersion         | ${CTX:gatewaySpecVersion}  |
      | name               | ${CTX:providerName}        |
      | displayName        | ${CTX:providerDisplayName} |
      | version            | ${CTX:providerVersion}     |
      | template           | azure-openai               |
      | spec.context       | ${CTX:providerContext}     |
      | spec.upstream.url  | http://testbench:3008      |
      | accessControl.mode | allow_all                  |
      | spec.policies      | [{"name":"azure-llm-cost","version":"v1","paths":[{"path":"/*","methods":["*"],"params":{"modelMappings":[{"deployment":"chat-mini","model":"<model>"}]}}]}] |
    Then the response status code should be 201

    # A scripted reply with no model goes unpriced, so polling it until the route is live leaves the
    # requests below the only priced ones on their paths.
    When I send a "POST" request to "${CTX:providerContext}/scripted/ready" until status 200 with body:
      """
      {"x_testbench_reply":{"body":{}}}
      """

    When I send a "POST" request to "${CTX:providerContext}/scripted/openai/v1/chat/completions" with body:
      """
      {"model":"chat-mini","messages":[{"role":"user","content":"Hello"}],"x_testbench_reply":<reply>}
      """
    Then the response status code should be 200
    And the response body should be:
      """
      <body>
      """
    And the response header "X-Testbench-Scripted" should be "true"
    And the response header "x-llm-cost" should not exist
    And the latest analytics event for path "${CTX:providerContext}/scripted/openai/v1/chat/completions" should have numeric metadata field "aiMetadata.llmCost" equal to "0"
    And the "gateway-runtime" service logs should have exactly 1 line containing:
      | <warning>           |
      | model=azure/<model> |

    When I delete the LLM provider "${CTX:providerName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:providerContext}/scripted/ready" until status 404

    Examples:
      | case            | slug      | model          | warning                                        | reply                                                                                 | body                                                                         |
      | no usage object | no-usage  | alc-no-usage   | response has no usage data, request not priced | {"body":{"model":"alc-no-usage"}}                                                     | {"model":"alc-no-usage"}                                                     |
      | malformed body  | malformed | alc-malformed  | failed to parse usage object                   | {"raw":"{\"model\":\"alc-malformed\",\"usage\":{"}                                    | {"model":"alc-malformed","usage":{                                           |
      | zero usage      | zero      | alc-zero-usage | response has no usage data, request not priced | {"body":{"model":"alc-zero-usage","usage":{"prompt_tokens":0,"completion_tokens":0}}} | {"model":"alc-zero-usage","usage":{"prompt_tokens":0,"completion_tokens":0}} |

  # The same volume twice, once with 800 of the 1000 input tokens cached:
  # cached: 200 x 0.000001 + 800 x 0.0000005 + 500 x 0.000004 = 0.0026; uncached: 0.003
  Scenario: Price a request whose input includes cached tokens, against an entry with a discounted cache-read rate
    Given I generate a unique resource name from "alc-cache-discount" and store it as "providerName"
    And I generate a unique value from "alc-cache-discount" and store it as "providerDisplayName"
    And I generate a unique API version from "alc-cache-discount" and store it as "providerVersion"
    And I generate a unique API context from "/alc-cache-discount" and store it as "providerContext"
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

    When I send a "POST" request to "${CTX:providerContext}/scripted/cached/chat/completions" with body:
      """
      {"model":"chat-mini","messages":[{"role":"user","content":"Hello"}],"x_testbench_reply":{"body":{"id":"chatcmpl-alc","object":"chat.completion","model":"gpt-4o-mini","choices":[{"index":0,"message":{"role":"assistant","content":"Hi there"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1000,"completion_tokens":500,"total_tokens":1500,"prompt_tokens_details":{"cached_tokens":800}}}}}
      """
    Then the response status code should be 200
    And the response body should be:
      """
      {"id":"chatcmpl-alc","object":"chat.completion","model":"gpt-4o-mini","choices":[{"index":0,"message":{"role":"assistant","content":"Hi there"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1000,"completion_tokens":500,"total_tokens":1500,"prompt_tokens_details":{"cached_tokens":800}}}
      """
    And the response header "X-Testbench-Scripted" should be "true"
    And the response header "x-llm-cost" should not exist
    And the latest analytics event for path "${CTX:providerContext}/scripted/cached/chat/completions" should have numeric metadata field "aiMetadata.llmCost" equal to "0.0026"
    And the latest analytics event for path "${CTX:providerContext}/scripted/cached/chat/completions" should have numeric metadata field "aiTokenUsage.promptTokens" equal to "1000"
    And the latest analytics event for path "${CTX:providerContext}/scripted/cached/chat/completions" should have numeric metadata field "aiTokenUsage.completionTokens" equal to "500"
    And the latest analytics event for path "${CTX:providerContext}/scripted/cached/chat/completions" should have numeric metadata field "aiTokenUsage.totalTokens" equal to "1500"

    When I send a "POST" request to "${CTX:providerContext}/scripted/uncached/chat/completions" with body:
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
    And the latest analytics event for path "${CTX:providerContext}/scripted/uncached/chat/completions" should have numeric metadata field "aiMetadata.llmCost" equal to "0.003"
    And the latest analytics event for path "${CTX:providerContext}/scripted/uncached/chat/completions" should have numeric metadata field "aiTokenUsage.promptTokens" equal to "1000"
    And the latest analytics event for path "${CTX:providerContext}/scripted/uncached/chat/completions" should have numeric metadata field "aiTokenUsage.completionTokens" equal to "500"
    And the latest analytics event for path "${CTX:providerContext}/scripted/uncached/chat/completions" should have numeric metadata field "aiTokenUsage.totalTokens" equal to "1500"

    When I delete the LLM provider "${CTX:providerName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:providerContext}/scripted/ready" until status 404

  # 280000 input tokens, 20000 of them cached: the uncached part alone (260000) is under 272k, but the
  # total is over, so the long-context rates apply to all of it:
  # 260000 x 0.000002 + 20000 x 0.0000002 + 1000 x 0.000015 = 0.539
  Scenario: Price a request whose total input exceeds the 272k long-context threshold, against an entry carrying above-272k rates
    Given I generate a unique resource name from "alc-long-context" and store it as "providerName"
    And I generate a unique value from "alc-long-context" and store it as "providerDisplayName"
    And I generate a unique API version from "alc-long-context" and store it as "providerVersion"
    And I generate a unique API context from "/alc-long-context" and store it as "providerContext"
    When I create LLM provider from "resources/templates/llm-provider.yaml" with values:
      | apiVersion         | ${CTX:gatewaySpecVersion}  |
      | name               | ${CTX:providerName}        |
      | displayName        | ${CTX:providerDisplayName} |
      | version            | ${CTX:providerVersion}     |
      | template           | azure-openai               |
      | spec.context       | ${CTX:providerContext}     |
      | spec.upstream.url  | http://testbench:3008      |
      | accessControl.mode | allow_all                  |
      | spec.policies      | [{"name":"azure-llm-cost","version":"v1","paths":[{"path":"/*","methods":["*"],"params":{"modelMappings":[{"deployment":"chat-54","model":"gpt-5.4"}]}}]}] |
    Then the response status code should be 201

    # A scripted reply with no model goes unpriced, so polling it until the route is live leaves the
    # requests below the only priced ones on their paths.
    When I send a "POST" request to "${CTX:providerContext}/scripted/ready" until status 200 with body:
      """
      {"x_testbench_reply":{"body":{}}}
      """

    When I send a "POST" request to "${CTX:providerContext}/scripted/openai/v1/chat/completions" with body:
      """
      {"model":"chat-54","messages":[{"role":"user","content":"Hello"}],"x_testbench_reply":{"body":{"id":"chatcmpl-alc","object":"chat.completion","model":"gpt-5.4","choices":[{"index":0,"message":{"role":"assistant","content":"Hi there"},"finish_reason":"stop"}],"usage":{"prompt_tokens":280000,"completion_tokens":1000,"total_tokens":281000,"prompt_tokens_details":{"cached_tokens":20000}}}}}
      """
    Then the response status code should be 200
    And the response body should be:
      """
      {"id":"chatcmpl-alc","object":"chat.completion","model":"gpt-5.4","choices":[{"index":0,"message":{"role":"assistant","content":"Hi there"},"finish_reason":"stop"}],"usage":{"prompt_tokens":280000,"completion_tokens":1000,"total_tokens":281000,"prompt_tokens_details":{"cached_tokens":20000}}}
      """
    And the response header "X-Testbench-Scripted" should be "true"
    And the response header "x-llm-cost" should not exist
    And the latest analytics event for path "${CTX:providerContext}/scripted/openai/v1/chat/completions" should have numeric metadata field "aiMetadata.llmCost" equal to "0.539"
    And the latest analytics event for path "${CTX:providerContext}/scripted/openai/v1/chat/completions" should have numeric metadata field "aiTokenUsage.promptTokens" equal to "280000"
    And the latest analytics event for path "${CTX:providerContext}/scripted/openai/v1/chat/completions" should have numeric metadata field "aiTokenUsage.completionTokens" equal to "1000"
    And the latest analytics event for path "${CTX:providerContext}/scripted/openai/v1/chat/completions" should have numeric metadata field "aiTokenUsage.totalTokens" equal to "281000"

    When I delete the LLM provider "${CTX:providerName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:providerContext}/scripted/ready" until status 404

  # gpt-5.4, 1000 input and 500 output tokens. Priority: 1000 x 0.000003 + 500 x 0.00002 = 0.013.
  # Base: 1000 x 0.000001 + 500 x 0.00001 = 0.006
  Scenario Outline: Send a response declaring the priority service tier, at the top level and nested inside the usage object (<case>)
    Given I generate a unique resource name from "alc-tier-<slug>" and store it as "providerName"
    And I generate a unique value from "alc-tier-<slug>" and store it as "providerDisplayName"
    And I generate a unique API version from "alc-tier-<slug>" and store it as "providerVersion"
    And I generate a unique API context from "/alc-tier-<slug>" and store it as "providerContext"
    When I create LLM provider from "resources/templates/llm-provider.yaml" with values:
      | apiVersion         | ${CTX:gatewaySpecVersion}  |
      | name               | ${CTX:providerName}        |
      | displayName        | ${CTX:providerDisplayName} |
      | version            | ${CTX:providerVersion}     |
      | template           | azure-openai               |
      | spec.context       | ${CTX:providerContext}     |
      | spec.upstream.url  | http://testbench:3008      |
      | accessControl.mode | allow_all                  |
      | spec.policies      | [{"name":"azure-llm-cost","version":"v1","paths":[{"path":"/*","methods":["*"],"params":{"modelMappings":[{"deployment":"chat-54","model":"gpt-5.4"}]}}]}] |
    Then the response status code should be 201

    # A scripted reply with no model goes unpriced, so polling it until the route is live leaves the
    # requests below the only priced ones on their paths.
    When I send a "POST" request to "${CTX:providerContext}/scripted/ready" until status 200 with body:
      """
      {"x_testbench_reply":{"body":{}}}
      """

    When I send a "POST" request to "${CTX:providerContext}/scripted/openai/v1/chat/completions" with body:
      """
      {"model":"chat-54","messages":[{"role":"user","content":"Hello"}],"x_testbench_reply":{"body":<reply>}}
      """
    Then the response status code should be 200
    And the response body should be:
      """
      <reply>
      """
    And the response header "X-Testbench-Scripted" should be "true"
    And the response header "x-llm-cost" should not exist
    And the latest analytics event for path "${CTX:providerContext}/scripted/openai/v1/chat/completions" should have numeric metadata field "aiMetadata.llmCost" equal to "<cost>"
    And the latest analytics event for path "${CTX:providerContext}/scripted/openai/v1/chat/completions" should have numeric metadata field "aiTokenUsage.promptTokens" equal to "1000"
    And the latest analytics event for path "${CTX:providerContext}/scripted/openai/v1/chat/completions" should have numeric metadata field "aiTokenUsage.completionTokens" equal to "500"
    And the latest analytics event for path "${CTX:providerContext}/scripted/openai/v1/chat/completions" should have numeric metadata field "aiTokenUsage.totalTokens" equal to "1500"

    When I delete the LLM provider "${CTX:providerName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:providerContext}/scripted/ready" until status 404

    Examples:
      | case                      | slug     | reply                                                                                                                                                                                                                                                                      | cost  |
      | priority at the top level | top      | {"id":"chatcmpl-alc","object":"chat.completion","model":"gpt-5.4","choices":[{"index":0,"message":{"role":"assistant","content":"Hi there"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1000,"completion_tokens":500,"total_tokens":1500},"service_tier":"priority"} | 0.013 |
      | priority inside usage     | usage    | {"id":"chatcmpl-alc","object":"chat.completion","model":"gpt-5.4","choices":[{"index":0,"message":{"role":"assistant","content":"Hi there"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1000,"completion_tokens":500,"total_tokens":1500,"service_tier":"priority"}} | 0.013 |
      | default tier              | default  | {"id":"chatcmpl-alc","object":"chat.completion","model":"gpt-5.4","choices":[{"index":0,"message":{"role":"assistant","content":"Hi there"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1000,"completion_tokens":500,"total_tokens":1500},"service_tier":"default"}  | 0.006 |
      | standard tier             | standard | {"id":"chatcmpl-alc","object":"chat.completion","model":"gpt-5.4","choices":[{"index":0,"message":{"role":"assistant","content":"Hi there"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1000,"completion_tokens":500,"total_tokens":1500},"service_tier":"standard"} | 0.006 |

  # Priority and above 272k at once: the combined rates win. 300000 x 0.000006 + 1000 x 0.00004 = 1.84
  Scenario: Price a priority request that also exceeds 272k input tokens, and an entry that carries only some of the tier override fields (priority above 272k)
    Given I generate a unique resource name from "alc-priority-long" and store it as "providerName"
    And I generate a unique value from "alc-priority-long" and store it as "providerDisplayName"
    And I generate a unique API version from "alc-priority-long" and store it as "providerVersion"
    And I generate a unique API context from "/alc-priority-long" and store it as "providerContext"
    When I create LLM provider from "resources/templates/llm-provider.yaml" with values:
      | apiVersion         | ${CTX:gatewaySpecVersion}  |
      | name               | ${CTX:providerName}        |
      | displayName        | ${CTX:providerDisplayName} |
      | version            | ${CTX:providerVersion}     |
      | template           | azure-openai               |
      | spec.context       | ${CTX:providerContext}     |
      | spec.upstream.url  | http://testbench:3008      |
      | accessControl.mode | allow_all                  |
      | spec.policies      | [{"name":"azure-llm-cost","version":"v1","paths":[{"path":"/*","methods":["*"],"params":{"modelMappings":[{"deployment":"chat-54","model":"gpt-5.4"}]}}]}] |
    Then the response status code should be 201

    # A scripted reply with no model goes unpriced, so polling it until the route is live leaves the
    # requests below the only priced ones on their paths.
    When I send a "POST" request to "${CTX:providerContext}/scripted/ready" until status 200 with body:
      """
      {"x_testbench_reply":{"body":{}}}
      """

    When I send a "POST" request to "${CTX:providerContext}/scripted/openai/v1/chat/completions" with body:
      """
      {"model":"chat-54","messages":[{"role":"user","content":"Hello"}],"x_testbench_reply":{"body":{"id":"chatcmpl-alc","object":"chat.completion","model":"gpt-5.4","choices":[{"index":0,"message":{"role":"assistant","content":"Hi there"},"finish_reason":"stop"}],"usage":{"prompt_tokens":300000,"completion_tokens":1000,"total_tokens":301000},"service_tier":"priority"}}}
      """
    Then the response status code should be 200
    And the response body should be:
      """
      {"id":"chatcmpl-alc","object":"chat.completion","model":"gpt-5.4","choices":[{"index":0,"message":{"role":"assistant","content":"Hi there"},"finish_reason":"stop"}],"usage":{"prompt_tokens":300000,"completion_tokens":1000,"total_tokens":301000},"service_tier":"priority"}
      """
    And the response header "X-Testbench-Scripted" should be "true"
    And the response header "x-llm-cost" should not exist
    And the latest analytics event for path "${CTX:providerContext}/scripted/openai/v1/chat/completions" should have numeric metadata field "aiMetadata.llmCost" equal to "1.84"
    And the latest analytics event for path "${CTX:providerContext}/scripted/openai/v1/chat/completions" should have numeric metadata field "aiTokenUsage.promptTokens" equal to "300000"
    And the latest analytics event for path "${CTX:providerContext}/scripted/openai/v1/chat/completions" should have numeric metadata field "aiTokenUsage.completionTokens" equal to "1000"
    And the latest analytics event for path "${CTX:providerContext}/scripted/openai/v1/chat/completions" should have numeric metadata field "aiTokenUsage.totalTokens" equal to "301000"

    When I delete the LLM provider "${CTX:providerName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:providerContext}/scripted/ready" until status 404

  # gpt-5.4-mini has a priority input rate only, so output stays at the base rate:
  # 1000 x 0.000003 + 500 x 0.00001 = 0.008
  Scenario: Price a priority request that also exceeds 272k input tokens, and an entry that carries only some of the tier override fields (partial overrides)
    Given I generate a unique resource name from "alc-priority-partial" and store it as "providerName"
    And I generate a unique value from "alc-priority-partial" and store it as "providerDisplayName"
    And I generate a unique API version from "alc-priority-partial" and store it as "providerVersion"
    And I generate a unique API context from "/alc-priority-partial" and store it as "providerContext"
    When I create LLM provider from "resources/templates/llm-provider.yaml" with values:
      | apiVersion         | ${CTX:gatewaySpecVersion}  |
      | name               | ${CTX:providerName}        |
      | displayName        | ${CTX:providerDisplayName} |
      | version            | ${CTX:providerVersion}     |
      | template           | azure-openai               |
      | spec.context       | ${CTX:providerContext}     |
      | spec.upstream.url  | http://testbench:3008      |
      | accessControl.mode | allow_all                  |
      | spec.policies      | [{"name":"azure-llm-cost","version":"v1","paths":[{"path":"/*","methods":["*"],"params":{"modelMappings":[{"deployment":"chat-54-mini","model":"gpt-5.4-mini"}]}}]}] |
    Then the response status code should be 201

    # A scripted reply with no model goes unpriced, so polling it until the route is live leaves the
    # requests below the only priced ones on their paths.
    When I send a "POST" request to "${CTX:providerContext}/scripted/ready" until status 200 with body:
      """
      {"x_testbench_reply":{"body":{}}}
      """

    When I send a "POST" request to "${CTX:providerContext}/scripted/openai/v1/chat/completions" with body:
      """
      {"model":"chat-54-mini","messages":[{"role":"user","content":"Hello"}],"x_testbench_reply":{"body":{"id":"chatcmpl-alc","object":"chat.completion","model":"gpt-5.4-mini","choices":[{"index":0,"message":{"role":"assistant","content":"Hi there"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1000,"completion_tokens":500,"total_tokens":1500},"service_tier":"priority"}}}
      """
    Then the response status code should be 200
    And the response body should be:
      """
      {"id":"chatcmpl-alc","object":"chat.completion","model":"gpt-5.4-mini","choices":[{"index":0,"message":{"role":"assistant","content":"Hi there"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1000,"completion_tokens":500,"total_tokens":1500},"service_tier":"priority"}
      """
    And the response header "X-Testbench-Scripted" should be "true"
    And the response header "x-llm-cost" should not exist
    And the latest analytics event for path "${CTX:providerContext}/scripted/openai/v1/chat/completions" should have numeric metadata field "aiMetadata.llmCost" equal to "0.008"
    And the latest analytics event for path "${CTX:providerContext}/scripted/openai/v1/chat/completions" should have numeric metadata field "aiTokenUsage.promptTokens" equal to "1000"
    And the latest analytics event for path "${CTX:providerContext}/scripted/openai/v1/chat/completions" should have numeric metadata field "aiTokenUsage.completionTokens" equal to "500"
    And the latest analytics event for path "${CTX:providerContext}/scripted/openai/v1/chat/completions" should have numeric metadata field "aiTokenUsage.totalTokens" equal to "1500"

    When I delete the LLM provider "${CTX:providerName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:providerContext}/scripted/ready" until status 404

  # gpt-4o-audio-preview has no audio or reasoning rate, so audio input bills as text input and audio
  # and reasoning output as text output: the same as 1000 x 0.000002 + 500 x 0.00001 = 0.007
  Scenario: Price responses carrying audio and reasoning tokens against an entry that declares no audio or reasoning rate (audio and reasoning)
    Given I generate a unique resource name from "alc-audio" and store it as "providerName"
    And I generate a unique value from "alc-audio" and store it as "providerDisplayName"
    And I generate a unique API version from "alc-audio" and store it as "providerVersion"
    And I generate a unique API context from "/alc-audio" and store it as "providerContext"
    When I create LLM provider from "resources/templates/llm-provider.yaml" with values:
      | apiVersion         | ${CTX:gatewaySpecVersion}  |
      | name               | ${CTX:providerName}        |
      | displayName        | ${CTX:providerDisplayName} |
      | version            | ${CTX:providerVersion}     |
      | template           | azure-openai               |
      | spec.context       | ${CTX:providerContext}     |
      | spec.upstream.url  | http://testbench:3008      |
      | accessControl.mode | allow_all                  |
      | spec.policies      | [{"name":"azure-llm-cost","version":"v1","paths":[{"path":"/*","methods":["*"],"params":{"modelMappings":[{"deployment":"chat-audio","model":"gpt-4o-audio-preview"}]}}]}] |
    Then the response status code should be 201

    # A scripted reply with no model goes unpriced, so polling it until the route is live leaves the
    # requests below the only priced ones on their paths.
    When I send a "POST" request to "${CTX:providerContext}/scripted/ready" until status 200 with body:
      """
      {"x_testbench_reply":{"body":{}}}
      """

    When I send a "POST" request to "${CTX:providerContext}/scripted/openai/v1/chat/completions" with body:
      """
      {"model":"chat-audio","messages":[{"role":"user","content":"Hello"}],"x_testbench_reply":{"body":{"id":"chatcmpl-alc","object":"chat.completion","model":"gpt-4o-audio-preview","choices":[{"index":0,"message":{"role":"assistant","content":"Hi there"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1000,"completion_tokens":500,"total_tokens":1500,"prompt_tokens_details":{"audio_tokens":300},"completion_tokens_details":{"audio_tokens":100,"reasoning_tokens":50}}}}}
      """
    Then the response status code should be 200
    And the response body should be:
      """
      {"id":"chatcmpl-alc","object":"chat.completion","model":"gpt-4o-audio-preview","choices":[{"index":0,"message":{"role":"assistant","content":"Hi there"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1000,"completion_tokens":500,"total_tokens":1500,"prompt_tokens_details":{"audio_tokens":300},"completion_tokens_details":{"audio_tokens":100,"reasoning_tokens":50}}}
      """
    And the response header "X-Testbench-Scripted" should be "true"
    And the response header "x-llm-cost" should not exist
    And the latest analytics event for path "${CTX:providerContext}/scripted/openai/v1/chat/completions" should have numeric metadata field "aiMetadata.llmCost" equal to "0.007"
    And the latest analytics event for path "${CTX:providerContext}/scripted/openai/v1/chat/completions" should have numeric metadata field "aiTokenUsage.promptTokens" equal to "1000"
    And the latest analytics event for path "${CTX:providerContext}/scripted/openai/v1/chat/completions" should have numeric metadata field "aiTokenUsage.completionTokens" equal to "500"
    And the latest analytics event for path "${CTX:providerContext}/scripted/openai/v1/chat/completions" should have numeric metadata field "aiTokenUsage.totalTokens" equal to "1500"

    When I delete the LLM provider "${CTX:providerName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:providerContext}/scripted/ready" until status 404

  # Anthropic spells reasoning thinking_tokens. claude-opus-4-5 has a reasoning rate of 0.00002:
  # 1000 x 0.000005 + 400 x 0.000025 + 100 x 0.00002 = 0.017 (0.0175 if thinking were plain output)
  Scenario: Price responses carrying audio and reasoning tokens against an entry that declares no audio or reasoning rate (thinking tokens)
    Given I generate a unique resource name from "alc-thinking" and store it as "providerName"
    And I generate a unique value from "alc-thinking" and store it as "providerDisplayName"
    And I generate a unique API version from "alc-thinking" and store it as "providerVersion"
    And I generate a unique API context from "/alc-thinking" and store it as "providerContext"
    When I create LLM provider from "resources/templates/llm-provider.yaml" with values:
      | apiVersion         | ${CTX:gatewaySpecVersion}  |
      | name               | ${CTX:providerName}        |
      | displayName        | ${CTX:providerDisplayName} |
      | version            | ${CTX:providerVersion}     |
      | template           | azureai-foundry            |
      | spec.context       | ${CTX:providerContext}     |
      | spec.upstream.url  | http://testbench:3008      |
      | accessControl.mode | allow_all                  |
      | spec.policies      | [{"name":"azure-llm-cost","version":"v1","paths":[{"path":"/*","methods":["*"],"params":{"modelMappings":[{"deployment":"my-claude","model":"claude-opus-4-5"}]}}]}] |
    Then the response status code should be 201

    # A scripted reply with no model goes unpriced, so polling it until the route is live leaves the
    # requests below the only priced ones on their paths.
    When I send a "POST" request to "${CTX:providerContext}/scripted/ready" until status 200 with body:
      """
      {"x_testbench_reply":{"body":{}}}
      """

    When I send a "POST" request to "${CTX:providerContext}/scripted/anthropic/v1/messages" with body:
      """
      {"model":"my-claude","max_tokens":100,"messages":[{"role":"user","content":"Hello"}],"x_testbench_reply":{"body":{"id":"msg_alc","type":"message","role":"assistant","model":"claude-opus-4-5","content":[{"type":"text","text":"Hi there"}],"usage":{"input_tokens":1000,"output_tokens":500,"output_tokens_details":{"thinking_tokens":100}}}}}
      """
    Then the response status code should be 200
    And the response body should be:
      """
      {"id":"msg_alc","type":"message","role":"assistant","model":"claude-opus-4-5","content":[{"type":"text","text":"Hi there"}],"usage":{"input_tokens":1000,"output_tokens":500,"output_tokens_details":{"thinking_tokens":100}}}
      """
    And the response header "X-Testbench-Scripted" should be "true"
    And the response header "x-llm-cost" should not exist
    And the latest analytics event for path "${CTX:providerContext}/scripted/anthropic/v1/messages" should have numeric metadata field "aiMetadata.llmCost" equal to "0.017"
    And the latest analytics event for path "${CTX:providerContext}/scripted/anthropic/v1/messages" should have numeric metadata field "aiTokenUsage.promptTokens" equal to "1000"
    And the latest analytics event for path "${CTX:providerContext}/scripted/anthropic/v1/messages" should have numeric metadata field "aiTokenUsage.completionTokens" equal to "500"
    And the latest analytics event for path "${CTX:providerContext}/scripted/anthropic/v1/messages" should have numeric metadata field "aiTokenUsage.totalTokens" equal to "1500"

    When I delete the LLM provider "${CTX:providerName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:providerContext}/scripted/ready" until status 404

  # The subsets exceed their totals, so the text parts floor at zero and only the subsets bill:
  # 300 cached x 0.0000005 + 80 reasoning x 0.000004 = 0.00047
  Scenario: Price a response whose token subsets exceed their totals, a web-search charge expressed both as a flat number and as a sized object, and an entry billed by a unit other than tokens (subsets exceed totals)
    Given I generate a unique resource name from "alc-subsets" and store it as "providerName"
    And I generate a unique value from "alc-subsets" and store it as "providerDisplayName"
    And I generate a unique API version from "alc-subsets" and store it as "providerVersion"
    And I generate a unique API context from "/alc-subsets" and store it as "providerContext"
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
      {"model":"chat-mini","messages":[{"role":"user","content":"Hello"}],"x_testbench_reply":{"body":{"id":"chatcmpl-alc","object":"chat.completion","model":"gpt-4o-mini","choices":[{"index":0,"message":{"role":"assistant","content":"Hi there"},"finish_reason":"stop"}],"usage":{"prompt_tokens":100,"completion_tokens":50,"total_tokens":150,"prompt_tokens_details":{"cached_tokens":300},"completion_tokens_details":{"reasoning_tokens":80}}}}}
      """
    Then the response status code should be 200
    And the response body should be:
      """
      {"id":"chatcmpl-alc","object":"chat.completion","model":"gpt-4o-mini","choices":[{"index":0,"message":{"role":"assistant","content":"Hi there"},"finish_reason":"stop"}],"usage":{"prompt_tokens":100,"completion_tokens":50,"total_tokens":150,"prompt_tokens_details":{"cached_tokens":300},"completion_tokens_details":{"reasoning_tokens":80}}}
      """
    And the response header "X-Testbench-Scripted" should be "true"
    And the response header "x-llm-cost" should not exist
    And the latest analytics event for path "${CTX:providerContext}/scripted/openai/v1/chat/completions" should have numeric metadata field "aiMetadata.llmCost" equal to "0.00047"
    And the latest analytics event for path "${CTX:providerContext}/scripted/openai/v1/chat/completions" should have numeric metadata field "aiTokenUsage.promptTokens" equal to "100"
    And the latest analytics event for path "${CTX:providerContext}/scripted/openai/v1/chat/completions" should have numeric metadata field "aiTokenUsage.completionTokens" equal to "50"
    And the latest analytics event for path "${CTX:providerContext}/scripted/openai/v1/chat/completions" should have numeric metadata field "aiTokenUsage.totalTokens" equal to "150"

    When I delete the LLM provider "${CTX:providerName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:providerContext}/scripted/ready" until status 404

  # A flat per-query rate: 100 x 0.000005 + 50 x 0.000025 + 2 x 0.01 = 0.02175
  Scenario: Price a response whose token subsets exceed their totals, a web-search charge expressed both as a flat number and as a sized object, and an entry billed by a unit other than tokens (flat web-search rate)
    Given I generate a unique resource name from "alc-search-flat" and store it as "providerName"
    And I generate a unique value from "alc-search-flat" and store it as "providerDisplayName"
    And I generate a unique API version from "alc-search-flat" and store it as "providerVersion"
    And I generate a unique API context from "/alc-search-flat" and store it as "providerContext"
    When I create LLM provider from "resources/templates/llm-provider.yaml" with values:
      | apiVersion         | ${CTX:gatewaySpecVersion}  |
      | name               | ${CTX:providerName}        |
      | displayName        | ${CTX:providerDisplayName} |
      | version            | ${CTX:providerVersion}     |
      | template           | azureai-foundry            |
      | spec.context       | ${CTX:providerContext}     |
      | spec.upstream.url  | http://testbench:3008      |
      | accessControl.mode | allow_all                  |
      | spec.policies      | [{"name":"azure-llm-cost","version":"v1","paths":[{"path":"/*","methods":["*"],"params":{"modelMappings":[{"deployment":"my-claude","model":"claude-opus-4-5"}]}}]}] |
    Then the response status code should be 201

    # A scripted reply with no model goes unpriced, so polling it until the route is live leaves the
    # requests below the only priced ones on their paths.
    When I send a "POST" request to "${CTX:providerContext}/scripted/ready" until status 200 with body:
      """
      {"x_testbench_reply":{"body":{}}}
      """

    When I send a "POST" request to "${CTX:providerContext}/scripted/anthropic/v1/messages" with body:
      """
      {"model":"my-claude","max_tokens":100,"messages":[{"role":"user","content":"Hello"}],"x_testbench_reply":{"body":{"id":"msg_alc","type":"message","role":"assistant","model":"claude-opus-4-5","content":[{"type":"text","text":"Hi there"}],"usage":{"input_tokens":100,"output_tokens":50,"server_tool_use":{"web_search_requests":2}}}}}
      """
    Then the response status code should be 200
    And the response body should be:
      """
      {"id":"msg_alc","type":"message","role":"assistant","model":"claude-opus-4-5","content":[{"type":"text","text":"Hi there"}],"usage":{"input_tokens":100,"output_tokens":50,"server_tool_use":{"web_search_requests":2}}}
      """
    And the response header "X-Testbench-Scripted" should be "true"
    And the response header "x-llm-cost" should not exist
    And the latest analytics event for path "${CTX:providerContext}/scripted/anthropic/v1/messages" should have numeric metadata field "aiMetadata.llmCost" equal to "0.02175"
    And the latest analytics event for path "${CTX:providerContext}/scripted/anthropic/v1/messages" should have numeric metadata field "aiTokenUsage.promptTokens" equal to "100"
    And the latest analytics event for path "${CTX:providerContext}/scripted/anthropic/v1/messages" should have numeric metadata field "aiTokenUsage.completionTokens" equal to "50"
    And the latest analytics event for path "${CTX:providerContext}/scripted/anthropic/v1/messages" should have numeric metadata field "aiTokenUsage.totalTokens" equal to "150"

    When I delete the LLM provider "${CTX:providerName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:providerContext}/scripted/ready" until status 404

  # A rate per context size: the response never reports the size, so the medium rate applies:
  # 1000 x 0.000002 + 500 x 0.00001 + 2 x 0.03 = 0.067
  Scenario: Price a response whose token subsets exceed their totals, a web-search charge expressed both as a flat number and as a sized object, and an entry billed by a unit other than tokens (sized web-search rate)
    Given I generate a unique resource name from "alc-search-sized" and store it as "providerName"
    And I generate a unique value from "alc-search-sized" and store it as "providerDisplayName"
    And I generate a unique API version from "alc-search-sized" and store it as "providerVersion"
    And I generate a unique API context from "/alc-search-sized" and store it as "providerContext"
    When I create LLM provider from "resources/templates/llm-provider.yaml" with values:
      | apiVersion         | ${CTX:gatewaySpecVersion}  |
      | name               | ${CTX:providerName}        |
      | displayName        | ${CTX:providerDisplayName} |
      | version            | ${CTX:providerVersion}     |
      | template           | azure-openai               |
      | spec.context       | ${CTX:providerContext}     |
      | spec.upstream.url  | http://testbench:3008      |
      | accessControl.mode | allow_all                  |
      | spec.policies      | [{"name":"azure-llm-cost","version":"v1","paths":[{"path":"/*","methods":["*"],"params":{"modelMappings":[{"deployment":"chat-search","model":"gpt-4o-search-preview"}]}}]}] |
    Then the response status code should be 201

    # A scripted reply with no model goes unpriced, so polling it until the route is live leaves the
    # requests below the only priced ones on their paths.
    When I send a "POST" request to "${CTX:providerContext}/scripted/ready" until status 200 with body:
      """
      {"x_testbench_reply":{"body":{}}}
      """

    When I send a "POST" request to "${CTX:providerContext}/scripted/openai/v1/chat/completions" with body:
      """
      {"model":"chat-search","messages":[{"role":"user","content":"Hello"}],"x_testbench_reply":{"body":{"id":"chatcmpl-alc","object":"chat.completion","model":"gpt-4o-search-preview","choices":[{"index":0,"message":{"role":"assistant","content":"Hi there"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1000,"completion_tokens":500,"total_tokens":1500,"server_tool_use":{"web_search_requests":2}}}}}
      """
    Then the response status code should be 200
    And the response body should be:
      """
      {"id":"chatcmpl-alc","object":"chat.completion","model":"gpt-4o-search-preview","choices":[{"index":0,"message":{"role":"assistant","content":"Hi there"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1000,"completion_tokens":500,"total_tokens":1500,"server_tool_use":{"web_search_requests":2}}}
      """
    And the response header "X-Testbench-Scripted" should be "true"
    And the response header "x-llm-cost" should not exist
    And the latest analytics event for path "${CTX:providerContext}/scripted/openai/v1/chat/completions" should have numeric metadata field "aiMetadata.llmCost" equal to "0.067"
    And the latest analytics event for path "${CTX:providerContext}/scripted/openai/v1/chat/completions" should have numeric metadata field "aiTokenUsage.promptTokens" equal to "1000"
    And the latest analytics event for path "${CTX:providerContext}/scripted/openai/v1/chat/completions" should have numeric metadata field "aiTokenUsage.completionTokens" equal to "500"
    And the latest analytics event for path "${CTX:providerContext}/scripted/openai/v1/chat/completions" should have numeric metadata field "aiTokenUsage.totalTokens" equal to "1500"

    When I delete the LLM provider "${CTX:providerName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:providerContext}/scripted/ready" until status 404

  # dall-e-3 is priced per image, not per token, so the policy leaves it unpriced.
  Scenario: Price a response whose token subsets exceed their totals, a web-search charge expressed both as a flat number and as a sized object, and an entry billed by a unit other than tokens (non-token entry)
    Given I generate a unique resource name from "alc-non-token" and store it as "providerName"
    And I generate a unique value from "alc-non-token" and store it as "providerDisplayName"
    And I generate a unique API version from "alc-non-token" and store it as "providerVersion"
    And I generate a unique API context from "/alc-non-token" and store it as "providerContext"
    When I create LLM provider from "resources/templates/llm-provider.yaml" with values:
      | apiVersion         | ${CTX:gatewaySpecVersion}  |
      | name               | ${CTX:providerName}        |
      | displayName        | ${CTX:providerDisplayName} |
      | version            | ${CTX:providerVersion}     |
      | template           | azure-openai               |
      | spec.context       | ${CTX:providerContext}     |
      | spec.upstream.url  | http://testbench:3008      |
      | accessControl.mode | allow_all                  |
      | spec.policies      | [{"name":"azure-llm-cost","version":"v1","paths":[{"path":"/*","methods":["*"],"params":{"modelMappings":[{"deployment":"my-dalle","model":"hd/1024-x-1024/dall-e-3"}]}}]}] |
    Then the response status code should be 201

    # A scripted reply with no model goes unpriced, so polling it until the route is live leaves the
    # requests below the only priced ones on their paths.
    When I send a "POST" request to "${CTX:providerContext}/scripted/ready" until status 200 with body:
      """
      {"x_testbench_reply":{"body":{}}}
      """

    When I send a "POST" request to "${CTX:providerContext}/scripted/openai/v1/images/generations" with body:
      """
      {"model":"my-dalle","prompt":"A lighthouse","x_testbench_reply":{"body":{"created":1730000000,"data":[{"url":"https://example.invalid/image.png"}],"usage":{"prompt_tokens":10,"completion_tokens":0}}}}
      """
    Then the response status code should be 200
    And the response body should be:
      """
      {"created":1730000000,"data":[{"url":"https://example.invalid/image.png"}],"usage":{"prompt_tokens":10,"completion_tokens":0}}
      """
    And the response header "X-Testbench-Scripted" should be "true"
    And the response header "x-llm-cost" should not exist
    And the latest analytics event for path "${CTX:providerContext}/scripted/openai/v1/images/generations" should have numeric metadata field "aiMetadata.llmCost" equal to "0"
    And the "gateway-runtime" service logs should contain "model has no per-token pricing, request not priced"

    When I delete the LLM provider "${CTX:providerName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:providerContext}/scripted/ready" until status 404
