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
Feature: LLM cost usage shapes and pricing rules
  As an API developer
  I want each call priced from the usage its provider reports
  So that every provider's own usage shape and billing rule reaches the cost exactly

  # Costs follow the staged pricing file (overlays/pricing/). Each scenario's comment shows the
  # arithmetic. The cost reaches analytics only, so the scenarios read it there.

  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"

  Scenario: Price a buffered OpenAI chat completion that omits total_tokens and inspect the response and analytics
    Given I generate a unique resource name from "lc-published" and store it as "providerName"
    And I generate a unique value from "lc-published" and store it as "providerDisplayName"
    And I generate a unique API version from "lc-published" and store it as "providerVersion"
    And I generate a unique API context from "/lc-published" and store it as "providerContext"
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
    # gpt-4o-mini: 1000 x 0.000001 + 500 x 0.000004 = 0.003; the total is derived as 1500

    When I send a "POST" request to "${CTX:providerContext}/scripted/openai/v1/chat/completions" with body:
      """
      {"model":"gpt-4o-mini","messages":[{"role":"user","content":"Hello"}],"x_testbench_reply":{"body":{"id":"chatcmpl-lc","object":"chat.completion","model":"gpt-4o-mini","choices":[{"index":0,"message":{"role":"assistant","content":"Hi there"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1000,"completion_tokens":500}}}}
      """
    Then the response status code should be 200
    And the response header "X-Testbench-Scripted" should be "true"
    And the response header "x-llm-cost" should not exist
    And the response header "x-llm-cost-status" should not exist
    And the response body should be:
      """
      {"id":"chatcmpl-lc","object":"chat.completion","model":"gpt-4o-mini","choices":[{"index":0,"message":{"role":"assistant","content":"Hi there"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1000,"completion_tokens":500}}
      """
    And the latest analytics event for path "${CTX:providerContext}/scripted/openai/v1/chat/completions" should have numeric metadata field "aiMetadata.llmCost" equal to "0.003"
    And the latest analytics event for path "${CTX:providerContext}/scripted/openai/v1/chat/completions" should have numeric metadata field "aiTokenUsage.promptTokens" equal to "1000"
    And the latest analytics event for path "${CTX:providerContext}/scripted/openai/v1/chat/completions" should have numeric metadata field "aiTokenUsage.completionTokens" equal to "500"
    And the latest analytics event for path "${CTX:providerContext}/scripted/openai/v1/chat/completions" should have numeric metadata field "aiTokenUsage.totalTokens" equal to "1500"

    When I delete the LLM provider "${CTX:providerName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:providerContext}/scripted/ready" until status 404

  Scenario: Attach llm-cost once at /* on an OpenAI provider and call both /chat/completions and /responses
    Given I generate a unique resource name from "lc-two-surfaces" and store it as "providerName"
    And I generate a unique value from "lc-two-surfaces" and store it as "providerDisplayName"
    And I generate a unique API version from "lc-two-surfaces" and store it as "providerVersion"
    And I generate a unique API context from "/lc-two-surfaces" and store it as "providerContext"
    When I create LLM provider from "resources/templates/llm-provider.yaml" with values:
      | apiVersion         | ${CTX:gatewaySpecVersion}  |
      | name               | ${CTX:providerName}        |
      | displayName        | ${CTX:providerDisplayName} |
      | version            | ${CTX:providerVersion}     |
      | template           | openai |
      | spec.context       | ${CTX:providerContext}     |
      | spec.upstream.url  | http://testbench:3008/scripted |
      | accessControl.mode | allow_all                  |
      | spec.policies      | [{"name":"llm-cost","version":"v1","paths":[{"path":"/*","methods":["*"]}]}] |
    Then the response status code should be 201

    # The upstream URL carries /scripted, so the called path ends in the real endpoint (/responses)
    # that the template's resourceMappings match, and the testbench still scripts the reply.
    # A scripted reply with no model goes unpriced, so polling it until the route is live leaves the
    # requests below the only priced ones on their paths.
    When I send a "POST" request to "${CTX:providerContext}/ready" until status 200 with body:
      """
      {"x_testbench_reply":{"body":{}}}
      """
    # chat: 1000 x 0.000001 + 500 x 0.000004 = 0.003. responses: 2000 x 0.000001 + 1000 x 0.000004 = 0.006

    When I send a "POST" request to "${CTX:providerContext}/chat/completions" with body:
      """
      {"model":"gpt-4o-mini","messages":[{"role":"user","content":"Hello"}],"x_testbench_reply":{"body":{"id":"chatcmpl-lc","object":"chat.completion","model":"gpt-4o-mini","choices":[{"index":0,"message":{"role":"assistant","content":"Hi there"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1000,"completion_tokens":500,"total_tokens":1500}}}}
      """
    Then the response status code should be 200
    And the response header "X-Testbench-Scripted" should be "true"
    And the response header "x-llm-cost" should not exist
    And the latest analytics event for path "${CTX:providerContext}/chat/completions" should have numeric metadata field "aiMetadata.llmCost" equal to "0.003"
    And the latest analytics event for path "${CTX:providerContext}/chat/completions" should have numeric metadata field "aiTokenUsage.promptTokens" equal to "1000"
    And the latest analytics event for path "${CTX:providerContext}/chat/completions" should have numeric metadata field "aiTokenUsage.completionTokens" equal to "500"

    When I send a "POST" request to "${CTX:providerContext}/responses" with body:
      """
      {"model":"gpt-4o-mini","input":"Hello","x_testbench_reply":{"body":{"id":"resp_lc","object":"response","model":"gpt-4o-mini","usage":{"input_tokens":2000,"output_tokens":1000,"total_tokens":3000}}}}
      """
    Then the response status code should be 200
    And the response header "X-Testbench-Scripted" should be "true"
    And the response header "x-llm-cost" should not exist
    And the latest analytics event for path "${CTX:providerContext}/responses" should have numeric metadata field "aiMetadata.llmCost" equal to "0.006"
    And the latest analytics event for path "${CTX:providerContext}/responses" should have numeric metadata field "aiTokenUsage.promptTokens" equal to "2000"
    And the latest analytics event for path "${CTX:providerContext}/responses" should have numeric metadata field "aiTokenUsage.completionTokens" equal to "1000"
    And the latest analytics event for path "${CTX:providerContext}/responses" should have numeric metadata field "aiTokenUsage.totalTokens" equal to "3000"

    When I delete the LLM provider "${CTX:providerName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:providerContext}/ready" until status 404

  Scenario Outline: Send a successful response with no usable usage (<case>)
    Given I generate a unique resource name from "lc-no-usage-<slug>" and store it as "providerName"
    And I generate a unique value from "lc-no-usage-<slug>" and store it as "providerDisplayName"
    And I generate a unique API version from "lc-no-usage-<slug>" and store it as "providerVersion"
    And I generate a unique API context from "/lc-no-usage-<slug>" and store it as "providerContext"
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
      {"model":"gpt-4o-mini","messages":[{"role":"user","content":"Hello"}],"x_testbench_reply":<reply>}
      """
    Then the response status code should be 200
    And the response header "X-Testbench-Scripted" should be "true"
    And the response header "x-llm-cost" should not exist
    And the latest analytics event for path "${CTX:providerContext}/scripted/openai/v1/chat/completions" should have numeric metadata field "aiMetadata.llmCost" equal to "0"

    When I delete the LLM provider "${CTX:providerName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:providerContext}/scripted/ready" until status 404

    Examples:
      | case          | slug   | reply                                                   |
      | absent usage  | absent | {"body":{"model":"gpt-4o-mini","choices":[]}}           |
      | empty body    | empty  | {"raw":""}                                              |
      | non-JSON body | text   | {"raw":"this is not json"}                              |

  Scenario Outline: Send hostile response bodies: negative token counts, counts at the int64 limit, and deeply nested JSON (<case>)
    Given I generate a unique resource name from "lc-hostile-<slug>" and store it as "providerName"
    And I generate a unique value from "lc-hostile-<slug>" and store it as "providerDisplayName"
    And I generate a unique API version from "lc-hostile-<slug>" and store it as "providerVersion"
    And I generate a unique API context from "/lc-hostile-<slug>" and store it as "providerContext"
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
      {"model":"gpt-4o-mini","messages":[{"role":"user","content":"Hello"}],"x_testbench_reply":{"body":<reply>}}
      """
    Then the response status code should be 200
    And the response header "X-Testbench-Scripted" should be "true"
    And the response header "x-llm-cost" should not exist
    And the latest analytics event for path "${CTX:providerContext}/scripted/openai/v1/chat/completions" should have numeric metadata field "aiMetadata.llmCost" at least "0"

    When I delete the LLM provider "${CTX:providerName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:providerContext}/scripted/ready" until status 404

    Examples:
      | case            | slug     | reply |
      | negative counts | negative | {"model":"gpt-4o-mini","usage":{"prompt_tokens":-1000,"completion_tokens":-500,"total_tokens":-1500}} |
      | int64 limit     | int64    | {"model":"gpt-4o-mini","usage":{"prompt_tokens":9223372036854775807,"completion_tokens":9223372036854775807,"total_tokens":9223372036854775807}} |
      | nested JSON     | nested   | {"model":"gpt-4o-mini","usage":{"prompt_tokens":1000,"completion_tokens":500,"total_tokens":1500},"x":{"a":{"a":{"a":{"a":{"a":{"a":{"a":{"a":{"a":{"a":{"a":{"a":{"a":{"a":{"a":{"a":{"a":{"a":{"a":{"a":{"a":{"a":{"a":{"a":{"a":{"a":{"a":{"a":{"a":{"a":1}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}} |

  Scenario Outline: Send an OpenAI response whose service tier is not billed apart (<case>)
    Given I generate a unique resource name from "lc-tier-<slug>" and store it as "providerName"
    And I generate a unique value from "lc-tier-<slug>" and store it as "providerDisplayName"
    And I generate a unique API version from "lc-tier-<slug>" and store it as "providerVersion"
    And I generate a unique API context from "/lc-tier-<slug>" and store it as "providerContext"
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
    # Neither tier changes the rate, so gpt-4o-mini stays at 1000 x 0.000001 + 500 x 0.000004 = 0.003

    When I send a "POST" request to "${CTX:providerContext}/scripted/openai/v1/chat/completions" with body:
      """
      {"model":"gpt-4o-mini","messages":[{"role":"user","content":"Hello"}],"x_testbench_reply":{"body":{"id":"chatcmpl-lc","object":"chat.completion","model":"gpt-4o-mini","choices":[{"index":0,"message":{"role":"assistant","content":"Hi there"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1000,"completion_tokens":500,"total_tokens":1500},"service_tier":"<tier>"}}}
      """
    Then the response status code should be 200
    And the response header "X-Testbench-Scripted" should be "true"
    And the response header "x-llm-cost" should not exist
    And the latest analytics event for path "${CTX:providerContext}/scripted/openai/v1/chat/completions" should have numeric metadata field "aiMetadata.llmCost" equal to "0.003"

    When I delete the LLM provider "${CTX:providerName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:providerContext}/scripted/ready" until status 404

    Examples:
      | case                                  | slug    | tier |
      | unrecognised tier                     | auto    | auto |
      | recognised tier the model has no rate | flex    | flex |

  Scenario: Price an Anthropic call whose input exceeds the large-context threshold, and one just below it
    Given I generate a unique resource name from "lc-large-context" and store it as "providerName"
    And I generate a unique value from "lc-large-context" and store it as "providerDisplayName"
    And I generate a unique API version from "lc-large-context" and store it as "providerVersion"
    And I generate a unique API context from "/lc-large-context" and store it as "providerContext"
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
    # claude-test above 200k tokens: 250000 x 0.000006 + 1000 x 0.0000225 = 1.5225
    # below it: 100000 x 0.000003 + 1000 x 0.000015 = 0.315

    When I send a "POST" request to "${CTX:providerContext}/scripted/anthropic/v1/messages-large" with body:
      """
      {"model":"claude-test","max_tokens":100,"messages":[{"role":"user","content":"Hello"}],"x_testbench_reply":{"body":{"id":"msg_lc","type":"message","role":"assistant","model":"claude-test","usage":{"input_tokens":250000,"output_tokens":1000}}}}
      """
    Then the response status code should be 200
    And the response header "X-Testbench-Scripted" should be "true"
    And the response header "x-llm-cost" should not exist
    And the latest analytics event for path "${CTX:providerContext}/scripted/anthropic/v1/messages-large" should have numeric metadata field "aiMetadata.llmCost" equal to "1.5225"

    When I send a "POST" request to "${CTX:providerContext}/scripted/anthropic/v1/messages-small" with body:
      """
      {"model":"claude-test","max_tokens":100,"messages":[{"role":"user","content":"Hello"}],"x_testbench_reply":{"body":{"id":"msg_lc","type":"message","role":"assistant","model":"claude-test","usage":{"input_tokens":100000,"output_tokens":1000}}}}
      """
    Then the response status code should be 200
    And the response header "X-Testbench-Scripted" should be "true"
    And the response header "x-llm-cost" should not exist
    And the latest analytics event for path "${CTX:providerContext}/scripted/anthropic/v1/messages-small" should have numeric metadata field "aiMetadata.llmCost" equal to "0.315"

    When I delete the LLM provider "${CTX:providerName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:providerContext}/scripted/ready" until status 404

  Scenario: Price a Gemini response that carries grounding web search queries
    Given I generate a unique resource name from "lc-gemini-grounding" and store it as "providerName"
    And I generate a unique value from "lc-gemini-grounding" and store it as "providerDisplayName"
    And I generate a unique API version from "lc-gemini-grounding" and store it as "providerVersion"
    And I generate a unique API context from "/lc-gemini-grounding" and store it as "providerContext"
    When I create LLM provider from "resources/templates/llm-provider.yaml" with values:
      | apiVersion         | ${CTX:gatewaySpecVersion}  |
      | name               | ${CTX:providerName}        |
      | displayName        | ${CTX:providerDisplayName} |
      | version            | ${CTX:providerVersion}     |
      | template           | gemini |
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
    # gemini-test: 1000 x 0.000001 + 500 x 0.000004 = 0.003, plus 2 queries x 0.035 = 0.073

    When I send a "POST" request to "${CTX:providerContext}/scripted/gemini/v1/models/gemini-test:generateContent" with body:
      """
      {"contents":[{"role":"user","parts":[{"text":"Hello"}]}],"x_testbench_reply":{"body":{"candidates":[{"content":{"role":"model","parts":[{"text":"Hi"}]},"groundingMetadata":{"webSearchQueries":["first query","second query"]}}],"modelVersion":"gemini-test","usageMetadata":{"promptTokenCount":1000,"candidatesTokenCount":500,"totalTokenCount":1500}}}}
      """
    Then the response status code should be 200
    And the response header "X-Testbench-Scripted" should be "true"
    And the response header "x-llm-cost" should not exist
    And the latest analytics event for path "${CTX:providerContext}/scripted/gemini/v1/models/gemini-test:generateContent" should have numeric metadata field "aiMetadata.llmCost" equal to "0.073"

    When I delete the LLM provider "${CTX:providerName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:providerContext}/scripted/ready" until status 404

  Scenario: Price a Gemini response carrying audio and image token details
    Given I generate a unique resource name from "lc-gemini-modalities" and store it as "providerName"
    And I generate a unique value from "lc-gemini-modalities" and store it as "providerDisplayName"
    And I generate a unique API version from "lc-gemini-modalities" and store it as "providerVersion"
    And I generate a unique API context from "/lc-gemini-modalities" and store it as "providerContext"
    When I create LLM provider from "resources/templates/llm-provider.yaml" with values:
      | apiVersion         | ${CTX:gatewaySpecVersion}  |
      | name               | ${CTX:providerName}        |
      | displayName        | ${CTX:providerDisplayName} |
      | version            | ${CTX:providerVersion}     |
      | template           | gemini |
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
    # gemini-test: text prompt 600 x 0.000001 + audio prompt 400 x 0.000003
    #   + text output 300 x 0.000004 + audio output 100 x 0.000012 + image output 200 x 0.00002
    #   = 0.0006 + 0.0012 + 0.0012 + 0.0012 + 0.004 = 0.0082

    When I send a "POST" request to "${CTX:providerContext}/scripted/gemini/v1/models/gemini-test:generateContent" with body:
      """
      {"contents":[{"role":"user","parts":[{"text":"Hello"}]}],"x_testbench_reply":{"body":{"candidates":[{"content":{"role":"model","parts":[{"text":"Hi"}]}}],"modelVersion":"gemini-test","usageMetadata":{"promptTokenCount":1000,"candidatesTokenCount":600,"totalTokenCount":1600,"promptTokensDetails":[{"modality":"TEXT","tokenCount":600},{"modality":"AUDIO","tokenCount":400}],"candidatesTokensDetails":[{"modality":"TEXT","tokenCount":300},{"modality":"AUDIO","tokenCount":100},{"modality":"IMAGE","tokenCount":200}]}}}}
      """
    Then the response status code should be 200
    And the response header "X-Testbench-Scripted" should be "true"
    And the response header "x-llm-cost" should not exist
    And the latest analytics event for path "${CTX:providerContext}/scripted/gemini/v1/models/gemini-test:generateContent" should have numeric metadata field "aiMetadata.llmCost" equal to "0.0082"

    When I delete the LLM provider "${CTX:providerName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:providerContext}/scripted/ready" until status 404

  Scenario: Price a Bedrock Converse response with cache writes broken down by TTL
    Given I generate a unique resource name from "lc-bedrock-cache-ttl" and store it as "providerName"
    And I generate a unique value from "lc-bedrock-cache-ttl" and store it as "providerDisplayName"
    And I generate a unique API version from "lc-bedrock-cache-ttl" and store it as "providerVersion"
    And I generate a unique API context from "/lc-bedrock-cache-ttl" and store it as "providerContext"
    When I create LLM provider from "resources/templates/llm-provider.yaml" with values:
      | apiVersion         | ${CTX:gatewaySpecVersion}  |
      | name               | ${CTX:providerName}        |
      | displayName        | ${CTX:providerDisplayName} |
      | version            | ${CTX:providerVersion}     |
      | template           | awsbedrock |
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
    # anthropic.claude-bedrock-test-v1:0: 100 x 0.000003 + 50 x 0.000015 + 200 cache read x 0.0000003
    #   + 1000 5m writes x 0.00000375 + 500 1h writes x 0.000006
    #   = 0.0003 + 0.00075 + 0.00006 + 0.00375 + 0.003 = 0.00786

    When I send a "POST" request to "${CTX:providerContext}/scripted/model/anthropic.claude-bedrock-test-v1:0/converse" with body:
      """
      {"messages":[{"role":"user","content":[{"text":"Hello"}]}],"x_testbench_reply":{"body":{"output":{"message":{"role":"assistant","content":[{"text":"Hi"}]}},"usage":{"inputTokens":100,"outputTokens":50,"totalTokens":150,"cacheReadInputTokens":200,"cacheWriteInputTokens":1500,"cacheDetails":[{"ttl":"5m","inputTokens":1000},{"ttl":"1h","inputTokens":500}]}}}}
      """
    Then the response status code should be 200
    And the response header "X-Testbench-Scripted" should be "true"
    And the response header "x-llm-cost" should not exist
    And the latest analytics event for path "${CTX:providerContext}/scripted/model/anthropic.claude-bedrock-test-v1:0/converse" should have numeric metadata field "aiMetadata.llmCost" equal to "0.00786"

    When I delete the LLM provider "${CTX:providerName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:providerContext}/scripted/ready" until status 404
