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
Feature: LLM cost model resolution and pricing file contents
  As an API developer
  I want each call priced from the model it actually used
  So that a model name is matched against the pricing file the way the pricing file defines it

  # The block stages a pricing file whose rates this suite controls (overlays/pricing/). gpt-4o-mini
  # costs 1000 x 0.000001 + 500 x 0.000004 = 0.003 for 1000 prompt and 500 completion tokens.

  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"

  Scenario: Add a custom model entry and override the rates of a model the file already carries
    Given I generate a unique resource name from "lc-custom-pricing" and store it as "providerName"
    And I generate a unique value from "lc-custom-pricing" and store it as "providerDisplayName"
    And I generate a unique API version from "lc-custom-pricing" and store it as "providerVersion"
    And I generate a unique API context from "/lc-custom-pricing" and store it as "providerContext"
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

    When I send a "POST" request to "${CTX:providerContext}/scripted/custom/chat/completions" with body:
      """
      {"model":"my-org-llm","messages":[{"role":"user","content":"Hello"}],"x_testbench_reply":{"body":{"id":"chatcmpl-lc","object":"chat.completion","model":"my-org-llm","choices":[{"index":0,"message":{"role":"assistant","content":"Hi there"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1000,"completion_tokens":500,"total_tokens":1500}}}}
      """
    Then the response status code should be 200
    And the response header "X-Testbench-Scripted" should be "true"
    And the response header "x-llm-cost" should not exist
    And the latest analytics event for path "${CTX:providerContext}/scripted/custom/chat/completions" should have numeric metadata field "aiMetadata.llmCost" equal to "0.006"
    # my-org-llm: 1000 x 0.000002 + 500 x 0.000008 = 0.006. The shipped gpt-4o-mini would cost
    # 0.00045, so 0.003 shows the staged rates replaced them.

    When I send a "POST" request to "${CTX:providerContext}/scripted/override/chat/completions" with body:
      """
      {"model":"gpt-4o-mini","messages":[{"role":"user","content":"Hello"}],"x_testbench_reply":{"body":{"id":"chatcmpl-lc","object":"chat.completion","model":"gpt-4o-mini","choices":[{"index":0,"message":{"role":"assistant","content":"Hi there"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1000,"completion_tokens":500,"total_tokens":1500}}}}
      """
    Then the response status code should be 200
    And the response header "X-Testbench-Scripted" should be "true"
    And the response header "x-llm-cost" should not exist
    And the latest analytics event for path "${CTX:providerContext}/scripted/override/chat/completions" should have numeric metadata field "aiMetadata.llmCost" equal to "0.003"

    When I delete the LLM provider "${CTX:providerName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:providerContext}/scripted/ready" until status 404

  Scenario Outline: Send responses whose model name is in mixed case, carries a provider prefix, or matches only a key with an uppercase letter (<case>)
    Given I generate a unique resource name from "lc-normalise-<slug>" and store it as "providerName"
    And I generate a unique value from "lc-normalise-<slug>" and store it as "providerDisplayName"
    And I generate a unique API version from "lc-normalise-<slug>" and store it as "providerVersion"
    And I generate a unique API context from "/lc-normalise-<slug>" and store it as "providerContext"
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
      {"model":"<model>","messages":[{"role":"user","content":"Hello"}],"x_testbench_reply":{"body":{"id":"chatcmpl-lc","object":"chat.completion","model":"<model>","choices":[{"index":0,"message":{"role":"assistant","content":"Hi there"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1000,"completion_tokens":500,"total_tokens":1500}}}}
      """
    Then the response status code should be 200
    And the response header "X-Testbench-Scripted" should be "true"
    And the response header "x-llm-cost" should not exist
    And the latest analytics event for path "${CTX:providerContext}/scripted/openai/v1/chat/completions" should have numeric metadata field "aiMetadata.llmCost" equal to "<cost>"

    When I delete the LLM provider "${CTX:providerName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:providerContext}/scripted/ready" until status 404

    Examples:
      | case                        | slug      | model              | cost  |
      | mixed case                  | mixed     | GPT-4O-Mini        | 0.003 |
      | provider prefix             | prefix    | openai/gpt-4o-mini | 0.003 |
      | key with an uppercase letter | uppercase | Upper-Key-Model    | 0     |

  # Fixed in gateway 1.2.0 by wso2/api-platform PR #2951 (https://github.com/wso2/api-platform/pull/2951): the 1.1.0 Bedrock template's model-from-URL pattern does not compile in Go.
  @known-issue-gw-1.1.0
  Scenario: Send a Bedrock call through an inference-profile ID that the pricing file carries only as the foundation model
    Given I generate a unique resource name from "lc-bedrock-alias" and store it as "providerName"
    And I generate a unique value from "lc-bedrock-alias" and store it as "providerDisplayName"
    And I generate a unique API version from "lc-bedrock-alias" and store it as "providerVersion"
    And I generate a unique API context from "/lc-bedrock-alias" and store it as "providerContext"
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
    # eu.anthropic.claude-bedrock-test-v1:0 resolves to anthropic.claude-bedrock-test-v1:0:
    # 1000 x 0.000003 + 500 x 0.000015 = 0.0105

    When I send a "POST" request to "${CTX:providerContext}/scripted/model/eu.anthropic.claude-bedrock-test-v1:0/converse" with body:
      """
      {"messages":[{"role":"user","content":[{"text":"Hello"}]}],"x_testbench_reply":{"body":{"output":{"message":{"role":"assistant","content":[{"text":"Hi"}]}},"usage":{"inputTokens":1000,"outputTokens":500,"totalTokens":1500}}}}
      """
    Then the response status code should be 200
    And the response header "X-Testbench-Scripted" should be "true"
    And the response header "x-llm-cost" should not exist
    And the latest analytics event for path "${CTX:providerContext}/scripted/model/eu.anthropic.claude-bedrock-test-v1:0/converse" should have numeric metadata field "aiMetadata.llmCost" equal to "0.0105"

    When I delete the LLM provider "${CTX:providerName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:providerContext}/scripted/ready" until status 404

  Scenario: Send a response that carries no model field while the request body names the model
    Given I generate a unique resource name from "lc-model-in-request" and store it as "providerName"
    And I generate a unique value from "lc-model-in-request" and store it as "providerDisplayName"
    And I generate a unique API version from "lc-model-in-request" and store it as "providerVersion"
    And I generate a unique API context from "/lc-model-in-request" and store it as "providerContext"
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
      {"model":"gpt-4o-mini","messages":[{"role":"user","content":"Hello"}],"x_testbench_reply":{"body":{"id":"chatcmpl-lc","object":"chat.completion","choices":[{"index":0,"message":{"role":"assistant","content":"Hi there"}}],"usage":{"prompt_tokens":1000,"completion_tokens":500,"total_tokens":1500}}}}
      """
    Then the response status code should be 200
    And the response header "X-Testbench-Scripted" should be "true"
    And the response header "x-llm-cost" should not exist
    And the latest analytics event for path "${CTX:providerContext}/scripted/openai/v1/chat/completions" should have numeric metadata field "aiMetadata.llmCost" equal to "0.003"
    And the latest analytics event for path "${CTX:providerContext}/scripted/openai/v1/chat/completions" should have numeric metadata field "aiTokenUsage.promptTokens" equal to "1000"
    And the latest analytics event for path "${CTX:providerContext}/scripted/openai/v1/chat/completions" should have numeric metadata field "aiTokenUsage.completionTokens" equal to "500"

    When I delete the LLM provider "${CTX:providerName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:providerContext}/scripted/ready" until status 404

  Scenario Outline: Send a response naming a model the pricing file does not carry (<case>)
    Given I generate a unique resource name from "lc-unknown-<slug>" and store it as "providerName"
    And I generate a unique value from "lc-unknown-<slug>" and store it as "providerDisplayName"
    And I generate a unique API version from "lc-unknown-<slug>" and store it as "providerVersion"
    And I generate a unique API context from "/lc-unknown-<slug>" and store it as "providerContext"
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
      {"model":"<model>","messages":[{"role":"user","content":"Hello"}],"x_testbench_reply":{"body":{"id":"chatcmpl-lc","object":"chat.completion","model":"<model>","choices":[{"index":0,"message":{"role":"assistant","content":"Hi there"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1000,"completion_tokens":500,"total_tokens":1500}}}}
      """
    Then the response status code should be 200
    And the response header "X-Testbench-Scripted" should be "true"
    And the response header "x-llm-cost" should not exist
    And the latest analytics event for path "${CTX:providerContext}/scripted/openai/v1/chat/completions" should have numeric metadata field "aiMetadata.llmCost" equal to "0"
    And the response body should contain "<model>"

    When I delete the LLM provider "${CTX:providerName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:providerContext}/scripted/ready" until status 404

    Examples:
      | case                      | slug     | model                  |
      | unlisted dated snapshot   | snapshot | gpt-4o-mini-2099-01-01 |
      | suffixed catalogued name  | suffixed | gpt-4o-mini-extra      |

  Scenario: Supply a pricing file where some entries are structurally invalid
    Given I generate a unique resource name from "lc-invalid-entry" and store it as "providerName"
    And I generate a unique value from "lc-invalid-entry" and store it as "providerDisplayName"
    And I generate a unique API version from "lc-invalid-entry" and store it as "providerVersion"
    And I generate a unique API context from "/lc-invalid-entry" and store it as "providerContext"
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
    # broken-entry carries a string where the input rate belongs, so the file loads without it.

    When I send a "POST" request to "${CTX:providerContext}/scripted/broken/chat/completions" with body:
      """
      {"model":"broken-entry","messages":[{"role":"user","content":"Hello"}],"x_testbench_reply":{"body":{"id":"chatcmpl-lc","object":"chat.completion","model":"broken-entry","choices":[{"index":0,"message":{"role":"assistant","content":"Hi there"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1000,"completion_tokens":500,"total_tokens":1500}}}}
      """
    Then the response status code should be 200
    And the response header "X-Testbench-Scripted" should be "true"
    And the response header "x-llm-cost" should not exist
    And the latest analytics event for path "${CTX:providerContext}/scripted/broken/chat/completions" should have numeric metadata field "aiMetadata.llmCost" equal to "0"

    When I send a "POST" request to "${CTX:providerContext}/scripted/valid/chat/completions" with body:
      """
      {"model":"gpt-4o-mini","messages":[{"role":"user","content":"Hello"}],"x_testbench_reply":{"body":{"id":"chatcmpl-lc","object":"chat.completion","model":"gpt-4o-mini","choices":[{"index":0,"message":{"role":"assistant","content":"Hi there"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1000,"completion_tokens":500,"total_tokens":1500}}}}
      """
    Then the response status code should be 200
    And the response header "X-Testbench-Scripted" should be "true"
    And the response header "x-llm-cost" should not exist
    And the latest analytics event for path "${CTX:providerContext}/scripted/valid/chat/completions" should have numeric metadata field "aiMetadata.llmCost" equal to "0.003"
    And the "gateway-runtime" service logs should contain "skipping invalid pricing entry"

    When I delete the LLM provider "${CTX:providerName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:providerContext}/scripted/ready" until status 404
