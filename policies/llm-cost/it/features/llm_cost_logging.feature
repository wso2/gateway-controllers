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
Feature: LLM cost logging
  As a gateway operator
  I want the policy's log lines to name models and amounts but never carry prompts or completions
  So that debug logging cannot leak what callers send or what a provider answers

  # The gateway logs at debug level (overlays/gateway.toml).

  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"

  Scenario: Price a request whose prompt and completion carry sensitive content and capture the policy engine logs
    Given I generate a unique resource name from "lc-logs" and store it as "providerName"
    And I generate a unique value from "lc-logs" and store it as "providerDisplayName"
    And I generate a unique API version from "lc-logs" and store it as "providerVersion"
    And I generate a unique API context from "/lc-logs" and store it as "providerContext"
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
      {"model":"gpt-4o-mini","messages":[{"role":"user","content":"LC-PROMPT-MARKER-7F3A"}],"x_testbench_reply":{"body":{"id":"chatcmpl-lc","object":"chat.completion","model":"gpt-4o-mini","choices":[{"index":0,"message":{"role":"assistant","content":"LC-COMPLETION-MARKER-9B2C"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1000,"completion_tokens":500,"total_tokens":1500}}}}
      """
    Then the response status code should be 200
    And the response header "X-Testbench-Scripted" should be "true"
    And the response header "x-llm-cost" should not exist
    And the latest analytics event for path "${CTX:providerContext}/scripted/openai/v1/chat/completions" should have numeric metadata field "aiMetadata.llmCost" equal to "0.003"
    # An unpriced call makes the policy log a warning, which proves the log is being read.

    When I send a "POST" request to "${CTX:providerContext}/scripted/unlisted/chat/completions" with body:
      """
      {"model":"gpt-9-unlisted","messages":[{"role":"user","content":"LC-PROMPT-MARKER-7F3A"}],"x_testbench_reply":{"body":{"id":"chatcmpl-lc","object":"chat.completion","model":"gpt-9-unlisted","choices":[{"index":0,"message":{"role":"assistant","content":"LC-COMPLETION-MARKER-9B2C"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1000,"completion_tokens":500,"total_tokens":1500}}}}
      """
    Then the response status code should be 200
    And the response header "X-Testbench-Scripted" should be "true"
    And the response header "x-llm-cost" should not exist
    And the latest analytics event for path "${CTX:providerContext}/scripted/unlisted/chat/completions" should have numeric metadata field "aiMetadata.llmCost" equal to "0"
    And the "gateway-runtime" service logs should contain "no pricing entry for model"
    And the "gateway-runtime" service logs should not contain "LC-COMPLETION-MARKER-9B2C"
    And the "gateway-runtime" service logs should not contain "LC-PROMPT-MARKER-7F3A"

    When I delete the LLM provider "${CTX:providerName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:providerContext}/scripted/ready" until status 404
