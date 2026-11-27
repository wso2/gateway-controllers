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

@ratelimit-streaming-cost
Feature: Advanced rate limit cost extraction from streamed responses
  As an LLM API operator
  I want the cost of a server-sent-event response to be charged when the stream ends
  So that token usage reported at the end of a stream counts against the quota

  # The LLM mock streams the events each request scripts in x_testbench_reply, flushing after each
  # one. The response headers leave before the first event, so a streamed response reports the
  # quota as it stood before the stream and the charge lands when the stream ends. The scenarios
  # therefore poll for the rejection instead of asserting the next request's headers.

  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"

  Scenario: Usage reported in the last event of a stream is charged at the end of the stream
    Given I generate a unique value from "arl-sse-usage" and store it as "apiName"
    And I generate a unique API version from "arl-sse-usage" and store it as "apiVersion"
    And I generate a unique API context from "/arl-sse-usage" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}         |
      | name                   | ${CTX:apiName}                   |
      | spec.displayName       | ${CTX:apiName}                   |
      | spec.version           | ${CTX:apiVersion}                |
      | spec.context           | ${CTX:apiContext}/$version       |
      | spec.upstream.main.url | http://testbench:3008/scripted   |
      | spec.operations        | [{"method":"GET","path":"/get"},{"method":"POST","path":"/chat","policies":[{"name":"advanced-ratelimit","version":"v1","params":{"quotas":[{"name":"stream-tokens","limits":[{"limit":100,"duration":"1h"}],"costExtraction":{"enabled":true,"sources":[{"type":"response_body","jsonPath":"$.usage.total_tokens"}],"default":1}}]}}]}] |
    Then the resource creation response should indicate successful deployment
    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 200 with body:
      """
      {"x_testbench_reply":{"events":[{"choices":[{"delta":{"content":"Hello"}}]},{"usage":{"total_tokens":70}},{"usage":{"total_tokens":60}},"data: [DONE]"]}}
      """
    Then the response header "Content-Type" should contain "text/event-stream"
    And the response body should contain "Hello"
    And the response body should contain "data: [DONE]"
    And the response header "X-RateLimit-Limit" should be "100"

    # The last usage value (60) is the charge. Charging the first value (70) would leave 30 and
    # adding the values up (130) would exhaust the quota, so what remains tells the rules apart.
    # This stream reports the remaining quota and spends it, with a charge of exactly 40.
    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until header "X-RateLimit-Remaining" is "40" with body:
      """
      {"x_testbench_reply":{"events":[{"usage":{"total_tokens":40}},"data: [DONE]"]}}
      """
    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 429 with body:
      """
      {"x_testbench_reply":{"events":[{"choices":[{"delta":{"content":"Again"}}]},{"usage":{"total_tokens":1}},"data: [DONE]"]}}
      """
    Then the response body should contain "Rate limit exceeded"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful

  Scenario: A stream without a usage event is charged the default cost
    Given I generate a unique value from "arl-sse-default" and store it as "apiName"
    And I generate a unique API version from "arl-sse-default" and store it as "apiVersion"
    And I generate a unique API context from "/arl-sse-default" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}         |
      | name                   | ${CTX:apiName}                   |
      | spec.displayName       | ${CTX:apiName}                   |
      | spec.version           | ${CTX:apiVersion}                |
      | spec.context           | ${CTX:apiContext}/$version       |
      | spec.upstream.main.url | http://testbench:3008/scripted   |
      | spec.operations        | [{"method":"GET","path":"/get"},{"method":"POST","path":"/chat","policies":[{"name":"advanced-ratelimit","version":"v1","params":{"quotas":[{"name":"stream-default","limits":[{"limit":50,"duration":"1h"}],"costExtraction":{"enabled":true,"sources":[{"type":"response_body","jsonPath":"$.usage.total_tokens"}],"default":50}}]}}]}] |
    Then the resource creation response should indicate successful deployment
    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 200 with body:
      """
      {"x_testbench_reply":{"events":[{"choices":[{"delta":{"content":"No usage here"}}]},"data: [DONE]"]}}
      """
    Then the response header "Content-Type" should contain "text/event-stream"

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 429 with body:
      """
      {"x_testbench_reply":{"events":[{"choices":[{"delta":{"content":"Again"}}]},"data: [DONE]"]}}
      """
    Then the response body should contain "Rate limit exceeded"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful

  Scenario: A stream charged through a CEL expression over the response body
    Given I generate a unique value from "arl-sse-cel" and store it as "apiName"
    And I generate a unique API version from "arl-sse-cel" and store it as "apiVersion"
    And I generate a unique API context from "/arl-sse-cel" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}         |
      | name                   | ${CTX:apiName}                   |
      | spec.displayName       | ${CTX:apiName}                   |
      | spec.version           | ${CTX:apiVersion}                |
      | spec.context           | ${CTX:apiContext}/$version       |
      | spec.upstream.main.url | http://testbench:3008/scripted   |
      | spec.operations        | [{"method":"GET","path":"/get"},{"method":"POST","path":"/chat","policies":[{"name":"advanced-ratelimit","version":"v1","params":{"quotas":[{"name":"stream-cel","limits":[{"limit":20,"duration":"1h"}],"costExtraction":{"enabled":true,"sources":[{"type":"response_cel","expression":"20"}],"default":1}}]}}]}] |
    Then the resource creation response should indicate successful deployment
    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 200 with body:
      """
      {"x_testbench_reply":{"events":[{"choices":[{"delta":{"content":"cel"}}]},"data: [DONE]"]}}
      """
    Then the response header "Content-Type" should contain "text/event-stream"

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 429 with body:
      """
      {"x_testbench_reply":{"events":[{"choices":[{"delta":{"content":"Again"}}]},"data: [DONE]"]}}
      """
    Then the response body should contain "Rate limit exceeded"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
