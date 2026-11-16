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

@content-length-guardrail
Feature: Content length guardrail policy on streamed responses
  As an API developer
  I want the byte length of streamed responses to be validated as they arrive
  So that I can enforce content size constraints and protect my backend services

  # The LLM mock streams the events each request scripts in x_testbench_reply, flushing after each
  # one, so the gateway receives them as a stream. Non-streamed responses are in the other
  # content_length_guardrail feature files.

  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"

  # The reply must be 10 to 50 bytes. The deltas pass 10 bytes at the second event, 18 in all.
  Scenario: Receive a valid SSE response that reaches min but remains below or equal to max
    Given I generate a unique value from "clg-sse-in-range" and store it as "apiName"
    And I generate a unique API version from "clg-sse-in-range" and store it as "apiVersion"
    And I generate a unique API context from "/clg-sse-in-range" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}        |
      | name                   | ${CTX:apiName}                   |
      | spec.displayName       | ${CTX:apiName}                   |
      | spec.version           | ${CTX:apiVersion}                |
      | spec.context           | ${CTX:apiContext}/$version       |
      | spec.upstream.main.url | http://testbench:3008/scripted |
      | spec.operations        | [{"method":"GET","path":"/get"},{"method":"POST","path":"/chat","policies":[{"name":"content-length-guardrail","version":"v1","params":{"response":{"enabled":true,"min":10,"max":50}}}]}] |
    Then the resource creation response should indicate successful deployment
    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 200 with body:
      """
      {"x_testbench_reply":{"events":[{"choices":[{"delta":{"content":"Hello"}}]},{"choices":[{"delta":{"content":" stream"}}]},{"choices":[{"delta":{"content":" world"}}]},"data: [DONE]"]}}
      """
    Then the response status code should be 200
    And the response header "Content-Type" should contain "text/event-stream"
    And the response body should contain "Hello"
    And the response body should contain " stream"
    And the response body should contain " world"
    And the response body should contain "data: [DONE]"
    And the response body should not contain "CONTENT_LENGTH_GUARDRAIL"

    # The second delta takes the reply past 50 bytes, so the stream ends with the error event.
    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" with body:
      """
      {"x_testbench_reply":{"events":[{"choices":[{"delta":{"content":"Hello"}}]},{"choices":[{"delta":{"content":" This streamed reply is longer than fifty bytes in all."}}]},"data: [DONE]"]}}
      """
    Then the response status code should be 200
    And the response header "Content-Type" should contain "text/event-stream"
    And the response body should contain "GUARDRAIL_INTERVENED"
    And the response body should match pattern "CONTENT_LENGTH_GUARDRAIL.\}\s*$"
    And the response body should not contain "data: [DONE]"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 404

  # The reply may be 1 to 10 bytes. The third delta takes it to 28 bytes. The policy ends the
  # stream with the guardrail's error event, so the overflowing content, what follows it and
  # [DONE] never reach the client. This short stream usually reaches the gateway in one piece, so
  # the scenario does not check whether the earlier deltas reach the client first.
  Scenario: Receive an SSE response that exceeds max after streaming has started
    Given I generate a unique value from "clg-sse-over-max" and store it as "apiName"
    And I generate a unique API version from "clg-sse-over-max" and store it as "apiVersion"
    And I generate a unique API context from "/clg-sse-over-max" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}        |
      | name                   | ${CTX:apiName}                   |
      | spec.displayName       | ${CTX:apiName}                   |
      | spec.version           | ${CTX:apiVersion}                |
      | spec.context           | ${CTX:apiContext}/$version       |
      | spec.upstream.main.url | http://testbench:3008/scripted |
      | spec.operations        | [{"method":"GET","path":"/get"},{"method":"POST","path":"/chat","policies":[{"name":"content-length-guardrail","version":"v1","params":{"response":{"enabled":true,"min":1,"max":10}}}]}] |
    Then the resource creation response should indicate successful deployment
    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 200 with body:
      """
      {"x_testbench_reply":{"events":[{"choices":[{"delta":{"content":"abcd"}}]},{"choices":[{"delta":{"content":"efgh"}}]},{"choices":[{"delta":{"content":"OVERFLOWING-PAST-TEN"}}]},{"choices":[{"delta":{"content":"after-the-overflow"}}]},"data: [DONE]"]}}
      """
    Then the response status code should be 200
    And the response header "Content-Type" should contain "text/event-stream"
    And the response body should contain "GUARDRAIL_INTERVENED"
    And the response body should match pattern "CONTENT_LENGTH_GUARDRAIL.\}\s*$"
    And the response body should not contain "data: [DONE]"
    And the response body should not contain "OVERFLOWING-PAST-TEN"
    And the response body should not contain "after-the-overflow"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 404

  # The reply must be at least 50 bytes, and the stream ends at 11.
  @known-issue
  Scenario: Receive [DONE] before the minimum is reached
    Given I generate a unique value from "clg-sse-below-min" and store it as "apiName"
    And I generate a unique API version from "clg-sse-below-min" and store it as "apiVersion"
    And I generate a unique API context from "/clg-sse-below-min" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}        |
      | name                   | ${CTX:apiName}                   |
      | spec.displayName       | ${CTX:apiName}                   |
      | spec.version           | ${CTX:apiVersion}                |
      | spec.context           | ${CTX:apiContext}/$version       |
      | spec.upstream.main.url | http://testbench:3008/scripted |
      | spec.operations        | [{"method":"GET","path":"/get"},{"method":"POST","path":"/chat","policies":[{"name":"content-length-guardrail","version":"v1","params":{"response":{"enabled":true,"min":50,"max":100}}}]}] |
    Then the resource creation response should indicate successful deployment
    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 200 with body:
      """
      {"x_testbench_reply":{"events":[{"choices":[{"delta":{"content":"short"}}]},{"choices":[{"delta":{"content":" reply"}}]},"data: [DONE]"]}}
      """
    Then the response status code should be 200
    And the response header "Content-Type" should contain "text/event-stream"
    And the response body should contain "GUARDRAIL_INTERVENED"
    And the response body should match pattern "CONTENT_LENGTH_GUARDRAIL.\}\s*$"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 404

  # The reply must be at least 5 bytes, and the stream ends at 11.
  Scenario: Receive [DONE] after the minimum is reached
    Given I generate a unique value from "clg-sse-done-after-min" and store it as "apiName"
    And I generate a unique API version from "clg-sse-done-after-min" and store it as "apiVersion"
    And I generate a unique API context from "/clg-sse-done-after-min" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}        |
      | name                   | ${CTX:apiName}                   |
      | spec.displayName       | ${CTX:apiName}                   |
      | spec.version           | ${CTX:apiVersion}                |
      | spec.context           | ${CTX:apiContext}/$version       |
      | spec.upstream.main.url | http://testbench:3008/scripted |
      | spec.operations        | [{"method":"GET","path":"/get"},{"method":"POST","path":"/chat","policies":[{"name":"content-length-guardrail","version":"v1","params":{"response":{"enabled":true,"min":5,"max":100}}}]}] |
    Then the resource creation response should indicate successful deployment
    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 200 with body:
      """
      {"x_testbench_reply":{"events":[{"choices":[{"delta":{"content":"Hello"}}]},{"choices":[{"delta":{"content":" again"}}]},"data: [DONE]"]}}
      """
    Then the response status code should be 200
    And the response header "Content-Type" should contain "text/event-stream"
    And the response body should contain "Hello"
    And the response body should contain " again"
    And the response body should contain "data: [DONE]"
    And the response body should not contain "CONTENT_LENGTH_GUARDRAIL"

    # A 104-byte delta is over the maximum of 100, so the stream ends with the error event.
    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" with body:
      """
      {"x_testbench_reply":{"events":[{"choices":[{"delta":{"content":"This streamed reply keeps going well past the one hundred byte maximum that this operation allows today."}}]},"data: [DONE]"]}}
      """
    Then the response status code should be 200
    And the response header "Content-Type" should contain "text/event-stream"
    And the response body should contain "GUARDRAIL_INTERVENED"
    And the response body should match pattern "CONTENT_LENGTH_GUARDRAIL.\}\s*$"
    And the response body should not contain "data: [DONE]"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 404

  # Each event carries a short delta.text and a long decoy at the default streaming path. Only
  # the 9 bytes of delta.text are measured against 1 to 10 bytes.
  Scenario: Configure a custom streaming JSONPath
    Given I generate a unique value from "clg-sse-custom-path" and store it as "apiName"
    And I generate a unique API version from "clg-sse-custom-path" and store it as "apiVersion"
    And I generate a unique API context from "/clg-sse-custom-path" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}        |
      | name                   | ${CTX:apiName}                   |
      | spec.displayName       | ${CTX:apiName}                   |
      | spec.version           | ${CTX:apiVersion}                |
      | spec.context           | ${CTX:apiContext}/$version       |
      | spec.upstream.main.url | http://testbench:3008/scripted |
      | spec.operations        | [{"method":"GET","path":"/get"},{"method":"POST","path":"/chat","policies":[{"name":"content-length-guardrail","version":"v1","params":{"response":{"enabled":true,"min":1,"max":10,"streamingJsonPath":"$.delta.text"}}}]}] |
    Then the resource creation response should indicate successful deployment
    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 200 with body:
      """
      {"x_testbench_reply":{"events":[{"delta":{"text":"short"},"choices":[{"delta":{"content":"this decoy content is far longer than ten bytes"}}]},{"delta":{"text":"text"},"choices":[{"delta":{"content":"another decoy far longer than ten bytes"}}]},"data: [DONE]"]}}
      """
    Then the response status code should be 200
    And the response header "Content-Type" should contain "text/event-stream"
    And the response body should contain "short"
    And the response body should contain "data: [DONE]"
    And the response body should not contain "CONTENT_LENGTH_GUARDRAIL"

    # The delta.text alone is over 10 bytes, so the stream ends with the error event.
    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" with body:
      """
      {"x_testbench_reply":{"events":[{"delta":{"text":"this text is longer than ten bytes"},"choices":[{"delta":{"content":"x"}}]},"data: [DONE]"]}}
      """
    Then the response status code should be 200
    And the response header "Content-Type" should contain "text/event-stream"
    And the response body should contain "GUARDRAIL_INTERVENED"
    And the response body should match pattern "CONTENT_LENGTH_GUARDRAIL.\}\s*$"
    And the response body should not contain "data: [DONE]"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 404

  # The reply must be 10 to 20 bytes. No fragment reaches 10 bytes alone; together they are 10.
  Scenario: Receive multiple SSE content fragments
    Given I generate a unique value from "clg-sse-fragments" and store it as "apiName"
    And I generate a unique API version from "clg-sse-fragments" and store it as "apiVersion"
    And I generate a unique API context from "/clg-sse-fragments" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}        |
      | name                   | ${CTX:apiName}                   |
      | spec.displayName       | ${CTX:apiName}                   |
      | spec.version           | ${CTX:apiVersion}                |
      | spec.context           | ${CTX:apiContext}/$version       |
      | spec.upstream.main.url | http://testbench:3008/scripted |
      | spec.operations        | [{"method":"GET","path":"/get"},{"method":"POST","path":"/chat","policies":[{"name":"content-length-guardrail","version":"v1","params":{"response":{"enabled":true,"min":10,"max":20}}}]}] |
    Then the resource creation response should indicate successful deployment
    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 200 with body:
      """
      {"x_testbench_reply":{"events":[{"choices":[{"delta":{"content":"abcd"}}]},{"choices":[{"delta":{"content":"efgh"}}]},{"choices":[{"delta":{"content":"ij"}}]},"data: [DONE]"]}}
      """
    Then the response status code should be 200
    And the response header "Content-Type" should contain "text/event-stream"
    And the response body should contain "abcd"
    And the response body should contain "efgh"
    And the response body should contain "ij"
    And the response body should contain "data: [DONE]"
    And the response body should not contain "CONTENT_LENGTH_GUARDRAIL"

    # No fragment passes 20 bytes alone; together they are 24, so the stream ends with the error event.
    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" with body:
      """
      {"x_testbench_reply":{"events":[{"choices":[{"delta":{"content":"abcdefgh"}}]},{"choices":[{"delta":{"content":"ijklmnop"}}]},{"choices":[{"delta":{"content":"qrstuvwx"}}]},"data: [DONE]"]}}
      """
    Then the response status code should be 200
    And the response header "Content-Type" should contain "text/event-stream"
    And the response body should contain "GUARDRAIL_INTERVENED"
    And the response body should match pattern "CONTENT_LENGTH_GUARDRAIL.\}\s*$"
    And the response body should not contain "data: [DONE]"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 404

  # The first event has an empty content. The deltas after it are exactly the 10-byte maximum.
  Scenario: Receive an SSE initialization event with empty content
    Given I generate a unique value from "clg-sse-init-event" and store it as "apiName"
    And I generate a unique API version from "clg-sse-init-event" and store it as "apiVersion"
    And I generate a unique API context from "/clg-sse-init-event" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}        |
      | name                   | ${CTX:apiName}                   |
      | spec.displayName       | ${CTX:apiName}                   |
      | spec.version           | ${CTX:apiVersion}                |
      | spec.context           | ${CTX:apiContext}/$version       |
      | spec.upstream.main.url | http://testbench:3008/scripted |
      | spec.operations        | [{"method":"GET","path":"/get"},{"method":"POST","path":"/chat","policies":[{"name":"content-length-guardrail","version":"v1","params":{"response":{"enabled":true,"min":1,"max":10}}}]}] |
    Then the resource creation response should indicate successful deployment
    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 200 with body:
      """
      {"x_testbench_reply":{"events":[{"choices":[{"delta":{"role":"assistant","content":""}}]},{"choices":[{"delta":{"content":"abcde"}}]},{"choices":[{"delta":{"content":"fghij"}}]},"data: [DONE]"]}}
      """
    Then the response status code should be 200
    And the response header "Content-Type" should contain "text/event-stream"
    And the response body should contain "abcde"
    And the response body should contain "fghij"
    And the response body should contain "data: [DONE]"
    And the response body should not contain "CONTENT_LENGTH_GUARDRAIL"

    # One more byte of content, 11 in all, takes the reply over the maximum.
    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" with body:
      """
      {"x_testbench_reply":{"events":[{"choices":[{"delta":{"role":"assistant","content":""}}]},{"choices":[{"delta":{"content":"abcde"}}]},{"choices":[{"delta":{"content":"fghijk"}}]},"data: [DONE]"]}}
      """
    Then the response status code should be 200
    And the response header "Content-Type" should contain "text/event-stream"
    And the response body should contain "GUARDRAIL_INTERVENED"
    And the response body should match pattern "CONTENT_LENGTH_GUARDRAIL.\}\s*$"
    And the response body should not contain "data: [DONE]"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 404

  # A data line that is not JSON is counted as content as it stands, so its 28 bytes take the
  # reply past the 20-byte maximum.
  Scenario: Receive malformed SSE data or a missing streaming JSONPath (malformed data line)
    Given I generate a unique value from "clg-sse-malformed" and store it as "apiName"
    And I generate a unique API version from "clg-sse-malformed" and store it as "apiVersion"
    And I generate a unique API context from "/clg-sse-malformed" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}        |
      | name                   | ${CTX:apiName}                   |
      | spec.displayName       | ${CTX:apiName}                   |
      | spec.version           | ${CTX:apiVersion}                |
      | spec.context           | ${CTX:apiContext}/$version       |
      | spec.upstream.main.url | http://testbench:3008/scripted |
      | spec.operations        | [{"method":"GET","path":"/get"},{"method":"POST","path":"/chat","policies":[{"name":"content-length-guardrail","version":"v1","params":{"response":{"enabled":true,"min":1,"max":20}}}]}] |
    Then the resource creation response should indicate successful deployment
    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 200 with body:
      """
      {"x_testbench_reply":{"events":[{"choices":[{"delta":{"content":"abc"}}]},"data: this line is not json at all","data: [DONE]"]}}
      """
    Then the response status code should be 200
    And the response header "Content-Type" should contain "text/event-stream"
    And the response body should contain "GUARDRAIL_INTERVENED"
    And the response body should match pattern "CONTENT_LENGTH_GUARDRAIL.\}\s*$"
    And the response body should not contain "data: [DONE]"

    # The same route still streams a well-formed reply.
    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 200 with body:
      """
      {"x_testbench_reply":{"events":[{"choices":[{"delta":{"content":"abc"}}]},"data: [DONE]"]}}
      """
    Then the response status code should be 200
    And the response header "Content-Type" should contain "text/event-stream"
    And the response body should contain "abc"
    And the response body should contain "data: [DONE]"
    And the response body should not contain "CONTENT_LENGTH_GUARDRAIL"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 404

  # An event without the streaming path is counted as its whole JSON text, so its 44 bytes take
  # the reply past the 20-byte maximum.
  Scenario: Receive malformed SSE data or a missing streaming JSONPath (event without the streaming path)
    Given I generate a unique value from "clg-sse-no-path" and store it as "apiName"
    And I generate a unique API version from "clg-sse-no-path" and store it as "apiVersion"
    And I generate a unique API context from "/clg-sse-no-path" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}        |
      | name                   | ${CTX:apiName}                   |
      | spec.displayName       | ${CTX:apiName}                   |
      | spec.version           | ${CTX:apiVersion}                |
      | spec.context           | ${CTX:apiContext}/$version       |
      | spec.upstream.main.url | http://testbench:3008/scripted |
      | spec.operations        | [{"method":"GET","path":"/get"},{"method":"POST","path":"/chat","policies":[{"name":"content-length-guardrail","version":"v1","params":{"response":{"enabled":true,"min":1,"max":20}}}]}] |
    Then the resource creation response should indicate successful deployment
    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 200 with body:
      """
      {"x_testbench_reply":{"events":[{"choices":[{"delta":{"content":"abc"}}]},{"choices":[{"delta":{"role":"assistant"}}]},"data: [DONE]"]}}
      """
    Then the response status code should be 200
    And the response header "Content-Type" should contain "text/event-stream"
    And the response body should contain "GUARDRAIL_INTERVENED"
    And the response body should match pattern "CONTENT_LENGTH_GUARDRAIL.\}\s*$"
    And the response body should not contain "data: [DONE]"

    # The same route still streams a well-formed reply.
    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 200 with body:
      """
      {"x_testbench_reply":{"events":[{"choices":[{"delta":{"content":"abc"}}]},"data: [DONE]"]}}
      """
    Then the response status code should be 200
    And the response header "Content-Type" should contain "text/event-stream"
    And the response body should contain "abc"
    And the response body should contain "data: [DONE]"
    And the response body should not contain "CONTENT_LENGTH_GUARDRAIL"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 404

  # The mock writes the JSON reply in two flushed parts, so it arrives chunked. Its 5-byte
  # content is within 1 to 10 bytes.
  Scenario: Receive a chunked, non-SSE response within the configured range
    Given I generate a unique value from "clg-chunked-in-range" and store it as "apiName"
    And I generate a unique API version from "clg-chunked-in-range" and store it as "apiVersion"
    And I generate a unique API context from "/clg-chunked-in-range" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}        |
      | name                   | ${CTX:apiName}                   |
      | spec.displayName       | ${CTX:apiName}                   |
      | spec.version           | ${CTX:apiVersion}                |
      | spec.context           | ${CTX:apiContext}/$version       |
      | spec.upstream.main.url | http://testbench:3008/scripted |
      | spec.operations        | [{"method":"GET","path":"/get"},{"method":"POST","path":"/chat","policies":[{"name":"content-length-guardrail","version":"v1","params":{"response":{"enabled":true,"min":1,"max":10}}}]}] |
    Then the resource creation response should indicate successful deployment
    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 200 with body:
      """
      {"x_testbench_reply":{"events":["{\"choices\":[{\"message\":","{\"role\":\"assistant\",\"content\":\"hello\"}}]}"],"contentType":"application/json"}}
      """
    Then the response status code should be 200
    And the JSON response field "choices[0].message.content" should be "hello"
    And the response body should not contain "CONTENT_LENGTH_GUARDRAIL"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 404

  # The same chunked reply with content longer than 10 bytes. The status is already sent, so the
  # response keeps it and ends with the guardrail's JSON error.
  @known-issue
  Scenario: Receive a chunked, non-SSE response outside the configured range
    Given I generate a unique value from "clg-chunked-over-max" and store it as "apiName"
    And I generate a unique API version from "clg-chunked-over-max" and store it as "apiVersion"
    And I generate a unique API context from "/clg-chunked-over-max" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}        |
      | name                   | ${CTX:apiName}                   |
      | spec.displayName       | ${CTX:apiName}                   |
      | spec.version           | ${CTX:apiVersion}                |
      | spec.context           | ${CTX:apiContext}/$version       |
      | spec.upstream.main.url | http://testbench:3008/scripted |
      | spec.operations        | [{"method":"GET","path":"/get"},{"method":"POST","path":"/chat","policies":[{"name":"content-length-guardrail","version":"v1","params":{"response":{"enabled":true,"min":1,"max":10}}}]}] |
    Then the resource creation response should indicate successful deployment
    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 200 with body:
      """
      {"x_testbench_reply":{"events":["{\"choices\":[{\"message\":","{\"role\":\"assistant\",\"content\":\"this content is longer than ten bytes\"}}]}"],"contentType":"application/json"}}
      """
    Then the response status code should be 200
    And the response body should contain "GUARDRAIL_INTERVENED"
    And the response body should match pattern "CONTENT_LENGTH_GUARDRAIL.\}\s*$"
    And the response body should not contain "this content is longer than ten bytes"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 404

  # The excluded range is 1 to 10 bytes. The reply is held back until it passes 10 bytes, at the
  # second delta, and then released. It is 18 bytes in all.
  Scenario: Use invert mode for an SSE response that eventually exceeds max
    Given I generate a unique value from "clg-sse-invert-over" and store it as "apiName"
    And I generate a unique API version from "clg-sse-invert-over" and store it as "apiVersion"
    And I generate a unique API context from "/clg-sse-invert-over" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}        |
      | name                   | ${CTX:apiName}                   |
      | spec.displayName       | ${CTX:apiName}                   |
      | spec.version           | ${CTX:apiVersion}                |
      | spec.context           | ${CTX:apiContext}/$version       |
      | spec.upstream.main.url | http://testbench:3008/scripted |
      | spec.operations        | [{"method":"GET","path":"/get"},{"method":"POST","path":"/chat","policies":[{"name":"content-length-guardrail","version":"v1","params":{"response":{"enabled":true,"min":1,"max":10,"invert":true}}}]}] |
    Then the resource creation response should indicate successful deployment
    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 200 with body:
      """
      {"x_testbench_reply":{"events":[{"choices":[{"delta":{"content":"abcdef"}}]},{"choices":[{"delta":{"content":"ghijkl"}}]},{"choices":[{"delta":{"content":"mnopqr"}}]},"data: [DONE]"]}}
      """
    Then the response status code should be 200
    And the response header "Content-Type" should contain "text/event-stream"
    And the response body should contain "abcdef"
    And the response body should contain "ghijkl"
    And the response body should contain "mnopqr"
    And the response body should contain "data: [DONE]"
    And the response body should not contain "CONTENT_LENGTH_GUARDRAIL"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 404

  # The excluded range is 1 to 10 bytes, and the stream ends at 5.
  @known-issue
  Scenario: Use invert mode and finish the SSE stream inside the denied range
    Given I generate a unique value from "clg-sse-invert-inside" and store it as "apiName"
    And I generate a unique API version from "clg-sse-invert-inside" and store it as "apiVersion"
    And I generate a unique API context from "/clg-sse-invert-inside" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}        |
      | name                   | ${CTX:apiName}                   |
      | spec.displayName       | ${CTX:apiName}                   |
      | spec.version           | ${CTX:apiVersion}                |
      | spec.context           | ${CTX:apiContext}/$version       |
      | spec.upstream.main.url | http://testbench:3008/scripted |
      | spec.operations        | [{"method":"GET","path":"/get"},{"method":"POST","path":"/chat","policies":[{"name":"content-length-guardrail","version":"v1","params":{"response":{"enabled":true,"min":1,"max":10,"invert":true}}}]}] |
    Then the resource creation response should indicate successful deployment
    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 200 with body:
      """
      {"x_testbench_reply":{"events":[{"choices":[{"delta":{"content":"abc"}}]},{"choices":[{"delta":{"content":"de"}}]},"data: [DONE]"]}}
      """
    Then the response status code should be 200
    And the response header "Content-Type" should contain "text/event-stream"
    And the response body should contain "GUARDRAIL_INTERVENED"
    And the response body should match pattern "CONTENT_LENGTH_GUARDRAIL.\}\s*$"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 404

  # The first delta takes the reply past its 5-byte maximum. The analytics event should record
  # the guardrail hit, as it does for request and buffered response violations.
  @known-issue
  Scenario: Trigger any violation while analytics are enabled (streamed response violation)
    Given I generate a unique value from "clg-sse-analytics" and store it as "apiName"
    And I generate a unique API version from "clg-sse-analytics" and store it as "apiVersion"
    And I generate a unique API context from "/clg-sse-analytics" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}        |
      | name                   | ${CTX:apiName}                   |
      | spec.displayName       | ${CTX:apiName}                   |
      | spec.version           | ${CTX:apiVersion}                |
      | spec.context           | ${CTX:apiContext}/$version       |
      | spec.upstream.main.url | http://testbench:3008/scripted |
      | spec.operations        | [{"method":"GET","path":"/get"},{"method":"POST","path":"/chat","policies":[{"name":"content-length-guardrail","version":"v1","params":{"response":{"enabled":true,"min":1,"max":5}}}]}] |
    Then the resource creation response should indicate successful deployment
    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 200 with body:
      """
      {"x_testbench_reply":{"events":[{"choices":[{"delta":{"content":"this delta is longer than five bytes"}}]},"data: [DONE]"]}}
      """
    Then the response status code should be 200
    And the response header "Content-Type" should contain "text/event-stream"
    And the response body should contain "GUARDRAIL_INTERVENED"
    # The policy sets no analytics metadata when it ends a stream, so the event has no
    # isGuardrailHit field.
    And the latest analytics event for path "${CTX:apiContext}/${CTX:apiVersion}/chat" should have metadata field "isGuardrailHit" with value "true"
    And the latest analytics event for path "${CTX:apiContext}/${CTX:apiVersion}/chat" should have metadata field "guardrailName" with value "content-length-guardrail"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 404
