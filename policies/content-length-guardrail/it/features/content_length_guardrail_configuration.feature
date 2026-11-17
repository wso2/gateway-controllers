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
Feature: Content length guardrail policy configuration
  As an API developer
  I want each side of a call to be checked only as configured
  So that I can enforce content size constraints and protect my backend services

  # Scenarios that check responses use the LLM mock, which answers each request with the reply it
  # scripts in x_testbench_reply.

  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"

  # The request is measured at the default request path, the last message's content, which is 5
  # to 20 bytes here. Each request has two messages, and only the last one is in range for the
  # allowed request and out of range for the blocked one. The LLM mock replies with the text the
  # request scripts in x_testbench_reply. The reply is far longer than 20 bytes and still reaches
  # the client, so responses are not checked.
  Scenario: Configure only request validation
    Given I generate a unique value from "clg-req-only" and store it as "apiName"
    And I generate a unique API version from "clg-req-only" and store it as "apiVersion"
    And I generate a unique API context from "/clg-req-only" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}        |
      | name                   | ${CTX:apiName}                   |
      | spec.displayName       | ${CTX:apiName}                   |
      | spec.version           | ${CTX:apiVersion}                |
      | spec.context           | ${CTX:apiContext}/$version       |
      | spec.upstream.main.url | http://testbench:3008/scripted |
      | spec.operations        | [{"method":"GET","path":"/get"},{"method":"POST","path":"/chat","policies":[{"name":"content-length-guardrail","version":"v1","params":{"request":{"min":5,"max":20}}}]}] |
    Then the resource creation response should indicate successful deployment
    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 200 with body:
      """
      {"messages":[{"role":"user","content":"hi"},{"role":"user","content":"hello world"}],"x_testbench_reply":{"body":{"choices":[{"message":{"role":"assistant","content":"This reply is far longer than the twenty bytes the request may have."}}]}}}
      """
    And the response body should contain "This reply is far longer than the twenty bytes the request may have."

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" with body:
      """
      {"messages":[{"role":"user","content":"hello world"},{"role":"user","content":"hi"}],"x_testbench_reply":{"body":{"choices":[{"message":{"role":"assistant","content":"ok"}}]}}}
      """
    Then the response status code should be 422
    And the JSON response field "type" should be "CONTENT_LENGTH_GUARDRAIL"
    And the JSON response field "message.action" should be "GUARDRAIL_INTERVENED"
    And the JSON response field "message.direction" should be "REQUEST"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 404

  # The reply is measured at the default response path, the first choice's message content, which
  # is 5 to 20 bytes here. A request message far longer than 20 bytes is not checked.
  Scenario: Configure only response validation
    Given I generate a unique value from "clg-resp-only" and store it as "apiName"
    And I generate a unique API version from "clg-resp-only" and store it as "apiVersion"
    And I generate a unique API context from "/clg-resp-only" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}        |
      | name                   | ${CTX:apiName}                   |
      | spec.displayName       | ${CTX:apiName}                   |
      | spec.version           | ${CTX:apiVersion}                |
      | spec.context           | ${CTX:apiContext}/$version       |
      | spec.upstream.main.url | http://testbench:3008/scripted |
      | spec.operations        | [{"method":"GET","path":"/get"},{"method":"POST","path":"/chat","policies":[{"name":"content-length-guardrail","version":"v1","params":{"response":{"enabled":true,"min":5,"max":20}}}]}] |
    Then the resource creation response should indicate successful deployment
    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 200 with body:
      """
      {"messages":[{"role":"user","content":"This request message is far longer than twenty bytes and is not checked."}],"x_testbench_reply":{"body":{"choices":[{"message":{"role":"assistant","content":"hello world"}}]}}}
      """
    And the response body should contain "hello world"

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" with body:
      """
      {"messages":[{"role":"user","content":"hello world"}],"x_testbench_reply":{"body":{"choices":[{"message":{"role":"assistant","content":"This reply is far longer than the twenty bytes allowed."}}]}}}
      """
    Then the response status code should be 422
    And the JSON response field "type" should be "CONTENT_LENGTH_GUARDRAIL"
    And the JSON response field "message.action" should be "GUARDRAIL_INTERVENED"
    And the JSON response field "message.direction" should be "RESPONSE"
    And the response body should not contain "This reply is far longer"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 404

  # Both sides allow 5 to 20 bytes. Each side is rejected on its own, with its own direction.
  # The request side measures only the last of two messages.
  Scenario: Configure both request and response validation
    Given I generate a unique value from "clg-both" and store it as "apiName"
    And I generate a unique API version from "clg-both" and store it as "apiVersion"
    And I generate a unique API context from "/clg-both" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}        |
      | name                   | ${CTX:apiName}                   |
      | spec.displayName       | ${CTX:apiName}                   |
      | spec.version           | ${CTX:apiVersion}                |
      | spec.context           | ${CTX:apiContext}/$version       |
      | spec.upstream.main.url | http://testbench:3008/scripted |
      | spec.operations        | [{"method":"GET","path":"/get"},{"method":"POST","path":"/chat","policies":[{"name":"content-length-guardrail","version":"v1","params":{"request":{"min":5,"max":20},"response":{"enabled":true,"min":5,"max":20}}}]}] |
    Then the resource creation response should indicate successful deployment
    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 200 with body:
      """
      {"messages":[{"role":"user","content":"This request message is longer than twenty bytes."},{"role":"user","content":"hello world"}],"x_testbench_reply":{"body":{"choices":[{"message":{"role":"assistant","content":"hello there"}}]}}}
      """
    And the response body should contain "hello there"

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" with body:
      """
      {"messages":[{"role":"user","content":"hello world"},{"role":"user","content":"This request message is longer than twenty bytes."}],"x_testbench_reply":{"body":{"choices":[{"message":{"role":"assistant","content":"hello there"}}]}}}
      """
    Then the response status code should be 422
    And the JSON response field "type" should be "CONTENT_LENGTH_GUARDRAIL"
    And the JSON response field "message.action" should be "GUARDRAIL_INTERVENED"
    And the JSON response field "message.direction" should be "REQUEST"

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" with body:
      """
      {"messages":[{"role":"user","content":"hello world"}],"x_testbench_reply":{"body":{"choices":[{"message":{"role":"assistant","content":"This reply is longer than twenty bytes."}}]}}}
      """
    Then the response status code should be 422
    And the JSON response field "type" should be "CONTENT_LENGTH_GUARDRAIL"
    And the JSON response field "message.action" should be "GUARDRAIL_INTERVENED"
    And the JSON response field "message.direction" should be "RESPONSE"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 404

  # The whole body is measured against 0 to 10 bytes. A 7-byte body passes and a 16-byte body is
  # blocked.
  Scenario: Configure min=0 and a positive max
    Given I generate a unique value from "clg-min-zero" and store it as "apiName"
    And I generate a unique API version from "clg-min-zero" and store it as "apiVersion"
    And I generate a unique API context from "/clg-min-zero" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}        |
      | name                   | ${CTX:apiName}                   |
      | spec.displayName       | ${CTX:apiName}                   |
      | spec.version           | ${CTX:apiVersion}                |
      | spec.context           | ${CTX:apiContext}/$version       |
      | spec.upstream.main.url | http://testbench:3000 |
      | spec.operations        | [{"method":"GET","path":"/get"},{"method":"POST","path":"/validate","policies":[{"name":"content-length-guardrail","version":"v1","params":{"request":{"min":0,"max":10,"jsonPath":""}}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 200

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/validate" with body:
      """
      {"a":1}
      """
    Then the response status code should be 200

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/validate" with body:
      """
      {"a":"too long"}
      """
    Then the response status code should be 422
    And the JSON response field "type" should be "CONTENT_LENGTH_GUARDRAIL"
    And the JSON response field "message.direction" should be "REQUEST"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 404

  # The body has no messages field, so the default request path could not be read if the request
  # were checked.
  Scenario: Disable a path without supplying min and max
    Given I generate a unique value from "clg-disabled" and store it as "apiName"
    And I generate a unique API version from "clg-disabled" and store it as "apiVersion"
    And I generate a unique API context from "/clg-disabled" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}        |
      | name                   | ${CTX:apiName}                   |
      | spec.displayName       | ${CTX:apiName}                   |
      | spec.version           | ${CTX:apiVersion}                |
      | spec.context           | ${CTX:apiContext}/$version       |
      | spec.upstream.main.url | http://testbench:3000 |
      | spec.operations        | [{"method":"GET","path":"/get"},{"method":"POST","path":"/validate","policies":[{"name":"content-length-guardrail","version":"v1","params":{"request":{"enabled":false}}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 200

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/validate" with body:
      """
      {"note":"no messages field"}
      """
    Then the response status code should be 200

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 404

  # The disabled request side has a minimum above its maximum, which an enabled side may not have.
  # The request is not checked, and the response side still is: 5 to 20 bytes.
  Scenario: Disable a path while supplying otherwise invalid range values
    Given I generate a unique value from "clg-disabled-range" and store it as "apiName"
    And I generate a unique API version from "clg-disabled-range" and store it as "apiVersion"
    And I generate a unique API context from "/clg-disabled-range" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}        |
      | name                   | ${CTX:apiName}                   |
      | spec.displayName       | ${CTX:apiName}                   |
      | spec.version           | ${CTX:apiVersion}                |
      | spec.context           | ${CTX:apiContext}/$version       |
      | spec.upstream.main.url | http://testbench:3008/scripted |
      | spec.operations        | [{"method":"GET","path":"/get"},{"method":"POST","path":"/chat","policies":[{"name":"content-length-guardrail","version":"v1","params":{"request":{"enabled":false,"min":100,"max":10},"response":{"enabled":true,"min":5,"max":20}}}]}] |
    Then the resource creation response should indicate successful deployment
    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 200 with body:
      """
      {"messages":[{"role":"user","content":"This request message is far longer than the ten-byte maximum of the disabled request side."}],"x_testbench_reply":{"body":{"choices":[{"message":{"role":"assistant","content":"hello world"}}]}}}
      """
    And the response body should contain "hello world"

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" with body:
      """
      {"messages":[{"role":"user","content":"hello"}],"x_testbench_reply":{"body":{"choices":[{"message":{"role":"assistant","content":"This reply is longer than twenty bytes."}}]}}}
      """
    Then the response status code should be 422
    And the JSON response field "type" should be "CONTENT_LENGTH_GUARDRAIL"
    And the JSON response field "message.action" should be "GUARDRAIL_INTERVENED"
    And the JSON response field "message.direction" should be "RESPONSE"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 404

  # The 63-byte body is outside the excluded range of 20 to 50 bytes.
  Scenario: Enable invert mode and send content longer than max
    Given I generate a unique value from "clg-invert-long" and store it as "apiName"
    And I generate a unique API version from "clg-invert-long" and store it as "apiVersion"
    And I generate a unique API context from "/clg-invert-long" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}        |
      | name                   | ${CTX:apiName}                   |
      | spec.displayName       | ${CTX:apiName}                   |
      | spec.version           | ${CTX:apiVersion}                |
      | spec.context           | ${CTX:apiContext}/$version       |
      | spec.upstream.main.url | http://testbench:3000 |
      | spec.operations        | [{"method":"GET","path":"/get"},{"method":"POST","path":"/validate","policies":[{"name":"content-length-guardrail","version":"v1","params":{"request":{"min":20,"max":50,"jsonPath":"","invert":true}}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 200

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/validate" with body:
      """
      {"message":"this body is longer than the fifty bytes excluded"}
      """
    Then the response status code should be 200

    # A 30-byte body falls inside the excluded range and is blocked.
    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/validate" with body:
      """
      {"msg":"inside the window ok"}
      """
    Then the response status code should be 422
    And the JSON response field "type" should be "CONTENT_LENGTH_GUARDRAIL"
    And the JSON response field "message.direction" should be "REQUEST"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 404
