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
Feature: Content length guardrail policy violation outcomes
  As an API developer
  I want a violation to stop the call and be recorded in analytics
  So that I can enforce content size constraints and protect my backend services

  # A blocked request never reaches the backend. A blocked response is replaced by the guardrail's
  # error. Either violation marks the analytics event as a guardrail hit. Response scenarios use the
  # LLM mock, which replies with the text the request scripts in x_testbench_reply.

  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"

  # The upstream records every request it receives. It records nothing for the blocked request,
  # and it records the allowed one sent next on the same path.
  Scenario: Trigger a request-side violation
    Given I resolve the "capture" service URL at "" and store it as "captureUpstream"
    And I generate a unique value from "clg-upstream" and store it as "apiName"
    And I generate a unique API version from "clg-upstream" and store it as "apiVersion"
    And I generate a unique API context from "/clg-upstream" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}        |
      | name                   | ${CTX:apiName}                   |
      | spec.displayName       | ${CTX:apiName}                   |
      | spec.version           | ${CTX:apiVersion}                |
      | spec.context           | ${CTX:apiContext}/$version       |
      | spec.upstream.main.url | ${CTX:captureUpstream} |
      | spec.operations        | [{"method":"GET","path":"/get"},{"method":"POST","path":"/clg-upstream-check","policies":[{"name":"content-length-guardrail","version":"v1","params":{"request":{"min":1,"max":5,"jsonPath":""}}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 200

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/clg-upstream-check" with body:
      """
      {"message":"this body is longer than five bytes"}
      """
    Then the response status code should be 422
    And the JSON response field "type" should be "CONTENT_LENGTH_GUARDRAIL"
    And the JSON response field "message.action" should be "GUARDRAIL_INTERVENED"
    And the JSON response field "message.direction" should be "REQUEST"
    When I send a "GET" request to the "capture" service at "/test/captured?path=/clg-upstream-check" until status 204

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/clg-upstream-check" with body:
      """
      abc
      """
    Then the response status code should be 200
    When I send a "GET" request to the "capture" service at "/test/captured?path=/clg-upstream-check" until status 200
    Then the response body should contain "/clg-upstream-check"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 404

  # The reply's content is longer than 10 bytes. The client gets the guardrail's error instead,
  # and none of the reply.
  Scenario: Trigger a response-side violation
    Given I generate a unique value from "clg-resp-violation" and store it as "apiName"
    And I generate a unique API version from "clg-resp-violation" and store it as "apiVersion"
    And I generate a unique API context from "/clg-resp-violation" and store it as "apiContext"
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
      {"messages":[{"role":"user","content":"hello"}],"x_testbench_reply":{"body":{"choices":[{"message":{"role":"assistant","content":"short"}}]}}}
      """

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" with body:
      """
      {"messages":[{"role":"user","content":"hello"}],"x_testbench_reply":{"body":{"choices":[{"message":{"role":"assistant","content":"this upstream reply is longer than ten bytes"}}]}}}
      """
    Then the response status code should be 422
    And the JSON response field "type" should be "CONTENT_LENGTH_GUARDRAIL"
    And the JSON response field "message.action" should be "GUARDRAIL_INTERVENED"
    And the JSON response field "message.direction" should be "RESPONSE"
    And the response body should not contain "this upstream reply"
    And the response should match the expected error response "content-length-guardrail-response-max"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 404

  # The gateway records a request the policy chain rejects under the API's context, without the
  # operation path.
  Scenario: Trigger any violation while analytics are enabled (request violation)
    Given I generate a unique value from "clg-analytics-req" and store it as "apiName"
    And I generate a unique API version from "clg-analytics-req" and store it as "apiVersion"
    And I generate a unique API context from "/clg-analytics-req" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}        |
      | name                   | ${CTX:apiName}                   |
      | spec.displayName       | ${CTX:apiName}                   |
      | spec.version           | ${CTX:apiVersion}                |
      | spec.context           | ${CTX:apiContext}/$version       |
      | spec.upstream.main.url | http://testbench:3000 |
      | spec.operations        | [{"method":"GET","path":"/get"},{"method":"POST","path":"/validate","policies":[{"name":"content-length-guardrail","version":"v1","params":{"request":{"min":1,"max":5,"jsonPath":""}}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 200

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/validate" with body:
      """
      {"message":"this body is longer than five bytes"}
      """
    Then the response status code should be 422
    And the latest analytics event for path "${CTX:apiContext}/${CTX:apiVersion}" should have metadata field "isGuardrailHit" with value "true"
    And the latest analytics event for path "${CTX:apiContext}/${CTX:apiVersion}" should have metadata field "guardrailName" with value "content-length-guardrail"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 404

  Scenario: Trigger any violation while analytics are enabled (response violation)
    Given I generate a unique value from "clg-analytics-resp" and store it as "apiName"
    And I generate a unique API version from "clg-analytics-resp" and store it as "apiVersion"
    And I generate a unique API context from "/clg-analytics-resp" and store it as "apiContext"
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
      {"messages":[{"role":"user","content":"hello"}],"x_testbench_reply":{"body":{"choices":[{"message":{"role":"assistant","content":"short"}}]}}}
      """

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" with body:
      """
      {"messages":[{"role":"user","content":"hello"}],"x_testbench_reply":{"body":{"choices":[{"message":{"role":"assistant","content":"this upstream reply is longer than ten bytes"}}]}}}
      """
    Then the response status code should be 422
    And the latest analytics event for path "${CTX:apiContext}/${CTX:apiVersion}/chat" should have metadata field "isGuardrailHit" with value "true"
    And the latest analytics event for path "${CTX:apiContext}/${CTX:apiVersion}/chat" should have metadata field "guardrailName" with value "content-length-guardrail"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 404
