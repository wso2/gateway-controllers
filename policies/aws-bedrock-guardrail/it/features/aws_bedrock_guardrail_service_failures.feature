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

@aws-bedrock-guardrail
Feature: AWS Bedrock guardrail policy when AWS Bedrock fails
  As an API developer
  I want to choose whether a request passes when the guardrail cannot decide it
  So that a Bedrock failure is handled the way the API is configured

  # Each API forwards to a capture service that records what reaches it. The Bedrock mock blocks
  # violence, "investment advice", "contraband" and "secret recipe", finds example.com emails,
  # phone numbers and SSNs as PII, and answers only requests signed with a fixture credential.

  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"
    And I resolve the "capture" service URL at "" and store it as "captureUpstream"

  # The mock fails the call for "simulate ... error" (500) and "simulate ... outage" (503), so the
  # prohibited content in the same message is let through.
  Scenario Outline: Enable passthroughOnError and make AWS Bedrock Guardrails unavailable or return an error (<case>)
    Given I generate a unique value from "bedrock-passthrough-failure" and store it as "apiName"
    And I generate a unique API version from "bedrock-passthrough-failure" and store it as "apiVersion"
    And I generate a unique API context from "/bedrock-passthrough-failure" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}                  |
      | name                   | ${CTX:apiName}                             |
      | spec.displayName       | ${CTX:apiName}                             |
      | spec.version           | ${CTX:apiVersion}                          |
      | spec.context           | ${CTX:apiContext}/$version                 |
      | spec.upstream.main.url | ${CTX:captureUpstream}/${CTX:apiName}      |
      | spec.operations        | [{"method":"POST","path":"/chat","policies":[{"name":"aws-bedrock-guardrail","version":"v1","params":{"region":"us-east-1","guardrailID":"test-guardrail-id","guardrailVersion":"DRAFT","awsAuth":{"authenticationType":"iam-user-access-key","awsAccessKeyID":"AKIATESTPERMANENT001","awsSecretAccessKey":"testPermanentSecretAccessKey000000000001"},<phase>}}]}] |
    Then the resource creation response should indicate successful deployment

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 200 with body:
      """
      {"messages":[{"role":"user","content":"<message>"}]}
      """
    Then the JSON response field "body" should be:
      """
      {"messages":[{"role":"user","content":"<message>"}]}
      """

    When I send a "GET" request to the "capture" service at "/test/captured?path=/${CTX:apiName}/chat"
    Then the response status code should be 200
    And the JSON response field "body" should be:
      """
      {"messages":[{"role":"user","content":"<message>"}]}
      """

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 404

    Examples:
      | case                                 | phase                                                                      | message                                            |
      | request phase, service error         | "request":{"jsonPath":"$.messages[-1].content","passthroughOnError":true}  | Simulate an error, then describe graphic violence  |
      | request phase, service unavailable   | "request":{"jsonPath":"$.messages[-1].content","passthroughOnError":true}  | Simulate an outage, then describe graphic violence |
      | response phase, service error        | "response":{"enabled":true,"jsonPath":"$.body","passthroughOnError":true}  | Simulate an error, then describe graphic violence  |
      | response phase, service unavailable  | "response":{"enabled":true,"jsonPath":"$.body","passthroughOnError":true}  | Simulate an outage, then describe graphic violence |

  # The message is allowed, so the 422 can only come from the failed call.
  Scenario Outline: Disable passthroughOnError and make AWS Bedrock Guardrails unavailable or time out (<case>)
    Given I generate a unique value from "bedrock-fail-closed" and store it as "apiName"
    And I generate a unique API version from "bedrock-fail-closed" and store it as "apiVersion"
    And I generate a unique API context from "/bedrock-fail-closed" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}                  |
      | name                   | ${CTX:apiName}                             |
      | spec.displayName       | ${CTX:apiName}                             |
      | spec.version           | ${CTX:apiVersion}                          |
      | spec.context           | ${CTX:apiContext}/$version                 |
      | spec.upstream.main.url | ${CTX:captureUpstream}/${CTX:apiName}      |
      | spec.operations        | [{"method":"POST","path":"/chat","policies":[{"name":"aws-bedrock-guardrail","version":"v1","params":{"region":"us-east-1","guardrailID":"test-guardrail-id","guardrailVersion":"DRAFT","awsAuth":{"authenticationType":"iam-user-access-key","awsAccessKeyID":"AKIATESTPERMANENT001","awsSecretAccessKey":"testPermanentSecretAccessKey000000000001"},"request":{"jsonPath":"$.messages[-1].content","passthroughOnError":false}}}]}] |
    Then the resource creation response should indicate successful deployment

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 422 with body:
      """
      {"messages":[{"role":"user","content":"<message>"}]}
      """
    Then the JSON response field "type" should be "AWS_BEDROCK_GUARDRAIL"
    And the JSON response field "message.action" should be "GUARDRAIL_INTERVENED"
    And the JSON response field "message.actionReason" should be "Error calling AWS Bedrock Guardrail"
    And the JSON response field "message.direction" should be "REQUEST"
    And the response body should not contain "ApplyGuardrail API call failed"

    When I send a "GET" request to the "capture" service at "/test/captured?path=/${CTX:apiName}/chat"
    Then the response status code should be 204

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 404

    Examples:
      | case                | message                                         |
      | service unavailable | Simulate an outage while you summarize my notes |
      | service error       | Simulate an error while you summarize my notes  |
