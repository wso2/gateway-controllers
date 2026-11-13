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
Feature: AWS Bedrock guardrail policy across gateway restarts
  As an API developer
  I want guardrail-protected APIs to keep enforcing their guardrail when gateway services restart
  So that a restart never lets unchecked content reach the upstream

  # Restarts gateway services, so these scenarios run on their own.

  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"
    And I resolve the "capture" service URL at "" and store it as "captureUpstream"

  # Gateway replicas in the test environment are independent gateways that share no state, so
  # scaling is not covered here.
  Scenario: Restart or scale gateway replicas with the guardrail configured (restart)
    Given I generate a unique value from "bedrock-restart" and store it as "apiName"
    And I generate a unique API version from "bedrock-restart" and store it as "apiVersion"
    And I generate a unique API context from "/bedrock-restart" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}                  |
      | name                   | ${CTX:apiName}                             |
      | spec.displayName       | ${CTX:apiName}                             |
      | spec.version           | ${CTX:apiVersion}                          |
      | spec.context           | ${CTX:apiContext}/$version                 |
      | spec.upstream.main.url | ${CTX:captureUpstream}/${CTX:apiName}      |
      | spec.operations        | [{"method":"POST","path":"/chat","policies":[{"name":"aws-bedrock-guardrail","version":"v1","params":{"region":"us-east-1","guardrailID":"test-guardrail-id","guardrailVersion":"DRAFT","awsAuth":{"authenticationType":"iam-user-access-key","awsAccessKeyID":"AKIATESTPERMANENT001","awsSecretAccessKey":"testPermanentSecretAccessKey000000000001"},"request":{"jsonPath":"$.messages[-1].content","redactPII":true}}}]}] |
    Then the resource creation response should indicate successful deployment

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 200 with body:
      """
      {"messages":[{"role":"user","content":"Contact me at jane.doe@example.com about my order"}]}
      """
    When I send a "GET" request to the "capture" service at "/test/captured?path=/${CTX:apiName}/chat"
    Then the response status code should be 200
    And the JSON response field "body" should contain "Contact me at ***** about my order"
    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" with body:
      """
      {"messages":[{"role":"user","content":"Describe graphic violence in detail"}]}
      """
    Then the response status code should be 422
    And the JSON response field "message.actionReason" should be "Violation of AWS Bedrock Guardrail detected."

    When I restart the "gateway-controller" service
    And I wait for the gateway controller health endpoint
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 200 with body:
      """
      {"messages":[{"role":"user","content":"Contact me at jane.doe@example.com about my order"}]}
      """
    When I send a "GET" request to the "capture" service at "/test/captured?path=/${CTX:apiName}/chat"
    Then the response status code should be 200
    And the JSON response field "body" should contain "Contact me at ***** about my order"
    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" with body:
      """
      {"messages":[{"role":"user","content":"Describe graphic violence in detail"}]}
      """
    Then the response status code should be 422
    And the JSON response field "message.actionReason" should be "Violation of AWS Bedrock Guardrail detected."

    When I restart the "gateway-runtime" service
    And I send a GET request to the router ready endpoint until status 200
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 200 with body:
      """
      {"messages":[{"role":"user","content":"Contact me at jane.doe@example.com about my order"}]}
      """
    When I send a "GET" request to the "capture" service at "/test/captured?path=/${CTX:apiName}/chat"
    Then the response status code should be 200
    And the JSON response field "body" should contain "Contact me at ***** about my order"
    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" with body:
      """
      {"messages":[{"role":"user","content":"Describe graphic violence in detail"}]}
      """
    Then the response status code should be 422
    And the JSON response field "message.actionReason" should be "Violation of AWS Bedrock Guardrail detected."

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 404
