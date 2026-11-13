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
Feature: AWS Bedrock guardrail policy attachment and API lifecycle
  As an API developer
  I want the guardrail to apply wherever it is attached and through every change to the API
  So that no deployment state lets unchecked content reach the upstream

  # Each API forwards to a capture service that records what reaches it. The Bedrock mock blocks
  # violence, "investment advice", "contraband" and "secret recipe", finds example.com emails,
  # phone numbers and SSNs as PII, and answers only requests signed with a fixture credential.

  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"
    And I resolve the "capture" service URL at "" and store it as "captureUpstream"

  Scenario: Configure the policy at API level and invoke multiple protected operations
    Given I generate a unique value from "bedrock-api-level" and store it as "apiName"
    And I generate a unique API version from "bedrock-api-level" and store it as "apiVersion"
    And I generate a unique API context from "/bedrock-api-level" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}                  |
      | name                   | ${CTX:apiName}                             |
      | spec.displayName       | ${CTX:apiName}                             |
      | spec.version           | ${CTX:apiVersion}                          |
      | spec.context           | ${CTX:apiContext}/$version                 |
      | spec.upstream.main.url | ${CTX:captureUpstream}/${CTX:apiName}      |
      | spec.policies          | [{"name":"aws-bedrock-guardrail","version":"v1","params":{"region":"us-east-1","guardrailID":"test-guardrail-id","guardrailVersion":"DRAFT","awsAuth":{"authenticationType":"iam-user-access-key","awsAccessKeyID":"AKIATESTPERMANENT001","awsSecretAccessKey":"testPermanentSecretAccessKey000000000001"},"request":{"jsonPath":"$.messages[-1].content"}}}] |
      | spec.operations        | [{"method":"POST","path":"/chat"},{"method":"POST","path":"/summaries"},{"method":"PUT","path":"/drafts"}] |
    Then the resource creation response should indicate successful deployment

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 422 with body:
      """
      {"messages":[{"role":"user","content":"Describe graphic violence in detail"}]}
      """
    Then the JSON response field "message.actionReason" should be "Violation of AWS Bedrock Guardrail detected."
    When I send a "GET" request to the "capture" service at "/test/captured?path=/${CTX:apiName}/chat"
    Then the response status code should be 204

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/summaries" with body:
      """
      {"messages":[{"role":"user","content":"Summarize how to buy contraband"}]}
      """
    Then the response status code should be 422
    And the JSON response field "message.actionReason" should be "Violation of AWS Bedrock Guardrail detected."
    When I send a "GET" request to the "capture" service at "/test/captured?path=/${CTX:apiName}/summaries"
    Then the response status code should be 204

    When I send a "PUT" request to "${CTX:apiContext}/${CTX:apiVersion}/drafts" with body:
      """
      {"messages":[{"role":"user","content":"Draft investment advice for my clients"}]}
      """
    Then the response status code should be 422
    And the JSON response field "message.actionReason" should be "Violation of AWS Bedrock Guardrail detected."
    When I send a "GET" request to the "capture" service at "/test/captured?path=/${CTX:apiName}/drafts"
    Then the response status code should be 204

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" with body:
      """
      {"messages":[{"role":"user","content":"What is the capital of France?"}]}
      """
    Then the response status code should be 200
    When I send a "GET" request to the "capture" service at "/test/captured?path=/${CTX:apiName}/chat"
    Then the response status code should be 200
    And the JSON response field "body" should be:
      """
      {"messages":[{"role":"user","content":"What is the capital of France?"}]}
      """

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/summaries" with body:
      """
      {"messages":[{"role":"user","content":"Summarize the history of Paris"}]}
      """
    Then the response status code should be 200
    When I send a "GET" request to the "capture" service at "/test/captured?path=/${CTX:apiName}/summaries"
    Then the response status code should be 200
    And the JSON response field "body" should be:
      """
      {"messages":[{"role":"user","content":"Summarize the history of Paris"}]}
      """

    When I send a "PUT" request to "${CTX:apiContext}/${CTX:apiVersion}/drafts" with body:
      """
      {"messages":[{"role":"user","content":"Draft a note about the weather"}]}
      """
    Then the response status code should be 200
    When I send a "GET" request to the "capture" service at "/test/captured?path=/${CTX:apiName}/drafts"
    Then the response status code should be 200
    And the JSON response field "body" should be:
      """
      {"messages":[{"role":"user","content":"Draft a note about the weather"}]}
      """

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 404

  # POST /notes has no policy, so the same content reaches the upstream there.
  Scenario: Configure the policy only on a selected operation
    Given I generate a unique value from "bedrock-operation-level" and store it as "apiName"
    And I generate a unique API version from "bedrock-operation-level" and store it as "apiVersion"
    And I generate a unique API context from "/bedrock-operation-level" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}                  |
      | name                   | ${CTX:apiName}                             |
      | spec.displayName       | ${CTX:apiName}                             |
      | spec.version           | ${CTX:apiVersion}                          |
      | spec.context           | ${CTX:apiContext}/$version                 |
      | spec.upstream.main.url | ${CTX:captureUpstream}/${CTX:apiName}      |
      | spec.operations        | [{"method":"POST","path":"/chat","policies":[{"name":"aws-bedrock-guardrail","version":"v1","params":{"region":"us-east-1","guardrailID":"test-guardrail-id","guardrailVersion":"DRAFT","awsAuth":{"authenticationType":"iam-user-access-key","awsAccessKeyID":"AKIATESTPERMANENT001","awsSecretAccessKey":"testPermanentSecretAccessKey000000000001"},"request":{"jsonPath":"$.messages[-1].content"}}}]},{"method":"POST","path":"/notes"}] |
    Then the resource creation response should indicate successful deployment

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 422 with body:
      """
      {"messages":[{"role":"user","content":"Describe graphic violence in detail"}]}
      """
    Then the JSON response field "message.actionReason" should be "Violation of AWS Bedrock Guardrail detected."
    When I send a "GET" request to the "capture" service at "/test/captured?path=/${CTX:apiName}/chat"
    Then the response status code should be 204

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/notes" with body:
      """
      {"messages":[{"role":"user","content":"Describe graphic violence in detail"}]}
      """
    Then the response status code should be 200
    When I send a "GET" request to the "capture" service at "/test/captured?path=/${CTX:apiName}/notes"
    Then the response status code should be 200
    And the JSON response field "body" should be:
      """
      {"messages":[{"role":"user","content":"Describe graphic violence in detail"}]}
      """

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 404

  # prompt-decorator, listed first, adds an email address. The guardrail redacts it, so it checked
  # the decorated message.
  Scenario: Apply another request transformation policy before the Bedrock Guardrail
    Given I generate a unique value from "bedrock-transform-before" and store it as "apiName"
    And I generate a unique API version from "bedrock-transform-before" and store it as "apiVersion"
    And I generate a unique API context from "/bedrock-transform-before" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}                  |
      | name                   | ${CTX:apiName}                             |
      | spec.displayName       | ${CTX:apiName}                             |
      | spec.version           | ${CTX:apiVersion}                          |
      | spec.context           | ${CTX:apiContext}/$version                 |
      | spec.upstream.main.url | ${CTX:captureUpstream}/${CTX:apiName}      |
      | spec.operations        | [{"method":"POST","path":"/chat","policies":[{"name":"prompt-decorator","version":"v1","params":{"promptDecoratorConfig":{"text":"Contact: help@example.com"},"append":true}},{"name":"aws-bedrock-guardrail","version":"v1","params":{"region":"us-east-1","guardrailID":"test-guardrail-id","guardrailVersion":"DRAFT","awsAuth":{"authenticationType":"iam-user-access-key","awsAccessKeyID":"AKIATESTPERMANENT001","awsSecretAccessKey":"testPermanentSecretAccessKey000000000001"},"request":{"jsonPath":"$.messages[-1].content","redactPII":true}}}]}] |
    Then the resource creation response should indicate successful deployment

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 200 with body:
      """
      {"messages":[{"role":"user","content":"What is the capital of France?"}]}
      """

    When I send a "GET" request to the "capture" service at "/test/captured?path=/${CTX:apiName}/chat"
    Then the response status code should be 200
    And the JSON response field "body" should contain "What is the capital of France? Contact: *****"
    And the response body should not contain "help@example.com"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 404

  # prompt-decorator, listed after the guardrail, decorates only what the guardrail let through.
  Scenario: Apply another transformation after the guardrail
    Given I generate a unique value from "bedrock-transform-after" and store it as "apiName"
    And I generate a unique API version from "bedrock-transform-after" and store it as "apiVersion"
    And I generate a unique API context from "/bedrock-transform-after" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}                  |
      | name                   | ${CTX:apiName}                             |
      | spec.displayName       | ${CTX:apiName}                             |
      | spec.version           | ${CTX:apiVersion}                          |
      | spec.context           | ${CTX:apiContext}/$version                 |
      | spec.upstream.main.url | ${CTX:captureUpstream}/${CTX:apiName}      |
      | spec.operations        | [{"method":"POST","path":"/chat","policies":[{"name":"aws-bedrock-guardrail","version":"v1","params":{"region":"us-east-1","guardrailID":"test-guardrail-id","guardrailVersion":"DRAFT","awsAuth":{"authenticationType":"iam-user-access-key","awsAccessKeyID":"AKIATESTPERMANENT001","awsSecretAccessKey":"testPermanentSecretAccessKey000000000001"},"request":{"jsonPath":"$.messages[-1].content","redactPII":true}}},{"name":"prompt-decorator","version":"v1","params":{"promptDecoratorConfig":{"text":"Contact: help@example.com"},"append":true}}]}] |
    Then the resource creation response should indicate successful deployment

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 422 with body:
      """
      {"messages":[{"role":"user","content":"Describe graphic violence in detail"}]}
      """
    Then the JSON response field "message.actionReason" should be "Violation of AWS Bedrock Guardrail detected."
    And the response body should not contain "help@example.com"
    When I send a "GET" request to the "capture" service at "/test/captured?path=/${CTX:apiName}/chat"
    Then the response status code should be 204

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 200 with body:
      """
      {"messages":[{"role":"user","content":"Contact me at jane.doe@example.com about my order"}]}
      """

    When I send a "GET" request to the "capture" service at "/test/captured?path=/${CTX:apiName}/chat"
    Then the response status code should be 200
    And the JSON response field "body" should contain "Contact me at ***** about my order Contact: help@example.com"
    And the response body should not contain "jane.doe@example.com"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 404

  # The API first checks the first message, so prohibited content in the last one is forwarded.
  Scenario: Update the guardrail ID/version/JSONPath while the API is deployed (JSONPath)
    Given I generate a unique value from "bedrock-update-jsonpath" and store it as "apiName"
    And I generate a unique API version from "bedrock-update-jsonpath" and store it as "apiVersion"
    And I generate a unique API context from "/bedrock-update-jsonpath" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}                  |
      | name                   | ${CTX:apiName}                             |
      | spec.displayName       | ${CTX:apiName}                             |
      | spec.version           | ${CTX:apiVersion}                          |
      | spec.context           | ${CTX:apiContext}/$version                 |
      | spec.upstream.main.url | ${CTX:captureUpstream}/${CTX:apiName}      |
      | spec.operations        | [{"method":"POST","path":"/chat","policies":[{"name":"aws-bedrock-guardrail","version":"v1","params":{"region":"us-east-1","guardrailID":"test-guardrail-id","guardrailVersion":"DRAFT","awsAuth":{"authenticationType":"iam-user-access-key","awsAccessKeyID":"AKIATESTPERMANENT001","awsSecretAccessKey":"testPermanentSecretAccessKey000000000001"},"request":{"jsonPath":"$.messages[0].content"}}}]}] |
    Then the resource creation response should indicate successful deployment

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 200 with body:
      """
      {"messages":[{"role":"system","content":"You are a helpful assistant."},{"role":"user","content":"Where can I buy contraband?"}]}
      """
    When I send a "GET" request to the "capture" service at "/test/captured?path=/${CTX:apiName}/chat"
    Then the response status code should be 200
    And the JSON response field "body" should be:
      """
      {"messages":[{"role":"system","content":"You are a helpful assistant."},{"role":"user","content":"Where can I buy contraband?"}]}
      """

    When I update API "${CTX:apiName}" from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}                  |
      | name                   | ${CTX:apiName}                             |
      | spec.displayName       | ${CTX:apiName}                             |
      | spec.version           | ${CTX:apiVersion}                          |
      | spec.context           | ${CTX:apiContext}/$version                 |
      | spec.upstream.main.url | ${CTX:captureUpstream}/${CTX:apiName}      |
      | spec.operations        | [{"method":"POST","path":"/chat","policies":[{"name":"aws-bedrock-guardrail","version":"v1","params":{"region":"us-east-1","guardrailID":"test-guardrail-id","guardrailVersion":"DRAFT","awsAuth":{"authenticationType":"iam-user-access-key","awsAccessKeyID":"AKIATESTPERMANENT001","awsSecretAccessKey":"testPermanentSecretAccessKey000000000001"},"request":{"jsonPath":"$.messages[-1].content"}}}]}] |
    Then the API update response should indicate successful deployment

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 422 with body:
      """
      {"messages":[{"role":"system","content":"You are a helpful assistant."},{"role":"user","content":"Where can I buy contraband?"}]}
      """
    And the JSON response field "message.actionReason" should be "Violation of AWS Bedrock Guardrail detected."

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 404

  # The API is first deployed with a guardrail the mock does not know, so every call fails.
  Scenario: Update the guardrail ID/version/JSONPath while the API is deployed (guardrail ID)
    Given I generate a unique value from "bedrock-update-guardrail-id" and store it as "apiName"
    And I generate a unique API version from "bedrock-update-guardrail-id" and store it as "apiVersion"
    And I generate a unique API context from "/bedrock-update-guardrail-id" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}                  |
      | name                   | ${CTX:apiName}                             |
      | spec.displayName       | ${CTX:apiName}                             |
      | spec.version           | ${CTX:apiVersion}                          |
      | spec.context           | ${CTX:apiContext}/$version                 |
      | spec.upstream.main.url | ${CTX:captureUpstream}/${CTX:apiName}      |
      | spec.operations        | [{"method":"POST","path":"/chat","policies":[{"name":"aws-bedrock-guardrail","version":"v1","params":{"guardrailID":"retired-guardrail-id","guardrailVersion":"DRAFT","region":"us-east-1","awsAuth":{"authenticationType":"iam-user-access-key","awsAccessKeyID":"AKIATESTPERMANENT001","awsSecretAccessKey":"testPermanentSecretAccessKey000000000001"},"request":{"jsonPath":"$.messages[-1].content"}}}]}] |
    Then the resource creation response should indicate successful deployment

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 422 with body:
      """
      {"messages":[{"role":"user","content":"What is the capital of France?"}]}
      """
    Then the JSON response field "message.actionReason" should be "Error calling AWS Bedrock Guardrail"
    When I send a "GET" request to the "capture" service at "/test/captured?path=/${CTX:apiName}/chat"
    Then the response status code should be 204

    When I update API "${CTX:apiName}" from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}                  |
      | name                   | ${CTX:apiName}                             |
      | spec.displayName       | ${CTX:apiName}                             |
      | spec.version           | ${CTX:apiVersion}                          |
      | spec.context           | ${CTX:apiContext}/$version                 |
      | spec.upstream.main.url | ${CTX:captureUpstream}/${CTX:apiName}      |
      | spec.operations        | [{"method":"POST","path":"/chat","policies":[{"name":"aws-bedrock-guardrail","version":"v1","params":{"guardrailID":"test-guardrail-id","guardrailVersion":"DRAFT","region":"us-east-1","awsAuth":{"authenticationType":"iam-user-access-key","awsAccessKeyID":"AKIATESTPERMANENT001","awsSecretAccessKey":"testPermanentSecretAccessKey000000000001"},"request":{"jsonPath":"$.messages[-1].content"}}}]}] |
    Then the API update response should indicate successful deployment

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 200 with body:
      """
      {"messages":[{"role":"user","content":"What is the capital of France?"}]}
      """
    When I send a "GET" request to the "capture" service at "/test/captured?path=/${CTX:apiName}/chat"
    Then the response status code should be 200
    And the JSON response field "body" should be:
      """
      {"messages":[{"role":"user","content":"What is the capital of France?"}]}
      """
    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" with body:
      """
      {"messages":[{"role":"user","content":"Ship the contraband tonight"}]}
      """
    Then the response status code should be 422
    And the JSON response field "message.actionReason" should be "Violation of AWS Bedrock Guardrail detected."

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 404

  # Each request carries its own number, so a response with another request's text or address
  # fails.
  Scenario: Run concurrent requests containing allowed, blocked, and PII content
    Given I generate a unique value from "bedrock-concurrency" and store it as "apiName"
    And I generate a unique API version from "bedrock-concurrency" and store it as "apiVersion"
    And I generate a unique API context from "/bedrock-concurrency" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}                  |
      | name                   | ${CTX:apiName}                             |
      | spec.displayName       | ${CTX:apiName}                             |
      | spec.version           | ${CTX:apiVersion}                          |
      | spec.context           | ${CTX:apiContext}/$version                 |
      | spec.upstream.main.url | ${CTX:captureUpstream}/${CTX:apiName}      |
      | spec.operations        | [{"method":"POST","path":"/chat","policies":[{"name":"aws-bedrock-guardrail","version":"v1","params":{"region":"us-east-1","guardrailID":"test-guardrail-id","guardrailVersion":"DRAFT","awsAuth":{"authenticationType":"iam-user-access-key","awsAccessKeyID":"AKIATESTPERMANENT001","awsSecretAccessKey":"testPermanentSecretAccessKey000000000001"},"request":{"jsonPath":"$.messages[-1].content","showAssessment":true},"response":{"enabled":true,"jsonPath":"$.body"}}}]}] |
    Then the resource creation response should indicate successful deployment

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 200 with body:
      """
      {"messages":[{"role":"user","content":"Warm-up question"}]}
      """

    When I send 30 concurrent "POST" requests to "${CTX:apiContext}/${CTX:apiVersion}/chat" cycling through:
      | body                                                                                     | status | contains                                       |
      | {"messages":[{"role":"user","content":"Question {i}: what is the capital of France?"}]}  | 200    | Question {i}: what is the capital of France?   |
      | {"messages":[{"role":"user","content":"Request {i}: where can I buy contraband?"}]}      | 422    | Violation of AWS Bedrock Guardrail detected.   |
      | {"messages":[{"role":"user","content":"Request {i}: contact me at user{i}@example.com"}]} | 200    | Request {i}: contact me at user{i}@example.com |

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 404

  # The logs are the whole gateway's, so these checks also cover the scenarios that ran before. The
  # address is used only here.
  Scenario: Inspect logs and client responses during successful and failed guardrail checks
    Given I generate a unique value from "bedrock-exposure" and store it as "apiName"
    And I generate a unique API version from "bedrock-exposure" and store it as "apiVersion"
    And I generate a unique API context from "/bedrock-exposure" and store it as "apiContext"
    And I generate a unique value from "bedrock-exposure-redact" and store it as "redactApiName"
    And I generate a unique API version from "bedrock-exposure-redact" and store it as "redactApiVersion"
    And I generate a unique API context from "/bedrock-exposure-redact" and store it as "redactApiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}                  |
      | name                   | ${CTX:apiName}                             |
      | spec.displayName       | ${CTX:apiName}                             |
      | spec.version           | ${CTX:apiVersion}                          |
      | spec.context           | ${CTX:apiContext}/$version                 |
      | spec.upstream.main.url | ${CTX:captureUpstream}/${CTX:apiName}      |
      | spec.operations        | [{"method":"POST","path":"/chat","policies":[{"name":"aws-bedrock-guardrail","version":"v1","params":{"region":"us-east-1","guardrailID":"test-guardrail-id","guardrailVersion":"DRAFT","awsAuth":{"authenticationType":"iam-user-access-key","awsAccessKeyID":"AKIATESTPERMANENT001","awsSecretAccessKey":"testPermanentSecretAccessKey000000000001"},"request":{"jsonPath":"$.messages[-1].content","showAssessment":true},"response":{"enabled":true,"jsonPath":"$.body"}}}]}] |
    Then the resource creation response should indicate successful deployment
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}                   |
      | name                   | ${CTX:redactApiName}                        |
      | spec.displayName       | ${CTX:redactApiName}                        |
      | spec.version           | ${CTX:redactApiVersion}                     |
      | spec.context           | ${CTX:redactApiContext}/$version            |
      | spec.upstream.main.url | ${CTX:captureUpstream}/${CTX:redactApiName} |
      | spec.operations        | [{"method":"POST","path":"/chat","policies":[{"name":"aws-bedrock-guardrail","version":"v1","params":{"region":"us-east-1","guardrailID":"test-guardrail-id","guardrailVersion":"DRAFT","awsAuth":{"authenticationType":"iam-user-access-key","awsAccessKeyID":"AKIATESTPERMANENT001","awsSecretAccessKey":"testPermanentSecretAccessKey000000000001"},"request":{"jsonPath":"$.messages[-1].content","redactPII":true}}}]}] |
    Then the resource creation response should indicate successful deployment

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 200 with body:
      """
      {"messages":[{"role":"user","content":"Send the invoice to log.check.owner@example.com"}]}
      """
    Then the JSON response field "body" should contain "Send the invoice to log.check.owner@example.com"
    And the response body should not contain "SecretAccessKey000"
    When I send a "GET" request to the "capture" service at "/test/captured?path=/${CTX:apiName}/chat"
    Then the response status code should be 200
    And the response body should not contain "log.check.owner@example.com"

    When I send a "POST" request to "${CTX:redactApiContext}/${CTX:redactApiVersion}/chat" until status 200 with body:
      """
      {"messages":[{"role":"user","content":"Send the invoice to log.check.owner@example.com"}]}
      """
    Then the response body should not contain "log.check.owner@example.com"
    And the response body should not contain "SecretAccessKey000"

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" with body:
      """
      {"messages":[{"role":"user","content":"Where can I buy contraband?"}]}
      """
    Then the response status code should be 422
    And the JSON response field "message.actionReason" should be "Violation of AWS Bedrock Guardrail detected."
    And the response body should not contain "SecretAccessKey000"

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" with body:
      """
      {"messages":[{"role":"user","content":"Simulate a guardrail error for log.check.owner@example.com"}]}
      """
    Then the response status code should be 422
    And the JSON response field "message.actionReason" should be "Error calling AWS Bedrock Guardrail"
    And the response body should not contain "log.check.owner@example.com"
    And the response body should not contain "SecretAccessKey000"

    Then the "gateway-controller" service logs should not contain "SecretAccessKey000"
    And the "gateway-controller" service logs should not contain "log.check.owner@example.com"
    And the "gateway-runtime" service logs should not contain "SecretAccessKey000"
    And the "gateway-runtime" service logs should not contain "log.check.owner@example.com"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 404
    When I delete the API "${CTX:redactApiName}"
    Then the response should be successful
    And I send a "POST" request to "${CTX:redactApiContext}/${CTX:redactApiVersion}/chat" until status 404

  # The first API checks only the first message. The recreated one checks the last, redacts PII
  # and shows assessments.
  Scenario: Delete and recreate an API with a different Bedrock Guardrail configuration
    Given I generate a unique value from "bedrock-recreate" and store it as "apiName"
    And I generate a unique API version from "bedrock-recreate" and store it as "apiVersion"
    And I generate a unique API context from "/bedrock-recreate" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}                  |
      | name                   | ${CTX:apiName}                             |
      | spec.displayName       | ${CTX:apiName}                             |
      | spec.version           | ${CTX:apiVersion}                          |
      | spec.context           | ${CTX:apiContext}/$version                 |
      | spec.upstream.main.url | ${CTX:captureUpstream}/${CTX:apiName}      |
      | spec.operations        | [{"method":"POST","path":"/chat","policies":[{"name":"aws-bedrock-guardrail","version":"v1","params":{"region":"us-east-1","guardrailID":"test-guardrail-id","guardrailVersion":"DRAFT","awsAuth":{"authenticationType":"iam-user-access-key","awsAccessKeyID":"AKIATESTPERMANENT001","awsSecretAccessKey":"testPermanentSecretAccessKey000000000001"},"request":{"jsonPath":"$.messages[0].content"}}}]}] |
    Then the resource creation response should indicate successful deployment

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 200 with body:
      """
      {"messages":[{"role":"system","content":"You are a helpful assistant."},{"role":"user","content":"Where can I buy contraband?"}]}
      """
    When I send a "GET" request to the "capture" service at "/test/captured?path=/${CTX:apiName}/chat"
    Then the response status code should be 200
    And the JSON response field "body" should contain "Where can I buy contraband?"
    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 200 with body:
      """
      {"messages":[{"role":"system","content":"You are a helpful assistant."},{"role":"user","content":"Mail me at jane.doe@example.com"}]}
      """
    When I send a "GET" request to the "capture" service at "/test/captured?path=/${CTX:apiName}/chat"
    Then the response status code should be 200
    And the JSON response field "body" should contain "Mail me at jane.doe@example.com"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 404

    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}                  |
      | name                   | ${CTX:apiName}                             |
      | spec.displayName       | ${CTX:apiName}                             |
      | spec.version           | ${CTX:apiVersion}                          |
      | spec.context           | ${CTX:apiContext}/$version                 |
      | spec.upstream.main.url | ${CTX:captureUpstream}/${CTX:apiName}      |
      | spec.operations        | [{"method":"POST","path":"/chat","policies":[{"name":"aws-bedrock-guardrail","version":"v1","params":{"region":"us-east-1","guardrailID":"test-guardrail-id","guardrailVersion":"DRAFT","awsAuth":{"authenticationType":"iam-user-access-key","awsAccessKeyID":"AKIATESTPERMANENT001","awsSecretAccessKey":"testPermanentSecretAccessKey000000000001"},"request":{"jsonPath":"$.messages[-1].content","redactPII":true,"showAssessment":true}}}]}] |
    Then the resource creation response should indicate successful deployment

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 422 with body:
      """
      {"messages":[{"role":"system","content":"You are a helpful assistant."},{"role":"user","content":"Where can I buy contraband?"}]}
      """
    And the JSON response field "message.actionReason" should be "Violation of AWS Bedrock Guardrail detected."
    And the JSON response field "message.assessments.wordPolicy.customWords[0].match" should be "contraband"
    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 200 with body:
      """
      {"messages":[{"role":"system","content":"You are a helpful assistant."},{"role":"user","content":"Mail me at jane.doe@example.com"}]}
      """
    When I send a "GET" request to the "capture" service at "/test/captured?path=/${CTX:apiName}/chat"
    Then the response status code should be 200
    And the JSON response field "body" should contain "Mail me at *****"
    And the response body should not contain "jane.doe@example.com"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 404
