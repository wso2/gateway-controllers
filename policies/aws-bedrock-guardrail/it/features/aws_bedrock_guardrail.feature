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
Feature: AWS Bedrock guardrail policy
  As an API developer
  I want to validate request and response content using AWS Bedrock Guardrails
  So that I can prevent harmful content and protect PII

  # Each API forwards to a capture service that records what reaches it. The Bedrock mock blocks
  # violence, "investment advice", "contraband" and "secret recipe", finds example.com emails,
  # phone numbers and SSNs as PII, and answers only requests signed with a fixture credential.

  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"
    And I resolve the "capture" service URL at "" and store it as "captureUpstream"

  Scenario: Configure the policy with valid region, guardrailID, guardrailVersion, credentials, and JSONPath, then invoke with allowed content
    Given I generate a unique value from "bedrock-allowed" and store it as "apiName"
    And I generate a unique API version from "bedrock-allowed" and store it as "apiVersion"
    And I generate a unique API context from "/bedrock-allowed" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}                  |
      | name                   | ${CTX:apiName}                             |
      | spec.displayName       | ${CTX:apiName}                             |
      | spec.version           | ${CTX:apiVersion}                          |
      | spec.context           | ${CTX:apiContext}/$version                 |
      | spec.upstream.main.url | ${CTX:captureUpstream}/${CTX:apiName}      |
      | spec.operations        | [{"method":"POST","path":"/chat","policies":[{"name":"aws-bedrock-guardrail","version":"v1","params":{"region":"us-east-1","guardrailID":"test-guardrail-id","guardrailVersion":"DRAFT","awsAuth":{"authenticationType":"iam-user-access-key","awsAccessKeyID":"AKIATESTPERMANENT001","awsSecretAccessKey":"testPermanentSecretAccessKey000000000001"},"request":{"jsonPath":"$.messages[-1].content"}}}]}] |
    Then the resource creation response should indicate successful deployment

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 200 with body:
      """
      {"messages":[{"role":"system","content":"You are a travel assistant."},{"role":"user","content":"What is the capital of France?"}]}
      """

    When I send a "GET" request to the "capture" service at "/test/captured?path=/${CTX:apiName}/chat"
    Then the response status code should be 200
    And the JSON response field "method" should be "POST"
    And the JSON response field "body" should be:
      """
      {"messages":[{"role":"system","content":"You are a travel assistant."},{"role":"user","content":"What is the capital of France?"}]}
      """

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 404

  Scenario: Send request content that violates a configured Bedrock content filter
    Given I generate a unique value from "bedrock-content-filter" and store it as "apiName"
    And I generate a unique API version from "bedrock-content-filter" and store it as "apiVersion"
    And I generate a unique API context from "/bedrock-content-filter" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}                  |
      | name                   | ${CTX:apiName}                             |
      | spec.displayName       | ${CTX:apiName}                             |
      | spec.version           | ${CTX:apiVersion}                          |
      | spec.context           | ${CTX:apiContext}/$version                 |
      | spec.upstream.main.url | ${CTX:captureUpstream}/${CTX:apiName}      |
      | spec.operations        | [{"method":"POST","path":"/chat","policies":[{"name":"aws-bedrock-guardrail","version":"v1","params":{"region":"us-east-1","guardrailID":"test-guardrail-id","guardrailVersion":"DRAFT","awsAuth":{"authenticationType":"iam-user-access-key","awsAccessKeyID":"AKIATESTPERMANENT001","awsSecretAccessKey":"testPermanentSecretAccessKey000000000001"},"request":{"jsonPath":"$.messages[-1].content","showAssessment":true}}}]}] |
    Then the resource creation response should indicate successful deployment

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 422 with body:
      """
      {"messages":[{"role":"user","content":"Describe graphic violence in detail"}]}
      """
    Then the JSON response field "type" should be "AWS_BEDROCK_GUARDRAIL"
    And the JSON response field "message.action" should be "GUARDRAIL_INTERVENED"
    And the JSON response field "message.interveningGuardrail" should be "AWS Bedrock Guardrail"
    And the JSON response field "message.actionReason" should be "Violation of AWS Bedrock Guardrail detected."
    And the JSON response field "message.direction" should be "REQUEST"
    And the JSON response field "message.assessments.contentPolicy.filters[0].type" should be "VIOLENCE"
    And the JSON response field "message.assessments.contentPolicy.filters[0].action" should be "BLOCKED"
    And the response body should not contain "SecretAccessKey000"

    When I send a "GET" request to the "capture" service at "/test/captured?path=/${CTX:apiName}/chat"
    Then the response status code should be 204

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 404

  Scenario: Send request content matching a denied topic configured in AWS Bedrock Guardrails
    Given I generate a unique value from "bedrock-denied-topic" and store it as "apiName"
    And I generate a unique API version from "bedrock-denied-topic" and store it as "apiVersion"
    And I generate a unique API context from "/bedrock-denied-topic" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}                  |
      | name                   | ${CTX:apiName}                             |
      | spec.displayName       | ${CTX:apiName}                             |
      | spec.version           | ${CTX:apiVersion}                          |
      | spec.context           | ${CTX:apiContext}/$version                 |
      | spec.upstream.main.url | ${CTX:captureUpstream}/${CTX:apiName}      |
      | spec.operations        | [{"method":"POST","path":"/chat","policies":[{"name":"aws-bedrock-guardrail","version":"v1","params":{"region":"us-east-1","guardrailID":"test-guardrail-id","guardrailVersion":"DRAFT","awsAuth":{"authenticationType":"iam-user-access-key","awsAccessKeyID":"AKIATESTPERMANENT001","awsSecretAccessKey":"testPermanentSecretAccessKey000000000001"},"request":{"jsonPath":"$.messages[-1].content","showAssessment":true}}}]}] |
    Then the resource creation response should indicate successful deployment

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 422 with body:
      """
      {"messages":[{"role":"user","content":"Can you give me investment advice on which stocks to buy?"}]}
      """
    Then the JSON response field "type" should be "AWS_BEDROCK_GUARDRAIL"
    And the JSON response field "message.action" should be "GUARDRAIL_INTERVENED"
    And the JSON response field "message.interveningGuardrail" should be "AWS Bedrock Guardrail"
    And the JSON response field "message.actionReason" should be "Violation of AWS Bedrock Guardrail detected."
    And the JSON response field "message.direction" should be "REQUEST"
    And the JSON response field "message.assessments.topicPolicy.topics[0].name" should be "Investment Advice"
    And the JSON response field "message.assessments.topicPolicy.topics[0].type" should be "DENY"
    And the JSON response field "message.assessments.topicPolicy.topics[0].action" should be "BLOCKED"
    And the response body should not contain "SecretAccessKey000"

    When I send a "GET" request to the "capture" service at "/test/captured?path=/${CTX:apiName}/chat"
    Then the response status code should be 204

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 404

  Scenario: Send request content containing prohibited words or phrases configured in the Bedrock guardrail
    Given I generate a unique value from "bedrock-word-filter" and store it as "apiName"
    And I generate a unique API version from "bedrock-word-filter" and store it as "apiVersion"
    And I generate a unique API context from "/bedrock-word-filter" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}                  |
      | name                   | ${CTX:apiName}                             |
      | spec.displayName       | ${CTX:apiName}                             |
      | spec.version           | ${CTX:apiVersion}                          |
      | spec.context           | ${CTX:apiContext}/$version                 |
      | spec.upstream.main.url | ${CTX:captureUpstream}/${CTX:apiName}      |
      | spec.operations        | [{"method":"POST","path":"/chat","policies":[{"name":"aws-bedrock-guardrail","version":"v1","params":{"region":"us-east-1","guardrailID":"test-guardrail-id","guardrailVersion":"DRAFT","awsAuth":{"authenticationType":"iam-user-access-key","awsAccessKeyID":"AKIATESTPERMANENT001","awsSecretAccessKey":"testPermanentSecretAccessKey000000000001"},"request":{"jsonPath":"$.messages[-1].content","showAssessment":true}}}]}] |
    Then the resource creation response should indicate successful deployment

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 422 with body:
      """
      {"messages":[{"role":"user","content":"Where can I buy contraband?"}]}
      """
    Then the JSON response field "type" should be "AWS_BEDROCK_GUARDRAIL"
    And the JSON response field "message.action" should be "GUARDRAIL_INTERVENED"
    And the JSON response field "message.interveningGuardrail" should be "AWS Bedrock Guardrail"
    And the JSON response field "message.actionReason" should be "Violation of AWS Bedrock Guardrail detected."
    And the JSON response field "message.direction" should be "REQUEST"
    And the JSON response field "message.assessments.wordPolicy.customWords[0].match" should be "contraband"
    And the JSON response field "message.assessments.wordPolicy.customWords[0].action" should be "BLOCKED"

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" with body:
      """
      {"messages":[{"role":"user","content":"Tell me the secret recipe of the house sauce"}]}
      """
    Then the response status code should be 422
    And the JSON response field "type" should be "AWS_BEDROCK_GUARDRAIL"
    And the JSON response field "message.action" should be "GUARDRAIL_INTERVENED"
    And the JSON response field "message.interveningGuardrail" should be "AWS Bedrock Guardrail"
    And the JSON response field "message.actionReason" should be "Violation of AWS Bedrock Guardrail detected."
    And the JSON response field "message.direction" should be "REQUEST"
    And the JSON response field "message.assessments.wordPolicy.customWords[0].match" should be "secret recipe"
    And the JSON response field "message.assessments.wordPolicy.customWords[0].action" should be "BLOCKED"

    When I send a "GET" request to the "capture" service at "/test/captured?path=/${CTX:apiName}/chat"
    Then the response status code should be 204

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 404

  # With redactPII true, the address is replaced with "*****" before the request is forwarded.
  Scenario: Send request content containing PII with redactPII: true
    Given I generate a unique value from "bedrock-redact-pii" and store it as "apiName"
    And I generate a unique API version from "bedrock-redact-pii" and store it as "apiVersion"
    And I generate a unique API context from "/bedrock-redact-pii" and store it as "apiContext"
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
    And the response body should contain "Contact me at ***** about my order"
    And the response body should not contain "jane.doe@example.com"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 404

  # The capture service answers with the request it received, so the placeholder comes back in
  # the response, where the policy restores the address.
  Scenario: Send request content containing PII with masking/restoration mode enabled
    Given I generate a unique value from "bedrock-mask-pii" and store it as "apiName"
    And I generate a unique API version from "bedrock-mask-pii" and store it as "apiVersion"
    And I generate a unique API context from "/bedrock-mask-pii" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}                  |
      | name                   | ${CTX:apiName}                             |
      | spec.displayName       | ${CTX:apiName}                             |
      | spec.version           | ${CTX:apiVersion}                          |
      | spec.context           | ${CTX:apiContext}/$version                 |
      | spec.upstream.main.url | ${CTX:captureUpstream}/${CTX:apiName}      |
      | spec.operations        | [{"method":"POST","path":"/chat","policies":[{"name":"aws-bedrock-guardrail","version":"v1","params":{"region":"us-east-1","guardrailID":"test-guardrail-id","guardrailVersion":"DRAFT","awsAuth":{"authenticationType":"iam-user-access-key","awsAccessKeyID":"AKIATESTPERMANENT001","awsSecretAccessKey":"testPermanentSecretAccessKey000000000001"},"request":{"jsonPath":"$.messages[-1].content"},"response":{"enabled":true,"jsonPath":"$.body"}}}]}] |
    Then the resource creation response should indicate successful deployment

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 200 with body:
      """
      {"messages":[{"role":"user","content":"Contact me at jane.doe@example.com about my order"}]}
      """
    Then the JSON response field "body" should contain "Contact me at jane.doe@example.com about my order"
    And the response body should not contain "EMAIL_0000"

    When I send a "GET" request to the "capture" service at "/test/captured?path=/${CTX:apiName}/chat"
    Then the response status code should be 200
    And the JSON response field "body" should contain "Contact me at EMAIL_0000 about my order"
    And the response body should not contain "jane.doe@example.com"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 404

  # Masking numbers the placeholders longest match first. request.redactPII also applies to the
  # response, so redaction restores nothing.
  Scenario Outline: Send content containing multiple PII types such as email, phone number, and identifiers (<case>)
    Given I generate a unique value from "bedrock-multi-pii" and store it as "apiName"
    And I generate a unique API version from "bedrock-multi-pii" and store it as "apiVersion"
    And I generate a unique API context from "/bedrock-multi-pii" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}                  |
      | name                   | ${CTX:apiName}                             |
      | spec.displayName       | ${CTX:apiName}                             |
      | spec.version           | ${CTX:apiVersion}                          |
      | spec.context           | ${CTX:apiContext}/$version                 |
      | spec.upstream.main.url | ${CTX:captureUpstream}/${CTX:apiName}      |
      | spec.operations        | [{"method":"POST","path":"/chat","policies":[{"name":"aws-bedrock-guardrail","version":"v1","params":{"region":"us-east-1","guardrailID":"test-guardrail-id","guardrailVersion":"DRAFT","awsAuth":{"authenticationType":"iam-user-access-key","awsAccessKeyID":"AKIATESTPERMANENT001","awsSecretAccessKey":"testPermanentSecretAccessKey000000000001"},"request":{"jsonPath":"$.messages[-1].content","redactPII":<redactPII>},"response":{"enabled":true,"jsonPath":"$.body"}}}]}] |
    Then the resource creation response should indicate successful deployment

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 200 with body:
      """
      {"messages":[{"role":"user","content":"Email jane.doe@example.com, call 555-123-4567, SSN 123-45-6789"}]}
      """
    Then the JSON response field "body" should contain "<returned>"

    When I send a "GET" request to the "capture" service at "/test/captured?path=/${CTX:apiName}/chat"
    Then the response status code should be 200
    And the JSON response field "body" should contain "<forwarded>"
    And the response body should not contain "jane.doe@example.com"
    And the response body should not contain "555-123-4567"
    And the response body should not contain "123-45-6789"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 404

    Examples:
      | case      | redactPII | forwarded                                                             | returned                                                       |
      | masking   | false     | Email EMAIL_0000, call PHONE_0001, SSN US_SOCIAL_SECURITY_NUMBER_0002 | Email jane.doe@example.com, call 555-123-4567, SSN 123-45-6789 |
      | redaction | true      | Email *****, call *****, SSN *****                                    | Email *****, call *****, SSN *****                             |

  # The capture service plays the model: it answers with the request it received, so $.body of
  # the response is the model output.
  Scenario: Configure guardrail validation on the response path and return allowed model output
    Given I generate a unique value from "bedrock-response-allowed" and store it as "apiName"
    And I generate a unique API version from "bedrock-response-allowed" and store it as "apiVersion"
    And I generate a unique API context from "/bedrock-response-allowed" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}                  |
      | name                   | ${CTX:apiName}                             |
      | spec.displayName       | ${CTX:apiName}                             |
      | spec.version           | ${CTX:apiVersion}                          |
      | spec.context           | ${CTX:apiContext}/$version                 |
      | spec.upstream.main.url | ${CTX:captureUpstream}/${CTX:apiName}      |
      | spec.operations        | [{"method":"POST","path":"/chat","policies":[{"name":"aws-bedrock-guardrail","version":"v1","params":{"region":"us-east-1","guardrailID":"test-guardrail-id","guardrailVersion":"DRAFT","awsAuth":{"authenticationType":"iam-user-access-key","awsAccessKeyID":"AKIATESTPERMANENT001","awsSecretAccessKey":"testPermanentSecretAccessKey000000000001"},"response":{"enabled":true,"jsonPath":"$.body"}}}]}] |
    Then the resource creation response should indicate successful deployment

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 200 with body:
      """
      {"messages":[{"role":"user","content":"The capital of France is Paris."}]}
      """
    Then the JSON response field "body" should be:
      """
      {"messages":[{"role":"user","content":"The capital of France is Paris."}]}
      """

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 404

  # Only the response is validated, so the prohibited content reaches the upstream and is blocked
  # on its way back.
  Scenario: Configure response validation and make the model return prohibited content
    Given I generate a unique value from "bedrock-response-blocked" and store it as "apiName"
    And I generate a unique API version from "bedrock-response-blocked" and store it as "apiVersion"
    And I generate a unique API context from "/bedrock-response-blocked" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}                  |
      | name                   | ${CTX:apiName}                             |
      | spec.displayName       | ${CTX:apiName}                             |
      | spec.version           | ${CTX:apiVersion}                          |
      | spec.context           | ${CTX:apiContext}/$version                 |
      | spec.upstream.main.url | ${CTX:captureUpstream}/${CTX:apiName}      |
      | spec.operations        | [{"method":"POST","path":"/chat","policies":[{"name":"aws-bedrock-guardrail","version":"v1","params":{"region":"us-east-1","guardrailID":"test-guardrail-id","guardrailVersion":"DRAFT","awsAuth":{"authenticationType":"iam-user-access-key","awsAccessKeyID":"AKIATESTPERMANENT001","awsSecretAccessKey":"testPermanentSecretAccessKey000000000001"},"response":{"enabled":true,"jsonPath":"$.body","showAssessment":true}}}]}] |
    Then the resource creation response should indicate successful deployment

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 422 with body:
      """
      {"messages":[{"role":"user","content":"Describe graphic violence in detail"}]}
      """
    Then the JSON response field "type" should be "AWS_BEDROCK_GUARDRAIL"
    And the JSON response field "message.action" should be "GUARDRAIL_INTERVENED"
    And the JSON response field "message.interveningGuardrail" should be "AWS Bedrock Guardrail"
    And the JSON response field "message.actionReason" should be "Violation of AWS Bedrock Guardrail detected."
    And the JSON response field "message.direction" should be "RESPONSE"
    And the JSON response field "message.assessments.contentPolicy.filters[0].type" should be "VIOLENCE"
    And the JSON response field "message.assessments.contentPolicy.filters[0].action" should be "BLOCKED"
    And the response body should not contain "graphic violence"
    And the response body should not contain "SecretAccessKey000"

    When I send a "GET" request to the "capture" service at "/test/captured?path=/${CTX:apiName}/chat"
    Then the response status code should be 200
    And the JSON response field "body" should contain "Describe graphic violence in detail"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 404

  # The request phase checks only the user's message, so the address in the reply field reaches
  # the model. request.redactPII also applies to the response, which redacts it.
  Scenario: Configure PII handling on the response and return PII from the model (redaction)
    Given I generate a unique value from "bedrock-response-pii" and store it as "apiName"
    And I generate a unique API version from "bedrock-response-pii" and store it as "apiVersion"
    And I generate a unique API context from "/bedrock-response-pii" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}                  |
      | name                   | ${CTX:apiName}                             |
      | spec.displayName       | ${CTX:apiName}                             |
      | spec.version           | ${CTX:apiVersion}                          |
      | spec.context           | ${CTX:apiContext}/$version                 |
      | spec.upstream.main.url | ${CTX:captureUpstream}/${CTX:apiName}      |
      | spec.operations        | [{"method":"POST","path":"/chat","policies":[{"name":"aws-bedrock-guardrail","version":"v1","params":{"region":"us-east-1","guardrailID":"test-guardrail-id","guardrailVersion":"DRAFT","awsAuth":{"authenticationType":"iam-user-access-key","awsAccessKeyID":"AKIATESTPERMANENT001","awsSecretAccessKey":"testPermanentSecretAccessKey000000000001"},"request":{"jsonPath":"$.messages[-1].content","redactPII":true},"response":{"enabled":true,"jsonPath":"$.body"}}}]}] |
    Then the resource creation response should indicate successful deployment

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 200 with body:
      """
      {"messages":[{"role":"user","content":"How do I reach the support team?"}],"reply":"Write to support@example.com"}
      """
    Then the JSON response field "body" should contain "Write to *****"
    And the response body should not contain "support@example.com"

    When I send a "GET" request to the "capture" service at "/test/captured?path=/${CTX:apiName}/chat"
    Then the response status code should be 200
    And the JSON response field "body" should contain "Write to support@example.com"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 404

  # In masking mode the response phase only restores the request's placeholders, so PII the model
  # adds reaches the client unchanged. The blocked reply shows the response phase runs.
  Scenario: Configure PII handling on the response and return PII from the model (masking)
    Given I generate a unique value from "bedrock-response-pii-masking" and store it as "apiName"
    And I generate a unique API version from "bedrock-response-pii-masking" and store it as "apiVersion"
    And I generate a unique API context from "/bedrock-response-pii-masking" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}                  |
      | name                   | ${CTX:apiName}                             |
      | spec.displayName       | ${CTX:apiName}                             |
      | spec.version           | ${CTX:apiVersion}                          |
      | spec.context           | ${CTX:apiContext}/$version                 |
      | spec.upstream.main.url | ${CTX:captureUpstream}/${CTX:apiName}      |
      | spec.operations        | [{"method":"POST","path":"/chat","policies":[{"name":"aws-bedrock-guardrail","version":"v1","params":{"region":"us-east-1","guardrailID":"test-guardrail-id","guardrailVersion":"DRAFT","awsAuth":{"authenticationType":"iam-user-access-key","awsAccessKeyID":"AKIATESTPERMANENT001","awsSecretAccessKey":"testPermanentSecretAccessKey000000000001"},"request":{"jsonPath":"$.messages[-1].content","redactPII":false},"response":{"enabled":true,"jsonPath":"$.body"}}}]}] |
    Then the resource creation response should indicate successful deployment

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 200 with body:
      """
      {"messages":[{"role":"user","content":"How do I reach the support team?"}],"reply":"Write to support@example.com"}
      """
    Then the JSON response field "body" should contain "Write to support@example.com"
    And the response body should not contain "EMAIL_0000"

    When I send a "GET" request to the "capture" service at "/test/captured?path=/${CTX:apiName}/chat"
    Then the response status code should be 200
    And the JSON response field "body" should contain "Write to support@example.com"

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" with body:
      """
      {"messages":[{"role":"user","content":"How do I reach the support team?"}],"reply":"Here is graphic violence in detail"}
      """
    Then the response status code should be 422
    And the JSON response field "message.direction" should be "RESPONSE"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 404

  # The request phase checks only the last message, so a "reply" field becomes model output that
  # only the response phase checks.
  Scenario: Configure both request and response validation on the same operation
    Given I generate a unique value from "bedrock-request-response" and store it as "apiName"
    And I generate a unique API version from "bedrock-request-response" and store it as "apiVersion"
    And I generate a unique API context from "/bedrock-request-response" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}                  |
      | name                   | ${CTX:apiName}                             |
      | spec.displayName       | ${CTX:apiName}                             |
      | spec.version           | ${CTX:apiVersion}                          |
      | spec.context           | ${CTX:apiContext}/$version                 |
      | spec.upstream.main.url | ${CTX:captureUpstream}/${CTX:apiName}      |
      | spec.operations        | [{"method":"POST","path":"/chat","policies":[{"name":"aws-bedrock-guardrail","version":"v1","params":{"region":"us-east-1","guardrailID":"test-guardrail-id","guardrailVersion":"DRAFT","awsAuth":{"authenticationType":"iam-user-access-key","awsAccessKeyID":"AKIATESTPERMANENT001","awsSecretAccessKey":"testPermanentSecretAccessKey000000000001"},"request":{"jsonPath":"$.messages[-1].content"},"response":{"enabled":true,"jsonPath":"$.body"}}}]}] |
    Then the resource creation response should indicate successful deployment

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 422 with body:
      """
      {"messages":[{"role":"user","content":"Describe graphic violence in detail"}]}
      """
    Then the JSON response field "type" should be "AWS_BEDROCK_GUARDRAIL"
    And the JSON response field "message.action" should be "GUARDRAIL_INTERVENED"
    And the JSON response field "message.actionReason" should be "Violation of AWS Bedrock Guardrail detected."
    And the JSON response field "message.direction" should be "REQUEST"

    When I send a "GET" request to the "capture" service at "/test/captured?path=/${CTX:apiName}/chat"
    Then the response status code should be 204

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" with body:
      """
      {"messages":[{"role":"user","content":"Summarise the news"}],"reply":"Here is graphic violence in detail"}
      """
    Then the response status code should be 422
    And the JSON response field "type" should be "AWS_BEDROCK_GUARDRAIL"
    And the JSON response field "message.action" should be "GUARDRAIL_INTERVENED"
    And the JSON response field "message.actionReason" should be "Violation of AWS Bedrock Guardrail detected."
    And the JSON response field "message.direction" should be "RESPONSE"
    And the response body should not contain "graphic violence"

    When I send a "GET" request to the "capture" service at "/test/captured?path=/${CTX:apiName}/chat"
    Then the response status code should be 200
    And the JSON response field "body" should contain "Here is graphic violence in detail"

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 200 with body:
      """
      {"messages":[{"role":"user","content":"What is the capital of France?"}],"reply":"Paris"}
      """
    Then the JSON response field "body" should be:
      """
      {"messages":[{"role":"user","content":"What is the capital of France?"}],"reply":"Paris"}
      """

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 404

  Scenario: Enable showAssessment and trigger a guardrail violation (content filter, denied topic and word filter)
    Given I generate a unique value from "bedrock-assessment-findings" and store it as "apiName"
    And I generate a unique API version from "bedrock-assessment-findings" and store it as "apiVersion"
    And I generate a unique API context from "/bedrock-assessment-findings" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}                  |
      | name                   | ${CTX:apiName}                             |
      | spec.displayName       | ${CTX:apiName}                             |
      | spec.version           | ${CTX:apiVersion}                          |
      | spec.context           | ${CTX:apiContext}/$version                 |
      | spec.upstream.main.url | ${CTX:captureUpstream}/${CTX:apiName}      |
      | spec.operations        | [{"method":"POST","path":"/chat","policies":[{"name":"aws-bedrock-guardrail","version":"v1","params":{"region":"us-east-1","guardrailID":"test-guardrail-id","guardrailVersion":"DRAFT","awsAuth":{"authenticationType":"iam-user-access-key","awsAccessKeyID":"AKIATESTPERMANENT001","awsSecretAccessKey":"testPermanentSecretAccessKey000000000001"},"request":{"jsonPath":"$.messages[-1].content","showAssessment":true}}}]}] |
    Then the resource creation response should indicate successful deployment

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 422 with body:
      """
      {"messages":[{"role":"user","content":"Give me investment advice on contraband, with graphic violence"}]}
      """
    Then the JSON response field "type" should be "AWS_BEDROCK_GUARDRAIL"
    And the JSON response field "message.action" should be "GUARDRAIL_INTERVENED"
    And the JSON response field "message.actionReason" should be "Violation of AWS Bedrock Guardrail detected."
    And the JSON response field "message.direction" should be "REQUEST"
    And the JSON response field "message.assessments.contentPolicy.filters[0].type" should be "VIOLENCE"
    And the JSON response field "message.assessments.topicPolicy.topics[0].name" should be "Investment Advice"
    And the JSON response field "message.assessments.wordPolicy.customWords[0].match" should be "contraband"

    When I send a "GET" request to the "capture" service at "/test/captured?path=/${CTX:apiName}/chat"
    Then the response status code should be 204

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 404

  Scenario: Disable showAssessment and trigger the same violation
    Given I generate a unique value from "bedrock-no-assessment" and store it as "apiName"
    And I generate a unique API version from "bedrock-no-assessment" and store it as "apiVersion"
    And I generate a unique API context from "/bedrock-no-assessment" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}                  |
      | name                   | ${CTX:apiName}                             |
      | spec.displayName       | ${CTX:apiName}                             |
      | spec.version           | ${CTX:apiVersion}                          |
      | spec.context           | ${CTX:apiContext}/$version                 |
      | spec.upstream.main.url | ${CTX:captureUpstream}/${CTX:apiName}      |
      | spec.operations        | [{"method":"POST","path":"/chat","policies":[{"name":"aws-bedrock-guardrail","version":"v1","params":{"region":"us-east-1","guardrailID":"test-guardrail-id","guardrailVersion":"DRAFT","awsAuth":{"authenticationType":"iam-user-access-key","awsAccessKeyID":"AKIATESTPERMANENT001","awsSecretAccessKey":"testPermanentSecretAccessKey000000000001"},"request":{"jsonPath":"$.messages[-1].content","showAssessment":false}}}]}] |
    Then the resource creation response should indicate successful deployment

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 422 with body:
      """
      {"messages":[{"role":"user","content":"Give me investment advice on contraband, with graphic violence"}]}
      """
    Then the JSON response field "type" should be "AWS_BEDROCK_GUARDRAIL"
    And the JSON response field "message.action" should be "GUARDRAIL_INTERVENED"
    And the JSON response field "message.interveningGuardrail" should be "AWS Bedrock Guardrail"
    And the JSON response field "message.actionReason" should be "Violation of AWS Bedrock Guardrail detected."
    And the JSON response field "message.direction" should be "REQUEST"
    And the JSON response field "message.assessments" should not exist
    And the response body should not contain "VIOLENCE"
    And the response body should not contain "Investment Advice"
    And the response body should not contain "contraband"

    When I send a "GET" request to the "capture" service at "/test/captured?path=/${CTX:apiName}/chat"
    Then the response status code should be 204

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 404

  Scenario: Request with safe content passes through
    Given I generate a unique value from "bedrock-safe-request" and store it as "apiName"
    And I generate a unique API version from "bedrock-safe-request" and store it as "apiVersion"
    And I generate a unique API context from "/bedrock-safe-request" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName}                    |
      | spec.displayName       | ${CTX:apiName}                    |
      | spec.version           | ${CTX:apiVersion}                 |
      | spec.context           | ${CTX:apiContext}/$version        |
      | spec.upstream.main.url | http://testbench:3002              |
      | spec.operations        | [{"method":"POST","path":"/validate","policies":[{"name":"aws-bedrock-guardrail","version":"v1","params":{"region":"us-east-1","guardrailID":"test-guardrail-id","guardrailVersion":"DRAFT","awsAuth":{"authenticationType":"iam-user-access-key","awsAccessKeyID":"AKIAIOSFODNN7TEST","awsSecretAccessKey":"testsecretaccesskeytestsecretaccesskey1"},"request":{"jsonPath":"","redactPII":false,"passthroughOnError":false,"showAssessment":false}}}]},{"method":"GET","path":"/health"}] |
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/validate" until status 200 with body:
      """
      {"message":"Hello, this is safe content"}
      """

    When I delete the API "${CTX:apiName}"
    Then the response should be successful

  Scenario: Request with violating content is blocked
    Given I generate a unique value from "bedrock-block-request" and store it as "apiName"
    And I generate a unique API version from "bedrock-block-request" and store it as "apiVersion"
    And I generate a unique API context from "/bedrock-block-request" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName}                    |
      | spec.displayName       | ${CTX:apiName}                    |
      | spec.version           | ${CTX:apiVersion}                 |
      | spec.context           | ${CTX:apiContext}/$version        |
      | spec.upstream.main.url | http://testbench:3002              |
      | spec.operations        | [{"method":"POST","path":"/validate","policies":[{"name":"aws-bedrock-guardrail","version":"v1","params":{"region":"us-east-1","guardrailID":"test-guardrail-id","guardrailVersion":"DRAFT","awsAuth":{"authenticationType":"iam-user-access-key","awsAccessKeyID":"AKIAIOSFODNN7TEST","awsSecretAccessKey":"testsecretaccesskeytestsecretaccesskey1"},"request":{"jsonPath":"","showAssessment":false}}}]},{"method":"GET","path":"/health"}] |
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I set header "Content-Type" to "application/json"
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/validate" with body:
      """
      {"message":"This content contains violence and illegal activities"}
      """
    Then the response status code should be 422
    And the response body should contain "AWS_BEDROCK_GUARDRAIL"
    And the response body should contain "GUARDRAIL_INTERVENED"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful

  Scenario: Request violation with detailed assessment
    Given I generate a unique value from "bedrock-assessment" and store it as "apiName"
    And I generate a unique API version from "bedrock-assessment" and store it as "apiVersion"
    And I generate a unique API context from "/bedrock-assessment" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName}                    |
      | spec.displayName       | ${CTX:apiName}                    |
      | spec.version           | ${CTX:apiVersion}                 |
      | spec.context           | ${CTX:apiContext}/$version        |
      | spec.upstream.main.url | http://testbench:3002              |
      | spec.operations        | [{"method":"POST","path":"/validate","policies":[{"name":"aws-bedrock-guardrail","version":"v1","params":{"region":"us-east-1","guardrailID":"test-guardrail-id","guardrailVersion":"DRAFT","awsAuth":{"authenticationType":"iam-user-access-key","awsAccessKeyID":"AKIAIOSFODNN7TEST","awsSecretAccessKey":"testsecretaccesskeytestsecretaccesskey1"},"request":{"jsonPath":"","showAssessment":true}}}]},{"method":"GET","path":"/health"}] |
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I set header "Content-Type" to "application/json"
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/validate" with body:
      """
      {"message":"This contains hate speech"}
      """
    Then the response status code should be 422
    And the response should be valid JSON
    And the JSON response field "type" should be "AWS_BEDROCK_GUARDRAIL"
    And the JSON response field "message.actionReason" should be "Violation of AWS Bedrock Guardrail detected."
    And the JSON response field "message.assessments.contentPolicy.filters[0].type" should be "VIOLENCE"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful

  Scenario: Response with safe content passes through
    Given I generate a unique value from "bedrock-safe-response" and store it as "apiName"
    And I generate a unique API version from "bedrock-safe-response" and store it as "apiVersion"
    And I generate a unique API context from "/bedrock-safe-response" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName}                    |
      | spec.displayName       | ${CTX:apiName}                    |
      | spec.version           | ${CTX:apiVersion}                 |
      | spec.context           | ${CTX:apiContext}/$version        |
      | spec.upstream.main.url | http://testbench:3002              |
      | spec.operations        | [{"method":"GET","path":"/data","policies":[{"name":"aws-bedrock-guardrail","version":"v1","params":{"region":"us-east-1","guardrailID":"test-guardrail-id","guardrailVersion":"DRAFT","awsAuth":{"authenticationType":"iam-user-access-key","awsAccessKeyID":"AKIAIOSFODNN7TEST","awsSecretAccessKey":"testsecretaccesskeytestsecretaccesskey1"},"response":{"enabled":true,"jsonPath":"","showAssessment":false}}}]},{"method":"GET","path":"/health"}] |
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/data" until status 200

    # The echo reflects the query, so this response carries "violence" and is blocked.
    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/data?topic=violence"
    Then the response status code should be 422
    And the JSON response field "message.direction" should be "RESPONSE"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful

  Scenario: Request JSONPath extraction validates only the targeted field
    Given I generate a unique value from "bedrock-jsonpath" and store it as "apiName"
    And I generate a unique API version from "bedrock-jsonpath" and store it as "apiVersion"
    And I generate a unique API context from "/bedrock-jsonpath" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName}                    |
      | spec.displayName       | ${CTX:apiName}                    |
      | spec.version           | ${CTX:apiVersion}                 |
      | spec.context           | ${CTX:apiContext}/$version        |
      | spec.upstream.main.url | http://testbench:3002              |
      | spec.operations        | [{"method":"POST","path":"/validate","policies":[{"name":"aws-bedrock-guardrail","version":"v1","params":{"region":"us-east-1","guardrailID":"test-guardrail-id","guardrailVersion":"DRAFT","awsAuth":{"authenticationType":"iam-user-access-key","awsAccessKeyID":"AKIAIOSFODNN7TEST","awsSecretAccessKey":"testsecretaccesskeytestsecretaccesskey1"},"request":{"jsonPath":"$.message"}}}]},{"method":"GET","path":"/health"}] |
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    # Safe message field, violating metadata field ignored since only $.message is checked
    When I set header "Content-Type" to "application/json"
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/validate" until status 200 with body:
      """
      {"message":"Safe content","metadata":"This contains violence but should be ignored"}
      """

    When I set header "Content-Type" to "application/json"
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/validate" with body:
      """
      {"message":"This message contains violence","metadata":"Safe metadata"}
      """
    Then the response status code should be 422

    When I delete the API "${CTX:apiName}"
    Then the response should be successful

  Scenario: PII is masked in request and restored in response
    Given I generate a unique value from "bedrock-pii-masking" and store it as "apiName"
    And I generate a unique API version from "bedrock-pii-masking" and store it as "apiVersion"
    And I generate a unique API context from "/bedrock-pii-masking" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName}                    |
      | spec.displayName       | ${CTX:apiName}                    |
      | spec.version           | ${CTX:apiVersion}                 |
      | spec.context           | ${CTX:apiContext}/$version        |
      | spec.upstream.main.url | ${CTX:captureUpstream}/${CTX:apiName} |
      | spec.operations        | [{"method":"POST","path":"/anything","policies":[{"name":"aws-bedrock-guardrail","version":"v1","params":{"region":"us-east-1","guardrailID":"test-guardrail-id","guardrailVersion":"DRAFT","awsAuth":{"authenticationType":"iam-user-access-key","awsAccessKeyID":"AKIAIOSFODNN7TEST","awsSecretAccessKey":"testsecretaccesskeytestsecretaccesskey1"},"request":{"jsonPath":"","redactPII":false},"response":{"enabled":true,"jsonPath":""}}}]},{"method":"GET","path":"/health"}] |
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/anything" until status 200 with body:
      """
      {"message":"Contact me at mask-test@example.com"}
      """
    Then the response body should contain "mask-test@example.com"
    And the response body should not contain "EMAIL_0000"

    When I send a "GET" request to the "capture" service at "/test/captured?path=/${CTX:apiName}/anything"
    Then the response status code should be 200
    And the JSON response field "body" should contain "Contact me at EMAIL_0000"
    And the response body should not contain "mask-test@example.com"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful

  Scenario: PII is permanently redacted with redactPII true
    Given I generate a unique value from "bedrock-pii-redaction" and store it as "apiName"
    And I generate a unique API version from "bedrock-pii-redaction" and store it as "apiVersion"
    And I generate a unique API context from "/bedrock-pii-redaction" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName}                    |
      | spec.displayName       | ${CTX:apiName}                    |
      | spec.version           | ${CTX:apiVersion}                 |
      | spec.context           | ${CTX:apiContext}/$version        |
      | spec.upstream.main.url | http://testbench:3002              |
      | spec.operations        | [{"method":"POST","path":"/anything","policies":[{"name":"aws-bedrock-guardrail","version":"v1","params":{"region":"us-east-1","guardrailID":"test-guardrail-id","guardrailVersion":"DRAFT","awsAuth":{"authenticationType":"iam-user-access-key","awsAccessKeyID":"AKIAIOSFODNN7TEST","awsSecretAccessKey":"testsecretaccesskeytestsecretaccesskey1"},"request":{"jsonPath":"","redactPII":true}}}]},{"method":"GET","path":"/health"}] |
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/anything" until status 200 with body:
      """
      {"message":"My SSN is test@example.com"}
      """
    Then the response body should contain "*****"
    And the response body should not contain "test@example.com"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful

  Scenario: Request and response phases each validate their own content independently
    Given I generate a unique value from "bedrock-both-phases" and store it as "apiName"
    And I generate a unique API version from "bedrock-both-phases" and store it as "apiVersion"
    And I generate a unique API context from "/bedrock-both-phases" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName}                    |
      | spec.displayName       | ${CTX:apiName}                    |
      | spec.version           | ${CTX:apiVersion}                 |
      | spec.context           | ${CTX:apiContext}/$version        |
      | spec.upstream.main.url | http://testbench:3002              |
      | spec.operations        | [{"method":"POST","path":"/validate","policies":[{"name":"aws-bedrock-guardrail","version":"v1","params":{"region":"us-east-1","guardrailID":"test-guardrail-id","guardrailVersion":"DRAFT","awsAuth":{"authenticationType":"iam-user-access-key","awsAccessKeyID":"AKIAIOSFODNN7TEST","awsSecretAccessKey":"testsecretaccesskeytestsecretaccesskey1"},"request":{"jsonPath":""},"response":{"enabled":true,"jsonPath":""}}}]},{"method":"GET","path":"/health"}] |
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/validate" until status 200 with body:
      """
      {"message":"Safe request content"}
      """

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/validate" with body:
      """
      {"message":"This request contains violence"}
      """
    Then the response status code should be 422
    And the JSON response field "message.direction" should be "REQUEST"

    # The request phase checks only the body. The echo reflects the query, so only the response
    # carries "violence".
    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/validate?topic=violence" with body:
      """
      {"message":"Safe request content"}
      """
    Then the response status code should be 422
    And the JSON response field "message.direction" should be "RESPONSE"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful

  Scenario: An empty request body is handled gracefully
    Given I generate a unique value from "bedrock-empty-body" and store it as "apiName"
    And I generate a unique API version from "bedrock-empty-body" and store it as "apiVersion"
    And I generate a unique API context from "/bedrock-empty-body" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName}                    |
      | spec.displayName       | ${CTX:apiName}                    |
      | spec.version           | ${CTX:apiVersion}                 |
      | spec.context           | ${CTX:apiContext}/$version        |
      | spec.upstream.main.url | http://testbench:3002              |
      | spec.operations        | [{"method":"POST","path":"/validate","policies":[{"name":"aws-bedrock-guardrail","version":"v1","params":{"region":"us-east-1","guardrailID":"test-guardrail-id","guardrailVersion":"DRAFT","awsAuth":{"authenticationType":"iam-user-access-key","awsAccessKeyID":"AKIAIOSFODNN7TEST","awsSecretAccessKey":"testsecretaccesskeytestsecretaccesskey1"},"request":{"jsonPath":""}}}]},{"method":"GET","path":"/health"}] |
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/validate" until status 200 with body:
      """
      """

    When I delete the API "${CTX:apiName}"
    Then the response should be successful

  Scenario: passthroughOnError allows the request through despite a guardrail service failure
    Given I generate a unique value from "bedrock-passthrough" and store it as "apiName"
    And I generate a unique API version from "bedrock-passthrough" and store it as "apiVersion"
    And I generate a unique API context from "/bedrock-passthrough" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName}                    |
      | spec.displayName       | ${CTX:apiName}                    |
      | spec.version           | ${CTX:apiVersion}                 |
      | spec.context           | ${CTX:apiContext}/$version        |
      | spec.upstream.main.url | http://testbench:3002              |
      | spec.operations        | [{"method":"POST","path":"/validate","policies":[{"name":"aws-bedrock-guardrail","version":"v1","params":{"region":"us-east-1","guardrailID":"test-guardrail-id","guardrailVersion":"DRAFT","awsAuth":{"authenticationType":"iam-user-access-key","awsAccessKeyID":"AKIAIOSFODNN7TEST","awsSecretAccessKey":"testsecretaccesskeytestsecretaccesskey1"},"request":{"jsonPath":"","passthroughOnError":true}}}]},{"method":"GET","path":"/health"}] |
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    # The mock simulates a guardrail-service 500 for this exact keyword combination
    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/validate" until status 200 with body:
      """
      {"message":"This will simulate error in mock service"}
      """

    When I delete the API "${CTX:apiName}"
    Then the response should be successful

  Scenario: A nested JSONPath extraction is validated
    Given I generate a unique value from "bedrock-nested-jsonpath" and store it as "apiName"
    And I generate a unique API version from "bedrock-nested-jsonpath" and store it as "apiVersion"
    And I generate a unique API context from "/bedrock-nested-jsonpath" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName}                    |
      | spec.displayName       | ${CTX:apiName}                    |
      | spec.version           | ${CTX:apiVersion}                 |
      | spec.context           | ${CTX:apiContext}/$version        |
      | spec.upstream.main.url | http://testbench:3002              |
      | spec.operations        | [{"method":"POST","path":"/chat","policies":[{"name":"aws-bedrock-guardrail","version":"v1","params":{"region":"us-east-1","guardrailID":"test-guardrail-id","guardrailVersion":"DRAFT","awsAuth":{"authenticationType":"iam-user-access-key","awsAccessKeyID":"AKIAIOSFODNN7TEST","awsSecretAccessKey":"testsecretaccesskeytestsecretaccesskey1"},"request":{"jsonPath":"$.data.content"}}}]},{"method":"GET","path":"/health"}] |
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    # Safe nested content field, violating outer field ignored
    When I set header "Content-Type" to "application/json"
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 200 with body:
      """
      {"data":{"content":"Safe nested message","timestamp":"2025-01-01"},"metadata":"This outer field contains violence but should be ignored"}
      """

    When I set header "Content-Type" to "application/json"
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" with body:
      """
      {"data":{"content":"This nested content contains violence","timestamp":"2025-01-01"}}
      """
    Then the response status code should be 422

    When I delete the API "${CTX:apiName}"
    Then the response should be successful

  Scenario: An unresolvable JSONPath is handled as a guardrail error
    Given I generate a unique value from "bedrock-invalid-path" and store it as "apiName"
    And I generate a unique API version from "bedrock-invalid-path" and store it as "apiVersion"
    And I generate a unique API context from "/bedrock-invalid-path" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName}                    |
      | spec.displayName       | ${CTX:apiName}                    |
      | spec.version           | ${CTX:apiVersion}                 |
      | spec.context           | ${CTX:apiContext}/$version        |
      | spec.upstream.main.url | http://testbench:3002              |
      | spec.operations        | [{"method":"POST","path":"/validate","policies":[{"name":"aws-bedrock-guardrail","version":"v1","params":{"region":"us-east-1","guardrailID":"test-guardrail-id","guardrailVersion":"DRAFT","awsAuth":{"authenticationType":"iam-user-access-key","awsAccessKeyID":"AKIAIOSFODNN7TEST","awsSecretAccessKey":"testsecretaccesskeytestsecretaccesskey1"},"request":{"jsonPath":"$.nonexistent.field"}}}]},{"method":"GET","path":"/health"}] |
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I set header "Content-Type" to "application/json"
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/validate" with body:
      """
      {"message":"This field exists but not the one we are looking for"}
      """
    Then the response status code should be 422
    And the response should be valid JSON
    And the response body should contain "AWS_BEDROCK_GUARDRAIL"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful

  Scenario: A blocked response carries the complete error structure
    Given I generate a unique value from "bedrock-error-structure" and store it as "apiName"
    And I generate a unique API version from "bedrock-error-structure" and store it as "apiVersion"
    And I generate a unique API context from "/bedrock-error-structure" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName}                    |
      | spec.displayName       | ${CTX:apiName}                    |
      | spec.version           | ${CTX:apiVersion}                 |
      | spec.context           | ${CTX:apiContext}/$version        |
      | spec.upstream.main.url | http://testbench:3002              |
      | spec.operations        | [{"method":"POST","path":"/validate","policies":[{"name":"aws-bedrock-guardrail","version":"v1","params":{"region":"us-east-1","guardrailID":"test-guardrail-id","guardrailVersion":"DRAFT","awsAuth":{"authenticationType":"iam-user-access-key","awsAccessKeyID":"AKIAIOSFODNN7TEST","awsSecretAccessKey":"testsecretaccesskeytestsecretaccesskey1"},"response":{"enabled":true,"jsonPath":"","showAssessment":true}}}]},{"method":"GET","path":"/health"}] |
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I set header "Content-Type" to "application/json"
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/validate" with body:
      """
      {"message":"This contains hate speech"}
      """
    Then the response status code should be 422
    And the response should be valid JSON
    And the JSON response field "type" should be "AWS_BEDROCK_GUARDRAIL"
    And the JSON response field "message.action" should be "GUARDRAIL_INTERVENED"
    And the JSON response field "message.interveningGuardrail" should be "AWS Bedrock Guardrail"
    And the JSON response field "message.actionReason" should be "Violation of AWS Bedrock Guardrail detected."
    And the JSON response field "message.direction" should be "RESPONSE"
    And the JSON response field "message.assessments.contentPolicy.filters[0].type" should be "VIOLENCE"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
