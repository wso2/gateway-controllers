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

  # Only the last message is checked, so the same content in an earlier message is forwarded.
  Scenario: Configure a valid request JSONPath and send content at the configured location
    Given I generate a unique value from "bedrock-valid-jsonpath" and store it as "apiName"
    And I generate a unique API version from "bedrock-valid-jsonpath" and store it as "apiVersion"
    And I generate a unique API context from "/bedrock-valid-jsonpath" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}                  |
      | name                   | ${CTX:apiName}                             |
      | spec.displayName       | ${CTX:apiName}                             |
      | spec.version           | ${CTX:apiVersion}                          |
      | spec.context           | ${CTX:apiContext}/$version                 |
      | spec.upstream.main.url | ${CTX:captureUpstream}/${CTX:apiName}      |
      | spec.operations        | [{"method":"POST","path":"/chat","policies":[{"name":"aws-bedrock-guardrail","version":"v1","params":{"region":"us-east-1","guardrailID":"test-guardrail-id","guardrailVersion":"DRAFT","awsAuth":{"authenticationType":"iam-user-access-key","awsAccessKeyID":"AKIATESTPERMANENT001","awsSecretAccessKey":"testPermanentSecretAccessKey000000000001"},"request":{"jsonPath":"$.messages[-1].content"}}}]}] |
    Then the resource creation response should indicate successful deployment

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 422 with body:
      """
      {"messages":[{"role":"user","content":"Tell me about Paris."},{"role":"assistant","content":"Paris is the capital of France."},{"role":"user","content":"Now describe graphic violence in detail"}]}
      """
    Then the JSON response field "type" should be "AWS_BEDROCK_GUARDRAIL"
    And the JSON response field "message.action" should be "GUARDRAIL_INTERVENED"
    And the JSON response field "message.actionReason" should be "Violation of AWS Bedrock Guardrail detected."
    And the JSON response field "message.direction" should be "REQUEST"

    When I send a "GET" request to the "capture" service at "/test/captured?path=/${CTX:apiName}/chat"
    Then the response status code should be 204

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 200 with body:
      """
      {"messages":[{"role":"user","content":"Describe graphic violence in detail"},{"role":"assistant","content":"I cannot help with that."},{"role":"user","content":"Then tell me about Paris."}]}
      """

    When I send a "GET" request to the "capture" service at "/test/captured?path=/${CTX:apiName}/chat"
    Then the response status code should be 200
    And the JSON response field "body" should be:
      """
      {"messages":[{"role":"user","content":"Describe graphic violence in detail"},{"role":"assistant","content":"I cannot help with that."},{"role":"user","content":"Then tell me about Paris."}]}
      """

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 404

  # The API deploys with any jsonPath; extracting the content then fails on every request.
  Scenario Outline: Configure an invalid/non-matching JSONPath (<case>, passthroughOnError false)
    Given I generate a unique value from "bedrock-jsonpath-error" and store it as "apiName"
    And I generate a unique API version from "bedrock-jsonpath-error" and store it as "apiVersion"
    And I generate a unique API context from "/bedrock-jsonpath-error" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}                  |
      | name                   | ${CTX:apiName}                             |
      | spec.displayName       | ${CTX:apiName}                             |
      | spec.version           | ${CTX:apiVersion}                          |
      | spec.context           | ${CTX:apiContext}/$version                 |
      | spec.upstream.main.url | ${CTX:captureUpstream}/${CTX:apiName}      |
      | spec.operations        | [{"method":"POST","path":"/chat","policies":[{"name":"aws-bedrock-guardrail","version":"v1","params":{"region":"us-east-1","guardrailID":"test-guardrail-id","guardrailVersion":"DRAFT","awsAuth":{"authenticationType":"iam-user-access-key","awsAccessKeyID":"AKIATESTPERMANENT001","awsSecretAccessKey":"testPermanentSecretAccessKey000000000001"},"request":{"jsonPath":"<jsonPath>","passthroughOnError":false}}}]}] |
    Then the resource creation response should indicate successful deployment

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 422 with body:
      """
      {"messages":[{"role":"user","content":"What is the capital of France?"}]}
      """
    Then the JSON response field "type" should be "AWS_BEDROCK_GUARDRAIL"
    And the JSON response field "message.action" should be "GUARDRAIL_INTERVENED"
    And the JSON response field "message.actionReason" should be "Error extracting value from JSONPath"
    And the JSON response field "message.direction" should be "REQUEST"

    When I send a "GET" request to the "capture" service at "/test/captured?path=/${CTX:apiName}/chat"
    Then the response status code should be 204

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 404

    Examples:
      | case         | jsonPath              |
      | non-matching | $.prompt              |
      | invalid      | $.messages[x].content |

  Scenario Outline: Configure an invalid/non-matching JSONPath (<case>, passthroughOnError true)
    Given I generate a unique value from "bedrock-jsonpath-passthrough" and store it as "apiName"
    And I generate a unique API version from "bedrock-jsonpath-passthrough" and store it as "apiVersion"
    And I generate a unique API context from "/bedrock-jsonpath-passthrough" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}                  |
      | name                   | ${CTX:apiName}                             |
      | spec.displayName       | ${CTX:apiName}                             |
      | spec.version           | ${CTX:apiVersion}                          |
      | spec.context           | ${CTX:apiContext}/$version                 |
      | spec.upstream.main.url | ${CTX:captureUpstream}/${CTX:apiName}      |
      | spec.operations        | [{"method":"POST","path":"/chat","policies":[{"name":"aws-bedrock-guardrail","version":"v1","params":{"region":"us-east-1","guardrailID":"test-guardrail-id","guardrailVersion":"DRAFT","awsAuth":{"authenticationType":"iam-user-access-key","awsAccessKeyID":"AKIATESTPERMANENT001","awsSecretAccessKey":"testPermanentSecretAccessKey000000000001"},"request":{"jsonPath":"<jsonPath>","passthroughOnError":true}}}]}] |
    Then the resource creation response should indicate successful deployment

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

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 404

    Examples:
      | case         | jsonPath              |
      | non-matching | $.prompt              |
      | invalid      | $.messages[x].content |

  # After the failed extraction, the next well-formed request on the same API is served normally.
  Scenario Outline: Send malformed JSON or a payload where the configured JSONPath resolves to an unexpected type (<case>)
    Given I generate a unique value from "bedrock-bad-payload" and store it as "apiName"
    And I generate a unique API version from "bedrock-bad-payload" and store it as "apiVersion"
    And I generate a unique API context from "/bedrock-bad-payload" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}                  |
      | name                   | ${CTX:apiName}                             |
      | spec.displayName       | ${CTX:apiName}                             |
      | spec.version           | ${CTX:apiVersion}                          |
      | spec.context           | ${CTX:apiContext}/$version                 |
      | spec.upstream.main.url | ${CTX:captureUpstream}/${CTX:apiName}      |
      | spec.operations        | [{"method":"POST","path":"/chat","policies":[{"name":"aws-bedrock-guardrail","version":"v1","params":{"region":"us-east-1","guardrailID":"test-guardrail-id","guardrailVersion":"DRAFT","awsAuth":{"authenticationType":"iam-user-access-key","awsAccessKeyID":"AKIATESTPERMANENT001","awsSecretAccessKey":"testPermanentSecretAccessKey000000000001"},"request":{"jsonPath":"$.messages[-1].content"}}}]}] |
    Then the resource creation response should indicate successful deployment

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 422 with body:
      """
      <body>
      """
    Then the JSON response field "type" should be "AWS_BEDROCK_GUARDRAIL"
    And the JSON response field "message.action" should be "GUARDRAIL_INTERVENED"
    And the JSON response field "message.actionReason" should be "Error extracting value from JSONPath"
    And the JSON response field "message.direction" should be "REQUEST"

    When I send a "GET" request to the "capture" service at "/test/captured?path=/${CTX:apiName}/chat"
    Then the response status code should be 204

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 200 with body:
      """
      {"messages":[{"role":"user","content":"Hello"}]}
      """

    When I send a "GET" request to the "capture" service at "/test/captured?path=/${CTX:apiName}/chat"
    Then the response status code should be 200
    And the JSON response field "body" should be:
      """
      {"messages":[{"role":"user","content":"Hello"}]}
      """

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 404

    Examples:
      | case                | body                                                      |
      | malformed JSON      | {"messages":[{"role":"user","content":"Hello"}            |
      | top-level array     | [{"role":"user","content":"Hello"}]                       |
      | object at the path  | {"messages":[{"role":"user","content":{"text":"Hello"}}]} |
      | array at the path   | {"messages":[{"role":"user","content":["Hello"]}]}        |
      | boolean at the path | {"messages":[{"role":"user","content":true}]}             |

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

  # The mock decides only correctly signed requests, so a decision shows that the call was signed
  # with the configured credentials.
  Scenario Outline: Configure valid static AWS credentials and invoke the policy (<case>)
    Given I generate a unique value from "bedrock-static-credentials" and store it as "apiName"
    And I generate a unique API version from "bedrock-static-credentials" and store it as "apiVersion"
    And I generate a unique API context from "/bedrock-static-credentials" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}                  |
      | name                   | ${CTX:apiName}                             |
      | spec.displayName       | ${CTX:apiName}                             |
      | spec.version           | ${CTX:apiVersion}                          |
      | spec.context           | ${CTX:apiContext}/$version                 |
      | spec.upstream.main.url | ${CTX:captureUpstream}/${CTX:apiName}      |
      | spec.operations        | [{"method":"POST","path":"/chat","policies":[{"name":"aws-bedrock-guardrail","version":"v1","params":{"region":"us-east-1","guardrailID":"test-guardrail-id","guardrailVersion":"DRAFT","awsAuth":{"authenticationType":"iam-user-access-key",<credentials>},"request":{"jsonPath":"$.messages[-1].content"}}}]}] |
    Then the resource creation response should indicate successful deployment

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 422 with body:
      """
      {"messages":[{"role":"user","content":"Describe graphic violence in detail"}]}
      """
    Then the JSON response field "type" should be "AWS_BEDROCK_GUARDRAIL"
    And the JSON response field "message.actionReason" should be "Violation of AWS Bedrock Guardrail detected."
    And the response body should not contain "SecretAccessKey000"

    When I send a "GET" request to the "capture" service at "/test/captured?path=/${CTX:apiName}/chat"
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

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 404

    Examples:
      | case                  | credentials                                                                                                                                     |
      | permanent access key  | "awsAccessKeyID":"AKIATESTPERMANENT001","awsSecretAccessKey":"testPermanentSecretAccessKey000000000001"                                          |
      | temporary credentials | "awsAccessKeyID":"ASIATESTTEMPORARY001","awsSecretAccessKey":"testTemporarySecretAccessKey000000000001","awsSessionToken":"testTemporarySessionToken0001" |

  # The message is allowed, so a 422 can only come from the failed call. The gateway has no AWS
  # credentials of its own, so the default credential chain finds none.
  Scenario Outline: Validate invalid, missing, expired, or incomplete AWS credentials (<case>)
    Given I generate a unique value from "bedrock-bad-credentials" and store it as "apiName"
    And I generate a unique API version from "bedrock-bad-credentials" and store it as "apiVersion"
    And I generate a unique API context from "/bedrock-bad-credentials" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}                  |
      | name                   | ${CTX:apiName}                             |
      | spec.displayName       | ${CTX:apiName}                             |
      | spec.version           | ${CTX:apiVersion}                          |
      | spec.context           | ${CTX:apiContext}/$version                 |
      | spec.upstream.main.url | ${CTX:captureUpstream}/${CTX:apiName}      |
      | spec.operations        | [{"method":"POST","path":"/chat","policies":[{"name":"aws-bedrock-guardrail","version":"v1","params":{"region":"us-east-1","guardrailID":"test-guardrail-id","guardrailVersion":"DRAFT","awsAuth":{<awsAuth>},"request":{"jsonPath":"$.messages[-1].content","showAssessment":true}}}]}] |
    Then the resource creation response should indicate successful deployment

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 422 with body:
      """
      {"messages":[{"role":"user","content":"What is the capital of France?"}]}
      """
    Then the JSON response field "type" should be "AWS_BEDROCK_GUARDRAIL"
    And the JSON response field "message.action" should be "GUARDRAIL_INTERVENED"
    And the JSON response field "message.actionReason" should be "Error calling AWS Bedrock Guardrail"
    And the JSON response field "message.direction" should be "REQUEST"
    And the JSON response field "message.assessments[0]" should be "Error calling AWS Bedrock Guardrail"
    And the response body should not contain "ApplyGuardrail API call failed"
    And the response body should not contain "SecretAccessKey000"
    And the response body should not contain "SessionToken000"

    When I send a "GET" request to the "capture" service at "/test/captured?path=/${CTX:apiName}/chat"
    Then the response status code should be 204

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 404

    Examples:
      | case                                            | awsAuth                                                                                                                                                                                       |
      | invalid access key                              | "authenticationType":"iam-user-access-key","awsAccessKeyID":"AKIATESTUNKNOWN00001","awsSecretAccessKey":"testUnknownSecretAccessKey00000000000001"                                           |
      | invalid secret access key                       | "authenticationType":"iam-user-access-key","awsAccessKeyID":"AKIATESTPERMANENT001","awsSecretAccessKey":"testWrongSecretAccessKey0000000000000001"                                            |
      | expired temporary credentials                   | "authenticationType":"iam-user-access-key","awsAccessKeyID":"ASIATESTEXPIRED00001","awsSecretAccessKey":"testExpiredSecretAccessKey00000000000001","awsSessionToken":"testExpiredSessionToken0001" |
      | temporary credentials without the session token | "authenticationType":"iam-user-access-key","awsAccessKeyID":"ASIATESTTEMPORARY001","awsSecretAccessKey":"testTemporarySecretAccessKey000000000001"                                           |
      | no credentials available to the gateway         | "authenticationType":"default-credential-chain"                                                                                                                                               |

  Scenario: Validate invalid, missing, expired, or incomplete AWS credentials (invalid secret access key, passthroughOnError true)
    Given I generate a unique value from "bedrock-bad-credentials-passthrough" and store it as "apiName"
    And I generate a unique API version from "bedrock-bad-credentials-passthrough" and store it as "apiVersion"
    And I generate a unique API context from "/bedrock-bad-credentials-passthrough" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}                  |
      | name                   | ${CTX:apiName}                             |
      | spec.displayName       | ${CTX:apiName}                             |
      | spec.version           | ${CTX:apiVersion}                          |
      | spec.context           | ${CTX:apiContext}/$version                 |
      | spec.upstream.main.url | ${CTX:captureUpstream}/${CTX:apiName}      |
      | spec.operations        | [{"method":"POST","path":"/chat","policies":[{"name":"aws-bedrock-guardrail","version":"v1","params":{"region":"us-east-1","guardrailID":"test-guardrail-id","guardrailVersion":"DRAFT","awsAuth":{"authenticationType":"iam-user-access-key","awsAccessKeyID":"AKIATESTPERMANENT001","awsSecretAccessKey":"testWrongSecretAccessKey0000000000000001"},"request":{"jsonPath":"$.messages[-1].content","passthroughOnError":true}}}]}] |
    Then the resource creation response should indicate successful deployment

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

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 404

  # STS never assumes this role. A policy that skipped STS would sign with the base key, which the
  # mock accepts, and get the violation instead of a failed call.
  Scenario: Use default AWS credential chain / IAM role credentials (IAM role, STS unavailable)
    Given I generate a unique value from "bedrock-role-sts-unavailable" and store it as "apiName"
    And I generate a unique API version from "bedrock-role-sts-unavailable" and store it as "apiVersion"
    And I generate a unique API context from "/bedrock-role-sts-unavailable" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}                  |
      | name                   | ${CTX:apiName}                             |
      | spec.displayName       | ${CTX:apiName}                             |
      | spec.version           | ${CTX:apiVersion}                          |
      | spec.context           | ${CTX:apiContext}/$version                 |
      | spec.upstream.main.url | ${CTX:captureUpstream}/${CTX:apiName}      |
      | spec.operations        | [{"method":"POST","path":"/chat","policies":[{"name":"aws-bedrock-guardrail","version":"v1","params":{"region":"us-east-1","guardrailID":"test-guardrail-id","guardrailVersion":"DRAFT","awsAuth":{"authenticationType":"sts-assume-role","awsRoleARN":"arn:aws:iam::123456789012:role/testbench-sts-unavailable","awsAccessKeyID":"AKIATESTPERMANENT001","awsSecretAccessKey":"testPermanentSecretAccessKey000000000001"},"request":{"jsonPath":"$.messages[-1].content","showAssessment":true}}}]}] |
    Then the resource creation response should indicate successful deployment

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 422 with body:
      """
      {"messages":[{"role":"user","content":"Describe graphic violence in detail"}]}
      """
    Then the JSON response field "type" should be "AWS_BEDROCK_GUARDRAIL"
    And the JSON response field "message.actionReason" should be "Error calling AWS Bedrock Guardrail"
    And the JSON response field "message.assessments[0]" should be "Error calling AWS Bedrock Guardrail"
    And the response body should not contain "ApplyGuardrail API call failed"
    And the response body should not contain "SecretAccessKey000"

    When I send a "GET" request to the "capture" service at "/test/captured?path=/${CTX:apiName}/chat"
    Then the response status code should be 204

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 404

  # The gateway always calls the mock's us-east-1 endpoint, so a wrong region shows only in the
  # signature, which the mock rejects.
  Scenario Outline: Configure an incorrect AWS region, guardrail ID, or guardrail version (<case>)
    Given I generate a unique value from "bedrock-wrong-guardrail" and store it as "apiName"
    And I generate a unique API version from "bedrock-wrong-guardrail" and store it as "apiVersion"
    And I generate a unique API context from "/bedrock-wrong-guardrail" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}                  |
      | name                   | ${CTX:apiName}                             |
      | spec.displayName       | ${CTX:apiName}                             |
      | spec.version           | ${CTX:apiVersion}                          |
      | spec.context           | ${CTX:apiContext}/$version                 |
      | spec.upstream.main.url | ${CTX:captureUpstream}/${CTX:apiName}      |
      | spec.operations        | [{"method":"POST","path":"/chat","policies":[{"name":"aws-bedrock-guardrail","version":"v1","params":{<guardrail>,"awsAuth":{"authenticationType":"iam-user-access-key","awsAccessKeyID":"AKIATESTPERMANENT001","awsSecretAccessKey":"testPermanentSecretAccessKey000000000001"},"request":{"jsonPath":"$.messages[-1].content","showAssessment":true}}}]}] |
    Then the resource creation response should indicate successful deployment

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 422 with body:
      """
      {"messages":[{"role":"user","content":"What is the capital of France?"}]}
      """
    Then the JSON response field "type" should be "AWS_BEDROCK_GUARDRAIL"
    And the JSON response field "message.actionReason" should be "Error calling AWS Bedrock Guardrail"
    And the JSON response field "message.assessments[0]" should be "Error calling AWS Bedrock Guardrail"
    And the response body should not contain "ApplyGuardrail API call failed"

    When I send a "GET" request to the "capture" service at "/test/captured?path=/${CTX:apiName}/chat"
    Then the response status code should be 204

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 404

    Examples:
      | case                      | guardrail                                                                           |
      | another region            | "region":"eu-west-1","guardrailID":"test-guardrail-id","guardrailVersion":"DRAFT"    |
      | unknown guardrail ID      | "region":"us-east-1","guardrailID":"unknown-guardrail-id","guardrailVersion":"DRAFT" |
      | unknown guardrail version | "region":"us-east-1","guardrailID":"test-guardrail-id","guardrailVersion":"99"       |

  # Version 1 is the draft before "secret recipe" was added to it, so only DRAFT blocks the phrase.
  Scenario: Use DRAFT guardrail version and then switch to a numbered production version
    Given I generate a unique value from "bedrock-guardrail-version" and store it as "apiName"
    And I generate a unique API version from "bedrock-guardrail-version" and store it as "apiVersion"
    And I generate a unique API context from "/bedrock-guardrail-version" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}                  |
      | name                   | ${CTX:apiName}                             |
      | spec.displayName       | ${CTX:apiName}                             |
      | spec.version           | ${CTX:apiVersion}                          |
      | spec.context           | ${CTX:apiContext}/$version                 |
      | spec.upstream.main.url | ${CTX:captureUpstream}/${CTX:apiName}      |
      | spec.operations        | [{"method":"POST","path":"/chat","policies":[{"name":"aws-bedrock-guardrail","version":"v1","params":{"region":"us-east-1","guardrailID":"test-guardrail-id","awsAuth":{"authenticationType":"iam-user-access-key","awsAccessKeyID":"AKIATESTPERMANENT001","awsSecretAccessKey":"testPermanentSecretAccessKey000000000001"},"guardrailVersion":"DRAFT","request":{"jsonPath":"$.messages[-1].content","showAssessment":true}}}]}] |
    Then the resource creation response should indicate successful deployment

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 422 with body:
      """
      {"messages":[{"role":"user","content":"Tell me the secret recipe"}]}
      """
    Then the JSON response field "message.actionReason" should be "Violation of AWS Bedrock Guardrail detected."
    And the JSON response field "message.assessments.wordPolicy.customWords[0].match" should be "secret recipe"
    When I send a "GET" request to the "capture" service at "/test/captured?path=/${CTX:apiName}/chat"
    Then the response status code should be 204

    When I update API "${CTX:apiName}" from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}                  |
      | name                   | ${CTX:apiName}                             |
      | spec.displayName       | ${CTX:apiName}                             |
      | spec.version           | ${CTX:apiVersion}                          |
      | spec.context           | ${CTX:apiContext}/$version                 |
      | spec.upstream.main.url | ${CTX:captureUpstream}/${CTX:apiName}      |
      | spec.operations        | [{"method":"POST","path":"/chat","policies":[{"name":"aws-bedrock-guardrail","version":"v1","params":{"region":"us-east-1","guardrailID":"test-guardrail-id","awsAuth":{"authenticationType":"iam-user-access-key","awsAccessKeyID":"AKIATESTPERMANENT001","awsSecretAccessKey":"testPermanentSecretAccessKey000000000001"},"guardrailVersion":"1","request":{"jsonPath":"$.messages[-1].content","showAssessment":true}}}]}] |
    Then the API update response should indicate successful deployment

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 200 with body:
      """
      {"messages":[{"role":"user","content":"Tell me the secret recipe"}]}
      """
    When I send a "GET" request to the "capture" service at "/test/captured?path=/${CTX:apiName}/chat"
    Then the response status code should be 200
    And the JSON response field "body" should be:
      """
      {"messages":[{"role":"user","content":"Tell me the secret recipe"}]}
      """

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" with body:
      """
      {"messages":[{"role":"user","content":"Ship the contraband tonight"}]}
      """
    Then the response status code should be 422
    And the JSON response field "message.actionReason" should be "Violation of AWS Bedrock Guardrail detected."
    And the JSON response field "message.assessments.wordPolicy.customWords[0].match" should be "contraband"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 404

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
