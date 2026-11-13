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
Feature: AWS Bedrock guardrail policy credentials
  As an API developer
  I want the guardrail to be called with the AWS credentials configured on the API
  So that invalid credentials never let content through unchecked

  # Each API forwards to a capture service that records what reaches it. The Bedrock mock blocks
  # violence, "investment advice", "contraband" and "secret recipe", finds example.com emails,
  # phone numbers and SSNs as PII, and answers only requests signed with a fixture credential.

  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"
    And I resolve the "capture" service URL at "" and store it as "captureUpstream"

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
