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
Feature: AWS Bedrock guardrail policy configuration validation
  As an API developer
  I want invalid AWS Bedrock guardrail configurations to be rejected
  So that an API whose guardrail could never be called is never deployed

  # Configurations rejected when the API is created, from the policy's parameter schema.

  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"

  Scenario Outline: Validate invalid, missing, expired, or incomplete AWS credentials (<case>, rejected at creation)
    Given I generate a unique value from "bedrock-incomplete-credentials" and store it as "apiName"
    And I generate a unique API version from "bedrock-incomplete-credentials" and store it as "apiVersion"
    And I generate a unique API context from "/bedrock-incomplete-credentials" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}                  |
      | name                   | ${CTX:apiName}                             |
      | spec.displayName       | ${CTX:apiName}                             |
      | spec.version           | ${CTX:apiVersion}                          |
      | spec.context           | ${CTX:apiContext}/$version                 |
      | spec.upstream.main.url | http://testbench:3002                      |
      | spec.operations        | [{"method":"POST","path":"/chat","policies":[{"name":"aws-bedrock-guardrail","version":"v1","params":{"region":"us-east-1","guardrailID":"test-guardrail-id","guardrailVersion":"DRAFT","awsAuth":{"authenticationType":"iam-user-access-key"<credentials>},"request":{"jsonPath":"$.messages[-1].content"}}}]}] |
    Then the response status code should be 400
    And the response should be valid JSON
    And the JSON response field "status" should be "error"
    And the response body should contain "Configuration validation failed"
    And the response body should contain "<error>"
    And the response body should not contain "SecretAccessKey000"

    Examples:
      | case                            | credentials                                                                                              | error                          |
      | no access key or secret         |                                                                                                          | awsAccessKeyID is required     |
      | access key without its secret   | ,"awsAccessKeyID":"AKIATESTPERMANENT001"                                                                 | awsSecretAccessKey is required |
      | secret without its access key   | ,"awsSecretAccessKey":"testPermanentSecretAccessKey000000000001"                                         | awsAccessKeyID is required     |

  Scenario Outline: Configure an incorrect AWS region, guardrail ID, or guardrail version (<case>, rejected at creation)
    Given I generate a unique value from "bedrock-invalid-guardrail" and store it as "apiName"
    And I generate a unique API version from "bedrock-invalid-guardrail" and store it as "apiVersion"
    And I generate a unique API context from "/bedrock-invalid-guardrail" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}                  |
      | name                   | ${CTX:apiName}                             |
      | spec.displayName       | ${CTX:apiName}                             |
      | spec.version           | ${CTX:apiVersion}                          |
      | spec.context           | ${CTX:apiContext}/$version                 |
      | spec.upstream.main.url | http://testbench:3002                      |
      | spec.operations        | [{"method":"POST","path":"/chat","policies":[{"name":"aws-bedrock-guardrail","version":"v1","params":{<guardrail>,"awsAuth":{"authenticationType":"iam-user-access-key","awsAccessKeyID":"AKIATESTPERMANENT001","awsSecretAccessKey":"testPermanentSecretAccessKey000000000001"},"request":{"jsonPath":"$.messages[-1].content"}}}]}] |
    Then the response status code should be 400
    And the response should be valid JSON
    And the JSON response field "status" should be "error"
    And the response body should contain "Configuration validation failed"
    And the response body should contain "<field>"
    And the response body should contain "<error>"

    Examples:
      | case                     | guardrail                                                                         | field            | error                                             |
      | malformed region         | "region":"US-East-1","guardrailID":"test-guardrail-id","guardrailVersion":"DRAFT" | region           | Does not match pattern                            |
      | empty guardrail ID       | "region":"us-east-1","guardrailID":"","guardrailVersion":"DRAFT"                  | guardrailID      | String length must be greater than or equal to 1 |
      | empty guardrail version  | "region":"us-east-1","guardrailID":"test-guardrail-id","guardrailVersion":""      | guardrailVersion | String length must be greater than or equal to 1 |
