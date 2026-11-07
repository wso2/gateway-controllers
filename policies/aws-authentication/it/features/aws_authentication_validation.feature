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

@aws-authentication
Feature: AWS Authentication policy configuration validation
  As an API developer
  I want invalid AWS Authentication configurations to be rejected
  So that an API that could never be signed correctly is never deployed

  # Configurations the gateway rejects when the API is created: empty permanent IAM credentials,
  # and policy parameters or a policy version that do not match the policy definition. The
  # credentials it accepts, including missing and whitespace-only ones, are in
  # aws_authentication.feature. Every fixture secret contains "SecretAccessKey000", so a response
  # without it discloses no secret.

  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"

  Scenario Outline: Validate permanent IAM credentials with valid, invalid, missing, and empty access key/secret combinations (<case>)
    Given I generate a unique value from "aws-auth-iam-empty" and store it as "apiName"
    And I generate a unique API version from "aws-auth-iam-empty" and store it as "apiVersion"
    And I generate a unique API context from "/aws-auth-iam-empty" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}                    |
      | name                   | ${CTX:apiName}                               |
      | spec.displayName       | ${CTX:apiName}                               |
      | spec.version           | ${CTX:apiVersion}                            |
      | spec.context           | ${CTX:apiContext}/$version                   |
      | spec.upstream.main.url | http://testbench/execute-api/us-east-1       |
      | spec.policies          | [{"name":"aws-authentication","version":"v0","params":{"service":"execute-api","region":"us-east-1","authenticationType":"iam-user-access-key","awsAccessKeyID":"<accessKeyID>","awsSecretAccessKey":"<secretAccessKey>"}}] |
      | spec.operations        | [{"method":"GET","path":"/items"}]           |
    Then the response status code should be 400
    And the response should be valid JSON
    And the JSON response field "status" should be "error"
    And the response body should contain "Configuration validation failed"
    And the response body should contain "String length must be greater than or equal to 1"
    And the response body should not contain "SecretAccessKey000"

    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/items"
    Then the response status code should be 404

    Examples:
      | case                         | accessKeyID          | secretAccessKey                          |
      | an empty access key ID       |                      | testPermanentSecretAccessKey000000000001 |
      | an empty secret access key   | AKIATESTPERMANENT001 |                                          |

  # The controller validates the policy reference and its parameters against the policy
  # definition: service, region and authenticationType are required strings, authenticationType
  # is one of sts-assume-role, iam-user-access-key, irsa and default-credential-chain, and the
  # policy version must be a major version the gateway has loaded. Each configuration below is
  # otherwise valid.
  Scenario Outline: Validate invalid policy configuration, including missing service/region, unsupported authentication type, wrong parameter type, and unsupported policy version (<case>)
    Given I generate a unique value from "aws-auth-invalid-config" and store it as "apiName"
    And I generate a unique API version from "aws-auth-invalid-config" and store it as "apiVersion"
    And I generate a unique API context from "/aws-auth-invalid-config" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}                    |
      | name                   | ${CTX:apiName}                               |
      | spec.displayName       | ${CTX:apiName}                               |
      | spec.version           | ${CTX:apiVersion}                            |
      | spec.context           | ${CTX:apiContext}/$version                   |
      | spec.upstream.main.url | http://testbench/execute-api/us-east-1       |
      | spec.policies          | [{"name":"aws-authentication","version":"<version>","params":{<params>"awsAccessKeyID":"AKIATESTPERMANENT001","awsSecretAccessKey":"testPermanentSecretAccessKey000000000001"}}] |
      | spec.operations        | [{"method":"GET","path":"/items"}]           |
    Then the response status code should be 400
    And the response should be valid JSON
    And the JSON response field "status" should be "error"
    And the response body should contain "Configuration validation failed"
    And the response body should contain "<error>"
    And the response body should not contain "SecretAccessKey000"

    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/items"
    Then the response status code should be 404

    Examples:
      | case                            | version | params                                                                                     | error                                                      |
      | missing service                 | v0      | "region":"us-east-1","authenticationType":"iam-user-access-key",                           | service is required                                        |
      | missing region                  | v0      | "service":"execute-api","authenticationType":"iam-user-access-key",                        | region is required                                         |
      | unsupported authentication type | v0      | "service":"execute-api","region":"us-east-1","authenticationType":"access-key",            | authenticationType must be one of the following            |
      | wrong parameter type            | v0      | "service":"execute-api","region":["us-east-1"],"authenticationType":"iam-user-access-key", | Invalid type. Expected: string, given: array               |
      | unsupported policy version      | v99     | "service":"execute-api","region":"us-east-1","authenticationType":"iam-user-access-key",   | major version 'v99' not found in loaded policy definitions |
