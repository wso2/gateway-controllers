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
Feature: AWS Authentication policy timeouts
  As an API developer
  I want a request whose AWS signing cannot complete in time to fail at the gateway
  So that a slow credential source never lets a request reach the backend unsigned

  # Credential retrieval that takes longer than the gateway allows for policy processing. It runs
  # in a block whose gateway answers a request itself after 5 seconds of policy processing,
  # instead of the default 60. The testbench STS never answers a request to assume
  # testbench-sts-unresponsive.

  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"

  # The policy obtains temporary credentials from STS before it signs, and STS never answers, so
  # the policy cannot finish. After 5 seconds the gateway stops waiting for the policy and
  # answers 504 itself instead of forwarding the request unsigned. The backend would reflect a
  # forwarded request with the X-Aws-Access-Key-Id header, or reject an unsigned one with 403.
  Scenario: Make credential retrieval or policy execution unavailable or force a timeout (timeout)
    Given I generate a unique value from "aws-auth-timeout" and store it as "apiName"
    And I generate a unique API version from "aws-auth-timeout" and store it as "apiVersion"
    And I generate a unique API context from "/aws-auth-timeout" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}                    |
      | name                   | ${CTX:apiName}                               |
      | spec.displayName       | ${CTX:apiName}                               |
      | spec.version           | ${CTX:apiVersion}                            |
      | spec.context           | ${CTX:apiContext}/$version                   |
      | spec.upstream.main.url | http://testbench/execute-api/us-east-1       |
      | spec.policies          | [{"name":"aws-authentication","version":"v0","params":{"service":"execute-api","region":"us-east-1","authenticationType":"sts-assume-role","awsAccessKeyID":"AKIATESTPERMANENT001","awsSecretAccessKey":"testPermanentSecretAccessKey000000000001","awsRoleARN":"arn:aws:iam::123456789012:role/testbench-sts-unresponsive"}}] |
      | spec.operations        | [{"method":"GET","path":"/items"}]           |
    Then the response should be successful

    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/items" until it times out after "5" seconds with status 504
    Then the response header "X-Aws-Access-Key-Id" should not exist
    And the response body should not contain "SecretAccessKey000"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/items" until status 404
