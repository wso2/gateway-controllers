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
Feature: AWS Authentication policy with gateway workload credentials
  As an API developer
  I want the gateway to sign with the AWS credentials of the environment it runs in
  So that no AWS credentials need to be configured on the API

  # The default credential chain when the gateway runtime has AWS workload credentials
  # (AKIATESTWORKLOAD0001). It runs in a block whose gateway runtime has them, a setting that
  # applies to every runner in the block. The same scenario with no credentials available is in
  # aws_authentication.feature.

  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"

  # The API configures no credentials, so the gateway signs with whatever the AWS SDK default
  # credential chain resolves in the gateway runtime.
  Scenario: Validate default-credential-chain with valid workload credentials and with no credentials available (valid workload credentials)
    Given I generate a unique value from "aws-auth-chain" and store it as "apiName"
    And I generate a unique API version from "aws-auth-chain" and store it as "apiVersion"
    And I generate a unique API context from "/aws-auth-chain" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}                    |
      | name                   | ${CTX:apiName}                               |
      | spec.displayName       | ${CTX:apiName}                               |
      | spec.version           | ${CTX:apiVersion}                            |
      | spec.context           | ${CTX:apiContext}/$version                   |
      | spec.upstream.main.url | http://testbench/execute-api/us-east-1       |
      | spec.policies          | [{"name":"aws-authentication","version":"v0","params":{"service":"execute-api","region":"us-east-1","authenticationType":"default-credential-chain"}}] |
      | spec.operations        | [{"method":"GET","path":"/items"}]           |
    Then the response should be successful

    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/items" until status 200
    Then the response header "Content-Type" should contain "application/json"
    And the response header "X-Aws-Access-Key-Id" should be "AKIATESTWORKLOAD0001"
    And the response body should not contain "SecretAccessKey000"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/items" until status 404
