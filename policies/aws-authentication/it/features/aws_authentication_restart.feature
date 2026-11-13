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
Feature: AWS Authentication policy across gateway restarts
  As an API developer
  I want AWS-signed APIs to keep working when gateway services restart
  So that a restart does not interrupt access to AWS-hosted backends

  # Restarting the gateway controller and the gateway runtime. It runs in a block of its own,
  # because a restart would interrupt any runner beside it. Gateway replicas are not covered: the
  # framework's replicas are independent gateways, and its API management steps reach only the
  # first one.

  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"

  # One API signs with a permanent access key and the other with credentials from STS
  # AssumeRole. The restarted gateway runtime builds the policies again, so the second API also
  # shows the runtime obtains new temporary credentials after a restart.
  Scenario: Restart controller and runtime with access key and STS credentials
    Given I generate a unique value from "aws-auth-restart-key" and store it as "keyApiName"
    And I generate a unique API version from "aws-auth-restart-key" and store it as "keyApiVersion"
    And I generate a unique API context from "/aws-auth-restart-key" and store it as "keyApiContext"
    And I generate a unique value from "aws-auth-restart-sts" and store it as "stsApiName"
    And I generate a unique API version from "aws-auth-restart-sts" and store it as "stsApiVersion"
    And I generate a unique API context from "/aws-auth-restart-sts" and store it as "stsApiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}                    |
      | name                   | ${CTX:keyApiName}                            |
      | spec.displayName       | ${CTX:keyApiName}                            |
      | spec.version           | ${CTX:keyApiVersion}                         |
      | spec.context           | ${CTX:keyApiContext}/$version                |
      | spec.upstream.main.url | http://testbench/execute-api/us-east-1       |
      | spec.policies          | [{"name":"aws-authentication","version":"v0","params":{"service":"execute-api","region":"us-east-1","authenticationType":"iam-user-access-key","awsAccessKeyID":"AKIATESTPERMANENT001","awsSecretAccessKey":"testPermanentSecretAccessKey000000000001"}}] |
      | spec.operations        | [{"method":"GET","path":"/items"}]           |
    Then the response should be successful
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}                    |
      | name                   | ${CTX:stsApiName}                            |
      | spec.displayName       | ${CTX:stsApiName}                            |
      | spec.version           | ${CTX:stsApiVersion}                         |
      | spec.context           | ${CTX:stsApiContext}/$version                |
      | spec.upstream.main.url | http://testbench/execute-api/us-east-1       |
      | spec.policies          | [{"name":"aws-authentication","version":"v0","params":{"service":"execute-api","region":"us-east-1","authenticationType":"sts-assume-role","awsAccessKeyID":"AKIATESTPERMANENT001","awsSecretAccessKey":"testPermanentSecretAccessKey000000000001","awsRoleARN":"arn:aws:iam::123456789012:role/aws-authentication-it"}}] |
      | spec.operations        | [{"method":"GET","path":"/items"}]           |
    Then the response should be successful

    When I send a "GET" request to "${CTX:keyApiContext}/${CTX:keyApiVersion}/items" until status 200
    Then the response header "X-Aws-Access-Key-Id" should be "AKIATESTPERMANENT001"
    When I send a "GET" request to "${CTX:stsApiContext}/${CTX:stsApiVersion}/items" until status 200
    Then the response header "X-Aws-Access-Key-Id" should match pattern "^ASIASTS[0-9]{13}$"

    When I restart the "gateway-controller" service
    And I wait for the gateway controller health endpoint
    And I send a "GET" request to "${CTX:keyApiContext}/${CTX:keyApiVersion}/items" until status 200
    Then the response header "X-Aws-Access-Key-Id" should be "AKIATESTPERMANENT001"
    When I send a "GET" request to "${CTX:stsApiContext}/${CTX:stsApiVersion}/items" until status 200
    Then the response header "X-Aws-Access-Key-Id" should match pattern "^ASIASTS[0-9]{13}$"

    When I restart the "gateway-runtime" service
    And I send a GET request to the router ready endpoint until status 200
    And I send a "GET" request to "${CTX:keyApiContext}/${CTX:keyApiVersion}/items" until status 200
    Then the response header "X-Aws-Access-Key-Id" should be "AKIATESTPERMANENT001"
    When I send a "GET" request to "${CTX:stsApiContext}/${CTX:stsApiVersion}/items" until status 200
    Then the response header "X-Aws-Access-Key-Id" should match pattern "^ASIASTS[0-9]{13}$"

    When I delete the API "${CTX:keyApiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:keyApiContext}/${CTX:keyApiVersion}/items" until status 404
    When I delete the API "${CTX:stsApiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:stsApiContext}/${CTX:stsApiVersion}/items" until status 404
