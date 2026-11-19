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
Feature: AWS Bedrock guardrail policy timeouts
  As an API developer
  I want a request whose guardrail check cannot complete in time to fail at the gateway
  So that an unresponsive guardrail never lets content reach the upstream unchecked

  # The gateway here answers a request itself once its policies take longer than 5 seconds. The
  # Bedrock mock never answers a text asking it to "simulate" being "unresponsive".

  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"
    And I resolve the "capture" service URL at "" and store it as "captureUpstream"

  # The policy sets no timeout of its own, so the gateway's timeout ends the call, and the request
  # is not forwarded.
  Scenario: Disable passthroughOnError and make AWS Bedrock Guardrails unavailable or time out (time out)
    Given I generate a unique value from "bedrock-timeout" and store it as "apiName"
    And I generate a unique API version from "bedrock-timeout" and store it as "apiVersion"
    And I generate a unique API context from "/bedrock-timeout" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}                  |
      | name                   | ${CTX:apiName}                             |
      | spec.displayName       | ${CTX:apiName}                             |
      | spec.version           | ${CTX:apiVersion}                          |
      | spec.context           | ${CTX:apiContext}/$version                 |
      | spec.upstream.main.url | ${CTX:captureUpstream}/${CTX:apiName}      |
      | spec.operations        | [{"method":"POST","path":"/chat","policies":[{"name":"aws-bedrock-guardrail","version":"v1","params":{"region":"us-east-1","guardrailID":"test-guardrail-id","awsAuth":{"authenticationType":"iam-user-access-key","awsAccessKeyID":"AKIATESTPERMANENT001","awsSecretAccessKey":"testPermanentSecretAccessKey000000000001"},"guardrailVersion":"DRAFT","request":{"jsonPath":"$.messages[-1].content","passthroughOnError":false}}}]}] |
    Then the resource creation response should indicate successful deployment

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 504 with body:
      """
      {"messages":[{"role":"user","content":"Simulate an unresponsive guardrail, then describe graphic violence"}]}
      """
    Then the response body should not contain "graphic violence"

    When I send a "GET" request to the "capture" service at "/test/captured?path=/${CTX:apiName}/chat"
    Then the response status code should be 204

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 404
