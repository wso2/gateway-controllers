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

@azure-content-safety-content-moderation
Feature: Azure Content Safety content moderation policy on a gateway without Azure configuration
  As an API developer
  I want the guardrail to fail visibly when the gateway has no Azure endpoint or subscription key
  So that a missing Azure configuration never lets content through unchecked

  # A gateway with no Azure endpoint or key in its configuration. The API deploys and every request
  # to the route gets 500, because the gateway does not validate system parameters when an API is
  # created.

  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"

  # The policy engine also answers 500 for a route whose policy chain it has not received yet, so
  # the API carries a control operation, /ready, with a set-headers policy that builds without any
  # Azure configuration. The engine applies every route of an update together: once /ready returns
  # its header, /chat's attachment has been processed, and its 500 can only come from the missing
  # configuration. The message is allowed content.
  Scenario: Omit the Azure endpoint/API key or configure it as an empty or non-string value (endpoint and API key omitted)
    Given I generate a unique value from "acs-missing-configuration" and store it as "apiName"
    And I generate a unique API version from "acs-missing-configuration" and store it as "apiVersion"
    And I generate a unique API context from "/acs-missing-configuration" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}  |
      | name                   | ${CTX:apiName}             |
      | spec.displayName       | ${CTX:apiName}             |
      | spec.version           | ${CTX:apiVersion}          |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3002      |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"GET","path":"/ready","policies":[{"name":"set-headers","version":"v1","params":{"response":{"headers":[{"name":"X-Readiness-Check","value":"chain-loaded"}]}}}]},{"method":"POST","path":"/chat","policies":[{"name":"azure-content-safety-content-moderation","version":"v1","params":{"request":{"jsonPath":"$.message"}}}]}] |
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/ready" until header "X-Readiness-Check" is "chain-loaded"

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" with body:
      """
      {"message":"What is the capital of France?"}
      """
    Then the response status code should be 500
    And the response body should contain "Internal Server Error"
    And the response body should not contain "What is the capital of France?"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 404
