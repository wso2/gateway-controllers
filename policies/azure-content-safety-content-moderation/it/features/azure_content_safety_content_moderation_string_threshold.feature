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
Feature: Azure Content Safety content moderation policy with a numeric string threshold
  As an API developer
  I want a severity threshold given as a numeric string to be used as an integer
  So that thresholds rendered from templates or environment values work as configured

  # Gateway 1.2.0 and later convert a numeric string parameter to the number its schema declares.
  # Earlier Gateways reject it, in the string-threshold validation feature.

  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"

  # A Hate severity of 5 passes and 6 blocks, so the threshold "6" is in force as the integer 6
  # rather than the default (4).
  Scenario: Configure a threshold as an integer, integral floating-point value, or numeric integer string (numeric integer string)
    Given I generate a unique value from "acs-threshold-string" and store it as "apiName"
    And I generate a unique API version from "acs-threshold-string" and store it as "apiVersion"
    And I generate a unique API context from "/acs-threshold-string" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}  |
      | name                   | ${CTX:apiName}             |
      | spec.displayName       | ${CTX:apiName}             |
      | spec.version           | ${CTX:apiVersion}          |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3002      |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"POST","path":"/chat","policies":[{"name":"azure-content-safety-content-moderation","version":"v1","params":{"request":{"jsonPath":"$.message","hateSeverityThreshold":"6"}}}]}] |
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 200 with body:
      """
      {"message":"hate-severity-5"}
      """

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" with body:
      """
      {"message":"hate-severity-6"}
      """
    Then the response status code should be 422
    And the JSON response field "message.actionReason" should be "Violation of Azure content safety content moderation detected."
    And the JSON response field "message.direction" should be "REQUEST"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 404
