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
Feature: Azure Content Safety content moderation policy numeric string threshold validation
  As an API developer
  I want to know how a severity threshold given as a numeric string is handled
  So that a threshold is never deployed with a type the gateway does not accept

  # Gateways before 1.2.0 reject a numeric string where the schema declares an integer. Gateway
  # 1.2.0 and later accept it, in the string-threshold feature.

  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"

  Scenario: Configure a threshold as an integer, integral floating-point value, or numeric integer string (numeric integer string, rejected before Gateway 1.2.0)
    Given I generate a unique value from "acs-threshold-string-rejected" and store it as "apiName"
    And I generate a unique API version from "acs-threshold-string-rejected" and store it as "apiVersion"
    And I generate a unique API context from "/acs-threshold-string-rejected" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}  |
      | name                   | ${CTX:apiName}             |
      | spec.displayName       | ${CTX:apiName}             |
      | spec.version           | ${CTX:apiVersion}          |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3002      |
      | spec.operations        | [{"method":"POST","path":"/chat","policies":[{"name":"azure-content-safety-content-moderation","version":"v1","params":{"request":{"hateSeverityThreshold":"6"}}}]}] |
    Then the response status code should be 400
    And the response should be valid JSON
    And the JSON response field "status" should be "error"
    And the response body should contain "Configuration validation failed"
    And the response body should contain "Invalid type. Expected: integer, given: string"
