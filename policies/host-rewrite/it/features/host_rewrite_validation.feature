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
# KIND, either express or implied. See the License for the
# specific language governing permissions and limitations
# under the License.
# --------------------------------------------------------------------

@host-rewrite
Feature: Host rewrite policy validation
  As an API developer
  I want an invalid host rewrite configuration to be rejected when the API is created
  So that a request is never sent upstream with an unintended Host

  # The gateway checks the policy's parameters against its schema: host is a required string of 1
  # to 255 letters, digits, dots, colons and hyphens.

  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"

  Scenario Outline: Configure an empty or missing rewrite host value (<case>)
    Given I generate a unique value from "hr-invalid-empty" and store it as "apiName"
    And I generate a unique API context from "/hr-invalid-empty" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion                     | ${CTX:gatewaySpecVersion} |
      | name                           | ${CTX:apiName} |
      | spec.displayName               | ${CTX:apiName} |
      | spec.version                   | v1.0 |
      | spec.context                   | ${CTX:apiContext}/$version |
      | spec.upstream.main.url         | http://testbench:3002/anything |
      | spec.upstream.main.hostRewrite | manual |
      | spec.policies                  | [{"name":"host-rewrite","version":"v1","params":<params>}] |
      | spec.operations                | [{"method":"GET","path":"/probe"}] |
    Then the response status code should be 400
    And the JSON response field "status" should be "error"
    And the JSON response field "message" should be "Configuration validation failed"
    And the response body should contain "<field>"
    And the response body should contain "<expected>"

    When I get the API "${CTX:apiName}"
    Then the response status should be 404

    Examples:
      | case            | params          | field                          | expected                                          |
      | empty string    | {"host":""}     | spec.policies[0].params.host   | String length must be greater than or equal to 1 |
      | whitespace only | {"host":"   "}  | spec.policies[0].params.host   | Does not match pattern                            |
      | missing         | {}              | spec.policies[0].params        | host is required                                  |

  Scenario Outline: Configure malformed host values, invalid characters, or unsupported parameter types (<case>)
    Given I generate a unique value from "hr-invalid-host" and store it as "apiName"
    And I generate a unique API context from "/hr-invalid-host" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion                     | ${CTX:gatewaySpecVersion} |
      | name                           | ${CTX:apiName} |
      | spec.displayName               | ${CTX:apiName} |
      | spec.version                   | v1.0 |
      | spec.context                   | ${CTX:apiContext}/$version |
      | spec.upstream.main.url         | http://testbench:3002/anything |
      | spec.upstream.main.hostRewrite | manual |
      | spec.operations                | [{"method":"GET","path":"/probe","policies":[{"name":"host-rewrite","version":"v1","params":{"host":<host>}}]}] |
    Then the response status code should be 400
    And the JSON response field "status" should be "error"
    And the JSON response field "message" should be "Configuration validation failed"
    And the response body should contain "spec.operations[0].policies[0].params.host"
    And the response body should contain "<expected>"

    When I get the API "${CTX:apiName}"
    Then the response status should be 404

    Examples:
      | case            | host                              | expected                                         |
      | underscore      | "hr_bad.example"                  | Does not match pattern                           |
      | URL with path   | "evil.example/path"               | Does not match pattern                           |
      | CRLF            | "hr.example\u000d\u000aX-Injected: 1" | Does not match pattern                     |
      | longer than 255 | "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" | String length must be less than or equal to 255 |
      | integer         | 8080                              | Invalid type. Expected: string, given: integer   |
      | array           | ["hr.example"]                    | Invalid type. Expected: string, given: array     |
