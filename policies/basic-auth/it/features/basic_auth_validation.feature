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

@basic-auth
Feature: Basic auth policy configuration validation
  As an API developer
  I want an invalid basic-auth configuration to be rejected when the API is created
  So that a change to it is caught before it reaches a release

  # Configurations rejected when the API is created, from the policy's parameter schema.

  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"

  # The configured username and password must each have at least one character, so an empty one
  # is rejected and no request can authenticate with it.
  Scenario Outline: Send an empty username or empty password (<case>)
    Given I generate a unique value from "ba-invalid-<key>" and store it as "apiName"
    And I generate a unique API version from "ba-invalid-<key>" and store it as "apiVersion"
    And I generate a unique API context from "/ba-invalid-<key>" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3000 |
      | spec.operations        | [{"method":"GET","path":"/protected","policies":[{"name":"basic-auth","version":"v1","params":<params>}]}] |
    Then the response status code should be 400
    And the response should be valid JSON
    And the JSON response field "status" should be "error"
    And the response body should contain "Configuration validation failed"
    And the response body should contain "<field>"

    Examples:
      | case                                | key  | field    | params                                   |
      | empty username in the configuration | user | username | {"username":"","password":"ba-secret?1"} |
      | empty password in the configuration | pass | password | {"username":"ba-user","password":""}     |


  # Username, password and realm each take 1 to 256 characters.
  Scenario Outline: A username, password or realm outside its length limits is rejected (<case>)
    Given I generate a unique value from "ba-invalid-<key>" and store it as "apiName"
    And I generate a unique API version from "ba-invalid-<key>" and store it as "apiVersion"
    And I generate a unique API context from "/ba-invalid-<key>" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3000 |
      | spec.operations        | [{"method":"GET","path":"/protected","policies":[{"name":"basic-auth","version":"v1","params":<params>}]}] |
    Then the response status code should be 400
    And the response should be valid JSON
    And the JSON response field "status" should be "error"
    And the response body should contain "Configuration validation failed"
    And the response body should contain "<field>"

    Examples:
      | case                       | key         | field    | params                                                                                                                                                                                                                                                                                                    |
      | username of 257 characters | long-user   | username | {"username":"uuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuu","password":"ba-secret?1"} |
      | password of 257 characters | long-pass   | password | {"username":"ba-user","password":"ppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp"}     |
      | empty realm                | empty-realm | realm    | {"username":"ba-user","password":"ba-secret?1","realm":""}                                                                                                                                                                                                                                                |
