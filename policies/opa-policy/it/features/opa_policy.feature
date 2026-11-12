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
@opa-policy
Feature: Validate Request with OPA policy
  As an API developer
  I want requests to be allowed or blocked by an Open Policy Agent decision
  So that authorization rules are enforced outside the gateway

  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"

  Scenario: A request is allowed or blocked by the decision OPA returns
    Given I generate a unique value from "opa-decision" and store it as "apiName"
    And I generate a unique API version from "opa-decision" and store it as "apiVersion"
    And I generate a unique API context from "/opa-decision" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}  |
      | name                   | ${CTX:apiName}             |
      | spec.displayName       | ${CTX:apiName}             |
      | spec.version           | ${CTX:apiVersion}          |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3000        |
      | spec.operations        | [{"method":"GET","path":"/orders","policies":[{"name":"opa-policy","version":"v0","params":{"serverUrl":"http://testbench:3018/v1/data","policy":"authz/policy","rule":"allow"}}]},{"method":"POST","path":"/orders","policies":[{"name":"opa-policy","version":"v0","params":{"serverUrl":"http://testbench:3018/v1/data","policy":"authz/policy","rule":"allow"}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/orders" until status 200
    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/orders" with body:
      """
      {}
      """
    Then the response status code should be 403
    And the response should be valid JSON
    And the response body should contain "rejected by the OPA policy validation"
    And I clear all headers
    And I set header "x-test-user" to "admin"
    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/orders" with body:
      """
      {}
      """
    Then the response status code should be 200
    And I clear all headers
    And I set header "x-opa-decision" to "deny"
    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/orders"
    Then the response status code should be 403
    And I clear all headers
    And I set header "x-opa-decision" to "allow"
    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/orders" with body:
      """
      {}
      """
    Then the response status code should be 200

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/orders" until status 404

  Scenario: The request is rejected with 500 when OPA cannot give a decision
    Given I generate a unique value from "opa-errors" and store it as "apiName"
    And I generate a unique API version from "opa-errors" and store it as "apiVersion"
    And I generate a unique API context from "/opa-errors" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}  |
      | name                   | ${CTX:apiName}             |
      | spec.displayName       | ${CTX:apiName}             |
      | spec.version           | ${CTX:apiVersion}          |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3000        |
      | spec.operations        | [{"method":"GET","path":"/orders","policies":[{"name":"opa-policy","version":"v0","params":{"serverUrl":"http://testbench:3018/v1/data","policy":"authz/policy","rule":"allow"}}]},{"method":"GET","path":"/unreachable","policies":[{"name":"opa-policy","version":"v0","params":{"serverUrl":"http://testbench:3999/v1/data","policy":"authz/policy","rule":"allow"}}]},{"method":"GET","path":"/unknown-rule","policies":[{"name":"opa-policy","version":"v0","params":{"serverUrl":"http://testbench:3018/v1/data","policy":"authz/policy","rule":"missing"}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/orders" until status 200
    And I clear all headers
    And I set header "x-opa-decision" to "undefined"
    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/orders"
    Then the response status code should be 500
    And I clear all headers
    And I set header "x-opa-decision" to "invalid"
    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/orders"
    Then the response status code should be 500
    And I clear all headers
    And I set header "x-opa-decision" to "error"
    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/orders"
    Then the response status code should be 500
    And the response should be valid JSON
    And the response body should contain "Unable to validate the request"
    And I clear all headers
    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/unreachable"
    Then the response status code should be 500
    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/unknown-rule"
    Then the response status code should be 500

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/orders" until status 404

  Scenario: The request metadata is sent to OPA in the input document
    Given I generate a unique value from "opa-input" and store it as "apiName"
    And I generate a unique API version from "opa-input" and store it as "apiVersion"
    And I generate a unique API context from "/opa-input" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}  |
      | name                   | ${CTX:apiName}             |
      | spec.displayName       | ${CTX:apiName}             |
      | spec.version           | ${CTX:apiVersion}          |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3000        |
      | spec.operations        | [{"method":"GET","path":"/orders","policies":[{"name":"opa-policy","version":"v0","params":{"serverUrl":"http://testbench:3018/v1/data","policy":"authz/context","rule":"allow"}}]},{"method":"POST","path":"/orders","policies":[{"name":"opa-policy","version":"v0","params":{"serverUrl":"http://testbench:3018/v1/data","policy":"authz/context","rule":"allow"}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/orders" until status 200
    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/orders" with body:
      """
      {}
      """
    Then the response status code should be 200

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/orders" until status 404

  Scenario: The access token is sent to OPA only when sendAccessToken is enabled
    Given I generate a unique value from "opa-token" and store it as "apiName"
    And I generate a unique API version from "opa-token" and store it as "apiVersion"
    And I generate a unique API context from "/opa-token" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}  |
      | name                   | ${CTX:apiName}             |
      | spec.displayName       | ${CTX:apiName}             |
      | spec.version           | ${CTX:apiVersion}          |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3000        |
      | spec.operations        | [{"method":"GET","path":"/with-token","policies":[{"name":"opa-policy","version":"v0","params":{"serverUrl":"http://testbench:3018/v1/data","policy":"authz/token","rule":"allow","sendAccessToken":true}}]},{"method":"GET","path":"/without-token","policies":[{"name":"opa-policy","version":"v0","params":{"serverUrl":"http://testbench:3018/v1/data","policy":"authz/notoken","rule":"allow"}}]}] |
    Then the resource creation response should indicate successful deployment
    And I clear all headers
    And I set header "Authorization" to "Bearer test-access-token"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/with-token" until status 200
    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/without-token"
    Then the response status code should be 200
    And I clear all headers
    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/with-token"
    Then the response status code should be 403

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/with-token" until status 404

  Scenario: The access key is sent to OPA as a bearer token
    Given I generate a unique value from "opa-key" and store it as "apiName"
    And I generate a unique API version from "opa-key" and store it as "apiVersion"
    And I generate a unique API context from "/opa-key" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}  |
      | name                   | ${CTX:apiName}             |
      | spec.displayName       | ${CTX:apiName}             |
      | spec.version           | ${CTX:apiVersion}          |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3000        |
      | spec.operations        | [{"method":"GET","path":"/secured","policies":[{"name":"opa-policy","version":"v0","params":{"serverUrl":"http://testbench:3018/v1/data","policy":"authz/secured","rule":"allow","accessKey":"opa-test-key"}}]},{"method":"GET","path":"/wrong-key","policies":[{"name":"opa-policy","version":"v0","params":{"serverUrl":"http://testbench:3018/v1/data","policy":"authz/secured","rule":"allow","accessKey":"not-the-key"}}]},{"method":"GET","path":"/no-key","policies":[{"name":"opa-policy","version":"v0","params":{"serverUrl":"http://testbench:3018/v1/data","policy":"authz/secured","rule":"allow"}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/secured" until status 200
    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/wrong-key"
    Then the response status code should be 500
    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/no-key"
    Then the response status code should be 500

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/secured" until status 404

  Scenario: The request is rejected with 500 when OPA does not answer within connectionTimeout
    Given I generate a unique value from "opa-timeout" and store it as "apiName"
    And I generate a unique API version from "opa-timeout" and store it as "apiVersion"
    And I generate a unique API context from "/opa-timeout" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}  |
      | name                   | ${CTX:apiName}             |
      | spec.displayName       | ${CTX:apiName}             |
      | spec.version           | ${CTX:apiVersion}          |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3000        |
      | spec.operations        | [{"method":"GET","path":"/slow-ok","policies":[{"name":"opa-policy","version":"v0","params":{"serverUrl":"http://testbench:3018/v1/data","policy":"authz/slow","rule":"allow","connectionTimeout":10}}]},{"method":"GET","path":"/slow-timeout","policies":[{"name":"opa-policy","version":"v0","params":{"serverUrl":"http://testbench:3018/v1/data","policy":"authz/slow","rule":"allow","connectionTimeout":1}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/slow-ok" until status 200
    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/slow-timeout"
    Then the response status code should be 500

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/slow-ok" until status 404

  Scenario: A policy without the required rule is rejected at deployment
    Given I generate a unique value from "opa-norule" and store it as "apiName"
    And I generate a unique API version from "opa-norule" and store it as "apiVersion"
    And I generate a unique API context from "/opa-norule" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}  |
      | name                   | ${CTX:apiName}             |
      | spec.displayName       | ${CTX:apiName}             |
      | spec.version           | ${CTX:apiVersion}          |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3000        |
      | spec.operations        | [{"method":"GET","path":"/orders","policies":[{"name":"opa-policy","version":"v0","params":{"serverUrl":"http://testbench:3018/v1/data","policy":"authz/policy"}}]}] |
    Then the response should be a client error

  Scenario: A policy without serverUrl is rejected at deployment
    Given I generate a unique value from "opa-nourl" and store it as "apiName"
    And I generate a unique API version from "opa-nourl" and store it as "apiVersion"
    And I generate a unique API context from "/opa-nourl" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}  |
      | name                   | ${CTX:apiName}             |
      | spec.displayName       | ${CTX:apiName}             |
      | spec.version           | ${CTX:apiVersion}          |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3000        |
      | spec.operations        | [{"method":"GET","path":"/orders","policies":[{"name":"opa-policy","version":"v0","params":{"policy":"authz/policy","rule":"allow"}}]}] |
    Then the response should be a client error

  Scenario: A policy without policy is rejected at deployment
    Given I generate a unique value from "opa-nopolicy" and store it as "apiName"
    And I generate a unique API version from "opa-nopolicy" and store it as "apiVersion"
    And I generate a unique API context from "/opa-nopolicy" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}  |
      | name                   | ${CTX:apiName}             |
      | spec.displayName       | ${CTX:apiName}             |
      | spec.version           | ${CTX:apiVersion}          |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3000        |
      | spec.operations        | [{"method":"GET","path":"/orders","policies":[{"name":"opa-policy","version":"v0","params":{"serverUrl":"http://testbench:3018/v1/data","rule":"allow"}}]}] |
    Then the response should be a client error
