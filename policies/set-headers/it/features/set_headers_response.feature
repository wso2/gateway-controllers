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

@set-headers
Feature: Set headers policy on the response flow
  As an API developer
  I want configured response headers set before a response reaches the client
  So that the backend and the client receive exactly the headers the API defines

  # The backend is the testbench echo service under /analytics-headers. It returns the request it
  # received as JSON, and answers with X-Allowed-Response: allowed, X-Denied-Response: denied,
  # X-Removed-Response: removed, X-Multi-Response as two header lines, and X-Correlation-Response
  # with the value of the request's X-Correlation-Id. The "echoed header" steps read the request
  # headers that reached the backend, and the "response header" steps read the headers the
  # client received.

  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"

  # SH03, SH08, SH15: The policy sets one response header: a header the backend does not send, or
  # one it does, whose value is overwritten. The backend is asked for a 201 status with the
  # statusCode query parameter. The client must receive the configured value, and the 201 and the
  # echoed body unchanged. The backend always returns X-Allowed-Response, X-Denied-Response and
  # X-Removed-Response; <kept> is one of them that the row's policy does not set, and it and
  # X-Removed-Response must reach the client with the backend's values.
  Scenario Outline: Set a single response header (<case>)
    Given I generate a unique value from "sh-resp-single-<key>" and store it as "apiName"
    And I generate a unique API version from "sh-resp-single-<key>" and store it as "apiVersion"
    And I generate a unique API context from "/sh-resp-single-<key>" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}               |
      | name                   | ${CTX:apiName}                          |
      | spec.displayName       | ${CTX:apiName}                          |
      | spec.version           | ${CTX:apiVersion}                       |
      | spec.context           | ${CTX:apiContext}/$version              |
      | spec.upstream.main.url | http://testbench:3000/analytics-headers |
      | spec.operations        | [{"method":"GET","path":"/get","policies":[{"name":"set-headers","version":"v1","params":{"response":{"headers":[{"name":"<header>","value":"gateway-value"}]}}}]}] |
    Then the resource creation response should indicate successful deployment

    When I clear all headers
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get?statusCode=201" until status 201
    Then the response status code should be 201
    And the response header "<header>" should have only the value "gateway-value"
    And the response header "<kept>" should be "<keptValue>"
    And the response header "X-Removed-Response" should be "removed"
    And the response header "Content-Type" should be "application/json"
    And the JSON response field "method" should be "GET"
    And the JSON response field "path" should be "/analytics-headers/get"
    And the JSON response field "query" should be "statusCode=201"

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 404

    Examples:
      | case                    | key      | header             | kept               | keptValue |
      | new header              | new      | X-Gateway-Response | X-Allowed-Response | allowed   |
      | existing backend header | existing | X-Allowed-Response | X-Denied-Response  | denied    |

  # SH04: The policy sets three response headers: two the backend does not send, and
  # X-Denied-Response, whose backend value is overwritten. The client must receive all three with
  # their configured values, and X-Allowed-Response and X-Removed-Response unchanged.
  Scenario: Set multiple response headers
    Given I generate a unique value from "sh-resp-multi" and store it as "apiName"
    And I generate a unique API version from "sh-resp-multi" and store it as "apiVersion"
    And I generate a unique API context from "/sh-resp-multi" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}               |
      | name                   | ${CTX:apiName}                          |
      | spec.displayName       | ${CTX:apiName}                          |
      | spec.version           | ${CTX:apiVersion}                       |
      | spec.context           | ${CTX:apiContext}/$version              |
      | spec.upstream.main.url | http://testbench:3000/analytics-headers |
      | spec.operations        | [{"method":"GET","path":"/get","policies":[{"name":"set-headers","version":"v1","params":{"response":{"headers":[{"name":"X-Gateway-Response","value":"gateway-value"},{"name":"X-Gateway-Region","value":"eu-west"},{"name":"X-Denied-Response","value":"overridden"}]}}}]}] |
    Then the resource creation response should indicate successful deployment

    When I clear all headers
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 200
    Then the response header "X-Gateway-Response" should be "gateway-value"
    And the response header "X-Gateway-Region" should be "eu-west"
    And the response header "X-Denied-Response" should have only the value "overridden"
    And the response header "X-Allowed-Response" should be "allowed"
    And the response header "X-Removed-Response" should be "removed"

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 404
