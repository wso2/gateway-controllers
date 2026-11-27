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

@remove-headers
Feature: Remove headers policy on the request flow
  As an API developer
  I want configured request headers removed before a request reaches the backend
  So that headers the backend or the client must not see never reach them

  # The backend is the testbench echo service, which returns the request it received as JSON: the
  # "echoed header" steps read the request headers that reached the backend, and the "response
  # header" steps read the headers the client received.

  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"

  # RH01: The policy removes X-Internal-Token from the request. X-Client-Id is sent beside it and
  # is not configured for removal, so it must reach the backend with its value; this shows that
  # the echo returns the request headers and that the policy removes only the configured one. The
  # request is sent twice so that the removal is shown to hold for each request.
  Scenario: Remove a single request header
    Given I generate a unique value from "rh-req-single" and store it as "apiName"
    And I generate a unique API version from "rh-req-single" and store it as "apiVersion"
    And I generate a unique API context from "/rh-req-single" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}  |
      | name                   | ${CTX:apiName}             |
      | spec.displayName       | ${CTX:apiName}             |
      | spec.version           | ${CTX:apiVersion}          |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3000      |
      | spec.operations        | [{"method":"GET","path":"/get","policies":[{"name":"remove-headers","version":"v1","params":{"request":{"headers":[{"name":"X-Internal-Token"}]}}}]}] |
    Then the resource creation response should indicate successful deployment

    When I clear all headers
    And I set header "X-Internal-Token" to "internal-token-value"
    And I set header "X-Client-Id" to "client-123"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 200
    Then the response should not contain echoed header "X-Internal-Token"
    And the response should contain echoed header "X-Client-Id" with value "client-123"

    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get"
    Then the response status code should be 200
    And the response should not contain echoed header "X-Internal-Token"
    And the response should contain echoed header "X-Client-Id" with value "client-123"

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 404

  # RH02, RH26: The policy removes three request headers at once: custom headers, or the
  # sensitive headers a client sends (credentials, session cookies and API keys). None of them,
  # and none of their values, may reach the backend. X-Client-Id and X-Request-Source are not
  # configured for removal and must reach the backend unchanged.
  Scenario Outline: Remove multiple request headers (<case>)
    Given I generate a unique value from "rh-req-multi-<key>" and store it as "apiName"
    And I generate a unique API version from "rh-req-multi-<key>" and store it as "apiVersion"
    And I generate a unique API context from "/rh-req-multi-<key>" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}  |
      | name                   | ${CTX:apiName}             |
      | spec.displayName       | ${CTX:apiName}             |
      | spec.version           | ${CTX:apiVersion}          |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3000      |
      | spec.operations        | [{"method":"GET","path":"/get","policies":[{"name":"remove-headers","version":"v1","params":{"request":{"headers":[{"name":"<first>"},{"name":"<second>"},{"name":"<third>"}]}}}]}] |
    Then the resource creation response should indicate successful deployment

    When I clear all headers
    And I set header "<first>" to "first-removed-value"
    And I set header "<second>" to "second-removed-value"
    And I set header "<third>" to "third-removed-value"
    And I set header "X-Client-Id" to "client-123"
    And I set header "X-Request-Source" to "mobile-app"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 200
    Then the response should not contain echoed header "<first>"
    And the response should not contain echoed header "<second>"
    And the response should not contain echoed header "<third>"
    And the response body should not contain "removed-value"
    And the response should contain echoed header "X-Client-Id" with value "client-123"
    And the response should contain echoed header "X-Request-Source" with value "mobile-app"

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 404

    Examples:
      | case                     | key       | first            | second       | third          |
      | custom headers           | custom    | X-Internal-Token | X-Debug-Mode | X-Session-Hint |
      | sensitive client headers | sensitive | Authorization    | Cookie       | X-API-Key      |

  # RH12, RH15: The policy removes X-Internal-Token, a custom header the client sends with a
  # POST that has a path parameter, a query string and a body. Only the header may change: the
  # backend must receive the same method, path, query string and body the client sent.
  Scenario: Remove a client-supplied custom request header and keep the rest of the request unchanged
    Given I generate a unique value from "rh-req-custom" and store it as "apiName"
    And I generate a unique API version from "rh-req-custom" and store it as "apiVersion"
    And I generate a unique API context from "/rh-req-custom" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}  |
      | name                   | ${CTX:apiName}             |
      | spec.displayName       | ${CTX:apiName}             |
      | spec.version           | ${CTX:apiVersion}          |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3000      |
      | spec.operations        | [{"method":"GET","path":"/probe"},{"method":"POST","path":"/orders/{orderId}","policies":[{"name":"remove-headers","version":"v1","params":{"request":{"headers":[{"name":"X-Internal-Token"}]}}}]}] |
    Then the resource creation response should indicate successful deployment

    When I clear all headers
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/probe" until status 200
    And I set header "X-Internal-Token" to "internal-token-value"
    And I set header "X-Client-Id" to "client-123"
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/orders/1001?status=new&notify=true" with body:
      """
      {"item":"book","quantity":2}
      """
    Then the response status code should be 200
    And the response should not contain echoed header "X-Internal-Token"
    And the response should contain echoed header "X-Client-Id" with value "client-123"
    And the JSON response field "method" should be "POST"
    And the JSON response field "path" should be "/orders/1001"
    And the JSON response field "query" should be "status=new&notify=true"
    And the JSON response field "body" should be:
      """
      {"item":"book","quantity":2}
      """

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/probe" until status 404

  # RH14: The policy removes X-Internal-Token from requests sent with each HTTP method. Every
  # method must reach the backend without the header and with the method unchanged.
  Scenario Outline: Remove a request header for each HTTP method (<method>)
    Given I generate a unique value from "rh-req-method-<key>" and store it as "apiName"
    And I generate a unique API version from "rh-req-method-<key>" and store it as "apiVersion"
    And I generate a unique API context from "/rh-req-method-<key>" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}  |
      | name                   | ${CTX:apiName}             |
      | spec.displayName       | ${CTX:apiName}             |
      | spec.version           | ${CTX:apiVersion}          |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3000      |
      | spec.operations        | [{"method":"GET","path":"/probe"},{"method":"<method>","path":"/orders","policies":[{"name":"remove-headers","version":"v1","params":{"request":{"headers":[{"name":"X-Internal-Token"}]}}}]}] |
    Then the resource creation response should indicate successful deployment

    When I clear all headers
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/probe" until status 200
    And I set header "X-Internal-Token" to "internal-token-value"
    And I set header "X-Client-Id" to "client-123"
    And I send a "<method>" request to "${CTX:apiContext}/${CTX:apiVersion}/orders"
    Then the response status code should be 200
    And the response should not contain echoed header "X-Internal-Token"
    And the response should contain echoed header "X-Client-Id" with value "client-123"
    And the JSON response field "method" should be "<method>"

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/probe" until status 404

    Examples:
      | method | key    |
      | GET    | get    |
      | POST   | post   |
      | PUT    | put    |
      | PATCH  | patch  |
      | DELETE | delete |
