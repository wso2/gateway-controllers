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
Feature: Set headers policy on the request flow
  As an API developer
  I want configured request headers set before a request reaches the backend
  So that the backend and the client receive exactly the headers the API defines

  # The backend is the testbench echo service, which returns the request it received as JSON: the
  # "echoed header" steps read the request headers that reached the backend, and the "response
  # header" steps read the headers the client received.

  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"

  # SH01, SH06, SH14: The policy sets X-Gateway-Tenant, a header the client does not send, on a
  # POST that has a path parameter, a query string and a body. The backend must receive the new
  # header with the configured value, X-Client-Id unchanged, and the same method, path, query string
  # and body the client sent.
  Scenario: Set a new request header and keep the rest of the request unchanged
    Given I generate a unique value from "sh-req-new" and store it as "apiName"
    And I generate a unique API version from "sh-req-new" and store it as "apiVersion"
    And I generate a unique API context from "/sh-req-new" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}  |
      | name                   | ${CTX:apiName}             |
      | spec.displayName       | ${CTX:apiName}             |
      | spec.version           | ${CTX:apiVersion}          |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3000      |
      | spec.operations        | [{"method":"GET","path":"/probe"},{"method":"POST","path":"/orders/{orderId}","policies":[{"name":"set-headers","version":"v1","params":{"request":{"headers":[{"name":"X-Gateway-Tenant","value":"tenant-a"}]}}}]}] |
    Then the resource creation response should indicate successful deployment

    When I clear all headers
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/probe" until status 200
    And I set header "X-Client-Id" to "client-123"
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/orders/1001?status=new&notify=true" with body:
      """
      {"item":"book","quantity":2}
      """
    Then the response status code should be 200
    And the response should contain echoed header "X-Gateway-Tenant" with value "tenant-a"
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

  # SH02: The policy sets three request headers at once. Each must reach the backend with its
  # configured value, and X-Client-Id and X-Request-Source, which the policy does not name, must
  # reach it unchanged.
  Scenario Outline: Set multiple request headers (<case>)
    Given I generate a unique value from "sh-req-multi-<key>" and store it as "apiName"
    And I generate a unique API version from "sh-req-multi-<key>" and store it as "apiVersion"
    And I generate a unique API context from "/sh-req-multi-<key>" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}  |
      | name                   | ${CTX:apiName}             |
      | spec.displayName       | ${CTX:apiName}             |
      | spec.version           | ${CTX:apiVersion}          |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3000      |
      | spec.operations        | [{"method":"GET","path":"/get","policies":[{"name":"set-headers","version":"v1","params":{"request":{"headers":[{"name":"<first>","value":"<firstValue>"},{"name":"<second>","value":"<secondValue>"},{"name":"<third>","value":"<thirdValue>"}]}}}]}] |
    Then the resource creation response should indicate successful deployment

    When I clear all headers
    And I set header "X-Client-Id" to "client-123"
    And I set header "X-Request-Source" to "mobile-app"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 200
    Then the response should contain echoed header "<first>" with value "<firstValue>"
    And the response should contain echoed header "<second>" with value "<secondValue>"
    And the response should contain echoed header "<third>" with value "<thirdValue>"
    And the response should contain echoed header "X-Client-Id" with value "client-123"
    And the response should contain echoed header "X-Request-Source" with value "mobile-app"

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 404

    Examples:
      | case             | key      | first            | firstValue | second           | secondValue | third             | thirdValue |
      | custom headers   | custom   | X-Gateway-Tenant | tenant-a   | X-Gateway-Region | eu-west     | X-Gateway-Version | v2         |
      | standard headers | standard | Accept-Language  | en-US      | Cache-Control    | no-cache    | Pragma            | no-cache   |

  # SH07, SH26: The client sends a header the policy sets, twice and with conflicting values, over a
  # raw connection, as a client trying to override an identity or routing header would. The policy
  # value must take precedence: the backend receives only the configured value, and neither client
  # value.
  Scenario Outline: Overwrite a request header the client already sends (<case>)
    Given I generate a unique value from "sh-req-override-<key>" and store it as "apiName"
    And I generate a unique API version from "sh-req-override-<key>" and store it as "apiVersion"
    And I generate a unique API context from "/sh-req-override-<key>" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}  |
      | name                   | ${CTX:apiName}             |
      | spec.displayName       | ${CTX:apiName}             |
      | spec.version           | ${CTX:apiVersion}          |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3000      |
      | spec.operations        | [{"method":"GET","path":"/get","policies":[{"name":"set-headers","version":"v1","params":{"request":{"headers":[{"name":"<header>","value":"<configured>"}]}}}]}] |
    Then the resource creation response should indicate successful deployment

    When I clear all headers
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 200
    And I send a raw "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" with headers:
      | <header>    | client-value-a |
      | <header>    | client-value-b |
      | X-Client-Id | client-123     |
    Then the response status code should be 200
    And the response should contain echoed header "<header>" with value "<configured>"
    And the response body should not contain "client-value-a"
    And the response body should not contain "client-value-b"
    And the response should contain echoed header "X-Client-Id" with value "client-123"

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 404

    Examples:
      | case            | key      | header               | configured      |
      | custom header   | custom   | X-Gateway-Tenant     | tenant-a        |
      | identity header | identity | X-Authenticated-User | service-account |
      | routing header  | routing  | X-Backend-Route      | primary         |

  # SH13: The policy sets X-Gateway-Tenant on requests sent with each HTTP method. Every method
  # must reach the backend with the header and with the method unchanged.
  Scenario Outline: Set a request header for each HTTP method (<method>)
    Given I generate a unique value from "sh-req-method-<key>" and store it as "apiName"
    And I generate a unique API version from "sh-req-method-<key>" and store it as "apiVersion"
    And I generate a unique API context from "/sh-req-method-<key>" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}  |
      | name                   | ${CTX:apiName}             |
      | spec.displayName       | ${CTX:apiName}             |
      | spec.version           | ${CTX:apiVersion}          |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3000      |
      | spec.operations        | [{"method":"GET","path":"/probe"},{"method":"<method>","path":"/orders","policies":[{"name":"set-headers","version":"v1","params":{"request":{"headers":[{"name":"X-Gateway-Tenant","value":"tenant-a"}]}}}]}] |
    Then the resource creation response should indicate successful deployment

    When I clear all headers
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/probe" until status 200
    And I set header "X-Client-Id" to "client-123"
    And I send a "<method>" request to "${CTX:apiContext}/${CTX:apiVersion}/orders"
    Then the response status code should be 200
    And the response should contain echoed header "X-Gateway-Tenant" with value "tenant-a"
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
