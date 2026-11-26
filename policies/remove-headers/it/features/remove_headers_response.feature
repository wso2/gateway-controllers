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
Feature: Remove headers policy on the response flow
  As an API developer
  I want configured response headers removed before a response reaches the client
  So that headers the backend or the client must not see never reach them

  # The backend is the testbench echo service under /analytics-headers. It returns the request it
  # received as JSON, and answers with X-Allowed-Response: allowed, X-Denied-Response: denied,
  # X-Removed-Response: removed, X-Multi-Response as two header lines, and X-Correlation-Response
  # with the value of the request's X-Correlation-Id. The "echoed header" steps read the request
  # headers that reached the backend, and the "response header" steps read the headers the
  # client received.

  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"

  # RH03, RH13, RH16, RH27: The policy removes one header the backend generates: a custom
  # header, or an internal tracing header (X-Correlation-Response, which the backend sets from the
  # request's X-Correlation-Id). The backend is asked for a 201 status with the statusCode query
  # parameter. The other headers must reach the client unchanged, and the client must receive the
  # 201 and the echoed body unchanged. Server and x-request-id are set by the gateway's router
  # after the policies run, so a policy cannot remove them, and the backend sends no X-Powered-By.
  Scenario Outline: Remove a single backend-generated response header (<case>)
    Given I generate a unique value from "rh-resp-single-<key>" and store it as "apiName"
    And I generate a unique API version from "rh-resp-single-<key>" and store it as "apiVersion"
    And I generate a unique API context from "/rh-resp-single-<key>" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}               |
      | name                   | ${CTX:apiName}                          |
      | spec.displayName       | ${CTX:apiName}                          |
      | spec.version           | ${CTX:apiVersion}                       |
      | spec.context           | ${CTX:apiContext}/$version              |
      | spec.upstream.main.url | http://testbench:3000/analytics-headers |
      | spec.operations        | [{"method":"GET","path":"/get","policies":[{"name":"remove-headers","version":"v1","params":{"response":{"headers":[{"name":"<removed>"}]}}}]}] |
    Then the resource creation response should indicate successful deployment

    When I clear all headers
    And I set header "X-Correlation-Id" to "trace-1001"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get?statusCode=201" until status 201
    Then the response status code should be 201
    And the response header "<removed>" should not exist
    And the response header "<kept>" should be "<keptValue>"
    And the response header "X-Allowed-Response" should be "allowed"
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
      | case                    | key     | removed                | kept               | keptValue |
      | custom backend header   | custom  | X-Removed-Response     | X-Denied-Response  | denied    |
      | internal tracing header | tracing | X-Correlation-Response | X-Removed-Response | removed   |

  # RH04: The policy removes two of the backend's response headers. X-Allowed-Response is not
  # configured for removal and must reach the client unchanged.
  Scenario: Remove multiple response headers
    Given I generate a unique value from "rh-resp-multi" and store it as "apiName"
    And I generate a unique API version from "rh-resp-multi" and store it as "apiVersion"
    And I generate a unique API context from "/rh-resp-multi" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}               |
      | name                   | ${CTX:apiName}                          |
      | spec.displayName       | ${CTX:apiName}                          |
      | spec.version           | ${CTX:apiVersion}                       |
      | spec.context           | ${CTX:apiContext}/$version              |
      | spec.upstream.main.url | http://testbench:3000/analytics-headers |
      | spec.operations        | [{"method":"GET","path":"/get","policies":[{"name":"remove-headers","version":"v1","params":{"response":{"headers":[{"name":"X-Removed-Response"},{"name":"X-Denied-Response"}]}}}]}] |
    Then the resource creation response should indicate successful deployment

    When I clear all headers
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 200
    Then the response header "X-Removed-Response" should not exist
    And the response header "X-Denied-Response" should not exist
    And the response header "X-Allowed-Response" should be "allowed"

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 404
