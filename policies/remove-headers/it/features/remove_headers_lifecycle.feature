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
Feature: Remove headers policy across updates, concurrent traffic and logs
  As an API developer
  I want header removal to hold as an API changes and under load
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

  # RH20: The policy first removes X-Internal-Token and X-Removed-Response, then the API is
  # updated to remove X-Debug-Mode and X-Denied-Response instead. After the update, requests must
  # follow the new list only, and the headers of the old list pass through again.
  Scenario: Update the headers removed by a deployed API
    Given I generate a unique value from "rh-update" and store it as "apiName"
    And I generate a unique API version from "rh-update" and store it as "apiVersion"
    And I generate a unique API context from "/rh-update" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}               |
      | name                   | ${CTX:apiName}                          |
      | spec.displayName       | ${CTX:apiName}                          |
      | spec.version           | ${CTX:apiVersion}                       |
      | spec.context           | ${CTX:apiContext}/$version              |
      | spec.upstream.main.url | http://testbench:3000/analytics-headers |
      | spec.operations        | [{"method":"GET","path":"/get","policies":[{"name":"remove-headers","version":"v1","params":{"request":{"headers":[{"name":"X-Internal-Token"}]},"response":{"headers":[{"name":"X-Removed-Response"}]}}}]}] |
    Then the resource creation response should indicate successful deployment

    When I clear all headers
    And I set header "X-Internal-Token" to "internal-token-value"
    And I set header "X-Debug-Mode" to "verbose"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 200
    Then the response should not contain echoed header "X-Internal-Token"
    And the response should contain echoed header "X-Debug-Mode" with value "verbose"
    And the response header "X-Removed-Response" should not exist
    And the response header "X-Denied-Response" should be "denied"

    When I clear all headers
    And I authenticate using basic auth as "admin"
    When I update API "${CTX:apiName}" from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}               |
      | name                   | ${CTX:apiName}                          |
      | spec.displayName       | ${CTX:apiName}                          |
      | spec.version           | ${CTX:apiVersion}                       |
      | spec.context           | ${CTX:apiContext}/$version              |
      | spec.upstream.main.url | http://testbench:3000/analytics-headers |
      | spec.operations        | [{"method":"GET","path":"/get","policies":[{"name":"remove-headers","version":"v1","params":{"request":{"headers":[{"name":"X-Debug-Mode"}]},"response":{"headers":[{"name":"X-Denied-Response"}]}}}]}] |
    Then the API update response should indicate successful deployment

    When I clear all headers
    And I set header "X-Internal-Token" to "internal-token-value"
    And I set header "X-Debug-Mode" to "verbose"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until header "X-Removed-Response" is "removed"
    Then the response status code should be 200
    And the response should contain echoed header "X-Internal-Token" with value "internal-token-value"
    And the response should not contain echoed header "X-Debug-Mode"
    And the response header "X-Denied-Response" should not exist

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 404

  # RH21: The policy is removed from a deployed API. After the update, the headers it removed
  # must reach the backend and the client again.
  Scenario: Remove the policy from a deployed API
    Given I generate a unique value from "rh-detach" and store it as "apiName"
    And I generate a unique API version from "rh-detach" and store it as "apiVersion"
    And I generate a unique API context from "/rh-detach" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}               |
      | name                   | ${CTX:apiName}                          |
      | spec.displayName       | ${CTX:apiName}                          |
      | spec.version           | ${CTX:apiVersion}                       |
      | spec.context           | ${CTX:apiContext}/$version              |
      | spec.upstream.main.url | http://testbench:3000/analytics-headers |
      | spec.operations        | [{"method":"GET","path":"/get","policies":[{"name":"remove-headers","version":"v1","params":{"request":{"headers":[{"name":"X-Internal-Token"}]},"response":{"headers":[{"name":"X-Removed-Response"}]}}}]}] |
    Then the resource creation response should indicate successful deployment

    When I clear all headers
    And I set header "X-Internal-Token" to "internal-token-value"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 200
    Then the response should not contain echoed header "X-Internal-Token"
    And the response header "X-Removed-Response" should not exist

    When I clear all headers
    And I authenticate using basic auth as "admin"
    When I update API "${CTX:apiName}" from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}               |
      | name                   | ${CTX:apiName}                          |
      | spec.displayName       | ${CTX:apiName}                          |
      | spec.version           | ${CTX:apiVersion}                       |
      | spec.context           | ${CTX:apiContext}/$version              |
      | spec.upstream.main.url | http://testbench:3000/analytics-headers |
      | spec.operations        | [{"method":"GET","path":"/get"}] |
    Then the API update response should indicate successful deployment

    When I clear all headers
    And I set header "X-Internal-Token" to "internal-token-value"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until header "X-Removed-Response" is "removed"
    Then the response status code should be 200
    And the response should contain echoed header "X-Internal-Token" with value "internal-token-value"

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 404

  # RH23: Many requests are in flight at once, each with its own X-Client-Request-Id, and every
  # other one also carrying X-Internal-Token. Each request must reach the backend with its own
  # X-Client-Request-Id and without X-Internal-Token, and no response may carry
  # X-Removed-Response. A request that receives another request's value would show headers leaking
  # between requests.
  Scenario: Remove headers under concurrent traffic with different header combinations
    Given I generate a unique value from "rh-concurrent" and store it as "apiName"
    And I generate a unique API version from "rh-concurrent" and store it as "apiVersion"
    And I generate a unique API context from "/rh-concurrent" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}               |
      | name                   | ${CTX:apiName}                          |
      | spec.displayName       | ${CTX:apiName}                          |
      | spec.version           | ${CTX:apiVersion}                       |
      | spec.context           | ${CTX:apiContext}/$version              |
      | spec.upstream.main.url | http://testbench:3000/analytics-headers |
      | spec.operations        | [{"method":"GET","path":"/get","policies":[{"name":"remove-headers","version":"v1","params":{"request":{"headers":[{"name":"X-Internal-Token"}]},"response":{"headers":[{"name":"X-Removed-Response"}]}}}]}] |
    Then the resource creation response should indicate successful deployment

    When I clear all headers
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 200
    And I send 100 concurrent "GET" requests to "${CTX:apiContext}/${CTX:apiVersion}/get" identified by the "X-Client-Request-Id" header, every other one also carrying the "X-Internal-Token" header
    Then every concurrent request should reach the backend with its own "X-Client-Request-Id" header and without the "X-Internal-Token" header
    And no concurrent response should carry the "X-Removed-Response" header

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 404

  # RH30: The policy removes X-Internal-Token, a sensitive request header, and
  # X-Removed-Response, an internal response header. Neither may reach the backend or the client,
  # and the token's value must not appear in the gateway runtime's or controller's logs. The value
  # is unique to this scenario, so a match cannot come from another scenario's traffic. The
  # gateway's analytics events record the headers the client sent, before any policy runs, so
  # they are not checked here.
  Scenario: Removed sensitive headers are absent from the backend, the client and the logs
    Given I generate a unique value from "rh-exposure" and store it as "apiName"
    And I generate a unique API version from "rh-exposure" and store it as "apiVersion"
    And I generate a unique API context from "/rh-exposure" and store it as "apiContext"
    And I generate a unique value from "rh-secret" and store it as "secretValue"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}               |
      | name                   | ${CTX:apiName}                          |
      | spec.displayName       | ${CTX:apiName}                          |
      | spec.version           | ${CTX:apiVersion}                       |
      | spec.context           | ${CTX:apiContext}/$version              |
      | spec.upstream.main.url | http://testbench:3000/analytics-headers |
      | spec.operations        | [{"method":"GET","path":"/get","policies":[{"name":"remove-headers","version":"v1","params":{"request":{"headers":[{"name":"X-Internal-Token"}]},"response":{"headers":[{"name":"X-Removed-Response"}]}}}]}] |
    Then the resource creation response should indicate successful deployment

    When I clear all headers
    And I set header "X-Internal-Token" to "${CTX:secretValue}"
    And I set header "X-Client-Id" to "client-123"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 200
    Then the response should not contain echoed header "X-Internal-Token"
    And the response body should not contain "${CTX:secretValue}"
    And the response should contain echoed header "X-Client-Id" with value "client-123"
    And the response header "X-Removed-Response" should not exist
    And the response header "X-Allowed-Response" should be "allowed"
    And the "gateway-runtime" service logs should not contain "${CTX:secretValue}"
    And the "gateway-controller" service logs should not contain "${CTX:secretValue}"

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 404
