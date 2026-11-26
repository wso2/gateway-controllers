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
Feature: Remove headers policy across gateway restarts
  As an API developer
  I want header removal to survive a gateway restart
  So that headers the backend or the client must not see never reach them

  # The backend is the testbench echo service under /analytics-headers. It returns the request it
  # received as JSON, and answers with X-Allowed-Response: allowed, X-Denied-Response: denied,
  # X-Removed-Response: removed, X-Multi-Response as two header lines, and X-Correlation-Response
  # with the value of the request's X-Correlation-Id. The "echoed header" steps read the request
  # headers that reached the backend, and the "response header" steps read the headers the
  # client received.

  # This scenario restarts gateway services, so it runs on its own.

  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"

  # RH22: The gateway controller and then the gateway runtime are restarted. The runtime loads
  # its configuration again from the restarted controller, and the policy must keep removing the
  # same headers.
  Scenario: Keep removing headers after the gateway restarts
    Given I generate a unique value from "rh-restart" and store it as "apiName"
    And I generate a unique API version from "rh-restart" and store it as "apiVersion"
    And I generate a unique API context from "/rh-restart" and store it as "apiContext"
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
    And I set header "X-Client-Id" to "client-123"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 200
    Then the response should not contain echoed header "X-Internal-Token"
    And the response header "X-Removed-Response" should not exist

    When I restart the "gateway-controller" service
    And I clear all headers
    And I authenticate using basic auth as "admin"
    And I wait for the gateway controller health endpoint
    And I restart the "gateway-runtime" service
    And I clear all headers
    And I authenticate using basic auth as "admin"
    And I wait for the gateway controller health endpoint
    And I clear all headers
    And I set header "X-Internal-Token" to "internal-token-value"
    And I set header "X-Client-Id" to "client-123"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 200
    Then the response should not contain echoed header "X-Internal-Token"
    And the response should contain echoed header "X-Client-Id" with value "client-123"
    And the response header "X-Removed-Response" should not exist
    And the response header "X-Allowed-Response" should be "allowed"

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 404
