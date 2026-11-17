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

@dynamic-endpoint
Feature: Dynamic endpoint with an unavailable upstream
  As an API developer
  I want an unavailable upstream to fail on its own
  So that traffic is never silently moved to a backend nobody selected

  # Nothing listens on testbench port 3999, so an upstream there refuses every connection.
  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"
    And I resolve the "capture" service URL at "" and store it as "captureUpstream"

  Scenario: The selected upstream is unavailable and the request does not switch to the main upstream
    Given I generate a unique value from "dynamic-down" and store it as "apiName"
    And I generate a unique API context from "/dynamic-down" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion               | ${CTX:gatewaySpecVersion}          |
      | name                     | ${CTX:apiName}                     |
      | spec.displayName         | Dynamic-Endpoint-Down-API          |
      | spec.version             | v1.0                               |
      | spec.context             | ${CTX:apiContext}/$version         |
      | spec.upstream.main.url   | ${CTX:captureUpstream}             |
      | spec.upstreamDefinitions | [{"name":"down-upstream","basePath":"/down","upstreams":[{"url":"http://testbench:3999"}]}] |
      | spec.operations          | [{"method":"GET","path":"/s20/probe","policies":[{"name":"dynamic-endpoint","version":"v1","params":{"targetUpstream":"down-upstream"}}]},{"method":"GET","path":"/s20/plain"}] |
    Then the response should be successful

    When I clear all headers
    And I send a "GET" request to "${CTX:apiContext}/v1.0/s20/plain" until status 200
    And I send a "GET" request to "${CTX:apiContext}/v1.0/s20/probe" until status 503
    Then the response body should not contain "/s20/probe"
    When I send a "GET" request to the "capture" service at "/test/captured?path=/s20/probe" until status 204

    # The unavailable upstream affects only the operation that selects it.
    When I send a "GET" request to "${CTX:apiContext}/v1.0/s20/plain"
    Then the response status code should be 200
    And the JSON response field "path" should be "/s20/plain"

  Scenario: The main upstream is unavailable and an operation selecting another upstream still works
    Given I generate a unique value from "dynamic-main-down" and store it as "apiName"
    And I generate a unique API context from "/dynamic-main-down" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion               | ${CTX:gatewaySpecVersion}          |
      | name                     | ${CTX:apiName}                     |
      | spec.displayName         | Dynamic-Endpoint-Main-Down-API     |
      | spec.version             | v1.0                               |
      | spec.context             | ${CTX:apiContext}/$version         |
      | spec.upstream.main.url   | http://testbench:3999              |
      | spec.upstreamDefinitions | [{"name":"alive-upstream","basePath":"/alive","upstreams":[{"url":"http://testbench:3000"}]}] |
      | spec.operations          | [{"method":"GET","path":"/s21/probe","policies":[{"name":"dynamic-endpoint","version":"v1","params":{"targetUpstream":"alive-upstream"}}]},{"method":"GET","path":"/s21/plain"}] |
    Then the response should be successful

    When I clear all headers
    And I send a "GET" request to "${CTX:apiContext}/v1.0/s21/probe" until status 200
    Then the JSON response field "path" should be "/alive/s21/probe"

    When I send a "GET" request to "${CTX:apiContext}/v1.0/s21/plain" until status 503
