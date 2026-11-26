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

@json-schema-guardrail
Feature: JSON Schema guardrail policy across gateway restarts
  As an API developer
  I want a guardrail-protected API to keep enforcing its schema when gateway services restart
  So that a restart never lets unchecked content reach the upstream

  # Restarting the gateway controller and the gateway runtime, so these scenarios run on their own.
  # Gateway replicas are not covered: the test environment's replicas are independent gateways
  # that share no state.

  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"

  Scenario: Restart or scale gateway replicas with the guardrail configured (restart)
    Given I generate a unique value from "jsg-restart" and store it as "apiName"
    And I generate a unique API version from "jsg-restart" and store it as "apiVersion"
    And I generate a unique API context from "/jsg-restart" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3000 |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"POST","path":"/orders","policies":[{"name":"json-schema-guardrail","version":"v1","params":{"request":{"enabled":true,"jsonPath":"","schema":"{\"type\":\"object\",\"properties\":{\"name\":{\"type\":\"string\"},\"email\":{\"type\":\"string\"}},\"required\":[\"name\",\"email\"]}"}}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/orders" with body:
      """
      {"name":"Ann","email":"ann@example.com"}
      """
    Then the response status code should be 200

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/orders" with body:
      """
      {"name":"Ann"}
      """
    Then the response status code should be 422
    And the JSON response field "message.actionReason" should be "Violation of JSON schema detected."

    When I restart the "gateway-controller" service
    And I wait for the gateway controller health endpoint
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/orders" until status 200 with body:
      """
      {"name":"Ann","email":"ann@example.com"}
      """
    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/orders" with body:
      """
      {"name":"Ann"}
      """
    Then the response status code should be 422
    And the JSON response field "message.actionReason" should be "Violation of JSON schema detected."

    When I restart the "gateway-runtime" service
    And I send a GET request to the router ready endpoint until status 200
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/orders" until status 200 with body:
      """
      {"name":"Ann","email":"ann@example.com"}
      """
    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/orders" with body:
      """
      {"name":"Ann"}
      """
    Then the response status code should be 422
    And the JSON response field "message.actionReason" should be "Violation of JSON schema detected."

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 404
