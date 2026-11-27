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
# KIND, either express or implied. See the License for the
# specific language governing permissions and limitations
# under the License.
# --------------------------------------------------------------------

@respond
Feature: Respond across gateway restarts
  As an API developer
  I want the reply to survive a gateway restart
  So that clients get the response the API defines without the backend being called

  # The upstream is the testbench capture service (${CTX:captureUpstream}/<API name>). It records
  # every request that reaches it, and its /test/captured query answers 204 for a path that
  # received nothing. RES01 uses it to prove that respond answers without calling the backend;
  # the other scenarios check the reply itself.
  # Most APIs also have a /ready operation without the policy, which the scenario polls until the
  # API is deployed; it answers 200 from the capture service.

  # This scenario restarts gateway services, so it runs on its own.

  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"
    And I resolve the "capture" service URL at "" and store it as "captureUpstream"

  # RES21: The gateway controller and then the gateway runtime restart. The runtime receives the
  # configuration again from the restarted controller, and respond must return the same reply.
  # The test gateway runs a single replica.
  Scenario: Keep returning the reply after the gateway restarts
    Given I generate a unique value from "res-restart" and store it as "apiName"
    And I generate a unique API version from "res-restart" and store it as "apiVersion"
    And I generate a unique API context from "/res-restart" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}             |
      | name                   | ${CTX:apiName}                        |
      | spec.displayName       | ${CTX:apiName}                        |
      | spec.version           | ${CTX:apiVersion}                     |
      | spec.context           | ${CTX:apiContext}/$version            |
      | spec.upstream.main.url | ${CTX:captureUpstream}/${CTX:apiName} |
      | spec.operations        | [{"method":"GET","path":"/ready"},{"method":"GET","path":"/orders","policies":[{"name":"respond","version":"v1","params":{"statusCode":202,"body":"survives restarts","headers":[{"name":"X-Reply-Source","value":"gateway"}]}}]}] |
    Then the resource creation response should indicate successful deployment
    When I clear all headers
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/ready" until status 200

    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/orders"
    Then the response status code should be 202
    And the response header "X-Reply-Source" should be "gateway"
    And the response body should be:
      """
      survives restarts
      """

    When I restart the "gateway-controller" service
    And I clear all headers
    And I authenticate using basic auth as "admin"
    And I wait for the gateway controller health endpoint
    And I restart the "gateway-runtime" service
    And I clear all headers
    And I authenticate using basic auth as "admin"
    And I wait for the gateway controller health endpoint
    And I clear all headers
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/orders" until status 202
    Then the response header "X-Reply-Source" should be "gateway"
    And the response body should be:
      """
      survives restarts
      """

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/ready" until status 404
