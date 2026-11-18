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

@host-rewrite
Feature: Host rewrite policy across gateway restarts
  As an API developer
  I want the configured upstream Host to survive a gateway restart
  So that a restart never sends requests upstream with another Host

  # These scenarios restart gateway services, so they run on their own.

  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"

  # After a restart, the runtime loads its configuration again from the controller.
  Scenario: Restart the gateway/controller with Host Rewrite configured (restart gateway-runtime)
    Given I generate a unique value from "hr-restart-runtime" and store it as "apiName"
    And I generate a unique API context from "/hr-restart-runtime" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion                     | ${CTX:gatewaySpecVersion} |
      | name                           | ${CTX:apiName} |
      | spec.displayName               | ${CTX:apiName} |
      | spec.version                   | v1.0 |
      | spec.context                   | ${CTX:apiContext}/$version |
      | spec.upstream.main.url         | http://testbench:3002/anything |
      | spec.upstream.main.hostRewrite | manual |
      | spec.operations                | [{"method":"POST","path":"/probe","policies":[{"name":"host-rewrite","version":"v1","params":{"host":"hr-restart-runtime.example"}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "POST" request to "${CTX:apiContext}/v1.0/probe" until status 200
    Then the JSON response field "headers.Host" should be "hr-restart-runtime.example"

    When I restart the "gateway-runtime" service
    And I clear all headers
    And I authenticate using basic auth as "admin"
    And I wait for the gateway controller health endpoint
    And I send a "POST" request to "${CTX:apiContext}/v1.0/probe" until the response body contains "hr-restart-runtime.example" with body:
      """
      {}
      """
    When I send a "POST" request to "${CTX:apiContext}/v1.0/probe"
    Then the response status code should be 200
    And the JSON response field "headers.Host" should be "hr-restart-runtime.example"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "POST" request to "${CTX:apiContext}/v1.0/probe" until status 404

  # The runtime keeps its configuration while the controller restarts. Restarting the runtime
  # afterwards makes it load the configuration from the restarted controller, which shows the
  # controller kept the policy's host.
  Scenario: Restart the gateway/controller with Host Rewrite configured (restart gateway-controller, then gateway-runtime)
    Given I generate a unique value from "hr-restart-controller" and store it as "apiName"
    And I generate a unique API context from "/hr-restart-controller" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion                     | ${CTX:gatewaySpecVersion} |
      | name                           | ${CTX:apiName} |
      | spec.displayName               | ${CTX:apiName} |
      | spec.version                   | v1.0 |
      | spec.context                   | ${CTX:apiContext}/$version |
      | spec.upstream.main.url         | http://testbench:3002/anything |
      | spec.upstream.main.hostRewrite | manual |
      | spec.operations                | [{"method":"POST","path":"/probe","policies":[{"name":"host-rewrite","version":"v1","params":{"host":"hr-restart-controller.example"}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "POST" request to "${CTX:apiContext}/v1.0/probe" until status 200

    When I restart the "gateway-controller" service
    And I clear all headers
    And I authenticate using basic auth as "admin"
    And I wait for the gateway controller health endpoint
    And I restart the "gateway-runtime" service
    And I clear all headers
    And I authenticate using basic auth as "admin"
    And I wait for the gateway controller health endpoint
    And I send a "POST" request to "${CTX:apiContext}/v1.0/probe" until the response body contains "hr-restart-controller.example" with body:
      """
      {}
      """
    When I send a "POST" request to "${CTX:apiContext}/v1.0/probe"
    Then the response status code should be 200
    And the JSON response field "headers.Host" should be "hr-restart-controller.example"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "POST" request to "${CTX:apiContext}/v1.0/probe" until status 404
