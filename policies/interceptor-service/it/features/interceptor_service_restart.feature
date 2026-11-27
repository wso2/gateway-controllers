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

@interceptor-service
Feature: Interceptor service policy across gateway restarts
  As an API developer
  I want interception to resume after the gateway runtime or controller restarts
  So that a restart never leaves an API uninspected

  # The backend answers any path with a JSON description of the request it received.
  # "request":{} turns on request-phase interception with its defaults: the request headers and
  # body go to the interceptor, and a failed call returns 500.

  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"

  Scenario: Restart or scale gateway replicas with interceptor enabled (restart gateway-runtime)
    Given I generate a unique value from "is-restart-runtime" and store it as "apiName"
    And I generate a unique API version from "is-restart-runtime" and store it as "apiVersion"
    And I generate a unique API context from "/is-restart-runtime" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3000 |
      | spec.operations        | [{"method":"GET","path":"/items","policies":[{"name":"interceptor-service","version":"v1","params":{"endpoint":"http://testbench:3003/scripted/${CTX:apiName}","request":{}}}]}] |
    Then the resource creation response should indicate successful deployment

    # Reply: {"headersToAdd":{"X-Intercepted":"request"}}
    When I set header "X-Testbench-Interceptor-Request-Reply" to "eyJoZWFkZXJzVG9BZGQiOnsiWC1JbnRlcmNlcHRlZCI6InJlcXVlc3QifX0="
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/items" until status 200
    Then the JSON response field "headers.X-Intercepted[0]" should be "request"

    When I restart the "gateway-runtime" service
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/items" until status 200
    Then the JSON response field "headers.X-Intercepted[0]" should be "request"

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/items" until status 404

  # A runtime keeps the configuration it already has while the controller restarts, so traffic alone
  # cannot show the controller kept the API. Restarting the runtime afterwards makes it fetch its
  # configuration from the restarted controller: interception then shows the controller still serves
  # the API with its interceptor attachment.
  Scenario: Restart or scale gateway replicas with interceptor enabled (restart gateway-controller, then gateway-runtime)
    Given I generate a unique value from "is-restart-controller" and store it as "apiName"
    And I generate a unique API version from "is-restart-controller" and store it as "apiVersion"
    And I generate a unique API context from "/is-restart-controller" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3000 |
      | spec.operations        | [{"method":"GET","path":"/items","policies":[{"name":"interceptor-service","version":"v1","params":{"endpoint":"http://testbench:3003/scripted/${CTX:apiName}","request":{}}}]}] |
    Then the resource creation response should indicate successful deployment

    # Reply: {"headersToAdd":{"X-Intercepted":"request"}}
    When I set header "X-Testbench-Interceptor-Request-Reply" to "eyJoZWFkZXJzVG9BZGQiOnsiWC1JbnRlcmNlcHRlZCI6InJlcXVlc3QifX0="
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/items" until status 200
    Then the JSON response field "headers.X-Intercepted[0]" should be "request"

    When I restart the "gateway-controller" service
    And I wait for the gateway controller health endpoint
    And I restart the "gateway-runtime" service
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/items" until status 200
    Then the JSON response field "headers.X-Intercepted[0]" should be "request"

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/items" until status 404
