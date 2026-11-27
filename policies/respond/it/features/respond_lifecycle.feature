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
Feature: Respond across updates, load and observability
  As an API developer
  I want the reply to follow configuration changes and stay observable
  So that clients get the response the API defines without the backend being called

  # The upstream is the testbench capture service (${CTX:captureUpstream}/<API name>). It records
  # every request that reaches it, and its /test/captured query answers 204 for a path that
  # received nothing. RES01 uses it to prove that respond answers without calling the backend;
  # the other scenarios check the reply itself.
  # Most APIs also have a /ready operation without the policy, which the scenario polls until the
  # API is deployed; it answers 200 from the capture service.

  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"
    And I resolve the "capture" service URL at "" and store it as "captureUpstream"

  # RES19, RES20: The reply is updated on the deployed API, and then the policy is removed. Each
  # change takes effect once it has propagated: the new status, body and header, and then the
  # normal flow, where the capture service answers the request.
  Scenario: Update and then remove respond on a deployed API
    Given I generate a unique value from "res-update" and store it as "apiName"
    And I generate a unique API version from "res-update" and store it as "apiVersion"
    And I generate a unique API context from "/res-update" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}             |
      | name                   | ${CTX:apiName}                        |
      | spec.displayName       | ${CTX:apiName}                        |
      | spec.version           | ${CTX:apiVersion}                     |
      | spec.context           | ${CTX:apiContext}/$version            |
      | spec.upstream.main.url | ${CTX:captureUpstream}/${CTX:apiName} |
      | spec.operations        | [{"method":"GET","path":"/ready"},{"method":"GET","path":"/orders","policies":[{"name":"respond","version":"v1","params":{"statusCode":200,"body":"first reply"}}]}] |
    Then the resource creation response should indicate successful deployment
    When I clear all headers
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/ready" until status 200

    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/orders"
    Then the response status code should be 200
    And the response body should be:
      """
      first reply
      """

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I update API "${CTX:apiName}" from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}             |
      | name                   | ${CTX:apiName}                        |
      | spec.displayName       | ${CTX:apiName}                        |
      | spec.version           | ${CTX:apiVersion}                     |
      | spec.context           | ${CTX:apiContext}/$version            |
      | spec.upstream.main.url | ${CTX:captureUpstream}/${CTX:apiName} |
      | spec.operations        | [{"method":"GET","path":"/ready"},{"method":"GET","path":"/orders","policies":[{"name":"respond","version":"v1","params":{"statusCode":202,"body":"second reply","headers":[{"name":"X-Reply-Version","value":"2"}]}}]}] |
    Then the API update response should indicate successful deployment

    When I clear all headers
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/orders" until status 202 and the response body contains "second reply"
    Then the response header "X-Reply-Version" should be "2"
    And the response body should be:
      """
      second reply
      """

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I update API "${CTX:apiName}" from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}             |
      | name                   | ${CTX:apiName}                        |
      | spec.displayName       | ${CTX:apiName}                        |
      | spec.version           | ${CTX:apiVersion}                     |
      | spec.context           | ${CTX:apiContext}/$version            |
      | spec.upstream.main.url | ${CTX:captureUpstream}/${CTX:apiName} |
      | spec.operations        | [{"method":"GET","path":"/ready"},{"method":"GET","path":"/orders"}] |
    Then the API update response should indicate successful deployment

    When I clear all headers
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/orders" until status 200 and the response body contains "/${CTX:apiName}/orders"
    Then the JSON response field "path" should be "/${CTX:apiName}/orders"

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/ready" until status 404

  # RES22: 100 concurrent requests, each with its own body, all receive the configured reply.
  Scenario: Answer concurrent requests with the same reply
    Given I generate a unique value from "res-concurrent" and store it as "apiName"
    And I generate a unique API version from "res-concurrent" and store it as "apiVersion"
    And I generate a unique API context from "/res-concurrent" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}             |
      | name                   | ${CTX:apiName}                        |
      | spec.displayName       | ${CTX:apiName}                        |
      | spec.version           | ${CTX:apiVersion}                     |
      | spec.context           | ${CTX:apiContext}/$version            |
      | spec.upstream.main.url | ${CTX:captureUpstream}/${CTX:apiName} |
      | spec.operations        | [{"method":"GET","path":"/ready"},{"method":"POST","path":"/orders","policies":[{"name":"respond","version":"v1","params":{"statusCode":200,"body":"concurrent reply"}}]}] |
    Then the resource creation response should indicate successful deployment
    When I clear all headers
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/ready" until status 200

    When I send 100 concurrent "POST" requests to "${CTX:apiContext}/${CTX:apiVersion}/orders" cycling through:
      | body              | status | contains         |
      | {"client":"{i}"} | 200    | concurrent reply |

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/ready" until status 404

  # RES30: Analytics records the request method and the reply's status for respond traffic, and
  # a 401 from basic-auth in front of respond is recorded too. The gateway records a request the
  # policy chain answers under the API's context, without the operation path, so each event is
  # read right after its request; if it starts recording the full path, these checks need /orders
  # and /protected. The caller's token never reaches the runtime log. (The test gateway records
  # request headers, Authorization included, in analytics for every request, with or without
  # respond; removing them is analytics-header-filter's job.) The /logged operation writes a line
  # with this scenario's marker first, so the negative log check reads a log holding its lines.
  Scenario: Record replies in analytics and keep the caller's token out of the logs
    Given I generate a unique value from "res-analytics" and store it as "apiName"
    And I generate a unique API version from "res-analytics" and store it as "apiVersion"
    And I generate a unique API context from "/res-analytics" and store it as "apiContext"
    And I generate a unique value from "res-caller-token" and store it as "callerToken"
    And I generate a unique value from "res-log-marker" and store it as "marker"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}             |
      | name                   | ${CTX:apiName}                        |
      | spec.displayName       | ${CTX:apiName}                        |
      | spec.version           | ${CTX:apiVersion}                     |
      | spec.context           | ${CTX:apiContext}/$version            |
      | spec.upstream.main.url | ${CTX:captureUpstream}/${CTX:apiName} |
      | spec.operations        | [{"method":"GET","path":"/ready"},{"method":"GET","path":"/orders","policies":[{"name":"respond","version":"v1","params":{"statusCode":503,"body":"maintenance"}}]},{"method":"GET","path":"/protected","policies":[{"name":"basic-auth","version":"v1","params":{"username":"res-user","password":"res-secret"}},{"name":"respond","version":"v1","params":{"body":"protected reply"}}]},{"method":"GET","path":"/logged","policies":[{"name":"set-headers","version":"v1","params":{"request":{"headers":[{"name":"X-Added-By-Gateway","value":"${CTX:marker}"}]}}},{"name":"log-message","version":"v1","params":{"request":{"headers":true}}}]}] |
    Then the resource creation response should indicate successful deployment
    When I clear all headers
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/ready" until status 200

    And I reset the analytics collector
    And I set header "Authorization" to "Bearer ${CTX:callerToken}"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/orders"
    Then the response status code should be 503
    And I wait for the analytics collector to settle
    And the latest analytics event for path "${CTX:apiContext}/${CTX:apiVersion}" should have request method "GET"
    And the latest analytics event for path "${CTX:apiContext}/${CTX:apiVersion}" should have response status 503

    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/protected"
    Then the response status code should be 401
    And I wait for the analytics collector to settle
    And the latest analytics event for path "${CTX:apiContext}/${CTX:apiVersion}" should have response status 401

    When I clear all headers
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/logged"
    Then the response status code should be 200
    And the "gateway-runtime" service logs should contain "${CTX:marker}"
    And the "gateway-runtime" service logs should not contain "${CTX:callerToken}"

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/ready" until status 404
