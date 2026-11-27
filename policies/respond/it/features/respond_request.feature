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
Feature: Respond to any client request
  As an API developer
  I want the configured reply returned whatever the client sends
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

  # RES09: The same reply is configured on an operation of each method, and each one answers with
  # it.
  Scenario Outline: Answer requests of every method (<method>)
    Given I generate a unique value from "res-method-<method>" and store it as "apiName"
    And I generate a unique API version from "res-method-<method>" and store it as "apiVersion"
    And I generate a unique API context from "/res-method-<method>" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}             |
      | name                   | ${CTX:apiName}                        |
      | spec.displayName       | ${CTX:apiName}                        |
      | spec.version           | ${CTX:apiVersion}                     |
      | spec.context           | ${CTX:apiContext}/$version            |
      | spec.upstream.main.url | ${CTX:captureUpstream}/${CTX:apiName} |
      | spec.operations        | [{"method":"GET","path":"/ready"},{"method":"<method>","path":"/orders","policies":[{"name":"respond","version":"v1","params":{"statusCode":200,"body":"same reply"}}]}] |
    Then the resource creation response should indicate successful deployment
    When I clear all headers
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/ready" until status 200

    When I send a "<method>" request to "${CTX:apiContext}/${CTX:apiVersion}/orders"
    Then the response status code should be 200
    And the response body should be:
      """
      same reply
      """

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/ready" until status 404

    Examples:
      | method  |
      | GET     |
      | POST    |
      | PUT     |
      | PATCH   |
      | DELETE  |
      | OPTIONS |

  # RES10, RES27: Path parameters, query parameters, headers and a request body do not change the
  # reply, including values that try to override the configured status,
  # body or header. The client always receives the configured 202, body and X-Reply-Source.
  Scenario Outline: Ignore client input (<case>)
    Given I generate a unique value from "res-input-<key>" and store it as "apiName"
    And I generate a unique API version from "res-input-<key>" and store it as "apiVersion"
    And I generate a unique API context from "/res-input-<key>" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}             |
      | name                   | ${CTX:apiName}                        |
      | spec.displayName       | ${CTX:apiName}                        |
      | spec.version           | ${CTX:apiVersion}                     |
      | spec.context           | ${CTX:apiContext}/$version            |
      | spec.upstream.main.url | ${CTX:captureUpstream}/${CTX:apiName} |
      | spec.operations        | [{"method":"GET","path":"/ready"},{"method":"POST","path":"/orders/{id}","policies":[{"name":"respond","version":"v1","params":{"statusCode":202,"body":"accepted","headers":[{"name":"X-Reply-Source","value":"gateway"}]}}]}] |
    Then the resource creation response should indicate successful deployment
    When I clear all headers
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/ready" until status 200

    And I set header "<header>" to "<value>"
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}<path>" with body:
      """
      <body>
      """
    Then the response status code should be 202
    And the response header "X-Reply-Source" should be "gateway"
    And the response body should be:
      """
      accepted
      """

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/ready" until status 404

    Examples:
      | case                                 | key             | path                                   | header         | value    | body                                                                                       |
      | path parameter                       | path            | /orders/42                             | X-Client-Id    | client-1 | {}                                                                                         |
      | query parameters                     | query           | /orders/42?page=2&tag=a%26b            | X-Client-Id    | client-1 | {}                                                                                         |
      | custom header                        | header          | /orders/42                             | X-Tenant       | tenant-a | {}                                                                                         |
      | request body                         | body            | /orders/42                             | X-Client-Id    | client-1 | {"item":"book","qty":2}                                                                    |
      | status in the query                  | query-override  | /orders/42?statusCode=500&body=changed | X-Client-Id    | client-1 | {}                                                                                         |
      | status in a header                   | header-status   | /orders/42                             | X-Status-Code  | 500      | {}                                                                                         |
      | configured header sent by the client | header-override | /orders/42                             | X-Reply-Source | client   | {}                                                                                         |
      | status, body and headers in the body | body-override   | /orders/42                             | X-Client-Id    | client-1 | {"statusCode":500,"body":"changed","headers":[{"name":"X-Reply-Source","value":"client"}]} |
