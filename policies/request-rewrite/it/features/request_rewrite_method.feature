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

@request-rewrite
Feature: Request rewrite of the method
  As an API developer
  I want the request method rewritten, alone or with the path and query
  So that the backend receives the request the API defines and nothing else changes

  # The backend is the testbench echo service at http://testbench:3002/anything. It returns the
  # request it received as JSON: "method", "path" (the upstream base path /anything followed by the
  # path the gateway forwarded), "args" (the query parameters; a repeated one is a list) and
  # "headers". The path, query and method assertions read these fields. A request whose forwarded
  # form is checked also sends page=2, a parameter no rule names, as a control that must reach the
  # backend unchanged.

  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"

  # RR13, RR14: The client sends <sent> and the policy rewrites the method to <rewritten>. The
  # backend must receive <rewritten> on the same path and query.
  Scenario Outline: Rewrite the request method (<sent> to <rewritten>)
    Given I generate a unique value from "rr-method-<rewritten>" and store it as "apiName"
    And I generate a unique API version from "rr-method-<rewritten>" and store it as "apiVersion"
    And I generate a unique API context from "/rr-method-<rewritten>" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}      |
      | name                   | ${CTX:apiName}                 |
      | spec.displayName       | ${CTX:apiName}                 |
      | spec.version           | ${CTX:apiVersion}              |
      | spec.context           | ${CTX:apiContext}/$version     |
      | spec.upstream.main.url | http://testbench:3002/anything |
      | spec.operations        | [{"method":"<sent>","path":"/orders","policies":[{"name":"request-rewrite","version":"v1","params":{"methodRewrite":"<rewritten>"}}]}] |
    Then the resource creation response should indicate successful deployment

    When I clear all headers
    And I send a "<sent>" request to "${CTX:apiContext}/${CTX:apiVersion}/orders?page=2" until status 200
    Then the response status code should be 200
    And the JSON response field "path" should be "/anything/orders"
    And the JSON response field "args.page" should be "2"
    And the JSON response field "method" should be "<rewritten>"

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/orders" until status 404

    Examples:
      | sent | rewritten |
      | POST | GET       |
      | GET  | POST      |
      | GET  | PUT       |
      | GET  | DELETE    |
      | GET  | PATCH     |
      | GET  | OPTIONS   |

  # RR14: A GET rewritten to HEAD must reach the backend as HEAD. The echo cannot report the
  # method of a HEAD request, so both requests carry a 3 KiB query value: the echo's reply is then
  # over 2 KiB and is streamed without a Content-Length. A GET to the operation without the policy
  # receives that reply as JSON, and the rewritten GET must receive an empty 200, which only a HEAD
  # to the backend returns. A shorter reply would carry a Content-Length the client waits for.
  Scenario: Rewrite the request method to HEAD
    Given I generate a unique value from "rr-method-head" and store it as "apiName"
    And I generate a unique API version from "rr-method-head" and store it as "apiVersion"
    And I generate a unique API context from "/rr-method-head" and store it as "apiContext"
    And I generate a value of 3 KiB of "QUFB" and store it as "padding"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}      |
      | name                   | ${CTX:apiName}                 |
      | spec.displayName       | ${CTX:apiName}                 |
      | spec.version           | ${CTX:apiVersion}              |
      | spec.context           | ${CTX:apiContext}/$version     |
      | spec.upstream.main.url | http://testbench:3002/anything |
      | spec.operations        | [{"method":"GET","path":"/plain"},{"method":"GET","path":"/orders","policies":[{"name":"request-rewrite","version":"v1","params":{"methodRewrite":"HEAD"}}]}] |
    Then the resource creation response should indicate successful deployment

    When I clear all headers
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/plain?page=2&pad=${CTX:padding}" until status 200
    Then the response status code should be 200
    And the JSON response field "path" should be "/anything/plain"
    And the JSON response field "args.page" should be "2"
    And the JSON response field "method" should be "GET"

    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/orders?page=2&pad=${CTX:padding}"
    Then the response status code should be 200
    And the response body should be empty

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/plain" until status 404

  # RR15: One policy rewrites the path prefix, adds and removes query parameters and changes the
  # method. A POST with a body must reach the backend as a PUT on the new path, with the new query
  # and the same body.
  Scenario: Rewrite the path, query and method of one request
    Given I generate a unique value from "rr-all" and store it as "apiName"
    And I generate a unique API version from "rr-all" and store it as "apiVersion"
    And I generate a unique API context from "/rr-all" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}      |
      | name                   | ${CTX:apiName}                 |
      | spec.displayName       | ${CTX:apiName}                 |
      | spec.version           | ${CTX:apiVersion}              |
      | spec.context           | ${CTX:apiContext}/$version     |
      | spec.upstream.main.url | http://testbench:3002/anything |
      | spec.operations        | [{"method":"POST","path":"/legacy/orders","policies":[{"name":"request-rewrite","version":"v1","params":{"pathRewrite":{"type":"ReplacePrefixMatch","replacePrefixMatch":"/v2/orders"},"queryRewrite":{"rules":[{"action":"Add","name":"source","value":"gateway"},{"action":"Remove","name":"debug"}]},"methodRewrite":"PUT"}}]}] |
    Then the resource creation response should indicate successful deployment

    When I clear all headers
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/legacy/orders?debug=true&page=2" until status 200 with body:
      """
      {"item":"book"}
      """
    Then the response status code should be 200
    And the JSON response field "path" should be "/anything/v2/orders"
    And the JSON response field "args.page" should be "2"
    And the JSON response field "method" should be "PUT"
    And the JSON response field "args.source" should be "gateway"
    And the JSON response field "args.debug" should not exist
    And the JSON response field "json.item" should be "book"

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/legacy/orders" until status 404
