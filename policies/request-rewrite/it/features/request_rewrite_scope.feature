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
Feature: Request rewrite scope and chaining
  As an API developer
  I want rewrites to apply where the policy is attached and beside other policies
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

  # RR22: The policy replaces the operation's own path prefix with /api/v2 and rewrites the method
  # to POST. Attached at API level it applies to every operation, so /orders is rewritten too.
  # Attached to /api/v1 only, the other operation, /health, reaches the backend unchanged.
  Scenario Outline: Apply the policy at <level> level
    Given I generate a unique value from "rr-<key>-level" and store it as "apiName"
    And I generate a unique API version from "rr-<key>-level" and store it as "apiVersion"
    And I generate a unique API context from "/rr-<key>-level" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}      |
      | name                   | ${CTX:apiName}                 |
      | spec.displayName       | ${CTX:apiName}                 |
      | spec.version           | ${CTX:apiVersion}              |
      | spec.context           | ${CTX:apiContext}/$version     |
      | spec.upstream.main.url | http://testbench:3002/anything |
      | spec.policies          | <apiPolicies> |
      | spec.operations        | <operations> |
    Then the resource creation response should indicate successful deployment

    When I clear all headers
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/api/v1?page=2" until status 200
    Then the response status code should be 200
    And the JSON response field "path" should be "/anything/api/v2"
    And the JSON response field "args.page" should be "2"
    And the JSON response field "method" should be "POST"

    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}<other>?page=2"
    Then the response status code should be 200
    And the JSON response field "path" should be "<otherForwarded>"
    And the JSON response field "args.page" should be "2"
    And the JSON response field "method" should be "<otherMethod>"

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/api/v1" until status 404

    Examples:
      | level     | key | apiPolicies                                                                                                                                              | operations                                                                                                                                                                                                                                | other   | otherForwarded   | otherMethod |
      | API       | api | [{"name":"request-rewrite","version":"v1","params":{"pathRewrite":{"type":"ReplacePrefixMatch","replacePrefixMatch":"/api/v2"},"methodRewrite":"POST"}}] | [{"method":"GET","path":"/api/v1"},{"method":"GET","path":"/orders"}]                                                                                                                                                                     | /orders | /anything/api/v2 | POST        |
      | operation | op  | []                                                                                                                                                       | [{"method":"GET","path":"/api/v1","policies":[{"name":"request-rewrite","version":"v1","params":{"pathRewrite":{"type":"ReplacePrefixMatch","replacePrefixMatch":"/api/v2"},"methodRewrite":"POST"}}]},{"method":"GET","path":"/health"}] | /health | /anything/health | GET         |

  # RR23: request-rewrite runs between basic-auth and basic-ratelimit, and host-rewrite runs after
  # it. A client without credentials is still refused, an authenticated request reaches the backend
  # rewritten, with the limit reported, and the Host header host-rewrite sets arrives with the
  # rewritten path.
  Scenario: Combine request-rewrite with authentication, rate limiting and host rewrite
    Given I generate a unique value from "rr-chain" and store it as "apiName"
    And I generate a unique API version from "rr-chain" and store it as "apiVersion"
    And I generate a unique API context from "/rr-chain" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion                     | ${CTX:gatewaySpecVersion}      |
      | name                           | ${CTX:apiName}                 |
      | spec.displayName               | ${CTX:apiName}                 |
      | spec.version                   | ${CTX:apiVersion}              |
      | spec.context                   | ${CTX:apiContext}/$version     |
      | spec.upstream.main.url         | http://testbench:3002/anything |
      | spec.upstream.main.hostRewrite | manual                         |
      | spec.operations                | [{"method":"GET","path":"/orders","policies":[{"name":"basic-auth","version":"v1","params":{"username":"rr-user","password":"rr-secret"}},{"name":"request-rewrite","version":"v1","params":{"pathRewrite":{"type":"ReplacePrefixMatch","replacePrefixMatch":"/v2/orders"},"queryRewrite":{"rules":[{"action":"Add","name":"source","value":"gateway"}]}}},{"name":"basic-ratelimit","version":"v1","params":{"limits":[{"requests":100,"duration":"1h"}]}},{"name":"host-rewrite","version":"v1","params":{"host":"rr-rewritten.example"}}]}] |
    Then the resource creation response should indicate successful deployment

    When I clear all headers
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/orders?page=2" until status 401

    When I set header "Authorization" to "Basic cnItdXNlcjpyci1zZWNyZXQ="
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/orders?page=2"
    Then the response status code should be 200
    And the JSON response field "path" should be "/anything/v2/orders"
    And the JSON response field "args.page" should be "2"
    And the JSON response field "args.source" should be "gateway"
    And the response header "X-RateLimit-Limit" should be "100"
    And the response should contain echoed header "Host" with value "rr-rewritten.example"

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/orders" until status 404

  # RR23: request-rewrite runs before dynamic-endpoint, which sends the request to the
  # alt-upstream definition: the testbench backend service on port 3000 with base path /alternate,
  # not the API's own upstream (the echo service on port 3002 under /anything). The backend
  # service must receive the rewritten path under /alternate. Its response has a raw "query"
  # field and no "url" field, the reverse of the echo service, so the assertions tell which
  # upstream answered.
  #
  # Known issue on gateway 1.1.0: a dynamic endpoint's request reaches the target upstream under
  # the API's own upstream base path (/anything) instead of the target's (/alternate); fixed in
  # 1.2.0 by wso2/api-platform#2000. The 1.1.0 runner skips @known-issue-gw-1.1.0.
  @known-issue-gw-1.1.0
  Scenario: Combine request-rewrite with a dynamic endpoint
    Given I generate a unique value from "rr-dynamic-endpoint" and store it as "apiName"
    And I generate a unique API version from "rr-dynamic-endpoint" and store it as "apiVersion"
    And I generate a unique API context from "/rr-dynamic-endpoint" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion               | ${CTX:gatewaySpecVersion}      |
      | name                     | ${CTX:apiName}                 |
      | spec.displayName         | ${CTX:apiName}                 |
      | spec.version             | ${CTX:apiVersion}              |
      | spec.context             | ${CTX:apiContext}/$version     |
      | spec.upstream.main.url   | http://testbench:3002/anything |
      | spec.upstreamDefinitions | [{"name":"alt-upstream","basePath":"/alternate","upstreams":[{"url":"http://testbench:3000"}]}] |
      | spec.operations          | [{"method":"GET","path":"/dynamic","policies":[{"name":"request-rewrite","version":"v1","params":{"pathRewrite":{"type":"ReplacePrefixMatch","replacePrefixMatch":"/v2"}}},{"name":"dynamic-endpoint","version":"v1","params":{"targetUpstream":"alt-upstream"}}]}] |
    Then the resource creation response should indicate successful deployment

    When I clear all headers
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/dynamic?page=2" until status 200
    Then the response status code should be 200
    And the JSON response field "path" should be "/alternate/v2"
    And the JSON response field "query" should be "page=2"
    And the JSON response field "url" should not exist

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/dynamic" until status 404
