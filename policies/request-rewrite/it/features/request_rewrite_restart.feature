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
Feature: Request rewrite across gateway restarts
  As an API developer
  I want rewrites to survive a gateway restart
  So that the backend receives the request the API defines and nothing else changes

  # The backend is the testbench echo service at http://testbench:3002/anything. It returns the
  # request it received as JSON: "method", "path" (the upstream base path /anything followed by the
  # path the gateway forwarded), "args" (the query parameters; a repeated one is a list) and
  # "headers". The path, query and method assertions read these fields. A request whose forwarded
  # form is checked also sends page=2, a parameter no rule names, as a control that must reach the
  # backend unchanged.

  # This scenario restarts gateway services, so it runs on its own.

  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"

  # RR25: The gateway controller and then the gateway runtime are restarted. The runtime loads its
  # configuration again from the restarted controller, and the policy must rewrite the path, query
  # and method exactly as before.
  Scenario: Keep rewriting requests after the gateway restarts
    Given I generate a unique value from "rr-restart" and store it as "apiName"
    And I generate a unique API version from "rr-restart" and store it as "apiVersion"
    And I generate a unique API context from "/rr-restart" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}      |
      | name                   | ${CTX:apiName}                 |
      | spec.displayName       | ${CTX:apiName}                 |
      | spec.version           | ${CTX:apiVersion}              |
      | spec.context           | ${CTX:apiContext}/$version     |
      | spec.upstream.main.url | http://testbench:3002/anything |
      | spec.operations        | [{"method":"GET","path":"/api/v1","policies":[{"name":"request-rewrite","version":"v1","params":{"pathRewrite":{"type":"ReplacePrefixMatch","replacePrefixMatch":"/api/v2"},"queryRewrite":{"rules":[{"action":"Add","name":"source","value":"gateway"}]},"methodRewrite":"POST"}}]}] |
    Then the resource creation response should indicate successful deployment

    When I clear all headers
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/api/v1?page=2" until status 200
    Then the response status code should be 200
    And the JSON response field "path" should be "/anything/api/v2"
    And the JSON response field "args.page" should be "2"
    And the JSON response field "args.source" should be "gateway"
    And the JSON response field "method" should be "POST"

    When I restart the "gateway-controller" service
    And I clear all headers
    And I authenticate using basic auth as "admin"
    And I wait for the gateway controller health endpoint
    And I restart the "gateway-runtime" service
    And I clear all headers
    And I authenticate using basic auth as "admin"
    And I wait for the gateway controller health endpoint
    And I clear all headers
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/api/v1?page=2" until status 200
    Then the response status code should be 200
    And the JSON response field "path" should be "/anything/api/v2"
    And the JSON response field "args.page" should be "2"
    And the JSON response field "args.source" should be "gateway"
    And the JSON response field "method" should be "POST"

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/api/v1" until status 404
