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
Feature: Dynamic endpoint routing across gateway restarts
  As an API developer
  I want the named upstream routing to come back after a restart
  So that a restart never leaves an operation on the wrong backend

  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"

  Scenario Outline: Routing to named upstreams is restored after the <service> restarts
    Given I generate a unique value from "dynamic-restart" and store it as "apiName"
    And I generate a unique API context from "/dynamic-restart" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion               | ${CTX:gatewaySpecVersion}          |
      | name                     | ${CTX:apiName}                     |
      | spec.displayName         | Dynamic-Endpoint-Restart-API       |
      | spec.version             | v1.0                               |
      | spec.context             | ${CTX:apiContext}/$version         |
      | spec.upstream.main.url   | http://testbench:3000              |
      | spec.upstreamDefinitions | [{"name":"upstream-a","basePath":"/aaa","upstreams":[{"url":"http://testbench:3000"}]},{"name":"upstream-e","basePath":"/eee","upstreams":[{"url":"http://testbench:3002"}]}] |
      | spec.operations          | [{"method":"GET","path":"/l14/one","policies":[{"name":"dynamic-endpoint","version":"v1","params":{"targetUpstream":"upstream-a"}}]},{"method":"GET","path":"/l14/two","policies":[{"name":"dynamic-endpoint","version":"v1","params":{"targetUpstream":"upstream-e"}}]},{"method":"GET","path":"/l14/plain"}] |
    Then the response should be successful
    When I clear all headers
    And I send a "GET" request to "${CTX:apiContext}/v1.0/l14/one" until the JSON field "path" is "/aaa/l14/one"
    And I send a "GET" request to "${CTX:apiContext}/v1.0/l14/two" until the JSON field "path" is "/eee/l14/two"

    When I restart the "<service>" service
    And I wait for the gateway controller health endpoint
    And I send a GET request to the router ready endpoint until status 200
    And I send a "GET" request to "${CTX:apiContext}/v1.0/l14/one" until the JSON field "path" is "/aaa/l14/one"
    Then the response should be served by the "backend" testbench service
    When I send a "GET" request to "${CTX:apiContext}/v1.0/l14/two" until the JSON field "path" is "/eee/l14/two"
    Then the response should be served by the "echo" testbench service
    When I send a "GET" request to "${CTX:apiContext}/v1.0/l14/plain" until the JSON field "path" is "/l14/plain"

    Examples:
      | service            |
      | gateway-runtime    |
      | gateway-controller |
