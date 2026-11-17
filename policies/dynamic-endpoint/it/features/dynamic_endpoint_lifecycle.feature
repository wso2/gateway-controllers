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
Feature: Dynamic endpoint configuration changes on a deployed API
  As an API developer
  I want routing to follow the latest API configuration
  So that changing, adding or removing the policy needs no gateway restart and leaves nothing stale

  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"

  @de-11
  Scenario: Changing targetUpstream and redeploying routes new requests to the new upstream only
    Given I generate a unique value from "dynamic-change-target" and store it as "apiName"
    And I generate a unique API context from "/dynamic-change-target" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion               | ${CTX:gatewaySpecVersion}          |
      | name                     | ${CTX:apiName}                     |
      | spec.displayName         | Dynamic-Endpoint-Change-Target-API |
      | spec.version             | v1.0                               |
      | spec.context             | ${CTX:apiContext}/$version         |
      | spec.upstream.main.url   | http://testbench:3000              |
      | spec.upstreamDefinitions | [{"name":"upstream-a","basePath":"/aaa","upstreams":[{"url":"http://testbench:3000"}]},{"name":"upstream-b","basePath":"/bbb","upstreams":[{"url":"http://testbench:3002"}]}] |
      | spec.operations          | [{"method":"GET","path":"/l11/probe","policies":[{"name":"dynamic-endpoint","version":"v1","params":{"targetUpstream":"upstream-a"}}]}] |
    Then the response should be successful
    When I clear all headers
    And I send a "GET" request to "${CTX:apiContext}/v1.0/l11/probe" until the JSON field "path" is "/aaa/l11/probe"
    Then the response should be served by the "backend" testbench service

    When I authenticate using basic auth as "admin"
    And I update API "${CTX:apiName}" from "resources/templates/rest-api.yaml" with values:
      | apiVersion               | ${CTX:gatewaySpecVersion}          |
      | name                     | ${CTX:apiName}                     |
      | spec.displayName         | Dynamic-Endpoint-Change-Target-API |
      | spec.version             | v1.0                               |
      | spec.context             | ${CTX:apiContext}/$version         |
      | spec.upstream.main.url   | http://testbench:3000              |
      | spec.upstreamDefinitions | [{"name":"upstream-a","basePath":"/aaa","upstreams":[{"url":"http://testbench:3000"}]},{"name":"upstream-b","basePath":"/bbb","upstreams":[{"url":"http://testbench:3002"}]}] |
      | spec.operations          | [{"method":"GET","path":"/l11/probe","policies":[{"name":"dynamic-endpoint","version":"v1","params":{"targetUpstream":"upstream-b"}}]}] |
    Then the API update response should indicate successful deployment

    When I clear all headers
    And I send a "GET" request to "${CTX:apiContext}/v1.0/l11/probe" until the JSON field "path" is "/bbb/l11/probe"
    Then the response should be served by the "echo" testbench service
    When I send 10 "GET" requests to "${CTX:apiContext}/v1.0/l11/probe"
    Then the response should be served by the "echo" testbench service
    And the JSON response field "path" should be "/bbb/l11/probe"

  @de-12
  Scenario: Adding and removing the policy changes routing without a gateway restart
    Given I generate a unique value from "dynamic-add-remove" and store it as "apiName"
    And I generate a unique API context from "/dynamic-add-remove" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion               | ${CTX:gatewaySpecVersion}          |
      | name                     | ${CTX:apiName}                     |
      | spec.displayName         | Dynamic-Endpoint-Add-Remove-API    |
      | spec.version             | v1.0                               |
      | spec.context             | ${CTX:apiContext}/$version         |
      | spec.upstream.main.url   | http://testbench:3000              |
      | spec.upstreamDefinitions | [{"name":"alt-upstream","basePath":"/alternate","upstreams":[{"url":"http://testbench:3000"}]}] |
      | spec.operations          | [{"method":"GET","path":"/l12/probe"}] |
    Then the response should be successful
    When I clear all headers
    And I send a "GET" request to "${CTX:apiContext}/v1.0/l12/probe" until the JSON field "path" is "/l12/probe"

    When I authenticate using basic auth as "admin"
    And I update API "${CTX:apiName}" from "resources/templates/rest-api.yaml" with values:
      | apiVersion               | ${CTX:gatewaySpecVersion}          |
      | name                     | ${CTX:apiName}                     |
      | spec.displayName         | Dynamic-Endpoint-Add-Remove-API    |
      | spec.version             | v1.0                               |
      | spec.context             | ${CTX:apiContext}/$version         |
      | spec.upstream.main.url   | http://testbench:3000              |
      | spec.upstreamDefinitions | [{"name":"alt-upstream","basePath":"/alternate","upstreams":[{"url":"http://testbench:3000"}]}] |
      | spec.operations          | [{"method":"GET","path":"/l12/probe","policies":[{"name":"dynamic-endpoint","version":"v1","params":{"targetUpstream":"alt-upstream"}}]}] |
    Then the API update response should indicate successful deployment
    When I clear all headers
    And I send a "GET" request to "${CTX:apiContext}/v1.0/l12/probe" until the JSON field "path" is "/alternate/l12/probe"

    When I authenticate using basic auth as "admin"
    And I update API "${CTX:apiName}" from "resources/templates/rest-api.yaml" with values:
      | apiVersion               | ${CTX:gatewaySpecVersion}          |
      | name                     | ${CTX:apiName}                     |
      | spec.displayName         | Dynamic-Endpoint-Add-Remove-API    |
      | spec.version             | v1.0                               |
      | spec.context             | ${CTX:apiContext}/$version         |
      | spec.upstream.main.url   | http://testbench:3000              |
      | spec.upstreamDefinitions | [{"name":"alt-upstream","basePath":"/alternate","upstreams":[{"url":"http://testbench:3000"}]}] |
      | spec.operations          | [{"method":"GET","path":"/l12/probe"}] |
    Then the API update response should indicate successful deployment
    When I clear all headers
    And I send a "GET" request to "${CTX:apiContext}/v1.0/l12/probe" until the JSON field "path" is "/l12/probe"

  @de-13
  Scenario: Changing the url or base path of the named upstream is picked up without changing the policy
    Given I generate a unique value from "dynamic-change-definition" and store it as "apiName"
    And I generate a unique API context from "/dynamic-change-definition" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion               | ${CTX:gatewaySpecVersion}          |
      | name                     | ${CTX:apiName}                     |
      | spec.displayName         | Dynamic-Endpoint-Change-Definition-API |
      | spec.version             | v1.0                               |
      | spec.context             | ${CTX:apiContext}/$version         |
      | spec.upstream.main.url   | http://testbench:3000              |
      | spec.upstreamDefinitions | [{"name":"target-upstream","basePath":"/one","upstreams":[{"url":"http://testbench:3000"}]}] |
      | spec.operations          | [{"method":"GET","path":"/l13/probe","policies":[{"name":"dynamic-endpoint","version":"v1","params":{"targetUpstream":"target-upstream"}}]}] |
    Then the response should be successful
    When I clear all headers
    And I send a "GET" request to "${CTX:apiContext}/v1.0/l13/probe" until the JSON field "path" is "/one/l13/probe"

    When I authenticate using basic auth as "admin"
    And I update API "${CTX:apiName}" from "resources/templates/rest-api.yaml" with values:
      | apiVersion               | ${CTX:gatewaySpecVersion}          |
      | name                     | ${CTX:apiName}                     |
      | spec.displayName         | Dynamic-Endpoint-Change-Definition-API |
      | spec.version             | v1.0                               |
      | spec.context             | ${CTX:apiContext}/$version         |
      | spec.upstream.main.url   | http://testbench:3000              |
      | spec.upstreamDefinitions | [{"name":"target-upstream","basePath":"/two","upstreams":[{"url":"http://testbench:3000"}]}] |
      | spec.operations          | [{"method":"GET","path":"/l13/probe","policies":[{"name":"dynamic-endpoint","version":"v1","params":{"targetUpstream":"target-upstream"}}]}] |
    Then the API update response should indicate successful deployment
    When I clear all headers
    And I send a "GET" request to "${CTX:apiContext}/v1.0/l13/probe" until the JSON field "path" is "/two/l13/probe"
    Then the response should be served by the "backend" testbench service

    When I authenticate using basic auth as "admin"
    And I update API "${CTX:apiName}" from "resources/templates/rest-api.yaml" with values:
      | apiVersion               | ${CTX:gatewaySpecVersion}          |
      | name                     | ${CTX:apiName}                     |
      | spec.displayName         | Dynamic-Endpoint-Change-Definition-API |
      | spec.version             | v1.0                               |
      | spec.context             | ${CTX:apiContext}/$version         |
      | spec.upstream.main.url   | http://testbench:3000              |
      | spec.upstreamDefinitions | [{"name":"target-upstream","basePath":"/two","upstreams":[{"url":"http://testbench:3002"}]}] |
      | spec.operations          | [{"method":"GET","path":"/l13/probe","policies":[{"name":"dynamic-endpoint","version":"v1","params":{"targetUpstream":"target-upstream"}}]}] |
    Then the API update response should indicate successful deployment
    When I clear all headers
    And I send a "GET" request to "${CTX:apiContext}/v1.0/l13/probe" until the JSON field "url" is "/two/l13/probe"
    Then the response should be served by the "echo" testbench service

  @de-25
  Scenario: An API deleted and recreated with different upstream definitions uses only the new ones
    Given I generate a unique value from "dynamic-recreate" and store it as "apiName"
    And I generate a unique API context from "/dynamic-recreate" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion               | ${CTX:gatewaySpecVersion}          |
      | name                     | ${CTX:apiName}                     |
      | spec.displayName         | Dynamic-Endpoint-Recreate-API      |
      | spec.version             | v1.0                               |
      | spec.context             | ${CTX:apiContext}/$version         |
      | spec.upstream.main.url   | http://testbench:3000              |
      | spec.upstreamDefinitions | [{"name":"target-upstream","basePath":"/first","upstreams":[{"url":"http://testbench:3000"}]}] |
      | spec.operations          | [{"method":"GET","path":"/l25/probe","policies":[{"name":"dynamic-endpoint","version":"v1","params":{"targetUpstream":"target-upstream"}}]}] |
    Then the response should be successful
    When I clear all headers
    And I send a "GET" request to "${CTX:apiContext}/v1.0/l25/probe" until the JSON field "path" is "/first/l25/probe"

    When I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    When I clear all headers
    And I send a "GET" request to "${CTX:apiContext}/v1.0/l25/probe" until status 404

    When I authenticate using basic auth as "admin"
    And I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion               | ${CTX:gatewaySpecVersion}          |
      | name                     | ${CTX:apiName}                     |
      | spec.displayName         | Dynamic-Endpoint-Recreate-API      |
      | spec.version             | v1.0                               |
      | spec.context             | ${CTX:apiContext}/$version         |
      | spec.upstream.main.url   | http://testbench:3000              |
      | spec.upstreamDefinitions | [{"name":"target-upstream","basePath":"/second","upstreams":[{"url":"http://testbench:3002"}]},{"name":"extra-upstream","basePath":"/extra","upstreams":[{"url":"http://testbench:3000"}]}] |
      | spec.operations          | [{"method":"GET","path":"/l25/probe","policies":[{"name":"dynamic-endpoint","version":"v1","params":{"targetUpstream":"target-upstream"}}]}] |
    Then the response should be successful
    When I clear all headers
    And I send a "GET" request to "${CTX:apiContext}/v1.0/l25/probe" until the JSON field "path" is "/second/l25/probe"
    Then the response should be served by the "echo" testbench service
    When I send 10 "GET" requests to "${CTX:apiContext}/v1.0/l25/probe"
    Then the JSON response field "path" should be "/second/l25/probe"
    And the response body should not contain "/first"
