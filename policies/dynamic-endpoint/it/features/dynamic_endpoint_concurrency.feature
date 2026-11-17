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
Feature: Dynamic endpoint under concurrent and sustained traffic
  As an API owner
  I want every request routed by its own operation's configuration
  So that load never sends a request to another operation's upstream

  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"
    And I resolve the "capture" service URL at "" and store it as "captureUpstream"

  @de-22
  Scenario: Concurrent requests to operations with different upstreams are never mixed up
    Given I generate a unique value from "dynamic-concurrent" and store it as "apiName"
    And I generate a unique API context from "/dynamic-concurrent" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion               | ${CTX:gatewaySpecVersion}          |
      | name                     | ${CTX:apiName}                     |
      | spec.displayName         | Dynamic-Endpoint-Concurrent-API    |
      | spec.version             | v1.0                               |
      | spec.context             | ${CTX:apiContext}/$version         |
      | spec.upstream.main.url   | http://testbench:3000              |
      | spec.upstreamDefinitions | [{"name":"up-a","basePath":"/aaa","upstreams":[{"url":"http://testbench:3000"}]},{"name":"up-b","basePath":"/bbb","upstreams":[{"url":"http://testbench:3000"}]},{"name":"up-e","basePath":"/eee","upstreams":[{"url":"http://testbench:3002"}]}] |
      | spec.operations          | [{"method":"GET","path":"/k22/one","policies":[{"name":"dynamic-endpoint","version":"v1","params":{"targetUpstream":"up-a"}}]},{"method":"GET","path":"/k22/two","policies":[{"name":"dynamic-endpoint","version":"v1","params":{"targetUpstream":"up-b"}}]},{"method":"GET","path":"/k22/three","policies":[{"name":"dynamic-endpoint","version":"v1","params":{"targetUpstream":"up-e"}}]},{"method":"GET","path":"/k22/plain"}] |
    Then the response should be successful

    When I clear all headers
    And I send a "GET" request to "${CTX:apiContext}/v1.0/k22/one" until status 200
    And I send a "GET" request to "${CTX:apiContext}/v1.0/k22/two" until status 200
    And I send a "GET" request to "${CTX:apiContext}/v1.0/k22/three" until status 200
    And I send a "GET" request to "${CTX:apiContext}/v1.0/k22/plain" until status 200

    When I send 400 concurrent requests cycling through:
      | GET | ${CTX:apiContext}/v1.0/k22/one   | path | /aaa/k22/one   |
      | GET | ${CTX:apiContext}/v1.0/k22/two   | path | /bbb/k22/two   |
      | GET | ${CTX:apiContext}/v1.0/k22/three | path | /eee/k22/three |
      | GET | ${CTX:apiContext}/v1.0/k22/plain | path | /k22/plain     |
    Then every concurrent response should have matched its expectation

  @de-23
  Scenario: High-volume traffic to a selected upstream keeps routing to it
    Given I generate a unique value from "dynamic-volume" and store it as "apiName"
    And I generate a unique API context from "/dynamic-volume" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion               | ${CTX:gatewaySpecVersion}          |
      | name                     | ${CTX:apiName}                     |
      | spec.displayName         | Dynamic-Endpoint-Volume-API        |
      | spec.version             | v1.0                               |
      | spec.context             | ${CTX:apiContext}/$version         |
      | spec.upstream.main.url   | ${CTX:captureUpstream}             |
      | spec.upstreamDefinitions | [{"name":"up-a","basePath":"/aaa","upstreams":[{"url":"http://testbench:3000"}]}] |
      | spec.operations          | [{"method":"GET","path":"/k23/probe","policies":[{"name":"dynamic-endpoint","version":"v1","params":{"targetUpstream":"up-a"}}]}] |
    Then the response should be successful

    When I clear all headers
    And I send a "GET" request to "${CTX:apiContext}/v1.0/k23/probe" until status 200
    And I send 800 concurrent requests cycling through:
      | GET | ${CTX:apiContext}/v1.0/k23/probe | path | /aaa/k23/probe |
    Then every concurrent response should have matched its expectation
    When I send a "GET" request to the "capture" service at "/test/captured?path=/k23/probe" until status 204

  @de-38
  Scenario: Rapid changes of targetUpstream under traffic only ever reach upstreams of a valid configuration
    Given I generate a unique value from "dynamic-rapid" and store it as "apiName"
    And I generate a unique API context from "/dynamic-rapid" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion               | ${CTX:gatewaySpecVersion}          |
      | name                     | ${CTX:apiName}                     |
      | spec.displayName         | Dynamic-Endpoint-Rapid-API         |
      | spec.version             | v1.0                               |
      | spec.context             | ${CTX:apiContext}/$version         |
      | spec.upstream.main.url   | http://testbench:3000              |
      | spec.upstreamDefinitions | [{"name":"up-a","basePath":"/aaa","upstreams":[{"url":"http://testbench:3000"}]},{"name":"up-b","basePath":"/bbb","upstreams":[{"url":"http://testbench:3000"}]},{"name":"up-never","basePath":"/never","upstreams":[{"url":"http://testbench:3002"}]}] |
      | spec.operations          | [{"method":"GET","path":"/r38/probe","policies":[{"name":"dynamic-endpoint","version":"v1","params":{"targetUpstream":"up-a"}}]}] |
    Then the response should be successful
    When I clear all headers
    And I send a "GET" request to "${CTX:apiContext}/v1.0/r38/probe" until the JSON field "path" is "/aaa/r38/probe"
    And I start background "GET" traffic to "${CTX:apiContext}/v1.0/r38/probe" as "rapid"

    When I authenticate using basic auth as "admin"
    And I update API "${CTX:apiName}" from "resources/templates/rest-api.yaml" with values:
      | apiVersion               | ${CTX:gatewaySpecVersion}          |
      | name                     | ${CTX:apiName}                     |
      | spec.displayName         | Dynamic-Endpoint-Rapid-API         |
      | spec.version             | v1.0                               |
      | spec.context             | ${CTX:apiContext}/$version         |
      | spec.upstream.main.url   | http://testbench:3000              |
      | spec.upstreamDefinitions | [{"name":"up-a","basePath":"/aaa","upstreams":[{"url":"http://testbench:3000"}]},{"name":"up-b","basePath":"/bbb","upstreams":[{"url":"http://testbench:3000"}]},{"name":"up-never","basePath":"/never","upstreams":[{"url":"http://testbench:3002"}]}] |
      | spec.operations          | [{"method":"GET","path":"/r38/probe","policies":[{"name":"dynamic-endpoint","version":"v1","params":{"targetUpstream":"up-b"}}]}] |
    Then the API update response should indicate successful deployment
    When I update API "${CTX:apiName}" from "resources/templates/rest-api.yaml" with values:
      | apiVersion               | ${CTX:gatewaySpecVersion}          |
      | name                     | ${CTX:apiName}                     |
      | spec.displayName         | Dynamic-Endpoint-Rapid-API         |
      | spec.version             | v1.0                               |
      | spec.context             | ${CTX:apiContext}/$version         |
      | spec.upstream.main.url   | http://testbench:3000              |
      | spec.upstreamDefinitions | [{"name":"up-a","basePath":"/aaa","upstreams":[{"url":"http://testbench:3000"}]},{"name":"up-b","basePath":"/bbb","upstreams":[{"url":"http://testbench:3000"}]},{"name":"up-never","basePath":"/never","upstreams":[{"url":"http://testbench:3002"}]}] |
      | spec.operations          | [{"method":"GET","path":"/r38/probe","policies":[{"name":"dynamic-endpoint","version":"v1","params":{"targetUpstream":"up-a"}}]}] |
    Then the API update response should indicate successful deployment
    When I update API "${CTX:apiName}" from "resources/templates/rest-api.yaml" with values:
      | apiVersion               | ${CTX:gatewaySpecVersion}          |
      | name                     | ${CTX:apiName}                     |
      | spec.displayName         | Dynamic-Endpoint-Rapid-API         |
      | spec.version             | v1.0                               |
      | spec.context             | ${CTX:apiContext}/$version         |
      | spec.upstream.main.url   | http://testbench:3000              |
      | spec.upstreamDefinitions | [{"name":"up-a","basePath":"/aaa","upstreams":[{"url":"http://testbench:3000"}]},{"name":"up-b","basePath":"/bbb","upstreams":[{"url":"http://testbench:3000"}]},{"name":"up-never","basePath":"/never","upstreams":[{"url":"http://testbench:3002"}]}] |
      | spec.operations          | [{"method":"GET","path":"/r38/probe","policies":[{"name":"dynamic-endpoint","version":"v1","params":{"targetUpstream":"up-b"}}]}] |
    Then the API update response should indicate successful deployment
    When I update API "${CTX:apiName}" from "resources/templates/rest-api.yaml" with values:
      | apiVersion               | ${CTX:gatewaySpecVersion}          |
      | name                     | ${CTX:apiName}                     |
      | spec.displayName         | Dynamic-Endpoint-Rapid-API         |
      | spec.version             | v1.0                               |
      | spec.context             | ${CTX:apiContext}/$version         |
      | spec.upstream.main.url   | http://testbench:3000              |
      | spec.upstreamDefinitions | [{"name":"up-a","basePath":"/aaa","upstreams":[{"url":"http://testbench:3000"}]},{"name":"up-b","basePath":"/bbb","upstreams":[{"url":"http://testbench:3000"}]},{"name":"up-never","basePath":"/never","upstreams":[{"url":"http://testbench:3002"}]}] |
      | spec.operations          | [{"method":"GET","path":"/r38/probe","policies":[{"name":"dynamic-endpoint","version":"v1","params":{"targetUpstream":"up-a"}}]}] |
    Then the API update response should indicate successful deployment
    When I update API "${CTX:apiName}" from "resources/templates/rest-api.yaml" with values:
      | apiVersion               | ${CTX:gatewaySpecVersion}          |
      | name                     | ${CTX:apiName}                     |
      | spec.displayName         | Dynamic-Endpoint-Rapid-API         |
      | spec.version             | v1.0                               |
      | spec.context             | ${CTX:apiContext}/$version         |
      | spec.upstream.main.url   | http://testbench:3000              |
      | spec.upstreamDefinitions | [{"name":"up-a","basePath":"/aaa","upstreams":[{"url":"http://testbench:3000"}]},{"name":"up-b","basePath":"/bbb","upstreams":[{"url":"http://testbench:3000"}]},{"name":"up-never","basePath":"/never","upstreams":[{"url":"http://testbench:3002"}]}] |
      | spec.operations          | [{"method":"GET","path":"/r38/probe","policies":[{"name":"dynamic-endpoint","version":"v1","params":{"targetUpstream":"up-b"}}]}] |
    Then the API update response should indicate successful deployment

    When I clear all headers
    And I send a "GET" request to "${CTX:apiContext}/v1.0/r38/probe" until the JSON field "path" is "/bbb/r38/probe"
    And I stop background traffic "rapid"
    Then background traffic "rapid" should have recorded at least 20 attempts
    And background traffic "rapid" should have received at least 10 successful responses
    And background traffic "rapid" should only have received successful responses whose JSON field "path" starts with one of "/aaa/,/bbb/"
