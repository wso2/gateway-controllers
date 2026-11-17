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
Feature: Dynamic endpoint configuration validation and unknown upstream names
  As an API developer
  I want a wrong targetUpstream to fail visibly
  So that a typo never sends traffic to a backend nobody chose

  # The main upstream of most scenarios is the capture service. It records the last request it
  # received for each path and answers 204 for a path it never received, so "the main upstream
  # never saw the request" is something a scenario can check.
  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"
    And I resolve the "capture" service URL at "" and store it as "captureUpstream"

  Scenario: A targetUpstream that names no upstream definition does not fall back to the main upstream
    Given I generate a unique value from "dynamic-unknown" and store it as "apiName"
    And I generate a unique API context from "/dynamic-unknown" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion               | ${CTX:gatewaySpecVersion}          |
      | name                     | ${CTX:apiName}                     |
      | spec.displayName         | Dynamic-Endpoint-Unknown-API       |
      | spec.version             | v1.0                               |
      | spec.context             | ${CTX:apiContext}/$version         |
      | spec.upstream.main.url   | ${CTX:captureUpstream}             |
      | spec.upstreamDefinitions | [{"name":"alt-upstream","basePath":"/alternate","upstreams":[{"url":"http://testbench:3000"}]}] |
      | spec.operations          | [{"method":"GET","path":"/unknown/probe","policies":[{"name":"dynamic-endpoint","version":"v1","params":{"targetUpstream":"missing-upstream"}}]}] |
    Then the response should be successful

    When I clear all headers
    And I send a "GET" request to "${CTX:apiContext}/v1.0/unknown/probe" until status 503
    Then the response body should not contain "/unknown/probe"
    When I send a "GET" request to the "capture" service at "/test/captured?path=/unknown/probe" until status 204

  Scenario: The upstream definition name must match exactly, including its case
    Given I generate a unique value from "dynamic-case" and store it as "apiName"
    And I generate a unique API context from "/dynamic-case" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion               | ${CTX:gatewaySpecVersion}          |
      | name                     | ${CTX:apiName}                     |
      | spec.displayName         | Dynamic-Endpoint-Case-API          |
      | spec.version             | v1.0                               |
      | spec.context             | ${CTX:apiContext}/$version         |
      | spec.upstream.main.url   | ${CTX:captureUpstream}             |
      | spec.upstreamDefinitions | [{"name":"Alt-Upstream","basePath":"/alternate","upstreams":[{"url":"http://testbench:3000"}]}] |
      | spec.operations          | [{"method":"GET","path":"/case/exact","policies":[{"name":"dynamic-endpoint","version":"v1","params":{"targetUpstream":"Alt-Upstream"}}]},{"method":"GET","path":"/case/wrong","policies":[{"name":"dynamic-endpoint","version":"v1","params":{"targetUpstream":"alt-upstream"}}]}] |
    Then the response should be successful

    When I clear all headers
    And I send a "GET" request to "${CTX:apiContext}/v1.0/case/exact" until status 200
    Then the JSON response field "path" should be "/alternate/case/exact"

    When I send a "GET" request to "${CTX:apiContext}/v1.0/case/wrong" until status 503
    Then the response body should not contain "/case/wrong"
    When I send a "GET" request to the "capture" service at "/test/captured?path=/case/wrong" until status 204

  Scenario: An empty targetUpstream leaves the routing unchanged
    Given I generate a unique value from "dynamic-empty" and store it as "apiName"
    And I generate a unique API context from "/dynamic-empty" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion               | ${CTX:gatewaySpecVersion}          |
      | name                     | ${CTX:apiName}                     |
      | spec.displayName         | Dynamic-Endpoint-Empty-API         |
      | spec.version             | v1.0                               |
      | spec.context             | ${CTX:apiContext}/$version         |
      | spec.upstream.main.url   | http://testbench:3000              |
      | spec.upstreamDefinitions | [{"name":"alt-upstream","basePath":"/alternate","upstreams":[{"url":"http://testbench:3000"}]}] |
      | spec.operations          | [{"method":"GET","path":"/empty/probe","policies":[{"name":"dynamic-endpoint","version":"v1","params":{"targetUpstream":""}}]}] |
    Then the response should be successful

    When I clear all headers
    And I send a "GET" request to "${CTX:apiContext}/v1.0/empty/probe" until status 200
    Then the JSON response field "path" should be "/empty/probe"

  Scenario Outline: Deploy is rejected when the policy parameters are invalid (<case>)
    Given I generate a unique value from "dynamic-bad-params" and store it as "apiName"
    And I generate a unique API context from "/dynamic-bad-params" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion               | ${CTX:gatewaySpecVersion}          |
      | name                     | ${CTX:apiName}                     |
      | spec.displayName         | Dynamic-Endpoint-Bad-Params-API    |
      | spec.version             | v1.0                               |
      | spec.context             | ${CTX:apiContext}/$version         |
      | spec.upstream.main.url   | http://testbench:3000              |
      | spec.upstreamDefinitions | [{"name":"alt-upstream","basePath":"/alternate","upstreams":[{"url":"http://testbench:3000"}]}] |
      | spec.operations          | [{"method":"GET","path":"/whoami","policies":[{"name":"dynamic-endpoint","version":"v1","params":<params>}]}] |
    Then the response should be a client error
    And the response should be valid JSON
    And the JSON response field "status" should be "error"

    Examples:
      | case              | params                                                        |
      | number            | {"targetUpstream":123}                                        |
      | array             | {"targetUpstream":["alt-upstream"]}                           |
      | object            | {"targetUpstream":{"name":"alt-upstream"}}                    |
      | unknown parameter | {"targetUpstream":"alt-upstream","fallback":"main"}           |

  Scenario: Deploy is rejected for a policy version that does not exist
    Given I generate a unique value from "dynamic-bad-version" and store it as "apiName"
    And I generate a unique API context from "/dynamic-bad-version" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion               | ${CTX:gatewaySpecVersion}          |
      | name                     | ${CTX:apiName}                     |
      | spec.displayName         | Dynamic-Endpoint-Bad-Version-API   |
      | spec.version             | v1.0                               |
      | spec.context             | ${CTX:apiContext}/$version         |
      | spec.upstream.main.url   | http://testbench:3000              |
      | spec.upstreamDefinitions | [{"name":"alt-upstream","basePath":"/alternate","upstreams":[{"url":"http://testbench:3000"}]}] |
      | spec.operations          | [{"method":"GET","path":"/whoami","policies":[{"name":"dynamic-endpoint","version":"v99","params":{"targetUpstream":"alt-upstream"}}]}] |
    Then the response should be a client error
    And the response should be valid JSON
    And the JSON response field "status" should be "error"

  Scenario: Renaming the upstream definition a policy refers to makes the route fail instead of reaching another backend
    Given I generate a unique value from "dynamic-rename" and store it as "apiName"
    And I generate a unique API context from "/dynamic-rename" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion               | ${CTX:gatewaySpecVersion}          |
      | name                     | ${CTX:apiName}                     |
      | spec.displayName         | Dynamic-Endpoint-Rename-API        |
      | spec.version             | v1.0                               |
      | spec.context             | ${CTX:apiContext}/$version         |
      | spec.upstream.main.url   | ${CTX:captureUpstream}             |
      | spec.upstreamDefinitions | [{"name":"up-a","basePath":"/aaa","upstreams":[{"url":"http://testbench:3000"}]},{"name":"up-other","basePath":"/other","upstreams":[{"url":"http://testbench:3000"}]}] |
      | spec.operations          | [{"method":"GET","path":"/renamed/probe","policies":[{"name":"dynamic-endpoint","version":"v1","params":{"targetUpstream":"up-a"}}]}] |
    Then the response should be successful
    When I clear all headers
    And I send a "GET" request to "${CTX:apiContext}/v1.0/renamed/probe" until status 200
    Then the JSON response field "path" should be "/aaa/renamed/probe"

    # The policy still names up-a, which no longer exists. up-other stays, so the route is
    # still bound to named upstreams and cannot quietly use the main upstream.
    When I authenticate using basic auth as "admin"
    And I update API "${CTX:apiName}" from "resources/templates/rest-api.yaml" with values:
      | apiVersion               | ${CTX:gatewaySpecVersion}          |
      | name                     | ${CTX:apiName}                     |
      | spec.displayName         | Dynamic-Endpoint-Rename-API        |
      | spec.version             | v1.0                               |
      | spec.context             | ${CTX:apiContext}/$version         |
      | spec.upstream.main.url   | ${CTX:captureUpstream}             |
      | spec.upstreamDefinitions | [{"name":"up-renamed","basePath":"/aaa","upstreams":[{"url":"http://testbench:3000"}]},{"name":"up-other","basePath":"/other","upstreams":[{"url":"http://testbench:3000"}]}] |
      | spec.operations          | [{"method":"GET","path":"/renamed/probe","policies":[{"name":"dynamic-endpoint","version":"v1","params":{"targetUpstream":"up-a"}}]}] |
    Then the API update response should indicate successful deployment

    When I clear all headers
    And I send a "GET" request to "${CTX:apiContext}/v1.0/renamed/probe" until status 503
    Then the response body should not contain "/renamed/probe"
    When I send a "GET" request to the "capture" service at "/test/captured?path=/renamed/probe" until status 204

  Scenario Outline: A malformed upstream name never falls back to the main upstream (<case>)
    Given I generate a unique value from "dynamic-malformed" and store it as "apiName"
    And I generate a unique API context from "/dynamic-malformed" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion               | ${CTX:gatewaySpecVersion}          |
      | name                     | ${CTX:apiName}                     |
      | spec.displayName         | Dynamic-Endpoint-Malformed-API     |
      | spec.version             | v1.0                               |
      | spec.context             | ${CTX:apiContext}/$version         |
      | spec.upstream.main.url   | ${CTX:captureUpstream}             |
      | spec.upstreamDefinitions | [{"name":"alt-upstream","basePath":"/alternate","upstreams":[{"url":"http://testbench:3000"}]}] |
      | spec.operations          | [{"method":"GET","path":"/<probe>/probe","policies":[{"name":"dynamic-endpoint","version":"v1","params":{"targetUpstream":"<name>"}}]}] |
    Then the response should be successful

    When I clear all headers
    And I send a "GET" request to "${CTX:apiContext}/v1.0/<probe>/probe" until status 503 or 500
    Then the response body should not contain "/<probe>/probe"
    When I send a "GET" request to the "capture" service at "/test/captured?path=/<probe>/probe" until status 204

    Examples:
      | case               | name              | probe               |
      | contains a space   | bad name          | malformed-space     |
      | path traversal     | ../alt-upstream   | malformed-traversal |
      | trailing character | alt-upstream;     | malformed-trailing  |

  # Known failure on gateway 1.2.0: without an upstream definition the route is bound to the main
  # cluster, the policy's selection is ignored, and the request is answered by the main upstream.
  Scenario: A targetUpstream without any upstream definition does not fall back to the main upstream
    Given I generate a unique value from "dynamic-no-definitions" and store it as "apiName"
    And I generate a unique API context from "/dynamic-no-definitions" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion               | ${CTX:gatewaySpecVersion}          |
      | name                     | ${CTX:apiName}                     |
      | spec.displayName         | Dynamic-Endpoint-No-Definitions-API |
      | spec.version             | v1.0                               |
      | spec.context             | ${CTX:apiContext}/$version         |
      | spec.upstream.main.url   | ${CTX:captureUpstream}             |
      | spec.operations          | [{"method":"GET","path":"/nodefs/probe","policies":[{"name":"dynamic-endpoint","version":"v1","params":{"targetUpstream":"alt-upstream"}}]}] |
    Then the response should be successful

    When I clear all headers
    And I send a "GET" request to "${CTX:apiContext}/v1.0/nodefs/probe" until status 503
    Then the response body should not contain "/nodefs/probe"
    When I send a "GET" request to the "capture" service at "/test/captured?path=/nodefs/probe" until status 204
