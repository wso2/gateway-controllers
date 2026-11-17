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

@dynamic-endpoint
Feature: Dynamic endpoint routing
  As an API developer
  I want operations to select configured upstreams
  So that routing policies direct requests to the intended backend

  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"

  @de-1 @de-3
  Scenario: Operation routed to a named upstream definition while others use the default upstream
    Given I generate a unique value from "dynamic-operation" and store it as "apiName1"
    And I generate a unique API context from "/dynamic-operation" and store it as "apiContext1"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion                    | ${CTX:gatewaySpecVersion}         |
      | name                          | ${CTX:apiName1}                    |
      | spec.displayName              | Dynamic-Endpoint-API               |
      | spec.version                  | v1.0                               |
      | spec.context                  | ${CTX:apiContext1}/$version        |
      | spec.upstream.main.url        | http://testbench:3000              |
      | spec.upstreamDefinitions      | [{"name":"alt-upstream","basePath":"/alternate","upstreams":[{"url":"http://testbench:3000"}]}] |
      | spec.operations               | [{"method":"GET","path":"/whoami","policies":[{"name":"dynamic-endpoint","version":"v1","params":{"targetUpstream":"alt-upstream"}}]},{"method":"GET","path":"/ping"}] |
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext1}/v1.0/ping" until status 200

    When I clear all headers
    And I send a "GET" request to "${CTX:apiContext1}/v1.0/whoami"
    Then the response should be successful
    And the response should be valid JSON
    And the JSON response field "path" should be "/alternate/whoami"

    When I clear all headers
    And I send a "GET" request to "${CTX:apiContext1}/v1.0/ping"
    Then the response should be successful
    And the response should be valid JSON
    And the JSON response field "path" should be "/ping"

  @de-2 @de-5
  Scenario: Different operations route to upstreams with different base paths
    Given I generate a unique value from "dynamic-base-paths" and store it as "apiName2"
    And I generate a unique API context from "/dynamic-base-paths" and store it as "apiContext2"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion                    | ${CTX:gatewaySpecVersion}         |
      | name                          | ${CTX:apiName2}                    |
      | spec.displayName              | Dynamic-Endpoint-Routes-API       |
      | spec.version                  | v1.0                               |
      | spec.context                  | ${CTX:apiContext2}/$version        |
      | spec.upstream.main.url        | http://testbench:3000              |
      | spec.upstreamDefinitions      | [{"name":"foo-upstream","basePath":"/foo","upstreams":[{"url":"http://testbench:3000"}]},{"name":"bar-upstream","basePath":"/bar","upstreams":[{"url":"http://testbench:3000"}]},{"name":"root-upstream","upstreams":[{"url":"http://testbench:3000"}]}] |
      | spec.operations               | [{"method":"GET","path":"/items","policies":[{"name":"dynamic-endpoint","version":"v1","params":{"targetUpstream":"foo-upstream"}}]},{"method":"GET","path":"/records","policies":[{"name":"dynamic-endpoint","version":"v1","params":{"targetUpstream":"bar-upstream"}}]},{"method":"GET","path":"/extras","policies":[{"name":"dynamic-endpoint","version":"v1","params":{"targetUpstream":"root-upstream"}}]}] |
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext2}/v1.0/items" until status 200

    When I clear all headers
    And I send a "GET" request to "${CTX:apiContext2}/v1.0/items"
    Then the response should be successful
    And the response should be valid JSON
    And the JSON response field "path" should be "/foo/items"

    When I clear all headers
    And I send a "GET" request to "${CTX:apiContext2}/v1.0/records"
    Then the response should be successful
    And the response should be valid JSON
    And the JSON response field "path" should be "/bar/records"

    When I clear all headers
    And I send a "GET" request to "${CTX:apiContext2}/v1.0/extras"
    Then the response should be successful
    And the response should be valid JSON
    And the JSON response field "path" should be "/extras"

  @de-9
  Scenario: Deploy fails when no target is set
    Given I generate a unique value from "dynamic-missing-target" and store it as "apiName3"
    And I generate a unique API context from "/dynamic-missing-target" and store it as "apiContext3"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}         |
      | name                   | ${CTX:apiName3}                    |
      | spec.displayName       | Dynamic-Endpoint-Missing-Param-API |
      | spec.version           | v1.0                               |
      | spec.context           | ${CTX:apiContext3}/$version        |
      | spec.upstream.main.url | http://testbench:3000              |
      | spec.operations        | [{"method":"GET","path":"/whoami","policies":[{"name":"dynamic-endpoint","version":"v1","params":{}}]}] |
    Then the response should be a client error
    And the response should be valid JSON
    And the JSON response field "status" should be "error"
    And the response body should contain "targetUpstream"

  @de-1
  Scenario: Dynamic-endpoint policy applies on the sandbox vhost
    Given I generate a unique value from "dynamic-sandbox-operation" and store it as "apiName4"
    And I generate a unique API context from "/dynamic-sandbox-operation" and store it as "apiContext4"
    And I generate a unique resource name from "dynamic-main" and store it as "mainHost4"
    And I generate a unique resource name from "dynamic-sandbox" and store it as "sandboxHost4"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion                    | ${CTX:gatewaySpecVersion}         |
      | name                          | ${CTX:apiName4}                    |
      | spec.displayName              | Dynamic-Endpoint-Sandbox-API      |
      | spec.version                  | v1.0                               |
      | spec.context                  | ${CTX:apiContext4}/$version        |
      | spec.vhosts                   | {"main":"${CTX:mainHost4}","sandbox":"${CTX:sandboxHost4}"} |
      | spec.upstreamDefinitions      | [{"name":"alt-upstream","basePath":"/alternate","upstreams":[{"url":"http://testbench:3000"}]}] |
      | spec.upstream.main.url        | http://testbench:3000              |
      | spec.upstream.sandbox.url     | http://testbench:3000/sandbox      |
      | spec.operations               | [{"method":"GET","path":"/whoami","policies":[{"name":"dynamic-endpoint","version":"v1","params":{"targetUpstream":"alt-upstream"}}]}] |
    Then the response should be successful
    And I set request host to "${CTX:mainHost4}"
    And I send a "GET" request to "${CTX:apiContext4}/v1.0/whoami" until status 200

    When I clear all headers
    And I set request host to "${CTX:mainHost4}"
    And I send a "GET" request to "${CTX:apiContext4}/v1.0/whoami"
    Then the response should be successful
    And the response should be valid JSON
    And the JSON response field "path" should be "/alternate/whoami"

    When I clear all headers
    And I set request host to "${CTX:sandboxHost4}"
    And I send a "GET" request to "${CTX:apiContext4}/v1.0/whoami"
    Then the response should be successful
    And the response should be valid JSON
    And the JSON response field "path" should be "/alternate/whoami"

  @de-4
  Scenario: API-level dynamic-endpoint policy applies on the sandbox vhost
    Given I generate a unique value from "dynamic-sandbox-api-policy" and store it as "apiName5"
    And I generate a unique API context from "/dynamic-sandbox-api-policy" and store it as "apiContext5"
    And I generate a unique resource name from "dynamic-api-main" and store it as "mainHost5"
    And I generate a unique resource name from "dynamic-api-sandbox" and store it as "sandboxHost5"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion                    | ${CTX:gatewaySpecVersion}         |
      | name                          | ${CTX:apiName5}                    |
      | spec.displayName              | Dynamic-Endpoint-API-Sandbox-API |
      | spec.version                  | v1.0                               |
      | spec.context                  | ${CTX:apiContext5}/$version        |
      | spec.vhosts                   | {"main":"${CTX:mainHost5}","sandbox":"${CTX:sandboxHost5}"} |
      | spec.upstreamDefinitions      | [{"name":"alt-upstream","basePath":"/alternate","upstreams":[{"url":"http://testbench:3000"}]}] |
      | spec.upstream.main.url        | http://testbench:3000              |
      | spec.upstream.sandbox.url     | http://testbench:3000/sandbox      |
      | spec.policies                 | [{"name":"dynamic-endpoint","version":"v1","params":{"targetUpstream":"alt-upstream"}}] |
      | spec.operations               | [{"method":"GET","path":"/whoami"},{"method":"GET","path":"/ping"}] |
    Then the response should be successful
    And I set request host to "${CTX:mainHost5}"
    And I send a "GET" request to "${CTX:apiContext5}/v1.0/whoami" until status 200

    When I clear all headers
    And I set request host to "${CTX:mainHost5}"
    And I send a "GET" request to "${CTX:apiContext5}/v1.0/whoami"
    Then the response should be successful
    And the response should be valid JSON
    And the JSON response field "path" should be "/alternate/whoami"

    When I clear all headers
    And I set request host to "${CTX:sandboxHost5}"
    And I send a "GET" request to "${CTX:apiContext5}/v1.0/ping"
    Then the response should be successful
    And the response should be valid JSON
    And the JSON response field "path" should be "/alternate/ping"

  @de-3
  Scenario: Sandbox operation without the policy falls back to the sandbox upstream
    Given I generate a unique value from "dynamic-sandbox-fallback" and store it as "apiName6"
    And I generate a unique API context from "/dynamic-sandbox-fallback" and store it as "apiContext6"
    And I generate a unique resource name from "dynamic-fallback-main" and store it as "mainHost6"
    And I generate a unique resource name from "dynamic-fallback-sandbox" and store it as "sandboxHost6"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion                    | ${CTX:gatewaySpecVersion}         |
      | name                          | ${CTX:apiName6}                    |
      | spec.displayName              | Dynamic-Endpoint-Sandbox-Mixed-API |
      | spec.version                  | v1.0                               |
      | spec.context                  | ${CTX:apiContext6}/$version        |
      | spec.vhosts                   | {"main":"${CTX:mainHost6}","sandbox":"${CTX:sandboxHost6}"} |
      | spec.upstreamDefinitions      | [{"name":"alt-upstream","basePath":"/alternate","upstreams":[{"url":"http://testbench:3000"}]}] |
      | spec.upstream.main.url        | http://testbench:3000              |
      | spec.upstream.sandbox.url     | http://testbench:3000/sandbox      |
      | spec.operations               | [{"method":"GET","path":"/whoami","policies":[{"name":"dynamic-endpoint","version":"v1","params":{"targetUpstream":"alt-upstream"}}]},{"method":"GET","path":"/ping"}] |
    Then the response should be successful
    And I set request host to "${CTX:sandboxHost6}"
    And I send a "GET" request to "${CTX:apiContext6}/v1.0/ping" until status 200

    When I clear all headers
    And I set request host to "${CTX:sandboxHost6}"
    And I send a "GET" request to "${CTX:apiContext6}/v1.0/whoami"
    Then the response should be successful
    And the response should be valid JSON
    And the JSON response field "path" should be "/alternate/whoami"

    When I clear all headers
    And I set request host to "${CTX:sandboxHost6}"
    And I send a "GET" request to "${CTX:apiContext6}/v1.0/ping"
    Then the response should be successful
    And the response should be valid JSON
    And the JSON response field "path" should be "/sandbox/ping"

  @de-17
  Scenario: Dynamic-endpoint combined with a path-rewrite policy on the same operation
    Given I generate a unique value from "dynamic-rewrite" and store it as "apiName7"
    And I generate a unique API context from "/dynamic-rewrite" and store it as "apiContext7"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion                    | ${CTX:gatewaySpecVersion}         |
      | name                          | ${CTX:apiName7}                    |
      | spec.displayName              | Dynamic-Endpoint-Rewrite-API      |
      | spec.version                  | v1.0                               |
      | spec.context                  | ${CTX:apiContext7}/$version        |
      | spec.upstreamDefinitions      | [{"name":"alt-upstream","basePath":"/alternate","upstreams":[{"url":"http://testbench:3000"}]}] |
      | spec.upstream.main.url        | http://testbench:3000              |
      | spec.operations               | [{"method":"GET","path":"/whoami","policies":[{"name":"request-rewrite","version":"v1","params":{"pathRewrite":{"type":"ReplaceFullPath","replaceFullPath":"/rewritten"}}},{"name":"dynamic-endpoint","version":"v1","params":{"targetUpstream":"alt-upstream"}}]}] |
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext7}/v1.0/whoami" until status 200

    When I clear all headers
    And I send a "GET" request to "${CTX:apiContext7}/v1.0/whoami"
    Then the response should be successful
    And the response should be valid JSON
    And the JSON response field "path" should be "/alternate/rewritten"

  @de-17
  Scenario: Dynamic-endpoint and a path-rewrite policy combined on the sandbox vhost
    Given I generate a unique value from "dynamic-sandbox-rewrite" and store it as "apiName8"
    And I generate a unique API context from "/dynamic-sandbox-rewrite" and store it as "apiContext8"
    And I generate a unique resource name from "dynamic-rewrite-main" and store it as "mainHost8"
    And I generate a unique resource name from "dynamic-rewrite-sandbox" and store it as "sandboxHost8"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion                    | ${CTX:gatewaySpecVersion}         |
      | name                          | ${CTX:apiName8}                    |
      | spec.displayName              | Dynamic-Endpoint-Rewrite-Sandbox-API |
      | spec.version                  | v1.0                               |
      | spec.context                  | ${CTX:apiContext8}/$version        |
      | spec.vhosts                   | {"main":"${CTX:mainHost8}","sandbox":"${CTX:sandboxHost8}"} |
      | spec.upstreamDefinitions      | [{"name":"alt-upstream","basePath":"/alternate","upstreams":[{"url":"http://testbench:3000"}]}] |
      | spec.upstream.main.url        | http://testbench:3000              |
      | spec.upstream.sandbox.url     | http://testbench:3000/sandbox      |
      | spec.operations               | [{"method":"GET","path":"/whoami","policies":[{"name":"request-rewrite","version":"v1","params":{"pathRewrite":{"type":"ReplaceFullPath","replaceFullPath":"/rewritten"}}},{"name":"dynamic-endpoint","version":"v1","params":{"targetUpstream":"alt-upstream"}}]}] |
    Then the response should be successful
    And I set request host to "${CTX:sandboxHost8}"
    And I send a "GET" request to "${CTX:apiContext8}/v1.0/whoami" until status 200

    When I clear all headers
    And I set request host to "${CTX:sandboxHost8}"
    And I send a "GET" request to "${CTX:apiContext8}/v1.0/whoami"
    Then the response should be successful
    And the response should be valid JSON
    And the JSON response field "path" should be "/alternate/rewritten"

  @de-6
  Scenario: Operation routed to an upstream definition with several weighted upstreams
    Given I generate a unique value from "dynamic-weighted" and store it as "apiName9"
    And I generate a unique API context from "/dynamic-weighted" and store it as "apiContext9"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion                    | ${CTX:gatewaySpecVersion}         |
      | name                          | ${CTX:apiName9}                    |
      | spec.displayName              | Dynamic-Endpoint-Weighted-API     |
      | spec.version                  | v1.0                               |
      | spec.context                  | ${CTX:apiContext9}/$version        |
      | spec.upstream.main.url        | http://testbench:3000              |
      | spec.upstreamDefinitions      | [{"name":"weighted-upstream","basePath":"/weighted","upstreams":[{"url":"http://testbench:3000","weight":80},{"url":"http://testbench:3000","weight":20}]}] |
      | spec.operations               | [{"method":"GET","path":"/whoami","policies":[{"name":"dynamic-endpoint","version":"v1","params":{"targetUpstream":"weighted-upstream"}}]},{"method":"GET","path":"/ping"}] |
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext9}/v1.0/ping" until status 200

    When I clear all headers
    And I send a "GET" request to "${CTX:apiContext9}/v1.0/whoami" until status 200
    Then the response should be valid JSON
    And the JSON response field "path" should be "/weighted/whoami"

    # Every request goes through the selected definition, whichever of its upstreams answers.
    When I send 50 concurrent requests cycling through:
      | GET | ${CTX:apiContext9}/v1.0/whoami | path | /weighted/whoami |
    Then every concurrent response should have matched its expectation

    When I send a "GET" request to "${CTX:apiContext9}/v1.0/ping"
    Then the response should be successful
    And the JSON response field "path" should be "/ping"

  @de-18
  Scenario: The request reaches the selected upstream with its method, headers and body unchanged
    Given I generate a unique value from "dynamic-passthrough-request" and store it as "apiName10"
    And I generate a unique API context from "/dynamic-passthrough-request" and store it as "apiContext10"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion                    | ${CTX:gatewaySpecVersion}         |
      | name                          | ${CTX:apiName10}                   |
      | spec.displayName              | Dynamic-Endpoint-Request-API      |
      | spec.version                  | v1.0                               |
      | spec.context                  | ${CTX:apiContext10}/$version       |
      | spec.upstream.main.url        | http://testbench:3000              |
      | spec.upstreamDefinitions      | [{"name":"alt-upstream","basePath":"/alternate","upstreams":[{"url":"http://testbench:3000"}]}] |
      | spec.operations               | [{"method":"POST","path":"/orders","policies":[{"name":"dynamic-endpoint","version":"v1","params":{"targetUpstream":"alt-upstream"}}]},{"method":"POST","path":"/plain-orders"}] |
    Then the response should be successful

    When I clear all headers
    And I set header "X-Trace-Id" to "trace-0123456789"
    And I set header "X-Custom-Header" to "custom-value"
    And I send a "POST" request to "${CTX:apiContext10}/v1.0/plain-orders" until status 200 with body:
      """
      {"orderId":"42","item":"widget"}
      """
    Then the JSON response field "method" should be "POST"
    And the JSON response field "body" should contain "widget"
    And the response should contain echoed header "X-Trace-Id" with value "trace-0123456789"
    And the response should contain echoed header "X-Custom-Header" with value "custom-value"

    When I send a "POST" request to "${CTX:apiContext10}/v1.0/orders" until status 200 with body:
      """
      {"orderId":"42","item":"widget"}
      """
    Then the JSON response field "path" should be "/alternate/orders"
    And the JSON response field "method" should be "POST"
    And the JSON response field "body" should contain "widget"
    And the JSON response field "body" should contain "42"
    And the response should contain echoed header "X-Trace-Id" with value "trace-0123456789"
    And the response should contain echoed header "X-Custom-Header" with value "custom-value"

  @de-19
  Scenario: The response of the selected upstream reaches the client unchanged
    Given I generate a unique value from "dynamic-passthrough-response" and store it as "apiName11"
    And I generate a unique API context from "/dynamic-passthrough-response" and store it as "apiContext11"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion                    | ${CTX:gatewaySpecVersion}         |
      | name                          | ${CTX:apiName11}                   |
      | spec.displayName              | Dynamic-Endpoint-Response-API     |
      | spec.version                  | v1.0                               |
      | spec.context                  | ${CTX:apiContext11}/$version       |
      | spec.upstream.main.url        | http://testbench:3000              |
      | spec.upstreamDefinitions      | [{"name":"alt-upstream","basePath":"/alternate","upstreams":[{"url":"http://testbench:3000"}]}] |
      | spec.operations               | [{"method":"GET","path":"/whoami","policies":[{"name":"dynamic-endpoint","version":"v1","params":{"targetUpstream":"alt-upstream"}}]}] |
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext11}/v1.0/whoami" until status 200

    When I clear all headers
    And I send a "GET" request to "${CTX:apiContext11}/v1.0/whoami?statusCode=201"
    Then the response status code should be 201
    And the response should be valid JSON
    And the response header "Content-Type" should contain "application/json"
    And the response header "X-Target-Upstream" should not exist
    And the JSON response field "path" should be "/alternate/whoami"

    When I send a "GET" request to "${CTX:apiContext11}/v1.0/whoami?statusCode=404"
    Then the response status code should be 404
    And the JSON response field "path" should be "/alternate/whoami"

  Scenario: An expression without a selector, or a selector without an expression, is rejected at deploy
    Given I generate a unique value from "global-backend-invalid" and store it as "apiName12"
    And I generate a unique API context from "/global-backend-invalid" and store it as "apiContext12"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}          |
      | name                   | ${CTX:apiName12}                     |
      | spec.displayName       | Global-Backend-No-Selector-API     |
      | spec.version           | v1.0                                |
      | spec.context           | ${CTX:apiContext12}/$version         |
      | spec.upstream.main.url | http://testbench:3000               |
      | spec.operations        | [{"method":"GET","path":"/items","policies":[{"name":"dynamic-endpoint","version":"v1","params":{"backendExpression":"request.Headers['x-backend'][0]"}}]}] |
    Then the response status code should be 400
    And the response body should contain "Has a dependency on backendSelector"

    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}          |
      | name                   | ${CTX:apiName12}                     |
      | spec.displayName       | Global-Backend-Selector-Only-API   |
      | spec.version           | v1.0                                |
      | spec.context           | ${CTX:apiContext12}/$version         |
      | spec.upstream.main.url | http://testbench:3000               |
      | spec.upstreamDefinitions | [{"name":"alt-upstream","upstreams":[{"url":"http://testbench:3000"}]}] |
      | spec.operations        | [{"method":"GET","path":"/items","policies":[{"name":"dynamic-endpoint","version":"v1","params":{"targetUpstream":"alt-upstream","backendSelector":{}}}]}] |
    Then the response status code should be 400
    And the response body should contain "Has a dependency on backendExpression"


  Scenario: A backendExpression reading a request header selects a gateway-wide Backend, and a new Backend needs no API change
    Given the gateway version satisfies ">1.2.0"
    And I generate a unique value from "global-backend-header" and store it as "apiName13"
    And I generate a unique API context from "/global-backend-header" and store it as "apiContext13"
    And I generate a unique value from "global-backend-probe" and store it as "apiName13p"
    And I generate a unique API context from "/global-backend-probe" and store it as "apiContext13p"
    And I generate a unique resource name from "team" and store it as "team13"
    And I generate a unique resource name from "ep-a" and store it as "backendA13"
    And I generate a unique resource name from "ep-b" and store it as "backendB13"
    And I generate a unique resource name from "ep-x" and store it as "backendX13"
    When I create Backend from "resources/templates/backend.yaml" with values:
      | apiVersion      | ${CTX:backendSpecVersion}           |
      | name            | ${CTX:backendX13}                  |
      | metadata.labels | {"team":"outsider-${CTX:team13}"}   |
      | spec.basePath   | /outsider                           |
      | spec.endpoints  | [{"url":"http://testbench:3000"}]   |
    Then the response status code should be 201
    When I create Backend from "resources/templates/backend.yaml" with values:
      | apiVersion      | ${CTX:backendSpecVersion}           |
      | name            | ${CTX:backendA13}                  |
      | metadata.labels | {"team":"${CTX:team13}"}            |
      | spec.basePath   | /tenant-a                           |
      | spec.endpoints  | [{"url":"http://testbench:3000"}]   |
    Then the response status code should be 201
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}          |
      | name                   | ${CTX:apiName13}                    |
      | spec.displayName       | Global-Backend-Header-API          |
      | spec.version           | v1.0                                |
      | spec.context           | ${CTX:apiContext13}/$version        |
      | spec.upstream.main.url | http://testbench:3000               |
      | spec.policies          | [{"name":"dynamic-endpoint","version":"v1","params":{"backendExpression":"request.Headers['x-backend'][0]","backendSelector":{"matchLabels":{"team":"${CTX:team13}"}}}},{"name":"remove-headers","version":"v1","params":{"request":{"headers":[{"name":"x-backend"}]}}}] |
      | spec.operations        | [{"method":"GET","path":"/items"}]  |
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext13}/v1.0/items" until status 200

    # A probe API whose selector allows every Backend shows when X is routable on this gateway,
    # so the 400 below comes from the selector rather than from a Backend the policy can't see.
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}          |
      | name                   | ${CTX:apiName13p}                   |
      | spec.displayName       | Global-Backend-Probe-API            |
      | spec.version           | v1.0                                |
      | spec.context           | ${CTX:apiContext13p}/$version       |
      | spec.upstream.main.url | http://testbench:3000               |
      | spec.policies          | [{"name":"dynamic-endpoint","version":"v1","params":{"backendExpression":"request.Headers['x-backend'][0]","backendSelector":{}}}] |
      | spec.operations        | [{"method":"GET","path":"/items"}]  |
    Then the response should be successful

    When I clear all headers
    And I send a "GET" request to "${CTX:apiContext13}/v1.0/items"
    Then the response should be successful
    And the JSON response field "path" should be "/items"

    When I clear all headers
    And I set header "x-backend" to "${CTX:backendA13}"
    And I send a "GET" request to "${CTX:apiContext13}/v1.0/items" until status 200
    Then the response should be successful
    And the JSON response field "path" should be "/tenant-a/items"
    And the response should not contain echoed header "x-backend"

    When I clear all headers
    And I set header "x-backend" to "${CTX:backendX13}"
    And I send a "GET" request to "${CTX:apiContext13p}/v1.0/items" until status 200
    Then the JSON response field "path" should be "/outsider/items"
    And I send a "GET" request to "${CTX:apiContext13}/v1.0/items"
    Then the response status code should be 400
    And the response body should contain "The requested backend is not available for this API."

    When I clear all headers
    And I set header "x-backend" to "${CTX:backendB13}"
    And I send a "GET" request to "${CTX:apiContext13}/v1.0/items"
    Then the response status code should be 400
    And the response body should contain "The requested backend is not available for this API."

    When I clear all headers
    And I set header "x-backend" to "Not_A_Backend"
    And I send a "GET" request to "${CTX:apiContext13}/v1.0/items"
    Then the response status code should be 400

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I create Backend from "resources/templates/backend.yaml" with values:
      | apiVersion      | ${CTX:backendSpecVersion}           |
      | name            | ${CTX:backendB13}                  |
      | metadata.labels | {"team":"${CTX:team13}"}            |
      | spec.basePath   | /tenant-b                           |
      | spec.endpoints  | [{"url":"http://testbench:3000"}]   |
    Then the response status code should be 201
    When I clear all headers
    And I set header "x-backend" to "${CTX:backendB13}"
    And I send a "GET" request to "${CTX:apiContext13}/v1.0/items" until status 200
    Then the JSON response field "path" should be "/tenant-b/items"

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I update Backend "${CTX:backendB13}" from "resources/templates/backend.yaml" with values:
      | apiVersion      | ${CTX:backendSpecVersion}           |
      | name            | ${CTX:backendB13}                  |
      | metadata.labels | {"team":"${CTX:team13}"}            |
      | spec.basePath   | /tenant-b-v2                        |
      | spec.endpoints  | [{"url":"http://testbench:3000"}]   |
    Then the response should be successful
    When I clear all headers
    And I set header "x-backend" to "${CTX:backendB13}"
    And I send a "GET" request to "${CTX:apiContext13}/v1.0/items" until the response body contains "/tenant-b-v2/items" with body:
      """
      {}
      """
    Then the response should be successful

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the Backend "${CTX:backendB13}"
    Then the response should be successful
    When I clear all headers
    And I set header "x-backend" to "${CTX:backendB13}"
    And I send a "GET" request to "${CTX:apiContext13}/v1.0/items" until status 400
    Then the response body should contain "The requested backend is not available for this API."


  Scenario: A targetUpstream naming a Backend answers 503 until it exists, and the Backend cannot be deleted while named
    Given the gateway version satisfies ">1.2.0"
    And I generate a unique value from "global-backend-fixed" and store it as "apiName14"
    And I generate a unique API context from "/global-backend-fixed" and store it as "apiContext14"
    And I generate a unique resource name from "ep-fixed" and store it as "backendF14"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}          |
      | name                   | ${CTX:apiName14}                    |
      | spec.displayName       | Global-Backend-Fixed-API           |
      | spec.version           | v1.0                                |
      | spec.context           | ${CTX:apiContext14}/$version        |
      | spec.upstream.main.url | http://testbench:3000               |
      | spec.operations        | [{"method":"GET","path":"/items","policies":[{"name":"dynamic-endpoint","version":"v1","params":{"targetUpstream":"${CTX:backendF14}"}}]}] |
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext14}/v1.0/items" until status 503
    # The policy engine's own reply for a Backend it doesn't hold: its body carries the same error
    # ID as the x-error-id header, which Envoy's and a backend's 503s don't. The fault code
    # (905008) goes to analytics and fault policies, never to the caller.
    And the response header "x-error-id" should exist
    And I store the response header "x-error-id" as "errorId14"
    And the JSON response field "error" should be "Service Unavailable"
    And the JSON response field "error_id" should be "${CTX:errorId14}"

    When I create Backend from "resources/templates/backend.yaml" with values:
      | apiVersion      | ${CTX:backendSpecVersion}           |
      | name            | ${CTX:backendF14}                  |
      | metadata.labels | {"team":"fixed"}                    |
      | spec.basePath   | /fixed                              |
      | spec.endpoints  | [{"url":"http://testbench:3000"}]   |
    Then the response status code should be 201
    And I send a "GET" request to "${CTX:apiContext14}/v1.0/items" until status 200
    And the JSON response field "path" should be "/fixed/items"

    When I delete the Backend "${CTX:backendF14}"
    Then the response status code should be 409
    And the response body should contain "${CTX:apiName14}"


  Scenario: A request whose expression yields no value is rejected or falls back, as configured per operation
    Given the gateway version satisfies ">1.2.0"
    And I generate a unique value from "global-backend-missing" and store it as "apiName15"
    And I generate a unique API context from "/global-backend-missing" and store it as "apiContext15"
    And I generate a unique resource name from "ep-sel" and store it as "backendS15"
    When I create Backend from "resources/templates/backend.yaml" with values:
      | apiVersion      | ${CTX:backendSpecVersion}           |
      | name            | ${CTX:backendS15}                  |
      | spec.basePath   | /selected                           |
      | spec.endpoints  | [{"url":"http://testbench:3000"}]   |
    Then the response status code should be 201
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}          |
      | name                   | ${CTX:apiName15}                    |
      | spec.displayName       | Global-Backend-Missing-Value-API  |
      | spec.version           | v1.0                                |
      | spec.context           | ${CTX:apiContext15}/$version        |
      | spec.upstream.main.url | http://testbench:3000               |
      | spec.upstreamDefinitions | [{"name":"alt-upstream","basePath":"/alternate","upstreams":[{"url":"http://testbench:3000"}]}] |
      | spec.operations        | [{"method":"GET","path":"/strict","policies":[{"name":"dynamic-endpoint","version":"v1","params":{"backendExpression":"request.Headers['x-backend'][0]","backendSelector":{},"onMissingValue":"reject"}}]},{"method":"GET","path":"/lenient","policies":[{"name":"dynamic-endpoint","version":"v1","params":{"backendExpression":"request.Headers['x-backend'][0]","backendSelector":{},"targetUpstream":"alt-upstream"}}]}] |
    Then the response should be successful

    # Wait until the Backend is selectable, so the 400 below can only come from the missing value.
    When I clear all headers
    And I set header "x-backend" to "${CTX:backendS15}"
    And I send a "GET" request to "${CTX:apiContext15}/v1.0/strict" until status 200
    Then the JSON response field "path" should be "/selected/strict"

    When I clear all headers
    And I send a "GET" request to "${CTX:apiContext15}/v1.0/strict"
    Then the response status code should be 400

    When I clear all headers
    And I send a "GET" request to "${CTX:apiContext15}/v1.0/lenient"
    Then the response should be successful
    And the JSON response field "path" should be "/alternate/lenient"


  Scenario: A backendExpression can read request context other than headers
    Given the gateway version satisfies ">1.2.0"
    And I generate a unique value from "global-backend-query" and store it as "apiName16"
    And I generate a unique API context from "/global-backend-query" and store it as "apiContext16"
    And I generate a unique resource name from "ep-q" and store it as "backendQ16"
    When I create Backend from "resources/templates/backend.yaml" with values:
      | apiVersion      | ${CTX:backendSpecVersion}           |
      | name            | ${CTX:backendQ16}                   |
      | spec.basePath   | /from-query                         |
      | spec.endpoints  | [{"url":"http://testbench:3000"}]   |
    Then the response status code should be 201
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}          |
      | name                   | ${CTX:apiName16}                    |
      | spec.displayName       | Global-Backend-Query-API            |
      | spec.version           | v1.0                                |
      | spec.context           | ${CTX:apiContext16}/$version        |
      | spec.upstream.main.url | http://testbench:3000               |
      | spec.policies          | [{"name":"dynamic-endpoint","version":"v1","params":{"backendExpression":"request.Path.split('route-to=')[1].split('&')[0]","backendSelector":{}}}] |
      | spec.operations        | [{"method":"GET","path":"/items"}]  |
    Then the response should be successful

    # The query-bearing request is the one that needs the Backend, so it is what waits for it.
    When I clear all headers
    And I send a "GET" request to "${CTX:apiContext16}/v1.0/items?route-to=${CTX:backendQ16}&page=2" until status 200
    Then the JSON response field "path" should be "/from-query/items"

    When I clear all headers
    And I send a "GET" request to "${CTX:apiContext16}/v1.0/items?page=2"
    Then the response should be successful
    And the JSON response field "path" should be "/items"


  Scenario: An API's own upstream definition takes precedence over a Backend of the same name
    Given the gateway version satisfies ">1.2.0"
    And I generate a unique value from "global-backend-shadow" and store it as "apiName17"
    And I generate a unique API context from "/global-backend-shadow" and store it as "apiContext17"
    And I generate a unique resource name from "ep-shadow" and store it as "backendS17"
    When I create Backend from "resources/templates/backend.yaml" with values:
      | apiVersion      | ${CTX:backendSpecVersion}           |
      | name            | ${CTX:backendS17}                   |
      | spec.basePath   | /shared                             |
      | spec.endpoints  | [{"url":"http://testbench:3000"}]   |
    Then the response status code should be 201
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}          |
      | name                   | ${CTX:apiName17}                    |
      | spec.displayName       | Global-Backend-Shadow-API           |
      | spec.version           | v1.0                                |
      | spec.context           | ${CTX:apiContext17}/$version        |
      | spec.upstream.main.url | http://testbench:3000               |
      | spec.upstreamDefinitions | [{"name":"${CTX:backendS17}","basePath":"/own","upstreams":[{"url":"http://testbench:3000"}]}] |
      | spec.operations        | [{"method":"GET","path":"/items","policies":[{"name":"dynamic-endpoint","version":"v1","params":{"targetUpstream":"${CTX:backendS17}"}}]},{"method":"GET","path":"/control","policies":[{"name":"dynamic-endpoint","version":"v1","params":{"backendExpression":"'${CTX:backendS17}'","backendSelector":{}}}]}] |
    Then the response should be successful

    # The control operation names the Backend through backendExpression, which only names
    # Backends, so it reaches the Backend once the Backend is routable.
    And I send a "GET" request to "${CTX:apiContext17}/v1.0/control" until status 200
    And the JSON response field "path" should be "/shared/control"
    When I send a "GET" request to "${CTX:apiContext17}/v1.0/items"
    Then the response should be successful
    And the JSON response field "path" should be "/own/items"

    When I delete the Backend "${CTX:backendS17}"
    Then the response status code should be 200
    # The control operation answers 400 once the gateway no longer routes to the deleted Backend.
    And I send a "GET" request to "${CTX:apiContext17}/v1.0/control" until status 400
    When I send a "GET" request to "${CTX:apiContext17}/v1.0/items"
    Then the response should be successful
    And the JSON response field "path" should be "/own/items"


  Scenario: A templated Backend reaches the host a request header's key expands to
    Given the gateway version satisfies ">1.2.0"
    And I generate a unique value from "templated-backend-header" and store it as "apiName18"
    And I generate a unique API context from "/templated-backend-header" and store it as "apiContext18"
    And I generate a unique value from "templated-backend-expr" and store it as "apiName19"
    And I generate a unique API context from "/templated-backend-expr" and store it as "apiContext19"
    And I generate a unique resource name from "team" and store it as "team18"
    And I generate a unique resource name from "ep-env" and store it as "backendT18"
    When I create Backend from "resources/templates/backend.yaml" with values:
      | apiVersion      | ${CTX:backendSpecVersion}                     |
      | name            | ${CTX:backendT18}                            |
      | metadata.labels | {"team":"${CTX:team18}"}                      |
      | spec.basePath   | /env                                          |
      | spec.endpoints  | [{"url":"http://env-{key}.testbench:3000"}]   |
    Then the response status code should be 201

    # A fixed target and a key from the env header.
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}          |
      | name                   | ${CTX:apiName18}                    |
      | spec.displayName       | Templated-Backend-Header-API        |
      | spec.version           | v1.0                                |
      | spec.context           | ${CTX:apiContext18}/$version        |
      | spec.upstream.main.url | http://testbench:3000               |
      | spec.policies          | [{"name":"dynamic-endpoint","version":"v1","params":{"targetUpstream":"${CTX:backendT18}","backendKeyExpression":"request.Headers['env'][0].lowerAscii()"}},{"name":"remove-headers","version":"v1","params":{"request":{"headers":[{"name":"env"}]}}}] |
      | spec.operations        | [{"method":"GET","path":"/items"}]  |
    Then the response should be successful

    When I clear all headers
    And I set header "env" to "Dev"
    And I send a "GET" request to "${CTX:apiContext18}/v1.0/items" until status 200
    Then the JSON response field "path" should be "/env/items"
    And the response should contain echoed header "Host" containing "env-dev.testbench"
    And the response should not contain echoed header "env"

    When I clear all headers
    And I set header "env" to "prod"
    And I send a "GET" request to "${CTX:apiContext18}/v1.0/items"
    Then the response status code should be 200
    And the response should contain echoed header "Host" containing "env-prod.testbench"

    When I clear all headers
    And I send a "GET" request to "${CTX:apiContext18}/v1.0/items"
    Then the response status code should be 400
    And the response body should contain "The requested backend is not available for this API."

    When I clear all headers
    And I set header "env" to "dev.testbench"
    And I send a "GET" request to "${CTX:apiContext18}/v1.0/items"
    Then the response status code should be 400

    # backendExpression picks the templated Backend by name and the selector; the key fills its host.
    When I authenticate using basic auth as "admin"
    And I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}          |
      | name                   | ${CTX:apiName19}                    |
      | spec.displayName       | Templated-Backend-Expression-API    |
      | spec.version           | v1.0                                |
      | spec.context           | ${CTX:apiContext19}/$version        |
      | spec.upstream.main.url | http://testbench:3000               |
      | spec.policies          | [{"name":"dynamic-endpoint","version":"v1","params":{"backendExpression":"request.Headers['x-backend'][0]","backendSelector":{"matchLabels":{"team":"${CTX:team18}"}},"backendKeyExpression":"request.Headers['env'][0]"}}] |
      | spec.operations        | [{"method":"GET","path":"/items"}]  |
    Then the response should be successful

    When I clear all headers
    And I set header "x-backend" to "${CTX:backendT18}"
    And I set header "env" to "prod"
    And I send a "GET" request to "${CTX:apiContext19}/v1.0/items" until status 200
    Then the JSON response field "path" should be "/env/items"
    And the response should contain echoed header "Host" containing "env-prod.testbench"

    When I clear all headers
    And I set header "x-backend" to "${CTX:backendT18}"
    And I send a "GET" request to "${CTX:apiContext19}/v1.0/items"
    Then the response status code should be 400


  Scenario: A templated Backend reaches the host the caller's subscription plan maps to
    Given the gateway version satisfies ">1.2.0"
    And I generate a unique value from "templated-plan" and store it as "planName20"
    And I generate a unique value from "templated-backend-plan" and store it as "apiName20"
    And I generate a unique API context from "/templated-backend-plan" and store it as "apiContext20"
    And I generate a unique resource name from "ep-plan" and store it as "backendT20"
    And I generate a unique value from "templated-plan-token" and store it as "subToken20"
    When I send a "POST" request to the "gateway-controller" service at "/subscription-plans" with body:
      """
      {"planName":"${CTX:planName20}","throttleLimitCount":100,"throttleLimitUnit":"Min"}
      """
    Then the response status should be 201
    And I store the JSON response field "id" as "planId20"
    And I register the "subscription-plan" "${CTX:planId20}" for cleanup

    When I create Backend from "resources/templates/backend.yaml" with values:
      | apiVersion      | ${CTX:backendSpecVersion}                     |
      | name            | ${CTX:backendT20}                            |
      | spec.basePath   | /plan                                         |
      | spec.endpoints  | [{"url":"http://env-{key}.testbench:3000"}]   |
    Then the response status code should be 201

    # subscription-validation runs first and stores the caller's plan in the request metadata; the
    # key expression maps the plan to a key. The API is sent as JSON, since its policies read the
    # request metadata.
    When I create API with JSON configuration:
      """
      {
        "apiVersion": "${CTX:gatewaySpecVersion}",
        "kind": "RestApi",
        "metadata": {"name": "${CTX:apiName20}"},
        "spec": {
          "displayName": "Templated-Backend-Plan-API",
          "version": "v1.0",
          "context": "${CTX:apiContext20}/$version",
          "subscriptionPlans": ["${CTX:planName20}"],
          "upstream": {"main": {"url": "http://testbench:3000"}},
          "policies": [
            {"name": "subscription-validation", "version": "v1", "params": {"subscriptionKeyHeader": "Subscription-Key"}},
            {"name": "dynamic-endpoint", "version": "v1", "params": {"targetUpstream": "${CTX:backendT20}",
              "backendKeyExpression": "request.Metadata['x-wso2-subscription-plan-name'] == '${CTX:planName20}' ? 'prod' : 'dev'"}}
          ],
          "operations": [{"method": "GET", "path": "/items"}]
        }
      }
      """
    Then the response should be successful
    When I clear all headers
    And I send a "GET" request to "${CTX:apiContext20}/v1.0/items" until status 403

    When I authenticate using basic auth as "admin"
    And I send a "POST" request to the "gateway-controller" service at "/subscriptions" with body:
      """
      {"apiId":"${CTX:apiName20}","subscriptionPlanId":"${CTX:planId20}","subscriptionToken":"${CTX:subToken20}"}
      """
    Then the response status should be 201
    And I store the JSON response field "id" as "subId20"
    And I register the "subscription" "${CTX:subId20}" for cleanup

    When I clear all headers
    And I set header "Subscription-Key" to "${CTX:subToken20}"
    And I send a "GET" request to "${CTX:apiContext20}/v1.0/items" until status 200
    Then the JSON response field "path" should be "/plan/items"
    And the response should contain echoed header "Host" containing "env-prod.testbench"
