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

  Scenario: Deploy fails when targetUpstream is omitted
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
