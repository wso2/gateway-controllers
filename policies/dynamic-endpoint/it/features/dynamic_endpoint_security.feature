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
# "AS IS" BASIS, WITH WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.
# --------------------------------------------------------------------

@dynamic-endpoint
Feature: Dynamic endpoint upstream selection cannot be influenced by the client
  As an API owner
  I want only the API configuration to choose the upstream
  So that no query, header, path, body or host sent by a client can redirect traffic

  # Every scenario deploys the same shape of API. The operation selects the "public" definition,
  # served by the backend service on port 3000. The "internal" definition is served by the echo
  # service on port 3002 and is never selected, so a request that ends up there is visible by the
  # echo response shape. The main upstream is the capture service, which answers 204 for a path
  # it never received, so a request that ends up there is visible too.
  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"
    And I resolve the "capture" service URL at "" and store it as "captureUpstream"

  Scenario: A query parameter cannot override the configured upstream
    Given I generate a unique value from "dynamic-sec-query" and store it as "apiName"
    And I generate a unique API context from "/dynamic-sec-query" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion               | ${CTX:gatewaySpecVersion}          |
      | name                     | ${CTX:apiName}                     |
      | spec.displayName         | Dynamic-Endpoint-Query-API         |
      | spec.version             | v1.0                               |
      | spec.context             | ${CTX:apiContext}/$version         |
      | spec.upstream.main.url   | ${CTX:captureUpstream}             |
      | spec.upstreamDefinitions | [{"name":"public","basePath":"/public","upstreams":[{"url":"http://testbench:3000"}]},{"name":"internal","basePath":"/internal","upstreams":[{"url":"http://testbench:3002"}]}] |
      | spec.operations          | [{"method":"GET","path":"/s26/probe","policies":[{"name":"dynamic-endpoint","version":"v1","params":{"targetUpstream":"public"}}]}] |
    Then the response should be successful

    When I clear all headers
    And I send a "GET" request to "${CTX:apiContext}/v1.0/s26/probe" until status 200
    And I send a "GET" request to "${CTX:apiContext}/v1.0/s26/probe?targetUpstream=internal&upstream=internal&target_upstream=internal"
    Then the response status code should be 200
    And the response should be served by the "backend" testbench service
    And the JSON response field "path" should be "/public/s26/probe"
    And the JSON response field "query" should contain "targetUpstream=internal"
    When I send a "GET" request to the "capture" service at "/test/captured?path=/s26/probe" until status 204

  Scenario: Request headers cannot select another upstream
    Given I generate a unique value from "dynamic-sec-headers" and store it as "apiName"
    And I generate a unique API context from "/dynamic-sec-headers" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion               | ${CTX:gatewaySpecVersion}          |
      | name                     | ${CTX:apiName}                     |
      | spec.displayName         | Dynamic-Endpoint-Headers-API       |
      | spec.version             | v1.0                               |
      | spec.context             | ${CTX:apiContext}/$version         |
      | spec.upstream.main.url   | ${CTX:captureUpstream}             |
      | spec.upstreamDefinitions | [{"name":"public","basePath":"/public","upstreams":[{"url":"http://testbench:3000"}]},{"name":"internal","basePath":"/internal","upstreams":[{"url":"http://testbench:3002"}]}] |
      | spec.operations          | [{"method":"GET","path":"/s27/probe","policies":[{"name":"dynamic-endpoint","version":"v1","params":{"targetUpstream":"public"}}]},{"method":"GET","path":"/s27/plain"}] |
    Then the response should be successful

    When I clear all headers
    And I send a "GET" request to "${CTX:apiContext}/v1.0/s27/probe" until status 200
    And I send a "GET" request to "${CTX:apiContext}/v1.0/s27/plain" until status 200

    When I set header "X-Upstream" to "internal"
    And I set header "X-Target-Upstream" to "internal"
    And I set header "X-Forwarded-Host" to "internal.example.com"
    And I send a "GET" request to "${CTX:apiContext}/v1.0/s27/probe"
    Then the response status code should be 200
    And the response should be served by the "backend" testbench service
    And the JSON response field "path" should be "/public/s27/probe"

    # Without the policy the same headers cannot choose an upstream either: the operation stays
    # on the main upstream.
    When I send a "GET" request to "${CTX:apiContext}/v1.0/s27/plain"
    Then the response status code should be 200
    And the JSON response field "path" should be "/s27/plain"

  Scenario: A URL supplied in a header, query, path or body is never used as an endpoint
    Given I generate a unique value from "dynamic-sec-url" and store it as "apiName"
    And I generate a unique API context from "/dynamic-sec-url" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion               | ${CTX:gatewaySpecVersion}          |
      | name                     | ${CTX:apiName}                     |
      | spec.displayName         | Dynamic-Endpoint-URL-API           |
      | spec.version             | v1.0                               |
      | spec.context             | ${CTX:apiContext}/$version         |
      | spec.upstream.main.url   | ${CTX:captureUpstream}             |
      | spec.upstreamDefinitions | [{"name":"public","basePath":"/public","upstreams":[{"url":"http://testbench:3000"}]},{"name":"internal","basePath":"/internal","upstreams":[{"url":"http://testbench:3002"}]}] |
      | spec.operations          | [{"method":"GET","path":"/s28/*","policies":[{"name":"dynamic-endpoint","version":"v1","params":{"targetUpstream":"public"}}]},{"method":"POST","path":"/s28/probe","policies":[{"name":"dynamic-endpoint","version":"v1","params":{"targetUpstream":"public"}}]}] |
    Then the response should be successful

    When I clear all headers
    And I set header "X-Upstream-URL" to "http://attacker.example.com"
    And I send a "GET" request to "${CTX:apiContext}/v1.0/s28/probe?url=http://attacker.example.com&target=http://attacker.example.com" until status 200
    Then the response should be served by the "backend" testbench service
    And the JSON response field "path" should be "/public/s28/probe"
    And the response should contain echoed header "Host" containing "testbench"

    When I send a "GET" request to "${CTX:apiContext}/v1.0/s28/http%3A%2F%2Fattacker.example.com"
    Then the response status code should be 200
    And the response should be served by the "backend" testbench service
    And the JSON response field "path" should contain "/public/s28/"
    And the response should contain echoed header "Host" containing "testbench"

    When I send a "POST" request to "${CTX:apiContext}/v1.0/s28/probe" with body:
      """
      {"url":"http://attacker.example.com","upstream":"http://attacker.example.com"}
      """
    Then the response status code should be 200
    And the response should be served by the "backend" testbench service
    And the JSON response field "path" should be "/public/s28/probe"
    And the response should contain echoed header "Host" containing "testbench"
    When I send a "GET" request to the "capture" service at "/test/captured?path=/s28/probe" until status 204

  Scenario Outline: Internal and loopback addresses in request input cannot redirect the request (<target>)
    Given I generate a unique value from "dynamic-sec-ssrf" and store it as "apiName"
    And I generate a unique API context from "/dynamic-sec-ssrf" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion               | ${CTX:gatewaySpecVersion}          |
      | name                     | ${CTX:apiName}                     |
      | spec.displayName         | Dynamic-Endpoint-SSRF-API          |
      | spec.version             | v1.0                               |
      | spec.context             | ${CTX:apiContext}/$version         |
      | spec.upstream.main.url   | ${CTX:captureUpstream}             |
      | spec.upstreamDefinitions | [{"name":"public","basePath":"/public","upstreams":[{"url":"http://testbench:3000"}]},{"name":"internal","basePath":"/internal","upstreams":[{"url":"http://testbench:3002"}]}] |
      | spec.operations          | [{"method":"GET","path":"/<probe>/probe","policies":[{"name":"dynamic-endpoint","version":"v1","params":{"targetUpstream":"public"}}]}] |
    Then the response should be successful

    When I clear all headers
    And I set header "X-Upstream" to "<target>"
    And I set header "X-Forwarded-Host" to "<target>"
    And I send a "GET" request to "${CTX:apiContext}/v1.0/<probe>/probe?target=<target>&redirect=<target>" until status 200
    Then the response should be served by the "backend" testbench service
    And the JSON response field "path" should be "/public/<probe>/probe"
    When I send a "GET" request to the "capture" service at "/test/captured?path=/<probe>/probe" until status 204

    Examples:
      | target                | probe       |
      | localhost             | ssrf-local  |
      | 127.0.0.1             | ssrf-loop   |
      | 169.254.169.254       | ssrf-meta   |
      | http://testbench:3002 | ssrf-echo   |

  Scenario: Only an authenticated administrator can introduce or change an upstream definition
    Given I generate a unique value from "dynamic-sec-admin" and store it as "apiName"
    And I generate a unique value from "dynamic-sec-admin-rejected" and store it as "rejectedApiName"
    And I generate a unique API context from "/dynamic-sec-admin" and store it as "apiContext"
    And I generate a unique API context from "/dynamic-sec-admin-rejected" and store it as "rejectedContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion               | ${CTX:gatewaySpecVersion}          |
      | name                     | ${CTX:apiName}                     |
      | spec.displayName         | Dynamic-Endpoint-Admin-API         |
      | spec.version             | v1.0                               |
      | spec.context             | ${CTX:apiContext}/$version         |
      | spec.upstream.main.url   | http://testbench:3000              |
      | spec.upstreamDefinitions | [{"name":"external","basePath":"/ext","upstreams":[{"url":"http://untrusted.example.invalid"}]}] |
      | spec.operations          | [{"method":"GET","path":"/s30/probe","policies":[{"name":"dynamic-endpoint","version":"v1","params":{"targetUpstream":"external"}}]}] |
    Then the response should be successful

    # An administrator may point a definition anywhere. The route follows that configuration,
    # and nothing a client sends changes it.
    When I clear all headers
    And I send a "GET" request to "${CTX:apiContext}/v1.0/s30/probe?upstream=http://attacker.example.com" until status 503

    # Without credentials a client can neither create an API with a definition nor change one.
    When I clear all headers
    And I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion               | ${CTX:gatewaySpecVersion}          |
      | name                     | ${CTX:rejectedApiName}             |
      | spec.displayName         | Dynamic-Endpoint-Rejected-API      |
      | spec.version             | v1.0                               |
      | spec.context             | ${CTX:rejectedContext}/$version    |
      | spec.upstream.main.url   | http://testbench:3000              |
      | spec.upstreamDefinitions | [{"name":"hijack","basePath":"/hijack","upstreams":[{"url":"http://testbench:3002"}]}] |
      | spec.operations          | [{"method":"GET","path":"/s30/probe","policies":[{"name":"dynamic-endpoint","version":"v1","params":{"targetUpstream":"hijack"}}]}] |
    Then the response status code should be 401

    When I update API "${CTX:apiName}" from "resources/templates/rest-api.yaml" with values:
      | apiVersion               | ${CTX:gatewaySpecVersion}          |
      | name                     | ${CTX:apiName}                     |
      | spec.displayName         | Dynamic-Endpoint-Admin-API         |
      | spec.version             | v1.0                               |
      | spec.context             | ${CTX:apiContext}/$version         |
      | spec.upstream.main.url   | http://testbench:3000              |
      | spec.upstreamDefinitions | [{"name":"hijack","basePath":"/hijack","upstreams":[{"url":"http://testbench:3002"}]}] |
      | spec.operations          | [{"method":"GET","path":"/s30/probe","policies":[{"name":"dynamic-endpoint","version":"v1","params":{"targetUpstream":"hijack"}}]}] |
    Then the response status code should be 401

    When I send a "GET" request to "${CTX:apiContext}/v1.0/s30/probe" until status 503
    And I send a "GET" request to "${CTX:rejectedContext}/v1.0/s30/probe" until status 404

  Scenario Outline: Encoded and traversal path values cannot select another upstream definition (<case>)
    Given I generate a unique value from "dynamic-sec-path" and store it as "apiName"
    And I generate a unique API context from "/dynamic-sec-path" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion               | ${CTX:gatewaySpecVersion}          |
      | name                     | ${CTX:apiName}                     |
      | spec.displayName         | Dynamic-Endpoint-Path-API          |
      | spec.version             | v1.0                               |
      | spec.context             | ${CTX:apiContext}/$version         |
      | spec.upstream.main.url   | http://testbench:3000              |
      | spec.upstreamDefinitions | [{"name":"public","basePath":"/public","upstreams":[{"url":"http://testbench:3000"}]},{"name":"internal","basePath":"/internal","upstreams":[{"url":"http://testbench:3002"}]}] |
      | spec.operations          | [{"method":"GET","path":"/s31/*","policies":[{"name":"dynamic-endpoint","version":"v1","params":{"targetUpstream":"public"}}]}] |
    Then the response should be successful

    When I clear all headers
    And I send a "GET" request to "${CTX:apiContext}/v1.0/s31/probe" until status 200
    And I send a "GET" request to "${CTX:apiContext}/v1.0<path>"
    Then the JSON response field "path", if present, should start with "/public/"
    And the response body should not contain "args"

    Examples:
      | case                  | path                                           |
      | dot segments          | /s31/probe/../../internal/probe                |
      | encoded dot segments  | /s31/probe/%2e%2e/%2e%2e/internal/probe        |
      | encoded slashes       | /s31/probe/..%2f..%2finternal%2fprobe          |
      | doubled slash         | /s31//internal/probe                           |
      | encoded null          | /s31/probe%00/internal                         |

  Scenario: A spoofed Host header does not change the selected upstream
    Given I generate a unique value from "dynamic-sec-host" and store it as "apiName"
    And I generate a unique API context from "/dynamic-sec-host" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion               | ${CTX:gatewaySpecVersion}          |
      | name                     | ${CTX:apiName}                     |
      | spec.displayName         | Dynamic-Endpoint-Host-API          |
      | spec.version             | v1.0                               |
      | spec.context             | ${CTX:apiContext}/$version         |
      | spec.upstream.main.url   | ${CTX:captureUpstream}             |
      | spec.upstreamDefinitions | [{"name":"public","basePath":"/public","upstreams":[{"url":"http://testbench:3000"}]},{"name":"internal","basePath":"/internal","upstreams":[{"url":"http://testbench:3002"}]}] |
      | spec.operations          | [{"method":"GET","path":"/s32/probe","policies":[{"name":"dynamic-endpoint","version":"v1","params":{"targetUpstream":"public"}}]}] |
    Then the response should be successful

    When I clear all headers
    And I send a "GET" request to "${CTX:apiContext}/v1.0/s32/probe" until status 200
    Then the JSON response field "path" should be "/public/s32/probe"

    When I set request host to "internal.example.com"
    And I set header "X-Forwarded-Host" to "internal.example.com"
    And I send a "GET" request to "${CTX:apiContext}/v1.0/s32/probe"
    Then the response body should not contain "/internal"
    And the response body should not contain "args"
    When I send a "GET" request to the "capture" service at "/test/captured?path=/s32/probe" until status 204

  Scenario: A spoofed Host header does not redirect traffic when Host Rewrite is combined with the policy
    Given I generate a unique value from "dynamic-sec-rewrite-host" and store it as "apiName"
    And I generate a unique API context from "/dynamic-sec-rewrite-host" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion               | ${CTX:gatewaySpecVersion}          |
      | name                     | ${CTX:apiName}                     |
      | spec.displayName         | Dynamic-Endpoint-Host-Rewrite-API  |
      | spec.version             | v1.0                               |
      | spec.context             | ${CTX:apiContext}/$version         |
      | spec.upstream.main.url   | ${CTX:captureUpstream}             |
      | spec.upstreamDefinitions | [{"name":"public","basePath":"/public","upstreams":[{"url":"http://testbench:3000"}]},{"name":"internal","basePath":"/internal","upstreams":[{"url":"http://testbench:3002"}]}] |
      | spec.operations          | [{"method":"GET","path":"/s33/baseline","policies":[{"name":"host-rewrite","version":"v1","params":{"host":"rewritten.example.com"}}]},{"method":"GET","path":"/s33/probe","policies":[{"name":"host-rewrite","version":"v1","params":{"host":"rewritten.example.com"}},{"name":"dynamic-endpoint","version":"v1","params":{"targetUpstream":"public"}}]}] |
    Then the response should be successful

    # Host Rewrite alone sets the upstream Host. The next two requests show whether it still does
    # once dynamic-endpoint has moved the request to a named upstream.
    When I clear all headers
    And I send a "GET" request to "${CTX:apiContext}/v1.0/s33/baseline" until status 200
    Then the response should contain echoed header "Host" with value "rewritten.example.com"

    When I send a "GET" request to "${CTX:apiContext}/v1.0/s33/probe" until status 200
    Then the response should be served by the "backend" testbench service
    And the JSON response field "path" should be "/public/s33/probe"
    And the response should contain echoed header "Host" with value "rewritten.example.com"

    When I set request host to "internal.example.com"
    And I send a "GET" request to "${CTX:apiContext}/v1.0/s33/probe"
    Then the response body should not contain "/internal"
    And the response body should not contain "internal.example.com"
    And the response body should not contain "args"
    When I send a "GET" request to the "capture" service at "/test/captured?path=/s33/probe" until status 204
