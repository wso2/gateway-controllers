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

@host-rewrite
Feature: Host rewrite routing
  As an API user
  I want gateway routing behavior to follow the configured rules
  So that requests reach the intended endpoint and response

  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"

  Scenario: Host rewrite sets the Host header on upstream request
    Given I generate a unique value from "host-rewrite-1" and store it as "apiName1"
    And I generate a unique API context from "/host-rewrite-1" and store it as "apiContext1"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion            | ${CTX:gatewaySpecVersion}                                      |
      | name                  | ${CTX:apiName1}                                               |
      | spec.displayName      | Host Rewrite Basic                                           |
      | spec.version          | v1.0                                                          |
      | spec.context          | ${CTX:apiContext1}/$version                                   |
      | spec.upstream.main.url| http://testbench:3002/anything                                |
      | spec.upstream.main.hostRewrite | manual                                    |
      | spec.operations       | [{"method":"GET","path":"/test","policies":[{"name":"host-rewrite","version":"v1","params":{"host":"example-updated.com"}}]}] |
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext1}/v1.0/test" until status 200
    When I send a "GET" request to "${CTX:apiContext1}/v1.0/test"
    Then the response status code should be 200
    And the JSON response field "headers.Host" should be "example-updated.com"

    When I delete the API "${CTX:apiName1}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext1}/v1.0/test" until status 404

  Scenario: Host rewrite with port number
    Given I generate a unique value from "host-rewrite-2" and store it as "apiName2"
    And I generate a unique API context from "/host-rewrite-2" and store it as "apiContext2"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion            | ${CTX:gatewaySpecVersion}                                      |
      | name                  | ${CTX:apiName2}                                               |
      | spec.displayName      | Host Rewrite With Port                                       |
      | spec.version          | v1.0                                                          |
      | spec.context          | ${CTX:apiContext2}/$version                                   |
      | spec.upstream.main.url| http://testbench:3002/anything                                |
      | spec.upstream.main.hostRewrite | manual                                    |
      | spec.operations       | [{"method":"GET","path":"/test","policies":[{"name":"host-rewrite","version":"v1","params":{"host":"backend.example.com:8080"}}]}] |
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext2}/v1.0/test" until status 200
    When I send a "GET" request to "${CTX:apiContext2}/v1.0/test"
    Then the response status code should be 200
    And the JSON response field "headers.Host" should be "backend.example.com:8080"

    When I delete the API "${CTX:apiName2}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext2}/v1.0/test" until status 404

  Scenario: Host rewrite at API level applies to all operations
    Given I generate a unique value from "host-rewrite-3" and store it as "apiName3"
    And I generate a unique API context from "/host-rewrite-3" and store it as "apiContext3"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion            | ${CTX:gatewaySpecVersion}                                      |
      | name                  | ${CTX:apiName3}                                               |
      | spec.displayName      | Host Rewrite API Level                                        |
      | spec.version          | v1.0                                                          |
      | spec.context          | ${CTX:apiContext3}/$version                                   |
      | spec.upstream.main.url| http://testbench:3002/anything                                |
      | spec.upstream.main.hostRewrite | manual                                    |
      | spec.policies         | [{"name":"host-rewrite","version":"v1","params":{"host":"api-level.example.com"}}] |
      | spec.operations       | [{"method":"GET","path":"/test1"},{"method":"POST","path":"/test2"}] |
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext3}/v1.0/test1" until status 200
    When I send a "GET" request to "${CTX:apiContext3}/v1.0/test1"
    Then the response status code should be 200
    And the JSON response field "headers.Host" should be "api-level.example.com"
    When I send a "POST" request to "${CTX:apiContext3}/v1.0/test2"
    Then the response status code should be 200
    And the JSON response field "headers.Host" should be "api-level.example.com"

    When I delete the API "${CTX:apiName3}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext3}/v1.0/test1" until status 404

  Scenario: Host rewrite without hostRewrite manual should not work
    Given I generate a unique value from "host-rewrite-4" and store it as "apiName4"
    And I generate a unique API context from "/host-rewrite-4" and store it as "apiContext4"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion            | ${CTX:gatewaySpecVersion}                                      |
      | name                  | ${CTX:apiName4}                                               |
      | spec.displayName      | Host Rewrite No Manual                                       |
      | spec.version          | v1.0                                                          |
      | spec.context          | ${CTX:apiContext4}/$version                                   |
      | spec.upstream.main.url| http://testbench:3002/anything                                |
      | spec.operations       | [{"method":"GET","path":"/test","policies":[{"name":"host-rewrite","version":"v1","params":{"host":"should-not-be-used.com"}}]}] |
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext4}/v1.0/test" until status 200
    When I send a "GET" request to "${CTX:apiContext4}/v1.0/test"
    Then the response status code should be 200
    And the JSON response field "headers.Host" should contain "testbench"

    When I delete the API "${CTX:apiName4}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext4}/v1.0/test" until status 404

  Scenario: Operation-level policy overrides API-level policy
    Given I generate a unique value from "host-rewrite-5" and store it as "apiName5"
    And I generate a unique API context from "/host-rewrite-5" and store it as "apiContext5"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion            | ${CTX:gatewaySpecVersion}                                      |
      | name                  | ${CTX:apiName5}                                               |
      | spec.displayName      | Host Rewrite Override                                         |
      | spec.version          | v1.0                                                          |
      | spec.context          | ${CTX:apiContext5}/$version                                   |
      | spec.upstream.main.url| http://testbench:3002/anything                                |
      | spec.upstream.main.hostRewrite | manual                                    |
      | spec.policies         | [{"name":"host-rewrite","version":"v1","params":{"host":"api-level.example.com"}}] |
      | spec.operations       | [{"method":"GET","path":"/default"},{"method":"GET","path":"/override","policies":[{"name":"host-rewrite","version":"v1","params":{"host":"operation-level.example.com"}}]}] |
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext5}/v1.0/default" until status 200
    When I send a "GET" request to "${CTX:apiContext5}/v1.0/default"
    Then the response status code should be 200
    And the JSON response field "headers.Host" should be "api-level.example.com"
    When I send a "GET" request to "${CTX:apiContext5}/v1.0/override"
    Then the response status code should be 200
    And the JSON response field "headers.Host" should be "operation-level.example.com"

    When I delete the API "${CTX:apiName5}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext5}/v1.0/default" until status 404

  Scenario: Configure different Host Rewrite values for different operations
    Given I generate a unique value from "host-rewrite-6" and store it as "apiName6"
    And I generate a unique API context from "/host-rewrite-6" and store it as "apiContext6"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion            | ${CTX:gatewaySpecVersion}                                      |
      | name                  | ${CTX:apiName6}                                               |
      | spec.displayName      | Host Rewrite Different Operations                             |
      | spec.version          | v1.0                                                          |
      | spec.context          | ${CTX:apiContext6}/$version                                   |
      | spec.upstream.main.url| http://testbench:3002/anything                                |
      | spec.upstream.main.hostRewrite | manual                                    |
      | spec.operations       | [{"method":"GET","path":"/test","policies":[{"name":"host-rewrite","version":"v1","params":{"host":"get.example.com"}}]},{"method":"POST","path":"/test","policies":[{"name":"host-rewrite","version":"v1","params":{"host":"post.example.com"}}]},{"method":"PUT","path":"/test","policies":[{"name":"host-rewrite","version":"v1","params":{"host":"put.example.com"}}]}] |
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext6}/v1.0/test" until status 200
    When I send a "GET" request to "${CTX:apiContext6}/v1.0/test"
    Then the response status code should be 200
    And the JSON response field "headers.Host" should be "get.example.com"
    When I send a "POST" request to "${CTX:apiContext6}/v1.0/test"
    Then the response status code should be 200
    And the JSON response field "headers.Host" should be "post.example.com"
    When I send a "PUT" request to "${CTX:apiContext6}/v1.0/test" with body:
      """
      {"test": "data"}
      """
    Then the response status code should be 200
    And the JSON response field "headers.Host" should be "put.example.com"

    When I delete the API "${CTX:apiName6}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext6}/v1.0/test" until status 404

  Scenario: Send a client request with a different incoming Host header
    Given I generate a unique value from "hr-client-host" and store it as "apiName"
    And I generate a unique API context from "/hr-client-host" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion                     | ${CTX:gatewaySpecVersion} |
      | name                           | ${CTX:apiName} |
      | spec.displayName               | ${CTX:apiName} |
      | spec.version                   | v1.0 |
      | spec.context                   | ${CTX:apiContext}/$version |
      | spec.upstream.main.url         | http://testbench:3002/anything |
      | spec.upstream.main.hostRewrite | manual |
      | spec.operations                | [{"method":"GET","path":"/probe","policies":[{"name":"host-rewrite","version":"v1","params":{"host":"hr-configured-02.example"}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/v1.0/probe" until status 200

    When I set request host to "client-original.example"
    And I send a "GET" request to "${CTX:apiContext}/v1.0/probe"
    Then the response status code should be 200
    And the JSON response field "headers.Host" should be "hr-configured-02.example"

    When I reset the request
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/v1.0/probe" until status 404

  # The upstream is the gateway itself. API B answers only on its own virtual host and forwards to
  # the echo service with the default host rewrite, so the echo reports the Host B received in
  # X-Envoy-Original-Host. Without the policy, the client's Host matches none of B's routes. The
  # wrong host gets the upstream's own 404, so a virtual-host mismatch is passed back as it is.
  Scenario: Configure an upstream that requires a specific virtual-host value and invoke without Host Rewrite, then with Host Rewrite enabled
    Given I generate a unique value from "hr-vhost-b" and store it as "apiNameB"
    And I generate a unique API context from "/hr-vhost-b" and store it as "apiContextB"
    And I generate a unique resource name from "hr-vhost-b" and store it as "vhostB"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiNameB} |
      | spec.displayName       | ${CTX:apiNameB} |
      | spec.version           | v1.0 |
      | spec.context           | ${CTX:apiContextB}/$version |
      | spec.vhosts            | {"main":"${CTX:vhostB}"} |
      | spec.upstream.main.url | http://testbench:3002/anything |
      | spec.operations        | [{"method":"GET","path":"/plain"},{"method":"GET","path":"/rewritten"},{"method":"GET","path":"/wrong"}] |
    Then the resource creation response should indicate successful deployment

    When I set request host to "${CTX:vhostB}"
    And I send a "GET" request to "${CTX:apiContextB}/v1.0/rewritten" until status 200
    And I reset the request
    And I authenticate using basic auth as "admin"
    Given I generate a unique value from "hr-vhost-a" and store it as "apiName"
    And I generate a unique API context from "/hr-vhost-a" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion                     | ${CTX:gatewaySpecVersion} |
      | name                           | ${CTX:apiName} |
      | spec.displayName               | ${CTX:apiName} |
      | spec.version                   | v1.0 |
      | spec.context                   | ${CTX:apiContext}/$version |
      | spec.upstream.main.url         | http://gateway-runtime:8080${CTX:apiContextB}/v1.0 |
      | spec.upstream.main.hostRewrite | manual |
      | spec.operations                | [{"method":"GET","path":"/plain"},{"method":"GET","path":"/rewritten","policies":[{"name":"host-rewrite","version":"v1","params":{"host":"${CTX:vhostB}"}}]},{"method":"GET","path":"/wrong","policies":[{"name":"host-rewrite","version":"v1","params":{"host":"hr-not-a-vhost.example"}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/v1.0/rewritten" until status 200

    When I send a "GET" request to "${CTX:apiContext}/v1.0/plain"
    Then the response status code should be 404

    When I send a "GET" request to "${CTX:apiContext}/v1.0/rewritten"
    Then the response status code should be 200
    And the JSON response field "path" should be "/anything/rewritten"
    And the response should contain echoed header "X-Envoy-Original-Host" with value "${CTX:vhostB}"

    When I send a "GET" request to "${CTX:apiContext}/v1.0/wrong"
    Then the response status code should be 404

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/v1.0/rewritten" until status 404

    When I delete the API "${CTX:apiNameB}"
    Then the response should be successful
    When I set request host to "${CTX:vhostB}"
    And I send a "GET" request to "${CTX:apiContextB}/v1.0/rewritten" until status 404
    And I reset the request

  # The gateway speaks HTTP/1.1 to the upstream, so the echo reports the rewritten value as Host.
  Scenario: Verify Host Rewrite over HTTP/2
    Given I generate a unique value from "hr-h2" and store it as "apiName"
    And I generate a unique API context from "/hr-h2" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion                     | ${CTX:gatewaySpecVersion} |
      | name                           | ${CTX:apiName} |
      | spec.displayName               | ${CTX:apiName} |
      | spec.version                   | v1.0 |
      | spec.context                   | ${CTX:apiContext}/$version |
      | spec.upstream.main.url         | http://testbench:3002/anything |
      | spec.upstream.main.hostRewrite | manual |
      | spec.operations                | [{"method":"GET","path":"/probe","policies":[{"name":"host-rewrite","version":"v1","params":{"host":"hr-h2.example"}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/v1.0/probe" until status 200

    When I send a "GET" request to "${CTX:apiContext}/v1.0/probe" over HTTP/2
    Then the response status code should be 200
    And the JSON response field "headers.Host" should be "hr-h2.example"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/v1.0/probe" until status 404

  # With hostRewrite manual and no policy on an operation, the upstream gets the client's Host.
  Scenario: Configure Host Rewrite only on one operation and invoke protected and unprotected operations
    Given I generate a unique value from "hr-op-only" and store it as "apiName"
    And I generate a unique API context from "/hr-op-only" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion                     | ${CTX:gatewaySpecVersion} |
      | name                           | ${CTX:apiName} |
      | spec.displayName               | ${CTX:apiName} |
      | spec.version                   | v1.0 |
      | spec.context                   | ${CTX:apiContext}/$version |
      | spec.upstream.main.url         | http://testbench:3002/anything |
      | spec.upstream.main.hostRewrite | manual |
      | spec.operations                | [{"method":"GET","path":"/with","policies":[{"name":"host-rewrite","version":"v1","params":{"host":"hr-op-only-07.example"}}]},{"method":"GET","path":"/without"}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/v1.0/with" until status 200

    When I set request host to "client-07.example"
    And I send a "GET" request to "${CTX:apiContext}/v1.0/with"
    Then the response status code should be 200
    And the JSON response field "headers.Host" should be "hr-op-only-07.example"

    When I send a "GET" request to "${CTX:apiContext}/v1.0/without"
    Then the response status code should be 200
    And the JSON response field "headers.Host" should be "client-07.example"

    When I reset the request
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/v1.0/with" until status 404

  Scenario: Change the rewrite host on an already deployed API
    Given I generate a unique value from "hr-change" and store it as "apiName"
    And I generate a unique API context from "/hr-change" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion                     | ${CTX:gatewaySpecVersion} |
      | name                           | ${CTX:apiName} |
      | spec.displayName               | ${CTX:apiName} |
      | spec.version                   | v1.0 |
      | spec.context                   | ${CTX:apiContext}/$version |
      | spec.upstream.main.url         | http://testbench:3002/anything |
      | spec.upstream.main.hostRewrite | manual |
      | spec.operations                | [{"method":"POST","path":"/echo","policies":[{"name":"host-rewrite","version":"v1","params":{"host":"hr-before-13.example"}}]}] |
    Then the resource creation response should indicate successful deployment

    When I send a "POST" request to "${CTX:apiContext}/v1.0/echo" until the response body contains "hr-before-13.example" with body:
      """
      {}
      """
    Then the JSON response field "headers.Host" should be "hr-before-13.example"

    When I update API "${CTX:apiName}" from "resources/templates/rest-api.yaml" with values:
      | apiVersion                     | ${CTX:gatewaySpecVersion} |
      | name                           | ${CTX:apiName} |
      | spec.displayName               | ${CTX:apiName} |
      | spec.version                   | v1.0 |
      | spec.context                   | ${CTX:apiContext}/$version |
      | spec.upstream.main.url         | http://testbench:3002/anything |
      | spec.upstream.main.hostRewrite | manual |
      | spec.operations                | [{"method":"POST","path":"/echo","policies":[{"name":"host-rewrite","version":"v1","params":{"host":"hr-after-13.example"}}]}] |
    Then the API update response should indicate successful deployment

    When I send a "POST" request to "${CTX:apiContext}/v1.0/echo" until the response body contains "hr-after-13.example" with body:
      """
      {}
      """
    And I send a "POST" request to "${CTX:apiContext}/v1.0/echo" with body:
      """
      {}
      """
    Then the response status code should be 200
    And the JSON response field "headers.Host" should be "hr-after-13.example"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "POST" request to "${CTX:apiContext}/v1.0/echo" until status 404

  # With hostRewrite manual and no policy, the upstream gets the client's Host.
  Scenario: Add and remove Host Rewrite from a deployed API
    Given I generate a unique value from "hr-add-remove" and store it as "apiName"
    And I generate a unique API context from "/hr-add-remove" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion                     | ${CTX:gatewaySpecVersion} |
      | name                           | ${CTX:apiName} |
      | spec.displayName               | ${CTX:apiName} |
      | spec.version                   | v1.0 |
      | spec.context                   | ${CTX:apiContext}/$version |
      | spec.upstream.main.url         | http://testbench:3002/anything |
      | spec.upstream.main.hostRewrite | manual |
      | spec.operations                | [{"method":"POST","path":"/echo"}] |
    Then the resource creation response should indicate successful deployment

    When I set request host to "client-14.example"
    And I send a "POST" request to "${CTX:apiContext}/v1.0/echo" until the response body contains "client-14.example" with body:
      """
      {}
      """
    Then the JSON response field "headers.Host" should be "client-14.example"

    When I update API "${CTX:apiName}" from "resources/templates/rest-api.yaml" with values:
      | apiVersion                     | ${CTX:gatewaySpecVersion} |
      | name                           | ${CTX:apiName} |
      | spec.displayName               | ${CTX:apiName} |
      | spec.version                   | v1.0 |
      | spec.context                   | ${CTX:apiContext}/$version |
      | spec.upstream.main.url         | http://testbench:3002/anything |
      | spec.upstream.main.hostRewrite | manual |
      | spec.operations                | [{"method":"POST","path":"/echo","policies":[{"name":"host-rewrite","version":"v1","params":{"host":"hr-added-14.example"}}]}] |
    Then the API update response should indicate successful deployment

    When I send a "POST" request to "${CTX:apiContext}/v1.0/echo" until the response body contains "hr-added-14.example" with body:
      """
      {}
      """
    Then the JSON response field "headers.Host" should be "hr-added-14.example"

    When I update API "${CTX:apiName}" from "resources/templates/rest-api.yaml" with values:
      | apiVersion                     | ${CTX:gatewaySpecVersion} |
      | name                           | ${CTX:apiName} |
      | spec.displayName               | ${CTX:apiName} |
      | spec.version                   | v1.0 |
      | spec.context                   | ${CTX:apiContext}/$version |
      | spec.upstream.main.url         | http://testbench:3002/anything |
      | spec.upstream.main.hostRewrite | manual |
      | spec.operations                | [{"method":"POST","path":"/echo"}] |
    Then the API update response should indicate successful deployment

    When I send a "POST" request to "${CTX:apiContext}/v1.0/echo" until the response body contains "client-14.example" with body:
      """
      {}
      """
    Then the JSON response field "headers.Host" should be "client-14.example"

    When I reset the request
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "POST" request to "${CTX:apiContext}/v1.0/echo" until status 404

  # Gateway 1.1.0 sends the request to the selected upstream without its base path, so the
  # dynamic endpoint scenarios run on 1.2.0 and later.
  Scenario: Combine Host Rewrite with Dynamic Endpoint
    Given the gateway version satisfies ">=1.2.0"
    And I generate a unique value from "hr-dyn" and store it as "apiName"
    And I generate a unique API context from "/hr-dyn" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion                     | ${CTX:gatewaySpecVersion} |
      | name                           | ${CTX:apiName} |
      | spec.displayName               | ${CTX:apiName} |
      | spec.version                   | v1.0 |
      | spec.context                   | ${CTX:apiContext}/$version |
      | spec.upstream.main.url         | http://testbench:3002/anything/main |
      | spec.upstream.main.hostRewrite | manual |
      | spec.upstreamDefinitions       | [{"name":"alt-upstream","basePath":"/anything/alt","upstreams":[{"url":"http://testbench:3002"}]}] |
      | spec.operations                | [{"method":"GET","path":"/probe","policies":[{"name":"dynamic-endpoint","version":"v1","params":{"targetUpstream":"alt-upstream"}},{"name":"host-rewrite","version":"v1","params":{"host":"hr-dyn-17.example"}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/v1.0/probe" until status 200

    When I send a "GET" request to "${CTX:apiContext}/v1.0/probe"
    Then the response status code should be 200
    And the JSON response field "path" should be "/anything/alt/probe"
    And the JSON response field "headers.Host" should be "hr-dyn-17.example"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/v1.0/probe" until status 404

  # The gateway sets the upstream-selection header itself and removes it before the upstream, so
  # a client's value neither picks the upstream nor reaches it.
  Scenario: Combine Host Rewrite with Dynamic Endpoint and attempt to manipulate both using client headers
    Given the gateway version satisfies ">=1.2.0"
    And I generate a unique value from "hr-dyn-spoof" and store it as "apiName"
    And I generate a unique API context from "/hr-dyn-spoof" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion                     | ${CTX:gatewaySpecVersion} |
      | name                           | ${CTX:apiName} |
      | spec.displayName               | ${CTX:apiName} |
      | spec.version                   | v1.0 |
      | spec.context                   | ${CTX:apiContext}/$version |
      | spec.upstream.main.url         | http://testbench:3002/anything/main |
      | spec.upstream.main.hostRewrite | manual |
      | spec.upstreamDefinitions       | [{"name":"alt-upstream","basePath":"/anything/alt","upstreams":[{"url":"http://testbench:3002"}]}] |
      | spec.operations                | [{"method":"GET","path":"/probe","policies":[{"name":"dynamic-endpoint","version":"v1","params":{"targetUpstream":"alt-upstream"}},{"name":"host-rewrite","version":"v1","params":{"host":"hr-dyn-31.example"}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/v1.0/probe" until status 200

    When I set request host to "attacker-31.example"
    And I set header "x-target-upstream" to "attacker-cluster"
    And I set header "X-Forwarded-Host" to "attacker-31.example"
    And I send a "GET" request to "${CTX:apiContext}/v1.0/probe"
    Then the response status code should be 200
    And the JSON response field "path" should be "/anything/alt/probe"
    And the JSON response field "headers.Host" should be "hr-dyn-31.example"
    And the response should not contain echoed header "x-target-upstream"

    When I reset the request
    And I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/v1.0/probe" until status 404

  Scenario: Combine Host Rewrite with Request Rewrite
    Given I generate a unique value from "hr-req-rewrite" and store it as "apiName"
    And I generate a unique API context from "/hr-req-rewrite" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion                     | ${CTX:gatewaySpecVersion} |
      | name                           | ${CTX:apiName} |
      | spec.displayName               | ${CTX:apiName} |
      | spec.version                   | v1.0 |
      | spec.context                   | ${CTX:apiContext}/$version |
      | spec.upstream.main.url         | http://testbench:3002/anything |
      | spec.upstream.main.hostRewrite | manual |
      | spec.operations                | [{"method":"GET","path":"/api/v1","policies":[{"name":"request-rewrite","version":"v1","params":{"pathRewrite":{"type":"ReplacePrefixMatch","replacePrefixMatch":"/api/v2"},"methodRewrite":"POST","queryRewrite":{"rules":[{"action":"Remove","name":"debug"}]}}},{"name":"host-rewrite","version":"v1","params":{"host":"hr-rr-18.example"}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/v1.0/api/v1" until status 200

    When I send a "GET" request to "${CTX:apiContext}/v1.0/api/v1?keep=1&debug=x"
    Then the response status code should be 200
    And the JSON response field "method" should be "POST"
    And the JSON response field "path" should be "/anything/api/v2"
    And the JSON response field "args.keep" should be "1"
    And the JSON response field "args.debug" should not exist
    And the JSON response field "headers.Host" should be "hr-rr-18.example"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/v1.0/api/v1" until status 404

  # The limit is three requests an hour for the route. Requests without a key are rejected by
  # authentication before the limiter counts them, so the wait for deployment spends none.
  Scenario: Combine Host Rewrite with authentication and rate-limiting policies
    Given I generate a unique value from "hr-sec" and store it as "apiName"
    And I generate a unique API context from "/hr-sec" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion                     | ${CTX:gatewaySpecVersion} |
      | name                           | ${CTX:apiName} |
      | spec.displayName               | ${CTX:apiName} |
      | spec.version                   | v1.0 |
      | spec.context                   | ${CTX:apiContext}/$version |
      | spec.upstream.main.url         | http://testbench:3002/anything |
      | spec.upstream.main.hostRewrite | manual |
      | spec.operations                | [{"method":"GET","path":"/probe","policies":[{"name":"api-key-auth","version":"v1","params":{"key":"API-Key","in":"header"}},{"name":"basic-ratelimit","version":"v1","params":{"limits":[{"requests":3,"duration":"1h"}]}},{"name":"host-rewrite","version":"v1","params":{"host":"hr-sec-19.example"}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/v1.0/probe" until status 401

    When I send a "POST" request to the "gateway-controller" service at "/rest-apis/${CTX:apiName}/api-keys" with body:
      """
      {"name":"hr-key"}
      """
    Then the response status should be 201
    And I store the JSON response field "apiKey.apiKey" as "apiKey"

    When I set header "API-Key" to "${CTX:apiKey}"
    And I send a "GET" request to "${CTX:apiContext}/v1.0/probe" until status 200
    And I send a "GET" request to "${CTX:apiContext}/v1.0/probe"
    Then the response status code should be 200
    And the JSON response field "headers.Host" should be "hr-sec-19.example"

    When I send a "GET" request to "${CTX:apiContext}/v1.0/probe"
    Then the response status code should be 200
    And the JSON response field "headers.Host" should be "hr-sec-19.example"

    When I send a "GET" request to "${CTX:apiContext}/v1.0/probe"
    Then the response status code should be 429

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I send a "GET" request to "${CTX:apiContext}/v1.0/probe"
    Then the response status code should be 401

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/v1.0/probe" until status 404

  Scenario: Verify request headers, body, method, and path apart from Host / :authority
    Given I generate a unique value from "hr-intact" and store it as "apiName"
    And I generate a unique API context from "/hr-intact" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion                     | ${CTX:gatewaySpecVersion} |
      | name                           | ${CTX:apiName} |
      | spec.displayName               | ${CTX:apiName} |
      | spec.version                   | v1.0 |
      | spec.context                   | ${CTX:apiContext}/$version |
      | spec.upstream.main.url         | http://testbench:3002/anything |
      | spec.upstream.main.hostRewrite | manual |
      | spec.operations                | [{"method":"POST","path":"/items","policies":[{"name":"host-rewrite","version":"v1","params":{"host":"hr-intact-20.example"}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "POST" request to "${CTX:apiContext}/v1.0/items" until status 200

    When I set header "X-Hr-Custom" to "marker-20"
    And I send a "POST" request to "${CTX:apiContext}/v1.0/items?q=1" with body:
      """
      {"item":"marker-20"}
      """
    Then the response status code should be 200
    And the JSON response field "method" should be "POST"
    And the JSON response field "path" should be "/anything/items"
    And the JSON response field "args.q" should be "1"
    And the response should contain echoed header "X-Hr-Custom" with value "marker-20"
    And the JSON response field "json.item" should be "marker-20"
    And the JSON response field "headers.Host" should be "hr-intact-20.example"

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "POST" request to "${CTX:apiContext}/v1.0/items" until status 404

  # The echo service answers with the status named in the statusCode query parameter.
  Scenario: Verify the backend response after Host Rewrite
    Given I generate a unique value from "hr-response" and store it as "apiName"
    And I generate a unique API context from "/hr-response" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion                     | ${CTX:gatewaySpecVersion} |
      | name                           | ${CTX:apiName} |
      | spec.displayName               | ${CTX:apiName} |
      | spec.version                   | v1.0 |
      | spec.context                   | ${CTX:apiContext}/$version |
      | spec.upstream.main.url         | http://testbench:3002/anything |
      | spec.upstream.main.hostRewrite | manual |
      | spec.operations                | [{"method":"GET","path":"/status-probe","policies":[{"name":"host-rewrite","version":"v1","params":{"host":"hr-resp-21.example"}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/v1.0/status-probe" until status 200

    When I send a "GET" request to "${CTX:apiContext}/v1.0/status-probe?statusCode=201"
    Then the response status code should be 201
    And the response header "Content-Type" should contain "application/json"
    And the JSON response field "path" should be "/anything/status-probe"
    And the JSON response field "headers.Host" should be "hr-resp-21.example"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/v1.0/status-probe" until status 404

  # Nothing listens on the upstream's port.
  Scenario: Make the target upstream unavailable while Host Rewrite is enabled
    Given I generate a unique value from "hr-down" and store it as "apiName"
    And I generate a unique API context from "/hr-down" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion                     | ${CTX:gatewaySpecVersion} |
      | name                           | ${CTX:apiName} |
      | spec.displayName               | ${CTX:apiName} |
      | spec.version                   | v1.0 |
      | spec.context                   | ${CTX:apiContext}/$version |
      | spec.upstream.main.url         | http://testbench:3999 |
      | spec.upstream.main.hostRewrite | manual |
      | spec.operations                | [{"method":"GET","path":"/probe","policies":[{"name":"host-rewrite","version":"v1","params":{"host":"hr-down-22.example"}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/v1.0/probe" until status 503

    When I send a "GET" request to "${CTX:apiContext}/v1.0/probe"
    Then the response status code should be 503
    And the response body should contain "upstream connect error or disconnect/reset before headers. reset reason: remote connection failure"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/v1.0/probe" until status 404

  # Two operations with different hosts take requests at the same time; each response must carry
  # its own operation's host.
  Scenario: Run concurrent/high-volume requests with Host Rewrite enabled
    Given I generate a unique value from "hr-concurrent" and store it as "apiName"
    And I generate a unique API context from "/hr-concurrent" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion                     | ${CTX:gatewaySpecVersion} |
      | name                           | ${CTX:apiName} |
      | spec.displayName               | ${CTX:apiName} |
      | spec.version                   | v1.0 |
      | spec.context                   | ${CTX:apiContext}/$version |
      | spec.upstream.main.url         | http://testbench:3002/anything |
      | spec.upstream.main.hostRewrite | manual |
      | spec.operations                | [{"method":"GET","path":"/a","policies":[{"name":"host-rewrite","version":"v1","params":{"host":"hr-conc-a.example"}}]},{"method":"GET","path":"/b","policies":[{"name":"host-rewrite","version":"v1","params":{"host":"hr-conc-b.example"}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/v1.0/a" until status 200
    And I send a "GET" request to "${CTX:apiContext}/v1.0/b" until status 200

    When I send 200 concurrent "GET" requests alternating between these paths, each echoing the JSON field "headers.Host":
      | ${CTX:apiContext}/v1.0/a | hr-conc-a.example |
      | ${CTX:apiContext}/v1.0/b | hr-conc-b.example |

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/v1.0/a" until status 404

  Scenario Outline: Send a malicious client Host header attempting to override the configured rewrite host (<case>)
    Given I generate a unique value from "hr-malicious" and store it as "apiName"
    And I generate a unique API context from "/hr-malicious" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion                     | ${CTX:gatewaySpecVersion} |
      | name                           | ${CTX:apiName} |
      | spec.displayName               | ${CTX:apiName} |
      | spec.version                   | v1.0 |
      | spec.context                   | ${CTX:apiContext}/$version |
      | spec.upstream.main.url         | http://testbench:3002/anything |
      | spec.upstream.main.hostRewrite | manual |
      | spec.operations                | [{"method":"GET","path":"/probe","policies":[{"name":"host-rewrite","version":"v1","params":{"host":"hr-configured-24.example"}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/v1.0/probe" until status 200

    When I set request host to "<clientHost>"
    And I send a "GET" request to "${CTX:apiContext}/v1.0/probe"
    Then the response status code should be 200
    And the JSON response field "headers.Host" should be "hr-configured-24.example"

    When I reset the request
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/v1.0/probe" until status 404

    Examples:
      | case                | clientHost       |
      | loopback            | 127.0.0.1        |
      | Envoy admin address | localhost:9901   |
      | cloud metadata      | 169.254.169.254  |
      | attacker domain     | attacker.example |

  Scenario: Send a spoofed HTTP/2 :authority value
    Given I generate a unique value from "hr-h2-spoof" and store it as "apiName"
    And I generate a unique API context from "/hr-h2-spoof" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion                     | ${CTX:gatewaySpecVersion} |
      | name                           | ${CTX:apiName} |
      | spec.displayName               | ${CTX:apiName} |
      | spec.version                   | v1.0 |
      | spec.context                   | ${CTX:apiContext}/$version |
      | spec.upstream.main.url         | http://testbench:3002/anything |
      | spec.upstream.main.hostRewrite | manual |
      | spec.operations                | [{"method":"GET","path":"/probe","policies":[{"name":"host-rewrite","version":"v1","params":{"host":"hr-h2-25.example"}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/v1.0/probe" until status 200

    When I set request host to "attacker-25.example"
    And I send a "GET" request to "${CTX:apiContext}/v1.0/probe" over HTTP/2
    Then the response status code should be 200
    And the JSON response field "headers.Host" should be "hr-h2-25.example"

    When I reset the request
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/v1.0/probe" until status 404

  # The gateway passes these headers to the upstream unchanged; none of them sets the Host.
  Scenario: Send headers such as X-Forwarded-Host, Forwarded, or X-Original-Host attempting to influence upstream host selection
    Given I generate a unique value from "hr-forwarded" and store it as "apiName"
    And I generate a unique API context from "/hr-forwarded" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion                     | ${CTX:gatewaySpecVersion} |
      | name                           | ${CTX:apiName} |
      | spec.displayName               | ${CTX:apiName} |
      | spec.version                   | v1.0 |
      | spec.context                   | ${CTX:apiContext}/$version |
      | spec.upstream.main.url         | http://testbench:3002/anything |
      | spec.upstream.main.hostRewrite | manual |
      | spec.operations                | [{"method":"GET","path":"/probe","policies":[{"name":"host-rewrite","version":"v1","params":{"host":"hr-configured-26.example"}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/v1.0/probe" until status 200

    When I set header "X-Forwarded-Host" to "evil-26.example"
    And I set header "Forwarded" to "host=evil-26.example"
    And I set header "X-Original-Host" to "evil-26.example"
    And I send a "GET" request to "${CTX:apiContext}/v1.0/probe"
    Then the response status code should be 200
    And the JSON response field "path" should be "/anything/probe"
    And the JSON response field "headers.Host" should be "hr-configured-26.example"
    And the response should contain echoed header "X-Forwarded-Host" with value "evil-26.example"
    And the response should contain echoed header "Forwarded" with value "host=evil-26.example"
    And the response should contain echoed header "X-Original-Host" with value "evil-26.example"

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/v1.0/probe" until status 404

  # The gateway reads a bare LF, or a CR LF pair, as the end of a header line, so what follows
  # arrives as a header of its own; a bare CR is dropped from the value. The upstream Host stays
  # the configured one in every case.
  Scenario Outline: Attempt CRLF/header-injection characters in incoming host-related headers (<case>)
    Given I generate a unique value from "hr-crlf" and store it as "apiName"
    And I generate a unique API context from "/hr-crlf" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion                     | ${CTX:gatewaySpecVersion} |
      | name                           | ${CTX:apiName} |
      | spec.displayName               | ${CTX:apiName} |
      | spec.version                   | v1.0 |
      | spec.context                   | ${CTX:apiContext}/$version |
      | spec.upstream.main.url         | http://testbench:3002/anything |
      | spec.upstream.main.hostRewrite | manual |
      | spec.operations                | [{"method":"GET","path":"/probe","policies":[{"name":"host-rewrite","version":"v1","params":{"host":"hr-configured-28.example"}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/v1.0/probe" until status 200

    When I send a raw "GET" request to "${CTX:apiContext}/v1.0/probe" with headers:
      | <name> | <value> |
    Then the response status code should be 200
    And the JSON response field "headers.Host" should be "hr-configured-28.example"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/v1.0/probe" until status 404

    Examples:
      | case                       | name             | value                            |
      | CRLF adding another header | X-Original-Host  | evil.example\r\nX-Injected: crlf |
      | bare CR                    | X-Forwarded-Host | a.example\rX-Injected: cr        |
      | bare LF                    | X-Original-Host  | a.example\nX-Injected: lf        |

  Scenario: Attempt to provide an internal hostname, localhost, metadata endpoint, or attacker-controlled hostname through query parameters, headers, or request body
    Given I generate a unique value from "hr-request-data" and store it as "apiName"
    And I generate a unique API context from "/hr-request-data" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion                     | ${CTX:gatewaySpecVersion} |
      | name                           | ${CTX:apiName} |
      | spec.displayName               | ${CTX:apiName} |
      | spec.version                   | v1.0 |
      | spec.context                   | ${CTX:apiContext}/$version |
      | spec.upstream.main.url         | http://testbench:3002/anything |
      | spec.upstream.main.hostRewrite | manual |
      | spec.operations                | [{"method":"POST","path":"/probe","policies":[{"name":"host-rewrite","version":"v1","params":{"host":"hr-configured-29.example"}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "POST" request to "${CTX:apiContext}/v1.0/probe" until status 200

    When I set header "X-Host" to "metadata.google.internal"
    And I send a "POST" request to "${CTX:apiContext}/v1.0/probe?host=169.254.169.254&target=localhost" with body:
      """
      {"host":"attacker.example"}
      """
    Then the response status code should be 200
    And the JSON response field "path" should be "/anything/probe"
    And the JSON response field "headers.Host" should be "hr-configured-29.example"

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "POST" request to "${CTX:apiContext}/v1.0/probe" until status 404

  # The rewrite host is only the Host header: the request still goes to the configured upstream,
  # and API key authentication in front of the policy still decides who gets through.
  Scenario: Configure a sensitive internal hostname deliberately as the rewrite value and invoke externally
    Given I generate a unique value from "hr-internal" and store it as "apiName"
    And I generate a unique API context from "/hr-internal" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion                     | ${CTX:gatewaySpecVersion} |
      | name                           | ${CTX:apiName} |
      | spec.displayName               | ${CTX:apiName} |
      | spec.version                   | v1.0 |
      | spec.context                   | ${CTX:apiContext}/$version |
      | spec.upstream.main.url         | http://testbench:3002/anything |
      | spec.upstream.main.hostRewrite | manual |
      | spec.operations                | [{"method":"GET","path":"/probe","policies":[{"name":"api-key-auth","version":"v1","params":{"key":"API-Key","in":"header"}},{"name":"host-rewrite","version":"v1","params":{"host":"localhost"}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/v1.0/probe" until status 401

    When I set request host to "metadata.google.internal"
    And I send a "GET" request to "${CTX:apiContext}/v1.0/probe"
    Then the response status code should be 401

    When I send a "POST" request to the "gateway-controller" service at "/rest-apis/${CTX:apiName}/api-keys" with body:
      """
      {"name":"hr-key"}
      """
    Then the response status should be 201
    And I store the JSON response field "apiKey.apiKey" as "apiKey"

    When I set header "API-Key" to "${CTX:apiKey}"
    And I send a "GET" request to "${CTX:apiContext}/v1.0/probe" until status 200
    Then the JSON response field "path" should be "/anything/probe"
    And the JSON response field "headers.Host" should be "localhost"

    When I reset the request
    And I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/v1.0/probe" until status 404

  Scenario: Apply authentication before Host Rewrite and invoke with invalid credentials
    Given I generate a unique value from "hr-auth" and store it as "apiName"
    And I generate a unique API context from "/hr-auth" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion                     | ${CTX:gatewaySpecVersion} |
      | name                           | ${CTX:apiName} |
      | spec.displayName               | ${CTX:apiName} |
      | spec.version                   | v1.0 |
      | spec.context                   | ${CTX:apiContext}/$version |
      | spec.upstream.main.url         | http://testbench:3002/anything |
      | spec.upstream.main.hostRewrite | manual |
      | spec.operations                | [{"method":"GET","path":"/probe","policies":[{"name":"api-key-auth","version":"v1","params":{"key":"API-Key","in":"header"}},{"name":"host-rewrite","version":"v1","params":{"host":"hr-auth-32.example"}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/v1.0/probe" until status 401

    When I set header "API-Key" to "not-a-valid-key"
    And I send a "GET" request to "${CTX:apiContext}/v1.0/probe"
    Then the response status code should be 401

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I send a "GET" request to "${CTX:apiContext}/v1.0/probe"
    Then the response status code should be 401

    When I send a "POST" request to the "gateway-controller" service at "/rest-apis/${CTX:apiName}/api-keys" with body:
      """
      {"name":"hr-key"}
      """
    Then the response status should be 201
    And I store the JSON response field "apiKey.apiKey" as "apiKey"

    When I set header "API-Key" to "${CTX:apiKey}"
    And I send a "GET" request to "${CTX:apiContext}/v1.0/probe" until status 200
    Then the JSON response field "headers.Host" should be "hr-auth-32.example"

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/v1.0/probe" until status 404

  # The limit is three requests an hour for the route, whatever Host the client sends. Requests
  # without a key are rejected before the limiter counts them.
  Scenario: Apply authorization/rate limiting before Host Rewrite and attempt host-header manipulation
    Given I generate a unique value from "hr-sec-spoof" and store it as "apiName"
    And I generate a unique API context from "/hr-sec-spoof" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion                     | ${CTX:gatewaySpecVersion} |
      | name                           | ${CTX:apiName} |
      | spec.displayName               | ${CTX:apiName} |
      | spec.version                   | v1.0 |
      | spec.context                   | ${CTX:apiContext}/$version |
      | spec.upstream.main.url         | http://testbench:3002/anything |
      | spec.upstream.main.hostRewrite | manual |
      | spec.operations                | [{"method":"GET","path":"/probe","policies":[{"name":"api-key-auth","version":"v1","params":{"key":"API-Key","in":"header"}},{"name":"basic-ratelimit","version":"v1","params":{"limits":[{"requests":3,"duration":"1h"}]}},{"name":"host-rewrite","version":"v1","params":{"host":"hr-sec-33.example"}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/v1.0/probe" until status 401

    When I set request host to "spoof-33a.example"
    And I set header "API-Key" to "not-a-valid-key"
    And I send a "GET" request to "${CTX:apiContext}/v1.0/probe"
    Then the response status code should be 401

    When I reset the request
    And I clear all headers
    And I authenticate using basic auth as "admin"
    And I send a "POST" request to the "gateway-controller" service at "/rest-apis/${CTX:apiName}/api-keys" with body:
      """
      {"name":"hr-key"}
      """
    Then the response status should be 201
    And I store the JSON response field "apiKey.apiKey" as "apiKey"

    When I set header "API-Key" to "${CTX:apiKey}"
    And I send a "GET" request to "${CTX:apiContext}/v1.0/probe" until status 200
    And I set request host to "spoof-33b.example"
    And I set header "X-Forwarded-Host" to "spoof-33b.example"
    And I send a "GET" request to "${CTX:apiContext}/v1.0/probe"
    Then the response status code should be 200
    And the JSON response field "headers.Host" should be "hr-sec-33.example"

    When I set request host to "spoof-33c.example"
    And I send a "GET" request to "${CTX:apiContext}/v1.0/probe"
    Then the response status code should be 200
    And the JSON response field "headers.Host" should be "hr-sec-33.example"

    When I set request host to "spoof-33d.example"
    And I send a "GET" request to "${CTX:apiContext}/v1.0/probe"
    Then the response status code should be 429

    When I reset the request
    And I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/v1.0/probe" until status 404

  # The gateway checks an HTTPS upstream's certificate against the upstream URL's host name. The
  # test CA that signs the TLS backend's certificates is trusted first: port 8446 presents a
  # certificate for tls-backend, port 8445 one that is valid only for not-this-host.test.
  Scenario: Verify TLS upstream behavior when rewritten host differs from backend DNS name
    Given I generate a unique value from "hr-tls-ca" and store it as "caName"
    When I upload the certificate fixture "backend-ca" as "${CTX:caName}"
    Then the response status should be 201

    Given I generate a unique value from "hr-tls" and store it as "apiName"
    And I generate a unique API context from "/hr-tls" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion                     | ${CTX:gatewaySpecVersion} |
      | name                           | ${CTX:apiName} |
      | spec.displayName               | ${CTX:apiName} |
      | spec.version                   | v1.0 |
      | spec.context                   | ${CTX:apiContext}/$version |
      | spec.upstream.main.url         | https://tls-backend:8446 |
      | spec.upstream.main.hostRewrite | manual |
      | spec.operations                | [{"method":"GET","path":"/tls-rewrite-34","policies":[{"name":"host-rewrite","version":"v1","params":{"host":"not-this-host.test"}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/v1.0/tls-rewrite-34" until status 200
    Then the JSON response field "backend" should be "optional"
    And the "gateway-runtime" service log event containing "/tls-rewrite-34" should contain "not-this-host.test"

    Given I generate a unique value from "hr-tls-wronghost" and store it as "apiNameW"
    And I generate a unique API context from "/hr-tls-wronghost" and store it as "apiContextW"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion                     | ${CTX:gatewaySpecVersion} |
      | name                           | ${CTX:apiNameW} |
      | spec.displayName               | ${CTX:apiNameW} |
      | spec.version                   | v1.0 |
      | spec.context                   | ${CTX:apiContextW}/$version |
      | spec.upstream.main.url         | https://tls-backend:8445 |
      | spec.upstream.main.hostRewrite | manual |
      | spec.operations                | [{"method":"GET","path":"/tls-wronghost-34","policies":[{"name":"host-rewrite","version":"v1","params":{"host":"not-this-host.test"}}]}] |
    Then the resource creation response should indicate successful deployment
    # The backend on port 8445 is listening (the suite waits for it) and shares the container
    # that answered on 8446, so this 503 comes from the certificate check, not a refused connection.
    And I send a "GET" request to "${CTX:apiContextW}/v1.0/tls-wronghost-34" until status 503
    Then the response body should contain "upstream connect error"

    When I delete the API "${CTX:apiNameW}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContextW}/v1.0/tls-wronghost-34" until status 404
    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/v1.0/tls-rewrite-34" until status 404
    And I delete the certificate named "${CTX:caName}"

  # The policy logs each rewrite as from=[<client host>] to=<configured host>. Log steps do not
  # expand stored values, so the hosts here are fixed markers.
  Scenario: Inspect gateway logs/analytics for incoming and rewritten host values (gateway log)
    Given I generate a unique value from "hr-log" and store it as "apiName"
    And I generate a unique API context from "/hr-log" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion                     | ${CTX:gatewaySpecVersion} |
      | name                           | ${CTX:apiName} |
      | spec.displayName               | ${CTX:apiName} |
      | spec.version                   | v1.0 |
      | spec.context                   | ${CTX:apiContext}/$version |
      | spec.upstream.main.url         | http://testbench:3002/anything |
      | spec.upstream.main.hostRewrite | manual |
      | spec.operations                | [{"method":"GET","path":"/probe","policies":[{"name":"host-rewrite","version":"v1","params":{"host":"hr-log-to-36.example"}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/v1.0/probe" until status 200

    When I set request host to "hr-log-from-36.example"
    And I send a "GET" request to "${CTX:apiContext}/v1.0/probe"
    Then the response status code should be 200
    And the "gateway-runtime" service log event containing "from=[hr-log-from-36.example]" should contain "to=hr-log-to-36.example"
    And the "gateway-runtime" service log event containing "from=[hr-log-from-36.example]" should not contain "Basic "

    When I reset the request
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/v1.0/probe" until status 404

  # Analytics records the request as the client sent it. Gateway 1.1.0 publishes request headers
  # only when analytics-header-filter is attached, so this runs on 1.2.0 and later.
  Scenario: Inspect gateway logs/analytics for incoming and rewritten host values (analytics event)
    Given the gateway version satisfies ">=1.2.0"
    And I generate a unique value from "hr-analytics" and store it as "apiName"
    And I generate a unique API context from "/hr-analytics" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion                     | ${CTX:gatewaySpecVersion} |
      | name                           | ${CTX:apiName} |
      | spec.displayName               | ${CTX:apiName} |
      | spec.version                   | v1.0 |
      | spec.context                   | ${CTX:apiContext}/$version |
      | spec.upstream.main.url         | http://testbench:3002/anything |
      | spec.upstream.main.hostRewrite | manual |
      | spec.operations                | [{"method":"GET","path":"/probe","policies":[{"name":"host-rewrite","version":"v1","params":{"host":"hr-analytics-36.example"}}]}] |
    Then the resource creation response should indicate successful deployment

    When I clear all headers
    And I set request host to "hr-analytics-from-36.example"
    And I send a "GET" request to "${CTX:apiContext}/v1.0/probe" until status 200
    Then the JSON response field "headers.Host" should be "hr-analytics-36.example"
    And the latest analytics event for path "${CTX:apiContext}/v1.0/probe" should contain request header ":authority" with value "hr-analytics-from-36.example"

    When I reset the request
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/v1.0/probe" until status 404

  # Requests run every 100 ms in the background while the host changes twice, back to back.
  # Each must get one of the configured hosts, never the client's, and the last one wins. The
  # traffic is kept running until it has itself received the first and the last host, and at
  # least one request must be answered while the last update rolls out.
  Scenario: Rapidly update the Host Rewrite value while traffic is active
    Given I generate a unique value from "hr-rapid" and store it as "apiName"
    And I generate a unique API context from "/hr-rapid" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion                     | ${CTX:gatewaySpecVersion} |
      | name                           | ${CTX:apiName} |
      | spec.displayName               | ${CTX:apiName} |
      | spec.version                   | v1.0 |
      | spec.context                   | ${CTX:apiContext}/$version |
      | spec.upstream.main.url         | http://testbench:3002/anything |
      | spec.upstream.main.hostRewrite | manual |
      | spec.operations                | [{"method":"POST","path":"/probe","policies":[{"name":"host-rewrite","version":"v1","params":{"host":"hr-rapid-v1.example"}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "POST" request to "${CTX:apiContext}/v1.0/probe" until status 200

    When I set request host to "client-37.example"
    And I start background "POST" requests to "${CTX:apiContext}/v1.0/probe" as "traffic"
    Then background requests "traffic" should eventually echo "hr-rapid-v1.example" in JSON field "headers.Host"
    When I update API "${CTX:apiName}" from "resources/templates/rest-api.yaml" with values:
      | apiVersion                     | ${CTX:gatewaySpecVersion} |
      | name                           | ${CTX:apiName} |
      | spec.displayName               | ${CTX:apiName} |
      | spec.version                   | v1.0 |
      | spec.context                   | ${CTX:apiContext}/$version |
      | spec.upstream.main.url         | http://testbench:3002/anything |
      | spec.upstream.main.hostRewrite | manual |
      | spec.operations                | [{"method":"POST","path":"/probe","policies":[{"name":"host-rewrite","version":"v1","params":{"host":"hr-rapid-v2.example"}}]}] |
    Then the API update response should indicate successful deployment

    When I update API "${CTX:apiName}" from "resources/templates/rest-api.yaml" with values:
      | apiVersion                     | ${CTX:gatewaySpecVersion} |
      | name                           | ${CTX:apiName} |
      | spec.displayName               | ${CTX:apiName} |
      | spec.version                   | v1.0 |
      | spec.context                   | ${CTX:apiContext}/$version |
      | spec.upstream.main.url         | http://testbench:3002/anything |
      | spec.upstream.main.hostRewrite | manual |
      | spec.operations                | [{"method":"POST","path":"/probe","policies":[{"name":"host-rewrite","version":"v1","params":{"host":"hr-rapid-v3.example"}}]}] |
    Then the API update response should indicate successful deployment

    Then background requests "traffic" should answer during the rollout and then echo "hr-rapid-v3.example" in JSON field "headers.Host"
    When I stop background requests "traffic"
    Then every background response of "traffic" should be successful with JSON field "headers.Host" set to one of:
      | hr-rapid-v1.example |
      | hr-rapid-v2.example |
      | hr-rapid-v3.example |

    When I send a "POST" request to "${CTX:apiContext}/v1.0/probe"
    Then the response status code should be 200
    And the JSON response field "headers.Host" should be "hr-rapid-v3.example"

    When I reset the request
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "POST" request to "${CTX:apiContext}/v1.0/probe" until status 404

  # 255 characters is the longest host the policy accepts.
  Scenario: Configure malformed host values, invalid characters, or unsupported parameter types (longest allowed host, 255 characters, accepted)
    Given I generate a unique value from "hr-long-host" and store it as "apiName"
    And I generate a unique API context from "/hr-long-host" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion                     | ${CTX:gatewaySpecVersion} |
      | name                           | ${CTX:apiName} |
      | spec.displayName               | ${CTX:apiName} |
      | spec.version                   | v1.0 |
      | spec.context                   | ${CTX:apiContext}/$version |
      | spec.upstream.main.url         | http://testbench:3002/anything |
      | spec.upstream.main.hostRewrite | manual |
      | spec.operations                | [{"method":"GET","path":"/probe","policies":[{"name":"host-rewrite","version":"v1","params":{"host":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/v1.0/probe" until status 200

    When I send a "GET" request to "${CTX:apiContext}/v1.0/probe"
    Then the response status code should be 200
    And the JSON response field "headers.Host" should be "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/v1.0/probe" until status 404
