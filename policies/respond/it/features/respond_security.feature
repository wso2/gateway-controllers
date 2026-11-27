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

@respond
Feature: Respond against hostile input and leaks
  As an API developer
  I want a reply that client input cannot change and that does not leak
  So that clients get the response the API defines without the backend being called

  # The upstream is the testbench capture service (${CTX:captureUpstream}/<API name>). It records
  # every request that reaches it, and its /test/captured query answers 204 for a path that
  # received nothing. RES01 uses it to prove that respond answers without calling the backend;
  # the other scenarios check the reply itself.
  # Most APIs also have a /ready operation without the policy, which the scenario polls until the
  # API is deployed; it answers 200 from the capture service.

  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"
    And I resolve the "capture" service URL at "" and store it as "captureUpstream"

  # RES26: CR LF and header lines in the path, the query and request headers cannot add a header
  # to the reply or change it. A raw request writes the header values with real CR LF bytes, so
  # each one arrives as an extra request header; the reply is still exactly the configured one,
  # with no Set-Cookie or X-Injected header.
  Scenario: Keep CR LF and header lines in client input out of the reply
    Given I generate a unique value from "res-crlf" and store it as "apiName"
    And I generate a unique API version from "res-crlf" and store it as "apiVersion"
    And I generate a unique API context from "/res-crlf" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}             |
      | name                   | ${CTX:apiName}                        |
      | spec.displayName       | ${CTX:apiName}                        |
      | spec.version           | ${CTX:apiVersion}                     |
      | spec.context           | ${CTX:apiContext}/$version            |
      | spec.upstream.main.url | ${CTX:captureUpstream}/${CTX:apiName} |
      | spec.operations        | [{"method":"GET","path":"/ready"},{"method":"GET","path":"/orders/{id}","policies":[{"name":"respond","version":"v1","params":{"statusCode":202,"body":"accepted","headers":[{"name":"X-Reply-Source","value":"gateway"}]}}]}] |
    Then the resource creation response should indicate successful deployment
    When I clear all headers
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/ready" until status 200

    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/orders/a%0D%0ASet-Cookie:%20session=stolen?note=x%0D%0AX-Injected:%20yes"
    Then the response status code should be 202
    And the response header "X-Reply-Source" should be "gateway"
    And the response header "Set-Cookie" should not exist
    And the response header "X-Injected" should not exist
    And the response body should be:
      """
      accepted
      """

    When I send a raw "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/orders/42" with headers:
      | X-Note         | a\r\nX-Injected: yes                  |
      | X-Reply-Source | client\r\nSet-Cookie: session=stolen |
    Then the response status code should be 202
    And the response header "X-Reply-Source" should be "gateway"
    And the response header "Set-Cookie" should not exist
    And the response header "X-Injected" should not exist
    And the response body should be:
      """
      accepted
      """

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/ready" until status 404

  # RES28: A value configured in the reply's body and headers reaches the client, as configured,
  # but neither the gateway controller nor the gateway runtime writes it to its logs. Each log is
  # first checked for a line this scenario caused, so the negative check reads a log that holds
  # this scenario's lines.
  Scenario: Keep a configured reply value out of the gateway logs
    Given I generate a unique value from "res-secret" and store it as "apiName"
    And I generate a unique API version from "res-secret" and store it as "apiVersion"
    And I generate a unique API context from "/res-secret" and store it as "apiContext"
    And I generate a unique value from "res-configured-secret" and store it as "secret"
    And I generate a unique value from "res-log-marker" and store it as "marker"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}             |
      | name                   | ${CTX:apiName}                        |
      | spec.displayName       | ${CTX:apiName}                        |
      | spec.version           | ${CTX:apiVersion}                     |
      | spec.context           | ${CTX:apiContext}/$version            |
      | spec.upstream.main.url | ${CTX:captureUpstream}/${CTX:apiName} |
      | spec.operations        | [{"method":"GET","path":"/ready"},{"method":"GET","path":"/orders","policies":[{"name":"respond","version":"v1","params":{"statusCode":200,"body":"token=${CTX:secret}","headers":[{"name":"X-Debug-Token","value":"${CTX:secret}"}]}}]},{"method":"GET","path":"/logged","policies":[{"name":"set-headers","version":"v1","params":{"request":{"headers":[{"name":"X-Added-By-Gateway","value":"${CTX:marker}"}]}}},{"name":"log-message","version":"v1","params":{"request":{"headers":true}}}]}] |
    Then the resource creation response should indicate successful deployment
    When I clear all headers
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/ready" until status 200

    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/orders"
    Then the response status code should be 200
    And the response header "X-Debug-Token" should be "${CTX:secret}"
    And the response body should be:
      """
      token=${CTX:secret}
      """

    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/logged"
    Then the response status code should be 200
    And the "gateway-runtime" service logs should contain "${CTX:marker}"
    And the "gateway-runtime" service logs should not contain "${CTX:secret}"
    And the "gateway-controller" service logs should contain "${CTX:apiName}"
    And the "gateway-controller" service logs should not contain "${CTX:secret}"

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/ready" until status 404

  # RES29: A caller without credentials asks for a protected reply. Policy order decides what it
  # receives: when basic-auth runs first, a 401 and none of the reply; when respond runs first,
  # the reply, because respond ends the chain before basic-auth. API-level policies run before
  # the operation's, so respond on the API answers before an operation's basic-auth.
  Scenario Outline: Protect a reply by placing basic-auth before respond (<case>)
    Given I generate a unique value from "res-order-<key>" and store it as "apiName"
    And I generate a unique API version from "res-order-<key>" and store it as "apiVersion"
    And I generate a unique API context from "/res-order-<key>" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}             |
      | name                   | ${CTX:apiName}                        |
      | spec.displayName       | ${CTX:apiName}                        |
      | spec.version           | ${CTX:apiVersion}                     |
      | spec.context           | ${CTX:apiContext}/$version            |
      | spec.upstream.main.url | ${CTX:captureUpstream}/${CTX:apiName} |
      | spec.policies          | <apiPolicies> |
      | spec.operations        | [{"method":"GET","path":"/ready"},{"method":"GET","path":"/orders","policies":<operationPolicies>}] |
    Then the resource creation response should indicate successful deployment

    When I clear all headers
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/orders" until status <status>
    Then the response status code should be <status>
    And the response body should be:
      """
      <reply>
      """

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/orders" until status 404

    Examples:
      | case                                            | key              | apiPolicies                                                                                     | operationPolicies                                                                                                                                                     | status | reply                                                        |
      | basic-auth then respond on the operation        | op-auth-first    | []                                                                                              | [{"name":"basic-auth","version":"v1","params":{"username":"res-user","password":"res-secret"}},{"name":"respond","version":"v1","params":{"body":"protected reply"}}] | 401    | {"error":"Unauthorized","message":"Authentication required"} |
      | respond then basic-auth on the operation        | op-respond-first | []                                                                                              | [{"name":"respond","version":"v1","params":{"body":"protected reply"}},{"name":"basic-auth","version":"v1","params":{"username":"res-user","password":"res-secret"}}] | 200    | protected reply                                              |
      | basic-auth on the API, respond on the operation | api-auth         | [{"name":"basic-auth","version":"v1","params":{"username":"res-user","password":"res-secret"}}] | [{"name":"respond","version":"v1","params":{"body":"protected reply"}}]                                                                                               | 401    | {"error":"Unauthorized","message":"Authentication required"} |
      | respond on the API, basic-auth on the operation | api-respond      | [{"name":"respond","version":"v1","params":{"body":"protected reply"}}]                         | [{"name":"basic-auth","version":"v1","params":{"username":"res-user","password":"res-secret"}}]                                                                       | 200    | protected reply                                              |
