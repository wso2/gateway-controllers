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

@set-headers
Feature: Set headers policy scope and chaining
  As an API developer
  I want header setting to apply where it is attached and in the order it is configured
  So that the backend and the client receive exactly the headers the API defines

  # The backend is the testbench echo service under /analytics-headers. It returns the request it
  # received as JSON, and answers with X-Allowed-Response: allowed, X-Denied-Response: denied,
  # X-Removed-Response: removed, X-Multi-Response as two header lines, and X-Correlation-Response
  # with the value of the request's X-Correlation-Id. The "echoed header" steps read the request
  # headers that reached the backend, and the "response header" steps read the headers the
  # client received.

  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"

  # SH10: The policy is attached at the API level, so it applies to every operation of the API. Each
  # operation, across different methods and resources, must receive the configured request header
  # and return the configured response header.
  Scenario: Apply set-headers at the API level to every operation
    Given I generate a unique value from "sh-api-level" and store it as "apiName"
    And I generate a unique API version from "sh-api-level" and store it as "apiVersion"
    And I generate a unique API context from "/sh-api-level" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}               |
      | name                   | ${CTX:apiName}                          |
      | spec.displayName       | ${CTX:apiName}                          |
      | spec.version           | ${CTX:apiVersion}                       |
      | spec.context           | ${CTX:apiContext}/$version              |
      | spec.upstream.main.url | http://testbench:3000/analytics-headers |
      | spec.policies          | [{"name":"set-headers","version":"v1","params":{"request":{"headers":[{"name":"X-Gateway-Tenant","value":"tenant-a"}]},"response":{"headers":[{"name":"X-Gateway-Response","value":"gateway-value"}]}}}] |
      | spec.operations        | [{"method":"GET","path":"/orders"},{"method":"POST","path":"/orders"},{"method":"GET","path":"/customers"}] |
    Then the resource creation response should indicate successful deployment

    When I clear all headers
    And I set header "X-Client-Id" to "client-123"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/orders" until status 200
    Then the response should contain echoed header "X-Gateway-Tenant" with value "tenant-a"
    And the response header "X-Gateway-Response" should be "gateway-value"

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/orders" with body:
      """
      {"order":"1001"}
      """
    Then the response status code should be 200
    And the JSON response field "method" should be "POST"
    And the response should contain echoed header "X-Gateway-Tenant" with value "tenant-a"
    And the response header "X-Gateway-Response" should be "gateway-value"

    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/customers"
    Then the response status code should be 200
    And the JSON response field "path" should be "/analytics-headers/customers"
    And the response should contain echoed header "X-Gateway-Tenant" with value "tenant-a"
    And the response header "X-Gateway-Response" should be "gateway-value"

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/orders" until status 404

  # SH11: The policy is attached to /restricted only. /public, in the same API, has no policy, so
  # neither header may be set there.
  Scenario: Apply set-headers to a selected operation only
    Given I generate a unique value from "sh-op-selected" and store it as "apiName"
    And I generate a unique API version from "sh-op-selected" and store it as "apiVersion"
    And I generate a unique API context from "/sh-op-selected" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}               |
      | name                   | ${CTX:apiName}                          |
      | spec.displayName       | ${CTX:apiName}                          |
      | spec.version           | ${CTX:apiVersion}                       |
      | spec.context           | ${CTX:apiContext}/$version              |
      | spec.upstream.main.url | http://testbench:3000/analytics-headers |
      | spec.operations        | [{"method":"GET","path":"/restricted","policies":[{"name":"set-headers","version":"v1","params":{"request":{"headers":[{"name":"X-Gateway-Tenant","value":"tenant-a"}]},"response":{"headers":[{"name":"X-Gateway-Response","value":"gateway-value"}]}}}]},{"method":"GET","path":"/public"}] |
    Then the resource creation response should indicate successful deployment

    When I clear all headers
    And I set header "X-Client-Id" to "client-123"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/restricted" until status 200
    Then the response should contain echoed header "X-Gateway-Tenant" with value "tenant-a"
    And the response header "X-Gateway-Response" should be "gateway-value"

    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/public"
    Then the response status code should be 200
    And the response should not contain echoed header "X-Gateway-Tenant"
    And the response header "X-Gateway-Response" should not exist
    And the response should contain echoed header "X-Client-Id" with value "client-123"

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/restricted" until status 404

  # SH12: Two operations attach the policy with different values for the same headers. Each must
  # receive and return its own values only.
  Scenario: Configure different header values for different operations
    Given I generate a unique value from "sh-op-values" and store it as "apiName"
    And I generate a unique API version from "sh-op-values" and store it as "apiVersion"
    And I generate a unique API context from "/sh-op-values" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}               |
      | name                   | ${CTX:apiName}                          |
      | spec.displayName       | ${CTX:apiName}                          |
      | spec.version           | ${CTX:apiVersion}                       |
      | spec.context           | ${CTX:apiContext}/$version              |
      | spec.upstream.main.url | http://testbench:3000/analytics-headers |
      | spec.operations        | [{"method":"GET","path":"/orders","policies":[{"name":"set-headers","version":"v1","params":{"request":{"headers":[{"name":"X-Gateway-Tenant","value":"orders-tenant"}]},"response":{"headers":[{"name":"X-Gateway-Response","value":"orders-response"}]}}}]},{"method":"GET","path":"/customers","policies":[{"name":"set-headers","version":"v1","params":{"request":{"headers":[{"name":"X-Gateway-Tenant","value":"customers-tenant"}]},"response":{"headers":[{"name":"X-Gateway-Response","value":"customers-response"}]}}}]}] |
    Then the resource creation response should indicate successful deployment

    When I clear all headers
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/orders" until status 200
    Then the response should contain echoed header "X-Gateway-Tenant" with value "orders-tenant"
    And the response header "X-Gateway-Response" should be "orders-response"

    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/customers" until status 200
    Then the response should contain echoed header "X-Gateway-Tenant" with value "customers-tenant"
    And the response header "X-Gateway-Response" should be "customers-response"

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/orders" until status 404

  # SH16, SH17: Two set-headers policies set different headers and the same headers, and the second
  # one sets X-Gateway-Tenant twice. Every header must be applied, and a header set more than once
  # must hold the value of the last policy to run. The gateway runs a chain's request phase first to
  # last and its response phase last to first, so the request keeps the second policy's last
  # X-Gateway-Tenant and the response keeps the first policy's X-Gateway-Response.
  Scenario: Apply several set-headers policies and set the same header more than once
    Given I generate a unique value from "sh-chain-order" and store it as "apiName"
    And I generate a unique API version from "sh-chain-order" and store it as "apiVersion"
    And I generate a unique API context from "/sh-chain-order" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}               |
      | name                   | ${CTX:apiName}                          |
      | spec.displayName       | ${CTX:apiName}                          |
      | spec.version           | ${CTX:apiVersion}                       |
      | spec.context           | ${CTX:apiContext}/$version              |
      | spec.upstream.main.url | http://testbench:3000/analytics-headers |
      | spec.operations        | [{"method":"GET","path":"/get","policies":[{"name":"set-headers","version":"v1","params":{"request":{"headers":[{"name":"X-Gateway-Tenant","value":"first"},{"name":"X-Gateway-Region","value":"eu-west"}]},"response":{"headers":[{"name":"X-Gateway-Response","value":"first"},{"name":"X-Gateway-Zone","value":"zone-a"}]}}},{"name":"set-headers","version":"v1","params":{"request":{"headers":[{"name":"X-Gateway-Tenant","value":"second"},{"name":"X-Gateway-Tenant","value":"third"}]},"response":{"headers":[{"name":"X-Gateway-Response","value":"second"}]}}}]}] |
    Then the resource creation response should indicate successful deployment

    When I clear all headers
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 200
    Then the response should contain echoed header "X-Gateway-Tenant" with value "third"
    And the response should contain echoed header "X-Gateway-Region" with value "eu-west"
    And the response header "X-Gateway-Response" should be "first"
    And the response header "X-Gateway-Zone" should be "zone-a"

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 404

  # SH18: set-headers runs before remove-headers for the same headers. The gateway runs a policy
  # chain's request phase first to last and its response phase last to first, so set-headers is
  # placed on each side of remove-headers to run before it in both phases. The headers set-headers
  # sets for remove-headers must be removed, and X-Gateway-Added and X-Gateway-Response, which
  # remove-headers does not name, must arrive, which shows that set-headers ran.
  Scenario: Apply set-headers before remove-headers for the same header
    Given I generate a unique value from "sh-set-first" and store it as "apiName"
    And I generate a unique API version from "sh-set-first" and store it as "apiVersion"
    And I generate a unique API context from "/sh-set-first" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}               |
      | name                   | ${CTX:apiName}                          |
      | spec.displayName       | ${CTX:apiName}                          |
      | spec.version           | ${CTX:apiVersion}                       |
      | spec.context           | ${CTX:apiContext}/$version              |
      | spec.upstream.main.url | http://testbench:3000/analytics-headers |
      | spec.operations        | [{"method":"GET","path":"/get","policies":[{"name":"set-headers","version":"v1","params":{"request":{"headers":[{"name":"X-Gateway-Tenant","value":"gateway-value"},{"name":"X-Gateway-Added","value":"gateway-added"}]}}},{"name":"remove-headers","version":"v1","params":{"request":{"headers":[{"name":"X-Gateway-Tenant"}]},"response":{"headers":[{"name":"X-Removed-Response"}]}}},{"name":"set-headers","version":"v1","params":{"response":{"headers":[{"name":"X-Removed-Response","value":"gateway-value"},{"name":"X-Gateway-Response","value":"gateway-added"}]}}}]}] |
    Then the resource creation response should indicate successful deployment

    When I clear all headers
    And I set header "X-Gateway-Tenant" to "client-value"
    And I set header "X-Client-Id" to "client-123"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 200
    Then the response should not contain echoed header "X-Gateway-Tenant"
    And the response should contain echoed header "X-Gateway-Added" with value "gateway-added"
    And the response should contain echoed header "X-Client-Id" with value "client-123"
    And the response header "X-Removed-Response" should not exist
    And the response header "X-Gateway-Response" should be "gateway-added"

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 404

  # SH19: remove-headers runs before set-headers for the same headers. The gateway runs a policy
  # chain's request phase first to last and its response phase last to first, so set-headers is
  # placed on each side of remove-headers to run after it in both phases. The client's and the
  # backend's values must be removed, and set-headers must recreate the headers with its values.
  Scenario: Apply remove-headers before set-headers for the same header
    Given I generate a unique value from "sh-remove-first" and store it as "apiName"
    And I generate a unique API version from "sh-remove-first" and store it as "apiVersion"
    And I generate a unique API context from "/sh-remove-first" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}               |
      | name                   | ${CTX:apiName}                          |
      | spec.displayName       | ${CTX:apiName}                          |
      | spec.version           | ${CTX:apiVersion}                       |
      | spec.context           | ${CTX:apiContext}/$version              |
      | spec.upstream.main.url | http://testbench:3000/analytics-headers |
      | spec.operations        | [{"method":"GET","path":"/get","policies":[{"name":"set-headers","version":"v1","params":{"response":{"headers":[{"name":"X-Removed-Response","value":"gateway-value"}]}}},{"name":"remove-headers","version":"v1","params":{"request":{"headers":[{"name":"X-Gateway-Tenant"}]},"response":{"headers":[{"name":"X-Removed-Response"}]}}},{"name":"set-headers","version":"v1","params":{"request":{"headers":[{"name":"X-Gateway-Tenant","value":"gateway-value"}]}}}]}] |
    Then the resource creation response should indicate successful deployment

    When I clear all headers
    And I set header "X-Gateway-Tenant" to "client-value"
    And I set header "X-Client-Id" to "client-123"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 200
    Then the response should contain echoed header "X-Gateway-Tenant" with value "gateway-value"
    And the response body should not contain "client-value"
    And the response should contain echoed header "X-Client-Id" with value "client-123"
    And the response header "X-Removed-Response" should be "gateway-value"

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 404

  # SH20: set-headers runs beside rate limiting and host rewrite without either changing what the
  # other does: the rate-limited operation still reports its limit, the rewritten Host still reaches
  # the backend, and the configured header is set on both.
  Scenario: Combine set-headers with rate limiting and host rewrite
    Given I generate a unique value from "sh-chain-limit" and store it as "apiName"
    And I generate a unique API version from "sh-chain-limit" and store it as "apiVersion"
    And I generate a unique API context from "/sh-chain-limit" and store it as "apiContext"
    And I generate a unique value from "sh-host-rewrite" and store it as "rewriteApiName"
    And I generate a unique API context from "/sh-host-rewrite" and store it as "rewriteApiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}  |
      | name                   | ${CTX:apiName}             |
      | spec.displayName       | ${CTX:apiName}             |
      | spec.version           | ${CTX:apiVersion}          |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3000      |
      | spec.operations        | [{"method":"GET","path":"/get","policies":[{"name":"basic-ratelimit","version":"v1","params":{"limits":[{"requests":100,"duration":"1h"}]}},{"name":"set-headers","version":"v1","params":{"request":{"headers":[{"name":"X-Gateway-Tenant","value":"tenant-a"}]},"response":{"headers":[{"name":"X-Gateway-Response","value":"gateway-value"}]}}}]}] |
    Then the resource creation response should indicate successful deployment
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion                     | ${CTX:gatewaySpecVersion}         |
      | name                           | ${CTX:rewriteApiName}             |
      | spec.displayName               | ${CTX:rewriteApiName}             |
      | spec.version                   | ${CTX:apiVersion}                 |
      | spec.context                   | ${CTX:rewriteApiContext}/$version |
      | spec.upstream.main.url         | http://testbench:3000             |
      | spec.upstream.main.hostRewrite | manual                            |
      | spec.operations                | [{"method":"GET","path":"/get","policies":[{"name":"host-rewrite","version":"v1","params":{"host":"sh-rewritten.example"}},{"name":"set-headers","version":"v1","params":{"request":{"headers":[{"name":"X-Gateway-Tenant","value":"tenant-a"}]}}}]}] |
    Then the resource creation response should indicate successful deployment

    When I clear all headers
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 200
    Then the response header "X-RateLimit-Limit" should be "100"
    And the response header "X-Gateway-Response" should be "gateway-value"
    And the response should contain echoed header "X-Gateway-Tenant" with value "tenant-a"

    When I send a "GET" request to "${CTX:rewriteApiContext}/${CTX:apiVersion}/get" until status 200
    Then the response should contain echoed header "Host" with value "sh-rewritten.example"
    And the response should contain echoed header "X-Gateway-Tenant" with value "tenant-a"

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:rewriteApiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:rewriteApiContext}/${CTX:apiVersion}/get" until status 404

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 404

  # SH20: set-headers runs beside basic-auth and dynamic-endpoint. A credential set-headers injects
  # before basic-auth must not authenticate a client that sent none, because basic-auth checks the
  # credentials the client sent, and the dynamic endpoint must still route to its upstream with
  # the configured header set.
  #
  # Known issue on gateway 1.1.0: it does not give policies a snapshot of the client's request, so
  # basic-auth accepts the injected credential and a client without credentials gets 200
  # (wso2/api-platform#2548), and it sends a dynamic endpoint's request without its base path
  # (wso2/api-platform#2000). Both are fixed in 1.2.0. The
  # set-headers-scope-gw-1.1.0 runner skips this tag.
  @known-issue-gw-1.1.0
  Scenario: Combine set-headers with authentication and a dynamic endpoint
    Given I generate a unique value from "sh-chain-auth" and store it as "apiName"
    And I generate a unique API version from "sh-chain-auth" and store it as "apiVersion"
    And I generate a unique API context from "/sh-chain-auth" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion               | ${CTX:gatewaySpecVersion}  |
      | name                     | ${CTX:apiName}             |
      | spec.displayName         | ${CTX:apiName}             |
      | spec.version             | ${CTX:apiVersion}          |
      | spec.context             | ${CTX:apiContext}/$version |
      | spec.upstream.main.url   | http://testbench:3000      |
      | spec.upstreamDefinitions | [{"name":"alt-upstream","basePath":"/alternate","upstreams":[{"url":"http://testbench:3000"}]}] |
      | spec.operations          | [{"method":"GET","path":"/auth-protected","policies":[{"name":"set-headers","version":"v1","params":{"request":{"headers":[{"name":"Authorization","value":"Basic c2gtdXNlcjpzaC1zZWNyZXQ="}]}}},{"name":"basic-auth","version":"v1","params":{"username":"sh-user","password":"sh-secret"}}]},{"method":"GET","path":"/dynamic","policies":[{"name":"set-headers","version":"v1","params":{"request":{"headers":[{"name":"X-Gateway-Tenant","value":"tenant-a"}]}}},{"name":"dynamic-endpoint","version":"v1","params":{"targetUpstream":"alt-upstream"}}]}] |
    Then the resource creation response should indicate successful deployment

    When I clear all headers
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/auth-protected" until status 401

    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/dynamic" until status 200
    Then the JSON response field "path" should be "/alternate/dynamic"
    And the response should contain echoed header "X-Gateway-Tenant" with value "tenant-a"

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/dynamic" until status 404
