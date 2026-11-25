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

@remove-headers
Feature: Remove headers policy scope and chaining
  As an API developer
  I want header removal to apply where it is attached and in the order it is configured
  So that headers the backend or the client must not see never reach them

  # The backend is the testbench echo service under /analytics-headers. It returns the request it
  # received as JSON, and answers with X-Allowed-Response: allowed, X-Denied-Response: denied,
  # X-Removed-Response: removed, X-Multi-Response as two header lines, and X-Correlation-Response
  # with the value of the request's X-Correlation-Id. The "echoed header" steps read the request
  # headers that reached the backend, and the "response header" steps read the headers the
  # client received.

  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"

  # RH09: The policy is attached at the API level, so it applies to every operation of the API.
  # Each operation, across different methods and resources, must remove the configured request
  # and response headers.
  Scenario: Apply header removal at the API level to every operation
    Given I generate a unique value from "rh-api-level" and store it as "apiName"
    And I generate a unique API version from "rh-api-level" and store it as "apiVersion"
    And I generate a unique API context from "/rh-api-level" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}               |
      | name                   | ${CTX:apiName}                          |
      | spec.displayName       | ${CTX:apiName}                          |
      | spec.version           | ${CTX:apiVersion}                       |
      | spec.context           | ${CTX:apiContext}/$version              |
      | spec.upstream.main.url | http://testbench:3000/analytics-headers |
      | spec.policies          | [{"name":"remove-headers","version":"v1","params":{"request":{"headers":[{"name":"X-Internal-Token"}]},"response":{"headers":[{"name":"X-Removed-Response"}]}}}] |
      | spec.operations        | [{"method":"GET","path":"/orders"},{"method":"POST","path":"/orders"},{"method":"GET","path":"/customers"}] |
    Then the resource creation response should indicate successful deployment

    When I clear all headers
    And I set header "X-Internal-Token" to "internal-token-value"
    And I set header "X-Client-Id" to "client-123"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/orders" until status 200
    Then the response should not contain echoed header "X-Internal-Token"
    And the response should contain echoed header "X-Client-Id" with value "client-123"
    And the response header "X-Removed-Response" should not exist

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/orders" with body:
      """
      {"order":"1001"}
      """
    Then the response status code should be 200
    And the JSON response field "method" should be "POST"
    And the response should not contain echoed header "X-Internal-Token"
    And the response header "X-Removed-Response" should not exist

    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/customers"
    Then the response status code should be 200
    And the JSON response field "path" should be "/analytics-headers/customers"
    And the response should not contain echoed header "X-Internal-Token"
    And the response header "X-Removed-Response" should not exist

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/orders" until status 404

  # RH10: The policy is attached to /restricted only. /public, in the same API, has no policy, so
  # the configured headers must pass through it unchanged.
  Scenario: Apply header removal to a selected operation only
    Given I generate a unique value from "rh-op-selected" and store it as "apiName"
    And I generate a unique API version from "rh-op-selected" and store it as "apiVersion"
    And I generate a unique API context from "/rh-op-selected" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}               |
      | name                   | ${CTX:apiName}                          |
      | spec.displayName       | ${CTX:apiName}                          |
      | spec.version           | ${CTX:apiVersion}                       |
      | spec.context           | ${CTX:apiContext}/$version              |
      | spec.upstream.main.url | http://testbench:3000/analytics-headers |
      | spec.operations        | [{"method":"GET","path":"/restricted","policies":[{"name":"remove-headers","version":"v1","params":{"request":{"headers":[{"name":"X-Internal-Token"}]},"response":{"headers":[{"name":"X-Removed-Response"}]}}}]},{"method":"GET","path":"/public"}] |
    Then the resource creation response should indicate successful deployment

    When I clear all headers
    And I set header "X-Internal-Token" to "internal-token-value"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/restricted" until status 200
    Then the response should not contain echoed header "X-Internal-Token"
    And the response header "X-Removed-Response" should not exist

    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/public"
    Then the response status code should be 200
    And the response should contain echoed header "X-Internal-Token" with value "internal-token-value"
    And the response header "X-Removed-Response" should be "removed"

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/restricted" until status 404

  # RH11: Two operations of the API each attach the policy with a different list: /orders removes
  # X-Internal-Token and X-Removed-Response, and /customers removes X-Debug-Mode and
  # X-Denied-Response. The same request is sent to both, and each must remove only its own list.
  Scenario: Configure different header removal rules for different operations
    Given I generate a unique value from "rh-op-rules" and store it as "apiName"
    And I generate a unique API version from "rh-op-rules" and store it as "apiVersion"
    And I generate a unique API context from "/rh-op-rules" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}               |
      | name                   | ${CTX:apiName}                          |
      | spec.displayName       | ${CTX:apiName}                          |
      | spec.version           | ${CTX:apiVersion}                       |
      | spec.context           | ${CTX:apiContext}/$version              |
      | spec.upstream.main.url | http://testbench:3000/analytics-headers |
      | spec.operations        | [{"method":"GET","path":"/orders","policies":[{"name":"remove-headers","version":"v1","params":{"request":{"headers":[{"name":"X-Internal-Token"}]},"response":{"headers":[{"name":"X-Removed-Response"}]}}}]},{"method":"GET","path":"/customers","policies":[{"name":"remove-headers","version":"v1","params":{"request":{"headers":[{"name":"X-Debug-Mode"}]},"response":{"headers":[{"name":"X-Denied-Response"}]}}}]}] |
    Then the resource creation response should indicate successful deployment

    When I clear all headers
    And I set header "X-Internal-Token" to "internal-token-value"
    And I set header "X-Debug-Mode" to "verbose"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/orders" until status 200
    Then the response should not contain echoed header "X-Internal-Token"
    And the response should contain echoed header "X-Debug-Mode" with value "verbose"
    And the response header "X-Removed-Response" should not exist
    And the response header "X-Denied-Response" should be "denied"

    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/customers" until status 200
    Then the response should contain echoed header "X-Internal-Token" with value "internal-token-value"
    And the response should not contain echoed header "X-Debug-Mode"
    And the response header "X-Removed-Response" should be "removed"
    And the response header "X-Denied-Response" should not exist

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/orders" until status 404

  # RH17: set-headers runs before remove-headers for the same headers. The gateway runs a policy
  # chain's request phase first to last and its response phase last to first, so set-headers is
  # placed on each side of remove-headers to run before it in both phases. The headers set-headers
  # sets must be removed. set-headers also sets X-Gateway-Added on the request and
  # X-Gateway-Response on the response, which remove-headers does not name; they must arrive, which
  # shows that set-headers ran and that only the removed headers are missing.
  Scenario: Apply set-headers before remove-headers for the same header
    Given I generate a unique value from "rh-set-first" and store it as "apiName"
    And I generate a unique API version from "rh-set-first" and store it as "apiVersion"
    And I generate a unique API context from "/rh-set-first" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}               |
      | name                   | ${CTX:apiName}                          |
      | spec.displayName       | ${CTX:apiName}                          |
      | spec.version           | ${CTX:apiVersion}                       |
      | spec.context           | ${CTX:apiContext}/$version              |
      | spec.upstream.main.url | http://testbench:3000/analytics-headers |
      | spec.operations        | [{"method":"GET","path":"/get","policies":[{"name":"set-headers","version":"v1","params":{"request":{"headers":[{"name":"X-Internal-Token","value":"gateway-value"},{"name":"X-Gateway-Added","value":"gateway-added"}]}}},{"name":"remove-headers","version":"v1","params":{"request":{"headers":[{"name":"X-Internal-Token"}]},"response":{"headers":[{"name":"X-Removed-Response"}]}}},{"name":"set-headers","version":"v1","params":{"response":{"headers":[{"name":"X-Removed-Response","value":"gateway-value"},{"name":"X-Gateway-Response","value":"gateway-added"}]}}}]}] |
    Then the resource creation response should indicate successful deployment

    When I clear all headers
    And I set header "X-Internal-Token" to "client-value"
    And I set header "X-Client-Id" to "client-123"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 200
    Then the response should not contain echoed header "X-Internal-Token"
    And the response should contain echoed header "X-Client-Id" with value "client-123"
    And the response header "X-Removed-Response" should not exist
    And the response should contain echoed header "X-Gateway-Added" with value "gateway-added"
    And the response header "X-Gateway-Response" should be "gateway-added"

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 404

  # RH18: remove-headers runs before set-headers for the same headers. The gateway runs a policy
  # chain's request phase first to last and its response phase last to first, so set-headers is
  # placed on each side of remove-headers to run after it in both phases. The client's and the
  # backend's values must be removed, and the headers must carry the values set-headers sets
  # afterwards.
  Scenario: Apply remove-headers before set-headers for the same header
    Given I generate a unique value from "rh-remove-first" and store it as "apiName"
    And I generate a unique API version from "rh-remove-first" and store it as "apiVersion"
    And I generate a unique API context from "/rh-remove-first" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}               |
      | name                   | ${CTX:apiName}                          |
      | spec.displayName       | ${CTX:apiName}                          |
      | spec.version           | ${CTX:apiVersion}                       |
      | spec.context           | ${CTX:apiContext}/$version              |
      | spec.upstream.main.url | http://testbench:3000/analytics-headers |
      | spec.operations        | [{"method":"GET","path":"/get","policies":[{"name":"set-headers","version":"v1","params":{"response":{"headers":[{"name":"X-Removed-Response","value":"gateway-value"}]}}},{"name":"remove-headers","version":"v1","params":{"request":{"headers":[{"name":"X-Internal-Token"}]},"response":{"headers":[{"name":"X-Removed-Response"}]}}},{"name":"set-headers","version":"v1","params":{"request":{"headers":[{"name":"X-Internal-Token","value":"gateway-value"}]}}}]}] |
    Then the resource creation response should indicate successful deployment

    When I clear all headers
    And I set header "X-Internal-Token" to "client-value"
    And I set header "X-Client-Id" to "client-123"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 200
    Then the response should contain echoed header "X-Internal-Token" with value "gateway-value"
    And the response body should not contain "client-value"
    And the response should contain echoed header "X-Client-Id" with value "client-123"
    And the response header "X-Removed-Response" should be "gateway-value"

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 404

  # RH19: remove-headers removes the Authorization header that basic-auth checks, on one operation
  # after basic-auth and on the other before it. basic-auth checks the credentials the client sent,
  # so in either order a request without credentials or with wrong ones is rejected, and only an
  # authenticated request reaches the backend, without its credentials. Removing the header never
  # lets a request past authentication.
  #
  # Known issue on gateway 1.1.0: it does not give policies a snapshot of the client's request, so
  # basic-auth sees the headers as earlier policies left them, and removing Authorization before it
  # rejects even valid credentials (wso2/api-platform#2548, fixed in 1.2.0). The
  # remove-headers-scope-gw-1.1.0 runner skips this tag.
  @known-issue-gw-1.1.0
  Scenario Outline: Chain header removal with authentication (<order>)
    Given I generate a unique value from "rh-auth" and store it as "apiName"
    And I generate a unique API version from "rh-auth" and store it as "apiVersion"
    And I generate a unique API context from "/rh-auth" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}  |
      | name                   | ${CTX:apiName}             |
      | spec.displayName       | ${CTX:apiName}             |
      | spec.version           | ${CTX:apiVersion}          |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3000      |
      | spec.operations        | [{"method":"GET","path":"/auth-first","policies":[{"name":"basic-auth","version":"v1","params":{"username":"rh-user","password":"rh-secret"}},{"name":"remove-headers","version":"v1","params":{"request":{"headers":[{"name":"Authorization"}]}}}]},{"method":"GET","path":"/remove-first","policies":[{"name":"remove-headers","version":"v1","params":{"request":{"headers":[{"name":"Authorization"}]}}},{"name":"basic-auth","version":"v1","params":{"username":"rh-user","password":"rh-secret"}}]}] |
    Then the resource creation response should indicate successful deployment

    When I clear all headers
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}<path>" until status 401

    When I set header "Authorization" to "Basic cmgtdXNlcjp3cm9uZy1zZWNyZXQ="
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}<path>"
    Then the response status code should be 401

    When I set header "Authorization" to "Basic cmgtdXNlcjpyaC1zZWNyZXQ="
    And I set header "X-Client-Id" to "client-123"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}<path>"
    Then the response status code should be 200
    And the response should not contain echoed header "Authorization"
    And the response should contain echoed header "X-Client-Id" with value "client-123"

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}<path>" until status 404

    Examples:
      | order                | path          |
      | basic-auth first     | /auth-first   |
      | remove-headers first | /remove-first |
