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
Feature: Remove headers policy header matching
  As an API developer
  I want every copy of a configured header removed, however the header is sent
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

  # RH05: The policy removes X-Internal-Token from the request and X-Removed-Response from the
  # response. The client also sends a request header named X-Removed-Response; it is configured
  # for the response flow only, so it must still reach the backend. This shows that each flow
  # applies its own list and no other.
  Scenario: Remove headers on both the request and response flows
    Given I generate a unique value from "rh-both-flows" and store it as "apiName"
    And I generate a unique API version from "rh-both-flows" and store it as "apiVersion"
    And I generate a unique API context from "/rh-both-flows" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}               |
      | name                   | ${CTX:apiName}                          |
      | spec.displayName       | ${CTX:apiName}                          |
      | spec.version           | ${CTX:apiVersion}                       |
      | spec.context           | ${CTX:apiContext}/$version              |
      | spec.upstream.main.url | http://testbench:3000/analytics-headers |
      | spec.operations        | [{"method":"GET","path":"/get","policies":[{"name":"remove-headers","version":"v1","params":{"request":{"headers":[{"name":"X-Internal-Token"}]},"response":{"headers":[{"name":"X-Removed-Response"}]}}}]}] |
    Then the resource creation response should indicate successful deployment

    When I clear all headers
    And I set header "X-Internal-Token" to "internal-token-value"
    And I set header "X-Removed-Response" to "client-value"
    And I set header "X-Client-Id" to "client-123"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 200
    Then the response should not contain echoed header "X-Internal-Token"
    And the response should contain echoed header "X-Removed-Response" with value "client-value"
    And the response should contain echoed header "X-Client-Id" with value "client-123"
    And the response header "X-Removed-Response" should not exist
    And the response header "X-Allowed-Response" should be "allowed"
    And the response header "X-Denied-Response" should be "denied"

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 404

  # RH06: The policy is configured to remove a request header the client does not send and a
  # response header the backend does not return. The call must succeed, and every header that is
  # present must pass through unchanged.
  Scenario: Remove headers that are not present
    Given I generate a unique value from "rh-absent" and store it as "apiName"
    And I generate a unique API version from "rh-absent" and store it as "apiVersion"
    And I generate a unique API context from "/rh-absent" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}               |
      | name                   | ${CTX:apiName}                          |
      | spec.displayName       | ${CTX:apiName}                          |
      | spec.version           | ${CTX:apiVersion}                       |
      | spec.context           | ${CTX:apiContext}/$version              |
      | spec.upstream.main.url | http://testbench:3000/analytics-headers |
      | spec.operations        | [{"method":"GET","path":"/get","policies":[{"name":"remove-headers","version":"v1","params":{"request":{"headers":[{"name":"X-Internal-Token"}]},"response":{"headers":[{"name":"X-Absent-Response"}]}}}]}] |
    Then the resource creation response should indicate successful deployment

    When I clear all headers
    And I set header "X-Client-Id" to "client-123"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 200
    Then the response should not contain echoed header "X-Internal-Token"
    And the response should contain echoed header "X-Client-Id" with value "client-123"
    And the response header "X-Absent-Response" should not exist
    And the response header "X-Allowed-Response" should be "allowed"
    And the response header "X-Denied-Response" should be "denied"
    And the response header "X-Removed-Response" should be "removed"

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 404

  # RH07: Header names are case-insensitive. The policy is configured with a header name in one
  # case and the request is sent over a raw connection with the name in another, so the case
  # reaches the gateway exactly as written. The response header the backend returns is configured
  # in its own case too. Both headers must be removed.
  Scenario Outline: Remove headers regardless of the case of their names (<case>)
    Given I generate a unique value from "rh-case-<key>" and store it as "apiName"
    And I generate a unique API version from "rh-case-<key>" and store it as "apiVersion"
    And I generate a unique API context from "/rh-case-<key>" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}               |
      | name                   | ${CTX:apiName}                          |
      | spec.displayName       | ${CTX:apiName}                          |
      | spec.version           | ${CTX:apiVersion}                       |
      | spec.context           | ${CTX:apiContext}/$version              |
      | spec.upstream.main.url | http://testbench:3000/analytics-headers |
      | spec.operations        | [{"method":"GET","path":"/get","policies":[{"name":"remove-headers","version":"v1","params":{"request":{"headers":[{"name":"<configured>"}]},"response":{"headers":[{"name":"<configuredResponse>"}]}}}]}] |
    Then the resource creation response should indicate successful deployment

    When I clear all headers
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 200
    And I send a raw "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" with headers:
      | <sent>      | case-test-value |
      | X-Client-Id | client-123      |
    Then the response status code should be 200
    And the response should not contain echoed header "X-Test"
    And the response should contain echoed header "X-Client-Id" with value "client-123"
    And the response header "X-Removed-Response" should not exist
    And the response header "X-Allowed-Response" should be "allowed"

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 404

    Examples:
      | case                           | key   | configured | sent   | configuredResponse |
      | X-Test configured, x-test sent | title | X-Test     | x-test | X-Removed-Response |
      | x-test configured, X-TEST sent | lower | x-test     | X-TEST | x-removed-response |
      | X-TEST configured, X-Test sent | upper | X-TEST     | X-Test | X-REMOVED-RESPONSE |

  # RH08: X-Internal-Token is sent over a raw connection as two separate header lines, and the
  # backend returns X-Multi-Response as two separate header lines. The /control operation has no
  # policy and shows that, without it, both request values reach the backend and X-Multi-Response
  # reaches the client. On /get the policy must remove each header with all of its values.
  Scenario: Remove a header that carries multiple values
    Given I generate a unique value from "rh-multi-value" and store it as "apiName"
    And I generate a unique API version from "rh-multi-value" and store it as "apiVersion"
    And I generate a unique API context from "/rh-multi-value" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}               |
      | name                   | ${CTX:apiName}                          |
      | spec.displayName       | ${CTX:apiName}                          |
      | spec.version           | ${CTX:apiVersion}                       |
      | spec.context           | ${CTX:apiContext}/$version              |
      | spec.upstream.main.url | http://testbench:3000/analytics-headers |
      | spec.operations        | [{"method":"GET","path":"/get","policies":[{"name":"remove-headers","version":"v1","params":{"request":{"headers":[{"name":"X-Internal-Token"}]},"response":{"headers":[{"name":"X-Multi-Response"}]}}}]},{"method":"GET","path":"/control"}] |
    Then the resource creation response should indicate successful deployment

    When I clear all headers
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/control" until status 200
    And I send a raw "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/control" with headers:
      | X-Internal-Token | token-a    |
      | X-Internal-Token | token-b    |
      | X-Client-Id      | client-123 |
    Then the response status code should be 200
    And the response should contain echoed header "X-Internal-Token" containing "token-a"
    And the response should contain echoed header "X-Internal-Token" containing "token-b"
    And the response header "X-Multi-Response" should exist

    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 200
    And I send a raw "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" with headers:
      | X-Internal-Token | token-a    |
      | X-Internal-Token | token-b    |
      | X-Client-Id      | client-123 |
    Then the response status code should be 200
    And the response should not contain echoed header "X-Internal-Token"
    And the response should contain echoed header "X-Client-Id" with value "client-123"
    And the response header "X-Multi-Response" should not exist
    And the response header "X-Allowed-Response" should be "allowed"

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 404

  # RH28: A client tries to slip a removed header past the policy by repeating it with
  # conflicting values and different cases of its name, sent as written over a raw connection.
  # Every copy must be removed, and the other header must reach the backend unchanged.
  Scenario: Remove duplicated, conflicting and differently cased copies of a header
    Given I generate a unique value from "rh-smuggling" and store it as "apiName"
    And I generate a unique API version from "rh-smuggling" and store it as "apiVersion"
    And I generate a unique API context from "/rh-smuggling" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}  |
      | name                   | ${CTX:apiName}             |
      | spec.displayName       | ${CTX:apiName}             |
      | spec.version           | ${CTX:apiVersion}          |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3000      |
      | spec.operations        | [{"method":"GET","path":"/get","policies":[{"name":"remove-headers","version":"v1","params":{"request":{"headers":[{"name":"X-Internal-Token"}]}}}]}] |
    Then the resource creation response should indicate successful deployment

    When I clear all headers
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 200
    And I send a raw "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" with headers:
      | X-Internal-Token | token-a    |
      | x-internal-token | token-b    |
      | X-INTERNAL-TOKEN | token-c    |
      | X-Client-Id      | client-123 |
    Then the response status code should be 200
    And the response should not contain echoed header "X-Internal-Token"
    And the response body should not contain "token-a"
    And the response body should not contain "token-b"
    And the response body should not contain "token-c"
    And the response should contain echoed header "X-Client-Id" with value "client-123"

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 404

  # RH29: The value of X-Client-Id carries a bare carriage return or line feed followed by text
  # that looks like a second header line naming the removed header. It is written to the socket as
  # it is here, with \r and \n as the bytes they name. The gateway either keeps the text inside
  # the X-Client-Id value or reads it as a separate X-Internal-Token header, which the policy then
  # removes. Either way, no X-Internal-Token header reaches the backend.
  Scenario Outline: Send CRLF-style values for a header targeted by the policy (<case>)
    Given I generate a unique value from "rh-crlf-<key>" and store it as "apiName"
    And I generate a unique API version from "rh-crlf-<key>" and store it as "apiVersion"
    And I generate a unique API context from "/rh-crlf-<key>" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}  |
      | name                   | ${CTX:apiName}             |
      | spec.displayName       | ${CTX:apiName}             |
      | spec.version           | ${CTX:apiVersion}          |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3000      |
      | spec.operations        | [{"method":"GET","path":"/get","policies":[{"name":"remove-headers","version":"v1","params":{"request":{"headers":[{"name":"X-Internal-Token"}]}}}]}] |
    Then the resource creation response should indicate successful deployment

    When I clear all headers
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 200
    And I send a raw "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" with headers:
      | X-Client-Id | <value> |
    Then the response status code should be 200
    And the response should not contain echoed header "X-Internal-Token"
    And the response should contain echoed header "X-Client-Id" containing "client-123"

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 404

    Examples:
      | case            | key | value                                  |
      | carriage return | cr  | client-123\rX-Internal-Token: injected |
      | line feed       | lf  | client-123\nX-Internal-Token: injected |
