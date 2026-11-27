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
Feature: Set headers policy header matching
  As an API developer
  I want configured headers set exactly once, however the client sends them
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

  # SH05: The policy sets X-Flow on both flows, with a different value on each. Each flow must apply
  # its own value only: the backend receives the request value and the client the response value.
  Scenario: Set headers on both the request and response flows
    Given I generate a unique value from "sh-both-flows" and store it as "apiName"
    And I generate a unique API version from "sh-both-flows" and store it as "apiVersion"
    And I generate a unique API context from "/sh-both-flows" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}               |
      | name                   | ${CTX:apiName}                          |
      | spec.displayName       | ${CTX:apiName}                          |
      | spec.version           | ${CTX:apiVersion}                       |
      | spec.context           | ${CTX:apiContext}/$version              |
      | spec.upstream.main.url | http://testbench:3000/analytics-headers |
      | spec.operations        | [{"method":"GET","path":"/get","policies":[{"name":"set-headers","version":"v1","params":{"request":{"headers":[{"name":"X-Flow","value":"request-value"}]},"response":{"headers":[{"name":"X-Flow","value":"response-value"}]}}}]}] |
    Then the resource creation response should indicate successful deployment

    When I clear all headers
    And I set header "X-Client-Id" to "client-123"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 200
    Then the response should contain echoed header "X-Flow" with value "request-value"
    And the response should contain echoed header "X-Client-Id" with value "client-123"
    And the response header "X-Flow" should be "response-value"
    And the response header "X-Allowed-Response" should be "allowed"

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 404

  # SH09: Header names are case-insensitive. The policy is configured with a header name in one case
  # and the client sends the header over a raw connection in another, so the case reaches the
  # gateway exactly as written. The response header the backend returns is configured in its own
  # case too. Each must end as one header holding the configured value.
  Scenario Outline: Set headers regardless of the case of their names (<case>)
    Given I generate a unique value from "sh-case-<key>" and store it as "apiName"
    And I generate a unique API version from "sh-case-<key>" and store it as "apiVersion"
    And I generate a unique API context from "/sh-case-<key>" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}               |
      | name                   | ${CTX:apiName}                          |
      | spec.displayName       | ${CTX:apiName}                          |
      | spec.version           | ${CTX:apiVersion}                       |
      | spec.context           | ${CTX:apiContext}/$version              |
      | spec.upstream.main.url | http://testbench:3000/analytics-headers |
      | spec.operations        | [{"method":"GET","path":"/get","policies":[{"name":"set-headers","version":"v1","params":{"request":{"headers":[{"name":"<configured>","value":"configured-value"}]},"response":{"headers":[{"name":"<configuredResponse>","value":"configured-value"}]}}}]}] |
    Then the resource creation response should indicate successful deployment

    When I clear all headers
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 200
    And I send a raw "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" with headers:
      | <sent>      | client-value |
      | X-Client-Id | client-123   |
    Then the response status code should be 200
    And the response should contain echoed header "X-Test" with value "configured-value"
    And the response body should not contain "client-value"
    And the response should contain echoed header "X-Client-Id" with value "client-123"
    And the response header "X-Allowed-Response" should be "configured-value"

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 404

    Examples:
      | case                           | key   | configured | sent   | configuredResponse |
      | X-Test configured, x-test sent | title | X-Test     | x-test | X-Allowed-Response |
      | x-test configured, X-TEST sent | lower | x-test     | X-TEST | x-allowed-response |
      | X-TEST configured, X-Test sent | upper | X-TEST     | X-Test | X-ALLOWED-RESPONSE |

  # SH28: The policy is configured to set X-Gateway-Tenant to a value that carries a line break
  # followed by a second header line, X-Injected. HTTP forbids CR and LF in a header value, so the
  # gateway must never send the extra header. The gateway accepts the configuration, and every
  # request to the operation then fails with 500 before reaching the backend, so neither the
  # extra header nor the request is forwarded.
  Scenario Outline: Configure a header value that carries CR/LF (<case>)
    Given I generate a unique value from "sh-crlf-<key>" and store it as "apiName"
    And I generate a unique API version from "sh-crlf-<key>" and store it as "apiVersion"
    And I generate a unique API context from "/sh-crlf-<key>" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}  |
      | name                   | ${CTX:apiName}             |
      | spec.displayName       | ${CTX:apiName}             |
      | spec.version           | ${CTX:apiVersion}          |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3000      |
      | spec.operations        | [{"method":"GET","path":"/get","policies":[{"name":"set-headers","version":"v1","params":{"request":{"headers":[{"name":"X-Gateway-Tenant","value":"<value>"}]}}}]}] |
    Then the resource creation response should indicate successful deployment

    When I clear all headers
    And I set header "X-Client-Id" to "client-123"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 500
    Then the response status code should be 500
    And the response body should not contain "X-Injected"
    And the response body should not contain "client-123"

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 404

    Examples:
      | case                          | key  | value                         |
      | carriage return and line feed | crlf | tenant-a\\r\\nX-Injected: yes |
      | line feed                     | lf   | tenant-a\\nX-Injected: yes    |
      | carriage return               | cr   | tenant-a\\rX-Injected: yes    |

  # SH29: The policy sets a security-sensitive header: a forwarding header, an identity header or a
  # CORS response header. The request must still be routed to the configured upstream path, and
  # the header must change only as configured.
  Scenario Outline: Set security-sensitive headers (<case>)
    Given I generate a unique value from "sh-sensitive-<key>" and store it as "apiName"
    And I generate a unique API version from "sh-sensitive-<key>" and store it as "apiVersion"
    And I generate a unique API context from "/sh-sensitive-<key>" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}               |
      | name                   | ${CTX:apiName}                          |
      | spec.displayName       | ${CTX:apiName}                          |
      | spec.version           | ${CTX:apiVersion}                       |
      | spec.context           | ${CTX:apiContext}/$version              |
      | spec.upstream.main.url | http://testbench:3000/analytics-headers |
      | spec.operations        | [{"method":"GET","path":"/get","policies":[{"name":"set-headers","version":"v1","params":<params>}]}] |
    Then the resource creation response should indicate successful deployment

    When I clear all headers
    And I set header "X-Client-Id" to "client-123"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 200
    Then the JSON response field "path" should be "/analytics-headers/get"
    And the response should contain echoed header "X-Client-Id" with value "client-123"
    And the <check>

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 404

    Examples:
      | case                 | key       | params                                                                                          | check                                                                             |
      | forwarding header    | forwarded | {"request":{"headers":[{"name":"X-Forwarded-For","value":"203.0.113.10"}]}}                     | response should contain echoed header "X-Forwarded-For" containing "203.0.113.10" |
      | identity header      | identity  | {"request":{"headers":[{"name":"X-User-Id","value":"service-account"}]}}                        | response should contain echoed header "X-User-Id" with value "service-account"    |
      | CORS response header | cors      | {"response":{"headers":[{"name":"Access-Control-Allow-Origin","value":"https://app.example"}]}} | response header "Access-Control-Allow-Origin" should be "https://app.example"     |

  # SH29: Host is a routing header, which the host-rewrite policy sets. set-headers must not be able
  # to change where a request goes. The gateway accepts a configuration that names Host, but does
  # not let a policy change a routing header, so every request to the operation fails with 500
  # before reaching the backend, and the request is never routed with the configured Host.
  Scenario: Set the Host header
    Given I generate a unique value from "sh-sensitive-host" and store it as "apiName"
    And I generate a unique API version from "sh-sensitive-host" and store it as "apiVersion"
    And I generate a unique API context from "/sh-sensitive-host" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}  |
      | name                   | ${CTX:apiName}             |
      | spec.displayName       | ${CTX:apiName}             |
      | spec.version           | ${CTX:apiVersion}          |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3000      |
      | spec.operations        | [{"method":"GET","path":"/get","policies":[{"name":"set-headers","version":"v1","params":{"request":{"headers":[{"name":"Host","value":"sh-configured.example"}]}}}]}] |
    Then the resource creation response should indicate successful deployment

    When I clear all headers
    And I set header "X-Client-Id" to "client-123"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 500
    Then the response status code should be 500
    And the response body should not contain "sh-configured.example"
    And the response body should not contain "client-123"

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 404
