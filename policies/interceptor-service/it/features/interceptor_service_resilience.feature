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

@interceptor-service
Feature: Interceptor service policy when the interceptor call fails
  As an API developer
  I want to know how the policy handles a failed interceptor call or a reply it cannot use
  So that a failing interceptor has a predictable effect on the request

  # The backend answers any path with a JSON description of the request it received: method, path,
  # query, headers and body.
  #
  # A scripted interceptor call answers with the reply, status or delay named in the client's
  # X-Testbench-Interceptor-* headers, which the policy forwards to the interceptor.
  #
  # "request":{} turns on the request phase with its defaults: the request headers and body go to
  # the interceptor, and a failed call returns 500. "response":{} sends the response headers and
  # body but not the request's, so a scripted response-phase reply turns on includeRequestHeaders to
  # carry its controls. Other options are set only where a scenario tests them or needs another value.

  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"

  # passthroughOnError is left at its default, false, so the failed call returns 500.
  Scenario Outline: Configure an invalid or unreachable interceptor endpoint (<case>)
    Given I generate a unique value from "is-bad-endpoint" and store it as "apiName"
    And I generate a unique API version from "is-bad-endpoint" and store it as "apiVersion"
    And I generate a unique API context from "/is-bad-endpoint" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3000 |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"POST","path":"/intercepted","policies":[{"name":"interceptor-service","version":"v1","params":{"endpoint":"<endpoint>","request":{}}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I set header "Content-Type" to "application/json"
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/intercepted" with body:
      """
      {"client":"payload"}
      """
    Then the response status code should be 500
    And the response should match the expected error response "interceptor-service-request-call-failed"

    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health"
    Then the response status code should be 200

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 404

    Examples:
      | case                          | endpoint                   |
      | closed port                   | http://testbench:3999      |
      | unknown host                  | http://interceptor.invalid |
      | host and port without http:// | testbench:3003             |

  # Go's URL parser rejects "not a url", so the policy cannot be built for /intercepted, although
  # the API deploys. The gateway answers that route with its own 500; the other route keeps working.
  Scenario: Configure an invalid or unreachable interceptor endpoint (endpoint the policy rejects)
    Given I generate a unique value from "is-invalid-url" and store it as "apiName"
    And I generate a unique API version from "is-invalid-url" and store it as "apiVersion"
    And I generate a unique API context from "/is-invalid-url" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3000 |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"POST","path":"/intercepted","policies":[{"name":"interceptor-service","version":"v1","params":{"endpoint":"not a url","request":{}}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/intercepted" with body:
      """
      {"client":"payload"}
      """
    Then the response status code should be 500
    And the response body should contain "Internal Server Error"

    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health"
    Then the response status code should be 200

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 404

  # passthroughOnError is left at its default, false, so the failed call returns 500.
  Scenario Outline: Interceptor returns HTTP 4xx or 5xx responses (request phase, <status>)
    Given I generate a unique value from "is-error-req" and store it as "apiName"
    And I generate a unique API version from "is-error-req" and store it as "apiVersion"
    And I generate a unique API context from "/is-error-req" and store it as "apiContext"
    And I resolve the "capture" service URL at "" and store it as "captureUpstream"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | ${CTX:captureUpstream}/${CTX:apiName} |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"GET","path":"/items","policies":[{"name":"interceptor-service","version":"v1","params":{"endpoint":"http://testbench:3003/scripted/${CTX:apiName}","request":{}}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I set header "X-Testbench-Interceptor-Request-Status" to "<status>"
    # Reply: {"headersToAdd":{"X-Should-Not":"apply"}}
    And I set header "X-Testbench-Interceptor-Request-Reply" to "eyJoZWFkZXJzVG9BZGQiOnsiWC1TaG91bGQtTm90IjoiYXBwbHkifX0="
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/items"
    Then the response status code should be 500
    And the response should match the expected error response "interceptor-service-request-call-failed"

    When I send a "GET" request to the "capture" service at "/test/captured?path=/${CTX:apiName}/items"
    Then the response status code should be 204

    When I send a "GET" request to the "capture" service at "/test/captured?path=/${CTX:apiName}/health"
    Then the response status code should be 200

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 404

    Examples:
      | status |
      | 403    |
      | 503    |

  # passthroughOnError is left at its default, false, so the failed call returns 500.
  Scenario Outline: Interceptor returns HTTP 4xx or 5xx responses (response phase, <status>)
    Given I generate a unique value from "is-error-resp" and store it as "apiName"
    And I generate a unique API version from "is-error-resp" and store it as "apiVersion"
    And I generate a unique API context from "/is-error-resp" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3000 |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"GET","path":"/items","policies":[{"name":"interceptor-service","version":"v1","params":{"endpoint":"http://testbench:3003/scripted/${CTX:apiName}","response":{"includeRequestHeaders":true}}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I set header "X-Testbench-Interceptor-Response-Status" to "<status>"
    # Reply: {"headersToAdd":{"X-Should-Not":"apply"}}
    And I set header "X-Testbench-Interceptor-Response-Reply" to "eyJoZWFkZXJzVG9BZGQiOnsiWC1TaG91bGQtTm90IjoiYXBwbHkifX0="
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/items"
    Then the response status code should be 500
    And the response should match the expected error response "interceptor-service-request-call-failed"
    And the response header "X-Should-Not" should not exist

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 404

    Examples:
      | status |
      | 400    |
      | 502    |

  # The interceptor answers after 2 seconds: /short gives up after 500 ms, /long waits 5 seconds.
  # passthroughOnError is left at its default, false, so the timed-out call returns 500.
  Scenario: Interceptor exceeds the configured timeout (request phase)
    Given I generate a unique value from "is-timeout-request" and store it as "apiName"
    And I generate a unique API version from "is-timeout-request" and store it as "apiVersion"
    And I generate a unique API context from "/is-timeout-request" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3000 |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"GET","path":"/short","policies":[{"name":"interceptor-service","version":"v1","params":{"endpoint":"http://testbench:3003/scripted/${CTX:apiName}","request":{},"timeoutMillis":500}}]},{"method":"GET","path":"/long","policies":[{"name":"interceptor-service","version":"v1","params":{"endpoint":"http://testbench:3003/scripted/${CTX:apiName}","request":{},"timeoutMillis":5000}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I set header "X-Testbench-Interceptor-Request-Delay-Ms" to "2000"
    # Reply: {}
    And I set header "X-Testbench-Interceptor-Request-Reply" to "e30="
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/short"
    Then the response status code should be 500
    And the response should match the expected error response "interceptor-service-request-call-failed"

    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/long"
    Then the response status code should be 200

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 404

  # The interceptor answers after 2 seconds: /short gives up after 500 ms, /long waits 5 seconds.
  # passthroughOnError is left at its default, false, so the timed-out call returns 500.
  Scenario: Interceptor exceeds the configured timeout (response phase)
    Given I generate a unique value from "is-timeout-response" and store it as "apiName"
    And I generate a unique API version from "is-timeout-response" and store it as "apiVersion"
    And I generate a unique API context from "/is-timeout-response" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3000 |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"GET","path":"/short","policies":[{"name":"interceptor-service","version":"v1","params":{"endpoint":"http://testbench:3003/scripted/${CTX:apiName}","response":{"includeRequestHeaders":true},"timeoutMillis":500}}]},{"method":"GET","path":"/long","policies":[{"name":"interceptor-service","version":"v1","params":{"endpoint":"http://testbench:3003/scripted/${CTX:apiName}","response":{"includeRequestHeaders":true},"timeoutMillis":5000}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I set header "X-Testbench-Interceptor-Response-Delay-Ms" to "2000"
    # Reply: {}
    And I set header "X-Testbench-Interceptor-Response-Reply" to "e30="
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/short"
    Then the response status code should be 500
    And the response should match the expected error response "interceptor-service-request-call-failed"

    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/long"
    Then the response status code should be 200

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 404

  # The interceptor answers 200 with these exact bytes.
  # passthroughOnError is left at its default, false, so the unusable reply returns 500.
  Scenario Outline: Interceptor returns malformed or unexpected data (<case>)
    Given I generate a unique value from "is-malformed-reply" and store it as "apiName"
    And I generate a unique API version from "is-malformed-reply" and store it as "apiVersion"
    And I generate a unique API context from "/is-malformed-reply" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3000 |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"GET","path":"/items","policies":[{"name":"interceptor-service","version":"v1","params":{"endpoint":"http://testbench:3003/scripted/${CTX:apiName}","request":{}}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I set header "X-Testbench-Interceptor-Request-Reply" to "<replyBase64>"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/items"
    Then the response status code should be 500
    And the response should match the expected error response "interceptor-service-request-call-failed"

    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health"
    Then the response status code should be 200

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 404

    # replyBase64 decodes to: not JSON: not json; JSON array: []; wrong field type:
    # {"headersToAdd":["a"]}; truncated JSON: {"headersToAdd":{"x":
    Examples:
      | case             | replyBase64                      |
      | not JSON         | bm90IGpzb24=                     |
      | JSON array       | W10=                             |
      | wrong field type | eyJoZWFkZXJzVG9BZGQiOlsiYSJdfQ== |
      | truncated JSON   | eyJoZWFkZXJzVG9BZGQiOnsieCI6     |

  # For /big the backend echoes the policy's call, so the interceptor's answer carries the whole body
  # base64-encoded, over the 1 MiB reply limit. /big-ok sends the same body to an interceptor that
  # answers {}. passthroughOnError is left at its default, false, so the oversize reply returns 500.
  Scenario: Interceptor returns malformed or unexpected data (oversize reply)
    Given I generate a unique value from "is-oversize-reply" and store it as "apiName"
    And I generate a unique API version from "is-oversize-reply" and store it as "apiVersion"
    And I generate a unique API context from "/is-oversize-reply" and store it as "apiContext"
    And I generate a value of 800 KiB of "x" and store it as "bigBody"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3000 |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"POST","path":"/big","policies":[{"name":"interceptor-service","version":"v1","params":{"endpoint":"http://testbench:3000","request":{}}}]},{"method":"POST","path":"/big-ok","policies":[{"name":"interceptor-service","version":"v1","params":{"endpoint":"http://testbench:3003/scripted/${CTX:apiName}","request":{}}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I set header "Content-Type" to "application/json"
    # Reply: {}
    And I set header "X-Testbench-Interceptor-Request-Reply" to "e30="
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/big" with body:
      """
      {"data":"${CTX:bigBody}"}
      """
    Then the response status code should be 500
    And the response should match the expected error response "interceptor-service-request-call-failed"

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/big-ok" with body:
      """
      {"data":"${CTX:bigBody}"}
      """
    Then the response status code should be 200

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 404

  # ?statusCode=503 makes the backend answer 503, still with its JSON description of the request.
  Scenario: Backend fails after successful interception
    Given I generate a unique value from "is-backend-fails" and store it as "apiName"
    And I generate a unique API version from "is-backend-fails" and store it as "apiVersion"
    And I generate a unique API context from "/is-backend-fails" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3000 |
      | spec.operations        | [{"method":"GET","path":"/items","policies":[{"name":"interceptor-service","version":"v1","params":{"endpoint":"http://testbench:3003/scripted/${CTX:apiName}","request":{}}}]}] |
    Then the resource creation response should indicate successful deployment

    # Reply: {"headersToAdd":{"X-Intercepted":"request"}}
    When I set header "X-Testbench-Interceptor-Request-Reply" to "eyJoZWFkZXJzVG9BZGQiOnsiWC1JbnRlcmNlcHRlZCI6InJlcXVlc3QifX0="
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/items?statusCode=503" until status 503
    Then the JSON response field "headers.X-Intercepted[0]" should be "request"
    And the response body should not contain "Internal Server Error"

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/items" until status 404

  # The interceptor answers 503 on both routes, so every call fails. /closed leaves passthroughOnError
  # at its default, false, and returns the policy's 500; /open sets it to true, so the request
  # carries on to the backend unchanged, as the documented opt-in for graceful degradation.
  Scenario: Interceptor failure passes through when passthroughOnError is true (request phase)
    Given I generate a unique value from "is-pt-req" and store it as "apiName"
    And I generate a unique API version from "is-pt-req" and store it as "apiVersion"
    And I generate a unique API context from "/is-pt-req" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3000 |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"GET","path":"/closed","policies":[{"name":"interceptor-service","version":"v1","params":{"endpoint":"http://testbench:3003/scripted/${CTX:apiName}","request":{}}}]},{"method":"GET","path":"/open","policies":[{"name":"interceptor-service","version":"v1","params":{"endpoint":"http://testbench:3003/scripted/${CTX:apiName}","request":{"passthroughOnError":true}}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I set header "X-Testbench-Interceptor-Request-Status" to "503"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/closed"
    Then the response status code should be 500
    And the response should match the expected error response "interceptor-service-request-call-failed"

    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/open"
    Then the response status code should be 200
    And the JSON response field "path" should be "/open"
    And the JSON response field "headers.X-Testbench-Interceptor-Request-Status[0]" should be "503"

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 404

  # The same in the response phase: on /open the backend's response reaches the client unchanged
  # although the interceptor call fails; on /closed it is replaced by the policy's 500.
  Scenario: Interceptor failure passes through when passthroughOnError is true (response phase)
    Given I generate a unique value from "is-pt-resp" and store it as "apiName"
    And I generate a unique API version from "is-pt-resp" and store it as "apiVersion"
    And I generate a unique API context from "/is-pt-resp" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3000 |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"GET","path":"/closed","policies":[{"name":"interceptor-service","version":"v1","params":{"endpoint":"http://testbench:3003/scripted/${CTX:apiName}","response":{"includeRequestHeaders":true}}}]},{"method":"GET","path":"/open","policies":[{"name":"interceptor-service","version":"v1","params":{"endpoint":"http://testbench:3003/scripted/${CTX:apiName}","response":{"includeRequestHeaders":true,"passthroughOnError":true}}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I set header "X-Testbench-Interceptor-Response-Status" to "503"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/closed"
    Then the response status code should be 500
    And the response should match the expected error response "interceptor-service-request-call-failed"

    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/open"
    Then the response status code should be 200
    And the JSON response field "path" should be "/open"
    And the JSON response field "method" should be "GET"

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 404
