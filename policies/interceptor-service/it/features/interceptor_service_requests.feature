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
Feature: Interceptor service policy across request types, other policies and configuration changes
  As an API developer
  I want interception to work for every kind of request, beside other policies and across configuration changes
  So that interception behaves the same whatever traffic and setup an API has

  # The backend answers any path with a JSON description of the request it received: method, path,
  # query, headers and body.
  #
  # A scripted interceptor call answers with the reply, status or delay named in the client's
  # X-Testbench-Interceptor-* headers, which the policy forwards to the interceptor.
  #
  # A reflected reply is the payload the interceptor received, as JSON: requestHeaders (names in
  # lower case), requestBody (base64) and invocationContext (method, path, apiName, apiVersion and
  # more). The response phase adds responseCode, responseHeaders, responseBody and the
  # interceptorContext the request phase set. A field the policy was not told to send is absent.
  #
  # "request":{} turns on the request phase with its defaults: the request headers and body go to
  # the interceptor, and a failed call returns 500. "response":{} sends the response headers and
  # body but not the request's, so a scripted response-phase reply turns on includeRequestHeaders to
  # carry its controls. Other options are set only where a scenario tests them or needs another value.
  #
  # The interceptor keeps no count of its calls. A scenario that must show whether the interceptor was
  # called points the policy at a fault-injection script instead, which forwards each call unchanged
  # to the interceptor and counts it in "received".

  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"

  # The first call reflects what the interceptor received; the second shows what the backend received.
  # The request phase sends the request headers by default, so the reflected payload carries them.
  Scenario Outline: Invoke with different HTTP methods, query parameters, path parameters, and custom headers (<method>)
    Given I generate a unique value from "is-r10" and store it as "apiName"
    And I generate a unique API version from "is-r10" and store it as "apiVersion"
    And I generate a unique API context from "/is-r10" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3000 |
      | spec.policies          | [{"name":"interceptor-service","version":"v1","params":{"endpoint":"http://testbench:3003/scripted/${CTX:apiName}","request":{}}}] |
      | spec.operations        | [{"method":"GET","path":"/items/{id}"},{"method":"POST","path":"/items/{id}"},{"method":"PUT","path":"/items/{id}"},{"method":"DELETE","path":"/items/{id}"},{"method":"PATCH","path":"/items/{id}"}] |
    Then the resource creation response should indicate successful deployment

    When I set header "X-Custom" to "custom-value"
    And I set header "X-Testbench-Interceptor-Request-Mode" to "reflect"
    And I send a "<method>" request to "${CTX:apiContext}/${CTX:apiVersion}/items/42?q=v1&r=v2" until status 200
    Then the JSON response field "invocationContext.method" should be "<method>"
    And the JSON response field "invocationContext.path" should contain "/items/42"
    And the JSON response field "invocationContext.path" should contain "q=v1&r=v2"
    And the JSON response field "invocationContext.pathTemplate" should contain "/items/{id}"
    And the JSON response field "requestHeaders.x-custom" should be "custom-value"

    When I clear all headers
    And I set header "X-Custom" to "custom-value"
    # Reply: {"headersToAdd":{"X-Intercepted":"request"}}
    And I set header "X-Testbench-Interceptor-Request-Reply" to "eyJoZWFkZXJzVG9BZGQiOnsiWC1JbnRlcmNlcHRlZCI6InJlcXVlc3QifX0="
    And I send a "<method>" request to "${CTX:apiContext}/${CTX:apiVersion}/items/42?q=v1&r=v2"
    Then the response status code should be 200
    And the JSON response field "method" should be "<method>"
    And the JSON response field "path" should be "/items/42"
    And the JSON response field "query" should be "q=v1&r=v2"
    And the JSON response field "headers.X-Custom[0]" should be "custom-value"
    And the JSON response field "headers.X-Intercepted[0]" should be "request"

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/items/1" until status 404

    Examples:
      | method |
      | GET    |
      | POST   |
      | PUT    |
      | DELETE |
      | PATCH  |

  Scenario: Send empty, JSON, Unicode, and large payloads (empty)
    Given I generate a unique value from "is-r11e" and store it as "apiName"
    And I generate a unique API version from "is-r11e" and store it as "apiVersion"
    And I generate a unique API context from "/is-r11e" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3000 |
      | spec.operations        | [{"method":"POST","path":"/payload","policies":[{"name":"interceptor-service","version":"v1","params":{"endpoint":"http://testbench:3003/scripted/${CTX:apiName}","request":{}}}]}] |
    Then the resource creation response should indicate successful deployment

    # Reply: {"headersToAdd":{"X-Intercepted":"request"}}
    When I set header "X-Testbench-Interceptor-Request-Reply" to "eyJoZWFkZXJzVG9BZGQiOnsiWC1JbnRlcmNlcHRlZCI6InJlcXVlc3QifX0="
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/payload" until status 200
    Then the JSON response field "headers.X-Intercepted[0]" should be "request"
    And the JSON response field "body" should not exist

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/payload" until status 404

  Scenario Outline: Send empty, JSON, Unicode, and large payloads (<case>)
    Given I generate a unique value from "is-r11" and store it as "apiName"
    And I generate a unique API version from "is-r11" and store it as "apiVersion"
    And I generate a unique API context from "/is-r11" and store it as "apiContext"
    And I generate a value of 512 KiB of "x" and store it as "largeBody"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3000 |
      | spec.operations        | [{"method":"POST","path":"/payload","policies":[{"name":"interceptor-service","version":"v1","params":{"endpoint":"http://testbench:3003/scripted/${CTX:apiName}","request":{}}}]},{"method":"GET","path":"/health"}] |
    Then the resource creation response should indicate successful deployment

    When I set header "Content-Type" to "application/json"
    # Reply: {"headersToAdd":{"X-Intercepted":"request"}}
    And I set header "X-Testbench-Interceptor-Request-Reply" to "eyJoZWFkZXJzVG9BZGQiOnsiWC1JbnRlcmNlcHRlZCI6InJlcXVlc3QifX0="
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/payload" until status 200 with body:
      """
      <body>
      """
    Then the JSON response field "body" should be:
      """
      <body>
      """
    And the JSON response field "headers.X-Intercepted[0]" should be "request"

    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health"
    Then the response status code should be 200

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 404

    Examples:
      | case    | body                         |
      | JSON    | {"a":[1,2,3],"b":{"c":null}} |
      | Unicode | {"text":"héllo wörld 世界 🚀"}  |
      | large   | {"data":"${CTX:largeBody}"}  |

  # The limit is two requests an hour. Readiness is polled without credentials, so it uses none of
  # them. Two counted calls, one for each allowed request, show that neither the request without
  # credentials nor the throttled one reached the interceptor.
  Scenario: Combine interceptor with authentication and rate limiting
    Given I generate a unique value from "is-r12" and store it as "apiName"
    And I generate a unique API version from "is-r12" and store it as "apiVersion"
    And I generate a unique API context from "/is-r12" and store it as "apiContext"
    And I resolve the "fault-injection" service URL at "" and store it as "faultBase"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3000 |
      | spec.operations        | [{"method":"GET","path":"/items","policies":[{"name":"basic-auth","version":"v1","params":{"username":"is-user","password":"is-pass-0123"}},{"name":"basic-ratelimit","version":"v1","params":{"limits":[{"requests":2,"duration":"1h"}]}},{"name":"interceptor-service","version":"v1","params":{"endpoint":"${CTX:faultBase}/${CTX:apiName}/scripted/${CTX:apiName}","request":{}}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/items" until status 401

    When I send a "PUT" request to the "fault-injection" service at "/test/scripts/${CTX:apiName}" with body:
      """
      {"forwardPort":3003,"steps":[]}
      """
    Then the response should be successful

    # Reply: {"headersToAdd":{"X-Intercepted":"request"}}
    When I set header "X-Testbench-Interceptor-Request-Reply" to "eyJoZWFkZXJzVG9BZGQiOnsiWC1JbnRlcmNlcHRlZCI6InJlcXVlc3QifX0="
    And I set header "Authorization" to "Basic aXMtdXNlcjppcy1wYXNzLTAxMjM="
    And I set header "X-Seq" to "seq-one"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/items"
    Then the response status code should be 200
    And the JSON response field "headers.X-Intercepted[0]" should be "request"

    When I set header "X-Seq" to "seq-two"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/items"
    Then the response status code should be 200
    And the JSON response field "headers.X-Intercepted[0]" should be "request"

    When I set header "X-Seq" to "seq-three"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/items"
    Then the response status code should be 429

    When I send a "GET" request to the "fault-injection" service at "/test/scripts/${CTX:apiName}"
    Then the response status code should be 200
    And the JSON response field "received" should be 2

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/items" until status 404

  Scenario: Apply request transformation before the interceptor
    Given I generate a unique value from "is-r13" and store it as "apiName"
    And I generate a unique API version from "is-r13" and store it as "apiVersion"
    And I generate a unique API context from "/is-r13" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3000 |
      | spec.operations        | [{"method":"GET","path":"/items","policies":[{"name":"set-headers","version":"v1","params":{"request":{"headers":[{"name":"X-Transformed","value":"set-before-interceptor"}]}}},{"name":"interceptor-service","version":"v1","params":{"endpoint":"http://testbench:3003/scripted/${CTX:apiName}","request":{}}}]}] |
    Then the resource creation response should indicate successful deployment

    When I set header "X-Testbench-Interceptor-Request-Mode" to "reflect"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/items" until status 200
    Then the JSON response field "requestHeaders.x-transformed" should be "set-before-interceptor"

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/items" until status 404

  # The upstream records what it received; the mediator converts the JSON body it is handed to XML.
  Scenario: Apply another transformation after the interceptor
    Given I generate a unique value from "is-r14" and store it as "apiName"
    And I generate a unique API version from "is-r14" and store it as "apiVersion"
    And I generate a unique API context from "/is-r14" and store it as "apiContext"
    And I resolve the "capture" service URL at "" and store it as "captureUpstream"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | ${CTX:captureUpstream}/${CTX:apiName} |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"POST","path":"/convert","policies":[{"name":"interceptor-service","version":"v1","params":{"endpoint":"http://testbench:3003/scripted/${CTX:apiName}","request":{}}},{"name":"json-xml-mediator","version":"v1","params":{"downsteamPayloadFormat":"json","upstreamPayloadFormat":"xml"}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I set header "Content-Type" to "application/json"
    # Reply: {"body":<base64 of {"marker":"from-interceptor"}>}
    And I set header "X-Testbench-Interceptor-Request-Reply" to "eyJib2R5IjoiZXlKdFlYSnJaWElpT2lKbWNtOXRMV2x1ZEdWeVkyVndkRzl5SW4wPSJ9"
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/convert" with body:
      """
      {"marker":"from-client"}
      """
    And I send a "GET" request to the "capture" service at "/test/captured?path=/${CTX:apiName}/convert"
    Then the response status code should be 200
    And the JSON response field "body" should contain "<marker>from-interceptor</marker>"
    And the response body should not contain "from-client"

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 404

  # The interceptor reflects what it received, and the update turns on sending the request body.
  # eyJrIjoidiJ9 is base64 of the client body {"k":"v"}.
  # The poll waits until a request shows the new configuration. The five requests after it check
  # that every later request does too, and none falls back to the old configuration.
  Scenario: Update or remove interceptor configuration on a deployed API (update)
    Given I generate a unique value from "is-r15u" and store it as "apiName"
    And I generate a unique API version from "is-r15u" and store it as "apiVersion"
    And I generate a unique API context from "/is-r15u" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3000 |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"POST","path":"/items","policies":[{"name":"interceptor-service","version":"v1","params":{"endpoint":"http://testbench:3003/scripted/${CTX:apiName}","request":{"includeRequestBody":false}}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I set header "Content-Type" to "application/json"
    And I set header "X-Testbench-Interceptor-Request-Mode" to "reflect"
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/items" with body:
      """
      {"k":"v"}
      """
    Then the response status code should be 200
    And the JSON response field "requestBody" should not exist

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I update API "${CTX:apiName}" from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3000 |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"POST","path":"/items","policies":[{"name":"interceptor-service","version":"v1","params":{"endpoint":"http://testbench:3003/scripted/${CTX:apiName}","request":{"includeRequestBody":true}}}]}] |
    Then the API update response should indicate successful deployment
    When I set header "Content-Type" to "application/json"
    And I set header "X-Testbench-Interceptor-Request-Mode" to "reflect"
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/items" until the response body contains "eyJrIjoidiJ9" with body:
      """
      {"k":"v"}
      """

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/items" with body:
      """
      {"k":"v"}
      """
    Then the response status code should be 200
    And the JSON response field "requestBody" should be "eyJrIjoidiJ9"

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/items" with body:
      """
      {"k":"v"}
      """
    Then the response status code should be 200
    And the JSON response field "requestBody" should be "eyJrIjoidiJ9"

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/items" with body:
      """
      {"k":"v"}
      """
    Then the response status code should be 200
    And the JSON response field "requestBody" should be "eyJrIjoidiJ9"

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/items" with body:
      """
      {"k":"v"}
      """
    Then the response status code should be 200
    And the JSON response field "requestBody" should be "eyJrIjoidiJ9"

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/items" with body:
      """
      {"k":"v"}
      """
    Then the response status code should be 200
    And the JSON response field "requestBody" should be "eyJrIjoidiJ9"

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 404

  # The interceptor's reply sets 203 and X-Intercepted: response, so the poll after the update waits
  # for 200, the first response the interceptor no longer touches. The five requests after it check
  # that every later request is untouched too, and none falls back to the old configuration.
  Scenario: Update or remove interceptor configuration on a deployed API (remove)
    Given I generate a unique value from "is-r15r" and store it as "apiName"
    And I generate a unique API version from "is-r15r" and store it as "apiVersion"
    And I generate a unique API context from "/is-r15r" and store it as "apiContext"
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

    # Reply: {"responseCode":203,"headersToAdd":{"X-Intercepted":"response"}}
    When I set header "X-Testbench-Interceptor-Response-Reply" to "eyJyZXNwb25zZUNvZGUiOjIwMywiaGVhZGVyc1RvQWRkIjp7IlgtSW50ZXJjZXB0ZWQiOiJyZXNwb25zZSJ9fQ=="
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/items"
    Then the response status code should be 203
    And the response header "X-Intercepted" should be "response"

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I update API "${CTX:apiName}" from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3000 |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"GET","path":"/items"}] |
    Then the API update response should indicate successful deployment
    # Reply: {"responseCode":203,"headersToAdd":{"X-Intercepted":"response"}}
    When I set header "X-Testbench-Interceptor-Response-Reply" to "eyJyZXNwb25zZUNvZGUiOjIwMywiaGVhZGVyc1RvQWRkIjp7IlgtSW50ZXJjZXB0ZWQiOiJyZXNwb25zZSJ9fQ=="
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/items" until status 200

    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/items"
    Then the response status code should be 200
    And the response header "X-Intercepted" should not exist

    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/items"
    Then the response status code should be 200
    And the response header "X-Intercepted" should not exist

    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/items"
    Then the response status code should be 200
    And the response header "X-Intercepted" should not exist

    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/items"
    Then the response status code should be 200
    And the response header "X-Intercepted" should not exist

    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/items"
    Then the response status code should be 200
    And the response header "X-Intercepted" should not exist

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 404

  # The two header values are interceptor replies: {"directRespond":true,"responseCode":201} and
  # the same with 202. The concurrent step sends 100 requests, 25 at a time, alternating the two,
  # and checks every response: each must return the status in its own value's row, so a reply that
  # reached the wrong request, or a request that was not intercepted (200), fails it.
  Scenario: Send concurrent/high-volume requests through the interceptor
    Given I generate a unique value from "is-r17" and store it as "apiName"
    And I generate a unique API version from "is-r17" and store it as "apiVersion"
    And I generate a unique API context from "/is-r17" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3000 |
      | spec.operations        | [{"method":"GET","path":"/items","policies":[{"name":"interceptor-service","version":"v1","params":{"endpoint":"http://testbench:3003/scripted/${CTX:apiName}","request":{}}}]}] |
    Then the resource creation response should indicate successful deployment
    # Reply: {"directRespond":true,"responseCode":201}
    When I set header "X-Testbench-Interceptor-Request-Reply" to "eyJkaXJlY3RSZXNwb25kIjp0cnVlLCJyZXNwb25zZUNvZGUiOjIwMX0="
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/items" until status 201

    When I send 100 concurrent "GET" requests to "${CTX:apiContext}/${CTX:apiVersion}/items" alternating the "X-Testbench-Interceptor-Request-Reply" header:
      | eyJkaXJlY3RSZXNwb25kIjp0cnVlLCJyZXNwb25zZUNvZGUiOjIwMX0= | 201 |
      | eyJkaXJlY3RSZXNwb25kIjp0cnVlLCJyZXNwb25zZUNvZGUiOjIwMn0= | 202 |

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/items" until status 404
