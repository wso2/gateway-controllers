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
Feature: Interceptor service policies
  As an API developer
  I want interceptor policies to modify requests and responses
  So that I can enforce interception behavior at the gateway

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

  # The fixed interceptor at testbench:3003 picks its reply by the request path. On a path with a
  # mutate segment it adds X-Interceptor-Request: true, rewrites the path to /anything/intercepted
  # and replaces the body with {"message":"mutated-by-interceptor"}.
  Scenario: Request interceptor mutates the path, headers, and body
    Given I generate a unique value from "interceptor-request-api" and store it as "apiName"
    And I generate a unique value from "interceptor-request-display" and store it as "apiDisplayName"
    And I generate a unique API version from "interceptor-request" and store it as "apiVersion"
    And I generate a unique API context from "/interceptor-request" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion            | ${CTX:gatewaySpecVersion}        |
      | name                  | ${CTX:apiName}                   |
      | spec.displayName      | ${CTX:apiDisplayName}             |
      | spec.version          | ${CTX:apiVersion}                 |
      | spec.context          | ${CTX:apiContext}/$version        |
      | spec.upstream.main.url | http://testbench:3000             |
      | spec.operations       | [{"method":"POST","path":"/mutate","policies":[{"name":"interceptor-service","version":"v1","params":{"endpoint":"http://testbench:3003","request":{"includeRequestHeaders":true,"includeRequestBody":true,"passthroughOnError":false}}}]}] |
    Then the response should be successful
    And I set header "Content-Type" to "application/json"
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/mutate" until status 200 with body:
      """
      {"client":"payload"}
      """
    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/mutate" with body:
      """
      {"client":"payload"}
      """
    Then the response status code should be 200
    And the response should be valid JSON
    And the JSON response field "path" should contain "/anything/intercepted"
    And the JSON response field "headers.X-Interceptor-Request[0]" should be "true"
    And the JSON response field "body" should contain "mutated-by-interceptor"
    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/mutate" until status 404

  # On a path with a block segment, the fixed interceptor answers with a direct 403 response that
  # carries X-Interceptor-Decision: blocked and {"error":"blocked by interceptor"}.
  Scenario: Request interceptor returns a direct response
    Given I generate a unique value from "interceptor-direct-api" and store it as "apiName"
    And I generate a unique value from "interceptor-direct-display" and store it as "apiDisplayName"
    And I generate a unique API version from "interceptor-direct" and store it as "apiVersion"
    And I generate a unique API context from "/interceptor-direct" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion            | ${CTX:gatewaySpecVersion}        |
      | name                  | ${CTX:apiName}                   |
      | spec.displayName      | ${CTX:apiDisplayName}             |
      | spec.version          | ${CTX:apiVersion}                 |
      | spec.context          | ${CTX:apiContext}/$version        |
      | spec.upstream.main.url | http://testbench:3000             |
      | spec.operations       | [{"method":"GET","path":"/block","policies":[{"name":"interceptor-service","version":"v1","params":{"endpoint":"http://testbench:3003","request":{"includeRequestHeaders":true,"includeRequestBody":false,"passthroughOnError":false}}}]}] |
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/block" until status 403
    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/block"
    Then the response status code should be 403
    And the response header "X-Interceptor-Decision" should be "blocked"
    And the response body should contain "blocked by interceptor"
    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/block" until status 404

  # On a path with a response-rewrite segment, the fixed interceptor sets trace=request-phase in the
  # request phase. In the response phase it answers 202 with X-Interceptor-Response: true,
  # X-Interceptor-Trace set to that trace, and {"message":"response-overridden"}.
  Scenario: Response interceptor rewrites the status, headers, and body
    Given I generate a unique value from "interceptor-response-api" and store it as "apiName"
    And I generate a unique value from "interceptor-response-display" and store it as "apiDisplayName"
    And I generate a unique API version from "interceptor-response" and store it as "apiVersion"
    And I generate a unique API context from "/interceptor-response" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion            | ${CTX:gatewaySpecVersion}        |
      | name                  | ${CTX:apiName}                   |
      | spec.displayName      | ${CTX:apiDisplayName}             |
      | spec.version          | ${CTX:apiVersion}                 |
      | spec.context          | ${CTX:apiContext}/$version        |
      | spec.upstream.main.url | http://testbench:3000             |
      | spec.operations       | [{"method":"GET","path":"/response-rewrite","policies":[{"name":"interceptor-service","version":"v1","params":{"endpoint":"http://testbench:3003","request":{"includeRequestHeaders":true,"includeRequestBody":false,"passthroughOnError":false},"response":{"includeRequestHeaders":true,"includeRequestBody":false,"includeResponseHeaders":true,"includeResponseBody":true,"passthroughOnError":false}}}]}] |
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/response-rewrite" until status 202
    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/response-rewrite"
    Then the response status code should be 202
    And the response header "X-Interceptor-Response" should be "true"
    And the response header "X-Interceptor-Trace" should be "request-phase"
    And the response body should contain "response-overridden"
    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/response-rewrite" until status 404

  # The response must match the expected error response recorded from the policy before a
  # change (resources/expected-error-responses), so a change a client could observe fails.
  # The endpoint is the echo service's /status/<code> route. The policy calls /status/handle-request,
  # which names no status code, so the call fails with 400.
  Scenario: interceptor-service refuses a request when the request-phase interceptor call fails
    Given I generate a unique value from "compat-is-req" and store it as "apiName"
    And I generate a unique API version from "compat-is-req" and store it as "apiVersion"
    And I generate a unique API context from "/compat-is-req" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3000 |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"POST","path":"/intercepted","policies":[{"name":"interceptor-service","version":"v1","params":{"endpoint":"http://testbench:3002/status","request":{"includeRequestHeaders":true,"includeRequestBody":true,"passthroughOnError":false}}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/intercepted" with body:
      """
      {"client":"payload"}
      """
    Then the response status code should be 500
    And the response should match the expected error response "interceptor-service-request-call-failed"
    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 404

  Scenario: Configure a valid request interceptor and invoke the API
    Given I generate a unique value from "is-r01" and store it as "apiName"
    And I generate a unique API version from "is-r01" and store it as "apiVersion"
    And I generate a unique API context from "/is-r01" and store it as "apiContext"
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
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/items" until status 200
    Then the JSON response field "headers.X-Intercepted[0]" should be "request"

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/items" until status 404

  Scenario: Configure a valid response interceptor and invoke the API
    Given I generate a unique value from "is-r02" and store it as "apiName"
    And I generate a unique API version from "is-r02" and store it as "apiVersion"
    And I generate a unique API context from "/is-r02" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3000 |
      | spec.operations        | [{"method":"GET","path":"/items","policies":[{"name":"interceptor-service","version":"v1","params":{"endpoint":"http://testbench:3003/scripted/${CTX:apiName}","response":{"includeRequestHeaders":true}}}]}] |
    Then the resource creation response should indicate successful deployment

    # Reply: {"headersToAdd":{"X-Intercepted":"response"},"body":<base64 of {"from":"interceptor"}>}
    When I set header "X-Testbench-Interceptor-Response-Reply" to "eyJoZWFkZXJzVG9BZGQiOnsiWC1JbnRlcmNlcHRlZCI6InJlc3BvbnNlIn0sImJvZHkiOiJleUptY205dElqb2lhVzUwWlhKalpYQjBiM0lpZlE9PSJ9"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/items" until status 200
    Then the response header "X-Intercepted" should be "response"
    And the JSON response field "from" should be "interceptor"

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/items" until status 404

  # The endpoint's /reflect segment makes the interceptor answer with the payload it received, so
  # the client sees what a response-only attachment with default flags sends: the response headers
  # and body, but not the request headers and body.
  Scenario: Configure a valid response interceptor and invoke the API (default flags)
    Given I generate a unique value from "is-r02d" and store it as "apiName"
    And I generate a unique API version from "is-r02d" and store it as "apiVersion"
    And I generate a unique API context from "/is-r02d" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3000 |
      | spec.operations        | [{"method":"GET","path":"/items","policies":[{"name":"interceptor-service","version":"v1","params":{"endpoint":"http://testbench:3003/scripted/${CTX:apiName}/reflect","response":{}}}]}] |
    Then the resource creation response should indicate successful deployment

    When I set header "X-Client" to "keep-me"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/items" until status 200
    Then the JSON response field "responseCode" should be 200
    And the JSON response should have field "responseHeaders"
    And the JSON response should have field "responseBody"
    And the JSON response field "requestHeaders" should not exist
    And the JSON response field "requestBody" should not exist

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/items" until status 404

  # The response phase reflects its payload to the client. It can only see request-first if the
  # request phase ran first and passed its context on. responseCode 200 shows the response phase ran
  # after the upstream answered.
  Scenario: Configure both request and response interception
    Given I generate a unique value from "is-r03" and store it as "apiName"
    And I generate a unique API version from "is-r03" and store it as "apiVersion"
    And I generate a unique API context from "/is-r03" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3000 |
      | spec.operations        | [{"method":"GET","path":"/items","policies":[{"name":"interceptor-service","version":"v1","params":{"endpoint":"http://testbench:3003/scripted/${CTX:apiName}","request":{},"response":{"includeRequestHeaders":true}}}]}] |
    Then the resource creation response should indicate successful deployment

    # Reply: {"interceptorContext":{"order":"request-first"}}
    When I set header "X-Testbench-Interceptor-Request-Reply" to "eyJpbnRlcmNlcHRvckNvbnRleHQiOnsib3JkZXIiOiJyZXF1ZXN0LWZpcnN0In19"
    And I set header "X-Testbench-Interceptor-Response-Mode" to "reflect"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/items" until status 200
    Then the JSON response field "interceptorContext.order" should be "request-first"
    And the JSON response field "responseCode" should be 200

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/items" until status 404

  Scenario: Interceptor modifies the request body
    Given I generate a unique value from "is-r08" and store it as "apiName"
    And I generate a unique API version from "is-r08" and store it as "apiVersion"
    And I generate a unique API context from "/is-r08" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3000 |
      | spec.operations        | [{"method":"POST","path":"/items","policies":[{"name":"interceptor-service","version":"v1","params":{"endpoint":"http://testbench:3003/scripted/${CTX:apiName}","request":{}}}]}] |
    Then the resource creation response should indicate successful deployment

    When I set header "Content-Type" to "application/json"
    # Reply: {"body":<base64 of {"replaced":true}>}
    And I set header "X-Testbench-Interceptor-Request-Reply" to "eyJib2R5IjoiZXlKeVpYQnNZV05sWkNJNmRISjFaWDA9In0="
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/items" until status 200 with body:
      """
      {"original":true}
      """
    Then the JSON response field "body" should be:
      """
      {"replaced":true}
      """

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/items" until status 404

  Scenario: Apply the interceptor at API level and invoke multiple operations
    Given I generate a unique value from "is-r04" and store it as "apiName"
    And I generate a unique API version from "is-r04" and store it as "apiVersion"
    And I generate a unique API context from "/is-r04" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3000 |
      | spec.policies          | [{"name":"interceptor-service","version":"v1","params":{"endpoint":"http://testbench:3003/scripted/${CTX:apiName}","request":{}}}] |
      | spec.operations        | [{"method":"GET","path":"/items"},{"method":"POST","path":"/orders"}] |
    Then the resource creation response should indicate successful deployment

    # Reply: {"headersToAdd":{"X-Intercepted":"request"}}
    When I set header "X-Testbench-Interceptor-Request-Reply" to "eyJoZWFkZXJzVG9BZGQiOnsiWC1JbnRlcmNlcHRlZCI6InJlcXVlc3QifX0="
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/items" until status 200
    Then the JSON response field "headers.X-Intercepted[0]" should be "request"

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/orders" with body:
      """
      {}
      """
    Then the response status code should be 200
    And the JSON response field "headers.X-Intercepted[0]" should be "request"

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/items" until status 404

  # One counted call for the two requests shows that /without never called the interceptor.
  Scenario: Apply the interceptor only to a selected operation
    Given I generate a unique value from "is-r05" and store it as "apiName"
    And I generate a unique API version from "is-r05" and store it as "apiVersion"
    And I generate a unique API context from "/is-r05" and store it as "apiContext"
    And I resolve the "fault-injection" service URL at "" and store it as "faultBase"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3000 |
      | spec.operations        | [{"method":"GET","path":"/with","policies":[{"name":"interceptor-service","version":"v1","params":{"endpoint":"${CTX:faultBase}/${CTX:apiName}/scripted/${CTX:apiName}","request":{}}}]},{"method":"GET","path":"/without"}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/without" until status 200

    When I send a "PUT" request to the "fault-injection" service at "/test/scripts/${CTX:apiName}" with body:
      """
      {"forwardPort":3003,"steps":[]}
      """
    Then the response should be successful

    # Reply: {"headersToAdd":{"X-Intercepted":"request"}}
    When I set header "X-Testbench-Interceptor-Request-Reply" to "eyJoZWFkZXJzVG9BZGQiOnsiWC1JbnRlcmNlcHRlZCI6InJlcXVlc3QifX0="
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/with"
    Then the response status code should be 200
    And the JSON response field "headers.X-Intercepted[0]" should be "request"

    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/without"
    Then the response status code should be 200
    And the JSON response field "headers.X-Intercepted" should not exist

    When I send a "GET" request to the "fault-injection" service at "/test/scripts/${CTX:apiName}"
    Then the response status code should be 200
    And the JSON response field "received" should be 1

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/without" until status 404

  # The interceptor answers {}. The count shows it was called, so the request reaches the backend
  # unchanged because of that reply, not because the call was skipped.
  Scenario: Interceptor returns the request/response without modification (request)
    Given I generate a unique value from "is-r06q" and store it as "apiName"
    And I generate a unique API version from "is-r06q" and store it as "apiVersion"
    And I generate a unique API context from "/is-r06q" and store it as "apiContext"
    And I resolve the "fault-injection" service URL at "" and store it as "faultBase"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3000 |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"POST","path":"/items/{id}","policies":[{"name":"interceptor-service","version":"v1","params":{"endpoint":"${CTX:faultBase}/${CTX:apiName}/scripted/${CTX:apiName}","request":{}}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I send a "PUT" request to the "fault-injection" service at "/test/scripts/${CTX:apiName}" with body:
      """
      {"forwardPort":3003,"steps":[]}
      """
    Then the response should be successful

    When I set header "Content-Type" to "application/json"
    And I set header "X-Client" to "keep-me"
    # Reply: {}
    And I set header "X-Testbench-Interceptor-Request-Reply" to "e30="
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/items/42?q=keep" with body:
      """
      {"k":"v"}
      """
    Then the response status code should be 200
    And the JSON response field "method" should be "POST"
    And the JSON response field "path" should be "/items/42"
    And the JSON response field "query" should be "q=keep"
    And the JSON response field "headers.X-Client[0]" should be "keep-me"
    And the JSON response field "body" should be:
      """
      {"k":"v"}
      """

    When I send a "GET" request to the "fault-injection" service at "/test/scripts/${CTX:apiName}"
    Then the response status code should be 200
    And the JSON response field "received" should be 1

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 404

  # The interceptor answers {}. The count shows the response phase called it, so the response comes
  # back unchanged because of that reply, not because the call was skipped.
  Scenario: Interceptor returns the request/response without modification (response)
    Given I generate a unique value from "is-r06s" and store it as "apiName"
    And I generate a unique API version from "is-r06s" and store it as "apiVersion"
    And I generate a unique API context from "/is-r06s" and store it as "apiContext"
    And I resolve the "fault-injection" service URL at "" and store it as "faultBase"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3000 |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"GET","path":"/items/{id}","policies":[{"name":"interceptor-service","version":"v1","params":{"endpoint":"${CTX:faultBase}/${CTX:apiName}/scripted/${CTX:apiName}","response":{"includeRequestHeaders":true}}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I send a "PUT" request to the "fault-injection" service at "/test/scripts/${CTX:apiName}" with body:
      """
      {"forwardPort":3003,"steps":[]}
      """
    Then the response should be successful

    When I set header "X-Client" to "keep-me"
    # Reply: {}
    And I set header "X-Testbench-Interceptor-Response-Reply" to "e30="
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/items/7"
    Then the response status code should be 200
    And the JSON response field "path" should be "/items/7"
    And the JSON response field "headers.X-Client[0]" should be "keep-me"

    When I send a "GET" request to the "fault-injection" service at "/test/scripts/${CTX:apiName}"
    Then the response status code should be 200
    And the JSON response field "received" should be 1

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 404

  Scenario: Interceptor adds, modifies, and removes request headers
    Given I generate a unique value from "is-r07" and store it as "apiName"
    And I generate a unique API version from "is-r07" and store it as "apiVersion"
    And I generate a unique API context from "/is-r07" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3000 |
      | spec.operations        | [{"method":"GET","path":"/items","policies":[{"name":"interceptor-service","version":"v1","params":{"endpoint":"http://testbench:3003/scripted/${CTX:apiName}","request":{}}}]}] |
    Then the resource creation response should indicate successful deployment

    When I set header "X-Modify" to "original"
    And I set header "X-Remove" to "gone"
    And I set header "X-Keep" to "kept"
    # Reply: {"headersToAdd":{"X-Added":"added"},"headersToReplace":{"X-Modify":"modified"},"headersToRemove":["X-Remove"]}
    And I set header "X-Testbench-Interceptor-Request-Reply" to "eyJoZWFkZXJzVG9BZGQiOnsiWC1BZGRlZCI6ImFkZGVkIn0sImhlYWRlcnNUb1JlcGxhY2UiOnsiWC1Nb2RpZnkiOiJtb2RpZmllZCJ9LCJoZWFkZXJzVG9SZW1vdmUiOlsiWC1SZW1vdmUiXX0="
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/items" until status 200
    Then the JSON response field "headers.X-Added[0]" should be "added"
    And the JSON response field "headers.X-Modify[0]" should be "modified"
    And the JSON response field "headers.X-Keep[0]" should be "kept"
    And the JSON response field "headers.X-Remove" should not exist

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/items" until status 404

  # On /analytics-headers the backend adds X-Allowed-Response: allowed, X-Denied-Response: denied and
  # X-Removed-Response: removed to its JSON reply. The interceptor replaces the first, removes the
  # third and replaces the body, so only X-Denied-Response reaches the client as the backend sent it.
  Scenario: Interceptor modifies response headers and body
    Given I generate a unique value from "is-r09" and store it as "apiName"
    And I generate a unique API version from "is-r09" and store it as "apiVersion"
    And I generate a unique API context from "/is-r09" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3000 |
      | spec.operations        | [{"method":"GET","path":"/analytics-headers","policies":[{"name":"interceptor-service","version":"v1","params":{"endpoint":"http://testbench:3003/scripted/${CTX:apiName}","response":{"includeRequestHeaders":true}}}]}] |
    Then the resource creation response should indicate successful deployment

    # Reply: {"headersToAdd":{"X-Resp-Added":"added"},"headersToReplace":{"X-Allowed-Response":"replaced"},"headersToRemove":["X-Removed-Response"],"body":<base64 of {"rewritten":true}>}
    When I set header "X-Testbench-Interceptor-Response-Reply" to "eyJoZWFkZXJzVG9BZGQiOnsiWC1SZXNwLUFkZGVkIjoiYWRkZWQifSwiaGVhZGVyc1RvUmVwbGFjZSI6eyJYLUFsbG93ZWQtUmVzcG9uc2UiOiJyZXBsYWNlZCJ9LCJoZWFkZXJzVG9SZW1vdmUiOlsiWC1SZW1vdmVkLVJlc3BvbnNlIl0sImJvZHkiOiJleUp5WlhkeWFYUjBaVzRpT25SeWRXVjkifQ=="
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/analytics-headers" until status 200
    Then the response header "X-Resp-Added" should be "added"
    And the response header "X-Allowed-Response" should be "replaced"
    And the response header "X-Denied-Response" should be "denied"
    And the response header "X-Removed-Response" should not exist
    And the response body should be:
      """
      {"rewritten":true}
      """

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/analytics-headers" until status 404

  # Gateway 1.1.0 does not apply a named upstream's base path, so this runs on 1.2.0 and later.
  Scenario: Interceptor routes the request to a named upstream
    Given the gateway version satisfies ">=1.2.0"
    And I generate a unique value from "is-dyn" and store it as "apiName"
    And I generate a unique API version from "is-dyn" and store it as "apiVersion"
    And I generate a unique API context from "/is-dyn" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion               | ${CTX:gatewaySpecVersion} |
      | name                     | ${CTX:apiName} |
      | spec.displayName         | ${CTX:apiName} |
      | spec.version             | ${CTX:apiVersion} |
      | spec.context             | ${CTX:apiContext}/$version |
      | spec.upstream.main.url   | http://testbench:3000 |
      | spec.upstreamDefinitions | [{"name":"alt-upstream","basePath":"/alternate","upstreams":[{"url":"http://testbench:3000"}]}] |
      | spec.operations          | [{"method":"GET","path":"/items","policies":[{"name":"interceptor-service","version":"v1","params":{"endpoint":"http://testbench:3003/scripted/${CTX:apiName}","request":{}}}]}] |
    Then the resource creation response should indicate successful deployment

    # Reply: {"dynamicEndpoint":{"endpointName":"alt-upstream"}}
    When I set header "X-Testbench-Interceptor-Request-Reply" to "eyJkeW5hbWljRW5kcG9pbnQiOnsiZW5kcG9pbnROYW1lIjoiYWx0LXVwc3RyZWFtIn19"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/items" until status 200
    Then the JSON response field "path" should be "/alternate/items"

    # Reply: {}
    When I set header "X-Testbench-Interceptor-Request-Reply" to "e30="
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/items"
    Then the response status code should be 200
    And the JSON response field "path" should be "/items"

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/items" until status 404
