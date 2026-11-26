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

  # passthroughOnError is left at its default, false, so the failed call returns 500.
  Scenario Outline: Configure an invalid or unreachable interceptor endpoint (<case>)
    Given I generate a unique value from "is-r18" and store it as "apiName"
    And I generate a unique API version from "is-r18" and store it as "apiVersion"
    And I generate a unique API context from "/is-r18" and store it as "apiContext"
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
    Given I generate a unique value from "is-r18n" and store it as "apiName"
    And I generate a unique API version from "is-r18n" and store it as "apiVersion"
    And I generate a unique API context from "/is-r18n" and store it as "apiContext"
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
    Given I generate a unique value from "is-r19q" and store it as "apiName"
    And I generate a unique API version from "is-r19q" and store it as "apiVersion"
    And I generate a unique API context from "/is-r19q" and store it as "apiContext"
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
    Given I generate a unique value from "is-r19s" and store it as "apiName"
    And I generate a unique API version from "is-r19s" and store it as "apiVersion"
    And I generate a unique API context from "/is-r19s" and store it as "apiContext"
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
    Given I generate a unique value from "is-r20q" and store it as "apiName"
    And I generate a unique API version from "is-r20q" and store it as "apiVersion"
    And I generate a unique API context from "/is-r20q" and store it as "apiContext"
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
    Given I generate a unique value from "is-r20s" and store it as "apiName"
    And I generate a unique API version from "is-r20s" and store it as "apiVersion"
    And I generate a unique API context from "/is-r20s" and store it as "apiContext"
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
    Given I generate a unique value from "is-r21" and store it as "apiName"
    And I generate a unique API version from "is-r21" and store it as "apiVersion"
    And I generate a unique API context from "/is-r21" and store it as "apiContext"
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
    Given I generate a unique value from "is-r21o" and store it as "apiName"
    And I generate a unique API version from "is-r21o" and store it as "apiVersion"
    And I generate a unique API context from "/is-r21o" and store it as "apiContext"
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
    Given I generate a unique value from "is-r22" and store it as "apiName"
    And I generate a unique API version from "is-r22" and store it as "apiVersion"
    And I generate a unique API context from "/is-r22" and store it as "apiContext"
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

  # No counted call after the wrong password shows the interceptor never ran. The capture service
  # records what reaches the upstream: its lookup answers 204 while nothing has, and 200 once a
  # request has. The right password then gives one call and one record, so both checks can see a call.
  Scenario: Invoke with invalid credentials when authentication is configured before the interceptor
    Given I generate a unique value from "is-r23" and store it as "apiName"
    And I generate a unique API version from "is-r23" and store it as "apiVersion"
    And I generate a unique API context from "/is-r23" and store it as "apiContext"
    And I resolve the "fault-injection" service URL at "" and store it as "faultBase"
    And I resolve the "capture" service URL at "" and store it as "captureUpstream"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | ${CTX:captureUpstream}/${CTX:apiName} |
      | spec.operations        | [{"method":"GET","path":"/items","policies":[{"name":"basic-auth","version":"v1","params":{"username":"is-user","password":"is-pass-0123"}},{"name":"interceptor-service","version":"v1","params":{"endpoint":"${CTX:faultBase}/${CTX:apiName}/scripted/${CTX:apiName}","request":{}}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/items" until status 401

    When I send a "PUT" request to the "fault-injection" service at "/test/scripts/${CTX:apiName}" with body:
      """
      {"forwardPort":3003,"steps":[]}
      """
    Then the response should be successful

    # Reply: {}
    When I set header "X-Testbench-Interceptor-Request-Reply" to "e30="
    And I set header "Authorization" to "Basic aXMtdXNlcjp3cm9uZy1wYXNz"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/items"
    Then the response status code should be 401

    When I send a "GET" request to the "fault-injection" service at "/test/scripts/${CTX:apiName}"
    Then the response status code should be 200
    And the JSON response field "received" should be 0

    When I send a "GET" request to the "capture" service at "/test/captured?path=/${CTX:apiName}/items"
    Then the response status code should be 204

    When I set header "Authorization" to "Basic aXMtdXNlcjppcy1wYXNzLTAxMjM="
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/items"
    Then the response status code should be 200

    When I send a "GET" request to the "fault-injection" service at "/test/scripts/${CTX:apiName}"
    Then the response status code should be 200
    And the JSON response field "received" should be 1

    When I send a "GET" request to the "capture" service at "/test/captured?path=/${CTX:apiName}/items"
    Then the response status code should be 200

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/items" until status 404

  # The interceptor is listed before basic-auth, and its reply replaces Authorization with the right
  # credentials. Authentication still runs first, in the request header phase, before the
  # interceptor sees the body: the wrong password gets 401 and no call reaches the interceptor.
  Scenario: Attempt to spoof or modify identity/authorization headers through the client or interceptor
    Given I generate a unique value from "is-r24" and store it as "apiName"
    And I generate a unique API version from "is-r24" and store it as "apiVersion"
    And I generate a unique API context from "/is-r24" and store it as "apiContext"
    And I resolve the "fault-injection" service URL at "" and store it as "faultBase"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3000 |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"GET","path":"/items","policies":[{"name":"interceptor-service","version":"v1","params":{"endpoint":"${CTX:faultBase}/${CTX:apiName}/scripted/${CTX:apiName}","request":{}}},{"name":"basic-auth","version":"v1","params":{"username":"is-user","password":"is-pass-0123"}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I send a "PUT" request to the "fault-injection" service at "/test/scripts/${CTX:apiName}" with body:
      """
      {"forwardPort":3003,"steps":[]}
      """
    Then the response should be successful

    # Reply: {"headersToReplace":{"Authorization":"Basic <base64 of is-user:is-pass-0123>"}}
    When I set header "X-Testbench-Interceptor-Request-Reply" to "eyJoZWFkZXJzVG9SZXBsYWNlIjp7IkF1dGhvcml6YXRpb24iOiJCYXNpYyBhWE10ZFhObGNqcHBjeTF3WVhOekxUQXhNak09In19"
    And I set header "Authorization" to "Basic aXMtdXNlcjp3cm9uZy1wYXNz"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/items"
    Then the response status code should be 401

    When I send a "GET" request to the "fault-injection" service at "/test/scripts/${CTX:apiName}"
    Then the response status code should be 200
    And the JSON response field "received" should be 0

    When I set header "Authorization" to "Basic aXMtdXNlcjppcy1wYXNzLTAxMjM="
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/items"
    Then the response status code should be 200

    When I send a "GET" request to the "fault-injection" service at "/test/scripts/${CTX:apiName}"
    Then the response status code should be 200
    And the JSON response field "received" should be 1

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 404

  # The first request reflects what the interceptor received; the second, with an empty reply,
  # shows what the backend received. Raw CR/LF in a header is not sent: HTTP clients and the
  # gateway's listener reject it before the policy runs.
  Scenario: Send malicious header/body content such as CRLF, script-like, SQL-like, or malformed input
    Given I generate a unique value from "is-r25" and store it as "apiName"
    And I generate a unique API version from "is-r25" and store it as "apiVersion"
    And I generate a unique API context from "/is-r25" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3000 |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"POST","path":"/items","policies":[{"name":"interceptor-service","version":"v1","params":{"endpoint":"http://testbench:3003/scripted/${CTX:apiName}","request":{}}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I set header "Content-Type" to "application/json"
    And I set header "X-Probe-Script" to "<script>alert(1)</script>"
    And I set header "X-Probe-Sql" to "' OR '1'='1' --"
    And I set header "X-Testbench-Interceptor-Request-Mode" to "reflect"
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/items" with body:
      """
      {"q": <script>alert(1)</script>
      """
    Then the response status code should be 200
    And the JSON response field "requestHeaders.x-probe-script" should be "<script>alert(1)</script>"
    And the JSON response field "requestHeaders.x-probe-sql" should be "' OR '1'='1' --"
    # requestBody is base64 of the client body, malformed on purpose: {"q": <script>alert(1)</script>
    And the JSON response field "requestBody" should be "eyJxIjogPHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="

    When I clear all headers
    And I set header "Content-Type" to "application/json"
    And I set header "X-Probe-Script" to "<script>alert(1)</script>"
    And I set header "X-Probe-Sql" to "' OR '1'='1' --"
    # Reply: {}
    And I set header "X-Testbench-Interceptor-Request-Reply" to "e30="
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/items" with body:
      """
      {"q": <script>alert(1)</script>
      """
    Then the response status code should be 200
    And the JSON response field "headers.X-Probe-Script[0]" should be "<script>alert(1)</script>"
    And the JSON response field "headers.X-Probe-Sql[0]" should be "' OR '1'='1' --"
    And the JSON response field "body" should be:
      """
      {"q": <script>alert(1)</script>
      """

    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health"
    Then the response status code should be 200

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 404

  # The client names a second fault-injection script, the decoy, in two headers, the query and the
  # body. The interceptor reflects what the policy sent it, which shows the policy received the decoy
  # in each place. The configured script counts the one call; the decoy counts none until it is
  # called directly, which shows it counts calls when they happen. The policy takes its endpoint only
  # from its configuration, so the field names tried stand for any the client might choose.
  Scenario: Attempt to control the interceptor destination using request headers, query parameters, body content, or URLs
    Given I generate a unique value from "is-r26" and store it as "apiName"
    And I generate a unique API version from "is-r26" and store it as "apiVersion"
    And I generate a unique API context from "/is-r26" and store it as "apiContext"
    And I generate a unique value from "is-r26-decoy" and store it as "decoyName"
    And I resolve the "fault-injection" service URL at "" and store it as "faultBase"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3000 |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"POST","path":"/items","policies":[{"name":"interceptor-service","version":"v1","params":{"endpoint":"${CTX:faultBase}/${CTX:apiName}/scripted/${CTX:apiName}","request":{}}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I send a "PUT" request to the "fault-injection" service at "/test/scripts/${CTX:apiName}" with body:
      """
      {"forwardPort":3003,"steps":[]}
      """
    Then the response should be successful

    When I send a "PUT" request to the "fault-injection" service at "/test/scripts/${CTX:decoyName}" with body:
      """
      {"forwardPort":3003,"steps":[]}
      """
    Then the response should be successful

    When I set header "Content-Type" to "application/json"
    And I set header "X-Interceptor-Endpoint" to "${CTX:faultBase}/${CTX:decoyName}/scripted/${CTX:decoyName}"
    And I set header "X-Endpoint" to "${CTX:faultBase}/${CTX:decoyName}/scripted/${CTX:decoyName}"
    And I set header "X-Testbench-Interceptor-Request-Mode" to "reflect"
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/items?endpoint=${CTX:faultBase}/${CTX:decoyName}/scripted/${CTX:decoyName}&interceptor=${CTX:faultBase}/${CTX:decoyName}/scripted/${CTX:decoyName}" with body:
      """
      {"endpoint":"${CTX:faultBase}/${CTX:decoyName}/scripted/${CTX:decoyName}","url":"${CTX:faultBase}/${CTX:decoyName}/scripted/${CTX:decoyName}"}
      """
    Then the response status code should be 200
    And the JSON response field "requestHeaders.x-interceptor-endpoint" should be "${CTX:faultBase}/${CTX:decoyName}/scripted/${CTX:decoyName}"
    And the JSON response field "requestHeaders.x-endpoint" should be "${CTX:faultBase}/${CTX:decoyName}/scripted/${CTX:decoyName}"
    And the JSON response field "invocationContext.path" should contain "interceptor="
    And the JSON response field "invocationContext.path" should contain "${CTX:decoyName}"
    # eyJlbmRwb2ludCI6 is base64 of {"endpoint":, the start of the client body.
    And the JSON response field "requestBody" should contain "eyJlbmRwb2ludCI6"

    When I send a "GET" request to the "fault-injection" service at "/test/scripts/${CTX:apiName}"
    Then the response status code should be 200
    And the JSON response field "received" should be 1

    When I send a "GET" request to the "fault-injection" service at "/test/scripts/${CTX:decoyName}"
    Then the response status code should be 200
    And the JSON response field "received" should be 0

    When I send a "POST" request to the "fault-injection" service at "/${CTX:decoyName}/scripted/${CTX:decoyName}/handle-request" with body:
      """
      {}
      """
    And I send a "GET" request to the "fault-injection" service at "/test/scripts/${CTX:decoyName}"
    Then the response status code should be 200
    And the JSON response field "received" should be 1

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 404

  # The gateway runtime trusts the certificate the testbench serves on https://testbench:3027, the
  # interceptor mock over HTTPS: /trusted gets the scripted reply through. 8446 serves a certificate
  # from a test CA the runtime does not trust and answers 200 to any caller, so only the certificate
  # check can make /untrusted fail. The policy has no client certificate setting, so mTLS is not
  # tested.
  Scenario: Use HTTPS/mTLS for the interceptor and test valid and invalid certificates
    Given I generate a unique value from "is-r27" and store it as "apiName"
    And I generate a unique API version from "is-r27" and store it as "apiVersion"
    And I generate a unique API context from "/is-r27" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3000 |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"GET","path":"/trusted","policies":[{"name":"interceptor-service","version":"v1","params":{"endpoint":"https://testbench:3027/scripted/${CTX:apiName}","request":{}}}]},{"method":"GET","path":"/untrusted","policies":[{"name":"interceptor-service","version":"v1","params":{"endpoint":"https://tls-backend:8446","request":{}}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    # Reply: {"headersToAdd":{"X-Intercepted":"request"}}
    When I set header "X-Testbench-Interceptor-Request-Reply" to "eyJoZWFkZXJzVG9BZGQiOnsiWC1JbnRlcmNlcHRlZCI6InJlcXVlc3QifX0="
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/trusted"
    Then the response status code should be 200
    And the JSON response field "path" should be "/trusted"
    And the JSON response field "headers.X-Intercepted[0]" should be "request"

    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/untrusted"
    Then the response status code should be 500
    And the response should match the expected error response "interceptor-service-request-call-failed"

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 404

  # includeRequestHeaders is false, so no request header goes to the interceptor. The endpoint's
  # /reflect path makes the interceptor answer with the payload it received: the body is in it, the
  # credentials are not.
  Scenario: Verify handling of sensitive data such as Authorization, cookies, API keys, and interceptor credentials (headers excluded)
    Given I generate a unique value from "is-r28h" and store it as "apiName"
    And I generate a unique API version from "is-r28h" and store it as "apiVersion"
    And I generate a unique API context from "/is-r28h" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | http://testbench:3000 |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"POST","path":"/items","policies":[{"name":"interceptor-service","version":"v1","params":{"endpoint":"http://testbench:3003/scripted/${CTX:apiName}/reflect","request":{"includeRequestHeaders":false}}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I set header "Content-Type" to "application/json"
    And I set header "Authorization" to "Bearer sec28-token-0123456789"
    And I set header "Cookie" to "session=sec28-cookie"
    And I set header "X-API-Key" to "sec28-key"
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/items" with body:
      """
      {"k":"v"}
      """
    Then the response status code should be 200
    # requestBody is base64 of the client body {"k":"v"}.
    And the JSON response field "requestBody" should be "eyJrIjoidiJ9"
    And the JSON response field "requestHeaders" should not exist
    And the response body should not contain "sec28-token-0123456789"
    And the response body should not contain "sec28-cookie"
    And the response body should not contain "sec28-key"

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 404

  # The request carries valid credentials. The interceptor answers 503, so the call fails: the
  # policy returns its 500 and nothing reaches the upstream, which the capture service records
  # (204 while nothing has arrived). A successful call then shows the record appear.
  Scenario: Simulate interceptor failure or compromise while handling a security-sensitive request (failure)
    Given I generate a unique value from "is-r29f" and store it as "apiName"
    And I generate a unique API version from "is-r29f" and store it as "apiVersion"
    And I generate a unique API context from "/is-r29f" and store it as "apiContext"
    And I resolve the "capture" service URL at "" and store it as "captureUpstream"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName} |
      | spec.displayName       | ${CTX:apiName} |
      | spec.version           | ${CTX:apiVersion} |
      | spec.context           | ${CTX:apiContext}/$version |
      | spec.upstream.main.url | ${CTX:captureUpstream}/${CTX:apiName} |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"GET","path":"/items","policies":[{"name":"basic-auth","version":"v1","params":{"username":"is-user","password":"is-pass-0123"}},{"name":"interceptor-service","version":"v1","params":{"endpoint":"http://testbench:3003/scripted/${CTX:apiName}","request":{}}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I set header "Authorization" to "Basic aXMtdXNlcjppcy1wYXNzLTAxMjM="
    And I set header "X-Testbench-Interceptor-Request-Status" to "503"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/items"
    Then the response status code should be 500
    And the response should match the expected error response "interceptor-service-request-call-failed"

    When I send a "GET" request to the "capture" service at "/test/captured?path=/${CTX:apiName}/items"
    Then the response status code should be 204

    When I clear all headers
    And I set header "Authorization" to "Basic aXMtdXNlcjppcy1wYXNzLTAxMjM="
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/items"
    Then the response status code should be 200

    When I send a "GET" request to the "capture" service at "/test/captured?path=/${CTX:apiName}/items"
    Then the response status code should be 200

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 404

  # The request passes basic-auth with valid credentials, then a compromised interceptor names an
  # upstream. A name the API defines is honoured: alt-upstream is the echo service, whose reply
  # carries a "url" field the main backend's does not. A name the API does not define gets the
  # gateway's 503, so the reply cannot send the request anywhere the API does not already route.
  # alt-upstream has no base path, so unlike the next scenario this runs on every gateway version.
  Scenario: Simulate interceptor failure or compromise while handling a security-sensitive request (compromised reply)
    Given I generate a unique value from "is-r29c" and store it as "apiName"
    And I generate a unique API version from "is-r29c" and store it as "apiVersion"
    And I generate a unique API context from "/is-r29c" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion               | ${CTX:gatewaySpecVersion} |
      | name                     | ${CTX:apiName} |
      | spec.displayName         | ${CTX:apiName} |
      | spec.version             | ${CTX:apiVersion} |
      | spec.context             | ${CTX:apiContext}/$version |
      | spec.upstream.main.url   | http://testbench:3000 |
      | spec.upstreamDefinitions | [{"name":"alt-upstream","upstreams":[{"url":"http://testbench:3002"}]}] |
      | spec.operations          | [{"method":"GET","path":"/health"},{"method":"GET","path":"/items","policies":[{"name":"basic-auth","version":"v1","params":{"username":"is-user","password":"is-pass-0123"}},{"name":"interceptor-service","version":"v1","params":{"endpoint":"http://testbench:3003/scripted/${CTX:apiName}","request":{}}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I set header "Authorization" to "Basic aXMtdXNlcjppcy1wYXNzLTAxMjM="
    # Reply: {"dynamicEndpoint":{"endpointName":"alt-upstream"}}
    And I set header "X-Testbench-Interceptor-Request-Reply" to "eyJkeW5hbWljRW5kcG9pbnQiOnsiZW5kcG9pbnROYW1lIjoiYWx0LXVwc3RyZWFtIn19"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/items" until status 200
    Then the JSON response field "url" should be "/items"

    # Reply: {"dynamicEndpoint":{"endpointName":"no-such-upstream"}}
    When I set header "X-Testbench-Interceptor-Request-Reply" to "eyJkeW5hbWljRW5kcG9pbnQiOnsiZW5kcG9pbnROYW1lIjoibm8tc3VjaC11cHN0cmVhbSJ9fQ=="
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/items"
    Then the response status code should be 503

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 404

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
