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
Feature: Interceptor service policy against hostile and sensitive input
  As an API developer
  I want client input and credentials handled safely around the interceptor call
  So that a client cannot bypass the interceptor, choose where it is called, or expose credentials through it

  # The backend answers any path with a JSON description of the request it received: method, path,
  # query, headers and body.
  #
  # A scripted interceptor call answers with the reply, status or delay named in the client's
  # X-Testbench-Interceptor-* headers, which the policy forwards to the interceptor.
  #
  # A reflected reply is the payload the interceptor received, as JSON: requestHeaders (names in
  # lower case), requestBody (base64) and invocationContext (method, path, apiName, apiVersion and
  # more). A field the policy was not told to send is absent.
  #
  # "request":{} turns on the request phase with its defaults: the request headers and body go to
  # the interceptor, and a failed call returns 500. Other options are set only where a scenario tests
  # them or needs another value.
  #
  # The interceptor keeps no count of its calls. A scenario that must show whether the interceptor was
  # called points the policy at a fault-injection script instead, which forwards each call unchanged
  # to the interceptor and counts it in "received".

  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"

  # No counted call after the wrong password shows the interceptor never ran. The capture service
  # records what reaches the upstream: its lookup answers 204 while nothing has, and 200 once a
  # request has. The right password then gives one call and one record, so both checks can see a call.
  Scenario: Invoke with invalid credentials when authentication is configured before the interceptor
    Given I generate a unique value from "is-invalid-creds" and store it as "apiName"
    And I generate a unique API version from "is-invalid-creds" and store it as "apiVersion"
    And I generate a unique API context from "/is-invalid-creds" and store it as "apiContext"
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
    When I clear all headers
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
    Given I generate a unique value from "is-spoof-identity" and store it as "apiName"
    And I generate a unique API version from "is-spoof-identity" and store it as "apiVersion"
    And I generate a unique API context from "/is-spoof-identity" and store it as "apiContext"
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
    Given I generate a unique value from "is-hostile-content" and store it as "apiName"
    And I generate a unique API version from "is-hostile-content" and store it as "apiVersion"
    And I generate a unique API context from "/is-hostile-content" and store it as "apiContext"
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
    Given I generate a unique value from "is-destination" and store it as "apiName"
    And I generate a unique API version from "is-destination" and store it as "apiVersion"
    And I generate a unique API context from "/is-destination" and store it as "apiContext"
    And I generate a unique value from "is-destination-decoy" and store it as "decoyName"
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
    Given I generate a unique value from "is-https" and store it as "apiName"
    And I generate a unique API version from "is-https" and store it as "apiVersion"
    And I generate a unique API context from "/is-https" and store it as "apiContext"
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
    Given I generate a unique value from "is-headers-excluded" and store it as "apiName"
    And I generate a unique API version from "is-headers-excluded" and store it as "apiVersion"
    And I generate a unique API context from "/is-headers-excluded" and store it as "apiContext"
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
    And I set header "Authorization" to "Bearer is-excluded-token-0123456789"
    And I set header "Cookie" to "session=is-excluded-cookie"
    And I set header "X-API-Key" to "is-excluded-key"
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/items" with body:
      """
      {"k":"v"}
      """
    Then the response status code should be 200
    # requestBody is base64 of the client body {"k":"v"}.
    And the JSON response field "requestBody" should be "eyJrIjoidiJ9"
    And the JSON response field "requestHeaders" should not exist
    And the response body should not contain "is-excluded-token-0123456789"
    And the response body should not contain "is-excluded-cookie"
    And the response body should not contain "is-excluded-key"

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 404

  # The request carries valid credentials. The interceptor answers 503, so the call fails: the
  # policy returns its 500 and nothing reaches the upstream, which the capture service records
  # (204 while nothing has arrived). A successful call then shows the record appear.
  Scenario: Simulate interceptor failure or compromise while handling a security-sensitive request (failure)
    Given I generate a unique value from "is-sensitive-failure" and store it as "apiName"
    And I generate a unique API version from "is-sensitive-failure" and store it as "apiVersion"
    And I generate a unique API context from "/is-sensitive-failure" and store it as "apiContext"
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
    Given I generate a unique value from "is-compromised-reply" and store it as "apiName"
    And I generate a unique API version from "is-compromised-reply" and store it as "apiVersion"
    And I generate a unique API context from "/is-compromised-reply" and store it as "apiContext"
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
