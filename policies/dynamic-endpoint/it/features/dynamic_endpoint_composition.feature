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

@dynamic-endpoint
Feature: Dynamic endpoint combined with other policies
  As an API developer
  I want policies chained with dynamic-endpoint to run in their configured order
  So that choosing an upstream never skips or weakens another policy

  # The upstream definition "capture-upstream" points at the capture service, which records the
  # last request it received for each path and answers 204 for a path it never received. A
  # policy placed before dynamic-endpoint that rejects a request must leave that path unrecorded.
  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"
    And I resolve the "capture" service URL at "" and store it as "captureUpstream"
    And I split the URL "${CTX:captureUpstream}" into origin "captureOrigin" and base path "captureBasePath"

  Scenario: Authentication, rate limiting and header policies run in order with dynamic-endpoint
    Given I generate a unique value from "dynamic-chain" and store it as "apiName"
    And I generate a unique API context from "/dynamic-chain" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion               | ${CTX:gatewaySpecVersion}          |
      | name                     | ${CTX:apiName}                     |
      | spec.displayName         | Dynamic-Endpoint-Chain-API         |
      | spec.version             | v1.0                               |
      | spec.context             | ${CTX:apiContext}/$version         |
      | spec.upstream.main.url   | http://testbench:3000              |
      | spec.upstreamDefinitions | [{"name":"alt-upstream","basePath":"/alternate","upstreams":[{"url":"http://testbench:3000"}]}] |
      | spec.operations          | [{"method":"GET","path":"/s16/health"},{"method":"GET","path":"/s16/secured","policies":[{"name":"api-key-auth","version":"v1","params":{"key":"API-Key","in":"header"}},{"name":"basic-ratelimit","version":"v1","params":{"limits":[{"requests":3,"duration":"1h"}]}},{"name":"set-headers","version":"v1","params":{"request":{"headers":[{"name":"X-Added-Request","value":"added"}]},"response":{"headers":[{"name":"X-Added-Response","value":"added"}]}}},{"name":"dynamic-endpoint","version":"v1","params":{"targetUpstream":"alt-upstream"}}]}] |
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/v1.0/s16/health" until status 200
    And I send a "GET" request to "${CTX:apiContext}/v1.0/s16/secured" until status 401

    When I send a "POST" request to the "gateway-controller" service at "/rest-apis/${CTX:apiName}/api-keys" with body:
      """
      {"name":"key-one"}
      """
    Then the response status should be 201
    And I store the JSON response field "apiKey.apiKey" as "chainKey"

    # The key reaches the policy engine after the create call returns, so the first request with
    # it is polled. Requests refused for a missing key do not count against the rate limit.
    When I clear all headers
    And I set header "API-Key" to "${CTX:chainKey}"
    And I send a "GET" request to "${CTX:apiContext}/v1.0/s16/secured" until status 200
    And the JSON response field "path" should be "/alternate/s16/secured"
    And the response should contain echoed header "X-Added-Request" with value "added"
    And the response header "X-Added-Response" should be "added"

    # The limit is three requests: one has been used, two are left, and the next is refused.
    When I send 2 "GET" requests to "${CTX:apiContext}/v1.0/s16/secured"
    Then the response status code should be 200
    When I send a "GET" request to "${CTX:apiContext}/v1.0/s16/secured"
    Then the response status code should be 429
    And the response body should not contain "/alternate"

    When I clear all headers
    And I send a "GET" request to "${CTX:apiContext}/v1.0/s16/secured"
    Then the response status code should be 401

  Scenario: A request rejected by authentication never reaches the selected upstream
    Given I generate a unique value from "dynamic-auth-first" and store it as "apiName"
    And I generate a unique API context from "/dynamic-auth-first" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion               | ${CTX:gatewaySpecVersion}          |
      | name                     | ${CTX:apiName}                     |
      | spec.displayName         | Dynamic-Endpoint-Auth-First-API    |
      | spec.version             | v1.0                               |
      | spec.context             | ${CTX:apiContext}/$version         |
      | spec.upstream.main.url   | http://testbench:3000              |
      | spec.upstreamDefinitions | [{"name":"capture-upstream","basePath":"${CTX:captureBasePath}","upstreams":[{"url":"${CTX:captureOrigin}"}]}] |
      | spec.operations          | [{"method":"GET","path":"/s34/health"},{"method":"GET","path":"/s34/protected","policies":[{"name":"api-key-auth","version":"v1","params":{"key":"API-Key","in":"header"}},{"name":"dynamic-endpoint","version":"v1","params":{"targetUpstream":"capture-upstream"}}]}] |
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/v1.0/s34/health" until status 200
    And I send a "GET" request to "${CTX:apiContext}/v1.0/s34/protected?attempt=missing" until status 401

    When I set header "API-Key" to "invalid-${CTX:apiName}"
    And I send a "GET" request to "${CTX:apiContext}/v1.0/s34/protected?attempt=invalid"
    Then the response status code should be 401
    When I send a "GET" request to the "capture" service at "/test/captured?path=/s34/protected" until status 204

    When I send a "POST" request to the "gateway-controller" service at "/rest-apis/${CTX:apiName}/api-keys" with body:
      """
      {"name":"key-one"}
      """
    Then the response status should be 201
    And I store the JSON response field "apiKey.apiKey" as "authKey"

    When I clear all headers
    And I set header "API-Key" to "${CTX:authKey}"
    And I send a "GET" request to "${CTX:apiContext}/v1.0/s34/protected?attempt=valid" until status 200
    Then the JSON response field "path" should be "/s34/protected"
    When I send a "GET" request to the "capture" service at "/test/captured?path=/s34/protected" until status 200
    Then the response body should contain "attempt=valid"

  Scenario: A request refused by rate limiting never reaches the selected upstream
    Given I generate a unique value from "dynamic-limit-first" and store it as "apiName"
    And I generate a unique API context from "/dynamic-limit-first" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion               | ${CTX:gatewaySpecVersion}          |
      | name                     | ${CTX:apiName}                     |
      | spec.displayName         | Dynamic-Endpoint-Limit-First-API   |
      | spec.version             | v1.0                               |
      | spec.context             | ${CTX:apiContext}/$version         |
      | spec.upstream.main.url   | http://testbench:3000              |
      | spec.upstreamDefinitions | [{"name":"capture-upstream","basePath":"${CTX:captureBasePath}","upstreams":[{"url":"${CTX:captureOrigin}"}]}] |
      | spec.operations          | [{"method":"GET","path":"/s35/health"},{"method":"GET","path":"/s35/limited","policies":[{"name":"basic-ratelimit","version":"v1","params":{"limits":[{"requests":2,"duration":"1h"}]}},{"name":"dynamic-endpoint","version":"v1","params":{"targetUpstream":"capture-upstream"}}]}] |
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/v1.0/s35/health" until status 200

    When I clear all headers
    And I send a "GET" request to "${CTX:apiContext}/v1.0/s35/limited?round=1"
    Then the response status code should be 200
    When I send a "GET" request to "${CTX:apiContext}/v1.0/s35/limited?round=2"
    Then the response status code should be 200
    When I send a "GET" request to "${CTX:apiContext}/v1.0/s35/limited?round=3"
    Then the response status code should be 429

    # The capture service holds the last request it received. It is the second one, so the
    # refused third request never reached it.
    When I send a "GET" request to the "capture" service at "/test/captured?path=/s35/limited" until status 200
    Then the response body should contain "round=2"
    And the response body should not contain "round=3"
