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

@ratelimit-gcra
Feature: Advanced rate limit with the GCRA algorithm
  As an API operator
  I want smooth rate enforcement with a configurable burst
  So that traffic is shaped evenly instead of being counted in fixed windows

  # The gateway of this runner is configured with algorithm=gcra, which is a system parameter
  # (overlays/gcra.toml). A GCRA limit of L per duration D admits one request every D/L once the
  # burst allowance is used.

  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"

  Scenario: Requests spaced at the emission interval keep being accepted
    Given I generate a unique value from "arl-gcra-spaced" and store it as "apiName"
    And I generate a unique API version from "arl-gcra-spaced" and store it as "apiVersion"
    And I generate a unique API context from "/arl-gcra-spaced" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}         |
      | name                   | ${CTX:apiName}                   |
      | spec.displayName       | ${CTX:apiName}                   |
      | spec.version           | ${CTX:apiVersion}                |
      | spec.context           | ${CTX:apiContext}/$version       |
      | spec.upstream.main.url | http://testbench:3000            |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"GET","path":"/steady","policies":[{"name":"advanced-ratelimit","version":"v1","params":{"quotas":[{"name":"steady","limits":[{"limit":1,"duration":"3s","burst":1}]}]}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/steady"
    Then the response status code should be 200

    # A second request straight away is faster than the rate allows.
    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/steady"
    Then the response status code should be 429
    And the response header "Retry-After" should exist

    # One emission interval later the next request is accepted, and so is the one after it.
    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/steady" until status 200
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/steady"
    Then the response status code should be 429
    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/steady" until status 200

    When I delete the API "${CTX:apiName}"
    Then the response should be successful

  Scenario: A burst above the allowance is throttled with headers describing the wait
    Given I generate a unique value from "arl-gcra-burst" and store it as "apiName"
    And I generate a unique API version from "arl-gcra-burst" and store it as "apiVersion"
    And I generate a unique API context from "/arl-gcra-burst" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}         |
      | name                   | ${CTX:apiName}                   |
      | spec.displayName       | ${CTX:apiName}                   |
      | spec.version           | ${CTX:apiVersion}                |
      | spec.context           | ${CTX:apiContext}/$version       |
      | spec.upstream.main.url | http://testbench:3000            |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"GET","path":"/burst","policies":[{"name":"advanced-ratelimit","version":"v1","params":{"quotas":[{"name":"burst-quota","limits":[{"limit":1,"duration":"1h","burst":3}]}]}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I send 3 "GET" requests to "${CTX:apiContext}/${CTX:apiVersion}/burst"
    Then the response status code should be 200
    And the response header "X-RateLimit-Remaining" should be "0"
    And the response header "RateLimit-Policy" should contain "burst-quota"

    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/burst"
    Then the response status code should be 429
    And the response header "X-RateLimit-Quota" should be "burst-quota"
    And the response header "Retry-After" should exist
    And the response header "X-RateLimit-Remaining" should be "0"
    And the response body should contain "Rate limit exceeded"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful

  # The same quota on a fixed window would hand out its whole allowance again at the next window
  # boundary (see ratelimit_window.feature). GCRA gives back one request per emission interval.
  Scenario: After throttling only one request per interval is replenished, not the whole quota
    Given I generate a unique value from "arl-gcra-smooth" and store it as "apiName"
    And I generate a unique API version from "arl-gcra-smooth" and store it as "apiVersion"
    And I generate a unique API context from "/arl-gcra-smooth" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}         |
      | name                   | ${CTX:apiName}                   |
      | spec.displayName       | ${CTX:apiName}                   |
      | spec.version           | ${CTX:apiVersion}                |
      | spec.context           | ${CTX:apiContext}/$version       |
      | spec.upstream.main.url | http://testbench:3000            |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"GET","path":"/smooth","policies":[{"name":"advanced-ratelimit","version":"v1","params":{"quotas":[{"name":"smooth","limits":[{"limit":3,"duration":"9s","burst":3}]}]}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/smooth" until status 429
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/smooth" until status 200
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/smooth"
    Then the response status code should be 429

    When I delete the API "${CTX:apiName}"
    Then the response should be successful

  Scenario: The strictest of several GCRA limits in one quota wins
    Given I generate a unique value from "arl-gcra-multi" and store it as "apiName"
    And I generate a unique API version from "arl-gcra-multi" and store it as "apiVersion"
    And I generate a unique API context from "/arl-gcra-multi" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}         |
      | name                   | ${CTX:apiName}                   |
      | spec.displayName       | ${CTX:apiName}                   |
      | spec.version           | ${CTX:apiVersion}                |
      | spec.context           | ${CTX:apiContext}/$version       |
      | spec.upstream.main.url | http://testbench:3000            |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"GET","path":"/multi","policies":[{"name":"advanced-ratelimit","version":"v1","params":{"quotas":[{"name":"multi-limit","limits":[{"limit":5,"duration":"1h","burst":5},{"limit":2,"duration":"1h","burst":2}]}]}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I send 2 "GET" requests to "${CTX:apiContext}/${CTX:apiVersion}/multi"
    Then the response status code should be 200
    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/multi"
    Then the response status code should be 429

    When I delete the API "${CTX:apiName}"
    Then the response should be successful

  Scenario: A weighted request is charged its full cost and refused when it does not fit
    Given I generate a unique value from "arl-gcra-weight" and store it as "apiName"
    And I generate a unique API version from "arl-gcra-weight" and store it as "apiVersion"
    And I generate a unique API context from "/arl-gcra-weight" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}         |
      | name                   | ${CTX:apiName}                   |
      | spec.displayName       | ${CTX:apiName}                   |
      | spec.version           | ${CTX:apiVersion}                |
      | spec.context           | ${CTX:apiContext}/$version       |
      | spec.upstream.main.url | http://testbench:3000            |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"POST","path":"/resource","policies":[{"name":"advanced-ratelimit","version":"v1","params":{"quotas":[{"name":"gcra-weighted","limits":[{"limit":10,"duration":"1h","burst":10}],"costExtraction":{"enabled":true,"sources":[{"type":"request_header","key":"X-Cost"}],"default":1}}]}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I set header "X-Cost" to "6"
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/resource" with body:
      """
      {}
      """
    Then the response status code should be 200
    And the response header "X-RateLimit-Remaining" should be "4"

    When I set header "X-Cost" to "6"
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/resource" with body:
      """
      {}
      """
    Then the response status code should be 429

    When I set header "X-Cost" to "4"
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/resource" with body:
      """
      {}
      """
    Then the response status code should be 200
    And the response header "X-RateLimit-Remaining" should be "0"
    And I clear all headers
    And I authenticate using basic auth as "admin"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful

  Scenario: A cost reported in the response is charged after the response and clamps at the quota
    Given I generate a unique value from "arl-gcra-response-cost" and store it as "apiName"
    And I generate a unique API version from "arl-gcra-response-cost" and store it as "apiVersion"
    And I generate a unique API context from "/arl-gcra-response-cost" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}         |
      | name                   | ${CTX:apiName}                   |
      | spec.displayName       | ${CTX:apiName}                   |
      | spec.version           | ${CTX:apiVersion}                |
      | spec.context           | ${CTX:apiContext}/$version       |
      | spec.upstream.main.url | http://testbench:3008/scripted   |
      | spec.operations        | [{"method":"GET","path":"/get"},{"method":"POST","path":"/chat","policies":[{"name":"advanced-ratelimit","version":"v1","params":{"quotas":[{"name":"gcra-tokens","limits":[{"limit":20,"duration":"1h","burst":20}],"costExtraction":{"enabled":true,"sources":[{"type":"response_body","jsonPath":"$.usage.total_tokens"}],"default":1}}]}}]}] |
    Then the resource creation response should indicate successful deployment
    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" until status 200 with body:
      """
      {"x_testbench_reply":{"body":{"usage":{"total_tokens":30}}}}
      """
    Then the response header "X-RateLimit-Limit" should be "20"
    And the response header "X-RateLimit-Remaining" should be "0"

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/chat" with body:
      """
      {"x_testbench_reply":{"body":{"usage":{"total_tokens":1}}}}
      """
    Then the response status code should be 429

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
