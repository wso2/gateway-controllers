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

@ratelimit-redis-gcra
Feature: Advanced rate limit with the GCRA algorithm on the Redis backend
  As an API operator
  I want smooth rate enforcement whose state is kept in Redis
  So that the burst allowance and the replenishment rate are shared by every replica

  # The gateway of this runner uses algorithm=gcra over Redis (overlays/redis-gcra.toml), so the
  # decision is taken by the GCRA Lua script.

  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"

  # Fixed in gateway 1.2.0 by wso2/api-platform PR #2596 (https://github.com/wso2/api-platform/pull/2596): config.toml gains {{ env }} interpolation, so the Redis password reaches the policy.
  @skip-gw-1.1.0
  Scenario: The burst allowance is enforced by the Redis script and then replenished at the rate
    Given I generate a unique value from "arl-rgcra-burst" and store it as "apiName"
    And I generate a unique API version from "arl-rgcra-burst" and store it as "apiVersion"
    And I generate a unique API context from "/arl-rgcra-burst" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}         |
      | name                   | ${CTX:apiName}                   |
      | spec.displayName       | ${CTX:apiName}                   |
      | spec.version           | ${CTX:apiVersion}                |
      | spec.context           | ${CTX:apiContext}/$version       |
      | spec.upstream.main.url | http://testbench:3000            |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"GET","path":"/burst","policies":[{"name":"advanced-ratelimit","version":"v1","params":{"quotas":[{"name":"redis-burst","limits":[{"limit":1,"duration":"4s","burst":2}]}]}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    # An empty bucket admits exactly the burst, then refuses the next request.
    When I send 2 "GET" requests to "${CTX:apiContext}/${CTX:apiVersion}/burst"
    Then the response status code should be 200
    And the response header "X-RateLimit-Remaining" should be "0"
    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/burst"
    Then the response status code should be 429
    And the response header "Retry-After" should exist
    And the response header "X-RateLimit-Quota" should be "redis-burst"

    # One emission interval later a request is admitted again.
    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/burst" until status 200

    When I delete the API "${CTX:apiName}"
    Then the response should be successful

  # Fixed in gateway 1.2.0 by wso2/api-platform PR #2596 (https://github.com/wso2/api-platform/pull/2596): config.toml gains {{ env }} interpolation, so the Redis password reaches the policy.
  @skip-gw-1.1.0
  Scenario: Weighted and response-reported costs are charged by the Redis script
    Given I generate a unique value from "arl-rgcra-cost" and store it as "apiName"
    And I generate a unique API version from "arl-rgcra-cost" and store it as "apiVersion"
    And I generate a unique API context from "/arl-rgcra-cost" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}         |
      | name                   | ${CTX:apiName}                   |
      | spec.displayName       | ${CTX:apiName}                   |
      | spec.version           | ${CTX:apiVersion}                |
      | spec.context           | ${CTX:apiContext}/$version       |
      | spec.upstream.main.url | http://testbench:3008/scripted   |
      | spec.operations        | [{"method":"POST","path":"/get"},{"method":"POST","path":"/weighted","policies":[{"name":"advanced-ratelimit","version":"v1","params":{"quotas":[{"name":"rgcra-weighted","limits":[{"limit":10,"duration":"1h","burst":10}],"costExtraction":{"enabled":true,"sources":[{"type":"request_header","key":"X-Cost"}],"default":1}}]}}]},{"method":"POST","path":"/tokens","policies":[{"name":"advanced-ratelimit","version":"v1","params":{"quotas":[{"name":"rgcra-tokens","limits":[{"limit":20,"duration":"1h","burst":20}],"costExtraction":{"enabled":true,"sources":[{"type":"response_body","jsonPath":"$.usage.total_tokens"}],"default":1}}]}}]}] |
    Then the resource creation response should indicate successful deployment
    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 200 with body:
      """
      {"x_testbench_reply":{"body":{"ok":true}}}
      """

    When I set header "X-Cost" to "6"
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/weighted" with body:
      """
      {"x_testbench_reply":{"body":{"ok":true}}}
      """
    Then the response status code should be 200
    When I set header "X-Cost" to "6"
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/weighted" with body:
      """
      {"x_testbench_reply":{"body":{"ok":true}}}
      """
    Then the response status code should be 429
    When I set header "X-Cost" to "4"
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/weighted" with body:
      """
      {"x_testbench_reply":{"body":{"ok":true}}}
      """
    Then the response status code should be 200
    And I clear all headers
    And I authenticate using basic auth as "admin"

    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/tokens" with body:
      """
      {"x_testbench_reply":{"body":{"usage":{"total_tokens":30}}}}
      """
    Then the response status code should be 200
    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/tokens" with body:
      """
      {"x_testbench_reply":{"body":{"usage":{"total_tokens":1}}}}
      """
    Then the response status code should be 429

    When I delete the API "${CTX:apiName}"
    Then the response should be successful

  # Fixed in gateway 1.2.0 by wso2/api-platform PR #2596 (https://github.com/wso2/api-platform/pull/2596): config.toml gains {{ env }} interpolation, so the Redis password reaches the policy.
  @skip-gw-1.1.0
  Scenario: The strictest of several GCRA limits is enforced over Redis
    Given I generate a unique value from "arl-rgcra-multi" and store it as "apiName"
    And I generate a unique API version from "arl-rgcra-multi" and store it as "apiVersion"
    And I generate a unique API context from "/arl-rgcra-multi" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}         |
      | name                   | ${CTX:apiName}                   |
      | spec.displayName       | ${CTX:apiName}                   |
      | spec.version           | ${CTX:apiVersion}                |
      | spec.context           | ${CTX:apiContext}/$version       |
      | spec.upstream.main.url | http://testbench:3000            |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"GET","path":"/multi","policies":[{"name":"advanced-ratelimit","version":"v1","params":{"quotas":[{"name":"rgcra-multi","limits":[{"limit":5,"duration":"1h","burst":5},{"limit":2,"duration":"1h","burst":2}]}]}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I send 2 "GET" requests to "${CTX:apiContext}/${CTX:apiVersion}/multi"
    Then the response status code should be 200
    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/multi"
    Then the response status code should be 429

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
