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

@ratelimit-redis
Feature: Advanced rate limit on the Redis backend with fail-open behaviour
  As an API operator running several gateway replicas
  I want quota state to live in Redis and keep working through a Redis outage
  So that the quota is shared, survives a gateway restart and degrades to open instead of failing requests

  # The gateway of this runner uses fixed-window over Redis with failure_mode=open
  # (overlays/redis.toml). Scenarios that stop Redis start it again before they end, and run last.

  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"

  Scenario: A quota kept in Redis is enforced with correct headers
    Given I generate a unique value from "arl-redis-basic" and store it as "apiName"
    And I generate a unique API version from "arl-redis-basic" and store it as "apiVersion"
    And I generate a unique API context from "/arl-redis-basic" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}         |
      | name                   | ${CTX:apiName}                   |
      | spec.displayName       | ${CTX:apiName}                   |
      | spec.version           | ${CTX:apiVersion}                |
      | spec.context           | ${CTX:apiContext}/$version       |
      | spec.upstream.main.url | http://testbench:3000            |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"GET","path":"/resource","policies":[{"name":"advanced-ratelimit","version":"v1","params":{"quotas":[{"name":"redis-quota","limits":[{"limit":3,"duration":"1h"}],"keyExtraction":[{"type":"header","key":"X-User-ID"}]}]}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I set header "X-User-ID" to "alice"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/resource"
    Then the response status code should be 200
    And the response header "X-RateLimit-Limit" should be "3"
    And the response header "X-RateLimit-Remaining" should be "2"
    And the response header "RateLimit-Policy" should contain "redis-quota"
    When I send 2 "GET" requests to "${CTX:apiContext}/${CTX:apiVersion}/resource"
    Then the response status code should be 200
    And the response header "X-RateLimit-Remaining" should be "0"
    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/resource"
    Then the response status code should be 429
    And the response header "Retry-After" should exist
    And the response header "X-RateLimit-Quota" should be "redis-quota"
    And the "gateway-runtime" service logs should not contain the Redis password

    When I set header "X-User-ID" to "bob"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/resource"
    Then the response status code should be 200
    And the response header "X-RateLimit-Remaining" should be "2"
    And I clear all headers
    And I authenticate using basic auth as "admin"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful

  Scenario: The strictest of several Redis-backed limits in one quota wins
    Given I generate a unique value from "arl-redis-multi" and store it as "apiName"
    And I generate a unique API version from "arl-redis-multi" and store it as "apiVersion"
    And I generate a unique API context from "/arl-redis-multi" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}         |
      | name                   | ${CTX:apiName}                   |
      | spec.displayName       | ${CTX:apiName}                   |
      | spec.version           | ${CTX:apiVersion}                |
      | spec.context           | ${CTX:apiContext}/$version       |
      | spec.upstream.main.url | http://testbench:3000            |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"GET","path":"/resource","policies":[{"name":"advanced-ratelimit","version":"v1","params":{"quotas":[{"name":"redis-multi","limits":[{"limit":5,"duration":"1h"},{"limit":2,"duration":"24h"}]}]}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I send 2 "GET" requests to "${CTX:apiContext}/${CTX:apiVersion}/resource"
    Then the response status code should be 200
    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/resource"
    Then the response status code should be 429

    When I delete the API "${CTX:apiName}"
    Then the response should be successful

  Scenario: Weighted requests and response-reported costs are charged in Redis
    Given I generate a unique value from "arl-redis-cost" and store it as "apiName"
    And I generate a unique API version from "arl-redis-cost" and store it as "apiVersion"
    And I generate a unique API context from "/arl-redis-cost" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}         |
      | name                   | ${CTX:apiName}                   |
      | spec.displayName       | ${CTX:apiName}                   |
      | spec.version           | ${CTX:apiVersion}                |
      | spec.context           | ${CTX:apiContext}/$version       |
      | spec.upstream.main.url | http://testbench:3008/scripted   |
      | spec.operations        | [{"method":"POST","path":"/get"},{"method":"POST","path":"/weighted","policies":[{"name":"advanced-ratelimit","version":"v1","params":{"quotas":[{"name":"redis-weighted","limits":[{"limit":10,"duration":"1h"}],"costExtraction":{"enabled":true,"sources":[{"type":"request_header","key":"X-Cost"}],"default":1}}]}}]},{"method":"POST","path":"/tokens","policies":[{"name":"advanced-ratelimit","version":"v1","params":{"quotas":[{"name":"redis-tokens","limits":[{"limit":20,"duration":"1h"}],"costExtraction":{"enabled":true,"sources":[{"type":"response_body","jsonPath":"$.usage.total_tokens"}],"default":1}}]}}]}] |
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
    And the response header "X-RateLimit-Remaining" should be "4"
    When I set header "X-Cost" to "6"
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/weighted" with body:
      """
      {"x_testbench_reply":{"body":{"ok":true}}}
      """
    Then the response status code should be 429
    And I clear all headers
    And I authenticate using basic auth as "admin"

    # The response reports 30 tokens against a quota of 20: the charge clamps at the quota.
    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/tokens" with body:
      """
      {"x_testbench_reply":{"body":{"usage":{"total_tokens":30}}}}
      """
    Then the response status code should be 200
    And the response header "X-RateLimit-Remaining" should be "0"
    When I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/tokens" with body:
      """
      {"x_testbench_reply":{"body":{"usage":{"total_tokens":1}}}}
      """
    Then the response status code should be 429

    When I delete the API "${CTX:apiName}"
    Then the response should be successful

  # A request refused for being heavier than what is left must leave the remainder untouched, as it
  # does on the in-memory backend (ratelimit_window.feature). The Redis fixed-window limiter adds
  # the cost to the shared counter before it compares it with the limit and never takes it back.
  @known-issue
  Scenario: A weighted request refused on Redis consumes none of the remaining quota
    Given I generate a unique value from "arl-redis-atomic" and store it as "apiName"
    And I generate a unique API version from "arl-redis-atomic" and store it as "apiVersion"
    And I generate a unique API context from "/arl-redis-atomic" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}         |
      | name                   | ${CTX:apiName}                   |
      | spec.displayName       | ${CTX:apiName}                   |
      | spec.version           | ${CTX:apiVersion}                |
      | spec.context           | ${CTX:apiContext}/$version       |
      | spec.upstream.main.url | http://testbench:3000            |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"POST","path":"/resource","policies":[{"name":"advanced-ratelimit","version":"v1","params":{"quotas":[{"name":"redis-atomic","limits":[{"limit":10,"duration":"1h"}],"costExtraction":{"enabled":true,"sources":[{"type":"request_header","key":"X-Cost"}],"default":1}}]}}]}] |
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

  Scenario: Quota state kept in Redis survives a gateway runtime restart
    Given I generate a unique value from "arl-redis-restart" and store it as "apiName"
    And I generate a unique API version from "arl-redis-restart" and store it as "apiVersion"
    And I generate a unique API context from "/arl-redis-restart" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}         |
      | name                   | ${CTX:apiName}                   |
      | spec.displayName       | ${CTX:apiName}                   |
      | spec.version           | ${CTX:apiVersion}                |
      | spec.context           | ${CTX:apiContext}/$version       |
      | spec.upstream.main.url | http://testbench:3000            |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"GET","path":"/resource","policies":[{"name":"advanced-ratelimit","version":"v1","params":{"quotas":[{"name":"redis-restart","limits":[{"limit":2,"duration":"1h"}]}]}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I send 2 "GET" requests to "${CTX:apiContext}/${CTX:apiVersion}/resource"
    Then the response status code should be 200
    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/resource"
    Then the response status code should be 429

    When I restart the "gateway-runtime" service
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200
    # A policy engine that had kept the count in memory would start from zero and answer 200.
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/resource"
    Then the response status code should be 429

    When I delete the API "${CTX:apiName}"
    Then the response should be successful

  Scenario: During a Redis outage requests pass and the failure is logged, and enforcement resumes after recovery
    Given I generate a unique value from "arl-redis-open" and store it as "apiName"
    And I generate a unique API version from "arl-redis-open" and store it as "apiVersion"
    And I generate a unique API context from "/arl-redis-open" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}         |
      | name                   | ${CTX:apiName}                   |
      | spec.displayName       | ${CTX:apiName}                   |
      | spec.version           | ${CTX:apiVersion}                |
      | spec.context           | ${CTX:apiContext}/$version       |
      | spec.upstream.main.url | http://testbench:3000            |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"GET","path":"/resource","policies":[{"name":"advanced-ratelimit","version":"v1","params":{"quotas":[{"name":"redis-open","limits":[{"limit":3,"duration":"1h"}]}]}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200
    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/resource"
    Then the response status code should be 200
    And the response header "X-RateLimit-Limit" should be "3"

    When I stop the Redis component
    # Every request is above the limit of 3 yet none is rejected: the policy fails open.
    And I send 6 "GET" requests to "${CTX:apiContext}/${CTX:apiVersion}/resource"
    Then the response status code should be 200
    And the "gateway-runtime" service logs should contain "Rate limit check failed (fail-open)"

    When I start the Redis component
    # Redis comes back empty, and the same policy instance counts and enforces again without a restart.
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/resource" until status 429
    Then the response body should contain "Rate limit exceeded"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
