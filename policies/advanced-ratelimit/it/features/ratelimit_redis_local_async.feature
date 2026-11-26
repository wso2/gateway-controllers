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

@ratelimit-redis-local-async
Feature: Advanced rate limit on the redis-local-async backend
  As an API operator who wants low per-request latency
  I want requests counted locally and reconciled to Redis in the background
  So that the hot path makes no Redis call, the shared count converges and an outage degrades to local enforcement

  # The gateway of this runner uses fixed-window over redis-local-async with failure_mode=open
  # and a 50ms sync interval (overlays/redis-local-async.toml). The scenario that stops Redis
  # starts it again before it ends.

  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"

  Scenario: A quota counted locally is enforced exactly on one replica
    Given I generate a unique value from "arl-async-basic" and store it as "apiName"
    And I generate a unique API version from "arl-async-basic" and store it as "apiVersion"
    And I generate a unique API context from "/arl-async-basic" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}         |
      | name                   | ${CTX:apiName}                   |
      | spec.displayName       | ${CTX:apiName}                   |
      | spec.version           | ${CTX:apiVersion}                |
      | spec.context           | ${CTX:apiContext}/$version       |
      | spec.upstream.main.url | http://testbench:3000            |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"GET","path":"/resource","policies":[{"name":"advanced-ratelimit","version":"v1","params":{"quotas":[{"name":"async-quota","limits":[{"limit":5,"duration":"1h"}],"keyExtraction":[{"type":"header","key":"X-User-ID"}]}]}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I set header "X-User-ID" to "alice"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/resource"
    Then the response status code should be 200
    And the response header "X-RateLimit-Limit" should be "5"
    When I send 4 "GET" requests to "${CTX:apiContext}/${CTX:apiVersion}/resource"
    Then the response status code should be 200
    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/resource"
    Then the response status code should be 429
    And the response header "X-RateLimit-Quota" should be "async-quota"

    When I set header "X-User-ID" to "bob"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/resource"
    Then the response status code should be 200
    And I clear all headers
    And I authenticate using basic auth as "admin"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful

  Scenario: Parallel requests around the boundary are admitted exactly up to the quota
    Given I generate a unique value from "arl-async-concurrent" and store it as "apiName"
    And I generate a unique API version from "arl-async-concurrent" and store it as "apiVersion"
    And I generate a unique API context from "/arl-async-concurrent" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}         |
      | name                   | ${CTX:apiName}                   |
      | spec.displayName       | ${CTX:apiName}                   |
      | spec.version           | ${CTX:apiVersion}                |
      | spec.context           | ${CTX:apiContext}/$version       |
      | spec.upstream.main.url | http://testbench:3000            |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"GET","path":"/resource","policies":[{"name":"advanced-ratelimit","version":"v1","params":{"quotas":[{"name":"async-parallel","limits":[{"limit":10,"duration":"1h"}]}]}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I send 25 concurrent "GET" requests to "${CTX:apiContext}/${CTX:apiVersion}/resource" and exactly 10 should return 200 while 15 should return 429

    When I delete the API "${CTX:apiName}"
    Then the response should be successful

  Scenario: Costs are charged through the synchronous Redis path
    Given I generate a unique value from "arl-async-cost" and store it as "apiName"
    And I generate a unique API version from "arl-async-cost" and store it as "apiVersion"
    And I generate a unique API context from "/arl-async-cost" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}         |
      | name                   | ${CTX:apiName}                   |
      | spec.displayName       | ${CTX:apiName}                   |
      | spec.version           | ${CTX:apiVersion}                |
      | spec.context           | ${CTX:apiContext}/$version       |
      | spec.upstream.main.url | http://testbench:3008/scripted   |
      | spec.operations        | [{"method":"POST","path":"/get"},{"method":"POST","path":"/weighted","policies":[{"name":"advanced-ratelimit","version":"v1","params":{"quotas":[{"name":"async-weighted","limits":[{"limit":10,"duration":"1h"}],"costExtraction":{"enabled":true,"sources":[{"type":"request_header","key":"X-Cost"}],"default":1}}]}}]}] |
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

    When I delete the API "${CTX:apiName}"
    Then the response should be successful

  Scenario: Locally counted requests are flushed to Redis and a restarted gateway converges on that count
    Given I generate a unique value from "arl-async-restart" and store it as "apiName"
    And I generate a unique API version from "arl-async-restart" and store it as "apiVersion"
    And I generate a unique API context from "/arl-async-restart" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}         |
      | name                   | ${CTX:apiName}                   |
      | spec.displayName       | ${CTX:apiName}                   |
      | spec.version           | ${CTX:apiVersion}                |
      | spec.context           | ${CTX:apiContext}/$version       |
      | spec.upstream.main.url | http://testbench:3000            |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"GET","path":"/resource","policies":[{"name":"advanced-ratelimit","version":"v1","params":{"quotas":[{"name":"async-restart","limits":[{"limit":2,"duration":"1h"}]}]}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I send 2 "GET" requests to "${CTX:apiContext}/${CTX:apiVersion}/resource"
    Then the response status code should be 200
    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/resource"
    Then the response status code should be 429

    When I restart the "gateway-runtime" service
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200
    # The restarted process counts locally from zero, so its first requests may still be admitted.
    # Once it has read the count back from Redis, where the first process flushed it, it rejects.
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/resource" until status 429
    Then the response body should contain "Rate limit exceeded"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful

  Scenario: While Redis is down the quota is still enforced locally and again shared once Redis returns
    Given I generate a unique value from "arl-async-outage" and store it as "apiName"
    And I generate a unique API version from "arl-async-outage" and store it as "apiVersion"
    And I generate a unique API context from "/arl-async-outage" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}         |
      | name                   | ${CTX:apiName}                   |
      | spec.displayName       | ${CTX:apiName}                   |
      | spec.version           | ${CTX:apiVersion}                |
      | spec.context           | ${CTX:apiContext}/$version       |
      | spec.upstream.main.url | http://testbench:3000            |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"GET","path":"/resource","policies":[{"name":"advanced-ratelimit","version":"v1","params":{"quotas":[{"name":"async-outage","limits":[{"limit":3,"duration":"1h"}],"keyExtraction":[{"type":"header","key":"X-User-ID"}]}]}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I stop the Redis component
    And I set header "X-User-ID" to "outage-user"
    And I send 3 "GET" requests to "${CTX:apiContext}/${CTX:apiVersion}/resource"
    Then the response status code should be 200
    # Open mode degrades to per-replica enforcement, not to unlimited traffic.
    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/resource" until status 429
    Then the response body should contain "Rate limit exceeded"
    And the "gateway-runtime" service logs should not contain the Redis password

    When I start the Redis component
    And I set header "X-User-ID" to "recovered-user"
    And I send 3 "GET" requests to "${CTX:apiContext}/${CTX:apiVersion}/resource"
    Then the response status code should be 200
    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/resource" until status 429
    And I clear all headers
    And I authenticate using basic auth as "admin"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
