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

@ratelimit-memory-tuning
Feature: Advanced rate limit system settings of the in-memory backend
  As an API operator
  I want to switch rate limit headers off and bound the in-memory state
  So that responses reveal only what I choose and a flood of distinct keys cannot grow memory without limit

  # The gateway of this runner has every rate limit header switched off and memory.max_entries at
  # 100 (overlays/memory-tuning.toml).

  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"

  Scenario: With the headers switched off neither allowed nor throttled responses carry rate limit headers
    Given I generate a unique value from "arl-headers-off" and store it as "apiName"
    And I generate a unique API version from "arl-headers-off" and store it as "apiVersion"
    And I generate a unique API context from "/arl-headers-off" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}         |
      | name                   | ${CTX:apiName}                   |
      | spec.displayName       | ${CTX:apiName}                   |
      | spec.version           | ${CTX:apiVersion}                |
      | spec.context           | ${CTX:apiContext}/$version       |
      | spec.upstream.main.url | http://testbench:3000            |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"GET","path":"/resource","policies":[{"name":"advanced-ratelimit","version":"v1","params":{"quotas":[{"name":"quiet","limits":[{"limit":1,"duration":"1h"}]}]}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/resource"
    Then the response status code should be 200
    And the response header "X-RateLimit-Limit" should not exist
    And the response header "X-RateLimit-Remaining" should not exist
    And the response header "X-RateLimit-Reset" should not exist
    And the response header "RateLimit" should not exist
    And the response header "RateLimit-Policy" should not exist

    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/resource"
    Then the response status code should be 429
    And the response body should contain "Rate limit exceeded"
    And the response header "X-RateLimit-Limit" should not exist
    And the response header "RateLimit" should not exist
    And the response header "Retry-After" should not exist

    When I delete the API "${CTX:apiName}"
    Then the response should be successful

  # memory.max_entries is documented as "oldest entries are evicted when limit is reached", so a
  # key that was used before a flood of other keys should have been dropped by the time it returns.
  @known-issue
  Scenario: The in-memory state is bounded by memory.max_entries
    Given I generate a unique value from "arl-max-entries" and store it as "apiName"
    And I generate a unique API version from "arl-max-entries" and store it as "apiVersion"
    And I generate a unique API context from "/arl-max-entries" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}         |
      | name                   | ${CTX:apiName}                   |
      | spec.displayName       | ${CTX:apiName}                   |
      | spec.version           | ${CTX:apiVersion}                |
      | spec.context           | ${CTX:apiContext}/$version       |
      | spec.upstream.main.url | http://testbench:3000            |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"GET","path":"/resource","policies":[{"name":"advanced-ratelimit","version":"v1","params":{"quotas":[{"name":"bounded","limits":[{"limit":1,"duration":"1h"}],"keyExtraction":[{"type":"header","key":"X-Tenant"}]}]}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I set header "X-Tenant" to "first-tenant"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/resource"
    Then the response status code should be 200
    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/resource"
    Then the response status code should be 429

    When I clear all headers
    And I authenticate using basic auth as "admin"
    And I send 300 concurrent "GET" requests to "${CTX:apiContext}/${CTX:apiVersion}/resource" with per-request headers:
      | X-Tenant | flood |

    When I set header "X-Tenant" to "first-tenant"
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/resource"
    Then the response status code should be 200
    And I clear all headers
    And I authenticate using basic auth as "admin"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
