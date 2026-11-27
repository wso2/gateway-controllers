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

@ratelimit-window
Feature: Advanced rate limit windows, attachment levels and weighted rejections
  As an API developer
  I want quotas to reset when their window ends and to apply at the level I attached them
  So that clients regain access on schedule and one operation's limit never leaks into another

  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"

  # Fixed windows are aligned to the clock, so the scenario never assumes where in a window it
  # starts: it polls until the quota rejects, then until the window rolls over.
  Scenario: A quota is available again once its window has ended
    Given I generate a unique value from "arl-window-reset" and store it as "apiName"
    And I generate a unique API version from "arl-window-reset" and store it as "apiVersion"
    And I generate a unique API context from "/arl-window-reset" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}         |
      | name                   | ${CTX:apiName}                   |
      | spec.displayName       | ${CTX:apiName}                   |
      | spec.version           | ${CTX:apiVersion}                |
      | spec.context           | ${CTX:apiContext}/$version       |
      | spec.upstream.main.url | http://testbench:3000            |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"GET","path":"/short","policies":[{"name":"advanced-ratelimit","version":"v1","params":{"quotas":[{"name":"short-window","limits":[{"limit":2,"duration":"4s"}]}]}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/short" until status 429
    Then the response header "Retry-After" should exist
    And the response body should contain "Rate limit exceeded"

    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/short" until status 200
    Then the response header "X-RateLimit-Limit" should be "2"
    And the response header "X-RateLimit-Remaining" should be "1"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful

  Scenario: A fixed window starts a fresh counter at its boundary and allows a full quota again
    Given I generate a unique value from "arl-window-boundary" and store it as "apiName"
    And I generate a unique API version from "arl-window-boundary" and store it as "apiVersion"
    And I generate a unique API context from "/arl-window-boundary" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}         |
      | name                   | ${CTX:apiName}                   |
      | spec.displayName       | ${CTX:apiName}                   |
      | spec.version           | ${CTX:apiVersion}                |
      | spec.context           | ${CTX:apiContext}/$version       |
      | spec.upstream.main.url | http://testbench:3000            |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"GET","path":"/boundary","policies":[{"name":"advanced-ratelimit","version":"v1","params":{"quotas":[{"name":"boundary-window","limits":[{"limit":3,"duration":"6s"}]}]}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/boundary" until status 429
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/boundary" until status 200
    Then the response header "X-RateLimit-Remaining" should be "2"

    # The whole quota is available straight away in the new window, which is the boundary burst
    # a fixed window permits and a smooth algorithm does not.
    When I send 2 "GET" requests to "${CTX:apiContext}/${CTX:apiVersion}/boundary"
    Then the response status code should be 200
    And the response header "X-RateLimit-Remaining" should be "0"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful

  Scenario: A request whose weight exceeds the remaining quota is rejected without consuming any of it
    Given I generate a unique value from "arl-weight-atomic" and store it as "apiName"
    And I generate a unique API version from "arl-weight-atomic" and store it as "apiVersion"
    And I generate a unique API context from "/arl-weight-atomic" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}         |
      | name                   | ${CTX:apiName}                   |
      | spec.displayName       | ${CTX:apiName}                   |
      | spec.version           | ${CTX:apiVersion}                |
      | spec.context           | ${CTX:apiContext}/$version       |
      | spec.upstream.main.url | http://testbench:3000            |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"POST","path":"/resource","policies":[{"name":"advanced-ratelimit","version":"v1","params":{"quotas":[{"name":"weighted","limits":[{"limit":10,"duration":"1h"}],"costExtraction":{"enabled":true,"sources":[{"type":"request_header","key":"X-Cost"}],"default":1}}]}}]}] |
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

    # The rejected request consumed nothing: the exact remainder is still available.
    When I set header "X-Cost" to "4"
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/resource" with body:
      """
      {}
      """
    Then the response status code should be 200
    And the response header "X-RateLimit-Remaining" should be "0"

    When I set header "X-Cost" to "1"
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/resource" with body:
      """
      {}
      """
    Then the response status code should be 429
    And I clear all headers
    And I authenticate using basic auth as "admin"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful

  Scenario: A quota attached at the API level is shared by every operation of the API
    Given I generate a unique value from "arl-api-level" and store it as "apiName"
    And I generate a unique API version from "arl-api-level" and store it as "apiVersion"
    And I generate a unique API context from "/arl-api-level" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}         |
      | name                   | ${CTX:apiName}                   |
      | spec.displayName       | ${CTX:apiName}                   |
      | spec.version           | ${CTX:apiVersion}                |
      | spec.context           | ${CTX:apiContext}/$version       |
      | spec.upstream.main.url | http://testbench:3000            |
      | spec.policies          | [{"name":"advanced-ratelimit","version":"v1","params":{"quotas":[{"name":"api-wide","limits":[{"limit":5,"duration":"1h"}],"keyExtraction":[{"type":"apiname"}]}]}}] |
      | spec.operations        | [{"method":"GET","path":"/first"},{"method":"GET","path":"/second"}] |
    Then the resource creation response should indicate successful deployment
    # The first successful answer is the first request counted against the quota.
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/first" until status 200

    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/second"
    Then the response status code should be 200
    And the response header "X-RateLimit-Remaining" should be "3"

    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/first"
    Then the response header "X-RateLimit-Remaining" should be "2"

    When I send 2 "GET" requests to "${CTX:apiContext}/${CTX:apiVersion}/second"
    Then the response status code should be 200
    And the response header "X-RateLimit-Remaining" should be "0"

    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/first"
    Then the response status code should be 429
    And the response header "X-RateLimit-Quota" should be "api-wide"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful

  Scenario: Each operation of one API enforces the limit configured for it
    Given I generate a unique value from "arl-per-op-limits" and store it as "apiName"
    And I generate a unique API version from "arl-per-op-limits" and store it as "apiVersion"
    And I generate a unique API context from "/arl-per-op-limits" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}         |
      | name                   | ${CTX:apiName}                   |
      | spec.displayName       | ${CTX:apiName}                   |
      | spec.version           | ${CTX:apiVersion}                |
      | spec.context           | ${CTX:apiContext}/$version       |
      | spec.upstream.main.url | http://testbench:3000            |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"GET","path":"/small","policies":[{"name":"advanced-ratelimit","version":"v1","params":{"quotas":[{"name":"small-quota","limits":[{"limit":2,"duration":"1h"}]}]}}]},{"method":"GET","path":"/large","policies":[{"name":"advanced-ratelimit","version":"v1","params":{"quotas":[{"name":"large-quota","limits":[{"limit":4,"duration":"1h"}]}]}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I send 2 "GET" requests to "${CTX:apiContext}/${CTX:apiVersion}/small"
    Then the response status code should be 200
    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/small"
    Then the response status code should be 429
    And the response header "X-RateLimit-Quota" should be "small-quota"

    When I send 4 "GET" requests to "${CTX:apiContext}/${CTX:apiVersion}/large"
    Then the response status code should be 200
    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/large"
    Then the response status code should be 429
    And the response header "X-RateLimit-Quota" should be "large-quota"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
