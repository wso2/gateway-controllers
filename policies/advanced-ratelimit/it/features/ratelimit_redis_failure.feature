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

@ratelimit-redis-closed
Feature: Advanced rate limit on the Redis backend with fail-closed behaviour
  As an API operator who must never serve traffic unmetered
  I want requests rejected while Redis is unavailable
  So that an outage of the rate limit store cannot be used to bypass the limit

  # The gateway of this runner uses fixed-window over Redis with failure_mode=closed
  # (overlays/redis-closed.toml). The scenario starts Redis again before it ends.

  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"

  Scenario: Requests are rejected while Redis is down and accepted again after it returns
    Given I generate a unique value from "arl-redis-closed" and store it as "apiName"
    And I generate a unique API version from "arl-redis-closed" and store it as "apiVersion"
    And I generate a unique API context from "/arl-redis-closed" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}         |
      | name                   | ${CTX:apiName}                   |
      | spec.displayName       | ${CTX:apiName}                   |
      | spec.version           | ${CTX:apiVersion}                |
      | spec.context           | ${CTX:apiContext}/$version       |
      | spec.upstream.main.url | http://testbench:3000            |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"GET","path":"/resource","policies":[{"name":"advanced-ratelimit","version":"v1","params":{"quotas":[{"name":"redis-closed","limits":[{"limit":100,"duration":"1h"}]}]}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/resource"
    Then the response status code should be 200
    And the response header "X-RateLimit-Limit" should be "100"

    When I stop the Redis component
    # The limit of 100 is far from used, so the rejection comes from the store failure alone.
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/resource" until status 429
    Then the response body should contain "Rate limit exceeded"
    And the "gateway-runtime" service logs should contain "Rate limit check failed (fail-closed)"
    And the response body should not contain "redis"
    And the response body should not contain "connection"
    And the "gateway-runtime" service logs should not contain the Redis password

    # An unmetered route is not affected by the outage.
    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health"
    Then the response status code should be 200

    When I start the Redis component
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/resource" until status 200
    Then the response header "X-RateLimit-Limit" should be "100"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
