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

@ratelimit-redis-tls
Feature: Advanced rate limit with a misconfigured Redis TLS setting
  As an API operator
  I want a broken Redis TLS configuration to stop the policy from serving traffic
  So that a misconfiguration is never mistaken for a Redis outage and quietly turned into fail-open

  # The gateway of this runner points the Redis TLS settings at a CA file that does not exist
  # (overlays/redis-tls-misconfigured.toml) while failure_mode=open.

  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"

  Scenario: A missing Redis CA file fails the route instead of leaving it unthrottled
    Given I generate a unique value from "arl-redis-tls" and store it as "apiName"
    And I generate a unique API version from "arl-redis-tls" and store it as "apiVersion"
    And I generate a unique API context from "/arl-redis-tls" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion}         |
      | name                   | ${CTX:apiName}                   |
      | spec.displayName       | ${CTX:apiName}                   |
      | spec.version           | ${CTX:apiVersion}                |
      | spec.context           | ${CTX:apiContext}/$version       |
      | spec.upstream.main.url | http://testbench:3000            |
      | spec.operations        | [{"method":"GET","path":"/health"},{"method":"GET","path":"/limited","policies":[{"name":"advanced-ratelimit","version":"v1","params":{"quotas":[{"name":"tls-broken","limits":[{"limit":1,"duration":"1h"}]}]}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/health" until status 200

    When I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/limited" until status 500
    Then the response body should not contain "missing-ca.pem"
    When I send 3 "GET" requests to "${CTX:apiContext}/${CTX:apiVersion}/limited"
    Then the response status code should be 500
    And the "gateway-runtime" service logs should contain "missing-ca.pem"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
